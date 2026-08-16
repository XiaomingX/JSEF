#!/usr/bin/env python3
"""JSEF Benchmark — 官方致盲分发包生成器 (blind.py)

将 benchmark/cases/ 下的源码匿名化，输出"盲化语料"供被测模型/工具使用，
同时生成私有映射 manifest（anchor → 真实 checkpoint id）。

盲化内容
--------
1. 替换 package 声明为中性 ``package blinded;``。
2. 移除 ``// [CHECKPOINT ...]`` 注解行 → 替换为行内中性锚点 ``/*ANCHOR_N*/``，
   保留锚点所在行（与原注解同行位置），不改变下方 sink 行的行号相对关系。
3. 移除 ``// [VULN]``、``// [SAFE]``、``// [VULN-xxx]`` 等行内教学标记。
4. 移除 Javadoc 块（``/** ... */``）与单行/块注释中包含答案词的注释内容。
   普通代码注释（非答案泄漏）保留，避免破坏可读性。
5. 替换类名/文件名中的 Safe / Unsafe / Vuln / Vulnerable / Secure / Insecure
   词素为中性前缀 ``B``，避免命名泄漏答案。
6. 文件改名为不透明编号 ``B0001.java``、``B0002.java``...（vuln/sec 统一编号）。

不盲化内容
----------
- 代码逻辑（赋值、调用、控制流）不做任何修改。
- 非答案词的普通注释（如算法说明、TODO）保留。
- import 语句保留（CWE 类型可能从 import 推断，但可接受——真正考验数据流分析）。

输出
----
--out <dir>       盲化后的 Java 文件目录（默认 benchmark/blinded/）
--manifest <f>    映射 JSON（默认 <out>/manifest.json），格式：
                  {
                    "files": {"B0001.java": "benchmark/cases/vuln/Foo.java", ...},
                    "anchors": {"B0001.java:ANCHOR_1": "JSEF-TP-001", ...}
                  }
--cases-dir <d>   源语料目录（默认 benchmark/cases）
--no-strip-doc    保留 Javadoc 块（用于调试，不建议用于盲测）

示例
----
    python blind.py --out benchmark/blinded
    python blind.py --cases-dir benchmark/cases --out /tmp/blind --manifest /tmp/blind/manifest.json

退出码
------
0 = 成功；1 = 发生错误。
"""

import argparse
import json
import os
import re
import sys

# ——————————————————————————————————————————————————————————————————
# 正则
# ——————————————————————————————————————————————————————————————————

# package 声明
PACKAGE_RE = re.compile(r"^(\s*package\s+)[\w.]+(\s*;)", re.MULTILINE)

# CHECKPOINT 注解行（含整行）：捕获 id
CHECKPOINT_LINE_RE = re.compile(
    r"^(?P<indent>[ \t]*)//\s*\[CHECKPOINT\b[^\]]*?\bid=(?P<id>[^\s,\]]+)[^\]]*\][ \t]*$"
)

# [VULN] / [SAFE] 等行内教学标记（只移除标记本身，保留同行代码）
INLINE_TAG_RE = re.compile(r"//\s*\[(VULN|SAFE)[\w\-]*\][^\n]*")

# 答案词（类名/文件名中出现时需替换）
ANSWER_WORDS_RE = re.compile(r"\b(Unsafe|Vulnerable|Insecure|Vuln)\b")
SAFE_WORDS_RE   = re.compile(r"\b(Safe|Secure)\b")

# Javadoc 块（/** ... */）—— 用于整块移除
JAVADOC_RE = re.compile(r"/\*\*.*?\*/", re.DOTALL)

# 普通块注释 (/* ... */)
BLOCK_COMMENT_RE = re.compile(r"/\*(?!\*).*?\*/", re.DOTALL)

# 答案词在注释文本里（检测用）
ANSWER_IN_COMMENT_RE = re.compile(
    r"\b(vuln|safe|unsafe|vulnerable|insecure|secure|CWE-\d+|VULN|SAFE|expect=)\b",
    re.IGNORECASE,
)


# ——————————————————————————————————————————————————————————————————
# Java 注释剥离状态机（字符级，正确处理字符串字面量）
# ——————————————————————————————————————————————————————————————————

def strip_java_doc_comments(source: str) -> str:
    """移除 /** ... */ Javadoc 块，保留其他注释和代码。"""
    result = []
    i = 0
    n = len(source)
    in_string = False
    in_char   = False

    while i < n:
        # 字符串字面量
        if in_string:
            if source[i] == '\\' and i + 1 < n:
                result.append(source[i]); result.append(source[i+1]); i += 2; continue
            if source[i] == '"':
                in_string = False
            result.append(source[i]); i += 1; continue

        # 字符字面量
        if in_char:
            if source[i] == '\\' and i + 1 < n:
                result.append(source[i]); result.append(source[i+1]); i += 2; continue
            if source[i] == "'":
                in_char = False
            result.append(source[i]); i += 1; continue

        # Javadoc 块开始
        if source[i:i+3] == "/**":
            # 找结束位置，计算中间换行数以保留行号对齐
            end = source.find("*/", i + 3)
            if end == -1:
                end = n - 2
            chunk = source[i:end+2]
            newlines = chunk.count('\n')
            result.append('\n' * newlines)
            i = end + 2
            continue

        if source[i] == '"':
            in_string = True
        elif source[i] == "'":
            in_char = True

        result.append(source[i]); i += 1

    return "".join(result)


# ——————————————————————————————————————————————————————————————————
# 主盲化逻辑（逐行）
# ——————————————————————————————————————————————————————————————————

def blindify_source(source: str, anchor_map: dict, strip_doc: bool = True) -> str:
    """对单个 Java 源文件内容进行盲化处理。

    Args:
        source: 原始 Java 源码字符串。
        anchor_map: 输出参数，{anchor_label: checkpoint_id}，由本函数填充。
        strip_doc: 是否移除 Javadoc。

    Returns:
        盲化后的源码字符串。
    """
    # 1. 移除 Javadoc（行号保留靠换行数维持）
    if strip_doc:
        source = strip_java_doc_comments(source)

    lines = source.split('\n')
    out_lines = []
    anchor_counter = [0]

    def next_anchor():
        anchor_counter[0] += 1
        return "ANCHOR_%d" % anchor_counter[0]

    for line in lines:
        # 2. 替换 package 声明
        line = PACKAGE_RE.sub(r"\1blinded\2", line)

        # 3. 识别并替换 CHECKPOINT 注解行 → 中性锚点
        m = CHECKPOINT_LINE_RE.match(line)
        if m:
            cid = m.group("id")
            anchor = next_anchor()
            anchor_map[anchor] = cid
            indent = m.group("indent")
            out_lines.append("%s/*%s*/" % (indent, anchor))
            continue

        # 4. 移除行内 [VULN]/[SAFE] 教学标记（保留同行代码逻辑）
        line = INLINE_TAG_RE.sub("", line)

        # 5. 替换行内注释中的答案词（仅行注释 // ... 部分）
        comment_start = _find_line_comment_start(line)
        if comment_start >= 0:
            code_part    = line[:comment_start]
            comment_part = line[comment_start:]
            if ANSWER_IN_COMMENT_RE.search(comment_part):
                # 注释含答案词 → 移除整段注释
                line = code_part.rstrip()
            else:
                line = code_part + comment_part

        out_lines.append(line)

    result = '\n'.join(out_lines)

    # 6. 替换类名/标识符中的答案词（Safe/Unsafe/Vuln/Vulnerable/Secure/Insecure）
    #    仅替换 Java 标识符边界内的词，不替换字符串字面量中的词
    result = _replace_answer_words_in_identifiers(result)

    return result


def _find_line_comment_start(line: str) -> int:
    """返回行注释 ``//`` 在行中的位置（不在字符串/字符字面量内），找不到返回 -1。"""
    in_string = False
    in_char   = False
    i = 0
    while i < len(line):
        c = line[i]
        if in_string:
            if c == '\\': i += 2; continue
            if c == '"': in_string = False
        elif in_char:
            if c == '\\': i += 2; continue
            if c == "'": in_char = False
        else:
            if c == '"': in_string = True
            elif c == "'": in_char = True
            elif line[i:i+2] == "//":
                return i
        i += 1
    return -1


def _replace_answer_words_in_identifiers(source: str) -> str:
    """在 Java 标识符中替换答案词，不替换字符串字面量内容。
    Unsafe/Vulnerable/Insecure/Vuln → X (标记为漏洞侧中性词)
    Safe/Secure → Y (标记为安全侧中性词)
    两侧统一用 B 前缀替换，保留原词长度信息无关紧要。
    """
    result = []
    i = 0
    n = len(source)
    in_string = False
    in_char   = False

    while i < n:
        if in_string:
            if source[i] == '\\' and i + 1 < n:
                result.append(source[i]); result.append(source[i+1]); i += 2; continue
            if source[i] == '"': in_string = False
            result.append(source[i]); i += 1; continue

        if in_char:
            if source[i] == '\\' and i + 1 < n:
                result.append(source[i]); result.append(source[i+1]); i += 2; continue
            if source[i] == "'": in_char = False
            result.append(source[i]); i += 1; continue

        if source[i] == '"': in_string = True; result.append(source[i]); i += 1; continue
        if source[i] == "'": in_char   = True; result.append(source[i]); i += 1; continue

        # 尝试匹配答案词（要求前后为非字母数字_，即单词边界）
        matched = False
        for pattern, replacement in [
            ("Unsafe",      "Bx"),
            ("Vulnerable",  "Bx"),
            ("Insecure",    "Bx"),
            ("Vuln",        "Bx"),
            ("Safe",        "By"),
            ("Secure",      "By"),
        ]:
            plen = len(pattern)
            if source[i:i+plen] == pattern:
                before_ok = (i == 0 or not (source[i-1].isalnum() or source[i-1] == '_'))
                after_ok  = (i + plen >= n or not (source[i+plen].isalnum() or source[i+plen] == '_'))
                if before_ok and after_ok:
                    result.append(replacement)
                    i += plen
                    matched = True
                    break
        if not matched:
            result.append(source[i]); i += 1

    return "".join(result)


# ——————————————————————————————————————————————————————————————————
# 文件名盲化
# ——————————————————————————————————————————————————————————————————

def blindify_filename(name: str) -> str:
    """移除文件名中的答案词（Safe/Unsafe/Vuln/...），仅保留 .java 后缀。"""
    base = name.replace(".java", "")
    base = re.sub(r"(Unsafe|Vulnerable|Insecure|Vuln)", "Bx", base)
    base = re.sub(r"(Safe|Secure)",                     "By", base)
    return base + ".java"


# ——————————————————————————————————————————————————————————————————
# 入口
# ——————————————————————————————————————————————————————————————————

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="JSEF 官方致盲分发包生成器：将 benchmark/cases/ 源码匿名化。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--cases-dir", default="benchmark/cases",
                        help="源语料目录（默认 benchmark/cases）")
    parser.add_argument("--out", default="benchmark/blinded",
                        help="输出目录（默认 benchmark/blinded）")
    parser.add_argument("--manifest", default=None,
                        help="映射文件路径（默认 <out>/manifest.json）")
    parser.add_argument("--no-strip-doc", action="store_true",
                        help="保留 Javadoc 块（调试用，不建议盲测时使用）")
    args = parser.parse_args(argv)

    if args.manifest is None:
        args.manifest = os.path.join(args.out, "manifest.json")

    if not os.path.isdir(args.cases_dir):
        print("[错误] cases 目录不存在: %s" % args.cases_dir, file=sys.stderr)
        return 1

    os.makedirs(args.out, exist_ok=True)

    strip_doc = not args.no_strip_doc

    # 收集所有 .java 文件
    java_files = []
    for root, _dirs, files in os.walk(args.cases_dir):
        for fn in sorted(files):
            if fn.endswith(".java"):
                java_files.append(os.path.join(root, fn))
    java_files.sort()

    manifest = {"files": {}, "anchors": {}}
    counter = 0
    errors  = 0

    for orig_path in java_files:
        counter += 1
        blind_name = "B%04d.java" % counter
        rel_orig   = orig_path  # 保留完整路径作为 manifest key

        try:
            with open(orig_path, encoding="utf-8", errors="ignore") as fh:
                source = fh.read()
        except OSError as exc:
            print("[警告] 无法读取 %s: %s" % (orig_path, exc), file=sys.stderr)
            errors += 1
            continue

        anchor_map = {}  # anchor_label -> checkpoint_id
        blind_source = blindify_source(source, anchor_map, strip_doc=strip_doc)

        out_path = os.path.join(args.out, blind_name)
        try:
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(blind_source)
        except OSError as exc:
            print("[警告] 无法写出 %s: %s" % (out_path, exc), file=sys.stderr)
            errors += 1
            continue

        manifest["files"][blind_name] = rel_orig
        for anchor, cid in anchor_map.items():
            manifest["anchors"]["%s:%s" % (blind_name, anchor)] = cid

    # 写 manifest
    try:
        with open(args.manifest, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, ensure_ascii=False, indent=2)
    except OSError as exc:
        print("[错误] 无法写出 manifest: %s" % exc, file=sys.stderr)
        return 1

    total_anchors = len(manifest["anchors"])
    total_files   = len(manifest["files"])
    print("盲化完成：%d 个文件 → %s/" % (total_files, args.out))
    print("  anchors（checkpoint）总数: %d" % total_anchors)
    print("  manifest 写出: %s" % args.manifest)
    if errors:
        print("  [警告] %d 个文件处理失败（见上方警告）" % errors, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
