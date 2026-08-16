#!/usr/bin/env python3
"""JSEF Benchmark — 未标注 sink 扫描器 (scan_untagged_sinks.py)

扫描 benchmark/cases/vuln/ 与 src/main/.../vulnerability/ 下的漏洞文件，
找出"存在危险 sink 调用但附近没有 [CHECKPOINT] 注解"的位置，
辅助人工审核补标工作（P0-2 多 sink 文件只标部分 checkpoint 问题）。

输出格式
--------
每个命中打印：
  [UNTAGGED] <file>:<line>  <sink_pattern>  (±N 行内无 CHECKPOINT)

退出码
------
0 = 扫描成功（不代表无问题）；1 = 错误。

示例
----
    python scan_untagged_sinks.py --window 3
    python scan_untagged_sinks.py --cases-dir benchmark/cases/vuln --out untagged.json
"""

import argparse
import json
import os
import re
import sys

# ——————————————————————————————————————————————————————————————————
# 危险 sink 特征（Java 方法调用级）
# ——————————————————————————————————————————————————————————————————
SINK_PATTERNS = [
    # 命令注入
    (re.compile(r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\("),      "CWE-78 Runtime.exec"),
    (re.compile(r"ProcessBuilder\s*\("),                                         "CWE-78 ProcessBuilder"),
    # SQL 注入
    (re.compile(r"\.query(?:ForList|ForObject|ForMap)?\s*\(\s*[^\"']"),          "CWE-89 jdbcTemplate.query"),
    (re.compile(r"\.execute(?:Query|Update)?\s*\(\s*[^\"']"),                    "CWE-89 Statement.execute"),
    (re.compile(r"createNativeQuery\s*\("),                                      "CWE-89 createNativeQuery"),
    # SpEL/EL 注入
    (re.compile(r"\.parseExpression\s*\("),                                      "CWE-917 parseExpression"),
    (re.compile(r"\.parseRaw\s*\("),                                             "CWE-917 parseRaw"),
    (re.compile(r"ExpressionFactory\s*\.\s*newInstance"),                        "CWE-917 EL ExpressionFactory"),
    # SSRF
    (re.compile(r"new\s+URL\s*\([^)]*\)\s*\.\s*openConnection"),                "CWE-918 URL.openConnection"),
    (re.compile(r"HttpClient[^\n]*\.execute\s*\("),                              "CWE-918 HttpClient.execute"),
    # XXE/XML
    (re.compile(r"DocumentBuilder[^\n]*\.parse\s*\("),                          "CWE-611 DocumentBuilder.parse"),
    (re.compile(r"SAXParser[^\n]*\.parse\s*\("),                                "CWE-611 SAXParser.parse"),
    # 反序列化
    (re.compile(r"ObjectInputStream[^\n]*\.readObject\s*\("),                   "CWE-502 readObject"),
    (re.compile(r"JSON\.parse(?:Object)?\s*\("),                                "CWE-502 fastjson.parse"),
    (re.compile(r"mapper\.readValue\s*\("),                                     "CWE-502 Jackson.readValue"),
    # 路径穿越
    (re.compile(r"new\s+File\s*\([^)]*\+[^)]*\)"),                             "CWE-22 new File concat"),
    (re.compile(r"Files\s*\.\s*(?:read|write|copy|move|delete)\w*\s*\("),      "CWE-22 Files.write/read"),
    # LDAP
    (re.compile(r"\.search\s*\([^,]+,[^,]+,[^)]*\)"),                          "CWE-90 LDAP.search"),
    # XPath
    (re.compile(r"XPath[^\n]*\.evaluate\s*\("),                                 "CWE-643 XPath.evaluate"),
    (re.compile(r"XPath[^\n]*\.compile\s*\("),                                  "CWE-643 XPath.compile"),
    # CRLF/Header 注入
    (re.compile(r"response\s*\.\s*addHeader\s*\("),                             "CWE-93 response.addHeader"),
    (re.compile(r"response\s*\.\s*setHeader\s*\("),                             "CWE-93 response.setHeader"),
    # 模板注入
    (re.compile(r"Template[^\n]*\.process\s*\("),                               "CWE-94 Template.process"),
]

CHECKPOINT_RE = re.compile(r"//\s*\[CHECKPOINT\b")


def scan_file(path: str, window: int = 3):
    """扫描单个文件，返回未标注 sink 列表。

    Args:
        path: Java 文件路径。
        window: sink 行前后各 N 行内若有 CHECKPOINT 则视为已标注。

    Returns:
        list[dict]: 每个未标注 sink 的信息字典。
    """
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return []

    # 预计算 CHECKPOINT 所在行号集合
    checkpoint_lines = set()
    for i, line in enumerate(lines, 1):
        if CHECKPOINT_RE.search(line):
            checkpoint_lines.add(i)

    results = []
    for lineno, line in enumerate(lines, 1):
        # 跳过注释行本身
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            continue

        for pattern, label in SINK_PATTERNS:
            if pattern.search(line):
                # 检查 window 范围内是否有 CHECKPOINT
                near = any(
                    (lineno - w) in checkpoint_lines or (lineno + w) in checkpoint_lines
                    for w in range(1, window + 1)
                )
                if not near:
                    results.append({
                        "file": path,
                        "line": lineno,
                        "sink": label,
                        "code": line.rstrip(),
                    })
                break  # 同一行只报第一个匹配

    return results


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="扫描漏洞文件中未被 CHECKPOINT 标注的危险 sink 调用（P0-2 辅助工具）。",
    )
    parser.add_argument("--cases-dir", default="benchmark/cases/vuln",
                        help="漏洞样本目录（默认 benchmark/cases/vuln）")
    parser.add_argument("--src-dir",
                        default="src/main/java/com/freedom/securitysamples/vulnerability",
                        help="src 侧漏洞目录（默认 src/main/java/.../vulnerability）")
    parser.add_argument("--window", type=int, default=3,
                        help="CHECKPOINT 与 sink 行的最大行距容差（默认 3）")
    parser.add_argument("--out", default=None,
                        help="将结果写出为 JSON 文件（可选）")
    parser.add_argument("--quiet", action="store_true",
                        help="仅打印统计摘要，不打印每条 sink")
    args = parser.parse_args(argv)

    all_results = []
    scan_dirs = [d for d in [args.cases_dir, args.src_dir] if os.path.isdir(d)]

    if not scan_dirs:
        print("[错误] 没有可扫描的目录（cases-dir 和 src-dir 均不存在）", file=sys.stderr)
        return 1

    for d in scan_dirs:
        for root, _dirs, files in os.walk(d):
            for fn in sorted(files):
                if not fn.endswith(".java"):
                    continue
                path = os.path.join(root, fn)
                findings = scan_file(path, window=args.window)
                all_results.extend(findings)

    # 打印
    if not args.quiet:
        for item in all_results:
            print("[UNTAGGED] %s:%d  (%s)" % (item["file"], item["line"], item["sink"]))
            print("           %s" % item["code"])

    # 摘要
    from collections import Counter
    by_sink = Counter(item["sink"] for item in all_results)
    by_file = Counter(item["file"] for item in all_results)
    print("\n=== 未标注 sink 摘要 ===")
    print("总计: %d 处" % len(all_results))
    print("\n按 sink 类型:")
    for sink, cnt in by_sink.most_common():
        print("  %3d  %s" % (cnt, sink))
    print("\n按文件（Top 10）:")
    for path, cnt in by_file.most_common(10):
        print("  %3d  %s" % (cnt, path))

    # 写出 JSON
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(all_results, fh, ensure_ascii=False, indent=2)
            print("\n结果写出: %s" % args.out)
        except OSError as exc:
            print("[警告] 无法写出结果: %s" % exc, file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
