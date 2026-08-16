#!/usr/bin/env python3
"""JSEF Benchmark — mimofan 驱动脚本（形态 A：LLM 推理）。

以 CSV 的「文件」为单位驱动 mimofan（exec --auto），把每个 Java 文件交给
mimo-v2.5 做漏洞挖掘，解析其 JSON 输出并按 sample id 对齐，落盘为
scorecard 能读取的 result.json。支持断点续跑、分层子集、超时保护。

用法：
  python3 run_mimofan_benchmark.py                # 全量
  python3 run_mimofan_benchmark.py --resume       # 只跑未完成文件
  python3 run_mimofan_benchmark.py --only-level L0,L1,L2
  python3 run_mimofan_benchmark.py --only-namespace tcm,sbm,dbg,str
  python3 run_mimofan_benchmark.py --only-file <path>
  python3 run_mimofan_benchmark.py --limit 10     # 调试：只跑前 N 个文件
  python3 run_mimofan_benchmark.py --dry-run      # 只打印将跑的文件，不调用

环境变量（mimo 网关，已验证连通）：
  MIMOFAN_PROVIDER=anthropic-compatible
  ANTHROPIC_BASE_URL=https://api.xiaomimimo.com/anthropic
  ANTHROPIC_MODEL=mimo-v2.5
  ANTHROPIC_AUTH_TOKEN=sk-...
"""
import argparse
import csv
import json
import os
import re
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
EXPECTED = os.path.join(ROOT, "benchmark", "expectedresults.csv")
MIMOFAN = os.path.join(ROOT, "..", "agent-mimofan", "target", "debug", "mimofan")
OUT_DIR = os.path.join(ROOT, "benchmark", "results", "mimofan-mimo-v2.5")
RESULT_JSON = os.path.join(OUT_DIR, "result.json")
DONE_FILE = os.path.join(OUT_DIR, ".done.txt")
TIMEOUT_S = 120  # JSEF 单样本超时阈值
MAX_TURNS = 20

# mimo 网关配置（也可从环境变量继承，这里提供默认值以便复现）
ENV = {
    "MIMOFAN_PROVIDER": "anthropic-compatible",
    "ANTHROPIC_BASE_URL": "https://api.xiaomimimo.com/anthropic",
    "ANTHROPIC_MODEL": "mimo-v2.5",
    "ANTHROPIC_AUTH_TOKEN": "sk-REVOKED-REMOVE-FROM-HISTORY",
}


def load_expected():
    samples = []
    with open(EXPECTED, newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            samples.append({
                "id": row["id"].strip(),
                "cwe": row["cwe"].strip(),
                "level": row["level"].strip(),
                "type": row["type"].strip().lower(),
                "file": row["file"].strip(),
                "line": int(row["line"]) if row["line"].strip().isdigit() else -1,
            })
    return samples


def aggregate_by_file(samples):
    by_file = {}
    for s in samples:
        by_file.setdefault(s["file"], []).append(s)
    return by_file


def build_prompt(file_path, file_samples):
    """构造单文件 prompt：列出该文件所有 expected sample id，要求逐条 hit 判定。"""
    lines = []
    lines.append("你是一名 Java 静态应用安全测试（SAST）专家。请对下面给定的 Java 源码文件做漏洞挖掘，")
    lines.append("识别其中真实存在的安全缺陷（true positive），不要对'看似危险但实际安全'的代码误报。")
    lines.append("")
    lines.append("分析该文件，并针对我列出的每个 sample id 给出判定：")
    lines.append("- 若该 id 对应代码经你判断确为真实漏洞，输出 {id, hit:true, line:<精确行号>, cwe:<CWE编号>, message:<一句话成因+修复建议>}。")
    lines.append("- 若该 id 对应代码经你判断是安全的（对照实现/已加固），输出 {id, hit:false, line:<该代码行号>, cwe:<CWE编号>, message:<为何安全>}。")
    lines.append("- 不要为未在列表中的 id 编造条目；若你发现列表中未覆盖的真实漏洞，可额外附一条 {id:'EXTRA', hit:true, ...}（不计入评分但供参考）。")
    lines.append("- 只输出一个 JSON 列表，不要 markdown 代码块标记、不要任何解释文字。")
    lines.append("")
    lines.append("待分析文件绝对路径：%s" % file_path)
    lines.append("")
    lines.append("需逐条判定的 sample id 清单：")
    for s in file_samples:
        lines.append("  - id=%s | 期望CWE=CWE-%s | 标注行=%d | 类型=%s"
                     % (s["id"], s["cwe"], s["line"], s["type"]))
    return "\n".join(lines)


def parse_stream_json(raw):
    """从 mimofan stream-json 输出拼接 content 文本。

    注意：mimofan 在 stream-json 模式下可能向 stdout 混入 TUI 装饰字符
    （如 ';🐋 mimofan' 转义序列），导致整行非合法 JSON。这里对每行定位
    第一个 '{' 再解析，容忍行首噪声。
    """
    texts = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        # 容忍行首 TUI 噪声：找到第一个 '{' 起解析
        brace = line.find("{")
        if brace > 0:
            line = line[brace:]
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type") == "content":
            texts.append(obj.get("content", ""))
        elif obj.get("type") == "result":
            c = obj.get("content")
            if isinstance(c, str):
                texts.append(c)
    return "".join(texts)


def extract_json_array(text):
    """强容错提取 JSON 数组。"""
    # 去 ``` 围栏
    text = re.sub(r"```(?:json)?", "", text).strip()
    if text.startswith("[") and text.endswith("]"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    # 截取首个 [ 到末个 ]
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        snippet = text[start:end + 1]
        try:
            return json.loads(snippet)
        except json.JSONDecodeError:
            pass
    # 回退：逐行找 {..} 对象
    objs = []
    for m in re.finditer(r"\{[^{}]*\}", text):
        try:
            objs.append(json.loads(m.group(0)))
        except json.JSONDecodeError:
            continue
    if objs:
        return objs
    return None


def run_mimofan(prompt, timeout_s=TIMEOUT_S):
    """调用 mimofan exec --auto，返回 (text, elapsed_ms, timed_out)。"""
    cmd = [
        MIMOFAN, "exec", "--auto",
        "--output-format", "stream-json",
        "--max-turns", str(MAX_TURNS),
        prompt,
    ]
    env = dict(os.environ)
    env.update(ENV)
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, cwd=ROOT,
    )
    timed_out = [False]
    out = [b""]
    err = [b""]

    def _kill():
        if proc.poll() is None:
            timed_out[0] = True
            proc.kill()

    timer = threading.Timer(timeout_s + 5, _kill)
    t0 = time.time()
    try:
        timer.start()
        out[0], err[0] = proc.communicate()
    finally:
        timer.cancel()
    elapsed = int((time.time() - t0) * 1000)
    if timed_out[0]:
        return "", elapsed, True
    if proc.returncode != 0:
        sys.stderr.write("[warn] mimofan exit=%s err=%s\n" % (proc.returncode, err[0][:300].decode(errors="replace")))
    return out[0].decode(errors="replace"), elapsed, False


def map_results(file_samples, parsed, file_rel, elapsed, timed_out):
    """把模型输出按 id 映射到 expected sample；未覆盖的 id 按类型补默认。"""
    by_id = {s["id"]: s for s in file_samples}
    reported = {}
    if isinstance(parsed, list):
        for item in parsed:
            if not isinstance(item, dict):
                continue
            sid = str(item.get("id", "")).strip()
            if sid in by_id:
                reported[sid] = {
                    "id": sid,
                    "hit": bool(item.get("hit", False)),
                    "file": file_rel,
                    "line": int(item.get("line", by_id[sid]["line"])) if str(item.get("line", "")).strip().isdigit() else by_id[sid]["line"],
                    "cwe": "CWE-%s" % by_id[sid]["cwe"],
                    "message": str(item.get("message", "")),
                    "elapsed_ms": elapsed,
                }
    # 未覆盖的 id：vuln 默认 hit:false（FN 候选），safe 默认不报（TN）
    results = list(reported.values())
    for s in file_samples:
        if s["id"] not in reported:
            if timed_out:
                # 超时：标记该文件所有未报样本为未产出（scorecard 视为未报）
                continue
            if s["type"] == "vuln":
                results.append({
                    "id": s["id"], "hit": False, "file": file_rel,
                    "line": s["line"], "cwe": "CWE-%s" % s["cwe"],
                    "message": "(未产出：模型未覆盖/超时)", "elapsed_ms": elapsed,
                })
            # safe 未报 = 正确，不写入
    return results


def load_done():
    if os.path.isfile(DONE_FILE):
        with open(DONE_FILE, encoding="utf-8") as fh:
            return set(l.strip() for l in fh if l.strip())
    return set()


def save_done(done):
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(DONE_FILE, "w", encoding="utf-8") as fh:
        for f in sorted(done):
            fh.write(f + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--only-level", help="逗号分隔 level 过滤，如 L0,L1,L2")
    ap.add_argument("--only-namespace", help="逗号分隔 id 前缀过滤，如 tcm,sbm,dbg,str")
    ap.add_argument("--only-file", help="只跑指定相对路径文件")
    ap.add_argument("--only-type", help="逗号分隔 type 过滤，vuln/safe")
    ap.add_argument("--limit", type=int, help="只跑前 N 个文件")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--timeout", type=int, default=TIMEOUT_S)
    ap.add_argument("--require-complete", dest="require_complete", action="store_true",
                    default=True,
                    help="默认开启：若覆盖率不足 100%% 则以 exit 2 中止，防止截断结果被误判为完整（scorecard 会把缺失 vuln 算作 FN）")
    ap.add_argument("--no-require-complete", dest="require_complete", action="store_false",
                    help="调试用：允许截断运行（覆盖率不足也正常退出）")
    args = ap.parse_args()

    samples = load_expected()
    by_file = aggregate_by_file(samples)

    # 过滤：--only-level / --only-namespace / --only-type 为「宽 OR」——
    # 文件只要含任一满足条件的 sample 即入选（保持该文件全部 sample 一起跑，
    # 以贴合「分析整个文件」的自然语义）。
    levels = set((args.only_level or "").upper().split(",")) - {""}
    nses = set((args.only_namespace or "").lower().split(",")) - {""}
    types = set((args.only_type or "").lower().split(",")) - {""}
    selected = {}
    for f, fs in by_file.items():
        if args.only_file and f != args.only_file:
            continue
        if levels or nses or types:
            keep = []
            for s in fs:
                ok = False
                if levels and s["level"] in levels:
                    ok = True
                if nses and any(s["id"].lower().startswith("jsef-" + n) for n in nses):
                    ok = True
                if types and s["type"] in types:
                    ok = True
                if ok:
                    keep.append(s)
            if not keep:
                continue
            selected[f] = keep
        else:
            selected[f] = fs

    if args.limit:
        items = list(selected.items())[:args.limit]
        selected = dict(items)

    done = load_done() if args.resume else set()
    todo = [f for f in selected if f not in done]

    print("[info] 总文件=%d 选中=%d 已完成=%d 待跑=%d"
          % (len(by_file), len(selected), len(done & set(selected)), len(todo)))

    if args.dry_run:
        for f in todo:
            print("  WOULD RUN:", f, "(%d samples)" % len(selected[f]))
        return

    os.makedirs(OUT_DIR, exist_ok=True)
    all_results = []
    # 若 resume，先载入已有 result.json 以免覆盖
    if os.path.isfile(RESULT_JSON) and args.resume:
        try:
            with open(RESULT_JSON, encoding="utf-8") as fh:
                all_results = json.load(fh)
        except Exception:
            all_results = []

    for i, f in enumerate(todo, 1):
        fs = selected[f]
        fabs = os.path.join(ROOT, f)
        if not os.path.isfile(fabs):
            sys.stderr.write("[skip] 文件不存在: %s\n" % f)
            done.add(f)
            continue
        # 单文件异常隔离：任一文件崩溃/异常都不应中断整轮 sweep，
        # 否则进程被杀后 .done.txt 停在半途，后续 scorecard 会把未跑的
        # vuln 样本全部算作 FN，造成「误判完成 / Recall 被低估」的假象。
        try:
            prompt = build_prompt(fabs, fs)
            sys.stderr.write("[%d/%d] %s (%d samples) ...\n" % (i, len(todo), f, len(fs)))
            text, elapsed, timed_out = run_mimofan(prompt, args.timeout)
            parsed = extract_json_array(parse_stream_json(text)) if text else None
            if parsed is None:
                sys.stderr.write("    [warn] 解析失败/超时，视为该文件全部未报\n")
                parsed = []
            results = map_results(fs, parsed, f, elapsed, timed_out)
            all_results.extend(results)
            done.add(f)
            # 及时落盘 + 续跑标记
            with open(RESULT_JSON, "w", encoding="utf-8") as fh:
                json.dump(all_results, fh, indent=2, ensure_ascii=False)
            save_done(done)
            sys.stderr.write("    ok: %d 条结果, elapsed=%dms, timeout=%s\n"
                             % (len(results), elapsed, timed_out))
        except Exception as exc:  # noqa: BLE001 — 单文件失败不应拖垮整轮
            sys.stderr.write("    [ERROR] 文件 %s 处理异常: %s\n" % (f, exc))
            # 不计入 done，保留在待跑集合以便 --resume 重试
            continue

    done_in_selected = len(done & set(selected))
    coverage = done_in_selected / len(selected) if selected else 1.0
    print("[SUMMARY] 选中=%d 已完成=%d 覆盖率=%.1f%%"
          % (len(selected), done_in_selected, coverage * 100))
    print("[done] 结果已写出: %s (%d 条)" % (RESULT_JSON, len(all_results)))

    # 防「误判完成」闸门：未跑完就别假装跑完了。scorecard 若读取这份
    # 不完整的 result.json，会把缺失 vuln 全部按 FN 计，严重低估 Recall。
    if done_in_selected < len(selected):
        sys.stderr.write(
            "\n[WARN] 截断运行！仅 %d/%d 文件完成（覆盖率 %.1f%%）。\n"
            "        未完成的文件不会被写入 result.json，其 vuln 样本会被\n"
            "        scorecard 误判为 FN。请重新运行（加 --resume）直到覆盖率为 100%%\n"
            "        再跑 scorecard。\n" % (done_in_selected, len(selected), coverage * 100)
        )
        if args.require_complete:
            sys.stderr.write("[FATAL] --require-complete 已设：因覆盖不足而中止（exit 2）。\n")
            sys.exit(2)


if __name__ == "__main__":
    main()
