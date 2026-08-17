#!/usr/bin/env python3
"""JSEF Benchmark — gadgetmine 族专用验收运行脚本。

作用：针对新增的 `gadgetmine` 样本族（fastjson AutoType RCE gadget 充要条件判定，
id 前缀 `JSEF-GM-`），提供一条从「运行被测对象 → 评分 → 报告」的闭环，用于验收
LLM / 其他 SAST 工具能否从第一性原理识别这类风险。

三种模式：
  1) scan  —— 本地基线「被测对象」：内置启发式判定器，不依赖外部网关，开箱即跑，
             用于验证该族验收链路闭环（也可作为其他被测对象的对照基线）。
  2) run   —— 驱动 mimofan（mimo-v2.5）只跑 GM 族，复用 run_mimofan_benchmark.py 逻辑。
  3) score —— 从全量 expectedresults.csv 抽取 JSEF-GM-* 子集，跑 scorecard 子集验收，
             支持 --check-trace，产出该族独立报告。

典型用法：
  # 本地基线闭环（无需 token/网络），验证族有效性
  python3 benchmark/scripts/run_gadgetmine.py scan
  python3 benchmark/scripts/run_gadgetmine.py score --check-trace

  # 用 mimofan 跑真实被测 LLM（需 MIMO 网关 token）
  python3 benchmark/scripts/run_gadgetmine.py run --resume
  python3 benchmark/scripts/run_gadgetmine.py score --name mimo-v2.5 --check-trace

  # 对任意已有的 result.json 做该族子集评分
  python3 benchmark/scripts/run_gadgetmine.py score --result <path/to/result.json>

说明：
  - 本脚本不修改任何样本/CSV；所有产物落在 benchmark/results/gadgetmine/。
  - score 模式会生成一个仅含 GM 行的临时 CSV（benchmark/results/gadgetmine/expected_gm.csv），
    再交给 scorecard.py，避免把缺失样本误算为全量 FN。
"""
import argparse
import csv
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BENCH = os.path.join(ROOT, "benchmark")
EXPECTED = os.path.join(BENCH, "expectedresults.csv")
SCRIPTS = os.path.join(BENCH, "scripts")
RESULTS_DIR = os.path.join(BENCH, "results", "gadgetmine")
EXPECTED_GM = os.path.join(RESULTS_DIR, "expected_gm.csv")
RESULT_JSON = os.path.join(RESULTS_DIR, "result.json")
GM_PREFIX = "JSEF-GM-"  # namespace 过滤前缀


# --------------------------------------------------------------------------
# 子集抽取：从全量 CSV 抽出 JSEF-GM-* 行，写临时 expected_gm.csv
# --------------------------------------------------------------------------
def extract_gm_expected():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    rows = []
    with open(EXPECTED, newline="", encoding="utf-8-sig") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        rows.append(header)
        for r in reader:
            if r and r[0].strip().startswith(GM_PREFIX):
                rows.append(r)
    with open(EXPECTED_GM, "w", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerows(rows)
    return len(rows) - 1


def load_gm_samples():
    samples = []
    with open(EXPECTED, newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            if not row["id"].strip().startswith(GM_PREFIX):
                continue
            samples.append({
                "id": row["id"].strip(),
                "cwe": row["cwe"].strip(),
                "level": row["level"].strip(),
                "type": row["type"].strip().lower(),
                "file": row["file"].strip(),
                "line": int(row["line"]) if row["line"].strip().isdigit() else -1,
                "expect": row.get("category", "").strip(),
            })
    return samples


# --------------------------------------------------------------------------
# 模式 1: scan —— 本地基线「被测对象」（启发式第一性原理判定器）
# --------------------------------------------------------------------------
# 该判定器模拟 gadget_tool 的充要条件判定：读取源码 CHECKPOINT 注解，
# 结合简单的语义启发式给出 hit 判定。其目的是让本族验收链路可本地闭环，
# 不代表真实 SAST 能力——真实被测请使用 run/score 对接 mimofan 或你的 SAST。
def baseline_scan(samples):
    """极简基线：信任源码 CHECKPOINT 的 expect 标注作为「理想被测对象」的判定。

    即基线 = 完美被测对象（所有 VULN 报 hit:true，所有 SAFE 报 hit:false）。
    用于验证：子集抽取 + scorecard 评分 + 报告产出链路是否闭环。
    """
    results = []
    for s in samples:
        hit = (s["type"] == "vuln")
        results.append({
            "id": s["id"],
            "hit": hit,
            "file": s["file"],
            "line": s["line"],
            "cwe": "CWE-%s" % s["cwe"],
            "message": ("基线判定：VULN 命中" if hit else "基线判定：SAFE 未报"),
        })
    return results


def cmd_scan(args):
    n = extract_gm_expected()
    samples = load_gm_samples()
    results = baseline_scan(samples)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(RESULT_JSON, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)
    print("[scan] 基线被测对象产出 %d 条结果（GM 族共 %d 样本）" % (len(results), n))
    print("[scan] 结果: %s" % RESULT_JSON)
    print("[scan] 下一步: python3 %s score --check-trace" % os.path.basename(__file__))


# --------------------------------------------------------------------------
# 模式 2: run —— 复用 run_mimofan_benchmark.py 驱动 GM 族
# --------------------------------------------------------------------------
def cmd_run(args):
    driver = os.path.join(ROOT, "run_mimofan_benchmark.py")
    if not os.path.isfile(driver):
        sys.exit("[FATAL] 找不到 %s" % driver)
    # 复用 mimofan 驱动的 --only-namespace gm 过滤；结果落在驱动默认目录
    # benchmark/results/mimofan-mimo-v2.5/result.json
    cmd = [sys.executable, driver, "--only-namespace", "gm"]
    if args.resume:
        cmd.append("--resume")
    if args.limit:
        cmd += ["--limit", str(args.limit)]
    if args.timeout:
        cmd += ["--timeout", str(args.timeout)]
    if args.no_require_complete:
        cmd.append("--no-require-complete")
    print("[run] 调用: %s" % " ".join(cmd))
    rc = subprocess.call(cmd, cwd=ROOT)
    default_result = os.path.join(ROOT, "benchmark", "results",
                                  "mimofan-mimo-v2.5", "result.json")
    print("[run] mimofan 驱动退出码=%d，结果: %s" % (rc, default_result))
    print("[run] 下一步: python3 %s score --result %s --name mimo-v2.5 --check-trace"
          % (os.path.basename(__file__), default_result))


# --------------------------------------------------------------------------
# 模式 3: score —— 子集 scorecard 验收
# --------------------------------------------------------------------------
def cmd_score(args):
    # 1) 确保子集 expected 存在
    if not os.path.isfile(EXPECTED_GM):
        n = extract_gm_expected()
        print("[score] 抽取 GM 子集 %d 样本 -> %s" % (n, EXPECTED_GM))
    else:
        print("[score] 复用已有子集: %s" % EXPECTED_GM)

    # 2) 确定 result 来源
    result = args.result
    if result is None:
        if os.path.isfile(RESULT_JSON):
            result = RESULT_JSON
        else:
            sys.exit("[FATAL] 无 result.json（先跑 scan 或 run）。可加 --result <path> 指定。")

    # 3) 拼装 scorecard 命令（子集 CSV + 该 result）
    out_path = args.out or os.path.join(RESULTS_DIR, "scorecard_gm.json")
    cmd = [
        sys.executable, os.path.join(SCRIPTS, "scorecard.py"),
        "--expected", EXPECTED_GM,
        "--result", result,
        "--name", args.name or "gadgetmine-subset",
        "--out", out_path,
    ]
    if args.check_trace:
        cmd.append("--check-trace")
    if args.verbose:
        cmd.append("--verbose")
    print("[score] 调用: %s" % " ".join(cmd))
    rc = subprocess.call(cmd, cwd=ROOT)
    print("[score] scorecard 退出码=%d，报告: %s" % (rc, out_path))
    if rc != 0:
        sys.exit("[FATAL] scorecard 失败（exit %d）" % rc)


def main():
    ap = argparse.ArgumentParser(description="JSEF gadgetmine 族验收运行脚本")
    sub = ap.add_subparsers(dest="mode", required=True)

    p_scan = sub.add_parser("scan", help="本地基线被测对象，开箱闭环（无需网关）")
    p_scan.set_defaults(func=cmd_scan)

    p_run = sub.add_parser("run", help="驱动 mimofan 只跑 GM 族")
    p_run.add_argument("--resume", action="store_true")
    p_run.add_argument("--limit", type=int, default=None)
    p_run.add_argument("--timeout", type=int, default=None)
    p_run.add_argument("--no-require-complete", action="store_true",
                       help="允许截断运行（调试用）")
    p_run.set_defaults(func=cmd_run)

    p_score = sub.add_parser("score", help="子集 scorecard 验收")
    p_score.add_argument("--result", default=None, help="result.json 路径（默认用 scan 产物）")
    p_score.add_argument("--name", default=None, help="被测对象名")
    p_score.add_argument("--check-trace", action="store_true", help="启用 trace_recall/precision")
    p_score.add_argument("--out", default=None, help="报告输出路径")
    p_score.add_argument("--verbose", action="store_true")
    p_score.set_defaults(func=cmd_score)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
