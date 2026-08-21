#!/usr/bin/env python3
"""JSEF Benchmark — trials 稳定性聚合（借鉴 DeepSWE：N 次试验全过才算 Pass@1）。

背景
----
DeepSWE 基准的做法：每个模型在同一任务上跑 N 次独立试验（trials），
**全部判对才算该样本通过（Pass@1）**，用于测模型的稳定性与可靠性。
JSEF 现状是单次算分，无稳定性概念。本脚本把"同一对象的 N 次 trial"
聚合成：sample 级 Pass@1（全过）、object 级 Pass@majority（多数过）、
正确率稳定性（acc_mean / acc_std / spread=best-worst）。

目录约定
--------
trials 模式：``benchmark/results/<object>/trial_<i>/result.json``（i 从 1，建议零填充）。
单次模式： ``benchmark/results/<object>/result.json``（向后兼容，不走本脚本聚合）。

本脚本只读复用 scorecard 的 ``score_object`` / ``_find_result_file``，
**不修改 scorecard**；纯标准库。

用法
----
    python3 benchmark/scripts/trials_aggregate.py \
        --expected benchmark/expectedresults.csv \
        --object benchmark/results/<object> \
        --out benchmark/results/compare/trials_matrix.json \
        [--line-tolerance 1] [--timeout-ms 120000] [--min-trials 2]
"""
import argparse
import json
import os
import re
import sys
from statistics import mean, pstdev

from scorecard import score_object, _find_result_file, load_expected

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_EXPECTED = os.path.join(ROOT, "benchmark", "expectedresults.csv")


# --------------------------------------------------------------------------- #
# trials 检测
# --------------------------------------------------------------------------- #
def detect_trials(obj_dir):
    """返回对象目录下的 trial 子目录列表（自然排序），无则 None。

    规则：目录名匹配 ``trial_\\d+``（允许零填充如 trial_001）。不含合法
    trial 子目录则视为单次模式返回 None。
    """
    trials = []
    if not os.path.isdir(obj_dir):
        return None
    for name in os.listdir(obj_dir):
        full = os.path.join(obj_dir, name)
        if os.path.isdir(full) and re.fullmatch(r"trial_\d+", name):
            trials.append(name)
    if not trials:
        return None
    trials.sort(key=lambda n: int(n.split("_")[1]))
    return trials


# --------------------------------------------------------------------------- #
# 聚合
# --------------------------------------------------------------------------- #
def _good(s, outcome):
    """判定某 sample 在该 trial 是否"判对"。"""
    if s["type"] == "vuln":
        return outcome == "TP"
    return outcome == "TN"


def _accuracy(metrics):
    total = metrics["TP"] + metrics["FN"] + metrics["FP"] + metrics["TN"]
    return (metrics["TP"] + metrics["TN"]) / total if total else 0.0


def aggregate_trials(samples, obj_dir, trials, timeout_ms, line_tolerance=0,
                     majority_k=0):
    """对对象的 N 次 trial 做稳定性聚合。

    Args:
        samples: load_expected 输出。
        obj_dir: 对象目录（含 trial_<i>/ 子目录）。
        trials: detect_trials 返回的 trial 子目录名列表。
        timeout_ms: scorecard 超时阈值。
        line_tolerance: 命中行号容差。
        majority_k: object_pass@majority 的 K；0 表示取 ceil(N/2)。

    Returns:
        dict: 含 trials_expected/actual、sample_pass@1、object_pass@majority、
              acc_mean/acc_std/best/worst/spread、per_sample verdict、per_trial 明细。
    """
    per_trial = []  # (trial, aligned, metrics)
    skipped = []
    for t in trials:
        rp = _find_result_file(os.path.join(obj_dir, t))
        if rp is None:
            skipped.append(t)
            continue
        report, aligned = score_object(samples, rp, timeout_ms,
                                       line_tolerance=line_tolerance)
        per_trial.append((t, aligned, report["metrics"]))

    N = len(per_trial)
    if N == 0:
        return {
            "object": os.path.basename(obj_dir.rstrip(os.sep)),
            "trials_expected": len(trials), "trials_actual": 0,
            "mode": "trials", "error": "无任何有效 trial 结果",
            "skipped": skipped,
        }

    # per-sample verdict
    verdict = {}
    for s in samples:
        ok = 0
        for _t, aligned, _m in per_trial:
            e = next((x for x in aligned if x["id"] == s["id"]), None)
            if e is None:
                continue  # align 通常覆盖全部 sample；缺省视为没报
            good = _good(s, e["outcome"])
            ok += 1 if good else 0
        verdict[s["id"]] = {
            "type": s["type"],
            "pass_all": ok == N,
            "pass_rate": ok / N if N else 0.0,
            "pass_count": ok,
        }

    # 对象级聚合
    pass_all_count = sum(1 for v in verdict.values() if v["pass_all"])
    k = majority_k if majority_k > 0 else (N + 1) // 2  # ceil(N/2)
    pass_maj_count = sum(1 for v in verdict.values() if v["pass_rate"] >= k / N)

    acc_list = [_accuracy(m) for _t, _a, m in per_trial]

    return {
        "object": os.path.basename(obj_dir.rstrip(os.sep)),
        "mode": "trials",
        "trials_expected": len(trials),
        "trials_actual": N,
        "skipped": skipped,
        "line_tolerance": line_tolerance,
        "majority_k": k,
        "sample_pass@1": pass_all_count / len(verdict) if verdict else 0.0,
        "object_pass@majority": pass_maj_count / len(verdict) if verdict else 0.0,
        "sample_pass_rate_mean": mean(v["pass_rate"] for v in verdict.values()) if verdict else 0.0,
        "acc_mean": mean(acc_list) if acc_list else 0.0,
        "acc_std": pstdev(acc_list) if len(acc_list) > 1 else 0.0,
        "best_acc": max(acc_list) if acc_list else 0.0,
        "worst_acc": min(acc_list) if acc_list else 0.0,
        "spread": (max(acc_list) - min(acc_list)) if len(acc_list) > 1 else 0.0,
        "per_sample": verdict,
        "per_trial_acc": [{"trial": t, "acc": _accuracy(m)}
                          for t, _a, m in per_trial],
    }


def load_meta(obj_dir, trials):
    """读取伴生 meta.json（成本/步数），返回每 trial 的 meta dict 或 None。"""
    metas = []
    for t in trials:
        meta_path = os.path.join(obj_dir, t, "meta.json")
        if os.path.isfile(meta_path):
            try:
                with open(meta_path, encoding="utf-8") as fh:
                    metas.append(json.load(fh))
            except (json.JSONDecodeError, OSError):
                metas.append(None)
        else:
            metas.append(None)
    return metas


def main(argv=None):
    ap = argparse.ArgumentParser(description="JSEF trials 稳定性聚合")
    ap.add_argument("--expected", default=DEFAULT_EXPECTED)
    ap.add_argument("--object", required=True, help="对象目录（含 trial_<i>/ 子目录）")
    ap.add_argument("--out", default=None, help="输出 JSON 路径；缺省打印到 stdout")
    ap.add_argument("--line-tolerance", type=int, default=0)
    ap.add_argument("--timeout-ms", type=int, default=120000)
    ap.add_argument("--min-trials", type=int, default=2,
                    help="低于该 trial 数则按单次降级")
    ap.add_argument("--majority-k", type=int, default=0,
                    help="object_pass@majority 的 K；0=自动取 ceil(N/2)")
    args = ap.parse_args(argv)

    samples = load_expected(args.expected)
    trials = detect_trials(args.object)

    if trials is None:
        print("[info] 对象 %s 无合法 trial_*/ 子目录，按单次降级。"
              % args.object, file=sys.stderr)
        return 1

    if len(trials) < args.min_trials:
        print("[info] trial 数 %d < --min-trials %d，按单次降级。"
              % (len(trials), args.min_trials), file=sys.stderr)
        return 1

    result = aggregate_trials(samples, args.object, trials,
                              args.timeout_ms, args.line_tolerance,
                              args.majority_k)
    result["meta"] = {"expected_count": len(samples)}
    metas = load_meta(args.object, trials)
    result["meta"]["cost_usd_avg"] = _avg_meta(metas, "cost_usd")
    result["meta"]["steps_avg"] = _avg_meta(metas, "steps")
    result["meta"]["output_tokens_avg"] = _avg_meta(metas, "output_tokens")

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
        print("[done] trials 聚合已写出: %s" % args.out)
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def _avg_meta(metas, key):
    vals = [m.get(key) for m in metas if isinstance(m, dict) and m.get(key) is not None]
    return mean(vals) if vals else None


if __name__ == "__main__":
    sys.exit(main())
