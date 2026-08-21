#!/usr/bin/env python3
"""JSEF Benchmark — 一键横向对比：多个模型/SAST 结果做排行，看谁强谁弱。

给定一个含多个 ``<object>/`` 结果子目录的根目录（每个对象含 result.json 或 *.sarif），
调用 scorecard 的 ``--results-dir`` 交叉矩阵算出各对象的混淆矩阵指标，然后：

1. 计算「做题正确率」= (TP + TN) / (TP + FN + FP + TN) —— 全样本做对比例
   （含 vuln 报对 + safe 不报），是最直观的"模型质量"锚点。
2. 输出 Markdown 排行表 ``compare.md``（按正确率排序）。
3. 用 matplotlib 输出 ``ranking.png``（横向条形）与 ``radar.png``（五维雷达）。

用法
----
  python3 compare_models.py \
      --results-dir benchmark/results \
      --expected benchmark/expectedresults.csv \
      --out-dir benchmark/results/compare \
      --timeout-ms 120000

依赖：scorecard.py（subprocess 调用，解耦不改动）、matplotlib、requests（仅 runner 用）。
"""
import argparse
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
SCORECARD = os.path.join(ROOT, "benchmark", "scripts", "scorecard.py")

# trials 聚合模块（benchmark/scripts/ 下），需加入 sys.path 才能 import
sys.path.insert(0, os.path.join(ROOT, "benchmark", "scripts"))
from trials_aggregate import detect_trials, aggregate_trials, load_meta


def run_scorecard(results_dir, expected, timeout_ms, out_path):
    """subprocess 调 scorecard --results-dir，返回 cross_matrix dict。"""
    cmd = [
        sys.executable, SCORECARD,
        "--expected", expected,
        "--results-dir", results_dir,
        "--out", out_path,
        "--timeout-ms", str(timeout_ms),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    if proc.returncode != 0:
        sys.stderr.write("[scorecard stderr]\n" + proc.stderr[-2000:] + "\n")
        raise RuntimeError("scorecard 交叉矩阵运行失败 (exit %d)" % proc.returncode)
    if not os.path.isfile(out_path):
        raise RuntimeError("scorecard 未产出 cross_matrix: %s" % out_path)
    with open(out_path, encoding="utf-8") as fh:
        return json.load(fh)


def accuracy(m):
    """正确率 = (TP+TN)/total，全样本做对比例。"""
    total = m["TP"] + m["FN"] + m["FP"] + m["TN"]
    return (m["TP"] + m["TN"]) / total if total else 0.0


def build_table(cross, trials_rows=None):
    """从 cross_matrix 构造排行行（按正确率降序）。

    trials_rows: 可选，trials 模式对象构造的行（带 pass@1/acc_std/spread 字段）。
    """
    rows = []
    for o in cross["objects"]:
        m = o["metrics"]
        rows.append({
            "name": o["name"],
            "acc": accuracy(m),
            "recall": m["Recall"],
            "precision": m["Precision"],
            "f1": m["F1"],
            "fpr": m["FPR"],
            "mcc": m["MCC"],
            "exact": m["exact_hit_rate"] if m["exact_hit_rate"] is not None else 0.0,
            "tp": m["TP"], "fn": m["FN"], "fp": m["FP"], "tn": m["TN"],
            # trials 相关字段（单次对象为 None）
            "pass@1": None, "pass@majority": None,
            "acc_std": None, "spread": None,
            "cost": None, "steps": None, "out_tok": None, "trials": None,
        })
    if trials_rows:
        rows.extend(trials_rows)
    rows.sort(key=lambda r: r["acc"], reverse=True)
    return rows


def collect_trials_rows(results_dir, expected, timeout_ms, line_tolerance,
                        min_trials, majority_k):
    """遍历 results_dir 下每个对象，检测并聚合 trials 模式对象。

    返回 (trials_rows, trials_objects)；单次对象返回空（交由 scorecard 处理）。
    """
    from scorecard import load_expected
    samples = load_expected(expected)
    rows = []
    trials_objects = {}
    if not os.path.isdir(results_dir):
        return rows, trials_objects
    for name in sorted(os.listdir(results_dir)):
        obj_dir = os.path.join(results_dir, name)
        if not os.path.isdir(obj_dir):
            continue
        trials = detect_trials(obj_dir)
        if trials is None or len(trials) < min_trials:
            continue  # 单次模式 → 交给 scorecard cross_matrix
        agg = aggregate_trials(samples, obj_dir, trials, timeout_ms,
                               line_tolerance, majority_k)
        if agg.get("error") or agg.get("trials_actual", 0) == 0:
            continue
        metas = load_meta(obj_dir, trials)
        avg = lambda k: _avg_meta(metas, k)  # noqa: E731
        # 排序锚点用 sample_pass@1（DeepSwe 全过语义）
        rows.append({
            "name": agg["object"],
            "acc": agg["sample_pass@1"],
            "recall": None, "precision": None, "f1": None,
            "fpr": None, "mcc": None, "exact": None,
            "tp": None, "fn": None, "fp": None, "tn": None,
            "pass@1": agg["sample_pass@1"],
            "pass@majority": agg["object_pass@majority"],
            "acc_std": agg["acc_std"],
            "spread": agg["spread"],
            "cost": avg("cost_usd"), "steps": avg("steps"),
            "out_tok": avg("output_tokens"),
            "trials": "%d/%d" % (agg["trials_actual"], agg["trials_expected"]),
        })
        trials_objects[agg["object"]] = agg
    return rows, trials_objects


def _avg_meta(metas, key):
    vals = [m.get(key) for m in metas if isinstance(m, dict) and m.get(key) is not None]
    return sum(vals) / len(vals) if vals else None


def render_markdown(rows, meta):
    lines = []
    lines.append("# JSEF 多模型横向对比报告\n")
    lines.append("> 生成时间：%s　|　样本总数：%s\n"
                 % (meta.get("generated_at", "?"), meta.get("expected_count", "?")))
    lines.append("> **正确率** = (TP+TN)/全部样本 = 做题做对比例（含 vuln 报对 + safe 不报）。"
                 "**Recall**=1−漏报率，**FPR**=误报率。")
    lines.append("> trials 对象（含 trial_*/ 子目录）：**Pass@1**=N 次全过的做题正确率（DeepSWE 语义），"
                 "另有 std/spread/成本/步数维度。")
    lines.append("")
    lines.append("| 排名 | 对象 | 正确率 | Pass@1 | Recall | Precision | F1 | 误报率FPR | 定位精确率 | std/spread | 成本$/步数 |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for i, r in enumerate(rows, 1):
        acc = ("%.1f%%" % (r["acc"] * 100)) if r["acc"] is not None else "-"
        pass1 = ("%.1f%%" % (r["pass@1"] * 100)) if r["pass@1"] is not None else "-"
        recall = ("%.3f" % r["recall"]) if r["recall"] is not None else "-"
        prec = ("%.3f" % r["precision"]) if r["precision"] is not None else "-"
        f1 = ("%.3f" % r["f1"]) if r["f1"] is not None else "-"
        fpr = ("%.3f" % r["fpr"]) if r["fpr"] is not None else "-"
        exact = ("%.3f" % r["exact"]) if r["exact"] is not None else "-"
        std = ("%.3f/%.3f" % (r["acc_std"], r["spread"])) if r["acc_std"] is not None else "-"
        cost = ("%.2f/%.0f" % (r["cost"], r["steps"])) if r["cost"] is not None else "-"
        lines.append(
            "| %d | %s | **%s** | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (i, r["name"], acc, pass1, recall, prec, f1, fpr, exact, std, cost))
    lines.append("")
    lines.append("## 解读")
    lines.append("- 正确率：模型整体「做题正确」比例，越高越好（首要排序锚点）。")
    lines.append("- Recall（召回率）= 1 − 漏报率：漏报越少越安全，最要紧。")
    lines.append("- FPR（误报率）：不是漏洞却报成漏洞的比例，越高越浪费复核人力。")
    lines.append("- 权衡：Recall 与 FPR 常此消彼长，看 F1（调和平均）与 MCC 综合平衡。")
    lines.append("")
    return "\n".join(lines)


def _setup_cjk_font():
    """配置 matplotlib 使用系统中文字体，避免中文标签渲染为方框。"""
    import matplotlib
    matplotlib.use("Agg")
    from matplotlib import font_manager, rcParams
    import glob

    candidates = [
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        "/System/Library/Fonts/Hiragino Sans GB.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
        "/System/Library/Fonts/Supplemental/Songti.ttc",
    ]
    chosen = None
    for pat in candidates:
        hits = glob.glob(pat)
        if hits:
            try:
                font_manager.fontManager.addfont(hits[0])
                chosen = font_manager.FontProperties(fname=hits[0]).get_name()
                break
            except Exception:
                continue
    if chosen:
        rcParams["font.sans-serif"] = [chosen] + rcParams.get("font.sans-serif", [])
        rcParams["axes.unicode_minus"] = False
    return chosen


def render_ranking_png(rows, out_path):
    """横向条形图：按正确率排序。trials 对象 recall/f1 为 None 时仅画 acc。"""
    _setup_cjk_font()
    import matplotlib.pyplot as plt

    names = [r["name"] for r in rows]
    accs = [r["acc"] * 100 for r in rows]
    nan = float("nan")
    recalls = [(r["recall"] * 100) if r["recall"] is not None else nan for r in rows]
    f1s = [(r["f1"] * 100) if r["f1"] is not None else nan for r in rows]

    fig, ax = plt.subplots(figsize=(10, max(4, len(names) * 0.7)))
    y = list(range(len(names)))
    ax.barh(y, f1s, height=0.25, label="F1", color="#4C72B0")
    ax.barh([v - 0.28 for v in y], recalls, height=0.25, label="Recall", color="#55A868")
    ax.barh([v + 0.28 for v in y], accs, height=0.25, label="正确率(Acc)", color="#C44E52")
    ax.set_yticks(y)
    ax.set_yticklabels(names)
    ax.invert_yaxis()
    ax.set_xlabel("百分比 (%)")
    ax.set_xlim(0, 105)
    ax.set_title("JSEF 多模型横向对比（按正确率排序）")
    ax.legend(loc="lower right")
    ax.grid(axis="x", linestyle=":", alpha=0.5)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def render_radar_png(rows, out_path):
    """五维雷达图：Recall / Precision / F1 / (1-FPR) / 定位精确率。"""
    _setup_cjk_font()
    import numpy as np
    import matplotlib.pyplot as plt

    labels = ["Recall", "Precision", "F1", "非误报(1-FPR)", "定位精确"]
    n = len(labels)
    angles = np.linspace(0, 2 * np.pi, n, endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(7, 7), subplot_kw=dict(polar=True))
    # 雷达图需要完整五维指标，仅画单次对象（trials 对象 recall/precision 为 None，跳过）
    for r in rows:
        if any(r[k] is None for k in ("recall", "precision", "f1", "fpr", "exact")):
            continue
        vals = [r["recall"], r["precision"], r["f1"],
                1 - r["fpr"], r["exact"]]
        vals += vals[:1]
        ax.plot(angles, vals, label=r["name"], linewidth=1.8)
        ax.fill(angles, vals, alpha=0.06)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 1)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.legend(loc="upper right", bbox_to_anchor=(1.35, 1.1), fontsize=9)
    ax.set_title("JSEF 多模型能力雷达", pad=20)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description="多模型横向对比（排行 + 雷达图）")
    ap.add_argument("--results-dir", default=os.path.join(ROOT, "benchmark", "results"),
                    help="含多个 <object>/ 子目录的根目录")
    ap.add_argument("--expected", default=os.path.join(ROOT, "benchmark", "expectedresults.csv"))
    ap.add_argument("--out-dir", default=os.path.join(ROOT, "benchmark", "results", "compare"))
    ap.add_argument("--timeout-ms", type=int, default=120000)
    ap.add_argument("--line-tolerance", type=int, default=0, help="命中行号容差")
    ap.add_argument("--min-trials", type=int, default=2,
                    help="对象至少含多少 trial_* 子目录才按 trials 聚合；低于按单次")
    ap.add_argument("--majority-k", type=int, default=0,
                    help="object_pass@majority 的 K；0=自动取 ceil(N/2)")
    ap.add_argument("--skip-plots", action="store_true", help="只出 Markdown，不生成 PNG")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    cross_path = os.path.join(args.out_dir, "cross_matrix.json")
    cross = run_scorecard(args.results_dir, args.expected, args.timeout_ms, cross_path)

    # 检测 trials 模式对象并聚合（单次对象由 scorecard 处理）
    trials_rows, trials_objects = collect_trials_rows(
        args.results_dir, args.expected, args.timeout_ms,
        args.line_tolerance, args.min_trials, args.majority_k)
    rows = build_table(cross, trials_rows)

    # trials 聚合矩阵单独落盘
    if trials_objects:
        trials_matrix_path = os.path.join(args.out_dir, "trials_matrix.json")
        with open(trials_matrix_path, "w", encoding="utf-8") as fh:
            json.dump({"objects": list(trials_objects.values()),
                       "meta": {"expected_count": cross["meta"].get("expected_count"),
                                "generated_at": cross["meta"].get("generated_at")}},
                      fh, indent=2, ensure_ascii=False)
        print("[done] trials 聚合矩阵: %s" % trials_matrix_path)

    # Markdown 排行
    md = render_markdown(rows, cross["meta"])
    md_path = os.path.join(args.out_dir, "compare.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(md)
    print("[done] Markdown 排行: %s" % md_path)

    # 终端摘要
    print("\n%2s  %-22s %8s %8s %8s %8s" % ("#", "对象", "正确率", "Pass@1", "std", "spread"))
    for i, r in enumerate(rows, 1):
        acc = ("%7.1f%%" % (r["acc"] * 100)) if r["acc"] is not None else "     -"
        pass1 = ("%7.1f%%" % (r["pass@1"] * 100)) if r["pass@1"] is not None else "     -"
        std = ("%7.3f" % r["acc_std"]) if r["acc_std"] is not None else "     -"
        spread = ("%7.3f" % r["spread"]) if r["spread"] is not None else "     -"
        print("%2d  %-22s %s %s %s %s" % (i, r["name"], acc, pass1, std, spread))

    if not args.skip_plots:
        try:
            rank_png = os.path.join(args.out_dir, "ranking.png")
            radar_png = os.path.join(args.out_dir, "radar.png")
            render_ranking_png(rows, rank_png)
            render_radar_png(rows, radar_png)
            print("[done] 条形图: %s\n[done] 雷达图: %s" % (rank_png, radar_png))
        except Exception as exc:  # noqa: BLE001 — 画图失败不阻断排行
            sys.stderr.write("[warn] 图表生成失败（已跳过）: %s\n" % exc)
    print("[done] 交叉矩阵: %s" % cross_path)


if __name__ == "__main__":
    main()
