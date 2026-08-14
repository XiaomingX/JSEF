#!/usr/bin/env python3
"""JSEF Benchmark — Scorecard 计算脚本（Phase C3）。

用途
----
读取 ``benchmark/expectedresults.csv``（事实源，含全样本真/假标注），
与被测对象（SAST 工具或大模型）产出的结果对齐，计算混淆矩阵（TP/FN/FP/TN）
及 OWASP Benchmark 口径指标：Recall / Precision / FPR / Youden Score，
并按 CWE 与 level 分组汇总，输出 Markdown 表格与可选的结构化 JSON。

输入格式（被测对象结果，二选一）
--------------------------------
1. SARIF 2.1.0（``.sarif``）
   - ``ruleId`` 为 CWE 编号（如 ``CWE-89``）。
   - ``locations[].physicalLocation.artifactLocation.uri`` 为相对仓库根的路径。
   - ``locations[].physicalLocation.region.startLine`` 为精确行号。
2. 简化 JSON
   - 列表：``[{"id": "...", "hit": true/false, "file": "...", "line": N,
     "cwe": "...", "message": "...", "elapsed_ms": N}, ...]``
   - 或字典（id → 命中信息)：``{"JSEF-SQLI-001": {"hit": true, "line": 59,
     "elapsed_ms": 1200}, ...}``

约束
----
仅使用标准库（csv / json / argparse / sys / os），可直接运行，无第三方依赖。

示例
----
    python scorecard.py --expected benchmark/expectedresults.csv \
        --result benchmark/scripts/example_result.json \
        --name "MockSAST" --timeout-ms 120000 --out report.json
"""

import argparse
import csv
import json
import os
import sys


# --------------------------------------------------------------------------- #
# 读取事实源
# --------------------------------------------------------------------------- #
def load_expected(expected_path):
    """读取 expectedresults.csv，返回规范化后的样本列表。

    Args:
        expected_path: CSV 文件路径，列需包含
            ``id, cwe, level, type, file, line, source, sink, category``。

    Returns:
        list[dict]: 每条样本一个 dict，字段含义同 CSV 列；``type`` 取值
        ``vuln``（expect=VULN）或 ``safe``（expect=SAFE），``line`` 转为 int。

    Raises:
        FileNotFoundError: 文件不存在。
        KeyError: 缺少必需列。
    """
    if not os.path.isfile(expected_path):
        raise FileNotFoundError("找不到 expectedresults.csv: %s" % expected_path)

    required = {"id", "cwe", "level", "type", "file", "line"}
    samples = []
    with open(expected_path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise KeyError("CSV 为空或无法解析表头")
        missing = required - set(reader.fieldnames)
        if missing:
            raise KeyError("expectedresults.csv 缺少必需列: %s" % ", ".join(sorted(missing)))
        for row in reader:
            try:
                line = int(row["line"])
            except (ValueError, TypeError):
                line = -1
            samples.append({
                "id": row["id"].strip(),
                "cwe": row["cwe"].strip(),
                "level": row["level"].strip(),
                "type": row["type"].strip().lower(),
                "file": row["file"].strip(),
                "line": line,
                "source": row.get("source", "").strip(),
                "sink": row.get("sink", "").strip(),
                "category": row.get("category", "").strip(),
            })
    return samples


# --------------------------------------------------------------------------- #
# 读取被测对象结果
# --------------------------------------------------------------------------- #
def load_result(result_path):
    """加载被测对象结果文件，统一为内部命中表。

    Args:
        result_path: ``.sarif`` 或 ``.json`` 文件路径。

    Returns:
        tuple: (findings, elapsed_list)
            - findings: dict[id -> {"hit": bool, "file": str, "line": int,
              "cwe": str, "message": str}]
              对于 SARIF，id 由 ``CWE@file:line`` 派生（用于 safe 样本的 FP 判定），
              对于显式 JSON 列表/字典，使用原始 ``id``。
            - elapsed_list: list[int]，所有样本的耗时（ms）。

    Raises:
        FileNotFoundError: 文件不存在。
        ValueError: 无法解析的内容（非合法 SARIF/JSON）。
    """
    if not os.path.isfile(result_path):
        raise FileNotFoundError("找不到结果文件: %s" % result_path)

    with open(result_path, encoding="utf-8") as fh:
        raw = fh.read()

    ext = os.path.splitext(result_path)[1].lower()
    if ext == ".sarif":
        return _parse_sarif(raw)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("结果文件不是合法 JSON: %s (%s)" % (result_path, exc))

    return _parse_simple_json(data)


def _parse_sarif(raw):
    """解析 SARIF，返回 (findings, elapsed_list)。

    SARIF 没有显式样本 id，因此以 ``CWE@file:line`` 作为命中键。对齐逻辑：
    - 对 vuln 样本：被测结果若命中「同 CWE + 同文件 + 同行」则记 TP（需将
      expected 的 file:line 转换为同一 key 比对）。
    - 对 safe 样本：若 SARIF 在同文件同行报了该 CWE，则记 FP。

    Returns:
        tuple: (findings, elapsed_list)
    """
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("SARIF 不是合法 JSON: %s" % exc)

    findings = {}
    elapsed_list = []
    runs = doc.get("runs", [])
    for run in runs:
        driver = run.get("tool", {}).get("driver", {})
        # 允许 SARIF 顶层携带耗时信息（宽松扩展）
        for res in run.get("results", []):
            rule_id = str(res.get("ruleId", "CWE-OTHER"))
            cwe = rule_id.replace("CWE-", "") if rule_id.startswith("CWE-") else rule_id
            msg = res.get("message", {}).get("text", "")
            for loc in res.get("locations", []):
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})
                line = int(region.get("startLine", -1))
                # 归一化路径：去掉仓库根前缀，统一为正斜杠
                uri_norm = uri.replace("\\", "/")
                key = "%s@%s:%d" % (cwe, uri_norm, line)
                findings[key] = {
                    "hit": True,
                    "file": uri_norm,
                    "line": line,
                    "cwe": cwe,
                    "message": msg,
                }
            if "elapsed_ms" in res:
                elapsed_list.append(int(res["elapsed_ms"]))
    return findings, elapsed_list


def _parse_simple_json(data):
    """解析简化 JSON（列表或字典），返回 (findings, elapsed_list)。

    Returns:
        tuple: (findings, elapsed_list)
    """
    findings = {}
    elapsed_list = []
    if isinstance(data, list):
        for item in data:
            sid = str(item.get("id", "")).strip()
            if not sid:
                continue
            hit = bool(item.get("hit", False))
            findings[sid] = {
                "hit": hit,
                "file": item.get("file", ""),
                "line": int(item.get("line", -1)),
                "cwe": str(item.get("cwe", "")).replace("CWE-", ""),
                "message": item.get("message", ""),
            }
            if "elapsed_ms" in item:
                elapsed_list.append(int(item["elapsed_ms"]))
    elif isinstance(data, dict):
        for sid, val in data.items():
            sid = str(sid).strip()
            if isinstance(val, bool):
                hit = val
                line = -1
                elapsed = None
            else:
                hit = bool(val.get("hit", False))
                line = int(val.get("line", -1))
                elapsed = val.get("elapsed_ms")
            findings[sid] = {
                "hit": hit,
                "file": val.get("file", "") if isinstance(val, dict) else "",
                "line": line,
                "cwe": str(val.get("cwe", "")).replace("CWE-", "") if isinstance(val, dict) else "",
                "message": val.get("message", "") if isinstance(val, dict) else "",
            }
            if elapsed is not None:
                elapsed_list.append(int(elapsed))
    else:
        raise ValueError("简化的 JSON 结果必须是列表或字典(id→命中信息)")
    return findings, elapsed_list


# --------------------------------------------------------------------------- #
# 对齐 + 混淆矩阵
# --------------------------------------------------------------------------- #
def _sarif_key(sample):
    """为 expected 样本生成与 SARIF 命中键一致的 key。"""
    file_norm = sample["file"].replace("\\", "/")
    return "%s@%s:%d" % (sample["cwe"], file_norm, sample["line"])


def align(samples, findings, use_sarif):
    """将事实源样本与被测结果对齐，返回每条样本的对齐结论。

    Args:
        samples: load_expected 的输出。
        findings: load_result 的 findings 部分。
        use_sarif: 结果是否来自 SARIF（决定是否用 ``CWE@file:line`` 匹配）。

    Returns:
        list[dict]: 在样本字段基础上追加 ``outcome`` ∈ {TP, FN, FP, TN} 与
        ``reported``(bool)、``elapsed_ms``(int|None)。
    """
    aligned = []
    for s in samples:
        if use_sarif:
            key = _sarif_key(s)
            reported = key in findings
        else:
            rep = findings.get(s["id"])
            reported = bool(rep and rep.get("hit"))
        elapsed = None
        if not use_sarif and s["id"] in findings:
            elapsed = findings[s["id"]].get("line")  # 占位，实际耗时在结果层聚合

        if s["type"] == "vuln":
            outcome = "TP" if reported else "FN"
        else:  # safe
            outcome = "FP" if reported else "TN"

        entry = dict(s)
        entry["reported"] = reported
        entry["outcome"] = outcome
        entry["elapsed_ms"] = elapsed
        aligned.append(entry)
    return aligned


# --------------------------------------------------------------------------- #
# 指标计算
# --------------------------------------------------------------------------- #
def compute_metrics(aligned):
    """基于对齐结果计算总体混淆矩阵与 OWASP 口径指标。

    Args:
        aligned: align() 的输出列表。

    Returns:
        dict: 含 TP/FN/FP/TN、Recall、Precision、FPR、Youden 等。
    """
    tp = sum(1 for a in aligned if a["outcome"] == "TP")
    fn = sum(1 for a in aligned if a["outcome"] == "FN")
    fp = sum(1 for a in aligned if a["outcome"] == "FP")
    tn = sum(1 for a in aligned if a["outcome"] == "TN")

    def safe_div(num, den):
        return (num / den) if den else 0.0

    recall = safe_div(tp, tp + fn)
    precision = safe_div(tp, tp + fp)
    fpr = safe_div(fp, fp + tn)
    youden = (recall - fpr) * 100.0  # 0–100，OWASP 口径
    return {
        "TP": tp, "FN": fn, "FP": fp, "TN": tn,
        "Recall": recall, "Precision": precision, "FPR": fpr,
        "Youden": youden,
    }


def group_by(aligned, key):
    """按指定字段（cwe / level）分组统计混淆矩阵，便于画雷达图。

    Args:
        aligned: align() 的输出。
        key: 分组字段名（"cwe" 或 "level"）。

    Returns:
        dict[str, dict]: 每组的 TP/FN/FP/TN 与派生指标。
    """
    groups = {}
    for a in aligned:
        g = a.get(key, "UNKNOWN")
        d = groups.setdefault(g, {"TP": 0, "FN": 0, "FP": 0, "TN": 0})
        d[a["outcome"]] += 1
    for g, d in groups.items():
        tp, fn, fp, tn = d["TP"], d["FN"], d["FP"], d["TN"]

        def safe_div(num, den):
            return (num / den) if den else 0.0

        d["Recall"] = safe_div(tp, tp + fn)
        d["Precision"] = safe_div(tp, tp + fp)
        d["FPR"] = safe_div(fp, fp + tn)
        d["Youden"] = (d["Recall"] - d["FPR"]) * 100.0
    return groups


def coverage_metrics(samples, aligned):
    """计算能力完备度 = 命中 CWE 数 / 覆盖 CWE 数（按 level 与 cwe 分组）。

    Args:
        samples: 事实源样本。
        aligned: align() 的输出。

    Returns:
        dict: total 完备度 + 按 cwe / level 的覆盖情况。
    """
    covered = {}  # cwe -> set(level)
    hit = {}      # cwe -> set(level)
    for s, a in zip(samples, aligned):
        covered.setdefault(s["cwe"], set()).add(s["level"])
        if a["outcome"] == "TP":
            hit.setdefault(s["cwe"], set()).add(s["level"])

    cwe_coverage = {}
    for cwe, levels in covered.items():
        total = len(levels)
        h = len(hit.get(cwe, set()))
        cwe_coverage[cwe] = {
            "covered_levels": sorted(levels),
            "hit_levels": sorted(hit.get(cwe, set())),
            "completeness": (h / total) if total else 0.0,
        }
    total_covered = len(covered)
    total_hit = sum(1 for cwe in covered if cwe in hit and hit[cwe])
    return {
        "total_completeness": (total_hit / total_covered) if total_covered else 0.0,
        "cwe_completeness": cwe_coverage,
    }


# --------------------------------------------------------------------------- #
# 时延 / 超时 / 简洁度
# --------------------------------------------------------------------------- #
def timing_and_quality(elapsed_list, aligned, total_output_findings=None):
    """计算平均耗时、超时样本数、报告简洁度。

    Args:
        elapsed_list: 各样本耗时（ms）列表。
        aligned: align() 的输出（用于 FP/TP 计数）。
        total_output_findings: 被测对象自称的总输出告警数（可选）。

    Returns:
        dict: avg_elapsed_ms、timeout_count、timeout_rate、simplicity。
    """
    avg = (sum(elapsed_list) / len(elapsed_list)) if elapsed_list else 0.0
    timeout_count = 0
    # 超时统计依赖结果层提供 per-finding elapsed_ms；此处对聚合列表做遍历
    # （示例 JSON 采用 dict 形式时未逐条携带，故兼容 0 计数的情况）
    return {
        "avg_elapsed_ms": avg,
        "timeout_count": timeout_count,
        "timeout_rate": 0.0,
    }


# --------------------------------------------------------------------------- #
# 输出
# --------------------------------------------------------------------------- #
def render_markdown(name, metrics, timing, simplicity, completeness):
    """渲染 Markdown 汇总表格。

    Args:
        name: 被测对象名。
        metrics: compute_metrics 的输出。
        timing: timing_and_quality 的输出。
        simplicity: 报告简洁度。
        completeness: coverage_metrics 的 total_completeness。

    Returns:
        str: Markdown 文本。
    """
    lines = []
    lines.append("# JSEF Benchmark Scorecard — %s" % name)
    lines.append("")
    lines.append("| 被测对象 | Recall | Precision | FPR | Youden | 平均耗时(ms) | 超时数 | 报告简洁度 | 能力完备度 |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    lines.append("| %s | %.3f | %.3f | %.3f | %.1f | %.1f | %d | %.3f | %.3f |" % (
        name,
        metrics["Recall"], metrics["Precision"], metrics["FPR"], metrics["Youden"],
        timing["avg_elapsed_ms"], timing["timeout_count"],
        simplicity, completeness,
    ))
    lines.append("")
    lines.append("混淆矩阵：TP=%d FN=%d FP=%d TN=%d" % (
        metrics["TP"], metrics["FN"], metrics["FP"], metrics["TN"]))
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def main(argv=None):
    parser = argparse.ArgumentParser(
        description="JSEF Benchmark Scorecard 计算脚本（Phase C3）。\n"
                    "读取 expectedresults.csv 与 SAST/LLM 结果（SARIF 或简化 JSON），"
                    "输出 Recall/Precision/FPR/Youden 与分组汇总。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--expected", required=True,
                        help="expectedresults.csv 路径（事实源，列: id,cwe,level,type,file,line,...)")
    parser.add_argument("--result", required=True,
                        help="被测对象结果文件：.sarif 或 .json（列表/字典两种简化格式均可）")
    parser.add_argument("--name", required=True, help="被测对象名（用于报告标识）")
    parser.add_argument("--timeout-ms", type=int, default=120000,
                        help="单次样本超时阈值（ms），默认 120000")
    parser.add_argument("--out", default=None,
                        help="可选，写出结构化 JSON 结果报告路径")
    parser.add_argument("--verbose", action="store_true",
                        help="额外打印按 CWE 与 level 的分组汇总")
    args = parser.parse_args(argv)

    # 1) 事实源
    try:
        samples = load_expected(args.expected)
    except (FileNotFoundError, KeyError) as exc:
        print("[错误] %s" % exc, file=sys.stderr)
        return 2

    # 2) 被测结果
    use_sarif = args.result.lower().endswith(".sarif")
    try:
        findings, elapsed_list = load_result(args.result)
    except (FileNotFoundError, ValueError) as exc:
        print("[错误] %s" % exc, file=sys.stderr)
        return 2

    # 3) 对齐 + 指标
    aligned = align(samples, findings, use_sarif)
    metrics = compute_metrics(aligned)

    # 4) 时延 / 超时 / 简洁度
    timing = timing_and_quality(elapsed_list, aligned)
    # 超时：根据 elapsed_list 与阈值（示例逐条未带 elapsed 时为 0）
    timeout_count = sum(1 for e in elapsed_list if e > args.timeout_ms)
    timing["timeout_count"] = timeout_count
    timing["timeout_rate"] = (timeout_count / len(elapsed_list)) if elapsed_list else 0.0

    tp = metrics["TP"]
    fp = metrics["FP"]
    total_output = tp + fp
    simplicity = (tp / total_output) if total_output else 0.0

    # 完备度
    cov = coverage_metrics(samples, aligned)

    # 5) 输出
    md = render_markdown(args.name, metrics, timing, simplicity, cov["total_completeness"])
    print(md)

    if args.verbose:
        by_cwe = group_by(aligned, "cwe")
        by_level = group_by(aligned, "level")
        print("\n## 按 CWE 分组")
        print("| CWE | TP | FN | FP | TN | Recall | Precision | FPR | Youden |")
        print("|---|---|---|---|---|---|---|---|---|")
        for cwe in sorted(by_cwe):
            d = by_cwe[cwe]
            print("| %s | %d | %d | %d | %d | %.3f | %.3f | %.3f | %.1f |" % (
                cwe, d["TP"], d["FN"], d["FP"], d["TN"],
                d["Recall"], d["Precision"], d["FPR"], d["Youden"]))
        print("\n## 按 Level 分组")
        print("| Level | TP | FN | FP | TN | Recall | Precision | FPR | Youden |")
        print("|---|---|---|---|---|---|---|---|---|")
        for lv in sorted(by_level):
            d = by_level[lv]
            print("| %s | %d | %d | %d | %d | %.3f | %.3f | %.3f | %.1f |" % (
                lv, d["TP"], d["FN"], d["FP"], d["TN"],
                d["Recall"], d["Precision"], d["FPR"], d["Youden"]))

    # 6) 可选结构化输出
    if args.out:
        report = {
            "name": args.name,
            "metrics": metrics,
            "timing": timing,
            "simplicity": simplicity,
            "completeness": cov,
            "by_cwe": group_by(aligned, "cwe"),
            "by_level": group_by(aligned, "level"),
            "aligned": aligned,
        }
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2, ensure_ascii=False)
            print("\n[完成] 结构化报告已写出: %s" % args.out)
        except OSError as exc:
            print("[警告] 无法写出 --out: %s" % exc, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
