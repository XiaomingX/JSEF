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
   - 允许每条 ``results[]`` 携带 ``elapsed_ms``（单 finding 耗时，ms）。
2. 简化 JSON
   - 列表：``[{"id": "...", "hit": true/false, "file": "...", "line": N,
     "cwe": "...", "message": "...", "elapsed_ms": N}, ...]``
   - 或字典（id → 命中信息)：``{"JSEF-SQLI-001": {"hit": true, "line": 59,
     "elapsed_ms": 1200}, ...}``
   - 列表/字典项均可携带 ``elapsed_ms``（单 finding 耗时，ms），会被透传到
     aligned 条目用于真实时延/超时统计。

新增能力（本次升级）
-------------------
- **真实时延/超时**：``timing_and_quality`` 输出 avg / p50 / p95 / max /
  count / timeout_count / timeout_rate，超时阈值由 ``--timeout-ms`` 控制。
- **定位精度 CAP-12**：``--line-tolerance``（默认 1）控制命中行的容差。
  ``exact_hit``（行号完全相等）→ 计入 TP 且定位精确；``near_hit``
  （|result_line - expected_line| <= tolerance 且 >0）→ 仍算 TP 但
  ``exact_location=false``。容差只影响定位精度统计，不改变 TP/FN。
  **默认值设为 1**：CHECKPOINT 注释行在 sink 行上方，工具通常按 sink 行报告，
  差值恒为 1，容差 1 消除该系统性偏移，避免 ``exact_hit_rate`` 恒为 0。
  新增指标 ``exact_hit_rate``、``near_hit_rate``。
- **综合指标**：``compute_metrics`` 新增 ``F1`` 与 ``MCC``（行业标准的
  调和平均与马修斯相关系数）。
- **多对象交叉矩阵**：``--results-dir <dir>``（与 ``--result`` 互斥）。遍历
  ``<dir>/<object>/`` 下 ``result.json`` 或 ``*.sarif``，对每个对象算分并
  聚合为 ``cross_matrix``，写出 ``cross_matrix.json``（``--out`` 指定路径；
  若 ``--out`` 为目录则在其中写 ``cross_matrix.json``）。
- **报告增强**：``render_markdown`` 表格增加 F1 / MCC / 定位精度
  （``exact_hit_rate``）列；``--verbose`` 仍按 CWE / level 分组。

约束
----
仅使用标准库（csv / json / argparse / sys / os），可直接运行，无第三方依赖。
单对象 ``--result`` 模式保持向后兼容（example_result.json 仍可跑）。

示例
----
    # 单对象
    python scorecard.py --expected benchmark/expectedresults.csv \
        --result benchmark/scripts/example_result.json \
        --name "MockSAST" --timeout-ms 120000 --out report.json

    # 多对象交叉矩阵
    python scorecard.py --expected benchmark/expectedresults.csv \
        --results-dir /tmp/results --out /tmp/cross_matrix.json

    # 定位精度容差
    python scorecard.py --expected expectedresults.csv \
        --result r.json --name X --line-tolerance 2
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
            # trace 列可选：逗号分隔的 file:line 节点列表（entry->critical_operation 中间链）
            trace_raw = (row.get("trace") or "").strip()
            trace_nodes = [t.strip() for t in trace_raw.split(",") if t.strip()] if trace_raw else []
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
                "trace": trace_nodes,
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
            locs = res.get("locations", [])
            trace_nodes = []
            for loc in locs:
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
                    "elapsed_ms": int(res["elapsed_ms"]) if "elapsed_ms" in res else None,
                }
                # 多个 physicalLocation 视为推理路径 trace（file:line 节点）
                if len(locs) > 1:
                    trace_nodes.append("%s:%d" % (uri_norm, line))
            # 第一个 location 作为主 finding，其余位置汇总到 trace
            if locs:
                first = locs[0]
                fphys = first.get("physicalLocation", {})
                furi = fphys.get("artifactLocation", {}).get("uri", "").replace("\\", "/")
                fline = int(fphys.get("region", {}).get("startLine", -1))
                fkey = "%s@%s:%d" % (cwe, furi, fline)
                if fkey in findings:
                    findings[fkey]["trace"] = trace_nodes
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
            elapsed = item.get("elapsed_ms")
            trace = item.get("trace") or []
            if isinstance(trace, str):
                trace = [t.strip() for t in trace.split(",") if t.strip()]
            plan = item.get("plan") or []
            if isinstance(plan, str):
                plan = [p.strip() for p in plan.split(",") if p.strip()]
            findings[sid] = {
                "hit": hit,
                "file": item.get("file", ""),
                "line": int(item.get("line", -1)),
                "cwe": str(item.get("cwe", "")).replace("CWE-", ""),
                "message": item.get("message", ""),
                "elapsed_ms": int(elapsed) if elapsed is not None else None,
                "trace": list(trace),
                "plan": list(plan),
            }
            if elapsed is not None:
                elapsed_list.append(int(elapsed))
    elif isinstance(data, dict):
        for sid, val in data.items():
            sid = str(sid).strip()
            if isinstance(val, bool):
                hit = val
                line = -1
                elapsed = None
                file_ = ""
                cwe = ""
                message = ""
                trace = []
            else:
                hit = bool(val.get("hit", False))
                line = int(val.get("line", -1))
                elapsed = val.get("elapsed_ms")
                file_ = val.get("file", "")
                cwe = str(val.get("cwe", "")).replace("CWE-", "")
                message = val.get("message", "")
                trace = val.get("trace") or []
                if isinstance(trace, str):
                    trace = [t.strip() for t in trace.split(",") if t.strip()]
                plan = val.get("plan") or []
                if isinstance(plan, str):
                    plan = [p.strip() for p in plan.split(",") if p.strip()]
            findings[sid] = {
                "hit": hit,
                "file": file_,
                "line": line,
                "cwe": cwe,
                "message": message,
                "elapsed_ms": int(elapsed) if elapsed is not None else None,
                "trace": list(trace),
                "plan": list(plan),
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


def align(samples, findings, use_sarif, line_tolerance=0):
    """将事实源样本与被测结果对齐，返回每条样本的对齐结论。

    Args:
        samples: load_expected 的输出。
        findings: load_result 的 findings 部分。
        use_sarif: 结果是否来自 SARIF（决定是否用 ``CWE@file:line`` 匹配）。
        line_tolerance: 命中行号容差（int，默认 0）。仅用于定位精度统计，
            不影响 TP/FN 判定（命中即 TP）。

    Returns:
        list[dict]: 在样本字段基础上追加 ``outcome`` ∈ {TP, FN, FP, TN}、
        ``reported``(bool)、``elapsed_ms``(int|None)、``result_line``(int|None，
        被测结果标注的行号)、``exact_location``(bool，定位是否精确)、
        ``result_trace``(list[str]，被测对象声明的推理路径节点)、
        ``result_cwe``(str|None，被测结果声明的 CWE 编号)、
        ``cwe_correct``(bool|None，TP 样本中 CWE 是否与 expected 一致；非 TP 为 None)。

        定位精度判定（仅对 vuln 且 reported 的样本）：
        - ``exact_hit``：result_line 与 expected line 完全相等。
        - ``near_hit``：|result_line - expected_line| <= line_tolerance 且 >0。
        - 容差内命中仍计入 TP，但 ``exact_location`` 仅在 exact_hit 时为 True。
    """
    aligned = []
    for s in samples:
        if use_sarif:
            key = _sarif_key(s)
            rep = findings.get(key)
            reported = key in findings
        else:
            rep = findings.get(s["id"])
            reported = bool(rep and rep.get("hit"))

        elapsed = None
        result_line = None
        exact_location = False
        near_hit = False
        result_trace = []
        result_cwe = None
        result_plan = []
        cwe_correct = None
        if rep is not None:
            elapsed = rep.get("elapsed_ms")
            result_line = rep.get("line")
            result_trace = list(rep.get("trace") or [])
            result_plan = list(rep.get("plan") or [])
            result_cwe = str(rep.get("cwe") or "").strip().lstrip("CWE-").lstrip("cwe-") or None
            if reported and s["type"] == "vuln" and isinstance(result_line, int) and result_line >= 0:
                diff = abs(result_line - s["line"])
                if diff == 0:
                    exact_location = True
                    near_hit = True
                elif line_tolerance > 0 and diff <= line_tolerance:
                    # near_hit：容差内命中但非精确行
                    near_hit = True

        if s["type"] == "vuln":
            outcome = "TP" if reported else "FN"
        else:  # safe
            outcome = "FP" if reported else "TN"

        # CWE 精确度：仅对 TP 样本计算（FP/TN/FN 无意义）
        if outcome == "TP" and result_cwe is not None:
            expected_cwe = str(s.get("cwe") or "").strip().lstrip("CWE-").lstrip("cwe-")
            cwe_correct = (result_cwe == expected_cwe)

        entry = dict(s)
        entry["reported"] = reported
        entry["outcome"] = outcome
        entry["elapsed_ms"] = elapsed
        entry["result_line"] = result_line
        entry["exact_location"] = exact_location
        entry["near_hit"] = near_hit
        entry["result_trace"] = result_trace
        entry["result_cwe"] = result_cwe
        entry["result_plan"] = result_plan
        entry["cwe_correct"] = cwe_correct
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
        dict: 含 TP/FN/FP/TN、Recall、Precision、FPR、Youden、F1、MCC、
        定位精度（exact_hit_rate / near_hit_rate）。
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

    # F1 = 2*P*R/(P+R)，除零返回 0.0
    f1 = safe_div(2 * precision * recall, precision + recall)

    # MCC = (TP*TN - FP*FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))
    denom = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    mcc = (tp * tn - fp * fn) / (denom ** 0.5) if denom > 0 else 0.0

    # 定位精度（仅对 vuln 应报且命中 TP 的样本统计）
    reported_hit = [a for a in aligned if a["outcome"] == "TP"]
    exact_hit = sum(1 for a in reported_hit if a.get("exact_location"))
    near_hit = sum(1 for a in reported_hit if a.get("near_hit"))
    exact_hit_rate = safe_div(exact_hit, len(reported_hit)) if reported_hit else 0.0
    near_hit_rate = safe_div(near_hit, len(reported_hit)) if reported_hit else 0.0

    # CWE 精确度：TP 中被测对象 CWE 与 expected CWE 精确匹配率。
    # 仅统计被测对象明确上报了 CWE（result_cwe 非 None）的 TP 样本；
    # 向后兼容：旧结果无 cwe 字段时 cwe_accuracy=None，不破坏既有流程。
    tp_with_cwe = [a for a in reported_hit if a.get("cwe_correct") is not None]
    cwe_correct_count = sum(1 for a in tp_with_cwe if a["cwe_correct"])
    cwe_accuracy = (
        (cwe_correct_count / len(tp_with_cwe)) if tp_with_cwe else None
    )

    return {
        "TP": tp, "FN": fn, "FP": fp, "TN": tn,
        "Recall": recall, "Precision": precision, "FPR": fpr,
        "Youden": youden, "F1": f1, "MCC": mcc,
        "exact_hit_rate": exact_hit_rate, "near_hit_rate": near_hit_rate,
        # CWE 精确度（null = 结果文件未提供 CWE 字段，不计入评分）
        "cwe_accuracy": cwe_accuracy,
        "cwe_reported_count": len(tp_with_cwe),
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
        d = groups.setdefault(g, {"TP": 0, "FN": 0, "FP": 0, "TN": 0,
                                  "_exact": 0, "_near": 0})
        d[a["outcome"]] += 1
        if a["outcome"] == "TP":
            if a.get("exact_location"):
                d["_exact"] += 1
            if a.get("near_hit"):
                d["_near"] += 1
    for g, d in groups.items():
        tp, fn, fp, tn = d["TP"], d["FN"], d["FP"], d["TN"]

        def safe_div(num, den):
            return (num / den) if den else 0.0

        recall = safe_div(tp, tp + fn)
        precision = safe_div(tp, tp + fp)
        fpr = safe_div(fp, fp + tn)
        d["Recall"] = recall
        d["Precision"] = precision
        d["FPR"] = fpr
        d["Youden"] = (recall - fpr) * 100.0
        d["F1"] = safe_div(2 * precision * recall, precision + recall)
        denom = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
        d["MCC"] = (tp * tn - fp * fn) / (denom ** 0.5) if denom > 0 else 0.0
        tot = (tp + fn)  # 该组 vuln 应报数 = TP+FN
        d["exact_hit_rate"] = safe_div(d["_exact"], tp) if tp else 0.0
        d["near_hit_rate"] = safe_div(d["_near"], tp) if tp else 0.0
        del d["_exact"], d["_near"]
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


def compute_trace_metrics(aligned, line_tolerance=0):
    """计算路径证据链（trace）指标，仅对支持 trace 的 expected 样本统计。

    借鉴 VulnGym 的 ``entry_point -> critical_operation -> trace`` 多节点理念，
    将 expected 的 trace（来自 CSV ``trace`` 列）与被测结果声明的 ``result_trace``
    做节点集合匹配（方向无关，``file:line`` 节点用 ``--line-tolerance`` 容差）。

    Args:
        aligned: align() 的输出（含 ``trace`` 期望节点与 ``result_trace`` 实测节点）。
        line_tolerance: 节点行号容差（int，默认 0）。

    Returns:
        dict: {trace_recall, trace_precision, trace_expected_nodes,
               trace_reported_nodes, trace_support_count}
            - trace_recall = 命中 expected 节点数 / expected 节点数（仅对支持 trace 的样本）。
            - trace_precision = 命中 expected 节点数 / 被测 trace 节点数。
            - trace_support_count = 支持 trace 评测的 expected 样本数。
    """
    def _node_key(node):
        """归一化 trace 节点为 (file_norm, line) 元组，便于容差匹配。"""
        if ":" not in node:
            return (node.replace("\\", "/"), None)
        f, _, l = node.rpartition(":")
        try:
            return (f.replace("\\", "/"), int(l))
        except ValueError:
            return (node.replace("\\", "/"), None)

    def _match(expected_node, reported_nodes):
        """判断 expected 节点是否被 reported 节点集合命中（方向无关 + 行容差）。"""
        ef, el = _node_key(expected_node)
        for rn in reported_nodes:
            rf, rl = _node_key(rn)
            if rf != ef:
                continue
            if el is None or rl is None:
                return rf == ef
            if line_tolerance > 0:
                if abs(rl - el) <= line_tolerance:
                    return True
            elif rl == el:
                return True
        return False

    total_expected = 0
    total_reported = 0
    total_hit = 0
    support = 0
    for a in aligned:
        exp_trace = a.get("trace") or []
        if not exp_trace:
            continue  # 仅对支持 trace 的 expected 样本统计
        support += 1
        res_trace = a.get("result_trace") or []
        total_expected += len(exp_trace)
        total_reported += len(res_trace)
        for en in exp_trace:
            if _match(en, res_trace):
                total_hit += 1

    def safe_div(num, den):
        return (num / den) if den else 0.0

    return {
        "trace_recall": safe_div(total_hit, total_expected),
        "trace_precision": safe_div(total_hit, total_reported),
        "trace_expected_nodes": total_expected,
        "trace_reported_nodes": total_reported,
        "trace_hit_nodes": total_hit,
        "trace_support_count": support,
    }


def compute_plan_metrics(aligned, plans_map):
    """计算多步规划（plan / sub-goal chain）指标，仅对支持 plan 的 expected 样本统计。

    对标 Cybench 的显式 subtask 检查点：将期望步骤（plans manifest 的 ``steps[].goal``）
    与被测结果声明的 ``result_plan``（步骤序列）比对，产出覆盖率与顺序正确性。

    Args:
        aligned: align() 的输出（含 ``id`` 与 ``result_plan`` 实测步骤序列）。
        plans_map: {id: [step_goal, ...]} 期望步骤映射，由 plans manifest 目录加载。

    Returns:
        dict: {plan_coverage, plan_order, plan_support_count,
               plan_expected_steps, plan_reported_steps, plan_hit_steps}
            - plan_coverage = 命中期望步骤数 / 期望步骤数（集合覆盖，方向无关）。
            - plan_order = 顺序正确性 ∈ [0,1]：基于最长公共子序列（LCSubSeq）占
              期望步骤长度的比例；乱序/缺步会显著降分。
    """
    def _norm(s):
        return (s or "").strip().lower()

    def _lcs_len(a, b):
        """最长公共子序列长度（步骤按归一化字符串匹配，顺序敏感）。"""
        n, m = len(a), len(b)
        if n == 0 or m == 0:
            return 0
        dp = [[0] * (m + 1) for _ in range(n + 1)]
        for i in range(1, n + 1):
            ai = _norm(a[i - 1])
            for j in range(1, m + 1):
                if ai == _norm(b[j - 1]):
                    dp[i][j] = dp[i - 1][j - 1] + 1
                else:
                    dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
        return dp[n][m]

    total_expected = 0
    total_reported = 0
    total_hit = 0
    total_order = 0.0
    support = 0
    for a in aligned:
        sid = a.get("id")
        exp_steps = plans_map.get(sid)
        if not exp_steps:
            continue  # 仅对支持 plan 的 expected 样本统计
        support += 1
        res_plan = a.get("result_plan") or []
        total_expected += len(exp_steps)
        total_reported += len(res_plan)
        # 覆盖率：expected 步骤中有多少出现在被测步骤集合里
        res_set = {_norm(x) for x in res_plan}
        for es in exp_steps:
            if _norm(es) in res_set:
                total_hit += 1
        # 顺序正确性：LCSubSeq / 期望长度
        if exp_steps:
            total_order += _lcs_len(exp_steps, res_plan) / len(exp_steps)

    def safe_div(num, den):
        return (num / den) if den else 0.0

    return {
        "plan_coverage": safe_div(total_hit, total_expected),
        "plan_order": safe_div(total_order, support),
        "plan_support_count": support,
        "plan_expected_steps": total_expected,
        "plan_reported_steps": total_reported,
        "plan_hit_steps": total_hit,
    }


def load_plans_map(plans_dir):
    """从 plans manifest 目录加载 {id: [step_goal,...]} 映射。

    Args:
        plans_dir: manifest 目录（含若干 ``<id>.plan.json``）。

    Returns:
        dict: {id: [step_goal, ...]}；目录不存在时返回空 dict。
    """
    plans_map = {}
    if not plans_dir or not os.path.isdir(plans_dir):
        return plans_map
    for fn in sorted(os.listdir(plans_dir)):
        if not fn.endswith(".plan.json"):
            continue
        fp = os.path.join(plans_dir, fn)
        try:
            with open(fp, encoding="utf-8") as fh:
                data = json.load(fh)
        except (ValueError, OSError):
            continue
        pid = (data.get("id") or "").strip()
        steps = data.get("steps") or []
        if pid and isinstance(steps, list):
            plans_map[pid] = [s.get("goal", "") for s in steps if isinstance(s, dict)]
    return plans_map


# --------------------------------------------------------------------------- #
# 时延 / 超时 / 简洁度
# --------------------------------------------------------------------------- #
def timing_and_quality(aligned, timeout_ms):
    """基于每个样本透传的 elapsed_ms 计算真实的时延/超时统计。

    Args:
        aligned: align() 的输出（每个条目携带 ``elapsed_ms``，可能为 None）。
        timeout_ms: 单次样本超时阈值（ms）。

    Returns:
        dict: avg / p50 / p95 / max / count / timeout_count / timeout_rate。
        - count: 实际携带有效耗时的样本数。
        - timeout_count: elapsed_ms > timeout_ms 的样本数。
        - timeout_rate: timeout_count / count。
    """
    vals = [a["elapsed_ms"] for a in aligned
            if isinstance(a.get("elapsed_ms"), (int, float))]
    count = len(vals)
    if not vals:
        return {
            "avg_elapsed_ms": 0.0, "p50_elapsed_ms": 0.0,
            "p95_elapsed_ms": 0.0, "max_elapsed_ms": 0.0,
            "count": 0, "timeout_count": 0, "timeout_rate": 0.0,
            "timeout_ms": timeout_ms,
        }
    vals_sorted = sorted(vals)
    avg = sum(vals) / count
    p50 = vals_sorted[min(count - 1, int(round(0.50 * (count - 1))))]
    p95 = vals_sorted[min(count - 1, int(round(0.95 * (count - 1))))]
    mx = vals_sorted[-1]
    timeout_count = sum(1 for v in vals if v > timeout_ms)
    return {
        "avg_elapsed_ms": avg,
        "p50_elapsed_ms": p50,
        "p95_elapsed_ms": p95,
        "max_elapsed_ms": mx,
        "count": count,
        "timeout_count": timeout_count,
        "timeout_rate": (timeout_count / count),
        "timeout_ms": timeout_ms,
    }


# --------------------------------------------------------------------------- #
# 输出
# --------------------------------------------------------------------------- #
def render_markdown(name, metrics, timing, simplicity, completeness):
    """渲染 Markdown 汇总表格。

    Args:
        name: 被测对象名。
        metrics: compute_metrics 的输出（含 F1 / MCC / 定位精度）。
        timing: timing_and_quality 的输出。
        simplicity: 报告简洁度。
        completeness: coverage_metrics 的 total_completeness。

    Returns:
        str: Markdown 文本。
    """
    lines = []
    lines.append("# JSEF Benchmark Scorecard — %s" % name)
    lines.append("")
    lines.append("| 被测对象 | Recall | Precision | F1 | MCC | FPR | Youden | 定位精度 | CWE精确度 | 平均耗时(ms) | 超时数 | 报告简洁度 | 能力完备度 |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    cwe_acc = metrics.get("cwe_accuracy")
    cwe_str = ("%.3f(%d)" % (cwe_acc, metrics.get("cwe_reported_count", 0))) if cwe_acc is not None else "N/A"
    lines.append("| %s | %.3f | %.3f | %.3f | %.3f | %.3f | %.1f | %.3f | %s | %.1f | %d | %.3f | %.3f |" % (
        name,
        metrics["Recall"], metrics["Precision"], metrics["F1"], metrics["MCC"],
        metrics["FPR"], metrics["Youden"], metrics["exact_hit_rate"],
        cwe_str,
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
# --------------------------------------------------------------------------- #
# 单对象评分（供 --result 与 --results-dir 复用）
# --------------------------------------------------------------------------- #
def score_object(samples, result_path, timeout_ms, line_tolerance=0,
                 check_trace=False, plans_map=None):
    """对一个被测对象结果文件算分，返回 (report_dict, aligned)。

    Args:
        samples: load_expected 的输出（事实源）。
        result_path: 单个结果文件（.sarif 或 .json）。
        timeout_ms: 超时阈值（ms）。
        line_tolerance: 命中行号容差（int）。
        check_trace: 是否计算路径证据链指标（--check-trace）。
        plans_map: {id: [step_goal,...]} 多步规划期望步骤（--check-plan），None 则不评测。

    Returns:
        tuple: (report, aligned)
            - report: 含 name / metrics / timing / simplicity / completeness /
              by_cwe / by_level 的 dict；若 check_trace 则 metrics 含
              trace_recall / trace_precision，若 plans_map 非 None 则含
              plan_coverage / plan_order，否则为 null。
            - aligned: align() 输出。
    """
    use_sarif = result_path.lower().endswith(".sarif")
    findings, _elapsed_list = load_result(result_path)
    aligned = align(samples, findings, use_sarif, line_tolerance=line_tolerance)
    metrics = compute_metrics(aligned)
    timing = timing_and_quality(aligned, timeout_ms)

    if check_trace:
        tm = compute_trace_metrics(aligned, line_tolerance=line_tolerance)
        metrics["trace_recall"] = tm["trace_recall"]
        metrics["trace_precision"] = tm["trace_precision"]
        metrics["trace_support_count"] = tm["trace_support_count"]
        metrics["trace_expected_nodes"] = tm["trace_expected_nodes"]
        metrics["trace_reported_nodes"] = tm["trace_reported_nodes"]
        metrics["trace_hit_nodes"] = tm["trace_hit_nodes"]
    else:
        metrics["trace_recall"] = None
        metrics["trace_precision"] = None

    if plans_map is not None:
        pm = compute_plan_metrics(aligned, plans_map)
        metrics["plan_coverage"] = pm["plan_coverage"]
        metrics["plan_order"] = pm["plan_order"]
        metrics["plan_support_count"] = pm["plan_support_count"]
        metrics["plan_expected_steps"] = pm["plan_expected_steps"]
        metrics["plan_reported_steps"] = pm["plan_reported_steps"]
        metrics["plan_hit_steps"] = pm["plan_hit_steps"]
    else:
        metrics["plan_coverage"] = None
        metrics["plan_order"] = None

    tp = metrics["TP"]
    fp = metrics["FP"]
    total_output = tp + fp
    simplicity = (tp / total_output) if total_output else 0.0
    cov = coverage_metrics(samples, aligned)

    report = {
        "name": os.path.basename(os.path.dirname(result_path)) or os.path.basename(result_path),
        "metrics": metrics,
        "timing": timing,
        "simplicity": simplicity,
        "completeness": cov["total_completeness"],
        "by_cwe": group_by(aligned, "cwe"),
        "by_level": group_by(aligned, "level"),
    }
    return report, aligned


def _find_result_file(obj_dir):
    """在对象子目录中查找结果文件：优先 result.json，否则首个 *.sarif。"""
    result_json = os.path.join(obj_dir, "result.json")
    if os.path.isfile(result_json):
        return result_json
    for fn in sorted(os.listdir(obj_dir)):
        if fn.lower().endswith(".sarif"):
            return os.path.join(obj_dir, fn)
    return None


def build_cross_matrix(samples, results_dir, timeout_ms, line_tolerance=0, check_trace=False):
    """遍历 results_dir 下每个 <object>/ 子目录，聚合为 cross_matrix 结构。

    Args:
        samples: 事实源样本列表。
        results_dir: 含若干 <object>/ 子目录的根目录。
        timeout_ms: 超时阈值（ms）。
        line_tolerance: 命中行号容差（int）。

    Returns:
        dict: {"objects": [...], "meta": {expected_count, generated_at}}
    """
    import datetime
    objects = []
    if not os.path.isdir(results_dir):
        raise FileNotFoundError("找不到 results-dir: %s" % results_dir)
    for name in sorted(os.listdir(results_dir)):
        obj_dir = os.path.join(results_dir, name)
        if not os.path.isdir(obj_dir):
            continue
        result_path = _find_result_file(obj_dir)
        if result_path is None:
            continue
        try:
            report, _aligned = score_object(
                samples, result_path, timeout_ms,
                line_tolerance=line_tolerance, check_trace=check_trace)
        except (ValueError, FileNotFoundError) as exc:
            print("[警告] 对象 %s 跳过: %s" % (name, exc), file=sys.stderr)
            continue
        m = report["metrics"]
        t = report["timing"]
        objects.append({
            "name": name,
            "metrics": {
                "Recall": m["Recall"], "Precision": m["Precision"],
                "F1": m["F1"], "MCC": m["MCC"], "Youden": m["Youden"],
                "FPR": m["FPR"], "TP": m["TP"], "FN": m["FN"],
                "FP": m["FP"], "TN": m["TN"],
                "exact_hit_rate": m["exact_hit_rate"],
                "near_hit_rate": m["near_hit_rate"],
                "trace_recall": m.get("trace_recall"),
                "trace_precision": m.get("trace_precision"),
                "trace_support_count": m.get("trace_support_count"),
                "timing": t,
            },
            "by_cwe": report["by_cwe"],
            "by_level": report["by_level"],
        })
    return {
        "objects": objects,
        "meta": {
            "expected_count": len(samples),
            "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        },
    }


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def main(argv=None):
    parser = argparse.ArgumentParser(
        description="JSEF Benchmark Scorecard 计算脚本（Phase C3，含 F1/MCC/定位精度/交叉矩阵）。\n"
                    "读取 expectedresults.csv 与 SAST/LLM 结果（SARIF 或简化 JSON），"
                    "输出 Recall/Precision/F1/MCC/FPR/Youden、定位精度与分组汇总。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--expected", required=True,
                        help="expectedresults.csv 路径（事实源，列: id,cwe,level,type,file,line,...)")
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("--result", default=None,
                     help="被测对象结果文件：.sarif 或 .json（列表/字典两种简化格式均可）")
    grp.add_argument("--results-dir", default=None,
                     help="多对象结果目录：<dir>/<object>/result.json 或 <dir>/<object>/*.sarif")
    parser.add_argument("--name", default=None, help="被测对象名（单对象模式；不填则用文件名）")
    parser.add_argument("--timeout-ms", type=int, default=120000,
                        help="单次样本超时阈值（ms），默认 120000")
    parser.add_argument("--line-tolerance", type=int, default=1,
                        help="命中行号容差（int，默认 1）：|result_line-expected_line|<=容差视为容差内命中，"
                             "仅用于定位精度统计，不改 TP/FN 判定。"
                             "默认为 1：CHECKPOINT 注释行在 sink 行上方一行，工具通常报 sink 行（N+1），"
                             "容差 1 消除该系统性偏移，使 exact_hit_rate 有意义。")
    parser.add_argument("--check-trace", action="store_true",
                        help="开启路径证据链评测：对支持 trace 的 expected 样本（CSV trace 列非空）"
                             "与被测结果 trace 计算 trace_recall/trace_precision；否则为 null。向后兼容。")
    parser.add_argument("--check-plan", default=None, metavar="DIR",
                        help="开启多步规划评测：传入 plans manifest 目录（如 benchmark/plans）。"
                             "对支持 plan 的 expected 样本（manifest 存在），比对被测结果声明的 plan "
                             "步骤序列与期望步骤，计算 plan_coverage / plan_order。向后兼容。")
    parser.add_argument("--out", default=None,
                        help="写出结构化 JSON 路径；多对象模式下若为目录则在其中写 cross_matrix.json")
    parser.add_argument("--verbose", action="store_true",
                        help="额外打印按 CWE 与 level 的分组汇总")
    args = parser.parse_args(argv)

    # 1) 事实源
    try:
        samples = load_expected(args.expected)
    except (FileNotFoundError, KeyError) as exc:
        print("[错误] %s" % exc, file=sys.stderr)
        return 2

    # 2) 多对象交叉矩阵模式
    if args.results_dir:
        try:
            cross = build_cross_matrix(
                samples, args.results_dir, args.timeout_ms,
                line_tolerance=args.line_tolerance, check_trace=args.check_trace)
        except FileNotFoundError as exc:
            print("[错误] %s" % exc, file=sys.stderr)
            return 2
        out_path = args.out
        if out_path and os.path.isdir(out_path):
            out_path = os.path.join(out_path, "cross_matrix.json")
        elif out_path is None:
            out_path = "cross_matrix.json"
        try:
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump(cross, fh, indent=2, ensure_ascii=False)
            print("[完成] 交叉矩阵已写出: %s（对象数=%d）" % (out_path, len(cross["objects"])))
        except OSError as exc:
            print("[警告] 无法写出 --out: %s" % exc, file=sys.stderr)
        return 0

    # 2.5) 加载多步规划 manifest（--check-plan）
    plans_map = load_plans_map(args.check_plan) if args.check_plan else None

    # 3) 单对象模式
    result_path = args.result
    try:
        report, aligned = score_object(
            samples, result_path, args.timeout_ms,
            line_tolerance=args.line_tolerance, check_trace=args.check_trace,
            plans_map=plans_map)
    except (FileNotFoundError, ValueError) as exc:
        print("[错误] %s" % exc, file=sys.stderr)
        return 2

    name = args.name or report["name"]
    metrics = report["metrics"]
    timing = report["timing"]
    simplicity = report["simplicity"]
    cov_total = report["completeness"]

    # 4) 输出
    md = render_markdown(name, metrics, timing, simplicity, cov_total)
    print(md)

    if args.check_trace:
        tr = metrics.get("trace_recall")
        tp_ = metrics.get("trace_precision")
        print("\n[路径证据链 trace] 支持样本=%d，expected 节点=%d，被测节点=%d，命中=%d"
              % (metrics.get("trace_support_count", 0),
                 metrics.get("trace_expected_nodes", 0),
                 metrics.get("trace_reported_nodes", 0),
                 metrics.get("trace_hit_nodes", 0)))
        print("  trace_recall=%.3f  trace_precision=%.3f" % (tr if tr is not None else 0.0,
                                                              tp_ if tp_ is not None else 0.0))

    if args.check_plan:
        pc = metrics.get("plan_coverage")
        po = metrics.get("plan_order")
        print("\n[多步规划 plan] 支持样本=%d，expected 步骤=%d，被测步骤=%d，命中=%d"
              % (metrics.get("plan_support_count", 0),
                 metrics.get("plan_expected_steps", 0),
                 metrics.get("plan_reported_steps", 0),
                 metrics.get("plan_hit_steps", 0)))
        print("  plan_coverage=%.3f  plan_order=%.3f" % (pc if pc is not None else 0.0,
                                                          po if po is not None else 0.0))

    if args.verbose:
        by_cwe = report["by_cwe"]
        by_level = report["by_level"]
        print("\n## 按 CWE 分组")
        print("| CWE | TP | FN | FP | TN | Recall | Precision | F1 | MCC | FPR | Youden | 定位精度 |")
        print("|---|---|---|---|---|---|---|---|---|---|---|---|")
        for cwe in sorted(by_cwe):
            d = by_cwe[cwe]
            print("| %s | %d | %d | %d | %d | %.3f | %.3f | %.3f | %.3f | %.3f | %.1f | %.3f |" % (
                cwe, d["TP"], d["FN"], d["FP"], d["TN"],
                d["Recall"], d["Precision"], d["F1"], d["MCC"], d["FPR"], d["Youden"],
                d["exact_hit_rate"]))
        print("\n## 按 Level 分组")
        print("| Level | TP | FN | FP | TN | Recall | Precision | F1 | MCC | FPR | Youden | 定位精度 |")
        print("|---|---|---|---|---|---|---|---|---|---|---|---|")
        for lv in sorted(by_level):
            d = by_level[lv]
            print("| %s | %d | %d | %d | %d | %.3f | %.3f | %.3f | %.3f | %.3f | %.1f | %.3f |" % (
                lv, d["TP"], d["FN"], d["FP"], d["TN"],
                d["Recall"], d["Precision"], d["F1"], d["MCC"], d["FPR"], d["Youden"],
                d["exact_hit_rate"]))

    # 5) 可选结构化输出
    if args.out:
        out_report = {
            "name": name,
            "metrics": metrics,
            "timing": timing,
            "simplicity": simplicity,
            "completeness": {"total_completeness": cov_total},
            "by_cwe": report["by_cwe"],
            "by_level": report["by_level"],
            "aligned": aligned,
        }
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(out_report, fh, indent=2, ensure_ascii=False)
            print("\n[完成] 结构化报告已写出: %s" % args.out)
        except OSError as exc:
            print("[警告] 无法写出 --out: %s" % exc, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
