#!/usr/bin/env python3
"""JSEF Benchmark — 行业标准报告生成器（Phase 7）。

用途
----
消费 ``scorecard.py --results-dir`` 产出的 ``cross_matrix.json``，结合
``expectedresults.csv`` 的 ``category`` 列，生成面向"行业标准对比"的报告：

* ``report.md``   —— 人类可读总表 + 逐 OWASP 类章节 + 按 Level 能力档位表
                     + OWASP Benchmark 式 Youden 排名说明。
* ``report.json`` —— 机器可读：总表数组 / 按 OWASP 类聚合 / 按 Level 聚合 / 排名。
* （可选）``ranking.png`` / ``radar_data.json``
                     —— 若 ``matplotlib`` 可用，画各对象按 Level 的 Youden 雷达/
                     排名条形图；不可用则只出 ``ranking_data.json`` 并注明。

输入（cross_matrix.json 结构，由 scorecard 的 build_cross_matrix 产出）
--------------------------------------------------------------------------
{
  "objects": [
    {
      "name": "<object>",
      "metrics": {Recall, Precision, F1, MCC, Youden, FPR, TP, FN, FP, TN,
                  exact_hit_rate, near_hit_rate,
                  timing: {avg/p50/p95/max/timeout_count/timeout_rate, ...}},
      "by_cwe":  {"<cwe>":  {TP,FN,FP,TN,Recall,Precision,F1,MCC,FPR,Youden,exact_hit_rate}},
      "by_level":{"<level>":{TP,FN,FP,TN,Recall,Precision,F1,MCC,FPR,Youden,exact_hit_rate}}
    }, ...
  ],
  "meta": {"expected_count": N, "generated_at": "..."}
}

输入（expectedresults.csv 结构，事实源）
----------------------------------------
列 ``id,cwe,level,type,file,line,source,sink,category``。本脚本只用其
``category`` 列建立 category → OWASP Top 10 2021 的映射（映射表硬编码于本脚本）。
cross_matrix.json 本身不携带 category，但携带 cwe；OWASP 聚合走
"category → OWASP 类"，Level 聚合走 "by_level"。

OWASP Top 10 2021 映射（category → 类）
--------------------------------------
* A01 Broken Access Control：idor* / broken-access-control / authorization-bypass /
  auth-bypass / idor / workflow-bypass / force-browse / business-logic(部分) ...
* A02 Cryptographic Failures：crypto* / weak-* / hardcoded-* / reused-iv / default-credentials
* A03 Injection：sql-* / command-* / xss-* / spel-* / *-injection / xxe / xpath-* /
  ldap-* / nosql-* / template-* / header-injection / log-injection / jsonp-* / jwt-* ...
* A04 Insecure Design：business-logic / mass-assignment / race-condition / workflow*
* A05 Security Misconfiguration：cors* / security-header* / missing-* / debug-* /
  error-info-leak / insecure-cookie / config-gated-sink / clickjacking
* A06 Vulnerable & Outdated Components：vulnerable-components
* A07 Identification & Authentication Failures：weak-password / sensitive-data-* /
  jwt-auth-bypass(部分) / auth-bypass(部分) → 见映射表
* A08 Software & Data Integrity Failures：insecure-integrity
* A09 Security Logging & Monitoring Failures：security-logging
* A10 Server-Side Request Forgery：ssrf

未在表中命中的未知 category → "Other"。详见 ``OWASP_MAP``。

用法
----
    python3 benchmark/reports/generate_report.py \
        --cross-matrix /tmp/rb_test/cross_matrix.json \
        --expected    benchmark/expectedresults.csv \
        --out         /tmp/rb_test/report.md

    # 仅出数据、不要 PNG（即便 matplotlib 可用）：
    #   --no-png

依赖
----
仅标准库（json/argparse/os/sys/csv）。``matplotlib`` 为可选：导入失败则跳过 PNG，
只出 ``ranking_data.json`` 并在 report.md 注明。

约束
----
不修改 scorecard.py，不修改 expectedresults.csv，不写任何攻击利用脚本。
"""

import argparse
import csv
import json
import os
import sys

# --------------------------------------------------------------------------- #
# category → OWASP Top 10 2021 硬编码映射
# --------------------------------------------------------------------------- #
# 逐条列出 CSV 中出现过的全部 category，按前缀/关键字归类。
# 未在表中出现的归 "Other"。
OWASP_CLASSES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable & Outdated Components",
    "A07": "Identification & Authentication Failures",
    "A08": "Software & Data Integrity Failures",
    "A09": "Security Logging & Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
    "Other": "Unmapped / Other",
}

# 显式 category → OWASP 类（精确匹配优先）。
OWASP_MAP = {
    # ---- A01 Broken Access Control ----
    "idor": "A01",
    "idor-broken-access-control": "A01",
    "broken-access-control": "A01",
    "authorization-bypass": "A01",
    "auth-bypass": "A01",
    "business-logic": "A04",          # 业务逻辦整体归 A04（Insecure Design）
    # ---- A02 Cryptographic Failures ----
    "weak-hash": "A02",
    "weak-random": "A02",
    "weak-password": "A07",           # 弱口令归 A07（认证）
    "hardcoded-key": "A02",
    "hardcoded-key-ecb": "A02",
    "hardcoded-credentials": "A02",
    "default-credentials": "A07",     # 默认凭据归 A07（认证）
    "reused-iv": "A02",
    "sensitive-data-exposure": "A07", # 敏感数据暴露归 A07（认证/身份）
    # ---- A03 Injection（大类）----
    "sql-injection": "A03",
    "sql-injection-jdbc": "A03",
    "sql-injection-jpa": "A03",
    "sql-injection-mybatis": "A03",
    "sql-injection-postgres": "A03",
    "command-injection": "A03",
    "xss-reflected": "A03",
    "spel-injection": "A03",
    "groovy-injection": "A03",
    "mvel-injection": "A03",
    "beanshell-injection": "A03",
    "ognl-injection": "A03",
    "script-engine-injection": "A03",
    "jndi-injection": "A03",
    "template-injection": "A03",
    "xpath-injection": "A03",
    "ldap-injection": "A03",
    "nosql-injection": "A03",
    "xxe": "A03",
    "yaml-deserialization": "A03",
    "fastjson-deserialization": "A03",
    "jackson-poly-deserialization": "A03",
    "unsafe-deserialization": "A03",
    "header-injection": "A03",
    "jsonp-callback-injection": "A03",
    "log-injection": "A03",
    "jwt-auth-bypass": "A07",         # JWT 鉴权绕过归 A07
    # ---- A04 Insecure Design ----
    "mass-assignment": "A04",
    "race-condition": "A04",
    "numeric-date-input": "A04",
    # ---- A05 Security Misconfiguration ----
    "cors-misconfig": "A05",
    "security-header-missing": "A05",
    "clickjacking": "A05",
    "debug-endpoint-exposed": "A05",
    "error-info-leak": "A05",
    "insecure-cookie": "A05",
    "config-gated-sink": "A05",
    "open-redirect": "A05",
    "missing-rate-limiting": "A05",
    # ---- A06 Vulnerable & Outdated Components ----
    "vulnerable-components": "A06",
    # ---- A08 Software & Data Integrity Failures ----
    "insecure-integrity": "A08",
    # ---- A09 Security Logging & Monitoring Failures ----
    "security-logging": "A09",
    # ---- A10 SSRF ----
    "ssrf": "A10",
    # ---- 其他归类 ----
    "path-traversal": "A03",          # 路径遍历在 OWASP 2021 归 A01，但常被视作注入类
    "timing-attack": "A02",           # 非恒定时间比较 → 密码学失败
    "regex-dos": "A04",               # ReDoS 归 Insecure Design（可用性问题）
    "hash-collision-dos": "A04",
    "risky-operations": "Other",
}


def category_to_owasp(category):
    """将单个 category 映射到 OWASP 类代码（含前缀模糊匹配）。

    Args:
        category: 字符串（可能为空）。

    Returns:
        str: A01..A10 或 "Other"。
    """
    if not category:
        return "Other"
    cat = category.strip().lower()
    if cat in OWASP_MAP:
        return OWASP_MAP[cat]
    # 前缀匹配（覆盖 CSV 未列出、但符合既有命名规律的新 category）
    for prefix, cls in (
        ("sql-", "A03"), ("command-", "A03"), ("xss-", "A03"),
        ("spel-", "A03"), ("injection", "A03"), ("xxe", "A03"),
        ("xpath-", "A03"), ("ldap-", "A03"), ("nosql-", "A03"),
        ("template-", "A03"), ("header-", "A03"), ("jsonp-", "A03"),
        ("jndi-", "A03"), ("deserialization", "A03"), ("yaml-", "A03"),
        ("weak-", "A02"), ("hardcoded-", "A02"), ("crypto", "A02"),
        ("reused-", "A02"),
        ("idor", "A01"), ("broken-access", "A01"),
        ("authorization-bypass", "A01"), ("auth-bypass", "A01"),
        ("business-logic", "A04"), ("mass-assign", "A04"),
        ("race-", "A04"),
        ("cors", "A05"), ("security-header", "A05"), ("missing-", "A05"),
        ("debug-", "A05"), ("error-info", "A05"), ("cookie", "A05"),
        ("config", "A05"), ("open-redirect", "A05"),
        ("vulnerable-components", "A06"),
        ("insecure-integrity", "A08"),
        ("security-logging", "A09"),
        ("ssrf", "A10"),
        ("weak-password", "A07"), ("default-credentials", "A07"),
        ("sensitive-data", "A07"), ("jwt-", "A07"),
    ):
        if cat.startswith(prefix):
            return cls
    return "Other"


def load_categories(expected_path):
    """读取 expectedresults.csv，返回 category -> OWASP 类 的映射表与
    category -> 出现样本数。

    Returns:
        tuple(dict, dict):
            - cat_to_owasp: category(str) -> owasp 类代码
            - cat_counts:   category(str) -> 样本数（含 safe，用于章节权重说明）
    """
    cat_to_owasp = {}
    cat_counts = {}
    if not expected_path or not os.path.isfile(expected_path):
        return cat_to_owasp, cat_counts
    with open(expected_path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            cat = (row.get("category") or "").strip()
            owasp = category_to_owasp(cat)
            cat_to_owasp[cat] = owasp
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
    return cat_to_owasp, cat_counts


# --------------------------------------------------------------------------- #
# 聚合
# --------------------------------------------------------------------------- #
def _aggregate_by_owasp(objects, cwe_to_owasp):
    """按 OWASP 类聚合（内部实现）。

    逐对象遍历其 by_cwe，把每个 cwe 归入其主流 OWASP 类（cwe_to_owasp），
    在类内做混淆矩阵累加后再算 Recall/Youden/F1。

    Returns:
        dict: owasp 类 -> {name -> {Recall, Precision, F1, Youden, TP, FN, FP, TN}}
    """
    # 先按 (owasp, name) 累加重度矩阵
    agg = {}  # owasp -> name -> {TP,FN,FP,TN}
    for obj in objects:
        name = obj["name"]
        by_cwe = obj.get("by_cwe", {})
        for cwe, d in by_cwe.items():
            owasp = cwe_to_owasp.get(cwe, "Other")
            slot = agg.setdefault(owasp, {}).setdefault(name, {
                "TP": 0, "FN": 0, "FP": 0, "TN": 0})
            slot["TP"] += d.get("TP", 0)
            slot["FN"] += d.get("FN", 0)
            slot["FP"] += d.get("FP", 0)
            slot["TN"] += d.get("TN", 0)

    result = {}
    for owasp, names in agg.items():
        result[owasp] = {}
        for name, m in names.items():
            tp, fn, fp, tn = m["TP"], m["FN"], m["FP"], m["TN"]

            def safe_div(a, b):
                return a / b if b else 0.0

            recall = safe_div(tp, tp + fn)
            precision = safe_div(tp, tp + fp)
            fpr = safe_div(fp, fp + tn)
            youden = (recall - fpr) * 100.0
            f1 = safe_div(2 * precision * recall, precision + recall)
            result[owasp][name] = {
                "Recall": recall, "Precision": precision, "F1": f1,
                "Youden": youden, "TP": tp, "FN": fn, "FP": fp, "TN": tn,
            }
    return result


def _aggregate_by_level(objects):
    """按 Level 聚合每个对象的 Youden / F1（直接用 cross_matrix 的 by_level）。"""
    levels = set()
    for obj in objects:
        levels.update(obj.get("by_level", {}).keys())
    levels = sorted(levels, key=lambda x: (len(x), x))  # L0,L1,...L5
    result = {}
    for lv in levels:
        result[lv] = {}
        for obj in objects:
            name = obj["name"]
            d = obj.get("by_level", {}).get(lv)
            if d is None:
                result[lv][name] = {"Youden": None, "F1": None,
                                    "Recall": None, "Precision": None}
            else:
                result[lv][name] = {
                    "Youden": d.get("Youden"), "F1": d.get("F1"),
                    "Recall": d.get("Recall"), "Precision": d.get("Precision"),
                }
    return result


def build_summary_table(objects):
    """构造总表数组（按 Youden 降序）。

    字段：name, Recall, Precision, F1, MCC, Youden, timeout_rate,
          exact_hit_rate(定位精度), completeness(能力完备度由 TP/CWE 覆盖估算)。

    能力完备度：cross_matrix 未直接给出 coverage，此处以该对象命中 CWE 数 /
    全部 CWE 数近似（hit CWE = by_cwe 中 TP>0 的 cwe）。
    """
    all_cwes = set()
    for obj in objects:
        all_cwes.update(obj.get("by_cwe", {}).keys())
    total_cwe = len(all_cwes) or 1

    rows = []
    for obj in objects:
        m = obj["metrics"]
        by_cwe = obj.get("by_cwe", {})
        hit_cwes = sum(1 for cwe, d in by_cwe.items() if d.get("TP", 0) > 0)
        completeness = hit_cwes / total_cwe
        timing = m.get("timing", {})
        rows.append({
            "name": obj["name"],
            "Recall": m.get("Recall", 0.0),
            "Precision": m.get("Precision", 0.0),
            "F1": m.get("F1", 0.0),
            "MCC": m.get("MCC", 0.0),
            "Youden": m.get("Youden", 0.0),
            "timeout_rate": timing.get("timeout_rate", 0.0),
            "exact_hit_rate": m.get("exact_hit_rate", 0.0),
            "completeness": completeness,
        })
    rows.sort(key=lambda r: r["Youden"], reverse=True)
    return rows


# --------------------------------------------------------------------------- #
# 渲染 Markdown
# --------------------------------------------------------------------------- #
def _fmt_rate(v):
    return "%.3f" % v


def _fmt_youden(v):
    return "%.1f" % v


def render_markdown(summary_rows, by_owasp, by_level, cat_to_owasp,
                    cat_counts, meta, ranking_png):
    """渲染完整 report.md。"""
    lines = []
    lines.append("# JSEF Benchmark — 行业标准对比报告（OWASP Top 10 2021）")
    lines.append("")
    gen = meta.get("generated_at", "unknown") if meta else "unknown"
    exp = meta.get("expected_count", "?") if meta else "?"
    lines.append("> 生成时间：%s ｜ 事实源样本数：%s ｜ 被测对象数：%d" % (
        gen, exp, len(summary_rows)))
    lines.append("")
    lines.append("Youden Score = (Recall − FPR) × 100，0–100，越高越好"
                 "（OWASP Benchmark 口径）。")
    lines.append("")

    # ---- 总表 ----
    lines.append("## 一、总表（按 Youden 降序排名）")
    lines.append("")
    lines.append("| 排名 | 被测对象 | Recall | Precision | F1 | MCC | Youden | "
                 "超时率 | 定位精度(exact) | 能力完备度 |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for i, r in enumerate(summary_rows, 1):
        lines.append("| %d | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            i, r["name"], _fmt_rate(r["Recall"]), _fmt_rate(r["Precision"]),
            _fmt_rate(r["F1"]), _fmt_rate(r["MCC"]), _fmt_youden(r["Youden"]),
            _fmt_rate(r["timeout_rate"]), _fmt_rate(r["exact_hit_rate"]),
            _fmt_rate(r["completeness"]),
        ))
    lines.append("")

    # ---- 逐 OWASP 类章节 ----
    lines.append("## 二、逐 OWASP Top 10 类章节")
    lines.append("")
    # 收集每类包含的 category
    owasp_cats = {}
    for cat, ow in cat_to_owasp.items():
        owasp_cats.setdefault(ow, []).append(cat)
    for ow in sorted(OWASP_CLASSES.keys()):
        if ow not in by_owasp and ow not in owasp_cats:
            continue
        cls_name = OWASP_CLASSES.get(ow, ow)
        lines.append("### %s — %s" % (ow, cls_name))
        cats = sorted(owasp_cats.get(ow, []))
        if cats:
            lines.append("")
            lines.append("**含 %d 类样本**：%s" % (
                len(cats), ", ".join("%s(%d)" % (c, cat_counts.get(c, 0))
                                     for c in cats)))
        lines.append("")
        if ow in by_owasp and by_owasp[ow]:
            lines.append("| 被测对象 | Recall | Precision | F1 | Youden | TP | FN | FP | TN |")
            lines.append("|---|---|---|---|---|---|---|---|---|")
            # 按 Youden 降序
            for name in sorted(by_owasp[ow],
                               key=lambda n: by_owasp[ow][n]["Youden"],
                               reverse=True):
                d = by_owasp[ow][name]
                lines.append("| %s | %s | %s | %s | %s | %d | %d | %d | %d |" % (
                    name, _fmt_rate(d["Recall"]), _fmt_rate(d["Precision"]),
                    _fmt_rate(d["F1"]), _fmt_youden(d["Youden"]),
                    d["TP"], d["FN"], d["FP"], d["TN"]))
        else:
            lines.append("（该类无样本命中或被测对象未覆盖）")
        lines.append("")

    # ---- 按 Level 能力档位表 ----
    lines.append("## 三、按 Level 能力档位表（L0–L5）")
    lines.append("")
    level_desc = {
        "L0": "L0 显式（能力基准）",
        "L1": "L1 单跳",
        "L2": "L2 多跳（无断点）",
        "L3": "L3 间接/跨方法",
        "L4": "L4 跨文件/框架语义/状态机",
        "L5": "L5 gadget chain",
    }
    for lv in sorted(by_level.keys(), key=lambda x: (len(x), x)):
        lines.append("### %s — %s" % (lv, level_desc.get(lv, "未定义档位")))
        lines.append("")
        lines.append("| 被测对象 | Youden | F1 | Recall | Precision |")
        lines.append("|---|---|---|---|---|")
        for name in sorted(by_level[lv],
                           key=lambda n: (by_level[lv][n]["Youden"] is not None,
                                          by_level[lv][n]["Youden"] or 0),
                           reverse=True):
            d = by_level[lv][name]
            y = "—" if d["Youden"] is None else _fmt_youden(d["Youden"])
            f = "—" if d["F1"] is None else _fmt_rate(d["F1"])
            rc = "—" if d["Recall"] is None else _fmt_rate(d["Recall"])
            pr = "—" if d["Precision"] is None else _fmt_rate(d["Precision"])
            lines.append("| %s | %s | %s | %s | %s |" % (name, y, f, rc, pr))
        lines.append("")

    # ---- OWASP Benchmark 式 Youden 排名说明 ----
    lines.append("## 四、OWASP Benchmark 式 Youden 排名说明")
    lines.append("")
    lines.append("对象按 Youden Score（0–100）降序，分数越高代表在「召回且不误报」"
                 "上的综合能力越强：")
    lines.append("")
    lines.append("| 排名 | 被测对象 | Youden (0–100) | 档位评价 |")
    lines.append("|---|---|---|---|")
    for i, r in enumerate(summary_rows, 1):
        y = r["Youden"]
        if y >= 80:
            grade = "优秀（接近真实场景可用）"
        elif y >= 60:
            grade = "良好"
        elif y >= 40:
            grade = "中等（漏报或误报偏高）"
        elif y >= 20:
            grade = "偏弱（能力断点明显）"
        else:
            grade = "弱（基本不可用）"
        lines.append("| %d | %s | %s | %s |" % (i, r["name"], _fmt_youden(y), grade))
    lines.append("")
    if ranking_png:
        lines.append("![Youden 排名](%s)" % os.path.basename(ranking_png))
        lines.append("")
    else:
        lines.append("> 注：matplotlib 不可用，未生成排名图；"
                     "ranking_data.json 含原始排名数据。")
        lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("本报告由 `benchmark/reports/generate_report.py` 自动生成，"
                 "数据来源 `cross_matrix.json` + `expectedresults.csv`。")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# 可选：matplotlib 排名图
# --------------------------------------------------------------------------- #
def try_render_png(summary_rows, by_level, out_dir):
    """尝试用 matplotlib 画排名条形图 + Level Youden 雷达数据。

    Returns:
        str|None: 成功则返回 ranking.png 路径，失败返回 None。
    """
    ranking_png = None
    radar_data = {"by_level_youden": by_level, "ranking": [
        {"rank": i + 1, "name": r["name"], "Youden": r["Youden"]}
        for i, r in enumerate(summary_rows)
    ]}
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        # 排名条形图（按 Youden）；使用 ASCII 标签避免 CJK 字体缺失警告
        names = [r["name"] for r in summary_rows]
        youdens = [r["Youden"] for r in summary_rows]
        fig, ax = plt.subplots(figsize=(max(6, len(names) * 1.4), 4))
        bars = ax.barh(names[::-1], youdens[::-1], color="#4C72B0")
        ax.set_xlabel("Youden Score (0-100)")
        ax.set_title("JSEF Benchmark - Youden Ranking")
        ax.set_xlim(0, 100)
        for b, v in zip(bars, youdens[::-1]):
            ax.text(v + 1, b.get_y() + b.get_height() / 2, "%.1f" % v,
                    va="center", fontsize=8)
        fig.tight_layout()
        ranking_png = os.path.join(out_dir, "ranking.png")
        fig.savefig(ranking_png, dpi=120)
        plt.close(fig)
    except Exception:
        ranking_png = None

    # 雷达数据始终写出（供外部绘图）
    radar_path = os.path.join(out_dir, "radar_data.json")
    try:
        with open(radar_path, "w", encoding="utf-8") as fh:
            json.dump(radar_data, fh, indent=2, ensure_ascii=False)
    except OSError:
        pass
    return ranking_png


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def _build_cwe_to_owasp(expected_path):
    """直接读 CSV，统计每个 cwe 的主流 category → OWASP 归属。"""
    cwe_cat_count = {}
    if not expected_path or not os.path.isfile(expected_path):
        return {}
    with open(expected_path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            cwe = (row.get("cwe") or "").strip()
            cat = (row.get("category") or "").strip()
            if not cwe:
                continue
            d = cwe_cat_count.setdefault(cwe, {})
            d[cat] = d.get(cat, 0) + 1
    cwe_to_owasp = {}
    for cwe, counts in cwe_cat_count.items():
        best_cat = max(counts, key=lambda c: counts[c])
        cwe_to_owasp[cwe] = category_to_owasp(best_cat)
    return cwe_to_owasp


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="JSEF Benchmark 行业标准报告生成器（Phase 7）："
                    "消费 cross_matrix.json 与 expectedresults.csv，"
                    "产出 report.md / report.json 与可选的排名图。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--cross-matrix", required=True,
                        help="scorecard --results-dir 产出的 cross_matrix.json")
    parser.add_argument("--expected", required=True,
                        help="expectedresults.csv（事实源，用于 category→OWASP 映射）")
    parser.add_argument("--out", required=True,
                        help="report.md 输出路径（同目录生成 report.json / "
                             "radar_data.json / ranking.png）")
    parser.add_argument("--no-png", action="store_true",
                        help="即便 matplotlib 可用也跳过 PNG 生成（只出数据 JSON）")
    args = parser.parse_args(argv)

    # 1) 读取 cross_matrix
    try:
        with open(args.cross_matrix, encoding="utf-8") as fh:
            cross = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print("[错误] 无法读取 cross_matrix.json: %s" % exc, file=sys.stderr)
        return 2

    objects = cross.get("objects", [])
    meta = cross.get("meta", {})
    if not objects:
        print("[警告] cross_matrix.json 中无对象，生成空报告。", file=sys.stderr)

    # 2) category / cwe → OWASP
    cat_to_owasp, cat_counts = load_categories(args.expected)
    cwe_to_owasp = _build_cwe_to_owasp(args.expected)

    # 3) 聚合
    summary_rows = build_summary_table(objects)
    by_owasp = _aggregate_by_owasp(objects, cwe_to_owasp)
    by_level = _aggregate_by_level(objects)

    # 4) 排名（按 Youden 降序，已含在 summary_rows）
    ranking = [
        {"rank": i + 1, "name": r["name"], "Youden": r["Youden"]}
        for i, r in enumerate(summary_rows)
    ]

    # 5) 写 report.md
    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    ranking_png = None
    if not args.no_png:
        ranking_png = try_render_png(summary_rows, by_level, out_dir)
    md = render_markdown(summary_rows, by_owasp, by_level, cat_to_owasp,
                         cat_counts, meta, ranking_png)
    try:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(md)
        print("[完成] 报告已写出: %s" % args.out)
    except OSError as exc:
        print("[错误] 无法写出 report.md: %s" % exc, file=sys.stderr)
        return 2

    # 6) 写 report.json（机器可读）
    report_json = {
        "meta": meta,
        "summary_table": summary_rows,
        "ranking": ranking,
        "by_owasp": by_owasp,
        "by_level": by_level,
        "owasp_classes": OWASP_CLASSES,
    }
    json_path = os.path.join(out_dir, "report.json")
    try:
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(report_json, fh, indent=2, ensure_ascii=False)
        print("[完成] 机器可读报告已写出: %s" % json_path)
    except OSError as exc:
        print("[警告] 无法写出 report.json: %s" % exc, file=sys.stderr)

    # 7) 提示 PNG 状态
    if ranking_png:
        print("[完成] 排名图已写出: %s" % ranking_png)
    else:
        print("[提示] matplotlib 不可用（或 --no-png）：未生成 PNG，"
              "已写出 radar_data.json 供外部绘图。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
