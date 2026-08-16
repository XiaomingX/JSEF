#!/usr/bin/env python3
"""把 semgrep SARIF 转成 JSEF scorecard 可用的 result.json（简单 JSON 模式）。

桥接逻辑：对每条 semgrep finding（file:line + CWE），在 expectedresults.csv 中
找「同 file、CWE 匹配、行号容差内」的 vuln 样本，把该样本 id 作为 result 的 id
（hit:true）。这样 scorecard 简单 JSON 模式可按 id 精确对齐，并享受 --line-tolerance。

对 safe 样本：若 semgrep 在同 file:line 报了同 CWE，则该 safe id 被标 hit:true（FP）。

找不到对应 expected 样本的 semgrep finding 直接丢弃（不在 JSEF 标注集内，不计分）。

用法：
  python3 convert_semgrep.py --sarif benchmark/results/semgrep/scan.sarif \
      --expected benchmark/expectedresults.csv \
      --out benchmark/results/semgrep/result.json --tolerance 3
"""
import argparse
import csv
import json
import os
import re


def load_expected(path):
    samples = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            samples.append({
                "id": row["id"].strip(),
                "cwe": row["cwe"].strip(),
                "type": row["type"].strip().lower(),
                "file": row["file"].strip(),
                "line": int(row["line"]) if row["line"].strip().isdigit() else -1,
            })
    return samples


def cwe_from_tags(tags):
    for t in tags or []:
        m = re.match(r"CWE-(\d+)", str(t))
        if m:
            return m.group(1)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sarif", required=True)
    ap.add_argument("--expected", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tolerance", type=int, default=3)
    args = ap.parse_args()

    samples = load_expected(args.expected)
    with open(args.sarif, encoding="utf-8") as fh:
        sarif = json.load(fh)
    run = sarif["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"].get("rules", [])}
    results = run.get("results", [])

    out = []
    for res in results:
        rid = res.get("ruleId", "")
        rule = rules.get(rid, {})
        tags = rule.get("properties", {}).get("tags", [])
        cwe = cwe_from_tags(tags)
        if not cwe:
            continue
        locs = res.get("locations", [])
        if not locs:
            continue
        uri = locs[0]["physicalLocation"]["artifactLocation"]["uri"].replace("\\", "/")
        line = int(locs[0]["physicalLocation"]["region"].get("startLine", -1))
        # 找最近匹配样本
        best = None
        best_dist = None
        for s in samples:
            if s["file"].replace("\\", "/") != uri:
                continue
            if s["cwe"] != cwe:
                continue
            dist = abs(s["line"] - line)
            if dist <= args.tolerance and (best_dist is None or dist < best_dist):
                best = s
                best_dist = dist
        if best is None:
            continue  # 不在 JSEF 标注集，丢弃
        out.append({
            "id": best["id"],
            "hit": True,
            "file": uri,
            "line": line,
            "cwe": "CWE-%s" % cwe,
            "message": res.get("message", {}).get("text", "")[:200],
        })

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
    print("[done] %d 条 semgrep finding 桥接到 expected 样本 -> %s" % (len(out), args.out))


if __name__ == "__main__":
    main()
