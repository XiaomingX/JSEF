#!/usr/bin/env python3
"""JSEF Benchmark — 双源校验脚本（validate_checkpoints.py）。

校验 ``expectedresults.csv``（事实源）与样本源码中 ``// [CHECKPOINT id=...]``
注解之间的一致性，防止两源漂移。

校验项
------
1. 孤儿 CSV 行：CSV 中有但源码无对应 CHECKPOINT 注解的 id。
2. 孤儿源码注解：源码有但 CSV 无对应行的 id。
3. 重复 id：CSV 内或源码内出现多次的 id。
4. 行号漂移：对两源都能定位的 id，校验 CSV ``line`` 列是否等于该
   CHECKPOINT 注解所在实际行号（grep -n 得到）。不一致报告
   "id=X csv_line=N actual_line=M"。

约束
----
纯标准库（os / argparse / sys / subprocess / re），无第三方依赖。

退出码
------
0 = 通过（无孤儿/重复/漂移）；1 = 存在问题。

示例
----
    python validate_checkpoints.py \
        --expected benchmark/expectedresults.csv \
        --cases-dir benchmark/cases \
        --src-dir src/main/java/com/freedom/securitysamples/vulnerability
"""

import argparse
import csv
import os
import re
import subprocess
import sys

# 匹配 // [CHECKPOINT ... id=JSEF-XXX ...]
CHECKPOINT_RE = re.compile(r"//\s*\[CHECKPOINT\b[^\]]*?\bid=([^\s,\]]+)")

# 可选 trace 字段：trace=FileA.java:lineB,FileC.java:lineD
# 非贪婪捕获到下一个空白或 ] 为止，逗号分隔的 file:line 节点列表。
TRACE_RE = re.compile(r"trace=([^\]\s]+)")

# 单个 trace 节点：相对仓库根路径:行号
TRACE_NODE_RE = re.compile(r"^(?P<file>.+):(?P<line>\d+)$")


def load_csv_ids(expected_path):
    """读取 CSV，返回 (id->line, id_list_in_order)。

    Returns:
        tuple: (csv_map, csv_order, missing_line_ids)
            - csv_map: {id: int(line)}（line 解析失败存 -1）。
            - csv_order: 出现顺序的 id 列表（用于重复检测）。
            - missing_line_ids: 无有效 line 列的 id 列表。
    """
    if not os.path.isfile(expected_path):
        raise FileNotFoundError("找不到 expectedresults.csv: %s" % expected_path)
    csv_map = {}
    csv_order = []
    missing_line_ids = []
    with open(expected_path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise KeyError("CSV 为空或无法解析表头")
        if "id" not in reader.fieldnames or "line" not in reader.fieldnames:
            raise KeyError("expectedresults.csv 缺少 id 或 line 列")
        for row in reader:
            sid = (row.get("id") or "").strip()
            if not sid:
                continue
            csv_order.append(sid)
            raw_line = (row.get("line") or "").strip()
            try:
                line = int(raw_line)
            except (ValueError, TypeError):
                line = -1
                missing_line_ids.append(sid)
            csv_map[sid] = line
    return csv_map, csv_order, missing_line_ids


def scan_source_ids(dirs):
    """用 grep 扫描多个目录下所有 ``// [CHECKPOINT id=...]`` 注解。

    Args:
        dirs: 待扫描目录列表（存在才扫）。

    Returns:
        dict: {(path, line_no): id} —— 记录每个注解出现的位置与 id。
    """
    found = {}
    for d in dirs:
        if not os.path.isdir(d):
            continue
        try:
            proc = subprocess.run(
                ["grep", "-rn", "-E", r"//\s*\[CHECKPOINT", d],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, check=False,
            )
        except FileNotFoundError:
            # 无 grep 时退化为逐文件读取
            for root, _sub, files in os.walk(d):
                for fn in files:
                    if not fn.endswith(".java"):
                        continue
                    fp = os.path.join(root, fn)
                    with open(fp, encoding="utf-8", errors="ignore") as fh:
                        for i, line in enumerate(fh, 1):
                            m = CHECKPOINT_RE.search(line)
                            if m:
                                trace_m = TRACE_RE.search(line)
                                found[(fp, i)] = (m.group(1).strip(),
                                                 trace_m.group(1) if trace_m else "")
            continue
        for line in proc.stdout.splitlines():
            # 形如 path:lineno:content
            parts = line.split(":", 2)
            if len(parts) < 3:
                continue
            path, lineno_s, content = parts[0], parts[1], parts[2]
            m = CHECKPOINT_RE.search(content)
            if not m:
                continue
            try:
                lineno = int(lineno_s)
            except ValueError:
                lineno = -1
            trace_m = TRACE_RE.search(content)
            found[(path, lineno)] = (m.group(1).strip(),
                                      trace_m.group(1) if trace_m else "")
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="校验 expectedresults.csv 与源码 CHECKPOINT 注解的双源一致性。",
    )
    parser.add_argument("--expected",
                        default="benchmark/expectedresults.csv",
                        help="expectedresults.csv 路径（默认 benchmark/expectedresults.csv）")
    parser.add_argument("--cases-dir",
                        default="benchmark/cases",
                        help="样本 cases 目录（默认 benchmark/cases）")
    parser.add_argument("--src-dir",
                        default="src/main/java/com/freedom/securitysamples/vulnerability",
                        help="漏洞源码目录（默认 src/main/java/.../vulnerability）")
    args = parser.parse_args(argv)

    rc = 0
    try:
        csv_map, csv_order, missing_line_ids = load_csv_ids(args.expected)
    except (FileNotFoundError, KeyError) as exc:
        print("[错误] %s" % exc, file=sys.stderr)
        return 2

    source_found = scan_source_ids([args.cases_dir, args.src_dir])

    # 源码 id -> 位置列表（含 trace 字符串）
    src_id_locations = {}
    src_id_trace = {}  # id -> trace 字符串（来自 CHECKPOINT 注解的 trace=）
    for (path, lineno), (sid, trace_str) in source_found.items():
        src_id_locations.setdefault(sid, []).append((path, lineno))
        if trace_str:
            src_id_trace[sid] = trace_str

    csv_ids = set(csv_map)
    src_ids = set(src_id_locations)

    print("=" * 64)
    print("JSEF 双源校验：%s" % args.expected)
    print("  扫描目录：%s , %s" % (args.cases_dir, args.src_dir))
    print("  CSV id 数=%d  源码注解 id 数=%d" % (len(csv_ids), len(src_ids)))
    print("=" * 64)

    # 1) 孤儿 CSV 行
    orphan_csv = sorted(csv_ids - src_ids)
    if orphan_csv:
        rc = 1
        print("\n[孤儿 CSV 行] CSV 有但源码无 CHECKPOINT 注解（共 %d）：" % len(orphan_csv))
        for sid in orphan_csv:
            print("  - %s (csv_line=%s)" % (sid, csv_map[sid]))
    else:
        print("\n[孤儿 CSV 行] 无（通过）")

    # 2) 孤儿源码注解
    orphan_src = sorted(src_ids - csv_ids)
    if orphan_src:
        rc = 1
        print("\n[孤儿源码注解] 源码有但 CSV 无对应行（共 %d）：" % len(orphan_src))
        for sid in orphan_src:
            locs = src_id_locations[sid]
            print("  - %s (%s)" % (sid, ", ".join("%s:%d" % (p, n) for p, n in locs)))
    else:
        print("\n[孤儿源码注解] 无（通过）")

    # 3) 重复 id
    csv_dup = sorted({sid for sid in csv_order if csv_order.count(sid) > 1})
    src_dup = sorted({sid for sid, locs in src_id_locations.items() if len(locs) > 1})
    if csv_dup or src_dup:
        rc = 1
        if csv_dup:
            print("\n[CSV 内重复 id]（共 %d）：" % len(csv_dup))
            for sid in csv_dup:
                print("  - %s 出现 %d 次" % (sid, csv_order.count(sid)))
        if src_dup:
            print("\n[源码内重复 id]（共 %d）：" % len(src_dup))
            for sid in src_dup:
                for p, n in src_id_locations[sid]:
                    print("  - %s @ %s:%d" % (sid, p, n))
    else:
        print("\n[重复 id] 无（通过）")

    # 4) 行号漂移
    drift = []
    for sid in sorted(csv_ids & src_ids):
        csv_line = csv_map[sid]
        locs = src_id_locations[sid]
        if csv_line < 0:
            continue  # 已在 missing_line_ids 中体现
        if len(locs) > 1:
            continue  # 重复情况已在上面报告，跳过逐行比对
        _path, actual_line = locs[0]
        if actual_line != csv_line:
            drift.append((sid, csv_line, actual_line))
    if drift:
        rc = 1
        print("\n[行号漂移] CSV line 与实际 CHECKPOINT 行不一致（共 %d）：" % len(drift))
        for sid, csv_line, actual_line in drift:
            print("  - id=%s csv_line=%d actual_line=%d" % (sid, csv_line, actual_line))
    else:
        print("\n[行号漂移] 无（通过）")

    if missing_line_ids:
        rc = 1
        print("\n[CSV line 列无效]（共 %d）：%s" % (
            len(missing_line_ids), ", ".join(missing_line_ids)))

    # 5) trace 节点有效性（仅告警，不阻断，不置 rc=1）
    trace_ids = sorted(src_id_trace)
    trace_invalid = 0
    if trace_ids:
        print("\n[trace 节点] 共 %d 个样本带 trace" % len(trace_ids))
        for sid in trace_ids:
            trace_str = src_id_trace[sid]
            nodes = [n.strip() for n in trace_str.split(",") if n.strip()]
            for node in nodes:
                nm = TRACE_NODE_RE.match(node)
                if not nm:
                    trace_invalid += 1
                    print("  - id=%s trace node %s 格式非法（应为 相对路径:行号）" % (sid, node))
                    continue
                nfile = nm.group("file")
                nline = int(nm.group("line"))
                # 相对于仓库根解析（grep 给出的 path 已经是相对路径）
                if not os.path.isfile(nfile):
                    trace_invalid += 1
                    print("  - id=%s trace node %s NOT FOUND" % (sid, node))
                    continue
                try:
                    with open(nfile, encoding="utf-8", errors="ignore") as fh:
                        total_lines = sum(1 for _ in fh)
                except OSError:
                    total_lines = 0
                if nline < 1 or nline > total_lines:
                    trace_invalid += 1
                    print("  - id=%s trace node %s 行号越界（文件共 %d 行）"
                          % (sid, node, total_lines))
        print("[trace 节点] %d 个无效" % trace_invalid)
    else:
        print("\n[trace 节点] 共 0 个样本带 trace")

    print("\n" + "=" * 64)
    if rc == 0:
        print("结果：通过（0=无孤儿/重复/漂移）")
    else:
        print("结果：存在问题（退出码 1）")
    print("=" * 64)
    return rc


if __name__ == "__main__":
    sys.exit(main())
