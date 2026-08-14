#!/usr/bin/env bash
# =============================================================================
# JSEF Benchmark — 端到端运行 Harness（Phase 7）
#
# Usage:
#   ./run_benchmark.sh <results-root> <expected-csv> <timeout-ms>
#
# 参数：
#   results-root  结果根目录；其下每个子目录是一个被测对象（含 result.json 或 *.sarif）
#   expected-csv  事实源 expectedresults.csv 路径
#   timeout-ms    单次样本超时阈值（ms），用于超时统计（默认 120000）
#
# 流程：
#   1) 对每个对象：调用 scorecard.py 单对象模式 → <obj>/scorecard.json
#   2) 调 scorecard.py --results-dir → <results-root>/cross_matrix.json
#   3) 调 generate_report.py → <results-root>/report.md（同目录 report.json / radar_data.json / ranking.png）
#
# -----------------------------------------------------------------------------
# 公平性约束（明文化，务必遵守）
# -----------------------------------------------------------------------------
#   * 同提示词：所有被测对象必须共用 benchmark/prompts/vuln_hunt.md 这一份提示词。
#   * 同样本：  所有对象对同一批样本（expectedresults.csv 覆盖的样本）产出结果。
#   * 只换对象：对比时仅切换被测对象（SAST 工具 / 不同 LLM），不改提示词、不换样本、
#               不改超时阈值（除非显式声明）。否则结果不可比。
#   * 结果落盘：每个对象目录放 result.json（id→{hit,file,line,...} 列表/字典）
#               或 *.sarif；scorecard 会自动优先 result.json，否则首个 *.sarif。
# =============================================================================

set -euo pipefail

# ---- 参数 ----
RESULTS_ROOT="${1:-}"
EXPECTED_CSV="${2:-}"
TIMEOUT_MS="${3:-120000}"

if [ -z "$RESULTS_ROOT" ] || [ -z "$EXPECTED_CSV" ]; then
  echo "Usage: $0 <results-root> <expected-csv> <timeout-ms>" >&2
  exit 2
fi

if [ ! -d "$RESULTS_ROOT" ]; then
  echo "[错误] results-root 不存在或不是目录: $RESULTS_ROOT" >&2
  exit 2
fi
if [ ! -f "$EXPECTED_CSV" ]; then
  echo "[错误] expected-csv 不存在: $EXPECTED_CSV" >&2
  exit 2
fi

# ---- 定位脚本（相对仓库根，支持从任意目录调用）----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCORECARD="$SCRIPT_DIR/scripts/scorecard.py"
REPORTER="$SCRIPT_DIR/reports/generate_report.py"

if [ ! -f "$SCORECARD" ]; then
  echo "[错误] 找不到 scorecard.py: $SCORECARD" >&2
  exit 2
fi

echo "==================================================================="
echo " JSEF Benchmark Harness"
echo " results-root : $RESULTS_ROOT"
echo " expected-csv : $EXPECTED_CSV"
echo " timeout-ms   : $TIMEOUT_MS"
echo "==================================================================="

# ---- 步骤 1：逐对象单对象评分 ----
obj_count=0
for obj_dir in "$RESULTS_ROOT"/*/; do
  [ -d "$obj_dir" ] || continue
  obj_name="$(basename "$obj_dir")"

  # 优先 result.json，否则首个 *.sarif
  result_file=""
  if [ -f "$obj_dir/result.json" ]; then
    result_file="$obj_dir/result.json"
  else
    shopt -s nullglob
    sarif_files=("$obj_dir"*.sarif)
    shopt -u nullglob
    if [ ${#sarif_files[@]} -gt 0 ]; then
      result_file="${sarif_files[0]}"
    fi
  fi

  if [ -z "$result_file" ]; then
    echo "[跳过] 对象 '$obj_name' 无 result.json 或 *.sarif"
    continue
  fi

  echo "[评分] 对象 '$obj_name' <- $(basename "$result_file")"
  python3 "$SCORECARD" \
    --expected "$EXPECTED_CSV" \
    --result "$result_file" \
    --name "$obj_name" \
    --timeout-ms "$TIMEOUT_MS" \
    --out "$obj_dir/scorecard.json"
  obj_count=$((obj_count + 1))
done

if [ "$obj_count" -eq 0 ]; then
  echo "[警告] results-root 下无任何可评分对象，仍尝试生成交叉矩阵（可能为空）。"
fi

# ---- 步骤 2：交叉矩阵 ----
echo ""
echo "[交叉矩阵] 聚合所有对象 → $RESULTS_ROOT/cross_matrix.json"
python3 "$SCORECARD" \
  --expected "$EXPECTED_CSV" \
  --results-dir "$RESULTS_ROOT" \
  --timeout-ms "$TIMEOUT_MS" \
  --out "$RESULTS_ROOT/cross_matrix.json"

# ---- 步骤 3：报告生成 ----
echo ""
echo "[报告] 生成 report.md → $RESULTS_ROOT/report.md"
python3 "$REPORTER" \
  --cross-matrix "$RESULTS_ROOT/cross_matrix.json" \
  --expected "$EXPECTED_CSV" \
  --out "$RESULTS_ROOT/report.md"

echo ""
echo "==================================================================="
echo " 完成。产出："
echo "   - $RESULTS_ROOT/cross_matrix.json"
echo "   - $RESULTS_ROOT/report.md"
echo "   - $RESULTS_ROOT/report.json (机器可读)"
echo "   - $RESULTS_ROOT/radar_data.json / ranking.png (可选)"
echo "==================================================================="
