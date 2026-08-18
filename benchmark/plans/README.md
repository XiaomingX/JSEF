# JSEF 多步规划清单（plan manifest）

本目录存放「多步规划（multi-step planning）」评测所需的**步骤清单（sub-goal chain）**，
与 `expectedresults.csv` / 源码 `// [CHECKPOINT]` 通过 **`id`** 关联。

## 设计动机

`expectedresults.csv` 固定 10 列，`trace` 列（第 10 列）已用于「路径正确性」评测
（VulnGym 式 `entry_point → critical_operation → trace`）。为评测 LLM 的
**规划能力**（是否按正确顺序完成多步子目标），本目录提供独立的、机器可读的
步骤清单，不污染现有双源门禁（10 列 / trace 语义 / 退出码 0 均不变）。

对标 Cybench 的显式 subtask 检查点范式：长程漏洞挖掘任务被拆为有序子目标，
被测 agent 声明的步骤序列可与期望步骤比对，产出「步骤覆盖率」与「顺序正确性」。

## manifest schema

每个样本一个文件：`<id>.plan.json`，如 `JSEF-MSP-001.plan.json`。

```json
{
  "id": "JSEF-MSP-001",
  "title": "MvcBinderStateMachine 多步规划",
  "steps": [
    {"goal": "识别绑定开关默认状态", "evidence": "benchmark/cases/vuln/msp-statemachine/MvcBinderStateMachine.java:NN"},
    {"goal": "追踪参数名→对象图路径映射", "evidence": "benchmark/cases/vuln/msp-statemachine/MvcBinderStateMachine.java:NN"},
    {"goal": "判定状态机危险分支（开关为真时可达 SpEL sink）", "evidence": "benchmark/cases/vuln/msp-statemachine/MvcBinderStateMachine.java:NN"},
    {"goal": "产出可达性证明至 SpEL sink", "evidence": "benchmark/cases/vuln/msp-statemachine/MvcBinderStateMachine.java:NN"}
  ]
}
```

字段说明：
- `id`：**必填**，与 `expectedresults.csv` 的 `id` 列、源码 `// [CHECKPOINT id=...]` 完全一致。
- `title`：可选，人类可读标题。
- `steps`：**有序**数组，每步含：
  - `goal`：子目标自然语言描述（agent 应执行的规划步骤）。
  - `evidence`：可选，该步骤对应的源码证据锚点 `相对仓库根路径:行号`（与 trace 节点同格式）。

## 评测

- `benchmark/scripts/validate_checkpoints.py --plans-dir benchmark/plans`
  在原有双源校验之外，额外做 manifest 与 CSV/源码的 `id` 关联一致性检查
  （孤儿 manifest / 孤儿 id），**仅告警不阻断**（保持退出码 0 门禁不变）。
- `benchmark/scripts/scorecard.py --check-plan --result <结果>`
  对支持 plan 的样本（CSV `category` 以 `msp-` 开头或 manifest 存在），
  比对被测结果声明的 `plan` 步骤序列与期望步骤，产出：
  - `plan_coverage`：命中期望步骤比例（集合覆盖）。
  - `plan_order`：顺序正确性（LCSubSeq / 编辑距离口径）。

## 关联约定

- manifest 文件名 = `<id>.plan.json`，便于人工定位与脚本扫描。
- 每个 vuln 样本的 `id` 在 `benchmark/plans/` 下应有且仅有一个 manifest；
  其配套 safe 样本（`id` 形如 `...S`）可共用同一 manifest（sec 路径通常是 vuln 的净化版）。
