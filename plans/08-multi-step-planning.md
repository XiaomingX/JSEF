# JSEF × 多步规划 + 长程复杂漏洞挖掘 样本补充计划

> 目标：从第一性原理出发，针对「LLM **多步规划（multi-step planning）** + 长程任务 + 复杂漏洞挖掘」这一评测维度，补齐 JSEF 当前**缺失且有真实区分度**的样本与评测能力。本计划是 `07-long-horizon-complex-vuln.md`（路径推理维度）的互补——`07` 考"路径是否正确"，本计划考"规划步骤是否完整且有序"。
>
> 全程遵循 `AGENTS.md` 的 checkpoint 双源门禁（`// [CHECKPOINT]` + `expectedresults.csv` 一致、退出码 0）与安全底线（仅 localhost 演示）。

---

## 0. 调研结论（学术界 / 开源界）

评估 LLM 多步规划 + 漏洞挖掘的数据集：

| 数据集 | 多步规划刻画方式 | 对 JSEF 的启示 |
|---|---|---|
| **Cybench**（Stanford, arXiv:2408.08926） | **显式 subtask 检查点**：任务拆为顺序子目标（如 find login.php→identify `==`→bypass OTP→get flag），支持 subtask-guided 评分 | JSEF 缺"步骤/子目标"机器可读标注 → 可引入 plan manifest |
| **VulnGym**（Tencent） | `entry_point→critical_operation→trace` 隐式子目标链（节点带 `desc`） | trace 是路径，非步骤；JSEF 已落地 trace |
| **NYU CTF Bench** | 无显式子目标，完全自主规划；暴露"Give up"率高 | 规划失败的负样本可贵 |
| **InterCode**（Princeton） | 交互式 grep/执行反馈循环基座 | agent 工具增强范式 |
| JIT Vuln. Agent（ACL'25） | ReAct thought-action-observation + 跨过程上下文 | 规划需跨过程上下文 |

**规划失败模式（被数据集捕捉，可作区分度设计依据）**：过早下结论、长程失焦、被无害分叉误导、缺"洞察跳跃"、能定位不能证可达性、跨文件推理断裂、token/轮数耗尽。

**关键缺口（第一性原理）**：公开数据集普遍缺 **Java Web 框架语义 + 多步规划**。JSEF 现状：
- `Spring4ShellStateMachine.java` 的 Javadoc **已手写「长程任务子目标清单 ①②③④」**——说明 JSEF 已有多步规划的**内容语义**，但仅停留在注释，**无机器可读、可自动评测的步骤链**。
- CSV 固定 10 列、`trace` 列已用于"路径正确性"评测（VulnGym 式），**不可改其语义承载步骤**。
- `grep plan/subgoal/pipeline` → 0 结果，无独立规划评测机制。

---

## 1. 设计原则

1. **不碰 10 列 / 不碰 trace 语义**：步骤链走**独立 manifest**，与源码/CSV 通过 `id` 关联，保持现有双源门禁不变。
2. **plan manifest 机器可读**：新增 `benchmark/plans/<id>.plan.json`，含有序 `steps[]`（每步 `goal` + 可选 `evidence` 源码锚点 `file:line`）。对标 Cybench subtask 检查点。
3. **新样本 Javadoc 同步写「子目标清单」**（沿用 Spring4ShellStateMachine 风格），并引用对应 plan manifest 文件名。
4. **评测可选增强**：`scorecard.py` 新增 `--check-plan` 模式，比对被测结果声明的步骤序列与期望步骤（覆盖率 + 顺序正确性），不影响现有 `scorecard`/`validate` 默认行为。
5. **每 vuln 配 safe 配对**（safe 实现真实防护），用于 FP/TN。
6. **SNIPPET 级、不编译**。

---

## 2. 实施阶段

### Phase P1 — 规划评测基础设施（不破坏现有门禁）
- 新增 `benchmark/plans/` 目录与 `benchmark/plans/README.md`，约定 manifest schema：
  ```json
  {
    "id": "JSEF-MSP-001",
    "steps": [
      {"goal": "识别绑定开关默认状态", "evidence": "benchmark/cases/vuln/.../X.java:NN"},
      {"goal": "追踪参数名→对象图路径映射", "evidence": "..."},
      {"goal": "判定状态机危险分支", "evidence": "..."},
      {"goal": "产出可达性证明至 sink", "evidence": "benchmark/cases/vuln/.../X.java:NN"}
    ]
  }
  ```
- 扩展 `validate_checkpoints.py`：**新增可选 `--plans-dir`**，仅做"manifest 的 id 与 CSV/源码 id 关联一致性"检查（孤儿 manifest / 孤儿 id），**仅告警不阻断**（保持现有退出码 0 门禁不变）。
- `scorecard.py` 新增 `compute_plan_metrics`（coverage / order），由 `--check-plan` 触发。

### Phase P2 — 框架状态机类多步规划样本（L5）
落点：`benchmark/cases/vuln/msp-statemachine/`、`sec/`、`benchmark/plans/`。
- `MvcBinderStateMachine`（L5）：绑定开关状态机 + `@InitBinder` 危险分支；plan 4 步（识别开关→映射参数名→判定分支→证 sink）。
- `JpaMethodSecurityStateMachine`（L5）：方法级安全注解 `@PreAuthorize` 被状态机绕过；plan 含"解析 SpEL 权限表达式→识别可绕过状态→证越权"。
- 各配 safe + 对应 `.plan.json`。

### Phase P3 — 跨文件侦察类多步规划样本（L4）
落点：`benchmark/cases/vuln/msp-recon/`、`sec/`、`benchmark/plans/`。
- `ReconChainSql`（L4）：要求 agent 先 grep 找到 source 点→跨 3 文件追到 Repository→识别派生查询注入；plan 显式列"信息收集→调用图构建→污点确认"3 步。
- `ReconChainSsrf`（L4）：source 在 Filter，sink 在 Service，中间经 2 个无害中转；plan 含"识别入口 Filter→追中转→证内网 sink"。
- 各配 safe + `.plan.json`。

### Phase P4 — 误导分叉类规划鲁棒样本（L4–L5，考规划失败模式）
落点：`benchmark/cases/vuln/msp-distractor/`、`sec/`、`benchmark/plans/`。
- `DistractorForkCmd`（L4）：主路径污点经 ServiceB→sink，同时存在无害 `auditLog()` 分叉 + 一个"看起来像 sink 但被白名单拦截"的假 sink；plan 步骤要求"排除假 sink、忽略无害分叉、锁定真 sink"——直接对抗调研中的「被无害分叉误导」「过早下结论」失败模式。
- `DecoyParamXss`（L5）：多个参数中仅 1 个真正到达 sink，其余经净化；plan 要求"识别真污点参数、排除已净化参数"。
- 各配 safe + `.plan.json`。

### Phase P5 — 可达性证明类样本（L5，考"能定位不能证可达"失败模式）
落点：`benchmark/cases/vuln/msp-reachability/`、`sec/`、`benchmark/plans/`。
- `VersionGatedReachability`（L5）：sink 仅在依赖版本 ≥ X 且配置开启时可达；plan 末步必须为"产出可达性证明（版本+配置双条件）"，对抗「缺洞察跳跃」「能定位不能证可达」。
- `ConditionalAuthzBypass`（L5）：越权仅在并发/特定时序下可达；plan 含"识别时序窗口→证可达性"。
- 各配 safe + `.plan.json`。

---

## 3. 验证清单（每阶段）

- [ ] 每个 vuln 配 ≥1 safe，`validate_checkpoints.py`（**不加** `--plans-dir` 时）退出码 **0**，双源无孤儿/重复/行号漂移。
- [ ] 新增 `.plan.json` 的 `id` 与 CSV/源码 `// [CHECKPOINT]` 的 `id` 一致；`validate_checkpoints.py --plans-dir benchmark/plans` 报"0 孤儿"（仅告警）。
- [ ] 自测：构造带 `plan` 步骤序列的结果 JSON，跑 `scorecard.py --check-plan`，确认 coverage/order 指标输出；故意乱序步骤应降 order 分。
- [ ] 安全底线：仅 localhost 演示语义，无真实利用脚本；桩带 `// 语义等价:` 注释。

---

## 4. 预期增量

- 新增约 **12–16 个 checkpoint**（P2–P5 每阶段 2–4 vuln+配对），新增 category：`msp-statemachine` / `msp-recon` / `msp-distractor` / `msp-reachability` 共 4 类。
- 能力升级：JSEF 从「路径正确性（trace）」升级到「**规划步骤完整性与顺序正确性（plan）**」，对标 Cybench subtask 但保留 Java Web 框架语义差异化；可直接评测调研所列"规划失败模式"。
- 不破坏现有门禁：10 列不变、trace 语义不变、validate 默认退出码 0 不变。

---

## 5. 参考源

- Cybench：https://cybench.github.io（subtask 检查点范式）
- VulnGym：https://github.com/Tencent/VulnGym（trace 节点理念，已落地）
- NYU CTF Bench：arXiv:2406.05590
- InterCode：NeurIPS'23
- 现有模板：`benchmark/cases/vuln/longtask/Spring4ShellStateMachine.java`（Javadoc 子目标清单风格）、`benchmark/cases/vuln/ChainController.java`（跨文件 trace）、`AGENTS.md`（checkpoint 门禁）、`benchmark/scripts/validate_checkpoints.py`（trace 解析，可扩展 plans 关联）、`benchmark/scripts/scorecard.py`（`compute_trace_metrics` 可参照实现 `compute_plan_metrics`）

---

## 6. 完成判定

1. 新增 4 类多步规划样本全部带 `// [CHECKPOINT]` 且 CSV 双源一致，validator 零问题、退出码 0。
2. 每个新样本配套 `benchmark/plans/<id>.plan.json`，id 与双源一致；`--plans-dir` 关联检查 0 孤儿。
3. `scorecard.py --check-plan` 可输出步骤 coverage/order 指标，能区分乱序/缺步。
4. 对抗"规划失败模式"（分叉误导、假 sink、可达性证明缺失）的样本落地。
5. 未触发安全底线。
