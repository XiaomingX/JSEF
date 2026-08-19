# JSEF × 场景化编排 + 检测压力 + 多漏洞组合链 样本补充计划

> 目标：从 **CyScenarioBench**（编排 orchestration / 分支决策 / 状态恢复）、**FrontierCyber**（检测压力 detection pressure / 多漏洞链 / 环境-目标-配置）、**Kimi K3 评测**（长程状态保持 / 工具反馈解释 / 失败恢复）三篇前沿 benchmark 论文中提取**本仓库尚未覆盖**的高价值、有区分度维度，补齐新样本族。
>
> 全程遵循 `AGENTS.md` 的 checkpoint 双源门禁（`// [CHECKPOINT]` + `expectedresults.csv` 一致、退出码 0）与安全底线（仅 localhost 演示、桩方法信名字/注释语义、不写真实攻击载荷）。

---

## 0. 三篇论文核心启发（来源与差异化结论）

| 来源 | 核心能力维度 | 对 JSEF 的差异化价值（经实查，均确认本仓库空白） |
|---|---|---|
| **CyScenarioBench**（2025-12-05） | 编排 orchestration；分支决策准确性；约束遵循；从状态不一致恢复；错误积累/上下文漂移；新手放大 | JSEF 现有 764 checkpoint 全是"**单数据流从 source 到 sink 的可达性**"，缺"**多分支/多约束/需折返**"与"**编排式组合**"语义 |
| **FrontierCyber**（2026-06-22） | **检测压力**（不触发日志/警报/限流/监控即达成目标）；开放路径；多漏洞链；环境-目标-配置 | JSEF **无任何"危险 sink 可达但会被检测到/需规避监控"** 的对抗样本（实查 `evasion/stealth/detect` 类别 = 0） |
| **Kimi K3 评测**（2026-08-19） | 保持攻击状态；解释工具反馈；从失败恢复；把中间发现转为验证结果 | 与"长程任务"（plans/07/08）互补——07 考路径正确、08 考步骤规划，本计划补"**状态保持 + 恢复 + 检测约束**"维度 |

**实查证据**（2026-08-19，`benchmark/expectedresults.csv` 共 764 checkpoint，vuln 402 / safe 362）：
- `category` 列含 `evasion/stealth/detect/cascade/cross-svc` 任意关键词的样本 = **0**。
- `benchmark/cases/{vuln,sec}/detection|cross-svc/` 目录均 **不存在**。
- 现有与"日志"相关样本全是"泄漏（CWE-532 secret-log）"、"缺失审计（CWE-778/390）"、"日志注入（CWE-117）"、"干扰项（msp-distractor）"，**均非"被检测需规避"**。
- 现有与"可达性"相关样本：`DeadBranchSanitizeVuln`（JSEF-DBS-001）是"净化在**死分支**里→sink 反而可达"（VULN 侧反向）；`confusion/*`、`case-bypass`、`regex-sanitize` 是"假消毒/名字混淆"。**无**"活分支把污点消毒截断→该分支不可达 sink"的 SAFE 对照语义。
- plans/07 的 **D5 跨 HTTP 边界污点传播**（`cross-svc/`）已计划但**未落地**（0 目录）。

**已覆盖、不重复**：单点可达性（L0–L2）、间接/跨方法（L3）、跨文件/gadget chain/状态机（L4–L5）、长程任务（07）、多步规划 manifest（08）、假消毒/混淆（confusion 系列）、死分支净化（DBS-001）、跨模块链（bizlogic5/longrange/TrustInternalInput）。

---

## 1. 设计原则

1. **区分度来自"约束/分支/编排"，而非更深的单链**：每个新样本必须引入三篇论文强调、而现有 764 条单数据流样本测不到的能力——检测压力（攻击有代价/会被发现）、分支折返（某分支消毒截断不可达）、级联编排（多系统/多漏洞组合才危险）。
2. **`trace=` 用于路径/节点正确性**：编排与级联样本（L4–L5）带 `trace=`，记录跨文件/跨模块中间节点；`--check-trace` 量化 `trace_recall/precision`。
3. **桩方法信名字/注释语义**（沿用 AGENTS.md 约定）：危险 sink 用语义桩 + `// 语义等价: ...` 声明；检测/审计用真实可读的 `logger`/计数调用表达"会被记录"。
4. **每 vuln 配 safe 配对**（safe 实现真实防护），用于 FP/TN。
5. **SNIPPET 级、不编译**（`benchmark/cases/` 样本规范）。
6. **不碰 10 列 schema**：三篇论文的"环境-目标-配置(EOC)""部分进展捕获""快照"是评测框架层能力，本计划不改为样本层，避免 schema 变更破坏现有门禁；可作为后续评测增强方向单列（见 §5）。

---

## 2. 样本族 A：检测压力 / 规避监控（对标 FrontierCyber）—— 完全空白，最高优先级

**核心语义**：危险 sink 确实可达（VULN 成立），但**同一份代码里存在会把该危险操作记录/审计/限流下来的监控逻辑**。被测对象必须额外判断"这个漏洞**在真实运营中能否不被检测地利用**"——这是纯语法 SAST 看不见、且现有 764 条样本完全测不到的维度。

**区分度设计**（vuln 侧全部 `expect=VULN`，但都带"检测约束"层）：
- 被测对象若只报"sink 可达"得基础分；若能识别"攻击会被审计捕获 / 触发限流"得更高区分（用于 LLM 对比，SAST 因无运营语义普遍只能报可达）。
- safe 侧对照：把监控做强到"攻击必然暴露且失败" → `expect=SAFE`（不是误报，是"实际不可利用"）。

| 样本 id | CWE | level | 语义 | category | sink |
|---|---|---|---|---|---|
| `JSEF-DE-001` | 78 | L2 | 命令注入 sink 前有 `logger.warn("exec: "+cmd)` 把命令写入审计日志 → 攻击可被发现；判 VULN（漏洞在，但需规避检测） | `detection-pressure` | `Runtime.getRuntime().exec` |
| `JSEF-DE-001S` | 78 | L2 | 同命令注入，但 sink 前有**强制审计 + 不可绕过日志**（`logger` + 返回值丢弃不可控）→ 实际不可隐蔽利用，判 SAFE | `detection-pressure` | `Runtime.getRuntime().exec` |
| `JSEF-DE-002` | 89 | L3 | SQL 注入，前面有 `auditTrail` 记录每次 SQL + 调用方 IP（`trace=` 跨审计模块）→ 可发现；判 VULN | `detection-pressure` | `jdbcTemplate.queryForList` |
| `JSEF-DE-003` | 285 | L3 | 越权端点，但存在**限流/失败锁定**（登录失败 N 次锁号）→ 暴力枚举受限；判 VULN（绕过限流才算可利用） | `detection-pressure` | 授权检查旁路 |
| `JSEF-DE-004` | 917 | L4 | SpEL 注入，sink 前置 `securityLogger` 把表达式+栈回溯落日志（`trace=` 跨 SpEL 解析模块）→ 攻击被审计；判 VULN | `detection-pressure` | `SpelExpressionParser.parseExpression` |
| `JSEF-DE-004S` | 917 | L4 | 同 SpEL，但表达式**先过安全沙箱校验**（非法类引用即 throw）→ 不可达，判 SAFE | `detection-pressure` | `SpelExpressionParser.parseExpression` |

> 设计要点：`JSEF-DE-00*S` 的 SAFE 不是"假消毒/名字混淆"（那已由 confusion 覆盖），而是"**监控/防护真实存在且不可绕过 → 实际不可利用**"。这直接对标本仓库空白的 FrontierCyber 检测压力语义。

---

## 3. 样本族 B：编排 / 级联信任 / 多漏洞组合链（对标 CyScenarioBench 编排 + FrontierCyber 多漏洞链 + 补 D5）

**核心语义**：单个系统/模块看似正常，**多个系统/漏洞/信任关系组合起来才危险**。包括：
- **B1 跨 HTTP 边界污点传播（补落地 plans/07 D5）**：污点经 `RestTemplate`/`Feign` 调下游服务、下游回传数据再进 sink。JSEF 现有跨模块链全是**进程内**（bizlogic5/longrange），**跨服务边界**完全空白。
- **B2 级联信任（多实体网络推理）**：系统 A 的配置/状态决定系统 B 的权限决策（CyScenarioBench multi-entity）。JSEF 有 `TrustInternalInput`（单模块隐式信任）与 `CrossTenantAdminService`（组合链），缺"**跨系统配置→下游权限决策**"的级联语义。
- **B3 多漏洞组合链（multi-vuln chain）**：单一目标需**先后利用两种不同漏洞**（如 信息泄露→凭据→越权）才达成目标（FrontierCyber 强调"构建 multi-vulnerability chain"）。JSEF 的 gadget chain 是"**单漏洞类型内**多类组合"，缺"**不同漏洞类型串成完整链**"。

| 样本 id | CWE | level | 语义 | category | sink |
|---|---|---|---|---|---|
| `JSEF-OS-001` | 89 | L4 | 跨 HTTP 边界：Controller A 收到不可信参数 → `RestTemplate` 调 Service B → B 回传 SQL 片段 → A 拼入 `queryForList`（`trace=` 跨 A/B 两文件 + 服务调用桩） | `cross-svc-taint` | `jdbcTemplate.queryForList` |
| `JSEF-OS-001S` | 89 | L4 | 同链，但 Service B 回传前用 `PreparedStatement`/参数化 → 判 SAFE | `cross-svc-taint` | `PreparedStatement` |
| `JSEF-OS-002` | 918 | L4 | 跨服务 SSRF：内网服务 A 把下游服务 B 返回的 URL 直接作为 `HttpURLConnection` 目标（隐式信任跨系统回传）→ SSRF | `cascade-trust` | `HttpURLConnection.openConnection` |
| `JSEF-OS-003` | 285 | L5 | 级联：系统 A 的 `featureFlag`（配置）被不可信来源改写 → 系统 B 据此放行权限（跨文件 `trace=` 配置→权限决策两节点） | `cascade-trust` | 授权检查旁路 |
| `JSEF-OS-004` | 639+502 | L5 | 多漏洞组合链：先凭信息泄露（CWE-532 日志泄漏 user id）拿到资源标识 → 再经未授权反序列化（CWE-502）达成越权读他人数据；两个独立 checkpoint 在同一目标上串成链（`trace=` 跨三文件） | `multi-vuln-chain` | 越权数据访问 + 反序列化 sink |
| `JSEF-OS-004S` | 639+502 | L5 | 同组合链，但第二环反序列化有白名单、第一环日志不泄漏 user id → 链条中断不可达，判 SAFE | `multi-vuln-chain` | — |

> 设计要点：
> - `JSEF-OS-00*` 的 `trace=` 必须指向真实存在的跨文件/跨服务中间节点（validate 仅告警不阻断，但需真实存在）。
> - `multi-vuln-chain`（B3）在 JSEF 是**首创 category**——现有 gadget chain 是单类型链，这里是**多漏洞类型串链**，直接对标 FrontierCyber "multi-vulnerability chain" 与 CyScenarioBench "orchestration"。

---

## 4. 样本族 C：活分支消毒截断 / 分支折返（对标 CyScenarioBench branching-dead-ends）

**核心语义**：污点看起来直连 sink，但中间存在一个**活分支**（`if`/`switch`/三元）在某条路径上把污点消毒/替换，导致**那条路径到不了 sink**。与现有样本的区别：
- 与 `DeadBranchSanitizeVuln`（JSEF-DBS-001）**方向相反**：DBS 是"净化在死分支（恒假）→ sink 可达"，本族是"净化在**活分支**（可达）→ 某分支 sink 不可达"。
- 与 `confusion`/`case-bypass`/`regex-sanitize` 不同：那些是"假消毒/名字混淆"（污点实际没被截断，VULN 成立），本族是"**真消毒在某条路径真实生效**"（SAFE 语义——该分支的 sink 确实不可达）。

**区分度价值**：测被测对象**是否过早下结论**。弱工具/模型看到"有 sanitize 调用"就报 SAFE（实际另一分支 VULN），或看到"有 sink"就报 VULN（实际该分支已被消毒截断 → FP）。正是 CyScenarioBench 的 "branching-dead-ends + 过早下结论" 失败模式。

| 样本 id | CWE | level | 语义 | category | sink |
|---|---|---|---|---|---|
| `JSEF-DEAD-001` | 78 | L3 | 命令注入：`if (isAdmin)` 分支对 cmd 做**完整消毒**（去掉 `;|&`）并走消毒路径；`else` 分支原样拼入 `exec` → 仅 else 分支 VULN，if 分支不可达；判 VULN（至少一条活路径可达） | `branch-dead-end` | `Runtime.getRuntime().exec` |
| `JSEF-DEAD-001S` | 78 | L3 | 同代码但 `if` 分支的消毒**恒为真路径**（两分支都消毒）→ 两条路径均截断，判 SAFE | `branch-dead-end` | `Runtime.getRuntime().exec` |
| `JSEF-DEAD-002` | 89 | L4 | SQL：`switch(param.getType())` 多分支，仅 `default` 分支参数化，其余分支拼 SQL → 需判断哪些分支可达 sink（`trace=` 跨多个 case 行） | `branch-dead-end` | `Statement.executeQuery` |
| `JSEF-DEAD-002S` | 89 | L4 | 同 switch 但**所有分支都参数化** → 判 SAFE | `branch-dead-end` | `PreparedStatement` |
| `JSEF-DEAD-003` | 79 | L3 | XSS：三元 `ctx.isSafe() ? escape(input) : raw` 双分支之一未编码 → 需判断哪条可达 sink；判 VULN | `branch-dead-end` | 响应输出 |

> 设计要点：每个 VULN 样本的 checkpoint 行号落在**真正可达 sink 的那条分支**的 sink 行；SAFE 对照的 checkpoint 落在消毒后的安全 sink 行。`trace=` 对多分支样本（DEAD-002）记录分支判定与 sink 两个节点。

---

## 5. 建议（可选，不做硬门禁）：评测框架层增强方向

三篇论文中"环境-目标-配置(EOC)""部分进展捕获""快照""编排状态保持"等属于**评测框架**而非单样本语义，当前 JSEF 10 列 schema 已满、不宜改动。若未来要补，可单独立项：
- **plan manifest 扩展**（对标 CyScenarioBench attack-tree / 约束遵循）：在 plans/08 的 `.plan.json` 中为 A/B 族样本追加 `constraints[]`（如"不得触发检测""必须保持状态一致"），供 `--check-plan` 扩展评测"约束遵循 + 状态恢复"。
- **detection-evasion 评测模式**：scorecard 新增可选 `--check-detection`，比对被测对象结果中是否识别"检测压力"层（识别到额外加分），不影响现有 Recall/Precision/F1/MCC。

---

## 6. 实施与门禁清单（贡献者必读）

每新增一个样本，完成以下步骤（缺一不可）：

1. **写样本**：`benchmark/cases/vuln/<族>/` 与 `benchmark/cases/sec/<族>/` 配对落地（A→`detection/`，B→`cross-svc/`|`cascade/`|`multivuln/`，C→`branch-dead-end/`），沿用现有 `longrange/Entry.java` 的 Javadoc「子目标/链路说明」风格，标注 `// [VULN]`。
2. **加 checkpoint**：在污点到达（或到达且被截断的）sink 精确行上方加 `// [CHECKPOINT id=JSEF-<族>-<序号> cwe=<CWE> level=<L2-L5> source=<不可信源> sink=<危险终点> expect=VULN|SAFE]`；L4–L5 带 `trace=`。
3. **补 CSV**：追加 10 列元数据到 `benchmark/expectedresults.csv`，`type` 与 `expect` 一致、`line` 为真实行号、category 用上表 slug。
4. **自测**：`python3 benchmark/scripts/scorecard.py --expected benchmark/expectedresults.csv --result <你的结果>` 验证两源 id 可关联。
5. **双源校验（硬门禁）**：新增/修改前与收尾前运行，退出码必须为 0：
   ```bash
   python3 benchmark/scripts/validate_checkpoints.py \
     --expected benchmark/expectedresults.csv \
     --cases-dir benchmark/cases \
     --src-dir src/main/java/com/freedom/securitysamples/vulnerability
   ```
   `trace=` 节点若使用必须指向真实存在的源码行（validate 仅告警不阻断，但无效节点需修正）。

---

## 7. 完成判定

- A/B/C 三族样本的 `// [CHECKPOINT]` 与 `expectedresults.csv` 两源一致、皆含新 id。
- `benchmark/scripts/validate_checkpoints.py` 退出码 0。
- 新增 category：`detection-pressure` / `cross-svc-taint` / `cascade-trust` / `multi-vuln-chain` / `branch-dead-end` 在 CSV 中真实出现。
- 未触发安全底线（仅 localhost 演示、桩方法语义声明、无真实攻击载荷）。
