# JSEF Benchmark 计划：SAST 能力与多模型漏洞挖掘验收

> 目标：在 JSEF 现有 35+ 漏洞教学案例基础上，建立一套**可用于验收 SAST 基础能力**与**对比多个大模型漏洞挖掘能力差异**的 benchmark。
> 验收维度：误报（FP）、漏报（FN）、平均耗时、超时样本、报告简洁度、能力完备程度。
> 本文档是"设计 + 规划"文档，不直接实现采样代码；样本以"有区分度的梯度 + 机器可读 checkpoint 标注"方式落入项目。

---

## 0. 现状分析（已确认，非待办）

通过阅读 `src/main/java/com/freedom/securitysamples/vulnerability/`、`.prompt/technical_architecture.md`、`skill.md`、`agent.md` 确认：

- **已有结构**：漏洞代码在 `vuln` 子包、安全代码在 `sec` 子包，URL 形如 `/api/v1/{type}/unsafe/{scenario}` 与 `/api/v1/{type}/safe/{scenario}`。
- **现有标注约定**（来自 `skill.md` 与样本文件）：
  - 行内标记：`// [VULN] 漏洞点：直接使用了用户输入的ID`
  - 方法 Javadoc：`VULNERABLE:` / `安全示例` / `漏洞点：...` / `攻击示例：...`
  - 包名隔离：`vuln`（不安全）/ `sec`（安全）
- **关键缺口（本计划要补齐）**：
  1. 缺少**机器可读的 checkpoint 标注**（精确 `file:line`、source、sink、CWE、期望判定）——无法自动算 TP/FP/FN/TN。
  2. 现有样本以"教学对比"为目的，**区分度梯度不足**——缺少多跳污点、间接污点（Map/字段）、跨文件/跨方法、框架语义依赖、gadget chain 等能拉开工具/模型档次的设计。
  3. 缺少统一的 **expectedresults** 清单与 scorecard 计算口径，无法交叉对比。

---

## 1. 待办总览

### Phase A — SAST 第一性原理能力模型（设计，不实现采样）
- [x] A1. 定义 SAST 能力验收维度矩阵（12 项基础能力 → 可观测指标）
- [x] A2. 设计 LLM 侧统一验收协议（提示词模板、SARIF 输出、计时/超时、报告评分）→ `benchmark/prompts/vuln_hunt.md` + `benchmark/README.md`
- [x] A3. 设计样本"区分度梯度"分级标准（L0–L5）→ 见 `benchmark/README.md` §3
- [x] A4. 定义机器可读 checkpoint 标注规范（注解 + 元数据）→ 已在 src/main + benchmark/cases 落地 38 处

### Phase B — 漏洞样本设计与落地（有区分度，落入项目）
- [x] B1. 污点传播能力样本（含"变量无断点"专项）：单跳 / 多跳 / 间接（Map/字段）梯度 → `benchmark/cases/vuln/Taint*.java`（L1–L3）
- [x] B2. 状态机 / 调用链追踪样本：跨方法 / 跨文件 / gadget chain → 跨方法已实现（TaintCrossMethod L3）；新增跨文件调用链（ChainController/A/B L4）+ gadget chain（GadgetChainDeserialization L5）
- [x] B3. 框架语义理解样本：Spring 参数绑定、SpEL、@RequestParam 驱动的 sink → `benchmark/cases/vuln/SpelFrameworkSemantics.java`（L4）
- [x] B4. 历史高危漏洞抽象样本：fastjson 反序列化、Spring4Shell SpEL、Log4j JNDI、CC 反序列化链、Struts2 OGNL → fastjson/SpEL 复用 src/main，Log4j 新增 `benchmark/cases/vuln/Log4jJndiInjection.java`（L3）；CC链复用 DeserializeController.bad04
- [x] B5. 真假混淆样本（OWASP 式 TP/FN/FP/TN）：每类 CWE 配套"看似危险但安全"样本 → `benchmark/cases/{vuln,sec}/Confusion*.java`（SQL/SpEL/CMD）
- [x] B6. 竞品质优样本留存：从 OWASP Benchmark / Juliet / CVEfixes / PrimeVul 抽取高质量 pattern 落库 → `benchmark/cases/vendor/`（SQLi混淆/命令注入跨文件/路径穿越/弱随机/XSS 共 7 文件 10 checkpoint）

### Phase C — 验收基础设施
- [x] C1. `expectedresults.csv`：全样本真/假标注 + CWE + 难度级 → 38 行，与源码双向一致
- [x] C2. checkpoint 标注注入：在现有 + 新增样本的精确行加 `// [CHECKPOINT]` → src/main 20 + benchmark/cases 18
- [x] C3. scorecard 计算脚本骨架（Java/Python）：Recall / Precision / Youden Score / 时延 / 超时率 / 报告冗余度 → `benchmark/scripts/scorecard.py`（SARIF + JSON 双输入）
- [x] C4. `MY_PLAN.md` 持续维护：本文件待办随实现更新 `[x]/[ ]`

### Phase D — 补充高区分度样本（缺口补齐，OWASP Top 10 视角）
> 当前 benchmark 偏重注入类（SQLi/CMD/SpEL/LDAP/XPath 占 35/52），L3+ 仅 15 个，且 A01 失效访问控制 / A02 加密 / A05 配置 / A07 认证 / A10 SSRF 几乎缺失。本轮补齐"有区分度"的代表类。
- [x] D1. SSRF（CWE-918）：单跳 + 内网IP白名单混淆（SAFE）→ `benchmark/cases/vuln/Ssrf*.java`（L1/L3）
- [x] D2. XXE（CWE-611）：未禁用 DTD + 安全配置混淆（SAFE）→ `benchmark/cases/vuln/Xxe*.java`（L1/L3）
- [x] D3. NoSQL 注入（CWE-943）：Spring Data Mongo 间接污点 → `benchmark/cases/vuln/NosqlInjection*.java`（L2/L3）
- [x] D4. JWT/认证失效（CWE-287/345）：alg=none/弱密钥/硬编码 + 校验存在但宽松混淆 → `benchmark/cases/vuln/JwtAuth*.java`（L2/L3）
- [x] D5. IDOR/越权（CWE-639/285）：对象归属语义 + 已做归属校验混淆 → `benchmark/cases/vuln/Idor*.java`（L3/L4）
- [x] D6. Jackson 多态反序列化（CWE-502）：`@JsonTypeInfo` 缺白名单 + 安全配置混淆 → `benchmark/cases/vuln/JacksonPolymorphic*.java`（L2/L3）
- [x] D7. 模板注入（CWE-1336）：FreeMarker/Thymeleaf 视图名拼接 → `benchmark/cases/vuln/TemplateInjection*.java`（L2/L3）
- [x] D8. 加密缺陷（CWE-327/798）：弱哈希/硬编码密钥 + 看似随机实则固定密钥混淆 → `benchmark/cases/vuln/Crypto*.java`（L1/L2）
- [x] D9. vendor 补充：SSRF/XXE/NoSQL/JWT/开放重定向-CORS 竞品风格样本 → `benchmark/cases/vendor/`（仿现有 3 种风格，带来源 URL）

### Phase E — src/main 漏洞目录批量补 checkpoint
> 现状：仅 7 个 src 漏洞目录有 checkpoint，其余 35+ 目录零标注。本轮为 OWASP Top 10 代表类补机器可读 checkpoint，扩大 SAST/LLM 可直接验收的教学样本面。
- [x] E1. 注入/表达式类补标：xpathInjection 已标；补 groovy/mvel/beanShell/ognl/scriptEngineInjection、templateInjection、jndiInjection、yamlDeserialization
- [x] E2. 访问控制/配置类补标：authBypass、authorizationBypass、brokenAccessControl、insecureDirectObjectReference、openRedirect、corsConfig、clickjacking、securityHeaderMissing、serverSideRequestForgery、xmlExternalEntity
- [x] E3. 加密/认证类补标：cryptoVuln、hardcodedCredentials、weakPassword、defaultCredentials、sensitiveDataExposure
- [x] E4. 业务逻辑/CVE 类补标：businessLogic、massassignment、raceCondition、cve202334050、cve202342809、numericAndDateInput、ratelimiting、regularExpressionDOS、hashCollision、jsonpCallback、headerInjection、RiskyOperations
- [x] E5. 同步 E1–E4 所有新增 checkpoint 到 `expectedresults.csv`，保持双向一致

### Phase F — 协作文档规范化（新样本强制 checkpoint）
- [x] F1. 新建 `CLAUDE.md`：面向 Claude Code 的贡献者规范，明确"新增漏洞样本必须带 `// [CHECKPOINT]` 标注"，引用 A4 规范与 `benchmark/expectedresults.csv` 同步要求
- [x] F2. 新建 `AGENTS.md`：面向通用 Agent 的同样规范（与现有 `agent.md` 架构说明互补，不冲突）
- [x] F3. 在 `benchmark/README.md` 补充"新增样本 checklist"（写样本 → 加 checkpoint → 追加 CSV → 跑 scorecard 自测）

### Phase G — 2026-08 补全落地（分层 · 分类 · 分级扩展 + 行业标准报告 + 门禁固化）

> 设计依据与样本目标见 `plans/00-benchmark-gap-completion.md`（原 Phase 1–8 计划，本次为 Phase 1–7 落地 + 文档固化）。本小节仅固化"已完成"的能力项，所有样本均遵循 A4 checkpoint 双源门禁（AGENTS.md / CLAUDE.md）。

- [x] **G1. scorecard 升级**：新增真实时延（avg/p50/p95/max/timeout_rate，取 `--timeout-ms`）、定位精度（exact_hit_rate / near_hit_rate，取 `--line-tolerance`）、综合指标 F1 / MCC、多对象交叉矩阵（`--results-dir` → `cross_matrix.json`）、双源校验脚本 `validate_checkpoints.py`。
- [x] **G2. L0 + L4 + L5 梯度补全**：新增 18 个 L0 基线样本（9 类 × vuln+sec 配对，CAP-01/02 校准能力下限），加厚 L4（跨文件/框架语义/状态机）与 L5（gadget chain），拉开强/弱 SAST 与不同档次 LLM 差距。
- [x] **G3. OWASP A01 / A02 / A04 / A05 覆盖**：失效访问控制（IDOR/越权/工作流绕过）、加密缺陷（弱 TLS/重用 IV/PBKDF 弱参/ECB）、不安全设计（价格篡改/批量赋值/业务逻辑绕过/配额竞态）、安全配置错误（CORS/错误泄露/安全头/调试端点/不安全 Cookie）。
- [x] **G4. OWASP A06 / A08 / A09 覆盖**：易受攻击组件（已知 CVE 版本依赖/传递依赖/过期 Spring）、软件与数据完整性（未签名 jar/信任边界反序列化/CI 脚本注入）、安全日志与监控失败（缺登录失败日志/日志缺上下文/无审计/吞安全异常）——A06/A08/A09 从零补齐。
- [x] **G5. 多后端 SQL 注入变体**：MyBatis `${}`/注解、JPA 原生查询、PostgreSQL COPY、存储过程、NamedParameterJdbcTemplate 误用、HQL、批量更新等，统一 `sql-injection-<variant>` 归类。
- [x] **G6. 高难度混淆 / 边境样本**：partial fix（看似已修未修完）、命名混淆（vendor 风格 Safe 类名实际危险）、blind SSRF / 错误泄露 / 时序侧信道、CRLF 日志注入 / Header 注入等 FP 陷阱加厚。
- [x] **G7. 报告生成器 + 运行 harness**：`benchmark/reports/generate_report.py`（消费 `cross_matrix.json` + `expectedresults.csv`，产出 `report.md` / `report.json` / 排名数据，OWASP Top 10 映射 + Youden 排名 + 逐类对比 + L0–L5 档位）；`benchmark/run_benchmark.sh <results-root> <expected-csv> <timeout-ms>` 端到端封装（公平性约束：同提示词、同样本、只换对象）。
- [x] **G8. 文档与门禁固化**：更新 `benchmark/README.md`（L0 更正、新参数/指标、双源校验 §、行业标准报告 §）、本文件 Phase G 现状统计、AGENTS.md / CLAUDE.md 门禁自测改为必跑 `validate_checkpoints.py`（退出码 0）。

#### G.x 现状统计（已核实，数字即事实）

来源：`benchmark/expectedresults.csv`（**260 行，含表头，即 259 个 checkpoint**）+ 源码 `// [CHECKPOINT]` 双向一致（`validate_checkpoints.py` 退出码 0）。

| 维度 | 现状 |
|------|------|
| **checkpoint 总数** | **259**（含表头 CSV 共 260 行） |
| **Level 分布** | L0=18（9 类 × vuln+sec 配对）＋ L1–L5 梯度加厚；L3–L5 占比较旧版（20%）显著提升（详见 CSV） |
| **Type** | vuln / safe 配对覆盖，safe 混淆样本含白名单/常量 sink/状态机前置不成立/partial fix/命名混淆等多套路 |
| **OWASP Top 10 2021 覆盖** | A01–A10 十类均有样本；其中 **A06 / A08 / A09 从零补齐**（原缺失），A01/A02/A04/A05 加厚 |
| **Category** | 由旧版 52 类扩展到约 70 类（多后端 SQL 变体 `sql-injection-<variant>`、A06/A08/A09 新类） |
| **指标能力** | scorecard 现支持 Recall/Precision/F1/MCC/Youden、真实时延(p50/p95/timeout_rate)、定位精度(exact/near hit)、多对象交叉矩阵 |
| **报告能力** | `run_benchmark.sh` 端到端产出 `cross_matrix.json` + `report.md`/`report.json`（OWASP 式 Youden 排名、逐类对比、L0–L5 档位） |

> 注：精确 Level 计数与逐类样本数请以 `expectedresults.csv` 实际内容为准；本统计只固化"已落地能力"的定性结论与总数。

---

### Phase H — VulnGym 差距补全（2026-08）

> 设计依据与缺口分析见 `plans/01-vulngym-gap-completion.md`（借鉴腾讯 VulnGym v0.1.4 的业务逻辑深度与路径证据链维度）。本小节固化"已完成"的能力项，所有样本均遵循 A4 checkpoint 双源门禁（AGENTS.md / CLAUDE.md）。

- [x] **H1（V1 业务逻辑子类）**：补齐 VulnGym 独有的业务逻辑子类——`agent-capability-bypass`(G1) / `origin-integrity`(G2) / `multi-tenant`(G3) / `trust-boundary`(G4) / `insecure-default`(G6) / `priv-esc`(G7) / `missing-authorization`(G8)，每类配 vuln+sec 配对，均带 `// [CHECKPOINT]` 且 CSV 双源一致。
- [x] **H2（V2 沙箱逃逸）**：补齐 `sandbox-escape`(G5)，复用 script/groovy 引擎基础，覆盖 L4–L5 逃逸维度，配 safe 对照。
- [x] **H3（V3 trace 标注）**：扩展 `// [CHECKPOINT]` 注解新增可选 `trace=` 字段（entry_point→critical_operation 中间节点）；`validate_checkpoints.py` 支持 trace 节点有效性告警（仅告警不阻断）；`scorecard.py` 新增 `--check-trace` 产出 `trace_recall`/`trace_precision`。跨节点样本回填 `trace=`。
- [x] **H4（V4 文档）**：在 `benchmark/README.md` 新增 §10「JSEF ↔ VulnGym 分类映射」（映射表覆盖全部 21 个 VulnGym `vuln_category_l2`，8 类补齐项标注"本项目已补齐"）；在 AGENTS.md 补充 `trace=` 字段说明；本 MY_PLAN.md 新增 Phase H；所有数字与 category 均实查自 `expectedresults.csv`（299 checkpoint）。

#### H.x 缺口分析结论

| 维度 | 结论 |
|------|------|
| **JSEF 强于 VulnGym** | L0–L5 完整区分度梯度；F1 / MCC / Precision 综合评测口径（VulnGym 仅 recall-only，行容差 ≤5，无 precision 惩罚）；gadget chain；混淆/safe 配对；SARIF 协议；多后端 SQL 变体；路径评测在保留 precision 优势下对标 trace 理念 |
| **借鉴 VulnGym 补齐** | 业务语义深度（AI/Agent 能力边界、来源完整性、多租户隔离、信任边界、不安全默认、权限提升精分、授权缺失）；路径证据链（`entry_point → critical_operation → trace` 多节点，升级为"路径正确性"评测） |
| **总样本规模** | `expectedresults.csv` 共 **299 个 checkpoint**（含表头 300 行），业务逻辑导向占比显著提升，对标 VulnGym 71.2% 业务逻辑分布取向 |

> 原则：只借鉴补齐，不替换 JSEF 优势维度（L0–L5 梯度、F1/MCC/precision、gadget chain、SARIF）。参见 `plans/01-vulngym-gap-completion.md` §1 差距分析与 §7 完成判定。

---

## 2. Phase A：SAST 能力模型（第一性原理）

> 第一性原理：SAST 的本质是"在不执行代码的前提下，从 source 到 sink 证明不可信数据可达危险操作"。其能力可分解为：识别 source、追踪数据流、保持污点不丢（无断点）、理解语义约束、识别 sink、跨过程/跨文件可达性分析、状态/配置前置条件判定。

### A1. 能力维度矩阵（验收项）

| ID | 能力（第一性原理） | 可观测指标 | 对应样本梯度 |
|----|------------------|-----------|-------------|
| CAP-01 | Source 识别 | 是否识别 HTTP 参数/请求体/Header 为不可信源 | L0 |
| CAP-02 | Sink 识别 | 是否识别 `Runtime.exec`/`eval`/`readObject`/`JndiLookup` 等危险终点 | L0–L1 |
| CAP-03 | 单跳污点传播 | source→sink 直连是否被检出 | L1 |
| CAP-04 | **多跳污点传播（变量无断点）** | 经 ≥2 中间变量/函数仍不丢污点 | L2 |
| CAP-05 | **间接污点（集合/字段/Map）** | 污点经 `Map<String,Object>`/对象字段/数组传递仍被追踪 | L3 |
| CAP-06 | **跨方法传播** | 污点经方法参数/返回值跨函数可达 | L3 |
| CAP-07 | **跨文件 / 调用链追踪** | 污点跨越编译单元（多 Controller/Service/Interceptor） | L4 |
| CAP-08 | **状态机 / 可达性分析** | 漏洞仅在配置开关/状态成立时成立（如 AutoType 开启） | L4 |
| CAP-09 | **框架语义理解** | 识别 Spring `@RequestParam` 绑定、DataBinder、SpEL 派发等隐式 source/sink | L4–L5 |
| CAP-10 | gadget chain 组合识别 | 多个单独安全的类组合形成危险可达性（CC 链） | L5 |
| CAP-11 | 误报抑制（真假混淆） | 对"看似危险但安全"样本不报（FP 控制） | L1–L5 配套 |
| CAP-12 | 定位精度 | 报告精确到 file:line（SARIF 行列命中率） | 全级 |

### A2. LLM 侧统一验收协议

- **统一提示词模板**（存放 `benchmark/prompts/vuln_hunt.md`）：固定指令，要求输出 SARIF 格式结果，含 `ruleId(CWE)`、`locations`、`message`。
- **计时与超时**：每个样本记录 `start_ts / end_ts`，超过阈值（默认 120s）记为"超时样本"。
- **报告评分（简洁度 / 完备度）**：
  - 简洁度 = 有效告警数 / 总输出 token 或行数
  - 完备度 = 命中真漏洞数 / 应报数（同 Recall），并考察是否给出修复建议
- **交叉对比表**：工具 × 模型 × 样本 → TP/FN/FP/TN / 时延 / 超时 / 报告分。

### A3. 区分度分级标准（L0–L5）

> 注：**L0 为能力基准参考（对应 CAP-01/02）**。早期本计划曾标注"CSV 中无样本标记为 L0"，该表述已过时——Phase G（G2）已落地 18 个 L0 样本（9 类 × vuln+sec 配对），详见下方 Phase G 与 `plans/00-benchmark-gap-completion.md`。

- **L0 显式（能力基准）**：`source` 直接传入 `sink`（一眼可见）。所有工具/模型都应命中（已新增 18 个 L0 配对样本）。
- **L1 单跳**：1 个中间变量。`// [VULN]` 直连。
- **L2 多跳（无断点）**：≥2 中间变量/函数，弱工具在中间断点丢失污点。
- **L3 间接/跨方法**：污点经 Map/字段/方法返回值传递；或跨方法。
- **L4 跨文件/框架语义/状态机**：污点跨编译单元，或依赖 Spring 绑定语义，或依赖配置开关。
- **L5 gadget chain**：多个安全类组合成危险可达性（CC 链级别）。

> 设计原则：逐级加大**推理距离 + 语义依赖**，使样本能区分"入门级 SAST / 强 SAST / 不同档次 LLM"。

### A4. 机器可读 checkpoint 标注规范

在样本精确行加行内注解（兼容现有 `// [VULN]` 约定并扩展）：

```java
// [CHECKPOINT id=JSEF-SPEL-007 cwe=917 level=L1 source=@RequestParam userControlledInput sink=spelParser.parseExpression expect=VULN]
Expression spelExpression = spelParser.parseExpression(userControlledInput);

// [CHECKPOINT id=JSEF-SPEL-007S cwe=917 level=L1 expect=SAFE]   // 混淆样本：白名单已拦截
```

- 字段：`id` / `cwe` / `level` / `source` / `sink` / `expect ∈ {VULN, SAFE}`。
- `expect=VULN` → 应报（计入 TP/FN）；`expect=SAFE` → 不应报（计入 TN/FP）。
- 元数据同时写入 `expectedresults.csv`（见 C1），双源一致。

---

## 3. Phase B：有区分度样本设计（落入项目）

> 落地位置：沿用 `src/main/java/com/freedom/securitysamples/vulnerability/{type}/vuln|sec/`，新增"梯度"样本目录 `benchmark/cases/`（源码级，可独立编译）。

### B1. 污点传播梯度（CAP-03/04/05）
- L1：SQL 拼接（已有 `sqlInjection/vuln`，复用）。
- L2：`source → tmpVar → builder → sink` 两跳（变量无断点专项）。
- L3 间接：污点存入 `Map<String,Object>` 后以 key 取出传入 sink（fastjson `@type` 风格）。
- L3 跨方法：source 经 `Service.process(input)` 返回后入 sink。

### B2. 状态机 / 调用链（CAP-06/07/10）
- L4 跨文件：Controller → ServiceA → ServiceB → sink（3 文件调用链）。
- L5 gadget chain：借鉴 CommonsCollections `InvokerTransformer`+`ChainedTransformer`+`LazyMap`（已有 `unsafeDeserialization/DeserializeController.bad04`，扩展为跨类可达性样本）。

### B3. 框架语义（CAP-09）
- Spring4Shell 风格：`@RequestParam` → DataBinder → `ClassLoader.defineClass`（CVE-2022-22965 抽象）。
- SpEL 经 field 名驼峰映射到达 sink（已有 `spelInjection`，扩展间接绑定样本）。

### B4. 历史高危漏洞抽象（复用 + 扩展）
- fastjson 反序列化（已有 `thirdParty/vuln/FastjsonDeserializationUnsafeController`，补充 `@type` 间接污点梯度 + checkpoint）。
- Log4j JNDI（CVE-2021-44228）：source 经日志字符串拼接 `${jndi:}` 子串匹配 → `JndiLookup`（新增 `benchmark/cases/jndi/`）。
- Struts2 OGNL（S2-045）：source 经 `ParametersInterceptor` 多层 → `Ognl.getValue()`（新增，跨文件演示）。

### B5. 真假混淆（CAP-11，OWASP 式）
- 每类 CWE 至少 1 个 `SAFE` 混淆样本：输入被白名单过滤 / sink 参数为常量 / 使用 `SimpleEvaluationContext` 等。
- 用于计算 FP（误报）与 TN。

### B6. 竞品质优样本留存
- 从 OWASP Benchmark（2,740 例，11 CWE）、Juliet（good/bad 配对）、CVEfixes / PrimeVul（真实 CVE + 高质标签）抽取 pattern，落地到 `benchmark/cases/vendor/` 作为对照集。
- 标注来源 URL 与 CWE，保证可溯源（见 A4 规范）。

---

## 4. Phase C：验收基础设施

### C1. `benchmark/expectedresults.csv`
列：`id, cwe, level, type(vuln/safe), file, line, source, sink, category`
- 全样本真/假标注来源，scorecard 唯一事实源。

### C2. checkpoint 注入
- 在 B1–B6 样本精确行加 `// [CHECKPOINT ...]`。
- 脚本校验：CSV 中每条 `id` 必须在源码中存在对应 checkpoint 注解（防漂移）。

### C3. scorecard 计算（骨架，Python）
- 输入：工具/模型产出的 SARIF（或 `id → {hit:bool, file, line, elapsed_ms}`）。
- 输出：
  - TP/FN/FP/TN → Recall / Precision / **Youden Score = TPR − FPR**（OWASP 口径，0–100）。
  - 平均耗时、超时样本数、超时率。
  - 报告简洁度（有效告警/输出量）、能力完备度（命中 CWE 覆盖数）。
- 按 CWE 与 level 分组输出"能力档位雷达图"数据。

### C4. 文档维护
- 本 `MY_PLAN.md` 随实现推进，将已完成项由 `[ ]` 改为 `[x]`。
- 新增 `benchmark/README.md` 说明运行与对比方法。

---

## 5. 验收/交叉对比用法（给用户的落地指引）

1. 启动 JSEF：`mvn clean package -DskipTests && java -jar target/*.jar`。
2. 选定被测对象：SAST 工具（CodeQL/SonarQube/Snyk）+ 大模型（在 Claude Code 中切换模型，相同提示词 `benchmark/prompts/vuln_hunt.md`）。
3. 各对象对 `benchmark/cases/` 跑一遍，产出结果（SARIF 或 id→hit 映射）+ 耗时。
4. 喂入 C3 scorecard 脚本，得到 TP/FN/FP/TN、Recall、Precision、Youden Score、平均耗时、超时率、报告评分。
5. 横向对比：工具×模型矩阵，识别差异（谁漏报多、谁误报多、谁超时、谁报告简洁）。

---

## 6. 关键参考（已调研，可信源）

- OWASP Benchmark：https://github.com/OWASP-Benchmark/BenchmarkJava — 混淆标注 + Youden Score 口径。
- Juliet (NIST SAMATE)：https://samate.nist.gov/SARD/ — good/bad 配对 + 跨文件调用链。
- LLM vs SAST 对比（Gnieciak & Szandala, 2025）：https://arxiv.org/abs/2508.04448 — SARIF 统一协议、时延/定位指标、结论"LLM 召回高但误报高且定位差"。
- PrimeVul：https://arxiv.org/abs/2403.18624 — 标签噪声警示，协商标注为标杆。
- CVEfixes：https://github.com/secureIT-project/CVEfixes — 真实 CVE + 修复对照。
- 历史漏洞能力抽象：fastjson CVE-2017-18349（间接污点）、Spring4Shell CVE-2022-22965（框架语义+状态机）、Log4j CVE-2021-44228（多跳+字符串拼接）、CC 反序列化链（gadget chain）、Struts2 S2-045（跨层调用链）。

---

## 7. 备注

- 本文档为**规划文档**，Phase B/C 的实际采样代码按 `benchmark/cases/` 组织，遵循 A4 checkpoint 规范与现有 `vuln`/`sec` 约定。
- 不修改现有教学样本语义；新增梯度样本独立放置，避免破坏教学闭环。
- 所有 Payload 仅限 `localhost` 演示（遵循 `agent.md` 安全底线）。
