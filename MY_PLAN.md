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
- [ ] B2. 状态机 / 调用链追踪样本：跨方法 / 跨文件 / gadget chain → 跨方法已实现（TaintCrossMethod L3），跨文件/CC链待扩展
- [x] B3. 框架语义理解样本：Spring 参数绑定、SpEL、@RequestParam 驱动的 sink → `benchmark/cases/vuln/SpelFrameworkSemantics.java`（L4）
- [x] B4. 历史高危漏洞抽象样本：fastjson 反序列化、Spring4Shell SpEL、Log4j JNDI、CC 反序列化链、Struts2 OGNL → fastjson/SpEL 复用 src/main，Log4j 新增 `benchmark/cases/vuln/Log4jJndiInjection.java`（L3）；CC链复用 DeserializeController.bad04
- [x] B5. 真假混淆样本（OWASP 式 TP/FN/FP/TN）：每类 CWE 配套"看似危险但安全"样本 → `benchmark/cases/{vuln,sec}/Confusion*.java`（SQL/SpEL/CMD）
- [ ] B6. 竞品质优样本留存：从 OWASP Benchmark / Juliet / CVEfixes / PrimeVul 抽取高质量 pattern 落库 → 待扩展 `benchmark/cases/vendor/`

### Phase C — 验收基础设施
- [x] C1. `expectedresults.csv`：全样本真/假标注 + CWE + 难度级 → 38 行，与源码双向一致
- [x] C2. checkpoint 标注注入：在现有 + 新增样本的精确行加 `// [CHECKPOINT]` → src/main 20 + benchmark/cases 18
- [x] C3. scorecard 计算脚本骨架（Java/Python）：Recall / Precision / Youden Score / 时延 / 超时率 / 报告冗余度 → `benchmark/scripts/scorecard.py`（SARIF + JSON 双输入）
- [x] C4. `MY_PLAN.md` 持续维护：本文件待办随实现更新 `[x]/[ ]`

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

- **L0 显式**：`source` 直接传入 `sink`（一眼可见）。所有工具/模型都应命中。
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
