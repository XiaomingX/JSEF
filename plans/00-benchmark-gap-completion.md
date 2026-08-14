# JSEF Benchmark 补全计划：分层 · 分类 · 分级扩展与行业标准报告

> 目标：在现有 133 个 checkpoint / 52 类样本基础上，补齐**有区分度的梯度样本**与**缺失的参考维度**，并把 scorecard 升级为"可横向评估 多 LLM × 多 code-agent harness × 多 SAST 工具"的行业标准报告。
> 全文遵循 `AGENTS.md` 的 checkpoint 硬门禁：`// [CHECKPOINT]` 注解 + `expectedresults.csv` 双源必须一致。
> 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。

---

## 0. 现状审计（已核实数据）

来源：`benchmark/expectedresults.csv`（133 行，含表头）+ `src/main/.../vulnerability/` 目录扫描。

### 0.1 现有分布（数字即事实）

| 维度 | 分布 | 观察 |
|------|------|------|
| **Level** | L1=89 / L2=17 / L3=16 / L4=8 / L5=3 | **67% 集中在 L1**，差异化梯度（L3–L5）仅占 20%。区分度不足。 |
| **Type** | vuln=93 / safe=40 | TP/FN 样本多，TN/FP（混淆）样本偏少 → 误报维度统计偏弱。 |
| **Category** | 52 类，前 5 占 55%（spel 21 / cmd 17 / deser 17 / sqli 7 / crypto-hardkey 7） | 长尾 33 类仅 1–2 个样本，覆盖面广但每类太薄。 |
| **CWE** | 917×21 / 78×17 / 502×17 / 89×7 / 798×7 … | 表达式注入与反序列化过载，A01/A02/A05/A07/A09/A10 稀疏。 |

### 0.2 关键缺口（MECE 维度）

1. **Level 梯度断层**：L0 基线缺失（计划称有 L0 但 CSV 无一行）；L4/L5 严重不足，拉不开强 SAST 与弱 SAST / 不同档次 LLM 的差距。
2. **OWASP Top 10 2021 覆盖缺口**：
   - A01 失效访问控制：IDOR 仅 2、authBypass 仅 3、broken-access-control 仅 1、authorizationBypass 仅 1。
   - A02 加密：弱哈希/硬编码密钥有，但**缺少 TLS/弱协议/不安全随机数重用/PBKDF 参数错误**等细分。
   - A04 不安全设计：**业务流绕过、价格篡改、权限提升逻辑**几乎未落入 benchmark（仅在 `MY_NEXT_PLAN_v1.md` 提议，未采样）。
   - A05 安全配置错误：**Spring 配置、CORS、HTTP 头、错误详情泄露**稀疏。
   - A06 易受攻击组件：**无 SCA / 依赖版本 / CVE 指纹类**样本（benchmark 全为手写源码，缺"组件级"维度）。
   - A08 软件与数据完整性：**无构建/CI、无签名校验、无不可信更新**样本。
   - A09 安全日志与监控失败：**完全缺失**（零样本）。
   - A10 SSRF：仅 3，缺云元数据（169.254.169.254）、DNS rebinding、blind SSRF。
3. **混淆/边界样本不足**：safe 样本仅 40，且多为"白名单已拦截"单一套路；缺**部分修复（partial fix）、看似危险实则安全但需推理、命名混淆（vend 风格）**等更难的 FP 陷阱。
4. **缺失的统计指标**（scorecard 当前不支持）：
   - 超时率实际为 0（elapsed 未逐条落库，`timing_and_quality` 仅占位）→ **时延/超时维度形同虚设**。
   - 无**定位精度**（file:line 命中 vs 邻近行）指标。
   - 无 **F1 / MCC（Matthews 相关系数）** 等行业标准综合指标。
   - 无**按 harness 的能力档位雷达图产出**（仅数据，无图）。
   - 无**多对象横向对比矩阵**聚合（每次只算单对象）。
5. **多语言/多后端维度缺失**：项目定位含 MySQL/PostgreSQL + Maven，但所有样本为纯 Java 片段；**MyBatis/Mapper XML、JPA 原生查询、PreparedStatement 误用、存储过程、ORM 二级注入**等 SQL 注入变体未覆盖（仅 7 个 sqli）。
6. **报告不符合行业标准**：输出为单对象 Markdown 表，无 SARIF 对照、无 **OWASP Benchmark 式 Youden 排名图**、无可机读的交叉对比 JSON。

### 0.3 行业对标（调研，可信源）

- **OWASP Benchmark**：2740 例 / 11 CWE，强混淆（TP/TN 配对），Youden Score 排名口径（0–100）。参考：混淆密度、配对结构。
- **Juliet (NIST SAMATE)**：good/bad 文件配对，强调跨文件调用链与确定性 sink。参考：跨文件结构。
- **PrimeVul**（arXiv:2403.18624）：真实 CVE + 协标签，警示标签噪声。参考：来源标注 + 修复对照。
- **CVEfixes**：真实 CVE + fix commit。参考：A06 组件类样本来源。
- **LLM vs SAST**（arXiv:2508.04448）：结论"LLM 召回高但误报高且定位差"，统一 SARIF 协议、时延/定位指标。参考：指标口径。
- **SecBench / CVEFixes / DiverseVul**：大规模 Java/CWE 覆盖。参考：CWE 覆盖广度。

---

## 1. 设计原则（MECE）

1. **分类（Category）**：按 OWASP Top 10 2021 的 10 大类 + 表达式/反序列化/注入等"技术族"双轨归类；每类内部按 CWE 细分，互不重叠。
2. **分级（Level L0–L5）**：严格按 `MY_PLAN.md` A3 推理距离 + 语义依赖定义，不跨级。
3. **分层（Layer）**：数据层（source→sink 单纯污点）/ 框架层（Spring 语义）/ 业务层（A01/A04 逻辑）/ 供应链层（A06/A08）/ 运维层（A09/A05 配置）。每层对应不同被测对象强项，拉开 harness 差异。
4. **配对（TP/TN）**：每个 vuln 必配至少 1 个 safe 混淆样本，safe 设计至少覆盖 3 种 FP 陷阱套路之一（白名单 / 常量 sink / 状态机前置不成立）。
5. **来源标注**：vendor 类样本标注来源 URL（OWASP/Juliet/PrimeVul/CVEfixes），保证可溯源。

---

## 2. 实施阶段总览

| 阶段 | 内容 | 新增样本目标 | 交付 |
|------|------|------|------|
| **Phase 1** | Level 梯度补全（L0 基线 + L4/L5 加厚） | +18 L0 + +20 L4/L5 | benchmark/cases + CSV |
| **Phase 2** | OWASP A01/A02/A04/A05 业务与配置层样本 | +30 | benchmark/cases + CSV |
| **Phase 3** | A06/A08 供应链与完整性样本 + A09 日志监控 | +15 | benchmark/cases + CSV |
| **Phase 4** | 多后端注入变体（MyBatis/JPA/PG/MySQL） | +20 | benchmark/cases + CSV |
| **Phase 5** | 高难度混淆/边境样本（partial fix / 命名混淆 / blind） | +25 | benchmark/cases + CSV |
| **Phase 6** | scorecard 升级：时延/超时/定位精度/F1/MCC/雷达图/交叉矩阵 | 改造脚本 | scorecard.py + report 模板 |
| **Phase 7** | 行业标准报告生成器 + 运行 harness 封装 | +report 脚本 | benchmark/reports/ |
| **Phase 8** | 文档与门禁：更新 README/MY_PLAN，固化 checkpoint 校验 | 文档 | *.md |

> 合计新增约 **128** 个 checkpoint（总计约 260），分类覆盖从 52 扩到 ~70，L3–L5 占比从 20% 提升到 ~40%。

---

## 3. Phase 1 — Level 梯度补全（区分度底座）

**目的**：补齐 L0 基线（所有工具必须全中，用于校准"能力下限"），并加厚 L4/L5 让强对象脱颖而出。

### 1.1 L0 基线样本（CAP-01/02，source 直传 sink，无中间变量）
落点：`benchmark/cases/vuln/L0*/` 与 `sec/`，每类 2 个（vuln+safe）：
- `L0SqlDirect`（CWE-89）、`L0CmdDirect`（CWE-78）、`L0XssDirect`（CWE-79）、`L0PathDirect`（CWE-22）、`L0XxeDirect`（CWE-611）、`L0SsrfDirect`（CWE-918）、`L0SpelDirect`（CWE-917）、`L0DeserDirect`（CWE-502）、`L0LdapDirect`（CWE-90）。
- 模板参考：`benchmark/cases/vuln/TaintSingleHop.java`（L1，单中间变量）→ L0 去掉中间变量，source 即入 sink。
- checkpoint：`// [CHECKPOINT id=JSEF-L0-xxx cwe=89 level=L0 source=@RequestParam x sink=Statement.executeQuery expect=VULN]`（**注意：当前 CSV 无 L0，需确认 scorecard 的 `level` 字段接受 L0** — 见 Phase 6 校验）。

### 1.2 L4 加厚（跨文件/框架语义/状态机）
- `ChainSqlCrossFile`（Controller→Service→Mapper，CWE-89，仿 `ChainController.java` 结构）
- `SpringBindingTaint`（@ModelAttribute 绑定到危险字段，CWE-915）
- `ConfigFlagGatedSink`（仅 `feature.enabled=true` 时危险，CWE-XXX，状态机 L4）
- `InterceptTaint`（HandlerInterceptor 注入污点跨层，CWE-917）

### 1.3 L5 加厚（gadget chain）
- `GadgetChainJdbc`（多个安全类组合触发 JDBC 任意 URL 连接，仿 `GadgetChainDeserialization.java`）
- `Spring4ShellChain`（class.module.classLoader 链抽象，CWE-917→RCE，仿 `SpelFrameworkSemantics.java`）
- `Log4jToJndiChain`（多跳字符串拼接 + JNDI lookup，CWE-917，仿 `Log4jJndiInjection.java`）

### 验证清单
- [ ] 每个样本 dir 含 vuln + sec 配对文件。
- [ ] grep 确认 L0/L4/L5 checkpoint 行号与 CSV `line` 列一致。
- [ ] 自测：`python3 benchmark/scripts/scorecard.py --expected benchmark/expectedresults.csv --result <mock_all_hit.json>` 不报孤儿 id。

---

## 4. Phase 2 — OWASP A01/A02/A04/A05 业务与配置层

**目的**：把"业务语义类"漏洞（数据流干净但授权/设计缺失）做厚，这是 LLM 相对 SAST 的优势区，最能拉开 harness 差距。

### 2.1 A01 失效访问控制（加厚 IDOR / 越权 / 工作流）
- `IdorByQueryParam`（CWE-639，L3，仿 `IdorObjectOwnership.java`）、`IdorByHeader`、`VerticalPrivEsc`（CWE-285，L4，role 字段未校验）、`WorkflowBypass`（CWE-840/285，L4，跳过支付步骤直接查订单）、`ForceBrowseAdmin`（CWE-285，L4）。
- safe 配对：`IdorSafeWithOwnerCheck`、`VerticalPrivEscSafeWithRoleCheck`、`WorkflowSafeWithStateCheck`（仿 `IdorSafe.java`）。

### 2.2 A02 加密缺陷（细分）
- `WeakTlsProtocol`（CWE-327，L2，SSLContext 启用 TLSv1.0）、`ReusedIv`（CWE-329，L3，AES-GCM 重用 IV）、`PbkdfWeakParam`（CWE-916/521，L3，迭代次数过低）、`EcbMode`（CWE-327，L2，仿 `CryptoHardcodedKey.java`）、`InsecureRandomStream`（CWE-330，L2）。
- safe：`CryptoSafeTls`、`CryptoSafeIv`、`CryptoSafePbkdf`（仿 `CryptoSafe.java`）。

### 2.3 A04 不安全设计（新增，来自 MY_NEXT_PLAN_v1 提议）
- `PriceTampering`（CWE-840/345，L3，前端价格直用）、`MassAssignPrivEsc`（CWE-915，L3，仿 `massassignment` 已有 2 个再补）、`BusinessRuleBypass`（CWE-840，L4）、`QuotaBypassRace`（CWE-362，L4，仿 `raceCondition`）。

### 2.4 A05 安全配置错误
- `CorsWildcardCreds`（CWE-942，L3，仿 `corsConfig`）、`VerboseErrorLeak`（CWE-209，L2）、`MissingSecurityHeader`（CWE-693，L2，仿 `securityHeaderMissing`）、`DebugEndpointExposed`（CWE-489，L3）、`InsecureCookie`（CWE-614，L2，HttpOnly/Secure 缺失）。

### 验证清单
- [ ] 业务层样本必须有注释说明"数据流干净但语义缺失"（仿 `IdorObjectOwnership.java` 头注释）。
- [ ] 每类 vuln 配 safe，CSV `category` 用统一 slug（如 `idor`、`crypto-tls`、`insecure-design`）。

---

## 5. Phase 3 — A06/A08 供应链与 A09 日志监控

### 3.1 A06 易受攻击组件（组件级维度，新增层）
- `VulnerableDepVersion`（CWE-1104/937，L2，pom.xml 引入已知 CVE 版本 Log4j 2.14.1 / Commons-Collections 3.2.1）→ 落点为 `benchmark/cases/vendor/ComponentCVE_*.java` + 配套 `pom.xml` 片段文件，标注 CVE 编号与来源（CVEfixes）。
- `TransitiveVulnDep`（CWE-1395，L3，传递依赖）、`OutdatedSpringVersion`（CWE-937，L2，Spring 5.2.x 已知 CVE）。
- 注：此类 sink 非传统代码 sink，checkpoint 的 `sink` 列写 `dependency:artifactId:version (CVE-xxxx)`。

### 3.2 A08 软件与数据完整性
- `UnsignedJarLoad`（CWE-494，L3，加载未签名远程 jar）、`UnsafeDeserOfTrust`（CWE-502，L4，信任边界内反序列化）、`BuildScriptInjection`（CWE-506，L4，CI 脚本拼接）。

### 3.3 A09 安全日志与监控失败（零→补齐）
- `MissingLoginFailLog`（CWE-778，L2，登录失败无日志）、`InadequateLogContent`（CWE-532，L2，日志缺 who/where）、`NoAuditTrail`（CWE-778，L3，敏感操作无审计）、`SwallowSecurityException`（CWE-390，L2，吞掉安全异常）。
- safe：`LoggingSafeWithAudit`、`LoggingSafeWithContext`（含 who/what/when/where）。

### 验证清单
- [ ] A06 样本必须附 `pom.xml` / `build.gradle` 片段并标注 CVE 来源 URL（可溯源要求）。
- [ ] A09 样本的 checkpoint `sink` 用 `log.xxx (missing context)` 描述性写法。

---

## 6. Phase 4 — 多后端注入变体（MySQL/PostgreSQL/MyBatis/JPA）

**目的**：覆盖项目定位的 MySQL/PostgreSQL + Maven 真实栈，拉开"懂 ORM/SQL 框架"对象与"只看字符串拼接"对象的差距。

- `MybatisMapperInjection`（CWE-89，L2，`${}` 拼接 vs `#{}`）、`MybatisAnnotationInjection`（CWE-89，L3，@Select 拼接）、`JpaNativeQueryInjection`（CWE-89，L3，`createNativeQuery` 拼接）、`PgCopyInjection`（CWE-89，L3，COPY FROM 拼接）、`StoredProcedureInjection`（CWE-89，L3，CallableStatement）、`JdbcNamedParamAbuse`（CWE-89，L2，NamedParameterJdbcTemplate 误用）、`HqlInjection`（CWE-89，L3，JPA QL 拼接）、`BatchUpdateInjection`（CWE-89，L2）。
- safe：`MybatisSafeHash`、`JpaSafeTypedQuery`、`PgSafeCopy`（仿 `SqlInjectionSafeController.java` 参数化写法）。
- 模板参考：`src/main/java/com/freedom/securitysamples/vulnerability/sqlInjection/vuln/SqlInjectionUnsafeController.java:59`（现有 JDBC 拼接 checkpoint）。

### 验证清单
- [ ] 每个样本顶部注释声明所需依赖（MyBatis / Spring Data JPA / PostgreSQL driver），独立 benchmark 源文件不强求编译。
- [ ] `category` 统一用 `sql-injection-<variant>` 以便分组统计。

---

## 7. Phase 5 — 高难度混淆 / 边境样本（FP 陷阱加厚）

**目的**：让误报（FP）维度有统计意义，区分"谨慎型"与"激进型"对象。

### 5.1 Partial Fix（部分修复，最难的 TN）
- `SqlPartialParam`（CWE-89，L3，仅首参数参数化其余拼接 → 实际仍 VULN，但易被判 SAFE 的混淆对照）、`CmdPartialAllowlist`（CWE-78，L3）。
- 设计：一个 vuln 样本故意"看似已修但未修完"，配套一个真正 safe 样本，考察对象是否会因"看起来有防护"而漏报。

### 5.2 命名混淆（vendor 风格，仿现有 OwaspStyle）
- `ConfusionDeserWhitelistType`（CWE-502，L3，类名含 Safe 但实际反射调用）、`ConfusionSsrfPrivateIpCheck`（CWE-918，L3，IP 校验仅判断前缀）。

### 5.3 Blind / 间接泄露
- `BlindSsrfNoResponse`（CWE-918，L3，无回显但可达）、`ErrorBasedInfoLeak`（CWE-209，L2）、`TimingSideChannel`（CWE-208，L4）。

### 5.4 上下文相关 sink
- `LogInjectionCrlf`（CWE-93，L2，日志注入 CRLF）、`HeaderInjectionFromParam`（CWE-113，L2，仿 `headerInjection`）。

### 验证清单
- [ ] 每个混淆样本在注释中明确"为什么容易被误判"，并在 CSV 的 `expect` 字段与真实语义一致（不诱导错误标注）。

---

## 8. Phase 6 — scorecard 升级（核心：让指标可横评）

**依据**：当前 `benchmark/scripts/scorecard.py` 的 `timing_and_quality`（L364-383）仅占位，`timeout_count` 实际恒为 0；无 F1/MCC/定位精度；每次只算单对象。

### 6.1 时延与超时（真实化）
- 结果 JSON 增加顶层 `meta: {object, model, harness, elapsed_ms_per_sample: {id: ms}}`。
- `align()` 时从 `findings[id].elapsed_ms` 或 `meta` 读取逐样本耗时，计算 **avg / p50 / p95 / max / timeout_rate**（阈值来自 `--timeout-ms`）。
- 输出到 `report.json` 的 `timing` 块（替换占位）。

### 6.2 定位精度（CAP-12）
- 新增 `location_accuracy`：对被测结果 `file:line` 与 expected `line` 做 ±k 行容差（默认 k=0 严格 / 可选 --line-tolerance 2）。
- 指标：`exact_hit_rate`（行精确）、`near_hit_rate`（容差内）。

### 6.3 综合指标（行业标准）
- 新增 **F1 = 2·P·R/(P+R)**、**MCC = (TP·TN−FP·FN)/√((TP+FP)(TP+FN)(TN+FP)(TN+FN))**（Matthews，正负样本不均衡时比 Youden 更稳）。
- 保留 Youden（OWASP 口径），三指标并列输出。

### 6.4 多对象交叉矩阵
- 新增 `--expected ... --results-dir <dir>` 模式：遍历 `<dir>/<object>/result.json`，逐个算分后聚合为 `cross_matrix.json`：object × metric 表 + object × CWE 热力。
- 新增雷达图数据导出（按 level 与 category 的 Youden/F1），供前端或 matplotlib 渲染。

### 6.5 校验加固
- 新增 `validate.py`（或 scorecard `--check`）：扫描所有 `// [CHECKPOINT]` 注解，提取 id，与 CSV 双向比对，报错孤儿/重复/行号漂移。**此步纳入 AGENTS.md 门禁自测**（替换现有占位式自测）。

### 验证清单
- [ ] 用 `example_result.json` 跑通，确认 timeout/elapsed 不再恒 0。
- [ ] 构造一个"行号偏差 2"的结果，确认 `near_hit_rate` 与 `exact_hit_rate` 区分。
- [ ] 跑 `--results-dir` 多对象，产出 `cross_matrix.json`。

---

## 9. Phase 7 — 行业标准报告生成器

**目的**：产出可横向对比、符合行业阅读习惯的报告。

### 7.1 报告模板 `benchmark/reports/generate_report.py`
- 输入：`cross_matrix.json`（Phase 6 产出）。
- 产出：
  1. `report.md`：总表（object | Recall | Precision | F1 | MCC | Youden | 超时率 | 定位精度 | 完备度）+ 按 OWASP Top 10 分章的逐类对比 + 按 Level 的能力档位表。
  2. `report.json`：机器可读，供 CI / 仪表盘。
  3. **OWASP Benchmark 式 Youden 排名图**数据（对象按 Youden 降序）+ 可选 matplotlib PNG（若环境有 matplotlib；无则只出数据）。
- 对标：OWASP Benchmark 的 scorecard 排名图、Juliet 的 good/bad 配对呈现。

### 7.2 运行 harness 封装 `benchmark/run_benchmark.sh`
- 封装：对 `benchmark/cases/` + 指定 `src/main` 目录，依次调用被测对象（SAST CLI / LLM 提示词），收集 SARIF/JSON + 耗时，落 `results/<object>/`，再调 scorecard + generate_report。
- 明文化公平性约束（同提示词、同样本、只换对象）。

### 验证清单
- [ ] 跑通端到端：mock 两个对象（一个高召回低精度、一个高精度低召回）→ 报告能体现差异与排名。

---

## 10. Phase 8 — 文档与门禁固化

- 更新 `benchmark/README.md`：补充 L0 说明、新增层/类、运行 harness 用法、报告解读。
- 更新 `MY_PLAN.md`：把本计划 Phase 1–8 落地项标记 `[x]`，保留缺口追踪。
- 更新 `AGENTS.md` / `CLAUDE.md`：门禁自测改为必跑 `validate.py`（双源一致性）。
- 新增 `benchmark/README_EN.md`（已有 README-en.md，补充本层报告章节）。

---

## 11. 关键参考（已调研）

- OWASP Benchmark：https://github.com/OWASP-Benchmark/BenchmarkJava — 混淆密度 + Youden 排名口径。
- Juliet (NIST SAMATE)：https://samate.nist.gov/SARD/ — good/bad 配对 + 跨文件调用链。
- PrimeVul：https://arxiv.org/abs/2403.18624 — 真实 CVE + 协标签，标签噪声警示。
- CVEfixes：https://github.com/secureIT-project/CVEfixes — A06 组件类来源。
- LLM vs SAST：https://arxiv.org/abs/2508.04448 — SARIF 统一协议、时延/定位指标（"LLM 召回高误报高定位差"）。
- DiverseVul / SecBench：大规模 Java/CWE 覆盖广度参考。

---

## 12. 验收标准（任务完成定义）

1. 新增约 128 个 checkpoint，全部带 `// [CHECKPOINT]` 且 CSV 双源一致（`validate.py` 零报错）。
2. L0 基线 9 类 ×2 落地；L3–L5 占比从 20% 提升至 ~40%。
3. OWASP Top 10 十类均有 ≥3 个 vuln + 配对 safe；A09/A06/A08 从零补齐。
4. scorecard 真实计算时延/超时/定位精度/F1/MCC，支持多对象交叉矩阵。
5. `generate_report.py` 产出行业标准报告（md + json + 排名数据），`run_benchmark.sh` 端到端可跑。
6. 未触发安全底线（仅 localhost 演示语义）。

> 所有样本遵循现有 `vuln`/`sec` 包约定与 `// [CHECKPOINT]` + CSV 双源门禁（AGENTS.md）。
