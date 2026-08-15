# JSEF Benchmark

> 用途：在 JSEF 现有 35+ 漏洞教学案例基础上，建立一套**验收 SAST 基础能力**与**对比多个大模型漏洞挖掘能力差异**的 benchmark。
> 验收维度：误报（FP）、漏报（FN）、平均耗时、超时样本、报告简洁度、能力完备程度（CWE 覆盖）。
> 设计依据见仓库根目录 `MY_PLAN.md`（Phase A2 统一提示词协议 / A3 区分度分级 L0–L5 / Phase C 验收基础设施）。

---

## 1. 为什么要做这个 Benchmark

SAST 的本质是"在不执行代码的前提下，从 source 到 sink 证明不可信数据可达危险操作"。JSEF 原有案例以教学对比为目的，区分度梯度不足、且缺乏机器可读标注，无法自动算 TP/FP/FN/TN。

本 benchmark 解决三件事：

1. **统一协议**：所有被测对象（SAST 工具 + 大模型）用同一提示词、对同批样本产出机器可读结果。
2. **区分度梯度**：样本按 L0–L5 分级，能拉开"入门级 SAST / 强 SAST / 不同档次 LLM"的差距。
3. **交叉对比**：用 scorecard 脚本产出工具 × 模型 × 样本的 Recall / Precision / Youden Score / 时延，识别谁漏报多、谁误报多、谁超时、谁报告简洁。

---

## 2. 目录结构

```
benchmark/
├── README.md                 # 本文件：运行与对比说明
├── prompts/
│   └── vuln_hunt.md          # 统一提示词模板（强制 SARIF 输出）
├── cases/                    # 样本库（源码级，可独立编译）
│   ├── vuln/                 # 不安全样本（按 CWE 分目录）
│   ├── sec/                  # 安全对照样本
│   └── vendor/               # 竞品对照集（OWASP Benchmark / Juliet 等抽象）
├── scripts/                  # scorecard 计算脚本（见 §5）
├── expectedresults.csv       # 全样本真/假标注（唯一事实源，Phase C1）
└── results/                  # 各被测对象产出（SARIF/JSON + 耗时），按对象分目录
    ├── codeql/
    ├── sonarqube/
    └── claude-<model>/
```

> 注：`expectedresults.csv` 已落地并持续维护，**当前共 426 个 checkpoint（含表头 427 行）**，覆盖 L0–L5 全梯度与 OWASP Top 10 2021 十类；`results/` 由各被测对象首次运行后填充。

---

## 3. 样本与区分度分级

样本按推理距离 + 语义依赖分为 L0–L5（详见 `MY_PLAN.md` A3）。其中 **L0 为能力基准（CAP-01/02），现已新增 18 个 L0 样本（9 类 × vuln+sec 配对），所有工具/模型都应命中**；余下样本覆盖 L1–L5，形成完整梯度：

- **L0 显式（能力基准）**：source 直接传入 sink，无中间变量，所有工具/模型都应命中（共 18 个 L0 vuln+sec 配对）。
- **L1 单跳**：1 个中间变量。
- **L2 多跳（无断点）**：≥2 中间变量/函数，弱工具在断点丢污点。
- **L3 间接/跨方法**：污点经 Map/字段/方法返回值，或跨方法。
- **L4 跨文件/框架语义/状态机**：跨编译单元、Spring 绑定语义、配置开关。
- **L5 gadget chain**：多个安全类组合成危险可达性（CC 链级别）。

#### 长程任务样本（LT 系列，验收多步规划与一致性）

为验收**大模型在漏洞挖掘中的长程任务能力（多步 tool 调用、规划、一致性）**，新增 `benchmark/cases/{vuln,sec}/longtask/` 样本族（id 前缀 `JSEF-LT-`）。这些样本刻意设计为**需跨文件/跨方法/跨状态机推理**才能定位 sink，每个文件头含「长程任务子目标清单（step-by-step）」与「预期可达性证明中间产物」(gadget 链节点序列)，驱动被测对象做规划而非单点判断。

按推理行为类型做 MECE 切分：

| 维度 | 验收的复杂能力 | 代表链 | 级别 |
|------|----------------|--------|------|
| A. 跨文件全局追踪 | 跨编译单元污点传播（源在 A 文件、sink 在 C 文件） | fastjson AutoType 跨类触发 | L4 |
| B. 框架状态机/绑定语义 | 理解 Spring 绑定/配置开关才危险的链路 | Spring4Shell `class.module` 路径 + 开关 | L5 |
| C. gadget chain 可达性还原 | 多个无害类组合成危险可达性 + 还原链 | CommonsCollections / Shiro 反序列化链 | L5 |
| D. 多跳字符串拼接 | 跨片段拼接后才危险 | Log4j `${jndi:}` 拼装 | L5 |
| E. 版本/配置依赖可达性 | 需结合依赖版本或开关判断 | fastjson 1.2.24 vs 1.2.47 黑名单 | L4 |
| F. 成对扰动一致性 | 结构扰动后结论一致 | 上述每类配 `*-Perturbed` 镜像对 | — |

**一致性验收（MECE 维度 F）**：为 A/C 两组构造语义等价但变量名/包名扰动的镜像对（`JSEF-LT-001P`/`003P` 等），要求被测对象对「原始 vs 扰动」给出一致结论（同 VULN 或同 SAFE）；同时复用既有 vuln+sec 配对间接验证不漂移。一致性在结果层统计（同一语义对结论一致率），不改动 scorecard 协议。

> 注：`expectresults.csv` 第 10 列 `trace` 已为所有 L4/L5 长程样本写入路径节点，可用 `scorecard.py --check-trace` 量化路径正确性（`trace_recall`/`trace_precision`）。

#### 代码质量 / 性能 DoS 类（高危/严重质量样本）

为验收**高危/严重的代码质量问题（可致 DoS 的性能缺陷）**，新增 `benchmark/cases/{vuln,sec}/perf/` 与若干质量类目录（id 前缀 `JSEF-PERF-*`）。这些样本区分"安全漏洞"与"质量/性能缺陷"——后者虽非传统注入类，但可导致服务不可用（DoS），是 SAST/LLM 质量评测的重要维度。

| 类 | CWE | sink 签名 | level | category |
|----|-----|-----------|-------|----------|
| 慢 SQL（无 LIMIT/无分页全表查询） | 89 / 400 | `jdbcTemplate.queryForList(sql)` 拼接无 LIMIT | L1/L2/L3 | `slow-sql` |
| DB 资源泄漏（Connection/Statement/ResultSet 未关） | 772 / 404 | `conn.createStatement()` 未 try-with-resources | L2 | `resource-leak` |
| 流资源泄漏（InputStream/OutputStream 未关） | 772 / 404 | `new FileInputStream(path)` 未关 | L1 | `resource-leak` |
| 持锁 sleep（吞吐骤降） | 410 / 400 | `synchronized{... Thread.sleep()}` | L2 | `perf-anti-pattern` |
| 循环内大对象分配（内存压力） | 400 | `for(...){ new byte[N] }` | L2 | `perf-anti-pattern` |
| ReDoS 注入版（外部输入直接 compile） | 1333 | `Pattern.compile(userInput)` | L2 | `redos` |

> 设计原则：宁缺毋滥——仅补有真实 sink 签名、可机器标注、有区分度的样本；慢 SQL 做 L1/L2/L3 梯度展开，其余做 vuln+sec 配对。

#### LGTM / CodeQL 安全缺口补充

对照 LGTM/CodeQL Java 规则库（Security + CodeQuality 套件），补齐本项目原缺失的漏洞类型与 sink 点（id 前缀 `JSEF-TB-*` / `JSEF-REFLECT-*` / `JSEF-FMT-*` / `JSEF-HOST-*` / `JSEF-XSLT-*` / `JSEF-FWD-*` / `JSEF-SEED-*`）：

| 类 | CWE | sink 签名 | level | category |
|----|-----|-----------|-------|----------|
| 信任边界违反 | 501 | `HttpSession.setAttribute(name, tainted)` | L3 | `trust-boundary` |
| 反射注入 | 470 | `Class.forName(userClass)` / `Method.invoke` | L4 | `reflection-injection` |
| 格式串注入 | 134 | `String.format(userFmt, ...)` | L3 | `format-string` |
| hostname 校验绕过 | 295 | `HostnameVerifier.verify()` 恒 true | L2 | `hostname-verifier` |
| XSLT 注入 | 91 | `TransformerFactory.newTransformer(Source)` | L3 | `xslt-injection` |
| forward 未校验 | 98 | `RequestDispatcher.forward(req,resp)` 不可信路径 | L2 | `unvalidated-forward` |
| 可预测种子 | 338 | `new SecureRandom(fixedSeed)` | L2 | `predictable-seed` |

> 已覆盖、未重复的类型：open-redirect(CWE-601)、http-response-splitting(CWE-113) 由既有 `open-redirect`/`header-injection`/`crlf-injection` 覆盖；TLS 证书信任绕过由既有 `tls-verification-bypass` 覆盖（本次仅补 hostname 维度）。

#### 逻辑漏洞样本（支付/会员/业务流程绕过）

为验收**典型逻辑漏洞**（权限漏洞、支付逻辑、会员逻辑、业务流程状态机绕过），新增 `benchmark/cases/{vuln,sec}/logic/` 样本族（id 前缀 `JSEF-PAY-*` / `JSEF-MEM-*` / `JSEF-WF-*`）。这类漏洞的核心是**客户端可篡改关键业务参数**或**服务端缺失状态/步骤校验**，区别于注入类——考验被测对象理解业务语义与状态机的能力。

| 类 | CWE | 典型缺陷 | level | category |
|----|-----|----------|-------|----------|
| 支付价格/数量篡改 | 840 / 20 | 订单 `amount`/`quantity` 取 `@RequestParam` 服务端未重算 → 负值/改数量绕过总额 | L3 | `payment-logic` |
| 优惠券/邀请码复用 | 840 | 同一 `couponCode` 可重复核销（无一次性去重） | L3 | `payment-logic` |
| 会员等级篡改 | 285 / 639 | `@RequestParam membershipLevel` 直接授权益，未校验真实等级 | L3 | `membership-logic` |
| 邀请奖励刷取 | 840 | 邀请码可自邀/无限刷奖励（缺防自邀/频率限制） | L3 | `membership-logic` |
| 重复退款（状态机绕过） | 840 | 已退款订单可再次退款（未校验订单状态机） | L4 | `workflow-bypass` |
| 关键步骤跳过 | 862 | 未校验支付状态直接发货/激活（缺步骤顺序校验） | L4 | `workflow-bypass` |

> 设计原则：宁缺毋滥——只补有真实业务语义、可机器标注、高区分度的逻辑漏洞；每类做 vuln+sec 配对，L3/L4 带 `trace=` 路径节点。

#### 原子范式样本族（TCM / SBM / DBG / STR，去库化原理还原）

为验收**被测对象对"同类原理"漏洞的泛化检测能力**（而非仅识别某具体库的已知 CVE），新增 `benchmark/cases/{vuln,sec}/{tcm,sbm,dbg,str}/` 样本族。这些样本从近年高危框架（Fastjson / Spring Boot / Dubbo / Struts2）的真实 0day/1day 中抽象出**与具体库无关**的底层危险组合，用纯 Java 标准库语义自包含复现，**不出现原框架类名**，且刻意避开仓库已有的 `JSEF-OGNL-*` / `JSEF-SPEL-*` / `JSEF-DESER-*` 等单层场景，只覆盖各框架**独有且未被建模**的原子维度。

| 命名空间 | 抽象自 | 原子范式维度（MECE） | 样本数 |
|---------|--------|---------------------|--------|
| `JSEF-TCM-` | Fastjson 反序列化 | TCM-1 直接类型选择 · TCM-2 继承绕过白名单 · TCM-3 缓存/二次解析绕过 · TCM-4 私有字段可控 · TCM-5 属性即代码 | 20 |
| `JSEF-SBM-` | Spring Boot | SBM-1 属性绑定穿越 · SBM-2 声明式配置被求值 · SBM-3 高权限端点暴露 · SBM-4 授权短路绕过 | 16 |
| `JSEF-DBG-` | Dubbo RPC | DBG-1 解析器/格式协商切换 · DBG-2 跨信任域隐式信任 · DBG-3 类名黑名单编码变形绕过 | 16 |
| `JSEF-STR-` | Struts2/OGNL | STR-1 双层求值 · STR-2 协议层字段注入 · STR-3 表达式排除列表/沙箱绕过 | 12 |

- 抽象原则：剥离"JSON 库 autotype""Web 框架 SpEL"等具体机制，只保留跨框架不变危险组合——攻击者控制类型/数据 + 系统自动调用隐式方法 + 隐式方法链抵达危险 sink。
- 高区分度：含 L4 跨文件、L5 gadget chain、跨方法链等难例；全部带 `// [CHECKPOINT]`，vuln+sec 配对算 FP/TN。
- 设计文档：`plans/02-type-confusion-mechanism-samples.md` / `03-spring-boot-atomic-mechanism-samples.md` / `04-dubbo-atomic-mechanism-samples.md` / `05-struts2-atomic-mechanism-samples.md`。

> 历史说明：早期 `MY_PLAN.md` A3 与本文档旧版曾标注"当前 `expectedresults.csv` 中无样本标记为 L0"，该表述已于 Phase 1（L0 基线补全）落地后**更正**——详见 `MY_PLAN.md` Phase G 与 `plans/00-benchmark-gap-completion.md`。

每条样本在源码精确行标注 `// [CHECKPOINT id=... cwe=... level=... expect=VULN|SAFE]`，元数据同步写入 `expectedresults.csv`。

#### 可选 `trace=` 字段（路径证据链）

借鉴 VulnGym 的 `entry_point → critical_operation → trace` 多节点理念，checkpoint 注解支持可选 `trace=` 字段，记录从入口（entry_point）到危险操作（critical_operation）之间的**中间推理节点**：

```
// [CHECKPOINT id=JSEF-XXX cwe=NNN level=L4 source=... sink=... expect=VULN trace=FileA.java:lineB,FileC.java:lineD]
```

- **格式**：逗号分隔的 `file:line` 节点列表，如 `trace=OrderController.java:42,TenantService.java:18`。节点为相对仓库根的路径。
- **作用**：支持"路径正确性"评测——被测结果（SARIF 多 location 或结果 JSON 携带 `trace` 列表）声明的路径节点可与期望节点比对，产出 `trace_recall`（命中期望节点比例）与 `trace_precision`（命中节点中有效比例）。详见 §5 `--check-trace` 与 `benchmark/scripts/scorecard.py` 的 `compute_trace_metrics`。
- **适用场景**：**仅 L3+ 且涉及跨节点（跨方法/跨文件/业务链）的样本**使用；单点直连样本（L0–L2 单跳）不加 `trace=`，保持单点命中评测语义。
- `trace=` 与 CSV 第 10 列 `trace` 对应：`expectedresults.csv` 表头已含 `trace` 列，节点用逗号分隔写入。

---

## 4. 如何运行被测对象

### 4.1 被测对象

- **SAST 工具**：CodeQL / SonarQube / Snyk 等，将其规则产出**人工转换为 SARIF**（或直接输出 SARIF），落到 `benchmark/results/<tool>/`。
- **大模型**：在 Claude Code 中切换模型（如 `claude-opus-4`、`claude-sonnet-4` 等），对同批样本使用**完全相同**的提示词 `benchmark/prompts/vuln_hunt.md`，产物落到 `benchmark/results/claude-<model>/`。

### 4.2 运行步骤

1. 启动 JSEF（如需带运行时上下文）：
   ```bash
   mvn clean package -DskipTests && java -jar target/*.jar
   ```
2. 选定被测对象，对 `benchmark/cases/`（及必要的 `src/.../vulnerability/`）跑一遍漏洞挖掘。
3. **强制**使用 `benchmark/prompts/vuln_hunt.md` 提示词，输出 SARIF（或退化为 `id → {hit, file, line, message}` JSON 列表）。
4. 记录每个样本 `start_ts` / `end_ts`，超 120s 记为超时样本。
5. 将产物写入 `benchmark/results/<object>/<case>.sarif`（或 `.json`）。

> 关键：大模型对比时，**只切换模型、不改提示词、不换样本**，否则结果不可比。

---

## 5. 如何产出结果 + 跑 Scorecard

1. 确保 `benchmark/expectedresults.csv` 已存在（每条样本 `id, cwe, level, type(vuln/safe), file, line, source, sink, category`）。
2. 运行 `benchmark/scripts/` 下的 scorecard 脚本（Python），输入为某对象的 SARIF/JSON 结果：
   ```bash
   python benchmark/scripts/scorecard.py \
     --expected benchmark/expectedresults.csv \
     --results  benchmark/results/claude-<model>/ \
     --out      benchmark/results/claude-<model>/scorecard.json
   ```
3. 脚本输出：
   - TP / FN / FP / TN → **Recall / Precision / Youden Score = TPR − FPR**（OWASP 口径，0–100）。
   - 综合指标 **F1 = 2·P·R/(P+R)** 与 **MCC（Matthews 相关系数）**：正负样本不均衡时 MCC 比 Youden 更稳健，三指标并列输出。
   - **真实时延**：逐样本 `elapsed_ms` 汇总为 `avg / p50 / p95 / max` 与 **超时率 `timeout_rate`**（阈值取 `--timeout-ms`，默认 120000ms）。
   - **定位精度**：`exact_hit_rate`（file:line 精确命中率）与 `near_hit_rate`（容差内命中率），容差由 `--line-tolerance` 控制（默认 0 严格；设为 2 表示 ±2 行内算 near hit）。
   - 报告简洁度（有效告警 / 输出量）、能力完备度（命中 CWE 覆盖数）。
   - 按 CWE 与 level 分组的"能力档位"数据，用于雷达图。

### 5.1 scorecard 关键参数

| 参数 | 说明 |
|------|------|
| `--expected <csv>` | 事实源 `expectedresults.csv`（必填）。 |
| `--result <file/dir>` | 单对象结果（SARIF 或 `id→{hit,file,line,...}` JSON）。 |
| `--results-dir <dir>` | 多对象根目录，遍历 `<dir>/<object>/result.json`（或首个 `*.sarif`），产出**交叉矩阵 `cross_matrix.json`**（object × metric + object × CWE 热力），供 `generate_report.py` 消费。 |
| `--line-tolerance <k>` | 定位精度容差（行）。`exact_hit_rate` 要求行精确，`near_hit_rate` 放宽到 ±k 行。默认 0。 |
| `--timeout-ms <ms>` | 单次样本超时阈值，用于超时统计（默认 120000）。 |
| `--name <object>` | 被测对象名（单对象模式写 `scorecard.json` 时用）。 |
| `--out <path>` | 输出 JSON 路径。 |
| `--check-trace` | 可选。开启路径证据链评测：对 CSV 中带 `trace` 列的样本（即支持 trace 的 expected 样本），将 expected 节点与本对象结果声明的 `trace` 节点比对，额外产出 `trace_recall` / `trace_precision` / `trace_expected_nodes` / `trace_reported_nodes` / `trace_support_count`。仅对支持 trace 的样本统计，不影响主 Recall/Precision/F1/MCC。 |

> scorecard 已升级为行业标准口径（时延/定位/F1/MCC/交叉矩阵），对应 `MY_PLAN.md` Phase G（G1）与 `plans/00-benchmark-gap-completion.md` Phase 6。

### 5.2 双源校验（门禁自测）

新增/修改任何样本前与收尾前，**必须**运行双源校验脚本，确认 CSV 与源码 `// [CHECKPOINT]` 注解双向一致：

```bash
python3 benchmark/scripts/validate_checkpoints.py \
  --expected benchmark/expectedresults.csv \
  --cases-dir benchmark/cases \
  --src-dir src/main/java/com/freedom/securitysamples/vulnerability
```

校验项与退出码：

| 校验项 | 含义 | 触发后果 |
|--------|------|----------|
| 孤儿 CSV 行 | CSV 有 id 但源码无 `// [CHECKPOINT]` 注解 | 退出码 1 |
| 孤儿源码注解 | 源码有注解但 CSV 无对应行 | 退出码 1 |
| 重复 id | CSV 内或源码内同一 id 出现多次 | 退出码 1 |
| 行号漂移 | CSV `line` 列 ≠ 注解实际行号（`grep -n`） | 退出码 1 |
| CSV `line` 列无效 | `line` 无法解析为整数 | 退出码 1 |

- **退出码 0 = 通过**（无孤儿/重复/漂移）；**退出码 1 = 存在问题**；找不到 CSV 或表头缺列返回 2。
- 该脚本为纯标准库实现（无第三方依赖），不依赖项目 Maven 构建。
- 此校验是 AGENTS.md / CLAUDE.md 门禁的硬性自测项，未通过则样本任务视为未完成。

**trace 节点有效性告警（仅告警，不阻断）**：脚本会解析 `// [CHECKPOINT]` 注解中的 `trace=` 字段（及 CSV `trace` 列），对每个 `file:line` 节点做三项检查——格式合法性（应为 `相对路径:行号`）、文件存在性、行号越界。命中问题时打印告警（如 `id=JSEF-XXX trace node Foo.java:99 NOT FOUND`），计入无效计数并展示，但**不置退出码为 1**，不影响门禁通过。即：trace 节点有问题只提示、不阻断，与孤儿/重复/漂移等硬门禁项区分。

> 详见脚本头部 docstring：`benchmark/scripts/validate_checkpoints.py`。

---

## 6. 交叉对比

对每个被测对象各产出一份 scorecard，横向比对：

| 维度 | 关注点 |
|------|--------|
| Recall | 谁漏报多（FN 高，尤其 L3–L5） |
| Precision | 谁误报多（FP 高，Safe 混淆样本） |
| Youden Score | 综合档位（0–100，越高越好） |
| 时延 / 超时率 | 谁慢、谁超时 |
| 报告简洁度 | 谁啰嗦、谁精准到 file:line |
| CWE 覆盖 | 谁能力完备度高 |

由此识别"入门级 SAST / 强 SAST / 不同档次 LLM"的差异，定位各对象的能力断点。

---

## 7. 安全底线

所有样本 Payload 仅限 `localhost` 演示（遵循仓库 `agent.md` 安全底线）。本 benchmark 只做**静态**分析与对比，不执行任何攻击代码。

---

## 8. 行业标准报告（端到端 harness）

`benchmark/run_benchmark.sh` 封装端到端流程，依次调用 scorecard 与报告生成器，产出可横向对比、符合行业阅读习惯的报告：

```bash
./benchmark/run_benchmark.sh <results-root> <expected-csv> <timeout-ms>
# 例：
./benchmark/run_benchmark.sh benchmark/results benchmark/expectedresults.csv 120000
```

**参数**
- `results-root`：结果根目录；其下每个子目录是一个被测对象（含 `result.json` 或 `*.sarif`）。
- `expected-csv`：事实源 `expectedresults.csv` 路径。
- `timeout-ms`：单次样本超时阈值（ms，默认 120000），用于超时统计。

**端到端产出**（`results-root/` 下）
| 产出 | 说明 |
|------|------|
| `cross_matrix.json` | 多对象交叉矩阵：object × metric + object × CWE 热力（由 scorecard `--results-dir` 聚合）。 |
| `report.md` | 人类可读总表 + 逐 OWASP 类章节 + L0–L5 档位表 + OWASP Benchmark 式 Youden 排名。 |
| `report.json` | 机器可读报告（总表 / 排名 / 逐 OWASP 类 / 逐 Level 聚合），供 CI 或仪表盘消费。 |
| `radar_data.json` / `ranking.png`（可选） | 若环境有 `matplotlib` 则画 Youden 排名图，否则仅出 `radar_data.json` 原始数据。 |

**报告内容结构**
1. **总表**：按 Youden 降序，列含 Recall / Precision / F1 / MCC / Youden / 超时率 / 定位精度(exact_hit_rate) / 能力完备度。
2. **逐 OWASP Top 10 类章节**：每类（A01–A10 + Other）含样本类别、各对象 Recall/Precision/F1/Youden/混淆矩阵。
3. **按 Level 能力档位表（L0–L5）**：每档位各对象的 Youden / F1 / Recall / Precision。
4. **OWASP Benchmark 式 Youden 排名**：对象按 Youden（0–100）降序并给档位评价（优秀/良好/中等/偏弱/弱）。

**OWASP Top 10 映射口径**
报告按 `expectedresults.csv` 的 `category` 列映射到 OWASP Top 10 2021（映射表硬编码于 `benchmark/reports/generate_report.py` 的 `OWASP_MAP`）：
- A01 Broken Access Control：`idor*` / `broken-access-control` / `authorization-bypass` / `auth-bypass` / `business-logic`(部分) 等。
- A02 Cryptographic Failures：`crypto*` / `weak-*` / `hardcoded-*` / `reused-iv` / `default-credentials` 等。
- A03 Injection：`sql-*` / `command-*` / `xss-*` / `spel-*` / `*-injection` / `xxe` / `xpath-*` / `ldap-*` / `nosql-*` / `template-*` / `header-injection` / `log-injection` / `jsonp-*` / `jwt-*` 等。
- A04 Insecure Design：`business-logic` / `mass-assignment` / `race-condition` / `workflow*` 等。
- A05 Security Misconfiguration：`cors*` / `security-header*` / `missing-*` / `debug-*` / `error-info-leak` / `insecure-cookie` / `config-gated-sink` / `clickjacking` 等。
- A06 Vulnerable & Outdated Components：`vulnerable-components`。
- A07 Identification & Authentication Failures：`weak-password` / `sensitive-data-*` / `jwt-auth-bypass`(部分) / `auth-bypass`(部分) 等。
- A08 Software & Data Integrity Failures：`insecure-integrity`。
- A09 Security Logging & Monitoring Failures：`security-logging`。
- A10 Server-Side Request Forgery：`ssrf`。
- 未在表中命中的未知 category → `Other`（另有前缀模糊匹配兜底）。

> 报告生成器与 harness 对应 `MY_PLAN.md` Phase G（G7）与 `plans/00-benchmark-gap-completion.md` Phase 7。
> **公平性约束**（harness 已明文化）：同提示词、同样本、只换被测对象（SAST 工具 / 不同 LLM），不改提示词、不换样本、不改超时阈值，否则结果不可比。

---

## 9. 新增样本 Checklist（贡献者必读）

新增或修改任何漏洞样本（无论 `src/main/.../vuln` 还是 `benchmark/cases/`）必须完成以下步骤，缺一不可：

1. **写样本**：漏洞代码放 `vuln/`（或 `src/main` 对应目录），配套安全对照放 `sec/`。语义正确、可读，仅 localhost 演示语义。
2. **加 checkpoint**：在漏洞精确行上方加机器可读注解：
   ```java
   // [CHECKPOINT id=JSEF-<类别>-<序号> cwe=<CWE编号> level=<L1-L5> source=<不可信源> sink=<危险终点> expect=VULN]
   ```
   安全对照（混淆样本）加 `expect=SAFE`（用于算 TN/FP）。
3. **同步 CSV**：把该 checkpoint 追加到 `benchmark/expectedresults.csv`（表头 `id,cwe,level,type,file,line,source,sink,category`），`type` 为 `vuln`/`safe`，`line` 为注解实际行号。
4. **自测一致性**：确认 CSV 与源码两源 id 完全一致（无孤儿行、无重复 id）：
   ```bash
   python3 benchmark/scripts/scorecard.py --expected benchmark/expectedresults.csv --result <你的结果> --name self-check
   ```
5. **提交**：遵循仓库 `CLAUDE.md` / `AGENTS.md` 的 checkpoint 门禁要求。

> id 全局唯一：`benchmark/cases` 与 `src/main` 下的同类样本可用不同序号（如 cases 用 `001`、src 用 `002`），但每个 `id` 必须在 CSV 与源码中同时存在且一一对应。

---

## 10. JSEF ↔ VulnGym 分类映射

> 背景：腾讯 **VulnGym**（v0.1.4）采用自订两级 taxonomy（`vuln_category_l1` / `vuln_category_l2`），**不用 CWE 编号**；JSEF 采用 CWE 编号 + `category` slug。为横向对标，下表将 VulnGym 的 `vuln_category_l2`（业务逻辑 12+1 子类 + 传统类）映射到 JSEF 实际 `category`（经 `awk/Python` 实查 `expectedresults.csv` 第 9 列，均为真实存在 slug，未编造）。映射覆盖 V1–V4 补齐的全部业务语义子类与沙箱逃逸维度（详见 `plans/01-vulngym-gap-completion.md`）。

| VulnGym `vuln_category_l2` | JSEF `category` slug | CWE | 状态 |
|----------------------------|----------------------|-----|------|
| BL-AGENT-CAPABILITY（AI/Agent 能力边界绕过） | `agent-capability-bypass` | 285 / 862 | 本项目已补齐（V1/G1） |
| BL-ORIGIN-INTEGRITY（来源/签名/完整性校验缺失） | `origin-integrity` | 345 / 347 | 本项目已补齐（V1/G2） |
| BL-MULTI-TENANT（多租户隔离失效） | `multi-tenant` | 639 / 285 | 本项目已补齐（V1/G3） |
| BL-TRUST-BOUNDARY（隐式信任内部输入） | `trust-boundary` | 502 / 94 | 本项目已补齐（V1/G4） |
| BL-INSECURE-DEFAULT（不安全默认配置） | `insecure-default` | 1188 / 16 | 已有覆盖（含 `config-gated-sink` 等） |
| BL-PRIV-ESC（权限提升） | `priv-esc` | 269 / 285 | 本项目已补齐（V1/G7，垂直越权精分） |
| BL-AUTHZ-MISSING（授权缺失/新端点漏鉴权） | `missing-authorization` | 862 | 本项目已补齐（V1/G8） |
| BL-AUTHZ-BROKEN（授权逻辑错误） | `authorization-bypass` / `broken-access-control` | 285 / 639 | 已有覆盖 |
| BL-AUTH-BYPASS（认证绕过） | `auth-bypass` / `jwt-auth-bypass` | 287 / 345 | 已有覆盖 |
| BL-WORKFLOW-VIOLATION（状态机违规） | `business-logic` / `race-condition` | 840 / 362 | 已有覆盖 |
| BL-MASS-ASSIGNMENT（参数污染） | `mass-assignment` | 915 | 已有覆盖 |
| BL-RACE-LOGIC（业务竞态） | `race-condition` | 362 | 已有覆盖 |
| Sandbox Escape（沙箱逃逸） | `sandbox-escape` | 265 / 284 | 本项目已补齐（V2/G5） |
| 代码注入（传统） | `spel-injection` / `ognl-injection` / `groovy-injection` / `mvel-injection` / `beanshell-injection` / `script-engine-injection` / `template-injection` | 917 / 94 / 1336 | 已有覆盖 |
| 路径穿越（传统） | `path-traversal` | 22 | 已有覆盖 |
| 命令注入（传统） | `command-injection` | 78 | 已有覆盖 |
| XSS（传统） | `xss-reflected` | 79 | 已有覆盖 |
| SSRF（传统） | `ssrf` | 918 | 已有覆盖 |
| 反序列化（传统） | `fastjson-deserialization` / `jackson-poly-deserialization` / `yaml-deserialization` / `unsafe-deserialization` | 502 | 已有覆盖 |
| 模板注入（传统） | `template-injection` | 1336 | 已有覆盖 |
| 供应链（传统） | `vulnerable-components` | 1104 | 已有覆盖 |
| 其余注入族（SQL/LDAP/NoSQL/XPath/XXE 等） | `sql-injection*` / `ldap-injection` / `nosql-injection` / `xpath-injection` / `xxe` / `header-injection` / `log-injection` / `jsonp-callback-injection` | 89 / 90 / 943 / 643 / 611 / 93 | 已有覆盖 |
| 长程任务（跨文件/gadget/状态机/拼接/版本门控） | `deserialization` / `unsafe-deserialization` / `spel-injection` / `fastjson-deserialization` / `log4j-jndi` | 502 / 917 | **本项目已补齐（LT 系列，§3 长程任务段）** |
| 代码质量/性能 DoS | `slow-sql` / `resource-leak` / `perf-anti-pattern` / `redos` | 400 / 772 / 410 / 1333 / 89 | **本项目已补齐（§3 代码质量/性能 DoS 段）** |
| 信任边界/反射/格式串/hostname/XSLT/forward/种子 | `trust-boundary` / `reflection-injection` / `format-string` / `hostname-verifier` / `xslt-injection` / `unvalidated-forward` / `predictable-seed` | 501 / 470 / 134 / 295 / 91 / 98 / 338 | **本项目已补齐（§3 LGTM/CodeQL 缺口段，对标 LGTM java/* 查询）** |
| 逻辑漏洞（支付/会员/业务流程） | `payment-logic` / `membership-logic` / `workflow-bypass` | 840 / 285 / 639 / 862 / 20 | **本项目已补齐（§3 逻辑漏洞段）** |

**映射结论**：
- JSEF 在 VulnGym 全部 21 个 `vuln_category_l2` 维度上均有对应 `category`：业务逻辑 12+1 子类中，8 个由 V1/V2 补齐（标"本项目已补齐"），其余由既有样本覆盖；传统类全部已有覆盖。
- VulnGym 独有且 JSEF 原缺失、现经补齐已对齐的子类：`agent-capability-bypass` / `origin-integrity` / `multi-tenant` / `trust-boundary` / `insecure-default` / `priv-esc` / `missing-authorization` / `sandbox-escape`（共 8 类，对应 G1–G8 / G5）。
- 路径评测维度：JSEF 通过可选 `trace=` 字段（§3）与 scorecard `--check-trace`（§5.1）对标 VulnGym 的 `entry_point → critical_operation → trace` 多节点理念，同时保留 JSEF 在 precision/F1/MCC 上的相对优势。

> 本节依据 `plans/01-vulngym-gap-completion.md` Phase V4（G10）与 `MY_PLAN.md` Phase H 编写。`category` 列表实查自 `benchmark/expectedresults.csv`（共 503 checkpoint，含表头 504 行；其中 LT 系列长程任务样本 16 条、代码质量/性能 DoS + LGTM 缺口样本 28 条、逻辑漏洞样本 12 条、原子范式样本族 TCM/SBM/DBG/STR 共 64 条，详见 §3）。
