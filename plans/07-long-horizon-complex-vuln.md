# JSEF × 长程任务 + 复杂漏洞挖掘 样本补充计划

> 目标：从第一性原理出发，针对「LLM 长程任务 + 复杂漏洞挖掘」这一评测维度，补齐 JSEF 当前**缺失且有真实区分度**的样本类别。本计划横向对标 VulnGym / JITVul / LiveCVEBench / NYU CTF Bench 的「长程多跳 + 路径推理」维度，但不重复 `01-vulngym-gap-completion.md`（该计划侧重业务逻辑子类与 trace 标注能力）。
>
> 全程遵循 `AGENTS.md` 的 checkpoint 双源门禁（`// [CHECKPOINT]` + `expectedresults.csv` 一致、退出码 0）与安全底线（仅 localhost 演示）。

---

## 0. 学术界 / 开源界调研结论（来源与发现）

公开用于评估 LLM 长程漏洞挖掘的数据集：

| 数据集 | 出处 | 长程/复杂维度 | 对 JSEF 的启示 |
|---|---|---|---|
| **VulnGym** | Tencent, 2026 | entry→critical_operation→trace 证据链，跨模块 | trace 字段理念已被 JSEF 采纳（89 样本已带 trace） |
| **JITVul** | ACL'25 | 879 CVE，多跳跨方法 | 真实 CVE 跨方法数据流 |
| **LiveCVEBench** | CVE-Factory, 2026 | 190 task，持续更新真实 CVE，长程 agentic | 真实长程 agent 链 |
| **NYU CTF Bench** | NeurIPS'24 | 真实 CTF，L3–L5 含二进制/Web | 长程推理 |
| OWASP Benchmark / Juliet (SAMATE) | OWASP / NIST | 单函数级，弱数据流 | 不覆盖长程 |

**关键缺口（第一性原理）**：上述数据集普遍**缺 Java Web 框架语义**（Spring 绑定、JPA、SpEL、反序列化 gadget chain）。这正是 JSEF 的差异化价值所在。但 JSEF 在「长程路径推理难度」上仍有以下**横向缺口**（已实查确认）：

| # | 缺失维度 | 实查证据 | 区分度理由 |
|---|---|---|---|
| D1 | **含无害分叉/汇合的 trace 链** | `grep branch/merge/fork/diverge/distract/noise/decoy` → 0 结果 | 现有 89 条 trace 全为干净直线链；含干扰节点才能真考 LLM 路径正确性（VulnGym `trace[]` 也是直线，此为 JSEF 可超越点） |
| D2 | **JPA 派生查询名注入（隐式框架数据流）** | `grep jpa/repository/derive` → 0 目录 | `findByXxx` 方法名被不可信输入拼接 → 隐式 SQL 注入，需理解 Spring Data 命名约定，纯语法 SAST 看不见 |
| D3 | **@ModelAttribute 深度绑定污点传播** | `grep modelattr/deepbind` → 0 目录 | 表单对象深度绑定把不可信字段透传到下游 sink，跨对象图长程传播 |
| D4 | **配置/版本门控的 sink 可达性链** | 仅零散 `misconfig/` | feature-flag / 版本判断控制 sink 是否可达，需跨「配置读取→条件分支→sink」三节点推理 |
| D5 | **跨 HTTP 边界污点传播（服务间调用桩）** | `grep rpc/feign/resttemplate/inter-svc` → 0 目录 | 污点经 RestTemplate/Feign 调下游服务再回传至 sink，考跨进程边界的隐式数据流 |

> 已覆盖（不重复）：L5 gadget chain（GadgetChainCmd/Jdbc/Ssrf/Xxe、Log4jToJndiChain、Spring4ShellChain）、跨文件链（ChainController/A/B）、state machine（Spring4ShellStateMachine）、Fastjson 版本门控（已有 FastjsonVersionGated）。

---

## 1. 设计原则

1. **路径推理难度优先**：每个长程样本必须体现「单点工具看不见、需跨节点/跨语义推理」的特征。
2. **trace= 用于路径正确性**：D1/D2/D3/D4/D5 全部带 `trace=`，且 D1 特意构造**无害分叉节点**（节点真实存在但不在污点主路径上），供 `--check-trace` 计算 `trace_precision`/`trace_recall`。
3. **框架语义用桩/注解表达**：JPA 用接口方法名 + 注释声明语义（`// 语义等价: 由方法名生成 SQL`）；跨服务用 `RestTemplate.exchange(...)` 桩 + 注释声明下游回传语义，符合 AGENTS.md「桩方法信名字/注释」约定。
4. **每 vuln 配 safe 配对**（safe 实现真实防护），用于 FP/TN 计算。
5. **SNIPPET 级、不编译**：保持 benchmark/cases 静态可读定位。

---

## 2. 实施阶段

### Phase L1 — 含无害分叉的 trace 链（D1，L4–L5）
落点：`benchmark/cases/vuln/trace-distractor/`、`sec/`。
- `TraceForkCmd`（L4）：Controller(source) → ServiceA(分叉：一条无害 `auditLog()` 分支 + 一条污点分支) → ServiceB(sink: Runtime.exec)。trace 仅含污点主路径节点，分叉的 `auditLog()` 行故意**不入** trace，考 LLM 是否误把无害节点当路径。
- `TraceMergeSql`（L5）：两条独立污点源（header + body）各自经无害加工后**汇合**进同一 JPA/Statement sink；trace 含两源汇合点，考 LLM 识别「汇合即危险」。
- 各配 safe（白名单/参数化）。

### Phase L2 — JPA 派生查询名注入（D2，L3–L4）
落点：`benchmark/cases/vuln/jpa-derived/`、`sec/`。
- `DerivedQueryNameInjection`（L4）：不可信 `sortField` 拼入 repository 方法名 `findBy<Field>`，Spring Data 据此生成 SQL → 注入。需理解「方法名即查询」隐式语义。桩：`interface UserRepo { @Query(...) List<User> findByXxx(...); }` + 注释声明语义等价。
- `DerivedQueryKeywordInjection`（L3）：`And/Or/OrderBy` 关键字被不可信输入拼接。
- 各配 safe（白名单字段映射 / 用 `Sort` 安全 API）。

### Phase L3 — @ModelAttribute 深度绑定传播（D3，L4）
落点：`benchmark/cases/vuln/modelattr-bind/`、`sec/`。
- `ModelAttrDeepBindXss`（L4）：`@ModelAttribute OrderForm form` 深度绑定，嵌套对象 `form.address.remark` 不可信字段经对象图透传至模板渲染 sink；考跨对象图隐式污点传播。
- `ModelAttrBindToSink`（L4）：绑定对象字段直接进 SQL/命令 sink。
- 各配 safe（绑定后统一校验 / `@Valid` + 白名单）。

### Phase L4 — 配置/版本门控可达性链（D4，L4–L5）
落点：`benchmark/cases/vuln/config-gated/`、`sec/`。
- `FeatureFlagGatedExec`（L5）：`if (config.isLegacyMode())` 为真时污点才进 `Runtime.exec`；需跨「@Value 配置读取 → 条件分支 → sink」三节点，且默认配置下可达（考 LLM 是否忽略默认可达性）。
- `VersionGatedDeser`（L4）：依赖版本号门控反序列化类型白名单（借鉴 FastjsonVersionGated 但换 Shiro/Jackson 语义）。
- 各配 safe（门控永久关闭危险路径 / 版本无关安全实现）。

### Phase L5 — 跨 HTTP 边界污点传播（D5，L4–L5）
落点：`benchmark/cases/vuln/cross-svc/`、`sec/`。
- `RestTemplateTaintForward`（L4）：Controller 收 `userId` → 经 `restTemplate.getForObject(下游URL?q=userId)` → 下游返回体未净化 → 进 SQL sink。桩：`RestTemplate` + 注释声明「下游回传即不可信」。
- `FeignChainSsrf`（L4）：Feign client 把不可信 host 转成内网请求 → SSRF sink。
- 各配 safe（下游响应净化 / host 白名单）。

---

## 3. 验证清单（每阶段）

- [ ] 每个 vuln 配 ≥1 safe，`validate_checkpoints.py` 退出码 **0**（无孤儿/重复/行号漂移）。
- [ ] `trace=` 仅出现在 L3+ 跨节点样本；D1 分叉节点真实存在但**不**入 trace；`validate_checkpoints.py` 报「0 无效」。
- [ ] 构造含 trace 的结果 JSON，跑 `scorecard.py --check-trace`，确认 D1 在无分叉误报时 `trace_precision=1`、漏报分叉时仍可区分。
- [ ] 自测：`python3 benchmark/scripts/scorecard.py --expected benchmark/expectedresults.csv --result <结果>` 双源可关联。
- [ ] 安全底线：所有样本仅 localhost 演示语义，无真实利用脚本；桩方法带 `// 语义等价:` 注释。

---

## 4. 预期增量

- 新增约 **14–18 个 checkpoint**（5 阶段，每阶段 2–4 vuln+配对），新增 category：`trace-distractor` / `jpa-derived` / `modelattr-bind` / `config-gated` / `cross-svc` 共 5 类。
- 维度升级：JSEF 从「直线 trace 链」升级到「含分叉/汇合干扰的路径正确性评测」，在长程路径推理维度**超越 VulnGym/JITVul 的直线 trace**。
- 框架语义补强：补齐 Java Web 长程特有的 JPA 派生查询、@ModelAttribute 深度绑定、跨服务边界三类隐式数据流样本（学术界数据集普遍缺失）。

---

## 5. 参考源

- VulnGym：https://github.com/Tencent/VulnGym（trace 字段理念）
- JITVul：ACL'25 (2025.acl-long.1490)
- LiveCVEBench：arXiv:2602.03012
- NYU CTF Bench：arXiv:2406.05590
- 模板样本：`benchmark/cases/vuln/ChainController.java`（跨文件 trace 风格）、`benchmark/cases/vuln/level5/GadgetChainCmd.java`（L5 组合链）、`AGENTS.md`（checkpoint 门禁 + trace 字段语义）、`benchmark/scripts/validate_checkpoints.py`（trace 解析，已支持）

---

## 6. 完成判定

1. 新增 5 类长程样本全部带 `// [CHECKPOINT]` 且 CSV 双源一致，validator 零问题、退出码 0。
2. D1 分叉/汇合干扰样本落地，`--check-trace` 可区分路径正确性。
3. JPA 派生查询、@ModelAttribute 深度绑定、跨 HTTP 边界三类框架语义长程样本落地。
4. 未触发安全底线。
