# JSEF × VulnGym 差距补全计划

> 目标：借鉴腾讯 **VulnGym**（项目级白盒漏洞狩猎 benchmark，v0.1.4，184 advisory / 408 entry）的优势维度，补齐 JSEF 当前**缺失的样本类别与标注能力**，使 JSEF 在"业务逻辑漏洞深度"与"路径证据链"两个维度上达到行业对标水平。
> 全程遵循 `AGENTS.md` 的 checkpoint 双源门禁（`// [CHECKPOINT]` + `expectedresults.csv` 一致）与安全底线（仅 localhost 演示）。

---

## 0. VulnGym 核心特征（已调研，来源 SCHEMA.md / README_zh.md）

- **结构**：项目级单元，每个样本绑定真实仓库的漏洞 commit；每条 entry 含 `entry_point`（可达入口）、`critical_operation`（核心缺陷点）、`trace[]`（跨模块推理链，多节点 `{file,line,code,desc}`）。
- **分类**：两级 taxonomy `vuln_category_l1` / `vuln_category_l2`，**不用 CWE 编号**，自订类名。
- **漏洞分布**：业务逻辑类 **131/184 (71.2%)** + 传统类 53/184 (28.8%)。
- **业务逻辑 12+1 子类**（按漏洞数）：
  - BL-AUTHZ-BROKEN 授权逻辑错误 31 / BL-AUTHZ-MISSING 授权缺失 23 / **BL-AGENT-CAPABILITY AI/Agent 能力边界绕过 20** / BL-PRIV-ESC 特权提升 13 / BL-AUTH-BYPASS 认证绕过 11 / **BL-ORIGIN-INTEGRITY 来源/签名/完整性校验缺失 8** / BL-WORKFLOW-VIOLATION 状态机违规 7 / **BL-INSECURE-DEFAULT 不安全默认配置 6** / BL-RACE-LOGIC 业务竞态 4 / **BL-MULTI-TENANT 多租户隔离失效 3** / BL-MASS-ASSIGNMENT 参数污染 3 / **BL-TRUST-BOUNDARY 隐式信任内部输入 2**。
- **传统类**：代码注入 12 / 路径穿越 9 / 命令注入 8 / XSS 5 / **沙箱逃逸 5** / SSRF 4 / 认证绕过 3 / 反序列化 2 / 其他(模板注入/RCE/供应链) 5。
- **评测**：仅算 advisory/entry 级 **recall（覆盖率）**，行容差 `|Δline|≤5`，无 precision 惩罚（这是 VulnGym 已知短板，JSEF 的 F1/MCC 反而更强）。

---

## 1. 差距分析（JSEF 现状 vs VulnGym）

JSEF 当前 259 checkpoint / 70+ category，已覆盖：注入全族（SQL/CMD/SpEL/OGNL/groovy/mvel/beanShell/script/XXE/XPath/LDAP/NoSQL/模板）、反序列化（fastjson/jackson/yaml/CC链）、A01 越权（IDOR×多、authBypass/authorizationBypass/brokenAccessControl）、A02 加密、A04 部分（price tampering/mass assignment/business rule/race）、A05 配置、A06/A08 供应链、A09 日志、多后端 SQL 变体、高难度混淆。

**JSEF 相对 VulnGym 的缺口（MECE）**：

| # | 缺口维度 | VulnGym 有 | JSEF 现状 | 缺口严重度 |
|---|----------|-----------|-----------|-----------|
| G1 | **AI/Agent 能力边界绕过** | BL-AGENT-CAPABILITY ×20 | 零 | 高（JSEF 定位含 code-agent harness 评估，此维度最关键） |
| G2 | **来源/签名/完整性校验缺失** | BL-ORIGIN-INTEGRITY ×8 | 零 | 高（webhook 签名、JWT/signed-token 验证缺失） |
| G3 | **多租户隔离失效** | BL-MULTI-TENANT ×3 | 零 | 中高 |
| G4 | **隐式信任内部输入（信任边界）** | BL-TRUST-BOUNDARY ×2 | 零 | 中 |
| G5 | **沙箱逃逸** | Sandbox Escape ×5 | 零 | 中（JSEF 已有 script/groovy/mvel 引擎，缺"逃逸出沙箱"维度） |
| G6 | **不安全默认配置** | BL-INSECURE-DEFAULT ×6 | 零散（config-gated-sink×2） | 中 |
| G7 | **权限提升（角色/垂直越权精分）** | BL-PRIV-ESC ×13 | 仅 A01-003 垂直越权 1 个 | 中 |
| G8 | **授权缺失（新端点漏加鉴权）** | BL-AUTHZ-MISSING ×23 | 仅 broken-access-control 1 | 中 |
| G9 | **路径证据链 trace 标注** | entry→critical_operation→trace 多节点 | 仅单点 sink CHECKPOINT | 高（影响"路径正确性"评测能力） |
| G10 | **CWE↔VulnGym 分类映射** | 自订类名 | 仅有 CWE | 低（对标报告需映射） |

> JSEF 强于 VulnGym 之处（保留，不弱化）：L0–L5 梯度、gadget chain、混淆/安全样本配对、F1/MCC/precision、SARIF 协议、多后端 SQL。本计划**只借鉴补齐，不替换**。

---

## 2. 设计原则

1. **借鉴 taxonomy，保留 CWE**：VulnGym 用自订类名，JSEF 用 CWE。新增样本仍标注 CWE，但在 `category` 与注释中引入 VulnGym 对应子类名（如 `agent-capability-bypass`），并在文档给出 CWE↔VulnGym 映射表，便于横向对标。
2. **借鉴"路径证据链"**：扩展 `// [CHECKPOINT]` 注解，新增可选 `trace=` 字段，记录从 entry_point 到 critical_operation 的中间节点（file:line 列表），使 JSEF 能从"单点命中"升级到"路径正确性"评测。
3. **业务语义类沿用 IdorObjectOwnership 风格**：注释明确"数据流干净但语义缺失"。
4. **每 vuln 配 safe 配对**，safe 设计覆盖 FP 陷阱套路。
5. **不引入真实仓库 commit 树**：JSEF 保持 snippet 级（符合教学+静态分析定位），用自包含 Java 片段表达 VulnGym 的业务逻辑语义。

---

## 3. 实施阶段

### Phase V1 — 补齐 VulnGym 独有业务逻辑子类（G1–G4, G6–G8）
落点：`benchmark/cases/vuln/<cat>/` + `sec/`，package `com.jsef.benchmark.vuln`/`sec`。

- **G1 AI/Agent 能力边界绕过**（CWE-285/862，category `agent-capability-bypass`，L3–L4）：
  - `AgentToolNoAuthz`（工具调用未校验调用方权限，L3）
  - `AgentIntentBypass`（prompt/指令绕过工具白名单，L4）
  - `AgentPrivilegeEscalate`（agent 自我提升权限等级，L4）
  - 各配 safe（显式权限校验 / 工具白名单强制）。
- **G2 来源/签名/完整性校验缺失**（CWE-345/347，category `origin-integrity`，L3–L4）：
  - `WebhookNoSigVerify`（webhook 回调未验签，L3）
  - `SignedTokenNoVerify`（签名 token 未校验即信任，L3）
  - `IntegrityCheckBypass`（哈希/MAC 校验可被绕过，L4）
  - 各配 safe（HMAC 验签 / 签名验证）。
- **G3 多租户隔离失效**（CWE-639/285，category `multi-tenant`，L3–L4）：
  - `TenantDataLeak`（查询未带 tenant_id 过滤，L3）
  - `TenantIdSpoof`（tenant_id 来自客户端可伪造，L4）
  - 各配 safe（服务端 tenant 上下文隔离）。
- **G4 隐式信任内部输入**（CWE-502/94，category `trust-boundary`，L3）：
  - `TrustInternalInput`（内部服务传来的数据未校验直接 eval/反序列化，L3）
  - 配 safe（边界校验）。
- **G6 不安全默认配置**（CWE-1188/16，category `insecure-default`，L2–L3）：
  - `InsecureDefaultCreds`（默认账户/密码启用，L2）
  - `DebugDefaultOn`（默认开启 debug/verbose，L3）
  - 各配 safe。
- **G7 权限提升精分**（CWE-269/285，category `priv-esc`，L3–L4）：
  - `RoleManipulationEsc`（修改 role 字段提权，L3）
  - `VerticalPrivEscToken`（token 中 role 未校验，L4）
  - 各配 safe（角色来源服务端/不可变）。
- **G8 授权缺失（新端点漏鉴权）**（CWE-862，category `missing-authorization`，L3–L4）：
  - `NewEndpointNoAuthz`（新增接口漏加 @PreAuthorize，L3）
  - `AnonymousAdminEndpoint`（管理端点匿名可达，L4）
  - 各配 safe（统一鉴权拦截器）。

### Phase V2 — 沙箱逃逸（G5，借鉴传统类）
- **G5 沙箱逃逸**（CWE-265/284，category `sandbox-escape`，L4–L5）：
  - `ScriptEngineSandboxEscape`（利用 ScriptEngine/Reflection 逃逸沙箱，L4，复用 script-engine 引擎基础）
  - `GroovySandboxEscape`（Groovy `SecureASTCustomizer` 被绕过，L5）
  - `ClassloaderEscape`（自定义 ClassLoader 逃逸受限上下文，L5）
  - 各配 safe（严格沙箱策略 / 禁用危险 API）。

### Phase V3 — 路径证据链 trace 标注（G9，标注能力升级）
- 扩展 `// [CHECKPOINT]` 注解语法（**向后兼容**，新增可选字段）：
  ```
  // [CHECKPOINT id=JSEF-XXX cwe=NNN level=Ln source=... sink=... expect=VULN trace=FileA:lineB,FileC:lineD]
  ```
  - `trace=`：逗号分隔的 `file:line` 中间节点（从 entry_point 到 critical_operation 的污点/推理链）。
  - 仅对**跨文件/跨方法/业务链**样本（L3+ 且涉及多节点）添加；单点样本不加。
- 更新 `validate_checkpoints.py`：解析 `trace=` 字段，校验其中每个 `file:line` 在源码中存在（可选告警，不阻断）。
- 更新 `benchmark/README.md` 与 `AGENTS.md`：记录 `trace=` 字段语义。
- 为 Phase V1/V2 中跨文件/业务链样本回填 `trace=`。
- scorecard 可选增强：新增 `--check-trace` 模式，对支持 trace 的被测结果（SARIF 多 location / JSON 带 trace 列表）计算"路径覆盖率/方向正确性"指标（entry→critical_operation 方向匹配，参考 VulnGym 严格方向匹配）。

### Phase V4 — 对标映射与文档（G10）
- 在 `benchmark/README.md` 新增「JSEF ↔ VulnGym 分类映射表」：VulnGym `vuln_category_l2` → JSEF `category`/CWE 对照（如 BL-AGENT-CAPABILITY→agent-capability-bypass/CWE-285）。
- 更新 `MY_PLAN.md` 与 `plans/00-benchmark-gap-completion.md` 追加本计划引用。
- 更新 `benchmark/reports/generate_report.py` 的 OWASP 映射，补充 VulnGym 子类归并（可选，增强报告语义）。

---

## 4. 验证清单（每阶段）

- [ ] 每个 vuln 配 ≥1 safe，`validate_checkpoints.py` 退出码 0（无孤儿/重复/行号漂移）。
- [ ] `trace=` 字段仅出现在 L3+ 跨节点样本；`validate_checkpoints.py` 解析无报错。
- [ ] 自测：构造含 trace 的结果 JSON，跑 scorecard `--check-trace`，确认路径指标输出。
- [ ] 报告：JSEF ↔ VulnGym 映射表写入 README，mapping 覆盖本计划新增全部 category。
- [ ] 安全底线：所有样本仅 localhost 演示语义，无真实利用脚本。

---

## 5. 预期增量

- 新增约 **30–36** 个 checkpoint（G1–G8 每类 2–3 vuln+配对，G5 三个），分类新增 `agent-capability-bypass` / `origin-integrity` / `multi-tenant` / `trust-boundary` / `insecure-default` / `priv-esc` / `missing-authorization` / `sandbox-escape` 共 8 类。
- 标注能力升级：从"单点 sink 命中"到"entry→critical_operation 路径正确性"评测，对标 VulnGym 的 trace 理念但保留 JSEF 的 precision/F1/MCC 优势。
- 业务语义类占比显著提升，对标 VulnGym 71.2% 业务逻辑导向。

---

## 6. 参考源

- VulnGym 仓库：https://github.com/Tencent/VulnGym
- VulnGym SCHEMA.md：entry_point / critical_operation / trace 字段定义与不变式
- VulnGym README_zh.md：12+1 业务逻辑子类分布、评测口径（recall-only，行容差 ≤5）
- 现有 JSEF 样本约定：`benchmark/cases/vuln/IdorObjectOwnership.java`（业务语义注释风格）、`AGENTS.md`（checkpoint 门禁）、`benchmark/scripts/validate_checkpoints.py`（待扩展 trace 解析）

---

## 7. 完成判定

1. 新增 8 类业务逻辑/沙箱样本，全部带 `// [CHECKPOINT]` 且 CSV 双源一致（validator 零问题）。
2. `trace=` 字段在跨节点样本落地，`validate_checkpoints.py` 支持解析，scorecard 支持可选路径评测。
3. JSEF ↔ VulnGym 映射表写入文档，可横向对标。
4. 未触发安全底线。
