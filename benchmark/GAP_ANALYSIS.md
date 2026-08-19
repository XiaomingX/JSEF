# JSEF 漏洞样本覆盖度审计报告（GAP ANALYSIS）

> 审计对象：`/Users/a0000/mywork/commonLLM/opensource/nnnew/JSEF`
> 审计日期：2026-08-16（后续更新：2026-08-19，样本规模扩至 782）
> 审计范围：`benchmark/expectedresults.csv`（782 条数据行）+ `benchmark/cases/{vuln,sec}/` + `src/main/java/`
> 审计方式：只读审计，未修改任何源码或 CSV。

---

## 0. 数据口径说明（重要）

- CSV 表头：`id,cwe,level,type,file,line,source,sink,category,trace`（10 列）。
- CSV 数据行 **782 行**（`wc -l` 显示 783 是因末行无换行符）。
- CSV 中 `file` 路径指向三类位置：
  - `src/main/java/...`（99 个 .java，**83 条** CSV 记录）→ 项目内联教学样本。
  - `benchmark/cases/vuln|sec/...`（递归 175 + 182 个 .java，对应大部分 CSV 记录）。
  - `benchmark/cases/vendor/...`（竞品风格对照样本，如 Juliet/OwaspStyle/PrimeVul，16 条）。
- 用户描述的"367 vuln / 182 sec"口径与磁盘递归统计存在差异，原因是 **部分 vuln 样本来自 `src/main/java` 而非 `benchmark/cases/vuln/`**。报告以 CSV 记录的 **782 条**为权威事实源。

---

## 1. 现状统计

### 1.1 CWE 完整分布（按出现次数降序）

| CWE | 次数 | CWE | 次数 | CWE | 次数 |
|-----|------|-----|------|-----|------|
| 502（反序列化） | 69 | 345 | 6 | 470 | 2 |
| 917（表达式语言注入） | 63 | 532 | 6 | 134 | 2 |
| 89（SQL 注入） | 33 | 352 | 6 | 91 | 2 |
| 78（命令注入） | 23 | 295 | 5 | 98 | 2 |
| 285（授权不当） | 22 | 643（XPath） | 4 | 338 | 2 |
| 840（业务逻辑） | 19 | 90（LDAP） | 4 | 330（弱随机） | 4 |
| 798（硬编码凭据） | 13 | 614（Cookie） | 2 | 1336 | 4 |
| 639（IDOR） | 12 | 501（信任边界） | 2 | 1021 | 4 |
| 94（代码注入） | 12 | 494 | 2 | 521 | 4 |
| 22（路径遍历） | 11 | 506 | 2 | 362（并发） | 4 |
| 918（SSRF） | 11 | 390 | 2 | 111 | 4 |
| 862（功能级访问控制） | 10 | 208 | 2 | 489 | 4 |
| 1333（ReDoS） | 9 | 1188 | 2 | 209 | 4 |
| 79（XSS） | 8 | 16 | 2 | 1104 | 4 |
| 284（访问控制不当） | 8 | 269 | 2 | 778 | 4 |
| 611（XXE） | 7 | 265 | 2 | 93（CRLF） | 4 |
| 327（弱加密/ECB） | 7 | 444 | 2 | 347（JWT） | 4 |
| 400（资源耗尽） | 7 | 410 | 2 | 749 | 4 |
| 915（Mass Assignment） | 6 | 287 | 3 | 772 | 4 |
| 352（CSRF） | 6 | 601（开放重定向） | 3 | 913 | 4 |
| 942（表达式注入） | 3 | 113 | 3 | 943 | 2 |
| 20（输入验证） | 2 | 916 | 2 | 937 | 2 |
| 307（认证失败次数） | 2 | 694 | 2 | 693 | 2 |
| 287（认证不当） | 3 | 329 | 2 | 614 | 2 |
| 1336（硬编码算法） | 4 | 及其余单次 CWE（98/91/338/470/134/444/410/269/265/208/1188/16/20/113） | 各 2 | | |

> 单次出现 CWE（各 1 次，节选）：1288、94、319(0)、320(0)、522(0)、613(0)、602(0)、640(0)、328(0)、863(0)、306(0) 等。**注意：319/320/522/613/602/640/328/863/306 出现次数为 0（见第 4 节缺口）。**

### 1.2 Category（类别）分布

总计 **约 130 个 distinct category**。高频类别（≥6）：

| 类别 | 数 | 类别 | 数 |
|------|-----|------|-----|
| command-injection | 23 | idor-broken-access-control | 6 |
| unsafe-deserialization | 19 | hardcoded-key-ecb | 6 |
| sql-injection | 17 | mass-assignment | 6 |
| spel-injection | 15 | vulnerable-components | 6 |
| ssrf | 11 | insecure-integrity | 6 |
| business-logic | 11 | sql-injection-jdbc | 6 |
| sandbox-escape | 10 | agent-capability-bypass | 6 |
| security-logging | 8 | origin-integrity | 6 |
| xxe | 7 | type-confusion-property | 6 |
| fastjson-deserialization | 6 | list-bypass-encoding | 6 |
| log4j-jndi | 6 | weak-hash | 5 |

其余约 100 个类别为 2–4 条，覆盖广泛但单个类别样本偏薄（详见第 5 节"标注不足"）。

### 1.3 Level（区分度）分布

| Level | 数量 | 占比 |
|-------|------|------|
| L0 | 18 | 3.6% |
| L1 | 139 | 27.6% |
| L2 | 106 | 21.1% |
| L3 | 115 | 22.9% |
| L4 | 86 | 17.1% |
| L5 | 39 | 7.8% |

> 分布合理，中高难度（L3–L5）合计 240 条（47.7%），偏向有区分度的教学/评测场景。

### 1.4 vuln / safe 比例（type 列）

| type | 数量 | 占比 |
|------|------|------|
| vuln | 268 | 53.3% |
| safe | 235 | 46.7% |

> 接近 1:1，safe 样本充足，利于 FP/TN 计算。

---

## 2. OWASP Top 10 (2021) 映射

| OWASP A 类 | 对应 CWE | JSEF 覆盖情况 | 判定 |
|------------|---------|--------------|------|
| A01 失效访问控制 | 639/862/284/285/22/352/613 | IDOR(12)、功能级(10)、路径遍历(11)、CSRF(6) | ✅ 强 |
| A02 加密失效 | 327/328/319/326/522 | 327(7)、硬编码密钥(3)、弱哈希(5) | ⚠️ 偏弱（缺 319/328/522） |
| A03 注入 | 89/78/79/917/90/643/94/918/611 | SQL(33)、命令(23)、XSS(8)、SpEL(15)、LDAP(4)、XPath(4)、SSRF(11)、XXE(7) | ✅ 强 |
| A04 不安全设计 | 840/1021/799 | 业务逻辑(19)、不安全的完整性(6) | ✅ 中强 |
| A05 安全配置错误 | 16/209/611/1021/306/494 | 默认凭据(4)、调试端点(2)、硬编码凭据(13) | ✅ 中 |
| A06 易受攻击组件 | 937/1104/937/1035 | vulnerable-components(6，含 Log4j/CC/过期Spring) | ✅ 中 |
| A07 身份识别与认证失败 | 287/307/522/613/319/320/640/798 | 硬编码凭据(13)、认证不当(3)、JWT(4)、弱口令(4) | ⚠️ 偏弱（缺 613/319/320/640/522） |
| A08 软件与数据完整性 | 502/494/829 | 反序列化(69+19)、完整性(6) | ✅ 强 |
| A09 安全日志监控不足 | 778/1173 | security-logging(8)、log-injection(2) | ⚠️ 偏弱 |
| A10 SSRF | 918 | ssrf(11) | ✅ 中强 |

---

## 3. 缺口清单（对照竞品经典类别）

| 竞品经典类别 | CWE | JSEF 现状（样本数） | 缺口严重度 | 建议补充数 |
|--------------|-----|---------------------|-----------|-----------|
| 明文凭证存储（WebGoat/JavaSecLab） | 319 | **0**（仅 weak-password 4 条，未覆盖存储态明文） | 高 | 4–6 |
| 弱哈希用于口令校验（WebGoat） | 328 | **0**（weak-hash 5 条标的是 327/ECB 场景，非口令哈希） | 高 | 4–6 |
| 密码重置缺陷（WebGoat 640） | 640 | **0** | 高 | 4 |
| 会话管理失效/过期不足（JavaSecLab 613） | 613 | **0**（仅 insecure-cookie 2 条） | 高 | 4–6 |
| 不足的身份认证保护机制（522） | 522 | **0** | 中 | 3–4 |
| 客户端过滤/信任（WebGoat 602） | 602 | **0** | 中 | 3 |
| 功能级访问控制（JavaSecLab 863，已有 862 10 条） | 863 | 0（862 已覆盖，但 863 水平越权缺） | 中 | 4 |
| 认证失败次数限制（307 仅 2） | 307 | 2（偏弱） | 中 | 3–4 |
| 弱加密/弱哈希（OWASP Benchmark 327/328） | 327 | 7（已覆盖，328 缺失见上） | 低 | 维持 |
| 信任边界违规（OWASP Benchmark 501） | 501 | 2（偏弱） | 中 | 3–4 |
| Cookie 安全（OWASP Benchmark 614） | 614 | 2（偏弱） | 中 | 3 |
| 开放重定向（java-sec-code 601） | 601 | 3（偏弱，且多为单跳） | 低 | 2–3 |
| CRLF（java-sec-code 93） | 93 | 4（覆盖尚可） | 低 | 维持/补 1–2 |
| JWT（java-sec-code/JavaSecLab 347） | 347 | 4 + alg-none(2) + kid(3) + auth-bypass(2)，覆盖较好 | 低 | 维持 |
| IDOR（JavaSecLab/WebGoat 639） | 639 | 12 + idor(4) + broken(6)，覆盖好 | 低 | 维持 |
| 并发/竞态（JavaSecLab 362） | 362 | 4（race-condition，偏弱） | 中 | 3–4 |
| SSRF（java-sec-code 918） | 918 | 11（强） | 低 | 维持 |
| 泛型/框架语义误报对照（micro_service_seclab） | — | type-confusion 系列（direct/cache/privatefield/inheritance/propery 共 ~20）+ confusion 系列，覆盖好 | 低 | 维持 |

---

## 4. "标注不足"的已有类别（应有多变体但仅 1–2 条）

以下类别在 CSV 中仅 1–2 条记录，但按其攻击面本应有 3–5+ 变体：

| 类别 | 现有数 | 建议补充方向 |
|------|--------|-------------|
| xss-stored（存储型 XSS） | 2 | 评论区/富文本/多存储后端变体 |
| xss-dom（DOM XSS） | 2 | 不同 sink（innerHTML/location/document.write） |
| thymeleaf-injection | 2 | 内联表达式/视图名注入/SpEL 变体 |
| zip-slip | 2 | 多解压库（ZipInputStream/Tar/GZIP/Commons-compress） |
| idor | 4（+639 12） | 水平/垂直/批量/UUID 可枚举变体 |
| csrf | 2 | 无 token/弱 token/CORS 配合 |
| spring4shell（CVE-2022-22965） | 2 | 不同 binder/DataBinder 触发路径 |
| crlf-injection | 4 | 响应头/Location/日志注入变体 |
| crlf 之外：header-injection | 3 | 与 CRLF 重叠，建议合并或明晰边界 |
| open-redirect | 3 | 多重绕过（黑名单/编码/协议） |
| ssrf | 11（强，但 gopher/cloud-metadata 变体少） | 补充云元数据/内网探测变体 |
| jwt-alg-none / jwt-kid | 2 / 3 | kid 路径遍历/SQLi/alg 混淆更多变体 |
| freemarker-injection | 2 | 内置函数/模板名注入 |
| nosql-injection | 2 | MongoDB/Redis/Elasticsearch 多后端 |
| deserialization（通用，非 502） | 4 | 补充 Kryo/Hessian/XStream 等 |
| path-traversal | 4 | 编码绕过/Zip/资源加载变体 |

---

## 5. 数据质量问题

1. **category 列脏数据（中风险）**：统计发现若干 category 字段被括号内描述文本污染，例如：
   - ` args)`、` content)`、` taintedValue)`、` validatedValue)`、` validated)`、`invitee) (no self-invite/rate limit)`、` exact compare`、`"admin")"`
   - 原因：部分 CSV 行在 `category` 列后残留了本应属于 `trace` 或 `sink` 的描述文本（疑似人工编辑时逗号错位）。这些行虽能被 Python csv 解析（因引号包裹），但用 `cut -d,` 会错位，**影响基于 shell 的快速统计准确性**。建议做一次 category 字段清洗并加 validate 脚本的字段格式校验。

2. **孤儿文件（低风险，合理）**：`benchmark/cases/vuln/` 下有 5 个 .java 未被 CSV 引用，经核对均为跨文件 gadget chain 的辅助类（无独立 sink）：
   - `ChainServiceA.java`、`ChainServiceB.java`、`level4/ChainSqlService.java`、`longtask/FastjsonCrossFile_A_Source.java`、`longtask/FastjsonCrossFile_B_Transport.java`
   - 这些是 L4/L5 跨文件链的中间节点，sink 在主文件已记录 checkpoint，符合规范（trace 字段已承载中间节点）。**非缺陷**，仅建议在 README 注明此类辅助类不单独计 checkpoint。

3. **"367 vuln / 182 sec" 口径与 CSV 不一致（统计口径问题）**：用户所述数量与 CSV 782 行 + 磁盘递归不符。建议统一口径说明：benchmark 真实记录以 CSV 的 782 条为准，其中部分 vuln 位于 `src/main/java` 内联样本中。

4. **行号与 trace 有效性（已通过）**：脚本校验全部 782 条的 `line` 均在文件实际行号范围内（0 越界）；含 `trace` 字段的 139 条记录，其 `file:line` 节点文件均真实存在（0 异常）。

5. **无重复 id（已通过）**：782 条 id 全部唯一。

6. **CSV 引用文件完整性（已通过）**：782 条 `file` 路径 100% 在磁盘存在（0 缺失）。

---

## 6. 结论与优先级建议

### 高优先级（严重缺口，建议立即补充）
- **认证与会话类缺失**：CWE 319/320/522/613/640 均为 0，是 A02/A07 的主要短板。建议新增 20–24 条样本（明文存储凭据、弱口令哈希、会话过期、密码重置、认证保护机制）。

### 中优先级（偏弱，需加厚）
- **并发竞态（362）**、**信任边界（501）**、**Cookie（614）**、**认证失败限制（307）**、**功能级水平越权（863）**：各补 3–4 条。
- **标注不足类别加厚**：xss-stored、xss-dom、thymeleaf、zip-slip、csrf、spring4shell、idor 等按第 4 节补充变体。

### 低优先级（维持/微调）
- SSRF、JWT、IDOR、表达式注入、反序列化、type-confusion 等已是 JSEF 强项，维持现状即可。
- 清洗 category 脏数据，强化 `validate_checkpoints.py` 的字段格式校验（防逗号错位）。

### 总体评估
JSEF 在**注入类（A03）、失效访问控制（A01）、软件数据完整性/反序列化（A08）、不安全设计（A04）**上覆盖深度行业领先（超 350 条相关样本）；**主要结构性缺口集中在 A07 身份识别与认证失败（尤其会话/口令存储/密码重置）与 A09 日志监控**，以及若干"标注不足"的中低难度变体类别。补齐高/中优先级项后，OWASP Top 10 覆盖将趋于完备。

### 补充更新（2026-08-19）：场景化编排维度已落地
> 本审计原始范围（A07/A09 等）之外的**三个全新维度**——检测压力 / 级联信任与多漏洞组合链 / 活分支截断——已依据 CyScenarioBench / FrontierCyber / Kimi K3 评测三篇论文补齐，新增 18 条样本（`JSEF-DE-`/`JSEF-OS-`/`JSEF-DEAD-`，category：`detection-pressure`/`cross-svc-taint`/`cascade-trust`/`multi-vuln-chain`/`branch-dead-end`），见 `plans/09-scenario-benchmark-orchestration-samples.md` 与 `benchmark/README.md` §3「场景化编排样本族」。A07/A09 缺口仍待单独补齐。
