# 计划 06 — new_vuln 高区分度样本补充（缺口核查与落地）

> 依据：用户提交的三份 `new_vuln` 补充计划（NV-01~NV-16、`#1~#27`、`plan/new_vuln.md` 22 族），
> 经事实核查后去重、剔除与现有 602 个 checkpoint 重复项，仅保留**确认为缺口**的样本。
> 规范：与 CLAUDE.md / AGENTS.md 一致 —— vuln/sec 成对、`// [CHECKPOINT]` 机器可读标注、
> 同步 `benchmark/expectedresults.csv`（10 列，行号精确）、跑 `validate_checkpoints.py` 退出码 0。
> 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本；样本不要求编译，语义可读优先。

## Phase 0 — 现状核查结论（已用 3 个 Explore 子代理全量盘点 benchmark/cases + src/main）

现有覆盖：602 checkpoint / 171 category。三份计划里的提案 **约 60% 已覆盖**，具体如下：

### 已覆盖、跳过（附证据，不重复补充）
| 提案 | 现有证据 |
|---|---|
| 二阶注入 / 二次注入 | `benchmark/cases/vuln/taint-variants/StoredTaintSql.java` (JSEF-TV-001, CWE-89 L4) |
| JWT 未验签取 role | `benchmark/cases/vuln/origin-integrity/SignedTokenNoVerify.java` (JSEF-V1-ORG-002, CWE-347 L3) |
| 常量时间比较 | `benchmark/cases/vuln/blind/TimingSideChannel.java` (JSEF-BL-003, CWE-208) + Safe |
| stacktrace 写响应 | `benchmark/cases/vuln/misconfig/VerboseErrorLeak.java` (JSEF-A05-002, CWE-209) |
| 明文口令存储 | `benchmark/cases/vuln/cleartext-cred/PlaintextPasswordStore.java` (JSEF-COMP-006, CWE-522) |
| 会话失效/超时 | `session-mgmt/SessionNoTimeout.java`、`password-reset/ResetKeepsOldSession.java` (CWE-613/640) |
| 密码重置 token 可预测 | `password-reset/PredictableResetToken.java` (JSEF-COMP-004, CWE-640) |
| 信任前端角色/隐藏域 | `accesscontrol/VerticalPrivEsc.java` (JSEF-A01-003)、`priv-esc/RoleManipulationEsc.java` |
| 水平越权(请求体 userId) | `accesscontrol/IdorByQueryParam.java` (JSEF-A01-002)、`InsecureDirectObjectReferenceController.java` |
| CORS 通配+凭证 | `benchmark/cases/vuln/misconfig/CorsWildcardCreds.java` (JSEF-A05-001) + `JSEF-CORS-001` |
| 速率限制缺失 | `src/main/.../ratelimiting/.../RateLimitingUnsafeController.java` (JSEF-RATELIMIT-001, CWE-307) |
| JDBC URL 注入 | `benchmark/cases/vuln/level5/GadgetChainJdbc.java` (JSEF-L5-JDBC-001, autoDeserialize) |
| Jackson 危险多态 | `benchmark/cases/vuln/JacksonPolymorphic.java` (JSEF-JACKSON-001) |
| 数组 `sh -c` 仍 RCE | `benchmark/cases/vuln/confusion/CmdPartialAllowlist.java` (JSEF-PF-002) + SAFE 对照 |
| 清洗器用错变量 | `benchmark/cases/vuln/taint-variants/WrongVarSanitized.java` (JSEF-TV-004) |
| Optional/Stream 传播 | `benchmark/cases/vuln/taint-variants/StreamPropagation.java` (JSEF-TV-003) |
| SQL `IN`/数值型拼接 | 现有 sql-injection 族（参数化 vs 拼接已覆盖） |
| 路径穿越(直连/拼接/zip-slip/binder) | `L0PathDirect`、`str/PathTraversalInjection`、`zip-slip/ZipSlip`、`sbm/*` |

### 部分覆盖 — 需补强（代码模式存在但无独立带 CHECKPOINT 的 benchmark 样本）
- **Velocity SSTI**：`src/main/.../templateInjection/TemplateInjectionVulnerabilityController.java:105` 有 `VelocityEngine.evaluate(... userInput)`，但无 `// [CHECKPOINT]`、无独立 benchmark 样本 → 补一个带 checkpoint 的 Velocity 样本（CWE-1336）。
- **重定向 startsWith 域名绕过**：`src/main/.../openRedirect/OpenRedirectVulnerabilityController.java:91` 有 `startsWith("http://")||startsWith("https://")` 绕过模式但无独立 checkpoint；benchmark 侧 `open-redirect/OpenRedirect.java` 仅直连无校验 → 补 `redirect-startswith-bypass` 专项样本（CWE-601）。
- **Spring 配置门控 sink**：`ConfigFlagGatedSink` 已覆盖「开关被篡改为真」；计划里的「默认 true 驱动求值」与之语义近，可视为已覆盖，不单列。

---

## Phase 1 — 完全缺口样本（高优先，整类缺失）

以下类别当前 **0 样本**，按三份计划合并去重后逐条落地，**每条 vuln+sec 配对**。

### 1.1 文件上传（CWE-434, L2/L3）— `benchmark/cases/{vuln,sec}/file-upload/`
- `UnrestrictedUploadVuln.java`：扩展名黑名单 `endsWith(".jpg")` 被双写 `.phphpp` / Content-Type 伪造绕过，写入后可访问 → sink 为文件落盘（语义等价 `Files.write`）。CHECKPOINT `source=filename sink=Files.write (extension blacklist bypass) expect=VULN`。
- `UploadAllowlistSafe.java`：MIME + 扩展名白名单 + 随机文件名 + 隔离目录。CHECKPOINT `expect=SAFE`。
- 参考模式：`benchmark/cases/vuln/zip-slip/ZipSlip.java`（文件写入 sink 写法）。

### 1.2 JWT RS256→HS256 算法混淆（CWE-347, L3）— `.../jwt-alg-confusion/`
- `JwtAlgConfusionVuln.java`：验签时从 token 头读 `alg`，若攻击者把 RS256 改 HS256，服务端用**公钥**当 HMAC 密钥验签通过 → sink `verify(token, publicKeyAsHmacSecret)`。CHECKPOINT `source=token.alg header sink=JWT.verify (RS256→HS256 confusion) expect=VULN`。
- `JwtAlgConfusionSafe.java`：固定 RS256 + 公钥验签，拒绝 alg 变更。CHECKPOINT `expect=SAFE`。
- 区别现有：`jwt-algnone`(alg=none)、`JwtWeakSecret`(弱密钥) 均不涉及非对称/对称错配，本项为新子场景。

### 1.3 JWT jku/x5u 不可信 JWKS 拉取（CWE-347/918, L4）— `.../jwt-jku/`
- `JwtJkuVuln.java`：信任 header 的 `jku` URL，从该 URL 拉取 JWKS 公钥验签 → SSRF + 公钥投毒。CHECKPOINT `source=jku header URL sink=JWT verify using fetched JWKS expect=VULN trace=...:lineA,...:lineB`。
- `JwtJkuSafe.java`：忽略 jku，仅用本地白名单 kid 固定公钥。CHECKPOINT `expect=SAFE`。

### 1.4 XMLDecoder 解析用户 XML（CWE-502, L2）— `.../xmldecoder/`
- `XmlDecoderVuln.java`：`new XMLDecoder(new ByteArrayInputStream(userXml)).readObject()` → 方法调用即代码。CHECKPOINT `source=userXml sink=XMLDecoder.readObject expect=VULN`。
- `XmlDecoderSafe.java`：不解析不可信 XML / 用白名单反序列化。CHECKPOINT `expect=SAFE`。

### 1.5 XStream 白名单语序陷阱（CWE-502, L3）— `.../xstream-late/`
- `XstreamLateAllowlistVuln.java`：`xstream.fromXML(xml)` **之后**才调用 `allowTypes(...)` → 解析时白名单未生效。CHECKPOINT `source=userXml sink=XStream.fromXML (allowlist configured AFTER parse) expect=VULN`。
- `XstreamLateAllowlistSafe.java`：`allowTypes` 在 `fromXML` 之前。CHECKPOINT `expect=SAFE`。
- 区别现有：`XStreamUnsafe`(完全无白名单) 已覆盖，本项是「防护顺序错误」陷阱（LLM 易误判 SAFE）。

### 1.6 Hessian2 无 Allowlist（CWE-502, L2）— `.../hessian/`
- `HessianVuln.java`：`Hessian2Input.readObject()` 无类型白名单。CHECKPOINT `source=hessianBytes sink=Hessian2Input.readObject expect=VULN`。
- `HessianSafe.java`：反序列化前类型校验 / 拒不可信。CHECKPOINT `expect=SAFE`。

### 1.7 Apache JEXL SSTI（CWE-917, L2）— `.../jexl/`
- `JexlVuln.java`：`new JexlBuilder().create().createExpression(userInput).evaluate(ctx)` → 表达式注入。CHECKPOINT `source=userInput sink=JEXLExpression.evaluate expect=VULN`。
- `JexlSafe.java`：表达式固定常量，用户输入仅作数据绑定。CHECKPOINT `expect=SAFE`。

### 1.8 Velocity SSTI（CWE-1336, L2）— `.../velocity/`（补缺口，现有 src 段无 checkpoint）
- `VelocityVuln.java`：`VelocityEngine.evaluate(ctx, writer, "tpl", userInput)` 渲染用户模板。CHECKPOINT `source=userInput sink=VelocityEngine.evaluate expect=VULN`。
- `VelocitySafe.java`：`th:text` 等价 / 模板固定。CHECKPOINT `expect=SAFE`。
- 参考现有：`src/main/.../templateInjection/TemplateInjectionVulnerabilityController.java:105`（Velocity 实现，但无 checkpoint，本项补独立带标注样本）。

### 1.9 SVG 上传触发 XXE（CWE-611, L3）— `.../svg-xxe/`
- `SvgXxeVuln.java`：用户上传 SVG（XML）用默认 `DocumentBuilderFactory` 解析 → XXE。CHECKPOINT `source=svgBytes sink=DocumentBuilder.parse (XXE via SVG) expect=VULN`。
- `SvgXxeSafe.java`：禁用 DOCTYPE / 安全解析。CHECKPOINT `expect=SAFE`。

### 1.10 XXE feature 设在错误工厂实例（CWE-611, L3）— `.../xxe-wrong-factory/`
- `XxeWrongFactoryVuln.java`：在另一个 `DocumentBuilderFactory` 实例上 `setFeature(DISALLOW_DOCTYPE, true)`，实际解析用的实例未加固。CHECKPOINT `source=userXml sink=DocumentBuilder.parse (hardening set on wrong factory) expect=VULN`。
- `XxeWrongFactorySafe.java`：加固设于同一实例。CHECKPOINT `expect=SAFE`。

---

## Phase 2 — 路径/规范化绕过（CWE-22，现有仅直连/拼接/zip-slip，缺「规范化陷阱」）

### 2.1 getAbsolutePath 未规范化（L3）— `.../path-canon/`
- `PathCanonVuln.java`：`new File(baseDir, userPath).getAbsolutePath()` 未 `toRealPath`/`getCanonicalPath`，`..` 未消解 → 穿越。CHECKPOINT `source=userPath sink=Files.write (getAbsolutePath not canonicalized) expect=VULN`。
- `PathCanonSafe.java`：`toRealPath()` + 基目录前缀校验。CHECKPOINT `expect=SAFE`。

### 2.2 String.replace("..","") 单次过滤绕过（L2）— `.../replace-once/`
- `ReplaceOnceVuln.java`：`path.replace("..","")` 被 `....//` → `../` 绕过。CHECKPOINT `source=userPath sink=Files.write (replace("..","") single-pass bypass) expect=VULN`。
- `ReplaceOnceSafe.java`：正则白名单 + canonical。CHECKPOINT `expect=SAFE`。
- 区别现有：`taint-variants/BlacklistBypassXss`(XSS 版 replace 绕过) 已覆盖，本项是路径穿越版（同类陷阱不同 sink）。

### 2.3 双重 URL 解码绕过（L3）— `.../double-decode/`
- `DoubleDecodeVuln.java`：校验在第一次 `URLDecoder.decode` 后过白名单，下游再 decode 一次还原 `../`（`%252e%252e`）。CHECKPOINT `source=userPath sink=Files.write (double URL-decode) expect=VULN trace=...:decode1,...:decode2`。
- `DoubleDecodeSafe.java`：先 canonicalize 到最终形态再一次性校验。CHECKPOINT `expect=SAFE`。

### 2.4 重定向 startsWith 域名绕过（CWE-601, L2）— `.../redirect-prefix/`（补强，现有 src 段无 checkpoint）
- `RedirectStartsWithVuln.java`：`url.startsWith("https://trusted.example/")` 被 `https://trusted.example.com.evil.com` 绕过。CHECKPOINT `source=userUrl sink=sendRedirect (startsWith domain bypass) expect=VULN`。
- `RedirectStartsWithSafe.java`：解析 host 精确匹配白名单。CHECKPOINT `expect=SAFE`。

---

## Phase 3 — 数值/业务语义陷阱（CWE-190/682，现有仅有通用整数溢出/BigDecimal 对照）

### 3.1 int 溢出绕余额校验（CWE-190, L3）— `.../int-overflow/`
- `QtyOverflowVuln.java`：`int total = price * qty` 溢出（qty=Integer.MAX_VALUE）绕总额上限。CHECKPOINT `source=qty sink=charge(total) (integer overflow) expect=VULN`。
- `QtyOverflowSafe.java`：`Math.multiplyExact`/`long` + 范围校验。CHECKPOINT `expect=SAFE`。

### 3.2 double 存金额 + == 比较（CWE-682, L2）— `.../float-money/`
- `FloatMoneyVuln.java`：`double balance; if (balance == expected)` 精度误差导致误判。CHECKPOINT `source=balance sink=balance comparison (double ==) expect=VULN`。
- `FloatMoneySafe.java`：`BigDecimal` 比较。CHECKPOINT `expect=SAFE`。

### 3.3 String.compareTo 字典序比金额（CWE-682, L2）— `.../compareto-amount/`
- `CompareToAmountVuln.java`：`a.compareTo(b) > 0` 当字符串金额 `"9" > "10"` 字典序错误。CHECKPOINT `source=amountStr sink=amount compare (lexicographic compareTo) expect=VULN`。
- `CompareToAmountSafe.java`：`BigDecimal.compareTo`。CHECKPOINT `expect=SAFE`。

---

## Phase 4 — 认证/授权/资源 缺口

### 4.1 HPP 重复绑定 roles 提权（CWE-915/269, L4）— `.../hpp-mass-assign/`
- `HppRoleBindingVuln.java`：`roles=USER&roles=ADMIN` 被框架绑定为数组，取最后一个 → ADMIN。CHECKPOINT `source=roles (repeated param) sink=setRoles(bound list) expect=VULN`。
- `HppExplicitDtoSafe.java`：`@RequestParam` 单一取值 / 忽略重复。CHECKPOINT `expect=SAFE`。

### 4.2 OAuth 缺 state 账号绑定 CSRF（CWE-352, L4）— `.../oauth-csrf/`
- `OAuthStateVuln.java`：回调 `callback?code=...` 无 `state` 参数 → 攻击者预生成绑定自己账号的 flow，受害者访问即绑定。CHECKPOINT `source=oauth callback sink=bindAccount (no state CSRF) expect=VULN`。
- `OAuthStateSafe.java`：校验 `state` 与会话绑定。CHECKPOINT `expect=SAFE`。

### 4.3 上传不限大小落盘（CWE-400, L1）— `.../upload-size/`
- `UploadNoSizeLimitVuln.java`：输入流不限大小直接落盘。CHECKPOINT `source=uploadStream sink=Files.copy (no size limit) expect=VULN`。
- `UploadSizeLimitSafe.java`：计数限额 + 拒绝超限。CHECKPOINT `expect=SAFE`。

### 4.4 Zip Bomb（CWE-409, L2）— `.../zip-bomb/`
- `ZipBombVuln.java`：解压不校验条目大小/压缩比。CHECKPOINT `source=zipBytes sink=ZipInputStream entries (no ratio check) expect=VULN`。
- `ZipBombSafe.java`：校验未压缩大小上限。CHECKPOINT `expect=SAFE`。

### 4.5 Billion Laughs 实体扩展（CWE-776, L2）— `.../xml-dos/`
- `XmlBombVuln.java`：XML 含内部 `<!ENTITY>` 递归展开，未禁 DTD。CHECKPOINT `source=xml sink=XML parse (entity expansion) expect=VULN`。
- `XmlBombSafe.java`：`setEntityExpansionLimit(0)` / 禁 DTD。CHECKPOINT `expect=SAFE`。

### 4.6 无界队列 OOM（CWE-400/770, L2）— `.../unbounded-queue/`
- `UnboundedQueueVuln.java`：`LinkedBlockingQueue` 无容量上限，用户触发任务堆积。CHECKPOINT `source=task sink=queue.put (unbounded) expect=VULN`。
- `UnboundedQueueSafe.java`：有界队列 + 拒绝策略。CHECKPOINT `expect=SAFE`。

---

## Phase 5 — 隐式传播 / 框架语义 缺口（CWE-917/78/22/918/1336）

### 5.1 CompletableFuture 异步 SpEL 求值（CWE-917, L3）— `.../async-taint/`
- `AsyncTaintVuln.java`：`CompletableFuture.supplyAsync(() -> parseExpression(tainted))` lambda 捕获污点异步求值。CHECKPOINT `source=tainted sink=SpEL.parseExpression (in async lambda) expect=VULN`。
- `AsyncTaintSafe.java`：异步内对常量求值。CHECKPOINT `expect=SAFE`。
- 区别现有：`taint-variants/StreamPropagation`(Stream.forEach) 已覆盖，本项是 CompletableFuture 异步线程变体。

### 5.2 三元运算符拼命令（CWE-78, L2）— `.../ternary-dispatch/`
- `TernaryVuln.java`：三元按攻击者可控布尔选分支拼命令 `exec(flag ? "rm "+x : "ls")` 仍拼接污点。CHECKPOINT `source=x sink=Runtime.exec (ternary concat) expect=VULN`。
- `TernarySafe.java`：两分支均参数化。CHECKPOINT `expect=SAFE`。

### 5.3 catch 块拼可控异常消息入命令（CWE-78, L3）— `.../exception-path-exec/`
- `ExceptionExecVuln.java`：catch 块把 `e.getMessage()`（攻击者可控，如异常含输入）拼进命令。CHECKPOINT `source=e.getMessage() sink=Runtime.exec (in catch) expect=VULN`。
- `ExceptionExecSafe.java`：catch 内固定命令。CHECKPOINT `expect=SAFE`。

### 5.4 循环 StringBuilder 累积入 sink（CWE-78, L3）— `.../loop-taint/`
- `LoopTaintVuln.java`：for 循环把多个不可信片段 `sb.append(part)` 累积后 `exec(sb.toString())`。CHECKPOINT `source=parts[] sink=Runtime.exec (loop-accumulated) expect=VULN trace=...:loop,...:exec`。
- `LoopTaintSafe.java`：循环内逐段白名单校验。CHECKPOINT `expect=SAFE`。

### 5.5 静态字段跨类污点（CWE-89, L3）— `.../static-taint/`
- `StaticTaintVuln.java`：污点写入 `public static String T;` 另一类读取后拼 SQL。CHECKPOINT `source=static field T sink=jdbcTemplate (cross-class static taint) expect=VULN`。
- `StaticTaintSafe.java`：读取后参数化。CHECKPOINT `expect=SAFE`。

### 5.6 SSRF 302 跳转跟随绕过（CWE-918, L3）— `.../ssrf-redirect/`
- `SsrfRedirectVuln.java`：对 userURL 做 host 白名单，但 `HttpURLConnection` 默认跟随 302 到内网。CHECKPOINT `source=userUrl sink=openConnection (follows 302 to intranet) expect=VULN`。
- `SsrfRedirectSafe.java`：禁重定向或对每跳校验。CHECKPOINT `expect=SAFE`。
- 区别现有：`taint-variants/PrefixCheckSsrf`(前缀校验) 已覆盖，本项是「校验后跟随跳转」绕过。

### 5.7 SSRF DNS 重绑定 TOCTOU（CWE-918, L4）— `.../ssrf-toctou/`
- `SsrfRebindVuln.java`：先 `InetAddress.getByName(host)` 校验 IP 非内网，再按 `host` 重连 → DNS 重绑定窗口。CHECKPOINT `source=host sink=openConnection (DNS rebind TOCTOU) expect=VULN trace=...:resolve,...:connect`。
- `SsrfRebindSafe.java`：解析后绑定 IP 连接（不用主机名二次解析）。CHECKPOINT `expect=SAFE`。

### 5.8 正则黑名单嵌套绕过 XSS（CWE-79, L2）— `.../regex-sanitize/`
- `RegexSanitizeVuln.java`：`replaceAll("(?i)script","")` 被 `<scr<script>ipt>` 嵌套绕过。CHECKPOINT `source=input sink=response output (nested regex bypass) expect=VULN`。
- `RegexSanitizeSafe.java`：HTML 实体编码。CHECKPOINT `expect=SAFE`。
- 区别现有：`taint-variants/BlacklistBypassXss`(单次 replace) 已覆盖，本项是 `replaceAll` 大小写/嵌套变体。

### 5.9 Spring Cloud Function Header 注入（CWE-917, L4）— `.../spring-cloud-func/`
- `SpringCloudFuncVuln.java`：路由表达式 Header（`spring.cloud.function.routing-expression`）注入 SpEL。CHECKPOINT `source=routing-expression header sink=SpEL.parseExpression expect=VULN`。
- `SpringCloudFuncSafe.java`：禁用 routing-expression / 固定路由。CHECKPOINT `expect=SAFE`。

### 5.10 @Query 外用户片段进 SpEL（CWE-917, L4）— `.../spring-data-spel/`
- `SpringDataSpelVuln.java`：`@Query("... ?#{#userInput} ...")` 外来源拼入 SpEL。CHECKPOINT `source=userInput sink=SpEL in @Query expect=VULN`。
- `SpringDataSpelSafe.java`：参数化 `@Query` 占位符。CHECKPOINT `expect=SAFE`。

### 5.11 GraphQL 别名/批处理爆破无限速（CWE-307/770, L3）— `.../graphql-brute/`
- `GraphqlAliasVuln.java`：别名批量发相同查询无速率限制 + 成本限制。CHECKPOINT `source=aliasedQueries sink=graphql execute (no rate/cost limit) expect=VULN`。
- `GraphqlAliasSafe.java`：别名数限制 + 速率限制。CHECKPOINT `expect=SAFE`。

---

## Phase 6 — 落地工程规范（每批必做，门禁）

1. 每个样本置于 `benchmark/cases/{vuln,sec}/<category>/`，package `com.jsef.benchmark.vuln` / `com.jsef.benchmark.sec`。
2. vuln 文件 sink 精确行上方加 `// [CHECKPOINT id=JSEF-NV-XXX cwe=<CWE> level=<Lx> source=... sink=... expect=VULN]`；L3+ 跨节点样本加 `trace=相对路径:行,...`。
3. sec 文件对应加 `expect=SAFE` 的 CHECKPOINT，类别与 vuln 一致（category 列）。
4. 把同一 id 的 **10 列**追加到 `benchmark/expectedresults.csv`：
   `id,cwe,level,type,file,line,source,sink,category,trace`
   - `line` = CHECKPOINT 实际行号（用 `grep -n` 确证）。
   - `type`/`expect` 对应：`vuln`↔`VULN`，`safe`↔`SAFE`。
   - sink/source 字段若含逗号，整字段用双引号包裹（**前次 TV 行因未加引号导致列数异常，务必先 `csv.writer` 写或手动加引号**）。
5. 自测：`python3 benchmark/scripts/validate_checkpoints.py --expected benchmark/expectedresults.csv --cases-dir benchmark/cases --src-dir src/main/java/com/freedom/securitysamples/vulnerability` **退出码必须为 0**。
6. 盲化复验：`python3 benchmark/scripts/blind.py` 后 grep 盲化输出，确认无 `Safe/Vuln/sec/vuln` 词素残留（P0-1 已修，新样本同理受益）。
7. 安全底线：仅 localhost 演示；桩方法用 `// 语义等价: ...` 注释声明真实 sink 语义（SAFE 侧按实现判安全）。

## 验收（每批完成后）
- [ ] 该批所有样本含 `// [CHECKPOINT]` 且行号精确
- [ ] `expectedresults.csv` 与注解双源一致（`validate_checkpoints.py` 退出码 0）
- [ ] 盲化输出无标签泄漏残留
- [ ] 新类别与现有 171 category 不重复（category 列命名唯一）

## 不实施项（已覆盖，明确排除）
二阶注入、JWT 未验签取 role、常量时间比较、stacktrace 泄露、明文口令、会话失效、密码重置 token、信任前端角色、水平越权、CORS 通配、速率限制、JDBC URL 注入、Jackson 多态、数组 sh -c RCE、WrongVarSanitized、Optional/Stream 传播、SQL IN 数值拼接、路径穿越直连/拼接/zip-slip —— 均已有等价样本，不重复补充。
