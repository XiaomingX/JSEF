# Java 漏洞 Benchmark / 靶场竞品分析报告

> 调研对象：5 个著名 Java 漏洞 benchmark / 靶场项目
> 调研方式：WebSearch / WebFetch（不 clone 仓库），聚焦漏洞类别与 CWE 映射
> 目标读者：JSEF 维护者 / SAST 评测设计者
> 报告日期：2026-08-16

---

## 0. 摘要（TL;DR）

| 项目 | 定位 | 总 case 量级 | 偏 SAST 还是 DAST |
|------|------|--------------|-------------------|
| OWASP BenchmarkJava | 经典可运行 SAST/DAST 评分基准，真实可利用 | 2,740（v1.2） | **双栖，偏 SAST 评分** |
| java-sec-code | Spring Boot 常见漏洞教学集合（含修复） | ~40 类单点 demo | 偏教学/DAST 验证 |
| JavaSecLab | 综合靶场，含缺陷+修复+Source/Sink 审计点 | 7 大模块多场景 | 偏审计/工具评测 |
| micro_service_seclab | 专为 SAST 漏报/误报测试设计的 SpringBoot 靶场 | 5 大类（重点难点场景） | **强偏 SAST** |
| WebGoat | OWASP 官方交互式教学应用 | 数十个课程 | 偏教学/DAST 交互 |

JSEF 当前已有 **503 条 checkpoint（367 vuln 样本视角）**，CWE 覆盖广（502×69、917×63、89×33、78×23、285×22…）。
**相对竞品，JSEF 最缺的独特高质量类别**：业务逻辑/越权类（IDOR/CWE-639、缺失功能级访问控制/CWE-862、并发竞争）、凭据/会话类（JWT/CWE-347、会话管理）、HTTP 协议类（CRLF/响应拆分 CWE-113、SSRF CWE-918、开放重定向 CWE-601）、弱配置类（弱加密 CWE-327/328、弱随机 CWE-330、Cookie 标志 CWE-614、信任边界 CWE-501）、组件生态（Fastjson 之外如 Log4j2 JNDI、Shiro、XStream、Jackson、SnakeYAML）。

---

## 1. OWASP BenchmarkJava

### 项目定位
可运行的 Java Web 测试套件，专门用来量化 SAST/DAST/IAST 工具的**速度与准确性（TP/FN/FP/TN）**，每个 case 均为真实可利用的真漏洞或安全对照。

### 漏洞类别清单（CWE → 数量 → 典型场景）
v1.2 共 **2,740** 个测试 case，覆盖 11 个 CWE 区域（每个 area 约一半为 vuln、一半为 safe 对照）：

| 类别 | CWE | v1.2 case 数 | 典型场景 |
|------|-----|--------------|----------|
| SQL Injection | CWE-89 | 504 | 拼接 SQL 到 Statement/PreparedStatement |
| Weak Randomness | CWE-330 | 493 | Random 生成 token/验证码/IV |
| XSS | CWE-79 | 455 | 未编码输出到 HTML/JS |
| Weak Cryptography | CWE-327 | 246 | DES/ECB 等弱对称加密 |
| Path Traversal | CWE-22 | 268 | 用户输入拼文件路径 |
| Weak Hashing | CWE-328 | 236 | MD5/SHA1 哈希口令 |
| Trust Boundary Violation | CWE-501 | 126 | 把不可信数据存 HttpSession 当可信 |
| Secure Cookie Flag 缺失 | CWE-614 | 67 | Cookie 无 secure/httpOnly |
| LDAP Injection | CWE-90 | 59 | 拼接 LDAP search filter |
| XPATH Injection | CWE-643 | 35 | 拼接 XPath 表达式 |
| Command Injection | CWE-78 | 251 | Runtime.exec 拼接命令 |

### SAST 可评测性
- **全部 11 类均高质量、SAST 可评测**：source→sink 单一清晰（每个 case 是一个独立 Servlet 方法），污点流极短，非常适合加 checkpoint。
- 设计上就是为 SAST 评分而生（提供 expectedresults，可算 recall/precision），**无偏 DAST/运行时专属类别**。
- 用户提示中猜的 "Privilege Escalation(732/269)、HTTP Response Splitting(113)、Log Forging(117)" **当前版本并未包含**——这是 BenchmarkJava 的已知缺口。

### 对 JSEF 最具补充价值的建议
1. **CWE-330 弱随机性**（JSEF 仅 4 条）——BenchmarkJava 有 493 条，可大幅扩充难度梯度。
2. **CWE-327/328 弱加密/弱哈希**（JSEF 各 7 条）——可补 ECB/DES/MD5 多 sink 场景。
3. **CWE-501 信任边界**（JSEF 仅 2 条）——BenchmarkJava 126 条，是 JSEF 明显短板。
4. **CWE-614 Cookie 标志**（JSEF 仅 2 条）——可补 secure/httpOnly 多配置点。

---

## 2. java-sec-code (JoyChou93)

### 项目定位
基于 Spring Boot + Spring Security 的 Java 常见漏洞教学集合，每个漏洞默认带不安全代码 + 注释/对照修复，覆盖广、偏实战教学与 DAST 验证。

### 漏洞类别清单（类别 → CWE → 难度/场景）
| 类别 | CWE（近似） | 典型场景 |
|------|-------------|----------|
| CommandInject / RCE（Runtime/ProcessBuilder/ScriptEngine/Yaml/Groovy） | 78 / 94 | 命令执行多种 sink |
| SQL Injection（MyBatis） | 89 | 拼接 SQL |
| XSS | 79 | 未编码输出 |
| SSRF | 918 | 内网请求伪造 |
| XXE / ooxmlXXE / xlsxStreamerXXE | 611 / 776 | DOM/SAX + POI 组件 XXE |
| SpEL | 917 | Spring 表达式注入 |
| SSTI | 1336 | 模板引擎注入 |
| Deserialize（原生）/ XStream / Fastjson / Yaml | 502 / 502 | 反序列化链 |
| JWT | 347 | 令牌伪造/弱密钥 |
| URL Redirect / URL 白名单绕过 | 601 | 开放重定向 |
| CORS / JSONP | 942 / 352 | 跨域配置错误 |
| CRLF Injection | 93 | 响应头注入 |
| CSRF | 352 | 跨站请求伪造 |
| PathTraversal | 22 | 路径遍历 |
| File Upload | 434 | 上传 webshell |
| Shiro / QLExpress / Log4j | 502 / 94 | 组件/表达式注入 |
| Actuators to RCE / Swagger | 配置暴露 | 端点暴露 |
| GetRequestURI / IP Forge | 逻辑缺陷 | 鉴权绕过/IP 伪造 |
| Java RMI | 传输层 | RMI 反序列化 |
| CVE-2022-22978（Spring 正则鉴权绕过） | 285 | 授权绕过 |

### SAST 可评测性
- **SAST 清晰可评测**：SQLi、XSS、SSRF、XXE、SpEL、SSTI、反序列化、命令注入、CRLF、PathTraversal、URL Redirect——污点流清楚，可加 checkpoint。
- **偏 DAST/运行时验证**：JWT 伪造、CSRF、CORS、Actuator 暴露、验证码绕过、IP 伪造更多是"运行时交互/配置验证"，SAST 难以单点命中，建议作为对照（safe 校验或低 level）。
- 多为**单点 demo**（一个 endpoint 一个漏洞），缺少 BenchmarkJava 那种成规模 safe/vuln 对照对。

### 对 JSEF 最具补充价值的建议
1. **CWE-918 SSRF**（JSEF 当前 CSV 未见）→ 直接补齐 url.openConnection/HttpClient/OkHttp 多 sink。
2. **CWE-601 开放重定向**（JSEF 仅 1 条左右）→ 补 URL Redirect + 白名单绕过。
3. **CWE-93 CRLF / 响应头注入**（JSEF 仅 3 条）→ 补 CRLF 多场景。
4. **组件生态**：Shiro(502)、QLExpress(94)、Log4j2 JNDI(917) → JSEF 已有 Fastjson，可补同类。
5. **CWE-347 JWT 令牌攻击**（JSEF 缺失）→ 补 alg=none / 弱密钥。

---

## 3. JavaSecLab (whgojp)

### 项目定位
基于 Spring Boot 的综合 Java 漏洞平台，提供**漏洞代码 + 修复代码 + 面向审计的 Source/Sink 注释**，专用于代码审计练习、安全开发培训与安全工具评测。

### 漏洞模块分类（模块 → 类别 → CWE 近似）
| 模块 | 具体漏洞 | CWE 近似 |
|------|----------|----------|
| 基础 Web | XSS, CSRF, CORS, JSONP, URL 重定向, XFF 欺骗, DoS, XPath 注入 | 79/352/942/601/348/400/643 |
| 注入与文件 | SQLi(含时间盲注), 任意文件读/上传/下载/删除, SSRF, XXE, RCE | 89/22/434/918/611/78 |
| 业务逻辑 | IDOR 越权, 验证码安全, 支付安全, 并发安全 | 639/863/362 |
| 敏感信息/凭证 | 信息泄露, 登录对抗, 请求签名, JWT 凭证 | 200/307/347 |
| 表达式/模板 | SpEL, SSTI, Java 反序列化 | 917/1336/502 |
| 组件生态 | Fastjson, Jackson, XStream, Log4j2, Shiro, SnakeYAML, XMLDecoder | 502/502/502/917/502/502 |
| Spring Boot 暴露 | Swagger, Actuator, Druid, MySQL JDBC 反序列化 | 配置暴露/502 |

每个模块默认都有 vulnerable + fixed 对照、source/sink 审计注释。

### SAST 可评测性
- **高质量 SAST 可评测**：注入类（SQLi/SSRF/XXE/RCE/SpEL/SSTI/反序列化）、XSS、PathTraversal、XPath 污点流清晰，且项目自带 source/sink 注释，**与 JSEF checkpoint 理念高度契合**。
- **偏审计/业务验证**：IDOR、验证码、支付、并发、JWT、会话管理、信息泄露更多是**业务逻辑/状态验证**，SAST 单点命中难，但 source 是对象 ID、sink 是数据返回，**可设计 L3-L4 跨方法 checkpoint**。
- 模块化的修复对照非常适合 JSEF 的 vuln/sec 双包结构。

### 对 JSEF 最具补充价值的建议
1. **业务逻辑类（IDOR CWE-639 / 缺失功能级访问控制 CWE-862 / 并发 CWE-362）** —— JSEF 几乎空白，是最大缺口。
2. **JWT / 会话管理（CWE-347/613）** —— JSEF 缺失。
3. **组件生态扩展**（Log4j2 JNDI、Shiro、XStream、Jackson、SnakeYAML）—— 在 Fastjson 之外补同类难点。
4. **信息泄露 / 请求签名（CWE-200/345）** —— SAST 可作为弱告警类补入。

---

## 4. micro_service_seclab (l4yn3 / Drun1baby)

### 项目定位
基于 Spring Boot 的 Java 漏洞靶场，**专为检测 SAST 工具准确性（漏报 FN / 误报 FP）而设计**，预置"埋点"漏洞，可对比 CodeQL/CheckMarx/Fortify 结果，是 5 个里**最偏 SAST** 的项目。

### 支持的漏洞与大类
| # | 大类 | 子场景（针对 SAST 难点的设计） | CWE |
|---|------|-------------------------------|-----|
| 1 | SQL 注入 | String Source / `List<Long>`（**测误报**）/ `Optional<String>` / `List<String>` / Object Source / MyBatis XML 分离 / In / Like / Lombok / MyBatis 注解 / Spring Data JPA | 89 |
| 2 | RCE 命令执行 | processBuilder / Runtime.getRuntime().exec | 78 |
| 3 | FastJson 反序列化 | 1.2.31 版本点（autotype） | 502 |
| 4 | SSRF | url.openConnection() / Request.Get() / OkHttpClient / DefaultHttpClient / url.openStream() | 918 |
| 5 | XXE | DocumentBuilderFactory | 611 |
| 6 | 反序列化 | 持续添加中 | 502 |
| 7 | 逻辑漏洞 | 添加中 | 639 等 |

### SAST 可评测性
- **全部类别均为 SAST 评测场景**，且刻意设计了**难静态分析**的情形：
  - 泛型/包装类型 source（`List<Long>` 应为 safe，测工具误报；`List<String>` 应为 vuln，测工具漏报）
  - 新语法 `Optional<String>`、Lombok 生成代码、MyBatis 注解/XML 分离 SQL、Spring Data JPA 方法名派生查询
  - 多 sink 的 SSRF（不同 HTTP 客户端库）
- 这是 5 个项目中**唯一系统化构造"safe 误报对照"**的，对 JSEF 的 `expect=SAFE` 对照样本设计极具参考价值。

### 对 JSEF 最具补充价值的建议
1. **泛型/包装类型 source 的误报对照（CWE-89/78）** —— JSEF 缺"看似 sink 实为安全类型"的混淆样本，可大幅提升 FP/TN 评测精度。
2. **ORM/框架语义难点**：MyBatis 注解、XML 分离、JPA 方法名查询、Lombok —— JSEF 的 L4 框架语义可补这些真实场景。
3. **多 sink SSRF（CWE-918）** —— 不同 HTTP 库同一污点，补多 checkpoint。
4. **`Optional<T>` 等新语法污染源** —— 测现代 Java 语法的 SAST 覆盖。

---

## 5. WebGoat (OWASP 官方)

### 项目定位
OWASP 官方交互式 Web 安全教学应用，以**课程(Lesson)形式**逐关演示漏洞原理与修复，偏教学/DAST 交互验证，非 SAST 评分基准。

### 课程/漏洞类别（类别 → CWE 近似）
| 类别 | CWE 近似 | 备注 |
|------|----------|------|
| SQL Injection (基础/高级/缓解) | 89 | Union/盲注/CASE 缓解 |
| XXE | 611 | 读本地文件/外带 DTD |
| Authentication Bypass | 287/285 | 改参数名绕过 |
| JWT tokens | 347 | alg=none/删签名/提权 |
| Password reset 攻击 | 640 | 用户名枚举/暴力 |
| XSS (反射/DOM/存储) | 79 | 多 lesson |
| IDOR | 639 | 篡改他人 profile |
| Missing Function Level Access Control | 862 | 隐藏菜单/改 Accept 头 |
| Insecure Login / 明文凭据 | 319 | 抓包看明文 |
| Insecure Deserialization | 502 | Java 序列化 payload |
| CSRF | 352 | 自动提交表单/JSON 绕过 |
| Vulnerable Components | 1104 | 点击/XML 注入 PoC |
| 绕过前端限制 / Client Side Filtering | 602/639 | 响应含全量数据 |
| HTML Tampering | 472 | 改隐藏 input 价格 |
| 各类 Challenge（无密码登录/无账户投票/管理员密码重置） | 287/639 | 综合 |

> 注：用户提示的点 Path Traversal、Session Management 在 WebGoat 8 中未作为独立课程出现（文件读散落在 XXE 中），但其他均覆盖。

### SAST 可评测性
- **SAST 清晰可评测**：SQLi、XXE、XSS、反序列化、CSRF、CRLF 等"代码层"漏洞污点流清楚。
- **偏 DAST/交互验证**：认证绕过、JWT、IDOR、功能级访问控制、客户端过滤、HTML 篡改、密码重置——**高度依赖运行时交互与业务状态**，SAST 难以单点命中，但 IDOR/功能级访问控制可设计 L3-L4 跨方法 checkpoint。
- 本质是教学关卡，**不适合直接当作 SAST 评分基准**（无成规模 safe/vuln 对照集）。

### 对 JSEF 最具补充价值的建议
1. **CWE-639 IDOR / CWE-862 缺失功能级访问控制** —— JSEF 几乎空白，WebGoat 课程结构清晰可借鉴。
2. **CWE-347 JWT 攻击** —— 补 alg=none / 弱密钥 / 提权场景。
3. **CWE-640 密码重置 / CWE-319 明文凭据** —— 补"认证与凭据"类缺口。
4. **CWE-472/602 客户端过滤/HTML 篡改** —— 补"前端信任"类逻辑漏洞。

---

## 6. 跨项目对比：共性缺口 & 对 JSEF 的优先级建议

### 6.1 五个竞品共同覆盖、而 JSEF 相对薄弱的类别
| 类别 | CWE | JSEF 现状 | 竞品覆盖 |
|------|-----|-----------|----------|
| SSRF | 918 | 缺失 | java-sec-code / JavaSecLab / micro / WebGoat |
| 开放重定向 | 601 | 极少 | java-sec-code / JavaSecLab |
| CRLF / 响应拆分 | 93/113 | 3 条 | java-sec-code |
| JWT 令牌攻击 | 347 | 缺失 | java-sec-code / JavaSecLab / WebGoat |
| IDOR 越权 | 639 | 缺失 | JavaSecLab / WebGoat |
| 缺失功能级访问控制 | 862 | 缺失 | JavaSecLab / WebGoat |
| 并发竞争 | 362 | 缺失 | JavaSecLab |
| 弱随机性 | 330 | 4 条 | BenchmarkJava(493) |
| 弱加密/弱哈希 | 327/328 | 各 7 条 | BenchmarkJava(246/236) |
| 信任边界 | 501 | 2 条 | BenchmarkJava(126) |
| Cookie 标志 | 614 | 2 条 | BenchmarkJava(67) |
| 会话管理 | 613 | 缺失 | JavaSecLab / WebGoat |
| 组件生态(非Fastjson) | 502/917 | 仅 Fastjson/Log4j | java-sec-code / JavaSecLab(Log4j2/Shiro/XStream/Jackson/SnakeYAML) |

### 6.2 JSEF 已有、但竞品可能更强的维度
- **反序列化(502)×69 / XSS(917)×63 / SQLi(89)×33 / 命令注入(78)×23** —— JSEF 数量已远超多数竞品的单类规模，且带 L1-L5 难度梯度与 trace 证据链，是 JSEF 的**优势护城河**。
- **checkpoint 双源校验 + scorecard** —— 竞品中只有 micro_service_seclab 有类似"埋点对照"思路，JSEF 的 `// [CHECKPOINT]` + CSV 机器可读门禁是独特设计。

### 6.3 建议优先补充的"独特高质量类别"（按价值排序）
1. **业务逻辑/越权三件套：IDOR(CWE-639)、缺失功能级访问控制(CWE-862)、并发竞争(CWE-362)** —— 五个竞品均强调、JSEF 几乎空白，且可设计 L3-L4 跨方法 checkpoint，区分度高。
2. **凭据/会话类：JWT(CWE-347)、会话管理(CWE-613)、密码重置(CWE-640)、明文凭据(CWE-319)** —— WebGoat/JavaSecLab 重点，JSEF 缺失。
3. **HTTP 协议类：SSRF(CWE-918)、开放重定向(CWE-601)、CRLF/响应拆分(CWE-93/113)** —— 多个竞品覆盖，JSEF 缺失或极少；污点流清晰，SAST 友好。
4. **弱配置类：弱随机(CWE-330)、弱加密/哈希(327/328)、Cookie标志(614)、信任边界(501)** —— BenchmarkJava 的强项（成百上千 case），JSEF 仅有零星样本，可规模化补齐并做 safe/vuln 对照对。
5. **组件生态扩展：Log4j2 JNDI、Shiro、XStream、Jackson、SnakeYAML** —— 在已有 Fastjson 基础上补齐同类第三方库反序列化/注入难点（借鉴 JavaSecLab 模块）。

### 6.4 借鉴 micro_service_seclab 的"误报对照"设计
JSEF 当前 `expect=SAFE` 样本偏少。建议引入：
- 泛型/包装类型 source（`List<Long>`、`Optional<String>`）应为 SAFE，专门测 SAST 误报；
- Lombok/MyBatis 注解/JPA 方法名查询的框架语义混淆样本；
- 多 HTTP 客户端库的同一 SSRF 污点（多 checkpoint）。

---

## 7. 结论

JSEF 在**单点注入类（SQLi/XSS/CMDi/反序列化/SpEL）已具规模优势与独特 checkpoint 门禁**；相对 5 个竞品，最显著的**独特高质量缺口**集中在：
- 业务逻辑/越权（IDOR、功能级访问控制、并发）
- 凭据/会话（JWT、会话管理、密码重置）
- HTTP 协议（SSRF、开放重定向、CRLF）
- 弱配置规模化（弱随机/加密/哈希/Cookie/信任边界）
- 组件生态扩展（Log4j2/Shiro/XStream/Jackson/SnakeYAML）
- SAST 误报对照样本（泛型/框架语义混淆）

以上类别污点流清晰、可加 `// [CHECKPOINT]` 与 CSV 同步，符合 JSEF 门禁要求，建议按 6.3 优先级逐步移植。

---

*本报告仅基于公开 Web 资料整理，未 clone 任何竞品仓库、未修改 JSEF 任何源码或 CSV。CWE 编号为近似映射，实际移植时需以源码污点流为准。*
