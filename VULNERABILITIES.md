# Vulnerability Cases in JSEF

This document provides a comprehensive list of all vulnerability examples implemented in the Java Security Education Framework (JSEF), categorized for easier navigation and study. Each entry represents a unique security flaw, often accompanied by both insecure and secure code implementations.

> 当前仓库共 **133 条**机器可读 `// [CHECKPOINT]` 标注（覆盖 `src/main` 现有漏洞 + `benchmark/cases` 梯度样本），其中 **93 个 VULN** + **40 个 SAFE**，跨 **34 类 CWE**。下方按漏洞家族列出已实现的代表性案例（非逐条穷举，完整清单见 `benchmark/expectedresults.csv`）。

---

## 📋 Vulnerability Cases Classification (覆盖 50+ 漏洞家族)

### 1. 注入类漏洞（Injection）
- SQL注入：基础拼接注入、多字段拼接、预编译对比实例（含混淆安全样本）
- 命令注入：Runtime.exec() 滥用、ProcessBuilder 注入、跨文件调用链污染
- 表达式/脚本引擎注入（表达式注入大家庭）：
  - SpEL 注入（含 Spring4Shell `class.module.classLoader` 框架语义专项）
  - Groovy 注入（GroovyShell / GroovyScriptEvaluator）
  - MVEL 注入（MVEL.eval / executeExpression）
  - BeanShell 注入（BshScriptEvaluator / Runtime.exec）
  - OGNL 注入（Ognl.getValue / Runtime.exec）
  - ScriptEngine 注入（ScriptEngine.eval / CompiledScript.eval）
  - JNDI 注入（InitialContext.lookup / RMI）
  - Log4j JNDI 注入（CVE-2021-44228 抽象）
- 模板注入：FreeMarker / Thymeleaf 视图名/内容拼接（CWE-1336）
- XSS：反射型 XSS（含混淆安全样本）
- LDAP注入：目录服务查询注入场景与防御
- XPath注入：XPath.compile / DOMXPath.selectNodes
- XML外部实体（XXE）：DocumentBuilder 未禁用 DTD 导致信息泄露（含安全配置对照）
- NoSQL注入：Spring Data Mongo 间接污点（CWE-943）
- 服务端请求伪造（SSRF）：内部服务访问与数据窃取（含内网 IP 白名单混淆 SAFE）

### 2. 认证与授权漏洞（Broken Authentication & Access Control）
- 身份认证绕过：Cookie/角色伪造、Session 缺失校验（CWE-287）
- 授权绕过 / 越权访问：水平越权、垂直越权（CWE-285）
- IDOR（不安全的直接对象引用）：对象归属语义缺失 + 已做归属校验的混淆 SAFE（CWE-639）
- 弱口令风险：明文密码验证、密码复杂度绕过（CWE-521）
- 默认凭证：管理员默认用户名/密码未修改（CWE-798）
- JWT漏洞：alg=none / 弱密钥 / 硬编码 + 宽松校验混淆（CWE-345）

### 3. 敏感信息泄露（Sensitive Data Exposure）
- 敏感数据直出：明文密码/身份证/信用卡返回响应体（CWE-532）
- 弱哈希存储：MD5/SHA1 明文密码哈希（CWE-327，含 PBKDF2 修复对照）
- 硬编码凭证/密钥：数据库连接硬编码、硬编码 AES 密钥（CWE-798 / CWE-798 ECB）
- 错误页面泄露 / 日志泄露：堆栈与配置信息暴露（教学示例）

### 4. 不安全的配置（Security Misconfiguration）
- 数值与日期输入验证不当：超大数值 DoS、格式模糊性风险（CWE-20）
- 默认密码风险（见第 2 节）
- 不安全 HTTP 方法 / 开放重定向：redirect Url 白名单缺失、`redirect:` 前缀绕过（CWE-601，含白名单 SAFE）
- CORS配置不当：Access-Control-Allow-Origin:* 跨域过度开放（CWE-942）
- 点击劫持 / 安全响应头缺失：缺失 X-Frame-Options / CSP（CWE-1021，含设头 SAFE）
- 限流缺失：短信 OTP 无频率限制（CWE-307，含限流 SAFE）

### 5. 反序列化与其他高危漏洞
- 反序列化漏洞（Java 原生）：ObjectInputStream.readObject、Jackson enableDefaultTyping、CC gadget chain（CWE-502，含 L5 gadget chain 专项）
- Fastjson 反序列化：JSON.parseObject / AutoType（CWE-502）
- Jackson 多态反序列化：@JsonTypeInfo 缺白名单（CWE-502，含 allowlist SAFE）
- YAML 反序列化：SnakeYAML load/loadAs（CWE-502）
- 依赖相关 CVE 专项：
  - Spring AMQP 反序列化（CVE-2023-34050，含 allowlist SAFE）
  - Redisson 反序列化（CVE-2023-42809，含 allowlist SAFE）
- 竞争条件（Race Condition）：非原子 read-modify-write（CWE-362，含 synchronized SAFE）
- 哈希碰撞攻击（Hash Collision）：HashMap 用户可控 key 性能退化 DoS（CWE-694，含 SHA-256 key SAFE）
- ReDoS：灾难性回溯正则 `(a+)+b`（CWE-1333）
- 路径遍历：目录穿越读取系统文件（CWE-22，含 Files.newInputStream SAFE）
- 批量赋值（Mass Assignment）：@RequestBody 绑定 isAdmin（CWE-915，含 DTO SAFE）
- JSONP 回调注入：callback 拼接脚本（CWE-352）
- 头注入：HttpHeaders.add 注入（CWE-113）
- 危险操作：sun.misc.Unsafe 任意内存读（CWE-111）
- 业务逻辑缺陷：余额篡改无符号校验、价格篡改、优惠券滥用、库存超卖（CWE-840，含优惠券 SAFE）

**注意：** 某些 CVE，如 CVE-2023-34034 (Spring WebFlux 授权绕过) 和 CVE-2023-44487 (HTTP/2 快速重置攻击)，由于其依赖于 Spring WebFlux 框架或属于低级别网络协议问题，与本项目 Spring MVC 的应用场景不符，或难以在简单控制器中演示，因此仅作记录，未实现具体的教程案例。
