# Vulnerability Cases in JSEF

This document provides a comprehensive list of all vulnerability examples implemented in the Java Security Education Framework (JSEF), categorized for easier navigation and study. Each entry represents a unique security flaw, often accompanied by both insecure and secure code implementations.

---

## 📋 Vulnerability Cases Classification (35+ Full List)

### 1. 注入类漏洞（Injection）
- SQL注入：基础拼接注入、报错注入、盲注、预编译对比实例
- 命令注入：Runtime.exec()滥用、ProcessBuilder注入场景
- 模板注入：FreeMarker/Thymeleaf/Velocity注入案例
- SPEL注入：Spring表达式注入漏洞与防御
- XSS：反射型XSS、存储型XSS、DOM型XSS（含CSP防御演示）
- LDAP注入：目录服务查询注入场景与防御
- XML外部实体（XXE）：XML解析器配置不当导致的信息泄露

### 2. 认证与授权漏洞（Broken Authentication）
- 身份认证绕过：Cookie伪造、Session固定攻击
- 越权访问：水平越权（用户间数据访问）、垂直越权（低权限访问管理员接口）
- 弱口令风险：明文密码验证、密码复杂度绕过
- JWT漏洞：签名绕过、过期时间篡改、密钥泄露
- 会话管理缺陷：会话超时设置不当、会话ID暴露

### 3. 敏感信息泄露（Sensitive Data Exposure）
- 明文传输：HTTP未加密导致Cookie/Token泄露
- 错误页面泄露：堆栈信息暴露、配置信息泄露
- 日志泄露：敏感数据（手机号、身份证）明文打印日志
- 第三方依赖泄露：依赖组件版本暴露（含CVE-2023-20860等案例）
- 密码存储不当：明文存储、弱哈希算法（MD5/SHA1）使用

### 4. 不安全的配置（Security Misconfiguration）
- 数值与日期输入验证不当：超大数值DoS、格式模糊性风险
- 默认密码风险：管理员默认密码未修改
- 不安全HTTP方法：允许PUT/DELETE方法未授权访问
- CORS配置不当：跨域资源共享权限过度开放
- 缓存机制漏洞：敏感页面被缓存导致信息泄露
- 安全响应头缺失：缺失CSP、X-Frame-Options等防护头

### 5. 其他高危漏洞
- 竞态条件（Race Condition）：并发操作导致数据不一致
- 哈希碰撞攻击（Hash Collision Attack）：HashMap性能退化DoS
- 文件上传漏洞：后缀名绕过、MIME类型伪造、文件内容解析漏洞
- 路径遍历：目录穿越读取系统文件（如/etc/passwd）
- 反序列化漏洞：Jackson/Gson反序列化远程代码执行
- 依赖混淆：供应链攻击演示（含依赖劫持案例）
- 服务器端请求伪造（SSRF）：内部服务访问与数据窃取
- 反序列化漏洞：Redisson反序列化漏洞（CVE-2023-42809）
- 反序列化漏洞：Spring AMQP反序列化漏洞（CVE-2023-34050）
- 反序列化漏洞：Java序列化/反序列化机制滥用

**注意：** 某些CVE，如CVE-2023-34034 (Spring WebFlux授权绕过) 和 CVE-2023-44487 (HTTP/2快速重置攻击)，由于其依赖于Spring WebFlux框架或属于低级别网络协议问题，与本项目Spring MVC的应用场景不符，或难以在简单控制器中演示，因此仅作记录，未实现具体的教程案例。
