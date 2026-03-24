# Java Security Education Framework (JSEF) - Spring Boot 安全实践平台
[![GitHub Stars](https://img.shields.io/github/stars/XiaomingX/JSEF?style=social&label=Star%20This%20Repo)](https://github.com/XiaomingX/JSEF)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Java Version](https://img.shields.io/badge/Java-17%2B-blue.svg)](https://www.oracle.com/java/technologies/downloads/#java17)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-orange.svg)](https://spring.io/projects/spring-boot)
[![Docker Ready](https://img.shields.io/badge/Docker-Supported-blue.svg)](docs/docker-deployment.md)

> 一款**可复现、可实操、可学习**的Spring Boot Web安全实验框架，助力开发者快速掌握Web安全漏洞原理与防御方案。


## 📖 项目简介
**Java Security Education Framework (JSEF)** 是基于Spring Boot 3.x构建的Web安全实践平台，专为**开发者、安全研究员、高校学生及企业培训**设计。通过**35+种真实业务场景下的安全漏洞实例**（含注入攻击、越权访问、敏感信息泄露等核心类型），提供“**原理讲解→漏洞复现→代码对比→修复验证**”的完整学习闭环，帮助学习者从“理论”到“实战”快速掌握Web安全核心能力。

本项目不依赖复杂环境，支持本地一键启动与Docker部署，所有漏洞案例均基于真实业务逻辑设计，避免“为了漏洞而漏洞”的演示性代码，更贴近实际开发场景。

**新结构说明：** 项目代码已重构，所有漏洞相关控制器现在位于 `com.freedom.securitysamples.vulnerability` 包下。每个漏洞类别内部进一步细分为 `vuln` (包含不安全/脆弱实现) 和 `sec` (包含安全/修复实现) 子包，便于直接对比学习。API 路由也已统一为 `/api/v1/{vulnerability-type}/unsafe/{scenario}` 和 `/api/v1/{vulnerability-type}/safe/{scenario}` 格式。


## 🔥 核心优势（为什么选择JSEF？）
| 优势                | 具体说明                                                                 |
|---------------------|--------------------------------------------------------------------------|
| **漏洞实例真实可复现** | 35+漏洞覆盖OWASP Top 10全类型，每个案例均模拟真实业务场景（如用户登录、数据查询、文件上传）。 |
| **学习闭环完整**     | 每个漏洞配套：原理文档+复现步骤+不安全代码+安全代码对比+防御最佳实践。         |
| **部署零门槛**       | 支持`mvn`一键启动、Docker容器化部署，无需手动配置数据库/中间件。             |
| **代码规范清晰**     | 采用Spring Boot最佳实践编码，漏洞代码与安全代码已按 `vuln`/`sec` 目录分离，便于对比学习。       |
| **资源生态丰富**     | 内置API文档、漏洞复现手册、安全编码规范，持续更新CVE最新漏洞案例。           |
| **高度可扩展**       | 提供插件化漏洞案例接口，支持开发者自定义新增漏洞场景或扩展防御方案。         |


## 🚀 快速开始
### 环境要求
- JDK 17 或更高版本
- Maven 3.6+ 或 Gradle 8.0+
- Git（可选，用于克隆仓库）
- Docker（可选，用于容器化部署）

### 方式1：本地Maven启动（推荐新手）
```bash
# 1. 克隆仓库（或直接下载ZIP包）
git clone --depth 1 https://github.com/XiaomingX/JSEF.git
cd JSEF

# 2. 构建项目（跳过测试加速构建）
mvn clean package -DskipTests

# 3. 启动服务
java -jar target/java-sec-code-plus-0.0.1-SNAPSHOT.jar
```

### 方式2：Docker一键部署
```bash
# 1. 构建镜像
docker build -t jsef-security-sample:latest .

# 2. 启动容器
docker run -d -p 8080:8080 --name jsef-demo jsef-security-sample:latest
```

### 验证部署成功
启动后访问以下地址：
- 项目首页：`http://localhost:8080`（查看项目导航与漏洞列表）
- API文档（Swagger）：`http://localhost:8080/swagger-ui/index.html`（查看所有漏洞接口详情）
- 漏洞手册：`http://localhost:8080/docs`（查看在线漏洞复现指南）


## 📋 漏洞案例分类（35+全列表）
关于所有已实现的漏洞案例的详细列表，请参阅 [VULNERABILITIES.md](VULNERABILITIES.md)。


## 🎯 适用场景
| 用户类型               | 适用场景                                                                 |
|------------------------|--------------------------------------------------------------------------|
| **开发工程师**         | 学习安全编码规范，避免在项目中写出存在漏洞的代码。                         |
| **安全研究员**         | 复现漏洞原理，验证防御方案有效性，开发安全工具的测试环境。                 |
| **高校师生**           | 信息安全/网络安全课程实验平台，替代传统演示性实验。                       |
| **企业培训**           | 开发团队安全编码培训、渗透测试团队入门实战练习。                           |
| **CTF选手**            | 基础漏洞实战练习，熟悉常见漏洞利用姿势。                                   |


## 📚 官方文档
- [📥 部署指南](docs/deployment.md)：本地/Mac/Linux/Windows/Docker部署全方案
- [🔍 漏洞复现手册](docs/vulnerability-guide.md)：每个漏洞的详细复现步骤（含Payload示例）
- [💻 API文档](docs/api-reference.md)：所有接口的请求参数、响应格式说明（支持Swagger在线调试）
- [🛡️ 安全编码规范](docs/secure-coding-guide.md)：基于Spring Boot的安全编码最佳实践
- [📌 新增漏洞指南](docs/contribute-vulnerability.md)：如何为项目新增漏洞案例
- [🎥 视频教程](https://github.com/XiaomingX/JSEF/wiki/Video-Tutorials)：B站配套漏洞复现视频（持续更新）


## 🤝 如何贡献
本项目欢迎所有形式的贡献，无论是**漏洞案例新增、文档完善、代码修复还是功能建议**，都能帮助更多人学习Web安全！

### 贡献方式
1. **提交Issue**：反馈漏洞、建议功能或报告Bug（推荐先搜索是否已有同类Issue）
2. **提交PR**：
   - 修复代码问题（如拼写错误、逻辑优化）
   - 新增漏洞案例（需遵循[新增漏洞指南](docs/contribute-vulnerability.md)）
   - 完善文档（如补充复现步骤、翻译英文文档）
3. **分享推广**：Star本项目、在技术社区分享使用体验，帮助更多人发现JSEF

### 新手友好贡献
- [Good First Issues](https://github.com/XiaomingX/JSEF/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)：适合新手的入门级任务（如文档补充、代码注释完善）


## 📄 开源许可
本项目基于 **MIT License** 开源，允许：
- 免费用于个人学习、企业培训及商业产品测试
- 修改、分发项目代码（需保留原作者版权声明）
- 基于本项目二次开发（需注明来源）

**禁止**：将本项目用于未经授权的渗透测试、恶意攻击等违法活动。


## ⭐ Star 历史
[![Star History Chart](https://api.star-history.com/svg?repos=XiaomingX/JSEF&type=Date)](https://star-history.com/#XiaomingX/JSEF&Date)


## 🙏 致谢
- 感谢[OWASP](https://owasp.org/)提供的Web安全标准与漏洞分类框架
- 感谢Spring社区提供的Spring Boot生态支持
- 感谢所有贡献者的代码提交与反馈（[Contributors](https://github.com/XiaomingX/JSEF/graphs/contributors)）
- 感谢安全社区技术博主的漏洞原理分享


## ⚠️ 免责声明
本项目仅用于**学习、研究及企业内部安全培训**，请勿用于任何未经授权的测试、攻击或破坏活动。使用本项目产生的一切法律责任，由使用者自行承担。