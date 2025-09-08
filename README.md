# Java安全教育实验框架 (Java Security Education Framework)

[![GitHub Stars](https://img.shields.io/github/stars/zgimszhd61/java-sec-code-plus?style=social)](https://github.com/zgimszhd61/java-sec-code-plus)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)


## 📌 项目简介

一款基于SpringBoot的Web安全实践平台，专为开发者、安全研究员和学习者设计。通过35+种真实可复现的安全漏洞实例，帮助用户直观理解漏洞原理、复现方式及防御策略，实现"边学边练"的安全学习体验。


## ✨ 核心特色

- **漏洞覆盖全面**：包含35+种常见Web安全漏洞（注入类、认证授权、配置安全等）
- **即开即用**：简化部署流程，无需复杂配置，本地一键启动
- **学习闭环**：每个漏洞配套原理说明、复现步骤和修复方案
- **接口完备**：提供完整API文档，支持二次开发和扩展
- **资源丰富**：内置安全最佳实践指南和学习路径


## 🚀 快速开始

### 环境要求
- JDK 17 及以上
- Maven 3.6 及以上
- Git

### 本地部署步骤
```bash
# 克隆仓库
git clone --depth 1 https://github.com/XiaomingX/simple-springboot-app

# 进入项目目录
cd simple-springboot-app

# 构建项目
mvn install

# 启动服务
mvn spring-boot:run
```

服务启动后，访问 `http://localhost:8080/hi`，若显示欢迎页面则表示部署成功。


## 📋 功能模块

### 支持的漏洞类型
<details>
<summary>点击查看完整列表</summary>

1. **注入类漏洞**
   - SQL注入（含报错注入、盲注等场景）
   - 命令注入
   - SPEL注入
   - XSS（存储型/反射型/ DOM型）
   - CSRF

2. **认证与授权漏洞**
   - 身份认证绕过
   - 水平/垂直越权访问
   - 会话固定攻击
   - 弱口令验证

3. **配置安全问题**
   - 敏感信息泄露
   - 错误配置暴露
   - 默认密码风险
   - 不安全的HTTP方法

4. **其他常见漏洞**
   - 文件上传漏洞
   - 路径遍历
   - 反序列化漏洞
   - 依赖组件漏洞（CVE实例）
</details>


## 🎯 适用场景

- 企业安全研发团队培训
- 渗透测试入门学习
- 安全工具/产品功能验证
- 代码审计实战练习
- 高校/培训机构信息安全课程实践


## 📚 详细文档

- [部署指南](docs/deployment.md) - 包含Docker部署、服务器部署等方案
- [漏洞列表](docs/vulnerabilities.md) - 所有漏洞的详细原理和复现步骤
- [API文档](docs/api.md) - 接口说明及调用示例
- [最佳实践](docs/best-practices.md) - 漏洞防御方案和编码规范


## 🤝 如何贡献

我们欢迎任何形式的贡献：
- 提交漏洞报告或功能建议
- 完善文档内容
- 修复代码问题
- 新增漏洞案例

贡献前请参考[贡献指南](CONTRIBUTING.md)。


## 📄 开源许可

本项目基于 [MIT 许可证](LICENSE) 开源，允许自由使用、修改和分发。


## ⭐ Star 历史

[![Star History Chart](https://api.star-history.com/svg?repos=zgimszhd61/java-sec-code-plus&type=Date)](https://star-history.com/#zgimszhd61/java-sec-code-plus&Date)


## 🌟 致谢

感谢所有贡献者的代码提交和使用反馈，特别感谢安全社区的技术分享！


> ⚠️ 免责声明：本项目仅用于学习和研究目的，严禁用于未经授权的测试或攻击行为。使用前请确保已获得合法授权。