# 业务架构文档

## 项目概述
Java Security Education Framework (JSEF) - Spring Boot 安全实践平台，提供 35+ 种 Web 安全漏洞实例的教学框架。

## 核心业务模块

### 1. 漏洞演示模块
- **SQL 注入** (sqlInjection)
- **XSS 跨站脚本** (crossSiteScripting)
- **命令注入** (commandInjection)
- **路径遍历** (pathTraversal)
- **SSRF 服务端请求伪造** (serverSideRequestForgery)
- **XXE XML 外部实体** (xmlExternalEntity)
- **反序列化漏洞** (unsafeDeserialization)
- **模板注入** (templateInjection)
- **认证绕过** (authBypass)
- **授权绕过** (authorizationBypass)
- **IDOR 不安全直接对象引用** (insecureDirectObjectReference)
- **访问控制缺陷** (brokenAccessControl)
- **敏感数据泄露** (sensitiveDataExposure)
- **弱密码** (weakPassword)
- **硬编码凭证** (hardcodedCredentials)
- **默认凭证** (defaultCredentials)
- **加密漏洞** (cryptoVuln)
- **开放重定向** (openRedirect)
- **点击劫持** (clickjacking)
- **CORS 配置错误** (corsConfig)
- **安全头缺失** (securityHeaderMissing)
- **业务逻辑漏洞** (businessLogic)
- **竞态条件** (raceCondition)
- **限流缺失** (ratelimiting)
- **批量赋值** (massassignment)
- **正则表达式 DoS** (regularExpressionDOS)
- **哈希碰撞** (hashCollision)
- **脚本引擎注入** (scriptEngineInjection, beanShellInjection, groovyInjection, mvelInjection, onglInjection, spelInjection)
- **JNDI 注入** (jndiInjection)
- **LDAP 注入** (ldapInjection)
- **XPath 注入** (xpathInjection)
- **YAML 反序列化** (yamlDeserialization)
- **第三方库漏洞** (thirdParty)
- **CVE 特定漏洞** (cve202334050, cve202342809)

### 2. 安全对比学习模块
每个漏洞类别包含：
- `vuln/` - 不安全实现示例
- `sec/` - 安全修复实现示例

### 3. 辅助工具模块
- **WebLogic 扫描器** (data-security-research2-v1/weblogicScanner)
- **数据安全研究工具** (data-security-research2-v1)

## 过时业务功能识别

### [ ] 待删除：WebLogic 扫描器模块
**位置**: `data-security-research2-v1/weblogicScanner/`
**原因**: 
- 该模块是独立的 Python 工具，与主项目 Java/Spring Boot 技术栈不一致
- 专注于 WebLogic CVE 扫描，与教学平台核心业务偏离
- 维护成本高，且已有专业的漏洞扫描工具
**建议**: 
- 移除整个 `data-security-research2-v1` 目录
- 如需保留，应独立为单独的仓库

### [ ] 待迁移：CVE 特定漏洞示例
**位置**: `src/main/java/com/freedom/securitysamples/cve/`
**原因**:
- CVE 目录当前为空（仅有 README.md）
- CVE 相关实现分散在 vulnerability 目录下（cve202334050, cve202342809）
**建议**:
- 统一 CVE 相关代码到 `cve/` 目录
- 或者删除空的 cve 目录，保持 vulnerability 结构

### [ ] 待改造：混合架构的控制器
**位置**: 多个 vulnerability 子目录
**问题**:
- 部分漏洞已按 `vuln/sec` 分离（如 authBypass, commandInjection）
- 部分漏洞仍为单一控制器（如 crossSiteScripting, pathTraversal）
**建议**:
- 统一所有漏洞为 `vuln/sec` 双控制器架构
- 提升代码一致性和学习体验

### [ ] 待优化：业务逻辑漏洞示例
**位置**: `vulnerability/businessLogic/`
**问题**:
- 当前仅有 IP 欺骗示例
- 业务逻辑漏洞类型丰富（价格篡改、库存绕过、优惠券滥用等）
**建议**:
- 扩展更多真实业务场景案例
- 添加电商、支付、订单等常见业务逻辑漏洞

### [ ] 待补充：API 文档完整性
**位置**: 各 Controller 类
**问题**:
- 部分控制器缺少 Swagger/OpenAPI 注解
- API 路由命名不统一（部分使用 `/unsafe/`，部分直接暴露）
**建议**:
- 统一添加 `@Operation`, `@ApiResponse` 注解
- 规范化路由为 `/api/v1/{type}/{safe|unsafe}/{scenario}`

### [x] 已完成：包结构重构
**位置**: `com.freedom.securitysamples.vulnerability`
**说明**: 已将所有漏洞代码从分散位置迁移到统一的 vulnerability 包下

## 业务扩展建议

### [ ] 新增：漏洞利用链演示
- 组合多个漏洞的真实攻击场景
- 例如：XSS + CSRF + 会话劫持完整攻击链

### [ ] 新增：防御方案对比
- 不同防御策略的效果对比
- 性能影响分析

### [ ] 新增：自动化测试套件
- 每个漏洞的自动化验证脚本
- CI/CD 集成的安全回归测试

### [ ] 新增：交互式学习模式
- Web UI 界面展示漏洞原理
- 在线代码编辑器实时验证修复方案


### [ ] 新增：多语言支持
- 当前文档已有中英日韩版本
- 代码注释和 API 响应需国际化
- 支持切换语言的学习体验

### [ ] 新增：难度分级系统
- 初级：基础注入类漏洞（SQL、XSS、命令注入）
- 中级：反序列化、模板注入、SSRF
- 高级：竞态条件、业务逻辑漏洞、漏洞链组合

### [ ] 新增：实战靶场模式
- 提供完整的业务系统（如博客、电商）
- 隐藏漏洞位置，让学习者自行发现
- 积分排行榜和成就系统

## 业务流程优化

### [ ] 待优化：漏洞复现流程
**当前**: 需要手动查看文档 → 启动服务 → 使用 Postman/curl 测试
**建议**:
- 集成 Swagger UI 的 Try it out 功能
- 提供预设的攻击 Payload
- 一键复现按钮

### [ ] 待优化：学习路径引导
**当前**: 漏洞列表平铺展示
**建议**:
- 按 OWASP Top 10 分类
- 提供推荐学习顺序
- 前置知识依赖提示

### [ ] 待优化：代码对比体验
**当前**: 需要手动切换 vuln/sec 目录查看代码
**建议**:
- Web UI 提供 Diff 视图
- 高亮关键修复点
- 添加修复原理解释

## 数据模型优化

### [ ] 待添加：用户学习进度追踪
**建议数据模型**:
```java
// 学习进度实体
class LearningProgress {
    Long userId;
    String vulnerabilityType;
    Boolean completed;
    LocalDateTime completedAt;
    Integer attempts;
}
```

### [ ] 待添加：漏洞元数据管理
**建议数据模型**:
```java
// 漏洞元数据
class VulnerabilityMetadata {
    String id;
    String name;
    String category; // OWASP Top 10
    Integer difficulty; // 1-5
    List<String> cveIds;
    String description;
    List<String> references;
}
```

## 业务指标监控

### [ ] 待实现：使用统计
- 各漏洞类型访问频率
- 学习完成率
- 平均学习时长

### [ ] 待实现：漏洞热度排行
- 最受欢迎的漏洞类型
- 最难理解的漏洞（高失败率）
- 社区贡献的新案例

## 合规性考虑

### [ ] 待添加：使用协议确认
- 首次启动时显示免责声明
- 用户需确认仅用于学习目的
- 记录用户同意日志

### [ ] 待添加：敏感操作审计
- 记录所有漏洞利用尝试
- IP 地址和时间戳
- 异常行为告警

## 社区生态建设

### [ ] 待建立：漏洞案例贡献机制
- 标准化的漏洞提交模板
- 代码审查流程
- 贡献者积分系统

### [ ] 待建立：问题反馈渠道
- GitHub Issues 模板
- 常见问题 FAQ
- 社区讨论区（Discussions）

### [ ] 待建立：教学资源库
- 配套视频教程
- 博客文章链接
- 推荐书籍和课程

## 业务风险管理

### [ ] 待实现：滥用防护
- 限制单 IP 请求频率
- 检测自动化扫描行为
- 蜜罐陷阱识别恶意用户

### [ ] 待实现：环境隔离
- 容器化部署强制隔离
- 禁止外网直接访问
- VPN 或内网部署建议

## 业务价值提升

### [ ] 待开发：企业培训版
- 多租户支持
- 培训进度管理后台
- 定制化漏洞场景

### [ ] 待开发：认证考试模式
- 限时挑战
- 自动评分系统
- 证书颁发

### [ ] 待开发：CTF 竞赛模式
- Flag 隐藏机制
- 实时排行榜
- 团队协作功能

## 业务债务优先级

### P0 (高优先级)
1. [ ] 删除 WebLogic 扫描器模块
2. [ ] 统一控制器架构（vuln/sec 分离）
3. [ ] 补充 API 文档注解
4. [ ] 优化漏洞复现流程

### P1 (中优先级)
1. [ ] 扩展业务逻辑漏洞案例
2. [ ] 添加难度分级系统
3. [ ] 实现学习进度追踪
4. [ ] 建立漏洞元数据管理

### P2 (低优先级)
1. [ ] 开发交互式学习 UI
2. [ ] 实战靶场模式
3. [ ] 企业培训版功能
4. [ ] CTF 竞赛模式
