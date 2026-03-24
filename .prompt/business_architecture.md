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

### [x] 已完成：包名大小写修复
**位置**: `businessLogic/`, `openRedirect/`
**说明**: 已修复所有包名大小写不一致问题，项目可正常编译和打包

### [ ] 待改造：混合架构的控制器统一
**位置**: 多个 vulnerability 子目录
**当前状态**:
- 已按 `vuln/sec` 分离：16 个模块（32 个控制器）
- 未分离的单一控制器：40 个
**问题**:
- 架构不一致，学习体验割裂
- 旧路由格式 `/security-example/` 与新格式 `/api/v1/` 混用
**待改造列表**（按优先级）:
1. **P0 - 核心漏洞**（OWASP Top 10）:
   - crossSiteScripting (XSS)
   - pathTraversal (路径遍历)
   - serverSideRequestForgery (SSRF)
   - xmlExternalEntity (XXE)
   - insecureDirectObjectReference (IDOR)
   - brokenAccessControl (访问控制缺陷)
   - authorizationBypass (授权绕过)
   - sensitiveDataExposure (敏感数据泄露)
   
2. **P1 - 注入类漏洞**:
   - spelInjection (SpEL 注入)
   - templateInjection (模板注入)
   - scriptEngineInjection (脚本引擎注入)
   - beanShellInjection (BeanShell 注入)
   - groovyInjection (Groovy 注入)
   - mvelInjection (MVEL 注入)
   - onglInjection (OGNL 注入)
   - jndiInjection (JNDI 注入)
   - ldapInjection (LDAP 注入)
   - xpathInjection (XPath 注入)
   - headerInjection (HTTP 头注入)
   
3. **P2 - 配置与认证**:
   - corsConfig (CORS 配置错误)
   - clickjacking (点击劫持)
   - securityHeaderMissing (安全头缺失)
   - hardcodedCredentials (硬编码凭证)
   - defaultCredentials (默认凭证)
   - weakPassword (弱密码)
   
4. **P3 - 其他漏洞**:
   - jsonpCallback (JSONP 回调注入)
   - regularExpressionDOS (正则 DoS)
   - RiskyOperations (不安全操作)
   - thirdParty 相关（部分已分离）

**改造步骤**:
1. 为每个漏洞创建 `vuln/` 和 `sec/` 子目录
2. 拆分现有控制器为 Unsafe 和 Safe 两个版本
3. 统一路由格式为 `/api/v1/{vulnerability-type}/{unsafe|safe}/{endpoint}`
4. 添加 OpenAPI 注解

### [x] 已完成：业务逻辑漏洞示例
**位置**: `vulnerability/businessLogic/`
**完成状态**: 7/7 场景全部实现 ✅

**已实现场景**:
1. **IP 欺骗**（IpSpoofingVulnerabilityController）
   - 不安全：信任 X-Forwarded-For 等请求头
   - 安全：验证代理链，使用白名单

2. **价格篡改**（PriceTamperingUnsafe/SafeController）
   - 不安全：信任客户端提交的价格
   - 安全：服务端查询真实价格

3. **库存超卖**（InventoryOversellUnsafe/SafeController）
   - 不安全：并发购买时检查和扣减不是原子操作
   - 安全：使用 ReentrantLock 和乐观锁防止超卖

4. **优惠券滥用**（CouponAbuseUnsafe/SafeController）
   - 不安全：未验证使用状态、有效期和叠加规则
   - 安全：严格验证 + 锁机制 + 用户使用历史

5. **订单金额篡改**（OrderAmountTamperingUnsafe/SafeController）
   - 不安全：信任客户端提交的总价、运费、折扣
   - 安全：服务端重新计算所有金额字段

6. **积分/余额操纵**（AccountManipulationUnsafe/SafeController）
   - 不安全：允许负数充值、整数溢出、并发提现
   - 安全：验证正数、检查溢出、使用锁保证原子性

7. **业务流程绕过**（WorkflowBypassUnsafe/SafeController）
   - 不安全：未验证状态转换，可跳过支付直接发货
   - 安全：状态机验证，定义合法转换规则

**统计数据**:
- 控制器文件：15 个（7 unsafe + 7 safe + 1 legacy）
- 模型文件：5 个（Product, Inventory, Coupon, Order, UserAccount）
- API 端点：约 60 个
- 代码行数：约 2500 行

**待扩展场景**（可选）:
- [ ] 退款漏洞（重复退款、金额篡改）
- [ ] 会员等级绕过（直接修改等级）
- [ ] 限购绕过（突破购买数量限制）

### [ ] 待补充：API 文档完整性
**位置**: 各 Controller 类
**当前问题**:
- 72 个控制器中，约 40 个缺少 OpenAPI 注解
- 路由格式不统一：
  - 旧格式：`/security-example/{type}` (40 个)
  - 新格式：`/api/v1/{type}/{safe|unsafe}` (32 个)
**改进计划**:
1. 统一添加 `@Tag`, `@Operation`, `@ApiResponse` 注解
2. 所有路由迁移到 `/api/v1/` 格式
3. 在 Swagger UI 中按漏洞类型分组展示

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
**当前状态**: 文档已有中英日韩版本
**待实现**:
- 代码注释国际化（支持中英文切换）
- API 响应消息国际化
- Swagger UI 多语言支持
- 学习路径引导多语言

### [ ] 新增：难度分级系统
- **初级**：基础注入类漏洞（SQL、XSS、命令注入）
- **中级**：反序列化、模板注入、SSRF
- **高级**：竞态条件、业务逻辑漏洞、漏洞链组合
- 每个漏洞标注难度星级（1-5 星）

### [ ] 新增：实战靶场模式
- 提供完整的业务系统（如博客、电商）
- 隐藏漏洞位置，让学习者自行发现
- 积分排行榜和成就系统


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

### P0 (高优先级 - 2 周内完成)
1. [x] 修复包名大小写错误（已完成）
2. [ ] 删除 WebLogic 扫描器模块或独立仓库
3. [ ] 决策 CVE 目录归属（推荐删除空目录）
4. [ ] 统一 8 个核心漏洞控制器架构（OWASP Top 10）
5. [ ] 补充核心漏洞的 OpenAPI 注解

### P1 (中优先级 - 1 个月内完成)
1. [ ] 统一 11 个注入类漏洞控制器架构
2. [ ] 扩展业务逻辑漏洞案例（至少 3 个新场景）
3. [ ] 统一所有路由为 `/api/v1/` 格式
4. [ ] 添加难度分级系统
5. [ ] 实现学习进度追踪

### P2 (低优先级 - 3 个月内完成)
1. [ ] 统一剩余 21 个控制器架构
2. [ ] 建立漏洞元数据管理
3. [ ] 开发交互式学习 UI
4. [ ] 多语言支持（代码注释和 API 响应）
5. [ ] 实战靶场模式

### P3 (长期规划)
1. [ ] 企业培训版功能
2. [ ] CTF 竞赛模式
3. [ ] 漏洞利用链演示
4. [ ] 社区贡献机制


## 改进实施路线图

### 第一阶段：基础设施完善（2 周）
**目标**: 建立统一的技术基础
- [x] 修复包名大小写错误
- [ ] 清理冗余配置
- [ ] 添加配置文件管理
- [ ] 优化异常处理
- [ ] 建立代码模板和规范

**交付物**:
- application.yml 配置文件
- 统一的 DTO 基类
- 增强的 GlobalExceptionHandler
- 控制器开发模板文档

### 第二阶段：核心漏洞重构（4 周）
**目标**: 完成 OWASP Top 10 相关漏洞的架构统一
- [ ] 8 个核心漏洞 vuln/sec 分离
- [ ] 添加 OpenAPI 完整注解
- [ ] 统一路由格式为 /api/v1/
- [ ] 为每个漏洞添加单元测试

**交付物**:
- 8 个核心漏洞的标准化实现
- Swagger UI 完整文档
- 单元测试套件（覆盖率 > 60%）

### 第三阶段：注入类漏洞扩展（4 周）
**目标**: 完成所有注入类漏洞的统一
- [ ] 11 个注入类漏洞重构
- [ ] 添加漏洞利用链演示
- [ ] 扩展业务逻辑漏洞案例
- [ ] 实现难度分级系统

**交付物**:
- 完整的注入类漏洞库
- 3 个新的业务逻辑漏洞案例
- 漏洞难度分级元数据

### 第四阶段：全面优化（4 周）
**目标**: 完成所有漏洞的架构统一和功能增强
- [ ] 剩余 21 个控制器重构
- [ ] 实现分层架构
- [ ] 添加学习进度追踪
- [ ] 多语言支持（代码注释）

**交付物**:
- 完整的漏洞演示平台
- 学习管理系统
- 多语言文档

### 第五阶段：高级功能（长期）
**目标**: 提升平台竞争力
- [ ] 交互式学习 UI
- [ ] 实战靶场模式
- [ ] 企业培训版
- [ ] CTF 竞赛模式

## 关键指标（KPI）

### 代码质量指标
- **架构一致性**: 100% 控制器按 vuln/sec 分离（当前 44%）
- **API 文档完整性**: 100% 控制器有 OpenAPI 注解（当前 ~40%）
- **单元测试覆盖率**: > 80%（当前 ~0%）
- **代码重复率**: < 5%

### 功能完整性指标
- **漏洞类型覆盖**: 35+ 种（当前已达标）
- **业务逻辑漏洞**: 5+ 个真实场景（当前 2 个）
- **CVE 案例**: 10+ 个（当前 2 个）
- **漏洞利用链**: 3+ 个组合场景（当前 0 个）

### 用户体验指标
- **API 响应时间**: < 200ms（P95）
- **文档完整性**: 每个漏洞有完整的复现步骤
- **学习路径**: 提供推荐学习顺序
- **多语言支持**: 中英文双语

### 技术债务指标
- **过时依赖**: 0 个高危漏洞依赖
- **代码异味**: SonarQube 评分 > A
- **安全扫描**: 0 个高危问题
- **性能瓶颈**: 0 个慢查询（> 1s）

## 风险管理

### 技术风险
| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|---------|
| Spring Boot 升级兼容性问题 | 高 | 中 | 先在测试环境验证，逐步迁移 |
| 大规模重构引入新 Bug | 高 | 高 | 增加单元测试，代码审查 |
| 性能下降 | 中 | 低 | 性能基准测试，监控关键指标 |
| 依赖冲突 | 中 | 中 | 使用依赖管理工具，锁定版本 |

### 业务风险
| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|---------|
| 用户学习曲线陡峭 | 中 | 中 | 提供详细文档和视频教程 |
| 漏洞案例过时 | 中 | 高 | 定期更新 CVE 案例 |
| 社区贡献不足 | 低 | 中 | 建立贡献激励机制 |
| 竞品压力 | 中 | 低 | 持续创新，保持技术领先 |

### 资源风险
| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|---------|
| 开发人力不足 | 高 | 中 | 优先级排序，分阶段实施 |
| 时间压力 | 中 | 高 | 合理规划，避免过度承诺 |
| 预算限制 | 低 | 低 | 使用开源工具，降低成本 |

## 成功标准

### 短期目标（3 个月）
- ✅ 所有编译错误已修复
- [ ] 核心漏洞架构统一完成
- [ ] 单元测试覆盖率 > 60%
- [ ] API 文档完整性 > 80%

### 中期目标（6 个月）
- [ ] 所有控制器架构统一
- [ ] 单元测试覆盖率 > 80%
- [ ] 实现分层架构
- [ ] 集成 CI/CD 流程

### 长期目标（1 年）
- [ ] 交互式学习平台上线
- [ ] 企业培训版发布
- [ ] 社区贡献者 > 10 人
- [ ] GitHub Stars > 1000
