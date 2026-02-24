# 技术架构文档

## 技术栈概览

### 核心框架
- **Spring Boot**: 3.1.0
- **Java**: 17
- **Maven**: 构建工具

### 主要依赖
- **SpringDoc OpenAPI**: 2.2.0 (API 文档)
- **Spring Security**: 认证授权
- **Spring JDBC**: 数据库访问
- **H2 Database**: 嵌入式数据库
- **MySQL Connector**: 8.0.33

### 模板引擎
- Thymeleaf
- Velocity 2.3
- Freemarker 2.3.32

### 序列化/反序列化库
- Fastjson 1.2.83 (故意使用漏洞版本)
- XStream 1.4.20
- Jackson (Spring Boot 内置)

### 脚本引擎
- Groovy 3.0.9
- Nashorn 15.3
- MVEL 2.5.2.Final
- OGNL 3.0.21

### 其他工具
- Hutool 5.8.11
- Javassist 3.28.0-GA
- Redisson 3.30.0
- PMD 7.2.0

## 过时技术实现识别

### [x] 已修复：包名大小写不一致
**位置**: businessLogic, openRedirect 目录
**问题**: Java 包名大小写错误导致编译失败
**解决**: 已统一修正为 camelCase 格式
**验证**: mvn clean install 和 mvn package 均成功

### [ ] 待升级：Spring Boot 版本
**当前版本**: 3.1.0
**最新稳定版**: 3.3.x (截至 2026 年 2 月)
**风险**:
- 缺少最新安全补丁
- 无法使用新特性（如虚拟线程优化）
**建议**: 升级到 Spring Boot 3.3.x
**影响范围**: 需测试所有 72 个控制器的兼容性

### [ ] 待移除：过时的 JAXB 依赖
**位置**: pom.xml
**问题**:
```xml
<dependency>
    <groupId>jakarta.xml.bind</groupId>
    <artifactId>jakarta.xml.bind-api</artifactId>
</dependency>
```
- Spring Boot 3.x 已内置 JAXB 支持
- 显式依赖可能导致版本冲突
**建议**: 移除显式声明，使用 Spring Boot 管理的版本

### [ ] 待替换：Velocity 模板引擎
**当前版本**: 2.3
**问题**:
- Velocity 项目活跃度低，最后更新 2020 年
- 存在已知的模板注入风险
- Spring Boot 官方不再推荐
**建议**: 
- 保留用于漏洞演示
- 生产代码迁移到 Thymeleaf 或 Freemarker

### [ ] 待更新：Fastjson 漏洞版本
**当前版本**: 1.2.83
**问题**:
- 故意使用漏洞版本用于教学
- 但 1.2.83 仍有未修复的 CVE
**建议**:
- 教学示例保持当前版本
- 添加安全版本对比（Fastjson2 或 Jackson）
- 文档中明确标注风险

### [ ] 待移除：commons-collections 3.2.1
**位置**: pom.xml
**问题**:
```xml
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.2.1</version>
</dependency>
```
- 该版本存在严重的反序列化漏洞
- 用于教学演示，但可能被误用
**建议**:
- 保留用于反序列化漏洞演示
- 添加 Scope 限制：`<scope>test</scope>`
- 文档中强调不可用于生产

### [ ] 待优化：数据库配置
**位置**: `DataSourceConfig.java`
**问题**:
```java
@Bean
public DataSource dataSource() {
    return new EmbeddedDatabaseBuilder()
            .setType(EmbeddedDatabaseType.H2)
            .build();
}
```
- 硬编码数据库类型
- 缺少初始化脚本配置
- 无法切换到 MySQL 进行真实场景测试
**建议**:
- 使用 Spring Boot 自动配置
- 通过 application.yml 管理数据源
- 支持多环境配置（H2 开发，MySQL 生产）

### [ ] 待改造：全局异常处理
**位置**: `GlobalExceptionHandler.java`
**问题**:
```java
errorDetails.put("details", ex.getMessage()); // For debugging
```
- 生产环境泄露异常详情
- 缺少日志记录
- 未区分开发/生产环境
**建议**:
- 添加 `@Profile` 区分环境
- 生产环境隐藏敏感信息
- 集成日志框架（SLF4J + Logback）

### [x] 已删除：冗余的 ComponentScan
**位置**: `JavaCodeSimpleApplication.java`
**问题**: 重复的包扫描配置，`com.litellm` 包不存在
**建议**: 移除 `@ComponentScan` 注解，`@SpringBootApplication` 已包含组件扫描
**状态**: 待验证并清理

### [ ] 待移除：未使用的依赖
**位置**: pom.xml
**问题**:
- PMD 7.2.0 - 静态代码分析工具，未在代码中使用
- Soot 4.5.0 - 字节码分析框架，未见使用
- JGraphT 1.5.1 - 图论库，未见使用
- JavaParser 3.23.1 - 代码解析器，未见使用
**建议**: 
- 审计依赖使用情况
- 移除未使用的库，减少打包体积

### [ ] 待规范：日志配置
**当前状态**: 使用 Spring Boot 默认日志
**问题**:
- 缺少自定义日志配置
- 敏感信息可能被记录
- 无日志分级策略
**建议**:
- 添加 `logback-spring.xml`
- 配置日志脱敏规则
- 区分开发/生产日志级别

### [ ] 待添加：容器化优化
**位置**: Dockerfile
**问题**:
- 未使用多阶段构建
- 镜像体积可能过大
- 缺少健康检查配置
**建议**:
```dockerfile
# 多阶段构建
FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn package -DskipTests

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/actuator/health || exit 1
ENTRYPOINT ["java", "-jar", "app.jar"]
```

### [ ] 待实现：配置外部化
**当前状态**: 缺少 application.yml/properties
**问题**:
- 配置硬编码在代码中（如 DataSourceConfig）
- 无法灵活切换环境
**建议**:
```yaml
# application.yml
spring:
  profiles:
    active: dev
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
  h2:
    console:
      enabled: true

# application-prod.yml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/security_samples
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
```
- 使用 Spring Profiles (dev, test, prod)
- 敏感配置使用环境变量

### [ ] 待添加：统一 DTO 层
**当前状态**: 
- 部分模块已有 DTO（businessLogic, massassignment）
- 大多数控制器直接使用实体类或 Map
**问题**:
- 缺少输入验证
- 实体类直接暴露给 API
- 无统一的响应格式
**建议**:
```java
// 统一响应包装类
public class ApiResponse<T> {
    private int code;
    private String message;
    private T data;
    private long timestamp;
}

// 请求 DTO 示例
public class VulnerabilityTestRequest {
    @NotBlank(message = "输入不能为空")
    @Size(max = 500, message = "输入长度不能超过500")
    private String input;
    
    // getters/setters
}
```

### [ ] 待实现：统一异常处理增强
**位置**: `GlobalExceptionHandler.java`
**当前问题**:
- 仅处理通用 Exception
- 缺少特定异常类型处理
- 生产环境泄露异常详情
**建议**:
```java
@ControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse> handleValidationException(
        MethodArgumentNotValidException ex) {
        // 处理参数校验异常
    }
    
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse> handleAccessDenied(
        AccessDeniedException ex) {
        // 处理权限异常
    }
    
    @ExceptionHandler(Exception.class)
    @Profile("!prod") // 仅非生产环境显示详情
    public ResponseEntity<ApiResponse> handleException(Exception ex) {
        // 开发环境显示详细错误
    }
}
```

### [ ] 待集成：安全扫描工具
**当前状态**: 无自动化安全检查
**建议**:
- 集成 OWASP Dependency-Check
- 添加 Snyk 或 Trivy 扫描
- CI/CD 流程中加入安全门禁

## 架构改进建议

### [ ] 分层架构优化
**当前**: Controller 直接处理业务逻辑
**问题**: 72 个控制器中，大部分混合了业务逻辑和数据访问
**建议**:
```
Controller (API 层) - 处理 HTTP 请求/响应
  ↓
Service (业务逻辑层) - 漏洞演示逻辑
  ↓
Repository (数据访问层) - 数据持久化
```
**实施计划**:
1. 先重构 8 个核心漏洞（OWASP Top 10）
2. 创建通用的 VulnerabilityService 接口
3. 逐步迁移其他漏洞

### [ ] 引入 DTO 模式（详见上文）
- 统一请求/响应对象
- 避免实体类直接暴露
- 添加参数校验注解（@Valid, @NotNull, @Size 等）

### [ ] 添加单元测试
**当前覆盖率**: 接近 0%
**目标**: 核心业务逻辑 > 80%
**工具**: JUnit 5 + Mockito + Spring Boot Test
**优先级**:
1. P0: 已分离的 vuln/sec 控制器（32 个）
2. P1: 核心漏洞控制器（8 个）
3. P2: 其他漏洞控制器
**测试模板**:
```java
@SpringBootTest
@AutoConfigureMockMvc
class SqlInjectionUnsafeControllerTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Test
    void testSqlInjectionVulnerability() throws Exception {
        // 测试漏洞可被利用
        mockMvc.perform(get("/api/v1/sql-injection/unsafe/search")
                .param("keyword", "' OR '1'='1"))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("admin")));
    }
}
```

### [ ] API 版本管理
**当前**: 路由格式混乱
- 旧格式：`/security-example/{type}` (40 个控制器)
- 新格式：`/api/v1/{type}/{safe|unsafe}` (32 个控制器)
**建议**: 
- 统一为 `/api/v1/` 前缀
- 预留 v2 升级空间
- 使用 `@RequestMapping("/api/v1")` 在基类或配置中统一管理
**迁移计划**:
1. 第一阶段：新增 v1 路由，保留旧路由（向后兼容）
2. 第二阶段：标记旧路由为 @Deprecated
3. 第三阶段：移除旧路由（发布 v2.0）

### [ ] 性能监控
**建议集成**:
- Spring Boot Actuator
- Micrometer + Prometheus
- 分布式追踪（Zipkin/Jaeger）

## 技术债务优先级

### P0 (高优先级 - 2 周内完成)
1. [x] 修复包名大小写错误（已完成）
2. [ ] 清理冗余的 ComponentScan 配置
3. [ ] 添加 application.yml 配置文件
4. [ ] 优化全局异常处理（添加特定异常类型）
5. [ ] 为 8 个核心漏洞添加 OpenAPI 注解

### P1 (中优先级 - 1 个月内完成)
1. [ ] 升级 Spring Boot 到 3.3.x
2. [ ] 清理未使用的依赖（PMD, Soot, JGraphT, JavaParser）
3. [ ] 优化 Dockerfile 多阶段构建
4. [ ] 统一 API 路由格式（迁移到 /api/v1/）
5. [ ] 添加日志配置（logback-spring.xml）
6. [ ] 为核心漏洞添加单元测试（目标覆盖率 > 60%）

### P2 (低优先级 - 3 个月内完成)
1. [ ] 移除 WebLogic 扫描器模块
2. [ ] 替换 Velocity 模板引擎（仅保留教学用途）
3. [ ] 集成安全扫描工具（OWASP Dependency-Check）
4. [ ] 实现分层架构（Controller-Service-Repository）
5. [ ] 添加统一 DTO 层
6. [ ] 完善单元测试（目标覆盖率 > 80%）

### P3 (长期规划)
1. [ ] 集成性能监控（Spring Boot Actuator + Micrometer）
2. [ ] 添加分布式追踪（Zipkin/Jaeger）
3. [ ] 实现 API 网关（统一认证、限流、日志）
4. [ ] 容器编排优化（Kubernetes 部署）


## 改进进度追踪

### 业务逻辑漏洞扩展进度
| 场景 | 状态 | 文件数 | API 端点 | 完成时间 |
|------|------|--------|----------|----------|
| IP 欺骗 | ✅ 已完成 | 1 | 7 | Week 1 |
| 价格篡改 | ✅ 已完成 | 2 | 2 | Week 1 |
| 库存超卖 | ✅ 已完成 | 3 | 6 | 2026-02-24 |
| 优惠券滥用 | ✅ 已完成 | 3 | 5 | 2026-02-24 |
| 订单金额篡改 | ✅ 已完成 | 2 | 8 | 2026-02-24 |
| 积分/余额操纵 | ✅ 已完成 | 3 | 10 | 2026-02-24 |
| 业务流程绕过 | ✅ 已完成 | 3 | 12 | 2026-02-24 |

**统计**:
- ✅ 已完成：7 个场景（20 个文件，约 60 个 API 端点）
- 🔴 待实现：0 个场景
- 完成率：100% ✅

### 控制器架构统一进度
| 漏洞类型 | 当前状态 | 目标状态 | 优先级 | 预计工作量 |
|---------|---------|---------|--------|-----------|
| sqlInjection | ✅ 已分离 + OpenAPI | - | - | - |
| commandInjection | ✅ 已分离 | 需添加 OpenAPI | P0 | 2h |
| authBypass | ✅ 已分离 | 需添加 OpenAPI | P0 | 2h |
| businessLogic | ✅ 已分离 | 需添加 OpenAPI | P1 | 2h |
| openRedirect | ✅ 已分离 | 需添加 OpenAPI | P0 | 2h |
| massassignment | ✅ 已分离 | 需添加 OpenAPI | P1 | 2h |
| raceCondition | ✅ 已分离 | 需添加 OpenAPI | P1 | 2h |
| ratelimiting | ✅ 已分离 | 需添加 OpenAPI | P1 | 2h |
| hashCollision | ✅ 已分离 | 需添加 OpenAPI | P2 | 2h |
| numericAndDateInput | ✅ 已分离 | 需添加 OpenAPI | P2 | 2h |
| thirdParty (部分) | ✅ 已分离 | 需添加 OpenAPI | P1 | 2h |
| cve202334050 | ✅ 已分离 | 需添加 OpenAPI | P2 | 2h |
| cve202342809 | ✅ 已分离 | 需添加 OpenAPI | P2 | 2h |
| cryptoVuln | ✅ 已分离 | 需添加 OpenAPI | P1 | 2h |
| clickjacking | ✅ 已分离 | 需添加 OpenAPI | P2 | 2h |
| crossSiteScripting | ✅ 已分离 + OpenAPI | - | - | - |
| corsConfig | 🔴 单一控制器 | vuln/sec 分离 | P2 | 2h |
| crossSiteScripting | 🔴 单一控制器 | vuln/sec 分离 | P0 | 3h |
| pathTraversal | 🔴 单一控制器 | vuln/sec 分离 | P0 | 2h |
| serverSideRequestForgery | 🔴 单一控制器 | vuln/sec 分离 | P0 | 3h |
| xmlExternalEntity | 🔴 单一控制器 | vuln/sec 分离 | P0 | 4h |
| insecureDirectObjectReference | 🔴 单一控制器 | vuln/sec 分离 | P0 | 2h |
| brokenAccessControl | 🔴 单一控制器 | vuln/sec 分离 | P0 | 3h |
| authorizationBypass | 🔴 单一控制器 | vuln/sec 分离 | P0 | 2h |
| sensitiveDataExposure | 🔴 单一控制器 | vuln/sec 分离 | P0 | 2h |
| spelInjection | 🔴 单一控制器 | vuln/sec 分离 | P1 | 3h |
| templateInjection | 🔴 单一控制器 | vuln/sec 分离 | P1 | 4h |
| scriptEngineInjection | 🔴 单一控制器 | vuln/sec 分离 | P1 | 3h |
| beanShellInjection | 🔴 单一控制器 | vuln/sec 分离 | P1 | 3h |
| groovyInjection | 🔴 单一控制器 | vuln/sec 分离 | P1 | 3h |
| mvelInjection | 🔴 单一控制器 | vuln/sec 分离 | P1 | 3h |
| onglInjection | 🔴 单一控制器 | vuln/sec 分离 | P1 | 3h |
| jndiInjection | 🔴 单一控制器 | vuln/sec 分离 | P1 | 4h |
| ldapInjection | 🔴 单一控制器 | vuln/sec 分离 | P1 | 3h |
| xpathInjection | 🔴 单一控制器 | vuln/sec 分离 | P1 | 3h |
| headerInjection | 🔴 单一控制器 | vuln/sec 分离 | P1 | 2h |
| clickjacking | 🔴 单一控制器 | vuln/sec 分离 | P2 | 2h |
| securityHeaderMissing | 🔴 单一控制器 | vuln/sec 分离 | P2 | 2h |
| hardcodedCredentials | 🔴 单一控制器 | vuln/sec 分离 | P2 | 2h |
| defaultCredentials | 🔴 单一控制器 | vuln/sec 分离 | P2 | 2h |
| weakPassword | 🔴 单一控制器 | vuln/sec 分离 | P2 | 2h |
| jsonpCallback | 🔴 单一控制器 | vuln/sec 分离 | P3 | 2h |
| regularExpressionDOS | 🔴 单一控制器 | vuln/sec 分离 | P3 | 2h |
| RiskyOperations | 🔴 单一控制器 | vuln/sec 分离 | P3 | 2h |
| unsafeDeserialization | 🔴 单一控制器 | vuln/sec 分离 | P1 | 4h |
| yamlDeserialization | 🔴 单一控制器 | vuln/sec 分离 | P1 | 3h |

**统计**:
- ✅ 已完成架构分离：16 个模块（32 个控制器）
- ✅ 已添加 OpenAPI 注解：2 个模块（sqlInjection, crossSiteScripting）
- 🟡 已分离待添加注解：14 个模块
- 🔴 待改造：40 个控制器
- 总预计工作量：约 110 小时（14 个工作日）

### Week 1 完成总结
- ✅ 修复了 businessLogic 和 openRedirect 的包名大小写错误
- ✅ 清理了 JavaCodeSimpleApplication 的冗余 @ComponentScan 配置
- ✅ 创建了完整的配置文件体系（application.yml + dev/test/prod 环境）
- ✅ 为 crossSiteScripting 创建了标准的 vuln/sec 分离模板（含 OpenAPI 注解）
- ✅ 为 sqlInjection 添加了完整的 OpenAPI 注解（作为参考模板）
- ✅ 所有更改通过编译验证（mvn clean package 成功）

### OpenAPI 注解补充进度
| 模块 | 注解完整度 | 优先级 | 预计工作量 |
|------|-----------|--------|-----------|
| 已分离的 vuln/sec 控制器 | 🟡 部分完整 | P0 | 16h |
| 核心漏洞（OWASP Top 10） | 🔴 缺失 | P0 | 8h |
| 注入类漏洞 | 🔴 缺失 | P1 | 11h |
| 其他漏洞 | 🔴 缺失 | P2 | 10h |

### 单元测试覆盖率进度
| 模块 | 当前覆盖率 | 目标覆盖率 | 优先级 | 预计工作量 |
|------|-----------|-----------|--------|-----------|
| 已分离的 vuln/sec | 0% | 80% | P0 | 32h |
| 核心漏洞 | 0% | 80% | P1 | 16h |
| 其他漏洞 | 0% | 60% | P2 | 40h |
| 配置和工具类 | 0% | 70% | P1 | 8h |

## 下一步行动计划

### 本周任务（Week 1）
1. [x] 修复包名大小写错误
2. [x] 清理 JavaCodeSimpleApplication 冗余配置
3. [x] 添加 application.yml 基础配置（含 dev/test/prod 环境）
4. [x] 为 crossSiteScripting 添加 vuln/sec 分离（作为模板）
5. [x] 为 sqlInjection 添加 OpenAPI 注解（作为模板）

### 下周任务（Week 2）
1. [ ] 完成 8 个核心漏洞的 vuln/sec 分离
   - [ ] pathTraversal
   - [ ] serverSideRequestForgery
   - [ ] xmlExternalEntity
   - [ ] insecureDirectObjectReference
   - [ ] brokenAccessControl
   - [ ] authorizationBypass
   - [ ] sensitiveDataExposure
2. [ ] 为所有已分离控制器添加 OpenAPI 注解
3. [ ] 优化 GlobalExceptionHandler
4. [ ] 添加 logback-spring.xml 配置

### 本月任务（Month 1）
1. [ ] 完成所有注入类漏洞的架构统一
2. [ ] 升级 Spring Boot 到 3.3.x
3. [ ] 清理未使用的依赖
4. [ ] 为核心漏洞添加单元测试（覆盖率 > 60%）
5. [ ] 优化 Dockerfile 多阶段构建

### 季度目标（Q1 2026）
1. [ ] 完成所有控制器的架构统一
2. [ ] 单元测试覆盖率达到 80%
3. [ ] 实现分层架构（Controller-Service-Repository）
4. [ ] 集成安全扫描工具
5. [ ] 完善文档和示例
