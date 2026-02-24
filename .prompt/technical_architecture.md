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

### [ ] 待升级：Spring Boot 版本
**当前版本**: 3.1.0
**最新稳定版**: 3.3.x (截至 2026 年 2 月)
**风险**:
- 缺少最新安全补丁
- 无法使用新特性（如虚拟线程优化）
**建议**: 升级到 Spring Boot 3.3.x

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

### [ ] 待删除：冗余的 ComponentScan
**位置**: `JavaCodeSimpleApplication.java`
**问题**:
```java
@ComponentScan(basePackages = {"com.freedom.securitysamples", "com.litellm"})
@SpringBootApplication(scanBasePackages = "com.freedom.securitysamples")
```
- 重复的包扫描配置
- `com.litellm` 包不存在于项目中
**建议**:
- 移除 `@ComponentScan` 注解
- `@SpringBootApplication` 已包含组件扫描

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
- 配置硬编码在代码中
- 无法灵活切换环境
**建议**:
- 添加 `application.yml`
- 使用 Spring Profiles (dev, test, prod)
- 敏感配置使用环境变量

### [ ] 待集成：安全扫描工具
**当前状态**: 无自动化安全检查
**建议**:
- 集成 OWASP Dependency-Check
- 添加 Snyk 或 Trivy 扫描
- CI/CD 流程中加入安全门禁

## 架构改进建议

### [ ] 分层架构优化
**当前**: Controller 直接处理业务逻辑
**建议**:
```
Controller (API 层)
  ↓
Service (业务逻辑层)
  ↓
Repository (数据访问层)
```

### [ ] 引入 DTO 模式
- 统一请求/响应对象
- 避免实体类直接暴露
- 添加参数校验注解

### [ ] 添加单元测试
**当前覆盖率**: 接近 0%
**目标**: 核心业务逻辑 > 80%
**工具**: JUnit 5 + Mockito + Spring Boot Test

### [ ] API 版本管理
**当前**: 路由无版本控制
**建议**: 
- 统一为 `/api/v1/` 前缀
- 预留 v2 升级空间

### [ ] 性能监控
**建议集成**:
- Spring Boot Actuator
- Micrometer + Prometheus
- 分布式追踪（Zipkin/Jaeger）

## 技术债务优先级

### P0 (高优先级)
1. [ ] 升级 Spring Boot 到 3.3.x
2. [ ] 移除冗余的 ComponentScan 配置
3. [ ] 添加 application.yml 配置文件
4. [ ] 优化全局异常处理

### P1 (中优先级)
1. [ ] 清理未使用的依赖
2. [ ] 优化 Dockerfile 多阶段构建
3. [ ] 统一控制器架构（vuln/sec 分离）
4. [ ] 添加日志配置

### P2 (低优先级)
1. [ ] 移除 WebLogic 扫描器模块
2. [ ] 替换 Velocity 模板引擎
3. [ ] 集成安全扫描工具
4. [ ] 添加单元测试
