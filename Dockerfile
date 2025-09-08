# ==================== 第一阶段：构建阶段（编译项目生成JAR包）====================
FROM openjdk:17-jdk-slim AS build-stage

# 设置构建阶段的工作目录（容器内路径，可自定义）
WORKDIR /app

# 1. 先复制 pom.xml 文件，利用Docker缓存机制加速依赖下载（依赖不变时无需重复下载）
COPY pom.xml .

# 2. 下载Maven依赖（仅下载依赖，不编译代码，进一步优化缓存）
# -Dmaven.test.skip=true：跳过测试（构建阶段无需执行测试，加速构建）
# --no-cache-dir：不保留Maven缓存文件，减小构建阶段镜像体积
RUN apt-get update && apt-get install -y maven \
    && mvn dependency:go-offline -Dmaven.test.skip=true --no-cache-dir \
    && apt-get remove -y maven && apt-get clean autoclean && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# 3. 复制项目所有源代码（src目录）到容器工作目录
COPY src ./src

# 4. 编译项目生成JAR包（输出到 target 目录）
# -DskipTests：跳过测试（与上面的 -Dmaven.test.skip=true 作用一致，双重保险）
RUN mvn clean package -DskipTests --no-cache-dir


# ==================== 第二阶段：运行阶段（仅保留运行必需文件，减小镜像体积）====================
FROM openjdk:17-jre-slim AS runtime-stage

# 设置运行阶段的工作目录（容器内路径，与构建阶段可不同）
WORKDIR /app

# 1. 从构建阶段复制编译好的JAR包到运行阶段（仅复制最终产物，剔除构建依赖）
# 注意：JAR包名称需与项目实际生成的一致（参考你之前的启动命令：springboot-security-sample-0.0.1-SNAPSHOT.jar）
COPY --from=build-stage /app/target/springboot-security-sample-0.0.1-SNAPSHOT.jar ./jsef-app.jar

# 2. 暴露容器端口（需与项目启动端口一致，默认8080）
# 此步骤仅为"声明"端口，实际端口映射通过 docker run -p 实现
EXPOSE 8080

# 3. 容器启动命令（执行JAR包）
# -XX:+UseContainerSupport：JVM自动适配容器资源（避免内存溢出）
# -XX:MaxRAMPercentage=70.0：限制JVM最大内存为容器内存的70%（可根据需求调整）
ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=70.0", "-jar", "jsef-app.jar"]