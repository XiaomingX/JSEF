# 使用官方JDK 17镜像作为基础镜像
FROM openjdk:17-slim

# 设置工作目录
WORKDIR /app

# 安装必要的工具
RUN apt-get update && apt-get install -y \
    git \
    wget \
    maven \
    && rm -rf /var/lib/apt/lists/*

# 配置Maven设置
COPY settings.xml /usr/share/maven/conf/settings.xml

# 克隆项目
RUN git clone https://github.com/zgimszhd61/java-sec-code-plus.git

# 设置工作目录
WORKDIR /app/java-sec-code-plus

# 编译项目
RUN mvn install && mvn package

# 暴露端口
EXPOSE 8080

# 启动命令
CMD ["mvn", "spring-boot:run"]