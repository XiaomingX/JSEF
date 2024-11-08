## Dockerfile内容
```dockerfile
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
```

## 安装教程

### 1. 准备工作
首先创建一个新目录并进入：
```bash
mkdir security-platform
cd security-platform
```

### 2. 创建settings.xml文件
在当前目录创建`settings.xml`文件：
```bash
vi settings.xml
```

将以下内容复制到settings.xml中：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd">
  <mirrors>
    <mirror>
     <id>aliyunmaven</id>
     <mirrorOf>*</mirrorOf>
     <name>阿里云公共仓库</name>
     <url>https://maven.aliyun.com/repository/public</url>
    </mirror>
  </mirrors>
</settings>
```

### 3. 构建Docker镜像
```bash
# 构建镜像
docker build -t security-platform:latest .

# 运行容器
docker run -d -p 8080:8080 --name security-platform security-platform:latest
```

### 4. 验证部署
```bash
# 检查容器运行状态
docker ps

# 查看容器日志
docker logs security-platform
```

## 使用说明

### 访问应用
- 应用成功启动后，可以通过 `http://localhost:8080` 访问

### 常用Docker命令
```bash
# 停止容器
docker stop security-platform

# 启动容器
docker start security-platform

# 重启容器
docker restart security-platform

# 删除容器
docker rm -f security-platform

# 查看容器日志
docker logs -f security-platform
```

### 注意事项
1. 确保Docker已正确安装并运行
2. 确保8080端口未被占用
3. 如需修改端口映射，可在运行容器时调整：
```bash
docker run -d -p 自定义端口:8080 --name security-platform security-platform:latest
```

### 故障排除
1. 如果构建失败，检查网络连接和Maven仓库配置
2. 如果启动失败，检查端口占用情况
3. 如果需要进入容器排查问题：
```bash
docker exec -it security-platform /bin/bash
```
