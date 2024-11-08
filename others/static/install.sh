#!/bin/bash

# 打印开始信息
echo "开始安装基础环境和依赖..."

# 安装基础环境和依赖
yum install git maven -y

# 下载并安装Maven
wget https://mirrors.estointernet.in/apache/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.tar.gz
tar -xvf apache-maven-3.6.3-bin.tar.gz
mv apache-maven-3.6.3 /opt/

# 下载并安装JDK 17
wget https://download.oracle.com/java/17/latest/jdk-17_linux-x64_bin.tar.gz
tar xf jdk-17_linux-x64_bin.tar.gz
mv jdk-17.0.7/ /usr/lib/jvm

# 配置Maven设置
echo "配置Maven设置..."
rm -rf /opt/apache-maven-3.6.3/conf/settings.xml
cat > /opt/apache-maven-3.6.3/conf/settings.xml << 'EOF'
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
EOF

# 配置环境变量
echo "配置环境变量..."
cat >> /etc/profile << 'EOF'
export M2_HOME='/opt/apache-maven-3.6.3'
export JAVA_HOME=/usr/lib/jvm/jdk-17.0.7
export CLASSPATH=$JAVA_HOME/lib/tools.jar:$JAVA_HOME/lib/dt.jar:$JAVA_HOME/lib
export PATH=$M2_HOME/bin:$JAVA_HOME/bin:$PATH
EOF

# 使环境变量生效
source /etc/profile

# 克隆并构建项目
echo "克隆并构建项目..."
git clone https://github.com/zgimszhd61/java-sec-code-plus.git
cd java-sec-code-plus
mvn install
mvn package

# 检查8080端口
echo "检查8080端口状态..."
if lsof -i:8080 > /dev/null; then
    echo "8080端口被占用，正在释放..."
    lsof -i:8080 | awk 'NR!=1 {print $2}' | xargs kill -9
fi

# 启动应用
echo "启动应用..."
mvn spring-boot:run &

echo "安装完成！应用已在后台启动，请访问 http://localhost:8080 检查服务状态。"