## 项目简介
- 这是一个基于SpringBoot的安全教育框架，提供了清晰的教程，帮助用户快速部署和运行平台。
- **项目目标**：打造一个简便的一站式平台，用于全面评估和提升系统的安全能力。

## 本地使用指南
```
git clone --depth 1 https://github.com/zgimszhd61/java-sec-code-plus
mvn install
mvn spring-boot:run
```

<details>
  <summary>支持的漏洞类别</summary>

  #### authBypass
  身份认证绕过漏洞允许攻击者绕过认证机制，未经授权即可访问受限区域或功能。

  #### authorizationBypass
  授权绕过漏洞是指攻击者可以获得其无权使用的资源，通常是由于权限验证的缺陷所致。

  #### beanShellInjection
  BeanShell注入漏洞是由于在BeanShell解释器中执行不可信输入而引发的，可导致任意代码执行。

  #### brokenAccessControl
  访问控制缺失漏洞使未经授权的用户可以访问受限数据或功能，可能会影响数据的机密性和完整性。

  #### businessLogicVuln
  业务逻辑漏洞是由应用程序逻辑设计缺陷引起的，可能导致意料之外的行为或应用程序功能被滥用。

  #### clickjacking
  点击劫持攻击诱使用户点击看似无害的元素，导致在网站上执行未经用户意愿的操作。

  #### commandInjection
  命令注入漏洞允许攻击者在服务器上执行任意系统命令，可能导致系统的完全控制。

  #### corsConfig
  CORS（跨域资源共享）配置漏洞由于配置不当，允许未经授权的跨域请求。

  #### crossSiteScripting
  跨站脚本攻击（XSS）是指攻击者将恶意脚本注入到网页中，其他用户访问时会执行该脚本。

  #### cryptoVuln
  加密漏洞由于弱加密算法或不当的加密实现引起，可能导致数据泄露或被篡改。

  #### defaultCredentials
  默认凭证漏洞是指系统或应用程序使用容易被猜测的默认用户名和密码，导致未经授权访问。

  #### groovyInjection
  Groovy注入漏洞是当用户输入被执行为Groovy脚本的一部分时，可能导致任意代码执行。

  #### hardcodedCredentials
  硬编码凭证指将静态的用户名和密码嵌入到代码中，容易被攻击者提取并进行未经授权的访问。

  #### headerInjection
  头部注入是指通过未经验证的用户输入操纵HTTP头部，可能导致响应分割或跨站脚本攻击。

  #### insecureDirectObjectReference
  不安全的直接对象引用漏洞允许攻击者通过操纵引用直接访问资源，绕过授权控制。

  #### jndiInjection
  JNDI注入涉及将不可信的数据注入JNDI查找中，可能导致远程代码执行或数据泄露。

  #### jsonpCallback
  JSONP回调漏洞是当不受信任的JSONP端点允许攻击者在响应中包含恶意JavaScript，从而引发XSS攻击。

  #### ldapInjection
  LDAP注入漏洞发生在用户输入不当使用于LDAP查询时，攻击者可操控LDAP语句，访问未经授权的数据。

  #### misconfig
  配置不当漏洞是由软件的不正确或不安全配置引起的，使系统容易受到各种攻击。

  #### mvelInjection
  MVEL注入漏洞是由于用户输入被用于MVEL表达式中，且未进行适当的验证，可能导致任意代码执行。

  #### onglInjection
  ONGL注入漏洞是当用户输入在ONGL表达式中被执行，未经过验证时，攻击者可以执行意外命令。

  #### openRedirect
  开放重定向漏洞允许攻击者将用户重定向到恶意网站，通常通过未验证的URL参数实现。

  #### pathTraversal
  路径遍历漏洞允许攻击者通过操控文件路径参数读取或写入服务器上的任意文件。

  #### regularExpressionDOS
  正则表达式拒绝服务（ReDoS）是指攻击者利用应用程序的正则表达式实现导致资源耗尽，进而引发拒绝服务攻击。

  #### scriptEngineInjection
  脚本引擎注入涉及在脚本引擎中执行不受信任的输入，可能导致任意代码执行。

  #### securityHeaderMissing
  缺少安全头部漏洞是由于HTTP响应中未包含关键的安全头部，导致应用程序容易受到各种攻击。

  #### sensitiveDataExposure
  敏感数据泄露是指应用程序未对敏感信息进行充分保护，导致数据被盗或被滥用的风险。

  #### serverSideRequestForgery
  服务器端请求伪造（SSRF）允许攻击者从服务器发起请求，访问内部或外部系统，可能导致信息泄露。

  #### spelInjection
  SPEL注入漏洞是由于用户输入未经验证便用于Spring表达式语言（SpEL）中，可能导致任意代码执行。

  #### sqlInjection
  SQL注入漏洞允许攻击者操控SQL查询，可能导致未经授权的数据访问或数据库篡改。

  #### templateInjection
  模板注入漏洞是指不受信任的输入被注入到模板引擎中，可能导致代码执行和应用程序被攻陷。

  #### thirdParty
  第三方漏洞是指由应用程序集成的第三方库或依赖项中的弱点引发的安全问题。

  #### unsafeDeserialization
  不安全反序列化漏洞发生在对不受信任的数据进行反序列化时，攻击者可能借此执行任意代码。

  #### weakPassword
  弱密码漏洞是由于使用容易猜测或不够复杂的密码，导致密码容易被暴力破解。

  #### xmlExternalEntity
  XML外部实体（XXE）漏洞发生在对包含外部实体引用的XML输入处理不当时，可能导致文件泄露或服务器端请求伪造。

  #### yamlDeserialization
  YAML反序列化漏洞是当对用户控制的YAML数据进行反序列化而未进行适当验证时，可能导致任意代码执行。

</details>

<details>
  <summary>部署指南（以阿里云服务器为例）</summary>

- 按照以下步骤部署，预计耗时约10分钟。

### LINUX环境下的操作
```bash
# 安装基础环境和依赖
yum install git maven -y
wget https://mirrors.estointernet.in/apache/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.tar.gz
tar -xvf apache-maven-3.6.3-bin.tar.gz
mv apache-maven-3.6.3 /opt/
wget https://download.oracle.com/java/17/latest/jdk-17_linux-x64_bin.tar.gz
tar xf jdk-17_linux-x64_bin.tar.gz
mv jdk-17.0.7/ /usr/lib/jvm

# 更新配置
rm -rf /opt/apache-maven-3.6.3/conf/settings.xml
vi /opt/apache-maven-3.6.3/conf/settings.xml
# 参考“settings.xml”节配置源

vi /etc/profile
# 设置Java和Maven环境
export M2_HOME='/opt/apache-maven-3.6.3'
export JAVA_HOME=/usr/lib/jvm/jdk-17.0.7
export CLASSPATH=$JAVA_HOME/lib/tools.jar:$JAVA_HOME/lib/dt.jar:$JAVA_HOME/lib
export PATH=$M2_HOME/bin:$JAVA_HOME/bin:$PATH

source /etc/profile

# 下载项目文件
git clone https://github.com/zgimszhd61/java-sec-code-plus.git
cd java-sec-code-plus

# 编译和运行
mvn install
mvn package
```

### 启动应用
```bash
mvn spring-boot:run
```

### 注意事项
- 默认监听8080端口，若使用阿里云，请在安全组中允许8080端口访问。
- 若要使用80端口，请在 `pom.xml` 文件中调整配置。

### settings.xml 配置示例
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
    <!-- 其他阿里云仓库配置同理 -->
  </mirrors>
</settings>
```


## 如果80或8080端口被占用
```bash
# 查找占用进程并结束
lsof -i:8080 
kill -9 [PID]
```
</details>

<details>
  <summary>漏洞验证接口</summary>
- 下面是一些用于安全测试的API接口示例：

```bash
# XSS攻击测试
GET http://localhost:80/api/xss/bad?name=<script>alert(1)</script>

# SSRF攻击测试
GET http://localhost:80/api/ssrf/bad?url=http://localhost:80/api/xss/bad?name=<script>alert(1)</script>

# 远程代码执行测试
GET http://localhost:80/api/rce/bad02?cmd=ls

# XXE攻击测试
GET http://localhost:80/api/xxe/bad01?xml=<!DOCTYPE doc [<!ENTITY xxe SYSTEM \"http://127.0.0.1:1664\">]><doc>&xxe;</doc>

# JSONP攻击测试
GET http://localhost:80/api/jsonp/bad01?callback=<script>alert(1)</script>

# SPEL攻击测试
GET http://localhost:80/api/spel/bad01?cmd=vulnhere
```
</details>

<details>
  <summary>应用场景</summary>
- **安全防护产品测试**：
  - IDE插件测试
  - WAF能力测试
  - 白盒、黑盒、IAST扫描测试
  - 供应链安全产品测试
- **人工代码审计学习**
</details>

## 看到类似截图内容表明部署运行成功
- 访问：http://localhost:8080/hi ,确认各个路由正常可用.
![image](https://github.com/user-attachments/assets/025d993a-59b1-420d-9c69-aa0617e18dfc)
