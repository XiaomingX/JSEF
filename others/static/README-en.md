# Java-Sec-Code-Plus

## Introduction

**Java-Sec-Code-Plus** is a security education framework built on SpringBoot. It provides comprehensive tutorials to help users quickly deploy and run the platform.

### Project Goals
- To create a one-stop solution for evaluating and improving system security.

## Quick Start Guide

Clone the repository and run the application using the following commands:

```bash
git clone --depth 1 https://github.com/zgimszhd61/java-sec-code-plus
mvn install
mvn spring-boot:run
```

## Supported Vulnerabilities

<details>
  <summary>Click to view supported vulnerabilities</summary>

  - **authBypass**: Authentication bypass vulnerabilities allow attackers to access restricted areas or functions without proper authorization.
  - **authorizationBypass**: Authorization bypass occurs when attackers gain access to resources beyond their privileges due to flaws in permission validation.
  - **beanShellInjection**: BeanShell injection vulnerabilities occur when untrusted input is executed in a BeanShell interpreter, leading to arbitrary code execution.
  - **brokenAccessControl**: Broken access control enables unauthorized users to access restricted data or functions, affecting data confidentiality and integrity.
  - **businessLogicVuln**: Business logic flaws are vulnerabilities in the application's design, leading to unintended behavior or functionality abuse.
  - **clickjacking**: Clickjacking tricks users into clicking concealed elements, resulting in unintended actions on a website.
  - **commandInjection**: Command injection allows attackers to execute arbitrary system commands on the server, potentially leading to full system compromise.
  - **corsConfig**: CORS (Cross-Origin Resource Sharing) misconfigurations allow unauthorized cross-origin requests.
  - **crossSiteScripting (XSS)**: Cross-site scripting enables attackers to inject malicious scripts into web pages viewed by other users.
  - **cryptoVuln**: Cryptographic vulnerabilities arise from weak algorithms or improper encryption implementation, potentially leading to data leakage.
  - **defaultCredentials**: Default credentials involve using easily guessable default usernames and passwords, leading to unauthorized access.
  - **groovyInjection**: Groovy injection vulnerabilities occur when untrusted user input is executed as part of a Groovy script, leading to code execution.
  - **hardcodedCredentials**: Hardcoded credentials involve embedding static usernames and passwords in code, which are easy for attackers to extract.
  - **headerInjection**: Header injection vulnerabilities allow attackers to manipulate HTTP headers, leading to response splitting or XSS.
  - **insecureDirectObjectReference**: Insecure direct object references allow attackers to manipulate references to access unauthorized resources.
  - **jndiInjection**: JNDI injection involves injecting untrusted data into JNDI lookups, potentially leading to remote code execution.
  - **jsonpCallback**: JSONP callback vulnerabilities allow attackers to inject malicious JavaScript through untrusted JSONP endpoints, resulting in XSS attacks.
  - **ldapInjection**: LDAP injection occurs when user input is improperly used in LDAP queries, allowing attackers to manipulate LDAP statements.
  - **misconfig**: Misconfiguration vulnerabilities result from insecure configurations, making systems vulnerable to various attacks.
  - **mvelInjection**: MVEL injection vulnerabilities occur when untrusted input is used in MVEL expressions, leading to code execution.
  - **onglInjection**: OGNL injection vulnerabilities occur when untrusted input is evaluated as an OGNL expression, leading to unintended command execution.
  - **openRedirect**: Open redirects allow attackers to redirect users to malicious websites via unvalidated URL parameters.
  - **pathTraversal**: Path traversal vulnerabilities allow attackers to read or write arbitrary files on the server by manipulating file path parameters.
  - **regularExpressionDOS (ReDoS)**: ReDoS occurs when attackers exploit regular expressions to exhaust system resources, causing denial of service.
  - **scriptEngineInjection**: Script engine injection allows attackers to execute arbitrary code by injecting untrusted input into the scripting engine.
  - **securityHeaderMissing**: Missing security headers in HTTP responses leave applications vulnerable to a range of attacks.
  - **sensitiveDataExposure**: Sensitive data exposure occurs when applications fail to adequately protect sensitive information, risking data leakage or misuse.
  - **serverSideRequestForgery (SSRF)**: SSRF enables attackers to manipulate the server to make requests to internal or external resources, potentially leading to data leakage.
  - **spelInjection**: SpEL injection occurs when untrusted input is used in Spring Expression Language, allowing code execution.
  - **sqlInjection**: SQL injection vulnerabilities allow attackers to manipulate SQL queries, resulting in unauthorized access or data manipulation.
  - **templateInjection**: Template injection occurs when untrusted input is injected into template engines, leading to arbitrary code execution.
  - **thirdParty**: Third-party vulnerabilities arise from insecure third-party libraries or dependencies used in the application.
  - **unsafeDeserialization**: Unsafe deserialization allows attackers to execute arbitrary code during the deserialization of untrusted data.
  - **weakPassword**: Weak password vulnerabilities occur when passwords are easy to guess or lack complexity, making them vulnerable to brute-force attacks.
  - **xmlExternalEntity (XXE)**: XXE vulnerabilities occur when improperly handled XML input contains external entity references, leading to data leakage or SSRF.
  - **yamlDeserialization**: YAML deserialization vulnerabilities occur when untrusted YAML data is deserialized without proper validation, leading to code execution.

</details>

## Deployment Guide (Example with Alibaba Cloud)

<details>
  <summary>Click to view deployment instructions</summary>

To deploy on an Alibaba Cloud server, follow these steps. Estimated time: 10 minutes.

### Steps for LINUX Environment
```bash
# Install basic dependencies
yum install git maven -y
wget https://mirrors.estointernet.in/apache/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.tar.gz
tar -xvf apache-maven-3.6.3-bin.tar.gz
mv apache-maven-3.6.3 /opt/
wget https://download.oracle.com/java/17/latest/jdk-17_linux-x64_bin.tar.gz
tar xf jdk-17_linux-x64_bin.tar.gz
mv jdk-17.0.7/ /usr/lib/jvm

# Update configuration
rm -rf /opt/apache-maven-3.6.3/conf/settings.xml
vi /opt/apache-maven-3.6.3/conf/settings.xml
# Configure Maven mirror sources as shown in the "settings.xml" example

vi /etc/profile
# Set Java and Maven environment variables
export M2_HOME='/opt/apache-maven-3.6.3'
export JAVA_HOME=/usr/lib/jvm/jdk-17.0.7
export CLASSPATH=$JAVA_HOME/lib/tools.jar:$JAVA_HOME/lib/dt.jar:$JAVA_HOME/lib
export PATH=$M2_HOME/bin:$JAVA_HOME/bin:$PATH

source /etc/profile

# Clone the repository
git clone https://github.com/zgimszhd61/java-sec-code-plus.git
cd java-sec-code-plus

# Compile and package
mvn install
mvn package
```

### Start the Application
```bash
mvn spring-boot:run
```

### Notes
- The application listens on port `8080` by default. On Alibaba Cloud, make sure to allow access to port `8080` in the security group.
- To use port `80`, modify the configuration in the `pom.xml` file.

### Example `settings.xml` Configuration
```xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd">

  <mirrors>
    <mirror>
     <id>aliyunmaven</id>
     <mirrorOf>*</mirrorOf>
     <name>Aliyun Public Repository</name>
     <url>https://maven.aliyun.com/repository/public</url>
    </mirror>
    <!-- Additional Aliyun repositories can be configured similarly -->
  </mirrors>
</settings>
```
</details>

## If Port 80 or 8080 Is in Use

```bash
# Find and terminate the process occupying the port
lsof -i:8080
kill -9 [PID]
```

## Vulnerability Test Interfaces
Below are some example APIs for testing security vulnerabilities:

```bash
# XSS Attack Test
GET http://localhost:80/api/xss/bad?name=<script>alert(1)</script>

# SSRF Attack Test
GET http://localhost:80/api/ssrf/bad?url=http://localhost:80/api/xss/bad?name=<script>alert(1)</script>

# Remote Code Execution Test
GET http://localhost:80/api/rce/bad02?cmd=ls

# XXE Attack Test
GET http://localhost:80/api/xxe/bad01?xml=<!DOCTYPE doc [<!ENTITY xxe SYSTEM "http://127.0.0.1:1664">]><doc>&xxe;</doc>

# JSONP Attack Test
GET http://localhost:80/api/jsonp/bad01?callback=<script>alert(1)</script>

# SPEL Attack Test
GET http://localhost:80/api/spel/bad01?cmd=vulnhere
```

## Use Cases
- **Security Testing Products**:
  - IDE Plugin Testing
  - WAF Capability Testing
  - White-Box, Black-Box, IAST Scanning
  - Supply Chain Security Product Testing
- **Manual Code Review Training**

![image](https://github.com/user-attachments/assets/025d993a-59b1-420d-9c69-aa0617e18dfc)

