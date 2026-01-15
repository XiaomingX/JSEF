# Java Security Education Framework (JSEF) - Spring Boot Security Practice Platform
[![GitHub Stars](https://img.shields.io/github/stars/XiaomingX/JSEF?style=social&label=Star%20This%20Repo)](https://github.com/XiaomingX/JSEF)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Java Version](https://img.shields.io/badge/Java-17%2B-blue.svg)](https://www.oracle.com/java/technologies/downloads/#java17)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-orange.svg)](https://spring.io/projects/spring-boot)
[![Docker Ready](https://img.shields.io/badge/Docker-Supported-blue.svg)](docs/docker-deployment.md)

> A **reproducible, practical, and learnable** Spring Boot web security experiment framework that helps developers quickly master the principles of web security vulnerabilities and defense solutions.


## 📖 Project Introduction
**Java Security Education Framework (JSEF)** is a web security practice platform built on Spring Boot 3.x, designed specifically for **developers, security researchers, university students, and corporate training**. Through **35+ real-world business scenario-based security vulnerability examples** (covering core types such as injection attacks, privilege escalation, and sensitive information leakage), it provides a complete learning loop of "**Principle Explanation → Vulnerability Reproduction → Code Comparison → Fix Verification**", helping learners quickly grasp core web security capabilities from "theory" to "practice".

This project does not rely on complex environments, supporting one-click local startup and Docker deployment. All vulnerability cases are designed based on real business logic, avoiding "vulnerabilities created merely for demonstration purposes" and being more aligned with actual development scenarios.

**New Structure Note:** The project code has been refactored. All vulnerability-related controllers are now located under the `com.freedom.securitysamples.vulnerability` package. Each vulnerability category is further divided into `vuln` (containing insecure/vulnerable implementations) and `sec` (containing secure/fixed implementations) sub-packages for direct comparative learning. API routes have also been unified to the format `/api/v1/{vulnerability-type}/unsafe/{scenario}` and `/api/v1/{vulnerability-type}/safe/{scenario}`.


## 🔥 Core Advantages (Why Choose JSEF?)
| Advantage | Detailed Description |
|-----------|----------------------|
| **Real Reproducible Vulnerability Examples** | 35+ vulnerabilities covering all OWASP Top 10 categories, each simulating real business scenarios (e.g., user login, data query, file upload). |
| **Complete Learning Loop** | Each vulnerability is equipped with: principle documentation + reproduction steps + insecure code + secure code comparison + defense best practices. |
| **Zero-Threshold Deployment** | Supports one-click startup via `mvn` and Docker containerization, no manual database/middleware configuration required. |
| **Clear Code Standards** | Adopts Spring Boot best practices for coding; insecure and secure code are now separated into `vuln`/`sec` directories for easy comparative learning. |
| **Rich Resource Ecosystem** | Built-in API documentation, vulnerability reproduction manual, and secure coding standards; continuously updates with the latest CVE vulnerability cases. |
| **High Extensibility** | Provides a pluggable vulnerability case interface, supporting developers to customize and add new vulnerability scenarios or extend defense solutions. |


## 🚀 Quick Start
### Environment Requirements
- JDK 17 or higher
- Maven 3.6+ or Gradle 8.0+
- Git (optional, for cloning the repository)
- Docker (optional, for containerized deployment)

### Method 1: Local Maven Startup (Recommended for Beginners)
```bash
# 1. Clone the repository (or download the ZIP package directly)
git clone --depth 1 https://github.com/XiaomingX/JSEF.git
cd JSEF

# 2. Build the project (skip tests to speed up the build)
mvn clean package -DskipTests

# 3. Start the service
java -jar target/java-sec-code-plus-0.0.1-SNAPSHOT.jar
```

### Method 2: One-Click Docker Deployment
```bash
# 1. Build the image
docker build -t jsef-security-sample:latest .

# 2. Start the container
docker run -d -p 8080:8080 --name jsef-demo jsef-security-sample:latest
```

### Verify Successful Deployment
After startup, access the following addresses:
- Project Homepage: `http://localhost:8080` (view project navigation and vulnerability list)
- API Documentation (Swagger): `http://localhost:8080/swagger-ui/index.html` (view details of all vulnerability interfaces)
- Vulnerability Manual: `http://localhost:8080/docs` (view online vulnerability reproduction guide)


## 📋 Vulnerability Case Categories (Full List of 35+)
For a detailed list of all implemented vulnerability cases, please refer to [VULNERABILITIES-en.md](VULNERABILITIES-en.md).

## 🎯 Application Scenarios
| User Group | Application Scenario |
|------------|----------------------|
| **Developers** | Learn secure coding standards to avoid writing vulnerable code in projects. |
| **Security Researchers** | Reproduce vulnerability principles, verify the effectiveness of defense solutions, and build test environments for security tools. |
| **University Teachers & Students** | Experimental platform for information security/cyber security courses, replacing traditional demonstration-based experiments. |
| **Corporate Training** | Secure coding training for development teams, hands-on practice for penetration testing teams. |
| **CTF Players** | Hands-on practice for basic vulnerabilities, familiarizing with common vulnerability exploitation techniques. |


## 📚 Official Documentation
- [📥 Deployment Guide](docs/deployment.md): Full deployment solutions for local/Mac/Linux/Windows/Docker
- [🔍 Vulnerability Reproduction Guide](docs/vulnerability-guide.md): Detailed reproduction steps for each vulnerability (including Payload examples)
- [💻 API Reference](docs/api-reference.md): Description of request parameters and response formats for all interfaces (supports Swagger online debugging)
- [🛡️ Secure Coding Guide](docs/secure-coding-guide.md): Spring Boot-based secure coding best practices
- [📌 Guide to Adding New Vulnerabilities](docs/contribute-vulnerability.md): How to add new vulnerability cases to the project
- [🎥 Video Tutorials](https://github.com/XiaomingX/JSEF/wiki/Video-Tutorials): Bilibili-supported vulnerability reproduction videos (continuously updated)


## 🤝 How to Contribute
This project welcomes all forms of contributions. Whether it’s **adding new vulnerability cases, improving documentation, fixing code issues, or suggesting features**, your help can enable more people to learn web security!

### Contribution Methods
1. **Submit an Issue**: Report vulnerabilities, suggest features, or report bugs (it’s recommended to search for existing similar Issues first)
2. **Submit a PR**:
   - Fix code issues (e.g., typos, logic optimizations)
   - Add new vulnerability cases (must follow the [Guide to Adding New Vulnerabilities](docs/contribute-vulnerability.md))
   - Improve documentation (e.g., supplement reproduction steps, translate English documents)
3. **Share & Promote**: Star this project and share your user experience in technical communities to help more people discover JSEF

### Newcomer-Friendly Contributions
- [Good First Issues](https://github.com/XiaomingX/JSEF/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22): Entry-level tasks suitable for newcomers (e.g., supplementing documentation, improving code comments)


## 📄 Open Source License
This project is open-source under the **MIT License**, allowing:
- Free use for personal learning, corporate training, and commercial product testing
- Modification and distribution of project code (original author’s copyright notice must be retained)
- Secondary development based on this project (source must be indicated)

**Prohibited**: Using this project for unauthorized penetration testing, malicious attacks, or other illegal activities.


## ⭐ Star History
[![Star History Chart](https://api.star-history.com/svg?repos=XiaomingX/JSEF&type=Date)](https://star-history.com/#XiaomingX/JSEF&Date)


## 🙏 Acknowledgements
- Thanks to [OWASP](https://owasp.org/) for providing web security standards and vulnerability classification frameworks
- Thanks to the Spring community for supporting the Spring Boot ecosystem
- Thanks to all contributors for their code submissions and feedback ([Contributors](https://github.com/XiaomingX/JSEF/graphs/contributors))
- Thanks to technical bloggers in the security community for sharing vulnerability principles


## ⚠️ Disclaimer
This project is for **learning, research, and internal corporate security training purposes only**. Do not use it for any unauthorized testing, attacks, or destructive activities. The user shall bear all legal liabilities arising from the use of this project.