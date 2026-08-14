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


## 🔬 SAST Capability & Multi-Model Vulnerability-Hunting Benchmark

JSEF is not only a teaching platform, but also ships a benchmark for **validating basic SAST capabilities** and **comparing vulnerability-hunting ability across multiple LLMs**. The design is based on first principles of SAST (proof of untrusted-data reachability from source to sink). Samples carry a discriminating-difficulty gradient, making it easy to cross-compare false positives, false negatives, average time, timeouts, report conciseness, and coverage completeness.

### Core Capabilities

| Capability Dimension | Description |
|----------------------|-------------|
| Taint propagation (no variable break) | Single-hop / multi-hop / indirect (Map/field) gradient, checking whether intermediate variables drop taint |
| State machine / call-chain tracking | Cross-method / cross-file / gadget chain, checking reachability analysis depth |
| Framework semantics understanding | Spring parameter binding, SpEL, `@RequestParam`-driven implicit source/sink |
| False-positive suppression | OWASP-style true/false confusion samples, checking discrimination of "looks dangerous but safe" code |

### Samples & Difficulty Grading

Samples are graded **L1-L5** (each level increases reasoning distance and semantic dependency to separate tools/models by tier; L0 is only a capability baseline reference, see `MY_PLAN.md` A3 — no sample is currently tagged L0):

| Level | Meaning | Example |
|-------|---------|---------|
| L1 | Single-hop direct | `Runtime.exec(userInput)` |
| L2 | Multi-hop (no break) | source -> intermediate var -> builder -> sink |
| L3 | Indirect / cross-method | taint via Map/field; via method return value across functions |
| L4 | Cross-file / framework semantics | Controller -> ServiceA -> ServiceB -> sink; Spring4Shell SpEL semantics |
| L5 | gadget chain | multiple safe classes combined into dangerous reachability (CC deserialization chain abstraction) |

### Current Sample Scale

> Data source: `benchmark/expectedresults.csv` (source of truth, kept in two-way sync with `// [CHECKPOINT]` annotations in source, 133 entries total)

- **133** machine-readable checkpoint annotations (covering existing `src/main` vulnerabilities + `benchmark/cases` gradient samples)
- **93 VULN** (should be reported) + **40 SAFE** (should not be reported, used to compute TN/FP)
- Difficulty distribution: L1 x 89, L2 x 17, L3 x 16, L4 x 8, L5 x 3
- CWE coverage (34 categories, VULN only): Expression Injection (917) x 18, Deserialization (502) x 12, Command Injection (78) x 9, Hardcoded Credentials/Key (798) x 5, SQLi (89) x 4, Business Logic (840) x 4, Template Injection (1336) x 3, Clickjacking/Missing Security Header (1021) x 3, XPath (643) x 2, LDAP (90) x 2, SSRF (918) x 2, XXE (611) x 2, IDOR (639) x 2, Weak Hash (327) x 2, Auth Bypass (287) x 2, Authorization Bypass (285) x 2, Open Redirect (601) x 2, plus Path Traversal (22)/Weak Random (330)/XSS (79)/NoSQL (943)/JWT (345)/CORS (942)/Weak Password (521)/Sensitive Data Exposure (532)/Mass Assignment (915)/Race Condition (362)/Numeric Input (20)/Missing Rate Limiting (307)/ReDoS (1333)/Hash Collision (694)/JSONP (352)/Header Injection (113)/Risky Operations (111) x 1 each

Sample organization:
- `benchmark/cases/vuln/` and `benchmark/cases/sec/`: discriminating-difficulty gradient samples (with safe counterparts)
- `benchmark/cases/vendor/`: high-quality competitor samples abstracted from OWASP Benchmark / Juliet / PrimeVul / CVEfixes, with source-URL provenance

### How to Run & Cross-Compare

1. Start JSEF: `mvn clean package -DskipTests && java -jar target/*.jar`
2. Select the subject under test: a SAST tool (CodeQL/SonarQube/Snyk) + an LLM (switch models in Claude Code, using the same prompt `benchmark/prompts/vuln_hunt.md`)
3. Each subject scans `benchmark/cases/` once, producing SARIF or `id -> {hit,file,line}` results, recording time
4. Run the scoring script for cross-comparison metrics (from repo root):
   ```bash
   python3 benchmark/scripts/scorecard.py --expected benchmark/expectedresults.csv --result <result.json|.sarif> --name <subject-name>
   ```
   Outputs Recall / Precision / **Youden Score (TPR - FPR)** / average time / timeout count / report conciseness / coverage completeness, grouped by CWE and level.

See [`benchmark/README.md`](benchmark/README.md) and [`MY_PLAN.md`](MY_PLAN.md) for detailed design and protocol.


## 📚 Official Documentation
- [📊 Benchmark Design & Protocol](benchmark/README.md): usage and extension of the SAST/LLM vulnerability-hunting acceptance benchmark
- [🗺️ Benchmark Implementation Plan](MY_PLAN.md): capability model, sample grading, and todo progress
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