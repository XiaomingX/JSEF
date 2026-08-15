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
java -jar target/java-sec-code-plus-1.2.0.jar
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

Samples are graded **L0-L5** (each level increases reasoning distance and semantic dependency to separate tools/models by tier; L0 is the capability baseline that all tools/models should hit):

| Level | Meaning | Example |
|-------|---------|---------|
| L0 | Capability baseline (explicit direct) | source passed straight to sink, no intermediate |
| L1 | Single-hop direct | `Runtime.exec(userInput)` |
| L2 | Multi-hop (no break) | source -> intermediate var -> builder -> sink |
| L3 | Indirect / cross-method | taint via Map/field; via method return value across functions |
| L4 | Cross-file / framework semantics | Controller -> ServiceA -> ServiceB -> sink; Spring4Shell SpEL semantics |
| L5 | gadget chain | multiple safe classes combined into dangerous reachability (CC deserialization chain abstraction) |

Beyond the base grading, two "long-horizon / complex task" sample families specifically validate LLM **planning** and **consistency**:
- **Long-horizon tasks (LT series)**: cross-file tracing / framework state machine / gadget chain reconstruction / multi-hop concatenation / version gating — see [`benchmark/README.md`](benchmark/README.md) §3.
- **Code quality / performance DoS + LGTM gaps (PERF/TB/REFLECT/FMT/HOST/XSLT/FWD/SEED series)**: slow SQL, resource leaks, reflection injection, trust boundary, format-string injection, etc., aligned with the LGTM/CodeQL Java rule pack.

### Current Sample Scale

> Data source: `benchmark/expectedresults.csv` (source of truth, kept in two-way sync with `// [CHECKPOINT]` annotations in source; `validate_checkpoints.py` exits 0)

- **503** machine-readable checkpoint annotations (covering existing `src/main` vulnerabilities + `benchmark/cases` gradient samples + long-horizon tasks + code-quality/perf-DoS + LGTM-gap + logic-flaw samples + **atomic-paradigm families TCM/SBM/DBG/STR**)
- **268 VULN** (should be reported) + **235 SAFE** (should not be reported, used to compute TN/FP)
- Difficulty distribution: L0 x 18, L1 x 139, L2 x 106, L3 x 115, L4 x 86, L5 x 39 (full L0-L5 gradient)
- CWE coverage: **69 categories** (VULN only). Top: Expression Injection (917) x 25, Deserialization (502) x 21, SQLi (89) x 17, Command Injection (78) x 12, Authorization Bypass (285) x 10, Hardcoded Credentials/Key (798) x 7, Business Logic (840) x 7, SSRF (918) x 6, IDOR (639) x 6, Path Traversal (22) x 5, ReDoS (1333) x 5, Performance DoS (400) x 5
- Covers **121 categories** (slug), including all OWASP Top 10 2021 classes; **65** samples carry `trace=` path nodes (enables `--check-trace` path-correctness scoring)
- Special families: Long-horizon (LT) x 16, Code-quality/Perf-DoS (PERF) x 15, Trust-boundary (TB)/Reflection (REFLECT)/Format-string (FMT)/Hostname (HOST)/XSLT (XSLT)/Forward (FWD)/Seed (SEED) x 2 each
- **Atomic-paradigm families (TCM/SBM/DBG/STR)** x 64: distilled from real Fastjson / Spring Boot / Dubbo / Struts2 0day/1day into **library-agnostic** atomic danger patterns, reproduced self-contained with pure Java standard library.

### Atomic-Paradigm Families (TCM / SBM / DBG / STR)

To assess whether LLMs / harnesses can detect **same-principle** vulnerabilities, JSEF distills real 0day/1day from recent high-impact frameworks (Fastjson, Spring Boot, Dubbo, Struts2) into **library-agnostic** atomic danger patterns, and builds complex samples that share the same root cause but are decoupled from the original framework. Each family ships `vuln` + `sec` counterparts (for FP/TN) and is graded L1–L5, all carrying `// [CHECKPOINT]` annotations and **no original-framework class names** (pure standard-library semantics).

| Namespace | Distilled from | Atomic paradigm dimensions (MECE, non-overlapping) | Samples |
|-----------|----------------|---------------------------------------------------|---------|
| **TCM** | Fastjson deserialization | TCM-1 direct type selection · TCM-2 inheritance allowlist bypass · TCM-3 cache/second-parse bypass · TCM-4 private-field binding · TCM-5 property-as-code (dangerous getter/setter) | 20 |
| **SBM** | Spring Boot | SBM-1 binder traversal · SBM-2 declarative-config-as-expression · SBM-3 privileged-endpoint exposure · SBM-4 authz short-circuit bypass | 16 |
| **DBG** | Dubbo RPC | DBG-1 parser/format negotiation switch · DBG-2 cross-trust-boundary implicit trust (attachment) · DBG-3 class-name denylist bypass by encoding | 16 |
| **STR** | Struts2/OGNL | STR-1 double evaluation · STR-2 protocol-layer field injection · STR-3 eval exclusion-list / sandbox bypass | 12 |

**Design notes**:
- Abstraction principle: strip framework-specific mechanisms (e.g. "JSON-library autotype", "Web-framework SpEL") and keep only the cross-framework invariant danger combination — attacker controls type/data + system auto-invokes implicit methods + implicit method chain reaches a dangerous sink.
- No overlap with existing samples: deliberately avoids the repo's existing `JSEF-OGNL-*`/`JSEF-SPEL-*` single-layer expression injection, `JSEF-DESER-*` direct deserialization, etc.; covers only the **unique, unmodeled** atomic dimensions (e.g. OGNL double evaluation, Spring4Shell binder traversal, Dubbo parser negotiation).
- High discrimination: includes L4 cross-file, L5 gadget-chain, and cross-method-chain hard cases to separate tool/model capability tiers.
- Safety baseline: all dangerous calls are localhost-demo placeholders; no real exploit scripts.

Sample location: `benchmark/cases/{vuln,sec}/{tcm,sbm,dbg,str}/`; design docs: `plans/02-~05-*.md`.

Sample organization:
- `benchmark/cases/vuln/` and `benchmark/cases/sec/`: discriminating-difficulty gradient samples (with safe counterparts)
- `benchmark/cases/vuln/longtask/` and `benchmark/cases/vuln/perf/`: long-horizon and code-quality/perf-DoS dedicated samples
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