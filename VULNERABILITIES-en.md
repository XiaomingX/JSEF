# Vulnerability Cases in JSEF (English)

This document provides a comprehensive list of all vulnerability examples implemented in the Java Security Education Framework (JSEF), categorized for easier navigation and study. Each entry represents a unique security flaw, often accompanied by both insecure and secure code implementations.

> The repository currently contains **503** machine-readable `// [CHECKPOINT]` annotations (covering existing `src/main` vulnerabilities + `benchmark/cases` gradient samples + long-range tasks + code-quality/performance-DoS + LGTM gaps + logic vulnerabilities + **atomic-paradigm families TCM/SBM/DBG/STR**), with **268 VULN** + **235 SAFE** across **69 CWE categories** and **121 categories** (slug). The families below list representative implemented cases (not an exhaustive enumeration; the full list is in `benchmark/expectedresults.csv`).

---

## 📋 Vulnerability Case Categories (50+ Vulnerability Families Covered)

### 1. Injection Vulnerabilities
- SQL Injection: Basic concatenation, multi-field concatenation, prepared-statement comparison (with safe confusion samples)
- Command Injection: Misuse of Runtime.exec(), ProcessBuilder injection, cross-file call-chain taint
- Expression / Script-Engine Injection (the expression-injection family):
  - SpEL Injection (incl. Spring4Shell `class.module.classLoader` framework-semantics case)
  - Groovy Injection (GroovyShell / GroovyScriptEvaluator)
  - MVEL Injection (MVEL.eval / executeExpression)
  - BeanShell Injection (BshScriptEvaluator / Runtime.exec)
  - OGNL Injection (Ognl.getValue / Runtime.exec)
  - ScriptEngine Injection (ScriptEngine.eval / CompiledScript.eval)
  - JNDI Injection (InitialContext.lookup / RMI)
  - Log4j JNDI Injection (CVE-2021-44228 abstraction)
- Template Injection: FreeMarker / Thymeleaf view-name/content concatenation (CWE-1336)
- XSS: Reflected XSS (with safe confusion sample)
- LDAP Injection: Directory-service query injection scenarios and defense
- XPath Injection: XPath.compile / DOMXPath.selectNodes
- XML External Entity (XXE): Information leakage from undisabled DTD in DocumentBuilder (with safe-config counterpart)
- NoSQL Injection: Spring Data Mongo indirect taint (CWE-943)
- Server-Side Request Forgery (SSRF): Internal service access and data theft (with intranet-IP-whitelist SAFE confusion)

### 2. Broken Authentication & Access Control
- Authentication Bypass: Cookie/role forgery, missing session checks (CWE-287)
- Authorization Bypass / Privilege Escalation: Horizontal & vertical privilege escalation (CWE-285)
- IDOR (Insecure Direct Object Reference): Missing object-ownership semantics + safe ownership-checked confusion sample (CWE-639)
- Weak Password Risks: Plaintext password verification, complexity bypass (CWE-521)
- Default Credentials: Unchanged default admin username/password (CWE-798)
- JWT Vulnerabilities: alg=none / weak key / hardcoded + loose-validation confusion (CWE-345)

### 3. Sensitive Data Exposure
- Sensitive Data in Response: Plaintext password / ID card / credit card in response body (CWE-532)
- Weak Hash Storage: MD5/SHA1 plaintext-password hashing (CWE-327, with PBKDF2 fix counterpart)
- Hardcoded Credentials / Keys: Hardcoded DB connection, hardcoded AES key (CWE-798 / CWE-798 ECB)
- Error-Page Leakage / Log Leakage: Stack-trace and configuration exposure (teaching examples)

### 4. Security Misconfiguration
- Improper Numeric and Date Input Validation: Large-number DoS, format ambiguity (CWE-20)
- Default Password Risks (see Section 2)
- Insecure HTTP Methods / Open Redirect: Missing redirect-URL whitelist, `redirect:` prefix bypass (CWE-601, with whitelist SAFE)
- Improper CORS Configuration: Access-Control-Allow-Origin:* over-permissive cross-origin (CWE-942)
- Clickjacking / Missing Security Headers: Missing X-Frame-Options / CSP (CWE-1021, with header-set SAFE)
- Missing Rate Limiting: SMS OTP without throttling (CWE-307, with rate-limited SAFE)

### 5. Deserialization & Other High-Risk Vulnerabilities
- Java Native Deserialization: ObjectInputStream.readObject, Jackson enableDefaultTyping, CC gadget chain (CWE-502, incl. L5 gadget-chain case)
- Fastjson Deserialization: JSON.parseObject / AutoType (CWE-502)
- Jackson Polymorphic Deserialization: @JsonTypeInfo missing allowlist (CWE-502, with allowlist SAFE)
- YAML Deserialization: SnakeYAML load/loadAs (CWE-502)
- Dependency-related CVE cases:
  - Spring AMQP Deserialization (CVE-2023-34050, with allowlist SAFE)
  - Redisson Deserialization (CVE-2023-42809, with allowlist SAFE)
- Race Condition: Non-atomic read-modify-write (CWE-362, with synchronized SAFE)
- Hash Collision Attack: HashMap user-controlled key performance degradation DoS (CWE-694, with SHA-256 key SAFE)
- ReDoS: Catastrophic-backtracking regex `(a+)+b` (CWE-1333)
- Path Traversal: Directory traversal to read system files (CWE-22, with Files.newInputStream SAFE)
- Mass Assignment: @RequestBody binds isAdmin (CWE-915, with DTO SAFE)
- JSONP Callback Injection: callback string concatenation (CWE-352)
- Header Injection: HttpHeaders.add injection (CWE-113)
- Risky Operations: sun.misc.Unsafe arbitrary memory read (CWE-111)
- Business Logic Flaws: Balance tampering without sign check, price tampering, coupon abuse, inventory oversell (CWE-840, with coupon SAFE)

### 6. Atomic-Paradigm Families (TCM / SBM / DBG / STR, library-decoupled principle restoration)

To evaluate whether LLMs / harnesses can detect vulnerabilities of the **same underlying principle**, JSEF abstracts framework-agnostic atomic danger patterns from recent real-world 0day/1day in high-risk frameworks (Fastjson, Spring Boot, Dubbo, Struts2), reproduced self-contained with pure Java standard library. Each family ships `vuln` + `sec` pairs, graded L1–L5, all carrying `// [CHECKPOINT]` annotations and avoiding the original framework class names. See the "Atomic-Paradigm Families" section in `README.md`.

| Namespace | Abstracted from | Atomic-paradigm dimensions (MECE, non-overlapping) | Samples |
|---------|--------|-------------------------------|--------|
| **TCM** | Fastjson deserialization | TCM-1 direct type selection · TCM-2 inheritance allowlist bypass · TCM-3 parser/cache second-parse bypass · TCM-4 private field controllable · TCM-5 property-as-code (dangerous getter/setter) | 20 |
| **SBM** | Spring Boot | SBM-1 binder traversal · SBM-2 declarative config evaluated as expression · SBM-3 privileged endpoint exposure · SBM-4 authorization short-circuit bypass | 16 |
| **DBG** | Dubbo RPC | DBG-1 parser/format negotiation switch · DBG-2 cross-trust-domain implicit trust (attachment) · DBG-3 classname denylist bypass via encoding | 16 |
| **STR** | Struts2/OGNL | STR-1 double evaluation · STR-2 protocol-layer field injection · STR-3 expression exclusion-list/sandbox bypass | 12 |

**Note:** Some CVEs, such as CVE-2023-34034 (Spring WebFlux Authorization Bypass) and CVE-2023-44487 (HTTP/2 Rapid Reset Attack), are related to the Spring WebFlux framework or are low-level network protocol issues. They are not directly applicable to this Spring MVC project or are difficult to demonstrate in simple controllers. Therefore, they are only noted and not implemented as specific tutorial cases.