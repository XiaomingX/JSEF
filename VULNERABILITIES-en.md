# Vulnerability Cases in JSEF (English)

This document provides a comprehensive list of all vulnerability examples implemented in the Java Security Education Framework (JSEF), categorized for easier navigation and study. Each entry represents a unique security flaw, often accompanied by both insecure and secure code implementations.

---

## 📋 Vulnerability Case Categories (Full List of 35+)

### 1. Injection Vulnerabilities
- SQL Injection: Basic concatenation injection, error-based injection, blind injection, prepared statement comparison examples
- Command Injection: Misuse of Runtime.exec(), ProcessBuilder injection scenarios
- Template Injection: FreeMarker/Thymeleaf/Velocity injection cases
- SPEL Injection: Spring Expression Language injection vulnerabilities and defense
- XSS: Reflected XSS, Stored XSS, DOM-based XSS (including CSP defense demonstration)
- LDAP Injection: Directory service query injection scenarios and defense
- XML External Entity (XXE): Information leakage caused by improper XML parser configuration

### 2. Broken Authentication & Authorization Vulnerabilities
- Authentication Bypass: Cookie forgery, session fixation attacks
- Privilege Escalation: Horizontal Privilege Escalation (data access between users), Vertical Privilege Escalation (low-privilege access to admin interfaces)
- Weak Password Risks: Plaintext password verification, password complexity bypass
- JWT Vulnerabilities: Signature bypass, expiration time tampering, secret key leakage
- Session Management Flaws: Improper session timeout settings, session ID exposure

### 3. Sensitive Data Exposure
- Plaintext Transmission: Cookie/Token leakage due to unencrypted HTTP
- Error Page Leakage: Stack trace exposure, configuration information leakage
- Log Leakage: Plaintext logging of sensitive data (phone numbers, ID cards)
- Third-Party Dependency Leakage: Exposure of dependency component versions (including cases like CVE-2023-20860)
- Improper Password Storage: Plaintext storage, use of weak hashing algorithms (MD5/SHA1)

### 4. Security Misconfiguration
- Improper Numeric and Date Input Validation: Large Number DoS, Format Ambiguity Risk
- Default Password Risks: Unchanged default admin passwords
- Insecure HTTP Methods: Unauthorized access to PUT/DELETE methods
- Improper CORS Configuration: Overly permissive Cross-Origin Resource Sharing
- Cache Mechanism Vulnerabilities: Sensitive page caching leading to information leakage
- Missing Security Headers: Lack of protective headers such as CSP and X-Frame-Options

### 5. Other High-Risk Vulnerabilities
- Race Condition: Concurrent operations lead to data inconsistency
- Hash Collision Attack: HashMap performance degradation DoS
- File Upload Vulnerabilities: File extension bypass, MIME type spoofing, file content parsing vulnerabilities
- Path Traversal: Directory traversal to read system files (e.g., /etc/passwd)
- Deserialization Vulnerabilities: Remote code execution via Jackson/Gson deserialization
- Dependency Confusion: Supply chain attack demonstration (including dependency hijacking cases)
- Server-Side Request Forgery (SSRF): Internal service access and data theft
- Deserialization Vulnerabilities: Redisson Deserialization Vulnerability (CVE-2023-42809)
- Deserialization Vulnerabilities: Spring AMQP Deserialization Vulnerability (CVE-2023-34050)
- Deserialization Vulnerabilities: Misuse of Java serialization/deserialization mechanisms

**Note:** Some CVEs, such as CVE-2023-34034 (Spring WebFlux Authorization Bypass) and CVE-2023-44487 (HTTP/2 Rapid Reset Attack), are related to the Spring WebFlux framework or are low-level network protocol issues. They are not directly applicable to this Spring MVC project or are difficult to demonstrate in simple controllers. Therefore, they are only noted and not implemented as specific tutorial cases.