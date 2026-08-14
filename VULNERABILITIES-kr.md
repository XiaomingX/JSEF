# Vulnerability Cases in JSEF (Korean)

이 문서는 Java Security Education Framework (JSEF)에 구현된 모든 취약점 예시에 대한 포괄적인 목록을 제공하며, 쉬운 탐색 및 학습을 위해 분류되어 있습니다. 각 항목은 고유한 보안 결함을 나타내며, 종종 안전하지 않은 코드 구현과 안전한 코드 구현이 모두 함께 제공됩니다.

> 현재 리포지토리에는 **133건**의 기계 판독 가능 `// [CHECKPOINT]` 주석이 있으며（`src/main` 기존 취약점 + `benchmark/cases` 구배 샘플 포괄）, **93건의 VULN** + **40건의 SAFE**, **34종의 CWE**를 커버합니다. 아래는 구현된 대표 사례를 취약점 패밀리별로 정리한 것입니다（완전한 열거는 아니며, 전체 목록은 `benchmark/expectedresults.csv` 참조）.

---

## 📋 취약점 사례 분류（50 이상의 취약점 패밀리 커버）

### 1. 인젝션 계열 취약점
- SQL 인젝션：기본 연결、다중 필드 연결、준비된 문장 비교（안전 혼동 샘플 포함）
- 명령어 인젝션：Runtime.exec() 오용、ProcessBuilder 인젝션、파일 간 호출 체인 오염
- 표현식 / 스크립트 엔진 인젝션（표현식 인젝션 대가족）：
  - SpEL 인젝션（Spring4Shell `class.module.classLoader` 프레임워크 의미 전용 사례 포함）
  - Groovy 인젝션（GroovyShell / GroovyScriptEvaluator）
  - MVEL 인젝션（MVEL.eval / executeExpression）
  - BeanShell 인젝션（BshScriptEvaluator / Runtime.exec）
  - OGNL 인젝션（Ognl.getValue / Runtime.exec）
  - ScriptEngine 인젝션（ScriptEngine.eval / CompiledScript.eval）
  - JNDI 인젝션（InitialContext.lookup / RMI）
  - Log4j JNDI 인젝션（CVE-2021-44228 추상）
- 템플릿 인젝션：FreeMarker / Thymeleaf 뷰명/내용 연결（CWE-1336）
- XSS：리플렉티드 XSS（안전 혼동 샘플 포함）
- LDAP 인젝션：디렉토리 서비스 쿼리 인젝션 시나리오 및 방어 방안
- XPath 인젝션：XPath.compile / DOMXPath.selectNodes
- XML 외부 엔티티（XXE）：DocumentBuilder에서 DTD 미비활성화로 인한 정보 유출（안전 설정 대조 포함）
- NoSQL 인젝션：Spring Data Mongo 간접 오염（CWE-943）
- 서버 측 요청 위조（SSRF）：내부 서비스 접근 및 데이터 탈취（인트라 IP 화이트리스트 혼동 SAFE 포함）

### 2. 인증·권한 계열 취약점
- 인증 우회：Cookie/역할 위조、세션 검증 누락（CWE-287）
- 권한 우회 / 권한 상승：수평·수직 권한 상승（CWE-285）
- IDOR（안전하지 않은 직접 객체 참조）：객체 소유 의미 누락 + 소유 검증된 혼동 SAFE（CWE-639）
- 약한 비밀번호 위험：평문 비밀번호 검증、복잡성 우회（CWE-521）
- 기본 인증 정보：변경되지 않은 기본 관리자 사용자/비밀번호（CWE-798）
- JWT 취약점：alg=none / 약한 키 / 하드코딩 + 느슨한 검증 혼동（CWE-345）

### 3. 민감 정보 유출
- 응답 내 민감 정보：평문 비밀번호/주민번호/신용카드를 응답 본문에（CWE-532）
- 약한 해시 저장：MD5/SHA1 평문 비밀번호 해시（CWE-327、PBKDF2 수정 대조 포함）
- 하드코딩 인증 정보/키：DB 연결 하드코딩、하드코딩 AES 키（CWE-798 / CWE-798 ECB）
- 오류 페이지 유출 / 로그 유출：스택 트레이스와 설정 정보 노출（교육 예시）

### 4. 불적절한 설정
- 부적절한 숫자·날짜 입력 검증：거대 수 DoS、모호한 형식 위험（CWE-20）
- 기본 비밀번호 위험（제2절 참조）
- 안전하지 않은 HTTP 메서드 / 오픈 리다이렉트：리다이렉트 URL 화이트리스트 누락、`redirect:` 접두사 우회（CWE-601、화이트리스트 SAFE 포함）
- CORS 불적절한 설정：Access-Control-Allow-Origin:* 과도하게 완화된 교차 출처（CWE-942）
- 클릭재킹 / 보안 헤더 누락：X-Frame-Options / CSP 누락（CWE-1021、헤더 설정 SAFE 포함）
- 속도 제한 누락：SMS OTP 빈도 제한 없음（CWE-307、제한 적용 SAFE 포함）

### 5. 역직렬화 및 기타 고위험 취약점
- Java 네이티브 역직렬화：ObjectInputStream.readObject、Jackson enableDefaultTyping、CC gadget chain（CWE-502、L5 gadget chain 사례 포함）
- Fastjson 역직렬화：JSON.parseObject / AutoType（CWE-502）
- Jackson 다형 역직렬화：@JsonTypeInfo 화이트리스트 누락（CWE-502、allowlist SAFE 포함）
- YAML 역직렬화：SnakeYAML load/loadAs（CWE-502）
- 의존성 관련 CVE 사례：
  - Spring AMQP 역직렬화（CVE-2023-34050、allowlist SAFE 포함）
  - Redisson 역직렬화（CVE-2023-42809、allowlist SAFE 포함）
- 경쟁 조건 (Race Condition)：비원자적 read-modify-write（CWE-362、synchronized SAFE 포함）
- 해시 충돌 공격 (Hash Collision Attack)：HashMap 사용자 제어 key 성능 저하 DoS（CWE-694、SHA-256 key SAFE 포함）
- ReDoS：파멸적 백트래킹 정규식 `(a+)+b`（CWE-1333）
- 경로 순회（Path Traversal）：디렉토리 순회로 시스템 파일 읽기（CWE-22、Files.newInputStream SAFE 포함）
- 대량 할당（Mass Assignment）：@RequestBody가 isAdmin 바인딩（CWE-915、DTO SAFE 포함）
- JSONP 콜백 인젝션：callback 문자열 연결（CWE-352）
- 헤더 인젝션：HttpHeaders.add 인젝션（CWE-113）
- 위험 연산：sun.misc.Unsafe 임의 메모리 읽기（CWE-111）
- 비즈니스 로직 결함：부호 검사 없는 잔액 조작、가격 조작、쿠폰 남용、재고 초과 판매（CWE-840、쿠폰 SAFE 포함）

**참고:** CVE-2023-34034 (Spring WebFlux 권한 우회) 및 CVE-2023-44487 (HTTP/2 Rapid Reset 공격)와 같은 일부 CVE는 Spring WebFlux 프레임워크와 관련되거나 하위 수준 네트워크 프로토콜 문제에 해당합니다. 본 프로젝트의 Spring MVC 중심 애플리케이션 시나리오와 일치하지 않거나 간단한 컨트롤러로 시연하기 어렵기 때문에, 이들은 기록만 해두었으며 구체적인 튜토리얼 사례로 구현되지 않았습니다.
