# Java Security Education Framework (JSEF) - Spring Boot 안전 실습 플랫폼
[![GitHub Stars](https://img.shields.io/github/stars/XiaomingX/JSEF?style=social&label=Star%20This%20Repo)](https://github.com/XiaomingX/JSEF)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Java Version](https://img.shields.io/badge/Java-17%2B-blue.svg)](https://www.oracle.com/java/technologies/downloads/#java17)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-orange.svg)](https://spring.io/projects/spring-boot)
[![Docker Ready](https://img.shields.io/badge/Docker-Supported-blue.svg)](docs/docker-deployment.md)

> **재현 가능、실습 가능、학습 가능**한 Spring Boot 웹 안전 실험 프레임워크로, 개발자가 웹 안전 취약점 원리와 방어 방안을 신속하게 습득하도록 지원합니다.


## 📖 프로젝트 개요
**Java Security Education Framework (JSEF)** 는 Spring Boot 3.x 기반으로 구축된 웹 안전 실습 플랫폼으로, **개발자、보안 연구원、대학생、기업 교육** 대상으로 설계되었습니다. **35가지 이상의 실제 비즈니스 시나리오 기반 안전 취약점 사례**（인젝션 공격、권한 침해、민감 정보 유출 등 핵심 유형 포함）를 통해「**원리 설명→취약점 재현→코드 비교→수정 검증**」의 완전한 학습 사이클을 제공하여, 학습자가「이론」에서「실습」으로 웹 안전 핵심 역량을 신속하게 습득하도록 돕습니다.

본 프로젝트는 복잡한 환경에 의존하지 않고, 로컬 원클릭 실행 및 Docker 배포를 지원합니다. 모든 취약점 사례는 실제 비즈니스 로직 기반으로 설계되어「취약점을 위한 취약점」이라는 데모용 코드를 회피하며, 실제 개발 시나리오에 보다 가깝게 제공합니다.

**새로운 구조 설명:** 프로젝트 코드가 리팩터링되었습니다. 이제 모든 취약점 관련 컨트롤러는 `com.freedom.securitysamples.vulnerability` 패키지 아래에 있습니다. 각 취약점 카테고리는 `vuln` (안전하지 않거나 취약한 구현 포함) 및 `sec` (안전하거나 수정된 구현 포함) 서브 패키지로 더 세분화되어 직접 비교 학습에 용이합니다. API 경로는 `/api/v1/{vulnerability-type}/unsafe/{scenario}` 및 `/api/v1/{vulnerability-type}/safe/{scenario}` 형식으로 통일되었습니다.


## 🔥 핵심 장점（왜 JSEF를 선택해야 할까요?）
| 장점 | 상세 설명 |
|-----------|----------------------|
| **취약점 사례의 실제 재현성** | 35가지 이상의 취약점이 OWASP Top 10 모든 유형을 커버하며, 각 사례는 사용자 로그인、데이터 쿼리、파일 업로드 등 실제 비즈니스 시나리오를 모방합니다. |
| **완전한 학습 사이클** | 각 취약점에는「원리 문서＋재현 단계＋안전하지 않은 코드＋안전한 코드 비교＋방어 모범 사례」가 함께 제공됩니다. |
| **배포 제로 장벽** | `mvn` 기반 원클릭 실행、Docker 컨테이너화 배포를 지원하며, 데이터베이스/미들웨어 수동 구성이 필요 없습니다. |
| **명확한 코드 규약** | Spring Boot 모범 사례에 따라 코딩하며, 안전하지 않은 코드와 안전한 코드가 이제 `vuln`/`sec` 디렉토리로 분리되어 비교 학습에 용이합니다. |
| **풍부한 리소스 생태계** | API 문서、취약점 재현 매뉴얼、안전 코딩 규약을 기본 제공하며, CVE 최신 취약점 사례를 지속적으로 업데이트합니다. |
| **높은 확장성** | 플러그인형 취약점 사례 인터페이스를 제공하여, 개발자가 사용자 정의로 새로운 취약점 시나리오를 추가하거나 방어 방안을 확장하는 것을 지원합니다. |


## 🚀 빠른 시작
### 환경 요구사항
- JDK 17 이상
- Maven 3.6+ 또는 Gradle 8.0+
- Git（선택 사항, 리포지토리 클론용）
- Docker（선택 사항, 컨테이너화 배포용）

### 방법 1：로컬 Maven 실행（초보자 추천）
```bash
# 1. 리포지토리 클론（또는 직접 ZIP 패키지 다운로드）
git clone --depth 1 https://github.com/XiaomingX/JSEF.git
cd JSEF

# 2. 프로젝트 빌드（테스트 건너뛰어 빌드 속도 향상）
mvn clean package -DskipTests

# 3. 서비스 실행
java -jar target/java-sec-code-plus-1.2.0.jar
```

### 방법 2：Docker 원클릭 배포
```bash
# 1. 이미지 빌드
docker build -t jsef-security-sample:latest .

# 2. 컨테이너 실행
docker run -d -p 8080:8080 --name jsef-demo jsef-security-sample:latest
```

### 배포 성공 검증
실행 후 다음 주소에 접속하세요：
- 프로젝트 홈페이지：`http://localhost:8080`（프로젝트 내비게이션 및 취약점 목록 확인）
- API 문서（Swagger）：`http://localhost:8080/swagger-ui/index.html`（모든 취약점 인터페이스 세부 정보 확인）
- 취약점 매뉴얼：`http://localhost:8080/docs`（온라인 취약점 재현 가이드 확인）


## 📋 취약점 사례 분류（35가지 이상 완전 목록）
모든 구현된 취약점 사례에 대한 자세한 목록은 [VULNERABILITIES-kr.md](VULNERABILITIES-kr.md)를 참조하십시오.

## 🎯 적용 시나리오
| 사용자 그룹 | 적용 시나리오 |
|------------|----------------------|
| **개발 엔지니어** | 안전 코딩 규약을 학습하여 프로젝트에서 취약점 코드 작성을 회피합니다. |
| **보안 연구원** | 취약점 원리를 재현하고 방어 방안의 효율성을 검증하며, 보안 도구 테스트 환경을 구축합니다. |
| **대학생·교수** | 정보 보안/네트워크 보안 과목 실험 플랫폼으로, 기존 데모형 실험을 대체합니다. |
| **기업 교육** | 개발 팀 안전 코딩 교육、침투 테스트 팀 입문 실습 연습에 활용합니다. |
| **CTF 플레이어** | 기본 취약점 실습 연습을 통해 일반적인 취약점 악용 기법을 익힙니다. |


## 🔬 SAST 역량 및 멀티모델 취약점 탐지 Benchmark

JSEF는 교육 플랫폼일 뿐만 아니라, **SAST 기본 역량 검증**과 **여러 LLM 간 취약점 탐지 능력 차이 비교**에 쓰는 benchmark를 내장하고 있습니다. 설계는 SAST 제1원리(source에서 sink까지의 불신 데이터 도달 가능성 증명)에 기반하며, 샘플에는 변별력 구배를 두어 오탐·미탐·평균 소요시간·타임아웃·보고서 간결성·완전성(coverage)을 교차 비교하기 쉽게 했습니다.

### 핵심 역량

| 역량 차원 | 설명 |
|---------|------|
| 오염 전파（변수 단절 없음） | 단홉/다홉/간접（Map/필드） 구배, 중간 변수에서 오염이 유실되는지 검증 |
| 상태 머신 / 호출 체인 추적 | 메서드 간/파일 간/gadget chain, 도달 가능성 분석 깊이 검증 |
| 프레임워크 의미 이해 | Spring 파라미터 바인딩, SpEL, `@RequestParam`이 유도하는 암묵적 source/sink |
| 오탐 억제 | OWASP식 진위 혼동 샘플, "위험해 보이나 안전한" 코드 판별 검증 |

### 샘플과 난이도 등급

샘플은 **L0-L5**로 등급화됩니다（각 단계마다 추론 거리와 의미 의존을 늘려 도구/모델 격차를 벌림；L0은 모든 도구/모델이命中해야 할 역량 기준）：

| 등급 | 의미 | 예 |
|------|------|------|
| L0 | 역량 기준（명시적 직결） | source가 중간 변수 없이 sink에 직결 |
| L1 | 단홉 직결 | `Runtime.exec(userInput)` |
| L2 | 다홉（변수 단절 없음） | source -> 중간 변수 -> builder -> sink |
| L3 | 간접 / 메서드 간 | 오염이 Map/필드 경유；메서드 반환값으로 함수 간 이동 |
| L4 | 파일 간 / 프레임워크 의미 / 상태 머신 | Controller -> ServiceA -> ServiceB -> sink；Spring4Shell SpEL 의미 |
| L5 | gadget chain | 여러 안전 클래스가 조합되어 위험한 도달 가능성 형성（CC 역직렬화 체인 추상） |

기본 등급 외에, LLM의 **계획 능력**과 **일관성**을 검증하는「장기/복잡 태스크」샘플군이 2개 있습니다：
- **장기 태스크（LT 계열）**：파일 간 추적 / 프레임워크 상태 머신 / gadget chain 재구성 / 다중 홉 연결 / 버전 게이팅 — 자세한 것은 [`benchmark/README.md`](benchmark/README.md) §3 참조.
- **코드 품질 / 성능 DoS + LGTM 누락（PERF/TB/REFLECT/FMT/HOST/XSLT/FWD/SEED 계열）**：슬로우 SQL, 리소스 누수, 리플렉션 주입, 신뢰 경계, 형식 문자열 주입 등. LGTM/CodeQL Java 규칙팩에 정렬.

### 현재 샘플 규모

> 데이터 출처：`benchmark/expectedresults.csv`（진실 원천, 소스의 `// [CHECKPOINT]` 주석과 양방향 일치；`validate_checkpoints.py` 종료 코드 0）

- **503건**의 기계 판독 가능 checkpoint 주석（`src/main` 기존 취약점 + `benchmark/cases` 구배 샘플 + 장기 태스크 + 코드 품질/성능 DoS + LGTM 누락 + 논리 취약점 샘플 + **원자 패러다임군 TCM/SBM/DBG/STR** 포괄）
- **268건의 VULN**（보고되어야 함） + **235건의 SAFE**（보고되지 않아야 함, TN/FP 산출용）
- 난이도 분포：L0 x 18、L1 x 139、L2 x 106、L3 x 115、L4 x 86、L5 x 39（완전한 L0-L5 구배）
- CWE 커버：**69종**（VULN만）. 상위：표현식 주입(917) x 25、역직렬화(502) x 21、SQLi(89) x 17、명령어 주입(78) x 12、인가 우회(285) x 10、하드코딩 자격증명/키(798) x 7、비즈니스 로직(840) x 7、SSRF(918) x 6、IDOR(639) x 6、경로 조작(22) x 5、ReDoS(1333) x 5、성능 DoS(400) x 5
- **121 카테고리**（slug） 커버（OWASP Top 10 2021 전 클래스 포함）；**65건**의 샘플이 `trace=` 경로 노드 보유（`--check-trace` 경로 정확성 평가 지원）
- 전용 샘플군：장기 태스크(LT) x 16、코드 품질/성능 DoS(PERF) x 15、신뢰 경계(TB)/리플렉션(REFLECT)/형식 문자열(FMT)/호스트명(HOST)/XSLT(XSLT)/포워드(FWD)/시드(SEED) 각 x 2
- **원자 패러다임군（TCM/SBM/DBG/STR）** x 64：Fastjson / Spring Boot / Dubbo / Struts2 의 실제 0day/1day 에서 **라이브러리 비종속** 원자 위험 패러다임을 추출해 순수 Java 표준 라이브러리만으로 자체 재현. 아래 "원자 패러다임군" 절 참조.

### 원자 패러다임군（TCM / SBM / DBG / STR）

LLM / harness 가 **동일 원리** 취약점을 탐지할 수 있는지 평가하기 위해, JSEF 는 최근 고영향 프레임워크(Fastjson / Spring Boot / Dubbo / Struts2)의 0day/1day 에서 **라이브러리 비종속** 원자 위험 패러다임을 추출하고, 원본 프레임워크와 분리된 동일 근인 복합 샘플을 구축합니다. 각 패밀리는 `vuln` + `sec` 대조(FP/TN 산출용)를 갖추고 L1–L5 로 등급되며, 모두 `// [CHECKPOINT]` 주석을 지니고 **원본 프레임워크 클래스명을 포함하지 않습니다**(순수 표준 라이브러리 의미론).

| 네임스페이스 | 추출원 | 원자 패러다임 차원（MECE, 비중복） | 샘플수 |
|---------|--------|-------------------------------|--------|
| **TCM** | Fastjson 역직렬화 | TCM-1 직접 형 선택・TCM-2 상속 허용목록 우회・TCM-3 캐시/재파싱 우회・TCM-4 비공개 필드 바인딩・TCM-5 프로퍼티即코드(위험 getter/setter) | 20 |
| **SBM** | Spring Boot | SBM-1 바인더 순회・SBM-2 선언적 구성 식 평가・SBM-3 고권한 엔드포인트 노출・SBM-4 인가 숏서킷 우회 | 16 |
| **DBG** | Dubbo RPC | DBG-1 파서/포맷 협상 전환・DBG-2 신뢰 경계 횡단 암묵적 신뢰(attachment)・DBG-3 클래스명 거부목록 인코딩 우회 | 16 |
| **STR** | Struts2/OGNL | STR-1 이중 평가(Double Evaluation)・STR-2 프로토콜 계층 필드 주입・STR-3 식 제외목록/샌드박스 우회 | 12 |

**설계 요점**：
- 추상화 원칙：프레임워크 특정 메커니즘(예 "JSON 라이브러리 autotype", "Web 프레임워크 SpEL")을 벗기고, 프레임워크를 넘나드는 불변 위험 결합——공격자가 형/데이터를 제어＋시스템이 암묵적 메서드를 자동 호출＋암묵적 메서드 체인이 위험한 sink 에 도달——만 남긴다.
- 기존 샘플과 중복 없음：기존 `JSEF-OGNL-*`/`JSEF-SPEL-*` 단층 식 주입, `JSEF-DESER-*` 직접 역직렬화 등은 의도적으로 회피하고, 위 프레임워크**고유且 미모델링** 원자 차원(OGNL 이중 평가, Spring4Shell 바인더 순회, Dubbo 파서 협상 등)만 커버.
- 높은 변별력：L4 파일 간, L5 gadget chain, 메서드 간 체인 등 난예를 포함해 도구/모델 능력 계층을 분리.
- 안전 기준：모든 위험 호출은 localhost 데모 의미론・플레이스홀더 문자열이며 실 exploit 스크립트는 제공하지 않음.

샘플 위치：`benchmark/cases/{vuln,sec}/{tcm,sbm,dbg,str}/`；설계 문서：`plans/02-~05-*.md`.

샘플 구성：
- `benchmark/cases/vuln/` 및 `benchmark/cases/sec/`：변별력 있는 구배 샘플（안전 대조 포함）
- `benchmark/cases/vuln/longtask/` 및 `benchmark/cases/vuln/perf/`：장기 태스크와 코드 품질/성능 DoS 전용 샘플
- `benchmark/cases/vendor/`：OWASP Benchmark / Juliet / PrimeVul / CVEfixes에서 추상한 고품질 경쟁 샘플（출처 URL 포함）

### 실행 및 교차 비교 방법

1. JSEF 시작：`mvn clean package -DskipTests && java -jar target/*.jar`
2. 피험체 선정：SAST 도구（CodeQL/SonarQube/Snyk） + LLM（Claude Code에서 모델 전환, 동일 프롬프트 `benchmark/prompts/vuln_hunt.md` 사용）
3. 각 피험체가 `benchmark/cases/`를 한 번 스캔하여 SARIF 또는 `id -> {hit,file,line}` 결과 출력, 소요시간 기록
4. 채점 스크립트로 교차 비교 지표 산출（저장소 루트에서 실행）：
   ```bash
   python3 benchmark/scripts/scorecard.py --expected benchmark/expectedresults.csv --result <result.json|.sarif> --name <피험체명>
   ```
   Recall / Precision / **Youden Score (TPR - FPR)** / 평균 소요시간 / 타임아웃 수 / 보고서 간결성 / 완전성을 CWE와 등급별로 그룹화하여 출력.

자세한 설계와 프로토콜은 [`benchmark/README.md`](benchmark/README.md)와 [`MY_PLAN.md`](MY_PLAN.md)를 참조.


## 📚 공식 문서
- [📊 Benchmark 설계 및 프로토콜](benchmark/README.md)：SAST/LLM 취약점 탐지 검수 benchmark 사용과 확장
- [🗺️ Benchmark 구현 계획](MY_PLAN.md)：역량 모델, 샘플 등급, 할 일 진행상황
- [📥 배포 가이드](docs/deployment.md)：로컬/Mac/Linux/Windows/Docker 배포 전체方案
- [🔍 취약점 재현 매뉴얼](docs/vulnerability-guide.md)：각 취약점에 대한 상세 재현 단계（Payload 예시 포함）
- [💻 API 참조서](docs/api-reference.md)：모든 인터페이스에 대한 요청 매개변수 및 응답 형식 설명（Swagger 온라인 디버깅 지원）
- [🛡️ 안전 코딩 가이드](docs/secure-coding-guide.md)：Spring Boot 기반 안전 코딩 모범 사례
- [📌 새로운 취약점 사례 추가 가이드](docs/contribute-vulnerability.md)：프로젝트에 새로운 취약점 사례를 추가하는 방법
- [🎥 비디오 튜토리얼](https://github.com/XiaomingX/JSEF/wiki/Video-Tutorials)：Bilibili（빌리빌리）연동 취약점 재현 영상（지속 업데이트）


## 🤝 기여 방법
본 프로젝트는 모든 형태의 기여를 환영합니다. **새로운 취약점 사례 추가、문서 보충、코드 문제 수정、기능 제안** 등 어떤 지원도 많은 사람이 웹 안전을 학습하는 데 도움이 됩니다！

### 기여 방법
1. **Issue 제출**：취약점 피드백、기능 제안、버그 보고（사전에 유사 Issue 검색 권장）
2. **PR（Pull Request）제출**：
   - 코드 문제 수정（오타、로직 최적화 등）
   - 새로운 취약점 사례 추가（[새로운 취약점 사례 추가 가이드](docs/contribute-vulnerability.md) 준수 필요）
   - 문서 보충（재현 단계 추가、영문 문서 번역 등）
3. **공유 및 보급**：본 프로젝트에 Star를 누르고 기술 커뮤니티에서 사용 경험을 공유하여, 더 많은 사람이 JSEF를 알게 합니다.

### 초보자 친화적 기여
- [Good First Issues](https://github.com/XiaomingX/JSEF/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)：초보자에게 적합한 입문 수준 과제（문서 보충、코드 주석 보충 등）


## 📄 오픈 소스 라이선스
본 프로젝트는 **MIT License** 기반으로 오픈 소스화되어 다음과 같은 사용을 허가합니다：
- 개인 학습、기업 교육、상용 제품 테스트에 무료로 사용
- 프로젝트 코드 수정·배포（원저자 저작권 표시 유지 필요）
- 본 프로젝트 기반 이차 개발（출처 명시 필요）

**금지**：본 프로젝트를 무단 침투 테스트、악의적 공격 등 불법 행위에 사용하는 것。


## ⭐ Star 기록
[![Star History Chart](https://api.star-history.com/svg?repos=XiaomingX/JSEF&type=Date)](https://star-history.com/#XiaomingX/JSEF&Date)


## 🙏 감사의 글
- OWASP（https://owasp.org/）가 제공하는 웹 안전 표준 및 취약점 분류 프레임워크에 감사합니다.
- Spring 커뮤니티가 제공하는 Spring Boot 생태계 지원에 감사합니다.
- 모든 기여자의 코드 제출 및 피드백에 감사합니다（[Contributors](https://github.com/XiaomingX/JSEF/graphs/contributors)）.
- 보안 커뮤니티 기술 블로거의 취약점 원리 공유에 감사합니다.


## ⚠️ 면책 조항
본 프로젝트는 **학습、연구、기업 내부 안전 교육 목적으로만 사용**해야 합니다. 무단 테스트、공격、파괴 행위에 사용하지 마십시오. 본 프로젝트 사용으로 발생하는 모든 법적 책임은 사용자가 스스로 부담합니다.