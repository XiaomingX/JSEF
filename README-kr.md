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
java -jar target/java-sec-code-plus-0.0.1-SNAPSHOT.jar
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


## 📚 공식 문서
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