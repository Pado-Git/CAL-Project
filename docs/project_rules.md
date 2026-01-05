# 프로젝트 규칙 및 아키텍처 헌법 (Project Rules & Constitution)

이 문서는 우리의 **자율 AI 보안 플랫폼(Autonomous AI Security Platform)** 개발을 위한 핵심 원칙, 아키텍처, 운영 규칙을 정의합니다. 모든 개발은 안정성, 안전성, 그리고 **기계적인 속도(Machine Speed)**를 달성하기 위해 이 가이드라인을 엄격히 준수해야 합니다.

## 1. 핵심 철학: 분산형 멀티 에이전트 아키텍처 (Distributed Multi-Agent Architecture)

단일 Brain과 단일 Hands 구조를 넘어, 효율성을 극대화하기 위해 역할을 세분화한 **멀티 에이전트 시스템**을 채택합니다.

*   **총괄 사령관 (Commander Brain)**
    *   **역할**: 전체 공격 캠페인의 지휘관.
    *   **임무**: 타겟의 전체적인 공격 표면(Attack Surface)을 분석하고, 하위 스페셜리스트 에이전트들에게 임무를 할당(Dispatch)하며, 최종 리포트를 취합합니다.
    *   **비유**: 해킹 팀의 리더 (Team Lead).

*   **스페셜리스트 에이전트 (Specialist Agents)**
    *   각 에이전트는 특정 공격 벡터에 특화된 "작은 Brain"을 가집니다.
    *   **Recon Agent**: 포트 스캔, 서브도메인 수집, 기술 스택 식별 전담.
    *   **Web Hacker Agent**: SQLi, XSS, SSRF 등 웹 애플리케이션 취약점 집중 공격.
    *   **Network Agent**: 서비스 취약점, 프로토콜 악용 시도.
    *   **Social Eng Agent**: (필요시) 피싱 시나리오 설계 등.
    *   **장점**: 서로 다른 영역을 병렬로 동시에 공격(Parallel Execution)하여 속도를 비약적으로 높입니다.

*   **실행 노드 (Execution Nodes - The Hands)**
    *   **역할**: 각 에이전트의 요청을 받아 실제로 도구를 실행하는 "손".
    *   **구조**: 스페셜리스트 에이전트 1명당 N개의 실행 노드를 거느릴 수 있어 대규모 병렬 스캐닝이 가능합니다.


## 2. 골든 룰: 능동적 검증 (환각 제로 / Zero Hallucination)

우리는 패턴 매칭에 기반한 "잠재적" 취약점을 보고하지 않습니다. 우리는 **입증된(Proven)** 취약점만 보고합니다.

*   **가설 단계 (Hypothesis)**: Brain이 취약점을 의심합니다 (예: "이 파라미터는 SQL 인젝션에 취약해 보임").
*   **검증 단계 (Verification)**:
    1.  Brain이 구체적인 **개념 증명(PoC, Proof of Concept)** 페이로드를 생성합니다.
    2.  Hands가 **검증 에이전트(Verification Agent)**(예: 헤드리스 브라우저 또는 특수 스크립트)를 가동합니다.
    3.  에이전트가 타겟 시스템에 실제 공격을 수행합니다.
    4.  시스템이 **증거(Evidence)**(DB 에러, 데이터 유출, 쉘 획득 등)를 캡처합니다.
*   **결과**: 증거가 확보된 경우에만 리포트에 기록합니다. 공격 실패 시 Brain에게 피드백을 주어 전략을 수정하게 합니다.

## 3. 툴링 및 생태계 (Tooling & Ecosystem)

### 자율 도구셋 (Autonomous Toolset)
AI는 바퀴를 다시 발명하지 않습니다. 검증된 최고의 보안 도구들을 오케스트레이션합니다:
*   **정찰(Recon)**: `nmap`, `subfinder`, `httpx`
*   **웹(Web)**: `Burp Suite` (API 연동 시), `Zap`, `Caido`, `ffuf`, `curl`
*   **익스플로잇(Exploitation)**: `Metasploit` (RPC), 커스텀 Python 스크립트.

### 에이전트 환경 (Agent Environment)
*   **샌드박싱(Sandboxing)**: 모든 "Hands"의 실행은 일회성 Docker 컨테이너 내에서 이루어져야 하며, 호스트 시스템 손상이나 불필요한 흔적(Persistence)을 방지합니다.
*   **헤드리스 브라우저**: XSS, CSRF, 로직 버그 검증을 위해 실제 브라우저(Puppeteer/Playwright)를 활용합니다.

## 4. 운영 워크플로우 (Operational Workflow)

1.  **타겟 확보**: 사용자가 URL/IP 제공.
2.  **정찰 (자동)**: 시스템 엔진이 정찰 도구 실행 -> 결과 데이터를 Brain에 주입.
3.  **전략 수립 (Brain)**: Brain이 정찰 데이터 분석 -> `AttackPlan` (공격 계획) 출력.
4.  **실행 (Hands)**: 시스템 엔진이 `AttackPlan` 순회 -> 도구 실행.
5.  **분석 (Brain)**: Brain이 도구 실행 결과 분석 -> 성공/실패 판독.
6.  **검증 (루프)**: 성공 가능성 발견 시 -> `VerificationModule` 트리거 -> 실제 공격으로 확증.
7.  **보고**: 재현 단계(Reproduction Steps)가 포함된 리포트 생성.

## 5. 코딩 표준 (Coding Standards)

*   **언어**: **Go (Golang)** - 고성능 동시성 처리 및 안정성을 위해 전면 채택.
*   **통신**: Brain과 Hands 간 JSON-RPC 또는 gRPC 사용.
*   **로깅**: 모든 LLM의 "생각"과 실행된 모든 "쉘 명령어"에 대한 완전한 감사 로그(Audit Trail) 기록.

---
**"해커처럼 생각하고, 기계처럼 움직인다."**
