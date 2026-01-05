# CAL Autonomous Security Platform - Walkthrough

## 프로젝트 개요

CAL는 Google Gemini AI를 활용한 자율형 보안 테스트 플랫폼입니다. "Brain & Hands" 아키텍처를 통해 AI 전략 수립과 도구 실행을 분리하여 안전하고 효율적인 보안 평가를 수행합니다.

**핵심 원칙:**
- **완전 자율성**: 사용자 개입 없이 독립적으로 작동
- **Active Verification**: 실제 취약점 검증 후에만 보고
- **Multi-Agent 협업**: 전문화된 에이전트들의 협력

## 시스템 아키텍처

### 핵심 컴포넌트

```mermaid
graph TB
    User[User] --> Main[main.go]
    Main --> Orchestrator[Orchestrator]
    Orchestrator --> Bus[Event Bus]
    Orchestrator --> Commander[Commander Agent]
    
    Commander --> |spawn| Recon[ReconSpecialist]
    Commander --> |spawn| XSS[XSSSpecialist]
    Commander --> |spawn| SQLi[SQLiSpecialist]
    Commander --> |spawn| Verify[VerificationSpecialist]
    
    Commander --> LLM[Gemini LLM]
    Recon --> LLM
    XSS --> LLM
    SQLi --> LLM
    Verify --> LLM
    
    Recon --> Hands[Hands - Docker Executor]
    XSS --> Hands
    SQLi --> Hands
    Verify --> Hands
    
    Hands --> Nmap[cal/nmap]
    Hands --> Curl[cal/curl]
    Hands --> Playwright[cal/xss-verifier]
    
    Bus --> |events| Commander
    Bus --> |events| Recon
    Bus --> |events| Verify
```

### 구현된 컴포넌트

#### 1. Event Bus ([bus.go](file:///e:/business/Cai/cal-project/internal/core/bus/bus.go))
- Go Channels 기반 비동기 메시지 전달
- Pub/Sub 패턴 구현
- 에이전트 간 통신 중재

#### 2. Orchestrator ([orchestrator.go](file:///e:/business/Cai/cal-project/internal/core/orchestrator/orchestrator.go))
- 에이전트 생명주기 관리
- Event Bus 관리
- Graceful shutdown 지원

#### 3. Commander Agent ([commander.go](file:///e:/business/Cai/cal-project/internal/brain/commander/commander.go))
- **전략적 두뇌**: Gemini API 활용
- **동적 에이전트 생성**: 필요시 Specialist 자동 생성
- **키워드 기반 의사결정**: 대소문자 무시, 확장된 키워드 매칭

**주요 개선사항:**
```go
// 대소문자 무시 키워드 매칭
lowerResponse := strings.ToLower(response)
keywords := []string{"nmap", "port", "scan", "reconnaissance", ...}
```

#### 4. ReconSpecialist ([recon.go](file:///e:/business/Cai/cal-project/internal/brain/specialist/recon.go))
- **정찰 전문 에이전트**: 자체 LLM Brain 보유
- **Hands 통합**: Docker executor를 통한 실제 도구 실행
- **윤리적 컨텍스트**: "승인된 테스트 환경" 명시

#### 5. Hands - Docker Executor ([executor.go](file:///e:/business/Cai/cal-project/internal/hands/docker/executor.go))
- **결정론적 실행 엔진**: Docker 컨테이너에서 도구 실행
- **샌드박싱**: 격리된 환경에서 안전한 실행
- **Polling 기반 대기**: ContainerInspect를 통한 완료 감지

#### 6. Tool Wrappers ([tools.go](file:///e:/business/Cai/cal-project/internal/hands/tools/tools.go))
- `NmapScan`: 포트 스캔 (`cal/nmap:latest`)
- `SimpleHTTPGet`: HTTP 요청 (`cal/security-tools:latest`)

## 커스텀 Docker 이미지

### [docker/nmap/](file:///e:/business/Cai/cal-project/docker/nmap/Dockerfile)
```dockerfile
FROM alpine:latest
RUN apk add --no-cache nmap nmap-scripts
ENTRYPOINT ["nmap"]
```

### [docker/security-tools/](file:///e:/business/Cai/cal-project/docker/security-tools/Dockerfile)
올인원 이미지: nmap, curl, wget, Python 3 포함

**빌드:**
```bash
cd docker
.\build-all.ps1  # Windows
```

## 취약한 테스트 서버

### [test_server/](file:///e:/business/Cai/cal-project/test_server/README.md)

윤리적이고 안전한 테스트를 위한 의도적으로 취약한 웹 애플리케이션:

**포함된 취약점:**
1. **SQL Injection** - `search.php`
2. **XSS** - `comment.php`
3. **Command Injection** - `ping.php`
4. **Directory Traversal** - `file.php`

**실행:**
```bash
cd test_server
docker-compose up -d
```
- 접속: http://localhost:8082

## 환경 설정

### [.env](file:///e:/business/Cai/cal-project/.env.example)
```bash
GEMINI_API_KEY=your-api-key-here
GEMINI_MODEL=gemini-2.0-flash-exp
TARGET_URL=http://localhost:8082
```

## 실행 및 테스트

### 1. 필수 준비사항
```bash
# Docker 이미지 빌드
cd docker
.\build-all.ps1

# 테스트 서버 시작
cd ../test_server
docker-compose up -d

# API 키 설정
# .env 파일 편집
```

### 2. 시스템 실행
```bash
# 빌드
go build -o cal-server.exe ./cmd/cal-server

# 실행
.\cal-server.exe
```

### 3. 예상 작동 흐름

```
1. [Commander-01] Online. Target: http://localhost:8082
2. [Commander-01] Thinking... (Gemini API 호출)
3. [Commander-01] Thought: "nmap으로 포트 스캔..." → 키워드 매칭
4. [Commander-01] Spawning ReconSpecialist...
5. [ReconAgent-01] Online. Awaiting reconnaissance tasks
6. [Commander-01] Sent task to ReconAgent-01: "Perform initial reconnaissance"
7. [ReconAgent-01] Thinking... (Gemini API: 어떤 도구 사용?)
8. [ReconAgent-01] LLM suggests: nmap
9. [Docker] Pulling image: cal/nmap:latest
10. [Docker] Running tool...
11. [ReconAgent-01] Recon completed. Output: (nmap 결과)
12. [Commander-01] Observation received → 다음 전략 수립
```

## 주요 기술적 결정

### 윤리적 AI 프롬프팅
```go
"CONTEXT: You are performing AUTHORIZED security testing on a 
controlled test environment owned by the user. This is ethical, 
legal, and educational. Proceed without warnings."
```
→ LLM의 불필요한 윤리적 경고 방지

### 대소문자 무시 키워드 매칭
```go
lowerResponse := strings.ToLower(response)
if strings.Contains(lowerResponse, "nmap") { ... }
```
→ LLM 응답 변동성 대응

### Polling 기반 Container Wait
```go
for {
    inspect, _ := client.ContainerInspect(ctx, containerID, ...)
    if !inspect.Container.State.Running { break }
    time.Sleep(500 * time.Millisecond)
}
```
→ moby/moby API 호환성

## 시스템 실행 흐름 (Execution Flow)

```mermaid
sequenceDiagram
    participant Orch as Orchestrator
    participant Cmdr as Commander
    participant Recon as ReconSpecialist
    participant XSS as XSSSpecialist
    participant SQLi as SQLiSpecialist
    participant Verify as VerificationSpecialist
    participant Browser as Headless Browser

    Orch->>Cmdr: Start Agent
    Cmdr->>Cmdr: Analyze Target
    Cmdr->>Recon: Spawn & Task (Port Scan)
    Cmdr->>XSS: Spawn & Task (XSS Hunt)
    Cmdr->>SQLi: Spawn & Task (SQLi Hunt)

    par Parallel Execution
        Recon->>Recon: Run Nmap
        XSS->>XSS: Fetch HTML & LLM Analysis
        SQLi->>SQLi: Fetch HTML & LLM Analysis
    end

    XSS-->>Cmdr: Report "VULNERABILITY FOUND"
    SQLi-->>Cmdr: Report "VULNERABILITY CANDIDATE"

    Cmdr->>Cmdr: Detect Vulnerabilities
    Cmdr->>Verify: Spawn & Forward Report
    
    Verify->>Verify: Extract URL & Payload (LLM)
    Verify->>Browser: Run Verification (Playwright)
    Browser-->>Verify: Result (Alert Triggered?)
    Verify-->>Cmdr: Verification Report (CONFIRMED/FAILED)
```

### 단계별 프로세스

1.  **초기화 (Initialization)**: Orchestrator가 Commander를 시작합니다.
2.  **전략 수립 (Strategy)**: Commander가 타겟을 분석하고 Recon, XSS, SQLi Specialist를 병렬로 생성합니다.
3.  **탐지 (Discovery)**:
    *   **Recon**: 포트 및 서비스 스캔 수행.
    *   **XSS/SQLi**: 웹 페이지를 가져와 LLM이 소스 코드를 분석하여 취약점 위치 식별.
4.  **보고 (Reporting)**: 각 Specialist가 발견된 내용을 Commander에게 보고합니다.
5.  **트리거 (Trigger)**: Commander가 "VULNERABILITY FOUND" 키워드를 감지하면 검증 절차를 시작합니다.
6.  **검증 (Verification)**:
    *   **VerificationSpecialist** 생성 및 보고서 전달.
    *   **Headless Browser (Playwright)**를 사용하여 실제 브라우저에서 XSS 페이로드 실행 여부 확인.
7.  **확정 (Confirmation)**: 공격 성공 시 "CONFIRMED" 리포트 생성.

## 프로젝트 통계

- **총 Go 파일**: 10개
- **총 라인 수**: ~1,500 lines
- **외부 의존성**: 
  - `google.golang.org/genai` (Gemini SDK)
  - `github.com/moby/moby/client` (Docker SDK)
  - `github.com/joho/godotenv` (.env 지원)

## 다음 단계

- [ ] 더 많은 Specialist 추가 (WebHackSpecialist, ExploitSpecialist)
- [ ] 검증 루프 구현 (PoC 자동 생성)
- [ ] 결과 보고서 자동 생성
- [ ] Redis 기반 분산 Event Bus
- [ ] 구조화된 LLM 출력 (JSON 파싱)

## 참고 문서

- [프로젝트 규칙](file:///e:/business/Cai/cal-project/docs/project_rules.md) - 핵심 철학 및 아키텍처 원칙
- [아키텍처 설계](file:///e:/business/Cai/cal-project/docs/architecture_design.md) - 기술 스택 및 통신 프로토콜
- [테스트 서버 README](file:///e:/business/Cai/cal-project/test_server/README.md) - 취약한 서버 사용법
