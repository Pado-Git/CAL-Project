# CAL Autonomous Security Platform

> **CAL is a Distributed Multi-Agent System (Go) for Autonomous Security Testing.**

Inspired by the CAL commercial product, CAL uses a "Brain & Hands" architecture...

## 설치 및 실행

### 1. 의존성 설치
```bash
go mod download
```

### 2. 환경 변수 설정
`.env.example`을 복사하여 `.env` 파일을 생성하고 API 키를 입력하세요:

```bash
cp .env.example .env
```

`.env` 파일을 열고 실제 값을 입력:
```env
GEMINI_API_KEY=your-actual-api-key-here
TARGET_URL=http://target-to-test.com
```

### 3. 실행
```bash
go run cmd/cal-server/main.go
```

### 4. 종료
`Ctrl + C`로 안전하게 종료됩니다.

## 아키텍처

- **Orchestrator**: 에이전트 생명주기 관리
- **Event Bus**: Go Channels 기반 메시지 버스
- **Commander Brain**: Gemini API를 사용한 전략 수립 에이전트
- **Hands** (TODO): Docker 기반 도구 실행기

자세한 내용은 `docs/` 폴더를 참조하세요.
