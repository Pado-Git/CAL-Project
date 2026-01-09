# 아키텍처 디자인:# CAL System Architecture Design

## 1. System Overview

**CAL (Cognitive Autonomous Loop)** is a distributed multi-agent system designed for autonomous security testing. It separates strategic planning ("Brain") from deterministic execution ("Hands").

### 핵심 구성요소
1.  **오케스트레이터 (The Kernel)**: Goroutine 기반의 이벤트 관리 및 에이전트 생명주기를 관리합니다.
2.  **사령관 에이전트 (Root Brain)**: 전체 공격을 계획하는 최상위 전략가입니다.
3.  **스페셜리스트 에이전트 (Sub-Brains)**: 정찰(Recon), 웹(Web), 네트워크(Network) 등 각 분야의 전문가입니다.
4.  **도구 실행기 (The Hands)**: TRT C2 서버에 연결된 **Callisto Agents**가 실제 명령을 수행합니다.

### Core Philosophy
1.  **Distributed Agents**: Independent agents collaborating via an Event Bus.
2.  **Brain & Hands Separation**: LLM handles logic; **Remote TRT Agents** handle execution.
3.  **Active Verification**: No findings without proof (PoC).

## 2. 기술 스택 선정

*   **언어**: Go 1.21+ (Goroutine 기반 동시성 처리)
*   **LLM 인터페이스**: Google GenAI SDK for Go
*   **실행 환경**: **TRT (Toncal) C2 Architecture** (Remote Agent Execution)
*   **통신**: Go Channels (Internal Bus) + **HTTP/JSON (TRT C2 API)**
    *   *결정*: 초기에는 **Go Channels**를 활용한 인메모리 버스로 시작하여 초고속 동시성을 확보합니다.

## 3. 통신 프로토콜 (스키마)

에이전트들은 구조화된 `AgentMessage` 객체를 통해 소통합니다.

```json
{
  "id": "uuid-v4",
  "timestamp": "2024-01-01T12:00:00Z",
  "from_agent": "ReconAgent-01",
  "to_agent": "Commander",
  "type": "TASK_RESULT | OBSEREVATION | ERROR",
  "priority": "HIGH | NORMAL",
  "payload": {
    "tool": "nmap",
    "output": "Open ports: 80, 443...",
    "analysis": "Web server detected."
  }
}
```

## 4. 폴더 구조 제안 (Go Standard Layout)

```
/cmd
  /cal-server    # 메인 엔트리포인트
/internal
  /core
    /bus          # 이벤트 버스 (Channels)
    /agent        # 에이전트 인터페이스
  /brain
    /llm          # Gemini 클라이언트
    /commander    # 사령관 로직
    /specialist   # 스페셜리스트 로직 (recon, web, net)
  /hands
    /docker       # (Legacy) Docker 실행기
    /tools        # 도구 래퍼
    /trt          # [NEW] TRT C2 Client & Remote Executor
/pkg              # 외부에서 사용 가능한 라이브러리 (선택적)
/configs          # 설정 파일
```

## 5. 사용자(개발자) 요구사항
이 아키텍처를 구현하기 위해 다음 사항이 필요합니다:
1.  **API 환경**: Gemini API (약 5~10개의 동시 에이전트 스레드를 감당할 수 있는 등급).
2.  **TRT 인프라**: TRT C2 Server(`toncal`) 및 1개 이상의 활성 **Callisto Agent**.
3.  **네트워크 권한**: 타겟을 합법적으로 스캔할 수 있는 권한 (윤리적/법적 필수 사항).
