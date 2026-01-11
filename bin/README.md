# CAL 바이너리 실행 가이드

⚠️ **중요**: 이 폴더에서 직접 실행하지 마세요!

## 올바른 실행 방법

바이너리는 반드시 **프로젝트 루트 디렉토리**에서 실행해야 합니다.

```bash
# 올바른 방법 ✅
cd E:\business\Cai\cal-project
.\bin\cal-server.exe --mode=single --url=http://localhost:8888

# 잘못된 방법 ❌
cd E:\business\Cai\cal-project\bin
.\cal-server.exe --mode=single --url=http://localhost:8888
# Error: open assets/prompts/config.yaml: The system cannot find the path specified.
```

## 이유

바이너리들은 다음 파일들을 상대 경로로 참조합니다:
- `assets/prompts/config.yaml`
- `assets/prompts/v1/`
- `.env`
- `docker-compose.yml`

bin 폴더에서 실행하면 이 파일들을 찾을 수 없습니다.

## Skills 사용 (권장)

Claude Code Skills를 사용하면 자동으로 올바른 경로에서 실행됩니다:

```bash
/build-cai              # 빌드
/test-trt               # TRT 연결 테스트
/run-test --target=URL  # 보안 테스트
/prompt-reindex         # 프롬프트 인덱싱
```

## 바이너리 목록

- `cal-server.exe` - 메인 공격 엔진
- `verify_trt.exe` - TRT 연결 검증
- `index-prompts.exe` - RAG 프롬프트 인덱싱
