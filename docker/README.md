# CAL Project Docker Services

이 폴더는 CAL 프로젝트의 Docker 서비스들을 관리합니다.

## 서비스 목록

### 1. cai-qdrant (RAG 벡터 데이터베이스)
- **위치**: `cal-project/docker/cai-qdrant/`
- **포트**: 6333 (HTTP), 6334 (gRPC)
- **용도**: AI 프롬프트 임베딩 저장 (선택적)
- **시작**: `cd cai-qdrant && docker-compose up -d`
- **중지**: `cd cai-qdrant && docker-compose down`

### 2. test_server (취약한 웹 서버)
- **위치**: `cal-project/docker/test_server/`
- **포트**: 8888
- **용도**: 보안 테스트 타겟
- **이미지**: Python Flask 기반 취약한 웹 애플리케이션
- **빌드**: `cd test_server && docker-compose build`
- **시작**: `cd test_server && docker-compose up -d`
- **중지**: `cd test_server && docker-compose down`

**포함된 취약점**:
- SQL Injection (`search.php`)
- XSS (`comment.php`)
- Command Injection (`ping.php`)
- Directory Traversal (`file.php`)

⚠️ **경고**: 이 서버는 의도적으로 취약합니다. 절대 공개 네트워크에 노출하지 마세요.

## 전체 시작/중지

### 모두 시작
```bash
cd cal-project/docker
docker-compose -f cai-qdrant/docker-compose.yml up -d
docker-compose -f test_server/docker-compose.yml up -d
```

### 모두 중지
```bash
cd cal-project/docker
docker-compose -f cai-qdrant/docker-compose.yml down
docker-compose -f test_server/docker-compose.yml down
```

## 저장소 구조

```
cal-project/docker/
├── cai-qdrant/
│   ├── docker-compose.yml
│   └── storage/              # Qdrant 데이터 저장소
├── test_server/
│   ├── docker-compose.yml
│   ├── Dockerfile
│   ├── app.py                # Flask 애플리케이션
│   ├── www/                  # 정적 파일 (HTML, PHP)
│   └── README.md             # 취약점 상세 설명
└── README.md                 # 이 파일
```

## 참고

- TRT (Toncal) Docker 서비스는 `E:\business\Cai\TRT\toncal\` 폴더에서 별도 관리됩니다.
- Qdrant 데이터는 `cai-qdrant/storage/`에 영구 저장됩니다.
