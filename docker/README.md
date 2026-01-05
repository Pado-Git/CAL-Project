# Docker Images for cal Hands

이 디렉토리는 cal의 "Hands" (실행 엔진)가 사용할 보안 도구 Docker 이미지들을 포함합니다.

## 이미지 목록

### 1. security-tools (올인원)
모든 기본 보안 도구가 포함된 이미지입니다.

**포함된 도구:**
- nmap
- curl
- wget
- DNS tools (dig, nslookup)
- Python 3

**빌드:**
```bash
docker build -t cal/security-tools:latest ./security-tools
```

**사용 예:**
```bash
docker run --rm cal/security-tools nmap -p 80 example.com
```

### 2. nmap (경량)
nmap만 포함된 경량 이미지입니다.

**빌드:**
```bash
docker build -t cal/nmap:latest ./nmap
```

**사용 예:**
```bash
docker run --rm cal/nmap -p 1-1000 scanme.nmap.org
```

## 빌드 스크립트

모든 이미지를 한 번에 빌드:
```bash
# Windows PowerShell
docker build -t cal/security-tools:latest .\security-tools
docker build -t cal/nmap:latest .\nmap

# Linux/Mac
docker build -t cal/security-tools:latest ./security-tools
docker build -t cal/nmap:latest ./nmap
```

## cal 코드 업데이트

`internal/hands/tools/tools.go`에서 이미지 이름을 변경하여 커스텀 이미지 사용:

```go
func NmapScan(ctx context.Context, executor ToolExecutor, target string, ports string) (string, error) {
    cmd := []string{"-p", ports, target}
    return executor.RunTool(ctx, "cal/nmap:latest", cmd)  // 변경됨
}
```
