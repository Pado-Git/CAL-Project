# 취약한 테스트 웹 서버

⚠️ **경고: 이 웹 서버는 의도적으로 취약점을 포함하고 있습니다.**

교육 및 보안 테스트 목적으로만 사용하세요. 절대 공개 네트워크에 노출하지 마세요.

## 포함된 취약점

1. **SQL Injection** - `search.php`
   - 테스트: `username=' OR '1'='1`
   
2. **Cross-Site Scripting (XSS)** - `comment.php`
   - 테스트: `<script>alert('XSS')</script>`
   
3. **Command Injection** - `ping.php`
   - 테스트: `localhost; ls`
   
4. **Directory Traversal** - `file.php`
   - 테스트: `../../etc/passwd`

## 실행 방법

### Docker Compose 사용 (권장)
```bash
# 서버 시작
docker-compose up -d

# 서버 중지
docker-compose down

# 로그 확인
docker-compose logs -f
```

### Docker 직접 사용
```bash
# 빌드
docker build -t cal-test-server .

# 실행
docker run -d -p 8081:80 --name cal-test-target cal-test-server

# 중지
docker stop cal-test-target
docker rm cal-test-target
```

## 접속

서버가 실행되면 다음 주소로 접속:
- **http://localhost:8080**

## cal 설정

`.env` 파일에서 타겟 URL 변경:
```env
TARGET_URL=http://localhost:8080
```

또는 Windows 호스트에서:
```env
TARGET_URL=http://host.docker.internal:8080
```

## 주의사항

- 이 서버는 **절대 프로덕션 환경에 배포하지 마세요**
- **로컬 환경에서만 실행하세요**
- 테스트 후 반드시 컨테이너를 중지하세요
- 방화벽에서 외부 접근을 차단하세요
