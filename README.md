# Session Middleware Token Injection Vulnerability (CVE-2024-38513)
- 취약점 유형: CWE-384 Session Fixation
- Version: GoFiber <=2.52.4

### 요약 
GoFiber의 세션 미들웨어는 클라이언트가 쿠키로 전달한 session_id 값을 검증 없이 그대로 사용해 세션을 생성한다.
공격자가 임의의 session_id를 쿠키에 심으면 서버는 그 ID로 세션을 만든다.
이후 정상 사용자가 해당 ID로 로그인하면 공격자가 세션을 탈취할 수 있다. 만약 세션 존재 여부만으로 인증을 판단하는 앱이라면 인증 우회도 가능하다.

---


### 환경 설정 (Environment Setup)
다음 명령어를 통해 GoFiber의 2.52.4 버전의 테스트 환경을 구축합니다.
```bash
docker compose up -d 또는
docker compose up --build
