# Session Middleware Token Injection Vulnerability (CVE-2024-38513)
- 취약점 유형: CWE-384 (Session Fixation)
- 취약 버전: github.com/gofiber/fiber/v2 < 2.52.5
- CVSS v3.x Score: 9.8 Critical
- 공개일: 2024-07-01
  
### 요약 
GoFiber의 세션 미들웨어는 클라이언트가 쿠키로 전달한 session_id 값을 검증 없이 그대로 사용해 세션을 생성한다.
공격자가 임의의 session_id를 쿠키에 심으면 서버는 그 ID로 세션을 만든다.
이후 정상 사용자가 해당 ID로 로그인하면 공격자가 세션을 탈취할 수 있다. 만약 세션 존재 여부만으로 인증을 판단하는 앱이라면 인증 우회도 가능하다.

---

## 1. 환경 설정 (Environment Setup)
다음 명령어를 통해 GoFiber의 2.52.4 버전의 테스트 환경을 구축합니다.
```bash
docker compose up -d 또는 docker compose up --build
```

---

## 2. 취약점 재현 (Vulnerability Reproduction)

**정상적인 세션 ID**
![](images/1.png)

공격자는 자신이 만든 세션 ID를 사용해 로그인을 처리합니다.
```bash
curl -i -H "Cookie: session_id=attacker1234" http://localhost:3000/login
```

**공격자가 생성한 세션 ID**
![](images/2.png)

동일한 세션으로 관리자 페이지에 요청을 보냅니다.

**정상 처리 케이스**
![](images/3.png)
![](images/4.png)
```bash
curl -i -H "Cookie: session_id=attacker1234" http://localhost:3000/admin
```

**공격자가 의도한 케이스**
![](images/5.png)

앞에서 로그인된 attacker1234를 그대로 사용합니다. 

---

## 3. 대응 방안 (Mitigation)
- GoFiber 라이브러리를 v2.52.5으로 업그레이드를 하여 대응 가능합니다.
- 세션 내 값으로 인증 여부를 명시적으로 검증
```go
// 취약한 코드
if sess.Fresh() {
    return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
}
// 서버 내부 값 검증
if sess.Fresh() || sess.Get("authenticated") != true {
    return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
}
```
- 로그인 시 세션 ID 재생성
```go
app.Post("/login", func(c *fiber.Ctx) error {
    // 인증 성공 후
    sess, _ := store.Get(c)
    
    // 기존 세션 파기 후 새 ID 생성 → 세션 고정 방지
    if err := sess.Regenerate(); err != nil {
        return c.Status(500).SendString(err.Error())
    }
    
    sess.Set("authenticated", true)
    sess.Set("user", "admin")
    return sess.Save()
})
```
- 세션 ID가 서버에서 발급 한 것인지 확인
```go
func validateSessionID(store *session.Store) fiber.Handler {
    return func(c *fiber.Ctx) error {
        cookieID := c.Cookies(store.Config.CookieName)
        if cookieID != "" {
            // UUID 형식이 아닌 ID는 거부
            if _, err := uuid.Parse(cookieID); err != nil {
                c.Cookie(&fiber.Cookie{
                    Name:  store.Config.CookieName,
                    Value: "",
                    MaxAge: -1,
                })
            }
        }
        return c.Next()
    }
}
```

---

## 4. 참고자료
| 구분 | URL |
|---|---|
| NVD CVE 상세 | https://nvd.nist.gov/vuln/detail/CVE-2024-38513 |
| GitHub Security Advisory | https://github.com/gofiber/fiber/security/advisories/GHSA-98j2-3j3p-fw2v |
| 패치 커밋 | https://github.com/gofiber/fiber/commit/66a881441b27322a331f1b526cf1eb6b3358a4d8 |
| CWE-384 Session Fixation | https://cwe.mitre.org/data/definitions/384.html |
