```markdown
# Burp Suite Professional Guide

![Burp Suite Logo](https://portswigger.net/burp/images/burp-suite-master.svg)

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Project Setup](#project-setup)
4. [Core Tools](#core-tools)
   - [Proxy](#proxy)
   - [Target](#target)
   - [Scanner](#scanner)
   - [Intruder](#intruder)
   - [Repeater](#repeater)
   - [Sequencer](#sequencer)
   - [Decoder](#decoder)
   - [Comparer](#comparer)
5. [Workflow](#workflow)
6. [Tips & Tricks](#tips--tricks)
7. [Resources](#resources)

---

## Introduction
Burp Suite is an integrated platform for security testing of web applications. This guide covers the Professional version features.

### Key Features:
- Intercepting proxy
- Automated scanner
- Advanced manual testing tools
- Extensibility via BApps (Burp Extensions)

---

## Installation
1. **Download**: Get the installer from [portswigger.net](https://portswigger.net/burp/pro)
2. **Install**: Run the installer for your OS (Windows/macOS/Linux)
3. **License**: Activate with your license key (or use trial mode)
4. **Java**: Ensure you have Java 11+ installed

---

## Project Setup
1. **New Project**:
   - Temporary (in-memory)
   - Saved to disk (recommended)
2. **Configuration**:
   ```bash
   Project Options > Connections > Upstream Proxy (if behind corporate proxy)
   User Options > Display > Font Size (adjust UI scaling)
   ```
3. **Browser Setup**:
   - Configure browser to use Burp as proxy (usually `127.0.0.1:8080`)
   - Install Burp's CA certificate (`http://burp/cert`)

---

## Core Tools

### Proxy
- **Intercept**: Toggle to capture requests
- **Forward/Drop**: Handle intercepted traffic
- **Action Menu**: Right-click for options (Send to Repeater, etc.)
- **Match/Replace**: Automate request/response modifications

### Target
- **Site Map**: Auto-populated tree of discovered content
- **Scope**: Define what's in/out of scope
   ```bash
   Target > Scope > Add (URL or regex)
   ```

### Scanner
1. **Active Scan**: Automated vulnerability detection
2. **Passive Scan**: Background analysis
3. **Scan Queue**: Manage running scans
4. **Issues**: Review found vulnerabilities

### Intruder
1. **Positions**: Mark insertion points with §
2. **Payloads**:
   - Simple list
   - Runtime file
   - Pitchfork (multiple payload sets)
3. **Attack Types**:
   - Sniper (single payload set)
   - Battering ram (same payload all positions)
   - Cluster bomb (all combinations)

### Repeater
- Manual request modification
- History of all sent requests
- Compare responses (diff view)

### Sequencer
- Analyze token randomness (session IDs, CSRF tokens)
- Live capture or manual load

### Decoder
- Smart decoding/encoding:
   - Base64
   - URL
   - HTML
   - Hex
- Hash generation

### Comparer
- Diff requests/responses
- Word-level comparison

---

## Workflow
1. **Proxy** → Browse application to populate Site Map
2. **Target** → Set scope and filter interesting endpoints
3. **Manual Testing**:
   - Use Repeater for specific requests
   - Run Intruder attacks on parameters
4. **Automated Testing**:
   - Right-click → "Active Scan"
   - Schedule scans for large applications
5. **Reporting**:
   - Generate HTML/XML reports
   - Export issues to CSV

---

## Tips & Tricks
### General:
- Use `Ctrl+R` to send requests between tools
- Bookmark interesting requests (Right-click → "Add to site map")

### Proxy:
- Create response rules to auto-unhide hidden form fields

### Intruder:
- Use "Grep - Extract" to mine responses for data
- Load huge wordlists from file rather than memory

### Scanner:
- Configure scan speed (Options > Misc > Scan Speed)
- Exclude false positives (Right-click → "False positive")

### Extensions:
- Install essential BApps:
  - Logger++
  - Turbo Intruder
  - Autorize

---

## Resources
1. [Official Documentation](https://portswigger.net/burp/documentation)
2. [Burp Suite Academy](https://portswigger.net/web-security)
3. [Community Extensions](https://github.com/PortSwigger)
4. [Practice Labs](https://portswigger.net/web-security/all-labs)

```

### How to Use This Guide:
1. Save as `burpsuite_guide.md`
2. Customize sections as needed
3. Convert to PDF if needed (using Markdown converters)
4. Keep it updated with new Burp features
