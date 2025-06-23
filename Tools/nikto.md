```markdown
# Nikto Web Server Scanner Guide

![Nikto Logo](https://cirt.net/images/nikto-logo.png)

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Scan Options](#scan-options)
5. [Advanced Techniques](#advanced-techniques)
6. [Output Formats](#output-formats)
7. [Interpretation of Results](#interpretation-of-results)
8. [Best Practices](#best-practices)
9. [Limitations](#limitations)
10. [Resources](#resources)

---

## Introduction
Nikto is an open-source web server scanner that performs comprehensive tests against web servers for multiple items.

**Key Features**:
- SSL support
- Proxy support
- Scan multiple ports
- Save reports in multiple formats
- Plugin-based architecture

---

## Installation

### Linux (Debian/Ubuntu)
```bash
sudo apt update && sudo apt install nikto
```

### Linux (From Source)
```bash
git clone https://github.com/sullo/nikto.git
cd nikto/program
perl nikto.pl -update
```

### Windows (via Perl)
1. Install Strawberry Perl
2. Run:
```cmd
cpan App::cpanminus
cpanm Nikto
```

### Docker
```bash
docker pull sullo/nikto
docker run --rm sullo/nikto -h
```

---

## Basic Usage

```bash
# Basic scan
nikto -h http://example.com

# Scan HTTPS site
nikto -h https://example.com

# Scan with port specification
nikto -h example.com -p 80,443,8080

# Update plugins database
nikto -update
```

---

## Scan Options

### Discovery Options
```bash
# Host scanning
nikto -h example.com -id my_scan_id

# Multiple hosts (from file)
nikto -h hosts.txt

# Scan entire subnet
nikto -h 192.168.1.0/24
```

### Tuning Options
```bash
# Only check for XSS vulnerabilities
nikto -h example.com -Tuning 1

# Only check for outdated server software
nikto -h example.com -Tuning 2

# Skip checks that cause server crashes
nikto -h example.com -Tuning 4
```

### Authentication
```bash
# Basic Auth
nikto -h example.com -id admin:password

# NTLM Auth
nikto -h example.com -id admin:password -usenlm
```

### Evasion Techniques
```bash
# Random URI encoding
nikto -h example.com -Evasion 1

# Directory self-reference
nikto -h example.com -Evasion 2

# Premature URL ending
nikto -h example.com -Evasion 3
```

---

## Advanced Techniques

### Using Plugins
```bash
# List available plugins
nikto -list-plugins

# Run specific plugin
nikto -h example.com -Plugins "apache_expect_xss"
```

### Proxy Support
```bash
nikto -h example.com -useproxy http://localhost:8080
```

### Mutations
```bash
# Mutate test cases
nikto -h example.com -mutate /path/to/mutations.txt
```

### Comprehensive Scan
```bash
nikto -h example.com -ssl -port 443 -Tuning 0 -Display V -Format htm -output scan_report.html
```

---

## Output Formats

```bash
# CSV output
nikto -h example.com -Format csv -output scan.csv

# HTML output
nikto -h example.com -Format htm -output report.html

# XML output
nikto -h example.com -Format xml -output results.xml

# JSON output (requires jq)
nikto -h example.com -Format json | jq .
```

---

## Interpretation of Results

### Common Findings:
1. **OSVDB-XXXXX**: Open Source Vulnerability Database ID
2. **Cookie without HttpOnly flag**: Session security issue
3. **X-XSS-Protection not enabled**: Browser XSS protection missing
4. **Allowed HTTP Methods**: Potentially dangerous methods (PUT, DELETE)

### Severity Levels:
- **0**: Informational
- **1**: Low
- **2**: Medium
- **3**: High
- **4**: Critical

---

## Best Practices

1. **Scan Timing**:
   ```bash
   # Slow scan (less intrusive)
   nikto -h example.com -delay 500
   ```

2. **Target Protection**:
   - Get permission before scanning
   - Avoid scanning production during peak hours

3. **Scan Optimization**:
   ```bash
   # Focus on important checks
   nikto -h example.com -Tuning xb
   ```

4. **Continuous Monitoring**:
   ```bash
   # Save results for comparison
   nikto -h example.com -output baseline_scan.xml
   ```

---

## Limitations

1. **No Vulnerability Exploitation**: Only identifies potential issues
2. **False Positives**: Manual verification required
3. **No JavaScript Analysis**: Static analysis only
4. **No Auth State Handling**: Basic auth only

---

## Resources

1. [Official Documentation](https://cirt.net/Nikto2)
2. [GitHub Repository](https://github.com/sullo/nikto)
3. [OSVDB Lookup](https://www.cvedetails.com/)
4. [Sample Mutations File](https://github.com/sullo/nikto/blob/master/program/mutations.txt)
```

### How to Use This Guide:
1. Save as `nikto_guide.md`
2. Customize for your needs
3. Convert to PDF/HTML if needed
4. Update with new Nikto features
