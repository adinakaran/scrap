```markdown
# Nmap Command Cheat Sheet

## Table of Contents
- [Basic Scans](#basic-scans)
- [Port Scanning Techniques](#port-scanning-techniques)
- [Banner Grabbing](#banner-grabbing)
- [Service Detection](#service-detection)
- [OS Detection](#os-detection)
- [Footprinting](#footprinting)
- [Vulnerability Scanning](#vulnerability-scanning)
- [Output Formats](#output-formats)
- [Firewall Evasion](#firewall-evasion)
- [Script Scanning](#script-scanning)
- [Timing and Performance](#timing-and-performance)
- [Advanced Techniques](#advanced-techniques)
- [Practical Examples](#practical-examples)
- [Nmap Scripting Engine (NSE)](#nmap-scripting-engine-nse)
- [Tips](#tips)
- [Resources](#resources)

## Basic Scans

| Command | Description | Example |
|---------|-------------|---------|
| `nmap <target>` | Basic TCP SYN scan | `nmap 192.168.1.1` |
| `nmap <target1> <target2>` | Scan multiple targets | `nmap 192.168.1.1 192.168.1.2` |
| `nmap <network>/<CIDR>` | Scan a network range | `nmap 192.168.1.0/24` |
| `nmap -iL <file>` | Scan targets from file | `nmap -iL targets.txt` |
| `nmap -sn <target>` | Ping scan (no port scan) | `nmap -sn 192.168.1.0/24` |

## Port Scanning Techniques

| Command | Description | Example |
|---------|-------------|---------|
| `nmap -p <port> <target>` | Scan specific port | `nmap -p 80 192.168.1.1` |
| `nmap -p <port-range> <target>` | Scan port range | `nmap -p 1-100 192.168.1.1` |
| `nmap -p- <target>` | Scan all ports (1-65535) | `nmap -p- 192.168.1.1` |
| `nmap -F <target>` | Fast scan (100 common ports) | `nmap -F 192.168.1.1` |
| `nmap --top-ports <n> <target>` | Scan top N ports | `nmap --top-ports 50 192.168.1.1` |

## Banner Grabbing

| Command | Description | Example |
|---------|-------------|---------|
| `nmap -sV --script=banner <target>` | Standard banner grabbing | `nmap -sV --script=banner 192.168.1.1` |
| `nmap -p <port> --script=banner <target>` | Grab banner from specific port | `nmap -p 21,22,80 --script=banner 192.168.1.1` |
| `nmap -sV --version-intensity 9 <target>` | Maximum version detection | `nmap -sV --version-intensity 9 192.168.1.1` |
| `nmap --script=http-headers <target>` | HTTP headers grabbing | `nmap --script=http-headers 192.168.1.1` |
| `nmap --script=ftp-anon <target>` | FTP banner and anonymous check | `nmap --script=ftp-anon -p 21 192.168.1.1` |

## Service Detection

| Command | Description | Example |
|---------|-------------|---------|
| `nmap -sV <target>` | Basic service detection | `nmap -sV 192.168.1.1` |
| `nmap -sV --version-light <target>` | Faster version detection | `nmap -sV --version-light 192.168.1.1` |
| `nmap -sV --version-all <target>` | Try every version probe | `nmap -sV --version-all 192.168.1.1` |
| `nmap -sV --version-trace <target>` | Show version detection process | `nmap -sV --version-trace 192.168.1.1` |
| `nmap --script=ssl-cert <target>` | SSL certificate detection | `nmap --script=ssl-cert -p 443 192.168.1.1` |

## OS Detection

| Command | Description | Example |
|---------|-------------|---------|
| `nmap -O <target>` | Basic OS detection | `nmap -O 192.168.1.1` |
| `nmap -O --osscan-limit <target>` | Only detect if promising | `nmap -O --osscan-limit 192.168.1.1` |
| `nmap -O --osscan-guess <target>` | Make guesses when unsure | `nmap -O --osscan-guess 192.168.1.1` |
| `nmap -O --max-os-tries 1 <target>` | Limit OS detection attempts | `nmap -O --max-os-tries 1 192.168.1.1` |
| `nmap -A <target>` | OS and service detection | `nmap -A 192.168.1.1` |

## Footprinting

| Command | Description | Example |
|---------|-------------|---------|
| `nmap --script=whois-domain <target>` | WHOIS domain lookup | `nmap --script=whois-domain example.com` |
| `nmap --script=dns-brute <target>` | DNS subdomain brute force | `nmap --script=dns-brute example.com` |
| `nmap --script=ip-geolocation* <target>` | IP geolocation | `nmap --script=ip-geolocation* 192.168.1.1` |
| `nmap --script=http-robots.txt <target>` | Check robots.txt | `nmap --script=http-robots.txt 192.168.1.1` |
| `nmap --script=hostmap-* <target>` | Discover hostnames | `nmap --script=hostmap-* 192.168.1.1` |

## Vulnerability Scanning

| Command | Description | Example |
|---------|-------------|---------|
| `nmap --script=vuln <target>` | Common vulnerability checks | `nmap --script=vuln 192.168.1.1` |
| `nmap --script=smb-vuln* <target>` | SMB vulnerabilities | `nmap --script=smb-vuln* -p 445 192.168.1.1` |
| `nmap --script=http-vuln* <target>` | HTTP vulnerabilities | `nmap --script=http-vuln* -p 80,443 192.168.1.1` |
| `nmap --script=ssl-* <target>` | SSL vulnerabilities | `nmap --script=ssl-* -p 443 192.168.1.1` |
| `nmap --script=vulscan --script-args vulscandb=scipvuldb.csv <target>` | External vulnerability DB | `nmap --script=vulscan 192.168.1.1` |

## Output Formats

| Command | Description | Example |
|---------|-------------|---------|
| `nmap -oN <file>` | Normal output | `nmap -oN scan.txt` |
| `nmap -oX <file>` | XML output | `nmap -oX scan.xml` |
| `nmap -oG <file>` | Grepable output | `nmap -oG scan.gnmap` |
| `nmap -oA <basename>` | All formats at once | `nmap -oA scan` |
| `nmap -v` | Increase verbosity | `nmap -v 192.168.1.1` |

## Firewall Evasion

| Command | Description | Example |
|---------|-------------|---------|
| `nmap -f <target>` | Fragment packets | `nmap -f 192.168.1.1` |
| `nmap --mtu <size>` | Set MTU size | `nmap --mtu 24 192.168.1.1` |
| `nmap -D <decoy1,decoy2>` | Decoy scan | `nmap -D RND:5 192.168.1.1` |
| `nmap --source-port <port>` | Use specific source port | `nmap --source-port 53 192.168.1.1` |
| `nmap --data-length <size>` | Append random data | `nmap --data-length 25 192.168.1.1` |

## Script Scanning

| Command | Description | Example |
|---------|-------------|---------|
| `nmap --script <script>` | Run specific script | `nmap --script http-title 192.168.1.1` |
| `nmap --script <category>` | Run script category | `nmap --script vuln 192.168.1.1` |
| `nmap --script-args <args>` | Script arguments | `nmap --script http-title --script-args http.useragent="Mozilla"` |
| `nmap --script-help <script>` | Script help | `nmap --script-help http-title` |
| `nmap --script-updatedb` | Update script database | `nmap --script-updatedb` |

## Timing and Performance

| Command | Description | Example |
|---------|-------------|---------|
| `nmap -T0` | Paranoid (slowest) | `nmap -T0 192.168.1.1` |
| `nmap -T1` | Sneaky | `nmap -T1 192.168.1.1` |
| `nmap -T3` | Normal (default) | `nmap -T3 192.168.1.1` |
| `nmap -T4` | Aggressive | `nmap -T4 192.168.1.1` |
| `nmap -T5` | Insane (fastest) | `nmap -T5 192.168.1.1` |

## Advanced Techniques

| Command | Description | Example |
|---------|-------------|---------|
| `nmap -sS <target>` | TCP SYN scan (default) | `nmap -sS 192.168.1.1` |
| `nmap -sT <target>` | TCP connect scan | `nmap -sT 192.168.1.1` |
| `nmap -sU <target>` | UDP scan | `nmap -sU 192.168.1.1` |
| `nmap -sN <target>` | TCP NULL scan | `nmap -sN 192.168.1.1` |
| `nmap -sX <target>` | TCP Xmas scan | `nmap -sX 192.168.1.1` |

## Practical Examples

### Comprehensive Security Audit
```bash
# Full security audit scan
nmap -p- -sV -O -T4 -A --script=vuln,malware,auth 192.168.1.1 -oA security_audit
```

### Web Application Footprinting
```bash
# Web server footprinting
nmap -p 80,443,8080,8443 -sV --script=http-title,http-headers,http-methods,http-robots.txt 192.168.1.1
```

### Network Vulnerability Assessment
```bash
# Network vulnerability scan
nmap -T4 -Pn --script vuln --script-args=unsafe=1 192.168.1.0/24 -oA vuln_scan
```

### Service-Specific Scanning
```bash
# MySQL vulnerability check
nmap -p 3306 --script=mysql-audit,mysql-vuln-cve2012-2122,mysql-info 192.168.1.1
```

### Network Discovery
```bash
# Ping sweep (discover live hosts)
nmap -sn 192.168.1.0/24

# Scan top ports on all live hosts
nmap -sn 192.168.1.0/24 | grep 'report for' | cut -d' ' -f5 | xargs nmap -sS -T4 --top-ports 100
```

### Firewall Evasion Scan
```bash
# Fragmented scan with decoys and timing
nmap -f -D RND:10 -T2 192.168.1.1
```

## Nmap Scripting Engine (NSE)

### Common Script Categories
| Category | Description |
|----------|-------------|
| `auth` | Authentication related scripts |
| `broadcast` | Discover hosts by broadcasting |
| `brute` | Brute force attacks |
| `default` | Default scripts (with -sC) |
| `discovery` | Service discovery |
| `dos` | Denial of service checks |
| `exploit` | Exploit verification |
| `external` | External services (e.g., whois) |
| `fuzzer` | Protocol fuzzing |
| `intrusive` | Potentially intrusive scripts |
| `malware` | Malware detection |
| `safe` | Safe scripts only |
| `vuln` | Vulnerability checks |
| `realvuln` | Verified vulnerability checks |

### Useful Script Examples
```bash
# Scan for SMB vulnerabilities
nmap --script smb-vuln* -p 445 192.168.1.1

# Check for Heartbleed vulnerability
nmap -p 443 --script ssl-heartbleed 192.168.1.1

# DNS enumeration
nmap --script dns-brute.nse 192.168.1.1

# FTP anonymous login check
nmap --script ftp-anon.nse -p 21 192.168.1.1
```

## Tips
1. Use `sudo` for SYN scans and OS detection (requires root privileges)
2. Combine options for powerful scans: `nmap -sS -sV -O -T4 -A`
3. Use `--packet-trace` to see what packets are being sent
4. Save scans with `-oA` for all output formats
5. Update Nmap regularly for latest scripts and features: `nmap --version` and `sudo apt update && sudo apt upgrade nmap`
6. For comprehensive scans, combine: `nmap -p- -sV -O --script=vuln`
7. Use `--min-rate` and `--max-rate` for bandwidth control
8. Consider using `-Pn` to skip host discovery when scanning known live hosts

## Resources
- [Official Nmap Documentation](https://nmap.org/book/man.html)
- [Nmap Cheat Sheet PDF](https://nmap.org/nmap_cheat_sheet.pdf)
- [NSE Script Documentation](https://nmap.org/nsedoc/)
- [Nmap Scripting Engine Guide](https://nmap.org/book/nse.html)
- [Nmap Vulnerability Scanning Guide](https://nmap.org/book/vscan.html)
```


