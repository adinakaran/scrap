```markdown
# LXC Security Guide: Basics, Hardening, and Privilege Escalation

## Table of Contents
1. [LXC Basics](#lxc-basics)
2. [Core Security Concepts](#core-security)
3. [Privilege Escalation Risks](#privilege-risks)
4. [Container Hardening](#hardening)
5. [Privilege Escalation Prevention](#prevention)
6. [Monitoring & Auditing](#monitoring)
7. [Resources](#resources)

---

## 1. LXC Basics <a name="lxc-basics"></a>

### Key Components
- **Host System**: Underlying OS running LXC (critical for security)
- **Containers**: Isolated user-space instances
- **Control Tools**: `lxc-*` commands for management
- **Backend Storage**: Typically ZFS, btrfs, or directory-based

### Basic Commands
```bash
lxc ls                          # List containers
lxc info <container>            # Show container details
lxc exec <container> -- bash    # Execute shell in container
lxc config show <container>     # Show container configuration
lxc stop <container>            # Stop a container
```

---

## 2. Core Security Concepts <a name="core-security"></a>

### Threat Model
1. **Container Breakouts**: Escaping to host system
2. **Resource Abuse**: CPU/memory/disk exhaustion
3. **Configuration Flaws**: Insecure container settings
4. **Kernel Exploits**: Shared kernel vulnerabilities

### Security Principles
- **Unprivileged Containers**: Always preferred over privileged
- **Namespace Isolation**: Proper use of user/pid/mount namespaces
- **Cgroup Limits**: Resource restrictions
- **AppArmor/SELinux**: Mandatory access controls

---

## 3. Privilege Escalation Risks <a name="privilege-risks"></a>

### Common Attack Vectors
1. **Privileged Containers**:
   ```bash
   lxc launch ubuntu test -c security.privileged=true  # Dangerous!
   ```
2. **Host Filesystem Access**:
   ```bash
   lxc config device add <container> hostdisk disk source=/ path=/host
   ```
3. **Insecure Kernel Features**:
   - `/proc` or `/sys` exposures
   - Unfiltered system calls

4. **Device Access**:
   ```bash
   lxc config device add <container> gpu gpu gid=44
   ```

### Exploit Examples
- **Abusing CAP_SYS_ADMIN**: Container escape via cgroups
- **Dirty Pipe (CVE-2022-0847)**: Kernel exploits
- **UID/GID Mapping Issues**: Bypassing user namespace isolation

---

## 4. Container Hardening <a name="hardening"></a>

### Host Configuration
```bash
# Enable user namespace remapping
echo "root:1000000:65536" >> /etc/subuid
echo "root:1000000:65536" >> /etc/subgid

# Configure kernel parameters
sysctl -w kernel.unprivileged_userns_clone=1
sysctl -w kernel.kptr_restrict=2
```

### Container Security
```bash
# Create unprivileged container
lxc launch ubuntu secure-container -c security.privileged=false

# Set resource limits
lxc config set <container> limits.cpu 2
lxc config set <container> limits.memory 512MB

# Enable AppArmor profile
lxc config set <container> raw.apparmor 'lxc-container-default-with-nesting'
```

### Example Secure Container Launch
```bash
lxc launch images:ubuntu/22.04 secure \
  -c security.privileged=false \
  -c security.nesting=false \
  -c limits.memory=1GB \
  -c limits.cpu=1
```

---

## 5. Privilege Escalation Prevention <a name="prevention"></a>

### Critical Defenses
1. **Always use unprivileged containers**:
   ```bash
   lxc init ubuntu safe-container -c security.privileged=false
   ```

2. **Secure ID mapping**:
   ```bash
   lxc config set <container> raw.idmap "both 1000 1000"
   ```

3. **Disable dangerous features**:
   ```bash
   lxc config set <container> security.syscalls.intercept.mknod false
   lxc config set <container> security.syscalls.intercept.setxattr false
   ```

4. **Network restrictions**:
   ```bash
   lxc config device add <container> eth0 nic nictype=bridged \
     parent=lxdbr0 name=eth0
   ```

### Runtime Protection
```bash
# Enable seccomp filtering
lxc config set <container> security.seccomp=true

# Use cgroup2
lxc config set <container> linux.cgroup2=true

# Disable module loading
lxc config set <container> security.privileged=false
lxc config set <container> security.syscalls.intercept.module_request=false
```

---

## 6. Monitoring & Auditing <a name="monitoring"></a>

### Audit Commands
```bash
# Check for privileged containers
lxc ls -c n,config | grep 'privileged=true'

# Verify ID mappings
lxc config show <container> | grep idmap

# Check AppArmor status
aa-status | grep lxc
```

### Tools
- **auditd**: Monitor LXC-related system calls
- **LXD Audit Logs**: `/var/log/lxd/`
- **AppArmor**: `aa-logprof` for profile generation
- **CIS Benchmark**: LXC-specific hardening guide

### Sample Audit Rules
```bash
# Monitor LXC container creation
auditctl -w /usr/bin/lxc-create -p x -k lxc_creation
auditctl -w /var/lib/lxc/ -p wa -k lxc_config
```

---

## 7. Resources <a name="resources"></a>
- [LXC Security Documentation](https://linuxcontainers.org/lxc/security/)
- [LXD Security Hardening](https://linuxcontainers.org/lxd/docs/master/security)
- [Kernel.org Namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [AppArmor for Containers](https://gitlab.com/apparmor/apparmor/-/wikis/AppArmor_and_containers)
- [Cgroups v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)

```

This guide covers:
1. LXC fundamentals and architecture
2. Core security principles for container isolation
3. Specific privilege escalation risks with examples
4. Hardening techniques with actionable commands
5. Prevention strategies for common attack vectors
6. Monitoring approaches and tools

