
```markdown
# Docker Security Guide: Basics, Hardening, and Privilege Escalation

## Table of Contents
1. [Docker Basics](#docker-basics)
2. [Core Security Concepts](#core-security)
3. [Privilege Escalation Risks](#privilege-risks)
4. [Security Hardening](#hardening)
5. [Privilege Escalation Prevention](#prevention)
6. [Monitoring & Auditing](#monitoring)
7. [Resources](#resources)

---

## 1. Docker Basics <a name="docker-basics"></a>

### Key Components
- **Images**: Read-only templates (potential attack surface)
- **Containers**: Runtime instances of images
- **Docker Daemon** (`dockerd`): Runs as root (critical security component)
- **Docker Client**: CLI interface to the daemon
- **Docker Hub**: Default public registry

### Basic Commands
```bash
docker build -t safe-image .          # Build image
docker run -it --rm alpine sh         # Run container interactively
docker ps -a                          # List all containers
docker inspect <container>            # Show container details
```

---

## 2. Core Security Concepts <a name="core-security"></a>

### Threat Model
1. **Breakout to Host**: Container escapes
2. **Denial of Service**: Resource exhaustion
3. **Supply Chain Attacks**: Malicious images
4. **Configuration Exploits**: Insecure defaults

### Security Principles
- **Least Privilege**: Containers should run with minimal permissions
- **Immutable Containers**: No runtime modifications
- **Defense in Depth**: Multiple security layers

---

## 3. Privilege Escalation Risks <a name="privilege-risks"></a>

### Common Attack Vectors
1. **Root Containers**:
   ```bash
   docker run --privileged -v /:/host ubuntu bash  # Mounts host FS
   ```
2. **SYS_ADMIN Capability**:
   ```bash
   docker run --cap-add=SYS_ADMIN ...
   ```
3. **Docker Socket Exposure**:
   ```bash
   docker run -v /var/run/docker.sock:/var/run/docker.sock ...
   ```
4. **Shared Namespaces**:
   ```bash
   docker run --pid=host --net=host ...
   ```

### Exploit Examples
- **Abusing writable cgroups**: Container escapes to host
- **Dirty Cow (CVE-2016-5195)**: Kernel exploits
- **Host Path Mounts**: Modifying host system files

---

## 4. Security Hardening <a name="hardening"></a>

### Host Configuration
```bash
# Ensure user namespaces are enabled
echo "kernel.unprivileged_userns_clone=1" >> /etc/sysctl.conf

# Apply kernel hardening
sysctl -w kernel.kptr_restrict=2
sysctl -w kernel.dmesg_restrict=1
```

### Container Security
```bash
# Run as non-root user
docker run -u 1000:1000 ...

# Drop all capabilities (then add needed ones)
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE ...

# Use read-only filesystem
docker run --read-only ...

# Enable security profiles
docker run --security-opt no-new-privileges ...
docker run --security-opt apparmor=docker-default ...
```

### Image Security
```dockerfile
# Example secure Dockerfile
FROM alpine:latest
RUN adduser -D appuser && \
    chown appuser /app
USER appuser
COPY --chown=appuser app /app
```

---

## 5. Privilege Escalation Prevention <a name="prevention"></a>

### Critical Defenses
1. **Never run containers as root**:
   ```bash
   docker run --user 1000:1000 ...
   ```
2. **Disable privileged mode**:
   ```bash
   # Instead of --privileged, add specific capabilities if absolutely needed
   docker run --cap-add=NET_ADMIN ...
   ```
3. **Protect Docker socket**:
   ```bash
   chmod 660 /var/run/docker.sock
   chown root:docker /var/run/docker.sock
   ```
4. **Use namespaces**:
   ```bash
   docker run --userns=host ...
   ```

### Runtime Protection
```bash
# Enable gVisor for additional isolation
docker run --runtime=runsc ...

# Use seccomp profiles
docker run --security-opt seccomp=profile.json ...
```

---

## 6. Monitoring & Auditing <a name="monitoring"></a>

### Audit Commands
```bash
# Check for privileged containers
docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Privileged={{ .HostConfig.Privileged }}'

# Scan for vulnerabilities
docker scan <image-name>

# Check container capabilities
docker inspect --format '{{ .HostConfig.CapAdd }}' <container>
```

### Tools
- **Falco**: Runtime security monitoring
- **Clair**: Static image vulnerability scanning
- **Docker Bench**: CIS benchmark compliance checker

---

## 7. Resources <a name="resources"></a>
- [Docker Security Documentation](https://docs.docker.com/engine/security/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker/)
- [OWASP Docker Security](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [gVisor](https://gvisor.dev/) - Container sandboxing
```

This guide covers:
1. Docker fundamentals
2. Core security principles
3. Privilege escalation risks with concrete examples
4. Hardening techniques with actionable commands
5. Prevention strategies
6. Monitoring approaches

