```markdown
# Kubernetes Security Guide: Basics, Hardening, and Privilege Escalation

## Table of Contents
1. [Kubernetes Basics](#kubernetes-basics)
2. [Core Security Concepts](#core-security)
3. [Privilege Escalation Risks](#privilege-risks)
4. [Cluster Hardening](#hardening)
5. [Privilege Escalation Prevention](#prevention)
6. [Monitoring & Auditing](#monitoring)
7. [Resources](#resources)

---

## 1. Kubernetes Basics <a name="kubernetes-basics"></a>

### Key Components
- **Control Plane**: API Server, Scheduler, Controller Manager, etcd
- **Nodes**: Run pods (kubelet, kube-proxy, container runtime)
- **Pods**: Smallest deployable units (1+ containers)
- **RBAC**: Role-Based Access Control system

### Basic Commands
```bash
kubectl get pods -A                      # List all pods
kubectl describe pod <pod-name>          # Inspect pod details
kubectl logs <pod-name>                  # View container logs
kubectl exec -it <pod-name> -- sh        # Execute shell in container
kubectl get roles -A                     # View cluster roles
```

---

## 2. Core Security Concepts <a name="core-security"></a>

### Threat Model
1. **Compromised Containers**: Container breakout attacks
2. **Over-Permissioned Pods**: Excessive RBAC permissions
3. **Cluster Takeovers**: Gaining control plane access
4. **Supply Chain Attacks**: Malicious container images

### Security Principles
- **Least Privilege**: Minimal required permissions
- **Network Segmentation**: Pod-to-pod communication limits
- **Immutable Infrastructure**: No runtime modifications
- **Defense in Depth**: Multiple security layers

---

## 3. Privilege Escalation Risks <a name="privilege-risks"></a>

### Common Attack Vectors
1. **Privileged Pods**:
   ```yaml
   # Dangerous pod spec
   securityContext:
     privileged: true
   ```
2. **HostPath Volumes**:
   ```yaml
   volumes:
     - name: host-root
       hostPath:
         path: /
   ```
3. **Token Mounting**:
   ```yaml
   automountServiceAccountToken: true  # Default in many cases
   ```
4. **Exposed Dashboard/API**:
   ```bash
   kubectl proxy --address=0.0.0.0 --accept-hosts='.*'  # Unsafe!
   ```

### Exploit Examples
- **Abusing privileged pods**: Host system access
- **Service account token theft**: Cluster lateral movement
- **etcd access**: Reading secrets from data store
- **Kubelet API abuse**: Unauthenticated access to node resources

---

## 4. Cluster Hardening <a name="hardening"></a>

### Cluster Configuration
```bash
# Enable PodSecurity admission (K8s 1.23+)
kubectl create namespace example
kubectl label namespace example pod-security.kubernetes.io/enforce=restricted

# Disable anonymous authentication
kube-apiserver --anonymous-auth=false
```

### Pod Security
```yaml
# Example secure pod spec
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
```

### RBAC Best Practices
```bash
# Create minimal role
kubectl create role pod-reader --verb=get,list --resource=pods

# Bind to service account
kubectl create rolebinding pod-reader-binding --role=pod-reader --serviceaccount=default:default
```

---

## 5. Privilege Escalation Prevention <a name="prevention"></a>

### Critical Defenses
1. **Pod Security Standards**:
   - Enforce `restricted` policy
   - Use `baseline` where exceptions needed

2. **Network Policies**:
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: default-deny
   spec:
     podSelector: {}
     policyTypes:
     - Ingress
     - Egress
   ```

3. **Service Account Controls**:
   ```bash
   # Disable auto-mounting where not needed
   kubectl patch serviceaccount default -p '{"automountServiceAccountToken": false}'
   ```

4. **Node Hardening**:
   - Enable SELinux/AppArmor
   - Use gVisor or Kata Containers for sensitive workloads

---

## 6. Monitoring & Auditing <a name="monitoring"></a>

### Audit Commands
```bash
# Check for privileged pods
kubectl get pods -A -o json | jq '.items[] | select(.spec.securityContext.privileged==true)'

# Check RBAC bindings
kubectl get rolebindings -A
kubectl get clusterrolebindings

# Audit service accounts
kubectl get serviceaccounts -A
kubectl get secrets -A | grep "service-account-token"
```

### Tools
- **kube-bench**: CIS benchmark compliance checker
- **Falco**: Runtime security monitoring
- **Kyverno**: Policy management
- **OPA Gatekeeper**: Policy enforcement

### Sample Audit Policy
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
  resources:
  - group: ""
    resources: ["secrets"]
```

---

## 7. Resources <a name="resources"></a>
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes/)
- [NSA Kubernetes Hardening Guide](https://media.defense.gov/2021/Aug/03/2002820425/-1/-1/1/CTR_KUBERNETES%20HARDENING%20GUIDANCE.PDF)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [OWASP Kubernetes Security](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
```

This guide covers:
1. Kubernetes fundamentals
2. Core security principles
3. Privilege escalation risks with concrete examples
4. Cluster hardening techniques
5. Prevention strategies with YAML examples
6. Monitoring approaches and tools

