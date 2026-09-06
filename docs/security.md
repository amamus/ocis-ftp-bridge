# Security Documentation

## Overview

The ocis-ftp-bridge is designed as a secure gateway between legacy FTP-based printers and modern oCIS storage. This document covers security considerations, deployment requirements, and hardening measures.

## Security Model

### Trust Boundaries

The bridge operates with the following trust model:

1. **Untrusted Zone**: Printers/Scanners connecting via FTP/FTPS
2. **Bridge Zone**: The ocis-ftp-bridge service
3. **Trusted Zone**: oCIS storage service

**Critical Principle**: Plain FTP must NEVER be exposed to untrusted networks.

### Authentication Flow

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│                 │         │                 │         │                 │
│   Printer       │────────▶│   Bridge       │────────▶│     oCIS        │
│                 │  FTP/   │                 │  Graph/  │                 │
│                 │  FTPS   │                 │  WebDAV │                 │
└─────────────────┘         └─────────────────┘         └─────────────────┘
       │                         │                       │
       │   Local Auth           │   Service Account    │
       │   (username/pass)      │   + App Token        │
       ▼                         ▼                       ▼
  ┌─────────────┐           ┌─────────────┐         ┌─────────────┐
  │             │           │             │         │             │
  │  Bridge DB  │           │  oCIS Auth  │         │  oCIS      │
  │  (config)   │           │  (Graph)    │         │  Storage   │
  │             │           │             │         │             │
  └─────────────┘           └─────────────┘         └─────────────┘
```

## Deployment Security Requirements

### Network Security

#### Plain FTP Deployment

**WARNING**: Plain FTP transmits credentials and file contents in cleartext.

**MANDATORY REQUIREMENTS:**
- ✅ Deploy bridge on isolated network segment (printer VLAN)
- ✅ Restrict bridge access to printer IPs only
- ✅ Block all external access to FTP ports (2121, passive range)
- ✅ Use firewall rules to prevent FTP traffic from leaving isolated network
- ✅ Never expose FTP ports to the Internet

**Network Diagram:**
```
┌─────────────────────────────────────────────────────────┐
│                 ISOLATED PRINTER NETWORK                      │
│  ┌─────────────┐         ┌─────────────────┐              │
│  │             │         │                 │              │
│  │  Printer    │────────▶│   ocis-ftp-     │              │
│  │  Network    │ FTP     │   bridge         │              │
│  │             │         │                 │              │
│  └─────────────┘         └────────┬────────┘              │
│                                    │                       │
│                                    ▼                       │
│                          ┌─────────────────┐                  │
│                          │    oCIS         │                  │
│                          │    (HTTPS)       │                  │
│                          └─────────────────┘                  │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐  │
│  │                    FIREWALL                               │  │
│  │  ┌─────────────┐         ┌─────────────────┐          │  │
│  │  │             │         │                 │          │  │
│  │  │  BLOCK FTP  │         │  ALLOW HTTPS   │          │  │
│  │  │  Ports      │         │  to oCIS       │          │  │
│  │  │  2121      │         │                 │          │  │
│  │  │  40000-50000│        │                 │          │  │
│  │  │             │         │                 │          │  │
│  │  └─────────────┘         └─────────────────┘          │  │
│  └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                              │
                      ┌───────────────────────┐
                      │     INTERNET          │
                      │   (UNTRUSTED)         │
                      │      ❌ NO FTP        │
                      └───────────────────────┘
```

#### Explicit FTPS Deployment

**RECOMMENDED** for production deployments.

**REQUIREMENTS:**
- ✅ Valid TLS certificates for bridge hostname
- ✅ Certificate chain trusted by printer clients
- ✅ All FTP traffic (control and data) encrypted
- ✅ Still requires network isolation for defense in depth

**Certificate Requirements:**
- Subject: Bridge hostname (e.g., `ftp-bridge.example.com`)
- SANs: All hostnames/IPs used to access bridge
- Key: RSA 2048+ or ECDSA P-256+
- Validity: Appropriate for your organization

### Container Security

#### Non-Root Operation

The bridge container runs as non-root user by default:

```dockerfile
FROM alpine:3.20
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser
```

- ✅ Container user: `appuser` (UID 1000)
- ✅ Container group: `appgroup` (GID 1000)
- ✅ No root privileges
- ✅ Writable volumes owned by appuser

#### Filesystem Permissions

**Spool Directory:**
- Owner: `appuser:appgroup`
- Permissions: `750` (owner: rwx, group: r-x, other: ---)
- Subdirectories: `750`
- Files: `640` (owner: rw-, group: r--, other: ---)

**Configuration Files:**
- Owner: `appuser:appgroup`
- Permissions: `600` (owner only)
- Contains sensitive credentials - MUST be mounted as secrets

#### Secrets Management

**NEVER bake secrets into container images:**

```yaml
# ❌ BAD - Secrets in image
FROM alpine:3.20
COPY config-with-secrets.yaml /app/config.yaml

# ✅ GOOD - Secrets mounted at runtime
volumes:
  - ./secrets:/app/secrets:ro
```

**Recommended Secret Management:**
1. **Kubernetes**: Use Secrets mounted as files
2. **Docker Compose**: Use environment variables or secret files
3. **Docker**: Use `--secret` flag (Docker 1.13+)

**Configuration File Secrets:**
- oCIS service account credentials
- App tokens
- Printer account passwords (hashed)
- TLS certificates and private keys

### Resource Limits

#### Memory and CPU

**Container Resource Limits:**
```yaml
# docker-compose.yaml
deploy:
  resources:
    limits:
      cpus: '1.0'
      memory: 512M
    reservations:
      cpus: '0.5'
      memory: 256M
```

**Recommended Limits:**
- CPU: 0.5-2.0 cores depending on concurrent uploads
- Memory: 256MB base + 64MB per concurrent upload
- Connections: 10-100 concurrent FTP sessions

#### Upload Limits

**Spool Configuration:**
```yaml
spool:
  directory: /var/spool/ocis-ftp
  maxsize: 10737418240  # 10GB
  cleanup_age_hours: 24
  file_permissions: 0600
  dir_permissions: 0700
```

**Per-Account Limits:**
```yaml
accounts:
  - username: printer1
    max_upload_size: 104857600  # 100MB
    max_concurrent_uploads: 5
```

## Security Features

### Path Traversal Protection

**Implementation:**
- All FTP paths are normalized using `filepath.Clean()`
- Absolute paths (`/etc/passwd`) are rejected
- Parent directory references (`../`) are detected and blocked
- Paths attempting to escape account root are rejected

**Validation Rules:**
1. Paths must be relative to account root
2. No absolute paths allowed
3. No `..` components allowed
4. No symlink following in spool directory
5. Filename validation (no control characters, max length)

**Examples:**
```
# Account root: /uploads

# ✅ ALLOWED
- scan.pdf
- folder/subfolder/file.txt
- file with spaces.txt
- file-with-unicode-📄.pdf

# ❌ BLOCKED
- /etc/passwd                          (absolute path)
- ../../../etc/passwd                  (traversal)
- folder/../../etc/passwd             (traversal in path)
- folder/../file.txt                  (parent reference)
- /uploads/../secret.txt              (traversal to escape)
- file\x00name.txt                    (null byte)
- "file>.txt"                          (special characters)
```

### Symlink Handling

**Security Measures:**
- Spool manager disables symlink following
- File operations use `O_NOFOLLOW` flag where supported
- Directory creation rejects existing symlinks
- Upload paths are validated to not contain symlinks

**Configuration:**
```yaml
spool:
  # Disable symlink following
  allow_symlinks: false  # Default: false
  
  # Reject files that are symlinks
  reject_symlinks: true  # Default: true
```

### Secret Redaction

**Never Log Secrets:**
```go
// ❌ BAD - Logging sensitive data
log.Printf("Uploading with token: %s", appToken)

// ✅ GOOD - Redacted logging
log.Printf("Uploading with token: [REDACTED]")

// ✅ GOOD - Structured logging with redaction
log.Info("upload start", 
    "user", user,
    "token", "[REDACTED]",
    "size", size)
```

**Redacted Fields:**
- Passwords (printer and service account)
- App tokens
- Authorization headers
- TLS private keys
- Configuration file contents in error messages

### TLS Configuration

**Recommended TLS Settings:**
```yaml
ftp:
  tls:
    enabled: true
    cert_file: /etc/ssl/certs/ftp-bridge.crt
    key_file: /etc/ssl/private/ftp-bridge.key
    
    # Modern TLS settings (default in Go)
    min_version: TLS12  # Default: TLS12
    cipher_suites: []  # Use Go defaults
    
    # Require TLS for all connections
    required: true  # Reject plaintext connections
    
    # Client certificate verification (optional)
    client_auth: require  # Optional: require client certs
    client_ca_file: /etc/ssl/certs/ca.crt
```

**TLS Best Practices:**
- Use TLS 1.2 or higher
- Disable SSLv3, TLS 1.0, TLS 1.1
- Use strong cipher suites (Go defaults are good)
- Certificate validity monitoring
- Automatic certificate rotation

### Network Security

#### Passive FTP Configuration

**Port Range:**
```yaml
ftp:
  passive:
    min_port: 40000
    max_port: 40100
    public_host: "ftp-bridge.example.com"
```

**Firewall Rules:**
```bash
# Allow FTP control port
iptables -A INPUT -p tcp --dport 2121 -j ACCEPT

# Allow passive port range
iptables -A INPUT -p tcp --dport 40000:40100 -j ACCEPT

# Allow outbound to oCIS (HTTPS)
iptables -A OUTPUT -p tcp --dport 443 -d ocis.example.com -j ACCEPT

# Default deny all other traffic
iptables -A INPUT -j DROP
```

#### NAT/Proxy Considerations

**Behind NAT:**
```yaml
ftp:
  passive:
    min_port: 40000
    max_port: 40100
    public_host: "public-ip.example.com"  # NAT public IP
```

**Docker/Kubernetes:**
- Use `public_host` to advertise external IP
- Configure port forwarding for passive range
- Test with `curl -v ftp://...` to verify passive IP

### Rate Limiting and Connection Controls

**Connection Limits:**
```yaml
server:
  max_connections: 100          # Total concurrent connections
  max_per_ip: 10               # Max connections per IP
  idle_timeout: 300            # Seconds of inactivity before disconnect
  connection_timeout: 60       # Connection establishment timeout
```

**Upload Rate Limiting:**
```yaml
accounts:
  - username: printer1
    max_upload_size: 104857600   # 100MB
    max_concurrent_uploads: 5   # Max simultaneous uploads per account
    rate_limit_bytes_per_sec: 10485760  # 10MB/s
```

**Global Limits:**
```yaml
server:
  max_total_uploads: 50       # Max concurrent uploads across all accounts
  max_bandwidth_mbps: 100     # Total bandwidth limit
```

## Security Hardening Checklist

### Pre-Deployment

- [ ] All printer passwords hashed in configuration
- [ ] oCIS service account has minimum required permissions
- [ ] TLS certificates valid and trusted by printer clients
- [ ] Network isolation configured for FTP traffic
- [ ] Firewall rules restrict FTP ports to printer IPs
- [ ] Spool directory has correct permissions (750)
- [ ] Container runs as non-root user
- [ ] Resource limits configured appropriately
- [ ] Health/readiness/metrics endpoints secured
- [ ] Log aggregation configured without sensitive data

### Runtime

- [ ] Monitor for failed login attempts
- [ ] Monitor spool directory usage
- [ ] Monitor concurrent connection counts
- [ ] Monitor upload success/failure rates
- [ ] Alert on configuration changes
- [ ] Regular backup of configuration files
- [ ] Certificate validity monitoring
- [ ] Dependency vulnerability scanning

### Incident Response

- [ ] Procedure for compromised printer credentials
- [ ] Procedure for suspected data breach
- [ ] Log retention policy defined
- [ ] Security contact information documented
- [ ] Vulnerability disclosure process established

## Vulnerability Management

### Known Security Considerations

1. **FTP Protocol Limitations**
   - Plain FTP vulnerable to credential interception
   - No built-in encryption or integrity protection
   - MITIGATION: Use FTPS or network isolation

2. **Spool Exhaustion**
   - Attacker could fill spool directory
   - MITIGATION: Size limits and quotas

3. **Path Traversal**
   - Malicious paths could access unauthorized files
   - MITIGATION: Strict path validation

4. **Memory Exhaustion**
   - Large uploads could consume memory
   - MITIGATION: Streaming uploads, no in-memory buffering

5. **Connection Flooding**
   - Attacker could open many connections
   - MITIGATION: Connection limits and timeouts

### Dependency Security

**Vulnerability Scanning:**
```bash
# Go vulnerability checker
govulncheck ./...

# Security scanner
gosec -severity=high ./...
```

**Dependency Updates:**
- Regular updates of all dependencies
- Security patch monitoring
- CVE database checking

### Security Testing

**Penetration Testing:**
- Path traversal attempts
- Buffer overflow attempts
- Credential brute force attempts
- Network flooding attempts
- TLS configuration testing

**Fuzzing:**
- Malformed FTP commands
- Invalid filenames
- Corrupted file content
- Unexpected protocol sequences

## Security Configuration Examples

### Secure Docker Compose

```yaml
version: '3.8'

services:
  ocis-ftp-bridge:
    image: ocis-ftp-bridge:latest
    container_name: ftp-bridge
    user: "1000:1000"  # Non-root user
    restart: unless-stopped
    
    # Network isolation
    networks:
      - printer-network
      - ocis-network
    
    # Port configuration
    ports:
      - "2121:2121"           # FTP control
      - "40000-40100:40000-40100"  # FTP passive range
      - "127.0.0.1:9200:9200" # HTTP metrics (local only)
    
    # Volume mounts
    volumes:
      - ./config.yaml:/app/config/config.yaml:ro
      - ./spool:/app/spool:rw
      - ./secrets:/app/secrets:ro
      - ./logs:/app/logs:rw
    
    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
    
    # Security options
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    
    # Environment
    environment:
      - TZ=UTC
      - LOG_LEVEL=info
    
    # Health checks
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:9200/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 5s

# Network definitions
networks:
  printer-network:
    driver: bridge
    # Restrict to printer subnet
    internal: true
    
  ocis-network:
    driver: bridge
    # Connect to oCIS network

# Secrets (managed separately)
secrets:
  ftp_bridge_config:
    file: ./secrets/config.yaml
  ocis_app_token:
    file: ./secrets/app-token.txt
```

### Secure Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ocis-ftp-bridge
  labels:
    app: ocis-ftp-bridge
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ocis-ftp-bridge
  template:
    metadata:
      labels:
        app: ocis-ftp-bridge
    spec:
      securityContext:
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
      
      containers:
      - name: ftp-bridge
        image: ocis-ftp-bridge:latest
        imagePullPolicy: IfNotPresent
        
        # Security context
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
          runAsNonRoot: true
        
        # Ports
        ports:
        - containerPort: 2121
          name: ftp
        - containerPort: 9200
          name: http-metrics
        
        # Resource limits
        resources:
          limits:
            cpu: "1"
            memory: "512Mi"
          requests:
            cpu: "500m"
            memory: "256Mi"
        
        # Liveness/Readiness probes
        livenessProbe:
          httpGet:
            path: /healthz
            port: 9200
          initialDelaySeconds: 10
          periodSeconds: 30
          timeoutSeconds: 5
          failureThreshold: 3
        
        readinessProbe:
          httpGet:
            path: /readyz
            port: 9200
          initialDelaySeconds: 5
          periodSeconds: 10
          timeoutSeconds: 3
          failureThreshold: 3
        
        # Environment
        env:
        - name: TZ
          value: UTC
        - name: LOG_LEVEL
          value: info
        
        # Volume mounts
        volumeMounts:
        - name: config
          mountPath: /app/config/config.yaml
          subPath: config.yaml
          readOnly: true
        - name: spool
          mountPath: /app/spool
        - name: secrets
          mountPath: /app/secrets
          readOnly: true
        - name: logs
          mountPath: /app/logs
      
      # Volumes
      volumes:
      - name: config
        configMap:
          name: ftp-bridge-config
      - name: spool
        persistentVolumeClaim:
          claimName: ftp-bridge-spool
      - name: secrets
        secret:
          secretName: ftp-bridge-secrets
      - name: logs
        emptyDir: {}
      
      # Network policy
      networkPolicy:
        podSelector:
          matchLabels:
            app: ocis-ftp-bridge
        policyTypes:
        - Ingress
        - Egress
        ingress:
        - from:
          - podSelector:
              matchLabels:
                app: printer
          ports:
          - protocol: TCP
            port: 2121
          - protocol: TCP
            portRange:
              min: 40000
              max: 40100
        egress:
        - to:
          - podSelector:
              matchLabels:
                app: ocis
          ports:
          - protocol: TCP
            port: 443

---
# Service for FTP
apiVersion: v1
kind: Service
metadata:
  name: ocis-ftp-bridge-ftp
spec:
  type: ClusterIP
  selector:
    app: ocis-ftp-bridge
  ports:
  - name: ftp
    port: 2121
    targetPort: 2121
    protocol: TCP
  - name: ftp-passive
    port: 40000
    targetPort: 40000
    protocol: TCP

---
# Service for metrics (internal only)
apiVersion: v1
kind: Service
metadata:
  name: ocis-ftp-bridge-metrics
spec:
  type: ClusterIP
  selector:
    app: ocis-ftp-bridge
  ports:
  - name: http
    port: 9200
    targetPort: 9200
    protocol: TCP
```

## Troubleshooting

### Common Security Issues

**Issue: Plain FTP exposed to Internet**
```bash
# Check for open FTP ports
nmap -p 2121,40000-40100 -sV target-server

# Fix: Restrict with firewall
ufw deny 2121/tcp
ufw deny 40000:40100/tcp
```

**Issue: Spool directory world-writable**
```bash
# Check permissions
ls -la /var/spool/ocis-ftp

# Fix: Set correct permissions
chown -R appuser:appgroup /var/spool/ocis-ftp
chmod -R 750 /var/spool/ocis-ftp
```

**Issue: Secrets in container image**
```bash
# Check for secrets in image
docker history ocis-ftp-bridge:latest | grep -i secret
docker inspect ocis-ftp-bridge:latest | grep -i password

# Fix: Rebuild without secrets, use volume mounts
```

**Issue: Running as root**
```bash
# Check container user
docker inspect ocis-ftp-bridge | grep User

# Fix: Configure user in Dockerfile
```

### Log Analysis

**Suspicious Login Attempts:**
```bash
# Find failed login attempts
grep "Login failed" /var/log/ftp-bridge.log | awk '{print $1, $2, $4}' | sort | uniq -c | sort -nr
```

**Path Traversal Attempts:**
```bash
# Find blocked path traversal
grep "Path traversal" /var/log/ftp-bridge.log
```

**Large Uploads:**
```bash
# Find large upload attempts
grep "Upload.*size" /var/log/ftp-bridge.log | awk '{print $1, $2, $4}' | sort -k3 -nr
```

### Metrics Analysis

**Connection Metrics:**
```bash
# Active FTP sessions
curl http://localhost:9200/metrics | grep ocis_ftp_sessions_active

# Upload failures
curl http://localhost:9200/metrics | grep ocis_ftp_upload_failures

# oCIS request errors
curl http://localhost:9200/metrics | grep ocis_requests_total{status="5xx"}
```

## Security Contacts

For security issues, vulnerabilities, or incidents:

- **Email**: security@amamus.net
- **GPG Key**: [Fingerprint to be added]
- **Response Time**: 24-48 hours for initial response
- **Disclosure**: Coordinated vulnerability disclosure process

**DO NOT** report security issues via public GitHub issues or email lists.