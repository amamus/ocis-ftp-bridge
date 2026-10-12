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

- ✅ Container user: `appuser` (system user created at image build time)
- ✅ Container group: `appgroup`
- ✅ No root privileges
- ✅ Writable directories owned by the container user

Note: the Docker Compose and Kubernetes examples below override the user to
`1000:1000` (`user:` / `runAsUser: 1000`). When you override the UID like
this, every writable volume (spool, logs) must be owned by or group-writable
to that UID/GID (in Kubernetes, `fsGroup`), or uploads fail with permission
errors.

#### Filesystem Permissions

**Spool Directory:**
- Owner: `appuser:appgroup`
- Permissions: `750` (owner: rwx, group: r-x, other: ---)
- Subdirectories: `750`
- Files: `600` (owner: rw-, group: ---, other: ---)

The spool manager creates directories with `0750` and files with `0600`, and
re-applies `0600` when committing an upload, so spooled documents are never
readable by other users on the host.

**Configuration Files:**
- Owner: `appuser:appgroup`
- Permissions: `600` (owner only)
- Contains sensitive credentials - MUST be mounted as secrets

#### Secrets Management

**NEVER bake secrets into container images:**

```dockerfile
# ❌ BAD - Secrets in image
FROM alpine:3.20
COPY config-with-secrets.yaml /app/config.yaml
```

```yaml
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
  # Directory for temporary upload storage (must be writable by the service)
  directory: /var/spool/ocis-ftp-bridge

  # Maximum total size of all files in the spool (prevents disk exhaustion)
  max_total_size: 10GiB

  # Spool usage monitoring, published as ocis_ftp_spool_* metrics on /metrics
  monitoring:
    enabled: true
    warning_threshold: 80    # log a warning at 80% usage
    critical_threshold: 95   # log a critical alert at 95% usage
    check_interval: 30s
```

Files left in the spool by a previous run are removed at startup when they
are older than 30 minutes.

**Per-Account Upload Limits:**
```yaml
accounts:
  - username: printer1
    upload:
      max_size: 100MiB  # maximum size of a single upload from this account
```

There is no per-account concurrency or bandwidth limit; bound concurrent
uploads with `server.max_connections` and `server.rate_limiting` below.

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
4. Filename validation (no control characters, max length)

The spool manager applies the same traversal checks to the local paths it
writes: user IDs and target paths containing `..` are rejected, and the
per-user spool directory is verified to stay inside the spool directory.

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

The spool manager does not use `O_NOFOLLOW` and has no symlink-specific
configuration; it relies on path validation instead:

- User IDs and target paths are rejected when they contain `..` (path
  traversal).
- The per-user spool directory is verified to stay inside the spool
  directory (`filepath.Rel` containment check).
- Temporary files are created with `os.CreateTemp` under the per-user
  directory (server-generated names, not client-controlled filenames).

Because of this, the spool directory must not be writable by untrusted local
users: a local attacker who can plant a symlink inside the spool directory
could redirect a write. Keep the spool directory owned by the service
account with `0750` permissions, on a dedicated volume.

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

Explicit FTPS is configured under `server.tls` (TLS is enabled by default;
plain FTP is insecure):

```yaml
server:
  tls:
    enabled: true
    cert: /etc/ssl/certs/ftp-bridge.crt   # PEM certificate
    key: /etc/ssl/private/ftp-bridge.key    # PEM private key
```

The certificate and key are loaded and validated at startup: both files must
exist and form a matching PEM pair, the certificate must be currently valid,
and the key must be strong (RSA 2048+ bits, ECDSA P-256/P-384/P-521, or
Ed25519). A missing, expired, or weak-key certificate fails startup instead
of surfacing on the first FTPS connection.

There is no client-certificate authentication and no configurable minimum
TLS version or cipher list: the Go TLS stack enforces TLS 1.2+ with modern
default ciphers.

**TLS Best Practices:**
- Use TLS 1.2 or higher (enforced by the Go TLS stack)
- Strong certificate keys (validated at startup, see above)
- Certificate validity monitoring
- Automatic certificate rotation

### Network Security

#### Passive FTP Configuration

**Port Range:**
```yaml
server:
  passive:
    min_port: 40000
    max_port: 40100
    public_ip: "ftp-bridge.example.com"  # advertised address for NAT/container deployments
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
server:
  passive:
    min_port: 40000
    max_port: 40100
    public_ip: "public-ip.example.com"  # NAT public IP
```

**Docker/Kubernetes:**
- Use `public_ip` to advertise the external IP
- Configure port forwarding for the passive range
- Test with `curl -v ftp://...` to verify the passive IP

### Rate Limiting and Connection Controls

**Connection and Authentication Limits:**
```yaml
server:
  max_connections: 100        # Total concurrent FTP connections
  rate_limiting:
    max_connections_per_ip: 10      # Max connections per IP
    max_global_connections: 100     # Max connections overall (0 = unlimited)
    max_auth_attempts_per_ip: 5     # Failed auth attempts per IP ...
    auth_attempt_window: 1m         # ... within this window
    auth_lockout_duration: 5m       # Lockout after exceeding the limit
    track_failed_attempts: true    # Enable auth rate limiting (default: true)
```

There are no per-account upload concurrency or bandwidth limits; the controls
above are the only rate limits. Per-account upload size limits are configured
under `accounts[].upload.max_size` (see Upload Limits).

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
- [ ] Operations endpoints secured: `/readyz` and `/metrics` require
  authentication (`http.auth` is enabled by default and a random password is
  generated and logged when `http.auth.password` is unset); `/healthz` stays
  unauthenticated for probes; the operations server binds to
  `127.0.0.1:9090` by default
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
   - MITIGATION: `spool.max_total_size` capacity enforcement, per-account
     `upload.max_size` limits, and spool usage metrics (`ocis_ftp_spool_*`)
     for alerting

3. **Path Traversal**
   - Malicious paths could access unauthorized files
   - MITIGATION: Strict path validation

4. **Memory Exhaustion**
   - Large uploads could consume memory
   - MITIGATION: Uploads stream from the FTP data connection to the spool in
     chunks and from the spool file to WebDAV; a file is never read fully
     into memory. Disk usage is bounded by `spool.max_total_size` and
     per-account `upload.max_size` limits.

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
      # The HTTP operations port (9090) is NOT published: the ops endpoints
      # (/readyz, /metrics) require basic auth, and the bridge must not share
      # a port with oCIS. Publish "127.0.0.1:9090:9090" only if you need
      # host access.
    
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
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:9090/healthz"]
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
  # The spool volume is ReadWriteOnce: run a single replica. Scale by
  # adding more bridges with separate spool volumes, not by adding replicas.
  replicas: 1
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
        - containerPort: 9090
          name: http
        
        # Resource limits
        resources:
          limits:
            cpu: "1"
            memory: "512Mi"
          requests:
            cpu: "500m"
            memory: "256Mi"
        
        # Liveness/Readiness probes against the operations port (9090).
        # /readyz requires authentication when http.auth is enabled (the
        # default), and kubelet httpGet probes cannot send credentials; this
        # example therefore probes /healthz for liveness. For readiness,
        # either disable http.auth on the cluster-internal operations port
        # (as the shipped kubernetes/deployment.yaml does) or probe /healthz
        # and check readiness externally.
        livenessProbe:
          httpGet:
            path: /healthz
            port: http
          initialDelaySeconds: 10
          periodSeconds: 30
          timeoutSeconds: 5
          failureThreshold: 3
        
        readinessProbe:
          httpGet:
            path: /healthz
            port: http
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
    port: 9090
    targetPort: 9090
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

**Metrics:**

`/metrics` requires authentication when `http.auth` is enabled (the default);
pass the generated or configured credentials with `-u`:

```bash
# Active FTP sessions
curl -u admin:<password> http://localhost:9090/metrics | grep ocis_ftp_sessions_active

# Upload failures
curl -u admin:<password> http://localhost:9090/metrics | grep ocis_ftp_uploads_failures_total

# oCIS request errors
curl -u admin:<password> http://localhost:9090/metrics | grep ocis_ftp_ocis_requests_total

# Spool usage (see spool.monitoring)
curl -u admin:<password> http://localhost:9090/metrics | grep ocis_ftp_spool_usage_percent
```

## Software Bill of Materials (SBOM)

### Overview

The ocis-ftp-bridge generates comprehensive Software Bill of Materials (SBOM) to provide full transparency into the software supply chain. SBOMs are automatically generated and updated as part of the CI/CD pipeline.

### SBOM Formats

The project generates SBOMs in two industry-standard formats:

1. **SPDX 3.0.1** (JSON-LD) - `sbom.spdx.json`
2. **CycloneDX 1.7** - `sbom.cyclonedx.json`

Both formats are widely supported by security tools, compliance frameworks, and vulnerability scanners.

The SBOM files are [REUSE](https://reuse.software) compatible: the SPDX SBOM is a
valid SPDX document and is recognised as such by the REUSE tool (REUSE
Specification 3.3 excludes SPDX documents from linting), while the CycloneDX
SBOM carries copyright and license information via the `REUSE.toml` annotation
and the `LICENSES/Apache-2.0.txt` license file.

### SBOM Contents

The SBOMs include:

- **Dependencies**: All direct and transitive Go module dependencies
- **Licenses**: License information for all components
- **Components**: Detailed information about each software component
- **Relationships**: How components depend on each other
- **External References**: PURLs (Package URLs) for vulnerability identification
- **Vulnerability Data**: Known vulnerabilities in dependencies (via Grype scanning)

### SBOM Generation

#### Automatic Generation

SBOMs are automatically generated:
- On every push to `main` branch
- On every pull request to `main` branch  
- On tag creation (releases)
- Weekly (every Sunday at midnight UTC)

#### Manual Generation

You can manually generate SBOMs using Syft:

```bash
# Install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Generate SPDX 3.0.1 SBOM
syft dir:. -o spdx-json@3.0=sbom.spdx.json

# Generate CycloneDX SBOM  
syft dir:. -o cyclonedx-json=sbom.cyclonedx.json
```

#### Docker Image SBOM

To generate an SBOM for the Docker image:

```bash
# Build the image
docker build -t ocis-ftp-bridge .

# Generate SBOM for the image
syft ocis-ftp-bridge -o spdx-json@3.0=docker-sbom.spdx.json
syft ocis-ftp-bridge -o cyclonedx-json=docker-sbom.cyclonedx.json
```

### SBOM Access

#### Development/Testing

- **GitHub Actions Artifacts**: SBOM files are available as downloadable artifacts in the SBOM workflow
- **Repository Files**: SPDX and CycloneDX SBOMs are committed to the repository root on main branch

#### Production Releases

- **GitHub Releases**: SBOM files are included in release assets
- **Release Artifacts**: Available in the release preparation workflow artifacts

### SBOM Validation

The CI pipeline validates that:
- The SPDX SBOM is a valid SPDX 3.0.1 JSON-LD document (`@context`, `@graph`,
  `CreationInfo` with `specVersion: 3.0.1`, packages and relationships)
- The CycloneDX SBOM contains components and dependencies
- SBOM files are valid JSON with license information and PURLs
- The SBOM files are REUSE compatible (`reuse lint` on the SBOM file set:
  the SPDX SBOM is recognised as an SPDX document, the CycloneDX SBOM is
  covered by `REUSE.toml`)

### Vulnerability Scanning

The SBOM workflow includes vulnerability scanning using Grype:

- Scans the generated SBOM for known vulnerabilities
- Reports findings with CVE IDs and severity levels
- Results are available in the `vulnerabilities.json` artifact

### Compliance Use Cases

#### Regulatory Compliance

SBOMs help meet requirements from:
- **Executive Order 14028** (US Federal): Requires SBOM for software sold to federal agencies
- **NIST SP 800-218**: Secure Software Development Framework guidelines
- **ISO/IEC 5962**: International SBOM standard
- **NTIA Minimum Elements**: US Department of Commerce SBOM guidelines

#### Supply Chain Security

- **Dependency Tracking**: Know exactly what's in your software
- **Vulnerability Management**: Quickly identify affected components
- **License Compliance**: Ensure all dependencies have compatible licenses
- **Incident Response**: Rapidly determine if a disclosed vulnerability affects your deployment

### SBOM Integration Examples

#### GitHub Dependency Review

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "daily"
    open-pull-requests-limit: 10
    labels:
      - "dependencies"
      - "security"
```

#### Vulnerability Alerting

Use the SBOM with vulnerability scanning tools:

```bash
# Scan with Grype
grype sbom:spdx.json -o json -q > vulnerabilities.json

# Filter for high/critical vulnerabilities
jq '.matches |= [.[] | select(.vulnerability.severity | ascii_downcase | contains("high") or contains("critical"))]' vulnerabilities.json
```

### SBOM Tools and Resources

- **Syft**: https://github.com/anchore/syft (SBOM generation)
- **Grype**: https://github.com/anchore/grype (vulnerability scanning)
- **SPDX Specification**: https://spdx.dev/specification/
- **CycloneDX Specification**: https://cyclonedx.org/specification/
- **NTIA SBOM Guidelines**: https://www.ntia.doc.gov/SBOM
- **NIST SSDF**: https://csrc.nist.gov/projects/ssdf

## Security Contacts

For security issues, vulnerabilities, or incidents:

- **Email**: security@amamus.net
- **GPG Key**: [Fingerprint to be added]
- **Response Time**: 24-48 hours for initial response
- **Disclosure**: Coordinated vulnerability disclosure process

**DO NOT** report security issues via public GitHub issues or email lists.