# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Issue #12**: Complete production hardening and documentation
  - Comprehensive architecture documentation (`docs/architecture.md`)
  - Detailed security documentation (`docs/security.md`)
  - Security policy and vulnerability reporting (`SECURITY.md`)
  - Contribution guidelines (`CONTRIBUTING.md`)
  - Changelog mechanism with structured format
  - Deployment examples for Docker Compose and Kubernetes
  - Hardening checklist and best practices

- **Issue #11**: End-to-end testing infrastructure
  - GitHub Actions CI workflow with multi-stage pipeline
  - Comprehensive E2E test scenarios covering all Issue #11 requirements
  - Mock oCIS WebDAV and Graph API servers for testing
  - Security scanning integration (govulncheck, gosec)
  - Release artifact builds for multiple platforms

- **Issue #10**: Container packaging and deployment
  - Multi-stage Dockerfile with Alpine base image
  - Non-root user configuration for security
  - OCI labels and version metadata
  - Container healthcheck integration
  - Docker Compose example with oCIS services
  - Kubernetes deployment with HPA, probes, security contexts
  - `.dockerignore` for proper build context

- **Issue #9**: HTTP operations and observability
  - Health endpoint (`/healthz`) for liveness probes
  - Readiness endpoint (`/readyz`) for service readiness
  - Metrics endpoint (`/metrics`) for Prometheus integration
  - Structured logging with stable field names
  - Comprehensive metrics (sessions, uploads, bytes, duration, oCIS requests)
  - Bounded cardinality labels to prevent metric explosion

- **Issue #8**: Explicit FTPS and passive-mode networking
  - Explicit FTPS support using ftpserverlib TLS facilities
  - Passive port range configuration
  - Public host/IP resolver for NAT deployments
  - EPSV support for modern clients
  - Data channel peer matching
  - TLS-required mode with plaintext rejection
  - Modern TLS defaults (TLS 1.2+)
  - Security warnings for plain FTP usage

- **Issue #7**: Path mapping, directory creation, collision policies
  - Path normalization and validation
  - Directory creation via WebDAV MKCOL
  - Three collision policies: `rename` (default), `reject`, `overwrite`
  - Traversal protection and root escape prevention
  - Unicode and spaces support in filenames
  - Concurrent upload safety with deterministic suffix generation
  - Nested directory support

- **Issue #6**: FTP server and printer upload command set
  - ftpserverlib integration for FTP/FTPS protocol
  - USER/PASS authentication with account selection
  - PWD, CWD, CDUP, TYPE, PASV, EPSV commands
  - STOR command for file upload
  - SIZE, NLST/LIST support for compatibility
  - MKD support for directory creation
  - QUIT command handling
  - Virtual filesystem model with account isolation
  - Destructive command rejection (DELE, RNFR/RNTO)
  - Upload-to-oCIS semantics with delayed FTP success
  - Client disconnect/cancel propagation

- **Issue #5**: Durable local upload spool and commit semantics
  - Per-upload temporary spool files with atomic semantics
  - Path traversal and filesystem write protection
  - Per-account and global upload size limits
  - Configurable total spool capacity
  - Partial upload cleanup on aborted sessions
  - Stale spool file handling on startup
  - Bounded memory usage with streaming
  - Deterministic startup behavior for stale files

- **Issue #4**: WebDAV upload client for oCIS spaces
  - WebDAV client supporting PUT, MKCOL, GET, HEAD, PROPFIND
  - Streaming file uploads without in-memory buffering
  - Conditional requests for collision detection
  - Proper URL escaping for path segments
  - Binary content preservation
  - HTTP error handling with specific status codes
  - Redirect safety (no credential following)
  - Client timeouts and connection reuse
  - Authentication via oCIS username + App Token

- **Issue #3**: LibreGraph drive discovery and target resolution
  - oCIS Graph API client with service account authentication
  - Drive resolution by ID (authoritative) or by name (must be unique)
  - Drive ID vs drive name mapping with proper validation
  - Drive metadata extraction (WebDAV URLs)
  - Typed errors for authentication, authorization, not found, ambiguous
  - Pagination support for Graph API responses
  - Context and timeout handling
  - Connection reuse for efficiency

- **Issue #2**: Configuration, printer accounts, oCIS credential mapping
  - YAML configuration with validation
  - Printer account configuration with password hashing
  - oCIS service account and App Token mapping
  - Per-account drive and target path configuration
  - Collision policy configuration per account
  - Size limit configuration per account
  - Secure configuration loading

- **Issue #1**: Bootstrap Go service and define bridge architecture
  - Go service foundation with proper module structure
  - Service lifecycle management
  - Error handling patterns
  - Package organization and dependencies

## [v1.0.0] - 2026-09-01

### Added

- Initial project structure and Go module
- Basic service architecture
- README with project overview
- LICENSE (Apache 2.0)
- GitHub repository setup

## Template for Future Entries

```
## [vX.Y.Z] - YYYY-MM-DD

### Added
- New features and functionality

### Changed
- Changes in existing functionality

### Deprecated
- Features that will be removed in future versions

### Removed
- Features that have been removed

### Fixed
- Bug fixes and corrections

### Security
- Security-related fixes and improvements
```

---

*Changelog started: September 2026*
*Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)*