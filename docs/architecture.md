# Architecture and Design

The ocis-ftp-bridge provides FTP protocol support for printer/scanner file ingestion into oCIS (ownCloud Infinite Scale) via LibreGraph and WebDAV APIs.

## Overview

```
┌─────────────┐    FTP/FTPS    ┌─────────────────┐    Graph API     ┌─────────┐
│             │ ───────────────▶│                 │ ───────────────▶│         │
│  Printer/  │                 │  ocis-ftp-bridge │                 │  oCIS   │
│  Scanner   │ ◀───────────────│                 │ ◀───────────────│         │
│             │    FTP/FTPS      │                 │    WebDAV      │         │
└─────────────┘                └─────────────────┘                 └─────────┘
```

## Component Architecture

### Core Components

1. **FTP Server Layer** (`pkg/ftp/`)
   - Handles FTP/FTPS protocol using ftpserverlib
   - Authenticates printer accounts
   - Manages FTP sessions and commands
   - Implements path validation and traversal protection

2. **LibreGraph Client** (`pkg/graph/`)
   - Resolves configured drives via Graph API
   - Validates drive IDs and names
   - Retrieves WebDAV endpoints for file operations
   - Handles authentication with oCIS service accounts

3. **WebDAV Client** (`pkg/webdav/`)
   - Uploads files to oCIS via WebDAV
   - Creates directory structures
   - Implements conditional requests for collision handling
   - Streams file data without buffering entire files in memory

4. **Spool Manager** (`pkg/spool/`)
   - Manages temporary upload files
   - Enforces size limits and quotas
   - Handles cleanup of partial/stale uploads
   - Provides atomic commit semantics

5. **Transfer Pipeline** (`pkg/transfer/`)
   - Orchestrates upload workflow
   - Implements collision policies (rename, reject, overwrite)
   - Maps FTP paths to oCIS destinations
   - Handles path normalization and validation

6. **HTTP Operations Server** (`pkg/http/`)
   - Provides health, readiness, and metrics endpoints
   - Exposes Prometheus metrics
   - Implements structured logging

7. **Configuration** (`pkg/config/`)
   - Loads and validates YAML configuration
   - Manages FTP server settings
   - Configures oCIS endpoints and credentials
   - Defines printer accounts and permissions

## Trust Boundaries

### Network Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│                     TRUSTED NETWORK                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │             │    │             │    │             │  │
│  │  Printer 1  │───▶│   Bridge    │───▶│    oCIS     │  │
│  │             │    │             │    │             │  │
│  └─────────────┘    └─────────────┘    └─────────────┘  │
│          ▲                  ▲                    ▲           │
│          │                  │                    │           │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │             │    │             │    │             │  │
│  │  Printer 2  │───▶│   Bridge    │───▶│    oCIS     │  │
│  │             │    │             │    │             │  │
│  └─────────────┘    └─────────────┘    └─────────────┘  │
└─────────────────────────────────────────────────────────┘
                              │
                              │ FTP Control (2121)
                              │ FTP Data (passive ports)
                              ▼
                    ┌─────────────────┐
                    │   INTERNET      │  ❌ NOT ALLOWED
                    │ (UNTRUSTED)     │
                    └─────────────────┘
```

### Security Model

1. **Plain FTP**: Only allowed on isolated, trusted networks
   - Credentials and file contents are transmitted in cleartext
   - MUST be restricted to isolated printer VLANs with firewall rules
   - Never expose plain FTP to the Internet

2. **Explicit FTPS**: Recommended for production
   - Uses TLS for control and data channels
   - Prevents credential and data interception
   - Requires proper certificate management

3. **Bridge Isolation**: The bridge runs as a gateway service
   - Authenticates printers locally (not via oCIS)
   - Maps printer accounts to oCIS service accounts
   - Never exposes oCIS credentials to printers

## Why Graph for Drive Resolution and WebDAV for File Data

### LibreGraph API Usage

The LibreGraph API is used for **drive discovery and resolution** because:

- **Standardized API**: Graph provides a consistent way to discover available drives
- **Drive Metadata**: Returns drive IDs, names, and WebDAV endpoints
- **Service Account Support**: Works with oCIS service accounts and App Tokens
- **Multi-tenant**: Can resolve drives across different oCIS users/spaces

**Resolution Flow:**
1. Bridge starts with configured service account credentials
2. Graph API call retrieves available drives
3. Drive is resolved by ID (authoritative) or by name (must be unique)
4. WebDAV endpoint is extracted from drive metadata
5. All file operations use the resolved WebDAV URL

### WebDAV for File Operations

WebDAV is used for **file uploads and directory management** because:

- **Standard Protocol**: HTTP-based file management standard
- **oCIS Native**: oCIS provides full WebDAV support for file operations
- **Streaming Support**: Allows efficient file uploads without loading entire files into memory
- **Conditional Operations**: Supports If-None-Match, If-Match headers for collision detection
- **Directory Operations**: MKCOL for directory creation, PROPFIND for listing

**Upload Flow:**
1. Printer connects via FTP and uploads file to bridge spool
2. Bridge validates file size and completeness
3. Bridge maps FTP path to oCIS target path
4. Bridge creates parent directories via WebDAV MKCOL
5. Bridge streams file to oCIS via WebDAV PUT
6. Bridge confirms success and cleans up spool file
7. FTP success response sent to printer only after oCIS confirmation

## Configuration Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Configuration                           │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐    ┌─────────────────┐                  │
│  │   Server        │    │    HTTP         │                  │
│  │   Settings      │    │   Operations    │                  │
│  └─────────────────┘    └─────────────────┘                  │
│         │                   │                              │
│  ┌─────────────────┐    ┌─────────────────┐                  │
│  │   FTP           │    │    oCIS         │                  │
│  │   Settings      │    │   Settings      │                  │
│  └─────────────────┘    └─────────────────┘                  │
│         │                   │                              │
│  ┌─────────────────┐    ┌─────────────────┐                  │
│  │   Spool         │    │   Accounts      │                  │
│  │   Settings      │    │   Configuration │                  │
│  └─────────────────┘    └─────────────────┘                  │
│         │                                                      │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              Printer Account Configuration                ││
│  │  [ {user, pass, drive_id, target_path, collision, limits} ] ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## Data Flow

### Upload Workflow

```
1. Printer Connection
   └─▶ FTP USER/PASS authentication

2. File Transfer Initiation
   └─▶ FTP STOR command with target path

3. Spool Reception
   └─▶ Write to temporary spool file with atomic semantics

4. Path Resolution
   └─▶ Map FTP path to oCIS target path
   └─▶ Validate path (traversal protection, naming)
   └─▶ Resolve drive via Graph API

5. Directory Creation
   └─▶ Create parent directories via WebDAV MKCOL

6. Collision Handling
   └─▶ Check if target exists
   └─▶ Apply collision policy (rename/reject/overwrite)

7. File Upload
   └─▶ Stream file from spool to oCIS via WebDAV PUT

8. Commit Confirmation
   └─▶ Verify oCIS upload success
   └─▶ Clean up spool file
   └─▶ Return FTP 226 Transfer complete

9. Error Handling
   └─▶ On any failure: clean up spool, return appropriate FTP error
```

### Collision Policy Flow

```
┌─────────────────────────┐
│     Collision Detected   │
└──────────────┬───────────┘
               │
      ┌────────▼────────┐
      │    Policy:       │
      │    RENAME        │◀────── Default
      └────────┬────────┘
               │
        ┌──────▼───────┐
        │  Generate     │
        │  Unique Name │
        │  (timestamp  │
        │   suffix)    │
        └──────┬───────┘
               │
        ┌──────▼───────┐
        │  Upload Both │
        │  Files       │
        └─────────────┘

┌─────────────────────────┐
│     Collision Detected   │
└──────────────┬───────────┘
               │
      ┌────────▼────────┐
      │    Policy:       │
      │    REJECT        │
      └────────┬────────┘
               │
        ┌──────▼───────┐
        │  Return FTP   │
        │  Error 550    │
        │  (File exists)│
        └─────────────┘

┌─────────────────────────┐
│     Collision Detected   │
└──────────────┬───────────┘
               │
      ┌────────▼────────┐
      │    Policy:       │
      │    OVERWRITE     │
      └────────┬────────┘
               │
        ┌──────▼───────┐
        │  Overwrite    │
        │  Existing     │
        │  File         │
        └─────────────┘
```

## Failure Modes and Recovery

### Spool Management

- **Partial Uploads**: Automatically cleaned up when FTP session ends
- **Stale Files**: Cleaned up on startup based on age threshold
- **Capacity Limits**: New uploads rejected when spool is full
- **Atomic Operations**: Spool files are only removed after successful oCIS commit

### Network Failures

- **oCIS Unavailable**: FTP upload fails with retryable error
- **Timeout Handling**: Configurable timeouts for all network operations
- **Connection Limits**: Bounded concurrent connections and goroutines

### Error Propagation

- **FTP Errors**: Appropriate FTP response codes (4xx/5xx) returned
- **oCIS Errors**: Mapped to appropriate FTP responses
- **Configuration Errors**: Fail fast at startup with clear messages
- **Runtime Errors**: Logged with structured fields, never leak secrets

## Security Considerations

### Authentication

- **Printer Accounts**: Local to bridge, not oCIS users
- **Service Accounts**: oCIS accounts used by bridge for Graph/WebDAV
- **App Tokens**: Used for service account authentication
- **Password Hashing**: Printer passwords are hashed (bcrypt) in config

### Data Protection

- **TLS**: Required for FTPS, recommended for all deployments
- **Secret Management**: No credentials in logs or error messages
- **Path Validation**: All paths validated for traversal and injection
- **Size Limits**: Configurable limits prevent resource exhaustion

### Isolation

- **Network**: Plain FTP must be on isolated networks
- **Filesystem**: Spool directory permissions restricted
- **Process**: Bridge runs as non-root user in container
- **Symlinks**: Symlink following disabled in spool operations

This architecture provides a secure, reliable bridge between legacy FTP-based printers and modern oCIS storage while maintaining clear trust boundaries and failure semantics.