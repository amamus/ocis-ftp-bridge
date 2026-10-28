# ADR-001: Single-Implementation Interfaces — Keep or Collapse?

**Status:** Accepted
**Date:** 2026-10-14
**Deciders:** amamus maintainers
**Issue:** #104

## Context

Six live interfaces have exactly one production implementation:

| Interface | Location | Implementation |
|-----------|----------|----------------|
| `spool.Manager` | pkg/spool/spool.go:92 | `defaultManager` |
| `spool.UploadManager` | pkg/spool/spool.go:178 | `uploadManager` |
| `spool.SpoolMonitor` | pkg/spool/monitor.go:225 | `Monitor` |
| `http.Server` | pkg/http/server.go:25 | `*OperationsServer` |
| `server.Server` | pkg/server/server.go:24 | `*server` |
| `ftp.Server` | pkg/ftp/ftp.go:26 | ftpserverlib server via `NewServer` |

For contrast, `graph.Client`, `webdav.Client`, and `observability.Client` have
2-3 implementations each (test fakes/mocks) and are genuine seams.

## Decision

**Keep all six interfaces.** Do not collapse them.

## Rationale

1. **Exported API stability**: These interfaces are exported. Collapsing them
   is a breaking API change that cascades across packages.

2. **Test seams**: Even with one production implementation, the interfaces
   enable mock-based unit testing. Removing them would couple tests to
   concrete types.

3. **Future extensibility**: The interfaces document the contract. Future
   implementations (e.g., a Redis-backed spool, a mock FTP server for E2E)
   can be added without changing consumers.

4. **Cost of keeping is low**: The interfaces are small and well-documented.
   The cost of collapsing (API surgery, cascading changes, lost test seams)
   far exceeds the benefit.

## Consequences

- No code changes required.
- Interfaces remain as-is.
- Future contributors should not collapse these interfaces without a new ADR.

## Alternatives Considered

- **Collapse to concrete types**: Rejected. Breaking API change, loses test
  seams, cascading changes across packages.
- **Add a second implementation**: Rejected as premature. YAGNI — add
  implementations when a real need arises, not to justify the interface.
