# Complexity Hotspots Tracking

This document tracks known complexity hotspots identified during the lean-cleanup
audit (Phase 2, 2026-10-12). These should be addressed in structural batches
AFTER the E2E suite is written, so behavior is pinned by tests before any
code motion.

## Production Functions (by line count)

| Function | Lines | Location | Notes |
|----------|-------|----------|-------|
| NewOperationsServer | 301 | pkg/http/server.go:301 | God constructor: 13 prometheus collectors + registry + routes + auth wiring |
| validateWithEnv | 108 | pkg/config/config.go:401 | Sequential validation; table-driving must preserve exact error strings |
| StartUpload | 106 | pkg/spool/spool.go:262 | |
| AuthUser | 96 | pkg/ftp/driver.go:454 | |
| uploadWriter.Close | 95 | pkg/ftp/driver.go:1113 | |
| handleUploadOpen | 84 | pkg/ftp/driver.go:977 | |
| FinishUpload | 77 | pkg/spool/spool.go:421 | |
| NewBridgeDriver | 73 | pkg/ftp/driver.go:341 | |
| server.New | 73 | pkg/server/server.go:39 | |

## Test Functions (by line count)

| Test | Lines | Location |
|------|-------|----------|
| TestPathTraversalSecurity | 187 | pkg/transfer/transfer_test.go:603 |
| TestWebDAVClient_WithMockServer | 132 | pkg/webdav/client_test.go:51 |
| TestTransferManager_CalculateTargetPath | 124 | pkg/transfer/transfer_test.go |
| TestPathNormalization | 122 | pkg/webdav/path_validation_test.go:8 |
| TestProcessUploadIntegration | 112 | pkg/transfer/transfer_test.go |
| TestValidateTLSConfig | 104 | pkg/config/config_test.go:291 |
| TestEdgeCases | 101 | (various) |

## Recommendation

Schedule these as structural batches AFTER the E2E suite is written, so
behavior is pinned by tests before any code motion. None of them block
E2E-suite authoring.

## Status

- [ ] E2E suite written (prerequisite)
- [ ] Batch 1: Extract metrics registration from NewOperationsServer
- [ ] Batch 2: Table-drive validateWithEnv
- [ ] Batch 3: Extract upload lifecycle helpers from uploadWriter.Close
- [ ] Batch 4: Split handleUploadOpen into smaller functions
- [ ] Batch 5: Split test functions into focused subtests
