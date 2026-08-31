# ocis-ftp-bridge

A Go sidecar that allows legacy FTP and explicit-FTPS devices such as scanners
and multifunction printers to publish files into ownCloud Infinite Scale (oCIS).

## Architecture

```text
FTP / explicit FTPS client
        |
        v
github.com/fclairamb/ftpserverlib
        |
        v
bridge MainDriver + account-scoped virtual filesystem
        |
        +--> durable local spool
        |
        +--> LibreGraph API for drive/space resolution
        |
        +--> WebDAV MKCOL/PUT for file publication
        |
        v
       oCIS
```

The bridge is an independently deployable service. It uses only public oCIS APIs
and must not depend on internal oCIS gRPC, NATS, storage-driver or private service
interfaces.

## FTP protocol implementation

The FTP/FTPS protocol layer is
[`github.com/fclairamb/ftpserverlib`](https://github.com/fclairamb/ftpserverlib),
pinned to v0.32.3.

The bridge does **not** implement its own FTP command parser or state machine.
`ftpserverlib` owns USER/PASS, PASV/EPSV, PORT/EPRT, AUTH TLS/PROT, REST,
LIST/MLST and connection lifecycle. The bridge owns:

- configured FTP-account to oCIS-service-account mapping
- per-account virtual-root isolation
- durable spool behavior
- path and collision policy
- LibreGraph target resolution
- WebDAV publication
- observability and deployment configuration

### STOR completion contract

For uploads, ftpserverlib calls the selected `FileTransfer.Close()` before it
calls its transfer-completion path. A non-nil `Close()` error is propagated to
that completion path. The bridge will use this property to publish the completed
spool object to oCIS from the transfer handle and return FTP `226 Transfer
complete` only after the downstream WebDAV operation succeeds.

This ordering is a mandatory integration invariant and will be covered by
protocol-level tests in the FTP implementation issue.

## Development

The bootstrap issue intentionally does not start a production FTP listener yet.
Later issues provide configured accounts, the account-scoped filesystem, spool
persistence and the complete FTP/WebDAV pipeline.

Run the local checks with:

```sh
go test ./...
go vet ./...
```
