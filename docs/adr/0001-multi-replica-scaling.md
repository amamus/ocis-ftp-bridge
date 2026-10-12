# ADR 0001: Multi-Replica Scaling

- **Status:** Accepted (2026-10-12)
- **Related:** issue #71 (QLT-010), `docs/architecture.md` (Scaling and Multi-Replica Operation), `kubernetes/deployment.yaml`

## Context

FTP upload has no resume, so throughput scales with the number of bridge
instances. The Kubernetes example ships a HorizontalPodAutoscaler, but the
bridge was not multi-replica safe:

- The spool was a ReadWriteOnce PVC: only one pod can mount it, and the
  per-instance spool monitor (stale-file sweep) assumes it owns the
  directory exclusively.
- Connection limits, rate limiting, and auth lockouts are in-process state,
  so they are per-instance and ineffective globally.
- FTP sessions are long-lived, so Kubernetes cannot rebalance them; without
  session affinity a client's control and passive data connections can land
  on different pods, and the data connection fails because the target pod
  holds no session state.

## Decision

Run multiple replicas with three mechanisms:

1. **Per-replica spool.** Each pod gets an `emptyDir` volume instead of a
   shared PVC. Uploads are spooled and pushed to oCIS within the FTP
   session, so the spool never needs sharing between replicas. The
   in-bridge spool monitor enforces `spool.max_total_size` per instance.
2. **Session-pinned FTP.** `sessionAffinity: ClientIP` on the FTP control
   Service and on the passive-port Service. The affinity hash is computed
   from the client IP; both Services select the same pods in the same order,
   so one printer's control and data connections stay on one pod.
3. **Per-instance limits, documented.** Connection limits, rate limiting,
   and auth lockouts remain per-instance; with N replicas the effective
   limit is N times the configured value. The example HPA scales on CPU
   (min 1, max 3); operators size the limits by the replica count.

## Consequences

- **Positive:** horizontal scaling works; a pod eviction or crash only
  interrupts that pod's in-flight sessions, and new connections spread over
  the remaining pods.
- **Negative (accepted):** a pod crash loses that pod's in-flight uploads,
  because the `emptyDir` is pod-local. FTP has no resume, so the printer
  simply retries the upload. The spool is a staging area, not durable
  storage; durability is oCIS's responsibility.
- **Negative (accepted):** rate limits, connection limits, and auth lockouts
  are per-instance, so a distributed attacker gets N times the configured
  budget. The SEC-004 connection counter (fixed in #67) is likewise
  per-instance. The alternative — externalizing quota/rate-limit state — is
  a larger effort and out of scope for this decision.
- **Operational:** the passive-port Service example exposes only two ports
  of the configured range (Kubernetes Services cannot express port ranges);
  production deployments need an FTP-aware load balancer or a NodePort
  setup with the full range, still pinned by client IP.
