# Benchmarks

`matter-bench` (`bin/dev bench`) measures a bridge node as a controller sees it: both in one process, over UDP on
the loopback interface, with the real cryptography and MRP at its real timings. Commissioning runs PASE, device
attestation, the CSR, AddNOC and CASE; each later operation runs on the commissioned bridge. Figures are
milliseconds per operation, from a release build on an Apple M2 (16 GB) with macOS 27.

## 100 bridged lights

```
| Operation | Runs | Median | p95 | Max |
|---|---|---|---|---|
| PASE session | 5 | 5.87 ms | 6.11 ms | 6.11 ms |
| Commissioning (PASE, attestation, NOC, CASE) | 5 | 13.07 ms | 14.02 ms | 14.02 ms |
| CASE session | 20 | 2.56 ms | 3.05 ms | 3.05 ms |
| CASE resumption | 20 | 0.67 ms | 1.02 ms | 1.02 ms |
| Read one attribute | 200 | 0.18 ms | 0.26 ms | 0.44 ms |
| Read a device's every attribute | 50 | 0.50 ms | 0.74 ms | 1.21 ms |
| Invoke (toggle) | 200 | 0.14 ms | 0.28 ms | 0.81 ms |
| Subscription report after a change | 100 | 0.14 ms | 0.34 ms | 0.41 ms |
Reads from 10 sessions at once: 13921 reads/s
Resident memory: 6.3 MB at start, 14.7 MB with 100 bridged lights
```

## 500 bridged lights

```
| Operation | Runs | Median | p95 | Max |
|---|---|---|---|---|
| PASE session | 10 | 5.77 ms | 11.36 ms | 11.36 ms |
| Commissioning (PASE, attestation, NOC, CASE) | 10 | 13.51 ms | 23.40 ms | 23.40 ms |
| CASE session | 40 | 2.67 ms | 4.24 ms | 4.54 ms |
| CASE resumption | 40 | 0.66 ms | 0.84 ms | 0.86 ms |
| Read one attribute | 400 | 0.16 ms | 0.22 ms | 0.38 ms |
| Read a device's every attribute | 100 | 0.52 ms | 0.65 ms | 0.98 ms |
| Invoke (toggle) | 400 | 0.14 ms | 0.21 ms | 0.42 ms |
| Subscription report after a change | 200 | 0.14 ms | 0.20 ms | 0.44 ms |
Reads from 20 sessions at once: 14070 reads/s
Resident memory: 6.4 MB at start, 19.4 MB with 500 bridged lights
```

Memory grows by about 30 KB per bridged light (endpoints, clusters and their attributes).

## Reading the numbers

- Session establishment is dominated by the P-256 work: PASE's SPAKE2+ and the PBKDF2 of the passcode, CASE's
  ECDH and signatures. Resumption skips the certificates and signatures.
- Reads, invokes and reports stay well under a millisecond: the loopback leaves only the stack's own cost.
- A lossless exchange never waits for MRP: the answer carries the acknowledgement of the request. The
  `acknowledgesWithoutWaitingForRetransmissions` test keeps it so; this benchmark found it broken once (380 ms per
  exchange).

## Against Matterbridge

The comparison with Matterbridge (matter.js on Node.js) has not been run yet: it needs Node.js and the
`matterbridge` package installed beside this checkout. To run it, start Matterbridge with as many virtual lights,
commission it with the same controller code (a `matter-bench --peer` mode is the planned way), and report the same
operations in this file.
