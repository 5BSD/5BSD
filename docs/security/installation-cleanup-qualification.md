# Automatic installation cleanup qualification

This records the 2026-09-13 development qualification of automatic provider
cleanup. It extends the earlier [installation authority qualification](installation-authority-qualification.md),
whose tests ran with automatic cleanup disabled. The manager now dispatches
cleanup after a committed last-source removal by default.

## Tested behavior

A disposable QEMU VM exercised real managed installations using all five stateful
providers: tzfsd, localcrypto, warden, waspnest, and logd. The fixture allocated
private storage, a named cryptographic key, a persistent jail, a virtual socket,
and log storage. It checked:

- Updating a bundle preserves its installation identity and all five resources.
- Removing a superseded source and cancelling removal preserve the installation.
- Last-source removal cleans the old installation while another installation
  continues using its own resources.
- A disabled provider leaves an explicit pending receipt. Reinstallation gets a
  fresh identity, and delayed cleanup of the old identity spares its replacement.
- Pending receipts and a retained ZFS snapshot survive a normal reboot. The
  snapshot blocks private-storage destruction; cleanup completes after the test
  explicitly removes that snapshot and restores the disabled provider.
- The replacement retains its identity and storage across that reboot and can
  still use all five providers. The manager exits normally during shutdown
  without restarting cleanup providers during the drain.

The persistent VM run passed 152 checks: 52 core lifecycle/library cases, seven
CLI cases, six normal-plane administrative cases, 15 privileged library API
cases, four jail descriptor cases, eight provider cleanup/reuse cases, 53 log
store/storage cases, five live daemon integration cases, and two real-package
cases. Final results have no skips. Crypto initially skipped because the isolated
boot had not loaded cryptodev; loading the module and rerunning passed both cases.
Two live test harness errors were corrected: expecting a nonexistent stop-log
message and attempting administrative discovery from a fixture without that
channel. The corrected tests observe process exit and supervised restart.

The real-package cases cover interrupted installation/removal recovery and
upgrade/removal of every principal in the shipped runtime package hooks. Live
integration additionally covers queued-session fencing, provider restart/replay,
retained system-domain discovery after reload, old/new identity queries, and
explicit adoption of previously unregistered services.

## Capacity and performance

At the 262,144-record limit, eight concurrent clients completed 800 queries with
zero busy or unexpected results. Per-client p95 latency was 34.3–36.5 ms and
steady RSS was 45,680 KiB. A subsequent run sampled throughout startup and another
800 successful queries: peak RSS was 166,756 KiB, below the previously recorded
196,608 KiB provisional budget. Sampling is not an allocation high-water mark.

TCG startup of all eight clients took 22.5 seconds, or 24.0 seconds with startup
sampling. The ordinary fixture's 15-second readiness deadline was insufficient;
this capacity-only run used a bounded 120-second allowance in the disposable
fixture harness. These measurements do not establish a 15-second maximum-capacity
startup guarantee. The seed helper reports 261,579 added records; together with
the existing fixture records, the store contains the full 262,144 records.

## Defects found and fixed

Early read-only boot now defers provider inventory writes, and shutdown suppresses
cleanup activation. Reload retains each native service's bundle origin. Crypto
opens privileged control descriptors from its root factory before restricting
privilege; its process limit accounts for all processes with the same real UID.
Warden accepts an unchanged jail with empty IP lists on reuse. Jail descriptor
allocation precedes the prison-list lock, and failed base-descriptor lookup no
longer releases the caller's prison reference twice. Busy read-only CLI queries
return the retryable status rather than an I/O failure.

Cleanup records possible provider holdings before session delegation, retains
pending work through history pruning, and fences accepted and queued sessions.
Provider work sets and dispatch batches are bounded. Query replies and cleanup
share one validated registry cache in the single-threaded manager.

## Scope and remaining release qualification

This is a development image with runtime overlays under QEMU TCG, not a coherent
supported release image. The test kernel used the existing VBSD object set with
the jail fix and a prior kern_umtx object rebuilt privately: an unrelated current
kern_umtx build error prevented a complete kernel rebuild. Kernel provenance is
retained with the evidence. No unrelated kernel source was changed for the test.

The tests establish process-failure recovery and normal reboot behavior. They do
not establish durability under physical power loss. Snapshot/rollback must follow
the consistent registry, package, program, and provider-data recovery contract.
The earlier authority-only long soak is historical evidence, not a long soak of
the newly enabled cleanup path. Repeat release installation/upgrade and sustained
cleanup qualification on the exact supported image and package set.

Process protection is a separate follow-up: audit cap_protect coverage of each
provider factory and worker, including unauthorized signals, debugger attachment,
and tracing, while retaining authorized supervisor control.

## Retained evidence

The final normal-plane boot passed with the tested manager and libraries: the
replacement retained its identity, all five resources worked, and the old
installation still had five completed receipts. Debug/syslog and serial output
showed no new lock-order reversal, panic, or provider failure. Software crypto
was temporarily enabled for TCG fixture allocation and restored to zero; the
normal capability plane was restored. The VM then powered off with all buffers
synced.

Evidence is retained in `/tmp/authority-cleanup/evidence.tgz` (10,438,005 bytes),
SHA256 `6ba331228ede5cfa5122ef0c40e5169c25ee0c11344876d2bfd5d582b5a64f09`.
The archive was recovered from the dedicated export disk after shutdown and its
gzip integrity checked. The exported Kyua databases independently confirm the
152 final passing cases; superseded failed/skipped attempts remain in the archive.
Final deployed binary hashes match the retained payload. Host build logs, kernel
provenance, source hashes, and the complete serial log are alongside the archive.
These temporary artifacts must be preserved elsewhere with release evidence
before the workspace is discarded.
