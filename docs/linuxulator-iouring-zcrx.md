# io_uring zero-copy receive: copied NODEV phase

## Scope and reference contract

`IORING_OP_RECV_ZC` now has a copied receive implementation for Linux
v7.1 `ZCRX_REG_NODEV`. Linux v7.1 adds `ZCRX_REG_NODEV` to `IORING_REGISTER_ZCRX_IFQ`. This mode does
not bind a NIC receive queue and explicitly copies received data into the
registered receive area. It provides a useful, reference-defined first phase
without claiming hardware zero-copy.

Pin the ABI and behavior to Linux v7.1 before implementation:

- [`include/uapi/linux/io_uring/zcrx.h`](https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/io_uring/zcrx.h)
- [`io_uring/zcrx.c`](https://github.com/torvalds/linux/blob/v7.1/io_uring/zcrx.c)
- [`io_uring/net.c`](https://github.com/torvalds/linux/blob/v7.1/io_uring/net.c)

The first phase supports `ZCRX_REG_NODEV` with ordinary user memory and TCP
sockets. It leaves net-device queue binding, DMABUF areas, import/export and
true hardware zero-copy unsupported and unadvertised.

## Ownership

Shared squeue should own the reusable mechanics:

- registered receive-area pinning and immutable lifetime references;
- the mmap-backed refill queue, acquire/release head and tail handling, and
  validation of returned area offsets;
- allocation, return and duplicate-return protection for receive chunks;
- copied socket receive into registered chunks, auxiliary CQE publication,
  cancellation, close and teardown serialization;
- resource counters and fault-injection points.

Linuxulator should own the Linux-only contract:

- the v7.1 ZCRX structures, constants and exact layout;
- `IORING_REGISTER_ZCRX_IFQ` and `IORING_REGISTER_ZCRX_CTRL` translation;
- setup requirements (`DEFER_TASKRUN` and `CQE32` or `CQE_MIXED`), capability
  checks, reserved fields, flag validation and Linux errno precedence;
- `IORING_OP_RECV_ZC` SQE decoding, `zcrx_ifq_idx`, `ioprio` flag checks and
  PROBE admission;
- rejecting hardware-only registration and control operations until their
  native backends exist.

Do not add a native syscall. Native squeue tests should enter through internal
registration/queue APIs so their ownership and lifetime rules are covered
without exposing Linux layouts to native applications.

## Required behavior for the first phase

Registration requires privilege, `IORING_SETUP_SINGLE_ISSUER` with
`IORING_SETUP_DEFER_TASKRUN`, and either
`IORING_SETUP_CQE32` or `IORING_SETUP_CQE_MIXED`. `rq_entries` is nonzero,
rounded to a power of two, and limited unless `IORING_SETUP_CLAMP` applies.
NODEV rejects nonzero interface and receive-queue selectors. Reserved fields,
unknown flags, a prefilled output `zcrx_id`, bad pointers and malformed region
or area descriptors fail without publishing a partial registration.

`RECV_ZC` requires a valid registered ZCRX id, zero `addr`, `addr2`, `addr3`
and `msg_flags`, and `IORING_RECV_MULTISHOT`. Only MULTISHOT and POLL_FIRST
are accepted in `ioprio` for this phase. TCP is supported; unsupported socket
protocols return the Linux reference error. Data completions use auxiliary
CQEs and identify the registered-area offset and length in the CQE32 payload.
Returned refill entries become reusable only after validation and acquire/
release publication. Closing the socket, ring, process or mapping must not
leave pinned pages or live requests.

The copied NODEV mode must be described as copied receive. It does not satisfy
applications that require NIC DMA into user memory.

## Linux oracle and candidate evidence

The freestanding Linux 7.1.5 QEMU matrix now passes 22 named cases. It covers
NODEV registration, setup and privilege requirements, bounded and multishot
TCP receive, user and mmap refill regions, refill reuse and malformed entries,
CQE32 and CQE_MIXED layouts, fixed files, multiple registrations, cancellation,
peer EOF, wrong descriptor and socket types, copyout rollback, pending ring
close, process exit, and PROBE admission. The Linux reference also fixes the
observable negative contract: an invalid import fd returns `EBADF`, NODEV with
DMA-BUF returns `EINVAL`, and explicit FLUSH_RQ consumes through the first
malformed entry while ordinary refill skips malformed entries.

The same 22 cases pass three rounds in the amd64 WITNESS ZFS-root candidate
VM (66 executions). All tracked requests, registered files, issuer references,
issuer tokens and wired pages return to zero; the ZFS pool remains healthy and
the VM powers off cleanly.

The frozen full gate also passes with no diagnostic failures or nonzero
results: 430 main io_uring cases, 1,092 shared-option executions, 39 NO_MMAP,
33 SQPOLL, 24 memory-region, 21 query, three native-squeue and 57 legacy-AIO
executions. Final page, file, request and issuer counts are zero, ZFS is
healthy, all buffers sync, and the guest powers off cleanly. Exact source,
kernel, module, test, image, console and result hashes are recorded in
`/tmp/linuxulator-gate-20260919/zcrx-final-full-gate3/manifest.json`.
Hardware queue binding, DMA-BUF receive, import/export and cross-ring sharing
remain outside this copied NODEV qualification.

## Mandatory oracle and VM matrix

Write freestanding named tests before enabling PROBE. Run every uncertain
errno and layout case on the Linux v7.1.5 oracle, then run the same cases in a
disposable amd64 ZFS-root BSD QEMU guest.

Positive cases:

- NODEV registration with kernel-allocated and user-backed regions;
- returned offsets, rounded refill size and requested receive page size;
- loopback TCP receive for one chunk, multiple chunks and a bounded length;
- MULTISHOT over several sends, POLL_FIRST, CQE32 and CQE_MIXED;
- refill and reuse after the consumer returns offsets;
- more than one ZCRX instance and explicit `zcrx_ifq_idx` selection;
- cancellation, peer shutdown, socket close, ring close, fork and process exit.

Negative cases:

- missing privilege; missing DEFER_TASKRUN; missing CQE32/CQE_MIXED;
- zero, excessive and CLAMPed queue sizes;
- unknown registration, area and SQE flags; every reserved field nonzero;
- bad, unmapped, read-only and boundary-crossing pointers;
- NODEV with nonzero `if_idx` or `if_rxq`; DMABUF and hardware queue requests;
- absent and stale ids; wrong fd type; UDP, Unix sockets and disconnected TCP;
- RECV_ZC without MULTISHOT; forbidden addresses or `msg_flags`;
- empty refill queue, malformed offsets, invalid area id, low offset-bit
  chunk selection,
  duplicate returns and producer overrun;
- CQ overflow, cancellation versus arrival, refill versus close, munmap/remap,
  exec and simultaneous ring teardown;
- allocation and copyout failure at each registration publication stage, with
  complete rollback.

Each focused case must run at least three rounds in the ZFS-root guest.
Add tmpfs rounds when the case exercises filesystem-backed behavior; copied
NODEV receive has no filesystem-dependent data path. Then run the full
Linuxulator guest gate. Acceptance requires zero nonzero test results, no
unexpected diagnostics, zero final pages/files/requests/issuers, healthy ZFS
and clean shutdown. Record source, kernel, module, binary, image, oracle and
result SHA256 hashes. Keep all candidate loading inside snapshot VMs. An arm64
runtime gate is required only if this phase gains machine-dependent code.

## Later phases

True ZCRX needs native network receive-queue ownership, DMA-safe memory,
packet lifetime transfer and driver participation. DMABUF and interface queue
registration belong there. `ZCRX_REG_IMPORT`, EXPORT and any cross-ring object
sharing need a separate fd-backed ownership design. Keep these operations
rejected and absent from negotiation until those backends and their race tests
exist.
