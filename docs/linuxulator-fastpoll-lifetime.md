# io_uring fast-poll file lifetime

## Contract

A Linux io_uring operation that returns `EAGAIN` and parks on fast poll remains
bound to the file selected when the SQE was submitted. Closing the ambient file
descriptor, then reusing that number for another file, must neither wake the old
request from readiness on the replacement nor strand it. Readiness on the
original file must retry the operation against that original file and preserve
the descriptor capability rights captured at submission.

This lifetime rule belongs to shared squeue. Linux opcode layouts, flag
validation, errno translation, and EPOLL_WAIT extension dispatch remain in the
Linuxulator. No native syscall number was added.

## Implementation

For a pollable ordinary descriptor, request preparation captures the target
`struct file` and its `filecaps`. A would-block request arms its per-ring kqueue
against that held file with a private request identity. The scanner therefore
does not depend on a reusable process descriptor number. Before retry, shared
squeue temporarily installs the captured file with the captured rights, invokes
the ordinary operation path, restores the SQE descriptor, and closes the
transient descriptor.

Fixed-file requests continue to use their registered-file generation. Once
shared squeue resolves a fixed file into a transient descriptor, it clears the
internal ambient-held-file marker in the dispatch copy so an extension such as
Linux EPOLL_WAIT cannot attempt a second resolution. Ring-file poll targets
retain their existing cycle-safe proxy/descriptor path because a direct strong
reference can form self-ring or mutual-ring close cycles.

## Permanent regression

`fastpoll_close_reuse` in `tests/sys/kern/linux_iouring.c` submits RECV on an
empty nonblocking socket, closes the receiver descriptor, reuses that descriptor
number for a new socket, proves readiness on the replacement does not complete
the request, then makes the original peer readable and requires the request to
return the original data. The test is in `tools/test/linuxulator/iouring-cases.json`
and the guest gate requires exactly 477 main cases.

The same branded binary passed 20 runs on Linux 6.18.35 and 20 runs on Linux
7.1.5. Before the fix, the amd64 FreeBSD candidate timed out with status 124,
which established that the negative test detects the stranded request. After
the fix, a 42-execution adjacent matrix passed.

The first complete candidate gate correctly rejected `epoll_wait_fixed` with
status 8. Failure-only diagnostics showed that readiness fired but retry
completed `-EBADF`. The fixed-file dispatch correction above then passed 100
`epoll_wait_fixed` runs interleaved with 100 `fastpoll_close_reuse` runs in a
WITNESS/INVARIANTS amd64 ZFS-root guest. Final request, registered-file, and
wired-page counters were zero.

## Accepted QEMU evidence

The corrected amd64 ZFS-root gate is
`/tmp/linuxulator-iouring-fastpoll-20260924/full2-run/results.json`. It passed
all 477 main io_uring cases, 1,146 shared native/Linux option executions, 78
shared-RWF executions, 78 registered-file lifecycle executions, three native
squeue runs, 39 NO_MMAP executions, 33 SQPOLL executions, 24 memory-region
executions, 21 query executions, and the broader Linuxulator matrices.
`fastpoll_close_reuse`, `epoll_wait_fixed`, and
`ioprio_send_zc_fixed_vectorized` each returned zero. The harness reported no
nonzero result and no recognized diagnostic. Final request, file, issuer,
token, and wired-page counts were zero; ZFS was healthy; all buffers synced;
and QEMU exited zero.

Artifact SHA-256 values:

- VM image: `d7be2fe12a082e78389e0f3f6e20b0f0dee8aae6b51f384c934e6f1ca0bba7ed`
- candidate kernel: `4c4e96bd450826643ec1458ab379d9fc849ba193f81f556657587dccf42daa16`
- test binary: `84cb42a525bc68633bbd5953ec8c5b860f2224f09b24f1879c98b3f2b84fb0e2`
- result JSON: `8900af6f20cec59f9333ae8cc50f8d16f56046a07a269d5c66702ed3bdff5dd2`
- console log: `1a932b2902f44d2487b3204416fa418f626e9fb8cc4871a3ac04010fe2e75628`

Arm64 runtime was waived for this architecture-neutral shared-core phase. The
candidate kernel and modules were never installed or loaded on the host.
