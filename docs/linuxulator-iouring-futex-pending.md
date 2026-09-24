# io_uring pending futex waits

`IORING_OP_FUTEX_WAIT` and `IORING_OP_FUTEX_WAITV` now park a request without
blocking its submitter or occupying an squeue I/O worker. The shared engine
owns pending-request lifetime, links, CQEs, cancellation and ring teardown.
Linuxulator owns Linux futex keying, private/shared scope, value, bitset and
vector rules. The umtx queue invokes a nonblocking callback after dequeue;
it schedules completion outside the umtx chain lock. A WAITV wake reports the
winning vector index. Same-ring and external wake, cancellation, ring close,
and wake/cancel races resolve once.

The Linux 6.18.35 oracle established pending wake and cancellation results,
bitset selection, vector index, external wake, invalid second-vector key,
opcode/all cancellation, linked-timeout cancellation and the descriptorless
`IOSQE_FIXED_FILE` behavior. The oracle cases all passed. Focused amd64
ZFS-root QEMU runs exercised the pending/race/cancellation cases on ZFS and
tmpfs, with clean shutdown and healthy ZFS. The final frozen 369-case
amd64 ZFS-root gate passed in 931.6 seconds: 369 io_uring cases, 918 native
and Linux squeue-option executions, 39 NO_MMAP and 33 SQPOLL executions,
zero diagnostics, zero nonzero results and final request/file counts of zero.
The exact results and SHA-256 artifact hashes are in
`/tmp/linuxulator-gate-20260919/futex-async-final-gate/results.json` and
`manifest.json`. The source was built with `-Werror`; the candidate kernel
and linux64 module ran only inside disposable QEMU guests.

For future changes, keep the oracle and VM gate on positive and negative
inputs, including invalid key and mask, cancellation by user data/opcode/all,
linked timeout, fixed-file flag, close, external wake and wake/cancel races.
Any change to the shared umtx or squeue path also requires native regressions
and the full ZFS-root gate. This record qualifies the named futex operations;
it does not imply that every io_uring opcode or option is complete.
