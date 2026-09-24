# io_uring SPLICE and TEE fixed input files

Linux v6.18 accepts `SPLICE_F_FD_IN_FIXED` in both `IORING_OP_SPLICE` and
`IORING_OP_TEE`. With that bit set, `splice_fd_in` names a registered file
slot; it is not an ordinary descriptor. The output side remains controlled by
`fd` and can independently use `IOSQE_FIXED_FILE`. Linux removes the fixed-input
bit before passing the remaining splice flags to its splice implementation.
See [Linux v6.18 `io_uring/splice.c`](https://raw.githubusercontent.com/torvalds/linux/v6.18/io_uring/splice.c).

The registered-file table and captured descriptor rights already belong to
the shared squeue engine. `sq_install_registered_fd()` exposes its existing
lookup and transient-descriptor installation to front-end opcodes. A temporary
descriptor holds the file for the operation and carries the registered slot's
rights; it is closed after the call. The Linuxulator alone recognizes
`SPLICE_F_FD_IN_FIXED`, resolves `splice_fd_in` through this helper and removes
the bit before calling its existing `linux_kern_splice()` or `linux_tee()` path.
No native squeue opcode or syscall number is added.

The `splice_fixed_input` case registers a regular file, both ends of a pipe and
an empty slot. It closes the original file descriptor before doing an explicit-
offset file-to-pipe splice, then uses fixed input and fixed output together
with current-position semantics. It splices from a registered pipe to a file
and tees from that registered pipe to another pipe, checking that tee leaves
its input data intact. Negative cases cover out-of-range and empty slots for
SPLICE, out-of-range slot for TEE, unknown flag bits for both opcodes, and a
previously valid slot after unregister. It also checks the output file data
and position after failures. This case passed the Linux 6.18.35 reference guest
in `/tmp/linuxulator-gate-20260919/splice-fixed-oracle.console.log`.

Three ZFS and three tmpfs rounds passed in the disposable amd64 ZFS-root
guest at `/tmp/linuxulator-gate-20260919/splice-fixed-focus.console.log`,
with a healthy ZFS pool and clean shutdown. The full amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/splice-fixed-full-gate5/results.json`: 918
shared squeue-option, 345 general io_uring, 39 `NO_MMAP` and 33 SQPOLL case
runs, with no nonzero results or kernel diagnostics. Final ring pages and
handles were zero, the ZFS pool was healthy, and QEMU shut down cleanly.
Arm64 was not rerun because this slice is architecture-neutral.
