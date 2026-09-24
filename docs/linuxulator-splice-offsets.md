# io_uring SPLICE offsets

Linux io_uring passes `splice_off_in` and `off` in the SQE by value. `-1`
means the corresponding descriptor's current position; a nonnegative offset
selects a file position without changing that descriptor's current position.
[Linux v6.18 `io_uring/splice.c`](https://raw.githubusercontent.com/torvalds/linux/v6.18/io_uring/splice.c)
uses the same `do_splice` operation as the direct syscall after converting
those values into optional kernel offset pointers.

The Linuxulator now shares one splice data path between the direct `splice(2)`
wrapper and its io_uring opcode. The direct wrapper copies offset values from
and back to user pointers; the io_uring front end supplies kernel-owned
copies of the SQE values. Descriptor-role checks, pipe room/availability,
read/write operations, flag validation and byte-count results remain in
`linux_file.c`. Native squeue does not expose `IORING_OP_SPLICE`, so this is
Linuxulator ownership rather than a new native syscall or shared-squeue
operation.

The `splice_offsets` case in `tests/sys/kern/linux_iouring.c` covers file to
pipe with explicit input offset and then current position; pipe to file with
explicit output offset and then current position; a direct-syscall offset
pointer baseline; exact bytes and unchanged/current descriptor positions;
explicit offsets on either pipe side (`ESPIPE`); negative offsets (`EINVAL`);
unknown flags; two non-pipe descriptors; and preservation of pipe data and
file position after each rejected request. It passed the Linux 6.18.35 oracle
in `/tmp/linuxulator-gate-20260919/splice-offsets-oracle.console.log`.
The rebuilt Linux64 module passed a `-Werror` build. Three ZFS and three
tmpfs focused rounds passed in the disposable amd64 ZFS-root guest at
`/tmp/linuxulator-gate-20260919/splice-focus.console.log`, with a healthy
pool and clean shutdown.

The full amd64 ZFS-root gate passed in
`/tmp/linuxulator-gate-20260919/splice-full-gate/results.json`: 918 shared
squeue-option, 344 general io_uring, 39 `NO_MMAP` and 33 SQPOLL case runs,
with no nonzero results or kernel diagnostics. The guest reported zero final
ring pages, a healthy ZFS pool and clean shutdown. Arm64 was not rerun because
this slice contains no architecture-specific changes. `SPLICE_F_FD_IN_FIXED`,
which uses a registered input file slot, remains a separate option and is not
claimed by this offset case.
