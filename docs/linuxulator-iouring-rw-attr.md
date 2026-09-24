# io_uring read/write attributes

Linux 7.1 adds `IORING_FEAT_RW_ATTR` and two SQE extension fields for the
read/write opcode family: `attr_ptr` and `attr_type_mask`.  Bit zero selects a
protection-information (`io_uring_attr_pi`) record.  The PI record is storage
metadata, not ordinary data: a complete implementation needs a native
metadata iterator and a target-device contract that can transfer protection
information with the data request.

The current native squeue engine has no such storage-metadata backend, so the
Linuxulator keeps `IORING_FEAT_RW_ATTR` clear.  It now gives every nonzero mask
an explicit result instead of silently executing an ordinary read or write:

- a zero mask ignores `attr_ptr`, including a non-null or invalid pointer;
- an unknown mask returns `EINVAL` before I/O or buffer lookup;
- the known `IORING_RW_ATTR_FLAG_PI` mask returns `EOPNOTSUPP` while the
  feature remains clear.

This validation belongs in `sys/compat/linux/linux_io_uring.c`.  The extension
field layout, Linux feature bit, PI structure and error policy are Linux ABI.
The shared squeue engine should gain code only when a real native metadata
transport exists; at that point both frontends can share the mechanism and the
Linuxulator can translate the PI record and advertise the feature.

The permanent `rw_attr` test covers mask-zero pointer handling, unknown-mask
rejection without a write side effect, a bad PI pointer and Linux's reserved-PI
field validation.  `rw_attr_opcode_matrix` repeats unknown-mask and known-PI
bad-pointer checks for READV, WRITEV, READ_FIXED, WRITE_FIXED, READ, WRITE,
READV_FIXED and WRITEV_FIXED.  This also pins validation before fixed-buffer
lookup.

Both cases passed the Linux 7.1.5 reference kernel in the disposable QEMU run
at `/tmp/rwattr-matrix-linux715.console.log`.  Both then passed three rounds in
the amd64 FreeBSD ZFS-root QEMU guest at
`/tmp/rwattr-matrix-focus.console.log`: six executions, all tracked squeue
resource counts returned to zero, the ZFS pool stayed healthy and the guest
powered off cleanly. Exact focused hashes are in
`/tmp/rwattr-focus-manifest.json`. The architecture-neutral Linux64 frontend
change does
not require another arm64 run under the current project gate policy. The
combined 432-case full gate also passed; its result and artifact hashes are
recorded in [the implementation gate](linuxulator-implementation-gate.md) and
`/tmp/linuxulator-quota-20260921/full4-run/manifest.json`.

## Read/write priority and write-stream audit (2026-09-21)

Linux 7.1 runs every nonzero read/write `sqe->ioprio` through
`ioprio_check_cap()`. Class NONE accepts only a zero low three-bit level,
classes BE and IDLE are accepted, realtime requires scheduling privilege, and
classes 4 through 7 are invalid. Higher data bits are independent Linux hint
bits and do not make class NONE invalid when its low three-bit level is zero.
Linux also consumes the adjacent `write_stream` byte as an advisory write
hint.

The Linuxulator frontend now applies that exact class, level and privilege
policy to READV, WRITEV, READ_FIXED, WRITE_FIXED, READ, WRITE, READV_FIXED and
WRITEV_FIXED. Valid priority and stream values remain advisory because native
squeue and the FreeBSD storage path do not expose an equivalent per-request
block priority or write-stream allocator contract. This policy belongs in the
Linux frontend: shared squeue accepts and transports the common SQE fields,
while Linux class numbering and realtime privilege checks remain ABI policy.

The permanent `rw_ioprio` case performs real writes with BE, IDLE, a class
NONE hint bit, `write_stream = 255`, and privileged realtime priority, then
checks the exact file data. `rw_ioprio_opcode_matrix` checks three invalid
encodings across all eight opcodes before buffer or descriptor side effects.
`rw_ioprio_privilege` drops to uid 65534 and requires `EPERM` for realtime
priority. All three passed the Linux 7.1.5 QEMU oracle and three rounds in the
disposable amd64 ZFS-root BSD QEMU guest. The focused guest reported zero live
requests, healthy ZFS, synced all buffers and powered off through ACPI. The
integrated gate evidence is recorded in
[the implementation gate](linuxulator-implementation-gate.md).
