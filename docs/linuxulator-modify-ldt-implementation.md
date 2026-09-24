# Linux64 modify_ldt implementation and gate

The amd64 Linuxulator `modify_ldt(2)` handler translates Linux's 16-byte
`user_desc` and its four command values (`0`, `1`, `2`, `0x11`) to the existing
5BSD amd64 LDT backend. Linux64 owns command decoding, descriptor bitfields,
legacy versus modern clear behavior, non-present conforming descriptors,
the all-zero default-table read, and Linux error/return conventions. A shared
amd64 helper snapshots raw descriptor bytes under the LDT lock before copying
them to userspace, allowing partial byte reads without writing
past the supplied buffer. The Linux wrapper uses a backend variant that
accepts non-present conforming descriptors; native `sysarch` validation
remains unchanged. The native tunable's default is now 8192 entries, matching the Linux ABI's last legal index; no
new native syscall number was needed. The tunable remains available for
administrators who intentionally want a lower limit.

The freestanding `tests/sys/kern/linux_modify_ldt.c` probe passed the pinned
Linux 6.18.35 amd64 reference VM at
`/tmp/linuxulator-gate-20260919/ldt-oracle.console.log`. It exercises empty
and default-table reads, modern and legacy writes, exact and partial reads,
clear operations, a non-present conforming descriptor, fork inheritance,
entry 8191, invalid command, descriptor size, address, index and contents,
and EFAULT on reads and writes. The exact probe (SHA-256
`42b65be10bdb9db973899a7cba924cca029c41f6357c29d4172759da380e7339`)
passed three runs each on ZFS and tmpfs in the disposable amd64 ZFS-root
QEMU gate. The full result is
`/tmp/linuxulator-gate-20260919/ldt-conforming-gate/results.json`: 42 rseq,
343 io_uring, 786 squeue-option, 57 Linux AIO, 6 native AIO, 36 base,
144 pathname, 6 remap, 6 Linux ioperm, 6 native ioperm and 6 iopl cases;
zero recognized diagnostics, healthy ZFS and clean shutdown. No
candidate kernel or module was installed or loaded on the host.

Further qualification remains for 16-bit segments, concurrent LDT updates,
exec clearing, and use of a loaded LDT selector by 32-bit compatibility code.
Those cases need their own Linux-reference and disposable-VM tests before
claiming complete `modify_ldt` equivalence.
