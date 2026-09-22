# Linux64 ioperm implementation and gate

The amd64 Linuxulator `ioperm(2)` wrapper validates the Linux 64-bit `from`
and `num` arguments before converting them to the native bitmap arguments. A
zero-length range, overflow, or any port outside 0–65535 returns `EINVAL`.
Any nonzero `turn_on` enables the selected ports; zero disables them. The
wrapper uses the existing amd64 I/O permission bitmap, so no new native
syscall is needed. The shared backend now checks privilege and securelevel
only when enabling permission and avoids allocating a bitmap for a disable
request when none exists. This lets an unprivileged process revoke its own
permission, matching the [Linux x86 syscall source](https://codebrowser.dev/linux/linux/arch/x86/kernel/ioport.c.html#71).

The freestanding `tests/sys/kern/linux_ioperm.c` probe passed the pinned Linux
6.18.35 amd64 reference VM at
`/tmp/linuxulator-gate-20260919/ioperm-oracle.console.log`. It checks initial
revocation, enable/disable, the last legal port, invalid ranges and zero
length, then drops privilege and requires enable to fail with `EPERM` while
disable succeeds. The native `tests/sys/kern/ioperm_native.c` probe checks the
shared bitmap's state and the same privilege transition through `sysarch`.
Both probes passed three times on ZFS and three times on tmpfs in the
disposable amd64 ZFS-root QEMU gate. The Linux probe SHA-256 was
`973ada06d347750cc1aabafbac929293911936351f9ff7ce18a7849ec42ccb7d`;
the native probe SHA-256 was
`5c0ea7616c2e337cd1a7f050901dc870615acbec77e27efbc3feeaba32dcf195`.
The full result is
`/tmp/linuxulator-gate-20260919/ioperm-second-gate/results.json`: 42 rseq,
343 io_uring, 786 squeue-option, 57 Linux AIO, 6 native AIO, 36 base,
144 pathname, and 6 remap cases; zero recognized diagnostics, healthy ZFS
and clean shutdown. Full Linuxulator, squeue, io_uring and AIO
regressions, zero recognized diagnostics, healthy ZFS and clean shutdown
remain mandatory. No candidate kernel or module is installed or loaded on
the host.

Further qualification remains for actual port access, inherited permission
across fork and exec, and interactions with `iopl`. Those are not covered by
these probes.
