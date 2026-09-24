# Linux64 iopl privilege-transition option

The existing amd64 Linuxulator `iopl(2)` handler accepted levels 0–3, but
required `PRIV_IO` even when a process kept or lowered its current level.
Linux requires privilege when raising the level; retaining or lowering it
succeeds without `CAP_SYS_RAWIO`. The handler now reads the current level
from the saved user flags and applies the privilege and securelevel checks
only for an increase, following the [Linux x86 syscall source](https://codebrowser.dev/linux/linux/arch/x86/kernel/ioport.c.html#179).

The freestanding `tests/sys/kern/linux_iopl_options.c` probe passed the pinned
Linux 6.18.35 amd64 reference VM at
`/tmp/linuxulator-gate-20260919/iopl-oracle.console.log`. It checks an
invalid level, the unchanged initial level, a privileged increase to 3, then
after dropping all UIDs checks same-level and lower-level success plus
increases returning `EPERM`. The exact probe (SHA-256
`f66579b67dc38d6d9315700aa03ba49dcd6f1e93cb5c914f5a74316c97ec8de5`)
passed three times on ZFS and three times on tmpfs in the disposable amd64
ZFS-root QEMU gate. The full result is
`/tmp/linuxulator-gate-20260919/iopl-full-gate/results.json`: 42 rseq,
343 io_uring, 786 squeue-option, 57 Linux AIO, 6 native AIO, 36 base,
144 pathname, 6 remap, 6 Linux ioperm and 6 native ioperm cases; zero
recognized diagnostics, healthy ZFS and clean shutdown. No candidate module is installed or loaded on the host.

The handler still uses the 5BSD saved IOPL flag representation. Linux now
emulates `iopl` with its per-thread I/O bitmap, so instruction-level behavior,
fork/exec inheritance and interaction with `ioperm` need further reference
and VM qualification before claiming full `iopl` equivalence.
