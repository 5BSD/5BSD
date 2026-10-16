# Linuxulator architecture parity (2026-10-16)

The Linux64 backend is built for amd64 and arm64. A new riscv64 Linux64
backend is present in `sys/riscv/linux` and selected by the RISC-V module
build. It is experimental until a riscv64 5BSD guest runs the ABI tests.

## Shared amd64 and arm64 behavior

The following previously amd64-only paths now compile for arm64:

| Area | Change | Check |
|---|---|---|
| Legacy AIO | `io_setup`, `io_destroy`, `io_submit`, `io_cancel`, `io_getevents`, `io_pgetevents`, and process sharing/cleanup | Arm64 generated syscall table; `linux_arm64_parity_test` exercises setup/destroy |
| Quotas | `quotactl` and `quotactl_fd` use the shared ZFS/native quota translator | Arm64 generated syscall table; parity test checks invalid fd |
| Memory | `remap_file_pages` uses the shared VM translator | Arm64 generated syscall table; parity test checks invalid arguments |
| Mounts | tmpfs option parser, `sysfs` to `linsysfs`, FUSE flag-only options, and bind-mount data fault checking | Arm64 module build; mount runtime tests still required |
| Process state | `PR_SET_NAME`/`PR_GET_NAME` use each thread's name, including cloned threads | Parity test checks the calling thread |
| Metadata | `statx` mount IDs come from the held vnode mount rather than `st_dev` | Parity test checks a nonzero mount ID |
| Sockets | Multicast filter and `SO_PEERNAME` translations use the shared 64-bit Linux ABI layout | Arm64 module build; runtime socket tests still required |
| ELF/ptrace | Arm64's fallback glibc loader path is `/lib/ld-linux-aarch64.so.1`; syscall info reports the program counter | Module build; ptrace runtime test still required |
| Process sharing | `unshare(CLONE_FS/CLONE_FILES)` accepts the flag argument on arm64 and uses the shared single-threaded implementation | Generated syscall table and module build; guest runtime test still required |

`make -j8 buildkernel` passed for amd64 and arm64, including `linux64.ko`
and `linux_common.ko`. The arm64 freestanding Linux test cross-compiles with
`clang --target=aarch64-linux-gnu`. Runtime acceptance requires an arm64
5BSD boot with these modules; a build alone does not establish syscall
behavior. The amd64 runtime tests likewise need the new kernel loaded.

## Experimental RISC-V Linux64 backend

The RISC-V directory supplies Linux ELF64 branding for LP64D, a RISC-V vDSO,
syscall register handling, TLS and clone setup, ptrace register conversion,
signal frames with floating point and vector context, user-atomic futex
helpers, and syscall numbers 258 (`riscv_hwprobe`) and 259
(`riscv_flush_icache`). The signal frame has compile-time ABI size and offset
assertions. `riscv_flush_icache` uses the native pmap synchronization across
active harts. `riscv_hwprobe` currently handles the common all-CPU query and
conservatively reports the base/FD/C/V bits from common native capabilities;
CPU-set filtering and newer extension keys remain unsupported.

The riscv64 GENERIC kernel and modules build, including `linux64.ko` and
`linux_common.ko`, passed with `-j8`. The freestanding
`tests/sys/kern/linux_riscv64_smoke.c` cross-compiles to a static Linux/RISC-V
ELF without a Linux sysroot. It checks process identity, `uname`, thread name,
`unshare`, both architecture-specific calls, and signal delivery/return on an
alternate stack. A guest must run this binary against the newly built modules;
the host's QEMU user mode does not exercise 5BSD's Linuxulator. Dynamic glibc
ELF, clone/TLS, futex contention, ptrace, floating point/vector preservation,
and the shared AIO/quota/remap/mount/socket paths still need guest tests before
riscv64 Linux binary support is advertised.
