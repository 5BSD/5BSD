# Linuxulator architecture parity (2026-10-16)

The Linux64 backend is built for amd64 and arm64. A new riscv64 Linux64
backend is present in `sys/riscv/linux` and selected by the RISC-V module
build. Its initial ABI smoke test passes in a riscv64 5BSD guest, but the
backend remains experimental while broader userland behavior is untested.

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
The Linux ELF stack, shared page, and vDSO are placed according to the active
Sv39 or Sv48 pmap mode. A fixed Sv48 address caused a guest kernel panic on
Sv39 during ELF stack copyout; the guest run below verifies the Sv39 fix.

The riscv64 GENERIC kernel and modules build, including `linux64.ko` and
`linux_common.ko`, passed with `-j8`. The freestanding
`tests/sys/kern/linux_riscv64_smoke.c` cross-compiles to a static Linux/RISC-V
ELF without a Linux sysroot. It checks process identity, `uname`, thread name,
`unshare`, both architecture-specific calls, signal delivery/return on an
alternate stack, a futex wake operation, and process clone/wait. On
2026-10-16, a 1 GiB QEMU `virt` guest booted a clean UFS2 stage through
virtio MMIO, loaded `linux_common.ko` and `linux64.ko`, printed
`LINUX64_SMOKE_RESULT=0`, and shut down cleanly. The guest transcript is
`/usr/obj/linux-riscv-guest-qemu-expanded-20261016.log`. Host QEMU user mode
does not exercise 5BSD's Linuxulator. Sv48 placement, dynamic glibc ELF,
thread clone/TLS, futex contention, ptrace, floating point/vector preservation,
and the shared AIO/quota/remap/mount/socket paths still need guest tests before
riscv64 Linux binary support is advertised.
