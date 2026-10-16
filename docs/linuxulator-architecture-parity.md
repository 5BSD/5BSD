# Linuxulator architecture parity (2026-10-16)

The Linux64 backend is built for amd64 and arm64. RISC-V currently has no
`sys/riscv/linux` backend or `linux64`/`linux_common` module selection in
`sys/modules/Makefile`. A successful riscv64 GENERIC build therefore checks
the native kernel and modules, **not** Linux binary compatibility.

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

`make -j8 buildkernel` passed for amd64 and arm64, including `linux64.ko`
and `linux_common.ko`. The arm64 freestanding Linux test cross-compiles with
`clang --target=aarch64-linux-gnu`. Runtime acceptance requires an arm64
5BSD boot with these modules; a build alone does not establish syscall
behavior. The amd64 runtime tests likewise need the new kernel loaded.

## RISC-V Linux64 backend required

Porting the above translator calls to riscv64 requires a complete machine
backend. The arm64 syscall table largely follows Linux's generic numbering,
but copying its table would still leave RISC-V without ELF branding, syscall
register entry/return handling, TLS and clone register setup, signal frames
and `rt_sigreturn`, register conversion for ptrace, user-atomic futex helpers,
and a RISC-V vDSO or equivalent safe signal trampoline. The RISC-V Linux
signal ABI also carries floating point and vector state; preserving it is a
correctness requirement before advertising Linux64 support. An arm64 module
copied into the RISC-V build would compile neither the architecture-dependent
assembly nor the signal ABI correctly.

The riscv64 GENERIC kernel and modules build passed with `-j8`, but no
Linuxulator module was produced. The backend needs its own ABI tests on a
RISC-V 5BSD guest, including static and dynamic Linux ELF, syscall results,
clone/TLS, signal delivery and return, futexes, and floating point/vector
state. Until that gate passes, riscv64 Linux binaries remain unsupported.
