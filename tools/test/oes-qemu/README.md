# OES QEMU integration tests

This harness boots a disposable amd64 FreeBSD guest and attaches the current
OES kernel module, public headers, `liboes`, ESLogger, and Kyua suite as a
read-only CD image. QEMU's snapshot mode leaves the base disk unchanged.

The guest image must use a kernel ABI compatible with the source tree and must
provide `kyua`, a compiler, and root console access. Run:

```sh
tools/test/oes-qemu/run.sh /path/to/freebsd-amd64.raw
```

At the guest console, log in as root and run the two commands printed by the
harness. The guest runner installs the staged userspace files only into the
temporary snapshot, loads `oes.ko`, checks ESLogger's CLI, runs all tests, and
prints a verbose report on failure.

`QEMU_BIN`, `QEMU_DATADIR`, `QEMU_LIBDIR`, `QEMU_ACCEL`, `QEMU_MEMORY`, `QEMU_CPUS`,
`OES_VM_WORKDIR`, and `SRCTOP` may be used to override defaults. TCG is the
default accelerator, so the harness does not require `/dev/vmm` or root access
on the host.
