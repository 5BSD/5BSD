# MAC ABAC QEMU integration tests

This harness boots a disposable amd64 FreeBSD guest and attaches the current
MAC ABAC module, public header, control and labeling tool, policy daemon,
sample policies, and Kyua suite as a read-only CD image. QEMU snapshot mode
leaves the base disk unchanged.

The guest image must use a kernel ABI compatible with the source tree and
provide Kyua and root console access. Run:

```sh
tools/test/mac-abac-qemu/run.sh /path/to/freebsd-amd64.raw
```

At the guest console, log in as root and run the commands printed by the
harness. The runner compiles every shipped policy format, loads the current
module, exercises the management and labeling tools, and runs the complete
suite.

`QEMU_BIN`, `QEMU_DATADIR`, `QEMU_LIBDIR`, `QEMU_ACCEL`, `QEMU_MEMORY`,
`QEMU_CPUS`, `MAC_ABAC_VM_WORKDIR`, and `SRCTOP` may override defaults. TCG is
the default, so host root access and `/dev/vmm` are not required.
