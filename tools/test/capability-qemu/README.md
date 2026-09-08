# Capability descriptor QEMU verification

`run.sh` packages the Crypto descriptor, EnvFD, shared-memory ring,
libnotify/BsdNotify, sysctl and network components, current control tools,
service-manager/control-plane, bundle parser, typed bootstrap, provider, and
TrustedZFS regression programs with matching managers, private libraries,
kernel, and modules. It boots the supplied raw amd64 image with QEMU's `-snapshot` option, so kernel,
library, and test writes disappear when QEMU exits.

Run the harness from a built source tree with an amd64 raw image:

```sh
doas env QEMU_BIN=/path/to/qemu-system-x86_64 \
    tools/test/capability-qemu/run.sh /path/to/5bsd.raw
```

`CAPABILITY_VM_SKIP_BUILD=yes` reuses existing objects for staging-only
iterations. `CAPABILITY_KERNEL_OBJ`, `OBJTOP`, `QEMU_ACCEL`, `QEMU_MEMORY`,
`QEMU_CPUS`, `QEMU_CPU`, `QEMU_DATADIR`, and
`CAPABILITY_VM_WORKDIR` override their
corresponding defaults. `QEMU_DATADIR` selects the firmware directory for a
custom QEMU build.

The harness deliberately keeps installation and execution as separate guest
steps: the replacement kernel, ZFS module, and cryptodev module must all start
from the same clean boot.  The installer selects single-user mode for that
second boot so raw provider-transport tests run before init claims
`/dev/mac_capability` for the system-wide supervisor. At the first boot, log
in as root, mount the payload CD, and install it:

```sh
mkdir -p /mnt
mount -t cd9660 /dev/cd0 /mnt
sh /mnt/guest-install.sh /mnt
```

The installer reboots into single-user mode. Accept `/bin/sh`, then run:

```sh
mount -uw /
mkdir -p /mnt
mount -t cd9660 /dev/cd0 /mnt
sh /mnt/guest-run.sh /mnt
```

`guest-run.sh` runs the generated suite through the guest's `kyua` binary.
Kyua applies each case's declared user, kernel-module, timeout, isolation, and
cleanup requirements and writes `/tmp/capability-kyua.db` before printing the
verbose aggregate report.  A nonzero Kyua test status is returned after the
report, so the VM run cannot hide an individual failure behind later passing
cases.

The host-side builder deliberately rebuilds every private library before its
consumers, then stages the matching shared libraries, helpers, selected source
fixtures, kernel modules, and test programs in one read-only ISO.  The printed
ISO and kernel SHA-256 values identify the exact payload used for a run.
