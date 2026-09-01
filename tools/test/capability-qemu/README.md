# Capability descriptor QEMU verification

`run.sh` packages the Crypto descriptor, EnvFD, libnotify/BsdNotify,
filesystem and network components, service-manager/control-plane, bundle
parser, typed bootstrap, provider, CLI, and TrustedZFS regression
programs with matching managers, private libraries, kernel, and modules. It
boots the supplied raw amd64 image with QEMU's `-snapshot` option, so kernel,
library, and test writes disappear when QEMU exits.

The harness deliberately keeps installation and execution as separate guest
steps: the replacement kernel, ZFS module, and cryptodev module must all start
from the same clean boot.  The installer selects single-user mode for that
second boot so raw provider-transport tests run before init claims
`/dev/mac_capability` for the system-wide supervisor.  At the shell prompt,
mount the root filesystem writable, mount the payload CD, and run:

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
