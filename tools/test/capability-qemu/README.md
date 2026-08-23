# Capability descriptor QEMU verification

`run.sh` packages the Crypto descriptor, EnvFD, libnotify/BsdNotify,
filesystem component and flavor, CLI, bundle, and TrustedZFS regression
programs with a matching kernel and modules.  It
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

`guest-run.sh` enumerates every ATF case, gives each one a private writable
working directory, invokes cleanup, and reports aggregate counts.
