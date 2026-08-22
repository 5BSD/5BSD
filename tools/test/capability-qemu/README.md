# Capability descriptor QEMU verification

`run.sh` packages the Crypto descriptor, EnvFD, BSDNotify, filesystem-flavor,
and TrustedZFS regression programs with a matching kernel and modules.  It
boots the supplied raw amd64 image with QEMU's `-snapshot` option, so kernel,
library, and test writes disappear when QEMU exits.

The harness deliberately keeps installation and execution as separate guest
steps: the replacement kernel, ZFS module, and cryptodev module must all start
from the same clean boot.  `guest-run.sh` enumerates every ATF case, gives each
one a private working directory, invokes cleanup, and reports aggregate counts.
