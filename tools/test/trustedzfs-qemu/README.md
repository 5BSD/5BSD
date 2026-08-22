# TrustedZFS QEMU verification

This directory contains the guest-side pieces used to run the TrustedZFS,
libtrustedzfs, libtzfsd, and tzfsd ATF programs in a disposable 64-bit FreeBSD
QEMU guest.  `guest-install.sh` installs a payload from a mounted CD image and
reboots so the test ZFS module starts cleanly.  After remounting the payload,
`guest-run.sh` enumerates and executes every test case and prints an aggregate
pass/fail/skip count.

`free_compat.c` is a narrowly scoped host shim for a build-host mismatch: it
lets a QEMU linked against a newer ports GLib run on a host libc predating the
C23 sized-free symbols.  It is not installed in or used by the guest.
