# TrustedZFS QEMU verification

This directory contains the guest-side pieces used to run the TrustedZFS,
libtrustedzfs, libbsdfilesystem, and bsdfilesystem ATF programs in a disposable 64-bit FreeBSD
QEMU guest.  `guest-install.sh` installs a payload from a mounted CD image and
reboots so the test ZFS module starts cleanly.  After remounting the payload,
`guest-run.sh` enumerates and executes every test case and prints an aggregate
pass/fail/skip count.

`free_compat.c` is a narrowly scoped host shim for a build-host mismatch: it
lets a QEMU linked against a newer ports GLib run on a host libc predating the
C23 sized-free symbols.  It is not installed in or used by the guest.

The runner rejects failed/empty test discovery, missing results and skipped
cases. It reads ATF result files rather than inferring outcomes from stdout.
Each run keeps its own result directory. The payload must include both
`trustedzfs_capsicum_test` and `trustedzfs_limit_test`: the first uses a test-only
`ZFD_LIMIT` double to test real Capsicum command lists; the second exercises the
unmodified production library and requires ordinary descriptors to be rejected.
Only the `zfshandle_*` tests exercise actual ZFS handles, including inherited
operation ceilings. Passing the native library tests does not qualify those
kernel operations or BIP persistent storage.

### Held property identity under legacy rename

The maintained `zfshandle_verbs_test:property_rename_identity` case holds a
filesystem handle while another process repeatedly uses the legacy ZFS CLI to
rename that dataset, create a replacement at its former name with different
native properties, destroy the replacement and restore the original name.
The reader checks numeric `atime` and string `mountpoint` continuously. It must
never observe replacement values or a lookup failure while the held dataset
continues to exist. A ready pipe establishes the first successful read before
mutation; a separate result pipe reports errors and counts. The loop is bounded
at 32 rename/replacement cycles and has an ATF timeout. Existing per-case pool
cleanup applies, including after a failed operation leaves an intermediate name.

This case uses the existing destructive, file-backed pool fixture and is for a
disposable guest only. It has been syntax-checked, not executed under the current
VM hold. It exercises generic ZFS handle behavior, not BIP reservation/grant
setup or boot. Bounded concurrency does not prove that every vulnerable
interleaving occurred. The guest runner discovers the new case from the existing
ATF program; no new program-list entry or standalone build workflow is needed.
