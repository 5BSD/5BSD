# Native base-accounts qualification

2026-11-01. The default amd64 component passes native build, complete
installation parity and all eleven unchanged installed-path ATF cases in a
bounded disposable guest. Make remains the production/default backend. This
is not a complete native world, package, upgrade or system-boot qualification.

## Source and installation ownership

`usr.sbin/base-accounts/BUILD.bazel` owns the original shell payload, pristine
source-tree group/master.passwd references, compressed manual and installation
metadata. The literal script is installed with mode 0555; no rewritten script,
interpreter shim, generated replacement policy or Make interpretation is used.
The test BUILD owns the original ATF shell wrapper and Kyuafile, both in the
`tests` package; program/reference files belong to `runtime`. Existing typed
`tests` and `split_manpages` selectors preserve test installation and the
`runtime-man` package split. The compressed-manual configuration is qualified;
other manual compression policies remain a wider installation-graph gate.

The independent maintained Make reference is
`/usr/obj/usr/src/bazel-base-accounts-make-r1-20261101/receipt.json`.
Its recorded source hashes still match. The immutable native capture is
`bazel-base-accounts-qualification-r3-20261101`, under the same object root.
`bazel-base-accounts-install-parity-r3-20261101.json` compares all nine component
records, including directories, owner/group/mode and package tags. All six
literal file payloads match Make bytes, including the generated original-test
wrapper, Kyuafile and compressed manual. Ancestor directory policy is supplied
by maintained mtree/account sources, rather than counted as component files.

The test-disabled/manpage-split variant also passes an independent maintained
Make comparison: all six component records and four literal payloads match,
no component test paths remain in the archive, and the manual is assigned to
`runtime-man`. Evidence: `bazel-base-accounts-make-reduced-20261101`,
`bazel-base-accounts-reduced-qualification-r2-20261101` and
`bazel-base-accounts-install-parity-reduced-r2-20261101.json`. Its explicit
format-5 profile sets `tests=false`, `split_manpages=true` and an empty tests
list; the normal frontend performs a build-only qualification.

## Installed-path runtime

All eleven original cases pass, with zero skips: creates_missing, idempotent,
dry_run, gid_taken, uid_taken, name_kept, removed_locally,
privileged_never_created, member_must_exist, missing_reference and
shipped_reference. Case identities and metadata come from the installed
original program's ATF listing; the checker attempts every listed case and
accepts only an actual `passed` result and successful exit. No original test
bodies or production files changed. Every source deadline is retained (the
ATF default 300 seconds here), with explicit timeout scale 1. The root adapter
has a 3600-second aggregate deadline and checked cleanup.

The dedicated guest checker verifies UID, primary GID and supplementary groups
are exactly 1001 before listing/running the suite. Each body has a separate
writable temporary directory, removed and checked afterward. Script, account
reference and helper hashes are checked before and after all cases. Native
`/bin/sh`, `/usr/sbin/base-accounts`, `/usr/sbin/pw`, `/usr/sbin/pwd_mkdb` and
ATF tools run at their genuine installed paths. In particular, pw's absolute
pwd_mkdb path remains intact. Test account databases are private `pw -R` roots;
no host or bootstrap-guest account files are rewritten. The full native ELF
NEEDED/interpreter closure is checked by the maintained explicit-input fixture
assembler. Shared helper libraries are explicit fixture runtime inputs, not
an assertion that their complete packages were installed or requalified here.

A dedicated static ATF adapter mounts guest devfs and a 16 MiB tmpfs at the
fixture's writable `/tmp`, then unmounts both with checked cleanup. The OS root
is a new 768 MiB disk-backed UFS image, not a memory disk. QEMU uses 2 GiB RAM,
four CPUs and no network, with a 3 GiB host-process RSS limit. An unrelated
operator VM was left untouched; these observations are not controlled
performance comparisons. Sampled peak QEMU RSS was 728,854,528 bytes, elapsed
VM time 221.195 seconds and last sampled QEMU CPU time 187.91 seconds. Sampling
excludes between-sample peaks and host page cache. QEMU exited normally with
status 0, without forced termination, and the wrapper cleanup passed.

The explicitly selected execution bootstrap is GENERIC-NODEBUG revision
`b2b89d0bcd48`, built 2026-11-01 01:09:28 UTC, kernel SHA256
`8a3b1cf6446946f9cc6a12f7645274fd59d49a8a44ca74137fd9189c5e9383da`.
All 93 matching captured boot files were hash-verified before reuse; no old
writable disk was reused. Static PID1/service bootstrap fixtures and the
separate SDK Python/loader runtime remain explicit non-native bootstrap inputs.
This is component testing under fixture PID1, not normal Capsule/rc startup,
SSH/PAM/login, current-host kernel acceptance or a full installed OS.

## Evidence and maintained entry points

All following paths are under `/usr/obj/usr/src`:

- `bazel-base-accounts-vm-inputs-20261101.json`: explicit format-5 native inputs;
- `bazel-base-accounts-qualification-r3-20261101/receipt.json`: 43 targets and
  two passing Bazel tests: seven guest-checker boundary tests and the existing
  bsdtrace safe-usage regression;
- `bazel-base-accounts-vm-plan-20261101.json` and
  `bazel-base-accounts-vm-fixture-r1-20261101/fixture.json`: explicit native
  archive/helpers, kernel/boot/bootstrap inputs and their hash bindings;
- `bazel-base-accounts-vm-r1-20261101/result.json`, `serial.log`,
  `host-resources.jsonl` and `base-accounts-results.json`: authoritative VM
  result, all original case stdout/stderr/results, identities, cleanup and
  input-integrity checks. The extracted case report is bound to the unchanged
  serial and harness result hashes.

The native artifacts and tests use normal `build-bsd bazel-test` with explicit
format-5 inputs and `--jobs 16`. The existing
`tools/build/bazel/iconv-runtime-fixture.py` assembles receipt-bound inputs and
`tools/test/daemon-runtime/run-vm.py` executes the fresh disposable disk.
The legacy `tests/iconv_vm_driver` fixture alias carries this component's
explicitly selected dedicated adapter; it does not substitute iconv test code.
No new frontend C option, shared ATF environment API or replacement build path
was needed. Existing disk guards retain an 18 GiB minimum start and 16 GiB
reserve; no budget was breached. No publication or host installation occurred.

Seven focused checker tests cover malformed/duplicate original metadata,
manifest mutation/traversal/symlink escapes, real nonzero child output,
timeout cleanup and stopping descendants after normal parent exit. The
process-group leader is retained with WNOWAIT until signalling finishes, so
PID reuse cannot redirect the cleanup signal. These are real boundary tests,
not simulated suite success.

## Preserved failures and limits

The first host attempt failed before account bodies because a declared dirname
helper was missing. Its corrected retry failed because `sh scriptname` does
not search PATH for that script operand. A low-space retry was rejected before
execution. Those r1/r2 reports and disk evidence remain; their generic
ATF-environment analysis passes never qualified account operations. The unused
generic environment/text-helper experiment was preserved under
`bazel-base-accounts-deferred-environment-20261101` and removed from active
source. The original shared ATF runner was not changed. The guest installation
approach qualifies all eleven cases instead of weakening or dropping them.

The first reduced-profile invocation omitted the mandatory empty `tests` list
and was rejected by format-5 schema validation before any Bazel action. Its
input/run evidence is retained separately from the corrected profile.

Cross-userland, complete base/pkgbase construction, real system account
migration/upgrade, normal startup/authentication, full publication and controlled
CPU/memory/disk-I/O regressions remain system-level gates. Runtime execution of
pre-existing native helpers here is not a new full Make parity claim for each
helper library/program.
