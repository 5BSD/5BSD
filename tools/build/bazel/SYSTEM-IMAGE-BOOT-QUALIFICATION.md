# Native complete package image and normal boot qualification

## Status — 2026-11-06

Complete current-profile AMD64 disk construction passes with all 447 packages.
The first normal-boot VM exposes a real kernel startup defect; normal startup,
console/PAM, SSH and su are not yet qualified. The guard-initialization correction
passes a native object regression. The complete corrected image is rebuilding.
Make remains the production/default backend; BIP is excluded.

## Construction contract

`//:amd64_system_boot_test_image` is an explicitly private qualification image.
`bsd_pkg_image` consumes the complete native pkgbase index and family catalogue,
installation inventory, declared payload hashes, typed construction and site
Files, and a separate explicit image policy. It verifies the package set and
hashes, creates a private local catalogue, and uses the real pkg solver to install
all selected packages. It does not impose an artificial dependency order or force
past dependency cycles.

`INSTALL_AS_USER=yes` is a pkg environment interface, not a configuration key.
The action exports it and suppresses scripts, triggers and plugins. Its package
database and cache are outside the staged root; only the declared local database
is copied into the image. No target executable or package script runs on the host.
The maintained release base/cache, DVD stage, hardware catalogue/firmware and
private database-construction callers now use the same environment interface.
The actual hardware suite passes 44 cases with one explicit-module case skipped;
that remaining case passes separately with the installed i915 module supplied.
The release command receiver also confirms the child environment. See
`bazel-rootless-pkg-helpers-review-r1-20261106/review.json`. Privileged database/jail
construction and full release-media qualification are not established by this test.

Source mtree-derived directory policy supplies all layout directories, including
unowned empty scaffolding. The action materializes that complete declared set,
then requires exact agreement between the completed tree and its inventory,
construction, generated database and explicit site additions. It verifies file
hashes and links and emits numeric UID/GID/modes/flags/epoch into METALOG using
account maps from the actual target passwd/group inputs. Host ownership is not
used as image policy. No missing-path exception list is accepted.

Native makefs creates a ZFS filesystem on disk and native mkimg supplies GPT,
PMBR and gptzfsboot. There are no host mounts or privileged host installation.
BIOS/ZFS is the explicitly supported policy here: no UEFI or verified-boot fallback
is inferred. Filesystem/dataset size/layout, bootcode paths, site operations and
generated state are inputs. Whole-image reproducibility is not established.

The private site adds DHCP/SSH startup and serial console settings, fstab,
firstboot, and rc.local; it only prepends to the package-declared SSH configuration.
It does not replace `/etc/rc`, init or Capsule. PAM remains enabled. Normal guest
`pw` tools provision known private-fixture passwords and a wheel user during
rc.local. These credentials and `/root/pkg-static` are test inputs, never production
image defaults. The guest pkg binary comes from the explicitly declared SDK.

## Evidence

All paths below are under `/usr/obj/usr/src`.

* `bazel-system-image-native-r6-20261106/receipt.json`: complete image target and
  three selected native tests pass. The image contains 447 package records,
  33,982 nondirectory records and 1,369 directories, including explicit generated
  and fixture additions. Image SHA-256:
  `8c7dc14c0664b519b6ce260a49ea42bb212a44b44826aa839bd036d9247abb85`.
  METALOG SHA-256:
  `319653463c51635ef44729eafdbd29744a267c5c5e8ebdb52d5447fe4ca94379`.
* The captured construction report records every subprocess, wait4 CPU time,
  child max RSS and block-operation counts. Example construction measurements:
  makefs 14.76 seconds / 31,996 KiB child max RSS; mkimg 10.46 seconds / 8,176 KiB.
  These are construction measurements, not comparative disk throughput or a bound
  on total builder memory/page cache.
* `bazel-system-normal-boot-vm-r1-20261106`: the actual image starts its BIOS loader
  and native kernel with 2,048 MiB guest memory and four vCPUs, then panics in
  `__stack_chk_init`. The runner result is failed. The serial log retains the
  complete panic trace. The owned failed VM was stopped, not restarted as success.
* `bazel-kernel-guard-init-native-r1-20261106`: the native regression passes on the
  corrected actual guard object and an actual ordinary kernel allocation object.
  The same test fails on the pre-correction object, which has an executable
  relocation to `__stack_chk_fail` from its guard initializer.

## Kernel defect and correction

`sys/conf/files` explicitly removes stack-protector flags for
`kern/stack_protector.c`. The source-owned Bazel declaration already selected
`stack_protector = False`, but the AMD64 macro only removed its local flag.
The hosted toolchain still enabled its default `bsd_ssp` feature, causing the
initializer to check the guard that it had just changed. That must panic.

The macro now explicitly disables `bsd_ssp` when the caller selects this exception.
The cross-kernel macro applies the same feature contract; its freestanding
compiler already defaults this feature off. Ordinary kernel objects retain their
strong stack-protector flag. The regression inspects executable ELF relocations
from actual built Files, ignoring DWARF references, and requires a protected
ordinary kernel object as the positive control. It does not disable protection
globally or alter kernel C code to evade the failure. Cross runtime requalification
remains outstanding.

## Normal runtime driver

`tools/test/system-pkg-runtime/run.py --plan <JSON> --output <fresh-object-path>`
resolves immutable captured image/report Files, creates its own disposable qcow2
backing overlay, and runs its own QEMU. The explicit plan names tools, firmware,
CPU/RAM, whole-run deadline, sampled QEMU RSS and allocated-overlay budgets.
It retains the plan, tool/runner hashes, serial log, authentication logs, resource
samples and result. Kernel failure diagnostics stop qualification immediately.
No host VM unrelated to this driver is managed.

Requested checks use the real normal startup, serial login/PAM, Capsule PID 1,
exact image-declared ZFS boot environment, installed package count, sshd PAM,
password SSH with a serial-pinned host key, positive/negative SSH and positive/
negative su authentication, and normal guest shutdown. A test failure remains a
failure; the presence of this driver is not evidence those checks passed.

## Frontend and remaining gates

Existing format-5 `build-bsd bazel-test --bazel-inputs` target/settings support
builds this image and its tests. No new build backend, signing authority or default
switch is needed. The normal Make world/kernel/packages/image flow stays default.
The VM driver consumes the resulting hash-bound frontend capture.

Next: complete corrected normal startup and authentication; installed ownership/
flags/links/config coverage; real version upgrade into a new boot environment,
rollback and removal; target package scripts/firstboot completeness. Independent
fresh Make compilation parity, optional/custom/cross completeness, bootstrap,
sandbox/cache/reproducibility, comparative CPU/RAM/disk I/O, hardware and verified
combined publication remain separate gates. BIOS boot here proves neither Secure
Boot, Veriexec enforcement nor protection against compromised root.
