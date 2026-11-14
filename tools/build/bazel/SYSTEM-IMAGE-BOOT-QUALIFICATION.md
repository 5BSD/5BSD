# Native complete package image and normal boot qualification

## Current certificate/image qualification (2026-11-13)

`bazel-certificate-image-native-r1-20261113/receipt.json` passes the complete
selected AMD64 package/image graph and its package-solver/certificate tests.
The resulting owned 2 GiB VM passes 15 checks in
`bazel-certificate-vm-r1-20261113/result.json` and powers off normally: normal
startup, console/PAM, SSH/su positive/negative authentication, firstboot database
proof, complete installed-tree reconciliation and default TLS/local-CA lifecycle.
Its normal ordinary-user fetch is unchanged; the test adds/removes a guest-local
CA through standard certctl rehash and restores the original bundle bytes.
The optional policy is documented by `tools/test/system-pkg-runtime/certificates.json`.
See MAKE-CLOSEOUT-CONTROL-QUALIFICATION.md for exact resource/source/evidence bounds.
This accepts the selected fresh image, not all configurations, ARM64, Secure Boot,
comparative performance or an updated full upgrade/provider/rollback scenario.
Historical attempts below retain their original context.


## Current accepted service-aware scenario (2026-11-11)

The corrected full AMD64 R10 candidate and VM R4 pass the complete signed
447-to-450-package inactive-BE upgrade, new-kernel boot, authentication, selected
provider operations, rollback, shared-file persistence and unused-BE deletion.
All 33 checks pass; the VM powers off normally. Each of four phases passes all
13 manifest-required services and six selected ordinary operations. Independent
acceptance review verifies raw hashes and resource bounds. See
RUNTIME-CONTAINER-CLEANUP-QUALIFICATION.md for exact evidence and limits.

This supersedes the historical cleanup/Notify failures recorded below. It does
not prove every provider operation, exhaustive upgraded-tree metadata parity,
Secure Boot, application schema rollback or comparative performance. The baseline
audit scope and explicit firstboot reconciliation limits remain unchanged.

## Status — 2026-11-06

The complete current-profile AMD64 package image now passes normal boot and all
12 requested functional checks in a 2 GB/four-vCPU VM, including console/PAM,
terminal sizing, exact Capsule PID 1 identity, preserved signal denial, expected
ZFS root, all 447 installed packages, effective PAM-enabled sshd, positive/negative
password SSH and positive/negative su. Normal guest shutdown and unchanged
backing-image/runner bindings pass. Earlier failures remain preserved below.
Installed-tree completeness, actual version/BE upgrades and the other global gates
remain open. Make remains the production/default backend; BIP is excluded.

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

## Corrected image and second VM evidence

`bazel-system-image-native-r7-20261106/receipt.json` passes the full image target
and four selected tests. Counts remain 447 packages, 33,982 nondirectory records
and 1,369 directories. The captured image hash is
`15b823325499645cc3a912ecc94fa1976f3047f1a46984faa4392c672917da0a`;
report hash is `e6ceacba764a874e73d56566e25348d06b039c89bb389598e96485590fe9b5e6`.
The report names the actual filesystem, pool, bootfs and dataset policy so the
runtime checker can require the expected root rather than just listing mounts.
Construction observations: pkg installation 33.89 s, makefs 6.68 s / 31,648 KiB
child max RSS, mkimg 7.10 s / 8,180 KiB. Whole Bazel build elapsed 1,017.28 s;
the retained JVM snapshot shows metadata/hash checks during the long cache-check
phase. Kernel debug package compression also consumes several minutes with the
explicit one-thread qualification setting. Comparative performance is still open.

`bazel-system-normal-boot-vm-r2-20261106/result.json` is **failed**, despite reaching
multiuser startup and a real authenticated root login. Its serial log shows no
repeat of the guard panic. It also exposes two private-fixture/harness defects:

* rc.local is sourced, so top-level `set -eu` leaks into its caller and causes
  `eval: rc_debug: parameter not set`. The fixture now contains strict options
  and provisioning inside a subshell; no base rc script is changed or bypassed.
* The harness sends its first shell command immediately after the password.
  The actual login profile runs resizewin, which switches terminal input mode,
  flushes pending input, and requests cursor position. The queued command is lost
  before the shell prompt. The check eventually times out; a visible prompt alone
  is not substituted for its missing command result.

The corrected harness waits for the shell prompt and answers absolute-position/
DSR terminal-size probes with bounds derived from explicit terminal rows/columns.
It does not modify login, PAM or resizewin. Unit checks cover every fragmentation
boundary, byte-at-a-time delivery, exactly-once responses, position bounds and no
invented response for an unknown cursor. A guest stty/resizewin check must verify
the resulting actual terminal size. Startup shell errors now fail immediately.
The R2 VM is stopped and retained as failed evidence. Its 650 samples observe
915,333,120 bytes maximum QEMU RSS and 428.05 s last observed QEMU CPU time; overlay
allocation stays below 13 MB. Those are functional-run observations, not peak
system-memory accounting or comparative disk/CPU performance acceptance.

## Fresh fixture image R8 and third VM

`bazel-system-image-native-r8-20261106/receipt.json` passes all five selected test
targets, including the new two-case streaming terminal protocol test. The full
package set and file/directory counts are unchanged. Captured image SHA-256:
`de684543140b87541c43ab38bb8e05f1997effa64a396d0fe50485100ed61bd7`;
report SHA-256: `5b03d93bc9cde6f942e45358d74508eaf4bda44ad1ba74b7fc1f1c1f2b57ac7a`.

The plan `bazel-system-normal-boot-plan-r3-20261106.json` retains 2 GB/four-vCPU
limits and declares 24 terminal rows and 80 columns. The fresh
`bazel-system-normal-boot-vm-r3-20261106` run is in progress. The driver now drains
its serial reader before the final failure scan, so late shutdown output cannot
be omitted from acceptance. No SSH/su or clean-shutdown result is accepted yet.

## Accepted normal-boot baseline: R9 image and R5 VM

`bazel-system-image-native-r9-20261106/receipt.json` passes five selected test
targets and the full 447-package image with 33,982 nondirectory records and 1,369
directories. Image SHA-256:
`3fe82e3c89cdf02fcbefb9bf063d1513934be441f22de9316bbfa144470b7011`;
construction report SHA-256:
`0ca576b3ff28c2ff25ff5edc8863b9f0625cc26144865187cecebc4961bfdef0`.

R3 passes console/PAM and actual terminal sizing, then exposes procstat's
`kill(pid, 0)` existence check: it drops visible signal-protected processes on any
error. The corrected base utility skips only ESRCH. MAC signal/visibility policy
is untouched. R4 then verifies the exact Capsule pathname and continued signal
probe denial, ZFS root and all package records. Its SSH check fails because the
harness expects lowercase `usepam`; this tree's source and maintained SSH tests
use canonical `UsePAM`. The harness now retains the full `sshd -T` output, matches
the keyword case-insensitively, requires exactly one `yes` value, and checks the
running daemon separately. PAM is not disabled or bypassed.

`bazel-system-normal-boot-vm-r5-20261106/result.json` is **passed**. Result SHA-256:
`c54f7dbba711934dded96c4b9558f7a8cc7e84a01bfc4a617ce25b49b491057e`.
All 12 checks pass, followed by actual ACPI poweroff / QEMU exit 0 and the final
serial diagnostic, immutable backing-byte and unchanged runner-source checks.
No init, rc, login, PAM or SSH implementation is replaced by a test shim.
Independent review checks the exact `1 capsule 1600027 /sbin/capsule` row and
`UsePAM yes`, authenticating UID 2001 over SSH and UID 0 through su, and rejection
of each wrong password. It confirms all kernel payload hashes unchanged between
R8 and R9; regular payload changes are procstat/aliases/debug, maintained manuals
and the generated private package database. Review record:
`bazel-system-normal-boot-review-r1-20261106/review.json`.

The configured guest has 2,048 MiB RAM and four vCPUs. Whole run 160.70 s; 150
QEMU-process samples observe max RSS 1,046,007,808 bytes, last CPU 166.45 s and
maximum allocated overlay 6,705,664 bytes. One actual terminal-size reply is used.
The serial log ends with synced buffers and normal poweroff. Sampling excludes
between-sample peaks, host page cache and other processes. This is not a controlled
comparison against Make, a disk throughput result or all-base/service coverage.

The new source ATF case exercises a live root-owned process read by a different
UID despite denied signal permission, with explicit process-visibility policy
prerequisites. The final source wrapper and native while1 helper are captured in
`bazel-procstat-visibility-native-r1-20261106`; the wrapper is verified byte-for-byte
against the final maintained source. That ATF case has **not run** yet. The mandatory
VM protected-PID1 path/read/signal checks provide the exercised regression here.

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

Next: complete installed ownership/flags/links/config coverage after normal
firstboot; real version upgrade into a new boot environment,
rollback and removal; target package scripts/firstboot completeness. Independent
fresh Make compilation parity, optional/custom/cross completeness, bootstrap,
sandbox/cache/reproducibility, comparative CPU/RAM/disk I/O, hardware and verified
combined publication remain separate gates. BIOS boot here proves neither Secure
Boot, Veriexec enforcement nor protection against compromised root.
