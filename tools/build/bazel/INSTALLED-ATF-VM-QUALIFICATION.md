# Installed locale and fortify ATF VM qualification (2026-11-05)

## Maintained implementation

The existing iconv runtime fixture assembler now accepts explicit checker_inputs
and guest_driver_destination fields. Checker inputs are copied under the dedicated
/runtime/checker-inputs subtree, hash-bound as bootstrap inputs and rejected for
traversal, noncanonical names, control bytes, ancestor collisions or missing source
files. The existing default driver destination remains supported. No normal build
or image input is replaced by a home-directory helper or host resource fallback.

A new installed_atf_vm static ATF driver uses the maintained daemon-runtime VM
harness. It mounts devfs and a bounded 384 MiB scratch tmpfs inside the prepared
root, invokes the installed ATF checker and verifies mount cleanup. Programs,
Citrus modules/databases and locale files remain on the disk-backed root. The
scratch filesystem contains per-case variable data, not the operating system.

installed-atf-check.py consumes a versioned plan listing installed program paths,
case-user selection and explicit stdin-terminal cases. It reads each actual
program's ATF listing; case names, root requirements, deadlines and cleanup come
from that metadata. Every requested program must have selected cases. Non-root
cases run after chroot with explicit uid/gid/supplementary group 1001; original
root cases run as root only in the disposable guest. Three id checks confirm the
ordinary child identity. Each case has a private writable directory. No C test
source or overflow expectation changes.

Each phase has its own session/process group, captured stdout/stderr and deadline;
timeout and completion terminate remaining descendants. Explicit terminal cases
receive a real PTY on stdin. Allocation/exec/cleanup failures reject acceptance.
Standard ATF expected_failure outcomes are recorded separately from passes;
skips, malformed results, unexpected failures and nonzero exits reject the run.
This is a selected installed-C-ATF harness, not a replacement for full Kyua
hierarchy discovery, arbitrary metadata/configuration support or normal startup.
The selected checker uses original unscaled ATF deadlines/defaults; the VM and
outer driver's deadlines remain separate bounds.

## Inputs and original coverage

The plan derives all 28 locale program identities from their independently
reviewed case inventory, and all 12 fortify identities from that original metadata
review. It selects all cases, including ten original root/jail cases and five
original ttyname_r cases with actual stdin terminals. There is no sampled-case
substitute for either selected suite.

Five complete native archive contributions supply locale/fortify tests, LC_CTYPE,
i18n data and all Citrus modules. Native libc/libsys/ATF, chroot/id and a static
working-directory helper complete the execution root. Archive targets must expose
one unambiguous selected tar; the assembler rejects ambiguous outputs. SDK Python,
its libraries and the ELF loader, matching execution kernel, boot files and outer
daemon-runtime baseline fixtures are separately identified bootstrap inputs.
They do not become native bootstrap or whole-system build achievements.

The execution kernel is the explicit matching GENERIC-NODEBUG build with SHA256
8a3b1cf6446946f9cc6a12f7645274fd59d49a8a44ca74137fd9189c5e9383da.
This fixture boots that supplied kernel; it does not prove Secure Boot, a newly
Bazel-built kernel boot, normal Capsule startup or a complete packaged OS image.

## Authoritative final evidence

All directories below are under /usr/obj/usr/src:

- bazel-installed-atf-native-r5-20261105: maintained build-bsd qualification with
  16 jobs builds the complete native fixture closure. Four policy/boundary targets
  pass. The installed checker target executes twelve methods, including real PTY
  stdin, descendant timeout termination, child-exit/deadline race handling and
  nonzero exit preservation. Fixture boundary tests execute eleven methods.
- bazel-installed-atf-request-r2-20261105/fixture-plan.json and atf-plan.json are
  the final explicit fixture/case inputs. The native build request is retained in
  request-r1/inputs.json. No host install or reboot occurs.
- bazel-installed-atf-fixture-r4-20261105/fixture.json binds the qualification
  receipt, captured native files, exact bootstrap input hashes, kernel identity,
  boot inventory and 325291925 logical payload bytes. These are content bindings,
  not a signature or verified-boot claim.
- bazel-installed-atf-vm-r3-20261105/result.json records PASS, QEMU exit zero,
  no forced termination and successful driver/mount cleanup. Serial output retains
  the complete installed-case report. All 418 original cases execute: 417 pass,
  one has its original expected failure, zero skip. All 378 fortify cases pass,
  including all ten root cases and all five terminal cases. All forty locale
  cases execute: thirty-nine pass and iconv_samples reports its existing PR
  lib/59019 expected failure for an ISO-2022-CN scenario.
- bazel-installed-atf-review-r1-20261105 retains the extracted installed report,
  audit.py and review.json. It binds the VM/serial/kernel/fixture inputs, compares
  exact case identity and original user requirements against both independent
  metadata reviews, verifies actual exit/cleanup/outcome fields, and checks all
  six locale/fortify installation outputs remain identical to prior independent
  Make-reviewed tar/record/directory outputs. No omitted requested case is accepted.

Seven imported locale cases still report absent ISO2022-JP/JP2 or eucTW individual
scenarios as in original source/base inventory. Their other vectors run, but these
unsupported individual scenarios remain outside coverage; the complete ATF case
count does not imply every embedded scenario succeeded. See the locale checkpoint
for the maintained-inventory audit of these absences.

## Resources and retained failures

The final guest uses four vCPUs and 2048 MiB RAM. Its 768 MiB UFS root boots from
ufs:/dev/vtbd0p2 on a private virtual disk, not an in-memory OS image. QEMU has an
enforced 3 GiB process-RSS ceiling. Over 68 samples, peak observed RSS is
688205824 bytes and last observed QEMU CPU time is 93.51 seconds. VM duration is
68.541 seconds. Sampling excludes between-sample peaks and host page cache; these
are resource observations/bounds, not a controlled Make or disk-I/O benchmark.
The VM/harness are terminal and shut down normally.

The first VM run executes forty locale plus ten root cases, but the new checker
incorrectly treats the original expected failure as an unexpected failure. Its
FAIL result remains retained in vm-r1. Standard outcome classification corrects
the checker without changing test software. vm-r2 then accepts the same fifty
cases with forty-nine passes/one expected failure. The final vm-r3 expands to both
complete selected suites and uses the lifecycle-tested final checker. Intermediate
native/fixture preparations remain recorded; unused fixture-r3 is not VM proof.

## Frontend integration and remaining goal

The maintained assembler, new checker/driver, regression tests, manual and ledgers
are updated together. Existing build-bsd explicit target/test inputs build/freeze
this closure; build-bsd.c, backend selection, input schema, bundle signing and
publication rules need no change. Make remains production/default.

This closes the ten pending installed-resource locale cases and ten pending
privileged fortify cases for the selected AMD64 profile. Remaining libc roots and
parent hierarchy, other ABI/options, independent whole-world/debug/pkgbase parity,
Bazel kernel/module boot/loading, bootstrap/reproducibility/cache/sandbox, normal
system/service tests, CPU/memory/disk performance comparisons and combined hardware
publication remain open. BIP stays outside the goal.
