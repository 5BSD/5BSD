# CAM, Capsicum and jail library tests — AMD64 qualification

## What changed

The original Make traversal contains these three selected test directories; the
prior Bazel declarations did not install any of them. CAM also omitted the
original libcam_test program, and CAM/jail prototypes linked SDK ATF libraries.
The source-owned native rules now build all five original programs, use native
ATF/library implementations and preserve the original GNU17/GNU++17, WARNS=6,
static-versus-PIE selection, split-debug files, registration, modes and packages.
Original test and library implementation sources are unchanged.

The test installation archive helper accepts the original package name, defaulting
to `tests`. Jail uses `libjail-tests`, including its test and debug directory tags.
Native cc_binary still owns compilation/link actions; explicit CcInfo ordering
preserves the final native library sequence. Static C++ uses the native unwinder;
static libc/compiler-runtime inputs are declared. Dynamic CAM links the native
ATF, CAM and libc ABI interfaces without an installed RPATH. SDK headers and
startup objects remain bootstrap inputs; this is not a self-hosted toolchain claim.

Each library now exposes `installation_archives`, appending its original test
contribution only when tests are enabled. The selected lib parent uses these
complete child parents. The wider lib parent retains its tests-enabled guard:
other selected library test contributions are still incomplete.

## Evidence

All evidence below is under `/usr/obj/usr/src`; no host installation, upgrade or
reboot was performed. Commands use the existing format-5 build-bsd bazel-test
frontend with `--arch amd64 --jobs 16`, explicit SDK/receipt/repository inputs,
TESTS_SUPPORT=yes, NIS disabled and MALLOC_PRODUCTION=yes. These are unsigned
qualification builds, not published packages or verified-boot evidence.

| Component | Test files | Parent files, tests on | Parent files, tests off | Original registered cases | Executed cases |
| --- | ---: | ---: | ---: | ---: | ---: |
| libcam | 5 | 35 | 30 | 14 | 1 |
| libcapsicum | 5 | 20 | 15 | 4 | 4 |
| libjail | 3 | 23 | 20 | 2 | 2 |

Counts are non-directory file/link records; repeated directory ownership/tag
claims are compared separately. They are not package or whole-world counts.

- `bazel-library-test-edges-inventory-r1-20261106/review.json`: independent
  read-only Make traversal, 326 directories tests off, 442 on, 116 added and
  66 test entry edges for the recorded AMD64 profile. Both SUBDIR and
  TESTS_SUBDIRS are followed; this is a traversal inventory, not payload proof.
- `bazel-library-test-declarations-r1-20261106/review.json`: unconfigured
  archive/manifest declaration inventory at those actual test entry roots.
  The three above initially had no installation contribution. Other roots
  still lack complete archives. Nested CSU modes are owned by their parent
  Bazel package; absent nested BUILD files alone do not establish an omission.
- `bazel-{libcam,libcapsicum,libjail}-tests-make-r1-20261106`: complete independent
  Make construction and staging of each test component, with TESTS enabled.
- `bazel-{libcam,libcapsicum,libjail}-parent-make-r1-20261106` and
  `bazel-{libcam,libcapsicum,libjail}-parent-no-tests-make-r1-20261106`: complete
  independent parent controls for both original option profiles.
- `bazel-cam-capsicum-jail-tests-request-r1-20261106/inputs.json` and
  `bazel-cam-capsicum-jail-tests-native-r3-20261106`: initial passing native
  construction and seven original host-safe bodies plus one source helper.
- `bazel-cam-capsicum-jail-parent-request-r1-20261106/inputs.json` and
  `bazel-cam-capsicum-jail-parent-native-r3-20261106`: final full positive parents,
  explicit original test archives, native runtime libraries and seven bodies.
- `bazel-cam-capsicum-jail-parent-no-tests-request-r1-20261106/inputs.json` and
  `bazel-cam-capsicum-jail-parent-no-tests-native-r3-20261106`: final negative
  profile, with no /usr/tests payload and one passing source helper.
- `bazel-cam-capsicum-jail-parent-review-r3-20261106/review.json`:
  all 78 positive file/link records, per-parent directory package claim sets,
  hardlinks, exact 60 non-ELF/non-static-archive payloads and seven program/DSO
  ELF/debug contracts match Make. Two static archive byte comparisons remain
  outside this claim. Debug directories use each actual library installation
  directory; jail's runtime and test package claims on a shared ancestor remain
  distinct. Modes, owners, groups, tags, flags and link targets are checked.
- `bazel-cam-capsicum-jail-parent-no-tests-review-r1-20261106/review.json`:
  all 65 negative file/link records, directory claims, non-ELF data and two DSO
  ELF/debug contracts match Make, with all test payloads absent.
- `bazel-cam-capsicum-jail-tests-final-review-r1-20261106/review.json`:
  final parent captures retain all 13 test records, five program/debug contracts,
  exact original Kyuafiles and identical actual ATF metadata for all 20 cases.
  Immutable final test-report hashes verify seven original case passes plus
  the source helper; the helper is not counted as an original case.

ELF comparison checks the static/PIE distinction, interpreter, ordered dynamic
libraries, imports/exports, version requirements, hardening and absence of RPATH.
Split-debug comparison checks presence/separation, installed debug basename and
GNU debuglink CRC. Raw executable/debug byte identity, debugger source lookup,
full static archive ABI equivalence and reproducible bootstrap remain separate.

The seven executed original cases are CAM cam_strmatch, both jail metadata cases,
three C stream cases and one C++ stream case. They preserve original 300-second
body deadlines and use external/no-remote test tags. CAM has declared native
ATF/CAM/sbuf/C/sys runtime libraries; the other programs are static. The supervisor
uses declared runfiles and DOF initialization is disabled for isolated body checks.
This does not establish per-case loader tracing, live probe firing or audit delivery.
The other thirteen CAM cases include privilege/device interactions and remain
unexecuted here; their original complete registration metadata is retained.

## Retained failures and remaining work

Native test r1 rejected BUILD-file loops; r2 rejected missing native rule prefixes
inside the moved Starlark macros. Neither performed compilation. Those errors
were corrected before the passing r3, without relaxing validation. Parent review
r1 caught the previously missing CAM runtime debug-directory package claim; r2
caught the incorrect jail ancestor assumption. Jail installs in /usr/lib in the
actual Make/native component profile. Final ancestors are derived using the
shared debug-directory helper from each declared installation directory, and all
original directory claims now match. Failed attempts and audits remain retained.

No C frontend/schema/signing change is needed: existing format-5 inputs already
select these targets/options. The manual is updated in the same change. Make
remains default. Complete library/world test traversal, world/kernel/module and
pkgbase parity, normal Capsule/service/SSH/PAM VM acceptance, resource/performance
comparisons, bootstrap/reproducibility and verified combined base/hardware
publication remain open. BIP is out of scope.
