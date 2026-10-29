# Bazel qualification

Bazel is experimental. `build-bsd` continues to accept only `bsd-make`;
there is no world, kernel, package, or image Bazel backend yet. Do not use
imported upstream BUILD files as evidence of BSD build coverage.

## Current completion gates (2026-10-24)

The current upstream stable release is **9.3.1**:
https://github.com/bazelbuild/bazel/releases/tag/9.3.1
The selected custom port and `bazel9.json` now pin **9.3.1**. The official
source checksum and fresh application of existing FreeBSD patches passed;
compilation and runtime qualification remain pending. Evidence is retained at
`/usr/obj/bazel931-port-validation/port-validation.json`. Cached 9.2.0 packages
are not evidence for the latest release. Qualify explicit rules_cc/Bzlmod inputs
with the new release. Do not change the production default based on the Bazel5
pilot results below.

`make packages` compatibility is required, not an optional follow-up:

1. Feed Bazel outputs through maintained world/kernel staging with DESTDIR,
   NO_ROOT, generated files and installation transformations. No installation
   adapter exists in the current pilot.
2. Preserve METALOG ownership, modes, flags, directories, links, package tags
   and configuration semantics. Sandbox permissions are not install metadata.
3. Pass METALOG conflict checks, mtree-to-plist conversion and complete world
   package coverage checks. Preserve packages/ definitions, bsd.pkg.mk scripts,
   dependencies, configuration handling, debug splits and shared-library metadata.
4. Preserve kernel.meta, module ownership, kernel configuration/flavors and
   existing kernel/hardware identity checks.
5. Finalize executable bytes before prepare-stage/signing; preserve ABI and
   OSVERSION derivation and package/source/set versioning.
6. Keep base/hardware staging separate and publish their verified combined
   repository under /usr/obj/usr/src/repo. Base-only make packages advances
   latest-built; only complete publication advances latest.
7. Compare Make/Bazel installed inventories and actual package metadata, then
   exercise installation, upgrades, rollback and persistent data in sequential
   2 GB disk-backed VMs. Include disk I/O, CPU, latency and memory budgets.

Bazel itself and its runtime dependencies must enter the installed system through
normal package composition, not the hardware package namespace or an untracked
copied launcher. GNU dependency minimization is deferred. The native bazel-test
frontend action is committed; Make remains the production backend until full
system, package and runtime parity is demonstrated.

## Native tool prerequisite

`native-probe.py` builds the actual base `bin/echo/echo.c` using Bazel's
native C toolchain and executes four argument/output cases. It uses an isolated
workspace, ignores user/system Bazel rc files, uses batch mode, and records
commands, tool/source/output hashes, and the reported version. Supply a fresh
output directory. Build products belong under `/usr/obj`, for example:

```
python3.12 tools/build/bazel/native-probe.py --src /usr/src \
  --output /usr/obj/usr/src/bazel-native-probe --bazel /usr/local/bin/bazel
```

The default parallelism is all logical CPUs. This probe intentionally uses
host headers/libraries. It does not establish hermeticity, source-tree sysroot
correctness, reproducibility, cross compilation, Make parity, or publication
readiness. Its passing result never enables a system backend.

At the initial probe inventory on 2026-10-24, the selected custom port `/usr/obj/5BSD-ports/devel/bazel`
defines 6.2.0_2, while the installed executable reports 5.4.1. These are different
inputs. Qualify the built port separately before selecting a supported version.
The port identifies Apache 2.0 licensing and OpenJDK 11 as a build dependency.
The same custom tree also supplies `bazel5` 5.4.1_2, `bazel7` 7.7.1,
`bazel8` 8.8.0 and `bazel9` 9.2.0_4. That inventory predates the
selected bazel9 update to 9.3.1 described above. The newer ports require OpenJDK 21.
The Bazel 9 distfile is cached, and that port includes FreeBSD toolchain patches;
only OpenJDK 11 is currently installed on the host. Select and stage the supported
version deliberately; do not silently fall back to the old installed executable.
This first probe was qualified with 5.4.1 only. Newer versions need an explicit
Bzlmod/rules_cc dependency set; the legacy native cc_binary workspace is not
claimed portable across all those versions.

## Next integration gates

1. Build the selected ports version in staging, without installing over host
   tools; run this prerequisite probe with that explicit executable.
2. Define a BSD C/C++ toolchain with compiler, linker, sysroot headers/libraries,
   generated headers, target triple and ABI flags as declared inputs. Passing
   absolute `-I` paths to cc_binary is rejected by Bazel and is not a solution.
   Do not disable dependency checking or rely on the host SDK for system builds.
3. Add actual BSD BUILD targets incrementally. Compare ELF metadata, behavior,
   dependencies and install/package manifests with maintained Make outputs.
4. Integrate supported targets through build-bsd backend selection and its plan,
   execution, configuration and manual contracts. Unsupported actions must fail
   explicitly. A Make subprocess wrapped by Bazel is not Bazel build coverage.
5. Qualify native and cross world/kernel/packages/images, incremental dependency
   invalidation, reproducibility and CPU/memory/disk budgets before changing the
   default. Keep Make available until parity is demonstrated.

## Base availability and Make coexistence

Bazel is required in the default installed base system, including images and
USB installations. It must be supplied by the maintained package construction
and verified combined repository, with its runtime closure, licenses and update
ownership recorded in the system manifest. Building the executable in a ports
checkout or finding a host installation does not satisfy base availability.
The package integration must account for the JDK runtime and shell dependencies;
a standalone copied Bazel launcher is insufficient. Determine the supported
Bazel/JDK versions together from the maintained custom port, then qualify them.
Do not misclassify Bazel as hardware merely to reuse the hardware package list.

Make stays installed and supported. Qualification must include conventional
world/kernel builds, package publication and representative unchanged ports
that use Make, alongside Bazel builds. Third-party build systems are not rewritten
as a condition of installation. Test upgrades and rollback of Bazel plus its
runtime packages, both tools in installed images, and no accidental dependency
on the builder's home configuration. Base provisioning is pending; this probe
does not install or package Bazel.

## Pinned ports input and package composition

`bazel9.json` is the candidate version contract, not a claim of qualification.
`port-plan.py` evaluates a trusted selected ports checkout through Make without
running a build or install target. It rejects package-version or Java-origin
drift instead of choosing whatever executable happens to be in PATH:

```
python3.12 tools/build/bazel/port-plan.py --ports /usr/obj/5BSD-ports \
  --config tools/build/bazel/bazel9.json \
  --output /usr/obj/usr/src/bazel9-port-plan.json
python3.12 -B tools/build/bazel/port-plan-test.py
```

The checkout path is a command input. The current candidate pins Bazel 9.3.1
and the OpenJDK21 origin. It does not lock the full dependency closure: the actual
package archives and their digests must be selected together using the existing
`tools/build/capimage/package_inventory.py` format-1 selection. Format-2 repository
roots can first resolve the package closure from a private, authenticated combined
repository. Inventory checks declared dependencies, shared-library providers and
conflicts; it does not itself authenticate the publisher or approve versions.
Reuse those existing inventory/composition contracts for system delivery.

Evaluated runtime dependencies of this port are bash, OpenJDK21 and Python3.12;
build dependencies add zip and Go1.26. OpenJDK21's default port includes X11,
audio and font dependencies. Include and measure the real dependency closure;
do not omit it to make image-size results look better. A headless variant would
need its own maintained port configuration and qualification.

Publication currently has maintained base and hardware paths. General default
software from ports needs an explicit system-software composition input/phase
before combined publication; Bazel is not hardware, and its files should not be
silently copied into pkgbase archives. Reuse package identities/inventory and
include the selected closure in installer/update manifests. Keep publication
atomic. This phase is not implemented by this metadata probe.

The first Make coexistence check cleaned and rebuilt unchanged `bin/echo` through
`make buildenv` with 16 jobs after the Bazel probe. Compilation/linking succeeded.
Executing the Make output on the older host failed with missing
`cap_rights_intersect@FBSD_1.9`; matching-system runtime qualification remains
required. The Bazel host-toolchain binary passed four cases. These two builds
use different sysroots and flags, so neither byte parity nor system runtime
parity is claimed. General ports Make coexistence remains to be exercised.

## Isolated package build prerequisite

The cached Bazel9 distribution, OpenJDK21 source, and amd64 bootstrap JDK archives
matched the selected ports `distinfo` SHA256 and sizes on 2026-10-24. No cached
Bazel9/OpenJDK21 package was found. This is input integrity evidence, not a build.

A native disposable build root is required for the next package build. Populate
it with a matching qualified world, pkg and the selected custom ports tree; use
standard `/usr/obj` work/staging paths and all logical CPUs. Ports dependency
installation must happen inside that root. The existing hardware builder has
hardware-specific kernel/package checks and cannot simply be relabeled for this
system-software phase. Root is needed for chroot and device/filesystem mounts;
the current unprivileged session has neither sudo nor doas.

Once the isolated root is prepared, the root-shell build operation is the normal
ports target (paths below are inside that root):

```
chroot /usr/obj/usr/src/bazel-builder make -C /usr/ports/devel/bazel9 \
  BATCH=yes MAKE_JOBS_NUMBER=16 WRKDIRPREFIX=/usr/obj \
  PACKAGES=/usr/obj/packages package-recursive
```

Here `/usr/ports` must be the explicitly selected 5BSD ports checkout staged into
the builder, and 16 is this host's logical CPU count; derive that count when
provisioning another builder. `/usr/obj/packages` is private build staging, not
an additional configured update repository. Do not run this against an arbitrary
or unprepared directory, and do not execute ports dependency installation on the
host. The command has not been executed. Clean-root provisioning and the general
system-software phase remain integration work.

Do not substitute a bootstrap JDK at an arbitrary object-directory JAVA_HOME to
get a green Bazel build: the port embeds JAVA_HOME in its launcher. The installed
image needs the declared JDK path and complete runtime dependency closure.

## Licensing and default installation

Bazel's Apache-2.0 license does not describe its complete distribution. The
selected Bazel9 port requires OpenJDK21, Bash and Python at runtime. OpenJDK
uses GPLv2 with the Classpath Exception where designated; Bash is GPLv3+;
Python uses the PSF license. Building BSD software with these tools does not
by itself change that software's license. Shipping the tools still requires
satisfying their own redistribution obligations, including applicable source
and notice requirements. A default installation containing this closure is not
an entirely permissively licensed installation.

The selected OpenJDK21 port also declares X11, font, audio and image-library
dependencies. For example, alsa-lib declares LGPL21+. The complete recursive
package closure and Bazel's bundled third-party components have not yet received
a license audit. Do not infer approval from the top-level LICENSE variable or
label unknown licenses permissive. Before default-image publication, inventory
licenses and license combinations from the actual selected packages, preserve
notices, and establish corresponding-source delivery for applicable components.
Record this beside the package hashes and update ownership. Build-only tools
must be distinguished from shipped runtime packages.

Keep Bazel and its runtime dependencies as separately identified packages in
the default system composition. Investigate a maintained headless Java variant
for footprint reduction; the current port does not supply that qualification.
No dependency may be silently excluded from the image to satisfy a size or
licensing claim. This requirement does not enable Bazel as a system backend.

License references:
- https://github.com/bazelbuild/bazel/blob/master/LICENSE
- https://openjdk.org/legal/gplv2+ce.html

The 2026-10-24 review used the selected local ports Makefiles, not an assertion
that every transitive or bundled component had been audited.

## Declared native C/C++ pilot

`declared-probe.py` and `cc_toolchain_config.bzl` exercise actual Bazel C/C++
compile/link actions with a copied source-built compiler and SDK. They do not
invoke Make for compilation. Required inputs are explicit:

```
python3.12 -B tools/build/bazel/declared-probe.py --src /usr/src \
  --sysroot /usr/obj/usr/src/amd64.amd64/tmp \
  --objdump /usr/obj/usr/src/amd64.amd64/usr.bin/clang/llvm-objdump/llvm-objdump \
  --bazel /usr/local/bin/bazel --target x86_64-unknown-freebsd16.0 \
  --cpu k8 --clang-version 21 \
  --readelf /usr/bin/readelf \
  --make-library /usr/obj/usr/src/amd64.amd64/tools/build/bazel/shared-reference/libbsd_samples.so.1 \
  --output /usr/obj/usr/src/bazel-declared-pilot
```

First build the independent Make reference described below. Use a fresh output path. The CPU name is Bazel's explicit toolchain key, while
the target triple determines Clang's ABI. No cross-build qualification is implied.
Development-header symlinks are materialized into declared files. Library links
must resolve within the staged SDK. Compiler/header and linker/library filegroups
are separate, avoiding library inputs on every compile. Whole-SDK staging is a
pilot convenience and its disk/time cost is not a production performance result.

The pilot builds the real base echo source and a C++ vector/iostream test, then
injects errors into the copied source and SDK header. Each change must cause a
real failed rebuild bearing the injected diagnostic; restoring it must rebuild
successfully. It records tool/source origins, staged input hashes, commands,
output hashes and explicit qualification limits. No dependency-check suppression
or host-header fallback is used. Only the C++ target requests C++ runtime libraries.

The `bsd_static_binary` macro rejects shared requests; the separate
`bsd_shared_library` macro now exercises explicit PIC and shared-link actions.
This experimental configuration is staged by `bsd_toolchain.py`, shared by this
pilot and `otel-probe.py`; it is not a supported build-backend interface. The earlier trial
with empty/disabled shared action configurations caused a Bazel5 internal error
and was removed. The new shared metadata gate below uses real configured actions,
not that failure as evidence of compatibility.

The processwrapper sandbox does not establish full hermeticity. Bazel/Java,
embedded tools, the host kernel, and any executable runtime dependencies remain
host inputs. SDK hashing does not authenticate source provenance. The current
qualification uses installed Bazel5.4.1; Bazel9/Bzlmod, full base targets, complete dynamic
runtime/ABI coverage, cross builds, package manifests, output parity and performance remain
unqualified. Build-bsd continues selecting Make.

`runtime_test.c` is a separately Make-built static ATF helper for matching-system
qualification. It checks four echo cases against both Bazel and Make outputs,
and the C++ expected output. It checks exact stdout, empty stderr and successful
exit status. Guest fixture defaults are `/usr/tests/bazel/echo`, `make-echo` and
`cpp_runtime`; ATF variables `echo_program`, `make_echo_program`, `cpp_program`
can override them. A parent VM runner supplies these files explicitly.

A native trial of the current-SDK static echo aborted on the older host's
capability ABI; the C++ program printed `3`. Matching-system VM evidence is
required rather than replacing echo's capability behavior or weakening checks.
See `SHELLS.md` for the separate Bash/Zsh feasibility audit. No shell replacement
is part of this pilot.

## Matching-kernel pilot runtime (2026-10-24)

The parent-run QEMU fixture passed echo_variants, make_echo_variants and
cpp_runtime: four exact output/exit/stderr cases for each echo, plus C++ output
3 followed by newline. Bazel r4 binaries were staged by receipt hashes; r5
outputs match those hashes exactly. The Make control was built independently
through maintained buildenv with NO_SHARED=yes and 16 jobs. This establishes
bounded static runtime coexistence, not artifact parity or general ports support.

The VM had 2048 MiB RAM, two vCPUs and a 512 MiB disk-backed root. It exited
zero with clean guest poweroff and no forced termination. Four retained harness
baselines also passed. Prior static harness binaries and boot support were
explicitly reused and hashed; this was not a new full world build.

An initial staging refresh failed on an inherited read-only destination and
the shell incorrectly continued to a VM missing the Make control. That run
failed and is retained under vm/. Corrected private-file replacement and
separate launch produced the accepted vm-r2/ run. No failed run is counted as
qualification. Evidence: /usr/obj/usr/src/security-qualification/
bazel-declared-runtime-20261024/runtime-receipt.json.

Bazel9, shared/dynamic libraries, full world/kernel/packages, cross compilation,
Secure Boot and performance remain unqualified. No backend default is changed.

## Static archives and assembly

The declared pilot now also builds unmodified `lib/libc/string/strnlen.c` and
`lib/libc/amd64/stdlib/div.S` into `libbsd_samples.a` through Bazel's C, preprocessed
assembly and archive actions. The source fixture is explicitly amd64; other
triples are rejected by this pilot until architecture-specific cases exist.
This does not establish a kernel build or generated kernel-header correctness.

`bsd_static_library` uses static library semantics, and `bsd_static_binary` accepts
explicit deps/copts. `archive_runtime.c` calls both real library members with
builtins disabled and checks signed quotient/remainder and bounded-string cases.
Archive member enumeration and defined-symbol output are recorded. Linker
trace-symbol diagnostics must show that both functions came from the new archive;
resolving them from the already-built SDK libc cannot satisfy this check.
The actual staged llvm-ar command is retained in the build transcript.

The negative dependency suite now additionally modifies copied strnlen.c, div.S
and machine/asm.h, requires the injected compiler/preprocessor diagnostic, then
restores and rebuilds each input. The SDK and source checkout are never mutated
by these tests. The initial qualified archive is recorded under
`/usr/obj/usr/src/bazel-archive-qualified-20261024/`; existing echo/C++ output
hashes match the preceding pilot. No archive reproducibility across independent
builders or CPU/disk/memory performance claim is made.

The static runtime helper adds `archive_runtime`, using guest input
`/usr/tests/bazel/archive_runtime` or explicit ATF `archive_program`. It requires
zero exit, empty stderr and exact `archive-runtime: ok` output with newline.
The parent controls matching-system VM execution and records its own receipt;
compile-only result files retain `runtime_qualified: false`.

Before frontend/backend exposure, real target graphs still need archive install
metadata, generated headers, compiler flags matching Make policy, kernel-specific
ABI flags and assembly inputs, dynamic/PIC toolchains, native and cross runtime
coverage, and package/output comparison. These primitive-action checks do not
authorize selecting Bazel as the production system backend.


### Archive runtime VM qualification (2026-10-24)

The amd64 static archive pilot now passes runtime qualification in a single
QEMU guest with 2048 MiB RAM and a disk-backed 512 MiB fixture root. Eight
ATF cases passed: four existing library/namespace controls, Bazel echo,
Make echo, C++ vector/iostream, and the new C/assembly archive behavior.
The new case checks signed div quotient/remainder and bounded strnlen results;
the compile receipt separately verifies the archive supplied both symbols.
QEMU exited zero after guest poweroff, without forced termination.

Evidence: /usr/obj/usr/src/security-qualification/bazel-archive-runtime-20261024,
including runtime-receipt.json binding the staged inputs, compile receipt,
VM result and serial transcript. Compile-only results remain unmodified.
The guest harness supplies per-case directories and deadlines; raw ATF warnings
about running outside kyua do not mean these controls were omitted.

Frontend review: no production backend or build input contract changes. Make
remains selected by build-bsd. This does not qualify Bazel9, world/kernel,
cross builds, shared libraries, package parity, Secure Boot, or performance.

## PIC and shared-object metadata gate

The toolchain now propagates the explicit target triple, staged sysroot and staged
LLD path to every executable and shared-library link action. `fully_static_link`
is enabled by static binary targets, rather than forcing `-static` onto shared
links. PIC compile actions receive `-fPIC` and BSD assembly's `-DPIC`. The shared
macro requires an explicit SONAME and enables fatal shared-textrel warnings;
links use immediate binding and RELRO to match the maintained Make defaults.

The independent reference uses `shared-reference/Makefile`, unmodified libc
strnlen.c and amd64 div.S, and the normal `bsd.lib.mk` implementation:

```
env MAKEOBJDIRPREFIX=/usr/obj make -C /usr/src buildenv \
  'BUILDENV_SHELL=make -C /usr/src/tools/build/bazel/shared-reference -j16 all'
```

The declared probe builds its own same-source shared object through Bazel, then
`elf-shared-check.py` compares ELF class/data/OS ABI/machine, SONAME and NEEDED
against the explicitly selected Make artifact. Both must have RELRO and NOW,
nonexecutable stacks, no writable-executable LOAD segment, no TEXTREL, and no
RPATH/RUNPATH. The checker records the readelf tool hash, both artifact hashes,
raw inspection output and metadata. It does not execute either library.

```
python3.12 -B tools/build/bazel/elf-shared-check-test.py \
  --readelf /usr/bin/readelf \
  --reference /usr/obj/usr/src/amd64.amd64/tools/build/bazel/shared-reference/libbsd_samples.so.1
```

Seven negative/positive metadata test cases pass. The qualified fixture has
SONAME `libbsd_samples.so.1` and NEEDED `libc.so.7`, matching Make. Evidence lives
under `/usr/obj/usr/src/bazel-shared-qualified-20261024-r2/`. Its existing result
field `shared_target_rejected` refers specifically to rejection of a shared
request through the static macro, not rejection of the supported shared macro.
The source/header/assembly invalidation checks cover both archive and shared
outputs. PIC archives legitimately contain `.pic.o` members; membership checks
still require exactly the two selected real sources.

This gate does not establish exported-symbol version policy, complete ABI parity,
installed library locations, loader search/runfiles deployment, dynamic runtime
behavior, or all Make compiler policy flags. Make uses `-fpic` in this amd64
reference while the Bazel pilot uses `-fPIC`; both are PIC here, but no cross-arch
flag equivalence is assumed. Source/SDK and hardening changes can alter the static
outputs too; previous VM receipts apply only to their recorded hashes.

## Shared-library runtime fixture

`shared_runtime.c` is compiled as a dynamic PIE by the declared Bazel toolchain.
It takes one absolute library pathname, uses `dlopen(RTLD_NOW | RTLD_LOCAL)`,
resolves div/strnlen with `dlsym`, then checks each pointer with `dladdr` and
canonical file paths. Both symbol providers must be the explicitly requested
library before signed division and bounded-string tests run. Finding same-named
functions in libc cannot satisfy that check. Success requires `dlclose` too.

The static ATF launcher provides three cases with explicit configurable inputs:

- `shared_bazel`: `shared_program` loads `bazel_library`.
- `shared_make`: the same program loads the independent `make_library`.
- `shared_missing_library`: confirms `missing_library` does not exist, then
  requires the actual dlopen-failure exit status, empty stdout, and a diagnostic
  identifying that requested pathname. A loader/exec failure is a different
  status and cannot pass this control.

Default guest paths are `/usr/tests/bazel/shared_runtime`,
`/usr/tests/bazel/libbsd_samples.so.1`,
`/usr/tests/bazel/libbsd_samples-make.so.1`, and
`/usr/tests/bazel/intentionally-missing.so`. The parent runner supplies those
fixtures. The dynamic program requests `/libexec/ld-elf.so.1` and libc.so.7;
matching rtld, libc and its dependency closure must be staged from the qualified
system. Do not run against older host runtime libraries and call that system
qualification.

Compilation, dependency-invalidation and shared-metadata evidence is under
`/usr/obj/usr/src/bazel-shared-runtime-qualified-20261024/`. Parent-controlled VM
execution remains a separate receipt. These library semantics tests cover two
small real-source functions, not general plugin loading, symbol versioning,
TLS, constructors, interposition, C++ exceptions across DSOs, or whole-system ABI
compatibility. No host packages or firmware were changed by this work.


### Shared-library VM runtime qualification (2026-10-24)

The current Bazel shared/PIC outputs passed in one 2048 MiB QEMU guest with
a disk-backed 512 MiB root. Eleven cases passed: four existing library/namespace
controls, Bazel and Make echo, C++ vector/iostream, static archive behavior,
Bazel shared-library behavior, Make shared-library behavior and an actual
missing-library failure. The dynamic checker uses dlopen/dlsym and verifies
each function's library with dladdr and realpath before testing its behavior.
Resolution from libc cannot satisfy the requested-library check.

The guest interpreter and dependencies were derived from ELF metadata: the
matching object-tree ld-elf.so.1 plus SDK libc.so.7 and libsys.so.7. No host
runtime library was substituted. The VM shut down cleanly, exit zero, without
forced termination. New static output hashes are covered by this receipt;
old receipts remain bound to their old artifacts. Compile-only result files
retain their original runtime_qualified=false scope.

Evidence: /usr/obj/usr/src/security-qualification/bazel-shared-runtime-20261024,
including runtime-receipt.json binding source, artifact and VM evidence.
Frontend review: these are primitive toolchain/runtime pilots. No production
Bazel backend is selected by build-bsd. Bazel9, full world/kernel, complete ABI
and symbol-version parity, cross compilation, installation/package parity
and performance remain open. Make remains the production backend.

## Real versioned base library: libsbuf

The declared pilot now builds the actual `sys/kern/subr_prf.c` and
`sys/kern/subr_sbuf.c` as `libsbuf.so.6`. Its inputs include maintained
`lib/libsbuf/Symbol.map`, `lib/libsbuf/Version.def` and
`share/mk/version_gen.awk`. `version_map.bzl` declares preprocessing and AWK
as separate executable actions; `stdout_redirect.c` supplies output redirection
without a shell pipeline. Compiler inputs, staged AWK and generator inputs are
explicit. This native execution tool uses the same staged toolchain; its use
has not qualified cross compilation. Host AWK runtime dependencies remain
execution dependencies; this is not complete hermeticity.

Build the comparison library in a fresh private Make object directory:

```
mkdir -p /usr/obj/usr/src/bazel-libsbuf-reference-20261024
env MAKEOBJDIRPREFIX=/usr/obj make -C /usr/src buildenv \
 'BUILDENV_SHELL=env MAKEOBJDIR=/usr/obj/usr/src/bazel-libsbuf-reference-20261024 make -C /usr/src/lib/libsbuf -j16 libsbuf.so.6'
```

In addition to the declared pilot's existing explicit inputs, supply:

```
--awk /usr/obj/usr/src/amd64.amd64/tmp/legacy/usr/bin/awk \
--make-sbuf-library /usr/obj/usr/src/bazel-libsbuf-reference-20261024/libsbuf.so.6 \
--make-sbuf-map /usr/obj/usr/src/bazel-libsbuf-reference-20261024/Version.map
```

These are example fixture locations, not product defaults. The pilot requires
byte-identical generated version maps and compares defined GLOBAL/WEAK dynamic
symbol names, versions, types, bindings and visibility using
`elf-version-check.py`, alongside existing shared-library metadata/hardening
checks. Version inputs each undergo error injection followed by recovery. A
second control removes the real `sbuf_len` export, links the resulting library,
and requires the interface comparison to reject it. The rejected binary is
retained with its hashes in `version-negative.json`; inputs are restored and
the positive comparison reruns. Source modifications are confined to staged
private fixtures.

This establishes a bounded real base-library integration step. It does not
prove full ABI parity, runtime semantics, symbol-interposition behavior,
performance, all Make policy flags, Bazel9 or whole-world coverage. The production
frontend remains Make; no new build-bsd selection or package contract is enabled
by this pilot. The next shared frontend change requires a supported system graph
and installation/package parity, not only these passing primitives.

2026-10-24 evidence: `/usr/obj/usr/src/bazel-libsbuf-qualified-20261024-r2/`
contains the successful full probe, retained deliberately broken library,
command logs, input hashes and comparisons. All 26 versioned dynamic exports
matched Make; definitions include FBSD_1.2 through FBSD_1.6. The restored library
SHA256 is `75eaf8356bb5e66e5d6ba45438d7a5d30ffb024982931a157b11b09d8a7ead3a`.
The independently linked missing-export library was rejected for export drift,
not for loader metadata or an unrelated build failure. Seven shared metadata
verifier tests also passed. This libsbuf artifact has not yet run in a VM.

### Real libsbuf runtime fixture

`sbuf_runtime.c` is a declared dynamic executable with no direct libsbuf link.
It takes an absolute library pathname and resolves each tested API with
`dlvsym(..., "FBSD_1.2")`; `dladdr` and canonical path equality must identify
the requested library for every function. It checks:

- Automatic growth from a two-byte request to 4096 payload bytes, formatted
  suffix, exact length/content, finish/error/done state and clear/reuse.
- A fixed eight-byte buffer's overflow, ENOMEM propagation through finish,
  and recovery using clear.
- Partial drain callbacks consuming at most three bytes, with exact collected
  contents after finish, plus explicit EIO from a failing drain callback.

ATF cases `sbuf_bazel` and `sbuf_make` use the same program and assertions.
Inputs are `sbuf_program`, `bazel_sbuf_library` and `make_sbuf_library`, defaulting
respectively to `/usr/tests/bazel/sbuf_runtime`, `/usr/tests/bazel/libsbuf.so.6`
and `/usr/tests/bazel/libsbuf-make.so.6`. These are fixture paths, not production
library installation decisions. Existing static/shared cases remain intact.
Stage the declared output and independent Make library plus the rebuilt static
`runtime_test` in the parent's matching-system VM fixture, using the existing
rtld/libc dependency closure. This new executable has only libc as DT_NEEDED;
it loads the requested libsbuf explicitly at runtime. Compilation alone does
not count as execution evidence; the parent must bind its VM receipt to hashes.
These cases do not exhaust sbuf's API, later symbol-version sets, allocation
failure handling or concurrency behavior.


### Real libsbuf runtime qualification (2026-10-24)

A single 2048 MiB QEMU guest with a 512 MiB disk-backed root passed thirteen
cases: four baseline cases, seven previous Bazel/Make runtime cases and new
sbuf_bazel/sbuf_make cases. The dynamic probe resolves each exercised API by
its FBSD_1.2 symbol version and verifies the requested library supplies it.
It checks buffer growth, formatting and content, finish/reuse, fixed-buffer
overflow and recovery, repeated partial drains and drain-error propagation.
Both the Bazel-built and independently Make-built libsbuf.so.6 pass.

Artifacts match the declared-build receipt and the guest's staged-input hashes.
The runtime uses matching object-tree ld-elf.so.1 and SDK libc/libsys, with no
host library substitution. The guest exits cleanly, QEMU status zero, without
forced termination. Sources were checked unchanged after execution.

Evidence: /usr/obj/usr/src/security-qualification/bazel-libsbuf-runtime-20261024,
including runtime-receipt.json. Compile-only pilot receipts retain their original
runtime_qualified=false scope; this separate receipt supplies guest evidence.
Full ABI coverage, Bazel9, cross compilation, world/kernel and packaging parity,
and performance qualification remain open. Make is still the production backend.
Frontend review: this extends the declared toolchain pilot and existing generic
runtime runner; no production backend selection changes in build-bsd.c.

## Maintained frontend qualification entrypoint

`qualify.py` is thin orchestration of this pilot, not a replacement build tool:

```
python3.12 tools/build/bazel/qualify.py --src /usr/src \
 --objtop /usr/obj/usr/src/amd64.amd64 --bazel /usr/local/bin/bazel \
 --output /usr/obj/usr/src/bazel-qualification-NEW --jobs 16
```

The frontend supplies source, native objtop, Bazel executable, a new evidence
output and selected job count explicitly. Optional `--make` and `--readelf`
default to `/usr/bin/make` and `/usr/bin/readelf`; tool hashes are recorded.
Only native FreeBSD amd64 is supported. Before creating evidence output, it
checks maintained Make buildenv's actual OBJTOP/MACHINE/MACHINE_ARCH, obtains
the target and resource directory from staged Clang, and rejects mismatches.
Source/output paths cannot overlap, output cannot be inside the copied sysroot,
and object/evidence locations must stay under `/usr/obj`.

The helper builds fresh private Make libraries through `buildenv`, with
`SRCCONF` and `__MAKE_CONF` set to `/dev/null` in a bounded environment. It then
runs the existing declared probe and metadata verifier tests. No host install,
VM or production backend selection occurs. `receipt.json` records compile-only
scope and failure status where construction has started; source/tool hashes
are rechecked before success. Checks cover selected source inputs and tools,
not a transactional snapshot of every Make include or SDK object. Host runtime,
Bazel/Java execution and SDK provenance still need broader qualification.

`qualify-test.py` covers invalid paths, symlink escapes, Make object identity
and staged target/resource identity. The real full entrypoint passed in
`/usr/obj/usr/src/bazel-entrypoint-20261024-r2/`; four boundary tests and actual
CLI rejection of non-object output and reused evidence directories passed too.
The frontend action remains a qualification action, with Make production.
Runtime qualification uses separate artifact-bound VM receipts.

Pinned distribution repository cache
------------------------------------
repository-cache.py --archive /absolute/bazel-dist.zip --sha256 EXPECTED_SHA256
--output /usr/obj/NEW-DIRECTORY exports the distribution's content-addressed
repository cache. Supply a previously verified distribution digest. The helper
checks every cache entry against its SHA256 filename, rejects unexpected or
duplicate entries and links, and publishes NEW-DIRECTORY/cache only after all
checks pass. It never executes archive contents or merges existing caches.
Failed exports retain a FAIL receipt and cache.pending for inspection.

Use the returned directory as Bazel's --repository_cache input. This is a
cache seed, not proof that an arbitrary consumer's module graph can resolve
offline. A consumer still needs explicit module versions, a lockfile, required
registry metadata and extension inputs, followed by an actual offline build.
The current Bazel5 pilot is not converted or qualified for Bazel9 by this helper.
Native corruption/escape/duplicate checks: python3.12 -B repository-cache-test.py.

Bootstrap failure propagation
-----------------------------
bootstrap-status-test.py --buildenv /absolute/patched/scripts/bootstrap/buildenv.sh
--bash /absolute/path/to/bash checks the actual upstream run helper, extracting
its body from the supplied source. It verifies success and exit statuses 1, 37,
and 134 in verbose and quiet modes. This guards against swallowing compiler
failures through the status of shell negation. A passing test proves helper
error propagation only; it does not qualify Java execution or a Bazel build.
Run this against the source after applying the selected ports patches.

Shared libmd generators
-----------------------
lib/libmd/genhl.sh and genman.sh implement the source/manual transformations
used by maintained Make recipes and the candidate Bazel graph. Algorithm
parameters remain declared in lib/libmd/Makefile. Tool executable inputs are
explicit; LIBMD_GEN_SED/CAT/MV/RM are individual executable names, not shell
command strings. Failed generation preserves an existing completed target;
success replaces it using a sibling temporary file and rename.

Run the standalone native amd64 regression against a staged Make world:

```
python3.12 -B tools/build/bazel/shared-generator-test.py \
  --component /usr/src/lib/libmd --src /usr/src \
  --objtop /usr/obj/usr/src/amd64.amd64 \
  --work /usr/obj/usr/src/NEW-generator-failure-check
```

It tests partial-writing sed/cat failures, rename failures, exclusive temporary
collisions, and ordinary Make retry without forcing a rebuild. The reviewed
candidate retained byte parity for all 16 active generated files with assembly
sources enabled and disabled. Native Make compilation/linking of libmd.a and
libmd.so.7.full also passed. Receipts are in
/usr/obj/usr/src/bazel-libmd-graph-20261024/atomic-generator-review-r9.json and
/usr/obj/usr/src/libmd-shared-generators-compile-20261024/receipt.json.
This refactor does not enable a Bazel system backend or establish Bazel9
compilation, installation, package or runtime parity.

Make installation reference in bazel-test
-----------------------------------------
The maintained build-bsd bazel-test action now runs install-reference.py after
the Bazel compile/artifact pilot. Its Make-only libmd build and stage are saved
in make-install-reference/ beneath the qualification output. This preserves
actual source-tree layout, recursively separate object directories, the
recorded .src_opts world profile, and top-level IMAKE_INSTALL metadata flags.
It does not import Bazel artifacts or qualify installation parity.

The combined receipt records make_install_reference separately and hashes its
receipt. Runtime, complete package archives, Bazel9 and the system backend
remain unqualified. Both the reference script and imported environment helper
are hashed before execution and rechecked; the recorded inputs are not a full
hermetic build closure. NO_ROOT ownership/modes remain logical METALOG values.

The standalone guard suite accepts --src, --objtop, --profile and fresh --work
below /usr/obj. It checks output reuse, copied-source components, mismatched
profiles, invalid parallelism, symlink escapes and Make/control-character
paths before output creation. Actual build/install coverage currently uses
libmd; this does not establish arbitrary component or world coverage.

OpenTelemetry component targets (2026-10-26)
--------------------------------------------
`otel-probe.py` builds real Bazel targets for every OpenTelemetry component
listed in `targets/sources.json` through the declared toolchain, and builds the
same sources independently through maintained Make `buildenv` against the same
staged SDK. No Make subprocess is wrapped by Bazel. build-bsd continues to
select Make. The 2026-10-26 results below (`bazel-otel-r3`) cover the first
four targets; the integrated set and its results are in "Integrated OTel set"
further down.

Layout:

- `bsd_toolchain.py` stages the declared toolchain package; `declared-probe.py`
  and `otel-probe.py` share it. The existing pilot was rerun after this
  refactor (`/usr/obj/5BSD-otel-validation/bazel-declared-pilot-r1/`): all nine
  outputs are byte-identical to the hashes bound by the 2026-10-24 VM receipts.
- `bsd_component.bzl` holds Make compile policy (base, debug, PIE, SSP and
  WARNS 6/3 lists from bsd.sys.mk/bsd.lib.mk/bsd.prog.mk) and macros:
  `bsd_internal_library` (INTERNALLIB: `lib<name>.a` plus `lib<name>_pie.a`
  with `-fpie -DPIC`), `bsd_program` (dynamic PIE, `PROG.full` before the
  debug split) and `bsd_atf_test_c` (`-lprivateatf-c`).
- `targets/` overlays BUILD files onto a workspace that mirrors source paths;
  no BUILD file is added to the source directories themselves. Source lists
  are the `*_SRCS` lists in `targets/<path>/BUILD.bazel`; update those when
  the component Makefiles change. `targets/BUILD.bazel` declares header-only
  bundles (`sys/**/*.h`, OpenSolaris compat/head, libdtrace/common,
  libtracecmp) whose `includes` reproduce Make's `-I` order without absolute
  paths. `targets/sources.json` lists copied directories, artifacts and
  dependency probes.
- `elf-artifact-check.py` compares programs (ELF identity, interpreter, PIE,
  RELRO/NOW, TEXTREL, RPATH/RUNPATH, stack, W+X, NEEDED set, imported and
  exported dynamic symbols with versions, version requirements per provider)
  and archives (member order, defined and undefined symbols per member), and
  records per-section hashes. `elf-artifact-check-test.py` has six
  positive/negative cases (program metadata drift, missing member, member
  order, renamed symbol).

Run (all logical CPUs; fresh output below /usr/obj):

```
python3.12 -B tools/build/bazel/otel-probe.py --src /usr/obj/5BSD-otel-bazel \
  --sysroot /usr/obj/usr/src/amd64.amd64/tmp \
  --objdump /usr/obj/usr/src/amd64.amd64/usr.bin/clang/llvm-objdump/llvm-objdump \
  --awk /usr/obj/usr/src/amd64.amd64/tmp/legacy/usr/bin/awk \
  --bazel /usr/local/bin/bazel --target x86_64-unknown-freebsd16.0 --cpu k8 \
  --clang-version 21 --jobs 16 --output /usr/obj/5BSD-otel-validation/bazel-otel-NEW
```

The Make reference runs `make -C SRC buildenv WORLDTMP=<sysroot>` with
`SRCCONF=__MAKE_CONF=/dev/null`, a private `MAKEOBJDIRPREFIX`, one private
`MAKEOBJDIR` per component and `LIBOTELEXPORTDIR` pointing consumers at the
private library build. Dry-run commands (`make -n`) and `-V SRCS/CFLAGS/
LDFLAGS/WARNS` are recorded. Bazel uses `--compilation_mode=opt` (so binaries
use non-PIC actions plus Make's explicit PIE flags) and `--strip=never`.

### Results (evidence `/usr/obj/5BSD-otel-validation/bazel-otel-r3/`)

- libotelexport is an `INTERNALLIB`: Make builds only `libotelexport.a` and
  `libotelexport_pie.a`; there is no shared object, SONAME, SHLIB_MAJOR or
  symbol version map to match. Bazel builds the same two archives and does not
  invent a shared library. Member order and per-member defined/undefined
  symbols equal Make's. Bazel also emits its own unused `lib*.pic.a` default
  outputs for direct library builds; nothing links them.
- Compile flags: after removing explained Bazel-only tokens (`-frandom-seed`,
  `-iquote` workspace roots, generated-file `-isystem` twins, explicit
  `-nostdinc`/SDK `-isystem`, dependency-file names and
  `-fdebug-compilation-dir=.`), every compile action equals Make's ordered
  flag list, and the include search order equals Make's `-I` order. Make also
  names `cddl/contrib/opensolaris/lib/libproc/common` and
  `sys/cddl/contrib/opensolaris/compat`, which do not exist in the tree.
  `includes` gives `-isystem` rather than `-I`; with Make's `-Wsystem-headers`
  this does not suppress diagnostics.
- Object code: the non-debug sections of every Bazel object equal the Make
  `.o`/`.pieo` except `otelexport_test.o`, whose `.rodata.str1.1`, `.rela.data*`
  and `.symtab` differ because ATF macros embed `__FILE__` (Make passes absolute
  source paths, Bazel workspace-relative paths).
- Link: options (`-pie`, `-gz=zlib`, `-z now`, `-z relro`), library set and
  object order equal Make. `bsd.prog.mk` links with `${CFLAGS}`; only
  `-gz=zlib` affects the link, so `bsd_program` passes it explicitly.
  NEEDED order differs for hwstat and bsdinstruments: Bazel emits a binary's
  own linkopts before dependency linkopts, while src.libnames.mk orders LDADD
  differently. The NEEDED set, imports and version requirements are equal; a
  diagnostic relink of the Bazel objects with Make's exact link command
  reproduces every non-debug section of Make's `.full` byte-for-byte for
  hwstat and bsdinstruments. The test program additionally differs by the
  `__FILE__` strings, which shift later sections.
- Debug: debug sections differ by recorded paths. Make's debug split
  (`.debug` file plus `--add-gnu-debuglink` stripped program) is not modeled;
  comparisons use Make's `.full`.
- Reproducibility: Bazel sandboxes each action in a numbered directory that
  clang recorded as `DW_AT_comp_dir`, so identical rebuilds differed. The
  toolchain now passes `-fdebug-compilation-dir=.` to compile actions. After
  that, all five outputs are byte-identical across three independent output
  roots (`bazel-otel-r2`, `-r3`, `-qualify-args-r1`) and after every
  restore in the negative suite. The change does not alter the existing
  pilot outputs, which have no debug information.
- Negative dependency suite: eleven copied inputs (library source, public and
  private headers, test source, program headers, source-tree `dtrace.h` that
  shadows the SDK copy, libspl `sys/types.h`, `tracecmp.h`, SDK `zlib.h` and
  `atf-c.h`) each produce a failed rebuild carrying the injected `#error`;
  replacing the copied SDK `libxo.so` and `libprivateatf-c.so` link inputs
  fails the link with the injected marker. Each is restored and rebuilt.
  Removing `oe_text.c` from the BUILD list is rejected by the Make SRCS check.
- Host runtime (not matching-system qualification): on this 16.0-CURRENT
  host (kernel built 2026-10-07, host rtld and libraries; SDK from
  2026-10-23) all eleven ATF cases pass for both the Bazel and the installed-
  form Make test program. hwstat and bsdinstruments usage paths return 2 with
  identical output; `bsdinstruments list`, `list --json` and `generate
  accept-latency` are identical between builds; hwstat `list` field labels,
  `list --format json` structure and a one-second `watch` agree. No host ABI
  failure was observed. `runtime-fixture/` holds both builds of each program
  and the SDK providers of their NEEDED entries for a parent VM runner; no VM
  was launched.

### Integrated OTel set (2026-10-29, evidence `/usr/obj/5BSD-otel-validation/integ-bazel-otel-r4/`; development runs r2, r3)

Targets (22 artifacts): `libotelexport` (12 sources, now including the
otel.conf layer `oe_sysconf.c`/`oe_service.c`; `-Icontrib/libucl/include` for
its own objects only; `_DP_otelexport` adds `-lprivateucl`) and `libdtotel`
(INTERNALLIBs, both archives; the `_pie` archive of libdtotel links the
`_pie` archive of libotelexport, as `${PIE_SUFFIX}` selects), hwstat,
bsdinstruments (now linking libdtotel and libjail), otelconf, otelpfd,
otelauditd, and the test programs `otelexport_test`, `sysconf_test`,
`sysconf_oom_test` (link-time `--wrap` allocation failure), `otlp_validate`,
`otlp_collector`, `dtotel_test`, `bsdinstruments_unit_test`,
`otlp_fake_receiver`, `otlp_json_validate`, `pfstat_test`, `mkpfstatus`,
`auditrec_test`, `mkaudittrail`. Each manifest artifact names the Make
variable holding its sources (`SRCS`, or `SRCS.<prog>` for bsd.progs.mk, with
`default_src` when bsd.progs.mk falls back to `<prog>.c`); private
INTERNALLIB directories (`LIBOTELEXPORTDIR`, `LIBDTOTELDIR`) are passed to
every consumer's Make reference.

Run against an SDK staged by a full buildworld of this tree
(final run r4: `integ-obj-world22/.../amd64.amd64/tmp` from the clean full
buildworld of the final merged tree, `integ-final2-buildworld.log`; r2 used the
merge-resolution snapshot `integ-snap-obj/.../tmp`):

```
python3.12 -B tools/build/bazel/otel-probe.py --src /usr/obj/5BSD-hypertrace \
  --sysroot $W/tmp --objdump $W/usr.bin/clang/llvm-objdump/llvm-objdump \
  --awk $W/tmp/legacy/usr/bin/awk --bazel /usr/local/bin/bazel \
  --target x86_64-unknown-freebsd16.0 --cpu k8 --clang-version 21 --jobs 16 \
  --output /usr/obj/5BSD-otel-validation/integ-bazel-otel-r4
```

Results (status passed):

- SRCS: all 22 BUILD source lists equal Make; removing `oe_text.c` is still
  rejected (`srcs_drift_rejected`).
- Compile: all 72 compile actions equal Make's ordered flag list and include
  order after the explained tokens. A component-private `-I` passed through
  `copts` (libucl) is compared as an include directory. When several
  bsd.progs.mk programs compile the same object, Make prints one command per
  program; they must be identical apart from `-MD/-MF/-MT`.
- Objects: non-debug sections equal Make except in 7 test objects
  (`.rodata.str1.1`, its relocations, `.symtab`). `path_string_check` now
  proves the explanation for every differing object: the merged strings are
  identical once Make's absolute source-root prefix is removed (`__FILE__` in
  ATF macros), and every other differing non-debug section keeps its size.
  An unexplained object difference fails the probe.
- Link: options, library set and object order equal Make for every program;
  NEEDED order differs as before (Bazel puts a binary's own linkopts before
  dependency linkopts). Relinking the Bazel objects with Make's exact
  command reproduces Make's non-debug sections for every program without
  `__FILE__` strings; the test programs keep the string-length shifts.
- Negative suite: 25 copied inputs (new: `oe_otlpenc.h`, `oe_sysconf.h`,
  `oe_sysconf.c`, `failalloc.h`, `contrib/libucl/include/ucl.h`,
  `dtotel_impl.h`, `dtotel.h`, `dtrace_stub.h`, `pfstat.h`, `auditrec.h`,
  `bsmgen.h`, SDK `net/pfvar.h` and `bsm/libbsm.h`) each fail the rebuild with
  the injected marker; 5 SDK link inputs (adding `libprivateucl.so`,
  `libbsm.so`, `libjail.so`) fail the link. All restored outputs are
  byte-identical.
- Source inputs (8612 files: component directories and header trees) are
  hashed before the Make build and rechecked at the end. A test source edited
  mid-run had earlier produced different `__LINE__` immediates between the two
  builds; such a run now fails instead of reporting a false difference.
- Host runtime (host kernel, rtld and libraries; not a matching-system
  qualification): all 7 ATF programs give identical results for both builds
  (otelexport_test 68, sysconf_test 17, sysconf_oom_test 4, dtotel_test 43,
  bsdinstruments_unit_test 12, pfstat_test 4, auditrec_test 5). Cases are
  run from a staged copy of the source directory (ATF requires the program
  in `-s`). `require.user` is honored the way kyua honors it, so
  `sysconf_test:wrong_owner` is skipped as non-root, and ATF's `expected_*`
  outcomes count as passing. 17 usage and deterministic-output checks are
  identical, including the new otelconf/otelpfd/otelauditd usage paths and
  `otelconf show`/`get endpoint` against `otel.conf.defaults`.

### bazel-test integration

`qualify.py` runs `otel-probe.py --skip-host-runtime` after the declared pilot
and records `otel_targets` and the result hash; component directory files are
hashed and rechecked with the other inputs. build-bsd.c is unchanged: the
`bazel-test` argv, the `bazel-compile-comparison` scope and
`runtime=not-performed` remain accurate, so its tests need no change. The
manual describes the added comparison. The full `qualify.py` entrypoint was
not rerun against `/usr/src`; the probe was run with the exact arguments
`qualify.py` passes (`bazel-otel-qualify-args-r1`).

### Not qualified

- Matching-system VM runtime, Bazel9/Bzlmod, cross builds, installation,
  METALOG/package parity, ATF shell tests (bsdinstruments_test.sh,
  otelconf/otelpfd/otelauditd shell tests and the rc.d tests are not compiled
  targets), hwstat's own ATF tests, man pages, FILESGROUPS/CONFGROUPS
  installation (profile catalog, golden files, otel.conf and its defaults)
  and performance.
- The `bazel-otel-r3` SDK was built from `/usr/src`; the integrated runs use
  an SDK from this tree. When sources change, update the `*_SRCS` lists in
  `targets/`; the SRCS check fails until they match the Makefiles, and new
  `LIBADD`/`_DP_*` entries must be mirrored in `linkopts`.

dtrace(1) and libdtrace under Bazel: design
-------------------------------------------
dtrace(1) is one source (`cddl/contrib/opensolaris/cmd/dtrace/dtrace.c`) with
WARNS 1 and the bsdinstruments include order plus `usr.sbin/dtraced`;
`LIBADD= dtrace ctf elf proc spl xo pthread crypto`. A `bsd_program` target
needs only a WARNS 1 policy list and a header bundle for `usr.sbin/dtraced`.
It could not be linked against the `/usr/src` SDK: an independent Make build
of this tree's dtrace(1) failed with 20 undefined libdtrace symbols
(`hypertrace_link`, `dtrace_elf_create`, `open_dtraced`, ...), because that
SDK's libdtrace came from a different revision
(`/usr/obj/5BSD-otel-validation/bazel-dtrace-sdk-skew-r1/receipt.json`).
dtrace(1) therefore needs libdtrace from the same tree. Both routes were
taken: the integrated runs use a world SDK staged from this tree, and the
Bazel dtrace(1) links a Bazel libdtrace target (see "Implementation and
results" below). Current dtrace(1) also links libdtotel, libotelexport,
libjail, libz and libssl, and includes cmd/dtrace's `dtrace_identifiers.h`
and `hypertrace_frame.h`.

libdtrace (`cddl/lib/libdtrace`, `LIB_CXX`, `SHLIB_MAJOR` 2, `/lib`):

1. Sources: 44 C and 12 C++ (`c++20`, `-fno-rtti`, exceptions on) files
   from libdtrace/common and libgen `gmatch.c`, plus amd64 `dis_tables.c` and
   `instr_size.c` from `sys/cddl/dev/dtrace/x86`. About seventeen amd64
   include directories in a fixed order, including `${.OBJDIR}` for generated
   headers, and the forced `-include .../spl/sys/ccompile.h`. Express these as
   header bundles in `targets/BUILD.bazel` plus a declared header passed with
   `-include` by workspace-relative path; C++ flags need a `bsd_cxxflags`
   policy list. The library is `cc_library` plus `bsd_shared_library(soname=
   "libdtrace.so.2")`; check whether exports are versioned, and add an
   unversioned export-set comparison to `elf-artifact-check.py` if they are
   not.
2. Grammar and scanner: `dt_grammar.y` is processed by the staged bootstrap
   yacc (`tmp/legacy/usr/bin/yacc`, `YFLAGS=-d`, `-o dt_grammar.c`), giving
   `dt_grammar.c` and `dt_grammar.h`, which dt_cc.c, dt_cg.c, dt_lex.l,
   dt_parser.c and dt_sugar.c include. `dt_lex.l` goes through
   `tmp/legacy/usr/bin/lex -o dt_lex.c`. Use small Starlark rules
   (`bsd_yacc`, `bsd_lex`) with the tools as `cfg = "exec"` executables and
   both outputs declared. Expose the header through a cc_library `includes`
   on the generated directory. Compare the generated files with Make's
   objdir byte-for-byte, after accounting for `#line` paths, as the libsbuf
   version map is compared.
3. Shell generators: `dt_errtags.c` (`sh mkerrtags.sh < dt_errtags.h`),
   `dt_names.c` (`sh mknames.sh < sys/dtrace.h`) and `priv.d` (`sh mkpriv -o
   priv.d sys/sys/priv.h`). Run them as declared actions with staged
   `sh`/`sed`/`awk`. Redirect stdin and stdout with an extended
   `stdout_redirect.c` helper rather than a shell pipeline.
4. D library files (`DSRCS`, `/usr/lib/dtrace`, mode `NOBINMODE`) are data.
   They wait on the same installation/METALOG adapter as every other target.
5. CTF: `MK_CTF` is `no` in this configuration (checked with `-V MK_CTF`), so
   Make runs neither ctfconvert nor ctfmerge for these userland builds. A
   `WITH_CTF` build converts each object in place and merges at link.
   Bazel actions cannot rewrite their own outputs, so this needs a Starlark
   rule that uses `cc_common.compile`, runs `ctfconvert` on a copied object
   as a separate declared action, then calls `cc_common.link` and `ctfmerge`.
   `ctfconvert`/`ctfmerge` are present in the staged SDK `usr/bin`.
6. USDT providers (`*.d` in SRCS, for example libtracecmp's
   `tracecmp_provider.d`) need `dtrace -h` for headers and `dtrace -G`, which
   rewrites objects and emits a provider object. This has the same
   in-place problem as CTF and needs a build-host `DTRACE_CROSS`, which is
   not present in this staged SDK.
7. Optional knobs (`MK_DTRACE_OPTIMIZED` = `-flto`, ASAN/TSAN, benchmarks,
   `DTRACE_TARGET_ARCH`) need explicit Bazel configuration settings rather than
   a fixed flag list. All of them are `no` in this configuration.
8. Qualification: generated-source parity, per-object non-debug section
   equality, `libdtrace.so.2` SONAME/NEEDED/export comparison, a negative
   dependency suite that includes the grammar, scanner and generator inputs,
   and a VM runtime with the DTrace modules preloaded from loader.conf (late
   kldload is denied by mac_capability). On this host only `dtrace -h`-style
   usage can run without loading modules.

### Implementation and results (2026-10-29, evidence `/usr/obj/5BSD-otel-validation/integ-bazel-dtrace-r4/`, SDK of the clean final buildworld; development run r2)

`dtrace-probe.py` (sharing otel-probe.py's helpers) builds
`//cddl/lib/libdtrace:dtrace` (libdtrace.so.2) and `//cddl/usr.sbin/dtrace:dtrace`
and compares them with Make builds of the same tree against the same SDK:

```
python3.12 -B tools/build/bazel/dtrace-probe.py --src /usr/obj/5BSD-hypertrace \
  --sysroot $W/tmp --objdump $W/usr.bin/clang/llvm-objdump/llvm-objdump \
  --awk $W/tmp/legacy/usr/bin/awk --bazel /usr/local/bin/bazel \
  --target x86_64-unknown-freebsd16.0 --cpu k8 --clang-version 21 --jobs 16 \
  --output /usr/obj/5BSD-otel-validation/integ-bazel-dtrace-r4
```

How each design item was realized:

1. Sources and flags: `bsd_mixed_shared_library` (bsd_generate.bzl) compiles
   the C sources with `bsd_cflags(1, pico=True)` and the C++ sources with
   `bsd_cxxflags(1, "c++20", pico=True)` (Make's CXXFLAGS: CFLAGS minus the
   C-only flags, component CXXFLAGS, `-fno-rtti`, debug flags again, `-std`,
   clang's C++ warning tail). Bazel 5 has one copts list for both languages,
   hence the two compile groups. It links the objects in Make SRCS order with
   `cc_common.link`. The forced `-include .../spl/sys/ccompile.h` is passed
   by its workspace path. `-I${.OBJDIR} -I${.CURDIR}` falls between two
   header bundles (`libdtrace_spl_headers`, `objdir_headers`,
   `libdtrace_headers`), which keeps Make's search order. The c++ link driver
   adds `-lc++ -lm` implicitly; the Bazel link names them, and the probe
   records them as driver-implicit. Exports are unversioned (no
   `VERSION_DEF`); `compare_shared` in elf-artifact-check.py compares SONAME,
   NEEDED, hardening, the dynamic imports and exports (848) with versions,
   version definitions/requirements and sections.
2. Grammar and scanner: `bsd_yacc` runs the staged `tmp/legacy/usr/bin/yacc`
   with Make's YFLAGS (`-d -d`; bsd.lib.mk adds a second `-d`) and declares
   `dt_grammar.c`/`.h`; `bsd_lex` runs the staged `lex`, whose `m4` is found
   only in the staged tool directory (`PATH=gentools`). Parity: `dt_grammar.h`
   is byte-identical to Make's; `dt_grammar.c` and `dt_lex.c` are identical
   after normalizing `#line` paths.
3. Shell generators: `bsd_generate` runs the staged `sh` with
   `stdout_redirect` (now with `-i input` for stdin) for
   `sh mkerrtags.sh < dt_errtags.h > dt_errtags.c` and
   `sh mknames.sh < sys/dtrace.h > dt_names.c`, and `sh mkpriv -o priv.d
   sys/sys/priv.h` directly. The scripts' sed/nawk/awk/cat come from the
   staged tool directory only. All three outputs are byte-identical to
   Make's. The staged tools are `tmp/legacy` of the world: yacc is built by
   buildworld; the others are host tools that buildworld copies there, which
   Make buildenv uses too.
4. DSRCS: `priv.d` is generated and compared; installing the D library files
   waits on the installation adapter, as for every target.
5.–7. MK_CTF, DTRACE_OPTIMIZED, DTRACE_ASAN, DTRACE_BENCHMARKS and
   DTRACE_DEBUG_TSAN are `no` and DTRACE_TARGET_ARCH is empty (checked
   through `make -V` each run; the probe refuses other values because it
   does not model them). The CTF and USDT designs are unchanged and not
   implemented.
8. Qualification results (status passed):
   - all 60 libdtrace objects plus dtrace.o: compile flags and include order
     equal Make's (Make's `-I${.OBJDIR}` is outside the tree and Bazel's twin
     is its bazel-out `-isystem`). Non-debug differences are only
     `.rodata.str1.1`, its relocations and `.symtab` (assert()'s
     `__FILE__`), all proven by `path_string_check`;
   - link options, libraries and object order equal Make; libdtrace NEEDED
     order equal, dtrace(1) NEEDED order differs as for the other programs;
     the relink diagnostic keeps only the string-length shifts;
   - `compare_shared`/`compare_program` metadata equal (SONAME, NEEDED set,
     imports/exports with versions, version requirements, RELRO/NOW, no
     TEXTREL, RPATH or executable stack);
   - negative suite, 30 injections, all observed: C, C++ and header sources;
     the forced include; `libproc_compat.h`; `dis_tables.h`; gmatch.c from
     another `.PATH`; the grammar and scanner (marker in the `%{ %}`
     prologue); both generator scripts (made to emit the marker); both stdin
     generator inputs; `priv.h` and `mkpriv` (priv.d regenerated); the staged
     yacc, lex, m4, sed and nawk (replaced by a failing tool); dtrace.c;
     `dtraced.h`; `dtotel_session.h`; SDK `libproc.h` and `libelf.h`; and the
     SDK link inputs libctf, librtld_db and libxo. Restored outputs are
     byte-identical;
   - 8198 source inputs rechecked unchanged;
   - host usage (SDK libraries via LD_LIBRARY_PATH, host kernel; no DTrace
     device is opened): both builds exit 2 with the same usage text, apart
     from getprogname() (`dtrace` vs Make's `dtrace.full`; normalized for
     later runs).

Two toolchain points were found and fixed. A program that links a
workspace shared library gets Bazel's PIC compile mode, which added
`-fPIC -DPIC` (`bsd_program` now disables the toolchain `pic` flags; Make
uses `-fpie -DPIC` only). Bazel's legacy `runtime_library_search_directories`
feature linked a RUNPATH into `_solib`; the toolchain overrides it with an
empty feature, since Make programs carry no RUNPATH.

Not done: the matching-system VM runtime of the Bazel libdtrace/dtrace(1)
with the DTrace modules preloaded, CTF/USDT, installation, and wiring
dtrace-probe.py into `qualify.py` (it is a standalone probe; bazel-test still
runs only otel-probe.py).

