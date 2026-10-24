# Bazel qualification

Bazel is experimental. `build-bsd` continues to accept only `bsd-make`;
there is no world, kernel, package, or image Bazel backend yet. Do not use
imported upstream BUILD files as evidence of BSD build coverage.

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

On 2026-10-24, the selected custom port `/usr/obj/5BSD-ports/devel/bazel`
defines 6.2.0_2, while the installed executable reports 5.4.1. These are different
inputs. Qualify the built port separately before selecting a supported version.
The port identifies Apache 2.0 licensing and OpenJDK 11 as a build dependency.
The same custom tree also supplies `bazel5` 5.4.1_2, `bazel7` 7.7.1,
`bazel8` 8.8.0 and `bazel9` 9.2.0_4. The newer ports require OpenJDK 21.
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

The checkout path is a command input. The example candidate pins Bazel 9.2.0_4
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
This experimental configuration remains private to the pilot. The earlier trial
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
