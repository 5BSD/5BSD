# ARM64 and RISC-V shared kernel modules

2026-11-01. This qualifies the real `filemon` module on ARM64 and RISC-V64,
with CTF/debug disabled and enabled. It does not qualify complete kernels,
module collections, loading/unloading, filemon behavior, boot or performance.
Make remains production/default. No OS C source changed or module was loaded.

## Architecture and maintained frontend

amd64 modules use relocatable ELF directly. The maintained Make pipeline for
ARM64 and RISC-V first links a relocatable `.kld`, merges CTF and applies export
policy, then links the shared `.ko` with `-Bshareable -znotext -znorelro`.
The existing declared `bsd_module_link` now supports both explicit stages and
an optional architecture linker script. Its default amd64 argv is preserved.
Architecture linker flags are declared inputs, not ambient shell flags.

The common artifact pipeline is extracted into `kernel_module_artifacts.bzl`;
`amd64_generic_module` keeps its existing signature, labels, output locations,
CTF/export/debug/install policy and default linkage. `cross_generic_module.bzl`
is explicitly instantiated for each supported target; existing amd64-only
module declarations are not silently advertised as cross-compatible.

`sys/dev/filemon` compiles the original source and included `filemon_wrapper.c`
using native rules_cc, actual target GENERIC options/layouts and declared
vnode interfaces. The textual fragment is a compiler input, not another object.
Both new targets use the registered freestanding target toolchain while host
CTF/nm/awk/objcopy/config tools stay in the execution configuration. ARM64 keeps
its fixed-register, branch, stack-guard and no-relax/BTI link policy. RISC-V
uses PIC, the kernel lp64 ABI and maintained ISA/code-model policy.

Use the existing format-5 `target-kind=kernel` inputs through
`build-bsd bazel-test --arch arm64|riscv64`. Explicit module and installation
labels are `//sys/modules/filemon:arm64_generic_module`,
`:arm64_install_manifest`, `:riscv_generic_module` and `:riscv_install_manifest`.
CTF and debug remain the existing typed settings, not a separate build script.
No frontend C, SDK staging, signing or publication changes are needed; the
manual now identifies these actual shared-module consumers.

## Independent Make evidence

Fresh no-debug references are under
`/usr/obj/usr/src/bazel-filemon-cross-make-r2-20261101/`; CTF/debug references are
under `bazel-filemon-cross-make-ctf-20261101` in the same object root.
Commands, generated includes, dependency files, objects, localized `.kld`,
shared `.ko`, split debug files and resource counters are retained. ARCH_FLAGS
is independently queried from the generated kernel Make context and passed to
the module build, just as the parent kernel build propagates it. The earlier
standalone reference without those parent flags is retained but not used for
parity. In particular, ARM64's per-thread stack guard is not discarded to make
a comparison pass.

Isolated installation uses the maintained leaf `install` target with explicit
unprivileged install flags and METALOG, preserving root/wheel ownership metadata.
The first leaf call demonstrated that NO_ROOT alone did not propagate -U into
its INSTALLFLAGS and attempted chown; the failure is retained. Correct staging
uses -U/-M/-D and the normal default module directory. The earlier explicit
/boot/kernel staging remains separate; final comparisons use the matching
/boot/modules default. This stages under /usr/obj and does not install on host.

| Target / options | Module bytes | Comparison |
| --- | ---: | --- |
| ARM64, CTF/debug off | 21,488 | entire file exactly matches Make |
| RISC-V, CTF/debug off | 24,472 | entire file exactly matches Make |
| ARM64, CTF/debug on | 42,256 | every installed ELF section except build-ID/debuglink matches |
| RISC-V, CTF/debug on | 58,784 | every installed ELF section except build-ID/debuglink matches |

All installed CTF, code/data, symbols and relocations match in the enabled
variants. Actual native and Make debuglink CRCs validate against their own
separate debug files. Separate debug files differ in debug_info, debug_line,
debug_str, build-ID and symtab; complete DWARF/symbol-file identity and debugger
path resolution remain open. These differences are not removed from reports.
All six file/debug installation records across the four architecture/option
cases match Make, including destination, ownership, permissions and pkgbase tags.
Directory metadata and linker.hints are not qualified by this file comparison.

Successful native receipts are `bazel-filemon-{arm64,riscv}-r1-20261101` and
`bazel-filemon-{arm64,riscv}-ctf-r1-20261101` below /usr/obj/usr/src.
The exact comparison, raw per-section differences, debug verification and
snapshots are retained at
`/usr/obj/usr/src/bazel-filemon-cross-review-20261101/{review,summary}.json`.
The amd64 regression receipt is `bazel-filemon-amd64-regression-r1-20261101`;
both filemon and firmware are byte-identical to their pre-existing independently
qualified outputs, covering export-NO and export-all branches. The initial filemon batch did not qualify shared export-all. That path now has
actual backlight and firmware consumers with independent comparisons in
[the next cohort](CROSS-FACILITIES-QUALIFICATION.md).

## Cache and failed expectations

Repeating each unchanged no-debug profile produces the exact original manifest
with zero external spawns (`bazel-filemon-{arm64,riscv}-cache-repeat-20261101`).
The earlier `...-cache-20261101` runs came after CTF/debug builds; they reproduced
the same bytes but each executed eight external actions. The original assertion
expecting no rebuilds is retained in initial-cache-expectation.json. Local
configuration-switch reuse, output-directory separation, disk/remote cache,
source-mutation testing and controlled CPU/RAM/disk-I/O comparisons remain open.
No claim is made that switching variants is free or that these counters measure
the full persistent JVM/descendant memory footprint.

The initial helper extraction also put a load after a Starlark assignment;
normal analysis rejected it (including fstyp r1), and the load was corrected.
No failed run was replaced with a success record or execution-policy exception.

## Next qualification

Extend declared real module bodies to additional selected drivers/facilities,
preserve their architecture and export/CTF/debug/install choices, and compare
actual Make products. Qualify shared export-all, prefixes and other module
options as consumers require them. Complete kernel/world/pkgbase products,
matching-kernel VM module loading/unloading and filemon read/write/exec/fork/
exit records, live tracing/audit and performance remain required. BIP is out.
