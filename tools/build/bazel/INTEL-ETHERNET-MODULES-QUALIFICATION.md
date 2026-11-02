# Intel Ethernet module qualification (2026-11-02)

## Source-owned graph and original policies

Seven selected amd64 GENERIC leaves now have native module declarations:
em/if_em, iavf/if_iavf, ice/if_ice, igc/if_igc, ix/if_ix, ixl/if_ixl and ixv/if_ixv.
The source-owned graph contains 118 compiler contexts over 99 physical ordinary
C files and two generated KOBJ schemas, grouped into 70 native object groups.
It uses 73 physical header contexts, reusing 50 exact existing contexts. Original
physical include ordering, generated headers/sources, per-source dependencies,
warnings, typed WERROR and complete OBJS link ordering are declared. No runtime
Make query supplies native compilation. Original ixl EXPORT_SYMS=YES and the
other six EXPORT_SYMS=NO policies remain explicit; all seven use package=kernel.

The two generated interfaces use existing declared KOBJ producers and source
filegroups. The single checked source-path provenance comment is the only
permitted generated-input byte difference. No source/compiler policy or final
artifact rewriting was used to obtain agreement.

## Actual compilation, links and artifacts

Both maintained build-bsd format-5 profiles pass using sixteen logical CPUs, opt
compilation, strip=never and the validated small-PIC SDK. Each independently
records 118 successful uncached compiler actions, 21,775 original Make dependency
occurrences and 21,775 actually consumed native dependency occurrences. Compiler
and source bytes, defines, warnings, semantic code-generation flags, forced-header
order and used physical include-root order pass. Native consumed dependencies
have matching declared input hashes. Each profile retains seven actual ordered
link argument files and object hashes matching complete original Make OBJS order.

All seven plain modules are whole-file byte-identical to untouched Make controls.
CTF/debug modules agree on recorded section inventory, metadata and payload except
GNU build-ID/debuglink values; CTF bytes agree and both original/native split-debug
CRC checks pass. Whole-file debug/DWARF identity is not claimed. Ten plain and
seventeen CTF/debug install records match corrected actual Make installation
metadata, including three relative compatibility aliases.

Six existing provider regression targets pass in each kernel profile; these are
not Intel driver hardware, protocol or loader runtime tests. See
[MODULE-LOADER-EXPORT-CONTRACT.md](MODULE-LOADER-EXPORT-CONTRACT.md) for the
static-export-test boundary and historical loader local-symbol fallback.

## Compatibility aliases and the Make packaging correction

The maintained module artifact helper now accepts default-empty aliases. The
three declarations are em's if_igb.ko/if_igbv.ko and iavf's if_ixlv.ko. Each is a
relative link to its module basename, carrying original root/wheel, 0755 and
package metadata. Both amd64 and cross-architecture macros forward this API;
that forwarding does not qualify ARM64/RISC-V builds.

Configured destination prefixes now apply to install-link destinations using the
same validation as install files. Hardlink target semantics remain unchanged.
Modules and aliases follow the caller's kernel_directory; split-debug files also
retain kernel_debug_directory. No fixed module-directory inventory is introduced.
Actual Make and native alternate-directory controls agree on metadata and targets;
native payload bytes are unchanged from the default layout.

Original em/iavf Make METALOGs exposed empty tags=package= on aliases while their
modules carried package=kernel. sys/conf/kmod.mk now derives default NO_ROOT link
TAGS from KMODTAGS, respecting an already explicit TAGS package. The fourteen
original builds and broken metadata remain untouched. Twenty-four fresh staged
Make installs pass default, alternate-directory, PACKAGE override, KMODTAGS
override and explicit alias-TAGS cases; original captured artifact hashes remain
unchanged. Only the empty alias package tags change in default metadata.

The new Bazel archive fixture checks configured destinations, real archive file
bytes and metadata, and relative symlink resolution (three Python methods). Two
analysis-negative targets reject relative/traversal prefixes. These three targets
pass in a userland profile, respecting the kernel test-provider gate. The legacy
archive remains whole-file identical. All 45 captured target/output bindings
across 27 prior network module/debug/install targets also remain whole-file exact
with default-empty aliases and the updated SDK configuration.

## Instrumentation, evidence and limits

The bounded scan of 99 C files and two schemas records 20 explicit DTrace/SDT/CTR/
audit candidate lines, including comments/macros. Four compiled modules (if_em,
if_ice, if_igc and if_ix) preserve their SDT tracepoint/probe-related sections and
relocations against Make. Source markers and preserved sections do not prove live
probe firing. No probes were added.

Evidence root: `/usr/obj/usr/src/bazel-intel-ethernet-modules-review-r1-20261102/`.
Original controls: `bazel-intel-ethernet-module-make-references-r1-20261102`.
Corrected installs: `bazel-intel-ethernet-module-corrected-installs-r1-20261102`.
Native captures: `bazel-intel-ethernet-modules-{ctf-debug,plain}-native-r1-20261102`.
The root retains source bindings, actual compiler/link witnesses and raw parameter
files, consumed dependency files, artifact/install comparisons, layout regressions,
SDK validation and migration/review drivers. SDK compiler/runtime bytes are
unchanged; its toolchain configuration adds the separately qualified default-off
small-PIC feature. This is not full SDK bootstrap qualification.

The original Make controls retain CPU time, child RSS and block-operation
observations; frontend builds retain free-space guards. These are not controlled
native-versus-Make performance, total-memory or physical disk-I/O benchmarks.
Complete world/rescue/pkgbase/hardware/publication/bootstrap, ARM64/RISC-V/options,
VM/runtime and CPU/memory/disk I/O/cache/sandbox gates remain open. Local BUILD
presence is 550/729 selected amd64 leaves (179 missing), not a qualification
percentage.

The build-bsd C inputs, existing format-5 backend, archive and installation
metadata already carry these products. Maintained rules, tests and manual are
updated in this change; no new CLI, signer, verifier or publication policy is
required. Bundle signing is not verified boot or compromised-root protection.
Make remains production/default; BIP is excluded. No host installation, module
loading, system upgrade or reboot was performed.
