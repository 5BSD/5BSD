# OpenSSL crypto kernel module qualification (November 2, 2026)

The selected amd64 GENERIC ossl module now uses native source-owned declarations
and existing module rules. Nineteen original object contexts comprise ten C
sources and nine checked-in preprocessed assembly sources. These are source
inputs, not assumed Perl generator outputs. Their original ordinary CTF
conversion policy is preserved; the EFI/SGX custom-assembly exception does not
apply. Original export stripping, object order and kernel package identity
remain explicit. Five source declaration files change; no C, original Make,
shared-rule or compiler/toolchain policy changes are needed.

Both native profiles pass through maintained build-bsd bazel-test with normal
format-5 inputs, all sixteen logical CPUs and disk reserve guards (exit zero).
Both independently retained actual compiler reviews pass nineteen contexts,
821 consumed prerequisite occurrences on each side, and nineteen selected
kernel option-header occurrences. Source/compiler bytes, macros, warnings,
code-generation options, forced includes, consumed physical header namespaces
and generated-input bytes are checked. Exact per-context basename/content
multisets and complete ordered compiler/CTF-to-link producer identities match
the original controls. Actual dependency and link parameter files were retained
before profile changes; witnesses come from each successful profile's own log.

The complete installed plain module is byte-for-byte identical to original
Make. Installed CTF/runtime sections match except for build ID and debug-link
metadata; both debug-link CRCs verify. The original/native installation manifests
match in each profile. Six existing provider regression tests pass in each
profile; these are shared-rule regression checks, not crypto execution tests.

A bounded nineteen-source scan records no direct SDT/DTrace/KTR/audit candidate
lines under its retained patterns, and neither compiled module inventory has
SDT/DTrace sections. This does not establish inherited instrumentation absence
or audit completeness. No probe is added or removed.

Evidence is retained under /usr/obj/usr/src/bazel-ossl-module-review-r1-20261102,
including actual compilers, consumed dependency files, full link parameters,
option/dependency reconciliations, artifact/install comparisons and source
bindings. Native profiles are bazel-ossl-module-{plain,ctf-debug}-native-r1-20261102;
original controls are bazel-final-module-make-references-r1-20261102.

This is one selected module/configuration. Separate DWARF/source lookup,
cryptographic runtime/CPU dispatch, alternative configurations, other targets,
complete world/kernel/pkgbase/bootstrap/cache/runtime/performance qualification
remain open. The existing generic frontend handles these targets without a new
build-bsd.c input or manual option. Make stays production/default. BIP stays
excluded; no host installation or module loading was performed.
