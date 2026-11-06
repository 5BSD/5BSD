# Original dynamic dependency sets and order

## Corrections and passed checks (2026-11-06)

The four observed dependency mismatches are corrected in source-owned Bazel rules:

- libpowercmp and libtimecmp remove an extra direct libthr dependency from their
  component and shared-library declarations. Original Make names service, FIDL
  and C++ dependencies; thread support remains through their actual dependency
  graph. No as-needed filtering or post-link editing is introduced.
- libnotify declares its direct thread library after its service/FIDL/C++ ABI
  dependencies, matching the actual original Make link command and ELF order.
- sysdecode's test uses original ATF-before-sysdecode-before-libc ABI precedence,
  with native libc/libsys execution and the exact stripped installed body.

All four complete parent constructions pass through normal build-bsd format-5
requests. All four original ELF dependency set/order gaps now match actual Make
artifacts, including imports/exports/version/hardening contracts. Complete original
installation comparison matches 185 component paths and 41 component directory
claims, with exact non-ELF contents and no metadata/link conflicts.

Four library and eight program ELF contracts pass; two untraced archive member/
symbol comparisons pass. Raw timecmp/notify DTrace symbol differences are retained
as separate failed strict comparisons. Their exact static archive bytes are
unchanged from the earlier actual-member DOF/order qualification. The powercmp
and sysdecode static archives also remain byte-identical to their prior captures.
All 24 native/original ELF debug separation/name/CRC checks pass.

The single original sysdecode cap_rights body passes, with no skip. Exact original/
native registration metadata and body hash match the captured installed program.
Loader traces resolve exactly native sysdecode/ATF/libc/libsys. Its production tar
is unchanged. This body checks rights formatting, not kernel policy enforcement.
Functional ATF execution explicitly disables DOF initialization; live tracing and
the other three production service APIs remain unqualified by this cohort.

The recorded warm build creates 2,355 actions and executes 56, including one
CppCompile action. These are observed BEP counters, not controlled incremental,
cache, CPU/RAM/disk-I/O/footprint performance qualification.

## Evidence and integration

All directories are under /usr/obj/usr/src:

- bazel-library-dynamic-dependency-request-r1-20261106: explicit complete parents,
  native runtime/body targets and existing format-5 settings.
- bazel-library-dynamic-dependency-native-r1-20261106: passed normal frontend,
  immutable artifacts, original body report, BEP metrics and source helper.
- bazel-library-dynamic-dependency-review-r1-20261106: each original installation
  and binary report; the two unchanged raw DTrace differences remain recorded.
- bazel-sysdecode-installed-native-abi-final-review-r2-20261106: exact original
  metadata/body/native runtime/production/debug controls. The earlier diagnostic
  selected the wrong SONAME and is retained in its r1 directory; r2 uses the actual
  declared libsysdecode.so.5. No source artifact was altered to resolve that error.
- bazel-library-dynamic-dependency-final-review-r1-20261106: every checked dependency
  order, unchanged object archive hash, all debug checks and bound build metrics.

Existing native cc_library/cc_shared_library declarations and ABI consumer/link
interfaces suffice. No C/frontend/backend/signing option changes are needed;
the manual records the existing API and this bounded result. Make remains the
production default, BIP stays excluded, and full-library generation/directory,
whole world/kernel/modules/pkgbase, normal-service VM, ARM64/RISC-V, bootstrap,
cache/sandbox/reproducibility/performance and combined publication gates remain.
