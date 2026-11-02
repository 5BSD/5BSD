# Chelsio module qualification

## Scope (November 2, 2026)

Eleven selected amd64 GENERIC leaves, 50 compiler contexts over 48 physical C
sources and two KOBJ interface schemas, 46 source-owned object groups and 102
physical header contexts (38 exact existing reuses). Modules:

cxgbe/ccr, cxgbe/cxgbei, cxgbe/if_cc, cxgbe/if_ccv, cxgbe/if_cxgbe, cxgbe/if_cxgbev, cxgbe/if_cxl, cxgbe/if_cxlv, cxgbe/iw_cxgbe, cxgbe/nvmf_che, cxgbe/tom

Both maintained build-bsd plain and CTF/debug profiles pass with 16 logical CPUs
and disk reserve guards. Make remains production/default; BIP is excluded.
These are module build/artifact checks. No driver or hardware behavior, live
probe delivery, VM boot or host module loading is established.

## Inputs, artifacts and installation

All 22 original Make controls build and install in private /usr/obj directories,
with the actual kernel SYSDIR, tied-kernel context and inherited option exports.
The source-owned native rules preserve selected TLS, crypto, RDMA and storage
offload source lists, definitions, warning policy, generated interfaces and
ordered LinuxKPI/OFED roots. Existing maintained module helpers are unchanged.
No runtime C source, original Makefile or export policy was altered.

Each profile has 50 actual successful compiler witnesses. Their compiler/source
hashes, semantic flags, defines, warning order, forced headers and physical
include order match original Make. Every original dependency binds to a native
action input; actual native .d files are retained. All 50 per-context consumed
basename/content-hash multisets match exactly: 11,730 original/native dependency
occurrences per profile, without extra or missing occurrences. Generated KOBJ
provenance comments have only the exact previously checked schema-path spelling
change; raw hashes and transformations are retained.

All eleven initial-link parameter files per profile are captured and digest-
checked against actual actions, and every original object order matches.
All eleven plain module ELF files are whole-file byte-identical to untouched
original Make files. All eleven CTF/debug inventories and payloads, including
CTF itself, match except build-id/debuglink fields; original and native debug
CRCs validate. All 22 CTF/debug and 11 plain installation records match original
destination, type, owner/group/mode and package/debug tags. No separate filename
control or artifact rewrite is used in this cohort.

A bounded scan of 50 physical C/schema inputs records 448 candidate SDT/DTrace/
KTR/audit lines, including comments/macros. Four modules contain compiled SDT/
DTrace sections; all their section payloads and relocations match Make. This is
not a claim of audit completeness or instrumentation absence elsewhere.

## Supplementary option audit correction

The initial separate option observer was wrong: it treated source directories
as KMOD output names and globbed .depend files, including genoffset host-helper
inputs. For this nested cohort it initially visited no module objects. That
vacuous result was rejected. The corrected audit obtains the complete object
inventory from the original facts, resolves directory to KMOD, requires each
actual metadata TARGET and compiler -MF dependency file, and requires the forced
global option header. Missing coverage fails instead of being silently skipped.

The complete Chelsio audit covers all 50 objects and 127 option-header occurrences,
all exact selected-kernel bytes. Its count independently matches the complete
compiler-input review. Rechecks of the preceding network and RDMA cohorts cover
188/206 objects and respectively 365/554 option occurrences; these agree with
their already complete compiler-input audits. Historical supplementary counts
280/561 are corrected in their docs. Retained correction diagnostics reproduce
the exact old counts and identify skipped directory mappings and extra genoffset
files. These corrections change no native artifact or full compiler-input result.

## Evidence and integration review

- Original controls: /usr/obj/usr/src/bazel-chelsio-module-make-references-r1-20261102
- Native CTF/debug: /usr/obj/usr/src/bazel-chelsio-modules-ctf-debug-native-r1-20261102
- Native plain: /usr/obj/usr/src/bazel-chelsio-modules-plain-native-r1-20261102
- Compiler/link/installation/instrumentation review: /usr/obj/usr/src/bazel-chelsio-modules-review-r1-20261102
- Earlier option-audit corrections: option-audit-correction.json in the network-services and rdma module review directories

The normal build-bsd bazel-test/backend, existing format-5 inputs and frozen SDK
are used. No CLI/manual option, C frontend, signing, staging or publication
policy change is required; this is native source/dependency declaration work.
No controlled CPU/memory/disk-I/O/cache/sandbox benchmark is inferred from these
build timings. No host install, upgrade, reboot or module loading occurred.

Local BUILD presence is 690 of 729 selected amd64 leaves (39 remain). This is
source declaration presence, not a full-system qualification percentage.
Remaining gates include all selected modules/configurations/architectures,
current full kernel refresh, world/rescue/libraries, installation/pkgbase,
bootstrap/hardware/publication, VM/runtime and performance qualification.
