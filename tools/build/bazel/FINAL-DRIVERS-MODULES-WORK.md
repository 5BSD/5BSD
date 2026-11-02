# Remaining driver/module migration work (November 2, 2026)

## Qualified cohort and remaining work

All 42 original Make controls pass: plain and CTF/debug variants of all 21
remaining selected amd64 module directories. They are private build/install
stages, not host installations. Actual recipes, object order, dependencies,
artifacts, installation METALOGs and command/resource logs are retained under
/usr/obj/usr/src/bazel-final-module-make-references-r1-20261102. Disk guard exit0;
no original failures. No native parity follows from original controls alone.

Native declarations are now applied for eighteen of these directories:

efirt, iwlwifi, iwm, iwn, iwx, otus, padlock, qat/qat, qat/qat_api, qat/qat_common, qat/qat_hw, qat_c2xxx, rtw88, rtw89, rtwn, rtwn_pci, rtwn_usb, sgx

The batch has 455 compiler contexts in 434 source-owned groups and 603 physical
header contexts (45 exact existing reuses). The declarations use existing native
helpers. Repeated object basenames in Intel wireless and QAT are distinct
one-object labels in explicit original order; no renamed/copy object workaround
or basename guess is used. Existing CTF source-relative path inputs preserve
original nested-path sorting. EFI/SGX custom assembly skips CTF conversion exactly
as the original recipes do and depends on the existing native assym producer.
USB device IDs also use the maintained native generator. RTWN has its original
module-owned option producer, with typed sourceless_ucode input rather than
substituting the empty kernel option header. Normal format-5 frontend settings
carry that boolean; the maintained manual is updated in the same change.

The native CTF/debug profile now passes for all eighteen modules, including six
existing provider regression tests. The installed runtime ELF sections and CTF
match the original controls except for build ID and debug-link metadata; both
native and original debug-link CRCs verify. All 36 installation records match.
This does not establish separate DWARF equality or debugger source lookup.

The input review covers all 455 compilation contexts and 159,574 consumed
prerequisite occurrences on each side, with exact per-context basename/content
multisets. Actual source identities, compiler bytes, macros, warnings, code
options, forced-header order, and consumed physical-header namespace precedence
are checked independently. Unused include roots are retained in the report;
the review does not claim all unused search paths are identical. Of 926 consumed
option-header occurrences, 101 use the original RTWN module-owned option recipe;
the others match the selected kernel headers. Complete link order is bound
through actual compiler/CTF output hashes to original source/object identities,
including repeated basenames.

Two failed native attempts are retained. The first exposed Bourne tokenization
of quoted macro values; 194 new source groups now pass those values through the
existing compiler-options interface with shell quoting. The second exposed ten
missing physical-header namespace contexts. Precise consumed-header providers
and the original include-root order correct these contexts without copying
headers or adding broad search roots. No C source, shared rule, or original Make
recipe was changed for these corrections. The passing review uses actual valid
witnesses from three attempts (7, 154 and 294 contexts respectively); cached
reuse is not described as a fresh execution. An observer correction excludes
the main source itself when identifying consumed-header namespace requirements.

Evidence is retained under
/usr/obj/usr/src/bazel-final-drivers-modules-review-r1-20261102, including failed
compiler actions, correction hashes, actual dependency files, link parameters,
source bindings and per-context reconciliations. The successful native build is
bazel-final-drivers-modules-ctf-debug-native-r3-20261102. The plain native build
bazel-final-drivers-modules-plain-native-r1-20261102 also passes: all eighteen
complete installed module files are byte-for-byte identical to their original
Make controls, and all installation records match. Its independent 455-context
review reconciles 159,574 consumed occurrences on each side, 926 option-header
occurrences and all eighteen complete ordered link identities. All plain
compiler witnesses come from this successful execution log; raw dependency files
and link parameters were captured before the next profile change.

A bounded scan of 453 distinct source/schema inputs records sixteen candidate
SDT/DTrace/KTR/audit lines, including comments and macros. Three modules have
compiled SDT/DTrace sections; their payloads and relocations match the originals.
This is preservation evidence, not live-event or audit-completeness qualification.
Both alternate RTWN profiles also pass against six independent original
controls with MK_SOURCELESS_UCODE=no. Each native profile has 101 actual
compiler contexts, 18,093 consumed occurrences and 296 option-header occurrences;
all three link orders and installation manifests match. All three complete plain
modules are byte-identical to their alternate controls; CTF/runtime sections
match with the same explicit build-ID/debug-link exception and verified CRCs.
The default/alternate transition changes the consumed opt_rtwn.h in every
context and changes .text in all three modules. All 101 alternate CTF compiler
witnesses are actual executions, with no reported cache hits. Some unchanged
CTF conversion outputs are reused; their link identities are traced through
retained successful prior actions with exact current compiler-input/output
hashes. The initial current-log-only observer failure is retained. This does
not establish general incremental/cache correctness or live firmware behavior.
Evidence: bazel-rtwn-no-ucode-modules-review-r1-20261102, including option-transition,
per-profile dependency, option, complete-link and artifact/install reviews.
At this cohort checkpoint local presence was 726/729 selected amd64 directories; the previous committed
cohort checkpoint was 708/729. Neither is full-system qualification.
OpenSSL crypto is now separately qualified in
[its module record](OSSL-MODULE-QUALIFICATION.md), bringing current local
presence to 727/729 at that checkpoint. VMM is now separately qualified in
[its module/layout record](VMM-MODULE-QUALIFICATION.md), bringing current local
presence to 728/729 at that checkpoint. Linux64 now separately passes its
[module/generated-input qualification](LINUX64-MODULE-QUALIFICATION.md), bringing
local declaration presence to all 729 selected amd64 directories. Full current
kernel/module aggregation, other configurations/targets and system gates remain
open; this is not full-system completion.

Both native profiles and RTWN alternatives used maintained build-bsd format-5
inputs, all sixteen logical CPUs and disk reserve guards, all exiting zero.
Existing provider regression tests pass; their scope is rule regression, not
hardware runtime. The generic frontend already carries typed settings, so no
build-bsd.c or shared-rule change is needed for this cohort. The new flag and
module-owned producer are documented in the maintained manual. Keep
separate DWARF/source lookup limitations explicit as described in
[MODULE-DEBUG-QUALIFICATION.md](MODULE-DEBUG-QUALIFICATION.md). Full world/kernel/
architecture/pkgbase/bootstrap/publication/runtime/performance gates remain
open. Make stays production/default; BIP is excluded. No host installation,
upgrade, reboot or module loading is authorized by these builds.
