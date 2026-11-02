# Atheros alternate rate-control source fixes

## Scope (2026-11-02)

Original Make ATH_RATE=onoe and ATH_RATE=amrr module builds failed before
native Bazel conversion. Both algorithms used MALLOC_DECLARE without including
sys/malloc.h and declared the public ath_rate_fetch_node_stats interface static.
AMRR additionally lacked net/ethernet.h and assigned -1 to output pointers rather
than their pointed-to values in ath_rate_findrate. The fixes include the defining
headers, match the public interface linkage, and write the two return values as
ONOe/sample and the interface contract require. No compiler diagnostics were
suppressed and no forced header or Make recipe workaround was added.

## Evidence

Under /usr/obj/usr/src, bazel-ath-module-make-references-r1-20261102 preserves
20 successful default-family controls and the four alternate-algorithm compiler
failures. bazel-ath-module-make-references-r2-20261102 records 24 successful
original Make build/install controls: ten default modules in plain and CTF/debug
profiles plus ONOe and AMRR in both profiles. These isolated controls use original
source recipes and standard source-built compiler tools; their stages do not
install onto the host. The default rate algorithm remains sample.

These are source correctness and compilation checks, not wireless runtime or
loadable-module dependency qualification. Radio behavior and alternative rate
selection at runtime remain open. Native Bazel parity is a separate requirement.

## Frontend review

No build input, CLI, staging, signing, verification, packaging or publication
contract changes. Maintained build-bsd and Make recipes consume the corrected
sources without a new frontend option. Make remains production/default; BIP is
excluded.
