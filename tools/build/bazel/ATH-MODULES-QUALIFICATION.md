# Atheros loadable module qualification

## Scope (2026-11-02)

Ten amd64 GENERIC module leaves now use native declared compile/CTF/link/export/
debug/install actions: if_ath (directory ath), ath_dfs, ath_hal, ath_hal_ar5210,
ath_hal_ar5211, ath_hal_ar5212, ath_hal_ar5416, ath_hal_ar9300, ath_main and
ath_rate. The default sample profile compiles 138 sources. Onoe and AMRR add two
alternative rate-control sources. Only the selected rate algorithm enters the
module. Original Make references are migration oracles, never runtime graph
inputs or a fallback build backend.

The 112 distinct physical header contexts reuse 79 exact existing providers;
33 new contexts declare the actual prerequisites. Consumer visibility is extended
only where required. Existing config(8)/KOBJ/offset/vnode producers supply the
generated headers. Warning exceptions follow the actual per-file Make recipes.
Groups share an action only when source ownership, header and warning contracts
and membership in selected modules/profiles agree; unrelated module sources do
not enter the same object collection.

## Object ordering and source corrections

The shared module API accepts an optional complete object_order basename list.
It rejects duplicate names, ambiguous basenames, paths, missing objects and extra
names. Initial link and CTF stages use the reconciled list. Existing callers keep
their prior order when the list is absent. All ten new modules explicitly retain
Make's OBJS order, even when compiler contexts span multiple groups/packages.
Six native Bazel tests cover the default and selected order and rejection cases.
This is a declared Bazel graph, not a shell link wrapper or imported object list.

Original Make controls exposed real Onoe/AMRR source defects and an ath_hal
Makefile export declaration placed after conditional rules had already parsed.
See [ATH-RATE-SOURCE-QUALIFICATION.md](ATH-RATE-SOURCE-QUALIFICATION.md) for the
separately committed fixes. HAL intentionally exports all symbols; the other
nine modules preserve their existing empty export lists. Build parity does not
prove that those existing policies provide complete load-time dependency closure.

## Evidence

All paths below are under /usr/obj/usr/src.

- bazel-ath-module-source-facts-r1-20261102 retains original selected source,
  object order and final variable queries. Final variable values alone did not
  reveal the HAL conditional-rule problem; actual recipes were inspected.
- bazel-ath-module-make-references-r1-20261102 retains four alternate algorithm
  compiler failures; r2 records 24 passing original Make build/install controls.
  bazel-ath-hal-make-references-r3-20261102 supplies the two corrected HAL controls.
- bazel-ath-modules-ctf-native-r1-20261102 records the normal frontend native
  default CTF/debug build and immutable artifacts. The sample-plain-native-r1
  sibling qualifies the default plain profile. onoe/amrr each have ctf-debug
  and plain native-r1 siblings. All six normal frontend runs passed.
- bazel-ath-modules-review-r1-20261102 retains strict comparisons: all ten default
  plain module files and both alternate plain files equal Make byte for byte.
  All twelve CTF/debug runtime section inventories, metadata and bytes agree
  except GNU build-ID and debug-link values; CTF bytes agree exactly. All native
  and Make debug-link CRC checks pass. The six profiles match 36 install records
  (owners, groups, modes, paths and package/debug tags).
- The same review binds 138 actual default compiler actions to source/compiler
  hashes, warnings, defines, code-generation settings and 15,162 original Make
  dependency occurrences. Onoe and AMRR actual compiler actions each pass a
  further 196 dependency checks. Generated KOBJ headers differ only by the exact
  checked provenance-comment source path. These are dependency-file checks, not
  complete dynamic filesystem discovery.
- actual-link-order.json verifies ten actual initial linker inventories/orders
  and object hashes. After later profiles replaced response files, their original
  bytes were recovered using recorded source-object paths and the original OBJS
  list only when the complete bytes reproduced the execution log's SHA-256.
  Unmatched current files were rejected. Retained response files are evidence;
  no module artifacts or production action inputs were rewritten.
- bazel-object-order-tests-native-r1-20261102 records the six passing registered
  Bazel tests. preparation/ and retained review scripts preserve migration facts.

Whole debug-file bytes are not equal or claimed equal. Full module loading,
wireless behavior, kernel package completeness and performance are not established.

## Maintained frontend and remaining gates

The existing build-bsd format-5 targets/build-settings interface supplies SDK,
platform, CTF/debug policy and all 16 workers. The maintained manual documents
//tools/build/bazel/config:ath_rate_algorithm, a typed sample/onoe/amrr choice
for the native loadable rate module. Invalid choices are rejected by the native
setting rule. This does not change built-in KERNCONF rate selection. No new C
frontend flag, signing, stage or publication policy is needed for these source
rules. Make remains production/default and BIP remains excluded.

Attach/detach, dependency loading, association/authentication, calibration,
rate-control transitions, Tx/Rx, power saving and error recovery need suitable
radio/runtime qualification. The scoped call-shaped observability scan found
three CTR-family calls in if_ath.c and no matching dedicated calls in the other
139 files; shared framework coverage may still apply. Probe/audit runtime delivery
was not exercised. Full module closure, other KERNCONF/architectures, world,
pkgbase/hardware publication, bootstrap, VM tests and controlled CPU/memory/disk
I/O/disk-use/cache/sandbox performance gates remain open. No host installation,
upgrade, module loading or reboot occurred.
