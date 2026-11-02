# Network, routing and entropy module qualification

## Scope (November 2, 2026)

37 selected amd64 GENERIC module leaves, 188 C compiler contexts over 186
physical C sources, 124 source-owned object groups, 230 physical header contexts
(91 exact existing context reuses), plus two root-owned physical header namespace
views. Modules:

dpdk_lpm4, dpdk_lpm6, dummymbuf, e6000sw, ena, enic, fib_dxr, gve, if_geneve, if_ovpn, if_tuntap, if_vether, if_vxlan, if_wg, ip6_mroute_mod, ip_mroute_mod, ipsec, khelp/h_ertt, mana, mgb, my, netlink, oce, qlxgb, qlxgbe, qlxge, random_fortuna, random_other, rdrand_rng, rdseed_rng, s3, sctp, send, sfxge, siftr, sume, wtap

Both maintained build-bsd format-5 profiles pass with 16 logical CPUs and disk
reserve guards. These are real module builds and artifact checks; modules were
not loaded and devices/network services were not exercised on the host or a VM.
Make remains production/default. No BIP work is included.

## Independent controls and compiler inputs

All 74 original Make controls (37 plain and 37 CTF/debug) build and install into
isolated object/stage directories under /usr/obj. The corrected controls query
the selected kernel's actual SYSDIR and supply it before module parsing, with
MODULE_TIED and inherited parent exports. The rejected first controls remain
recorded: six early source-lookup failures from omitted SYSDIR were control
errors, not module-source defects. See [inventory context](MODULE-INVENTORY-CONTEXT.md).
All 280 consumed option-header occurrences match the selected kernel bytes.

Each native profile has 188 actual successful uncached compiler witnesses.
Compiler executable/source hashes, definitions, semantic flags, warning order,
forced headers and physical include order match the original recorded commands.
Every original dependency is bound to a declared native input digest. The native
compiler's actual .d files are retained: all 188 per-context consumed basename/
content-hash multisets reconcile exactly, 32,362 occurrences on each side, in
each profile. Generated KOBJ headers differ only the previously checked exact
source-path provenance comment; raw hashes and exact transformations remain
recorded. A wtap dependency uses ../ in its spelling: lexical normalization is
accepted only after proving the same resolved physical object and exact declared
input hash. No dependency is omitted.

Actual initial-link parameter files are retained and digest-checked for all 37
modules in each profile. Netlink's original nested route/*.o paths are recorded
from the actual metadata TARGET and compiler output/dependency arguments; the
native initial-link order uses their unique basenames without losing order.

## Corrections established by rejected comparisons

The first native CTF/debug build failed on ENA's ena-com include namespace.
Original Make supplies -I sys/contrib before the general kernel include root.
Two root-owned source-header providers now expose precisely declared physical
headers with that original namespace; physical owning packages grant narrow
file visibility. Driver sources and production include directives are unchanged.
No broad filesystem access, undeclared include root or copied header tree was
introduced. The original failed build remains retained.

The next native build passed, but strict artifact comparison rejected netlink's
CTF. ctfmerge sorts complete input paths: basename-only staging lost the original
route/ prefix and changed type merge order. The native CTF merge rule now accepts
optional explicit relative object paths corresponding to the complete ordered
inventory. Paths must be unique, safe, complete and match each object's basename;
validation applies even with CTF disabled. Netlink declares its actual original
paths. Default staging is unchanged: 108 module/debug/install outputs for the
other 36 modules are byte-identical before/after this helper correction.

Four maintained tests exercise the actual merge rule's rejection of traversal,
incomplete mapping, duplicates and basename mismatch. All pass, as does the
existing executable CTF regression. This is an ordinary declared rule input,
not an artifact rewrite or a verifier exception.

## Artifact, installation and observability results

All 37 plain module ELF files are whole-file byte-identical to untouched original
Make artifacts. All 37 CTF/debug module section inventories/payloads match Make
except build-id/debuglink fields; CTF itself is exact. Native and original debug
CRCs validate. All 74 CTF/debug installation records and 37 plain records match
original owner, group, mode, destination, type and package/debug tags.

A bounded scan of 186 physical sources records 160 DTrace/SDT/KTR/audit candidate
lines (including macros/comments). All 22 modules with compiled SDT/DTrace
sections preserve their sections and relocations exactly. This does not establish
live events, audit completeness or instrumentation absence in other modules.

## Evidence and integration

- Original controls: /usr/obj/usr/src/bazel-network-services-module-make-references-r2-20261102
- Native CTF/debug: /usr/obj/usr/src/bazel-network-services-modules-ctf-debug-native-r3-20261102
- Native plain: /usr/obj/usr/src/bazel-network-services-modules-plain-native-r1-20261102
- CTF rule tests: /usr/obj/usr/src/bazel-network-services-ctf-path-tests-native-r1-20261102
- Compiler/link/artifact/install/dependency/instrumentation review: /usr/obj/usr/src/bazel-network-services-modules-review-r1-20261102
- Migration declarations and hash manifest: /tmp/network-services-module-stage-r3-20261102

Compiler evidence binds the initial and corrected ENA runs; the final CTF run
changes only merge path staging, not compiler actions. Failed runs and strict
comparison failures are retained. Neither controlled CPU/memory/disk I/O
benchmarking nor cache/sandbox qualification is inferred from build timing.

Frontend review: the normal build-bsd bazel-test/backend, existing format-5 inputs
and SDK are used. Optional CTF sort paths are native rule metadata; no new CLI,
manual option, stage/signing/publication policy or C frontend change is required.
No host install, upgrade, reboot or module loading occurred. Source declarations
now cover 665 of 729 selected amd64 leaves (64 remain); this is BUILD presence,
not a percentage of full-system qualification. ARM64/RISC-V conversion/builds,
current full GENERIC kernel refresh, world/rescue/libraries/options, pkgbase,
hardware/publication/bootstrap and VM/runtime/performance gates remain open.
