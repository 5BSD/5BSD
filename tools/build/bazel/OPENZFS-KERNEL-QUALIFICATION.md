# OpenZFS built-in kernel qualification

## Scope (2026-11-02)

237 selected OpenZFS sources have native amd64 GENERIC built-in object rules:
232 C and five assembly sources, covering SPL, ZFS, Lua, nvpair, zcommon, AVL,
compression and selected crypto implementations. All five assembly reference
objects contain CTF; the native graph preserves that policy. No production
source, filesystem behavior, CPU dispatch or runtime security policy changed.

The existing OpenZFS package owns its sources and 244 distinct physical header
contexts across existing owners. Compatibility overlays precede ordinary BSD
headers in maintained Make order. Source-owned providers expose only used roots;
unused directories absent from a sandbox are omitted, not fabricated. Toolchain
SIMD definitions follow maintained kern.pre.mk's amd64 policy, not host runtime
CPU observations. Other architectures/toolchains remain separate qualification.

The shared amd64 kernel macro gains optional early_deps and pre_copts, preserving
its existing defaults. This expresses header overlays and forced-include ordering
through native dependency/compile inputs. simd_config.h and static_ccompile.h
precede opt_global.h, then SPL ccompile.h follows. Per-source RPC/config and warning
exceptions remain explicit. No Make query or generated-header import runs during
native compilation. Config, offset, vnode and bus/device interfaces reuse native
producers. Actual warnings, definitions and forced includes match maintained recipes.

The normal build-bsd bazel-test format-5 interface supplies SDK, kernel platform,
CTF/debug settings, compact logs and all 16 workers. This graph/helper extension
needs no additional frontend C/backend API, user configuration option, manual CLI,
signing/verification/staging or package-policy change. Make remains production
and default; BIP remains excluded.

## Evidence and corrections

All paths below are under /usr/obj/usr/src.

- bazel-kernel-openzfs-make-metadata-r1-20261102 captures actual maintained recipes
  with filemon disabled. All 237 completed-kernel reference object hashes stay
  unchanged; selected source hashes match the independent inventory. The capture
  does not establish a complete dynamic dependency trace or performance baseline.
- Native r1 retains a failed declaration that incorrectly coupled two independent
  per-file exceptions. The corrected r2 retains HAVE_RPC_TYPES only for nvpair.c
  and the extra forced zfs_config.h only for sysctl_os.c. Neither feature settings,
  warning checks nor production sources were changed to bypass that failure.
- bazel-kernel-openzfs-amd64-ctf-r2-20261102 is the successful final frontend build,
  with immutable captures and compact logs. Hash-matching successful execution
  records from r1/r2 provide 237 cacheHit=false compiler actions and CTF provenance.
  Only final-policy actions whose output hashes bind to final captures are accepted.
- bazel-kernel-openzfs-review-r1-20261102 binds 65,092 physical and 1,095 generated
  prerequisites. Warnings/order, defines including intentional duplicates,
  code-generation option sets, stack protection, final debug switch, language and
  all forced includes match Make. Actual compiler actions independently prove
  every used overlay root precedes ordinary sys headers in maintained order.

All 237 .text and .SUNW_ctf sections match byte for byte. Allocated payloads/layout
match except 234 exact known-source filename spellings. All other strings and
119,118 nondebug relocations compare symbolically. No artifact is rewritten.
Complete DWARF, string-table or symbol-index byte equality is not claimed.

### CTF checker boundary

The unchanged standalone CTF artifact checker initially rejects spl_taskq.o:
it treats the physical address of an untyped string literal as part of symbol
identity, even though a shorter diagnostic filename shifts that literal and CTF
bytes remain identical. That rejected result is retained in ctf-semantic-r1.
The standalone checker was not weakened or reported as passing this cohort.

The additional read-only ctf-semantic-r2 review compares all 237 identical CTF
payloads with the unchanged graph comparator. Typed symbol identities stay strict.
Only string-section object associations with CTF type zero represent their
addresses by the complete verified canonical string plus interior offset. Names,
bindings, visibility, sections, types and all other identities remain unchanged.
A changed filename symbol must cover exactly the original full literal; its
canonical size follows the verified filename. Ambiguity fails. Complete string
pools must match except independently listed physical source filenames. All
normalizations and original identities remain recorded. Separate required full
allocated-layout and nondebug-relocation reviews bind the same original hashes.
This is a bounded qualification comparison, not an exception in runtime policy
or a general relaxation of CTF/type compatibility.

Upstream compact-log reconstruction verifies all 189 converter bindings before/
after, preserving commands, log hashes and exit status. Expanded JSON is streamed.
Source/profile/review hashes and the failed declaration/correction are retained.
ELF inspections read original bytes without modifying the evidence.

### Shared rule and coverage

Final query r21 passes for 1,061 known groups and 1,236 compiler actions. All 824
previous groups retain identical configured arguments/output paths for their
999 compiler actions after the additive shared macro change. This is configured
compatibility evidence, not a fresh compilation of those previous groups.

Reconciliation r16 finds 1,227 source matches, two object-name and four generated-
name matches, with 1,233 unmatched among 2,466 Make final link products. Three
auxiliary generator objects remain separate. Counts cover the known amd64 graph,
not a complete linked kernel or all-architecture compiled coverage.

## Observability and remaining gates

The bounded call-shaped scan finds existing tracing/CTR/audit-family markers in
21 selected sources, including SPL DTrace, ARC/DBUF/DMU, ZFS vnode and worker paths.
No probe plumbing changed. Absence of matches in 216 sources is not evidence of
missing shared hooks or absence of other instrumentation mechanisms.

tests=[] does not exercise a live filesystem. Pool import/export, data integrity,
ZIL/sync, snapshots/clones, receive/send, error recovery and workload/performance
qualification remain open. The recorded 2026-10-03 ZFS/filedesc WITNESS lock-order
reversal was consulted; its captured trace is not diagnosed or fixed by this
build conversion. No host pool or installation was altered.

Complete native kernel link/order/identity/post-processing/install, loadable
modules, alternate KERNCONF, ARM64/RISC-V64, world/pkgbase/hardware publication,
bootstrap and runtime/VM checks remain open. Disk-reserve checks pass, while
controlled CPU/memory/disk I/O/disk-use/cache comparisons remain open. No host
installation, upgrade or reboot occurred.
