# Kernel codec, crypto and supporting-library qualification

## Scope (2026-11-02)

94 selected amd64 GENERIC objects now have native built-in targets: Concurrency
Kit, libnv, XZ, Zstd, zlib, Blake2, Sodium, kernel crypto adapters and algorithms,
entropy support, and AES assembly. Existing source packages remain; sys/dev/xz
gets its own source package. 91 per-source prerequisite contexts reuse identical
sets, alongside the shared XZ/Zstd port providers. No production C or assembly source changed.

Native cc_library compilation and the maintained CTF pipeline preserve common
kernel flags and per-source warning exceptions, XZ CRC64, Zstd heap/intrinsics
settings and macro undefines, Sodium/Blake2 include contexts, and AES language/
LOCORE policy. Source-owned port providers expose complete XZ header layout and
the Zstd FreeBSD standard-header overlay; that overlay precedes generic roots.
Original KOBJ producers generate interface headers. No generated Make reference
file enters the native graph.

The maintained build-bsd bazel-test format-5 workflow handles the targets with
16 CPUs. Existing frontend C/backend API, staging, signing, verification, package
policy and manual options cover the inputs; no frontend change is required.
Make remains production/default; BIP remains excluded.

## Retained evidence

Paths below are under /usr/obj/usr/src.

- bazel-kernel-codecs-crypto-make-metadata-r1-20261102 records supported Make
  recipes with filemon disabled. All 94 reference object hashes remain unchanged.
  This is not complete dynamic-input or performance qualification.
- Native r1 retains the missing textual ChaCha dependency failure: hash.c embeds
  chacha.c with its source-level configuration, while chacha.c also has a separate
  standalone object. The corrected declaration gives hash.c the real textual
  source dependency without adding a link object. Retry
  bazel-kernel-codecs-crypto-amd64-ctf-r2-20261102 passes normally.
- bazel-kernel-codecs-crypto-review-r1-20261102 binds all 94 effective successful
  compiler recipes through CTF input/output hashes to immutable final captures.
  Per-log counts distinguish retry/reuse from one fresh full run. Final configured
  argv matches each actual execution. The audit checks
  6,674 physical and 180 generated prerequisite occurrences, original
  source identities, ordered warnings, defines and undefines, code-generation
  option sets, stack protection, final debug setting, language and forced includes.
  All 23 Zstd recipes explicitly keep the port overlay before sys.
- All 94 objects have byte-identical .text and CTF, with equivalent typed CTF
  graphs. Complete allocated payloads and 8,030 non-debug relocations agree;
  7 independently bound source-filename spellings in read-only strings differ.
  No ELF artifact was rewritten. Full DWARF/string/symbol table byte parity is
  not claimed. KOBJ provenance comparison changes only the exact schema-path
  comment to input basename; original and comparison hashes remain.
- The original relocation observer rejected a valid Zstd one-past-array pointer
  because it required every computed address to be inside a string. Its failed
  implementation/diagnostic remain. For byte-identical complete pools the final
  observer compares raw symbol identities, offsets and addends strictly; changed
  filename pools retain complete symbolic checks. This does not omit relocations
  or change binary artifacts.
- The bounded source-hash-bound scan finds call-shaped tracing/CTR/audit markers
  in 1 selected files. It is neither live probe coverage nor proof of missing
  shared hooks in other files. Existing instrumentation remains.

Closure query r35 passes for 2,017 known groups and
2,192 compile actions, including vendor declarations outside sys. Reconciliation
r28 finds 2,183 source-identity matches, two object-name-only and four generated-
name-only matches among 2,466 Make final-link products, leaving
277 unmatched. These are graph counts, not a complete compiled or linked kernel.

## Remaining qualification

Codec round trips, crypto test vectors and consumers, entropy/device behavior,
allocation/error paths and live tracing need runtime qualification. This profile
selects tests=[]; no entropy or crypto device operations occurred. Full kernel
link/order/identity, post-processing/install, modules, alternate KERNCONF,
ARM64/RISC-V64, world, pkgbase/hardware publication and bootstrap remain open.
Disk reserves pass; controlled CPU, memory and disk I/O/use comparisons remain
open. Persistent cache qualification is separate; no managed disk cache was
enabled. No host install, upgrade or reboot occurred.
