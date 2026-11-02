# Network stack and PF built-in kernel qualification

## Scope (2026-11-02)

102 selected amd64 GENERIC C sources now have native built-in targets across
routing, Netlink, congestion control/netdump, IPsec, Netgraph/Bluetooth, Dummynet
and PF vendor/glue code. Existing package ownership remains. Identical physical
prerequisite sets share 153 header contexts; no production source changed.

The declarations preserve native cc_library compilation and the maintained CTF
pipeline. PF keeps its distinct original built-in warning vector, OPENBSD_PF
and glue defines, forced compatibility header and first compatibility include
root. The existing complete PF compatibility provider is reused with visibility
limited to its consumer packages; module compilation policy is unchanged. Other
sources use maintained common built-in warnings. Original config-tree/KOBJ/USB
ID generators supply generated headers. No generated Make reference is substituted
into the native build.

The normal build-bsd bazel-test format-5 workflow handles these targets with 16
CPUs. Existing frontend C/backend API, staging, signing, verification, packaging
and manual options cover the inputs; no frontend change is required. Make remains
production/default; BIP remains excluded. Network behavior/policy is unchanged.

## Evidence

Paths below are under /usr/obj/usr/src.

- bazel-kernel-network-policy-make-metadata-r1-20261102 records actual supported
  Make recipes with filemon disabled. All 102 reference object hashes remain
  unchanged. This is not complete dynamic input or performance qualification.
- Native r1 retains the analysis failure for a per-source compatibility include
  root without a declared header below it. Reusing the existing complete PF
  compatibility provider fixes that model. R2 retains the missing usbdevs.h
  dependency failure; four Bluetooth sources now consume the existing native USB
  ID provider. bazel-kernel-network-policy-amd64-ctf-r3-20261102 passes through
  the maintained frontend; no fallback was used.
- bazel-kernel-network-policy-review-r1-20261102 binds all 102 effective successful
  compiler recipes through CTF input/output hashes to immutable object captures.
  Summary per-log counts distinguish retries/reuse from a single fresh full run.
  Final configured argv matches every actual audited recipe.
- The review checks 17,160 physical and 379 generated prerequisite
  occurrences, source identities, ordered warning vectors, defines, code-generation
  option sets, stack protection, final debug choice, language and forced includes.
  All 27 PF recipes explicitly keep the compatibility include root before sys.
- All 102 objects have byte-identical .text and equivalent typed CTF graphs.
  101 have byte-identical CTF. PF ioctl differs by one unreferenced empty
  type slot; its unchanged production verifier report preserves strict original
  symbol identities and all nonempty/referenced type multiplicities. The initial
  raw-byte rejection and partial reports remain in ctf-semantic-r1; r2 retains
  semantic proof and an explicit correction of its overbroad console label.
  Complete allocated payloads and 44,205 non-debug relocations agree
  after reconciling 83 source-filename spellings in read-only pools. No ELF
  artifact is rewritten. Full DWARF/string/symbol table byte parity is not claimed.
  PF's original /usr/src/sys/../contrib source spelling is reconciled only for a
  complete filename resolving to the independently declared physical input.
  Unknown filenames and non-filename payload differences remain failures. Typed
  CTF symbol identities are unchanged; only zero-type string-object addresses
  use their complete, verified source-filename pool content. KOBJ provenance
  comparison changes only the exact schema-path comment to input basename.
  Original and comparison hashes remain in the review.
- The bounded source-hash-bound observability scan finds call-shaped markers in
  27 selected files. It is not runtime probe coverage or proof that other
  files lack shared hooks. Existing instrumentation remains.

Closure query r34 discovers maintained amd64 built-in macro declarations throughout
the source tree, including PF vendor declarations outside sys. It passes for
1,923 known groups and 2,098 compile actions. Reconciliation r27 finds
2,089 source-identity matches, two object-name-only and four generated-name-only
matches among 2,466 Make final-link products, leaving 371 unmatched. These are
graph counts, not a complete compiled or linked kernel.

## Remaining qualification

Routing/Netlink operations, congestion control, IPsec key management/traffic,
Netgraph/Bluetooth/USB devices, PF rules/NAT/state/synchronization, Dummynet and
live tracing need runtime qualification. The profile selects tests=[]; no host
network policy, keys or interfaces were modified. Full kernel link/order/identity,
post-processing/install, modules, alternate KERNCONF, ARM64/RISC-V64, world,
pkgbase/hardware publication and bootstrap remain open. Disk reserves pass;
controlled CPU, memory and disk I/O/use comparisons remain open. Persistent cache
qualification is separate; no managed disk cache was enabled. No host install,
upgrade or reboot occurred.
