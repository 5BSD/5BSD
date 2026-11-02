# Generated RPC kernel object qualification

## Scope (2026-11-02)

Four additional amd64 GENERIC final-link objects now use native compilation of
the RPC TLS client/server protocol XDR and client sources. The existing native
kernel_rpc_protocol actions run the original rpcgen and maintained kernel include
filters; two original .x schemas generate four C files and two headers. Four
physical prerequisite contexts preserve actual header ownership. Schemas and
production C sources are unchanged. No Make subprocess or reference-generated
file enters the native build graph.

The original custom Make recipes omit Werror for these generated sources.
Explicit common kernel warnings preserve that policy independently of the normal
built-in Werror setting. Native GENERIC option/offset headers remain ordinary
declared dependencies. Original protocol targets are captured alongside objects.
Existing build-bsd format-5 target/backend, CTF and immutable capture support the
batch without frontend C, staging/security/signing/verification, publication or
manual option changes. Make remains production/default; BIP remains excluded.

## Evidence

Paths below are under /usr/obj/usr/src.

- bazel-kernel-rpc-builtins-make-metadata-r1-20261102 records four original
  compiler recipes, filemon disabled, with all reference object hashes unchanged.
  Complete dynamic-input or performance qualification is not claimed.
- Native r1 passes binary construction, but strict compiler comparison rejects
  inherited Werror that is absent from Make's custom RPC recipe. The source-owned
  warning-vector correction preserves the actual recipe; native r2 passes for
  all ten targets through the maintained frontend with 16 jobs and disk reserves.
- bazel-kernel-rpc-builtins-review-r1-20261102 compares six immutable generated
  C/header files against Make byte-for-byte, without normalization. It binds all
  four final actual compiler recipes to immutable object captures through raw/CTF
  hashes. All four final configured argv match actual executions.
- CTF conversion reused unchanged objects after the warning-only correction.
  The retained r1/r2 logs bind the conversion through identical raw and output
  hashes; a rejected observer that incorrectly demanded fresh CTF spawn records
  is retained. It does not claim four fresh conversions in r2.
- Compiler checks verify exact ordered warnings, macros, code-generation flags,
  stack/debug/language/forced-header policies, 516 physical and
  16 generated prerequisite occurrences, including generated compilation sources.
  All four .text/CTF payloads and runtime sections are byte-identical; CTF graphs
  agree and all 57 non-debug relocations are identical. No filename-string
  differences occur. Full DWARF/string/symbol-table byte equality is not claimed.
- A bounded source-bound scan of the two original schemas finds no matching
  call-shaped tracing/audit markers. This proves neither absent shared hooks nor
  runtime protocol behavior. Original instrumentation remains.

Closure query r42 passes for 2,284 known groups and
2,459 compile actions. Reconciliation r35 finds 2,396 physical source-identity
matches, 57 generated-name-only and two object-name-only matches among 2,466
Make link products, leaving 11 missing. Independent generator/artifact comparisons
now strengthen 53 of the generated-name matches (49 KOBJ plus these four RPC
objects); the graph-only classification remains explicit. This is not proof of
complete final kernel linking or system completion.

## Remaining gates

TLS RPC client/server interaction, error/time-out paths, NFS integration and live
observability require runtime tests. This profile has tests=[] and performs no
network/service operations. Eleven unmatched custom/renamed products, four other
generated and two object-name identities, full linking/post-processing/install,
modules, alternate KERNCONF, ARM64/RISC-V64, world, pkgbase/hardware publication,
bootstrap, boot and controlled CPU/memory/disk I/O/use comparisons remain open.
No managed disk cache was enabled. No host install, upgrade or reboot occurred.
