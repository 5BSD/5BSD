# Final kernel producer qualification

## Native implementation (2026-11-02)

The amd64 final-link force-dynamic helper now uses Bazel Skylib write_file for
its original empty C translation unit, ordinary rules_cc compilation, an explicit
regular-object selection and cc_binary(linkshared=True, linkstatic=True). The
selected kernel C++ toolchain supplies the declared Clang/lld and nostdlib link
policy. Source-owned kernel flags and warnings match Make; this custom recipe
has no Werror or CTF conversion. A declared symlink exposes its original .pico
final-link name without altering ELF bytes. bsd_object_alias now also accepts .so
inputs because this particular .pico is a shared ELF, not a relocatable object.
No startup objects, host libraries, substitute payloads or Make process enter the
native producer. Make's combined compile/link command becomes separate native
compile/link actions; raw command-line identity is not claimed across that split.

The existing VDSO producer already provided separate compile/link/validate/embed
actions. Reconciliation r38 omitted it because discovery selected ordinary
_KERNEL compilation groups. That was an inventory-query gap, not an absent
implementation. Current query r45 explicitly includes these special compilation
groups. The VDSO producer itself is unchanged.

The maintained build-bsd format-5 kernel target workflow and immutable capture
support both producers, as demonstrated by the actual profile. No frontend C,
CLI/manual option, SDK-export schema, staging/signing/verification or publication
policy change is required. Make remains production/default; BIP remains excluded.

## Merge and refreshed evidence

The concurrent committed HyperTrace merge 7056e69713f changed source-backed
cap_authority.h and amd64 GENERIC after the earlier SDK preparation. The normal
input-integrity guard rejected that stale receipt. The old receipt was not
rebound: maintained libmd-plan.py and libmd-stage-tools.py prepared a new SDK in
bazel-posthypertrace-sdk-20261102. An independent old-input audit found exactly
the two expected changes; its immutable SDK snapshot and host dependencies were
unchanged. Earlier cohort evidence remains tied to its earlier source/config.

Paths below are under /usr/obj/usr/src.

- bazel-kernel-posthypertrace-config-reference-20261102 contains freshly configured
  amd64, ARM64 and RISC-V64 GENERIC references. The maintained kernel_inventory.py
  audits in bazel-kernel-posthypertrace-product-inventory[-r2]-20261102 select
  2,462, 2,035 and 1,194 final-link products respectively. amd64 removes ichsmb.o,
  ichsmb_pci.o, intpm.o and uvideo.o relative to the old 2,466-product inventory;
  this follows current configuration rather than changing native code to fit a count.
- bazel-kernel-posthypertrace-full-make-reference-r1-20261102 passes a complete
  independent Make amd64 GENERIC kernel-only build, with 16 CPUs and disk-reserve
  monitoring. Before/after inventories agree on all 2,444 physical source hashes
  and the configured Makefile. This supplies current reference artifacts, not a
  Bazel kernel result. time -l CPU/RSS/I/O observations and disk-budget records are
  retained; this is not a controlled Make-versus-Bazel performance comparison.
- bazel-kernel-final-producers-amd64-r1-20261102 passes the maintained frontend
  seven-target build-only profile with 16 jobs and disk monitoring. Six original
  products match fresh Make byte-for-byte: sigtramp.pico, elf-vdso.so.1,
  vdso_offsets.h, elf-vdso.so.o, the empty force-dynamic-hack.c and its final
  force-dynamic-hack.pico. The seventh capture is the helper's intermediate object.
- bazel-kernel-final-producers-review-r1-20261102 retains configured action graphs,
  immutable capture bindings, Make/compiler policy, original preprocessing inputs,
  ELF readelf/section reports, review implementations and source declarations.
  The helper's actual fresh compiler/linker hashes follow FileWrite -> CppCompile
  -> CppLink -> Symlink. Both original Make prerequisites (source and opt_global.h)
  bind to native input digests. Warning/macro/code-generation/debug/forced-header
  policies agree with Make. All helper ELF bytes agree, not merely .text.
- The linker uses Bazel's normal response file. Its complete bytes are retained
  only after matching the execution-log input digest, then parsed and compared
  with the expanded configured argv. The first observer incorrectly expected
  literal expanded arguments in the execution log; its implementation is retained.
- VDSO comparison binds eight original trampoline and five wrapper prerequisites.
  Only its wrapper compiler reran in this profile. The trampoline compiler,
  linker and validator reused cached results; their actual prior execution logs
  are named explicitly, with current configured argv, compiler/linker/source
  identities and current captured output hashes checked. No absent cache-hit
  spawn is invented. The initial observer's missing-fresh-spawn rejection and
  implementation are retained separately. VDSO validation policy and its prior
  16-method native regression test are unchanged; this profile tests=[] does not
  rerun that test or establish live signal delivery.

## Coverage and remaining gates

Query r45 passes for 2,296 known compilation groups and 2,471 compiler actions.
Reconciliation r39 uses the refreshed 2,462-product amd64 inventory: 2,392 source
inventory identities, nine actual-recipe source identities, 57 generated-name
matches, two qualified special producer chains and two object-name-only matches.
There are no missing products in this configured inventory audit. Five explicit
final-link aliases are accounted for; nine helper/unselected compilation actions
remain distinct. Older custom recipe/alias evidence is preserved and hash-checked;
this reconciliation does not assert every selected object was recompiled now.

subr_clockcalib.o and vers.o still need stronger identity/artifact checks. Of the
57 generated-name matches, 53 have separate KOBJ/RPC cohort proofs; config/env/
hints/vnode need independent completion. Full native kernel aggregation, exact
link order, version generation policy, post-processing and install remain open.
All modules/drivers, alternate KERNCONF/features, ARM64/RISC-V64 native closures,
complete world and selected-recursion changes, pkgbase/hardware publication,
bootstrap, actual sandbox/runtime/VM and CPU/memory/disk I/O/use comparisons also
remain open. The helper's source is empty; original VDSO assembly/instrumentation
is unchanged. No host installation, upgrade or reboot occurred.
