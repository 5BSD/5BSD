# Filesystem and RPC built-in kernel qualification

## Scope (2026-11-02)

101 selected amd64 GENERIC C objects now have native built-in declarations across
base filesystems (including NFS, UFS/FFS, MSDOSFS, CD9660 and nullfs), RPC, NLM and
XDR. Existing source/header package ownership is retained; previously unowned
filesystem directories get local packages. 108 physical header contexts share
identical prerequisite sets. No production filesystem or RPC sources change.

100 ordinary objects use the common built-in kernel policy. nfs_clkdtrace uses
the original OpenZFS/SPL compatibility roots before ordinary BSD headers and
legacy Solaris roots afterward. static_ccompile.h remains forced before
opt_global.h; ccompile.h remains after it. Exact original defines/warning order
are preserved. Unconsumed ZFS/zstd search roots are omitted, without empty
placeholder directories or warning suppression. Actual include/forced-include
order is checked independently of machine-code equality.

Consumed options come from native config-tree extraction, including empty files.
Existing vnode/offset and bus/device producers remain native. RPC TLS explicitly
depends on existing generated_rpc_headers: the maintained native rpcgen/filter
actions consume the original protocol schemas. No generated Make files enter the
native graph. Metadata recording supplies independent reference recipes only.

The maintained build-bsd bazel-test format-5 workflow handles SDK/platform,
16 workers, CTF/debug and compact logs. No frontend C/backend API, CLI/manual,
staging, signing/verification or package-policy change is required. Make remains
production/default. BIP remains excluded.

## Retained evidence

Paths below are under /usr/obj/usr/src.

- bazel-kernel-filesystems-rpc-make-metadata-r1-20261102 records actual supported
  Make recipes with filemon disabled. All 101 completed reference objects retain
  their hashes; this is not full dynamic dependency or performance proof.
- bazel-kernel-filesystems-rpc-amd64-ctf-r1-20261102 is the retained failed
  build: RPC TLS lacked its two generated header dependencies. r2 corrects this
  by reusing the existing native provider and passes all 101 targets.
- bazel-kernel-filesystems-rpc-review-r1-20261102 checks 16,780 physical and
  508 generated inputs, including exact native generated RPC header digests.
  Selected source hashes match the independent Make inventory. Actual warning
  order, defines, code-generation option sets, stack protection, final debug
  switch, language and forced includes match Make. Absolute forced-header paths
  map only to the same independently consumed physical source inputs.

All 101 .text sections are byte-identical. 100 .SUNW_ctf sections are byte-identical;
ufs_bmap differs in encoding with 1,226 versus 1,225 type records. The unchanged
maintained ctf-artifact-check.py passes original ELF symbol identities, labels,
ordered type-reference graphs and all nonempty/referenced type multiplicities.
Only the unreferenced empty UNKNOWN-slot count differs (six versus five).
The original strict byte comparison failure and partial reports remain, alongside
a diagnostic and unchanged production-checker reports. Byte parity is not claimed
for this one object. No production verifier was changed to accept it.

All 101 typed CTF association graphs pass. For filename-spelling differences, the
bounded read-only procedure in OPENZFS-KERNEL-QUALIFICATION.md canonicalizes only
zero-type string object addresses through complete verified strings/interior
offsets, retaining typed identities and full-literal size checks. Separate full
string-pool, allocated-layout and relocation gates bind original object hashes.

Allocated payload/layouts match except 76 exact known-source filename spellings;
all 41,791 nondebug relocations compare symbolically. No artifacts are rewritten.
Full DWARF, symbol-index and string-table byte parity remains unclaimed. Final
captures bind through CTF input/output hashes to 101 fresh successful compiler
actions: 98 from r2 and three unchanged outputs from r1. This is a qualified union
of actual hash-bound actions, not a claim that all compiled fresh in one run.

Compact logs are streamed through the upstream converter, with all 189 recorded
converter bindings verified before/after. Source/declaration/profile snapshots,
review code and hashes remain alongside the results. The original failed
header-dependency declarations remain separately retained.

Configured query r27 passes for 1,528 known built-in groups and 1,703 compiler
actions. Reconciliation r22 finds 1,694 source matches, two object-name matches
and four generated-name matches among 2,466 Make final-link products, leaving
766 unmatched. Three auxiliary generator objects remain separate. These counts
are known amd64 analysis, not complete compiled/linked or cross-architecture proof.

## Observability and remaining gates

The bounded source-hash-bound call scan finds existing tracing/CTR/audit-family
markers in 17 of 101 files. The other 84 do not prove missing shared hooks.
NFS tracing headers remain compiled with their original compatibility policy;
live probes, NFS/RPC/TLS/authentication/locking/recovery, local mount/unmount,
filesystem consistency and error behavior need relevant runtime qualification.
The profile has tests=[] and performs no host mount/storage/network operations.

Full native kernel link/order/identity/post-processing/install, all modules,
alternate KERNCONF, ARM64/RISC-V64, complete world, pkgbase/hardware publication,
bootstrap and boot/services remain open. Disk guards pass; controlled CPU, memory,
disk I/O/use and cache comparisons remain open. No host install, upgrade or reboot.
