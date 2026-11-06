# Netgraph and TCP module parent qualification (2026-11-06)

## Source-owned selection

The AMD64 Netgraph parent composes its 35 unconditional products, the existing
Bluetooth parent when the source bluetooth setting is enabled, and MPPC when
crypt is enabled and the original rc4/rc4.c selection source exists. Direct parent
selection is independent of the root netgraph family toggle, as in Make.

The optional source predicate uses a package-owned, precise source glob and a typed
module-set source_availability input. An explicitly empty source group excludes
that optional family; an unspecified predicate preserves ordinary selection.
Generated files are rejected because their existence is not a source-availability
predicate. This adds no runtime policy or installed files. Analysis tests cover
present, absent and rejected generated-file cases without deleting tracked source.

The TCP parent selects HPTS, BBR and RACK when either source inet_support or
inet6_support is enabled. TCP-MD5 also requires actual kernel IPSEC_SUPPORT and
absence of TCP_SIGNATURE. Both IP support options disabled is an explicitly valid
empty TCP installation, not permission for an empty full kernel image.

New kernel_ipsec_support and kernel_tcp_signature string settings accept auto,
yes and no. The shared kernel_option_setting macro derives positive and negative
selectors from the same architecture/default declaration consumed by the native
configuration action. All three GENERIC architectures declare IPSEC_SUPPORT=yes
and TCP_SIGNATURE=no. Auto leaves native source configuration unchanged; normal
configuration actions check the complete generated option-header set against the
resolved expectation before publishing identity/inventory. FDT uses this same
macro. No Make queries run in production actions and no frozen global module list
or synthetic option header is used.

## Evidence

All paths below are under /usr/obj/usr/src. Four normal build-bsd bazel-test
requests use format-5 inputs, the maintained package SDK and all 16 logical CPUs:

| Native output suffix (20261106) | Netgraph | TCP | Unique products |
| --- | ---: | ---: | ---: |
| bazel-network-module-parents-default-native-r1 | 43 | 4 | 47 |
| bazel-network-module-parents-off-native-r1 | 35 | 3 | 38 |
| bazel-network-module-parents-signature-native-r1 | 43 | 3 | 46 |
| bazel-network-module-parents-ip-off-native-r1 | 43 | 0 | 43 |

Off sets bluetooth=false, crypt=false and kernel_ipsec_support=no. Signature sets
kernel_tcp_signature=yes. IP-off disables both inet_support and inet6_support.
Each request passes 19 test targets; previously cached tests are not new executions.
The three new source-predicate analysis tests execute successfully in the default
request. Source defaults and explicit overrides are checked against actual headers.

bazel-network-module-parents-review-r1-20261106/review.json independently queries
the original Make root and actual nested parents, propagating their exported state.
It compares complete recursive membership, each leaf's owner/group/mode/package/
debug/alias attributes, complete installation records, and exact resolved ordered
OBJS against native recipes emitted by the real link actions. All 174 selected
runtime/debug pairs across the four profiles pass actual ELF/debug-link CRC checks.
Common TCP bytes are not assumed equal across changed IPsec/signature kernel ABIs.
This is not fresh Make machine-code or complete DWARF parity. Review SHA256:
c21c938229c13b2a8e9f4fe1055a38883a4bc753b60b1a1349ad9fe221b536d2

The review retains commands, effective options, inherited/exported names, complete
artifact bindings and actual link recipes. The migration inputs and source-policy
snapshot are retained under bazel-network-module-parent-migration-r1-20261106.

## Integration and remaining scope

The maintained build-bsd frontend already carries these settings through its
format-5 build-settings API; no frontend C or signing/staging/publication protocol
change is needed. Backend declarations, source selection, analysis tests, manual
and completion records change together. No runtime C or kernel I/O path changes.
These structural observations do not establish build or runtime performance parity.

ALL_MODULES/standalone alternative traversal, an actual source checkout without
RC4, custom kernel configurations and complete ARM64/RISC-V parent builds remain
unqualified. The absent-source behavior has analysis-fixture evidence only. Full
root traversal, coherent kernel/GDB/modules/directories/aliases/linker.hints/pkgbase,
normal boot/authentication/services, genuine upgrades and cross/bootstrap/cache/
sandbox/reproducibility/debug/CPU/RAM/disk/hardware/publication gates remain open.
Make stays production/default. BIP is excluded; no host installation or reboot.
