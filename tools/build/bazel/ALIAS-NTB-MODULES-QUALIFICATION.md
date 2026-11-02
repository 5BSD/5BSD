# libalias and NTB module qualification

## Implemented scope

Fifteen selected amd64 GENERIC module leaves now use existing native C/KOBJ and
module link/CTF/debug/install helpers: eight libalias core/extension modules and
seven NTB core/hardware/transport/network/tool modules. Twenty-one compiler
contexts cover twenty physical C files and one generated ntb_if.c from original
ntb_if.m. Source/header dependencies and all original object order are explicit.
The generated KOBJ source/header outputs come from the existing native producer.
Three original EXPORT_SYMS=YES policies (libalias, ntb, ntb_transport) and all
remaining EXPORT_SYMS=NO policies are preserved. No runtime source, original
Makefile or common module helper changes. Eleven of twenty-six physical header
contexts reuse existing exact providers. No Make discovery runs in build actions.

## Evidence

Paths below are under /usr/obj/usr/src:

- bazel-alias-ntb-module-make-references-r1-20261102 retains all thirty original
  build/install controls: fifteen modules times plain/CTF-debug, one Make workload
  at a time using all sixteen CPUs.
- bazel-alias-ntb-modules-{plain,ctf-debug}-native-r1-20261102 qualify 51 targets
  through normal build-bsd format-5 inputs, including six existing provider tests.
  Those test results are regressions, not libalias protocol or NTB hardware tests.
- bazel-alias-ntb-modules-review-r1-20261102 retains actual compiler/link actions,
  exact parameter bytes captured before the next profile, input hashes, artifact/
  metadata proofs, source snapshot, profiles and review drivers.

All fifteen plain modules are byte-identical to untouched original Make outputs.
CTF/debug section inventories, metadata and payloads agree except GNU build-ID
and debug-link values; CTF bytes agree exactly and both debug CRC sets validate.
All 45 file installation records match. Whole DWARF byte identity is not claimed.
Twenty-one actual compiler actions agree in SDK compiler, defines, warning order,
code-generation flags and 2,793 original consumed prerequisite occurrences.
Only an exact single KOBJ source-path provenance comment may differ; raw input
hashes and any checked comment controls are retained. All fifteen original link
object lists and input digests pass. No finished-artifact normalization is used.
Parameter capture is observer ordering, not automatic maintained frontend support.

The bounded scan of twenty C files and ntb_if.m records 34 explicit marker lines:
eight in if_ntb.c and twenty-six in ntb_transport.c. Existing compiled section/
payload comparisons preserve instrumentation selected by this GENERIC build;
KTR-enabled configurations and live events remain unqualified. Remaining files
have no explicit markers under this scan, which does not establish absence of
shared header/subsystem instrumentation. Protocol/helper dispatch and failures,
NTB link/memory-window/doorbell lifecycle, DMA, queue/reset and rx/tx error paths
need runtime instrumentation review. Preserve existing KTR hooks; avoid per-packet
logging or payload disclosure. No new runtime probes are added in this migration.

## Workflow and open gates

Existing build-bsd C/frontend format-5 and backend SDK/kernel inputs express this
composition without new CLI, security/signing, staging or publication requirements.
Source-owned declarations and qualification docs are the changes in this cohort.
Original export behavior retains the default-loader/strict-export distinction in
MODULE-LOADER-EXPORT-CONTRACT.md; static build evidence does not prove loading.

Actual module loading, libalias protocol/NAT behavior and NTB hardware operation,
KTR/alternate kernel options, ARM64/RISC-V, complete world/rescue/pkgbase/hardware,
bootstrap/publication, VM/runtime, real cache/sandbox and CPU/memory/disk I/O/disk-use
performance gates remain open. Resource records are bounded build observations.
Make remains production/default; BIP is excluded. No host module loading,
installation, upgrade or reboot was performed.
