# Device-driver family module qualification

## Implemented scope

Fifteen selected amd64 GENERIC leaves now use existing native C/KOBJ and module
link/CTF/debug/install helpers: IPMI and Linux compatibility; MFI core/Linux/CAM;
MRSAS core/Linux; one-wire bus/temperature/GPIO controller; PWM bus/controller;
and VMware PVSCSI/VMCI/VMXNET3. Forty-four compiler contexts cover forty-one
physical C files and three generated implementations from own_if.m, owll_if.m
and pwmbus_if.m. Forty source groups declare actual consumed header relationships:
fifty-five physical contexts, thirty-five exactly reused. Generated option and
bus/interface inputs are explicit native producer dependencies.

All original object orders and package=kernel tags are retained. Original
EXPORT_SYMS=YES for mfi/owc/pwmbus and other EXPORT_SYMS=NO policies remain.
The original machine/../linux include spelling in three Linux-compatibility
modules uses the existing declared architecture header view. Its narrow consumer
visibility is extended and the three modules declare that dependency; no header
rewrites, ad hoc include roots or helper changes. The rejected r1 missing-view
compile is retained. Successful unchanged compiler witnesses may come from r1;
failed spawns are excluded; final CTF/debug artifacts come from accepted r2 and
plain artifacts from accepted plain r1.
No runtime C, assembly, original Makefile, common module helper or compiler policy
changes. No Make metadata query or subprocess runs inside the native actions.
These declarations cover selected current source/configuration contexts and need
explicit updates when those relationships change.

## Evidence

Paths below are under /usr/obj/usr/src:

- bazel-device-families-module-make-references-r1-20261102 retains all thirty
  original build/install controls: fifteen leaves in plain/CTF-debug. One workload
  at a time uses all sixteen CPUs. Original Makefile hashes are checked against
  the source inventory before building, with inherited parent exports preserved.
- bazel-device-families-modules-plain-native-r1-20261102 and
  bazel-device-families-modules-ctf-debug-native-r2-20261102 qualify 51
  targets through normal build-bsd format-5 inputs, including six existing provider
  tests per profile. These are regression checks, not new driver/hardware tests.
- bazel-device-families-modules-review-r1-20261102 retains actual compiler/link
  actions, exact parameter bytes, input hashes, artifact/debug/install proofs,
  source snapshots, profiles and review drivers.

All fifteen plain modules are byte-identical to untouched original Make outputs.
CTF/debug section inventories, metadata and payloads agree except GNU build-ID
and debug-link values; CTF bytes agree exactly and both debug CRC sets validate.
All 45 file installation records match. Whole DWARF byte identity is not claimed.
Forty-four actual compiler contexts agree in SDK compiler, defines, warning order,
code-generation flags and 5,098 original consumed prerequisite occurrences.
Only exact single KOBJ source-path provenance comments may differ in generated
inputs; hashes and any checked comment controls are retained. Fifteen original
ordered initial links pass with actual input digests. Exact parameter bytes are
captured before the later profile. This observer ordering is not automatic
maintained frontend parameter capture. No final artifact is normalized.

## Observability and open gates

The bounded scan of forty-one C files and three interface schemas finds zero
explicit DTrace/SDT/CTR/audit marker lines under the recorded patterns. This is
not proof of no inherited header/subsystem instrumentation. The selected compiled modules also contain no SDT/DTrace sections under the
recorded inventory; complete section/payload comparisons pass. This does not
establish absence of instrumentation in shared subsystem code.
Review IPMI transaction/timeouts, CAM/storage command/recovery/error paths,
one-wire/PWM bus lifecycle and VMCI datagram/doorbell/queue-pair and VMXNET3
attach/reset/rx/tx with useful shared hooks. Avoid per-packet logs or payload/
credential disclosure. No runtime probes are added in this metadata migration.

The existing build-bsd C interface/format-5 backend and maintained helpers express
these inputs and package metadata. No new CLI/manual behavior, security/signing,
staging or publication requirement is introduced. The default-loader/strict-export
distinction remains documented separately; static build parity does not prove
module loading or hardware operation.

ARM64/RISC-V, FDT-enabled PWM paths, ACPI/ISA/Linux-compatibility alternatives and
other KERNCONF/option combinations, actual module loading, hardware/sensor/PWM/
VMware behavior, live probes/audit, full world/rescue/pkgbase/hardware/bootstrap/
publication, VM/runtime, cache/sandbox and CPU/memory/disk I/O/disk-use performance
gates remain open. Resource records are bounded build observations. Make remains
production/default; BIP is excluded. No host module loading, installation,
upgrade or reboot was performed.
