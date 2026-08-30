#!/bin/sh
#
# Validate the Intel nested-VMX requirement-to-code-to-test ledger without
# deriving any architectural values from the implementation.

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${SRCTOP:-/usr/src}
ledger="$here/vmx-nested-requirements.tsv"
live_ledger="$here/vmx-nested-live-qualification.tsv"
default_live_ledger="$here/vmx-nested-default-policy-live-qualification.tsv"
private_ledger="$here/vmx-nested-nonstandard-interfaces.tsv"
live_coverage="$here/validate-vmx-nested-live-coverage.sh"
corpus="$src/tests/sys/kern/vsock_device_harness/virtio-reference-corpus.tsv"
reference_validator="$src/tests/sys/kern/vsock_device_harness/validate-virtio-reference-corpus.sh"
test_source="$src/tests/sys/vmm/vmx_nested_state_test.c"
snapshot_test_source="$src/tests/sys/vmm/vmm_snapshot_op_test.c"
envelope_test_source="$src/tests/sys/vmm/vmm_snapshot_envelope_test.c"
event_test_source="$src/tests/sys/vmm/vmm_event_state_test.c"
event_state_source="$src/sys/amd64/vmm/vmm_event_state.c"
ingress_test_source="$src/tests/sys/vmm/vmm_event_ingress_test.c"
startup_test_source="$src/tests/sys/vmm/vmm_startup_event_test.c"
startup_state_source="$src/sys/amd64/vmm/vmm_x86_startup_state.c"
startup_state_header="$src/sys/amd64/vmm/vmm_x86_startup_state.h"
startup_state_test_source="$src/tests/sys/vmm/vmm_x86_startup_state_test.c"
startup_execution_source="$src/sys/amd64/vmm/vmm_x86_startup_transaction.c"
startup_execution_header="$src/sys/amd64/vmm/vmm_x86_startup_transaction.h"
startup_execution_test_source="$src/tests/sys/vmm/vmm_x86_startup_transaction_test.c"
startup_machine_source="$src/sys/amd64/vmm/vmm_x86_startup_machine.c"
startup_machine_header="$src/sys/amd64/vmm/vmm_x86_startup_machine.h"
startup_machine_test_source="$src/tests/sys/vmm/vmm_x86_startup_machine_test.c"
startup_vmreg_source="$src/sys/amd64/vmm/vmm_x86_startup_vmreg.c"
startup_vmreg_header="$src/sys/amd64/vmm/vmm_x86_startup_vmreg.h"
startup_vmreg_test_source="$src/tests/sys/vmm/vmm_x86_startup_vmreg_test.c"
startup_backend_source="$src/sys/amd64/vmm/vmm_x86_startup_backend.c"
startup_backend_header="$src/sys/amd64/vmm/vmm_x86_startup_backend.h"
startup_backend_test_source="$src/tests/sys/vmm/vmm_x86_startup_backend_test.c"
startup_finalizer_source="$src/sys/amd64/vmm/vmm_x86_startup_finalizer.c"
startup_finalizer_header="$src/sys/amd64/vmm/vmm_x86_startup_finalizer.h"
startup_finalizer_test_source="$src/tests/sys/vmm/vmm_x86_startup_finalizer_test.c"
startup_mode_source="$src/sys/dev/vmm/vmm_startup_mode.c"
startup_mode_header="$src/sys/dev/vmm/vmm_startup_mode.h"
startup_mode_test_source="$src/tests/sys/vmm/vmm_startup_mode_test.c"
startup_entry_owner_source="$src/sys/dev/vmm/vmm_startup_entry_owner.c"
startup_entry_owner_header="$src/sys/dev/vmm/vmm_startup_entry_owner.h"
startup_entry_owner_test_source="$src/tests/sys/vmm/vmm_startup_entry_owner_test.c"
startup_handshake_source="$src/sys/dev/vmm/vmm_startup_handshake.c"
startup_handshake_header="$src/sys/dev/vmm/vmm_startup_handshake.h"
startup_handshake_test_source="$src/tests/sys/vmm/vmm_startup_handshake_test.c"
startup_controller_source="$src/sys/dev/vmm/vmm_startup_controller.c"
startup_controller_header="$src/sys/dev/vmm/vmm_startup_controller.h"
startup_controller_test_source="$src/tests/sys/vmm/vmm_startup_controller_test.c"
startup_request_source="$src/sys/dev/vmm/vmm_startup_request.c"
startup_request_header="$src/sys/dev/vmm/vmm_startup_request.h"
startup_request_test_source="$src/tests/sys/vmm/vmm_startup_request_test.c"
startup_run_request_source="$src/sys/dev/vmm/vmm_startup_run_request.c"
startup_run_request_header="$src/sys/dev/vmm/vmm_startup_run_request.h"
startup_run_request_test_source="$src/tests/sys/vmm/vmm_startup_run_request_test.c"
startup_management_abi_test_source="$src/tests/sys/vmm/vmm_startup_management_abi_test.c"
startup_staging_live_test_source="$src/tests/sys/vmm/vmm_startup_staging_live_test.c"
checkpoint_test_source="$src/tests/sys/vmm/vmm_event_checkpoint_test.c"
wait_test_source="$src/tests/sys/vmm/vmm_event_wait_test.c"
exception_test_source="$src/tests/sys/vmm/vmm_exception_test.c"
ingress_source="$src/sys/dev/vmm/vmm_event_ingress.c"
ingress_header="$src/sys/dev/vmm/vmm_event_ingress.h"
startup_source="$src/sys/dev/vmm/vmm_startup_event.c"
startup_header="$src/sys/dev/vmm/vmm_startup_event.h"
startup_transaction_source="$src/sys/amd64/vmm/intel/vmx_nested_startup_transaction.c"
startup_transaction_header="$src/sys/amd64/vmm/intel/vmx_nested_startup_transaction.h"
startup_policy_source="$src/sys/amd64/vmm/intel/vmx_nested_startup_policy.c"
startup_policy_header="$src/sys/amd64/vmm/intel/vmx_nested_startup_policy.h"
startup_dispatch_source="$src/sys/amd64/vmm/intel/vmx_nested_startup_dispatch.c"
startup_dispatch_header="$src/sys/amd64/vmm/intel/vmx_nested_startup_dispatch.h"
event_checkpoint_source="$src/sys/dev/vmm/vmm_event_checkpoint.c"
event_checkpoint_header="$src/sys/dev/vmm/vmm_event_checkpoint.h"
snapshot_envelope_source="$src/sys/dev/vmm/vmm_snapshot_envelope.c"
address_range_header="$src/sys/dev/vmm/vmm_address_range.h"
event_wait_source="$src/sys/dev/vmm/vmm_event_wait.c"
event_wait_header="$src/sys/dev/vmm/vmm_event_wait.h"
event_coordinator_source="$src/sys/dev/vmm/vmm_event_coordinator.c"
event_coordinator_header="$src/sys/dev/vmm/vmm_event_coordinator.h"
vmm_vm_source="$src/sys/dev/vmm/vmm_vm.c"
vmm_vm_header="$src/sys/dev/vmm/vmm_vm.h"
ingress_callers="$here/vmm-event-ingress-callers.tsv"
entry_edge_matrix="$here/vmx-startup-entry-edge-matrix.tsv"
transaction_source="$src/sys/amd64/vmm/vmm_snapshot_x86_transaction.c"
x86_state_source="$src/sys/amd64/vmm/vmm_snapshot_x86_state.c"
x86_state_header="$src/sys/amd64/vmm/vmm_snapshot_x86_state.h"
cpuid_test_source="$src/tests/sys/kern/vsock_device_harness/x86_cpuid_topology_test.c"
manifest="$src/tests/sys/kern/vsock_e2e/virtio-lab.yaml"
module_makefile="$src/sys/modules/vmm/Makefile"
arm64_files="$src/sys/conf/files.arm64"
riscv_files="$src/sys/conf/files.riscv"
vmx_source=${VMX_NESTED_VMX_SOURCE:-"$src/sys/amd64/vmm/intel/vmx.c"}
model_runner=${VMX_NESTED_MODEL_RUNNER:-"$src/tests/sys/vmm/run-vmx-nested-model.sh"}
vmx_header="$src/sys/amd64/vmm/intel/vmx.h"
svm_source="$src/sys/amd64/vmm/amd/svm.c"
vmm_header="$src/sys/amd64/include/vmm.h"
checkpoint_source="$src/sys/amd64/vmm/intel/vmx_nested_checkpoint.c"
context_source="$src/sys/amd64/vmm/intel/vmx_nested_context.c"
registry_source="$src/sys/amd64/vmm/intel/vmx_nested_vmcs_registry.c"
registry_state_source="$src/sys/amd64/vmm/intel/vmx_nested_vmcs_registry_state.c"
vmcs02_intel_source="$src/sys/amd64/vmm/intel/vmx_nested_vmcs02_intel.c"
vmcs02_intel_header="$src/sys/amd64/vmm/intel/vmx_nested_vmcs02_intel.h"
environment_intel_source="$src/sys/amd64/vmm/intel/vmx_nested_entry_environment_intel.c"
instruction_runtime_source="$src/sys/amd64/vmm/intel/vmx_nested_instruction_runtime.c"
instruction_handoff_source="$src/sys/amd64/vmm/intel/vmx_nested_instruction_handoff.c"
ept_handoff_source="$src/sys/amd64/vmm/intel/vmx_nested_ept_handoff.c"
l1_restore_source="$src/sys/amd64/vmm/intel/vmx_nested_l1_restore.c"
l2_thaw_source="$src/sys/amd64/vmm/intel/vmx_nested_l2_thaw.c"
l2_thaw_staged_source="$src/sys/amd64/vmm/intel/vmx_nested_l2_thaw_staged.c"
l2_freeze_source="$src/sys/amd64/vmm/intel/vmx_nested_l2_freeze.c"
exit_capture_source="$src/sys/amd64/vmm/intel/vmx_nested_exit_capture.c"
apic_priority_source="$src/sys/amd64/vmm/intel/vmx_nested_apic_priority.c"
hot_exit_source="$src/sys/amd64/vmm/intel/vmx_nested_hot_exit.c"
vmcs02_apply_source="$src/sys/amd64/vmm/intel/vmx_nested_vmcs02_apply.c"
refreeze_source="$src/sys/amd64/vmm/intel/vmx_nested_refreeze.c"
msr_source="$src/sys/amd64/vmm/intel/vmx_nested_msr.c"
vpid_owner_source="$src/sys/amd64/vmm/intel/vmx_nested_vpid_owner.c"
bitmap_source="$src/sys/amd64/vmm/intel/vmx_nested_bitmap.c"
bitmap_header="$src/sys/amd64/vmm/intel/vmx_nested_bitmap.h"
ept_cache_source="$src/sys/amd64/vmm/intel/vmx_nested_ept_cache.c"
vmcs02_resources_intel_source="$src/sys/amd64/vmm/intel/vmx_nested_vmcs02_resources_intel.c"
vmm_source="$src/sys/amd64/vmm/vmm.c"
vmm_dev_source="$src/sys/dev/vmm/vmm_dev.c"
common_vmm_dev_header="$src/sys/dev/vmm/vmm_dev.h"
devfs_vnops_source="$src/sys/fs/devfs/devfs_vnops.c"
kern_conf_source="$src/sys/kern/kern_conf.c"
vmm_dev_machdep_source="$src/sys/amd64/vmm/vmm_dev_machdep.c"
vmm_dev_header="$src/sys/amd64/include/vmm_dev.h"
libvmmapi_source="$src/lib/libvmmapi/vmmapi.c"
libvmmapi_header="$src/lib/libvmmapi/vmmapi.h"
libvmmapi_internal="$src/lib/libvmmapi/internal.h"
vmm_snapshot_header="$src/sys/amd64/include/vmm_snapshot.h"
bhyve_snapshot_source="$src/usr.sbin/bhyve/snapshot.c"
bhyve_run_source="$src/usr.sbin/bhyve/bhyverun.c"
bhyve_run_header="$src/usr.sbin/bhyve/bhyverun.h"
bhyve_machdep_source="$src/usr.sbin/bhyve/amd64/bhyverun_machdep.c"
bhyve_arm64_machdep_source="$src/usr.sbin/bhyve/aarch64/bhyverun_machdep.c"
bhyve_riscv_machdep_source="$src/usr.sbin/bhyve/riscv/bhyverun_machdep.c"
bhyve_config_man="$src/usr.sbin/bhyve/bhyve_config.5"
libvmmapi_makefile="$src/lib/libvmmapi/Makefile"
bhyve_vmexit_source="$src/usr.sbin/bhyve/amd64/vmexit.c"
bhyve_spinup_source="$src/usr.sbin/bhyve/amd64/spinup_ap.c"
live_runner=${VMX_NESTED_LIVE_RUNNER:-$src/tests/sys/vmm/run-vmx-nested-live.sh}
staging_validator="$src/tests/sys/vmm/validate-vmx-nested-live-staging.sh"
policy_pair_validator="$src/tests/sys/vmm/validate-vmx-nested-policy-pair.sh"
review_prompt="$src/tests/sys/vmm/VMX_NESTED_FULL_REVIEW_PROMPT.md"
virtio_roadmap="$src/usr.sbin/bhyve/VIRTIO_1_4_ROADMAP.md"

fail()
{
	echo "nested-vmx requirements: $*" >&2
	exit 1
}

[ -d "$src/sys" ] || fail "source tree not found at $src"
if [ ! -f "$ledger" ]; then
	ledger="$src/tests/sys/vmm/vmx-nested-requirements.tsv"
fi
if [ ! -f "$live_ledger" ]; then
	live_ledger="$src/tests/sys/vmm/vmx-nested-live-qualification.tsv"
fi
if [ ! -f "$default_live_ledger" ]; then
	default_live_ledger="$src/tests/sys/vmm/vmx-nested-default-policy-live-qualification.tsv"
fi
if [ ! -f "$private_ledger" ]; then
	private_ledger="$src/tests/sys/vmm/vmx-nested-nonstandard-interfaces.tsv"
fi
if [ ! -f "$live_coverage" ]; then
	live_coverage="$src/tests/sys/vmm/validate-vmx-nested-live-coverage.sh"
fi
[ -f "$ledger" ] || fail "missing ledger $ledger"
[ -f "$live_ledger" ] || fail "missing live ledger $live_ledger"
[ -f "$default_live_ledger" ] ||
    fail "missing default-policy live ledger $default_live_ledger"
[ -f "$private_ledger" ] ||
    fail "missing non-standard interface ledger $private_ledger"
[ -x "$live_coverage" ] || fail "missing live coverage validator $live_coverage"
[ -f "$corpus" ] || fail "missing reference corpus $corpus"
[ -x "$reference_validator" ] ||
    fail "missing strict reference-corpus validator $reference_validator"
"$reference_validator" "$corpus" --waspnest >/dev/null ||
    fail "reference corpus does not satisfy the WASPNest strict profile"
[ -f "$test_source" ] || fail "missing test source $test_source"
[ -f "$snapshot_test_source" ] ||
    fail "missing snapshot operation test source $snapshot_test_source"
[ -f "$envelope_test_source" ] ||
    fail "missing snapshot envelope test source $envelope_test_source"
[ -f "$event_test_source" ] ||
    fail "missing event-state test source $event_test_source"
[ -f "$ingress_test_source" ] ||
    fail "missing event-ingress test source $ingress_test_source"
[ -f "$ingress_source" ] || fail "missing event-ingress value protocol"
[ -f "$ingress_header" ] || fail "missing event-ingress declaration"
[ -f "$startup_source" ] || fail "missing startup-event value protocol"
[ -f "$startup_header" ] || fail "missing startup-event declaration"
[ -f "$startup_transaction_source" ] ||
    fail "missing nested startup transaction"
[ -f "$startup_transaction_header" ] ||
    fail "missing nested startup transaction declaration"
[ -f "$startup_policy_source" ] ||
    fail "missing nested startup composition policy"
[ -f "$startup_policy_header" ] ||
    fail "missing nested startup composition policy declaration"
[ -f "$startup_dispatch_source" ] ||
    fail "missing durable nested startup dispatch owner"
[ -f "$startup_dispatch_header" ] ||
    fail "missing durable nested startup dispatch declaration"
[ -f "$startup_test_source" ] ||
    fail "missing startup-event test source $startup_test_source"
[ -f "$startup_state_source" ] || fail "missing x86 startup-state planner"
[ -f "$startup_state_header" ] ||
    fail "missing x86 startup-state declaration"
[ -f "$startup_state_test_source" ] ||
    fail "missing x86 startup-state test source"
[ -f "$startup_machine_source" ] ||
    fail "missing x86 startup machine adapter"
[ -f "$startup_machine_header" ] ||
    fail "missing x86 startup machine adapter declaration"
[ -f "$startup_machine_test_source" ] ||
    fail "missing x86 startup machine adapter test source"
[ -f "$startup_vmreg_source" ] ||
    fail "missing x86 startup VM register mapping"
[ -f "$startup_vmreg_header" ] ||
    fail "missing x86 startup VM register mapping declaration"
[ -f "$startup_vmreg_test_source" ] ||
    fail "missing x86 startup VM register mapping test source"
[ -f "$startup_backend_source" ] ||
    fail "missing x86 startup composite backend adapter"
[ -f "$startup_backend_header" ] ||
    fail "missing x86 startup composite backend declaration"
[ -f "$startup_backend_test_source" ] ||
    fail "missing x86 startup composite backend test source"
[ -f "$startup_finalizer_source" ] ||
    fail "missing x86 startup frozen-target finalizer"
[ -f "$startup_finalizer_header" ] ||
    fail "missing x86 startup frozen-target finalizer declaration"
[ -f "$startup_finalizer_test_source" ] ||
    fail "missing x86 startup frozen-target finalizer test source"
[ -f "$startup_handshake_source" ] ||
    fail "missing prestarted-vCPU startup handshake"
[ -f "$startup_handshake_header" ] ||
    fail "missing prestarted-vCPU startup handshake declaration"
[ -f "$startup_handshake_test_source" ] ||
    fail "missing prestarted-vCPU startup handshake test source"
[ -f "$startup_controller_source" ] ||
    fail "missing fd-owned startup controller value protocol"
[ -f "$startup_controller_header" ] ||
    fail "missing fd-owned startup controller declaration"
[ -f "$startup_controller_test_source" ] ||
    fail "missing fd-owned startup controller test source"
[ -f "$startup_run_request_source" ] ||
    fail "missing generation-bearing startup run request value"
[ -f "$startup_run_request_header" ] ||
    fail "missing generation-bearing startup run request declaration"
[ -f "$startup_run_request_test_source" ] ||
    fail "missing generation-bearing startup run request tests"
[ -f "$event_checkpoint_source" ] ||
    fail "missing event-checkpoint group protocol"
[ -f "$event_checkpoint_header" ] ||
    fail "missing event-checkpoint declaration"
[ -f "$snapshot_envelope_source" ] ||
    fail "missing snapshot envelope validation"
[ -f "$event_wait_source" ] || fail "missing event-driven wait protocol"
[ -f "$event_wait_header" ] || fail "missing event-wait declaration"
[ -f "$event_coordinator_source" ] ||
    fail "missing event-checkpoint coordinator"
[ -f "$event_coordinator_header" ] ||
    fail "missing event-checkpoint coordinator declaration"
[ -f "$exception_test_source" ] ||
    fail "missing exception provenance test source $exception_test_source"
[ -f "$transaction_source" ] || fail "missing VMS2 transaction decoder"
[ -f "$x86_state_source" ] || fail "missing VMS2 x86 state codec"
[ -f "$x86_state_header" ] || fail "missing VMS2 x86 state declaration"
[ -f "$cpuid_test_source" ] ||
    fail "missing CPUID policy test source $cpuid_test_source"
[ -f "$manifest" ] || fail "missing qualification manifest $manifest"
[ -f "$module_makefile" ] || fail "missing VMM module makefile"
[ -f "$vmx_source" ] || fail "missing Intel VMX runtime"
[ -f "$svm_source" ] || fail "missing AMD SVM runtime"
[ -f "$vmm_header" ] || fail "missing amd64 VMM operation declarations"
[ -f "$checkpoint_source" ] || fail "missing nested checkpoint codec"
[ -f "$registry_source" ] || fail "missing nested VMCS registry"
[ -f "$registry_state_source" ] ||
    fail "missing nested VMCS registry state codec"
[ -f "$vmcs02_intel_source" ] || fail "missing Intel VMCS02 adapter"
[ -f "$vmcs02_intel_header" ] || fail "missing Intel VMCS02 adapter header"
[ -f "$environment_intel_source" ] ||
    fail "missing Intel nested-entry environment adapter"
[ -f "$vmm_source" ] || fail "missing machine-independent VMM runtime"
[ -f "$vmm_dev_source" ] || fail "missing VMM device runtime"
[ -f "$devfs_vnops_source" ] || fail "missing devfs file-description runtime"
[ -f "$kern_conf_source" ] || fail "missing character-device lifetime runtime"
[ -x "$live_runner" ] || fail "missing nested live qualification runner"
[ -x "$staging_validator" ] ||
    fail "missing nested live staging validator"
[ -x "$policy_pair_validator" ] ||
    fail "missing nested two-boot policy-pair validator"
[ -f "$review_prompt" ] || fail "missing nested review procedure"
rg -q -U --pcre2 \
    '#ifdef BHYVE_SNAPSHOT\s+#include <dev/vmm/vmm_snapshot_envelope.h>\s+#endif' \
    "$vmm_source" ||
    fail "snapshot-enabled VMM omits the snapshot envelope declarations"

# Nested VMX has both an Intel architectural ABI and several private bhyve
# contracts.  Require two independent kernel traversals around the private
# inventory plus a final composition pass; none may be inferred from another.
for phase in \
    'Pass 7: second independent kernel implementation review' \
    'Pass 8: non-standard and experimental interface review' \
    'Pass 9: final kernel replay after private-interface review' \
    'Pass 10: private-interface composition and namespace separation' \
    'Pass 11: second independent non-standard inventory replay' \
    'Pass 12: final cross-layer synthesis' \
    'Pass 13: independent kernel transaction replay' \
    'Pass 14: independent non-standard contract reconciliation' \
    'Pass 15: kernel/private adapter failure-atomicity replay' \
    'Pass 16: withheld, unsupported, and implementation-defined behavior review' \
    'Pass 17: shared-kernel ownership and execution-context review' \
    'Pass 18: non-standard dispatch, compatibility, and operator-policy review' \
    'Pass 19: final-source kernel teardown and publication review' \
    'Pass 20: final-source private ABI and compatibility review' \
    'Pass 21: second final-source kernel implementation review' \
    'Pass 22: second final-source non-standard and private-policy review' \
    'Pass 23: production activation-edge kernel review' \
    'Pass 24: definition-first staged and private activation review' \
    'Pass 25: reverse activation and teardown kernel review' \
    'Pass 26: consumer-first operational and compatibility review' \
	'Pass 27: independent second kernel-code review' \
	'Pass 28: independent non-standard-interface lifecycle review' \
	'Pass 29: second kernel-primitive lifecycle review' \
	'Pass 30: second private-boundary activation review' \
	'Pass 31: doubled kernel callback-context and irreversible-tail review' \
	'Pass 32: doubled non-standard provider and policy-domain review' \
	'Pass 33: independent second kernel-code review' \
	'Pass 34: independent second non-standard-interface review' \
	'Pass 35: post-preparation final kernel-code replay' \
	'Pass 36: post-preparation final non-standard contract replay' \
	'Pass 37: dormant and unsupported kernel-code replay' \
	'Pass 38: implementation-defined and non-standard behavior replay' \
	'Pass 39 must trace the future kernel startup dispatcher' \
	'Pass 40 must rebuild the same boundary' \
	'Pass 41 must trace the notification window' \
	'Pass 42 must independently reconstruct the eventual consumer' \
	'Pass 43 must discard the Pass 41/42 finding list' \
	'Pass 44 must ignore the private ledger initially' \
	'Pass 45 must review the architecture-neutral startup entry runtime model' \
	'Pass 46 must independently review the deferred activation boundary' \
	'Pass 47 must restart the kernel-source review after the final correction' \
	'Pass 48 must perform the matching second non-standard review' \
	'Pass 49: every backend hardware-entry boundary' \
	'Pass 52: first exact hardware-entry kernel traversal' \
	'Pass 53: reverse hardware-unwind kernel traversal' \
	'Pass 54: definition-first private and non-standard replay' \
	'Pass 55: consumer-first private and non-standard replay' \
	'Pass 56: forward composed-entry transaction review' \
	'Pass 57: reverse composed-entry transaction review' \
	'Pass 58: definition-first composed-entry non-standard review' \
	'Pass 59: consumer-first composed-entry non-standard review' \
	'Pass 60: forward stack-owned run transaction' \
	'Pass 61: reverse stack-owned run transaction' \
	'Pass 62: definition-first stack-owner non-standard review' \
	'Pass 63: consumer-first stack-owner non-standard review' \
	'Pass 64: forward cross-owner state-product review' \
	'Pass 65: reverse retirement and destruction review' \
	'Pass 66: definition-first outer-owner private review' \
	'Pass 67: consumer-first outer-owner private review' \
	'Pass 68: first no-entry kernel return review' \
	'Pass 69: independent reverse no-entry kernel review' \
	'Pass 70: definition-first no-entry private-result review' \
	'Pass 71: consumer-first no-entry private-result review' \
	'Pass 72: forward common frozen-admission review' \
	'Pass 73: reverse common return and wait review' \
	'Pass 74: exact VMX, nested-VMX, and SVM placement review' \
	'Pass 75: consumer-first live private-boundary review' \
	'Pass 76: forward frozen-admission transaction review' \
	'Pass 77: reverse frozen-admission transaction review' \
	'Pass 78: definition-first admission private-interface review' \
	'Pass 79: consumer-first admission private-interface review' \
	'Pass 80: post-correction forward kernel entry review' \
	'Pass 81: post-correction reverse kernel entry review' \
	'Pass 82: post-correction definition-first non-standard review' \
	'Pass 83: post-correction consumer-first non-standard review' \
	'Pass 84: second machine-entry activation review' \
	'Pass 85: reverse machine-entry and cleanup review' \
	'Pass 86: dormant and non-standard activation-surface review' \
	'Pass 87: cross-architecture and reference behavior replay' \
	'Pass 88: common frozen-observation and dispatch transaction review' \
	'Pass 89: consumer-first newly-live private-boundary review' \
	'Pass 90: compiled-kernel and dormant-path second traversal' \
	'Pass 91: reverse non-standard contract and containment review' \
	'Pass 92: machine-entry edge matrix review' \
	'Pass 93: implementation-defined boundary and observability review' \
	'Pass 94: restore-residency and derived-cache review' \
	'Pass 95: historical common-record forward kernel review' \
	'Pass 96: historical common-record reverse and non-standard review' \
	'Pass 97: legacy architecture-exception inventory replay' \
	'Pass 98: privileged qualification-runner boundary review' \
	'Pass 99: final independent common-kernel traversal' \
	'Pass 100: final independent non-standard decoder and policy replay' \
	'Pass 101: second independent kernel implementation replay' \
	'Pass 102: implementation-defined and non-standard seam replay' \
	'Pass 103: second reverse kernel-lifetime replay' \
	'Pass 104: second private-policy and observability replay' \
	'Pass 105: terminal kernel callback-current-owner review' \
	'Pass 106: second restore-resource publication review' \
	'Pass 107: opaque-provider transfer and rollback replay' \
	'Pass 108: second common-kernel lifecycle and portability replay' \
	'Pass 109: second non-standard operational and decoder replay' \
	'Pass 110: staged common-owner kernel implementation replay' \
	'Pass 111: staged common-owner non-standard contract replay' \
	'Pass 112: nested VMCS02 owner-conversion feasibility replay' \
	'Pass 113: second kernel execution-path review' \
	'Pass 114: second private-interface and non-standard containment review' \
	'Pass 115: nested guard-result and unwind-outcome composition review' \
	'Pass 116: deferred common-owner commit review' \
	'Pass 117: deferred-owner kernel state-product replay' \
	'Pass 118: deferred-owner private-contract and non-standard review' \
	'Pass 119: post-entry deferred-owner kernel transaction review' \
	'Pass 120: post-entry deferred-owner non-standard containment review' \
	'Pass 121: deferred-owner live-observation boundary review' \
	'Pass 122: nested no-entry disposition and unwind review' \
	'Pass 123: selected-unwind action handoff review' \
	'Pass 124: VMCS02 transaction-boundary completeness review' \
	'Pass 125: second kernel-code and non-standard-boundary review' \
	'Pass 126: independent evidence and portability review' \
	'Pass 127: hardware-attempt versus real-L2-exit classification review' \
	'Pass 128: fail-closed activation and unsupported-surface review' \
	'Pass 129: attempted-entry ownership review' \
	'Pass 130: conclusive no-entry terminal-outcome review' \
	'Pass 131: admission-observation authority review' \
	'Pass 132: classified hardware-attempt settlement review' \
	'Pass 133: private attempted-entry adapter review' \
	'Pass 134: nonstandard private-storage and alias review' \
	'Pass 135: nested private error-domain preservation review' \
	'Pass 136: kernel payload-provenance review' \
	'Pass 137: non-standard payload containment replay' \
	'Pass 138: private representation and ABI-boundary review' \
	'Pass 139: public common-primitives precondition review' \
	'Pass 140: VMX/SVM common-entry parity review' \
	'Pass 141: terminal doubled common-kernel implementation review' \
	'Pass 142: terminal doubled non-standard/private-contract review' \
	'Pass 143: checkpoint and guest-memory kernel transaction replay' \
	'Pass 144: non-standard host-policy and resource-boundary replay' \
	'Pass 145: terminal kernel mutation/rollback replay' \
	'Pass 146: terminal non-standard semantics and observability replay' \
	'Pass 147: withheld-feature reachability and error-domain replay' \
	'Pass 148: independent test-oracle and activation replay'; do
	rg -q -F "$phase" "$review_prompt" ||
	    fail "required nested review phase is missing: $phase"
done
# The terminal cycle is deliberately numbered and ordered.  A textual
# presence check alone would accept an accidental duplicate heading, making
# the review record ambiguous about which pass is the terminal one.
for number in 99 100 101 102 103 104 105 106 107 108 109 110 111 112 113 114 115 116 117 118 119 120 121 122 123 124 125 126 127 128 129 130 131 132 133 134 135 136 137 138 139 140 141 142 143 144 145 146 147 148; do
	count=$(rg -c "^## Pass ${number}:" "$review_prompt")
	[ "$count" -eq 1 ] ||
	    fail "nested review phase ${number} must occur exactly once"
done
rg -q -F 'Any correction restarts Passes 99 through' "$review_prompt" ||
    fail "terminal callback-owner review restart rule is missing"
rg -q -F 'synthesis must reconcile this' \
    "$review_prompt" ||
    fail "terminal restore-resource review synthesis is missing"
rg -q -U 'duplicate object\s+identity is not proof' "$review_prompt" ||
    fail "opaque-provider transfer review is missing"
rg -q -F 'every explicit `ENOTSUP` return' "$review_prompt" ||
    fail "non-standard fail-closed inventory review is missing"
rg -q -F 'production correction restarts both kernel passes' \
    "$review_prompt" || fail "nested review restart rule is missing"
rg -q -F 'untracked production or test files' "$review_prompt" ||
    fail "final-source review manifest does not include untracked sources"
rg -q -F 'git diff --name-only' "$review_prompt" ||
    fail "final-source review does not reject diff-only manifests"
echo "nested-vmx requirements: doubled kernel and private-boundary reviews required"

# Every deliberate nested-VMX feature gate must have a private-contract
# mapping.  This prevents a newly added unsupported path from being mistaken
# for a conforming implementation or drifting outside the review inventory.
# Do not limit this to a literal `return (ENOTSUP)`: staged cleanup commonly
# records ENOTSUP/EOPNOTSUPP in a local error before it reaches the shared
# rollback tail, and that deferred form is just as much a private contract.
# private-test: explicit-ENOTSUP-inventory
for unsupported_source in $(rg -l '\b(ENOTSUP|EOPNOTSUPP)\b' \
    "$src/sys/amd64/vmm/intel"/vmx*.c | sort); do
	unsupported_base=${unsupported_source##*/}
	rg -q -F "$unsupported_base" "$private_ledger" ||
	    fail "nested fail-closed source lacks private-ledger mapping: $unsupported_base"
done

# A destroyed EPT02 cache remains a usable derived-cache container, but stale
# by-value references must never resolve a same-slot replacement.  Keep this
# regression in the independent model source so a cleanup simplification
# cannot reset the generation clock and reintroduce an ABA-style alias.
rg -q -F 'Destruction retires every root but deliberately preserves the monotonic' \
    "$test_source" ||
    fail "nested EPT cache destroy/reuse stale-reference regression is missing"
rg -q -F 'second_ref.generation > stale.generation' "$test_source" ||
    fail "nested EPT cache reuse does not prove monotonic stale rejection"

# EPT reflection carries optional GLA state between private handoff stages.
# An absent GLA must be canonical before a prospective VMCS12 exit is built;
# otherwise malformed private state can be accepted merely because the output
# path happens to discard it.
rg -q -U --pcre2 \
    '!result->guest_linear_address_valid &&\s*result->guest_linear_address != 0' \
    "$src/sys/amd64/vmm/intel/vmx_nested_ept_reflect.c" ||
    fail "nested EPT reflection accepts noncanonical absent GLA state"
rg -q -F 'result.guest_linear_address_valid = false;' "$test_source" ||
    fail "nested EPT reflection absent-GLA rejection regression is missing"
rg -q -U --pcre2 \
    'guest_linear_address_valid = false;\s*ATF_CHECK_EQ\(vmx_nested_ept_reflection_information\(&result,\s*&source, &reflection\), EPROTO\)' \
    "$test_source" ||
    fail "nested EPT reflection absent-GLA regression lacks EPROTO proof"
rg -q -U --pcre2 \
    'VMX_NESTED_EPT_FAULT_POPULATE;\s*reflection = before;\s*ATF_CHECK_EQ\(vmx_nested_ept_reflection_information\(&result,\s*&source, &reflection\), ENOTSUP\);\s*ATF_CHECK_EQ\(memcmp\(&reflection, &before, sizeof\(reflection\)\), 0\)' \
    "$test_source" ||
    fail "nested EPT reflection unsupported-action regression lacks output-preservation proof"

for phase in \
    'Second common-kernel primitive lifecycle review' \
    'Second private/non-standard activation-boundary review' \
	'nested-VMX review Passes 29 and 30' \
	'Post-preparation final kernel-code replay' \
	'Post-preparation final non-standard contract replay' \
	'nested-VMX review Pass 35' \
	'nested-VMX review Pass 36' \
	'nested-VMX review Pass 37' \
	'nested-VMX review Pass 38' \
	'Kernel vCPU-entry integration review' \
	'Reverse non-standard entry-boundary review' \
	'Frozen-to-running notification-window review' \
	'Entry-transition unwind and fairness review' \
	'Second final-source kernel integration review' \
	'Second final-source non-standard behavior review' \
	'Architecture-neutral entry-unwind model review' \
	'Deferred activation and private-policy review' \
	'Post-correction kernel replay' \
	'Post-correction non-standard replay' \
	'Every-hardware-entry guard review' \
	'Post-correction forward kernel entry review' \
	'Post-correction reverse kernel entry review' \
	'Post-correction definition-first non-standard review' \
	'Post-correction consumer-first non-standard review' \
	'Second machine-entry activation review' \
	'Reverse machine-entry activation review' \
	'Dormant and non-standard activation-surface review' \
	'Cross-architecture and reference comparison replay' \
	'Compiled-kernel and dormant-path second traversal' \
	'Reverse non-standard contract and containment review' \
	'Machine-entry edge matrix review' \
	'Implementation-defined boundary and observability review' \
	'Restore-residency and derived-cache review'; do
	rg -q -F "$phase" "$virtio_roadmap" ||
	    fail "VirtIO roadmap is missing doubled review phase: $phase"
done

for contract in \
    'not an ingress lease' \
    'must not be silently dropped' \
    'must not silently acquire current semantics' \
    'fall back to a legacy decoder'; do
	rg -q -F "$contract" "$review_prompt" ||
	    fail "expanded kernel/private review contract is missing: $contract"
done

# private-test: event-ingress-lease-value-protocol
# The generic lease is a non-blocking, externally synchronized value protocol.
# It is deliberately not production VMS2 dispatch: the architecture adapter
# must still classify every publisher and merge deferred idempotent work.
for symbol in \
    VMM_EVENT_INGRESS_OPEN \
    VMM_EVENT_INGRESS_DRAINING \
    VMM_EVENT_INGRESS_QUIESCED \
    vmm_event_ingress_publisher_enter \
    vmm_event_ingress_publisher_exit \
    vmm_event_ingress_quiesce_begin \
    vmm_event_ingress_defer_idempotent \
    vmm_event_ingress_quiesce_finish \
    vmm_event_ingress_quiesce_abort; do
	rg -q -F "$symbol" "$ingress_source" "$ingress_header" ||
	    fail "event-ingress protocol is missing: $symbol"
done
if rg -q -F 'invalidate_translations' "$startup_finalizer_header" \
    "$startup_finalizer_source" "$startup_machine_source"; then
	fail "startup finalizer retains ambiguous VM-wide translation wording"
fi
rg -q -F 'Retire only this vCPU' "$startup_finalizer_header" ||
    fail "startup finalizer lacks vCPU-local translation residency scope"
rg -q 'NVMX-EVENT-100.*INIT retires only vCPU translation residency' \
    "$ledger" || fail "INIT translation-residency requirement is missing"
rg -q 'NVMX-PRIVATE-156.*retire-translation-residency' \
    "$private_ledger" ||
    fail "translation residency private contract is missing"
rg -q 'NVMX-EVENT-101.*BSP remains runnable after legacy and kernel-owned INIT' \
    "$ledger" || fail "BSP INIT startup-state requirement is missing"
rg -q 'NVMX-PRIVATE-157.*exact-target-startup-state-publication' \
    "$private_ledger" ||
    fail "exact target startup-state private contract is missing"
rg -q 'NVMX-EVENT-102.*Userspace-owned BSP INIT gap blocks activation' \
    "$ledger" || fail "userspace-owned BSP INIT gap is missing"
rg -q 'NVMX-PRIVATE-158.*withheld-userspace-BSP-INIT-workaround' \
    "$private_ledger" ||
    fail "unsafe userspace BSP INIT workaround is not classified"
# private-test: startup-transaction-outcome-composition
for contract in \
	'VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID' \
	'VMM_X86_STARTUP_TRANSACTION_OUTCOME_COMMITTED' \
	'VMM_X86_STARTUP_TRANSACTION_OUTCOME_ROLLED_BACK' \
	'VMM_X86_STARTUP_TRANSACTION_OUTCOME_POISONED' \
	'vmm_x86_startup_transaction_result_classify'; do
	rg -q -F "$contract" "$startup_execution_header" \
	    "$startup_execution_source" ||
	    fail "startup transaction outcome contract is missing: $contract"
done
for contract in \
	'error < 0 || result == NULL' \
	'result->committed > 1' \
	'result->rollback_complete > 1' \
	'result->poisoned > 1' \
	'result->reserved8 != 0' \
	'result->reserved32 != 0' \
	'result->committed == 1 && result->rollback_complete == 1' \
	'result->poisoned != 0' \
	'result->rollback_complete == 1'; do
	rg -q -F "$contract" "$startup_execution_source" ||
	    fail "startup outcome classifier omits: $contract"
done
rg -q 'ATF_TC_WITHOUT_HEAD\(result_outcome_classification\)' \
	"$startup_execution_test_source" ||
	fail "startup outcome classifier lacks an independent model test"
rg -q 'NVMX-EVENT-104.*Nested startup transaction outcome composition' \
	"$ledger" || fail "startup outcome composition requirement is missing"
rg -q 'NVMX-PRIVATE-162.*composable-result-outcome' "$private_ledger" ||
	fail "startup outcome composition private contract is missing"
# private-test: nested-restore-publication-storage-graph
for contract in \
	'vmx_nested_vmcs_registry_storage_overlaps(destination, workspaces' \
	'vmx_nested_vmcs_registry_storage_overlaps(replacement, workspaces' \
	'workspaces[i].workspace, sizeof(*workspaces[i].workspace)' \
	'workspaces[i].capabilities' \
	'vmx_nested_state_ranges_overlap(workspaces, binding_bytes' \
	'rollback_failed = true' \
	'Preserve the generation which still names the owner.' \
	'panic("%s: validated nested restore rollback failed"'; do
	rg -q -F "$contract" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_restore_transaction.c" ||
	    fail "nested restore storage graph omits: $contract"
done
rg -q -F 'destination_entry, 1), EINVAL' "$test_source" ||
	fail "nested restore lacks registry-resident binding-table rejection"
rg -q 'NVMX-PRIVATE-163.*registry-publication-rollback-storage' \
	"$private_ledger" ||
	fail "nested restore storage graph private contract is missing"
# private-test: nested-restore-destination-runtime-fence
for contract in \
    'vmx_nested_snapshot_destination_validate(struct vmx_vcpu *vcpu)' \
    'vmx_nested_context_quiesce(&vcpu->nested)' \
    'VMX_NESTED_STARTUP_DISPATCH_EMPTY' \
    'VMX_NESTED_L2_THAW_STAGED_IDLE' \
    'VMX_NESTED_REFREEZE_IDLE' \
    'vmx_nested_ept_binding_validate(&vcpu->nested_ept_binding)' \
	'vmx_nested_ept_cache_owner_quiesce(vcpu)' \
    'vmx_nested_vmcs02_intel_inactive_validate(' \
    'vmx_nested_vmcs02_lease_owner_validate(' \
    'vmx_nested_vpid_restore_destination_validate(' \
    'vmx_nested_mtf_owner_validate(&vcpu->nested_mtf_owner)' \
    'vmx_nested_exit_msr_transaction_validate(' \
    'VMX_NESTED_HARDWARE_MSR_NONE' \
    'VMX_NESTED_TSC_AUX_L1'; do
	rg -q -F "$contract" "$vmx_source" ||
	    fail "nested restore destination fence omits: $contract"
done
rg -q -U --pcre2 \
    'vmx_nested_snapshot_destination_validate\([\s\S]*?vmx_nested_ept_cache_destroy\([\s\S]*?vmx_nested_restore_transaction_commit\(' \
    "$vmx_source" ||
    fail "nested EPT cache is not retired before restore publication"
rg -q -U --pcre2 \
    'vmx_nested_snapshot_destination_validate\([\s\S]*?vmx_nested_restore_transaction_commit\(' \
    "$vmx_source" ||
    fail "nested restore publishes before validating destination runtime"
rg -q 'NVMX-EVENT-107.*Complete destination runtime fence before restore' \
    "$ledger" || fail "nested restore destination-fence requirement is missing"
rg -q 'NVMX-PRIVATE-166.*restore-destination-runtime-fence' \
    "$private_ledger" ||
    fail "nested restore destination-fence private contract is missing"
# private-test: nested-restore-exact-topology-binding
for contract in \
    'vm_vcpu(vcpu->vmx->vm, vcpu->vcpuid) != vcpu->vcpu' \
    'generic_vcpu == NULL && (stage->vcpus[i].valid ||' \
    'stage->vcpus[i].vcpu->vmx != vmx' \
    'stage->vcpus[i].vcpu->vcpu != generic_vcpu' \
    'stage->vcpus[i].vcpu->vcpuid != i'; do
	rg -q -F "$contract" "$vmx_source" ||
	    fail "nested restore topology binding omits: $contract"
done
topology_line=$(rg -n -F \
    'generic_vcpu == NULL && (stage->vcpus[i].valid ||' "$vmx_source" |
    head -n 1 | cut -d: -f1)
cache_line=$(rg -n -F 'vmx_nested_ept_cache_destroy(' "$vmx_source" |
    tail -n 1 | cut -d: -f1)
commit_line=$(rg -n -F 'vmx_nested_restore_transaction_commit(' \
    "$vmx_source" | tail -n 1 | cut -d: -f1)
[ -n "$topology_line" ] && [ -n "$cache_line" ] && [ -n "$commit_line" ] &&
    [ "$topology_line" -lt "$cache_line" ] &&
    [ "$topology_line" -lt "$commit_line" ] ||
    fail "nested restore topology is checked after runtime or architectural mutation"
rg -q 'NVMX-EVENT-110.*Exact nested restore topology binding' "$ledger" ||
    fail "nested restore topology requirement is missing"
rg -q 'NVMX-PRIVATE-171.*nested-restore-exact-topology-binding' \
    "$private_ledger" ||
    fail "nested restore topology private contract is missing"
# private-test: nested-snapshot-source-runtime-fence
for contract in \
    'vmx_nested_snapshot_source_validate(struct vmx_vcpu *vcpu, bool active_l2)' \
	'vmx_nested_context_quiesce(&vcpu->nested)' \
	'vmx_nested_context_guest_continuation_validate(' \
    'vmx_nested_startup_dispatch_validate(' \
    'vmx_nested_ept_cache_owner_quiesce(vcpu)' \
    'vmx_nested_vmcs02_intel_inactive_validate(' \
    'vmx_nested_vmcs02_lease_owner_validate(' \
    'vmx_nested_vpid_owner_validate(&vcpu->nested_vpid_owner)' \
    'vmx_nested_exit_msr_transaction_validate(' \
    'vcpu->nested_tsc_aux_rollback_residency !=' \
    'vmx_nested_snapshot_source_validate(vcpu, active_l2)'; do
	rg -q -F "$contract" "$vmx_source" ||
	    fail "nested snapshot source fence omits: $contract"
done
rg -q -U --pcre2 \
    'active_l2 = vcpu->nested_vmcs02_plan_valid;[\s\S]*?vmx_nested_snapshot_source_validate\(vcpu, active_l2\);[\s\S]*?vmx_snapshot_vmcs_state\(' \
    "$vmx_source" ||
    fail "nested snapshot writes VMCS state before source runtime validation"
rg -q 'NVMX-EVENT-108.*Complete source runtime fence before snapshot' \
    "$ledger" || fail "nested snapshot source-fence requirement is missing"
rg -q 'NVMX-PRIVATE-167.*snapshot-source-runtime-fence' \
    "$private_ledger" ||
    fail "nested snapshot source-fence private contract is missing"
rg -q 'NVMX-EVENT-111.*Source context validated before VMCS serialization' \
    "$ledger" || fail "early source-context requirement is missing"
rg -q 'NVMX-PRIVATE-172.*snapshot-source-context-prefence' \
    "$private_ledger" ||
    fail "early source-context private contract is missing"
# private-test: typed-vmcs02-inactive-validation
rg -q -F 'vmx_nested_vmcs02_intel_inactive_validate(' \
    "$vmcs02_intel_header" ||
    fail "VMCS02 inactive ownership has no typed validator"
rg -q -F 'vmx_nested_vmcs02_intel_inactive_validate(&adapter)' \
    "$test_source" ||
    fail "typed VMCS02 inactive validation has no negative model"
rg -q 'NVMX-EVENT-109.*Typed inactive VMCS02 ownership validation' \
    "$ledger" || fail "typed inactive VMCS02 requirement is missing"
rg -q 'NVMX-PRIVATE-168.*typed-inactive-VMCS02-owner' \
    "$private_ledger" ||
    fail "typed inactive VMCS02 private contract is missing"
for contract in \
    'owner_id is a lifetime incarnation' \
    'state->storage_cookie != (uintptr_t)state' \
	'ticket->state_cookie != (uintptr_t)state' \
    'ticket->storage_cookie != (uintptr_t)ticket' \
	'lease->state_cookie != (uintptr_t)state' \
    'lease->storage_cookie != (uintptr_t)lease' \
    'state->active_publishers == UINT32_MAX' \
    'state->last_lease_id == UINT64_MAX' \
    'state->publisher_generation == UINT64_MAX'; do
	rg -q -F "$contract" "$ingress_source" "$ingress_header" ||
	    fail "event-ingress ownership boundary is missing: $contract"
done
for test_case in lifecycle immediate_and_abort transactional_failures \
    overflow_and_validation cross_state_isolation; do
	rg -q -F "$test_case" "$ingress_test_source" ||
	    fail "event-ingress protocol test is missing: $test_case"
done
rg -q -F 'vmm_event_ingress.c' "$module_makefile" ||
    fail "event-ingress protocol is not architecture-neutral VMM code"

# private-test: startup-event-value-protocol
# This is bounded architecture-neutral provenance for a future INIT/SIPI
# adapter.  It is not yet production APIC or nested-VMX wiring and therefore
# cannot make MTF or nested INIT/SIPI visible to a guest.
for symbol in \
    VMM_STARTUP_EVENT_PENDING_INIT \
    VMM_STARTUP_EVENT_PENDING_SIPI \
    vmm_startup_event_publish_init \
    vmm_startup_event_publish_sipi \
    vmm_startup_event_peek \
    vmm_startup_event_consume \
    vmm_startup_event_reset; do
	rg -q -F "$symbol" "$startup_source" "$startup_header" ||
	    fail "startup-event protocol is missing: $symbol"
done
for contract in \
    'state->storage_cookie != (uintptr_t)state' \
    'receipt->state_cookie != (uintptr_t)state' \
    'receipt->storage_cookie != (uintptr_t)receipt' \
    'receipt->generation != state->generation' \
    'state->pending = VMM_STARTUP_EVENT_PENDING_INIT' \
    'state->pending |= VMM_STARTUP_EVENT_PENDING_SIPI' \
    'state->generation == UINT64_MAX'; do
	rg -q -F "$contract" "$startup_source" ||
	    fail "startup-event ownership boundary is missing: $contract"
done
for test_case in order_and_coalescing stale_and_cross_owner \
    failure_atomicity overflow_and_reset; do
	rg -q -F "$test_case" "$startup_test_source" ||
	    fail "startup-event protocol test is missing: $test_case"
done
rg -q -F 'vmm_startup_event.c' "$module_makefile" ||
    fail "startup-event protocol is not architecture-neutral VMM code"
rg -q 'NVMX-EVENT-031.*startup-event-value-protocol' "$ledger" ||
    fail "startup-event protocol is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-089.*startup-event-value-protocol' "$private_ledger" ||
    fail "startup-event protocol is absent from the private ledger"

# private-test: startup-event-publish-claim-atomicity
# A future multi-target delivery transaction cannot first publish and later
# claim: failure on a later target would otherwise expose a partial broadcast.
# This single-state primitive builds both mutations in private storage and
# commits only after both finite identities have been preflighted.
for contract in \
    'vmm_startup_event_publish_claim(' \
    'candidate_state = *state' \
    'candidate_state.storage_cookie = (uintptr_t)&candidate_state' \
    'vmm_startup_event_claim_begin(&candidate_state' \
    'candidate_state.storage_cookie = (uintptr_t)state' \
    'candidate_claim.state_cookie = (uintptr_t)state' \
    'candidate_claim.storage_cookie = (uintptr_t)claim'; do
	rg -q -F "$contract" "$startup_source" "$startup_header" ||
	    fail "startup publish+claim atomicity is missing: $contract"
done
rg -q 'ATF_TC_WITHOUT_HEAD\(publish_claim_atomicity\)' \
    "$startup_test_source" ||
    fail "startup publish+claim lacks an independent atomicity test"
rg -q 'NVMX-EVENT-037.*Failure-atomic startup publication and claim' \
    "$ledger" ||
    fail "startup publish+claim atomicity is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-095.*startup-event-publish-claim-atomicity' \
    "$private_ledger" ||
    fail "startup publish+claim atomicity is absent from the private ledger"

# private-test: coordinator-cancel-entry-interlock
# Startup operations do not carry publisher tickets, so cancellation must
# close admission under the same entry locks used by their final ready check.
for contract in \
    'vmm_event_coordinator_close_admission(' \
    'atomic_store_rel_int(&coordinator->cancelled, 1)' \
    'vmm_event_coordinator_close_admission(coordinator);'; do
	rg -q -F "$contract" "$event_coordinator_source" ||
	    fail "coordinator cancellation interlock is missing: $contract"
done
python3 - "$event_coordinator_source" <<'PY' ||
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text()
start = text.index("\nvmm_event_coordinator_close_admission(")
opening = text.index("{", start)
depth = 0
for end in range(opening, len(text)):
    if text[end] == "{":
        depth += 1
    elif text[end] == "}":
        depth -= 1
        if depth == 0:
            break
body = text[opening:end + 1]
lock = body.index("mtx_lock_spin")
close = body.index("atomic_store_rel_int")
unlock = body.index("mtx_unlock_spin")
assert lock < close < unlock
assert "i < coordinator->maxcpus" in body
assert "i = coordinator->maxcpus; i > 0; i--" in body
PY
    fail "coordinator cancellation is not interlocked in stable lock order"
rg -q 'NVMX-EVENT-038.*Cancellation and startup admission serialization' \
    "$ledger" ||
    fail "coordinator cancellation interlock is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-096.*coordinator-cancel-entry-interlock' \
    "$private_ledger" ||
    fail "coordinator cancellation interlock is absent from the private ledger"

# private-test: startup-event-multitarget-atomic-claim
# Membership must be strictly ordered, all target owners must remain held
# across private trials and commit, and no recoverable error may remain once
# the first target is changed.
for contract in \
    'vmm_event_coordinator_startup_publish_claim_batch(' \
    'vmm_event_coordinator_instances_validate(coordinator, instances' \
    'vmm_event_coordinator_lock_entries(coordinator, instances, count)' \
    'trial_state = entry->startup' \
    'trial_state.storage_cookie = (uintptr_t)&trial_state' \
    'trial_claim = claims[i]' \
    'panic("%s: startup commit failed after preflight: %d"' \
    'vmm_event_coordinator_unlock_entries(coordinator, instances, count)'; do
	rg -q -F "$contract" "$event_coordinator_source" \
	    "$event_coordinator_header" ||
	    fail "multi-target startup claim boundary is missing: $contract"
done
python3 - "$event_coordinator_source" <<'PY' ||
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text()
start = text.index("\nvmm_event_coordinator_startup_publish_claim_batch(")
opening = text.index("{", start)
depth = 0
for end in range(opening, len(text)):
    if text[end] == "{":
        depth += 1
    elif text[end] == "}":
        depth -= 1
        if depth == 0:
            break
body = text[opening:end + 1]
lock = body.index("vmm_event_coordinator_lock_entries")
trial = body.index("trial_state = entry->startup")
commit = body.index("commit_error = vmm_startup_event_publish_claim")
unlock = body.index("vmm_event_coordinator_unlock_entries")
assert lock < trial < commit < unlock
assert "if (error == 0)" in body[trial:commit]
assert "panic(" in body[commit:unlock]
PY
    fail "multi-target startup claim is not one locked preflight/commit"
rg -q 'NVMX-EVENT-039.*All-target startup publication and claim atomicity' \
    "$ledger" ||
    fail "multi-target startup claim is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-097.*startup-event-multitarget-atomic-claim' \
    "$private_ledger" ||
    fail "multi-target startup claim is absent from the private ledger"

# private-test: startup-event-multitarget-atomic-publish
# Persistent target-local publication is the safe foundation for delivery
# which can outlive an initiating rendezvous stack.  It must be all-target
# failure-atomic and must not export transient claim storage.
for contract in \
    'vmm_event_coordinator_startup_publish_set(' \
    'CPU_FOREACH_ISSET(i, instances)' \
	'last = i + 1' \
    'mtx_lock_spin(&coordinator->entry[i].lock)' \
    'trial_state = entry->startup' \
    'trial_state.storage_cookie = (uintptr_t)&trial_state' \
    'vmm_event_coordinator_startup_publish_value(&trial_state' \
    'panic("%s: startup commit failed after preflight: %d"' \
	'for (i = last; i > 0; i--)' \
    'mtx_unlock_spin(&coordinator->entry[i - 1].lock)'; do
	rg -q -F "$contract" "$event_coordinator_source" \
	    "$event_coordinator_header" ||
	    fail "multi-target startup publication is missing: $contract"
done
python3 - "$event_coordinator_source" <<'PY' ||
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text()
start = text.index("\nvmm_event_coordinator_startup_publish_set(")
opening = text.index("{", start)
depth = 0
for end in range(opening, len(text)):
    if text[end] == "{":
        depth += 1
    elif text[end] == "}":
        depth -= 1
        if depth == 0:
            break
body = text[opening:end + 1]
lock = body.index("mtx_lock_spin")
trial = body.index("trial_state = entry->startup")
commit = body.index("commit_error =")
unlock = body.index("mtx_unlock_spin")
assert lock < trial < commit < unlock
assert "if (error == 0)" in body[trial:commit]
assert "panic(" in body[commit:unlock]
assert "vmm_startup_event_claim" not in body
assert "malloc" not in body
PY
    fail "multi-target startup publication is not one claim-free locked transaction"
for contract in \
	'CPU_COPY(targets, &stable_targets)' \
	'target = vm_vcpu(vm, i)' \
	'vmm_event_coordinator_startup_publish_set(' \
	'vcpu_notify_startup_event(vm_vcpu(vm, i))' \
    'vm_startup_event_publish_init_set(' \
    'vm_startup_event_publish_sipi_set('; do
	rg -q -F "$contract" "$vmm_vm_source" ||
	    fail "VM startup publication adapter is missing: $contract"
done
python3 - "$vmm_vm_source" <<'PY' ||
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text()
start = text.index("\nvm_startup_event_publish_set(")
opening = text.index("{", start)
depth = 0
for end in range(opening, len(text)):
    if text[end] == "{":
        depth += 1
    elif text[end] == "}":
        depth -= 1
        if depth == 0:
            break
body = text[opening:end + 1]
copy = body.index("CPU_COPY")
preflight = body.index("target = vm_vcpu")
publish = body.index("vmm_event_coordinator_startup_publish_set")
notify = body.index("vcpu_notify_startup_event")
assert copy < preflight < publish < notify
assert "malloc" not in body
PY
    fail "VM startup publication adapter does not preflight then publish then notify"
rg -q 'NVMX-EVENT-043.*All-target durable startup publication without caller claims' \
    "$ledger" ||
    fail "multi-target startup publication is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-100.*startup-event-multitarget-atomic-publish' \
    "$private_ledger" ||
    fail "multi-target startup publication is absent from the private ledger"

# private-test: startup-event-coordinator-ownership
# The common coordinator owns one startup state under the same per-vCPU spin
# owner as checkpoint admission.  Until startup events have a versioned image,
# a pending value is a recoverable checkpoint blocker, never silently omitted.
for contract in \
    'struct vmm_startup_event_state startup;' \
    'vmm_startup_event_init(&coordinator->entry[i].startup' \
    'vmm_event_coordinator_startup_publish_init' \
    'vmm_event_coordinator_startup_publish_sipi' \
	'vmm_event_coordinator_startup_claim_begin' \
	'vmm_event_coordinator_startup_claim_finish' \
	'vmm_event_coordinator_startup_claim_abort' \
    'vmm_startup_event_reset(' \
    'startup.pending !=' \
    'error = EBUSY;'; do
	rg -q -F "$contract" "$event_coordinator_source" \
	    "$event_coordinator_header" ||
	    fail "startup-event coordinator boundary is missing: $contract"
done
if rg -q 'vmm_event_coordinator_startup_(peek|consume)' \
    "$event_coordinator_source" "$event_coordinator_header"; then
    fail "unlocked coordinator startup receipt API is exposed"
fi
for contract in \
    'vmm_startup_event_claim_begin' \
    'vmm_startup_event_claim_finish' \
    'vmm_startup_event_claim_abort' \
    'startup.active_claim_id != 0' \
    'startup.active_claim_id != 0)'; do
	rg -q -F "$contract" "$startup_source" \
	    "$startup_header" "$event_coordinator_source" \
	    "$event_coordinator_header" ||
	    fail "startup claim ownership is missing: $contract"
done
rg -q 'NVMX-EVENT-033.*startup-event claim lease' "$ledger" ||
    fail "startup claim lease is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-091.*startup-event-claim-lease' "$private_ledger" ||
    fail "startup claim lease is absent from the private ledger"
if sed -n '/^vmm_startup_event_claim_end(/,/^}/p' "$startup_source" |
    rg -q 'generation'; then
    fail "startup claim release consumes a publication generation"
fi
for contract in \
    'vcpu_startup_event_publish_init' \
    'vcpu_startup_event_publish_sipi' \
    'vcpu_startup_event_claim_begin' \
    'vcpu_startup_event_claim_finish' \
    'vcpu_startup_event_claim_abort'; do
	rg -q -F "$contract" "$src/sys/dev/vmm/vmm_vm.c" \
	    "$src/sys/dev/vmm/vmm_vm.h" ||
	    fail "startup vCPU notification boundary is missing: $contract"
done
python3 - "$src/sys/dev/vmm/vmm_vm.c" <<'PY' ||
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text()

def body(name):
    start = text.index("\n" + name + "(")
    opening = text.index("{", start)
    depth = 0
    for pos in range(opening, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[opening:pos + 1]
    raise AssertionError(name + " has no closing brace")

for name, call in (
    ("vcpu_startup_event_publish_init",
     "vmm_event_coordinator_startup_publish_init"),
    ("vcpu_startup_event_publish_sipi",
     "vmm_event_coordinator_startup_publish_sipi"),
):
    source = body(name)
    assert source.index(call) < source.index("vcpu_notify_startup_event")

source = body("vcpu_startup_event_claim_end")
assert source.index("vmm_event_coordinator_startup_claim_abort") < \
    source.index("vcpu_notify_startup_event")
assert source.index("vmm_event_coordinator_startup_claim_finish") < \
    source.index("vcpu_notify_startup_event")
assert "vcpu_notify_startup_event" not in \
    body("vcpu_startup_event_claim_begin")
PY
    fail "startup vCPU notification is not ordered after coordinator release"
rg -q 'NVMX-EVENT-034.*Event-driven startup publication' "$ledger" ||
    fail "startup vCPU notification is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-092.*startup-event-vcpu-notification' \
    "$private_ledger" ||
    fail "startup vCPU notification is absent from the private ledger"
for contract in \
    'enum vmx_nested_startup_action' \
    'VMX_NESTED_STARTUP_NONE' \
    'VMX_NESTED_STARTUP_ACTION_APPLY_L0' \
    'VMX_NESTED_STARTUP_ACTION_REFLECT_L1' \
    'VMX_NESTED_STARTUP_ACTION_RETAIN_RETRY' \
    'VMX_NESTED_STARTUP_ACTION_DISCARD' \
    'vmx_nested_startup_plan(' \
    'vmx_nested_startup_plan_validate('; do
	rg -q -F "$contract" "$src/sys/amd64/vmm/intel/vmx_nested_event.c" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_event.h" ||
	    fail "nested startup value plan is missing: $contract"
done
rg -q 'ATF_TC_WITHOUT_HEAD\(nested_startup_arbitration\)' \
    "$test_source" ||
    fail "nested startup value plan lacks an independent model test"
if rg -q -F 'vmx_nested_startup_plan(' "$vmx_source"; then
    fail "nested startup value plan was wired before its commit boundary"
fi
rg -q 'NVMX-EVENT-035.*nested INIT and SIPI arbitration' "$ledger" ||
    fail "nested startup value plan is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-093.*nested-startup-value-plan' "$private_ledger" ||
    fail "nested startup value plan is absent from the private ledger"
# private-test: nested-startup-vmx-operation
for contract in \
    'candidate.vmx_operation = context->machine.vmxon' \
    'input->kind == VMX_NESTED_STARTUP_INIT' \
    'VMX_NESTED_STARTUP_ACTION_RETAIN_RETRY' \
    'VMX_NESTED_STARTUP_ACTION_DISCARD'; do
	rg -q -F "$contract" "$src/sys/amd64/vmm/intel/vmx_nested_event.c" ||
	    fail "VMX-operation startup classification is missing: $contract"
done
rg -q 'NVMX-EVENT-044.*VMX-operation startup-event disposition' "$ledger" ||
    fail "VMX-operation startup disposition is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-101.*startup-event-VMX-operation-classification' \
    "$private_ledger" ||
    fail "VMX-operation startup classification is absent from the private ledger"
# private-test: nested-startup-discard-provenance
for contract in \
    'candidate.active_l2 = input->active_l2' \
    'input->active_l2 && input->nested_entry_pending' \
    '!plan->active_l2 && plan->consume_claim' \
    '!plan->active_l2 || !plan->consume_claim' \
    'plan->kind == VMX_NESTED_STARTUP_SIPI &&' \
    '!plan->discard_mtf ? 0 : EINVAL' \
    'transaction->plan.active_l2 ?'; do
	rg -q -F "$contract" "$src/sys/amd64/vmm/intel/vmx_nested_event.c" \
	    "$startup_transaction_source" ||
	    fail "startup discard provenance is missing: $contract"
done
rg -q -F 'a->active_l2 == b->active_l2' \
    "$src/sys/amd64/vmm/intel/vmx_nested_cold_reflect.c" ||
    fail "cold startup comparison omits active-L2 provenance"
rg -q 'NVMX-EVENT-045.*Startup discard ownership provenance' "$ledger" ||
    fail "startup discard provenance is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-102.*startup-discard-provenance' "$private_ledger" ||
    fail "startup discard provenance is absent from the private ledger"
# private-test: nested-startup-transaction
for contract in \
	'VMX_NESTED_STARTUP_TRANSACTION_PLANNED' \
	'VMX_NESTED_STARTUP_TRANSACTION_EXECUTING' \
	'VMX_NESTED_STARTUP_TRANSACTION_RETAINED' \
	'VMX_NESTED_STARTUP_TRANSACTION_FINISH_PENDING' \
	'VMX_NESTED_STARTUP_TRANSACTION_RELEASING' \
    'VMX_NESTED_STARTUP_TRANSACTION_POISONED' \
	'vmx_nested_startup_transaction_begin(' \
	'vmx_nested_startup_transaction_replan(' \
    'vmx_nested_startup_transaction_execute(' \
    'vmx_nested_startup_transaction_release(' \
    'vmx_nested_startup_transaction_resolve('; do
	rg -q -F "$contract" "$startup_transaction_source" \
	    "$startup_transaction_header" ||
	    fail "nested startup transaction is missing: $contract"
done
rg -q -F 'transaction->state = VMX_NESTED_STARTUP_TRANSACTION_POISONED' \
    "$startup_transaction_source" ||
    fail "nested startup transaction lacks a fail-closed poisoned state"
rg -q -F 'retry only claim_finish without executing the side effect again' \
    "$startup_transaction_source" ||
    fail "nested startup transaction cannot retry exact claim release"
if rg -q -F 'claim_abort' "$startup_transaction_source" \
    "$startup_transaction_header"; then
    fail "nested startup retry still releases and reacquires the exact claim"
fi
rg -q -F 'commit_active_l2' "$startup_transaction_header" ||
    fail "nested startup transaction exposes only partial active-L2 callbacks"
rg -q 'ATF_TC_WITHOUT_HEAD\(nested_startup_transaction\)' "$test_source" ||
    fail "nested startup transaction lacks an independent model test"
rg -q -F 'vmx_nested_startup_transaction.c' "$module_makefile" ||
    fail "nested startup transaction is absent from the kernel module"
# private-test: nested-startup-composition-policy
rg -q -F 'vmx_nested_startup_policy.c' "$module_makefile" ||
    fail "nested startup composition policy is absent from the kernel module"
for contract in \
	'VMX_NESTED_STARTUP_MACHINE_FAIL_STOP' \
	'VMX_NESTED_STARTUP_MACHINE_COMMITTED' \
	'VMX_NESTED_STARTUP_MACHINE_RETRY' \
	'vmx_nested_startup_machine_disposition'; do
	rg -q -F "$contract" "$startup_policy_header" "$startup_policy_source" ||
	    fail "nested startup composition policy is missing: $contract"
done
rg -q -U --pcre2 \
    'vmm_x86_startup_transaction_result_classify\(error, result\)[\s\S]*?OUTCOME_COMMITTED[\s\S]*?MACHINE_COMMITTED[\s\S]*?OUTCOME_ROLLED_BACK[\s\S]*?MACHINE_RETRY[\s\S]*?OUTCOME_POISONED[\s\S]*?OUTCOME_INVALID[\s\S]*?MACHINE_FAIL_STOP' \
    "$startup_policy_source" ||
    fail "nested startup composition policy no longer maps only proven rollback to retry"
rg -q 'ATF_TC_WITHOUT_HEAD\(intel_outer_disposition\)' \
    "$startup_execution_test_source" ||
    fail "nested startup composition policy lacks exhaustive value tests"
rg -q 'NVMX-EVENT-139.*Intel outer startup result disposition' "$ledger" ||
    fail "nested startup composition policy is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-201.*intel-outer-startup-result-policy' \
    "$private_ledger" ||
    fail "nested startup composition policy is absent from the private ledger"
rg -q 'NVMX-EVENT-036.*startup transaction boundary' "$ledger" ||
    fail "nested startup transaction is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-094.*exact-claim-commit-adapter' "$private_ledger" ||
    fail "nested startup transaction is absent from the private ledger"
# private-test: nested-startup-durable-dispatch
for contract in \
	'VMX_NESTED_STARTUP_DISPATCH_EMPTY' \
	'VMX_NESTED_STARTUP_DISPATCH_CLAIMED' \
	'VMX_NESTED_STARTUP_DISPATCH_ACTIVE' \
	'VMX_NESTED_STARTUP_DISPATCH_POISONED' \
	'vmx_nested_startup_dispatch_step(' \
	'vmx_nested_startup_dispatch_cleanup(' \
	'nvmxsd_abort('; do
	rg -q -F "$contract" "$startup_dispatch_source" \
	    "$startup_dispatch_header" ||
	    fail "durable nested startup dispatch is missing: $contract"
done
for contract in \
	'VMX_NESTED_STARTUP_TRANSACTION_PLANNED ||' \
	'VMX_NESTED_STARTUP_TRANSACTION_RETAINED ||' \
	'VMX_NESTED_STARTUP_TRANSACTION_FINISH_PENDING)' \
	'dispatch->storage_cookie != storage_cookie' \
	'dispatch->ops_cookie != (uintptr_t)ops' \
	'dispatch->arg_cookie != (uintptr_t)arg' \
	'!nvmxsd_claim_equal(&dispatch->claim, &claim_before)'; do
	rg -q -F "$contract" "$startup_dispatch_source" ||
	    fail "durable startup stored-state or cleanup guard is missing: $contract"
done
rg -q 'ATF_TC_WITHOUT_HEAD\(nested_startup_dispatch\)' "$test_source" ||
    fail "durable startup dispatch lacks an independent model test"
rg -q -F 'vmx_nested_startup_dispatch.c' "$module_makefile" ||
    fail "durable startup dispatch is absent from the kernel module"
rg -q 'NVMX-EVENT-046.*Durable target startup dispatch ownership' "$ledger" ||
    fail "durable startup dispatch is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-103.*startup-durable-dispatch-owner' \
    "$private_ledger" ||
    fail "durable startup dispatch is absent from the private ledger"
# private-test: intel-startup-dispatch-binding
for contract in \
	'vmx_startup_derive(void *arg' \
	'vcpu == NULL || claim == NULL || input == NULL' \
	'vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN' \
	'vmx_nested_startup_input_from_frozen_target(kind' \
	'vmx_startup_prepare_l0(void *arg' \
	'vmx_nested_ept_cache_destroy(&vcpu->nested_ept_cache)' \
	'vmx_startup_apply_l0(void *arg' \
	'vmm_x86_startup_machine_execute(&input, processor_signature,' \
	'vmx_nested_startup_machine_disposition(error, &result)' \
	'vmx_startup_commit_active_l2(void *arg' \
	'vmx_nested_cold_startup_commit(&vcpu->nested' \
	'.derive = vmx_startup_derive' \
	'.prepare_l0 = vmx_startup_prepare_l0' \
	'.apply_l0 = vmx_startup_apply_l0' \
	'.commit_active_l2 = vmx_startup_commit_active_l2'; do
	rg -q -F "$contract" "$vmx_source" ||
	    fail "Intel startup dispatch binding is missing: $contract"
done
rg -q -U --pcre2 \
    'vmx_startup_apply_l0\(void \*arg,[\s\S]*?vmm_x86_startup_machine_execute\(&input, processor_signature,[\s\S]*?\*errorp = error;[\s\S]*?vmx_nested_startup_machine_disposition\(error, &result\)' \
    "$vmx_source" ||
    fail "Intel L0 startup application does not execute and classify the common transaction"
[ "$(rg -c -F 'vmx_nested_startup_dispatch_step(' "$vmx_source")" -eq 1 ] ||
    fail "Intel startup dispatcher has an unexpected caller count"
rg -q -U --pcre2 \
    'vmx_vcpu_startup_event_step\(void \*vcpui,[\s\S]*?vmx_nested_startup_dispatch_step\(' \
    "$vmx_source" ||
    fail "Intel startup dispatcher caller is not the staged machine adapter"
rg -q 'NVMX-EVENT-086.*Frozen Intel startup callback binding' "$ledger" ||
    fail "Intel startup callback binding is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-142.*intel-frozen-startup-dispatch-adapter' \
    "$private_ledger" ||
    fail "Intel startup callback binding is absent from the private ledger"
# private-test: architecture-event-owner-cleanup
for contract in \
	'DECLARE_VMMOPS_FUNC(int, vcpu_event_cleanup_check' \
	'vmmops_vcpu_event_cleanup_check_t vcpu_event_cleanup_check' \
	'DECLARE_VMMOPS_FUNC(int, vcpu_event_cleanup' \
	'vmmops_vcpu_event_cleanup_t vcpu_event_cleanup'; do
	rg -q -F "$contract" "$vmm_header" ||
	    fail "architecture event cleanup operation is missing: $contract"
done
rg -q -U --pcre2 \
	'vm_vcpu_event_cleanup\(struct vm \*vm\)[\s\S]*?vcpu_get_state\(vm->vcpu\[i\], NULL\) != VCPU_FROZEN[\s\S]*?vmmops_vcpu_event_cleanup_check\([\s\S]*?vmmops_vcpu_event_cleanup\(vm->vcpu\[i\]->cookie\)[\s\S]*?panic\(' \
	"$vmm_source" ||
	fail "architecture event cleanup lacks frozen exact-owner preflight or fail-stop commit"
rg -q -U --pcre2 \
    'vm_destroy\(struct vm \*vm\)[\s\S]*?vm_vcpu_event_cleanup\(vm\)[\s\S]*?vm_event_coordinator_cleanup\(vm\)' \
    "$vmm_source" ||
    fail "VM destruction cancels the coordinator before architecture claims"
rg -q -U --pcre2 \
    'vm_reset\(struct vm \*vm\)[\s\S]*?vm_vcpu_event_cleanup\(vm\)[\s\S]*?vm_event_coordinator_reset\(vm\)' \
    "$vmm_source" ||
    fail "VM reset changes coordinator generations before architecture claims"
for contract in \
	'svm_vcpu_event_cleanup_check(void *vcpui __unused)' \
	'.vcpu_event_cleanup_check = svm_vcpu_event_cleanup_check' \
	'svm_vcpu_event_cleanup(void *vcpui __unused)' \
	'.vcpu_event_cleanup = svm_vcpu_event_cleanup'; do
	rg -q -F "$contract" "$svm_source" ||
	    fail "AMD event cleanup no-op is missing: $contract"
done
for contract in \
	'vmx_nested_startup_dispatch_init(&vcpu->nested_startup_dispatch)' \
	'vmx_vcpu_event_cleanup_check(void *vcpui)' \
	'.vcpu_event_cleanup_check = vmx_vcpu_event_cleanup_check' \
	'vmx_vcpu_event_cleanup(void *vcpui)' \
	'.vcpu_event_cleanup = vmx_vcpu_event_cleanup' \
	'VMX_NESTED_STARTUP_DISPATCH_EMPTY'; do
	rg -q -F "$contract" "$vmx_source" ||
	    fail "Intel durable event cleanup lifecycle is missing: $contract"
done
if rg -q -F 'nested_startup_dispatch' "$checkpoint_source" \
    "$x86_state_source" "$x86_state_header"; then
	fail "runtime startup dispatch leaked into checkpoint state"
fi
rg -q 'NVMX-EVENT-047.*architecture event-owner cleanup' "$ledger" ||
    fail "architecture event cleanup is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-104.*architecture-event-owner-cleanup' \
    "$private_ledger" ||
	fail "architecture event cleanup is absent from the private ledger"
# private-test: architecture-event-owner-cleanup-preflight
for contract in \
	'vmm_startup_event_claim_check(' \
	'vmm_event_coordinator_startup_claim_check(' \
	'vcpu_startup_event_claim_check(' \
	'vmx_nested_startup_dispatch_cleanup_check('; do
	rg -q -F "$contract" "$startup_source" "$startup_header" \
	    "$event_coordinator_source" "$event_coordinator_header" \
	    "$vmm_vm_source" "$startup_dispatch_source" \
	    "$startup_dispatch_header" "$vmx_source" ||
		fail "two-phase architecture cleanup preflight is missing: $contract"
done
rg -q 'vmm_startup_event_claim_check\(&state, &claim\)' \
    "$startup_test_source" ||
	fail "exact startup claim check lacks an independent value test"
rg -q 'vmx_nested_startup_dispatch_cleanup_check\(&dispatch' \
    "$test_source" ||
	fail "durable startup cleanup preflight lacks an independent model test"
rg -q 'NVMX-EVENT-051.*Two-phase architecture event-owner cleanup' \
    "$ledger" ||
	fail "two-phase architecture cleanup is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-107.*architecture-event-owner-cleanup-preflight' \
    "$private_ledger" ||
	fail "two-phase architecture cleanup is absent from the private ledger"
# private-test: l0-startup-completion-gate
for contract in \
	'Copying `VM_EXITCODE_IPI` or the legacy' \
	'is not proof that userspace' \
	'target-specific acknowledgment identifies the completed side' \
	'A claim may not' \
	'be finished merely because an exit was selected or copied out'; do
	rg -q -F "$contract" "$review_prompt" ||
	    fail "L0 startup completion review gate is missing: $contract"
done
rg -q 'NVMX-EVENT-048.*Acknowledged L0 startup completion ownership' \
    "$ledger" ||
    fail "L0 startup completion ownership is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-105.*withheld-private-compatibility-design' \
    "$private_ledger" ||
    fail "L0 startup completion private contract is absent from the private ledger"
# private-test: x86-startup-state-plan
for contract in \
	'current_cr0 & (X86_CR0_CD | X86_CR0_NW)' \
	'X86_CR0_ET' \
	'candidate.gpr[VMM_X86_STARTUP_RDX] = processor_signature' \
	'(uint16_t)(vector << 8)' \
	'(uint64_t)vector << 12' \
	'*plan = candidate'; do
	rg -q -F "$contract" "$startup_state_source" ||
	    fail "x86 startup-state planner is missing: $contract"
done
for contract in \
	'UINT64_C(0x60000010)' \
	'UINT64_C(0x20000010)' \
	'UINT64_C(0x40000010)' \
	'UINT16_C(0xab00)' \
	'UINT64_C(0xab000)' \
	'rejection_is_transactional'; do
	rg -q -F "$contract" "$startup_state_test_source" ||
	    fail "independent x86 startup-state coverage is missing: $contract"
done
rg -q -F 'vmm_x86_startup_state.c' "$module_makefile" ||
    fail "x86 startup-state planner is absent from vmm.ko"
rg -q 'NVMX-EVENT-049.*INIT and SIPI value plans' "$ledger" ||
    fail "x86 startup-state plan is absent from the requirements ledger"
rg -q 'NVMX-EVENT-050.*Complete kernel-owned INIT and SIPI' "$ledger" ||
    fail "x86 startup side-effect boundary is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-106.*transient-INIT-SIPI-value-plans' \
	"$private_ledger" ||
	fail "x86 startup-state plan is absent from the private ledger"
# private-test: architectural-BSP-classification
for contract in \
	'X86_APICBASE_BSP' \
	'vmm_x86_startup_apicbase_classify(uint64_t apicbase,' \
	'candidate = (apicbase & X86_APICBASE_BSP) != 0' \
	'*bootstrap_processor = candidate'; do
	rg -q -F "$contract" "$startup_state_source" ||
	    fail "architectural BSP classifier is missing: $contract"
done
for fixture in \
	'UINT64_C(0xfee00900)' \
	'UINT64_C(0xfee00800)' \
	'apicbase_bsp_classification'; do
	rg -q -F "$fixture" "$startup_state_test_source" ||
	    fail "independent BSP-classification fixture is missing: $fixture"
done
rg -q 'NVMX-EVENT-073.*Virtual APIC-base BSP classification' "$ledger" ||
	fail "architectural BSP classification is absent from the ledger"
rg -q 'NVMX-PRIVATE-129.*architectural-BSP-classification' \
	"$private_ledger" ||
	fail "private BSP classification policy is absent from the ledger"
# private-test: frozen-vlapic-BSP-adapter
startup_classifier=$(sed -n \
    '/^vmmdev_machdep_startup_classify(struct vcpu \*vcpu,/,/^}/p' \
    "$vmm_dev_machdep_source")
for contract in \
	'vcpu == NULL || bootstrap_processor == NULL' \
	'vcpu_get_state(vcpu, NULL) != VCPU_FROZEN' \
	'vlapic = vm_lapic(vcpu)' \
	'vlapic_get_apicbase(vlapic)' \
	'vmm_x86_startup_apicbase_classify(' \
	'*bootstrap_processor = candidate'; do
	printf '%s\n' "$startup_classifier" | rg -q -F "$contract" ||
	    fail "frozen-vLAPIC BSP adapter is missing: $contract"
done
if printf '%s\n' "$startup_classifier" | rg -q \
    'vcpuid|vcpu_id|hostcpu'; then
	fail "frozen-vLAPIC BSP adapter contains a non-architectural classifier"
fi
rg -q 'NVMX-EVENT-074.*Frozen-vLAPIC BSP provenance adapter' "$ledger" ||
	fail "frozen-vLAPIC BSP adapter is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-130.*frozen-vLAPIC-BSP-adapter' \
	"$private_ledger" ||
	fail "private frozen-vLAPIC adapter policy is absent from the ledger"
# private-test: nonpanicking-startup-controller-release
startup_release=$(sed -n \
    '/^vmm_event_coordinator_startup_controller_release(/,/^}/p' \
    "$event_coordinator_source")
for contract in \
	'vmm_event_coordinator_startup_controller_check_locked(' \
	'vmm_event_coordinator_fail_closed_locked(coordinator)' \
	'explicit_bzero(ticket, sizeof(*ticket))'; do
	printf '%s\n' "$startup_release" | rg -q -F "$contract" ||
	    fail "startup-controller release is missing: $contract"
done
if printf '%s\n' "$startup_release" | rg -q \
    'panic\(|KASSERT\(|ticket_forget'; then
	fail "startup-controller release retains panic-based close recovery"
fi
rg -q 'NVMX-EVENT-075.*Non-panicking exact controller close' "$ledger" ||
	fail "non-panicking controller close is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-131.*nonpanicking-exact-controller-close' \
	"$private_ledger" ||
	fail "private non-panicking controller close is absent from the ledger"
# private-test: versioned-startup-request-value
for contract in \
	'VMM_STARTUP_REQUEST_VERSION' \
	'VMM_STARTUP_REQUEST_SIZE' \
	'VMM_STARTUP_REQUEST_CONFIGURE = 1' \
	'VMM_STARTUP_REQUEST_WAIT_READY' \
	'VMM_STARTUP_REQUEST_COMMIT' \
	'VMM_STARTUP_REQUEST_STATUS' \
	'uint8_t reserved8[20]'; do
	rg -q -F "$contract" "$startup_request_header" ||
	    fail "startup request definition is missing: $contract"
done
for contract in \
	'request->flags != 0' \
	'request->entered_vcpus != 0' \
	'request->generation != 0 || request->expected_vcpus == 0' \
	'request->generation == 0 || request->expected_vcpus != 0' \
	'request != output && vmm_startup_request_overlap' \
	'vmm_startup_request_status_valid(status)' \
	'*output = candidate'; do
	rg -q -F "$contract" "$startup_request_source" ||
	    fail "startup request validation is missing: $contract"
done
for fixture in \
	'#define' \
	'TEST_VERSION' \
	'UINT16_C(1)' \
	'TEST_SIZE' \
	'UINT16_C(48)' \
	'layout_and_closed_operations' \
	'operation_specific_inputs' \
	'reserved_and_output_fields_rejected' \
	'status_encoding_is_failure_atomic'; do
	rg -q -F "$fixture" "$startup_request_test_source" ||
	    fail "independent startup request coverage is missing: $fixture"
done
if rg -q '_IO(W|R|WR)?\(' "$startup_request_header" \
    "$startup_request_source"; then
	fail "unreviewed startup request value was assigned an ioctl number"
fi
rg -q -F 'vmm_startup_request.c' "$module_makefile" ||
	fail "startup request validation is absent from vmm.ko"
rg -q 'NVMX-EVENT-076.*Versioned startup management request value' \
	"$ledger" ||
	fail "versioned startup request is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-132.*versioned-startup-request-value' \
	"$private_ledger" ||
	fail "private startup request value is absent from the ledger"
# private-test: generation-bearing-run-request-value
for contract in \
	'VMM_STARTUP_RUN_REQUEST_VERSION' \
	'VMM_STARTUP_RUN_REQUEST_SIZE' \
	'int32_t vcpuid' \
	'uint64_t generation' \
	'uint64_t cpuset_address' \
	'uint64_t cpuset_size' \
	'uint64_t exit_address' \
	'uint64_t exit_size' \
	'uint8_t reserved8[8]'; do
	rg -q -F "$contract" "$startup_run_request_header" ||
	    fail "startup run request definition is missing: $contract"
done
for contract in \
	'request->flags != 0' \
	'request->vcpuid < 0' \
	'request->reserved32 != 0' \
	'request->generation == 0' \
	'request->cpuset_size > max_cpuset_size' \
	'request->exit_size != expected_exit_size' \
	'vmm_startup_run_request_range_valid(request->cpuset_address' \
	'vmm_startup_run_request_range_valid(request->exit_address' \
	'vmm_startup_run_request_ranges_overlap(request->cpuset_address'; do
	rg -q -F "$contract" "$startup_run_request_source" ||
	    fail "startup run request validation is missing: $contract"
done
for fixture in \
	'TEST_VERSION' \
	'UINT16_C(1)' \
	'TEST_SIZE' \
	'UINT16_C(64)' \
	'TEST_ADDRESS_MAX_32' \
	'layout_is_fixed_width' \
	'version_flags_and_reserved_are_closed' \
	'generation_vcpu_and_sizes_are_exact' \
	'address_ranges_cover_32_and_64_bit_callers'; do
	rg -q -F "$fixture" "$startup_run_request_test_source" ||
	    fail "independent startup run request coverage is missing: $fixture"
done
if rg -q '(^|[^a-zA-Z0-9_])(size_t|uintptr_t|cpuset_t|struct vm_exit|void \*)' \
    "$startup_run_request_header"; then
	fail "startup run request embeds a native-width or implementation type"
fi
if rg -q '_IO(W|R|WR)?\(' "$startup_run_request_header" \
    "$startup_run_request_source"; then
	fail "unreviewed startup run request was assigned an ioctl number"
fi
rg -q -F 'vmm_startup_run_request.c' "$module_makefile" ||
	fail "startup run request validation is absent from vmm.ko"
rg -q 'NVMX-EVENT-078.*Generation-bearing run request value' "$ledger" ||
	fail "generation-bearing run request is absent from requirements ledger"
rg -q 'NVMX-PRIVATE-134.*generation-bearing-run-request-value' \
	"$private_ledger" ||
	fail "private generation-bearing run request is absent from ledger"
# private-test: startup-management-cdevpriv-dispatch
for contract in \
	'VM_STARTUP_REQUEST' \
	'IOCNUM_STARTUP_REQUEST = VMM_STARTUP_REQUEST_IOCNUM' \
	"_IOWR('v', VMM_STARTUP_REQUEST_IOCNUM," \
	'struct vmm_startup_controller_ticket startup_controller' \
	'uint64_t startup_controller_id' \
	'bool startup_active' \
	'VMMDEV_IOCTL(VM_STARTUP_REQUEST, 0)' \
	'case VM_STARTUP_REQUEST:' \
	'vmmdev_startup_request(sc->vm,'; do
	rg -q -F "$contract" "$common_vmm_dev_header" "$vmm_dev_header" \
	    "$vmm_dev_source" ||
	    fail "startup management cdevpriv dispatch is missing: $contract"
done
startup_management=$(sed -n \
    '/^vmmdev_startup_request(struct vm \*vm,/,/^}/p' "$vmm_dev_source")
for contract in \
	'devfs_get_cdevpriv((void **)&priv)' \
	'vm_startup_controller_claim(vm,' \
	'vm_startup_configure_kernel(vm,' \
	'vm_startup_controller_release(vm,' \
	'sx_xunlock(&priv->lock)' \
	'vm_startup_wait_ready(vm, &priv->startup_controller' \
	'vm_startup_commit(vm, &priv->startup_controller'; do
	printf '%s\n' "$startup_management" | rg -q -F "$contract" ||
	    fail "startup management operation is missing: $contract"
done
for contract in \
	'TEST_IOCTL_NUMBER' \
	'UINT32_C(116)' \
	'IOCPARM_LEN(VM_STARTUP_REQUEST)' \
	'IOC_IN' \
	'IOC_OUT'; do
	rg -q -F "$contract" "$startup_management_abi_test_source" ||
	    fail "independent startup management ABI fixture is missing: $contract"
done
for contract in \
	'vm_startup_request(struct vmctx *ctx,' \
	'ioctl(ctx->fd, VM_STARTUP_REQUEST, request)' \
	'VM_STARTUP_REQUEST,'; do
	rg -q -F "$contract" "$libvmmapi_source" "$libvmmapi_internal" ||
	    fail "libvmmapi startup management contract is missing: $contract"
done
rg -q 'NVMX-EVENT-079.*File-description-authenticated startup management ABI' \
	"$ledger" || fail "startup management ABI is absent from ledger"
rg -q 'NVMX-PRIVATE-135.*startup-management-cdevpriv-dispatch' \
	"$private_ledger" || fail "startup management ABI is absent from private ledger"
# private-test: startup-final-close-fail-closed-fallback
startup_dtor=$(sed -n '/^vmmdev_fdpriv_dtor(void \*arg)/,/^}/p' \
    "$vmm_dev_source")
printf '%s\n' "$startup_dtor" | rg -q -U --pcre2 \
    'vm_startup_controller_release\(priv->vm,[\s\S]*?if \(error != 0\)[\s\S]*?vmm_event_coordinator_cancel\([\s\S]*?explicit_bzero\(&priv->startup_controller' ||
    fail "startup final close can discard a live controller credential"
if printf '%s\n' "$startup_dtor" | rg -q 'panic\([^\n]*startup'; then
	fail "startup final-close fallback is panic based"
fi
rg -q 'NVMX-EVENT-081.*Defensive final-close fail-closed fallback' \
	"$ledger" || fail "startup final-close fallback is absent from ledger"
rg -q 'NVMX-PRIVATE-137.*startup-final-close-fail-closed-fallback' \
	"$private_ledger" || fail "startup final-close fallback is absent from private ledger"
# private-test: generation-authenticated-run-dispatch
rg -q -U --pcre2 \
    'struct vmm_startup_run_request \{[[:space:]]*int32_t vcpuid;' \
    "$startup_run_request_header" ||
    fail "generation run request vCPU is not the first dispatcher field"
for contract in \
	'VM_RUN_GENERATION' \
	'IOCNUM_RUN_GENERATION = VMM_STARTUP_RUN_REQUEST_IOCNUM' \
	"_IOW('v', VMM_STARTUP_RUN_REQUEST_IOCNUM," \
	'VMMDEV_IOCTL(VM_RUN_GENERATION, VMMDEV_IOCTL_LOCK_ONE_VCPU)' \
	'case VM_RUN_GENERATION:' \
	'td->td_proc->p_sysent->sv_maxuser - 1' \
	'vmm_startup_run_request_validate(request,' \
	'vmmdev_startup_run_enter(vm, vcpu,' \
	'error = vm_run(vcpu)' \
	'copyout(vme, exit_address, sizeof(*vme))'; do
	rg -q -F "$contract" "$common_vmm_dev_header" "$vmm_dev_header" \
	    "$vmm_dev_machdep_source" ||
	    fail "generation-authenticated run dispatch is missing: $contract"
done
startup_run_enter=$(sed -n \
    '/^vmmdev_startup_run_enter(struct vm \*vm,/,/^}/p' "$vmm_dev_source")
for contract in \
	'devfs_get_cdevpriv((void **)&priv)' \
	'vmmdev_machdep_startup_classify(vcpu, &bootstrap_processor)' \
	'vm_startup_enter(vm, &priv->startup_controller' \
	'vm_startup_wait_committed(vm, &priv->startup_controller' \
	'"vmcommit", 0'; do
	printf '%s\n' "$startup_run_enter" | rg -q -F "$contract" ||
	    fail "authenticated run admission is missing: $contract"
done
startup_wait_committed=$(sed -n \
    '/^vmm_event_coordinator_startup_wait_committed(/,/^}/p' \
    "$event_coordinator_source")
for contract in \
	'vmm_event_coordinator_startup_controller_check_locked(' \
	'generation !=' \
	'VMM_STARTUP_HANDSHAKE_COMMITTED' \
	'VMM_STARTUP_HANDSHAKE_COLLECTING' \
	'vmm_event_wait_prepare(' \
	'vmm_event_wait_sleep(' \
	'if (error == EAGAIN)'; do
	printf '%s\n' "$startup_wait_committed" | rg -q -F "$contract" ||
	    fail "event-driven commit wait is missing: $contract"
done
for contract in \
	'TEST_RUN_IOCTL_NUMBER' \
	'UINT32_C(117)' \
	'IOCPARM_LEN(VM_RUN_GENERATION)' \
	'VM_RUN_GENERATION & IOC_DIRMASK & IOC_OUT'; do
	rg -q -F "$contract" "$startup_management_abi_test_source" ||
	    fail "independent generation run ABI fixture is missing: $contract"
done
for contract in \
	'vm_run_generation(struct vcpu *vcpu,' \
	'vcpu_ioctl(vcpu, VM_RUN_GENERATION, request)' \
	'VM_RUN_GENERATION,'; do
	rg -q -F "$contract" "$libvmmapi_source" "$libvmmapi_internal" ||
	    fail "libvmmapi generation run contract is missing: $contract"
done
rg -q 'NVMX-EVENT-080.*Generation-authenticated prestarted run ABI' \
	"$ledger" || fail "generation run ABI is absent from ledger"
rg -q 'NVMX-PRIVATE-136.*generation-authenticated-run-dispatch' \
	"$private_ledger" || fail "generation run ABI is absent from private ledger"

# The public management result vocabulary is independently versioned from the
# internal handshake enums, and its wider count field may never narrow into
# the coordinator's uint16_t ownership domain.
for contract in \
	'request->expected_vcpus > UINT16_MAX' \
	'VMM_STARTUP_REQUEST_PHASE_COLLECTING' \
	'VMM_STARTUP_REQUEST_OWNER_KERNEL' \
	'VMM_STARTUP_REQUEST_EXECUTION_PRESTARTED'; do
	rg -q -F "$contract" "$startup_request_source" ||
	    fail "startup management translation/bound is missing: $contract"
done
for contract in \
	'UINT32_C(65536)' \
	'VMM_STARTUP_REQUEST_OWNER_KERNEL' \
	'VMM_STARTUP_REQUEST_EXECUTION_PRESTARTED' \
	'VMM_STARTUP_REQUEST_PHASE_OPEN'; do
	rg -q -F "$contract" "$startup_request_test_source" ||
	    fail "independent startup ABI boundary fixture is missing: $contract"
done
# private-test: startup-public-status-and-count-boundary

# The libvmmapi run wrapper must use the vCPU object so the long-standing
# first-field dispatcher invariant supplies the authoritative vCPU id.
rg -q -U --pcre2 \
    'vm_run_generation\(struct vcpu \*vcpu,[\s\S]*?vcpu_ioctl\(vcpu, VM_RUN_GENERATION, request\)' \
    "$libvmmapi_source" ||
    fail "libvmmapi generation run is not bound to the vCPU object"
rg -q -F -- '-I${SRCTOP}/sys' "$libvmmapi_makefile" ||
    fail "libvmmapi source build cannot resolve the versioned VMM ABI headers"
# private-test: libvmmapi-vcpu-bound-generation-run

# Kernel-owned startup is selected explicitly by the amd64 manager.  It must
# configure before creating vCPU threads, admit each vCPU with the exact
# generation, wait without polling, and commit only after every vCPU (including
# exactly one BSP) is ready.  The monitor parent must retain the exact
# file-description controller and refresh the reset-advanced generation before
# forking a replacement child.  Other architectures retain their historical run
# paths, and restore remains fail-closed until restored AP startup state can be
# rebound without boot-time admission changing it.
for contract in \
	'set_config_bool("x86.kernel_startup", false)' \
	'kernel_startup_configure(ctx)' \
	'kernel_startup_commit(ctx)' \
	'kernel_startup_refresh(ctx)' \
	'vm_run_generation(vcpu, &startup_run)' \
	'VMM_STARTUP_REQUEST_WAIT_READY' \
	'VMM_STARTUP_REQUEST_COMMIT' \
	'request.bootstrap_entered != 1' \
	'x86.kernel_startup is not yet compatible with restore'; do
	rg -q -F "$contract" "$bhyve_run_source" "$bhyve_machdep_source" ||
	    fail "bhyve kernel-startup manager omits: $contract"
done
rg -q -U --pcre2 \
    'kernel_startup_configure\(ctx\);[\s\S]*?fork\(\)[\s\S]*?vm_reinit\(ctx\)[\s\S]*?kernel_startup_refresh\(ctx\)' \
    "$bhyve_run_source" ||
    fail "monitor replacement does not retain and refresh startup ownership"
if rg -q -F 'x86.kernel_startup is not yet compatible with monitor mode' \
    "$bhyve_run_source"; then
	fail "monitor replacement remains needlessly disabled after generation refresh"
fi
if rg -q 'x86\.kernel_startup|kernel_startup_(configure|commit)|vm_run_generation' \
    "$bhyve_arm64_machdep_source" "$bhyve_riscv_machdep_source"; then
	fail "amd64 kernel-startup manager leaked to another architecture"
fi
rg -q -U --pcre2 \
    'vmmdev_startup_kernel_actions_ready\(void\)[\s\S]*?return \(vmmops_startup_kernel_actions_ready\(\)\);[\s\S]*?case VMM_STARTUP_REQUEST_CONFIGURE:[\s\S]*?if \(!vmmdev_startup_kernel_actions_ready\(\)\)[\s\S]*?return \(EOPNOTSUPP\);' \
    "$vmm_dev_source" ||
    fail "build-staged startup ioctl does not fail closed before kernel INIT/SIPI binding"
rg -q -U --pcre2 \
    'vmmdev_startup_run_enter\(struct vm \*vm,[\s\S]*?if \(!vmmdev_startup_kernel_actions_ready\(\)\)[\s\S]*?return \(EOPNOTSUPP\);[\s\S]*?devfs_get_cdevpriv' \
    "$vmm_dev_source" ||
    fail "build-staged generation run does not fail closed before controller or LAPIC access"
rg -q 'ATF_TC_WITH_CLEANUP\(generation_run_requires_controller\)' \
    "$startup_staging_live_test_source" ||
    fail "generation run lacks installed-kernel controller coverage"
rg -q -F 'memcmp(&request, &request_before, sizeof(request))' \
    "$startup_staging_live_test_source" ||
    fail "staged startup failures do not prove request storage remains unchanged"
rg -q -F 'memcmp(&vmexit, &vmexit_before, sizeof(vmexit))' \
    "$startup_staging_live_test_source" ||
    fail "staged generation-run failure does not prove exit storage remains unchanged"
# private-test: startup-manager-activation-boundary
rg -q -U --pcre2 \
    '#ifdef __amd64__[\s\S]*?#define[[:space:]]+VM_STARTUP_REQUEST[\s\S]*?#define[[:space:]]+VM_RUN_GENERATION[\s\S]*?#endif' \
    "$common_vmm_dev_header" ||
    fail "private startup commands escaped the amd64 declaration boundary"
for contract in \
	'IOCNUM_STARTUP_REQUEST = VMM_STARTUP_REQUEST_IOCNUM' \
	'IOCNUM_RUN_GENERATION = VMM_STARTUP_RUN_REQUEST_IOCNUM'; do
	rg -q -F "$contract" "$vmm_dev_header" ||
	    fail "private startup command number is not reserved by amd64: $contract"
done
for contract in \
	'VMM_STARTUP_REQUEST_IOCNUM' \
	'VMM_STARTUP_RUN_REQUEST_IOCNUM'; do
	rg -q -F "$contract" "$startup_request_header" \
	    "$startup_run_request_header" ||
	    fail "private startup command number has no payload-owned definition: $contract"
done
rg -q -U --pcre2 \
    '\.if \$\{MACHINE_CPUARCH\} == "amd64"[\s\S]*?ATF_TESTS_C\+=\tvmm_startup_management_abi_test[\s\S]*?ATF_TESTS_C\+=\tvmm_startup_staging_live_test[\s\S]*?ATF_TESTS_C\+=\tvmx_nested_state_test[\s\S]*?\.endif' \
    "$src/tests/sys/vmm/Makefile" ||
    fail "amd64-only private startup and nested tests are not architecture-gated"
# private-test: startup-amd64-boundary
for requirement in NVMX-EVENT-082 NVMX-EVENT-083 NVMX-EVENT-084 NVMX-EVENT-085 \
    NVMX-EVENT-086 NVMX-EVENT-087 NVMX-EVENT-088 NVMX-EVENT-089 \
	NVMX-EVENT-090 NVMX-EVENT-091 NVMX-EVENT-092 NVMX-EVENT-093 \
	NVMX-EVENT-094 NVMX-EVENT-095 NVMX-EVENT-096 \
	NVMX-EVENT-097 NVMX-EVENT-098 NVMX-EVENT-099 \
	NVMX-EVENT-100 NVMX-EVENT-101 NVMX-EVENT-102 NVMX-EVENT-103 \
	NVMX-EVENT-104; do
	rg -q "^${requirement}[[:space:]]" "$ledger" ||
	    fail "startup consumer requirement is missing: $requirement"
done
for interface in NVMX-PRIVATE-138 NVMX-PRIVATE-139 NVMX-PRIVATE-140 \
    NVMX-PRIVATE-141 NVMX-PRIVATE-142 NVMX-PRIVATE-143 NVMX-PRIVATE-144 \
	NVMX-PRIVATE-145 NVMX-PRIVATE-146 NVMX-PRIVATE-147 NVMX-PRIVATE-148 \
	NVMX-PRIVATE-149 NVMX-PRIVATE-150 NVMX-PRIVATE-151 \
	NVMX-PRIVATE-152 NVMX-PRIVATE-153 NVMX-PRIVATE-154 \
	NVMX-PRIVATE-155 NVMX-PRIVATE-156 NVMX-PRIVATE-157 \
	NVMX-PRIVATE-158 NVMX-PRIVATE-159 NVMX-PRIVATE-160 \
	NVMX-PRIVATE-161 NVMX-PRIVATE-162 NVMX-PRIVATE-163; do
	rg -q "^${interface}[[:space:]]" "$private_ledger" ||
	    fail "startup consumer private interface is missing: $interface"
done
# The rootless orchestrator's sole aggregate PASS is a commit record for all
# composed model, requirements, evidence, staging, policy-pair, and
# live-coverage gates.  It
# must therefore follow the last composed selftest rather than precede gates
# whose failure would otherwise leave a misleading PASS in the transcript.
aggregate_pass_line=$(rg -n '^\s*echo "PASS nested-vmx cases=' \
    "$model_runner" | cut -d: -f1)
policy_selftest_line=$(rg -n '^"\$policy_pair_selftest"$' \
    "$model_runner" | cut -d: -f1)
live_coverage_selftest_line=$(rg -n '^"\$live_coverage_selftest"$' \
    "$model_runner" | cut -d: -f1)
public_header_validator=$src/tests/sys/vmm/validate-vmx-nested-public-headers.sh
public_header_validator_line=$(rg -n '^env SRCTOP="\$src" "\$public_header_validator"$' \
    "$model_runner" | cut -d: -f1)
[ "$(printf '%s\n' "$aggregate_pass_line" | wc -l | tr -d ' ')" -eq 2 ] ||
    fail "rootless model must contain exactly two aggregate PASS branches"
[ -n "$policy_selftest_line" ] ||
    fail "rootless model no longer executes the policy-pair selftest"
[ -n "$live_coverage_selftest_line" ] ||
    fail "rootless model no longer executes the live-coverage validator selftest"
[ -x "$public_header_validator" ] ||
    fail "nested public-header validator is unavailable"
[ -n "$public_header_validator_line" ] ||
    fail "rootless model no longer executes the public-header validator"
for public_header_line in $public_header_validator_line; do
	[ "$public_header_line" -lt "$policy_selftest_line" ] ||
	    fail "rootless public-header validation no longer precedes model selftests"
done
for pass_line in $aggregate_pass_line; do
	[ "$pass_line" -gt "$live_coverage_selftest_line" ] ||
	    fail "rootless aggregate PASS precedes a composed validation gate"
done
# Detached execution uses RESULT_FILE as the authoritative terminal state.
# It must be durable before either user-facing PASS branch so an executor
# which reaps immediately after the last test cannot leave RUNNING behind.
result_pass_line=$(rg -n "printf 'PASS nested-vmx cases=%s workdir=%s" \
    "$model_runner" | cut -d: -f1)
[ "$(printf '%s\n' "$result_pass_line" | wc -l | tr -d ' ')" -eq 1 ] ||
    fail "rootless model must contain exactly one durable aggregate PASS"
[ -n "$result_pass_line" ] ||
    fail "rootless model no longer publishes durable aggregate PASS"
for pass_line in $aggregate_pass_line; do
	[ "$result_pass_line" -lt "$pass_line" ] ||
	    fail "rootless durable aggregate PASS follows cosmetic stdout PASS"
done
# A terminal PASS record alone cannot distinguish a worker that is still
# building from a worker whose early failure or signal was lost by a detached
# supervisor.  Keep the entire RESULT_FILE state machine structural: the
# runner must publish a PID-bearing RUNNING record before work begins and a
# non-success terminal record from its EXIT/signal cleanup path.
for result_contract in \
    'result_file=${RESULT_FILE:-}' \
    'result_started=0' \
    'publish_running()' \
    "printf 'RUNNING nested-vmx pid=%s workdir=%s phase=%s\\n' \"\$\$\"" \
    'result_started=1' \
    "printf 'FAIL nested-vmx exit=%s workdir=%s\\n' \"\$status\"" \
    "trap 'cleanup 130' INT" \
    "trap 'cleanup 143' TERM"; do
	rg -q -F "$result_contract" "$model_runner" ||
	    fail "rootless model RESULT_FILE contract is missing: $result_contract"
done
# Configuration validation must run only after the runner has installed its
# EXIT/signal cleanup and made RESULT_FILE live.  Otherwise a malformed
# caller option exits before publishing FAIL, leaving a detached executor
# unable to distinguish a rejected invocation from a vanished worker.
result_start_line=$(rg -n '^\s*result_started=1$' "$model_runner" | cut -d: -f1)
jobs_validation_line=$(rg -n '^case "\$jobs" in$' "$model_runner" | cut -d: -f1)
sanitize_validation_line=$(rg -n '^if \[ -n "\$\{SANITIZE:-\}" \]; then$' \
    "$model_runner" | cut -d: -f1)
exit_trap_line=$(rg -n -F "trap 'cleanup \$?' EXIT" "$model_runner" | cut -d: -f1)
[ "$(printf '%s\n' "$result_start_line" | wc -l | tr -d ' ')" -eq 1 ] ||
    fail "rootless model must start RESULT_FILE state exactly once"
[ "$(printf '%s\n' "$jobs_validation_line" | wc -l | tr -d ' ')" -eq 1 ] ||
    fail "rootless model must validate VMX_NESTED_BUILD_JOBS exactly once"
[ "$(printf '%s\n' "$sanitize_validation_line" | wc -l | tr -d ' ')" -eq 1 ] ||
    fail "rootless model must reject deprecated SANITIZE exactly once"
[ "$(printf '%s\n' "$exit_trap_line" | wc -l | tr -d ' ')" -eq 1 ] ||
    fail "rootless model must install exactly one EXIT cleanup trap"
[ "$exit_trap_line" -lt "$result_start_line" ] ||
    fail "rootless model starts RESULT_FILE before cleanup is installed"
[ "$result_start_line" -lt "$jobs_validation_line" ] ||
    fail "rootless model validates build jobs before RESULT_FILE is live"
[ "$result_start_line" -lt "$sanitize_validation_line" ] ||
    fail "rootless model validates SANITIZE before RESULT_FILE is live"
echo "nested-vmx requirements: durable model RESULT_FILE state machine validated"
# The x86 envelope test owns the portable VMS2 wire codec and all-vCPU
# transaction rejection cases.  It must be part of both regular and sanitized
# aggregate runs, not merely an individually buildable ATF program.
for contract in \
    'vmm_snapshot_envelope_test' \
    'envelope_test_program=$obj/vmm_snapshot_envelope_test' \
    'list_atf_cases()' \
    '"$program" -l >"$case_log" 2>&1' \
	'case_log=' \
	'if [ -n "$case_log" ]; then' \
	'rm -f "$case_log" 2>/dev/null || :' \
    'envelope_cases=$(list_atf_cases "$envelope_test_program" snapshot-envelope)' \
    'vmm_exception_test' \
    'exception_test_program=$obj/vmm_exception_test' \
    'exception_cases=$(list_atf_cases "$exception_test_program" exception-model)' \
    'vmm_snapshot_session_abi_test' \
    'snapshot_session_abi_test_program=$obj/vmm_snapshot_session_abi_test' \
    'snapshot_session_abi_cases=$(list_atf_cases "$snapshot_session_abi_test_program" snapshot-session-abi)' \
	'vmm_snapshot_session_live_test' \
	'vmm_startup_staging_live_test' \
	'make -C "$src/lib/libvmmapi"' \
	'"CFLAGS+=-I$src/lib/libvmmapi"' \
    '"CFLAGS+=-I$src/sys/amd64/include"' \
	'"$program" -r /dev/stdout "$test_case"' \
	'tail -n 1 "$case_log" | grep -qx passed' \
	'run_atf_case "$envelope_test_program" "$test_case" snapshot-envelope'; do
	rg -q -F "$contract" "$model_runner" ||
	    fail "rootless nested model omits required ABI or snapshot coverage: $contract"
done
# The VM-free model must stay VM-free even if an operator happens to invoke it
# as root on a host with /dev/vmm.  Its two kernel-liveness binaries are built
# for ABI coverage, while the reviewed live wrapper is the normal execution
# path.  Require a deliberate, documented opt-in before the model runner can
# execute VM_CREATE/VM_ACTIVATE tests.
rg -q -F 'VMX_NESTED_MODEL_LIVE_ATF:-no' "$model_runner" ||
    fail "rootless nested model may run live VMM tests without an explicit opt-in"
rg -q -F 'VMX_NESTED_MODEL_LIVE_ATF=yes as root with /dev/vmm' "$model_runner" ||
    fail "rootless nested model does not describe the live-test opt-in"
# Command-line CFLAGS replace the library makefile's defaults.  Keep the
# sanitizer branch's libvmmapi invocation self-contained: the two root-only
# liveness tests link that archive, and a non-instrumented or snapshot-less
# archive would make a sanitizer transcript weaker than it claims to be.
sanitized_libvmmapi_build=$(awk '
    /make -C "\$src\/lib\/libvmmapi"/ { capture = 1 }
    capture { print }
    capture && /make -C "\$src\/tests\/sys\/vmm"/ { exit }
' "$model_runner")
for contract in \
    'CFLAGS+=-I$src/lib/libvmmapi' \
    'CFLAGS+=-I$src/sys' \
    'CFLAGS+=-I$src/sys/amd64/include' \
    'CFLAGS+=-DWITH_VMMAPI_SNAPSHOT' \
    'CFLAGS+=-fsanitize=$sanitizers' \
    'LDFLAGS+=-fsanitize=$sanitizers'; do
	printf '%s\n' "$sanitized_libvmmapi_build" | rg -q -F "$contract" ||
	    fail "sanitized libvmmapi build omits required contract: $contract"
done
# The aggregate runner is the rootless qualification gate for the complete
# common/amd64 value model.  Every ATF binary that has no VM-creation or
# loaded-kernel prerequisite must be both built and given an execution path;
# the two live tests remain intentionally outside this execution set.  They
# are nevertheless built by both model branches above, against a fresh
# libvmmapi archive, so a public ABI/link regression cannot hide until root
# qualification.
for test_program in \
    vmx_nested_state_test vmm_exception_test vmm_snapshot_op_test \
    vmm_snapshot_session_abi_test vmm_snapshot_envelope_test \
    vmm_event_ingress_test vmm_startup_event_test vmm_event_checkpoint_test \
    vmm_event_state_test vmm_startup_mode_test vmm_startup_entry_owner_test \
    vmm_startup_handshake_test vmm_startup_controller_test \
    vmm_startup_request_test vmm_startup_run_request_test \
    vmm_startup_management_abi_test vmm_event_wait_test \
    vmm_x86_startup_state_test vmm_x86_startup_transaction_test \
    vmm_x86_startup_machine_test vmm_x86_startup_vmreg_test \
    vmm_x86_startup_backend_test vmm_x86_startup_finalizer_test; do
	rg -q -F "$test_program" "$model_runner" ||
	    fail "rootless nested model omits safe VMM test: $test_program"
done
# private-test: rootless-aggregate-pass-order
# private-test: intel-startup-l0-binding-staged
rg -q -U --pcre2 \
    'struct vmx_startup_l0_binding[\s\S]*?struct vmx_vcpu \*vcpu;[\s\S]*?struct vmm_x86_startup_backend backend;' \
    "$vmx_source" || fail "Intel staged startup binding is missing"
for callback in vmx_startup_raw_getreg vmx_startup_raw_setreg \
    vmx_startup_raw_getdesc vmx_startup_raw_setdesc \
    vmx_startup_event_capture vmx_startup_event_compare_clear \
    vmx_startup_reset_nested vmx_startup_reset_lapic \
    vmx_startup_retire_translation_residency vmx_startup_set_nextrip \
    vmx_startup_publish_wait; do
	rg -q -F "$callback" "$vmx_source" ||
	    fail "Intel staged startup callback is missing: $callback"
done
rg -q -U --pcre2 \
    'vmx_startup_l0_binding_prepare\([\s\S]*?x86_emulate_cpuid\([\s\S]*?signature_candidate = \(uint32_t\)rax;[\s\S]*?\*processor_signature = signature_candidate;[\s\S]*?return \(0\);' \
    "$vmx_source" || fail "Intel startup binding does not derive CPUID.1 signature"
rg -q -U --pcre2 \
    'vmx_startup_l0_binding_prepare\([\s\S]*?vmm_x86_startup_finalizer_consumed\(finalizer\)[\s\S]*?vmx_nested_state_ranges_overlap\([\s\S]*?signature_candidate = \(uint32_t\)rax;[\s\S]*?vmm_x86_startup_finalizer_init\([\s\S]*?\*binding = binding_candidate;[\s\S]*?\*input = input_candidate;[\s\S]*?\*processor_signature = signature_candidate;' \
    "$vmx_source" ||
    fail "Intel startup binding preparation is not failure-atomic and disjoint"
rg -q -U --pcre2 \
	'vmx_startup_apply_l0\([\s\S]*?vmx_startup_l0_owner_preflight\([\s\S]*?vmx_startup_l0_binding_prepare\([\s\S]*?vmm_x86_startup_machine_execute\([\s\S]*?vmx_nested_startup_machine_disposition\(' \
	"$vmx_source" || fail "Intel staged startup binding does not execute the typed common transaction"
rg -q -U --pcre2 \
	'vmx_startup_kernel_actions_ready\(void\)[\s\S]*?return \(true\);' \
	"$vmx_source" || fail "Intel startup binding is not enabled after all-path conversion"
rg -q -U --pcre2 \
    'vmx_nested_vpid_owner_validate\(&vcpu->nested_vpid_owner\)[\s\S]*?vcpu->nested_vpid_owner.callback_active[\s\S]*?kind == VMX_NESTED_STARTUP_SIPI[\s\S]*?vcpu->nested_vpid_owner.active[\s\S]*?vcpu->nested_vpid_owner.pending_flush[\s\S]*?VMX_NESTED_L0_STARTUP_VPID' \
    "$vmx_source" ||
    fail "Intel SIPI preflight accepts destination-local VPID ownership"
rg -q -U --pcre2 \
    'vmx_startup_reset_nested\(void \*arg\)[\s\S]*?vmx_nested_vpid_owner_release\([\s\S]*?panic\([\s\S]*?vmx_nested_context_reset\(' \
    "$vmx_source" ||
    fail "Intel INIT finalizer does not release VPID02 before context reset"
rg -q -U --pcre2 \
    'if \(!owner->active\) \{[\s\S]*?vmx_nested_vpid_owner_init\(owner\);[\s\S]*?return \(0\);' \
    "$src/sys/amd64/vmm/intel/vmx_nested_vpid_owner.c" ||
    fail "VPID owner release retains an inactive pending invalidation"
rg -q -F 'vmm_x86_startup_machine_execute(' "$vmx_source" ||
	fail "Intel startup machine transaction is not wired to the prepared binding"
rg -q -U --pcre2 \
    'vmx_startup_kernel_actions_ready\(void\)[\s\S]*?return \(true\);' \
    "$vmx_source" ||
	fail "Intel startup machine transaction is not reachable through opt-in management"
[ "$(rg -c -F 'vmx_nested_startup_dispatch_step(' "$vmx_source")" -eq 1 ] ||
    fail "Intel startup dispatcher acquired an unexpected caller"
rg -q -U --pcre2 \
    'vlapic_reset_startup\(struct vcpu \*vcpu\)[\s\S]*?VCPU_FROZEN[\s\S]*?vlapic_reset\(vm_lapic\(vcpu\)\);' \
    "$src/sys/amd64/vmm/io/vlapic.c" ||
    fail "staged startup LAPIC reset lacks frozen-target enforcement"
# private-test: vlapic-reset-cancels-host-timer
rg -q -U --pcre2 \
    'vlapic_reset\(struct vlapic \*vlapic\)[\s\S]*?VLAPIC_TIMER_LOCK\(vlapic\);[\s\S]*?callout_stop\(&vlapic->callout\);[\s\S]*?timer_fire_bt[\s\S]*?timer_period_bt[\s\S]*?VLAPIC_TIMER_UNLOCK\(vlapic\);[\s\S]*?bzero\(lapic, sizeof\(struct LAPIC\)\)' \
    "$src/sys/amd64/vmm/io/vlapic.c" ||
	fail "vLAPIC reset does not cancel and retire the host timer before architectural reset"
# private-test: rendezvous-owned-startup-wait-publication
rg -q -U --pcre2 \
    'vm_publish_startup_wait_rendezvous\(struct vcpu \*vcpu, bool waiting\)[\s\S]*?mtx_assert\(&vm->rendezvous_mtx, MA_OWNED\);[\s\S]*?if \(waiting\)[\s\S]*?CPU_SET\([\s\S]*?else[\s\S]*?CPU_CLR\(' \
    "$src/sys/amd64/vmm/vmm.c" ||
	fail "startup wait finalizer has no rendezvous-owned atomic set/clear primitive"
if rg -q 'vm_await_start_rendezvous' "$src/sys/amd64/include/vmm.h" \
    "$src/sys/amd64/vmm/vmm.c"; then
	fail "obsolete AP-only INIT publication wrapper remains"
fi
# private-test: vmxoff-releases-registry-owner
rg -q -U --pcre2 \
    'case VMX_NESTED_INSTRUCTION_VMXOFF:[\s\S]*?vmx_nested_machine_vmxoff\(&candidate\);[\s\S]*?ops->vmxoff_release\(arg\)[\s\S]*?VMX_NESTED_INSTRUCTION_ACCESS_RETRY' \
    "$src/sys/amd64/vmm/intel/vmx_nested_instruction_handoff.c" ||
	fail "VMXOFF handoff does not transactionally release its VMCS owner"
rg -q -U --pcre2 \
    'nvmx_runtime_vmxoff_release\(void \*arg\)[\s\S]*?sx_xlock\(runtime->vmcs_sx\);[\s\S]*?vmx_nested_vmcs_registry_release\(runtime->registry,[\s\S]*?runtime->owner\)[\s\S]*?sx_xunlock\(runtime->vmcs_sx\);' \
    "$src/sys/amd64/vmm/intel/vmx_nested_instruction_runtime.c" ||
	fail "Intel VMXOFF runtime does not release registry ownership under its lock"
rg -q -U --pcre2 \
    'fixture.next_vmxoff = VMX_NESTED_INSTRUCTION_ACCESS_RETRY;[\s\S]*?vmx_nested_instruction_handoff_handle\(&handoff,[\s\S]*?EAGAIN\);[\s\S]*?fixture.vmxoff_release_count, 0[\s\S]*?vmx_nested_instruction_handoff_handle\(&handoff,[\s\S]*?fixture.vmxoff_release_count, 1' \
    "$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "VMXOFF release retry and exactly-once behavior lack an independent model"
# private-test: startup-mode-value-plan
for contract in \
	'VMM_STARTUP_OWNER_USERSPACE = 0' \
	'VMM_STARTUP_OWNER_KERNEL' \
	'VMM_STARTUP_EXECUTION_USERSPACE_RESUME = 0' \
	'VMM_STARTUP_EXECUTION_PRESTARTED_WAIT' \
	'VMM_STARTUP_ACTION_EXIT_USERSPACE_INIT' \
	'VMM_STARTUP_ACTION_APPLY_KERNEL_SIPI'; do
	rg -q -F "$contract" "$startup_mode_header" ||
	    fail "startup-mode closed value set is missing: $contract"
done
for contract in \
	'mode->locked == 0' \
	'mode->execution != VMM_STARTUP_EXECUTION_PRESTARTED_WAIT' \
	'VMM_STARTUP_ACTION_DISCARD_SIPI' \
	'VMM_STARTUP_OWNER_USERSPACE || !bootstrap_processor' \
	'*plan = candidate'; do
	rg -q -F "$contract" "$startup_mode_source" ||
	    fail "startup-mode decision contract is missing: $contract"
done
for contract in \
	'default_preserves_userspace_contract' \
	'kernel_owner_ap_transitions' \
	'kernel_owner_bsp_init_remains_runnable' \
	'selection_is_immutable' \
	'execution_contract_must_match_owner' \
	'rejection_is_failure_atomic'; do
	rg -q -F "$contract" "$startup_mode_test_source" ||
	    fail "startup-mode independent test is missing: $contract"
done
rg -q -F 'vmm_startup_mode.c' "$module_makefile" ||
    fail "startup-mode value planner is absent from vmm.ko"
rg -q 'NVMX-EVENT-052.*Immutable startup ownership' "$ledger" ||
    fail "startup-mode decision is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-108.*startup-owner-execution-value-plan' \
    "$private_ledger" ||
    fail "startup-mode decision is absent from the private ledger"
# private-test: prestarted-vcpu-startup-handshake
for contract in \
	VMM_STARTUP_HANDSHAKE_OPEN \
	VMM_STARTUP_HANDSHAKE_COLLECTING \
	VMM_STARTUP_HANDSHAKE_COMMITTED \
	VMM_STARTUP_HANDSHAKE_CANCELLED \
	vmm_startup_handshake_configure_kernel \
	vmm_startup_handshake_enter \
	vmm_startup_handshake_commit \
	vmm_startup_handshake_cancel; do
	rg -q -F "$contract" "$startup_handshake_header" \
	    "$startup_handshake_source" ||
	    fail "prestarted-vCPU handshake is missing: $contract"
done
for contract in \
	'vcpus_cookie != (uintptr_t)handshake->vcpus' \
	'__builtin_mul_overflow((size_t)expected_vcpus' \
	'startup_handshake_records_valid(handshake)' \
	'bootstrap_processor >' \
	'handshake->vcpus[i].entered' \
	'startup_handshake_overlap(handshake, sizeof(*handshake), vcpus' \
	'vcpu->handshake_cookie == (uintptr_t)handshake' \
	'entered_count != handshake->entered_vcpus' \
	'entered_count != handshake->expected_vcpus || bootstrap_count != 1' \
	'vmm_startup_handshake_reset_check' \
	'vmm_startup_handshake_reset' \
	'vmm_startup_handshake_status' \
	'startup_handshake_overlap(handshake->vcpus, vcpus_size, status' \
	'candidate.generation++' \
	'candidate.vcpus = NULL;' \
	'memset(vcpus, 0, vcpus_size);' \
	'candidate.phase = VMM_STARTUP_HANDSHAKE_CANCELLED;'; do
	rg -q -F "$contract" "$startup_handshake_source" ||
	    fail "prestarted-vCPU handshake contract is missing: $contract"
done
for test_case in \
	default_is_locked_without_thread_handshake \
	kernel_requires_every_distinct_vcpu_and_one_bsp \
	missing_or_duplicate_bsp_is_rejected \
	canonical_array_and_failure_atomicity \
	corruption_is_not_reported_as_incomplete \
	cancel_invalidates_external_storage \
	retire_is_unconditional_and_terminal \
	reset_recollects_locked_kernel_owner \
	reset_is_failure_atomic_at_generation_exhaustion \
	reset_advances_historical_owner_generation \
	status_reports_recollection_and_is_failure_atomic; do
	rg -q -F "$test_case" "$startup_handshake_test_source" ||
	    fail "prestarted-vCPU handshake test is missing: $test_case"
done
rg -q -F 'vmm_startup_handshake.c' "$module_makefile" ||
    fail "prestarted-vCPU handshake is absent from vmm.ko"
rg -q 'NVMX-EVENT-060.*prestarted-vCPU startup handshake' "$ledger" ||
    fail "prestarted-vCPU handshake is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-116.*canonical-prestarted-thread-handshake' \
    "$private_ledger" ||
    fail "prestarted-vCPU handshake is absent from the private ledger"
# private-test: fd-owned-startup-controller-value
for contract in \
	VMM_STARTUP_CONTROLLER_UNCLAIMED \
	VMM_STARTUP_CONTROLLER_CLAIMED \
	VMM_STARTUP_CONTROLLER_REVOKED \
	vmm_startup_controller_claim \
	vmm_startup_controller_check \
	vmm_startup_controller_abort \
	vmm_startup_controller_retire \
	vmm_startup_controller_ticket_forget; do
	rg -q -F "$contract" "$startup_controller_header" \
	    "$startup_controller_source" ||
	    fail "startup controller value protocol is missing: $contract"
done
for contract in \
	'startup_controller_overlap(state, sizeof(*state), ticket' \
	'startup_controller_ticket_empty(ticket)' \
	'startup_controller_ticket_valid(ticket)' \
	'ticket->state_cookie != (uintptr_t)state' \
	'ticket->storage_cookie == (uintptr_t)ticket' \
	'state->generation == UINT64_MAX' \
	'candidate.phase = VMM_STARTUP_CONTROLLER_REVOKED' \
	'memset(ticket, 0, sizeof(*ticket))'; do
	rg -q -F "$contract" "$startup_controller_source" ||
	    fail "startup controller ownership contract is missing: $contract"
done
for test_case in \
	claim_and_exact_check \
	copied_and_cross_owner_tickets_fail \
	abort_invalidates_and_allows_fresh_claim \
	exhaustion_and_alias_reject_without_mutation \
	retire_is_terminal_and_ticket_forget_is_local; do
	rg -q -F "$test_case" "$startup_controller_test_source" ||
	    fail "startup controller independent test is missing: $test_case"
done
rg -q -F 'vmm_startup_controller.c' "$module_makefile" ||
    fail "startup controller value protocol is absent from vmm.ko"
rg -q 'NVMX-EVENT-064.*fd-owned startup controller' "$ledger" ||
    fail "startup controller ownership is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-120.*fd-owned-startup-controller-value' \
    "$private_ledger" ||
    fail "startup controller value is absent from the private ledger"
# private-test: coordinator-startup-handshake-lifetime
# private-test: monitor-replacement-startup-recollection
# private-test: coordinator-startup-controller-composition
for contract in \
	'base_size > SIZE_MAX - (alignment - 1)' \
	'vmm_event_coordinator_startup_records_const' \
	'coordinator->startup_handshake.vcpus != startup_records' \
	'vmm_event_coordinator_startup_record_empty' \
	'vmm_event_coordinator_wait_ticket_empty' \
	'vmm_startup_controller_validate(' \
	'&coordinator->startup_controller' \
	'coordinator->startup_controller.owner_id != coordinator->owner_id' \
	'coordinator->startup_handshake.owner_id != coordinator->owner_id' \
	'VMM_STARTUP_CONTROLLER_CLAIMED' \
	'VMM_STARTUP_CONTROLLER_REVOKED' \
	'coordinator->startup_handshake.mode.owner !=' \
	'VMM_STARTUP_OWNER_KERNEL' \
	'vmm_event_coordinator_fail_closed_locked' \
	'vmm_event_wait_cancel(&coordinator->startup_wait)' \
	'vmm_event_wait_cancel(&coordinator->wait)' \
	'vmm_event_wait_drain(&coordinator->startup_wait' \
	'vmm_event_wait_drain(&coordinator->wait'; do
	rg -q -F "$contract" "$event_coordinator_source" ||
	    fail "coordinator startup lifetime contract is missing: $contract"
done
for contract in \
	vmm_event_coordinator_startup_lock_default \
	vmm_event_coordinator_startup_controller_claim \
	vmm_event_coordinator_startup_controller_release \
	vmm_event_coordinator_startup_configure_kernel \
	vmm_event_coordinator_startup_enter \
	vmm_event_coordinator_startup_wait_ready \
	vmm_event_coordinator_startup_commit \
	vmm_event_coordinator_startup_status; do
	rg -q -F "$contract" "$event_coordinator_header" \
	    "$event_coordinator_source" ||
	    fail "coordinator startup API is missing: $contract"
done
for contract in \
	'coordinator->startup_controller.phase !=' \
	'VMM_STARTUP_CONTROLLER_UNCLAIMED' \
	'already_locked = error == 0' \
	'vmm_startup_controller_retire(' \
	'vmm_event_coordinator_startup_controller_check_locked' \
	'vmm_event_coordinator_overlap(controller_ticket' \
	'coordinator->transaction_active == 0 &&' \
	'vmm_event_coordinator_fail_closed_locked(coordinator)' \
	'explicit_bzero(ticket, sizeof(*ticket))' \
	'already_committed = error == 0' \
	'if (error == 0 && !already_committed)'; do
	rg -q -F "$contract" "$event_coordinator_source" ||
	    fail "coordinator startup controller composition is missing: $contract"
done
rg -q 'NVMX-EVENT-061.*Coordinator-owned prestarted-vCPU readiness' \
    "$ledger" || fail "coordinator startup lifetime is absent from the ledger"
rg -q 'NVMX-PRIVATE-117.*coordinator-owned-startup-readiness' \
    "$private_ledger" ||
    fail "coordinator startup lifetime is absent from the private ledger"
rg -q 'NVMX-EVENT-062.*Monitor replacement startup recollection' "$ledger" ||
    fail "monitor replacement startup recollection is absent from the ledger"
rg -q 'NVMX-PRIVATE-118.*generation-bound-startup-status' \
    "$private_ledger" ||
    fail "generation-bound startup status is absent from the private ledger"
rg -q 'NVMX-EVENT-065.*Coordinator startup controller composition' \
    "$ledger" ||
    fail "coordinator startup controller composition is absent from the ledger"
rg -q 'NVMX-PRIVATE-121.*coordinator-startup-controller-composition' \
    "$private_ledger" ||
    fail "coordinator startup controller composition is absent from the private ledger"
# private-test: legacy-vm-run-locks-default-startup-owner
for contract in \
	'case VM_RUN:' \
	'case VM_RUN_13:' \
	'error = vm_startup_lock_default(vm, &startup_generation);' \
	'if (error == 0)' \
	'error = vm_run(vcpu);'; do
	rg -q -F "$contract" "$vmm_dev_machdep_source" ||
	    fail "legacy VM_RUN startup-owner lock is missing: $contract"
done
rg -q -F 'vmm_event_coordinator_startup_lock_default(' "$vmm_vm_source" ||
    fail "VM startup default-owner wrapper is missing"
rg -q 'NVMX-EVENT-066.*Legacy VM_RUN startup-owner lock' "$ledger" ||
    fail "legacy VM_RUN startup-owner lock is absent from the ledger"
rg -q 'NVMX-PRIVATE-122.*legacy-VM_RUN-default-owner-lock' \
    "$private_ledger" ||
    fail "legacy VM_RUN startup-owner policy is absent from the private ledger"
# private-test: event-driven-prestarted-ap-wait
for contract in \
	'vmm_event_coordinator_startup_execution_status' \
	'VMM_STARTUP_HANDSHAKE_COMMITTED' \
	'error = EAGAIN;' \
	'vmm_startup_handshake_status('; do
	rg -q -F "$contract" "$event_coordinator_source" \
	    "$event_coordinator_header" ||
	    fail "startup execution-status contract is missing: $contract"
done
for contract in \
	'vm_handle_startup_wait(struct vcpu *vcpu, bool *retu)' \
	'mtx_lock(&vm->rendezvous_mtx)' \
	'vcpu_lock(vcpu)' \
	'waiting = CPU_ISSET(vcpu->vcpuid, &vm->startup_cpus)' \
	'sleepq_lock(vcpu)' \
	'SLEEPQ_SLEEP |' \
	'SLEEPQ_INTERRUPTIBLE' \
	'vcpu_require_state_locked(vcpu, VCPU_SLEEPING)' \
	'error = sleepq_wait_sig(vcpu, 0)' \
	'vcpu_require_state_locked(vcpu, VCPU_FROZEN)' \
	'vm_handle_rendezvous(vcpu)' \
	'vm_exit_suspended(vcpu, vcpu->nextrip)' \
	'vm_handle_suspend(vcpu, retu)' \
	'vm_exit_reqidle(vcpu, vcpu->nextrip)' \
	'vm_handle_reqidle(vcpu, retu)' \
	'vm_exit_debug(vcpu, vcpu->nextrip)' \
	'thread_check_susp(td, false)' \
	'A wake requests a complete predicate replay' \
	'goto done;'; do
	rg -q -F "$contract" "$vmm_source" ||
	    fail "event-driven prestarted AP wait is missing: $contract"
done
if sed -n '/^vm_handle_startup_wait(/,/^vm_run(/p' "$vmm_source" |
    rg -q '(msleep_spin|pause\(|hz\)|timeout)'; then
	fail "prestarted AP wait contains polling or timeout progress"
fi
# TEST-ANCHOR: startup-wait-lifecycle-precedence
# One locked predicate snapshot can observe both an accepted SIPI and a
# pending lifecycle request.  The latter must be serviced before the cleared
# startup bit permits hardware re-entry.
startup_wait_body=$(sed -n '/^vm_handle_startup_wait(/,/^vm_run(/p' \
    "$vmm_source")
printf '%s\n' "$startup_wait_body" | rg -q -U --pcre2 \
    'if \(rendezvous\)[\s\S]*?if \(suspended\)[\s\S]*?if \(reqidle\)[\s\S]*?if \(debugged\)[\s\S]*?KASSERT\(!waiting' ||
    fail "startup wait does not prioritize lifecycle predicates over SIPI"
rg -q 'NVMX-EVENT-106.*Startup wait lifecycle precedence' "$ledger" ||
    fail "startup wait lifecycle-precedence requirement is absent"
rg -q 'NVMX-PRIVATE-165.*startup-wait-lifecycle-precedence' \
    "$private_ledger" ||
    fail "startup wait lifecycle-precedence policy is absent"
# TEST-ANCHOR: accepted-sipi-wakes-startup-target
# Clearing the wait-for-SIPI predicate is not sufficient once the staged
# kernel owner can put the target on its vCPU sleepqueue.  Require the
# predicate transition under rendezvous_mtx followed by an exact-target
# notification after releasing that outer owner, matching the wait-side lock
# order and closing both sides of the predicate-to-enqueue race.
startup_clear=$(sed -n \
    '/^vm_start_cpus(struct vm \*vm,/,/^}/p' "$vmm_source")
for contract in \
    'CPU_AND(&set, &vm->startup_cpus, tostart)' \
    'CPU_ANDNOT(&vm->startup_cpus, &vm->startup_cpus, &set)' \
    'mtx_unlock(&vm->rendezvous_mtx)' \
    'CPU_FOREACH_ISSET(vcpuid, &set)' \
    'vcpu_notify_event(vm_vcpu(vm, vcpuid))'; do
	printf '%s\n' "$startup_clear" | rg -q -F "$contract" ||
	    fail "accepted SIPI target notification is missing: $contract"
done
unlock_line=$(printf '%s\n' "$startup_clear" | rg -n -F \
    'mtx_unlock(&vm->rendezvous_mtx)' | head -n 1 | cut -d: -f1)
notify_line=$(printf '%s\n' "$startup_clear" | rg -n -F \
    'vcpu_notify_event(vm_vcpu(vm, vcpuid))' | head -n 1 | cut -d: -f1)
if [ -z "$unlock_line" ] || [ -z "$notify_line" ] ||
    [ "$notify_line" -le "$unlock_line" ]; then
	fail "accepted SIPI notifies before releasing rendezvous_mtx"
fi
rg -q 'NVMX-EVENT-067.*Event-driven prestarted AP sleep' "$ledger" ||
    fail "event-driven prestarted AP wait is absent from the ledger"
rg -q 'NVMX-EVENT-105.*Accepted SIPI wakes sleeping startup target' \
    "$ledger" || fail "accepted SIPI wake requirement is absent from the ledger"
rg -q 'NVMX-PRIVATE-123.*event-driven-prestarted-AP-wait' \
    "$private_ledger" ||
    fail "prestarted AP wait policy is absent from the private ledger"
rg -q 'NVMX-PRIVATE-164.*accepted-SIPI-target-notification' \
    "$private_ledger" ||
    fail "accepted SIPI notification policy is absent from the private ledger"
# private-test: admission-before-readiness-AP-wait-publication
for contract in \
	'vm_startup_enter(struct vm *vm,' \
	'vm_vcpu(vm, vcpuid) == NULL' \
	'mtx_lock(&vm->rendezvous_mtx)' \
	'already_waiting = CPU_ISSET(vcpuid, &vm->startup_cpus)' \
	'if (bootstrap_processor)' \
	'CPU_CLR(vcpuid, &vm->startup_cpus)' \
	'else' \
	'CPU_SET(vcpuid, &vm->startup_cpus)' \
	'vmm_event_coordinator_startup_enter(vm->event_coordinator,' \
	'if (error != 0)' \
	'if (already_waiting)' \
	'mtx_unlock(&vm->rendezvous_mtx)'; do
	rg -q -F "$contract" "$vmm_vm_source" ||
	    fail "AP wait publication/admission transaction is missing: $contract"
done
rg -q -F 'int vm_startup_enter(struct vm *,' "$vmm_vm_header" ||
    fail "AP startup admission wrapper declaration is missing"
rg -q 'cpuset_t[[:space:]]+startup_cpus;' "$vmm_vm_header" ||
    fail "startup wait set is not owned by the architecture-neutral VM"
if rg -q -F 'startup_cpus' "$src/sys/amd64/include/vmm.h"; then
	fail "startup wait set remains duplicated in amd64-private VM state"
fi
rg -q -U --pcre2 \
	'mtx_lock\(&vm->rendezvous_mtx\);[\s\S]*?vmm_event_coordinator_reset\(vm->event_coordinator\);[\s\S]*?if \(error == 0\)[\s\S]*?CPU_ZERO\(&vm->startup_cpus\);[\s\S]*?mtx_unlock\(&vm->rendezvous_mtx\);' \
	"$vmm_vm_source" || fail "common reset is not atomic with startup admission and wait-set clearing"
rg -q 'NVMX-EVENT-068.*Admission-before-readiness AP wait publication' \
	"$ledger" || fail "AP wait publication ordering is absent from the ledger"
rg -q 'NVMX-PRIVATE-124.*admission-before-readiness-AP-wait-publication' \
	"$private_ledger" ||
	fail "AP wait publication policy is absent from the private ledger"
rg -q 'NVMX-EVENT-069.*Atomic startup generation and wait-set reset' \
	"$ledger" || fail "atomic startup reset is absent from the ledger"
rg -q 'NVMX-PRIVATE-125.*atomic-startup-generation-and-wait-set-reset' \
	"$private_ledger" ||
	fail "atomic startup reset policy is absent from the private ledger"
# private-test: vm-startup-controller-boundary
for contract in \
	'vm_startup_controller_claim(struct vm *vm,' \
	'vm_startup_controller_release(struct vm *vm,' \
	'vm_startup_configure_kernel(struct vm *vm,' \
	'vm_startup_wait_ready(struct vm *vm,' \
	'vm_startup_commit(struct vm *vm,' \
	'vm_startup_status(struct vm *vm,'; do
	rg -q -F "$contract" "$vmm_vm_source" ||
	    fail "common VM startup controller boundary is missing: $contract"
done
for raw in \
	vmm_event_coordinator_startup_controller_claim \
	vmm_event_coordinator_startup_controller_release \
	vmm_event_coordinator_startup_configure_kernel \
	vmm_event_coordinator_startup_wait_ready \
	vmm_event_coordinator_startup_commit \
	vmm_event_coordinator_startup_status; do
	count=$(rg -l -g '*.c' -F "$raw(" "$src/sys" | wc -l | tr -d ' ')
	[ "$count" -eq 2 ] ||
	    fail "raw startup coordinator operation escaped its value owner and VM wrapper: $raw ($count source files)"
done
rg -q 'NVMX-EVENT-070.*Architecture-neutral startup controller VM boundary' \
	"$ledger" || fail "common startup controller VM boundary is absent from the ledger"
rg -q 'NVMX-PRIVATE-126.*vm-startup-controller-boundary' \
	"$private_ledger" ||
	fail "common startup controller private boundary is absent from the private ledger"
# private-test: generation-bearing-admission-retry
for contract in \
	'handshake->phase != VMM_STARTUP_HANDSHAKE_COLLECTING &&' \
	'handshake->phase != VMM_STARTUP_HANDSHAKE_COMMITTED' \
	'vcpu->bootstrap_processor == bootstrap_processor ?' \
	'EALREADY : EBUSY' \
	'if (error == EALREADY)' \
	'else if (error == 0)' \
	'if (error == 0 && changed)'; do
	rg -q -F "$contract" "$startup_handshake_source" \
	    "$event_coordinator_source" ||
	    fail "generation-bearing admission retry is missing: $contract"
done
rg -q -U --pcre2 \
    'vmm_startup_handshake_enter\(&handshake, 1, false\),[\s\S]*?EALREADY[\s\S]*?vmm_startup_handshake_enter\(&handshake, 1, true\), EBUSY' \
    "$startup_handshake_test_source" ||
	fail "collecting admission retry does not test exact BSP classification"
rg -q -U --pcre2 \
    'vmm_startup_handshake_commit\(&handshake\), 0\);[\s\S]*?vmm_startup_handshake_enter\(&handshake, 0, true\),[\s\S]*?EALREADY[\s\S]*?vmm_startup_handshake_enter\(&handshake, 3, false\),[\s\S]*?EALREADY' \
    "$startup_handshake_test_source" ||
	fail "committed admission retry is not tested"
rg -q 'NVMX-EVENT-072.*Exact generation-bearing admission retry' \
    "$ledger" || fail "generation-bearing admission retry is absent from the ledger"
rg -q 'NVMX-PRIVATE-128.*generation-bearing-admission-retry' \
    "$private_ledger" ||
	fail "generation-bearing admission retry policy is absent from the ledger"
rg -q 'NVMX-EVENT-053.*event-state commit ordering' "$ledger" ||
    fail "startup event-state commit ordering is absent from the ledger"
rg -q 'NVMX-PRIVATE-109.*exact-event-compare-clear' "$private_ledger" ||
    fail "exact event compare-clear boundary is absent from the private ledger"
# private-test: exact-event-compare-clear
rg -q -F 'vm_event_state_compare_clear(struct vcpu *' "$vmm_source" ||
    fail "exact event compare-clear implementation is absent"
rg -q -F 'vm_event_state_compare_clear(struct vcpu *,' "$vmm_header" ||
    fail "exact event compare-clear declaration is absent"
for contract in \
	'vm_event_output_overlaps_owner(vcpu->vm, expected,' \
	'expected_copy = *expected' \
	'error = vmm_event_coordinator_publisher_enter(' \
	'error = vm_event_state_capture_locked(vcpu, &current)' \
	'!vmm_event_state_equal(&current, &expected_copy)' \
	'vcpu->exception_pending = 0' \
	'vcpu_event_generation_advance_locked(vcpu)' \
	'vm_event_publisher_exit_checked(vcpu, &ticket)'; do
	rg -q -F "$contract" "$vmm_source" ||
	    fail "exact event compare-clear contract is missing: $contract"
done
rg -q -U --pcre2 \
    'vcpu_event_lock\(vcpu\);[\s\S]*?vmm_event_state_equal\(&current, &expected_copy\)[\s\S]*?vcpu_event_generation_advance_locked\(vcpu\);[\s\S]*?vcpu_event_unlock\(vcpu\);[\s\S]*?vm_event_publisher_exit_checked\(vcpu, &ticket\);' \
    "$vmm_source" ||
    fail "exact event compare-clear lock and publication order is not pinned"
rg -q -F 'named_equality_ignores_padding' "$event_test_source" ||
    fail "exact event comparison lacks an independent named-field test"
# private-test: x86-startup-transaction-executor
for contract in \
	'(*capture)(void *' \
	'(*apply)(void *)' \
	'(*rollback)(void *)' \
	'(*commit_event)(void *)' \
	'(*finalize)(void *)'; do
	rg -q -F "$contract" "$startup_execution_header" ||
	    fail "x86 startup transaction operation is missing: $contract"
done
for contract in \
	'error = ops_expected.capture(arg, input)' \
	'error = ops_expected.apply(arg)' \
	'error = ops_expected.commit_event(arg)' \
	'ops_expected.finalize(arg)' \
	'rollback_error = ops_expected.rollback(arg)' \
	'candidate.poisoned = 1'; do
	rg -q -F "$contract" "$startup_execution_source" ||
	    fail "x86 startup transaction ordering is missing: $contract"
done
for contract in \
	'success_commit_order' \
	'capture_failure_has_no_rollback' \
	'sipi_input_reaches_capture' \
	'negative_callback_error_is_protocol_error' \
	'apply_failure_rolls_back' \
	'event_race_rolls_back' \
	'rollback_failure_poisoned' \
	'apply_contract_violation_uses_captured_rollback' \
	'post_event_violation_does_not_fake_rollback' \
	'rejection_is_failure_atomic'; do
	rg -q -F "$contract" "$startup_execution_test_source" ||
	    fail "x86 startup transaction test is missing: $contract"
done
rg -q -F 'vmm_x86_startup_transaction.c' "$module_makefile" ||
    fail "x86 startup transaction executor is absent from vmm.ko"
rg -q 'NVMX-EVENT-054.*startup transaction executor' "$ledger" ||
    fail "x86 startup transaction executor is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-110.*startup-transaction-executor' "$private_ledger" ||
    fail "x86 startup transaction executor is absent from the private ledger"
# private-test: x86-startup-machine-adapter
for contract in \
	'VMM_X86_STARTUP_REG_INTR_SHADOW' \
	'VMM_X86_STARTUP_DESC_IDTR' \
	'(*event_compare_clear)(void *' \
	'struct vmm_x86_startup_finalizer *'; do
	rg -q -F "$contract" "$startup_machine_header" ||
	    fail "x86 startup machine interface is missing: $contract"
done
for contract in \
	'startup_machine_setreg_verified' \
	'startup_machine_setdesc_verified' \
	'startup_machine_restore_reg_verified' \
	'startup_machine_restore_desc_verified' \
	'transaction->applied_regs++' \
	'transaction->applied_descs++' \
	'ops.getreg(transaction->arg' \
	'ops.getdesc(transaction->arg' \
	'ops.event_capture(transaction->arg' \
	'ops.event_compare_clear(transaction->arg' \
	'vmm_x86_startup_finalizer_check(transaction->finalizer' \
	'startup_machine_finalizer_equal(' \
	'vmm_x86_startup_finalizer_commit(transaction->finalizer)' \
	'vmm_x86_startup_finalizer_consumed(finalizer)' \
	'vmm_x86_startup_transaction_execute(&input_candidate' \
	'result->poisoned = 1'; do
	rg -q -F "$contract" "$startup_machine_source" ||
	    fail "x86 startup machine contract is missing: $contract"
done
rg -q -U --pcre2 \
    'startup_machine_setreg_verified\([\s\S]*?setreg\([\s\S]*?applied_regs\+\+[\s\S]*?getreg\([\s\S]*?observed == value' \
    "$startup_machine_source" ||
    fail "x86 startup register writes are not verified before commit"
rg -q -U --pcre2 \
    'startup_machine_setdesc_verified\([\s\S]*?setdesc\([\s\S]*?applied_descs\+\+[\s\S]*?getdesc\([\s\S]*?startup_machine_desc_equal' \
    "$startup_machine_source" ||
    fail "x86 startup descriptor writes are not verified before commit"
for contract in \
	'init_commits_complete_architectural_value' \
	'sipi_changes_only_cs_and_rip' \
	'each_init_setter_failure_rolls_back' \
	'each_sipi_setter_failure_rolls_back' \
	'silent_register_write_is_detected_and_rolled_back' \
	'silent_descriptor_write_is_detected_and_rolled_back' \
	'silent_rollback_is_poisoned' \
	'mutating_setter_error_is_rolled_back' \
	'event_race_rolls_back_machine_state' \
	'external_input_mutation_is_poisoned' \
	'external_callback_mutation_is_poisoned' \
	'mismatched_finalizer_is_rejected_before_capture' \
	'external_finalizer_mutation_is_poisoned' \
	'postcommit_finalizer_repopulation_is_poisoned'; do
	rg -q -F "$contract" "$startup_machine_test_source" ||
	    fail "x86 startup machine test is missing: $contract"
done
rg -q -F 'vmm_x86_startup_machine.c' "$module_makefile" ||
    fail "x86 startup machine adapter is absent from vmm.ko"
rg -q 'NVMX-EVENT-055.*transactional machine-state adapter' "$ledger" ||
    fail "x86 startup machine adapter is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-111.*startup-machine-state-adapter' "$private_ledger" ||
    fail "x86 startup machine adapter is absent from the private ledger"
# private-test: x86-startup-vmreg-map
for contract in \
	vmm_x86_startup_register_vmreg \
	vmm_x86_startup_descriptor_vmreg; do
	rg -q -F "$contract" "$startup_vmreg_header" "$startup_vmreg_source" ||
	    fail "x86 startup VM register map is missing: $contract"
done
for contract in \
	'case VMM_X86_STARTUP_REG_INTR_SHADOW:' \
	'candidate = VM_REG_GUEST_INTR_SHADOW;' \
	'case VMM_X86_STARTUP_DESC_IDTR:' \
	'candidate = VM_REG_GUEST_IDTR;' \
	'*destination = candidate;'; do
	rg -q -F "$contract" "$startup_vmreg_source" ||
	    fail "x86 startup VM register map contract is missing: $contract"
done
for contract in \
	register_mapping_is_complete \
	descriptor_mapping_is_complete \
	rejection_preserves_output; do
	rg -q -F "$contract" "$startup_vmreg_test_source" ||
	    fail "x86 startup VM register map test is missing: $contract"
done
rg -q -F 'vmm_x86_startup_vmreg.c' "$module_makefile" ||
    fail "x86 startup VM register map is absent from vmm.ko"
rg -q 'NVMX-EVENT-056.*startup-to-backend register mapping' "$ledger" ||
    fail "x86 startup VM register map is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-112.*startup-to-VM_REG-map' "$private_ledger" ||
    fail "x86 startup VM register map is absent from the private ledger"
# private-test: x86-startup-composite-backend
for contract in \
	vmm_x86_startup_backend_init \
	vmm_x86_startup_backend_getreg \
	vmm_x86_startup_backend_setreg \
	vmm_x86_startup_backend_getdesc \
	vmm_x86_startup_backend_setdesc; do
	rg -q -F "$contract" "$startup_backend_header" \
	    "$startup_backend_source" ||
	    fail "x86 startup composite backend is missing: $contract"
done
for contract in \
	'startup_backend_validate(backend)' \
	'old_selector > UINT16_MAX' \
	'selector > UINT16_MAX' \
	'restore_desc_error = backend->ops.setdesc' \
	'restore_reg_error = backend->ops.setreg' \
	'restore_desc_error != 0 || restore_reg_error != 0'; do
	rg -q -F "$contract" "$startup_backend_source" ||
	    fail "x86 startup composite backend contract is missing: $contract"
done
for contract in \
	composite_descriptor_round_trip \
	hidden_failure_restores_both_halves \
	mutating_hidden_failure_restores_both_halves \
	restore_failure_is_reported_and_not_hidden \
	wide_selector_and_rejection_preserve_output \
	register_mapping_delegates_exact_name \
	corrupt_context_fails_closed; do
	rg -q -F "$contract" "$startup_backend_test_source" ||
	    fail "x86 startup composite backend test is missing: $contract"
done
rg -q -F 'vmm_x86_startup_backend.c' "$module_makefile" ||
    fail "x86 startup composite backend is absent from vmm.ko"
rg -q 'NVMX-EVENT-057.*Composite startup backend adapter' "$ledger" ||
    fail "x86 startup composite backend is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-113.*composite-VM_REG-backend-adapter' \
    "$private_ledger" ||
    fail "x86 startup composite backend is absent from the private ledger"
# private-test: x86-startup-frozen-target-finalizer
for contract in \
	vmm_x86_startup_finalizer_plan \
	vmm_x86_startup_finalizer_init \
	vmm_x86_startup_finalizer_check \
	vmm_x86_startup_finalizer_consumed \
	vmm_x86_startup_finalizer_commit; do
	rg -q -F "$contract" "$startup_finalizer_header" \
	    "$startup_finalizer_source" ||
	    fail "x86 startup frozen-target finalizer is missing: $contract"
done
for contract in \
	'candidate.kind = input->kind;' \
	'candidate.vector = input->vector;' \
	'candidate.bootstrap_processor = input->bootstrap_processor;' \
	'(uint64_t)input->vector << VMM_X86_SIPI_SHIFT;' \
	'plan->startup_wait == !plan->bootstrap_processor' \
	'candidate.ops = *ops;' \
	'candidate.plan = *plan;' \
	'bound = *finalizer;' \
	'memset(finalizer, 0, sizeof(*finalizer));' \
	'panic("%s: corrupt finalizer", __func__);' \
	'bound.ops.reset_nested(bound.arg);' \
	'bound.ops.reset_lapic(bound.arg);' \
	'bound.ops.retire_translation_residency(bound.arg);' \
	'bound.ops.set_nextrip(bound.arg, bound.plan.nextrip);' \
	'bound.ops.publish_startup_wait(bound.arg,'; do
	rg -q -F "$contract" "$startup_finalizer_source" ||
	    fail "x86 startup frozen-target finalizer contract is missing: $contract"
done
for contract in \
	init_ap_order \
	init_bsp_remains_runnable \
	sipi_changes_only_nextrip_and_wait \
	sipi_plan_binds_vector_and_entrypoint \
	rejection_is_failure_atomic \
	binding_copies_plan_and_callbacks \
	binding_matches_exact_input; do
	rg -q -F "$contract" "$startup_finalizer_test_source" ||
	    fail "x86 startup frozen-target finalizer test is missing: $contract"
done
rg -q -U --pcre2 \
    'sipi_changes_only_cs_and_rip[\s\S]*?published_nextrip, UINT64_C\(0x5a000\)' \
    "$startup_machine_test_source" ||
    fail "composed SIPI machine transaction does not prove final nextrip"
rg -q -F 'vmm_x86_startup_finalizer.c' "$module_makefile" ||
    fail "x86 startup frozen-target finalizer is absent from vmm.ko"
rg -q 'NVMX-EVENT-059.*frozen-target startup finalizer' "$ledger" ||
    fail "x86 startup frozen-target finalizer is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-115.*one-shot-startup-finalizer' "$private_ledger" ||
    fail "x86 startup frozen-target finalizer is absent from the private ledger"
rg -q 'NVMX-EVENT-087.*SIPI final-entry publication invariant' "$ledger" ||
    fail "SIPI final-entry publication invariant is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-143.*sipi-vector-entrypoint-binding' "$private_ledger" ||
    fail "SIPI vector entrypoint binding is absent from the private ledger"
# private-test: startup-padding-independent-integrity
for contract in \
	vmx_nested_startup_transaction_equal \
	nvmx_startup_claim_equal \
	nvmxsd_claim_equal \
	nvmxsd_dispatch_equal; do
	rg -q -F "$contract" "$src/sys/amd64/vmm/intel/vmx_nested_startup_transaction.c" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_startup_dispatch.c" ||
	    fail "startup named integrity comparison is missing: $contract"
done
if rg -q 'memcmp\(' "$src/sys/amd64/vmm/intel/vmx_nested_startup_transaction.c" \
    "$src/sys/amd64/vmm/intel/vmx_nested_startup_dispatch.c"; then
	fail "durable startup owner integrity still depends on object padding"
fi
rg -q -F 'startup_named_equality_ignores_padding' \
    "$src/tests/sys/vmm/vmx_nested_state_test.c" ||
    fail "startup padding-independent equality test is missing"
rg -q 'NVMX-EVENT-088.*Padding-independent startup owner integrity' \
    "$ledger" || fail "startup named integrity requirement is missing"
rg -q 'NVMX-PRIVATE-144.*named-owner-integrity-comparison' \
    "$private_ledger" || fail "startup named integrity interface is missing"
# private-test: common-startup-padding-independent-integrity
rg -q -F 'vmm_x86_startup_transaction_input_equal' \
    "$startup_execution_source" "$startup_machine_source" ||
    fail "common startup named input integrity comparison is missing"
if rg -q 'memcmp\(input' "$startup_execution_source" \
    "$startup_machine_source"; then
	fail "common startup input integrity still depends on object bytes"
fi
rg -q -F 'input_equality_uses_named_fields' \
    "$startup_execution_test_source" ||
    fail "common startup named-input equality test is missing"
rg -q 'NVMX-EVENT-089.*Padding-independent common startup input integrity' \
    "$ledger" || fail "common startup named-input requirement is missing"
rg -q 'NVMX-PRIVATE-145.*named-input-integrity-comparison' \
    "$private_ledger" || fail "common startup named-input interface is missing"
# private-test: startup-controller-named-empty-state
rg -q -U --pcre2 \
    'startup_controller_ticket_empty[\s\S]*?ticket->owner_id == 0[\s\S]*?ticket->generation == 0[\s\S]*?ticket->controller_id == 0[\s\S]*?ticket->state_cookie == 0[\s\S]*?ticket->storage_cookie == 0[\s\S]*?ticket->active == 0[\s\S]*?startup_controller_reserved_empty' \
    "$startup_controller_source" ||
    fail "startup controller empty-ticket predicate is not named-field based"
if rg -q 'memcmp\(' "$startup_controller_source"; then
	fail "startup controller credential logic depends on object bytes"
fi
rg -q -F 'ticket_empty_is_named_state' "$startup_controller_test_source" ||
    fail "startup controller named empty-state test is missing"
rg -q 'NVMX-EVENT-090.*Named empty-state startup credential validation' \
    "$ledger" || fail "startup controller named empty-state requirement is missing"
rg -q 'NVMX-PRIVATE-146.*named-empty-ticket-predicate' \
    "$private_ledger" || fail "startup controller named empty-state interface is missing"
# private-test: sipi-non-bsp-admission
rg -q -U --pcre2 \
    'input->kind == VMM_STARTUP_EVENT_SIPI &&[[:space:]]*input->bootstrap_processor != 0' \
    "$startup_execution_source" ||
    fail "shared startup transaction does not reject SIPI to the BSP"
rg -q -F 'sipi_rejects_bootstrap_processor' \
    "$startup_execution_test_source" ||
    fail "shared startup transaction lacks SIPI BSP negative coverage"
rg -q 'NVMX-EVENT-091.*SIPI non-BSP admission invariant' "$ledger" ||
    fail "SIPI non-BSP admission requirement is missing"
rg -q 'NVMX-PRIVATE-147.*sipi-bootstrap-admission' "$private_ledger" ||
    fail "SIPI BSP private admission interface is missing"
# private-test: l0-startup-owner-inventory
for contract in VMX_NESTED_L0_STARTUP_BLOCKERS \
    vmx_nested_l0_startup_preflight_validate \
    vmx_nested_ept_binding_validate \
	vmx_nested_ept_cache_quiesce \
    vmx_nested_vmcs02_lease_owner_validate \
	vmx_nested_vmcs02_intel_inactive_validate; do
	rg -q -F "$contract" "$startup_transaction_header" \
	    "$startup_transaction_source" "$vmx_source" ||
	    fail "L0 startup owner-inventory contract is missing: $contract"
done
for owner in CONTEXT CONTINUATION RUNTIME MTF THAW REFREEZE PORTABLE \
    VMCS02 EPT LEASES WORKSPACE EXIT_MSR PREPARED HARDWARE_MSR VPID \
    HOT_FAILURE VMCS_REGISTRY; do
	rg -q -F "VMX_NESTED_L0_STARTUP_$owner" "$vmx_source" ||
	    fail "production L0 startup preflight omits owner class: $owner"
done
rg -q -U --pcre2 \
    'sx_slock\(&vcpu->vmx->nested_vmcs_sx\);[\s\S]*?vmx_nested_vmcs_registry_owner_active\([\s\S]*?vcpu->vcpuid[\s\S]*?sx_sunlock\(&vcpu->vmx->nested_vmcs_sx\);[\s\S]*?VMX_NESTED_L0_STARTUP_VMCS_REGISTRY' \
    "$vmx_source" ||
    fail "production L0 startup preflight does not serialize VMCS ownership"
rg -q -U --pcre2 \
    'vmx_nested_vmcs_registry_owner_active\([\s\S]*?vmx_nested_vmcs_registry_storage_overlaps\([\s\S]*?seen == registry->limit[\s\S]*?seen != registry->count[\s\S]*?\*active = matches != 0' \
	"$registry_source" ||
    fail "VMCS registry owner query is not bounded and alias-safe"
rg -q -F 'startup_l0_preflight_inventory' "$test_source" ||
    fail "L0 startup owner-inventory negative test is missing"
rg -q -F 'vmcs02_intel_inactive_owner' "$test_source" ||
    fail "VMCS02 Intel inactive-owner negative test is missing"
rg -q -U --pcre2 \
	'nvmxi_begin\([\s\S]*?vmx_nested_vmcs02_intel_inactive_validate\(adapter\)[\s\S]*?if \(error != 0\)[\s\S]*?return \(error\);[\s\S]*?vmclear\(adapter->vmcs02\)' \
    "$vmcs02_intel_source" ||
	fail "VMCS02 hardware begin bypasses typed inactive-owner admission"
for contract in \
    'vmx_startup_preflight_owner_error(' \
	'(blocker & (blocker - 1)) != 0' \
    'if (error != EBUSY)' \
    'preflight->blockers |= blocker' \
	'vmx_nested_ept_cache_owner_quiesce(vcpu)' \
    'vcpu->nested_tsc_aux_rollback_residency <' \
    'vcpu->nested_tsc_aux_rollback_residency !=' \
    'VMX_NESTED_L2_THAW_STAGED_POISONED' \
    'VMX_NESTED_REFREEZE_POISONED'; do
	rg -q -F "$contract" "$vmx_source" ||
	    fail "typed L0 startup owner preflight omits: $contract"
done
rg -q 'NVMX-EVENT-092.*L0 startup owner-inventory preflight' \
    "$ledger" || fail "L0 startup preflight requirement is missing"
rg -q 'NVMX-PRIVATE-148.*l0-startup-preflight' "$private_ledger" ||
    fail "L0 startup private contract is missing"
rg -q 'NVMX-EVENT-099.*VMCS registry ownership in startup preflight' \
    "$ledger" || fail "VMCS registry startup requirement is missing"
rg -q 'NVMX-PRIVATE-155.*owner-active-query' "$private_ledger" ||
    fail "VMCS registry owner query private contract is missing"
rg -q 'NVMX-EVENT-112.*Typed complete L0 startup owner preflight' \
    "$ledger" || fail "typed startup owner requirement is missing"
rg -q 'NVMX-PRIVATE-173.*typed-L0-startup-owner-classification' \
    "$private_ledger" || fail "typed startup owner contract is missing"
rg -q 'NVMX-EVENT-113.*Typed hardware VMCS02 transaction admission' \
    "$ledger" || fail "typed VMCS02 begin requirement is missing"
rg -q 'NVMX-PRIVATE-174.*typed-hardware-begin-admission' \
    "$private_ledger" || fail "typed VMCS02 begin contract is missing"
# private-test: typed-context-quiescence
for contract in \
    'context->phase > VMX_NESTED_CONTEXT_ABORTED' \
    '!nvmx_context_machine_valid(&context->machine)' \
    'context->abort_indicator > 6' \
    'context->phase == VMX_NESTED_CONTEXT_ABORTED' \
    'return (EPROTO);'; do
	rg -q -F "$contract" "$context_source" ||
	    fail "typed context quiescence omits: $contract"
done
rg -q -F 'malformed.phase = (enum vmx_nested_context_phase)99' \
    "$test_source" || fail "typed context quiescence phase test is missing"
rg -q -F 'malformed.machine.vmxon_gpa = 0' "$test_source" ||
    fail "typed context quiescence machine test is missing"
rg -q -F 'malformed.abort_indicator = 7' "$test_source" ||
    fail "typed context quiescence abort test is missing"
rg -q 'NVMX-EVENT-114.*Typed canonical nested-context quiescence' \
    "$ledger" || fail "typed context quiescence requirement is missing"
rg -q 'NVMX-PRIVATE-175.*typed-context-quiescence' \
    "$private_ledger" || fail "typed context quiescence contract is missing"
# private-test: prepared-entry-cross-owner
for contract in \
    'vmx_nested_prepared_owner_validate(const struct vmx_vcpu *vcpu)' \
    '!vcpu->nested_vmcs02_plan_valid' \
    'vcpu->nested_msr_workspace.active' \
    'vcpu->nested_msr_generation !=' \
    'vcpu->nested_msr_workspace.generation' \
    'vcpu->nested_entry_msr_count >' \
    'vcpu->nested_vmcs12_snapshot.controls.entry_msr_load_count' \
    'vmx_nested_vmcs02_id_equal(&vcpu->nested_vmcs02_plan.id,' \
    'VMX_NESTED_VMENTRY_READY'; do
	rg -q -F "$contract" "$vmx_source" ||
	    fail "prepared-entry cross-owner validation omits: $contract"
done
[ "$(rg -c -F 'vmx_nested_prepared_owner_validate(vcpu)' "$vmx_source")" \
    -ge 3 ] || fail "prepared-entry owner is not validated at all three frozen boundaries"
rg -q 'NVMX-EVENT-115.*Cross-object prepared-entry ownership validation' \
    "$ledger" || fail "prepared-entry ownership requirement is missing"
rg -q 'NVMX-PRIVATE-176.*prepared-entry-cross-owner' \
    "$private_ledger" || fail "prepared-entry ownership contract is missing"
# private-test: nested-run-local-plan-precondition
# The selector currently supplies a valid VMCS02 plan before this helper is
# called.  Keep the helper independently defensive: a future caller or a
# restore-path refactor must not reach a plan dereference without that proof.
rg -q -U --pcre2 \
    'vmx_run_nested\(struct vmx_vcpu \*vcpu,[\s\S]*?if \(vcpu == NULL \|\| pmap == NULL \|\| evinfo == NULL \|\|[\s\S]*?!vcpu->nested_vmcs02_plan_valid\)[\s\S]*?return \(EINVAL\);' \
    "$vmx_source" ||
    fail "nested run does not locally reject an invalid VMCS02 plan"
# private-test: init-ept-cache-retirement
rg -q -U --pcre2 \
    'vmx_startup_reset_nested\(void \*arg\)[\s\S]*?vmx_nested_ept_cache_empty\([\s\S]*?vmx_nested_vpid_owner_release\([\s\S]*?vmx_nested_context_reset\(' \
    "$vmx_source" || fail "INIT finalizer does not require pre-retired EPT roots"
rg -q -U --pcre2 \
    'vmx_startup_prepare_l0\(void \*arg,[\s\S]*?vmx_startup_l0_owner_preflight\(arg, kind, vector\)[\s\S]*?kind == VMX_NESTED_STARTUP_SIPI\)[\s\S]*?return \(0\);[\s\S]*?vmx_nested_ept_cache_destroy\(&vcpu->nested_ept_cache\)[\s\S]*?vmx_nested_ept_cache_empty\(&vcpu->nested_ept_cache\)' \
    "$vmx_source" ||
    fail "fallible INIT EPT retirement is missing or incorrectly affects SIPI"
rg -q -U --pcre2 \
    'VMX_NESTED_STARTUP_ACTION_APPLY_L0[\s\S]*?ops_snapshot.prepare_l0\(arg,[\s\S]*?VMX_NESTED_STARTUP_TRANSACTION_PLANNED' \
    "$startup_transaction_source" ||
    fail "startup preparation does not retain a retryable exact transaction"
for contract in \
    'context.prepare_error = EAGAIN;' \
    'ATF_CHECK_EQ(context.prepare_calls, 2);' \
    'ATF_CHECK(!context.derived_cache_present);' \
    'context.mutate_prepare_transaction = true;'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "INIT preparation model coverage omits: $contract"
done
rg -q -F 'Root destruction may release a vmspace' "$vmx_source" ||
    fail "INIT finalizer does not document its precommit EPT retirement blocker"
rg -q 'NVMX-EVENT-116.*INIT retires destination-local nested EPT roots' \
    "$ledger" || fail "INIT EPT retirement requirement is missing"
rg -q 'NVMX-PRIVATE-177.*INIT-nested-EPT-cache-retirement' \
    "$private_ledger" || fail "INIT EPT retirement contract is missing"
# private-test: typed-ept-cache-quiescence
for contract in \
    'nvmx_ept_cache_validate(' \
    'cache->ops.create == NULL' \
    'entry->generation > cache->next_generation' \
    'entry->last_used > cache->clock' \
    'entry->runtime_root == other->runtime_root' \
    'entry->generation == other->generation' \
    'vmx_nested_ept_cache_key_equal(&entry->key,'; do
	rg -q -F "$contract" "$src/sys/amd64/vmm/intel/vmx_nested_ept_cache.c" ||
	    fail "typed EPT cache quiescence omits: $contract"
done
for contract in \
    'vmx_nested_ept_cache_owner_quiesce(' \
    'vcpu->nested_ept_cache.entries != vcpu->nested_ept_entries' \
    'vcpu->nested_ept_cache.ops.create !=' \
    'vcpu->nested_ept_cache.ops.destroy !=' \
    'vcpu->nested_ept_cache.ops.invalidate !=' \
    'vcpu->nested_ept_cache.arg != &vcpu->nested_ept_backend' \
    'VM_MAXUSER_ADDRESS_LA48'; do
	rg -q -F "$contract" "$vmx_source" ||
	    fail "production EPT cache owner validation omits: $contract"
done
for contract in \
    'cache.capacity = 0' \
    'cache.ops.create = NULL' \
    'entries[0].generation = 1' \
    'entries[1].runtime_root = entries[0].runtime_root'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "typed EPT cache negative test omits: $contract"
done
rg -q 'NVMX-EVENT-117.*Typed EPT cache and production-owner quiescence' \
    "$ledger" || fail "typed EPT cache requirement is missing"
rg -q 'NVMX-PRIVATE-178.*typed-EPT-cache-owner-quiescence' \
    "$private_ledger" || fail "typed EPT cache private contract is missing"
# private-test: ept-cache-hot-path-header-validation
for contract in \
    'vmx_nested_ept_cache_header_validate(' \
    'cache->ops.create == NULL' \
    'cache->ops.destroy == NULL' \
    'cache->ops.invalidate == NULL'; do
	rg -q -F "$contract" "$src/sys/amd64/vmm/intel/vmx_nested_ept_cache.c" ||
	    fail "EPT cache hot-path header validation omits: $contract"
done
[ "$(rg -c -F 'vmx_nested_ept_cache_header_validate(cache)' \
    "$src/sys/amd64/vmm/intel/vmx_nested_ept_cache.c")" -ge 5 ] ||
    fail "EPT cache header validation does not cover every public hot path"
for contract in \
    'malformed_ops.invalidate = NULL' \
    'vmx_nested_ept_cache_acquire(&cache, &second,' \
    'vmx_nested_ept_cache_resolve(&cache, &first_ref, &first,' \
    'vmx_nested_ept_cache_release(&cache, &first_ref)' \
    'vmx_nested_ept_cache_invalidate(&cache,'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "EPT cache malformed-provider test omits: $contract"
done
rg -q 'NVMX-EVENT-118.*EPT cache hot-path callback-table validation' \
    "$ledger" || fail "EPT cache hot-path requirement is missing"
rg -q 'NVMX-PRIVATE-179.*hot-path-header-validation' \
    "$private_ledger" || fail "EPT cache hot-path private contract is missing"
# private-test: ept-cache-selected-entry-validation
for contract in \
    'vmx_nested_ept_cache_entry_validate(' \
	'vmx_nested_ept_cache_slot_validate(' \
    'entries[first_ref.slot].runtime_root = NULL' \
	'entries[1].runtime_root = (void *)(uintptr_t)UINT64_C(0xbeef);' \
    'vmx_nested_ept_cache_release(&cache, &first_ref), EPROTO' \
    'vmx_nested_ept_cache_resolve(&cache, &first_ref, &first,' \
    'vmx_nested_ept_cache_invalidate(&cache,'; do
	rg -q -F "$contract" "$src/sys/amd64/vmm/intel/vmx_nested_ept_cache.c" \
	    "$test_source" ||
	    fail "EPT cache selected-entry validation omits: $contract"
done
[ "$(rg -c -F 'vmx_nested_ept_cache_entry_validate(cache, entry)' \
    "$src/sys/amd64/vmm/intel/vmx_nested_ept_cache.c")" -ge 5 ] ||
    fail "EPT cache selected-entry validation misses a root consumer"
rg -q 'NVMX-EVENT-166.*Selected EPT-cache slot validation' \
    "$ledger" || fail "EPT cache selected-entry requirement is missing"
rg -q 'NVMX-PRIVATE-241.*selected-retained-slot-validation' \
    "$private_ledger" ||
    fail "EPT cache selected-entry private contract is missing"
rg -q -F 'vmx_nested_ept_cache_slot_validate(cache, entry)' \
    "$src/sys/amd64/vmm/intel/vmx_nested_ept_cache.c" ||
    fail "EPT cache selected empty slot is not validated"
# private-test: ept-cache-duplicate-root-quarantine
rg -q -F 'identity that is already retained violates that private contract' \
    "$src/sys/amd64/vmm/intel/vmx_nested_ept_cache.c" ||
    fail "EPT cache duplicate-provider contract is not explicit"
rg -q -F 'not call destroy on it' \
    "$src/sys/amd64/vmm/intel/vmx_nested_ept_cache.c" ||
    fail "EPT cache duplicate root is not quarantined before destruction"
for contract in \
    'backend.forced_root = first_ref.runtime_root' \
    'ATF_CHECK_EQ(backend.destroy_count, 0);' \
    'ATF_CHECK_EQ(backend.destroy_count, 1);'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "EPT cache duplicate-transfer regression omits: $contract"
done
rg -q 'NVMX-EVENT-167.*Malformed duplicate EPT-root quarantine' \
    "$ledger" || fail "EPT cache rejected-transfer requirement is missing"
rg -q 'NVMX-PRIVATE-243.*duplicate-created-root-quarantine' \
    "$private_ledger" ||
    fail "EPT cache rejected-transfer private contract is missing"
# private-test: typed-vpid-mutating-consumers
for function in \
    vmx_nested_vpid_owner_acquire \
    vmx_nested_vpid_owner_release \
    vmx_nested_vpid_owner_request_flush \
    vmx_nested_vpid_owner_flush_required_on_cpu \
    vmx_nested_vpid_owner_flush_complete_on_cpu; do
	rg -q -U --pcre2 \
	    "$function\\([\\s\\S]*?error = vmx_nested_vpid_owner_validate\\(owner\\);[\\s\\S]*?return \\(error\\);" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_vpid_owner.c" ||
	    fail "VPID mutating consumer collapses typed owner error: $function"
done
for contract in \
    'vmx_nested_vpid_owner_release(&owner, &ops,' \
    'vmx_nested_vpid_owner_acquire(&owner, 5, &ops,' \
    'vmx_nested_vpid_owner_request_flush(&owner)' \
    'vmx_nested_vpid_owner_flush_required_on_cpu(' \
    'vmx_nested_vpid_owner_flush_complete_on_cpu('; do
	rg -q -F "$contract" "$test_source" ||
	    fail "typed VPID malformed-owner test omits: $contract"
done
rg -q 'NVMX-EVENT-119.*Typed VPID owner errors at every mutating consumer' \
    "$ledger" || fail "typed VPID consumer requirement is missing"
rg -q 'NVMX-PRIVATE-180.*typed-mutating-consumer-errors' \
    "$private_ledger" || fail "typed VPID consumer private contract is missing"
# private-test: typed-mtf-direct-consumers
for function in \
    vmx_nested_mtf_owner_take_portable \
    vmx_nested_mtf_owner_put_portable \
    vmx_nested_mtf_owner_peek \
    vmx_nested_mtf_owner_consume; do
	rg -q -U --pcre2 \
	    "$function\\([\\s\\S]*?error = vmx_nested_mtf_owner_validate\\(owner\\);[\\s\\S]*?return \\(error\\);" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_mtf_owner.c" ||
	    fail "MTF direct consumer collapses typed owner error: $function"
done
for contract in \
    'malformed_owner.origin_generation = 1' \
    'vmx_nested_mtf_owner_take_portable(' \
    'vmx_nested_mtf_owner_put_portable(' \
    'vmx_nested_mtf_owner_peek(&malformed_owner,' \
    'vmx_nested_mtf_owner_consume(&malformed_owner,'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "typed MTF malformed-owner test omits: $contract"
done
rg -q 'NVMX-EVENT-120.*Typed MTF owner errors at every direct consumer' \
    "$ledger" || fail "typed MTF consumer requirement is missing"
rg -q 'NVMX-PRIVATE-181.*typed-direct-consumer-errors' \
    "$private_ledger" || fail "typed MTF consumer private contract is missing"
# private-test: vmcs02-lease-callback-isolation
lease_source="$src/sys/amd64/vmm/intel/vmx_nested_vmcs02_lease.c"
for contract in \
    'struct vmx_nested_vmcs02_lease_ops ops_snapshot;' \
    'owner_before = *owner;' \
    'ops_snapshot = *ops;' \
    'nvmxl_release_all(&candidate, &ops_snapshot, arg)' \
    '*owner = owner_before;' \
    'candidate = *owner;'; do
	rg -q -F "$contract" "$lease_source" ||
	    fail "VMCS02 lease callback isolation omits: $contract"
done
[ "$(rg -c -F 'error = vmx_nested_vmcs02_lease_owner_validate(owner);' \
    "$lease_source")" -eq 2 ] ||
    fail "VMCS02 lease consumers do not both propagate typed owner state"
for contract in \
    'fixture.corrupt_owner = true' \
    'fixture.corrupt_ops = true' \
    'ATF_CHECK(ops.release == NULL)' \
    'vmx_nested_vmcs02_lease_owner_validate(&owner), 0'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "VMCS02 lease callback-isolation test omits: $contract"
done
for contract in \
	'Calls run only in a fallible frozen-vCPU preparation or release' \
	'may enter guest-page mapping code' \
	'must never' \
	'irreversible finalizer' \
	'snapshots this table'; do
	rg -q -F "$contract" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_vmcs02_lease.h" ||
	    fail "VMCS02 lease callback contract omits: $contract"
done
rg -q 'NVMX-EVENT-121.*Transactional VMCS02 lease callback isolation' \
    "$ledger" || fail "VMCS02 lease callback requirement is missing"
rg -q 'NVMX-PRIVATE-182.*callback-isolated-owner-transaction' \
    "$private_ledger" || fail "VMCS02 lease private contract is missing"
# private-test: hardware-entry-callback-snapshot
hardware_entry_source="$src/sys/amd64/vmm/intel/vmx_nested_hardware_entry.c"
for contract in \
    'nvmxhe_callback_error(int error)' \
    'error = vmx_nested_entry_runtime_validate(runtime);' \
    'return (ESTALE);' \
    'struct vmx_nested_hardware_entry_ops ops_snapshot;' \
    'ops_snapshot = *ops;' \
    'ops_snapshot.install_msrs(' \
    'ops_snapshot.program_vmcs02(' \
    'ops_snapshot.rollback_msrs(' \
    'ops_snapshot.commit_vmcs_launch(' \
    'ops_snapshot.commit_msrs(' \
    'ops_snapshot.leave_vmcs02('; do
	rg -q -F "$contract" "$hardware_entry_source" ||
	    fail "hardware-entry callback snapshot omits: $contract"
done
for contract in \
    'runtime.abort_cleanup = VMX_NESTED_ENTRY_CLEANUP_CANCEL' \
    'fixture.mutable_ops = &mutable_ops' \
    'fixture.corrupt_ops = true' \
    'mutable_ops.program_vmcs02 == NULL' \
    'fixture.install_error = -1'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "hardware-entry negative callback test omits: $contract"
done
for contract in \
    'One CPU-pinned transition snapshots this complete table' \
    'Callbacks must not sleep' \
    'mutate the context/runtime ownership objects'; do
	rg -q -F "$contract" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_hardware_entry.h" ||
	    fail "hardware-entry callback contract omits: $contract"
done
rg -q 'NVMX-EVENT-122.*Typed and callback-stable hardware-entry transitions' \
    "$ledger" || fail "hardware-entry callback requirement is missing"
rg -q 'NVMX-PRIVATE-183.*typed-captured-transition-ops' \
    "$private_ledger" || fail "hardware-entry private contract is missing"
# private-test: typed-production-owner-composition
if [ "$(rg -c -F 'vmx_nested_vmcs02_lease_owner_validate(' \
    "$vmcs02_resources_intel_source")" -ne 2 ]; then
	fail "VMCS02 resource wrapper does not validate both lease-owner boundaries"
fi
if [ "$(rg -c -F 'vmx_nested_ept_binding_validate(' \
    "$vmcs02_resources_intel_source")" -ne 2 ]; then
	fail "VMCS02 resource wrapper does not validate both EPT-owner boundaries"
fi
for contract in \
    'return (EBUSY);' \
    'return (ENOENT);' \
    'return (ESTALE);'; do
	rg -q -F "$contract" "$vmcs02_resources_intel_source" ||
	    fail "VMCS02 resource typed-owner contract omits: $contract"
done
for contract in \
    'nvmx_environment_intel_vpid_owner_validate' \
    'error = vmx_nested_vpid_owner_validate(&vcpu->nested_vpid_owner);' \
    'vcpu->nested_vpid_owner.vmcs01_vpid == vcpu->state.vpid ? 0 :' \
    'EPROTO);'; do
	rg -q -F "$contract" "$environment_intel_source" ||
	    fail "entry-environment VPID-owner contract omits: $contract"
done
if [ "$(rg -c -F \
    'error = nvmx_environment_intel_vpid_owner_validate(vcpu);' \
    "$environment_intel_source")" -ne 2 ]; then
	fail "entry-environment does not validate both VPID-owner consumers"
fi
for contract in \
    'state = vmx_nested_vpid_owner_validate(vpid_owner);' \
    'return (state);'; do
	rg -q -F "$contract" "$instruction_runtime_source" ||
	    fail "instruction-runtime VPID-owner contract omits: $contract"
done
rg -q 'NVMX-EVENT-123.*Typed production-owner composition' \
    "$ledger" || fail "typed production-owner requirement is missing"
rg -q 'NVMX-PRIVATE-184.*typed-production-owner-composition' \
    "$private_ledger" || fail "typed production-owner contract is missing"
# private-test: constructor-ept-cache-owner-admission
for contract in \
    'vmx_nested_ept_cache_header_validate(' \
    'complete provider table are present and' \
    'does not scan entries or require quiescence'; do
	rg -q -F "$contract" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_ept_cache.h" ||
	    fail "EPT cache constructor contract omits: $contract"
done
rg -q -U --pcre2 \
    'vmx_nested_instruction_runtime_init\([\s\S]*?state = vmx_nested_ept_cache_header_validate\(ept_cache\);[\s\S]*?if \(state != 0\)[\s\S]*?return \(state\);[\s\S]*?state = vmx_nested_vpid_owner_validate\(vpid_owner\);' \
    "$instruction_runtime_source" ||
    fail "instruction runtime admits an unvalidated EPT cache owner"
rg -q 'NVMX-EVENT-124.*Constructor EPT cache owner admission' \
    "$ledger" || fail "constructor EPT cache requirement is missing"
rg -q 'NVMX-PRIVATE-185.*constructor-header-owner-admission' \
    "$private_ledger" || fail "constructor EPT cache contract is missing"
# private-test: instruction-handoff-callback-snapshot
for contract in \
    'struct vmx_nested_instruction_handoff_ops ops_snapshot;' \
    'ops_snapshot = *ops;' \
    'ops = &ops_snapshot;' \
    'One instruction uses one immutable provider identity.'; do
	rg -q -F "$contract" "$instruction_handoff_source" ||
	    fail "instruction handoff callback snapshot omits: $contract"
done
for contract in \
    'fixture.mutable_ops = &ops;' \
    'fixture.corrupt_ops_after_linear_read = true;' \
    'fixture->mutable_ops->check_region = NULL;' \
    'ATF_CHECK_EQ(ops.check_region, NULL);'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "instruction handoff callback-mutation test omits: $contract"
done
for contract in \
    'handle() snapshots this table before the first callback' \
    'cannot redirect a later callback in the same instruction transaction'; do
	rg -q -F "$contract" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_instruction_handoff.h" ||
	    fail "instruction handoff callback contract omits: $contract"
done
rg -q 'NVMX-EVENT-125.*Callback-stable VMX instruction handoff' \
    "$ledger" || fail "instruction callback-stability requirement is missing"
rg -q 'NVMX-PRIVATE-186.*per-instruction-operation-snapshot' \
    "$private_ledger" || fail "instruction callback-stability contract is missing"
# private-test: ept-handoff-callback-snapshot
for contract in \
    'struct vmx_nested_ept_handoff_ops ops_snapshot;' \
    'struct vmx_nested_ept_memory memory_snapshot;' \
	'struct vmx_nested_ept_handoff expected;' \
	'struct vmx_nested_ept_handoff_request request_snapshot;' \
    'memory_snapshot = *memory;' \
    'ops_snapshot = *ops;' \
	'request_snapshot = handoff->request;' \
    'walk.memory = &memory_snapshot;' \
	'vmx_nested_ept_handoff_equal(handoff, &expected)' \
    'One frozen walk uses one immutable memory/provider identity.'; do
	rg -q -F "$contract" "$ept_handoff_source" ||
	    fail "EPT handoff callback snapshot omits: $contract"
done
for contract in \
    'tree.mutable_memory = &memory;' \
    'tree.mutable_ops = &ops;' \
    'tree.corrupt_provider_tables = true;' \
    'tree->mutable_memory->load = NULL;' \
    'tree->mutable_ops->populate = NULL;' \
    'ATF_CHECK_EQ(memory.load, NULL);' \
	'ATF_CHECK_EQ(ops.populate, NULL);' \
	'backend.corrupt_handoff = true;' \
	'backend->handoff->request.id.execution_epoch = UINT64_MAX;' \
	'&memory, &ops, &backend), EPROTO);' \
	'ATF_CHECK_EQ(handoff.request.id.execution_epoch,'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "EPT handoff callback-mutation test omits: $contract"
done
rg -q 'NVMX-EVENT-126.*Callback-stable frozen EPT handoff' \
    "$ledger" || fail "EPT callback-stability requirement is missing"
rg -q 'NVMX-PRIVATE-187.*per-walk-provider-snapshot' \
    "$private_ledger" || fail "EPT callback-stability contract is missing"
# private-test: l1-restore-callback-snapshot
for contract in \
    'struct vmx_nested_l1_restore_ops ops_snapshot;' \
    'struct vmx_nested_l1_exit_ops ops_snapshot;' \
    'ops_snapshot = *ops;' \
    'ops = &ops_snapshot;'; do
	rg -q -F "$contract" "$l1_restore_source" ||
	    fail "L1 restore callback snapshot omits: $contract"
done
for contract in \
    'fixture.mutable_ops = &ops;' \
    'fixture.corrupt_ops_after_begin = true;' \
    'fixture->mutable_ops->abort = NULL;' \
    'ATF_CHECK_EQ(ops.abort, NULL);'; do
	[ "$(rg -c -F "$contract" "$test_source")" -ge 2 ] ||
	    fail "L1 restore callback-mutation tests omit: $contract"
done
rg -q 'NVMX-EVENT-127.*Callback-stable L1 restoration' \
    "$ledger" || fail "L1 restore callback-stability requirement is missing"
rg -q 'NVMX-PRIVATE-188.*per-L1-restore-operation-snapshot' \
    "$private_ledger" || fail "L1 restore callback-stability contract is missing"
# private-test: staged-thaw-provider-identity
for contract in \
    'struct vmx_nested_l2_thaw_frozen_ops ops_snapshot;' \
    'ops->provider_id == 0' \
    'staged->frozen_provider_id = ops->provider_id;' \
    'ops->provider_id != staged->frozen_provider_id' \
    'return (ESTALE);'; do
	rg -q -F "$contract" "$l2_thaw_staged_source" ||
	    fail "staged thaw provider identity omits: $contract"
done
rg -q -F '.provider_id = UINT64_C(0x494e54454c000001),' "$vmx_source" ||
    fail "production staged-thaw provider has no stable private identity"
for contract in \
    'wrong_frozen_ops.provider_id++;' \
    '&wrong_frozen_ops, &fixture), ESTALE' \
    'ATF_CHECK_EQ(memcmp(&staged, &staged_before, sizeof(staged)), 0);'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "staged thaw wrong-provider test omits: $contract"
done
rg -q 'NVMX-EVENT-128.*Stable staged-thaw provider ownership' "$ledger" ||
    fail "staged thaw provider requirement is missing"
rg -q 'NVMX-PRIVATE-189.*staged-thaw-provider-identity' "$private_ledger" ||
    fail "staged thaw provider private contract is missing"
# private-test: freeze-thaw-operation-snapshots
for source in "$l2_thaw_source" "$l2_freeze_source"; do
	rg -q -F 'ops_snapshot = *ops;' "$source" ||
	    fail "freeze/thaw transaction does not snapshot its operation table: $source"
	rg -q -F 'ops = &ops_snapshot;' "$source" ||
	    fail "freeze/thaw transaction does not use its operation snapshot: $source"
done
for contract in \
    'fixture->ops->detach = NULL;' \
    'fixture->ops->rollback_hot = NULL;' \
    'fixture->ops->acquire_resources = NULL;' \
    'fixture->ops->rollback_cold = NULL;' \
    'A callback cannot redirect the remainder of the transaction.'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "freeze/thaw callback-mutation tests omit: $contract"
done
rg -q 'NVMX-EVENT-129.*Callback-stable monolithic freeze and thaw' "$ledger" ||
    fail "freeze/thaw callback-stability requirement is missing"
rg -q 'NVMX-PRIVATE-190.*freeze-thaw-operation-snapshots' "$private_ledger" ||
    fail "freeze/thaw operation-snapshot private contract is missing"
# private-test: second-kernel-callback-identity-replay
for pair in \
    "$exit_capture_source:struct vmx_nested_exit_capture_ops ops_snapshot;" \
    "$apic_priority_source:struct vmx_nested_memory memory_snapshot;" \
    "$hot_exit_source:struct vmx_nested_l0_continuation_ops ops_snapshot;" \
    "$vmcs02_apply_source:struct vmx_nested_vmcs02_program_apply_ops ops_snapshot;"; do
	source=${pair%%:*}
	contract=${pair#*:}
	rg -q -F "$contract" "$source" ||
	    fail "second kernel callback replay omits: $contract"
	rg -q -F 'ops_snapshot = *ops;' "$source" 2>/dev/null ||
	    rg -q -F 'memory_snapshot = *memory;' "$source" ||
	    fail "second kernel callback replay does not capture provider: $source"
done
for contract in \
    'mock.mutate_ops = true;' \
    'mock->ops->write = NULL;' \
    'fixture->ops->resolve = NULL;' \
    'fixture->memory->write = NULL;' \
    'fixture->ops->read = NULL;'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "second kernel callback-mutation tests omit: $contract"
done
rg -q 'NVMX-EVENT-130.*Second kernel callback identity replay' "$ledger" ||
    fail "second kernel callback-identity requirement is missing"
rg -q 'NVMX-PRIVATE-191.*second-kernel-callback-identity-replay' \
    "$private_ledger" ||
    fail "second kernel callback-identity private contract is missing"
# private-test: staged-refreeze-provider-identity
for contract in \
    'struct vmx_nested_refreeze_hot_ops ops_snapshot;' \
    'struct vmx_nested_refreeze_frozen_ops ops_snapshot;' \
    'ops_snapshot = *ops;' \
    'staged->provider_id = ops->provider_id;' \
    'ops->provider_id != staged->provider_id' \
    'staged->resource_generation == 0 || staged->provider_id == 0'; do
	rg -q -F "$contract" "$refreeze_source" ||
	    fail "staged refreeze provider identity omits: $contract"
done
for contract in \
    'fixture.mutable_hot_ops = &hot_ops;' \
    'fixture.mutate_provider_table = true;' \
    'fixture->mutable_hot_ops->provider_id++;' \
    'ATF_CHECK_EQ(staged.provider_id, 1);' \
    'wrong_frozen_ops.provider_id++;'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "staged refreeze provider test omits: $contract"
done
rg -q 'NVMX-EVENT-131.*Stable staged-refreeze provider ownership' "$ledger" ||
    fail "staged refreeze provider requirement is missing"
rg -q 'NVMX-PRIVATE-192.*staged-refreeze-provider-identity' \
    "$private_ledger" || fail "staged refreeze private contract is missing"
# private-test: msr-provider-snapshots
for contract in \
    'struct vmx_nested_memory memory_snapshot;' \
    'struct vmx_nested_msr_policy policy_snapshot;' \
    'struct vmx_nested_msr_apply_ops ops_snapshot;' \
    'struct vmx_nested_exit_msr_store_ops ops_snapshot;' \
    'memory_snapshot = *memory;' \
    'policy_snapshot = *policy;' \
    'ops_snapshot = *ops;'; do
	rg -q -F "$contract" "$msr_source" ||
	    fail "MSR provider snapshots omit: $contract"
done
for contract in \
    'backend.mutable_memory = &memory;' \
    'backend.mutable_policy = &policy;' \
    'runtime.mutable_apply_ops = &apply_ops;' \
    'runtime.mutable_store_ops = &store_ops;' \
    'memory->mutable_memory->read = NULL;' \
    'runtime->mutable_apply_ops->write = NULL;' \
    'runtime->mutable_store_ops->read = NULL;'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "MSR provider mutation tests omit: $contract"
done
rg -q 'NVMX-EVENT-132.*Callback-stable nested MSR transactions' "$ledger" ||
    fail "MSR callback-stability requirement is missing"
rg -q 'NVMX-PRIVATE-193.*captured-memory-policy-and-runtime-providers' \
    "$private_ledger" || fail "MSR provider private contract is missing"
# private-test: compound-private-provider-snapshots
for pair in \
    "$vpid_owner_source:struct vmx_nested_vpid_owner_ops ops_snapshot;" \
    "$startup_transaction_source:struct vmx_nested_startup_transaction_ops ops_snapshot;"; do
	source=${pair%%:*}
	contract=${pair#*:}
	rg -q -F "$contract" "$source" ||
	    fail "compound private provider snapshot omits: $contract"
	rg -q -F 'ops_snapshot = *ops;' "$source" ||
	    fail "compound private provider is not captured: $source"
done
for contract in \
	'nvmx_startup_ops_equal(' \
	'error = ops_snapshot.prepare_l0(' \
	'nvmx_startup_side_effect(transaction, &ops_snapshot, arg,' \
	'!nvmx_startup_ops_equal(ops, &ops_snapshot)' \
    'sizeof(*ops)) || ops->claim_finish == NULL)'; do
	rg -q -F "$contract" "$startup_transaction_source" ||
	    fail "startup prepare/apply callback snapshot omits: $contract"
done
for contract in \
    'backend.mutable_ops = &ops;' \
    'backend->mutable_ops->release = NULL;' \
    'context.mutable_ops = &ops;' \
    'context->mutable_ops->claim_finish = NULL;' \
    'context.mutate_prepare_provider_table = true;' \
    'context->mutable_ops->apply_l0 = NULL;' \
    'context.mutate_finish_provider_table = true;' \
    'context->mutable_ops->claim_finish = NULL;' \
    'incomplete_ops.claim_finish = NULL;' \
    'ATF_CHECK_EQ(context.prepare_calls, 0);'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "compound private provider mutation tests omit: $contract"
done
rg -q 'NVMX-EVENT-133.*Callback-stable compound private ownership' "$ledger" ||
    fail "compound private provider requirement is missing"
rg -q 'NVMX-PRIVATE-194.*compound-private-provider-snapshots' \
    "$private_ledger" || fail "compound private provider contract is missing"
rg -q 'NVMX-EVENT-136.*Immutable startup preparation provider' "$ledger" ||
    fail "startup preparation provider requirement is missing"
rg -q 'NVMX-PRIVATE-198.*startup-preparation-provider-snapshot' \
    "$private_ledger" || fail "startup preparation provider contract is missing"
# private-test: typed-startup-apply-boundary
for contract in \
    'enum vmx_nested_startup_machine_disposition' \
    '(*apply_l0)(void *, enum vmx_nested_startup_kind, uint8_t,' \
    'error = -1;' \
    'VMX_NESTED_STARTUP_MACHINE_COMMITTED &&' \
    'VMX_NESTED_STARTUP_MACHINE_RETRY &&' \
    '*poisoned = true;' \
    'if (side_poisoned)' \
    'VMX_NESTED_STARTUP_TRANSACTION_POISONED'; do
	rg -q -F "$contract" "$startup_transaction_source" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_startup_transaction.h" ||
	    fail "typed startup apply boundary omits: $contract"
done
for contract in \
    'override_apply_disposition' \
    'VMX_NESTED_STARTUP_MACHINE_FAIL_STOP, 0' \
    'VMX_NESTED_STARTUP_MACHINE_COMMITTED, EIO' \
    'VMX_NESTED_STARTUP_MACHINE_RETRY, 0' \
    'VMX_NESTED_STARTUP_MACHINE_RETRY, -1' \
    'vmx_nested_startup_machine_disposition)99' \
    'VMX_NESTED_STARTUP_TRANSACTION_POISONED'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "typed startup apply negative coverage omits: $contract"
done
rg -q 'NVMX-EVENT-140.*Typed Intel startup apply boundary' "$ledger" ||
    fail "typed startup apply requirement is missing"
rg -q 'NVMX-PRIVATE-202.*typed-startup-apply-boundary' \
    "$private_ledger" || fail "typed startup apply private contract is missing"
# private-test: negative-provider-status-fail-stop
for source in "$startup_transaction_source" "$startup_dispatch_source"; do
	rg -q -F 'if (error < 0)' "$source" ||
	    fail "negative provider status is not fail-stopped: $source"
	rg -q -F 'VMX_NESTED_STARTUP_TRANSACTION_POISONED' \
	    "$startup_transaction_source" ||
	    fail "negative startup status cannot poison the transaction"
	rg -q -F 'VMX_NESTED_STARTUP_DISPATCH_POISONED' \
	    "$startup_dispatch_source" ||
	    fail "negative dispatch status cannot poison the dispatch"
done
for contract in \
    'context.prepare_error = -1;' \
    'context.side_error = -1;' \
    'context.release_error = -1;' \
    'context.begin_error = -1;' \
    'context.derive_error = -1;' \
    'context.abort_error = -1;'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "negative provider fail-stop coverage omits: $contract"
done
rg -q 'NVMX-EVENT-141.*Negative private callback status fail-stop' \
    "$ledger" || fail "negative callback fail-stop requirement is missing"
rg -q 'NVMX-PRIVATE-203.*negative-provider-status-fail-stop' \
    "$private_ledger" || fail "negative callback private contract is missing"
# private-test: typed-machine-startup-dispatch
startup_mode_header="$src/sys/dev/vmm/vmm_startup_mode.h"
startup_mode_source="$src/sys/dev/vmm/vmm_startup_mode.c"
machine_vmm_header="$src/sys/amd64/include/vmm.h"
common_vmm_source="$src/sys/amd64/vmm/vmm.c"
vmmdev_source="$src/sys/dev/vmm/vmm_dev.c"
svm_source="$src/sys/amd64/vmm/amd/svm.c"
startup_mode_test="$src/tests/sys/vmm/vmm_startup_mode_test.c"
for contract in \
    'enum vmm_startup_dispatch_result' \
    'VMM_STARTUP_DISPATCH_IDLE' \
    'VMM_STARTUP_DISPATCH_RETAINED' \
    'VMM_STARTUP_DISPATCH_CONSUMED' \
    'struct vmm_startup_dispatch_plan'; do
	rg -q -F "$contract" "$startup_mode_header" ||
	    fail "common startup dispatch result omits: $contract"
done
for contract in \
    'result == VMM_STARTUP_DISPATCH_CONSUMED' \
    'candidate.replay_lifecycle = 1;' \
    'candidate.enter_guest = 1;'; do
	rg -q -F "$contract" "$startup_mode_source" ||
	    fail "startup dispatch run policy omits: $contract"
done
for contract in \
    'DECLARE_VMMOPS_FUNC(bool, startup_kernel_actions_ready, (void));' \
    'DECLARE_VMMOPS_FUNC(int, vcpu_startup_event_step, (void *vcpui,'; do
	rg -q -F "$contract" "$machine_vmm_header" ||
	    fail "machine startup dispatch declaration omits: $contract"
done
for contract in \
    'DEFINE_VMMOPS_IFUNC(bool, startup_kernel_actions_ready, (void))' \
    'DEFINE_VMMOPS_IFUNC(int, vcpu_startup_event_step, (void *vcpui,'; do
	rg -q -F "$contract" "$common_vmm_source" ||
	    fail "machine startup dispatch selector omits: $contract"
done
rg -q -F 'return (vmmops_startup_kernel_actions_ready());' \
    "$vmmdev_source" || fail "management readiness is not machine-owned"
rg -q -U --pcre2 \
    'static bool\s+vm_startup_kernel_actions_ready\(void\)[\s\S]*?#ifdef __amd64__[\s\S]*?return \(vmmops_startup_kernel_actions_ready\(\)\);[\s\S]*?#else[\s\S]*?return \(false\);[\s\S]*?#endif[\s\S]*?vm_startup_configure_kernel\(struct vm \*vm,[\s\S]*?if \(!vm_startup_kernel_actions_ready\(\)\)[\s\S]*?return \(EOPNOTSUPP\);[\s\S]*?vmm_event_coordinator_startup_configure_kernel\(' \
    "$vmm_vm_source" ||
    fail "direct VM startup configuration does not fail closed off amd64"
rg -q -U --pcre2 \
    'vmx_startup_kernel_actions_ready\(void\)[\s\S]*?return \(true\);' \
    "$vmx_source" || fail "qualified VMX startup readiness is not enabled"
rg -q -U --pcre2 \
    'svm_startup_kernel_actions_ready\(void\)[\s\S]*?return \(false\);' \
    "$svm_source" || fail "unconverted SVM startup readiness is not fail closed"
rg -q 'NVMX-EVENT-183.*Readiness is explicit and backend-specific' "$ledger" ||
	fail "backend-specific readiness requirement is missing"
# private-test: backend-specific-readiness-policy
# private-test: nested-owner-refusal-probe
rg -q 'NVMX-PRIVATE-261.*backend-specific-readiness-after-atomic-source-order-conversion' \
    "$private_ledger" || fail "fail-closed readiness private contract is missing"
# The nested bridge is compiled but not yet publicly exposed.  Check the
# source-ordered contract directly: lifecycle-only no-entry exits settle
# immediately, while every physical attempt reaches the shared attempted-entry
# guard through the Intel-private helper after its inverse is available.
rg -q -F 'vmx_nested_owner_guard_attempt' "$vmx_source" ||
    fail "nested VMX owner bridge helper is missing"
rg -q -F 'vmx_nested_owner_outcome.h' "$vmx_source" ||
    fail "nested VMX owner bridge omits its outcome contract"
rg -q -F 'vmx_nested_owner_outcome.c' "$src/sys/modules/vmm/Makefile" ||
    fail "nested VMX owner bridge is not linked into vmm.ko"
rg -q -U --pcre2 \
	'suspended = vcpu_suspended\(evinfo\);[\s\S]*?if \(suspended \|\| rendezvous \|\| reqidle \|\| yield \|\| debugged \|\| pvclock\)[\s\S]*?vmm_startup_entry_owner_software_exit\(entry_owner,[\s\S]*?return \(0\);[\s\S]*?vmx_msr_guest_enter\(vcpu\);' \
    "$vmx_source" ||
    fail "nested VMX lifecycle owner path no longer precedes private residency"
# private-test: attempted-entry-owner-model
for contract in \
    'VMM_STARTUP_ENTRY_OWNER_ENTRY_PENDING' \
	'vcpu_startup_entry_owner_guard_before_attempt' \
    'vmm_startup_entry_owner_guard_before_attempt' \
    'vmm_startup_entry_owner_commit_attempt' \
    'vmm_startup_entry_owner_abort_attempt' \
	'vmm_startup_entry_owner_abort_attempt_error' \
	'vmm_startup_entry_loop_fail_checked' \
    'vmm_startup_entry_loop_software_exit_checked'; do
	rg -q -F "$contract" "$startup_entry_owner_source" \
	    "$startup_entry_owner_header" "$startup_mode_source" \
	    "$startup_mode_header" "$vmm_vm_source" "$vmm_vm_header" ||
	    fail "attempted-entry owner model omits: $contract"
done
rg -q 'NVMX-EVENT-184.*Hardware-attempt pending state' "$ledger" ||
    fail "attempted-entry requirement is missing"
rg -q 'NVMX-PRIVATE-262.*attempted-hardware-entry-owner' "$private_ledger" ||
    fail "attempted-entry private contract is missing"
# private-test: attempted-entry-terminal-error-model
rg -q 'NVMX-EVENT-185.*Conclusive no-entry terminal errors' "$ledger" ||
	fail "attempted-entry terminal-error requirement is missing"
rg -q 'NVMX-PRIVATE-263.*attempted-hardware-entry-terminal-error' \
	"$private_ledger" ||
	fail "attempted-entry terminal-error private contract is missing"
rg -q -U --pcre2 \
	'vmm_startup_entry_owner_abort_attempt_error\(&owner, EAGAIN,[\s\S]*?EINVAL[\s\S]*?vmm_startup_entry_owner_abort_attempt_error\(&owner, EIO,[\s\S]*?RETURN_ERROR[\s\S]*?entry_count, 1[\s\S]*?check_count, 1' \
	"$startup_entry_owner_test_source" ||
	fail "attempted-entry terminal-error model lacks initial and re-entry coverage"
rg -q -F 'entry_owner_hardware_attempt_is_not_guest_entry' \
    "$startup_entry_owner_test_source" ||
    fail "attempted-entry owner model test is missing"
# private-test: classified-hardware-attempt-owner-model
for contract in \
	'vmx_nested_owner_attempt_outcome_compose' \
	'VMX_NESTED_OWNER_ATTEMPT_COMMIT_ENTRY' \
	'VMX_NESTED_OWNER_ATTEMPT_ABORT_SOFTWARE' \
	'VMX_NESTED_OWNER_ATTEMPT_ABORT_ERROR' \
	'nested_owner_attempt_outcome_composition'; do
	rg -q -F "$contract" "$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.h" \
	    "$src/tests/sys/vmm/vmx_nested_state_test.c" ||
		fail "classified hardware-attempt owner model omits: $contract"
done
rg -q 'NVMX-EVENT-186.*Classified VMX hardware attempt' "$ledger" ||
	fail "classified hardware-attempt owner requirement is missing"
rg -q 'NVMX-PRIVATE-264.*classified-attempt-owner-settlement' \
	"$private_ledger" ||
	fail "classified hardware-attempt owner private contract is missing"
rg -q -U --pcre2 \
	'VMX_NESTED_ATTEMPT_INITIAL_EXIT[\s\S]*?COMMIT_ENTRY[\s\S]*?INITIAL_REJECTION[\s\S]*?ABORT_SOFTWARE[\s\S]*?INITIAL_L0_FAILURE[\s\S]*?ABORT_ERROR' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "classified hardware-attempt model lacks all settlement domains"
rg -q -U --pcre2 \
	'nvmxoo_unwind_matches_unentered_attempt[\s\S]*?INITIAL_REJECTION[\s\S]*?INITIAL_L0_FAILURE[\s\S]*?ROLLBACK_INITIAL[\s\S]*?RESUMED_FAILED_ENTRY[\s\S]*?RESUMED_L0_FAILURE[\s\S]*?REFREEZE_UNENTERED' \
	"$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" ||
	fail "classified hardware-attempt model does not bind rollback to attempt provenance"
rg -q -U --pcre2 \
	'RESUMED_FAILED_ENTRY[\s\S]*?ROLLBACK_INITIAL[\s\S]*?EINV[\s\S]*?INITIAL_REJECTION[\s\S]*?REFREEZE_UNENTERED[\s\S]*?EINV' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "classified hardware-attempt model lacks wrong-residency rejection coverage"
rg -q -U --pcre2 \
	'VMX_NESTED_ATTEMPT_RESUMED_L0_FAILURE[\s\S]*?REFREEZE_UNENTERED[\s\S]*?ROLLBACK_INITIAL[\s\S]*?EINV[\s\S]*?VMX_NESTED_ATTEMPT_INITIAL_L0_FAILURE[\s\S]*?REFREEZE_UNENTERED[\s\S]*?EINV' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "immutable attempt-plan bridge lacks wrong-residency rejection coverage"
# private-test: private-attempt-settlement-adapter
for contract in \
	'vmx_nested_owner_attempt_outcome_settle' \
	'VMX_NESTED_OWNER_ATTEMPT_COMMIT_ENTRY' \
	'VMX_NESTED_OWNER_ATTEMPT_ABORT_SOFTWARE' \
	'VMX_NESTED_OWNER_ATTEMPT_ABORT_ERROR'; do
	rg -q -F "$contract" "$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.h" \
	    "$src/tests/sys/vmm/vmx_nested_state_test.c" ||
		fail "private attempt settlement adapter omits: $contract"
done
rg -q 'NVMX-EVENT-187.*Private classified-attempt adapter' "$ledger" ||
	fail "private attempt settlement adapter requirement is missing"
rg -q 'NVMX-EVENT-188.*Private immutable classifications' "$ledger" ||
	fail "private immutable-classification alias requirement is missing"
rg -q 'NVMX-PRIVATE-265.*private-attempt-settlement-adapter' \
	"$private_ledger" ||
	fail "private attempt settlement adapter contract is missing"
rg -q 'NVMX-PRIVATE-266.*private-input-output-alias-boundary' \
	"$private_ledger" ||
	fail "private immutable-classification alias contract is missing"
rg -q -U --pcre2 \
	'VMX_NESTED_OWNER_ATTEMPT_COMMIT_ENTRY[\s\S]*?vmx_nested_owner_attempt_outcome_settle\(&owner, &outcome,[\s\S]*?&result\)[\s\S]*?EINVAL[\s\S]*?owner\.phase, VMM_STARTUP_ENTRY_OWNER_ENTRY_PENDING' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "private attempt settlement adapter lacks commit-input atomicity"
rg -q -U --pcre2 \
	'VMX_NESTED_ATTEMPT_INITIAL_REJECTION[\s\S]*?vmx_nested_owner_attempt_outcome_settle\(&owner, &outcome,[\s\S]*?NULL\)[\s\S]*?EINVAL[\s\S]*?owner\.phase, VMM_STARTUP_ENTRY_OWNER_ENTRY_PENDING' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "private attempt settlement adapter lacks invalid-input atomicity"
rg -q -F 'outcome_result_alias' "$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "private attempt settlement adapter lacks immutable-outcome alias coverage"
rg -q -F 'vmx_nested_state_ranges_overlap(outcome, sizeof(*outcome), result,' \
	"$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" ||
	fail "private attempt settlement adapter permits outcome/result overlap"
rg -q -F 'vmx_nested_state_ranges_overlap(owner, sizeof(*owner), result,' \
	"$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" ||
	fail "private attempt settlement adapter permits owner/result overlap"
rg -q -F '(struct vmm_startup_entry_loop_result *)(void *)&owner' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "private attempt settlement adapter lacks owner/result alias coverage"
# The adapter is production code now.  Check both the runtime call sites and
# the module link; the model runner also validates that the built object
# exposes the production symbols rather than silently dropping the adapter.
rg -q -F 'vmx_nested_owner_attempt_outcome_settle(owner, &outcome,' "$vmx_source" ||
	fail "private attempt settlement adapter is not reached from the VMX runtime"
rg -q -F 'vmx_nested_owner_outcome.c' "$src/sys/modules/vmm/Makefile" ||
	fail "private owner-outcome adapter is not linked into vmm.ko"
rg -q -F 'checking production owner-adapter symbols in vmm.ko' "$model_runner" ||
	fail "nested model runner lacks the built-vmm.ko owner-adapter linkage gate"
rg -q -U --pcre2 \
	'make -C "\$src/sys/modules/vmm"(?: -j"\$jobs")? vmm\.ko' \
	"$model_runner" ||
	fail "nested model runner does not build vmm.ko for owner-model linkage validation"
rg -q -F 'nm -a "$module_ko"' "$model_runner" ||
	fail "nested model runner does not inspect vmm.ko symbols"
rg -q -F 'vmx_nested_owner_(attempt_outcome|initial_attempt_outcome|resumed_attempt_outcome|postentry_transition)' "$model_runner" ||
	fail "nested model runner linkage gate has no owner-model symbol set"
# private-test: initial-hardware-completion-provenance
for contract in \
	'vmx_nested_owner_initial_attempt_outcome_compose' \
	'VMX_NESTED_HARDWARE_ENTRY_FINISH_UNENTERED_ROLLED_BACK' \
	'VMX_NESTED_HARDWARE_ENTRY_FINISH_NONE'; do
	rg -q -F "$contract" "$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.h" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_hardware_entry.c" \
	    "$src/tests/sys/vmm/vmx_nested_state_test.c" ||
		fail "initial hardware completion provenance omits: $contract"
done
rg -q 'NVMX-EVENT-193.*Initial hardware completion retains inverse provenance' \
	"$ledger" || fail "initial hardware completion requirement is missing"
rg -q 'NVMX-PRIVATE-273.*initial-hardware-completion-provenance' \
	"$private_ledger" ||
	fail "initial hardware completion private contract is missing"
rg -q -U --pcre2 \
	'INITIAL_REJECTION[\s\S]*?UNENTERED_ROLLED_BACK[\s\S]*?UNWIND_CLEAN[\s\S]*?ABORT_SOFTWARE[\s\S]*?INITIAL_EXIT[\s\S]*?FINISH_NONE[\s\S]*?EINVAL' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "initial hardware completion model lacks completed-and-incomplete coverage"
rg -q -U --pcre2 \
	'vmx_nested_finish_initial_hardware_attempt[\s\S]*?completion == NULL[\s\S]*?\*completion = VMX_NESTED_HARDWARE_ENTRY_FINISH_NONE[\s\S]*?vmx_nested_hardware_entry_finish[\s\S]*?completion, rejection[\s\S]*?INITIAL_EXIT[\s\S]*?\*completion != VMX_NESTED_HARDWARE_ENTRY_FINISH_ENTERED[\s\S]*?INITIAL_REJECTION[\s\S]*?\*completion !=[\s\S]*?UNENTERED_ROLLED_BACK' \
	"$vmx_source" ||
	fail "initial hardware attempt does not reset, preserve, and validate completion"
rg -q -U --pcre2 \
	'vmx_nested_finish_initial_hardware_attempt\(vcpu,[\s\S]*?&initial_completion\)[\s\S]*?INITIAL_EXIT[\s\S]*?initial_completion !=[\s\S]*?FINISH_ENTERED[\s\S]*?INITIAL_REJECTION[\s\S]*?initial_completion !=[\s\S]*?UNENTERED_ROLLED_BACK' \
	"$vmx_source" ||
	fail "nested run does not validate initial hardware completion before use"
rg -q -U --pcre2 \
	'nested_owner_full_transaction_flow[\s\S]*?INITIAL_EXIT[\s\S]*?HARDWARE_ENTRY_FINISH_ENTERED[\s\S]*?vmx_nested_owner_initial_attempt_outcome_compose' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "full owner transaction lacks initial entered-completion coverage"
rg -q -U --pcre2 \
	'INITIAL_REJECTION[\s\S]*?UNENTERED_ROLLED_BACK[\s\S]*?ABORT_SOFTWARE[\s\S]*?INITIAL_L0_FAILURE[\s\S]*?failure_error = EIO[\s\S]*?RETURN_ERROR' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "full owner transaction lacks initial rollback and terminal coverage"
# private-test: resumed-hardware-completion-provenance
for contract in \
	'vmx_nested_finish_resumed_hardware_attempt' \
	'vmx_nested_owner_resumed_attempt_outcome_compose' \
	'VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_UNENTERED_REFROZEN' \
	'VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_NONE'; do
	rg -q -F "$contract" "$vmx_source" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.h" \
	    "$src/tests/sys/vmm/vmx_nested_state_test.c" ||
		fail "resumed hardware completion provenance omits: $contract"
done
rg -q 'NVMX-EVENT-194.*Resumed hardware completion retains refreeze provenance' \
	"$ledger" || fail "resumed hardware completion requirement is missing"
rg -q 'NVMX-EVENT-194.*nested_owner_full_transaction_flow' "$ledger" ||
	fail "resumed hardware completion requirement omits full transaction coverage"
rg -q 'NVMX-PRIVATE-274.*resumed-hardware-completion-provenance' \
	"$private_ledger" ||
	fail "resumed hardware completion private contract is missing"
rg -q 'NVMX-PRIVATE-274.*nested_owner_full_transaction_flow' \
	"$private_ledger" ||
	fail "resumed hardware completion private contract omits full transaction coverage"
rg -q -U --pcre2 \
	'RESUMED_FAILED_ENTRY[\s\S]*?UNENTERED_REFROZEN[\s\S]*?ABORT_SOFTWARE[\s\S]*?RESUMED_L0_FAILURE[\s\S]*?ABORT_ERROR[\s\S]*?RESUMED_EXIT[\s\S]*?ATTEMPT_NONE[\s\S]*?EINVAL' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "resumed hardware completion model lacks completed-and-incomplete coverage"
rg -q -U --pcre2 \
	'RESUMED_FAILED_ENTRY[\s\S]*?UNENTERED_REFROZEN[\s\S]*?failure_error = EIO[\s\S]*?EINVAL[\s\S]*?RESUMED_L0_FAILURE[\s\S]*?failure_error = 0[\s\S]*?EINVAL' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "resumed hardware completion model lacks error-domain negative coverage"
rg -q -U --pcre2 \
	'nested_owner_full_transaction_flow[\s\S]*?RESUMED_EXIT[\s\S]*?ATTEMPT_ENTERED[\s\S]*?vmx_nested_owner_resumed_attempt_outcome_compose[\s\S]*?guard_after' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "full owner transaction lacks resumed entered-completion and recheck coverage"
rg -q -U --pcre2 \
	'RESUMED_FAILED_ENTRY[\s\S]*?UNENTERED_REFROZEN[\s\S]*?ABORT_SOFTWARE[\s\S]*?RESUMED_L0_FAILURE[\s\S]*?failure_error = EIO[\s\S]*?RETURN_ERROR' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "full owner transaction lacks resumed refreeze and terminal coverage"
# private-test: postentry-route-transition
# EPT walking, direct reflection, and an unhandled L0 result all return an
# L2-visible result only after different private publication paths.  They must
# share DEFERRED common-owner state, whereas a locally handled result must
# recheck before another attempted VM entry.
for contract in \
	'vmx_nested_owner_postentry_transition' \
	'VMX_NESTED_OWNER_POSTENTRY_DEFER_EPT_WALK' \
	'VMX_NESTED_OWNER_POSTENTRY_DEFER_REFLECTION' \
	'VMX_NESTED_OWNER_POSTENTRY_DEFER_UNHANDLED' \
	'VMX_NESTED_OWNER_POSTENTRY_RECHECK'; do
	rg -q -F "$contract" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.h" \
	    "$src/tests/sys/vmm/vmx_nested_state_test.c" ||
		fail "post-entry route transition omits: $contract"
done
rg -q 'NVMX-PRIVATE-275.*postentry-route-transition' "$private_ledger" ||
	fail "post-entry route transition private contract is missing"
rg -q 'NVMX-EVENT-195.*Post-entry route preserves private-publication ordering' \
	"$ledger" || fail "post-entry route transition requirement is missing"
rg -q 'NVMX-EVENT-195.*terminal private unwind must override' "$ledger" ||
	fail "post-entry terminal-unwind rule is missing from the requirements ledger"
rg -q 'NVMX-EVENT-195.*preserved private outcome must equal the deferred common error' \
	"$ledger" || fail "post-entry deferred-error binding is missing from the requirements ledger"
rg -q -U --pcre2 \
	'vmx_nested_owner_postentry_transition\([\s\S]*?route, int backend_error\)[\s\S]*?backend_error < 0[\s\S]*?POSTENTRY_RECHECK &&[\s\S]*?backend_error != 0[\s\S]*?guard_after_defer\(owner,[\s\S]*?backend_error\)' \
	"$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" ||
	fail "post-entry route transition does not preserve its classified result domain"
rg -q -U --pcre2 \
	'nested_owner_full_transaction_flow[\s\S]*?POSTENTRY_RECHECK[\s\S]*?DEFER_UNHANDLED[\s\S]*?DEFER_EPT_WALK[\s\S]*?DEFER_REFLECTION[\s\S]*?ROUTE_LAST[\s\S]*?EINVAL' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "post-entry route transition model lacks complete route coverage"
rg -q -U --pcre2 \
	'nested_owner_postentry_route_matrix[\s\S]*?DEFER_EPT_WALK[\s\S]*?DEFER_REFLECTION[\s\S]*?DEFER_UNHANDLED[\s\S]*?results\[\][\s\S]*?0, EAGAIN, EBUSY[\s\S]*?LOOP_RETURN_VMEXIT[\s\S]*?LOOP_REPLAY[\s\S]*?LOOP_RETURN_ERROR' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "post-entry route matrix lacks every deferred route/result outcome"
rg -q -U --pcre2 \
	'route-specific inverse failure[\s\S]*?for \(route_index = 0; route_index < nitems\(routes\); route_index\+\+\)[\s\S]*?routes\[route_index\], 0\)[\s\S]*?UNWIND_DETACH_FATAL[\s\S]*?exit_error = 0[\s\S]*?unwind_error = EIO[\s\S]*?LOOP_RETURN_ERROR[\s\S]*?result\.error, EIO' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "post-entry route matrix lacks all-route terminal-unwind coverage"
rg -q 'NVMX-EVENT-195.*nested_owner_postentry_route_matrix' "$ledger" ||
	fail "post-entry route requirement omits matrix-test evidence"
rg -q -U --pcre2 \
	'The same two deferred routes[\s\S]*?DEFER_EPT_WALK[\s\S]*?DEFER_REFLECTION[\s\S]*?UNWIND_DETACH_FATAL[\s\S]*?unwind_error = EIO[\s\S]*?RETURN_ERROR[\s\S]*?result\.error, EIO' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "EPT-walk/reflection terminal unwind coverage is missing"
rg -q -U --pcre2 \
	'guard_after_defer\(&owner, EAGAIN\)[\s\S]*?exit_input\.unwind_action = VMX_NESTED_RUN_UNWIND_FREEZE_HOT[\s\S]*?resolve_postentry\(&owner,[\s\S]*?EPROTO[\s\S]*?exit_input\.exit_error = EAGAIN[\s\S]*?LOOP_REPLAY' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "post-entry deferred-error binding coverage is missing"
rg -q -U --pcre2 \
	'vmx_nested_owner_postentry_transition\(NULL,[\s\S]*?POSTENTRY_RECHECK, 0\), EINVAL' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "post-entry route transition lacks null-owner coverage"
rg -q -U --pcre2 \
	'POSTENTRY_DEFER_UNHANDLED, EAGAIN\)[\s\S]*?exit_input\.exit_error = EAGAIN[\s\S]*?LOOP_REPLAY[\s\S]*?POSTENTRY_DEFER_REFLECTION, EBUSY\)[\s\S]*?exit_input\.exit_error = EBUSY[\s\S]*?RETURN_ERROR[\s\S]*?result\.error, EBUSY[\s\S]*?POSTENTRY_RECHECK, EAGAIN\), EINVAL' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "post-entry route transition does not preserve its classified result"
# The route adapter is called only after the corresponding private
# publication/freeze, which is checked again below against all L2 exit paths.
rg -q -F 'vmx_nested_owner_postentry_transition(owner, route,' "$vmx_source" ||
	fail "post-entry route transition is not reached through the VMX adapter"
# private-test: private-owner-outcome-canonicalization
# The private structures are not a native-layout contract, but each successful
# composer must still overwrite a complete candidate.  This prevents padding
# or later private fields from inheriting caller bytes before an explicit
# adapter consumes the value.
for composer in \
	'vmx_nested_owner_attempt_outcome_compose' \
	'vmx_nested_owner_initial_attempt_outcome_compose' \
	'vmx_nested_owner_resumed_attempt_outcome_compose'; do
	rg -q -U --pcre2 "${composer}[\\s\\S]*?bzero\\(&candidate, sizeof\\(candidate\\)\\);" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" ||
		fail "private owner outcome composer lacks canonical candidate initialization: $composer"
done
rg -q 'NVMX-EVENT-197.*Private owner outcomes have canonical value representation' \
	"$ledger" || fail "private owner outcome canonicalization requirement is missing"
rg -q 'NVMX-PRIVATE-276.*private-owner-outcome-canonicalization' \
	"$private_ledger" ||
	fail "private owner outcome canonicalization contract is missing"
rg -q -U --pcre2 \
	'canonical_commit_outcome[\s\S]*?memset\(&outcome, 0xa5[\s\S]*?canonical_software_outcome[\s\S]*?memset\(&outcome, 0x3c' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "private owner outcome canonicalization lacks independent caller-byte coverage"
# postentry-outcome-rejects-noentry-inverses
rg -q 'NVMX-EVENT-196.*Post-entry outcomes reject no-entry inverses' \
	"$ledger" || fail "post-entry no-entry-inverse requirement is missing"
rg -q -U --pcre2 \
	'vmx_nested_owner_exit_outcome_compose[\s\S]*?UNWIND_CLEAN[\s\S]*?UNWIND_FREEZE_HOT[\s\S]*?UNWIND_ROLLBACK_INITIAL[\s\S]*?return \(EINVAL\);[\s\S]*?UNWIND_REFREEZE_UNENTERED[\s\S]*?return \(EINVAL\);' \
	"$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" ||
	fail "post-entry outcome accepts a no-entry inverse"
rg -q -U --pcre2 \
	'No-entry inverses cannot manufacture a post-entry VM exit[\s\S]*?UNWIND_ROLLBACK_INITIAL[\s\S]*?UNWIND_REFREEZE_UNENTERED[\s\S]*?EINVAL' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "post-entry no-entry-inverse rejection lacks independent coverage"
# private-test: hardware-attempt-classification-publication-order
# A failed residency transition still needs the immutable hardware report
# classification.  Keep both adapters publishing that value before their
# respective state transition; a later common-owner conversion then combines
# it with the inverse action actually selected after failure rather than
# guessing from cleaned-up state.
rg -q -U --pcre2 \
	'vmx_nested_finish_initial_hardware_attempt[\s\S]*?vmx_nested_attempt_classify[\s\S]*?\*attempt = candidate;[\s\S]*?vmx_nested_hardware_entry_finish' \
	"$vmx_source" ||
	fail "initial hardware attempt does not publish classification before transition"
rg -q -U --pcre2 \
	'vmx_nested_finish_resumed_hardware_attempt[\s\S]*?vmx_nested_attempt_classify[\s\S]*?\*attempt = candidate;[\s\S]*?switch \(candidate\.action\)' \
	"$vmx_source" ||
	fail "resumed hardware attempt does not publish classification before transition"
rg -q -U --pcre2 \
	'vmx_nested_finish_resumed_hardware_attempt[\s\S]*?\*completion = VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_NONE;[\s\S]*?RESUMED_EXIT[\s\S]*?vmx_nested_l0_resume_entered_intel[\s\S]*?ATTEMPT_ENTERED[\s\S]*?RESUMED_FAILED_ENTRY[\s\S]*?vmx_nested_l0_refreeze_late_entry_intel[\s\S]*?UNENTERED_REFROZEN[\s\S]*?RESUMED_L0_FAILURE[\s\S]*?vmx_nested_l0_refreeze_unentered_intel[\s\S]*?UNENTERED_REFROZEN' \
	"$vmx_source" ||
	fail "resumed hardware attempt does not publish completion after its exact inverse"
rg -q -U --pcre2 \
	'vmx_nested_finish_resumed_hardware_attempt\(vcpu,[\s\S]*?&resumed_completion\)[\s\S]*?RESUMED_EXIT[\s\S]*?resumed_completion !=[\s\S]*?ATTEMPT_ENTERED[\s\S]*?UNENTERED_REFROZEN' \
	"$vmx_source" ||
	fail "nested run does not validate resumed hardware completion before use"
# private-test: nested-attempt-error-domain-inventory
for contract in \
	'VMX_NESTED_ATTEMPT_INITIAL_REJECTION' \
	'VMX_NESTED_ATTEMPT_INITIAL_L0_FAILURE' \
	'VMX_NESTED_ATTEMPT_RESUMED_FAILED_ENTRY' \
	'VMX_NESTED_ATTEMPT_RESUMED_L0_FAILURE' \
	'VMX_NESTED_RUN_UNWIND_DETACH_FATAL'; do
	rg -q -F "$contract" "$vmx_source" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" ||
		fail "nested attempt error-domain inventory omits: $contract"
done
rg -q -F 'int		host_error;' "$src/sys/amd64/vmm/intel/vmx_nested_attempt.h" ||
	fail "nested attempt plan lacks an immutable host-error field"
rg -q -F 'candidate.host_error = EIO;' \
	"$src/sys/amd64/vmm/intel/vmx_nested_attempt.c" ||
	fail "nested L0-only attempt lacks the documented host-error policy"
rg -q -F 'vmx_nested_attempt_plan_validate' \
	"$src/sys/amd64/vmm/intel/vmx_nested_attempt.c" \
	"$src/sys/amd64/vmm/intel/vmx_nested_attempt.h" \
	"$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "nested attempt plan lacks a validated private boundary"
rg -q -F 'vmx_nested_owner_attempt_plan_outcome_compose' \
	"$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" \
	"$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.h" \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "nested attempt error-domain bridge is missing"
rg -q 'NVMX-EVENT-189.*Nested attempt error domains' "$ledger" ||
	fail "nested attempt error-domain requirement is missing"
rg -q 'NVMX-PRIVATE-267.*nested-attempt-error-domain-source-order' \
	"$private_ledger" ||
	fail "nested attempt error-domain private contract is missing"
# private-test: nested-attempt-payload-provenance
rg -q 'NVMX-EVENT-190.*Nested attempt plans validate selected payload provenance' \
	"$ledger" || fail "nested attempt payload-provenance requirement is missing"
rg -q 'NVMX-PRIVATE-268.*attempt-plan-selected-payload-contract' \
	"$private_ledger" ||
	fail "nested attempt payload-provenance private contract is missing"
rg -q 'NVMX-EVENT-191.*Private nested values are semantic not native representations' \
	"$ledger" || fail "nested attempt representation requirement is missing"
rg -q 'NVMX-PRIVATE-269.*private-representation-and-abi-boundary' \
	"$private_ledger" ||
	fail "nested attempt representation private contract is missing"
# private-test: vmx-svm-common-entry-parity
rg -q 'NVMX-EVENT-192.*VMX and SVM final admission have one portable no-entry meaning' \
	"$ledger" || fail "VMX/SVM final-admission parity is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-270.*ordinary-final-admission-parity' \
	"$private_ledger" ||
	fail "VMX/SVM final-admission parity is absent from the private ledger"
rg -q 'entry_owner_declined_final_admission_is_noentry' \
	"$src/tests/sys/vmm/vmm_startup_entry_owner_test.c" ||
	fail "VMX/SVM final-admission parity lacks a no-entry value test"
for contract in \
	'nvmxa_exit_empty' \
	'nvmxa_rejection_empty' \
	'nvmxa_exit_valid' \
	'nvmxa_failed_entry_valid' \
	'vmx_nested_exit_information_equal' \
	'vmx_nested_vmentry_result_equal' \
	'vmx_nested_vmentry_rejection_validate' \
	'vmx_nested_vmentry_hardware_failed_entry' \
	'VMX_NESTED_ATTEMPT_RESUMED_FAILED_ENTRY'; do
	rg -q -F "$contract" "$src/sys/amd64/vmm/intel/vmx_nested_attempt.c" ||
		fail "nested attempt payload validator omits: $contract"
done
! rg -q 'memcmp.*(exit|rejection|normalized)' \
	"$src/sys/amd64/vmm/intel/vmx_nested_attempt.c" ||
	fail "nested attempt payload validator compares compiler representation"
! rg -q 'memcmp\(' "$src/sys/amd64/vmm/intel" --glob 'vmx_nested*.c' \
	--glob 'vmx_nested*.h' ||
	fail "Intel-private nested state compares compiler representation"
for mutation in \
	'plan.rejection.instruction_error = 1;' \
	'plan.exit.exit_reason |= UINT32_C(1) << 31;' \
	'plan.exit.exit_reason = 12;' \
	'plan.rejection.detail = 0;' \
	'representation_byte = offsetof(struct vmx_nested_exit_information,' \
	'representation_byte = offsetof(struct vmx_nested_vmentry_result,' \
	'exit.exit_interruption_info = 1;' \
	'plan.exit.exit_interruption_info = 1;' \
	'plan.exit.exit_reason = (UINT32_C(1) << 31) | 34;'; do
	rg -q -F "$mutation" "$src/tests/sys/vmm/vmx_nested_state_test.c" ||
		fail "nested attempt payload validator lacks mutation: $mutation"
done
# The plan is a private, stack-value adapter.  Common lifecycle and snapshot
# code must never acquire an Intel attempt/result field merely because it is
# useful to a future nested-VMX transaction.
for source in \
	"$startup_entry_owner_source" \
	"$startup_entry_owner_header" \
	"$startup_mode_source" \
	"$startup_mode_header" \
	"$vmm_vm_source" \
	"$vmm_vm_header" \
	"$event_checkpoint_source" \
	"$event_checkpoint_header" \
	"$transaction_source" \
	"$x86_state_source" \
	"$x86_state_header" \
	"$vmm_snapshot_header" \
	"$libvmmapi_header" \
	"$libvmmapi_internal"; do
	! rg -q 'vmx_nested_attempt_plan|VMX_NESTED_ATTEMPT_|host_error' "$source" ||
		fail "Intel private attempt state leaked into portable interface: $source"
done
for contract in \
    'svm_vcpu_startup_event_step' \
    'return (EOPNOTSUPP);'; do
	rg -q -F "$contract" "$svm_source" ||
	    fail "AMD startup dispatch stub omits: $contract"
done
for contract in \
    'vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN' \
    'vmx_nested_startup_dispatch_step(' \
    '*result = VMM_STARTUP_DISPATCH_IDLE;' \
    '*result = VMM_STARTUP_DISPATCH_RETAINED;' \
    '*result = VMM_STARTUP_DISPATCH_CONSUMED;'; do
	rg -q -F "$contract" "$src/sys/amd64/vmm/intel/vmx.c" ||
	    fail "Intel startup dispatch adapter omits: $contract"
done
[ "$(rg -c -F 'vcpu_startup_event_step,' "$common_vmm_source" ||
    true)" -eq 1 ] ||
    fail "machine startup dispatch selector count changed before entry-order qualification"
for contract in \
    'dispatch_result_run_policy' \
    'dispatch_result_rejection_is_failure_atomic' \
    'VMM_STARTUP_DISPATCH_RESULT_LAST' \
    '(enum vmm_startup_dispatch_result)-1'; do
	rg -q -F "$contract" "$startup_mode_test" ||
	    fail "startup dispatch policy tests omit: $contract"
done
rg -q 'NVMX-EVENT-142.*Typed machine startup dispatch boundary' "$ledger" ||
    fail "typed machine startup dispatch requirement is missing"
rg -q 'NVMX-PRIVATE-204.*typed-machine-startup-dispatch' \
    "$private_ledger" || fail "typed machine startup dispatch contract is missing"
# private-test: startup-frozen-running-token
for contract in \
    'struct vmm_startup_event_run_token' \
    'uint64_t active_claim_id;' \
    'uint8_t active_kind;' \
    'vmm_startup_event_run_token_capture(' \
    'vmm_startup_event_run_token_check('; do
	rg -q -F "$contract" "$startup_header" ||
	    fail "startup run-token declaration omits: $contract"
done
for contract in \
    'candidate.owner_id = state->owner_id;' \
    'candidate.active_claim_id = state->active_claim_id;' \
    'token->owner_id != state->owner_id' \
    'return (ESTALE);' \
    'token->generation != state->generation' \
    'token->active_claim_id != state->active_claim_id' \
    'return (EAGAIN);'; do
	rg -q -F "$contract" "$startup_source" ||
	    fail "startup run-token implementation omits: $contract"
done
for contract in \
    'vmm_event_coordinator_startup_run_token_capture(' \
    'vmm_event_coordinator_startup_run_token_check(' \
    'mtx_lock_spin(&entry->lock);' \
    'vmm_startup_event_run_token_check(&entry->startup,'; do
	rg -q -F "$contract" "$event_coordinator_source" ||
	    fail "coordinator startup run-token ownership omits: $contract"
done
[ "$(rg -c -F 'error = vmm_event_coordinator_startup_ready(coordinator, entry);' \
    "$event_coordinator_source")" -ge 2 ] ||
    fail "startup run-token capture and check do not both reject quiesce/cancel"
for contract in \
    'vcpu_startup_event_run_token_capture(' \
    'vcpu_startup_event_run_token_check('; do
	rg -q -F "$contract" "$vmm_vm_source" ||
	    fail "vCPU startup run-token wrapper omits: $contract"
done
for contract in \
    'run_token_closes_frozen_entry_window' \
    'vmm_startup_event_claim_finish(&state, &claim)' \
    'state.generation, before_token.generation' \
    'ESTALE' \
    'EAGAIN'; do
	rg -q -F "$contract" "$startup_test_source" ||
	    fail "startup run-token test omits: $contract"
done
rg -q 'NVMX-EVENT-143.*Frozen-to-running startup notification token' \
    "$ledger" || fail "startup run-token requirement is missing"
rg -q 'NVMX-PRIVATE-205.*frozen-running-startup-token' \
    "$private_ledger" || fail "startup run-token private contract is missing"
# private-test: startup-entry-arbitration
for contract in \
    'enum vmm_startup_entry_action' \
    'VMM_STARTUP_ENTRY_SERVICE_RENDEZVOUS' \
    'VMM_STARTUP_ENTRY_SERVICE_SUSPEND' \
    'VMM_STARTUP_ENTRY_SERVICE_REQIDLE' \
    'VMM_STARTUP_ENTRY_RETURN_DEBUG' \
    'VMM_STARTUP_ENTRY_WAIT' \
    'VMM_STARTUP_ENTRY_ENTER_GUEST' \
    'VMM_STARTUP_ENTRY_REPLAY' \
    'struct vmm_startup_entry_snapshot' \
    'vmm_startup_entry_pre_dispatch(' \
    'vmm_startup_entry_post_dispatch('; do
	rg -q -F "$contract" "$startup_mode_header" ||
	    fail "startup entry-arbitration declaration omits: $contract"
done
for contract in \
    'if (snapshot->rendezvous != 0)' \
    'else if (snapshot->suspended != 0)' \
    'else if (snapshot->reqidle != 0)' \
    'else if (snapshot->debugged != 0)' \
    'result == VMM_STARTUP_DISPATCH_CONSUMED' \
    'candidate = VMM_STARTUP_ENTRY_REPLAY;' \
    'result == VMM_STARTUP_DISPATCH_IDLE &&' \
    'candidate = VMM_STARTUP_ENTRY_WAIT;' \
    'candidate = VMM_STARTUP_ENTRY_ENTER_GUEST;'; do
	rg -q -F "$contract" "$startup_mode_source" ||
	    fail "startup entry arbitration omits: $contract"
done
for contract in \
    'entry_arbitration_exhaustive' \
    'entry_arbitration_rejection_is_failure_atomic' \
    'bits < 32' \
    'result < VMM_STARTUP_DISPATCH_RESULT_LAST'; do
	rg -q -F "$contract" "$startup_mode_test_source" ||
	    fail "startup entry-arbitration test omits: $contract"
done
rg -q 'NVMX-EVENT-144.*Two-stage startup entry arbitration' "$ledger" ||
    fail "startup entry-arbitration requirement is missing"
rg -q 'NVMX-PRIVATE-206.*two-stage-startup-entry-arbitration' \
    "$private_ledger" || fail "startup entry-arbitration private contract is missing"
# private-test: startup-entry-handoff
for contract in \
    'struct vmm_startup_entry_handoff' \
    'uint64_t notification_generation;' \
    'vmm_startup_entry_handoff_capture(' \
    'vmm_startup_entry_handoff_check(' \
    'vmm_startup_entry_handoff_disarm(' \
    'vmm_startup_notification_advance('; do
	rg -q -F "$contract" "$startup_mode_header" ||
	    fail "startup entry-handoff declaration omits: $contract"
done
for contract in \
    'handoff->notification_generation == 0' \
    'result == VMM_STARTUP_DISPATCH_CONSUMED' \
    'vmm_startup_notification_advance(' \
    'notification_generation_after != expected_generation' \
    'candidate.notification_generation = notification_generation_after;' \
    'notification_generation != handoff->notification_generation' \
    'return (EAGAIN);' \
    'memset(handoff, 0, sizeof(*handoff));'; do
	rg -q -F "$contract" "$startup_mode_source" ||
	    fail "startup entry-handoff implementation omits: $contract"
done
rg -q 'uint64_t[[:space:]]+startup_notify_generation;' "$vmm_vm_header" ||
    fail "vCPU startup notification epoch declaration omits its generation"
rg -q -F 'vcpu_startup_notify_generation_capture(' "$vmm_vm_header" ||
    fail "vCPU startup notification epoch declaration omits capture"
for contract in \
    'vcpu_notify_startup_event(struct vcpu *vcpu)' \
    'vmm_startup_notification_advance(' \
    'vcpu_startup_notify_generation_capture(struct vcpu *vcpu)'; do
	rg -q -F "$contract" "$vmm_vm_source" ||
	    fail "vCPU startup notification epoch omits: $contract"
done
[ "$(rg -c -F 'vcpu_notify_startup_event(' "$vmm_vm_source")" -eq 6 ] ||
    fail "not every startup publication/release path uses the startup epoch"
for contract in \
    'entry_handoff_detects_preentry_notification' \
    'entry_handoff_rejection_is_failure_atomic' \
    'notification_generation_boundaries' \
    'vmm_startup_notification_advance(UINT64_MAX, &next)' \
    'VMM_STARTUP_DISPATCH_IDLE, 72, &handoff), EAGAIN' \
    'VMM_STARTUP_DISPATCH_RETAINED, 82, &handoff), EAGAIN' \
    'VMM_STARTUP_DISPATCH_CONSUMED, 91, &handoff), EAGAIN' \
    'VMM_STARTUP_DISPATCH_CONSUMED, 103, &handoff), EAGAIN' \
    'vmm_startup_entry_handoff_check(43, &handoff), EAGAIN' \
    'vmm_startup_entry_handoff_disarm(42, &handoff), 0'; do
	rg -q -F "$contract" "$startup_mode_test_source" ||
	    fail "startup entry-handoff test omits: $contract"
done
rg -q 'NVMX-EVENT-145.*Interrupt-disabled startup entry handoff' "$ledger" ||
    fail "startup entry-handoff requirement is missing"
rg -q 'NVMX-PRIVATE-207.*startup-entry-notification-handoff' \
    "$private_ledger" || fail "startup entry-handoff private contract is missing"
startup_handoff_files=$(rg -l \
    'startup_notify_generation|vmm_startup_entry_handoff' "$src/sys" | sort)
expected_startup_handoff_files=$(printf '%s\n' \
    "$src/sys/dev/vmm/vmm_startup_entry_owner.c" \
    "$src/sys/dev/vmm/vmm_startup_entry_owner.h" \
    "$src/sys/dev/vmm/vmm_startup_mode.c" \
    "$src/sys/dev/vmm/vmm_startup_mode.h" \
    "$src/sys/dev/vmm/vmm_vm.c" \
    "$src/sys/dev/vmm/vmm_vm.h" | sort)
[ "$startup_handoff_files" = "$expected_startup_handoff_files" ] ||
    fail "runtime-only startup handoff leaked into an unreviewed kernel consumer"
# private-test: startup-entry-runtime-model
for contract in \
    'enum vmm_startup_entry_runtime_phase' \
    'enum vmm_startup_entry_runtime_action' \
    'struct vmm_startup_entry_runtime' \
    'struct vmm_startup_entry_runtime_result' \
    'vmm_startup_entry_runtime_enter_critical(' \
    'vmm_startup_entry_runtime_restore_guest_fpu(' \
    'vmm_startup_entry_runtime_publish_running(' \
    'vmm_startup_entry_runtime_check(' \
    'vmm_startup_entry_runtime_publish_frozen(' \
    'vmm_startup_entry_runtime_save_guest_fpu(' \
    'vmm_startup_entry_runtime_exit_critical('; do
	rg -q -F "$contract" "$startup_mode_header" ||
	    fail "startup entry-runtime declaration omits: $contract"
done
for contract in \
    'runtime->phase != VMM_STARTUP_ENTRY_RUNTIME_FROZEN' \
    'candidate.critical = 1;' \
    'runtime->phase != VMM_STARTUP_ENTRY_RUNTIME_CRITICAL' \
    'candidate.guest_fpu = 1;' \
    'runtime->phase != VMM_STARTUP_ENTRY_RUNTIME_GUEST_FPU' \
    'candidate.running = 1;' \
    'runtime->phase != VMM_STARTUP_ENTRY_RUNTIME_RUNNING &&' \
    'runtime->phase != VMM_STARTUP_ENTRY_RUNTIME_CHECKED' \
    'vmm_startup_entry_error_compose(' \
    'const int errors[] = { first, second, third };' \
    'terminal != errors[i]' \
    'return (EPROTO);' \
    'candidate_result.error == EAGAIN' \
    'candidate.running = 0;' \
    'runtime->phase != VMM_STARTUP_ENTRY_RUNTIME_REFROZEN' \
    'candidate.guest_fpu = 0;' \
    'runtime->phase != VMM_STARTUP_ENTRY_RUNTIME_HOST_FPU' \
    'candidate.critical = 0;'; do
	rg -q -F "$contract" "$startup_mode_source" ||
	    fail "startup entry-runtime implementation omits: $contract"
done
for contract in \
    'entry_runtime_exact_unwind' \
    'entry_runtime_replay_and_error_unwind' \
    'entry_runtime_rechecks_each_hardware_entry' \
    'entry_runtime_rejects_invalid_order' \
    '{ EAGAIN, 0, EAGAIN }' \
    '{ 0, EAGAIN, EAGAIN }' \
    '{ EAGAIN, EAGAIN, EAGAIN }' \
    '{ EBUSY, EAGAIN, EBUSY }' \
    '{ EAGAIN, EBUSY, EBUSY }' \
    '{ EAGAIN, EINVAL, EINVAL }' \
    '{ EINVAL, EAGAIN, EINVAL }' \
    '{ EBUSY, EBUSY, EBUSY }' \
    '{ EBUSY, EINVAL, EPROTO }' \
    '{ EINVAL, EBUSY, EPROTO }' \
    'VMM_STARTUP_ENTRY_RUNTIME_RETURN_ERROR' \
    '(struct vmm_startup_entry_runtime_result *)(void *)&runtime'; do
	rg -q -F "$contract" "$startup_mode_test_source" ||
	    fail "startup entry-runtime test omits: $contract"
done
rg -q 'NVMX-EVENT-146.*Startup entry FPU and run-state unwind model' \
    "$ledger" || fail "startup entry-runtime requirement is missing"
rg -q 'NVMX-PRIVATE-208.*startup-entry-runtime-model' "$private_ledger" ||
    fail "startup entry-runtime private contract is missing"
# private-test: startup-entry-every-hardware-entry
for contract in \
    'runtime->phase != VMM_STARTUP_ENTRY_RUNTIME_RUNNING &&' \
    'runtime->phase != VMM_STARTUP_ENTRY_RUNTIME_CHECKED' \
    'Every backend hardware re-entry repeats this same check.'; do
	rg -q -F "$contract" "$startup_mode_source" ||
	    fail "startup repeated-entry implementation omits: $contract"
done
for contract in \
    'entry_runtime_rechecks_each_hardware_entry' \
    'vmm_startup_entry_runtime_check(&runtime, 0, 0,' \
    'vmm_startup_entry_runtime_check(&runtime, EAGAIN,' \
    'VMM_STARTUP_ENTRY_RUNTIME_REPLAY'; do
	rg -q -F "$contract" "$startup_mode_test_source" ||
	    fail "startup repeated-entry test omits: $contract"
done
rg -q 'NVMX-EVENT-147.*Startup guard validation before every hardware entry' \
    "$ledger" || fail "startup repeated-entry requirement is missing"
rg -q 'NVMX-PRIVATE-209.*repeated-hardware-entry-guard' "$private_ledger" ||
    fail "startup repeated-entry private contract is missing"
# private-test: startup-entry-loop-model
for contract in \
    'enum vmm_startup_entry_loop_phase' \
    'struct vmm_startup_entry_loop' \
    'vmm_startup_entry_loop_init(' \
    'vmm_startup_entry_loop_check(' \
    'vmm_startup_entry_loop_enter(' \
    'vmm_startup_entry_loop_exit(' \
    'vmm_startup_entry_loop_finish('; do
	rg -q -F "$contract" "$startup_mode_header" ||
	    fail "startup entry-loop declaration omits: $contract"
done
for contract in \
    'loop->check_count != loop->entry_count + 1' \
    'loop->check_count != loop->entry_count' \
    'vmm_startup_entry_runtime_result_validate(' \
    'candidate.check_count++;' \
    'candidate.entry_count++;' \
    'VMM_STARTUP_ENTRY_LOOP_NEED_CHECK' \
    'VMM_STARTUP_ENTRY_LOOP_CHECKED' \
    'VMM_STARTUP_ENTRY_LOOP_IN_GUEST' \
    'VMM_STARTUP_ENTRY_LOOP_RETURNABLE' \
    'VMM_STARTUP_ENTRY_LOOP_COMPLETE'; do
	rg -q -F "$contract" "$startup_mode_source" ||
	    fail "startup entry-loop implementation omits: $contract"
done
for contract in \
    'entry_loop_requires_check_before_each_entry' \
    'entry_loop_drift_after_handled_exit_returns' \
    'entry_loop_rejects_malformed_and_overflow' \
    'vmm_startup_entry_loop_exit(&loop, true, 0)' \
    'vmm_startup_entry_loop_enter(&loop), EINVAL' \
    'vmm_startup_entry_loop_check(&loop, &replay)' \
    'loop.check_count = UINT64_MAX' \
    'EOVERFLOW'; do
	rg -q -F "$contract" "$startup_mode_test_source" ||
	    fail "startup entry-loop test omits: $contract"
done
rg -q 'NVMX-EVENT-148.*Checked hardware-entry loop state machine' \
    "$ledger" || fail "startup entry-loop requirement is missing"
rg -q 'NVMX-PRIVATE-210.*checked-hardware-entry-loop' "$private_ledger" ||
    fail "startup entry-loop private contract is missing"
# private-test: startup-entry-loop-owned-disposition
for contract in \
    'enum vmm_startup_entry_loop_action' \
    'struct vmm_startup_entry_loop_result' \
    'struct vmm_startup_entry_loop_result disposition;' \
    'candidate.disposition.error = result->error;' \
    'candidate_result = loop->disposition;' \
    'loop->phase <= VMM_STARTUP_ENTRY_LOOP_IN_GUEST' \
    'vmm_startup_mode_overlap(loop, sizeof(*loop), result,'; do
	rg -q -F "$contract" "$startup_mode_header" "$startup_mode_source" ||
	    fail "startup entry-loop disposition implementation omits: $contract"
done
for contract in \
    'entry_loop_owns_return_disposition' \
    'replay.error = EBUSY;' \
    'VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT' \
    'VMM_STARTUP_ENTRY_LOOP_REPLAY' \
    'VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR' \
    'vmm_startup_entry_loop_finish(&loop, &result)' \
    'vmm_startup_entry_loop_finish(&loop, NULL)' \
    'loop.disposition.reserved8[2] = 1' \
    'memcmp(&result, &result_before, sizeof(result))'; do
	rg -q -F "$contract" "$startup_mode_test_source" ||
	    fail "startup entry-loop disposition test omits: $contract"
done
rg -q 'NVMX-EVENT-149.*Owned backend-loop return disposition' "$ledger" ||
    fail "startup entry-loop disposition requirement is missing"
rg -q 'NVMX-PRIVATE-211.*backend-loop-disposition-snapshot' \
    "$private_ledger" ||
    fail "startup entry-loop disposition private contract is missing"
rg -q 'NVMX-EVENT-150.*Distinct guard and backend-return action domains' \
    "$ledger" || fail "startup entry-loop action-domain requirement is missing"
rg -q 'NVMX-PRIVATE-212.*backend-loop-return-action-domain' \
    "$private_ledger" ||
    fail "startup entry-loop action-domain private contract is missing"
# private-test: nested-guard-boundary-unwind
for contract in \
    'nested_run_guard_boundary_unwind' \
    'VMX_NESTED_ENTRY_RUNTIME_RESOURCES' \
    'VMX_NESTED_ENTRY_RUNTIME_L0_THAWING' \
    'VMX_NESTED_L0_CONTINUATION_THAWING' \
    'VMX_NESTED_RUN_UNWIND_FREEZE_HOT' \
    'VMX_NESTED_RUN_UNWIND_FAIL_STOP'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "nested guard-boundary unwind test omits: $contract"
done
rg -q 'NVMX-EVENT-151.*Nested guard-boundary unwind classes' "$ledger" ||
    fail "nested guard-boundary unwind requirement is missing"
rg -q 'NVMX-PRIVATE-213.*nested-guard-boundary-unwind' \
    "$private_ledger" ||
    fail "nested guard-boundary unwind private policy is missing"
# private-test: startup-entry-guard-admission
for contract in \
    'vmm_startup_entry_guard_before(' \
    'runtime_candidate = *runtime;' \
    'loop_candidate = *loop;' \
    'vmm_startup_entry_runtime_check(&runtime_candidate' \
    'vmm_startup_entry_loop_check(&loop_candidate' \
    'vmm_startup_entry_loop_enter(&loop_candidate)'; do
	rg -q -F "$contract" "$startup_mode_header" "$startup_mode_source" ||
	    fail "startup entry guard admission omits: $contract"
done
for contract in \
    'entry_guard_admission_is_failure_atomic' \
    'loop.reserved8[0] = 1;' \
	'vmm_startup_entry_loop_finish(&loop, &loop_result)' \
	'vmm_startup_entry_runtime_publish_frozen(&runtime)' \
	'vmm_startup_entry_runtime_save_guest_fpu(&runtime)' \
	'vmm_startup_entry_runtime_exit_critical(&runtime)' \
    'memcmp(&runtime, &before_runtime, sizeof(runtime))' \
    'memcmp(&loop, &before_loop, sizeof(loop))' \
    'memcmp(&result, &before_result, sizeof(result))'; do
	rg -q -F "$contract" "$startup_mode_test_source" ||
	    fail "startup entry guard admission test omits: $contract"
done
rg -q 'NVMX-EVENT-152.*Failure-atomic guard admission composition' \
    "$ledger" || fail "startup entry guard admission requirement is missing"
rg -q 'NVMX-PRIVATE-214.*startup-entry-guard-admission' \
    "$private_ledger" ||
    fail "startup entry guard admission private contract is missing"
# private-test: startup-entry-guard-return
for contract in \
    'vmm_startup_entry_guard_after(' \
    'loop_candidate = *loop;' \
    'vmm_startup_entry_loop_exit(&loop_candidate, handled,' \
    'vmm_startup_entry_loop_finish(&loop_candidate,' \
    '(handled && (backend_error != 0 || result != NULL))' \
    'candidate.disposition.error = backend_error;' \
    'VMM_STARTUP_ENTRY_LOOP_REPLAY :' \
    '(!handled && result == NULL)'; do
	rg -q -F "$contract" "$startup_mode_header" "$startup_mode_source" ||
	    fail "startup entry guard return omits: $contract"
done
for contract in \
    'entry_guard_return_is_failure_atomic' \
    'vmm_startup_entry_guard_after(&loop, true, 0, NULL)' \
    'vmm_startup_entry_guard_after(&loop, false, 0,' \
    'vmm_startup_entry_guard_after(&loop, false, EAGAIN,' \
    'vmm_startup_entry_guard_after(&loop, false, EIO,' \
    'vmm_startup_entry_guard_after(&loop, true, EIO, NULL)' \
    'VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT' \
    'VMM_STARTUP_ENTRY_LOOP_REPLAY' \
    'VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR' \
    'memcmp(&loop, &before, sizeof(loop))' \
    'memcmp(&result, &before_result, sizeof(result))' \
    '(struct vmm_startup_entry_loop_result *)(void *)&loop'; do
	rg -q -F "$contract" "$startup_mode_test_source" ||
	    fail "startup entry guard return test omits: $contract"
done
rg -q 'NVMX-EVENT-153.*Failure-atomic hardware-return composition' \
    "$ledger" || fail "startup entry guard return requirement is missing"
rg -q 'NVMX-PRIVATE-215.*startup-entry-guard-return' \
    "$private_ledger" ||
    fail "startup entry guard return private contract is missing"
# private-test: startup-entry-guard-completion
for contract in \
    'vmm_startup_entry_guard_complete(' \
    'vmm_startup_entry_error_compose(backend_result->error,' \
    'VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT' \
    'VMM_STARTUP_ENTRY_LOOP_REPLAY' \
    'VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR'; do
	rg -q -F "$contract" "$startup_mode_header" "$startup_mode_source" ||
	    fail "startup entry guard completion omits: $contract"
done
for contract in \
    'entry_guard_completion_closes_final_return_window' \
    'vmm_startup_entry_guard_complete(&normal, EAGAIN, 0,' \
    'vmm_startup_entry_guard_complete(&terminal, EAGAIN, 0,' \
    'vmm_startup_entry_guard_complete(&normal, EIO, ESTALE,' \
    'ATF_CHECK_EQ(result.error, EPROTO)' \
    'vmm_startup_entry_guard_complete(&normal, -1, 0,' \
    'vmm_startup_entry_guard_complete(&result, 0, 0,'; do
	rg -q -F "$contract" "$startup_mode_test_source" ||
	    fail "startup entry guard completion test omits: $contract"
done
rg -q 'NVMX-EVENT-155.*Final refrozen startup-owner arbitration' \
    "$ledger" || fail "final startup-owner arbitration requirement is missing"
rg -q 'NVMX-PRIVATE-217.*startup-entry-final-arbitration' \
    "$private_ledger" ||
    fail "final startup-owner arbitration private contract is missing"
# private-test: startup-entry-stack-owner
for contract in \
    'struct vmm_startup_entry_owner' \
    'struct vmm_startup_event_run_token coordinator;' \
    'struct vmm_startup_entry_handoff notification;' \
    'struct vmm_startup_entry_runtime runtime;' \
    'struct vmm_startup_entry_loop loop;' \
	'enum vmm_startup_entry_owner_phase' \
	'VMM_STARTUP_ENTRY_OWNER_BOUND' \
    'vmm_startup_entry_owner_validate(' \
    'vmm_startup_entry_owner_init('; do
	rg -q -F "$contract" "$startup_entry_owner_header" \
	    "$startup_entry_owner_source" ||
	    fail "startup entry stack owner omits: $contract"
done
for contract in \
    'vmm_startup_event_run_token_validate(&owner->coordinator)' \
    'vmm_startup_entry_handoff_validate(&owner->notification)' \
    'vmm_startup_entry_runtime_validate(&owner->runtime)' \
    'vmm_startup_entry_loop_validate(&owner->loop)' \
	'case VMM_STARTUP_ENTRY_OWNER_BOUND:' \
	'owner->runtime.phase ==' \
	'VMM_STARTUP_ENTRY_RUNTIME_FROZEN ? 0 : EINVAL' \
	'owner->loop.phase != VMM_STARTUP_ENTRY_LOOP_NEED_CHECK' \
	'owner->loop.check_count != 0 || owner->loop.entry_count != 0' \
    'vmm_startup_entry_owner_overlap(coordinator, sizeof(*coordinator),' \
    'vmm_startup_entry_owner_overlap(notification, sizeof(*notification),' \
    '!vmm_startup_entry_owner_empty(owner)' \
    'candidate.coordinator = *coordinator;' \
    'candidate.notification = *notification;' \
    'candidate.armed = 1;'; do
	rg -q -F "$contract" "$startup_entry_owner_source" ||
	    fail "startup entry stack owner implementation omits: $contract"
done
for contract in \
    'entry_owner_binds_post_dispatch_values' \
    'vmm_startup_entry_owner_init(&token, &handoff,' \
    'vmm_startup_entry_owner_validate(&owner)' \
    'bad_token.reserved = 1;' \
    'handoff.reserved = 1;' \
	'malformed.loop.check_count = 4;' \
	'malformed.loop.entry_count = 4;' \
    '&owner.coordinator, &handoff, &owner' \
    'memcmp(&owner, &before, sizeof(owner))'; do
	rg -q -F "$contract" "$startup_entry_owner_test_source" ||
	    fail "startup entry stack owner test omits: $contract"
done
rg -q 'NVMX-EVENT-156.*Stack-owned startup entry value bundle' \
    "$ledger" || fail "startup entry stack-owner requirement is missing"
rg -q 'NVMX-PRIVATE-218.*startup-entry-stack-owner' \
    "$private_ledger" ||
    fail "startup entry stack-owner private contract is missing"
rg -q -F 'vmm_startup_entry_owner.c' "$module_makefile" ||
    fail "startup entry stack owner is not architecture-neutral VMM code"
# private-test: startup-entry-owner-preparation
for contract in \
	'VMM_STARTUP_ENTRY_OWNER_CRITICAL' \
	'VMM_STARTUP_ENTRY_OWNER_GUEST_FPU' \
	'VMM_STARTUP_ENTRY_OWNER_RUNNING' \
	'vmm_startup_entry_owner_enter_critical(' \
	'vmm_startup_entry_owner_restore_guest_fpu(' \
	'vmm_startup_entry_owner_publish_running('; do
	rg -q -F "$contract" "$startup_entry_owner_header" \
	    "$startup_entry_owner_source" ||
	    fail "startup entry owner preparation omits: $contract"
done
for contract in \
	'vmm_startup_entry_owner_relation_validate(' \
	'owner->loop.phase != VMM_STARTUP_ENTRY_LOOP_NEED_CHECK' \
	'candidate = *owner;' \
	'vmm_startup_entry_runtime_enter_critical(&candidate.runtime)' \
	'vmm_startup_entry_runtime_restore_guest_fpu(&candidate.runtime)' \
	'vmm_startup_entry_runtime_publish_running(&candidate.runtime)' \
	'vmm_startup_entry_owner_validate(&candidate)'; do
	rg -q -F "$contract" "$startup_entry_owner_source" ||
	    fail "startup entry owner preparation implementation omits: $contract"
done
for contract in \
	'entry_owner_preparation_is_ordered_and_failure_atomic' \
	'vmm_startup_entry_owner_restore_guest_fpu(&owner), EINVAL' \
	'vmm_startup_entry_owner_publish_running(&owner), EINVAL' \
	'vmm_startup_entry_owner_enter_critical(&owner)' \
	'malformed.loop.check_count = 2;' \
	'malformed.loop.entry_count = 2;' \
	'memcmp(&malformed, &before, sizeof(malformed))'; do
	rg -q -F "$contract" "$startup_entry_owner_test_source" ||
	    fail "startup entry owner preparation test omits: $contract"
done
rg -q 'NVMX-EVENT-157.*Ordered stack-owner preparation' "$ledger" ||
    fail "startup entry owner preparation requirement is missing"
rg -q 'NVMX-PRIVATE-219.*startup-entry-owner-preparation' \
    "$private_ledger" ||
    fail "startup entry owner preparation private contract is missing"
# private-test: startup-entry-owner-retirement
for contract in \
	'VMM_STARTUP_ENTRY_OWNER_IN_GUEST' \
	'VMM_STARTUP_ENTRY_OWNER_RECHECK' \
	'VMM_STARTUP_ENTRY_OWNER_RETURNABLE' \
	'VMM_STARTUP_ENTRY_OWNER_REFROZEN' \
	'VMM_STARTUP_ENTRY_OWNER_HOST_FPU' \
	'VMM_STARTUP_ENTRY_OWNER_COMPLETE' \
	'vmm_startup_entry_owner_guard_before(' \
	'vmm_startup_entry_owner_guard_after(' \
	'vmm_startup_entry_owner_publish_frozen(' \
	'vmm_startup_entry_owner_save_guest_fpu(' \
	'vmm_startup_entry_owner_exit_critical(' \
	'vmm_startup_entry_owner_retire('; do
	rg -q -F "$contract" "$startup_entry_owner_header" \
	    "$startup_entry_owner_source" ||
	    fail "startup entry owner retirement omits: $contract"
done
for contract in \
	'vmm_startup_entry_guard_before(&candidate.runtime,' \
	'vmm_startup_entry_loop_finish(&candidate.loop,' \
	'vmm_startup_entry_guard_after(&candidate.loop, handled,' \
	'handled ? VMM_STARTUP_ENTRY_OWNER_RECHECK :' \
	'vmm_startup_entry_runtime_publish_frozen(&candidate.runtime)' \
	'vmm_startup_entry_runtime_save_guest_fpu(&candidate.runtime)' \
	'vmm_startup_entry_runtime_exit_critical(&candidate.runtime)' \
	'vmm_startup_entry_guard_complete(&owner->loop.disposition,' \
	'memset(owner, 0, sizeof(*owner));'; do
	rg -q -F "$contract" "$startup_entry_owner_source" ||
	    fail "startup entry owner retirement implementation omits: $contract"
done
for contract in \
	'entry_owner_loop_unwind_and_retirement_are_owned' \
	'vmm_startup_entry_owner_guard_before(&owner, -1, 0,' \
	'VMM_STARTUP_ENTRY_OWNER_IN_GUEST' \
	'vmm_startup_entry_owner_guard_after(&owner, true, 0,' \
	'VMM_STARTUP_ENTRY_OWNER_RECHECK' \
	'owner.loop.check_count = UINT64_MAX;' \
	'owner.loop.entry_count = UINT64_MAX;' \
	'&decision), EOVERFLOW' \
	'vmm_startup_entry_owner_guard_after(&owner, false, EIO,' \
	'vmm_startup_entry_owner_guard_after(&owner, false, -1,' \
	'vmm_startup_entry_owner_retire(&owner, -1, 0, &final)' \
	'(struct vmm_startup_entry_loop_result *)(void *)&owner.notification' \
	'vmm_startup_entry_owner_guard_before(&owner, EAGAIN, 0,' \
	'memcmp(&owner, &zero, sizeof(owner))'; do
	rg -q -F "$contract" "$startup_entry_owner_test_source" ||
	    fail "startup entry owner retirement test omits: $contract"
done
for contract in \
	'entry_owner_final_arbitration_preserves_domains' \
	'entry_owner_complete_backend(&token, &handoff, 0, &owner)' \
	'vmm_startup_entry_owner_retire(&owner, EAGAIN, 0,' \
	'vmm_startup_entry_owner_retire(&owner, EIO, ESTALE,' \
	'ATF_CHECK_EQ(final.error, EPROTO)' \
	'entry_owner_complete_backend(&token, &handoff, EBUSY, &owner)' \
	'vmm_startup_entry_owner_retire(&owner, EAGAIN, EBUSY,'; do
	rg -q -F "$contract" "$startup_entry_owner_test_source" ||
	    fail "startup entry owner final arbitration test omits: $contract"
done
for contract in \
	'entry_owner_state_product_is_exact' \
	'owner_phase < VMM_STARTUP_ENTRY_OWNER_PHASE_LAST' \
	'runtime_phase < VMM_STARTUP_ENTRY_RUNTIME_PHASE_LAST' \
	'loop_phase < VMM_STARTUP_ENTRY_LOOP_PHASE_LAST' \
	'action < VMM_STARTUP_ENTRY_LOOP_ACTION_LAST' \
	'entry_owner_tuple_expected(&owner)' \
	'vmm_startup_entry_owner_validate(&owner) == 0' \
	'owner=%u runtime=%u loop=%u count=%ju action=%u'; do
	rg -q -F "$contract" "$startup_entry_owner_test_source" ||
	    fail "startup entry owner state-product test omits: $contract"
done
rg -q 'NVMX-EVENT-158.*Owned entry loop unwind and retirement' "$ledger" ||
    fail "startup entry owner retirement requirement is missing"
rg -q 'NVMX-PRIVATE-220.*startup-entry-owner-retirement' \
    "$private_ledger" ||
    fail "startup entry owner retirement private contract is missing"
# private-test: startup-entry-no-hardware-return
for contract in \
	'VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT' \
	'vmm_startup_entry_loop_software_exit(' \
	'vmm_startup_entry_loop_fail_before_entry(' \
	'vmm_startup_entry_owner_software_exit(' \
	'vmm_startup_entry_owner_fail_before_entry('; do
	rg -q -F "$contract" "$startup_mode_header" "$startup_mode_source" \
	    "$startup_entry_owner_header" "$startup_entry_owner_source" ||
	    fail "startup no-hardware return contract omits: $contract"
done
for contract in \
	'loop->phase != VMM_STARTUP_ENTRY_LOOP_NEED_CHECK' \
	'(software_exit && error != 0)' \
	'(!software_exit && error <= 0)' \
	'VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT' \
	'candidate.phase = VMM_STARTUP_ENTRY_LOOP_COMPLETE' \
	'backend_result->action ==' \
	'VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT ?'; do
	rg -q -F "$contract" "$startup_mode_source" ||
	    fail "startup no-hardware return implementation omits: $contract"
done
for contract in \
	'entry_loop_distinguishes_no_entry_returns' \
	'vmm_startup_entry_loop_software_exit(&loop, &result)' \
	'vmm_startup_entry_loop_fail_before_entry(&loop, EAGAIN,' \
	'vmm_startup_entry_loop_fail_before_entry(&loop, EIO,' \
	'vmm_startup_entry_loop_fail_before_entry(&loop, 0,' \
	'(struct vmm_startup_entry_loop_result *)(void *)&loop'; do
	rg -q -F "$contract" "$startup_mode_test_source" ||
	    fail "startup no-hardware loop test omits: $contract"
done
for contract in \
	'entry_owner_distinguishes_preentry_returns' \
	'vmm_startup_entry_owner_software_exit(&owner, &result)' \
	'VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT' \
	'owner.loop.entry_count, 0' \
	'VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT' \
	'vmm_startup_entry_owner_fail_before_entry(&owner, 0,' \
	'vmm_startup_entry_owner_fail_before_entry(&owner, EIO,'; do
	rg -q -F "$contract" "$startup_entry_owner_test_source" ||
	    fail "startup no-hardware owner test omits: $contract"
done
# Keep the independent all-backend-shape model from silently degenerating
# into another generic loop test.  These literals name the source inventory,
# while the counts prove ordinary, nested re-entry, SVM, and no-entry paths
# retain distinct coverage without presenting this rootless model as hardware
# activation evidence.
for contract in \
	'entry_owner_backend_edge_shapes' \
	'entry_owner_run_backend_shape' \
	'ordinary VMX, nested cold entry, nested' \
	'ordinary-VMX nested-cold nested-resume nested-hot and SVM-shaped' \
	'&token, &handoff, 1, false, false, 0, 2' \
	'&token, &handoff, 2, false, false, 0, 3' \
	'&token, &handoff, 0, true, true, 0, 0' \
	'&token, &handoff, 0, true, false, EAGAIN,' \
	'&token, &handoff, 0, true, false, EIO, 0' \
	'EOPNOTSUPP, 0'; do
	rg -q -F "$contract" "$startup_entry_owner_test_source" \
	    "$private_ledger" ||
	    fail "startup backend-edge owner model omits: $contract"
done
rg -q 'NVMX-EVENT-159.*Typed return without hardware entry' "$ledger" ||
    fail "startup no-hardware return requirement is missing"
rg -q 'NVMX-PRIVATE-221.*no-hardware-return-provenance' \
    "$private_ledger" ||
    fail "startup no-hardware return private contract is missing"
if rg -q --pcre2 'vmm_startup_entry_runtime_(?:init|validate|enter_critical|restore_guest_fpu|publish_running|check|publish_frozen|save_guest_fpu|exit_critical)\(' "$src/sys/amd64/vmm/intel/vmx.c" ||
	    rg -q --pcre2 'vmm_startup_entry_loop_[a-z_]+\(' "$src/sys/amd64/vmm/intel/vmx.c"; then
	fail "VMX bypasses the checked startup-owner adapter with raw runtime or loop state"
fi
# The common entry boundary owns the architecture-neutral admission and final
# unwind.  Backends remain fail-closed until every hardware and no-entry edge
# consumes the owner; do not let this narrow shared integration become a
# blanket permission for owner helpers in VMX or SVM.
for contract in \
	'struct vmm_startup_entry_admission startup_admission;' \
	'struct vmm_startup_entry_owner startup_owner;' \
	'vcpu_startup_event_run_token_capture(vcpu,' \
	'vmm_startup_entry_owner_admit(&startup_token,' \
	'vmm_startup_entry_owner_enter_critical(&startup_owner)' \
	'vmm_startup_entry_owner_restore_guest_fpu(&startup_owner)' \
	'vmm_startup_entry_owner_publish_running(&startup_owner)' \
	'startup_owner_active ? &startup_owner : NULL' \
	'vmm_startup_entry_owner_fail_before_entry(&startup_owner,' \
	'vmm_startup_entry_owner_publish_frozen(&startup_owner)' \
	'vmm_startup_entry_owner_save_guest_fpu(&startup_owner)' \
	'vmm_startup_entry_owner_exit_critical(&startup_owner)' \
	'vcpu_startup_entry_owner_retire(vcpu, &startup_owner,'; do
	rg -q -F "$contract" "$vmm_source" ||
	    fail "common startup-owner integration omits: $contract"
done
# private-test: ordinary-vmx-attempted-entry-owner
# Ordinary L1 VMX has one fully audited VMLAUNCH/VMRESUME loop.  It may use
# only the checked owner adapter, and only with the immediate-before-entry
# placement and full reverse cleanup below.  Nested cold/hot VMCS02 execution
# remains fail-closed: it retains its explicit EOPNOTSUPP boundary until its
# distinct hardware residency and refreeze paths are converted together.
for contract in \
	'vmm_startup_entry_owner_software_exit(entry_owner,' \
	'vcpu_startup_entry_owner_guard_before_attempt(vcpu->vcpu,' \
	'vmm_startup_entry_owner_resolve_deferred(entry_owner,' \
	'vmm_startup_entry_owner_commit_attempt(entry_owner)' \
	'vmm_startup_entry_owner_abort_attempt(entry_owner,' \
	'vmm_startup_entry_owner_guard_after(entry_owner,' \
	'vmx_run_nested(vcpu, rip, pmap, evinfo,' \
	'return (EOPNOTSUPP);'; do
	rg -q -F "$contract" "$vmx_source" ||
		fail "ordinary VMX startup-owner conversion omits: $contract"
done
rg -q -U --pcre2 \
	'vmx_run\(void \*vcpui,[\s\S]*?vmx_pmap_activate\(vmx, pmap\);[\s\S]*?vcpu_startup_entry_owner_guard_before_attempt\(vcpu->vcpu,[\s\S]*?if \(error != 0 \|\| owner_runtime.action !=[\s\S]*?vmx_pmap_deactivate\(vmx, pmap\);[\s\S]*?vmx_dr_leave_guest\(vmxctx\);[\s\S]*?vmx_msr_guest_exit_tsc_aux\(vmx, vcpu\);[\s\S]*?bare_lgdt\(&gdtr\);[\s\S]*?lidt\(&idtr\);[\s\S]*?lldt\(ldt_sel\);[\s\S]*?enable_intr\(\);[\s\S]*?vmm_startup_entry_owner_resolve_deferred\(entry_owner,[\s\S]*?break;[\s\S]*?vmx_enter_guest\(vmxctx, vmx, launched\);[\s\S]*?if \(rc == VMX_GUEST_VMEXIT\) \{[\s\S]*?vmm_startup_entry_owner_commit_attempt\(entry_owner\)[\s\S]*?\} else \{[\s\S]*?vmx_exit_inst_error\(vmxctx, rc, vmexit\);[\s\S]*?vmm_startup_entry_owner_abort_attempt\(entry_owner,[\s\S]*?if \(rc == VMX_GUEST_VMEXIT && entry_owner != NULL &&[\s\S]*?vmm_startup_entry_owner_guard_after\(entry_owner,' \
	"$vmx_source" ||
	fail "ordinary VMX owner guard/cleanup is not ordered around VM entry"
rg -q -U --pcre2 \
	'vmx_exit_inst_error\(vmxctx, rc, vmexit\);[\s\S]*?vmm_startup_entry_owner_abort_attempt\(entry_owner,[\s\S]*?if \(rc == VMX_GUEST_VMEXIT\)\s*launched = 1;' \
	"$vmx_source" ||
	fail "ordinary VMX instruction failure can incorrectly mark VMLAUNCH complete"
rg -q 'NVMX-EVENT-169.*attempted-entry guard' "$ledger" ||
	fail "ordinary VMX attempted-entry requirement is missing"
rg -q 'NVMX-PRIVATE-272.*ordinary-VMX-attempted-entry-owner' \
	"$private_ledger" ||
	fail "ordinary VMX attempted-entry private contract is missing"
rg -q -U --pcre2 \
	'bool owner_guard_declined;[\s\S]*?owner_guard_declined = false;[\s\S]*?owner_guard_declined = true;[\s\S]*?if \(!owner_guard_declined &&[\s\S]*?Mismatch between handled' \
	"$vmx_source" ||
	fail "ordinary VMX no-entry owner result can reach the legacy VM-exit assertion"
owner_phase_writers=$(rg -l \
    '\.phase[[:space:]]*=[[:space:]]*VMM_STARTUP_ENTRY_OWNER_' \
    "$src/sys" | sort)
[ "$owner_phase_writers" = "$startup_entry_owner_source" ] ||
    fail "startup entry-owner phase is mutated outside its private owner"
rg -q 'NVMX-EVENT-137.*Compound startup cleanup admission' "$ledger" ||
    fail "compound startup admission requirement is missing"
rg -q 'NVMX-PRIVATE-199.*compound-startup-provider-admission' \
    "$private_ledger" || fail "compound startup admission contract is missing"
rg -q 'NVMX-EVENT-138.*Preparation and release blocker dispatch semantics' \
    "$ledger" ||
    fail "startup preparation blocker requirement is missing"
rg -q 'NVMX-PRIVATE-200.*startup-preparation-retained-result' \
    "$private_ledger" || fail "startup preparation result contract is missing"
# private-test: bitmap-and-ept-provider-ownership
for contract in \
    'struct vmx_nested_memory memory_snapshot;' \
    'memory_snapshot = *memory;' \
    'memory = &memory_snapshot;'; do
	[ "$(rg -c -F "$contract" "$bitmap_source")" -ge 2 ] ||
	    fail "compound bitmap provider snapshots omit: $contract"
done
for contract in \
    'struct vmx_nested_ept_cache_ops ops;' \
    'cache->ops = *ops;' \
    'cache->ops.create(cache->arg, key, &root);' \
    'cache->ops.invalidate(cache->arg,' \
    'cache->ops.destroy(cache->arg,'; do
	rg -q -F "$contract" "$ept_cache_source" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_ept_cache.h" ||
	    fail "EPT cache provider ownership omits: $contract"
done
for contract in \
    'bytes.mutable_memory = &memory;' \
    'bytes.mutate_provider_table = true;' \
    'memory->mutable_memory->read = NULL;' \
    'ops.create = NULL;' \
    'ATF_CHECK(cache.ops.create == test_ept_cache_create);'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "bitmap/EPT provider ownership tests omit: $contract"
done
rg -q 'NVMX-EVENT-134.*Stable bitmap and EPT-cache providers' "$ledger" ||
    fail "bitmap/EPT provider requirement is missing"
rg -q 'NVMX-PRIVATE-195.*bitmap-and-EPT-provider-ownership' \
    "$private_ledger" || fail "bitmap/EPT provider private contract is missing"
# private-test: startup-dispatch-callback-ownership
for contract in nvmxsd_ops_valid nvmxsd_ops_equal; do
	rg -q -F "$contract" "$startup_dispatch_source" ||
	    fail "startup dispatch callback ownership contract is missing: $contract"
done
for callback in claim_begin claim_check claim_abort derive prepare_l0 apply_l0 \
    commit_active_l2 claim_finish; do
	rg -q -F "$callback" "$startup_dispatch_source" ||
	    fail "startup dispatch completeness omits callback: $callback"
done
rg -q -F 'if (error == EAGAIN || error == EBUSY)' \
    "$startup_dispatch_source" ||
    fail "startup preparation EBUSY is not reported as retained"
for contract in \
    'context.transaction.prepare_error = EBUSY;' \
	'context.transaction.release_error = EBUSY;' \
    'context.transaction.apply_calls, apply_calls + 1'; do
	rg -q -F "$contract" "$test_source" ||
	    fail "startup preparation retained-retry coverage omits: $contract"
done
rg -q -F 'Every retained path must be releasable before claim_begin is called' \
    "$test_source" ||
    fail "startup dispatch lacks incomplete-callback negative coverage"
rg -q -F 'Callback identities are immutable for the durable owner' \
    "$test_source" ||
    fail "startup dispatch lacks callback-mutation negative coverage"
rg -q -F 'A side-effect callback cannot redirect the later release callback' \
    "$test_source" ||
    fail "startup dispatch lacks compound callback-substitution coverage"
if [ "$(rg -c -F '&ops_before.transaction' "$startup_dispatch_source")" -lt 3 ]; then
	fail "startup dispatch does not use captured callbacks for compound release"
fi
rg -q 'NVMX-EVENT-093.*Durable startup callback completeness and identity' \
    "$ledger" || fail "startup dispatch callback ownership requirement is missing"
rg -q 'NVMX-EVENT-093.*complete eight-function.*L0-prepare.*L0-apply' \
    "$ledger" || fail "startup dispatch requirement has a stale callback count"
rg -q 'NVMX-PRIVATE-149.*complete-immutable-callback-owner' \
    "$private_ledger" || fail "startup dispatch callback private contract is missing"
rg -q 'NVMX-PRIVATE-149.*named-eight-function-callback-set' \
    "$private_ledger" || fail "startup dispatch private callback count is stale"
rg -q 'NVMX-EVENT-094.*Immutable compound startup callback execution' \
    "$ledger" || fail "startup dispatch compound callback requirement is missing"
rg -q 'NVMX-PRIVATE-150.*captured-compound-callback-set' \
    "$private_ledger" || fail "startup dispatch compound callback contract is missing"
rg -q -U --pcre2 \
    'vmm_event_coordinator_lock_entries\(coordinator, checkpoint_instances,[\s\S]*?startup\.pending !=[\s\S]*?error = EBUSY;[\s\S]*?vmm_event_owner_allocate\(&checkpoint_owner_id\)[\s\S]*?vmm_event_checkpoint_begin\(' \
    "$event_coordinator_source" ||
    fail "checkpoint owner is allocated before locked startup-event preflight"
rg -q -F '"vmm event owner", MTX_SPIN' "$event_coordinator_source" ||
    fail "checkpoint owner allocator can sleep below startup spin owners"
rg -q 'NVMX-EVENT-032.*startup-event-coordinator-ownership' "$ledger" ||
    fail "startup-event coordinator ownership is absent from the ledger"
rg -q 'NVMX-PRIVATE-090.*startup-event-coordinator-ownership' \
    "$private_ledger" ||
    fail "startup-event coordinator ownership is absent from the private ledger"

# private-test: event-checkpoint-group-value-protocol
for symbol in \
    vmm_event_checkpoint_begin \
    vmm_event_checkpoint_ready \
    vmm_event_checkpoint_finish \
    vmm_event_checkpoint_abort; do
	rg -q -F "$symbol" "$event_checkpoint_source" \
	    "$event_checkpoint_header" ||
	    fail "event-checkpoint group protocol is missing: $symbol"
done
for contract in \
    'checkpoint->storage_cookie != (uintptr_t)checkpoint' \
    'checkpoint->entries_cookie != (uintptr_t)checkpoint->entries' \
    'entries[i].state->last_lease_id == UINT64_MAX' \
    'entries[i].state->publisher_generation == UINT64_MAX' \
    'entry->state->active_publishers == 0' \
    'entry->state->publisher_generation == UINT64_MAX'; do
	rg -q -F "$contract" "$event_checkpoint_source" ||
	    fail "event-checkpoint ownership boundary is missing: $contract"
done
rg -q -F '<dev/vmm/vmm_address_range.h>' "$event_checkpoint_source" ||
    fail "event-checkpoint does not use the common address-range contract"
for contract in \
    'vmm_address_range_valid' \
    'vmm_address_ranges_overlap' \
    'length > (size_t)limit' \
    'right_start - left_start <= left_extent'; do
	rg -q -F "$contract" "$address_range_header" ||
	    fail "common address-range contract is incomplete: $contract"
done
# Portable callers must share the same range contract.  This prevents the
# checkpoint, startup, and event paths from silently diverging on address
# wrapping or future size_t/uintptr_t-width combinations.
for range_user in \
    "$snapshot_envelope_source" \
    "$event_checkpoint_source" "$event_coordinator_source" \
    "$startup_handshake_source" "$startup_entry_owner_source" \
    "$startup_mode_source" "$startup_controller_source" \
    "$vmm_vm_source" "$event_wait_source" "$startup_source" \
    "$startup_request_source" "$ingress_source"; do
	rg -q -F '<dev/vmm/vmm_address_range.h>' "$range_user" ||
	    fail "$(basename "$range_user") bypasses common address-range validation"
	rg -q -F 'vmm_address_ranges_overlap' "$range_user" ||
	    fail "$(basename "$range_user") bypasses common address-range overlap"
done
# The amd64 startup adapters are private implementation detail, but their
# pointer-alias checks are not architecture-specific.  Keep their arithmetic
# in the portable helper too, so size_t/uintptr_t width changes cannot make
# the private paths disagree with the public checkpoint contract.
for range_user in \
    "$event_state_source" "$startup_execution_source" \
    "$startup_machine_source" "$startup_backend_source" \
    "$startup_finalizer_source"; do
	rg -q -F '"../../dev/vmm/vmm_address_range.h"' "$range_user" ||
	    fail "$(basename "$range_user") bypasses common private range validation"
	rg -q -F 'vmm_address_ranges_overlap' "$range_user" ||
	    fail "$(basename "$range_user") bypasses common private range overlap"
done
rg -q -F 'vmm_address_range_valid' "$event_state_source" ||
    fail "event-state range validation bypasses the common range contract"
for contract in \
    'vmm_event_ranges_overlap(wrapping, 3, bytes, 1)' \
    'vmm_event_ranges_overlap(bytes, 1, NULL, 1)'; do
	rg -q -F "$contract" "$event_test_source" ||
	    fail "event-state invalid-range alias test is missing: $contract"
done
for contract in \
    '<dev/vmm/vmm_address_range.h>' \
    'vmm_address_range_valid(wrapping, 16)' \
    '!vmm_address_range_valid(wrapping, 17)' \
    'vmm_address_ranges_overlap(wrapping, 17, wire, 1)'; do
	rg -q -F "$contract" "$envelope_test_source" ||
	    fail "common address-range test is missing: $contract"
done
for test_case in group_lifecycle group_abort_draining \
    group_transactional_failures group_overflow_and_alias; do
	rg -q -F "$test_case" "$checkpoint_test_source" ||
	    fail "event-checkpoint group test is missing: $test_case"
done
rg -q -F 'vmm_event_checkpoint.c' "$module_makefile" ||
    fail "event-checkpoint protocol is not architecture-neutral VMM code"

# private-test: all-vcpu-state-rollback-identity
# A failed lock-all transition must thaw each vCPU named by the accumulated
# cpuset.  Reusing the loop's stale 'vcpu' pointer repeatedly targets the
# failure member and leaves earlier members frozen.
state_all_body=$(sed -n '/^vcpu_set_state_all(struct vm \*vm,/,/^}/p' \
    "$src/sys/dev/vmm/vmm_vm.c")
for contract in \
    'CPU_FOREACH_ISSET(rollback_id, &locked)' \
    'rollback_vcpu = vm_vcpu(vm, rollback_id)' \
    'vcpu_set_state(rollback_vcpu,'; do
	printf '%s\n' "$state_all_body" | rg -q -F "$contract" ||
	    fail "all-vCPU rollback lost exact member identity: $contract"
done
if printf '%s\n' "$state_all_body" |
    rg -U -q 'CPU_FOREACH_ISSET\([^\n]+\n[[:space:]]*\(void\)vcpu_set_state\(vcpu,'; then
	fail "all-vCPU rollback reuses the failed iteration vCPU"
fi
printf '%s\n' "$state_all_body" | rg -q -U --pcre2 \
    'rollback_vcpu = vm_vcpu\(vm, rollback_id\);[\s\S]*?if \(rollback_vcpu == NULL\)[\s\S]*?panic\("%s: missing locked vCPU %d"[\s\S]*?rollback_error = vcpu_set_state\(rollback_vcpu,[[:space:]]*VCPU_IDLE, false\);[\s\S]*?if \(rollback_error != 0\)[\s\S]*?panic\("%s: failed to roll back vCPU %d: %d"' ||
    fail "all-vCPU rollback integrity checks disappear without INVARIANTS"
if printf '%s\n' "$state_all_body" | rg -q -U --pcre2 \
    'KASSERT\((rollback_vcpu != NULL|rollback_error == 0)|\(void\)rollback_error'; then
	fail "all-vCPU rollback still relies on diagnostic-only error handling"
fi

# private-test: vm-destroy-freeze-barrier
rg -q -U --pcre2 \
    'vm_disable_vcpu_creation\(sc->vm\);[\s\S]*?error = vcpu_lock_all\(sc\);[\s\S]*?if \(error != 0\)[[:space:]]*panic\("%s: error %d freezing vcpus", __func__, error\);[\s\S]*?vm_unlock_vcpus\(sc->vm\);[\s\S]*?vm_destroy\(sc->vm\);' \
    "$vmm_dev_source" ||
    fail "release-kernel VM destruction can continue after freeze failure"
if rg -q -U --pcre2 \
    'error = vcpu_lock_all\(sc\);[[:space:]]*KASSERT\(error == 0' \
    "$vmm_dev_source"; then
	fail "VM destruction freeze barrier still depends on INVARIANTS"
fi
rg -q -F 'vmm_dev.c:destruction-freeze-fail-stop' "$private_ledger" ||
    fail "VM destruction freeze fail-stop policy is absent from the private ledger"

# private-test: vm-destroy-owner-integrity
destroy_body=$(sed -n '/^vmmdev_destroy(struct vmmdev_softc \*sc)/,/^}/p' \
    "$vmm_dev_source")
for contract in \
    'if (sc->cdev != NULL)' \
    'panic("%s: cdev not free", __func__)' \
    'if (sc->ucred == NULL)' \
    'panic("%s: missing ucred", __func__)' \
    'if (dsc->cdev == NULL)' \
    'panic("%s: devmem cdev already destroyed", __func__)' \
    'if (dsc->cdev != NULL)' \
    'panic("%s: devmem not free", __func__)'; do
	printf '%s\n' "$destroy_body" | rg -q -F "$contract" ||
	    fail "release-kernel VMM device teardown lacks owner check: $contract"
done
if printf '%s\n' "$destroy_body" | rg -q -U --pcre2 \
    'KASSERT\([^\n]*(sc->cdev|sc->ucred|dsc->cdev)'; then
	fail "VMM device teardown ownership still depends on INVARIANTS"
fi
rg -q -F 'vmm_dev.c:destruction-cdev-owner-fail-stop' "$private_ledger" ||
    fail "VMM device destruction owner policy is absent from the private ledger"

# private-test: event-driven-checkpoint-wait
# private-test: generation-bound-wake-predicate-replay
# The sleepqueue chain lock is the publication/enqueue interlock.  The waiter
# must recheck the exact generation-bound ticket while holding it, and the
# publisher must update and broadcast while holding the same chain lock.
for symbol in \
    vmm_event_wait_prepare_locked \
    vmm_event_wait_changed_locked \
    vmm_event_wait_wake_result_locked \
    vmm_event_wait_signal_locked \
    vmm_event_wait_cancel_locked \
    vmm_event_wait_prepare \
    vmm_event_wait_signal \
    vmm_event_wait_cancel \
    vmm_event_wait_sleep \
    vmm_event_wait_drain; do
	rg -q -F "$symbol" "$event_wait_source" "$event_wait_header" ||
	    fail "event-driven wait protocol is missing: $symbol"
done
for contract in \
    'state->storage_cookie != (uintptr_t)state' \
    'state->waiters == UINT32_MAX' \
    'ticket->state_cookie != (uintptr_t)state' \
    'ticket->storage_cookie != (uintptr_t)ticket' \
    'sleepq_lock(state)' \
    'vmm_event_wait_changed_locked(state, ticket, &changed)' \
    'sleepq_add(state, NULL, wmesg, SLEEPQ_SLEEP | SLEEPQ_INTERRUPTIBLE' \
    'DROP_GIANT()' \
    'sleepq_wait_sig(state, pri)' \
    'PICKUP_GIANT()' \
    'sleepq_broadcast(state, SLEEPQ_SLEEP, 0, 0)'; do
	rg -q -F "$contract" "$event_wait_source" ||
	    fail "event-driven wait ownership/interlock is missing: $contract"
done
sleep_body=$(sed -n '/^vmm_event_wait_sleep(/,/^vmm_event_wait_drain(/p' \
    "$event_wait_source")
printf '%s\n' "$sleep_body" | rg -q -F '(pri & ~PRIMASK) != 0' ||
	fail "raw interruptible wait accepts _sleep-only priority flags"
drain_body=$(sed -n '/^vmm_event_wait_drain(/,$p' "$event_wait_source")
printf '%s\n' "$drain_body" | rg -q -F '(pri & ~PRIMASK) != 0' ||
	fail "raw waiter drain accepts _sleep-only priority flags"
rg -q -U --pcre2 \
    'vmm_event_coordinator_checkpoint_wait_ready\([\s\S]*?"vmsess", 0\);' \
    "$vmm_dev_source" ||
	fail "snapshot readiness passes _sleep-only flags to a raw sleepqueue wait"
rg -q 'NVMX-EVENT-071.*Raw sleepqueue priority discipline' "$ledger" ||
	fail "raw sleepqueue priority discipline is absent from the ledger"
rg -q 'NVMX-PRIVATE-127.*raw-sleepqueue-priority-discipline' \
    "$private_ledger" ||
	fail "raw sleepqueue private priority policy is absent from the ledger"
rg -q -U --pcre2 \
    'sleepq_add\(state,[\s\S]*?DROP_GIANT\(\);[\s\S]*?sleepq_wait_sig\(state, pri\);[\s\S]*?PICKUP_GIANT\(\);' \
    "$event_wait_source" ||
    fail "event-driven interruptible wait does not preserve Giant ordering"
rg -q -U --pcre2 \
    'sleep_error = sleepq_wait_sig\(state, pri\);[\s\S]*?sleepq_lock\(state\);[\s\S]*?state->waiters--;[\s\S]*?vmm_event_wait_wake_result_locked\(state, ticket, error\);' \
    "$event_wait_source" ||
    fail "ordinary event wake can bypass the generation-bound predicate recheck"
rg -q -U --pcre2 \
    'vmm_event_wait_drain\([\s\S]*?state->cancelled == 0[\s\S]*?while \(state->waiters != 0\)[\s\S]*?sleepq_add\(state,[\s\S]*?sleepq_wait\(state, pri\)' \
    "$event_wait_source" ||
    fail "event-wait teardown lacks cancellation-bound waiter drain"
rg -q -U --pcre2 \
    'state->waiters--;[\s\S]*?state->cancelled != 0 && state->waiters == 0[\s\S]*?sleepq_broadcast\(state' \
    "$event_wait_source" ||
    fail "last event waiter does not wake lifecycle drain"
if rg -q 'pause|DELAY|msleep_spin|sleepq_set_timeout' "$event_wait_source"; then
	fail "event-driven checkpoint wait contains polling or a timed retry"
fi
for test_case in generation_lifecycle cancel_and_overflow \
    exact_storage_identity transactional_rejection \
    post_wake_always_replays_predicate; do
	rg -q -F "$test_case" "$wait_test_source" ||
	    fail "event-wait value test is missing: $test_case"
done
rg -q -F 'vmm_event_wait.c' "$module_makefile" ||
    fail "event-wait protocol is not architecture-neutral VMM code"
rg -q 'NVMX-EVENT-063.*Generation-bound wake predicate replay' "$ledger" ||
    fail "generation-bound wake predicate replay is absent from the ledger"
rg -q 'NVMX-PRIVATE-119.*sleepqueue-wake-is-not-predicate-success' \
    "$private_ledger" ||
    fail "sleepqueue wake contract is absent from the private ledger"

# private-test: event-checkpoint-coordinator
# Kernel orchestration retains transaction membership independently of the
# value record because finish/abort deliberately consume and zero that record.
# VM pointer stability remains the enclosing lifecycle owner's responsibility.
for symbol in \
    vmm_event_coordinator_create \
    vmm_event_coordinator_publisher_enter \
    vmm_event_coordinator_publisher_exit \
    vmm_event_coordinator_publisher_enter_or_defer \
    vmm_event_coordinator_checkpoint_begin \
    vmm_event_coordinator_checkpoint_wait_ready \
    vmm_event_coordinator_checkpoint_finish \
    vmm_event_coordinator_checkpoint_abort \
    vmm_event_coordinator_cancel \
    vmm_event_coordinator_drain \
    vmm_event_coordinator_drain_publishers \
    vmm_event_coordinator_destroy; do
	rg -q -F "$symbol" "$event_coordinator_source" \
	    "$event_coordinator_header" ||
	    fail "event coordinator operation is missing: $symbol"
done
for contract in \
    'vmm_event_owner_allocate(&checkpoint_owner_id)' \
    'vmm_event_coordinator_checkpoint_instances(coordinator)' \
    'memcpy(checkpoint_instances, instances, instances_length)' \
    'vmm_event_coordinator_instances_validate(coordinator,' \
    'coordinator->checkpoint_count = count' \
    'entry->ingress.mode == VMM_EVENT_INGRESS_OPEN' \
    'vmm_event_ingress_defer_idempotent(&entry->ingress' \
    'vmm_event_coordinator_lock_checkpoint(coordinator, checkpoint)' \
    'vmm_event_checkpoint_finish(checkpoint)' \
    'vmm_event_coordinator_unlock_checkpoint(coordinator, checkpoint)' \
    'atomic_store_rel_int(&coordinator->cancelled, 1)' \
    'vmm_event_wait_drain(&coordinator->wait, wmesg, pri)' \
    'The enclosing VM lifetime is the pointer-stability authority' \
    'kernel programming interface; consumers must remain inside vmm(4)'; do
	rg -q -F "$contract" "$event_coordinator_source" \
	    "$event_coordinator_header" ||
	    fail "event coordinator ownership contract is missing: $contract"
done
rg -q -U --pcre2 \
    'vmm_event_checkpoint_(abort|finish)\(checkpoint\);[\s\S]*?vmm_event_coordinator_unlock_checkpoint\(coordinator, checkpoint\)' \
    "$event_coordinator_source" ||
    fail "event coordinator does not unlock retained membership after reopen"
if rg -q 'pause\(|DELAY\(|sleepq_set_timeout|msleep_sbt|callout_reset' \
    "$event_coordinator_source"; then
	fail "event coordinator contains polling or timed progress"
fi
rg -q -U --pcre2 \
    'sleepq_lock\(coordinator\);[[:space:]]*for \(;;\) \{[[:space:]]*error = 0;[[:space:]]*drained = true;[\s\S]*?if \(error != 0 \|\| drained\)' \
    "$event_coordinator_source" ||
    fail "publisher drain can inspect an uninitialized scan result"
rg -q -F 'vmm_event_coordinator.c' "$module_makefile" ||
    fail "event coordinator is not architecture-neutral VMM code"

# private-test: event-coordinator-vm-lifecycle
# One common coordinator is created before memory publication on every VMM
# architecture, reset errors remain recoverable, and destroy closes admission
# before an event-driven publisher/waiter drain.  The coordinator-address
# sleepqueue interlocks the publisher predicate with the exit broadcast.
for contract in \
    'int vm_event_coordinator_init(struct vm *vm, u_int maxcpus);' \
    'int vm_event_coordinator_reset(struct vm *vm);' \
    'void vm_event_coordinator_cleanup(struct vm *vm);' \
    'struct vmm_event_coordinator *event_coordinator'; do
	rg -q -F "$contract" "$src/sys/dev/vmm/vmm_vm.h" ||
	    fail "common VM coordinator lifecycle contract is missing: $contract"
done
for contract in \
    'error = vmm_event_coordinator_cancel(vm->event_coordinator)' \
    'vmm_event_coordinator_drain_publishers(' \
    'vmm_event_coordinator_drain(vm->event_coordinator' \
    'error = vmm_event_coordinator_reset(vm->event_coordinator)' \
    'error = vm_reset(vm)'; do
	rg -q -F "$contract" "$src/sys/dev/vmm/vmm_vm.c" ||
	    fail "common VM coordinator lifecycle ordering is missing: $contract"
done
rg -q -U --pcre2 \
    'vmm_event_wait_init\(&coordinator->wait, owner_id\);[\s\S]*?if \(error != 0\)[[:space:]]*panic\("%s: wait initialization failed: %d"[\s\S]*?vmm_event_ingress_init\(&coordinator->entry\[i\]\.ingress,[[:space:]]*owner_id\);[\s\S]*?if \(error != 0\)[[:space:]]*panic\("%s: ingress initialization failed: %d"' \
    "$event_coordinator_source" ||
    fail "release kernel can publish a partially initialized event coordinator"
if rg -q -U --pcre2 \
    'vmm_event_(wait|ingress)_init\([^;]+;[[:space:]]*KASSERT\(error == 0' \
    "$event_coordinator_source"; then
	fail "event coordinator construction still depends on INVARIANTS"
fi
for architecture in amd64 arm64 riscv; do
	architecture_vmm="$src/sys/$architecture/vmm/vmm.c"
	rg -q -U --pcre2 \
	    'vm_event_coordinator_init\(vm, vm_maxcpu\);[\s\S]*?vm_mem_init' \
	    "$architecture_vmm" ||
	    fail "$architecture coordinator is not created before VM memory"
	rg -q -U --pcre2 \
	    'vm_destroy\(struct vm \*vm\)[\s\S]*?vm_event_coordinator_cleanup\(vm\);[\s\S]*?vm_cleanup\(vm, true\)' \
	    "$architecture_vmm" ||
	    fail "$architecture coordinator is not destroyed before VM storage"
	rg -q -U --pcre2 \
	    'int[\s\n]+vm_reset\(struct vm \*vm\)[\s\S]*?vm_event_coordinator_reset\(vm\);[\s\S]*?if \(error != 0\)[\s\S]*?return \(error\);[\s\S]*?vm_cleanup\(vm, false\)' \
	    "$architecture_vmm" ||
	    fail "$architecture reset cannot reject a busy coordinator transactionally"
done
for contract in \
    'sleepq_lock(coordinator)' \
    'coordinator->entry[i].ingress.active_publishers != 0' \
    'sleepq_add(coordinator, NULL, wmesg, SLEEPQ_SLEEP, 0)' \
    'sleepq_wait(coordinator, pri)' \
    'sleepq_broadcast(coordinator, SLEEPQ_SLEEP, 0, 0)'; do
	rg -q -F "$contract" "$event_coordinator_source" ||
	    fail "publisher teardown interlock is missing: $contract"
done
if rg -q 'pause\(|DELAY\(|sleepq_set_timeout|msleep_sbt|callout_reset' \
    "$event_coordinator_source"; then
	fail "VM coordinator lifecycle contains polling or a timed retry"
fi

# private-test: event-coordinator-deferred-merge
# Deferred bits are transient architecture-adapter values.  They must be
# merged under the same retained ingress locks before admission is visible,
# and successful consumption must leave reusable zeroed caller credentials.
for contract in \
    'typedef void vmm_event_deferred_apply_t(void *, uint16_t, uint64_t)' \
    'entries[i].state->deferred_mask != 0' \
    'apply(apply_arg, (uint16_t)instances[i]' \
    'explicit_bzero(entries, count * sizeof(*entries))' \
    'vmm_event_coordinator_unlock_checkpoint(coordinator, checkpoint)'; do
	rg -q -F "$contract" "$event_coordinator_source" \
	    "$event_coordinator_header" ||
	    fail "deferred event merge transaction is missing: $contract"
done
rg -q -U --pcre2 \
    'vmm_event_coordinator_lock_checkpoint\(coordinator, checkpoint\);[\s\S]*?vmm_event_checkpoint_(?:abort|finish)\(checkpoint\);[\s\S]*?apply\(apply_arg,[\s\S]*?explicit_bzero\(entries,[\s\S]*?vmm_event_coordinator_unlock_checkpoint\(coordinator, checkpoint\);' \
    "$event_coordinator_source" ||
    fail "deferred events are not merged and consumed under retained locks"
[ -f "$ingress_callers" ] ||
    fail "event-ingress caller/context inventory is missing"
header=$(awk 'NR == 1 { print; exit }' "$ingress_callers")
case "$header" in
"id	owner-operation	production-entry-or-caller	execution-context"*) ;;
*) fail "event-ingress caller/context inventory header is invalid" ;;
esac
for contract in \
    vm_exit_intinfo vm_inject_exception_class vm_inject_nmi vm_inject_extint \
    vm_entry_intinfo_commit vm_nmi_clear vm_extint_clear vcpu_init \
    vm_event_state_restore vm_event_state_capture_all \
    vm_snapshot_x86_restore_plan_commit \
    vmm_event_ingress_quiesce_finish; do
	rg -q -F "$contract" "$ingress_callers" ||
	    fail "event-ingress caller/context inventory is incomplete: $contract"
done
[ "$(awk -F '\t' 'NR > 1 && $8 == "adapter-pending" { n++ } END { print n + 0 }' \
    "$ingress_callers")" -eq 3 ] ||
    fail "event-ingress inventory must retain exactly the three unwired consumer/lifecycle adapters"
[ "$(awk -F '\t' 'NR > 1 && $8 ~ /^adapter-wired-pending/ { n++ } END { print n + 0 }' \
    "$ingress_callers")" -ge 6 ] ||
    fail "event-ingress inventory does not record all wired publisher/merge adapters"

# private-test: amd64-event-publisher-admission
# These are the first production users of the common admission owner.  Keep
# non-idempotent owners on exact tickets and idempotent NMI/ExtINT on a private
# transient bit domain.  Notification must occur only after ticket release.
for contract in \
    'VM_EVENT_DEFERRED_VALID' \
    'vmm_event_coordinator_publisher_enter(' \
    'vmm_event_coordinator_publisher_enter_or_defer(' \
    'vm_event_publisher_exit_checked(vcpu, &ticket)'; do
	rg -q -F "$contract" "$vmm_source" ||
	    fail "amd64 event publisher adapter is missing: $contract"
done
rg -q 'VM_EVENT_DEFERRED_NMI[[:space:]]+UINT64_C\(1\)' "$vmm_source" ||
    fail "amd64 deferred NMI bit changed without private-policy review"
rg -q 'VM_EVENT_DEFERRED_EXTINT[[:space:]]+UINT64_C\(2\)' "$vmm_source" ||
    fail "amd64 deferred ExtINT bit changed without private-policy review"
for operation in vm_exit_intinfo vm_inject_exception_class \
    vm_event_state_restore; do
	publisher_body=$(sed -n "/^$operation(/,/^}/p" "$vmm_source")
	printf '%s\n' "$publisher_body" | rg -q -F \
	    'vmm_event_coordinator_publisher_enter(' ||
	    fail "$operation does not acquire a non-idempotent publisher ticket"
	printf '%s\n' "$publisher_body" | rg -q -F \
	    'vm_event_publisher_exit_checked(vcpu, &ticket)' ||
	    fail "$operation is not covered by a non-idempotent publisher ticket"
done
for operation in vm_inject_nmi vm_inject_extint; do
	publisher_body=$(sed -n "/^$operation(/,/^}/p" "$vmm_source")
	printf '%s\n' "$publisher_body" | rg -q -U --pcre2 \
	    'vmm_event_coordinator_publisher_enter_or_defer\([\s\S]*?if \(error != 0 \|\| deferred\)[\s\S]*?return \(error\);[\s\S]*?vm_event_publisher_exit_checked\(vcpu, &ticket\);[\s\S]*?vcpu_notify_event\(vcpu\);' ||
	    fail "$operation does not defer atomically or release before notification"
done
publisher_body=$(sed -n '/^vm_inject_exception_class(/,/^}/p' "$vmm_source")
printf '%s\n' "$publisher_body" | rg -q -U --pcre2 \
    'exception_injecting = 1;[\s\S]*?vm_set_register\(vcpu, VM_REG_GUEST_INTR_SHADOW[\s\S]*?exception_pending = 1;[\s\S]*?vm_event_publisher_exit_checked\(vcpu, &ticket\);[\s\S]*?abort:[\s\S]*?exception_injecting = 0;[\s\S]*?vm_event_publisher_exit_checked\(vcpu, &ticket\);' ||
    fail "exception publisher ticket does not span reserve publish and rollback"
rg -q -F 'vmm.c:amd64-deferred-NMI-ExtINT-bits' "$private_ledger" ||
    fail "amd64 deferred event bit domain is absent from the private ledger"
for private_owner in \
    'vmm.c:event-publisher-credential-fail-stop' \
    'vmm.c:event-publication-during-checkpoint'; do
	rg -q -F "$private_owner" "$private_ledger" ||
	    fail "amd64 event publication policy is absent from the private ledger: $private_owner"
done
rg -q -U --pcre2 \
    'vm_event_publisher_exit_checked\([\s\S]*?vmm_event_coordinator_publisher_exit\([\s\S]*?if \(error != 0\)[\s\S]*?panic\("%s: lost event publisher credential:' \
    "$vmm_source" ||
    fail "lost kernel event publisher credentials do not fail stop"

# private-test: event-coordinator-topology-boundary
rg -q -U --pcre2 \
    'vm_event_coordinator_init\(struct vm \*vm, u_int maxcpus\)[\s\S]*?maxcpus == 0 \|\| maxcpus > UINT16_MAX[\s\S]*?vm->maxcpus != 0[\s\S]*?error = vmm_event_coordinator_create\(\(uint16_t\)maxcpus,[\s\S]*?if \(error != 0\)[\s\S]*?return \(error\);[\s\S]*?CPU_ZERO\(&vm->startup_cpus\);[\s\S]*?vm->maxcpus = \(uint16_t\)maxcpus;' \
    "$src/sys/dev/vmm/vmm_vm.c" ||
    fail "common event coordinator does not publish topology only after creation"
for arch_source in \
    "$src/sys/amd64/vmm/vmm.c" \
    "$src/sys/arm64/vmm/vmm.c" \
    "$src/sys/riscv/vmm/vmm.c"; do
	rg -q -F 'vm_event_coordinator_init(vm, vm_maxcpu)' "$arch_source" ||
	    fail "architecture constructor does not pass the original topology limit: $arch_source"
	if rg -q -F 'vm->maxcpus = vm_maxcpu' "$arch_source"; then
		fail "architecture constructor narrows maxcpus before validation: $arch_source"
	fi
done
# The arm64 and riscv VMM implementations compile the portable coordinator
# and startup helpers.  The x86-only readiness operation is selected by the
# amd64 branch in vmm_vm.c; every other architecture fails closed.  Keep the
# non-x86 kernel configuration manifests in
# lock step with the module Makefile: otherwise an arm64 or riscv VMM kernel
# can compile a portable helper caller yet omit its common definition at link
# time.
for arch_files in "$arm64_files" "$riscv_files"; do
	for common_source in \
	    vmm_event_checkpoint.c \
	    vmm_event_coordinator.c \
	    vmm_event_ingress.c \
	    vmm_startup_event.c \
	    vmm_startup_mode.c \
	    vmm_startup_entry_owner.c \
	    vmm_startup_handshake.c \
	    vmm_startup_controller.c \
	    vmm_startup_request.c \
	    vmm_startup_run_request.c \
	    vmm_event_wait.c; do
		rg -q -F "dev/vmm/$common_source" "$arch_files" ||
		    fail "portable VMM source $common_source is absent from $arch_files"
	done
done
rg -q -F 'vmm_vm.c:event-coordinator-topology-narrowing' "$private_ledger" ||
    fail "coordinator topology narrowing is absent from the private ledger"

# private-test: event-coordinator-membership-bound
rg -q -U --pcre2 \
    'vmm_event_coordinator_instances_validate\([\s\S]*?count == 0 \|\| count > coordinator->maxcpus \|\|[\s\S]*?vmm_event_coordinator_range' \
    "$event_coordinator_source" ||
    fail "event coordinator membership validator lacks its destination capacity bound"
rg -q -U --pcre2 \
    'vmm_event_coordinator_validate\(coordinator\);[\s\S]*?count == 0 \|\| count > coordinator->maxcpus[\s\S]*?error = E2BIG;[\s\S]*?memcpy\(checkpoint_instances, instances, instances_length\)' \
    "$event_coordinator_source" ||
    fail "event coordinator copies group membership before checking fixed capacity"
rg -q -F 'vmm_event_coordinator.c:checkpoint-membership-capacity' \
    "$private_ledger" ||
    fail "event coordinator membership capacity is absent from the private ledger"

# private-test: event-coordinator-signal-composition
rg -q -U --pcre2 \
    'vmm_event_wait_signal_locked\([\s\S]*?state->generation >= UINT64_MAX - 1[\s\S]*?state->cancelled = 1;[\s\S]*?return \(EOVERFLOW\);' \
    "$event_wait_source" ||
    fail "wait signal can enter an unrepresentable terminal generation"
rg -q -U --pcre2 \
    'state\.generation = UINT64_MAX - 1;[\s\S]*?vmm_event_wait_prepare_locked\(&state, &ticket\), 0\);[\s\S]*?vmm_event_wait_signal_locked\(&state\), EOVERFLOW\);[\s\S]*?state\.generation, UINT64_MAX - 1\);[\s\S]*?state\.cancelled, 1\);' \
    "$wait_test_source" ||
    fail "penultimate wait-generation fail-closed boundary lacks a direct test"
rg -q -U --pcre2 \
    'vmm_event_coordinator_signal\([\s\S]*?vmm_event_wait_signal\(&coordinator->wait\);[\s\S]*?error == EOVERFLOW \|\| error == ECANCELED[\s\S]*?vmm_event_coordinator_fail_closed_locked\(coordinator\);[\s\S]*?else if \(error != 0\)[\s\S]*?panic\(' \
    "$event_coordinator_source" ||
    fail "coordinator and wait channel do not share one fail-closed signal domain"
for caller in \
    'error = vmm_event_coordinator_signal(coordinator)' \
    '(void)vmm_event_coordinator_signal(coordinator)'; do
	rg -q -F "$caller" "$event_coordinator_source" ||
	    fail "coordinator signal result policy is missing: $caller"
done
if rg -q -F '(void)vmm_event_wait_signal(&coordinator->wait)' \
    "$event_coordinator_source"; then
	fail "coordinator still discards a raw wait-signal result"
fi
rg -q -F 'vmm_event_coordinator.c:wait-signal-failure-domain' \
    "$private_ledger" ||
    fail "coordinator wait-signal failure domain is absent from the private ledger"

# private-test: event-wait-prepared-ticket-cleanup
rg -q -U --pcre2 \
    'vmm_event_coordinator_wait_ticket_release_required\([\s\S]*?vmm_event_wait_ticket_release\(ticket\);[\s\S]*?if \(error != 0\)[\s\S]*?panic\(' \
    "$event_coordinator_source" ||
    fail "required prepared wait-ticket cleanup does not fail stop"
for wait_function in \
    vmm_event_coordinator_startup_wait_ready \
    vmm_event_coordinator_startup_wait_committed \
    vmm_event_coordinator_checkpoint_wait_ready; do
	wait_body=$(sed -n "/^${wait_function}(/,/^}/p" \
	    "$event_coordinator_source")
	release_calls=$(printf '%s\n' "$wait_body" | rg -c \
	    'vmm_event_coordinator_wait_ticket_release_required\(')
	[ "$release_calls" -ge 2 ] ||
	    fail "$wait_function omits required prepared-ticket cleanup"
done
rg -q -F 'vmm_event_coordinator.c:prepared-wait-ticket-cleanup' \
    "$private_ledger" ||
    fail "prepared wait-ticket cleanup is absent from the private ledger"

# private-test: event-checkpoint-owner-allocation-preflight
python3 - "$event_coordinator_source" <<'PY' ||
import re
import sys

source = open(sys.argv[1], encoding="utf-8").read()
match = re.search(
    r"vmm_event_coordinator_checkpoint_begin\([^)]*\)\s*\{(?P<body>.*?)\n\}",
    source, re.S)
if match is None:
    raise SystemExit(1)
body = match.group("body")
allocation = body.find("vmm_event_owner_allocate(&checkpoint_owner_id)")
entry_preflight = body.find("entries[i].state != NULL")
entry_publish = body.find("entries[i].state =")
if min(allocation, entry_preflight, entry_publish) < 0:
    raise SystemExit(1)
if not entry_preflight < allocation < entry_publish:
    raise SystemExit(1)
PY
	fail "checkpoint owner ID is allocated before rejectable preflight"
rg -q -F 'vmm_event_coordinator.c:checkpoint-owner-allocation-preflight' \
    "$private_ledger" ||
    fail "checkpoint owner allocation preflight is absent from the private ledger"

# private-test: event-wait-accounting-fail-stop
rg -q -U --pcre2 \
    'sleepq_lock\(state\);[\s\S]*?if \(state->waiters == 0\)[\s\S]*?panic\("%s: missing registered waiter"[\s\S]*?state->waiters--;' \
    "$event_wait_source" ||
    fail "waiter accounting underflow is diagnostic-only"
if rg -q -U --pcre2 \
    'KASSERT\(state->waiters != 0[\s\S]{0,120}?state->waiters--' \
    "$event_wait_source"; then
	fail "release kernel can underflow the checkpoint waiter count"
fi
rg -q -F 'vmm_event_wait.c:waiter-accounting-fail-stop' \
    "$private_ledger" ||
    fail "waiter accounting fail-stop is absent from the private ledger"

# private-test: event-checkpoint-commit-fail-stop
for commit_message in \
    'prevalidated begin failed' \
    'prevalidated reopen failed'; do
	rg -q -F "panic(\"%s: $commit_message" "$event_checkpoint_source" ||
	    fail "event checkpoint commit invariant is recoverable: $commit_message"
done
rg -q -F 'vmm_event_checkpoint.c:group-commit-fail-stop' \
    "$private_ledger" ||
    fail "event checkpoint group commit invariant is absent from the private ledger"

# Pass-22 boundary: transient adapter bits and coordinator credentials must
# not escape into architectural headers or either snapshot codec.  The common
# coordinator declaration is kernel-only and explicitly not a stable KPI.
if rg -q 'VM_EVENT_DEFERRED_(NMI|EXTINT|VALID)' \
    "$src/sys/amd64/include" "$src/sys/dev/vmm/vmm_snapshot_envelope.c" \
    "$src/sys/amd64/vmm/vmm_snapshot_x86_state.c" \
    "$src/sys/amd64/vmm/vmm_snapshot_x86_transaction.c"; then
	fail "private deferred-event bits leaked into an ABI or snapshot codec"
fi
rg -q -F '#ifdef _KERNEL' "$event_coordinator_header" ||
    fail "event coordinator declarations escaped their kernel-only boundary"
rg -q -F 'None is a save-state, userspace ABI, or stable' \
    "$event_coordinator_header" ||
    fail "event coordinator transient-interface boundary is undocumented"
if rg -q 'event_coordinator|vmm_event_ingress_(ticket|lease)' \
    "$src/sys/dev/vmm/vmm_snapshot_envelope.c" \
    "$src/sys/amd64/vmm/vmm_snapshot_x86_state.c" \
    "$src/sys/amd64/vmm/vmm_snapshot_x86_transaction.c"; then
	fail "coordinator ownership credentials leaked into serialized state"
fi

# VM_SNAPSHOT_VALIDATE is a userspace codec operation.  Pin the kernel ABI
# guard as well as its unit predicate so an ioctl refactor cannot dispatch it
# into VM-wide nested restore staging.
rg -q -F '!vm_snapshot_op_is_kernel(meta->op)' "$vmm_source" ||
    fail "kernel snapshot ioctl operation guard is missing"

# private-test: current-struct-vm-vms2-only
# This project has no released checkpoint ABI.  STRUCT_VM therefore selects
# only the canonical VMS2 envelope; retaining a native-width fallback would
# create an obsolete compatibility path before the first release.
current_vm=$(sed -n '/^vm_snapshot_vm(struct vm \*vm,/,/^}/p' \
    "$vmm_source")
for contract in \
    'vm_snapshot_x86_capture_all(vm, stage, maxcpus,' \
    'vmm_snapshot_x86_transaction_encode(&transaction, stage,' \
    'vmm_snapshot_x86_transaction_decode(wire, length, stage,' \
    'vm_snapshot_x86_restore_plan_create(vm, &transaction, stage,' \
    'vm_snapshot_x86_restore_plan_commit(vm, plan)' \
    'length > written' \
    'explicit_bzero(wire, malloc_usable_size(wire))' \
    'explicit_bzero(stage, malloc_usable_size(stage))'; do
	printf '%s\n' "$current_vm" | rg -q -F "$contract" ||
	    fail "current STRUCT_VM VMS2 integration is missing: $contract"
done
if rg -q '^vm_snapshot_vcpus\(' "$vmm_source" ||
    printf '%s\n' "$current_vm" | rg -q \
    'SNAPSHOT_VAR_OR_LEAVE|vm_snapshot_common_restore|struct vm_exit'; then
	fail "obsolete native STRUCT_VM codec remains reachable"
fi

# private-test: vms2-transaction-encoder
# The current format must be constructed by an independently testable
# canonical encoder and must be the sole production STRUCT_VM selection.
for symbol in \
    vmm_snapshot_x86_transaction_size \
    vmm_snapshot_x86_transaction_encode \
    vmm_snapshot_envelope_builder_init \
    vmm_snapshot_vm_common_encode \
    vmm_snapshot_vcpu_common_encode \
    vmm_snapshot_vcpu_x86_encode; do
	rg -q -F "$symbol" "$transaction_source" ||
	    fail "VMS2 canonical encoder is missing $symbol"
done
for anchor in \
    'ATF_TC_WITHOUT_HEAD(x86_transaction_encode)' \
    'ATF_CHECK_EQ(length, 384 + 2 * (VMM_SNAPSHOT_SECTION_HEADER_SIZE +' \
	'memcmp(wire_roundtrip, wire, length)' \
    'wire, 383, &sentinel), E2BIG' \
    'memcmp(wire, before, sizeof(wire))'; do
	rg -q -F "$anchor" "$envelope_test_source" ||
	    fail "VMS2 independent encoder test is missing: $anchor"
done
rg -q -F 'vmm_snapshot_x86_transaction_encode(&transaction, stage,' \
    "$vmm_source" || fail "VMS2 production save selection is absent"
rg -q -F 'vmm_snapshot_x86_transaction_decode(wire, length, stage,' \
    "$vmm_source" || fail "VMS2 production restore selection is absent"

# private-test: destination-xcr0-restore-validation
# XCR0 is loaded by the kernel on the next vCPU entry.  A portable or legacy
# checkpoint must not be able to stage host-unsupported components or invalid
# architectural dependency combinations and reach load_xcr().
for contract in \
    'vmm_snapshot_x86_xcr0_validate(' \
    'stage_candidates[index].x86.guest_xcr0' \
    'xsave_limits->xcr0_allowed' \
    'xsave_limits->xsave_enabled != 0'; do
	rg -q -F "$contract" "$vmm_source" \
	    "$src/sys/amd64/vmm/vmm_snapshot_x86_state.c" ||
	    fail "destination XCR0 restore validation is missing: $contract"
done
for anchor in \
    'vmm_snapshot_x86_xcr0_validate(3, 3, false), EINVAL' \
    'vmm_snapshot_x86_xcr0_validate(5, UINT64_MAX, true)' \
    'vmm_snapshot_x86_xcr0_validate(0x27, UINT64_MAX, true)' \
    'vmm_snapshot_x86_xcr0_validate(0xe7, 0x7f, true)'; do
	rg -q -F "$anchor" "$envelope_test_source" ||
	    fail "destination XCR0 negative model is missing: $anchor"
done
rg -q 'NVMX-STATE-032.*destination XSAVE mask' "$ledger" ||
    fail "destination XCR0 restore validation is absent from the ledger"

# private-test: frozen-nested-checkpoint-no-wait
# All nested-VMX checkpoint save, reconstruction, and VM-wide publication
# happens while the coordinator has stopped the guest.  None of these paths
# may enter an unbounded allocator wait.  Parse complete function bodies so a
# later helper refactor cannot hide M_WAITOK beyond a line-oriented window.
if ! python3 - "$vmx_source" "$checkpoint_source" "$registry_source" \
    "$registry_state_source" "$test_source" <<'PY'
import pathlib
import re
import sys

vmx, checkpoint, registry, registry_state, tests = [
    pathlib.Path(path).read_text() for path in sys.argv[1:]
]

def function_body(source, name):
    match = re.search(r"(?:^|\n)(?:static\s+)?[^;\n]*\n?" +
        re.escape(name) + r"\s*\([^;]*?\)\s*\{", source, re.S)
    if match is None:
        raise SystemExit(f"missing function {name}")
    start = source.find("{", match.start())
    depth = 0
    state = "code"
    i = start
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if ch == '"':
                state = "string"
            elif ch == "'":
                state = "char"
            elif ch == "/" and nxt == "*":
                state = "block"
                i += 1
            elif ch == "/" and nxt == "/":
                state = "line"
                i += 1
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return source[start:i + 1]
        elif state == "string":
            if ch == "\\":
                i += 1
            elif ch == '"':
                state = "code"
        elif state == "char":
            if ch == "\\":
                i += 1
            elif ch == "'":
                state = "code"
        elif state == "block" and ch == "*" and nxt == "/":
            state = "code"
            i += 1
        elif state == "line" and ch == "\n":
            state = "code"
        i += 1
    raise SystemExit(f"unterminated function {name}")

for source, names in (
    (vmx, ("vmx_vm_snapshot", "vmx_vcpu_nested_snapshot",
           "vmx_vm_snapshot_complete")),
    (checkpoint, ("nvmxcp_fields_alloc",)),
    (registry_state, ("nvmxrs_fields_alloc",)),
):
    for name in names:
        body = function_body(source, name)
        if "M_WAITOK" in body or "M_NOWAIT" not in body:
            raise SystemExit(f"{name} is not wholly non-waiting")

restore_body = function_body(registry_state, "nvmxrs_restore")
if "vmx_nested_vmcs_registry_import_nowait(" not in restore_body:
    raise SystemExit("registry restore uses a sleeping import")
nowait_body = function_body(registry,
    "vmx_nested_vmcs_registry_import_nowait")
if "abort_indicator, false" not in nowait_body:
    raise SystemExit("non-waiting import does not select M_NOWAIT")
select_body = function_body(registry, "vmx_nested_vmcs_registry_select")
if "nvmx_registry_create(registry, gpa, false, &entry)" not in select_body:
    raise SystemExit("frozen VMPTRLD selection can sleep while allocating")
vcpu_snapshot = function_body(vmx, "vmx_vcpu_nested_snapshot")
if "vmx_nested_msr_workspace_ensure(vcpu," not in vcpu_snapshot or \
        "&stage->registry.capabilities, false" not in vcpu_snapshot:
    raise SystemExit("active-L2 restore can wait for MSR workspace")
if "vmx_nested_msr_workspace_stage(" not in vcpu_snapshot or \
        "&vcpu_stage->msr_workspace" not in vcpu_snapshot or \
        "&vcpu_stage->msr_storage" not in vcpu_snapshot or \
        "vcpu_stage->msr_workspace_staged = true" not in vcpu_snapshot:
    raise SystemExit("fresh active-L2 restore scratch is not staged")
complete = function_body(vmx, "vmx_vm_snapshot_complete")
if "vcpu_stage->msr_workspace_staged" not in complete or \
        "nested_msr_workspace =\n\t\t\t\t    vcpu_stage->msr_workspace" not in complete or \
        "nested_msr_storage =\n\t\t\t\t    vcpu_stage->msr_storage" not in complete:
    raise SystemExit("staged active-L2 scratch is not transferred after commit")
stage_free = function_body(vmx, "vmx_nested_snapshot_restore_free")
if "vmx_nested_msr_workspace_unbind(" not in stage_free or \
        "stage->vcpus[i].msr_storage" not in stage_free:
    raise SystemExit("failed active-L2 restore can strand staged scratch")
if "&instruction->request.capabilities, true" not in vmx:
    raise SystemExit("ordinary nested entry lost its waitable workspace path")
if "vmx_nested_vmcs_registry_import_nowait(&source" not in tests or \
        "ATF_CHECK_EQ(source.count, 1)" not in tests:
    raise SystemExit("non-waiting registry import lacks direct regression")
PY
then
	fail "nested checkpoint can sleep or lost its no-wait regression contract"
fi

# private-test: nested-snapshot-frozen-vcpu-boundary
# VM_SNAPSHOT_REQ is presently dispatched with LOCK_ALL_VCPUS, but the
# architecture helpers also enforce that private synchronization contract.
# This prevents a future internal caller or dispatch-table refactor from
# staging scratch or publishing VM-wide nested ownership beside a running CPU.
if ! python3 - "$vmx_source" "$vmm_dev_machdep_source" <<'PY'
import pathlib
import re
import sys

vmx = pathlib.Path(sys.argv[1]).read_text()
dispatch = pathlib.Path(sys.argv[2]).read_text()

def body(name):
    match = re.search(r"\n" + re.escape(name) +
        r"\s*\([^;]*?\)\s*\{", vmx, re.S)
    if match is None:
        raise SystemExit(f"missing function {name}")
    start = vmx.find("{", match.start())
    depth = 0
    state = "code"
    offset = start
    while offset < len(vmx):
        ch = vmx[offset]
        nxt = vmx[offset + 1] if offset + 1 < len(vmx) else ""
        if state == "code":
            if ch == '"':
                state = "string"
            elif ch == "'":
                state = "char"
            elif ch == "/" and nxt == "*":
                state = "block"
                offset += 1
            elif ch == "/" and nxt == "/":
                state = "line"
                offset += 1
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return vmx[start:offset + 1]
        elif state == "string":
            if ch == "\\":
                offset += 1
            elif ch == '"':
                state = "code"
        elif state == "char":
            if ch == "\\":
                offset += 1
            elif ch == "'":
                state = "code"
        elif state == "block" and ch == "*" and nxt == "/":
            state = "code"
            offset += 1
        elif state == "line" and ch == "\n":
            state = "code"
        offset += 1
    raise SystemExit(f"unterminated function {name}")

vcpu = body("vmx_vcpu_nested_snapshot")
outer = body("vmx_vcpu_snapshot")
complete = body("vmx_vm_snapshot_complete")
freeze = "vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN"
if freeze not in vcpu:
    raise SystemExit("per-vCPU nested staging trusts remote freeze policy")
if freeze not in outer or outer.find(freeze) > outer.find("vmx_snapshot_vmcs_state("):
    raise SystemExit("architecture snapshot checks freeze after VMCS mutation")
if "vcpu_get_state(generic_vcpu, NULL) != VCPU_FROZEN" not in complete:
    raise SystemExit("VM-wide nested publication trusts remote freeze policy")
if "VMMDEV_IOCTL(VM_SNAPSHOT_REQ, VMMDEV_IOCTL_LOCK_ALL_VCPUS)" not in dispatch:
    raise SystemExit("snapshot ioctl lost its all-vCPU freeze dispatch")
PY
then
	fail "nested snapshot lost its checked frozen-vCPU boundary"
fi

# private-test: mtf-runtime-owner-lifetime
# Monitor-trap state has two mutually exclusive owners: the portable cold
# image or a generation-bound hot runtime value.  The hot owner is private,
# never serialized, initialized for every vCPU, and must be empty at every
# generic snapshot boundary and final release until the complete transfer
# adapter is enabled.
rg -q -F '#include "vmx_nested_mtf_owner.h"' "$vmx_header" ||
    fail "vmx_vcpu lacks the typed nested MTF runtime owner declaration"
rg -q -F 'struct vmx_nested_mtf_owner nested_mtf_owner;' "$vmx_header" ||
    fail "vmx_vcpu does not retain a generation-bound nested MTF owner"
if ! python3 - "$vmx_source" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text()

def body(name):
    match = re.search(r"\n" + re.escape(name) +
        r"\s*\([^;]*?\)\s*\{", source, re.S)
    if match is None:
        raise SystemExit(f"missing function {name}")
    start = source.find("{", match.start())
    depth = 0
    state = "code"
    offset = start
    while offset < len(source):
        ch = source[offset]
        nxt = source[offset + 1] if offset + 1 < len(source) else ""
        if state == "code":
            if ch == '"':
                state = "string"
            elif ch == "'":
                state = "char"
            elif ch == "/" and nxt == "*":
                state = "block"
                offset += 1
            elif ch == "/" and nxt == "/":
                state = "line"
                offset += 1
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return source[start:offset + 1]
        elif state == "string":
            if ch == "\\":
                offset += 1
            elif ch == '"':
                state = "code"
        elif state == "char":
            if ch == "\\":
                offset += 1
            elif ch == "'":
                state = "code"
        elif state == "block" and ch == "*" and nxt == "/":
            state = "code"
            offset += 1
        elif state == "line" and ch == "\n":
            state = "code"
        offset += 1
    raise SystemExit(f"unterminated function {name}")

init = body("vmx_vcpu_init")
cleanup = body("vmx_vcpu_cleanup")
snapshot = body("vmx_vcpu_snapshot")
snapshot_source = body("vmx_nested_snapshot_source_validate")
restore = body("vmx_vm_snapshot_complete")
restore_destination = body("vmx_nested_snapshot_destination_validate")
if "vmx_nested_mtf_owner_init(&vcpu->nested_mtf_owner)" not in init:
    raise SystemExit("nested MTF owner is not initialized with every vCPU")
if "vmx_nested_mtf_owner_validate(&vcpu->nested_mtf_owner)" not in cleanup or \
        "vcpu->nested_mtf_owner.pending" not in cleanup or \
        "nested MTF owner still active" not in cleanup:
    raise SystemExit("vCPU teardown does not reject a retained MTF owner")
if "vmx_nested_snapshot_source_validate(vcpu, active_l2)" not in snapshot or \
        "vmx_nested_mtf_owner_validate(&vcpu->nested_mtf_owner)" not in snapshot_source or \
        "vcpu->nested_mtf_owner.pending" not in snapshot_source:
    raise SystemExit("per-vCPU snapshot does not reject a hot MTF owner")
if "vmx_nested_snapshot_destination_validate(" not in restore or \
        "vmx_nested_mtf_owner_validate(" not in restore_destination or \
        "nested_mtf_owner.pending" not in restore_destination:
    raise SystemExit("VM-wide restore does not reject an occupied MTF owner")
PY
then
    fail "nested MTF runtime owner lifetime is incomplete"
fi

# private-test: intel-adapter-fail-stop-boundary
# Guest values and ordinary hardware-access failures are recoverable errors.
# A host panic is reserved for loss of CPU-local current-VMCS or rollback
# ownership after a destructive transition, where returning would permit the
# thread to migrate or execute with an unknown VMCS.  Pin both halves so a
# refactor cannot broaden fail-stop behavior into a guest-triggerable parser.
for anchor in \
    'return (vmread(encoding, value) == 0 ? 0 : EIO)' \
    'return (vmwrite(encoding, value) == 0 ? 0 : EIO)' \
    'VMCS02 is already detached, so this cannot remain a' \
    'cannot roll back VMCS01 TSC state'; do
	rg -q -F "$anchor" "$vmcs02_intel_source" ||
	    fail "Intel VMCS residency boundary changed: $anchor"
done
for anchor in \
    'A failed VMCLEAR does not prove that the per-CPU current-VMCS' \
    'There is no recoverable owner to which' \
    'cannot detach captured VMCS01'; do
	rg -q -F "$anchor" "$environment_intel_source" ||
	    fail "Intel environment fail-stop boundary changed: $anchor"
done
if rg -q -F 'panic(' "$src/sys/amd64/vmm/intel/vmx_nested_vmcs02_program.c" \
    "$src/sys/amd64/vmm/intel/vmx_nested_entry_environment.c"; then
	fail "value-only nested adapters acquired a host fail-stop path"
fi

# private-test: frozen-event-state-transaction
# Pending exception, NMI, ExtINT, and reinjection state are one private kernel
# owner.  The checkpoint adapter must reject an active producer, require a
# frozen vCPU, validate a complete value before restore publication, and keep
# its x86-only implementation out of the architecture-neutral module list.
for function in vm_event_state_capture vm_event_state_restore; do
	rg -q -F "$function" "$vmm_source" ||
	    fail "missing frozen event-state adapter $function"
done
rg -q -F 'vcpu_get_state(vcpu, NULL) != VCPU_FROZEN' "$vmm_source" ||
    fail "event-state adapter is not frozen-vCPU-only"
rg -q -F 'vcpu->exception_injecting != 0' "$vmm_source" ||
    fail "event-state adapter does not fence an active exception producer"
rg -q -F 'vmm_event_state_validate(state)' "$vmm_source" ||
    fail "event-state restore does not validate before publication"
event_restore=$(sed -n \
    '/^vm_event_state_restore(struct vcpu \*vcpu,/,/^}/p' "$vmm_source")
for owner in \
    'vcpu->exception_injecting != 0' \
    'vcpu->exception_pending != 0' \
    'vcpu->nmi_pending != 0' \
    'vcpu->extint_pending != 0' \
    'vcpu->exitintinfo != 0'; do
	printf '%s\n' "$event_restore" | rg -q -F "$owner" ||
	    fail "single-vCPU event restore can overwrite owner: $owner"
done
printf '%s\n' "$event_restore" | rg -q -F 'return (EBUSY)' ||
    fail "single-vCPU event restore does not reject occupied destination"
if sed -n '/# generic vmm support/,/\.if ${MACHINE_CPUARCH}/p' \
    "$module_makefile" | rg -q -F 'vmm_event_state.c'; then
	fail "x86 event-state implementation leaked into generic VMM sources"
fi

# private-test: all-vcpu-event-capture
# The VM-wide adapter is a no-poll consistency transaction, not an ingress
# lock.  Require exact frozen sparse topology, private candidates, a generation
# check before output publication, and an explicit coordinator obligation for
# the interval after the transaction's linearization point.
for symbol in \
    event_generation \
    vm_event_state_capture_all \
    vcpu_event_generation_advance_locked; do
	rg -q -F "$symbol" "$vmm_source" "$src/sys/amd64/include/vmm.h" ||
	    fail "missing all-vCPU event capture symbol $symbol"
done
rg -q -F 'sx_xlocked(&vm->vcpus_init_lock)' "$vmm_source" ||
    fail "all-vCPU event capture does not require topology ownership"
rg -q -F 'mallocarray(count, sizeof(*candidates)' "$vmm_source" ||
    fail "all-vCPU event capture does not stage private candidates"
event_capture_all=$(sed -n \
    '/^vm_event_state_capture_all(struct vm \*vm,/,/^}/p' "$vmm_source")
printf '%s\n' "$event_capture_all" | rg -q -F 'M_NOWAIT | M_ZERO' ||
    fail "all-vCPU event capture can sleep indefinitely while the VM is frozen"
printf '%s\n' "$event_capture_all" | rg -q -F 'return (ENOMEM)' ||
    fail "all-vCPU event capture lacks transactional allocation failure"
rg -q -F 'vm_event_output_overlaps_owner' "$vmm_source" ||
    fail "all-vCPU event capture does not reject live-owner aliases"
rg -q -F 'vmm_event_capture_commit_validate(generation' "$vmm_source" ||
    fail "all-vCPU event capture lacks generation/count commit validation"
rg -q -F 'external event ingress quiesced' "$vmm_source" ||
    fail "all-vCPU event capture omits its post-linearization ingress contract"
rg -q -F 'all_vcpu_capture_generation' "$event_test_source" ||
    fail "missing generation/count transaction value coverage"
rg -q -F 'capture_output_ranges' "$event_test_source" ||
    fail "missing output range and alias primitive coverage"

# private-test: vms2-kernel-capture-composition
# Common and amd64 state must be composed in private storage at one frozen-VM
# boundary.  This is a source/build gate until the named V2 record and a real
# coordinator ingress lease make a live all-vCPU publication test possible.
capture_all=$(sed -n \
    '/^vm_snapshot_x86_capture_all(struct vm \*vm,/,/^}/p' "$vmm_source")
for contract in \
    'sx_xlocked(&vm->vcpus_init_lock)' \
    'vcpu_get_state(vcpu, NULL) != VCPU_FROZEN' \
    'mallocarray(count, sizeof(*stage_candidates)' \
	'vm_event_state_capture_all(vm, instances, events, count, &index)' \
	'CPU_COPY(&vm->startup_cpus, &startup_cpus)' \
	'now = rdtsc()' \
    'vmm_snapshot_vcpu_x86_event_from_runtime(&events[index]' \
    'vmm_event_capture_commit_validate(generation' \
    'memcpy(stage, stage_candidates, stage_length)' \
    '*transaction = transaction_candidate'; do
	printf '%s\n' "$capture_all" | rg -q -F "$contract" ||
	    fail "VMS2 kernel capture composer is missing: $contract"
done
printf '%s\n' "$capture_all" | rg -q -U --pcre2 \
    'mtx_lock\(&vm->rendezvous_mtx\);[\s\S]*?CPU_COPY\(&vm->startup_cpus, &startup_cpus\);[\s\S]*?mtx_unlock\(&vm->rendezvous_mtx\);[\s\S]*?CPU_ISSET\(i, &startup_cpus\)' ||
    fail "VMS2 kernel capture reads startup wait state outside its owner"
rg -q 'NVMX-STATE-041.*Owner-protected startup wait capture' "$ledger" ||
    fail "startup wait capture ownership requirement is missing"
rg -q 'NVMX-PRIVATE-169.*startup-wait-capture-snapshot' \
    "$private_ledger" ||
    fail "startup wait capture private contract is missing"
printf '%s\n' "$capture_all" | rg -q -F 'M_NOWAIT | M_ZERO' ||
    fail "VMS2 kernel capture can sleep indefinitely while the VM is frozen"
printf '%s\n' "$capture_all" | rg -q -F 'error = ENOMEM' ||
    fail "VMS2 kernel capture lacks transactional allocation failure"
publish_line=$(printf '%s\n' "$capture_all" | rg -n -F \
    'memcpy(stage, stage_candidates, stage_length)' | cut -d: -f1)
commit_line=$(printf '%s\n' "$capture_all" | rg -n -F \
    'vmm_event_capture_commit_validate(generation' | cut -d: -f1)
[ -n "$publish_line" ] && [ -n "$commit_line" ] &&
    [ "$publish_line" -gt "$commit_line" ] ||
    fail "VMS2 kernel capture publishes before its final event check"
printf '%s\n' "$capture_all" | rg -q -F \
    'vm_event_output_overlaps_owner(vm, stage' ||
    fail "VMS2 kernel capture does not reject live-owner stage aliases"
printf '%s\n' "$capture_all" | rg -q -F \
    'vm_event_output_overlaps_owner(vm, transaction' ||
    fail "VMS2 kernel capture does not reject live-owner transaction aliases"

# private-test: event-capture-scratch-complete-wipe
# Pending event candidates contain error codes, provenance, and reinjection
# state.  The two capture layers may publish copies to their caller, but their
# discarded heap duplicates must be cleared on every release path.
[ "$(printf '%s\n' "$event_capture_all" | rg -c -F \
    'malloc_usable_size(candidates)')" -eq 2 ] ||
    fail "event capture candidates are not wiped on success and failure"
printf '%s\n' "$capture_all" | rg -q -F \
    'malloc_usable_size(events)' ||
    fail "VMS2 capture event scratch is not wiped"
rg -q 'NVMX-PRIVATE-057.*event-capture-scratch-complete-wipe' \
    "$private_ledger" ||
    fail "event capture scratch lifetime is absent from private ledger"

# TEST-ANCHOR: vms2-restore-owner-order
# These are distinct private owners.  The ordinary x2APIC setter is an
# initialization operation which resets LAPIC mode-dependent state, while the
# startup mask is protected by the rendezvous mutex.  A future VMS2 publisher
# must therefore not call the setter after restoring LAPIC state or acquire
# the sleepable rendezvous owner while holding all event spin locks.
x2apic_setter=$(sed -n \
    '/^vm_set_x2apic_state(struct vcpu \*vcpu,/,/^}/p' "$vmm_source")
printf '%s\n' "$x2apic_setter" | rg -q -F \
    'vlapic_set_x2apic_state(vcpu, state)' ||
    fail "x2APIC setter no longer exposes its LAPIC-reset ordering constraint"
for startup_owner in vm_start_cpus vm_publish_startup_wait; do
    startup_body=$(sed -n \
	"/^${startup_owner}(struct vm \*vm,/,/^}/p" "$vmm_source")
    printf '%s\n' "$startup_body" | rg -q -F \
	'mtx_lock(&vm->rendezvous_mtx)' ||
	fail "$startup_owner no longer acquires the startup-mask owner"
    printf '%s\n' "$startup_body" | rg -q -F \
	'mtx_unlock(&vm->rendezvous_mtx)' ||
	fail "$startup_owner no longer releases the startup-mask owner"
done
rg -q 'NVMX-PRIVATE-049.*VMS2-restore-owner-order' \
    "$private_ledger" ||
    fail "VMS2 restore owner ordering is absent from the private ledger"
restore_create=$(sed -n \
    '/^vm_snapshot_x86_restore_plan_create(struct vm \*vm,/,/^}/p' \
    "$vmm_source")
for contract in \
    'transaction_candidate = *transaction' \
    'memcpy(stage_candidates, stage, stage_length)' \
    'M_NOWAIT | M_ZERO' \
    'vmm_snapshot_x86_transaction_restore_preflight(' \
    'vmm_snapshot_vcpu_x86_event_to_runtime(' \
    'vm_event_exception_class_prepare(' \
    'vlapic_get_apicbase(' \
	'CPU_COPY(&vm->startup_cpus, &plan->destination_startup_cpus)' \
    'generation = atomic_load_acq_64(&vm->event_generation)' \
    'vcpu->exception_injecting != 0' \
    'vcpu->exception_pending != 0' \
    'atomic_load_acq_64(&vm->event_generation) != generation' \
    'plan->event_generation = generation' \
    '*planp = plan'; do
    printf '%s\n' "$restore_create" | rg -q -F "$contract" ||
	fail "VMS2 restore plan lacks immutable preflight: $contract"
done
rg -q -F 'vmm_snapshot_x86_transaction_restore_preflight(' \
    "$envelope_test_source" ||
    fail "missing independent VMS2 restore LAPIC/topology preflight coverage"
publish_plan=$(sed -n \
    '/^vm_snapshot_x86_restore_plan_commit(struct vm \*vm,/,/^}/p' \
    "$vmm_source")
for contract in \
    'plan->entries[count].stage.instance != i' \
    'vcpu_get_state(entry->vcpu, NULL) != VCPU_FROZEN' \
    'vlapic_get_apicbase(vm_lapic(entry->vcpu))' \
    'mtx_lock(&vm->rendezvous_mtx)' \
    'if (plan->committed)' \
	'CPU_CMP(&vm->startup_cpus,' \
	'&plan->destination_startup_cpus) != 0' \
    'vcpu_event_lock(plan->entries[index].vcpu)' \
    'plan->event_generation' \
    'exception_injecting != 0' \
    'CPU_COPY(&plan->startup_cpus, &vm->startup_cpus)' \
    'vm_event_state_publish_locked(entry->vcpu, &entry->event' \
    'plan->committed = true' \
    'vcpu_event_unlock(plan->entries[index - 1].vcpu)' \
    'mtx_unlock(&vm->rendezvous_mtx)'; do
    printf '%s\n' "$publish_plan" | rg -q -F "$contract" ||
	fail "VMS2 restore commit lacks ordered publication: $contract"
done
if printf '%s\n' "$publish_plan" | rg -q -F \
    'vm_set_x2apic_state('; then
    fail "VMS2 restore commit resets the already-restored LAPIC image"
fi
rendezvous_line=$(printf '%s\n' "$publish_plan" | rg -n -F \
    'mtx_lock(&vm->rendezvous_mtx)' | head -n 1 | cut -d: -f1)
event_line=$(printf '%s\n' "$publish_plan" | rg -n -F \
    'vcpu_event_lock(plan->entries[index].vcpu)' | head -n 1 | cut -d: -f1)
[ -n "$rendezvous_line" ] && [ -n "$event_line" ] &&
[ "$rendezvous_line" -lt "$event_line" ] ||
    fail "VMS2 restore commit acquires a sleepable owner under event spin locks"
printf '%s\n' "$publish_plan" | rg -q -U --pcre2 \
    'mtx_lock\(&vm->rendezvous_mtx\);[\s\S]*?CPU_CMP\(&vm->startup_cpus,[\s\S]*?&plan->destination_startup_cpus\) != 0[\s\S]*?return \(EAGAIN\);[\s\S]*?vcpu_event_lock' ||
    fail "VMS2 restore commit does not reject startup-owner drift before event locks"
rg -q 'NVMX-STATE-042.*Restore plan startup-owner reservation' "$ledger" ||
    fail "restore startup-owner reservation requirement is missing"
rg -q 'NVMX-PRIVATE-170.*restore-plan-startup-owner-reservation' \
    "$private_ledger" ||
    fail "restore startup-owner private contract is missing"

# private-test: vms2-restore-plan-complete-wipe
# The plan is opaque outside the kernel coordinator and contains complete
# per-vCPU architectural/event staging.  Teardown must clear the allocation's
# actual extent without deriving a shorter length from mutable plan fields.
restore_free=$(sed -n \
    '/^vm_snapshot_x86_restore_plan_free(/,/^}/p' "$vmm_source")
for contract in \
    'plan_size = malloc_usable_size(plan)' \
    'explicit_bzero(plan, plan_size)' \
    'free(plan, M_VM)'; do
	printf '%s\n' "$restore_free" | rg -q -F "$contract" ||
	    fail "VMS2 restore-plan teardown lacks complete wipe: $contract"
done
printf '%s\n' "$restore_free" | rg -q -F 'plan->count' &&
    fail "VMS2 restore-plan teardown trusts mutable count"
rg -q 'NVMX-PRIVATE-053.*VMS2-restore-plan-complete-wipe' \
    "$private_ledger" ||
    fail "VMS2 restore-plan complete-wipe policy is absent from private ledger"
restore_create=$(sed -n \
    '/^vm_snapshot_x86_restore_plan_create(/,/^}/p' "$vmm_source")
[ "$(printf '%s\n' "$restore_create" | rg -c -F \
    'malloc_usable_size(stage_candidates)')" -eq 2 ] ||
    fail "VMS2 temporary staging is not wiped on success and failure"
rg -q 'NVMX-PRIVATE-056.*VMS2-restore-temporary-stage-wipe' \
    "$private_ledger" ||
    fail "VMS2 temporary-stage wipe policy is absent from private ledger"

# private-test: current-struct-vm-event-ownership
# VMS2 captures and restores the complete event domain through the shared
# generation-fenced all-vCPU transaction.  No reduced legacy event path is
# permitted.
for contract in \
    'vm_event_state_capture_all(vm, instances, events, count, &index)' \
    'vmm_snapshot_vcpu_x86_event_from_runtime(&events[index]' \
    'vm_snapshot_x86_restore_plan_create(vm, &transaction, stage,' \
    'vm_snapshot_x86_restore_plan_commit(vm, plan)'; do
	rg -q -F "$contract" "$vmm_source" ||
	    fail "current STRUCT_VM event ownership is missing: $contract"
done
rg -q 'NVMX-STATE-045.*Current STRUCT_VM uses complete VMS2 event ownership' \
    "$ledger" ||
    fail "current STRUCT_VM event ownership requirement is missing"

# private-test: historical-vatpit-snapshot-transaction
# The legacy PIT wire layout cannot be changed, but copyin must stage it before
# touching the timer and a restored channel-zero counter must rearm exactly one
# destination callout rather than retaining a source-relative deadline.
vatpit_source="$src/sys/amd64/vmm/io/vatpit.c"
for contract in \
    'struct vatpit_snapshot_state' \
    'vatpit_snapshot_capture_locked' \
    'vatpit_snapshot_restore_locked' \
    'vatpit_snapshot_state_valid' \
	'vatpit_snapshot_state_serializable' \
    '_Static_assert(sizeof(bool) == sizeof(uint8_t)' \
    'callout_stop(&vatpit->channel[0].callout)' \
    'pit_timer_start_cntr0(vatpit)' \
    'if (meta->op == VM_SNAPSHOT_SAVE)' \
    'if (meta->op == VM_SNAPSHOT_RESTORE)' \
    'explicit_bzero(&state, sizeof(state))'; do

	rg -q -F "$contract" "$vatpit_source" ||
	    fail "historical VATPIT snapshot transaction lacks: $contract"
done
for contract in \
    'state->freq_bt.sec != freq_bt.sec' \
    'channel->crbyte < 0 || channel->crbyte > 1' \
    'channel->elapsed_bt.sec < 0 ||' \
    'channel->callout_armed > 1' \
	'state->channel[i].olbyte != 0' \
	'ret = EBUSY;' \
    'channel->frbyte < 0 || channel->frbyte > 1' \
    'channel->slatched > 1' \
    'if (!vatpit_snapshot_state_valid(&state))'; do

	rg -q -F "$contract" "$vatpit_source" ||
	    fail "historical VATPIT snapshot input validation lacks: $contract"
done
if rg -q -F 'snapshot restore does not reset timers' "$vatpit_source"; then
	fail "historical VATPIT snapshot still leaves timers unrearmed"
fi
rg -q 'NVMX-STATE-046.*Historical virtual-PIT snapshot restores atomically and rearms channel zero' \
    "$ledger" ||
    fail "historical VATPIT snapshot requirement is missing"

# private-test: historical-vatpic-snapshot-transaction
# Like VATPIT, the fixed PIC record is a compatibility ABI.  It must decode
# outside the live interrupt owner and reject values which would make the IRQ
# selector index or mode logic non-canonical before its one commit point.
vatpic_source="$src/sys/amd64/vmm/io/vatpic.c"
for contract in \
    'struct vatpic_snapshot_state' \
    'vatpic_snapshot_capture_locked' \
    'vatpic_snapshot_state_valid' \
    'vatpic_snapshot_restore_locked' \
    '_Static_assert(sizeof(bool) == sizeof(uint8_t)' \
    'if (meta->op == VM_SNAPSHOT_SAVE)' \
    'if (!vatpic_snapshot_state_valid(&state))' \
    'explicit_bzero(&state, sizeof(state))'; do

	rg -q -F "$contract" "$vatpic_source" ||
	    fail "historical VATPIC snapshot transaction lacks: $contract"
done
for contract in \
    'atpic->icw_num < 0 || atpic->icw_num > 4' \
    '(atpic->rd_cmd_reg & ~OCW3_RIS) != 0' \
    '(atpic->irq_base & 0x7) != 0' \
    'atpic->lowprio < 0' \
    'atpic->lowprio > 7'; do

	rg -q -F "$contract" "$vatpic_source" ||
	    fail "historical VATPIC snapshot input validation lacks: $contract"
done
rg -q 'NVMX-STATE-047.*Historical virtual-PIC snapshot restores atomically' \
    "$ledger" ||
    fail "historical VATPIC snapshot requirement is missing"

# private-test: historical-vrtc-snapshot-transaction
# STRUCT_VRTC is a fixed compatibility record.  Decode must not update a live
# RTC or change its callout epoch until every field has been obtained.
vrtc_source="$src/sys/amd64/vmm/io/vrtc.c"
for contract in \
    'struct vrtc_snapshot_state' \
    'vrtc_snapshot_capture_locked' \
    'vrtc_snapshot_restore_locked' \
    'if (meta->op == VM_SNAPSHOT_SAVE)' \
    'if (meta->op == VM_SNAPSHOT_RESTORE)' \
    'vrtc->base_uptime = sbinuptime()' \
    'vrtc_callout_reset(vrtc, vrtc_freq(vrtc))' \
    'explicit_bzero(&state, sizeof(state))'; do

	rg -q -F "$contract" "$vrtc_source" ||
	    fail "historical VRTC snapshot transaction lacks: $contract"
done
rg -q -U --pcre2 \
    'SNAPSHOT_VAR_OR_LEAVE\(state\.addr[\s\S]*?SNAPSHOT_BUF_OR_LEAVE\(state\.rtcdev\.nvram2[\s\S]*?if \(meta->op == VM_SNAPSHOT_RESTORE\)[\s\S]*?vrtc_snapshot_restore_locked' \
    "$vrtc_source" ||
    fail "historical VRTC snapshot no longer stages the full wire record before commit"
rg -q 'NVMX-STATE-048.*Historical virtual-RTC snapshot restores atomically' \
    "$ledger" ||
    fail "historical VRTC snapshot requirement is missing"

# private-test: historical-vhpet-snapshot-transaction
# The fixed HPET record contains a host-relative callout deadline.  Decode it
# before changing the live counter and stop stale destination callbacks before
# vm_restore_time reanchors any enabled timers.
vhpet_source="$src/sys/amd64/vmm/io/vhpet.c"
for contract in \
    'struct vhpet_snapshot_state' \
    'vhpet_snapshot_capture_locked' \
    'vhpet_snapshot_state_valid' \
    'vhpet_snapshot_restore_locked' \
    'state->freq_sbt != vhpet->freq_sbt' \
    'state->freq_sbt == 0' \
    'callout_stop(&vhpet->timer[i].callout)' \
    'if (meta->op == VM_SNAPSHOT_SAVE)' \
    'if (meta->op == VM_SNAPSHOT_RESTORE)' \
    'explicit_bzero(&state, sizeof(state))'; do

	rg -q -F "$contract" "$vhpet_source" ||
	    fail "historical VHPET snapshot transaction lacks: $contract"
done
rg -q -U --pcre2 \
    'SNAPSHOT_VAR_OR_LEAVE\(state\.freq_sbt[\s\S]*?SNAPSHOT_VAR_OR_LEAVE\(state\.timer\[i\]\.callout_sbt[\s\S]*?if \(meta->op == VM_SNAPSHOT_RESTORE\)[\s\S]*?vhpet_snapshot_state_valid[\s\S]*?vhpet_snapshot_restore_locked' \
    "$vhpet_source" ||
    fail "historical VHPET snapshot no longer stages the full wire record before commit"
rg -q -U --pcre2 \
    'vhpet_restore_time\(struct vhpet \*vhpet\)[\s\S]*?VHPET_LOCK\(vhpet\)[\s\S]*?vhpet_start_counting\(vhpet\)[\s\S]*?VHPET_UNLOCK\(vhpet\)' \
    "$vhpet_source" ||
    fail "historical VHPET restore-time restart no longer owns the timer state"
rg -q 'NVMX-STATE-049.*Historical virtual-HPET snapshot restores atomically' \
    "$ledger" ||
    fail "historical VHPET snapshot requirement is missing"

# private-test: historical-vioapic-snapshot-transaction
# The I/O APIC routing table and assertion counts have one spin-lock owner.
# Historical decode must not expose a partially copied routing table to an IRQ
# publisher or interrupt-delivery path.
vioapic_source="$src/sys/amd64/vmm/io/vioapic.c"
for contract in \
    'struct vioapic_snapshot_state' \
    'vioapic_snapshot_capture_locked' \
    'vioapic_snapshot_restore_locked' \
    'if (meta->op == VM_SNAPSHOT_SAVE)' \
    'if (meta->op == VM_SNAPSHOT_RESTORE)' \
    'explicit_bzero(&state, sizeof(state))'; do

	rg -q -F "$contract" "$vioapic_source" ||
	    fail "historical VIOAPIC snapshot transaction lacks: $contract"
done
rg -q -U --pcre2 \
    'SNAPSHOT_VAR_OR_LEAVE\(state\.ioregsel[\s\S]*?SNAPSHOT_VAR_OR_LEAVE\(state\.rtbl\[i\]\.acnt[\s\S]*?if \(meta->op == VM_SNAPSHOT_RESTORE\)[\s\S]*?VIOAPIC_LOCK\(vioapic\)[\s\S]*?vioapic_snapshot_restore_locked' \
    "$vioapic_source" ||
    fail "historical VIOAPIC snapshot no longer stages the full wire record before commit"
rg -q 'NVMX-STATE-050.*Historical virtual-I/O-APIC snapshot restores atomically' \
    "$ledger" ||
    fail "historical VIOAPIC snapshot requirement is missing"

# private-test: historical-vpmtmr-snapshot-reanchor
# The wire record contains a count, never a host uptime.  Saving the live
# count and rebasing it on restore is required for portable counter progress.
vpmtmr_source="$src/sys/amd64/vmm/io/vpmtmr.c"
for contract in \
    'struct mtx' \
    'vpmtmr_value_locked' \
    'VPMTMR_LOCK(vpmtmr)' \
    'baseval = vpmtmr_value_locked(vpmtmr)' \
    'vpmtmr->baseuptime = sbinuptime()'; do

	rg -q -F "$contract" "$vpmtmr_source" ||
	    fail "historical VPMTMR snapshot reanchor lacks: $contract"
done
rg -q -U --pcre2 \
    'if \(meta->op == VM_SNAPSHOT_SAVE\)[\s\S]*?baseval = vpmtmr_value_locked\(vpmtmr\)[\s\S]*?SNAPSHOT_VAR_OR_LEAVE\(baseval[\s\S]*?if \(meta->op == VM_SNAPSHOT_RESTORE\)[\s\S]*?vpmtmr->baseval = baseval;[\s\S]*?vpmtmr->baseuptime = sbinuptime\(\)' \
    "$vpmtmr_source" ||
    fail "historical VPMTMR snapshot no longer captures and reanchors a count"
rg -q 'NVMX-STATE-051.*Historical virtual-PM-timer snapshot preserves counter continuity' \
    "$ledger" ||
    fail "historical VPMTMR snapshot requirement is missing"

# private-test: historical-vlapic-snapshot-transaction
# STRUCT_VLAPIC combines a page-sized frozen-vCPU image and a timer callout
# owned by a distinct spin lock.  Restore must stage the full record, reject
# corrupted ISR-stack/timer state, stop any old deadline, then publish once.
vlapic_source="$src/sys/amd64/vmm/io/vlapic.c"
for contract in \
    'struct vlapic_snapshot_state' \
    'vlapic_snapshot_capture_locked' \
    'vlapic_snapshot_lvt_state_valid' \
    'vlapic_snapshot_isr_stack_valid' \
    'vlapic_snapshot_state_valid' \
    'vlapic_snapshot_restore_locked' \
    'mallocarray(maxcpus, sizeof(*states)' \
    'vlapic_reset_callout_locked' \
    'callout_stop(&vlapic->callout)' \
    'state->lvt_last[APIC_LVT_TIMER] == lapic->lvt_timer' \
    'state->isrvec_stk[i] != vector' \
    '!vlapic_snapshot_state_valid(&states[i])' \
    'explicit_bzero(states, maxcpus * sizeof(*states))'; do

	rg -q -F "$contract" "$vlapic_source" ||
	    fail "historical VLAPIC snapshot transaction lacks: $contract"
done
rg -q -U --pcre2 \
    'SNAPSHOT_BUF_OR_LEAVE\(state->apic\.apic_page[\s\S]*?SNAPSHOT_VAR_OR_LEAVE\(state->ccr[\s\S]*?if \(meta->op == VM_SNAPSHOT_RESTORE\)[\s\S]*?!vlapic_snapshot_state_valid\(&states\[i\]\)[\s\S]*?VLAPIC_TIMER_LOCK\(vlapic\)[\s\S]*?vlapic_snapshot_restore_locked\(vlapic, &states\[i\]\)' \
    "$vlapic_source" ||
    fail "historical VLAPIC snapshot no longer validates every full wire record before commit"
rg -q 'NVMX-STATE-052.*Historical virtual-LAPIC snapshot restores atomically' \
    "$ledger" ||
    fail "historical VLAPIC snapshot requirement is missing"

# private-test: exception-producer-rollback
# Reservation rollback must work in release kernels as well as INVARIANTS
# kernels.  Replaying the failure edges from each backend prerequisite must
# reach a checked abort path, and the public restart helper must use its error
# channel instead of diagnostic-only assertions or panic.
inject_exception=$(sed -n \
    '/^vm_inject_exception_class(struct vcpu \*vcpu,/,/^}/p' "$vmm_source")
for prerequisite in \
    'error = vm_get_register(vcpu, VM_REG_GUEST_CR0, &regval)' \
    'error = vm_set_register(vcpu, VM_REG_GUEST_INTR_SHADOW, 0)' \
    'error = vm_restart_instruction_prepare(vcpu, &restart_plan)'; do
	printf '%s\n' "$inject_exception" | rg -q -F "$prerequisite" ||
	    fail "exception producer prerequisite is unchecked: $prerequisite"
done
printf '%s\n' "$inject_exception" | rg -q -F \
    'vcpu->exception_injecting = 0' ||
    fail "exception producer failure does not roll back its reservation"
printf '%s\n' "$inject_exception" | rg -q -F \
    'vcpu_event_generation_advance_locked(vcpu)' ||
    fail "exception producer rollback does not advance the capture epoch"
restart_instruction=$(sed -n \
    '/^vm_restart_instruction(struct vcpu \*vcpu)/,/^}/p' "$vmm_source")
if printf '%s\n' "$restart_instruction" | rg -q 'KASSERT|panic\('; then
	fail "instruction restart still depends on diagnostic-only failure handling"
fi
printf '%s\n' "$restart_instruction" | rg -q -F \
    'vm_restart_instruction_prepare(vcpu, &plan)' ||
    fail "instruction restart bypasses its read-only preparation"
printf '%s\n' "$restart_instruction" | rg -q -F \
    'vm_restart_instruction_apply(vcpu, &plan)' ||
    fail "instruction restart does not apply its validated plan"
restart_prepare=$(sed -n \
    '/^vm_restart_instruction_prepare(struct vcpu \*vcpu,/,/^}/p' \
    "$vmm_source")
printf '%s\n' "$restart_prepare" | rg -q -F 'return (EBUSY)' ||
    fail "instruction restart preparation does not reject invalid run-state"
set_shadow_line=$(printf '%s\n' "$inject_exception" | rg -n -F \
    'error = vm_set_register(vcpu, VM_REG_GUEST_INTR_SHADOW, 0)' |
    cut -d: -f1)
apply_restart_line=$(printf '%s\n' "$inject_exception" | rg -n -F \
    'vm_restart_instruction_apply(vcpu, &restart_plan)' | cut -d: -f1)
[ -n "$set_shadow_line" ] && [ -n "$apply_restart_line" ] &&
    [ "$apply_restart_line" -gt "$set_shadow_line" ] ||
    fail "exception restart is not prepared before and applied after shadow update"

# private-test: legacy-event-consume-transaction
# VMX and SVM retain a boolean-only compatibility helper.  It cannot expose
# EAGAIN, so require one event-lock critical section for planning and
# consumption and forbid assertion-only error handling in this path.
legacy_event_helper=$(sed -n \
    '/^vm_entry_intinfo(struct vcpu \*vcpu, uint64_t \*retinfo)/,/^}/p' \
    "$vmm_source")
printf '%s\n' "$legacy_event_helper" | rg -q -F \
    'vm_entry_intinfo_peek_locked(vcpu, &snapshot)' ||
    fail "legacy event helper does not plan while holding event ownership"
printf '%s\n' "$legacy_event_helper" | rg -q -F \
    'vm_entry_intinfo_consume_locked(vcpu, &snapshot' ||
    fail "legacy event helper does not consume the same locked snapshot"
if printf '%s\n' "$legacy_event_helper" | rg -q -F 'KASSERT'; then
	fail "legacy event helper still relies on diagnostic-only error handling"
fi

# private-test: transactional-exception-provenance
# The generic wire image does not distinguish fault, trap, ICEBP, and
# task-switch #DB.  A nested backend must receive that kernel-owned value in
# the same compare-and-commit snapshot as the event bits, never by peeking at
# the mutable vCPU owner after releasing its event lock.
event_peek=$(sed -n \
    '/^vm_entry_intinfo_peek_locked(struct vcpu \*vcpu,/,/^}/p' \
    "$vmm_source")
event_commit=$(sed -n \
    '/^vm_entry_intinfo_commit(struct vcpu \*vcpu,/,/^}/p' \
    "$vmm_source")
for contract in \
    'snapshot->exception_class = vcpu->exc_class' \
    'vcpu->exc_class <= VM_EXCEPTION_NONE' \
    'vcpu->exc_class >= VM_EXCEPTION_CLASS_LAST' \
    'vcpu->exc_class != VM_EXCEPTION_NONE'; do
	printf '%s\n' "$event_peek" | rg -q -F "$contract" ||
	    fail "event snapshot lacks provenance invariant: $contract"
done
printf '%s\n' "$event_commit" | rg -q -F \
    'snapshot->exception_class != current.exception_class' ||
    fail "event commit does not compare exception provenance"
rg -q 'NVMX-PRIVATE-054.*transactional-exception-provenance' \
    "$private_ledger" ||
    fail "transactional exception provenance is absent from private ledger"
rg -q -F 'vmx_nested_mtf_input_from_snapshot(' \
    "$src/sys/amd64/vmm/intel/vmx_nested_event.c" ||
    fail "Intel MTF arbitration bypasses the coherent event snapshot adapter"
for contract in \
    'snapshot->exception_class <= VMX_NESTED_EXCEPTION_NONE' \
    'snapshot->exception_class >= VMX_NESTED_EXCEPTION_LAST' \
    'candidate.reinjection_pending =' \
    'candidate.high_priority_non_debug_pending = true' \
    'VMX_NESTED_DEBUG_TASK_SWITCH'; do
	rg -q -F "$contract" "$src/sys/amd64/vmm/intel/vmx_nested_event.c" ||
	    fail "MTF snapshot adapter lacks closed mapping: $contract"
done
rg -q 'NVMX-PRIVATE-058.*generic-event-to-MTF-priority-input' \
    "$private_ledger" ||
    fail "generic-event MTF adapter is absent from private ledger"

# private-test: debug-provenance-adapters
# Mixed #DB delivery class is not recoverable from the vector alone.  Both
# hardware adapters must classify it before common event publication, and the
# ICEBP VMX path must retain privileged-software-exception instruction length.
rg -q -F 'vm_debug_exception_class(qual |' "$vmx_source" ||
    fail "VMX does not classify current #DB provenance"
rg -q -F 'intr_type == VMCS_INTR_T_PRIV_SWEXCEPTION' "$vmx_source" ||
    fail "VMX does not preserve ICEBP provenance"
rg -q -F 'vm_debug_exception_class(dr6, dr7)' \
    "$src/sys/amd64/vmm/amd/svm.c" ||
    fail "SVM does not classify #DB provenance"
rg -q -F 'vm_inject_exception_class' "$vmx_source" ||
    fail "VMX does not publish explicit exception provenance"
rg -q -F 'vm_inject_exception_class' "$src/sys/amd64/vmm/amd/svm.c" ||
    fail "SVM does not publish explicit exception provenance"
rg -q -F 'debug_classification' "$exception_test_source" ||
    fail "missing independent #DB classifier coverage"
rg -q -F 'decode_pass(buffer, length, NULL, capacity, NULL, false)' \
    "$transaction_source" || fail "VMS2 transaction lacks validation pass"
rg -q -F 'vmm_snapshot_ranges_overlap(buffer, length, stage, stage_length)' \
    "$transaction_source" || fail "VMS2 transaction lacks wire alias fence"

# private-test: vms2-public-range-boundaries
# Every public builder and codec is independently callable; do not rely on the
# all-vCPU transaction wrapper to reject a wrapping pointer range.
rg -q -F 'vmm_snapshot_range_valid' \
    "$src/sys/dev/vmm/vmm_snapshot_envelope.c" \
    "$src/sys/dev/vmm/vmm_snapshot_state.c" "$x86_state_source" ||
    fail "VMS2 public codecs do not share checked pointer ranges"
rg -q -F 'UINTPTR_MAX - 15' "$envelope_test_source" ||
    fail "missing direct envelope wrapping-range coverage"
overlap_primitive=$(sed -n \
    '/^vmm_snapshot_ranges_overlap(/,/^}/p' \
    "$src/sys/dev/vmm/vmm_snapshot_envelope.c")
for boundary in \
    'vmm_snapshot_range_valid(left, left_length)' \
    'vmm_snapshot_range_valid(right, right_length)'; do
	printf '%s\n' "$overlap_primitive" | rg -q -F "$boundary" ||
	    fail "VMS2 overlap primitive accepts a nonrepresentable range: $boundary"
done
rg -q -F 'vmm_snapshot_ranges_overlap(wrapping, 32, wire, 1)' \
	"$envelope_test_source" ||
	    fail "missing first-argument overlap wrapping-range coverage"
rg -q -F 'vmm_snapshot_ranges_overlap(wire, 1, wrapping, 32)' \
	"$envelope_test_source" ||
	    fail "missing second-argument overlap wrapping-range coverage"
rg -q -F 'UINTPTR_MAX - 7' "$envelope_test_source" ||
    fail "missing direct common/x86 codec wrapping-range coverage"
destination_preflight=$(sed -n \
    '/^vmm_snapshot_x86_transaction_validate_destination(/,/^}/p' \
    "$transaction_source")
for boundary in \
    'vmm_snapshot_range_valid(transaction, sizeof(*transaction))' \
    'vmm_snapshot_range_valid(stage, stage_length)' \
    'vmm_snapshot_range_valid(destination_instances, instances_length)' \
    'vmm_snapshot_ranges_overlap(transaction, sizeof(*transaction)' \
    'vmm_snapshot_ranges_overlap(stage, stage_length'; do
	printf '%s\n' "$destination_preflight" | rg -q -F "$boundary" ||
	    fail "VMS2 destination preflight is missing range contract: $boundary"
done
rg -q -F 'UINTPTR_MAX - 3' "$envelope_test_source" ||
    fail "missing direct VMS2 destination wrapping-range coverage"

# private-test: cpu-compat-query-transaction
# This management ABI is private and versioned.  Backend participation cannot
# publish a partial common record on error or on final protocol validation.
cpu_compat=$(sed -n '/^vm_get_cpu_compat(struct vcpu \*vcpu,/,/^}/p' \
    "$vmm_source")
for contract in \
    'struct vm_cpu_compat candidate' \
    'vmmops_get_cpu_compat(vcpu->cookie, &candidate)' \
    'candidate.version != VM_CPU_COMPAT_VERSION' \
    '(candidate.flags & ~VM_CPU_COMPAT_F_VALID) != 0' \
    '*compat = candidate'; do
	printf '%s\n' "$cpu_compat" | rg -q -F "$contract" ||
	    fail "CPU compatibility query is not transactional: $contract"
done
publish_compat_line=$(printf '%s\n' "$cpu_compat" | rg -n -F \
    '*compat = candidate' | cut -d: -f1)
validate_compat_line=$(printf '%s\n' "$cpu_compat" | rg -n -F \
    'candidate.version != VM_CPU_COMPAT_VERSION' | cut -d: -f1)
[ -n "$publish_compat_line" ] && [ -n "$validate_compat_line" ] &&
    [ "$publish_compat_line" -gt "$validate_compat_line" ] ||
    fail "CPU compatibility query publishes before protocol validation"
rg -q -U --pcre2 \
    'case VM_GET_CPU_COMPAT:[\s\S]*?query->reserved != 0[\s\S]*?EINVAL' \
    "$vmm_dev_source" ||
    fail "CPU compatibility ioctl does not reject its reserved input"

# private-test: vms2-no-transient-host-exit
# The last host exit is bookkeeping, not architectural guest state.  Keep its
# former wire area reserved-zero so enum vm_exitcode can evolve without
# becoming an accidental migration ABI.
for offset in 48 56 64 72; do
	rg -q -F "le64dec(wire + $offset) != 0" "$x86_state_source" ||
	    fail "VMS2 x86 reserved word at offset $offset is not rejected"
done
for field in exitcode exit_instruction_length exit_rip; do
	if rg -q -F "$field" "$x86_state_header" "$x86_state_source"; then
		fail "transient host exit field leaked into VMS2 x86 state: $field"
	fi
done
for adapter in vmm_snapshot_vcpu_x86_event_from_runtime \
    vmm_snapshot_vcpu_x86_event_to_runtime; do
	rg -q -F "$adapter" "$x86_state_source" ||
	    fail "missing explicit VMS2/runtime event adapter $adapter"
done
rg -q -F 'x86_event_conversion' "$envelope_test_source" ||
    fail "missing independent VMS2/runtime event-domain coverage"
if sed -n '/# generic vmm support/,/\.if ${MACHINE_CPUARCH}/p' \
    "$module_makefile" | rg -q -F 'vmm_exception.c'; then
	fail "x86 exception classifier leaked into generic VMM sources"
fi

inventory=$(mktemp -d /tmp/vmx-nested-inventory.XXXXXX)
trap 'rm -rf "$inventory"' EXIT HUP INT TERM

# The owner-outcome adapter is production code and must participate in the
# exact source/module inventory like every other nested lifecycle component.
find "$src/sys/amd64/vmm/intel" -maxdepth 1 -name 'vmx_nested_*.c' \
    -exec basename {} \; | sort > "$inventory/source"
sed -n 's/^[[:space:]]*\(vmx_nested_[A-Za-z0-9_]*\.c\).*/\1/p' \
    "$module_makefile" | sort > "$inventory/module"
if ! cmp -s "$inventory/source" "$inventory/module"; then
	comm -3 "$inventory/source" "$inventory/module" >&2
	fail "nested source inventory and vmm.ko source list differ"
fi

sed -n 's/.*\(vmx_nested_[A-Za-z0-9_]*\.c\).*/\1/p' "$test_source" |
    sort > "$inventory/model"
[ -z "$(uniq -d "$inventory/model")" ] ||
    fail "architectural model includes a nested source more than once"

# These adapters execute privileged VMX, pmap, or guest-memory operations and
# therefore compile in vmm.ko but cannot be linked into the rootless model.
# Every other value/lifecycle component must be the exact production source,
# not a test rewrite.
cat > "$inventory/kernel-only" <<'EOF'
vmx_nested_control_capabilities_intel.c
vmx_nested_entry_environment_intel.c
vmx_nested_ept_root.c
vmx_nested_ept_runtime.c
vmx_nested_guest_memory_intel.c
vmx_nested_instruction_runtime.c
vmx_nested_vmcs02_intel.c
vmx_nested_vmcs02_lease_intel.c
vmx_nested_vmcs02_resources_intel.c
EOF
sort -o "$inventory/kernel-only" "$inventory/kernel-only"
comm -23 "$inventory/source" "$inventory/model" \
    > "$inventory/model-exclusions"
if ! cmp -s "$inventory/kernel-only" "$inventory/model-exclusions"; then
	comm -3 "$inventory/kernel-only" "$inventory/model-exclusions" >&2
	fail "rootless model source exclusions changed without review"
fi

# VMX specifies both MSR and I/O bitmap pages in fixed 4 KiB architectural
# units.  They are Intel-private host allocations, but their sizes must not
# silently inherit the host base-page size: a future host-port or a larger
# host page could otherwise turn a VMX ABI object into host-sized staging
# storage.  Require every allocation/clear site for the MSR staging buffers
# to use the explicit contract from the standalone public bitmap header.
rg -q -F 'VMX_NESTED_BITMAP_PAGE_SIZE' "$bitmap_header" ||
    fail "nested bitmap header omits the architectural page-size contract"
for bitmap_staging_source in "$vmx_source" "$vmcs02_resources_intel_source"; do
	if rg -q -U --pcre2 \
	    '(nested_(l1_)?msr_bitmap(_scratch)?[^;]{0,200}PAGE_SIZE|PAGE_SIZE[^;]{0,200}nested_(l1_)?msr_bitmap(_scratch)?)' \
	    "$bitmap_staging_source"; then
		fail "nested MSR bitmap staging depends on host PAGE_SIZE: $bitmap_staging_source"
	fi
done
rg -q -F 'VMX_NESTED_MSR_BITMAP_SIZE' "$vmx_source" ||
    fail "VMX vCPU allocation omits the architectural MSR bitmap size"
rg -q -F 'VMX_NESTED_MSR_BITMAP_SIZE' "$vmcs02_resources_intel_source" ||
    fail "VMX resource staging omits the architectural MSR bitmap size"

# Compilation alone does not prove that the architectural model reaches the
# production run loop.  Pin the minimum cross-layer wiring that makes nested
# VMX more than an unreferenced helper library.  Detailed semantics remain in
# the requirement ledger and independent ATF cases.
for symbol in \
    vmx_nested_guest_configure \
    vmx_nested_instruction_capture_publish \
    vmx_nested_context_commit_vmentry_instruction \
    vmx_nested_entry_environment_intel_capture \
    vmx_nested_vmcs02_resources_intel_acquire \
    vmx_nested_hardware_entry_prepare \
    vmx_nested_run_select \
    vmx_run_nested \
    vmx_nested_run_pmap_activate \
    vmx_nested_run_pmap_deactivate \
    vmx_nested_vmcs02_intel_entry_instruction \
    vmx_nested_hardware_report_intel \
    vmx_nested_context_publish_vmexit \
    vmx_nested_hot_exit_freeze_publish \
    vmx_nested_vmcs02_program_apply \
    vmx_nested_ept_root_activate \
    vmx_nested_exit_policy_prepare \
    vmx_nested_checkpoint_active_context_restore \
    vmx_nested_restore_transaction_commit \
    vmx_nested_vpid_restore_destination_validate
do
	rg -q -w "$symbol" "$vmx_source" ||
	    fail "production VMX runtime does not call $symbol"
done

# A declaration or local definition must not satisfy the run-loop gate.  Pin
# representative call-site shapes at each destructive ownership boundary.
for call_site in \
    'return (vmx_run_nested(vcpu, rip, pmap, evinfo,' \
    'error = vmx_nested_context_commit_vmentry_instruction(' \
    'error = vmx_nested_vmcs02_resources_intel_acquire(vcpu,' \
    'error = vmx_nested_hardware_entry_prepare(' \
    'vmx_nested_run_pmap_activate(vmx, &run_pmap);' \
    'rc = vmx_enter_guest(vmxctx, vmx, launched);' \
    'vmx_nested_run_pmap_deactivate(vmx, &run_pmap);' \
    'error = vmx_nested_hardware_report_intel(vcpu, rc,' \
    'error = vmx_nested_context_publish_vmexit(&vcpu->nested, id,' \
    'error = vmx_nested_hot_exit_freeze_publish('
do
	rg -q -F "$call_site" "$vmx_source" ||
	    fail "production VMX runtime is missing call site: $call_site"
done

# private-test: hardware-report-sum-type
# The private hardware-attempt result is a closed sum type, not a loose bag of
# independently valid fields.  Pin validation at the destructive consumer so
# stale rejection state cannot accompany a proven L2 exit or an L0 failure.
hardware_result="$src/sys/amd64/vmm/intel/vmx_nested_hardware_result.c"
hardware_entry="$src/sys/amd64/vmm/intel/vmx_nested_hardware_entry.c"
rg -q -F 'vmx_nested_hardware_report_result_validate(' "$hardware_result" ||
    fail "hardware report result has no semantic validator"
rg -q -F 'return (nvmxhr_rejection_empty(&result->rejection) ? 0 : EPROTO);' \
    "$hardware_result" ||
    fail "non-rejection hardware reports do not require an empty rejection"
rg -q -F 'vmx_nested_hardware_report_result_validate(report) != 0' \
    "$hardware_entry" ||
    fail "hardware entry mutates state before validating the complete report"
rg -q -F 'vmx_nested_hardware_report_result_validate(&report),' \
    "$test_source" ||
    fail "hardware report sum-type negative test is missing"
rg -q -U --pcre2 \
    'entry_msr_count == 0 \|\| exit_qualification == 0 \|\|[[:space:]]*exit_qualification > entry_msr_count' \
    "$src/sys/amd64/vmm/intel/vmx_nested_vmentry.c" ||
    fail "hardware MSR-load failure qualification is not Intel one-based"
rg -q -F '(UINT32_C(1) << 31) | 34, 3, 3, &result), 0);' \
    "$test_source" ||
    fail "hardware MSR-load failure does not test the final one-based entry"
rg -q -F '(UINT32_C(1) << 31) | 34, 0, 3, &result), EINVAL);' \
    "$test_source" ||
    fail "hardware MSR-load failure does not reject qualification zero"
rg -q -F 'prove Intel one-based qualifications 1 and count' \
    "$live_ledger" ||
    fail "live VM-entry qualification omits one-based MSR failure evidence"

# A failed VMCLEAR cannot be returned as an ordinary adapter error: hardware
# may still associate the VMCS with the pinned CPU, and the caller cannot
# repair that association after dropping the pin.  Pin both kernel-only
# cleanup boundaries and require the staged residency marker to be cleared
# only after the fail-stop check.
entry_environment_intel="$src/sys/amd64/vmm/intel/vmx_nested_entry_environment_intel.c"
vmcs02_intel="$src/sys/amd64/vmm/intel/vmx_nested_vmcs02_intel.c"
rg -q -F 'panic("%s: cannot detach captured VMCS01: %d"' \
    "$entry_environment_intel" ||
    fail "standalone VMCS01 capture does not fail stop on VMCLEAR failure"
rg -q -F 'panic("%s: cannot detach VMCS02: %d"' "$vmcs02_intel" ||
    fail "destructive VMCS02 capture does not fail stop on VMCLEAR failure"
rg -q -F 'panic("%s: cannot restore current VMCS01"' "$vmcs02_intel" ||
    fail "destructive VMCS02 cleanup does not fail stop on VMPTRLD failure"
rg -q -F 'panic("%s: cannot clear VMCS02 launch ownership"' \
    "$vmcs02_intel" ||
    fail "hardware detach and software VMCS02 ownership are not atomic"
rg -q -U --pcre2 \
    'vmx_nested_l2_intel_clear_unpin\([\s\S]*?error = vmclear\(transaction->vcpu->vmcs\);[\s\S]*?if \(error != VM_SUCCESS\)[\s\S]*?panic\("%s: cannot detach VMCS01: %d"[\s\S]*?transaction->critical_held = false;' \
    "$vmx_source" ||
    fail "staged VMCS01 cleanup can publish detachment before VMCLEAR succeeds"

# Model and build coverage must never silently turn the experimental ABI on.
# Live qualification enables the read-only-at-runtime loader tunable before
# boot and opts an individual VM into the VM-wide capability explicitly.
# private-test: default-off
rg -q '^static int nested_vmx_allowed;$' "$vmx_source" ||
    fail "nested VMX host policy is not statically default-off"
rg -q 'SYSCTL_INT\(_hw_vmm_vmx, OID_AUTO, nested, CTLFLAG_RDTUN,' \
    "$vmx_source" ||
    fail "nested VMX host policy is not a loader-only tunable"
rg -q '^static int nested_vpid_qualification;$' "$vmx_source" ||
    fail "nested VPID qualification policy is not statically default-off"
rg -q 'SYSCTL_INT\(_hw_vmm_vmx, OID_AUTO, nested_vpid, CTLFLAG_RDTUN,' \
    "$vmx_source" ||
    fail "nested VPID qualification policy is not a loader-only tunable"
rg -q -F 'VMX_NESTED_POLICY_F_QUALIFY_VPID;' "$vmx_source" ||
    fail "nested VPID qualification policy is not connected to capabilities"

# guest-memory-bounds: this is a private frozen-adapter resource contract,
# not an Intel architectural limit.  Keep both the byte and scatter/gather
# bounds explicit and require every mapped segment to be torn down on all
# successful and failed copy paths.
guest_memory_intel="$src/sys/amd64/vmm/intel/vmx_nested_guest_memory_intel.c"
rg -q -F '#define	NVMX_GUEST_MEMORY_MAX_LENGTH	PAGE_SIZE' \
    "$guest_memory_intel" ||
    fail "nested Intel guest-memory byte bound changed without review"
rg -q -F '#define	NVMX_GUEST_MEMORY_MAX_SEGMENTS	2' \
    "$guest_memory_intel" ||
    fail "nested Intel guest-memory segment bound changed without review"
rg -q -F 'vm_copy_teardown(copyinfo, nitems(copyinfo));' \
    "$src/sys/amd64/vmm/intel/vmx_nested_instruction_runtime.c" ||
    fail "nested instruction operand mappings are not unconditionally torn down"
rg -q -U --pcre2 \
    'VMX_NESTED_INSTRUCTION_VMXON \|\|[\s\S]*?VMX_NESTED_INSTRUCTION_VMCLEAR \|\|[\s\S]*?VMX_NESTED_INSTRUCTION_VMPTRLD\)[\s\S]*?nvmx_ih_linear_read\([\s\S]*?sizeof\(uint64_t\)\);' \
    "$src/sys/amd64/vmm/intel/vmx_nested_instruction_handoff.c" ||
    fail "VMX region-pointer instructions do not read exactly 8 bytes"
rg -q -U --pcre2 \
    'case VMX_NESTED_INSTRUCTION_VMPTRST:[\s\S]*?nvmx_ih_linear_write\([\s\S]*?sizeof\(uint64_t\)\);' \
    "$src/sys/amd64/vmm/intel/vmx_nested_instruction_handoff.c" ||
    fail "VMPTRST does not write exactly its architectural 8-byte operand"
rg -q -F 'vm_gpa_hold' "$guest_memory_intel" ||
    fail "nested Intel guest-memory adapter no longer holds mapped pages"
rg -q -F 'vm_gpa_release' "$guest_memory_intel" ||
    fail "nested Intel guest-memory adapter does not release held pages"
rg -q -F 'sysctl -n hw.vmm.vmx.initialized' "$live_runner" ||
    fail "nested live qualification does not require the Intel VMX backend"
if rg -q -F 'machdep.cpu_vendor' "$live_runner"; then
	fail "nested live qualification uses a nonexistent FreeBSD vendor sysctl"
fi
rg -q -F 'sysctl -n hw.vmm.vmx.nested_vpid' "$live_runner" ||
    fail "nested live qualification does not require the VPID opt-in"
rg -q -F 'export NESTED_VPID_QUALIFICATION=$vpid_qualification' \
    "$live_runner" ||
    fail "nested live qualification does not bind the boot policy to L1"
rg -q -F 'vmx-nested-default-policy-live-qualification.tsv' \
    "$live_runner" ||
    fail "nested live qualification cannot select the default-off ledger"
rg -q -F 'host-policy.tsv' "$live_runner" ||
    fail "nested live qualification does not publish its boot policy"
rg -q -F 'kernel_version_sha256' "$live_runner" ||
    fail "nested live qualification does not bind the kernel build"
rg -q -F 'vmm_module_sha256' "$live_runner" ||
    fail "nested live qualification does not bind the vmm module image"
rg -q -F 'NESTED_LIVE_TIMEOUT' "$live_runner" ||
    fail "nested live qualification does not bound the external L1 runner"
rg -q -F 'NESTED_SNAPSHOT_SESSION_TIMEOUT' "$live_runner" ||
    fail "nested live qualification does not bound the snapshot-session preflight"
rg -q -F 'trusted_executable "$NESTED_SNAPSHOT_SESSION_TEST"' "$live_runner" ||
    fail "nested live qualification does not bind a trusted snapshot-session test"
rg -q -F 'trusted_executable "$NESTED_STARTUP_STAGING_TEST"' "$live_runner" ||
    fail "nested live qualification does not bind a trusted startup-staging test"
rg -q -F 'if [ -x /usr/obj/usr/src/amd64.amd64/tests/sys/vmm/vmm_snapshot_session_live_test ]; then' \
    "$live_runner" ||
    fail "nested live qualification does not prefer the source-built snapshot-session test"
rg -q -F 'if [ -x /usr/obj/usr/src/amd64.amd64/tests/sys/vmm/vmm_startup_staging_live_test ]; then' \
    "$live_runner" ||
    fail "nested live qualification does not prefer the source-built startup-staging test"
rg -q -F 'run_root_vmm_preflight snapshot-session "$snapshot_session_test"' \
    "$live_runner" ||
    fail "nested live qualification omits the mandatory snapshot-session preflight"
rg -q -F 'run_root_vmm_preflight startup-staging "$startup_staging_test"' \
    "$live_runner" ||
    fail "nested live qualification omits the mandatory startup-staging preflight"
rg -q -F 'trap cleanup EXIT' "$live_runner" ||
    fail "nested live qualification does not clean unpublished evidence"
rg -q -F 'rm -rf -- "$staged_result"' "$live_runner" ||
    fail "nested live cleanup is not scoped to its staging directory"
rg -q -F 'vmx-nested-default-policy-live-qualification.tsv' \
    "$policy_pair_validator" ||
    fail "policy-pair validator does not require the default-off ledger"

header=$(sed -n '1p' "$ledger")
[ "$header" = "$(printf 'requirement_id\tauthority\tsection\trequirement\tcode\ttest\tstatus')" ] ||
	fail "invalid header"

awk -F '	' '
NR == 1 { next }
NF != 7 {
	printf "%s:%d: expected 7 fields, found %d\n", FILENAME, NR, NF
	bad = 1
}
$1 !~ /^NVMX-[A-Z]+-[0-9][0-9][0-9]$/ {
	printf "%s:%d: malformed requirement id %s\n", FILENAME, NR, $1
	bad = 1
}
seen[$1]++ {
	printf "%s:%d: duplicate requirement id %s\n", FILENAME, NR, $1
	bad = 1
}
$3 == "" || $4 == "" || $5 == "" || $6 == "" {
	printf "%s:%d: empty traceability field\n", FILENAME, NR
	bad = 1
}
$7 != "foundation-tested-experimental" &&
$7 != "experimental-pending-live" && $7 != "pending" {
	printf "%s:%d: unsupported status %s\n", FILENAME, NR, $7
	bad = 1
}
END { exit bad }
' "$ledger" || fail "ledger structure failed"

live_header=$(sed -n '1p' "$live_ledger")
[ "$live_header" = "$(printf 'feature_id\trequirement_ids\tlinux_l2_status\tlinux_l2_evidence\tfivebsd_l2_status\tfivebsd_l2_evidence\thost_evidence\tnotes')" ] ||
	fail "invalid live qualification header"
rg -q -F "$(printf 'VMX-INSTRUCTIONS\tNVMX-INST-001;NVMX-INST-002;NVMX-INST-003;NVMX-INST-004;NVMX-INST-005;NVMX-INST-006;NVMX-INST-007;NVMX-INST-008;NVMX-INST-009;NVMX-INST-010\t')" \
    "$live_ledger" ||
    fail "nested live VMX-instruction group does not cover every instruction requirement"
rg -q -F 'place VMXON VMCLEAR VMPTRLD and VMPTRST operands at page boundaries with adjacent canaries' \
    "$live_ledger" ||
    fail "nested live VMX-instruction group lacks exact operand-width qualification"

awk -F '	' '
function status_ok(value) {
	return value == "exercised" || value == "pending" ||
	    value == "driver-gap"
}
function evidence_ok(value) {
	return value ~ /^[A-Za-z0-9_.-]+:[A-Za-z0-9_.+,-]+$/
}
NR == 1 { next }
NF != 8 {
	printf "%s:%d: expected 8 live fields, found %d\n",
	    FILENAME, NR, NF
	bad = 1
	next
}
$1 !~ /^[A-Z0-9][A-Z0-9-]*$/ || seen[$1]++ {
	printf "%s:%d: invalid or duplicate live feature %s\n",
	    FILENAME, NR, $1
	bad = 1
}
!status_ok($3) || !status_ok($5) {
	printf "%s:%d: invalid live status\n", FILENAME, NR
	bad = 1
}
($3 == "exercised") != ($4 != "-") ||
($5 == "exercised") != ($6 != "-") {
	printf "%s:%d: live evidence/status disagree\n", FILENAME, NR
	bad = 1
}
$3 == "exercised" && !evidence_ok($4) {
	printf "%s:%d: invalid Linux L2 evidence\n", FILENAME, NR
	bad = 1
}
$5 == "exercised" && !evidence_ok($6) {
	printf "%s:%d: invalid 5BSD L2 evidence\n", FILENAME, NR
	bad = 1
}
($3 == "exercised" || $5 == "exercised") &&
($7 == "-" || !evidence_ok($7)) {
	printf "%s:%d: exercised feature lacks host evidence\n",
	    FILENAME, NR
	bad = 1
}
$8 == "" {
	printf "%s:%d: live feature lacks notes\n", FILENAME, NR
	bad = 1
}
END { exit bad }
' "$live_ledger" || fail "live qualification ledger structure failed"

# A count alone does not show which mandatory proof obligation disappeared or
# was silently replaced.  Keep the inventory explicit and order-independent:
# a new feature must be deliberately added here, while a renamed, missing, or
# unexpected feature fails before any root-only evidence is accepted.
expected_live_features=$(printf '%s\n' \
	EXPOSURE-POLICY VMX-INSTRUCTIONS VM-ENTRY-VALIDATION EXIT-REFLECTION \
	EPT-INVEPT VPID-INVVPID INTERRUPT-APIC TIMER-TSC \
	STARTUP-OWNER-LIFECYCLE ACTIVE-CHECKPOINT CONCURRENCY-SOAK \
	CHECKPOINT-PUBLICATION | sort)
actual_live_features=$(awk -F '\t' 'NR > 1 { print $1 }' "$live_ledger" | sort)
[ "$actual_live_features" = "$expected_live_features" ] ||
	fail "live qualification feature inventory changed without an explicit review"

default_live_header=$(sed -n '1p' "$default_live_ledger")
[ "$default_live_header" = "$live_header" ] ||
	fail "invalid default-policy live qualification header"
awk -F '\t' '
NR == 1 { next }
NF != 8 || $1 != "VPID-DEFAULT-OFF" || seen[$1]++ ||
    $2 == "" || $3 != "pending" || $4 != "-" ||
    $5 != "pending" || $6 != "-" || $7 != "-" || $8 == "" {
	bad = 1
}
END { if (NR != 2) bad = 1; exit bad }
' "$default_live_ledger" ||
    fail "default-policy live qualification ledger structure failed"

live_requirements=$(awk -F '	' 'NR > 1 {
	n = split($2, item, ";")
	for (i = 1; i <= n; i++)
		print item[i]
}' "$live_ledger" | sort -u)
default_live_requirements=$(awk -F '	' 'NR > 1 {
	n = split($2, item, ";")
	for (i = 1; i <= n; i++)
		print item[i]
}' "$default_live_ledger" | sort -u)
ledger_ids=$(awk -F '	' 'NR > 1 { print $1 }' "$ledger")
for requirement in $live_requirements $default_live_requirements; do
	echo "$ledger_ids" | grep -qx "$requirement" ||
	    fail "live feature references missing requirement $requirement"
done
sh "$live_coverage" "$ledger" "$live_ledger" ||
    fail "pending-live hardware qualification coverage failed"

# Evidence uses case-id:assertion.  An exercised claim is invalid if the case
# is not a first-class orchestrator entry, even if an ad-hoc run produced a
# similarly named log.
scheduled_cases=$(awk '
/^cases:$/ { in_cases = 1; next }
in_cases && $1 == "-" && $2 == "id:" { print $3 }
' "$manifest")
live_cases=$(awk -F '	' '
function case_id(value, parts) {
	split(value, parts, ":")
	return parts[1]
}
NR > 1 {
	if ($3 == "exercised")
		print case_id($4)
	if ($5 == "exercised")
		print case_id($6)
	if ($3 == "exercised" || $5 == "exercised")
		print case_id($7)
}
' "$live_ledger" | sort -u)
for case_id in $live_cases; do
	echo "$scheduled_cases" | grep -qx "$case_id" ||
	    fail "live evidence references unscheduled case $case_id"
done

references=$(awk -F '	' 'NR > 1 { print $1 }' "$corpus")
authorities=$(awk -F '	' 'NR > 1 { print $2 }' "$ledger" |
    tr ';' '\n' | sort -u)
for authority in $authorities; do
	case "$authority" in
	WASPNEST-POLICY)
		continue
		;;
	esac
	echo "$references" | grep -qx "$authority" ||
	    fail "authority $authority is not an immutable corpus id"
done

codes=$(awk -F '	' '
NR > 1 {
	n = split($5, item, ";")
	for (i = 1; i <= n; i++)
		if (item[i] ~ /^[A-Za-z_][A-Za-z0-9_]*$/)
			print item[i]
}
' "$ledger" | sort -u)
# Build one exact C-identifier index for the complete implementation scope.
# Searching the tree once per ledger symbol made this otherwise rootless gate
# needlessly proportional to both source size and ledger size.  A sorted set
# comparison retains the prior whole-token semantics without treating a
# substring as a mapped implementation boundary.
printf '%s\n' "$codes" > "$inventory/ledger-symbols"
LC_ALL=C rg -o -w --no-filename -f "$inventory/ledger-symbols" \
    "$src/sys" "$src/usr.sbin" "$src/lib/libvmmapi" | LC_ALL=C sort -u \
	> "$inventory/implementation-symbols"
missing_symbols=$(comm -23 "$inventory/ledger-symbols" \
	"$inventory/implementation-symbols")
if [ -n "$missing_symbols" ]; then
	echo "$missing_symbols" >&2
	fail "one or more implementation symbols are absent"
fi

# The doubled kernel review is source-complete only when every production
# nested component has at least one exported boundary named by the normative
# requirement ledger.  A file that is merely compiled or indirectly reached
# can otherwise escape both requirement ownership and focused test review.
for source_file in "$src"/sys/amd64/vmm/intel/vmx_nested_*.c; do
	exported=$(sed -n \
	    's/^\(vmx_nested_[A-Za-z0-9_]*\)(.*/\1/p' "$source_file" |
	    sort -u)
	[ -n "$exported" ] || continue
	if ! printf '%s\n' "$exported" |
	    grep -Fqx -f "$inventory/ledger-symbols"; then
		fail "nested source $(basename "$source_file") has no ledger-mapped exported boundary"
	fi
done
echo "nested-vmx requirements: every production nested source is ledger-mapped"
# private-test: production-source-inventory

# A nested implementation source that is intentionally excluded from vmm.ko
# is still reviewed and ledger-mapped, but must say so in its own source.
# This prevents a model-only prerequisite from being mistaken for a compiled
# runtime bridge (or an accidentally omitted runtime source from being hidden
# among the model files).
for source_file in "$src"/sys/amd64/vmm/intel/vmx_nested_*.c; do
	base=$(basename "$source_file")
	if rg -q -F "$base" "$src/sys/modules/vmm/Makefile"; then
		continue
	fi
	rg -q -i 'model-only' "$source_file" &&
	    rg -q 'not linked into vmm[.]ko' "$source_file" ||
	    fail "unlinked nested source $base lacks a model-only declaration"
done
echo "nested-vmx requirements: unlinked nested sources are explicitly model-only"
# private-test: nested-build-membership

# Synthetic CPU-model identifiers are private ABI, not Intel constants.  A
# test which imports the implementation macro would approve an accidental ABI
# change by construction.  Require the independent fixture and inventory row.
if rg -q -w 'VMX_NESTED_VIRTUAL_REVISION_ID' "$test_source"; then
	fail "nested test imports the implementation virtual revision identifier"
fi
rg -q -w 'NVMX_TEST_VIRTUAL_REVISION_ID' "$test_source" ||
    fail "nested test lacks an independent virtual revision fixture"
rg -q -F 'vmx_nested_caps.h:VMX_NESTED_VIRTUAL_REVISION_ID' \
    "$private_ledger" || fail "virtual revision private ABI is not inventoried"

# private-test: instruction-completion-bridge
# The value-only model proves the cold portable transaction, but it cannot
# link the machine-independent kernel VMM.  Pin the production bridge which
# supplies that transaction: it must be frozen-only, return the common
# decoder's exit RIP/decoded length/nextrip tuple, and invoke the portable
# commit before destination-local thaw.  An EPT VM-exit instruction length is
# not an architectural completion oracle and must never be substituted here.
python3 - "$vmm_source" "$vmx_source" <<'PY' ||
import re
import sys

vmm = open(sys.argv[1], encoding="utf-8").read()
vmx = open(sys.argv[2], encoding="utf-8").read()

getter = re.search(
    r"vm_get_instruction_completion\([^\)]*\)\s*\{(?P<body>.*?)\n\}",
    vmm, re.S)
if getter is None:
    raise SystemExit(1)
body = getter.group("body")
for required in (
    "vcpu_get_state(vcpu, NULL) != VCPU_FROZEN",
    "*rip = vcpu->exitinfo.rip",
    "*inst_length = vcpu->exitinfo.inst_length",
    "*nextrip = vcpu->nextrip",
):
    if required not in body:
        raise SystemExit(1)

handler = re.search(
    r"vmx_nested_handle_continuation_frozen\([^\)]*\)\s*\{"
    r"(?P<body>.*?)\n\}", vmx, re.S)
if handler is None:
    raise SystemExit(1)
body = handler.group("body")
getpos = body.find("vm_get_instruction_completion(")
commitpos = body.find("vmx_nested_l2_portable_complete_instruction(")
thawpos = body.find("vmx_nested_l0_thaw_prepare_intel(")
if getpos < 0 or commitpos <= getpos or thawpos <= commitpos:
    raise SystemExit(1)
bridge = body[getpos:thawpos]
if ("attempt.exit.exit_instruction_length" in bridge or
    "exit_instruction_length" in bridge):
    raise SystemExit(1)
PY
    fail "nested L2 instruction-completion bridge is not source-pinned"

# private-test: pending-mtf-publication-transaction
# Pending MTF is a private versioned continuation contract until live Intel
# qualification permits exposure.  Pin all three layers independently: the
# generation-bound owner, the VMCS12 control dependency, and the outer/inner
# checkpoint agreement.  The test uses literal SDM bit and exit numbers.
portable_source="$src/sys/amd64/vmm/intel/vmx_nested_l2_portable.c"
event_source="$src/sys/amd64/vmm/intel/vmx_nested_event.c"
l2_state_source="$src/sys/amd64/vmm/intel/vmx_nested_l2_state.c"
continuation_state_source="$src/sys/amd64/vmm/intel/vmx_nested_l2_continuation_state.c"
checkpoint_source="$src/sys/amd64/vmm/intel/vmx_nested_checkpoint.c"
rg -q -F 'if (state->mtf_pending)' "$portable_source" ||
    fail "portable instruction completion does not serialize pending MTF"
rg -q -F 'vmx_nested_l2_portable_mtf_peek(' "$portable_source" ||
    fail "immutable pending MTF exit construction is missing"
rg -q -F 'vmx_nested_l2_portable_mtf_commit(' "$portable_source" ||
    fail "generation-bound pending MTF commit is missing"
rg -q 'NVMX-PRIVATE-055.*pending-MTF-publication-transaction' \
    "$private_ledger" ||
    fail "pending MTF publication transaction is absent from private ledger"

# private-test: pending-mtf-hot-fail-closed
# Entry, direct reflection, and refreeze owners are connected, but DEFER still
# needs a no-entry retry boundary and DISCARD needs authoritative
# INIT-in-wait-for-SIPI provenance.  Until both exist, every non-NONE
# post-thaw plan remains fail-closed and MTF remains unadvertised.
for contract in \
    'vmx_nested_mtf_snapshot_intel(' \
    'vmx_nested_mtf_input_from_snapshot(&mtf_snapshot' \
	'nested_l2_portable.mtf_pending, false, false' \
    'event->mtf_plan.action != VMX_NESTED_MTF_NONE' \
    'error = EOPNOTSUPP'; do
	rg -q -F "$contract" "$vmx_source" ||
	    fail "pending MTF hot bridge is not fail-closed: $contract"
done
for mapping in \
    'VM_EXCEPTION_NONE:[\s\S]*?VMX_NESTED_EXCEPTION_NONE' \
    'VM_EXCEPTION_FAULT:[\s\S]*?VMX_NESTED_EXCEPTION_FAULT' \
    'VM_EXCEPTION_TRAP:[\s\S]*?VMX_NESTED_EXCEPTION_TRAP' \
    'VM_EXCEPTION_ICEBP:[\s\S]*?VMX_NESTED_EXCEPTION_ICEBP' \
    'VM_EXCEPTION_TASK_SWITCH:[\s\S]*?VMX_NESTED_EXCEPTION_TASK_SWITCH'; do
	rg -q -U --pcre2 "$mapping" "$vmx_source" ||
	    fail "pending MTF hot bridge lacks provenance mapping: $mapping"
done
rg -q 'NVMX-PRIVATE-059.*pending-MTF-hot-fail-closed' \
    "$private_ledger" ||
    fail "pending MTF fail-closed bridge is absent from private ledger"

# private-test: hot-mtf-owner-transaction
# A deferred MTF cannot remain in the portable rollback image after hardware
# has entered L2 because that image is then destroyed.  Pin the independent
# runtime owner and its bidirectional, generation-bound transfer operations.
# The production adapter is pinned separately below; exposure remains disabled
# until the retry/discard boundary and live Intel evidence exist.
mtf_owner_source="$src/sys/amd64/vmm/intel/vmx_nested_mtf_owner.c"
for contract in \
    'vmx_nested_mtf_owner_take_portable(' \
    'vmx_nested_mtf_owner_put_portable(' \
    'vmx_nested_mtf_owner_peek(' \
    'vmx_nested_mtf_owner_consume(' \
    'vmx_nested_mtf_owner_reflect(' \
    'vmx_nested_mtf_owner_resolve(' \
    'origin_generation != owner->origin_generation' \
    'portable->portable_generation <= owner->origin_generation' \
    'vmx_nested_vmcs02_id_equal(&owner->id, id)' \
	'nvmx_mtf_plan_matches_portable(plan, portable)' \
	'(plan->image.controls.primary & NVMX_MTF_PRIMARY_CONTROL) != 0' \
	'vmx_nested_state_ranges_overlap(owner, sizeof(*owner), id' \
	'vmx_nested_state_ranges_overlap(id, sizeof(*id), plan' \
	'case VMX_NESTED_MTF_DEFER:' \
	'case VMX_NESTED_MTF_DISCARD:' \
	'case VMX_NESTED_MTF_REFLECT:' \
    'candidate.exit_reason = NVMX_MTF_EXIT_REASON'; do
	rg -q -F "$contract" "$mtf_owner_source" ||
	    fail "hot MTF owner contract is missing: $contract"
done
rg -q 'NVMX-PRIVATE-061.*hot-MTF-runtime-owner' "$private_ledger" ||
    fail "hot MTF runtime owner is absent from private ledger"
for anchor in \
    'vmx_nested_mtf_owner_take_portable(&mtf_owner' \
	'&completed, &no_mtf_plan, completed.portable_generation' \
    'vmx_nested_mtf_owner_put_portable(&mtf_owner' \
	'&next_cold, &no_mtf_plan), ESTALE' \
    'vmx_nested_mtf_owner_peek(&mtf_owner' \
    'vmx_nested_mtf_owner_consume(&mtf_owner' \
    'vmx_nested_mtf_owner_resolve(&mtf_owner' \
    '&resolve_owner.id, resolve_owner.origin_generation' \
	'resolve_plan.action = VMX_NESTED_MTF_DEFER' \
	'resolve_plan.action = VMX_NESTED_MTF_DISCARD' \
	'.action = VMX_NESTED_MTF_REFLECT' \
    'mtf_fixture.reentry_error, EBUSY' \
    'stale_id.execution_epoch++'; do
	rg -q -F "$anchor" "$test_source" ||
	    fail "hot MTF owner test anchor is missing: $anchor"
done
for contract in \
    'CPU-pinned, single-threaded transaction object' \
    'Publication completes synchronously' \
    'must not retain any' \
    'must not sleep'; do
	rg -q -F "$contract" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_mtf_owner.h" ||
	    fail "hot MTF owner callback contract is missing: $contract"
done
rg -q -F 'vmx_nested_mtf_plan(' "$event_source" ||
    fail "pending MTF lacks a value-only priority planner"
rg -q -F '(unsigned int)input->debug_event >' "$event_source" ||
    fail "pending MTF debug-source domain is not closed"
rg -q -U --pcre2 \
    'nested_entry_pending[\s\S]*?reinjection_pending[\s\S]*?VMX_NESTED_MTF_DEFER[\s\S]*?init_processed_in_wait_for_sipi[\s\S]*?VMX_NESTED_MTF_DISCARD[\s\S]*?high_priority_non_debug_pending[\s\S]*?VMX_NESTED_MTF_DEFER[\s\S]*?VMX_NESTED_MTF_REFLECT' \
    "$event_source" ||
    fail "pending MTF priority or wait-for-SIPI discard ordering changed"
rg -q -F 'capability_signature != state->capability_signature' \
    "$portable_source" ||
    fail "portable completion does not bind the current capability policy"
if rg -q -F 'NVMXL2S_VERSION_LEGACY' "$l2_state_source"; then
    fail "portable-state retained an obsolete v1 decoder"
fi
if rg -q -F 'NVMXL2CS_VERSION_LEGACY' "$continuation_state_source"; then
    fail "continuation-state retained an obsolete v1 decoder"
fi
rg -q -F 'candidate_portable.mtf_pending !=' "$checkpoint_source" ||
    fail "active checkpoint does not cross-check outer and inner MTF state"
rg -q -F 'NVMXCP_PRIMARY_MTF' "$checkpoint_source" ||
    fail "active checkpoint does not bind pending MTF to VMCS12 controls"
# Active capture publishes both its state view and the caller's VMCS field
# storage only after all frozen-context validation has succeeded.  Keep a
# direct model proof for the early lifecycle, malformed-handoff, and stale
# continuation rejections: changing either output before returning would make
# a retry serialize a mixed image.
rg -q -U --pcre2 \
    'memset\(captured_fields, 0x5a, sizeof\(captured_fields\)\);[\s\S]*?memcpy\(captured_before, captured_fields, sizeof\(captured_before\)\);[\s\S]*?vmx_nested_checkpoint_active_capture\([\s\S]*?EBUSY\);[\s\S]*?memcmp\(&state, &state_before, sizeof\(state\)\), 0\);[\s\S]*?memcmp\(captured_fields, captured_before,[\s\S]*?sizeof\(captured_fields\)\), 0\);[\s\S]*?VMX_NESTED_CONTINUATION_HANDOFF_RESOLVED;[\s\S]*?vmx_nested_checkpoint_active_capture\([\s\S]*?EPROTO\);[\s\S]*?memcmp\(captured_fields, captured_before,[\s\S]*?sizeof\(captured_fields\)\), 0\);[\s\S]*?exit_sequence\+\+;[\s\S]*?vmx_nested_checkpoint_active_capture\([\s\S]*?ESTALE\);[\s\S]*?memcmp\(captured_fields, captured_before,[\s\S]*?sizeof\(captured_fields\)\), 0\);' \
    "$test_source" ||
    fail "active checkpoint capture lacks output-atomic rejection coverage"

# The active restore publishes continuation and VMCS12 snapshot values in one
# final transaction.  They are distinct caller-owned outputs, so their ranges
# must be disjoint before a registry owner can be selected.  Keep both the
# source boundary and the direct alias regression in the review gate.
rg -q -U --pcre2 \
    'vmx_nested_checkpoint_active_context_restore\([\s\S]*?vmx_nested_state_ranges_overlap\(continuation, sizeof\(\*continuation\),[\s\S]*?snapshot, sizeof\(\*snapshot\)\)' \
    "$checkpoint_source" ||
    fail "active checkpoint restore permits continuation/snapshot output overlap"
rg -q -U --pcre2 \
    'continuation_before = restored_continuation;[\s\S]*?vmx_nested_checkpoint_active_context_restore\([\s\S]*?\(struct vmx_nested_vmcs12_snapshot \*\)\(void \*\)&restored_continuation,[\s\S]*?EINVAL\);[\s\S]*?memcmp\(&restored_continuation, &continuation_before,[\s\S]*?sizeof\(restored_continuation\)\), 0\);[\s\S]*?vmx_nested_vmcs_registry_owner_active\(&destination, 19,[\s\S]*?ATF_CHECK\(!owner_active\);' \
    "$test_source" ||
    fail "active checkpoint restore lacks continuation/snapshot alias coverage"

# private-test: production-mtf-owner-adapter
# A real resumed VM exit is the only cold-to-hot commit point.  Every hot
# freeze must put the owner into the newly captured, strictly newer portable
# image before publishing it, and direct nested-exit publication must consume
# the exact owner only after publication succeeds.
python3 - "$vmx_source" <<'PY' ||
import re
import sys

source = open(sys.argv[1], encoding="utf-8").read()

def body(name):
    match = re.search(r"\n(?:static\s+)?(?:int|void)\s*\n" +
        re.escape(name) + r"\s*\([^;]*?\)\s*\{", source, re.S)
    if match is None:
        raise SystemExit(1)
    start = match.end() - 1
    depth = 0
    for pos in range(start, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[start + 1:pos]
    raise SystemExit(1)

freeze = body("vmx_nested_l0_freeze_intel")
put = freeze.find("vmx_nested_mtf_owner_put_portable(")
publish = freeze.find("vcpu->nested_l2_portable = portable;")
if put < 0 or publish <= put:
    raise SystemExit(1)

entered = body("vmx_nested_l0_resume_entered_intel")
take = entered.find("vmx_nested_mtf_owner_take_portable(")
resolve = entered.find("vmx_nested_l0_continuation_resolve(")
destroy = entered.find("memset(&vcpu->nested_l2_portable")
if take < 0 or resolve <= take or destroy <= resolve:
    raise SystemExit(1)

wrapper = body("vmx_nested_publish_reflected_exit_hot")
if ("vmx_nested_mtf_owner_reflect(" not in wrapper or
        "vmx_nested_publish_reflected_exit_hot_raw(" not in wrapper or
        "vmx_nested_mtf_owner_consume(" not in wrapper):
    raise SystemExit(1)

callback = body("vmx_nested_publish_mtf_exit_hot")
if ("vmx_nested_vmcs02_id_equal" not in callback or
		"VMX_EXIT_REASON_BASIC_MASK" not in callback or
		"publish->expected" not in callback or
		"vmx_nested_publish_reflected_exit_hot_raw" not in callback):
    raise SystemExit(1)

synthetic = body("vmx_nested_publish_hot_synthetic_event_intel")
publication = synthetic.find("vmx_nested_context_publish_vmexit(")
consume = synthetic.find("vmx_nested_mtf_owner_consume(")
event_commit = synthetic.find(
    "vmx_nested_entry_event_intel_commit_reflected(")
if publication < 0 or consume <= publication or event_commit <= consume:
    raise SystemExit(1)

cleanup = body("vmx_vcpu_cleanup")
detached = cleanup.find("if (vcpu->nested_hot_failure_detached)")
runtime_reset = cleanup.find("vmx_nested_entry_runtime_reset(", detached)
workspace_end = cleanup.find("vmx_nested_msr_workspace_end(", runtime_reset)
abandon = cleanup.find("vmx_nested_mtf_owner_consume(", workspace_end)
clear = cleanup.find("vmx_nested_prepared_values_clear(vcpu)", abandon)
if (detached < 0 or runtime_reset <= detached or
        workspace_end <= runtime_reset or abandon <= workspace_end or
        clear <= abandon):
    raise SystemExit(1)
PY
    fail "production MTF owner adapter is not transactionally connected"
rg -q 'NVMX-EVENT-012.*production-mtf-owner-adapter' "$ledger" ||
    fail "production MTF adapter is absent from the requirements ledger"
rg -q 'NVMX-PRIVATE-061.*production-mtf-owner-adapter' "$private_ledger" ||
    fail "production MTF adapter is absent from the private ledger"

rg -q -F '#define	NVMXCP_VERSION	3U' "$checkpoint_source" ||
    fail "nested checkpoint does not require the sole current outer version"
if rg -q 'NVMXCP_(VERSION|L2_CONT_VERSION).*LEGACY' \
    "$checkpoint_source"; then
    fail "nested checkpoint retained an obsolete compatibility decoder"
fi
for anchor in \
    'frozen.image.controls.primary |= UINT32_C(1) << 27' \
    'ATF_CHECK_EQ(mtf_exit.exit_reason, 37)' \
    'for (mask = 0; mask < 32; mask++)' \
    'debug <= VMX_NESTED_DEBUG_TASK_SWITCH' \
    '(enum vmx_nested_debug_event_class)-1' \
    'input.init_processed_in_wait_for_sipi =' \
    'ATF_TP_ADD_TC(tp, nested_mtf_boundary)' \
    'completed.portable_generation + 1' \
    'before.mtf_pending = true' \
    'stale_capabilities.debugctl_allowed ^= UINT64_C(1)' \
    '(bool *)(void *)&capabilities' \
    '(bool *)(void *)&alias_plan' \
    'Every obsolete outer version is rejected before decoding sections' \
    'Obsolete wrapper and nested versions are rejected transactionally'; do
	rg -q -F "$anchor" "$test_source" ||
	    fail "independent pending-MTF test anchor is missing: $anchor"
done

# private-test: closed-enum-domains
# These internal C enums are not wire formats, but model/fault tests can forge
# their object representations.  A signed negative must not pass an upper-only
# check and fall into the zero/default architectural case.
for anchor in \
    '(unsigned int)plan->kind > VMX_NESTED_EVENT_NMI' \
    '(unsigned int)plan->action > VMX_NESTED_EVENT_ACTION_INJECT_L2' \
    '(unsigned int)input->kind > VMX_NESTED_EVENT_NMI'; do
	rg -q -F "$anchor" "$event_source" ||
	    fail "closed event enum domain is missing: $anchor"
done
rg -q -F '(unsigned int)transition->direction >' \
    "$src/sys/amd64/vmm/intel/vmx_nested_invalidate.c" ||
    fail "closed VPID transition enum domain is missing"
for member in event_source ept_fault_source ept_misconfiguration_source; do
	rg -q -F "(unsigned int)outer->$member" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_reflect.c" ||
	    fail "outer exit enum domain is missing: $member"
	rg -q -F "(unsigned int)provenance->$member" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_reflect.c" ||
	    fail "exit provenance enum domain is missing: $member"
	rg -q -F "(unsigned int)policy->$member" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_reflect.c" ||
	    fail "exit policy enum domain is missing: $member"
	rg -q -F "(unsigned int)context->$member" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_reflect.c" ||
	    fail "exit context enum domain is missing: $member"
done
for anchor in \
    '(enum vmx_nested_event_kind)-1' \
    '(enum vmx_nested_event_action)-1' \
    '(enum vmx_nested_vpid_transition_direction)-1' \
    '(enum vmx_nested_event_source)-1' \
    '(enum vmx_nested_ept_fault_source)-1'; do
	rg -q -F "$anchor" "$test_source" ||
	    fail "negative closed-enum test is missing: $anchor"
done

tests=$(awk -F '	' '
NR > 1 {
	n = split($6, item, ";")
	for (i = 1; i <= n; i++)
		if (item[i] ~ /^[A-Za-z_][A-Za-z0-9_]*$/)
			print item[i]
}
' "$ledger" | sort -u)
for test_case in $tests; do
	if rg -q "ATF_TC(_WITHOUT_HEAD|_WITH_CLEANUP)?\\($test_case\\)" "$test_source"; then
		case_source=$test_source
	elif rg -q "ATF_TC(_WITHOUT_HEAD|_WITH_CLEANUP)?\\($test_case\\)" \
	    "$cpuid_test_source"; then
		case_source=$cpuid_test_source
	elif rg -q "ATF_TC(_WITHOUT_HEAD|_WITH_CLEANUP)?\\($test_case\\)" \
	    "$snapshot_test_source"; then
		case_source=$snapshot_test_source
	elif rg -q "ATF_TC(_WITHOUT_HEAD|_WITH_CLEANUP)?\\($test_case\\)" \
	    "$startup_execution_test_source"; then
		case_source=$startup_execution_test_source
	elif rg -q "ATF_TC(_WITHOUT_HEAD|_WITH_CLEANUP)?\\($test_case\\)" \
	    "$startup_machine_test_source"; then
		case_source=$startup_machine_test_source
	else
	    fail "ATF case $test_case is not declared"
	fi
	rg -q "ATF_TP_ADD_TC\\(tp, $test_case\\)" "$case_source" ||
	    fail "ATF case $test_case is not registered"
done

# The common segment order places TR before LDTR, unlike Intel's VMCS field
# encodings.  Arithmetic derivation silently swaps both segments and has
# caused real snapshot and exit-capture defects; require the checked map.
if rg -n 'VMCS_GUEST_ES_(SELECTOR|LIMIT|ACCESS_RIGHTS|BASE)[[:space:]]*\+[[:space:]]*[^;]*(i|index|segment)' \
    "$src/sys/amd64/vmm/intel"; then
	fail "guest segment VMCS encodings must use the checked field map"
fi

# A VMCS02 identity is an architectural value tuple, not an object
# representation.  Comparing its storage with memcmp() silently introduces
# padding and future-layout dependencies into stale-work fencing.
if rg -n -U --pcre2 \
    'memcmp\((?:(?!;).)*(?:->id|\.id|sizeof\([^)]*id)(?:(?!;).)*\)' \
    "$src/sys/amd64/vmm/intel"/vmx_nested_*.c "$vmx_source"; then
	fail "VMCS02 identities must use field-wise equality"
fi

# VMCS GPA zero is architecturally valid.  Keep every private adapter on the
# shared identity predicate so copied checks cannot drift back to treating
# zero as the internal "no current VMCS" sentinel.
for identity_user in \
    vmx_nested_continuation_handoff.c vmx_nested_continuation.c \
    vmx_nested_vmcs02_lease.c vmx_nested_vmexit_handoff.c \
    vmx_nested_vmentry_handoff.c vmx_nested_entry_runtime.c \
    vmx_nested_vmcs02.c vmx_nested_l1_restore.c \
    vmx_nested_entry_environment.c vmx_nested_l2_portable.c; do
	rg -q -F 'return (vmx_nested_vmcs02_id_valid(id));' \
	    "$src/sys/amd64/vmm/intel/$identity_user" ||
	    fail "$identity_user bypasses the shared VMCS02 identity predicate"
done
rg -q -F '!vmx_nested_vmcs02_id_valid(&record->id)' \
    "$src/sys/amd64/vmm/intel/vmx_nested_l2_continuation_state.c" ||
    fail "L2 continuation decode bypasses the shared VMCS02 identity predicate"
for identity_value_user in vmx_nested_ept_exit.c \
    vmx_nested_vmcs02_program.c vmx_nested_refreeze.c \
    vmx_nested_vmcs02_apply.c vmx_nested_late_entry.c \
    vmx_nested_vmcs02_bind.c; do
	rg -q -F 'vmx_nested_vmcs02_id_valid(' \
	    "$src/sys/amd64/vmm/intel/$identity_value_user" ||
	    fail "$identity_value_user bypasses the shared VMCS02 identity predicate"
done

# Equality is deliberately separate from validity, but it is still one
# private ABI operation.  Require identity-bearing state machines to call the
# shared tuple comparator instead of carrying copies that can omit a future
# identity field.  The context comparator is intentionally excluded because
# it compares an identity to three differently named context fields.
for identity_equal_user in \
    vmx_nested_continuation_handoff.c vmx_nested_continuation.c \
    vmx_nested_vmcs02_lease.c vmx_nested_vmexit_handoff.c \
    vmx_nested_vmentry_handoff.c vmx_nested_entry_runtime.c \
    vmx_nested_vmcs02.c vmx_nested_entry_environment.c \
    vmx_nested_l2_portable.c vmx_nested_l2_continuation_state.c \
    vmx_nested_hardware_entry.c vmx_nested_cold_ept.c \
    vmx_nested_cold_reflect.c vmx_nested_refreeze.c \
    vmx_nested_late_entry.c \
    vmx_nested_vmcs02_bind.c; do
	rg -q -F 'vmx_nested_vmcs02_id_equal(' \
	    "$src/sys/amd64/vmm/intel/$identity_equal_user" ||
	    fail "$identity_equal_user bypasses shared VMCS02 identity equality"
done

# vmx_nested_vmcs02_apply.c carries one identity from the immutable program
# into the result and passes that same object to begin(); it never compares
# two independently sourced identity tuples.  Requiring an equality call in
# that file would reward a vacuous self-comparison and weaken this source
# policy check rather than finding copied tuple comparisons.

# Cross-boundary architectural values may contain compiler padding.  Keep
# ownership and restore validation independent of native object layout.
if rg -n -U --pcre2 \
    'memcmp\((?:(?!;).)*(?:l2_control|l2_arch|pdpte|vmcs02_exit|late_entry|refreeze|vmentry_result|handoff->request)(?:(?!;).)*\)' \
    "$src/sys/amd64/vmm/intel"/vmx_nested_*.c "$vmx_source"; then
	fail "nested architectural values must use field-wise equality"
fi

# All nested wire encoders share one overflow-safe overlap predicate.  Local
# variants have drifted in NULL and address-wrap handling.
if rg -n '(nvmx[a-z0-9_]*_ranges_overlap|vmx_nested_ranges_overlap)' \
    "$src/sys/amd64/vmm/intel"/vmx_nested_*.c; then
	fail "nested checkpoint code must use the common range predicate"
fi
for range_user in vmx_nested_state.c vmx_nested_checkpoint.c \
    vmx_nested_l2_state.c vmx_nested_l2_continuation_state.c \
    vmx_nested_vmcs_registry_state.c vmx_nested_restore_transaction.c \
    vmx_nested_msr_workspace.c vmx_nested_l2_rebuild.c \
    vmx_nested_bitmap.c vmx_nested_vmcs_store.c \
    vmx_nested_vmcs_registry.c; do
	rg -q 'vmx_nested_state_ranges_overlap' \
	    "$src/sys/amd64/vmm/intel/$range_user" ||
	    fail "$range_user does not use the common range predicate"
done
rg -q -F '<dev/vmm/vmm_address_range.h>' \
    "$src/sys/amd64/vmm/intel/vmx_nested_state_range.h" ||
    fail "nested range predicate is detached from common address validation"
rg -q -F 'vmm_address_ranges_overlap' \
    "$src/sys/amd64/vmm/intel/vmx_nested_state_range.h" ||
    fail "nested range predicate reimplemented common address arithmetic"

# Intel validates an ordinary non-all-ones VMCS link pointer even when VMCS
# shadowing is disabled.  Do not regress to treating every link as an opaque
# shadow image or rejecting an otherwise portable active-L2 checkpoint.  The
# same centralized predicate must guard capture and destination rebuild.
for link_state_user in vmx_nested_checkpoint.c vmx_nested_l2_rebuild.c; do
	rg -q 'vmx_nested_link_state_required' \
	    "$src/sys/amd64/vmm/intel/$link_state_user" ||
	    fail "$link_state_user bypasses linked-state dependency policy"
done
if rg -q 'nested_vmcs12_snapshot\.link_pointer' "$vmx_source"; then
	fail "production snapshot must not reject an ordinary VMCS link pointer"
fi

# The per-vCPU capability switch returns retval before it reaches hardware
# programming.  Unsupported fixed RDPID/RDTSCP policy must update that return
# owner, not the later vmwrite status temporary.
if rg -q -U --pcre2 \
    'case VM_CAP_RDPID:(?:(?!break;).)*error = EOPNOTSUPP;' "$vmx_source"; then
	fail "fixed RDPID/RDTSCP capability policy writes the wrong status owner"
fi

# Private policy is reviewed separately from Intel architectural behavior.
# Keep every non-standard interface explicitly owned and classified, and pin
# the fixed CPU-topology bound to the kernel build rather than allowing a
# future larger MAXCPU configuration to fail only after scheduling an L2.
awk -F '\t' '
NR == 1 {
	if ($1 != "id" || $2 != "class" || $3 != "owner" ||
	    $4 != "versioning" || $5 != "default" ||
	    $6 != "authorization" || $7 != "compatibility" ||
	    $8 != "rollback" || $9 != "negative_test" || $10 != "notes")
		bad = 1
	next
}
NF != 10 || $1 !~ /^NVMX-PRIVATE-[0-9][0-9][0-9]$/ ||
    ($2 != "private-implementation" && $2 != "private-adapter" &&
	$2 != "private-management-policy" && $2 != "management-abi" &&
	$2 != "versioned-private-abi" &&
	$2 != "versioned-private-userspace-abi" &&
    $2 != "legacy-private-abi" &&
    $2 != "experimental-guest-interface" &&
    $2 != "private-kernel-interface" &&
    $2 != "private-kernel-lifecycle" &&
    $2 != "private-kernel-policy" &&
    $2 != "private-runtime-contract" &&
    $2 != "private-test-orchestration" &&
    $2 != "withheld-private-compatibility-design" &&
    $2 != "implementation-bound" && $2 != "observability-contract") ||
    $3 == "" || $4 == "" || $5 == "" || $6 == "" || $7 == "" ||
    $8 == "" || $9 == "" || $10 == "" || seen[$1]++ { bad = 1 }
END { if (NR < 2) bad = 1; exit bad }
' "$private_ledger" || fail "non-standard interface ledger structure failed"

# Every claimed private-contract negative test must resolve to either a real
# ATF case in the independent value-model suite or a named semantic anchor in
# a review/self-test script.  This is deliberately stricter than merely
# validating the ledger columns: stale prose cannot count as test evidence.
awk -F '\t' '
NR > 1 {
	n = split($9, tests, ";")
	for (i = 1; i <= n; i++)
		print tests[i]
}
' "$private_ledger" |
while IFS= read -r private_test; do
	case "$private_test" in
	*.sh:*)
		program=${private_test%%:*}
		anchor=${private_test#*:}
		[ -f "$here/$program" ] ||
		    fail "private test script is missing: $program"
		rg -q -F "$anchor" "$here/$program" ||
		    fail "private test anchor is missing: $private_test"
		;;
	*:*)
		program=${private_test%%:*}
		case_name=${private_test#*:}
		source="$here/$program.c"
		if [ ! -f "$source" ]; then
			source="$src/tests/sys/kern/vsock_device_harness/$program.c"
		fi
		[ -f "$source" ] ||
		    fail "private ATF program is missing: $program"
		rg -q "ATF_TC(_WITHOUT_HEAD|_WITH_CLEANUP)?\\($case_name\\)" "$source" ||
		    fail "private ATF case is missing: $private_test"
		;;
	*)
		rg -q "ATF_TC(_WITHOUT_HEAD|_WITH_CLEANUP)?\\($private_test\\)" \
		    "$test_source" ||
		    fail "private model test is missing: $private_test"
		;;
	esac
done

# private-test: pmap-guest-query-dirty-contract
# The amd64 helper is intentionally a small hardware leaf primitive.  It must
# not silently turn software-emulated A/D write permission into dirty state,
# must return the real leaf shape so the common collector can expand it into
# canonical 4 KiB units, and must invalidate the nested context after a clear.
pmap_source="$src/sys/amd64/amd64/pmap.c"
pmap_header="$src/sys/amd64/include/pmap.h"
[ -f "$pmap_source" ] || fail "missing amd64 pmap source"
[ -f "$pmap_header" ] || fail "missing amd64 pmap header"
rg -q 'struct pmap_guest_dirty_leaf' "$pmap_header" ||
    fail "pmap guest dirty leaf result is missing"
rg -q 'pmap_guest_query_dirty\(pmap_t pmap, vm_offset_t va, bool clear' \
    "$pmap_header" || fail "pmap guest dirty query declaration is missing"
rg -q 'pmap_guest_query_dirty\(pmap_t pmap, vm_offset_t va, bool clear' \
    "$pmap_source" || fail "pmap guest dirty query implementation is missing"
rg -q -U --pcre2 \
    'pmap_type_guest\(pmap_t pmap\)[\s\S]*?PT_EPT[\s\S]*?PT_RVI' \
    "$pmap_source" ||
    fail "pmap guest dirty query must retain EPT/NPT pmap parity"
rg -q -U --pcre2 'pmap_emulate_ad_bits\(pmap\)\)\s*\n\s*return \(ENOTSUP\)' \
    "$pmap_source" ||
    fail "pmap guest dirty query must reject emulated A/D"
for token in 'PDPMASK' 'PDRMASK' 'NBPDP' 'NBPDR' \
    'atomic_fcmpset_long' 'pmap_invalidate_page'; do
	rg -q -F "$token" "$pmap_source" ||
	    fail "pmap guest dirty query lacks $token handling"
done

# private-test: dirty-log-backend-ticket-fence
# A future EPT/NPT collector must not guess from owner fields or use a stale
# collection after map/reset/snapshot invalidation.  Keep the check as a
# read-only common contract and require direct owner-model coverage.
dirty_owner_header="$src/sys/dev/vmm/vmm_dirty_log_owner.h"
dirty_owner_source="$src/sys/dev/vmm/vmm_dirty_log_owner.c"
dirty_owner_test="$src/tests/sys/vmm/vmm_dirty_log_owner_test.c"
dirty_mem_header="$src/sys/dev/vmm/vmm_mem.h"
dirty_mem_source="$src/sys/dev/vmm/vmm_mem.c"
rg -q 'vmm_dirty_log_owner_ticket_check' "$dirty_owner_header" ||
    fail "dirty-log backend ticket check declaration is missing"
rg -q 'vmm_dirty_log_owner_ticket_check' "$dirty_owner_source" ||
    fail "dirty-log backend ticket check implementation is missing"
rg -q -U --pcre2 'vmm_dirty_log_owner_ticket_check\([^)]*\)[\s\S]*?return \(ESTALE\)' \
    "$dirty_owner_source" ||
    fail "dirty-log backend ticket check must reject stale tickets"
rg -q 'vmm_dirty_log_owner_ticket_check' "$dirty_owner_test" ||
    fail "dirty-log backend ticket check lacks owner-model coverage"
rg -q -U --pcre2 \
    'vmm_dirty_log_owner_settle\([\s\S]*?vmm_dirty_log_generation_next\([\s\S]*?vmm_dirty_log_owner_exhaust\(&candidate\)[\s\S]*?\*owner = candidate[\s\S]*?return \(error\)' \
    "$dirty_owner_source" ||
    fail "dirty-log clear-generation exhaustion can strand a collecting owner"
rg -q -F 'clear_generation_exhaustion_retires_completed_owner' \
    "$dirty_owner_test" ||
    fail "dirty-log clear-generation exhaustion lacks direct coverage"
rg -q 'vm_mem_dirty_log_ticket_check' "$dirty_mem_header" ||
    fail "dirty-log common ticket fence declaration is missing"
rg -q -U --pcre2 'vm_mem_dirty_log_ticket_check\([^)]*\)[\s\S]*?vm_assert_memseg_xlocked\(vm\)[\s\S]*?vmm_dirty_log_owner_ticket_check' \
    "$dirty_mem_source" ||
    fail "dirty-log common ticket fence must retain the memory lock boundary"

# private-test: wire-format-inventory-replay
# Pass 14 starts from production rather than the ledger.  Every nested source
# which defines private wire magic or a retained wire version must map back to
# an explicitly owned private-interface row; adding a codec without extending
# the inventory is therefore a gate failure.
rg -l '^#define[[:space:]].*(MAGIC|VERSION)' \
    "$src"/sys/amd64/vmm/intel/vmx_nested* |
while IFS= read -r format_source; do
	format_name=${format_source##*/}
	format_owner=${format_name%.*}
	rg -q -F "$format_owner" "$private_ledger" ||
	    fail "private wire format is absent from inventory: $format_name"
done

# private-test: internal-exit-dispatch
# VM_EXITCODE_VMM_INTERNAL is a kernel-private scheduling token.  The common
# run loop must consume it through the backend while the vCPU is frozen and
# must never return that value to the userspace VM_RUN ABI.
rg -q -U --pcre2 \
    'case VM_EXITCODE_VMM_INTERNAL:[[:space:]]*error = vm_handle_internal_exit\(vcpu\);[[:space:]]*break;' \
    "$vmm_source" ||
    fail "kernel-private internal exits can escape the common VM_RUN loop"

# private-test: maxcpu-policy
# getenv_int() owns a signed destination.  Stage the loader tunable in that
# type, validate both bounds, and only then publish the unsigned kernel-wide
# ceiling used by VM allocation and VPID reservation.
rg -q -U --pcre2 \
    'int error, maxcpu;[\s\S]*?maxcpu = mp_ncpus;[\s\S]*?TUNABLE_INT_FETCH\("hw\.vmm\.maxcpu", &maxcpu\);[\s\S]*?if \(maxcpu > VM_MAXCPU\)[\s\S]*?if \(maxcpu <= 0\)[\s\S]*?vm_maxcpu = \(u_int\)maxcpu;' \
    "$vmm_dev_source" ||
    fail "VMM maxcpu tunable is not validated before unsigned publication"

# Bus-lock detection and instruction timeout are L0 facilities until their
# VMCS12 controls and guest-visible semantics receive an explicit exposure
# contract.  A future outer-VMCS policy may enable either control, so the raw
# Appendix C exit must be classified before the generic unsupported-reason
# path even though L1 cannot request it today.
nested_reflect="$src/sys/amd64/vmm/intel/vmx_nested_reflect.c"
for exit_name in EXIT_REASON_BUS_LOCK EXIT_REASON_INSTRUCTION_TIMEOUT; do
	rg -q -F "$exit_name" "$nested_reflect" ||
	    fail "$exit_name is not classified by nested exit routing"
done
rg -q -F 'static const uint16_t l0_only_routes[]' \
    "$test_source" ||
    fail "independent host-only Appendix C route fixtures are missing"
rg -q -F 'hardware.exit_reason = (UINT32_C(1) << 26) | 10;' \
    "$test_source" ||
    fail "independent bus-lock metadata provenance fixture is missing"
rg -q -F '84, 85,' "$test_source" ||
    fail "unexposed immediate-form MSR exits lack an L0-owned fixture"
rg -q -U --pcre2 \
    'regular_readable "\$staged" "staged evidence"\s*NESTED_LIVE_LEDGER=\$ledger "\$staging_validator" "\$staged" "\$artifact_dir"\s*hash_artifacts' \
    "$live_runner" ||
    fail "live runner operates on external artifact paths before staging validation"
rg -q -F 'testdir=$here' "$live_runner" ||
    fail "installed live runner cannot resolve its packaged validators"
rg -q -F 'CTASSERT(MAXCPU <= VMX_NESTED_VPID_CPU_LIMIT);' "$vmx_source" ||
    fail "nested VPID CPU residency bound is not tied to MAXCPU"

# private-test: implementation-resource-bounds
# These limits are bhyve resource policy, not Intel VMX architecture.  Keep
# both the production declaration and its independent boundary fixture tied
# to an explicit private-interface row so increasing or removing a bound
# forces a compatibility and resource-exhaustion review.
rg -q -F 'struct vmx_nested_ept_cache_entry nested_ept_entries[8];' \
    "$src/sys/amd64/vmm/intel/vmx.h" ||
    fail "nested EPT cache bound changed without private-policy review"
rg -q -F 'vmx.h:nested_ept_entries[8]' "$private_ledger" ||
    fail "nested EPT cache bound is absent from the private ledger"
rg -q -F '#define	VMX_NESTED_STATE_MAX_FIELDS	512U' \
    "$src/sys/amd64/vmm/intel/vmx_nested_state.h" ||
    fail "nested checkpoint field bound changed without private-policy review"
rg -q -F 'vmx_nested_state.h:VMX_NESTED_STATE_MAX_FIELDS' \
    "$private_ledger" ||
    fail "nested checkpoint field bound is absent from the private ledger"
rg -q -F '#define	NVMX_MAX_FIELDS		512U' "$test_source" ||
    fail "independent nested checkpoint field-bound fixture is missing"
rg -q -F '#define	VMX_NESTED_VMCS_REGISTRY_BUCKETS	64U' \
    "$src/sys/amd64/vmm/intel/vmx_nested_vmcs_registry.h" ||
    fail "nested VMCS registry hash bound changed without private-policy review"
rg -q -F 'vmx_nested_vmcs_registry.h:VMX_NESTED_VMCS_REGISTRY_BUCKETS' \
    "$private_ledger" ||
    fail "nested VMCS registry hash bound is absent from the private ledger"
rg -q -F '(VMX_NESTED_VMCS_REGISTRY_BUCKETS - 1)) == 0' \
    "$src/sys/amd64/vmm/intel/vmx_nested_vmcs_registry.h" ||
    fail "nested VMCS registry masked hash lacks a power-of-two invariant"
rg -q -F '(uint64_t)VMX_NESTED_VMCS_REGISTRY_BUCKETS * PAGE_SIZE' \
    "$test_source" ||
    fail "nested VMCS collision test is detached from the private hash bound"

# private-test: monitor-trap-exposure-policy
# Primary-control bit 27 is architectural, but advertising it is a private
# virtual-CPU-model decision.  Until the production continuation path owns a
# generation-bound pending MTF, hardware support must not leak through the
# virtual allowed-one mask.  Keep the independent test on the SDM literal so
# changing this production name cannot silently change the oracle.
rg -q -F '#define	VMX_PRIMARY_MONITOR_TRAP_FLAG	(UINT32_C(1) << 27)' \
    "$src/sys/amd64/vmm/intel/vmx_nested_caps.c" ||
    fail "nested MTF exposure bit is not named as private policy"
rg -q -U --pcre2 \
    'VMX_PRIMARY_IMPLEMENTED[\s\S]*?VMX_PRIMARY_MONITOR_TRAP_FLAG' \
    "$src/sys/amd64/vmm/intel/vmx_nested_caps.c" ||
    fail "nested MTF is not withheld by the production control allowlist"
rg -q -F 'vmx_nested_caps.c:monitor-trap-exposure-policy' \
    "$private_ledger" ||
    fail "nested MTF exposure policy is absent from the private ledger"
rg -q -U --pcre2 \
    'capabilities\.primary >> 32\) &[\s\S]*?UINT32_C\(1\) << 27\), 0\);' \
    "$test_source" ||
    fail "nested MTF exposure policy lacks an independent negative fixture"
rg -q -U --pcre2 \
    'vmx_nested_capability_read_msr\(&capabilities, 0x482,[\s\S]*?legacy_primary[\s\S]*?vmx_nested_capability_read_msr\(&capabilities, 0x48e,[\s\S]*?true_primary' \
    "$test_source" ||
    fail "legacy and true primary-control MSRs lack direct MTF-withholding coverage"
rg -q -U --pcre2 \
    'legacy_primary >> 32\) &[\s\S]*?UINT32_C\(1\) << 27\), 0\);[\s\S]*?true_primary >> 32\) &[\s\S]*?UINT32_C\(1\) << 27\), 0\);' \
    "$test_source" ||
    fail "primary-control MSR MTF checks are not independent of production headers"

# private-test: cold-mtf-reflection-transaction
# The synthetic MTF result is a private frozen-continuation protocol, not an
# Intel VMCS field.  Pin its distinct result domain, staging order, atomic
# owner consumption, and independent exit-reason fixture.
rg -q -F 'VMX_NESTED_CONTINUATION_MTF_REFLECTED' \
    "$src/sys/amd64/vmm/intel/vmx_nested_continuation_handoff.h" ||
    fail "cold synthetic MTF disposition is missing"
rg -q -U --pcre2 \
    'portable_candidate = \*portable;[\s\S]*?vmx_nested_l2_portable_complete_instruction\([[:space:]]*&portable_candidate,[\s\S]*?vmx_nested_mtf_plan\(&mtf_input, &mtf_plan\);[\s\S]*?VMX_NESTED_MTF_REFLECT[\s\S]*?\*portable = portable_candidate;[\s\S]*?VMX_NESTED_CONTINUATION_MTF_REFLECTED;[\s\S]*?DEFER is a request to re-run arbitration[\s\S]*?return \(EOPNOTSUPP\);[\s\S]*?vmx_nested_l0_thaw_prepare_intel\(vcpu,[[:space:]]*&portable_candidate\);[\s\S]*?\*portable = portable_candidate;' \
    "$vmx_source" ||
    fail "cold instruction completion is not staged across MTF and thaw failures"
rg -q -U --pcre2 \
    'vmx_nested_cold_mtf_reflect_publish\([\s\S]*?vmx_nested_l2_portable_mtf_peek\([\s\S]*?vmx_nested_internal_publish_vmexit\(&internal_candidate,[\s\S]*?runtime_candidate = \*runtime;[\s\S]*?portable_candidate = \*portable;[\s\S]*?vmx_nested_l2_portable_mtf_commit\(&portable_candidate,[\s\S]*?context->internal = internal_candidate;[\s\S]*?\*portable = portable_candidate;' \
    "$src/sys/amd64/vmm/intel/vmx_nested_cold_reflect.c" ||
    fail "cold synthetic MTF publication is not an all-owner transaction"
rg -q -F 'information.exit_reason, 37);' "$test_source" ||
    fail "cold synthetic MTF publication lacks an independent reason fixture"
rg -q -F 'state.portable_generation + 1), ESTALE);' "$test_source" ||
    fail "cold synthetic MTF publication lacks a stale-generation negative test"
rg -q -F 'vmx_nested_cold_reflect.c:synthetic-MTF-continuation-disposition' \
    "$private_ledger" ||
    fail "cold synthetic MTF protocol is absent from the private ledger"
rg -q -U --pcre2 \
	'restart:\s*/\*[\s\S]*?\*/\s*retu = false;[\s\S]*?if \(startup_status\.mode\.owner == VMM_STARTUP_OWNER_KERNEL\)[\s\S]*?critical_enter\(\);' \
    "$vmm_source" ||
    fail "common run loop does not initialize retu before startup or backend errors"
rg -q -U --pcre2 \
    'error = vmmops_modinit\(vmm_ipinum\);[\s\S]*?if \(error != 0\) \{[\s\S]*?vmm_suspend_p = NULL;[\s\S]*?vmm_resume_p = NULL;[\s\S]*?lapic_ipi_free\(vmm_ipinum\);[\s\S]*?vmm_ipinum = IPI_AST;' \
    "$vmm_source" ||
    fail "common VMM module-init failure does not undo published hooks and IPI"
# private-test: module-init-rollback
rg -q -U --pcre2 \
	'fail:[\s\S]*?if \(pirvec >= 0\) \{[\s\S]*?lapic_ipi_free\(pirvec\);[\s\S]*?pirvec = -1;[\s\S]*?posted_interrupts = 0;[\s\S]*?if \(nmi_flush_l1d_sw == 1\)[\s\S]*?nmi_flush_l1d_sw = 0;[\s\S]*?return \(error\);' \
    "$vmx_source" ||
	fail "Intel module-init failure does not unwind posted-interrupt and software L1D-flush state"
rg -q -U --pcre2 \
	'vmx_modcleanup\(void\)[\s\S]*?if \(pirvec >= 0\) \{[\s\S]*?lapic_ipi_free\(pirvec\);[\s\S]*?pirvec = -1;[\s\S]*?\}[\s\S]*?posted_interrupts = 0;' \
    "$vmx_source" ||
	fail "Intel module cleanup can retain a freed posted-interrupt vector"
rg -q -U --pcre2 \
	'vmx_modcleanup\(void\)[\s\S]*?if \(vmxon_region != NULL\) \{[\s\S]*?kmem_free\(vmxon_region,[\s\S]*?vmxon_region = NULL;[\s\S]*?\}[\s\S]*?vmx_initialized = 0;' \
    "$vmx_source" ||
	fail "Intel module cleanup can retain released VMXON or initialized state"
rg -q -U --pcre2 \
    'vmx = malloc\([\s\S]*?sx_init\(&vmx->nested_vmcs_sx,[\s\S]*?error = vmx_nested_vmcs_registry_init\(&vmx->nested_vmcs_registry,[\s\S]*?VMX_NESTED_VMCS_REGISTRY_LIMIT\);' \
    "$vmx_source" ||
    fail "VM creation does not initialize the checkpointed VMCS registry"
rg -q -U --pcre2 \
    'error = vm_map_mmio\(vm, DEFAULT_APIC_BASE, PAGE_SIZE,[\s\S]*?if \(error != 0\)[[:space:]]*panic\("%s: cannot map APIC-access page:' \
    "$vmx_source" ||
    fail "release kernel can continue after required APIC-access map failure"
# private-test: required-fault-injection-fail-stop
rg -q -U --pcre2 \
    'vm_inject_fault\([\s\S]*?error = vm_inject_exception_class\([\s\S]*?if \(error != 0\)[[:space:]]*panic\("vm_inject_exception error %d", error\);' \
    "$vmm_source" ||
    fail "release kernel can continue after required exception publication failure"
rg -q -U --pcre2 \
    'vm_inject_pf\([\s\S]*?error = vm_set_register\(vcpu, VM_REG_GUEST_CR2, cr2\);[\s\S]*?if \(error != 0\)[[:space:]]*panic\("vm_set_register\(cr2\) error %d", error\);' \
    "$vmm_source" ||
    fail "release kernel can continue after required page-fault CR2 publication failure"
if rg -q -U --pcre2 \
    'vm_inject_(fault|pf)\([\s\S]{0,700}?KASSERT\(error == 0' \
    "$vmm_source"; then
	fail "required fault injection still relies on a diagnostic-only assertion"
fi
rg -q -F 'vmm.c:void-fault-injection-fail-stop' "$private_ledger" ||
    fail "void fault-injection fail-stop policy is absent from the private ledger"
# private-test: event-generation-no-wrap
rg -q -U --pcre2 \
    'vm_event_generation_advance\(struct vm \*vm\)[\s\S]*?generation = atomic_load_acq_64\(&vm->event_generation\);[\s\S]*?generation == UINT64_MAX[\s\S]*?panic\("%s: event generation exhausted", __func__\);[\s\S]*?atomic_fcmpset_rel_64\(&vm->event_generation, &generation,[[:space:]]*generation \+ 1\)' \
    "$vmm_source" ||
    fail "VM event publication epoch can wrap or lacks release ordering"
if rg -q 'atomic_add_rel_64\(&vcpu->vm->event_generation' "$vmm_source"; then
	fail "a VM event publisher bypasses the non-wrapping epoch helper"
fi
rg -q -U --pcre2 \
    'vcpu_init\([\s\S]*?vm_event_generation_advance\(vcpu->vm\);' \
    "$vmm_source" ||
    fail "vCPU initialization bypasses the non-wrapping event epoch helper"
rg -q -F 'vmm.c:event-generation-exhaustion' "$private_ledger" ||
    fail "event-generation exhaustion policy is absent from the private ledger"
# private-test: release-nested-callback-invariants
for invariant in \
    'no active L1 restore' \
    'incomplete nested exit' \
    'no active nested exit' \
    'wrong nested MSR transition' \
    'invalid resumed-entry transaction' \
    'resumed L2 lost its portable rollback image' \
    'invalid entered-event transaction' \
    'no active event transaction' \
    'successful return retained VMCS02' \
    'successful return retained nested MSR transition' \
    'successful return retained TSC_AUX residency'; do
	rg -q -F "panic(\"%s: $invariant" "$vmx_source" ||
	    fail "nested callback invariant is diagnostic-only: $invariant"
done
for vmcs_operation in vmcs_read vmcs_write; do
	rg -q -U --pcre2 \
    "${vmcs_operation}\\([^)]*\\)[\\s\\S]*?if \\(error != 0\\)[\\s\\S]*?panic\\(\"${vmcs_operation}" \
    "$src/sys/amd64/vmm/intel/vmcs.h" ||
	    fail "$vmcs_operation can continue after a hardware failure"
done
for adapter_source in \
    "$src/sys/amd64/vmm/intel/vmx_nested_ept_root.c" \
    "$src/sys/amd64/vmm/intel/vmx_nested_vmcs02_intel.c" \
    "$src/sys/amd64/vmm/intel/vmx_nested_vmcs02_lease_intel.c"; do
	if rg -q 'KASSERT' "$adapter_source"; then
		fail "nested adapter still uses diagnostic-only ownership control: $adapter_source"
	fi
done
rg -q -F 'vmx.c;vmcs.h:nested-release-callback-invariants' \
    "$private_ledger" ||
    fail "nested callback release-kernel invariants are absent from the private ledger"
if rg -q 'XXX this should really return an error' "$vmx_source"; then
	fail "VM creation retains an ignored production initialization error"
fi
if rg -q -U --pcre2 \
    'vmx_nested_vmcs_registry_release\([\s\S]*?error != EINVAL' \
    "$vmx_source"; then
	fail "VMCS teardown accepts an invalid initialized registry"
fi
if rg -q -F '(void)vmx_nested_vmcs_segment_encoding' \
    "$src/sys/amd64/vmm/intel"; then
	fail "production VMCS adapter ignores a segment schema lookup failure"
fi
rg -q -U --pcre2 \
    'nvmx_ept_remove_partial\([\s\S]*?vm_map_remove\([\s\S]*?if \(error != KERN_SUCCESS\)[\s\S]*?panic\(' \
    "$src/sys/amd64/vmm/intel/vmx_nested_ept_root.c" ||
    fail "nested EPT partial-alias cleanup can lose a failed removal"
rg -q -U --pcre2 \
    'vmx_nested_snapshot_restore_free\([\s\S]*?vmx_nested_vmcs_registry_destroy\([\s\S]*?panic\([\s\S]*?vmx_nested_vpid_owner_release\([\s\S]*?panic\(' \
    "$vmx_source" ||
    fail "staged nested restore cleanup ignores a resource release failure"
if rg -q -U --pcre2 \
    'KASSERT\(error == 0,\s*\([^;]{0,160}(vmcs_init error|error customizing the vmcs|vm_unmap_mmio error|vmx_allow_x2apic_msrs error|prevalidated TSC_AUX transition failed|hardware rollback lost TSC_AUX residency)' \
    "$vmx_source"; then
	fail "release kernel retains a diagnostic-only hardware invariant"
fi
rg -q -F 'panic("%s: cannot program initial VMCS: %d"' "$vmx_source" ||
    fail "initial VMCS programming failure is diagnostic-only"
rg -q -F 'panic("%s: cannot update x2APIC MSR bitmap: %d"' "$vmx_source" ||
    fail "x2APIC bitmap publication failure is diagnostic-only"
rg -q -F 'panic("%s: hardware rollback lost TSC_AUX residency: %d"' \
    "$vmx_source" ||
    fail "TSC_AUX rollback failure is diagnostic-only"

# Destructive nested teardown runs in release kernels as well as INVARIANTS
# kernels.  A diagnostic-only assertion must not permit cleanup to erase the
# last owner of VMCS02, EPT, VPID, or software-MSR state after an impossible
# phase transition.  Pin representative checks at every release boundary.
for release_invariant in \
    'panic("%s: clearing state with TSC_AUX residency %u"' \
    'panic("%s: no prepared nested entry"' \
    'panic("%s: cold reflected entry retains hardware resources"' \
    'panic("%s: cold continuation retains hardware resources"' \
    'panic("%s: incomplete recovered hot-entry failure"' \
    'panic("%s: active nested VMCS02 resource lease"'
do
	rg -q -F "$release_invariant" "$vmx_source" ||
	    fail "nested teardown invariant is diagnostic-only: $release_invariant"
done

# Nested-specific operational observability is private policy, not Intel
# architectural state.  Require it to remain explicitly inventoried whenever
# its stable name or probe contract remains compiled into the kernel.
# private-test: nested-observability-inventory
for private_owner in \
    'vmx.c:VCPU_NESTED_INVVPID_DONE' \
    'vmm.c:vmm-kernel-internal_exit-handled'
do
	rg -q -F "$private_owner" "$private_ledger" ||
	    fail "nested operational interface is not inventoried: $private_owner"
done
rg -q -U --pcre2 \
    'case VM_CAP_NESTED_VMX:[\s\S]*?if \(val != 0 && val != 1\)[\s\S]*?return \(EINVAL\);[\s\S]*?vmx_nested_guest_configure\(vcpu->vmx, val == 1\)' \
    "$vmx_source" ||
    fail "nested VMX management capability accepts noncanonical booleans"
# private-test: canonical-capability-value

# The state-machine model proves that the enabled bit becomes immutable once
# locked.  Pin the production transition as well: it must occur before nested
# run selection, VMCS loading, or any guest-visible VMX instruction handling.
# Otherwise two vCPUs could observe different CPU models during their first
# entry even though the standalone state helper remains correct.
rg -q -U --pcre2 \
    'static int[[:space:]]+vmx_run\([\s\S]*?vmx_nested_guest_config_lock\(vmx\);[\s\S]*?vmx_nested_run_select_intel\(vcpu, &nested_target\)' \
    "$vmx_source" ||
    fail "nested VMX exposure is not frozen before nested run selection"
# Instruction emulation and checkpoint validation are earlier exposure
# boundaries, but VMCS02 residency needs its own final fence.  In particular,
# a stale private state image must not turn a selector result into an L2 entry
# after the CPU model has withheld nested VMX or before the complete entry
# transaction is qualified.
rg -q -U --pcre2 \
    'if \(nested_target != VMX_NESTED_RUN_L1\) \{[\s\S]*?if \(!vmx_nested_guest_enabled\(vmx\)\)[\s\S]*?return \(EOPNOTSUPP\);[\s\S]*?error = vmx_nested_guest_exposure_validate\(\);[\s\S]*?if \(error != 0\)[\s\S]*?return \(error\);[\s\S]*?return \(vmx_run_nested\(vcpu, rip, pmap, evinfo,' \
    "$vmx_source" ||
    fail "nested VMX L2 selection lacks the final exposure-policy fence"
# vmx_run_nested() is deliberately static.  Its sole call site is the
# immediately preceding final policy fence, so an additional call site could
# bypass the immutable exposure decision and make the presently withheld
# VMCS02 path reachable.  Presence of the fenced call above is not enough:
# pin both the complete source inventory and the unique executable call.
nested_run_mentions=$(rg -c 'vmx_run_nested\(' "$vmx_source" || true)
[ "$nested_run_mentions" -eq 3 ] ||
    fail "nested VMX execution helper has an unexpected source reference count"
nested_run_callers=$(rg -c \
    'return \(vmx_run_nested\(vcpu, rip, pmap, evinfo,' "$vmx_source" || true)
[ "$nested_run_callers" -eq 1 ] ||
    fail "nested VMX execution helper has an unexpected caller count"
rg -q -F 'vmx_nested_exposure_configure(locked, false, &next),' \
    "$test_source" ||
    fail "nested model lacks locked exposure transition rejection"
# private-test: exposure-freeze-before-run

# The exposure header and registry are separate private records but one CPU
# model.  A disabled envelope must reject a non-empty registry before the
# staged VM-wide swap, and the model test must independently cover both sides.
rg -q -U --pcre2 \
    'vmx_nested_vmcs_registry_state_restore\(&stage->registry,[\s\S]*?vmx_nested_exposure_registry_validate\(source_nested_vmx,[\s\S]*?stage->registry.count\)' \
    "$vmx_source" ||
    fail "disabled nested exposure does not validate the staged VMCS registry"
rg -q -F 'vmx_nested_exposure_registry_validate(false, 1), EPROTO' \
    "$test_source" ||
    fail "nested model lacks disabled-exposure/non-empty-registry rejection"
# private-test: exposure-registry-composition

# The durable event fence is a descriptor-owned, versioned management ABI,
# not Intel architectural state.  Pin its exact input domain, close cleanup,
# allocation policy, and userspace publication ordering.  These source checks
# complement (but do not replace) installed-kernel close/race qualification.
rg -q '^[[:space:]]*#define[[:space:]]+VM_SNAPSHOT_SESSION_VERSION[[:space:]]+1U' \
    "$vmm_snapshot_header" ||
    fail "checkpoint session ABI lacks an explicit version"
rg -q -F '_Static_assert(sizeof(struct vm_snapshot_session) == 40' \
    "$vmm_snapshot_header" ||
    fail "checkpoint session ABI layout is not frozen"
rg -q -F 'IOCNUM_SNAPSHOT_SESSION = 114' "$vmm_dev_header" ||
    fail "checkpoint session ioctl number changed without ABI review"
rg -q -F 'VM_SNAPSHOT_SESSION,' "$vmm_dev_machdep_source" ||
    fail "checkpoint session ioctl is not dispatched"
rg -q -U --pcre2 \
    'case VM_SNAPSHOT_SESSION:[\s\S]*?\(fflag & FWRITE\) == 0[\s\S]*?session->version != VM_SNAPSHOT_SESSION_VERSION[\s\S]*?session->flags != 0[\s\S]*?session->reserved\[0\] != 0[\s\S]*?session->reserved\[1\] != 0' \
    "$vmm_dev_machdep_source" ||
    fail "checkpoint session ioctl lacks authorization or reserved-field validation"
rg -q -U --pcre2 \
    'vmmdev_fdpriv_dtor\([\s\S]*?priv->active[\s\S]*?vmm_event_coordinator_checkpoint_abort\([\s\S]*?panic\(' \
    "$vmm_dev_source" ||
    fail "descriptor close does not resolve an active checkpoint session exactly"
rg -q -U --pcre2 \
    'vmmdev_snapshot_session_begin\([\s\S]*?mallocarray\([\s\S]*?M_NOWAIT \| M_ZERO[\s\S]*?if \(count == 0\)[\s\S]*?error = EINVAL;[\s\S]*?vmm_event_coordinator_checkpoint_wait_ready' \
    "$vmm_dev_source" ||
    fail "checkpoint session does not reject empty groups or use bounded event-driven quiescence"
rg -q -U --pcre2 \
    'vm_event_checkpoint_deferred_apply\([\s\S]*?vcpu_event_generation_advance_locked\(vcpu\);[\s\S]*?vcpu_event_unlock\(vcpu\);' \
    "$vmm_source" ||
    fail "deferred event merge does not publish under the pending-event owner"
if sed -n '/^vm_event_checkpoint_deferred_apply(/,/^}/p' \
    "$vmm_source" | rg -q 'vcpu_notify_event\('; then
    fail "deferred merge notifies while coordinator ingress locks are retained"
fi
rg -q -U --pcre2 \
    'vmmdev_snapshot_session_notify\([\s\S]*?vcpu_notify_event\(vcpu\);[\s\S]*?vmm_event_coordinator_checkpoint_abort\([\s\S]*?vmmdev_snapshot_session_notify\(priv\);' \
    "$vmm_dev_source" ||
    fail "checkpoint adapter does not notify after coordinator unlock"
checkpoint_function=$(sed -n \
    '/^vm_checkpoint(struct vmctx \*ctx,/,/^}/p' \
    "$bhyve_snapshot_source")
[ -n "$checkpoint_function" ] || fail "checkpoint function is missing"
printf '%s\n' "$checkpoint_function" | awk '
	/vm_snapshot_session_begin_exact\(ctx, &snapshot_session,/ { session = NR }
	/memsz = vm_snapshot_mem/ { memory = NR }
	/error = checkpoint_publish/ { publish = NR }
	/vm_snapshot_session_release_exact\(ctx,/ { release = NR }
	END {
		exit session && memory && publish && release &&
		    session < memory && memory < publish && publish < release ? 0 : 1
	}
' || fail "checkpoint session does not span capture through manifest publication"
# private-test: durable-checkpoint-session

# Destination restore uses the same descriptor-owned all-vCPU ingress owner.
# This is a bhyve-private transaction boundary, not Intel architectural state.
restore_transaction=$(sed -n \
    '/^vm_restore_transaction(struct vmctx \*ctx,/,/^}/p' \
    "$bhyve_snapshot_source")
[ -n "$restore_transaction" ] ||
    fail "destination restore transaction is missing"
printf '%s\n' "$restore_transaction" | awk '
	/vm_pause_devices\(\)/ { pause = NR }
	/vm_restore_preflight\(rstate\)/ { preflight = NR }
	/vm_restore_memory_preflight\(ctx, rstate\)/ { memory_preflight = NR }
	/vm_snapshot_session_begin_exact\(ctx, &session,/ { begin = NR }
	/restore_vm_mem\(ctx, rstate\)/ { memory = NR }
	/vm_restore_devices\(rstate\)/ { devices = NR }
	/vm_restore_kern_structs\(ctx, rstate\)/ { kernel = NR }
	/vm_snapshot_session_release_exact\(ctx, &session, true,/ { commit = NR }
	/vm_resume_devices\(\)/ { resume = NR }
	END {
		exit pause && preflight && memory_preflight && begin && memory &&
		    devices && kernel && commit && resume &&
		    pause < preflight && preflight < memory_preflight &&
		    memory_preflight < begin && begin < memory &&
		    memory < devices && devices < kernel && kernel < commit &&
		    commit < resume ? 0 : 1
	}
' || fail "destination event session does not span restore publication"
printf '%s\n' "$restore_transaction" | rg -q -U --pcre2 \
    'failed:[\s\S]*?if \(session_active\)[\s\S]*?vm_snapshot_session_release_exact\(ctx, &session,[\s\S]*?false, &released\)' ||
    fail "destination restore failure does not abort the exact session"
rg -q -U --pcre2 \
	'vm_snapshot_session_release_exact\([\s\S]*?VM_SNAPSHOT_SESSION_ABORT;[\s\S]*?retry_error == ESTALE[\s\S]*?vm_snapshot_session\(ctx, session\) == 0 \|\| errno == ESTALE' \
	"$bhyve_snapshot_source" ||
	fail "destination session does not retry an ambiguous exact ABORT"
session_live_source="$src/tests/sys/vmm/vmm_snapshot_session_live_test.c"
rg -q -U --pcre2 \
	'copyout_fault_consumes_exact_operation[\s\S]*?VM_SNAPSHOT_SESSION_BEGIN[\s\S]*?PROT_READ[\s\S]*?EFAULT[\s\S]*?VM_SNAPSHOT_SESSION_ABORT_CURRENT[\s\S]*?ESTALE' \
	"$session_live_source" ||
	fail "live session suite lacks BEGIN copyout-fault recovery coverage"
rg -q -U --pcre2 \
	'BEGIN before faulted ABORT[\s\S]*?VM_SNAPSHOT_SESSION_ABORT[\s\S]*?PROT_READ[\s\S]*?EFAULT[\s\S]*?PROT_READ \| PROT_WRITE[\s\S]*?ESTALE[\s\S]*?BEGIN after faulted ABORT' \
	"$session_live_source" ||
	fail "live session suite lacks exact-ABORT copyout-fault recovery coverage"
rg -q -U --pcre2 \
    'vm_snapshot_session_begin_exact\([\s\S]*?error != EFAULT[\s\S]*?VM_SNAPSHOT_SESSION_ABORT_CURRENT[\s\S]*?retry_error == ESTALE' \
    "$bhyve_snapshot_source" ||
    fail "checkpoint BEGIN copyout ambiguity is not descriptor-recoverable"
rg -q -U --pcre2 \
    'case VM_SNAPSHOT_SESSION_ABORT_CURRENT:[\s\S]*?session->session_id != 0[\s\S]*?vmmdev_snapshot_session_abort_current\(vm\)' \
    "$vmm_dev_machdep_source" ||
    fail "descriptor-scoped current-session abort dispatch is missing"
rg -q -U --pcre2 \
    'vmmdev_snapshot_session_abort_current\([\s\S]*?devfs_get_cdevpriv[\s\S]*?priv->vm != vm[\s\S]*?sx_xlock\(&priv->lock\)[\s\S]*?!priv->active[\s\S]*?vmmdev_snapshot_session_finish_locked\(priv, true\)[\s\S]*?sx_xunlock\(&priv->lock\)' \
    "$vmm_dev_source" ||
    fail "current-session abort is not bound to the exact descriptor owner"
rg -q -U --pcre2 \
    'snapshot_session_unresolved = error != 0 &&[\s\S]*?!resolved \|\| error == EBUSY[\s\S]*?!snapshot_session_unresolved[\s\S]*?vm_resume_devices' \
    "$bhyve_snapshot_source" ||
    fail "source checkpoint may resume after unresolved BEGIN ownership"
rg -q -F 'vm_restore_transaction(ctx, &rstate)' "$bhyve_run_source" ||
    fail "bhyve restore entry point bypasses the destination session"
rg -q 'NVMX-STATE-043.*Destination restore event-ingress transaction' \
    "$ledger" || fail "destination restore lease is absent from requirements"
rg -q 'NVMX-PRIVATE-196.*destination-restore-event-session' \
    "$private_ledger" ||
    fail "destination restore lease is absent from private inventory"
# private-test: destination-restore-event-session

# A nested entry which has not executed L2 is a retry barrier, not active-L2
# evidence.  Active L2 must instead come from the exact detached cold image,
# and target classification must remain value-only and failure-atomic.
rg -q -U --pcre2 \
    'nvmxe_startup_runtime_preentry\([\s\S]*?VMX_NESTED_ENTRY_RUNTIME_IDLE:[\s\S]*?VMX_NESTED_ENTRY_RUNTIME_PREPARING:[\s\S]*?VMX_NESTED_ENTRY_RUNTIME_RESOURCES:[\s\S]*?VMX_NESTED_ENTRY_RUNTIME_MSRS:[\s\S]*?VMX_NESTED_ENTRY_RUNTIME_VMCS02:[\s\S]*?return \(true\);[\s\S]*?default:[\s\S]*?return \(false\);' \
    "$src/sys/amd64/vmm/intel/vmx_nested_event.c" ||
    fail "nested startup pre-entry runtime whitelist is incomplete"
rg -q -U --pcre2 \
    'vmx_nested_startup_input_from_frozen_target\([\s\S]*?VMX_NESTED_CONTEXT_ROOT:[\s\S]*?vmx_nested_context_quiesce\(context\)[\s\S]*?VMX_NESTED_CONTEXT_ENTRY_PENDING:[\s\S]*?nvmxe_startup_runtime_preentry\(runtime\)[\s\S]*?candidate\.nested_entry_pending = true;[\s\S]*?VMX_NESTED_CONTEXT_GUEST:[\s\S]*?vmx_nested_l0_continuation_quiesce_context\([\s\S]*?candidate\.active_l2 = true;[\s\S]*?VMX_NESTED_L0_COMPLETE_RESUME_L2[\s\S]*?candidate\.continuation_pending = true;[\s\S]*?idt_vectoring_info[\s\S]*?activity ==[\s\S]*?candidate\.mtf_pending = portable->mtf_pending' \
    "$src/sys/amd64/vmm/intel/vmx_nested_event.c" ||
    fail "nested startup target state is not derived from the frozen cold owner"
rg -q -U --pcre2 \
    '!input->active_l2 && \(input->continuation_pending \|\|[\s\S]*?input->reinjection_pending \|\| input->wait_for_sipi \|\|[\s\S]*?input->mtf_pending\)' \
    "$src/sys/amd64/vmm/intel/vmx_nested_event.c" ||
    fail "nested startup planner still conflates ENTRY_PENDING with active L2"
rg -q -U --pcre2 \
    'VMX_NESTED_STARTUP_ACTION_DISCARD;[\s\S]*?candidate\.discard_mtf = input->mtf_pending' \
    "$src/sys/amd64/vmm/intel/vmx_nested_event.c" ||
    fail "nested startup MTF disposal is not bound to the frozen owner"
rg -q -F 'ATF_TC_WITHOUT_HEAD(nested_startup_frozen_target);' "$test_source" ||
    fail "nested startup frozen-target negative model is missing"
# private-test: nested-startup-frozen-target

# A consuming active-L2 startup plan must be rederived at the frozen cold
# boundary.  Reflection replaces only the pending RESUME_L2 handoff, while an
# ignored event may consume only its exact portable MTF generation.
rg -q -U --pcre2 \
    'vmx_nested_cold_startup_commit\([\s\S]*?vmx_nested_startup_input_from_frozen_target\([\s\S]*?vmx_nested_startup_plan\([\s\S]*?nvmxcr_startup_plan_equal\([\s\S]*?VMX_NESTED_STARTUP_ACTION_DISCARD[\s\S]*?vmx_nested_l2_portable_mtf_commit\([\s\S]*?vmx_nested_internal_publish_vmexit\([\s\S]*?vmx_nested_entry_runtime_l0_reflect_captured\([\s\S]*?VMX_NESTED_CONTEXT_EXIT_PENDING' \
    "$src/sys/amd64/vmm/intel/vmx_nested_cold_reflect.c" ||
    fail "nested startup cold commit is not an exact atomic replacement"
rg -q -U --pcre2 \
    'SIPI-in-WFS replaces the pending resume[\s\S]*?vmx_nested_cold_startup_commit\([\s\S]*?VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED_COLD' \
    "$test_source" ||
    fail "nested startup cold commit negative model is missing"
# private-test: nested-startup-cold-commit

# The legacy L0 INIT adapter is also the future APPLY_L0 commit point.  The
# rendezvous is interruptible and can have completed only a subset when its
# initiator returns, so each target must publish reset and wait-for-SIPI under
# the same rendezvous owner rather than trusting the aggregate return value.
rg -q -U --pcre2 \
	'vlapic_handle_init\([\s\S]*?vlapic_reset\(vlapic\);[\s\S]*?APICBASE_BSP[\s\S]*?vm_publish_startup_wait_rendezvous\(vcpu, waiting\);' \
	"$src/sys/amd64/vmm/io/vlapic.c" ||
	fail "INIT reset and BSP/AP startup publication are not target-atomic"
rg -q -U --pcre2 \
	'CPU_AND\(&reinit, &active, dmask\);[\s\S]*?CPU_FOREACH_ISSET\(target_id, dmask\)[\s\S]*?APICBASE_BSP[\s\S]*?vm_publish_startup_wait\(vm, dmask, &waiting\);[\s\S]*?vm_smp_rendezvous\(vcpu, reinit, vlapic_handle_init,' \
	"$src/sys/amd64/vmm/io/vlapic.c" ||
	fail "INIT does not publish exact BSP/AP state for all targets"
rg -q -U --pcre2 \
	'vm_publish_startup_wait\([\s\S]*?CPU_ANDNOT\(&invalid, waiting, targets\);[\s\S]*?CPU_AND\(&bounded, waiting, targets\);[\s\S]*?CPU_ANDNOT\(&vm->startup_cpus, &vm->startup_cpus, targets\);[\s\S]*?CPU_OR\(&vm->startup_cpus, &vm->startup_cpus, &bounded\);' \
	"$src/sys/amd64/vmm/vmm.c" ||
	fail "startup wait mask replacement is not exact and target-bounded"
if rg -q -U --pcre2 \
	'fbsdrun_vcpu_is_bsp|case APIC_DELMODE_INIT:[\s\S]*?vcpu_reset\(' \
	"$src/usr.sbin/bhyve/bhyverun.c" \
	"$src/usr.sbin/bhyve/amd64/vmexit.c"; then
	fail "unsafe nontransactional userspace BSP INIT workaround is present"
fi
# private-test: init-rendezvous-error-propagation

# Kernel-owned INIT/SIPI cannot be wired by treating selection or an IPI
# copyout as completion.  bhyve already creates every configured vCPU thread,
# but its historical contract deliberately debugger-suspends APs and resumes
# them from the userspace SIPI handler.  Pin that compatibility boundary and
# keep the future architecture wait distinct from debug_cpus until an explicit
# frozen per-VM opt-in, event-driven wait, and versioned restore contract land.
for lifecycle_contract in NVMX-EVENT-058 NVMX-PRIVATE-114; do
	rg -q -F "$lifecycle_contract" "$ledger" "$private_ledger" ||
	    fail "kernel startup vCPU lifecycle gate is not inventoried: $lifecycle_contract"
done
rg -q -U --pcre2 \
    'for \(int vcpuid = 0; vcpuid < guest_ncpus; vcpuid\+\+\)[\s\S]*?bhyve_start_vcpu\(vcpu_info\[vcpuid\]\.vcpu, vcpuid == BSP\);[\s\S]*?vm_resume_cpu\(bsp\);' \
    "$bhyve_run_source" ||
    fail "bhyve no longer pre-creates every vCPU while initially resuming only the BSP"
rg -q -U --pcre2 \
    'fbsdrun_addcpu\(int vcpuid\)[\s\S]*?vm_activate_cpu\(vi->vcpu\);[\s\S]*?vm_suspend_cpu\(vi->vcpu\);[\s\S]*?pthread_create\(' \
    "$bhyve_run_source" ||
    fail "historical bhyve AP thread activation/suspension contract changed"
rg -q -U --pcre2 \
    'case APIC_DELMODE_STARTUP:[\s\S]*?spinup_ap\(fbsdrun_vcpu\(i\),' \
    "$bhyve_vmexit_source" ||
    fail "historical userspace SIPI handler changed without lifecycle review"
rg -q -U --pcre2 \
    'spinup_ap\(struct vcpu \*newcpu, uint64_t rip\)[\s\S]*?vcpu_reset\(newcpu\);[\s\S]*?spinup_ap_realmode\(newcpu, rip\);[\s\S]*?vm_resume_cpu\(newcpu\)\);' \
    "$bhyve_spinup_source" ||
    fail "historical userspace SIPI reset/resume sequence changed"
if rg -q 'vmm_startup_mode_(configure|configure_execution|lock)|vmm_startup_action_plan' \
	"$vmm_source" "$src/sys/amd64/vmm/io/vlapic.c" "$bhyve_run_source" \
	"$bhyve_vmexit_source"; then
	fail "kernel startup owner was wired before the vCPU lifecycle contract"
fi
# private-test: kernel-startup-vcpu-lifecycle-gate

# A future startup controller credential is owned by one open file
# description, not by a process or integer descriptor.  Prove the generic
# devfs lifetime that the VMM adapter relies on in both directions: dup/fork
# retain the same f_cdevpriv object until final file close, an active cdev
# method is drained before forced cdevpriv destruction, every destructor is
# complete before destroy_dev() returns, and only then may vmmdev_destroy()
# free the VM and its event coordinator.  These source checks do not replace
# installed-kernel dup/fork/close and race qualification before ioctl exposure.
rg -q -U --pcre2 \
    'devfs_set_cdevpriv\(void \*priv,[\s\S]*?fp = curthread->td_fpop;[\s\S]*?p->cdpd_fp = fp;[\s\S]*?fp->f_cdevpriv = p;' \
    "$devfs_vnops_source" ||
    fail "devfs cdevpriv is no longer attached to the open file description"
rg -q -U --pcre2 \
    'devfs_close_f\(struct file \*fp,[\s\S]*?vnops\.fo_close\(fp, td\);[\s\S]*?if \(fp->f_cdevpriv != NULL\)[\s\S]*?devfs_fpdrop\(fp\);' \
    "$devfs_vnops_source" ||
    fail "devfs final-close no longer destroys file-description private state"
rg -q -U --pcre2 \
    'while \(dev->si_threadcount != 0\)[\s\S]*?while \(\(p = LIST_FIRST\(&cdp->cdp_fdpriv\)\) != NULL\)[\s\S]*?devfs_destroy_cdevpriv\(p\);[\s\S]*?while \(cdp->cdp_fdpriv_dtrc != 0\)' \
    "$kern_conf_source" ||
    fail "character-device destruction no longer drains methods and cdevpriv destructors"
rg -q -U --pcre2 \
    'vmmdev_lookup_and_destroy\([\s\S]*?destroy_dev\(cdev\);[\s\S]*?vmmdev_destroy\(sc\);' \
    "$vmm_dev_source" ||
    fail "VMM destruction no longer drains cdevpriv before freeing VM lifetime"
# private-test: startup-controller-cdevpriv-lifetime-prerequisite

# The two transient startup-entry observations intentionally have different
# baselines.  Notification generation brackets the frozen dispatcher so an
# otherwise inert FROZEN publication cannot disappear.  The coordinator token
# is captured only afterward because claim begin/finish legitimately changes
# the generation, pending set, and active-claim fields it protects.  Pin the
# doubled review and keep production consumers absent until one stack-owned
# transaction implements this order and passes installed race qualification.
for contract in NVMX-EVENT-154 NVMX-PRIVATE-216; do
	rg -q -F "$contract" "$ledger" "$private_ledger" ||
	    fail "startup stack-owner ordering is not inventoried: $contract"
done
for phase in \
	'Pass 60: forward stack-owned run transaction' \
	'Pass 61: reverse stack-owned run transaction' \
	'Pass 62: definition-first stack-owner non-standard review' \
	'Pass 63: consumer-first stack-owner non-standard review' \
	'Pass 64: forward cross-owner state-product review' \
	'Pass 65: reverse retirement and destruction review' \
	'Pass 66: definition-first outer-owner private review' \
	'Pass 67: consumer-first outer-owner private review' \
	'Pass 68: first no-entry kernel return review' \
	'Pass 69: independent reverse no-entry kernel review' \
	'Pass 70: definition-first no-entry private-result review' \
	'Pass 71: consumer-first no-entry private-result review' \
	'Pass 72: forward common frozen-admission review' \
	'Pass 73: reverse common return and wait review' \
	'Pass 74: exact VMX, nested-VMX, and SVM placement review' \
	'Pass 75: consumer-first live private-boundary review' \
	'Pass 76: forward frozen-admission transaction review' \
	'Pass 77: reverse frozen-admission transaction review' \
	'Pass 78: definition-first admission private-interface review' \
	'Pass 79: consumer-first admission private-interface review' \
	'Pass 84: second machine-entry activation review' \
	'Pass 85: reverse machine-entry and cleanup review' \
	'Pass 86: dormant and non-standard activation-surface review' \
	'Pass 87: cross-architecture and reference behavior replay' \
	'Pass 92: machine-entry edge matrix review' \
	'Pass 93: implementation-defined boundary and observability review' \
	'Pass 94: restore-residency and derived-cache review'; do
	rg -q -F "$phase" "$review_prompt" ||
	    fail "startup stack-owner review phase is missing: $phase"
done
# The common admission review found that the historical wait helper cannot
# remain ahead of a future kernel-owned frozen dispatcher: only that
# dispatcher consumes SIPI and clears the AP wait predicate.  Pin both the
# architectural requirement and the private ordering decision while keeping
# the production owner consumer prohibited below.
for contract in NVMX-EVENT-160 NVMX-PRIVATE-222; do
	rg -q -F "$contract" "$ledger" "$private_ledger" ||
	    fail "common frozen-admission ordering is not inventoried: $contract"
done
for contract in \
	'vm_handle_startup_wait' \
	'vmmops_vcpu_startup_event_step' \
	'vcpu_startup_notify_generation_capture' \
	'vmm_startup_entry_handoff_capture' \
	'vcpu_startup_event_run_token_capture' \
	'vmm_startup_entry_owner_admit'; do
	rg -q -F "$contract" "$ledger" "$private_ledger" ||
	    fail "common frozen-admission boundary is incomplete: $contract"
done
for contract in \
	'vmm_startup_entry_admission' \
	'vmm_startup_entry_admission_validate' \
	'vmm_startup_entry_dispatch_admit'; do
	rg -q -F "$contract" "$startup_mode_header" "$startup_mode_source" ||
	    fail "common frozen-admission value model is incomplete: $contract"
done
# private-test: common-frozen-entry-observation
# Keep the lifecycle values and notification generation one frozen observation:
# separate reads would permit a startup publication to cross dispatch unseen.
for contract in \
	'vcpu_startup_entry_observation' \
	'vcpu_startup_entry_overlap' \
	'vcpu_startup_notify_generation_capture_locked' \
	'vmm_startup_notification_generation_capture(' \
	'vcpu_startup_entry_observation(vcpu, snapshot, NULL)' \
	'generationp != NULL && vcpu_startup_entry_overlap(snapshot,'; do
	rg -q -F "$contract" "$vmm_vm_source" ||
	    fail "common frozen-entry observation omits: $contract"
done
# The lifecycle predicate and notification epoch form one observation.  The
# generic strings above are insufficient: they could survive a refactor which
# samples the epoch after dropping either owner and reintroduces the exact
# dispatch-past-publication race this adapter exists to prevent.
rg -q -U --pcre2 \
	'vcpu_startup_entry_observation\(struct vcpu \*vcpu,[\s\S]*?mtx_lock\(&vm->rendezvous_mtx\);[\s\S]*?vcpu_lock\(vcpu\);[\s\S]*?candidate\.rendezvous = [\s\S]*?candidate\.waiting = [\s\S]*?generation = vcpu_startup_notify_generation_capture_locked\(vcpu\);[\s\S]*?vcpu_unlock\(vcpu\);[\s\S]*?mtx_unlock\(&vm->rendezvous_mtx\);' \
	"$vmm_vm_source" ||
	fail "frozen lifecycle snapshot and notification epoch are not one ordered observation"
rg -q -U --pcre2 \
	'vcpu_startup_notify_generation_capture_locked\(struct vcpu \*vcpu\)[\s\S]*?vcpu_assert_locked\(vcpu\);[\s\S]*?vmm_startup_notification_generation_capture\([\s\S]*?return \(vcpu->startup_notify_generation\);' \
	"$vmm_vm_source" ||
	fail "startup notification baseline is not normalized under the vCPU owner"
for contract in \
	'vmm_startup_notification_generation_capture(0)' \
	'vmm_startup_notification_generation_capture(UINT64_MAX)'; do
	rg -q -F "$contract" "$startup_mode_test" ||
	    fail "startup notification baseline lacks independent boundary coverage: $contract"
done
if rg -q -U --pcre2 \
	'vm_startup_kernel_entry_action\(struct vcpu \*vcpu,[\s\S]*?vcpu_startup_notify_generation_capture\(' \
	"$vmm_source"; then
	fail "common frozen dispatcher split its lifecycle and notification observations"
fi
for contract in \
	'vm_startup_kernel_entry_action' \
	'vcpu_startup_entry_observation(vcpu, &before,' \
	'memset(admissionp, 0, sizeof(*admissionp));' \
	'vmm_startup_entry_pre_dispatch(&before, action)' \
	'vmmops_vcpu_startup_event_step(vcpu->cookie, &dispatch)' \
	'vcpu_startup_entry_observation(vcpu, &after,' \
	'vmm_startup_entry_dispatch_admit(&before, &after, dispatch,' \
	'if (startup_action == VMM_STARTUP_ENTRY_REPLAY)' \
	'if (startup_action != VMM_STARTUP_ENTRY_ENTER_GUEST)'; do
	rg -q -F "$contract" "$vmm_source" ||
	    fail "common frozen startup dispatcher omits: $contract"
done
# The common production slice now preserves an ENTER_GUEST admission through
# the shared owner lifecycle, but the machine backends still reject it before
# machine-state acquisition.  This proves the intermediate state is typed and
# fail-closed rather than a silent activation.
rg -q -F 'startup_owner_active ? &startup_owner : NULL);' "$vmm_source" ||
    fail "frozen dispatch slice omits the staged startup-owner boundary"
# Admission handoffs are common transient values, not native wire objects.
# A field-wise empty-state check keeps future padding or layout changes from
# becoming an implicit cross-architecture requirement.
if rg -q 'memcmp\([^\n]*handoff' "$startup_mode_source"; then
	fail "startup admission validates a handoff by native object representation"
fi
for contract in \
	'admission->handoff.notification_generation != 0' \
	'admission->handoff.armed != 0' \
	'admission->handoff.reserved != 0'; do
	rg -q -F "$contract" "$startup_mode_source" ||
	    fail "startup admission lacks field-wise empty-handoff validation: $contract"
done
rg -q -F 'entry_dispatch_admission_is_exact' "$startup_mode_test_source" ||
    fail "common frozen-admission exhaustive test is missing"
rg -q -F 'entry_dispatch_admission_is_exact' "$ledger" "$private_ledger" ||
    fail "common frozen-admission exhaustive evidence is not inventoried"
for contract in \
	'vmm_startup_entry_pre_dispatch(before, &action)' \
	'vmm_startup_entry_handoff_capture(' \
	'vmm_startup_entry_pre_dispatch(after, &action)' \
	'action != VMM_STARTUP_ENTRY_ENTER_GUEST'; do
	rg -q -F "$contract" "$startup_mode_source" ||
	    fail "common frozen-admission transaction ordering is incomplete: $contract"
done
for contract in \
	'for (pre_bits = 0; pre_bits < 32; pre_bits++)' \
	'for (bits = 0; bits < 32; bits++)' \
	'before.waiting = (pre_bits >> 4) & 1' \
	'VMM_STARTUP_DISPATCH_RETAINED, 300, 300' \
	'VMM_STARTUP_ENTRY_ENTER_GUEST' \
	'VMM_STARTUP_DISPATCH_IDLE, 300, 300' \
	'VMM_STARTUP_ENTRY_WAIT' \
	'VMM_STARTUP_DISPATCH_CONSUMED'; do
	rg -q -F "$contract" "$startup_mode_test_source" ||
	    fail "common frozen-admission product test is incomplete: $contract"
done
admission_consumers=$(rg -l \
    'vmm_startup_entry_(dispatch_admit|admission_validate)' \
    "$src/sys" "$src/usr.sbin" || true)
for source in $admission_consumers; do
	case "$source" in
	"$startup_mode_header"|"$startup_mode_source"|\
	"$startup_entry_owner_source"|"$vmm_source")
		;;
	*)
		fail "startup admission acquired a production consumer before qualification: $source"
		;;
	esac
done
# private-test: startup-common-frozen-admission

for contract in NVMX-EVENT-161 NVMX-PRIVATE-223; do
	rg -q -F "$contract" "$ledger" "$private_ledger" ||
	    fail "typed admission-to-owner boundary is not inventoried: $contract"
done
for contract in \
	'vmm_startup_entry_owner_admit' \
	'admission->action != VMM_STARTUP_ENTRY_ENTER_GUEST'; do
	rg -q -F "$contract" "$startup_entry_owner_header" \
	    "$startup_entry_owner_source" ||
	    fail "typed admission-to-owner boundary is incomplete: $contract"
done
rg -q -F 'entry_owner_requires_entry_admission' \
    "$startup_entry_owner_test_source" ||
    fail "typed admission-to-owner negative test is missing"
rg -q -F 'entry_owner_requires_entry_admission' "$ledger" \
    "$private_ledger" ||
    fail "typed admission-to-owner evidence is not inventoried"
# private-test: startup-admission-owner-boundary

# private-test: startup-production-entry-map
# Pin the complete current entry-edge inventory before changing the synchronous
# run signature.  These are placement facts, not activation evidence: the
# consumer prohibition below must remain in force until the guards are wired
# and installed races pass.
for contract in NVMX-EVENT-162 NVMX-PRIVATE-224; do
	rg -q -F "$contract" "$ledger" "$private_ledger" ||
	    fail "production entry map is not inventoried: $contract"
done
[ -f "$entry_edge_matrix" ] || fail "missing machine-entry edge matrix"
awk -F '\t' '
NR == 1 {
	if ($1 != "id" || $2 != "architecture" || $3 != "entry_class" ||
	    $4 != "source" || $5 != "source_anchor" ||
	    $6 != "precondition" || $7 != "entry_boundary" ||
	    $8 != "return_or_unwind" || $9 != "owner_contract" ||
	    $10 != "caller_disposition" || $11 != "independent_evidence") bad = 1
	next
}
NF != 11 || $1 !~ /^EDGE-(COMMON|VMX|NVMX|SVM)-[0-9][0-9][0-9][A-Z]?$/ ||
    $2 == "" || $3 == "" || $4 == "" || $5 == "" || $6 == "" ||
    $7 == "" || $8 == "" || $9 == "" || $10 == "" || $11 == "" ||
    seen[$1]++ {
	bad = 1
}
$1 == "EDGE-COMMON-002" { common = 1 }
$1 == "EDGE-VMX-002" { vmx = 1 }
$1 == "EDGE-NVMX-004" { nested = 1 }
$1 == "EDGE-SVM-002" { svm = 1 }
END { exit bad || !common || !vmx || !nested || !svm }
' "$entry_edge_matrix" || fail "machine-entry edge matrix is incomplete"
# Each row must name an exact source anchor inside the function identified by
# its source column.  Counts alone catch an added entry instruction, but they
# do not catch a moved no-entry or cleanup edge that leaves a stale review row
# behind.  This remains a source review gate, not evidence of hardware
# placement or activation.
python3 - "$entry_edge_matrix" "$vmm_source" "$vmx_source" "$svm_source" <<'PY' || fail "machine-entry edge matrix source anchors are stale"
import csv
import re
import sys

matrix, vmm, vmx, svm = sys.argv[1:]
sources = {
    "vmm.c": open(vmm, encoding="utf-8").read(),
    "vmx.c": open(vmx, encoding="utf-8").read(),
    "svm.c": open(svm, encoding="utf-8").read(),
}

def body(source, name):
    match = re.search(r"(?ms)^(?:static\s+)?(?:int|void|bool)\s*\n?" +
        re.escape(name) + r"\s*\([^;]*?\)\s*\{", source)
    if match is None:
        raise ValueError(f"missing function {name}")
    begin = source.find("{", match.start())
    depth = 0
    quote = None
    comment = None
    index = begin
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if comment == "line":
            if char == "\n":
                comment = None
        elif comment == "block":
            if char == "*" and next_char == "/":
                comment = None
                index += 1
        elif quote is not None:
            if char == "\\":
                index += 1
            elif char == quote:
                quote = None
        elif char == "/" and next_char == "/":
            comment = "line"
            index += 1
        elif char == "/" and next_char == "*":
            comment = "block"
            index += 1
        elif char in "\"'":
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[begin:index + 1]
        index += 1
    raise ValueError(f"unterminated function {name}")

def executable_text(source):
    """Blank comments and literals without changing source positions.

    The matrix anchors are C statements.  Matching them in a comment or a
    diagnostic string would turn this placement check back into a checklist,
    so retain only executable tokens while preserving line layout for useful
    validator errors.
    """
    result = []
    quote = None
    comment = None
    index = 0
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if comment == "line":
            if char == "\n":
                comment = None
                result.append(char)
            else:
                result.append(" ")
        elif comment == "block":
            if char == "*" and next_char == "/":
                result.extend((" ", " "))
                comment = None
                index += 1
            else:
                result.append("\n" if char == "\n" else " ")
        elif quote is not None:
            result.append("\n" if char == "\n" else " ")
            if char == "\\" and index + 1 < len(source):
                index += 1
                escaped = source[index]
                result.append("\n" if escaped == "\n" else " ")
            elif char == quote:
                quote = None
        elif char == "/" and next_char == "/":
            result.extend((" ", " "))
            comment = "line"
            index += 1
        elif char == "/" and next_char == "*":
            result.extend((" ", " "))
            comment = "block"
            index += 1
        elif char in "\"'":
            result.append(" ")
            quote = char
        else:
            result.append(char)
        index += 1
    return "".join(result)

# Exercise the filtering rule itself.  Without these checks a future
# simplification can silently allow a stale matrix row to be satisfied by a
# review comment or an error message rather than a live entry edge.
anchor_selftest = "entry_instruction()"
if anchor_selftest in executable_text(
        "/* entry_instruction() */ \"entry_instruction()\" 'x'") or \
        anchor_selftest not in executable_text("entry_instruction();"):
    raise SystemExit("source-anchor comment/string filtering is broken")

with open(matrix, newline="", encoding="utf-8") as stream:
    rows = csv.DictReader(stream, delimiter="\t")
    for row in rows:
        try:
            filename, function = row["source"].split(":", 1)
            text = body(sources[filename], function)
        except (KeyError, ValueError) as error:
            raise SystemExit(f"{row.get('id', '?')}: {error}")
        if row["source_anchor"] not in executable_text(text):
            raise SystemExit(f"{row['id']}: source anchor is absent from "
                f"{row['source']}")
PY
for contract in \
	'EDGE-COMMON-001' \
	'EDGE-COMMON-002' \
	'EDGE-VMX-001' \
	'EDGE-VMX-002' \
	'EDGE-VMX-003' \
	'EDGE-NVMX-001' \
	'EDGE-NVMX-002' \
	'EDGE-NVMX-003' \
	'EDGE-NVMX-004' \
	'EDGE-NVMX-004A' \
	'EDGE-NVMX-005' \
	'EDGE-NVMX-005A' \
	'EDGE-NVMX-005B' \
	'EDGE-NVMX-006' \
	'EDGE-NVMX-007' \
	'EDGE-NVMX-008' \
	'EDGE-NVMX-009' \
	'EDGE-NVMX-010' \
	'EDGE-NVMX-011' \
	'EDGE-NVMX-012' \
	'EDGE-SVM-001' \
	'EDGE-SVM-002' \
	'EDGE-SVM-003'; do
	rg -q -F "$contract" "$entry_edge_matrix" ||
	    fail "machine-entry edge matrix omits: $contract"
done
vmx_entry_count=$(rg -c -F \
    'rc = vmx_enter_guest(vmxctx, vmx, launched);' "$vmx_source")
[ "$vmx_entry_count" -eq 2 ] ||
    fail "ordinary and nested VMX entry-edge inventory changed"
svm_entry_count=$(rg -c -F \
    'svm_launch(vmcb_pa, gctx, get_pcpu());' "$svm_source")
[ "$svm_entry_count" -eq 1 ] ||
    fail "SVM entry-edge inventory changed"
for contract in \
	'error = vm_handle_startup_wait(vcpu, &retu);' \
	'critical_enter();' \
	'restore_guest_fpustate(vcpu);' \
	'vcpu_require_state(vcpu, VCPU_RUNNING);' \
	'error = vmmops_run(vcpu->cookie, vcpu->nextrip, pmap, &evinfo,' \
	'startup_owner_active ? &startup_owner : NULL);' \
	'vcpu_require_state(vcpu, VCPU_FROZEN);' \
	'save_guest_fpustate(vcpu);' \
	'critical_exit();'; do
	rg -q -F "$contract" "$vmm_source" ||
	    fail "common production entry/unwind map omits: $contract"
done
for contract in \
	'disable_intr();' \
	'error = vmx_nested_vmcs02_intel_entry_instruction(' \
	'rc = vmx_enter_guest(vmxctx, vmx, launched);' \
	'error = vmx_nested_run_unwind_intel(vcpu, &event,' \
	'&unwind_action);'; do
	rg -q -F "$contract" "$vmx_source" ||
	    fail "VMX production entry/unwind map omits: $contract"
done
for contract in \
	'disable_gintr();' \
	'svm_launch(vmcb_pa, gctx, get_pcpu());' \
	'enable_gintr();' \
	'} while (handled);'; do
	rg -q -F "$contract" "$svm_source" ||
	    fail "SVM production entry/unwind map omits: $contract"
done
# CPU residency is an AMD-private execution cache, not an admission claim.
# It must become current only once VMRUN has actually executed; lifecycle
# exits before VMRUN otherwise suppress the ASID/cache refresh on the next
# real entry.  This source-order assertion is the rootless evidence available
# on the Intel development host; live AMD qualification remains a release
# gate rather than a fabricated passing test.
python3 - "$svm_source" <<'PY' || fail "SVM CPU-residency publication is not post-VMRUN"
import sys

source = open(sys.argv[1], encoding="utf-8").read()
start = source.index("static int\nsvm_run(")
end = source.index("\nstatic void\nsvm_vcpu_cleanup", start)
body = source[start:end]
launch = body.index("svm_launch(vmcb_pa, gctx, get_pcpu());")
publish = body.index("vcpu->lastcpu = curcpu;")
stat = body.index("vmm_stat_incr(vcpu->vcpu, VCPU_MIGRATIONS, 1);")
if not (launch < publish < stat):
    raise SystemExit(1)
if "migrated = vcpu->lastcpu != curcpu;" not in body:
    raise SystemExit(1)
PY
# private-test: svm-lastcpu-after-vmrun

# Snapshot records exclude host-cache fields entirely.  VMX host defaults/VPID
# and SVM ASID/EPT state are CPU-local execution caches; restoration must not
# reconstruct them from source-host values.
# VMX host defaults/VPID and SVM ASID/EPT state are CPU-local execution caches;
# a next entry must rebuild them even when source and destination CPU numbers
# happen to match.  This source-level contract is architecture-neutral in
# intent while the field mechanics remain private to each backend.
python3 - "$vmx_source" "$svm_source" "$vmm_source" <<'PY' || fail "snapshot restore violates the staged architecture contract"
import pathlib
import re
import sys

def body(text, name):
    match = re.search(r"\n" + re.escape(name) +
        r"\s*\([^;]*?\)\s*\{", text, re.S)
    if match is None:
        raise SystemExit(f"missing function {name}")
    start = text.find("{", match.start())
    depth = 0
    state = "code"
    offset = start
    while offset < len(text):
        ch = text[offset]
        nxt = text[offset + 1] if offset + 1 < len(text) else ""
        if state == "code":
            if ch == '"':
                state = "string"
            elif ch == "'":
                state = "char"
            elif ch == "/" and nxt == "*":
                state = "block"
                offset += 1
            elif ch == "/" and nxt == "/":
                state = "line"
                offset += 1
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start:offset + 1]
        elif state == "string":
            if ch == "\\":
                offset += 1
            elif ch == '"':
                state = "code"
        elif state == "char":
            if ch == "\\":
                offset += 1
            elif ch == "'":
                state = "code"
        elif state == "block" and ch == "*" and nxt == "/":
            state = "code"
            offset += 1
        elif state == "line" and ch == "\n":
            state = "code"
        offset += 1
    raise SystemExit(f"unterminated function {name}")

vmx = body(pathlib.Path(sys.argv[1]).read_text(), "vmx_vcpu_snapshot")
vmx_complete = body(pathlib.Path(sys.argv[1]).read_text(),
    "vmx_vm_snapshot_complete")
svm = body(pathlib.Path(sys.argv[2]).read_text(), "svm_vcpu_snapshot")
svm_apply = body(pathlib.Path(sys.argv[2]).read_text(),
    "svm_vcpu_snapshot_apply")
svm_vm = body(pathlib.Path(sys.argv[2]).read_text(), "svm_vm_snapshot")
svm_complete = body(pathlib.Path(sys.argv[2]).read_text(),
    "svm_vm_snapshot_complete")
common_vm = body(pathlib.Path(sys.argv[3]).read_text(), "vm_snapshot_vm")
for required in (
        "if (vcpui == NULL || meta == NULL)",
        "vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN"):
    if required not in vmx:
        raise SystemExit(f"VMX snapshot omits {required}")
if "err == 0 && meta->op == VM_SNAPSHOT_RESTORE" not in vmx or \
        "vmx_snapshot_arch_vcpu_publish(arch_stage);" not in vmx_complete or \
        "vcpu->state.lastcpu = NOCPU;" not in pathlib.Path(sys.argv[1]).read_text():
    raise SystemExit("VMX restore does not invalidate CPU-local defaults")
for required in (
        "struct vmx_snapshot_vmcs_state rollback_vmcs, snapshot_vmcs;",
        "err = vmx_snapshot_vmcs_state(vmcs, run, meta, &snapshot_vmcs,",
        "arch_stage->candidate_vmcs = snapshot_vmcs;",
        "arch_stage->rollback_vmcs = rollback_vmcs;",
        "arch_stage->valid = true;"):
    if required not in vmx:
        raise SystemExit(f"VMX snapshot omits transactional VMCS state: {required}")
if "vmx_snapshot_vmcs_state_apply(vmcs, run, &snapshot_vmcs);" in vmx:
    raise SystemExit("VMX vCPU callback publishes before VM-wide completion")
for required in (
        "vmx_snapshot_vmcs_state_apply(arch_stage->vmcs,",
        "vmx_nested_restore_transaction_commit(",
        "vmx_snapshot_arch_vcpu_publish(arch_stage);",
        "rollback_vmcs:",
        'panic("%s: VMCS rollback failed", __func__);'):
    if required not in vmx_complete:
        raise SystemExit(f"VMX VM-wide completion omits {required}")
if re.search(r"err\s*\+=\s*vmcs_snapshot_", vmx):
    raise SystemExit("VMX snapshot can continue after an ordered field error")
candidate_decode = vmx.find("err = vmx_snapshot_vmcs_state(vmcs, run, meta,")
nested_stage = vmx.find("err = vmx_vcpu_nested_snapshot(vcpu, meta);")
candidate_stage = vmx.find("arch_stage->candidate_vmcs = snapshot_vmcs;")
candidate_apply = vmx_complete.find("vmx_snapshot_vmcs_state_apply(arch_stage->vmcs,")
nested_commit = vmx_complete.find("vmx_nested_restore_transaction_commit(")
software_publish = vmx_complete.find("vmx_snapshot_arch_vcpu_publish(arch_stage);")
rollback = vmx_complete.find("rollback_vmcs:")
if min(candidate_decode, nested_stage, candidate_stage, candidate_apply,
       nested_commit, software_publish, rollback) < 0 or \
        not candidate_decode < nested_stage < candidate_stage or \
        not candidate_apply < nested_commit < software_publish < rollback:
    raise SystemExit("VMX VM-wide candidate, nested commit, or rollback ordering drifted")
for required in (
        "uint64_t snapshot_guest_msrs[GUEST_MSR_NUM];",
        "snapshot_pir_desc = *vcpu->pir_desc;",
        "snapshot_mtrr = vcpu->mtrr;",
		"vmx_snapshot_pir_desc_valid(vcpu->pir_desc)",
		"vmx_snapshot_pir_desc_valid(&snapshot_pir_desc)",
		"vm_mtrr_validate(&vcpu->mtrr,",
		"vm_mtrr_validate(&snapshot_mtrr,",
        "snapshot_ctx = vcpu->ctx;",
        "bcopy(snapshot_guest_msrs, arch_stage->guest_msrs,",
        "arch_stage->pir_desc = snapshot_pir_desc;",
        "arch_stage->mtrr = snapshot_mtrr;"):
    if required not in vmx:
        raise SystemExit(f"VMX software restore omits staged publication: {required}")
if "bcopy(snapshot_guest_msrs, vcpu->guest_msrs," in vmx:
    raise SystemExit("VMX software state publishes before VM-wide completion")
vmx_source = pathlib.Path(sys.argv[1]).read_text()
for required in (
		"pir_desc->pending <= 1",
		"pir_desc->unused[0] == 0",
		"pir_desc->unused[1] == 0",
		"pir_desc->unused[2] == 0",
		"vlapic_vtx->pending_prio = 0;"):
	if required not in vmx_source:
		raise SystemExit(f"VMX posted-interrupt restore omits {required}")
for required in (
		"if (vcpui == NULL || meta == NULL)",
		"vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN",
		"candidate = *vcpu;",
        "candidate.vmcb = vcpu->snapshot_vmcb;",
        "error = svm_vcpu_snapshot_apply(&candidate, meta);",
        "vcpu_stage->vcpu = vcpu;",
        "vcpu_stage->valid = true;"):
    if required not in svm:
        raise SystemExit(f"SVM restore omits {required}")
if "bcopy(candidate.vmcb, vcpu->vmcb, sizeof(*vcpu->vmcb));" in svm:
    raise SystemExit("SVM vCPU callback publishes before VM-wide completion")
for required in (
        "stage = malloc(sizeof(*stage), M_SVM, M_NOWAIT | M_ZERO);",
        "sc->snapshot_restore = stage;"):
    if required not in svm_vm:
        raise SystemExit(f"SVM VM-wide stage omits {required}")
for required in (
        "Complete all topology and frozen-state checks before first publication.",
        "bcopy(vcpu_stage->vcpu->snapshot_vmcb,",
        "vcpu_stage->vcpu->swctx = vcpu_stage->swctx;",
        "svm_snapshot_restore_free(stage);"):
    if required not in svm_complete:
        raise SystemExit(f"SVM VM-wide completion omits {required}")
topology_check = svm_complete.find(
    "Complete all topology and frozen-state checks before first publication.")
publish = svm_complete.find("bcopy(vcpu_stage->vcpu->snapshot_vmcb,")
if min(topology_check, publish) < 0 or topology_check > publish:
    raise SystemExit("SVM VM-wide topology validation follows publication")
for required in (
        "Destination CPU residency and translation caches start empty.",
        "vcpu->lastcpu = NOCPU;",
        "vcpu->eptgen = 0;",
        "vcpu->asid.gen = 0;",
        "vcpu->asid.num = 0;",
		"svm_set_dirty(vcpu_stage->vcpu, 0xffffffff);"):
    if required not in svm_complete:
        raise SystemExit(f"SVM shadow restore omits {required}")
for forbidden in (
        "SNAPSHOT_VAR_OR_LEAVE(vcpu->lastcpu",
        "SNAPSHOT_VAR_OR_LEAVE(vcpu->dirty",
        "SNAPSHOT_VAR_OR_LEAVE(vcpu->eptgen",
        "SNAPSHOT_VAR_OR_LEAVE(vcpu->asid.gen",
        "SNAPSHOT_VAR_OR_LEAVE(vcpu->asid.num",
        "vcpu_stage->lastcpu = candidate.lastcpu",
        "vcpu_stage->dirty = candidate.dirty",
        "vcpu_stage->eptgen = candidate.eptgen",
        "vcpu_stage->asid = candidate.asid"):
    if forbidden in svm:
        raise SystemExit(f"SVM snapshot retains source-host cache state: {forbidden}")
if "SVM_SNAPSHOT_CALL_OR_LEAVE" not in svm_apply or \
        re.search(r"err\s*\+=\s*(?:svm|vmcb)_snapshot_", svm_apply):
    raise SystemExit("SVM snapshot can continue after an ordered field error")
if "meta->op == VM_SNAPSHOT_SAVE && !vm_mtrr_validate(&vcpu->mtrr," not in svm_apply:
    raise SystemExit("SVM save does not validate its source MTRR image")
if "if (!vm_mtrr_validate(&vcpu->mtrr," not in svm_apply:
    raise SystemExit("SVM restore does not validate its decoded MTRR image")
svm_source = pathlib.Path(sys.argv[2]).read_text()
for required in (
        "vcpu->snapshot_vmcb = malloc_aligned(sizeof(struct vmcb), PAGE_SIZE,",
        "free(vcpu->snapshot_vmcb, M_SVM);"):
    if required not in svm_source:
        raise SystemExit(f"SVM restore candidate lifetime omits {required}")
for required in (
		"stage = mallocarray(maxcpus, sizeof(*stage), M_VM,",
		"vm_snapshot_x86_capture_all(vm, stage, maxcpus,",
		"vmm_snapshot_x86_transaction_encode(&transaction, stage,",
		"vmm_snapshot_x86_transaction_decode(wire, length, stage,",
		"vm_snapshot_x86_restore_plan_create(vm, &transaction, stage,",
		"vm_snapshot_x86_restore_plan_commit(vm, plan);",
		"vm_snapshot_x86_restore_plan_free(plan);",
		"explicit_bzero(wire, malloc_usable_size(wire));",
		"explicit_bzero(stage, malloc_usable_size(stage));"):
    if required not in common_vm:
        raise SystemExit(f"current common VMS2 transaction omits {required}")
decode = common_vm.find("vmm_snapshot_x86_transaction_decode(wire, length, stage,")
plan = common_vm.find("vm_snapshot_x86_restore_plan_create(vm, &transaction, stage,")
commit = common_vm.find("vm_snapshot_x86_restore_plan_commit(vm, plan);")
if min(decode, plan, commit) < 0 or not decode < plan < commit:
    raise SystemExit("current common VMS2 validation follows publication")
for forbidden in (
		"SNAPSHOT_VAR_OR_LEAVE",
		"vm_snapshot_common_restore",
		"struct vm_exit"):
    if forbidden in common_vm:
        raise SystemExit(f"obsolete native common snapshot remains: {forbidden}")
PY
# private-test: x86-mtrr-state-validation
mtrr_source="$src/sys/amd64/vmm/vmm_mtrr.c"
mtrr_test="$src/tests/sys/vmm/vmm_mtrr_test.c"
for contract in \
	'vm_mtrr_type_valid(' \
	'vm_mtrr_fixed_valid(' \
	'vm_mtrr_variable_masks(' \
	'vm_mtrr_maxphyaddr(' \
	'vm_mtrr_validate(' \
	'!vm_mtrr_type_valid(val & MTRR_DEF_TYPE)' \
	'!vm_mtrr_type_valid(val & MTRR_PHYSBASE_TYPE)' \
	'phys_addr_width < VMM_MTRR_PHYS_ADDR_WIDTH_MIN' \
	'phys_addr_width > VMM_MTRR_PHYS_ADDR_WIDTH_MAX' \
	'(val & ~mask_mask) != 0'; do
	rg -q -F "$contract" "$mtrr_source" ||
		fail "MTRR semantic validation is missing: $contract"
done
for anchor in \
	'validate_architectural_types' \
	'write_rejects_without_mutation' \
	'mtrr.fixed4k[7] = 2;' \
	'mtrr.var[9].mask = UINT64_C(1) << 63;' \
	'mtrr.var[0].base = (UINT64_C(1) << 36) | DOC_MTRR_WB;' \
	'vm_mtrr_maxphyaddr(DOC_MAXPHYADDR_MAX + 5)' \
	'vm_mtrr_validate(&mtrr, DOC_MAXPHYADDR_MIN - 1)' \
	'memcmp(&mtrr, &before, sizeof(mtrr))'; do
	rg -q -F "$anchor" "$mtrr_test" ||
		fail "MTRR independent regression is missing: $anchor"
done
rg -q -F 'ATF_TESTS_C+=	vmm_mtrr_test' "$src/tests/sys/vmm/Makefile" ||
	fail "MTRR regression is not installed"
for source in \
	"$src/sys/amd64/vmm/intel/vmx.c" \
	"$src/sys/amd64/vmm/intel/vmx_msr.c" \
	"$src/sys/amd64/vmm/amd/svm.c" \
	"$src/sys/amd64/vmm/amd/svm_msr.c"; do
	rg -q -F 'vm_mtrr_maxphyaddr(cpu_maxphyaddr)' "$source" ||
		fail "MTRR producer/consumer does not use the guest width: $source"
done
rg -q -F 'vm_mtrr_maxphyaddr(regs[0] & 0xffU)' "$src/sys/amd64/vmm/x86.c" ||
	fail "guest CPUID MAXPHYADDR is not clamped to the emulated MTRR width"
# private-test: host-cache-restore-invalidation
# private-test: architecture-record-staging-boundary
# private-test: all-vcpu-architecture-publication
# private-test: architecture-specific-assumption-audit
# VM_SNAPSHOT_VALIDATE is deliberately userspace-only.  The legacy VMX VMCS
# record now decodes into an explicit field candidate and rolls the opaque
# hardware object back if publication fails.  SVM stages every VMCB candidate
# to its VM-wide completion boundary; VMX still requires a corresponding
# all-vCPU coordinator around its opaque hardware object and nested commit.
# This validator prevents a private kernel validation ABI from being added as
# a shortcut around either boundary.
for contract in NVMX-PRIVATE-234 NVMX-PRIVATE-235 NVMX-PRIVATE-236 \
	NVMX-PRIVATE-237 NVMX-PRIVATE-238 NVMX-PRIVATE-239 \
	NVMX-PRIVATE-240; do
	rg -q -F "$contract" "$private_ledger" ||
	    fail "restore or architecture-specific private boundary is not inventoried: $contract"
done
rg -q -F 'XXX this needs to be fixed' "$src/sys/amd64/vmm/amd/svm.c" ||
	fail "SVM IRET/NMI caveat changed without an updated private-boundary review"
for marker in \
	'DecodeAssist capability' \
	'EFER_LMSLE' \
	'VMEXIT_EXTINT_INVALID' \
	'produced a record without it; retain the established narrow' \
	'We do this every time because we may setup the virtual machine' \
	'the processor retains global mappings when %cr3'; do
	rg -q -F "$marker" "$src/sys/amd64/vmm/amd/svm.c" \
	    "$src/sys/amd64/vmm/intel/vmx.c" ||
	    fail "architecture-specific compatibility boundary changed: $marker"
done
# private-test: live-runner-trust-boundary
# The privileged L1 runner and the executable bhyve input are part of the
# qualification root of trust.  They must not be selected through a symlink,
# a mutable group/other-writable file, or a hard-link alias that can be
# replaced outside the reviewed invocation.
for marker in \
	'trusted_executable()' \
	'trusted_regular_input()' \
	'PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin' \
	'umask 077' \
	'[ -f "$1" ] && [ ! -L "$1" ] && [ -r "$1" ]' \
	'trusted_path=$(/bin/realpath "$path")' \
	'trusted_workdir_hierarchy()' \
	'root-owned sticky directory, notably /tmp' \
	'workdir_trusted=1' \
	'component=$trusted_path' \
	'path component is writable by group or other' \
	'runner=$trusted_executable_path' \
	'NESTED_L1_IMAGE=$trusted_regular_input_path' \
	'NESTED_LINUX_L2_IMAGE=$trusted_regular_input_path' \
	'NESTED_FIVEBSD_L2_IMAGE=$trusted_regular_input_path' \
	'trusted_regular_input "$NESTED_L1_IMAGE" "L1 image"' \
	'trusted_regular_input "$NESTED_LINUX_L2_IMAGE" "Linux L2 image"' \
	'trusted_regular_input "$NESTED_FIVEBSD_L2_IMAGE" "5BSD L2 image"' \
	'bhyve=$trusted_executable_path' \
	'-k 30 "$live_timeout" "$runner"' \
	'"$3" -eq 1' \
	'trusted_executable "$NESTED_L1_RUNNER" "L1 runner"' \
	'trusted_executable "$bhyve" "bhyve"' \
	'runner_tmp=$(mktemp -d "$WORKDIR/runner-tmp.XXXXXX")' \
	'rm -rf -- "$runner_tmp"' \
	'if ! "$test_program" -l >"$case_log" 2>&1; then' \
	'env -i \' \
	'TMPDIR="$runner_tmp"' \
	'NESTED_LIVE_RUN_ID="$NESTED_LIVE_RUN_ID"' \
	'find -x "$staged_result" -type d -exec chmod u+rwx {} +'; do
	rg -q -F -- "$marker" "$live_runner" ||
	    fail "privileged nested live runner trust boundary omits: $marker"
done
# Keep the timeout itself on the reviewed command line rather than relying on
# a matching comment or an unrelated helper invocation.
rg -q -- '^[[:space:]]*timeout[[:space:]]+' "$live_runner" ||
	fail "privileged nested live runner omits the timeout command"
# FreeBSD timeout(1) acts as a descendant reaper unless --foreground/-f is
# selected.  The L1 runner can create bhyve and helper descendants, so
# foreground mode would let a timed-out qualification leave a guest behind.
! rg -q -- '^[[:space:]]*timeout[[:space:]]+(-f|--foreground)([[:space:]]|$)' \
	"$live_runner" ||
	fail "privileged nested live runner must not use timeout foreground mode"
# private-test: startup-production-entry-map

# private-test: startup-live-owner-observation-adapter
for contract in NVMX-EVENT-163 NVMX-PRIVATE-225; do
	rg -q -F "$contract" "$ledger" "$private_ledger" ||
	    fail "live startup-owner adapter is not inventoried: $contract"
done
for contract in \
	'vcpu_startup_entry_owner_guard_before(' \
	'vcpu_startup_entry_owner_retire('; do
	rg -q -F "$contract" "$vmm_vm_header" "$vmm_vm_source" ||
	    fail "live startup-owner adapter omits: $contract"
done
for contract in \
	'coordinator_error = vcpu_startup_event_run_token_check(vcpu,' \
	'notification_generation =' \
	'vcpu_startup_notify_generation_capture(vcpu);' \
	'notification_error = vmm_startup_entry_handoff_check(' \
	'return (vmm_startup_entry_owner_guard_before(owner,' \
	'return (vmm_startup_entry_owner_retire(owner, coordinator_error,'; do
	rg -q -F "$contract" "$vmm_vm_source" ||
	    fail "live startup-owner observation/composition omits: $contract"
done
live_owner_consumers=$(rg -l \
    'vcpu_startup_entry_owner_(guard_before|retire)' \
    "$src/sys/amd64/vmm" "$src/sys/arm64/vmm" "$src/sys/riscv/vmm" || true)
for source in $live_owner_consumers; do
	case "$source" in
	"$vmm_source"|"$vmx_source"|"$src/sys/amd64/vmm/intel/vmx.c"|"$svm_source")
		# VMX_NESTED_VMX_SOURCE may point at a temporary, deliberately
		# malformed fixture.  Keep the canonical VMX source in this allow-list
		# as well, so that a fixture can exercise a later source-order rule
		# without turning this earlier production-consumer inventory into the
		# reason it fails.
		# The common vm_run() tail is the one staged consumer: it may retire
		# an owner after a backend's pre-acquisition rejection.  VMX and SVM
		# each own one audited ordinary hardware-entry loop; nested VMX remains
		# separately fail-closed until its cold/hot unwind is converted.
		;;
	*)
		fail "live startup-owner adapter reached an unconverted machine consumer: $source"
		;;
	esac
done
# The stack owner is deliberately a common, value-only lifecycle protocol.
# It may eventually be consumed by each architecture's run loop, but it must
# not acquire an AMD64/VMX/SVM type, a pmap, or a register-width dependency in
# the common ABI merely because its first consumer will be Intel VMX.  This
# preserves a single contract for future arm64/riscv implementations and keeps
# architecture residency behind each run adapter.
if rg -n \
    '#include <machine/|\bpmap_t\b|\bregister_t\b|\bvmx_|\bsvm_|\bVMX_|\bSVM_|struct (vmx|svm|vmcs)' \
    "$startup_entry_owner_header" "$startup_entry_owner_source"; then
	fail "common startup-entry owner leaked an architecture-specific dependency"
fi
# private-test: startup-live-owner-observation-adapter

# private-test: startup-synchronous-run-owner-parameter
for contract in NVMX-EVENT-164 NVMX-PRIVATE-226; do
	rg -q -F "$contract" "$ledger" "$private_ledger" ||
	    fail "synchronous run-owner parameter is not inventoried: $contract"
done
for contract in \
	'struct vmm_startup_entry_owner;' \
	'struct vmm_startup_entry_owner *entry_owner));'; do
	rg -q -F "$contract" "$src/sys/amd64/include/vmm.h" ||
	    fail "amd64 run-owner operation declaration omits: $contract"
done
for contract in \
	'struct vmm_startup_entry_owner *entry_owner))' \
	'vmmops_run(vcpu->cookie, vcpu->nextrip, pmap, &evinfo,' \
	'startup_owner_active ? &startup_owner : NULL);'; do
	rg -q -F "$contract" "$vmm_source" ||
	    fail "common amd64 run-owner call boundary omits: $contract"
done
for contract in \
	'struct vmm_startup_entry_owner *entry_owner)' \
	'vcpu_startup_entry_owner_guard_before_attempt(vcpu->vcpu,' \
	'vmm_startup_entry_owner_commit_attempt(entry_owner)' \
	'vmm_startup_entry_owner_abort_attempt(entry_owner,' \
	'vmm_startup_entry_owner_guard_after(entry_owner,' \
	'nested_target, entry_owner));'; do
	rg -q -F "$contract" "$vmx_source" ||
	    fail "VMX run-owner ordinary-loop conversion omits: $contract"
done
for contract in \
	'struct vmm_startup_entry_owner *entry_owner)' \
	'vmm_startup_entry_owner_software_exit(entry_owner,' \
	'vcpu_startup_entry_owner_guard_before(vcpu->vcpu,' \
	'vmm_startup_entry_owner_guard_after(entry_owner,'; do
	rg -q -F "$contract" "$svm_source" ||
	    fail "SVM run-owner ordinary-entry conversion omits: $contract"
done
# The initial nested lifecycle return is provably before guest MSRs, VMCS02,
# EPT, and event ownership, so it may be a typed no-entry software exit.  The
# later cold/resumed/hot paths use the complete owner adapter instead: it
# records the common admission result, completes the selected Intel-private
# inverse on a refusal, and only then resolves the common result.
rg -q -U --pcre2 \
	'vmx_run_nested\(struct vmx_vcpu \*vcpu,[\s\S]*?struct vmm_startup_entry_owner \*entry_owner\)[\s\S]*?if \(vcpu == NULL \|\| pmap == NULL \|\| evinfo == NULL[\s\S]*?suspended = vcpu_suspended\(evinfo\);[\s\S]*?if \(suspended \|\| rendezvous \|\| reqidle \|\| yield \|\| debugged \|\| pvclock\)[\s\S]*?vmm_startup_entry_owner_software_exit\(entry_owner,[\s\S]*?return \(0\);[\s\S]*?vmx_msr_guest_enter\(vcpu\);' \
	"$vmx_source" ||
	fail "nested VMX lifecycle owner conversion is misordered"
# A refusal must complete private cleanup before publishing the common result.
# This is a source-order check on the actual production helper, not a check
# that merely sees the same names in a separate value-model file.
rg -q -U --pcre2 \
	'vmx_nested_owner_guard_attempt\([\s\S]*?vcpu_startup_entry_owner_guard_before_attempt\([\s\S]*?vmx_nested_run_unwind_intel\([\s\S]*?vmx_nested_owner_outcome_compose\([\s\S]*?vmx_nested_owner_outcome_resolve_preentry\(' \
	"$vmx_source" ||
	fail "nested VMX owner refusal does not unwind before resolving the common result"
for contract in NVMX-EVENT-172 NVMX-EVENT-173 NVMX-PRIVATE-250 NVMX-PRIVATE-251; do
	rg -q -F "$contract" "$ledger" "$private_ledger" ||
		fail "nested owner/unwind outcome contract is not inventoried: $contract"
done
# deferred-common-owner-prerequisite
for contract in NVMX-EVENT-174 NVMX-EVENT-175 NVMX-EVENT-176 NVMX-EVENT-177 NVMX-PRIVATE-252 NVMX-PRIVATE-253 NVMX-PRIVATE-254 NVMX-PRIVATE-255; do
	rg -q -F "$contract" "$ledger" "$private_ledger" ||
		fail "deferred common-owner contract is not inventoried: $contract"
done
for contract in \
	'VMM_STARTUP_ENTRY_OWNER_DEFERRED' \
	'vmm_startup_entry_owner_guard_before_defer' \
	'vmm_startup_entry_owner_resolve_deferred' \
	'vmm_startup_entry_owner_guard_after_defer' \
	'vmm_startup_entry_owner_resolve_deferred_after'; do
	rg -q -F "$contract" "$src/sys/dev/vmm/vmm_startup_entry_owner.c" \
	    "$src/sys/dev/vmm/vmm_startup_entry_owner.h" ||
		fail "deferred common-owner prerequisite omits: $contract"
done
rg -q -F 'entry_owner_deferred_preentry_resolution' \
	"$src/tests/sys/vmm/vmm_startup_entry_owner_test.c" ||
	fail "deferred common-owner prerequisite lacks an independent model"
rg -q -F 'entry_owner_deferred_postentry_resolution' \
    "$src/tests/sys/vmm/vmm_startup_entry_owner_test.c" ||
	fail "post-entry deferred common-owner prerequisite lacks an independent model"
rg -q -F 'entry_owner_deferred_postentry_state_product_is_exact' \
    "$src/tests/sys/vmm/vmm_startup_entry_owner_test.c" ||
	fail "post-entry deferred common-owner prerequisite lacks state-product coverage"
for contract in \
	'NVMX-EVENT-174.*preserving Intel-private outcome must equal the stored deferred guard error' \
	'NVMX-EVENT-175.*preserving Intel-private outcome must equal the stored deferred post-entry error'; do
	rg -q "$contract" "$ledger" ||
		fail "deferred common-owner exact-error binding is missing from the requirements ledger"
done
rg -q -U --pcre2 \
	'vmx_nested_owner_outcome_resolve_preentry[\s\S]*?outcome->error != owner->deferred\.error[\s\S]*?return \(EPROTO\)' \
	"$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" ||
	fail "pre-entry owner outcome does not bind its deferred error"
rg -q -U --pcre2 \
	'vmx_nested_owner_exit_outcome_resolve_postentry[\s\S]*?outcome->error != owner->deferred_exit\.error[\s\S]*?return \(EPROTO\)' \
	"$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" ||
	fail "post-entry owner outcome does not bind its deferred error"
rg -q -U --pcre2 \
	'vmx_nested_owner_outcome_resolve_preentry[\s\S]*?ranges_overlap\(owner,\s*sizeof\(\*owner\), result, sizeof\(\*result\)\)[\s\S]*?return \(EINVAL\)' \
	"$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" ||
	fail "pre-entry owner resolver permits mutable owner/result aliasing"
rg -q -U --pcre2 \
	'vmx_nested_owner_exit_outcome_resolve_postentry[\s\S]*?ranges_overlap\(owner,\s*sizeof\(\*owner\), result, sizeof\(\*result\)\)[\s\S]*?return \(EINVAL\)' \
	"$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" ||
	fail "post-entry owner resolver permits mutable owner/result aliasing"
rg -q -U --pcre2 \
	'preserved pre-entry outcome is bound[\s\S]*?guard_error = EBUSY[\s\S]*?EPROTO[\s\S]*?guard_error = EAGAIN[\s\S]*?LOOP_REPLAY' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "pre-entry deferred-error binding coverage is missing"
rg -q -U --pcre2 \
	'nested_owner_begin_running\(&token, &handoff, &owner\);[\s\S]*?resolve_preentry\(&owner, &outcome,[\s\S]*?\(struct vmm_startup_entry_loop_result \*\)\(void \*\)&owner\), EINVAL[\s\S]*?memcmp\(&owner, &owner_before, sizeof\(owner\)\), 0[\s\S]*?resolve_postentry\(&owner,[\s\S]*?\(struct vmm_startup_entry_loop_result \*\)\(void \*\)&owner\),[\s\S]*?EINVAL[\s\S]*?memcmp\(&owner, &owner_before, sizeof\(owner\)\), 0' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "deferred owner/result alias coverage is missing"
rg -q -U --pcre2 \
	'Immutable outcome storage must not alias the mutable common owner[\s\S]*?resolve_preentry\(&owner,[\s\S]*?\(const struct vmx_nested_owner_outcome \*\)\(const void \*\)&owner,[\s\S]*?EINVAL[\s\S]*?memcmp\(&owner, &owner_before, sizeof\(owner\)\), 0[\s\S]*?resolve_postentry\(&owner,[\s\S]*?\(const struct vmx_nested_owner_exit_outcome \*\)\(const void \*\)&owner,[\s\S]*?EINVAL[\s\S]*?memcmp\(&owner, &owner_before, sizeof\(owner\)\), 0' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "deferred owner/immutable-outcome alias coverage is missing"
for resolver in \
	vmx_nested_owner_outcome_resolve_preentry \
	vmx_nested_owner_exit_outcome_resolve_postentry; do
	rg -q -U --pcre2 \
		"${resolver}[\\s\\S]*?outcome == NULL[\\s\\S]*?ranges_overlap\\(owner,\\s*sizeof\\(\\*owner\\), outcome,[\\s\\S]*?Reject mutable storage aliases before interpreting immutable inputs[\\s\\S]*?validate\\(owner\\)" \
		"$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" ||
		fail "${resolver} validates an immutable outcome before rejecting aliases"
done
# The deferred post-entry result remains inside the owner until the matching
# private inverse completes.  Publishing it here would permit a caller to
# mistake a still-DEFERRED transaction for a returnable VMEXIT/replay.
rg -q -U --pcre2 \
	'vmm_startup_entry_owner_guard_after_defer\(\n\s*struct vmm_startup_entry_owner \*owner, int backend_error\)\n\{' \
	"$src/sys/dev/vmm/vmm_startup_entry_owner.c" ||
	fail "deferred post-entry owner publishes a provisional result"
rg -q -U --pcre2 \
	'vmm_startup_entry_owner_guard_after_defer\(\n\s*struct vmm_startup_entry_owner \*, int\);' \
	"$src/sys/dev/vmm/vmm_startup_entry_owner.h" ||
	fail "deferred post-entry owner public contract exposes a provisional result"
# deferred-owner-live-observation-boundary
rg -q -U --pcre2 \
	'vcpu_startup_entry_owner_observe\(struct vcpu \*vcpu,[\s\S]*?vcpu_startup_event_run_token_check\(vcpu,[\s\S]*?vcpu_startup_notify_generation_capture\(vcpu\)[\s\S]*?vmm_startup_entry_handoff_check\(' \
	"$src/sys/dev/vmm/vmm_vm.c" ||
	fail "deferred owner lacks its single live-observation helper"
rg -q -U --pcre2 \
	'vcpu_startup_entry_owner_guard_before_defer\(struct vcpu \*vcpu,[\s\S]*?vcpu_startup_entry_owner_observe\(vcpu, owner,[\s\S]*?vmm_startup_entry_owner_guard_before_defer\(owner,' \
	"$src/sys/dev/vmm/vmm_vm.c" ||
fail "deferred pre-entry owner bypasses the live-observation helper"
rg -q -U --pcre2 \
	'vcpu_startup_entry_owner_guard_before_attempt\(struct vcpu \*vcpu,[\s\S]*?vcpu_startup_entry_owner_observe\(vcpu, owner,[\s\S]*?vmm_startup_entry_owner_guard_before_attempt\(owner,' \
	"$src/sys/dev/vmm/vmm_vm.c" ||
	fail "attempted-entry owner bypasses the live-observation helper"
count=$(rg -c '^vcpu_startup_entry_owner_guard_before_defer\(' \
	"$src/sys/dev/vmm/vmm_vm.c" || true)
[ "$count" -eq 1 ] ||
	fail "deferred pre-entry wrapper has an unexpected live-observation implementation count"
count=$(rg -c '^vcpu_startup_entry_owner_guard_before_attempt\(' \
	"$src/sys/dev/vmm/vmm_vm.c" || true)
[ "$count" -eq 1 ] ||
	fail "attempted-entry wrapper has an unexpected live-observation implementation count"
# Ordinary VMX has a complete, separately checked attempted-entry transaction.
# Nested VMX now uses the same common protocol through a private adapter; SVM
# retains its independently reviewed generic ordinary-loop boundary.
if rg -q 'vcpu_startup_entry_owner_guard_before_(defer|attempt)' \
	"$src/sys/amd64/vmm/amd/svm.c"; then
	fail "SVM attempted/deferred owner was wired without a reviewed transaction"
fi
rg -q -F '#include "vmx_nested_owner_outcome.h"' "$vmx_source" ||
	fail "nested VMX runtime does not import its reviewed owner adapter"
rg -q -F 'vmx_nested_owner_outcome.c' "$src/sys/modules/vmm/Makefile" ||
	fail "nested VMX owner adapter is not linked into vmm.ko"
# Keep the runtime boundary intentionally narrow: only the adapter helpers and
# state-preserving owner transitions may operate on the common owner.  This
# protects against later device-specific calls bypassing the value protocol.
nested_owner_body=$(awk '
    /^static int$/ { candidate = 1; next }
    candidate && /^vmx_run_nested\(/ { in_body = 1; candidate = 0 }
    candidate { candidate = 0 }
    in_body && /^static [[:alnum:]_]+$/ { exit }
    in_body { print }
' "$vmx_source")
[ -n "$nested_owner_body" ] ||
	fail "cannot isolate vmx_run_nested for owner-boundary validation"
nested_owner_calls=$(printf '%s\n' "$nested_owner_body" |
	rg -o 'vmm_startup_entry_owner_[a-z_]+' | sort -u | tr '\n' ' ' || true)
case " $nested_owner_calls " in
*' vmm_startup_entry_owner_software_exit '* ) ;;
*) fail "nested VMX owner boundary lost its lifecycle owner transition" ;;
esac
case " $nested_owner_calls " in
*' vmm_startup_entry_owner_abort_attempt '* ) ;;
*) fail "nested VMX owner boundary cannot retire a retryable pending attempt" ;;
esac
case " $nested_owner_calls " in
*' vmm_startup_entry_owner_abort_attempt_error '* ) ;;
*) fail "nested VMX owner boundary cannot retire a failed pending attempt" ;;
esac
# nested-owner-postentry-outcome-prerequisite
for contract in \
	'vmx_nested_owner_outcome_resolve_preentry' \
	'vmx_nested_owner_exit_outcome_compose' \
	'vmx_nested_owner_exit_outcome_resolve_postentry' \
	'VMX_NESTED_OWNER_EXIT_OUTCOME_TERMINAL_UNWIND' \
	'nested_owner_exit_unwind_outcome_composition'; do
	rg -q -F "$contract" "$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" \
	    "$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.h" \
	    "$src/tests/sys/vmm/vmx_nested_state_test.c" ||
		fail "nested post-entry outcome prerequisite omits: $contract"
done
# nested-noentry-owner-boundary
for contract in NVMX-EVENT-178 NVMX-PRIVATE-256; do
	rg -q -F "$contract" "$ledger" "$private_ledger" ||
	fail "nested no-entry owner boundary is not inventoried: $contract"
done
rg -q -U --pcre2 \
	'vmx_run_nested\(struct vmx_vcpu \*vcpu,[\s\S]*?suspended = vcpu_suspended\(evinfo\);[\s\S]*?if \(suspended \|\| rendezvous \|\| reqidle \|\| yield \|\| debugged \|\| pvclock\)[\s\S]*?vmm_startup_entry_owner_software_exit\(entry_owner,[\s\S]*?return \(0\);[\s\S]*?vmx_msr_guest_enter\(vcpu\);' \
	"$vmx_source" ||
	fail "nested no-entry owner boundary is no longer before private residency"
rg -q -U --pcre2 \
	'vmx_nested_owner_guard_or_exit\([\s\S]*?vmx_nested_owner_guard_attempt\(vcpu, event, entry_owner, &enter\)' \
	"$vmx_source" ||
	fail "nested owner-admission wrapper no longer delegates to the typed guard"
count=$(rg -o 'vmx_nested_owner_guard_or_exit\(vcpu, rip, &event,' \
	"$vmx_source" | wc -l | tr -d ' ')
[ "$count" -eq 3 ] ||
	fail "nested owner admission is not present on all initial/resumed/hot entry paths"
rg -q -F 'nested_noentry_owner_outcome_matrix' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "nested no-entry owner boundary lacks its unwind/outcome matrix"
# nested-unwind-action-handoff
for contract in NVMX-EVENT-179 NVMX-PRIVATE-257; do
	rg -q -F "$contract" "$ledger" "$private_ledger" ||
		fail "nested unwind action handoff is not inventoried: $contract"
done
rg -q -U --pcre2 \
	'vmx_nested_run_unwind_intel\(struct vmx_vcpu \*vcpu,[\s\S]*?enum vmx_nested_run_unwind_action \*actionp\)[\s\S]*?vmx_nested_run_unwind_select\(&input, &action\)[\s\S]*?switch \(action\) \{[\s\S]*?\n\t\}[\s\S]*?Publish it only after[\s\S]*?if \(actionp != NULL\)[\s\S]*?\*actionp = action;' \
	"$vmx_source" ||
	fail "nested unwind action is not selected and published only after cleanup"
# The action out-parameter is consumed by two owner bridges.  It must be
# initialized to the non-composable fail-stop value before any validation or
# private inverse can return, and both bridges must reject that sentinel.
# Otherwise an unexpected private cleanup failure could be composed from an
# indeterminate enum value and published as a guest-visible result.
rg -q -U --pcre2 \
	'vmx_nested_run_unwind_intel\(struct vmx_vcpu \*vcpu,[\s\S]*?if \(actionp != NULL\)[\s\S]*?\*actionp = VMX_NESTED_RUN_UNWIND_FAIL_STOP;[\s\S]*?vmx_nested_run_unwind_select\(&input, &action\)' \
	"$vmx_source" ||
	fail "nested unwind action lacks a fail-stop output sentinel"
rg -q -U --pcre2 \
	'vmx_nested_owner_guard_attempt\([\s\S]*?action = VMX_NESTED_RUN_UNWIND_FAIL_STOP;[\s\S]*?vmx_nested_run_unwind_intel\([\s\S]*?if \(action == VMX_NESTED_RUN_UNWIND_FAIL_STOP\)[\s\S]*?panic\(' \
	"$vmx_source" ||
	fail "nested guard owner may compose an unpublished unwind action"
rg -q -U --pcre2 \
	'fail_intr:[\s\S]*?unwind_action = VMX_NESTED_RUN_UNWIND_FAIL_STOP;[\s\S]*?vmx_nested_run_unwind_intel\(vcpu, &event,[\s\S]*?&unwind_action\)[\s\S]*?if \(unwind_action == VMX_NESTED_RUN_UNWIND_FAIL_STOP\)[\s\S]*?panic\([\s\S]*?vmx_nested_owner_settle_unwind_error\(entry_owner,[\s\S]*?unwind_action' \
	"$vmx_source" ||
	fail "nested unwind action is not handed to the common owner after private cleanup"
# nested-vmcs02-transaction-graph
for contract in NVMX-EVENT-180 NVMX-EVENT-181 NVMX-PRIVATE-258 NVMX-PRIVATE-259 \
	EDGE-NVMX-007 EDGE-NVMX-008 EDGE-NVMX-009; do
	rg -q -F "$contract" "$ledger" "$private_ledger" "$entry_edge_matrix" ||
		fail "nested VMCS02 transaction graph is not fully inventoried: $contract"
done
rg -q -U --pcre2 \
	'vmx_nested_run_pmap_activate\(vmx, &run_pmap\);[\s\S]*?rc = vmx_enter_guest\(vmxctx, vmx, launched\);[\s\S]*?vmx_nested_run_pmap_deactivate\(vmx, &run_pmap\);[\s\S]*?vmx_dr_leave_guest\(vmxctx\);[\s\S]*?handled = vmx_exit_process\(vmx, vcpu, vmexit\);[\s\S]*?vmx_nested_hot_exit_freeze_publish\(' \
	"$vmx_source" ||
	fail "nested VMCS02 transaction graph lost entry/exit source ordering"
rg -q -F 'nested_owner_common_outcome_composition' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "nested VMCS02 transaction graph lacks common/private outcome composition evidence"
! rg -q -F 'vmx_nested_owner_outcome.c' "$startup_entry_owner_test_source" ||
	fail "portable startup-owner test imports an Intel-private outcome model"
# nested-owner-exit-kind-boundaries
for contract in NVMX-EVENT-182 NVMX-PRIVATE-260 \
	EDGE-NVMX-010 EDGE-NVMX-011 EDGE-NVMX-012; do
	rg -q -F "$contract" "$ledger" "$private_ledger" "$entry_edge_matrix" ||
		fail "nested owner exit-kind boundary is not inventoried: $contract"
done
rg -q -U --pcre2 \
	'if \(attempt\.action ==[\s\S]*?VMX_NESTED_ATTEMPT_INITIAL_REJECTION\)[\s\S]*?vmx_nested_publish_initial_rejection\([\s\S]*?VM_EXITCODE_VMM_INTERNAL' \
	"$vmx_source" ||
	fail "nested initial hardware rejection lost its no-entry publication boundary"
rg -q -U --pcre2 \
	'rc = vmx_enter_guest\(vmxctx, vmx, launched\);[\s\S]*?vmx_nested_hardware_report_intel[\s\S]*?VMX_NESTED_OUTER_EXIT_EPT_WALK[\s\S]*?vmx_nested_publish_ept_exit_hot\([\s\S]*?VMX_NESTED_EXIT_REFLECT_L1[\s\S]*?vmx_nested_publish_reflected_exit_hot\(' \
	"$vmx_source" ||
	fail "nested real-exit EPT/reflection publication ordering drifted"
rg -q -U --pcre2 \
	'VMX_NESTED_OUTER_EXIT_EPT_WALK[\s\S]*?vmx_nested_owner_defer_postentry\(entry_owner,[\s\S]*?VMX_NESTED_RUN_UNWIND_FREEZE_HOT[\s\S]*?VMX_NESTED_EXIT_REFLECT_L1[\s\S]*?vmx_nested_owner_defer_postentry\(entry_owner,[\s\S]*?VMX_NESTED_RUN_UNWIND_CLEAN' \
	"$vmx_source" ||
	fail "nested EPT/reflection owner routes do not describe their completed private inverses"
rg -q -F 'nested_hardware_attempt_plan' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "nested initial rejection lacks an independent hardware-attempt model"
rg -q -F 'vmexit_dispatch_transaction' \
	"$src/tests/sys/vmm/vmx_nested_state_test.c" ||
	fail "nested post-entry EPT/reflection lacks an independent dispatch model"
# nested-owner-unwind-outcome-preservation
rg -q -F 'EDGE-NVMX-005A' "$entry_edge_matrix" ||
	fail "nested owner/unwind edge is absent from the machine-entry matrix"
rg -q -U --pcre2 \
	'vmx_nested_run_unwind_select\([\s\S]*?VMX_NESTED_RUN_UNWIND_DETACH_FATAL' \
	"$src/sys/amd64/vmm/intel/vmx_nested_run.c" ||
	fail "nested unwind selector no longer identifies fatal detach"
rg -q -F 'vmx_nested_owner_outcome_compose' \
	"$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" ||
	fail "nested owner/unwind value protocol is absent"
rg -q -F 'VMX_NESTED_OWNER_OUTCOME_TERMINAL_UNWIND' \
	"$src/sys/amd64/vmm/intel/vmx_nested_owner_outcome.c" ||
	fail "nested terminal unwind no longer dominates the owner result"
rg -q -U --pcre2 \
	'vmx_run_nested\(struct vmx_vcpu \*vcpu,[\s\S]*?vmx_nested_hot_residency_abort_intel\(vcpu,[\s\S]*?vmx_nested_owner_settle_unwind_error\(entry_owner,[\s\S]*?VMX_NESTED_RUN_UNWIND_DETACH_FATAL' \
	"$vmx_source" ||
	fail "nested owner boundary no longer preserves fatal-unwind outcome"
# nested-owner-post-entry-outcome-preservation
rg -q -U --pcre2 \
	'vmx_run_nested\(struct vmx_vcpu \*vcpu,[\s\S]*?vmx_exit_process\(vmx, vcpu, vmexit\);[\s\S]*?vmx_nested_hot_exit_freeze_publish\(' \
	"$vmx_source" ||
	fail "nested post-entry freeze boundary is no longer source-ordered"
rg -q -U --pcre2 \
	'svm_run\(void \*vcpui,[\s\S]*?svm_dr_enter_guest\(gctx\);[\s\S]*?vcpu_startup_entry_owner_guard_before\(vcpu->vcpu,[\s\S]*?if \(error != 0 \|\| owner_runtime.action !=[\s\S]*?svm_dr_leave_guest\(gctx\);[\s\S]*?svm_pmap_deactivate\(pmap\);[\s\S]*?svm_set_dirty\(vcpu, 0xffffffff\);[\s\S]*?enable_gintr\(\);[\s\S]*?break;[\s\S]*?svm_launch\(vmcb_pa, gctx, get_pcpu\(\)\);[\s\S]*?handled = svm_vmexit\(svm_sc, vcpu, vmexit\);[\s\S]*?vmm_startup_entry_owner_guard_after\(entry_owner,' \
	"$svm_source" ||
	fail "SVM run-owner guard/cleanup is not ordered around VMRUN"
if rg -q -F 'vmm_startup_entry_owner' "$src/sys/arm64" "$src/sys/riscv"; then
	fail "amd64-private run-owner parameter leaked to another architecture"
fi
# private-test: startup-synchronous-run-owner-parameter

for source in "$vmm_source" "$vmx_source" "$svm_source"; do
	if rg -q 'vmm_startup_entry_(guard_before|guard_after|handoff_check)' \
	    "$source"; then
		fail "startup stack owner was wired before production qualification: $source"
	fi
done
# private-test: startup-activation-completeness
#
# VMX has a complete ordinary/nested entry-owner conversion and an explicit
# bhyve manager handshake.  SVM remains unavailable until its startup dispatcher
# and frozen-target transaction are implemented.
for contract in NVMX-EVENT-162 NVMX-EVENT-163 NVMX-EVENT-164 \
	NVMX-EVENT-168 NVMX-EVENT-169 NVMX-EVENT-170 NVMX-EVENT-171 NVMX-EVENT-172 NVMX-EVENT-173 NVMX-EVENT-174 NVMX-EVENT-175 NVMX-EVENT-176 NVMX-EVENT-177 NVMX-EVENT-178 NVMX-PRIVATE-224 NVMX-PRIVATE-225 \
	NVMX-PRIVATE-226 NVMX-PRIVATE-245 NVMX-PRIVATE-246 \
	NVMX-PRIVATE-247 NVMX-PRIVATE-248 NVMX-PRIVATE-249 NVMX-PRIVATE-250 NVMX-PRIVATE-251 NVMX-PRIVATE-252 NVMX-PRIVATE-253 NVMX-PRIVATE-254 NVMX-PRIVATE-255 NVMX-PRIVATE-256; do
	rg -q -F "$contract" "$ledger" "$private_ledger" ||
		fail "startup activation completeness contract is not inventoried: $contract"
done
rg -q -U --pcre2 \
	'vmx_startup_kernel_actions_ready\(void\)[\s\S]*?return \(true\);' \
	"$vmx_source" ||
	fail "VMX startup readiness is not enabled after all-path owner conversion"
rg -q -U --pcre2 \
	'svm_startup_kernel_actions_ready\(void\)[\s\S]*?return \(false\);' \
	"$svm_source" ||
	fail "SVM startup readiness changed without an all-path owner conversion review"
# vmm_dev.c is also built by arm64 and riscv.  The complete private startup
# ABI, including its amd64-only machine operation, must remain inside one
# architecture guard rather than leaking a vmmops dependency into other VMMs.
rg -q -U --pcre2 \
	'#ifdef __amd64__[\s\S]*?vmmdev_startup_kernel_actions_ready\(void\)[\s\S]*?vmmops_startup_kernel_actions_ready\(\)[\s\S]*?VM_STARTUP_REQUEST[\s\S]*?#endif /\* __amd64__ \*/' \
	"$src/sys/dev/vmm/vmm_dev.c" ||
	fail "amd64 startup ABI is not fully contained in its architecture guard"
rg -q -U --pcre2 \
	'vmx_startup_apply_l0\([\s\S]*?vmm_x86_startup_machine_execute\([\s\S]*?\*errorp = error;[\s\S]*?vmx_nested_startup_machine_disposition\(error, &result\)' \
	"$vmx_source" ||
	fail "VMX frozen startup apply is not bound to the typed common transaction"
rg -q -U --pcre2 \
	'svm_vcpu_startup_event_step\([\s\S]*?return \(EOPNOTSUPP\);' \
	"$svm_source" ||
	fail "SVM startup dispatcher changed without an all-path owner conversion review"
# private-test: startup-activation-completeness
# private-test: startup-stack-owner-order

# A common dirty-log scan must publish an all-or-nothing canonical bitmap.  It
# accepts only an already-frozen ticket and architecture-neutral leaf values.
# The separately invoked clear walk is part of that portable transaction, but
# neither operation may smuggle a pmap or architecture-private backend into
# common code.
# private-test: dirty-log-collector-atomic-publication
dirty_collector_header="$src/sys/dev/vmm/vmm_dirty_log_collector.h"
dirty_collector_source="$src/sys/dev/vmm/vmm_dirty_log_collector.c"
dirty_collector_test="$src/tests/sys/vmm/vmm_dirty_log_collector_test.c"
for source in "$dirty_collector_header" "$dirty_collector_source" \
	"$dirty_collector_test"; do
	[ -f "$source" ] || fail "portable dirty-log collector evidence is missing: $source"
done
rg -q -U --pcre2 \
	'vmm_dirty_log_collect\([\s\S]*?vmm_dirty_log_owner_ticket_check\([\s\S]*?vmm_address_ranges_overlap\([\s\S]*?memset\(staging, 0, staging_bytes\)[\s\S]*?collector->query[\s\S]*?vmm_dirty_log_bitmap_mark_range[\s\S]*?vmm_dirty_log_owner_ticket_check\([\s\S]*?memcpy\(bitmap, staging, bitmap_bytes\)' \
	"$dirty_collector_source" ||
	fail "dirty-log collector lost its staged publication transaction"
! rg -q 'pmap_|vmx_|svm_' "$dirty_collector_header" \
	"$dirty_collector_source" ||
	fail "portable dirty-log collector leaked a private backend or clear operation"
for test_case in observe_publishes_only_after_full_scan \
	failed_scan_and_stale_ticket_do_not_publish \
	superleaf_is_clipped_to_ticket_range \
	malformed_leaf_and_alias_do_not_publish; do
	rg -q -F "$test_case" "$dirty_collector_test" ||
		fail "dirty-log collector negative/atomicity test is missing: $test_case"
done
# private-test: dirty-log-collector-atomic-publication

# The portable wire and transaction layer must remain compilable with a
# 32-bit size_t even though live VMX qualification runs on amd64.  This catches
# count-to-size conversions and pointer bounds that amd64 execution cannot
# expose.  These sources are CPU-independent value code and need no link step.
cc=${CC:-cc}
"$cc" -m32 -std=gnu17 -Werror -Wall -Wextra \
    -I "$src/sys" -I "$src/sys/amd64/vmm/intel" -fsyntax-only \
	"$src/sys/dev/vmm/vmm_dirty_log.c" \
	"$src/sys/dev/vmm/vmm_dirty_log_map.c" \
	"$src/sys/dev/vmm/vmm_dirty_log_owner.c" \
	"$src/sys/dev/vmm/vmm_dirty_log_collector.c" \
    "$src/sys/amd64/vmm/intel/vmx_nested_state.c" \
    "$src/sys/amd64/vmm/intel/vmx_nested_checkpoint.c" \
    "$src/sys/amd64/vmm/intel/vmx_nested_vmcs_registry_state.c" ||
    fail "32-bit nested checkpoint portability compilation failed"

entries=$(awk 'END { print NR - 1 }' "$ledger")
echo "nested-vmx requirements: $entries entries validated"
private_entries=$(awk 'END { print NR - 1 }' "$private_ledger")
echo "nested-vmx non-standard interfaces: $private_entries entries validated"
live_entries=$(awk 'END { print NR - 1 }' "$live_ledger")
echo "nested-vmx live qualification: $live_entries feature groups tracked"
