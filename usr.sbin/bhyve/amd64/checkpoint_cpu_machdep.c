/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

/*
 * bhyve is built against the source tree while the host may still expose an
 * older installed machine/vmm*.h pair.  This checkpoint writer consumes the
 * current source ABI (baseline CPUID and CPU-compatibility records), so do
 * not let the installed compatibility headers silently select an older view.
 */
#include <amd64/include/vmm.h>
#include <amd64/include/vmm_dev.h>

#include <vmmapi.h>

#include "checkpoint_cpu.h"

#define	CPUID_BASIC_LIMIT	256U
#define	CPUID_EXTENDED_BASE	0x80000000U
#define	CPUID_HYPERVISOR_BASE	0x40000000U
#define	CPUID_HYPERVISOR_LAST	0x40000001U
#define	CPU_CONTRACT_X86_PLATFORM 0xfffffffdU
#define	CPU_CONTRACT_X86_POLICY	0xfffffffeU
#define	CPU_CONTRACT_X86_NESTED	0xffffffffU

static int
capture_one(struct vcpu *vcpu, struct checkpoint_cpu_contract *contract,
    uint32_t selector, uint32_t parameter)
{
	struct checkpoint_cpu_record *record;
	uint32_t eax, ebx, ecx, edx;

	if (contract->record_count >= CHECKPOINT_CPU_MAX_RECORDS)
		return (E2BIG);
	eax = selector;
	ebx = 0;
	ecx = parameter;
	edx = 0;
	errno = 0;
	if (vm_get_cpuid(vcpu, VM_CPUID_F_BASELINE, &eax, &ebx, &ecx,
	    &edx) != 0)
		return (errno != 0 ? errno : EIO);
	record = &contract->records[contract->record_count++];
	record->selector = selector;
	record->parameter = parameter;
	record->values[0] = eax;
	record->values[1] = ebx;
	record->values[2] = ecx;
	record->values[3] = edx;
	return (0);
}

static int
capture_cache_subleaves(struct vcpu *vcpu,
    struct checkpoint_cpu_contract *contract, uint32_t selector)
{
	size_t before;
	int error;

	/*
	 * CPUID.04H and CPUID.8000001DH terminate when EAX[4:0] is zero.
	 * Subleaf zero is already present in the contract when this helper is
	 * called, so do not query a non-existent subleaf one for a processor with
	 * no deterministic-cache records.
	 */
	before = contract->record_count - 1;
	if ((contract->records[before].values[0] & 0x1fU) == 0)
		return (0);
	for (uint32_t parameter = 1;
	    contract->record_count < CHECKPOINT_CPU_MAX_RECORDS; parameter++) {
		before = contract->record_count;
		error = capture_one(vcpu, contract, selector, parameter);
		if (error != 0)
			return (error);
		if ((contract->records[before].values[0] & 0x1fU) == 0)
			return (0);
	}
	return (E2BIG);
}

static int
capture_topology_subleaves(struct vcpu *vcpu,
    struct checkpoint_cpu_contract *contract, uint32_t selector)
{
	size_t before;
	int error;

	/*
	 * CPUID.0BH and CPUID.1FH enumerate topology levels until EBX[15:0]
	 * is zero.  The number of levels is not fixed: in addition to SMT and
	 * core, current and future processors may expose die, module, or other
	 * hierarchy levels.  Preserve the terminating leaf as well, since it is
	 * guest-visible and is part of the CPU execution contract.
	 */
	before = contract->record_count - 1;
	if ((contract->records[before].values[1] & 0xffffU) == 0)
		return (0);
	for (uint32_t parameter = 1;
	    contract->record_count < CHECKPOINT_CPU_MAX_RECORDS; parameter++) {
		before = contract->record_count;
		error = capture_one(vcpu, contract, selector, parameter);
		if (error != 0)
			return (error);
		if ((contract->records[before].values[1] & 0xffffU) == 0)
			return (0);
	}
	return (E2BIG);
}

static int
capture_range(struct vcpu *vcpu, struct checkpoint_cpu_contract *contract,
    uint32_t first, uint32_t last)
{
	int error;

	if (last < first || last - first >= CPUID_BASIC_LIMIT)
		return (E2BIG);
	for (uint32_t selector = first;; selector++) {
		error = capture_one(vcpu, contract, selector, 0);
		if (error != 0)
			return (error);
		switch (selector) {
		case 4:
		case 0x8000001dU:
			error = capture_cache_subleaves(vcpu, contract, selector);
			break;
		case 0xb:
		case 0x1f:
			error = capture_topology_subleaves(vcpu, contract, selector);
			break;
		case 0xd: {
			uint64_t xcr0;

			xcr0 = contract->records[
			    contract->record_count - 1].values[0] |
			    ((uint64_t)contract->records[
			    contract->record_count - 1].values[3] << 32);
			error = capture_one(vcpu, contract, selector, 1);
			for (uint32_t bit = 2; error == 0 && bit < 64; bit++) {
				if ((xcr0 & (UINT64_C(1) << bit)) != 0)
					error = capture_one(vcpu, contract,
					    selector, bit);
			}
			break;
		}
		default:
			break;
		}
		if (error != 0 || selector == last)
			return (error);
	}
}

int
checkpoint_cpu_contract_capture(struct vcpu *vcpu,
    struct checkpoint_cpu_contract *contract)
{
	struct checkpoint_cpu_contract candidate;
	struct checkpoint_cpu_record *record;
	struct vm_cpu_compat compat;
	uint32_t extended_last;
	int error;

	if (vcpu == NULL || contract == NULL)
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.version = CHECKPOINT_CPU_CONTRACT_VERSION;
	candidate.architecture = CHECKPOINT_CPU_ARCH_AMD64;

	error = capture_one(vcpu, &candidate, 0, 0);
	if (error != 0)
		return (error);
	error = capture_range(vcpu, &candidate, 1,
	    candidate.records[0].values[0]);
	if (error != 0)
		return (error);
	error = capture_range(vcpu, &candidate, CPUID_HYPERVISOR_BASE,
	    CPUID_HYPERVISOR_LAST);
	if (error != 0)
		return (error);
	error = capture_one(vcpu, &candidate, CPUID_EXTENDED_BASE, 0);
	if (error != 0)
		return (error);
	extended_last =
	    candidate.records[candidate.record_count - 1].values[0];
	if (extended_last < CPUID_EXTENDED_BASE)
		return (EPROTO);
	if (extended_last > CPUID_EXTENDED_BASE)
		error = capture_range(vcpu, &candidate,
		    CPUID_EXTENDED_BASE + 1, extended_last);
	if (error == 0) {
		errno = 0;
		if (vm_get_cpu_compat(vcpu, &compat) != 0)
			error = errno != 0 ? errno : EIO;
	}
	if (error == 0 && (compat.version != VM_CPU_COMPAT_VERSION ||
	    (compat.flags & ~VM_CPU_COMPAT_F_VALID) != 0 ||
	    compat.x2apic_state > X2APIC_ENABLED ||
	    compat.tsc_frequency == 0))
		error = EPROTO;
	if (error == 0) {
		if (candidate.record_count + 3 > CHECKPOINT_CPU_MAX_RECORDS)
			return (E2BIG);
		record = &candidate.records[candidate.record_count++];
		record->selector = CPU_CONTRACT_X86_PLATFORM;
		record->parameter = 0;
		record->values[0] = (uint32_t)compat.tsc_frequency;
		record->values[1] = (uint32_t)(compat.tsc_frequency >> 32);
		record->values[2] = compat.x2apic_state;
		record->values[3] = 0;
		record = &candidate.records[candidate.record_count++];
		record->selector = CPU_CONTRACT_X86_POLICY;
		record->parameter = 0;
		record->values[0] = (uint32_t)compat.xcr0_allowed;
		record->values[1] = (uint32_t)(compat.xcr0_allowed >> 32);
		record->values[2] = compat.xsave_max_size;
		record->values[3] = compat.flags;
		record = &candidate.records[candidate.record_count++];
		record->selector = CPU_CONTRACT_X86_NESTED;
		record->parameter = 0;
		record->values[0] =
		    (uint32_t)compat.nested_capability_signature;
		record->values[1] =
		    (uint32_t)(compat.nested_capability_signature >> 32);
		record->values[2] =
		    (uint32_t)compat.nested_schema_signature;
		record->values[3] =
		    (uint32_t)(compat.nested_schema_signature >> 32);
	}
	if (error == 0)
		error = checkpoint_cpu_contract_validate(&candidate);
	if (error != 0)
		return (error);
	*contract = candidate;
	return (0);
}
