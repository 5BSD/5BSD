/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define VM_CAP_SSTC 1
/* SBI_IDS */

#include "checkpoint_cpu.h"
#include "guest_cpu_abi.h"

struct vcpu { int unused; };
static int capability, capability_error, timebase_error;
static uint32_t timebase = 1000000;

int
vm_get_capability(struct vcpu *vcpu, int type, int *value)
{
	assert(vcpu != NULL && type == VM_CAP_SSTC);
	if (capability_error != 0) {
		errno = capability_error;
		return (-1);
	}
	*value = capability;
	return (0);
}

int
vm_get_riscv_timebase(struct vcpu *vcpu, uint32_t *value)
{
	assert(vcpu != NULL);
	if (timebase_error != 0) {
		errno = timebase_error;
		return (-1);
	}
	*value = timebase;
	return (0);
}

/* PRODUCTION_SBI_MASK */
/* PRODUCTION_CAPTURE */
/* PRODUCTION_MATCH */

int
main(void)
{
	struct vcpu vcpu = {};
	struct checkpoint_cpu_contract contract, saved, destination;
	const char *isa;

	for (capability = 0; capability <= 1; capability++) {
		memset(&contract, 0xa5, sizeof(contract));
		assert(checkpoint_cpu_contract_capture(&vcpu, &contract) == 0);
		assert(contract.version == CHECKPOINT_CPU_CONTRACT_VERSION);
		assert(contract.architecture == CHECKPOINT_CPU_ARCH_RISCV64);
		assert(contract.record_count == 5);
		for (size_t i = 0; i < contract.record_count; i++)
			assert(contract.records[i].selector == i + 1);
		isa = capability ? RISCV_GUEST_ISA_SSTC : RISCV_GUEST_ISA_BASE;
		assert(memcmp(contract.records[0].values, isa,
		    strlen(isa) + 1) == 0);
		assert(memcmp(contract.records[1].values, RISCV_GUEST_MMU_TYPE,
		    sizeof(RISCV_GUEST_MMU_TYPE)) == 0);
		assert(contract.records[2].values[0] == timebase);
		assert(contract.records[2].values[1] == (uint32_t)capability);
		assert(contract.records[3].values[0] ==
		    RISCV_GUEST_SBI_VERS_MAJOR);
		assert(contract.records[3].values[1] ==
		    RISCV_GUEST_SBI_VERS_MINOR);
		assert(contract.records[3].values[2] == SBI_IMPL_ID_BHYVE);
		assert(contract.records[3].values[3] ==
		    RISCV_GUEST_SBI_IMPL_VERSION);
		assert(contract.records[4].values[0] == 0x7f);
		assert(contract.records[4].values[1] == SBI_EXT_ID_HYPERTRACE);
		assert(contract.records[4].values[2] == SBI_HYPERTRACE_VERSION);
	}
	saved = contract;
	assert(checkpoint_cpu_contract_validate(&saved) == 0);
	assert(checkpoint_cpu_contract_match(&saved, &saved, NULL, 0) == 0);
	capability = 0;
	assert(checkpoint_cpu_contract_capture(&vcpu, &destination) == 0);
	assert(checkpoint_cpu_contract_match(&saved, &destination,
	    NULL, 0) == EXDEV);
	capability = 1;
	timebase = 2000000;
	assert(checkpoint_cpu_contract_capture(&vcpu, &destination) == 0);
	assert(checkpoint_cpu_contract_match(&saved, &destination,
	    NULL, 0) == EXDEV);
	timebase = 1000000;
	destination = saved;
	destination.records[4].values[0] ^= 1;
	assert(checkpoint_cpu_contract_match(&saved, &destination,
	    NULL, 0) == EXDEV);
	char reason[160];
	assert(checkpoint_cpu_contract_match(&saved, &destination,
	    reason, sizeof(reason)) == EXDEV);
	assert(strstr(reason, " value[0]: source 0x0000007f, "
	    "destination 0x0000007e") != NULL);
	capability = 2;
	assert(checkpoint_cpu_contract_capture(&vcpu, &contract) == EPROTO);
	assert(memcmp(&saved, &contract, sizeof(saved)) == 0);
	capability = 0;
	timebase = 0;
	assert(checkpoint_cpu_contract_capture(&vcpu, &contract) == EPROTO);
	assert(memcmp(&saved, &contract, sizeof(saved)) == 0);
	timebase = 1000000;
	capability_error = EACCES;
	assert(checkpoint_cpu_contract_capture(&vcpu, &contract) == EACCES);
	capability_error = 0;
	timebase_error = ENXIO;
	assert(checkpoint_cpu_contract_capture(&vcpu, &contract) == ENXIO);
	assert(memcmp(&saved, &contract, sizeof(saved)) == 0);
	assert(checkpoint_cpu_contract_capture(NULL, &contract) == EINVAL);
	assert(checkpoint_cpu_contract_capture(&vcpu, NULL) == EINVAL);
	return (0);
}
