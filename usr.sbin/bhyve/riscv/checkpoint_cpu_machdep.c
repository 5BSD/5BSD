/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <sys/types.h>

#include <machine/sbi.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <vmmapi.h>

#include "checkpoint_cpu.h"
#include "guest_cpu_abi.h"

static void
record_scalar(struct checkpoint_cpu_contract *contract, uint32_t selector,
    uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
	struct checkpoint_cpu_record *record;

	record = &contract->records[contract->record_count++];
	record->selector = selector;
	record->values[0] = a;
	record->values[1] = b;
	record->values[2] = c;
	record->values[3] = d;
}

int
checkpoint_cpu_contract_capture(struct vcpu *vcpu,
    struct checkpoint_cpu_contract *contract)
{
	struct checkpoint_cpu_contract candidate;
	struct checkpoint_cpu_record *record;
	const char *isa;
	uint32_t frequency;
	int sstc;

	if (vcpu == NULL || contract == NULL)
		return (EINVAL);
	errno = 0;
	if (vm_get_capability(vcpu, VM_CAP_SSTC, &sstc) != 0)
		return (errno != 0 ? errno : EIO);
	if (sstc != 0 && sstc != 1)
		return (EPROTO);
	errno = 0;
	if (vm_get_riscv_timebase(vcpu, &frequency) != 0)
		return (errno != 0 ? errno : EIO);
	if (frequency == 0)
		return (EPROTO);
	isa = sstc == 1 ? RISCV_GUEST_ISA_SSTC : RISCV_GUEST_ISA_BASE;
	memset(&candidate, 0, sizeof(candidate));
	candidate.version = CHECKPOINT_CPU_CONTRACT_VERSION;
	candidate.architecture = CHECKPOINT_CPU_ARCH_RISCV64;
	record = &candidate.records[candidate.record_count++];
	record->selector = 1; /* Exact guest FDT riscv,isa string. */
	if (strlen(isa) >= sizeof(record->values))
		return (E2BIG);
	memcpy(record->values, isa, strlen(isa) + 1);
	record = &candidate.records[candidate.record_count++];
	record->selector = 2; /* Exact guest FDT mmu-type string. */
	if (strlen(RISCV_GUEST_MMU_TYPE) >= sizeof(record->values))
		return (E2BIG);
	memcpy(record->values, RISCV_GUEST_MMU_TYPE,
	    sizeof(RISCV_GUEST_MMU_TYPE));
	record_scalar(&candidate, 3, frequency, (uint32_t)sstc, 0, 0);
	record_scalar(&candidate, 4, RISCV_GUEST_SBI_VERS_MAJOR,
	    RISCV_GUEST_SBI_VERS_MINOR, SBI_IMPL_ID_BHYVE,
	    RISCV_GUEST_SBI_IMPL_VERSION);
	record_scalar(&candidate, 5, vmexit_sbi_extension_mask(),
	    SBI_EXT_ID_HYPERTRACE, SBI_HYPERTRACE_VERSION, 1);
	*contract = candidate;
	return (0);
}
