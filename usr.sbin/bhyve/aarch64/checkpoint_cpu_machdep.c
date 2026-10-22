/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <arm64/include/vmm_dev.h>
#include <vmmapi.h>

#include "checkpoint_cpu.h"

/* The VMM supplies its masked guest ID registers and counter frequency. */
int
checkpoint_cpu_contract_capture(struct vcpu *vcpu,
    struct checkpoint_cpu_contract *contract)
{
	struct checkpoint_cpu_contract candidate;
	struct vm_arm64_cpu_features features;
	uint64_t values[6];
	struct checkpoint_cpu_record *record;

	if (vcpu == NULL || contract == NULL)
		return (EINVAL);
	memset(&features, 0, sizeof(features));
	errno = 0;
	if (vm_get_arm64_cpu_features(vcpu, &features) != 0)
		return (errno != 0 ? errno : EIO);
	if (features.version != VM_ARM64_CPU_FEATURES_VERSION ||
	    features.reserved != 0 || features.cntfrq == 0)
		return (EPROTO);
	values[0] = features.id_aa64pfr0;
	values[1] = features.id_aa64dfr0;
	values[2] = features.id_aa64isar0;
	values[3] = features.id_aa64mmfr0;
	values[4] = features.id_aa64mmfr1;
	values[5] = features.cntfrq;
	memset(&candidate, 0, sizeof(candidate));
	candidate.version = CHECKPOINT_CPU_CONTRACT_VERSION;
	candidate.architecture = CHECKPOINT_CPU_ARCH_ARM64;
	for (size_t i = 0; i < 6; i++) {
		record = &candidate.records[candidate.record_count++];
		record->selector = (uint32_t)i + 1;
		record->values[0] = (uint32_t)values[i];
		record->values[1] = (uint32_t)(values[i] >> 32);
	}
	*contract = candidate;
	return (0);
}
