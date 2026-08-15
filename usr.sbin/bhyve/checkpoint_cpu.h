/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BHYVE_CHECKPOINT_CPU_H_
#define	_BHYVE_CHECKPOINT_CPU_H_

#include <sys/types.h>

#include <stdint.h>

#define	CHECKPOINT_CPU_CONTRACT_VERSION	1U
#define	CHECKPOINT_CPU_ARCH_AMD64	1U
#define	CHECKPOINT_CPU_ARCH_ARM64	2U
#define	CHECKPOINT_CPU_ARCH_RISCV64	3U
#define	CHECKPOINT_CPU_MAX_RECORDS	256U

struct checkpoint_cpu_record {
	uint32_t selector;
	uint32_t parameter;
	uint32_t values[4];
};

struct checkpoint_cpu_contract {
	uint32_t version;
	uint32_t architecture;
	size_t record_count;
	struct checkpoint_cpu_record records[CHECKPOINT_CPU_MAX_RECORDS];
};

struct vcpu;

int	checkpoint_cpu_contract_validate(
	    const struct checkpoint_cpu_contract *);
int	checkpoint_cpu_contract_match(
	    const struct checkpoint_cpu_contract *,
	    const struct checkpoint_cpu_contract *);
int	checkpoint_cpu_contract_encode(
	    const struct checkpoint_cpu_contract *, char **);
int	checkpoint_cpu_contract_decode(const char *,
	    struct checkpoint_cpu_contract *);
int	checkpoint_cpu_contract_capture(struct vcpu *,
	    struct checkpoint_cpu_contract *);

#endif /* _BHYVE_CHECKPOINT_CPU_H_ */
