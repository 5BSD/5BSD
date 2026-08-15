/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>

#include "checkpoint_cpu.h"

/*
 * The common checkpoint envelope is architecture-neutral, but an ARM64 CPU
 * contract has not been defined yet.  Do not let the generic save path infer
 * an x86 contract or publish a checkpoint without one.
 */
int
checkpoint_cpu_contract_capture(struct vcpu *vcpu,
    struct checkpoint_cpu_contract *contract)
{

	(void)vcpu;
	(void)contract;
	return (EOPNOTSUPP);
}
