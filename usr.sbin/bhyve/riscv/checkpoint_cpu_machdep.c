/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <errno.h>

#include "checkpoint_cpu.h"

/*
 * The checkpoint envelope and device state are portable, but no versioned
 * RISC-V CPU-state contract exists yet.  Refuse capture explicitly rather
 * than selecting an amd64 implementation or publishing a CPU-less image.
 */
int
checkpoint_cpu_contract_capture(struct vcpu *vcpu,
    struct checkpoint_cpu_contract *contract)
{

	(void)vcpu;
	(void)contract;
	return (EOPNOTSUPP);
}
