/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _AMD64_VMM_VMM_X86_STARTUP_FINALIZER_H_
#define	_AMD64_VMM_VMM_X86_STARTUP_FINALIZER_H_

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdbool.h>
#include <stdint.h>
#endif

#include "vmm_x86_startup_transaction.h"

/* Private transient values, not save state, userspace ABI, or a stable KPI. */
struct vmm_x86_startup_finalizer_plan {
	uint64_t nextrip;
	uint8_t kind;
	uint8_t vector;
	uint8_t bootstrap_processor;
	uint8_t reset_nested;
	uint8_t reset_lapic;
	uint8_t retire_translation_residency;
	uint8_t startup_wait;
	uint8_t reserved8;
};

struct vmm_x86_startup_finalizer_ops {
	void	(*reset_nested)(void *);
	void	(*reset_lapic)(void *);
	/* Retire only this vCPU's tagged residency; do not invalidate VM EPT. */
	void	(*retire_translation_residency)(void *);
	void	(*set_nextrip)(void *, uint64_t);
	/* Atomically publish the predicate and wake the target when necessary. */
	void	(*publish_startup_wait)(void *, bool);
};

struct vmm_x86_startup_finalizer {
	struct vmm_x86_startup_finalizer_ops ops;
	struct vmm_x86_startup_finalizer_plan plan;
	void *arg;
	uintptr_t storage_cookie;
};

int	vmm_x86_startup_finalizer_plan(
	    const struct vmm_x86_startup_transaction_input *,
	    struct vmm_x86_startup_finalizer_plan *);
int	vmm_x86_startup_finalizer_init(
	    const struct vmm_x86_startup_finalizer_ops *, void *,
	    const struct vmm_x86_startup_finalizer_plan *,
	    struct vmm_x86_startup_finalizer *);
int	vmm_x86_startup_finalizer_check(
	    const struct vmm_x86_startup_finalizer *,
	    const struct vmm_x86_startup_transaction_input *);
bool	vmm_x86_startup_finalizer_consumed(
	    const struct vmm_x86_startup_finalizer *);
void	vmm_x86_startup_finalizer_commit(
	    struct vmm_x86_startup_finalizer *);

#endif /* _AMD64_VMM_VMM_X86_STARTUP_FINALIZER_H_ */
