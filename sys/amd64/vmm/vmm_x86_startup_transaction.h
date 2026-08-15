/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _AMD64_VMM_VMM_X86_STARTUP_TRANSACTION_H_
#define	_AMD64_VMM_VMM_X86_STARTUP_TRANSACTION_H_

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdbool.h>
#include <stdint.h>
#endif

#include <dev/vmm/vmm_startup_event.h>

/* Private transient values, not save state, userspace ABI, or a stable KPI. */
struct vmm_x86_startup_transaction_input {
	uint8_t kind;
	uint8_t vector;
	uint8_t bootstrap_processor;
	uint8_t reserved8;
	uint32_t reserved32;
};

struct vmm_x86_startup_transaction_result {
	uint8_t committed;
	/* True when rollback was unnecessary or completed successfully. */
	uint8_t rollback_complete;
	uint8_t poisoned;
	uint8_t reserved8;
	uint32_t reserved32;
};

/*
 * A caller composing this transaction inside a larger transaction must not
 * infer rollback safety from the errno alone.  In particular, a nonzero
 * return may accompany a poisoned or incompletely rolled-back result.
 */
enum vmm_x86_startup_transaction_outcome {
	VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID = 0,
	VMM_X86_STARTUP_TRANSACTION_OUTCOME_COMMITTED,
	VMM_X86_STARTUP_TRANSACTION_OUTCOME_ROLLED_BACK,
	VMM_X86_STARTUP_TRANSACTION_OUTCOME_POISONED,
};

struct vmm_x86_startup_transaction_ops {
	/*
	 * Every fallible callback returns zero or a positive errno.  Callback,
	 * input, result, and opaque workspace storage are caller-serialized and
	 * mutually disjoint for the complete execution.
	 */
	/* Capture and validate a complete rollback image without mutation. */
	int	(*capture)(void *,
	    const struct vmm_x86_startup_transaction_input *);
	/* Apply every fallible register and descriptor mutation. */
	int	(*apply)(void *);
	/* Restore the complete captured backend image; must be idempotent. */
	int	(*rollback)(void *);
	/* Commit event-specific pending state; SIPI implementations may no-op. */
	int	(*commit_event)(void *);
	/*
	 * Only infallible frozen-target operations are permitted here: LAPIC
	 * reset, translation invalidation, and final startup-wait publication.
	 */
	void	(*finalize)(void *);
};

bool	vmm_x86_startup_transaction_input_equal(
	    const struct vmm_x86_startup_transaction_input *,
	    const struct vmm_x86_startup_transaction_input *);
enum vmm_x86_startup_transaction_outcome
	vmm_x86_startup_transaction_result_classify(int,
	    const struct vmm_x86_startup_transaction_result *);
int	vmm_x86_startup_transaction_execute(
	    const struct vmm_x86_startup_transaction_input *,
	    const struct vmm_x86_startup_transaction_ops *, void *,
	    struct vmm_x86_startup_transaction_result *);

#endif /* _AMD64_VMM_VMM_X86_STARTUP_TRANSACTION_H_ */
