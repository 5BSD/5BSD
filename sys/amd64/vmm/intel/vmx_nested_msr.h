/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_MSR_H_
#define	_VMM_INTEL_VMX_NESTED_MSR_H_

#include "vmx_nested_types.h"

struct vmx_nested_capabilities;
struct vmx_nested_memory;

struct vmx_nested_msr_policy {
	/*
	 * This callback validates only.  It must not change architectural
	 * state; loads are applied only after every entry has validated.
	 */
	int	(*validate_write)(void *, uint32_t, uint64_t, bool);
	/*
	 * Validate that RDMSR of index is permitted for a VM-exit MSR-store
	 * entry.  This callback also validates only and must not read the MSR.
	 */
	int	(*validate_read)(void *, uint32_t, bool);
	void	*arg;
};

struct vmx_nested_msr_entry {
	uint32_t	index;
	uint64_t	value;
};

enum vmx_nested_msr_failure {
	VMX_NESTED_MSR_OK = 0,
	VMX_NESTED_MSR_PREREQUISITE,
	VMX_NESTED_MSR_COUNT,
	VMX_NESTED_MSR_ADDRESS,
	VMX_NESTED_MSR_MEMORY,
	VMX_NESTED_MSR_RESERVED,
	VMX_NESTED_MSR_FORBIDDEN,
	VMX_NESTED_MSR_VALUE,
	VMX_NESTED_MSR_CAPACITY,
	VMX_NESTED_MSR_RUNTIME,
};

int	vmx_nested_entry_msr_list_validate(
	    const struct vmx_nested_capabilities *, uint64_t, uint32_t, bool,
	    const struct vmx_nested_memory *,
	    const struct vmx_nested_msr_policy *,
	    enum vmx_nested_msr_failure *, uint32_t *);
int	vmx_nested_entry_msr_list_snapshot(
	    const struct vmx_nested_capabilities *, uint64_t, uint32_t, bool,
	    const struct vmx_nested_memory *,
	    const struct vmx_nested_msr_policy *,
	    struct vmx_nested_msr_entry *, uint32_t, uint32_t *,
	    enum vmx_nested_msr_failure *, uint32_t *);
int	vmx_nested_exit_msr_load_snapshot(
	    const struct vmx_nested_capabilities *, uint64_t, uint32_t, bool,
	    const struct vmx_nested_memory *,
	    const struct vmx_nested_msr_policy *,
	    struct vmx_nested_msr_entry *, uint32_t, uint32_t *,
	    enum vmx_nested_msr_failure *, uint32_t *);

struct vmx_nested_msr_apply_ops {
	int	(*read)(void *, uint32_t, uint64_t *);
	/*
	 * A failed write must leave the indexed MSR unchanged.  This permits
	 * the common layer to roll back only writes that completed.
	 */
	int	(*write)(void *, uint32_t, uint64_t);
};

enum vmx_nested_msr_apply_outcome {
	VMX_NESTED_MSR_APPLY_OK = 0,
	VMX_NESTED_MSR_APPLY_READ_FAILED,
	VMX_NESTED_MSR_APPLY_WRITE_FAILED_ROLLED_BACK,
	VMX_NESTED_MSR_APPLY_ROLLBACK_FAILED,
};

int	vmx_nested_msr_list_apply(
	    const struct vmx_nested_msr_entry *, uint32_t,
	    const struct vmx_nested_msr_apply_ops *, void *,
	    struct vmx_nested_msr_entry *, uint32_t,
	    enum vmx_nested_msr_apply_outcome *, uint32_t *);
/*
 * Undo a previously successful list application in reverse architectural
 * order.  Every write is attempted even after one fails.  This is used when
 * a later VM-entry stage cannot publish L2 execution.
 */
int	vmx_nested_msr_list_rollback(
	    const struct vmx_nested_msr_entry *, uint32_t,
	    const struct vmx_nested_msr_apply_ops *, void *, uint32_t *);

enum vmx_nested_exit_msr_load_outcome {
	VMX_NESTED_EXIT_MSR_LOAD_OK = 0,
	VMX_NESTED_EXIT_MSR_LOAD_ABORT_4_ROLLED_BACK,
	VMX_NESTED_EXIT_MSR_LOAD_HOST_FAILED,
};

int	vmx_nested_exit_msr_load_apply(
	    const struct vmx_nested_msr_entry *, uint32_t,
	    const struct vmx_nested_msr_apply_ops *, void *,
	    struct vmx_nested_msr_entry *, uint32_t,
	    enum vmx_nested_exit_msr_load_outcome *, uint32_t *);

struct vmx_nested_exit_msr_store_ops {
	int	(*read)(void *, uint32_t, uint64_t *);
};

/*
 * Freeze the VM-exit MSR-store descriptor list without reading any runtime
 * MSR values.  The resulting index-only plan can cross the sleepable-to-hot
 * execution boundary; values are captured later while L2 state is still
 * authoritative.
 */
int	vmx_nested_exit_msr_store_plan_snapshot(
	    const struct vmx_nested_capabilities *, uint64_t, uint32_t, bool,
	    const struct vmx_nested_memory *,
	    const struct vmx_nested_msr_policy *,
	    struct vmx_nested_msr_entry *, uint32_t, uint32_t *,
	    enum vmx_nested_msr_failure *, uint32_t *);
int	vmx_nested_exit_msr_store_values_capture(
	    struct vmx_nested_msr_entry *, uint32_t,
	    const struct vmx_nested_exit_msr_store_ops *, void *,
	    uint32_t *);

/*
 * The target array forms an immutable VM-exit MSR-store plan containing
 * values read from the effective L2 runtime before guest-memory mutation.
 */
int	vmx_nested_exit_msr_store_snapshot(
	    const struct vmx_nested_capabilities *, uint64_t, uint32_t, bool,
	    const struct vmx_nested_memory *,
	    const struct vmx_nested_msr_policy *,
	    const struct vmx_nested_exit_msr_store_ops *, void *,
	    struct vmx_nested_msr_entry *, uint32_t, uint32_t *,
	    enum vmx_nested_msr_failure *, uint32_t *);

enum vmx_nested_exit_msr_store_outcome {
	VMX_NESTED_EXIT_MSR_STORE_OK = 0,
	/*
	 * Intel VMX-abort indicator 1.  Stores completed before the failing
	 * entry remain visible, matching architectural processing order.
	 */
	VMX_NESTED_EXIT_MSR_STORE_ABORT_1_PARTIAL,
	/*
	 * An L0 invariant or effective-L2 value capture failed.  This is not
	 * an architecturally attributable VMX abort and must fail stop.
	 */
	VMX_NESTED_EXIT_MSR_STORE_HOST_FAILED,
};

int	vmx_nested_exit_msr_store_commit(
	    uint64_t, const struct vmx_nested_msr_entry *,
	    uint32_t, const struct vmx_nested_memory *,
	    enum vmx_nested_exit_msr_store_outcome *, uint32_t *);
int	vmx_nested_exit_msr_store_execute(
	    const struct vmx_nested_capabilities *, uint64_t, uint32_t, bool,
	    const struct vmx_nested_memory *,
	    const struct vmx_nested_msr_policy *,
	    const struct vmx_nested_exit_msr_store_ops *, void *,
	    enum vmx_nested_exit_msr_store_outcome *,
	    enum vmx_nested_msr_failure *, uint32_t *);

/*
 * Retry-safe ownership for the architecturally ordered VM-exit MSR
 * transaction.  Guest-memory stores are irreversible and precede host MSR
 * loads, so a caller must never infer progress from a returned errno alone.
 * This value-only state records the one-way publication boundary and can be
 * checked before retrying a frozen handoff.
 */
enum vmx_nested_exit_msr_transaction_state {
	VMX_NESTED_EXIT_MSR_TRANSACTION_IDLE = 0,
	VMX_NESTED_EXIT_MSR_TRANSACTION_ACTIVE,
	VMX_NESTED_EXIT_MSR_TRANSACTION_STORE_COMMITTED,
	VMX_NESTED_EXIT_MSR_TRANSACTION_LOAD_APPLIED,
	VMX_NESTED_EXIT_MSR_TRANSACTION_ABORTED,
	VMX_NESTED_EXIT_MSR_TRANSACTION_COMMITTED,
	VMX_NESTED_EXIT_MSR_TRANSACTION_POISONED,
};

struct vmx_nested_exit_msr_transaction {
	uint64_t	generation;
	uint32_t	store_count;
	uint32_t	load_count;
	uint32_t	abort_indicator;
	enum vmx_nested_exit_msr_transaction_state state;
};

void	vmx_nested_exit_msr_transaction_init(
	    struct vmx_nested_exit_msr_transaction *);
int	vmx_nested_exit_msr_transaction_begin(
	    struct vmx_nested_exit_msr_transaction *, uint64_t, uint32_t,
	    uint32_t);
int	vmx_nested_exit_msr_transaction_store_result(
	    struct vmx_nested_exit_msr_transaction *,
	    enum vmx_nested_exit_msr_store_outcome);
int	vmx_nested_exit_msr_transaction_load_result(
	    struct vmx_nested_exit_msr_transaction *,
	    enum vmx_nested_exit_msr_load_outcome);
int	vmx_nested_exit_msr_transaction_abort(
	    struct vmx_nested_exit_msr_transaction *, uint32_t);
int	vmx_nested_exit_msr_transaction_commit(
	    struct vmx_nested_exit_msr_transaction *);
int	vmx_nested_exit_msr_transaction_reset(
	    struct vmx_nested_exit_msr_transaction *);
int	vmx_nested_exit_msr_transaction_validate(
	    const struct vmx_nested_exit_msr_transaction *);

#endif /* _VMM_INTEL_VMX_NESTED_MSR_H_ */
