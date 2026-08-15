/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#endif

#include "vmx_nested_caps.h"
#include "vmx_nested_memory.h"
#include "vmx_nested_msr.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_validate.h"

#define	NVMX_MSR_FS_BASE	0xc0000100U
#define	NVMX_MSR_GS_BASE	0xc0000101U
#define	NVMX_MSR_UCODE_WRITE	0x00000079U
#define	NVMX_MSR_UCODE_REV	0x0000008bU
#define	NVMX_MSR_SMM_MONITOR_CTL 0x0000009bU
#define	NVMX_MSR_SMBASE		0x0000009eU

static bool
nvmx_msr_common_forbidden(uint32_t index)
{

	return (index == NVMX_MSR_UCODE_WRITE ||
	    index == NVMX_MSR_UCODE_REV ||
	    /*
	     * The current virtual APIC model does not expose an x2APIC-mode
	     * input at this boundary.  Reject the complete architectural
	     * x2APIC MSR page rather than conditionally accepting a list that
	     * a later runtime cannot safely reproduce.
	     */
	    (index >> 8) == 0x8);
}

static int
nvmx_msr_fail(enum vmx_nested_msr_failure value,
    enum vmx_nested_msr_failure *failure)
{

	if (failure != NULL)
		*failure = value;
	return (EINVAL);
}

static int
nvmx_entry_msr_list(
    const struct vmx_nested_capabilities *capabilities, uint64_t address,
    uint32_t count, bool in_smm, const struct vmx_nested_memory *memory,
    const struct vmx_nested_msr_policy *policy,
    struct vmx_nested_msr_entry *entries, uint32_t capacity,
    uint32_t *snapshot_count,
    enum vmx_nested_msr_failure *failure, uint32_t *failed_entry)
{
	struct vmx_nested_memory memory_snapshot;
	struct vmx_nested_msr_policy policy_snapshot;
	uint8_t bytes[16];
	uint32_t index, maximum, reserved;
	uint64_t value;

	if (failure != NULL)
		*failure = VMX_NESTED_MSR_OK;
	if (failed_entry != NULL)
		*failed_entry = 0;
	if (snapshot_count != NULL)
		*snapshot_count = 0;
	if (vmx_nested_capabilities_validate(capabilities) != 0 ||
	    (count != 0 && (memory == NULL || memory->read == NULL ||
	    policy == NULL || policy->validate_write == NULL)))
		return (nvmx_msr_fail(VMX_NESTED_MSR_PREREQUISITE, failure));
	maximum = 512U * (1U + ((capabilities->misc >> 25) & 7));
	if (count > maximum)
		return (nvmx_msr_fail(VMX_NESTED_MSR_COUNT, failure));
	/*
	 * Architectural count validation precedes the caller's bounded
	 * snapshot capacity.  Otherwise one malformed L1 list could be
	 * misclassified as an L0 resource shortage when both limits are
	 * exceeded.
	 */
	if (entries != NULL && capacity < count)
		return (nvmx_msr_fail(VMX_NESTED_MSR_CAPACITY, failure));
	if (count == 0)
		return (0);
	if (!vmx_nested_vmx_physical_range_valid(capabilities, address,
	    (uint64_t)count * sizeof(bytes), sizeof(bytes)))
		return (nvmx_msr_fail(VMX_NESTED_MSR_ADDRESS, failure));
	memory_snapshot = *memory;
	policy_snapshot = *policy;
	memory = &memory_snapshot;
	policy = &policy_snapshot;
	for (uint32_t i = 0; i < count; i++) {
		if (memory->read(memory->arg,
		    address + (uint64_t)i * sizeof(bytes), bytes,
		    sizeof(bytes)) != 0) {
			if (failure != NULL)
				*failure = VMX_NESTED_MSR_MEMORY;
			if (failed_entry != NULL)
				*failed_entry = i + 1;
			return (EFAULT);
		}
		index = le32dec(bytes);
		reserved = le32dec(bytes + 4);
		value = le64dec(bytes + 8);
		if (reserved != 0) {
			if (failed_entry != NULL)
				*failed_entry = i + 1;
			return (nvmx_msr_fail(VMX_NESTED_MSR_RESERVED,
			    failure));
		}
		if (index == NVMX_MSR_FS_BASE || index == NVMX_MSR_GS_BASE ||
		    index == NVMX_MSR_SMM_MONITOR_CTL ||
		    nvmx_msr_common_forbidden(index)) {
			if (failed_entry != NULL)
				*failed_entry = i + 1;
			return (nvmx_msr_fail(VMX_NESTED_MSR_FORBIDDEN,
			    failure));
		}
		if (policy->validate_write(policy->arg, index, value,
		    in_smm) != 0) {
			if (failed_entry != NULL)
				*failed_entry = i + 1;
			return (nvmx_msr_fail(VMX_NESTED_MSR_VALUE,
			    failure));
		}
		if (entries != NULL) {
			entries[i].index = index;
			entries[i].value = value;
		}
	}
	if (snapshot_count != NULL)
		*snapshot_count = count;
	return (0);
}

int
vmx_nested_entry_msr_list_validate(
    const struct vmx_nested_capabilities *capabilities, uint64_t address,
    uint32_t count, bool in_smm, const struct vmx_nested_memory *memory,
    const struct vmx_nested_msr_policy *policy,
    enum vmx_nested_msr_failure *failure, uint32_t *failed_entry)
{

	return (nvmx_entry_msr_list(capabilities, address, count, in_smm,
	    memory, policy, NULL, 0, NULL, failure, failed_entry));
}

int
vmx_nested_entry_msr_list_snapshot(
    const struct vmx_nested_capabilities *capabilities, uint64_t address,
    uint32_t count, bool in_smm, const struct vmx_nested_memory *memory,
    const struct vmx_nested_msr_policy *policy,
    struct vmx_nested_msr_entry *entries, uint32_t capacity,
    uint32_t *snapshot_count, enum vmx_nested_msr_failure *failure,
    uint32_t *failed_entry)
{

	if (snapshot_count == NULL || (count != 0 && entries == NULL))
		return (nvmx_msr_fail(VMX_NESTED_MSR_PREREQUISITE, failure));
	return (nvmx_entry_msr_list(capabilities, address, count, in_smm,
	    memory, policy, entries, capacity, snapshot_count, failure,
	    failed_entry));
}

int
vmx_nested_exit_msr_load_snapshot(
    const struct vmx_nested_capabilities *capabilities, uint64_t address,
    uint32_t count, bool end_in_smm, const struct vmx_nested_memory *memory,
    const struct vmx_nested_msr_policy *policy,
    struct vmx_nested_msr_entry *entries, uint32_t capacity,
    uint32_t *snapshot_count, enum vmx_nested_msr_failure *failure,
    uint32_t *failed_entry)
{

	if (snapshot_count == NULL || (count != 0 && entries == NULL))
		return (nvmx_msr_fail(VMX_NESTED_MSR_PREREQUISITE, failure));
	return (nvmx_entry_msr_list(capabilities, address, count, end_in_smm,
	    memory, policy, entries, capacity, snapshot_count, failure,
	    failed_entry));
}

int
vmx_nested_msr_list_rollback(
    const struct vmx_nested_msr_entry *rollback, uint32_t count,
    const struct vmx_nested_msr_apply_ops *ops, void *arg,
    uint32_t *failed_entry)
{
	struct vmx_nested_msr_apply_ops ops_snapshot;
	int error;

	if (ops == NULL || ops->write == NULL || failed_entry == NULL ||
	    (count != 0 && rollback == NULL))
		return (EINVAL);
	ops_snapshot = *ops;
	ops = &ops_snapshot;
	*failed_entry = 0;
	error = 0;
	while (count != 0) {
		count--;
		if (ops->write(arg, rollback[count].index,
		    rollback[count].value) == 0)
			continue;
		if (*failed_entry == 0)
			*failed_entry = count + 1;
		error = EIO;
	}
	return (error);
}

int
vmx_nested_msr_list_apply(const struct vmx_nested_msr_entry *entries,
    uint32_t count, const struct vmx_nested_msr_apply_ops *ops, void *arg,
    struct vmx_nested_msr_entry *rollback, uint32_t rollback_capacity,
    enum vmx_nested_msr_apply_outcome *outcome, uint32_t *failed_entry)
{
	struct vmx_nested_msr_apply_ops ops_snapshot;
	size_t entries_bytes, rollback_bytes;
	uint32_t rollback_failed_entry;
	int error, rollback_error;

	if ((count != 0 && SIZE_MAX / count < sizeof(*entries)) ||
	    (rollback_capacity != 0 &&
	    SIZE_MAX / rollback_capacity < sizeof(*rollback)))
		return (EOVERFLOW);
	entries_bytes = (size_t)count * sizeof(*entries);
	rollback_bytes = (size_t)rollback_capacity * sizeof(*rollback);
	if (outcome == NULL || failed_entry == NULL || ops == NULL ||
	    ops->read == NULL || ops->write == NULL ||
	    (count != 0 && (entries == NULL || rollback == NULL)) ||
	    rollback_capacity < count)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(rollback, rollback_bytes,
	    entries, entries_bytes) ||
	    vmx_nested_state_ranges_overlap(rollback, rollback_bytes,
	    ops, sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(outcome, sizeof(*outcome),
	    entries, entries_bytes) ||
	    vmx_nested_state_ranges_overlap(outcome, sizeof(*outcome),
	    rollback, rollback_bytes) ||
	    vmx_nested_state_ranges_overlap(outcome, sizeof(*outcome),
	    ops, sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(failed_entry,
	    sizeof(*failed_entry), entries, entries_bytes) ||
	    vmx_nested_state_ranges_overlap(failed_entry,
	    sizeof(*failed_entry), rollback, rollback_bytes) ||
	    vmx_nested_state_ranges_overlap(failed_entry,
	    sizeof(*failed_entry), ops, sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(outcome, sizeof(*outcome),
	    failed_entry, sizeof(*failed_entry)))
		return (EINVAL);
	ops_snapshot = *ops;
	ops = &ops_snapshot;
	*outcome = VMX_NESTED_MSR_APPLY_OK;
	*failed_entry = 0;

	/*
	 * Capture every old value before the first mutation.  This makes
	 * duplicate indices safe: reverse rollback reconstructs each prior
	 * value in exact architectural order.
	 */
	for (uint32_t i = 0; i < count; i++) {
		rollback[i].index = entries[i].index;
		error = ops->read(arg, entries[i].index, &rollback[i].value);
		if (error != 0) {
			*outcome = VMX_NESTED_MSR_APPLY_READ_FAILED;
			*failed_entry = i + 1;
			return (error);
		}
	}
	for (uint32_t i = 0; i < count; i++) {
		error = ops->write(arg, entries[i].index, entries[i].value);
		if (error == 0)
			continue;
		*outcome = VMX_NESTED_MSR_APPLY_WRITE_FAILED_ROLLED_BACK;
		*failed_entry = i + 1;
		rollback_error = vmx_nested_msr_list_rollback(rollback, i,
		    ops, arg, &rollback_failed_entry);
		if (rollback_error != 0) {
			*outcome = VMX_NESTED_MSR_APPLY_ROLLBACK_FAILED;
			return (rollback_error);
		}
		return (error);
	}
	return (0);
}

int
vmx_nested_exit_msr_load_apply(
    const struct vmx_nested_msr_entry *entries, uint32_t count,
    const struct vmx_nested_msr_apply_ops *ops, void *arg,
    struct vmx_nested_msr_entry *rollback, uint32_t rollback_capacity,
    enum vmx_nested_exit_msr_load_outcome *outcome, uint32_t *failed_entry)
{
	size_t entries_bytes, rollback_bytes;
	enum vmx_nested_msr_apply_outcome apply_outcome;
	int error;

	if (outcome == NULL || failed_entry == NULL)
		return (EINVAL);
	if ((count != 0 && SIZE_MAX / count < sizeof(*entries)) ||
	    (rollback_capacity != 0 &&
	    SIZE_MAX / rollback_capacity < sizeof(*rollback)))
		return (EOVERFLOW);
	entries_bytes = (size_t)count * sizeof(*entries);
	rollback_bytes = (size_t)rollback_capacity * sizeof(*rollback);
	if (vmx_nested_state_ranges_overlap(outcome, sizeof(*outcome),
	    entries, entries_bytes) ||
	    vmx_nested_state_ranges_overlap(outcome, sizeof(*outcome),
	    rollback, rollback_bytes) ||
	    vmx_nested_state_ranges_overlap(outcome, sizeof(*outcome),
	    ops, ops == NULL ? 0 : sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(outcome, sizeof(*outcome),
	    failed_entry, sizeof(*failed_entry)))
		return (EINVAL);
	*outcome = VMX_NESTED_EXIT_MSR_LOAD_OK;
	*failed_entry = 0;
	apply_outcome = VMX_NESTED_MSR_APPLY_READ_FAILED;
	error = vmx_nested_msr_list_apply(entries, count, ops, arg, rollback,
	    rollback_capacity, &apply_outcome, failed_entry);
	switch (apply_outcome) {
	case VMX_NESTED_MSR_APPLY_OK:
		break;
	case VMX_NESTED_MSR_APPLY_WRITE_FAILED_ROLLED_BACK:
		*outcome =
		    VMX_NESTED_EXIT_MSR_LOAD_ABORT_4_ROLLED_BACK;
		break;
	case VMX_NESTED_MSR_APPLY_READ_FAILED:
	case VMX_NESTED_MSR_APPLY_ROLLBACK_FAILED:
		*outcome = VMX_NESTED_EXIT_MSR_LOAD_HOST_FAILED;
		break;
	}
	return (error);
}

int
vmx_nested_exit_msr_store_plan_snapshot(
    const struct vmx_nested_capabilities *capabilities, uint64_t address,
    uint32_t count, bool end_in_smm, const struct vmx_nested_memory *memory,
    const struct vmx_nested_msr_policy *policy,
    struct vmx_nested_msr_entry *target, uint32_t capacity,
    uint32_t *snapshot_count, enum vmx_nested_msr_failure *failure,
    uint32_t *failed_entry)
{
	struct vmx_nested_memory memory_snapshot;
	struct vmx_nested_msr_policy policy_snapshot;
	uint8_t bytes[16];
	uint32_t index, maximum, reserved;
	int error;

	if (failure != NULL)
		*failure = VMX_NESTED_MSR_OK;
	if (failed_entry != NULL)
		*failed_entry = 0;
	if (snapshot_count != NULL)
		*snapshot_count = 0;
	if (snapshot_count == NULL ||
	    vmx_nested_capabilities_validate(capabilities) != 0 ||
	    (count != 0 && (memory == NULL || memory->read == NULL ||
	    policy == NULL || policy->validate_read == NULL ||
	    target == NULL)))
		return (nvmx_msr_fail(VMX_NESTED_MSR_PREREQUISITE, failure));
	maximum = 512U * (1U + ((capabilities->misc >> 25) & 7));
	if (count > maximum)
		return (nvmx_msr_fail(VMX_NESTED_MSR_COUNT, failure));
	if (capacity < count)
		return (nvmx_msr_fail(VMX_NESTED_MSR_CAPACITY, failure));
	if (count == 0)
		return (0);
	if (!vmx_nested_vmx_physical_range_valid(capabilities, address,
	    (uint64_t)count * sizeof(bytes), sizeof(bytes)))
		return (nvmx_msr_fail(VMX_NESTED_MSR_ADDRESS, failure));
	memory_snapshot = *memory;
	policy_snapshot = *policy;
	memory = &memory_snapshot;
	policy = &policy_snapshot;

	/*
	 * Build the complete immutable value plan before the first
	 * guest-memory write.  Commit still follows Intel's architectural
	 * entry order and does not roll earlier stores back after an abort.
	 */
	for (uint32_t i = 0; i < count; i++) {
		error = memory->read(memory->arg,
		    address + (uint64_t)i * sizeof(bytes), bytes,
		    sizeof(bytes));
		if (error != 0) {
			if (failure != NULL)
				*failure = VMX_NESTED_MSR_MEMORY;
			if (failed_entry != NULL)
				*failed_entry = i + 1;
			return (EFAULT);
		}
		index = le32dec(bytes);
		reserved = le32dec(bytes + 4);
		if (reserved != 0) {
			if (failed_entry != NULL)
				*failed_entry = i + 1;
			return (nvmx_msr_fail(VMX_NESTED_MSR_RESERVED,
			    failure));
		}
		/* VM-exit stores permit FS_BASE and GS_BASE, unlike loads. */
		if (index == NVMX_MSR_SMBASE ||
		    nvmx_msr_common_forbidden(index)) {
			if (failed_entry != NULL)
				*failed_entry = i + 1;
			return (nvmx_msr_fail(VMX_NESTED_MSR_FORBIDDEN,
			    failure));
		}
		if (policy->validate_read(policy->arg, index, end_in_smm) != 0) {
			if (failed_entry != NULL)
				*failed_entry = i + 1;
			return (nvmx_msr_fail(VMX_NESTED_MSR_VALUE,
			    failure));
		}
		target[i].index = index;
		target[i].value = 0;
	}
	*snapshot_count = count;
	return (0);
}

int
vmx_nested_exit_msr_store_values_capture(
    struct vmx_nested_msr_entry *target, uint32_t count,
    const struct vmx_nested_exit_msr_store_ops *ops, void *ops_arg,
    uint32_t *failed_entry)
{
	struct vmx_nested_exit_msr_store_ops ops_snapshot;
	uint64_t value;
	int error;

	if (failed_entry == NULL)
		return (EINVAL);
	*failed_entry = 0;
	if (count == 0)
		return (0);
	if (target == NULL || ops == NULL || ops->read == NULL)
		return (EINVAL);
	ops_snapshot = *ops;
	ops = &ops_snapshot;
	for (uint32_t i = 0; i < count; i++) {
		error = ops->read(ops_arg, target[i].index, &value);
		if (error != 0) {
			*failed_entry = i + 1;
			return (error);
		}
		target[i].value = value;
	}
	return (0);
}

int
vmx_nested_exit_msr_store_snapshot(
    const struct vmx_nested_capabilities *capabilities, uint64_t address,
    uint32_t count, bool end_in_smm, const struct vmx_nested_memory *memory,
    const struct vmx_nested_msr_policy *policy,
    const struct vmx_nested_exit_msr_store_ops *ops, void *ops_arg,
    struct vmx_nested_msr_entry *target, uint32_t capacity,
    uint32_t *snapshot_count, enum vmx_nested_msr_failure *failure,
    uint32_t *failed_entry)
{
	struct vmx_nested_memory memory_snapshot;
	struct vmx_nested_msr_policy policy_snapshot;
	struct vmx_nested_exit_msr_store_ops ops_snapshot;
	uint32_t plan_count;
	int error;

	if (failure != NULL)
		*failure = VMX_NESTED_MSR_OK;
	if (snapshot_count != NULL)
		*snapshot_count = 0;
	if (snapshot_count == NULL ||
	    (count != 0 && (memory == NULL || memory->read == NULL ||
	    policy == NULL || policy->validate_read == NULL || ops == NULL ||
	    ops->read == NULL || target == NULL))) {
		return (nvmx_msr_fail(VMX_NESTED_MSR_PREREQUISITE,
		    failure));
	}
	if (count != 0) {
		memory_snapshot = *memory;
		policy_snapshot = *policy;
		ops_snapshot = *ops;
		memory = &memory_snapshot;
		policy = &policy_snapshot;
		ops = &ops_snapshot;
	}
	error = vmx_nested_exit_msr_store_plan_snapshot(capabilities,
	    address, count, end_in_smm, memory, policy, target, capacity,
	    &plan_count, failure, failed_entry);
	if (error != 0)
		return (error);
	error = vmx_nested_exit_msr_store_values_capture(target, plan_count,
	    ops, ops_arg, failed_entry);
	if (error != 0) {
		if (failure != NULL)
			*failure = VMX_NESTED_MSR_RUNTIME;
		return (error);
	}
	*snapshot_count = plan_count;
	return (0);
}

int
vmx_nested_exit_msr_store_commit(uint64_t address,
    const struct vmx_nested_msr_entry *target, uint32_t count,
    const struct vmx_nested_memory *memory,
    enum vmx_nested_exit_msr_store_outcome *outcome, uint32_t *failed_entry)
{
	struct vmx_nested_memory memory_snapshot;
	uint8_t bytes[8], record[16];
	uint32_t index, reserved;
	uint64_t offset;
	int error;

	if (outcome == NULL || failed_entry == NULL ||
	    (count != 0 && (target == NULL || memory == NULL ||
	    memory->read == NULL || memory->write == NULL)) ||
	    (address & 15) != 0 ||
	    (count != 0 && address > ~(uint64_t)0 -
	    ((uint64_t)count - 1) * 16 - 8))
		return (EINVAL);
	if (count != 0) {
		memory_snapshot = *memory;
		memory = &memory_snapshot;
	}
	*outcome = VMX_NESTED_EXIT_MSR_STORE_OK;
	*failed_entry = 0;
	for (uint32_t i = 0; i < count; i++) {
		offset = address + (uint64_t)i * 16;
		error = memory->read(memory->arg, offset, record,
		    sizeof(record));
		if (error != 0)
			goto abort;
		index = le32dec(record);
		reserved = le32dec(record + 4);
		if (index != target[i].index || reserved != 0) {
			error = EAGAIN;
			goto abort;
		}
		offset += 8;
		le64enc(bytes, target[i].value);
		error = memory->write(memory->arg, offset, bytes,
		    sizeof(bytes));
		if (error == 0)
			continue;
abort:
		*outcome =
		    VMX_NESTED_EXIT_MSR_STORE_ABORT_1_PARTIAL;
		*failed_entry = i + 1;
		return (error);
	}
	return (0);
}

int
vmx_nested_exit_msr_store_execute(
    const struct vmx_nested_capabilities *capabilities, uint64_t address,
    uint32_t count, bool end_in_smm, const struct vmx_nested_memory *memory,
    const struct vmx_nested_msr_policy *policy,
    const struct vmx_nested_exit_msr_store_ops *ops, void *ops_arg,
    enum vmx_nested_exit_msr_store_outcome *outcome,
    enum vmx_nested_msr_failure *failure, uint32_t *failed_entry)
{
	struct vmx_nested_memory memory_snapshot;
	struct vmx_nested_msr_policy policy_snapshot;
	struct vmx_nested_exit_msr_store_ops ops_snapshot;
	struct vmx_nested_msr_entry entry;
	enum vmx_nested_exit_msr_store_outcome commit_outcome;
	uint32_t maximum, one_count, one_failed;
	uint64_t entry_address;
	int error;

	if (outcome == NULL || failure == NULL || failed_entry == NULL)
		return (EINVAL);
	*outcome = VMX_NESTED_EXIT_MSR_STORE_OK;
	*failure = VMX_NESTED_MSR_OK;
	*failed_entry = 0;
	if (vmx_nested_capabilities_validate(capabilities) != 0 ||
	    (count != 0 && (memory == NULL || memory->read == NULL ||
	    memory->write == NULL || policy == NULL ||
	    policy->validate_read == NULL || ops == NULL ||
	    ops->read == NULL))) {
		*failure = VMX_NESTED_MSR_PREREQUISITE;
		return (EINVAL);
	}
	maximum = 512U * (1U + ((capabilities->misc >> 25) & 7));
	if (count == 0)
		return (0);
	memory_snapshot = *memory;
	policy_snapshot = *policy;
	ops_snapshot = *ops;
	memory = &memory_snapshot;
	policy = &policy_snapshot;
	ops = &ops_snapshot;

	/*
	 * Intel processes the store area in entry order.  Do not validate a
	 * later record before publishing an earlier record: a later failure
	 * must leave the already completed stores visible before abort 1.
	 * Effective L2 values come from the immutable value adapter, while
	 * each record header is rechecked immediately before its value write.
	 */
	for (uint32_t i = 0; i < count; i++) {
		if (i >= maximum) {
			*failure = VMX_NESTED_MSR_COUNT;
			*outcome =
			    VMX_NESTED_EXIT_MSR_STORE_ABORT_1_PARTIAL;
			*failed_entry = i + 1;
			return (EINVAL);
		}
		if (address > UINT64_MAX - (uint64_t)i * 16) {
			*failure = VMX_NESTED_MSR_ADDRESS;
			*outcome =
			    VMX_NESTED_EXIT_MSR_STORE_ABORT_1_PARTIAL;
			*failed_entry = i + 1;
			return (EINVAL);
		}
		entry_address = address + (uint64_t)i * 16;
		one_count = 0;
		one_failed = 0;
		error = vmx_nested_exit_msr_store_plan_snapshot(capabilities,
		    entry_address, 1, end_in_smm, memory, policy, &entry, 1,
		    &one_count, failure, &one_failed);
		if (error != 0) {
			*outcome =
			    VMX_NESTED_EXIT_MSR_STORE_ABORT_1_PARTIAL;
			*failed_entry = i + 1;
			return (error);
		}
		error = vmx_nested_exit_msr_store_values_capture(&entry, 1,
		    ops, ops_arg, &one_failed);
		if (error != 0) {
			*failure = VMX_NESTED_MSR_RUNTIME;
			*outcome = VMX_NESTED_EXIT_MSR_STORE_HOST_FAILED;
			*failed_entry = i + 1;
			return (error);
		}
		commit_outcome = VMX_NESTED_EXIT_MSR_STORE_OK;
		error = vmx_nested_exit_msr_store_commit(entry_address,
		    &entry, one_count, memory, &commit_outcome, &one_failed);
		if (error != 0) {
			*failure = VMX_NESTED_MSR_MEMORY;
			*outcome =
			    VMX_NESTED_EXIT_MSR_STORE_ABORT_1_PARTIAL;
			*failed_entry = i + 1;
			return (error);
		}
	}
	return (0);
}

void
vmx_nested_exit_msr_transaction_init(
    struct vmx_nested_exit_msr_transaction *transaction)
{

	if (transaction != NULL)
		memset(transaction, 0, sizeof(*transaction));
}

int
vmx_nested_exit_msr_transaction_validate(
    const struct vmx_nested_exit_msr_transaction *transaction)
{

	if (transaction == NULL ||
	    transaction->state < VMX_NESTED_EXIT_MSR_TRANSACTION_IDLE ||
	    transaction->state > VMX_NESTED_EXIT_MSR_TRANSACTION_POISONED)
		return (EINVAL);
	if (transaction->state == VMX_NESTED_EXIT_MSR_TRANSACTION_IDLE) {
		return (transaction->generation == 0 &&
		    transaction->store_count == 0 &&
		    transaction->load_count == 0 &&
		    transaction->abort_indicator == 0 ? 0 : EPROTO);
	}
	if (transaction->generation == 0)
		return (EPROTO);
	if (transaction->state == VMX_NESTED_EXIT_MSR_TRANSACTION_ABORTED)
		return (transaction->abort_indicator == 1 ||
		    transaction->abort_indicator == 2 ||
		    transaction->abort_indicator == 4 ? 0 : EPROTO);
	return (transaction->abort_indicator == 0 ? 0 : EPROTO);
}

int
vmx_nested_exit_msr_transaction_begin(
    struct vmx_nested_exit_msr_transaction *transaction,
    uint64_t generation, uint32_t store_count, uint32_t load_count)
{

	if (transaction == NULL || generation == 0 ||
	    vmx_nested_exit_msr_transaction_validate(transaction) != 0 ||
	    transaction->state != VMX_NESTED_EXIT_MSR_TRANSACTION_IDLE)
		return (EINVAL);
	transaction->generation = generation;
	transaction->store_count = store_count;
	transaction->load_count = load_count;
	transaction->state = VMX_NESTED_EXIT_MSR_TRANSACTION_ACTIVE;
	return (0);
}

int
vmx_nested_exit_msr_transaction_store_result(
    struct vmx_nested_exit_msr_transaction *transaction,
    enum vmx_nested_exit_msr_store_outcome outcome)
{

	if (transaction == NULL ||
	    vmx_nested_exit_msr_transaction_validate(transaction) != 0 ||
	    transaction->state != VMX_NESTED_EXIT_MSR_TRANSACTION_ACTIVE)
		return (EINVAL);
	switch (outcome) {
	case VMX_NESTED_EXIT_MSR_STORE_OK:
		transaction->state =
		    VMX_NESTED_EXIT_MSR_TRANSACTION_STORE_COMMITTED;
		break;
	case VMX_NESTED_EXIT_MSR_STORE_ABORT_1_PARTIAL:
		transaction->abort_indicator = 1;
		transaction->state =
		    VMX_NESTED_EXIT_MSR_TRANSACTION_ABORTED;
		break;
	case VMX_NESTED_EXIT_MSR_STORE_HOST_FAILED:
		transaction->state =
		    VMX_NESTED_EXIT_MSR_TRANSACTION_POISONED;
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

int
vmx_nested_exit_msr_transaction_load_result(
    struct vmx_nested_exit_msr_transaction *transaction,
    enum vmx_nested_exit_msr_load_outcome outcome)
{

	if (transaction == NULL ||
	    vmx_nested_exit_msr_transaction_validate(transaction) != 0 ||
	    transaction->state !=
	    VMX_NESTED_EXIT_MSR_TRANSACTION_STORE_COMMITTED)
		return (EINVAL);
	switch (outcome) {
	case VMX_NESTED_EXIT_MSR_LOAD_OK:
		transaction->state =
		    VMX_NESTED_EXIT_MSR_TRANSACTION_LOAD_APPLIED;
		break;
	case VMX_NESTED_EXIT_MSR_LOAD_ABORT_4_ROLLED_BACK:
		transaction->abort_indicator = 4;
		transaction->state =
		    VMX_NESTED_EXIT_MSR_TRANSACTION_ABORTED;
		break;
	case VMX_NESTED_EXIT_MSR_LOAD_HOST_FAILED:
		transaction->state =
		    VMX_NESTED_EXIT_MSR_TRANSACTION_POISONED;
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

int
vmx_nested_exit_msr_transaction_abort(
    struct vmx_nested_exit_msr_transaction *transaction, uint32_t indicator)
{

	if (transaction == NULL || indicator != 2 ||
	    vmx_nested_exit_msr_transaction_validate(transaction) != 0 ||
	    transaction->state !=
	    VMX_NESTED_EXIT_MSR_TRANSACTION_STORE_COMMITTED)
		return (EINVAL);
	transaction->abort_indicator = indicator;
	transaction->state = VMX_NESTED_EXIT_MSR_TRANSACTION_ABORTED;
	return (0);
}

int
vmx_nested_exit_msr_transaction_commit(
    struct vmx_nested_exit_msr_transaction *transaction)
{

	if (transaction == NULL ||
	    vmx_nested_exit_msr_transaction_validate(transaction) != 0 ||
	    transaction->state !=
	    VMX_NESTED_EXIT_MSR_TRANSACTION_LOAD_APPLIED)
		return (EINVAL);
	transaction->state = VMX_NESTED_EXIT_MSR_TRANSACTION_COMMITTED;
	return (0);
}

int
vmx_nested_exit_msr_transaction_reset(
    struct vmx_nested_exit_msr_transaction *transaction)
{

	if (transaction == NULL ||
	    vmx_nested_exit_msr_transaction_validate(transaction) != 0 ||
	    (transaction->state !=
	    VMX_NESTED_EXIT_MSR_TRANSACTION_COMMITTED &&
	    transaction->state !=
	    VMX_NESTED_EXIT_MSR_TRANSACTION_ABORTED))
		return (EINVAL);
	vmx_nested_exit_msr_transaction_init(transaction);
	return (0);
}
