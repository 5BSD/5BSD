/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMCS_REGISTRY_H_
#define	_VMM_INTEL_VMX_NESTED_VMCS_REGISTRY_H_

#include <sys/queue.h>
#include "vmx_nested_types.h"

#include "vmx_nested_caps.h"

struct vmx_nested_exit_information;
struct vmx_nested_field;
struct vmx_nested_vmcs12_snapshot;
struct vmx_nested_vmexit_state_input;
struct vmx_nested_vmentry_result;

#define	VMX_NESTED_VMCS_NO_OWNER	UINT32_MAX
#define	VMX_NESTED_VMCS_REGISTRY_LIMIT	1024U
#define	VMX_NESTED_VMCS_REGISTRY_BUCKETS	64U

_Static_assert(VMX_NESTED_VMCS_REGISTRY_BUCKETS != 0 &&
    (VMX_NESTED_VMCS_REGISTRY_BUCKETS &
    (VMX_NESTED_VMCS_REGISTRY_BUCKETS - 1)) == 0,
    "nested VMCS registry bucket count must be a power of two");
struct vmx_nested_vmcs_registry_entry {
	LIST_ENTRY(vmx_nested_vmcs_registry_entry) link;
	uint64_t gpa;
	uint32_t owner;
	uint8_t region[VMX_NESTED_VMCS_REGION_SIZE];
};

LIST_HEAD(vmx_nested_vmcs_registry_head,
    vmx_nested_vmcs_registry_entry);

/*
 * Runtime-only per-VM VMCS backing.  Callers serialize every operation.
 * Pointers and implementation-defined regions are never checkpoint fields.
 */
struct vmx_nested_vmcs_registry {
	struct vmx_nested_vmcs_registry_head
	    entries[VMX_NESTED_VMCS_REGISTRY_BUCKETS];
	struct vmx_nested_capabilities capabilities;
	uint32_t count;
	uint32_t limit;
	bool initialized;
};

int	vmx_nested_vmcs_registry_init(struct vmx_nested_vmcs_registry *,
	    const struct vmx_nested_capabilities *, uint32_t);
/*
 * Validate private registry bookkeeping before a cold checkpoint or restore
 * operation traverses every entry.  Callers hold the enclosing registry lock.
 */
int	vmx_nested_vmcs_registry_validate(
	    const struct vmx_nested_vmcs_registry *);
int	vmx_nested_vmcs_registry_destroy(struct vmx_nested_vmcs_registry *);
int	vmx_nested_vmcs_registry_replace(
	    struct vmx_nested_vmcs_registry *,
	    struct vmx_nested_vmcs_registry *);
/*
 * Report whether a range aliases any storage owned by an initialized
 * registry, including its separately allocated VMCS entries.  The caller
 * must hold the registry's enclosing serialization lock.  Invalid registry
 * bookkeeping is reported as overlap so transactional callers fail closed.
 */
bool	vmx_nested_vmcs_registry_storage_overlaps(
	    const struct vmx_nested_vmcs_registry *, const void *, size_t);
int	vmx_nested_vmcs_registry_select(struct vmx_nested_vmcs_registry *,
	    uint64_t, uint32_t, uint32_t);
int	vmx_nested_vmcs_registry_owner_active(
	    const struct vmx_nested_vmcs_registry *, uint32_t, bool *);
int	vmx_nested_vmcs_registry_release(struct vmx_nested_vmcs_registry *,
	    uint32_t);
int	vmx_nested_vmcs_registry_clear(struct vmx_nested_vmcs_registry *,
	    uint64_t, uint32_t);
int	vmx_nested_vmcs_registry_read(struct vmx_nested_vmcs_registry *,
	    uint64_t, uint32_t, uint32_t, uint64_t *);
int	vmx_nested_vmcs_registry_write(struct vmx_nested_vmcs_registry *,
	    uint64_t, uint32_t, uint32_t, uint64_t);
int	vmx_nested_vmcs_registry_set_instruction_error(
	    struct vmx_nested_vmcs_registry *, uint64_t, uint32_t, uint32_t);
int	vmx_nested_vmcs_registry_import(
	    struct vmx_nested_vmcs_registry *, uint64_t,
	    const struct vmx_nested_field *, uint32_t, bool, uint64_t,
	    uint32_t);
int	vmx_nested_vmcs_registry_import_nowait(
	    struct vmx_nested_vmcs_registry *, uint64_t,
	    const struct vmx_nested_field *, uint32_t, bool, uint64_t,
	    uint32_t);
int	vmx_nested_vmcs_registry_commit_ept_exit(
	    struct vmx_nested_vmcs_registry *, uint64_t, uint32_t,
	    const struct vmx_nested_exit_information *, uint64_t);
int	vmx_nested_vmcs_registry_commit_vmexit(
	    struct vmx_nested_vmcs_registry *, uint64_t, uint32_t,
	    const struct vmx_nested_vmexit_state_input *,
	    const struct vmx_nested_exit_information *, uint64_t, void *,
	    size_t);
int	vmx_nested_vmcs_registry_prepare_vmexit(
	    struct vmx_nested_vmcs_registry *, uint64_t, uint32_t,
	    const struct vmx_nested_vmexit_state_input *,
	    const struct vmx_nested_exit_information *, uint64_t, void *,
	    size_t);
int	vmx_nested_vmcs_registry_publish_vmexit(
	    struct vmx_nested_vmcs_registry *, uint64_t, uint32_t,
	    const void *, size_t, uint64_t);
int	vmx_nested_vmcs_registry_commit_vmentry_failure(
	    struct vmx_nested_vmcs_registry *, uint64_t, uint32_t,
	    const struct vmx_nested_vmentry_result *);
int	vmx_nested_vmcs_registry_launched(
	    struct vmx_nested_vmcs_registry *, uint64_t, uint32_t,
	    bool *, uint64_t *);
int	vmx_nested_vmcs_registry_set_launched(
	    struct vmx_nested_vmcs_registry *, uint64_t, uint32_t, uint64_t);
int	vmx_nested_vmcs_registry_abort_indicator(
	    struct vmx_nested_vmcs_registry *, uint64_t, uint32_t,
	    uint32_t *);
int	vmx_nested_vmcs_registry_set_abort_indicator(
	    struct vmx_nested_vmcs_registry *, uint64_t, uint32_t,
	    uint32_t);
int	vmx_nested_vmcs_registry_snapshot(
	    struct vmx_nested_vmcs_registry *, uint64_t, uint32_t, bool,
	    struct vmx_nested_vmcs12_snapshot *);

#endif /* _VMM_INTEL_VMX_NESTED_VMCS_REGISTRY_H_ */
