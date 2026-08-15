/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/systm.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

#include <machine/pmap.h>

#include <dev/vmm/vmm_dirty_log.h>
#include <dev/vmm/vmm_dirty_log_collector.h>
#include <dev/vmm/vmm_dirty_log_machdep.h>
#include <dev/vmm/vmm_mem.h>

static int
vmm_dirty_log_machdep_access(void *arg, uint64_t gpa, bool clear,
    struct vmm_dirty_log_leaf *leaf)
{
	struct pmap_guest_dirty_leaf hardware;
	struct vm *vm;
	int error;

	vm = arg;
	if (vm == NULL || leaf == NULL ||
	    (gpa & (VMM_DIRTY_LOG_GRANULARITY - 1)) != 0)
		return (EINVAL);
	error = pmap_guest_query_dirty(vmspace_pmap(vm_vmspace(vm)), gpa,
	    clear, &hardware);
	if (error == ENOENT) {
		/* An absent nested translation has never been written by a vCPU. */
		*leaf = (struct vmm_dirty_log_leaf) {
			.range = {
				.gpa = gpa,
				.length = VMM_DIRTY_LOG_GRANULARITY,
			},
			.dirty = false,
		};
		return (0);
	}
	if (error != 0)
		return (error);
	*leaf = (struct vmm_dirty_log_leaf) {
		.range = {
			.gpa = hardware.pgl_base,
			.length = hardware.pgl_size,
		},
		.dirty = hardware.pgl_dirty,
	};
	return (vmm_dirty_log_range_validate(&leaf->range, NULL) == 0 ? 0 :
	    EPROTO);
}

int
vmm_dirty_log_machdep_query(void *arg, uint64_t gpa,
    struct vmm_dirty_log_leaf *leaf)
{

	return (vmm_dirty_log_machdep_access(arg, gpa, false, leaf));
}

int
vmm_dirty_log_machdep_clear(void *arg, uint64_t gpa,
    struct vmm_dirty_log_leaf *leaf)
{

	return (vmm_dirty_log_machdep_access(arg, gpa, true, leaf));
}

const struct vmm_dirty_log_collector vmm_dirty_log_machdep_collector = {
	.query = vmm_dirty_log_machdep_query,
	.clear = vmm_dirty_log_machdep_clear,
};
