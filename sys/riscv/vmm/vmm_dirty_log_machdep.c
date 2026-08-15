/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#include <dev/vmm/vmm_dirty_log_collector.h>
#include <dev/vmm/vmm_dirty_log_machdep.h>

int
vmm_dirty_log_machdep_query(void *arg __unused, uint64_t gpa __unused,
    struct vmm_dirty_log_leaf *leaf __unused)
{

	return (ENOTSUP);
}

int
vmm_dirty_log_machdep_clear(void *arg __unused, uint64_t gpa __unused,
    struct vmm_dirty_log_leaf *leaf __unused)
{

	return (ENOTSUP);
}

const struct vmm_dirty_log_collector vmm_dirty_log_machdep_collector = {
	.query = vmm_dirty_log_machdep_query,
	.clear = vmm_dirty_log_machdep_clear,
};
