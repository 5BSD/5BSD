/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VMM_VMM_DIRTY_LOG_MACHDEP_H_
#define _DEV_VMM_VMM_DIRTY_LOG_MACHDEP_H_

#include <dev/vmm/vmm_dirty_log_collector.h>

struct vm;

int vmm_dirty_log_machdep_query(void *, uint64_t,
    struct vmm_dirty_log_leaf *);
int vmm_dirty_log_machdep_clear(void *, uint64_t,
    struct vmm_dirty_log_leaf *);

extern const struct vmm_dirty_log_collector vmm_dirty_log_machdep_collector;

#endif /* _DEV_VMM_VMM_DIRTY_LOG_MACHDEP_H_ */
