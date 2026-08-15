/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BHYVE_CHECKPOINT_NUMA_H_
#define	_BHYVE_CHECKPOINT_NUMA_H_

#include <sys/types.h>

#include <stdint.h>

#include "checkpoint_topology.h"

int	checkpoint_numa_encode(const uint64_t *, size_t, const uint16_t *,
	    size_t, char **, char **);
int	checkpoint_numa_decode(const char *, const char *, size_t, uint64_t,
	    uint64_t [CHECKPOINT_NUMA_MAX_DOMAINS], size_t *, uint16_t *);

#endif
