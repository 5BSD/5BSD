/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 */

#ifndef _VMM_SNAPSHOT_
#define	_VMM_SNAPSHOT_

#include <sys/errno.h>
#include <sys/types.h>
#ifndef _KERNEL
#include <stdbool.h>
#endif

/*
 * Kernel record selectors for VM_SNAPSHOT_REQ.  Values are private to this
 * architecture; userspace names records by string ("vm", ...), never by
 * these numbers.  Every record is a single canonical VMS2 envelope.
 */
enum snapshot_req {
	STRUCT_VM = 1,		/* "vm": VMS2 VM/vCPU, FP/SIMD and timers */
	STRUCT_VGIC = 2,	/* "vgic": VMS2 GICv3 distributor and CPUs */
};

#include <dev/vmm/vmm_snapshot_common.h>

#endif	/* _VMM_SNAPSHOT_ */
