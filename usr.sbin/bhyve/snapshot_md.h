/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 */

/*
 * Machine-dependent checkpoint hooks for targets other than amd64.
 *
 * amd64 checkpoints its single non-PCI platform device ("atkbdc") through
 * dedicated code in snapshot.c.  ARM64 and RISC-V instead export a table of
 * named platform records (vCPU power state and MMIO devices) that snapshot.c
 * treats exactly like that amd64 record: saved after the PCI devices, checked
 * for presence/topology before a restore, validated side-effect free, and
 * paused/resumed with the other devices.
 */

#ifndef _BHYVE_SNAPSHOT_MD_H_
#define	_BHYVE_SNAPSHOT_MD_H_

#include <stddef.h>

struct vm_snapshot_meta;
struct vmctx;

struct snapshot_md_device {
	const char	*name;
	/* SAVE, RESTORE or side-effect-free VALIDATE of one record. */
	int		(*snapshot)(struct vm_snapshot_meta *);
	/* Optional; both must be idempotent (unwind may call resume twice). */
	int		(*pause)(void);
	int		(*resume)(void);
};

#ifndef __amd64__
const struct snapshot_md_device *bhyve_snapshot_md_devices(size_t *count);

/*
 * Resume every vCPU that is architecturally powered on (PSCI on ARM64, SBI
 * HSM on RISC-V).  A powered-off vCPU stays suspended: resuming it would
 * start it at a stale PC.
 */
int	bhyve_resume_powered_cpus(struct vmctx *ctx);
#endif

#endif /* _BHYVE_SNAPSHOT_MD_H_ */
