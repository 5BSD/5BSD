/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#ifndef _PVPANIC_H_
#define	_PVPANIC_H_

struct vmctx;
struct vm_snapshot_meta;

/* Name used on the bhyve command line (-l pvpanic[,action=...]). */
const char	*pvpanic_getname(void);

/*
 * Parse the LPC option string for the pvpanic device.  "opts" is the text
 * after the device name, e.g. "action=reset" (may be NULL/empty).  Stores the
 * parsed configuration in the global config tree.  Returns 0 on success.
 */
int		 pvpanic_parse(const char *opts);

/* Instantiate the device: register the I/O port and arm the host action. */
int		 pvpanic_init(struct vmctx *ctx);

#ifdef BHYVE_SNAPSHOT
int		 pvpanic_snapshot(struct vm_snapshot_meta *meta);
#endif

#endif /* _PVPANIC_H_ */
