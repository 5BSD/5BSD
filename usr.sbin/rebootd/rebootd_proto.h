/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Wire protocol for rebootd — reboot and shutdown manager.
 */

#ifndef _REBOOTD_PROTO_H_
#define	_REBOOTD_PROTO_H_

#include <sys/types.h>

#define	REBOOT_OP_REBOOT	1	/* Reboot system */
#define	REBOOT_OP_SHUTDOWN	2	/* Clean shutdown (halt) */
#define	REBOOT_OP_STATUS	3	/* Query pending shutdown state */

#define	REBOOT_STATUS_OK	0
#define	REBOOT_STATUS_ERR	1
#define	REBOOT_STATUS_PERM	3
#define	REBOOT_STATUS_PENDING	4	/* Shutdown already in progress */

struct reboot_req {
	uint32_t	op;
	uint32_t	flags;		/* RB_* howto flags (REBOOT only) */
} __packed;

struct reboot_reply {
	int32_t		status;
	uint32_t	_pad;
} __packed;

#endif /* !_REBOOTD_PROTO_H_ */
