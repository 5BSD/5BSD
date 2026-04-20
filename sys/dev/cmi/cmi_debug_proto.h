/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cmi_debug — wire protocol for the debug shield service.
 *
 * Shared between kernel and userspace.  Include this header
 * to construct CMI_CALL requests for the "debug" service.
 */

#ifndef _DEV_CMI_CMI_DEBUG_PROTO_H_
#define _DEV_CMI_CMI_DEBUG_PROTO_H_

#include <sys/types.h>

#define	DEBUG_OP_SHIELD		1	/* shield calling program (nonce-scoped) */
#define	DEBUG_OP_MINT		2	/* create debug token (returns reply fd) */
#define	DEBUG_OP_ACTIVATE	3	/* authorize caller to debug (on token fd) */

struct debug_request {
	uint32_t	op;
	uint32_t	_reserved;
} __packed;

#endif /* _DEV_CMI_CMI_DEBUG_PROTO_H_ */
