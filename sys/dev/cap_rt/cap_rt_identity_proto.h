/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cap_rt_identity — wire protocol for the identity service.
 *
 * The identity service lets a process query program nonces:
 *   IDENTITY_OP_SELF    — caller's own nonce
 *   IDENTITY_OP_QUERY   — nonce of a process via an attached procdesc fd
 */

#ifndef _DEV_CAP_RT_CAP_RT_IDENTITY_PROTO_H_
#define _DEV_CAP_RT_CAP_RT_IDENTITY_PROTO_H_

#define	IDENTITY_OP_SELF	1	/* Get caller's nonce */
#define	IDENTITY_OP_QUERY	2	/* Get nonce of attached procdesc */

struct identity_request {
	uint32_t	op;
	uint32_t	_reserved;
} __packed;

struct identity_reply {
	uint32_t	status;
	uint32_t	_pad;
	uint64_t	nonce;
} __packed;

#define	IDENTITY_STATUS_OK		0
#define	IDENTITY_STATUS_ERR		1
#define	IDENTITY_STATUS_DEAD		2	/* process has exited */

#endif /* _DEV_CAP_RT_CAP_RT_IDENTITY_PROTO_H_ */
