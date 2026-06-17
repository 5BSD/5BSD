/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cap_rt_channel — wire protocol constants.
 *
 * Shared between kernel and userspace.  The channel service has a single
 * operation: CHANNEL_OP_CREATE, sent via CAP_RT_SENDMSG on an unconnected
 * instance.  The reply (via CAP_RT_RECVMSG) carries the peer fd.
 */

#ifndef _DEV_CAP_RT_CAP_RT_CHANNEL_PROTO_H_
#define _DEV_CAP_RT_CAP_RT_CHANNEL_PROTO_H_

#define	CHANNEL_OP_CREATE	1	/* create connected peer (reply carries fd) */

#endif /* _DEV_CAP_RT_CAP_RT_CHANNEL_PROTO_H_ */
