/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * mac_capability_channel — wire protocol constants.
 *
 * Shared between kernel and userspace.  The channel service has a single
 * operation: CHANNEL_OP_CREATE, sent via MAC_CAPABILITY_SENDMSG on an unconnected
 * instance.  The reply (via MAC_CAPABILITY_RECVMSG) carries the peer fd.
 */

#ifndef _DEV_MAC_CAPABILITY_MAC_CAPABILITY_CHANNEL_PROTO_H_
#define _DEV_MAC_CAPABILITY_MAC_CAPABILITY_CHANNEL_PROTO_H_

#define	CHANNEL_OP_CREATE	1	/* create connected peer (reply carries fd) */

#endif /* _DEV_MAC_CAPABILITY_MAC_CAPABILITY_CHANNEL_PROTO_H_ */
