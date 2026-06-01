/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cap_rt_pair — wire protocol constants.
 *
 * Shared between kernel and userspace.  The pair service has a single
 * operation: PAIR_OP_CREATE, sent via CAP_RT_SENDMSG on an unpaired
 * instance.  The reply (via CAP_RT_RECVMSG) carries the peer fd.
 */

#ifndef _DEV_CAP_RT_CAP_RT_PAIR_PROTO_H_
#define _DEV_CAP_RT_CAP_RT_PAIR_PROTO_H_

#define	PAIR_OP_CREATE	1	/* create paired peer (reply carries fd) */

#endif /* _DEV_CAP_RT_CAP_RT_PAIR_PROTO_H_ */
