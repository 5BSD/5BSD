/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cap_rt_vnode_claim — wire protocol for Vnode Claim service.
 *
 * Shared between kernel and userspace.  Include this header
 * to construct CAP_RT_CALL requests for the "vnode_claim" service.
 *
 * PURPOSE
 *
 * Allow a supervisor (e.g. init) to claim exclusive open access to
 * device vnodes.  Once a device is claimed, the kernel denies open()
 * from any process whose CAP_RT nonce does not match the claimer's.
 * The claimer may still dup/pass the resulting fd to other processes;
 * only the open path is gated.
 *
 * OPERATIONS
 *
 *   VC_OP_CLAIM
 *     Claim exclusive open rights to a device identified by dev_t.
 *     The caller's nonce becomes the owner.  Fails with EBUSY if
 *     already claimed by a different nonce.  Re-claiming the same
 *     device from the same nonce is a no-op success.
 *
 *     The caller passes an open fd to the target device in the
 *     CAP_RT_CALL message (cm_nfds=1).  The service extracts dev_t
 *     from the fd's vnode, so userspace never needs to deal with
 *     dev_t directly.
 *
 *   VC_OP_RELEASE
 *     Release a previously claimed device.  Only the owning nonce
 *     may release.  Passes the same fd (or any fd to the same
 *     device) to identify the target.
 *
 *   VC_OP_QUERY
 *     Check whether a device is currently claimed.  Returns the
 *     claim status in vc_reply.flags:
 *       VC_QF_CLAIMED  — device is claimed
 *       VC_QF_MINE     — claimed by the caller's nonce
 *
 * ENFORCEMENT
 *
 *   The service registers (or extends) an mpo_vnode_check_open MACF
 *   hook.  On every open() of a character or block device, the hook
 *   looks up the vnode's dev_t in the claims table:
 *     - No entry          → allow (default-open)
 *     - Entry, nonce match → allow
 *     - Entry, nonce mismatch → EACCES
 *
 * LIFECYCLE
 *
 *   Claims are held by the CAP_RT instance fd.  When the claimer's
 *   CAP_RT connection closes (instance revoke), all claims owned by
 *   that instance are automatically released.  This prevents stale
 *   claims from orphaned supervisors.
 *
 *   If the claimer exec()s, its nonce rotates and it loses the
 *   ability to release via a new connection — but the original
 *   instance fd (if kept open across exec) still holds the claim
 *   until closed.
 */

#ifndef _DEV_CAP_RT_CAP_RT_VNODE_CLAIM_PROTO_H_
#define _DEV_CAP_RT_CAP_RT_VNODE_CLAIM_PROTO_H_

#include <sys/types.h>

#define	VC_OP_CLAIM		1
#define	VC_OP_RELEASE		2
#define	VC_OP_QUERY		3

/* Query reply flags */
#define	VC_QF_CLAIMED		0x01	/* device is claimed by someone */
#define	VC_QF_MINE		0x02	/* claimed by caller's nonce */

struct vc_request {
	uint32_t	op;
	uint32_t	flags;		/* reserved, must be 0 */
} __packed;

struct vc_reply {
	uint32_t	flags;		/* VC_QF_* for QUERY; 0 otherwise */
	uint32_t	_pad;
} __packed;

#endif /* _DEV_CAP_RT_CAP_RT_VNODE_CLAIM_PROTO_H_ */
