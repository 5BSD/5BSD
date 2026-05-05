/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * cap_rt_file_isolation — wire protocol for File Isolation service.
 *
 * Shared between kernel and userspace.  Include this header
 * to construct CAP_RT_CALL requests for the "file_isolation" service.
 *
 * PURPOSE
 *
 * Allow a supervisor (e.g. init) to fully isolate vnodes so that
 * only processes sharing the claimer's CAP_RT nonce can interact
 * with them.  Isolated vnodes are protected against:
 *
 *   - open / exec                (content access)
 *   - unlink / link / rename     (namespace mutation)
 *   - chmod / chown / chflags / utimes / truncate (metadata mutation)
 *   - stat / access / readlink   (information disclosure)
 *   - connect (AF_UNIX)          (socket access)
 *
 * The claimer may still dup/pass an already-open fd to other
 * processes; only new vnode operations are gated.
 *
 * Isolation works for any vnode type: device nodes (character and
 * block), regular files, FIFOs, and Unix domain sockets (connect
 * is gated; bind creates a new vnode so cannot be gated).  Claims
 * are keyed by vnode identity (held via vref), not by pathname or
 * dev_t.
 *
 * OPERATIONS
 *
 *   FI_OP_CLAIM
 *     Claim isolation over a vnode.  The caller passes an open fd
 *     to the target in the CAP_RT_CALL message (cm_nfds=1).  The
 *     service identifies the vnode from the fd internally.
 *     The caller's nonce becomes the owner.  Fails with EBUSY if
 *     already claimed by a different nonce.  Re-claiming the same
 *     vnode from the same nonce transfers ownership to the calling
 *     instance (the claim's lifetime tracks the most recent claimer).
 *
 *   FI_OP_RELEASE
 *     Release a previously isolated vnode.  Only the owning nonce
 *     may release.  Passes any fd referring to the same vnode to
 *     identify the target.
 *
 *   FI_OP_QUERY
 *     Check whether a vnode is currently isolated.  Returns the
 *     status in fi_reply.flags:
 *       FI_QF_CLAIMED  — vnode is isolated
 *       FI_QF_MINE     — isolated by the caller's nonce
 *
 * ENFORCEMENT
 *
 *   The service registers MACF hooks for all vnode check operations
 *   listed above.  Each hook looks up the vnode in the isolation
 *   table:
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

#ifndef _DEV_CAP_RT_CAP_RT_FILE_ISOLATION_PROTO_H_
#define _DEV_CAP_RT_CAP_RT_FILE_ISOLATION_PROTO_H_

#include <sys/types.h>

#define	FI_OP_CLAIM		1
#define	FI_OP_RELEASE		2
#define	FI_OP_QUERY		3

/* Query reply flags */
#define	FI_QF_CLAIMED		0x01	/* vnode is isolated by someone */
#define	FI_QF_MINE		0x02	/* isolated by caller's nonce */

struct fi_request {
	uint32_t	op;
	uint32_t	flags;		/* reserved, must be 0 */
} __packed;

struct fi_reply {
	uint32_t	flags;		/* FI_QF_* for QUERY; 0 otherwise */
	uint32_t	_pad;
} __packed;

#endif /* _DEV_CAP_RT_CAP_RT_FILE_ISOLATION_PROTO_H_ */
