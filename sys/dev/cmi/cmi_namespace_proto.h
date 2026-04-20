/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cmi_namespace — wire protocol for the namespace service.
 *
 * Shared between kernel and userspace.  Include this header
 * to construct CMI_CALL requests for the "namespace" service.
 */

#ifndef _DEV_CMI_CMI_NAMESPACE_PROTO_H_
#define _DEV_CMI_CMI_NAMESPACE_PROTO_H_

#include <sys/types.h>

#define	NS_OP_INFO	1	/* query current namespace */
#define	NS_OP_CREATE	2	/* create child, return owner fd */
#define	NS_OP_ATTACH	3	/* get jid for jail_attach(2) */
#define	NS_OP_REMOVE	4	/* destroy namespace + children */
#define	NS_OP_MINT	5	/* create member fd */

struct ns_request {
	uint32_t	op;
	uint32_t	_reserved;
} __packed;

struct ns_create_request {
	uint32_t	op;		/* NS_OP_CREATE */
	uint32_t	_reserved;
	char		hostname[256];	/* child hostname */
} __packed;

struct ns_info_reply {
	uint32_t	status;
	int		jid;
	char		name[256];
};

#endif /* _DEV_CMI_CMI_NAMESPACE_PROTO_H_ */
