/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Wire protocol for kldmgrd — kernel module loading manager.
 */

#ifndef _KLDMGRD_PROTO_H_
#define	_KLDMGRD_PROTO_H_

#include <sys/types.h>

#define	KLDMGR_OP_LOAD		1	/* Load a kernel module */
#define	KLDMGR_OP_UNLOAD	2	/* Unload a kernel module */
#define	KLDMGR_OP_LIST		3	/* List loaded modules */

#define	KLDMGR_STATUS_OK	0
#define	KLDMGR_STATUS_ERR	1
#define	KLDMGR_STATUS_NOTFOUND	2
#define	KLDMGR_STATUS_PERM	3

#define	KLDMGR_NAME_MAX		128
#define	KLDMGR_LIST_MAX		64

struct kldmgr_req {
	uint32_t	op;
	uint32_t	_pad;
	char		name[KLDMGR_NAME_MAX];	/* module name (LOAD/UNLOAD) */
} __packed;

struct kldmgr_reply {
	int32_t		status;
	int32_t		id;			/* kld id on success (LOAD) */
} __packed;

struct kldmgr_list_entry {
	int32_t		id;
	char		name[KLDMGR_NAME_MAX];
} __packed;

struct kldmgr_list_reply {
	int32_t		status;
	uint32_t	count;
	struct kldmgr_list_entry entries[];
} __packed;

#endif /* !_KLDMGRD_PROTO_H_ */
