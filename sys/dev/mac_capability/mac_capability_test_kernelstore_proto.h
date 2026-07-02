/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * mac_capability_test_kernelstore — wire protocol for the shared key-value store.
 *
 * Shared between kernel and userspace.  Include this header
 * to construct MAC_CAPABILITY_CALL requests for the "test_kernelstore" service.
 */

#ifndef _DEV_MAC_CAPABILITY_MAC_CAPABILITY_TEST_KERNELSTORE_PROTO_H_
#define _DEV_MAC_CAPABILITY_MAC_CAPABILITY_TEST_KERNELSTORE_PROTO_H_

#include <sys/types.h>

#define	KSTORE_OP_PUT		1	/* store value under key */
#define	KSTORE_OP_GET		2	/* retrieve value by key */
#define	KSTORE_OP_DELETE	3	/* remove a key */
#define	KSTORE_OP_MINT		4	/* create member fd (owner only) */

#define	KSTORE_STATUS_OK	0
#define	KSTORE_STATUS_NOTFOUND	1
#define	KSTORE_STATUS_FULL	2
#define	KSTORE_STATUS_TOOBIG	3

#define	KSTORE_KEY_MAX		64	/* max key name length */
#define	KSTORE_MAX_VALUE	4096	/* max value size */
#define	KSTORE_MAX_KEYS		256	/* max keys per store */

struct kstore_request {
	uint32_t	op;
	uint32_t	_reserved;
	char		key[KSTORE_KEY_MAX];
} __packed;

struct kstore_status_reply {
	uint32_t	status;
} __packed;

#endif /* _DEV_MAC_CAPABILITY_MAC_CAPABILITY_TEST_KERNELSTORE_PROTO_H_ */
