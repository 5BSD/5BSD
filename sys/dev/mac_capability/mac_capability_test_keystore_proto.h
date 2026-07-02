/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * mac_capability_test_keystore — wire protocol for the async key-value test fixture.
 *
 * This service exists for framework testing.  It exercises async
 * messaging, credential access, and badges.
 */

#ifndef _DEV_MAC_CAPABILITY_MAC_CAPABILITY_TEST_KEYSTORE_PROTO_H_
#define _DEV_MAC_CAPABILITY_MAC_CAPABILITY_TEST_KEYSTORE_PROTO_H_

#include <sys/types.h>

#define	KS_OP_STORE	1
#define	KS_OP_FETCH	2

#define	KS_STATUS_OK		0
#define	KS_STATUS_NOTFOUND	1
#define	KS_STATUS_ERR		2

struct ks_request {
	uint32_t	op;
	uint32_t	keyid;
} __packed;

struct ks_reply {
	uint32_t	status;
} __packed;

#endif /* _DEV_MAC_CAPABILITY_MAC_CAPABILITY_TEST_KEYSTORE_PROTO_H_ */
