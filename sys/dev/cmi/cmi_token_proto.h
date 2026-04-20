/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cmi_token — wire protocol for the authorization token service.
 *
 * Shared between kernel and userspace.  Include this header
 * to construct CMI_CALL requests for the "token" service.
 */

#ifndef _DEV_CMI_CMI_TOKEN_PROTO_H_
#define _DEV_CMI_CMI_TOKEN_PROTO_H_

#include <sys/types.h>

#define	TOKEN_OP_CREATE		1	/* create token (returns reply fd) */
#define	TOKEN_OP_VALIDATE	2	/* check token is live */
#define	TOKEN_OP_REVOKE		3	/* revoke this token */

#define	TOKEN_LABEL_MAX		64

struct token_create_request {
	uint32_t	op;
	uint32_t	_reserved;
	char		label[TOKEN_LABEL_MAX];
} __packed;

struct token_request {
	uint32_t	op;
	uint32_t	_reserved;
} __packed;

struct token_validate_reply {
	uint32_t	valid;		/* 1 = live, 0 = revoked */
	uid_t		issuer_uid;	/* who created it */
	uint64_t	issuer_nonce;	/* issuer's program nonce */
	char		label[TOKEN_LABEL_MAX];
};

#endif /* _DEV_CMI_CMI_TOKEN_PROTO_H_ */
