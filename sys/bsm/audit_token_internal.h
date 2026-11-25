/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * The private layout of audit_token_t (audit_token(3)), shared by the
 * kernel (<bsm/audit_token.h>) and libbsm's accessors, and by nothing
 * else: programs read a token only through the accessors, so the layout
 * may change with them.  Not installed.
 *
 *	word	content					zero means
 *	0	uniqueid (set at fork, never changes)	never zero for a process
 *	1	execgen (new at fork and every exec)	never zero for a process
 *	2	imageid (the credential's, new at exec)	no image: a credential
 *							the kernel made
 *	3	pid (low 32 bits), jail id (high 32)
 *	4	euid (low), ruid (high)
 *	5	egid (low), rgid (high)
 *	6	audit user id (low), audit session id (high)
 *	7	reserved, zero
 */

#ifndef _BSM_AUDIT_TOKEN_INTERNAL_H_
#define	_BSM_AUDIT_TOKEN_INTERNAL_H_

#define	AUDIT_TOKEN_W_UNIQUEID	0
#define	AUDIT_TOKEN_W_EXECGEN	1
#define	AUDIT_TOKEN_W_IMAGEID	2
#define	AUDIT_TOKEN_W_PID_JID	3
#define	AUDIT_TOKEN_W_UIDS	4
#define	AUDIT_TOKEN_W_GIDS	5
#define	AUDIT_TOKEN_W_AUDIT	6
#define	AUDIT_TOKEN_W_RESERVED	7

/* The low and high 32 bits of a word, and a word made of two halves. */
#define	AUDIT_TOKEN_LO(t, w)	((u_int32_t)(t)->__at_w[(w)])
#define	AUDIT_TOKEN_HI(t, w)	((u_int32_t)((t)->__at_w[(w)] >> 32))
#define	AUDIT_TOKEN_PAIR(lo, hi)					\
	((u_int64_t)(u_int32_t)(lo) | ((u_int64_t)(u_int32_t)(hi) << 32))

#endif /* !_BSM_AUDIT_TOKEN_INTERNAL_H_ */
