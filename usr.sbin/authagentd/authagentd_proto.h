/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * system.authagent wire protocol.
 *
 * A login program (login/su/sshd), after authenticating a principal, asks the
 * auth-agent to mint that session's capability bundle.  The auth-agent holds the
 * principal->bundle policy and the mint authority; the login program holds only
 * a channel to system.authagent.  See docs/auth-agent-design.md.
 */
#ifndef	AUTHAGENTD_PROTO_H
#define	AUTHAGENTD_PROTO_H

#include <sys/types.h>
#include <stdint.h>

#define	AUTHAGENTD_NAME			"system.authagent"
#define	AUTHAGENTD_PROTO_VERSION	1U

/* Request op codes (first field of every request). */
#define	AUTHAGENT_OP_MINT_SESSION	1U

/*
 * AUTHAGENT_OP_MINT_SESSION
 *   request: struct authagent_mint_req
 *   reply:   struct authagent_mint_reply; on success the minted session lookup
 *            channel is attached via SCM_RIGHTS (nfds == 1).
 *
 * No credential is sent.  Authentication already happened; holding a channel to
 * system.authagent IS the assertion "I am a trusted authenticator and have
 * authenticated the named principal."  The auth-agent applies the
 * principal->bundle policy to `uid` and mints the scoped channel (SYSTEM for an
 * admin principal, a per-uid USER channel otherwise), delivered so the caller
 * installs it as the session leader's inherited lookup channel and cannot
 * re-delegate it.
 */
struct authagent_mint_req {
	uint32_t	version;	/* AUTHAGENTD_PROTO_VERSION */
	uint32_t	op;		/* AUTHAGENT_OP_MINT_SESSION */
	uint32_t	uid;		/* the authenticated principal, by name */
	uint32_t	flags;		/* reserved, must be 0 */
};

struct authagent_mint_reply {
	int32_t		status;		/* 0 on success, else a positive errno */
	uint32_t	flags;		/* reserved */
};

#endif /* AUTHAGENTD_PROTO_H */
