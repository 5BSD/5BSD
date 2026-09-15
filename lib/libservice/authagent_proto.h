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
/* v2: AUTHAGENT_OP_ELEVATE (docs/ipc-anointments-design.md "Elevation"). */
#define	AUTHAGENTD_PROTO_VERSION	2U

/* Request op codes (second field of every request, after `version`). */
#define	AUTHAGENT_OP_MINT_SESSION	1U
#define	AUTHAGENT_OP_ELEVATE		2U

/*
 * Request flags.  FORWARDABLE: the caller (sshd's monitor) must forward the
 * minted descriptor over one more SCM_RIGHTS hop to the session child, so the
 * agent delivers it still-transferable rather than consuming it to
 * non-transferable at this caller.  A session leaf (login/su) passes 0.
 */
#define	AUTHAGENT_FLAG_FORWARDABLE	0x1U

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

/*
 * AUTHAGENT_OP_ELEVATE — the sudo/doas replacement.
 *   request: struct authagent_elevate_req
 *   reply:   struct authagent_mint_reply; on success the minted session lookup
 *            channel (the caller's current anointment set plus `name`) is
 *            attached via SCM_RIGHTS (nfds == 1); on failure nfds == 0.
 *
 * The request goes from the client straight to system.authagent over the
 * client's own ambient lookup channel (it does not pass through a switchboard
 * op).  The agent takes the caller's identity — uid, session/program nonce —
 * from the kernel-stamped sender of the message, NEVER from the payload; the
 * payload carries only the requested anointment name and the password for
 * the caller's OWN account (PAM inside the agent).  Policy: `name` must be in
 * the principal's `may_elevate` (or `*`), else EPERM; a failed authentication
 * is EACCES; both are audited.  Every call re-authenticates.
 *
 * `password` is NUL-terminated within AUTHAGENT_PASSWORD_MAX.  Both sides
 * zero (explicit_bzero) their copy of the request after use.
 */
#define	AUTHAGENT_NAME_MAX	64	/* == SVC_ANOINT_NAME_MAX */
#define	AUTHAGENT_PASSWORD_MAX	256

struct authagent_elevate_req {
	uint32_t	version;	/* AUTHAGENTD_PROTO_VERSION */
	uint32_t	op;		/* AUTHAGENT_OP_ELEVATE */
	uint32_t	flags;		/* reserved, must be 0 */
	uint32_t	reserved;	/* must be 0 */
	char		name[AUTHAGENT_NAME_MAX];	/* NUL-terminated */
	char		password[AUTHAGENT_PASSWORD_MAX];	/* NUL-terminated */
};
_Static_assert(sizeof(struct authagent_elevate_req) == 336,
    "authagent_elevate_req wire layout");

#endif /* AUTHAGENTD_PROTO_H */
