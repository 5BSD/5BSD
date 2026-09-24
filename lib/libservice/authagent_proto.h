/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * system.Auth wire protocol.
 *
 * A login program (login/su/sshd), after authenticating a principal, asks the
 * auth-agent to mint that session's capability bundle.  The auth-agent holds the
 * principal->bundle policy and the mint authority; the login program holds only
 * a channel to system.Auth.  See docs/auth-agent-design.md.
 */
#ifndef	AUTHAGENTD_PROTO_H
#define	AUTHAGENTD_PROTO_H

#include <sys/types.h>
#include <stdint.h>

#define	AUTHAGENTD_NAME			"system.Auth"
/*
 * v2: AUTHAGENT_OP_ELEVATE (docs/ipc-anointments-design.md "Elevation").
 * v3: AUTHAGENT_OP_MINT_AUTH -- a non-admin caller (an ordinary session's
 *     su) mints another principal's session by proving that principal's
 *     password, instead of holding SERVICE_RIGHTS_ADMIN.
 */
#define	AUTHAGENTD_PROTO_VERSION	3U
/*
 * Oldest version the agent still accepts.  MINT_SESSION and ELEVATE are
 * wire-identical from v2 on (v3 only ADDED the MINT_AUTH op and its own
 * request struct), so a v2 login/su/sshd keeps working against a v3 agent
 * across a rolling upgrade.  MINT_AUTH itself requires the exact current
 * version -- no v2 client emits it.
 */
#define	AUTHAGENTD_PROTO_VERSION_MIN	2U

/* Request op codes (second field of every request, after `version`). */
#define	AUTHAGENT_OP_MINT_SESSION	1U
#define	AUTHAGENT_OP_ELEVATE		2U
#define	AUTHAGENT_OP_MINT_AUTH		3U

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
 * system.Auth IS the assertion "I am a trusted authenticator and have
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
 * The request goes from the client straight to system.Auth over the
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

/*
 * AUTHAGENT_OP_MINT_AUTH -- authenticated session mint for a non-admin caller.
 *   request: struct authagent_mint_auth_req
 *   reply:   struct authagent_mint_reply; on success the minted session lookup
 *            channel for `uid` is attached via SCM_RIGHTS (nfds == 1).
 *
 * AUTHAGENT_OP_MINT_SESSION trusts the caller's SERVICE_RIGHTS_ADMIN (the bit
 * switchboard stamps only on the login family's full-discovery channel) as
 * the assertion "I authenticated this principal."  A su from an ordinary,
 * non-admin session holds no such bit, so it cannot mint the target's session
 * and the switched shell loses its lookup channel.  MINT_AUTH closes that: the
 * caller supplies the TARGET principal's `password` (the one su already
 * collected through PAM), and the agent authenticates it against
 * /etc/master.passwd itself -- exactly as ELEVATE does -- before minting the
 * target uid's full policy set.  No admin bit is required; the caller must be
 * a session (not a unit), and failures are rate-limited per uid.  Unlike
 * ELEVATE the uid CHANGES to the target and the set is the target's own, not
 * the caller's set plus one.
 *
 * `password` is NUL-terminated within AUTHAGENT_PASSWORD_MAX.  Both sides
 * zero (explicit_bzero) their copy after use.
 */
struct authagent_mint_auth_req {
	uint32_t	version;	/* AUTHAGENTD_PROTO_VERSION */
	uint32_t	op;		/* AUTHAGENT_OP_MINT_AUTH */
	uint32_t	uid;		/* the target principal being switched to */
	uint32_t	flags;		/* FORWARDABLE, else 0 */
	char		password[AUTHAGENT_PASSWORD_MAX];	/* NUL-terminated */
};
_Static_assert(sizeof(struct authagent_mint_auth_req) == 272,
    "authagent_mint_auth_req wire layout");

#endif /* AUTHAGENTD_PROTO_H */
