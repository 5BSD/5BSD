/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NETWORKCMP_POLICY_H_
#define	_NETWORKCMP_POLICY_H_

#include <stdbool.h>
#include <stdint.h>

#include <libservice.h>		/* service_rights_t */

/*
 * Network-capability rights (docs/capability-authority-model.md).  In this OS a
 * session's authority is the unforgeable set of rights serviced stamps onto the
 * granted channel (struct service_identity.rights) — never a hardcoded default
 * and never the caller's uid.  These per-service low bits name the individual
 * network operations the network capability distinguishes; the minter (an
 * authority-agent / manifest ceiling) attenuates a grant by clearing bits, and
 * attenuation is monotone (a child grant can only clear, never set, bits).
 *
 * SERVICE_RIGHTS_ADMIN (the reserved top bit) is the cross-service admin bypass:
 * it authorizes every operation, including reaching internal ranges.  A legacy
 * lookup that carries no explicit rights receives SERVICE_RIGHTS_ALL (all bits,
 * including ADMIN), so it continues to receive full network authority; a session
 * granted SERVICE_RIGHTS_NONE receives nothing and is denied (default-deny).
 */
#define	NETWORKCMP_RIGHT_RESOLVE	((service_rights_t)1 << 0) /* DNS resolve */
#define	NETWORKCMP_RIGHT_CONNECT	((service_rights_t)1 << 1) /* TCP connect */
#define	NETWORKCMP_RIGHT_UDP		((service_rights_t)1 << 2) /* UDP */
#define	NETWORKCMP_RIGHT_INET4		((service_rights_t)1 << 3) /* IPv4 */
#define	NETWORKCMP_RIGHT_INET6		((service_rights_t)1 << 4) /* IPv6 */
/*
 * Permission to reach internal destinations — loopback, link-local, and the
 * RFC1918/ULA private ranges (SSRF surface: other local capability endpoints and
 * management planes).  Denied by default; granted only to a session whose
 * authority explicitly carries this bit (or ADMIN).
 */
#define	NETWORKCMP_RIGHT_INTERNAL	((service_rights_t)1 << 5)

/*
 * Session policy.  It is derived once, at session creation, from the rights the
 * caller's granted channel actually carries (networkcmp_policy_from_rights) and
 * is immutable for the life of the session: the broker copies it once and never
 * mutates it, and the client never supplies policy on a request.  Every connect,
 * udp, and resolve is validated against this fixed policy.  A session that
 * carries no network rights derives an all-false policy that permits nothing.
 */
struct networkcmp_policy {
	bool		ipv4;
	bool		ipv6;
	bool		allow_connect;	/* CONNECT (TCP) permitted */
	bool		allow_udp;	/* UDP (connected datagram) permitted */
	bool		resolve;	/* DNS resolution permitted */
	bool		allow_internal;	/* loopback/link-local/private permitted */
	uint32_t	max_results;	/* resolve result ceiling */
};

/*
 * Derive the immutable session policy from the rights serviced granted this
 * session.  Fail-closed: every dimension defaults to deny and is enabled only
 * when the corresponding right (or ADMIN) is held.
 */
int	networkcmp_policy_from_rights(struct networkcmp_policy *,
	    service_rights_t rights);

/*
 * The full (admin-equivalent) policy: networkcmp_policy_from_rights() with
 * SERVICE_RIGHTS_ALL.  Retained for callers/tests that legitimately exercise the
 * broker under an unattenuated grant; it is NOT the session default.
 */
int	networkcmp_policy_default(struct networkcmp_policy *);

/* True iff the policy authorizes any operation at all (else deny the session). */
bool	networkcmp_policy_permits_any(const struct networkcmp_policy *);

#endif
