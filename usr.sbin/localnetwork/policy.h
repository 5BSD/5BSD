/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NETWORKCMP_POLICY_H_
#define	_NETWORKCMP_POLICY_H_

#include <stdbool.h>
#include <stdint.h>

/*
 * Session policy.  It is derived from the requesting unit's manifest and the
 * administrative ceiling at session creation and is immutable for the life of
 * the session: the broker copies it once and never mutates it, and the client
 * never supplies policy on a request.  Every connect, udp, and resolve is
 * validated against this fixed policy.
 */
struct networkcmp_policy {
	bool		ipv4;
	bool		ipv6;
	bool		allow_connect;	/* CONNECT (TCP) permitted */
	bool		allow_udp;	/* UDP (connected datagram) permitted */
	uint32_t	max_results;	/* resolve result ceiling */
};

int	networkcmp_policy_default(struct networkcmp_policy *);

#endif
