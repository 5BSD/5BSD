/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * serviced private-lookup-channel adoption decision
 * (docs/capability-ambient-lookup-per-process.md, P2).
 *
 * SVC_OP_REGISTER_LOOKUP lets a process hand serviced one endpoint of a channel
 * pair it created for itself, which serviced adopts as that process's private
 * lookup channel.  This is the single source of truth for the pure part of that
 * decision — the message-shape and scope rules — factored out of domain.c's
 * handler so it is self-documenting and unit-testable without a live daemon.
 *
 * The security-critical invariant lives here: the adopted channel's domain is
 * the domain of the channel the request ARRIVED on (never a value from the
 * wire), so a client can never register a wider scope than it already holds.
 */
#ifndef SERVICED_REGISTER_LOOKUP_GATE_H
#define SERVICED_REGISTER_LOOKUP_GATE_H

#include <sys/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>

#include "serviced.h"			/* enum svc_domain_kind */
#include "serviced_svc_proto.h"		/* struct svc_register_lookup_req */

/*
 * Validate a SVC_OP_REGISTER_LOOKUP request and decide the adopted channel's
 * domain.  Pure: it inspects only the wire-visible shape (message length,
 * declared flags, attached-descriptor count, and whether that descriptor is a
 * mac_capability channel) plus the ARRIVING channel's domain.
 *
 *   msg_len       length of the request payload
 *   nfds          number of attached descriptors (must be exactly 1)
 *   fd_is_channel whether the attached descriptor answered MAC_CAPABILITY_GETINFO
 *   flags         the request's flags field (reserved, must be 0)
 *   arriving      the domain of the channel the request came in on
 *   adopt         OUT: the domain to adopt the endpoint under (== arriving)
 *
 * Returns 0 with *adopt set on success; a positive errno otherwise:
 *   EINVAL  wrong payload length, non-zero flags, not exactly one descriptor,
 *           or the descriptor is not a mac_capability channel.
 *
 * The adopted domain is ALWAYS the arriving domain: SYSTEM stays SYSTEM, USER
 * stays USER, CONTROL stays CONTROL.  Adoption never widens scope.
 */
static inline int
svc_register_lookup_check(size_t msg_len, size_t nfds, bool fd_is_channel,
    uint32_t flags, enum svc_domain_kind arriving, enum svc_domain_kind *adopt)
{

	if (msg_len != sizeof(struct svc_register_lookup_req))
		return (EINVAL);
	if (flags != 0)
		return (EINVAL);
	if (nfds != 1)
		return (EINVAL);
	if (!fd_is_channel)
		return (EINVAL);
	*adopt = arriving;
	return (0);
}

#endif /* SERVICED_REGISTER_LOOKUP_GATE_H */
