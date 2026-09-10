/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libservice per-process private-lookup-channel registration decision
 * (docs/capability-ambient-lookup-per-process.md, P2).
 *
 * On first ambient use a process tries to register its OWN private lookup
 * channel with switchboard (create a pair, hand switchboard one end, keep the other),
 * so its lookups never share the inherited discovery channel's racy receive
 * queue.  The whole mechanism is best-effort: if the create syscall is missing
 * (old kernel), the registration send fails, or no ACK arrives before the
 * bounded timeout, the process MUST fall back to the inherited shared channel
 * exactly as before — a broken registration can never break service discovery
 * or boot.  This predicate is the single source of truth for that fail-soft
 * decision, factored out of service_ambient.c so it is pure and unit-testable
 * with no live plane.
 */
#ifndef LIBSERVICE_AMBIENT_LOOKUP_H
#define LIBSERVICE_AMBIENT_LOOKUP_H

#include <stdbool.h>

enum service_ambient_reg_outcome {
	SERVICE_AMBIENT_USE_PRIVATE,	/* registration succeeded: use the private fd */
	SERVICE_AMBIENT_USE_INHERITED,	/* any failure: fall back to the shared fd */
};

/*
 * Decide, from the three registration steps' outcomes, whether to use the newly
 * created private lookup channel or fall back to the inherited shared channel.
 *
 *   create_errno  0 if mac_capability_channel_create() made a pair, else the
 *                 errno it failed with (ENOSYS on an old kernel, etc.)
 *   send_ok       whether the SVC_OP_REGISTER_LOOKUP message (carrying the peer
 *                 endpoint) was successfully sent over the shared channel
 *   ack_ok        whether switchboard's ACK arrived and validated on the private
 *                 endpoint within the bounded timeout
 *
 * Only an all-green path uses the private channel; ANY failure — no syscall, a
 * send error, or a missing/invalid/late ACK — falls back to the inherited
 * shared channel.  Fail-soft is the invariant: the process gets no less
 * discovery than it had before, never more, and a registration hiccup is
 * invisible to callers.
 */
static inline enum service_ambient_reg_outcome
service_ambient_reg_decide(int create_errno, bool send_ok, bool ack_ok)
{

	if (create_errno != 0)
		return (SERVICE_AMBIENT_USE_INHERITED);
	if (!send_ok)
		return (SERVICE_AMBIENT_USE_INHERITED);
	if (!ack_ok)
		return (SERVICE_AMBIENT_USE_INHERITED);
	return (SERVICE_AMBIENT_USE_PRIVATE);
}

#endif /* LIBSERVICE_AMBIENT_LOOKUP_H */
