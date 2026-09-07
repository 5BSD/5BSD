/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * serviced control-plane authorization gate (P3, sctl.c).
 *
 * The capability control channel (system.serviced) exposes read-only status
 * ops to any holder, but every STATE-CHANGING op — reload, start, stop, and
 * label reclaim — requires the administrative right SVC_RIGHTS_ADMIN held on
 * the caller's grant.  A caller that holds only a plain control grant (no
 * ADMIN bit) is refused with EPERM; the read-only STATUS/SERVICES ops stay
 * open.  These two predicates are the single source of truth for that
 * decision, factored out of sctl_cap_request()/sctl_execute_op() so they are
 * pure, self-documenting, and unit-testable without a live daemon.
 *
 * NOTE: the "core management class is unstoppable even WITH admin" rule is a
 * SECOND, independent gate (svc_management_check_class(), management.c): admin
 * clears the door here, then the management class is checked separately, so a
 * core unit stays running even for an ADMIN caller.
 */
#ifndef SERVICED_SCTL_GATE_H
#define SERVICED_SCTL_GATE_H

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#include "serviced_ctl.h"		/* SCTL_OP_* */
#include "serviced_svc_proto.h"		/* SVC_RIGHTS_ADMIN */

/*
 * Whether a control op mutates serviced state and therefore requires the
 * ADMIN right.  STATUS and SERVICES are read-only and open to any control
 * grant; RELOAD, START, STOP and RECLAIM change the running configuration and
 * are admin-gated.  Any unrecognized op is treated as privileged (deny by
 * default) — an unknown op is never something an unprivileged caller should
 * reach, and the dispatcher rejects it with ENOTSUP regardless.
 */
static inline bool
sctl_op_requires_admin(uint32_t op)
{

	switch (op) {
	case SCTL_OP_STATUS:
	case SCTL_OP_SERVICES:
		return (false);
	case SCTL_OP_RELOAD:
	case SCTL_OP_START_SVC:
	case SCTL_OP_STOP_SVC:
	case SCTL_OP_RECLAIM:
		return (true);
	default:
		return (true);
	}
}

/*
 * Derive the caller's admin authority from the rights held on its control
 * grant.  Authority is the held SVC_RIGHTS_ADMIN bit, not a uid: this is the
 * capability-plane replacement for the retired "peer euid == 0" socket check.
 */
static inline bool
sctl_rights_is_admin(uint64_t cap_rights)
{

	return ((cap_rights & SVC_RIGHTS_ADMIN) != 0);
}

#endif /* SERVICED_SCTL_GATE_H */
