/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * switchboard label-reclaim decision points (docs/capability-lifecycle-cleanup.md).
 *
 * The operator reclaim op (SCTL_OP_RECLAIM, switchboardctl reclaim, driven by the
 * pkg deinstall hook) carries a bundle label that must fit the reclaim
 * notification's fixed label[] field with room for its NUL, and it fans the
 * SVC_OP_RECLAIM_LABEL notification out to running providers only.  These two
 * predicates are the single source of truth for those decisions, factored out
 * of sctl.c's SCTL_OP_RECLAIM handler and reload.c's svc_retire_label() so they
 * are pure, self-documenting, and unit-testable without a live daemon.
 */
#ifndef SWITCHBOARD_RECLAIM_GATE_H
#define SWITCHBOARD_RECLAIM_GATE_H

#include <sys/types.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

#include "switchboard.h"			/* SVC_STATE_* */
#include "switchboard_svc_proto.h"		/* struct svc_reclaim_label_msg */

/*
 * Whether a reclaim label of the given length fits the reclaim notification's
 * fixed label[] field with room for a terminating NUL.  A zero-length label is
 * rejected (nothing to reclaim); a label of exactly the field size or larger
 * leaves no room for the NUL and is rejected.  Valid range is 1 .. size-1.
 */
static inline bool
svc_reclaim_label_len_ok(size_t len)
{

	return (len >= 1 &&
	    len <= sizeof(((struct svc_reclaim_label_msg *)0)->label) - 1);
}

/*
 * Whether a running-service slot should receive the reclaim notification: only
 * a service that is fully RUNNING and has a live control channel.  A service in
 * any other state, or one without a control channel, is skipped by the push.
 * There is no safe pull reconciliation yet, so the package helper retries and
 * reports a visible failure if SwitchBoard has no running recipients.
 */
static inline bool
svc_reclaim_notify_target(int state, bool has_channel)
{

	return (state == SVC_STATE_RUNNING && has_channel);
}

/* A broadcast with no recipients did no work and must remain retryable. */
static inline int
svc_reclaim_delivery_status(unsigned recipients)
{

	return (recipients == 0 ? EAGAIN : 0);
}

#endif /* SWITCHBOARD_RECLAIM_GATE_H */
