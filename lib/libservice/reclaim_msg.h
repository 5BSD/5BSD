/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libservice inbound reclaim-notification message validation
 * (docs/capability-lifecycle-cleanup.md).
 *
 * SVC_OP_RECLAIM_LABEL is a fire-and-forget serviced -> service notification
 * that a bundle label has been retired.  The dispatch path must fail closed on
 * any malformation — wrong length, wrong op, reserved flags set, or an
 * unterminated label — and never invoke a provider's reclaim handler on a
 * message it did not fully validate.  This predicate is the single source of
 * truth for that message-shape check, factored out of libservice.c's dispatch
 * so it is pure and unit-testable with no live plane.  The runtime
 * "handler != NULL" check stays at the call site; it is not a message property.
 */
#ifndef LIBSERVICE_RECLAIM_MSG_H
#define LIBSERVICE_RECLAIM_MSG_H

#include <sys/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "serviced_svc_proto.h"		/* struct svc_reclaim_label_msg, SVC_OP_* */

/*
 * Whether a received message is a well-formed SVC_OP_RECLAIM_LABEL
 * notification: it is exactly the reclaim struct's size, carries the reclaim
 * op, has no reserved flags set, and its label is NUL-terminated within the
 * fixed field.  Fail closed on any deviation.
 */
static inline bool
service_reclaim_msg_valid(const struct svc_reclaim_label_msg *m, size_t msglen)
{

	return (msglen == sizeof(*m) &&
	    m->op == SVC_OP_RECLAIM_LABEL &&
	    m->flags == 0 &&
	    strnlen(m->label, sizeof(m->label)) < sizeof(m->label));
}

#endif /* LIBSERVICE_RECLAIM_MSG_H */
