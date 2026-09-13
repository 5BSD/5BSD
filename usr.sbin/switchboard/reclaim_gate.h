/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Administrative retirement label-length validation.
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

#endif /* SWITCHBOARD_RECLAIM_GATE_H */
