/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NOTIFY_INTERNAL_H_
#define	_NOTIFY_INTERNAL_H_

#include <stdint.h>

#include "notify_protocol.h"

#define	NOTIFY_REPLY_GRACE_MS	1000U

static inline uint32_t
notify_rpc_timeout(uint32_t timeout_ms)
{

	if (timeout_ms == NOTIFY_TIMEOUT_INFINITE)
		return (NOTIFY_TIMEOUT_INFINITE);
	if (timeout_ms >= UINT32_MAX - NOTIFY_REPLY_GRACE_MS)
		return (UINT32_MAX - 1);
	return (timeout_ms + NOTIFY_REPLY_GRACE_MS);
}

#endif
