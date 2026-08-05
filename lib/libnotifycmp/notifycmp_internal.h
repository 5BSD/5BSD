/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NOTIFYCMP_INTERNAL_H_
#define	_NOTIFYCMP_INTERNAL_H_

#include <stdint.h>

#include "notifycmp_protocol.h"

#define	NOTIFYCMP_REPLY_GRACE_MS	1000U

static inline uint32_t
notifycmp_rpc_timeout(uint32_t timeout_ms)
{

	if (timeout_ms == NOTIFYCMP_TIMEOUT_INFINITE)
		return (NOTIFYCMP_TIMEOUT_INFINITE);
	if (timeout_ms >= UINT32_MAX - NOTIFYCMP_REPLY_GRACE_MS)
		return (UINT32_MAX - 1);
	return (timeout_ms + NOTIFYCMP_REPLY_GRACE_MS);
}

#endif
