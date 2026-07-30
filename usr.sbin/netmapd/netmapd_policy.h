/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _NETMAPD_POLICY_H_
#define	_NETMAPD_POLICY_H_

#include <stddef.h>

#include <netmap_bearer.h>

int	netmapd_validate_message(const struct netmap_bearer_msg *, size_t,
	    size_t);
int	netmapd_validate_create(const struct netmap_bearer_create *);

#endif
