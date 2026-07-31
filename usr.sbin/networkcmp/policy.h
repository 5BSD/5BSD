/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NETWORKCMP_POLICY_H_
#define	_NETWORKCMP_POLICY_H_

#include <stdbool.h>
#include <stdint.h>

struct networkcmp_policy {
	bool		ipv4;
	bool		ipv6;
	bool		allow_connect;
	bool		allow_bind;
	uint32_t	max_results;
	uint32_t	max_sockets;
};

int	networkcmp_policy_default(struct networkcmp_policy *);

#endif
