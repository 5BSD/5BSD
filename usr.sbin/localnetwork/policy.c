/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <string.h>

#include "policy.h"
#include "session.h"

int
networkcmp_policy_default(struct networkcmp_policy *policy)
{

	if (policy == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(policy, 0, sizeof(*policy));
	policy->ipv4 = true;
	policy->ipv6 = true;
	policy->allow_connect = true;
	policy->allow_bind = false;
	policy->max_results = 16;
	policy->max_sockets = NETWORKCMP_SESSION_MAX_SOCKETS;
	return (0);
}
