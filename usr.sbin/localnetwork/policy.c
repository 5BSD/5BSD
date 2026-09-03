/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <string.h>

#include "policy.h"

int
networkcmp_policy_from_rights(struct networkcmp_policy *policy,
    service_rights_t rights)
{
	bool admin;

	if (policy == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(policy, 0, sizeof(*policy));
	admin = service_rights_allow(rights, SERVICE_RIGHTS_ADMIN);
	policy->ipv4 = admin || service_rights_allow(rights, NETWORKCMP_RIGHT_INET4);
	policy->ipv6 = admin || service_rights_allow(rights, NETWORKCMP_RIGHT_INET6);
	policy->allow_connect = admin ||
	    service_rights_allow(rights, NETWORKCMP_RIGHT_CONNECT);
	policy->allow_udp = admin ||
	    service_rights_allow(rights, NETWORKCMP_RIGHT_UDP);
	policy->resolve = admin ||
	    service_rights_allow(rights, NETWORKCMP_RIGHT_RESOLVE);
	policy->allow_internal = admin ||
	    service_rights_allow(rights, NETWORKCMP_RIGHT_INTERNAL);
	policy->max_results = policy->resolve ? 16 : 0;
	return (0);
}

int
networkcmp_policy_default(struct networkcmp_policy *policy)
{

	return (networkcmp_policy_from_rights(policy, SERVICE_RIGHTS_ALL));
}

bool
networkcmp_policy_permits_any(const struct networkcmp_policy *policy)
{

	if (policy == NULL)
		return (false);
	return (policy->allow_connect || policy->allow_udp || policy->resolve);
}
