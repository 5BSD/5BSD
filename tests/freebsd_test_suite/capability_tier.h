/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Skips for cases that need /dev/mac_capability themselves, naming the VM
 * tier they belong to (docs/book/src/develop/testing.md).  With the plane
 * on and kern.mac_capability_isolation.enforce set, the production tier,
 * Capsule's claim refuses the device to every test: such a skip carries the
 * token DEFERRED_DEVICE_TIER, which tools/build/fuchsia/vm-provider.sh counts
 * as DEFERRED_TO_DEVICE_TIER=N.  Any other failure to reach the device keeps
 * the plain "capability plane unavailable" reason.
 */

#ifndef	_FREEBSD_TEST_CAPABILITY_TIER_H_
#define	_FREEBSD_TEST_CAPABILITY_TIER_H_

#include <sys/types.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <string.h>

#include <atf-c.h>

/* Skip after an open of, or a connect through, /dev/mac_capability failed. */
static inline void
capability_plane_skip(int error)
{
	size_t len;
	int enforce;

	len = sizeof(enforce);
	if ((error == EACCES || error == EPERM) &&
	    sysctlbyname("kern.mac_capability_isolation.enforce", &enforce,
	    &len, NULL, 0) == 0 && enforce != 0)
		atf_tc_skip("DEFERRED_DEVICE_TIER: capability plane "
		    "unavailable: /dev/mac_capability is claimed by the "
		    "enforcing plane (%s); this case runs in the plane-on test "
		    "tier", strerror(error));
	atf_tc_skip("capability plane unavailable: %s", strerror(error));
}

#endif /* _FREEBSD_TEST_CAPABILITY_TIER_H_ */
