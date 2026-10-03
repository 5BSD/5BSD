/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Session minting requires AUTHENTICATE, a distinct authority from ADMIN.
 * These tests drive the real caller gate without a live daemon.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdbool.h>
#include <stdint.h>

#include <libservice.h>

#include "bsdauth_test.h"

/* All ordinary rights, including ADMIN, are insufficient without the
 * dedicated authentication right. */
ATF_TC_WITHOUT_HEAD(caller_without_authenticator_is_denied);
ATF_TC_BODY(caller_without_authenticator_is_denied, tc)
{
	service_rights_t rights = SERVICE_RIGHTS_ALL & ~SERVICE_RIGHTS_AUTHENTICATE;

	ATF_CHECK_MSG(!authagent_caller_allowed(rights),
	    "a caller lacking SERVICE_RIGHTS_AUTHENTICATE must be refused a mint "
	    "(privilege-escalation regression)");
}

/* Explicit authentication authority permits minting; ADMIN alone does not. */
ATF_TC_WITHOUT_HEAD(caller_with_authenticator_is_allowed);
ATF_TC_BODY(caller_with_authenticator_is_allowed, tc)
{

	ATF_CHECK(authagent_caller_allowed(SERVICE_RIGHTS_AUTHENTICATE));
	ATF_CHECK(!authagent_caller_allowed(SERVICE_RIGHTS_ADMIN));
	/* An intentional all-rights grant includes authentication authority. */
	ATF_CHECK(authagent_caller_allowed(SERVICE_RIGHTS_ALL));
}

/* Fail closed: an unknown or empty identity (no rights) is denied. */
ATF_TC_WITHOUT_HEAD(caller_with_zero_rights_is_denied);
ATF_TC_BODY(caller_with_zero_rights_is_denied, tc)
{

	ATF_CHECK(!authagent_caller_allowed(SERVICE_RIGHTS_NONE));
}

/* The authentication bit has a stable, distinct position in the wire mask. */
ATF_TC_WITHOUT_HEAD(authenticator_right_is_separate);
ATF_TC_BODY(authenticator_right_is_separate, tc)
{

	ATF_CHECK_EQ((service_rights_t)1 << 62, SERVICE_RIGHTS_AUTHENTICATE);
	ATF_CHECK_EQ(SERVICE_RIGHTS_NONE, (service_rights_t)0);
	ATF_CHECK_EQ(SERVICE_RIGHTS_ALL, ~(service_rights_t)0);
	/* The right belongs to ALL and never to NONE. */
	ATF_CHECK((SERVICE_RIGHTS_ALL & SERVICE_RIGHTS_AUTHENTICATE) != 0);
	ATF_CHECK((SERVICE_RIGHTS_NONE & SERVICE_RIGHTS_AUTHENTICATE) == 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, caller_without_authenticator_is_denied);
	ATF_TP_ADD_TC(tp, caller_with_authenticator_is_allowed);
	ATF_TP_ADD_TC(tp, caller_with_zero_rights_is_denied);
	ATF_TP_ADD_TC(tp, authenticator_right_is_separate);
	return (atf_no_error());
}
