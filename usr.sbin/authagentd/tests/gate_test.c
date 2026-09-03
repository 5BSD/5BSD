/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The crown-jewel regression for system.AuthAgent: the mint caller-gate.
 *
 * authagentd mints a session's capability bundle (a SYSTEM or per-uid USER
 * lookup channel) for whoever holds a channel to system.authagent.  Because
 * system.authagent is a plain SYSTEM name, any serviced-managed SYSTEM unit
 * could otherwise connect and ask us to mint {uid=0}, and be handed a SYSTEM
 * admin channel — the exact proxy privilege-escalation the serviced mint-gate
 * was written to close.  The gate refuses every caller that does not hold
 * SERVICE_RIGHTS_ADMIN, the right serviced stamps only on an ambient
 * login-session lookup on a full-discovery (root/wheel) channel — i.e. exactly
 * the login family (login/su/sshd).
 *
 * These are pure predicate tests: no plane, no serviced, no Casper.  They run
 * anywhere, which is why the gate was factored into authagent_caller_allowed().
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdbool.h>
#include <stdint.h>

#include <libservice.h>

#include "authagentd_test.h"

/*
 * The single most important assertion in the whole program.  An ordinary
 * SYSTEM unit reaches us over its own bootstrap channel, which serviced stamps
 * WITHOUT the admin bit (requester != NULL).  Modelled here as "every right
 * except ADMIN": even a maximally-privileged non-authenticator caller must be
 * refused a mint.  If this ever passes ADMIN through, the verified proxy
 * privilege-escalation is reopened.
 */
ATF_TC_WITHOUT_HEAD(caller_without_admin_is_denied);
ATF_TC_BODY(caller_without_admin_is_denied, tc)
{
	service_rights_t rights = SERVICE_RIGHTS_ALL & ~SERVICE_RIGHTS_ADMIN;

	ATF_CHECK_MSG(!authagent_caller_allowed(rights),
	    "a caller lacking SERVICE_RIGHTS_ADMIN must be refused a mint "
	    "(privilege-escalation regression)");
}

/* The login family reaches us with the admin bit set and is allowed. */
ATF_TC_WITHOUT_HEAD(caller_with_admin_is_allowed);
ATF_TC_BODY(caller_with_admin_is_allowed, tc)
{

	ATF_CHECK(authagent_caller_allowed(SERVICE_RIGHTS_ADMIN));
	/* The admin bit amid other rights is still allowed. */
	ATF_CHECK(authagent_caller_allowed(SERVICE_RIGHTS_ALL));
}

/* Fail closed: an unknown or empty identity (no rights) is denied. */
ATF_TC_WITHOUT_HEAD(caller_with_zero_rights_is_denied);
ATF_TC_BODY(caller_with_zero_rights_is_denied, tc)
{

	ATF_CHECK(!authagent_caller_allowed(SERVICE_RIGHTS_NONE));
}

/*
 * The gate's meaning depends on ADMIN being the reserved top bit that ordinary
 * per-service rights (the low bits) can never collide with.  Pin the ABI
 * assumptions the escalation argument rests on.
 */
ATF_TC_WITHOUT_HEAD(admin_right_is_the_reserved_top_bit);
ATF_TC_BODY(admin_right_is_the_reserved_top_bit, tc)
{

	ATF_CHECK_EQ((service_rights_t)1 << 63, SERVICE_RIGHTS_ADMIN);
	ATF_CHECK_EQ(SERVICE_RIGHTS_NONE, (service_rights_t)0);
	ATF_CHECK_EQ(SERVICE_RIGHTS_ALL, ~(service_rights_t)0);
	/* ADMIN is genuinely inside ALL and genuinely outside NONE. */
	ATF_CHECK((SERVICE_RIGHTS_ALL & SERVICE_RIGHTS_ADMIN) != 0);
	ATF_CHECK((SERVICE_RIGHTS_NONE & SERVICE_RIGHTS_ADMIN) == 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, caller_without_admin_is_denied);
	ATF_TP_ADD_TC(tp, caller_with_admin_is_allowed);
	ATF_TP_ADD_TC(tp, caller_with_zero_rights_is_denied);
	ATF_TP_ADD_TC(tp, admin_right_is_the_reserved_top_bit);
	return (atf_no_error());
}
