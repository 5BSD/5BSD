/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for the SYSTEM ambient-channel launch-hygiene predicate
 * (ambient_hygiene.h svc_exec_ambient_spare_fd), the single decision point
 * that keeps the admin-bearing SYSTEM ambient lookup channel from surviving a
 * launched command's drop to an unprivileged uid.  Regression coverage for the
 * SEC-1 escalation: an unprivileged oneshot/RC unit (manifest user=/group=)
 * must NOT inherit the SYSTEM ambient channel.
 */
#include <sys/types.h>
#include <stdbool.h>

#include <atf-c.h>

#include "ambient_hygiene.h"

#define	 AMBIENT_FD	7	/* an arbitrary "installed channel" fd number */

/*
 * A command that does not drop credentials runs as serviced's own uid (root)
 * and keeps the SYSTEM ambient channel: rc and the want_console bootstrap need
 * discovery, and root is the admin principal by the plane's model.
 */
ATF_TC_WITHOUT_HEAD(no_creds_keeps_channel);
ATF_TC_BODY(no_creds_keeps_channel, tc)
{
	bool unset_env = true;
	int spare;

	spare = svc_exec_ambient_spare_fd(false, 65534, AMBIENT_FD, &unset_env);
	ATF_CHECK_EQ_MSG(AMBIENT_FD, spare,
	    "a non-cred-dropping command must keep the ambient channel");
	ATF_CHECK_MSG(!unset_env,
	    "SERVICE_LOOKUP_FD must be preserved when the channel is kept");
}

/*
 * An explicit user=root (creds resolved, but uid stays 0) keeps the channel:
 * root remains the admin principal, so no downgrade is warranted.
 */
ATF_TC_WITHOUT_HEAD(root_creds_keep_channel);
ATF_TC_BODY(root_creds_keep_channel, tc)
{
	bool unset_env = true;
	int spare;

	spare = svc_exec_ambient_spare_fd(true, 0, AMBIENT_FD, &unset_env);
	ATF_CHECK_EQ_MSG(AMBIENT_FD, spare,
	    "user=root must keep the ambient channel (still the admin uid)");
	ATF_CHECK_MSG(!unset_env, "SERVICE_LOOKUP_FD must be preserved for root");
}

/*
 * THE SECURITY PROPERTY: a command dropping to a non-root uid must get NO
 * ambient channel (spare fd == -1) and SERVICE_LOOKUP_FD must be unset, so an
 * unprivileged oneshot cannot look up system.serviced / system.lifecycle over
 * an inherited SYSTEM channel and drive the admin control plane.
 */
ATF_TC_WITHOUT_HEAD(nonroot_creds_scrub_channel);
ATF_TC_BODY(nonroot_creds_scrub_channel, tc)
{
	bool unset_env = false;
	int spare;

	spare = svc_exec_ambient_spare_fd(true, 65534, AMBIENT_FD, &unset_env);
	ATF_CHECK_EQ_MSG(-1, spare,
	    "an unprivileged uid must NOT inherit the SYSTEM ambient channel");
	ATF_CHECK_MSG(unset_env,
	    "SERVICE_LOOKUP_FD must be unset so no stale fd number is named");
}

/*
 * The decision must not depend on whether a channel happens to be installed:
 * a non-root drop scrubs regardless (defends against a future caller that
 * passes the live fd unconditionally), and with no channel installed
 * (ambient_fd == -1) the kept case is simply "-1", still consistent.
 */
ATF_TC_WITHOUT_HEAD(no_installed_channel_is_consistent);
ATF_TC_BODY(no_installed_channel_is_consistent, tc)
{
	bool unset_env;
	int spare;

	/* No channel installed, root: nothing to spare, nothing to unset. */
	unset_env = true;
	spare = svc_exec_ambient_spare_fd(false, 0, -1, &unset_env);
	ATF_CHECK_EQ(-1, spare);
	ATF_CHECK(!unset_env);

	/* No channel installed, non-root: still -1, and unset requested. */
	unset_env = false;
	spare = svc_exec_ambient_spare_fd(true, 1001, -1, &unset_env);
	ATF_CHECK_EQ(-1, spare);
	ATF_CHECK(unset_env);
}

/* A NULL unset_env pointer must be tolerated (fd decision still correct). */
ATF_TC_WITHOUT_HEAD(null_unset_env_ok);
ATF_TC_BODY(null_unset_env_ok, tc)
{
	ATF_CHECK_EQ(-1,
	    svc_exec_ambient_spare_fd(true, 42, AMBIENT_FD, NULL));
	ATF_CHECK_EQ(AMBIENT_FD,
	    svc_exec_ambient_spare_fd(false, 42, AMBIENT_FD, NULL));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, no_creds_keeps_channel);
	ATF_TP_ADD_TC(tp, root_creds_keep_channel);
	ATF_TP_ADD_TC(tp, nonroot_creds_scrub_channel);
	ATF_TP_ADD_TC(tp, no_installed_channel_is_consistent);
	ATF_TP_ADD_TC(tp, null_unset_env_ok);
	return (atf_no_error());
}
