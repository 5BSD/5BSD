/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Manifest parsing for Phase 5 activation sources: activation.timer and
 * activation.path.  Exercises capbundle_parse_unit_ucl() directly (declared in
 * the internal header) so the accept/reject decisions are tested at the parser
 * boundary, with no daemon or capability kernel required.
 */

#include <sys/stat.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "libcapbundle_internal.h"

/*
 * Write a Unit.ucl body to a temp file in the test's cwd and parse it.  Returns
 * the capbundle_parse_unit_ucl() result; on success svc is filled.  The parser
 * does not stat the program binary (verify does), so no bin/ tree is needed.
 */
static int
parse_unit(const char *body, struct capbundle_service *svc, char *errbuf,
    size_t errlen)
{
	struct capbundle bundle;
	FILE *f;

	memset(&bundle, 0, sizeof(bundle));
	strlcpy(bundle.bundle_id, "org.test.activation",
	    sizeof(bundle.bundle_id));

	f = fopen("Unit.ucl", "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE(fputs(body, f) >= 0);
	ATF_REQUIRE_EQ(0, fclose(f));

	if (errbuf != NULL && errlen > 0)
		errbuf[0] = '\0';
	return (capbundle_parse_unit_ucl("Unit.ucl", ".", &bundle, "worker",
	    svc, errbuf, errlen));
}

ATF_TC_WITHOUT_HEAD(timer_interval_parses);
ATF_TC_BODY(timer_interval_parses, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { timer = { interval = 45; } }\n", &svc, err,
	    sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK_EQ(45U, svc.timer_interval_sec);
	ATF_CHECK_EQ('\0', svc.activation_path[0]);
	/* A timer alone is a complete activation: no boot, no ipc needed. */
	ATF_CHECK(!svc.activation_boot);
	ATF_CHECK_EQ(0U, svc.nprovides);
}

ATF_TC_WITHOUT_HEAD(timer_calendar_string_rejected);
ATF_TC_BODY(timer_calendar_string_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* A cron/calendar string is not a monotonic interval: fail closed. */
	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { timer = { interval = \"0 * * * *\"; } }\n", &svc,
	    err, sizeof(err)));
	ATF_CHECK(strstr(err, "interval") != NULL);
}

ATF_TC_WITHOUT_HEAD(timer_unknown_key_rejected);
ATF_TC_BODY(timer_unknown_key_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* calendar=/persistent= schedules are deferred; reject unknown keys. */
	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { timer = { calendar = \"daily\"; } }\n", &svc, err,
	    sizeof(err)));
}

ATF_TC_WITHOUT_HEAD(timer_zero_rejected);
ATF_TC_BODY(timer_zero_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { timer = { interval = 0; } }\n", &svc, err,
	    sizeof(err)));
}

ATF_TC_WITHOUT_HEAD(timer_overlarge_rejected);
ATF_TC_BODY(timer_overlarge_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];
	char body[128];

	(void)snprintf(body, sizeof(body),
	    "activation { timer = { interval = %ld; } }\n",
	    (long)CAPBUNDLE_MAX_TIMER_INTERVAL + 1);
	ATF_CHECK_EQ(-1, parse_unit(body, &svc, err, sizeof(err)));
}

ATF_TC_WITHOUT_HEAD(path_parses);
ATF_TC_BODY(path_parses, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { path = { path = \"/var/spool/incoming\"; } }\n",
	    &svc, err, sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK_STREQ("/var/spool/incoming", svc.activation_path);
	ATF_CHECK_EQ(0U, svc.timer_interval_sec);
}

ATF_TC_WITHOUT_HEAD(path_relative_rejected);
ATF_TC_BODY(path_relative_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { path = { path = \"spool/incoming\"; } }\n", &svc,
	    err, sizeof(err)));
	ATF_CHECK(strstr(err, "absolute") != NULL);
}

ATF_TC_WITHOUT_HEAD(path_empty_rejected);
ATF_TC_BODY(path_empty_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { path = { path = \"\"; } }\n", &svc, err,
	    sizeof(err)));
}

ATF_TC_WITHOUT_HEAD(path_missing_key_rejected);
ATF_TC_BODY(path_missing_key_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit("activation { path = { } }\n", &svc, err,
	    sizeof(err)));
}

ATF_TC_WITHOUT_HEAD(empty_activation_still_rejected);
ATF_TC_BODY(empty_activation_still_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* No boot, ipc, timer, or path is still an error. */
	ATF_CHECK_EQ(-1, parse_unit("activation { }\n", &svc, err,
	    sizeof(err)));
}

ATF_TC_WITHOUT_HEAD(timer_and_ipc_coexist);
ATF_TC_BODY(timer_and_ipc_coexist, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* A unit may publish an IPC name and also be timer-activated. */
	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { ipc = [\"org.test.svc\"]; timer = { interval = 60; } }\n",
	    &svc, err, sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK_EQ(60U, svc.timer_interval_sec);
	ATF_CHECK_EQ(1U, svc.nprovides);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, timer_interval_parses);
	ATF_TP_ADD_TC(tp, timer_calendar_string_rejected);
	ATF_TP_ADD_TC(tp, timer_unknown_key_rejected);
	ATF_TP_ADD_TC(tp, timer_zero_rejected);
	ATF_TP_ADD_TC(tp, timer_overlarge_rejected);
	ATF_TP_ADD_TC(tp, path_parses);
	ATF_TP_ADD_TC(tp, path_relative_rejected);
	ATF_TP_ADD_TC(tp, path_empty_rejected);
	ATF_TP_ADD_TC(tp, path_missing_key_rejected);
	ATF_TP_ADD_TC(tp, empty_activation_still_rejected);
	ATF_TP_ADD_TC(tp, timer_and_ipc_coexist);

	return (atf_no_error());
}
