/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Launch constraints in a unit manifest: the `launch { responsible = [...] }`
 * block that names who may cause a unit to exist.  Exercises
 * capbundle_parse_unit_ucl() at the parser boundary, the accessors, and the
 * svc_manifest conversion -- no daemon or capability kernel required.  The
 * switchboard side (matching a recorded responsible party against this list)
 * is tested by usr.sbin/switchboard/tests/responsibility_test.
 */

#include <sys/stat.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "libcapbundle_internal.h"

static int
parse_unit(const char *body, struct capbundle_service *svc, char *errbuf,
    size_t errlen)
{
	struct capbundle bundle;
	FILE *f;

	memset(&bundle, 0, sizeof(bundle));
	strlcpy(bundle.bundle_id, "org.test.launch", sizeof(bundle.bundle_id));

	f = fopen("Unit.ucl", "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE(fputs(body, f) >= 0);
	ATF_REQUIRE_EQ(0, fclose(f));

	if (errbuf != NULL && errlen > 0)
		errbuf[0] = '\0';
	return (capbundle_parse_unit_ucl("Unit.ucl", ".", &bundle, "worker",
	    svc, errbuf, errlen));
}

#define	PARSE_OK(body, svc)						\
	do {								\
		char _err[512];						\
		ATF_REQUIRE_EQ_MSG(0, parse_unit((body), (svc), _err,	\
		    sizeof(_err)), "unexpected error: %s", _err);	\
	} while (0)

#define	PARSE_FAILS(body, needle)					\
	do {								\
		struct capbundle_service _svc;				\
		char _err[512];						\
		ATF_REQUIRE_EQ_MSG(-1, parse_unit((body), &_svc, _err,	\
		    sizeof(_err)), "accepted: %s", (body));		\
		ATF_CHECK_MSG(strstr(_err, (needle)) != NULL,		\
		    "message \"%s\" does not mention \"%s\"", _err,	\
		    (needle));						\
	} while (0)

/* An ipc-activated unit: on-demand, so a constraint is meaningful. */
#define	IPC	"activation { ipc = [\"org.test.launch.worker\"]; }\n"

ATF_TC_WITHOUT_HEAD(absent_is_unconstrained);
ATF_TC_BODY(absent_is_unconstrained, tc)
{
	struct capbundle_service svc;

	PARSE_OK(IPC, &svc);
	ATF_CHECK_EQ(0U, svc.nlaunch_responsible);
	ATF_CHECK_EQ(0U, capbundle_svc_nlaunch_responsible(&svc));
	ATF_CHECK(capbundle_svc_launch_responsible(&svc, 0) == NULL);
}

ATF_TC_WITHOUT_HEAD(vocabulary_accepted);
ATF_TC_BODY(vocabulary_accepted, tc)
{
	struct capbundle_service svc;

	PARSE_OK(IPC "launch { responsible = [\"self\", \"switchboard\", "
	    "\"session\", \"session:uid=1001\", \"bundle\", "
	    "\"org.other.app/parent\"]; }\n", &svc);
	ATF_CHECK_EQ(6U, svc.nlaunch_responsible);
	ATF_CHECK_STREQ("self", svc.launch_responsible[0]);
	ATF_CHECK_STREQ("switchboard", svc.launch_responsible[1]);
	ATF_CHECK_STREQ("session", svc.launch_responsible[2]);
	ATF_CHECK_STREQ("session:uid=1001", svc.launch_responsible[3]);
	ATF_CHECK_STREQ("bundle", svc.launch_responsible[4]);
	ATF_CHECK_STREQ("org.other.app/parent", svc.launch_responsible[5]);
	ATF_CHECK_EQ(6U, capbundle_svc_nlaunch_responsible(&svc));
	ATF_CHECK_STREQ("self", capbundle_svc_launch_responsible(&svc, 0));
	ATF_CHECK_STREQ("org.other.app/parent",
	    capbundle_svc_launch_responsible(&svc, 5));
	ATF_CHECK(capbundle_svc_launch_responsible(&svc, 6) == NULL);
}

ATF_TC_WITHOUT_HEAD(string_form_accepted);
ATF_TC_BODY(string_form_accepted, tc)
{
	struct capbundle_service svc;

	PARSE_OK(IPC "launch { responsible = \"bundle\"; }\n", &svc);
	ATF_CHECK_EQ(1U, svc.nlaunch_responsible);
	ATF_CHECK_STREQ("bundle", svc.launch_responsible[0]);
}

ATF_TC_WITHOUT_HEAD(unknown_token_rejected);
ATF_TC_BODY(unknown_token_rejected, tc)
{

	PARSE_FAILS(IPC "launch { responsible = [\"anyone\"]; }\n",
	    "launch.responsible");
	/* A bare uid is not a party; the session form is required. */
	PARSE_FAILS(IPC "launch { responsible = [\"uid=1001\"]; }\n",
	    "launch.responsible");
	PARSE_FAILS(IPC "launch { responsible = [\"session:uid=\"]; }\n",
	    "launch.responsible");
	PARSE_FAILS(IPC "launch { responsible = [\"session:uid=abc\"]; }\n",
	    "launch.responsible");
	/* A label needs both halves and exactly one separator. */
	PARSE_FAILS(IPC "launch { responsible = [\"org.test.launch/\"]; }\n",
	    "launch.responsible");
	PARSE_FAILS(IPC "launch { responsible = [\"/worker\"]; }\n",
	    "launch.responsible");
	PARSE_FAILS(IPC "launch { responsible = [\"a/b/c\"]; }\n",
	    "launch.responsible");
	/* A bundle id is reverse-domain; a bare word is not a label. */
	PARSE_FAILS(IPC "launch { responsible = [\"parent\"]; }\n",
	    "launch.responsible");
}

ATF_TC_WITHOUT_HEAD(shape_errors_rejected);
ATF_TC_BODY(shape_errors_rejected, tc)
{

	PARSE_FAILS(IPC "launch = \"self\";\n", "launch must be an object");
	PARSE_FAILS(IPC "launch { }\n", "responsible");
	PARSE_FAILS(IPC "launch { responsible = []; }\n",
	    "at least one party");
	PARSE_FAILS(IPC "launch { responsible = [\"self\"]; who = 1; }\n",
	    "unknown key");
	PARSE_FAILS(IPC "launch { responsible = [1]; }\n", "must be strings");
	PARSE_FAILS(IPC "launch { responsible = [\"self\", \"self\"]; }\n",
	    "duplicate");
}

ATF_TC_WITHOUT_HEAD(over_max_rejected);
ATF_TC_BODY(over_max_rejected, tc)
{
	struct capbundle_service svc;
	char body[1024];
	size_t off;
	unsigned i;

	/* Exactly the maximum is accepted. */
	off = (size_t)snprintf(body, sizeof(body), IPC
	    "launch { responsible = [\"self\"");
	for (i = 1; i < CAPBUNDLE_MAX_LAUNCH_RESPONSIBLE; i++)
		off += (size_t)snprintf(body + off, sizeof(body) - off,
		    ", \"session:uid=%u\"", i);
	(void)snprintf(body + off, sizeof(body) - off, "]; }\n");
	PARSE_OK(body, &svc);
	ATF_CHECK_EQ(CAPBUNDLE_MAX_LAUNCH_RESPONSIBLE,
	    svc.nlaunch_responsible);

	/* One more is refused. */
	off = (size_t)snprintf(body, sizeof(body), IPC
	    "launch { responsible = [\"self\"");
	for (i = 1; i <= CAPBUNDLE_MAX_LAUNCH_RESPONSIBLE; i++)
		off += (size_t)snprintf(body + off, sizeof(body) - off,
		    ", \"session:uid=%u\"", i);
	(void)snprintf(body + off, sizeof(body) - off, "]; }\n");
	PARSE_FAILS(body, "more than");
}

ATF_TC_WITHOUT_HEAD(boot_unit_must_allow_switchboard);
ATF_TC_BODY(boot_unit_must_allow_switchboard, tc)
{
	struct capbundle_service svc;

	/*
	 * A boot-activated unit is launched by the switchboard, so a
	 * constraint that excludes it would refuse the unit's own boot.
	 */
	PARSE_FAILS("activation { boot = true; }\n"
	    "launch { responsible = [\"session\"]; }\n", "switchboard");
	PARSE_OK("activation { boot = true; }\n"
	    "launch { responsible = [\"switchboard\", \"session\"]; }\n", &svc);
	ATF_CHECK_EQ(2U, svc.nlaunch_responsible);
}

ATF_TC_WITHOUT_HEAD(own_bundle_label_must_exist);
ATF_TC_BODY(own_bundle_label_must_exist, tc)
{

	/*
	 * The harness bundle declares no units, so any label naming it is a
	 * typo; a label in another bundle cannot be checked here and passes.
	 */
	PARSE_FAILS(IPC "launch { responsible = "
	    "[\"org.test.launch/ghost\"]; }\n", "not a unit of this bundle");
}

ATF_TC_WITHOUT_HEAD(other_bundle_label_accepted);
ATF_TC_BODY(other_bundle_label_accepted, tc)
{
	struct capbundle_service svc;

	PARSE_OK(IPC "launch { responsible = "
	    "[\"org.other.app/main\"]; }\n", &svc);
	ATF_CHECK_EQ(1U, svc.nlaunch_responsible);
	ATF_CHECK_STREQ("org.other.app/main", svc.launch_responsible[0]);
}

ATF_TC_WITHOUT_HEAD(reaches_svc_manifest);
ATF_TC_BODY(reaches_svc_manifest, tc)
{
	struct capbundle_service svc;
	struct svc_manifest m;

	PARSE_OK(IPC "launch { responsible = [\"bundle\", "
	    "\"session:uid=1001\"]; }\n", &svc);
	memset(&m, 0, sizeof(m));
	ATF_REQUIRE_EQ(0, capbundle_svc_fill_manifest(&svc, &m));
	ATF_CHECK_EQ(2U, m.nlaunch_responsible);
	ATF_CHECK_STREQ("bundle", m.launch_responsible[0]);
	ATF_CHECK_STREQ("session:uid=1001", m.launch_responsible[1]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, absent_is_unconstrained);
	ATF_TP_ADD_TC(tp, vocabulary_accepted);
	ATF_TP_ADD_TC(tp, string_form_accepted);
	ATF_TP_ADD_TC(tp, unknown_token_rejected);
	ATF_TP_ADD_TC(tp, shape_errors_rejected);
	ATF_TP_ADD_TC(tp, over_max_rejected);
	ATF_TP_ADD_TC(tp, boot_unit_must_allow_switchboard);
	ATF_TP_ADD_TC(tp, own_bundle_label_must_exist);
	ATF_TP_ADD_TC(tp, other_bundle_label_accepted);
	ATF_TP_ADD_TC(tp, reaches_svc_manifest);
	return (atf_no_error());
}
