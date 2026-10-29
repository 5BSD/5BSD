/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Unit tests for the BSM record to log record conversion.
 */

#include <sys/types.h>

#include <bsm/audit.h>
#include <bsm/audit_kevents.h>
#include <bsm/audit_record.h>
#include <bsm/libbsm.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "auditrec.h"
#include "bsmgen.h"

static struct auditrec_events events;

static void
load_events(void)
{

	ATF_REQUIRE_EQ(auditrec_events_load(&events), 0);
	ATF_REQUIRE(events.n > 100);
}

/* Read the records of the standard trail back with au_read_rec(3). */
static int
read_trail(u_char **recs, int *lens, int max, int files, int corrupt)
{
	FILE *f;
	int n;

	f = tmpfile();
	ATF_REQUIRE(f != NULL);
	(void)bsmgen_trail(f, files, corrupt);
	rewind(f);
	for (n = 0; n < max; n++) {
		lens[n] = au_read_rec(f, &recs[n]);
		if (lens[n] == -1)
			break;
	}
	fclose(f);
	return (n);
}

ATF_TC_WITHOUT_HEAD(event_table);
ATF_TC_BODY(event_table, tc)
{
	const struct auditrec_event *e;

	load_events();
	e = auditrec_event_find(&events, AUE_EXECVE);
	ATF_REQUIRE(e != NULL);
	ATF_CHECK_STREQ(e->name, "AUE_EXECVE");
	ATF_CHECK_STREQ(e->desc, "execve(2)");
	ATF_CHECK(auditrec_event_find(&events, 65000) == NULL);
	auditrec_events_free(&events);
	ATF_CHECK(auditrec_event_find(&events, AUE_EXECVE) == NULL);
}

ATF_TC_WITHOUT_HEAD(convert_trail);
ATF_TC_BODY(convert_trail, tc)
{
	struct oe_event ev;
	u_char *recs[8];
	int lens[8], n, i;
	char body[AUDITREC_BODY_MAX], probe[64];

	load_events();
	n = read_trail(recs, lens, 8, 1, 0);
	ATF_REQUIRE_EQ(n, 6);

	/* Trail file tokens are not events. */
	ATF_CHECK_EQ(auditrec_convert(&events, recs[0], lens[0], &ev, body,
	    sizeof(body), probe, sizeof(probe)), 0);
	ATF_CHECK_EQ(auditrec_convert(&events, recs[5], lens[5], &ev, body,
	    sizeof(body), probe, sizeof(probe)), 0);

	ATF_REQUIRE_EQ(auditrec_convert(&events, recs[1], lens[1], &ev, body,
	    sizeof(body), probe, sizeof(probe)), 1);
	ATF_CHECK_STREQ(ev.probe, "AUE_EXECVE");
	ATF_CHECK_STREQ(ev.profile, "audit");
	ATF_CHECK_EQ(ev.pid, 4242);
	ATF_CHECK_EQ(ev.ts.tv_sec, 1700000000);
	ATF_CHECK_EQ(ev.ts.tv_nsec, 250000000L);
	ATF_CHECK_STREQ(ev.body, "AUE_EXECVE execve(2) auid=1001 euid=0 "
	    "egid=0 ruid=1001 pid=4242 args=\"ls -l a b\\\"c\\\\d\" "
	    "path=/bin/ls "
	    "result=success:0");

	ATF_REQUIRE_EQ(auditrec_convert(&events, recs[2], lens[2], &ev, body,
	    sizeof(body), probe, sizeof(probe)), 1);
	ATF_CHECK_STREQ(ev.probe, "AUE_OPEN_R");
	ATF_CHECK_EQ(ev.pid, 77);
	ATF_CHECK_STREQ(ev.body, "AUE_OPEN_R open(2) - read auid=- euid=1001 "
	    "egid=20 ruid=1001 pid=77 path=/etc/master.passwd "
	    "text=\"note \\\"q\\\" \\\\ x\" text=\"\" result=failure:13");
	/* exec_env tokens never leak. */
	ATF_CHECK(strstr(ev.body, "hunter2") == NULL);

	ATF_REQUIRE_EQ(auditrec_convert(&events, recs[3], lens[3], &ev, body,
	    sizeof(body), probe, sizeof(probe)), 1);
	ATF_CHECK_STREQ(ev.probe, "event_65000");
	ATF_CHECK_STREQ(ev.body, "event_65000 auid=0 euid=0 egid=0 ruid=0 "
	    "pid=9 result=success:7");

	ATF_REQUIRE_EQ(auditrec_convert(&events, recs[4], lens[4], &ev, body,
	    sizeof(body), probe, sizeof(probe)), 1);
	ATF_CHECK_EQ(ev.ts.tv_sec, 1700000003);
	ATF_CHECK_STREQ(ev.body, "AUE_EXECVE execve(2) auid=0 euid=0 egid=0 "
	    "ruid=0 pid=10 result=failure:2");

	for (i = 0; i < n; i++)
		free(recs[i]);
	auditrec_events_free(&events);
}

ATF_TC_WITHOUT_HEAD(malformed);
ATF_TC_BODY(malformed, tc)
{
	struct oe_event ev;
	u_char *recs[8], junk[4] = { 0xee, 0, 0, 0 };
	int lens[8], n, i;
	char body[AUDITREC_BODY_MAX], probe[64];

	load_events();
	n = read_trail(recs, lens, 8, 0, 1);
	ATF_REQUIRE_EQ(n, 4);
	ATF_CHECK_EQ(auditrec_convert(&events, recs[0], lens[0], &ev, body,
	    sizeof(body), probe, sizeof(probe)), -1);
	ATF_CHECK_EQ(auditrec_convert(&events, recs[1], lens[1], &ev, body,
	    sizeof(body), probe, sizeof(probe)), 1);
	/* A record cut inside its first token. */
	ATF_CHECK_EQ(auditrec_convert(&events, recs[1], 3, &ev, body,
	    sizeof(body), probe, sizeof(probe)), -1);
	/* Cut inside a later token. */
	ATF_CHECK_EQ(auditrec_convert(&events, recs[1], lens[1] - 20, &ev,
	    body, sizeof(body), probe, sizeof(probe)), -1);
	ATF_CHECK_EQ(auditrec_convert(&events, junk, sizeof(junk), &ev, body,
	    sizeof(body), probe, sizeof(probe)), -1);
	ATF_CHECK_EQ(auditrec_convert(&events, recs[0], 0, &ev, body,
	    sizeof(body), probe, sizeof(probe)), -1);
	for (i = 0; i < n; i++)
		free(recs[i]);
	auditrec_events_free(&events);
}

ATF_TC_WITHOUT_HEAD(truncated_body);
ATF_TC_BODY(truncated_body, tc)
{
	struct oe_event ev;
	u_char *recs[8];
	int lens[8], n, i;
	char body[24], probe[8];

	load_events();
	n = read_trail(recs, lens, 8, 0, 0);
	ATF_REQUIRE_EQ(auditrec_convert(&events, recs[0], lens[0], &ev, body,
	    sizeof(body), probe, sizeof(probe)), 1);
	/* Small buffers truncate but stay terminated. */
	ATF_CHECK_EQ(strlen(ev.body), sizeof(body) - 1);
	ATF_CHECK_STREQ(ev.probe, "AUE_EXE");
	for (i = 0; i < n; i++)
		free(recs[i]);
	auditrec_events_free(&events);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, event_table);
	ATF_TP_ADD_TC(tp, convert_trail);
	ATF_TP_ADD_TC(tp, malformed);
	ATF_TP_ADD_TC(tp, truncated_body);
	return (atf_no_error());
}
