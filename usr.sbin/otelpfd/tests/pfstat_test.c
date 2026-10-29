/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Unit tests for the pf status to metrics conversion.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "pfstat.h"

/* A capturing exporter: renders every data point as one text line. */
struct capture {
	struct oe_exporter	 e;
	char			 text[16384];
	size_t			 len;
	int			 fail;
};

static int
cap_snapshot(struct oe_exporter *e, const struct oe_snapshot *sn)
{
	struct capture *c = (struct capture *)e;
	size_t i, j;

	for (i = 0; i < sn->npoints; i++) {
		c->len += snprintf(c->text + c->len, sizeof(c->text) - c->len,
		    "%s.%s %s", sn->profile, sn->name,
		    sn->kind == OE_AGG_COUNT ? "sum" :
		    sn->kind == OE_AGG_MAX ? "gauge" : "?");
		for (j = 0; j < sn->points[i].nattrs; j++)
			c->len += snprintf(c->text + c->len,
			    sizeof(c->text) - c->len, " %s=%s",
			    sn->points[i].attrs[j].name,
			    sn->points[i].attrs[j].value);
		c->len += snprintf(c->text + c->len, sizeof(c->text) - c->len,
		    " = %jd", (intmax_t)sn->points[i].scalar);
		if (sn->start.tv_sec != 0)
			c->len += snprintf(c->text + c->len,
			    sizeof(c->text) - c->len, " since %jd",
			    (intmax_t)sn->start.tv_sec);
		c->len += snprintf(c->text + c->len, sizeof(c->text) - c->len,
		    "\n");
	}
	return (c->fail ? -1 : 0);
}

static const struct oe_exporter_ops cap_ops = {
	.snapshot = cap_snapshot,
};

static void
has(const struct capture *c, const char *line)
{

	ATF_CHECK_MSG(strstr(c->text, line) != NULL, "missing \"%s\" in:\n%s",
	    line, c->text);
}

ATF_TC_WITHOUT_HEAD(conversion);
ATF_TC_BODY(conversion, tc)
{
	struct capture c;
	struct pf_status st;
	struct timespec ts = { 1700000000, 5 };

	memset(&c, 0, sizeof(c));
	c.e.ops = &cap_ops;
	memset(&st, 0, sizeof(st));
	st.running = 1;
	st.states = 42;
	st.states_halfopen = 2;
	st.src_nodes = 3;
	st.fragments = 4;
	st.syncookies_active = 1;
	st.fcounters[FCNT_STATE_SEARCH] = 10;
	st.fcounters[FCNT_STATE_INSERT] = 11;
	st.fcounters[FCNT_STATE_REMOVALS] = 12;
	st.scounters[SCNT_SRC_NODE_INSERT] = 21;
	st.ncounters[NCNT_FRAG_REMOVALS] = 33;
	st.counters[PFRES_MATCH] = 500;
	st.counters[PFRES_NOROUTE] = 7;
	st.lcounters[LCNT_STATES] = 8;
	st.lcounters[LCNT_SYNCOOKIES_VALID] = 9;
	st.pcounters[0][0][PF_PASS] = 1000;
	st.pcounters[0][0][PF_DROP] = 20;
	st.pcounters[1][1][PF_PASS] = 3000;
	st.pcounters[1][1][PF_DROP] = 40;
	st.bcounters[0][1] = 123456;
	st.bcounters[1][0] = UINT64_MAX;
	/* Enabled at uptime 100; now is uptime 1100. */
	st.since = 100;

	ATF_REQUIRE_EQ(pfstat_emit(&c.e, &st, &ts, 1100), 13);
	has(&c, "pf.running gauge = 1\n");
	has(&c, "pf.states gauge = 42\n");
	has(&c, "pf.states_halfopen gauge = 2\n");
	has(&c, "pf.src_nodes gauge = 3\n");
	has(&c, "pf.fragments gauge = 4\n");
	has(&c, "pf.syncookies_active gauge = 1\n");
	has(&c, "pf.state_operations sum operation=search = 10 since "
	    "1699999000\n");
	has(&c, "pf.state_operations sum operation=insert = 11 since 1699999000\n");
	has(&c, "pf.state_operations sum operation=removal = 12 since 1699999000\n");
	has(&c, "pf.src_node_operations sum operation=insert = 21 since 1699999000\n");
	has(&c, "pf.fragment_operations sum operation=removal = 33 since 1699999000\n");
	has(&c, "pf.reasons sum reason=match = 500 since 1699999000\n");
	has(&c, "pf.reasons sum reason=no-route = 7 since 1699999000\n");
	has(&c, "pf.limits sum limit=max states per rule = 8 since 1699999000\n");
	has(&c, "pf.limits sum limit=syncookies validated = 9 since 1699999000\n");
	has(&c, "pf.packets sum network.type=ipv4 "
	    "network.io.direction=receive action=pass = 1000 since "
	    "1699999000\n");
	has(&c, "pf.packets sum network.type=ipv4 "
	    "network.io.direction=receive action=block = 20 since "
	    "1699999000\n");
	has(&c, "pf.packets sum network.type=ipv6 "
	    "network.io.direction=transmit action=pass = 3000 since "
	    "1699999000\n");
	has(&c, "pf.packets sum network.type=ipv6 "
	    "network.io.direction=transmit action=block = 40 since "
	    "1699999000\n");
	has(&c, "pf.bytes sum network.type=ipv4 "
	    "network.io.direction=transmit = 123456 since 1699999000\n");
	/* Values beyond int64 saturate instead of turning negative. */
	has(&c, "pf.bytes sum network.type=ipv6 "
	    "network.io.direction=receive = 9223372036854775807 since "
	    "1699999000\n");
	/* Gauges carry no start time. */
	has(&c, "pf.states gauge = 42\n");
}

ATF_TC_WITHOUT_HEAD(stopped);
ATF_TC_BODY(stopped, tc)
{
	struct capture c;
	struct pf_status st;
	struct timespec ts = { 0, 0 };

	memset(&c, 0, sizeof(c));
	c.e.ops = &cap_ops;
	memset(&st, 0, sizeof(st));
	st.running = 0;
	ATF_REQUIRE_EQ(pfstat_emit(&c.e, &st, &ts, 50), 13);
	has(&c, "pf.running gauge = 0\n");
	has(&c, "pf.syncookies_active gauge = 0\n");
	/* Never enabled: no start time. */
	has(&c, "pf.reasons sum reason=match = 0\n");
}

ATF_TC_WITHOUT_HEAD(exporter_failure);
ATF_TC_BODY(exporter_failure, tc)
{
	struct capture c;
	struct pf_status st;
	struct timespec ts = { 0, 0 };

	memset(&c, 0, sizeof(c));
	c.e.ops = &cap_ops;
	c.fail = 1;
	memset(&st, 0, sizeof(st));
	ATF_CHECK_EQ(pfstat_emit(&c.e, &st, &ts, 0), -1);
}

/* A replayed status from a longer-running system: start unknown. */
ATF_TC_WITHOUT_HEAD(since_ahead);
ATF_TC_BODY(since_ahead, tc)
{
	struct capture c;
	struct pf_status st;
	struct timespec ts = { 1000, 0 };

	memset(&c, 0, sizeof(c));
	c.e.ops = &cap_ops;
	memset(&st, 0, sizeof(st));
	st.since = 500;
	ATF_REQUIRE_EQ(pfstat_emit(&c.e, &st, &ts, 400), 13);
	has(&c, "pf.reasons sum reason=match = 0\n");
	/* An uptime longer than the wall clock: start unknown too. */
	memset(&c, 0, sizeof(c));
	c.e.ops = &cap_ops;
	ATF_REQUIRE_EQ(pfstat_emit(&c.e, &st, &ts, 5000), 13);
	has(&c, "pf.reasons sum reason=match = 0\n");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, conversion);
	ATF_TP_ADD_TC(tp, stopped);
	ATF_TP_ADD_TC(tp, exporter_failure);
	ATF_TP_ADD_TC(tp, since_ahead);
	return (atf_no_error());
}
