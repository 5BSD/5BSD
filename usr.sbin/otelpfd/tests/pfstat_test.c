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
		    " = %jd\n", (intmax_t)sn->points[i].scalar);
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

	ATF_REQUIRE_EQ(pfstat_emit(&c.e, &st, &ts), 13);
	has(&c, "pf.running gauge = 1\n");
	has(&c, "pf.states gauge = 42\n");
	has(&c, "pf.states_halfopen gauge = 2\n");
	has(&c, "pf.src_nodes gauge = 3\n");
	has(&c, "pf.fragments gauge = 4\n");
	has(&c, "pf.syncookies_active gauge = 1\n");
	has(&c, "pf.state_operations sum operation=search = 10\n");
	has(&c, "pf.state_operations sum operation=insert = 11\n");
	has(&c, "pf.state_operations sum operation=removal = 12\n");
	has(&c, "pf.src_node_operations sum operation=insert = 21\n");
	has(&c, "pf.fragment_operations sum operation=removal = 33\n");
	has(&c, "pf.reasons sum reason=match = 500\n");
	has(&c, "pf.reasons sum reason=no-route = 7\n");
	has(&c, "pf.limits sum limit=max states per rule = 8\n");
	has(&c, "pf.limits sum limit=syncookies validated = 9\n");
	has(&c, "pf.packets sum network.type=inet direction=in action=pass "
	    "= 1000\n");
	has(&c, "pf.packets sum network.type=inet direction=in action=block "
	    "= 20\n");
	has(&c, "pf.packets sum network.type=inet6 direction=out action=pass "
	    "= 3000\n");
	has(&c, "pf.packets sum network.type=inet6 direction=out "
	    "action=block = 40\n");
	has(&c, "pf.bytes sum network.type=inet direction=out = 123456\n");
	/* Values beyond int64 saturate instead of turning negative. */
	has(&c, "pf.bytes sum network.type=inet6 direction=in = "
	    "9223372036854775807\n");
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
	ATF_REQUIRE_EQ(pfstat_emit(&c.e, &st, &ts), 13);
	has(&c, "pf.running gauge = 0\n");
	has(&c, "pf.syncookies_active gauge = 0\n");
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
	ATF_CHECK_EQ(pfstat_emit(&c.e, &st, &ts), -1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, conversion);
	ATF_TP_ADD_TC(tp, stopped);
	ATF_TP_ADD_TC(tp, exporter_failure);
	return (atf_no_error());
}
