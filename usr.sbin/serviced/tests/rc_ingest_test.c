/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Hermetic unit tests for the rc.d header parser (rc_ingest.c).
 */

#include <string.h>

#include <atf-c.h>

#include "rc_ingest.h"

static bool
has(char list[][SERVICED_LABEL_MAX], unsigned n, const char *name)
{
	unsigned i;

	for (i = 0; i < n; i++)
		if (strcmp(list[i], name) == 0)
			return (true);
	return (false);
}

ATF_TC_WITHOUT_HEAD(basic);
ATF_TC_BODY(basic, tc)
{
	static const char hdr[] =
	    "#!/bin/sh\n"
	    "#\n"
	    "# PROVIDE: sshd\n"
	    "# REQUIRE: LOGIN FILESYSTEMS\n"
	    "# BEFORE: securelevel\n"
	    "# KEYWORD: shutdown\n"
	    "\n"
	    ". /etc/rc.subr\n"
	    "# PROVIDE: notparsed\n";	/* after code: must be ignored */
	struct rc_unit_meta m;

	ATF_CHECK_EQ(0, rc_parse_header(hdr, &m));
	ATF_CHECK_EQ(1, m.nprovides);
	ATF_CHECK(has(m.provides, m.nprovides, "sshd"));
	ATF_CHECK(!has(m.provides, m.nprovides, "notparsed"));
	ATF_CHECK_EQ(2, m.nreq);
	ATF_CHECK(has(m.req, m.nreq, "LOGIN"));
	ATF_CHECK(has(m.req, m.nreq, "FILESYSTEMS"));
	ATF_CHECK_EQ(1, m.nbefore);
	ATF_CHECK(has(m.before, m.nbefore, "securelevel"));
	ATF_CHECK(m.kw_shutdown);
	ATF_CHECK(!m.kw_nostart);
	ATF_CHECK(!m.kw_firstboot);
}

ATF_TC_WITHOUT_HEAD(whitespace_and_multi);
ATF_TC_BODY(whitespace_and_multi, tc)
{
	static const char hdr[] =
	    "#   PROVIDE:   foo   bar\n"
	    "#\tREQUIRE:\tNETWORKING\n"
	    "# KEYWORD: nostart firstboot\n";
	struct rc_unit_meta m;

	ATF_CHECK_EQ(0, rc_parse_header(hdr, &m));
	ATF_CHECK_EQ(2, m.nprovides);
	ATF_CHECK(has(m.provides, m.nprovides, "foo"));
	ATF_CHECK(has(m.provides, m.nprovides, "bar"));
	ATF_CHECK_EQ(1, m.nreq);
	ATF_CHECK(has(m.req, m.nreq, "NETWORKING"));
	ATF_CHECK(m.kw_nostart);
	ATF_CHECK(m.kw_firstboot);
	ATF_CHECK(!m.kw_shutdown);
}

ATF_TC_WITHOUT_HEAD(no_provide);
ATF_TC_BODY(no_provide, tc)
{
	static const char hdr[] =
	    "#!/bin/sh\n"
	    "# REQUIRE: DAEMON\n"
	    "echo hi\n";
	struct rc_unit_meta m;

	ATF_CHECK_EQ(0, rc_parse_header(hdr, &m));
	ATF_CHECK_EQ(0, m.nprovides);	/* not an orderable service */
	ATF_CHECK_EQ(1, m.nreq);
}

ATF_TC_WITHOUT_HEAD(header_ends_at_code);
ATF_TC_BODY(header_ends_at_code, tc)
{
	/* A comment tag appearing after the first code line is ignored. */
	static const char hdr[] =
	    "# PROVIDE: early\n"
	    "name=early\n"
	    "# REQUIRE: late\n";
	struct rc_unit_meta m;

	ATF_CHECK_EQ(0, rc_parse_header(hdr, &m));
	ATF_CHECK_EQ(1, m.nprovides);
	ATF_CHECK(has(m.provides, m.nprovides, "early"));
	ATF_CHECK_EQ(0, m.nreq);		/* "late" was past the header */
}

ATF_TC_WITHOUT_HEAD(provide_overflow_bounded);
ATF_TC_BODY(provide_overflow_bounded, tc)
{
	/* More provides than SERVICED_MAX_PROVIDES must not overflow. */
	static const char hdr[] =
	    "# PROVIDE: a b c d e f g h i j k l\n";
	struct rc_unit_meta m;

	ATF_CHECK_EQ(0, rc_parse_header(hdr, &m));
	ATF_CHECK(m.nprovides <= SERVICED_MAX_PROVIDES);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, basic);
	ATF_TP_ADD_TC(tp, whitespace_and_multi);
	ATF_TP_ADD_TC(tp, no_provide);
	ATF_TP_ADD_TC(tp, header_ends_at_code);
	ATF_TP_ADD_TC(tp, provide_overflow_bounded);
	return (atf_no_error());
}
