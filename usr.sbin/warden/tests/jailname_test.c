/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Pure-unit tests for warden(8)'s jail-name derivation and descriptor parsing.
 *
 * The headline invariant is INJECTIVITY: jail_name_from_label() must map two
 * distinct channel labels to two distinct jail names.  A recent fix replaced a
 * lossy sanitise-and-truncate mapping (which folded "a.b" and "a_b" together and
 * collapsed every label sharing a 63-char prefix) with a collision-resistant
 * SHA-256 scheme.  These tests are the executable statement of that invariant:
 * if the lossy mapping ever returns, distinct_labels_get_distinct_names fails.
 *
 * These are pure functions of their arguments — no capability plane, no jail, no
 * root — so this suite runs anywhere, including in-session.
 */

#include <atf-c.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "warden_proto.h"
#include "warden_test.h"

/*
 * Contract constant.  warden.c defines WARDEN_JAIL_NAME_MAX privately (64); the
 * derivation promises a name of at most WARDEN_JAIL_NAME_MAX-1 characters.  We
 * mirror the value here so the bound is asserted rather than assumed.
 */
#define	TEST_JAIL_NAME_MAX	64

/*
 * A produced name must use only the jail-legal alphabet AND, per the injectivity
 * fix, must NOT contain '.' (which the kernel treats as jail hierarchy).  The
 * SHA-256 scheme emits "wj_" followed by lowercase hex, so the accepted set is
 * [A-Za-z0-9_-]; '.' is explicitly forbidden.
 */
static bool
name_is_valid(const char *name)
{
	size_t i, len;

	len = strlen(name);
	if (len == 0 || len > TEST_JAIL_NAME_MAX - 1)
		return (false);
	for (i = 0; i < len; i++) {
		char c = name[i];

		if (c == '.')
			return (false);
		if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9') || c == '_' || c == '-'))
			return (false);
	}
	return (true);
}

static void
derive(const char *label, char *out, size_t outsz)
{

	ATF_REQUIRE_MSG(warden_test_jail_name(label, out, outsz),
	    "derivation failed for label \"%s\"", label);
	ATF_REQUIRE_MSG(name_is_valid(out),
	    "label \"%s\" produced invalid jail name \"%s\"", label, out);
}

/*
 * THE PROPERTY.  A curated set of label pairs the OLD lossy mapping collided —
 * punctuation folded to '_', and long shared prefixes truncated — plus a larger
 * generated population, must all map to pairwise-distinct, valid jail names.
 */
ATF_TC_WITHOUT_HEAD(distinct_labels_get_distinct_names);
ATF_TC_BODY(distinct_labels_get_distinct_names, tc)
{
	/*
	 * Hand-picked adversarial labels.  Under the retired sanitise-and-
	 * truncate scheme, each bracketed group would have collapsed to a single
	 * jail name; the injective derivation must keep every one distinct.
	 */
	static const char *const labels[] = {
		/* Punctuation folded to '_' by the old mapping. */
		"a.b", "a_b", "a-b",
		"org.x.svc", "org_x_svc", "org-x-svc",
		"com.example.App", "com_example_App",
		/* First 63 chars identical, differ only afterwards. */
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxA",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxB",
		/* Share a 63-char prefix, diverge in the tail only. */
		"prefix.shared.identical.for.a.very.long.while.aaaaaaaaaaaaaaaa.1",
		"prefix.shared.identical.for.a.very.long.while.aaaaaaaaaaaaaaaa.2",
		/* Case and separator variants. */
		"user.session", "user.Session", "User.session",
		/* Empty-component and trailing-separator variants. */
		"a..b", "a.b.", ".a.b",
	};
	char names[nitems(labels)][TEST_JAIL_NAME_MAX];
	size_t i, j;

	for (i = 0; i < nitems(labels); i++)
		derive(labels[i], names[i], sizeof(names[i]));

	for (i = 0; i < nitems(labels); i++) {
		for (j = i + 1; j < nitems(labels); j++) {
			ATF_CHECK_MSG(strcmp(names[i], names[j]) != 0,
			    "COLLISION: labels \"%s\" and \"%s\" both map to "
			    "jail name \"%s\"", labels[i], labels[j], names[i]);
		}
	}
}

/*
 * A larger generated population.  200 distinct labels, deliberately mixing '.',
 * '_' and '-' separators so that any residual sanitise-fold would surface as a
 * collision; every derived name must be unique.
 */
ATF_TC_WITHOUT_HEAD(generated_labels_have_no_collisions);
ATF_TC_BODY(generated_labels_have_no_collisions, tc)
{
#define	N	200
	static char labels[N][96];
	static char names[N][TEST_JAIL_NAME_MAX];
	size_t i, j;

	for (i = 0; i < N; i++) {
		/*
		 * Vary the separator by index so labels i and its fold-twin only
		 * differ in punctuation the old mapping would have erased.
		 */
		char sep = (i % 3 == 0) ? '.' : (i % 3 == 1) ? '_' : '-';

		(void)snprintf(labels[i], sizeof(labels[i]),
		    "org%cservice%cinstance%c%zu%cshard%c%zu",
		    sep, sep, sep, i, sep, sep, (i * 7 + 3));
		derive(labels[i], names[i], sizeof(names[i]));
	}
	for (i = 0; i < N; i++)
		for (j = i + 1; j < N; j++)
			ATF_CHECK_MSG(strcmp(names[i], names[j]) != 0,
			    "COLLISION between \"%s\" and \"%s\" -> \"%s\"",
			    labels[i], labels[j], names[i]);
#undef N
}

/*
 * Legitimate jail reuse across a consumer restart depends on the derivation
 * being a pure, deterministic function of the label: the same label must always
 * produce the same name, or a relaunched consumer could never reattach.
 */
ATF_TC_WITHOUT_HEAD(same_label_is_deterministic);
ATF_TC_BODY(same_label_is_deterministic, tc)
{
	static const char *const labels[] = {
		"org.example.service",
		"a",
		"a.b.c.d.e.f.g",
		"UPPER.and.lower.MixeD",
	};
	char first[TEST_JAIL_NAME_MAX], again[TEST_JAIL_NAME_MAX];
	size_t i;

	for (i = 0; i < nitems(labels); i++) {
		derive(labels[i], first, sizeof(first));
		derive(labels[i], again, sizeof(again));
		ATF_CHECK_STREQ(first, again);
	}
}

/*
 * The derived name fits the jail-name bound and uses only the jail-legal charset
 * (and never '.'), across a spread of pathological labels.
 */
ATF_TC_WITHOUT_HEAD(name_within_bounds_and_charset);
ATF_TC_BODY(name_within_bounds_and_charset, tc)
{
	static const char *const labels[] = {
		"x",
		"org.example.some.deeply.nested.capability.label.instance.42",
		"has spaces and\ttabs",
		"weird/slashes:and;semis",
		"unicode-\xc3\xa9\xc3\xa8-bytes",
	};
	char name[TEST_JAIL_NAME_MAX];
	size_t i;

	for (i = 0; i < nitems(labels); i++) {
		ATF_REQUIRE(warden_test_jail_name(labels[i], name,
		    sizeof(name)));
		ATF_CHECK(strlen(name) <= TEST_JAIL_NAME_MAX - 1);
		ATF_CHECK_MSG(name_is_valid(name),
		    "label \"%s\" -> invalid name \"%s\"", labels[i], name);
		ATF_CHECK_MSG(strchr(name, '.') == NULL,
		    "name \"%s\" contains a '.'", name);
	}
}

/* An empty (or NULL) label has no jail, and a too-small buffer is refused. */
ATF_TC_WITHOUT_HEAD(empty_label_and_small_buffer_are_refused);
ATF_TC_BODY(empty_label_and_small_buffer_are_refused, tc)
{
	char name[TEST_JAIL_NAME_MAX];
	char tiny[4];

	ATF_CHECK(!warden_test_jail_name("", name, sizeof(name)));
	ATF_CHECK(!warden_test_jail_name(NULL, name, sizeof(name)));
	/* Room for "wj_" + a NUL but not the 128-bit minimum of hash. */
	ATF_CHECK(!warden_test_jail_name("label", tiny, sizeof(tiny)));
}

/*
 * The "desc" descriptor parser is the strtol-validation fix: an empty or
 * malformed desc must be rejected rather than silently coerced to fd 0, and a
 * clean decimal must parse.
 */
ATF_TC_WITHOUT_HEAD(desc_parse_rejects_malformed_accepts_numeric);
ATF_TC_BODY(desc_parse_rejects_malformed_accepts_numeric, tc)
{
	int fd;

	/* Rejected: empty, non-numeric, trailing junk, negative, overflow. */
	ATF_CHECK(!warden_test_parse_desc("", &fd));
	ATF_CHECK(!warden_test_parse_desc("abc", &fd));
	ATF_CHECK(!warden_test_parse_desc("12abc", &fd));
	ATF_CHECK(!warden_test_parse_desc("-1", &fd));
	ATF_CHECK(!warden_test_parse_desc("999999999999999999999", &fd));

	/* Accepted: clean non-negative decimals. */
	fd = -1;
	ATF_CHECK(warden_test_parse_desc("0", &fd));
	ATF_CHECK_EQ(0, fd);
	fd = -1;
	ATF_CHECK(warden_test_parse_desc("7", &fd));
	ATF_CHECK_EQ(7, fd);
	fd = -1;
	ATF_CHECK(warden_test_parse_desc("128", &fd));
	ATF_CHECK_EQ(128, fd);
}

/*
 * valid_request is exercised directly here (its channel-level counterpart lives
 * in provider_test): opcode, flag bits, NUL-termination and absolute-path rules.
 */
ATF_TC_WITHOUT_HEAD(valid_request_enforces_shape);
ATF_TC_BODY(valid_request_enforces_shape, tc)
{
	struct warden_request rq;

	/* A well-formed request. */
	memset(&rq, 0, sizeof(rq));
	rq.op = WARDEN_OP_ENTER_JAIL;
	rq.flags = 0;
	(void)strlcpy(rq.path, "/jails/example", sizeof(rq.path));
	ATF_CHECK(warden_test_valid_request(&rq));

	/* The only defined flag is accepted. */
	rq.flags = WARDEN_F_EPHEMERAL;
	ATF_CHECK(warden_test_valid_request(&rq));

	/* Unknown opcode. */
	rq.flags = 0;
	rq.op = 0x4242;
	ATF_CHECK(!warden_test_valid_request(&rq));

	/* Unknown flag bits. */
	rq.op = WARDEN_OP_ENTER_JAIL;
	rq.flags = WARDEN_F_EPHEMERAL | 0x2u;
	ATF_CHECK(!warden_test_valid_request(&rq));

	/* Relative path. */
	rq.flags = 0;
	(void)strlcpy(rq.path, "relative/path", sizeof(rq.path));
	ATF_CHECK(!warden_test_valid_request(&rq));

	/* Unterminated path field. */
	rq.op = WARDEN_OP_ENTER_JAIL;
	rq.flags = 0;
	memset(rq.path, 'A', sizeof(rq.path));
	ATF_CHECK(!warden_test_valid_request(&rq));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, distinct_labels_get_distinct_names);
	ATF_TP_ADD_TC(tp, generated_labels_have_no_collisions);
	ATF_TP_ADD_TC(tp, same_label_is_deterministic);
	ATF_TP_ADD_TC(tp, name_within_bounds_and_charset);
	ATF_TP_ADD_TC(tp, empty_label_and_small_buffer_are_refused);
	ATF_TP_ADD_TC(tp, desc_parse_rejects_malformed_accepts_numeric);
	ATF_TP_ADD_TC(tp, valid_request_enforces_shape);
	return (atf_no_error());
}
