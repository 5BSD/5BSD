/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * ELEVATE (docs/ipc-anointments-design.md "Elevation"), unit-tested through
 * the pure pieces the daemon factored out of handle_elevate(): the session
 * label gate (E5), the name validator, the may_elevate policy check (S6, P5,
 * P9), in-agent password verification against a master.passwd snapshot (P3,
 * P4), the per-uid failure limiter, and the session-set-plus-one composition
 * (E1).  No plane, no switchboard, no PAM: runs anywhere.
 */

#include <sys/param.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <libcapbundle.h>

#include "authagentd_test.h"

/* wheel == 0, operators == 500; nothing else resolves. */
static gid_t
groups(void *ctx __unused, const char *name)
{

	if (strcmp(name, "wheel") == 0)
		return (0);
	if (strcmp(name, "operators") == 0)
		return (500);
	return ((gid_t)-1);
}

static void
write_policy(char path[], size_t pathlen, const char *text)
{
	FILE *fp;
	int fd;

	strlcpy(path, "/tmp/authagent_elevate.XXXXXX", pathlen);
	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	fp = fdopen(fd, "w");
	ATF_REQUIRE(fp != NULL);
	ATF_REQUIRE(fputs(text, fp) >= 0);
	ATF_REQUIRE(fclose(fp) == 0);
}

/* Resolve `uid` (in `gids`) against the policy text into *g. */
static void
resolve(const char *policy, uid_t uid, const gid_t *gids, unsigned ngids,
    struct capbundle_principal_grant *g)
{
	char path[64];
	int fd;

	write_policy(path, sizeof(path), policy);
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(fd, uid, gids, ngids,
	    groups, NULL, g));
	(void)close(fd);
	(void)unlink(path);
}

#define	OPERATORS_POLICY \
	"principals {\n" \
	"  admin { groups = [\"wheel\"]; uids = [0]; anointments = [\"*\"];" \
	" admin_rights = true; }\n" \
	"  default { anointments = []; }\n" \
	"  operators { groups = [\"operators\"];" \
	" anointments = [\"system.trace.client\"];" \
	" may_elevate = [\"system.notify.system\"]; }\n" \
	"}\n"

/* ---- label gate (E5) ---------------------------------------------------- */

ATF_TC_WITHOUT_HEAD(label_session_allowed);
ATF_TC_BODY(label_session_allowed, tc)
{

	ATF_CHECK(authagent_elevate_caller_allowed("org.5bsd.user-session"));
	ATF_CHECK(authagent_elevate_caller_allowed(AUTHAGENT_SESSION_LABEL));
}

/* A unit's label -- any bundle label -- is refused: units declare. */
ATF_TC_WITHOUT_HEAD(label_unit_denied);
ATF_TC_BODY(label_unit_denied, tc)
{

	ATF_CHECK(!authagent_elevate_caller_allowed("com.example.pub"));
	ATF_CHECK(!authagent_elevate_caller_allowed("system.AuthAgent/authagentd"));
	ATF_CHECK(!authagent_elevate_caller_allowed("system.Switchboard"));
}

/* Fail closed: empty, NULL, or a near-miss of the session label. */
ATF_TC_WITHOUT_HEAD(label_fail_closed);
ATF_TC_BODY(label_fail_closed, tc)
{

	ATF_CHECK(!authagent_elevate_caller_allowed(""));
	ATF_CHECK(!authagent_elevate_caller_allowed(NULL));
	ATF_CHECK(!authagent_elevate_caller_allowed("org.5bsd.user-session "));
	ATF_CHECK(!authagent_elevate_caller_allowed("org.5bsd.user-sessio"));
	ATF_CHECK(!authagent_elevate_caller_allowed("ORG.5BSD.USER-SESSION"));
	ATF_CHECK(!authagent_elevate_caller_allowed("org.5bsd.user-session.x"));
}

/* ---- name validation ---------------------------------------------------- */

ATF_TC_WITHOUT_HEAD(name_valid);
ATF_TC_BODY(name_valid, tc)
{
	char longest[SERVICE_ANOINT_NAME_MAX];

	ATF_CHECK(authagent_valid_name("system.notify.system",
	    SERVICE_ANOINT_NAME_MAX));
	ATF_CHECK(authagent_valid_name("a.b", SERVICE_ANOINT_NAME_MAX));
	ATF_CHECK(authagent_valid_name("Org-1.Sub_2.x", SERVICE_ANOINT_NAME_MAX));
	/* Exactly maxlen - 1 characters is the longest legal name. */
	memset(longest, 'a', sizeof(longest));
	longest[1] = '.';
	longest[sizeof(longest) - 1] = '\0';
	ATF_CHECK(authagent_valid_name(longest, SERVICE_ANOINT_NAME_MAX));
}

/* "*" is a policy wildcard, never something a caller may request. */
ATF_TC_WITHOUT_HEAD(name_star_rejected);
ATF_TC_BODY(name_star_rejected, tc)
{

	ATF_CHECK(!authagent_valid_name("*", SERVICE_ANOINT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("system.*", SERVICE_ANOINT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("*.system", SERVICE_ANOINT_NAME_MAX));
}

ATF_TC_WITHOUT_HEAD(name_malformed_rejected);
ATF_TC_BODY(name_malformed_rejected, tc)
{
	char toolong[SERVICE_ANOINT_NAME_MAX + 1];

	ATF_CHECK(!authagent_valid_name(NULL, SERVICE_ANOINT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("", SERVICE_ANOINT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("nodot", SERVICE_ANOINT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name(".a.b", SERVICE_ANOINT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("a.b.", SERVICE_ANOINT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("a..b", SERVICE_ANOINT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("a/b.c", SERVICE_ANOINT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("a b.c", SERVICE_ANOINT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("a.b\n", SERVICE_ANOINT_NAME_MAX));
	/* maxlen characters (no room for the NUL within the bound). */
	memset(toolong, 'a', sizeof(toolong));
	toolong[1] = '.';
	toolong[sizeof(toolong) - 1] = '\0';
	ATF_CHECK(!authagent_valid_name(toolong, SERVICE_ANOINT_NAME_MAX));
}

/* ---- policy check (S6, P5, P9, `*`) ------------------------------------- */

/* S6: a default user may elevate nothing -> EPERM (before any password). */
ATF_TC_WITHOUT_HEAD(check_default_user_eperm);
ATF_TC_BODY(check_default_user_eperm, tc)
{
	struct capbundle_principal_grant g;
	gid_t gids[] = { 1001 };

	resolve(OPERATORS_POLICY, 1001, gids, 1, &g);
	ATF_CHECK_EQ(EPERM,
	    authagent_elevate_check(&g, "system.notify.system"));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "system.storage.admin"));
}

/* P3/P5: an operator may elevate the listed name and nothing else. */
ATF_TC_WITHOUT_HEAD(check_operator_listed_only);
ATF_TC_BODY(check_operator_listed_only, tc)
{
	struct capbundle_principal_grant g;
	gid_t gids[] = { 1002, 500 };

	resolve(OPERATORS_POLICY, 1002, gids, 2, &g);
	ATF_CHECK_EQ(0, authagent_elevate_check(&g, "system.notify.system"));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "system.storage.admin"));
	/* Already-held-from-login names are not thereby elevatable. */
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "system.trace.client"));
}

/*
 * The shipped default: admin holds "*" but has no may_elevate -- an admin
 * does not need to elevate, and the policy does not pretend otherwise.
 */
ATF_TC_WITHOUT_HEAD(check_shipped_admin_no_may_elevate);
ATF_TC_BODY(check_shipped_admin_no_may_elevate, tc)
{
	struct capbundle_principal_grant g;
	gid_t gids[] = { 0 };

	resolve(OPERATORS_POLICY, 0, gids, 1, &g);
	ATF_CHECK(g.anoint_all);
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "system.notify.system"));
}

/* P9 / P6: may_elevate = ["*"] honours every valid name. */
ATF_TC_WITHOUT_HEAD(check_star_honoured);
ATF_TC_BODY(check_star_honoured, tc)
{
	struct capbundle_principal_grant g;
	gid_t gids[] = { 0 };

	resolve("principals {\n"
	    "  admin { groups = [\"wheel\"]; anointments = [];"
	    " may_elevate = [\"*\"]; }\n"
	    "}\n", 42, gids, 1, &g);
	ATF_CHECK(g.elevate_all);
	ATF_CHECK(!g.anoint_all);
	ATF_CHECK_EQ(0U, g.nanointments);
	ATF_CHECK_EQ(0, authagent_elevate_check(&g, "system.notify.system"));
	ATF_CHECK_EQ(0, authagent_elevate_check(&g, "anything.at.all"));
	/* The strict-admin profile mints USER: nothing held until asked. */
	ATF_CHECK_EQ(SERVICE_MINT_USER, authagent_mint_kind_for_grant(&g));
}

/* P10: policy absent -> historical rule: nobody may elevate. */
ATF_TC_WITHOUT_HEAD(check_no_policy_nobody_elevates);
ATF_TC_BODY(check_no_policy_nobody_elevates, tc)
{
	struct capbundle_principal_grant g;
	gid_t root_gids[] = { 0 };
	gid_t user_gids[] = { 1001 };

	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(-1, 0, root_gids, 1,
	    groups, NULL, &g));
	ATF_CHECK(g.from_default_rule);
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "system.notify.system"));
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(-1, 1001, user_gids, 1,
	    groups, NULL, &g));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "system.notify.system"));
}

ATF_TC_WITHOUT_HEAD(check_null_fails_closed);
ATF_TC_BODY(check_null_fails_closed, tc)
{
	struct capbundle_principal_grant g;

	memset(&g, 0, sizeof(g));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(NULL, "a.b"));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, NULL));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "a.b"));
}

/* ---- password verification (P3, P4) ------------------------------------- */

/* Build a master.passwd snapshot with uid 1002's hash for `password`. */
static char *
masterpw_with(const char *password, const char *extra_lines)
{
	char *hash, *text;

	hash = crypt(password, "$6$elevatetestsalt$");
	ATF_REQUIRE(hash != NULL);
	ATF_REQUIRE(asprintf(&text,
	    "# comment line\n"
	    "root:*:0:0::0:0:Charlie &:/root:/bin/sh\n"
	    "%s"
	    "operator:%s:1002:500::0:0:Op:/home/op:/bin/sh\n"
	    "nopw::1003:1003::0:0:Empty:/home/nopw:/bin/sh\n"
	    "bang:!$6$x$y:1004:1004::0:0:Bang:/home/bang:/bin/sh\n"
	    "star:*LOCKED*:1005:1005::0:0:Star:/home/star:/bin/sh\n"
	    "capability:*:976:976::0:0:Capability:/nonexistent:/usr/sbin/nologin\n",
	    extra_lines, hash) > 0);
	return (text);
}

ATF_TC_WITHOUT_HEAD(password_correct);
ATF_TC_BODY(password_correct, tc)
{
	char *text;

	text = masterpw_with("correct horse", "");
	ATF_CHECK_EQ(0, authagent_verify_password(text, 1002, "correct horse"));
	free(text);
}

ATF_TC_WITHOUT_HEAD(password_wrong_eacces);
ATF_TC_BODY(password_wrong_eacces, tc)
{
	char *text;

	text = masterpw_with("correct horse", "");
	ATF_CHECK_EQ(EACCES,
	    authagent_verify_password(text, 1002, "battery staple"));
	free(text);
	text = masterpw_with("correct horse", "");
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 1002, ""));
	free(text);
	/* Case and prefix variants are not the password. */
	text = masterpw_with("correct horse", "");
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 1002, "Correct horse"));
	free(text);
	text = masterpw_with("correct horse", "");
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 1002, "correct hors"));
	free(text);
}

/* A locked ("*"- or "!"-prefixed) hash never authenticates: EPERM. */
ATF_TC_WITHOUT_HEAD(password_locked_eperm);
ATF_TC_BODY(password_locked_eperm, tc)
{
	char *text;

	text = masterpw_with("x", "");
	ATF_CHECK_EQ(EPERM, authagent_verify_password(text, 0, ""));
	free(text);
	text = masterpw_with("x", "");
	ATF_CHECK_EQ(EPERM, authagent_verify_password(text, 0, "*"));
	free(text);
	text = masterpw_with("x", "");
	ATF_CHECK_EQ(EPERM, authagent_verify_password(text, 1004, "y"));
	free(text);
	text = masterpw_with("x", "");
	ATF_CHECK_EQ(EPERM, authagent_verify_password(text, 1005, "*LOCKED*"));
	free(text);
	/* The capability user is locked; it can never elevate either. */
	text = masterpw_with("x", "");
	ATF_CHECK_EQ(EPERM, authagent_verify_password(text, 976, ""));
	free(text);
}

/* An empty hash is not "no password needed": EPERM, even for "". */
ATF_TC_WITHOUT_HEAD(password_empty_hash_eperm);
ATF_TC_BODY(password_empty_hash_eperm, tc)
{
	char *text;

	text = masterpw_with("x", "");
	ATF_CHECK_EQ(EPERM, authagent_verify_password(text, 1003, ""));
	free(text);
	text = masterpw_with("x", "");
	ATF_CHECK_EQ(EPERM, authagent_verify_password(text, 1003, "anything"));
	free(text);
}

ATF_TC_WITHOUT_HEAD(password_missing_uid_enoent);
ATF_TC_BODY(password_missing_uid_enoent, tc)
{
	char *text;

	text = masterpw_with("x", "");
	ATF_CHECK_EQ(ENOENT, authagent_verify_password(text, 4242, "x"));
	free(text);
	text = strdup("");
	ATF_CHECK_EQ(ENOENT, authagent_verify_password(text, 0, "x"));
	free(text);
}

/*
 * Malformed lines are skipped, never matched: a line whose uid field is not
 * a number, a truncated line, a uid with a sign, and a line whose hash field
 * would match uid 1002 but whose uid is spelled "+1002".
 */
ATF_TC_WITHOUT_HEAD(password_malformed_lines_skipped);
ATF_TC_BODY(password_malformed_lines_skipped, tc)
{
	char *hash, *text, *extra;

	hash = crypt("attacker", "$6$elevatetestsalt$");
	ATF_REQUIRE(hash != NULL);
	ATF_REQUIRE(asprintf(&extra,
	    "junk\n"
	    ":%s:1002:500::0:0:noname:/:/bin/sh\n"	/* empty name */
	    "plus:%s:+1002:500::0:0:x:/:/bin/sh\n"	/* signed uid */
	    "trunc:%s\n"					/* no uid field */
	    "space:%s:1002 :500::0:0:x:/:/bin/sh\n"	/* trailing space */
	    "huge:%s:99999999999999999999:500::0:0:x:/:/bin/sh\n",
	    hash, hash, hash, hash, hash) > 0);
	text = masterpw_with("correct horse", extra);
	/* The attacker's hash never became uid 1002's. */
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 1002, "attacker"));
	free(text);
	text = masterpw_with("correct horse", extra);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 1002, "correct horse"));
	free(text);
	free(extra);
}

/* The first record for a uid wins, as getpwuid(3) would. */
ATF_TC_WITHOUT_HEAD(password_first_record_wins);
ATF_TC_BODY(password_first_record_wins, tc)
{
	char *hash, *text, *extra;

	hash = crypt("first", "$6$elevatetestsalt$");
	ATF_REQUIRE(hash != NULL);
	ATF_REQUIRE(asprintf(&extra,
	    "dup:%s:1002:500::0:0:x:/:/bin/sh\n", hash) > 0);
	text = masterpw_with("second", extra);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 1002, "first"));
	free(text);
	text = masterpw_with("second", extra);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 1002, "second"));
	free(text);
	free(extra);
}

/*
 * The compare is length-checked and constant-time: a stored hash that is a
 * strict prefix of (or extends) the computed one never matches, so a memcmp
 * over the shorter length could not be fooled either.
 */
ATF_TC_WITHOUT_HEAD(password_length_mismatch_never_matches);
ATF_TC_BODY(password_length_mismatch_never_matches, tc)
{
	char *hash, *text;

	hash = crypt("pw", "$6$elevatetestsalt$");
	ATF_REQUIRE(hash != NULL);
	ATF_REQUIRE(strlen(hash) > 10);
	/* Truncated stored hash. */
	ATF_REQUIRE(asprintf(&text, "u:%.*s:7:7::0:0:x:/:/bin/sh\n",
	    (int)strlen(hash) - 1, hash) > 0);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, "pw"));
	free(text);
	/* Extended stored hash. */
	ATF_REQUIRE(asprintf(&text, "u:%sX:7:7::0:0:x:/:/bin/sh\n",
	    hash) > 0);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, "pw"));
	free(text);
}

ATF_TC_WITHOUT_HEAD(password_null_einval);
ATF_TC_BODY(password_null_einval, tc)
{
	char text[] = "u:x:7:7::0:0:x:/:/bin/sh\n";

	ATF_CHECK_EQ(EINVAL, authagent_verify_password(NULL, 7, "pw"));
	ATF_CHECK_EQ(EINVAL, authagent_verify_password(text, 7, NULL));
}

/* ---- rate limiter --------------------------------------------------------- */

ATF_TC_WITHOUT_HEAD(ratelimit_five_failures_block);
ATF_TC_BODY(ratelimit_five_failures_block, tc)
{
	struct authagent_ratelimit rl;
	unsigned i;

	memset(&rl, 0, sizeof(rl));
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1002, 100));
	for (i = 0; i < AUTHAGENT_RL_MAX_FAILURES - 1; i++) {
		authagent_ratelimit_failure(&rl, 1002, 100 + i);
		ATF_CHECK_MSG(!authagent_ratelimit_blocked(&rl, 1002, 100 + i),
		    "blocked after only %u failures", i + 1);
	}
	authagent_ratelimit_failure(&rl, 1002, 110);
	ATF_CHECK(authagent_ratelimit_blocked(&rl, 1002, 110));
	ATF_CHECK(authagent_ratelimit_blocked(&rl, 1002, 159));
	/* Other uids are unaffected. */
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1003, 110));
}

/* The block expires AUTHAGENT_RL_WINDOW_SEC after the FIRST failure. */
ATF_TC_WITHOUT_HEAD(ratelimit_window_expires);
ATF_TC_BODY(ratelimit_window_expires, tc)
{
	struct authagent_ratelimit rl;
	unsigned i;

	memset(&rl, 0, sizeof(rl));
	for (i = 0; i < AUTHAGENT_RL_MAX_FAILURES; i++)
		authagent_ratelimit_failure(&rl, 1002, 100 + i);
	ATF_CHECK(authagent_ratelimit_blocked(&rl, 1002,
	    100 + AUTHAGENT_RL_WINDOW_SEC - 1));
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1002,
	    100 + AUTHAGENT_RL_WINDOW_SEC));
	/* And the counter restarted: one more failure does not re-block. */
	authagent_ratelimit_failure(&rl, 1002, 100 + AUTHAGENT_RL_WINDOW_SEC);
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1002,
	    101 + AUTHAGENT_RL_WINDOW_SEC));
}

/* Failures spread wider than the window never accumulate to a block. */
ATF_TC_WITHOUT_HEAD(ratelimit_slow_failures_never_block);
ATF_TC_BODY(ratelimit_slow_failures_never_block, tc)
{
	struct authagent_ratelimit rl;
	unsigned i;

	memset(&rl, 0, sizeof(rl));
	for (i = 0; i < 20; i++) {
		time_t t = 100 + (time_t)i * AUTHAGENT_RL_WINDOW_SEC;

		ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1002, t));
		authagent_ratelimit_failure(&rl, 1002, t);
	}
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1002,
	    100 + 20 * AUTHAGENT_RL_WINDOW_SEC));
}

ATF_TC_WITHOUT_HEAD(ratelimit_success_resets);
ATF_TC_BODY(ratelimit_success_resets, tc)
{
	struct authagent_ratelimit rl;
	unsigned i;

	memset(&rl, 0, sizeof(rl));
	for (i = 0; i < AUTHAGENT_RL_MAX_FAILURES - 1; i++)
		authagent_ratelimit_failure(&rl, 1002, 100);
	authagent_ratelimit_success(&rl, 1002);
	for (i = 0; i < AUTHAGENT_RL_MAX_FAILURES - 1; i++) {
		authagent_ratelimit_failure(&rl, 1002, 101);
		ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1002, 101));
	}
	/* Resetting an unknown uid is harmless. */
	authagent_ratelimit_success(&rl, 9999);
	authagent_ratelimit_success(NULL, 9999);
}

/* More distinct uids than slots: the table recycles and still blocks. */
ATF_TC_WITHOUT_HEAD(ratelimit_slot_exhaustion);
ATF_TC_BODY(ratelimit_slot_exhaustion, tc)
{
	struct authagent_ratelimit rl;
	unsigned i, u;

	memset(&rl, 0, sizeof(rl));
	for (u = 0; u < AUTHAGENT_RL_SLOTS + 8; u++)
		authagent_ratelimit_failure(&rl, 5000 + u, 100 + u);
	/* The newest uid is tracked; drive it to the limit. */
	u = 5000 + AUTHAGENT_RL_SLOTS + 7;
	for (i = 1; i < AUTHAGENT_RL_MAX_FAILURES; i++)
		authagent_ratelimit_failure(&rl, u, 200);
	ATF_CHECK(authagent_ratelimit_blocked(&rl, u, 200));
	/* A recycled (oldest) uid simply starts over. */
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 5000, 200));
}

/* A clock that steps backwards is treated as expiry, never as a lockout. */
ATF_TC_WITHOUT_HEAD(ratelimit_clock_backwards);
ATF_TC_BODY(ratelimit_clock_backwards, tc)
{
	struct authagent_ratelimit rl;
	unsigned i;

	memset(&rl, 0, sizeof(rl));
	for (i = 0; i < AUTHAGENT_RL_MAX_FAILURES; i++)
		authagent_ratelimit_failure(&rl, 1002, 1000);
	ATF_CHECK(authagent_ratelimit_blocked(&rl, 1002, 1000));
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1002, 900));
	ATF_CHECK(!authagent_ratelimit_blocked(NULL, 1002, 1000));
}

/* ---- session-set-plus-one (E1) ------------------------------------------ */

ATF_TC_WITHOUT_HEAD(compose_appends_name);
ATF_TC_BODY(compose_appends_name, tc)
{
	struct capbundle_principal_grant g;
	char out[SERVICE_ANOINT_MAX][SERVICE_ANOINT_NAME_MAX];
	gid_t gids[] = { 1002, 500 };
	unsigned n;
	bool all;

	resolve(OPERATORS_POLICY, 1002, gids, 2, &g);
	ATF_REQUIRE_EQ(0, authagent_compose_set(&g, "system.notify.system",
	    out, nitems(out), &n, &all));
	ATF_CHECK(!all);
	ATF_REQUIRE_EQ(2U, n);
	ATF_CHECK_STREQ("system.trace.client", out[0]);
	ATF_CHECK_STREQ("system.notify.system", out[1]);
}

/* An empty session set plus one is exactly one. */
ATF_TC_WITHOUT_HEAD(compose_from_empty);
ATF_TC_BODY(compose_from_empty, tc)
{
	struct capbundle_principal_grant g;
	char out[SERVICE_ANOINT_MAX][SERVICE_ANOINT_NAME_MAX];
	unsigned n;
	bool all;

	memset(&g, 0, sizeof(g));
	ATF_REQUIRE_EQ(0, authagent_compose_set(&g, "a.one", out, nitems(out),
	    &n, &all));
	ATF_CHECK(!all);
	ATF_REQUIRE_EQ(1U, n);
	ATF_CHECK_STREQ("a.one", out[0]);
}

/* A name already held is not duplicated. */
ATF_TC_WITHOUT_HEAD(compose_dedupes);
ATF_TC_BODY(compose_dedupes, tc)
{
	struct capbundle_principal_grant g;
	char out[SERVICE_ANOINT_MAX][SERVICE_ANOINT_NAME_MAX];
	gid_t gids[] = { 1002, 500 };
	unsigned n;
	bool all;

	resolve(OPERATORS_POLICY, 1002, gids, 2, &g);
	ATF_REQUIRE_EQ(0, authagent_compose_set(&g, "system.trace.client",
	    out, nitems(out), &n, &all));
	ATF_CHECK(!all);
	ATF_REQUIRE_EQ(1U, n);
	ATF_CHECK_STREQ("system.trace.client", out[0]);
}

/* "*" held from login: the result is still "all", with an empty list. */
ATF_TC_WITHOUT_HEAD(compose_star_stays_all);
ATF_TC_BODY(compose_star_stays_all, tc)
{
	struct capbundle_principal_grant g;
	char out[SERVICE_ANOINT_MAX][SERVICE_ANOINT_NAME_MAX];
	gid_t gids[] = { 0 };
	unsigned n;
	bool all;

	resolve(OPERATORS_POLICY, 0, gids, 1, &g);
	ATF_REQUIRE_EQ(0, authagent_compose_set(&g, "system.notify.system",
	    out, nitems(out), &n, &all));
	ATF_CHECK(all);
	ATF_CHECK_EQ(0U, n);
}

/* A full set plus a new name is E2BIG; plus a held name is fine. */
ATF_TC_WITHOUT_HEAD(compose_full_e2big);
ATF_TC_BODY(compose_full_e2big, tc)
{
	struct capbundle_principal_grant g;
	char out[SERVICE_ANOINT_MAX][SERVICE_ANOINT_NAME_MAX];
	unsigned i, n;
	bool all;

	memset(&g, 0, sizeof(g));
	for (i = 0; i < CAPBUNDLE_PRINCIPAL_MAX_NAMES; i++)
		snprintf(g.anointments[i], sizeof(g.anointments[i]),
		    "held.name%u", i);
	g.nanointments = CAPBUNDLE_PRINCIPAL_MAX_NAMES;
	ATF_CHECK_EQ(E2BIG, authagent_compose_set(&g, "new.name", out,
	    nitems(out), &n, &all));
	ATF_REQUIRE_EQ(0, authagent_compose_set(&g, "held.name31", out,
	    nitems(out), &n, &all));
	ATF_CHECK_EQ((unsigned)CAPBUNDLE_PRINCIPAL_MAX_NAMES, n);
	ATF_CHECK(!all);
	/* One short of full accepts exactly one more. */
	g.nanointments = CAPBUNDLE_PRINCIPAL_MAX_NAMES - 1;
	ATF_REQUIRE_EQ(0, authagent_compose_set(&g, "new.name", out,
	    nitems(out), &n, &all));
	ATF_CHECK_EQ((unsigned)CAPBUNDLE_PRINCIPAL_MAX_NAMES, n);
	ATF_CHECK_STREQ("new.name", out[CAPBUNDLE_PRINCIPAL_MAX_NAMES - 1]);
}

ATF_TC_WITHOUT_HEAD(compose_einval);
ATF_TC_BODY(compose_einval, tc)
{
	struct capbundle_principal_grant g;
	char out[SERVICE_ANOINT_MAX][SERVICE_ANOINT_NAME_MAX];
	unsigned n;
	bool all;

	memset(&g, 0, sizeof(g));
	ATF_CHECK_EQ(EINVAL, authagent_compose_set(NULL, "a.b", out,
	    nitems(out), &n, &all));
	ATF_CHECK_EQ(EINVAL, authagent_compose_set(&g, NULL, out, nitems(out),
	    &n, &all));
	ATF_CHECK_EQ(EINVAL, authagent_compose_set(&g, "a.b", NULL,
	    nitems(out), &n, &all));
	ATF_CHECK_EQ(EINVAL, authagent_compose_set(&g, "a.b", out,
	    nitems(out), NULL, &all));
	ATF_CHECK_EQ(EINVAL, authagent_compose_set(&g, "a.b", out,
	    nitems(out), &n, NULL));
	/* A grant claiming more names than the output holds is refused. */
	g.nanointments = SERVICE_ANOINT_MAX + 1;
	ATF_CHECK_EQ(EINVAL, authagent_compose_set(&g, "a.b", out,
	    nitems(out), &n, &all));
}

/* ---- kind for an elevated channel ---------------------------------------- */

/* Elevation never changes the kind: an operator elevates on a USER channel. */
ATF_TC_WITHOUT_HEAD(kind_unchanged_by_elevation);
ATF_TC_BODY(kind_unchanged_by_elevation, tc)
{
	struct capbundle_principal_grant g;
	gid_t gids[] = { 1002, 500 };

	resolve(OPERATORS_POLICY, 1002, gids, 2, &g);
	ATF_CHECK_EQ(SERVICE_MINT_USER, authagent_mint_kind_for_grant(&g));
	ATF_CHECK(!g.admin_rights);
	ATF_CHECK_EQ(SERVICE_MINT_USER, authagent_mint_kind_for_grant(NULL));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, label_session_allowed);
	ATF_TP_ADD_TC(tp, label_unit_denied);
	ATF_TP_ADD_TC(tp, label_fail_closed);
	ATF_TP_ADD_TC(tp, name_valid);
	ATF_TP_ADD_TC(tp, name_star_rejected);
	ATF_TP_ADD_TC(tp, name_malformed_rejected);
	ATF_TP_ADD_TC(tp, check_default_user_eperm);
	ATF_TP_ADD_TC(tp, check_operator_listed_only);
	ATF_TP_ADD_TC(tp, check_shipped_admin_no_may_elevate);
	ATF_TP_ADD_TC(tp, check_star_honoured);
	ATF_TP_ADD_TC(tp, check_no_policy_nobody_elevates);
	ATF_TP_ADD_TC(tp, check_null_fails_closed);
	ATF_TP_ADD_TC(tp, password_correct);
	ATF_TP_ADD_TC(tp, password_wrong_eacces);
	ATF_TP_ADD_TC(tp, password_locked_eperm);
	ATF_TP_ADD_TC(tp, password_empty_hash_eperm);
	ATF_TP_ADD_TC(tp, password_missing_uid_enoent);
	ATF_TP_ADD_TC(tp, password_malformed_lines_skipped);
	ATF_TP_ADD_TC(tp, password_first_record_wins);
	ATF_TP_ADD_TC(tp, password_length_mismatch_never_matches);
	ATF_TP_ADD_TC(tp, password_null_einval);
	ATF_TP_ADD_TC(tp, ratelimit_five_failures_block);
	ATF_TP_ADD_TC(tp, ratelimit_window_expires);
	ATF_TP_ADD_TC(tp, ratelimit_slow_failures_never_block);
	ATF_TP_ADD_TC(tp, ratelimit_success_resets);
	ATF_TP_ADD_TC(tp, ratelimit_slot_exhaustion);
	ATF_TP_ADD_TC(tp, ratelimit_clock_backwards);
	ATF_TP_ADD_TC(tp, compose_appends_name);
	ATF_TP_ADD_TC(tp, compose_from_empty);
	ATF_TP_ADD_TC(tp, compose_dedupes);
	ATF_TP_ADD_TC(tp, compose_star_stays_all);
	ATF_TP_ADD_TC(tp, compose_full_e2big);
	ATF_TP_ADD_TC(tp, compose_einval);
	ATF_TP_ADD_TC(tp, kind_unchanged_by_elevation);
	return (atf_no_error());
}
