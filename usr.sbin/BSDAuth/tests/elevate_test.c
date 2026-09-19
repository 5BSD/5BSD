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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <libcapbundle.h>

#include <authagent_proto.h>

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
	ATF_CHECK(!authagent_elevate_caller_allowed("system.Auth/authagentd"));
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

/* ======================================================================
 * Edge-case and negative additions.  One decision per case so a report
 * names the exact boundary that moved.
 * ====================================================================== */

/* ---- names: boundaries and syntax ---------------------------------------- */

/* "a." followed by (len - 2) 'a's: a syntactically valid name of `len`. */
static void
fill_name(char *buf, size_t bufsz, size_t len)
{

	ATF_REQUIRE(len + 1 <= bufsz);
	memset(buf, 'a', len);
	buf[1] = '.';
	buf[len] = '\0';
}

/* 63 characters is the longest name; 64 (== AUTHAGENT_NAME_MAX) is not. */
ATF_TC_WITHOUT_HEAD(name_len_63_ok_64_invalid);
ATF_TC_BODY(name_len_63_ok_64_invalid, tc)
{
	char buf[AUTHAGENT_NAME_MAX + 8];

	ATF_REQUIRE_EQ(64, AUTHAGENT_NAME_MAX);
	fill_name(buf, sizeof(buf), 63);
	ATF_CHECK(authagent_valid_name(buf, AUTHAGENT_NAME_MAX));
	fill_name(buf, sizeof(buf), 64);
	ATF_CHECK(!authagent_valid_name(buf, AUTHAGENT_NAME_MAX));
	fill_name(buf, sizeof(buf), 65);
	ATF_CHECK(!authagent_valid_name(buf, AUTHAGENT_NAME_MAX));
	/* The wire form of an unterminated name: 64 non-NUL bytes. */
	memset(buf, 'a', sizeof(buf));
	buf[1] = '.';
	ATF_CHECK(!authagent_valid_name(buf, AUTHAGENT_NAME_MAX));
	/* maxlen is honoured as a bound, not a hint. */
	ATF_CHECK(authagent_valid_name("a.b", 4));
	ATF_CHECK(!authagent_valid_name("a.bc", 4));
	ATF_CHECK(!authagent_valid_name("a.b", 0));
}

/* Names are case-sensitive: uppercase is legal and distinct. */
ATF_TC_WITHOUT_HEAD(name_uppercase_case_sensitive);
ATF_TC_BODY(name_uppercase_case_sensitive, tc)
{
	struct capbundle_principal_grant g;

	ATF_CHECK(authagent_valid_name("System.Notify.System",
	    AUTHAGENT_NAME_MAX));
	ATF_CHECK(authagent_valid_name("SYSTEM.NOTIFY", AUTHAGENT_NAME_MAX));
	/* ...and the policy match is exact, so the case must agree. */
	memset(&g, 0, sizeof(g));
	strlcpy(g.may_elevate[0], "system.notify.system",
	    sizeof(g.may_elevate[0]));
	g.nmay_elevate = 1;
	ATF_CHECK_EQ(0, authagent_elevate_check(&g, "system.notify.system"));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "System.Notify.System"));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "SYSTEM.NOTIFY.SYSTEM"));
}

ATF_TC_WITHOUT_HEAD(name_leading_dot_invalid);
ATF_TC_BODY(name_leading_dot_invalid, tc)
{

	ATF_CHECK(!authagent_valid_name(".system.notify", AUTHAGENT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name(".", AUTHAGENT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name(".a", AUTHAGENT_NAME_MAX));
}

ATF_TC_WITHOUT_HEAD(name_trailing_dot_invalid);
ATF_TC_BODY(name_trailing_dot_invalid, tc)
{

	ATF_CHECK(!authagent_valid_name("system.notify.", AUTHAGENT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("a.", AUTHAGENT_NAME_MAX));
}

ATF_TC_WITHOUT_HEAD(name_double_dot_invalid);
ATF_TC_BODY(name_double_dot_invalid, tc)
{

	ATF_CHECK(!authagent_valid_name("..", AUTHAGENT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("a..b", AUTHAGENT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("system..notify.x", AUTHAGENT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("a...b", AUTHAGENT_NAME_MAX));
}

ATF_TC_WITHOUT_HEAD(name_star_invalid);
ATF_TC_BODY(name_star_invalid, tc)
{

	ATF_CHECK(!authagent_valid_name("*", AUTHAGENT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("**", AUTHAGENT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("*.*", AUTHAGENT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("a.*.b", AUTHAGENT_NAME_MAX));
}

ATF_TC_WITHOUT_HEAD(name_system_star_invalid);
ATF_TC_BODY(name_system_star_invalid, tc)
{

	ATF_CHECK(!authagent_valid_name("system.*", AUTHAGENT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("system.notify.*", AUTHAGENT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("system.notify*", AUTHAGENT_NAME_MAX));
}

ATF_TC_WITHOUT_HEAD(name_empty_invalid);
ATF_TC_BODY(name_empty_invalid, tc)
{

	ATF_CHECK(!authagent_valid_name("", AUTHAGENT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("", 1));
}

ATF_TC_WITHOUT_HEAD(name_single_segment_invalid);
ATF_TC_BODY(name_single_segment_invalid, tc)
{

	ATF_CHECK(!authagent_valid_name("system", AUTHAGENT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("a", AUTHAGENT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("root", AUTHAGENT_NAME_MAX));
	ATF_CHECK(!authagent_valid_name("system-notify_x", AUTHAGENT_NAME_MAX));
}

/* Every byte outside [A-Za-z0-9._-] is refused, including high bytes. */
ATF_TC_WITHOUT_HEAD(name_bad_bytes_invalid);
ATF_TC_BODY(name_bad_bytes_invalid, tc)
{
	static const char *const bad[] = {
		"a.b c", "a.b/c", "a.b\\c", "a.b:c", "a.b@c", "a.b+c", "a.b,c",
		"a.b;c", "a.b=c", "a.b!c", "a.b?c", "a.b#c", "a.b$c", "a.b%c",
		"a.b\tc", "a.b\rc", "a.b\x7f", "a.b\xc3\xa9", "a.b\xff",
		"\"a.b\"", "'a.b'", "a.b\x01",
	};
	unsigned i;

	for (i = 0; i < nitems(bad); i++)
		ATF_CHECK_MSG(!authagent_valid_name(bad[i], AUTHAGENT_NAME_MAX),
		    "accepted bad name #%u", i);
	/* The legal punctuation, at every position it may appear. */
	ATF_CHECK(authagent_valid_name("-a.b-", AUTHAGENT_NAME_MAX));
	ATF_CHECK(authagent_valid_name("_a.b_", AUTHAGENT_NAME_MAX));
	ATF_CHECK(authagent_valid_name("0.1", AUTHAGENT_NAME_MAX));
	ATF_CHECK(authagent_valid_name("-.-", AUTHAGENT_NAME_MAX));
}

/* ---- password boundaries ------------------------------------------------ */

/* Build one record for uid 7 whose hash is crypt(password, salt). */
static char *
record_for(uid_t uid, const char *password, const char *salt)
{
	char *hash, *text;

	hash = crypt(password, salt);
	ATF_REQUIRE_MSG(hash != NULL, "crypt(%s) failed", salt);
	ATF_REQUIRE(asprintf(&text, "u:%s:%u:7::0:0:x:/:/bin/sh\n", hash,
	    (unsigned)uid) > 0);
	return (text);
}

#define	SHA512_SALT	"$6$elevatetestsalt$"

/* 255 characters (the longest the wire carries) verify against their hash. */
ATF_TC_WITHOUT_HEAD(password_255_chars_ok);
ATF_TC_BODY(password_255_chars_ok, tc)
{
	char pw[AUTHAGENT_PASSWORD_MAX + 1];
	char *text;

	ATF_REQUIRE_EQ(256, AUTHAGENT_PASSWORD_MAX);
	memset(pw, 'p', sizeof(pw));
	pw[255] = '\0';
	text = record_for(7, pw, SHA512_SALT);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, pw));
	free(text);
	/* One char shorter is a different password. */
	text = record_for(7, pw, SHA512_SALT);
	pw[254] = '\0';
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, pw));
	free(text);
}

/*
 * A 256-character password is never silently truncated to the 255 the wire
 * carries: against a 255-character hash it is a mismatch.  (The wire form,
 * 256 bytes without a NUL, is refused by the request validator before this
 * function runs -- provider_test elevate_unterminated_password_is_einval.)
 */
ATF_TC_WITHOUT_HEAD(password_256_not_truncated_to_255);
ATF_TC_BODY(password_256_not_truncated_to_255, tc)
{
	char pw255[AUTHAGENT_PASSWORD_MAX];
	char pw256[AUTHAGENT_PASSWORD_MAX + 1];
	char *text;

	memset(pw255, 'p', sizeof(pw255));
	pw255[255] = '\0';
	memset(pw256, 'p', sizeof(pw256));
	pw256[256] = '\0';
	text = record_for(7, pw255, SHA512_SALT);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, pw256));
	free(text);
	/* And the reverse: a 256-char hash does not accept its 255 prefix. */
	text = record_for(7, pw256, SHA512_SALT);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, pw255));
	free(text);
	text = record_for(7, pw256, SHA512_SALT);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, pw256));
	free(text);
}

/*
 * An EMPTY HASH refuses even an empty password (EPERM: the account cannot
 * authenticate).  A REAL HASH OF "" is a different thing: it is a password,
 * it happens to be empty, and "" verifies against it -- exactly as login(1)
 * would.  This case pins the distinction.
 */
ATF_TC_WITHOUT_HEAD(password_empty_vs_hash_of_empty);
ATF_TC_BODY(password_empty_vs_hash_of_empty, tc)
{
	char *text;

	text = strdup("u::7:7::0:0:x:/:/bin/sh\n");
	ATF_CHECK_EQ(EPERM, authagent_verify_password(text, 7, ""));
	free(text);
	text = record_for(7, "", SHA512_SALT);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, ""));
	free(text);
	text = record_for(7, "", SHA512_SALT);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, " "));
	free(text);
	text = record_for(7, "", SHA512_SALT);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, "x"));
	free(text);
}

/* ---- master.passwd parsing ---------------------------------------------- */

/*
 * The parser needs only name:hash:uid; a record with fewer than the ten
 * canonical fields still supplies a hash (implemented behaviour, pinned).
 * A record with no uid field at all is skipped.
 */
ATF_TC_WITHOUT_HEAD(masterpw_short_line);
ATF_TC_BODY(masterpw_short_line, tc)
{
	char *hash, *text;

	/* strdup: verify_password calls crypt(3), which reuses the static buffer. */
	hash = strdup(crypt("pw", SHA512_SALT));
	ATF_REQUIRE(hash != NULL);
	/* Three fields: matches. */
	ATF_REQUIRE(asprintf(&text, "u:%s:7\n", hash) > 0);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, "pw"));
	free(text);
	ATF_REQUIRE(asprintf(&text, "u:%s:7\n", hash) > 0);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, "no"));
	free(text);
	/* Three fields, no newline. */
	ATF_REQUIRE(asprintf(&text, "u:%s:7", hash) > 0);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, "pw"));
	free(text);
	/* Two fields (no uid): skipped -> ENOENT. */
	ATF_REQUIRE(asprintf(&text, "u:%s\n", hash) > 0);
	ATF_CHECK_EQ(ENOENT, authagent_verify_password(text, 7, "pw"));
	free(text);
	/* Two fields with a trailing colon: empty uid field -> skipped. */
	ATF_REQUIRE(asprintf(&text, "u:%s:\n", hash) > 0);
	ATF_CHECK_EQ(ENOENT, authagent_verify_password(text, 7, "pw"));
	free(text);
	/* One field. */
	text = strdup("u\n");
	ATF_CHECK_EQ(ENOENT, authagent_verify_password(text, 7, "pw"));
	free(text);
	free(hash);
}

/* Fields beyond the tenth are ignored; the record still matches. */
ATF_TC_WITHOUT_HEAD(masterpw_extra_fields_ignored);
ATF_TC_BODY(masterpw_extra_fields_ignored, tc)
{
	char *hash, *text;

	/* strdup: verify_password calls crypt(3), which reuses the static buffer. */
	hash = strdup(crypt("pw", SHA512_SALT));
	ATF_REQUIRE(hash != NULL);
	ATF_REQUIRE(asprintf(&text,
	    "u:%s:7:7::0:0:x:/:/bin/sh:extra:more:7:7\n", hash) > 0);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, "pw"));
	free(text);
	/* Colons inside gecos do not shift the uid field. */
	ATF_REQUIRE(asprintf(&text,
	    "u:%s:7:7::0:0:Name: with: colons:/:/bin/sh\n", hash) > 0);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, "pw"));
	free(text);
	free(hash);
}

/* Duplicate uid: the first record wins, even when it is the locked one. */
ATF_TC_WITHOUT_HEAD(masterpw_duplicate_uid_first_wins);
ATF_TC_BODY(masterpw_duplicate_uid_first_wins, tc)
{
	char *hash, *text;

	/* strdup: verify_password calls crypt(3), which reuses the static buffer. */
	hash = strdup(crypt("pw", SHA512_SALT));
	ATF_REQUIRE(hash != NULL);
	/* Locked first, valid second: locked wins (EPERM). */
	ATF_REQUIRE(asprintf(&text,
	    "a:*:7:7::0:0:x:/:/bin/sh\n"
	    "b:%s:7:7::0:0:x:/:/bin/sh\n", hash) > 0);
	ATF_CHECK_EQ(EPERM, authagent_verify_password(text, 7, "pw"));
	free(text);
	/* Valid first, locked second: valid wins. */
	ATF_REQUIRE(asprintf(&text,
	    "b:%s:7:7::0:0:x:/:/bin/sh\n"
	    "a:*:7:7::0:0:x:/:/bin/sh\n", hash) > 0);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, "pw"));
	free(text);
	/* Different names, same uid: still first-wins by position. */
	ATF_REQUIRE(asprintf(&text,
	    "zzz:%s:7:7::0:0:x:/:/bin/sh\n"
	    "aaa:*:7:7::0:0:x:/:/bin/sh\n", hash) > 0);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, "pw"));
	free(text);
	free(hash);
}

ATF_TC_WITHOUT_HEAD(masterpw_uid_absent_enoent);
ATF_TC_BODY(masterpw_uid_absent_enoent, tc)
{
	char *hash, *text;

	/* strdup: verify_password calls crypt(3), which reuses the static buffer. */
	hash = strdup(crypt("pw", SHA512_SALT));
	ATF_REQUIRE(hash != NULL);
	ATF_REQUIRE(asprintf(&text,
	    "root:*:0:0::0:0:x:/:/bin/sh\n"
	    "u:%s:7:7::0:0:x:/:/bin/sh\n"
	    "v:%s:8:8::0:0:x:/:/bin/sh\n", hash, hash) > 0);
	ATF_CHECK_EQ(ENOENT, authagent_verify_password(text, 6, "pw"));
	free(text);
	ATF_REQUIRE(asprintf(&text, "u:%s:7:7::0:0:x:/:/bin/sh\n", hash) > 0);
	ATF_CHECK_EQ(ENOENT, authagent_verify_password(text, 70, "pw"));
	free(text);
	ATF_REQUIRE(asprintf(&text, "u:%s:7:7::0:0:x:/:/bin/sh\n", hash) > 0);
	ATF_CHECK_EQ(ENOENT, authagent_verify_password(text, UINT32_MAX, "pw"));
	free(text);
	/* A snapshot of only comments and blanks. */
	text = strdup("# nothing\n\n\n#\n");
	ATF_CHECK_EQ(ENOENT, authagent_verify_password(text, 7, "pw"));
	free(text);
	free(hash);
}

/* Comment and blank lines are skipped even when they look like records. */
ATF_TC_WITHOUT_HEAD(masterpw_comments_and_blanks_skipped);
ATF_TC_BODY(masterpw_comments_and_blanks_skipped, tc)
{
	char *hash, *text;

	/* strdup: verify_password calls crypt(3), which reuses the static buffer. */
	hash = strdup(crypt("pw", SHA512_SALT));
	ATF_REQUIRE(hash != NULL);
	/* The only record for uid 7 is commented out. */
	ATF_REQUIRE(asprintf(&text,
	    "\n"
	    "#u:%s:7:7::0:0:x:/:/bin/sh\n"
	    "\n\n"
	    "# u:%s:7:7::0:0:x:/:/bin/sh\n"
	    "\n", hash, hash) > 0);
	ATF_CHECK_EQ(ENOENT, authagent_verify_password(text, 7, "pw"));
	free(text);
	/* Blank and comment lines between records do not hide a record. */
	ATF_REQUIRE(asprintf(&text,
	    "\n\n# header\n\nroot:*:0:0::0:0:x:/:/bin/sh\n\n#\n"
	    "u:%s:7:7::0:0:x:/:/bin/sh\n\n", hash) > 0);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, "pw"));
	free(text);
	/* A comment record whose uid matches is never a match for its hash. */
	ATF_REQUIRE(asprintf(&text,
	    "#u:%s:7:7::0:0:x:/:/bin/sh\n"
	    "u:*:7:7::0:0:x:/:/bin/sh\n", hash) > 0);
	ATF_CHECK_EQ(EPERM, authagent_verify_password(text, 7, "pw"));
	free(text);
	free(hash);
}

/* "10" must not match uid 100, 1, 1000, or 010-style spellings. */
ATF_TC_WITHOUT_HEAD(masterpw_uid_prefix_no_match);
ATF_TC_BODY(masterpw_uid_prefix_no_match, tc)
{
	char *h10, *h100, *text;

	h10 = strdup(crypt("ten", SHA512_SALT));
	h100 = strdup(crypt("hundred", SHA512_SALT));
	ATF_REQUIRE(h10 != NULL && h100 != NULL);
	ATF_REQUIRE(asprintf(&text,
	    "ten:%s:10:10::0:0:x:/:/bin/sh\n"
	    "hundred:%s:100:100::0:0:x:/:/bin/sh\n", h10, h100) > 0);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 10, "ten"));
	free(text);
	ATF_REQUIRE(asprintf(&text,
	    "ten:%s:10:10::0:0:x:/:/bin/sh\n"
	    "hundred:%s:100:100::0:0:x:/:/bin/sh\n", h10, h100) > 0);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 100, "hundred"));
	free(text);
	ATF_REQUIRE(asprintf(&text,
	    "ten:%s:10:10::0:0:x:/:/bin/sh\n"
	    "hundred:%s:100:100::0:0:x:/:/bin/sh\n", h10, h100) > 0);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 10, "hundred"));
	free(text);
	ATF_REQUIRE(asprintf(&text,
	    "ten:%s:10:10::0:0:x:/:/bin/sh\n"
	    "hundred:%s:100:100::0:0:x:/:/bin/sh\n", h10, h100) > 0);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 100, "ten"));
	free(text);
	ATF_REQUIRE(asprintf(&text,
	    "ten:%s:10:10::0:0:x:/:/bin/sh\n"
	    "hundred:%s:100:100::0:0:x:/:/bin/sh\n", h10, h100) > 0);
	ATF_CHECK_EQ(ENOENT, authagent_verify_password(text, 1, "ten"));
	free(text);
	ATF_REQUIRE(asprintf(&text,
	    "ten:%s:10:10::0:0:x:/:/bin/sh\n"
	    "hundred:%s:100:100::0:0:x:/:/bin/sh\n", h10, h100) > 0);
	ATF_CHECK_EQ(ENOENT, authagent_verify_password(text, 1000, "ten"));
	free(text);
	/* Leading zeros are digits: "010" parses as 10 (pinned). */
	ATF_REQUIRE(asprintf(&text, "ten:%s:010:10::0:0:x:/:/bin/sh\n",
	    h10) > 0);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 10, "ten"));
	free(text);
	/* Hex, negative and empty uid fields never match anything. */
	ATF_REQUIRE(asprintf(&text,
	    "a:%s:0xa:10::0:0:x:/:/bin/sh\n"
	    "b:%s:-10:10::0:0:x:/:/bin/sh\n"
	    "c:%s::10::0:0:x:/:/bin/sh\n"
	    "d:%s: 10:10::0:0:x:/:/bin/sh\n", h10, h10, h10, h10) > 0);
	ATF_CHECK_EQ(ENOENT, authagent_verify_password(text, 10, "ten"));
	free(text);
	ATF_REQUIRE(asprintf(&text, "c:%s::10::0:0:x:/:/bin/sh\n", h10) > 0);
	ATF_CHECK_EQ(ENOENT, authagent_verify_password(text, 0, "ten"));
	free(text);
	free(h10);
	free(h100);
}

/* Every locked spelling is EPERM, with any password, before crypt(3). */
ATF_TC_WITHOUT_HEAD(masterpw_locked_forms_eperm);
ATF_TC_BODY(masterpw_locked_forms_eperm, tc)
{
	static const char *const locked[] = {
		"*", "!", "*LOCKED*", "*LOCKED*$6$salt$hashhashhash",
		"!$6$salt$hashhashhash", "!!", "**", "*x", "!x",
		"*LOCKED*$2b$04$abcdefghijklmnopqrstuv",
	};
	static const char *const passwords[] = {
		"", "*", "!", "*LOCKED*", "pw",
	};
	char *text;
	unsigned i, j;

	for (i = 0; i < nitems(locked); i++) {
		for (j = 0; j < nitems(passwords); j++) {
			ATF_REQUIRE(asprintf(&text,
			    "u:%s:7:7::0:0:x:/:/bin/sh\n", locked[i]) > 0);
			ATF_CHECK_MSG(EPERM == authagent_verify_password(text,
			    7, passwords[j]), "hash '%s' password '%s' not EPERM",
			    locked[i], passwords[j]);
			free(text);
		}
	}
}

/*
 * A hash whose prefix names no crypt(3) format is not a crash and not a
 * match: libcrypt falls back to its default format (or DES for a 13-char
 * salt), the computed string differs, EACCES.  A malformed salt for a known
 * format (crypt returns NULL) is EACCES too.
 */
ATF_TC_WITHOUT_HEAD(masterpw_unsupported_hash_prefix_eacces);
ATF_TC_BODY(masterpw_unsupported_hash_prefix_eacces, tc)
{
	static const char *const hashes[] = {
		"$9$abc$def", "$", "$$", "$6$", "$6", "$6$$", "$2b$", "$2b$04$",
		"$2b$99$abcdefghijklmnopqrstuv", "$2x$04$abcdefghijklmnopqrstuv",
		"$1$", "$5$", "$sha1$", "$md5$", "_", "_abcd", "x", "xy",
		"xyz", "abcdefghijklm", "$6$salt$", "$6$salt$notahash",
		"=", "$6$\xff\xfe$", "{SSHA}abc", "$argon2id$v=19$m=65536",
		"$y$j9T$abc", "$7$abc",
	};
	char *text;
	unsigned i;

	for (i = 0; i < nitems(hashes); i++) {
		ATF_REQUIRE(asprintf(&text, "u:%s:7:7::0:0:x:/:/bin/sh\n",
		    hashes[i]) > 0);
		ATF_CHECK_MSG(EACCES == authagent_verify_password(text, 7, "pw"),
		    "hash '%s' with 'pw' not EACCES", hashes[i]);
		free(text);
		ATF_REQUIRE(asprintf(&text, "u:%s:7:7::0:0:x:/:/bin/sh\n",
		    hashes[i]) > 0);
		ATF_CHECK_MSG(EACCES == authagent_verify_password(text, 7, ""),
		    "hash '%s' with '' not EACCES", hashes[i]);
		free(text);
		/* The hash itself as the password is not a match either. */
		ATF_REQUIRE(asprintf(&text, "u:%s:7:7::0:0:x:/:/bin/sh\n",
		    hashes[i]) > 0);
		ATF_CHECK_MSG(EACCES == authagent_verify_password(text, 7,
		    hashes[i]), "hash '%s' as its own password not EACCES",
		    hashes[i]);
		free(text);
	}
}

/*
 * A record far longer than any fixed buffer (> 4 KiB, here 16 KiB of gecos)
 * neither overflows nor hides the records around it.  The snapshot is
 * followed by a canary that must survive; the parser works in place on the
 * caller's buffer and must never write past its NUL.
 */
ATF_TC_WITHOUT_HEAD(masterpw_long_line_no_overflow);
ATF_TC_BODY(masterpw_long_line_no_overflow, tc)
{
	static const char canary[] = "CANARY-CANARY-CANARY";
	char *gecos, *hash, *text, *buf;
	size_t textlen, geclen;

	geclen = 16 * 1024;
	gecos = malloc(geclen + 1);
	ATF_REQUIRE(gecos != NULL);
	memset(gecos, 'g', geclen);
	gecos[geclen] = '\0';
	hash = strdup(crypt("pw", SHA512_SALT));
	ATF_REQUIRE(hash != NULL);

	/* Long line for another uid before, and for the target uid itself. */
	ATF_REQUIRE(asprintf(&text,
	    "before:%s:6:6::0:0:%s:/:/bin/sh\n"
	    "u:%s:7:7::0:0:%s:/:/bin/sh\n"
	    "after:%s:8:8::0:0:x:/:/bin/sh\n", hash, gecos, hash, gecos,
	    hash) > 0);
	textlen = strlen(text);
	buf = malloc(textlen + 1 + sizeof(canary));
	ATF_REQUIRE(buf != NULL);
	memcpy(buf, text, textlen + 1);
	memcpy(buf + textlen + 1, canary, sizeof(canary));
	ATF_CHECK_EQ(0, authagent_verify_password(buf, 7, "pw"));
	ATF_CHECK_EQ(0, memcmp(buf + textlen + 1, canary, sizeof(canary)));
	memcpy(buf, text, textlen + 1);
	ATF_CHECK_EQ(0, authagent_verify_password(buf, 8, "pw"));
	ATF_CHECK_EQ(0, memcmp(buf + textlen + 1, canary, sizeof(canary)));
	memcpy(buf, text, textlen + 1);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(buf, 6, "no"));
	ATF_CHECK_EQ(0, memcmp(buf + textlen + 1, canary, sizeof(canary)));
	free(buf);
	free(text);

	/* A long line with NO newline and no uid field is skipped, not read past. */
	ATF_REQUIRE(asprintf(&text, "u:%s", gecos) > 0);
	textlen = strlen(text);
	buf = malloc(textlen + 1 + sizeof(canary));
	ATF_REQUIRE(buf != NULL);
	memcpy(buf, text, textlen + 1);
	memcpy(buf + textlen + 1, canary, sizeof(canary));
	ATF_CHECK_EQ(ENOENT, authagent_verify_password(buf, 7, "pw"));
	ATF_CHECK_EQ(0, memcmp(buf + textlen + 1, canary, sizeof(canary)));
	free(buf);
	free(text);

	/* A 16 KiB "hash" field for the target uid: EACCES, no overflow. */
	ATF_REQUIRE(asprintf(&text, "u:%s:7:7::0:0:x:/:/bin/sh\n", gecos) > 0);
	textlen = strlen(text);
	buf = malloc(textlen + 1 + sizeof(canary));
	ATF_REQUIRE(buf != NULL);
	memcpy(buf, text, textlen + 1);
	memcpy(buf + textlen + 1, canary, sizeof(canary));
	ATF_CHECK_EQ(EACCES, authagent_verify_password(buf, 7, "pw"));
	ATF_CHECK_EQ(0, memcmp(buf + textlen + 1, canary, sizeof(canary)));
	free(buf);
	free(text);

	/* A 16 KiB password against a normal hash: EACCES, no overflow. */
	ATF_REQUIRE(asprintf(&text, "u:%s:7:7::0:0:x:/:/bin/sh\n", hash) > 0);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, gecos));
	free(text);

	free(hash);
	free(gecos);
}

/* The last record needs no trailing newline; CRLF is not tolerated. */
ATF_TC_WITHOUT_HEAD(masterpw_last_line_without_newline);
ATF_TC_BODY(masterpw_last_line_without_newline, tc)
{
	char *hash, *text;

	/* strdup: verify_password calls crypt(3), which reuses the static buffer. */
	hash = strdup(crypt("pw", SHA512_SALT));
	ATF_REQUIRE(hash != NULL);
	ATF_REQUIRE(asprintf(&text,
	    "root:*:0:0::0:0:x:/:/bin/sh\n"
	    "u:%s:7:7::0:0:x:/:/bin/sh", hash) > 0);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, "pw"));
	free(text);
	/* Short last line without newline, hash then uid then EOF. */
	ATF_REQUIRE(asprintf(&text, "u:%s:7", hash) > 0);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, "pw"));
	free(text);
	/*
	 * CRLF: the "\r" lands in the shell field of a full record (harmless,
	 * matches) but in the uid field of a 3-field record (skipped).
	 */
	ATF_REQUIRE(asprintf(&text, "u:%s:7:7::0:0:x:/:/bin/sh\r\n", hash) > 0);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, "pw"));
	free(text);
	ATF_REQUIRE(asprintf(&text, "u:%s:7\r\n", hash) > 0);
	ATF_CHECK_EQ(ENOENT, authagent_verify_password(text, 7, "pw"));
	free(text);
	free(hash);
}

/* ---- crypt(3) algorithms -------------------------------------------------- */

ATF_TC_WITHOUT_HEAD(crypt_sha512_verify);
ATF_TC_BODY(crypt_sha512_verify, tc)
{
	char *text;

	text = record_for(7, "correct horse", "$6$rounds=5000$saltsaltsalt$");
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, "correct horse"));
	free(text);
	text = record_for(7, "correct horse", "$6$rounds=5000$saltsaltsalt$");
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, "correct horsf"));
	free(text);
	text = record_for(7, "correct horse", SHA512_SALT);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, "correct hors"));
	free(text);
	text = record_for(7, "correct horse", SHA512_SALT);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, ""));
	free(text);
	/* The stored hash is a sha512 one (the pin for the format). */
	text = record_for(7, "x", SHA512_SALT);
	ATF_CHECK(strncmp(text, "u:$6$", 5) == 0);
	free(text);
}

#define	BCRYPT_SALT	"$2b$04$abcdefghijklmnopqrstuv"

ATF_TC_WITHOUT_HEAD(crypt_bcrypt_verify);
ATF_TC_BODY(crypt_bcrypt_verify, tc)
{
	char *text;

	text = record_for(7, "correct horse", BCRYPT_SALT);
	ATF_CHECK(strncmp(text, "u:$2b$04$", 9) == 0);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, "correct horse"));
	free(text);
	text = record_for(7, "correct horse", BCRYPT_SALT);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, "correct horsf"));
	free(text);
	text = record_for(7, "correct horse", BCRYPT_SALT);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, "Correct horse"));
	free(text);
	text = record_for(7, "correct horse", BCRYPT_SALT);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, ""));
	free(text);
	/* "$2a$" and "$2y$" spellings of the same salt verify too. */
	text = record_for(7, "pw", "$2a$04$abcdefghijklmnopqrstuv");
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, "pw"));
	free(text);
	text = record_for(7, "pw", "$2y$04$abcdefghijklmnopqrstuv");
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, "pw"));
	free(text);
}

/*
 * bcrypt's own contract: only the first 72 bytes of a password are hashed.
 * Pinned so the property is visible (it is the algorithm, not the agent):
 * a 73rd-byte difference is NOT detected under $2b$, but IS under $6$.
 */
ATF_TC_WITHOUT_HEAD(crypt_bcrypt_72_byte_truncation_documented);
ATF_TC_BODY(crypt_bcrypt_72_byte_truncation_documented, tc)
{
	char pw[80], other[80];
	char *text;

	memset(pw, 'p', 73);
	pw[73] = '\0';
	memcpy(other, pw, sizeof(pw));
	other[72] = 'X';		/* differs only in byte 73 */
	text = record_for(7, pw, BCRYPT_SALT);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, pw));
	free(text);
	text = record_for(7, pw, BCRYPT_SALT);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, other));
	free(text);
	/* But byte 72 (inside the window) does matter. */
	other[72] = 'p';
	other[71] = 'X';
	text = record_for(7, pw, BCRYPT_SALT);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, other));
	free(text);
	/* sha512 has no such window. */
	other[71] = 'p';
	other[72] = 'X';
	text = record_for(7, pw, SHA512_SALT);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, other));
	free(text);
}

/* Traditional DES (13-char hash): supported, 8-significant-char contract. */
ATF_TC_WITHOUT_HEAD(crypt_des_verify);
ATF_TC_BODY(crypt_des_verify, tc)
{
	char *hash, *text;

	hash = crypt("pw", "ab");
	ATF_REQUIRE(hash != NULL);
	if (strlen(hash) != 13)
		atf_tc_skip("crypt(3) has no DES support here (hash '%s')",
		    hash);
	text = record_for(7, "pw", "ab");
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, "pw"));
	free(text);
	text = record_for(7, "pw", "ab");
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, "pq"));
	free(text);
	text = record_for(7, "pw", "ab");
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, ""));
	free(text);
	/* Wrong salt for the same password: mismatch. */
	text = record_for(7, "pw", "ac");
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, "pw"));
	free(text);
	/* DES uses eight characters: "password1" and "password2" collide. */
	text = record_for(7, "password1", "ab");
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, "password2"));
	free(text);
	text = record_for(7, "password1", "ab");
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, "passwor"));
	free(text);
}

/* ---- compare discipline ------------------------------------------------- */

/*
 * The compare is over the whole stored hash: a stored prefix of the computed
 * hash, the computed hash with only its LAST byte changed, and the computed
 * hash with only its FIRST byte changed are all mismatches.  A byte-at-a-time
 * early-exit compare over min(len) would accept the first of these.
 */
ATF_TC_WITHOUT_HEAD(password_compare_is_whole_hash);
ATF_TC_BODY(password_compare_is_whole_hash, tc)
{
	char *hash, *mod, *text;
	size_t len;

	hash = strdup(crypt("pw", SHA512_SALT));
	ATF_REQUIRE(hash != NULL);
	len = strlen(hash);
	ATF_REQUIRE(len > 20);

	/* One-byte stored hash "$": a prefix of the computed one. */
	text = strdup("u:$:7:7::0:0:x:/:/bin/sh\n");
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, "pw"));
	free(text);
	/* Half of the computed hash. */
	ATF_REQUIRE(asprintf(&text, "u:%.*s:7:7::0:0:x:/:/bin/sh\n",
	    (int)(len / 2), hash) > 0);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, "pw"));
	free(text);
	/* Last byte changed. */
	mod = strdup(hash);
	ATF_REQUIRE(mod != NULL);
	mod[len - 1] = mod[len - 1] == 'A' ? 'B' : 'A';
	ATF_REQUIRE(asprintf(&text, "u:%s:7:7::0:0:x:/:/bin/sh\n", mod) > 0);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, "pw"));
	free(text);
	free(mod);
	/* First byte of the hash body (after the salt) changed. */
	mod = strdup(hash);
	ATF_REQUIRE(mod != NULL);
	mod[strlen(SHA512_SALT)] = mod[strlen(SHA512_SALT)] == 'A' ? 'B' : 'A';
	ATF_REQUIRE(asprintf(&text, "u:%s:7:7::0:0:x:/:/bin/sh\n", mod) > 0);
	ATF_CHECK_EQ(EACCES, authagent_verify_password(text, 7, "pw"));
	free(text);
	free(mod);
	/* The unmodified one still matches (the control). */
	ATF_REQUIRE(asprintf(&text, "u:%s:7:7::0:0:x:/:/bin/sh\n", hash) > 0);
	ATF_CHECK_EQ(0, authagent_verify_password(text, 7, "pw"));
	free(text);
	free(hash);
}

/* ---- rate limiter --------------------------------------------------------- */

/* Exactly: four failures are not blocked, the fifth is. */
ATF_TC_WITHOUT_HEAD(ratelimit_fourth_open_fifth_blocked);
ATF_TC_BODY(ratelimit_fourth_open_fifth_blocked, tc)
{
	struct authagent_ratelimit rl;

	ATF_REQUIRE_EQ(5U, AUTHAGENT_RL_MAX_FAILURES);
	memset(&rl, 0, sizeof(rl));
	authagent_ratelimit_failure(&rl, 1002, 100);
	authagent_ratelimit_failure(&rl, 1002, 100);
	authagent_ratelimit_failure(&rl, 1002, 100);
	authagent_ratelimit_failure(&rl, 1002, 100);
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1002, 100));
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1002, 159));
	authagent_ratelimit_failure(&rl, 1002, 100);
	ATF_CHECK(authagent_ratelimit_blocked(&rl, 1002, 100));
	/* Further failures while blocked keep it blocked (no wrap-around). */
	authagent_ratelimit_failure(&rl, 1002, 100);
	authagent_ratelimit_failure(&rl, 1002, 100);
	ATF_CHECK(authagent_ratelimit_blocked(&rl, 1002, 100));
}

/* The window is anchored on the FIRST failure and expires at exactly +60. */
ATF_TC_WITHOUT_HEAD(ratelimit_expiry_exact_boundary);
ATF_TC_BODY(ratelimit_expiry_exact_boundary, tc)
{
	struct authagent_ratelimit rl;
	const time_t t0 = 1000;

	ATF_REQUIRE_EQ(60, AUTHAGENT_RL_WINDOW_SEC);
	memset(&rl, 0, sizeof(rl));
	authagent_ratelimit_failure(&rl, 1002, t0);
	authagent_ratelimit_failure(&rl, 1002, t0 + 10);
	authagent_ratelimit_failure(&rl, 1002, t0 + 20);
	authagent_ratelimit_failure(&rl, 1002, t0 + 30);
	authagent_ratelimit_failure(&rl, 1002, t0 + 40);	/* fifth */
	ATF_CHECK(authagent_ratelimit_blocked(&rl, 1002, t0 + 40));
	ATF_CHECK(authagent_ratelimit_blocked(&rl, 1002, t0 + 59));
	/* Not anchored on the fifth (t0+40+60 = t0+100): free at t0+60. */
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1002, t0 + 60));
	/* And the slot was cleared, not merely bypassed. */
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1002, t0 + 60));
	authagent_ratelimit_failure(&rl, 1002, t0 + 60);
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1002, t0 + 60));
}

/* A success while blocked clears the block at once. */
ATF_TC_WITHOUT_HEAD(ratelimit_success_clears_block);
ATF_TC_BODY(ratelimit_success_clears_block, tc)
{
	struct authagent_ratelimit rl;
	unsigned i;

	memset(&rl, 0, sizeof(rl));
	for (i = 0; i < AUTHAGENT_RL_MAX_FAILURES; i++)
		authagent_ratelimit_failure(&rl, 1002, 100);
	ATF_REQUIRE(authagent_ratelimit_blocked(&rl, 1002, 100));
	authagent_ratelimit_success(&rl, 1002);
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1002, 100));
	/* The counter is at zero again: four more do not block. */
	for (i = 0; i < AUTHAGENT_RL_MAX_FAILURES - 1; i++)
		authagent_ratelimit_failure(&rl, 1002, 100);
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1002, 100));
	authagent_ratelimit_failure(&rl, 1002, 100);
	ATF_CHECK(authagent_ratelimit_blocked(&rl, 1002, 100));
	/* A success for a DIFFERENT uid does not clear this one. */
	authagent_ratelimit_success(&rl, 1003);
	ATF_CHECK(authagent_ratelimit_blocked(&rl, 1002, 100));
}

ATF_TC_WITHOUT_HEAD(ratelimit_per_uid_independent);
ATF_TC_BODY(ratelimit_per_uid_independent, tc)
{
	struct authagent_ratelimit rl;
	unsigned i;

	memset(&rl, 0, sizeof(rl));
	for (i = 0; i < AUTHAGENT_RL_MAX_FAILURES - 1; i++) {
		authagent_ratelimit_failure(&rl, 1002, 100);
		authagent_ratelimit_failure(&rl, 1003, 100);
		authagent_ratelimit_failure(&rl, 1004, 100);
	}
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1002, 100));
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1003, 100));
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1004, 100));
	authagent_ratelimit_failure(&rl, 1003, 100);
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1002, 100));
	ATF_CHECK(authagent_ratelimit_blocked(&rl, 1003, 100));
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1004, 100));
	/* Twelve failures across three uids never sum to a block. */
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1005, 100));
}

/* Count the used slots and find the slot for a uid (the table is public). */
static unsigned
slots_used(const struct authagent_ratelimit *rl)
{
	unsigned i, n;

	n = 0;
	for (i = 0; i < AUTHAGENT_RL_SLOTS; i++)
		if (rl->slots[i].used)
			n++;
	return (n);
}

static const struct authagent_ratelimit_slot *
slot_for(const struct authagent_ratelimit *rl, uid_t uid)
{
	unsigned i;

	for (i = 0; i < AUTHAGENT_RL_SLOTS; i++)
		if (rl->slots[i].used && rl->slots[i].uid == uid)
			return (&rl->slots[i]);
	return (NULL);
}

/*
 * 65 distinct uids in a 64-slot table with nothing expired: the STALEST
 * slot (earliest window_start) is recycled -- not the first, not the last,
 * and no slot is double-booked.  Then a flood of distinct uids is survivable.
 */
ATF_TC_WITHOUT_HEAD(ratelimit_65_uids_stalest_recycled);
ATF_TC_BODY(ratelimit_65_uids_stalest_recycled, tc)
{
	struct authagent_ratelimit rl;
	const struct authagent_ratelimit_slot *s;
	unsigned i, u;

	ATF_REQUIRE_EQ(64, AUTHAGENT_RL_SLOTS);
	memset(&rl, 0, sizeof(rl));
	/*
	 * 64 uids, five failures each: uid 7005 first at t=190 (the stalest),
	 * then the other 63 at t=200.  Chronological order matters: a slot
	 * whose window_start is in the future of `now` counts as expired.
	 */
	for (i = 0; i < AUTHAGENT_RL_MAX_FAILURES; i++)
		authagent_ratelimit_failure(&rl, 7005, 190);
	for (u = 0; u < AUTHAGENT_RL_SLOTS; u++) {
		if (u == 5)
			continue;
		for (i = 0; i < AUTHAGENT_RL_MAX_FAILURES; i++)
			authagent_ratelimit_failure(&rl, 7000 + u, 200);
	}
	ATF_REQUIRE_EQ(64U, slots_used(&rl));
	for (u = 0; u < AUTHAGENT_RL_SLOTS; u++)
		ATF_REQUIRE(authagent_ratelimit_blocked(&rl, 7000 + u, 210));

	/* The 65th uid at t=210: nothing has expired; 7005 is the stalest. */
	authagent_ratelimit_failure(&rl, 9999, 210);
	ATF_CHECK_EQ(64U, slots_used(&rl));
	ATF_CHECK(slot_for(&rl, 7005) == NULL);
	s = slot_for(&rl, 9999);
	ATF_REQUIRE(s != NULL);
	ATF_CHECK_EQ(1U, s->failures);
	ATF_CHECK_EQ(210, s->window_start);
	/* Everyone else is intact and still blocked. */
	for (u = 0; u < AUTHAGENT_RL_SLOTS; u++) {
		if (u == 5)
			continue;
		s = slot_for(&rl, 7000 + u);
		ATF_REQUIRE_MSG(s != NULL, "uid %u lost its slot", 7000 + u);
		ATF_CHECK_EQ(AUTHAGENT_RL_MAX_FAILURES, s->failures);
		ATF_CHECK(authagent_ratelimit_blocked(&rl, 7000 + u, 210));
	}
	/* The evicted uid starts over: four fresh failures do not block. */
	for (i = 0; i < AUTHAGENT_RL_MAX_FAILURES - 1; i++)
		authagent_ratelimit_failure(&rl, 7005, 211);
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 7005, 211));
	ATF_CHECK_EQ(64U, slots_used(&rl));

	/* A flood of 10000 distinct uids: never more than 64 slots, no crash. */
	for (u = 0; u < 10000; u++) {
		authagent_ratelimit_failure(&rl, 100000 + u, 300);
		ATF_REQUIRE(slots_used(&rl) <= AUTHAGENT_RL_SLOTS);
	}
	ATF_CHECK_EQ(64U, slots_used(&rl));
	/* Ties in window_start recycle the first such slot, deterministically. */
	ATF_CHECK(slot_for(&rl, 100000 + 9999) != NULL);
}

/* uid 0 and uid UINT32_MAX are ordinary keys, distinct from each other. */
ATF_TC_WITHOUT_HEAD(ratelimit_uid_zero_and_max_keys);
ATF_TC_BODY(ratelimit_uid_zero_and_max_keys, tc)
{
	struct authagent_ratelimit rl;
	unsigned i;

	memset(&rl, 0, sizeof(rl));
	/* A zeroed table does not treat uid 0 as "present". */
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 0, 100));
	ATF_CHECK(slot_for(&rl, 0) == NULL);
	for (i = 0; i < AUTHAGENT_RL_MAX_FAILURES; i++)
		authagent_ratelimit_failure(&rl, 0, 100);
	ATF_CHECK(authagent_ratelimit_blocked(&rl, 0, 100));
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, (uid_t)UINT32_MAX, 100));
	for (i = 0; i < AUTHAGENT_RL_MAX_FAILURES; i++)
		authagent_ratelimit_failure(&rl, (uid_t)UINT32_MAX, 100);
	ATF_CHECK(authagent_ratelimit_blocked(&rl, (uid_t)UINT32_MAX, 100));
	ATF_CHECK(authagent_ratelimit_blocked(&rl, 0, 100));
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 1, 100));
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, (uid_t)UINT32_MAX - 1, 100));
	ATF_CHECK_EQ(2U, slots_used(&rl));
	authagent_ratelimit_success(&rl, 0);
	ATF_CHECK(!authagent_ratelimit_blocked(&rl, 0, 100));
	ATF_CHECK(authagent_ratelimit_blocked(&rl, (uid_t)UINT32_MAX, 100));
	ATF_CHECK_EQ(1U, slots_used(&rl));
}

/* Asking is free: blocked() never counts as a failure. */
ATF_TC_WITHOUT_HEAD(ratelimit_query_has_no_side_effect);
ATF_TC_BODY(ratelimit_query_has_no_side_effect, tc)
{
	struct authagent_ratelimit rl;
	unsigned i;

	memset(&rl, 0, sizeof(rl));
	for (i = 0; i < 1000; i++)
		ATF_REQUIRE(!authagent_ratelimit_blocked(&rl, 1002, 100));
	ATF_CHECK_EQ(0U, slots_used(&rl));
	authagent_ratelimit_failure(&rl, 1002, 100);
	for (i = 0; i < 1000; i++)
		ATF_REQUIRE(!authagent_ratelimit_blocked(&rl, 1002, 100));
	ATF_CHECK_EQ(1U, slot_for(&rl, 1002)->failures);
}

/* ---- compose_set ---------------------------------------------------------- */

/* A name already held: no duplicate, count unchanged, order preserved. */
ATF_TC_WITHOUT_HEAD(compose_held_name_count_unchanged);
ATF_TC_BODY(compose_held_name_count_unchanged, tc)
{
	struct capbundle_principal_grant g;
	char out[SERVICE_ANOINT_MAX][SERVICE_ANOINT_NAME_MAX];
	unsigned n;
	bool all;

	memset(&g, 0, sizeof(g));
	strlcpy(g.anointments[0], "a.one", sizeof(g.anointments[0]));
	strlcpy(g.anointments[1], "a.two", sizeof(g.anointments[1]));
	strlcpy(g.anointments[2], "a.three", sizeof(g.anointments[2]));
	g.nanointments = 3;
	ATF_REQUIRE_EQ(0, authagent_compose_set(&g, "a.two", out, nitems(out),
	    &n, &all));
	ATF_CHECK_EQ(3U, n);
	ATF_CHECK(!all);
	ATF_CHECK_STREQ("a.one", out[0]);
	ATF_CHECK_STREQ("a.two", out[1]);
	ATF_CHECK_STREQ("a.three", out[2]);
	/* Held is exact-match: a case variant is a NEW name. */
	ATF_REQUIRE_EQ(0, authagent_compose_set(&g, "A.two", out, nitems(out),
	    &n, &all));
	ATF_CHECK_EQ(4U, n);
	ATF_CHECK_STREQ("A.two", out[3]);
}

ATF_TC_WITHOUT_HEAD(compose_32_held_plus_new_e2big);
ATF_TC_BODY(compose_32_held_plus_new_e2big, tc)
{
	struct capbundle_principal_grant g;
	char out[SERVICE_ANOINT_MAX][SERVICE_ANOINT_NAME_MAX];
	unsigned i, n;
	bool all;

	ATF_REQUIRE_EQ(32, SERVICE_ANOINT_MAX);
	memset(&g, 0, sizeof(g));
	for (i = 0; i < 32; i++)
		snprintf(g.anointments[i], sizeof(g.anointments[i]),
		    "held.name%u", i);
	g.nanointments = 32;
	n = 77;
	all = true;
	ATF_CHECK_EQ(E2BIG, authagent_compose_set(&g, "new.name", out,
	    nitems(out), &n, &all));
	/* Not "all", whatever was left in *all before. */
	ATF_CHECK(!all);
	/* Every held name still composes (32, no growth). */
	for (i = 0; i < 32; i++) {
		char name[SERVICE_ANOINT_NAME_MAX];

		snprintf(name, sizeof(name), "held.name%u", i);
		ATF_REQUIRE_EQ(0, authagent_compose_set(&g, name, out,
		    nitems(out), &n, &all));
		ATF_CHECK_EQ(32U, n);
	}
}

ATF_TC_WITHOUT_HEAD(compose_31_held_plus_new_is_32);
ATF_TC_BODY(compose_31_held_plus_new_is_32, tc)
{
	struct capbundle_principal_grant g;
	char out[SERVICE_ANOINT_MAX][SERVICE_ANOINT_NAME_MAX];
	unsigned i, n;
	bool all;

	memset(&g, 0, sizeof(g));
	for (i = 0; i < 31; i++)
		snprintf(g.anointments[i], sizeof(g.anointments[i]),
		    "held.name%u", i);
	g.nanointments = 31;
	ATF_REQUIRE_EQ(0, authagent_compose_set(&g, "new.name", out,
	    nitems(out), &n, &all));
	ATF_CHECK_EQ(32U, n);
	ATF_CHECK(!all);
	for (i = 0; i < 31; i++) {
		char name[SERVICE_ANOINT_NAME_MAX];

		snprintf(name, sizeof(name), "held.name%u", i);
		ATF_CHECK_STREQ(name, out[i]);
	}
	ATF_CHECK_STREQ("new.name", out[31]);
	/* max smaller than the table: 31 held into max 31 -> E2BIG. */
	ATF_CHECK_EQ(E2BIG, authagent_compose_set(&g, "new.name", out, 31,
	    &n, &all));
	/* max 0 with an empty grant: nothing fits, E2BIG (not EINVAL). */
	g.nanointments = 0;
	ATF_CHECK_EQ(E2BIG, authagent_compose_set(&g, "new.name", out, 0,
	    &n, &all));
}

/* anoint_all plus any name is "all" with an empty list, listed or not. */
ATF_TC_WITHOUT_HEAD(compose_anoint_all_plus_name_is_all);
ATF_TC_BODY(compose_anoint_all_plus_name_is_all, tc)
{
	struct capbundle_principal_grant g;
	char out[SERVICE_ANOINT_MAX][SERVICE_ANOINT_NAME_MAX];
	unsigned n;
	bool all;

	memset(&g, 0, sizeof(g));
	g.anoint_all = true;
	strlcpy(g.anointments[0], "a.listed", sizeof(g.anointments[0]));
	g.nanointments = 1;
	n = 77;
	all = false;
	ATF_REQUIRE_EQ(0, authagent_compose_set(&g, "a.listed", out,
	    nitems(out), &n, &all));
	ATF_CHECK(all);
	ATF_CHECK_EQ(0U, n);
	ATF_REQUIRE_EQ(0, authagent_compose_set(&g, "b.new", out, nitems(out),
	    &n, &all));
	ATF_CHECK(all);
	ATF_CHECK_EQ(0U, n);
	/* Even a full listed set beside "*" is not E2BIG. */
	g.nanointments = SERVICE_ANOINT_MAX;
	ATF_REQUIRE_EQ(0, authagent_compose_set(&g, "b.new", out, nitems(out),
	    &n, &all));
	ATF_CHECK(all);
	ATF_CHECK_EQ(0U, n);
}

/* elevate_all honours every valid name, held or not; may_elevate is exact. */
ATF_TC_WITHOUT_HEAD(check_elevate_all_any_name);
ATF_TC_BODY(check_elevate_all_any_name, tc)
{
	struct capbundle_principal_grant g;
	char longest[SERVICE_ANOINT_NAME_MAX];

	memset(&g, 0, sizeof(g));
	g.elevate_all = true;
	strlcpy(g.anointments[0], "a.held", sizeof(g.anointments[0]));
	g.nanointments = 1;
	ATF_CHECK_EQ(0, authagent_elevate_check(&g, "a.held"));
	ATF_CHECK_EQ(0, authagent_elevate_check(&g, "system.notify.system"));
	ATF_CHECK_EQ(0, authagent_elevate_check(&g, "x.y"));
	ATF_CHECK_EQ(0, authagent_elevate_check(&g, "X.Y"));
	fill_name(longest, sizeof(longest), sizeof(longest) - 1);
	ATF_CHECK_EQ(0, authagent_elevate_check(&g, longest));
	/* The check is policy only: syntax is the validator's job. */
	ATF_CHECK_EQ(0, authagent_elevate_check(&g, "nodot"));
}

ATF_TC_WITHOUT_HEAD(check_may_elevate_exact_match_only);
ATF_TC_BODY(check_may_elevate_exact_match_only, tc)
{
	struct capbundle_principal_grant g;

	memset(&g, 0, sizeof(g));
	strlcpy(g.may_elevate[0], "system.notify.system",
	    sizeof(g.may_elevate[0]));
	strlcpy(g.may_elevate[1], "a.b", sizeof(g.may_elevate[1]));
	g.nmay_elevate = 2;
	ATF_CHECK_EQ(0, authagent_elevate_check(&g, "system.notify.system"));
	ATF_CHECK_EQ(0, authagent_elevate_check(&g, "a.b"));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "system.notify"));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "system"));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "system.notify.system.x"));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "system.notify.syste"));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "system.notify.systen"));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "system.notify.system "));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, " system.notify.system"));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "system.notify.*"));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "*"));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, ""));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "a.b.c"));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "a"));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "b"));
	/* The count bounds the list: an entry past nmay_elevate is invisible. */
	strlcpy(g.may_elevate[2], "c.d", sizeof(g.may_elevate[2]));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "c.d"));
	g.nmay_elevate = 3;
	ATF_CHECK_EQ(0, authagent_elevate_check(&g, "c.d"));
	/* Holding a name from login is not permission to elevate to it. */
	strlcpy(g.anointments[0], "held.only", sizeof(g.anointments[0]));
	g.nanointments = 1;
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "held.only"));
	/* anoint_all is not elevate_all. */
	g.anoint_all = true;
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "held.only"));
	ATF_CHECK_EQ(EPERM, authagent_elevate_check(&g, "z.z"));
}

/* ---- label gate ----------------------------------------------------------- */

ATF_TC_WITHOUT_HEAD(label_trailing_space_denied);
ATF_TC_BODY(label_trailing_space_denied, tc)
{

	ATF_CHECK(!authagent_elevate_caller_allowed("org.5bsd.user-session "));
	ATF_CHECK(!authagent_elevate_caller_allowed(" org.5bsd.user-session"));
	ATF_CHECK(!authagent_elevate_caller_allowed("org.5bsd.user-session\t"));
	ATF_CHECK(!authagent_elevate_caller_allowed("org.5bsd.user-session\n"));
}

ATF_TC_WITHOUT_HEAD(label_prefix_extended_denied);
ATF_TC_BODY(label_prefix_extended_denied, tc)
{

	ATF_CHECK(!authagent_elevate_caller_allowed("org.5bsd.user-sessionX"));
	ATF_CHECK(!authagent_elevate_caller_allowed("org.5bsd.user-session2"));
	ATF_CHECK(!authagent_elevate_caller_allowed("org.5bsd.user-session/x"));
	ATF_CHECK(!authagent_elevate_caller_allowed("org.5bsd.user-sessions"));
	ATF_CHECK(!authagent_elevate_caller_allowed("xorg.5bsd.user-session"));
	ATF_CHECK(!authagent_elevate_caller_allowed("org.5bsd.user_session"));
	ATF_CHECK(!authagent_elevate_caller_allowed("org.5bsd.user-sessio"));
}

ATF_TC_WITHOUT_HEAD(label_empty_denied);
ATF_TC_BODY(label_empty_denied, tc)
{
	char zeroed[64];

	ATF_CHECK(!authagent_elevate_caller_allowed(""));
	memset(zeroed, 0, sizeof(zeroed));
	ATF_CHECK(!authagent_elevate_caller_allowed(zeroed));
	ATF_CHECK(!authagent_elevate_caller_allowed(NULL));
}

/* A 63-character label (the longest a client_label[64] can carry). */
ATF_TC_WITHOUT_HEAD(label_63_chars_denied);
ATF_TC_BODY(label_63_chars_denied, tc)
{
	char label[64];

	memset(label, 'a', sizeof(label));
	label[63] = '\0';
	ATF_CHECK(!authagent_elevate_caller_allowed(label));
	/* The session label padded out to 63 with its own prefix repeated. */
	strlcpy(label, AUTHAGENT_SESSION_LABEL, sizeof(label));
	memset(label + strlen(AUTHAGENT_SESSION_LABEL), 'x',
	    63 - strlen(AUTHAGENT_SESSION_LABEL));
	label[63] = '\0';
	ATF_CHECK_EQ(63U, strlen(label));
	ATF_CHECK(!authagent_elevate_caller_allowed(label));
}

ATF_TC_WITHOUT_HEAD(label_unit_shaped_denied);
ATF_TC_BODY(label_unit_shaped_denied, tc)
{

	ATF_CHECK(!authagent_elevate_caller_allowed("system.Notify/bsdnotify"));
	ATF_CHECK(!authagent_elevate_caller_allowed("system.Auth/authagentd"));
	ATF_CHECK(!authagent_elevate_caller_allowed("org.5bsd.user-session/x"));
	ATF_CHECK(!authagent_elevate_caller_allowed("system.Notify"));
	ATF_CHECK(!authagent_elevate_caller_allowed("org.5bsd"));
	ATF_CHECK(!authagent_elevate_caller_allowed("user-session"));
}

/* ---- mint kind for a grant ------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(kind_anoint_all_is_system);
ATF_TC_BODY(kind_anoint_all_is_system, tc)
{
	struct capbundle_principal_grant g;

	memset(&g, 0, sizeof(g));
	g.anoint_all = true;
	ATF_CHECK_EQ(SERVICE_MINT_SYSTEM, authagent_mint_kind_for_grant(&g));
	/* anoint_all alone, even with elevate_all false and no admin. */
	ATF_CHECK(!g.admin_rights);
}

ATF_TC_WITHOUT_HEAD(kind_admin_rights_only_is_system);
ATF_TC_BODY(kind_admin_rights_only_is_system, tc)
{
	struct capbundle_principal_grant g;

	memset(&g, 0, sizeof(g));
	g.admin_rights = true;
	ATF_CHECK_EQ(SERVICE_MINT_SYSTEM, authagent_mint_kind_for_grant(&g));
	/* Both set is also SYSTEM. */
	g.anoint_all = true;
	ATF_CHECK_EQ(SERVICE_MINT_SYSTEM, authagent_mint_kind_for_grant(&g));
}

ATF_TC_WITHOUT_HEAD(kind_neither_is_user);
ATF_TC_BODY(kind_neither_is_user, tc)
{
	struct capbundle_principal_grant g;
	unsigned i;

	memset(&g, 0, sizeof(g));
	ATF_CHECK_EQ(SERVICE_MINT_USER, authagent_mint_kind_for_grant(&g));
	/* A full listed set and elevate_all do not make an admin. */
	for (i = 0; i < SERVICE_ANOINT_MAX; i++)
		snprintf(g.anointments[i], sizeof(g.anointments[i]), "n.%u", i);
	g.nanointments = SERVICE_ANOINT_MAX;
	g.elevate_all = true;
	ATF_CHECK_EQ(SERVICE_MINT_USER, authagent_mint_kind_for_grant(&g));
	/* from_default_rule by itself says nothing about the kind. */
	g.from_default_rule = true;
	ATF_CHECK_EQ(SERVICE_MINT_USER, authagent_mint_kind_for_grant(&g));
}

/* Policy absent: the historical rule makes root SYSTEM and others USER. */
ATF_TC_WITHOUT_HEAD(kind_default_rule_root_is_system);
ATF_TC_BODY(kind_default_rule_root_is_system, tc)
{
	struct capbundle_principal_grant g;
	gid_t root_gids[] = { 0 };
	gid_t wheel_gids[] = { 1001, 0 };
	gid_t user_gids[] = { 1001 };

	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(-1, 0, root_gids, 1,
	    groups, NULL, &g));
	ATF_CHECK(g.from_default_rule);
	ATF_CHECK_EQ(SERVICE_MINT_SYSTEM, authagent_mint_kind_for_grant(&g));
	/* A wheel member likewise. */
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(-1, 1001, wheel_gids, 2,
	    groups, NULL, &g));
	ATF_CHECK(g.from_default_rule);
	ATF_CHECK_EQ(SERVICE_MINT_SYSTEM, authagent_mint_kind_for_grant(&g));
	/* An ordinary user is USER with nothing. */
	ATF_REQUIRE_EQ(0, capbundle_principal_resolve(-1, 1001, user_gids, 1,
	    groups, NULL, &g));
	ATF_CHECK(g.from_default_rule);
	ATF_CHECK_EQ(SERVICE_MINT_USER, authagent_mint_kind_for_grant(&g));
	ATF_CHECK_EQ(0U, g.nanointments);
	ATF_CHECK(!g.anoint_all);
	ATF_CHECK(!g.elevate_all);
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
	/* Edge-case and negative additions. */
	ATF_TP_ADD_TC(tp, name_len_63_ok_64_invalid);
	ATF_TP_ADD_TC(tp, name_uppercase_case_sensitive);
	ATF_TP_ADD_TC(tp, name_leading_dot_invalid);
	ATF_TP_ADD_TC(tp, name_trailing_dot_invalid);
	ATF_TP_ADD_TC(tp, name_double_dot_invalid);
	ATF_TP_ADD_TC(tp, name_star_invalid);
	ATF_TP_ADD_TC(tp, name_system_star_invalid);
	ATF_TP_ADD_TC(tp, name_empty_invalid);
	ATF_TP_ADD_TC(tp, name_single_segment_invalid);
	ATF_TP_ADD_TC(tp, name_bad_bytes_invalid);
	ATF_TP_ADD_TC(tp, password_255_chars_ok);
	ATF_TP_ADD_TC(tp, password_256_not_truncated_to_255);
	ATF_TP_ADD_TC(tp, password_empty_vs_hash_of_empty);
	ATF_TP_ADD_TC(tp, masterpw_short_line);
	ATF_TP_ADD_TC(tp, masterpw_extra_fields_ignored);
	ATF_TP_ADD_TC(tp, masterpw_duplicate_uid_first_wins);
	ATF_TP_ADD_TC(tp, masterpw_uid_absent_enoent);
	ATF_TP_ADD_TC(tp, masterpw_comments_and_blanks_skipped);
	ATF_TP_ADD_TC(tp, masterpw_uid_prefix_no_match);
	ATF_TP_ADD_TC(tp, masterpw_locked_forms_eperm);
	ATF_TP_ADD_TC(tp, masterpw_unsupported_hash_prefix_eacces);
	ATF_TP_ADD_TC(tp, masterpw_long_line_no_overflow);
	ATF_TP_ADD_TC(tp, masterpw_last_line_without_newline);
	ATF_TP_ADD_TC(tp, crypt_sha512_verify);
	ATF_TP_ADD_TC(tp, crypt_bcrypt_verify);
	ATF_TP_ADD_TC(tp, crypt_bcrypt_72_byte_truncation_documented);
	ATF_TP_ADD_TC(tp, crypt_des_verify);
	ATF_TP_ADD_TC(tp, password_compare_is_whole_hash);
	ATF_TP_ADD_TC(tp, ratelimit_fourth_open_fifth_blocked);
	ATF_TP_ADD_TC(tp, ratelimit_expiry_exact_boundary);
	ATF_TP_ADD_TC(tp, ratelimit_success_clears_block);
	ATF_TP_ADD_TC(tp, ratelimit_per_uid_independent);
	ATF_TP_ADD_TC(tp, ratelimit_65_uids_stalest_recycled);
	ATF_TP_ADD_TC(tp, ratelimit_uid_zero_and_max_keys);
	ATF_TP_ADD_TC(tp, ratelimit_query_has_no_side_effect);
	ATF_TP_ADD_TC(tp, compose_held_name_count_unchanged);
	ATF_TP_ADD_TC(tp, compose_32_held_plus_new_e2big);
	ATF_TP_ADD_TC(tp, compose_31_held_plus_new_is_32);
	ATF_TP_ADD_TC(tp, compose_anoint_all_plus_name_is_all);
	ATF_TP_ADD_TC(tp, check_elevate_all_any_name);
	ATF_TP_ADD_TC(tp, check_may_elevate_exact_match_only);
	ATF_TP_ADD_TC(tp, label_trailing_space_denied);
	ATF_TP_ADD_TC(tp, label_prefix_extended_denied);
	ATF_TP_ADD_TC(tp, label_empty_denied);
	ATF_TP_ADD_TC(tp, label_63_chars_denied);
	ATF_TP_ADD_TC(tp, label_unit_shaped_denied);
	ATF_TP_ADD_TC(tp, kind_anoint_all_is_system);
	ATF_TP_ADD_TC(tp, kind_admin_rights_only_is_system);
	ATF_TP_ADD_TC(tp, kind_neither_is_user);
	ATF_TP_ADD_TC(tp, kind_default_rule_root_is_system);
	return (atf_no_error());
}
