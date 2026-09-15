/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "policy.h"

ATF_TC_WITHOUT_HEAD(default_deny);
ATF_TC_BODY(default_deny, tc)
{
	struct notify_policy policy;

	ATF_REQUIRE_EQ(0, notify_policy_parse("{}", &policy));
	ATF_CHECK(!policy.timers);
	ATF_CHECK(!notify_policy_can_publish(&policy, "system.ready",
	    strlen("system.ready")));
	ATF_CHECK(!notify_policy_can_subscribe(&policy, "system.ready",
	    strlen("system.ready")));
}

ATF_TC_WITHOUT_HEAD(exact_topics);
ATF_TC_BODY(exact_topics, tc)
{
	struct notify_policy policy;

	ATF_REQUIRE_EQ(0, notify_policy_parse(
	    "{publish=[\"system.ready\"];"
	    "subscribe=[\"system.ready\",\"system.stop\"];timers=true;}",
	    &policy));
	ATF_CHECK(policy.timers);
	ATF_CHECK(notify_policy_can_publish(&policy, "system.ready",
	    strlen("system.ready")));
	ATF_CHECK(!notify_policy_can_publish(&policy, "system.stop",
	    strlen("system.stop")));
	ATF_CHECK(notify_policy_can_subscribe(&policy, "system.stop",
	    strlen("system.stop")));
	ATF_CHECK(!notify_policy_can_subscribe(&policy, "system",
	    strlen("system")));
}

ATF_TC_WITHOUT_HEAD(wildcard);
ATF_TC_BODY(wildcard, tc)
{
	struct notify_policy policy;

	ATF_REQUIRE_EQ(0, notify_policy_parse(
	    "{publish=[\"*\"];subscribe=[\"*\"];}", &policy));
	ATF_CHECK(notify_policy_can_publish(&policy, "any.valid-topic",
	    strlen("any.valid-topic")));
	ATF_CHECK(notify_policy_can_subscribe(&policy, "another",
	    strlen("another")));
}

ATF_TC_WITHOUT_HEAD(rejects_invalid_policy);
ATF_TC_BODY(rejects_invalid_policy, tc)
{
	struct notify_policy policy;

	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{unknown=true;}", &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{timers=\"yes\";}", &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{publish=\"topic\";}", &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{publish=[\"*\",\"topic\"];}",
	    &policy) == -1);
	ATF_CHECK_ERRNO(EEXIST,
	    notify_policy_parse("{subscribe=[\"topic\",\"topic\"];}",
	    &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{publish=[\"bad topic\"];}",
	    &policy) == -1);
}

ATF_TC_WITHOUT_HEAD(identity_database);
ATF_TC_BODY(identity_database, tc)
{
	struct notify_policy_db db;
	const struct notify_policy *policy;

	errno = EDOM;
	ATF_REQUIRE_EQ(notify_policy_db_parse(
	    "{clients={\"com.example/publisher\"={publish=[\"system.ready\"];};"
	    "\"com.example/subscriber\"={subscribe=[\"system.ready\"];"
	    "timers=true;};};}", &db), 0);
	ATF_CHECK_EQ(0, errno);
	policy = notify_policy_db_lookup(&db, "com.example/publisher");
	ATF_REQUIRE(policy != NULL);
	ATF_CHECK(notify_policy_can_publish(policy, "system.ready", 12));
	ATF_CHECK(!notify_policy_can_subscribe(policy, "system.ready", 12));
	policy = notify_policy_db_lookup(&db, "com.example/subscriber");
	ATF_REQUIRE(policy != NULL);
	ATF_CHECK(policy->timers);
	ATF_CHECK(notify_policy_db_lookup(&db, "unknown") == NULL);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_db_parse("{clients={};extra=true;}", &db) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_db_parse("{clients={\"bad label\"={};};}",
	    &db) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_db_parse("{clients={\"missing-separator\"={};};}",
	    &db) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_db_parse("{clients={\"bad//label\"={};};}",
	    &db) == -1);
}

/* Prefix patterns: "<prefix>.*" matches one or more further segments. */
ATF_TC_WITHOUT_HEAD(prefix_patterns);
ATF_TC_BODY(prefix_patterns, tc)
{
	struct notify_policy policy;

	ATF_REQUIRE_EQ(0, notify_policy_parse(
	    "{publish=[\"user.*\"];subscribe=[\"system.shutdown.*\",\"exact\"];}",
	    &policy));
	ATF_CHECK_EQ(1, policy.npublish);
	ATF_CHECK(policy.publish[0].prefix);
	ATF_CHECK_EQ(4, policy.publish[0].length);
	ATF_CHECK_EQ(0, memcmp(policy.publish[0].name, "user", 4));
	ATF_CHECK(!policy.publish_all);
	/* positive */
	ATF_CHECK(notify_policy_can_publish(&policy, "user.x", 6));
	ATF_CHECK(notify_policy_can_publish(&policy, "user.x.y", 8));
	ATF_CHECK(notify_policy_can_publish(&policy, "user.me.changed", 15));
	ATF_CHECK(notify_policy_can_subscribe(&policy, "system.shutdown.now",
	    19));
	ATF_CHECK(notify_policy_can_subscribe(&policy, "exact", 5));
	/* negative: the bare prefix, a sibling, a dangling dot, other roots */
	ATF_CHECK(!notify_policy_can_publish(&policy, "user", 4));
	ATF_CHECK(!notify_policy_can_publish(&policy, "users.x", 7));
	ATF_CHECK(!notify_policy_can_publish(&policy, "user.", 5));
	ATF_CHECK(!notify_policy_can_publish(&policy, "use", 3));
	ATF_CHECK(!notify_policy_can_publish(&policy, "system.x", 8));
	ATF_CHECK(!notify_policy_can_publish(&policy, "xuser.x", 7));
	ATF_CHECK(!notify_policy_can_subscribe(&policy, "system.shutdown", 15));
	ATF_CHECK(!notify_policy_can_subscribe(&policy, "exact.more", 10));
	ATF_CHECK(!notify_policy_can_subscribe(&policy, "user.x", 6));
	/* an exact entry and a pattern with the same prefix coexist */
	ATF_REQUIRE_EQ(0, notify_policy_parse(
	    "{publish=[\"user\",\"user.*\"];}", &policy));
	ATF_CHECK_EQ(2, policy.npublish);
	ATF_CHECK(notify_policy_can_publish(&policy, "user", 4));
	ATF_CHECK(notify_policy_can_publish(&policy, "user.x", 6));
	ATF_CHECK(!notify_policy_can_publish(&policy, "users", 5));
	/* invalid patterns */
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{publish=[\"*.x\"];}", &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{publish=[\"user.*.y\"];}", &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{publish=[\"user*\"];}", &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{publish=[\"user.**\"];}", &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{publish=[\".*\"];}", &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{publish=[\"*.\"];}", &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{publish=[\"**\"];}", &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{publish=[\"user..*\"];}", &policy) == -1);
	/* a bare "*" still excludes every other entry, patterns included */
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{publish=[\"*\",\"user.*\"];}",
	    &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{publish=[\"user.*\",\"*\"];}",
	    &policy) == -1);
	/* duplicates */
	ATF_CHECK_ERRNO(EEXIST,
	    notify_policy_parse("{publish=[\"user.*\",\"user.*\"];}",
	    &policy) == -1);
}

static void
check_builtin_open(const struct notify_policy *policy)
{

	ATF_CHECK(policy->subscribe_all);
	ATF_CHECK(!policy->publish_all);
	ATF_CHECK(!policy->timers);
	ATF_CHECK(notify_policy_can_subscribe(policy, "system.shutdown.x", 17));
	ATF_CHECK(notify_policy_can_subscribe(policy, "anything", 8));
	ATF_CHECK(notify_policy_can_publish(policy, "user.me.x", 9));
	ATF_CHECK(notify_policy_can_publish(policy, "user.x", 6));
	ATF_CHECK(!notify_policy_can_publish(policy, "user", 4));
	ATF_CHECK(!notify_policy_can_publish(policy, "users.x", 7));
	ATF_CHECK(!notify_policy_can_publish(policy, "system.x", 8));
}

static void
check_builtin_system(const struct notify_policy *policy)
{

	ATF_CHECK(policy->subscribe_all);
	ATF_CHECK(policy->publish_all);
	ATF_CHECK(policy->timers);
	ATF_CHECK(notify_policy_can_publish(policy, "system.x", 8));
	ATF_CHECK(notify_policy_can_publish(policy, "user.x", 6));
	ATF_CHECK(notify_policy_can_subscribe(policy, "system.x", 8));
}

/* Missing blocks fall back to the compiled-in per-tier defaults. */
ATF_TC_WITHOUT_HEAD(tier_defaults_when_absent);
ATF_TC_BODY(tier_defaults_when_absent, tc)
{
	static const char *const documents[] = {
		"", "  \n\t", "{}", "clients {};", "{clients={};}",
		"clients { \"a.b/c\" { timers = true; } }",
	};
	struct notify_policy_db *db;
	struct notify_policy policy;
	size_t i;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	for (i = 0; i < nitems(documents); i++) {
		errno = EDOM;
		ATF_REQUIRE_EQ(0, notify_policy_db_parse(documents[i], db));
		ATF_CHECK_EQ(0, errno);
		ATF_CHECK(!db->has_default);
		ATF_CHECK(!db->has_system_default);
		check_builtin_open(&db->open_default);
		check_builtin_system(&db->system_default);
	}
	ATF_CHECK_EQ(1, db->nclients);
	notify_policy_builtin_open(&policy);
	check_builtin_open(&policy);
	notify_policy_builtin_system(&policy);
	check_builtin_system(&policy);
	/* the file-level loader agrees with the string parser */
	{
		int fd;

		fd = open("empty.conf", O_WRONLY | O_CREAT | O_TRUNC, 0600);
		ATF_REQUIRE(fd >= 0);
		close(fd);
		ATF_REQUIRE_EQ(0, notify_policy_db_load("empty.conf", db));
		check_builtin_open(&db->open_default);
		check_builtin_system(&db->system_default);
	}
	free(db);
}

/* The shipped bsdnotify.conf spells the builtins out; both must agree. */
ATF_TC_WITHOUT_HEAD(shipped_defaults_equal_builtins);
ATF_TC_BODY(shipped_defaults_equal_builtins, tc)
{
	struct notify_policy_db *db;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "default { subscribe = [ \"*\" ]; publish = [ \"user.*\" ];"
	    " timers = false; }\n"
	    "system_default { publish = [ \"*\" ]; subscribe = [ \"*\" ];"
	    " timers = true; }\n"
	    "clients {\n};\n", db));
	ATF_CHECK(db->has_default);
	ATF_CHECK(db->has_system_default);
	ATF_CHECK_EQ(0, db->nclients);
	check_builtin_open(&db->open_default);
	check_builtin_system(&db->system_default);
	free(db);
}

/* default {} and system_default {} parse and override the builtins. */
ATF_TC_WITHOUT_HEAD(tier_blocks_parse);
ATF_TC_BODY(tier_blocks_parse, tc)
{
	struct notify_policy_db *db;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "default { publish = [\"a.b\"]; timers = true; }", db));
	ATF_CHECK(db->has_default);
	ATF_CHECK(!db->has_system_default);
	ATF_CHECK(db->open_default.timers);
	ATF_CHECK(notify_policy_can_publish(&db->open_default, "a.b", 3));
	ATF_CHECK(!notify_policy_can_publish(&db->open_default, "user.x", 6));
	ATF_CHECK(!notify_policy_can_subscribe(&db->open_default, "a.b", 3));
	check_builtin_system(&db->system_default);

	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "system_default { subscribe = [\"c.d\"]; timers = false; }", db));
	ATF_CHECK(!db->has_default);
	ATF_CHECK(db->has_system_default);
	ATF_CHECK(!db->system_default.timers);
	ATF_CHECK(!db->system_default.publish_all);
	ATF_CHECK(!notify_policy_can_publish(&db->system_default, "system.x",
	    8));
	ATF_CHECK(notify_policy_can_subscribe(&db->system_default, "c.d", 3));
	check_builtin_open(&db->open_default);

	/* An empty block is a deny-all block, not "use the builtin". */
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "default {} system_default {}", db));
	ATF_CHECK(db->has_default && db->has_system_default);
	ATF_CHECK(!notify_policy_can_publish(&db->open_default, "user.x", 6));
	ATF_CHECK(!notify_policy_can_subscribe(&db->open_default, "x", 1));
	ATF_CHECK(!notify_policy_can_publish(&db->system_default, "x", 1));
	ATF_CHECK(!db->system_default.timers);

	/* All three together, in any order. */
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "clients { \"x.y/z\" { publish = [\"*\"]; } }"
	    "system_default { timers = true; }"
	    "default { subscribe = [\"*\"]; }", db));
	ATF_CHECK_EQ(1, db->nclients);
	ATF_CHECK(db->has_default && db->has_system_default);
	free(db);
}

ATF_TC_WITHOUT_HEAD(tier_blocks_reject_invalid);
ATF_TC_BODY(tier_blocks_reject_invalid, tc)
{
	struct notify_policy_db *db;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	/* unknown top-level keys */
	ATF_CHECK_ERRNO(EINVAL, notify_policy_db_parse("unknown {}", db) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_db_parse("{clients={};extra=true;}", db) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_db_parse("defaults {}", db) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_db_parse("Default {}", db) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_db_parse("default {} system_default {} open {}",
	    db) == -1);
	/* wrong shapes */
	ATF_CHECK_ERRNO(EINVAL, notify_policy_db_parse("default = [];", db) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_db_parse("default = true;", db) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_db_parse("system_default = \"x\";", db) == -1);
	ATF_CHECK_ERRNO(EINVAL, notify_policy_db_parse("clients = [];", db) == -1);
	/* the block-level parser stays strict inside the tier blocks */
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_db_parse("default { unknown = true; }", db) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_db_parse("system_default { timers = \"yes\"; }",
	    db) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_db_parse("default { publish = [\"*.x\"]; }",
	    db) == -1);
	ATF_CHECK_ERRNO(EEXIST,
	    notify_policy_db_parse(
	    "system_default { publish = [\"a.*\", \"a.*\"]; }", db) == -1);
	/* a tier block cannot be keyed like a client */
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_db_parse("clients { default { timers = true; } }",
	    db) == -1);
	/* syntax errors */
	ATF_CHECK_ERRNO(EINVAL, notify_policy_db_parse("default {", db) == -1);
	free(db);
}

/* notify_policy_db_select(): open ignores clients; system narrows. */
ATF_TC_WITHOUT_HEAD(select_by_tier);
ATF_TC_BODY(select_by_tier, tc)
{
	struct notify_policy_db *db;
	const struct notify_policy *policy;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "clients { \"com.example/pub\" { publish = [\"system.shutdown.*\"]; } }",
	    db));
	/* open tier: always the default block, listed label or not */
	policy = notify_policy_db_select(db, NOTIFY_TIER_OPEN, "com.example/pub");
	ATF_CHECK(policy == &db->open_default);
	policy = notify_policy_db_select(db, NOTIFY_TIER_OPEN, "org.other/x");
	ATF_CHECK(policy == &db->open_default);
	policy = notify_policy_db_select(db, NOTIFY_TIER_OPEN, NULL);
	ATF_CHECK(policy == &db->open_default);
	ATF_CHECK(!notify_policy_can_publish(policy, "system.shutdown.now", 19));
	ATF_CHECK(notify_policy_can_publish(policy, "user.x", 6));
	/* system tier: clients entry first, then system_default */
	policy = notify_policy_db_select(db, NOTIFY_TIER_SYSTEM,
	    "com.example/pub");
	ATF_REQUIRE(policy != NULL);
	ATF_CHECK(policy == notify_policy_db_lookup(db, "com.example/pub"));
	ATF_CHECK(notify_policy_can_publish(policy, "system.shutdown.now", 19));
	ATF_CHECK(!notify_policy_can_publish(policy, "system.other", 12));
	ATF_CHECK(!policy->timers);
	policy = notify_policy_db_select(db, NOTIFY_TIER_SYSTEM, "org.other/x");
	ATF_CHECK(policy == &db->system_default);
	ATF_CHECK(notify_policy_can_publish(policy, "system.other", 12));
	policy = notify_policy_db_select(db, NOTIFY_TIER_SYSTEM, NULL);
	ATF_CHECK(policy == &db->system_default);
	/* label matching is exact, never prefix or case-folded */
	policy = notify_policy_db_select(db, NOTIFY_TIER_SYSTEM,
	    "com.example/pub2");
	ATF_CHECK(policy == &db->system_default);
	policy = notify_policy_db_select(db, NOTIFY_TIER_SYSTEM,
	    "com.example/Pub");
	ATF_CHECK(policy == &db->system_default);
	/* unknown tier or no database: nothing, so admission fails closed */
	ATF_CHECK(notify_policy_db_select(db, 2, "com.example/pub") == NULL);
	ATF_CHECK(notify_policy_db_select(db, UINT32_MAX, "x") == NULL);
	ATF_CHECK(notify_policy_db_select(NULL, NOTIFY_TIER_OPEN, "x") == NULL);
	free(db);
}

ATF_TC_WITHOUT_HEAD(load_rejects_unsafe_files);
ATF_TC_BODY(load_rejects_unsafe_files, tc)
{
	static const char policy[] = "{clients={};}";
	struct notify_policy_db db;
	char nul_policy[sizeof(policy)];
	int fd;

	(void)tc;
	fd = open("bsdnotify.conf",
	    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(sizeof(policy) - 1,
	    write(fd, policy, sizeof(policy) - 1));
	close(fd);
	ATF_REQUIRE_EQ(0, notify_policy_db_load("bsdnotify.conf", &db));
	ATF_REQUIRE_EQ(0, chmod("bsdnotify.conf", 0666));
	ATF_CHECK_ERRNO(EPERM,
	    notify_policy_db_load("bsdnotify.conf", &db) == -1);
	ATF_REQUIRE_EQ(0, chmod("bsdnotify.conf", 0600));
	ATF_REQUIRE_EQ(0, symlink("bsdnotify.conf", "policy-link.conf"));
	ATF_CHECK(notify_policy_db_load("policy-link.conf", &db) == -1);
	ATF_CHECK(errno == ELOOP || errno == EMLINK);
	ATF_REQUIRE_EQ(0, mkdir("policy-directory", 0700));
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_db_load("policy-directory", &db) == -1);
	fd = open("large.conf",
	    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, ftruncate(fd, NOTIFY_POLICY_FILE_MAX + 1));
	close(fd);
	ATF_CHECK_ERRNO(EFBIG,
	    notify_policy_db_load("large.conf", &db) == -1);
	memcpy(nul_policy, policy, sizeof(policy));
	nul_policy[2] = '\0';
	fd = open("nul.conf",
	    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(sizeof(nul_policy),
	    write(fd, nul_policy, sizeof(nul_policy)));
	close(fd);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_db_load("nul.conf", &db) == -1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, default_deny);
	ATF_TP_ADD_TC(tp, exact_topics);
	ATF_TP_ADD_TC(tp, wildcard);
	ATF_TP_ADD_TC(tp, rejects_invalid_policy);
	ATF_TP_ADD_TC(tp, identity_database);
	ATF_TP_ADD_TC(tp, load_rejects_unsafe_files);
	ATF_TP_ADD_TC(tp, prefix_patterns);
	ATF_TP_ADD_TC(tp, tier_defaults_when_absent);
	ATF_TP_ADD_TC(tp, shipped_defaults_equal_builtins);
	ATF_TP_ADD_TC(tp, tier_blocks_parse);
	ATF_TP_ADD_TC(tp, tier_blocks_reject_invalid);
	ATF_TP_ADD_TC(tp, select_by_tier);
	return (atf_no_error());
}
