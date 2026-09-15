/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <notify_server.h>

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

/*
 * ---------------------------------------------------------------------------
 * Edge-case and negative coverage for the ipc-anointments v1 conf schema
 * (tiers, prefix patterns, limits, selection).  Each case is narrow on
 * purpose so a regression names the rule it broke.
 * ---------------------------------------------------------------------------
 */

static bool
pub(const struct notify_policy *policy, const char *topic)
{

	return (notify_policy_can_publish(policy, topic, strlen(topic)));
}

static bool
sub(const struct notify_policy *policy, const char *topic)
{

	return (notify_policy_can_subscribe(policy, topic, strlen(topic)));
}

/* Build "<segment>.<segment>..." of exactly `length` characters. */
static void
long_topic(char *buffer, size_t length, const char *head)
{
	size_t i, n;

	n = strlcpy(buffer, head, length + 1);
	ATF_REQUIRE(n < length);
	for (i = n; i < length; i++)
		buffer[i] = (i - n) % 8 == 7 ? '.' : 'a' + (char)(i % 26);
	/* never end on a dot: the validator rejects a trailing separator */
	if (buffer[length - 1] == '.')
		buffer[length - 1] = 'z';
	buffer[length] = '\0';
	ATF_REQUIRE_EQ(length, strlen(buffer));
}

/*
 * "user.*" matches user.<one or more segments> of any legal length and
 * nothing else: not the bare prefix, not a dangling dot, not a sibling
 * sharing the first characters, not a case variant.
 */
ATF_TC_WITHOUT_HEAD(prefix_boundary);
ATF_TC_BODY(prefix_boundary, tc)
{
	struct notify_policy policy;
	char topic[NOTIFY_MAX_TOPIC + 2];

	ATF_REQUIRE_EQ(0, notify_policy_parse("{publish=[\"user.*\"];}",
	    &policy));
	ATF_CHECK(pub(&policy, "user.a"));
	ATF_CHECK(pub(&policy, "user.a.b"));
	ATF_CHECK(pub(&policy, "user.a.b.c"));
	ATF_CHECK(pub(&policy, "user.a.b.c.d.e.f.g.h"));
	ATF_CHECK(pub(&policy, "user.A"));
	ATF_CHECK(pub(&policy, "user.a-b_c"));
	ATF_CHECK(pub(&policy, "user.x1"));
	/* longest legal topics under the prefix */
	long_topic(topic, NOTIFY_MAX_TOPIC - 1, "user.");
	ATF_CHECK_EQ(0, notify_validate_topic(topic, NOTIFY_MAX_TOPIC - 1));
	ATF_CHECK(pub(&policy, topic));
	long_topic(topic, NOTIFY_MAX_TOPIC, "user.");
	ATF_CHECK_EQ(0, notify_validate_topic(topic, NOTIFY_MAX_TOPIC));
	ATF_CHECK(pub(&policy, topic));
	/* the shortest possible match is exactly prefix + '.' + 1 */
	ATF_CHECK(pub(&policy, "user.x"));
	ATF_CHECK(!notify_policy_can_publish(&policy, "user.x", 5));
	ATF_CHECK(!notify_policy_can_publish(&policy, "user.x", 4));
	ATF_CHECK(!notify_policy_can_publish(&policy, "user.x", 0));
	/* negatives */
	ATF_CHECK(!pub(&policy, "user"));
	ATF_CHECK(!pub(&policy, "user."));
	ATF_CHECK(!pub(&policy, "users.a"));
	ATF_CHECK(!pub(&policy, "use"));
	ATF_CHECK(!pub(&policy, "use.a"));
	ATF_CHECK(!pub(&policy, "User.a"));
	ATF_CHECK(!pub(&policy, "USER.a"));
	ATF_CHECK(!pub(&policy, "xuser.a"));
	ATF_CHECK(!pub(&policy, ".user.a"));
	ATF_CHECK(!pub(&policy, "user-a"));
	ATF_CHECK(!pub(&policy, "user_a"));
	ATF_CHECK(!pub(&policy, "usera"));
	ATF_CHECK(!pub(&policy, "a.user.b"));
	ATF_CHECK(!pub(&policy, ""));
	/* the pattern only governs the list it appears in */
	ATF_CHECK(!sub(&policy, "user.a"));
	/*
	 * "user..a" is not a topic: the wire validator rejects it before any
	 * policy is consulted.  The matcher itself is not a validator (it
	 * would accept the prefix + '.' + garbage), so the ordering
	 * "validate, then authorize" in the router is load-bearing.
	 */
	ATF_CHECK_ERRNO(EINVAL, notify_validate_topic("user..a", 7) == -1);
	ATF_CHECK_ERRNO(EINVAL, notify_validate_topic("user.", 5) == -1);
	ATF_CHECK_ERRNO(EINVAL, notify_validate_topic("user.a.", 7) == -1);
	ATF_CHECK(pub(&policy, "user..a"));
	/* a case-different pattern likewise never matches the lower case */
	ATF_REQUIRE_EQ(0, notify_policy_parse("{publish=[\"User.*\"];}",
	    &policy));
	ATF_CHECK(pub(&policy, "User.a"));
	ATF_CHECK(!pub(&policy, "user.a"));
	/* a multi-segment prefix binds at the last dot */
	ATF_REQUIRE_EQ(0, notify_policy_parse("{publish=[\"a.b.*\"];}",
	    &policy));
	ATF_CHECK_EQ(3, policy.publish[0].length);
	ATF_CHECK(pub(&policy, "a.b.c"));
	ATF_CHECK(!pub(&policy, "a.b"));
	ATF_CHECK(!pub(&policy, "a.bc.d"));
	ATF_CHECK(!pub(&policy, "a.c"));
}

/* Every '*' placement other than a whole entry or a ".*" suffix is invalid. */
ATF_TC_WITHOUT_HEAD(pattern_forms_rejected);
ATF_TC_BODY(pattern_forms_rejected, tc)
{
	static const char *const bad[] = {
		"*.a", "a.*.b", "a*", "*a", ".*", "*.", "**", "a.**", "",
		"*.*", "a..*", ".", "a.", ".a", "*a.*", "a.*b", "a .*",
		"a.* ", " *", "* ", "a.*.", "..*", "a*.*", "*.a.*", "a/*",
		"a.?", "a.*\n", "\t*", "a.b.*.", "9.*", "a.*a"
	};
	static const char *const keys[] = { "publish", "subscribe" };
	struct notify_policy policy;
	char document[128];
	size_t i, k;

	for (k = 0; k < nitems(keys); k++) {
		for (i = 0; i < nitems(bad); i++) {
			ATF_REQUIRE(snprintf(document, sizeof(document),
			    "{%s=[\"%s\"];}", keys[k], bad[i]) <
			    (int)sizeof(document));
			errno = 0;
			ATF_CHECK_MSG(notify_policy_parse(document,
			    &policy) == -1 && errno == EINVAL,
			    "%s accepted or wrong errno (%d)", document, errno);
		}
		/* a bare "*" is the whole-list wildcard, never a pattern */
		ATF_REQUIRE(snprintf(document, sizeof(document),
		    "{%s=[\"*\"];}", keys[k]) < (int)sizeof(document));
		ATF_REQUIRE_EQ(0, notify_policy_parse(document, &policy));
		if (k == 0) {
			ATF_CHECK(policy.publish_all);
			ATF_CHECK_EQ(0, policy.npublish);
			ATF_CHECK(!policy.subscribe_all);
			ATF_CHECK(pub(&policy, "a"));
			ATF_CHECK(pub(&policy, "user.x"));
			ATF_CHECK(pub(&policy, "system.x.y"));
			ATF_CHECK(!sub(&policy, "a"));
		} else {
			ATF_CHECK(policy.subscribe_all);
			ATF_CHECK_EQ(0, policy.nsubscribe);
			ATF_CHECK(!policy.publish_all);
			ATF_CHECK(sub(&policy, "system.x.y"));
			ATF_CHECK(!pub(&policy, "a"));
		}
	}
	/* a single bad entry poisons the whole block, later ones included */
	ATF_CHECK_ERRNO(EINVAL, notify_policy_parse(
	    "{publish=[\"ok.x\",\"*.bad\",\"ok.y\"];}", &policy) == -1);
	/* and a non-string entry, wherever it sits */
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{publish=[\"ok.x\",1];}", &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{publish=[true];}", &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{publish=[[\"a.b\"]];}", &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{publish=[{a=\"b\"}];}", &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_parse("{publish=[null];}", &policy) == -1);
	/* an empty list is legal and means "nothing" */
	ATF_REQUIRE_EQ(0, notify_policy_parse("{publish=[];subscribe=[];}",
	    &policy));
	ATF_CHECK_EQ(0, policy.npublish);
	ATF_CHECK(!policy.publish_all);
	ATF_CHECK(!pub(&policy, "a"));
}

/*
 * Topic length at the wire limit.  NOTIFY_MAX_TOPIC characters is the
 * longest a request can carry (the topic field has no NUL), so an exact
 * entry of that length is accepted and matches; one more is rejected.  A
 * prefix pattern whose prefix is already the maximum can never match a
 * legal topic (it would need prefix + 2), but it is not a parse error.
 */
ATF_TC_WITHOUT_HEAD(topic_length_limits);
ATF_TC_BODY(topic_length_limits, tc)
{
	struct notify_policy policy;
	char topic[NOTIFY_MAX_TOPIC + 8], document[NOTIFY_MAX_TOPIC + 64];

	/* NOTIFY_MAX_TOPIC - 1 */
	long_topic(topic, NOTIFY_MAX_TOPIC - 1, "t.");
	ATF_REQUIRE(snprintf(document, sizeof(document), "{publish=[\"%s\"];}",
	    topic) < (int)sizeof(document));
	ATF_REQUIRE_EQ(0, notify_policy_parse(document, &policy));
	ATF_CHECK_EQ(1, policy.npublish);
	ATF_CHECK(!policy.publish[0].prefix);
	ATF_CHECK_EQ(NOTIFY_MAX_TOPIC - 1, policy.publish[0].length);
	ATF_CHECK(pub(&policy, topic));
	topic[NOTIFY_MAX_TOPIC - 2] = '\0';
	ATF_CHECK(!pub(&policy, topic));
	/* NOTIFY_MAX_TOPIC exactly: the wire maximum, still a topic */
	long_topic(topic, NOTIFY_MAX_TOPIC, "t.");
	ATF_CHECK_EQ(0, notify_validate_topic(topic, NOTIFY_MAX_TOPIC));
	ATF_REQUIRE(snprintf(document, sizeof(document), "{publish=[\"%s\"];}",
	    topic) < (int)sizeof(document));
	ATF_REQUIRE_EQ(0, notify_policy_parse(document, &policy));
	ATF_CHECK_EQ(NOTIFY_MAX_TOPIC, policy.publish[0].length);
	ATF_CHECK(pub(&policy, topic));
	ATF_CHECK(!notify_policy_can_publish(&policy, topic,
	    NOTIFY_MAX_TOPIC - 1));
	/* NOTIFY_MAX_TOPIC + 1: never a topic, rejected at parse */
	long_topic(topic, NOTIFY_MAX_TOPIC + 1, "t.");
	ATF_CHECK_ERRNO(EINVAL,
	    notify_validate_topic(topic, NOTIFY_MAX_TOPIC + 1) == -1);
	ATF_REQUIRE(snprintf(document, sizeof(document), "{publish=[\"%s\"];}",
	    topic) < (int)sizeof(document));
	ATF_CHECK_ERRNO(EINVAL, notify_policy_parse(document, &policy) == -1);
	ATF_REQUIRE(snprintf(document, sizeof(document),
	    "{subscribe=[\"%s\"];}", topic) < (int)sizeof(document));
	ATF_CHECK_ERRNO(EINVAL, notify_policy_parse(document, &policy) == -1);

	/* prefix patterns: prefix of MAX-2 matches a MAX-length topic */
	long_topic(topic, NOTIFY_MAX_TOPIC - 2, "p.");
	ATF_REQUIRE(snprintf(document, sizeof(document),
	    "{publish=[\"%s.*\"];}", topic) < (int)sizeof(document));
	ATF_REQUIRE_EQ(0, notify_policy_parse(document, &policy));
	ATF_CHECK(policy.publish[0].prefix);
	ATF_CHECK_EQ(NOTIFY_MAX_TOPIC - 2, policy.publish[0].length);
	topic[NOTIFY_MAX_TOPIC - 2] = '.';
	topic[NOTIFY_MAX_TOPIC - 1] = 'x';
	topic[NOTIFY_MAX_TOPIC] = '\0';
	ATF_CHECK_EQ(0, notify_validate_topic(topic, NOTIFY_MAX_TOPIC));
	ATF_CHECK(pub(&policy, topic));
	/* prefix of MAX: parses, but no legal topic can match it */
	long_topic(topic, NOTIFY_MAX_TOPIC, "p.");
	ATF_REQUIRE(snprintf(document, sizeof(document),
	    "{publish=[\"%s.*\"];}", topic) < (int)sizeof(document));
	ATF_REQUIRE_EQ(0, notify_policy_parse(document, &policy));
	ATF_CHECK_EQ(NOTIFY_MAX_TOPIC, policy.publish[0].length);
	ATF_CHECK(!pub(&policy, topic));
	/* prefix of MAX + 1: rejected like any over-long topic */
	long_topic(topic, NOTIFY_MAX_TOPIC + 1, "p.");
	ATF_REQUIRE(snprintf(document, sizeof(document),
	    "{publish=[\"%s.*\"];}", topic) < (int)sizeof(document));
	ATF_CHECK_ERRNO(EINVAL, notify_policy_parse(document, &policy) == -1);
}

/* "*" is exclusive: it cannot share a list with named entries or patterns. */
ATF_TC_WITHOUT_HEAD(mixing_all_with_named_rejected);
ATF_TC_BODY(mixing_all_with_named_rejected, tc)
{
	static const char *const lists[] = {
		"[\"*\",\"user.*\"]", "[\"user.*\",\"*\"]",
		"[\"*\",\"a.b\"]", "[\"a.b\",\"*\"]",
		"[\"*\",\"*\"]", "[\"a.b\",\"*\",\"c.d\"]",
		"[\"*\",\"a.*\",\"*\"]"
	};
	struct notify_policy policy;
	char document[128];
	size_t i;

	for (i = 0; i < nitems(lists); i++) {
		ATF_REQUIRE(snprintf(document, sizeof(document),
		    "{publish=%s;}", lists[i]) < (int)sizeof(document));
		errno = 0;
		ATF_CHECK_MSG(notify_policy_parse(document, &policy) == -1 &&
		    errno == EINVAL, "%s accepted or wrong errno (%d)",
		    document, errno);
		ATF_REQUIRE(snprintf(document, sizeof(document),
		    "{subscribe=%s;}", lists[i]) < (int)sizeof(document));
		errno = 0;
		ATF_CHECK_MSG(notify_policy_parse(document, &policy) == -1 &&
		    errno == EINVAL, "%s accepted or wrong errno (%d)",
		    document, errno);
	}
	/* the two lists are independent: "*" in one, names in the other */
	ATF_REQUIRE_EQ(0, notify_policy_parse(
	    "{publish=[\"*\"];subscribe=[\"user.*\",\"a.b\"];}", &policy));
	ATF_CHECK(policy.publish_all);
	ATF_CHECK(!policy.subscribe_all);
	ATF_CHECK_EQ(2, policy.nsubscribe);
	ATF_CHECK(pub(&policy, "anything"));
	ATF_CHECK(sub(&policy, "user.q"));
	ATF_CHECK(sub(&policy, "a.b"));
	ATF_CHECK(!sub(&policy, "anything"));
}

/* Duplicates are EEXIST; different forms sharing a prefix coexist. */
ATF_TC_WITHOUT_HEAD(duplicate_and_overlapping_entries);
ATF_TC_BODY(duplicate_and_overlapping_entries, tc)
{
	struct notify_policy policy;

	ATF_CHECK_ERRNO(EEXIST, notify_policy_parse(
	    "{publish=[\"user.*\",\"user.*\"];}", &policy) == -1);
	ATF_CHECK_ERRNO(EEXIST, notify_policy_parse(
	    "{subscribe=[\"user.*\",\"user.*\"];}", &policy) == -1);
	ATF_CHECK_ERRNO(EEXIST, notify_policy_parse(
	    "{publish=[\"user.x\",\"user.x\"];}", &policy) == -1);
	ATF_CHECK_ERRNO(EEXIST, notify_policy_parse(
	    "{publish=[\"a.*\",\"b.c\",\"a.*\"];}", &policy) == -1);
	/* the duplicate check is exact: case and length matter */
	ATF_REQUIRE_EQ(0, notify_policy_parse(
	    "{publish=[\"user.*\",\"User.*\",\"users.*\"];}", &policy));
	ATF_CHECK_EQ(3, policy.npublish);
	/* pattern plus exact under it: both live, both match their own */
	ATF_REQUIRE_EQ(0, notify_policy_parse(
	    "{publish=[\"user.*\",\"user.x\"];}", &policy));
	ATF_CHECK_EQ(2, policy.npublish);
	ATF_CHECK(pub(&policy, "user.x"));
	ATF_CHECK(pub(&policy, "user.y"));
	ATF_CHECK(pub(&policy, "user.x.z"));
	ATF_CHECK(!pub(&policy, "user"));
	/* order-independent */
	ATF_REQUIRE_EQ(0, notify_policy_parse(
	    "{publish=[\"user.x\",\"user.*\"];}", &policy));
	ATF_CHECK_EQ(2, policy.npublish);
	ATF_CHECK(pub(&policy, "user.x"));
	ATF_CHECK(pub(&policy, "user.y"));
	/* nested patterns: the wider one wins nothing extra, both match */
	ATF_REQUIRE_EQ(0, notify_policy_parse(
	    "{publish=[\"a.*\",\"a.b.*\"];}", &policy));
	ATF_CHECK_EQ(2, policy.npublish);
	ATF_CHECK(pub(&policy, "a.b.c"));
	ATF_CHECK(pub(&policy, "a.c"));
	ATF_CHECK(pub(&policy, "a.b"));	/* via "a.*" */
	ATF_CHECK(!pub(&policy, "a"));
	/* the same name in both lists is not a duplicate */
	ATF_REQUIRE_EQ(0, notify_policy_parse(
	    "{publish=[\"a.*\"];subscribe=[\"a.*\"];}", &policy));
	ATF_CHECK(pub(&policy, "a.b") && sub(&policy, "a.b"));
}

/* NOTIFY_POLICY_TOPIC_MAX entries per list; one more is EINVAL. */
ATF_TC_WITHOUT_HEAD(prefix_count_limit);
ATF_TC_BODY(prefix_count_limit, tc)
{
	struct notify_policy policy;
	char *document;
	size_t i, offset, size;

	size = 64 * (NOTIFY_POLICY_TOPIC_MAX + 2) * 2;
	document = malloc(size);
	ATF_REQUIRE(document != NULL);
	/* exactly the limit, all prefixes */
	offset = (size_t)snprintf(document, size, "{publish=[");
	for (i = 0; i < NOTIFY_POLICY_TOPIC_MAX; i++)
		offset += (size_t)snprintf(document + offset, size - offset,
		    "%s\"p%zu.*\"", i == 0 ? "" : ",", i);
	offset += (size_t)snprintf(document + offset, size - offset, "];}");
	ATF_REQUIRE(offset < size);
	ATF_REQUIRE_EQ(0, notify_policy_parse(document, &policy));
	ATF_CHECK_EQ(NOTIFY_POLICY_TOPIC_MAX, policy.npublish);
	ATF_CHECK(pub(&policy, "p0.x"));
	ATF_CHECK(pub(&policy, "p63.x"));
	ATF_CHECK(!pub(&policy, "p64.x"));
	/* the same list in both keys: the limit is per list */
	offset = (size_t)snprintf(document, size, "{publish=[");
	for (i = 0; i < NOTIFY_POLICY_TOPIC_MAX; i++)
		offset += (size_t)snprintf(document + offset, size - offset,
		    "%s\"p%zu.*\"", i == 0 ? "" : ",", i);
	offset += (size_t)snprintf(document + offset, size - offset,
	    "];subscribe=[");
	for (i = 0; i < NOTIFY_POLICY_TOPIC_MAX; i++)
		offset += (size_t)snprintf(document + offset, size - offset,
		    "%s\"s%zu\"", i == 0 ? "" : ",", i);
	offset += (size_t)snprintf(document + offset, size - offset, "];}");
	ATF_REQUIRE(offset < size);
	ATF_REQUIRE_EQ(0, notify_policy_parse(document, &policy));
	ATF_CHECK_EQ(NOTIFY_POLICY_TOPIC_MAX, policy.npublish);
	ATF_CHECK_EQ(NOTIFY_POLICY_TOPIC_MAX, policy.nsubscribe);
	/* limit + 1 (prefix appended) */
	offset = (size_t)snprintf(document, size, "{publish=[");
	for (i = 0; i < NOTIFY_POLICY_TOPIC_MAX + 1; i++)
		offset += (size_t)snprintf(document + offset, size - offset,
		    "%s\"p%zu.*\"", i == 0 ? "" : ",", i);
	offset += (size_t)snprintf(document + offset, size - offset, "];}");
	ATF_REQUIRE(offset < size);
	ATF_CHECK_ERRNO(EINVAL, notify_policy_parse(document, &policy) == -1);
	/* limit + 1 where the extra entry is an exact name */
	offset = (size_t)snprintf(document, size, "{subscribe=[");
	for (i = 0; i < NOTIFY_POLICY_TOPIC_MAX; i++)
		offset += (size_t)snprintf(document + offset, size - offset,
		    "%s\"p%zu.*\"", i == 0 ? "" : ",", i);
	offset += (size_t)snprintf(document + offset, size - offset,
	    ",\"extra\"];}");
	ATF_REQUIRE(offset < size);
	ATF_CHECK_ERRNO(EINVAL, notify_policy_parse(document, &policy) == -1);
	/* a trailing "*" past the limit is still the mixing error, not E2BIG */
	offset = (size_t)snprintf(document, size, "{publish=[");
	for (i = 0; i < NOTIFY_POLICY_TOPIC_MAX; i++)
		offset += (size_t)snprintf(document + offset, size - offset,
		    "%s\"p%zu.*\"", i == 0 ? "" : ",", i);
	offset += (size_t)snprintf(document + offset, size - offset,
	    ",\"*\"];}");
	ATF_CHECK_ERRNO(EINVAL, notify_policy_parse(document, &policy) == -1);
	free(document);
}

/* Wrong value shapes anywhere in the tree are EINVAL. */
ATF_TC_WITHOUT_HEAD(block_shapes_rejected);
ATF_TC_BODY(block_shapes_rejected, tc)
{
	static const char *const bad[] = {
		"default = \"x\";", "default = [];", "default = 1;",
		"default = true;", "default = null;", "default = [{}];",
		"system_default = \"x\";", "system_default = [];",
		"system_default = 0;", "system_default = false;",
		"system_default = null;",
		"clients = \"x\";", "clients = [];", "clients = 1;",
		"clients = null;", "clients = [{}];",
		/* unknown keys inside a client entry */
		"clients { \"a.b/c\" { unknown = true; } }",
		"clients { \"a.b/c\" { Publish = [\"a.b\"]; } }",
		"clients { \"a.b/c\" { publish = [\"a.b\"]; extra = 1; } }",
		"clients { \"a.b/c\" { timer = true; } }",
		"clients { \"a.b/c\" { default { } } }",
		/* wrong value types inside tier blocks */
		"default { timers = \"yes\"; }",
		"default { timers = \"true\"; }",
		"default { timers = 1; }",
		"default { timers = null; }",
		"default { timers = [true]; }",
		"default { timers = { on = true; }; }",
		"system_default { timers = \"yes\"; }",
		"system_default { timers = 0; }",
		"default { publish = \"user.*\"; }",
		"default { publish = { a = \"b\"; }; }",
		"default { publish = true; }",
		"default { subscribe = null; }",
		"system_default { subscribe = \"*\"; }",
		/* unknown keys inside tier blocks */
		"default { clients {} }",
		"default { system_default {} }",
		"system_default { default {} }",
		"default { publish = []; PUBLISH = []; }",
		/* not an object at the top */
		"[]", "\"x\"", "1", "true", "[default {}]",
		/* syntax */
		"default {", "default }", "default { publish = [ }",
		"clients { \"a.b/c\" { }", "{",
	};
	struct notify_policy_db *db;
	size_t i;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	for (i = 0; i < nitems(bad); i++) {
		errno = 0;
		ATF_CHECK_MSG(notify_policy_db_parse(bad[i], db) == -1 &&
		    errno == EINVAL, "%s accepted or wrong errno (%d)",
		    bad[i], errno);
	}
	/* UCL boolean spellings are booleans, so these are legal */
	ATF_REQUIRE_EQ(0, notify_policy_db_parse("default { timers = yes; }",
	    db));
	ATF_CHECK(db->open_default.timers);
	ATF_REQUIRE_EQ(0, notify_policy_db_parse("default { timers = on; }",
	    db));
	ATF_CHECK(db->open_default.timers);
	ATF_REQUIRE_EQ(0, notify_policy_db_parse("default { timers = no; }",
	    db));
	ATF_CHECK(!db->open_default.timers);
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "system_default { timers = off; }", db));
	ATF_CHECK(!db->system_default.timers);
	free(db);
}

/*
 * notify_policy_db_select_source(): the block that answered, as the router
 * reports it on the tier-policy probe.  Selection is identical to
 * notify_policy_db_select(); *source is always set, never left NULL (the
 * probe copies it), and is "unknown" whenever no policy is returned.
 */
ATF_TC_WITHOUT_HEAD(select_source_names_block);
ATF_TC_BODY(select_source_names_block, tc)
{
	static const uint32_t tiers[] = { NOTIFY_TIER_OPEN, NOTIFY_TIER_SYSTEM,
	    2, UINT32_MAX };
	static const char *const labels[] = { "com.example/pub", "org.other/x",
	    "com.example/Pub", "", NULL };
	struct notify_policy_db *db;
	const struct notify_policy *policy;
	const char *source;
	unsigned i, j;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "clients { \"com.example/pub\" { publish = [\"system.shutdown.*\"]; } }",
	    db));

	/* Open tier: always "default", listed label or not. */
	source = NULL;
	policy = notify_policy_db_select_source(db, NOTIFY_TIER_OPEN,
	    "com.example/pub", &source);
	ATF_CHECK(policy == &db->open_default);
	ATF_CHECK_STREQ("default", source);
	source = NULL;
	policy = notify_policy_db_select_source(db, NOTIFY_TIER_OPEN, NULL,
	    &source);
	ATF_CHECK(policy == &db->open_default);
	ATF_CHECK_STREQ("default", source);

	/* System tier: the clients{} entry, else "system_default". */
	source = NULL;
	policy = notify_policy_db_select_source(db, NOTIFY_TIER_SYSTEM,
	    "com.example/pub", &source);
	ATF_CHECK(policy == notify_policy_db_lookup(db, "com.example/pub"));
	ATF_CHECK_STREQ("clients", source);
	source = NULL;
	policy = notify_policy_db_select_source(db, NOTIFY_TIER_SYSTEM,
	    "org.other/x", &source);
	ATF_CHECK(policy == &db->system_default);
	ATF_CHECK_STREQ("system_default", source);
	source = NULL;
	policy = notify_policy_db_select_source(db, NOTIFY_TIER_SYSTEM, NULL,
	    &source);
	ATF_CHECK(policy == &db->system_default);
	ATF_CHECK_STREQ("system_default", source);
	/* Exact label match only: a case variant is not "clients". */
	source = NULL;
	policy = notify_policy_db_select_source(db, NOTIFY_TIER_SYSTEM,
	    "com.example/Pub", &source);
	ATF_CHECK(policy == &db->system_default);
	ATF_CHECK_STREQ("system_default", source);

	/* Unknown tier or no database: NULL policy and "unknown". */
	source = NULL;
	ATF_CHECK(notify_policy_db_select_source(db, 2, "com.example/pub",
	    &source) == NULL);
	ATF_CHECK_STREQ("unknown", source);
	source = NULL;
	ATF_CHECK(notify_policy_db_select_source(db, UINT32_MAX, "x",
	    &source) == NULL);
	ATF_CHECK_STREQ("unknown", source);
	source = NULL;
	ATF_CHECK(notify_policy_db_select_source(NULL, NOTIFY_TIER_OPEN, "x",
	    &source) == NULL);
	ATF_CHECK_STREQ("unknown", source);
	source = NULL;
	ATF_CHECK(notify_policy_db_select_source(NULL, NOTIFY_TIER_SYSTEM,
	    "com.example/pub", &source) == NULL);
	ATF_CHECK_STREQ("unknown", source);

	/* The two entry points agree everywhere, and a source is always one
	 * of the four documented strings. */
	for (i = 0; i < nitems(tiers); i++) {
		for (j = 0; j < nitems(labels); j++) {
			source = NULL;
			policy = notify_policy_db_select_source(db, tiers[i],
			    labels[j], &source);
			ATF_CHECK_MSG(policy == notify_policy_db_select(db,
			    tiers[i], labels[j]),
			    "tier %u label %s: select and select_source differ",
			    tiers[i], labels[j] != NULL ? labels[j] : "(null)");
			ATF_REQUIRE(source != NULL);
			ATF_CHECK_MSG(strcmp(source, "default") == 0 ||
			    strcmp(source, "system_default") == 0 ||
			    strcmp(source, "clients") == 0 ||
			    strcmp(source, "unknown") == 0,
			    "unexpected source '%s'", source);
			ATF_CHECK_EQ_MSG(policy == NULL,
			    strcmp(source, "unknown") == 0,
			    "tier %u label %s: source '%s' with %s policy",
			    tiers[i], labels[j] != NULL ? labels[j] : "(null)",
			    source, policy == NULL ? "no" : "a");
		}
	}
	free(db);
}

/* notify_policy_db_select() edge cases: tiers, labels, missing db. */
ATF_TC_WITHOUT_HEAD(select_edge_cases);
ATF_TC_BODY(select_edge_cases, tc)
{
	struct notify_policy_db *db;
	const struct notify_policy *policy, *entry;
	char long_label[NOTIFY_MAX_PUBLISHER + 2];

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "default { publish = [\"open.*\"]; }"
	    "system_default { publish = [\"sys.*\"]; timers = true; }"
	    "clients { \"com.example/listed\" { subscribe = [\"only.this\"]; } }",
	    db));
	entry = notify_policy_db_lookup(db, "com.example/listed");
	ATF_REQUIRE(entry != NULL);

	/* tier 0: the label being listed changes nothing */
	policy = notify_policy_db_select(db, NOTIFY_TIER_OPEN,
	    "com.example/listed");
	ATF_CHECK(policy == &db->open_default);
	ATF_CHECK(pub(policy, "open.x"));
	ATF_CHECK(!sub(policy, "only.this"));
	ATF_CHECK(!policy->timers);
	ATF_CHECK(notify_policy_db_select(db, NOTIFY_TIER_OPEN, "") ==
	    &db->open_default);
	ATF_CHECK(notify_policy_db_select(db, NOTIFY_TIER_OPEN, NULL) ==
	    &db->open_default);
	/* tier 1: listed -> entry; otherwise system_default */
	policy = notify_policy_db_select(db, NOTIFY_TIER_SYSTEM,
	    "com.example/listed");
	ATF_CHECK(policy == entry);
	ATF_CHECK(sub(policy, "only.this"));
	ATF_CHECK(!pub(policy, "sys.x"));
	ATF_CHECK(!policy->timers);
	policy = notify_policy_db_select(db, NOTIFY_TIER_SYSTEM,
	    "com.example/unlisted");
	ATF_CHECK(policy == &db->system_default);
	ATF_CHECK(pub(policy, "sys.x"));
	ATF_CHECK(policy->timers);
	/* label matching is exact: prefix, suffix, case, embedded NUL-free */
	ATF_CHECK(notify_policy_db_select(db, NOTIFY_TIER_SYSTEM,
	    "com.example/liste") == &db->system_default);
	ATF_CHECK(notify_policy_db_select(db, NOTIFY_TIER_SYSTEM,
	    "com.example/listedx") == &db->system_default);
	ATF_CHECK(notify_policy_db_select(db, NOTIFY_TIER_SYSTEM,
	    "Com.example/listed") == &db->system_default);
	ATF_CHECK(notify_policy_db_select(db, NOTIFY_TIER_SYSTEM,
	    "com.example/listed/") == &db->system_default);
	ATF_CHECK(notify_policy_db_select(db, NOTIFY_TIER_SYSTEM,
	    "/com.example/listed") == &db->system_default);
	ATF_CHECK(notify_policy_db_select(db, NOTIFY_TIER_SYSTEM,
	    " com.example/listed") == &db->system_default);
	/* NULL and empty labels on the system tier fall to system_default */
	ATF_CHECK(notify_policy_db_select(db, NOTIFY_TIER_SYSTEM, NULL) ==
	    &db->system_default);
	ATF_CHECK(notify_policy_db_select(db, NOTIFY_TIER_SYSTEM, "") ==
	    &db->system_default);
	/* an over-long label cannot match anything */
	memset(long_label, 'a', sizeof(long_label));
	long_label[3] = '/';
	long_label[sizeof(long_label) - 1] = '\0';
	ATF_CHECK(notify_policy_db_select(db, NOTIFY_TIER_SYSTEM,
	    long_label) == &db->system_default);
	/* unknown tiers: NULL regardless of label (admission fails closed) */
	ATF_CHECK(notify_policy_db_select(db, 2, "com.example/listed") == NULL);
	ATF_CHECK(notify_policy_db_select(db, 2, NULL) == NULL);
	ATF_CHECK(notify_policy_db_select(db, 255, "x") == NULL);
	ATF_CHECK(notify_policy_db_select(db, (uint32_t)-1, "x") == NULL);
	ATF_CHECK(notify_policy_db_select(db, UINT32_MAX, NULL) == NULL);
	ATF_CHECK(notify_policy_db_select(db, 0x80000000U, "x") == NULL);
	ATF_CHECK(notify_policy_db_select(db, 0x10000U, "x") == NULL);
	/* no database: NULL on every tier */
	ATF_CHECK(notify_policy_db_select(NULL, NOTIFY_TIER_OPEN, "x") == NULL);
	ATF_CHECK(notify_policy_db_select(NULL, NOTIFY_TIER_SYSTEM, "x") ==
	    NULL);
	ATF_CHECK(notify_policy_db_select(NULL, NOTIFY_TIER_SYSTEM, NULL) ==
	    NULL);
	ATF_CHECK(notify_policy_db_select(NULL, 2, NULL) == NULL);
	/* and the matchers themselves fail closed on a NULL policy */
	ATF_CHECK(!notify_policy_can_publish(NULL, "a", 1));
	ATF_CHECK(!notify_policy_can_subscribe(NULL, "a", 1));
	/* the lookup helper never sees the open tier's defaults */
	ATF_CHECK(notify_policy_db_lookup(db, "default") == NULL);
	ATF_CHECK(notify_policy_db_lookup(db, "system_default") == NULL);
	ATF_CHECK(notify_policy_db_lookup(db, NULL) == NULL);
	ATF_CHECK(notify_policy_db_lookup(NULL, "com.example/listed") == NULL);
	free(db);
}

/*
 * An explicit tier block replaces the builtin wholesale: whatever it does
 * not grant is denied.  So "default {}" is deny-all and
 * "system_default { timers = false; }" grants nothing at all.
 */
ATF_TC_WITHOUT_HEAD(explicit_blocks_replace_builtins);
ATF_TC_BODY(explicit_blocks_replace_builtins, tc)
{
	struct notify_policy_db *db;
	const struct notify_policy *policy;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	/* default {} : deny-all on the open tier */
	ATF_REQUIRE_EQ(0, notify_policy_db_parse("default {}", db));
	ATF_CHECK(db->has_default);
	policy = notify_policy_db_select(db, NOTIFY_TIER_OPEN, "any/label");
	ATF_REQUIRE(policy == &db->open_default);
	ATF_CHECK(!policy->subscribe_all && !policy->publish_all);
	ATF_CHECK_EQ(0, policy->npublish);
	ATF_CHECK_EQ(0, policy->nsubscribe);
	ATF_CHECK(!policy->timers);
	ATF_CHECK(!sub(policy, "system.shutdown.x"));
	ATF_CHECK(!sub(policy, "anything"));
	ATF_CHECK(!pub(policy, "user.x"));
	ATF_CHECK(!pub(policy, "user.me.x"));
	/* the system tier is untouched by that */
	check_builtin_system(&db->system_default);

	/* system_default { timers = false; } : nothing else is inherited */
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "system_default { timers = false; }", db));
	ATF_CHECK(db->has_system_default);
	policy = notify_policy_db_select(db, NOTIFY_TIER_SYSTEM, "com.x/y");
	ATF_REQUIRE(policy == &db->system_default);
	ATF_CHECK(!policy->timers);
	ATF_CHECK(!policy->publish_all && !policy->subscribe_all);
	ATF_CHECK(!pub(policy, "system.x"));
	ATF_CHECK(!pub(policy, "user.x"));
	ATF_CHECK(!sub(policy, "system.x"));
	check_builtin_open(&db->open_default);

	/* system_default { timers = true; } : timers only */
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "system_default { timers = true; }", db));
	policy = &db->system_default;
	ATF_CHECK(policy->timers);
	ATF_CHECK(!pub(policy, "system.x"));
	ATF_CHECK(!sub(policy, "system.x"));

	/* default { subscribe = ["*"]; } : the builtin user.* is NOT kept */
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "default { subscribe = [\"*\"]; }", db));
	policy = &db->open_default;
	ATF_CHECK(policy->subscribe_all);
	ATF_CHECK(!pub(policy, "user.x"));
	ATF_CHECK(!policy->timers);

	/* default { publish = ["user.*"]; } : the builtin subscribe-all is NOT kept */
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "default { publish = [\"user.*\"]; }", db));
	policy = &db->open_default;
	ATF_CHECK(pub(policy, "user.x"));
	ATF_CHECK(!sub(policy, "user.x"));
	ATF_CHECK(!sub(policy, "system.x"));

	/* an explicit empty clients{} beside explicit blocks changes nothing */
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "default {} system_default {} clients {}", db));
	ATF_CHECK_EQ(0, db->nclients);
	ATF_CHECK(!pub(notify_policy_db_select(db, NOTIFY_TIER_SYSTEM,
	    "com.x/y"), "system.x"));
	ATF_CHECK(!pub(notify_policy_db_select(db, NOTIFY_TIER_OPEN,
	    "com.x/y"), "user.x"));
	free(db);
}

/* has_default / has_system_default reflect block presence, not content. */
ATF_TC_WITHOUT_HEAD(has_flags_track_presence);
ATF_TC_BODY(has_flags_track_presence, tc)
{
	struct notify_policy_db *db;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	/* only clients{} */
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "clients { \"a.b/c\" { timers = true; } }", db));
	ATF_CHECK(!db->has_default);
	ATF_CHECK(!db->has_system_default);
	ATF_CHECK_EQ(1, db->nclients);
	check_builtin_open(&db->open_default);
	check_builtin_system(&db->system_default);
	/* only default{} */
	ATF_REQUIRE_EQ(0, notify_policy_db_parse("default {}", db));
	ATF_CHECK(db->has_default);
	ATF_CHECK(!db->has_system_default);
	ATF_CHECK_EQ(0, db->nclients);
	check_builtin_system(&db->system_default);
	/* only system_default{} */
	ATF_REQUIRE_EQ(0, notify_policy_db_parse("system_default {}", db));
	ATF_CHECK(!db->has_default);
	ATF_CHECK(db->has_system_default);
	check_builtin_open(&db->open_default);
	/* a block spelled out identically to the builtin is still explicit */
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "default { subscribe = [\"*\"]; publish = [\"user.*\"]; }", db));
	ATF_CHECK(db->has_default);
	check_builtin_open(&db->open_default);
	/* re-parsing into the same db resets the flags */
	ATF_REQUIRE_EQ(0, notify_policy_db_parse("", db));
	ATF_CHECK(!db->has_default);
	ATF_CHECK(!db->has_system_default);
	ATF_CHECK_EQ(0, db->nclients);
	/* comments-only documents are blank documents */
	ATF_REQUIRE_EQ(0, notify_policy_db_parse("# nothing here\n", db));
	ATF_CHECK(!db->has_default && !db->has_system_default);
	check_builtin_open(&db->open_default);
	ATF_REQUIRE_EQ(0, notify_policy_db_parse("/* nothing */", db));
	ATF_CHECK(!db->has_default && !db->has_system_default);
	free(db);
}

/* Label rules inside clients{}: separator required, bounded, charset. */
ATF_TC_WITHOUT_HEAD(client_label_validation);
ATF_TC_BODY(client_label_validation, tc)
{
	static const char *const bad[] = {
		"com.example", "noslash", "ab", "/a.b", "a.b/", "a//b",
		"a/b/", "/", "//", "a b/c", "a\tb/c", "a/b\n", "a.b/c;d",
		"a.b/c:d", "a.b/c@d", "a.b/c*", "a.b/c.*", "\xc3\xa9/x",
		"a.b/c$", "a.b/c#d", "a.b/c|d"
	};
	static const char *const good[] = {
		"a/b", "a.b/c", "A.B/C", "org.5bsd/unit-1_x", "a/b/c",
		"a.b.c.d/e.f.g.h", "0.1/2", "-/-", "_/_", "a.b/c-d_e.f"
	};
	struct notify_policy_db *db;
	char label[NOTIFY_MAX_PUBLISHER + 2], document[NOTIFY_MAX_PUBLISHER + 64];
	size_t i;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	for (i = 0; i < nitems(bad); i++) {
		ATF_REQUIRE(snprintf(document, sizeof(document),
		    "clients { \"%s\" {} }", bad[i]) < (int)sizeof(document));
		errno = 0;
		ATF_CHECK_MSG(notify_policy_db_parse(document, db) == -1 &&
		    errno == EINVAL, "label %s accepted or wrong errno (%d)",
		    bad[i], errno);
	}
	for (i = 0; i < nitems(good); i++) {
		ATF_REQUIRE(snprintf(document, sizeof(document),
		    "clients { \"%s\" { timers = true; } }", good[i]) <
		    (int)sizeof(document));
		ATF_CHECK_MSG(notify_policy_db_parse(document, db) == 0,
		    "label %s rejected (%d)", good[i], errno);
		ATF_CHECK_EQ(1, db->nclients);
		ATF_CHECK_STREQ(good[i], db->clients[0].label);
		ATF_CHECK(notify_policy_db_lookup(db, good[i]) != NULL);
	}
	/* NOTIFY_MAX_PUBLISHER characters fit; one more does not */
	memset(label, 'a', NOTIFY_MAX_PUBLISHER);
	label[1] = '/';
	label[NOTIFY_MAX_PUBLISHER] = '\0';
	ATF_REQUIRE(snprintf(document, sizeof(document), "clients { \"%s\" {} }",
	    label) < (int)sizeof(document));
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(document, db));
	ATF_CHECK_EQ(NOTIFY_MAX_PUBLISHER, strlen(db->clients[0].label));
	ATF_CHECK(notify_policy_db_select(db, NOTIFY_TIER_SYSTEM, label) ==
	    &db->clients[0].policy);
	memset(label, 'a', NOTIFY_MAX_PUBLISHER + 1);
	label[1] = '/';
	label[NOTIFY_MAX_PUBLISHER + 1] = '\0';
	ATF_REQUIRE(snprintf(document, sizeof(document), "clients { \"%s\" {} }",
	    label) < (int)sizeof(document));
	ATF_CHECK_ERRNO(EINVAL, notify_policy_db_parse(document, db) == -1);
	/* an empty key is not a label */
	ATF_CHECK(notify_policy_db_parse("clients { \"\" {} }", db) == -1);
	/* the tier-block names are not labels either (no separator) */
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_db_parse("clients { default {} }", db) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_policy_db_parse("clients { system_default {} }", db) == -1);
	free(db);
}

/* NOTIFY_POLICY_CLIENT_MAX entries; one more is E2BIG. */
ATF_TC_WITHOUT_HEAD(client_count_limit);
ATF_TC_BODY(client_count_limit, tc)
{
	struct notify_policy_db *db;
	char *document;
	size_t i, offset, size;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	size = 48 * (NOTIFY_POLICY_CLIENT_MAX + 2);
	document = malloc(size);
	ATF_REQUIRE(document != NULL);
	offset = (size_t)snprintf(document, size, "clients {");
	for (i = 0; i < NOTIFY_POLICY_CLIENT_MAX; i++)
		offset += (size_t)snprintf(document + offset, size - offset,
		    "\"c/l%zu\" { timers = true; }", i);
	offset += (size_t)snprintf(document + offset, size - offset, "}");
	ATF_REQUIRE(offset < size);
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(document, db));
	ATF_CHECK_EQ(NOTIFY_POLICY_CLIENT_MAX, db->nclients);
	ATF_CHECK(notify_policy_db_lookup(db, "c/l0") != NULL);
	ATF_CHECK(notify_policy_db_lookup(db, "c/l255") != NULL);
	ATF_CHECK(notify_policy_db_select(db, NOTIFY_TIER_SYSTEM,
	    "c/l255")->timers);
	offset = (size_t)snprintf(document, size, "clients {");
	for (i = 0; i < NOTIFY_POLICY_CLIENT_MAX + 1; i++)
		offset += (size_t)snprintf(document + offset, size - offset,
		    "\"c/l%zu\" {}", i);
	offset += (size_t)snprintf(document + offset, size - offset, "}");
	ATF_REQUIRE(offset < size);
	ATF_CHECK_ERRNO(E2BIG, notify_policy_db_parse(document, db) == -1);
	free(document);
	free(db);
}

/*
 * A key given twice.  libucl folds duplicate keys into an implicit array,
 * and the loader looks the block up by name, so the FIRST block wins and
 * every later one is silently ignored: "default { publish = [\"user.*\"]; }
 * default {}" still publishes user.*.  The same applies to a client label
 * listed twice, which makes the parser's EEXIST check unreachable.  An
 * operator appending a tighter block gets the looser one; this is a
 * fail-open bug and should be a parse error.
 */
ATF_TC_WITHOUT_HEAD(duplicate_blocks_rejected);
ATF_TC_BODY(duplicate_blocks_rejected, tc)
{
	struct notify_policy_db *db;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	ATF_CHECK(notify_policy_db_parse(
	    "default { publish = [\"user.*\"]; } default {}", db) == -1);
	ATF_CHECK(notify_policy_db_parse(
	    "system_default { timers = true; } system_default { timers = false; }",
	    db) == -1);
	ATF_CHECK(notify_policy_db_parse(
	    "clients { \"a.b/c\" {} } clients { \"d.e/f\" {} }", db) == -1);
	/* A repeated label is a parse error (no implicit arrays), so it is
	 * refused before the EEXIST check could see it. */
	ATF_CHECK_ERRNO(EINVAL, notify_policy_db_parse(
	    "clients { \"a.b/c\" { timers = true; } \"a.b/c\" { timers = false; } }",
	    db) == -1);
	ATF_CHECK(notify_policy_db_parse(
	    "default { publish = [\"user.*\"]; publish = [\"x.y\"]; }",
	    db) == -1);
	free(db);
}

/*
 * A client entry that is not an object.  It is reported as E2BIG because
 * the shape check shares the client-count limit's errno; EINVAL is what
 * every other shape error returns (and what notifyctl configtest then
 * prints as "Invalid argument" rather than "Argument list too long").
 */
ATF_TC_WITHOUT_HEAD(client_entry_shape_errno);
ATF_TC_BODY(client_entry_shape_errno, tc)
{
	struct notify_policy_db *db;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	/* rejected, whatever the errno */
	ATF_CHECK(notify_policy_db_parse("clients { \"a.b/c\" = \"x\"; }",
	    db) == -1);
	ATF_CHECK(notify_policy_db_parse("clients { \"a.b/c\" = []; }",
	    db) == -1);
	ATF_CHECK(notify_policy_db_parse("clients { \"a.b/c\" = null; }",
	    db) == -1);
	ATF_CHECK(notify_policy_db_parse("clients { \"a.b/c\" = true; }",
	    db) == -1);
	ATF_CHECK_ERRNO(EINVAL, notify_policy_db_parse(
	    "clients { \"a.b/c\" = \"x\"; }", db) == -1);
	free(db);
}

/* NULL arguments and the exact file-size boundary of the loader. */
ATF_TC_WITHOUT_HEAD(null_arguments_and_size_boundary);
ATF_TC_BODY(null_arguments_and_size_boundary, tc)
{
	static const char head[] = "default { publish = [\"x.y\"]; }\n#";
	struct notify_policy_db *db;
	struct notify_policy policy;
	char *text;
	int fd, pair[2];

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	ATF_CHECK_ERRNO(EINVAL, notify_policy_parse(NULL, &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL, notify_policy_parse("{}", NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, notify_policy_db_parse(NULL, db) == -1);
	ATF_CHECK_ERRNO(EINVAL, notify_policy_db_parse("", NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, notify_policy_db_load(NULL, db) == -1);
	ATF_CHECK_ERRNO(EINVAL, notify_policy_db_load("x.conf", NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, notify_policy_db_load_fd(-1, db) == -1);
	ATF_CHECK_ERRNO(ENOENT, notify_policy_db_load("missing.conf", db) == -1);
	/* a non-regular descriptor is refused (and consumed) */
	ATF_REQUIRE_EQ(0, pipe(pair));
	ATF_CHECK_ERRNO(EINVAL, notify_policy_db_load_fd(pair[0], db) == -1);
	close(pair[1]);
	/* exactly NOTIFY_POLICY_FILE_MAX bytes is still loadable */
	text = malloc(NOTIFY_POLICY_FILE_MAX + 1);
	ATF_REQUIRE(text != NULL);
	memset(text, 'x', NOTIFY_POLICY_FILE_MAX);
	memcpy(text, head, sizeof(head) - 1);
	text[NOTIFY_POLICY_FILE_MAX - 1] = '\n';
	fd = open("max.conf", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(NOTIFY_POLICY_FILE_MAX,
	    write(fd, text, NOTIFY_POLICY_FILE_MAX));
	close(fd);
	ATF_REQUIRE_EQ(0, notify_policy_db_load("max.conf", db));
	ATF_CHECK(db->has_default);
	ATF_CHECK(pub(&db->open_default, "x.y"));
	/* one byte more is EFBIG before any parsing */
	fd = open("max.conf", O_WRONLY | O_APPEND | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(1, write(fd, "\n", 1));
	close(fd);
	ATF_CHECK_ERRNO(EFBIG, notify_policy_db_load("max.conf", db) == -1);
	free(text);
	free(db);
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
	ATF_TP_ADD_TC(tp, prefix_boundary);
	ATF_TP_ADD_TC(tp, pattern_forms_rejected);
	ATF_TP_ADD_TC(tp, topic_length_limits);
	ATF_TP_ADD_TC(tp, mixing_all_with_named_rejected);
	ATF_TP_ADD_TC(tp, duplicate_and_overlapping_entries);
	ATF_TP_ADD_TC(tp, prefix_count_limit);
	ATF_TP_ADD_TC(tp, block_shapes_rejected);
	ATF_TP_ADD_TC(tp, select_edge_cases);
	ATF_TP_ADD_TC(tp, explicit_blocks_replace_builtins);
	ATF_TP_ADD_TC(tp, has_flags_track_presence);
	ATF_TP_ADD_TC(tp, client_label_validation);
	ATF_TP_ADD_TC(tp, client_count_limit);
	ATF_TP_ADD_TC(tp, duplicate_blocks_rejected);
	ATF_TP_ADD_TC(tp, client_entry_shape_errno);
	ATF_TP_ADD_TC(tp, null_arguments_and_size_boundary);
	ATF_TP_ADD_TC(tp, select_source_names_block);
	return (atf_no_error());
}
