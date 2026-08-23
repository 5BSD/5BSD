/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
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
	return (atf_no_error());
}
