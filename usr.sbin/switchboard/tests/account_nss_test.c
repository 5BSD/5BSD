/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include "nss_exchange.h"
static unsigned direct_calls, exchanges;
static int lookup_error;
static struct passwd *tracked_uid(uid_t id) { direct_calls++; return (getpwuid(id)); }
static struct passwd *tracked_user(const char *name) { direct_calls++; return (getpwnam(name)); }
static struct group *tracked_group(const char *name) { direct_calls++; return (getgrnam(name)); }
static int tracked_groups(const char *name, gid_t gid, gid_t *groups, int *count)
{ direct_calls++; return (getgrouplist(name, gid, groups, count)); }
int
sb_nss_exchange(const char *helper, int diagnostic,
    const struct sb_nss_request *req, uid_t owner, int timeout,
    struct sb_nss_reply *reply)
{
	ATF_REQUIRE_STREQ(helper, "/test/helper");
	ATF_REQUIRE(fcntl(diagnostic, F_GETFD) >= 0);
	ATF_REQUIRE_EQ(timeout, 1234);
	ATF_REQUIRE_EQ(sb_nss_request_valid(req), 0);
	exchanges++;
	memset(reply, 0, sizeof(*reply));
	if (lookup_error) return (errno = lookup_error, -1);
	reply->version = SB_NSS_VERSION;
	switch (req->operation) {
	case SB_NSS_USER_UID:
		ATF_REQUIRE_EQ(req->id, 1000);
		ATF_REQUIRE_EQ(owner, 1000);
		/* FALLTHROUGH */
	case SB_NSS_USER_NAME:
		reply->uid = 1000; reply->gid = 2000;
		strlcpy(reply->name, "account", sizeof(reply->name));
		strlcpy(reply->home, "/home/account", sizeof(reply->home));
		strlcpy(reply->shell, "/bin/sh", sizeof(reply->shell));
		break;
	case SB_NSS_GROUP_NAME: reply->gid = 2001; break;
	case SB_NSS_GROUPS:
		ATF_REQUIRE_EQ(req->id, 2001);
		reply->ngroups = 2; reply->groups[0] = 2001; reply->groups[1] = 2002;
		break;
	}
	return (sb_nss_reply_valid(req, reply, sizeof(*reply), owner));
}
#define getpwuid tracked_uid
#define getpwnam tracked_user
#define getgrnam tracked_group
#define getgrouplist tracked_groups
#include "../account_nss.c"
#undef getpwuid
#undef getpwnam
#undef getgrnam
#undef getgrouplist
ATF_TC_WITHOUT_HEAD(writable_mode);
ATF_TC_BODY(writable_mode, tc)
{
	struct service_account_identity user;
	char name[64];
	gid_t group, groups[NGROUPS_MAX + 1];
	int count = nitems(groups);
	ATF_REQUIRE_EQ(account_nss_uid(getuid(), name, sizeof(name)), 0);
	ATF_REQUIRE_EQ(account_nss_user(name, &user), 0);
	ATF_REQUIRE_EQ(user.uid, getuid());
	struct group *gr = getgrgid(user.gid);
	ATF_REQUIRE(gr != NULL);
	ATF_REQUIRE_EQ(account_nss_group(gr->gr_name, &group), 0);
	ATF_REQUIRE_EQ(group, user.gid);
	ATF_REQUIRE(account_nss_groups(name, group, groups, &count) >= 0);
	ATF_REQUIRE_EQ(direct_calls, 4);
	ATF_REQUIRE_EQ(exchanges, 0);
}
ATF_TC_WITHOUT_HEAD(isolated_mode);
ATF_TC_BODY(isolated_mode, tc)
{
	struct service_account_identity user;
	char path[64] = "/test/helper", name[64];
	gid_t group, groups[2] = {99, 99};
	int count = 1, fd = open("/dev/null", O_WRONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(account_nss_isolate(path, fd, 1234), 0);
	close(fd);
	strlcpy(path, "/changed", sizeof(path));
	ATF_REQUIRE_EQ(account_nss_isolate(path, -1, 1), -1);
	ATF_REQUIRE_EQ(errno, EALREADY);
	ATF_REQUIRE_EQ(account_nss_uid(1000, name, sizeof(name)), 0);
	ATF_REQUIRE_STREQ(name, "account");
	ATF_REQUIRE_EQ(account_nss_user("alias", &user), 0);
	ATF_REQUIRE_EQ(user.uid, 1000);
	ATF_REQUIRE_EQ(account_nss_group("group", &group), 0);
	ATF_REQUIRE_EQ(group, 2001);
	ATF_REQUIRE_EQ(account_nss_groups("account", group, groups, &count), -1);
	ATF_REQUIRE_EQ(errno, ERANGE);
	ATF_REQUIRE_EQ(count, 2);
	ATF_REQUIRE_EQ(groups[0], 99);
	ATF_REQUIRE_EQ(account_nss_groups("account", group, groups, &count), 0);
	ATF_REQUIRE_EQ(groups[0], 2001);
	ATF_REQUIRE_EQ(groups[1], 2002);
	/* Group and UID lookups must not invalidate returned user strings. */
	ATF_REQUIRE_STREQ(user.home, "/home/account");
	lookup_error = ETIMEDOUT;
	ATF_REQUIRE_EQ(account_nss_uid(1000, name, sizeof(name)), -1);
	ATF_REQUIRE_EQ(errno, ETIMEDOUT);
	ATF_REQUIRE_EQ(account_nss_user("account", &user), -1);
	ATF_REQUIRE_EQ(errno, ETIMEDOUT);
	ATF_REQUIRE_EQ(account_nss_group("group", &group), -1);
	ATF_REQUIRE_EQ(errno, ETIMEDOUT);
	ATF_REQUIRE_EQ(account_nss_groups("account", group, groups, &count), -1);
	ATF_REQUIRE_EQ(errno, ETIMEDOUT);
	ATF_REQUIRE_EQ(direct_calls, 0);
	ATF_REQUIRE_EQ(exchanges, 9);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, writable_mode);
	ATF_TP_ADD_TC(tp, isolated_mode);
	return (atf_no_error());
}
