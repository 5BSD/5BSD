/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "nss-helper/nss_protocol.h"

static struct passwd entry;
static struct group group_entry;
static int provider_error, provider_calls, group_count, group_result;
static gid_t group_value;
static struct passwd *
fake_getpwnam(const char *name __unused)
{
	provider_calls++;
	errno = provider_error;
	return (provider_error == 0 ? &entry : NULL);
}
static struct passwd *
fake_getpwuid(uid_t uid __unused)
{
	return (fake_getpwnam(NULL));
}
static struct group *
fake_getgrnam(const char *name __unused)
{
	provider_calls++;
	errno = provider_error;
	return (provider_error == 0 ? &group_entry : NULL);
}
static int
fake_getgrouplist(const char *name __unused, gid_t gid __unused,
    gid_t *groups, int *count)
{
	provider_calls++;
	for (int i = 0; i < *count; i++) groups[i] = group_value;
	*count = group_count;
	errno = provider_error;
	return (group_result);
}
#define getpwnam fake_getpwnam
#define getpwuid fake_getpwuid
#define getgrnam fake_getgrnam
#define getgrouplist fake_getgrouplist
#include "nss-helper/nss_lookup.c"
#undef getpwnam
#undef getpwuid
#undef getgrnam
#undef getgrouplist

static struct sb_nss_request
request(uint32_t operation)
{
	struct sb_nss_request req = { .version = SB_NSS_VERSION,
	    .operation = operation };
	if (operation != SB_NSS_USER_UID) strlcpy(req.name, "account", sizeof(req.name));
	return (req);
}
static void
expect_error(struct sb_nss_request *req, int error)
{
	struct sb_nss_reply reply, expected = { .version = SB_NSS_VERSION,
	    .error = error };
	memset(&reply, 0xa5, sizeof(reply));
	sb_nss_lookup(req, &reply);
	ATF_REQUIRE(memcmp(&reply, &expected, sizeof(reply)) == 0);
}
ATF_TC_WITHOUT_HEAD(provider_errors);
ATF_TC_BODY(provider_errors, tc)
{
	struct sb_nss_request req = request(SB_NSS_USER_NAME);
	struct sb_nss_reply reply;
	char name[] = "account", home[] = "/home/account";
	char shell[] = "/bin/sh", root[] = "/";
	char too_long[PATH_MAX + 1];
	memset(too_long, 'x', sizeof(too_long) - 1);
	too_long[sizeof(too_long) - 1] = '\0';
	entry = (struct passwd){ .pw_name = name, .pw_uid = 100,
	    .pw_gid = 200, .pw_dir = home, .pw_shell = shell };
	sb_nss_lookup(&req, &reply);
	ATF_REQUIRE_EQ(reply.error, 0);
	ATF_REQUIRE_EQ(reply.uid, 100);
	ATF_REQUIRE_STREQ(reply.home, "/home/account");
	provider_error = EIO;
	expect_error(&req, EIO);
	provider_error = 0;
	entry.pw_dir = too_long;
	expect_error(&req, ERANGE);
	entry.pw_dir = NULL;
	expect_error(&req, EINVAL);
	entry.pw_dir = root;
	entry.pw_name = too_long;
	expect_error(&req, ERANGE);
	entry.pw_name = name;
	req = request(SB_NSS_USER_UID);
	req.id = 101;
	expect_error(&req, EINVAL);
	req.id = 100;
	sb_nss_lookup(&req, &reply);
	ATF_REQUIRE_EQ(reply.error, 0);
	entry.pw_uid = (uid_t)-1;
	expect_error(&req, EINVAL);
	req = request(SB_NSS_GROUP_NAME);
	group_entry.gr_gid = (gid_t)-1;
	expect_error(&req, EINVAL);
}
ATF_TC_WITHOUT_HEAD(group_membership);
ATF_TC_BODY(group_membership, tc)
{
	struct sb_nss_request req = request(SB_NSS_GROUPS);
	struct sb_nss_reply reply;
	group_count = NGROUPS_MAX + 1;
	group_value = 25;
	sb_nss_lookup(&req, &reply);
	ATF_REQUIRE_EQ(reply.error, 0);
	ATF_REQUIRE_EQ(reply.ngroups, NGROUPS_MAX + 1);
	ATF_REQUIRE_EQ(reply.groups[NGROUPS_MAX], 25);
	group_count++;
	expect_error(&req, EINVAL);
	group_count = 0;
	expect_error(&req, EINVAL);
	group_count = -1;
	expect_error(&req, EINVAL);
	group_count = 1;
	group_value = (gid_t)-1;
	expect_error(&req, EINVAL);
	group_result = -1;
	expect_error(&req, ERANGE);
	provider_error = EIO;
	expect_error(&req, EIO);
}
ATF_TC_WITHOUT_HEAD(request_validation);
ATF_TC_BODY(request_validation, tc)
{
	struct sb_nss_request req = request(SB_NSS_USER_NAME);
	req.version++;
	expect_error(&req, EINVAL);
	req = request(SB_NSS_USER_NAME);
	memset(req.name, 'a', sizeof(req.name));
	expect_error(&req, EINVAL);
	req = request(SB_NSS_USER_NAME);
	req.name[0] = '\0';
	expect_error(&req, EINVAL);
	req = request(SB_NSS_USER_NAME);
	req.id = 5;
	expect_error(&req, EINVAL);
	req = request(SB_NSS_USER_UID);
	req.id = UINT32_MAX;
	expect_error(&req, EINVAL);
	req = request(99);
	expect_error(&req, EINVAL);
	ATF_REQUIRE_EQ(provider_calls, 0);
}

/* Execute the real helper with ordinary test-process credentials. This does
 * not exercise the future protected-manager isolation/launch sequence. */
static size_t
exchange(const atf_tc_t *tc, const void *data, size_t size,
    struct sb_nss_reply *reply, int *status)
{
	int input[2], output[2];
	pid_t pid;
	ssize_t n;
	size_t used = 0;
	const char *helper = atf_tc_get_config_var_wd(tc, "helper",
	    "/usr/libexec/switchboard-nss");
	ATF_REQUIRE(pipe(input) == 0);
	ATF_REQUIRE(pipe(output) == 0);
	ATF_REQUIRE((pid = fork()) >= 0);
	if (pid == 0) {
		if (dup2(input[0], STDIN_FILENO) == -1 ||
		    dup2(output[1], STDOUT_FILENO) == -1) _exit(126);
		closefrom(STDERR_FILENO + 1);
		execl(helper, helper, (char *)NULL);
		_exit(127);
	}
	close(input[0]); close(output[1]);
	ATF_REQUIRE_EQ(write(input[1], data, size), (ssize_t)size);
	close(input[1]);
	while (used < sizeof(*reply)) {
		n = read(output[0], (char *)reply + used, sizeof(*reply) - used);
		if (n == -1 && errno == EINTR) continue;
		ATF_REQUIRE(n >= 0);
		if (n == 0) break;
		used += n;
	}
	char extra;
	ATF_REQUIRE_EQ(read(output[0], &extra, 1), 0);
	close(output[0]);
	ATF_REQUIRE_EQ(waitpid(pid, status, 0), pid);
	ATF_REQUIRE(WIFEXITED(*status));
	return (used);
}
ATF_TC_WITHOUT_HEAD(helper_roundtrip);
ATF_TC_BODY(helper_roundtrip, tc)
{
	struct sb_nss_request req = request(SB_NSS_USER_UID);
	struct sb_nss_reply reply;
	struct passwd *pw = getpwuid(getuid());
	char name[SB_NSS_NAME_MAX];
	gid_t groups[NGROUPS_MAX + 1], primary;
	int count = nitems(groups), status;
	ATF_REQUIRE(pw != NULL);
	ATF_REQUIRE(strlcpy(name, pw->pw_name, sizeof(name)) < sizeof(name));
	primary = pw->pw_gid;
	req.id = getuid();
	ATF_REQUIRE_EQ(exchange(tc, &req, sizeof(req), &reply, &status), sizeof(reply));
	ATF_REQUIRE_EQ(WEXITSTATUS(status), 0);
	ATF_REQUIRE_EQ(reply.error, 0);
	ATF_REQUIRE_EQ(sb_nss_reply_valid(&req, &reply, sizeof(reply), getuid()), 0);
	ATF_REQUIRE_EQ(reply.uid, getuid());
	ATF_REQUIRE_EQ(reply.gid, primary);
	ATF_REQUIRE_STREQ(reply.name, name);
	req = request(SB_NSS_USER_NAME);
	strlcpy(req.name, name, sizeof(req.name));
	ATF_REQUIRE_EQ(exchange(tc, &req, sizeof(req), &reply, &status), sizeof(reply));
	ATF_REQUIRE_EQ(WEXITSTATUS(status), 0);
	ATF_REQUIRE_EQ(reply.error, 0);
	ATF_REQUIRE_EQ(sb_nss_reply_valid(&req, &reply, sizeof(reply), getuid()), 0);
	ATF_REQUIRE_EQ(reply.uid, getuid());
	struct group *gr = getgrgid(primary);
	ATF_REQUIRE(gr != NULL);
	req = request(SB_NSS_GROUP_NAME);
	ATF_REQUIRE(strlcpy(req.name, gr->gr_name, sizeof(req.name)) < sizeof(req.name));
	ATF_REQUIRE_EQ(exchange(tc, &req, sizeof(req), &reply, &status), sizeof(reply));
	ATF_REQUIRE_EQ(WEXITSTATUS(status), 0);
	ATF_REQUIRE_EQ(reply.error, 0);
	ATF_REQUIRE_EQ(reply.gid, primary);
	req = request(SB_NSS_GROUPS);
	strlcpy(req.name, name, sizeof(req.name));
	req.id = primary;
	ATF_REQUIRE(getgrouplist(name, primary, groups, &count) >= 0);
	ATF_REQUIRE_EQ(exchange(tc, &req, sizeof(req), &reply, &status), sizeof(reply));
	ATF_REQUIRE_EQ(WEXITSTATUS(status), 0);
	ATF_REQUIRE_EQ(reply.error, 0);
	ATF_REQUIRE_EQ(sb_nss_reply_valid(&req, &reply, sizeof(reply), (uid_t)-1), 0);
	ATF_REQUIRE_EQ(reply.ngroups, (uint32_t)count);
	for (int i = 0; i < count; i++) ATF_REQUIRE_EQ(reply.groups[i], groups[i]);
}
ATF_TC_WITHOUT_HEAD(helper_framing);
ATF_TC_BODY(helper_framing, tc)
{
	struct sb_nss_request req = request(99);
	struct sb_nss_reply reply;
	unsigned char extra[sizeof(req) + 1] = {0};
	int status;
	ATF_REQUIRE_EQ(exchange(tc, &req, sizeof(req) - 1, &reply, &status), 0);
	ATF_REQUIRE(WEXITSTATUS(status) != 0);
	ATF_REQUIRE_EQ(exchange(tc, extra, sizeof(extra), &reply, &status), 0);
	ATF_REQUIRE(WEXITSTATUS(status) != 0);
	ATF_REQUIRE_EQ(exchange(tc, &req, sizeof(req), &reply, &status), sizeof(reply));
	ATF_REQUIRE_EQ(WEXITSTATUS(status), 0);
	ATF_REQUIRE_EQ(reply.error, EINVAL);
}
static void
bad_reply(const struct sb_nss_request *req, const void *reply, size_t size,
    uid_t owner, int error)
{
	errno = 0;
	ATF_REQUIRE_EQ(sb_nss_reply_valid(req, reply, size, owner), -1);
	ATF_REQUIRE_EQ(errno, error);
}
ATF_TC_WITHOUT_HEAD(reply_validation);
ATF_TC_BODY(reply_validation, tc)
{
	struct sb_nss_request req = request(SB_NSS_USER_UID);
	struct sb_nss_reply reply = { .version = SB_NSS_VERSION,
	    .uid = 100, .gid = 200, .name = "account", .home = "/home/account",
	    .shell = "/bin/sh" }, changed;
	unsigned char unaligned[sizeof(reply) + 1];
	req.id = 100;
	ATF_REQUIRE_EQ(sb_nss_reply_valid(&req, &reply, sizeof(reply), 100), 0);
	memcpy(unaligned + 1, &reply, sizeof(reply));
	ATF_REQUIRE_EQ(sb_nss_reply_valid(&req, unaligned + 1, sizeof(reply), 100), 0);
	bad_reply(&req, &reply, sizeof(reply) - 1, 100, EPROTO);
	bad_reply(&req, &reply, sizeof(reply) + 1, 100, EPROTO);
	bad_reply(&req, NULL, sizeof(reply), 100, EPROTO);
	bad_reply(&req, &reply, sizeof(reply), 101, EPERM);
	changed = reply; changed.uid = 101;
	bad_reply(&req, &changed, sizeof(changed), (uid_t)-1, EPERM);
	changed = reply; changed.version++;
	bad_reply(&req, &changed, sizeof(changed), 100, EPROTO);
	changed = reply; changed.error = UINT32_MAX;
	bad_reply(&req, &changed, sizeof(changed), 100, EPROTO);
	changed = reply; changed.gid = UINT32_MAX;
	bad_reply(&req, &changed, sizeof(changed), 100, EPROTO);
	changed = reply; changed.ngroups = 1;
	bad_reply(&req, &changed, sizeof(changed), 100, EPROTO);
	changed = reply; changed.groups[NGROUPS_MAX] = 1;
	bad_reply(&req, &changed, sizeof(changed), 100, EPROTO);
	changed = reply; memset(changed.name, 'x', sizeof(changed.name));
	bad_reply(&req, &changed, sizeof(changed), 100, EPROTO);
	changed = reply; memset(changed.home, 'x', sizeof(changed.home));
	bad_reply(&req, &changed, sizeof(changed), 100, EPROTO);
	changed = reply; memset(changed.shell, 'x', sizeof(changed.shell));
	bad_reply(&req, &changed, sizeof(changed), 100, EPROTO);
	changed = reply; changed.name[sizeof(changed.name) - 1] = 'x';
	bad_reply(&req, &changed, sizeof(changed), 100, EPROTO);
	changed = (struct sb_nss_reply){ .version = SB_NSS_VERSION, .error = EIO };
	bad_reply(&req, &changed, sizeof(changed), 100, EIO);
	changed.uid = 1;
	bad_reply(&req, &changed, sizeof(changed), 100, EPROTO);

	/* Canonical names and ordinary UNIX path strings do not grant authority.
	 * Do not require getpwnam's result name to equal the queried alias. */
	req = request(SB_NSS_USER_NAME);
	strlcpy(req.name, "alias", sizeof(req.name));
	ATF_REQUIRE_EQ(sb_nss_reply_valid(&req, &reply, sizeof(reply), 100), 0);
	bad_reply(&req, &reply, sizeof(reply), 101, EPERM);
	reply.home[0] = '\0'; memset(reply.home, 0, sizeof(reply.home));
	ATF_REQUIRE_EQ(sb_nss_reply_valid(&req, &reply, sizeof(reply), 100), 0);
}
ATF_TC_WITHOUT_HEAD(group_reply_validation);
ATF_TC_BODY(group_reply_validation, tc)
{
	struct sb_nss_request req = request(SB_NSS_GROUP_NAME);
	struct sb_nss_reply reply = { .version = SB_NSS_VERSION, .gid = 200 };
	ATF_REQUIRE_EQ(sb_nss_reply_valid(&req, &reply, sizeof(reply), (uid_t)-1), 0);
	reply.uid = 100;
	bad_reply(&req, &reply, sizeof(reply), (uid_t)-1, EPROTO);
	reply.uid = 0; reply.name[0] = 'x';
	bad_reply(&req, &reply, sizeof(reply), (uid_t)-1, EPROTO);
	reply = (struct sb_nss_reply){ .version = SB_NSS_VERSION, .ngroups = 1,
	    .groups = {200} };
	req = request(SB_NSS_GROUPS); req.id = 200;
	ATF_REQUIRE_EQ(sb_nss_reply_valid(&req, &reply, sizeof(reply), (uid_t)-1), 0);
	reply.groups[1] = 201;
	bad_reply(&req, &reply, sizeof(reply), (uid_t)-1, EPROTO);
	reply.ngroups = 2;
	ATF_REQUIRE_EQ(sb_nss_reply_valid(&req, &reply, sizeof(reply), (uid_t)-1), 0);
	reply.groups[1] = UINT32_MAX;
	bad_reply(&req, &reply, sizeof(reply), (uid_t)-1, EPROTO);
	reply.groups[1] = 0; reply.ngroups = NGROUPS_MAX + 2;
	bad_reply(&req, &reply, sizeof(reply), (uid_t)-1, EPROTO);
	reply.ngroups = 0;
	bad_reply(&req, &reply, sizeof(reply), (uid_t)-1, EPROTO);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, reply_validation);
	ATF_TP_ADD_TC(tp, group_reply_validation);
	ATF_TP_ADD_TC(tp, provider_errors);
	ATF_TP_ADD_TC(tp, group_membership);
	ATF_TP_ADD_TC(tp, request_validation);
	ATF_TP_ADD_TC(tp, helper_roundtrip);
	ATF_TP_ADD_TC(tp, helper_framing);
	return (atf_no_error());
}
