/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "authagentd_test.h"

static int
text_fd(const char *text)
{
	char path[] = "/tmp/authagent_identity.XXXXXX";
	size_t length;
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, unlink(path));
	length = strlen(text);
	ATF_REQUIRE_EQ((ssize_t)length, write(fd, text, length));
	return (fd);
}

ATF_TC_WITHOUT_HEAD(valid_identity_database);
ATF_TC_BODY(valid_identity_database, tc)
{
	const char *passwd_text =
	    "root:*:0:0:System Administrator:/root:/bin/sh\n"
	    "alice:*:1001:100:Alice:/home/alice:/bin/sh\n";
	const char *group_text =
	    "wheel:*:0:root\n"
	    "staff:*:100:alice\n"
	    "admin:*:200:alice,bob\n";
	char name[MAXLOGNAME + 1];
	gid_t members[8], primary, wheel;
	unsigned nmember;
	int grfd, pwfd;

	pwfd = text_fd(passwd_text);
	grfd = text_fd(group_text);
	authagentd_test_identity_configure(pwfd, grfd);
	ATF_REQUIRE_EQ(0, authagentd_test_resolve_identity(1001, name,
	    sizeof(name), &primary, members, nitems(members), &nmember));
	ATF_CHECK_STREQ("alice", name);
	ATF_CHECK_EQ(100, primary);
	ATF_REQUIRE_EQ(2, nmember);
	ATF_CHECK_EQ(100, members[0]);
	ATF_CHECK_EQ(200, members[1]);
	ATF_REQUIRE_EQ(0, authagentd_test_name2gid("wheel", &wheel));
	ATF_CHECK_EQ(0, wheel);
	close(pwfd);
	close(grfd);
}

ATF_TC_WITHOUT_HEAD(malformed_ids_fail_closed);
ATF_TC_BODY(malformed_ids_fail_closed, tc)
{
	const char *passwd_text =
	    "empty:*::0:Empty:/nonexistent:/sbin/nologin\n"
	    "signed:*:+0:0:Signed:/nonexistent:/sbin/nologin\n"
	    "alpha:*:root:0:Alpha:/nonexistent:/sbin/nologin\n"
	    "badgid:*:0:wheel:Bad:/nonexistent:/sbin/nologin\n"
	    "overflow:*:18446744073709551616:0:Overflow:/x:/x\n";
	const char *group_text =
	    "empty:*::root\n"
	    "signed:*:+0:root\n"
	    "alpha:*:wheel:root\n"
	    "overflow:*:18446744073709551616:root\n";
	char name[MAXLOGNAME + 1];
	gid_t gid, members[8], primary;
	unsigned nmember;
	int grfd, pwfd;

	pwfd = text_fd(passwd_text);
	grfd = text_fd(group_text);
	authagentd_test_identity_configure(pwfd, grfd);
	ATF_CHECK_ERRNO(ENOENT, authagentd_test_resolve_identity(0, name,
	    sizeof(name), &primary, members, nitems(members), &nmember) == -1);
	ATF_CHECK_ERRNO(ENOENT,
	    authagentd_test_name2gid("empty", &gid) == -1);
	ATF_CHECK_ERRNO(ENOENT,
	    authagentd_test_name2gid("signed", &gid) == -1);
	ATF_CHECK_ERRNO(ENOENT,
	    authagentd_test_name2gid("alpha", &gid) == -1);
	ATF_CHECK_ERRNO(ENOENT,
	    authagentd_test_name2gid("overflow", &gid) == -1);
	close(pwfd);
	close(grfd);
}

ATF_TC_WITHOUT_HEAD(oversized_snapshot_fails_closed);
ATF_TC_BODY(oversized_snapshot_fails_closed, tc)
{
	char chunk[4096], name[MAXLOGNAME + 1];
	gid_t members[8], primary;
	unsigned i, nmember;
	int grfd, pwfd;

	pwfd = text_fd("root:*:0:0:root:/root:/bin/sh\n");
	memset(chunk, 'x', sizeof(chunk));
	for (i = 0; i < 33; i++)
		ATF_REQUIRE_EQ((ssize_t)sizeof(chunk),
		    write(pwfd, chunk, sizeof(chunk)));
	grfd = text_fd("wheel:*:0:root\n");
	authagentd_test_identity_configure(pwfd, grfd);
	ATF_CHECK_ERRNO(EOVERFLOW, authagentd_test_resolve_identity(0, name,
	    sizeof(name), &primary, members, nitems(members), &nmember) == -1);
	close(pwfd);
	close(grfd);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, valid_identity_database);
	ATF_TP_ADD_TC(tp, malformed_ids_fail_closed);
	ATF_TP_ADD_TC(tp, oversized_snapshot_fails_closed);
	return (atf_no_error());
}
