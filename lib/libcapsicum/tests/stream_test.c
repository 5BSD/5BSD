/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/filio.h>
#include <capsicum_helpers.h>
#include <atf-c.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

ATF_TC_WITHOUT_HEAD(narrow_stream);
ATF_TC_BODY(narrow_stream, tc)
{
	cap_rights_t before, after;
	char byte;
	int fd;
	(void)tc;

	fd = open("output", O_RDWR | O_CREAT, 0600);
	ATF_REQUIRE(fd >= 0);
	cap_rights_init(&before, CAP_WRITE, CAP_FSTAT);
	ATF_REQUIRE_EQ(0, cap_rights_limit(fd, &before));
	ATF_REQUIRE_EQ(0, caph_limit_stream(fd, CAPH_READ | CAPH_WRITE));
	ATF_REQUIRE_EQ(0, cap_rights_get(fd, &after));
	ATF_CHECK(cap_rights_contains(&before, &after));
	ATF_CHECK(cap_rights_contains(&after, &before));
	ATF_CHECK_EQ(1, write(fd, "x", 1));
	ATF_CHECK_ERRNO(ENOTCAPABLE, read(fd, &byte, 1) == -1);
	ATF_CHECK_ERRNO(ENOTCAPABLE, fcntl(fd, F_GETFL) == -1);
	ATF_CHECK_EQ(0, caph_limit_stream(fd, CAPH_WRITE));
	close(fd);
}

ATF_TC_WITHOUT_HEAD(narrow_commands);
ATF_TC_BODY(narrow_commands, tc)
{
	unsigned long initial[] = { FIONREAD, FIONBIO, FIOASYNC,
	    FIOCLEX, FIONCLEX, TIOCGWINSZ }, actual[4];
	uint32_t fcntls;
	cap_rights_t rights;
	int fd;
	(void)tc;

	fd = open("output", O_RDWR | O_CREAT, 0600);
	ATF_REQUIRE(fd >= 0);
	/* The native host may run an older rights ABI. Bound this fixture to
	 * named common rights before using the matching world's library. */
	cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_FSTAT, CAP_IOCTL,
	    CAP_FCNTL, CAP_FSYNC);
	ATF_REQUIRE_EQ(0, cap_rights_limit(fd, &rights));
	ATF_REQUIRE_EQ(0, cap_ioctls_limit(fd, initial, nitems(initial)));
	ATF_REQUIRE_EQ(0, cap_fcntls_limit(fd, CAP_FCNTL_SETFL));
	ATF_REQUIRE_EQ(0, caph_limit_stream(fd, CAPH_WRITE));
	ATF_REQUIRE_EQ(1, cap_ioctls_get(fd, actual, nitems(actual)));
	ATF_CHECK_EQ(TIOCGWINSZ, actual[0]);
	ATF_REQUIRE_EQ(0, cap_fcntls_get(fd, &fcntls));
	ATF_CHECK_EQ(0, fcntls);
	ATF_REQUIRE_EQ(0, cap_rights_get(fd, &rights));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_READ));
	ATF_CHECK_ERRNO(ENOTCAPABLE, cap_fcntls_limit(fd, CAP_FCNTL_GETFL) == -1);
	ATF_CHECK_ERRNO(ENOTCAPABLE, cap_ioctls_limit(fd, initial, nitems(initial)) == -1);
	ATF_REQUIRE_EQ(0, caph_limit_stream(fd, CAPH_WRITE));
	ATF_REQUIRE_EQ(1, cap_ioctls_get(fd, actual, nitems(actual)));
	ATF_REQUIRE_EQ(0, cap_ioctls_limit(fd, NULL, 0));
	ATF_REQUIRE_EQ(0, caph_limit_stream(fd, CAPH_WRITE));
	ATF_CHECK_EQ(0, cap_ioctls_get(fd, actual, nitems(actual)));
	close(fd);
}

ATF_TC_WITHOUT_HEAD(ordinary_and_empty);
ATF_TC_BODY(ordinary_and_empty, tc)
{
	cap_rights_t rights, expected;
	uint32_t fcntls;
	unsigned long commands[8];
	int fd;
	(void)tc;

	fd = open("output", O_RDWR | O_CREAT, 0600);
	ATF_REQUIRE(fd >= 0);
	caph_stream_rights(&rights, CAPH_READ | CAPH_WRITE);
	cap_rights_set(&rights, CAP_FSYNC);
	ATF_REQUIRE_EQ(0, cap_rights_limit(fd, &rights));
	ATF_REQUIRE_EQ(0, caph_limit_stream(fd, CAPH_WRITE));
	caph_stream_rights(&expected, CAPH_WRITE);
	ATF_REQUIRE_EQ(0, cap_rights_get(fd, &rights));
	ATF_CHECK(cap_rights_contains(&rights, &expected));
	ATF_CHECK(cap_rights_contains(&expected, &rights));
	ATF_REQUIRE_EQ(nitems(caph_stream_cmds), cap_ioctls_get(fd, commands, nitems(commands)));
	ATF_CHECK_EQ(0, memcmp(commands, caph_stream_cmds, sizeof(caph_stream_cmds)));
	ATF_REQUIRE_EQ(0, cap_fcntls_get(fd, &fcntls));
	ATF_CHECK_EQ(CAP_FCNTL_GETFL, fcntls);
	cap_rights_init(&expected);
	ATF_REQUIRE_EQ(0, cap_rights_limit(fd, &expected));
	ATF_REQUIRE_EQ(0, caph_limit_stream(fd, CAPH_READ | CAPH_WRITE));
	ATF_REQUIRE_EQ(0, cap_rights_get(fd, &rights));
	ATF_CHECK(cap_rights_contains(&expected, &rights));
	close(fd);
	ATF_CHECK_ERRNO(EBADF, caph_limit_stream(-1, CAPH_READ) == -1);
	ATF_CHECK_EQ(0, caph_limit_stream(-1, CAPH_READ | CAPH_IGNORE_EBADF));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, narrow_stream);
	ATF_TP_ADD_TC(tp, narrow_commands);
	ATF_TP_ADD_TC(tp, ordinary_and_empty);
	return (atf_no_error());
}
