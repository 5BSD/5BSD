/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

ATF_TC(stdin_rights);
ATF_TC_HEAD(stdin_rights, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Opening /dev/stdin duplicates only held rights and access mode");
}
ATF_TC_BODY(stdin_rights, tc)
{
	cap_rights_t rights, actual;
	int source, saved, copy;
	char path[] = "/tmp/fd-device.XXXXXXXX";
	char byte;

	(void)tc;
	saved = dup(STDIN_FILENO);
	ATF_REQUIRE(saved >= 0);
	source = mkstemp(path);
	ATF_REQUIRE(source >= 0);
	ATF_REQUIRE(write(source, "x", 1) == 1);
	close(source);
	source = open(path, O_RDONLY);
	ATF_REQUIRE(source >= 0);
	ATF_REQUIRE(unlink(path) == 0);
	ATF_REQUIRE(dup2(source, STDIN_FILENO) == STDIN_FILENO);
	close(source);
	cap_rights_init(&rights, CAP_READ);
	ATF_REQUIRE(cap_rights_limit(STDIN_FILENO, &rights) == 0);
	copy = open("/dev/stdin", O_RDONLY);
	ATF_REQUIRE_MSG(copy >= 0, "open /dev/stdin: errno %d", errno);
	ATF_REQUIRE(cap_rights_get(copy, &actual) == 0);
	ATF_CHECK(cap_rights_contains(&rights, &actual));
	ATF_CHECK(cap_rights_contains(&actual, &rights));
	ATF_REQUIRE(read(copy, &byte, 1) == 1);
	ATF_CHECK_EQ(byte, 'x');
	close(copy);
	ATF_REQUIRE_ERRNO(EACCES, open("/dev/stdin", O_WRONLY) == -1);
	close(STDIN_FILENO);
	ATF_REQUIRE_ERRNO(EBADF, open("/dev/stdin", O_RDONLY) == -1);
	ATF_REQUIRE(dup2(saved, STDIN_FILENO) == STDIN_FILENO);
	close(saved);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, stdin_rights);
	return (atf_no_error());
}
