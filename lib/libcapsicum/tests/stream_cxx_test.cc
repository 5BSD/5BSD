/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/filio.h>
#include <capsicum_helpers.h>
#include <atf-c++.hpp>
#include <fcntl.h>
#include <unistd.h>

ATF_TEST_CASE(narrow_commands);
ATF_TEST_CASE_HEAD(narrow_commands)
{
    set_md_var("descr", "C++ stream helper preserves monotonic ioctl restrictions");
}
ATF_TEST_CASE_BODY(narrow_commands)
{
    cap_rights_t rights;
    unsigned long initial[] = { FIONREAD, TIOCGWINSZ }, actual[2];
    int fd = open("output", O_RDWR | O_CREAT, 0600);
    ATF_REQUIRE(fd >= 0);
    cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_IOCTL);
    ATF_REQUIRE_EQ(0, cap_rights_limit(fd, &rights));
    ATF_REQUIRE_EQ(0, cap_ioctls_limit(fd, initial, nitems(initial)));
    ATF_REQUIRE_EQ(0, caph_limit_stream(fd, CAPH_WRITE));
    ATF_REQUIRE_EQ(1, cap_ioctls_get(fd, actual, nitems(actual)));
    ATF_REQUIRE_EQ(TIOCGWINSZ, actual[0]);
    ATF_CHECK_ERRNO(ENOTCAPABLE, cap_ioctls_limit(fd, initial, nitems(initial)) == -1);
    ATF_REQUIRE_EQ(0, caph_limit_stream(fd, CAPH_WRITE));
    ATF_REQUIRE_EQ(1, cap_ioctls_get(fd, actual, nitems(actual)));
    ATF_REQUIRE_EQ(TIOCGWINSZ, actual[0]);
    close(fd);
}
ATF_INIT_TEST_CASES(tcs)
{
    ATF_ADD_TEST_CASE(tcs, narrow_commands);
}
