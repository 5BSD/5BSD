/* SPDX-License-Identifier: BSD-2-Clause */
/* Test the production fallback decision with an observable verifier transport. */
#include <sys/types.h>
#include <sys/stat.h>
#include <atf-c.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

static int calls, verification;
static const struct stat *expected_stat;
static int
rtld_verify_object_signature(const char *path, int fd, const struct stat *st,
    bool required)
{
	ATF_REQUIRE_STREQ("signed-library", path);
	ATF_REQUIRE_EQ(42, fd);
	ATF_REQUIRE(st == expected_stat);
	ATF_REQUIRE(required);
	calls++;
	return (verification);
}
static bool
#include "cache_pin_func.c"

ATF_TC_WITHOUT_HEAD(fallback);
ATF_TC_BODY(fallback, tc)
{
	(void)tc;
	struct stat st;
	memset(&st, 0, sizeof(st)); expected_stat = &st;
	const int unavailable[] = {ECAPMODE, EOPNOTSUPP, ENOSYS};
	for (unsigned i = 0; i < sizeof(unavailable)/sizeof(unavailable[0]); i++) {
		calls = 0; verification = 0;
		ATF_REQUIRE(rtld_cache_pin_fallback("signed-library", 42, &st, -1, unavailable[i]));
		ATF_REQUIRE_EQ(1, calls);
		calls = 0; verification = -1;
		ATF_REQUIRE(!rtld_cache_pin_fallback("signed-library", 42, &st, -1, unavailable[i]));
		ATF_REQUIRE_EQ(1, calls);
	}
	const int fatal[] = {EAUTH, EPERM, EACCES, ENOTCAPABLE, EBADF, EIO, ENOMEM, ETXTBSY};
	verification = 0; calls = 0;
	for (unsigned i = 0; i < sizeof(fatal)/sizeof(fatal[0]); i++)
		ATF_REQUIRE(!rtld_cache_pin_fallback("signed-library", 42, &st, -1, fatal[i]));
	/* A successful/absent transport result cannot be disguised by stale errno. */
	ATF_REQUIRE(!rtld_cache_pin_fallback("signed-library", 42, &st, 0, ECAPMODE));
	ATF_REQUIRE(!rtld_cache_pin_fallback("signed-library", 42, &st, 10, ECAPMODE));
	ATF_REQUIRE_EQ(0, calls);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fallback);
	return (atf_no_error());
}
