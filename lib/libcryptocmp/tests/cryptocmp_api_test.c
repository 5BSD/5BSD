/*- SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>

#include <errno.h>
#include <string.h>

#include <atf-c.h>

#include <cryptocmp.h>

ATF_TC(argument_validation);
ATF_TC_HEAD(argument_validation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "libcryptocmp rejects malformed named-key requests before IPC");
}
ATF_TC_BODY(argument_validation, tc)
{
	struct cryptocmp_generate generate;
	char long_name[65];
	uint64_t generation;
	int descriptor;

	memset(&generate, 0, sizeof(generate));
	memset(long_name, 'x', sizeof(long_name));
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_named_create(NULL, "", &generate,
	    &generation) == -1);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_named_create(NULL, long_name,
	    &generate, &generation) == -1);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_named_lease(NULL, "", 0, 0,
	    &generation, &descriptor) == -1);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_named_rotate(NULL, long_name,
	    &generation) == -1);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_named_delete(NULL, "", &generation)
	    == -1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, argument_validation);
	return (atf_no_error());
}
