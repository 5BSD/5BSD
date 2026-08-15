/*- SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>

#include <errno.h>
#include <string.h>

#include <atf-c.h>

#include <cryptodesc.h>

ATF_TC(argument_validation);
ATF_TC_HEAD(argument_validation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "libcryptodesc rejects malformed capability requests before ioctl");
}
ATF_TC_BODY(argument_validation, tc)
{
	struct session2_op session;
	uint8_t public_key[CRYPTODESC_ED25519_PUBLIC_SIZE];
	uint64_t generation;
	int descriptor;

	memset(&session, 0, sizeof(session));
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptodesc_mint(-1, NULL, 0, NULL) == -1);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptodesc_mint_generated(-1, &session,
	    CRYPTODESC_RIGHT_ENCRYPT, 0, &descriptor) == -1);
	session.key = public_key;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptodesc_mint_generated(-1, &session,
	    CRYPTODESC_RIGHT_ENCRYPT, 0, &descriptor) == -1);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptodesc_mint_key(-1, CRYPTODESC_KEY_ED25519,
	    CRYPTODESC_RIGHT_SIGN, 0, NULL, &descriptor) == -1);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptodesc_named_create(0, "bad/name", "owner",
	    &session, CRYPTODESC_RIGHT_ENCRYPT, &generation) == -1);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptodesc_named_lease(0, "name", "bad/owner",
	    CRYPTODESC_RIGHT_ENCRYPT, 0, &generation, &descriptor) == -1);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptodesc_named_rotate(0, "", "owner",
	    &generation) == -1);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptodesc_restrict(-1,
	    CRYPTODESC_RIGHT_ALL + 1) == -1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, argument_validation);
	return (atf_no_error());
}
