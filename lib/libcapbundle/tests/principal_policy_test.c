/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Unit tests for the principal->bundle admin policy
 * (docs/capability-authority-model.md, P1).  The path-parameterized core
 * capbundle_principal_is_admin_at() is driven with temporary policy files.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libcapbundle_internal.h"

/* A synthetic principal, not present in any group database on the host. */
static struct passwd
principal(uid_t uid)
{
	struct passwd pw;

	memset(&pw, 0, sizeof(pw));
	pw.pw_name = __DECONST(char *, "cap_policy_test_user");
	pw.pw_uid = uid;
	pw.pw_gid = uid;
	return (pw);
}

/* Write `text` to a fresh temp file; caller unlinks via the returned path. */
static void
write_policy(char path[], size_t pathlen, const char *text)
{
	int fd;
	FILE *fp;

	strlcpy(path, "/tmp/cappolicy.XXXXXX", pathlen);
	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	fp = fdopen(fd, "w");
	ATF_REQUIRE(fp != NULL);
	ATF_REQUIRE(fputs(text, fp) >= 0);
	ATF_REQUIRE(fclose(fp) == 0);
}

ATF_TC_WITHOUT_HEAD(no_policy_defaults_to_root);
ATF_TC_BODY(no_policy_defaults_to_root, tc)
{
	struct passwd root = principal(0);
	struct passwd user = principal(1234);

	/* Absent policy: historical default -- root is admin, others are not
	 * (the synthetic user is in no group, so not in wheel). */
	ATF_CHECK(capbundle_principal_is_admin_at(&root,
	    "/nonexistent/principal-policy.ucl"));
	ATF_CHECK(!capbundle_principal_is_admin_at(&user,
	    "/nonexistent/principal-policy.ucl"));
}

ATF_TC_WITHOUT_HEAD(policy_grants_by_uid);
ATF_TC_BODY(policy_grants_by_uid, tc)
{
	struct passwd granted = principal(1234);
	struct passwd other = principal(5678);
	char path[64];

	write_policy(path, sizeof(path), "admin { uids = [ 1234 ] }\n");
	ATF_CHECK(capbundle_principal_is_admin_at(&granted, path));
	ATF_CHECK(!capbundle_principal_is_admin_at(&other, path));
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(valid_policy_is_authoritative);
ATF_TC_BODY(valid_policy_is_authoritative, tc)
{
	struct passwd root = principal(0);
	char path[64];

	/* A valid policy that lists no uids is authoritative: even root is not
	 * an administrator unless the policy names it.  (This is the model --
	 * root is not automatically privileged.) */
	write_policy(path, sizeof(path), "admin { uids = [ 1234 ] }\n");
	ATF_CHECK(!capbundle_principal_is_admin_at(&root, path));
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(malformed_policy_fails_safe_to_default);
ATF_TC_BODY(malformed_policy_fails_safe_to_default, tc)
{
	struct passwd root = principal(0);
	struct passwd user = principal(1234);
	char path[64];

	/* An unparseable policy must fall back to the historical default so a
	 * typo can never lock root out. */
	write_policy(path, sizeof(path), "admin { uids = [ this is not ucl \n");
	ATF_CHECK(capbundle_principal_is_admin_at(&root, path));
	ATF_CHECK(!capbundle_principal_is_admin_at(&user, path));
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(null_principal_is_not_admin);
ATF_TC_BODY(null_principal_is_not_admin, tc)
{

	ATF_CHECK(!capbundle_principal_is_admin_at(NULL,
	    "/nonexistent/principal-policy.ucl"));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, no_policy_defaults_to_root);
	ATF_TP_ADD_TC(tp, policy_grants_by_uid);
	ATF_TP_ADD_TC(tp, valid_policy_is_authoritative);
	ATF_TP_ADD_TC(tp, malformed_policy_fails_safe_to_default);
	ATF_TP_ADD_TC(tp, null_principal_is_not_admin);
	return (atf_no_error());
}
