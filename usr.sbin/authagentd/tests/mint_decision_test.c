/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The SYSTEM-vs-USER mint decision, unit-tested through the pure predicate
 * authagent_mint_kind() the daemon factored out of handle_request().  An admin
 * principal mints a full-discovery SYSTEM channel; every other principal mints
 * a per-uid USER channel.  This mirrors lib/libcapbundle's principal-policy
 * tests (temp policy files) one layer up — at the daemon's own decision point —
 * rather than duplicating the policy engine's own coverage.
 *
 * Pure: no plane, no serviced, no Casper.  Runs anywhere.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <libcapbundle.h>

#include "authagentd_test.h"

/*
 * A group-name resolver that knows nothing.  The uid-keyed policies below name
 * no groups, so this is never consulted; it stands in for the daemon's Casper
 * cap_grp backing and proves the decision core needs no group database of its
 * own for these cases.
 */
static gid_t
no_groups(void *ctx __unused, const char *name __unused)
{

	return ((gid_t)-1);
}

/* Write `text` to a fresh temp file; caller unlinks via the returned path. */
static void
write_policy(char path[], size_t pathlen, const char *text)
{
	FILE *fp;
	int fd;

	strlcpy(path, "/tmp/authagent_policy.XXXXXX", pathlen);
	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	fp = fdopen(fd, "w");
	ATF_REQUIRE(fp != NULL);
	ATF_REQUIRE(fputs(text, fp) >= 0);
	ATF_REQUIRE(fclose(fp) == 0);
}

/*
 * With no policy delivered (fd == -1) the historical root-or-wheel default
 * applies: root is an administrator and mints SYSTEM.
 */
ATF_TC_WITHOUT_HEAD(default_root_mints_system);
ATF_TC_BODY(default_root_mints_system, tc)
{

	ATF_CHECK_EQ(SERVICE_MINT_SYSTEM,
	    authagent_mint_kind(-1, 0, NULL, 0, no_groups, NULL));
}

/*
 * A non-admin principal (a synthetic uid in no group) mints USER under the
 * default policy.
 */
ATF_TC_WITHOUT_HEAD(default_nonadmin_mints_user);
ATF_TC_BODY(default_nonadmin_mints_user, tc)
{
	gid_t members[] = { 1234 };

	ATF_CHECK_EQ(SERVICE_MINT_USER,
	    authagent_mint_kind(-1, 1234, members, 1, no_groups, NULL));
}

/* A policy that names a uid mints SYSTEM for it and USER for everyone else. */
ATF_TC_WITHOUT_HEAD(policy_admin_uid_mints_system);
ATF_TC_BODY(policy_admin_uid_mints_system, tc)
{
	gid_t granted_groups[] = { 1234 };
	gid_t other_groups[] = { 5678 };
	char path[64];
	int fd;

	write_policy(path, sizeof(path), "admin { uids = [ 1234 ] }\n");
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_CHECK_EQ(SERVICE_MINT_SYSTEM,
	    authagent_mint_kind(fd, 1234, granted_groups, 1, no_groups, NULL));
	ATF_CHECK_EQ(SERVICE_MINT_USER,
	    authagent_mint_kind(fd, 5678, other_groups, 1, no_groups, NULL));

	(void)close(fd);
	(void)unlink(path);
}

/*
 * An authoritative policy that names no uids denies even root: root is not
 * automatically privileged in the capability model, so it mints USER.
 */
ATF_TC_WITHOUT_HEAD(policy_without_root_mints_user_for_root);
ATF_TC_BODY(policy_without_root_mints_user_for_root, tc)
{
	char path[64];
	int fd;

	write_policy(path, sizeof(path), "admin { uids = [ 1234 ] }\n");
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_CHECK_EQ(SERVICE_MINT_USER,
	    authagent_mint_kind(fd, 0, NULL, 0, no_groups, NULL));

	(void)close(fd);
	(void)unlink(path);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, default_root_mints_system);
	ATF_TP_ADD_TC(tp, default_nonadmin_mints_user);
	ATF_TP_ADD_TC(tp, policy_admin_uid_mints_system);
	ATF_TP_ADD_TC(tp, policy_without_root_mints_user_for_root);
	return (atf_no_error());
}
