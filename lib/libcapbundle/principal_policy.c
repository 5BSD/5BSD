/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The principal->bundle admin policy (docs/capability-authority-model.md, P1).
 *
 * This is the single, explicit place the admin decision is made.  It reads a
 * UCL policy and answers whether a principal is entitled to an admin
 * (full-discovery) session; login/su consult it instead of testing the uid
 * inline.  When no policy is configured it applies the historical rule -- root,
 * or a member of group "wheel" -- so a system with no policy behaves exactly as
 * before.  A later sub-phase moves the policy read (and the session-mint
 * capability) into an isolated auth-agent daemon; the call sites do not change.
 *
 * Policy format (UCL):
 *
 *   admin {
 *       uids   = [ 0 ]        # principals by uid
 *       groups = [ "wheel" ]  # principals in any of these groups
 *   }
 *
 * A principal is an administrator if its uid appears in admin.uids or it is a
 * member of any group in admin.groups.  A present-but-invalid policy fails safe
 * to the historical default (so a parse error can never lock out root); a valid
 * policy is authoritative, even if it omits root.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ucl.h>

#include "libcapbundle.h"
#include "libcapbundle_internal.h"

#define	PRINCIPAL_POLICY_PATH	"/Capabilities/Config/principal-policy.ucl"

/* The historical rule, used when no policy is configured: root or wheel. */
static bool
default_admin(const struct passwd *pwd)
{
	gid_t groups[NGROUPS_MAX];
	struct group *wheel;
	int ngroups, i;

	if (pwd->pw_uid == 0)
		return (true);
	if ((wheel = getgrnam("wheel")) == NULL)
		return (false);
	ngroups = nitems(groups);
	if (getgrouplist(pwd->pw_name, pwd->pw_gid, groups, &ngroups) == -1)
		ngroups = nitems(groups);	/* truncated: scan what fit */
	for (i = 0; i < ngroups && i < (int)nitems(groups); i++)
		if (groups[i] == wheel->gr_gid)
			return (true);
	return (false);
}

/* Whether pwd is a member of any group named in the admin.groups array. */
static bool
in_policy_group(const struct passwd *pwd, const ucl_object_t *groups_arr)
{
	gid_t groups[NGROUPS_MAX];
	ucl_object_iter_t it = NULL;
	const ucl_object_t *g;
	int ngroups, i;

	ngroups = nitems(groups);
	if (getgrouplist(pwd->pw_name, pwd->pw_gid, groups, &ngroups) == -1)
		ngroups = nitems(groups);
	while ((g = ucl_object_iterate(groups_arr, &it, true)) != NULL) {
		const char *name = ucl_object_tostring(g);
		struct group *gr;

		if (name == NULL || (gr = getgrnam(name)) == NULL)
			continue;
		for (i = 0; i < ngroups && i < (int)nitems(groups); i++)
			if (groups[i] == gr->gr_gid)
				return (true);
	}
	return (false);
}

/*
 * Evaluate a parsed policy against a principal.  `root` is a parsed policy
 * document (which the caller unrefs) or NULL, in which case the historical
 * root-or-wheel default applies.  Shared by the path and fd entry points.
 */
static bool
eval_admin(const struct passwd *pwd, const ucl_object_t *root)
{
	const ucl_object_t *admin, *uids, *groups_arr, *u;
	ucl_object_iter_t it = NULL;
	bool result;

	if (root == NULL)
		return (default_admin(pwd));

	result = false;
	admin = ucl_object_lookup(root, "admin");
	if (admin != NULL) {
		uids = ucl_object_lookup(admin, "uids");
		while (uids != NULL &&
		    (u = ucl_object_iterate(uids, &it, true)) != NULL) {
			if ((uid_t)ucl_object_toint(u) == pwd->pw_uid) {
				result = true;
				break;
			}
		}
		if (!result) {
			groups_arr = ucl_object_lookup(admin, "groups");
			if (groups_arr != NULL &&
			    in_policy_group(pwd, groups_arr))
				result = true;
		}
	}
	return (result);
}

/*
 * Path-parameterized core (see libcapbundle_internal.h): resolve the admin
 * decision against the policy at `policy_path`.  The public entry point below
 * pins the real path; tests drive this with a temporary policy file.
 */
bool
capbundle_principal_is_admin_at(const struct passwd *pwd, const char *policy_path)
{
	struct ucl_parser *parser;
	ucl_object_t *root;
	bool result;

	if (pwd == NULL)
		return (false);

	parser = ucl_parser_new(0);
	if (parser == NULL)
		return (default_admin(pwd));
	if (!ucl_parser_add_file(parser, policy_path) ||
	    ucl_parser_get_error(parser) != NULL) {
		/* Absent, unreadable, or invalid: historical default. */
		ucl_parser_free(parser);
		return (default_admin(pwd));
	}
	root = ucl_parser_get_object(parser);
	ucl_parser_free(parser);
	result = eval_admin(pwd, root);
	if (root != NULL)
		ucl_object_unref(root);
	return (result);
}

/*
 * Descriptor-parameterized core: resolve the admin decision against a policy
 * delivered as an already-open read-only descriptor (capabilities.open).  This
 * is the capsicum-clean path — the auth-agent holds no policy path and never
 * calls open(2).  The fd is read into a buffer and parsed as a chunk (no mmap,
 * so CAP_READ|CAP_SEEK|CAP_FSTAT on the fd suffice).  A bad or absent fd fails
 * safe to the historical default, exactly like an unreadable policy path.
 */
bool
capbundle_principal_is_admin_fd(const struct passwd *pwd, int policy_fd)
{
	struct ucl_parser *parser;
	ucl_object_t *root;
	struct stat sb;
	unsigned char *buf;
	ssize_t rd;
	bool result;

	if (pwd == NULL)
		return (false);
	if (policy_fd < 0 || fstat(policy_fd, &sb) == -1 ||
	    !S_ISREG(sb.st_mode) || sb.st_size <= 0 ||
	    sb.st_size > CAPBUNDLE_MAX_UCL_SIZE)
		return (default_admin(pwd));
	buf = malloc((size_t)sb.st_size);
	if (buf == NULL)
		return (default_admin(pwd));
	rd = pread(policy_fd, buf, (size_t)sb.st_size, 0);
	if (rd != (ssize_t)sb.st_size) {
		free(buf);
		return (default_admin(pwd));
	}
	parser = ucl_parser_new(0);
	if (parser == NULL) {
		free(buf);
		return (default_admin(pwd));
	}
	if (!ucl_parser_add_chunk(parser, buf, (size_t)rd) ||
	    ucl_parser_get_error(parser) != NULL) {
		ucl_parser_free(parser);
		free(buf);
		return (default_admin(pwd));
	}
	root = ucl_parser_get_object(parser);
	ucl_parser_free(parser);
	free(buf);
	result = eval_admin(pwd, root);
	if (root != NULL)
		ucl_object_unref(root);
	return (result);
}

bool
capbundle_principal_is_admin(const struct passwd *pwd)
{

	return (capbundle_principal_is_admin_at(pwd, PRINCIPAL_POLICY_PATH));
}
