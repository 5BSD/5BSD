/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The principal->bundle admin policy (docs/capability-authority-model.md, P1).
 *
 * This is the single, explicit place the admin decision is made.  It reads a
 * UCL policy and answers whether a principal is entitled to an admin
 * (full-discovery) session.  When no policy is configured it applies the
 * historical rule -- root, or a member of group "wheel" -- so a system with no
 * policy behaves exactly as before.  The session-mint authority lives in the
 * isolated auth-agent daemon (authagentd), which runs this decision inside a
 * capsicum sandbox.
 *
 * The decision core (admin_decision) is data-only: it takes a principal already
 * resolved to a uid and a set of member group ids, plus a caller-supplied
 * group-name->gid resolver.  That keeps the policy engine free of any
 * group-database access of its own -- the auth-agent backs the resolver with
 * Casper cap_grp inside its sandbox; an ordinary in-process caller backs it with
 * getgrnam(3).  The struct-passwd wrappers below build the member set with libc
 * for callers that are not sandboxed.
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

#include <fcntl.h>
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

/* ---- the data-only decision core ------------------------------------- */

static bool
member_of(const gid_t *members, unsigned nmember, gid_t g)
{
	unsigned i;

	if (g == (gid_t)-1)
		return (false);
	for (i = 0; i < nmember; i++)
		if (members[i] == g)
			return (true);
	return (false);
}

/* Historical default when no policy is configured: uid 0 or a "wheel" member. */
static bool
default_admin(uid_t uid, const gid_t *members, unsigned nmember,
    capbundle_group_gid_fn name2gid, void *ctx)
{

	if (uid == 0)
		return (true);
	return (member_of(members, nmember, name2gid(ctx, "wheel")));
}

/* Whether the principal is a member of any group named in admin.groups. */
static bool
in_policy_group(const gid_t *members, unsigned nmember,
    const ucl_object_t *groups_arr, capbundle_group_gid_fn name2gid, void *ctx)
{
	ucl_object_iter_t it = NULL;
	const ucl_object_t *g;

	while ((g = ucl_object_iterate(groups_arr, &it, true)) != NULL) {
		const char *name = ucl_object_tostring(g);

		if (name != NULL &&
		    member_of(members, nmember, name2gid(ctx, name)))
			return (true);
	}
	return (false);
}

/*
 * Resolve the admin decision for a principal already reduced to (uid, member
 * gid set), against a parsed policy `root` (or NULL for the historical default).
 */
static bool
admin_decision(uid_t uid, const gid_t *members, unsigned nmember,
    const ucl_object_t *root, capbundle_group_gid_fn name2gid, void *ctx)
{
	const ucl_object_t *admin, *uids, *groups_arr, *u;
	ucl_object_iter_t it = NULL;

	if (root == NULL)
		return (default_admin(uid, members, nmember, name2gid, ctx));

	admin = ucl_object_lookup(root, "admin");
	if (admin == NULL)
		return (false);
	uids = ucl_object_lookup(admin, "uids");
	while (uids != NULL &&
	    (u = ucl_object_iterate(uids, &it, true)) != NULL)
		if ((uid_t)ucl_object_toint(u) == uid)
			return (true);
	groups_arr = ucl_object_lookup(admin, "groups");
	if (groups_arr != NULL &&
	    in_policy_group(members, nmember, groups_arr, name2gid, ctx))
		return (true);
	return (false);
}

/*
 * Public data-only entry point (see libcapbundle.h).  Parse the policy from an
 * open read-only descriptor (or none) and decide.  This is what the sandboxed
 * auth-agent calls: it resolves the principal via Casper and passes the results
 * plus a cap_grp-backed resolver, so no group database is touched here.  A bad
 * or absent fd fails safe to the historical default.
 */
bool
capbundle_principal_is_admin_resolved(int policy_fd, uid_t uid,
    const gid_t *member_gids, unsigned nmember,
    capbundle_group_gid_fn name2gid, void *ctx)
{
	struct ucl_parser *parser;
	ucl_object_t *root = NULL;
	struct stat sb;
	unsigned char *buf;
	ssize_t rd;
	bool result;

	if (name2gid == NULL)
		return (false);
	if (policy_fd >= 0 && fstat(policy_fd, &sb) == 0 &&
	    S_ISREG(sb.st_mode) && sb.st_size > 0 &&
	    sb.st_size <= CAPBUNDLE_MAX_UCL_SIZE &&
	    (buf = malloc((size_t)sb.st_size)) != NULL) {
		rd = pread(policy_fd, buf, (size_t)sb.st_size, 0);
		if (rd == (ssize_t)sb.st_size &&
		    (parser = ucl_parser_new(0)) != NULL) {
			if (ucl_parser_add_chunk(parser, buf, (size_t)rd) &&
			    ucl_parser_get_error(parser) == NULL)
				root = ucl_parser_get_object(parser);
			ucl_parser_free(parser);
		}
		free(buf);
	}
	result = admin_decision(uid, member_gids, nmember, root, name2gid, ctx);
	if (root != NULL)
		ucl_object_unref(root);
	return (result);
}

/* ---- libc-backed convenience wrappers (non-sandboxed callers) -------- */

static gid_t
libc_name2gid(void *ctx __unused, const char *name)
{
	struct group *gr = getgrnam(name);

	return (gr != NULL ? gr->gr_gid : (gid_t)-1);
}

/* Resolve a principal's group membership (primary + supplementary) via libc. */
static unsigned
libc_member_gids(const struct passwd *pwd, gid_t *out, unsigned max)
{
	int ng = (int)max;

	if (getgrouplist(pwd->pw_name, pwd->pw_gid, out, &ng) == -1)
		ng = (int)max;			/* truncated: use what fit */
	if (ng < 0)
		ng = 0;
	return ((unsigned)ng > max ? max : (unsigned)ng);
}

/*
 * Path-parameterized form: open the policy and decide with libc-resolved group
 * membership.  Used by tests (temporary policy files) and by in-process,
 * non-sandboxed callers.
 */
bool
capbundle_principal_is_admin_at(const struct passwd *pwd, const char *policy_path)
{
	gid_t members[NGROUPS_MAX];
	unsigned n;
	int fd;
	bool result;

	if (pwd == NULL)
		return (false);
	n = libc_member_gids(pwd, members, nitems(members));
	fd = open(policy_path, O_RDONLY | O_CLOEXEC);
	result = capbundle_principal_is_admin_resolved(fd, pwd->pw_uid, members,
	    n, libc_name2gid, NULL);
	if (fd >= 0)
		(void)close(fd);
	return (result);
}

/* Descriptor form with a struct passwd, libc group resolution. */
bool
capbundle_principal_is_admin_fd(const struct passwd *pwd, int policy_fd)
{
	gid_t members[NGROUPS_MAX];
	unsigned n;

	if (pwd == NULL)
		return (false);
	n = libc_member_gids(pwd, members, nitems(members));
	return (capbundle_principal_is_admin_resolved(policy_fd, pwd->pw_uid,
	    members, n, libc_name2gid, NULL));
}

bool
capbundle_principal_is_admin(const struct passwd *pwd)
{

	return (capbundle_principal_is_admin_at(pwd, PRINCIPAL_POLICY_PATH));
}
