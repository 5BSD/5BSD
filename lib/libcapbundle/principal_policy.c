/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The principal policy (docs/capability-authority-model.md, P1;
 * docs/ipc-anointments-design.md, "Domains and sessions").
 *
 * This is the single, explicit place a login session's grant is decided: which
 * IPC anointments it holds from login, which it may elevate to per command,
 * and whether its connections carry the ADMIN rights bit.  The session-mint
 * authority lives in the isolated auth-agent daemon (bsdauth), which runs
 * this decision inside a capsicum sandbox.
 *
 * The decision core is data-only: it takes a principal already resolved to a
 * uid and a set of member group ids, plus a caller-supplied group-name->gid
 * resolver.  That keeps the policy engine free of any group-database access of
 * its own -- the auth-agent backs the resolver with Casper cap_grp inside its
 * sandbox; an ordinary in-process caller backs it with getgrnam(3).  The
 * struct-passwd wrappers below build the member set with libc for callers that
 * are not sandboxed.
 *
 * Policy format (UCL):
 *
 *   principals {
 *       admin     { groups = ["wheel"]; uids = [0];
 *                   anointments = ["*"]; admin_rights = true; }
 *       default   { anointments = []; }
 *       operators { groups = ["operators"];
 *                   anointments = ["system.trace.client"];
 *                   may_elevate = ["system.notify.system"]; }
 *   }
 *
 * Entries are evaluated in file order.  The first entry whose `uids` or
 * `groups` match the principal wins; an entry named "default" (or any entry
 * with neither `uids` nor `groups`) is the fallback when nothing matches.  Each
 * entry has a closed schema: uids, groups, anointments, may_elevate,
 * admin_rights.  `anointments` and `may_elevate` are a string or an array of
 * strings, each a reverse-domain name or exactly "*" -- the wildcard is legal
 * here and nowhere else.  `admin_rights` is a boolean; it defaults to true for
 * an entry granting anointments = ["*"] and to false otherwise.
 *
 * Legacy format, still honoured when there is no `principals` block:
 *
 *   admin {
 *       uids   = [ 0 ]        # principals by uid
 *       groups = [ "wheel" ]  # principals in any of these groups
 *   }
 *
 * maps a matching principal to "*" + admin_rights and everyone else to nothing.
 *
 * A present-but-invalid policy (unparseable, unknown key, bad type, bad name)
 * fails safe to the historical default -- uid 0 or a member of "wheel" gets
 * "*" + admin_rights, everyone else nothing -- and reports it through
 * from_default_rule so a parse error can never lock out root yet is never
 * silent.  A valid policy is authoritative, even if it omits root.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
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

/* Closed per-entry schema. */
static const char *const entry_keys[] = {
	"uids", "groups", "anointments", "may_elevate", "admin_rights" };
/* Closed legacy admin-block schema. */
static const char *const legacy_admin_keys[] = { "uids", "groups" };

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

/*
 * Historical default when no usable policy is configured: uid 0 or a "wheel"
 * member holds everything and carries ADMIN; everyone else holds nothing.
 */
static void
default_grant(uid_t uid, const gid_t *members, unsigned nmember,
    capbundle_group_gid_fn name2gid, void *ctx,
    struct capbundle_principal_grant *out)
{

	(void)uid;
	(void)members;
	(void)nmember;
	(void)name2gid;
	(void)ctx;
	/*
	 * Least privilege for EVERY principal, uid 0 included: with no principal
	 * policy present, a login holds nothing gated and carries no admin bypass.
	 * uid 0 is not magic here -- operator authority is granted only by an
	 * explicit principal-policy.ucl entry (declaration-is-the-grant), never by
	 * being root.  A machine with no policy at all is administered from the
	 * pre-plane recovery shell (capsule single-user), not from a logged-in
	 * session, so this fail-closed default cannot lock the operator out.
	 */
	memset(out, 0, sizeof(*out));
	out->from_default_rule = true;
}

static bool
keys_allowed(const ucl_object_t *obj, const char *const *allowed,
    size_t nallowed)
{
	const ucl_object_t *v;
	ucl_object_iter_t it = NULL;
	const char *key;
	size_t i;

	while ((v = ucl_object_iterate(obj, &it, true)) != NULL) {
		key = ucl_object_key(v);
		if (key == NULL)
			return (false);
		for (i = 0; i < nallowed; i++)
			if (strcmp(key, allowed[i]) == 0)
				break;
		if (i == nallowed)
			return (false);
	}
	return (true);
}

/*
 * uids: an integer or an array of non-negative integers.  Sets *match when
 * the principal's uid is listed.  Returns false when malformed.
 */
static bool
match_uids(const ucl_object_t *uids, uid_t uid, bool *match)
{
	const ucl_object_t *u;
	ucl_object_iter_t it = NULL;
	int64_t v;

	if (ucl_object_type(uids) != UCL_INT && ucl_object_type(uids) != UCL_ARRAY)
		return (false);
	while ((u = ucl_object_iterate(uids, &it, true)) != NULL) {
		if (ucl_object_type(u) != UCL_INT)
			return (false);
		v = ucl_object_toint(u);
		if (v < 0 || v > (int64_t)UINT32_MAX)
			return (false);
		if ((uid_t)v == uid)
			*match = true;
	}
	return (true);
}

/*
 * groups: a string or an array of group names.  Sets *match when the
 * principal is a member of any of them (an unknown name simply never matches).
 * Returns false when malformed.
 */
static bool
match_groups(const ucl_object_t *groups, const gid_t *members, unsigned nmember,
    capbundle_group_gid_fn name2gid, void *ctx, bool *match)
{
	const ucl_object_t *g;
	ucl_object_iter_t it = NULL;
	const char *name;

	if (ucl_object_type(groups) != UCL_STRING &&
	    ucl_object_type(groups) != UCL_ARRAY)
		return (false);
	while ((g = ucl_object_iterate(groups, &it, true)) != NULL) {
		if (ucl_object_type(g) != UCL_STRING)
			return (false);
		name = ucl_object_tostring(g);
		if (name[0] == '\0')
			return (false);
		if (member_of(members, nmember, name2gid(ctx, name)))
			*match = true;
	}
	return (true);
}

/*
 * One name list (`anointments` or `may_elevate`): a string or an array of
 * strings, each a reverse-domain name or "*".  Names are deduplicated; "*"
 * sets *all.  Returns false when malformed or over the size limit.
 */
static bool
grant_names(const ucl_object_t *v, char (*dst)[CAPBUNDLE_LABEL_MAX],
    unsigned *count, bool *all)
{
	const ucl_object_t *e;
	ucl_object_iter_t it = NULL;
	const char *name;
	unsigned i;

	*count = 0;
	*all = false;
	if (ucl_object_type(v) != UCL_STRING && ucl_object_type(v) != UCL_ARRAY)
		return (false);
	while ((e = ucl_object_iterate(v, &it, true)) != NULL) {
		if (ucl_object_type(e) != UCL_STRING)
			return (false);
		name = ucl_object_tostring(e);
		if (strcmp(name, "*") == 0) {
			*all = true;
			continue;
		}
		if (!capbundle_valid_service_name(name, CAPBUNDLE_LABEL_MAX))
			return (false);
		for (i = 0; i < *count; i++)
			if (strcmp(dst[i], name) == 0)
				break;
		if (i < *count)
			continue;
		if (*count >= CAPBUNDLE_PRINCIPAL_MAX_NAMES)
			return (false);
		strlcpy(dst[*count], name, CAPBUNDLE_LABEL_MAX);
		(*count)++;
	}
	return (true);
}

/*
 * Fill *out from one principals entry.  Returns false when the entry is
 * malformed.  The caller has already cleared *out.
 */
static bool
apply_entry(const ucl_object_t *entry, struct capbundle_principal_grant *out)
{
	const ucl_object_t *v;

	if ((v = ucl_object_lookup(entry, "anointments")) != NULL &&
	    !grant_names(v, out->anointments, &out->nanointments,
	    &out->anoint_all))
		return (false);
	if ((v = ucl_object_lookup(entry, "may_elevate")) != NULL &&
	    !grant_names(v, out->may_elevate, &out->nmay_elevate,
	    &out->elevate_all))
		return (false);
	v = ucl_object_lookup(entry, "admin_rights");
	if (v == NULL)
		out->admin_rights = out->anoint_all;
	else if (ucl_object_type(v) == UCL_BOOLEAN)
		out->admin_rights = ucl_object_toboolean(v);
	else
		return (false);
	return (true);
}

/*
 * Check one entry's shape and selectors without committing to it: closed
 * key set, well-typed uids/groups/name lists/admin_rights.  Reports whether
 * the principal matches and whether the entry is a fallback.
 */
static bool
inspect_entry(const ucl_object_t *entry, uid_t uid, const gid_t *members,
    unsigned nmember, capbundle_group_gid_fn name2gid, void *ctx,
    bool *match, bool *is_default)
{
	struct capbundle_principal_grant scratch;
	const ucl_object_t *uids, *groups;
	const char *key;

	*match = false;
	*is_default = false;
	if (ucl_object_type(entry) != UCL_OBJECT)
		return (false);
	if (!keys_allowed(entry, entry_keys, nitems(entry_keys)))
		return (false);
	uids = ucl_object_lookup(entry, "uids");
	groups = ucl_object_lookup(entry, "groups");
	if (uids != NULL && !match_uids(uids, uid, match))
		return (false);
	if (groups != NULL &&
	    !match_groups(groups, members, nmember, name2gid, ctx, match))
		return (false);
	key = ucl_object_key(entry);
	if ((uids == NULL && groups == NULL) ||
	    (key != NULL && strcmp(key, "default") == 0))
		*is_default = true;
	memset(&scratch, 0, sizeof(scratch));
	return (apply_entry(entry, &scratch));
}

/*
 * Resolve the grant against a parsed policy `root`.  Returns false when the
 * policy is malformed, in which case the caller applies the historical rule.
 * A valid policy always yields a grant (possibly empty) and returns true.
 */
static bool
policy_grant(const ucl_object_t *root, uid_t uid, const gid_t *members,
    unsigned nmember, capbundle_group_gid_fn name2gid, void *ctx,
    struct capbundle_principal_grant *out)
{
	const ucl_object_t *principals, *entry, *chosen, *fallback;
	const ucl_object_t *admin, *uids, *groups;
	ucl_object_iter_t it = NULL;
	bool match, is_default;

	memset(out, 0, sizeof(*out));
	if (ucl_object_type(root) != UCL_OBJECT)
		return (false);
	principals = ucl_object_lookup(root, "principals");
	if (principals == NULL) {
		/* Legacy: admin { uids; groups } -> "*" + ADMIN, else nothing. */
		admin = ucl_object_lookup(root, "admin");
		if (admin == NULL)
			return (true);
		if (ucl_object_type(admin) != UCL_OBJECT ||
		    !keys_allowed(admin, legacy_admin_keys,
		    nitems(legacy_admin_keys)))
			return (false);
		match = false;
		uids = ucl_object_lookup(admin, "uids");
		groups = ucl_object_lookup(admin, "groups");
		if (uids != NULL && !match_uids(uids, uid, &match))
			return (false);
		if (groups != NULL && !match_groups(groups, members, nmember,
		    name2gid, ctx, &match))
			return (false);
		if (match) {
			out->anoint_all = true;
			out->admin_rights = true;
		}
		return (true);
	}
	if (ucl_object_type(principals) != UCL_OBJECT)
		return (false);

	/*
	 * Validate every entry before choosing one, so a malformed entry
	 * anywhere in the file makes the whole file fall back rather than
	 * silently applying only the well-formed prefix.  First match in file
	 * order wins; the first fallback entry applies when nothing matches.
	 */
	chosen = fallback = NULL;
	while ((entry = ucl_object_iterate(principals, &it, true)) != NULL) {
		if (!inspect_entry(entry, uid, members, nmember, name2gid, ctx,
		    &match, &is_default))
			return (false);
		if (match && chosen == NULL)
			chosen = entry;
		else if (is_default && fallback == NULL)
			fallback = entry;
	}
	if (chosen == NULL)
		chosen = fallback;
	if (chosen == NULL)
		return (true);		/* in no entry: empty grant */
	return (apply_entry(chosen, out));
}

/* Parse the policy from an open read-only descriptor; NULL if unusable. */
static ucl_object_t *
load_policy(int policy_fd)
{
	struct ucl_parser *parser;
	ucl_object_t *root = NULL;
	struct stat sb;
	unsigned char *buf;
	ssize_t rd;

	if (policy_fd < 0 || fstat(policy_fd, &sb) != 0 ||
	    !S_ISREG(sb.st_mode) || sb.st_size <= 0 ||
	    sb.st_size > CAPBUNDLE_MAX_UCL_SIZE)
		return (NULL);
	if ((buf = malloc((size_t)sb.st_size)) == NULL)
		return (NULL);
	rd = pread(policy_fd, buf, (size_t)sb.st_size, 0);
	if (rd == (ssize_t)sb.st_size && (parser = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_FILEVARS)) != NULL) {
		if (ucl_parser_add_chunk(parser, buf, (size_t)rd) &&
		    ucl_parser_get_error(parser) == NULL)
			root = ucl_parser_get_object(parser);
		ucl_parser_free(parser);
	}
	free(buf);
	return (root);
}

/*
 * Enumerate every SPECIFIC anointment name that any entry in the policy grants
 * or lets a principal elevate to -- i.e. the union of all entries'
 * `anointments` and `may_elevate` lists, excluding "*".  The graph tool uses
 * this to know a gated endpoint is reachable by some principal (an operator
 * granted the name, or one that may elevate to it), not only by a wildcard
 * admin, so it does not falsely flag such an endpoint unreachable.  Names are
 * deduplicated; `*count` is set to how many were written (capped at `max`).
 * A missing or malformed policy yields `*count == 0` and success.  Returns 0
 * on success, -1 with errno on a bad argument.
 */
int
capbundle_principal_declared_names(int policy_fd,
    char (*names)[CAPBUNDLE_LABEL_MAX], unsigned max, unsigned *count)
{
	ucl_object_t *root;
	const ucl_object_t *principals, *entry, *lists[2];
	ucl_object_iter_t it = NULL;
	unsigned k, li;

	if (names == NULL || count == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*count = 0;
	root = load_policy(policy_fd);
	if (root == NULL)
		return (0);
	principals = ucl_object_lookup(root, "principals");
	if (principals == NULL || ucl_object_type(principals) != UCL_OBJECT) {
		ucl_object_unref(root);
		return (0);
	}
	while ((entry = ucl_object_iterate(principals, &it, true)) != NULL) {
		if (ucl_object_type(entry) != UCL_OBJECT)
			continue;
		lists[0] = ucl_object_lookup(entry, "anointments");
		lists[1] = ucl_object_lookup(entry, "may_elevate");
		for (li = 0; li < nitems(lists); li++) {
			const ucl_object_t *e;
			ucl_object_iter_t jt = NULL;
			const char *name;

			if (lists[li] == NULL)
				continue;
			while ((e = ucl_object_iterate(lists[li], &jt,
			    true)) != NULL) {
				if (ucl_object_type(e) != UCL_STRING)
					continue;
				name = ucl_object_tostring(e);
				if (name == NULL || strcmp(name, "*") == 0)
					continue;
				for (k = 0; k < *count; k++)
					if (strcmp(names[k], name) == 0)
						break;
				if (k < *count)
					continue;
				if (*count >= max)
					continue;
				strlcpy(names[*count], name,
				    CAPBUNDLE_LABEL_MAX);
				(*count)++;
			}
		}
	}
	ucl_object_unref(root);
	return (0);
}

/*
 * Public data-only entry point (see libcapbundle.h).  This is what the
 * sandboxed auth-agent calls: it resolves the principal via Casper and passes
 * the results plus a cap_grp-backed resolver, so no group database is touched
 * here.  A bad, absent, or malformed policy fails safe to the historical rule
 * and says so through from_default_rule.
 */
int
capbundle_principal_resolve(int policy_fd, uid_t uid, const gid_t *member_gids,
    unsigned nmember, capbundle_group_gid_fn name2gid, void *ctx,
    struct capbundle_principal_grant *out)
{
	ucl_object_t *root;

	if (out == NULL || name2gid == NULL ||
	    (member_gids == NULL && nmember > 0)) {
		errno = EINVAL;
		return (-1);
	}
	root = load_policy(policy_fd);
	if (root == NULL || !policy_grant(root, uid, member_gids, nmember,
	    name2gid, ctx, out))
		default_grant(uid, member_gids, nmember, name2gid, ctx, out);
	if (root != NULL)
		ucl_object_unref(root);
	return (0);
}

static bool
grant_lists(const char (*names)[CAPBUNDLE_LABEL_MAX], unsigned n, bool all,
    const char *name)
{
	unsigned i;

	if (name == NULL || name[0] == '\0')
		return (false);
	if (all)
		return (true);
	if (n > CAPBUNDLE_PRINCIPAL_MAX_NAMES)
		n = CAPBUNDLE_PRINCIPAL_MAX_NAMES;
	for (i = 0; i < n; i++)
		if (strcmp(names[i], name) == 0)
			return (true);
	return (false);
}

bool
capbundle_principal_holds(const struct capbundle_principal_grant *g,
    const char *name)
{

	if (g == NULL)
		return (false);
	return (grant_lists(g->anointments, g->nanointments, g->anoint_all,
	    name));
}

bool
capbundle_principal_may_elevate(const struct capbundle_principal_grant *g,
    const char *name)
{

	if (g == NULL)
		return (false);
	return (grant_lists(g->may_elevate, g->nmay_elevate, g->elevate_all,
	    name));
}

/*
 * Admin-ness is the grant's admin_rights knob; kept as a thin wrapper for the
 * auth-agent until it consumes the full grant.
 */
bool
capbundle_principal_is_admin_resolved(int policy_fd, uid_t uid,
    const gid_t *member_gids, unsigned nmember,
    capbundle_group_gid_fn name2gid, void *ctx)
{
	struct capbundle_principal_grant g;

	if (capbundle_principal_resolve(policy_fd, uid, member_gids, nmember,
	    name2gid, ctx, &g) != 0)
		return (false);
	return (g.admin_rights);
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
	/* O_VERIFY: verified when mac_veriexec enforces, a no-op otherwise
	 * (docs/ipc-anointments-design.md).  The principal policy decides every
	 * session's anointment set, so it is integrity-protected alongside the
	 * bundle policy files. */
	fd = open(policy_path, O_RDONLY | O_CLOEXEC | O_VERIFY);
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
