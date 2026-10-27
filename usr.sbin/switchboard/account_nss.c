/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include "account_nss.h"
#include "nss_exchange.h"

static bool isolated;
static char helper_path[PATH_MAX];
static int diagnostic_fd = -1, lookup_timeout;
static struct sb_nss_reply user_reply;

int
account_nss_isolate(const char *helper, int diagnostic, int timeout_ms)
{
	int fd;
	if (isolated) return (errno = EALREADY, -1);
	if (helper == NULL || helper[0] != '/' || strlen(helper) >= sizeof(helper_path) ||
	    diagnostic < 0 || timeout_ms <= 0) return (errno = EINVAL, -1);
	fd = fcntl(diagnostic, F_DUPFD_CLOEXEC, 3);
	if (fd == -1) return (-1);
	strlcpy(helper_path, helper, sizeof(helper_path));
	diagnostic_fd = fd;
	lookup_timeout = timeout_ms;
	isolated = true;
	return (0);
}

static int
lookup(uint32_t operation, const char *name, uint32_t id, uid_t owner,
    struct sb_nss_reply *reply)
{
	struct sb_nss_request request = { .version = SB_NSS_VERSION,
	    .operation = operation, .id = id };
	if (name != NULL && strlcpy(request.name, name, sizeof(request.name)) >=
	    sizeof(request.name)) return (errno = ENAMETOOLONG, -1);
	return (sb_nss_exchange(helper_path, diagnostic_fd, &request, owner,
	    lookup_timeout, reply));
}

int
account_nss_uid(uid_t uid, char *name, size_t size)
{
	struct sb_nss_reply reply;
	struct passwd *pw;
	const char *resolved;
	if (uid == (uid_t)-1 || name == NULL || size == 0)
		return (errno = EINVAL, -1);
	if (isolated) {
		if (lookup(SB_NSS_USER_UID, NULL, uid, uid, &reply) == -1) return (-1);
		resolved = reply.name;
	} else {
		errno = 0;
		pw = getpwuid(uid);
		if (pw == NULL) { if (errno == 0) errno = ENOENT; return (-1); }
		if (pw->pw_uid != uid || pw->pw_name == NULL)
			return (errno = EPERM, -1);
		resolved = pw->pw_name;
	}
	if (strlcpy(name, resolved, size) >= size)
		return (errno = ENAMETOOLONG, -1);
	return (0);
}

int
account_nss_user(const char *name, struct service_account_identity *out)
{
	struct passwd *pw;
	if (name == NULL || out == NULL) return (errno = EINVAL, -1);
	if (isolated) {
		if (lookup(SB_NSS_USER_NAME, name, 0, (uid_t)-1, &user_reply) == -1)
			return (-1);
		out->uid = user_reply.uid; out->gid = user_reply.gid;
		out->home = user_reply.home; out->shell = user_reply.shell;
		return (0);
	}
	errno = 0;
	pw = getpwnam(name);
	if (pw == NULL) { if (errno == 0) errno = ENOENT; return (-1); }
	out->uid = pw->pw_uid; out->gid = pw->pw_gid;
	out->home = pw->pw_dir; out->shell = pw->pw_shell;
	return (0);
}

int
account_nss_group(const char *name, gid_t *out)
{
	struct sb_nss_reply reply;
	struct group *gr;
	if (name == NULL || out == NULL) return (errno = EINVAL, -1);
	if (isolated) {
		if (lookup(SB_NSS_GROUP_NAME, name, 0, (uid_t)-1, &reply) == -1)
			return (-1);
		*out = reply.gid;
		return (0);
	}
	errno = 0;
	gr = getgrnam(name);
	if (gr == NULL) { if (errno == 0) errno = ENOENT; return (-1); }
	*out = gr->gr_gid;
	return (0);
}

int
account_nss_groups(const char *name, gid_t primary, gid_t *groups, int *count)
{
	struct sb_nss_reply reply;
	if (name == NULL || count == NULL || *count < 0 ||
	    (*count != 0 && groups == NULL)) return (errno = EINVAL, -1);
	if (!isolated) return (getgrouplist(name, primary, groups, count));
	if (lookup(SB_NSS_GROUPS, name, primary, (uid_t)-1, &reply) == -1)
		return (-1);
	if ((uint32_t)*count < reply.ngroups) {
		*count = reply.ngroups;
		return (errno = ERANGE, -1);
	}
	for (size_t i = 0; i < reply.ngroups; i++) groups[i] = reply.groups[i];
	*count = reply.ngroups;
	return (0);
}
