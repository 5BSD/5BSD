/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include "nss_protocol.h"

static int
copy_string(char *out, size_t size, const char *in)
{
	if (in == NULL)
		return (EINVAL);
	return (strlcpy(out, in, size) >= size ? ERANGE : 0);
}

void
sb_nss_lookup(const struct sb_nss_request *req, struct sb_nss_reply *reply)
{
	struct passwd *pw;
	struct group *gr;
	gid_t groups[NGROUPS_MAX + 1] = {0};
	int count, error = 0;

	memset(reply, 0, sizeof(*reply));
	reply->version = SB_NSS_VERSION;
	if (sb_nss_request_valid(req) == -1) {
		error = errno;
		goto done;
	}
	errno = 0;
	switch (req->operation) {
	case SB_NSS_USER_NAME:
	case SB_NSS_USER_UID:
		pw = req->operation == SB_NSS_USER_UID ?
		    getpwuid((uid_t)req->id) : getpwnam(req->name);
		if (pw == NULL) { error = errno != 0 ? errno : ENOENT; break; }
		if (pw->pw_uid == (uid_t)-1 || pw->pw_gid == (gid_t)-1 ||
		    (req->operation == SB_NSS_USER_UID && pw->pw_uid != req->id)) {
			error = EINVAL;
			break;
		}
		reply->uid = pw->pw_uid;
		reply->gid = pw->pw_gid;
		error = copy_string(reply->name, sizeof(reply->name), pw->pw_name);
		if (error == 0 && reply->name[0] == '\0') error = EINVAL;
		if (error == 0)
			error = copy_string(reply->home, sizeof(reply->home), pw->pw_dir);
		if (error == 0)
			error = copy_string(reply->shell, sizeof(reply->shell), pw->pw_shell);
		break;
	case SB_NSS_GROUP_NAME:
		gr = getgrnam(req->name);
		if (gr == NULL) { error = errno != 0 ? errno : ENOENT; break; }
		if (gr->gr_gid == (gid_t)-1) { error = EINVAL; break; }
		reply->gid = gr->gr_gid;
		break;
	case SB_NSS_GROUPS:
		count = nitems(groups);
		if (getgrouplist(req->name, (gid_t)req->id, groups, &count) == -1) {
			error = errno != 0 ? errno : ERANGE;
			break;
		}
		if (count <= 0 || (size_t)count > nitems(groups)) {
			error = EINVAL;
			break;
		}
		for (int i = 0; i < count; i++) {
			if (groups[i] == (gid_t)-1) { error = EINVAL; break; }
			reply->groups[i] = groups[i];
		}
		reply->ngroups = count;
		break;
	}
done:
	/* Never publish partial account data on failure. These checks constrain
	 * accidental provider errors; the parent must distrust the entire reply. */
	if (error != 0) {
		memset(reply, 0, sizeof(*reply));
		reply->version = SB_NSS_VERSION;
		reply->error = error;
	}
}
