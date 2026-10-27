/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include "nss_protocol.h"

int
sb_nss_request_valid(const struct sb_nss_request *req)
{
	if (req == NULL || req->version != SB_NSS_VERSION ||
	    memchr(req->name, '\0', sizeof(req->name)) == NULL ||
	    req->operation < SB_NSS_USER_NAME || req->operation > SB_NSS_GROUPS ||
	    (req->operation == SB_NSS_USER_UID ? req->name[0] != '\0' :
	    req->name[0] == '\0') ||
	    ((req->operation == SB_NSS_USER_NAME ||
	    req->operation == SB_NSS_GROUP_NAME) && req->id != 0) ||
	    ((req->operation == SB_NSS_USER_UID ||
	    req->operation == SB_NSS_GROUPS) && req->id == UINT32_MAX)) {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

static bool
zero_bytes(const void *data, size_t size)
{
	const unsigned char *p = data;
	for (size_t i = 0; i < size; i++)
		if (p[i] != 0) return (false);
	return (true);
}

/* Enforce the helper's zero-filled string representation, without imposing
 * extra UNIX pathname or account-name policy. NSS may canonicalize a name. */
static bool
string_valid(const char *s, size_t size, bool nonempty)
{
	const char *end = memchr(s, '\0', size);
	return (end != NULL && (!nonempty || end != s) &&
	    zero_bytes(end, size - (size_t)(end - s)));
}

int
sb_nss_reply_valid(const struct sb_nss_request *req, const void *data,
    size_t size, uid_t owner)
{
	struct sb_nss_reply reply;
	bool user;

	if (sb_nss_request_valid(req) == -1) return (-1);
	if (data == NULL || size != sizeof(reply)) goto malformed;
	/* Do not assume alignment of transport storage. */
	memcpy(&reply, data, sizeof(reply));
	if (reply.version != SB_NSS_VERSION || reply.error > ELAST)
		goto malformed;
	if (reply.error != 0) {
		int error = reply.error;
		reply.version = reply.error = 0;
		if (!zero_bytes(&reply, sizeof(reply))) goto malformed;
		errno = error;
		return (-1);
	}
	user = req->operation == SB_NSS_USER_NAME ||
	    req->operation == SB_NSS_USER_UID;
	if (!string_valid(reply.name, sizeof(reply.name), user) ||
	    !string_valid(reply.home, sizeof(reply.home), false) ||
	    !string_valid(reply.shell, sizeof(reply.shell), false))
		goto malformed;
	if (user) {
		if (reply.uid == UINT32_MAX || reply.gid == UINT32_MAX ||
		    reply.ngroups != 0 || !zero_bytes(reply.groups, sizeof(reply.groups)))
			goto malformed;
		if ((req->operation == SB_NSS_USER_UID && reply.uid != req->id) ||
		    (owner != (uid_t)-1 && reply.uid != owner)) {
			errno = EPERM;
			return (-1);
		}
		return (0);
	}
	if (reply.uid != 0 || reply.name[0] != '\0' || reply.home[0] != '\0' ||
	    reply.shell[0] != '\0') goto malformed;
	if (req->operation == SB_NSS_GROUP_NAME) {
		if (reply.gid == UINT32_MAX || reply.ngroups != 0 ||
		    !zero_bytes(reply.groups, sizeof(reply.groups))) goto malformed;
		return (0);
	}
	if (reply.gid != 0 || reply.ngroups == 0 ||
	    reply.ngroups > nitems(reply.groups)) goto malformed;
	for (size_t i = 0; i < reply.ngroups; i++)
		if (reply.groups[i] == UINT32_MAX) goto malformed;
	if (!zero_bytes(reply.groups + reply.ngroups,
	    (nitems(reply.groups) - reply.ngroups) * sizeof(reply.groups[0])))
		goto malformed;
	return (0);
malformed:
	errno = EPROTO;
	return (-1);
}
