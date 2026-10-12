/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * A scripted libextensioncmp for sysextctl's command-line tests: the session
 * calls answer from SYSEXT_TEST without a provider.  The wire protocol and the
 * client's reply validation are covered by the BSDExtension provider and
 * evolution tests; here a malformed reply is the client's EPROTO.
 */
#include <sys/types.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libservice.h>
#include <extensioncmp.h>
#include <sysext_proto.h>

struct extensioncmp_session { int open; };
static struct extensioncmp_session session;

static const char *
mode(void)
{
	const char *m = getenv("SYSEXT_TEST");

	return (m != NULL ? m : "");
}

/* The client's own argument rules (extensioncmp.c check_name()). */
static int
check(const char *name, int empty_ok)
{
	size_t length;

	if (name == NULL)
		return (EINVAL);
	length = strnlen(name, SYSEXT_NAME_MAX);
	if (length >= SYSEXT_NAME_MAX)
		return (ENAMETOOLONG);
	if (length == 0)
		return (empty_ok ? 0 : EINVAL);
	if (strchr(name, '/') != NULL || strcmp(name, ".") == 0 ||
	    strcmp(name, "..") == 0)
		return (EINVAL);
	if (strcmp(name, "linux64") != 0)
		abort();
	return (0);
}

/* The outcome every scripted mode shares; 0 lets the call succeed. */
static int
outcome(int malformed_modes)
{
	const char *m = mode();

	if (strcmp(m, "denied") == 0)
		return (EPERM);
	if (strcmp(m, "io") == 0)
		return (EIO);
	if (malformed_modes && (strcmp(m, "short") == 0 ||
	    strcmp(m, "count") == 0 || strcmp(m, "name") == 0 ||
	    strcmp(m, "errno") == 0 || strcmp(m, "state") == 0))
		return (EPROTO);
	return (0);
}

int
extensioncmp_session_open(struct extensioncmp_session **out)
{
	session.open = 1;
	*out = &session;
	return (0);
}

void
extensioncmp_session_close(struct extensioncmp_session *s)
{
	if (s != &session || !session.open)
		abort();
	session.open = 0;
}

int
extensioncmp_load(struct extensioncmp_session *s, const char *name)
{
	int error;

	if (s != &session)
		abort();
	if ((error = check(name, 0)) != 0 || (error = outcome(1)) != 0)
		return (errno = error, -1);
	return (0);
}

int
extensioncmp_reload(struct extensioncmp_session *s)
{
	int error;

	if (s != &session)
		abort();
	if ((error = outcome(1)) != 0)
		return (errno = error, -1);
	return (0);
}

int
extensioncmp_manage(struct extensioncmp_session *s,
    enum service_extension_action action, const char *name)
{
	int error;

	if (s != &session)
		abort();
	if (action != SERVICE_EXTENSION_RESTORE && (error = check(name, 0)) != 0)
		return (errno = error, -1);
	if ((error = outcome(1)) != 0)
		return (errno = error, -1);
	return (0);
}

int
extensioncmp_info(struct extensioncmp_session *s, const char *name, int next,
    struct service_extension_info *info)
{
	const char *m = mode();
	int error;

	if (s != &session)
		abort();
	memset(info, 0, sizeof(*info));
	if ((error = check(name, next)) != 0)
		return (errno = error, -1);
	if (next && name[0] != '\0')
		return (errno = ENOENT, -1);
	if ((error = outcome(1)) != 0)
		return (errno = error, -1);
	strlcpy(info->name, "linux64", sizeof(info->name));
	info->allowed = 1;
	info->ready = 1;
	info->loaded = 1;
	if (strcmp(m, "hidden") == 0)
		info->allowed = info->loaded = 0;
	else if (strcmp(m, "absent") == 0)
		info->loaded = 0;
	return (0);
}

/* Keep filesystem probes independent of the host's installed modules. */
int
sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen)
{
	const char *path = getenv("SYSEXT_TEST_MODULE_PATH");
	size_t len;

	if (strcmp(name, "kern.module_path") != 0 || newp != NULL || newlen != 0)
		abort();
	if (path == NULL) {
		errno = EACCES;
		return (-1);
	}
	len = strlen(path) + 1;
	if (oldp != NULL) {
		if (*oldlenp < len) {
			errno = ENOMEM;
			return (-1);
		}
		memcpy(oldp, path, len);
	}
	*oldlenp = len;
	return (0);
}
