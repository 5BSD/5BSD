/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * A scripted libextensioncmp for sysextctl's command-line tests: the session
 * calls answer from SYSEXT_TEST without a provider.  The wire protocol and the
 * client's reply validation are covered by the BSDExtension provider and
 * evolution tests; here a malformed reply is the client's EPROTO.
 */
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libservice.h>
#include <extensioncmp.h>
#include <sysext_proto.h>

/*
 * SYSEXT_TEST_ACCESS: "full" (the default) reaches the full endpoint (rc,
 * devd); "root" reaches only the read-only
 * view, as a root login shell does; "none" reaches neither (another user).
 */
struct extensioncmp_session { int open, status; };
static struct extensioncmp_session session;

static const char *
access_mode(void)
{
	const char *m = getenv("SYSEXT_TEST_ACCESS");

	return (m != NULL ? m : "full");
}

/* A load or policy verb must never use the read-only view. */
static void
writable(const struct extensioncmp_session *s)
{
	if (s != &session || !session.open)
		abort();
	if (session.status)
		abort();
}

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
	if (strcmp(access_mode(), "full") != 0)
		return (errno = ENOENT, -1);
	session.open = 1;
	session.status = 0;
	*out = &session;
	return (0);
}

int
extensioncmp_session_open_status(struct extensioncmp_session **out)
{
	if (strcmp(access_mode(), "none") == 0)
		return (errno = ENOENT, -1);
	session.open = 1;
	session.status = 1;
	*out = &session;
	return (0);
}

int
extensioncmp_session_read_only(const struct extensioncmp_session *s)
{
	return (s == &session && session.status);
}

/* Two scripted decisions; time 1700000000 is 2023-11-14 22:13:20 UTC. */
int
extensioncmp_decision(struct extensioncmp_session *s, uint64_t after,
    struct service_extension_decision *d)
{
	if (s != &session || !session.open)
		abort();
	memset(d, 0, sizeof(*d));
	if (!session.status)
		return (errno = EOPNOTSUPP, -1);
	if (strcmp(mode(), "io") == 0)
		return (errno = EIO, -1);
	if (strcmp(mode(), "nodecisions") == 0 || after >= 2)
		return (errno = ENOENT, -1);
	d->sequence = after + 1;
	d->time = 1700000000;
	d->operation = SYSEXT_OP_ENSURE;
	if (d->sequence == 1) {
		strlcpy(d->name, "accf_http", sizeof(d->name));
		strlcpy(d->client, "devd", sizeof(d->client));
		d->result = SYSEXT_DECISION_DRIVERS_ONLY;
	} else {
		strlcpy(d->name, "linux64", sizeof(d->name));
		strlcpy(d->client, "etc-rc", sizeof(d->client));
		d->result = SYSEXT_DECISION_FAILED;
		d->error = ENOEXEC;
	}
	return (0);
}

/* The kernel's module view: pf and zfs built in, one loaded file. */
int
kldnext(int fileid)
{
	return (fileid == 0 ? 1 : fileid == 1 ? 2 : 0);
}

int
kldstat(int fileid, struct kld_file_stat *stat)
{
	if (fileid != 1 && fileid != 2)
		return (errno = ENOENT, -1);
	strlcpy(stat->name, fileid == 1 ? "kernel" : "if_urndis.ko",
	    sizeof(stat->name));
	stat->id = fileid;
	return (0);
}

int
kldfirstmod(int fileid)
{
	return (fileid == 1 ? 10 : 0);
}

int
modfnext(int modid)
{
	return (modid == 10 ? 11 : 0);
}

int
modstat(int modid, struct module_stat *stat)
{
	if (modid != 10 && modid != 11)
		return (errno = ENOENT, -1);
	strlcpy(stat->name, modid == 10 ? "zfs" : "pf", sizeof(stat->name));
	stat->id = modid;
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

	writable(s);
	if ((error = check(name, 0)) != 0 || (error = outcome(1)) != 0)
		return (errno = error, -1);
	return (0);
}

int
extensioncmp_reload(struct extensioncmp_session *s)
{
	int error;

	writable(s);
	if ((error = outcome(1)) != 0)
		return (errno = error, -1);
	return (0);
}

int
extensioncmp_manage(struct extensioncmp_session *s,
    enum service_extension_action action, const char *name)
{
	int error;

	writable(s);
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
