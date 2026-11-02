/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsdextension(8) — the system-extension broker.
 *
 * Owns kernel-module ("system extension") loading, taking it out of PID 1.
 * bsdextension is a socket-free service_provider: it exposes the well-known name
 * system.SystemExtension and serves each client on its own mac_capability
 * worker channel.  A client asks it to ensure a named extension is loaded; the
 * domain layer restricts system.SystemExtension to SYSTEM-domain clients, so a
 * user service can never reach it and therefore can never load kernel code.
 *
 * bsdextension holds no /dev/mac_capability handle of its own — PID 1 owns that
 * device.  It declares the kldload system-capability gate in its
 * manifest; switchboard mints the matching system token (capsule claims the
 * gate under its nonce) and delivers it as a bootstrap capability.
 * service_provider_authorize_capabilities() authorizes that token, adding
 * bsdextension's process nonce to the gate's authorized set.  Because the
 * client-serving threads share the daemon's process — and thus its held gate
 * token — each thread's load passes the gate; no token is minted here, no device
 * is opened, and no socket appears anywhere in the path.
 *
 * bsdextension is BORN IN CAPABILITY MODE as the unprivileged capability user.
 * kldload(2) is capmode-enabled but runs priv_check(PRIV_KLD_LOAD); rather than
 * hold ambient root, the daemon performs each load THROUGH the held
 * SYS_GATE_KLDLOAD token in kernel context (service_system_kldload), where the
 * held claim replaces PRIV_KLD_LOAD and the module-path lookup runs in kernel
 * context.  The raw kldload(2) stays refused inside the Capsicum cage, so the
 * sandbox is never loosened and even root is denied the load without the token.
 * For ENSURE, modfind(2)/kldstat(2) are avoided: a kldload whose module is
 * already present returns EEXIST, which bsdextension reports as success, so ENSURE
 * needs only the kldload gate.  The STAT operation, in contrast, must query
 * without loading; it uses kldfind(2) (a filename lookup that pairs with
 * kldload's filename argument).  kldfind is a read-only query and is not
 * gated — module enumeration is deliberately open (the DTrace toolchain
 * depends on it) — so bsdextension's manifest declares only the kldload gate.
 *
 * There is deliberately no UNLOAD operation: safe removal needs per-consumer
 * module refcounting/ownership this broker does not track, so one SYSTEM client
 * could otherwise unload code another still depends on.  See sysext_proto.h.
 *
 * Loading is default-deny by module name as well as by domain: bsdextension carries
 * an allow-list of module names supplied by its required UCL configuration.  A name that passes the path-traversal check but is not
 * on the allow-list is refused with EPERM and logged.  This closes the gap where
 * any SYSTEM-domain client, once past the domain gate, could load ARBITRARY
 * kernel code; the gate authorizes reaching bsdextension, the allow-list authorizes
 * WHICH kernel code may load.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/procdesc.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include <fidl/bsd.extension.v1/c/bsd.h>
#include <libservice.h>

#include "sysext_proto.h"
#include "bsdextension.h"
#include "bsdextension_reclaim.h"
#include "bsdextension_probes.h"
#include "trace_pressure.h"

/*
 * The required startup policy supplies the complete base allow-list. Missing
 * or invalid input stops startup; executable defaults grant no module access.
 * Administrator overrides have a separate explicit writer and persistent store.
 */

/*
 * Shared before accepting clients; authorized reloads publish to all workers.
 */
static struct sysext_policy *active_policy;
static const char *policy_path = SYSEXT_DEFAULT_CONF;
/*
 * True when the allow-list came from the switchboard-delivered Config directory
 * (production, born-in-capmode) rather than an explicit -c path (tests / pre-
 * capmode).  RELOAD must then re-open via service_config_open, since an absolute
 * open(policy_path) is refused (ECAPMODE) after the daemon enters capability mode.
 */
static bool policy_delivered = true;

struct sysext_client {
	const char *label;
	const char *bundle;	/* installed bundle (stamped container), or "" */
	service_rights_t rights;
	/*
	 * Arrived on system.SystemExtension.Status: only Info and Next are
	 * decided, whatever the session's rights.  The status handler table has
	 * no other method; this is the second, independent refusal.
	 */
	bool read_only;
	/*
	 * Arrived on system.SystemExtension.RootLoad: only the root Load and
	 * Unload decisions (root_decide) apply; sysext_handle() refuses every
	 * request from such a session.
	 */
	bool root_load;
	uint64_t nonce;		/* the requester's per-exec program nonce */
};

/* Which endpoint a session arrived on (the listener that accepted it). */
enum sysext_endpoint {
	SYSEXT_ENDPOINT_FULL,		/* system.SystemExtension */
	SYSEXT_ENDPOINT_STATUS,		/* system.SystemExtension.Status */
	SYSEXT_ENDPOINT_ROOTLOAD	/* system.SystemExtension.RootLoad */
};
#define	SYSEXT_ENDPOINTS	3

/* The client recorded for a root Load or Unload in the decision ring. */
#define	SYSEXT_ROOT_CLIENT	"root (uid 0)"

/* The module -> bundle owner map's directory (reclaim.c), or -1. */
static int sysext_owners_fd = -1;

/*
 * Recent load decisions for the status view.  A fixed ring indexed by
 * sequence; client-serving threads record and read it under one mutex.
 */
static pthread_mutex_t sysext_decisions_lock = PTHREAD_MUTEX_INITIALIZER;
static struct sysext_decision sysext_decisions[SYSEXT_DECISIONS_MAX];
static uint64_t sysext_decision_seq = 1;	/* the next sequence to assign */

void
sysext_decision_record(const char *module, const char *client,
    uint32_t operation, uint32_t result, int error)
{
	struct sysext_decision *d;
	struct timespec now;

	if (clock_gettime(CLOCK_REALTIME, &now) == -1)
		now.tv_sec = 0;
	pthread_mutex_lock(&sysext_decisions_lock);
	d = &sysext_decisions[sysext_decision_seq % SYSEXT_DECISIONS_MAX];
	memset(d, 0, sizeof(*d));
	d->sequence = sysext_decision_seq++;
	d->time = (int64_t)now.tv_sec;
	(void)strlcpy(d->module, module, sizeof(d->module));
	(void)strlcpy(d->client, client != NULL ? client : "", sizeof(d->client));
	d->operation = operation;
	d->result = result;
	d->error = (uint32_t)error;
	pthread_mutex_unlock(&sysext_decisions_lock);
}

int
sysext_decision_next(uint64_t after, struct sysext_decision *out)
{
	uint64_t oldest, want;
	int error = 0;

	pthread_mutex_lock(&sysext_decisions_lock);
	oldest = sysext_decision_seq > SYSEXT_DECISIONS_MAX ?
	    sysext_decision_seq - SYSEXT_DECISIONS_MAX : 1;
	want = after >= oldest ? after + 1 : oldest;
	if (after == UINT64_MAX || want >= sysext_decision_seq)
		error = ENOENT;
	else
		*out = sysext_decisions[want % SYSEXT_DECISIONS_MAX];
	pthread_mutex_unlock(&sysext_decisions_lock);
	return (error);
}

/*
 * The held "system" gate token covering SYS_GATE_KLDLOAD (+ KLDUNLOAD),
 * dup'd in main() before entering capability mode.  A born-in-capmode broker
 * loads/unloads modules THROUGH this token (service_system_kldload/kldunload),
 * since the raw kldload(2) would fail priv_check(PRIV_KLD_LOAD) as the
 * unprivileged capability user.  -1 when no token is held (a unit test, or
 * fail-soft), in which case load/unload fall back to the direct syscalls.
 */
int sysext_kld_token = -1;
#define	g_kld_token	sysext_kld_token

/*
 * Guarantee fds 0/1/2 are open before any capability handle is created, so a
 * held service instance can never occupy a stdio slot and be clobbered by a
 * later /dev/null redirect.  bsdextension is launched by switchboard without a
 * controlling terminal.
 */
#ifndef BSDEXTENSION_TESTING
static void
reserve_stdio(void)
{
	int fd, nfd;

	for (fd = 0; fd <= 2; fd++) {
		if (fcntl(fd, F_GETFD) != -1)
			continue;
		nfd = open("/dev/null", O_RDWR);
		if (nfd == -1)
			continue;
		if (nfd != fd) {
			(void)dup2(nfd, fd);
			(void)close(nfd);
		}
	}
}
#endif /* !BSDEXTENSION_TESTING */

/*
 * A module name must be a single, safe filename component: NUL-terminated
 * within the buffer, non-empty, not "." or "..", and containing no '/' (no path
 * traversal, no absolute path).  Embedded dots ARE permitted — real module
 * names contain them (e.g. "if_foo.ko"-style names) — only the pure "." and
 * ".." directory names are rejected.  This is a syntactic guard; the allow-list
 * (extension_allowed) decides WHICH module may actually load.
 */
SYSEXT_STATIC bool
valid_module_name(const char *name)
{

	if (name == NULL || strnlen(name, SYSEXT_NAME_MAX) == SYSEXT_NAME_MAX)
		return (false);
	if (name[0] == '\0' || strcmp(name, ".") == 0 ||
	    strcmp(name, "..") == 0)
		return (false);
	if (strchr(name, '/') != NULL)
		return (false);
	return (true);
}

/* Deployment grants live in the packaged policy, never in executable defaults. */
SYSEXT_STATIC void
sysext_config_defaults(struct sysext_config *cfg)
{

	memset(cfg, 0, sizeof(*cfg));
}

/* True iff name is on the resolved allow-list (exact match). */
SYSEXT_STATIC bool
extension_allowed(const struct sysext_config *cfg, const char *name)
{
	size_t i;

	for (i = 0; i < cfg->nallow; i++) {
		if (strcmp(cfg->allow[i], name) == 0)
			return (true);
	}
	return (false);
}

/*
 * True iff client is admitted for the hardware-driver class only.  The label is
 * switchboard's, derived from the requester's kernel-stamped authority, never
 * from the request payload.
 */
SYSEXT_STATIC bool
sysext_driver_client(const struct sysext_config *cfg, const char *client)
{
	size_t i;

	if (client == NULL)
		return (false);
	for (i = 0; i < cfg->ndriver_clients; i++)
		if (strcmp(cfg->driver_clients[i], client) == 0)
			return (true);
	return (false);
}

/* A switchboard client label: [A-Za-z0-9._-], not "." or "..". */
static bool
valid_client_label(const char *label, size_t len)
{
	size_t i;

	if (len == 0 || len >= SYSEXT_CLIENT_MAX || strcmp(label, ".") == 0 ||
	    strcmp(label, "..") == 0)
		return (false);
	for (i = 0; i < len; i++) {
		char c = label[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
			return (false);
	}
	return (true);
}

/*
 * Hardware-driver class.  kldxref(8) writes linker.hints as an int version
 * followed by records: an int-aligned int length (covering the type and
 * data), an int type, then data.  An MDT_MODULE record carries the module
 * name and its file name as length-prefixed strings; the MDT_PNP_INFO
 * records that follow describe the plug-and-play tables of that file.  This
 * is the data devmatch(8) matches hardware against, so a file with such a
 * record is exactly a module devmatch can select.  The kernel's own records
 * ("kernel") are not loadable modules.  Bounds are checked on every field.
 */
int sysext_driver_dirfd = -1;

static bool
hints_str(const unsigned char *buf, size_t end, size_t *pos, char *out,
    size_t outlen)
{
	size_t n;

	if (*pos >= end)
		return (false);
	n = buf[*pos];
	if (n >= outlen || end - *pos - 1 < n)
		return (false);
	memcpy(out, buf + *pos + 1, n);
	out[n] = '\0';
	*pos += 1 + n;
	return (true);
}

bool
sysext_hints_pnp_module(const void *image, size_t len, const char *name)
{
	const unsigned char *buf = image;
	char lastmod[256], modname[256], want[SYSEXT_NAME_MAX + 3];
	size_t pos, data, end;
	int version, reclen, type;

	if (buf == NULL || name == NULL || !valid_module_name(name))
		return (false);
	/* devmatch(8) and the rc script name modules with or without .ko. */
	if (snprintf(want, sizeof(want), "%s%s", name,
	    strlen(name) > 3 && strcmp(name + strlen(name) - 3, ".ko") == 0 ?
	    "" : ".ko") >= (int)sizeof(want))
		return (false);
	if (len < sizeof(int))
		return (false);
	memcpy(&version, buf, sizeof(int));
	if (version != LINKER_HINTS_VERSION)
		return (false);
	lastmod[0] = '\0';
	pos = sizeof(int);
	for (;;) {
		pos = roundup2(pos, sizeof(int));
		if (pos > len || len - pos < 2 * sizeof(int))
			break;
		memcpy(&reclen, buf + pos, sizeof(int));
		data = pos + sizeof(int);
		if (reclen < (int)sizeof(int) || (size_t)reclen > len - data)
			break;
		end = data + (size_t)reclen;
		memcpy(&type, buf + data, sizeof(int));
		data += sizeof(int);
		if (type == MDT_MODULE) {
			if (!hints_str(buf, end, &data, modname,
			    sizeof(modname)) ||
			    !hints_str(buf, end, &data, lastmod, sizeof(lastmod)))
				lastmod[0] = '\0';
		} else if (type == MDT_PNP_INFO && lastmod[0] != '\0' &&
		    strcmp(lastmod, "kernel") != 0 &&
		    strcmp(lastmod, want) == 0)
			return (true);
		pos = end;
	}
	return (false);
}

/*
 * The kernel directory's linker.hints, read once and kept while the file is
 * the same (device, inode, size, modification and change times): every
 * request outside the allow-list consults it, and it can be 16 MB.
 */
static struct {
	pthread_mutex_t lock;
	dev_t	dev;
	ino_t	ino;
	off_t	size;
	struct timespec mtim, ctim;
	unsigned char *image;
} hints_cache = { .lock = PTHREAD_MUTEX_INITIALIZER };

static bool
same_hints(const struct stat *st)
{

	return (hints_cache.image != NULL && hints_cache.dev == st->st_dev &&
	    hints_cache.ino == st->st_ino && hints_cache.size == st->st_size &&
	    timespeccmp(&hints_cache.mtim, &st->st_mtim, ==) &&
	    timespeccmp(&hints_cache.ctim, &st->st_ctim, ==));
}

/* With the cache lock held: make it current for dirfd; false without hints. */
static bool
hints_refresh_locked(int dirfd)
{
	struct stat st, again;
	unsigned char *image;
	size_t done = 0;
	ssize_t n;
	int fd;

	if (dirfd < 0)
		goto none;
	/* A non-regular file is refused before an open that could block. */
	if (fstatat(dirfd, "linker.hints", &st, AT_SYMLINK_NOFOLLOW) == -1 ||
	    !S_ISREG(st.st_mode) || st.st_size <= 0 ||
	    st.st_size > SYSEXT_HINTS_MAX)
		goto none;
	if (same_hints(&st))
		return (true);
	fd = openat(dirfd, "linker.hints", O_RDONLY | O_NOFOLLOW | O_CLOEXEC |
	    O_NONBLOCK);
	if (fd == -1)
		goto none;
	if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
	    st.st_size > SYSEXT_HINTS_MAX ||
	    (image = malloc((size_t)st.st_size)) == NULL) {
		(void)close(fd);
		goto none;
	}
	while (done < (size_t)st.st_size) {
		n = pread(fd, image + done, (size_t)st.st_size - done,
		    (off_t)done);
		if (n == -1 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		done += (size_t)n;
	}
	/* Rewritten while it was read: do not keep a mixed image. */
	if (done != (size_t)st.st_size || fstat(fd, &again) == -1 ||
	    again.st_size != st.st_size ||
	    !timespeccmp(&again.st_mtim, &st.st_mtim, ==) ||
	    !timespeccmp(&again.st_ctim, &st.st_ctim, ==)) {
		free(image);
		(void)close(fd);
		goto none;
	}
	(void)close(fd);
	free(hints_cache.image);
	hints_cache.image = image;
	hints_cache.dev = st.st_dev;
	hints_cache.ino = st.st_ino;
	hints_cache.size = st.st_size;
	hints_cache.mtim = st.st_mtim;
	hints_cache.ctim = st.st_ctim;
	return (true);
none:
	free(hints_cache.image);
	hints_cache.image = NULL;
	return (false);
}

/* Read the delivered kernel directory's linker.hints and classify name. */
bool
sysext_driver_module(int dirfd, const char *name)
{
	bool found = false;

	pthread_mutex_lock(&hints_cache.lock);
	if (hints_refresh_locked(dirfd))
		found = sysext_hints_pnp_module(hints_cache.image,
		    (size_t)hints_cache.size, name);
	pthread_mutex_unlock(&hints_cache.lock);
	return (found);
}

/*
 * linker_hints_lookup(): the first MDT_VERSION record of modname with the
 * preferred version, else the highest version within [minimum, maximum]
 * (above 0, as the kernel compares against an initial best of 0).  True with
 * its file name; false when no record qualifies.
 */
bool
sysext_hints_version_file(const void *image, size_t len, const char *modname,
    int minimum, int preferred, int maximum, char *file, size_t filelen)
{
	const unsigned char *buf = image;
	char name[256], kld[256], best[256];
	size_t pos, data, end;
	int version, reclen, type, ival, bestver = 0;

	best[0] = '\0';
	if (buf == NULL || len < sizeof(int))
		return (false);
	memcpy(&version, buf, sizeof(int));
	if (version != LINKER_HINTS_VERSION)
		return (false);
	pos = sizeof(int);
	for (;;) {
		pos = roundup2(pos, sizeof(int));
		if (pos > len || len - pos < 2 * sizeof(int))
			break;
		memcpy(&reclen, buf + pos, sizeof(int));
		data = pos + sizeof(int);
		if (reclen < (int)sizeof(int) || (size_t)reclen > len - data)
			break;
		end = data + (size_t)reclen;
		memcpy(&type, buf + data, sizeof(int));
		data += sizeof(int);
		pos = end;
		if (type != MDT_VERSION ||
		    !hints_str(buf, end, &data, name, sizeof(name)) ||
		    strcmp(name, modname) != 0)
			continue;
		data = roundup2(data, sizeof(int));
		if (data > end || end - data < sizeof(int))
			continue;
		memcpy(&ival, buf + data, sizeof(int));
		data += sizeof(int);
		if (!hints_str(buf, end, &data, kld, sizeof(kld)))
			continue;
		if (ival == preferred)
			return (strlcpy(file, kld, filelen) < filelen);
		if (ival >= minimum && ival <= maximum && ival > bestver) {
			bestver = ival;
			(void)strlcpy(best, kld, sizeof(best));
		}
	}
	if (best[0] == '\0')
		return (false);
	return (strlcpy(file, best, filelen) < filelen);
}

/*
 * The file the kernel linker would load from the kernel directory for a
 * dependency: the linker.hints choice, else modname itself, the first of
 * NAME and NAME.ko that is a regular file (linker_lookup_file()).  An empty
 * file name when the directory has none.
 */
void
sysext_kernel_dir_dependency(const char *modname, int minimum, int preferred,
    int maximum, char *file, size_t filelen)
{
	static const char *const ext[] = { "", ".ko" };
	struct stat st;
	char candidate[MAXPATHLEN];
	bool hinted = false;
	size_t i;

	file[0] = '\0';
	pthread_mutex_lock(&hints_cache.lock);
	if (hints_refresh_locked(sysext_driver_dirfd))
		hinted = sysext_hints_version_file(hints_cache.image,
		    (size_t)hints_cache.size, modname, minimum, preferred,
		    maximum, candidate, sizeof(candidate));
	pthread_mutex_unlock(&hints_cache.lock);
	if (!hinted)
		(void)strlcpy(candidate, modname, sizeof(candidate));
	for (i = 0; i < nitems(ext); i++) {
		char name[MAXPATHLEN];

		if ((size_t)snprintf(name, sizeof(name), "%s%s", candidate,
		    ext[i]) >= sizeof(name) || strchr(name, '/') != NULL)
			continue;
		/* The kernel follows links here; the checks then refuse one. */
		if (fstatat(sysext_driver_dirfd, name, &st, 0) == 0 &&
		    S_ISREG(st.st_mode)) {
			(void)strlcpy(file, name, filelen);
			return;
		}
	}
}

/* True when an administrator override denies name (with or without .ko). */
bool
sysext_admin_denied(const char *name)
{
	char modname[SYSEXT_NAME_MAX];
	size_t len;

	/* Without a policy no override exists (and root_decide() loads nothing). */
	if (active_policy == NULL)
		return (false);
	(void)strlcpy(modname, name, sizeof(modname));
	len = strlen(modname);
	if (len > 3 && strcmp(modname + len - 3, ".ko") == 0)
		modname[len - 3] = '\0';
	return (sysext_policy_denied(active_policy, modname) ||
	    sysext_policy_denied(active_policy, name));
}

/*
 * The complete load decision: the resolved allow-list, then the hardware
 * driver class when the policy enables it and no administrator override
 * denies the name, and only while the kernel directory still holds the
 * running kernel (sysext_kernel_dir_check()): devmatch(8) and the kernel load
 * drivers by name from it.  *driver reports a class grant (for logging).
 */
static bool
request_allowed(const struct sysext_config *cfg, const char *client,
    const char *name, bool *driver)
{
	char why[384];

	*driver = false;
	/* A driver-only client (driver_clients) never uses the allow-list. */
	if (!sysext_driver_client(cfg, client) && extension_allowed(cfg, name))
		return (true);
	if (!cfg->device_drivers || active_policy == NULL ||
	    sysext_policy_denied(active_policy, name))
		return (false);
	if (sysext_kernel_dir_check(why, sizeof(why)) != 0)
		return (false);
	*driver = sysext_driver_module(sysext_driver_dirfd, name);
	return (*driver);
}

/*
 * The delivered descriptor's provenance is the caller's responsibility. These
 * checks validate syntax and bound reads; UNIX modes do not establish BIP trust.
 * A failed load/reload leaves the previous configuration untouched.
 */
static int
sysext_config_parse_fd(struct sysext_config *cfg, int fd)
{
	struct sysext_config candidate;
	ucl_object_t *root;
	const ucl_object_t *arr, *ent, *drivers, *clients, *repo;
	ucl_object_iter_t it = NULL;
	const char *name;
	size_t i;
	int error = EINVAL;

	if (cfg == NULL)
		return (errno = EINVAL, -1);
	root = sysext_config_object_fd(fd, S_IWGRP | S_IWOTH);
	if (root == NULL)
		return (-1);
	memset(&candidate, 0, sizeof(candidate));
	if (ucl_object_type(root) != UCL_OBJECT || root->len < 1 || root->len > 4)
		goto done;
	/* Optional: the hardware-driver class (see struct sysext_config). */
	drivers = ucl_object_lookup(root, "device_drivers");
	if (drivers != NULL && (drivers->next != NULL ||
	    drivers->keylen != strlen("device_drivers") ||
	    ucl_object_type(drivers) != UCL_BOOLEAN))
		goto done;
	/* Optional: clients limited to the hardware-driver class. */
	clients = ucl_object_lookup(root, "driver_clients");
	if (clients != NULL && (clients->next != NULL ||
	    clients->keylen != strlen("driver_clients") ||
	    ucl_object_type(clients) != UCL_ARRAY))
		goto done;
	/*
	 * Optional: the repository whose base packages a UID 0 session may load
	 * modules from (system.SystemExtension.RootLoad); absent refuses them.
	 */
	repo = ucl_object_lookup(root, "root_load_repository");
	if (repo != NULL && (repo->next != NULL ||
	    repo->keylen != strlen("root_load_repository") ||
	    ucl_object_type(repo) != UCL_STRING ||
	    (name = ucl_object_tostring(repo)) == NULL ||
	    strlen(name) != repo->len ||
	    repo->len >= sizeof(candidate.root_load_repository) ||
	    !valid_client_label(name, repo->len)))
		goto done;
	if (repo != NULL)
		(void)strlcpy(candidate.root_load_repository, name,
		    sizeof(candidate.root_load_repository));
	/* Every key is one of the four, each at most once: no unknown key. */
	if (root->len != 1 + (drivers != NULL) + (clients != NULL) +
	    (repo != NULL))
		goto done;
	it = NULL;
	while (clients != NULL &&
	    (ent = ucl_object_iterate(clients, &it, true)) != NULL) {
		if (candidate.ndriver_clients == SYSEXT_MAX_DRIVER_CLIENTS ||
		    ucl_object_type(ent) != UCL_STRING ||
		    (name = ucl_object_tostring(ent)) == NULL ||
		    strlen(name) != ent->len ||
		    !valid_client_label(name, ent->len))
			goto done;
		for (i = 0; i < candidate.ndriver_clients; i++)
			if (strcmp(candidate.driver_clients[i], name) == 0)
				goto done;
		strlcpy(candidate.driver_clients[candidate.ndriver_clients++],
		    name, SYSEXT_CLIENT_MAX);
	}
	it = NULL;
	arr = ucl_object_lookup(root, "allowed_extensions");
	if (arr == NULL || arr->next != NULL ||
	    arr->keylen != strlen("allowed_extensions") ||
	    ucl_object_type(arr) != UCL_ARRAY)
		goto done;
	while ((ent = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (candidate.nallow == SYSEXT_MAX_ALLOW ||
		    ucl_object_type(ent) != UCL_STRING ||
		    (name = ucl_object_tostring(ent)) == NULL ||
		    strlen(name) != ent->len || !valid_module_name(name))
			goto done;
		for (i = 0; i < candidate.nallow; i++)
			if (strcmp(candidate.allow[i], name) == 0)
				goto done;
		strlcpy(candidate.allow[candidate.nallow++], name,
		    SYSEXT_NAME_MAX);
	}
	candidate.device_drivers = drivers != NULL && ucl_object_toboolean(drivers);
	*cfg = candidate;
	error = 0;
done:
	ucl_object_unref(root);
	return (error == 0 ? 0 : (errno = error, -1));
}

static int
sysext_config_read(struct sysext_config *cfg, const char *path)
{
	int fd, r, error;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd == -1)
		return (-1);
	r = sysext_config_parse_fd(cfg, fd);
	error = errno;
	(void)close(fd);
	errno = error;
	return (r);
}

SYSEXT_STATIC int
sysext_config_load(struct sysext_config *cfg, const char *path)
{
	return (sysext_config_read(cfg, path));
}

/*
 * Load the allow-list from a switchboard-delivered Config descriptor (the
 * born-in-capmode path: no global namespace access).  Holding the fd is the
 * authorization; the fd is not closed here.  External linkage (not
 * SYSEXT_STATIC): policy.c's capmode-safe RELOAD (sysext_policy_reload_fd) calls
 * it, and main()/tests use it too.
 */
int
sysext_config_load_fd(struct sysext_config *cfg, int fd)
{
	return (sysext_config_parse_fd(cfg, fd));
}

int
sysext_config_reload_fd(struct sysext_config *cfg, int fd)
{
	return (sysext_config_parse_fd(cfg, fd));
}

int
sysext_config_reload(struct sysext_config *cfg, const char *path)
{
	return (sysext_config_read(cfg, path));
}

/*
 * Ensure the named kernel extension is loaded.  Returns 0 on success (including
 * "already loaded") or an errno.  kldload(2) is CAPENABLED; a name that is
 * already present returns EEXIST, which is success for an ensure.
 */
static int ensure_extension_locked(const char *, bool *);

/* Serialised with root loads, which check the files each load brings in. */
static int
ensure_extension(const char *name, bool *loaded_now)
{
	int error;

	pthread_mutex_lock(&sysext_load_lock);
	error = ensure_extension_locked(name, loaded_now);
	pthread_mutex_unlock(&sysext_load_lock);
	return (error);
}

static int
ensure_extension_locked(const char *name, bool *loaded_now)
{
	int fileid;

	*loaded_now = false;
	/*
	 * Load THROUGH the held SYS_GATE_KLDLOAD token when born in capability
	 * mode (the raw kldload(2) would fail priv_check as the unprivileged
	 * capability user); fall back to a direct kldload(2) when no token is
	 * held (a unit test).  Both resolve `name` the same way and treat an
	 * already-loaded module (EEXIST) as success.
	 */
#ifdef BSDEXTENSION_TESTING
	if (sysext_test_kld_load != NULL) {
		int error;

		error = sysext_test_kld_load(name, &fileid);
		*loaded_now = error == 0;
		return (error == EEXIST ? 0 : error);
	}
#endif
	if (g_kld_token >= 0) {
		if (service_system_kldload(g_kld_token, name, &fileid) == 0) {
			*loaded_now = true;
			return (0);
		}
		if (errno == EEXIST)
			return (0);
		return (errno);
	}
	if (kldload(name) != -1) {
		*loaded_now = true;
		return (0);
	}
	if (errno == EEXIST)
		return (0);
	return (errno);
}

/*
 * Query whether the named kernel extension is currently loaded, WITHOUT loading
 * it.  Sets *loaded to 1 if present, 0 if not, and returns 0; on a real error
 * returns the errno (and leaves *loaded 0).  kldfind(2) resolves a bare module
 * name against the loaded-file list exactly as kldload resolves it against the
 * module path (both accept the ".ko"-less name), so STAT and ENSURE agree on
 * what a name refers to.  kldfind is the query ENSURE deliberately avoids; it
 * is read-only and ungated (module enumeration is deliberately open), so STAT
 * needs no system capability at all.
 */
static int
stat_extension(const char *name, int *loaded)
{
	char modname[SYSEXT_NAME_MAX];
	size_t len;

	*loaded = 0;
	if (kldfind(name) != -1) {
		*loaded = 1;
		return (0);
	}
	if (errno != ENOENT)
		return (errno);
	/*
	 * A module compiled into the kernel has no file of its own: kldfind
	 * cannot see it, but modfind(2) (read-only, capability-mode enabled)
	 * finds its module name.  Accept the ".ko" spelling as kldfind does.
	 */
	strlcpy(modname, name, sizeof(modname));
	len = strlen(modname);
	if (len > 3 && strcmp(modname + len - 3, ".ko") == 0)
		modname[len - 3] = '\0';
	if (modfind(modname) != -1) {
		*loaded = 1;
		return (0);
	}
	if (errno == ENOENT)
		return (0);
	return (errno);
}

/* Pin before loading, so reclaim cannot race an administrative/boot ensure.
 * Failed loads can retain a conservative boot claim; they never grant a load. */
static int
managed_ensure(const char *name, const char *bundle, bool *loaded_nowp)
{
	bool loaded_now = false;
	const char *owner = bundle[0] != '\0' ? bundle : SYSEXT_BOOT_OWNER;
	int error;

	*loaded_nowp = false;
	if (sysext_owners_fd >= 0 &&
	    sysext_owner_note(sysext_owners_fd, name, owner, false) == -1)
		return (errno);
	error = ensure_extension(name, &loaded_now);
	if (error == 0 && sysext_owners_fd >= 0 &&
	    sysext_owner_note(sysext_owners_fd, name, owner, loaded_now) == -1)
		syslog(LOG_WARNING, "reclaim attribution for %s: %m", name);
	*loaded_nowp = loaded_now;
	return (error);
}

/* Record a permitted load's outcome for the status view. */
static void
record_load(const char *name, const char *client, uint32_t op, int error,
    bool loaded_now)
{

	sysext_decision_record(name, client, op, error != 0 ?
	    SYSEXT_DECISION_FAILED : loaded_now ? SYSEXT_DECISION_LOADED :
	    SYSEXT_DECISION_PRESENT, error);
	/* Another client now relies on a module a root session may have loaded. */
	if (error == 0 && !loaded_now)
		sysext_root_note_shared(name);
}

static int
restore_extensions(const char *client)
{
	bool loaded_now;
	struct sysext_config enabled, current;
	size_t i;
	int error, first = 0;

	if (sysext_policy_enabled(active_policy, &enabled) == -1)
		return (errno);
	for (i = 0; i < enabled.nallow; i++) {
		/* Recheck permission: a concurrent deny must not use the old list. */
		if (sysext_policy_snapshot(active_policy, &current) == -1)
			return (errno);
		if (!extension_allowed(&current, enabled.allow[i]))
			continue;
		error = managed_ensure(enabled.allow[i], "", &loaded_now);
		record_load(enabled.allow[i], client, SYSEXT_OP_RESTORE, error,
		    loaded_now);
		if (error != 0) {
			syslog(LOG_ERR, "restore %s: %s", enabled.allow[i], strerror(error));
			if (first == 0)
				first = error;
		}
	}
	return (first);
}


/* Which reply shape sysext_handle() filled. */
enum sysext_reply_kind {
	SYSEXT_REPLY_BASIC,		/* rp: status only */
	SYSEXT_REPLY_STAT,		/* srp */
	SYSEXT_REPLY_LIST,		/* lrp */
	SYSEXT_REPLY_INFO		/* irp */
};

/*
 * Decide one request.  The bsd.extension.v1 handlers below build the
 * request in the legacy record shape (op and a NUL-terminated name), so the
 * validation, authorization and policy decisions here are the historical ones.
 */
static enum sysext_reply_kind
sysext_handle(const struct sysext_client *identity,
    const struct sysext_request *rq, struct sysext_reply *rp,
    struct sysext_stat_reply *srp, struct sysext_list_reply *lrp,
    struct sysext_info_reply *irp)
{
	const char *client = identity->label;
	struct sysext_config cfg;
	bool driver, loaded_now;
	int loaded;

	memset(rp, 0, sizeof(*rp));
	memset(srp, 0, sizeof(*srp));
	memset(irp, 0, sizeof(*irp));
	if (rq->_reserved != 0 ||
	    (rq->op != SYSEXT_OP_ENSURE && rq->op != SYSEXT_OP_STAT &&
	    rq->op != SYSEXT_OP_LIST && rq->op != SYSEXT_OP_RELOAD &&
	    (rq->op < SYSEXT_OP_ALLOW || rq->op > SYSEXT_OP_NEXT))) {
		rp->status = EINVAL;
		return (SYSEXT_REPLY_BASIC);
	}
	if (rq->op == SYSEXT_OP_LIST || rq->op == SYSEXT_OP_RELOAD ||
	    rq->op == SYSEXT_OP_RESTORE) {
		static const char empty[SYSEXT_NAME_MAX];
		if (memcmp(rq->name, empty, sizeof(empty)) != 0) {
			rp->status = EINVAL;
			return (SYSEXT_REPLY_BASIC);
		}
	}
	/*
	 * The read-only status view decides Info and Next only.  Its handler
	 * table has no other method, so this is defense in depth: whatever the
	 * session's rights, nothing here loads a module or edits policy.
	 */
	if (identity->read_only && rq->op != SYSEXT_OP_INFO &&
	    rq->op != SYSEXT_OP_NEXT) {
		rp->status = EPERM;
		syslog(LOG_WARNING, "request %u (client %s) -> DENIED "
		    "(read-only status session)", rq->op, client);
		return (SYSEXT_REPLY_BASIC);
	}
	/* A root-load session has no method that reaches this decision. */
	if (identity->root_load) {
		rp->status = EPERM;
		syslog(LOG_WARNING, "request %u (client %s) -> DENIED "
		    "(root-load session)", rq->op, client);
		return (SYSEXT_REPLY_BASIC);
	}
	if (rq->op >= SYSEXT_OP_ALLOW && rq->op <= SYSEXT_OP_RESTORE) {
		if (!service_rights_allow(identity->rights, SERVICE_RIGHTS_ADMIN))
			rp->status = EPERM;
		else if (rq->op == SYSEXT_OP_RESTORE)
			rp->status = restore_extensions(client);
		else if (sysext_policy_change(active_policy, rq->op, rq->name,
		    identity->rights) == -1)
			rp->status = errno;
		return (SYSEXT_REPLY_BASIC);
	}
	if (rq->op == SYSEXT_OP_INFO || rq->op == SYSEXT_OP_NEXT) {
		if (!valid_module_name(rq->name) &&
		    !(rq->op == SYSEXT_OP_NEXT && rq->name[0] == '\0')) {
			rp->status = EINVAL;
			return (SYSEXT_REPLY_BASIC);
		}
		if (sysext_policy_info(active_policy, rq->name,
		    rq->op == SYSEXT_OP_NEXT, irp) == -1) {
			rp->status = errno;
			return (SYSEXT_REPLY_BASIC);
		}
		/*
		 * The hardware-driver class grants without an allow-list entry;
		 * report it as allowed unless an override denies the name.
		 */
		if ((irp->flags & SYSEXT_STATE_ALLOWED) == 0 &&
		    sysext_policy_snapshot(active_policy, &cfg) == 0 &&
		    request_allowed(&cfg, NULL, irp->name, &driver))
			irp->flags |= SYSEXT_STATE_ALLOWED;
		/* Do not disclose loaded state for a denied module. */
		if ((irp->flags & SYSEXT_STATE_ALLOWED) != 0) {
			rp->status = stat_extension(irp->name, &loaded);
			if (rp->status != 0)
				return (SYSEXT_REPLY_BASIC);
			if (loaded)
				irp->flags |= SYSEXT_STATE_LOADED;
		}
		return (SYSEXT_REPLY_INFO);
	}
	if (rq->op == SYSEXT_OP_RELOAD) {
		if (!service_rights_allow(identity->rights, SERVICE_RIGHTS_ADMIN)) {
			rp->status = EPERM;
			return (SYSEXT_REPLY_BASIC);
		}
		/*
		 * Reload capmode-safely: in production the operator allow-list is read
		 * through the switchboard-delivered Config descriptor (an absolute
		 * open(policy_path) is refused after cap_enter); an explicit -c path
		 * (tests / pre-capmode) still reloads by path.
		 */
		if (policy_delivered) {
			int rfd;

			if (service_config_open(SYSEXT_CONFIG_NAME, &rfd) == 0) {
				if (sysext_policy_reload_fd(active_policy, rfd,
				    identity->rights) == -1)
					rp->status = errno;
				(void)close(rfd);
			} else {
				rp->status = errno;
			}
		} else if (sysext_policy_reload(active_policy, policy_path,
		    identity->rights) == -1) {
			rp->status = errno;
		}
		syslog(LOG_NOTICE, "RELOAD (client %s) -> %s", client,
		    rp->status == 0 ? "policy installed" : strerror(rp->status));
		return (SYSEXT_REPLY_BASIC);
	}
	if (sysext_policy_snapshot(active_policy, &cfg) == -1) {
		rp->status = errno;
		return (SYSEXT_REPLY_BASIC);
	}
	/*
	 * LIST enumerates the module names the allow-list permits, so a consumer
	 * can discover what it may ENSURE without STAT-probing names blindly.  It
	 * carries no module name and is not itself gated by the allow-list (it
	 * only reveals which names may load, never any loaded/not-loaded state);
	 * reaching bsdextension at all already required the SYSTEM-domain gate.  The
	 * allow-list is global, not per-label, so every caller sees the same set.
	 */
	if (rq->op == SYSEXT_OP_LIST) {
		size_t i;

		if (cfg.nallow > SYSEXT_LIST_MAX) {
			rp->status = EOVERFLOW;
			return (SYSEXT_REPLY_BASIC);
		}
		memset(lrp, 0, sizeof(*lrp));
		lrp->status = 0;
		lrp->count = (uint32_t)cfg.nallow;
		for (i = 0; i < cfg.nallow && i < SYSEXT_LIST_MAX; i++)
			(void)strlcpy(lrp->names[i], cfg.allow[i],
			    SYSEXT_NAME_MAX);
		BSDEXTENSION_PROBE_LIST(client, lrp->count, 0);
		syslog(LOG_INFO, "LIST (client %s) -> %u module(s)", client,
		    lrp->count);
		return (SYSEXT_REPLY_LIST);
	}
	if (!valid_module_name(rq->name)) {
		rp->status = EINVAL;
		return (SYSEXT_REPLY_BASIC);
	}
	/*
	 * Default-deny by name, for BOTH operations: even a syntactically valid
	 * module is refused unless it is on the allow-list or, when the policy
	 * enables device_drivers, the kernel's linker.hints records the file
	 * with plug-and-play match data (request_allowed()).  This is the boundary
	 * between "may reach bsdextension" (the domain gate) and "may act on THIS
	 * kernel code".  A client may STAT only a module it could ENSURE, so a
	 * non-allow-listed name is EPERM rather than a loaded/not-loaded answer —
	 * denial leaks no information about the module set.
	 */
	if (!request_allowed(&cfg, client, rq->name, &driver)) {
		uint32_t reason;

		/* The most specific cause: an administrator deny, then the class. */
		if (active_policy != NULL &&
		    sysext_policy_denied(active_policy, rq->name))
			reason = SYSEXT_DECISION_OVERRIDE;
		else if (sysext_driver_client(&cfg, client))
			reason = SYSEXT_DECISION_DRIVERS_ONLY;
		else
			reason = SYSEXT_DECISION_NOT_PERMITTED;
		rp->status = EPERM;
		syslog(LOG_WARNING,
		    "%s %s (client %s) -> DENIED (%s)",
		    rq->op == SYSEXT_OP_STAT ? "STAT" : "ENSURE", rq->name,
		    client, reason == SYSEXT_DECISION_OVERRIDE ?
		    "administrator deny override" :
		    reason == SYSEXT_DECISION_DRIVERS_ONLY ?
		    "client may load hardware drivers only" :
		    "not on allow-list");
		if (rq->op == SYSEXT_OP_ENSURE)
			sysext_decision_record(rq->name, client,
			    SYSEXT_OP_ENSURE, reason, 0);
		return (SYSEXT_REPLY_BASIC);
	}

	if (rq->op == SYSEXT_OP_STAT) {
		srp->status = stat_extension(rq->name, &loaded);
		srp->loaded = loaded;
		if (srp->status == 0)
			syslog(LOG_INFO, "STAT %s (client %s) -> %s", rq->name,
			    client, srp->loaded ? "loaded" : "not loaded");
		else
			syslog(LOG_NOTICE, "STAT %s (client %s) -> %s", rq->name,
			    client, strerror(srp->status));
		return (SYSEXT_REPLY_STAT);
	}

	rp->status = managed_ensure(rq->name, identity->bundle, &loaded_now);
	record_load(rq->name, client, SYSEXT_OP_ENSURE, rp->status, loaded_now);
	syslog(LOG_INFO, "ENSURE %s (client %s%s): %s", rq->name, client,
	    driver ? ", hardware driver" : "",
	    rp->status == 0 ? "loaded" : strerror(rp->status));
	return (SYSEXT_REPLY_BASIC);
}

struct sysext_session {
	const struct sysext_client *identity;
	bool negotiated;
};

/*
 * bsd.extension.v1 method handlers.  Every method but GetProtocolInfo requires
 * a negotiated session; a failed reply closes the connection.  The
 * request-done probe keeps the historical SYSEXT_OP_* codes (0 is protocol
 * negotiation).
 */
static bool
ext_ready(struct sysext_session *session, struct fidl_bsd_connection *connection,
    uint32_t opcode)
{

	if (session->negotiated)
		return (true);
	BSDEXTENSION_PROBE_REQUEST_DONE(opcode, EPROTO, EPROTO);
	fidl_bsd_connection_close(connection, EPROTO);
	return (false);
}

static void
ext_completed(struct fidl_bsd_connection *connection, uint32_t opcode,
    int status, int transport_error)
{

	BSDEXTENSION_PROBE_REQUEST_DONE(opcode, status, transport_error);
	if (transport_error != 0)
		fidl_bsd_connection_close(connection, transport_error);
}

static void
ext_protocol_info(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct sysext_session *session = argument;
	struct bsd_extension_v1_ProtocolInfo info = { SYSEXT_WIRE_VERSION };
	int error;

	error = bsd_extension_v1_SystemExtension_GetProtocolInfo_reply(
	    connection, request, &info);
	session->negotiated = error == 0;
	ext_completed(connection, 0, 0, error);
}

/*
 * Build the legacy-shaped request; an embedded NUL in the name is refused
 * (it would silently truncate the module name).
 */
static bool
ext_request(struct sysext_request *rq, uint32_t op, const char *name,
    size_t length)
{

	memset(rq, 0, sizeof(*rq));
	rq->op = op;
	if (length >= sizeof(rq->name) ||
	    (length != 0 && memchr(name, '\0', length) != NULL))
		return (false);
	if (length != 0)
		memcpy(rq->name, name, length);
	return (true);
}

/*
 * Run one request and answer it.  `reply` is the method's generated reply
 * function wrapped below; the decision and every status are sysext_handle()'s.
 */
struct ext_outcome {
	enum sysext_reply_kind kind;
	int status;
	struct sysext_reply rp;
	struct sysext_stat_reply srp;
	struct sysext_list_reply lrp;
	struct sysext_info_reply irp;
};

static void
ext_decide(struct sysext_session *session, uint32_t op, const char *name,
    size_t length, struct ext_outcome *out)
{
	struct sysext_request rq;

	if (!ext_request(&rq, op, name, length)) {
		memset(out, 0, sizeof(*out));
		out->kind = SYSEXT_REPLY_BASIC;
		out->status = EINVAL;
		return;
	}
	out->kind = sysext_handle(session->identity, &rq, &out->rp, &out->srp,
	    &out->lrp, &out->irp);
	switch (out->kind) {
	case SYSEXT_REPLY_STAT:
		out->status = out->srp.status;
		break;
	case SYSEXT_REPLY_LIST:
		out->status = out->lrp.status;
		break;
	case SYSEXT_REPLY_INFO:
		out->status = out->irp.status;
		break;
	default:
		out->status = out->rp.status;
		break;
	}
}

/* Methods whose success reply is empty. */
#define	EXT_EMPTY_METHOD(fn, method, op, has_name)			\
static void								\
fn(void *argument, struct fidl_bsd_connection *connection,		\
    struct fidl_bsd_request *request, EXT_ARG_##has_name)		\
{									\
	struct sysext_session *session = argument;			\
	struct bsd_extension_v1_SystemExtension_##method##_Result reply;\
	struct ext_outcome *out;					\
	int status;							\
									\
	if (!ext_ready(session, connection, op))			\
		return;							\
	memset(&reply, 0, sizeof(reply));				\
	out = malloc(sizeof(*out));					\
	if (out == NULL)						\
		status = ENOMEM;					\
	else {								\
		ext_decide(session, op, EXT_NAME_##has_name, out);	\
		status = out->status;					\
	}								\
	if (status == 0)						\
		reply.tag = bsd_extension_v1_SystemExtension_##method##_Result_response_tag; \
	else {								\
		reply.tag = bsd_extension_v1_SystemExtension_##method##_Result_err_tag; \
		reply.value.err = (uint32_t)status;			\
	}								\
	free(out);							\
	ext_completed(connection, op, status,				\
	    bsd_extension_v1_SystemExtension_##method##_reply(connection,	\
	    request, &reply));						\
}
#define	EXT_ARG_1	struct bsd_extension_v1_Module *value
#define	EXT_ARG_0	struct fidl_bsd_empty *value __unused
#define	EXT_NAME_1	value->name, value->name_size
#define	EXT_NAME_0	"", 0

EXT_EMPTY_METHOD(ext_ensure, Ensure, SYSEXT_OP_ENSURE, 1)
EXT_EMPTY_METHOD(ext_reload, Reload, SYSEXT_OP_RELOAD, 0)
EXT_EMPTY_METHOD(ext_allow, Allow, SYSEXT_OP_ALLOW, 1)
EXT_EMPTY_METHOD(ext_deny, Deny, SYSEXT_OP_DENY, 1)
EXT_EMPTY_METHOD(ext_reset, Reset, SYSEXT_OP_RESET, 1)
EXT_EMPTY_METHOD(ext_enable, Enable, SYSEXT_OP_ENABLE, 1)
EXT_EMPTY_METHOD(ext_disable, Disable, SYSEXT_OP_DISABLE, 1)
EXT_EMPTY_METHOD(ext_restore, Restore, SYSEXT_OP_RESTORE, 0)

static void
ext_stat(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_extension_v1_Module *value)
{
	struct sysext_session *session = argument;
	struct bsd_extension_v1_SystemExtension_Stat_Result reply;
	struct ext_outcome out;

	if (!ext_ready(session, connection, SYSEXT_OP_STAT))
		return;
	memset(&reply, 0, sizeof(reply));
	ext_decide(session, SYSEXT_OP_STAT, value->name, value->name_size, &out);
	if (out.status == 0 && out.kind == SYSEXT_REPLY_STAT) {
		reply.tag = bsd_extension_v1_SystemExtension_Stat_Result_response_tag;
		reply.value.response.loaded = out.srp.loaded != 0;
	} else {
		reply.tag = bsd_extension_v1_SystemExtension_Stat_Result_err_tag;
		reply.value.err = (uint32_t)(out.status != 0 ? out.status : EIO);
	}
	ext_completed(connection, SYSEXT_OP_STAT, out.status,
	    bsd_extension_v1_SystemExtension_Stat_reply(connection, request,
	    &reply));
}

static void
ext_list(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct sysext_session *session = argument;
	struct bsd_extension_v1_SystemExtension_List_Result reply;
	struct bsd_extension_v1_Module modules[SYSEXT_LIST_MAX];
	struct ext_outcome *out;
	int status;

	if (!ext_ready(session, connection, SYSEXT_OP_LIST))
		return;
	memset(&reply, 0, sizeof(reply));
	out = malloc(sizeof(*out));
	if (out == NULL)
		status = ENOMEM;
	else {
		ext_decide(session, SYSEXT_OP_LIST, "", 0, out);
		status = out->status;
	}
	if (status == 0 && out->kind == SYSEXT_REPLY_LIST) {
		for (uint32_t i = 0; i < out->lrp.count; i++) {
			modules[i].name = out->lrp.names[i];
			modules[i].name_size = strnlen(out->lrp.names[i],
			    SYSEXT_NAME_MAX);
		}
		reply.tag = bsd_extension_v1_SystemExtension_List_Result_response_tag;
		reply.value.response.modules = modules;
		reply.value.response.modules_size = out->lrp.count;
	} else {
		reply.tag = bsd_extension_v1_SystemExtension_List_Result_err_tag;
		reply.value.err = (uint32_t)(status != 0 ? status : EIO);
	}
	ext_completed(connection, SYSEXT_OP_LIST, status,
	    bsd_extension_v1_SystemExtension_List_reply(connection, request,
	    &reply));
	free(out);
}

static void
ext_info_reply(struct sysext_session *session,
    struct fidl_bsd_connection *connection, struct fidl_bsd_request *request,
    uint32_t op, const char *name, size_t length)
{
	struct bsd_extension_v1_SystemExtension_Info_Result reply;
	struct ext_outcome out;
	int error;

	memset(&reply, 0, sizeof(reply));
	ext_decide(session, op, name, length, &out);
	if (out.status == 0 && out.kind == SYSEXT_REPLY_INFO) {
		reply.tag = bsd_extension_v1_SystemExtension_Info_Result_response_tag;
		reply.value.response.name = out.irp.name;
		reply.value.response.name_size = strnlen(out.irp.name,
		    sizeof(out.irp.name));
		reply.value.response.flags = out.irp.flags;
	} else {
		reply.tag = bsd_extension_v1_SystemExtension_Info_Result_err_tag;
		reply.value.err = (uint32_t)(out.status != 0 ? out.status : EIO);
	}
	/* Info and Next share the result layout. */
	if (op == SYSEXT_OP_INFO)
		error = bsd_extension_v1_SystemExtension_Info_reply(connection,
		    request, &reply);
	else
		error = bsd_extension_v1_SystemExtension_Next_reply(connection,
		    request,
		    (struct bsd_extension_v1_SystemExtension_Next_Result *)&reply);
	ext_completed(connection, op, out.status, error);
}

static void
ext_info(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_extension_v1_Module *value)
{
	struct sysext_session *session = argument;

	if (!ext_ready(session, connection, SYSEXT_OP_INFO))
		return;
	ext_info_reply(session, connection, request, SYSEXT_OP_INFO,
	    value->name, value->name_size);
}

static void
ext_next(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_extension_v1_Cursor *value)
{
	struct sysext_session *session = argument;

	if (!ext_ready(session, connection, SYSEXT_OP_NEXT))
		return;
	ext_info_reply(session, connection, request, SYSEXT_OP_NEXT,
	    value->name, value->name_size);
}

/*
 * bsd.extension.v1 SystemExtensionStatus: the read-only view served on
 * system.SystemExtension.Status.  The protocol has no Ensure, Reload or policy
 * method, so a request for one is an unknown ordinal and closes the session.
 * Info and Next are decided by sysext_handle() exactly as on SystemExtension
 * (the session's identity is marked read-only as well).
 */
static void
st_protocol_info(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct sysext_session *session = argument;
	struct bsd_extension_v1_ProtocolInfo info = { SYSEXT_WIRE_VERSION };
	int error;

	error = bsd_extension_v1_SystemExtensionStatus_GetProtocolInfo_reply(
	    connection, request, &info);
	session->negotiated = error == 0;
	ext_completed(connection, 0, 0, error);
}

/* Info and Next share a result layout; one macro per generated type. */
#define	ST_INFO_METHOD(fn, method, op, argtype)				\
static void								\
fn(void *argument, struct fidl_bsd_connection *connection,		\
    struct fidl_bsd_request *request, argtype *value)			\
{									\
	struct sysext_session *session = argument;			\
	struct bsd_extension_v1_SystemExtensionStatus_##method##_Result reply; \
	struct ext_outcome out;						\
									\
	if (!ext_ready(session, connection, op))			\
		return;							\
	memset(&reply, 0, sizeof(reply));				\
	ext_decide(session, op, value->name, value->name_size, &out);	\
	if (out.status == 0 && out.kind == SYSEXT_REPLY_INFO) {		\
		reply.tag = bsd_extension_v1_SystemExtensionStatus_##method##_Result_response_tag; \
		reply.value.response.name = out.irp.name;		\
		reply.value.response.name_size = strnlen(out.irp.name,	\
		    sizeof(out.irp.name));				\
		reply.value.response.flags = out.irp.flags;		\
	} else {							\
		reply.tag = bsd_extension_v1_SystemExtensionStatus_##method##_Result_err_tag; \
		reply.value.err = (uint32_t)(out.status != 0 ?		\
		    out.status : EIO);					\
	}								\
	ext_completed(connection, op, out.status,			\
	    bsd_extension_v1_SystemExtensionStatus_##method##_reply(	\
	    connection, request, &reply));				\
}
ST_INFO_METHOD(st_info, Info, SYSEXT_OP_INFO, struct bsd_extension_v1_Module)
ST_INFO_METHOD(st_next, Next, SYSEXT_OP_NEXT, struct bsd_extension_v1_Cursor)

static void
st_next_decision(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request,
    struct bsd_extension_v1_DecisionCursor *value)
{
	struct sysext_session *session = argument;
	struct bsd_extension_v1_SystemExtensionStatus_NextDecision_Result reply;
	struct sysext_decision d;
	int status;

	if (!ext_ready(session, connection, SYSEXT_OP_DECISION))
		return;
	memset(&reply, 0, sizeof(reply));
	status = sysext_decision_next(value->after, &d);
	if (status == 0) {
		reply.tag = bsd_extension_v1_SystemExtensionStatus_NextDecision_Result_response_tag;
		reply.value.response.sequence = d.sequence;
		reply.value.response.time = d.time;
		reply.value.response.module = d.module;
		reply.value.response.module_size = strnlen(d.module,
		    sizeof(d.module));
		reply.value.response.client = d.client;
		reply.value.response.client_size = strnlen(d.client,
		    sizeof(d.client));
		reply.value.response.operation = d.operation;
		reply.value.response.result = d.result;
		reply.value.response.error = d.error;
	} else {
		reply.tag = bsd_extension_v1_SystemExtensionStatus_NextDecision_Result_err_tag;
		reply.value.err = (uint32_t)status;
	}
	ext_completed(connection, SYSEXT_OP_DECISION, status,
	    bsd_extension_v1_SystemExtensionStatus_NextDecision_reply(connection,
	    request, &reply));
}

/*
 * bsd.extension.v1 SystemExtensionRootLoad, served on
 * system.SystemExtension.RootLoad: switchboard resolves it for UID 0 sessions
 * outside a jail that hold no software authority (root-load.ucl).  The
 * protocol has Load and Unload only; neither consults the allow-list or the
 * session's rights.  Load requires the policy's root_load_repository and no
 * administrator deny, then rootload.c's checks of the module and every
 * dependency it would bring in (package, checksum, administrator deny,
 * protected modules), all before anything is loaded.  Every
 * request is recorded in the decision ring and logged with the switchboard
 * label and the requester's program nonce.
 */
static const char *
decision_word(uint32_t result)
{

	switch (result) {
	case SYSEXT_DECISION_LOADED:
		return ("loaded");
	case SYSEXT_DECISION_PRESENT:
		return ("already loaded");
	case SYSEXT_DECISION_OVERRIDE:
		return ("DENIED (administrator deny override)");
	case SYSEXT_DECISION_FAILED:
		return ("FAILED");
	case SYSEXT_DECISION_NOT_PACKAGED:
		return ("DENIED (not a file of a 5BSD base package)");
	case SYSEXT_DECISION_CHECKSUM:
		return ("DENIED (checksum differs from the package record)");
	case SYSEXT_DECISION_NOT_KERNEL_DIR:
		return ("DENIED (no regular module file in the running kernel's "
		    "directory)");
	case SYSEXT_DECISION_UNLOADED:
		return ("unloaded");
	case SYSEXT_DECISION_NOT_ROOT_LOADED:
		return ("DENIED (not loaded by a root load)");
	case SYSEXT_DECISION_DISABLED:
		return ("DENIED (root loads are not configured)");
	case SYSEXT_DECISION_PKGDB:
		return ("DENIED (package database unavailable)");
	case SYSEXT_DECISION_CHANGED:
		return ("DENIED (file changed during the load)");
	case SYSEXT_DECISION_PROTECTED:
		return ("DENIED (protected module)");
	default:
		return ("?");
	}
}

static uint32_t
root_decide(const struct sysext_client *identity, uint32_t op,
    const char *name, size_t length, int *errorp, int *statusp)
{
	struct sysext_request rq;
	struct sysext_config cfg;
	char detail[384];
	uint32_t result;
	int error = 0, loaded = 0;

	*errorp = 0;
	*statusp = 0;
	if (!identity->root_load) {
		*statusp = EPERM;
		return (0);
	}
	if (!ext_request(&rq, op, name, length) || !valid_module_name(rq.name)) {
		*statusp = EINVAL;
		syslog(LOG_WARNING, "ROOT %s (uid 0 session, client %s) -> "
		    "invalid module name", op == SYSEXT_OP_ROOT_LOAD ? "LOAD" :
		    "UNLOAD", identity->label);
		return (0);
	}
	if (active_policy == NULL ||
	    sysext_policy_snapshot(active_policy, &cfg) == -1) {
		*statusp = active_policy == NULL ? EINVAL : errno;
		return (0);
	}
	detail[0] = '\0';
	if (op != SYSEXT_OP_ROOT_LOAD)
		result = sysext_root_unload(rq.name, &error, detail,
		    sizeof(detail));
	else if (cfg.root_load_repository[0] == '\0') {
		result = SYSEXT_DECISION_DISABLED;
		(void)snprintf(detail, sizeof(detail), "%s sets no "
		    "root_load_repository", SYSEXT_CONFIG_NAME);
	} else if (sysext_policy_denied(active_policy, rq.name))
		result = SYSEXT_DECISION_OVERRIDE;
	else if (stat_extension(rq.name, &loaded) == 0 && loaded)
		result = SYSEXT_DECISION_PRESENT;
	else
		result = sysext_root_load(cfg.root_load_repository, rq.name,
		    &error, detail, sizeof(detail));
	sysext_decision_record(rq.name, SYSEXT_ROOT_CLIENT, op, result, error);
	syslog(result == SYSEXT_DECISION_LOADED ||
	    result == SYSEXT_DECISION_PRESENT ||
	    result == SYSEXT_DECISION_UNLOADED ? LOG_NOTICE : LOG_WARNING,
	    "ROOT %s %s (uid 0 session, client %s, program nonce %#jx) -> "
	    "%s%s%s%s%s", op == SYSEXT_OP_ROOT_LOAD ? "LOAD" : "UNLOAD",
	    rq.name, identity->label, (uintmax_t)identity->nonce,
	    decision_word(result), error != 0 ? ": " : "",
	    error != 0 ? strerror(error) : "", detail[0] != '\0' ? "; " : "",
	    detail);
	*errorp = error;
	return (result);
}

static void
rl_protocol_info(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct sysext_session *session = argument;
	struct bsd_extension_v1_ProtocolInfo info = { SYSEXT_WIRE_VERSION };
	int error;

	error = bsd_extension_v1_SystemExtensionRootLoad_GetProtocolInfo_reply(
	    connection, request, &info);
	session->negotiated = error == 0;
	ext_completed(connection, 0, 0, error);
}

#define	RL_METHOD(fn, method, op)					\
static void								\
fn(void *argument, struct fidl_bsd_connection *connection,		\
    struct fidl_bsd_request *request, struct bsd_extension_v1_Module *value) \
{									\
	struct sysext_session *session = argument;			\
	struct bsd_extension_v1_SystemExtensionRootLoad_##method##_Result reply; \
	uint32_t result;						\
	int status, error;						\
									\
	if (!ext_ready(session, connection, op))			\
		return;							\
	memset(&reply, 0, sizeof(reply));				\
	result = root_decide(session->identity, op, value->name,	\
	    value->name_size, &error, &status);				\
	if (status == 0) {						\
		reply.tag = bsd_extension_v1_SystemExtensionRootLoad_##method##_Result_response_tag; \
		reply.value.response.result = result;			\
		reply.value.response.error = (uint32_t)error;		\
	} else {							\
		reply.tag = bsd_extension_v1_SystemExtensionRootLoad_##method##_Result_err_tag; \
		reply.value.err = (uint32_t)status;			\
	}								\
	ext_completed(connection, op, status,				\
	    bsd_extension_v1_SystemExtensionRootLoad_##method##_reply(	\
	    connection, request, &reply));				\
}
RL_METHOD(rl_load, Load, SYSEXT_OP_ROOT_LOAD)
RL_METHOD(rl_unload, Unload, SYSEXT_OP_ROOT_UNLOAD)

/*
 * Serve one client on its own worker channel until it closes.  Runs in a
 * client-serving thread; it shares the daemon's process and held gate token, so
 * its kldload passes the gate under the authorization granted at startup.
 * A status session (system.SystemExtension.Status) is bound to the
 * SystemExtensionStatus handlers instead and marked read-only; a root-load
 * session (system.SystemExtension.RootLoad) to SystemExtensionRootLoad.
 */
static int
sysext_worker(int fd, const char *client, const char *container,
    service_rights_t rights, enum sysext_endpoint kind, uint64_t nonce)
{
	static const struct bsd_extension_v1_SystemExtensionRootLoad_server
	    rootload_handlers = {
		.GetProtocolInfo = rl_protocol_info,
		.Load = rl_load,
		.Unload = rl_unload
	};
	static const struct bsd_extension_v1_SystemExtensionStatus_server
	    status_handlers = {
		.GetProtocolInfo = st_protocol_info,
		.Info = st_info,
		.Next = st_next,
		.NextDecision = st_next_decision
	};
	static const struct bsd_extension_v1_SystemExtension_server handlers = {
		.GetProtocolInfo = ext_protocol_info,
		.Ensure = ext_ensure,
		.Stat = ext_stat,
		.List = ext_list,
		.Reload = ext_reload,
		.Allow = ext_allow,
		.Deny = ext_deny,
		.Reset = ext_reset,
		.Enable = ext_enable,
		.Disable = ext_disable,
		.Restore = ext_restore,
		.Info = ext_info,
		.Next = ext_next
	};
	struct fidl_bsd_connection *connection;
	char label[SYSEXT_NAME_MAX], bundle[64] = "";
	struct sysext_client identity = { .label = label, .bundle = bundle,
	    .rights = rights, .read_only = kind == SYSEXT_ENDPOINT_STATUS,
	    .root_load = kind == SYSEXT_ENDPOINT_ROOTLOAD, .nonce = nonce };
	struct sysext_session session = { .identity = &identity };
	int bound;

	(void)strlcpy(label, client, sizeof(label));
	/* The stamped container names the bundle; "" for units without one. */
	if (sysext_bundle_of(container, bundle, sizeof(bundle)) == -1)
		bundle[0] = '\0';

	/*
	 * fidl_bsd_connection_create() takes fd on success and leaves it on
	 * failure -- so close it here only on failure, and NEVER after return.
	 * The caller (sysext_client_thread) must not close it again: doing so
	 * closes an fd number this worker already gave up, which a concurrent
	 * accept on another thread may have re-used (double-close race that
	 * silently drops a co-connecting client).
	 */
	if (fidl_bsd_connection_create(fd, FIDL_BSD_SERVER, &connection) != 0) {
		(void)close(fd);
		return (1);
	}
	switch (kind) {
	case SYSEXT_ENDPOINT_STATUS:
		bound = bsd_extension_v1_SystemExtensionStatus_bind(connection,
		    &status_handlers, &session);
		break;
	case SYSEXT_ENDPOINT_ROOTLOAD:
		bound = bsd_extension_v1_SystemExtensionRootLoad_bind(connection,
		    &rootload_handlers, &session);
		break;
	default:
		bound = bsd_extension_v1_SystemExtension_bind(connection,
		    &handlers, &session);
		break;
	}
	if (bound != 0) {
		fidl_bsd_connection_destroy(connection);
		return (1);
	}
	/* Peer close or a protocol violation ends the session. */
	while (fidl_bsd_connection_poll(connection, -1) == 0)
		;
	fidl_bsd_connection_destroy(connection);
	return (0);
}

#ifdef BSDEXTENSION_TESTING
/*
 * Test-only serve entry point.  Installs cfg as the resolved allow-list (which
 * every client-serving thread otherwise shares through the daemon's process) and
 * runs the real per-client worker on fd, so a test drives the identical
 * sysext_request path a production worker would.  ENSURE cases a test drives
 * (deny, malformed) are refused before ensure_extension is reached, so no
 * kldload(2) runs; STAT cases for an allow-listed name do reach kldfind(2), a
 * read-only query that loads nothing and is not gated, so it succeeds in any
 * environment.
 */
int
sysext_test_serve(int fd, const char *client, const struct sysext_config *cfg)
{
	int result;

	active_policy = sysext_policy_create(cfg);
	if (active_policy == NULL)
		return (1);
	result = sysext_worker(fd, client, "", SERVICE_RIGHTS_NONE,
	    SYSEXT_ENDPOINT_FULL, 0);
	sysext_policy_destroy(active_policy);
	return (result);
}

/*
 * The status view.  The session is given every right, ADMIN included, so a
 * test shows that the endpoint alone, not the rights, keeps it read-only.
 */
int
sysext_test_serve_status(int fd, const char *client,
    const struct sysext_config *cfg)
{
	int result;

	active_policy = sysext_policy_create(cfg);
	if (active_policy == NULL)
		return (1);
	result = sysext_worker(fd, client, "", SERVICE_RIGHTS_ALL,
	    SYSEXT_ENDPOINT_STATUS, 0);
	sysext_policy_destroy(active_policy);
	return (result);
}


/*
 * The root-load endpoint over the test's root, kernel and package directories.
 * The session is given every right, ADMIN included: the endpoint alone decides
 * what it may do.
 */
int
sysext_test_serve_rootload(int fd, const char *client,
    const struct sysext_config *cfg, int rootdir, int bootdir, int pkgdir,
    const char *deny)
{
	int result, saved_root = sysext_root_dirfd,
	    saved_boot = sysext_boot_dirfd,
	    saved_kernel = sysext_driver_dirfd, saved_pkg = sysext_pkgdb_dirfd,
	    statedir;

	active_policy = sysext_policy_create(cfg);
	if (active_policy == NULL)
		return (1);
	/* An administrator deny override, in a private state directory. */
	if (deny != NULL) {
		(void)mkdir("rl-policy-state", 0700);
		statedir = open("rl-policy-state", O_DIRECTORY | O_RDONLY);
		if (statedir == -1 ||
		    sysext_policy_attach(active_policy, statedir) == -1 ||
		    sysext_policy_change(active_policy, SYSEXT_OP_DENY, deny,
		    SERVICE_RIGHTS_ADMIN) == -1)
			return (1);
	}
	sysext_root_dirfd = rootdir;
	sysext_boot_dirfd = bootdir;
	sysext_pkgdb_dirfd = pkgdir;
	if (sysext_kernel_dir_open() != 0)
		sysext_driver_dirfd = -1;
	result = sysext_worker(fd, client, "", SERVICE_RIGHTS_ALL,
	    SYSEXT_ENDPOINT_ROOTLOAD, 0x5b5d);
	if (sysext_driver_dirfd != -1)
		(void)close(sysext_driver_dirfd);
	sysext_root_dirfd = saved_root;
	sysext_boot_dirfd = saved_boot;
	sysext_driver_dirfd = saved_kernel;
	sysext_pkgdb_dirfd = saved_pkg;
	sysext_policy_destroy(active_policy);
	active_policy = NULL;
	return (result);
}
void
sysext_test_decisions_reset(void)
{

	pthread_mutex_lock(&sysext_decisions_lock);
	memset(sysext_decisions, 0, sizeof(sysext_decisions));
	sysext_decision_seq = 1;
	pthread_mutex_unlock(&sysext_decisions_lock);
}
#endif /* BSDEXTENSION_TESTING */

#ifndef BSDEXTENSION_TESTING
/*
 * Per-client thread argument (heap-allocated; the thread owns and frees it).
 */
struct sysext_conn {
	int			fd;
	service_rights_t	rights;
	char			label[64];	/* service_identity.client_label */
	char			container[64];	/* service_identity.container */
	enum sysext_endpoint	kind;		/* the listener that accepted it */
	uint64_t		nonce;		/* service_identity.client_nonce */
};

/*
 * Bound concurrent client threads.  Sessions are long-lived (a consumer caches
 * a persistent session via service_ensure_extension), and each detached thread
 * costs a stack plus a channel fd, so an unbounded spawn would let a
 * switchboard-authorized label exhaust threads/fds/address space on the
 * privileged kldload broker.  A thread carries a stack (unlike a pdfork worker's
 * separate address space), so the ceiling is lower than the *_MAX_WORKERS = 4096
 * the process-per-client daemons use; 256 concurrent kldload sessions is still
 * far above any legitimate need, and a refused client simply retries.
 */
#define	SYSEXT_MAX_CLIENTS	256
static _Atomic unsigned sysext_nthreads;

/*
 * Per-client worker thread: run the channel session to completion, then close
 * the client fd and release the argument.  Threads (unlike pdfork workers)
 * share the daemon's SYS_GATE_KLDLOAD token, so each can perform gated loads.
 */
static void *
sysext_client_thread(void *arg)
{
	struct sysext_conn *c = arg;

	/* sysext_worker() owns c->fd (its connection takes it, or it closes it
	 * on failure) -- do NOT close it again here (double-close race). */
	(void)sysext_worker(c->fd, c->label, c->container, c->rights,
	    c->kind, c->nonce);
	free(c);
	(void)atomic_fetch_sub_explicit(&sysext_nthreads, 1,
	    memory_order_relaxed);
	return (NULL);
}

/*
 * Expose system.SystemExtension and the read-only system.SystemExtension.Status
 * and serve each accepted client.  Each name has its own listener; the
 * listener that fired decides the handler table, and the endpoint switchboard
 * names in the identity must agree with it.
 * service_provider_authorize_capabilities() authorizes the delivered
 * SYS_GATE_KLDLOAD/KLDUNLOAD token, which is then dup'd (survives the bootstrap
 * authority drop) so it outlives into capability mode.
 *
 * bsdextension is BORN IN CAPABILITY MODE.  kldload(2)/kldunload(2) are
 * capmode-enabled but run priv_check(PRIV_KLD_LOAD/UNLOAD), which the
 * unprivileged capability user fails; the load/unload instead go THROUGH the
 * held gate (service_system_kldload/kldunload -> kern_kldload_gated), whose
 * claim replaces that privilege.  The kernel performs the module-path lookup in
 * kernel context (a UIO_SYSSPACE namei, exempt from the capmode userspace-path
 * restriction), so a born-in-capmode broker resolves modules that the raw
 * syscall could not.  The delivered token is close-on-fork, so clients are
 * served INLINE (no per-client worker could inherit it).  Returns -1 only on
 * setup failure.
 */
static int
sysext_serve(void)
{
	static const char *const names[SYSEXT_ENDPOINTS] = {
		[SYSEXT_ENDPOINT_FULL] = SYSEXT_SERVICE_NAME,
		[SYSEXT_ENDPOINT_STATUS] = SYSEXT_STATUS_SERVICE_NAME,
		[SYSEXT_ENDPOINT_ROOTLOAD] = SYSEXT_ROOTLOAD_SERVICE_NAME
	};
	struct service_identity id;
	struct service_listener *listeners[SYSEXT_ENDPOINTS];
	struct service_provider *provider;
	struct kevent changes[SYSEXT_ENDPOINTS], event;
	unsigned which;
	int fd, kq;

	if ((kq = kqueue()) == -1 ||
	    service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1)
		return (-1);
	for (which = 0; which < SYSEXT_ENDPOINTS; which++) {
		if (service_provider_expose(provider, names[which],
		    &listeners[which]) == -1)
			return (-1);
		if ((fd = service_listener_fd(listeners[which])) == -1)
			return (-1);
		EV_SET(&changes[which], fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0,
		    0, (void *)(uintptr_t)which);
	}
	if (kevent(kq, changes, SYSEXT_ENDPOINTS, NULL, 0, NULL) == -1)
		return (-1);
	/*
	 * Anti-tamper the process before it holds the SYS_GATE_KLDLOAD token -- the
	 * highest-value token in the fleet (module load == kernel code execution).
	 * SERVICE_PROTECT_EXTERNAL blocks ptrace/ktrace/debug of this daemon by
	 * another same-uid process, which could otherwise drive it to load a module
	 * or read the held token fd.  Every other token/privilege-holding provider
	 * (BSDTime, BSDSysctl, ...) does this; this daemon holds a strictly more
	 * dangerous token, so it must too.
	 */
	if (service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL) == -1)
		return (-1);
	/*
	 * Dup the delivered kldload/kldunload token before entering capmode;
	 * fail-soft if none was delivered (loads then attempt the raw syscall).
	 */
	if (service_system_token_dup(&sysext_kld_token) == -1) {
		syslog(LOG_WARNING, "no kldload capability; module load/unload "
		    "will attempt the raw syscall: %m");
		sysext_kld_token = -1;
	}
	if (service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		return (-1);

	/*
	 * Container model: reconcile the modules loaded on bundles' behalf
	 * against the installed-or-running bundles (reclaim.c).  Soft: without
	 * the delivered roots there is no reclaim, and loads proceed as before.
	 */
	sysext_reclaim_start(sysext_owners_fd);

	for (;;) {
		struct sysext_conn *c;
		pthread_t tid;
		int error;

		if (kevent(kq, NULL, 0, &event, 1, NULL) == -1) {
			if (errno == EINTR)
				continue;
			syslog(LOG_ERR, "accept queue: %m");
			return (-1);
		}
		which = (unsigned)(uintptr_t)event.udata;
		if (which >= SYSEXT_ENDPOINTS)
			continue;
		memset(&id, 0, sizeof(id));
		id.size = sizeof(id);
		if (service_listener_accept(listeners[which], &id, &fd) == -1) {
			error = errno;
			/* A clean quiesce is the only reason to leave the loop. */
			if (service_provider_quiescing(provider) == 1) {
				int qst = service_provider_quiesce_complete(
				    provider, 0);
				return (qst == 0 ? 0 : 1);
			}
			/*
			 * Otherwise never take the privileged kldload broker down
			 * on a transient accept error (EINTR/EMFILE/...).  Log and
			 * keep serving; back off on fd exhaustion so the loop does
			 * not spin.
			 */
			BSDEXTENSION_TRACE_ACCEPT_RETRY(error);
			if (error == EMFILE || error == ENFILE)
				(void)usleep(100000);
			if (error != EINTR)
				syslog(LOG_ERR, "accept: %s", strerror(error));
			continue;
		}
		/*
		 * Serve each client on its own THREAD, not a pdfork worker: the
		 * delivered SYS_GATE_KLDLOAD token is close-on-fork, but threads
		 * share it, so a born-in-capmode broker can serve concurrent,
		 * long-lived consumer connections (service_ensure_extension caches
		 * a persistent session) without head-of-line blocking.  The shared
		 * allow-list policy is already concurrency-safe (a robust mutex +
		 * double-buffered slots); the per-label check in sysext_request
		 * stays the access boundary.
		 */
		if (atomic_load_explicit(&sysext_nthreads,
		    memory_order_relaxed) >= SYSEXT_MAX_CLIENTS) {
			BSDEXTENSION_TRACE_WORKER_REJECT(1, ENOSPC);
			syslog(LOG_WARNING, "client from %s refused: %u sessions "
			    "already active", id.client_label, SYSEXT_MAX_CLIENTS);
			(void)close(fd);
			continue;
		}
		/*
		 * The listener and the endpoint switchboard resolved must agree; a
		 * disagreement is a routing fault and never widens a status
		 * session to the full protocol.
		 */
		if (strcmp(id.service_name, names[which]) != 0) {
			syslog(LOG_ERR, "client from %s refused: endpoint %.64s "
			    "arrived on the %s listener", id.client_label,
			    id.service_name, names[which]);
			(void)close(fd);
			continue;
		}
		c = malloc(sizeof(*c));
		if (c == NULL) {
			BSDEXTENSION_TRACE_WORKER_REJECT(2, errno);
			syslog(LOG_WARNING, "client alloc: %m");
			(void)close(fd);
			continue;
		}
		c->fd = fd;
		(void)strlcpy(c->label, id.client_label, sizeof(c->label));
		(void)strlcpy(c->container, id.container, sizeof(c->container));
		c->rights = id.rights;
		c->kind = (enum sysext_endpoint)which;
		c->nonce = id.client_nonce;
		/*
		 * Count the thread before creating it, so a burst of accepts cannot
		 * race past the cap; undo on failure.  The accept loop is the only
		 * incrementer (single-threaded), workers only decrement.
		 */
		(void)atomic_fetch_add_explicit(&sysext_nthreads, 1,
		    memory_order_relaxed);
		error = pthread_create(&tid, NULL, sysext_client_thread, c);
		if (error != 0) {
			(void)atomic_fetch_sub_explicit(&sysext_nthreads, 1,
			    memory_order_relaxed);
			BSDEXTENSION_TRACE_WORKER_REJECT(3, error);
			syslog(LOG_ERR, "pthread_create: %s", strerror(error));
			(void)close(fd);
			free(c);
			continue;
		}
		(void)pthread_detach(tid);
	}
}

int
main(int argc, char **argv)
{
	struct sysext_config sysext_conf;
	const char *conf = SYSEXT_DEFAULT_CONF;
	bool conf_from_arg = false;
	int ch, kerror = 0;

	while ((ch = getopt(argc, argv, "c:")) != -1) {
		switch (ch) {
		case 'c':
			conf = optarg;
			conf_from_arg = true;
			break;
		default:
			(void)fprintf(stderr, "usage: bsdextension [-c config]\n");
			return (1);
		}
	}
	if (argc != optind) {
		(void)fprintf(stderr, "usage: bsdextension [-c config]\n");
		return (1);
	}

	/*
	 * LOG_PERROR unconditionally: switchboard captures the copies on the
	 * launching side; there is no controlling terminal in production.
	 */
	openlog("bsdextension", LOG_PID | LOG_PERROR, LOG_DAEMON);
	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGCHLD, SIG_IGN);

	/* Before opening any capability handle (see reserve_stdio). */
	reserve_stdio();

	setproctitle("-SystemExtension");
	syslog(LOG_NOTICE, "bsdextension system-extension broker");

	/* Required startup policy; a failed reload retains the last active policy. */
	sysext_config_defaults(&sysext_conf);
	if (conf_from_arg) {
		if (sysext_config_load(&sysext_conf, conf) == -1)
			err(1, "load extension policy %s", conf);
	} else {
		int cfgfd, error, result;

		if (service_config_open(SYSEXT_CONFIG_NAME, &cfgfd) == -1)
			err(1, "open delivered extension policy");
		result = sysext_config_load_fd(&sysext_conf, cfgfd);
		error = errno;
		(void)close(cfgfd);
		if (result == -1) {
			errno = error;
			err(1, "load delivered extension policy");
		}
	}
	policy_path = conf;
	policy_delivered = !conf_from_arg;
	active_policy = sysext_policy_create(&sysext_conf);
	if (active_policy == NULL)
		err(1, "initialize shared extension policy");
	/* The directory is part of the root filesystem, available before ZFS.
	 * A missing or invalid administrator store is not an empty policy. */
	if (!conf_from_arg) {
		int dirfd;

		if (service_resource_dir(SYSEXT_POLICY_DIR, &dirfd) == -1 ||
		    sysext_policy_attach(active_policy, dirfd) == -1)
			err(1, "initialize administrator extension policy");
	}
	/*
	 * The hardware-driver class reads the running kernel's linker.hints and
	 * root loads open module files beneath its directory, found beneath the
	 * delivered /boot (kerneldir.c).  Soft: without it the class grants
	 * nothing and root loads are refused; only the allow-list applies.
	 * Opened whatever the policy says, so a policy reload can enable either.
	 * "/" (fstatat(2) only) shows which /boot an absolute path names.
	 */
	if (!conf_from_arg &&
	    (service_resource_dir(SYSEXT_ROOT_DIR, &sysext_root_dirfd) == -1 ||
	    (kerror = sysext_root_dir_limit(sysext_root_dirfd)) != 0)) {
		if (sysext_root_dirfd == -1)
			kerror = errno;
		else
			(void)close(sysext_root_dirfd);
		sysext_root_dirfd = -1;
		syslog(LOG_WARNING, "cannot use %s (%s); hardware drivers and "
		    "root loads are refused", SYSEXT_ROOT_DIR,
		    strerror(kerror));
	}
	if (!conf_from_arg &&
	    (service_resource_dir(SYSEXT_BOOT_DIR, &sysext_boot_dirfd) == -1 ||
	    (kerror = sysext_kernel_dir_open()) != 0)) {
		if (sysext_boot_dirfd == -1)
			kerror = errno;
		sysext_driver_dirfd = -1;
		syslog(LOG_WARNING, "cannot open the running kernel's module "
		    "directory beneath %s (%s); hardware drivers and root loads "
		    "are refused", SYSEXT_BOOT_DIR, strerror(kerror));
	} else if (!conf_from_arg)
		syslog(LOG_INFO, "kernel module directory %s",
		    sysext_kernel_dir);
	/* Root loads read the package database beneath this directory. */
	if (!conf_from_arg &&
	    service_resource_dir(SYSEXT_PKGDB_DIR, &sysext_pkgdb_dirfd) == -1) {
		sysext_pkgdb_dirfd = -1;
		if (sysext_conf.root_load_repository[0] != '\0')
			syslog(LOG_WARNING, "cannot open %s (%m); root loads "
			    "are refused", SYSEXT_PKGDB_DIR);
	}


	/*
	 * The module -> bundle owner map (reclaim.c), opened before serving so
	 * every client-serving thread shares it.  Its home is the switchboard-
	 * delivered per-unit container: a born-in-capmode broker has no global
	 * namespace, so it acquires the container capability by descriptor rather
	 * than opening /var/run by path.  Soft at every step: without the
	 * container or the map, loads are served exactly as before, unattributed
	 * and never reclaimed, logged once.
	 */
	{
		struct service_context *rc_ctx = NULL;
		int container_fd = -1;

		if (service_acquire(&rc_ctx) == 0) {
			if (service_capability_open(rc_ctx, "container",
			    "directory", &container_fd) == -1)
				container_fd = -1;
			service_release(rc_ctx);
		}
		sysext_owners_fd = sysext_reclaim_open(container_fd);
		if (container_fd >= 0)
			(void)close(container_fd);
	}
	if (sysext_owners_fd == -1)
		syslog(LOG_WARNING, "reclaim: cannot open reclaim state (%m); "
		    "module reclaim disabled");

	/*
	 * Serve as a socket-free service_provider: authorize the delivered
	 * kldload system token, expose system.SystemExtension, remain privileged,
	 * and dispatch each client on its own worker channel.
	 * sysext_serve() owns the provider lifecycle and does not return on
	 * success.
	 */
	if (sysext_serve() == -1)
		errx(1, "system-extension provider failed");

	return (0);
}
#endif /* !BSDEXTENSION_TESTING */
