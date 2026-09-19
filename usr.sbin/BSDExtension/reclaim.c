/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * sysextd's reconcile client (docs/capability-container-model.md "Cleanup"):
 * a kernel module loaded on a bundle's behalf stays loaded after the bundle
 * is uninstalled, with nothing attributing it.  sysextd keeps a module ->
 * bundle map, written by the worker that served the ENSURE from the stamped
 * container (never the wire), and reconciles it against the installed-or-
 * running bundles with libcapreclaim: at boot at once, on a timer only when
 * seen gone twice.  Only a module sysextd itself loaded is ever unloaded, and
 * only when no other bundle still claims it; one the kernel reports busy is
 * left loaded and retried next pass.  A module sysextd found already loaded
 * (EEXIST) is attributed for the record but never unloaded -- something else
 * put it there.
 *
 * The map lives under /var/run, not in a storage container: modules do not
 * survive a reboot (the map is stamped with the boot epoch and reset when it
 * changes), and tzfsd -- the storage provider -- needs sysextd to load zfs
 * before it can serve any claim, so a storage claim here would be a boot
 * cycle.  Every failure is soft: without the map or the delivered roots,
 * sysextd serves loads exactly as before, without reclaim, logged once.
 */
#include <sys/param.h>
#include <sys/file.h>
#include <sys/linker.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <logcmp.h>
#include <unistd.h>

#include <capreclaim.h>
#include <libservice.h>

#include "sysextd_probes.h"
#include "sysextd_reclaim.h"

#define	OWNERS_FILE	"modules.meta"
#define	OWNERS_TMP	"modules.meta.tmp"
#define	OWNERS_LOCK	"modules.lock"
#define	OWNERS_MAX	1024
#define	MODULE_MAX	64
#define	EPOCH_MAX	48

struct owner_entry {
	char	module[MODULE_MAX];
	char	bundle[CAPRECLAIM_OWNER_MAX];
	bool	ours;		/* sysextd loaded it (not found already loaded) */
};

struct owner_map {
	char			 epoch[EPOCH_MAX];
	struct owner_entry	*e;
	unsigned		 n, cap;
};

static int
real_unload(const char *module)
{
	int id;

	id = kldfind(module);
	if (id == -1)
		return (errno);
	if (kldunload(id) == -1)
		return (errno);
	return (0);
}

static int (*unloader)(const char *module) = real_unload;

/* Take the map lock (a separate file, so rewrites can rename over the map). */
static int
owners_lock(int dirfd, int op)
{
	int lfd;

	lfd = openat(dirfd, OWNERS_LOCK, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (lfd == -1)
		return (-1);
	if (flock(lfd, op) == -1) {
		int saved = errno;

		(void)close(lfd);
		errno = saved;
		return (-1);
	}
	return (lfd);
}

static void
owners_unlock(int lfd)
{
	if (lfd >= 0)
		(void)close(lfd);	/* releases the flock */
}

static bool
safe_component(const char *s, size_t max)
{
	size_t i, len = strnlen(s, max);

	if (len == 0 || len >= max)
		return (false);
	for (i = 0; i < len; i++) {
		char c = s[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
			return (false);
	}
	return (true);
}

/* The boot epoch: kern.boottime, formatted.  "" if unavailable. */
static void
boot_epoch(char *out, size_t outsz)
{
	struct timeval tv;
	size_t len = sizeof(tv);

	if (sysctlbyname("kern.boottime", &tv, &len, NULL, 0) == -1 ||
	    len != sizeof(tv)) {
		out[0] = '\0';
		return;
	}
	(void)snprintf(out, outsz, "%jd.%06ld", (intmax_t)tv.tv_sec,
	    (long)tv.tv_usec);
}

/*
 * "ours" is a property of the MODULE for this boot, not of one bundle's
 * request: once sysextd loaded it, every bundle that later found it already
 * loaded is claiming the same load, and the last of them to go must unload
 * it.  So a real load marks every entry of the module, and a later "already
 * loaded" inherits whatever the module's entries say.
 */
static int
map_add(struct owner_map *m, const char *module, const char *bundle, bool ours)
{
	unsigned i;
	bool found = false;

	for (i = 0; i < m->n; i++)
		if (strcmp(m->e[i].module, module) == 0)
			ours = ours || m->e[i].ours;
	for (i = 0; i < m->n; i++)
		if (strcmp(m->e[i].module, module) == 0) {
			m->e[i].ours = ours;
			if (strcmp(m->e[i].bundle, bundle) == 0)
				found = true;
		}
	if (found)
		return (0);
	if (m->n >= OWNERS_MAX) {
		errno = ENOSPC;
		return (-1);
	}
	if (m->n == m->cap) {
		unsigned ncap = m->cap == 0 ? 16 : m->cap * 2;
		struct owner_entry *ne = reallocarray(m->e, ncap, sizeof(*ne));

		if (ne == NULL)
			return (-1);
		m->e = ne;
		m->cap = ncap;
	}
	(void)strlcpy(m->e[m->n].module, module, sizeof(m->e[m->n].module));
	(void)strlcpy(m->e[m->n].bundle, bundle, sizeof(m->e[m->n].bundle));
	m->e[m->n].ours = ours;
	m->n++;
	return (0);
}

static void
map_free(struct owner_map *m)
{
	free(m->e);
	m->e = NULL;
	m->n = m->cap = 0;
}

/*
 * Load the map: an "epoch <boottime>" header, then one "<module> <bundle>
 * <0|1>" line per entry.  Malformed lines are dropped (and gone on the next
 * save); a missing file is an empty map with no epoch.
 */
static int
owners_load(int dirfd, struct owner_map *m)
{
	FILE *f;
	char line[256];
	int fd;

	memset(m, 0, sizeof(*m));
	fd = openat(dirfd, OWNERS_FILE, O_RDONLY | O_CLOEXEC);
	if (fd == -1)
		return (errno == ENOENT ? 0 : -1);
	f = fdopen(fd, "r");
	if (f == NULL) {
		(void)close(fd);
		return (-1);
	}
	while (fgets(line, sizeof(line), f) != NULL) {
		char *a, *b, *c, *nl;

		nl = strchr(line, '\n');
		if (nl == NULL)
			continue;	/* truncated last line */
		*nl = '\0';
		a = line;
		b = strchr(a, ' ');
		if (b == NULL)
			continue;
		*b++ = '\0';
		if (strcmp(a, "epoch") == 0) {
			if (m->epoch[0] == '\0' && strlen(b) < EPOCH_MAX)
				(void)strlcpy(m->epoch, b, sizeof(m->epoch));
			continue;
		}
		c = strchr(b, ' ');
		if (c == NULL)
			continue;
		*c++ = '\0';
		if (!safe_component(a, MODULE_MAX) ||
		    !safe_component(b, CAPRECLAIM_OWNER_MAX) ||
		    (strcmp(c, "0") != 0 && strcmp(c, "1") != 0))
			continue;
		if (map_add(m, a, b, c[0] == '1') == -1)
			break;
	}
	(void)fclose(f);
	return (0);
}

/* Save the map atomically (write a temp, fsync, rename over). */
static int
owners_save(int dirfd, const struct owner_map *m)
{
	FILE *f;
	unsigned i;
	int fd;

	fd = openat(dirfd, OWNERS_TMP, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
	    0600);
	if (fd == -1)
		return (-1);
	f = fdopen(fd, "w");
	if (f == NULL) {
		(void)close(fd);
		return (-1);
	}
	if (m->epoch[0] != '\0')
		(void)fprintf(f, "epoch %s\n", m->epoch);
	for (i = 0; i < m->n; i++)
		(void)fprintf(f, "%s %s %d\n", m->e[i].module, m->e[i].bundle,
		    m->e[i].ours ? 1 : 0);
	if (fflush(f) != 0 || fsync(fd) == -1 || fclose(f) != 0) {
		(void)unlinkat(dirfd, OWNERS_TMP, 0);
		return (-1);
	}
	if (renameat(dirfd, OWNERS_TMP, dirfd, OWNERS_FILE) == -1) {
		(void)unlinkat(dirfd, OWNERS_TMP, 0);
		return (-1);
	}
	return (0);
}

/*
 * Record that `bundle` asked for `module`; loaded_now says sysextd loaded it
 * on this request (as opposed to finding it already loaded).  Best-effort,
 * fail-open: a map that cannot be written costs a module its attribution,
 * never the client its load.
 */
int
sysext_owner_note(int dirfd, const char *module, const char *bundle,
    bool loaded_now)
{
	struct owner_map m;
	int lfd, rc = -1;

	if (dirfd < 0 || !safe_component(module, MODULE_MAX) ||
	    !safe_component(bundle, CAPRECLAIM_OWNER_MAX)) {
		errno = EINVAL;
		return (-1);
	}
	lfd = owners_lock(dirfd, LOCK_EX);
	if (lfd == -1)
		return (-1);
	if (owners_load(dirfd, &m) == 0) {
		if (m.epoch[0] == '\0')
			boot_epoch(m.epoch, sizeof(m.epoch));
		if (map_add(&m, module, bundle, loaded_now) == 0)
			rc = owners_save(dirfd, &m);
	}
	map_free(&m);
	owners_unlock(lfd);
	return (rc);
}

/* The bundle of container "<bundle>/<unit>", or -1 if there is none. */
int
sysext_bundle_of(const char *container, char *out, size_t outsz)
{
	const char *slash = strchr(container, '/');
	size_t n;

	if (container[0] == '\0' || slash == NULL || slash == container)
		return (-1);
	n = (size_t)(slash - container);
	if (n >= outsz)
		return (-1);
	memcpy(out, container, n);
	out[n] = '\0';
	return (0);
}

/*
 * capreclaim enumerate(): every bundle the map attributes a module to.  The
 * map is the record of ownership -- an entry is "owned" until destroy()
 * prunes it, so the map never accumulates stale lines.
 */
static int
reclaim_enumerate(void *arg, void (*emit)(void *, const char *),
    void *emit_arg)
{
	struct sysext_reclaim *sr = arg;
	struct owner_map m;
	unsigned i;
	int lfd, rc;

	lfd = owners_lock(sr->owners_fd, LOCK_SH);
	if (lfd == -1)
		return (-1);
	rc = owners_load(sr->owners_fd, &m);
	owners_unlock(lfd);
	if (rc == -1)
		return (-1);
	for (i = 0; i < m.n; i++)
		emit(emit_arg, m.e[i].bundle);
	map_free(&m);
	return (0);
}

/* True iff some entry of ANOTHER bundle names the module. */
static bool
claimed_elsewhere(const struct owner_map *m, const char *module,
    const char *bundle)
{
	unsigned i;

	for (i = 0; i < m->n; i++)
		if (strcmp(m->e[i].module, module) == 0 &&
		    strcmp(m->e[i].bundle, bundle) != 0)
			return (true);
	return (false);
}

/*
 * capreclaim destroy(): drop every attribution of the bundle, unloading a
 * module only when sysextd loaded it and no other bundle still claims it.  A
 * busy module keeps its entry (and the pass reports a failure) so the next
 * pass retries once its user is gone.
 */
static int
reclaim_destroy(void *arg, const char *bundle)
{
	struct sysext_reclaim *sr = arg;
	struct owner_map m;
	unsigned i, unloaded = 0, pruned = 0;
	int lfd, rc = 0;

	lfd = owners_lock(sr->owners_fd, LOCK_EX);
	if (lfd == -1)
		return (-1);
	if (owners_load(sr->owners_fd, &m) == -1) {
		owners_unlock(lfd);
		return (-1);
	}
	for (i = 0; i < m.n; i++) {
		struct owner_entry *e = &m.e[i];
		int error;

		if (strcmp(e->bundle, bundle) != 0)
			continue;
		if (claimed_elsewhere(&m, e->module, bundle)) {
			logcmp_log(LOG_NOTICE, "reclaim: %s (bundle %s): still claimed "
			    "by another bundle; attribution dropped", e->module,
			    bundle);
		} else if (!e->ours) {
			logcmp_log(LOG_NOTICE, "reclaim: %s (bundle %s): found already "
			    "loaded, not sysextd's to unload; attribution dropped",
			    e->module, bundle);
		} else {
			error = unloader(e->module);
			if (error != 0 && error != ENOENT) {
				logcmp_log(LOG_WARNING, "reclaim: %s (bundle %s): %s; "
				    "left loaded, retried next pass", e->module,
				    bundle, strerror(error));
				rc = -1;
				continue;	/* keep its entry */
			}
			if (error == 0)
				unloaded++;
		}
		pruned++;
		memmove(&m.e[i], &m.e[i + 1], (m.n - i - 1) * sizeof(m.e[0]));
		m.n--;
		i--;
	}
	if (owners_save(sr->owners_fd, &m) == -1)
		rc = -1;
	map_free(&m);
	owners_unlock(lfd);
	if (pruned > 0)
		logcmp_log(LOG_NOTICE, "reclaim: unloaded %u orphan module(s) of "
		    "bundle %s (%u attribution(s) dropped)", unloaded, bundle,
		    pruned);
	return (rc);
}

static unsigned
reclaim_interval(void)
{
	const char *s = getenv("SYSEXTD_RECLAIM_INTERVAL");
	char *end;
	long v;

	if (s == NULL || *s == '\0')
		return (SYSEXT_RECLAIM_INTERVAL);
	errno = 0;
	v = strtol(s, &end, 10);
	if (errno != 0 || *end != '\0' || v < SYSEXT_RECLAIM_INTERVAL_MIN ||
	    v > SYSEXT_RECLAIM_INTERVAL_MAX)
		return (SYSEXT_RECLAIM_INTERVAL);
	return ((unsigned)v);
}

/* The reconcile loop: the body of the forked child. */
static void
reclaim_loop(struct sysext_reclaim *sr)
{
	struct capreclaim r = CAPRECLAIM_INIT;
	struct capreclaim_stats stats;
	enum capreclaim_when when = CAPRECLAIM_BOOT;

	r.sources[0].fd = sr->sys_fd;  r.sources[0].strip_cap = true;
	r.sources[1].fd = sr->apps_fd; r.sources[1].strip_cap = true;
	r.sources[2].fd = sr->run_fd;  r.sources[2].strip_cap = false;
	r.nsources = 3;
	r.enumerate = reclaim_enumerate;
	r.destroy = reclaim_destroy;
	r.arg = sr;
	r.stats = &stats;
	r.status_dirfd = capreclaim_status_dir();	/* -1 if unavailable: no record */
	r.status_name = "SystemExtension";
	for (;;) {
		int n = capreclaim_run(&r, when);

		if (n == -1)
			logcmp_log(LOG_WARNING, "reclaim: %s pass failed: %m",
			    when == CAPRECLAIM_BOOT ? "boot" : "timer");
		else {
			SYSEXTD_PROBE_RECLAIM_PASS(when == CAPRECLAIM_BOOT ? 0 : 1,
			    stats.nlive, stats.nowned, stats.norphans,
			    stats.ndestroyed, stats.nfailed);
			if (n > 0 || stats.nfailed > 0)
				logcmp_log(LOG_NOTICE, "reclaim: %s pass reaped the "
				    "modules of %d bundle%s (%u live, %u owned, "
				    "%u orphaned, %u failed)",
				    when == CAPRECLAIM_BOOT ? "boot" : "timer", n,
				    n == 1 ? "" : "s", stats.nlive, stats.nowned,
				    stats.norphans, stats.nfailed);
		}
		/* A floored pass saw nothing: the boot pass is still owed. */
		if (n >= 0 && !stats.floored)
			when = CAPRECLAIM_TIMER;
		(void)sleep(when == CAPRECLAIM_BOOT ? SYSEXT_RECLAIM_POLL :
		    reclaim_interval());
	}
}

/*
 * Open (creating) the map's runtime directory, root-only and never followed
 * through a symlink, and reset a map stamped with a previous boot's epoch:
 * its modules are gone with that boot, and an attribution that survived would
 * unload a module the same bundle legitimately re-requested since.
 */
int
sysext_reclaim_open(void)
{
	struct owner_map m;
	struct stat sb;
	char now[EPOCH_MAX];
	int dirfd, lfd;

	if (mkdir(SYSEXT_RECLAIM_DIR, 0700) == -1 && errno != EEXIST)
		return (-1);
	dirfd = open(SYSEXT_RECLAIM_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
	    O_CLOEXEC);
	if (dirfd == -1)
		return (-1);
	if (fstat(dirfd, &sb) == -1 || sb.st_uid != 0 ||
	    (sb.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
		(void)close(dirfd);
		errno = EPERM;
		return (-1);
	}
	boot_epoch(now, sizeof(now));
	lfd = owners_lock(dirfd, LOCK_EX);
	if (lfd == -1) {
		(void)close(dirfd);
		return (-1);
	}
	if (owners_load(dirfd, &m) == 0 && strcmp(m.epoch, now) != 0) {
		if (m.n > 0)
			logcmp_log(LOG_NOTICE, "reclaim: dropping %u module attribution(s) "
			    "from a previous boot", m.n);
		map_free(&m);
		memset(&m, 0, sizeof(m));
		(void)strlcpy(m.epoch, now, sizeof(m.epoch));
		(void)owners_save(dirfd, &m);
	}
	map_free(&m);
	owners_unlock(lfd);
	return (dirfd);
}

/*
 * Open the delivered live-set roots and fork the reconcile child.  Every
 * failure is soft: without the roots sysextd still notes owners (for the
 * log) and serves loads as before.
 */
void
sysext_reclaim_start(int owners_fd)
{
	static struct sysext_reclaim sr = { .owners_fd = -1, .sys_fd = -1,
	    .apps_fd = -1, .run_fd = -1 };
	pid_t pid;

	if (owners_fd < 0)
		return;
	sr.owners_fd = owners_fd;
	if (service_resource_dir(SYSEXT_SYSTEM_DIR, &sr.sys_fd) == -1) {
		logcmp_log(LOG_WARNING, "reclaim: %s not delivered (%m); module "
		    "reclaim disabled", SYSEXT_SYSTEM_DIR);
		return;
	}
	if (service_resource_dir(SYSEXT_APPS_DIR, &sr.apps_fd) == -1)
		sr.apps_fd = -1;	/* optional root: absent is skipped */
	if (service_resource_dir(SYSEXT_RUN_LIVE_DIR, &sr.run_fd) == -1)
		sr.run_fd = -1;
	pid = fork();
	if (pid == -1) {
		logcmp_log(LOG_WARNING, "reclaim: fork: %m; module reclaim disabled");
		return;
	}
	if (pid == 0) {
		setproctitle("-SystemExtension[reclaim]");
		reclaim_loop(&sr);
		_exit(0);
	}
}

#ifdef SYSEXTD_TESTING
int
sysext_test_owners_load(int dirfd, struct sysext_test_entry *out, unsigned max)
{
	struct owner_map m;
	unsigned i, n;

	if (owners_load(dirfd, &m) == -1)
		return (-1);
	n = m.n < max ? m.n : max;
	for (i = 0; i < n; i++) {
		(void)strlcpy(out[i].module, m.e[i].module, sizeof(out[i].module));
		(void)strlcpy(out[i].bundle, m.e[i].bundle, sizeof(out[i].bundle));
		out[i].ours = m.e[i].ours;
	}
	map_free(&m);
	return ((int)n);
}

int
sysext_test_destroy(int dirfd, const char *bundle)
{
	struct sysext_reclaim sr = { .owners_fd = dirfd };

	return (reclaim_destroy(&sr, bundle));
}

struct test_enum { char (*bundles)[64]; unsigned n, max; };

static void
test_emit(void *arg, const char *bundle)
{
	struct test_enum *te = arg;

	if (te->n < te->max)
		(void)strlcpy(te->bundles[te->n], bundle, 64);
	te->n++;
}

int
sysext_test_enumerate(int dirfd, char (*bundles)[64], unsigned max)
{
	struct sysext_reclaim sr = { .owners_fd = dirfd };
	struct test_enum te = { .bundles = bundles, .max = max };

	if (reclaim_enumerate(&sr, test_emit, &te) == -1)
		return (-1);
	return ((int)te.n);
}

void
sysext_test_set_unloader(int (*fn)(const char *module))
{
	unloader = fn != NULL ? fn : real_unload;
}

/* Rewrite the map's epoch line in place (the rest of the map is kept). */
int
sysext_test_epoch_write(int dirfd, const char *epoch)
{
	struct owner_map m;
	int rc;

	if (owners_load(dirfd, &m) == -1)
		return (-1);
	(void)strlcpy(m.epoch, epoch, sizeof(m.epoch));
	rc = owners_save(dirfd, &m);
	map_free(&m);
	return (rc);
}
#endif /* SYSEXTD_TESTING */
