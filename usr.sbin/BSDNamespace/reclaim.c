/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsdnamespace's reconcile client (docs/capability-container-model.md "Cleanup"):
 * a persistent jail outlives the unit that entered it -- by design, so a
 * relaunched consumer reattaches -- but it must not outlive the BUNDLE.  A
 * jail is named "wj_" + hash of the unit's resource owner, which is one-way,
 * so bsdnamespace keeps a durable owner map (jail name -> bundle) in its own storage
 * container, written when a client connects, and reconciles the wj_ jails
 * against the installed-or-running bundles with libcapreclaim: at boot at
 * once, on a timer only when seen gone twice.  A wj_ jail that no map entry
 * attributes (created before the map existed) is left alone and logged.
 */
#include <sys/param.h>
#include <sys/file.h>
#include <sys/jail.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <logcmp.h>
#include <unistd.h>

#include <jail.h>
#include <capreclaim.h>
#include <libservice.h>

#include "bsdnamespace_reclaim.h"
#include "bsdnamespace_probes.h"

#define	OWNERS_FILE	"jails.meta"
#define	OWNERS_TMP	"jails.meta.tmp"
#define	OWNERS_LOCK	"jails.lock"
#define	OWNERS_MAX	4096

struct owner_entry {
	char	jail[BSDNAMESPACE_RECLAIM_JAIL_MAX];
	char	bundle[CAPRECLAIM_OWNER_MAX];
};

struct owner_map {
	struct owner_entry	*e;
	unsigned		 n, cap;
};

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

static int
map_add(struct owner_map *m, const char *jail, const char *bundle)
{
	unsigned i;

	for (i = 0; i < m->n; i++)
		if (strcmp(m->e[i].jail, jail) == 0) {
			(void)strlcpy(m->e[i].bundle, bundle, sizeof(m->e[i].bundle));
			return (0);
		}
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
	(void)strlcpy(m->e[m->n].jail, jail, sizeof(m->e[m->n].jail));
	(void)strlcpy(m->e[m->n].bundle, bundle, sizeof(m->e[m->n].bundle));
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
 * Load the map: one "<jail> <bundle>" line per entry.  Malformed lines are
 * dropped (and gone on the next save); a missing file is an empty map.
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
		char *sp = strchr(line, ' '), *nl;

		if (sp == NULL)
			continue;
		*sp++ = '\0';
		nl = strchr(sp, '\n');
		if (nl == NULL)
			continue;	/* truncated last line */
		*nl = '\0';
		if (!safe_component(line, BSDNAMESPACE_RECLAIM_JAIL_MAX) ||
		    !safe_component(sp, CAPRECLAIM_OWNER_MAX))
			continue;
		if (map_add(m, line, sp) == -1)
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
	for (i = 0; i < m->n; i++)
		(void)fprintf(f, "%s %s\n", m->e[i].jail, m->e[i].bundle);
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
 * Record that jail `jail` belongs to `bundle` (idempotent; a re-note with a
 * different bundle -- a label reused by another bundle -- replaces it).
 * Best-effort, fail-open: a map that cannot be written costs a jail its
 * attribution, never the client its jail.
 */
int
bsdnamespace_owner_note(int dirfd, const char *jail, const char *bundle)
{
	struct owner_map m;
	int lfd, rc = -1;

	if (dirfd < 0 || !safe_component(jail, BSDNAMESPACE_RECLAIM_JAIL_MAX) ||
	    !safe_component(bundle, CAPRECLAIM_OWNER_MAX)) {
		errno = EINVAL;
		return (-1);
	}
	lfd = owners_lock(dirfd, LOCK_EX);
	if (lfd == -1)
		return (-1);
	if (owners_load(dirfd, &m) == 0 && map_add(&m, jail, bundle) == 0)
		rc = owners_save(dirfd, &m);
	map_free(&m);
	owners_unlock(lfd);
	return (rc);
}

/* The bundle of container "<bundle>/<unit>", or NULL if there is none. */
int
bsdnamespace_bundle_of(const char *container, char *out, size_t outsz)
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

/* Walk every jail in the system, calling cb(name) for each "wj_" one. */
static int
foreach_wj_jail(void (*cb)(void *, const char *), void *arg)
{
	struct jailparam params[2];
	int lastjid = 0, jid;

	for (;;) {
		char *name;

		if (jailparam_init(&params[0], "lastjid") == -1 ||
		    jailparam_import_raw(&params[0], &lastjid, sizeof(lastjid))
		    == -1 || jailparam_init(&params[1], "name") == -1)
			return (-1);
		jid = jailparam_get(params, 2, 0);
		if (jid < 0) {
			int saved = errno;

			jailparam_free(params, 2);
			if (saved == ENOENT)
				return (0);	/* end of the list */
			errno = saved;
			return (-1);
		}
		name = jailparam_export(&params[1]);
		if (name != NULL) {
			if (strncmp(name, BSDNAMESPACE_RECLAIM_PREFIX,
			    sizeof(BSDNAMESPACE_RECLAIM_PREFIX) - 1) == 0)
				cb(arg, name);
			free(name);
		}
		jailparam_free(params, 2);
		lastjid = jid;
	}
}

struct enum_ctx {
	struct owner_map	*map;
	void			(*emit)(void *, const char *);
	void			*emit_arg;
	unsigned		 unattributed;
};

static void
enum_one(void *arg, const char *jail)
{
	struct enum_ctx *ec = arg;
	unsigned i;

	for (i = 0; i < ec->map->n; i++)
		if (strcmp(ec->map->e[i].jail, jail) == 0)
			return;		/* attributed: emitted from the map */
	ec->unattributed++;
}

/*
 * capreclaim enumerate(): every bundle the map attributes a jail to.  The map
 * is the record of ownership -- an entry whose jail is already gone (jails do
 * not survive a reboot) is still "owned" until destroy() prunes it, so the
 * map never accumulates stale lines.  Existing wj_ jails the map does not
 * know are counted and logged, never reaped.
 */
static int
reclaim_enumerate(void *arg, void (*emit)(void *, const char *),
    void *emit_arg)
{
	struct bsdnamespace_reclaim *wr = arg;
	struct owner_map m;
	struct enum_ctx ec = { .map = &m, .emit = emit, .emit_arg = emit_arg };
	unsigned i;
	int lfd, rc;

	lfd = owners_lock(wr->owners_fd, LOCK_SH);
	if (lfd == -1)
		return (-1);
	rc = owners_load(wr->owners_fd, &m);
	owners_unlock(lfd);
	if (rc == -1)
		return (-1);
	for (i = 0; i < m.n; i++)
		emit(emit_arg, m.e[i].bundle);
	rc = foreach_wj_jail(enum_one, &ec);
	if (rc == 0 && ec.unattributed > 0)
		logcmp_log(LOG_INFO, "reclaim: %u wj_ jail(s) predate the owner map "
		    "and are left alone", ec.unattributed);
	map_free(&m);
	return (rc);
}

/* capreclaim destroy(): remove every jail attributed to the bundle. */
static int
reclaim_destroy(void *arg, const char *bundle)
{
	struct bsdnamespace_reclaim *wr = arg;
	struct owner_map m;
	unsigned i, removed = 0, killed = 0;
	int lfd, rc = 0, jid;

	lfd = owners_lock(wr->owners_fd, LOCK_EX);
	if (lfd == -1)
		return (-1);
	if (owners_load(wr->owners_fd, &m) == -1) {
		owners_unlock(lfd);
		return (-1);
	}
	for (i = 0; i < m.n; i++) {
		if (strcmp(m.e[i].bundle, bundle) != 0)
			continue;
		jid = jail_getid(m.e[i].jail);
		if (jid >= 0 && jail_remove(jid) == -1 && errno != ENOENT) {
			logcmp_log(LOG_WARNING, "reclaim: jail_remove %s (bundle %s): %m",
			    m.e[i].jail, bundle);
			rc = -1;
			continue;	/* keep its entry: retried next pass */
		}
		if (jid >= 0)
			killed++;
		removed++;
		memmove(&m.e[i], &m.e[i + 1], (m.n - i - 1) * sizeof(m.e[0]));
		m.n--;
		i--;
	}
	if (owners_save(wr->owners_fd, &m) == -1)
		rc = -1;
	map_free(&m);
	owners_unlock(lfd);
	if (removed > 0)
		logcmp_log(LOG_NOTICE, "reclaim: removed %u orphan jail(s) of bundle "
		    "%s%s", removed, bundle, killed == 0 ? " (already gone; map "
		    "pruned)" : "");
	return (rc);
}

static unsigned
reclaim_interval(void)
{
	const char *s = getenv("BSDNAMESPACE_RECLAIM_INTERVAL");
	char *end;
	long v;

	if (s == NULL || *s == '\0')
		return (BSDNAMESPACE_RECLAIM_INTERVAL);
	errno = 0;
	v = strtol(s, &end, 10);
	if (errno != 0 || *end != '\0' || v < BSDNAMESPACE_RECLAIM_INTERVAL_MIN ||
	    v > BSDNAMESPACE_RECLAIM_INTERVAL_MAX)
		return (BSDNAMESPACE_RECLAIM_INTERVAL);
	return ((unsigned)v);
}

/* The reconcile loop: the body of the forked child. */
static void
reclaim_loop(struct bsdnamespace_reclaim *wr)
{
	struct capreclaim r = CAPRECLAIM_INIT;
	struct capreclaim_stats stats;
	enum capreclaim_when when = CAPRECLAIM_BOOT;

	r.sources[0].fd = wr->sys_fd;  r.sources[0].strip_cap = true;
	r.sources[1].fd = wr->apps_fd; r.sources[1].strip_cap = true;
	r.sources[2].fd = wr->run_fd;  r.sources[2].strip_cap = false;
	r.nsources = 3;
	r.enumerate = reclaim_enumerate;
	r.destroy = reclaim_destroy;
	r.arg = wr;
	r.stats = &stats;
	r.status_dirfd = capreclaim_status_dir();	/* -1 if unavailable: no record */
	r.status_name = "Namespace";
	for (;;) {
		int n = capreclaim_run(&r, when);

		if (n == -1)
			logcmp_log(LOG_WARNING, "reclaim: %s pass failed: %m",
			    when == CAPRECLAIM_BOOT ? "boot" : "timer");
		else {
			BSDNAMESPACE_PROBE_RECLAIM_PASS(when == CAPRECLAIM_BOOT ? 0 : 1,
			    stats.nlive, stats.nowned, stats.norphans,
			    stats.ndestroyed, stats.nfailed);
			if (n > 0 || stats.nfailed > 0)
				logcmp_log(LOG_NOTICE, "reclaim: %s pass reaped the "
				    "jails of %d bundle%s (%u live, %u owned, "
				    "%u orphaned, %u failed)",
				    when == CAPRECLAIM_BOOT ? "boot" : "timer", n,
				    n == 1 ? "" : "s", stats.nlive, stats.nowned,
				    stats.norphans, stats.nfailed);
		}
		/* A floored pass saw nothing: the boot pass is still owed. */
		if (n >= 0 && !stats.floored)
			when = CAPRECLAIM_TIMER;
		(void)sleep(when == CAPRECLAIM_BOOT ? BSDNAMESPACE_RECLAIM_POLL :
		    reclaim_interval());
	}
}

/*
 * Open bsdnamespace's own storage (the owner map's home) and the live-set roots,
 * then fork the reconcile child.  Every failure is soft: a plane without
 * storage (installer media) or without the delivered roots simply runs
 * without jail reclaim, logged once.  Returns the owner-map directory fd for
 * the accept loop to note connections into, or -1 when reclaim is off.
 */
int
bsdnamespace_reclaim_start(void)
{
	static struct bsdnamespace_reclaim wr = { .owners_fd = -1, .sys_fd = -1,
	    .apps_fd = -1, .run_fd = -1 };
	struct service_context *ctx = NULL;
	pid_t pid;

	if (service_acquire(&ctx) == -1 ||
	    service_storage_open(ctx, "owners", &wr.owners_fd) == -1) {
		logcmp_log(LOG_WARNING, "reclaim: no storage for the jail owner map "
		    "(%m); jail reclaim disabled");
		return (-1);
	}
	if (service_resource_dir(BSDNAMESPACE_SYSTEM_DIR, &wr.sys_fd) == -1) {
		logcmp_log(LOG_WARNING, "reclaim: %s not delivered (%m); jail "
		    "reclaim disabled", BSDNAMESPACE_SYSTEM_DIR);
		return (wr.owners_fd);	/* still note owners for a later boot */
	}
	if (service_resource_dir(BSDNAMESPACE_APPS_DIR, &wr.apps_fd) == -1)
		wr.apps_fd = -1;	/* optional root: absent is skipped */
	if (service_resource_dir(BSDNAMESPACE_RUN_LIVE_DIR, &wr.run_fd) == -1)
		wr.run_fd = -1;
	pid = fork();
	if (pid == -1) {
		logcmp_log(LOG_WARNING, "reclaim: fork: %m; jail reclaim disabled");
		return (wr.owners_fd);
	}
	if (pid == 0) {
		setproctitle("-Namespace[reclaim]");
		reclaim_loop(&wr);
		_exit(0);
	}
	return (wr.owners_fd);
}

#ifdef BSDNAMESPACE_TESTING
int
bsdnamespace_test_owners_load(int dirfd, char (*jails)[BSDNAMESPACE_RECLAIM_JAIL_MAX],
    char (*bundles)[CAPRECLAIM_OWNER_MAX], unsigned max)
{
	struct owner_map m;
	unsigned i, n;

	if (owners_load(dirfd, &m) == -1)
		return (-1);
	n = m.n < max ? m.n : max;
	for (i = 0; i < n; i++) {
		(void)strlcpy(jails[i], m.e[i].jail, BSDNAMESPACE_RECLAIM_JAIL_MAX);
		(void)strlcpy(bundles[i], m.e[i].bundle, CAPRECLAIM_OWNER_MAX);
	}
	map_free(&m);
	return ((int)n);
}

int
bsdnamespace_test_destroy_entries(int dirfd, const char *bundle)
{
	struct bsdnamespace_reclaim wr = { .owners_fd = dirfd };

	/* jail_getid() finds nothing in a test: only the map changes. */
	return (reclaim_destroy(&wr, bundle));
}
#endif
