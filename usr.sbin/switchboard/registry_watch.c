/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 *
 * Install-folder watch for the container model (docs/capability-container-
 * model.md, "Lifecycle"): switchboard watches its install roots (System/ and
 * Apps/) and, when a bundle directory appears, disappears, or is replaced,
 * re-scans the registry exactly as `switchboardctl reload` would -- loading new
 * units, unloading removed ones (which is what makes their data an orphan the
 * providers' reconcile may reap), and republishing the running-bundle markers.
 *
 * The watch is an edge-triggered EVFILT_VNODE on each root directory, so a pkg
 * extraction that touches the root many times coalesces into one event per trip
 * through the loop; a short quiescence timer then runs a single reload after
 * the last change, so a bundle is scanned whole rather than mid-copy.  Only the
 * roots are watched: a bundle is added or removed as a directory entry of its
 * root, and pkg replaces a bundle by removing and re-creating its directory --
 * both root writes.  An edit deep inside an installed bundle is not an install
 * event and still needs an explicit reload, as before.  A root that does not
 * exist yet (Apps/ on a system-only image, until pkg creates it) is watched
 * for by a parent watch on its directory, so its appearance is noticed and it
 * is then watched itself.
 */
#include <sys/types.h>
#include <sys/event.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "switchboard.h"
#include "switchboard_probes.h"

/* Quiescence before a reload, so a multi-file pkg write is scanned whole. */
#define	REGISTRY_WATCH_SETTLE_S		2
/* One reserved timer ident; bit -4 is free of the other allocators' bits. */
#define	REGISTRY_WATCH_TIMER_IDENT	((uintptr_t)1 << (sizeof(uintptr_t) * 8 - 4))
/* Root events that mean "an entry may have been added, removed, or renamed". */
#define	REGISTRY_WATCH_FFLAGS \
	(NOTE_WRITE | NOTE_EXTEND | NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE)

/*
 * Bundle directories are watched one level below each root, too: a package
 * manager removes (or replaces) a bundle's FILES inside its directory, which
 * touches the bundle dir but not the root, so the root watch alone would miss
 * an uninstall that leaves an emptied "<Name>.cap" behind.  The list is
 * refreshed whenever the root is (re)armed and after every settled reload.
 */
#define	REGISTRY_WATCH_MAX_BUNDLES	256

struct registry_root {
	const char *const *path;	/* the (env-overridable) root */
	int		 fd;		/* watched dir fd, or -1 */
	int		 parent_fd;	/* while absent: watched parent, or -1 */
	int		*bundle_fds;	/* watched <Name>.cap dirs */
	unsigned	 nbundles;
};

static void
disarm_bundles(struct registry_root *r)
{
	unsigned i;

	for (i = 0; i < r->nbundles; i++)
		(void)close(r->bundle_fds[i]);	/* drops the registration */
	free(r->bundle_fds);
	r->bundle_fds = NULL;
	r->nbundles = 0;
}

/* (Re)watch every "<Name>.cap" directory entry under an armed root. */
static void
arm_bundles(int kq, struct registry_root *r)
{
	struct kevent kev;
	struct dirent *de;
	DIR *d;
	int dfd;

	disarm_bundles(r);
	if (r->fd == -1)
		return;
	dfd = dup(r->fd);
	if (dfd == -1)
		return;
	(void)lseek(dfd, 0, SEEK_SET);
	d = fdopendir(dfd);
	if (d == NULL) {
		(void)close(dfd);
		return;
	}
	rewinddir(d);
	while ((de = readdir(d)) != NULL) {
		size_t len = strlen(de->d_name);
		int fd, *grown;

		if (len <= 4 || strcmp(de->d_name + len - 4, ".cap") != 0 ||
		    r->nbundles >= REGISTRY_WATCH_MAX_BUNDLES)
			continue;
		fd = openat(r->fd, de->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (fd == -1)
			continue;
		EV_SET(&kev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
		    REGISTRY_WATCH_FFLAGS, 0, NULL);
		grown = reallocarray(r->bundle_fds, r->nbundles + 1,
		    sizeof(*grown));
		if (grown == NULL || kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
			(void)close(fd);
			continue;
		}
		r->bundle_fds = grown;
		r->bundle_fds[r->nbundles++] = fd;
	}
	(void)closedir(d);
}

static struct registry_root roots[] = {
	{ &switchboard_bundle_dir_system, -1, -1, NULL, 0 },
	{ &switchboard_bundle_dir_user, -1, -1, NULL, 0 },
};

static bool
owns_bundle_fd(const struct registry_root *r, int fd)
{
	unsigned i;

	for (i = 0; i < r->nbundles; i++)
		if (r->bundle_fds[i] == fd)
			return (true);
	return (false);
}

/* Watch the parent of an absent root so the root's creation is noticed. */
static void
arm_parent(int kq, struct registry_root *r)
{
	struct kevent kev;
	char parent[PATH_MAX];
	const char *slash;
	size_t n;
	int fd;

	if (r->parent_fd != -1)
		return;
	slash = strrchr(*r->path, '/');
	if (slash == NULL)
		return;
	n = slash == *r->path ? 1 : (size_t)(slash - *r->path);
	if (n >= sizeof(parent))
		return;
	memcpy(parent, *r->path, n);
	parent[n] = '\0';
	fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd == -1)
		return;
	EV_SET(&kev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
	    NOTE_WRITE | NOTE_EXTEND | NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE,
	    0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
		(void)close(fd);
		return;
	}
	r->parent_fd = fd;
}

static void
disarm_parent(struct registry_root *r)
{
	if (r->parent_fd != -1) {
		(void)close(r->parent_fd);	/* drops the registration */
		r->parent_fd = -1;
	}
}

static bool settle_armed;
/*
 * Settled rescans after a scan quarantined a bundle or failed outright (a
 * package still extracting into an install folder).  Bounded so a permanently
 * broken bundle costs a few cheap directory scans, not a rescan every settle.
 */
#define	REGISTRY_WATCH_RESCAN_RETRIES	8
static unsigned rescan_retries;

static unsigned
settle_seconds(void)
{
	const char *s = getenv("SWITCHBOARD_REGISTRY_WATCH_SETTLE");
	char *end;
	unsigned long v;

	if (s == NULL || *s == '\0')
		return (REGISTRY_WATCH_SETTLE_S);
	errno = 0;
	v = strtoul(s, &end, 10);
	if (errno != 0 || *end != '\0' || v == 0 || v > 60)
		return (REGISTRY_WATCH_SETTLE_S);
	return ((unsigned)v);
}

void
registry_watch_arm(int kq)
{
	struct kevent kev;
	unsigned i;

	for (i = 0; i < nitems(roots); i++) {
		struct registry_root *r = &roots[i];
		int fd;

		if (r->fd != -1)
			continue;
		fd = open(*r->path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (fd == -1) {
			arm_parent(kq, r);	/* absent root: watch for it */
			continue;
		}
		EV_SET(&kev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
		    REGISTRY_WATCH_FFLAGS, 0, NULL);
		if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
			syslog(LOG_WARNING, "registry: cannot watch %s: %m",
			    *r->path);
			(void)close(fd);
			continue;
		}
		r->fd = fd;
		disarm_parent(r);
		syslog(LOG_INFO, "registry: watching install folder %s",
		    *r->path);
	}
	/* The bundle set under an armed root may have changed: re-watch it. */
	for (i = 0; i < nitems(roots); i++)
		if (roots[i].fd != -1)
			arm_bundles(kq, &roots[i]);
}

bool
registry_watch_owns(int fd)
{
	unsigned i;

	for (i = 0; i < nitems(roots); i++)
		if ((roots[i].fd != -1 && roots[i].fd == fd) ||
		    (roots[i].parent_fd != -1 && roots[i].parent_fd == fd) ||
		    owns_bundle_fd(&roots[i], fd))
			return (true);
	return (false);
}

void
registry_watch_event(const struct kevent *kev, int kq)
{
	struct kevent tkev;
	unsigned i;

	/* A real change in a watched folder: the retry budget starts over. */
	rescan_retries = 0;
	for (i = 0; i < nitems(roots); i++) {
		struct registry_root *r = &roots[i];

		if (r->parent_fd != -1 && r->parent_fd == (int)kev->ident) {
			/* The parent changed: the absent root may exist now. */
			SWITCHBOARD_PROBE_REGISTRY_CHANGE(*r->path, kev->fflags);
			if ((kev->fflags & (NOTE_DELETE | NOTE_RENAME |
			    NOTE_REVOKE)) != 0)
				disarm_parent(r);
			registry_watch_arm(kq);
			continue;
		}
		if (owns_bundle_fd(r, (int)kev->ident)) {
			/* A bundle's contents changed (pkg delete/upgrade). */
			SWITCHBOARD_PROBE_REGISTRY_CHANGE(*r->path, kev->fflags);
			continue;		/* settle below; re-armed on reload */
		}
		if (r->fd == -1 || r->fd != (int)kev->ident)
			continue;
		SWITCHBOARD_PROBE_REGISTRY_CHANGE(*r->path, kev->fflags);
		/*
		 * The root itself went away (or was renamed/revoked): the watch
		 * is dead.  Drop it; a reload re-arms if the root reappears.
		 */
		if ((kev->fflags & (NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE)) != 0) {
			(void)close(r->fd);	/* also drops the registration */
			r->fd = -1;
			disarm_bundles(r);
			syslog(LOG_WARNING, "registry: install folder %s went "
			    "away; will re-watch when it returns", *r->path);
			arm_parent(kq, r);
		}
	}
	if (sd.shutting_down)
		return;
	/*
	 * (Re)arm the one-shot settle timer.  EV_ADD on an existing timer
	 * ident restarts it, so a burst of changes yields one reload after the
	 * last one.
	 */
	EV_SET(&tkev, REGISTRY_WATCH_TIMER_IDENT, EVFILT_TIMER,
	    EV_ADD | EV_ONESHOT, NOTE_SECONDS, settle_seconds(), NULL);
	if (kevent(kq, &tkev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_WARNING, "registry: cannot arm settle timer: %m");
		return;
	}
	settle_armed = true;
}

bool
registry_watch_is_timer(uintptr_t ident)
{
	return (ident == REGISTRY_WATCH_TIMER_IDENT);
}

void
registry_watch_timer_fire(int kq)
{
	settle_armed = false;
	if (sd.shutting_down)
		return;
	int rc;

	syslog(LOG_NOTICE, "registry: install folders changed; reloading");
	SWITCHBOARD_PROBE_REGISTRY_RELOAD();
	rc = supervisor_reload(kq, NULL, 0);
	/* A root that was absent (or went away) may exist now. */
	registry_watch_arm(kq);
	/*
	 * A package manager writes a bundle file by file after creating its
	 * directory (the only event a root or bundle-directory watch sees; the
	 * files below Units/ are two levels down), so a scan can catch it
	 * incomplete: a new bundle is quarantined, an already-registered
	 * SYSTEM bundle fails the rescan (previous registry retained).  Either
	 * way nothing else will trigger a rescan once the copy finishes, so
	 * retry a bounded number of settled times; give up after that (a truly
	 * malformed bundle stays out until the next change).
	 */
	if (rc == 0 && bundle_registry_quarantined() == 0) {
		/* A clean scan: the next change starts with a full budget. */
		rescan_retries = 0;
		return;
	}
	if (rescan_retries >= REGISTRY_WATCH_RESCAN_RETRIES) {
		/*
		 * Budget spent on a bundle that never came whole: stop, and
		 * stay stopped until a folder CHANGE (a vnode event, which
		 * resets the budget) -- exhaustion itself must not re-arm the
		 * retries, or a permanently broken bundle would cost the full
		 * budget on every later install for the life of the system.
		 */
		if (rescan_retries == REGISTRY_WATCH_RESCAN_RETRIES) {
			syslog(LOG_NOTICE, "registry: %u bundle(s) still not "
			    "admitted after %u retries; waiting for a change",
			    bundle_registry_quarantined(),
			    REGISTRY_WATCH_RESCAN_RETRIES);
			rescan_retries++;	/* log once */
		}
		return;
	}
	{
		struct kevent tkev;

		rescan_retries++;
		if (rc == -1)
			syslog(LOG_NOTICE, "registry: rescan failed; retrying "
			    "in %us (retry %u/%u)", settle_seconds(),
			    rescan_retries, REGISTRY_WATCH_RESCAN_RETRIES);
		else
			syslog(LOG_NOTICE, "registry: %u bundle(s) quarantined; "
			    "rescanning in %us (retry %u/%u)",
			    bundle_registry_quarantined(), settle_seconds(),
			    rescan_retries, REGISTRY_WATCH_RESCAN_RETRIES);
		EV_SET(&tkev, REGISTRY_WATCH_TIMER_IDENT, EVFILT_TIMER,
		    EV_ADD | EV_ONESHOT, NOTE_SECONDS, settle_seconds(), NULL);
		if (kevent(kq, &tkev, 1, NULL, 0, NULL) == 0)
			settle_armed = true;
	}
}

bool
registry_watch_pending(void)
{
	return (settle_armed);
}

/* Drop every watch (closing a descriptor drops its registration). */
void
registry_watch_fini(void)
{
	unsigned i;

	for (i = 0; i < nitems(roots); i++) {
		if (roots[i].fd != -1) {
			(void)close(roots[i].fd);
			roots[i].fd = -1;
		}
		disarm_parent(&roots[i]);
		disarm_bundles(&roots[i]);
	}
	settle_armed = false;
	rescan_retries = 0;
}
