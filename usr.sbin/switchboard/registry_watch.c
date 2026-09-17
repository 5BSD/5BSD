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

struct registry_root {
	const char *const *path;	/* the (env-overridable) root */
	int		 fd;		/* watched dir fd, or -1 */
	int		 parent_fd;	/* while absent: watched parent, or -1 */
};

static struct registry_root roots[] = {
	{ &switchboard_bundle_dir_system, -1, -1 },
	{ &switchboard_bundle_dir_user, -1, -1 },
};

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
}

bool
registry_watch_owns(int fd)
{
	unsigned i;

	for (i = 0; i < nitems(roots); i++)
		if ((roots[i].fd != -1 && roots[i].fd == fd) ||
		    (roots[i].parent_fd != -1 && roots[i].parent_fd == fd))
			return (true);
	return (false);
}

void
registry_watch_event(const struct kevent *kev, int kq)
{
	struct kevent tkev;
	unsigned i;

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
	syslog(LOG_NOTICE, "registry: install folders changed; reloading");
	SWITCHBOARD_PROBE_REGISTRY_RELOAD();
	supervisor_reload(kq, NULL, 0);
	/* A root that was absent (or went away) may exist now. */
	registry_watch_arm(kq);
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
	}
	settle_armed = false;
}
