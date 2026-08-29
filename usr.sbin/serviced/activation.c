/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Timer, path, and socket activation sources for serviced (Phase 5 timer/path,
 * plan §13; Phase 4 socket).
 *
 * These are demand sources, not dependency units and not ordering.  A source
 * names one unit in its own bundle and creates demand for that unit when it
 * fires, exactly as a lookup would: if the unit is stopped it is launched
 * (svc_launch_or_await); if it is already starting or running the fire
 * coalesces.  Sources outlive the unit's own start/stop cycles — the timer
 * keeps firing and the vnode watch keeps reporting while the activated unit is
 * stopped, so the next interval or change re-activates it.
 *
 *   activation { timer = { interval = 30; } }   monotonic seconds
 *   activation { path  = { path = "/some/dir"; } } kqueue vnode events
 *
 * Timer idents carry ACTIVATION_TIMER_BIT so the main event loop routes them
 * here; they are matched to their unit by value, immune to services[]
 * compaction.  Path watches use EVFILT_VNODE whose ident is the watched
 * descriptor, so they are routed and matched by fd.  Path events are hints:
 * bursts coalesce (EV_CLEAR), and a delete/rename triggers a re-open so an
 * atomic replacement keeps being watched, or the watch is dropped and logged.
 *
 *   activation { socket = { name = "l"; listen = "tcp:*:80"; } }
 *
 * A socket source is the manager-OWNED listener: serviced binds and listen(2)s
 * the socket itself (never through the network broker — that would be a boot
 * chicken-and-egg, since the broker is itself an on-demand service) and holds
 * it open.  The first inbound connection makes the listen fd readable, which is
 * the demand that launches the unit; the listener is delivered to the provider
 * by logical name and, because serviced keeps its own copy open across the
 * unit's start/stop cycles, a queued connection is never dropped on restart.
 * Listen fds are routed and matched by fd like path watches, and their
 * EVFILT_READ is deliberately level-triggered (NOT EV_CLEAR): a slow provider
 * that has not yet accept(2)ed keeps the level asserted, so repeated demand
 * coalesces until the backlog drains.  All socket-creation policy is isolated
 * in listener_create() so it can later be swapped to a broker mint.
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <netinet/in.h>

#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <libcapbundle.h>

#include "serviced.h"
#include "serviced_audit.h"
#include "serviced_probes.h"
#include "activation_calendar.h"

/*
 * Timer-ident domain for periodic activation timers.  The high bits of a
 * uintptr_t tag which subsystem owns an EVFILT_TIMER ident (see the matching
 * STOP_TIMER_BIT / ON_DEMAND_TIMER_BIT / IDLE_TIMER_BIT / SVC_LAUNCH_TIMER_BIT
 * allocators, at bits width-1..width-4); bit (width-5) is reserved here.
 */
#define	ACTIVATION_TIMER_BIT	((uintptr_t)1 << (sizeof(uintptr_t) * 8 - 5))
static uintptr_t activation_timer_next = ACTIVATION_TIMER_BIT | 1;

/* EVFILT_FS is a distinct filter, so its idents live in their own space. */
static uintptr_t activation_mount_next = 1;

/* Vnode events that mean "the watched path may have changed". */
#define	ACTIVATION_VNODE_FFLAGS	\
	(NOTE_WRITE | NOTE_DELETE | NOTE_RENAME | NOTE_EXTEND | NOTE_ATTRIB)

/*
 * Locate the unit that owns a periodic activation timer ident.  Matching by
 * value (not by a udata pointer) survives services[] compaction moving the
 * owning svc_runtime.
 */
static struct svc_runtime *
timer_owner(uintptr_t ident)
{
	unsigned i;

	for (i = 0; i < sd.nservices; i++)
		if (sd.services[i].activation_timer_ident == ident)
			return (&sd.services[i]);
	return (NULL);
}

/*
 * Locate the unit watching a given vnode descriptor.  The EVFILT_VNODE ident
 * is the descriptor, which is unique among open fds and moves with the struct
 * across compaction, so a scan by fd is stable.
 */
static struct svc_runtime *
path_owner(int fd)
{
	unsigned i;

	for (i = 0; i < sd.nservices; i++)
		if (sd.services[i].activation_path_fd == fd)
			return (&sd.services[i]);
	return (NULL);
}

/* Locate the unit watching a given queue-directory descriptor. */
static struct svc_runtime *
queue_owner(int fd)
{
	unsigned i;

	for (i = 0; i < sd.nservices; i++)
		if (sd.services[i].activation_queue_fd == fd)
			return (&sd.services[i]);
	return (NULL);
}

/* Locate the unit that owns a given EVFILT_FS (mount) ident. */
static struct svc_runtime *
mount_owner(uintptr_t ident)
{
	unsigned i;

	for (i = 0; i < sd.nservices; i++)
		if (sd.services[i].activation_mount_ident == ident)
			return (&sd.services[i]);
	return (NULL);
}

/*
 * True if a directory holds any entry other than "." and "..".  Used to gate
 * queue-directory activation on there actually being work to drain.  Operates
 * on a dup of the watch fd so the caller's descriptor position is untouched.
 */
static bool
dir_nonempty(int dirfd)
{
	int fd;
	DIR *dir;
	struct dirent *de;
	bool any = false;

	fd = dup(dirfd);
	if (fd == -1)
		return (true);	/* fail toward activating rather than stalling */
	if (lseek(fd, 0, SEEK_SET) == -1) {
		/* not seekable is unexpected for a dir; fall through to opendir */
	}
	dir = fdopendir(fd);
	if (dir == NULL) {
		(void)close(fd);
		return (true);
	}
	while ((de = readdir(dir)) != NULL) {
		if (de->d_name[0] == '.' && (de->d_name[1] == '\0' ||
		    (de->d_name[1] == '.' && de->d_name[2] == '\0')))
			continue;
		any = true;
		break;
	}
	closedir(dir);
	return (any);
}

/*
 * Locate the unit that owns a given socket-activation listen descriptor.  Like
 * path watches, the EVFILT_READ ident is the descriptor, unique among open fds
 * and stable across services[] compaction, so a scan by fd is safe.  The listen
 * fd set is disjoint from every channel/control fd, so matching by fd here can
 * never mistake a listener for another EVFILT_READ user.
 */
static struct svc_runtime *
listen_owner(int fd)
{
	unsigned i, j;

	if (fd < 0)
		return (NULL);
	for (i = 0; i < sd.nservices; i++)
		for (j = 0; j < sd.services[i].nactivation_listen; j++)
			if (sd.services[i].activation_listen_fds[j] == fd)
				return (&sd.services[i]);
	return (NULL);
}

/*
 * Create demand for a unit from an activation source.  Identical in effect to
 * a lookup arriving for the unit: a stopped (or completed-oneshot) unit is
 * launched; a unit that is already starting, running, or stopping coalesces so
 * repeated fires never stack duplicate launches.
 */
static void
activation_create_demand(struct svc_runtime *svc, const char *source, int kq)
{

	if (svc->state != SVC_STATE_STOPPED && svc->state != SVC_STATE_DONE) {
		/* A previous activation is still in flight; coalesce. */
		SERVICED_PROBE_ON_DEMAND_COALESCE(svc->manifest.label);
		return;
	}
	svc->state = SVC_STATE_STOPPED;
	strlcpy(svc->launched_by, source, sizeof(svc->launched_by));
	clock_gettime(CLOCK_MONOTONIC, &svc->launch_time);
	if (svc_launch_or_await(svc, kq) == -1) {
		syslog(LOG_ERR, "activation: %s launch of '%s' failed: %m",
		    source, svc->manifest.label);
		return;
	}
	SERVICED_PROBE_ON_DEMAND_LAUNCH(svc->manifest.label, source);
	serviced_audit(AUE_SERVICED_ONDEMAND, getuid(), 0,
	    "activation launch svc=%s source=%s", svc->manifest.label, source);
	syslog(LOG_INFO, "activation: %s activated '%s'", source,
	    svc->manifest.label);
}

/*
 * Open and register the vnode watch for a unit's activation path.  The path
 * may be a directory or a file; O_RDONLY is sufficient for kqueue to observe
 * it and avoids demanding write authority over an operand we only watch.  On
 * failure the watch is simply not armed (the timer source, if any, is
 * independent), and a diagnostic is logged.
 */
static void
arm_path(struct svc_runtime *svc, int kq)
{
	struct kevent kev;
	int fd;

	if (svc->manifest.activation_path[0] == '\0' ||
	    svc->activation_path_fd >= 0)
		return;

	fd = open(svc->manifest.activation_path, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		syslog(LOG_WARNING, "activation: %s: cannot watch path %s: %m",
		    svc->manifest.label, svc->manifest.activation_path);
		return;
	}
	/*
	 * EV_CLEAR makes the watch edge-triggered: a burst of writes between
	 * two trips through the event loop is reported once, which is exactly
	 * the coalescing the plan requires for path hints.
	 */
	EV_SET(&kev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
	    ACTIVATION_VNODE_FFLAGS, 0, svc);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "activation: %s: kevent vnode for %s: %m",
		    svc->manifest.label, svc->manifest.activation_path);
		(void)close(fd);
		return;
	}
	svc->activation_path_fd = fd;
	syslog(LOG_INFO, "activation: %s watching path %s", svc->manifest.label,
	    svc->manifest.activation_path);
}

/*
 * Create the manager-owned listening socket for one socket activation source.
 * serviced binds and listen(2)s directly — deliberately NOT through the network
 * broker, which is itself an on-demand service and cannot be required to mint
 * serviced's own boot listeners without a chicken-and-egg hazard.  All socket
 * creation policy lives here in one place so a future policy could swap this
 * for a broker mint without touching any caller.  Returns the listen fd, or -1
 * with errno set; the caller logs and skips a failed listener (never fatal).
 */
static int
listener_create(const struct svc_activation_socket *s)
{
	struct sockaddr_storage ss;
	socklen_t slen;
	int fd, on, saved;

	memset(&ss, 0, sizeof(ss));
	switch (s->domain) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;

		sin->sin_family = AF_INET;
		sin->sin_port = htons(s->port);
		memcpy(&sin->sin_addr, s->addr, sizeof(sin->sin_addr));
		slen = sizeof(*sin);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;

		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(s->port);
		memcpy(&sin6->sin6_addr, s->addr, sizeof(sin6->sin6_addr));
		slen = sizeof(*sin6);
		break;
	}
	case AF_UNIX: {
		struct sockaddr_un *sun = (struct sockaddr_un *)&ss;

		sun->sun_family = AF_UNIX;
		if (strlcpy(sun->sun_path, s->unixpath, sizeof(sun->sun_path)) >=
		    sizeof(sun->sun_path)) {
			errno = ENAMETOOLONG;
			return (-1);
		}
		slen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
		    strlen(sun->sun_path) + 1);
		break;
	}
	default:
		errno = EAFNOSUPPORT;
		return (-1);
	}

	fd = socket(s->domain, s->socktype | SOCK_CLOEXEC, 0);
	if (fd == -1)
		return (-1);
	on = 1;
	(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	/*
	 * A stale AF_UNIX node from a previous boot would make bind(2) fail
	 * EADDRINUSE; unlink it first.  This is safe because serviced owns the
	 * path (it is the sole binder of this activation socket).
	 */
	if (s->domain == AF_UNIX)
		(void)unlink(s->unixpath);
	if (bind(fd, (struct sockaddr *)&ss, slen) == -1) {
		saved = errno;
		(void)close(fd);
		errno = saved;
		return (-1);
	}
	if (s->socktype == SOCK_STREAM && listen(fd, s->backlog) == -1) {
		saved = errno;
		(void)close(fd);
		errno = saved;
		return (-1);
	}
	return (fd);
}

/*
 * Arm a queue-directory source (launchd QueueDirectories): watch the directory
 * with the same edge-triggered EVFILT_VNODE as arm_path.  A vnode event gates
 * demand on the directory actually being non-empty, so the unit runs only when
 * there is work to drain.  If the directory already holds work when serviced
 * starts, demand it immediately.  Idempotent; failures are logged and skipped.
 */
static void
arm_queue(struct svc_runtime *svc, int kq)
{
	struct kevent kev;
	int fd;

	if (svc->manifest.queue_directory[0] == '\0' ||
	    svc->activation_queue_fd >= 0)
		return;

	fd = open(svc->manifest.queue_directory,
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd == -1) {
		syslog(LOG_WARNING, "activation: %s: cannot watch queue %s: %m",
		    svc->manifest.label, svc->manifest.queue_directory);
		return;
	}
	EV_SET(&kev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
	    ACTIVATION_VNODE_FFLAGS, 0, svc);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "activation: %s: kevent queue for %s: %m",
		    svc->manifest.label, svc->manifest.queue_directory);
		(void)close(fd);
		return;
	}
	svc->activation_queue_fd = fd;
	syslog(LOG_INFO, "activation: %s watching queue %s", svc->manifest.label,
	    svc->manifest.queue_directory);
	/* Backlog present at startup: drain it now. */
	if (dir_nonempty(fd))
		activation_create_demand(svc, "queue", kq);
}

/*
 * Arm a mount source (launchd StartOnMount): a single EVFILT_FS registration
 * whose events fire on any filesystem mount/unmount.  Edge-triggered; on a
 * mount the unit is demanded.  Idempotent.
 */
static void
arm_mount(struct svc_runtime *svc, int kq)
{
	struct kevent kev;
	uintptr_t ident;

	if (!svc->manifest.activation_on_mount ||
	    svc->activation_mount_ident != 0)
		return;

	ident = activation_mount_next++;
	/*
	 * filt_fsevent only reports events whose hint intersects the registered
	 * fflags, so VQ_MOUNT must be requested explicitly — a zero mask would
	 * make the knote never fire.  We watch mounts, not unmounts.
	 */
	EV_SET(&kev, ident, EVFILT_FS, EV_ADD | EV_CLEAR, VQ_MOUNT, 0, svc);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "activation: %s: kevent EVFILT_FS: %m",
		    svc->manifest.label);
		return;
	}
	svc->activation_mount_ident = ident;
	syslog(LOG_INFO, "activation: %s watching for filesystem mounts",
	    svc->manifest.label);
}

/*
 * Arm a unit's declared socket activation listeners.  Each not-yet-armed
 * listener is created and registered with a level-triggered EVFILT_READ so a
 * slow provider keeps demand asserted (see the file banner).  A listener that
 * fails to bind (EADDRINUSE, EMFILE, ...) is logged and skipped — mirroring
 * arm_path(), it never aborts serviced and never blocks the other listeners or
 * units from arming.  Idempotent: an already-open listen fd is left in place.
 */
static void
arm_sockets(struct svc_runtime *svc, int kq)
{
	struct kevent kev;
	unsigned i;
	int fd;

	if (svc->manifest.nactivation_sockets == 0)
		return;
	svc->nactivation_listen = svc->manifest.nactivation_sockets;
	for (i = 0; i < svc->manifest.nactivation_sockets; i++) {
		const struct svc_activation_socket *s =
		    &svc->manifest.activation_sockets[i];

		if (svc->activation_listen_fds[i] >= 0)
			continue;	/* already armed */
		fd = listener_create(s);
		if (fd == -1) {
			syslog(LOG_WARNING,
			    "activation: %s: cannot bind socket '%s': %m",
			    svc->manifest.label, s->name);
			continue;
		}
		/*
		 * Level-triggered (no EV_CLEAR): while the provider has not yet
		 * accept(2)ed, the listener stays readable and demand coalesces
		 * via activation_create_demand until the backlog drains.
		 */
		EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, svc);
		if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
			syslog(LOG_ERR,
			    "activation: %s: kevent listener '%s': %m",
			    svc->manifest.label, s->name);
			(void)close(fd);
			continue;
		}
		svc->activation_listen_fds[i] = fd;
		SERVICED_PROBE_TIMEOUT_ARM(svc->manifest.label, "socket", 0);
		syslog(LOG_INFO, "activation: %s listening for socket '%s'",
		    svc->manifest.label, s->name);
	}
}

/*
 * Persistent-schedule last-run marker.  A calendar unit with persistent=true
 * records each fire under a per-unit file; on the next arm, if a scheduled
 * occurrence elapsed since that run (the machine was down when it was due), the
 * unit is demanded once immediately — anacron-style catch-up.
 */
#define	CALENDAR_STATE_DIR	"/var/db/serviced/calendar"

static void
calendar_marker_path(const char *label, char *buf, size_t len)
{
	size_t i;

	(void)snprintf(buf, len, "%s/", CALENDAR_STATE_DIR);
	for (i = strlen(buf); *label != '\0' && i + 1 < len; label++)
		buf[i++] = (*label == '/' || *label == '.') ? '_' : *label;
	buf[i] = '\0';
}

static time_t
calendar_last_run(const char *label)
{
	char path[PATH_MAX];
	FILE *f;
	long long v = 0;

	calendar_marker_path(label, path, sizeof(path));
	if ((f = fopen(path, "r")) == NULL)
		return (0);
	if (fscanf(f, "%lld", &v) != 1)
		v = 0;
	(void)fclose(f);
	return ((time_t)v);
}

static void
calendar_record_run(const char *label, time_t when)
{
	char path[PATH_MAX];
	FILE *f;

	(void)mkdir(CALENDAR_STATE_DIR, 0700);
	calendar_marker_path(label, path, sizeof(path));
	if ((f = fopen(path, "w")) == NULL)
		return;
	(void)fprintf(f, "%lld\n", (long long)when);
	(void)fclose(f);
}

/*
 * Arm (or re-arm) a unit's calendar activation as a one-shot EVFILT_TIMER for
 * the next wall-clock match.  Called at startup and again from the fire handler
 * — a one-shot timer auto-deletes on fire, so each occurrence arms the next.
 */
static void
arm_calendar(struct svc_runtime *svc, int kq)
{
	struct kevent kev;
	time_t now, next;
	long delay;
	uintptr_t ident;

	if (!svc->manifest.has_calendar || svc->activation_timer_ident != 0)
		return;
	now = time(NULL);

	/*
	 * Anacron-style catch-up: if a scheduled occurrence elapsed since the
	 * last recorded run, fire once now.  A just-fired re-arm sees last_run ==
	 * the occurrence it recorded, so it never double-fires.
	 */
	if (svc->manifest.calendar_persistent) {
		time_t prev = calendar_prev(&svc->manifest.calendar, now);

		if (prev != (time_t)-1 &&
		    prev > calendar_last_run(svc->manifest.label)) {
			syslog(LOG_INFO, "activation: %s persistent catch-up",
			    svc->manifest.label);
			calendar_record_run(svc->manifest.label, now);
			activation_create_demand(svc, "catchup", kq);
		}
	}
	next = calendar_next(&svc->manifest.calendar, now);
	if (next == (time_t)-1) {
		syslog(LOG_ERR, "activation: %s: unsatisfiable schedule",
		    svc->manifest.label);
		return;
	}
	delay = (long)(next - now);
	if (delay < 1)
		delay = 1;	/* never arm a zero/negative one-shot */
	ident = activation_timer_next++;
	EV_SET(&kev, ident, EVFILT_TIMER, EV_ADD | EV_ONESHOT, NOTE_SECONDS,
	    delay, svc);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "activation: %s: kevent calendar: %m",
		    svc->manifest.label);
		return;
	}
	svc->activation_timer_ident = ident;
	SERVICED_PROBE_TIMEOUT_ARM(svc->manifest.label, "calendar", delay);
	syslog(LOG_INFO, "activation: %s scheduled, next fire in %lds",
	    svc->manifest.label, delay);
}

/*
 * Arm a unit's declared activation sources.  Idempotent: an already-armed
 * source is left in place, so it is safe to call at startup and again on
 * reload without stacking duplicate timers or watches.
 */
void
activation_source_arm(struct svc_runtime *svc, int kq)
{
	struct kevent kev;

	if (svc == NULL)
		return;

	if (svc->manifest.timer_interval_sec > 0 &&
	    svc->activation_timer_ident == 0) {
		uintptr_t ident;

		ident = activation_timer_next++;
		/*
		 * A periodic timer (no EV_ONESHOT) re-arms itself in the kernel,
		 * so it keeps firing every interval while the unit is stopped
		 * with no per-fire re-registration.
		 */
		EV_SET(&kev, ident, EVFILT_TIMER, EV_ADD, NOTE_SECONDS,
		    svc->manifest.timer_interval_sec, svc);
		if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
			syslog(LOG_ERR, "activation: %s: kevent timer: %m",
			    svc->manifest.label);
		else {
			svc->activation_timer_ident = ident;
			SERVICED_PROBE_TIMEOUT_ARM(svc->manifest.label, "timer",
			    svc->manifest.timer_interval_sec);
			syslog(LOG_INFO,
			    "activation: %s armed timer every %us",
			    svc->manifest.label,
			    svc->manifest.timer_interval_sec);
		}
	}

	arm_calendar(svc, kq);
	arm_path(svc, kq);
	arm_queue(svc, kq);
	arm_mount(svc, kq);
	arm_sockets(svc, kq);
}

/*
 * Tear a unit's activation sources down.  Called from svc_remove() (the single
 * chokepoint for unit removal on reload and shutdown), so a removed unit never
 * leaves a live timer or vnode watch behind.
 */
void
activation_source_teardown(struct svc_runtime *svc, int kq)
{
	struct kevent kev;

	if (svc == NULL)
		return;

	if (svc->activation_timer_ident != 0) {
		EV_SET(&kev, svc->activation_timer_ident, EVFILT_TIMER,
		    EV_DELETE, 0, 0, NULL);
		(void)kevent(kq, &kev, 1, NULL, 0, NULL);
		svc->activation_timer_ident = 0;
	}
	if (svc->activation_path_fd >= 0) {
		/* Closing the descriptor removes its EVFILT_VNODE registration. */
		(void)close(svc->activation_path_fd);
		svc->activation_path_fd = -1;
	}
	if (svc->activation_queue_fd >= 0) {
		(void)close(svc->activation_queue_fd);
		svc->activation_queue_fd = -1;
	}
	if (svc->activation_mount_ident != 0) {
		EV_SET(&kev, svc->activation_mount_ident, EVFILT_FS, EV_DELETE,
		    0, 0, NULL);
		(void)kevent(kq, &kev, 1, NULL, 0, NULL);
		svc->activation_mount_ident = 0;
	}
	/*
	 * Close the manager-owned listen fds ONLY here (unit removal).  They are
	 * deliberately untouched by svc_close_fds() on provider stop/restart so a
	 * queued connection survives across restarts; only removing the unit
	 * retires the listener.
	 */
	while (svc->nactivation_listen > 0) {
		unsigned i = --svc->nactivation_listen;
		int fd = svc->activation_listen_fds[i];

		if (fd < 0)
			continue;
		EV_SET(&kev, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
		(void)kevent(kq, &kev, 1, NULL, 0, NULL);
		(void)close(fd);
		svc->activation_listen_fds[i] = -1;
		if (svc->manifest.activation_sockets[i].domain == AF_UNIX)
			(void)unlink(svc->manifest.activation_sockets[i].unixpath);
	}
}

bool
activation_timer_owns(uintptr_t ident)
{

	return ((ident & ACTIVATION_TIMER_BIT) != 0);
}

/*
 * A periodic activation timer fired: create demand for its unit.  The kernel
 * has already re-armed the periodic timer, so nothing is re-registered here.
 */
void
activation_timer_fire(uintptr_t ident, int kq)
{
	struct svc_runtime *svc;

	svc = timer_owner(ident);
	if (svc == NULL)
		return;		/* stale ident for an already-removed unit */
	activation_create_demand(svc,
	    svc->manifest.has_calendar ? "calendar" : "timer", kq);
	if (svc->manifest.has_calendar) {
		/*
		 * A calendar timer is one-shot: the kernel deleted it on fire, so
		 * clear the recorded ident and arm the following occurrence.  Record
		 * the run first so persistent catch-up on the re-arm sees it.
		 */
		if (svc->manifest.calendar_persistent)
			calendar_record_run(svc->manifest.label, time(NULL));
		svc->activation_timer_ident = 0;
		arm_calendar(svc, kq);
	}
}

/*
 * An EVFILT_FS event fired: a filesystem was mounted or unmounted.  Create
 * demand for the unit that armed this ident.  The watch is edge-triggered and
 * kernel-persistent (not one-shot), so nothing is re-registered here.
 */
void
activation_mount_event(struct kevent *kev, int kq)
{
	struct svc_runtime *svc;

	svc = mount_owner(kev->ident);
	if (svc == NULL)
		return;		/* stale ident for an already-removed unit */
	activation_create_demand(svc, "mount", kq);
}

/*
 * An EVFILT_VNODE event fired on a watched path.  Events are hints, so we
 * create demand on any change and, when the watched name is deleted or
 * renamed out from under us, attempt to re-open the path (handling atomic
 * replace) or drop the watch and log.
 */
void
activation_path_event(struct kevent *kev, int kq)
{
	struct svc_runtime *svc;
	int fd;

	fd = (int)kev->ident;

	/*
	 * A queue-directory watch shares the EVFILT_VNODE filter but is gated on
	 * the directory still holding work: demand only while there is something
	 * to drain.  The watch is level-in-spirit — each relaunch re-checks on
	 * the next change event until the directory empties.
	 */
	svc = queue_owner(fd);
	if (svc != NULL) {
		if (dir_nonempty(fd))
			activation_create_demand(svc, "queue", kq);
		return;
	}

	svc = path_owner(fd);
	if (svc == NULL) {
		/*
		 * No unit owns this descriptor any more (removed between the
		 * kernel queuing the event and us draining it).  Closing the fd
		 * elsewhere already removed the filter; nothing to do.
		 */
		return;
	}

	/* Any reported change is demand. */
	activation_create_demand(svc, "path", kq);

	/*
	 * The watched name went away.  The open descriptor still refers to the
	 * now-unlinked or renamed vnode, so re-open by path: an atomic replace
	 * (write-new + rename-over) leaves a fresh file at the path we resume
	 * watching; a plain removal leaves nothing and we drop the watch.
	 */
	if (kev->fflags & (NOTE_DELETE | NOTE_RENAME) ||
	    kev->flags & EV_EOF) {
		char path[PATH_MAX];

		strlcpy(path, svc->manifest.activation_path, sizeof(path));
		(void)close(svc->activation_path_fd);
		svc->activation_path_fd = -1;
		arm_path(svc, kq);
		if (svc->activation_path_fd < 0)
			syslog(LOG_WARNING,
			    "activation: %s: watch on %s dropped after "
			    "delete/rename", svc->manifest.label, path);
		else
			syslog(LOG_INFO,
			    "activation: %s: re-registered watch on %s after "
			    "delete/rename", svc->manifest.label, path);
	}
}

/*
 * True when fd is a manager-owned socket-activation listener.  The main event
 * loop calls this to route an EVFILT_READ before its generic channel handling,
 * so a listener fd is never mistaken for a control/channel descriptor.
 */
bool
activation_socket_owns(int fd)
{

	return (listen_owner(fd) != NULL);
}

/*
 * A socket-activation listener became readable: an inbound connection (or, for
 * SOCK_DGRAM, a waiting datagram) is the demand that launches the unit.  We do
 * NOT accept()/recv() — the connection/datagram stays queued in the kernel for
 * the provider to take once it is up.  The EVFILT_READ stays registered
 * (level-triggered), so while the provider is still coming up the still-readable
 * listener keeps coalescing demand via activation_create_demand; once the
 * provider accepts and the backlog drains, the level clears on its own.
 */
void
activation_socket_event(struct kevent *kev, int kq)
{
	struct svc_runtime *svc;

	svc = listen_owner((int)kev->ident);
	if (svc == NULL) {
		/*
		 * No unit owns this descriptor any more (removed between the
		 * kernel queuing the event and us draining it).  Teardown
		 * already deleted the filter and closed the fd; nothing to do.
		 */
		return;
	}
	activation_create_demand(svc, "socket", kq);
}

/*
 * Arm activation sources for every unit that declares one.  A unit activated
 * purely by a timer or path has no boot launch and no IPC name, so startup
 * never gave it a runtime slot; create a stopped slot here so its source has a
 * unit to activate.  Units that already have a slot (boot units, or units that
 * also publish IPC names) are found by label and only have their sources
 * armed.  Idempotent, so it is safe to call again on reload.
 */
int
activation_register_all(int kq)
{
	struct capbundle *b;
	struct capbundle_service *asvc;
	struct svc_runtime *svc;
	unsigned bi, si, armed;

	if (sd.services == NULL)
		return (-1);

	armed = 0;
	for (bi = 0; bi < bundle_registry_count(); bi++) {
		b = bundle_registry_get(bi);
		if (b == NULL)
			continue;
		for (si = 0; si < capbundle_nservices(b); si++) {
			asvc = capbundle_service(b, si);
			if (asvc == NULL)
				continue;
			if (capbundle_svc_timer_interval(asvc) == 0 &&
			    capbundle_svc_activation_path(asvc)[0] == '\0' &&
			    capbundle_svc_nactivation_sockets(asvc) == 0)
				continue;

			svc = svc_by_label(capbundle_svc_label(asvc));
			if (svc == NULL) {
				if (sd.nservices >= SERVICED_MAX_SERVICES) {
					syslog(LOG_WARNING,
					    "activation: service limit reached, "
					    "cannot register '%s'",
					    capbundle_svc_label(asvc));
					continue;
				}
				svc = &sd.services[sd.nservices];
				memset(svc, 0, sizeof(*svc));
				svc_runtime_init_fds(svc);
				svc->state = SVC_STATE_STOPPED;
				svc->bundle_idx = bi;
				svc->bundle_svc_idx = si;
				if (capbundle_svc_fill_manifest(asvc,
				    &svc->manifest) == -1) {
					syslog(LOG_WARNING,
					    "activation: invalid bundle service "
					    "'%s'", capbundle_svc_label(asvc));
					memset(svc, 0, sizeof(*svc));
					svc_runtime_init_fds(svc);
					continue;
				}
				strlcpy(svc->launched_by, "activation",
				    sizeof(svc->launched_by));
				clock_gettime(CLOCK_MONOTONIC,
				    &svc->launch_time);
				sd.nservices++;
			}
			activation_source_arm(svc, kq);
			armed++;
		}
	}
	if (armed != 0)
		syslog(LOG_INFO, "activation: %u activation source%s registered",
		    armed, armed == 1 ? "" : "s");
	return (0);
}
