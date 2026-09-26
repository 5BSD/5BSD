/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 *
 * libcapreclaim: the shared cleanup primitive for the capability container
 * model (docs/book/src/plane/containers-and-storage.md).  A provider that stores
 * per-capability resources keyed by a stable owner name reclaims them by
 * reconciling its owned set against the live set -- the capabilities that are
 * installed OR running, read straight from the filesystem -- and destroying
 * whatever is no longer live.  Cleanup is a reconcile, never a reaction to an
 * event: it runs at boot (destroy immediately) and on a timer (destroy only
 * after an owner has been gone across a full interval -- "seen gone twice"),
 * so an upgrade's transient absence is never acted on.
 *
 * The library owns the hard, safety-critical parts (reading the live set,
 * computing orphans, the grace) so every provider gets identical, correct,
 * upgrade-safe behaviour.  The provider supplies only two callbacks: enumerate
 * the owners it holds, and destroy one.
 */
#ifndef CAPRECLAIM_H
#define CAPRECLAIM_H

#include <stdbool.h>
#include <stddef.h>

#define	CAPRECLAIM_OWNER_MAX	64	/* == svc_new_client_msg.resource_owner */

/* When a reconcile pass runs. */
enum capreclaim_when {
	CAPRECLAIM_BOOT,	/* settled state: destroy orphans immediately */
	CAPRECLAIM_TIMER,	/* running system: destroy only if gone twice */
};

/*
 * Optional per-pass accounting, filled when `stats` is set: the sizes of the
 * live and owned sets, the orphans found, and how many were destroyed this
 * pass versus failed (a failed destroy is retried on a later pass).  Providers
 * feed these to their tracing probes; tests assert on them.
 */
struct capreclaim_stats {
	unsigned	nlive;
	unsigned	nowned;
	unsigned	norphans;
	unsigned	ndestroyed;
	unsigned	nfailed;
	/*
	 * The pass hit the empty-live-set floor (sources read, nothing live):
	 * nothing was examined or destroyed and the result 0 means "not yet",
	 * not "settled".  A caller running its BOOT pass should stay in BOOT
	 * until a pass completes without flooring.
	 */
	bool		floored;
};

/*
 * Live sources: read-only directory descriptors switchboard delivers, whose
 * entry names are owner keys.  The installed markers (System/, Apps/) and the
 * running markers (Run/) together are the live set.  `strip_cap` trims a
 * trailing ".cap" from a marker directory name to yield the owner key.
 */
struct capreclaim_source {
	int	fd;		/* dir fd, or -1 to skip */
	bool	strip_cap;	/* entries are <owner>.cap (installed markers) */
};

/*
 * Provider callbacks.  `enumerate` calls `emit(emit_arg, owner)` once per owner
 * it currently holds resources for; it returns 0 on success.  `destroy` frees
 * one owner's resources and returns 0 on success (a failure is retried next
 * pass).  `arg` is the provider's context.
 */
typedef int (*capreclaim_enumerate_fn)(void *arg,
    void (*emit)(void *emit_arg, const char *owner), void *emit_arg);
typedef int (*capreclaim_destroy_fn)(void *arg, const char *owner);

/*
 * Opaque per-reconciler grace state, owned by the library and defined
 * privately in capreclaim.c: the owners seen orphaned on the previous timer
 * pass ("seen gone twice").  It is deliberately NOT a set of public fields --
 * a caller cannot stomp it, copy it into a second reconciler, or leave a
 * count out of step with its array.  Zeroed by CAPRECLAIM_INIT, allocated
 * lazily on the first graced pass, released by capreclaim_fini().
 */
struct capreclaim_state;

struct capreclaim {
	/*
	 * Must equal sizeof(struct capreclaim) at the CALLER's compile time;
	 * CAPRECLAIM_INIT sets it.  It is the ABI-skew guard: a provider built
	 * against one libcapreclaim and dynamically linked against another
	 * reports the size of the struct it actually allocated, so the library
	 * never reads an optional field past the end of an older, smaller
	 * struct.  capreclaim_run() rejects a struct_size of zero or one out of
	 * range (which also catches a struct that was never initialised), so
	 * every reconciler MUST be initialised with CAPRECLAIM_INIT.
	 */
	size_t			 struct_size;
	struct capreclaim_source sources[4];	/* live-set sources */
	unsigned		 nsources;
	capreclaim_enumerate_fn	 enumerate;
	capreclaim_destroy_fn	 destroy;
	void			*arg;
	/*
	 * Opt out of the empty-live-set safety floor.  The floor assumes an
	 * empty live set means "not published yet"; a client whose sources are
	 * gated on their own readiness signal (the marker directory existing,
	 * created by the publisher before anything runs) may treat an empty set
	 * as genuinely empty -- e.g. group containers once no installed bundle
	 * claims any group.  Default false.
	 *
	 * A reconcile whose sources are the install roots (System/ [+ Apps/ +
	 * Run/live]) must leave this false: System/ always contains at least
	 * the provider's own bundle while the provider runs, so a live set that
	 * reads back empty means a source could not be read, not that every
	 * owner is gone -- the floor is that reconcile's readiness gate.  Set it
	 * true ONLY when an empty source set is a legitimate "nothing is
	 * claimed" AND the client has an independent readiness signal, or the
	 * first unreadable pass will destroy every owned resource.
	 */
	bool			 allow_empty_live;
	struct capreclaim_state	*state;		/* opaque; library-owned */
	/*
	 * --- Optional tail.  Each field below is read only when struct_size
	 * shows the caller's struct is large enough to contain it, so a future
	 * field may be appended here without breaking an already-compiled
	 * caller.  Everything above is mandatory (part of CAPRECLAIM_SIZE_MIN). ---
	 */
	struct capreclaim_stats	*stats;			/* optional */
	/*
	 * Operability: if status_dirfd >= 0, each pass rewrites an
	 * operator-readable record named status_name in that directory -- the
	 * managed (owned) set, the orphans, and the last pass's counts -- so an
	 * admin can see what the provider is managing without a live query.
	 * Open the directory with capreclaim_status_dir() (before cap_enter for
	 * a capability-mode client) and hold the descriptor.  Off by default.
	 */
	int			 status_dirfd;
	const char		*status_name;
};

/*
 * The mandatory prefix of struct capreclaim: a caller's struct_size below this
 * cannot describe a usable reconciler and is rejected.  Fields from `stats`
 * onward are the size-gated optional tail.
 */
#define	CAPRECLAIM_SIZE_MIN	offsetof(struct capreclaim, stats)

/*
 * The one correct way to initialise a reconciler: zeroes every field (so the
 * opaque state starts NULL, allow_empty_live false, optional fds absent) and
 * stamps struct_size with the caller's own sizeof for the ABI-skew guard.
 * Use it, then set the fields you need:
 *
 *	struct capreclaim r = CAPRECLAIM_INIT;
 *	r.sources[0].fd = sys_fd; r.sources[0].strip_cap = true;
 *	r.nsources = 1; r.enumerate = ...; r.destroy = ...; r.arg = ...;
 */
#define	CAPRECLAIM_INIT		{ .struct_size = sizeof(struct capreclaim) }

/*
 * Run one reconcile pass.  Reads the live set from the sources, asks the
 * provider for its owned set, and destroys owners that are owned but not live
 * -- immediately for CAPRECLAIM_BOOT, or only when also orphaned on the prior
 * pass for CAPRECLAIM_TIMER.  Returns the number of owners
 * destroyed, or -1 with errno on a hard error (a per-owner destroy failure is
 * counted as not-destroyed, not a hard error).  Safe to call repeatedly;
 * idempotent.
 */
int	capreclaim_run(struct capreclaim *r, enum capreclaim_when when);

/*
 * Open (creating) the shared status directory /var/run/reclaim and return a
 * descriptor to store in capreclaim.status_dirfd, or -1 with errno set.  Call
 * it before entering capability mode; the descriptor is then usable from a
 * sandbox.  The records written there are operator-readable (see reclaimstat).
 */
#define	CAPRECLAIM_STATUS_DIR	"/var/run/reclaim"
int	capreclaim_status_dir(void);

/* Release the grace state. */
void	capreclaim_fini(struct capreclaim *r);

#endif /* CAPRECLAIM_H */
