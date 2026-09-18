/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 *
 * libcapreclaim: the shared cleanup primitive for the capability container
 * model (docs/capability-container-model.md).  A provider that stores
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

struct capreclaim {
	struct capreclaim_source sources[4];	/* live-set sources */
	unsigned		 nsources;
	capreclaim_enumerate_fn	 enumerate;
	capreclaim_destroy_fn	 destroy;
	void			*arg;
	struct capreclaim_stats	*stats;			/* optional */
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
	/* Grace state: owners seen orphaned on the previous timer pass. */
	char			(*prev_orphans)[CAPRECLAIM_OWNER_MAX];
	unsigned		 nprev;
	unsigned		 cprev;
};

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

/* Release the grace state. */
void	capreclaim_fini(struct capreclaim *r);

#endif /* CAPRECLAIM_H */
