/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 *
 * libcapreclaim implementation.  See capreclaim.h and
 * docs/capability-container-model.md.
 */
#include <sys/param.h>
#include <sys/types.h>

#include <sys/stat.h>

#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "capreclaim.h"

/* A small growable set of owner keys (dozens of entries; linear ops are fine). */
struct owner_set {
	char	(*names)[CAPRECLAIM_OWNER_MAX];
	unsigned  n, cap;
};

/*
 * The opaque grace state forward-declared in the header: owners orphaned on
 * the previous timer pass.  Kept out of the public struct so a caller can
 * neither corrupt it nor share it between reconcilers.  Allocated lazily; a
 * failure to allocate simply means this pass records no grace, which only
 * DELAYS a reap (the orphan is "seen for the first time" again next pass) --
 * never an early one -- so it is safe to carry on without it.
 */
struct capreclaim_state {
	char		(*orphans)[CAPRECLAIM_OWNER_MAX];
	unsigned	  n, cap;
};

/*
 * True when the caller's struct_size shows its struct actually contains field
 * `f`.  Used to read an optional tail field only when an older, smaller caller
 * really has it -- the ABI-skew guard in action.
 */
#define	CAPRECLAIM_HAS(r, f)						\
	((r)->struct_size >= offsetof(struct capreclaim, f) +		\
	    sizeof(((struct capreclaim *)0)->f))

static bool
set_contains(const struct owner_set *s, const char *name)
{
	unsigned i;

	for (i = 0; i < s->n; i++)
		if (strcmp(s->names[i], name) == 0)
			return (true);
	return (false);
}

static int
set_add(struct owner_set *s, const char *name)
{
	if (name[0] == '\0' || strlen(name) >= CAPRECLAIM_OWNER_MAX)
		return (0);			/* skip malformed, never fail */
	if (set_contains(s, name))
		return (0);
	if (s->n == s->cap) {
		unsigned ncap = s->cap == 0 ? 16 : s->cap * 2;
		void *p = reallocarray(s->names, ncap, sizeof(*s->names));

		if (p == NULL)
			return (-1);
		s->names = p;
		s->cap = ncap;
	}
	(void)strlcpy(s->names[s->n++], name, CAPRECLAIM_OWNER_MAX);
	return (0);
}

static void
set_free(struct owner_set *s)
{
	free(s->names);
	s->names = NULL;
	s->n = s->cap = 0;
}

/* Read one live-set source directory, adding each entry (minus ".cap") to live. */
static int
read_source(const struct capreclaim_source *src, struct owner_set *live)
{
	/*
	 * Hold the whole entry name, which for a marker source is "<owner>.cap"
	 * -- four bytes longer than the owner.  Sizing this at just
	 * CAPRECLAIM_OWNER_MAX would drop a valid near-max owner's marker on the
	 * strlcpy truncation check below, leaving its live container looking
	 * orphaned and destroying it at boot.  The stripped owner is still bounded
	 * by set_add() to CAPRECLAIM_OWNER_MAX.
	 */
	char name[CAPRECLAIM_OWNER_MAX + sizeof(".cap") - 1];
	struct dirent *de;
	DIR *d;
	int fd2;

	if (src->fd < 0)
		return (0);
	/*
	 * Read through a dup(2) of the delivered descriptor, rewound: never a
	 * fresh open of ".", which is a path lookup the plane refuses (EACCES)
	 * to a client that dropped privileges inside its sandbox (logd's
	 * storage manager), while a dup needs no lookup at all.  The dup shares
	 * the open file's offset with the caller's descriptor, so rewinddir(3)
	 * puts every pass at the start whatever a previous pass left there;
	 * closedir(3) closes only the dup.  A source that is not a readable
	 * directory still fails here, never listing nothing silently.
	 */
	fd2 = dup(src->fd);
	if (fd2 == -1)
		return (-1);
	d = fdopendir(fd2);
	if (d == NULL) {
		(void)close(fd2);
		return (-1);
	}
	rewinddir(d);
	/*
	 * readdir(3) returns NULL for end-of-directory AND for an error; only
	 * errno tells them apart.  A truncated listing must fail the pass: every
	 * owner past the failure point would otherwise look like an orphan and,
	 * at boot, be destroyed at once.
	 */
	errno = 0;
	while ((de = readdir(d)) != NULL) {
		size_t len;

		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;
		if (strlcpy(name, de->d_name, sizeof(name)) >= sizeof(name))
			continue;
		if (src->strip_cap) {
			len = strlen(name);
			if (len > 4 && strcmp(name + len - 4, ".cap") == 0)
				name[len - 4] = '\0';
			else
				continue;	/* a marker dir is always <owner>.cap */
		}
		if (set_add(live, name) == -1) {
			(void)closedir(d);
			return (-1);
		}
		errno = 0;
	}
	if (errno != 0) {
		int saved = errno;

		(void)closedir(d);
		errno = saved;
		return (-1);
	}
	(void)closedir(d);
	return (0);
}

/* Forget the previous pass's orphans: the grace window starts over. */
static void
forget_prev(struct capreclaim *r)
{
	if (r->state == NULL)
		return;
	free(r->state->orphans);
	r->state->orphans = NULL;
	r->state->n = r->state->cap = 0;
}

/* Was `owner` orphaned on the previous timer pass?  (No state == no, safely.) */
static bool
seen_orphaned_before(const struct capreclaim *r, const char *owner)
{
	unsigned j;

	if (r->state == NULL)
		return (false);
	for (j = 0; j < r->state->n; j++)
		if (strcmp(r->state->orphans[j], owner) == 0)
			return (true);
	return (false);
}

/*
 * Hand this pass's orphan array to the grace state for the next pass to check
 * against.  Allocates the state on first use; on allocation failure the array
 * is left with the caller to free and grace simply resets (safe: delays a reap,
 * never causes an early one).  Returns true iff ownership of `orphans` moved.
 */
static bool
remember_orphans(struct capreclaim *r, struct owner_set *orphans)
{
	if (r->state == NULL) {
		r->state = calloc(1, sizeof(*r->state));
		if (r->state == NULL)
			return (false);
	}
	free(r->state->orphans);
	r->state->orphans = orphans->names;
	r->state->n = orphans->n;
	r->state->cap = orphans->cap;
	orphans->names = NULL;		/* ownership moved */
	return (true);
}

/* enumerate() emit target: collect the provider's owned owners. */
static void
emit_owned(void *emit_arg, const char *owner)
{
	struct owner_set *owned = emit_arg;

	(void)set_add(owned, owner);	/* a failed add just under-reports; safe */
}

/*
 * Open (creating) the shared, operator-readable status directory.  0755 so an
 * operator can list it; the records name bundles, which are not secret.
 */
int
capreclaim_status_dir(void)
{

	if (mkdir(CAPRECLAIM_STATUS_DIR, 0755) == -1 && errno != EEXIST)
		return (-1);
	return (open(CAPRECLAIM_STATUS_DIR,
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC));
}

/*
 * Rewrite the provider's status record (managed set, orphans, last-pass
 * counts) atomically.  Best-effort operability: a failure here never affects
 * the pass.  Written even for a floored/failed pass, so an operator can see
 * that the provider could not read its sources.
 */
static void
write_status(const struct capreclaim *r, enum capreclaim_when when,
    unsigned nlive, const struct owner_set *owned,
    const struct owner_set *orphans, int destroyed, int failed,
    bool floored, int error)
{
	char tmp[128];
	FILE *f;
	unsigned i;
	int fd;

	if (!CAPRECLAIM_HAS(r, status_dirfd) ||
	    !CAPRECLAIM_HAS(r, status_name) ||
	    r->status_dirfd < 0 || r->status_name == NULL)
		return;
	if (snprintf(tmp, sizeof(tmp), "%s.tmp", r->status_name) >=
	    (int)sizeof(tmp))
		return;
	fd = openat(r->status_dirfd, tmp,
	    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
	if (fd == -1)
		return;
	f = fdopen(fd, "w");
	if (f == NULL) {
		(void)close(fd);
		(void)unlinkat(r->status_dirfd, tmp, 0);
		return;
	}
	(void)fprintf(f, "provider %s\npass %s at %jd\n", r->status_name,
	    when == CAPRECLAIM_BOOT ? "boot" : "timer", (intmax_t)time(NULL));
	(void)fprintf(f, "counts live=%u owned=%u orphans=%u destroyed=%d "
	    "failed=%d floored=%d error=%d\n", nlive,
	    owned != NULL ? owned->n : 0u, orphans != NULL ? orphans->n : 0u,
	    destroyed, failed, floored ? 1 : 0, error);
	for (i = 0; owned != NULL && i < owned->n; i++)
		(void)fprintf(f, "manage %s\n", owned->names[i]);
	for (i = 0; orphans != NULL && i < orphans->n; i++)
		(void)fprintf(f, "orphan %s\n", orphans->names[i]);
	if (fflush(f) != 0 || fsync(fd) == -1) {
		(void)fclose(f);
		(void)unlinkat(r->status_dirfd, tmp, 0);
		return;
	}
	if (fclose(f) != 0) {
		(void)unlinkat(r->status_dirfd, tmp, 0);
		return;
	}
	(void)renameat(r->status_dirfd, tmp, r->status_dirfd, r->status_name);
}
int
capreclaim_run(struct capreclaim *r, enum capreclaim_when when)
{
	struct owner_set live = { 0 }, owned = { 0 }, orphans = { 0 };
	unsigned i, failed = 0, nread = 0;
	int destroyed = 0, error = 0;
	bool floored = false, completed = false;

	if (r == NULL || r->struct_size < CAPRECLAIM_SIZE_MIN ||
	    r->struct_size > sizeof(*r) || r->enumerate == NULL ||
	    r->destroy == NULL || r->nsources > nitems(r->sources))
		return (errno = EINVAL, -1);
	if (CAPRECLAIM_HAS(r, stats) && r->stats != NULL)
		memset(r->stats, 0, sizeof(*r->stats));

	/* 1. Build the live set from the delivered sources. */
	for (i = 0; i < r->nsources; i++) {
		if (r->sources[i].fd < 0)
			continue;		/* absent: skipped, not "empty" */
		if (read_source(&r->sources[i], &live) == -1) {
			error = errno;
			goto out;
		}
		nread++;
	}

	/*
	 * Safety floor: an empty live set almost always means the source was not
	 * published yet (or is being rewritten), not that every owner is gone.
	 * Reaping everything on "nothing is alive" would be catastrophic, so a
	 * reconcile with no live owners destroys nothing.  A caller that must
	 * reap the last owner on a genuinely empty system is expected to gate on
	 * its own readiness signal before calling; this only removes the
	 * dangerous all-or-nothing edge.
	 */
	/*
	 * ... except that a client which gates on its own readiness signal may
	 * opt out (allow_empty_live) -- but only for a live set that was READ
	 * and found empty; when no source could be read at all, nothing is
	 * known and nothing is reaped, opt-out or not.
	 */
	if (live.n == 0 && (nread == 0 || !r->allow_empty_live)) {
		floored = true;
		goto out;
	}

	/* 2. Ask the provider which owners it holds. */
	if (r->enumerate(r->arg, emit_owned, &owned) != 0) {
		error = errno != 0 ? errno : EIO;
		goto out;
	}

	/* 3. Orphans = owned but not live. */
	for (i = 0; i < owned.n; i++)
		if (!set_contains(&live, owned.names[i]) &&
		    set_add(&orphans, owned.names[i]) == -1) {
			error = errno;
			goto out;
		}

	/*
	 * 4. Destroy.  At boot the state is settled, so an orphan is durably
	 * gone -- destroy now.  On the timer, destroy only an orphan that was
	 * ALSO orphaned on the previous pass ("seen gone twice"); the interval
	 * is the grace window, so an upgrade's transient absence is never
	 * confirmed.
	 */
	for (i = 0; i < orphans.n; i++) {
		bool act = when == CAPRECLAIM_BOOT;

		if (!act)
			act = seen_orphaned_before(r, orphans.names[i]);
		if (!act)
			continue;
		if (r->destroy(r->arg, orphans.names[i]) == 0)
			destroyed++;
		else
			failed++;
	}
	if (CAPRECLAIM_HAS(r, stats) && r->stats != NULL) {
		r->stats->nlive = live.n;
		r->stats->nowned = owned.n;
		r->stats->norphans = orphans.n;
		r->stats->ndestroyed = (unsigned)destroyed;
		r->stats->nfailed = failed;
	}
	completed = true;

	/* Remember this pass's orphans for the next graced pass. */
	if (when != CAPRECLAIM_BOOT)
		(void)remember_orphans(r, &orphans);
out:
	/*
	 * A pass that did not complete (floored, or a source/enumerate error)
	 * observed nothing: forget the previous pass's orphans so the grace
	 * window restarts, rather than confirming an orphan across an interval
	 * that was never actually observed.
	 */
	if (!completed && when != CAPRECLAIM_BOOT)
		forget_prev(r);
	if (CAPRECLAIM_HAS(r, stats) && r->stats != NULL)
		r->stats->floored = floored;
	write_status(r, when, live.n, &owned, &orphans, destroyed, failed,
	    floored, error);
	set_free(&live);
	set_free(&owned);
	set_free(&orphans);
	if (error != 0)
		return (errno = error, -1);
	return (destroyed);
}

void
capreclaim_fini(struct capreclaim *r)
{
	if (r == NULL || r->state == NULL)
		return;
	free(r->state->orphans);
	free(r->state);
	r->state = NULL;
}
