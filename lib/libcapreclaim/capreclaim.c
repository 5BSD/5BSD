/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 *
 * libcapreclaim implementation.  See capreclaim.h and
 * docs/capability-container-model.md.
 */
#include <sys/types.h>

#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "capreclaim.h"

/* A small growable set of owner keys (dozens of entries; linear ops are fine). */
struct owner_set {
	char	(*names)[CAPRECLAIM_OWNER_MAX];
	unsigned  n, cap;
};

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
	char name[CAPRECLAIM_OWNER_MAX];
	struct dirent *de;
	DIR *d;
	int fd2;

	if (src->fd < 0)
		return (0);
	/* fdopendir consumes the fd; dup so the caller's fd stays usable. */
	fd2 = dup(src->fd);
	if (fd2 == -1)
		return (-1);
	if (lseek(fd2, 0, SEEK_SET) == -1) {
		/* Not seekable is fine on some fs; fdopendir rewinds anyway. */
	}
	d = fdopendir(fd2);
	if (d == NULL) {
		(void)close(fd2);
		return (-1);
	}
	rewinddir(d);
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
	}
	(void)closedir(d);
	return (0);
}

/* enumerate() emit target: collect the provider's owned owners. */
static void
emit_owned(void *emit_arg, const char *owner)
{
	struct owner_set *owned = emit_arg;

	(void)set_add(owned, owner);	/* a failed add just under-reports; safe */
}

int
capreclaim_run(struct capreclaim *r, enum capreclaim_when when)
{
	struct owner_set live = { 0 }, owned = { 0 }, orphans = { 0 };
	unsigned i, failed = 0;
	int destroyed = 0, error = 0;

	if (r == NULL || r->enumerate == NULL || r->destroy == NULL)
		return (errno = EINVAL, -1);
	if (r->stats != NULL)
		memset(r->stats, 0, sizeof(*r->stats));

	/* 1. Build the live set from the delivered sources. */
	for (i = 0; i < r->nsources; i++)
		if (read_source(&r->sources[i], &live) == -1) {
			error = errno;
			goto out;
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
	if (live.n == 0)
		goto out;

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

		if (!act) {
			unsigned j;

			for (j = 0; j < r->nprev; j++)
				if (strcmp(r->prev_orphans[j],
				    orphans.names[i]) == 0) {
					act = true;
					break;
				}
		}
		if (!act)
			continue;
		if (r->destroy(r->arg, orphans.names[i]) == 0)
			destroyed++;
		else
			failed++;
	}
	if (r->stats != NULL) {
		r->stats->nlive = live.n;
		r->stats->nowned = owned.n;
		r->stats->norphans = orphans.n;
		r->stats->ndestroyed = (unsigned)destroyed;
		r->stats->nfailed = failed;
	}

	/* Remember this pass's orphans for the next graced pass. */
	if (when != CAPRECLAIM_BOOT) {
		free(r->prev_orphans);
		r->prev_orphans = orphans.names;
		r->nprev = orphans.n;
		r->cprev = orphans.cap;
		orphans.names = NULL;	/* ownership moved */
	}
out:
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
	if (r == NULL)
		return;
	free(r->prev_orphans);
	r->prev_orphans = NULL;
	r->nprev = r->cprev = 0;
}
