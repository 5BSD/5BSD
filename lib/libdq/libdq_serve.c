/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * dq_serve_file(): answer every stage 1b-i event from a backing file.
 *
 * Locks are the one part with state, kept in one struct dq_serve_state per
 * queue.  The requester's lock owners (a POSIX owner is a process, a flock
 * or OFD owner an open file; the kernel names each with a stable id in the
 * LOCK body) are mapped to distinct open file descriptions of the backing
 * file, opened with O_EMPTY_PATH from the backing descriptor, and every
 * kind is applied as an OFD lock on its owner's open: OFD and flock locks
 * share lockf's table, a flock is a whole-file lock, and the owner of an
 * OFD lock is the open, so two requesters that conflict on the served file
 * conflict on the backing file and one requester's locks never conflict
 * with its own.
 *
 * A POSIX owner is a process, and a process holds one set of POSIX locks
 * per file however many descriptors it has: its owner is shared by every
 * object of the same identity (di_dev, di_ino) on the queue, as the kernel
 * shares it (a lock through one object marks its siblings, and closing any
 * of them posts UNLOCK_ALL for the owner).  A flock or OFD owner is an open
 * file, which is one object: those owners are per object.
 *
 * A SETLKW blocks in a thread of its own (F_OFD_SETLKW is a cancellation
 * point); the INTERRUPT the kernel posts when the requester gives up
 * cancels it, and a grant that races the INTERRUPT (the reply then answers
 * ESRCH) is undone.
 *
 * Each owner keeps a shadow of what it holds (C15): the ranges and types
 * the replies granted, merged as lockf(9) merges an owner's locks.  It
 * restores the owner's earlier locks when a raced grant is undone, and it
 * names the owner of a blocker F_GETLK reports (lockf reports no pid for
 * the OFD locks it proxies with).  The shadow follows the order this
 * process applied its operations to the backing file; one owner's
 * operations that race each other (two threads of a POSIX owner, one
 * waiting) can be applied by the kernel in either order, and the shadow
 * records a grant when its thread takes the mutex after it.  A GETLK that
 * meets a grant in that moment, before its thread has the mutex, names no
 * owner (-1).
 *
 * flock(2) owners follow lf_setlock's rule for an exclusive request that
 * would block: the open file's shared lock goes first, then it sleeps.
 * OFD locks convert in place while they wait, so the drop is made here.
 */

#include <sys/param.h>
#include <sys/ioccom.h>
#include <sys/mount.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libdq.h"

/* Who an owner is: POSIX by identity, flock and OFD by object. */
struct dq_serve_key {
	uint32_t	 kind;
	uint64_t	 owner;
	uint64_t	 object;	/* flock, OFD */
	uint64_t	 dev, ino;	/* POSIX */
};

/* One range of an owner's shadow: [sr_start, sr_end], OFF_MAX = to EOF. */
struct dq_serve_range {
	TAILQ_ENTRY(dq_serve_range) sr_link;
	off_t		 sr_start, sr_end;
	short		 sr_type;	/* F_RDLCK, F_WRLCK */
};
TAILQ_HEAD(dq_serve_shadow, dq_serve_range);

/*
 * The ranges a shadow update may need: one to insert, one when a range
 * is split around the change.  Taken before the backing file is touched,
 * so a shadow update never fails after the lock changed.
 */
#define	DQ_SERVE_SPARES	2
struct dq_serve_spare {
	struct dq_serve_range *sp[DQ_SERVE_SPARES];
};

struct dq_serve_owner {
	LIST_ENTRY(dq_serve_owner) so_link;
	struct dq_serve_key so_key;
	int		 so_fd;		/* the owner's open of the backing file */
	int		 so_nwaits;	/* its SETLKW threads (ss_mtx) */
	pid_t		 so_pid;	/* POSIX: the process; else -1 */
	struct dq_serve_shadow so_shadow;	/* what it holds (ss_mtx) */
};

/*
 * A SETLKW thread.  It works on its own descriptor of the owner's open
 * file (sw_dupfd), never on the owner's number: an owner closed while the
 * thread runs frees that number for any other open of this process.  The
 * owner itself outlives the thread: whoever closes it waits for its
 * so_nwaits to drain first (dq_serve_owner_close).
 */
struct dq_serve_wait {
	LIST_ENTRY(dq_serve_wait) sw_link;
	struct dq_serve_state *sw_state;
	struct dq_serve_owner *sw_owner;
	pthread_t	 sw_thr;
	uint64_t	 sw_id;		/* the event; INTERRUPT names it */
	struct dq_serve_key sw_key;
	int		 sw_q;
	int		 sw_dupfd;	/* a dup of sw_owner->so_fd, the thread's */
	struct flock	 sw_fl;
	struct dq_serve_spare sw_spare;	/* for the grant's shadow update */
};

struct dq_serve_state {
	pthread_mutex_t	 ss_mtx;
	pthread_cond_t	 ss_cv;		/* a wait ended */
	LIST_HEAD(, dq_serve_owner) ss_owners;
	LIST_HEAD(, dq_serve_wait) ss_waits;
	int		 ss_nowners;
	int		 ss_nwaits;
};

/* An errno the operation's allow-list refuses reaches the requester as EIO. */
static int
dq_serve_map(uint32_t op, int error)
{

	return (dq_reply_errno_allowed(op, error) ? error : EIO);
}

/*
 * Shadows
 */

static int
dq_serve_spare_get(struct dq_serve_spare *sp)
{
	int i;

	memset(sp, 0, sizeof(*sp));
	for (i = 0; i < DQ_SERVE_SPARES; i++) {
		sp->sp[i] = malloc(sizeof(*sp->sp[i]));
		if (sp->sp[i] == NULL) {
			while (i-- > 0)
				free(sp->sp[i]);
			memset(sp, 0, sizeof(*sp));
			return (ENOLCK);
		}
	}
	return (0);
}

static void
dq_serve_spare_put(struct dq_serve_spare *sp)
{
	int i;

	for (i = 0; i < DQ_SERVE_SPARES; i++) {
		free(sp->sp[i]);
		sp->sp[i] = NULL;
	}
}

static struct dq_serve_range *
dq_serve_spare_take(struct dq_serve_spare *sp)
{
	struct dq_serve_range *r;
	int i;

	for (i = 0; i < DQ_SERVE_SPARES; i++) {
		if ((r = sp->sp[i]) != NULL) {
			sp->sp[i] = NULL;
			return (r);
		}
	}
	return (NULL);	/* not reached: an update takes two at most */
}

/* The inclusive end of a lock body's or flock's range (len 0: to EOF). */
static off_t
dq_serve_range_end(off_t start, off_t len)
{

	return (len == 0 ? OFF_MAX : start + len - 1);
}

static void
dq_serve_range_flock(struct flock *fl, short type, off_t start, off_t end)
{

	memset(fl, 0, sizeof(*fl));
	fl->l_type = type;
	fl->l_whence = SEEK_SET;
	fl->l_start = start;
	fl->l_len = end == OFF_MAX ? 0 : end - start + 1;
}

/*
 * [start, end] becomes type (F_UNLCK: nothing) in the owner's shadow, as
 * lockf(9) applies a request to one owner's locks: overlapped ranges are
 * cut back or split, and a range of the same type that touches or
 * overlaps the new one joins it.  The mutex is held.
 */
static void
dq_serve_shadow_apply(struct dq_serve_owner *so, off_t start, off_t end,
    short type, struct dq_serve_spare *sp)
{
	struct dq_serve_range *r, *tmp, *nr, *prev;

	TAILQ_FOREACH_SAFE(r, &so->so_shadow, sr_link, tmp) {
		if (r->sr_end < start)
			continue;
		if (r->sr_start > end)
			break;
		if (r->sr_start < start && r->sr_end > end) {
			/* Split: the tail keeps its type after the change. */
			nr = dq_serve_spare_take(sp);
			nr->sr_start = end + 1;
			nr->sr_end = r->sr_end;
			nr->sr_type = r->sr_type;
			TAILQ_INSERT_AFTER(&so->so_shadow, r, nr, sr_link);
			r->sr_end = start - 1;
			break;
		}
		if (r->sr_start < start)
			r->sr_end = start - 1;
		else if (r->sr_end > end)
			r->sr_start = end + 1;
		else {
			TAILQ_REMOVE(&so->so_shadow, r, sr_link);
			free(r);
		}
	}
	if (type == F_UNLCK)
		return;

	/* Insert in order, then join same-type neighbours that touch it. */
	prev = NULL;
	TAILQ_FOREACH(r, &so->so_shadow, sr_link) {
		if (r->sr_start > end)
			break;
		prev = r;
	}
	nr = dq_serve_spare_take(sp);
	nr->sr_start = start;
	nr->sr_end = end;
	nr->sr_type = type;
	if (prev == NULL)
		TAILQ_INSERT_HEAD(&so->so_shadow, nr, sr_link);
	else
		TAILQ_INSERT_AFTER(&so->so_shadow, prev, nr, sr_link);
	if (prev != NULL && prev->sr_type == type && prev->sr_end + 1 == start) {
		prev->sr_end = nr->sr_end;
		TAILQ_REMOVE(&so->so_shadow, nr, sr_link);
		free(nr);
		nr = prev;
	}
	r = TAILQ_NEXT(nr, sr_link);
	if (r != NULL && r->sr_type == type && nr->sr_end != OFF_MAX &&
	    nr->sr_end + 1 == r->sr_start) {
		nr->sr_end = r->sr_end;
		TAILQ_REMOVE(&so->so_shadow, r, sr_link);
		free(r);
	}
}

static void
dq_serve_shadow_free(struct dq_serve_owner *so)
{
	struct dq_serve_range *r;

	while ((r = TAILQ_FIRST(&so->so_shadow)) != NULL) {
		TAILQ_REMOVE(&so->so_shadow, r, sr_link);
		free(r);
	}
}

/*
 * A grant nobody asked for any more is taken back: [start, end] returns to
 * what the shadow says the owner held there before (an abandoned upgrade
 * keeps the old lock, as on a real file).  Each change only lowers a lock
 * this owner holds over the whole range, so none can block or conflict.
 * The mutex is held.
 */
static void
dq_serve_shadow_restore(int fd, const struct dq_serve_owner *so, off_t start,
    off_t end)
{
	const struct dq_serve_range *r;
	struct flock fl;
	off_t pos;

	pos = start;
	TAILQ_FOREACH(r, &so->so_shadow, sr_link) {
		if (r->sr_end < start)
			continue;
		if (r->sr_start > end)
			break;
		if (r->sr_start > pos) {
			dq_serve_range_flock(&fl, F_UNLCK, pos, r->sr_start - 1);
			(void)fcntl(fd, F_OFD_SETLK, &fl);
		}
		dq_serve_range_flock(&fl, r->sr_type, MAX(pos, r->sr_start),
		    MIN(end, r->sr_end));
		(void)fcntl(fd, F_OFD_SETLK, &fl);
		if (r->sr_end >= end)
			return;
		pos = r->sr_end + 1;
	}
	dq_serve_range_flock(&fl, F_UNLCK, pos, end);
	(void)fcntl(fd, F_OFD_SETLK, &fl);
}

/*
 * The pid of the served POSIX owner whose locks are the blocker F_GETLK
 * reported (type, [start, end]: lockf reports an OFD owner's whole run of
 * one type), or -1: a flock or OFD owner, as a real file reports them.
 * The mutex is held.
 */
static pid_t
dq_serve_blocker_pid(struct dq_serve_state *st, short type, off_t start,
    off_t end)
{
	const struct dq_serve_owner *so;
	const struct dq_serve_range *r;

	LIST_FOREACH(so, &st->ss_owners, so_link) {
		if (so->so_key.kind != DQ_LOCK_POSIX)
			continue;
		TAILQ_FOREACH(r, &so->so_shadow, sr_link) {
			if (r->sr_start > start)
				break;
			if (r->sr_start == start && r->sr_end == end &&
			    r->sr_type == type)
				return (so->so_pid);
		}
	}
	return (-1);
}

/*
 * Lock state
 */

struct dq_serve_state *
dq_serve_state_create(void)
{
	struct dq_serve_state *st;
	int error;

	st = calloc(1, sizeof(*st));
	if (st == NULL)
		return (NULL);
	error = pthread_mutex_init(&st->ss_mtx, NULL);
	if (error == 0) {
		error = pthread_cond_init(&st->ss_cv, NULL);
		if (error != 0)
			(void)pthread_mutex_destroy(&st->ss_mtx);
	}
	if (error != 0) {
		free(st);
		errno = error;
		return (NULL);
	}
	LIST_INIT(&st->ss_owners);
	LIST_INIT(&st->ss_waits);
	return (st);
}

/* The mutex is held; the wait unlinks itself from its cleanup handler. */
static void
dq_serve_wait_cancel(struct dq_serve_wait *w)
{

	(void)pthread_cancel(w->sw_thr);
}

/*
 * The mutex is held.  Owners are opens: closing one releases its locks.
 * The owner leaves the table first, so no new SETLKW joins it; its
 * threads are cancelled and waited for (each closes its own descriptor),
 * and only then is its open closed.  The wait drops the mutex.
 */
static void	dq_serve_owner_close(struct dq_serve_state *st,
		    struct dq_serve_owner *so) __requires_exclusive(st->ss_mtx);

static void
dq_serve_owner_close(struct dq_serve_state *st, struct dq_serve_owner *so)
{
	struct dq_serve_wait *w;

	LIST_REMOVE(so, so_link);
	st->ss_nowners--;
	while (so->so_nwaits > 0) {
		LIST_FOREACH(w, &st->ss_waits, sw_link) {
			if (w->sw_owner == so)
				dq_serve_wait_cancel(w);
		}
		pthread_cond_wait(&st->ss_cv, &st->ss_mtx);
	}
	(void)close(so->so_fd);
	dq_serve_shadow_free(so);
	free(so);
}

void
dq_serve_state_destroy(struct dq_serve_state *st)
{
	struct dq_serve_owner *so, *sotmp;
	struct dq_serve_wait *w;

	if (st == NULL)
		return;
	pthread_mutex_lock(&st->ss_mtx);
	LIST_FOREACH(w, &st->ss_waits, sw_link)
		dq_serve_wait_cancel(w);
	while (st->ss_nwaits > 0)
		pthread_cond_wait(&st->ss_cv, &st->ss_mtx);
	LIST_FOREACH_SAFE(so, &st->ss_owners, so_link, sotmp)
		dq_serve_owner_close(st, so);
	pthread_mutex_unlock(&st->ss_mtx);
	(void)pthread_cond_destroy(&st->ss_cv);
	(void)pthread_mutex_destroy(&st->ss_mtx);
	free(st);
}

int
dq_serve_state_owners(const struct dq_serve_state *st)
{
	struct dq_serve_state *s;
	int n;

	if (st == NULL)
		return (0);
	s = __DECONST(struct dq_serve_state *, st);
	pthread_mutex_lock(&s->ss_mtx);
	n = s->ss_nowners;
	pthread_mutex_unlock(&s->ss_mtx);
	return (n);
}

/*
 * The key of a lock owner.  The identity is the controller's copy when it
 * has one (what the kernel compares for siblings), else the backing file's.
 */
static int
dq_serve_key_make(struct dq_serve_key *k, uint32_t kind, uint64_t owner,
    uint64_t object, const struct dq_serve_opts *opts, int backing)
{
	struct stat sb;

	memset(k, 0, sizeof(*k));
	k->kind = kind;
	k->owner = owner;
	if (kind != DQ_LOCK_POSIX) {
		k->object = object;
		return (0);
	}
	if (opts != NULL && opts->so_ident != NULL) {
		k->dev = opts->so_ident->di_dev;
		k->ino = opts->so_ident->di_ino;
		return (0);
	}
	if (fstat(backing, &sb) == -1)
		return (-1);
	k->dev = (uint64_t)sb.st_dev;
	k->ino = (uint64_t)sb.st_ino;
	return (0);
}

static bool
dq_serve_key_eq(const struct dq_serve_key *a, const struct dq_serve_key *b)
{

	if (a->kind != b->kind || a->owner != b->owner)
		return (false);
	if (a->kind == DQ_LOCK_POSIX)
		return (a->dev == b->dev && a->ino == b->ino);
	return (a->object == b->object);
}

/*
 * A new open file description of the backing file's vnode (O_EMPTY_PATH),
 * read-write when the controller may, else read-only (a write lock then
 * fails as it would on a read-only descriptor).
 *
 * O_CLOFORK: an OFD lock lives while any descriptor of its open does.  A
 * copy inherited by a process the controller forks later (a requester,
 * typically) would keep the owner's locks after UNLOCK_ALL closed ours,
 * and a requester could wait on a lock its own inherited copy holds.
 */
static int
dq_serve_open_backing(int backing)
{
	int fd;

	fd = openat(backing, "", O_RDWR | O_EMPTY_PATH | O_CLOEXEC |
	    O_CLOFORK);
	if (fd == -1 && (errno == EACCES || errno == EPERM || errno == EROFS ||
	    errno == EISDIR))
		fd = openat(backing, "", O_RDONLY | O_EMPTY_PATH | O_CLOEXEC |
		    O_CLOFORK);
	return (fd);
}

/*
 * The owner's open, made on first use when create is set (SETLK and
 * SETLKW only; a GETLK or an UNLCK by an owner that holds nothing makes
 * none).  The mutex is held.
 */
static struct dq_serve_owner *
dq_serve_owner_get(struct dq_serve_state *st, int backing,
    const struct dq_serve_key *k, pid_t pid, bool create)
{
	struct dq_serve_owner *so;
	int fd;

	LIST_FOREACH(so, &st->ss_owners, so_link) {
		if (dq_serve_key_eq(&so->so_key, k))
			return (so);
	}
	if (!create)
		return (NULL);
	fd = dq_serve_open_backing(backing);
	if (fd == -1)
		return (NULL);
	so = calloc(1, sizeof(*so));
	if (so == NULL) {
		(void)close(fd);
		errno = ENOMEM;
		return (NULL);
	}
	so->so_key = *k;
	so->so_fd = fd;
	so->so_pid = k->kind == DQ_LOCK_POSIX ? pid : -1;
	TAILQ_INIT(&so->so_shadow);
	LIST_INSERT_HEAD(&st->ss_owners, so, so_link);
	st->ss_nowners++;
	return (so);
}

static void
dq_serve_flock_from_body(const struct dq_lock_body *lb, struct flock *fl)
{

	memset(fl, 0, sizeof(*fl));
	fl->l_type = (short)lb->dl_type;
	fl->l_whence = SEEK_SET;
	fl->l_start = lb->dl_start;
	fl->l_len = lb->dl_len;
}

/*
 * Cleanup of a SETLKW thread, on completion or cancellation: its own
 * descriptor goes (the owner's open stays, held by the owner), then the
 * owner's count, which its close may be waiting for.
 */
static void
dq_serve_wait_unlink(void *arg)
{
	struct dq_serve_wait *w = arg;
	struct dq_serve_state *st = w->sw_state;

	(void)close(w->sw_dupfd);
	pthread_mutex_lock(&st->ss_mtx);
	LIST_REMOVE(w, sw_link);
	st->ss_nwaits--;
	w->sw_owner->so_nwaits--;
	pthread_cond_broadcast(&st->ss_cv);
	pthread_mutex_unlock(&st->ss_mtx);
	dq_serve_spare_put(&w->sw_spare);
	free(w);
}

static void *
dq_serve_waiter(void *arg)
{
	struct dq_serve_wait *w = arg;
	struct dq_serve_state *st = w->sw_state;
	off_t start, end;
	int error, old, rv;

	pthread_cleanup_push(dq_serve_wait_unlink, w);
	/* The cancellation point: an INTERRUPT ends the wait here. */
	error = fcntl(w->sw_dupfd, F_OFD_SETLKW, &w->sw_fl) == -1 ? errno : 0;
	(void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old);
	start = w->sw_fl.l_start;
	end = dq_serve_range_end(w->sw_fl.l_start, w->sw_fl.l_len);
	/*
	 * The reply and the shadow under one hold of the mutex: a GETLK
	 * that finds this grant on the backing file names its owner.
	 */
	pthread_mutex_lock(&st->ss_mtx);
	rv = dq_reply(w->sw_q, w->sw_id, dq_serve_map(DQ_OP_LOCK, error), NULL,
	    0);
	if (rv == -1 && errno == ESRCH && error == 0) {
		/*
		 * Granted after the requester gave up (its INTERRUPT is on
		 * its way or already handled, the event is no longer in
		 * flight): nobody asked for this lock any more, so take it
		 * back on the owner's own open file (this thread's
		 * descriptor of it), to what the owner held there before.
		 */
		dq_serve_shadow_restore(w->sw_dupfd, w->sw_owner, start, end);
	} else if (error == 0)
		dq_serve_shadow_apply(w->sw_owner, start, end, w->sw_fl.l_type,
		    &w->sw_spare);
	pthread_mutex_unlock(&st->ss_mtx);
	pthread_cleanup_pop(1);
	return (NULL);
}

/* The mutex is held.  Returns 0 or an errno for the reply. */
static int
dq_serve_setlkw(struct dq_serve_state *st, int q, uint64_t id,
    const struct dq_lock_body *lb, const struct dq_serve_key *k,
    struct dq_serve_owner *so)
{
	struct dq_serve_wait *w;
	pthread_attr_t attr;
	int error;

	w = calloc(1, sizeof(*w));
	if (w == NULL)
		return (ENOLCK);
	if (dq_serve_spare_get(&w->sw_spare) != 0) {
		free(w);
		return (ENOLCK);
	}
	/* The same open file, so the same OFD owner: the owner's locks. */
	w->sw_dupfd = fcntl(so->so_fd, F_DUPFD_CLOEXEC, 0);
	if (w->sw_dupfd == -1) {
		dq_serve_spare_put(&w->sw_spare);
		free(w);
		return (ENOLCK);
	}
	w->sw_state = st;
	w->sw_owner = so;
	w->sw_id = id;
	w->sw_key = *k;
	w->sw_q = q;
	dq_serve_flock_from_body(lb, &w->sw_fl);
	LIST_INSERT_HEAD(&st->ss_waits, w, sw_link);
	st->ss_nwaits++;
	so->so_nwaits++;
	(void)pthread_attr_init(&attr);
	(void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	error = pthread_create(&w->sw_thr, &attr, dq_serve_waiter, w);
	(void)pthread_attr_destroy(&attr);
	if (error != 0) {
		LIST_REMOVE(w, sw_link);
		st->ss_nwaits--;
		so->so_nwaits--;
		(void)close(w->sw_dupfd);
		dq_serve_spare_put(&w->sw_spare);
		free(w);
		return (ENOLCK);
	}
	return (0);
}

/*
 * An exclusive flock(2) request that may wait (lf_setlock): taken at once
 * when nothing blocks it, converting the open file's shared lock in place;
 * when something does, the shared lock is dropped and the request waits.
 * Returns 0 (granted), EAGAIN (dropped; the caller starts the wait) or the
 * errno for the reply.  The mutex is held.
 */
static int
dq_serve_flock_upgrade(struct dq_serve_owner *so, struct flock *fl,
    struct dq_serve_spare *sp)
{
	struct flock unl;
	off_t end;

	end = dq_serve_range_end(fl->l_start, fl->l_len);
	if (fcntl(so->so_fd, F_OFD_SETLK, fl) == 0) {
		dq_serve_shadow_apply(so, fl->l_start, end, fl->l_type, sp);
		return (0);
	}
	if (errno != EAGAIN)
		return (errno);
	unl = *fl;
	unl.l_type = F_UNLCK;
	if (fcntl(so->so_fd, F_OFD_SETLK, &unl) == -1)
		return (errno);
	dq_serve_shadow_apply(so, fl->l_start, end, F_UNLCK, sp);
	return (EAGAIN);
}

static int
dq_serve_lock(int q, const struct dq_event *ev, const struct dq_lock_body *lb,
    int backing, const struct dq_serve_opts *opts)
{
	struct dq_serve_state *st;
	struct dq_serve_owner *so;
	struct dq_serve_spare sp;
	struct dq_serve_key k;
	struct dq_lock_reply lr;
	struct flock fl;
	int error, fd, rv;

	st = opts != NULL ? opts->so_state : NULL;
	if (st == NULL)
		return (dq_reply(q, ev->de_id, ENOLCK, NULL, 0));
	if (lb->dl_kind != DQ_LOCK_POSIX && lb->dl_kind != DQ_LOCK_FLOCK &&
	    lb->dl_kind != DQ_LOCK_OFD)
		return (dq_reply(q, ev->de_id, EINVAL, NULL, 0));
	if (dq_serve_key_make(&k, lb->dl_kind, lb->dl_owner, ev->de_object,
	    opts, backing) == -1)
		return (dq_reply(q, ev->de_id, ENOLCK, NULL, 0));
	dq_serve_flock_from_body(lb, &fl);
	/* What a shadow update may need, before anything is changed. */
	if (lb->dl_op != DQ_LOCK_GETLK && dq_serve_spare_get(&sp) != 0)
		return (dq_reply(q, ev->de_id, ENOLCK, NULL, 0));
	pthread_mutex_lock(&st->ss_mtx);
	switch (lb->dl_op) {
	case DQ_LOCK_GETLK:
		/*
		 * Asked through the owner's open when it has one (its own
		 * locks never block it), else through a temporary open
		 * closed at once: a query creates no owner.
		 */
		so = dq_serve_owner_get(st, backing, &k, lb->dl_pid, false);
		fd = so != NULL ? so->so_fd : dq_serve_open_backing(backing);
		if (fd == -1) {
			error = errno;
			pthread_mutex_unlock(&st->ss_mtx);
			return (dq_reply(q, ev->de_id,
			    dq_serve_map(DQ_OP_LOCK, error), NULL, 0));
		}
		rv = fcntl(fd, F_OFD_GETLK, &fl);
		error = rv == -1 ? errno : 0;
		if (so == NULL)
			(void)close(fd);
		memset(&lr, 0, sizeof(lr));
		if (rv == 0) {
			lr.dlr_type = (uint32_t)fl.l_type;
			if (fl.l_type != F_UNLCK) {
				lr.dlr_start = fl.l_start;
				lr.dlr_len = fl.l_len;
				/*
				 * The blocker's owner, as a real file names
				 * it: a real process's POSIX lock on the
				 * backing file carries its pid; the OFD
				 * locks proxied here carry none, and the
				 * shadows say which served owner holds
				 * the run (a POSIX owner's pid, else -1).
				 */
				lr.dlr_pid = fl.l_pid > 0 ? fl.l_pid :
				    dq_serve_blocker_pid(st, fl.l_type,
				    fl.l_start, dq_serve_range_end(fl.l_start,
				    fl.l_len));
			}
		}
		pthread_mutex_unlock(&st->ss_mtx);
		if (rv == -1)
			return (dq_reply(q, ev->de_id,
			    dq_serve_map(DQ_OP_LOCK, error), NULL, 0));
		return (dq_reply_lock(q, ev->de_id, &lr));
	case DQ_LOCK_SETLK:
	case DQ_LOCK_UNLCK:
		so = dq_serve_owner_get(st, backing, &k, lb->dl_pid,
		    lb->dl_op == DQ_LOCK_SETLK);
		if (so == NULL) {
			/* An unlock by an owner that holds nothing. */
			error = lb->dl_op == DQ_LOCK_UNLCK ? 0 : errno;
			break;
		}
		if (lb->dl_op == DQ_LOCK_UNLCK)
			fl.l_type = F_UNLCK;
		error = fcntl(so->so_fd, F_OFD_SETLK, &fl) == -1 ? errno : 0;
		if (error == 0)
			dq_serve_shadow_apply(so, fl.l_start,
			    dq_serve_range_end(fl.l_start, fl.l_len), fl.l_type,
			    &sp);
		break;
	case DQ_LOCK_SETLKW:
		so = dq_serve_owner_get(st, backing, &k, lb->dl_pid, true);
		if (so == NULL) {
			error = errno;
			break;
		}
		if (lb->dl_kind == DQ_LOCK_FLOCK && fl.l_type == F_WRLCK) {
			error = dq_serve_flock_upgrade(so, &fl, &sp);
			if (error != EAGAIN)
				break;		/* granted at once, or failed */
		}
		error = dq_serve_setlkw(st, q, ev->de_id, lb, &k, so);
		if (error == 0) {
			pthread_mutex_unlock(&st->ss_mtx);
			dq_serve_spare_put(&sp);
			return (0);	/* the thread answers */
		}
		break;
	default:
		error = EINVAL;
		break;
	}
	pthread_mutex_unlock(&st->ss_mtx);
	if (lb->dl_op != DQ_LOCK_GETLK)
		dq_serve_spare_put(&sp);
	return (dq_reply(q, ev->de_id, dq_serve_map(DQ_OP_LOCK, error), NULL, 0));
}


/*
 * UNLOCK_ALL {kind, owner}: that owner's open goes, and its locks with it.
 * For a POSIX owner that is its locks on the identity, whichever sibling
 * object the record came from.
 */
static void
dq_serve_unlock_all(const struct dq_event *ev,
    const struct dq_unlock_all_body *ub, int backing,
    const struct dq_serve_opts *opts)
{
	struct dq_serve_state *st;
	struct dq_serve_owner *so;
	struct dq_serve_key k;

	st = opts != NULL ? opts->so_state : NULL;
	if (st == NULL || dq_serve_key_make(&k, ub->dua_kind, ub->dua_owner,
	    ev->de_object, opts, backing) == -1)
		return;
	pthread_mutex_lock(&st->ss_mtx);
	LIST_FOREACH(so, &st->ss_owners, so_link) {
		if (dq_serve_key_eq(&so->so_key, &k)) {
			/* Its waits are cancelled and drained first. */
			dq_serve_owner_close(st, so);
			break;
		}
	}
	pthread_mutex_unlock(&st->ss_mtx);
}

static void
dq_serve_interrupt(struct dq_serve_state *st, uint64_t id)
{
	struct dq_serve_wait *w;

	if (st == NULL)
		return;
	pthread_mutex_lock(&st->ss_mtx);
	LIST_FOREACH(w, &st->ss_waits, sw_link) {
		if (w->sw_id == id) {
			dq_serve_wait_cancel(w);
			break;
		}
	}
	pthread_mutex_unlock(&st->ss_mtx);
}

/*
 * The object is gone: its flock and OFD owners (its open file) go.  POSIX
 * owners belong to the identity and are released by UNLOCK_ALL, which
 * the kernel posts at the close of any sibling.
 */
static void
dq_serve_close(struct dq_serve_state *st, uint64_t object)
{
	struct dq_serve_owner *so;

	if (st == NULL)
		return;
	pthread_mutex_lock(&st->ss_mtx);
	/*
	 * dq_serve_owner_close drops the mutex while it drains an owner's
	 * waits: the list may change under it, so look again from the
	 * start after each close.
	 */
restart:
	LIST_FOREACH(so, &st->ss_owners, so_link) {
		if (so->so_key.kind != DQ_LOCK_POSIX &&
		    so->so_key.object == object) {
			dq_serve_owner_close(st, so);
			goto restart;
		}
	}
	pthread_mutex_unlock(&st->ss_mtx);
}

/*
 * Identity
 */

/* Refresh the controller's identity copy from the backing file. */
static int
dq_serve_ident_refresh(int backing, struct dq_ident_file *ident)
{
	struct dq_ident_file *tmp;
	struct statfs sfs;
	struct stat sb;
	int error;

	if (fstat(backing, &sb) == -1 || fstatfs(backing, &sfs) == -1)
		return (-1);
	tmp = malloc(sizeof(*tmp));
	if (tmp == NULL)
		return (-1);
	if (dq_ident_from_stat(tmp, ident->di_path, &sb, &sfs, backing) == -1) {
		error = errno;
		free(tmp);
		errno = error;
		return (-1);
	}
	*ident = *tmp;
	free(tmp);
	return (0);
}

static int
dq_serve_ident_sync(int q, const struct dq_event *ev,
    const struct dq_serve_opts *opts, int backing)
{

	if (opts == NULL || opts->so_ident == NULL)
		return (0);
	if (dq_serve_ident_refresh(backing, opts->so_ident) == -1)
		return (-1);
	/*
	 * The operation was answered: an object the program closed since
	 * (ESRCH) has no identity left to follow, and that is no failure.
	 */
	if (dq_set_ident(q, ev->de_object, opts->so_ident) == -1 &&
	    errno != ESRCH)
		return (-1);
	return (0);
}

/*
 * Operations
 */

/* libdq.c: whether the kernel takes post-operation blocks. */
int	_dq_postop_probe(void) __hidden;


/*
 * A successful reply with the backing file's attributes after the
 * operation (DQ_REPLY_F_POSTOP): the kernel presents them, so fstat(2)
 * of the served file and stat(2) of the backing file agree (T-A02).  A
 * kernel without FEATURE(dq_postop) gets the reply without them, as does
 * one whose backing file cannot be asked, and stamps the times itself.
 * A kernel that has the feature and refuses the block refuses a reply
 * this code built wrong: that is the caller's error (dq_serve_failclosed
 * then answers EIO), and the next reply still carries a block.
 */
static int
dq_serve_reply_postop(int q, uint64_t id, int backing, const void *data,
    size_t len, uint32_t valid)
{
	struct dq_postop_attr pa;
	struct stat sb;

	switch (_dq_postop_probe()) {
	case -1:
		return (-1);	/* reported; dq_serve_failclosed answers EIO */
	case 2:
		return (dq_reply(q, id, 0, data, len));
	}
	if (fstat(backing, &sb) == -1)
		return (dq_reply(q, id, 0, data, len));
	dq_postop_from_stat(&pa, &sb, valid);
	return (dq_reply_postop(q, id, data, len, &pa));
}

static int
dq_serve_read(int q, const struct dq_event *ev, int backing)
{
	const struct dq_read_body *rb;
	char *buf;
	ssize_t n;
	int error, rv;

	if (dq_event_read(ev, &rb) != 0)
		return (dq_reply(q, ev->de_id, EIO, NULL, 0));
	buf = malloc(rb->dr_len != 0 ? rb->dr_len : 1);
	if (buf == NULL)
		return (dq_reply(q, ev->de_id, EIO, NULL, 0));
	n = pread(backing, buf, rb->dr_len, (off_t)rb->dr_offset);
	if (n == -1)
		rv = dq_reply(q, ev->de_id, errno, NULL, 0);
	else if (n > 0 && ev->de_op == DQ_OP_READ)
		/*
		 * The access time the read gave the backing file.  A
		 * READ_ASYNC (sendfile's pages) carries none: it has no
		 * post-operation block.
		 */
		rv = dq_serve_reply_postop(q, ev->de_id, backing, buf,
		    (size_t)n, DQ_PA_ATIME);
	else
		rv = dq_reply(q, ev->de_id, 0, buf, (size_t)n);
	error = errno;
	free(buf);
	errno = error;
	return (rv);
}

static int
dq_serve_getattr(int q, const struct dq_event *ev,
    const struct dq_serve_opts *opts, int backing)
{

	if (opts == NULL || opts->so_ident == NULL ||
	    dq_serve_ident_refresh(backing, opts->so_ident) == -1)
		return (dq_reply(q, ev->de_id, EIO, NULL, 0));
	return (dq_reply(q, ev->de_id, 0, opts->so_ident,
	    sizeof(*opts->so_ident)));
}

static int
dq_serve_write(int q, const struct dq_event *ev,
    const struct dq_serve_opts *opts, int backing)
{
	const struct dq_write_body *wb;
	struct dq_write_reply wr;
	const void *data;
	struct stat sb;
	size_t len;
	ssize_t n;
	off_t off;
	int error, rv;

	if (dq_event_write(ev, &wb, &data, &len) != 0)
		return (dq_reply(q, ev->de_id, EIO, NULL, 0));
	if ((wb->dw_flags & DQ_WRITE_F_APPEND) != 0) {
		/* The authoritative end of file is the backing file's. */
		if (fstat(backing, &sb) == -1)
			return (dq_reply(q, ev->de_id,
			    dq_serve_map(DQ_OP_WRITE, errno), NULL, 0));
		off = sb.st_size;
	} else
		off = (off_t)wb->dw_offset;
	n = pwrite(backing, data, len, off);
	if (n == -1)
		return (dq_reply(q, ev->de_id, dq_serve_map(DQ_OP_WRITE, errno),
		    NULL, 0));
	error = 0;
	if ((wb->dw_flags & DQ_WRITE_F_SYNC) != 0) {
		if (fsync(backing) == -1)
			error = errno;
	} else if ((wb->dw_flags & DQ_WRITE_F_DSYNC) != 0) {
		if (fdatasync(backing) == -1)
			error = errno;
	}
	if (error != 0)
		return (dq_reply(q, ev->de_id, dq_serve_map(DQ_OP_WRITE, error),
		    NULL, 0));
	if (ev->de_op == DQ_OP_WRITE) {
		wr.dwr_written = (uint64_t)n;
		wr.dwr_offset = (uint64_t)off;
		rv = dq_serve_reply_postop(q, ev->de_id, backing, &wr,
		    sizeof(wr), DQ_PA_SIZE | DQ_PA_MTIME | DQ_PA_CTIME |
		    DQ_PA_BLOCKS);
	} else
		rv = dq_reply_write(q, ev->de_id, (uint64_t)n, (uint64_t)off);
	/*
	 * Not after a WRITE_ASYNC: write-back of a mapping's pages runs from
	 * the page daemon and msync, and the size and times a mapping
	 * changes are the kernel's to present; the controller may SETIDENT.
	 */
	if (rv == 0 && opts != NULL && ev->de_op == DQ_OP_WRITE &&
	    (opts->so_flags & DQ_SERVE_F_SYNC_IDENT) != 0)
		rv = dq_serve_ident_sync(q, ev, opts, backing);
	return (rv);
}

/*
 * The masked fields in an order that lets them all apply: the size, mode
 * and owner first, the times, and the flags last (an immutable or append
 * flag set first would refuse the rest).  The birth time has no userland
 * setter; the kernel applied it to the identity already.
 */
static int
dq_serve_setattr(int q, const struct dq_event *ev,
    const struct dq_serve_opts *opts, int backing)
{
	const struct dq_setattr_body *sb;
	struct timespec ts[2];
	uid_t uid;
	gid_t gid;
	uint32_t mask;
	int error, rv;
	bool opath;

	if (dq_event_setattr(ev, &sb) != 0)
		return (dq_reply(q, ev->de_id, EIO, NULL, 0));
	mask = sb->dsa_mask;
	error = 0;
	/*
	 * An O_PATH backing descriptor (a served symbolic link, 1c-iii-b)
	 * takes the *at(fd, "", AT_EMPTY_PATH) forms, which change the node
	 * itself as lchmod(2) and friends do.
	 */
	opath = (fcntl(backing, F_GETFL) & O_PATH) != 0;
	if (error == 0 && (mask & DQ_SETATTR_SIZE) != 0 &&
	    ftruncate(backing, (off_t)sb->dsa_size) == -1)
		error = errno;
	if (error == 0 && (mask & DQ_SETATTR_MODE) != 0 &&
	    (opath ? fchmodat(backing, "", (mode_t)(sb->dsa_mode & ALLPERMS),
	    AT_EMPTY_PATH) :
	    fchmod(backing, (mode_t)(sb->dsa_mode & ALLPERMS))) == -1)
		error = errno;
	if (error == 0 && (mask & (DQ_SETATTR_UID | DQ_SETATTR_GID)) != 0) {
		uid = (mask & DQ_SETATTR_UID) != 0 ? (uid_t)sb->dsa_uid :
		    (uid_t)-1;
		gid = (mask & DQ_SETATTR_GID) != 0 ? (gid_t)sb->dsa_gid :
		    (gid_t)-1;
		if ((opath ? fchownat(backing, "", uid, gid, AT_EMPTY_PATH) :
		    fchown(backing, uid, gid)) == -1)
			error = errno;
	}
	if (error == 0 && (mask & (DQ_SETATTR_ATIME | DQ_SETATTR_MTIME)) != 0) {
		ts[0].tv_sec = sb->dsa_atime.tv_sec;
		ts[0].tv_nsec = (mask & DQ_SETATTR_ATIME) != 0 ?
		    sb->dsa_atime.tv_nsec : UTIME_OMIT;
		ts[1].tv_sec = sb->dsa_mtime.tv_sec;
		ts[1].tv_nsec = (mask & DQ_SETATTR_MTIME) != 0 ?
		    sb->dsa_mtime.tv_nsec : UTIME_OMIT;
		if ((opath ? utimensat(backing, "", ts, AT_EMPTY_PATH) :
		    futimens(backing, ts)) == -1)
			error = errno;
	}
	if (error == 0 && (mask & DQ_SETATTR_FLAGS) != 0 &&
	    (opath ? chflagsat(backing, "", sb->dsa_flags, AT_EMPTY_PATH) :
	    fchflags(backing, sb->dsa_flags)) == -1)
		error = errno;
	if (error != 0)
		return (dq_reply(q, ev->de_id, dq_serve_map(DQ_OP_SETATTR, error),
		    NULL, 0));
	rv = dq_reply(q, ev->de_id, 0, NULL, 0);
	if (rv == 0)
		rv = dq_serve_ident_sync(q, ev, opts, backing);
	return (rv);
}

/*
 * READDIR of a served directory (1c-iii-b): getdirentries(2) of the
 * backing directory from the cookie, which is its own offset; the cookie
 * after the records is the backing offset after them, and an empty read
 * is the end.  The records go as getdirentries returned them (the kernel
 * validates and zeroes their pads).
 */
static int
dq_serve_readdir(int q, const struct dq_event *ev, int backing)
{
	const struct dq_readdir_body *rb;
	char *buf;
	ssize_t n;
	off_t base, next;
	int error, rv;

	if (dq_event_readdir(ev, &rb) != 0)
		return (dq_reply(q, ev->de_id, EIO, NULL, 0));
	buf = malloc(rb->drd_len != 0 ? rb->drd_len : 1);
	if (buf == NULL)
		return (dq_reply(q, ev->de_id, EIO, NULL, 0));
	n = -1;
	if (lseek(backing, (off_t)rb->drd_cookie, SEEK_SET) != -1)
		n = getdirentries(backing, buf, rb->drd_len, &base);
	next = n >= 0 ? lseek(backing, 0, SEEK_CUR) : -1;
	if (n < 0 || next < 0) {
		error = dq_reply_errno_allowed(DQ_OP_READDIR, errno) ?
		    errno : EIO;
		rv = dq_reply(q, ev->de_id, error, NULL, 0);
	} else
		rv = dq_reply_readdir(q, ev->de_id, (uint64_t)next, n == 0,
		    buf, (size_t)n);
	error = errno;
	free(buf);
	errno = error;
	return (rv);
}

static int
dq_serve_fsync(int q, const struct dq_event *ev, int backing)
{
	const struct dq_fsync_body *fb;
	int error;

	if (dq_event_fsync(ev, &fb) != 0)
		return (dq_reply(q, ev->de_id, EIO, NULL, 0));
	if (fb->dfs_mode == DQ_FSYNC_DATA)
		error = fdatasync(backing) == -1 ? errno : 0;
	else
		error = fsync(backing) == -1 ? errno : 0;
	return (dq_reply(q, ev->de_id, dq_serve_map(DQ_OP_FSYNC, error), NULL,
	    0));
}

static int
dq_serve_fallocate(int q, const struct dq_event *ev,
    const struct dq_serve_opts *opts, int backing)
{
	const struct dq_fallocate_body *fb;
	int error, rv;

	if (dq_event_fallocate(ev, &fb) != 0)
		return (dq_reply(q, ev->de_id, EIO, NULL, 0));
	if (fb->dfa_offset > (uint64_t)OFF_MAX || fb->dfa_len > (uint64_t)OFF_MAX)
		error = EINVAL;
	else
		error = posix_fallocate(backing, (off_t)fb->dfa_offset,
		    (off_t)fb->dfa_len);
	if (error == 0)
		rv = dq_serve_reply_postop(q, ev->de_id, backing, NULL, 0,
		    DQ_PA_SIZE | DQ_PA_MTIME | DQ_PA_CTIME | DQ_PA_BLOCKS);
	else
		rv = dq_reply(q, ev->de_id, dq_serve_map(DQ_OP_FALLOCATE,
		    error), NULL, 0);
	if (rv == 0 && error == 0 && opts != NULL &&
	    (opts->so_flags & DQ_SERVE_F_SYNC_IDENT) != 0)
		rv = dq_serve_ident_sync(q, ev, opts, backing);
	return (rv);
}

static int
dq_serve_fspacectl(int q, const struct dq_event *ev,
    const struct dq_serve_opts *opts, int backing)
{
	const struct dq_fspacectl_body *sb;
	struct dq_fspacectl_reply sr;
	struct spacectl_range rqsr, rmsr;
	int rv;

	if (dq_event_fspacectl(ev, &sb) != 0)
		return (dq_reply(q, ev->de_id, EIO, NULL, 0));
	rqsr.r_offset = (off_t)sb->dsc_offset;
	rqsr.r_len = (off_t)sb->dsc_len;
	memset(&rmsr, 0, sizeof(rmsr));
	if (fspacectl(backing, (int)sb->dsc_cmd, &rqsr, (int)sb->dsc_flags,
	    &rmsr) == -1)
		return (dq_reply(q, ev->de_id,
		    dq_serve_map(DQ_OP_FSPACECTL, errno), NULL, 0));
	sr.dscr_offset = (uint64_t)rmsr.r_offset;
	sr.dscr_len = (uint64_t)rmsr.r_len;
	/* A deallocation changes no size: none is reported. */
	rv = dq_serve_reply_postop(q, ev->de_id, backing, &sr, sizeof(sr),
	    DQ_PA_MTIME | DQ_PA_CTIME | DQ_PA_BLOCKS);
	if (rv == 0 && opts != NULL &&
	    (opts->so_flags & DQ_SERVE_F_SYNC_IDENT) != 0)
		rv = dq_serve_ident_sync(q, ev, opts, backing);
	return (rv);
}

static int
dq_serve_ioctl(int q, const struct dq_event *ev,
    const struct dq_serve_opts *opts, int backing)
{
	const struct dq_ioctl_body *ib;
	const void *in;
	void *out;
	size_t inlen, outlen;
	int error, rv;

	if (dq_event_ioctl(ev, &ib, &in, &inlen) != 0)
		return (dq_reply(q, ev->de_id, EIO, NULL, 0));
	if (opts == NULL || opts->so_ioctl == NULL)
		return (dq_reply(q, ev->de_id, ENOTTY, NULL, 0));
	outlen = (ib->dio_cmd & IOC_OUT) != 0 ? IOCPARM_LEN(ib->dio_cmd) : 0;
	out = NULL;
	if (outlen != 0) {
		out = calloc(1, outlen);
		if (out == NULL)
			return (dq_reply(q, ev->de_id, EIO, NULL, 0));
	}
	error = opts->so_ioctl(backing, ib, in, out, outlen, opts->so_arg);
	if (error < 0)
		error = errno != 0 ? errno : EIO;
	error = dq_serve_map(DQ_OP_IOCTL, error);
	rv = dq_reply_ioctl(q, ev->de_id, error, error == 0 ? out : NULL,
	    error == 0 ? outlen : 0);
	error = errno;
	free(out);
	errno = error;
	return (rv);
}

/*
 * RESOLVE (stage 1c-i): PASS or an errno.  The M2 default under
 * DQ_SERVE_F_RESOLVE_STRICT: a consultation that is not the requester's
 * own path (a kernel consumer's, class 2, or a kernel-origin lookup, class
 * 3) is PASSed only for EXEC_INTERP (the interpreter of an image the
 * requester was allowed to exec) and refused with EACCES otherwise.  The
 * caller's handler, when set, decides everything else; an errno outside
 * the operation's RESOLVE allow-list is sent as EIO.  socket(2) and
 * socketpair(2) (DQ_ROP_SOCKET, DQ_ROP_SOCKETPAIR, class 1) are PASSed
 * unless the handler refuses them.
 */
static int
dq_serve_resolve(int q, const struct dq_event *ev,
    const struct dq_serve_opts *opts)
{
	const struct dq_resolve_body *rb;
	const char *path, *path2;
	int error;

	if (dq_event_resolve(ev, &rb, &path, &path2, NULL, NULL) != 0)
		return (dq_reply_resolve_errno(q, ev->de_id, EIO));
	error = 0;
	if (opts != NULL && (opts->so_flags & DQ_SERVE_F_RESOLVE_STRICT) != 0 &&
	    rb->drs_flags != DQ_RCLASS_USER && rb->drs_op != DQ_ROP_EXEC_INTERP)
		error = EACCES;
	else if (opts != NULL && opts->so_resolve != NULL)
		error = opts->so_resolve(ev, rb, path, path2,
		    opts->so_resolve_arg);
	if (error == 0)
		return (dq_reply_resolve_pass(q, ev->de_id));
	if (error < 0 || !dq_resolve_errno_allowed_ev(rb, error))
		error = EIO;
	return (dq_reply_resolve_errno(q, ev->de_id, error));
}

/*
 * A waited event whose answer was not delivered (the kernel refused the
 * reply body, EINVAL, and kept the event in flight; or the reply could not
 * be built) would hold its requester until the deadline.  Answer EIO so it
 * fails at once.  ESRCH means the event is gone (answered, or abandoned by
 * its requester): nothing is left to answer.  ret and errno pass through.
 */
static int
dq_serve_failclosed(int q, const struct dq_event *ev, int ret)
{
	int error;

	if (ret == 0 || ev->de_id == 0 || errno == ESRCH)
		return (ret);
	error = errno;
	(void)dq_reply(q, ev->de_id, EIO, NULL, 0);
	errno = error;
	return (ret);
}

static int
dq_serve_file_op(int q, const struct dq_event *ev, int backing_fd,
    const struct dq_serve_opts *opts)
{
	const struct dq_unlock_all_body *ub;
	const struct dq_interrupt_body *ib;
	const struct dq_lock_body *lb;
	struct dq_serve_state *st;

	st = opts != NULL ? opts->so_state : NULL;
	switch (ev->de_op) {
	case DQ_OP_READ:
	case DQ_OP_READ_ASYNC:		/* sendfile: answered as READ */
		return (dq_serve_read(q, ev, backing_fd));
	case DQ_OP_GETATTR:
		return (dq_serve_getattr(q, ev, opts, backing_fd));
	case DQ_OP_WRITE:
	case DQ_OP_WRITE_ASYNC:		/* write-back: pwrite at dw_offset */
		return (dq_serve_write(q, ev, opts, backing_fd));
	case DQ_OP_SETATTR:
		return (dq_serve_setattr(q, ev, opts, backing_fd));
	case DQ_OP_FSYNC:
		return (dq_serve_fsync(q, ev, backing_fd));
	case DQ_OP_FALLOCATE:
		return (dq_serve_fallocate(q, ev, opts, backing_fd));
	case DQ_OP_FSPACECTL:
		return (dq_serve_fspacectl(q, ev, opts, backing_fd));
	case DQ_OP_LOCK:
		if (dq_event_lock(ev, &lb) != 0)
			return (dq_reply(q, ev->de_id, EIO, NULL, 0));
		return (dq_serve_lock(q, ev, lb, backing_fd, opts));
	case DQ_OP_UNLOCK_ALL:
		if (dq_event_unlock_all(ev, &ub) == 0)
			dq_serve_unlock_all(ev, ub, backing_fd, opts);
		return (0);
	case DQ_OP_IOCTL:
		return (dq_serve_ioctl(q, ev, opts, backing_fd));
	case DQ_OP_READDIR:
		return (dq_serve_readdir(q, ev, backing_fd));
	case DQ_OP_INTERRUPT:
		if (dq_event_interrupt(ev, &ib) == 0)
			dq_serve_interrupt(st, ib->din_id);
		return (0);
	case DQ_OP_RESOLVE:
		return (dq_serve_resolve(q, ev, opts));
	case DQ_OP_CLOSE:
		dq_serve_close(st, ev->de_object);
		return (0);
	default:
		/* An operation this routine does not know; never leave it waiting. */
		if (ev->de_id != 0)
			return (dq_reply(q, ev->de_id, EIO, NULL, 0));
		return (0);
	}
}

int
dq_serve_file(int q, const struct dq_event *ev, const void *body,
    size_t bodylen, int backing_fd, const struct dq_serve_opts *opts)
{

	(void)body;
	(void)bodylen;
	if (ev == NULL || ev->de_size < sizeof(*ev)) {
		errno = EINVAL;
		return (-1);
	}
	return (dq_serve_failclosed(q, ev,
	    dq_serve_file_op(q, ev, backing_fd, opts)));
}
