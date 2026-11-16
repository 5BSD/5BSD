/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The controller harness of the DescriptorQueue tests: reader threads that
 * answer from memory or through dq_serve_file(), forked requesters, and the
 * waits and oracle comparisons the tests share; see dq_test.h.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dq_test.h"

#define	DQT_READ_BUFSIZE	(65536 + 131072 + 128)	/* a whole max_io WRITE fits */
#define	DQT_POLL_MS		50

/*
 * Queue and controller threads
 */

static void
dqt_record_seq(struct dqt_ctl *c, uint64_t seq)
    __requires_exclusive(c->mtx)
{

	if (c->nseqs < DQT_MAX_SEQS)
		c->seqs[c->nseqs++] = seq;
	/* Online gap counting is only meaningful with one reader. */
	if (c->nthr == 1 && c->last_seq != 0 && seq != c->last_seq + 1)
		c->gaps++;
	if (seq > c->last_seq)
		c->last_seq = seq;
}

struct dqt_pending_reply {
	uint64_t	 id;
	int		 error;
	const void	*data;
	size_t		 len;
	/* Set: hand the record to dq_serve_file() instead of replying. */
	const struct dq_event *serve_ev;
	struct dqt_object *serve_obj;
};

/*
 * Record a stage 1b body on the object (and WRITE bodies on the controller)
 * for the tests' field assertions.  The mutex is held.
 */
static void
dqt_record_body(struct dqt_ctl *c, struct dqt_object *o,
    const struct dq_event *ev)
    __requires_exclusive(c->mtx)
{
	const struct dq_read_body *rbp;
	const struct dq_write_body *wb;
	const struct dq_setattr_body *sb;
	const struct dq_fsync_body *fb;
	const struct dq_fallocate_body *ab;
	const struct dq_fspacectl_body *pb;
	const struct dq_lock_body *lb;
	const struct dq_unlock_all_body *ub;
	const struct dq_ioctl_body *ib;
	const void *in;
	size_t inlen;

	switch (ev->de_op) {
	case DQ_OP_READ:
	case DQ_OP_READ_ASYNC:
		if (dq_event_read(ev, &rbp) == 0 && c->nrd < DQT_MAX_SEQS) {
			c->rd[c->nrd].object = ev->de_object;
			c->rd[c->nrd].offset = rbp->dr_offset;
			c->rd[c->nrd].len = rbp->dr_len;
			c->nrd++;
		}
		break;
	case DQ_OP_WRITE:
	case DQ_OP_WRITE_ASYNC:
		if (dq_event_write(ev, &wb, NULL, NULL) != 0)
			return;
		if (c->nwr < DQT_MAX_SEQS) {
			c->wr[c->nwr].object = ev->de_object;
			c->wr[c->nwr].offset = wb->dw_offset;
			c->wr[c->nwr].len = wb->dw_len;
			c->wr[c->nwr].flags = wb->dw_flags;
			c->nwr++;
		}
		if (o != NULL)
			o->last_write = *wb;
		break;
	case DQ_OP_SETATTR:
		if (o != NULL && dq_event_setattr(ev, &sb) == 0)
			o->last_setattr = *sb;
		break;
	case DQ_OP_FSYNC:
		if (o != NULL && dq_event_fsync(ev, &fb) == 0)
			o->last_fsync = *fb;
		break;
	case DQ_OP_FALLOCATE:
		if (o != NULL && dq_event_fallocate(ev, &ab) == 0)
			o->last_fallocate = *ab;
		break;
	case DQ_OP_FSPACECTL:
		if (o != NULL && dq_event_fspacectl(ev, &pb) == 0)
			o->last_fspacectl = *pb;
		break;
	case DQ_OP_LOCK:
		if (o != NULL && dq_event_lock(ev, &lb) == 0 &&
		    o->nlocks < DQT_MAX_LOCKS)
			o->locks[o->nlocks++] = *lb;
		break;
	case DQ_OP_UNLOCK_ALL:
		if (o != NULL && dq_event_unlock_all(ev, &ub) == 0 &&
		    o->nunlocks < DQT_MAX_LOCKS)
			o->unlocks[o->nunlocks++] = *ub;
		break;
	case DQ_OP_IOCTL:
		if (o != NULL && dq_event_ioctl(ev, &ib, &in, &inlen) == 0) {
			o->last_ioctl = *ib;
			memset(o->last_ioctl_in, 0, sizeof(o->last_ioctl_in));
			if (inlen != 0)
				memcpy(o->last_ioctl_in, in,
				    MIN(inlen, sizeof(o->last_ioctl_in)));
		}
		break;
	default:
		break;
	}
}

/*
 * Hold an event the test wants left unanswered.  The mutex is held.  The
 * length and offset of a READ/READ_ASYNC or WRITE/WRITE_ASYNC body are
 * kept, whatever the caller passed, so a test can answer it later.
 */
static void
dqt_hold_event(struct dqt_ctl *c, const struct dq_event *ev, uint32_t len,
    uint64_t offset)
    __requires_exclusive(c->mtx)
{
	const struct dq_read_body *rb;
	const struct dq_write_body *wb;

	if (dq_event_read(ev, &rb) == 0) {
		len = rb->dr_len;
		offset = rb->dr_offset;
	} else if (dq_event_write(ev, &wb, NULL, NULL) == 0) {
		len = wb->dw_len;
		offset = wb->dw_offset;
	}
	if (c->nheld < DQT_MAX_HELD) {
		c->held[c->nheld].id = ev->de_id;
		c->held[c->nheld].object = ev->de_object;
		c->held[c->nheld].op = ev->de_op;
		c->held[c->nheld].len = len;
		c->held[c->nheld].offset = offset;
		c->nheld++;
	}
}

static const struct dq_resolve_reply dqt_pass = { DQ_RESOLVE_PASS, 0 };

/* A RESOLVE: recorded; held, refused or PASSed.  The mutex is held. */
static bool
dqt_handle_resolve(struct dqt_ctl *c, const struct dq_event *ev,
    struct dqt_pending_reply *pr)
    __requires_exclusive(c->mtx)
{
	const struct dq_resolve_body *rb;
	const char *path, *path2, *sp2;
	struct dqt_resolve_seen *s;
	int error;

	pr->id = ev->de_id;
	pr->data = NULL;
	pr->len = 0;
	if (dq_event_resolve(ev, &rb, &path, &path2, NULL, &sp2) != 0) {
		pr->error = EIO;
		return (true);
	}
	if (c->nrs < DQT_MAX_RESOLVES) {
		s = &c->rs[c->nrs++];
		s->id = ev->de_id;
		s->op = rb->drs_op;
		s->cls = rb->drs_flags;
		s->rflags = rb->drs_rflags;
		s->mode = rb->drs_mode;
		s->syscall = rb->drs_syscall;
		s->caller_flags = ev->de_caller.dc_flags;
		s->pid = ev->de_caller.dc_pid;
		s->start_kind = rb->drs_start_kind;
		s->start2_kind = rb->drs_start2_kind;
		s->accept = rb->drs_accept;
		s->cmode = rb->drs_cmode;
		s->domain = rb->drs_domain;
		s->type = rb->drs_type;
		s->protocol = rb->drs_protocol;
		s->pathlen = rb->drs_pathlen;
		(void)strlcpy(s->startpath2, sp2, sizeof(s->startpath2));
		(void)strlcpy(s->path, path, sizeof(s->path));
		(void)strlcpy(s->path2, path2, sizeof(s->path2));
	}
	if ((c->resolve_hold_op != 0 && rb->drs_op == c->resolve_hold_op) ||
	    (c->resolve_hold_match[0] != '\0' &&
	    (strstr(path, c->resolve_hold_match) != NULL ||
	    strstr(path2, c->resolve_hold_match) != NULL))) {
		dqt_hold_event(c, ev, 0, 0);
		return (false);
	}
	error = rb->drs_op <= DQ_ROP_MAX ? c->resolve_errno[rb->drs_op] : 0;
	if (c->resolve_fail_match[0] != '\0' &&
	    (strstr(path, c->resolve_fail_match) != NULL ||
	    strstr(path2, c->resolve_fail_match) != NULL))
		error = c->resolve_fail_errno;
	pr->error = error;
	if (error == 0) {
		pr->data = &dqt_pass;
		pr->len = sizeof(dqt_pass);
	}
	return (true);
}

/* Decide one record under the mutex; the reply itself is made later. */
static bool
dqt_handle_record(struct dqt_ctl *c, const struct dq_event *ev,
    struct dqt_pending_reply *pr)
    __requires_exclusive(c->mtx)
{
	const struct dq_read_body *rb;
	const struct dq_interrupt_body *ib;
	struct dqt_object *o;
	size_t bodylen;
	const void *body;

	body = dq_event_body(ev, &bodylen);
	o = dqt_object_by_id(c, ev->de_object);
	if (o != NULL && o->fence) {
		/* A fence's records are its own: see dq_test.h. */
		dqt_record_seq(c, ev->de_seq);
		if (ev->de_op == DQ_OP_CLOSE)
			c->fence_closes++;
		if (ev->de_op != DQ_OP_READ || ev->de_id == 0)
			return (false);
		c->fence_reads++;
		pr->serve_ev = NULL;
		pr->serve_obj = NULL;
		pr->id = ev->de_id;
		pr->error = 0;
		pr->data = o->data;
		pr->len = o->len;
		return (true);
	}
	c->records++;
	if (ev->de_op <= DQ_OP_REPLY)
		c->events[ev->de_op]++;
	dqt_record_seq(c, ev->de_seq);
	c->last_caller = ev->de_caller;
	if (ev->de_op <= DQ_OP_REPLY) {
		c->op_seq[ev->de_op] = ev->de_seq;
		c->op_caller[ev->de_op] = ev->de_caller;
	}
	pr->serve_ev = NULL;
	pr->serve_obj = NULL;
	dqt_record_body(c, o, ev);

	/* An object with a backing file: dq_serve_file answers, unlocked. */
	if (o != NULL && o->backing != -1) {
		if (ev->de_op == DQ_OP_READ || ev->de_op == DQ_OP_READ_ASYNC)
			o->reads++;
		else if (ev->de_op == DQ_OP_GETATTR)
			o->getattrs++;
		else if (ev->de_op == DQ_OP_CLOSE)
			o->closes++;
		if (ev->de_op == DQ_OP_INTERRUPT && bodylen >= sizeof(*ib)) {
			ib = body;
			if (c->ninterrupted < DQT_MAX_INTERRUPTS)
				c->interrupted[c->ninterrupted++] = ib->din_id;
		}
		if (c->hold_replies && ev->de_id != 0) {
			dqt_hold_event(c, ev, 0, 0);
			return (false);
		}
		pr->serve_ev = ev;
		pr->serve_obj = o;
		return (true);
	}

	switch (ev->de_op) {
	case DQ_OP_READ:
	case DQ_OP_READ_ASYNC:	/* sendfile: answered as READ */
		if (o != NULL)
			o->reads++;
		if (bodylen < sizeof(*rb))
			return (false);
		rb = body;
		if (c->hold_replies) {
			if (c->nheld < DQT_MAX_HELD) {
				c->held[c->nheld].id = ev->de_id;
				c->held[c->nheld].object = ev->de_object;
				c->held[c->nheld].op = ev->de_op;
				c->held[c->nheld].len = rb->dr_len;
				c->held[c->nheld].offset = rb->dr_offset;
				c->nheld++;
			}
			return (false);
		}
		pr->id = ev->de_id;
		if (o == NULL) {
			pr->error = EIO;
			pr->len = 0;
		} else if (o->read_errno != 0) {
			pr->error = o->read_errno;
			pr->len = 0;
		} else {
			pr->error = 0;
			/* A short answer is the end of the file. */
			if (rb->dr_offset >= o->len)
				pr->len = 0;
			else
				pr->len = MIN((size_t)rb->dr_len,
				    o->len - (size_t)rb->dr_offset);
			pr->data = o->data + rb->dr_offset;
		}
		return (true);
	case DQ_OP_GETATTR:
		if (o != NULL)
			o->getattrs++;
		if (c->hold_replies) {
			if (c->nheld < DQT_MAX_HELD) {
				c->held[c->nheld].id = ev->de_id;
				c->held[c->nheld].object = ev->de_object;
				c->held[c->nheld].op = ev->de_op;
				c->held[c->nheld].len = 0;
				c->held[c->nheld].offset = 0;
				c->nheld++;
			}
			return (false);
		}
		pr->id = ev->de_id;
		if (o == NULL) {
			pr->error = EIO;
			pr->len = 0;
		} else {
			pr->error = 0;
			pr->data = &o->ident;
			pr->len = sizeof(o->ident);
		}
		return (true);
	case DQ_OP_CLOSE:
		if (o != NULL)
			o->closes++;
		return (false);
	case DQ_OP_INTERRUPT:
		if (bodylen >= sizeof(*ib)) {
			ib = body;
			if (c->ninterrupted < DQT_MAX_INTERRUPTS)
				c->interrupted[c->ninterrupted++] = ib->din_id;
		}
		return (false);
	case DQ_OP_RESOLVE:
		return (dqt_handle_resolve(c, ev, pr));
	case DQ_OP_UNLOCK_ALL:
		return (false);
	default:
		/*
		 * A stage 1b event on a memory object: held when asked, else
		 * answered with the object's serve_errno (EIO, or ENOLCK for
		 * a lock, when none is set) and no body.
		 */
		if (ev->de_id == 0)
			return (false);
		if (c->hold_replies) {
			dqt_hold_event(c, ev, 0, 0);
			return (false);
		}
		pr->id = ev->de_id;
		pr->len = 0;
		pr->data = NULL;
		if (o != NULL && o->serve_errno != 0)
			pr->error = o->serve_errno;
		else
			pr->error = ev->de_op == DQ_OP_LOCK ? ENOLCK : EIO;
		return (true);
	}
}

static void
dqt_process_batch(struct dqt_ctl *c, const char *buf, size_t len)
{
	const struct dq_event *recs[DQT_READ_BUFSIZE / sizeof(struct dq_event)];
	struct dqt_pending_reply replies[nitems(recs)];
	const struct dq_event *ev;
	int delay, i, n, nreplies, step, start;

	n = 0;
	for (ev = dq_event_first(buf, len); ev != NULL;
	    ev = dq_event_next(buf, len, ev)) {
		if ((size_t)n < nitems(recs))
			recs[n++] = ev;
	}

	pthread_mutex_lock(&c->mtx);
	c->reads++;
	if (c->paused)
		c->paused_reads++;
	nreplies = 0;
	/* Reverse the batch when asked: the replies land last first. */
	if (c->order == DQT_ORDER_REVERSE) {
		start = n - 1;
		step = -1;
	} else {
		start = 0;
		step = 1;
	}
	for (i = start; i >= 0 && i < n; i += step) {
		if (dqt_handle_record(c, recs[i], &replies[nreplies]))
			nreplies++;
	}
	delay = c->reply_delay_ms;
	pthread_mutex_unlock(&c->mtx);

	if (nreplies == 0)
		return;
	if (delay > 0)
		dqt_msleep(delay);
	for (i = 0; i < nreplies; i++) {
		if (replies[i].serve_ev != NULL) {
			struct dqt_object *so = replies[i].serve_obj;
			const void *sbody;
			size_t sbodylen;
			int rv, serr;

			sbody = dq_event_body(replies[i].serve_ev, &sbodylen);
			rv = dq_serve_file(c->q, replies[i].serve_ev, sbody,
			    sbodylen, so->backing, &so->sopts);
			serr = errno;
			pthread_mutex_lock(&c->mtx);
			so->served++;
			if (rv == -1) {
				so->serve_failures++;
				c->reply_failures++;
				c->last_reply_errno = serr;
			}
			pthread_mutex_unlock(&c->mtx);
			continue;
		}
		if (dq_reply(c->q, replies[i].id, replies[i].error,
		    replies[i].data, replies[i].len) == -1) {
			pthread_mutex_lock(&c->mtx);
			c->reply_failures++;
			c->last_reply_errno = errno;
			pthread_mutex_unlock(&c->mtx);
		}
	}
}

static void
dqt_batch_done(struct dqt_ctl *c)
{

	pthread_mutex_lock(&c->mtx);
	c->inbatch--;
	pthread_cond_broadcast(&c->cv);
	pthread_mutex_unlock(&c->mtx);
}

static void *
dqt_reader(void *arg)
{
	struct dqt_reader_arg *ra = arg;
	struct dqt_ctl *c = ra->c;
	struct pollfd pfd;
	struct timespec ts;
	char *buf;
	ssize_t got;
	int err, q;

	buf = malloc(DQT_READ_BUFSIZE);
	if (buf == NULL)
		return (NULL);
	for (;;) {
		pthread_mutex_lock(&c->mtx);
		while (c->paused && !c->stop) {
			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_nsec += DQT_POLL_MS * 1000000L;
			if (ts.tv_nsec >= 1000000000L) {
				ts.tv_sec++;
				ts.tv_nsec -= 1000000000L;
			}
			pthread_cond_timedwait(&c->cv, &c->mtx, &ts);
		}
		q = c->q;
		if (c->stop || q == -1) {
			pthread_mutex_unlock(&c->mtx);
			break;
		}
		pthread_mutex_unlock(&c->mtx);

		pfd.fd = q;
		pfd.events = POLLIN;
		pfd.revents = 0;
		if (poll(&pfd, 1, DQT_POLL_MS) <= 0)
			continue;
		if ((pfd.revents & (POLLIN | POLLHUP)) == 0)
			continue;
		/*
		 * A pause set while this thread was in poll: go back and park
		 * rather than read what a test wants left on the queue.
		 */
		pthread_mutex_lock(&c->mtx);
		if (c->paused) {
			pthread_mutex_unlock(&c->mtx);
			continue;
		}
		/* From here to the last reply: dqt_pause waits for it. */
		c->inbatch++;
		pthread_mutex_unlock(&c->mtx);
		/*
		 * The queue is non-blocking: with two readers both wake on
		 * poll and the loser must not sleep in read(2) forever.
		 */
		if (dq_read_events(q, buf, DQT_READ_BUFSIZE, &got) == -1) {
			err = errno;
			dqt_batch_done(c);
			if (err == EAGAIN || err == EINTR)
				continue;
			break;	/* ENXIO: the queue is gone */
		}
		pthread_mutex_lock(&c->mtx);
		c->thr_batches[ra->idx]++;
		pthread_mutex_unlock(&c->mtx);
		dqt_process_batch(c, buf, (size_t)got);
		dqt_batch_done(c);
	}
	free(buf);
	return (NULL);
}

void
dqt_init_manual(struct dqt_ctl *c)
{
	int i;

	memset(c, 0, sizeof(*c));
	c->q = dqt_open_queue();
	ATF_REQUIRE_EQ(0, pthread_mutex_init(&c->mtx, NULL));
	ATF_REQUIRE_EQ(0, pthread_cond_init(&c->cv, NULL));
	for (i = 0; i < DQT_MAX_OBJECTS; i++)
		c->objs[i].fd = -1;
}

void
dqt_start(struct dqt_ctl *c, int nreaders)
{
	int flags, i;

	ATF_REQUIRE(nreaders >= 1 && nreaders <= DQT_READERS_MAX);
	flags = fcntl(c->q, F_GETFL);
	ATF_REQUIRE(flags != -1);
	ATF_REQUIRE_EQ(0, fcntl(c->q, F_SETFL, flags | O_NONBLOCK));
	c->nthr = nreaders;
	for (i = 0; i < nreaders; i++) {
		c->rarg[i].c = c;
		c->rarg[i].idx = i;
		ATF_REQUIRE_EQ(0, pthread_create(&c->thr[i], NULL, dqt_reader,
		    &c->rarg[i]));
	}
}

void
dqt_init(struct dqt_ctl *c)
{

	dqt_init_manual(c);
	dqt_start(c, 1);
}

void
dqt_stop(struct dqt_ctl *c)
{
	int i;

	pthread_mutex_lock(&c->mtx);
	c->stop = true;
	pthread_cond_broadcast(&c->cv);
	pthread_mutex_unlock(&c->mtx);
	for (i = 0; i < c->nthr; i++)
		(void)pthread_join(c->thr[i], NULL);
	c->nthr = 0;
}

void
dqt_close_queue(struct dqt_ctl *c)
{

	dqt_stop(c);
	if (c->q != -1) {
		(void)close(c->q);
		c->q = -1;
	}
}

void
dqt_fini(struct dqt_ctl *c)
{
	int i, n;

	dqt_stop(c);
	pthread_mutex_lock(&c->mtx);
	n = c->nobjs;
	pthread_mutex_unlock(&c->mtx);
	for (i = 0; i < n; i++) {
		if (c->objs[i].fd != -1) {
			(void)close(c->objs[i].fd);
			c->objs[i].fd = -1;
		}
		c->objs[i].lockstate = NULL;
	}
	if (c->lockstate != NULL) {
		dq_serve_state_destroy(c->lockstate);
		c->lockstate = NULL;
	}
	if (c->q != -1) {
		(void)close(c->q);
		c->q = -1;
	}
	pthread_cond_destroy(&c->cv);
	pthread_mutex_destroy(&c->mtx);
}

/*
 * A lock taken twice (EDEADLK from the error-checking mutex) or released
 * unheld (EPERM) is a test bug that would read state unlocked: abort.
 */
void
dqt_lock(struct dqt_ctl *c)
{
	int error;

	error = pthread_mutex_lock(&c->mtx);
	if (error != 0) {
		fprintf(stderr, "dqt_lock: %s\n", strerror(error));
		abort();
	}
}

void
dqt_unlock(struct dqt_ctl *c)
{
	int error;

	error = pthread_mutex_unlock(&c->mtx);
	if (error != 0) {
		fprintf(stderr, "dqt_unlock: %s\n", strerror(error));
		abort();
	}
}

unsigned
dqt_events(struct dqt_ctl *c, uint32_t op)
{
	unsigned n;

	ATF_REQUIRE(op <= DQ_OP_REPLY);
	pthread_mutex_lock(&c->mtx);
	n = c->events[op];
	pthread_mutex_unlock(&c->mtx);
	return (n);
}

void
dqt_set_order(struct dqt_ctl *c, enum dqt_order order)
{

	pthread_mutex_lock(&c->mtx);
	c->order = order;
	pthread_mutex_unlock(&c->mtx);
}

void
dqt_set_reply_delay(struct dqt_ctl *c, int ms)
{

	pthread_mutex_lock(&c->mtx);
	c->reply_delay_ms = ms;
	pthread_mutex_unlock(&c->mtx);
}

void
dqt_resolve_fail(struct dqt_ctl *c, const char *match, int error)
{

	pthread_mutex_lock(&c->mtx);
	if (match != NULL)
		(void)strlcpy(c->resolve_fail_match, match,
		    sizeof(c->resolve_fail_match));
	c->resolve_fail_errno = error;
	pthread_mutex_unlock(&c->mtx);
	ATF_REQUIRE(match == NULL || strlen(match) < DQT_RPATH);
}

void
dqt_resolve_hold(struct dqt_ctl *c, const char *match, uint32_t op)
{

	pthread_mutex_lock(&c->mtx);
	(void)strlcpy(c->resolve_hold_match, match != NULL ? match : "",
	    sizeof(c->resolve_hold_match));
	c->resolve_hold_op = op;
	pthread_mutex_unlock(&c->mtx);
	ATF_REQUIRE(match == NULL || strlen(match) < DQT_RPATH);
}

void
dqt_resolve_errno(struct dqt_ctl *c, uint32_t op, int error)
{

	ATF_REQUIRE(op <= DQ_ROP_MAX);
	pthread_mutex_lock(&c->mtx);
	c->resolve_errno[op] = error;
	pthread_mutex_unlock(&c->mtx);
}

void
dqt_object_serve_errno(struct dqt_ctl *c, struct dqt_object *o, int error)
{

	pthread_mutex_lock(&c->mtx);
	o->serve_errno = error;
	pthread_mutex_unlock(&c->mtx);
}

void
dqt_object_read_errno(struct dqt_ctl *c, struct dqt_object *o, int error)
{

	pthread_mutex_lock(&c->mtx);
	o->read_errno = error;
	pthread_mutex_unlock(&c->mtx);
}

void
dqt_pause(struct dqt_ctl *c)
{

	pthread_mutex_lock(&c->mtx);
	c->paused = true;
	/*
	 * A reader already past the check finishes its current batch,
	 * replies (and any reply_delay_ms) included; none starts another.
	 */
	while (c->inbatch > 0)
		pthread_cond_wait(&c->cv, &c->mtx);
	pthread_mutex_unlock(&c->mtx);
}

void
dqt_resume(struct dqt_ctl *c)
{

	pthread_mutex_lock(&c->mtx);
	c->paused = false;
	pthread_cond_broadcast(&c->cv);
	pthread_mutex_unlock(&c->mtx);
}

void
dqt_hold(struct dqt_ctl *c, bool hold)
{

	pthread_mutex_lock(&c->mtx);
	c->hold_replies = hold;
	pthread_mutex_unlock(&c->mtx);
}

/*
 * Oracle and objects
 */

void
dqt_fill(unsigned char *buf, size_t len, unsigned seed)
{
	size_t i;
	uint32_t x;

	/* A small LCG: deterministic, no two objects alike. */
	x = seed * 2654435761u + 1;
	for (i = 0; i < len; i++) {
		x = x * 1103515245u + 12345u;
		buf[i] = (unsigned char)(x >> 16);
	}
}

int
dqt_make_rw(const char *name, const void *data, size_t len, char *path,
    size_t pathlen)
{
	int fd;

	fd = dqt_make_oracle(name, data, len, path, pathlen);
	(void)close(fd);
	fd = open(path, O_RDWR);
	ATF_REQUIRE_MSG(fd != -1, "open %s: %s", path, strerror(errno));
	return (fd);
}

void
dqt_fixture_init(struct dqt_fixture *f, const void *data, size_t len,
    char *backing_path, char *oracle_path, const struct dq_policy *pol,
    uint32_t mflags)
{

	f->backing = dqt_make_rw("backing", data, len, backing_path,
	    DQT_PATH_MAX);
	f->oracle = oracle_path == NULL ? -1 :
	    dqt_make_rw("oracle", data, len, oracle_path, DQT_PATH_MAX);
	dqt_init(&f->c);
	f->o = dqt_mint_backing(&f->c, f->backing, backing_path, pol, mflags);
}

void
dqt_fixture_fini(struct dqt_fixture *f)
{

	dqt_lock(&f->c);
	ATF_CHECK_EQ_MSG(0, f->c.reply_failures, "reply failures: last %d",
	    f->c.last_reply_errno);
	dqt_unlock(&f->c);
	dqt_fini(&f->c);
	(void)close(f->backing);
	if (f->oracle != -1)
		(void)close(f->oracle);
}

int
dqt_make_oracle(const char *name, const void *data, size_t len, char *path,
    size_t pathlen)
{
	const char *p;
	ssize_t n;
	size_t off;
	int fd;

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE_MSG(fd != -1, "open %s: %s", name, strerror(errno));
	p = data;
	for (off = 0; off < len; off += (size_t)n) {
		n = write(fd, p + off, len - off);
		ATF_REQUIRE_MSG(n > 0, "write %s: %s", name, strerror(errno));
	}
	ATF_REQUIRE_EQ(0, fsync(fd));
	ATF_REQUIRE_EQ(0, close(fd));
	/* The presented path must be absolute and normalized. */
	ATF_REQUIRE_MSG(realpath(name, path) != NULL, "realpath %s: %s", name,
	    strerror(errno));
	ATF_REQUIRE(strlen(path) < pathlen);
	/* Read-only, so F_GETFL of the oracle matches the served fd (I13). */
	fd = open(path, O_RDONLY);
	ATF_REQUIRE_MSG(fd != -1, "open %s: %s", path, strerror(errno));
	return (fd);
}

void
dqt_ident_of(int fd, const char *path, struct dq_ident_file *ident,
    struct stat *st, struct statfs *sfs)
{

	ATF_REQUIRE_EQ(0, fstat(fd, st));
	ATF_REQUIRE_EQ(0, fstatfs(fd, sfs));
	ATF_REQUIRE_MSG(dq_ident_from_stat(ident, path, st, sfs, fd) == 0,
	    "dq_ident_from_stat: %s", strerror(errno));
}

void
dqt_policy_write(struct dq_policy *pol)
{

	dq_policy_default(pol);
	pol->dp_write = DQ_EVENT;
}

/*
 * The object is filled before it is counted (under the mutex), so the
 * reader thread never sees one half made.
 */
static struct dqt_object *
dqt_mint_common(struct dqt_ctl *c, const struct dq_ident_file *ident,
    const struct dq_policy *pol, uint32_t mflags, const void *data,
    size_t len, int backing)
{
	struct dq_policy defpol;
	struct dqt_object *o;
	int reason, slot;

	if (pol == NULL) {
		dq_policy_default(&defpol);
		pol = &defpol;
	}
	/* Only this thread mints: the slot stays free until it is counted. */
	pthread_mutex_lock(&c->mtx);
	slot = c->nobjs;
	pthread_mutex_unlock(&c->mtx);
	ATF_REQUIRE(slot < DQT_MAX_OBJECTS);
	o = &c->objs[slot];
	memset(o, 0, sizeof(*o));
	o->ident = *ident;
	o->data = data;
	o->len = len;
	o->backing = backing;
	if (backing != -1) {
		if (c->lockstate == NULL)
			c->lockstate = dq_serve_state_create();
		ATF_REQUIRE(c->lockstate != NULL);
		o->lockstate = c->lockstate;
		o->sopts.so_state = o->lockstate;
		o->sopts.so_ident = &o->ident;
	}
	reason = DQ_REASON_NONE;
	ATF_REQUIRE_MSG(dq_mint_file_flags(c->q, ident, pol, mflags, &o->id,
	    &o->fd, &reason) == 0, "dq_mint_file: %s (reason %d)",
	    strerror(errno), reason);
	ATF_REQUIRE(o->fd >= 0);
	ATF_REQUIRE(o->id != 0);
	pthread_mutex_lock(&c->mtx);
	c->nobjs++;
	pthread_mutex_unlock(&c->mtx);
	return (o);
}

struct dqt_object *
dqt_mint_ident(struct dqt_ctl *c, const struct dq_ident_file *ident,
    const struct dq_policy *pol, const void *data, size_t len)
{

	return (dqt_mint_common(c, ident, pol, 0, data, len, -1));
}

struct dqt_object *
dqt_mint_ident_flags(struct dqt_ctl *c, const struct dq_ident_file *ident,
    const struct dq_policy *pol, uint32_t mflags, const void *data, size_t len)
{

	return (dqt_mint_common(c, ident, pol, mflags, data, len, -1));
}

struct dqt_object *
dqt_mint_backing(struct dqt_ctl *c, int backing_fd, const char *path,
    const struct dq_policy *pol, uint32_t mflags)
{
	struct dq_ident_file *ident;
	struct dq_policy wpol;
	struct dqt_object *o;
	struct statfs sfs;
	struct stat st;

	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	dqt_ident_of(backing_fd, path, ident, &st, &sfs);
	if (pol == NULL) {
		dqt_policy_write(&wpol);
		pol = &wpol;
	}
	o = dqt_mint_common(c, ident, pol, mflags, NULL, 0, backing_fd);
	free(ident);
	return (o);
}

struct dqt_object *
dqt_mint(struct dqt_ctl *c, int oracle_fd, const char *path, const void *data,
    size_t len, const struct dq_policy *pol)
{
	struct dq_ident_file *ident;
	struct dq_policy defpol;
	struct dqt_object *o;
	struct statfs sfs;
	struct stat st;

	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	dqt_ident_of(oracle_fd, path, ident, &st, &sfs);
	if (pol == NULL) {
		dq_policy_default(&defpol);
		pol = &defpol;
	}
	o = dqt_mint_ident(c, ident, pol, data, len);
	free(ident);
	return (o);
}

struct dqt_object *
dqt_object_by_id(struct dqt_ctl *c, uint64_t id)
    __requires_exclusive(c->mtx)
{
	int i;

	for (i = 0; i < c->nobjs; i++) {
		if (c->objs[i].id == id)
			return (&c->objs[i]);
	}
	return (NULL);
}

/*
 * Fences
 */

static const unsigned char dqt_fence_byte = 'f';

static void
dqt_fence_child(void *arg, void *result)
{
	struct dqt_rr *r = result;
	unsigned char b;

	r->rv = pread(*(int *)arg, &b, 1, 0);
	r->err = r->rv == -1 ? errno : 0;
}

/* A sentinel object presenting the identity of a file of its own. */
static struct dqt_object *
dqt_fence_mint(struct dqt_ctl *c, const char *name, uint32_t events)
{
	char path[DQT_PATH_MAX];
	struct dq_policy pol;
	struct dqt_object *o;
	int fd;

	fd = dqt_make_oracle(name, &dqt_fence_byte, 1, path, sizeof(path));
	dq_policy_default(&pol);
	pol.dp_events = events;
	o = dqt_mint(c, fd, path, &dqt_fence_byte, 1, &pol);
	(void)close(fd);
	pthread_mutex_lock(&c->mtx);
	o->fence = true;
	pthread_mutex_unlock(&c->mtx);
	return (o);
}

void
dqt_fence(struct dqt_ctl *c)
{
	struct dqt_rr r;
	unsigned before, after;
	bool paused;

	pthread_mutex_lock(&c->mtx);
	paused = c->paused;
	before = c->fence_reads;
	pthread_mutex_unlock(&c->mtx);
	ATF_REQUIRE_MSG(c->nthr == 1 && !paused, "a fence needs one reader "
	    "thread, not paused");
	if (c->fence_obj == NULL)
		c->fence_obj = dqt_fence_mint(c, "dqt-fence", 0);
	dqt_run_child(dqt_fence_child, &c->fence_obj->fd, &r, sizeof(r));
	ATF_REQUIRE_EQ_MSG(1, r.rv, "the fence's read: %s", strerror(r.err));
	pthread_mutex_lock(&c->mtx);
	after = c->fence_reads;
	pthread_mutex_unlock(&c->mtx);
	ATF_REQUIRE_MSG(after > before, "the fence's READ was answered but "
	    "not recorded");
}

static bool
dqt_cond_fence_closes(struct dqt_ctl *c, uintptr_t n,
    uintptr_t unused __unused)
    __requires_exclusive(c->mtx)
{

	return (c->fence_closes >= (unsigned)n);
}

void
dqt_close_fence(struct dqt_ctl *c)
{
	struct dqt_object *o;
	unsigned before;

	pthread_mutex_lock(&c->mtx);
	before = c->fence_closes;
	pthread_mutex_unlock(&c->mtx);
	o = dqt_fence_mint(c, "dqt-close-fence", DQ_EVENTS_CLOSE);
	ATF_REQUIRE_EQ(0, close(o->fd));
	o->fd = -1;
	ATF_REQUIRE_MSG(dqt_wait_cond(c, dqt_cond_fence_closes,
	    (uintptr_t)before + 1, 0, DQT_WAIT_MS), "the close fence's CLOSE "
	    "did not arrive");
}

/*
 * Requesters
 */

/*
 * The child's half: run fn, send the whole result and exit 0, or exit
 * DQT_EXIT_NORESULT when the result could not be sent.  A child that dies
 * in fn never writes, and its parent sees a short result.
 */
static void
dqt_child_run(int resfd, dqt_child_fn fn, void *arg)
{
	char result[DQT_RESULT_MAX];

	memset(result, 0, sizeof(result));
	fn(arg, result);
	_exit(write(resfd, result, sizeof(result)) == (ssize_t)sizeof(result) ?
	    0 : DQT_EXIT_NORESULT);
}

size_t
dqt_read_full(int fd, void *buf, size_t len)
{
	char *p;
	ssize_t n;
	size_t off;

	p = buf;
	for (off = 0; off < len; off += (size_t)n) {
		n = read(fd, p + off, len - off);
		if (n == -1 && errno == EINTR) {
			n = 0;
			continue;
		}
		if (n <= 0)
			break;
	}
	return (off);
}

const char *
dqt_status_str(int status, char *buf, size_t len)
{

	if (WIFEXITED(status))
		snprintf(buf, len, "exit %d", WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		snprintf(buf, len, "signal %d%s", WTERMSIG(status),
		    WCOREDUMP(status) ? " (core dumped)" : "");
	else
		snprintf(buf, len, "status %#x", status);
	return (buf);
}

void
dqt_run_ints(int q, dqt_int_fn fn, void *arg, int *res, int nres, uid_t uid,
    bool attach)
{
	int go[2], back[2], pd, status;
	size_t got, len;
	pid_t pid;
	char c;

	len = sizeof(int) * (size_t)nres;
	memset(res, 0, len);
	ATF_REQUIRE(pipe(go) == 0 && pipe(back) == 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int *r;

		(void)close(q);
		if (uid != (uid_t)-1 && (setgid(uid) != 0 || setuid(uid) != 0))
			_exit(2);
		r = calloc((size_t)nres, sizeof(int));
		if (r == NULL || read(go[0], &c, 1) != 1)
			_exit(1);
		fn(arg, r);
		_exit(write(back[1], r, len) == (ssize_t)len ? 0 :
		    DQT_EXIT_NORESULT);
	}
	/* Only the child holds the write ends: its death is an EOF here. */
	(void)close(go[0]);
	(void)close(back[1]);
	if (attach)
		ATF_REQUIRE_MSG(dq_attach(q, pd) == 0, "attach: %s",
		    strerror(errno));
	ATF_REQUIRE(write(go[1], "g", 1) == 1);
	got = dqt_read_full(back[0], res, len);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	(void)close(pd);
	(void)close(go[1]);
	(void)close(back[0]);
	dqt_require_exit0(status, "requester");
	ATF_REQUIRE_EQ(len, got);
}

bool
dqt_pred_current(const struct dq_stats *st, uintptr_t n)
{

	return (st->ds_queue_current >= n);
}

uint64_t
dqt_digest(const void *p, size_t len)
{
	const unsigned char *b = p;
	uint64_t h;
	size_t i;

	h = 14695981039346656037ULL;
	for (i = 0; i < len; i++) {
		h ^= b[i];
		h *= 1099511628211ULL;
	}
	return (h);
}

void
dqt_idle_spawn(struct dqt_idle *s, int rfflags, int pdflags,
    const char *exec_path, const char *exec_arg, dqt_idle_prep prep,
    void *arg)
{
	char b;
	int error;

	ATF_REQUIRE_EQ(0, pipe(s->go));
	if (rfflags != 0)
		s->pid = pdrfork(&s->pd, pdflags, rfflags);
	else
		s->pid = pdfork(&s->pd, pdflags);
	ATF_REQUIRE_MSG(s->pid != -1, "pdfork: %s", strerror(errno));
	if (s->pid != 0)
		return;
	(void)close(s->go[1]);
	if (prep != NULL && (error = prep(arg)) != 0)
		_exit(error);
	/*
	 * Not before the parent says so: a NOTE_EXEC filter added after the
	 * exec never reports it.
	 */
	if (read(s->go[0], &b, 1) != 1)
		_exit(exec_path != NULL ? 4 : 0);
	if (exec_path != NULL) {
		execl(exec_path, exec_path, exec_arg, (char *)NULL);
		_exit(3);
	}
	_exit(0);
}

void
dqt_idle_exec(struct dqt_idle *s)
{
	struct kevent kev;
	struct timespec ts = { 30, 0 };
	int kq;

	kq = kqueue();
	ATF_REQUIRE(kq != -1);
	EV_SET(&kev, s->pd, EVFILT_PROCDESC, EV_ADD, NOTE_EXEC | NOTE_EXIT, 0,
	    NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, &kev, 1, NULL, 0, NULL));
	ATF_REQUIRE_EQ(1, write(s->go[1], "g", 1));
	ATF_REQUIRE_EQ_MSG(1, kevent(kq, NULL, 0, &kev, 1, &ts),
	    "the target neither exec'd nor exited in 30 s");
	ATF_REQUIRE_MSG((kev.fflags & NOTE_EXIT) == 0 &&
	    (kev.fflags & NOTE_EXEC) != 0, "the target did not exec: %#x",
	    kev.fflags);
	(void)close(kq);
}

void
dqt_idle_end(struct dqt_idle *s)
{
	int status;

	(void)write(s->go[1], "x", 1);
	(void)pdkill(s->pd, SIGKILL);
	(void)pdwait(s->pd, &status, WEXITED, NULL, NULL);
	(void)close(s->pd);
	(void)close(s->go[0]);
	(void)close(s->go[1]);
}

void
dqt_child_read(void *arg, void *result)
{
	struct dqt_read_arg *a = arg;
	struct dqt_rr *r = result;
	unsigned char buf[4096];

	r->rv = read(a->fd, buf, MIN(a->len, sizeof(buf)));
	r->err = r->rv == -1 ? errno : 0;
}

void
dqt_require_exit0(int status, const char *what)
{
	char sbuf[64];

	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "%s: %s", what, dqt_status_str(status, sbuf, sizeof(sbuf)));
}

/*
 * The parent's half of collecting a result: got bytes arrived out of
 * resultlen.  A result is only trusted whole; a short one is zeroed so
 * that no assertion reads stale bytes.  A child that exited 0 without its
 * whole result is a harness failure, whatever the caller expects.
 */
static void
dqt_result_check(int status, size_t got, void *result, size_t resultlen)
{

	if (got == resultlen)
		return;
	memset(result, 0, resultlen);
	ATF_REQUIRE_MSG(!WIFEXITED(status) || WEXITSTATUS(status) != 0,
	    "requester exited 0 with %zu of %zu result bytes", got, resultlen);
}

void
dqt_spawn(struct dqt_child *ch, dqt_child_fn fn, void *arg)
{
	int pfd[2];

	ATF_REQUIRE_EQ(0, pipe(pfd));
	ch->pid = fork();
	ATF_REQUIRE_MSG(ch->pid != -1, "fork: %s", strerror(errno));
	if (ch->pid == 0) {
		(void)close(pfd[0]);
		dqt_child_run(pfd[1], fn, arg);
	}
	(void)close(pfd[1]);
	ch->pipefd = pfd[0];
}

int
dqt_wait(struct dqt_child *ch, void *result, size_t resultlen)
{
	size_t got;
	int status;

	ATF_REQUIRE(resultlen <= DQT_RESULT_MAX);
	got = dqt_read_full(ch->pipefd, result, resultlen);
	(void)close(ch->pipefd);
	ch->pipefd = -1;
	ATF_REQUIRE_MSG(waitpid(ch->pid, &status, 0) == ch->pid, "waitpid: %s",
	    strerror(errno));
	dqt_result_check(status, got, result, resultlen);
	return (status);
}

void
dqt_collect(struct dqt_child *ch, void *result, size_t resultlen)
{

	dqt_require_exit0(dqt_wait(ch, result, resultlen), "requester");
}

void
dqt_run_child(dqt_child_fn fn, void *arg, void *result, size_t resultlen)
{
	struct dqt_child ch;

	dqt_spawn(&ch, fn, arg);
	dqt_collect(&ch, result, resultlen);
}

/*
 * Waits and queries
 */

void
dqt_msleep(int ms)
{
	struct timespec ts;

	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (ms % 1000) * 1000000L;
	while (nanosleep(&ts, &ts) == -1 && errno == EINTR)
		continue;
}

bool
dqt_wait_wmesg(pid_t pid, const char *wmesg, int ms)
{
	struct kinfo_proc *kp;
	int64_t deadline;
	size_t len;
	int i, mib[4], n;
	bool found;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID | KERN_PROC_INC_THREAD;
	mib[3] = pid;
	deadline = dqt_now_ms() + ms;
	for (;;) {
		found = false;
		len = 0;
		if (sysctl(mib, nitems(mib), NULL, &len, NULL, 0) == 0 &&
		    len != 0) {
			len *= 2;
			kp = malloc(len);
			if (kp != NULL &&
			    sysctl(mib, nitems(mib), kp, &len, NULL, 0) == 0) {
				n = (int)(len / sizeof(*kp));
				for (i = 0; i < n && !found; i++)
					found = strcmp(kp[i].ki_wmesg,
					    wmesg) == 0;
			}
			free(kp);
		}
		if (found)
			return (true);
		if (dqt_now_ms() >= deadline)
			return (false);
		dqt_msleep(5);
	}
}

int64_t
dqt_now_ms(void)
{
	struct timespec ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

/* cond(c, a, b) under the lock, until it holds or ms have passed. */
bool
dqt_wait_cond(struct dqt_ctl *c, dqt_cond_fn cond, uintptr_t a, uintptr_t b,
    int ms)
{
	int64_t deadline;
	bool ok;

	deadline = dqt_now_ms() + ms;
	for (;;) {
		pthread_mutex_lock(&c->mtx);
		ok = cond(c, a, b);
		pthread_mutex_unlock(&c->mtx);
		if (ok || dqt_now_ms() >= deadline)
			return (ok);
		dqt_msleep(10);
	}
}

static bool
dqt_cond_events(struct dqt_ctl *c, uintptr_t op, uintptr_t n)
    __requires_exclusive(c->mtx)
{

	return (c->events[op] >= (unsigned)n);
}

static bool
dqt_cond_held(struct dqt_ctl *c, uintptr_t n, uintptr_t unused __unused)
    __requires_exclusive(c->mtx)
{

	return (c->nheld >= (int)n);
}

static bool
dqt_cond_interrupts(struct dqt_ctl *c, uintptr_t n, uintptr_t unused __unused)
    __requires_exclusive(c->mtx)
{

	return (c->ninterrupted >= (int)n);
}

bool
dqt_wait_events(struct dqt_ctl *c, uint32_t op, unsigned n, int ms)
{

	return (dqt_wait_cond(c, dqt_cond_events, op, n, ms));
}

bool
dqt_wait_held(struct dqt_ctl *c, int n, int ms)
{

	return (dqt_wait_cond(c, dqt_cond_held, (uintptr_t)n, 0, ms));
}

bool
dqt_wait_interrupts(struct dqt_ctl *c, int n, int ms)
{

	return (dqt_wait_cond(c, dqt_cond_interrupts, (uintptr_t)n, 0, ms));
}

static bool
dqt_cond_locks(struct dqt_ctl *c __unused, uintptr_t o, uintptr_t n)
    __requires_exclusive(c->mtx)
{

	return (((struct dqt_object *)o)->nlocks >= (int)n);
}

bool
dqt_wait_locks(struct dqt_ctl *c, struct dqt_object *o, int n, int ms)
{

	return (dqt_wait_cond(c, dqt_cond_locks, (uintptr_t)o, (uintptr_t)n,
	    ms));
}

void
dqt_stats2(struct dqt_ctl *c, struct dq_stats2 *st)
{

	ATF_REQUIRE_MSG(dq_get_stats2(c->q, st) == 0, "DQ_IOC_GET_STATS2: %s",
	    strerror(errno));
}

void
dqt_stats(struct dqt_ctl *c, struct dq_stats *st)
{

	ATF_REQUIRE_MSG(dq_get_stats(c->q, st) == 0, "DQ_IOC_GET_STATS: %s",
	    strerror(errno));
}

bool
dqt_wait_stats(struct dqt_ctl *c, dqt_stats_pred pred, uintptr_t arg, int ms)
{
	struct dq_stats st;
	int64_t deadline;

	deadline = dqt_now_ms() + ms;
	for (;;) {
		dqt_stats(c, &st);
		if (pred(&st, arg))
			return (true);
		if (dqt_now_ms() >= deadline)
			return (false);
		dqt_msleep(10);
	}
}

void
dqt_copy_helper(const atf_tc_t *tc, const char *prog, const char *name)
{
	char buf[8192], path[PATH_MAX];
	ssize_t n;
	int in, out;

	ATF_REQUIRE((size_t)snprintf(path, sizeof(path), "%s/%s",
	    atf_tc_get_config_var(tc, "srcdir"), prog) < sizeof(path));
	in = open(path, O_RDONLY);
	ATF_REQUIRE_MSG(in != -1, "%s: %s", path, strerror(errno));
	out = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	ATF_REQUIRE_MSG(out != -1, "%s: %s", name, strerror(errno));
	while ((n = read(in, buf, sizeof(buf))) > 0)
		ATF_REQUIRE_EQ(n, write(out, buf, (size_t)n));
	ATF_REQUIRE_MSG(n == 0, "%s: %s", path, strerror(errno));
	ATF_REQUIRE_EQ(0, close(in));
	ATF_REQUIRE_EQ(0, fchmod(out, 0755));
	ATF_REQUIRE_EQ(0, close(out));
}

/* As tests/sys/file/fsetattr_test.c mount_fdesc(), plus one option. */
void
dqt_mount_fdesc(const char *option)
{
	struct iovec iov[6];
	u_int n;

	ATF_REQUIRE_EQ(0, mkdir(DQT_FDESC_DIR, 0755));
	iov[0].iov_base = __DECONST(char *, "fstype");
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = __DECONST(char *, "fdescfs");
	iov[1].iov_len = sizeof("fdescfs");
	iov[2].iov_base = __DECONST(char *, "fspath");
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = __DECONST(char *, DQT_FDESC_DIR);
	iov[3].iov_len = sizeof(DQT_FDESC_DIR);
	n = 4;
	if (option != NULL) {
		/* A flag option: a name with an empty value. */
		iov[4].iov_base = __DECONST(char *, option);
		iov[4].iov_len = strlen(option) + 1;
		iov[5].iov_base = NULL;
		iov[5].iov_len = 0;
		n = 6;
	}
	if (nmount(iov, n, 0) != 0)
		atf_tc_fail("mount fdescfs: %s", strerror(errno));
}

void
dqt_umount_fdesc(void)
{

	(void)unmount(DQT_FDESC_DIR, MNT_FORCE);
}

bool
dqt_sysctl_get_uint(const char *name, u_int *value)
{
	size_t len;

	len = sizeof(*value);
	return (sysctlbyname(name, value, &len, NULL, 0) == 0);
}

void
dqt_sysctl_set_uint(const char *name, u_int value)
{

	ATF_REQUIRE_MSG(sysctlbyname(name, NULL, NULL, &value,
	    sizeof(value)) == 0, "sysctl %s=%u: %s", name, value,
	    strerror(errno));
}

/*
 * Comparisons
 */

#define	DQT_EQ(field)							\
	ATF_CHECK_EQ_MSG((long long)want->field, (long long)served->field,	\
	    "%s: served %lld want %lld", #field, (long long)served->field,	\
	    (long long)want->field)

void
dqt_check_stat_eq(const struct stat *served, const struct stat *want)
{

	DQT_EQ(st_dev);
	DQT_EQ(st_ino);
	DQT_EQ(st_nlink);
	DQT_EQ(st_mode);
	DQT_EQ(st_uid);
	DQT_EQ(st_gid);
	DQT_EQ(st_rdev);
	DQT_EQ(st_atim.tv_sec);
	DQT_EQ(st_atim.tv_nsec);
	DQT_EQ(st_mtim.tv_sec);
	DQT_EQ(st_mtim.tv_nsec);
	DQT_EQ(st_ctim.tv_sec);
	DQT_EQ(st_ctim.tv_nsec);
	DQT_EQ(st_birthtim.tv_sec);
	DQT_EQ(st_birthtim.tv_nsec);
	DQT_EQ(st_size);
	DQT_EQ(st_blocks);
	DQT_EQ(st_blksize);
	DQT_EQ(st_flags);
	DQT_EQ(st_gen);
	DQT_EQ(st_filerev);
	/*
	 * st_bsdflags is not part of the identity: the kernel answers 0
	 * for a served file (dq_ident_to_stat), where a real one carries
	 * SFBSD_MNTPOINT only for a mount point.
	 */
	ATF_CHECK_EQ_MSG(0, served->st_bsdflags, "st_bsdflags: served %#x",
	    served->st_bsdflags);
}

void
dqt_check_statfs_eq(const struct statfs *served, const struct statfs *want)
{

	/* The kernel forces f_version on both sides. */
	ATF_CHECK_EQ(STATFS_VERSION, served->f_version);
	DQT_EQ(f_type);
	DQT_EQ(f_flags);
	DQT_EQ(f_bsize);
	DQT_EQ(f_iosize);
	DQT_EQ(f_blocks);
	DQT_EQ(f_bfree);
	DQT_EQ(f_bavail);
	DQT_EQ(f_files);
	DQT_EQ(f_ffree);
	DQT_EQ(f_syncwrites);
	DQT_EQ(f_asyncwrites);
	DQT_EQ(f_syncreads);
	DQT_EQ(f_asyncreads);
	DQT_EQ(f_nvnodelistsize);
	DQT_EQ(f_namemax);
	DQT_EQ(f_owner);
	DQT_EQ(f_fsid.val[0]);
	DQT_EQ(f_fsid.val[1]);
	ATF_CHECK_STREQ(want->f_fstypename, served->f_fstypename);
	ATF_CHECK_STREQ(want->f_mntfromname, served->f_mntfromname);
	ATF_CHECK_STREQ(want->f_mntonname, served->f_mntonname);
}

/*
 * Pages
 */

static sigjmp_buf dqt_touch_jmp;
static volatile sig_atomic_t dqt_touch_sig;

static void
dqt_touch_handler(int sig)
{

	dqt_touch_sig = sig;
	siglongjmp(dqt_touch_jmp, 1);
}

int
dqt_touch(volatile unsigned char *p, bool write, unsigned char wval,
    unsigned char *val)
{
	struct sigaction sa, obus, osegv;
	unsigned char v;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = dqt_touch_handler;
	sigemptyset(&sa.sa_mask);
	(void)sigaction(SIGBUS, &sa, &obus);
	(void)sigaction(SIGSEGV, &sa, &osegv);
	dqt_touch_sig = 0;
	if (sigsetjmp(dqt_touch_jmp, 1) == 0) {
		if (write)
			*p = wval;
		v = *p;
		if (val != NULL)
			*val = v;
	}
	(void)sigaction(SIGBUS, &obus, NULL);
	(void)sigaction(SIGSEGV, &osegv, NULL);
	return (dqt_touch_sig);
}

void
dqt_sync_init(struct dqt_sync *s)
{

	ATF_REQUIRE_EQ(0, pipe(s->tochild));
	ATF_REQUIRE_EQ(0, pipe(s->toparent));
}

void
dqt_sync_post(int fd)
{
	char b;

	b = 's';
	(void)write(fd, &b, 1);
}

bool
dqt_sync_wait(int fd, int ms)
{
	struct pollfd pfd;
	char b;

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (poll(&pfd, 1, ms) != 1)
		return (false);
	return (read(fd, &b, 1) == 1);
}

/*
 * Resolution (1c)
 */

void
dqt_attach_spawn(struct dqt_ctl *c, struct dqt_achild *ch, dqt_child_fn fn,
    void *arg)
{
	int go[2], res[2];
	char b;

	ATF_REQUIRE_EQ(0, pipe(go));
	ATF_REQUIRE_EQ(0, pipe(res));
	ch->pid = pdfork(&ch->pd, 0);
	ATF_REQUIRE_MSG(ch->pid != -1, "pdfork: %s", strerror(errno));
	if (ch->pid == 0) {
		(void)close(go[1]);
		(void)close(res[0]);
		if (read(go[0], &b, 1) != 1)
			_exit(DQT_EXIT_NOGO);
		dqt_child_run(res[1], fn, arg);
	}
	(void)close(go[0]);
	(void)close(res[1]);
	ch->pipefd = res[0];
	ATF_REQUIRE_MSG(dq_attach(c->q, ch->pd) == 0, "DQ_IOC_ATTACH: %s",
	    strerror(errno));
	b = 'g';
	ATF_REQUIRE_EQ(1, write(go[1], &b, 1));
	(void)close(go[1]);
}

int
dqt_attach_wait(struct dqt_achild *ch, void *result, size_t resultlen)
{
	size_t got;
	int status;

	ATF_REQUIRE(resultlen <= DQT_RESULT_MAX);
	got = dqt_read_full(ch->pipefd, result, resultlen);
	(void)close(ch->pipefd);
	ch->pipefd = -1;
	ATF_REQUIRE_MSG(pdwait(ch->pd, &status, WEXITED, NULL, NULL) == 0,
	    "pdwait: %s", strerror(errno));
	(void)close(ch->pd);
	ch->pd = -1;
	dqt_result_check(status, got, result, resultlen);
	return (status);
}

void
dqt_attach_collect(struct dqt_achild *ch, void *result, size_t resultlen)
{

	dqt_require_exit0(dqt_attach_wait(ch, result, resultlen),
	    "attached requester");
}

void
dqt_attach_run(struct dqt_ctl *c, dqt_child_fn fn, void *arg, void *result,
    size_t resultlen)
{
	struct dqt_achild ch;

	dqt_attach_spawn(c, &ch, fn, arg);
	dqt_attach_collect(&ch, result, resultlen);
}

int
dqt_find_resolve(struct dqt_ctl *c, const char *match, uint32_t op, int from)
{
	int i, found;

	found = -1;
	pthread_mutex_lock(&c->mtx);
	for (i = from; i < c->nrs; i++) {
		if ((op == 0 || c->rs[i].op == op) &&
		    (strstr(c->rs[i].path, match) != NULL ||
		    strstr(c->rs[i].path2, match) != NULL)) {
			found = i;
			break;
		}
	}
	pthread_mutex_unlock(&c->mtx);
	return (found);
}

uint64_t
dqt_held_id(struct dqt_ctl *c, int i)
{
	uint64_t id;

	pthread_mutex_lock(&c->mtx);
	ATF_REQUIRE_MSG(i >= 0 && i < c->nheld, "held[%d] of %d", i, c->nheld);
	id = c->held[i].id;
	pthread_mutex_unlock(&c->mtx);
	return (id);
}

void
dqt_resolve_at(struct dqt_ctl *c, int i, struct dqt_resolve_seen *rs)
{

	pthread_mutex_lock(&c->mtx);
	ATF_REQUIRE_MSG(i >= 0 && i < c->nrs, "rs[%d] of %d", i, c->nrs);
	*rs = c->rs[i];
	pthread_mutex_unlock(&c->mtx);
}

int
dqt_count_resolve(struct dqt_ctl *c, const char *match, uint32_t op)
{
	int i, n;

	n = 0;
	pthread_mutex_lock(&c->mtx);
	for (i = 0; i < c->nrs; i++) {
		if ((op == 0 || c->rs[i].op == op) &&
		    (strstr(c->rs[i].path, match) != NULL ||
		    strstr(c->rs[i].path2, match) != NULL))
			n++;
	}
	pthread_mutex_unlock(&c->mtx);
	return (n);
}
