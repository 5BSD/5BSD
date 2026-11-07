/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue: observer descriptors (design 7.2).
 *
 * An observer receives a copy of every event posted on a queue and of
 * every reply, with the data bodies removed unless it was minted with
 * DQ_OBS_F_DATA (a separate right the holder cannot widen).  It is a
 * DTYPE_DEV descriptor with its own table, like the authority lease
 * control, so the served mark (DTYPE_DQ) stays the mark of an object.
 * Records are best effort: a copy that cannot be allocated under the
 * queue lock, or that would exceed the depth, is a counted drop with a
 * sequence gap, never a stall of the queue it watches.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/filio.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/selinfo.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/uio.h>
#include <sys/user.h>

#include <dev/dq/dq.h>
#include <dev/dq/dq_var.h>

/* fc_ioctls is freed by filecaps_free() with this type (kern_descrip.c). */
MALLOC_DECLARE(M_FILECAPS);

static fo_rdwr_t	dq_observer_read;
static fo_ioctl_t	dq_observer_ioctl;
static fo_poll_t	dq_observer_poll;
static fo_kqfilter_t	dq_observer_kqfilter;
static fo_stat_t	dq_observer_stat;
static fo_close_t	dq_observer_close;
static fo_fill_kinfo_t	dq_observer_fill_kinfo;

const struct fileops dq_observer_fileops = {
	.fo_read = dq_observer_read,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = dq_observer_ioctl,
	.fo_poll = dq_observer_poll,
	.fo_kqfilter = dq_observer_kqfilter,
	.fo_stat = dq_observer_stat,
	.fo_close = dq_observer_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_fill_kinfo = dq_observer_fill_kinfo,
	.fo_cmp = file_kcmp_generic,
	.fo_flags = DFLAG_PASSABLE,
};

struct dq_observer *
dq_observer_create(struct dq_queue *q, u_int flags)
{
	struct dq_observer *ob;

	ob = malloc(sizeof(*ob), M_DQ, M_WAITOK | M_ZERO);
	sx_init(&ob->ob_rdsx, "dq observer read");
	ob->ob_flags = flags;
	ob->ob_depth = dq_queue_depth;
	TAILQ_INIT(&ob->ob_pending);
	knlist_init_mtx(&ob->ob_sel.si_note, &q->q_mtx);
	dq_queue_hold(q);
	ob->ob_queue = q;
	DQ_LOCK(q);
	if ((q->q_flags & DQ_Q_CLOSING) != 0) {
		DQ_UNLOCK(q);
		knlist_destroy(&ob->ob_sel.si_note);
		sx_destroy(&ob->ob_rdsx);
		dq_queue_rele(q);
		free(ob, M_DQ);
		return (NULL);
	}
	LIST_INSERT_HEAD(&q->q_observers, ob, ob_link);
	q->q_nobservers++;
	DQ_UNLOCK(q);
	return (ob);
}

/* Read-only, GET_STATS only, never transferable, locked across fork/exec. */
int
dq_observer_install(struct thread *td, struct dq_observer *ob, int *fdp)
{
	struct fdinstall_prop prop = {
	    .fip_xfer_state = CAP_XFER_NONE,
	    .fip_cloexec_state = CAP_CLOEXEC_LOCKED,
	    .fip_clofork_state = CAP_CLOFORK_LOCKED };
	struct filecaps fcaps;
	struct file *fp;
	int error;

	error = falloc_noinstall(td, &fp);
	if (error != 0) {
		dq_observer_close_ob(ob);
		return (error);
	}
	filecaps_init(&fcaps);
	cap_rights_init(&fcaps.fc_rights, CAP_READ, CAP_EVENT, CAP_IOCTL,
	    CAP_FCNTL, CAP_FSTAT, CAP_KQUEUE_EVENT);
	fcaps.fc_fcntls = CAP_FCNTL_GETFL | CAP_FCNTL_SETFL;	/* O_NONBLOCK */
	fcaps.fc_ioctls = malloc(3 * sizeof(u_long), M_FILECAPS, M_WAITOK);
	fcaps.fc_ioctls[0] = DQ_IOC_GET_STATS;
	fcaps.fc_ioctls[1] = FIONBIO;
	fcaps.fc_ioctls[2] = FIOASYNC;
	fcaps.fc_nioctls = 3;
	finit(fp, FREAD, DTYPE_DEV, ob, &dq_observer_fileops);
	error = finstall_prop(td, fp, fdp, O_CLOEXEC | O_CLOFORK, &fcaps, &prop);
	if (error != 0)
		filecaps_free(&fcaps);
	fdrop(fp, td);	/* on failure dq_observer_close runs */
	return (error);
}

static void
dq_observer_free(struct dq_observer *ob)
{
	struct dq_queue *q;
	struct dq_obs_rec *rec, *tmp;

	q = ob->ob_queue;
	knlist_clear(&ob->ob_sel.si_note, 0);
	knlist_destroy(&ob->ob_sel.si_note);
	seldrain(&ob->ob_sel);
	TAILQ_FOREACH_SAFE(rec, &ob->ob_pending, or_link, tmp)
		free(rec, M_DQ);
	sx_destroy(&ob->ob_rdsx);
	free(ob, M_DQ);
	dq_queue_rele(q);
}

/* Unlink from the queue (idempotent) and free. */
void
dq_observer_close_ob(struct dq_observer *ob)
{
	struct dq_queue *q;

	q = ob->ob_queue;
	DQ_LOCK(q);
	if (!ob->ob_closed) {
		LIST_REMOVE(ob, ob_link);
		q->q_nobservers--;
		ob->ob_closed = true;
	}
	DQ_UNLOCK(q);
	dq_observer_free(ob);
}

static int
dq_observer_close(struct file *fp, struct thread *td __unused)
{
	struct dq_observer *ob = fp->f_data;

	fp->f_data = NULL;
	dq_observer_close_ob(ob);
	return (0);
}

/*
 * The queue is closing: detach every observer so it drains what it has
 * and then reads end of file.  The queue lock is held.
 */
void
dq_observer_unlink_all(struct dq_queue *q)
{
	struct dq_observer *ob, *tmp;

	DQ_LOCK_ASSERT(q);
	LIST_FOREACH_SAFE(ob, &q->q_observers, ob_link, tmp) {
		LIST_REMOVE(ob, ob_link);
		q->q_nobservers--;
		ob->ob_closed = true;
		wakeup(&ob->ob_pending);
		selwakeup(&ob->ob_sel);
		KNOTE_LOCKED(&ob->ob_sel.si_note, 0);
	}
}

/*
 * Fan-out, under q_mtx: M_NOWAIT copies, a failure or a full observer is
 * a counted drop.  ob_seq advances either way so the observer sees a gap.
 */
static void
dq_observer_deliver_locked(struct dq_queue *q, struct dq_observer *ob,
    const struct dq_event *hdr, const void *body, size_t bodylen,
    bool strip)
{
	struct dq_obs_rec *rec;
	size_t size;

	DQ_LOCK_ASSERT(q);
	ob->ob_seq++;
	size = sizeof(struct dq_event) + (strip ? 0 : bodylen);
	rec = (ob->ob_count < ob->ob_depth) ?
	    malloc(offsetof(struct dq_obs_rec, or_hdr) + size, M_DQ,
	    M_NOWAIT) : NULL;
	if (rec == NULL) {
		ob->ob_drops++;
		return;
	}
	rec->or_size = size;
	rec->or_hdr = *hdr;
	rec->or_hdr.de_size = size;
	rec->or_hdr.de_seq = ob->ob_seq;
	rec->or_hdr.de_flags |= DQ_EVENT_F_OBSERVED;
	if (strip && bodylen != 0)
		rec->or_hdr.de_flags |= DQ_EVENT_F_NODATA;
	if (!strip && bodylen != 0)
		memcpy((char *)&rec->or_hdr + sizeof(struct dq_event), body,
		    bodylen);
	TAILQ_INSERT_TAIL(&ob->ob_pending, rec, or_link);
	ob->ob_count++;
	wakeup(&ob->ob_pending);
	selwakeup(&ob->ob_sel);
	KNOTE_LOCKED(&ob->ob_sel.si_note, 0);
}

/*
 * Events: in stage 1a no event body carries requester data (READ asks
 * for an offset and a length), so events are copied whole; the data flag
 * matters for replies and for later stages' WRITE bodies.
 */
void
dq_observer_fanout_event(struct dq_queue *q, const struct dq_event_k *ev)
{
	struct dq_observer *ob;
	const void *body;
	size_t bodylen;
	bool data_body;

	if (LIST_EMPTY(&q->q_observers))
		return;
	body = (const char *)&ev->ev_hdr + sizeof(struct dq_event);
	bodylen = ev->ev_size - sizeof(struct dq_event);
	data_body = ev->ev_hdr.de_op == DQ_OP_WRITE ||
	    ev->ev_hdr.de_op == DQ_OP_WRITE_ASYNC;
	LIST_FOREACH(ob, &q->q_observers, ob_link) {
		dq_observer_deliver_locked(q, ob, &ev->ev_hdr, body, bodylen,
		    data_body && (ob->ob_flags & DQ_OBS_F_DATA) == 0);
	}
}

/*
 * Replies are recorded as DQ_OP_REPLY with the id, errno and length; the
 * data itself travels only to an observer minted with DQ_OBS_F_DATA, and
 * in stage 1a not even then (the reply buffer belongs to the waiter; a
 * data observer is a 1b item once the pager shares pages).  Lengths are
 * always visible (D41).
 */
void
dq_observer_fanout_reply(struct dq_queue *q, uint64_t id, int error,
    size_t len)
{
	struct dq_observer *ob;
	struct dq_event hdr;
	struct dq_reply_record rr;
	struct timespec ts;

	if (LIST_EMPTY(&q->q_observers))
		return;
	bzero(&hdr, sizeof(hdr));
	hdr.de_version = DQ_API_VERSION;
	hdr.de_op = DQ_OP_REPLY;
	hdr.de_id = id;
	nanouptime(&ts);
	hdr.de_time.tv_sec = ts.tv_sec;
	hdr.de_time.tv_nsec = ts.tv_nsec;
	rr.drr_id = id;
	rr.drr_errno = error;
	rr.drr_len = len;
	LIST_FOREACH(ob, &q->q_observers, ob_link)
		dq_observer_deliver_locked(q, ob, &hdr, &rr, sizeof(rr), false);
}

void
dq_observer_wakeup(struct dq_queue *q)
{
	struct dq_observer *ob;

	DQ_LOCK_ASSERT(q);
	LIST_FOREACH(ob, &q->q_observers, ob_link) {
		wakeup(&ob->ob_pending);
		selwakeup(&ob->ob_sel);
		KNOTE_LOCKED(&ob->ob_sel.si_note, 0);
	}
}

/* Whole records, as many as fit; a dead queue drains then reads EOF. */
static int
dq_observer_read(struct file *fp, struct uio *uio,
    struct ucred *active_cred __unused, int flags __unused, struct thread *td __unused)
{
	struct dq_observer *ob = fp->f_data;
	struct dq_queue *q = ob->ob_queue;
	struct dq_obs_rec *rec;
	int error;
	bool copied;

	if (uio->uio_resid < (ssize_t)sizeof(struct dq_event))
		return (EINVAL);
	copied = false;
	error = 0;
	sx_xlock(&ob->ob_rdsx);
	DQ_LOCK(q);
	while (TAILQ_EMPTY(&ob->ob_pending)) {
		if (ob->ob_closed)
			goto out;	/* EOF */
		if ((fp->f_flag & FNONBLOCK) != 0) {
			error = EAGAIN;
			goto out;
		}
		error = msleep(&ob->ob_pending, &q->q_mtx, PCATCH, "dqobrd", 0);
		if (error != 0)
			goto out;
	}
	while ((rec = TAILQ_FIRST(&ob->ob_pending)) != NULL) {
		if (uio->uio_resid < (ssize_t)rec->or_size) {
			if (!copied)
				error = ENOBUFS;
			break;
		}
		TAILQ_REMOVE(&ob->ob_pending, rec, or_link);
		ob->ob_count--;
		DQ_UNLOCK(q);
		error = uiomove(&rec->or_hdr, rec->or_size, uio);
		DQ_LOCK(q);
		if (error != 0) {
			/* Put it back: the reader is serialized by ob_rdsx. */
			TAILQ_INSERT_HEAD(&ob->ob_pending, rec, or_link);
			ob->ob_count++;
			if (copied)
				error = 0;
			break;
		}
		free(rec, M_DQ);
		copied = true;
	}
out:
	DQ_UNLOCK(q);
	sx_xunlock(&ob->ob_rdsx);
	return (error);
}

static int
dq_observer_ioctl(struct file *fp, u_long com, void *data,
    struct ucred *active_cred __unused, struct thread *td __unused)
{
	struct dq_observer *ob = fp->f_data;

	switch (com) {
	case DQ_IOC_GET_STATS:
		dq_queue_stats(ob->ob_queue, data);
		return (0);
	case FIONBIO:
	case FIOASYNC:
		return (0);
	default:
		return (ENOTTY);
	}
}

static int
dq_observer_poll(struct file *fp, int events, struct ucred *active_cred __unused,
    struct thread *td)
{
	struct dq_observer *ob = fp->f_data;
	struct dq_queue *q = ob->ob_queue;
	int revents;

	revents = 0;
	DQ_LOCK(q);
	if ((events & (POLLIN | POLLRDNORM)) != 0) {
		if (!TAILQ_EMPTY(&ob->ob_pending) || ob->ob_closed)
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(td, &ob->ob_sel);
	}
	if (ob->ob_closed)
		revents |= POLLHUP;
	DQ_UNLOCK(q);
	return (revents);
}

static void
dq_observer_kqdetach(struct knote *kn)
{
	struct dq_observer *ob = kn->kn_hook;

	knlist_remove(&ob->ob_sel.si_note, kn, 0);
}

static int
dq_observer_kqread(struct knote *kn, long hint __unused)
{
	struct dq_observer *ob = kn->kn_hook;

	DQ_LOCK_ASSERT(ob->ob_queue);
	kn->kn_data = ob->ob_count;
	if (ob->ob_closed) {
		kn->kn_flags |= EV_EOF;
		return (1);
	}
	return (!TAILQ_EMPTY(&ob->ob_pending));
}

static const struct filterops dq_observer_rfiltops = {
	.f_isfd = 1,
	.f_detach = dq_observer_kqdetach,
	.f_event = dq_observer_kqread,
};

static int
dq_observer_kqfilter(struct file *fp, struct knote *kn)
{
	struct dq_observer *ob = fp->f_data;

	if (kn->kn_filter != EVFILT_READ)
		return (EINVAL);
	kn->kn_fop = &dq_observer_rfiltops;
	kn->kn_hook = ob;
	knlist_add(&ob->ob_sel.si_note, kn, 0);
	return (0);
}

/* A character-device-like descriptor with no node behind it. */
static int
dq_observer_stat(struct file *fp __unused, struct stat *sb,
    struct ucred *active_cred __unused)
{

	bzero(sb, sizeof(*sb));
	sb->st_mode = S_IFCHR | S_IRUSR;
	sb->st_blksize = PAGE_SIZE;
	return (0);
}

static int
dq_observer_fill_kinfo(struct file *fp __unused, struct kinfo_file *kif,
    struct filedesc *fdp __unused)
{

	kif->kf_type = KF_TYPE_DEV;
	strlcpy(kif->kf_path, "dq-observer", sizeof(kif->kf_path));
	return (0);
}
