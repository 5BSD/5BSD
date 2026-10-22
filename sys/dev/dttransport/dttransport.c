/*-
 * Copyright (c) 2020 Domagoj Stolfa
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/condvar.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/resourcevar.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/time.h>
#include <sys/uio.h>



#include "dttransport.h"

static MALLOC_DEFINE(M_DTTRANSPORT, "dttransport", "");

typedef struct dtt_qentry {
	TAILQ_ENTRY(dtt_qentry)	next;
	struct dtt_entry	*ent;
} dtt_qentry_t;

struct dtt_softc {
	struct cdev			*cdev;
	struct mtx			mtx;
	struct cv			cv;

	TAILQ_HEAD(, dtt_qentry)	dataq;
	struct mtx			qmtx;

	struct proc			*proc;
	pid_t				proc_pid;
	struct timeval			proc_start;
	uint64_t			owner_generation;	/* qmtx: changes on open/close */
	bool				dying;
	bool				read_busy;	/* qmtx: one uncommitted copyout */
	size_t				queued;
};

static struct dtt_softc *gsc = NULL;
static struct sx dtt_transport_lock;
SX_SYSINIT(dtt_transport, &dtt_transport_lock, "DTrace guest transport");
static dtt_send_t *dtt_send;
static dtt_identity_t *dtt_identity;
static dtt_rekey_commit_t *dtt_rekey_commit;
static dtt_cleanup_query_t *dtt_cleanup_query;
static void *dtt_send_arg;
static bool dtt_transport_dying;

int
dtt_register_transport(dtt_send_t *send, dtt_identity_t *identity,
    dtt_rekey_commit_t *rekey_commit, dtt_cleanup_query_t *cleanup_query,
    void *arg)
{
	int error = 0;

	if (send == NULL || identity == NULL || rekey_commit == NULL ||
	    cleanup_query == NULL ||
	    arg == NULL)
		return (EINVAL);
	sx_xlock(&dtt_transport_lock);
	if (dtt_transport_dying)
		error = ENXIO;
	else if (dtt_send != NULL)
		error = EBUSY;
	else {
		dtt_send_arg = arg;
		dtt_send = send;
		dtt_identity = identity;
		dtt_rekey_commit = rekey_commit;
		dtt_cleanup_query = cleanup_query;
	}
	sx_xunlock(&dtt_transport_lock);
	return (error);
}

void
dtt_unregister_transport(void *arg)
{
	/* Wait for all writes through this device before freeing its softc. */
	sx_xlock(&dtt_transport_lock);
	if (dtt_send_arg == arg) {
		dtt_send = NULL;
		dtt_identity = NULL;
		dtt_rekey_commit = NULL;
		dtt_cleanup_query = NULL;
		dtt_send_arg = NULL;
	}
	sx_xunlock(&dtt_transport_lock);
}

static int
dtt_transport_send(dtt_entry_t *entry)
{
	int error;

	sx_slock(&dtt_transport_lock);
	error = dtt_send == NULL ? ENXIO : dtt_send(dtt_send_arg, entry);
	sx_sunlock(&dtt_transport_lock);
	return (error);
}

static int
dtt_transport_identity(struct dtt_vm_identity *identity)
{
	int error;

	sx_slock(&dtt_transport_lock);
	error = dtt_identity == NULL ? ENXIO :
	    dtt_identity(dtt_send_arg, identity);
	sx_sunlock(&dtt_transport_lock);
	return (error);
}

static int
dtt_transport_rekey_commit(const struct dtt_vm_identity *identity)
{
	int error;

	sx_slock(&dtt_transport_lock);
	error = dtt_rekey_commit == NULL ? ENXIO :
	    dtt_rekey_commit(dtt_send_arg, identity);
	sx_sunlock(&dtt_transport_lock);
	return (error);
}

static int
dtt_transport_cleanup_query(struct dtt_cleanup_state *state)
{
	int error;

	sx_slock(&dtt_transport_lock);
	error = dtt_cleanup_query == NULL ? ENXIO :
	    dtt_cleanup_query(dtt_send_arg, state);
	sx_sunlock(&dtt_transport_lock);
	return (error);
}

/*
 * cdevsw
 */
static d_read_t		dtt_read;
static d_write_t	dtt_write;
static d_ioctl_t	dtt_ioctl;
static d_open_t		dtt_open;
static d_close_t	dtt_close;

static struct cdevsw dtt_cdevsw = {
	.d_version	= D_VERSION,
	.d_open		= dtt_open,
	.d_close	= dtt_close,
	.d_read		= dtt_read,
	.d_write	= dtt_write,
	.d_ioctl	= dtt_ioctl,
	.d_name		= "dttransport"
};

/* A transferred descriptor can outlive its opener. Do not mistake a new
 * process allocated at the same address for that opener. */
static bool
dtt_owner_matches(const struct dtt_softc *sc, const struct proc *p)
{
	const struct timeval *start;

	if (p == NULL || sc->proc != p || sc->proc_pid != p->p_pid ||
	    p->p_stats == NULL)
		return (false);
	start = &p->p_stats->p_start;
	return (sc->proc_start.tv_sec == start->tv_sec &&
	    sc->proc_start.tv_usec == start->tv_usec);
}

static dtt_qentry_t *
dtt_queue_fst(struct dtt_softc *sc)
{

	return (TAILQ_FIRST(&sc->dataq));
}

static int
dtt_queue_empty(struct dtt_softc *sc)
{

	return (dtt_queue_fst(sc) == NULL);
}

static void
dtt_queue_remove(struct dtt_softc *sc, dtt_qentry_t *qe)
{

	TAILQ_REMOVE(&sc->dataq, qe, next);
	sc->queued--;
}

static int
dtt_handler(module_t mod, int what, void *arg)
{
	struct dtt_softc *sc = NULL;
	dtt_qentry_t *entry;
	struct make_dev_args args;
	int error;

	switch (what) {
	case MOD_LOAD:
		sc = malloc(sizeof(struct dtt_softc),
		    M_DTTRANSPORT, M_WAITOK | M_ZERO);

		mtx_init(&sc->mtx, "dttscmtx", NULL, MTX_DEF);
		mtx_init(&sc->qmtx, "dttqmtx", NULL, MTX_DEF);

		cv_init(&sc->cv, "dttransport CV");

		TAILQ_INIT(&sc->dataq);
		make_dev_args_init(&args);
		args.mda_devsw = &dtt_cdevsw;
		args.mda_uid = UID_ROOT;
		args.mda_gid = GID_OPERATOR;
		args.mda_mode = S_IRUSR | S_IWUSR;
		args.mda_si_drv1 = sc;
		error = make_dev_s(&args, &sc->cdev, "dttransport");
		if (error != 0) {
			cv_destroy(&sc->cv);
			mtx_destroy(&sc->qmtx);
			mtx_destroy(&sc->mtx);
			free(sc, M_DTTRANSPORT);
			return (error);
		}
		/* The enqueue path must never observe a partially initialized
		 * softc, even if another provider loads at the same time. */
		sx_xlock(&dtt_transport_lock);
		gsc = sc;
		sx_xunlock(&dtt_transport_lock);

		break;

	case MOD_QUIESCE:
	case MOD_UNLOAD:
		sx_xlock(&dtt_transport_lock);
		sc = gsc;
		if (sc == NULL) {
			sx_xunlock(&dtt_transport_lock);
			return (ENXIO);
		}
		mtx_lock(&sc->mtx);
		if (sc->proc != NULL || dtt_send != NULL) {
			mtx_unlock(&sc->mtx);
			sx_xunlock(&dtt_transport_lock);
			return (EBUSY);
		}
		if (what == MOD_QUIESCE) {
			mtx_unlock(&sc->mtx);
			sx_xunlock(&dtt_transport_lock);
			return (0);
		}
		/* Registration uses this same lock.  No provider may attach after
		 * unload has passed its busy check and begun destroying the cdev. */
		dtt_transport_dying = true;
		/* Enqueue also holds this lock while using gsc. Withdraw the
		 * pointer before releasing it, while the softc is still live. */
		gsc = NULL;
		/* A reader may be asleep on an empty queue while destroy_dev()
		 * waits for its cdev operation to return. Set dying under the
		 * queue lock used by that reader's wait predicate. */
		mtx_lock(&sc->qmtx);
		sc->dying = true;
		cv_broadcast(&sc->cv);
		mtx_unlock(&sc->qmtx);
		mtx_unlock(&sc->mtx);
		sx_xunlock(&dtt_transport_lock);
		destroy_dev(sc->cdev);
		while ((entry = TAILQ_FIRST(&sc->dataq)) != NULL) {
			dtt_queue_remove(sc, entry);
			free(entry->ent, M_DTTRANSPORT);
			free(entry, M_DTTRANSPORT);
		}
		mtx_destroy(&sc->mtx);
		mtx_destroy(&sc->qmtx);
		cv_destroy(&sc->cv);
		free(sc, M_DTTRANSPORT);
		break;

	default:
		break;
	}

	return (0);
}


static int
dtt_open(struct cdev *dev, int flags, int fmt, struct thread *td)
{
	struct dtt_softc *sc;

	sc = dev->si_drv1;

	mtx_lock(&sc->mtx);
	if (sc->dying || sc->proc != NULL) {
		mtx_unlock(&sc->mtx);
		return (EBUSY);
	}
	if (td->td_proc->p_stats == NULL) {
		mtx_unlock(&sc->mtx);
		return (EINVAL);
	}

	mtx_lock(&sc->qmtx);
	sc->proc = td->td_proc;
	sc->proc_pid = td->td_proc->p_pid;
	sc->proc_start = td->td_proc->p_stats->p_start;
	sc->owner_generation++;
	mtx_unlock(&sc->qmtx);
	mtx_unlock(&sc->mtx);

	return (0);
}

static int
dtt_close(struct cdev *dev, int flags, int fmt, struct thread *td)
{
	struct dtt_softc *sc;

	sc = dev->si_drv1;

	mtx_lock(&sc->mtx);
	mtx_lock(&sc->qmtx);
	sc->proc = NULL;
	sc->proc_pid = 0;
	timevalclear(&sc->proc_start);
	sc->owner_generation++;
	cv_broadcast(&sc->cv);
	mtx_unlock(&sc->qmtx);
	mtx_unlock(&sc->mtx);

	return (0);
}

static int
dtt_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int flags,
    struct thread *td)
{
	struct dtt_softc *sc = dev->si_drv1;
	int error;

	if (cmd != DTT_GET_VM_IDENTITY && cmd != DTT_COMMIT_VM_REKEY &&
	    cmd != DTT_GET_CLEANUP_STATE)
		return (ENOTTY);
	mtx_lock(&sc->mtx);
	if (sc->dying || !dtt_owner_matches(sc, td->td_proc)) {
		mtx_unlock(&sc->mtx);
		return (EBUSY);
	}
	mtx_unlock(&sc->mtx);
	if (cmd == DTT_GET_VM_IDENTITY) {
		memset(data, 0, sizeof(struct dtt_vm_identity));
		error = dtt_transport_identity((struct dtt_vm_identity *)data);
	} else if (cmd == DTT_GET_CLEANUP_STATE) {
		memset(data, 0, sizeof(struct dtt_cleanup_state));
		error = dtt_transport_cleanup_query(
		    (struct dtt_cleanup_state *)data);
	} else
		error = dtt_transport_rekey_commit(
		    (const struct dtt_vm_identity *)data);
	return (error);
}

static int
dtt_read(struct cdev *dev, struct uio *uio, int flags)
{
	struct dtt_softc *sc;
	int err;
	dtt_qentry_t *entry;
	uint64_t owner_generation;

	sc = dev->si_drv1;

	mtx_lock(&sc->mtx);
	KASSERT(uio->uio_rw == UIO_READ, ("%s: bogus write", __func__));
	KASSERT(uio->uio_resid >= 0, ("%s: bogus negative resid", __func__));

	err = 0;

	if (uio->uio_resid != DTT_ENTRYLEN) {
		mtx_unlock(&sc->mtx);
		return (EINVAL);
	}

	if (!dtt_owner_matches(sc, uio->uio_td->td_proc)) {
		mtx_unlock(&sc->mtx);
		return (EBUSY);
	}

	mtx_lock(&sc->qmtx);
	owner_generation = sc->owner_generation;
	mtx_unlock(&sc->mtx);

	while (err == 0 && !sc->dying &&
	    owner_generation == sc->owner_generation &&
	    (sc->read_busy || dtt_queue_empty(sc))) {
		if (flags & O_NONBLOCK) {
			mtx_unlock(&sc->qmtx);
			return (EWOULDBLOCK);
		}

		err = cv_wait_sig(&sc->cv, &sc->qmtx);
	}

	if (err != 0 || sc->dying ||
	    owner_generation != sc->owner_generation) {
		err = err != 0 ? err : sc->dying ? ENXIO : EBUSY;
		mtx_unlock(&sc->qmtx);
		return (err);
	}

	entry = dtt_queue_fst(sc);
	/* Keep it in the queue until copyout succeeds.  A priority rekey
	 * arriving during copyout can still be inserted ahead of it. */
	sc->read_busy = true;
	mtx_unlock(&sc->qmtx);

	err = uiomove(entry->ent, DTT_ENTRYLEN, uio);
	mtx_lock(&sc->qmtx);
	if (err == 0)
		dtt_queue_remove(sc, entry);
	sc->read_busy = false;
	cv_broadcast(&sc->cv);
	mtx_unlock(&sc->qmtx);
	if (err == 0) {
		free(entry->ent, M_DTTRANSPORT);
		free(entry, M_DTTRANSPORT);
	}
	return (err);
}

static int
dtt_write(struct cdev *dev, struct uio *uio, int flags)
{
	struct dtt_softc *sc;
	int err;
	dtt_entry_t entry;

	sc = dev->si_drv1;

	err = 0;

	mtx_lock(&sc->mtx);
	KASSERT(uio->uio_rw == UIO_WRITE, ("%s: bogus write", __func__));
	KASSERT(uio->uio_resid >= 0, ("%s: bogus negative resid", __func__));

	if (uio->uio_resid != DTT_ENTRYLEN) {
		mtx_unlock(&sc->mtx);
		return (EINVAL);
	}

	if (!dtt_owner_matches(sc, uio->uio_td->td_proc)) {
		mtx_unlock(&sc->mtx);
		return (EBUSY);
	}

	mtx_unlock(&sc->mtx);

	err = uiomove(&entry, DTT_ENTRYLEN, uio);
	if (err)
		return (err);

	err = dtt_transport_send(&entry);
	if (err)
		return (err);

	return (0);
}

static int
dtt_queue_enqueue_at(dtt_entry_t *e, bool front, bool replace)
{
	struct dtt_softc *sc;
	dtt_qentry_t *qe;
	dtt_entry_t *ent;

	qe = NULL;
	ent = NULL;

	sx_slock(&dtt_transport_lock);
	sc = gsc;
	if (sc == NULL || e == NULL) {
		sx_sunlock(&dtt_transport_lock);
		return (ENXIO);
	}
	/* Unload withdraws gsc before marking the softc dying, both under the
	 * exclusive transport lock. */
	KASSERT(!sc->dying, ("%s: dying softc still published", __func__));

	qe = malloc(sizeof(dtt_qentry_t), M_DTTRANSPORT, M_NOWAIT | M_ZERO);
	if (qe == NULL) {
		sx_sunlock(&dtt_transport_lock);
		return (ENOMEM);
	}

	ent = malloc(sizeof(dtt_entry_t), M_DTTRANSPORT, M_NOWAIT | M_ZERO);
	if (ent == NULL) {
		free(qe, M_DTTRANSPORT);
		sx_sunlock(&dtt_transport_lock);
		return (ENOMEM);
	}

	memcpy(ent, e, sizeof(dtt_entry_t));
	qe->ent = ent;

	mtx_lock(&sc->qmtx);
	/* Copyout owns an entry while qmtx is dropped. Do not invalidate it;
	 * the caller keeps tracing fenced and retries its stop request. */
	if (replace && sc->read_busy) {
		mtx_unlock(&sc->qmtx);
		free(ent, M_DTTRANSPORT);
		free(qe, M_DTTRANSPORT);
		sx_sunlock(&dtt_transport_lock);
		return (EBUSY);
	}
	if (replace) {
		dtt_qentry_t *old;
		while ((old = TAILQ_FIRST(&sc->dataq)) != NULL) {
			dtt_queue_remove(sc, old);
			free(old->ent, M_DTTRANSPORT);
			free(old, M_DTTRANSPORT);
		}
	}
	if (sc->queued >= 4096) {
		mtx_unlock(&sc->qmtx);
		free(ent, M_DTTRANSPORT);
		free(qe, M_DTTRANSPORT);
		sx_sunlock(&dtt_transport_lock);
		return (ENOBUFS);
	}
	if (front)
		TAILQ_INSERT_HEAD(&sc->dataq, qe, next);
	else
		TAILQ_INSERT_TAIL(&sc->dataq, qe, next);
	sc->queued++;
	cv_signal(&sc->cv);
	mtx_unlock(&sc->qmtx);
	sx_sunlock(&dtt_transport_lock);

	return (0);
}

int
dtt_queue_enqueue(dtt_entry_t *e)
{
	return (dtt_queue_enqueue_at(e, false, false));
}

int
dtt_queue_enqueue_front(dtt_entry_t *e)
{
	return (dtt_queue_enqueue_at(e, true, false));
}

/* Called only after the transport driver fences ordinary session traffic. */
int
dtt_queue_session_stop(dtt_entry_t *e)
{
	if (e == NULL || e->event_kind != DTT_SESSION_STOP ||
	    e->u.cleanup.vmid == 0 || e->u.cleanup.epoch == 0 ||
	    e->u.cleanup.delivery_id == 0)
		return (EINVAL);
	return (dtt_queue_enqueue_at(e, true, true));
}

static moduledata_t dtt_kmod = {
	"dttransport",
	dtt_handler,
	NULL
};

DECLARE_MODULE(dttransport, dtt_kmod, SI_SUB_DTRACE + 1, SI_ORDER_ANY);
MODULE_VERSION(dttransport, 3);
