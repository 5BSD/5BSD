/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <dev/dttransport/dttransport.h>

typedef struct dtt_qentry {
	TAILQ_ENTRY(dtt_qentry) next;
	dtt_entry_t *ent;
} dtt_qentry_t;
struct mtx { int unused; };
struct cv { int unused; };
struct pstats { struct timeval p_start; };
struct proc { pid_t p_pid; struct pstats *p_stats; };
struct thread { struct proc *td_proc; };
struct cdev { void *si_drv1; };
struct uio {
	int uio_rw;
	ssize_t uio_resid;
	struct thread *uio_td;
	dtt_entry_t *destination;
};
struct dtt_softc {
	struct mtx mtx;
	struct mtx qmtx;
	struct cv cv;
	TAILQ_HEAD(, dtt_qentry) dataq;
	struct proc *proc;
	pid_t proc_pid;
	struct timeval proc_start;
	uint64_t owner_generation;
	bool dying;
	bool read_busy;
	size_t queued;
};

#define UIO_READ 0
#define KASSERT(condition, message) assert(condition)
#define mtx_lock(lock) ((void)(lock))
#define mtx_unlock(lock) ((void)(lock))
#define cv_signal(cv) ((void)(cv))
#define cv_broadcast(cv) ((void)(cv))
static struct dtt_softc *close_while_waiting;
static int cv_wait_sig(struct cv *cv, struct mtx *mtx) {
	(void)cv;
	(void)mtx;
	if (close_while_waiting != NULL) {
		close_while_waiting->proc = NULL;
		close_while_waiting->owner_generation++;
		close_while_waiting = NULL;
		return (0);
	}
	assert(!"read unexpectedly waited for a queue event");
	return (EINTR);
}
static int fail_copy;
static struct dtt_softc *inject_rekey_into;
static int uiomove(void *source, size_t length, struct uio *uio) {
	if (inject_rekey_into != NULL) {
		dtt_qentry_t *priority = calloc(1, sizeof(*priority));
		assert(priority != NULL);
		priority->ent = calloc(1, sizeof(*priority->ent));
		assert(priority->ent != NULL);
		priority->ent->event_kind = DTT_VM_REKEY;
		TAILQ_INSERT_HEAD(&inject_rekey_into->dataq, priority, next);
		inject_rekey_into->queued++;
		inject_rekey_into = NULL;
	}
	if (fail_copy) {
		fail_copy = 0;
		return (EFAULT);
	}
	assert(length == DTT_ENTRYLEN);
	memcpy(uio->destination, source, length);
	uio->uio_resid -= length;
	return (0);
}
#define M_DTTRANSPORT 0
#define free(pointer, type) free(pointer)
#include "transport-read.inc"
#undef free

static void
append(struct dtt_softc *sc, uint8_t kind)
{
	dtt_qentry_t *entry = calloc(1, sizeof(*entry));
	assert(entry != NULL);
	entry->ent = calloc(1, sizeof(*entry->ent));
	assert(entry->ent != NULL);
	entry->ent->event_kind = kind;
	TAILQ_INSERT_TAIL(&sc->dataq, entry, next);
	sc->queued++;
}

int
main(void)
{
	struct pstats stats = {.p_start = {.tv_sec = 17, .tv_usec = 23}};
	struct proc owner = {.p_pid = 42, .p_stats = &stats};
	struct thread reader = {.td_proc = &owner};
	struct dtt_softc sc = {.proc = &owner, .proc_pid = 42,
	    .proc_start = {.tv_sec = 17, .tv_usec = 23}};
	struct cdev dev = {.si_drv1 = &sc};
	dtt_entry_t copied = {};
	struct uio uio = {.uio_rw = UIO_READ, .uio_resid = DTT_ENTRYLEN,
	    .uio_td = &reader, .destination = &copied};
	TAILQ_INIT(&sc.dataq);
	assert(dtt_owner_matches(&sc, &owner));
	owner.p_pid++;
	assert(!dtt_owner_matches(&sc, &owner));
	owner.p_pid--;
	stats.p_start.tv_usec++;
	assert(!dtt_owner_matches(&sc, &owner));
	stats.p_start.tv_usec--;
	append(&sc, DTT_VM_REKEY);
	append(&sc, DTT_KILL);
	assert(sc.queued == 2);
	sc.proc = NULL;
	assert(dtt_read(&dev, &uio, O_NONBLOCK) == EBUSY);
	sc.proc = &owner;
	owner.p_pid++;
	assert(dtt_read(&dev, &uio, O_NONBLOCK) == EBUSY);
	owner.p_pid--;
	stats.p_start.tv_usec++;
	assert(dtt_read(&dev, &uio, O_NONBLOCK) == EBUSY);
	stats.p_start.tv_usec--;
	assert(sc.queued == 2);
	fail_copy = 1;
	assert(dtt_read(&dev, &uio, O_NONBLOCK) == EFAULT);
	assert(sc.queued == 2 && uio.uio_resid == DTT_ENTRYLEN);
	assert(TAILQ_FIRST(&sc.dataq)->ent->event_kind == DTT_VM_REKEY);
	assert(dtt_read(&dev, &uio, O_NONBLOCK) == 0);
	assert(copied.event_kind == DTT_VM_REKEY && sc.queued == 1);
	uio.uio_resid = DTT_ENTRYLEN;
	assert(dtt_read(&dev, &uio, O_NONBLOCK) == 0);
	assert(copied.event_kind == DTT_KILL && sc.queued == 0);
	uio.uio_resid = DTT_ENTRYLEN;
	assert(dtt_read(&dev, &uio, O_NONBLOCK) == EWOULDBLOCK);
	close_while_waiting = &sc;
	assert(dtt_read(&dev, &uio, 0) == EBUSY);
	assert(sc.queued == 0);
	sc.proc = &owner;
	sc.owner_generation++;
	sc.read_busy = true;
	append(&sc, DTT_ELF);
	assert(dtt_read(&dev, &uio, O_NONBLOCK) == EWOULDBLOCK);
	sc.read_busy = false;
	fail_copy = 1;
	inject_rekey_into = &sc;
	assert(dtt_read(&dev, &uio, O_NONBLOCK) == EFAULT);
	assert(sc.queued == 2 && !sc.read_busy);
	assert(TAILQ_FIRST(&sc.dataq)->ent->event_kind == DTT_VM_REKEY);
	assert(dtt_read(&dev, &uio, O_NONBLOCK) == 0);
	assert(copied.event_kind == DTT_VM_REKEY);
	uio.uio_resid = DTT_ENTRYLEN;
	assert(dtt_read(&dev, &uio, O_NONBLOCK) == 0);
	assert(copied.event_kind == DTT_ELF && sc.queued == 0);
	uio.uio_resid = DTT_ENTRYLEN;
	sc.dying = true;
	assert(dtt_read(&dev, &uio, O_NONBLOCK) == ENXIO);
	append(&sc, DTT_VM_REKEY);
	assert(dtt_read(&dev, &uio, O_NONBLOCK) == ENXIO);
	assert(sc.queued == 1);
	dtt_qentry_t *last = TAILQ_FIRST(&sc.dataq);
	TAILQ_REMOVE(&sc.dataq, last, next);
	free(last->ent);
	free(last);
	puts("PASS: stale owner wake denied, priority preserved, dying read exits");
}
