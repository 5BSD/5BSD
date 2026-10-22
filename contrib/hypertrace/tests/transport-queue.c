/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/queue.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dev/dttransport/dttransport.h>

typedef struct dtt_qentry {
    TAILQ_ENTRY(dtt_qentry) next;
    dtt_entry_t *ent;
} dtt_qentry_t;
struct mtx { int unused; };
struct sx { pthread_rwlock_t lock; };
static struct sx dtt_transport_lock;
static atomic_bool enqueue_lock_attempted;
static void sx_slock(struct sx *s) {
    atomic_store(&enqueue_lock_attempted, true);
    assert(pthread_rwlock_rdlock(&s->lock) == 0);
}
static void sx_sunlock(struct sx *s) { assert(pthread_rwlock_unlock(&s->lock) == 0); }
static void sx_xlock(struct sx *s) { assert(pthread_rwlock_wrlock(&s->lock) == 0); }
static void sx_xunlock(struct sx *s) { assert(pthread_rwlock_unlock(&s->lock) == 0); }
struct cv { unsigned signaled; };
struct dtt_softc {
    TAILQ_HEAD(, dtt_qentry) dataq;
    struct mtx qmtx;
    struct cv cv;
    size_t queued;
    bool dying, read_busy;
};
static struct dtt_softc *gsc;
static size_t live;
static int fail_allocation;
static void *test_malloc(size_t n, int flags) {
    if (fail_allocation > 0 && --fail_allocation == 0) return NULL;
    void *p = flags & 2 ? calloc(1, n) : malloc(n);
    if (p != NULL) live++;
    return p;
}
static void test_free(void *p) { if (p != NULL) { live--; free(p); } }
#define M_DTTRANSPORT 0
#define M_NOWAIT 1
#define M_ZERO 2
#define malloc(n, type, flags) test_malloc(n, flags)
#define free(p, type) test_free(p)
#define mtx_lock(mtx) ((void)(mtx))
#define mtx_unlock(mtx) ((void)(mtx))
#define cv_signal(cv) ((cv)->signaled++)
static void dtt_queue_remove(struct dtt_softc *sc, dtt_qentry_t *entry) {
    TAILQ_REMOVE(&sc->dataq, entry, next);
    sc->queued--;
}
#include "transport-queue.inc"
#undef malloc
#undef free

static uint8_t pop(struct dtt_softc *sc) {
    dtt_qentry_t *entry = TAILQ_FIRST(&sc->dataq);
    assert(entry != NULL);
    uint8_t kind = entry->ent->event_kind;
    TAILQ_REMOVE(&sc->dataq, entry, next);
    sc->queued--;
    test_free(entry->ent);
    test_free(entry);
    return kind;
}

static atomic_bool enqueue_started;
static int enqueue_result;
static void *late_enqueue(void *arg) {
    atomic_store(&enqueue_started, true);
    enqueue_result = dtt_queue_enqueue(arg);
    return NULL;
}

int main(void) {
    struct dtt_softc sc = {0};
    assert(pthread_rwlock_init(&dtt_transport_lock.lock, NULL) == 0);
    TAILQ_INIT(&sc.dataq);
    dtt_entry_t first = {.event_kind = DTT_ELF};
    dtt_entry_t second = {.event_kind = DTT_KILL};
    dtt_entry_t rekey = {.event_kind = DTT_VM_REKEY};
    assert(dtt_queue_enqueue(&first) == ENXIO);
    gsc = &sc;
    assert(dtt_queue_enqueue(&first) == 0);
    assert(dtt_queue_enqueue(&second) == 0);
    assert(dtt_queue_enqueue_front(&rekey) == 0);
    assert(sc.queued == 3 && sc.cv.signaled == 3);
    assert(pop(&sc) == DTT_VM_REKEY);
    assert(pop(&sc) == DTT_ELF);
    assert(pop(&sc) == DTT_KILL);
    assert(live == 0);
    sc.queued = 4096;
    assert(dtt_queue_enqueue_front(&rekey) == ENOBUFS && live == 0);

    sc.queued = 0;
    dtt_entry_t stop = {.event_kind = DTT_SESSION_STOP,
        .u.cleanup = {.vmid = 1, .epoch = 7, .delivery_id = 8}};
    assert(dtt_queue_session_stop(NULL) == EINVAL);
    assert(dtt_queue_session_stop(&first) == EINVAL);
    for (int i = 0; i < 4096; i++)
        assert(dtt_queue_enqueue(&first) == 0);
    dtt_qentry_t *copying = TAILQ_FIRST(&sc.dataq);
    for (int nth = 1; nth <= 2; nth++) {
        fail_allocation = nth;
        assert(dtt_queue_session_stop(&stop) == ENOMEM);
        assert(sc.queued == 4096 && live == 8192 &&
            TAILQ_FIRST(&sc.dataq) == copying);
    }
    sc.read_busy = true;
    assert(dtt_queue_session_stop(&stop) == EBUSY);
    assert(sc.queued == 4096 && TAILQ_FIRST(&sc.dataq) == copying);
    assert(copying->ent->event_kind == DTT_ELF && live == 8192);
    sc.read_busy = false;
    assert(dtt_queue_session_stop(&stop) == 0);
    assert(sc.queued == 1 && live == 2);
    assert(pop(&sc) == DTT_SESSION_STOP && live == 0);
    sc.dying = true;
    assert(dtt_queue_enqueue_front(&rekey) == ENXIO && live == 0);
    sc.dying = false;
    sx_xlock(&dtt_transport_lock);
    pthread_t thread;
    enqueue_result = -1;
    atomic_store(&enqueue_lock_attempted, false);
    assert(pthread_create(&thread, NULL, late_enqueue, &rekey) == 0);
    while (!atomic_load(&enqueue_started) ||
        !atomic_load(&enqueue_lock_attempted)) usleep(1000);
    assert(enqueue_result == -1);
    gsc = NULL; /* Unload withdraws gsc before dropping the lifetime lock. */
    sx_xunlock(&dtt_transport_lock);
    assert(pthread_join(thread, NULL) == 0);
    assert(enqueue_result == ENXIO && live == 0 && sc.queued == 0);
    assert(pthread_rwlock_destroy(&dtt_transport_lock.lock) == 0);
    puts("PASS: priority rekey, bounded queue, and unload-safe enqueue lifetime");
}
