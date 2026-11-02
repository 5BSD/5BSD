/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/queue.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dev/dttransport/dttransport.h>
#include <dev/virtio/dtrace/virtio_dtrace_wire.h>
#include <sys/hypertrace.h>
typedef void *device_t;
#include "driver-types.inc"
struct mtx { pthread_mutex_t lock; };
struct cv { pthread_cond_t cond; };
struct sema { int posted; };
struct task { int unused; };
struct taskqueue { unsigned queued; };
struct virtqueue { void *pending[8]; unsigned count, used; int intr_pending; };
struct vtdtr_softc;
struct virtio_dtrace_queue {
    struct mtx vtdq_mtx;
    struct vtdtr_softc *vtdq_sc;
    struct virtqueue *vtdq_vq;
    struct taskqueue *vtdq_tq;
    struct task vtdq_intrtask;
};
struct vtdtr_ctrl_entry {
    STAILQ_ENTRY(vtdtr_ctrl_entry) entries;
    struct virtio_dtrace_control *ctrl;
};
struct vtdtr_ctrlq { STAILQ_HEAD(, vtdtr_ctrl_entry) head; size_t n_entries; };
struct vtdtr_softc {
    struct mtx vtdtr_mtx;
    struct virtio_dtrace_queue vtdtr_rxq;
    struct virtio_dtrace_queue vtdtr_txq;
    struct mtx vtdtr_ctrlmtx;
    struct cv vtdtr_condvar;
    struct vtdtr_ctrlq *vtdtr_ctrlq;
    struct sema vtdtr_exit;
    int vtdtr_shutdown, vtdtr_host_ready, vtdtr_ready;
	uint64_t vtdtr_features;
    uint16_t vtdtr_node_id;
    uint64_t vtdtr_node_epoch;
    bool vtdtr_rekeyed;
    bool vtdtr_rekey_local_committed;
    bool vtdtr_registered;
    bool vtdtr_cleanup_pending, vtdtr_cleanup_applied;
    bool vtdtr_session_stop;
    bool vtdtr_session_stop_queued;
    struct dtt_vm_identity vtdtr_fresh_identity;
    bool vtdtr_fresh_commit_pending;
    uint16_t vtdtr_cleanup_vmid;
    uint64_t vtdtr_cleanup_epoch, vtdtr_cleanup_delivery_id;
    uint64_t vtdtr_cleanup_last_accepted_id;
    uint16_t vtdtr_rekey_old_id;
    uint64_t vtdtr_rekey_old_epoch;
    bool vtdtr_rekey_query_pending;
    uint32_t vtdtr_rekey_query_event;
    uint64_t vtdtr_rekey_query_delivery_id;
    uint64_t vtdtr_rekey_query_id;
    uint8_t vtdtr_rekey_query_program_id[16];
    uint8_t vtdtr_rekey_query_source_id[16];
    uint8_t vtdtr_rekey_query_digest[32];
    device_t vtdtr_dev;
};
static struct virtio_dtrace_control eof_ctrl = { .vd_event = VIRTIO_DTRACE_EOF };
static struct virtio_dtrace_control ready_ctrl = {
    .vd_event = VIRTIO_DTRACE_DEVICE_READY };
static struct virtio_dtrace_control query_node_id_ctrl = {
    .vd_event = VIRTIO_DTRACE_NODE_ID };
#define M_DEVBUF 0
#define M_NOWAIT 1
#define M_WAITOK 2
#define M_ZERO 4
#define hz 100
static size_t live_allocations;
static unsigned fail_nowait_at;
static void *test_alloc(size_t n, int flags) {
    if ((flags & M_NOWAIT) && fail_nowait_at != 0 &&
        --fail_nowait_at == 0) return NULL;
    void *p = flags & M_ZERO ? calloc(1, n) : malloc(n);
    assert(p != NULL); __atomic_add_fetch(&live_allocations, 1, __ATOMIC_RELAXED); return p;
}
static void test_free(void *p) {
    if (p != NULL) { __atomic_sub_fetch(&live_allocations, 1, __ATOMIC_RELAXED); free(p); }
}
#define malloc(n, pool, flags) test_alloc(n, flags)
#define free(p, pool) test_free(p)
static void mtx_lock(struct mtx *m) { assert(pthread_mutex_lock(&m->lock) == 0); }
static void mtx_unlock(struct mtx *m) { assert(pthread_mutex_unlock(&m->lock) == 0); }
#define MA_OWNED 1
#define mtx_assert(m, how) assert(pthread_mutex_trylock(&(m)->lock) == EBUSY)
#define VTDTR_QUEUE_LOCK(q) mtx_lock(&(q)->vtdq_mtx)
#define VTDTR_QUEUE_UNLOCK(q) mtx_unlock(&(q)->vtdq_mtx)
static int atomic_load_int(int *p) { return __atomic_load_n(p, __ATOMIC_ACQUIRE); }
static void atomic_store_int(int *p, int n) { __atomic_store_n(p, n, __ATOMIC_RELEASE); }
static void cv_signal(struct cv *c) { pthread_cond_broadcast(&c->cond); }
static void cv_timedwait(struct cv *c, struct mtx *m, int ticks) {
    struct timespec until; clock_gettime(CLOCK_REALTIME, &until); until.tv_sec++;
    int error = pthread_cond_timedwait(&c->cond, &m->lock, &until);
    assert(error == 0 || error == ETIMEDOUT);
}
static void sema_post(struct sema *s) { s->posted++; }
static void kthread_exit(void) { pthread_exit(NULL); }
static int virtqueue_full(struct virtqueue *vq) { return vq->count == 8; }
static int virtqueue_empty(struct virtqueue *vq) { return vq->count == 0; }
static void *virtqueue_dequeue(struct virtqueue *vq, uint32_t *len) {
    if (!vq->used) return NULL;
    void *p = vq->pending[0]; vq->used--; vq->count--;
    memmove(vq->pending, vq->pending + 1, vq->count * sizeof(void *));
    *len = sizeof(struct virtio_dtrace_control); return p;
}
static int fail_requeue, requeue_attempts;
static int vtdtr_queue_enqueue_ctrl(struct virtio_dtrace_queue *q,
    struct virtio_dtrace_control *ctrl, int readable, int writable) {
    assert((readable == 1 && writable == 0) ||
        (readable == 0 && writable == 1));
    if (writable) requeue_attempts++;
    if (writable && fail_requeue) return ENOSPC;
    if (virtqueue_full(q->vtdq_vq)) return ENOSPC;
    q->vtdq_vq->pending[q->vtdq_vq->count++] = ctrl; return 0;
}
static void virtqueue_notify(struct virtqueue *vq) {}
static int virtqueue_enable_intr(struct virtqueue *vq) { return vq->intr_pending; }
static void taskqueue_enqueue(struct taskqueue *q, struct task *task __unused) {
    q->queued++;
}
static int receive_error, received, front_received;
static dtt_entry_t last_entry;
static uint64_t dtrace_node_id;
static uint64_t mbufid_node_epoch;
static void mbufid_origin_epoch_set(uint64_t epoch) {
    mbufid_node_epoch = epoch;
}
int dtt_queue_enqueue(dtt_entry_t *entry) {
    assert(entry != NULL);
    if (receive_error) return receive_error;
    last_entry = *entry;
    received++;
    return 0;
}
int dtt_queue_enqueue_front(dtt_entry_t *entry) {
    front_received++;
    return dtt_queue_enqueue(entry);
}
static int stop_queue_error;
int dtt_queue_session_stop(dtt_entry_t *entry) {
    assert(entry->event_kind == DTT_SESSION_STOP);
    return stop_queue_error ? stop_queue_error : dtt_queue_enqueue(entry);
}
#define debug_printf(dev, ...) ((void)(dev))
#define device_printf(dev, ...) ((void)(dev))
#define smp_rendezvous_cpus(...) ((void)0)
static uint64_t host_features;
static uint64_t virtio_negotiate_features(device_t dev __unused,
    uint64_t requested) { return (requested & host_features); }
static int finalize_error, finalize_calls;
static int virtio_finalize_features(device_t dev __unused) {
	finalize_calls++;
	return (finalize_error);
}
static int vtdtr_fill_desc(struct virtio_dtrace_queue *,
    struct virtio_dtrace_control *);
static void vtdtr_notify(struct virtio_dtrace_queue *q __unused) {}
static void vtdtr_stop(struct vtdtr_softc *sc) {
    atomic_store_int(&sc->vtdtr_shutdown, 1);
}
#include "driver-assert.inc"
#include "driver-functions.inc"
static void *worker(void *arg) { vtdtr_run(arg); return NULL; }
int main(void) {
    alarm(15);
	dtt_entry_t data = { .event_kind = DTT_ELF };
	data.u.elf.delivery_id = 17;
	data.u.elf.vmid = 42;
	data.u.elf.epoch = 99;
	data.u.elf.program_id[0] = 0x42;
	data.u.elf.source_id[0] = 0x55;
    data.u.elf.len = data.u.elf.totallen = 4; memcpy(data.u.elf.data, "abcd", 4);
    struct virtio_dtrace_control *ctrl = ctrl_from_dttentry(&data);
	assert(ctrl && ctrl->vd_elflen == 4 && ctrl->vd_elf[4] == 0 &&
	    ctrl->vd_delivery_id == 17 && ctrl->vd_vmid == 42 &&
	    ctrl->vd_epoch == 99); free(ctrl, M_DEVBUF);
	data.u.elf.epoch = 0;
	assert(ctrl_from_dttentry(&data) == NULL);
	data.u.elf.epoch = 99;
	data.u.elf.delivery_id = 0;
	assert(ctrl_from_dttentry(&data) == NULL);
	data.u.elf.delivery_id = 17;
	data.u.elf.program_id[0] = 0;
	assert(ctrl_from_dttentry(&data) == NULL);
	data.u.elf.program_id[0] = 0x42;
    data.u.elf.len = SIZE_MAX; assert(ctrl_from_dttentry(&data) == NULL);
    data.u.elf.len = 2049; assert(ctrl_from_dttentry(&data) == NULL);
    data.u.elf.len = 0; assert(ctrl_from_dttentry(&data) == NULL);
    data.u.elf.len = 4; data.u.elf.hasmore = 1; assert(ctrl_from_dttentry(&data) == NULL);
    data.u.elf.totallen = SIZE_MAX; assert(ctrl_from_dttentry(&data) == NULL);
    data.u.elf.totallen = 4; data.u.elf.hasmore = -1; assert(ctrl_from_dttentry(&data) == NULL);
    data.u.elf.hasmore = 0;
	dtt_entry_t observation = { .event_kind = DTT_INSTALLED };
	assert(ctrl_from_dttentry(&observation) == NULL);
	observation.u.installed.delivery_id = 17;
	observation.u.installed.vmid = 42;
	observation.u.installed.epoch = 99;
	observation.u.installed.program_id[0] = 0x42;
	assert(ctrl_from_dttentry(&observation) == NULL);
	observation.u.installed.source_id[0] = 0x55;
	ctrl = ctrl_from_dttentry(&observation);
	assert(ctrl != NULL && ctrl->vd_event == VIRTIO_DTRACE_INSTALLED &&
	    ctrl->vd_installed_delivery_id == 17 &&
	    ctrl->vd_installed_vmid == 42 &&
	    ctrl->vd_installed_epoch == 99 &&
	    ctrl->vd_installed_program_id[0] == 0x42 &&
	    ctrl->vd_installed_source_id[0] == 0x55);
	free(ctrl, M_DEVBUF);
	observation.event_kind = DTT_UNINSTALLED;
	ctrl = ctrl_from_dttentry(&observation);
	assert(ctrl != NULL && ctrl->vd_event ==
	    VIRTIO_DTRACE_UNINSTALLED &&
	    ctrl->vd_installed_delivery_id == 17);
	free(ctrl, M_DEVBUF);
	observation.event_kind = DTT_STATUS;
	dtt_entry_t identity_query = {0};
	identity_query.event_kind = DTT_VM_IDENTITY_QUERY;
	assert(ctrl_from_dttentry(&identity_query) == NULL);
	identity_query.u.installed.query_id = 456;
	ctrl = ctrl_from_dttentry(&identity_query);
	assert(ctrl != NULL && ctrl->vd_event ==
	    VIRTIO_DTRACE_NODE_ID && ctrl->vd_node_query_id == 456);
	free(ctrl, M_DEVBUF);
	identity_query.u.installed.delivery_id = 1;
	assert(ctrl_from_dttentry(&identity_query) == NULL);
	assert(ctrl_from_dttentry(&observation) == NULL);
	observation.u.installed.query_id = 123;
	ctrl = ctrl_from_dttentry(&observation);
	assert(ctrl != NULL && ctrl->vd_event == VIRTIO_DTRACE_STATUS &&
	    ctrl->vd_installed_delivery_id == 17 &&
	    ctrl->vd_installed_query_id == 123);
	free(ctrl, M_DEVBUF);
	observation.u.installed.phase = 'i';
	assert(ctrl_from_dttentry(&observation) == NULL);
	observation.u.installed.phase = 0;
	observation.event_kind = DTT_INGRESS_STATUS;
	observation.u.installed.vmid = 0;
	observation.u.installed.epoch = 0;
	ctrl = ctrl_from_dttentry(&observation);
	assert(ctrl != NULL && ctrl->vd_event ==
	    VIRTIO_DTRACE_INGRESS_STATUS &&
	    ctrl->vd_installed_query_id == 123 &&
	    ctrl->vd_installed_vmid == 0 &&
	    ctrl->vd_installed_epoch == 0);
	free(ctrl, M_DEVBUF);
	observation.u.installed.vmid = 42;
	assert(ctrl_from_dttentry(&observation) == NULL);
	observation.u.installed.vmid = 42;
	observation.u.installed.epoch = 99;
	observation.event_kind = DTT_STATUS;
    struct vtdtr_softc sc = {0}; struct vtdtr_ctrlq cq; struct virtqueue vq = {0};
	struct virtqueue rxvq = {.intr_pending = 1};
	struct taskqueue rxtq = {0};
	sc.vtdtr_rxq.vtdq_sc = &sc;
	sc.vtdtr_rxq.vtdq_vq = &rxvq;
	sc.vtdtr_rxq.vtdq_tq = &rxtq;
	sc.vtdtr_txq.vtdq_sc = &sc;
	sc.vtdtr_txq.vtdq_vq = &vq;
	assert(pthread_mutex_init(&sc.vtdtr_mtx.lock, NULL) == 0);
	mtx_lock(&sc.vtdtr_mtx);
	vtdtr_enable_interrupts(&sc);
	mtx_unlock(&sc.vtdtr_mtx);
	assert(rxtq.queued == 1);
	assert(vtdtr_setup_features(&sc) == ENOTSUP);
	assert(finalize_calls == 0);
	host_features = VTDTR_WIRE_F_CONTROL_V1;
	assert(vtdtr_setup_features(&sc) == ENOTSUP);
	host_features |= VTDTR_WIRE_F_KILL_APPLIED_V1;
	assert(vtdtr_setup_features(&sc) == ENOTSUP);
	host_features |= VTDTR_WIRE_F_HOST_ELF_DIGEST_V1;
	assert(vtdtr_setup_features(&sc) == ENOTSUP);
	host_features |= VTDTR_WIRE_F_CLEANUP_APPLIED_V1;
	finalize_error = EIO;
	assert(vtdtr_setup_features(&sc) == EIO);
	assert(finalize_calls == 1);
	finalize_error = 0;
	assert(vtdtr_setup_features(&sc) == 0);
	assert(finalize_calls == 2);
	/* A fresh session attaches without any continuity features. */
	assert(sc.vtdtr_features == VTDTR_WIRE_F_SESSION_REQUIRED);
	const uint64_t session_bits[] = { VTDTR_WIRE_F_CONTROL_V1,
	    VTDTR_WIRE_F_KILL_APPLIED_V1, VTDTR_WIRE_F_HOST_ELF_DIGEST_V1,
	    VTDTR_WIRE_F_CLEANUP_APPLIED_V1 };
	for (size_t i = 0; i < sizeof(session_bits) / sizeof(session_bits[0]); i++) {
		host_features = (VTDTR_WIRE_F_SESSION_REQUIRED |
		    VTDTR_WIRE_F_CONTINUITY) & ~session_bits[i];
		assert(vtdtr_setup_features(&sc) == ENOTSUP);
	}
	assert(finalize_calls == 2);
	/* Keep exercising the retained rekey handlers when explicitly negotiated. */
	host_features = VTDTR_WIRE_F_SESSION_REQUIRED |
	    VTDTR_WIRE_F_NODE_REKEY_V1 | VTDTR_WIRE_F_REKEY_COMMIT_V1;
	assert(vtdtr_setup_features(&sc) == 0);
	assert(sc.vtdtr_features == (VTDTR_WIRE_F_CONTROL_V1 |
	    VTDTR_WIRE_F_KILL_APPLIED_V1 | VTDTR_WIRE_F_NODE_REKEY_V1 |
	    VTDTR_WIRE_F_HOST_ELF_DIGEST_V1 | VTDTR_WIRE_F_REKEY_COMMIT_V1 |
	    VTDTR_WIRE_F_CLEANUP_APPLIED_V1));
    vtdtr_cq_init(&cq); sc.vtdtr_ctrlq = &cq; sc.vtdtr_host_ready = 1;
    sc.vtdtr_txq.vtdq_sc = &sc; sc.vtdtr_txq.vtdq_vq = &vq;
    assert(pthread_mutex_init(&sc.vtdtr_ctrlmtx.lock, NULL) == 0);
    assert(pthread_mutex_init(&sc.vtdtr_txq.vtdq_mtx.lock, NULL) == 0);
    assert(pthread_cond_init(&sc.vtdtr_condvar.cond, NULL) == 0);
	/* A failed startup control must be reported; no silent host wait. */
	fail_nowait_at = 1;
	assert(vtdtr_notify_ready(&sc) == ENOMEM && !sc.vtdtr_ready);
	assert(cq.n_entries == 0 && live_allocations == 0);
	fail_nowait_at = 2;
	assert(vtdtr_query_node_id(&sc) == ENOMEM);
	assert(cq.n_entries == 0 && live_allocations == 0);
	assert(vtdtr_notify_ready(&sc) == 0 && sc.vtdtr_ready);
	assert(vtdtr_query_node_id(&sc) == 0);
	assert(cq.n_entries == 2);
	struct vtdtr_ctrl_entry *startup;
	while ((startup = vtdtr_cq_dequeue(&cq)) != NULL) {
		free(startup->ctrl, M_DEVBUF);
		free(startup, M_DEVBUF);
	}
	assert(live_allocations == 0);
	dtt_entry_t early_ack = {0};
	early_ack.event_kind = DTT_KILL_APPLIED;
	early_ack.u.kill.pid = 123;
	early_ack.u.kill.vmid = 42;
	early_ack.u.kill.epoch = 99;
	early_ack.u.kill.source_id[0] = 0x42;
	assert(vtdtr_enqueue(&sc, &early_ack) == ESTALE);
	assert(cq.n_entries == 0 && live_allocations == 0);
    struct virtio_dtrace_control node = { .vd_event = VIRTIO_DTRACE_NODE_ID,
        .vd_node_id = 42, .vd_node_epoch = 99 };
    assert(vtdtr_ctrl_process_event(&sc, &node, sizeof(node)) == 0);
    assert(sc.vtdtr_node_id == 42 && sc.vtdtr_node_epoch == 99);
	struct dtt_cleanup_state cleanup_state = {0};
	assert(vtdtr_cleanup_query(&sc, &cleanup_state) == 0 &&
	    cleanup_state.flags == 0 && cleanup_state.delivery_id == 0);
	assert(vtdtr_enqueue(&sc, &early_ack) == 0);
	struct vtdtr_ctrl_entry *early = vtdtr_cq_dequeue(&cq);
	assert(early != NULL && early->ctrl->vd_event ==
	    VIRTIO_DTRACE_KILL_APPLIED);
	free(early->ctrl, M_DEVBUF);
	free(early, M_DEVBUF);
    struct virtio_dtrace_control incoming = { .vd_event = VIRTIO_DTRACE_ELF,
	    .vd_elflen = 4, .vd_totalelflen = 4,
	    .vd_delivery_id = 17, .vd_vmid = 42, .vd_epoch = 99 };
	incoming.vd_program_id[0] = 0x42;
    incoming.vd_elf_source_id[0] = 0x55;
    sc.vtdtr_ready = 1;
    assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming) - 1) == EINVAL);
    assert(sc.vtdtr_ready == 1);
    incoming.vd_delivery_id = 0;
    assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == EINVAL);
    assert(sc.vtdtr_ready == 1);
    incoming.vd_delivery_id = 17;
    incoming.vd_epoch = 0;
    assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == EINVAL);
    assert(sc.vtdtr_ready == 1);
    incoming.vd_epoch = 98;
    assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == EINVAL);
    assert(sc.vtdtr_ready == 1);
    incoming.vd_epoch = 99;
    receive_error = ENOBUFS;
    assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == ENOBUFS);
    assert(sc.vtdtr_ready == 0);
    sc.vtdtr_ready = 1;
    receive_error = ENOMEM;
    assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == ENOMEM);
    assert(sc.vtdtr_ready == 0);
    assert(received == 0);
    receive_error = 0;
    assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == 0);
    assert(received == 1);
    assert(sc.vtdtr_ready == 0);
	assert(last_entry.event_kind == DTT_ELF &&
	    last_entry.u.elf.delivery_id == 17 &&
	    last_entry.u.elf.vmid == 42 &&
	    last_entry.u.elf.epoch == 99 &&
	    last_entry.u.elf.source_id[0] == 0x55);
    incoming.vd_event = VIRTIO_DTRACE_KILL;
	memset(&incoming.wire.uctrl, 0, sizeof(incoming.wire.uctrl));
    sc.vtdtr_ready = 1;
    incoming.vd_pid = -1;
    assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == EINVAL);
    assert(sc.vtdtr_ready == 1);
    incoming.vd_pid = 0;
    assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == EINVAL);
    assert(sc.vtdtr_ready == 1);
    incoming.vd_pid = 123;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == EINVAL);
	assert(sc.vtdtr_ready == 1);
	incoming.vd_source_id[0] = 0x42;
    incoming.vd_kill_vmid = 42;
    incoming.vd_kill_epoch = 98;
    assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == EINVAL);
    assert(sc.vtdtr_ready == 1);
    incoming.vd_kill_epoch = 99;
    assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == 0);
    assert(sc.vtdtr_ready == 0);
    assert(received == 2);
	assert(last_entry.event_kind == DTT_KILL &&
	    last_entry.u.kill.source_id[0] == 0x42 &&
	    last_entry.u.kill.vmid == 42 && last_entry.u.kill.epoch == 99);
	incoming.vd_event = VIRTIO_DTRACE_CLEANUP_DTRACED;
	memset(&incoming.wire.uctrl, 0, sizeof(incoming.wire.uctrl));
	incoming.vd_cleanup_vmid = 42;
	incoming.vd_cleanup_epoch = 98;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == EINVAL);
	assert(received == 2);
	incoming.vd_cleanup_epoch = 99;
	incoming.vd_cleanup_delivery_id = 0x8899;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == 0);
	assert(last_entry.event_kind == DTT_CLEANUP_DTRACED &&
	    last_entry.u.cleanup.delivery_id == 0x8899 &&
	    last_entry.u.cleanup.vmid == 42 &&
	    last_entry.u.cleanup.epoch == 99);
	assert(sc.vtdtr_cleanup_pending && !sc.vtdtr_cleanup_applied);
	assert(vtdtr_cleanup_query(&sc, &cleanup_state) == 0 &&
	    cleanup_state.flags == DTT_CLEANUP_STATE_PENDING &&
	    cleanup_state.delivery_id == 0x8899 &&
	    cleanup_state.vmid == 42 && cleanup_state.epoch == 99);
	struct virtio_dtrace_control premature_rekey = {
	    .vd_event = VIRTIO_DTRACE_NODE_REKEY,
	    .vd_rekey_old_id = 42, .vd_rekey_old_epoch = 99,
	    .vd_rekey_new_id = 43, .vd_rekey_new_epoch = 100 };
	assert(vtdtr_ctrl_process_event(&sc, &premature_rekey,
	    sizeof(premature_rekey)) == EBUSY);
	dtt_entry_t cleanup_applied = { .event_kind = DTT_CLEANUP_APPLIED };
	cleanup_applied.u.cleanup = last_entry.u.cleanup;
	cleanup_applied.u.cleanup.delivery_id++;
	assert(vtdtr_enqueue(&sc, &cleanup_applied) == ESTALE);
	assert(!sc.vtdtr_cleanup_applied);
	cleanup_applied.u.cleanup.delivery_id--;
	assert(vtdtr_enqueue(&sc, &cleanup_applied) == 0);
	assert(sc.vtdtr_cleanup_applied && cq.n_entries == 0);
	assert(vtdtr_cleanup_query(&sc, &cleanup_state) == 0 &&
	    cleanup_state.flags == (DTT_CLEANUP_STATE_PENDING |
	    DTT_CLEANUP_STATE_APPLIED));
	incoming.vd_event = VIRTIO_DTRACE_HOST_CLEANUP_APPLIED;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == 0);
	assert(!sc.vtdtr_cleanup_pending &&
	    sc.vtdtr_cleanup_last_accepted_id == 0x8899);
	assert(vtdtr_cleanup_query(&sc, &cleanup_state) == 0 &&
	    cleanup_state.flags == 0 && cleanup_state.delivery_id == 0);
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == 0); /* duplicate receipt */
	incoming.vd_event = VIRTIO_DTRACE_HOST_INSTALLED;
	memset(&incoming.wire.uctrl, 0, sizeof(incoming.wire.uctrl));
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == EINVAL);
	incoming.vd_installed_delivery_id = 17;
	incoming.vd_installed_vmid = 42;
	incoming.vd_installed_epoch = 99;
	incoming.vd_installed_program_id[0] = 0x42;
	incoming.vd_installed_source_id[0] = 0x55;
	incoming.vd_installed_epoch = 0;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == EINVAL);
	incoming.vd_installed_epoch = 98;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == EINVAL);
	incoming.vd_installed_epoch = 99;
	receive_error = ENOBUFS;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == ENOBUFS);
	receive_error = 0;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == 0);
	assert(last_entry.event_kind == DTT_HOST_INSTALLED &&
	    last_entry.u.installed.delivery_id == 17 &&
	    last_entry.u.installed.vmid == 42 &&
	    last_entry.u.installed.epoch == 99 &&
	    last_entry.u.installed.program_id[0] == 0x42 &&
	    last_entry.u.installed.source_id[0] == 0x55);
	incoming.vd_event = VIRTIO_DTRACE_HOST_UNINSTALLED;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == 0);
	assert(last_entry.event_kind == DTT_HOST_UNINSTALLED);
	incoming.vd_event = VIRTIO_DTRACE_HOST_ELF;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == EINVAL);
	incoming.vd_installed_digest[0] = 0x42;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == 0);
	assert(last_entry.event_kind == DTT_HOST_ELF &&
	    last_entry.u.installed.delivery_id == 17 &&
	    last_entry.u.installed.digest[0] == 0x42);
	incoming.vd_installed_query_id = 1;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == EINVAL);
	incoming.vd_installed_query_id = 0;
	incoming.vd_installed_digest[0] = 0;
	incoming.vd_event = VIRTIO_DTRACE_HOST_STATUS;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == EINVAL);
	incoming.vd_installed_query_id = 123;
	incoming.vd_installed_phase = 'x';
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == EINVAL);
	incoming.vd_installed_phase = 'i';
	incoming.vd_installed_revoked = 2;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == EINVAL);
	incoming.vd_installed_revoked = 1;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == 0);
	assert(last_entry.event_kind == DTT_HOST_STATUS &&
	    last_entry.u.installed.phase == 'i' &&
	    last_entry.u.installed.revoked == 1);
	incoming.vd_installed_replay = 1;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == EINVAL);
	incoming.vd_installed_revoked = 0;
	incoming.vd_installed_digest[0] = 0x42;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == 0);
	assert(last_entry.u.installed.replay == 1 &&
	    last_entry.u.installed.digest[0] == 0x42 &&
	    last_entry.u.installed.query_id == 123);
	incoming.vd_installed_phase = 'u';
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == EINVAL);
	incoming.vd_installed_replay = 0;
	incoming.vd_installed_digest[0] = 0;
	incoming.vd_installed_revoked = 0;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == 0);
	assert(last_entry.event_kind == DTT_HOST_STATUS &&
	    last_entry.u.installed.phase == 'u' &&
	    last_entry.u.installed.revoked == 0 &&
	    last_entry.u.installed.query_id == 123);
	incoming.vd_event = VIRTIO_DTRACE_HOST_INGRESS_STATUS;
	incoming.vd_installed_phase = 'a';
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == EINVAL);
	incoming.vd_installed_digest[0] = 0x42;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == 0);
	assert(last_entry.event_kind == DTT_HOST_INGRESS_STATUS &&
	    last_entry.u.installed.phase == 'a' &&
	    last_entry.u.installed.digest[0] == 0x42);
	incoming.vd_installed_replay = 1;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == EINVAL);
	incoming.vd_installed_replay = 0;
	incoming.vd_installed_phase = 'u';
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == EINVAL);
	incoming.vd_installed_digest[0] = 0;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == 0);
	assert(last_entry.event_kind == DTT_HOST_INGRESS_STATUS &&
	    last_entry.u.installed.phase == 'u');
	incoming.vd_event = VIRTIO_DTRACE_HOST_INSTALLED;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == EINVAL);
	incoming.vd_installed_phase = 0;
	incoming.vd_installed_revoked = 0;
    incoming.vd_event = VIRTIO_DTRACE_NODE_ID;
    incoming.vd_node_id = HYPERTRACE_MAX_VMS;
    assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == EINVAL);
    incoming.vd_node_id = 0;
    assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == EINVAL);
    incoming.vd_node_id = 42;
    incoming.vd_node_epoch = 0;
    assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == EINVAL);
    incoming.vd_node_epoch = 99;
    assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == 0);
    assert(dtrace_node_id == 42 && mbufid_node_epoch == 99);
    incoming.vd_node_epoch = 100;
    assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == ESTALE);
    assert(sc.vtdtr_node_epoch == 99);
    incoming.vd_node_epoch = 99;
    incoming.vd_node_query_id = 456;
    assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == 0);
    assert(last_entry.event_kind == DTT_VM_IDENTITY &&
        last_entry.u.installed.query_id == 456 &&
        last_entry.u.installed.vmid == 42 &&
        last_entry.u.installed.epoch == 99);
	dtt_entry_t applied = {0};
	applied.event_kind = DTT_KILL_APPLIED;
	applied.u.kill.pid = 123;
	applied.u.kill.vmid = 42;
	applied.u.kill.epoch = 99;
	applied.u.kill.source_id[0] = 0x42;
	ctrl = ctrl_from_dttentry(&applied);
	assert(ctrl != NULL && ctrl->vd_event == VIRTIO_DTRACE_KILL_APPLIED &&
	    ctrl->vd_pid == 123 && ctrl->vd_kill_vmid == 42 &&
	    ctrl->vd_kill_epoch == 99 && ctrl->vd_source_id[0] == 0x42);
	free(ctrl, M_DEVBUF);
	applied.u.kill.epoch = 98;
	assert(vtdtr_enqueue(&sc, &applied) == ESTALE);
	applied.u.kill.epoch = 99;
	incoming.vd_event = VIRTIO_DTRACE_HOST_KILL_APPLIED;
	memset(&incoming.wire.uctrl, 0, sizeof(incoming.wire.uctrl));
	incoming.vd_pid = 123;
	incoming.vd_kill_vmid = 42;
	incoming.vd_kill_epoch = 98;
	incoming.vd_source_id[0] = 0x42;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == EINVAL);
	incoming.vd_kill_epoch = 99;
	assert(vtdtr_ctrl_process_event(&sc, &incoming,
	    sizeof(incoming)) == 0);
	assert(last_entry.event_kind == DTT_HOST_KILL_APPLIED &&
	    last_entry.u.kill.pid == 123 &&
	    last_entry.u.kill.source_id[0] == 0x42);
    incoming.vd_event = UINT32_MAX;
    assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == EINVAL);
    cq.n_entries = 4096;
    assert(vtdtr_enqueue(&sc, &data) == ENOBUFS && live_allocations == 0);
    cq.n_entries = 0;
    assert(vtdtr_enqueue(&sc, &data) == 0);
    pthread_t thread; assert(pthread_create(&thread, NULL, worker, &sc) == 0);
    bool sent = false;
    for (int i = 0; i < 200 && !sent; i++) {
        mtx_lock(&sc.vtdtr_ctrlmtx); VTDTR_QUEUE_LOCK(&sc.vtdtr_txq);
        sent = vq.count != 0;
        VTDTR_QUEUE_UNLOCK(&sc.vtdtr_txq); mtx_unlock(&sc.vtdtr_ctrlmtx);
        if (!sent) usleep(10000);
    }
    assert(sent);
    mtx_lock(&sc.vtdtr_ctrlmtx); VTDTR_QUEUE_LOCK(&sc.vtdtr_txq);
    assert(vq.count == 2 && cq.n_entries == 0);
    ctrl = vq.pending[0]; assert(memcmp(ctrl->vd_elf, "abcd", 4) == 0);
    VTDTR_QUEUE_UNLOCK(&sc.vtdtr_txq); mtx_unlock(&sc.vtdtr_ctrlmtx);
    memcpy(data.u.elf.data, "WXYZ", 4); assert(vtdtr_enqueue(&sc, &data) == 0);
    /* The host holds the old descriptors indefinitely; their storage survives. */
    mtx_lock(&sc.vtdtr_ctrlmtx); VTDTR_QUEUE_LOCK(&sc.vtdtr_txq);
    assert(memcmp(ctrl->vd_elf, "abcd", 4) == 0 && cq.n_entries == 1);
    atomic_store_int(&sc.vtdtr_shutdown, 1); cv_signal(&sc.vtdtr_condvar);
    VTDTR_QUEUE_UNLOCK(&sc.vtdtr_txq); mtx_unlock(&sc.vtdtr_ctrlmtx);
    assert(pthread_join(thread, NULL) == 0 && sc.vtdtr_exit.posted == 1);
    assert(vtdtr_enqueue(&sc, &data) == ENOBUFS);
    assert(vtdtr_fill_desc(&sc.vtdtr_txq, &eof_ctrl) == ENOBUFS);
    vq.used = vq.count; uint32_t len;
    while ((ctrl = virtqueue_dequeue(&vq, &len)) != NULL) free(ctrl, M_DEVBUF);
    struct vtdtr_ctrl_entry *entry;
    while ((entry = vtdtr_cq_dequeue(&cq)) != NULL) { free(entry->ctrl, M_DEVBUF); free(entry, M_DEVBUF); }
    assert(live_allocations == 0);
	struct virtio_dtrace_control rekey = {
	    .vd_event = VIRTIO_DTRACE_NODE_REKEY,
	    .vd_rekey_old_id = 42, .vd_rekey_old_epoch = 99,
	    .vd_rekey_new_id = 43, .vd_rekey_new_epoch = 100,
	};
	rekey.vd_rekey_old_epoch = 98;
	assert(vtdtr_ctrl_process_event(&sc, &rekey, sizeof(rekey)) == ESTALE);
	rekey.vd_rekey_old_epoch = 99;
	int notifications = received;
	receive_error = ENOBUFS;
	assert(vtdtr_ctrl_process_event(&sc, &rekey, sizeof(rekey)) == ENOBUFS);
	assert(sc.vtdtr_node_id == 42 && sc.vtdtr_node_epoch == 99 &&
	    !sc.vtdtr_rekeyed && received == notifications &&
	    mbufid_node_epoch == 99);
	receive_error = 0;
	assert(vtdtr_ctrl_process_event(&sc, &rekey, sizeof(rekey)) == 0);
	assert(sc.vtdtr_node_id == 43 && sc.vtdtr_node_epoch == 100 &&
	    dtrace_node_id == 43 && mbufid_node_epoch == 100 &&
	    sc.vtdtr_ready == 0 && sc.vtdtr_rekeyed);
	assert(received == notifications + 1 && last_entry.event_kind ==
	    DTT_VM_REKEY && last_entry.u.installed.vmid == 43 &&
	    last_entry.u.installed.epoch == 100 && front_received == 2);
	atomic_store_int(&sc.vtdtr_shutdown, 0);
	struct dtt_vm_identity current = {0};
	assert(vtdtr_identity(&sc, &current) == 0);
	assert(current.vmid == 43 && current.epoch == 100 &&
	    current.old_vmid == 42 && current.old_epoch == 99 &&
	    current.flags == DTT_IDENTITY_REKEY_PENDING);
	dtt_entry_t receipt_query = { .event_kind = DTT_REKEY_DELIVERY_QUERY };
	receipt_query.u.installed.delivery_id = 71;
	receipt_query.u.installed.vmid = 42;
	receipt_query.u.installed.epoch = 99;
	receipt_query.u.installed.query_id = 901;
	receipt_query.u.installed.program_id[0] = 1;
	receipt_query.u.installed.source_id[0] = 2;
	receipt_query.u.installed.digest[0] = 3;
	assert(vtdtr_enqueue(&sc, &receipt_query) == ENOTSUP);
	assert(vq.count == 0 && !sc.vtdtr_rekey_query_pending);
	host_features |= VTDTR_WIRE_F_REKEY_RECEIPT_V1;
	assert(vtdtr_setup_features(&sc) == 0);
	receipt_query.u.installed.vmid = 43;
	assert(vtdtr_enqueue(&sc, &receipt_query) == ESTALE);
	receipt_query.u.installed.vmid = 42;
	receipt_query.u.installed.digest[0] = 0;
	assert(vtdtr_enqueue(&sc, &receipt_query) == EINVAL);
	receipt_query.u.installed.digest[0] = 3;
	vq.count = 8;
	assert(vtdtr_enqueue(&sc, &receipt_query) == EBUSY);
	vq.count = 0;
	assert(vtdtr_enqueue(&sc, &receipt_query) == 0);
	assert(vq.count == 1 && sc.vtdtr_rekey_query_pending);
	ctrl = vq.pending[0];
	assert(ctrl->vd_event == VIRTIO_DTRACE_REKEY_DELIVERY_QUERY &&
	    ctrl->vd_installed_vmid == 42 &&
	    ctrl->vd_installed_query_id == 901);
	assert(vtdtr_enqueue(&sc, &receipt_query) == EBUSY);
	struct virtio_dtrace_control source_receipt = {0};
	source_receipt.vd_event = VIRTIO_DTRACE_REKEY_DELIVERY_RECEIPT;
	source_receipt.vd_installed_delivery_id = 71;
	source_receipt.vd_installed_vmid = 42;
	source_receipt.vd_installed_epoch = 99;
	source_receipt.vd_installed_query_id = 901;
	source_receipt.vd_installed_program_id[0] = 1;
	source_receipt.vd_installed_source_id[0] = 2;
	source_receipt.vd_installed_digest[0] = 3;
	source_receipt.vd_installed_phase = 'a';
	source_receipt.vd_installed_query_id++;
	assert(vtdtr_ctrl_process_event(&sc, &source_receipt,
	    sizeof(source_receipt)) == ESTALE && sc.vtdtr_rekey_query_pending);
	source_receipt.vd_installed_query_id--;
	source_receipt.vd_installed_digest[0]++;
	assert(vtdtr_ctrl_process_event(&sc, &source_receipt,
	    sizeof(source_receipt)) == EPROTO && sc.vtdtr_rekey_query_pending);
	source_receipt.vd_installed_digest[0] = 3;
	receive_error = ENOBUFS;
	assert(vtdtr_ctrl_process_event(&sc, &source_receipt,
	    sizeof(source_receipt)) == ENOBUFS && sc.vtdtr_rekey_query_pending);
	receive_error = 0;
	assert(vtdtr_ctrl_process_event(&sc, &source_receipt,
	    sizeof(source_receipt)) == 0 && !sc.vtdtr_rekey_query_pending);
	assert(last_entry.event_kind == DTT_REKEY_DELIVERY_RECEIPT &&
	    last_entry.u.installed.delivery_id == 71 &&
	    last_entry.u.installed.digest[0] == 3);
	/* A consumed reply never permits reusing its nonce or bypassing the ring. */
	assert(vtdtr_ctrl_process_event(&sc, &source_receipt,
	    sizeof(source_receipt)) == ESTALE);
	assert(vtdtr_enqueue(&sc, &receipt_query) == EBUSY);
	vq.used = vq.count;
	while ((ctrl = virtqueue_dequeue(&vq, &len)) != NULL)
		free(ctrl, M_DEVBUF);
	receipt_query.u.installed.query_id = 904;
	assert(vtdtr_enqueue(&sc, &receipt_query) == 0);
	source_receipt.vd_installed_query_id = 904;
	source_receipt.vd_installed_phase = 't';
	source_receipt.vd_installed_revoked = 1;
	source_receipt.vd_installed_digest[0] = 0;
	assert(vtdtr_ctrl_process_event(&sc, &source_receipt,
	    sizeof(source_receipt)) == 0 && !sc.vtdtr_rekey_query_pending);
	assert(last_entry.event_kind == DTT_REKEY_DELIVERY_RECEIPT &&
	    last_entry.u.installed.phase == 't' &&
	    last_entry.u.installed.revoked == 1);
	vq.used = vq.count;
	while ((ctrl = virtqueue_dequeue(&vq, &len)) != NULL)
		free(ctrl, M_DEVBUF);
	receipt_query.event_kind = DTT_REKEY_INGRESS_QUERY;
	receipt_query.u.installed.query_id = 902;
	assert(vtdtr_enqueue(&sc, &receipt_query) == 0);
	source_receipt.vd_event = VIRTIO_DTRACE_REKEY_INGRESS_RECEIPT;
	source_receipt.vd_installed_query_id = 902;
	source_receipt.vd_installed_phase = 'u';
	source_receipt.vd_installed_revoked = 0;
	source_receipt.vd_installed_digest[0] = 0;
	assert(vtdtr_ctrl_process_event(&sc, &source_receipt,
	    sizeof(source_receipt)) == 0 && !sc.vtdtr_rekey_query_pending);
	assert(last_entry.event_kind == DTT_REKEY_INGRESS_RECEIPT &&
	    last_entry.u.installed.phase == 'u');
	vq.used = vq.count;
	while ((ctrl = virtqueue_dequeue(&vq, &len)) != NULL)
		free(ctrl, M_DEVBUF);
	receipt_query.event_kind = DTT_REKEY_KILL_QUERY;
	receipt_query.u.installed.delivery_id = 123;
	receipt_query.u.installed.query_id = 903;
	receipt_query.u.installed.program_id[0] = 0;
	receipt_query.u.installed.digest[0] = 0;
	assert(vtdtr_enqueue(&sc, &receipt_query) == 0);
	source_receipt.vd_event = VIRTIO_DTRACE_REKEY_KILL_RECEIPT;
	source_receipt.vd_installed_delivery_id = 123;
	source_receipt.vd_installed_query_id = 903;
	source_receipt.vd_installed_program_id[0] = 0;
	source_receipt.vd_installed_phase = 'p';
	source_receipt.vd_installed_revoked = 1;
	assert(vtdtr_ctrl_process_event(&sc, &source_receipt,
	    sizeof(source_receipt)) == 0 && !sc.vtdtr_rekey_query_pending);
	assert(last_entry.event_kind == DTT_REKEY_KILL_RECEIPT &&
	    last_entry.u.installed.revoked == 1);
	vq.used = vq.count;
	while ((ctrl = virtqueue_dequeue(&vq, &len)) != NULL)
		free(ctrl, M_DEVBUF);
	assert(live_allocations == 0);
	/* A routine READY must not stand in for journal commit. */
	struct virtio_dtrace_control ordinary_ready = {
	    .vd_event = VIRTIO_DTRACE_DEVICE_READY,
	};
	assert(vtdtr_fill_desc(&sc.vtdtr_txq, &ordinary_ready) == EBUSY);
	assert(cq.n_entries == 0 && live_allocations == 0);
	assert(vtdtr_ctrl_process_event(&sc, &ordinary_ready,
	    sizeof(ordinary_ready)) == EBUSY);
	struct virtio_dtrace_control premature_kill = {
	    .vd_event = VIRTIO_DTRACE_KILL,
	    .vd_kill_vmid = 43,
	    .vd_kill_epoch = 100,
	    .vd_pid = 123,
	};
	assert(vtdtr_ctrl_process_event(&sc, &premature_kill,
	    sizeof(premature_kill)) == EBUSY);
	data.u.elf.vmid = 43;
	data.u.elf.epoch = 100;
	assert(vtdtr_enqueue(&sc, &data) == 0);
	atomic_store_int(&sc.vtdtr_host_ready, 1);
	assert(pthread_create(&thread, NULL, worker, &sc) == 0);
	usleep(20000);
	mtx_lock(&sc.vtdtr_ctrlmtx);
	VTDTR_QUEUE_LOCK(&sc.vtdtr_txq);
	assert(cq.n_entries == 1 && vq.count == 0);
	atomic_store_int(&sc.vtdtr_shutdown, 1);
	cv_signal(&sc.vtdtr_condvar);
	VTDTR_QUEUE_UNLOCK(&sc.vtdtr_txq);
	mtx_unlock(&sc.vtdtr_ctrlmtx);
	assert(pthread_join(thread, NULL) == 0);
	while ((entry = vtdtr_cq_dequeue(&cq)) != NULL) {
		free(entry->ctrl, M_DEVBUF);
		free(entry, M_DEVBUF);
	}
	assert(live_allocations == 0);
	data.u.elf.vmid = 42;
	data.u.elf.epoch = 99;
	assert(vtdtr_enqueue(&sc, &early_ack) == ESTALE);
	assert(vtdtr_enqueue(&sc, &data) == ESTALE);
	dtt_entry_t status = {0};
	status.event_kind = DTT_STATUS;
	status.u.installed.delivery_id = 1;
	status.u.installed.vmid = 42;
	status.u.installed.epoch = 99;
	status.u.installed.query_id = 2;
	status.u.installed.program_id[0] = 1;
	status.u.installed.source_id[0] = 2;
	assert(vtdtr_enqueue(&sc, &status) == ESTALE);
	dtt_entry_t ingress = {0};
	ingress.event_kind = DTT_INGRESS_STATUS;
	ingress.u.installed.delivery_id = 1;
	ingress.u.installed.query_id = 2;
	ingress.u.installed.program_id[0] = 1;
	ingress.u.installed.source_id[0] = 2;
	assert(vtdtr_enqueue(&sc, &ingress) == ESTALE);
	assert(vtdtr_ctrl_process_event(&sc, &rekey, sizeof(rekey)) == EBUSY);
	rekey.vd_rekey_old_id = 43;
	rekey.vd_rekey_old_epoch = 100;
	assert(vtdtr_ctrl_process_event(&sc, &rekey, sizeof(rekey)) == EINVAL);
	struct dtt_vm_identity commit = {
	    .old_vmid = 42, .old_epoch = 99, .vmid = 43, .epoch = 100,
	};
	assert(vtdtr_rekey_commit(&sc, &commit) == ENXIO);
	atomic_store_int(&sc.vtdtr_shutdown, 0);
	commit.old_epoch = 98;
	assert(vtdtr_rekey_commit(&sc, &commit) == ESTALE && sc.vtdtr_rekeyed);
	commit.old_epoch = 99;
	commit.flags = DTT_IDENTITY_REKEY_PENDING;
	assert(vtdtr_rekey_commit(&sc, &commit) == EINVAL && sc.vtdtr_rekeyed);
	commit.flags = 0;
	struct virtio_dtrace_control acknowledged = {
	    .vd_event = VIRTIO_DTRACE_REKEY_COMMITTED,
	    .vd_rekey_old_id = 42, .vd_rekey_old_epoch = 99,
	    .vd_rekey_new_id = 43, .vd_rekey_new_epoch = 100,
	};
	assert(vtdtr_ctrl_process_event(&sc, &acknowledged,
	    sizeof(acknowledged)) == ESTALE && sc.vtdtr_rekeyed);
	vq.count = 8;
	assert(vtdtr_rekey_commit(&sc, &commit) == EBUSY &&
	    !sc.vtdtr_rekey_local_committed);
	vq.count = 0;
	fail_nowait_at = 1;
	assert(vtdtr_rekey_commit(&sc, &commit) == ENOMEM &&
	    !sc.vtdtr_rekey_local_committed);
	fail_nowait_at = 0;
	assert(vtdtr_rekey_commit(&sc, &commit) == 0);
	assert(vtdtr_rekey_commit(&sc, &commit) == 0);
	assert(vq.count == 1);
	for (unsigned i = 0; i < vq.count; i++) {
		struct virtio_dtrace_control *sent_commit = vq.pending[i];
		assert(sent_commit->vd_event == VIRTIO_DTRACE_REKEY_COMMIT &&
		    sent_commit->vd_rekey_old_id == 42 &&
		    sent_commit->vd_rekey_old_epoch == 99 &&
		    sent_commit->vd_rekey_new_id == 43 &&
		    sent_commit->vd_rekey_new_epoch == 100);
	}
	assert(sc.vtdtr_rekeyed && sc.vtdtr_rekey_local_committed);
	commit.old_epoch = 98;
	assert(vtdtr_rekey_commit(&sc, &commit) == ESTALE);
	commit.old_epoch = 99;
	assert(vtdtr_identity(&sc, &current) == 0 &&
	    current.vmid == 43 && current.epoch == 100 &&
	    current.flags == DTT_IDENTITY_REKEY_LOCAL_COMMITTED &&
	    current.old_vmid == 42 && current.old_epoch == 99);
	assert(vtdtr_fill_desc(&sc.vtdtr_txq, &ordinary_ready) == EBUSY);
	/* Detach must clear only the transport owner's current packet origin. */
	sc.vtdtr_registered = false;
	dtrace_node_id = 43;
	vtdtr_clear_node_identity(&sc);
	assert(dtrace_node_id == 43 && mbufid_node_epoch == 100);
	sc.vtdtr_registered = true;
	dtrace_node_id = 44;
	vtdtr_clear_node_identity(&sc);
	assert(dtrace_node_id == 44 && mbufid_node_epoch == 100);
	dtrace_node_id = 43;
	vtdtr_clear_node_identity(&sc);
	assert(dtrace_node_id == 0 && mbufid_node_epoch == 0);
	/* The RX task must not enqueue ordinary READY while NODE_REKEY fences
	 * the transport. That would return EBUSY and stop the device. */
	struct virtqueue fenced_rx_vq = {0};
	sc.vtdtr_rxq.vtdq_sc = &sc;
	sc.vtdtr_rxq.vtdq_vq = &fenced_rx_vq;
	assert(pthread_mutex_init(&sc.vtdtr_rxq.vtdq_mtx.lock, NULL) == 0);
	size_t queued_before = sc.vtdtr_ctrlq->n_entries;
	sc.vtdtr_ready = 0;
	vtdtr_rxq_tq_intr(&sc.vtdtr_rxq, 0);
	assert(sc.vtdtr_ctrlq->n_entries == queued_before &&
	    sc.vtdtr_ready == 0 && sc.vtdtr_rekeyed &&
	    atomic_load_int(&sc.vtdtr_shutdown) == 0);
	pthread_mutex_destroy(&sc.vtdtr_rxq.vtdq_mtx.lock);
	vq.used = vq.count;
	while ((ctrl = virtqueue_dequeue(&vq, &len)) != NULL)
		free(ctrl, M_DEVBUF);
	acknowledged.vd_rekey_old_epoch = 98;
	assert(vtdtr_ctrl_process_event(&sc, &acknowledged,
	    sizeof(acknowledged)) == ESTALE && sc.vtdtr_rekeyed);
	acknowledged.vd_rekey_old_epoch = 99;
	assert(vtdtr_ctrl_process_event(&sc, &acknowledged,
	    sizeof(acknowledged)) == 0 && !sc.vtdtr_rekeyed &&
	    !sc.vtdtr_rekey_local_committed && sc.vtdtr_ready == 1 &&
	    vq.count == 1);
	ctrl = vq.pending[0];
	assert(ctrl->vd_event == VIRTIO_DTRACE_REKEY_APPLIED &&
	    ctrl->vd_rekey_old_id == 42 &&
	    ctrl->vd_rekey_old_epoch == 99 &&
	    ctrl->vd_rekey_new_id == 43 &&
	    ctrl->vd_rekey_new_epoch == 100);
	assert(atomic_load_int(&sc.vtdtr_host_ready) == 0);
	vq.used = vq.count;
	while ((ctrl = virtqueue_dequeue(&vq, &len)) != NULL)
		free(ctrl, M_DEVBUF);
	assert(vtdtr_ctrl_process_event(&sc, &acknowledged,
	    sizeof(acknowledged)) == ESTALE);
	assert(live_allocations == 0);
	/* Fresh-session stop is distinct from cleanup and cannot be released
	 * by an old cleanup acknowledgment or ordinary READY. */
	sc.vtdtr_node_id = 42;
	sc.vtdtr_node_epoch = 99;
	sc.vtdtr_cleanup_pending = false;
	sc.vtdtr_cleanup_applied = false;
	struct virtio_dtrace_control stop = {
	    .vd_event = VIRTIO_DTRACE_SESSION_STOP,
	    .vd_cleanup_vmid = 42, .vd_cleanup_epoch = 99,
	    .vd_cleanup_delivery_id = 456 };
	assert(vtdtr_ctrl_process_event(&sc, &stop, sizeof(stop)) == ENOTSUP);
	sc.vtdtr_features |= VTDTR_WIRE_F_SESSION_STOP_V1;
	stop.vd_cleanup_epoch = 98;
	assert(vtdtr_ctrl_process_event(&sc, &stop, sizeof(stop)) == EINVAL);
	assert(!sc.vtdtr_session_stop);
	stop.vd_cleanup_epoch = 99;
	stop_queue_error = EBUSY;
	assert(vtdtr_ctrl_process_event(&sc, &stop, sizeof(stop)) == 0);
	assert(sc.vtdtr_session_stop && sc.vtdtr_cleanup_pending &&
	    !sc.vtdtr_session_stop_queued);
	assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == EBUSY);
	stop_queue_error = 0;
	assert(vtdtr_ctrl_process_event(&sc, &stop, sizeof(stop)) == 0);
	assert(last_entry.event_kind == DTT_SESSION_STOP &&
	    sc.vtdtr_session_stop && sc.vtdtr_cleanup_pending &&
	    !sc.vtdtr_cleanup_applied);
	int stop_received = received;
	assert(vtdtr_ctrl_process_event(&sc, &stop, sizeof(stop)) == 0);
	assert(received == stop_received);
	stop.vd_cleanup_delivery_id++;
	assert(vtdtr_ctrl_process_event(&sc, &stop, sizeof(stop)) == EBUSY);
	stop.vd_cleanup_delivery_id--;
	assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == EBUSY);
	dtt_entry_t stopped = {.event_kind = DTT_CLEANUP_APPLIED};
	stopped.u.cleanup = last_entry.u.cleanup;
	assert(vtdtr_enqueue(&sc, &stopped) == ESTALE);
	stopped.event_kind = DTT_SESSION_STOPPED;
	stopped.u.cleanup.delivery_id++;
	assert(vtdtr_enqueue(&sc, &stopped) == ESTALE);
	stopped.u.cleanup.delivery_id--;
	struct vtdtr_ctrl_entry *stale = malloc(sizeof(*stale), M_DEVBUF,
	    M_WAITOK | M_ZERO);
	stale->ctrl = malloc(sizeof(*stale->ctrl), M_DEVBUF, M_WAITOK | M_ZERO);
	stale->ctrl->vd_event = VIRTIO_DTRACE_ELF;
	vtdtr_cq_enqueue(&cq, stale);
	assert(vtdtr_enqueue(&sc, &stopped) == 0);
	assert(cq.n_entries == 0);
	assert(sc.vtdtr_cleanup_applied && sc.vtdtr_session_stop);
	assert(vtdtr_cleanup_query(&sc, &cleanup_state) == 0 &&
	    cleanup_state.flags == (DTT_CLEANUP_STATE_PENDING |
	    DTT_CLEANUP_STATE_APPLIED | DTT_CLEANUP_STATE_SESSION_STOP));
	stop.vd_event = VIRTIO_DTRACE_HOST_CLEANUP_APPLIED;
	assert(vtdtr_ctrl_process_event(&sc, &stop, sizeof(stop)) == EBUSY);
	assert(vtdtr_notify_ready(&sc) == EBUSY);
	assert(live_allocations == 0);
	struct virtio_dtrace_control prepare = {
	    .vd_event = VIRTIO_DTRACE_SESSION_PREPARE };
	prepare.wire.uctrl.session_prepare.stop_token = 456;
	prepare.wire.uctrl.session_prepare.old_id = 42;
	prepare.wire.uctrl.session_prepare.old_epoch = 99;
	prepare.wire.uctrl.session_prepare.new_id = 43;
	prepare.wire.uctrl.session_prepare.new_epoch = 100;
	assert(vtdtr_ctrl_process_event(&sc, &prepare, sizeof(prepare)) == ENOTSUP);
	sc.vtdtr_features |= VTDTR_WIRE_F_SESSION_FRESH_V1;
	sc.vtdtr_cleanup_applied = false;
	assert(vtdtr_ctrl_process_event(&sc, &prepare, sizeof(prepare)) == EBUSY);
	sc.vtdtr_cleanup_applied = true;
	prepare.wire.uctrl.session_prepare.stop_token++;
	assert(vtdtr_ctrl_process_event(&sc, &prepare, sizeof(prepare)) == ESTALE);
	prepare.wire.uctrl.session_prepare.stop_token--;
	prepare.wire.uctrl.session_prepare.new_epoch = 99;
	assert(vtdtr_ctrl_process_event(&sc, &prepare, sizeof(prepare)) == EINVAL);
	prepare.wire.uctrl.session_prepare.new_epoch = 100;
	assert(vtdtr_ctrl_process_event(&sc, &prepare, sizeof(prepare)) == 0);
	assert(vtdtr_ctrl_process_event(&sc, &prepare, sizeof(prepare)) == 0);
	struct dtt_vm_identity fresh;
	assert(vtdtr_identity(&sc, &fresh) == 0 &&
	    fresh.flags == DTT_IDENTITY_FRESH_PENDING && fresh.vmid == 43 &&
	    fresh.epoch == 100 && fresh.old_vmid == 42 && fresh.old_epoch == 99);
	assert(sc.vtdtr_node_id == 42 && sc.vtdtr_node_epoch == 99 &&
	    sc.vtdtr_session_stop && sc.vtdtr_cleanup_applied);
	assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == EBUSY);
	prepare.wire.uctrl.session_prepare.new_epoch++;
	assert(vtdtr_ctrl_process_event(&sc, &prepare, sizeof(prepare)) == ESTALE);
	assert(vtdtr_identity(&sc, &fresh) == 0 && fresh.epoch == 100);
	struct virtio_dtrace_control fresh_commit = prepare;
	fresh_commit.vd_event = VIRTIO_DTRACE_SESSION_COMMIT;
	fresh_commit.wire.uctrl.session_prepare.new_epoch = 100;
	assert(vtdtr_ctrl_process_event(&sc, &fresh_commit, sizeof(fresh_commit)) == ESTALE);
	dtt_entry_t local_ready = {.event_kind = DTT_SESSION_READY};
	local_ready.u.cleanup = stopped.u.cleanup;
	assert(vtdtr_enqueue(&sc, &local_ready) == ESTALE);
	local_ready.u.cleanup.vmid = 43;
	local_ready.u.cleanup.epoch = 100;
	local_ready.u.cleanup.delivery_id++;
	assert(vtdtr_enqueue(&sc, &local_ready) == ESTALE);
	local_ready.u.cleanup.delivery_id--;
	assert(vtdtr_enqueue(&sc, &local_ready) == 0);
	assert(vtdtr_enqueue(&sc, &local_ready) == 0);
	prepare.wire.uctrl.session_prepare.new_epoch--;
	assert(vtdtr_ctrl_process_event(&sc, &prepare, sizeof(prepare)) == 0);
	assert(vtdtr_identity(&sc, &fresh) == 0 &&
	    fresh.flags == DTT_IDENTITY_FRESH_READY);
	assert(sc.vtdtr_node_id == 42 && sc.vtdtr_node_epoch == 99 &&
	    sc.vtdtr_session_stop && sc.vtdtr_cleanup_applied);
	assert(vtdtr_ctrl_process_event(&sc, &incoming, sizeof(incoming)) == EBUSY);
	/* Local readiness keeps the fence and reports the entire transition. */
	atomic_store_int(&sc.vtdtr_host_ready, 1);
	assert(pthread_create(&thread, NULL, worker, &sc) == 0);
	bool stop_sent = false;
	for (int i = 0; i < 200 && !stop_sent; i++) {
		mtx_lock(&sc.vtdtr_ctrlmtx);
		VTDTR_QUEUE_LOCK(&sc.vtdtr_txq);
		stop_sent = vq.count != 0;
		VTDTR_QUEUE_UNLOCK(&sc.vtdtr_txq);
		mtx_unlock(&sc.vtdtr_ctrlmtx);
		if (!stop_sent) usleep(10000);
	}
	assert(stop_sent);
	mtx_lock(&sc.vtdtr_ctrlmtx);
	VTDTR_QUEUE_LOCK(&sc.vtdtr_txq);
	ctrl = vq.pending[0];
	assert(vq.count == 2 && cq.n_entries == 0 &&
	    ctrl->vd_event == VIRTIO_DTRACE_SESSION_READY &&
	    ctrl->wire.uctrl.session_prepare.stop_token == 456 &&
	    ctrl->wire.uctrl.session_prepare.old_id == 42 &&
	    ctrl->wire.uctrl.session_prepare.old_epoch == 99 &&
	    ctrl->wire.uctrl.session_prepare.new_id == 43 &&
	    ctrl->wire.uctrl.session_prepare.new_epoch == 100 &&
	    ctrl->wire.uctrl.session_prepare.reserved == 0);
	atomic_store_int(&sc.vtdtr_shutdown, 1);
	cv_signal(&sc.vtdtr_condvar);
	VTDTR_QUEUE_UNLOCK(&sc.vtdtr_txq);
	mtx_unlock(&sc.vtdtr_ctrlmtx);
	assert(pthread_join(thread, NULL) == 0);
	atomic_store_int(&sc.vtdtr_shutdown, 0);
	fresh_commit.wire.uctrl.session_prepare.stop_token++;
	assert(vtdtr_ctrl_process_event(&sc, &fresh_commit, sizeof(fresh_commit)) == ESTALE);
	fresh_commit.wire.uctrl.session_prepare.stop_token--;
	assert(vtdtr_ctrl_process_event(&sc, &fresh_commit, sizeof(fresh_commit)) == 0);
	mtx_lock(&sc.vtdtr_ctrlmtx);
	vtdtr_activate_fresh(&sc);
	assert(sc.vtdtr_fresh_commit_pending && sc.vtdtr_session_stop &&
	    sc.vtdtr_node_id == 42 && vq.count == 2);
	mtx_unlock(&sc.vtdtr_ctrlmtx);
	vq.used = vq.count;
	while ((ctrl = virtqueue_dequeue(&vq, &len)) != NULL)
		free(ctrl, M_DEVBUF);
	mtx_lock(&sc.vtdtr_ctrlmtx);
	vtdtr_activate_fresh(&sc);
	assert(!sc.vtdtr_fresh_commit_pending && !sc.vtdtr_session_stop &&
	    !sc.vtdtr_cleanup_pending && sc.vtdtr_node_id == 43 &&
	    sc.vtdtr_node_epoch == 100 && dtrace_node_id == 43 &&
	    !atomic_load_int(&sc.vtdtr_host_ready));
	assert(vq.count == 1);
	ctrl = vq.pending[0];
	assert(ctrl->vd_event == VIRTIO_DTRACE_SESSION_ACTIVE &&
	    ctrl->wire.uctrl.session_prepare.stop_token == 456 &&
	    ctrl->wire.uctrl.session_prepare.new_epoch == 100);
	mtx_unlock(&sc.vtdtr_ctrlmtx);
	assert(vtdtr_identity(&sc, &fresh) == 0 &&
	    fresh.flags == DTT_IDENTITY_FRESH_ACTIVE && fresh.vmid == 43);
	assert(vtdtr_enqueue(&sc, &stopped) == ESTALE);
	assert(vtdtr_ctrl_process_event(&sc, &fresh_commit, sizeof(fresh_commit)) == 0);
	vq.used = vq.count;
	while ((ctrl = virtqueue_dequeue(&vq, &len)) != NULL)
		free(ctrl, M_DEVBUF);
	mtx_lock(&sc.vtdtr_ctrlmtx);
	vtdtr_activate_fresh(&sc);
	assert(vq.count == 1 && !sc.vtdtr_session_stop);
	mtx_unlock(&sc.vtdtr_ctrlmtx);
	vq.used = vq.count;
	while ((ctrl = virtqueue_dequeue(&vq, &len)) != NULL)
		free(ctrl, M_DEVBUF);
	stop.vd_event = VIRTIO_DTRACE_SESSION_STOP;
	stop.vd_cleanup_vmid = 43;
	stop.vd_cleanup_epoch = 100;
	stop.vd_cleanup_delivery_id = 457;
	assert(vtdtr_ctrl_process_event(&sc, &stop, sizeof(stop)) == 0);
	assert(vtdtr_ctrl_process_event(&sc, &fresh_commit, sizeof(fresh_commit)) == ESTALE);
	stopped.u.cleanup.vmid = 43;
	stopped.u.cleanup.epoch = 100;
	stopped.u.cleanup.delivery_id = 457;
	assert(vtdtr_enqueue(&sc, &stopped) == 0);
	prepare.wire.uctrl.session_prepare.old_id = 43;
	prepare.wire.uctrl.session_prepare.old_epoch = 100;
	prepare.wire.uctrl.session_prepare.new_id = 44;
	prepare.wire.uctrl.session_prepare.new_epoch = 101;
	prepare.wire.uctrl.session_prepare.stop_token = 457;
	assert(vtdtr_ctrl_process_event(&sc, &prepare, sizeof(prepare)) == 0);
	assert(vtdtr_identity(&sc, &fresh) == 0 &&
	    fresh.flags == DTT_IDENTITY_FRESH_PENDING && fresh.vmid == 44 &&
	    fresh.old_vmid == 43 && fresh.epoch == 101 && fresh.old_epoch == 100);
	assert(live_allocations == 0);
    pthread_cond_destroy(&sc.vtdtr_condvar.cond);
	pthread_mutex_destroy(&sc.vtdtr_mtx.lock);
    pthread_mutex_destroy(&sc.vtdtr_ctrlmtx.lock); pthread_mutex_destroy(&sc.vtdtr_txq.vtdq_mtx.lock);
    /* A failed RX requeue must free its buffer and stop the transport. */
    struct vtdtr_softc failed = {0};
    struct virtqueue failed_vq = {0};
    failed.vtdtr_rxq.vtdq_sc = &failed;
    failed.vtdtr_rxq.vtdq_vq = &failed_vq;
    assert(pthread_mutex_init(&failed.vtdtr_mtx.lock, NULL) == 0);
    assert(pthread_mutex_init(&failed.vtdtr_ctrlmtx.lock, NULL) == 0);
    assert(pthread_mutex_init(&failed.vtdtr_rxq.vtdq_mtx.lock, NULL) == 0);
    struct virtio_dtrace_control *rxctrl = malloc(sizeof(*rxctrl),
        M_DEVBUF, M_WAITOK | M_ZERO);
    rxctrl->vd_event = VIRTIO_DTRACE_EOF;
    failed_vq.pending[0] = rxctrl;
    failed_vq.count = failed_vq.used = 1;
    fail_requeue = 1;
    vtdtr_rxq_tq_intr(&failed.vtdtr_rxq, 0);
    assert(requeue_attempts == 1 && failed_vq.count == 0 &&
        atomic_load_int(&failed.vtdtr_shutdown) == 1 &&
        live_allocations == 0);
    pthread_mutex_destroy(&failed.vtdtr_rxq.vtdq_mtx.lock);
    pthread_mutex_destroy(&failed.vtdtr_ctrlmtx.lock);
    pthread_mutex_destroy(&failed.vtdtr_mtx.lock);
    /* Credit: bhyve sends every queued control as a batch that clears its
     * vsd_guest_ready until the guest's READY. Each host control kind the
     * device queues (pci_vtdtr_cq_enqueue) must therefore make the real RX
     * task queue exactly one READY; a missing READY stalls host-to-guest
     * delivery (HOST_* receipts, the DTT_VM_IDENTITY_QUERY reply). */
    {
        fail_requeue = 0; /* the failure case above left it armed */
        static const uint32_t credited[] = { VIRTIO_DTRACE_NODE_ID,
            VIRTIO_DTRACE_HOST_INSTALLED, VIRTIO_DTRACE_HOST_UNINSTALLED,
            VIRTIO_DTRACE_HOST_STATUS, VIRTIO_DTRACE_HOST_INGRESS_STATUS,
            VIRTIO_DTRACE_HOST_ELF, VIRTIO_DTRACE_HOST_KILL_APPLIED,
            VIRTIO_DTRACE_HOST_CLEANUP_APPLIED, VIRTIO_DTRACE_ELF,
            VIRTIO_DTRACE_KILL };
        for (size_t k = 0; k < sizeof(credited) / sizeof(credited[0]); k++) {
            struct vtdtr_softc g = {0};
            struct vtdtr_ctrlq gq;
            struct virtqueue grx = {0};
            vtdtr_cq_init(&gq);
            g.vtdtr_ctrlq = &gq;
            g.vtdtr_rxq.vtdq_sc = g.vtdtr_txq.vtdq_sc = &g;
            g.vtdtr_rxq.vtdq_vq = &grx;
            assert(pthread_mutex_init(&g.vtdtr_mtx.lock, NULL) == 0);
            assert(pthread_mutex_init(&g.vtdtr_ctrlmtx.lock, NULL) == 0);
            assert(pthread_mutex_init(&g.vtdtr_rxq.vtdq_mtx.lock, NULL) == 0);
            assert(pthread_cond_init(&g.vtdtr_condvar.cond, NULL) == 0);
            g.vtdtr_node_id = 42;
            g.vtdtr_node_epoch = 99;
            dtrace_node_id = 42;
            g.vtdtr_ready = 1; /* READY for the previous batch already sent */
            atomic_store_int(&g.vtdtr_host_ready, 1);
            g.vtdtr_cleanup_last_accepted_id = 0x51;
            struct virtio_dtrace_control *in = malloc(sizeof(*in),
                M_DEVBUF, M_WAITOK | M_ZERO);
            struct virtio_dtrace_control *eof = malloc(sizeof(*eof),
                M_DEVBUF, M_WAITOK | M_ZERO);
            in->vd_event = credited[k];
            eof->vd_event = VIRTIO_DTRACE_EOF;
            switch (credited[k]) {
            case VIRTIO_DTRACE_NODE_ID:
                /* bhyve's answer to an unchanged-identity query. */
                in->vd_node_id = 42; in->vd_node_epoch = 99;
                in->vd_node_query_id = 6;
                break;
            case VIRTIO_DTRACE_ELF:
                in->vd_delivery_id = 17; in->vd_vmid = 42; in->vd_epoch = 99;
                in->vd_program_id[0] = 1; in->vd_elf_source_id[0] = 2;
                in->vd_identifier = 3;
                in->vd_elflen = in->vd_totalelflen = 4;
                memcpy(in->vd_elf, "\177ELF", 4);
                break;
            case VIRTIO_DTRACE_KILL:
            case VIRTIO_DTRACE_HOST_KILL_APPLIED:
                in->vd_pid = 77; in->vd_kill_vmid = 42; in->vd_kill_epoch = 99;
                in->vd_source_id[0] = 5;
                break;
            case VIRTIO_DTRACE_HOST_CLEANUP_APPLIED:
                /* A duplicate receipt for an already accepted cleanup. */
                in->vd_cleanup_vmid = 42; in->vd_cleanup_epoch = 99;
                in->vd_cleanup_delivery_id = 0x51;
                break;
            default:
                in->vd_installed_delivery_id = 9;
                in->vd_installed_vmid = 42; in->vd_installed_epoch = 99;
                in->vd_installed_program_id[0] = 1;
                in->vd_installed_source_id[0] = 2;
                if (credited[k] == VIRTIO_DTRACE_HOST_STATUS ||
                    credited[k] == VIRTIO_DTRACE_HOST_INGRESS_STATUS) {
                    in->vd_installed_query_id = 3;
                    in->vd_installed_phase = 'a';
                }
                if (credited[k] == VIRTIO_DTRACE_HOST_INGRESS_STATUS)
                    in->vd_installed_digest[0] = 1;
                if (credited[k] == VIRTIO_DTRACE_HOST_ELF)
                    in->vd_installed_digest[0] = 1;
                break;
            }
            grx.pending[0] = in; grx.pending[1] = eof;
            grx.count = grx.used = 2;
            int received_before = received;
            vtdtr_rxq_tq_intr(&g.vtdtr_rxq, 0);
            unsigned readies = 0;
            struct vtdtr_ctrl_entry *qe;
            STAILQ_FOREACH(qe, &gq.head, entries)
                readies += qe->ctrl->vd_event == VIRTIO_DTRACE_DEVICE_READY;
            if (atomic_load_int(&g.vtdtr_shutdown) != 0 || readies != 1) {
                fprintf(stderr, "credit: host control %u consumed without "
                    "READY (shutdown %d, READY %u)\n", credited[k],
                    atomic_load_int(&g.vtdtr_shutdown), readies);
                abort();
            }
            assert(g.vtdtr_ready == 1);
            if (credited[k] != VIRTIO_DTRACE_HOST_CLEANUP_APPLIED)
                assert(received == received_before + 1);
            /* The RX buffers were requeued on the ring; release them. */
            grx.used = grx.count;
            while ((ctrl = virtqueue_dequeue(&grx, &len)) != NULL)
                free(ctrl, M_DEVBUF);
            while ((qe = vtdtr_cq_dequeue(&gq)) != NULL) {
                free(qe->ctrl, M_DEVBUF);
                free(qe, M_DEVBUF);
            }
            pthread_cond_destroy(&g.vtdtr_condvar.cond);
            pthread_mutex_destroy(&g.vtdtr_rxq.vtdq_mtx.lock);
            pthread_mutex_destroy(&g.vtdtr_ctrlmtx.lock);
            pthread_mutex_destroy(&g.vtdtr_mtx.lock);
        }
        assert(live_allocations == 0);
        puts("PASS: every credited host control is answered with READY");
    }
    puts("PASS: guest attach, TX/RX ownership, requeue failure, ELF validation and rekey READY fence");
}
