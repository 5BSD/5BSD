/*-
 * Copyright (c) 2017 Domagoj Stolfa
 * All rights reserved.
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
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/hypertrace.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/condvar.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbufid.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sema.h>
#include <sys/sglist.h>
#include <sys/smp.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/uio.h>
#include <sys/uuid.h>
#include <sys/vnode.h>

#include <machine/atomic.h>
#include <machine/bus.h>
#include <machine/resource.h>

#include <dev/dttransport/dttransport.h>
#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>

#include "virtio_dtrace.h"

#define VIRTIO_DTRACE_MAXELFLEN VTDTR_WIRE_MAXELFLEN
#include "virtio_if.h"

struct vtdtr_softc;

struct virtio_dtrace_control {
	struct vtdtr_wire_control wire;
};

#define vd_event wire.event
#define vd_identifier wire.uctrl.elf.identifier
#define vd_delivery_id wire.uctrl.elf.delivery_id
#define vd_vmid wire.uctrl.elf.vmid
#define vd_epoch wire.uctrl.elf.epoch
#define vd_program_id wire.uctrl.elf.program_id
#define vd_elf_source_id wire.uctrl.elf.elf_source_id
#define vd_elflen wire.uctrl.elf.elflen
#define vd_elfhasmore wire.uctrl.elf.elfhasmore
#define vd_totalelflen wire.uctrl.elf.totalelflen
#define vd_elf wire.uctrl.elf.elf
#define vd_pid wire.uctrl.kill.pid
#define vd_kill_vmid wire.uctrl.kill.vmid
#define vd_kill_epoch wire.uctrl.kill.epoch
#define vd_source_id wire.uctrl.kill.source_id
#define vd_installed_program_id wire.uctrl.installed.program_id
#define vd_installed_source_id wire.uctrl.installed.source_id
#define vd_installed_delivery_id wire.uctrl.installed.delivery_id
#define vd_installed_vmid wire.uctrl.installed.vmid
#define vd_installed_epoch wire.uctrl.installed.epoch
#define vd_installed_phase wire.uctrl.installed.phase
#define vd_installed_revoked wire.uctrl.installed.revoked
#define vd_installed_replay wire.uctrl.installed.replay
#define vd_installed_query_id wire.uctrl.installed.query_id
#define vd_installed_digest wire.uctrl.installed.digest
#define vd_node_id wire.uctrl.node_id.id
#define vd_node_epoch wire.uctrl.node_id.epoch
#define vd_node_query_id wire.uctrl.node_id.query_id
#define vd_rekey_old_id wire.uctrl.node_rekey.old_id
#define vd_rekey_old_epoch wire.uctrl.node_rekey.old_epoch
#define vd_rekey_new_id wire.uctrl.node_rekey.new_id
#define vd_rekey_new_epoch wire.uctrl.node_rekey.new_epoch
#define vd_cleanup_vmid wire.uctrl.cleanup.vmid
#define vd_cleanup_epoch wire.uctrl.cleanup.epoch
#define vd_cleanup_delivery_id wire.uctrl.cleanup.delivery_id

_Static_assert(sizeof(struct virtio_dtrace_control) <= 4096,
    "virtio_dtrace_control must fit in one page");
_Static_assert(sizeof(struct virtio_dtrace_control) ==
    sizeof(struct vtdtr_wire_control), "guest control wrapper changed wire size");

struct virtio_dtrace_queue {
	struct mtx           vtdq_mtx;
	struct vtdtr_softc  *vtdq_sc;
	struct virtqueue    *vtdq_vq;
	void               (*vtdq_vqintr)(void *);
	int                  vtdq_id;
	struct taskqueue    *vtdq_tq;
	struct task          vtdq_intrtask;
	char                 vtdq_name[16];
	int                  vtdq_ready;
};

struct vtdtr_ctrl_entry {
	STAILQ_ENTRY(vtdtr_ctrl_entry)	entries;
	struct virtio_dtrace_control	*ctrl;
};

struct vtdtr_ctrlq {
	STAILQ_HEAD(, vtdtr_ctrl_entry)	head;
	size_t				n_entries;
};

struct vtdtr_softc {
	device_t                   vtdtr_dev;
	struct mtx                 vtdtr_mtx;
	uint64_t                   vtdtr_features;

	struct virtio_dtrace_queue vtdtr_txq;
	struct virtio_dtrace_queue vtdtr_rxq;
	int                        vtdtr_tx_nseg;
	int                        vtdtr_rx_nseg;

	struct cv                  vtdtr_condvar;
	struct mtx                 vtdtr_ctrlmtx;
	struct vtdtr_ctrlq        *vtdtr_ctrlq;

	struct thread             *vtdtr_commtd;

	struct sema                vtdtr_exit;

	/*
	 * We need to keep track of all the enabled probes in the
	 * driver in order to act as a bridge between the guest DTrace
	 * and host DTrace. The driver is the one asking to install
	 * or uninstall the probes on the guest, as instructed by host.
	 */

	_Atomic int                vtdtr_shutdown;
	int                        vtdtr_ready;
	_Atomic int                vtdtr_host_ready;
	uint16_t                   vtdtr_node_id;
	uint64_t                   vtdtr_node_epoch;
	bool                       vtdtr_rekeyed;
	bool                       vtdtr_rekey_local_committed;
	bool                       vtdtr_registered;
	/* Protected by ctrlmtx; a host receipt ends exact cleanup retries. */
	bool                       vtdtr_cleanup_pending;
	bool                       vtdtr_cleanup_applied;
	bool                       vtdtr_session_stop;
	bool                       vtdtr_session_stop_queued;
	struct dtt_vm_identity     vtdtr_fresh_identity;
	bool                       vtdtr_fresh_commit_pending;
	uint16_t                   vtdtr_cleanup_vmid;
	uint64_t                   vtdtr_cleanup_epoch;
	uint64_t                   vtdtr_cleanup_delivery_id;
	uint64_t                   vtdtr_cleanup_last_accepted_id;
	uint16_t                   vtdtr_rekey_old_id;
	uint64_t                   vtdtr_rekey_old_epoch;
	/* One source-incarnation receipt query at a time. Protected by ctrlmtx. */
	bool                       vtdtr_rekey_query_pending;
	uint32_t                   vtdtr_rekey_query_event;
	uint64_t                   vtdtr_rekey_query_delivery_id;
	uint64_t                   vtdtr_rekey_query_id;
	uint8_t                    vtdtr_rekey_query_program_id[16];
	uint8_t                    vtdtr_rekey_query_source_id[16];
	uint8_t                    vtdtr_rekey_query_digest[32];
};

#define	VTDTR_QUEUE_LOCK(__q)   mtx_lock(&((__q)->vtdq_mtx))
#define	VTDTR_QUEUE_UNLOCK(__q) mtx_unlock(&((__q)->vtdq_mtx))
#define	VTDTR_QUEUE_LOCK_ASSERT(__q)		\
	mtx_assert(&((__q)->vtdq_mtx), MA_OWNED)
#define	VTDTR_QUEUE_LOCK_ASSERT_NOTOWNED(__q)	\
	mtx_assert(&((__q)->vtdq_mtx), MA_NOTOWNED)



static struct virtio_dtrace_control eof_ctrl;
static struct virtio_dtrace_control ready_ctrl;
static struct virtio_dtrace_control query_node_id_ctrl;

SYSCTL_NODE(_dev, OID_AUTO, vtdtr, CTLFLAG_RD, NULL, NULL);

static uint32_t debug = 0;
SYSCTL_U32(_dev_vtdtr, OID_AUTO, debug, CTLFLAG_RWTUN, &debug, 0,
    "Enable debugging of virtio-dtrace");

static int vtdtr_modevent(module_t, int, void *);
static void vtdtr_cleanup(void);

static int vtdtr_probe(device_t);
static int vtdtr_attach(device_t);
static int vtdtr_detach(device_t);
static int vtdtr_config_change(device_t);
static int vtdtr_negotiate_features(struct vtdtr_softc *);
static int vtdtr_setup_features(struct vtdtr_softc *);
static int vtdtr_alloc_virtqueues(struct vtdtr_softc *);
static void vtdtr_stop(struct vtdtr_softc *);
static void vtdtr_drain_virtqueues(struct vtdtr_softc *);
static int vtdtr_queue_populate(struct virtio_dtrace_queue *);
static int vtdtr_queue_enqueue_ctrl(struct virtio_dtrace_queue *,
    struct virtio_dtrace_control *, int, int);
static int vtdtr_queue_requeue_ctrl(struct virtio_dtrace_queue *,
    struct virtio_dtrace_control *, int, int);
static int vtdtr_queue_new_ctrl(struct virtio_dtrace_queue *);

static void vtdtr_enable_interrupts(struct vtdtr_softc *);
static void vtdtr_disable_interrupts(struct vtdtr_softc *);
/*
 * Control-state invariants, all under vtdtr_ctrlmtx.  Only the RX task (one
 * thread) sets session_stop, cleanup_pending and rekeyed, and it accepts a
 * stop or cleanup only while not rekeyed and rekeys only while no cleanup is
 * pending.  A cleanup is accepted only for the current node identity, which
 * changes only while no cleanup is pending (rekey) or together with clearing
 * it (fresh activation).  FRESH_READY is entered only from a stopped,
 * applied cleanup and left only by activation.  A rekey commit is sent only
 * with no receipt query outstanding, and a query only before that commit.
 */
#define	VTDTR_STATE_ASSERT(sc) do {					\
	mtx_assert(&(sc)->vtdtr_ctrlmtx, MA_OWNED);			\
	KASSERT(!(sc)->vtdtr_session_stop || (sc)->vtdtr_cleanup_pending,\
	    ("vtdtr: session stop without a pending cleanup"));		\
	KASSERT(!(sc)->vtdtr_rekeyed || !(sc)->vtdtr_cleanup_pending,	\
	    ("vtdtr: cleanup pending during a rekey"));			\
	KASSERT(!(sc)->vtdtr_cleanup_pending ||				\
	    ((sc)->vtdtr_cleanup_vmid == (sc)->vtdtr_node_id &&		\
	    (sc)->vtdtr_cleanup_epoch == (sc)->vtdtr_node_epoch),		\
	    ("vtdtr: pending cleanup for another identity"));		\
	KASSERT((sc)->vtdtr_fresh_identity.flags !=			\
	    DTT_IDENTITY_FRESH_READY || ((sc)->vtdtr_session_stop &&	\
	    (sc)->vtdtr_cleanup_pending && (sc)->vtdtr_cleanup_applied),	\
	    ("vtdtr: fresh identity ready without an applied stop"));	\
	KASSERT((sc)->vtdtr_node_id == 0 || (sc)->vtdtr_node_epoch != 0,	\
	    ("vtdtr: node identity without an epoch"));			\
	KASSERT(!(sc)->vtdtr_rekey_local_committed ||			\
	    !(sc)->vtdtr_rekey_query_pending,				\
	    ("vtdtr: receipt query after the rekey commit"));		\
} while (0)

static int vtdtr_ctrl_process_event(struct vtdtr_softc *,
    struct virtio_dtrace_control *, uint32_t);
static int vtdtr_start_taskqueues(struct vtdtr_softc *);
static void vtdtr_drain_taskqueues(struct vtdtr_softc *);
static int vtdtr_vq_enable_intr(struct virtio_dtrace_queue *);
static void vtdtr_vq_disable_intr(struct virtio_dtrace_queue *);
static void vtdtr_rxq_tq_intr(void *, int);
static int vtdtr_notify_ready(struct vtdtr_softc *);
static int vtdtr_query_node_id(struct vtdtr_softc *);
static void vtdtr_rxq_vq_intr(void *);
static void vtdtr_txq_vq_intr(void *);
static int vtdtr_enqueue(void *, dtt_entry_t *);
static int vtdtr_identity(void *, struct dtt_vm_identity *);
static int vtdtr_cleanup_query(void *, struct dtt_cleanup_state *);
static int vtdtr_rekey_commit(void *, const struct dtt_vm_identity *);
static int vtdtr_rekey_query_send(struct vtdtr_softc *,
    struct virtio_dtrace_control *);
static void vtdtr_clear_node_identity(struct vtdtr_softc *);
static void vtdtr_init_txq(struct vtdtr_softc *, int);
static void vtdtr_init_rxq(struct vtdtr_softc *, int);
static void vtdtr_queue_destroy(struct virtio_dtrace_queue *);
static int vtdtr_fill_desc(struct virtio_dtrace_queue *,
    struct virtio_dtrace_control *);
static void vtdtr_cq_init(struct vtdtr_ctrlq *);
static void vtdtr_cq_enqueue(struct vtdtr_ctrlq *,
    struct vtdtr_ctrl_entry *);
static int vtdtr_cq_empty(struct vtdtr_ctrlq *);
static struct vtdtr_ctrl_entry * vtdtr_cq_dequeue(struct vtdtr_ctrlq *);
static void vtdtr_notify(struct virtio_dtrace_queue *);
static void vtdtr_run(void *);

static device_method_t vtdtr_methods[] = {
	/* Device methods. */
	DEVMETHOD(device_probe, vtdtr_probe),
	DEVMETHOD(device_attach, vtdtr_attach),
	DEVMETHOD(device_detach, vtdtr_detach),

	/* VirtIO methods. */
	DEVMETHOD(virtio_config_change, vtdtr_config_change),

	DEVMETHOD_END
};

static driver_t vtdtr_driver = {
	"vtdtr",
	vtdtr_methods,
	sizeof(struct vtdtr_softc)
};

VIRTIO_DRIVER_MODULE(virtio_dtrace, vtdtr_driver, vtdtr_modevent, NULL);
MODULE_VERSION(virtio_dtrace, 1);
MODULE_DEPEND(virtio_dtrace, virtio, 1, 1, 1);
MODULE_DEPEND(virtio_dtrace, dtrace, 1, 1, 1);
MODULE_DEPEND(virtio_dtrace, dttransport, 3, 3, 3);

static struct virtio_feature_desc vtdtr_feature_desc[] = {
	{ VTDTR_WIRE_F_CONTROL_V1, "ControlV1" },
	{ VTDTR_WIRE_F_KILL_APPLIED_V1, "KillAppliedV1" },
	{ VTDTR_WIRE_F_NODE_REKEY_V1, "NodeRekeyV1" },
	{ VTDTR_WIRE_F_HOST_ELF_DIGEST_V1, "HostElfDigestV1" },
	{ VTDTR_WIRE_F_REKEY_COMMIT_V1, "RekeyCommitV1" },
	{ VTDTR_WIRE_F_SESSION_STOP_V1, "SessionStopV1" },
	{ VTDTR_WIRE_F_SESSION_FRESH_V1, "SessionFreshV1" },
	{ 0, NULL }
};

#define debug_printf(dev, ...) \
	if (debug)             \
		device_printf(dev, __VA_ARGS__);

static int
vtdtr_modevent(module_t mod, int type, void *unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		eof_ctrl.vd_event = VIRTIO_DTRACE_EOF;
		ready_ctrl.vd_event = VIRTIO_DTRACE_DEVICE_READY;
		query_node_id_ctrl.vd_event = VIRTIO_DTRACE_NODE_ID;
		error = 0;
		break;
	case MOD_QUIESCE:
		error = 0;
		break;
	case MOD_UNLOAD:
		vtdtr_cleanup();
		error = 0;
		break;
	case MOD_SHUTDOWN:
		error = 0;
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

static void
vtdtr_cleanup(void)
{
	/*
	 * Perhaps to be used for cleaning up the module unloading later on. For
	 * now, the VMM handles that.
	 */
}

static int
vtdtr_probe(device_t dev)
{
	if (virtio_get_device_type(dev) != VIRTIO_ID_DTRACE)
		return (ENXIO);

	device_set_desc(dev, "VirtIO DTrace driver");

	return (BUS_PROBE_DEFAULT);
}

/*
 * Here we initialize the device. This is largely boilerplate. Here we
 * initialize all of the necessary mutexes, condition variables, threads, the
 * control queue, virtqueues and taskqueues and perform the necessary error
 * checking. Finally, we spawn the vtdtr_run() communicator thread and return
 * the error code.
 *
 * If the error code is non-zero, we will detach the device immediately.
 */
static int
vtdtr_attach(device_t dev)
{
	struct vtdtr_softc *sc;
	int error;

	sc = device_get_softc(dev);
	sc->vtdtr_dev = dev;
	sc->vtdtr_registered = false;
	mtx_init(&sc->vtdtr_mtx, "vtdtrmtx", NULL, MTX_DEF);
	sc->vtdtr_rx_nseg = 2;
	sc->vtdtr_tx_nseg = 2;
	atomic_store_int(&sc->vtdtr_shutdown, 0);
	atomic_store_int(&sc->vtdtr_host_ready, 1);

	sc->vtdtr_ctrlq = malloc(sizeof(struct vtdtr_ctrlq),
	    M_DEVBUF, M_WAITOK | M_ZERO);

	mtx_init(&sc->vtdtr_ctrlmtx, "vtdtrctrlmtx", NULL, MTX_DEF);
	cv_init(&sc->vtdtr_condvar, "Virtio DTrace CV");
	sema_init(&sc->vtdtr_exit, 0, "vtdtrexitsema");

	vtdtr_cq_init(sc->vtdtr_ctrlq);

	virtio_set_feature_desc(dev, vtdtr_feature_desc);
	error = vtdtr_setup_features(sc);
	if (error != 0) {
		device_printf(dev, "host lacks required control wire feature\n");
		goto fail;
	}

	vtdtr_init_rxq(sc, 0);
	vtdtr_init_txq(sc, 0);

	error = vtdtr_alloc_virtqueues(sc);
	if (error) {
		device_printf(dev, "cannot allocate virtqueues\n");
		goto fail;
	}

	device_printf(dev, "txq = %s, rxq = %s\n",
	    sc->vtdtr_txq.vtdq_name, sc->vtdtr_rxq.vtdq_name);

	error = vtdtr_queue_populate(&sc->vtdtr_rxq);
	if (error) {
		device_printf(dev, "cannot populate %s\n",
		    sc->vtdtr_rxq.vtdq_name);
		goto fail;
	}
	/* Claim the sole transport before installing an interrupt handler;
	 * a failed second attach must never process NODE_ID. */
	error = dtt_register_transport(vtdtr_enqueue, vtdtr_identity,
	    vtdtr_rekey_commit, vtdtr_cleanup_query, sc);
	if (error != 0)
		goto fail;
	sc->vtdtr_registered = true;

	error = virtio_setup_intr(dev, INTR_TYPE_MISC);
	if (error) {
		device_printf(dev, "cannot set up virtio interrupts\n");
		goto fail;
	}

	error = vtdtr_start_taskqueues(sc);
	if (error != 0)
		goto fail;
	error = kthread_add(vtdtr_run, sc, NULL, &sc->vtdtr_commtd,
	    0, 0, "vtdtr_communicator");
	if (error != 0)
		goto fail;

	mtx_lock(&sc->vtdtr_mtx);
	vtdtr_enable_interrupts(sc);
	sc->vtdtr_ready = 0;
	error = vtdtr_notify_ready(sc);
	if (error == 0)
		error = vtdtr_query_node_id(sc);
	mtx_unlock(&sc->vtdtr_mtx);

fail:
	if (error)
		vtdtr_detach(dev);

	return (error);
}

static void
vtdtr_cq_destroy(struct vtdtr_softc *sc)
{
	struct vtdtr_ctrl_entry *n1, *n2;

	mtx_lock(&sc->vtdtr_ctrlmtx);
	n1 = STAILQ_FIRST(&sc->vtdtr_ctrlq->head);
	while (n1 != NULL) {
		n2 = STAILQ_NEXT(n1, entries);
		free(n1->ctrl, M_DEVBUF);
		free(n1, M_DEVBUF);
		n1 = n2;
	}

	STAILQ_INIT(&sc->vtdtr_ctrlq->head);
	sc->vtdtr_ctrlq->n_entries = 0;
	mtx_unlock(&sc->vtdtr_ctrlmtx);
}

/*
 * Here we free all the used memory in the
 * driver, drain all the taskqeueues and
 * destroy all the mutexes.
 */
static int
vtdtr_detach(device_t dev)
{
	struct vtdtr_softc *sc = device_get_softc(dev);

	mtx_lock(&sc->vtdtr_mtx);
	vtdtr_stop(sc);
	mtx_unlock(&sc->vtdtr_mtx);
	/* Drain callbacks before reclaiming their queue and mutex owners. */
	virtio_teardown_intr(dev);
	if (sc->vtdtr_commtd != NULL) {
		sema_wait(&sc->vtdtr_exit);
		sc->vtdtr_commtd = NULL;
	}
	vtdtr_drain_taskqueues(sc);
	/* Keep ownership exclusive until the last RX task can no longer
	 * publish a node ID. A failed second attach never owns this identity. */
	vtdtr_clear_node_identity(sc);
	if (sc->vtdtr_registered) {
		dtt_unregister_transport(sc);
		sc->vtdtr_registered = false;
	}
	vtdtr_drain_virtqueues(sc);
	vtdtr_queue_destroy(&sc->vtdtr_rxq);
	vtdtr_queue_destroy(&sc->vtdtr_txq);
	vtdtr_cq_destroy(sc);
	mtx_destroy(&sc->vtdtr_ctrlmtx);
	free(sc->vtdtr_ctrlq, M_DEVBUF);
	cv_destroy(&sc->vtdtr_condvar);
	sema_destroy(&sc->vtdtr_exit);
	mtx_destroy(&sc->vtdtr_mtx);
	return (0);
}

static int
vtdtr_config_change(device_t dev)
{
	/*
	 * There is no reason to change the configuration yet.
	 */
	return (0);
}

/*
 * Wrapper function for virtio_negotiate_features()
 */
static int
vtdtr_negotiate_features(struct vtdtr_softc *sc)
{
	device_t dev;
	uint64_t required;

	dev = sc->vtdtr_dev;
	required = VTDTR_WIRE_F_SESSION_REQUIRED;

	sc->vtdtr_features = virtio_negotiate_features(dev,
	    required | VTDTR_WIRE_F_CONTINUITY | VTDTR_WIRE_F_SESSION_STOP_V1 |
	    VTDTR_WIRE_F_SESSION_FRESH_V1);
	return ((sc->vtdtr_features & required) == required ?
	    0 : ENOTSUP);
}

/*
 * Set up the features that this driver can handle
 */
static int
vtdtr_setup_features(struct vtdtr_softc *sc)
{
	int error;

	error = vtdtr_negotiate_features(sc);
	if (error != 0)
		return (error);
	return (virtio_finalize_features(sc->vtdtr_dev));
}

/*
 * Allocate all the virtqueues.
 */
static int
vtdtr_alloc_virtqueues(struct vtdtr_softc *sc)
{
	device_t dev;
	struct vq_alloc_info *info;
	struct virtio_dtrace_queue *rxq, *txq;
	int error;

	dev = sc->vtdtr_dev;
	rxq = &sc->vtdtr_rxq;
	txq = &sc->vtdtr_txq;
	rxq->vtdq_vqintr = vtdtr_rxq_vq_intr;
	txq->vtdq_vqintr = vtdtr_txq_vq_intr;

	info = malloc(2 * sizeof(struct vq_alloc_info), M_TEMP, M_WAITOK);

	VQ_ALLOC_INFO_INIT(&info[0], sc->vtdtr_rx_nseg, rxq->vtdq_vqintr, sc,
	    &rxq->vtdq_vq, "%s-control RX", device_get_nameunit(dev));
	VQ_ALLOC_INFO_INIT(&info[1], sc->vtdtr_tx_nseg, txq->vtdq_vqintr, sc,
	    &txq->vtdq_vq, "%s-control TX", device_get_nameunit(dev));

	error = virtio_alloc_virtqueues(dev, 2, info);
	free(info, M_TEMP);
	if (error == 0) {
		/*
		 * Host-side predicates cannot prevent guest forwarding. Exclude
		 * both queues before population, registration or interrupt setup.
		 */
		virtqueue_disable_sdt(rxq->vtdq_vq);
		virtqueue_disable_sdt(txq->vtdq_vq);
	}

	return (error);
}

static void
vtdtr_stop(struct vtdtr_softc *sc)
{
	/* Serialize with the worker before resetting descriptors it owns. */
	mtx_lock(&sc->vtdtr_ctrlmtx);
	atomic_store_int(&sc->vtdtr_shutdown, 1);
	cv_broadcast(&sc->vtdtr_condvar);
	mtx_unlock(&sc->vtdtr_ctrlmtx);
	if (mtx_initialized(&sc->vtdtr_rxq.vtdq_mtx))
		VTDTR_QUEUE_LOCK(&sc->vtdtr_rxq);
	if (mtx_initialized(&sc->vtdtr_txq.vtdq_mtx))
		VTDTR_QUEUE_LOCK(&sc->vtdtr_txq);
	vtdtr_disable_interrupts(sc);
	virtio_stop(sc->vtdtr_dev);
	if (mtx_initialized(&sc->vtdtr_txq.vtdq_mtx))
		VTDTR_QUEUE_UNLOCK(&sc->vtdtr_txq);
	if (mtx_initialized(&sc->vtdtr_rxq.vtdq_mtx))
		VTDTR_QUEUE_UNLOCK(&sc->vtdtr_rxq);
}

/*
 * A wrapper function around vtdtr_queue_enqueue_ctrl() used to requeue a
 * descriptor we have just processed in the RX taskqueue.
 */
static int
vtdtr_queue_requeue_ctrl(struct virtio_dtrace_queue *q,
    struct virtio_dtrace_control *ctrl, int readable, int writable)
{
	memset(ctrl, 0, sizeof(struct virtio_dtrace_control));
	return (vtdtr_queue_enqueue_ctrl(q, ctrl, readable, writable));
}

/*
 * A simple function used to populate the RX queue in the initialization
 */
static int
vtdtr_queue_populate(struct virtio_dtrace_queue *q)
{
	struct virtqueue *vq;
	int nbufs;
	int error;

	vq = q->vtdq_vq;
	error = ENOSPC;

	for (nbufs = 0; !virtqueue_full(vq); nbufs++) {
		error = vtdtr_queue_new_ctrl(q);
		if (error)
			break;
	}

	if (nbufs > 0) {
		virtqueue_notify(vq);
		error = 0;
	}

	return (error);
}

/*
 * Wrapper around the vtdtr_queue_enqueue_ctrl() function in order to create a
 * new descriptor in the RX queue.
 */
static int
vtdtr_queue_new_ctrl(struct virtio_dtrace_queue *q)
{
	struct virtio_dtrace_control *ctrl;
	int error;

	ctrl = malloc(sizeof(struct virtio_dtrace_control),
	    M_DEVBUF, M_WAITOK | M_ZERO);

	error = vtdtr_queue_enqueue_ctrl(q, ctrl, 0, 1);
	if (error)
		free(ctrl, M_DEVBUF);

	return (error);
}

/*
 * A more hands-on function used to enqueue a control message in the virtqueue.
 * We use this in order to enqueue empty descriptors in the RX queue with the
 * writable >= 1 and readable == 0, and to enqueue control messages in the TX
 * queue with readable >= 1 and writable == 0.
 */
static int
vtdtr_queue_enqueue_ctrl(struct virtio_dtrace_queue *q,
    struct virtio_dtrace_control *ctrl, int readable, int writable)
{
	struct sglist_seg seg[2];
	struct sglist sg;
	struct virtqueue *vq;
	int error;

	vq = q->vtdq_vq;

	/* A control buffer may cross a physical page boundary. */
	CTASSERT(sizeof(*ctrl) <= PAGE_SIZE);
	sglist_init(&sg, nitems(seg), seg);
	error = sglist_append(&sg, ctrl, sizeof(*ctrl));
	KASSERT(error == 0, ("%s: control crosses more than one page (%d)",
	    __func__, error));

	error = virtqueue_enqueue(vq, ctrl, &sg,
	    readable ? sg.sg_nseg : 0, writable ? sg.sg_nseg : 0);

	return (error);
}

static void
vtdtr_sync_fn(void *arg __unused)
{
}

static void
vtdtr_clear_node_identity(struct vtdtr_softc *sc)
{
	if (!sc->vtdtr_registered || sc->vtdtr_node_id == 0 ||
	    dtrace_node_id != sc->vtdtr_node_id)
		return;
	mbufid_origin_epoch_set(0);
	dtrace_node_id = 0;
	smp_rendezvous_cpus(all_cpus, smp_no_rendezvous_barrier,
	    vtdtr_sync_fn, smp_no_rendezvous_barrier, NULL);
}

/*
 * Used for identification of the event type we need to process and delegating
 * it to the according functions.
 */
CTASSERT(VIRTIO_DTRACE_MAXELFLEN <= DTT_MAXDATALEN);

static bool
vtdtr_elf_valid(size_t length, size_t total, int more)
{
	return (length != 0 && length <= VIRTIO_DTRACE_MAXELFLEN &&
	    total >= length &&
	    total <= 64U * 1024U * 1024U - 4096U &&
	    (more == 0 || (more == 1 && length < total)));
}

/* ctrlmtx serializes initial delivery, retry, and the daemon's proof. */
static void
vtdtr_session_stop_notify(struct vtdtr_softc *sc)
{
	dtt_entry_t event = { .event_kind = DTT_SESSION_STOP };
	if (!sc->vtdtr_session_stop || sc->vtdtr_session_stop_queued)
		return;
	VTDTR_STATE_ASSERT(sc);
	event.u.cleanup.vmid = sc->vtdtr_cleanup_vmid;
	event.u.cleanup.epoch = sc->vtdtr_cleanup_epoch;
	event.u.cleanup.delivery_id = sc->vtdtr_cleanup_delivery_id;
	if (dtt_queue_session_stop(&event) == 0)
		sc->vtdtr_session_stop_queued = true;
}

static int
vtdtr_ctrl_process_event(struct vtdtr_softc *sc,
    struct virtio_dtrace_control *ctrl, uint32_t length)
{
	device_t dev;
	int retval;
	dtt_entry_t e;
	bool rekey_pending, session_stop;

	if (length != sizeof(*ctrl))
		return (EINVAL);
	/*
	 * bhyve closes its guest-ready gate after every batch that carries a
	 * control other than READY or EOF and reopens it only on READY, so
	 * each such control is owed one.  The RX task sends it once the batch
	 * is processed unless the rekey or session-stop fence withholds it.
	 */
	if (ctrl->vd_event != VIRTIO_DTRACE_DEVICE_READY &&
	    ctrl->vd_event != VIRTIO_DTRACE_EOF)
		sc->vtdtr_ready = 0;
	/* A queued control after NODE_REKEY cannot run against journals that
	 * still name the source incarnation.  The host must wait for a separate
	 * durable commit acknowledgement, not an ordinary READY. */
	mtx_lock(&sc->vtdtr_ctrlmtx);
	rekey_pending = sc->vtdtr_rekeyed;
	session_stop = sc->vtdtr_session_stop;
	mtx_unlock(&sc->vtdtr_ctrlmtx);
	/* READY permits only retransmission of the stop proof. It cannot
	 * authorize new tracing work or clear the stopped-session state. */
	if (session_stop && ctrl->vd_event != VIRTIO_DTRACE_SESSION_STOP &&
	    ctrl->vd_event != VIRTIO_DTRACE_SESSION_PREPARE &&
	    ctrl->vd_event != VIRTIO_DTRACE_SESSION_COMMIT &&
	    ctrl->vd_event != VIRTIO_DTRACE_DEVICE_READY &&
	    ctrl->vd_event != VIRTIO_DTRACE_EOF)
		return (EBUSY);
	if (rekey_pending && ctrl->vd_event != VIRTIO_DTRACE_NODE_REKEY &&
	    ctrl->vd_event != VIRTIO_DTRACE_REKEY_COMMITTED &&
	    ctrl->vd_event != VIRTIO_DTRACE_REKEY_DELIVERY_RECEIPT &&
	    ctrl->vd_event != VIRTIO_DTRACE_REKEY_INGRESS_RECEIPT &&
	    ctrl->vd_event != VIRTIO_DTRACE_REKEY_KILL_RECEIPT)
		return (EBUSY);
	dev = sc->vtdtr_dev;
	retval = 0;
	memset(&e, 0, sizeof(e));

	switch (ctrl->vd_event) {
	case VIRTIO_DTRACE_SESSION_COMMIT: {
		const __typeof(ctrl->wire.uctrl.session_prepare) *request =
		    &ctrl->wire.uctrl.session_prepare;
		mtx_lock(&sc->vtdtr_ctrlmtx);
		VTDTR_STATE_ASSERT(sc);
		/* Only this task sets rekeyed; the snapshot above was false. */
		KASSERT(!sc->vtdtr_rekeyed, ("%s: commit while rekeyed",
		    __func__));
		if ((sc->vtdtr_features & VTDTR_WIRE_F_SESSION_FRESH_V1) == 0 ||
		    request->reserved != 0 ||
		    (sc->vtdtr_fresh_identity.flags != DTT_IDENTITY_FRESH_READY &&
		    sc->vtdtr_fresh_identity.flags != DTT_IDENTITY_FRESH_ACTIVE) ||
		    request->stop_token == 0 ||
		    request->stop_token != sc->vtdtr_cleanup_delivery_id ||
		    request->old_id != sc->vtdtr_fresh_identity.old_vmid ||
		    request->old_epoch != sc->vtdtr_fresh_identity.old_epoch ||
		    request->new_id != sc->vtdtr_fresh_identity.vmid ||
		    request->new_epoch != sc->vtdtr_fresh_identity.epoch ||
		    (sc->vtdtr_fresh_identity.flags == DTT_IDENTITY_FRESH_ACTIVE &&
		    sc->vtdtr_session_stop)) {
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			return (ESTALE);
		}
		sc->vtdtr_fresh_commit_pending = true;
		cv_signal(&sc->vtdtr_condvar);
		mtx_unlock(&sc->vtdtr_ctrlmtx);
		break;
	}
	case VIRTIO_DTRACE_SESSION_PREPARE: {
		const __typeof(ctrl->wire.uctrl.session_prepare) *request =
		    &ctrl->wire.uctrl.session_prepare;
		if ((sc->vtdtr_features & VTDTR_WIRE_F_SESSION_FRESH_V1) == 0)
			return (ENOTSUP);
		if (request->reserved != 0 || request->stop_token == 0 ||
		    request->old_id == 0 || request->old_id >= HYPERTRACE_MAX_VMS ||
		    request->new_id == 0 || request->new_id >= HYPERTRACE_MAX_VMS ||
		    request->old_epoch == 0 || request->new_epoch == 0 ||
		    request->old_epoch == request->new_epoch)
			return (EINVAL);
		mtx_lock(&sc->vtdtr_ctrlmtx);
		VTDTR_STATE_ASSERT(sc);
		if (!sc->vtdtr_session_stop || !sc->vtdtr_cleanup_applied) {
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			return (EBUSY);
		}
		/* A stopped session's pending cleanup names the node identity. */
		if (request->stop_token != sc->vtdtr_cleanup_delivery_id ||
		    request->old_id != sc->vtdtr_node_id ||
		    request->old_epoch != sc->vtdtr_node_epoch ||
		    (sc->vtdtr_fresh_identity.flags != 0 &&
		    sc->vtdtr_fresh_identity.flags != DTT_IDENTITY_FRESH_ACTIVE &&
		    (request->new_id != sc->vtdtr_fresh_identity.vmid ||
		    request->new_epoch != sc->vtdtr_fresh_identity.epoch))) {
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			return (ESTALE);
		}
		/* Preparation neither publishes the new kernel identity nor opens
		 * admission. The new daemon must first select empty session state. */
		if (sc->vtdtr_fresh_identity.flags != 0 &&
		    sc->vtdtr_fresh_identity.flags != DTT_IDENTITY_FRESH_ACTIVE) {
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			break;
		}
		sc->vtdtr_fresh_identity = (struct dtt_vm_identity){
		    .vmid = request->new_id, .old_vmid = request->old_id,
		    .flags = DTT_IDENTITY_FRESH_PENDING,
		    .epoch = request->new_epoch, .old_epoch = request->old_epoch };
		mtx_unlock(&sc->vtdtr_ctrlmtx);
		break;
	}
	case VIRTIO_DTRACE_DEVICE_READY:
		debug_printf(dev, "VIRTIO_DTRACE_DEVICE_READY\n");
		atomic_store_int(&sc->vtdtr_host_ready, 1);

		/*
		 * We have a similar situation to one in vtdtr_stop() here. We
		 * have to lock the ctrlq mutex in order to signal the condition
		 * variable correctly and prevent indefinite waits. We can
		 * signal here because we're using two queues, so we won't have
		 * any contention between them.
		 */
		mtx_lock(&sc->vtdtr_ctrlmtx);
		cv_signal(&sc->vtdtr_condvar);
		mtx_unlock(&sc->vtdtr_ctrlmtx);
		break;

	case VIRTIO_DTRACE_ELF:
		debug_printf(dev, "VIRTIO_DTRACE_ELF\n");

		e.event_kind = DTT_ELF;
		const uint8_t zero_id[16] = { 0 };
		if (memcmp(ctrl->vd_program_id, zero_id, 16) == 0 ||
		    memcmp(ctrl->vd_elf_source_id, zero_id, 16) == 0)
			return (EINVAL);
		if (ctrl->vd_delivery_id == 0 || ctrl->vd_vmid == 0 ||
		    ctrl->vd_vmid >= HYPERTRACE_MAX_VMS || ctrl->vd_epoch == 0 ||
		    ctrl->vd_vmid != sc->vtdtr_node_id ||
		    ctrl->vd_epoch != sc->vtdtr_node_epoch)
			return (EINVAL);
		if (!vtdtr_elf_valid(ctrl->vd_elflen, ctrl->vd_totalelflen,
		    ctrl->vd_elfhasmore))
			return (EINVAL);
		memcpy(e.u.elf.data, ctrl->vd_elf, ctrl->vd_elflen);
		e.u.elf.identifier = ctrl->vd_identifier;
		e.u.elf.delivery_id = ctrl->vd_delivery_id;
		e.u.elf.vmid = ctrl->vd_vmid;
		e.u.elf.epoch = ctrl->vd_epoch;
		memcpy(e.u.elf.program_id, ctrl->vd_program_id, 16);
		memcpy(e.u.elf.source_id, ctrl->vd_elf_source_id, 16);
		e.u.elf.len = ctrl->vd_elflen;
		e.u.elf.totallen = ctrl->vd_totalelflen;
		e.u.elf.hasmore = ctrl->vd_elfhasmore;

		retval = dtt_queue_enqueue(&e);
		break;

	case VIRTIO_DTRACE_KILL:
	case VIRTIO_DTRACE_HOST_KILL_APPLIED:
		debug_printf(dev, "VIRTIO_DTRACE_KILL\n");

		if (ctrl->vd_pid <= 1 ||
		    ctrl->vd_kill_vmid != sc->vtdtr_node_id ||
		    ctrl->vd_kill_epoch != sc->vtdtr_node_epoch)
			return (EINVAL);
		const uint8_t zero_source[16] = { 0 };
		if (memcmp(ctrl->vd_source_id, zero_source, 16) == 0)
			return (EINVAL);
		e.event_kind = ctrl->vd_event == VIRTIO_DTRACE_KILL ?
		    DTT_KILL : DTT_HOST_KILL_APPLIED;
		e.u.kill.pid = ctrl->vd_pid;
		memcpy(e.u.kill.source_id, ctrl->vd_source_id, 16);
		e.u.kill.vmid = ctrl->vd_kill_vmid;
		e.u.kill.epoch = ctrl->vd_kill_epoch;

		retval = dtt_queue_enqueue(&e);
		break;

	case VIRTIO_DTRACE_HOST_INSTALLED:
	case VIRTIO_DTRACE_HOST_UNINSTALLED:
	case VIRTIO_DTRACE_HOST_STATUS:
	case VIRTIO_DTRACE_HOST_INGRESS_STATUS:
	case VIRTIO_DTRACE_HOST_ELF:
		{
			const uint8_t zero_id[16] = { 0 };
			if (ctrl->vd_installed_delivery_id == 0 ||
			    ctrl->vd_installed_vmid == 0 ||
			    ctrl->vd_installed_vmid >= HYPERTRACE_MAX_VMS ||
			    ctrl->vd_installed_epoch == 0 ||
			    ctrl->vd_installed_vmid != sc->vtdtr_node_id ||
			    ctrl->vd_installed_epoch != sc->vtdtr_node_epoch ||
			    memcmp(ctrl->vd_installed_program_id, zero_id, 16) == 0 ||
			    memcmp(ctrl->vd_installed_source_id, zero_id, 16) == 0)
				return (EINVAL);
			if (ctrl->vd_event == VIRTIO_DTRACE_HOST_STATUS ||
			    ctrl->vd_event == VIRTIO_DTRACE_HOST_INGRESS_STATUS) {
				bool ingress = ctrl->vd_event ==
				    VIRTIO_DTRACE_HOST_INGRESS_STATUS;
				if (ctrl->vd_installed_query_id == 0 ||
				    (ingress ?
				    (ctrl->vd_installed_phase != 0 &&
				    ctrl->vd_installed_phase != 'p' &&
				    ctrl->vd_installed_phase != 'a' &&
				    ctrl->vd_installed_phase != 'u') :
				    (ctrl->vd_installed_phase != 0 &&
				    ctrl->vd_installed_phase != 'p' &&
				    ctrl->vd_installed_phase != 'a' &&
				    ctrl->vd_installed_phase != 'i' &&
				    ctrl->vd_installed_phase != 't' &&
				    ctrl->vd_installed_phase != 'u')) ||
				    ctrl->vd_installed_revoked > 1 ||
				    (ingress ? ctrl->vd_installed_replay != 0 :
				    ctrl->vd_installed_replay > 1) ||
				    (ctrl->vd_installed_replay != 0 &&
				    (ctrl->vd_installed_revoked != 0 ||
				    (ctrl->vd_installed_phase != 'a' &&
				    ctrl->vd_installed_phase != 'i'))) ||
				    (!ingress && ctrl->vd_installed_replay == 0 &&
				    memcmp(ctrl->vd_installed_digest,
				    (const uint8_t[32]){0}, 32) != 0) ||
				    (ingress &&
				    ((ctrl->vd_installed_phase == 'p' ||
				    ctrl->vd_installed_phase == 'a') ==
				    (memcmp(ctrl->vd_installed_digest,
				    (const uint8_t[32]){0}, 32) == 0))) ||
				    (ctrl->vd_installed_phase == 'u' &&
				    ctrl->vd_installed_revoked != 0))
					return (EINVAL);
				e.event_kind = ingress ?
				    DTT_HOST_INGRESS_STATUS : DTT_HOST_STATUS;
			} else {
				if (ctrl->vd_installed_phase != 0 ||
				    ctrl->vd_installed_revoked != 0 ||
				    ctrl->vd_installed_replay != 0 ||
				    ((ctrl->vd_event == VIRTIO_DTRACE_HOST_ELF) ==
				    (memcmp(ctrl->vd_installed_digest,
				    (const uint8_t[32]){0}, 32) == 0)) ||
				    ctrl->vd_installed_query_id != 0)
					return (EINVAL);
			e.event_kind = ctrl->vd_event ==
			    VIRTIO_DTRACE_HOST_INSTALLED ? DTT_HOST_INSTALLED :
			    ctrl->vd_event == VIRTIO_DTRACE_HOST_ELF ?
			    DTT_HOST_ELF : DTT_HOST_UNINSTALLED;
			}
			e.u.installed.delivery_id = ctrl->vd_installed_delivery_id;
			e.u.installed.vmid = ctrl->vd_installed_vmid;
			e.u.installed.epoch = ctrl->vd_installed_epoch;
			memcpy(e.u.installed.program_id,
			    ctrl->vd_installed_program_id, 16);
			memcpy(e.u.installed.source_id,
			    ctrl->vd_installed_source_id, 16);
			e.u.installed.phase = ctrl->vd_installed_phase;
			e.u.installed.revoked = ctrl->vd_installed_revoked;
			e.u.installed.replay = ctrl->vd_installed_replay;
			e.u.installed.query_id = ctrl->vd_installed_query_id;
			memcpy(e.u.installed.digest,
			    ctrl->vd_installed_digest, 32);
			retval = dtt_queue_enqueue(&e);
		}
		break;

	case VIRTIO_DTRACE_SESSION_STOP:
	case VIRTIO_DTRACE_CLEANUP_DTRACED:
		debug_printf(dev, "VIRTIO_DTRACE_CLEANUP_DTRACED\n");

		if (ctrl->vd_event == VIRTIO_DTRACE_SESSION_STOP &&
		    (sc->vtdtr_features & VTDTR_WIRE_F_SESSION_STOP_V1) == 0)
			return (ENOTSUP);
		if (ctrl->vd_cleanup_vmid == 0 ||
		    ctrl->vd_cleanup_epoch == 0 ||
		    ctrl->vd_cleanup_delivery_id == 0)
			return (EINVAL);
		/* The communicator thread changes the node identity under
		 * ctrlmtx when it activates a committed fresh session. */
		mtx_lock(&sc->vtdtr_ctrlmtx);
		VTDTR_STATE_ASSERT(sc);
		if (ctrl->vd_cleanup_vmid != sc->vtdtr_node_id ||
		    ctrl->vd_cleanup_epoch != sc->vtdtr_node_epoch) {
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			return (EINVAL);
		}
		if (sc->vtdtr_cleanup_pending) {
			/* A stopped session admits only SESSION_STOP here. */
			KASSERT(!sc->vtdtr_session_stop ||
			    ctrl->vd_event == VIRTIO_DTRACE_SESSION_STOP,
			    ("%s: cleanup control while stopped", __func__));
			bool exact_stop = sc->vtdtr_session_stop &&
			    ctrl->vd_cleanup_delivery_id ==
			    sc->vtdtr_cleanup_delivery_id;
			if (exact_stop) {
				vtdtr_session_stop_notify(sc);
				cv_signal(&sc->vtdtr_condvar);
			}
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			return (exact_stop ? 0 : EBUSY);
		}
		sc->vtdtr_session_stop =
		    ctrl->vd_event == VIRTIO_DTRACE_SESSION_STOP;
		sc->vtdtr_fresh_commit_pending = false;
		sc->vtdtr_cleanup_pending = true;
		sc->vtdtr_cleanup_applied = false;
		sc->vtdtr_cleanup_vmid = ctrl->vd_cleanup_vmid;
		sc->vtdtr_cleanup_epoch = ctrl->vd_cleanup_epoch;
		sc->vtdtr_cleanup_delivery_id = ctrl->vd_cleanup_delivery_id;
		if (sc->vtdtr_session_stop) {
			vtdtr_session_stop_notify(sc);
			cv_signal(&sc->vtdtr_condvar);
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			break;
		}
		mtx_unlock(&sc->vtdtr_ctrlmtx);
		e.event_kind = DTT_CLEANUP_DTRACED;
		e.u.cleanup.delivery_id = ctrl->vd_cleanup_delivery_id;
		e.u.cleanup.vmid = ctrl->vd_cleanup_vmid;
		e.u.cleanup.epoch = ctrl->vd_cleanup_epoch;

		retval = dtt_queue_enqueue(&e);
		if (retval != 0) {
			mtx_lock(&sc->vtdtr_ctrlmtx);
			sc->vtdtr_cleanup_pending = false;
			mtx_unlock(&sc->vtdtr_ctrlmtx);
		}
		break;

	case VIRTIO_DTRACE_HOST_CLEANUP_APPLIED:
		mtx_lock(&sc->vtdtr_ctrlmtx);
		if (!sc->vtdtr_cleanup_pending &&
		    ctrl->vd_cleanup_delivery_id != 0 &&
		    ctrl->vd_cleanup_delivery_id ==
		    sc->vtdtr_cleanup_last_accepted_id &&
		    ctrl->vd_cleanup_vmid == sc->vtdtr_node_id &&
		    ctrl->vd_cleanup_epoch == sc->vtdtr_node_epoch) {
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			break;
		}
		if (sc->vtdtr_cleanup_pending &&
		    ctrl->vd_cleanup_delivery_id != 0 &&
		    ctrl->vd_cleanup_delivery_id ==
		    sc->vtdtr_cleanup_last_accepted_id &&
		    ctrl->vd_cleanup_delivery_id !=
		    sc->vtdtr_cleanup_delivery_id &&
		    ctrl->vd_cleanup_vmid == sc->vtdtr_node_id &&
		    ctrl->vd_cleanup_epoch == sc->vtdtr_node_epoch) {
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			break;
		}
		if (!sc->vtdtr_cleanup_pending ||
		    !sc->vtdtr_cleanup_applied ||
		    sc->vtdtr_cleanup_vmid != ctrl->vd_cleanup_vmid ||
		    sc->vtdtr_cleanup_epoch != ctrl->vd_cleanup_epoch ||
		    sc->vtdtr_cleanup_delivery_id !=
		    ctrl->vd_cleanup_delivery_id) {
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			return (ESTALE);
		}
		sc->vtdtr_cleanup_pending = false;
		sc->vtdtr_cleanup_applied = false;
		sc->vtdtr_cleanup_last_accepted_id =
		    ctrl->vd_cleanup_delivery_id;
		mtx_unlock(&sc->vtdtr_ctrlmtx);
		break;

	case VIRTIO_DTRACE_REKEY_DELIVERY_RECEIPT:
	case VIRTIO_DTRACE_REKEY_INGRESS_RECEIPT:
	case VIRTIO_DTRACE_REKEY_KILL_RECEIPT: {
		bool kill, terminal, unavailable;
		uint32_t query_event;

		kill = ctrl->vd_event == VIRTIO_DTRACE_REKEY_KILL_RECEIPT;
		query_event = kill ? VIRTIO_DTRACE_REKEY_KILL_QUERY :
		    ctrl->vd_event == VIRTIO_DTRACE_REKEY_INGRESS_RECEIPT ?
		    VIRTIO_DTRACE_REKEY_INGRESS_QUERY :
		    VIRTIO_DTRACE_REKEY_DELIVERY_QUERY;
		mtx_lock(&sc->vtdtr_ctrlmtx);
		if ((sc->vtdtr_features & VTDTR_WIRE_F_REKEY_RECEIPT_V1) == 0 ||
		    !sc->vtdtr_rekeyed || !sc->vtdtr_rekey_query_pending ||
		    sc->vtdtr_rekey_query_event != query_event ||
		    ctrl->vd_installed_vmid != sc->vtdtr_rekey_old_id ||
		    ctrl->vd_installed_epoch != sc->vtdtr_rekey_old_epoch ||
		    ctrl->vd_installed_delivery_id !=
		    sc->vtdtr_rekey_query_delivery_id ||
		    ctrl->vd_installed_query_id != sc->vtdtr_rekey_query_id ||
		    memcmp(ctrl->vd_installed_program_id,
		    sc->vtdtr_rekey_query_program_id, 16) != 0 ||
		    memcmp(ctrl->vd_installed_source_id,
		    sc->vtdtr_rekey_query_source_id, 16) != 0) {
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			return (ESTALE);
		}
		unavailable = ctrl->vd_installed_phase == 'u';
		terminal = query_event == VIRTIO_DTRACE_REKEY_DELIVERY_QUERY &&
		    ctrl->vd_installed_phase == 't';
		if ((unavailable &&
		    (ctrl->vd_installed_revoked != 0 ||
		    ctrl->vd_installed_replay != 0 ||
		    memcmp(ctrl->vd_installed_digest,
		    (const uint8_t[32]){0}, 32) != 0)) ||
		    (!unavailable &&
		    (ctrl->vd_installed_replay != 0 ||
		    (kill ?
		    ((ctrl->vd_installed_phase != 'p' &&
		    ctrl->vd_installed_phase != 'a') ||
		    ctrl->vd_installed_revoked != 1 ||
		    memcmp(ctrl->vd_installed_digest,
		    (const uint8_t[32]){0}, 32) != 0) :
		    terminal ?
		    (ctrl->vd_installed_revoked > 1 ||
		    memcmp(ctrl->vd_installed_digest,
		    (const uint8_t[32]){0}, 32) != 0) :
		    ((query_event == VIRTIO_DTRACE_REKEY_INGRESS_QUERY ?
		    ctrl->vd_installed_phase != 'a' :
		    (ctrl->vd_installed_phase != 'a' &&
		    ctrl->vd_installed_phase != 'i')) ||
		    ctrl->vd_installed_revoked != 0 ||
		    memcmp(ctrl->vd_installed_digest,
		    sc->vtdtr_rekey_query_digest, 32) != 0))))) {
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			return (EPROTO);
		}
		e.event_kind = kill ? DTT_REKEY_KILL_RECEIPT :
		    query_event == VIRTIO_DTRACE_REKEY_INGRESS_QUERY ?
		    DTT_REKEY_INGRESS_RECEIPT : DTT_REKEY_DELIVERY_RECEIPT;
		e.u.installed.delivery_id = ctrl->vd_installed_delivery_id;
		e.u.installed.vmid = ctrl->vd_installed_vmid;
		e.u.installed.epoch = ctrl->vd_installed_epoch;
		memcpy(e.u.installed.program_id,
		    ctrl->vd_installed_program_id, 16);
		memcpy(e.u.installed.source_id,
		    ctrl->vd_installed_source_id, 16);
		e.u.installed.phase = ctrl->vd_installed_phase;
		e.u.installed.revoked = ctrl->vd_installed_revoked;
		e.u.installed.replay = ctrl->vd_installed_replay;
		e.u.installed.query_id = ctrl->vd_installed_query_id;
		memcpy(e.u.installed.digest,
		    ctrl->vd_installed_digest, 32);
		retval = dtt_queue_enqueue(&e);
		if (retval == 0)
			sc->vtdtr_rekey_query_pending = false;
		mtx_unlock(&sc->vtdtr_ctrlmtx);
		break;
	}

	case VIRTIO_DTRACE_NODE_REKEY:
		if ((sc->vtdtr_features & (VTDTR_WIRE_F_NODE_REKEY_V1 |
		    VTDTR_WIRE_F_REKEY_COMMIT_V1)) !=
		    (VTDTR_WIRE_F_NODE_REKEY_V1 |
		    VTDTR_WIRE_F_REKEY_COMMIT_V1) ||
		    ctrl->vd_rekey_old_id == 0 ||
		    ctrl->vd_rekey_old_id >= HYPERTRACE_MAX_VMS ||
		    ctrl->vd_rekey_old_epoch == 0 ||
		    ctrl->vd_rekey_new_id == 0 ||
		    ctrl->vd_rekey_new_id >= HYPERTRACE_MAX_VMS ||
		    ctrl->vd_rekey_new_epoch == 0 ||
		    (ctrl->vd_rekey_old_id == ctrl->vd_rekey_new_id &&
		    ctrl->vd_rekey_old_epoch == ctrl->vd_rekey_new_epoch))
			return (EINVAL);
		mtx_lock(&sc->vtdtr_ctrlmtx);
		if (sc->vtdtr_rekeyed || sc->vtdtr_cleanup_pending) {
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			return (EBUSY);
		}
		if (sc->vtdtr_node_id != ctrl->vd_rekey_old_id ||
		    sc->vtdtr_node_epoch != ctrl->vd_rekey_old_epoch) {
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			return (ESTALE);
		}
		/* Never switch identity without notifying the daemon. If the
		 * notification cannot be queued, the RX task stops this transport. */
		e.event_kind = DTT_VM_REKEY;
		e.u.installed.vmid = ctrl->vd_rekey_new_id;
		e.u.installed.epoch = ctrl->vd_rekey_new_epoch;
		retval = dtt_queue_enqueue_front(&e);
		if (retval != 0) {
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			return (retval);
		}
		sc->vtdtr_node_id = ctrl->vd_rekey_new_id;
		sc->vtdtr_node_epoch = ctrl->vd_rekey_new_epoch;
		sc->vtdtr_rekeyed = true;
		sc->vtdtr_rekey_local_committed = false;
		sc->vtdtr_rekey_old_id = ctrl->vd_rekey_old_id;
		sc->vtdtr_rekey_old_epoch = ctrl->vd_rekey_old_epoch;
		sc->vtdtr_rekey_query_pending = false;
		atomic_store_int(&sc->vtdtr_host_ready, 0);
		mtx_unlock(&sc->vtdtr_ctrlmtx);
		mbufid_origin_epoch_set(ctrl->vd_rekey_new_epoch);
		if (dtrace_node_id != ctrl->vd_rekey_new_id) {
			dtrace_node_id = ctrl->vd_rekey_new_id;
			smp_rendezvous_cpus(all_cpus, smp_no_rendezvous_barrier,
			    vtdtr_sync_fn, smp_no_rendezvous_barrier, NULL);
		}
		break;

	case VIRTIO_DTRACE_REKEY_COMMITTED: {
		struct virtio_dtrace_queue *txq = &sc->vtdtr_txq;
		struct virtio_dtrace_control *applied;
		struct vtdtr_ctrl_entry *entry;

		mtx_lock(&sc->vtdtr_ctrlmtx);
		VTDTR_STATE_ASSERT(sc);
		if (!sc->vtdtr_rekeyed ||
		    !sc->vtdtr_rekey_local_committed ||
		    ctrl->vd_rekey_old_id != sc->vtdtr_rekey_old_id ||
		    ctrl->vd_rekey_old_epoch != sc->vtdtr_rekey_old_epoch ||
		    ctrl->vd_rekey_new_id != sc->vtdtr_node_id ||
		    ctrl->vd_rekey_new_epoch != sc->vtdtr_node_epoch) {
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			return (ESTALE);
		}
		/* Queued source-incarnation controls cannot follow REKEY_APPLIED.
		 * Durable journals, not this volatile queue, own replay. */
		while ((entry = vtdtr_cq_dequeue(sc->vtdtr_ctrlq)) != NULL) {
			free(entry->ctrl, M_DEVBUF);
			free(entry, M_DEVBUF);
		}
		applied = malloc(sizeof(*applied), M_DEVBUF, M_NOWAIT | M_ZERO);
		if (applied == NULL) {
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			return (ENOMEM);
		}
		applied->vd_event = VIRTIO_DTRACE_REKEY_APPLIED;
		applied->vd_rekey_old_id = sc->vtdtr_rekey_old_id;
		applied->vd_rekey_old_epoch = sc->vtdtr_rekey_old_epoch;
		applied->vd_rekey_new_id = sc->vtdtr_node_id;
		applied->vd_rekey_new_epoch = sc->vtdtr_node_epoch;
		VTDTR_QUEUE_LOCK(txq);
		retval = vtdtr_queue_enqueue_ctrl(txq, applied, 1, 0);
		if (retval == 0)
			virtqueue_notify(txq->vtdq_vq);
		VTDTR_QUEUE_UNLOCK(txq);
		if (retval != 0) {
			free(applied, M_DEVBUF);
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			return (retval);
		}
		sc->vtdtr_rekeyed = false;
		sc->vtdtr_rekey_local_committed = false;
		sc->vtdtr_rekey_old_id = 0;
		sc->vtdtr_rekey_old_epoch = 0;
		sc->vtdtr_rekey_query_pending = false;
		sc->vtdtr_ready = 1;
		atomic_store_int(&sc->vtdtr_host_ready, 0);
		mtx_unlock(&sc->vtdtr_ctrlmtx);
		break;
	}

	case VIRTIO_DTRACE_NODE_ID:
		debug_printf(dev, "VIRTIO_DTRACE_NODE_ID\n");

		if (ctrl->vd_node_id == 0 ||
		    ctrl->vd_node_id >= HYPERTRACE_MAX_VMS ||
		    ctrl->vd_node_epoch == 0)
			return (EINVAL);
		/* dtt writes can enqueue an ACK concurrently with this RX task. */
		mtx_lock(&sc->vtdtr_ctrlmtx);
		if (sc->vtdtr_node_id != 0 &&
		    (sc->vtdtr_node_id != ctrl->vd_node_id ||
		    sc->vtdtr_node_epoch != ctrl->vd_node_epoch)) {
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			return (ESTALE);
		}
		sc->vtdtr_node_id = ctrl->vd_node_id;
		sc->vtdtr_node_epoch = ctrl->vd_node_epoch;
		mtx_unlock(&sc->vtdtr_ctrlmtx);
		mbufid_origin_epoch_set(ctrl->vd_node_epoch);
		if (dtrace_node_id != ctrl->vd_node_id) {
			dtrace_node_id = ctrl->vd_node_id;
			device_printf(dev,
			    "STATUS: Set DTrace node ID to %lu\n", dtrace_node_id);
			smp_rendezvous_cpus(all_cpus, smp_no_rendezvous_barrier,
			    vtdtr_sync_fn, smp_no_rendezvous_barrier, NULL);
		}
		if (ctrl->vd_node_query_id != 0) {
			e.event_kind = DTT_VM_IDENTITY;
			e.u.installed.vmid = ctrl->vd_node_id;
			e.u.installed.epoch = ctrl->vd_node_epoch;
			e.u.installed.query_id = ctrl->vd_node_query_id;
			retval = dtt_queue_enqueue(&e);
		}
		break;

	case VIRTIO_DTRACE_EOF:
		debug_printf(dev, "VIRTIO_DTRACE_EOF\n");
		retval = 1;
		break;

	default:
		device_printf(dev,
		    "WARNING: Wrong control event: %x\n", ctrl->vd_event);
		retval = EINVAL;
	}

	return (retval);
}

/*
 * Start all the taskqueues on the cpu_id = 1. This ensures that each of the
 * taskqueues have a thread assigned to them that will then process all the
 * events that take place.
 */
static int
vtdtr_start_taskqueues(struct vtdtr_softc *sc)
{
	struct virtio_dtrace_queue *rxq = &sc->vtdtr_rxq;

	return (taskqueue_start_threads(&rxq->vtdq_tq, 1, PI_SOFT,
	    "%s rxq %d", device_get_nameunit(sc->vtdtr_dev), rxq->vtdq_id));
}

/*
 * Drain all the taskqueues in the driver
 */
static void
vtdtr_drain_taskqueues(struct vtdtr_softc *sc)
{
	struct virtio_dtrace_queue *rxq;
	struct virtio_dtrace_queue *txq __diagused;

	rxq = &sc->vtdtr_rxq;
	txq = &sc->vtdtr_txq;

	if (rxq->vtdq_tq != NULL)
		taskqueue_drain(rxq->vtdq_tq, &rxq->vtdq_intrtask);
	/* The TX queue has no taskqueue (see vtdtr_init_txq). */
	MPASS(txq->vtdq_tq == NULL);
}

static void
vtdtr_drain_virtqueues(struct vtdtr_softc *sc)
{
	struct virtio_dtrace_queue *rxq, *txq;
	struct virtio_dtrace_control *ctrl;
	struct virtqueue *vq;
	int last;

	rxq = &sc->vtdtr_rxq;
	txq = &sc->vtdtr_txq;
	last = 0;

	vq = rxq->vtdq_vq;

	while (vq != NULL && (ctrl = virtqueue_drain(vq, &last)) != NULL)
		free(ctrl, M_DEVBUF);

	/* The drain cursor is per virtqueue.  Reusing the RX end index
	 * would skip every TX descriptor and leak its control buffer. */
	vq = txq->vtdq_vq;
	last = 0;

	while (vq != NULL && (ctrl = virtqueue_drain(vq, &last)) != NULL)
		free(ctrl, M_DEVBUF);
}

/*
 * Disable interrupts on all of the virtqueues in the virtio driver
 */
static void
vtdtr_disable_interrupts(struct vtdtr_softc *sc)
{
	mtx_assert(&sc->vtdtr_mtx, MA_OWNED);
	if (sc->vtdtr_rxq.vtdq_vq != NULL)
		vtdtr_vq_disable_intr(&sc->vtdtr_rxq);
	if (sc->vtdtr_txq.vtdq_vq != NULL)
		vtdtr_vq_disable_intr(&sc->vtdtr_txq);
}

/*
 * Enable interrupts on all of the virtqueues in the virtio driver.
 */
static void
vtdtr_enable_interrupts(struct vtdtr_softc *sc)
{
	/* Attach already owns this mutex. Taking it again deadlocks. */
	mtx_assert(&sc->vtdtr_mtx, MA_OWNED);
	if (vtdtr_vq_enable_intr(&sc->vtdtr_rxq) != 0)
		taskqueue_enqueue(sc->vtdtr_rxq.vtdq_tq,
		    &sc->vtdtr_rxq.vtdq_intrtask);
	(void)vtdtr_vq_enable_intr(&sc->vtdtr_txq);
}

/*
 * A wrapper function to enable interrupts in a virtqueue
 */
static int
vtdtr_vq_enable_intr(struct virtio_dtrace_queue *q)
{
	struct vtdtr_softc *sc __unused;
	sc = q->vtdq_sc;

	mtx_assert(&sc->vtdtr_mtx, MA_OWNED);
	return (virtqueue_enable_intr(q->vtdq_vq));
}

/*
 * A wrapper function to disable interrupts in a virtqueue
 */
static void
vtdtr_vq_disable_intr(struct virtio_dtrace_queue *q)
{
	struct vtdtr_softc *sc __unused;
	sc = q->vtdq_sc;

	mtx_assert(&sc->vtdtr_mtx, MA_OWNED);
	virtqueue_disable_intr(q->vtdq_vq);
}

/*
 * This function is used to enqueue the READY descriptor in the TX virtqueue. If
 * we already are ready, we simply notify the communicator thread that it is
 * safe to proceed execution. If not, we enqueue the said descriptor and
 * following that notify the communicator.
 */
static int
vtdtr_notify_ready(struct vtdtr_softc *sc)
{
	int error;

	error = vtdtr_fill_desc(&sc->vtdtr_txq, &ready_ctrl);
	if (error == 0)
		sc->vtdtr_ready = 1;
	return (error);
}

static int
vtdtr_query_node_id(struct vtdtr_softc *sc)
{
	return (vtdtr_fill_desc(&sc->vtdtr_txq, &query_node_id_ctrl));
}

/*
 * The separate thread (created by the taskqueue) that acts as an interrupt
 * handler that blocks, allowing us to process more interrupts. In here we
 * dequeue every control message until we have either dequeued the maximum
 * allowed size of the virtqueue or until we hit an EOF descriptor. We process
 * each of the events lockless and finally notify that we are ready after
 * processing every event. Additionally, this function is responsible for
 * requeuing the memory in the virtqueue.
 */
static void
vtdtr_rxq_tq_intr(void *xrxq, int pending)
{
	struct vtdtr_softc *sc;
	struct virtio_dtrace_queue *rxq;
	struct virtio_dtrace_control *ctrl;
	uint32_t len;
	int retval, error;
	bool rekey_pending;

	rxq = xrxq;
	sc = rxq->vtdq_sc;
	retval = 0;

	VTDTR_QUEUE_LOCK(rxq);
	while (!atomic_load_int(&sc->vtdtr_shutdown) &&
	    (ctrl = virtqueue_dequeue(rxq->vtdq_vq, &len)) != NULL) {
		VTDTR_QUEUE_UNLOCK(rxq);
		retval = vtdtr_ctrl_process_event(sc, ctrl, len);
		if (retval != 0 && retval != 1) {
			/* A lost fragment invalidates the stream: never send READY. */
			device_printf(sc->vtdtr_dev,
			    "control receive failed (%d); transport stopped\n", retval);
			mtx_lock(&sc->vtdtr_mtx);
			vtdtr_stop(sc);
			mtx_unlock(&sc->vtdtr_mtx);
			free(ctrl, M_DEVBUF);
			return;
		}
		VTDTR_QUEUE_LOCK(rxq);

		if (atomic_load_int(&sc->vtdtr_shutdown)) {
			free(ctrl, M_DEVBUF);
			break;
		}
		error = vtdtr_queue_requeue_ctrl(rxq, ctrl, 0, 1);
		if (error != 0) {
			VTDTR_QUEUE_UNLOCK(rxq);
			device_printf(sc->vtdtr_dev,
			    "cannot requeue RX control (%d); transport stopped\n",
			    error);
			mtx_lock(&sc->vtdtr_mtx);
			vtdtr_stop(sc);
			mtx_unlock(&sc->vtdtr_mtx);
			free(ctrl, M_DEVBUF);
			return;
		}
		if (retval == 1)
			break;
	}
	VTDTR_QUEUE_UNLOCK(rxq);

	mtx_lock(&sc->vtdtr_mtx);
	if (atomic_load_int(&sc->vtdtr_shutdown)) {
		mtx_unlock(&sc->vtdtr_mtx);
		return;
	}
	vtdtr_notify(rxq);
	if (vtdtr_vq_enable_intr(rxq) != 0)
		taskqueue_enqueue(rxq->vtdq_tq, &rxq->vtdq_intrtask);

	mtx_lock(&sc->vtdtr_ctrlmtx);
	rekey_pending = sc->vtdtr_rekeyed || sc->vtdtr_session_stop;
	mtx_unlock(&sc->vtdtr_ctrlmtx);
	if (sc->vtdtr_ready == 0 && !rekey_pending) {
		retval = vtdtr_notify_ready(sc);
		if (retval != 0) {
			device_printf(sc->vtdtr_dev,
			    "cannot queue READY (%d); transport stopped\n", retval);
			vtdtr_stop(sc);
		}
	}
	mtx_unlock(&sc->vtdtr_mtx);

}

/*
 * Interrupt handler for the RX virtqueue. We enqueue the operation in the
 * taskqueue specific to the RX queue and enable interrupts.
 */
static void
vtdtr_rxq_vq_intr(void *xsc)
{
	struct vtdtr_softc *sc;
	struct virtio_dtrace_queue *rxq;

	sc = xsc;
	rxq = &sc->vtdtr_rxq;

	if (!atomic_load_int(&sc->vtdtr_shutdown))
		taskqueue_enqueue(rxq->vtdq_tq, &rxq->vtdq_intrtask);
}

/*
 * Interrupt handler for the TX virtqueue. The only thing we do here is enable
 * interrupts again so that we can send control messages.
 */
static void
vtdtr_txq_vq_intr(void *xsc)
{
	struct vtdtr_softc *sc = xsc;

	mtx_lock(&sc->vtdtr_ctrlmtx);
	cv_signal(&sc->vtdtr_condvar);
	mtx_unlock(&sc->vtdtr_ctrlmtx);
}

/*
 * This functions sets up all the necessary data for the correct
 * operation of a RX queue of the VirtIO driver:
 *     rxq->vtdq_sc       <- sc
 *     rxq->vtdq_id       <- id
 *     rxq->vtdq_name     <- devname-rx(1|2|3...)
 *     rxq->vtdq_sg       <- allocate or ENOMEM
 *     rxq->vtdq_intrtask <- vtdtr_rxq_tq_intr
 *     rxq->vtdq_tq       <- create taskqueue
 */
static void
vtdtr_init_rxq(struct vtdtr_softc *sc, int id)
{
	struct virtio_dtrace_queue *rxq;

	rxq = &sc->vtdtr_rxq;

	snprintf(rxq->vtdq_name, sizeof(rxq->vtdq_name), "%s-rx%d",
	    device_get_nameunit(sc->vtdtr_dev), id);
	mtx_init(&rxq->vtdq_mtx, rxq->vtdq_name, NULL, MTX_DEF);

	rxq->vtdq_sc = sc;
	rxq->vtdq_id = id;

	TASK_INIT(&rxq->vtdq_intrtask, 0, vtdtr_rxq_tq_intr, rxq);
	/* An M_WAITOK taskqueue_create(9) does not fail. */
	rxq->vtdq_tq = taskqueue_create(rxq->vtdq_name, M_WAITOK,
	    taskqueue_thread_enqueue, &rxq->vtdq_tq);
}

/*
* This functions sets up all the necessary data for the correct
* operation of a TX queue of the VirtIO driver:
*     txq->vtdq_sc       <- sc
*     txq->vtdq_id       <- id
*     txq->vtdq_name     <- devname-tx(1|2|3...)
*
* In the TX queue, we do not need a taskqueue as we are not required to handle
* complex events upon being interrupted by it.
*/
static void
vtdtr_init_txq(struct vtdtr_softc *sc, int id)
{
	struct virtio_dtrace_queue *txq;

	txq = &sc->vtdtr_txq;

	snprintf(txq->vtdq_name, sizeof(txq->vtdq_name), "%s-tx%d",
	    device_get_nameunit(sc->vtdtr_dev), id);
	mtx_init(&txq->vtdq_mtx, txq->vtdq_name, NULL, MTX_DEF);

	txq->vtdq_sc = sc;
	txq->vtdq_id = id;
}

/*
 * Destroy a given queue.
 */
static void
vtdtr_queue_destroy(struct virtio_dtrace_queue *q)
{
	if (mtx_initialized(&q->vtdq_mtx))
		mtx_destroy(&q->vtdq_mtx);
	q->vtdq_sc = NULL;
	if (q->vtdq_tq != NULL)
		taskqueue_free(q->vtdq_tq);
}

/*
 * Fill the virtqueue descriptor with a given control message. This is a wrapper
 * around vtdtr_queue_enqueue_ctrl() with read-only data
 */
static int
vtdtr_fill_desc(struct virtio_dtrace_queue *q,
    struct virtio_dtrace_control *ctrl)
{
	struct vtdtr_softc *sc = q->vtdq_sc;
	struct vtdtr_ctrl_entry *entry;

	entry = malloc(sizeof(*entry), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (entry == NULL)
		return (ENOMEM);
	entry->ctrl = malloc(sizeof(*ctrl), M_DEVBUF, M_NOWAIT);
	if (entry->ctrl == NULL) {
		free(entry, M_DEVBUF);
		return (ENOMEM);
	}
	memcpy(entry->ctrl, ctrl, sizeof(*ctrl));
	mtx_lock(&sc->vtdtr_ctrlmtx);
	if (sc->vtdtr_session_stop || (sc->vtdtr_rekeyed &&
	    ctrl->vd_event == VIRTIO_DTRACE_DEVICE_READY)) {
		mtx_unlock(&sc->vtdtr_ctrlmtx);
		free(entry->ctrl, M_DEVBUF);
		free(entry, M_DEVBUF);
		return (EBUSY);
	}
	if (atomic_load_int(&sc->vtdtr_shutdown) ||
	    sc->vtdtr_ctrlq->n_entries >= 4096) {
		mtx_unlock(&sc->vtdtr_ctrlmtx);
		free(entry->ctrl, M_DEVBUF);
		free(entry, M_DEVBUF);
		return (ENOBUFS);
	}
	vtdtr_cq_enqueue(sc->vtdtr_ctrlq, entry);
	cv_signal(&sc->vtdtr_condvar);
	mtx_unlock(&sc->vtdtr_ctrlmtx);
	return (0);
}

static void
vtdtr_cq_init(struct vtdtr_ctrlq *cq)
{

	STAILQ_INIT(&cq->head);
	cq->n_entries = 0;
}

static __inline void
vtdtr_cq_enqueue(struct vtdtr_ctrlq *cq,
    struct vtdtr_ctrl_entry *ctrl_entry)
{

	STAILQ_INSERT_TAIL(&cq->head, ctrl_entry, entries);
	cq->n_entries++;
}

static __inline int
vtdtr_cq_empty(struct vtdtr_ctrlq *cq)
{

	return (STAILQ_EMPTY(&cq->head));
}

static struct vtdtr_ctrl_entry *
vtdtr_cq_dequeue(struct vtdtr_ctrlq *cq)
{
	struct vtdtr_ctrl_entry *ctrl_entry;
	ctrl_entry = STAILQ_FIRST(&cq->head);
	if (ctrl_entry != NULL) {
		STAILQ_REMOVE_HEAD(&cq->head, entries);
		cq->n_entries--;
	}

	return (ctrl_entry);
}

static void
vtdtr_notify(struct virtio_dtrace_queue *q)
{
	struct virtqueue *vq;

	VTDTR_QUEUE_LOCK(q);
	vq = q->vtdq_vq;
	virtqueue_notify(vq);
	VTDTR_QUEUE_UNLOCK(q);
}



/*
 * This is the communicator thread. It is responsible for spinning until we shut
 * down and sending messages to the emulated PCI device on the host.
 */
/* ctrlmtx is held. Ring-owned old controls must be reclaimed before the
 * identity changes. Allocation or ring pressure leaves the commit pending. */
static void
vtdtr_activate_fresh(struct vtdtr_softc *sc)
{
	struct virtio_dtrace_queue *txq = &sc->vtdtr_txq;
	struct virtio_dtrace_control *ctrl;
	bool first;

	if (!sc->vtdtr_fresh_commit_pending)
		return;
	VTDTR_QUEUE_LOCK(txq);
	if (!virtqueue_empty(txq->vtdq_vq)) {
		VTDTR_QUEUE_UNLOCK(txq);
		return;
	}
	VTDTR_QUEUE_UNLOCK(txq);
	ctrl = malloc(sizeof(*ctrl), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (ctrl == NULL)
		return;
	ctrl->vd_event = VIRTIO_DTRACE_SESSION_ACTIVE;
	ctrl->wire.uctrl.session_prepare.stop_token = sc->vtdtr_cleanup_delivery_id;
	ctrl->wire.uctrl.session_prepare.old_id = sc->vtdtr_fresh_identity.old_vmid;
	ctrl->wire.uctrl.session_prepare.old_epoch = sc->vtdtr_fresh_identity.old_epoch;
	ctrl->wire.uctrl.session_prepare.new_id = sc->vtdtr_fresh_identity.vmid;
	ctrl->wire.uctrl.session_prepare.new_epoch = sc->vtdtr_fresh_identity.epoch;
	first = sc->vtdtr_fresh_identity.flags == DTT_IDENTITY_FRESH_READY;
	if (first) {
		mbufid_origin_epoch_set(sc->vtdtr_fresh_identity.epoch);
		dtrace_node_id = sc->vtdtr_fresh_identity.vmid;
		smp_rendezvous_cpus(all_cpus, smp_no_rendezvous_barrier,
		    vtdtr_sync_fn, smp_no_rendezvous_barrier, NULL);
	}
	VTDTR_QUEUE_LOCK(txq);
	if (vtdtr_queue_enqueue_ctrl(txq, ctrl, 1, 0) != 0) {
		VTDTR_QUEUE_UNLOCK(txq);
		free(ctrl, M_DEVBUF);
		return;
	}
	if (first) {
		sc->vtdtr_node_id = sc->vtdtr_fresh_identity.vmid;
		sc->vtdtr_node_epoch = sc->vtdtr_fresh_identity.epoch;
		sc->vtdtr_fresh_identity.flags = DTT_IDENTITY_FRESH_ACTIVE;
		sc->vtdtr_cleanup_pending = sc->vtdtr_cleanup_applied = false;
		sc->vtdtr_session_stop = sc->vtdtr_session_stop_queued = false;
		sc->vtdtr_cleanup_last_accepted_id = 0;
		sc->vtdtr_ready = 0;
		atomic_store_int(&sc->vtdtr_host_ready, 0);
	}
	sc->vtdtr_fresh_commit_pending = false;
	virtqueue_notify(txq->vtdq_vq);
	VTDTR_QUEUE_UNLOCK(txq);
}

static void
vtdtr_run(void *xsc)
{
	struct vtdtr_softc *sc = xsc;
	struct virtio_dtrace_queue *txq = &sc->vtdtr_txq;
	struct virtqueue *vq = txq->vtdq_vq;
	struct vtdtr_ctrl_entry *entry;
	struct virtio_dtrace_control *ctrl;
	uint32_t len;
	int error, sent, ready;

	mtx_lock(&sc->vtdtr_ctrlmtx);
	while (!atomic_load_int(&sc->vtdtr_shutdown)) {
		/* Allocation pressure or a read copyout must not lose the stop. */
		vtdtr_session_stop_notify(sc);
		VTDTR_QUEUE_LOCK(txq);
		while ((ctrl = virtqueue_dequeue(vq, &len)) != NULL)
			free(ctrl, M_DEVBUF);
		VTDTR_QUEUE_UNLOCK(txq);
		vtdtr_activate_fresh(sc);
		VTDTR_QUEUE_LOCK(txq);
		sent = 0;
		ready = 1;
		while (!sc->vtdtr_rekeyed && !sc->vtdtr_session_stop &&
		    !sc->vtdtr_fresh_commit_pending &&
		    atomic_load_int(&sc->vtdtr_host_ready) &&
		    !virtqueue_full(vq) && !vtdtr_cq_empty(sc->vtdtr_ctrlq)) {
			entry = STAILQ_FIRST(&sc->vtdtr_ctrlq->head);
			error = vtdtr_queue_enqueue_ctrl(txq, entry->ctrl, 1, 0);
			if (error != 0)
				break;
			(void)vtdtr_cq_dequeue(sc->vtdtr_ctrlq);
			if (entry->ctrl->vd_event != VIRTIO_DTRACE_DEVICE_READY)
				ready = 0;
			free(entry, M_DEVBUF);
			sent++;
		}
		/* Keep the proof in the driver across daemon re-exec. The host
		 * journal is idempotent; repeat until its exact receipt arrives. */
		VTDTR_STATE_ASSERT(sc);
		if (sc->vtdtr_cleanup_pending &&
		    !sc->vtdtr_fresh_commit_pending &&
		    sc->vtdtr_cleanup_applied &&
		    atomic_load_int(&sc->vtdtr_host_ready) &&
		    !virtqueue_full(vq)) {
			ctrl = malloc(sizeof(*ctrl), M_DEVBUF, M_NOWAIT | M_ZERO);
			if (ctrl != NULL) {
				ctrl->vd_event = sc->vtdtr_session_stop ?
				    VIRTIO_DTRACE_SESSION_STOPPED :
				    VIRTIO_DTRACE_CLEANUP_APPLIED;
				ctrl->vd_cleanup_vmid = sc->vtdtr_cleanup_vmid;
				ctrl->vd_cleanup_epoch = sc->vtdtr_cleanup_epoch;
				ctrl->vd_cleanup_delivery_id =
				    sc->vtdtr_cleanup_delivery_id;
				if (sc->vtdtr_fresh_identity.flags ==
				    DTT_IDENTITY_FRESH_READY) {
					/* Replace the stop proof only after local setup.
					 * Both identities and the stop token bind readiness. */
					memset(ctrl, 0, sizeof(*ctrl));
					ctrl->vd_event = VIRTIO_DTRACE_SESSION_READY;
					ctrl->wire.uctrl.session_prepare.stop_token =
					    sc->vtdtr_cleanup_delivery_id;
					ctrl->wire.uctrl.session_prepare.old_id =
					    sc->vtdtr_fresh_identity.old_vmid;
					ctrl->wire.uctrl.session_prepare.old_epoch =
					    sc->vtdtr_fresh_identity.old_epoch;
					ctrl->wire.uctrl.session_prepare.new_id =
					    sc->vtdtr_fresh_identity.vmid;
					ctrl->wire.uctrl.session_prepare.new_epoch =
					    sc->vtdtr_fresh_identity.epoch;
				}
				if (vtdtr_queue_enqueue_ctrl(txq, ctrl, 1, 0) == 0) {
					sent++;
					ready = 0;
				} else
					free(ctrl, M_DEVBUF);
			}
		}
		if (sent != 0) {
			if (!virtqueue_full(vq)) {
				ctrl = malloc(sizeof(*ctrl), M_DEVBUF, M_NOWAIT);
				if (ctrl != NULL) {
					*ctrl = eof_ctrl;
					if (vtdtr_queue_enqueue_ctrl(txq, ctrl, 1, 0) != 0)
						free(ctrl, M_DEVBUF);
				}
			}
			atomic_store_int(&sc->vtdtr_host_ready, ready);
			virtqueue_notify(vq);
		}
		(void)virtqueue_enable_intr(vq);
		VTDTR_QUEUE_UNLOCK(txq);
		/* Timed recheck also recovers an interrupt coalesced at enable. */
		cv_timedwait(&sc->vtdtr_condvar, &sc->vtdtr_ctrlmtx, hz);
	}
	mtx_unlock(&sc->vtdtr_ctrlmtx);
	sema_post(&sc->vtdtr_exit);
	kthread_exit();
}

static struct virtio_dtrace_control *
ctrl_from_dttentry(dtt_entry_t *e)
{
	struct virtio_dtrace_control *ctrl;
	const uint8_t zero_id[16] = { 0 };

	if (e->event_kind == DTT_ELF &&
	    (!vtdtr_elf_valid(e->u.elf.len, e->u.elf.totallen,
	    e->u.elf.hasmore) ||
	    e->u.elf.delivery_id == 0 ||
	    e->u.elf.vmid == 0 ||
	    e->u.elf.vmid >= HYPERTRACE_MAX_VMS ||
	    e->u.elf.epoch == 0 ||
	    memcmp(e->u.elf.program_id, zero_id, 16) == 0 ||
	    memcmp(e->u.elf.source_id, zero_id, 16) == 0))
		return (NULL);
	if ((e->event_kind == DTT_INSTALLED ||
	    e->event_kind == DTT_UNINSTALLED ||
	    e->event_kind == DTT_STATUS ||
	    e->event_kind == DTT_INGRESS_STATUS) &&
	    (e->u.installed.delivery_id == 0 ||
	    (e->event_kind == DTT_INGRESS_STATUS ?
	    (e->u.installed.vmid != 0 || e->u.installed.epoch != 0) :
	    (e->u.installed.vmid == 0 ||
	    e->u.installed.vmid >= HYPERTRACE_MAX_VMS ||
	    e->u.installed.epoch == 0)) ||
	    memcmp(e->u.installed.program_id, zero_id, 16) == 0 ||
	    memcmp(e->u.installed.source_id, zero_id, 16) == 0 ||
	    e->u.installed.phase != 0 || e->u.installed.revoked != 0 ||
	    e->u.installed.replay != 0 ||
	    memcmp(e->u.installed.digest, (const uint8_t[32]){0}, 32) != 0 ||
	    (e->event_kind == DTT_STATUS ||
	    e->event_kind == DTT_INGRESS_STATUS ?
	    e->u.installed.query_id == 0 :
	    e->u.installed.query_id != 0)))
		return (NULL);
	if (e->event_kind == DTT_VM_IDENTITY_QUERY &&
	    (e->u.installed.query_id == 0 ||
	    e->u.installed.delivery_id != 0 ||
	    e->u.installed.vmid != 0 || e->u.installed.epoch != 0 ||
	    memcmp(e->u.installed.program_id, zero_id, 16) != 0 ||
	    memcmp(e->u.installed.source_id, zero_id, 16) != 0 ||
	    e->u.installed.phase != 0 || e->u.installed.revoked != 0 ||
	    e->u.installed.replay != 0 ||
	    memcmp(e->u.installed.digest,
	    (const uint8_t[32]){0}, 32) != 0))
		return (NULL);
	if (e->event_kind == DTT_KILL_APPLIED &&
	    (e->u.kill.pid <= 1 || e->u.kill.vmid == 0 ||
	    e->u.kill.vmid >= HYPERTRACE_MAX_VMS ||
	    e->u.kill.epoch == 0 ||
	    memcmp(e->u.kill.source_id, zero_id, 16) == 0))
		return (NULL);
	if ((e->event_kind == DTT_CLEANUP_APPLIED ||
	    e->event_kind == DTT_SESSION_STOPPED) &&
	    (e->u.cleanup.delivery_id == 0 || e->u.cleanup.vmid == 0 ||
	    e->u.cleanup.vmid >= HYPERTRACE_MAX_VMS ||
	    e->u.cleanup.epoch == 0))
		return (NULL);
	if ((e->event_kind == DTT_REKEY_DELIVERY_QUERY ||
	    e->event_kind == DTT_REKEY_INGRESS_QUERY ||
	    e->event_kind == DTT_REKEY_KILL_QUERY) &&
	    (e->u.installed.delivery_id == 0 ||
	    e->u.installed.vmid == 0 ||
	    e->u.installed.vmid >= HYPERTRACE_MAX_VMS ||
	    e->u.installed.epoch == 0 ||
	    e->u.installed.query_id == 0 ||
	    e->u.installed.phase != 0 ||
	    e->u.installed.revoked != 0 ||
	    e->u.installed.replay != 0 ||
	    memcmp(e->u.installed.source_id, zero_id, 16) == 0 ||
	    (e->event_kind == DTT_REKEY_KILL_QUERY ?
	    (e->u.installed.delivery_id <= 1 ||
	    e->u.installed.delivery_id > INT32_MAX ||
	    memcmp(e->u.installed.program_id, zero_id, 16) != 0 ||
	    memcmp(e->u.installed.digest,
	    (const uint8_t[32]){0}, 32) != 0) :
	    (memcmp(e->u.installed.program_id, zero_id, 16) == 0 ||
	    memcmp(e->u.installed.digest,
	    (const uint8_t[32]){0}, 32) == 0))))
		return (NULL);

	ctrl = malloc(
	    sizeof(struct virtio_dtrace_control), M_DEVBUF, M_WAITOK | M_ZERO);

	switch (e->event_kind) {
	case DTT_ELF:
		ctrl->vd_event = VIRTIO_DTRACE_ELF;
		ctrl->vd_identifier = e->u.elf.identifier;
		ctrl->vd_delivery_id = e->u.elf.delivery_id;
		ctrl->vd_vmid = e->u.elf.vmid;
		ctrl->vd_epoch = e->u.elf.epoch;
		memcpy(ctrl->vd_program_id, e->u.elf.program_id, 16);
		memcpy(ctrl->vd_elf_source_id, e->u.elf.source_id, 16);
		ctrl->vd_elflen = e->u.elf.len;
		ctrl->vd_elfhasmore = e->u.elf.hasmore;
		ctrl->vd_totalelflen = e->u.elf.totallen;
		memcpy(ctrl->vd_elf, e->u.elf.data, e->u.elf.len);
		break;
	case DTT_INSTALLED:
	case DTT_UNINSTALLED:
	case DTT_STATUS:
	case DTT_INGRESS_STATUS:
		ctrl->vd_event = e->event_kind == DTT_INSTALLED ?
		    VIRTIO_DTRACE_INSTALLED :
		    e->event_kind == DTT_UNINSTALLED ?
		    VIRTIO_DTRACE_UNINSTALLED :
		    e->event_kind == DTT_STATUS ? VIRTIO_DTRACE_STATUS :
		    VIRTIO_DTRACE_INGRESS_STATUS;
		ctrl->vd_installed_delivery_id = e->u.installed.delivery_id;
		ctrl->vd_installed_vmid = e->u.installed.vmid;
		ctrl->vd_installed_epoch = e->u.installed.epoch;
		memcpy(ctrl->vd_installed_program_id,
		    e->u.installed.program_id, 16);
		memcpy(ctrl->vd_installed_source_id,
		    e->u.installed.source_id, 16);
		ctrl->vd_installed_query_id = e->u.installed.query_id;
		memcpy(ctrl->vd_installed_digest,
		    e->u.installed.digest, 32);
		break;
	case DTT_VM_IDENTITY_QUERY:
		ctrl->vd_event = VIRTIO_DTRACE_NODE_ID;
		ctrl->vd_node_query_id = e->u.installed.query_id;
		break;
	case DTT_REKEY_DELIVERY_QUERY:
	case DTT_REKEY_INGRESS_QUERY:
	case DTT_REKEY_KILL_QUERY:
		ctrl->vd_event = e->event_kind == DTT_REKEY_DELIVERY_QUERY ?
		    VIRTIO_DTRACE_REKEY_DELIVERY_QUERY :
		    e->event_kind == DTT_REKEY_INGRESS_QUERY ?
		    VIRTIO_DTRACE_REKEY_INGRESS_QUERY :
		    VIRTIO_DTRACE_REKEY_KILL_QUERY;
		ctrl->vd_installed_delivery_id = e->u.installed.delivery_id;
		ctrl->vd_installed_vmid = e->u.installed.vmid;
		ctrl->vd_installed_epoch = e->u.installed.epoch;
		ctrl->vd_installed_query_id = e->u.installed.query_id;
		memcpy(ctrl->vd_installed_program_id,
		    e->u.installed.program_id, 16);
		memcpy(ctrl->vd_installed_source_id,
		    e->u.installed.source_id, 16);
		memcpy(ctrl->vd_installed_digest,
		    e->u.installed.digest, 32);
		break;
	case DTT_KILL_APPLIED:
		ctrl->vd_event = VIRTIO_DTRACE_KILL_APPLIED;
		ctrl->vd_pid = e->u.kill.pid;
		ctrl->vd_kill_vmid = e->u.kill.vmid;
		ctrl->vd_kill_epoch = e->u.kill.epoch;
		memcpy(ctrl->vd_source_id, e->u.kill.source_id, 16);
		break;
	case DTT_CLEANUP_APPLIED:
	case DTT_SESSION_STOPPED:
		ctrl->vd_event = e->event_kind == DTT_SESSION_STOPPED ?
		    VIRTIO_DTRACE_SESSION_STOPPED : VIRTIO_DTRACE_CLEANUP_APPLIED;
		ctrl->vd_cleanup_vmid = e->u.cleanup.vmid;
		ctrl->vd_cleanup_epoch = e->u.cleanup.epoch;
		ctrl->vd_cleanup_delivery_id = e->u.cleanup.delivery_id;
		break;
	case DTT_KILL:
		/*
		 * We have no business sending this to the host...
		 */
		free(ctrl, M_DEVBUF);
		ctrl = NULL;
		break;
	default:
		free(ctrl, M_DEVBUF);
		ctrl = NULL;
		break;
	}

	return (ctrl);
}

static int
vtdtr_identity(void *arg, struct dtt_vm_identity *identity)
{
	struct vtdtr_softc *sc = arg;
	int error = 0;

	memset(identity, 0, sizeof(*identity));
	mtx_lock(&sc->vtdtr_ctrlmtx);
	VTDTR_STATE_ASSERT(sc);
	if (atomic_load_int(&sc->vtdtr_shutdown))
		error = ENXIO;
	else if (sc->vtdtr_node_id == 0)
		error = EAGAIN;
	else if (sc->vtdtr_fresh_identity.flags != 0)
		*identity = sc->vtdtr_fresh_identity;
	else {
		identity->vmid = sc->vtdtr_node_id;
		identity->epoch = sc->vtdtr_node_epoch;
		if (sc->vtdtr_rekeyed) {
			identity->old_vmid = sc->vtdtr_rekey_old_id;
			identity->old_epoch = sc->vtdtr_rekey_old_epoch;
			identity->flags = sc->vtdtr_rekey_local_committed ?
			    DTT_IDENTITY_REKEY_LOCAL_COMMITTED :
			    DTT_IDENTITY_REKEY_PENDING;
		}
	}
	mtx_unlock(&sc->vtdtr_ctrlmtx);
	return (error);
}

static int
vtdtr_cleanup_query(void *arg, struct dtt_cleanup_state *state)
{
	struct vtdtr_softc *sc = arg;
	int error = 0;

	memset(state, 0, sizeof(*state));
	mtx_lock(&sc->vtdtr_ctrlmtx);
	VTDTR_STATE_ASSERT(sc);
	if (atomic_load_int(&sc->vtdtr_shutdown))
		error = ENXIO;
	else if (sc->vtdtr_node_id == 0)
		error = EAGAIN;
	else if (sc->vtdtr_cleanup_pending) {
		state->delivery_id = sc->vtdtr_cleanup_delivery_id;
		state->epoch = sc->vtdtr_cleanup_epoch;
		state->vmid = sc->vtdtr_cleanup_vmid;
		state->flags = DTT_CLEANUP_STATE_PENDING |
		    (sc->vtdtr_cleanup_applied ? DTT_CLEANUP_STATE_APPLIED : 0) |
		    (sc->vtdtr_session_stop ? DTT_CLEANUP_STATE_SESSION_STOP : 0);
	}
	mtx_unlock(&sc->vtdtr_ctrlmtx);
	return (error);
}

static int
vtdtr_rekey_commit(void *arg, const struct dtt_vm_identity *identity)
{
	struct vtdtr_softc *sc = arg;
	struct virtio_dtrace_control *commit;
	struct virtio_dtrace_control *done;
	struct virtio_dtrace_queue *txq = &sc->vtdtr_txq;
	uint32_t length;
	int error = 0;

	/* dttransport passes the ioctl's copied-in argument. */
	KASSERT(identity != NULL, ("%s: no identity", __func__));
	if (identity->flags != 0)
		return (EINVAL);
	mtx_lock(&sc->vtdtr_ctrlmtx);
	if (atomic_load_int(&sc->vtdtr_shutdown))
		error = ENXIO;
	else if (!sc->vtdtr_rekeyed ||
	    identity->old_vmid != sc->vtdtr_rekey_old_id ||
	    identity->old_epoch != sc->vtdtr_rekey_old_epoch ||
	    identity->vmid != sc->vtdtr_node_id ||
	    identity->epoch != sc->vtdtr_node_epoch)
		error = ESTALE;
	else if (sc->vtdtr_rekey_query_pending)
		error = EBUSY;
	else if (sc->vtdtr_rekey_local_committed)
		/* The first commit remains owned by the TX ring. */
		error = 0;
	else {
		/* Send through the TX ring directly: its ordinary worker is fenced
		 * until the host confirms this exact transition. A retry after a
		 * lost ioctl reply observes the already queued commit above. */
		VTDTR_QUEUE_LOCK(txq);
		while ((done = virtqueue_dequeue(txq->vtdq_vq,
		    &length)) != NULL)
			free(done, M_DEVBUF);
		if (!virtqueue_empty(txq->vtdq_vq)) {
			error = EBUSY;
			VTDTR_QUEUE_UNLOCK(txq);
		} else {
			commit = malloc(sizeof(*commit), M_DEVBUF,
			    M_NOWAIT | M_ZERO);
			if (commit == NULL) {
				error = ENOMEM;
				VTDTR_QUEUE_UNLOCK(txq);
			} else {
			commit->vd_event = VIRTIO_DTRACE_REKEY_COMMIT;
			commit->vd_rekey_old_id = identity->old_vmid;
			commit->vd_rekey_old_epoch = identity->old_epoch;
			commit->vd_rekey_new_id = identity->vmid;
			commit->vd_rekey_new_epoch = identity->epoch;
			error = vtdtr_queue_enqueue_ctrl(txq, commit, 1, 0);
			if (error == 0)
				virtqueue_notify(txq->vtdq_vq);
			VTDTR_QUEUE_UNLOCK(txq);
			if (error != 0)
				free(commit, M_DEVBUF);
			else
				sc->vtdtr_rekey_local_committed = true;
			}
		}
	}
	mtx_unlock(&sc->vtdtr_ctrlmtx);
	return (error);
}

static int
vtdtr_rekey_query_send(struct vtdtr_softc *sc,
    struct virtio_dtrace_control *ctrl)
{
	struct virtio_dtrace_queue *txq = &sc->vtdtr_txq;
	int error;

	mtx_lock(&sc->vtdtr_ctrlmtx);
	if (atomic_load_int(&sc->vtdtr_shutdown))
		error = ENXIO;
	else if ((sc->vtdtr_features & VTDTR_WIRE_F_REKEY_RECEIPT_V1) == 0)
		error = ENOTSUP;
	else if (!sc->vtdtr_rekeyed || sc->vtdtr_rekey_local_committed ||
	    ctrl->vd_installed_vmid != sc->vtdtr_rekey_old_id ||
	    ctrl->vd_installed_epoch != sc->vtdtr_rekey_old_epoch)
		error = ESTALE;
	else if (sc->vtdtr_rekey_query_pending)
		error = EBUSY;
	else {
		/* Never displace a queued control. The ordinary worker still
		 * reaps completed descriptors while rekey keeps it from sending. */
		VTDTR_QUEUE_LOCK(txq);
		if (!virtqueue_empty(txq->vtdq_vq))
			error = EBUSY;
		else {
			error = vtdtr_queue_enqueue_ctrl(txq, ctrl, 1, 0);
			if (error == 0) {
				sc->vtdtr_rekey_query_pending = true;
				sc->vtdtr_rekey_query_event = ctrl->vd_event;
				sc->vtdtr_rekey_query_delivery_id =
				    ctrl->vd_installed_delivery_id;
				sc->vtdtr_rekey_query_id =
				    ctrl->vd_installed_query_id;
				memcpy(sc->vtdtr_rekey_query_program_id,
				    ctrl->vd_installed_program_id, 16);
				memcpy(sc->vtdtr_rekey_query_source_id,
				    ctrl->vd_installed_source_id, 16);
				memcpy(sc->vtdtr_rekey_query_digest,
				    ctrl->vd_installed_digest, 32);
				virtqueue_notify(txq->vtdq_vq);
			}
		}
		VTDTR_QUEUE_UNLOCK(txq);
	}
	mtx_unlock(&sc->vtdtr_ctrlmtx);
	if (error != 0)
		free(ctrl, M_DEVBUF);
	return (error);
}

static int
vtdtr_enqueue(void *arg, dtt_entry_t *e)
{
	struct vtdtr_softc *sc;
	struct vtdtr_ctrl_entry *ctrl_entry;
	struct virtio_dtrace_control *ctrl;

	sc = arg;

	/* dttransport refuses a NULL registration argument and passes the
	 * address of its own entry. */
	KASSERT(sc != NULL && e != NULL, ("%s: NULL softc or entry", __func__));
	if (e->event_kind == DTT_SESSION_READY) {
		mtx_lock(&sc->vtdtr_ctrlmtx);
		VTDTR_STATE_ASSERT(sc);
		if (atomic_load_int(&sc->vtdtr_shutdown) ||
		    !sc->vtdtr_session_stop || !sc->vtdtr_cleanup_applied ||
		    (sc->vtdtr_fresh_identity.flags != DTT_IDENTITY_FRESH_PENDING &&
		    sc->vtdtr_fresh_identity.flags != DTT_IDENTITY_FRESH_READY) ||
		    e->u.cleanup.vmid != sc->vtdtr_fresh_identity.vmid ||
		    e->u.cleanup.epoch != sc->vtdtr_fresh_identity.epoch ||
		    e->u.cleanup.delivery_id != sc->vtdtr_cleanup_delivery_id) {
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			return (ESTALE);
		}
		sc->vtdtr_fresh_identity.flags = DTT_IDENTITY_FRESH_READY;
		cv_signal(&sc->vtdtr_condvar);
		mtx_unlock(&sc->vtdtr_ctrlmtx);
		return (0);
	}

	ctrl = ctrl_from_dttentry(e);
	if (ctrl == NULL)
		return (EINVAL);
	if (e->event_kind == DTT_REKEY_DELIVERY_QUERY ||
	    e->event_kind == DTT_REKEY_INGRESS_QUERY ||
	    e->event_kind == DTT_REKEY_KILL_QUERY)
		return (vtdtr_rekey_query_send(sc, ctrl));
	ctrl_entry = malloc(sizeof(struct vtdtr_ctrl_entry),
	    M_DEVBUF, M_WAITOK | M_ZERO);
	ctrl_entry->ctrl = ctrl;

	mtx_lock(&sc->vtdtr_ctrlmtx);
	if (e->event_kind == DTT_CLEANUP_APPLIED ||
	    e->event_kind == DTT_SESSION_STOPPED) {
		if (atomic_load_int(&sc->vtdtr_shutdown) ||
		    sc->vtdtr_session_stop != (e->event_kind == DTT_SESSION_STOPPED) ||
		    sc->vtdtr_rekeyed || !sc->vtdtr_cleanup_pending ||
		    e->u.cleanup.vmid != sc->vtdtr_node_id ||
		    e->u.cleanup.epoch != sc->vtdtr_node_epoch ||
		    e->u.cleanup.delivery_id !=
		    sc->vtdtr_cleanup_delivery_id) {
			mtx_unlock(&sc->vtdtr_ctrlmtx);
			free(ctrl, M_DEVBUF);
			free(ctrl_entry, M_DEVBUF);
			return (ESTALE);
		}
		/* No queued old-session control may survive a successful stop.
		 * Ring-owned descriptors remain owned by the ring until reclaimed. */
		if (sc->vtdtr_session_stop) {
			struct vtdtr_ctrl_entry *old;
			while ((old = vtdtr_cq_dequeue(sc->vtdtr_ctrlq)) != NULL) {
				free(old->ctrl, M_DEVBUF);
				free(old, M_DEVBUF);
			}
		}
		sc->vtdtr_cleanup_applied = true;
		cv_signal(&sc->vtdtr_condvar);
		mtx_unlock(&sc->vtdtr_ctrlmtx);
		free(ctrl, M_DEVBUF);
		free(ctrl_entry, M_DEVBUF);
		return (0);
	}
	if (sc->vtdtr_session_stop) {
		mtx_unlock(&sc->vtdtr_ctrlmtx);
		free(ctrl, M_DEVBUF);
		free(ctrl_entry, M_DEVBUF);
		return (EBUSY);
	}
	/* Ingress status has no VM identity on the wire. Do not let an old
	 * journal query cross a rekey until guest journal migration is defined. */
	if ((e->event_kind == DTT_INGRESS_STATUS && sc->vtdtr_rekeyed) ||
	    (e->event_kind == DTT_KILL_APPLIED &&
	    (e->u.kill.vmid != sc->vtdtr_node_id ||
	    e->u.kill.epoch != sc->vtdtr_node_epoch)) ||
	    (e->event_kind == DTT_ELF &&
	    (e->u.elf.vmid != sc->vtdtr_node_id ||
	    e->u.elf.epoch != sc->vtdtr_node_epoch)) ||
	    ((e->event_kind == DTT_INSTALLED ||
	    e->event_kind == DTT_UNINSTALLED ||
	    e->event_kind == DTT_STATUS) &&
	    (e->u.installed.vmid != sc->vtdtr_node_id ||
	    e->u.installed.epoch != sc->vtdtr_node_epoch))) {
		mtx_unlock(&sc->vtdtr_ctrlmtx);
		free(ctrl, M_DEVBUF);
		free(ctrl_entry, M_DEVBUF);
		return (ESTALE);
	}
	if (atomic_load_int(&sc->vtdtr_shutdown) ||
	    sc->vtdtr_ctrlq->n_entries >= 4096) {
		mtx_unlock(&sc->vtdtr_ctrlmtx);
		free(ctrl, M_DEVBUF);
		free(ctrl_entry, M_DEVBUF);
		return (ENOBUFS);
	}
	vtdtr_cq_enqueue(sc->vtdtr_ctrlq, ctrl_entry);
	cv_signal(&sc->vtdtr_condvar);
	mtx_unlock(&sc->vtdtr_ctrlmtx);

	return (0);
}
