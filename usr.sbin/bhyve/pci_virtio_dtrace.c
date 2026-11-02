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
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/hypertrace.h>
#include <sys/hypertrace_wire.h>

#include <stdbool.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#include <sys/types.h>
#include <sys/dtrace_bsd.h>
#include <sys/endian.h>
#include <sys/event.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#include <sys/uuid.h>

#include <machine/vmm.h>

#include <assert.h>
#include <dtraced.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <vmmapi.h>

#include "bhyverun.h"
#include "hypertrace.h"
#include "hypertrace_elf.h"
#include "hypertrace_session.h"

#include "pci_emul.h"
#include "virtio.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif
#include <dev/virtio/dtrace/virtio_dtrace_wire.h>

#define MAX_VMNAME	((size_t)100)

#define	VTDTR_RINGSZ	4096
#define	VTDTR_MAXQ	2
#define VTDTR_MAX_IOV 16

/* The restored guest daemon must query exact old-incarnation receipts
 * before it can commit NODE_REKEY and release queued controls. */
#define VTDTR_RESTORE_REQUIRED_FEATURES \
	(VTDTR_WIRE_F_SESSION_REQUIRED | VTDTR_WIRE_F_CONTINUITY)

#define	VTDTR_DEVICE_READY		VTDTR_WIRE_EVENT_READY /* Device is ready */
#define	VTDTR_DEVICE_REGISTER		VTDTR_WIRE_EVENT_REGISTER /* UNUSED */
#define	VTDTR_DEVICE_UNREGISTER		VTDTR_WIRE_EVENT_UNREGISTER /* UNUSED */
#define	VTDTR_DEVICE_DESTROY		VTDTR_WIRE_EVENT_DESTROY /* UNUSED */
#define	VTDTR_DEVICE_PROBE_CREATE	VTDTR_WIRE_EVENT_PROBE_CREATE /* UNUSED */
#define	VTDTR_DEVICE_PROBE_INSTALL	VTDTR_WIRE_EVENT_PROBE_INSTALL /* Install a given probe */
#define	VTDTR_DEVICE_PROBE_UNINSTALL	VTDTR_WIRE_EVENT_RESERVED_06 /* Unused legacy name */
#define	VTDTR_DEVICE_EOF		VTDTR_WIRE_EVENT_EOF /* End of file */
#define	VTDTR_DEVICE_GO			VTDTR_WIRE_EVENT_GO /* Start the tracing */
#define	VTDTR_DEVICE_ELF		VTDTR_WIRE_EVENT_ELF /* Send an ELF file */
#define	VTDTR_DEVICE_STOP		VTDTR_WIRE_EVENT_STOP /* Stop tracing */
#define	VTDTR_DEVICE_KILL		VTDTR_WIRE_EVENT_KILL /* Kill a DTrace process */
#define	VTDTR_DEVICE_CLEANUP_DTRACED	VTDTR_WIRE_EVENT_CLEANUP_DTRACED /* Clean up dtraced state */
#define	VTDTR_DEVICE_NODE_ID		VTDTR_WIRE_EVENT_NODE_ID /* Negotiate DTrace node ID */
#define VTDTR_DEVICE_SESSION_STOP VTDTR_WIRE_EVENT_SESSION_STOP
#define VTDTR_DEVICE_SESSION_STOPPED VTDTR_WIRE_EVENT_SESSION_STOPPED
#define VTDTR_DEVICE_SESSION_PREPARE VTDTR_WIRE_EVENT_SESSION_PREPARE
#define VTDTR_DEVICE_SESSION_READY VTDTR_WIRE_EVENT_SESSION_READY
#define VTDTR_DEVICE_SESSION_COMMIT VTDTR_WIRE_EVENT_SESSION_COMMIT
#define VTDTR_DEVICE_SESSION_ACTIVE VTDTR_WIRE_EVENT_SESSION_ACTIVE
#define VTDTR_DEVICE_NODE_REKEY VTDTR_WIRE_EVENT_NODE_REKEY
#define VTDTR_DEVICE_REKEY_COMMIT VTDTR_WIRE_EVENT_REKEY_COMMIT
#define VTDTR_DEVICE_REKEY_COMMITTED VTDTR_WIRE_EVENT_REKEY_COMMITTED
#define VTDTR_DEVICE_REKEY_APPLIED VTDTR_WIRE_EVENT_REKEY_APPLIED
#define VTDTR_DEVICE_REKEY_DELIVERY_QUERY VTDTR_WIRE_EVENT_REKEY_DELIVERY_QUERY
#define VTDTR_DEVICE_REKEY_INGRESS_QUERY VTDTR_WIRE_EVENT_REKEY_INGRESS_QUERY
#define VTDTR_DEVICE_REKEY_KILL_QUERY VTDTR_WIRE_EVENT_REKEY_KILL_QUERY
#define VTDTR_DEVICE_REKEY_DELIVERY_RECEIPT VTDTR_WIRE_EVENT_REKEY_DELIVERY_RECEIPT
#define VTDTR_DEVICE_REKEY_INGRESS_RECEIPT VTDTR_WIRE_EVENT_REKEY_INGRESS_RECEIPT
#define VTDTR_DEVICE_REKEY_KILL_RECEIPT VTDTR_WIRE_EVENT_REKEY_KILL_RECEIPT
#define	VTDTR_DEVICE_INSTALLED		VTDTR_WIRE_EVENT_INSTALLED /* Guest observed installation */
#define	VTDTR_DEVICE_UNINSTALLED	VTDTR_WIRE_EVENT_UNINSTALLED /* Guest tracing child exited */
#define VTDTR_DEVICE_HOST_INSTALLED VTDTR_WIRE_EVENT_HOST_INSTALLED /* Host accepted install observation */
#define VTDTR_DEVICE_HOST_UNINSTALLED VTDTR_WIRE_EVENT_HOST_UNINSTALLED /* Host accepted exit observation */
#define VTDTR_DEVICE_STATUS VTDTR_WIRE_EVENT_STATUS /* Query host delivery phase */
#define VTDTR_DEVICE_HOST_STATUS VTDTR_WIRE_EVENT_HOST_STATUS /* Durable phase or unavailable */
#define VTDTR_DEVICE_HOST_ELF VTDTR_WIRE_EVENT_HOST_ELF /* Host daemon accepted guest ELF */
#define VTDTR_DEVICE_INGRESS_STATUS VTDTR_WIRE_EVENT_INGRESS_STATUS /* Query host guest-ELF ingest */
#define VTDTR_DEVICE_HOST_INGRESS_STATUS VTDTR_WIRE_EVENT_HOST_INGRESS_STATUS /* Host ingest phase */
#define VTDTR_DEVICE_KILL_APPLIED VTDTR_WIRE_EVENT_KILL_APPLIED
#define VTDTR_DEVICE_HOST_KILL_APPLIED VTDTR_WIRE_EVENT_HOST_KILL_APPLIED
#define VTDTR_DEVICE_CLEANUP_APPLIED VTDTR_WIRE_EVENT_CLEANUP_APPLIED
#define VTDTR_DEVICE_HOST_CLEANUP_APPLIED VTDTR_WIRE_EVENT_HOST_CLEANUP_APPLIED

#define PCI_VTDTR_MAXELFLEN VTDTR_WIRE_MAXELFLEN

#define PCI_VTDTR_EVENTSLEEPTIME	5
#define PCI_VTDTR_REKEY_TIMEOUT_SEC 60
#define VTDTR_MAX_PENDING (64U * 1024U * 1024U / PCI_VTDTR_MAXELFLEN + 2)
/* Admission can add the full bounded durable KILL set after a saved queue
 * passes its source budget. These slots are for restored KILLs only; normal
 * controls remain under VTDTR_MAX_PENDING. */
#define VTDTR_MAX_RESTORE_PENDING \
	(VTDTR_MAX_PENDING + DTRACED_REPLAY_KILL_MAX)

static int pci_vtdtr_debug;
#define	DPRINTF(params) if (pci_vtdtr_debug) printf params
#define	WPRINTF(params) printf params

struct pci_vtdtr_control {
	struct vtdtr_wire_control wire;
};

#define pvc_event wire.event
#define pvc_identifier wire.uctrl.elf.identifier
#define pvc_delivery_id wire.uctrl.elf.delivery_id
#define pvc_vmid wire.uctrl.elf.vmid
#define pvc_epoch wire.uctrl.elf.epoch
#define pvc_program_id wire.uctrl.elf.program_id
#define pvc_elf_source_id wire.uctrl.elf.elf_source_id
#define pvc_elflen wire.uctrl.elf.elflen
#define pvc_elfhasmore wire.uctrl.elf.elfhasmore
#define pvc_totalelflen wire.uctrl.elf.totalelflen
#define pvc_elf wire.uctrl.elf.elf
#define pvc_pid wire.uctrl.kill.pid
#define pvc_kill_vmid wire.uctrl.kill.vmid
#define pvc_kill_epoch wire.uctrl.kill.epoch
#define pvc_source_id wire.uctrl.kill.source_id
#define pvc_installed_program_id wire.uctrl.installed.program_id
#define pvc_installed_source_id wire.uctrl.installed.source_id
#define pvc_installed_delivery_id wire.uctrl.installed.delivery_id
#define pvc_installed_vmid wire.uctrl.installed.vmid
#define pvc_installed_epoch wire.uctrl.installed.epoch
#define pvc_installed_phase wire.uctrl.installed.phase
#define pvc_installed_revoked wire.uctrl.installed.revoked
#define pvc_installed_replay wire.uctrl.installed.replay
#define pvc_installed_query_id wire.uctrl.installed.query_id
#define pvc_installed_digest wire.uctrl.installed.digest
#define pvc_node_id wire.uctrl.node_id.id
#define pvc_node_epoch wire.uctrl.node_id.epoch
#define pvc_node_query_id wire.uctrl.node_id.query_id
#define pvc_rekey_old_id wire.uctrl.node_rekey.old_id
#define pvc_rekey_old_epoch wire.uctrl.node_rekey.old_epoch
#define pvc_rekey_new_id wire.uctrl.node_rekey.new_id
#define pvc_rekey_new_epoch wire.uctrl.node_rekey.new_epoch
#define pvc_cleanup_vmid wire.uctrl.cleanup.vmid
#define pvc_cleanup_epoch wire.uctrl.cleanup.epoch
#define pvc_cleanup_delivery_id wire.uctrl.cleanup.delivery_id

_Static_assert(sizeof(struct pci_vtdtr_control) <= 4096,
    "pci_vtdtr_control must fit in one page");
_Static_assert(sizeof(struct pci_vtdtr_control) ==
    sizeof(struct vtdtr_wire_control), "host control wrapper changed wire size");

struct pci_vtdtr_ctrl_entry {
	STAILQ_ENTRY(pci_vtdtr_ctrl_entry)	entries;
	struct pci_vtdtr_control		*ctrl;
	/* A restored revocation must be guest-applied before ELF replay. */
	bool					restored_kill;
	/* Transient queue provenance; never copied into a device image. */
	bool					restored_control;
	/* Prevent a late KILL from splitting an ELF whose head was sent. */
	bool					restored_elf_start;
};

struct pci_vtdtr_ctrlq {
	STAILQ_HEAD(, pci_vtdtr_ctrl_entry)	head;
	size_t count;
	size_t restored_kills;
};

struct pci_vtdtr_softc {
	struct virtio_softc	vsd_vs;
	struct vqueue_info	vsd_queues[VTDTR_MAXQ];
	struct vmctx		*vsd_vmctx;
	struct pci_vtdtr_ctrlq	*vsd_ctrlq;
	pthread_cond_t		vsd_cond;
	pthread_mutex_t		vsd_mtx;
	uint64_t		vsd_cfg;
	int			vsd_guest_ready;
	bool			vsd_session_stop_requested;
	bool			vsd_session_stop_delivered;
	bool			vsd_session_stopped;
	bool			vsd_session_collectors_stopped;
	bool			vsd_session_collectors_busy;
	bool			vsd_session_restore_pending;
	bool			vsd_session_restore_staged;
	bool			vsd_session_migration_staged;
	bool			vsd_session_migration_released;
	uint8_t			vsd_session_migration_record[HYPERTRACE_SESSION_RECORD_SIZE];
	uint8_t			vsd_session_restore_record[HYPERTRACE_SESSION_RECORD_SIZE];
	uint64_t		vsd_session_restore_cfg;
	uint16_t		vsd_session_stop_vmid;
	uint64_t		vsd_session_stop_epoch;
	uint64_t		vsd_session_stop_token;
	uint8_t			vsd_session_gate_token[16];
	struct timespec		vsd_session_stop_deadline;
	bool			vsd_fresh_requested;
	bool			vsd_fresh_prepare_delivered;
	bool			vsd_fresh_commit_queued;
	bool			vsd_fresh_commit_delivered;
	bool			vsd_fresh_active;
	bool			vsd_fresh_released;
	bool			vsd_fresh_release_busy;
	uint8_t			vsd_fresh_gate_token[16];
	uint16_t		vsd_fresh_vmid;
	uint64_t		vsd_fresh_epoch;
	struct timespec		vsd_fresh_deadline;
	/* A delivered CLEANUP needs an exact guest-applied receipt before a new
	 * source checkpoint can omit it from the saved control queue. */
	bool			vsd_cleanup_unapplied;
	uint64_t		vsd_cleanup_delivery_id;
	uint64_t		vsd_cleanup_previous_delivery_id;
	/* NODE_REKEY was delivered; ordinary READY cannot release its queue. */
	bool			vsd_rekey_wait;
	bool			vsd_rekey_ack_pending;
	bool			vsd_rekey_ack_sent;
	bool			vsd_rekey_receipt_reply_pending;
	struct pci_vtdtr_control vsd_rekey_receipt_reply;
	uint16_t		vsd_rekey_old_id, vsd_rekey_new_id;
	uint64_t		vsd_rekey_old_epoch, vsd_rekey_new_epoch;
	struct timespec		vsd_rekey_deadline;
	bool			vsd_restored_kill_wait;
	pid_t			vsd_restored_kill_pid;
	uint8_t			vsd_restored_kill_source_id[16];
	struct timespec		vsd_restored_kill_deadline;
	/* Coordinator-owned ticket for exact old-incarnation receipt queries.
	 * Never take authority from a guest descriptor. */
	bool			vsd_handoff_ticket_valid;
	uint8_t			vsd_handoff_token[16];
	uint8_t			vsd_handoff_digest[32];
	uint8_t			vsd_replay_manifest_digest[SHA256_DIGEST_LENGTH];
	uint16_t		vsd_handoff_vmid;
	uint64_t		vsd_handoff_epoch;
	bool			vsd_ticket_wait;
	struct timespec		vsd_ticket_deadline;
	bool			vsd_stopping;
	bool			vsd_suspended;
	bool			vsd_checkpoint_paused;
	bool			vsd_reader_active;
	uint64_t		vsd_generation;
	pthread_t		vsd_communicator, vsd_reader;
	int			vsd_ready;
	struct hypertrace_elf	vsd_inbound_elf;
	uint64_t		vsd_inbound_delivery_id;
	uint16_t		vsd_inbound_vmid;
	uint64_t		vsd_inbound_epoch;
	uint8_t			vsd_inbound_program_id[16];
	uint8_t			vsd_inbound_source_id[16];
#ifdef BHYVE_SNAPSHOT
	/* Read-only validator's exact device-private span. The coordinator
	 * consumes it only after the generic PCI/VirtIO parser finishes. */
	bool			vsd_capture_private;
	bool			vsd_capture_seen;
	bool			vsd_capture_complete;
	const void		*vsd_capture_start;
	size_t			vsd_capture_length;
	/* Planned while paused; published only after daemon CLAIM and binding. */
	struct pci_vtdtr_ctrlq *vsd_restore_planned;
	uint64_t		vsd_restore_cfg;
	uint16_t		vsd_restore_vmid;
	uint64_t		vsd_restore_epoch;
#endif
};

/*
 * By defn, a flexibly array member is not included in the sizeof(), so we can
 * simply compute the maximum amount of bytes we can fit in each event to not
 * overwrite the ringbuffer using it.
 */

static void pci_vtdtr_reset(void *);
static int pci_vtdtr_control_rx(struct pci_vtdtr_softc *,
    struct iovec *, int);
static void pci_vtdtr_notify_tx(void *, struct vqueue_info *);
static void pci_vtdtr_notify_rx(void *, struct vqueue_info *);
static void pci_vtdtr_cq_enqueue(struct pci_vtdtr_ctrlq *,
    struct pci_vtdtr_ctrl_entry *);
static void pci_vtdtr_cq_enqueue_front(struct pci_vtdtr_ctrlq *,
    struct pci_vtdtr_ctrl_entry *);
static int pci_vtdtr_cq_empty(struct pci_vtdtr_ctrlq *);
static struct pci_vtdtr_ctrl_entry *pci_vtdtr_cq_dequeue(
    struct pci_vtdtr_ctrlq *);
static bool pci_vtdtr_insert_restore_kill(struct pci_vtdtr_ctrlq *,
    struct pci_vtdtr_ctrl_entry *);
static bool pci_vtdtr_fill_desc(struct vqueue_info *,
    struct pci_vtdtr_control *);
static void pci_vtdtr_poll(struct vqueue_info *, int);
static void pci_vtdtr_notify_ready(struct pci_vtdtr_softc *);
static void pci_vtdtr_fill_eof_desc(struct vqueue_info *);
static void * pci_vtdtr_run(void *);
static void pci_vtdtr_reset_queue(struct pci_vtdtr_softc *);
static int pci_vtdtr_init(struct pci_devinst *, nvlist_t *);
static bool pci_vtdtr_ctrl_matches_vm(const struct pci_vtdtr_control *,
    uint16_t, uint64_t);
static bool pci_vtdtr_deadline_expired(const struct timespec *);
#ifdef BHYVE_SNAPSHOT
static int pci_vtdtr_session_source_valid(struct pci_vtdtr_softc *);
static int pci_vtdtr_checkpoint_state_valid(struct pci_vtdtr_softc *);
static int pci_vtdtr_checkpoint_replayable(struct pci_vtdtr_softc *);
static void pci_vtdtr_checkpoint_queue_free(struct pci_vtdtr_ctrlq *);
static int pci_vtdtr_private_snapshot(struct pci_vtdtr_softc *,
    struct vm_snapshot_meta *);
static int pci_vtdtr_private_snapshot_restore(struct pci_vtdtr_softc *,
    struct vm_snapshot_meta *);
static int pci_vtdtr_session_private_restore(struct pci_vtdtr_softc *,
    struct vm_snapshot_meta *);
#endif
/* The forwarding protocol currently has one channel pair per VM. */
static bool vtdtr_present;
static struct pci_vtdtr_softc *vtdtr_shutdown_sc;

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* Caller owns vsd_mtx. The ticket must not outlive its VM incarnation. */
static void
pci_vtdtr_handoff_ticket_forget(struct pci_vtdtr_softc *sc)
{
	explicit_bzero(sc->vsd_handoff_token, sizeof(sc->vsd_handoff_token));
	explicit_bzero(sc->vsd_handoff_digest, sizeof(sc->vsd_handoff_digest));
	explicit_bzero(sc->vsd_replay_manifest_digest,
	    sizeof(sc->vsd_replay_manifest_digest));
	sc->vsd_handoff_vmid = 0;
	sc->vsd_handoff_epoch = 0;
	sc->vsd_handoff_ticket_valid = false;
	sc->vsd_rekey_ack_pending = false;
	sc->vsd_rekey_ack_sent = false;
	sc->vsd_rekey_old_id = sc->vsd_rekey_new_id = 0;
	sc->vsd_rekey_old_epoch = sc->vsd_rekey_new_epoch = 0;
	sc->vsd_rekey_deadline = (struct timespec){ 0 };
	sc->vsd_rekey_receipt_reply_pending = false;
	explicit_bzero(&sc->vsd_rekey_receipt_reply,
	    sizeof(sc->vsd_rekey_receipt_reply));
	sc->vsd_ticket_wait = false;
	sc->vsd_ticket_deadline = (struct timespec){ 0 };
}

static void
pci_vtdtr_stop_workers(struct pci_vtdtr_softc *sc)
{
	pthread_mutex_lock(&sc->vsd_mtx);
	sc->vsd_stopping = true;
	pci_vtdtr_handoff_ticket_forget(sc);
	pthread_cond_broadcast(&sc->vsd_cond);
	pthread_mutex_unlock(&sc->vsd_mtx);
	/* Retire the session after closing admission, before joining the reader. */
	(void)hypertrace_reset();
	pthread_join(sc->vsd_reader, NULL);
	pthread_join(sc->vsd_communicator, NULL);
#ifdef BHYVE_SNAPSHOT
	pci_vtdtr_checkpoint_queue_free(sc->vsd_restore_planned);
	sc->vsd_restore_planned = NULL;
#endif
}

static void
pci_vtdtr_shutdown(void)
{
	struct pci_vtdtr_softc *sc = vtdtr_shutdown_sc;

	if (sc == NULL)
		return;
	vtdtr_shutdown_sc = NULL;
	pci_vtdtr_stop_workers(sc);
	/* Other vCPU threads may still hold pi_arg during process exit. */
}

/* Common VirtIO dispatch owns vsd_mtx across these lifecycle callbacks. */
static int
pci_vtdtr_suspend_device(void *vsc)
{
	struct pci_vtdtr_softc *sc = vsc;

	sc->vsd_suspended = true;
	pthread_cond_broadcast(&sc->vsd_cond);
	return (0);
}

static int
pci_vtdtr_resume_device(void *vsc)
{
	struct pci_vtdtr_softc *sc = vsc;

	sc->vsd_suspended = false;
	return (0);
}

static void
pci_vtdtr_resume_complete(void *vsc)
{
	struct pci_vtdtr_softc *sc = vsc;

	/* Common VirtIO still owns vsd_mtx after releasing its queue fence. */
	pthread_cond_broadcast(&sc->vsd_cond);
}

static bool
pci_vtdtr_normal_control_room(const struct pci_vtdtr_ctrlq *queue)
{
	return (queue != NULL && queue->restored_kills <= queue->count &&
	    queue->count < VTDTR_MAX_RESTORE_PENDING &&
	    queue->count - queue->restored_kills < VTDTR_MAX_PENDING);
}

#ifdef BHYVE_SNAPSHOT
/*
 * Retain backend ownership across pause/resume, as required by the common
 * VirtIO checkpoint gate.  Both workers serialize guest-memory and queue
 * updates with this lock. External dtraced state is stopped separately by
 * the coordinated fresh-session cut; it is not restored from this codec.
 */
static int
pci_vtdtr_pause(void *vsc)
{
	struct pci_vtdtr_softc *sc = vsc;
	int error;
	struct timespec deadline;

	error = pthread_mutex_lock(&sc->vsd_mtx);
	if (error != 0)
		return (error);
	/* Close reader admission, then drain the frame already being processed.
	 * A queue blocked on guest backpressure must fail rather than hang the
	 * checkpoint while vCPUs are stopped. */
	if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
		error = errno;
		goto fail;
	}
	deadline.tv_sec += 12;
	sc->vsd_checkpoint_paused = true;
	pthread_cond_broadcast(&sc->vsd_cond);
	while (sc->vsd_reader_active) {
		error = pthread_cond_timedwait(&sc->vsd_cond, &sc->vsd_mtx,
		    &deadline);
		if (error != 0)
			goto fail;
	}
	error = sc->vsd_session_stop_requested ?
	    pci_vtdtr_session_source_valid(sc) : pci_vtdtr_checkpoint_state_valid(sc);
	if (error == 0)
		return (0);
fail:
	sc->vsd_checkpoint_paused = false;
	pthread_cond_broadcast(&sc->vsd_cond);
	pthread_mutex_unlock(&sc->vsd_mtx);
	return (error);
}

static int
pci_vtdtr_resume(void *vsc)
{
	struct pci_vtdtr_softc *sc = vsc;

	if (sc->vsd_restore_planned != NULL || sc->vsd_session_restore_pending ||
	    sc->vsd_session_restore_staged || (sc->vsd_session_migration_staged &&
	    !sc->vsd_session_migration_released))
		return (EBUSY);
	sc->vsd_checkpoint_paused = false;
	pthread_cond_broadcast(&sc->vsd_cond);
	return (pthread_mutex_unlock(&sc->vsd_mtx));
}

/* The successful stop-VM path exits without a normal device resume.  It
 * still must release checkpoint's mutex ownership before the atexit handler
 * joins workers; closing admission first keeps the final queue cut intact. */
static int
pci_vtdtr_release_checkpoint_for_stop(struct pci_vtdtr_softc *sc)
{
	if (!sc->vsd_checkpoint_paused || sc->vsd_reader_active)
		return (EBUSY);
	sc->vsd_stopping = true;
	pthread_cond_broadcast(&sc->vsd_cond);
	return (pthread_mutex_unlock(&sc->vsd_mtx));
}

int
pci_vtdtr_checkpoint_stop(void)
{
	struct pci_vtdtr_softc *sc = vtdtr_shutdown_sc;
	int error;

	if (sc == NULL)
		return (0);
	error = pci_vtdtr_release_checkpoint_for_stop(sc);
	if (error != 0)
		return (error);
	pci_vtdtr_shutdown();
	return (0);
}

static int
pci_vtdtr_snapshot(void *vsc, struct vm_snapshot_meta *meta)
{
	int error;

	if (meta != NULL && meta->op == VM_SNAPSHOT_VALIDATE) {
		struct pci_vtdtr_softc *sc = vsc;
		const uint8_t *start = meta->buffer.buf;

		error = pci_vtdtr_private_snapshot(NULL, meta);
		if (error == 0 && sc != NULL && sc->vsd_capture_private) {
			sc->vsd_capture_start = start;
			sc->vsd_capture_length =
			    (const uint8_t *)meta->buffer.buf - start;
			sc->vsd_capture_seen = true;
		}
		return (error);
	}
	if (vsc != NULL && meta != NULL && meta->op == VM_SNAPSHOT_SAVE) {
		error = pci_vtdtr_checkpoint_replayable(vsc);
		if (error != 0)
			return (error);
		error = pci_vtdtr_private_snapshot(vsc, meta);
		if (error != 0)
			return (error);
		if (((struct pci_vtdtr_softc *)vsc)->vsd_session_stop_requested)
			return (0);
	}
	if (vsc != NULL && meta != NULL &&
	    meta->op == VM_SNAPSHOT_RESTORE) {
		if (((struct pci_vtdtr_softc *)vsc)->vsd_session_restore_staged)
			return (pci_vtdtr_session_private_restore(vsc, meta));
		return (pci_vtdtr_private_snapshot_restore(vsc, meta));
	}
	/* A VirtIO queue image cannot restore the external tracing session. */
	return (EOPNOTSUPP);
}

static int
pci_vtdtr_snapshot_validate(struct vm_snapshot_meta *meta)
{
	int error;

	if (meta == NULL || meta->op != VM_SNAPSHOT_VALIDATE ||
	    meta->dev_data == NULL)
		return (EOPNOTSUPP);
	error = vi_pci_snapshot(meta);
	if (error != 0)
		return (error);
	struct pci_devinst *pi = meta->dev_data;
	struct pci_vtdtr_softc *sc = pi->pi_arg;
	if (sc != NULL && sc->vsd_capture_private)
		sc->vsd_capture_complete = sc->vsd_capture_seen;
	/* The private image is valid, but daemon state is not yet rebound. */
	return (EOPNOTSUPP);
}

bool
pci_vtdtr_checkpoint_is_device(const struct pci_devinst *pi)
{
	return (pi != NULL && pi->pi_d != NULL &&
	    pi->pi_d->pe_emu != NULL &&
	    strcmp(pi->pi_d->pe_emu, "virtio-dtrace") == 0 &&
	    pi->pi_d->pe_snapshot_validate == pci_vtdtr_snapshot_validate);
}

int
pci_vtdtr_checkpoint_features_validate(uint64_t negotiated)
{
	return ((negotiated & VTDTR_RESTORE_REQUIRED_FEATURES) ==
	    VTDTR_RESTORE_REQUIRED_FEATURES ? 0 : EPROTO);
}

/* Hash the canonical admission records, not the native structure padding.
 * This also makes a lost-reply retry an exact manifest retry. */
static int
pci_vtdtr_replay_manifest_digest(const dtraced_replay_kill_t *kills,
    size_t count, uint8_t digest[SHA256_DIGEST_LENGTH])
{
	EVP_MD_CTX *hash;
	uint8_t wire[DTRACED_REPLAY_KILL_WIRE_SIZE];
	uint8_t count_wire[4];
	unsigned int digest_length = 0;
	int error = EIO;

	hash = EVP_MD_CTX_new();
	if (hash == NULL)
		return (ENOMEM);
	le32enc(count_wire, (uint32_t)count);
	if (EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1 ||
	    EVP_DigestUpdate(hash, count_wire, sizeof(count_wire)) != 1)
		goto done;
	for (size_t i = 0; i < count; i++) {
		le32enc(wire, (uint32_t)kills[i].pid);
		le16enc(wire + 4, kills[i].vmid);
		wire[6] = wire[7] = 0;
		le64enc(wire + 8, kills[i].epoch);
		memcpy(wire + 16, kills[i].source_id, 16);
		if (EVP_DigestUpdate(hash, wire, sizeof(wire)) != 1)
			goto done;
	}
	if (EVP_DigestFinal_ex(hash, digest, &digest_length) == 1 &&
	    digest_length == SHA256_DIGEST_LENGTH)
		error = 0;
done:
	EVP_MD_CTX_free(hash);
	explicit_bzero(wire, sizeof(wire));
	return (error);
}

static bool
pci_vtdtr_replay_manifest_room(const struct pci_vtdtr_ctrlq *queue,
    size_t count)
{
	return (queue != NULL && queue->restored_kills <= queue->count &&
	    count <= DTRACED_REPLAY_KILL_MAX &&
	    queue->count < VTDTR_MAX_RESTORE_PENDING - 2 &&
	    count < VTDTR_MAX_RESTORE_PENDING - 2 - queue->count);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* Caller owns vsd_mtx. The restore coordinator can attach while the common
 * VirtIO pause still owns that mutex, before the reader can inspect the
 * restored queue. The ticket never comes from a guest descriptor. */
static int
pci_vtdtr_handoff_ticket_attach_locked(struct pci_devinst *pi,
    const uint8_t token[16], const uint8_t digest[32],
    const dtraced_replay_kill_t *kills, size_t count, bool paused)
{
	const uint8_t zero16[16] = {}, zero32[32] = {};
	struct pci_vtdtr_softc *sc;
	struct pci_vtdtr_ctrlq *target;
	struct pci_vtdtr_ctrlq staged = { 0 };
	struct pci_vtdtr_ctrl_entry *entry;
	uint8_t manifest_digest[SHA256_DIGEST_LENGTH];
	uint16_t vmid;
	uint64_t epoch;
	int error = 0;

	if (!pci_vtdtr_checkpoint_is_device(pi) || token == NULL ||
	    digest == NULL || memcmp(token, zero16, sizeof(zero16)) == 0 ||
	    memcmp(digest, zero32, sizeof(zero32)) == 0 ||
	    (sc = pi->pi_arg) == NULL ||
	    (count != 0 && kills == NULL))
		return (EINVAL);
	if (count > DTRACED_REPLAY_KILL_MAX)
		return (ENOBUFS);
	error = pci_vtdtr_replay_manifest_digest(kills, count,
	    manifest_digest);
	if (error != 0)
		return (error);
	STAILQ_INIT(&staged.head);
	/* A paused restore still has the old live queue. Keep admission KILLs
	 * with the private saved queue until the coordinator publishes it. */
	target = paused && sc->vsd_restore_planned != NULL ?
	    sc->vsd_restore_planned : sc->vsd_ctrlq;
	if (sc->vsd_stopping || sc->vsd_checkpoint_paused != paused ||
	    (paused && sc->vsd_reader_active) ||
	    sc->vsd_ctrlq == NULL ||
	    (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		error = EBUSY;
	else if (vm_get_identity(sc->vsd_vmctx, &vmid, &epoch) != 0 ||
	    vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0)
		error = ESTALE;
	else if (sc->vsd_handoff_ticket_valid) {
		if (sc->vsd_handoff_vmid != vmid ||
		    sc->vsd_handoff_epoch != epoch ||
		    memcmp(sc->vsd_handoff_token, token, 16) != 0 ||
		    memcmp(sc->vsd_handoff_digest, digest, 32) != 0 ||
		    memcmp(sc->vsd_replay_manifest_digest, manifest_digest,
		    sizeof(manifest_digest)) != 0)
			error = EBUSY;
	} else {
		if (!pci_vtdtr_replay_manifest_room(target, count))
			error = ENOBUFS;
		for (size_t i = 0; error == 0 && i < count; i++) {
			if (kills[i].pid <= 1 || kills[i].vmid != vmid ||
			    kills[i].epoch != epoch ||
			    memcmp(kills[i].source_id, zero16, 16) == 0) {
				error = ESTALE;
				break;
			}
			entry = calloc(1, sizeof(*entry));
			if (entry != NULL)
				entry->ctrl = calloc(1, sizeof(*entry->ctrl));
			if (entry == NULL || entry->ctrl == NULL) {
				free(entry);
				error = ENOMEM;
				break;
			}
			entry->ctrl->pvc_event = VTDTR_DEVICE_KILL;
			entry->ctrl->pvc_pid = kills[i].pid;
			entry->ctrl->pvc_kill_vmid = kills[i].vmid;
			entry->ctrl->pvc_kill_epoch = kills[i].epoch;
			memcpy(entry->ctrl->pvc_source_id,
			    kills[i].source_id, 16);
			entry->restored_kill = true;
			entry->restored_control = true;
			pci_vtdtr_cq_enqueue(&staged, entry);
		}
		if (error == 0) {
			while ((entry = pci_vtdtr_cq_dequeue(&staged)) != NULL)
				if (!pci_vtdtr_insert_restore_kill(target,
				    entry))
					pci_vtdtr_cq_enqueue(target, entry);
			memcpy(sc->vsd_handoff_token, token, 16);
			memcpy(sc->vsd_handoff_digest, digest, 32);
			memcpy(sc->vsd_replay_manifest_digest, manifest_digest,
			    sizeof(manifest_digest));
			sc->vsd_handoff_vmid = vmid;
			sc->vsd_handoff_epoch = epoch;
			sc->vsd_handoff_ticket_valid = true;
		}
	}
	while ((entry = pci_vtdtr_cq_dequeue(&staged)) != NULL) {
		free(entry->ctrl);
		free(entry);
	}
	if (error == 0) {
		sc->vsd_ticket_wait = false;
		sc->vsd_ticket_deadline = (struct timespec){ 0 };
		pthread_cond_signal(&sc->vsd_cond);
	}
	explicit_bzero(manifest_digest, sizeof(manifest_digest));
	return (error);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
int
pci_vtdtr_handoff_ticket_attach(struct pci_devinst *pi,
    const uint8_t token[16], const uint8_t digest[32],
    const dtraced_replay_kill_t *kills, size_t count)
{
	struct pci_vtdtr_softc *sc;
	int error, unlock_error;

	if (!pci_vtdtr_checkpoint_is_device(pi) ||
	    (sc = pi->pi_arg) == NULL)
		return (EINVAL);
	error = pthread_mutex_lock(&sc->vsd_mtx);
	if (error != 0)
		return (error);
	error = pci_vtdtr_handoff_ticket_attach_locked(pi, token, digest,
	    kills, count, false);
	unlock_error = pthread_mutex_unlock(&sc->vsd_mtx);
	return (error != 0 ? error : unlock_error);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* vm_pause_devices() leaves vsd_mtx owned by this coordinator thread. */
int
pci_vtdtr_handoff_ticket_attach_paused(struct pci_devinst *pi,
    const uint8_t token[16], const uint8_t digest[32],
    const dtraced_replay_kill_t *kills, size_t count)
{
	return (pci_vtdtr_handoff_ticket_attach_locked(pi, token, digest,
	    kills, count, true));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
void
pci_vtdtr_handoff_ticket_clear(struct pci_devinst *pi)
{
	struct pci_vtdtr_softc *sc;

	if (!pci_vtdtr_checkpoint_is_device(pi) ||
	    (sc = pi->pi_arg) == NULL)
		return;
	pthread_mutex_lock(&sc->vsd_mtx);
	pci_vtdtr_handoff_ticket_forget(sc);
	pthread_mutex_unlock(&sc->vsd_mtx);
}

int
pci_vtdtr_checkpoint_capture_begin(struct pci_devinst *pi)
{
	struct pci_vtdtr_softc *sc;

	if (!pci_vtdtr_checkpoint_is_device(pi) ||
	    (sc = pi->pi_arg) == NULL)
		return (EINVAL);
	/* The restore coordinator owns this mutex through device pause. */
	if (!sc->vsd_checkpoint_paused || sc->vsd_capture_private)
		return (EBUSY);
	sc->vsd_capture_start = NULL;
	sc->vsd_capture_length = 0;
	sc->vsd_capture_seen = false;
	sc->vsd_capture_complete = false;
	sc->vsd_capture_private = true;
	return (0);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Source-side
 * handoff: called only under vm_checkpoint()'s handoff_enabled, so this is
 * intentionally unreachable until enabled. */
int
pci_vtdtr_checkpoint_source_replay_room(struct pci_devinst *pi,
    size_t projected)
{
	struct pci_vtdtr_softc *sc;
	int error;

	if (!pci_vtdtr_checkpoint_is_device(pi) ||
	    (sc = pi->pi_arg) == NULL)
		return (EINVAL);
	/* Device pause owns vsd_mtx until the source cut completes. */
	if (!sc->vsd_checkpoint_paused || sc->vsd_reader_active)
		return (EBUSY);
	error = pci_vtdtr_checkpoint_state_valid(sc);
	if (error != 0)
		return (error);
	/* Destination replay adds NODE_REKEY and must leave two slots for
	 * publication and acknowledgements while guest vCPUs stay fenced. */
	if (sc->vsd_ctrlq->count >= VTDTR_MAX_PENDING - 3 ||
	    projected >= VTDTR_MAX_PENDING - 3 - sc->vsd_ctrlq->count)
		return (ENOBUFS);
	return (0);
}

int
pci_vtdtr_checkpoint_capture_end(struct pci_devinst *pi,
    const void **start, size_t *length, bool *complete)
{
	struct pci_vtdtr_softc *sc;

	if (!pci_vtdtr_checkpoint_is_device(pi) ||
	    (sc = pi->pi_arg) == NULL || start == NULL || length == NULL ||
	    complete == NULL || !sc->vsd_capture_private)
		return (EINVAL);
	*start = sc->vsd_capture_seen ? sc->vsd_capture_start : NULL;
	*length = sc->vsd_capture_seen ? sc->vsd_capture_length : 0;
	*complete = sc->vsd_capture_complete;
	sc->vsd_capture_private = false;
	sc->vsd_capture_seen = false;
	sc->vsd_capture_complete = false;
	sc->vsd_capture_start = NULL;
	sc->vsd_capture_length = 0;
	return (0);
}

static int
pci_vtdtr_snapshot_extra_capacity(struct pci_devinst *pi, size_t *extra)
{
	struct pci_vtdtr_softc *sc;
	size_t queued, partial, entry_size;
	int error;

	if (pi == NULL || extra == NULL ||
	    (sc = pi->pi_arg) == NULL || sc->vsd_ctrlq == NULL)
		return (EINVAL);
	/* The checkpoint coordinator owns vsd_mtx through device pause. */
	error = sc->vsd_session_stop_requested ?
	    pci_vtdtr_session_source_valid(sc) : pci_vtdtr_checkpoint_state_valid(sc);
	if (error != 0)
		return (error);
	queued = sc->vsd_ctrlq->count;
	partial = sc->vsd_inbound_elf.received;
	if (queued == 0 && partial == 0) {
		*extra = 0;
		return (0);
	}
	/* Allow a per-control record header and private image header. */
	entry_size = sizeof(struct pci_vtdtr_control) + 16;
	if (partial > SIZE_MAX - 4096 ||
	    queued > (SIZE_MAX - partial - 4096) / entry_size)
		return (EOVERFLOW);
	*extra = 4096 + queued * entry_size + partial;
	return (0);
}
#endif

static int
pci_vtdtr_apply_features(void *vsc __unused, uint64_t features)
{
	/* Require ordinary session safety; continuity has separate admission. */
	const uint64_t required = VTDTR_WIRE_F_SESSION_REQUIRED;
	return ((features & required) == required ? 0 : EPROTO);
}

static struct virtio_consts vtdtr_vi_consts = {
	.vc_name = "vtdtr",
	.vc_nvq = VTDTR_MAXQ,
	.vc_reset = pci_vtdtr_reset,
	.vc_apply_features = pci_vtdtr_apply_features,
	.vc_hv_caps = VTDTR_WIRE_F_SESSION_REQUIRED | VTDTR_WIRE_F_CONTINUITY |
	    VTDTR_WIRE_F_SESSION_STOP_V1 | VTDTR_WIRE_F_SESSION_FRESH_V1,
	.vc_suspend = pci_vtdtr_suspend_device,
	.vc_resume_device = pci_vtdtr_resume_device,
	.vc_resume_complete = pci_vtdtr_resume_complete,
#ifdef BHYVE_SNAPSHOT
	.vc_pause = pci_vtdtr_pause,
	.vc_resume = pci_vtdtr_resume,
	.vc_snapshot = pci_vtdtr_snapshot,
#endif
};

static void
pci_vtdtr_reset(void *xsc)
{
	struct pci_vtdtr_softc *sc = xsc;

	/* VirtIO dispatch already owns vsd_mtx. */
	if (sc->vsd_stopping || sc->vsd_session_stop_requested) {
		/* A late guest reset must not restart a retired host session. */
		vi_set_needs_reset(&sc->vsd_vs);
		return;
	}
	DPRINTF(("vtdtr: device reset requested!\n"));
	sc->vsd_generation = hypertrace_reset();
	sc->vsd_guest_ready = sc->vsd_ready = 0;
	sc->vsd_rekey_wait = false;
	sc->vsd_rekey_ack_pending = sc->vsd_rekey_ack_sent = false;
	sc->vsd_rekey_old_id = sc->vsd_rekey_new_id = 0;
	sc->vsd_rekey_old_epoch = sc->vsd_rekey_new_epoch = 0;
	sc->vsd_rekey_deadline = (struct timespec){ 0 };
	sc->vsd_restored_kill_wait = false;
	sc->vsd_restored_kill_pid = 0;
	memset(sc->vsd_restored_kill_source_id, 0,
	    sizeof(sc->vsd_restored_kill_source_id));
	sc->vsd_restored_kill_deadline = (struct timespec){ 0 };
	pci_vtdtr_handoff_ticket_forget(sc);
	sc->vsd_suspended = false;
	pci_vtdtr_reset_queue(sc);
	hypertrace_elf_reset(&sc->vsd_inbound_elf);
	sc->vsd_inbound_delivery_id = 0;
	sc->vsd_inbound_vmid = 0;
	sc->vsd_inbound_epoch = 0;
	memset(sc->vsd_inbound_program_id, 0, sizeof(sc->vsd_inbound_program_id));
	memset(sc->vsd_inbound_source_id, 0, sizeof(sc->vsd_inbound_source_id));
	vi_reset_dev(&sc->vsd_vs);
	pthread_cond_broadcast(&sc->vsd_cond);
}

static int
pci_vtdtr_session_stop_begin_impl(struct vmctx *ctx, bool checkpoint)
{
	struct pci_vtdtr_softc *sc = vtdtr_shutdown_sc;
	struct pci_vtdtr_ctrl_entry *entry = NULL;
	struct pci_vtdtr_control *ctrl = NULL;
	uint16_t vmid;
	uint64_t epoch;
	int error = 0;

	if (sc == NULL || ctx == NULL || sc->vsd_vmctx != ctx)
		return (ENXIO);
	pthread_mutex_lock(&sc->vsd_mtx);
	if (sc->vsd_stopping ||
	    (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		error = ENXIO;
	else if (vm_get_identity(ctx, &vmid, &epoch) != 0)
		error = errno != 0 ? errno : EIO;
	else if (vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0)
		error = EPROTO;
	else if (checkpoint && (sc->vsd_vs.vs_negotiated_caps &
	    (VTDTR_WIRE_F_SESSION_REQUIRED | VTDTR_WIRE_F_SESSION_STOP_V1 |
	    VTDTR_WIRE_F_SESSION_FRESH_V1)) !=
	    (VTDTR_WIRE_F_SESSION_REQUIRED | VTDTR_WIRE_F_SESSION_STOP_V1 |
	    VTDTR_WIRE_F_SESSION_FRESH_V1))
		error = ENOTSUP;
	else if (sc->vsd_session_stop_requested) {
		if (vmid != sc->vsd_session_stop_vmid ||
		    epoch != sc->vsd_session_stop_epoch)
			error = ESTALE;
	} else if ((sc->vsd_vs.vs_negotiated_caps &
	    VTDTR_WIRE_F_SESSION_STOP_V1) == 0)
		error = ENOTSUP;
	else if (sc->vsd_checkpoint_paused || sc->vsd_suspended ||
	    sc->vsd_rekey_wait || sc->vsd_restored_kill_wait ||
	    sc->vsd_cleanup_unapplied || sc->vsd_handoff_ticket_valid)
		error = EBUSY;
	else if ((entry = calloc(1, sizeof(*entry))) == NULL ||
	    (ctrl = calloc(1, sizeof(*ctrl))) == NULL)
		error = ENOMEM;
	else if (clock_gettime(CLOCK_MONOTONIC,
	    &sc->vsd_session_stop_deadline) != 0)
		error = errno;
	else {
		/* Retain ownership even if suspend succeeds but readback fails. */
		if (memcmp(sc->vsd_session_gate_token,
		    (const uint8_t[16]){0}, 16) == 0) {
			do {
				arc4random_buf(sc->vsd_session_gate_token, 16);
			} while (memcmp(sc->vsd_session_gate_token,
			    (const uint8_t[16]){0}, 16) == 0);
			sc->vsd_session_stop_vmid = vmid;
			sc->vsd_session_stop_epoch = epoch;
		}
		if (vmid != sc->vsd_session_stop_vmid ||
		    epoch != sc->vsd_session_stop_epoch)
			error = ESTALE;
		else if (hypertrace_session_host_stop(ctx,
		    sc->vsd_session_gate_token) != 0)
			error = errno != 0 ? errno : EIO;
		if (error != 0)
			goto out;
		uint64_t token;
		do { arc4random_buf(&token, sizeof(token)); } while (token == 0);
		sc->vsd_session_stop_deadline.tv_sec += 15;
		ctrl->pvc_event = VTDTR_DEVICE_SESSION_STOP;
		ctrl->pvc_cleanup_vmid = vmid;
		ctrl->pvc_cleanup_epoch = epoch;
		ctrl->pvc_cleanup_delivery_id = token;
		entry->ctrl = ctrl;
		sc->vsd_session_stop_vmid = vmid;
		sc->vsd_session_stop_epoch = epoch;
		sc->vsd_session_stop_token = token;
		sc->vsd_session_stop_requested = true;
		sc->vsd_session_collectors_stopped = false;
		sc->vsd_session_stopped = false;
		sc->vsd_session_stop_delivered = false;
		sc->vsd_fresh_requested = sc->vsd_fresh_active = false;
		sc->vsd_fresh_prepare_delivered = sc->vsd_fresh_commit_queued = false;
		sc->vsd_fresh_commit_delivered = sc->vsd_fresh_released = false;
		memset(sc->vsd_fresh_gate_token, 0, 16);
		sc->vsd_ready = 0;
		/* Publication now refuses all frames, including a reader that
		 * was already assembling an old-session delivery. */
		pci_vtdtr_reset_queue(sc);
		hypertrace_elf_reset(&sc->vsd_inbound_elf);
		sc->vsd_inbound_delivery_id = 0;
		sc->vsd_inbound_vmid = 0;
		sc->vsd_inbound_epoch = 0;
		memset(sc->vsd_inbound_program_id, 0, 16);
		memset(sc->vsd_inbound_source_id, 0, 16);
		pci_vtdtr_cq_enqueue(sc->vsd_ctrlq, entry);
		entry = NULL;
		ctrl = NULL;
		pci_vtdtr_notify_ready(sc);
		pthread_cond_broadcast(&sc->vsd_cond);
	}
out:
	free(ctrl);
	free(entry);
	pthread_mutex_unlock(&sc->vsd_mtx);
	return (error);
}

int
pci_vtdtr_session_stop_begin(struct vmctx *ctx)
{
	return (pci_vtdtr_session_stop_begin_impl(ctx, false));
}

int
pci_vtdtr_session_checkpoint_begin(struct vmctx *ctx)
{
	/* Check restart support under the same lock as the stop transition. */
	return (pci_vtdtr_session_stop_begin_impl(ctx, true));
}

/* A destination owns a new gate token, never the serialized source token.
 * Retain it across uncertain suspend/readback so an exact retry can resolve
 * ownership without changing the operation's identity. */
static int
pci_vtdtr_fresh_gate_check(struct pci_vtdtr_softc *sc)
{
	uint16_t vmid;
	uint64_t epoch;
	if (vm_get_identity(sc->vsd_vmctx, &vmid, &epoch) != 0)
		return (errno != 0 ? errno : EIO);
	if (vmid != sc->vsd_fresh_vmid || epoch != sc->vsd_fresh_epoch)
		return (ESTALE);
	return ((sc->vsd_fresh_released ?
	    hypertrace_session_host_released(sc->vsd_vmctx, sc->vsd_fresh_gate_token) :
	    hypertrace_session_host_stopped(sc->vsd_vmctx, sc->vsd_fresh_gate_token)) == 0 ?
	    0 : (errno != 0 ? errno : EIO));
}

static int
pci_vtdtr_fresh_gate_hold(struct pci_vtdtr_softc *sc, uint16_t vmid, uint64_t epoch)
{
	if (memcmp(sc->vsd_fresh_gate_token, (const uint8_t[16]){0}, 16) == 0) {
		do {
			arc4random_buf(sc->vsd_fresh_gate_token, 16);
		} while (memcmp(sc->vsd_fresh_gate_token, (const uint8_t[16]){0}, 16) == 0);
		sc->vsd_fresh_vmid = vmid;
		sc->vsd_fresh_epoch = epoch;
	}
	if (vmid != sc->vsd_fresh_vmid || epoch != sc->vsd_fresh_epoch)
		return (ESTALE);
	if (hypertrace_session_host_stop(sc->vsd_vmctx, sc->vsd_fresh_gate_token) != 0)
		return (errno != 0 ? errno : EIO);
	return (pci_vtdtr_fresh_gate_check(sc));
}

/* Called after source identity retirement and destination VM creation.
 * The coordinator must retain the proven stop tuple across that transition. */
int
pci_vtdtr_session_attach_begin(struct vmctx *ctx)
{
	struct pci_vtdtr_softc *sc = vtdtr_shutdown_sc;
	struct pci_vtdtr_ctrl_entry *entry = NULL;
	struct pci_vtdtr_control *ctrl = NULL;
	uint16_t vmid;
	uint64_t epoch;
	int error = 0;

	if (sc == NULL || ctx == NULL || sc->vsd_vmctx != ctx)
		return (ENXIO);
	pthread_mutex_lock(&sc->vsd_mtx);
	if (sc->vsd_stopping ||
	    (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		error = ENXIO;
	else if (!sc->vsd_session_stop_requested || !sc->vsd_session_stopped ||
	    (sc->vsd_session_migration_staged && !sc->vsd_session_migration_released) ||
	    sc->vsd_session_stop_vmid == 0 || sc->vsd_session_stop_epoch == 0 ||
	    sc->vsd_session_stop_token == 0 || sc->vsd_suspended ||
	    sc->vsd_checkpoint_paused || sc->vsd_session_restore_pending ||
	    sc->vsd_rekey_wait)
		error = EBUSY;
	else if ((sc->vsd_vs.vs_negotiated_caps &
	    VTDTR_WIRE_F_SESSION_FRESH_V1) == 0)
		error = ENOTSUP;
	else if (vm_get_identity(ctx, &vmid, &epoch) != 0)
		error = errno != 0 ? errno : EIO;
	else if (vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0 ||
	    epoch == sc->vsd_session_stop_epoch)
		error = ESTALE;
	else if (sc->vsd_fresh_requested) {
		if (vmid != sc->vsd_fresh_vmid || epoch != sc->vsd_fresh_epoch)
			error = ESTALE;
		else
			error = pci_vtdtr_fresh_gate_check(sc);
	} else if (!sc->vsd_session_migration_staged &&
	    hypertrace_session_retired(sc->vsd_session_stop_vmid,
	    sc->vsd_session_stop_epoch) != 0)
		error = errno != 0 ? errno : EIO;
	else if ((error = pci_vtdtr_fresh_gate_hold(sc, vmid, epoch)) != 0)
		;
	else if ((entry = calloc(1, sizeof(*entry))) == NULL ||
	    (ctrl = calloc(1, sizeof(*ctrl))) == NULL)
		error = ENOMEM;
	else if (clock_gettime(CLOCK_MONOTONIC, &sc->vsd_fresh_deadline) != 0)
		error = errno;
	else {
		ctrl->pvc_event = VTDTR_DEVICE_SESSION_PREPARE;
		ctrl->wire.uctrl.session_prepare.stop_token = sc->vsd_session_stop_token;
		ctrl->wire.uctrl.session_prepare.old_id = sc->vsd_session_stop_vmid;
		ctrl->wire.uctrl.session_prepare.old_epoch = sc->vsd_session_stop_epoch;
		ctrl->wire.uctrl.session_prepare.new_id = vmid;
		ctrl->wire.uctrl.session_prepare.new_epoch = epoch;
		entry->ctrl = ctrl;
		sc->vsd_fresh_vmid = vmid;
		sc->vsd_fresh_epoch = epoch;
		sc->vsd_fresh_requested = true;
		sc->vsd_fresh_deadline.tv_sec += 60;
		/* The stop fence still rejects publication and old inbound work. */
		pci_vtdtr_reset_queue(sc);
		pci_vtdtr_cq_enqueue(sc->vsd_ctrlq, entry);
		ctrl = NULL;
		entry = NULL;
		sc->vsd_guest_ready = 1;
		sc->vsd_ready = 0;
		pci_vtdtr_notify_ready(sc);
		pthread_cond_broadcast(&sc->vsd_cond);
	}
	free(ctrl);
	free(entry);
	pthread_mutex_unlock(&sc->vsd_mtx);
	return (error);
}

int
pci_vtdtr_session_checkpoint_export(struct vmctx *ctx, void *buffer,
    size_t length)
{
	struct pci_vtdtr_softc *sc = vtdtr_shutdown_sc;
	struct hypertrace_session_record record;
	uint16_t vmid;
	uint64_t epoch;
	int error = 0;
	if (sc == NULL || ctx == NULL || sc->vsd_vmctx != ctx)
		return (ENXIO);
	if (buffer == NULL || length != HYPERTRACE_SESSION_RECORD_SIZE)
		return (EINVAL);
	pthread_mutex_lock(&sc->vsd_mtx);
	if (sc->vsd_stopping || !sc->vsd_session_stop_requested ||
	    !sc->vsd_session_stop_delivered || !sc->vsd_session_stopped ||
	    !sc->vsd_session_collectors_stopped || sc->vsd_session_collectors_busy ||
	    sc->vsd_fresh_requested || sc->vsd_rekey_wait ||
	    (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		error = EBUSY;
	else if ((sc->vsd_vs.vs_negotiated_caps & HYPERTRACE_SESSION_FEATURES) !=
	    HYPERTRACE_SESSION_FEATURES)
		error = ENOTSUP;
	else if (vm_get_identity(ctx, &vmid, &epoch) != 0)
		error = errno != 0 ? errno : EIO;
	else if (vmid != sc->vsd_session_stop_vmid ||
	    epoch != sc->vsd_session_stop_epoch)
		error = ESTALE;
	else if (hypertrace_session_host_stopped(ctx,
	    sc->vsd_session_gate_token) != 0)
		error = errno != 0 ? errno : EIO;
	else {
		record = (struct hypertrace_session_record){
		    .vmid = vmid, .epoch = epoch,
		    .stop_token = sc->vsd_session_stop_token,
		    .features = HYPERTRACE_SESSION_FEATURES };
		error = hypertrace_session_record_encode(buffer, length, &record);
	}
	pthread_mutex_unlock(&sc->vsd_mtx);
	return (error);
}

#ifdef BHYVE_SNAPSHOT
/* The restore coordinator owns vsd_mtx through vm_pause_devices(). This
 * imports only private stop metadata; generic VirtIO ring restoration still
 * requires the coordinator's separate discard/drain phase before resume. */
int
pci_vtdtr_session_checkpoint_import_paused(struct pci_devinst *pi,
    const void *buffer, size_t length)
{
	struct hypertrace_session_record record;
	struct pci_vtdtr_softc *sc;
	uint16_t vmid;
	uint64_t epoch;
	int error;
	if (!pci_vtdtr_checkpoint_is_device(pi) || (sc = pi->pi_arg) == NULL)
		return (EINVAL);
	error = hypertrace_session_record_decode(buffer, length, &record);
	if (error != 0)
		return (error);
	if (!sc->vsd_checkpoint_paused || sc->vsd_reader_active ||
	    sc->vsd_session_collectors_busy ||
	    sc->vsd_stopping || sc->vsd_fresh_requested || sc->vsd_rekey_wait ||
	    sc->vsd_restored_kill_wait || sc->vsd_cleanup_unapplied ||
	    sc->vsd_rekey_ack_pending || sc->vsd_rekey_ack_sent ||
	    sc->vsd_rekey_receipt_reply_pending || sc->vsd_ticket_wait ||
	    sc->vsd_handoff_ticket_valid || sc->vsd_restore_planned != NULL ||
	    (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		return (EBUSY);
	if ((sc->vsd_vs.vs_negotiated_caps & record.features) != record.features)
		return (ENOTSUP);
	if (vm_get_identity(sc->vsd_vmctx, &vmid, &epoch) != 0)
		return (errno != 0 ? errno : EIO);
	if (vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0 ||
	    epoch == record.epoch || (sc->vsd_session_stop_requested &&
	    (sc->vsd_session_stop_vmid != record.vmid ||
	    sc->vsd_session_stop_epoch != record.epoch ||
	    sc->vsd_session_stop_token != record.stop_token)))
		return (ESTALE);
	if (sc->vsd_session_migration_staged &&
	    memcmp(buffer, sc->vsd_session_migration_record, length) != 0)
		return (ESTALE);
	if (!sc->vsd_session_migration_staged &&
	    hypertrace_session_retired(record.vmid, record.epoch) != 0)
		return (errno != 0 ? errno : EIO);
	pci_vtdtr_reset_queue(sc);
	hypertrace_elf_reset(&sc->vsd_inbound_elf);
	sc->vsd_inbound_delivery_id = 0;
	sc->vsd_inbound_vmid = 0;
	sc->vsd_inbound_epoch = 0;
	memset(sc->vsd_inbound_program_id, 0, 16);
	memset(sc->vsd_inbound_source_id, 0, 16);
	sc->vsd_session_stop_vmid = record.vmid;
	sc->vsd_session_stop_epoch = record.epoch;
	sc->vsd_session_stop_token = record.stop_token;
	sc->vsd_session_stop_requested = sc->vsd_session_stop_delivered = true;
	sc->vsd_session_stopped = true;
	/* The source collector proof is not local ownership on this host. */
	sc->vsd_session_collectors_stopped = false;
	sc->vsd_session_restore_pending = true;
	sc->vsd_guest_ready = sc->vsd_ready = 0;
	memset(sc->vsd_session_gate_token, 0, sizeof(sc->vsd_session_gate_token));
	return (0);
}

/* Called after guest memory and generic VirtIO state have been restored,
 * with vCPUs stopped and checkpoint ownership of vsd_mtx retained. Return
 * each obsolete guest TX buffer through its used ring; never execute its
 * control or reset ring indices behind the guest's ownership bookkeeping.
 * Host TX contains guest receive buffers, which must remain posted. */
int
pci_vtdtr_session_discard_paused(struct pci_devinst *pi)
{
	struct pci_vtdtr_softc *sc;
	struct vqueue_info *vq;
	struct iovec iov[VTDTR_MAX_IOV];
	struct vi_req req;
	uint16_t vmid;
	uint64_t epoch;
	bool pending;
	int error, n;
	unsigned int budget;

	if (!pci_vtdtr_checkpoint_is_device(pi) || (sc = pi->pi_arg) == NULL)
		return (EINVAL);
	if (!sc->vsd_checkpoint_paused || sc->vsd_reader_active ||
	    sc->vsd_stopping || !sc->vsd_session_restore_pending ||
	    !sc->vsd_session_stopped || sc->vsd_fresh_requested)
		return (EBUSY);
	if ((sc->vsd_vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0 ||
	    !vq_is_allocated(&sc->vsd_queues[0]) ||
	    !vq_is_allocated(&sc->vsd_queues[1]))
		return (EBUSY);
	if (vm_get_identity(sc->vsd_vmctx, &vmid, &epoch) != 0)
		return (errno != 0 ? errno : EIO);
	if (vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0 ||
	    epoch == sc->vsd_session_stop_epoch)
		return (ESTALE);
	if (!sc->vsd_session_migration_staged &&
	    hypertrace_session_retired(sc->vsd_session_stop_vmid,
	    sc->vsd_session_stop_epoch) != 0)
		return (errno != 0 ? errno : EIO);
	vq = &sc->vsd_queues[1];
	budget = vq->vq_qsize;
	for (;;) {
		error = vq_checkpoint_has_descs(vq, &pending);
		if (error != 0)
			return (error);
		if (!pending)
			break;
		if (budget-- == 0) {
			vi_set_needs_reset(&sc->vsd_vs);
			return (EPROTO);
		}
		n = vq_getchain(vq, iov, nitems(iov), &req);
		if (n <= 0) {
			if (n == 0)
				return (EBUSY);
			vi_set_needs_reset(&sc->vsd_vs);
			return (EPROTO);
		}
		vq_relchain_req(vq, &req, 0);
		if (n > VTDTR_MAX_IOV || !req.ordered || req.readable != n ||
		    req.writable != 0 ||
		    (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0) {
			vi_set_needs_reset(&sc->vsd_vs);
			return (EPROTO);
		}
	}
	/* Also publish notification accounting after a partial prior attempt. */
	vq_endchains(vq, 1);
	if ((sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		return (EPROTO);
	sc->vsd_session_restore_pending = false;
	return (0);
}
#endif

int
pci_vtdtr_session_attach_status(struct vmctx *ctx)
{
	struct pci_vtdtr_softc *sc = vtdtr_shutdown_sc;
	uint16_t vmid;
	uint64_t epoch;
	int error;
	if (sc == NULL || ctx == NULL || sc->vsd_vmctx != ctx)
		return (ENXIO);
	pthread_mutex_lock(&sc->vsd_mtx);
	if (!sc->vsd_fresh_requested)
		error = ENOENT;
	else if (sc->vsd_stopping ||
	    (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		error = ENXIO;
	else if (vm_get_identity(ctx, &vmid, &epoch) != 0)
		error = errno != 0 ? errno : EIO;
	else if (vmid != sc->vsd_fresh_vmid || epoch != sc->vsd_fresh_epoch)
		error = ESTALE;
	else if ((error = pci_vtdtr_fresh_gate_check(sc)) != 0)
		;
	else if (sc->vsd_fresh_active)
		error = 0;
	else if (pci_vtdtr_deadline_expired(&sc->vsd_fresh_deadline))
		error = ETIMEDOUT;
	else
		error = EBUSY;
	pthread_mutex_unlock(&sc->vsd_mtx);
	return (error);
}

/* Guest ACTIVE is necessary but not sufficient: authenticate host release
 * outside the device lock, then invalidate old reader work before reopening
 * ordinary traffic. A lost reply leaves local admission closed for retry. */
int
pci_vtdtr_session_authorize(struct vmctx *ctx)
{
	struct pci_vtdtr_softc *sc = vtdtr_shutdown_sc;
	uint8_t token[16];
	uint16_t vmid;
	uint64_t epoch, generation;
	int error;
	if (sc == NULL || ctx == NULL || sc->vsd_vmctx != ctx)
		return (ENXIO);
	pthread_mutex_lock(&sc->vsd_mtx);
	if (!sc->vsd_fresh_requested || !sc->vsd_fresh_active ||
	    (sc->vsd_session_migration_staged && !sc->vsd_session_migration_released) ||
	    sc->vsd_fresh_release_busy || sc->vsd_stopping || sc->vsd_checkpoint_paused ||
	    sc->vsd_session_restore_staged || sc->vsd_session_restore_pending ||
	    sc->vsd_suspended || sc->vsd_rekey_wait ||
	    (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0) {
		error = EBUSY;
		goto out;
	}
	if (vm_get_identity(ctx, &vmid, &epoch) != 0) {
		error = errno != 0 ? errno : EIO;
		goto out;
	}
	if (vmid != sc->vsd_fresh_vmid || epoch != sc->vsd_fresh_epoch) {
		error = ESTALE;
		goto out;
	}
	if (sc->vsd_fresh_released) {
		error = pci_vtdtr_fresh_gate_check(sc);
		if (error == 0 && !sc->vsd_ready)
			pci_vtdtr_notify_ready(sc);
		goto out;
	}
	if (!sc->vsd_session_stop_requested || !sc->vsd_session_stopped ||
	    sc->vsd_generation == UINT64_MAX) {
		error = EBUSY;
		goto out;
	}
	memcpy(token, sc->vsd_fresh_gate_token, 16);
	generation = sc->vsd_generation;
	sc->vsd_fresh_release_busy = true;
	pthread_mutex_unlock(&sc->vsd_mtx);
	error = hypertrace_session_release(ctx, token) == 0 ? 0 :
	    (errno != 0 ? errno : EIO);
	pthread_mutex_lock(&sc->vsd_mtx);
	sc->vsd_fresh_release_busy = false;
	if (error != 0)
		goto out;
	if (!sc->vsd_fresh_active || !sc->vsd_session_stop_requested ||
	    !sc->vsd_session_stopped || sc->vsd_stopping || sc->vsd_checkpoint_paused ||
	    sc->vsd_suspended || sc->vsd_generation != generation ||
	    memcmp(token, sc->vsd_fresh_gate_token, 16) != 0 ||
	    vm_get_identity(ctx, &vmid, &epoch) != 0 ||
	    vmid != sc->vsd_fresh_vmid || epoch != sc->vsd_fresh_epoch ||
	    (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0) {
		error = ESTALE;
		goto out;
	}
	if (hypertrace_session_host_released(ctx, token) != 0) {
		error = errno != 0 ? errno : EIO;
		goto out;
	}
	/* Use the channel's generation, not an independent device counter:
	 * newly received frames carry the value maintained by hypertrace.c. */
	sc->vsd_generation = hypertrace_reset();
	pci_vtdtr_reset_queue(sc);
	hypertrace_elf_reset(&sc->vsd_inbound_elf);
	sc->vsd_inbound_delivery_id = sc->vsd_inbound_epoch = 0;
	sc->vsd_inbound_vmid = 0;
	memset(sc->vsd_inbound_program_id, 0, 16);
	memset(sc->vsd_inbound_source_id, 0, 16);
	memset(sc->vsd_session_gate_token, 0, 16);
	sc->vsd_session_stop_requested = sc->vsd_session_stopped = false;
	sc->vsd_session_collectors_stopped = false;
	sc->vsd_fresh_released = true;
	sc->vsd_session_migration_staged = false;
	sc->vsd_session_migration_released = false;
	explicit_bzero(sc->vsd_session_migration_record,
	    sizeof(sc->vsd_session_migration_record));
	sc->vsd_guest_ready = sc->vsd_ready = 0;
	pci_vtdtr_notify_ready(sc);
	pthread_cond_broadcast(&sc->vsd_cond);
out:
	pthread_mutex_unlock(&sc->vsd_mtx);
	return (error);
}

static int
pci_vtdtr_session_stop_status_locked(struct pci_vtdtr_softc *sc)
{
	struct vmctx *ctx = sc->vsd_vmctx;
	struct timespec now;
	uint16_t vmid;
	uint64_t epoch;
	int error;

	if (!sc->vsd_session_stop_requested)
		error = ENOENT;
	else if (sc->vsd_stopping ||
	    (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		error = ENXIO;
	else if (vm_get_identity(ctx, &vmid, &epoch) != 0)
		error = errno != 0 ? errno : EIO;
	else if (vmid != sc->vsd_session_stop_vmid ||
	    epoch != sc->vsd_session_stop_epoch)
		error = ESTALE;
	else if (sc->vsd_session_stopped)
		error = hypertrace_session_host_stopped(ctx,
		    sc->vsd_session_gate_token) == 0 ? 0 :
		    (errno != 0 ? errno : EIO);
	else if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		error = errno;
	else if (now.tv_sec > sc->vsd_session_stop_deadline.tv_sec ||
	    (now.tv_sec == sc->vsd_session_stop_deadline.tv_sec &&
	    now.tv_nsec >= sc->vsd_session_stop_deadline.tv_nsec))
		error = ETIMEDOUT;
	else
		error = EBUSY;
	return (error);
}

int
pci_vtdtr_session_stop_status(struct vmctx *ctx)
{
	struct pci_vtdtr_softc *sc = vtdtr_shutdown_sc;
	int error;

	if (sc == NULL || ctx == NULL || sc->vsd_vmctx != ctx)
		return (ENXIO);
	pthread_mutex_lock(&sc->vsd_mtx);
	error = pci_vtdtr_session_stop_status_locked(sc);
	pthread_mutex_unlock(&sc->vsd_mtx);
	return (error);
}

/* The checkpoint coordinator owns device lifetime. Do not hold vsd_mtx
 * across a collector RPC: the guest/device must still be able to run. */
int
pci_vtdtr_session_collectors_stop_step(struct vmctx *ctx, bool *complete)
{
	struct pci_vtdtr_softc *sc = vtdtr_shutdown_sc;
	uint8_t token[16];
	uint16_t vmid;
	uint64_t epoch, guest_token;
	int error, step;

	if (complete == NULL)
		return (EINVAL);
	*complete = false;
	if (sc == NULL || ctx == NULL || sc->vsd_vmctx != ctx)
		return (ENXIO);
	pthread_mutex_lock(&sc->vsd_mtx);
	error = pci_vtdtr_session_stop_status_locked(sc);
	if (error == 0 && (sc->vsd_session_collectors_busy ||
	    sc->vsd_checkpoint_paused || sc->vsd_suspended || sc->vsd_fresh_requested))
		error = EBUSY;
	if (error != 0)
		goto out;
	if (sc->vsd_session_collectors_stopped) {
		*complete = true;
		goto out;
	}
	vmid = sc->vsd_session_stop_vmid;
	epoch = sc->vsd_session_stop_epoch;
	guest_token = sc->vsd_session_stop_token;
	memcpy(token, sc->vsd_session_gate_token, sizeof(token));
	sc->vsd_session_collectors_busy = true;
	pthread_mutex_unlock(&sc->vsd_mtx);
	step = hypertrace_session_collectors_stop_step(ctx, token);
	error = step < 0 ? (errno != 0 ? errno : EIO) : 0;
	pthread_mutex_lock(&sc->vsd_mtx);
	sc->vsd_session_collectors_busy = false;
	if (error == 0 && (sc->vsd_session_stop_vmid != vmid ||
	    sc->vsd_session_stop_epoch != epoch ||
	    sc->vsd_session_stop_token != guest_token ||
	    memcmp(token, sc->vsd_session_gate_token, sizeof(token)) != 0))
		error = ESTALE;
	if (error == 0)
		error = pci_vtdtr_session_stop_status_locked(sc);
	if (error == 0 && (sc->vsd_checkpoint_paused || sc->vsd_suspended ||
	    sc->vsd_fresh_requested))
		error = EBUSY;
	if (error == 0 && step > 1)
		error = EPROTO;
	if (error == 0 && step == 0)
		*complete = sc->vsd_session_collectors_stopped = true;
out:
	pthread_mutex_unlock(&sc->vsd_mtx);
	return (error);
}

static void
pci_vtdtr_node_id(struct pci_vtdtr_softc *sc, uint64_t query_id)
{
	struct pci_vtdtr_ctrl_entry *ctrl_entry;
	struct pci_vtdtr_control *ctrl;
	struct vmctx *ctx = sc->vsd_vmctx;

	ctrl_entry = malloc(sizeof(struct pci_vtdtr_ctrl_entry));
	if (ctrl_entry == NULL) {
		fprintf(stderr, "failed to malloc new ctrl entry\n");
		vi_set_needs_reset(&sc->vsd_vs);
		return;
	}
	memset(ctrl_entry, 0, sizeof(struct pci_vtdtr_ctrl_entry));

	ctrl = malloc(sizeof(struct pci_vtdtr_control));
	if (ctrl == NULL) {
		fprintf(stderr, "failed to malloc new control event\n");
		free(ctrl_entry);
		vi_set_needs_reset(&sc->vsd_vs);
		return;
	}

	memset(ctrl, 0, sizeof(struct pci_vtdtr_control));

	ctrl->pvc_event = VTDTR_DEVICE_NODE_ID;
	if (vm_get_identity(ctx, &ctrl->pvc_node_id,
	    &ctrl->pvc_node_epoch) != 0 || ctrl->pvc_node_id == 0 ||
	    ctrl->pvc_node_id >= HYPERTRACE_MAX_VMS ||
	    ctrl->pvc_node_epoch == 0) {
		free(ctrl);
		free(ctrl_entry);
		vi_set_needs_reset(&sc->vsd_vs);
		return;
	}
	ctrl->pvc_node_query_id = query_id;

	ctrl_entry->ctrl = ctrl;
	if (!pci_vtdtr_normal_control_room(sc->vsd_ctrlq)) {
		free(ctrl);
		free(ctrl_entry);
		vi_set_needs_reset(&sc->vsd_vs);
		return;
	}

	pci_vtdtr_cq_enqueue(sc->vsd_ctrlq, ctrl_entry);
	pthread_cond_signal(&sc->vsd_cond);
}

/* Validate the whole chain before copying any bytes into guest memory. */
static bool
pci_vtdtr_copy_control(struct iovec *iov, int niov, void *control, bool to_guest)
{
	size_t remaining = sizeof(struct pci_vtdtr_control), n;
	unsigned char *cursor = control;
	int i;

	if (niov <= 0 || niov > VTDTR_MAX_IOV)
		return (false);
	for (i = 0; i < niov; i++) {
		/* Guest-to-host controls have an exact wire length. A larger
		 * descriptor cannot hide bytes after the decoded record. */
		if (!to_guest && iov[i].iov_len > remaining)
			return (false);
		remaining -= MIN(remaining, iov[i].iov_len);
	}
	if (remaining != 0)
		return (false);
	remaining = sizeof(struct pci_vtdtr_control);
	for (i = 0; i < niov && remaining != 0; i++) {
		n = MIN(remaining, iov[i].iov_len);
		if (n == 0)
			continue;
		if (to_guest)
			memcpy(iov[i].iov_base, cursor, n);
		else
			memcpy(cursor, iov[i].iov_base, n);
		cursor += n;
		remaining -= n;
	}
	return (true);
}

static bool
pci_vtdtr_deadline_expired(const struct timespec *deadline)
{
	struct timespec now;

	return (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
	    now.tv_sec > deadline->tv_sec ||
	    (now.tv_sec == deadline->tv_sec &&
	    now.tv_nsec >= deadline->tv_nsec));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
static bool
pci_vtdtr_rekey_expired(const struct pci_vtdtr_softc *sc)
{
	return (pci_vtdtr_deadline_expired(&sc->vsd_rekey_deadline));
}

static void
pci_vtdtr_rekey_quarantine(struct pci_vtdtr_softc *sc)
{
	vi_set_needs_reset(&sc->vsd_vs);
	pci_vtdtr_reset_queue(sc);
	sc->vsd_rekey_wait = false;
	sc->vsd_rekey_ack_pending = sc->vsd_rekey_ack_sent = false;
	sc->vsd_restored_kill_wait = false;
	sc->vsd_restored_kill_pid = 0;
	memset(sc->vsd_restored_kill_source_id, 0,
	    sizeof(sc->vsd_restored_kill_source_id));
	sc->vsd_restored_kill_deadline = (struct timespec){ 0 };
	pci_vtdtr_handoff_ticket_forget(sc);
	pthread_cond_broadcast(&sc->vsd_cond);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Reached only from
 * transfer-ticket replay (NODE_REKEY / restored KILLs), which restore
 * refuses, so this is intentionally unreachable until enabled. */
/* Read one exact source receipt through the coordinator's ticket. This is
 * deliberately separate from the ordinary STATUS path, which is bound to
 * the destination incarnation and cannot authorize an old journal record.
 * Caller owns vsd_mtx; no guest control can supply or replace the ticket. */
static int
pci_vtdtr_rekey_delivery_receipt(struct pci_vtdtr_softc *sc,
    uint8_t scope, uint64_t delivery_id, const uint8_t program_id[16],
    const uint8_t source_id[16], const uint8_t payload_digest[32],
    dtraced_delivery_status_t *status)
{
	const uint8_t zero16[16] = {}, zero32[32] = {};
	dtraced_handoff_delivery_request_t request = { 0 };
	uint16_t vmid;
	uint64_t epoch;

	if (sc == NULL || status == NULL || program_id == NULL ||
	    source_id == NULL || payload_digest == NULL ||
	    (scope != 0 && scope != 3) || delivery_id == 0 ||
	    memcmp(program_id, zero16, 16) == 0 ||
	    memcmp(source_id, zero16, 16) == 0 ||
	    memcmp(payload_digest, zero32, 32) == 0)
		return (EINVAL);
	memset(status, 0, sizeof(*status));
	if (sc->vsd_stopping || !sc->vsd_rekey_wait ||
	    !sc->vsd_handoff_ticket_valid || sc->vsd_rekey_ack_pending ||
	    sc->vsd_rekey_ack_sent ||
	    (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0 ||
	    pci_vtdtr_rekey_expired(sc) ||
	    vm_get_identity(sc->vsd_vmctx, &vmid, &epoch) != 0 ||
	    vmid != sc->vsd_rekey_new_id ||
	    epoch != sc->vsd_rekey_new_epoch)
		return (ESTALE);
	memcpy(request.token, sc->vsd_handoff_token, sizeof(request.token));
	memcpy(request.digest, sc->vsd_handoff_digest,
	    sizeof(request.digest));
	request.delivery_id = delivery_id;
	memcpy(request.program_id, program_id, 16);
	memcpy(request.source_id, source_id, 16);
	request.scope = scope;
	if (hypertrace_handoff_delivery_live(sc->vsd_vmctx, &request,
	    status) != 0)
		return (errno != 0 ? errno : EIO);
	bool terminal = scope == 0 && status->phase == 't';
	if (status->delivery_id != delivery_id || status->replay != 0 ||
	    (terminal ?
	    (status->revoked > 1 ||
	    memcmp(status->digest, zero32, 32) != 0) :
	    ((scope == 0 ? status->phase != 'a' &&
	    status->phase != 'i' : status->phase != 'a') ||
	    status->revoked != 0 ||
	    memcmp(status->digest, payload_digest, 32) != 0)))
		return (EPROTO);
	return (0);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Reached only from
 * transfer-ticket replay (NODE_REKEY / restored KILLs), which restore
 * refuses, so this is intentionally unreachable until enabled. */
static int
pci_vtdtr_rekey_kill_receipt(struct pci_vtdtr_softc *sc, pid_t pid,
    const uint8_t source_id[16], dtraced_delivery_status_t *status)
{
	const uint8_t zero16[16] = {}, zero32[32] = {};
	dtraced_handoff_kill_request_t request = { 0 };
	uint16_t vmid;
	uint64_t epoch;

	if (sc == NULL || status == NULL || source_id == NULL || pid <= 1 ||
	    memcmp(source_id, zero16, 16) == 0)
		return (EINVAL);
	memset(status, 0, sizeof(*status));
	if (sc->vsd_stopping || !sc->vsd_rekey_wait ||
	    !sc->vsd_handoff_ticket_valid || sc->vsd_rekey_ack_pending ||
	    sc->vsd_rekey_ack_sent ||
	    (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0 ||
	    pci_vtdtr_rekey_expired(sc) ||
	    vm_get_identity(sc->vsd_vmctx, &vmid, &epoch) != 0 ||
	    vmid != sc->vsd_rekey_new_id ||
	    epoch != sc->vsd_rekey_new_epoch)
		return (ESTALE);
	memcpy(request.token, sc->vsd_handoff_token, sizeof(request.token));
	memcpy(request.digest, sc->vsd_handoff_digest,
	    sizeof(request.digest));
	request.pid = pid;
	memcpy(request.source_id, source_id, 16);
	if (hypertrace_handoff_kill_live(sc->vsd_vmctx, &request,
	    status) != 0)
		return (errno != 0 ? errno : EIO);
	if (status->delivery_id != (uint32_t)pid ||
	    (status->phase != 'p' && status->phase != 'a') ||
	    status->revoked != 1 || status->replay != 0 ||
	    memcmp(status->digest, zero32, 32) != 0)
		return (EPROTO);
	return (0);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Reached only from
 * transfer-ticket replay (NODE_REKEY / restored KILLs), which restore
 * refuses, so this is intentionally unreachable until enabled. */
/* One receipt response may bypass the stopped ordinary control queue.
 * The response carries the queried old identity and a nonce, never the
 * coordinator's handoff ticket. Caller owns vsd_mtx. */
static int
pci_vtdtr_rekey_receipt_query_rx(struct pci_vtdtr_softc *sc,
    const struct pci_vtdtr_control *ctrl)
{
	const uint8_t zero16[16] = {}, zero32[32] = {};
	dtraced_delivery_status_t status = { 0 };
	struct pci_vtdtr_control *reply = &sc->vsd_rekey_receipt_reply;
	bool kill = ctrl->pvc_event == VTDTR_DEVICE_REKEY_KILL_QUERY;
	uint8_t scope = ctrl->pvc_event ==
	    VTDTR_DEVICE_REKEY_INGRESS_QUERY ? 3 : 0;
	int error;

	if (!sc->vsd_rekey_wait || !sc->vsd_handoff_ticket_valid ||
	    (sc->vsd_vs.vs_negotiated_caps &
	    VTDTR_WIRE_F_REKEY_RECEIPT_V1) == 0 ||
	    sc->vsd_rekey_receipt_reply_pending ||
	    sc->vsd_rekey_ack_pending || sc->vsd_rekey_ack_sent ||
	    ctrl->pvc_installed_vmid != sc->vsd_rekey_old_id ||
	    ctrl->pvc_installed_epoch != sc->vsd_rekey_old_epoch ||
	    ctrl->pvc_installed_query_id == 0 ||
	    ctrl->pvc_installed_delivery_id == 0 ||
	    ctrl->pvc_installed_phase != 0 ||
	    ctrl->pvc_installed_revoked != 0 ||
	    ctrl->pvc_installed_replay != 0 ||
	    memcmp(ctrl->pvc_installed_source_id, zero16, 16) == 0 ||
	    (kill ?
	    (ctrl->pvc_installed_delivery_id <= 1 ||
	    ctrl->pvc_installed_delivery_id > INT32_MAX ||
	    memcmp(ctrl->pvc_installed_program_id, zero16, 16) != 0 ||
	    memcmp(ctrl->pvc_installed_digest, zero32, 32) != 0) :
	    (memcmp(ctrl->pvc_installed_program_id, zero16, 16) == 0 ||
	    memcmp(ctrl->pvc_installed_digest, zero32, 32) == 0)))
		return (EPROTO);
	if (kill)
		error = pci_vtdtr_rekey_kill_receipt(sc,
		    (pid_t)ctrl->pvc_installed_delivery_id,
		    ctrl->pvc_installed_source_id, &status);
	else
		error = pci_vtdtr_rekey_delivery_receipt(sc, scope,
		    ctrl->pvc_installed_delivery_id,
		    ctrl->pvc_installed_program_id,
		    ctrl->pvc_installed_source_id,
		    ctrl->pvc_installed_digest, &status);
	if (pci_vtdtr_rekey_expired(sc))
		return (ETIMEDOUT);
	if (error != 0 && error != ENOTCONN && error != ECONNRESET &&
	    error != EPIPE && error != ETIMEDOUT && error != EIO)
		return (error);
	memset(reply, 0, sizeof(*reply));
	reply->pvc_event = kill ? VTDTR_DEVICE_REKEY_KILL_RECEIPT :
	    scope == 3 ? VTDTR_DEVICE_REKEY_INGRESS_RECEIPT :
	    VTDTR_DEVICE_REKEY_DELIVERY_RECEIPT;
	reply->pvc_installed_delivery_id = ctrl->pvc_installed_delivery_id;
	reply->pvc_installed_vmid = sc->vsd_rekey_old_id;
	reply->pvc_installed_epoch = sc->vsd_rekey_old_epoch;
	reply->pvc_installed_query_id = ctrl->pvc_installed_query_id;
	memcpy(reply->pvc_installed_program_id,
	    ctrl->pvc_installed_program_id, 16);
	memcpy(reply->pvc_installed_source_id,
	    ctrl->pvc_installed_source_id, 16);
	if (error == 0) {
		reply->pvc_installed_phase = status.phase;
		reply->pvc_installed_revoked = status.revoked;
		reply->pvc_installed_replay = status.replay;
		memcpy(reply->pvc_installed_digest, status.digest, 32);
	} else
		reply->pvc_installed_phase = 'u';
	sc->vsd_rekey_receipt_reply_pending = true;
	pthread_cond_signal(&sc->vsd_cond);
	return (0);
}

static int
pci_vtdtr_control_rx(struct pci_vtdtr_softc *sc, struct iovec *iov, int niov)
{
	struct pci_vtdtr_control message, *ctrl = &message;
	int retval;
	size_t len;
	unsigned char *elf;
	int complete, error;
	uint64_t size;
	char name[MAX_VMNAME];
	uint16_t vmid;
	uint64_t vmepoch;
	struct hypertrace_vm_envelope envelope = {
	    .magic = HYPERTRACE_ENVELOPE_MAGIC,
	    .version = HYPERTRACE_ENVELOPE_VERSION };
	static char inbound[DTRACED_LOCSIZE] = "inbound";
	size_t buflen, l;
	unsigned char *buf, *_buf;
	dtraced_hdr_t header;

	memset(&header, 0, sizeof(header));
	retval = 0;
	vmid = 0;
	buf = _buf = NULL;
	/* Shutdown closes guest admission before retiring the host session. */
	if (sc->vsd_stopping) {
		vi_set_needs_reset(&sc->vsd_vs);
		return (1);
	}
	/* A failed transport cannot accept another program before guest reset. */
	if (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET)
		return (1);
	/* Trace continuity (disabled future feature): rekey state comes only from transfer-ticket replay, which restore refuses. */
	if (sc->vsd_rekey_wait && pci_vtdtr_rekey_expired(sc)) {
		pci_vtdtr_rekey_quarantine(sc);
		return (1);
	}
	/* Trace continuity (disabled future feature): restored KILLs come only from transfer-ticket replay, which restore refuses. */
	if (sc->vsd_restored_kill_wait &&
	    pci_vtdtr_deadline_expired(&sc->vsd_restored_kill_deadline)) {
		pci_vtdtr_rekey_quarantine(sc);
		return (1);
	}

	if (!pci_vtdtr_copy_control(iov, niov, &message, false)) {
		if (sc->vsd_rekey_wait)
			pci_vtdtr_rekey_quarantine(sc);
		else
			vi_set_needs_reset(&sc->vsd_vs);
		return (1);
	}
	if (ctrl->pvc_event == VTDTR_DEVICE_SESSION_READY ||
	    ctrl->pvc_event == VTDTR_DEVICE_SESSION_ACTIVE) {
		const __typeof(ctrl->wire.uctrl.session_prepare) *reply =
		    &ctrl->wire.uctrl.session_prepare;
		if (!sc->vsd_fresh_requested || !sc->vsd_fresh_prepare_delivered ||
		    (!sc->vsd_fresh_active &&
		    pci_vtdtr_deadline_expired(&sc->vsd_fresh_deadline)) ||
		    vm_get_identity(sc->vsd_vmctx, &vmid, &vmepoch) != 0 ||
		    vmid != sc->vsd_fresh_vmid || vmepoch != sc->vsd_fresh_epoch ||
		    reply->reserved != 0 || reply->stop_token != sc->vsd_session_stop_token ||
		    reply->old_id != sc->vsd_session_stop_vmid ||
		    reply->old_epoch != sc->vsd_session_stop_epoch ||
		    reply->new_id != vmid || reply->new_epoch != vmepoch ||
		    (ctrl->pvc_event == VTDTR_DEVICE_SESSION_ACTIVE &&
		    !sc->vsd_fresh_commit_delivered)) {
			vi_set_needs_reset(&sc->vsd_vs);
			return (1);
		}
		if (ctrl->pvc_event == VTDTR_DEVICE_SESSION_ACTIVE) {
			/* The coordinator still owns host admission. This proof alone
			 * must not release old collector deliveries into the new VM. */
			sc->vsd_fresh_active = true;
		} else if (!sc->vsd_fresh_commit_queued) {
			struct pci_vtdtr_ctrl_entry *entry = calloc(1, sizeof(*entry));
			struct pci_vtdtr_control *commit = calloc(1, sizeof(*commit));
			if (entry == NULL || commit == NULL) {
				free(entry);
				free(commit);
				vi_set_needs_reset(&sc->vsd_vs);
				return (1);
			}
			commit->pvc_event = VTDTR_DEVICE_SESSION_COMMIT;
			commit->wire.uctrl.session_prepare = *reply;
			entry->ctrl = commit;
			pci_vtdtr_cq_enqueue(sc->vsd_ctrlq, entry);
			sc->vsd_fresh_commit_queued = true;
			sc->vsd_guest_ready = 1;
		}
		sc->vsd_ready = 0;
		pthread_cond_broadcast(&sc->vsd_cond);
		return (0);
	}
	if (ctrl->pvc_event == VTDTR_DEVICE_SESSION_STOPPED) {
		if (sc->vsd_fresh_requested &&
		    ctrl->pvc_cleanup_vmid == sc->vsd_session_stop_vmid &&
		    ctrl->pvc_cleanup_epoch == sc->vsd_session_stop_epoch &&
		    ctrl->pvc_cleanup_delivery_id == sc->vsd_session_stop_token) {
			sc->vsd_ready = 0;
			return (0);
		}
		if (!sc->vsd_session_stop_requested ||
		    !sc->vsd_session_stop_delivered ||
		    vm_get_identity(sc->vsd_vmctx, &vmid, &vmepoch) != 0 ||
		    vmid != sc->vsd_session_stop_vmid ||
		    vmepoch != sc->vsd_session_stop_epoch ||
		    ctrl->pvc_cleanup_vmid != vmid ||
		    ctrl->pvc_cleanup_epoch != vmepoch ||
		    ctrl->pvc_cleanup_delivery_id != sc->vsd_session_stop_token) {
			vi_set_needs_reset(&sc->vsd_vs);
			return (1);
		}
		sc->vsd_session_stopped = true;
		sc->vsd_guest_ready = sc->vsd_ready = 0;
		pthread_cond_broadcast(&sc->vsd_cond);
		return (0);
	}
	/* Stop discards old session work. READY is needed to deliver STOP,
	 * but cannot reopen ordinary delivery after the request is published. */
	if (sc->vsd_session_stop_requested &&
	    ctrl->pvc_event != VTDTR_DEVICE_READY) {
		/* An old batch consumed the guest's outbound credit. Regrant
		 * credit for STOPPED even though its payload is discarded. */
		sc->vsd_ready = 0;
		return (ctrl->pvc_event == VTDTR_DEVICE_EOF ? 1 : 0);
	}
	/* Trace continuity (disabled future feature): rekey state comes only from transfer-ticket replay, which restore refuses. */
	if (sc->vsd_rekey_wait &&
	    (ctrl->pvc_event == VTDTR_DEVICE_REKEY_DELIVERY_QUERY ||
	    ctrl->pvc_event == VTDTR_DEVICE_REKEY_INGRESS_QUERY ||
	    ctrl->pvc_event == VTDTR_DEVICE_REKEY_KILL_QUERY)) {
		if (pci_vtdtr_rekey_receipt_query_rx(sc, ctrl) != 0) {
			pci_vtdtr_rekey_quarantine(sc);
			return (1);
		}
		return (0);
	}
	/* A rekey commit is accepted only for the transition actually delivered
	 * to this VM. It cannot overtake saved controls or forge a new epoch. */
	/* Trace continuity (disabled future feature): rekey state comes only from transfer-ticket replay, which restore refuses. */
	if (sc->vsd_rekey_wait &&
	    ctrl->pvc_event == VTDTR_DEVICE_REKEY_COMMIT) {
		if (!sc->vsd_handoff_ticket_valid ||
		    sc->vsd_rekey_receipt_reply_pending ||
		    vm_get_identity(sc->vsd_vmctx, &vmid, &vmepoch) != 0 ||
		    ctrl->pvc_rekey_old_id != sc->vsd_rekey_old_id ||
		    ctrl->pvc_rekey_old_epoch != sc->vsd_rekey_old_epoch ||
		    ctrl->pvc_rekey_new_id != sc->vsd_rekey_new_id ||
		    ctrl->pvc_rekey_new_epoch != sc->vsd_rekey_new_epoch ||
		    vmid != sc->vsd_rekey_new_id ||
		    vmepoch != sc->vsd_rekey_new_epoch) {
			pci_vtdtr_rekey_quarantine(sc);
			return (1);
		}
		if (!sc->vsd_rekey_ack_sent) {
			sc->vsd_rekey_ack_pending = true;
			pthread_cond_signal(&sc->vsd_cond);
		}
		return (0);
	}
	/* Trace continuity (disabled future feature): rekey state comes only from transfer-ticket replay, which restore refuses. */
	if (sc->vsd_rekey_wait &&
	    ctrl->pvc_event == VTDTR_DEVICE_REKEY_APPLIED) {
		if (!sc->vsd_handoff_ticket_valid ||
		    !sc->vsd_rekey_ack_sent ||
		    vm_get_identity(sc->vsd_vmctx, &vmid, &vmepoch) != 0 ||
		    ctrl->pvc_rekey_old_id != sc->vsd_rekey_old_id ||
		    ctrl->pvc_rekey_old_epoch != sc->vsd_rekey_old_epoch ||
		    ctrl->pvc_rekey_new_id != sc->vsd_rekey_new_id ||
		    ctrl->pvc_rekey_new_epoch != sc->vsd_rekey_new_epoch ||
		    vmid != sc->vsd_rekey_new_id ||
		    vmepoch != sc->vsd_rekey_new_epoch) {
			pci_vtdtr_rekey_quarantine(sc);
			return (1);
		}
		/* Do not forget the attested ticket or release READY until the
		 * daemon durably records this exact guest rekey and activates the
		 * committed import. A lost ACK is an idempotent retry; an
		 * unresolved failure quarantines the device. */
		if (hypertrace_handoff_rekey_applied(sc->vsd_vmctx,
		    sc->vsd_handoff_token, sc->vsd_handoff_digest) != 0 ||
		    pci_vtdtr_rekey_expired(sc)) {
			pci_vtdtr_rekey_quarantine(sc);
			return (1);
		}
		sc->vsd_rekey_wait = false;
		sc->vsd_guest_ready = 1;
		pci_vtdtr_handoff_ticket_forget(sc);
		/* The guest has closed its old host-ready gate. Send a fresh
		 * READY for outbound traffic under the new incarnation. */
		sc->vsd_ready = 0;
		pci_vtdtr_notify_ready(sc);
		pthread_cond_signal(&sc->vsd_cond);
		return (0);
	}
	/* No ordinary guest-to-host control may cross the transition. */
	/* Trace continuity (disabled future feature): rekey state comes only from transfer-ticket replay, which restore refuses. */
	if (sc->vsd_rekey_wait && ctrl->pvc_event != VTDTR_DEVICE_READY) {
		pci_vtdtr_rekey_quarantine(sc);
		return (1);
	}
	switch (ctrl->pvc_event) {
	case VTDTR_DEVICE_READY:
		if (!sc->vsd_rekey_wait) {
			sc->vsd_rekey_wait = false;
			sc->vsd_guest_ready = 1;
			pthread_cond_signal(&sc->vsd_cond);
		}
		break;

	case VTDTR_DEVICE_ELF:
		sc->vsd_ready = 0;
		const uint8_t zero_id[16] = { 0 };
		uint64_t current_epoch = 0;
		if (ctrl->pvc_delivery_id == 0 ||
		    memcmp(ctrl->pvc_program_id, zero_id, 16) == 0 ||
		    memcmp(ctrl->pvc_elf_source_id, zero_id, 16) == 0 ||
		    vm_get_identity(sc->vsd_vmctx, &vmid,
		    &current_epoch) != 0 ||
		    ctrl->pvc_vmid != vmid ||
		    ctrl->pvc_epoch != current_epoch) {
			hypertrace_elf_reset(&sc->vsd_inbound_elf);
			vi_set_needs_reset(&sc->vsd_vs);
			return (1);
		}
		if (sc->vsd_inbound_elf.data == NULL) {
			sc->vsd_inbound_delivery_id = ctrl->pvc_delivery_id;
			sc->vsd_inbound_vmid = ctrl->pvc_vmid;
			sc->vsd_inbound_epoch = ctrl->pvc_epoch;
			memcpy(sc->vsd_inbound_program_id, ctrl->pvc_program_id, 16);
			memcpy(sc->vsd_inbound_source_id,
			    ctrl->pvc_elf_source_id, 16);
		} else if (sc->vsd_inbound_delivery_id != ctrl->pvc_delivery_id ||
		    sc->vsd_inbound_vmid != ctrl->pvc_vmid ||
		    sc->vsd_inbound_epoch != ctrl->pvc_epoch ||
		    memcmp(sc->vsd_inbound_program_id,
		    ctrl->pvc_program_id, 16) != 0 ||
		    memcmp(sc->vsd_inbound_source_id,
		    ctrl->pvc_elf_source_id, 16) != 0) {
			hypertrace_elf_reset(&sc->vsd_inbound_elf);
			vi_set_needs_reset(&sc->vsd_vs);
			return (1);
		}
		if (ctrl->pvc_elflen > sizeof(ctrl->pvc_elf)) {
			hypertrace_elf_reset(&sc->vsd_inbound_elf);
			vi_set_needs_reset(&sc->vsd_vs);
			return (1);
		}
		error = hypertrace_elf_append(&sc->vsd_inbound_elf,
		    ctrl->pvc_identifier, ctrl->pvc_totalelflen,
		    ctrl->pvc_elf, ctrl->pvc_elflen, ctrl->pvc_elfhasmore,
		    &complete);
		if (error != 0) {
			vi_set_needs_reset(&sc->vsd_vs);
			return (1);
		}
		if (complete) {
			len = sc->vsd_inbound_elf.total;
			elf = sc->vsd_inbound_elf.data;
			if (len < 4 || memcmp(elf, "\177ELF", 4) != 0) {
				hypertrace_elf_reset(&sc->vsd_inbound_elf);
				vi_set_needs_reset(&sc->vsd_vs);
				return (1);
			}
			if (vm_get_identity(sc->vsd_vmctx, &vmid,
			    &envelope.epoch) != 0 ||
			    vmid != sc->vsd_inbound_vmid ||
			    envelope.epoch != sc->vsd_inbound_epoch) {
				hypertrace_elf_reset(&sc->vsd_inbound_elf);
				vi_set_needs_reset(&sc->vsd_vs);
				return (1);
			}
			envelope.vmid = vmid;

			l = strlcpy(name, vm_get_name(sc->vsd_vmctx), MAX_VMNAME);
			if (l >= MAX_VMNAME) {
				fprintf(stderr,
				    "failed to strlcpy: strlen(%s) >= %zu\n",
				    vm_get_name(sc->vsd_vmctx), MAX_VMNAME);
				hypertrace_elf_reset(&sc->vsd_inbound_elf);
				vi_set_needs_reset(&sc->vsd_vs);
				return (1);
			}
			size = strlen(name);
			envelope.name_length = size;

			DTRACED_MSG_TYPE(header) = DTRACED_MSG_ELF;
			header.elf.delivery_id = sc->vsd_inbound_delivery_id;
			memcpy(header.elf.program_id, sc->vsd_inbound_program_id, 16);
			memcpy(header.elf.source_id, sc->vsd_inbound_source_id, 16);
			memcpy(DTRACED_MSG_LOC(header), inbound,
			    DTRACED_LOCSIZE);

			buflen = HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + size + len;

			DTRACED_MSG_LEN(header) = buflen;
			assert(buflen > len);

			buf = malloc(buflen);
			if (buf == NULL) {
				fprintf(stderr, "malloc() failed with: %s\n",
				    strerror(errno));
				hypertrace_elf_reset(&sc->vsd_inbound_elf);
				vi_set_needs_reset(&sc->vsd_vs);
				return (1);
			}

			_buf = buf;
			hypertrace_envelope_encode(_buf, &envelope);
			_buf += HYPERTRACE_VM_ENVELOPE_WIRE_SIZE;

			assert((_buf + size) < (buf + buflen));

			memcpy(_buf, name, size);
			_buf += size;

			assert(_buf > buf);
			assert((_buf + len) == (buf + buflen));

			memcpy(_buf, elf, len);

			if (hypertrace_write(&header, buf, buflen) == -1) {
				fprintf(stderr,
				    "hypertrace_write() failed: %s\n",
				    strerror(errno));
				free(buf);
				hypertrace_elf_reset(&sc->vsd_inbound_elf);
				vi_set_needs_reset(&sc->vsd_vs);
				return (1);
			}
			/* The write ACK proves a durable upload, but the exact
			 * acceptance receipt must identify these ELF bytes before the
			 * guest sender is released. */
			uint8_t elf_digest[SHA256_DIGEST_LENGTH];
			dtraced_hdr_t receipt_query = { 0 };
			dtraced_delivery_status_t accepted = { 0 };
			if (SHA256(elf, len, elf_digest) == NULL) {
				free(buf);
				hypertrace_elf_reset(&sc->vsd_inbound_elf);
				vi_set_needs_reset(&sc->vsd_vs);
				return (1);
			}
			receipt_query.msg_type = DTRACED_MSG_INGRESS_STATUS;
			receipt_query.installed.delivery_id =
			    sc->vsd_inbound_delivery_id;
			receipt_query.installed.vmid = vmid;
			receipt_query.installed.epoch = envelope.epoch;
			memcpy(receipt_query.installed.program_id,
			    sc->vsd_inbound_program_id, 16);
			memcpy(receipt_query.installed.source_id,
			    sc->vsd_inbound_source_id, 16);
			if (strlcpy(receipt_query.installed.name, name,
			    sizeof(receipt_query.installed.name)) >=
			    sizeof(receipt_query.installed.name) ||
			    hypertrace_ingress_status(&receipt_query, &accepted) != 0 ||
			    accepted.delivery_id != sc->vsd_inbound_delivery_id ||
			    accepted.phase != 'a' || accepted.revoked != 0 ||
			    accepted.replay != 0 ||
			    memcmp(accepted.digest, elf_digest,
			    sizeof(elf_digest)) != 0) {
				free(buf);
				hypertrace_elf_reset(&sc->vsd_inbound_elf);
				vi_set_needs_reset(&sc->vsd_vs);
				return (1);
			}
			/* The daemon has acknowledged the durable inbound spool write.
			 * Report that result to the guest before it releases its sender. */
			if (!pci_vtdtr_normal_control_room(sc->vsd_ctrlq)) {
				free(buf);
				hypertrace_elf_reset(&sc->vsd_inbound_elf);
				vi_set_needs_reset(&sc->vsd_vs);
				return (1);
			}
			struct pci_vtdtr_ctrl_entry *elf_receipt =
			    calloc(1, sizeof(*elf_receipt));
			struct pci_vtdtr_control *elf_reply =
			    calloc(1, sizeof(*elf_reply));
			if (elf_receipt == NULL || elf_reply == NULL) {
				free(elf_receipt);
				free(elf_reply);
				free(buf);
				hypertrace_elf_reset(&sc->vsd_inbound_elf);
				vi_set_needs_reset(&sc->vsd_vs);
				return (1);
			}
			elf_reply->pvc_event = VTDTR_DEVICE_HOST_ELF;
			elf_reply->pvc_installed_delivery_id =
			    sc->vsd_inbound_delivery_id;
			elf_reply->pvc_installed_vmid = vmid;
			elf_reply->pvc_installed_epoch = envelope.epoch;
			memcpy(elf_reply->pvc_installed_program_id,
			    sc->vsd_inbound_program_id, 16);
			memcpy(elf_reply->pvc_installed_source_id,
			    sc->vsd_inbound_source_id, 16);
			memcpy(elf_reply->pvc_installed_digest, elf_digest,
			    sizeof(elf_digest));
			elf_receipt->ctrl = elf_reply;
			pci_vtdtr_cq_enqueue(sc->vsd_ctrlq, elf_receipt);
			pthread_cond_signal(&sc->vsd_cond);

			free(buf);
			hypertrace_elf_reset(&sc->vsd_inbound_elf);
			sc->vsd_inbound_delivery_id = 0;
			sc->vsd_inbound_vmid = 0;
			sc->vsd_inbound_epoch = 0;
			memset(sc->vsd_inbound_program_id, 0, 16);
			memset(sc->vsd_inbound_source_id, 0, 16);
		}
		break;

	case VTDTR_DEVICE_EOF:
		retval = 1;
		break;

	case VTDTR_DEVICE_KILL:
		WPRINTF(("Warning: VTDTR_DEVICE_KILL received on the host "
			 "for pid %d\n",
		    ctrl->pvc_pid));
		vi_set_needs_reset(&sc->vsd_vs);
		return (1);

	case VTDTR_DEVICE_KILL_APPLIED:
		/* The guest closed its host-ready gate for this batch; every
		 * consumed non-READY control must regrant it (see notify_rx). */
		sc->vsd_ready = 0;
		{
			const uint8_t zero_source[16] = { 0 };
			if (ctrl->pvc_pid <= 1 ||
			    memcmp(ctrl->pvc_source_id, zero_source, 16) == 0 ||
			    vm_get_identity(sc->vsd_vmctx, &vmid,
			    &envelope.epoch) != 0 ||
			    ctrl->pvc_kill_vmid != vmid ||
			    ctrl->pvc_kill_epoch != envelope.epoch ||
			    vmid == 0 || vmid >= HYPERTRACE_MAX_VMS ||
			    envelope.epoch == 0) {
				vi_set_needs_reset(&sc->vsd_vs);
				return (1);
			}
			/* Trace continuity (disabled future feature): restored KILLs come only from transfer-ticket replay, which restore refuses. */
			if (sc->vsd_restored_kill_wait &&
			    (ctrl->pvc_pid != sc->vsd_restored_kill_pid ||
			    memcmp(ctrl->pvc_source_id,
			    sc->vsd_restored_kill_source_id, 16) != 0)) {
				pci_vtdtr_rekey_quarantine(sc);
				return (1);
			}
			header.msg_type = DTRACED_MSG_KILL_APPLIED;
			header.kill.pid = ctrl->pvc_pid;
			header.kill.vmid = vmid;
			header.kill.epoch = envelope.epoch;
			memcpy(header.kill.source_id, ctrl->pvc_source_id, 16);
			if (hypertrace_write(&header, NULL, 0) != 0) {
				/* The guest's durable pending KILL retries after a lost
				 * control socket. A daemon rejection is not retryable. */
				if (errno == ENOTCONN || errno == ECONNRESET ||
				    errno == EPIPE || errno == ETIMEDOUT || errno == EIO)
					break;
				vi_set_needs_reset(&sc->vsd_vs);
				return (1);
			}
			/* The host has persisted the observation. If its receipt cannot
			 * be queued, the guest repeats the exact idempotent report. */
			if (!pci_vtdtr_normal_control_room(sc->vsd_ctrlq))
				break;
			struct pci_vtdtr_ctrl_entry *receipt =
			    calloc(1, sizeof(*receipt));
			struct pci_vtdtr_control *reply = malloc(sizeof(*reply));
			if (receipt == NULL || reply == NULL) {
				free(receipt);
				free(reply);
				break;
			}
			memset(reply, 0, sizeof(*reply));
			reply->pvc_event = VTDTR_DEVICE_HOST_KILL_APPLIED;
			reply->pvc_pid = ctrl->pvc_pid;
			reply->pvc_kill_vmid = vmid;
			reply->pvc_kill_epoch = envelope.epoch;
			memcpy(reply->pvc_source_id, ctrl->pvc_source_id, 16);
			receipt->ctrl = reply;
			pci_vtdtr_cq_enqueue(sc->vsd_ctrlq, receipt);
			if (sc->vsd_restored_kill_wait) {
				sc->vsd_restored_kill_wait = false;
				sc->vsd_restored_kill_pid = 0;
				memset(sc->vsd_restored_kill_source_id, 0,
				    sizeof(sc->vsd_restored_kill_source_id));
				sc->vsd_restored_kill_deadline =
				    (struct timespec){ 0 };
				sc->vsd_guest_ready = 1;
				/* READY was held while inherited revocations were
				 * pending. It can now be retried if this was the last. */
				pci_vtdtr_notify_ready(sc);
			}
			pthread_cond_signal(&sc->vsd_cond);
		}
		break;

	case VTDTR_DEVICE_CLEANUP_APPLIED:
		sc->vsd_ready = 0;
		/* A queued retry can arrive after a later cleanup has started. */
		if (ctrl->pvc_cleanup_delivery_id != 0 &&
		    ctrl->pvc_cleanup_delivery_id ==
		    sc->vsd_cleanup_previous_delivery_id &&
		    vm_get_identity(sc->vsd_vmctx, &vmid, &vmepoch) == 0 &&
		    vmid == ctrl->pvc_cleanup_vmid &&
		    vmepoch == ctrl->pvc_cleanup_epoch)
			break;
		if (ctrl->pvc_cleanup_delivery_id == 0 ||
		    ctrl->pvc_cleanup_delivery_id !=
		    sc->vsd_cleanup_delivery_id ||
		    vm_get_identity(sc->vsd_vmctx, &vmid, &vmepoch) != 0 ||
		    vmid != ctrl->pvc_cleanup_vmid ||
		    vmepoch != ctrl->pvc_cleanup_epoch) {
			vi_set_needs_reset(&sc->vsd_vs);
			return (1);
		}
		header.msg_type = DTRACED_MSG_CLEANUP_APPLIED;
		header.cleanup.vmid = vmid;
		header.cleanup.epoch = vmepoch;
		DTRACED_MSG_CLEANUP_DELIVERY_ID(header) =
		    ctrl->pvc_cleanup_delivery_id;
		if (hypertrace_write(&header, NULL, 0) != 0) {
			if (errno == ENOTCONN || errno == ECONNRESET ||
			    errno == EPIPE || errno == ETIMEDOUT || errno == EIO)
				break; /* guest retries the exact report */
			vi_set_needs_reset(&sc->vsd_vs);
			return (1);
		}
		/* Keep the queue fenced until the matching host receipt itself
		 * is queued. An allocation failure must not expose a later cleanup
		 * to the guest before the first receipt. */
		if (pci_vtdtr_normal_control_room(sc->vsd_ctrlq)) {
			struct pci_vtdtr_ctrl_entry *receipt =
			    calloc(1, sizeof(*receipt));
			struct pci_vtdtr_control *reply = calloc(1,
			    sizeof(*reply));
			if (receipt != NULL && reply != NULL) {
				reply->pvc_event =
				    VTDTR_DEVICE_HOST_CLEANUP_APPLIED;
				reply->pvc_cleanup_vmid = vmid;
				reply->pvc_cleanup_epoch = vmepoch;
				reply->pvc_cleanup_delivery_id =
				    ctrl->pvc_cleanup_delivery_id;
				receipt->ctrl = reply;
				pci_vtdtr_cq_enqueue_front(sc->vsd_ctrlq, receipt);
				sc->vsd_cleanup_unapplied = false;
				pthread_cond_signal(&sc->vsd_cond);
			} else {
				free(receipt);
				free(reply);
			}
		}
		break;

	case VTDTR_DEVICE_INSTALLED:
	case VTDTR_DEVICE_UNINSTALLED:
	case VTDTR_DEVICE_STATUS:
	case VTDTR_DEVICE_INGRESS_STATUS:
		/* Observations and queries consume the guest's TX credit. */
		sc->vsd_ready = 0;
		{
			dtraced_delivery_status_t query_status = { 0 };
			const uint8_t zero_installed_id[16] = { 0 };
			if (memcmp(ctrl->pvc_installed_program_id,
			    zero_installed_id, 16) == 0 ||
			    memcmp(ctrl->pvc_installed_source_id,
			    zero_installed_id, 16) == 0 ||
			    ctrl->pvc_installed_delivery_id == 0 ||
			    (ctrl->pvc_event == VTDTR_DEVICE_INGRESS_STATUS ?
			    (ctrl->pvc_installed_vmid != 0 ||
			    ctrl->pvc_installed_epoch != 0) :
			    (ctrl->pvc_installed_vmid == 0 ||
			    ctrl->pvc_installed_vmid >= HYPERTRACE_MAX_VMS ||
			    ctrl->pvc_installed_epoch == 0)) ||
			    ctrl->pvc_installed_phase != 0 ||
			    ctrl->pvc_installed_revoked != 0 ||
			    ctrl->pvc_installed_replay != 0 ||
			    memcmp(ctrl->pvc_installed_digest,
			    (const uint8_t[32]){0}, 32) != 0 ||
			    (ctrl->pvc_event == VTDTR_DEVICE_STATUS ||
			    ctrl->pvc_event == VTDTR_DEVICE_INGRESS_STATUS ?
			    ctrl->pvc_installed_query_id == 0 :
			    ctrl->pvc_installed_query_id != 0) ||
			    vm_get_identity(sc->vsd_vmctx, &vmid,
			    &envelope.epoch) != 0 || vmid == 0 ||
			    vmid >= HYPERTRACE_MAX_VMS ||
			    envelope.epoch == 0 ||
			    (ctrl->pvc_event != VTDTR_DEVICE_INGRESS_STATUS &&
			    (ctrl->pvc_installed_vmid != vmid ||
			    ctrl->pvc_installed_epoch != envelope.epoch))) {
				vi_set_needs_reset(&sc->vsd_vs);
				return (1);
			}
			header.msg_type = ctrl->pvc_event ==
			    VTDTR_DEVICE_INSTALLED ? DTRACED_MSG_INSTALLED :
			    ctrl->pvc_event == VTDTR_DEVICE_UNINSTALLED ?
			    DTRACED_MSG_UNINSTALLED :
			    ctrl->pvc_event == VTDTR_DEVICE_STATUS ?
			    DTRACED_MSG_STATUS : DTRACED_MSG_INGRESS_STATUS;
			header.installed.delivery_id =
			    ctrl->pvc_installed_delivery_id;
			/* The guest does not know its host-assigned epoch. Bind an
			 * ingress query to the attested VM identity here. */
			header.installed.vmid = vmid;
			header.installed.epoch = envelope.epoch;
			memcpy(header.installed.program_id,
			    ctrl->pvc_installed_program_id, 16);
			memcpy(header.installed.source_id,
			    ctrl->pvc_installed_source_id, 16);
			if (strlcpy(header.installed.name,
			    vm_get_name(sc->vsd_vmctx),
			    sizeof(header.installed.name)) >=
			    sizeof(header.installed.name)) {
				vi_set_needs_reset(&sc->vsd_vs);
				return (1);
			}
			if (ctrl->pvc_event == VTDTR_DEVICE_STATUS ||
			    ctrl->pvc_event == VTDTR_DEVICE_INGRESS_STATUS) {
				int result = ctrl->pvc_event ==
				    VTDTR_DEVICE_STATUS ?
				    hypertrace_delivery_status(&header,
				    &query_status) :
				    hypertrace_ingress_status(&header,
				    &query_status);
				if (result != 0) {
					/* Only transport loss is retryable. A protocol
					 * rejection must still reset the device. */
					if (errno != ENOTCONN && errno != ECONNRESET &&
					    errno != EPIPE && errno != ETIMEDOUT &&
					    errno != EIO) {
						vi_set_needs_reset(&sc->vsd_vs);
						return (1);
					}
					query_status.delivery_id =
					    ctrl->pvc_installed_delivery_id;
					query_status.phase = 'u';
				}
			} else if (hypertrace_write(&header, NULL, 0) != 0) {
				vi_set_needs_reset(&sc->vsd_vs);
				return (1);
			}
			/* The host response is an observation, not a durable replay grant. */
			if (!pci_vtdtr_normal_control_room(sc->vsd_ctrlq)) {
				vi_set_needs_reset(&sc->vsd_vs);
				return (1);
			}
			struct pci_vtdtr_ctrl_entry *receipt =
			    calloc(1, sizeof(*receipt));
			struct pci_vtdtr_control *reply = malloc(sizeof(*reply));
			if (receipt == NULL || reply == NULL) {
				free(receipt);
				free(reply);
				vi_set_needs_reset(&sc->vsd_vs);
				return (1);
			}
			memset(reply, 0, sizeof(*reply));
			reply->pvc_event = ctrl->pvc_event ==
			    VTDTR_DEVICE_INSTALLED ? VTDTR_DEVICE_HOST_INSTALLED :
			    ctrl->pvc_event == VTDTR_DEVICE_UNINSTALLED ?
			    VTDTR_DEVICE_HOST_UNINSTALLED :
			    ctrl->pvc_event == VTDTR_DEVICE_STATUS ?
			    VTDTR_DEVICE_HOST_STATUS :
			    VTDTR_DEVICE_HOST_INGRESS_STATUS;
			reply->pvc_installed_delivery_id =
			    ctrl->pvc_installed_delivery_id;
			reply->pvc_installed_vmid = vmid;
			reply->pvc_installed_epoch = envelope.epoch;
			reply->pvc_installed_query_id =
			    ctrl->pvc_installed_query_id;
			memcpy(reply->pvc_installed_program_id,
			    ctrl->pvc_installed_program_id, 16);
			memcpy(reply->pvc_installed_source_id,
			    ctrl->pvc_installed_source_id, 16);
			if (ctrl->pvc_event == VTDTR_DEVICE_STATUS ||
			    ctrl->pvc_event == VTDTR_DEVICE_INGRESS_STATUS) {
				reply->pvc_installed_phase = query_status.phase;
				reply->pvc_installed_revoked = query_status.revoked;
				reply->pvc_installed_replay = query_status.replay;
				memcpy(reply->pvc_installed_digest,
				    query_status.digest, 32);
			}
			receipt->ctrl = reply;
			pci_vtdtr_cq_enqueue(sc->vsd_ctrlq, receipt);
			pthread_cond_signal(&sc->vsd_cond);
		}
		break;

	case VTDTR_DEVICE_NODE_ID:
		if (ctrl->pvc_node_id != 0 || ctrl->pvc_node_epoch != 0) {
			vi_set_needs_reset(&sc->vsd_vs);
			return (1);
		}
		/* A DTT_VM_IDENTITY_QUERY batch also closed the guest's
		 * host-ready gate; without READY its next control never leaves. */
		sc->vsd_ready = 0;
		retval = 0;
		pci_vtdtr_node_id(sc, ctrl->pvc_node_query_id);
		break;

	default:
		WPRINTF(("Warning: Unknown event: %u\n", ctrl->pvc_event));
		vi_set_needs_reset(&sc->vsd_vs);
		return (1);
	}

	return (retval);
}

static void
pci_vtdtr_notify_tx(void *xsc, struct vqueue_info *vq __unused)
{
	struct pci_vtdtr_softc *sc = xsc;

	if (sc->vsd_stopping)
		return;
	if (sc->vsd_ready == 0)
		pci_vtdtr_notify_ready(sc);
	pthread_cond_broadcast(&sc->vsd_cond);
}

/*
 * The RX queue interrupt. Process all available descriptors, including a new
 * batch that may already follow EOF, while holding the common VirtIO lock.
 */
static void
pci_vtdtr_notify_rx(void *xsc, struct vqueue_info *vq)
{
	struct pci_vtdtr_softc *sc;
	struct iovec iov[VTDTR_MAX_IOV];
	struct vi_req req;
	int n;
	int retval = 0, process = 1;
	uint16_t budget;

	sc = xsc;
	if (sc->vsd_stopping)
		return;

	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
		n = vq_getchain(vq, iov, nitems(iov), &req);
		if (n <= 0) {
			if (n < 0)
				vi_set_needs_reset(&sc->vsd_vs);
			break;
		}
		if (n > VTDTR_MAX_IOV || !req.ordered || req.readable != n ||
		    req.writable != 0) {
			vq_relchain_req(vq, &req, 0);
			vi_set_needs_reset(&sc->vsd_vs);
			break;
		}
		if (__predict_true(process))
			retval = pci_vtdtr_control_rx(sc, iov, n);
		vq_relchain_req(vq, &req, 0);
		/* EOF ends one batch, not the entire ring. A READY-only batch can
		 * leave guest TX open, so another batch may already be queued. Only
		 * a failed control invalidates the rest of this receive pass. */
		if (retval == 1 &&
		    (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0) {
			process = 0;
		}
	}

	if (sc->vsd_ready == 0)
		pci_vtdtr_notify_ready(sc);

	pci_vtdtr_poll(vq, 1);
}

static __inline void
pci_vtdtr_cq_enqueue(struct pci_vtdtr_ctrlq *cq,
    struct pci_vtdtr_ctrl_entry *ctrl_entry)
{

	STAILQ_INSERT_TAIL(&cq->head, ctrl_entry, entries);
	cq->count++;
	if (ctrl_entry->restored_kill)
		cq->restored_kills++;
}

static __inline void __unused
pci_vtdtr_cq_enqueue_front(struct pci_vtdtr_ctrlq *cq,
    struct pci_vtdtr_ctrl_entry *ctrl_entry)
{

	STAILQ_INSERT_HEAD(&cq->head, ctrl_entry, entries);
	cq->count++;
	if (ctrl_entry->restored_kill)
		cq->restored_kills++;
}

static __inline int
pci_vtdtr_cq_empty(struct pci_vtdtr_ctrlq *cq)
{

	return (STAILQ_EMPTY(&cq->head));
}

static struct pci_vtdtr_ctrl_entry *
pci_vtdtr_cq_dequeue(struct pci_vtdtr_ctrlq *cq)
{
	struct pci_vtdtr_ctrl_entry *ctrl_entry;
	ctrl_entry = STAILQ_FIRST(&cq->head);
	if (ctrl_entry != NULL) {
		STAILQ_REMOVE_HEAD(&cq->head, entries);
		cq->count--;
		if (ctrl_entry->restored_kill)
			cq->restored_kills--;
	}

	return (ctrl_entry);
}

/*
 * In this function we fill the descriptor that was provided to us by the guest.
 * No allocation is needed, since we memcpy everything.
 */
static bool
pci_vtdtr_fill_desc(struct vqueue_info *vq, struct pci_vtdtr_control *ctrl)
{
	struct iovec iov[VTDTR_MAX_IOV];
	size_t len;
	int n;
	struct vi_req req;

	n = vq_getchain(vq, iov, nitems(iov), &req);
	if (n <= 0) {
		if (n < 0)
			vi_set_needs_reset(vq->vq_vs);
		return (false);
	}
	if (n > VTDTR_MAX_IOV || !req.ordered || req.readable != 0 ||
	    req.writable != n ||
	    !pci_vtdtr_copy_control(iov, n, ctrl, true)) {
		vq_relchain_req(vq, &req, 0);
		vi_set_needs_reset(vq->vq_vs);
		return (false);
	}

	len = sizeof(struct pci_vtdtr_control);
	/* Mapping-time dirtiness can be consumed by a pre-copy round before
	 * this write finishes. Mark the actual written spans after copying and
	 * before returning the chain, while the request still owns its mappings.
	 * The common VirtIO completion path tracks the used-ring writes. */
	size_t remaining = len;
	for (int i = 0; i < n && remaining != 0; i++) {
		size_t written = MIN(remaining, iov[i].iov_len);
		if (written != 0)
			vi_mark_dma_dirty(vq->vq_vs, iov[i].iov_base, written);
		remaining -= written;
	}

	vq_relchain_req(vq, &req, len);
	return (true);
}

static void
pci_vtdtr_poll(struct vqueue_info *vq, int all_used)
{

	vq_endchains(vq, all_used);
}

/*
 * In this function we enqueue the READY control message in front of the queue,
 * so that when the guest receives the messages, READY is the first one in the
 * queue. If we already are ready, we simply signal the communicator thread that
 * it is safe to run.
 */
static bool
pci_vtdtr_restored_kills_pending(struct pci_vtdtr_softc *sc)
{
	struct pci_vtdtr_ctrl_entry *entry;

	STAILQ_FOREACH(entry, &sc->vsd_ctrlq->head, entries)
		if (entry->restored_kill)
			return (true);
	return (false);
}

static void
pci_vtdtr_notify_ready(struct pci_vtdtr_softc *sc)
{
	struct pci_vtdtr_control ctrl = { 0 };
	/* vsd_ctrlq exists from init; restored_kills_pending() relies on it too. */
	struct pci_vtdtr_ctrl_entry *head = STAILQ_FIRST(&sc->vsd_ctrlq->head);

	/* A failed session must not acknowledge another guest program as ready. */
	if (sc->vsd_stopping || (sc->vsd_session_stopped &&
	    (!sc->vsd_fresh_requested || sc->vsd_fresh_active)) ||
	    sc->vsd_suspended || sc->vsd_rekey_wait ||
	    sc->vsd_restored_kill_wait ||
	    (head != NULL && head->ctrl->pvc_event ==
	    VTDTR_DEVICE_NODE_REKEY && !sc->vsd_handoff_ticket_valid) ||
	    pci_vtdtr_restored_kills_pending(sc) ||
	    (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		return;
	ctrl.pvc_event = VTDTR_DEVICE_READY;
	if (vq_has_descs(&sc->vsd_queues[0]) &&
	    pci_vtdtr_fill_desc(&sc->vsd_queues[0], &ctrl)) {
		sc->vsd_ready = 1;
		pci_vtdtr_poll(&sc->vsd_queues[0], 1);
	}
}

static void
pci_vtdtr_fill_eof_desc(struct vqueue_info *vq)
{
	/*
	 * Do a malloc to ensure that we don't break the stack
	 */
	struct pci_vtdtr_control ctrl = { 0 };
	ctrl.pvc_event = VTDTR_DEVICE_EOF;
	pci_vtdtr_fill_desc(vq, &ctrl);
}

static bool
pci_vtdtr_ctrl_matches_vm(const struct pci_vtdtr_control *ctrl,
    uint16_t vmid, uint64_t epoch)
{
	switch (ctrl->pvc_event) {
	case VTDTR_DEVICE_ELF:
		return (ctrl->pvc_vmid == vmid && ctrl->pvc_epoch == epoch);
	case VTDTR_DEVICE_KILL:
	case VTDTR_DEVICE_HOST_KILL_APPLIED:
		return (ctrl->pvc_kill_vmid == vmid &&
		    ctrl->pvc_kill_epoch == epoch);
	case VTDTR_DEVICE_CLEANUP_DTRACED:
	case VTDTR_DEVICE_HOST_CLEANUP_APPLIED:
	case VTDTR_DEVICE_SESSION_STOP:
		return (ctrl->pvc_cleanup_vmid == vmid &&
		    ctrl->pvc_cleanup_epoch == epoch);
	case VTDTR_DEVICE_NODE_ID:
		return (ctrl->pvc_node_id == vmid &&
		    ctrl->pvc_node_epoch == epoch);
	case VTDTR_DEVICE_NODE_REKEY:
		return (ctrl->pvc_rekey_new_id == vmid &&
		    ctrl->pvc_rekey_new_epoch == epoch);
	case VTDTR_DEVICE_SESSION_PREPARE:
	case VTDTR_DEVICE_SESSION_COMMIT:
		return (ctrl->wire.uctrl.session_prepare.new_id == vmid &&
		    ctrl->wire.uctrl.session_prepare.new_epoch == epoch);
	case VTDTR_DEVICE_HOST_INSTALLED:
	case VTDTR_DEVICE_HOST_UNINSTALLED:
	case VTDTR_DEVICE_HOST_STATUS:
	case VTDTR_DEVICE_HOST_ELF:
	case VTDTR_DEVICE_HOST_INGRESS_STATUS:
		return (ctrl->pvc_installed_vmid == vmid &&
		    ctrl->pvc_installed_epoch == epoch);
	case VTDTR_DEVICE_READY:
	case VTDTR_DEVICE_EOF:
		return (true);
	default:
		/* New host-to-guest controls need an explicit identity rule. */
		return (false);
	}
}

#ifdef BHYVE_SNAPSHOT
struct pci_vtdtr_elf_run {
	uint64_t delivery_id, epoch;
	uint32_t total, bytes;
	uint16_t vmid;
	uint8_t program_id[16], source_id[16];
	bool open;
};

/* The reader publishes every fragment of one ELF as an ordered frame.
 * A checkpoint can start at any fragment because earlier ones may already
 * be in guest memory, but its remaining suffix must still be canonical. */
static bool
pci_vtdtr_elf_run_advance(struct pci_vtdtr_elf_run *run,
    const struct pci_vtdtr_control *ctrl)
{
	if (ctrl->pvc_event != VTDTR_DEVICE_ELF)
		return (!run->open);
	if (!run->open) {
		run->delivery_id = ctrl->pvc_delivery_id;
		run->vmid = ctrl->pvc_vmid;
		run->epoch = ctrl->pvc_epoch;
		run->total = ctrl->pvc_totalelflen;
		run->bytes = 0;
		memcpy(run->program_id, ctrl->pvc_program_id, 16);
		memcpy(run->source_id, ctrl->pvc_elf_source_id, 16);
		run->open = true;
	} else if (run->delivery_id != ctrl->pvc_delivery_id ||
	    run->vmid != ctrl->pvc_vmid || run->epoch != ctrl->pvc_epoch ||
	    run->total != ctrl->pvc_totalelflen ||
	    memcmp(run->program_id, ctrl->pvc_program_id, 16) != 0 ||
	    memcmp(run->source_id, ctrl->pvc_elf_source_id, 16) != 0) {
		return (false);
	}
	if (ctrl->pvc_elflen > run->total - run->bytes ||
	    (ctrl->pvc_elfhasmore != 0 &&
	    ctrl->pvc_elflen != PCI_VTDTR_MAXELFLEN))
		return (false);
	run->bytes += ctrl->pvc_elflen;
	if (ctrl->pvc_elfhasmore == 0) {
		if ((run->total - run->bytes) % PCI_VTDTR_MAXELFLEN != 0)
			return (false);
		run->open = false;
	}
	return (true);
}

static bool
pci_vtdtr_ctrl_checkpoint_valid(const struct pci_vtdtr_control *ctrl,
    uint16_t vmid, uint64_t epoch)
{
	const uint8_t zero_id[16] = { 0 };
	const uint8_t zero_digest[32] = { 0 };
	bool digest_empty;

	if (!pci_vtdtr_ctrl_matches_vm(ctrl, vmid, epoch))
		return (false);
	switch (ctrl->pvc_event) {
	case VTDTR_DEVICE_ELF:
		return (ctrl->pvc_elflen != 0 &&
		    ctrl->pvc_elflen <= PCI_VTDTR_MAXELFLEN &&
		    ctrl->pvc_totalelflen != 0 &&
		    ctrl->pvc_totalelflen <= HYPERTRACE_ELF_MAX &&
		    ctrl->pvc_elflen <= ctrl->pvc_totalelflen &&
		    (ctrl->pvc_elfhasmore == 0 ||
		    ctrl->pvc_elfhasmore == 1) &&
		    ctrl->pvc_delivery_id != 0 &&
		    memcmp(ctrl->pvc_program_id, zero_id, 16) != 0 &&
		    memcmp(ctrl->pvc_elf_source_id, zero_id, 16) != 0);
	case VTDTR_DEVICE_KILL:
	case VTDTR_DEVICE_HOST_KILL_APPLIED:
		return (ctrl->pvc_pid > 1 &&
		    memcmp(ctrl->pvc_source_id, zero_id, 16) != 0);
	case VTDTR_DEVICE_HOST_INSTALLED:
	case VTDTR_DEVICE_HOST_UNINSTALLED:
	case VTDTR_DEVICE_HOST_STATUS:
	case VTDTR_DEVICE_HOST_ELF:
	case VTDTR_DEVICE_HOST_INGRESS_STATUS:
		if (ctrl->pvc_installed_delivery_id == 0 ||
		    ctrl->pvc_installed_revoked > 1 ||
		    ctrl->pvc_installed_replay > 1 ||
		    memcmp(ctrl->pvc_installed_program_id, zero_id, 16) == 0 ||
		    memcmp(ctrl->pvc_installed_source_id, zero_id, 16) == 0)
			return (false);
		digest_empty = memcmp(ctrl->pvc_installed_digest,
		    zero_digest, sizeof(zero_digest)) == 0;
		if (ctrl->pvc_event == VTDTR_DEVICE_HOST_STATUS)
			return (ctrl->pvc_installed_query_id != 0 &&
			    (ctrl->pvc_installed_phase == 0 ||
			    ctrl->pvc_installed_phase == 'p' ||
			    ctrl->pvc_installed_phase == 'a' ||
			    ctrl->pvc_installed_phase == 'i' ||
			    ctrl->pvc_installed_phase == 't' ||
			    ctrl->pvc_installed_phase == 'u') &&
			    (ctrl->pvc_installed_replay == 0 ? digest_empty :
			    (!digest_empty && ctrl->pvc_installed_revoked == 0 &&
			    (ctrl->pvc_installed_phase == 'a' ||
			    ctrl->pvc_installed_phase == 'i'))) &&
			    (ctrl->pvc_installed_phase != 'u' ||
			    ctrl->pvc_installed_revoked == 0));
		if (ctrl->pvc_event == VTDTR_DEVICE_HOST_INGRESS_STATUS)
			return (ctrl->pvc_installed_query_id != 0 &&
			    ctrl->pvc_installed_replay == 0 &&
			    (ctrl->pvc_installed_phase == 0 ||
			    ctrl->pvc_installed_phase == 'p' ||
			    ctrl->pvc_installed_phase == 'a' ||
			    ctrl->pvc_installed_phase == 'u') &&
			    (digest_empty ==
			    (ctrl->pvc_installed_phase == 0 ||
			    ctrl->pvc_installed_phase == 'u')) &&
			    (ctrl->pvc_installed_phase != 'u' ||
			    ctrl->pvc_installed_revoked == 0));
		return (ctrl->pvc_installed_query_id == 0 &&
		    ctrl->pvc_installed_phase == 0 &&
		    ctrl->pvc_installed_revoked == 0 &&
		    ctrl->pvc_installed_replay == 0 &&
		    (ctrl->pvc_event == VTDTR_DEVICE_HOST_ELF ?
		    !digest_empty : digest_empty));
	case VTDTR_DEVICE_NODE_ID:
		return (ctrl->pvc_node_id != 0);
	case VTDTR_DEVICE_NODE_REKEY:
		return (ctrl->pvc_rekey_old_id != 0 &&
		    ctrl->pvc_rekey_old_id < HYPERTRACE_MAX_VMS &&
		    ctrl->pvc_rekey_old_epoch != 0 &&
		    ctrl->pvc_rekey_new_id != 0 &&
		    (ctrl->pvc_rekey_old_id != ctrl->pvc_rekey_new_id ||
		    ctrl->pvc_rekey_old_epoch != ctrl->pvc_rekey_new_epoch));
	case VTDTR_DEVICE_CLEANUP_DTRACED:
	case VTDTR_DEVICE_HOST_CLEANUP_APPLIED:
		return (ctrl->pvc_cleanup_delivery_id != 0);
	case VTDTR_DEVICE_READY:
	case VTDTR_DEVICE_EOF:
		return (true);
	default:
		return (false);
	}
}

/* The common VirtIO gate owns the queue lock before a private image can be
 * captured.  Refuse stale or internally inconsistent state even while the
 * restore codec remains gated: such state cannot be remapped safely. */
/* Empty private image for a stopped session. This is never a replayable
 * continuity cut and does not authorize restoring the source identity. */
static int
pci_vtdtr_session_source_valid(struct pci_vtdtr_softc *sc)
{
	const uint8_t zero[16] = {0};
	struct hypertrace_elf *elf = &sc->vsd_inbound_elf;
	int error = pci_vtdtr_session_stop_status_locked(sc);
	if (error != 0)
		return (error);
	if (!sc->vsd_session_stop_delivered || !sc->vsd_session_collectors_stopped ||
	    sc->vsd_session_collectors_busy || sc->vsd_session_restore_pending ||
	    sc->vsd_fresh_requested || sc->vsd_rekey_wait || sc->vsd_restored_kill_wait ||
	    sc->vsd_handoff_ticket_valid || sc->vsd_restore_planned != NULL ||
	    sc->vsd_ticket_wait || sc->vsd_cleanup_unapplied ||
	    sc->vsd_rekey_ack_pending || sc->vsd_rekey_ack_sent ||
	    sc->vsd_rekey_receipt_reply_pending || sc->vsd_guest_ready || sc->vsd_ready)
		return (EBUSY);
	if ((sc->vsd_vs.vs_negotiated_caps & HYPERTRACE_SESSION_FEATURES) !=
	    HYPERTRACE_SESSION_FEATURES)
		return (ENOTSUP);
	if (sc->vsd_ctrlq == NULL || sc->vsd_ctrlq->count != 0 ||
	    !STAILQ_EMPTY(&sc->vsd_ctrlq->head) || sc->vsd_ctrlq->restored_kills != 0 ||
	    elf->data != NULL || elf->total != 0 || elf->received != 0 ||
	    elf->identifier != 0 || sc->vsd_inbound_delivery_id != 0 ||
	    sc->vsd_inbound_vmid != 0 || sc->vsd_inbound_epoch != 0 ||
	    memcmp(sc->vsd_inbound_program_id, zero, 16) != 0 ||
	    memcmp(sc->vsd_inbound_source_id, zero, 16) != 0)
		return (EPROTO);
	return (0);
}

static int
pci_vtdtr_checkpoint_state_valid(struct pci_vtdtr_softc *sc)
{
	const uint8_t zero_id[16] = { 0 };
	struct pci_vtdtr_ctrl_entry *entry;
	struct hypertrace_elf *elf = &sc->vsd_inbound_elf;
	uint16_t vmid;
	uint64_t epoch;
	size_t count = 0, restored_kills = 0;
	struct pci_vtdtr_elf_run run = { 0 };

	/* The rekey barrier has no committed host/guest image yet. */
	if (sc->vsd_rekey_wait || sc->vsd_restored_kill_wait ||
	    sc->vsd_session_stop_requested ||
	    memcmp(sc->vsd_session_gate_token, zero_id, 16) != 0)
		return (EBUSY);
	if (sc->vsd_stopping || sc->vsd_ctrlq == NULL ||
	    vm_get_identity(sc->vsd_vmctx, &vmid, &epoch) != 0 ||
	    vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0)
		return (ESTALE);
	/* A restore may still hold admission KILLs in its dedicated reserve.
	 * Wait for their guest-applied drain before taking another source cut. */
	if (sc->vsd_ctrlq->count > VTDTR_MAX_PENDING)
		return (EBUSY);
	STAILQ_FOREACH(entry, &sc->vsd_ctrlq->head, entries) {
		if (entry->restored_kill)
			restored_kills++;
		if (++count > VTDTR_MAX_PENDING || entry->ctrl == NULL ||
		    (entry->restored_kill &&
		    entry->ctrl->pvc_event != VTDTR_DEVICE_KILL) ||
		    !pci_vtdtr_ctrl_checkpoint_valid(entry->ctrl, vmid, epoch) ||
		    !pci_vtdtr_elf_run_advance(&run, entry->ctrl))
			return (EPROTO);
	}
	if (count != sc->vsd_ctrlq->count ||
	    restored_kills != sc->vsd_ctrlq->restored_kills || run.open)
		return (EPROTO);
	if (elf->data == NULL) {
		if (elf->total != 0 || elf->received != 0 ||
		    elf->identifier != 0 || sc->vsd_inbound_delivery_id != 0 ||
		    sc->vsd_inbound_vmid != 0 || sc->vsd_inbound_epoch != 0 ||
		    memcmp(sc->vsd_inbound_program_id, zero_id, 16) != 0 ||
		    memcmp(sc->vsd_inbound_source_id, zero_id, 16) != 0)
			return (EPROTO);
	} else if (elf->total == 0 || elf->total > HYPERTRACE_ELF_MAX ||
	    elf->received == 0 || elf->received >= elf->total ||
	    sc->vsd_inbound_delivery_id == 0 ||
	    sc->vsd_inbound_vmid != vmid || sc->vsd_inbound_epoch != epoch ||
	    memcmp(sc->vsd_inbound_program_id, zero_id, 16) == 0 ||
	    memcmp(sc->vsd_inbound_source_id, zero_id, 16) == 0)
		return (EPROTO);
	return (0);
}

/* Refuse a source checkpoint whose private image cannot pass the destination
 * query/queue plan. A partial guest upload has no durable ingress receipt;
 * an ELF suffix lacks the bytes needed to authenticate its source receipt.
 * Validate before writing any device bytes into the checkpoint. */
static int
pci_vtdtr_checkpoint_replayable(struct pci_vtdtr_softc *sc)
{
	struct pci_vtdtr_ctrl_entry *entry;
	struct pci_vtdtr_elf_run run = { 0 };
	bool pending;
	int error;
	if (sc->vsd_session_stop_requested) {
		error = pci_vtdtr_session_source_valid(sc);
		if (error != 0)
			return (error);
		error = vq_checkpoint_has_descs(&sc->vsd_queues[1], &pending);
		return (error != 0 ? error : pending ? EBUSY : 0);
	}

	/* A restored incarnation cannot become a new source until its guest
	 * rekey and daemon admission have settled. Keep this check separate from
	 * state_valid(), which also validates the private destination queue. */
	if (sc->vsd_restore_planned != NULL || sc->vsd_ticket_wait ||
	    sc->vsd_handoff_ticket_valid || sc->vsd_rekey_ack_pending ||
	    sc->vsd_rekey_ack_sent ||
	    sc->vsd_rekey_receipt_reply_pending ||
	    sc->vsd_cleanup_unapplied)
		return (EBUSY);
	error = pci_vtdtr_checkpoint_state_valid(sc);
	if (error != 0)
		return (error);
	/* Queue 1 carries guest-to-host controls.  The checkpoint pause hides
	 * descriptors from the normal vq_has_descs() path, so inspect the ring
	 * directly before treating the source cut as settled.  A queued control
	 * has not passed the host/daemon receipt protocol and cannot be replayed
	 * from the private image. */
	error = vq_checkpoint_has_descs(&sc->vsd_queues[1], &pending);
	if (error != 0)
		return (error);
	if (pending)
		return (EBUSY);
	error = pci_vtdtr_checkpoint_features_validate(
	    sc->vsd_vs.vs_negotiated_caps);
	if (error != 0)
		return (error);
	if (sc->vsd_inbound_elf.data != NULL)
		return (EOPNOTSUPP);
	STAILQ_FOREACH(entry, &sc->vsd_ctrlq->head, entries) {
		if (!pci_vtdtr_elf_run_advance(&run, entry->ctrl))
			return (EPROTO);
		switch (entry->ctrl->pvc_event) {
		case VTDTR_DEVICE_ELF:
			if (!run.open && run.bytes != run.total)
				return (EOPNOTSUPP);
			break;
		case VTDTR_DEVICE_KILL:
		case VTDTR_DEVICE_HOST_KILL_APPLIED:
		case VTDTR_DEVICE_HOST_ELF:
		case VTDTR_DEVICE_CLEANUP_DTRACED:
		case VTDTR_DEVICE_READY:
		case VTDTR_DEVICE_EOF:
			break;
		default:
			return (EOPNOTSUPP);
		}
	}
	return (0);
}

/* Version 1 stores control fields, never host structure padding or size_t. */
#define VTDTR_SNAPSHOT_MAGIC 0x31524456U /* "VDR1" in little endian */
#define VTDTR_SNAPSHOT_VERSION 3U

static int
pci_vtdtr_snapshot_control(struct pci_vtdtr_control *ctrl,
    struct vm_snapshot_meta *meta, uint16_t vmid, uint64_t epoch)
{
	uint32_t event = ctrl->pvc_event;
	uint32_t length, total, identifier, pid;
	uint16_t id;
	uint64_t delivery, control_epoch, query;
	uint8_t more, phase, revoked, replay;
	int error;

	SNAPSHOT_LE32_OR_LEAVE(event, meta, error, done);
	if (vm_snapshot_is_loading(meta))
		ctrl->pvc_event = event;
	switch (event) {
	case VTDTR_DEVICE_ELF:
		length = (uint32_t)ctrl->pvc_elflen;
		total = (uint32_t)ctrl->pvc_totalelflen;
		identifier = ctrl->pvc_identifier;
		delivery = ctrl->pvc_delivery_id;
		id = ctrl->pvc_vmid;
		control_epoch = ctrl->pvc_epoch;
		more = (uint8_t)ctrl->pvc_elfhasmore;
		SNAPSHOT_LE32_OR_LEAVE(length, meta, error, done);
		SNAPSHOT_LE32_OR_LEAVE(total, meta, error, done);
		SNAPSHOT_LE32_OR_LEAVE(identifier, meta, error, done);
		SNAPSHOT_LE64_OR_LEAVE(delivery, meta, error, done);
		SNAPSHOT_LE16_OR_LEAVE(id, meta, error, done);
		SNAPSHOT_LE64_OR_LEAVE(control_epoch, meta, error, done);
		SNAPSHOT_U8_OR_LEAVE(more, meta, error, done);
		if (length == 0 || length > PCI_VTDTR_MAXELFLEN) {
			error = EINVAL;
			goto done;
		}
		ctrl->pvc_elflen = length;
		ctrl->pvc_totalelflen = total;
		ctrl->pvc_identifier = identifier;
		ctrl->pvc_delivery_id = delivery;
		ctrl->pvc_vmid = id;
		ctrl->pvc_epoch = control_epoch;
		ctrl->pvc_elfhasmore = more;
		SNAPSHOT_BUF_OR_LEAVE(ctrl->pvc_program_id, 16, meta,
		    error, done);
		SNAPSHOT_BUF_OR_LEAVE(ctrl->pvc_elf_source_id, 16, meta,
		    error, done);
		SNAPSHOT_BUF_OR_LEAVE(ctrl->pvc_elf, length, meta,
		    error, done);
		break;
	case VTDTR_DEVICE_KILL:
	case VTDTR_DEVICE_HOST_KILL_APPLIED:
		pid = (uint32_t)ctrl->pvc_pid;
		id = ctrl->pvc_kill_vmid;
		control_epoch = ctrl->pvc_kill_epoch;
		SNAPSHOT_LE32_OR_LEAVE(pid, meta, error, done);
		SNAPSHOT_LE16_OR_LEAVE(id, meta, error, done);
		SNAPSHOT_LE64_OR_LEAVE(control_epoch, meta, error, done);
		if (pid > INT32_MAX) {
			error = EINVAL;
			goto done;
		}
		ctrl->pvc_pid = (pid_t)pid;
		ctrl->pvc_kill_vmid = id;
		ctrl->pvc_kill_epoch = control_epoch;
		SNAPSHOT_BUF_OR_LEAVE(ctrl->pvc_source_id, 16, meta,
		    error, done);
		break;
	case VTDTR_DEVICE_HOST_INSTALLED:
	case VTDTR_DEVICE_HOST_UNINSTALLED:
	case VTDTR_DEVICE_HOST_STATUS:
	case VTDTR_DEVICE_HOST_ELF:
	case VTDTR_DEVICE_HOST_INGRESS_STATUS:
		delivery = ctrl->pvc_installed_delivery_id;
		id = ctrl->pvc_installed_vmid;
		control_epoch = ctrl->pvc_installed_epoch;
		phase = ctrl->pvc_installed_phase;
		revoked = ctrl->pvc_installed_revoked;
		replay = ctrl->pvc_installed_replay;
		query = ctrl->pvc_installed_query_id;
		SNAPSHOT_LE64_OR_LEAVE(delivery, meta, error, done);
		SNAPSHOT_LE16_OR_LEAVE(id, meta, error, done);
		SNAPSHOT_LE64_OR_LEAVE(control_epoch, meta, error, done);
		SNAPSHOT_U8_OR_LEAVE(phase, meta, error, done);
		SNAPSHOT_U8_OR_LEAVE(revoked, meta, error, done);
		SNAPSHOT_U8_OR_LEAVE(replay, meta, error, done);
		SNAPSHOT_LE64_OR_LEAVE(query, meta, error, done);
		ctrl->pvc_installed_delivery_id = delivery;
		ctrl->pvc_installed_vmid = id;
		ctrl->pvc_installed_epoch = control_epoch;
		ctrl->pvc_installed_phase = phase;
		ctrl->pvc_installed_revoked = revoked;
		ctrl->pvc_installed_replay = replay;
		ctrl->pvc_installed_query_id = query;
		SNAPSHOT_BUF_OR_LEAVE(ctrl->pvc_installed_program_id, 16,
		    meta, error, done);
		SNAPSHOT_BUF_OR_LEAVE(ctrl->pvc_installed_source_id, 16,
		    meta, error, done);
		SNAPSHOT_BUF_OR_LEAVE(ctrl->pvc_installed_digest, 32,
		    meta, error, done);
		break;
	case VTDTR_DEVICE_CLEANUP_DTRACED:
		id = ctrl->pvc_cleanup_vmid;
		control_epoch = ctrl->pvc_cleanup_epoch;
		query = ctrl->pvc_cleanup_delivery_id;
		SNAPSHOT_LE16_OR_LEAVE(id, meta, error, done);
		SNAPSHOT_LE64_OR_LEAVE(control_epoch, meta, error, done);
		SNAPSHOT_LE64_OR_LEAVE(query, meta, error, done);
		ctrl->pvc_cleanup_vmid = id;
		ctrl->pvc_cleanup_epoch = control_epoch;
		ctrl->pvc_cleanup_delivery_id = query;
		break;
	case VTDTR_DEVICE_NODE_ID:
		id = ctrl->pvc_node_id;
		control_epoch = ctrl->pvc_node_epoch;
		query = ctrl->pvc_node_query_id;
		SNAPSHOT_LE16_OR_LEAVE(id, meta, error, done);
		SNAPSHOT_LE64_OR_LEAVE(control_epoch, meta, error, done);
		SNAPSHOT_LE64_OR_LEAVE(query, meta, error, done);
		ctrl->pvc_node_id = id;
		ctrl->pvc_node_epoch = control_epoch;
		ctrl->pvc_node_query_id = query;
		break;
	case VTDTR_DEVICE_NODE_REKEY: {
		uint16_t old_id = ctrl->pvc_rekey_old_id;
		uint64_t old_epoch = ctrl->pvc_rekey_old_epoch;
		uint16_t new_id = ctrl->pvc_rekey_new_id;
		uint64_t new_epoch = ctrl->pvc_rekey_new_epoch;
		SNAPSHOT_LE16_OR_LEAVE(old_id, meta, error, done);
		SNAPSHOT_LE64_OR_LEAVE(old_epoch, meta, error, done);
		SNAPSHOT_LE16_OR_LEAVE(new_id, meta, error, done);
		SNAPSHOT_LE64_OR_LEAVE(new_epoch, meta, error, done);
		ctrl->pvc_rekey_old_id = old_id;
		ctrl->pvc_rekey_old_epoch = old_epoch;
		ctrl->pvc_rekey_new_id = new_id;
		ctrl->pvc_rekey_new_epoch = new_epoch;
		break;
	}
	case VTDTR_DEVICE_READY:
	case VTDTR_DEVICE_EOF:
		break;
	default:
		error = EINVAL;
		goto done;
	}
	error = pci_vtdtr_ctrl_checkpoint_valid(ctrl, vmid, epoch) ?
	    0 : EPROTO;
done:
	return (error);
}

struct pci_vtdtr_checkpoint_stage {
	struct pci_vtdtr_control *controls;
	uint8_t *partial_prefix;
	uint32_t count, partial_total, partial_received, partial_identifier;
	uint64_t cfg, source_epoch, partial_delivery_id;
	uint64_t partial_epoch;
	uint16_t source_vmid, partial_vmid;
	uint8_t guest_ready, ready;
	uint8_t program_id[16], source_id[16];
};

static void
pci_vtdtr_checkpoint_stage_clear(struct pci_vtdtr_checkpoint_stage *stage)
{
	if (stage == NULL)
		return;
	if (stage->partial_prefix != NULL)
		explicit_bzero(stage->partial_prefix, stage->partial_received);
	free(stage->partial_prefix);
	free(stage->controls);
	memset(stage, 0, sizeof(*stage));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* Read-only source-journal check after destination RESERVE, before any VM
 * mutation. This deliberately does not bind a receipt or authorize replay.
 * Controls without an exact handoff lookup keep the restore gate closed. */
static int
pci_vtdtr_checkpoint_delivery_receipt(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32], uint64_t delivery_id,
    const uint8_t program_id[16], const uint8_t source_id[16],
    uint8_t scope, const uint8_t payload_digest[32], bool bind)
{
	const uint8_t zero32[32] = { 0 };
	dtraced_handoff_delivery_request_t delivery = { 0 };
	dtraced_handoff_bind_delivery_request_t bound = { 0 };
	dtraced_delivery_status_t status = { 0 };

	memcpy(delivery.token, token, sizeof(delivery.token));
	memcpy(delivery.digest, digest, sizeof(delivery.digest));
	delivery.delivery_id = delivery_id;
	memcpy(delivery.program_id, program_id, 16);
	memcpy(delivery.source_id, source_id, 16);
	delivery.scope = scope;
	if (bind && scope != 0)
		return (EOPNOTSUPP);
	if (bind) {
		if (payload_digest == NULL ||
		    memcmp(payload_digest, zero32, sizeof(zero32)) == 0)
			return (EINVAL);
		bound.delivery = delivery;
		memcpy(bound.payload_digest, payload_digest, 32);
	}
	if ((bind ? hypertrace_handoff_bind_delivery_prestart(ctx, &bound,
	    &status) : hypertrace_handoff_delivery_prestart(ctx, &delivery,
	    &status)) != 0)
		return (errno != 0 ? errno : EIO);
	if (status.delivery_id != delivery.delivery_id ||
	    (scope == 3 ? status.phase != 'a' :
	    (status.phase != 'a' && status.phase != 'i')) ||
	    status.revoked != 0 || status.replay != 0 ||
	    memcmp(status.digest, zero32, sizeof(zero32)) == 0 ||
	    ((scope == 0 || scope == 3) && (payload_digest == NULL ||
	    memcmp(status.digest, payload_digest, sizeof(status.digest)) != 0)))
		return (EPROTO);
	return (0);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
static int
pci_vtdtr_checkpoint_cleanup_receipt(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32],
    uint64_t delivery_id)
{
	dtraced_handoff_cleanup_request_t request = { 0 };
	dtraced_delivery_status_t status = { 0 };

	memcpy(request.token, token, sizeof(request.token));
	memcpy(request.digest, digest, sizeof(request.digest));
	request.delivery_id = delivery_id;
	if (hypertrace_handoff_cleanup_prestart(ctx, &request, &status) != 0)
		return (errno != 0 ? errno : EIO);
	if (status.delivery_id != delivery_id || status.phase != 'a' ||
	    status.revoked != 0 || status.replay != 0)
		return (EPROTO);
	return (0);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* A checkpoint may capture only the suffix of a fragmented ELF. Its source
 * receipt cannot authenticate bytes that are no longer in the queue. */
static int
pci_vtdtr_checkpoint_elf_digest(const struct pci_vtdtr_checkpoint_stage *stage,
    uint32_t first, uint8_t digest[32])
{
	struct pci_vtdtr_elf_run run = { 0 };
	EVP_MD_CTX *hash;
	unsigned length = 0;
	int error = EPROTO;

	if (stage == NULL || digest == NULL || first >= stage->count ||
	    stage->controls[first].pvc_event != VTDTR_DEVICE_ELF)
		return (EINVAL);
	hash = EVP_MD_CTX_new();
	if (hash == NULL)
		return (ENOMEM);
	if (EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) {
		error = EIO;
		goto done;
	}
	for (uint32_t i = first; i < stage->count; i++) {
		const struct pci_vtdtr_control *ctrl = &stage->controls[i];
		if (ctrl->pvc_event != VTDTR_DEVICE_ELF ||
		    !pci_vtdtr_ctrl_checkpoint_valid(ctrl, stage->source_vmid,
		    stage->source_epoch) ||
		    !pci_vtdtr_elf_run_advance(&run, ctrl))
			goto done;
		if (EVP_DigestUpdate(hash, ctrl->pvc_elf,
		    ctrl->pvc_elflen) != 1) {
			error = EIO;
			goto done;
		}
		if (!run.open) {
			if (run.bytes != run.total) {
				error = EOPNOTSUPP;
				goto done;
			}
			if (EVP_DigestFinal_ex(hash, digest, &length) != 1 ||
			    length != 32) {
				error = EIO;
				goto done;
			}
			error = 0;
			goto done;
		}
	}
done:
	EVP_MD_CTX_free(hash);
	return (error);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
static int
pci_vtdtr_checkpoint_stage_query(const struct pci_vtdtr_checkpoint_stage *stage,
    struct vmctx *ctx, const uint8_t token[16], const uint8_t digest[32])
{
	const uint8_t zero16[16] = { 0 }, zero32[32] = { 0 };
	dtraced_handoff_kill_request_t kill;
	dtraced_delivery_status_t status;
	const struct pci_vtdtr_control *ctrl, *previous;
	struct pci_vtdtr_elf_run run = { 0 };
	uint8_t payload_digest[32];
	int error;

	if (stage == NULL || ctx == NULL || token == NULL || digest == NULL ||
	    stage->source_vmid == 0 || stage->source_epoch == 0 ||
	    (stage->count != 0 && stage->controls == NULL) ||
	    memcmp(token, zero16, sizeof(zero16)) == 0 ||
	    memcmp(digest, zero32, sizeof(zero32)) == 0)
		return (EINVAL);
	/* An unfinished guest-to-host ELF has no durable receipt to query yet. */
	if (stage->partial_received != 0)
		return (EOPNOTSUPP);
	for (uint32_t i = 0; i < stage->count; i++) {
		ctrl = &stage->controls[i];
		if (!pci_vtdtr_ctrl_checkpoint_valid(ctrl, stage->source_vmid,
		    stage->source_epoch) ||
		    !pci_vtdtr_elf_run_advance(&run, ctrl))
			return (EPROTO);
		switch (ctrl->pvc_event) {
		case VTDTR_DEVICE_ELF:
			previous = i == 0 ? NULL : &stage->controls[i - 1];
			if (previous != NULL &&
			    previous->pvc_event == VTDTR_DEVICE_ELF &&
			    previous->pvc_elfhasmore != 0)
				break;
			error = pci_vtdtr_checkpoint_elf_digest(stage, i,
			    payload_digest);
			if (error != 0)
				return (error);
			error = pci_vtdtr_checkpoint_delivery_receipt(ctx, token,
			    digest, ctrl->pvc_delivery_id, ctrl->pvc_program_id,
			    ctrl->pvc_elf_source_id, 0, payload_digest, false);
			if (error != 0)
				return (error);
			break;
		case VTDTR_DEVICE_HOST_ELF:
			error = pci_vtdtr_checkpoint_delivery_receipt(ctx, token,
			    digest, ctrl->pvc_installed_delivery_id,
			    ctrl->pvc_installed_program_id,
			    ctrl->pvc_installed_source_id, 3,
			    ctrl->pvc_installed_digest, false);
			if (error != 0)
				return (error);
			break;
		case VTDTR_DEVICE_KILL:
		case VTDTR_DEVICE_HOST_KILL_APPLIED:
			memset(&kill, 0, sizeof(kill));
			memcpy(kill.token, token, sizeof(kill.token));
			memcpy(kill.digest, digest, sizeof(kill.digest));
			kill.pid = ctrl->pvc_pid;
			memcpy(kill.source_id, ctrl->pvc_source_id, 16);
			if (hypertrace_handoff_kill_prestart(ctx, &kill,
			    &status) != 0)
				return (errno != 0 ? errno : EIO);
			if (status.delivery_id != (uint32_t)kill.pid ||
			    (ctrl->pvc_event == VTDTR_DEVICE_KILL ?
			    (status.phase != 'p' && status.phase != 'a') :
			    status.phase != 'a') || status.revoked != 1 ||
			    status.replay != 0)
				return (EPROTO);
			break;
		case VTDTR_DEVICE_CLEANUP_DTRACED:
			error = pci_vtdtr_checkpoint_cleanup_receipt(ctx,
			    token, digest, ctrl->pvc_cleanup_delivery_id);
			if (error != 0)
				return (error);
			break;
		case VTDTR_DEVICE_READY:
		case VTDTR_DEVICE_EOF:
			break;
		default:
			return (EOPNOTSUPP);
		}
	}
	return (run.open ? EPROTO : 0);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* Binding is idempotent at the daemon journal. A retry after a partial bind
 * completes the same ticket; no guest may run until every bind succeeds. */
static int
pci_vtdtr_checkpoint_stage_bind(const struct pci_vtdtr_checkpoint_stage *stage,
    struct vmctx *ctx, const uint8_t token[16], const uint8_t digest[32])
{
	const struct pci_vtdtr_control *ctrl, *previous;
	uint8_t payload_digest[32];
	int error;

	error = pci_vtdtr_checkpoint_stage_query(stage, ctx, token, digest);
	if (error != 0)
		return (error);
	for (uint32_t i = 0; i < stage->count; i++) {
		ctrl = &stage->controls[i];
		switch (ctrl->pvc_event) {
		case VTDTR_DEVICE_ELF:
			previous = i == 0 ? NULL : &stage->controls[i - 1];
			if (previous != NULL &&
			    previous->pvc_event == VTDTR_DEVICE_ELF &&
			    previous->pvc_elfhasmore != 0)
				break;
			error = pci_vtdtr_checkpoint_elf_digest(stage, i,
			    payload_digest);
			if (error != 0)
				return (error);
			error = pci_vtdtr_checkpoint_delivery_receipt(ctx, token,
			    digest, ctrl->pvc_delivery_id, ctrl->pvc_program_id,
			    ctrl->pvc_elf_source_id, 0, payload_digest, true);
			if (error != 0)
				return (error);
			break;
		case VTDTR_DEVICE_HOST_ELF:
			/* The accepted guest upload stays in the host ingress
			 * ledger. The queued receipt needs an exact read-only check,
			 * not a host-outbound delivery bind. */
			break;
		default:
			break;
		}
	}
	return (0);
}

static void
pci_vtdtr_checkpoint_queue_free(struct pci_vtdtr_ctrlq *queue)
{
	struct pci_vtdtr_ctrl_entry *entry;

	if (queue == NULL)
		return;
	while ((entry = pci_vtdtr_cq_dequeue(queue)) != NULL) {
		free(entry->ctrl);
		free(entry);
	}
	free(queue);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Reached only from
 * transfer-ticket replay (NODE_REKEY / restored KILLs), which restore
 * refuses, so this is intentionally unreachable until enabled. */
/* Prepare a complete destination queue without publishing it. The rekey
 * notice must precede every saved control, and KILLs precede ELF replay.
 * A source HOST_KILL_APPLIED receipt is omitted because guest journal rekey
 * invalidates that ACK. Saved READY/EOF markers cannot reopen the guest TX
 * path; a fresh READY follows the authorized publication transaction. */
static int
pci_vtdtr_checkpoint_queue_plan(const struct pci_vtdtr_checkpoint_stage *stage,
    uint16_t destination_vmid, uint64_t destination_epoch,
    struct pci_vtdtr_ctrlq **output)
{
	struct pci_vtdtr_ctrlq *queue;
	struct pci_vtdtr_ctrl_entry *entry;
	struct pci_vtdtr_control *copy;
	int error = 0;

	if (stage == NULL || output == NULL || stage->source_vmid == 0 ||
	    stage->source_vmid >= HYPERTRACE_MAX_VMS ||
	    stage->source_epoch == 0 || destination_vmid == 0 ||
	    destination_vmid >= HYPERTRACE_MAX_VMS || destination_epoch == 0 ||
	    (stage->source_vmid == destination_vmid &&
	    stage->source_epoch == destination_epoch) ||
	    stage->count >= VTDTR_MAX_PENDING ||
	    (stage->count != 0 && stage->controls == NULL))
		return (EINVAL);
	*output = NULL;
	if (stage->partial_received != 0)
		return (EOPNOTSUPP);
	queue = calloc(1, sizeof(*queue));
	if (queue == NULL)
		return (ENOMEM);
	STAILQ_INIT(&queue->head);
	for (unsigned pass = 0; pass < 3; pass++) {
		uint32_t count = pass == 0 ? 1 : stage->count;
		for (uint32_t i = 0; i < count; i++) {
			const struct pci_vtdtr_control *saved =
			    pass == 0 ? NULL : &stage->controls[i];
			if (saved != NULL) {
				if (!pci_vtdtr_ctrl_checkpoint_valid(saved,
				    stage->source_vmid, stage->source_epoch)) {
					error = EPROTO;
					goto failed;
				}
				if ((pass == 1) !=
				    (saved->pvc_event == VTDTR_DEVICE_KILL))
					continue;
				if (saved->pvc_event ==
				    VTDTR_DEVICE_HOST_KILL_APPLIED ||
				    saved->pvc_event == VTDTR_DEVICE_READY ||
				    saved->pvc_event == VTDTR_DEVICE_EOF)
					continue;
			}
			entry = calloc(1, sizeof(*entry));
			copy = calloc(1, sizeof(*copy));
			if (entry == NULL || copy == NULL) {
				free(entry);
				free(copy);
				error = ENOMEM;
				goto failed;
			}
			if (saved == NULL) {
				copy->pvc_event = VTDTR_DEVICE_NODE_REKEY;
				copy->pvc_rekey_old_id = stage->source_vmid;
				copy->pvc_rekey_old_epoch = stage->source_epoch;
				copy->pvc_rekey_new_id = destination_vmid;
				copy->pvc_rekey_new_epoch = destination_epoch;
			} else {
				*copy = *saved;
				switch (copy->pvc_event) {
				case VTDTR_DEVICE_ELF:
					copy->pvc_vmid = destination_vmid;
					copy->pvc_epoch = destination_epoch;
					break;
				case VTDTR_DEVICE_KILL:
					copy->pvc_kill_vmid = destination_vmid;
					copy->pvc_kill_epoch = destination_epoch;
					break;
				case VTDTR_DEVICE_HOST_ELF:
					copy->pvc_installed_vmid = destination_vmid;
					copy->pvc_installed_epoch = destination_epoch;
					break;
				case VTDTR_DEVICE_CLEANUP_DTRACED:
					copy->pvc_cleanup_vmid = destination_vmid;
					copy->pvc_cleanup_epoch = destination_epoch;
					break;
				case VTDTR_DEVICE_READY:
				case VTDTR_DEVICE_EOF:
					break;
				default:
					free(copy);
					free(entry);
					error = EOPNOTSUPP;
					goto failed;
				}
			}
			if (!pci_vtdtr_ctrl_checkpoint_valid(copy,
			    destination_vmid, destination_epoch)) {
				free(copy);
				free(entry);
				error = EPROTO;
				goto failed;
			}
			entry->ctrl = copy;
			entry->restored_kill = saved != NULL &&
			    saved->pvc_event == VTDTR_DEVICE_KILL;
			entry->restored_control = true;
			entry->restored_elf_start = saved != NULL &&
			    saved->pvc_event == VTDTR_DEVICE_ELF &&
			    (i == 0 || stage->controls[i - 1].pvc_event !=
			    VTDTR_DEVICE_ELF ||
			    stage->controls[i - 1].pvc_elfhasmore == 0);
			pci_vtdtr_cq_enqueue(queue, entry);
		}
	}
	*output = queue;
	return (0);
failed:
	pci_vtdtr_checkpoint_queue_free(queue);
	return (error);
}

static int
pci_vtdtr_private_snapshot_stage(struct pci_vtdtr_softc *sc,
    struct vm_snapshot_meta *meta, struct pci_vtdtr_checkpoint_stage *stage)
{
	const uint8_t zero_id[16] = { 0 };
	struct pci_vtdtr_checkpoint_stage candidate = { 0 };
	struct pci_vtdtr_ctrl_entry *entry;
	struct pci_vtdtr_control control;
	uint8_t program_id[16] = { 0 }, source_id[16] = { 0 };
	uint8_t scratch[4096], guest_ready = 0, ready = 0;
	uint32_t magic = VTDTR_SNAPSHOT_MAGIC;
	uint16_t version = VTDTR_SNAPSHOT_VERSION, vmid = 0, partial_vmid = 0;
	uint64_t epoch = 0, cfg = 0, partial_epoch = 0, delivery = 0;
	uint32_t count = 0, total = 0, received = 0, identifier = 0;
	struct pci_vtdtr_elf_run run = { 0 };
	size_t remaining;
	int error;

	if (meta == NULL || (meta->op != VM_SNAPSHOT_SAVE &&
	    meta->op != VM_SNAPSHOT_VALIDATE))
		return (EINVAL);
	if (stage != NULL && (meta->op != VM_SNAPSHOT_VALIDATE ||
	    stage->controls != NULL || stage->partial_prefix != NULL ||
	    stage->count != 0 || stage->source_vmid != 0))
		return (EINVAL);
	if (meta->op == VM_SNAPSHOT_SAVE) {
		if (sc == NULL || (error =
		    (sc->vsd_session_stop_requested ? pci_vtdtr_session_source_valid(sc) :
		    pci_vtdtr_checkpoint_state_valid(sc))) != 0)
			return (sc == NULL ? EINVAL : error);
		if (vm_get_identity(sc->vsd_vmctx, &vmid, &epoch) != 0)
			return (ESTALE);
		cfg = sc->vsd_cfg;
		guest_ready = sc->vsd_guest_ready != 0;
		ready = sc->vsd_ready != 0;
		count = (uint32_t)sc->vsd_ctrlq->count;
		if (sc->vsd_inbound_elf.data != NULL) {
			total = (uint32_t)sc->vsd_inbound_elf.total;
			received = (uint32_t)sc->vsd_inbound_elf.received;
			identifier = sc->vsd_inbound_elf.identifier;
			delivery = sc->vsd_inbound_delivery_id;
			partial_vmid = sc->vsd_inbound_vmid;
			partial_epoch = sc->vsd_inbound_epoch;
			memcpy(program_id, sc->vsd_inbound_program_id, 16);
			memcpy(source_id, sc->vsd_inbound_source_id, 16);
		}
	}
	SNAPSHOT_LE32_OR_LEAVE(magic, meta, error, done);
	SNAPSHOT_LE16_OR_LEAVE(version, meta, error, done);
	SNAPSHOT_LE16_OR_LEAVE(vmid, meta, error, done);
	SNAPSHOT_LE64_OR_LEAVE(epoch, meta, error, done);
	SNAPSHOT_LE64_OR_LEAVE(cfg, meta, error, done);
	SNAPSHOT_U8_OR_LEAVE(guest_ready, meta, error, done);
	SNAPSHOT_U8_OR_LEAVE(ready, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(count, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(total, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(received, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(identifier, meta, error, done);
	SNAPSHOT_LE64_OR_LEAVE(delivery, meta, error, done);
	SNAPSHOT_LE16_OR_LEAVE(partial_vmid, meta, error, done);
	SNAPSHOT_LE64_OR_LEAVE(partial_epoch, meta, error, done);
	SNAPSHOT_BUF_OR_LEAVE(program_id, sizeof(program_id), meta,
	    error, done);
	SNAPSHOT_BUF_OR_LEAVE(source_id, sizeof(source_id), meta,
	    error, done);
	if (magic != VTDTR_SNAPSHOT_MAGIC ||
	    version != VTDTR_SNAPSHOT_VERSION ||
	    vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0 ||
	    guest_ready > 1 || ready > 1 || count > VTDTR_MAX_PENDING ||
	    (total == 0 ?
	    (received != 0 || identifier != 0 || delivery != 0 ||
	    partial_vmid != 0 || partial_epoch != 0 ||
	    memcmp(program_id, zero_id, 16) != 0 ||
	    memcmp(source_id, zero_id, 16) != 0) :
	    (total > HYPERTRACE_ELF_MAX || received == 0 ||
	    received >= total || delivery == 0 || partial_vmid != vmid ||
	    partial_epoch != epoch ||
	    memcmp(program_id, zero_id, 16) == 0 ||
	    memcmp(source_id, zero_id, 16) == 0))) {
		error = EPROTO;
		goto done;
	}
	if (meta->op == VM_SNAPSHOT_SAVE) {
		if (received != 0)
			SNAPSHOT_BUF_OR_LEAVE(sc->vsd_inbound_elf.data,
			    received, meta, error, done);
	} else if (stage != NULL && received != 0) {
		if (meta->buffer.buf_rem < received) {
			error = E2BIG;
			goto done;
		}
		candidate.partial_prefix = malloc(received);
		if (candidate.partial_prefix == NULL) {
			error = ENOMEM;
			goto done;
		}
		candidate.partial_received = received;
		SNAPSHOT_BUF_OR_LEAVE(candidate.partial_prefix, received,
		    meta, error, done);
	} else {
		remaining = received;
		while (remaining != 0) {
			size_t chunk = remaining < sizeof(scratch) ?
			    remaining : sizeof(scratch);
			SNAPSHOT_BUF_OR_LEAVE(scratch, chunk, meta,
			    error, done);
			remaining -= chunk;
		}
	}
	if (meta->op == VM_SNAPSHOT_SAVE) {
		STAILQ_FOREACH(entry, &sc->vsd_ctrlq->head, entries) {
			error = pci_vtdtr_snapshot_control(entry->ctrl,
			    meta, vmid, epoch);
			if (error != 0)
				goto done;
		}
	} else if (stage != NULL) {
		if (count > meta->buffer.buf_rem / sizeof(uint32_t)) {
			error = E2BIG;
			goto done;
		}
		/* Reject a short or corrupt queue before allocating count full
		 * controls from an untrusted image.  Four bytes per event above is
		 * only a cheap bound; actual records have variable lengths. */
		struct vm_snapshot_meta scan = *meta;
		for (uint32_t i = 0; i < count; i++) {
			memset(&control, 0, sizeof(control));
			error = pci_vtdtr_snapshot_control(&control,
			    &scan, vmid, epoch);
			if (error != 0)
				goto done;
			if (!pci_vtdtr_elf_run_advance(&run, &control)) {
				error = EPROTO;
				goto done;
			}
		}
		if (run.open) {
			error = EPROTO;
			goto done;
		}
		if (count != 0) {
			candidate.controls = calloc(count,
			    sizeof(*candidate.controls));
			if (candidate.controls == NULL) {
				error = ENOMEM;
				goto done;
			}
		}
		for (uint32_t i = 0; i < count; i++) {
			error = pci_vtdtr_snapshot_control(
			    &candidate.controls[i], meta, vmid, epoch);
			if (error != 0)
				goto done;
		}
		if (scan.buffer.buf != meta->buffer.buf ||
		    scan.buffer.buf_rem != meta->buffer.buf_rem) {
			error = EPROTO;
			goto done;
		}
	} else {
		for (uint32_t i = 0; i < count; i++) {
			memset(&control, 0, sizeof(control));
			error = pci_vtdtr_snapshot_control(&control,
			    meta, vmid, epoch);
			if (error != 0)
				goto done;
			if (!pci_vtdtr_elf_run_advance(&run, &control)) {
				error = EPROTO;
				goto done;
			}
		}
		if (run.open) {
			error = EPROTO;
			goto done;
		}
	}
	if (stage != NULL) {
		candidate.count = count;
		candidate.source_vmid = vmid;
		candidate.source_epoch = epoch;
		candidate.cfg = cfg;
		candidate.guest_ready = guest_ready;
		candidate.ready = ready;
		candidate.partial_total = total;
		candidate.partial_received = received;
		candidate.partial_identifier = identifier;
		candidate.partial_delivery_id = delivery;
		candidate.partial_vmid = partial_vmid;
		candidate.partial_epoch = partial_epoch;
		memcpy(candidate.program_id, program_id, 16);
		memcpy(candidate.source_id, source_id, 16);
		*stage = candidate;
		memset(&candidate, 0, sizeof(candidate));
	}
	error = 0;
done:
	if (error != 0)
		pci_vtdtr_checkpoint_stage_clear(&candidate);
	return (error);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* Both operations stage the same immutable image. Query requires RESERVE;
 * binding requires MUTATE and remains separate from device publication. */
static int
pci_vtdtr_checkpoint_private_image_operation(void *image, size_t length,
    struct vmctx *ctx, const uint8_t token[16], const uint8_t digest[32],
    bool bind)
{
	struct pci_vtdtr_checkpoint_stage stage = { 0 };
	struct pci_vtdtr_ctrlq *queue = NULL;
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = image,
			.buf_size = length,
			.buf = image,
			.buf_rem = length,
		},
		.op = VM_SNAPSHOT_VALIDATE,
	};
	uint16_t destination_vmid;
	uint64_t destination_epoch;
	int error;

	if (image == NULL || length == 0 || ctx == NULL)
		return (EINVAL);
	error = pci_vtdtr_private_snapshot_stage(NULL, &meta, &stage);
	if (error == 0 && meta.buffer.buf_rem != 0)
		error = EPROTO;
	if (error == 0) {
		if (vm_get_identity(ctx, &destination_vmid,
		    &destination_epoch) != 0)
			error = ESTALE;
		else
			error = pci_vtdtr_checkpoint_queue_plan(&stage,
			    destination_vmid, destination_epoch, &queue);
	}
	pci_vtdtr_checkpoint_queue_free(queue);
	if (error == 0)
		error = bind ? pci_vtdtr_checkpoint_stage_bind(&stage, ctx,
		    token, digest) : pci_vtdtr_checkpoint_stage_query(&stage,
		    ctx, token, digest);
	pci_vtdtr_checkpoint_stage_clear(&stage);
	return (error);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
int
pci_vtdtr_checkpoint_private_image_replay_room(void *image, size_t length,
    size_t projected)
{
	struct pci_vtdtr_checkpoint_stage stage = { 0 };
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = image,
			.buf_size = length,
			.buf = image,
			.buf_rem = length,
		},
		.op = VM_SNAPSHOT_VALIDATE,
	};
	size_t planned = 1; /* NODE_REKEY precedes every saved control. */
	int error;

	if (image == NULL || length == 0)
		return (EINVAL);
	error = pci_vtdtr_private_snapshot_stage(NULL, &meta, &stage);
	if (error == 0 && meta.buffer.buf_rem != 0)
		error = EPROTO;
	if (error == 0 && stage.partial_received != 0)
		error = EOPNOTSUPP;
	if (error == 0) {
		for (uint32_t i = 0; i < stage.count; i++) {
			switch (stage.controls[i].pvc_event) {
			case VTDTR_DEVICE_HOST_KILL_APPLIED:
			case VTDTR_DEVICE_READY:
			case VTDTR_DEVICE_EOF:
				break;
			default:
				planned++;
				break;
			}
		}
		/* One queued receipt and one publication slot must remain while
		 * imported ELF replay drains behind the guest startup fence. */
		if (planned >= VTDTR_MAX_PENDING - 2 ||
		    projected >= VTDTR_MAX_PENDING - 2 - planned)
			error = ENOBUFS;
	}
	pci_vtdtr_checkpoint_stage_clear(&stage);
	return (error);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
int
pci_vtdtr_checkpoint_private_image_query(void *image, size_t length,
    struct vmctx *ctx, const uint8_t token[16], const uint8_t digest[32])
{
	return (pci_vtdtr_checkpoint_private_image_operation(image, length,
	    ctx, token, digest, false));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
int
pci_vtdtr_checkpoint_private_image_bind(void *image, size_t length,
    struct vmctx *ctx, const uint8_t token[16], const uint8_t digest[32])
{
	return (pci_vtdtr_checkpoint_private_image_operation(image, length,
	    ctx, token, digest, true));
}

static int
pci_vtdtr_private_snapshot(struct pci_vtdtr_softc *sc,
    struct vm_snapshot_meta *meta)
{
	return (pci_vtdtr_private_snapshot_stage(sc, meta, NULL));
}

/* Called only while the common VirtIO checkpoint pause owns vsd_mtx and
 * destination vCPUs are fenced. Parsing must not publish a saved control
 * before the daemon has claimed and bound this destination. */
static bool
pci_vtdtr_session_image_matches(const struct pci_vtdtr_checkpoint_stage *stage,
    const struct hypertrace_session_record *record)
{
	return (stage->source_vmid == record->vmid &&
	    stage->source_epoch == record->epoch && stage->count == 0 &&
	    stage->partial_total == 0 && !stage->guest_ready && !stage->ready);
}

/* Preflight before mutating guest memory. The caller owns the device pause;
 * only a canonical empty image may select the non-replaying restore path. */
static int
pci_vtdtr_session_restore_stage_impl(struct pci_devinst *pi,
    const void *record_bytes, size_t record_length, void *image, size_t length,
    bool migration)
{
	struct pci_vtdtr_softc *sc;
	struct hypertrace_session_record record;
	struct pci_vtdtr_checkpoint_stage stage = {0};
	struct vm_snapshot_meta scan = {
	    .buffer = {.buf_start = image, .buf_size = length,
	        .buf = image, .buf_rem = length}, .op = VM_SNAPSHOT_VALIDATE };
	uint16_t vmid;
	uint64_t epoch;
	int error;

	if (!pci_vtdtr_checkpoint_is_device(pi) || (sc = pi->pi_arg) == NULL ||
	    image == NULL || length == 0 || sc->vsd_vs.vs_pi != pi)
		return (EINVAL);
	if (!sc->vsd_checkpoint_paused || sc->vsd_reader_active ||
	    sc->vsd_session_restore_staged || sc->vsd_session_migration_staged ||
	    sc->vsd_restore_planned != NULL ||
	    sc->vsd_session_stop_requested || sc->vsd_session_collectors_busy ||
	    sc->vsd_session_restore_pending || sc->vsd_fresh_requested ||
	    sc->vsd_handoff_ticket_valid || sc->vsd_ticket_wait ||
	    sc->vsd_cleanup_unapplied || sc->vsd_rekey_ack_pending ||
	    sc->vsd_rekey_ack_sent || sc->vsd_rekey_receipt_reply_pending)
		return (EBUSY);
	error = hypertrace_session_record_decode(record_bytes, record_length, &record);
	if (error == 0)
		error = pci_vtdtr_checkpoint_state_valid(sc);
	if (error == 0 && vm_get_identity(sc->vsd_vmctx, &vmid, &epoch) != 0)
		error = errno != 0 ? errno : EIO;
	if (error == 0 && epoch == record.epoch)
		error = ESTALE;
	if (error == 0 && !migration &&
	    hypertrace_session_retired(record.vmid, record.epoch) != 0)
		error = errno != 0 ? errno : EIO;
	if (error == 0)
		error = pci_vtdtr_private_snapshot_stage(NULL, &scan, &stage);
	if (error == 0 && (scan.buffer.buf_rem != 0 ||
	    !pci_vtdtr_session_image_matches(&stage, &record)))
		error = EPROTO;
	if (error == 0)
		error = pci_vtdtr_fresh_gate_hold(sc, vmid, epoch);
	if (error == 0) {
		memcpy(sc->vsd_session_restore_record, record_bytes, record_length);
		sc->vsd_session_restore_cfg = stage.cfg;
		sc->vsd_session_restore_staged = true;
		if (migration) {
			memcpy(sc->vsd_session_migration_record, record_bytes, record_length);
			sc->vsd_session_migration_staged = true;
			sc->vsd_session_migration_released = false;
		}
	}
	pci_vtdtr_checkpoint_stage_clear(&stage);
	return (error);
}

int
pci_vtdtr_session_restore_stage_paused(struct pci_devinst *pi,
    const void *record, size_t record_length, void *image, size_t length)
{
	return (pci_vtdtr_session_restore_stage_impl(pi, record, record_length,
	    image, length, false));
}

/* Migration may prepare before source retirement, but resume/attach remain
 * closed until the coordinator validates RELEASE on its trusted stream. */
int
pci_vtdtr_session_migration_stage_paused(struct pci_devinst *pi,
    const void *record, size_t record_length, void *image, size_t length)
{
	return (pci_vtdtr_session_restore_stage_impl(pi, record, record_length,
	    image, length, true));
}

int
pci_vtdtr_session_migration_release_paused(struct pci_devinst *pi,
    const void *record, size_t length)
{
	struct pci_vtdtr_softc *sc;
	int error;

	if (!pci_vtdtr_checkpoint_is_device(pi) || (sc = pi->pi_arg) == NULL ||
	    record == NULL || length != HYPERTRACE_SESSION_RECORD_SIZE)
		return (EINVAL);
	if (!sc->vsd_checkpoint_paused || sc->vsd_reader_active ||
	    !sc->vsd_session_migration_staged || sc->vsd_session_restore_staged ||
	    sc->vsd_session_restore_pending || !sc->vsd_session_stopped ||
	    sc->vsd_stopping || sc->vsd_fresh_requested ||
	    (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		return (EBUSY);
	if (memcmp(record, sc->vsd_session_migration_record, length) != 0)
		return (ESTALE);
	error = pci_vtdtr_fresh_gate_check(sc);
	if (error == 0)
		sc->vsd_session_migration_released = true;
	return (error);
}

static int
pci_vtdtr_session_private_restore(struct pci_vtdtr_softc *sc,
    struct vm_snapshot_meta *meta)
{
	struct hypertrace_session_record record;
	struct pci_vtdtr_checkpoint_stage stage = {0};
	struct vm_snapshot_meta scan = *meta;
	int error;

	if (!sc->vsd_checkpoint_paused || sc->vsd_reader_active ||
	    !sc->vsd_session_restore_staged || meta->op != VM_SNAPSHOT_RESTORE)
		return (EBUSY);
	error = hypertrace_session_record_decode(sc->vsd_session_restore_record,
	    sizeof(sc->vsd_session_restore_record), &record);
	if (error == 0)
		error = pci_vtdtr_fresh_gate_check(sc);
	scan.op = VM_SNAPSHOT_VALIDATE;
	if (error == 0)
		error = pci_vtdtr_private_snapshot_stage(NULL, &scan, &stage);
	if (error == 0 && (!pci_vtdtr_session_image_matches(&stage, &record) ||
	    stage.cfg != sc->vsd_session_restore_cfg))
		error = EPROTO;
	if (error == 0)
		error = pci_vtdtr_session_checkpoint_import_paused(sc->vsd_vs.vs_pi,
		    sc->vsd_session_restore_record, sizeof(sc->vsd_session_restore_record));
	if (error == 0) {
		sc->vsd_cfg = stage.cfg;
		sc->vsd_session_restore_staged = false;
		explicit_bzero(sc->vsd_session_restore_record,
		    sizeof(sc->vsd_session_restore_record));
		meta->buffer.buf = scan.buffer.buf;
		meta->buffer.buf_rem = scan.buffer.buf_rem;
	}
	pci_vtdtr_checkpoint_stage_clear(&stage);
	return (error);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Reached only from
 * transfer-ticket replay (NODE_REKEY / restored KILLs), which restore
 * refuses, so this is intentionally unreachable until enabled. */
static int
pci_vtdtr_private_snapshot_restore(struct pci_vtdtr_softc *sc,
    struct vm_snapshot_meta *meta)
{
	struct pci_vtdtr_checkpoint_stage stage = { 0 };
	struct pci_vtdtr_ctrlq *planned = NULL;
	struct vm_snapshot_meta scan = meta != NULL ? *meta :
	    (struct vm_snapshot_meta){ 0 };
	uint16_t vmid;
	uint64_t epoch;
	int error;

	if (sc == NULL || meta == NULL ||
	    meta->op != VM_SNAPSHOT_RESTORE || !sc->vsd_checkpoint_paused ||
	    sc->vsd_reader_active || sc->vsd_stopping ||
	    sc->vsd_ctrlq == NULL || sc->vsd_rekey_wait ||
	    sc->vsd_restored_kill_wait ||
	    sc->vsd_rekey_ack_pending || sc->vsd_rekey_ack_sent ||
	    sc->vsd_rekey_receipt_reply_pending || sc->vsd_ticket_wait ||
	    sc->vsd_handoff_ticket_valid ||
	    sc->vsd_restore_planned != NULL ||
	    sc->vsd_inbound_elf.data != NULL)
		return (EBUSY);
	/* A fresh destination must not inherit a malformed or stale queue or
	 * inbound upload, even when the latter has no allocated data buffer. */
	error = pci_vtdtr_checkpoint_state_valid(sc);
	if (error != 0)
		return (error);
	scan.op = VM_SNAPSHOT_VALIDATE;
	error = pci_vtdtr_private_snapshot_stage(NULL, &scan, &stage);
	if (error == 0 && vm_get_identity(sc->vsd_vmctx,
	    &vmid, &epoch) != 0)
		error = ESTALE;
	if (error == 0)
		error = pci_vtdtr_checkpoint_queue_plan(&stage,
		    vmid, epoch, &planned);
	if (error == 0) {
		sc->vsd_restore_planned = planned;
		sc->vsd_restore_cfg = stage.cfg;
		sc->vsd_restore_vmid = vmid;
		sc->vsd_restore_epoch = epoch;
		planned = NULL;
		meta->buffer.buf = scan.buffer.buf;
		meta->buffer.buf_rem = scan.buffer.buf_rem;
	}
	pci_vtdtr_checkpoint_queue_free(planned);
	pci_vtdtr_checkpoint_stage_clear(&stage);
	return (error);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* Publish after daemon CLAIM, saved-control binding, admission replay, and
 * ticket attachment. The pause still owns vsd_mtx; the reader and guest
 * vCPUs cannot observe a half cut. */
static int
pci_vtdtr_checkpoint_publish_sc_paused(struct pci_vtdtr_softc *sc)
{
	struct pci_vtdtr_ctrlq *old;
	uint16_t vmid;
	uint64_t epoch;
	bool pending;
	int error;

	if (sc == NULL || !sc->vsd_checkpoint_paused || sc->vsd_reader_active ||
	    sc->vsd_stopping || sc->vsd_restore_planned == NULL ||
	    sc->vsd_ctrlq == NULL)
		return (EBUSY);
	error = pci_vtdtr_checkpoint_features_validate(
	    sc->vsd_vs.vs_negotiated_caps);
	if (error != 0)
		return (error);
	if (vm_get_identity(sc->vsd_vmctx, &vmid, &epoch) != 0 ||
	    vmid != sc->vsd_restore_vmid || epoch != sc->vsd_restore_epoch)
		return (ESTALE);
	if (sc->vsd_handoff_ticket_valid &&
	    (sc->vsd_handoff_vmid != vmid ||
	    sc->vsd_handoff_epoch != epoch))
		return (ESTALE);
	error = pci_vtdtr_checkpoint_state_valid(sc);
	if (error != 0)
		return (error);
	/* A caller must not publish saved controls before the attested daemon
	 * ticket is attached to this destination incarnation. */
	if (!sc->vsd_handoff_ticket_valid)
		return (EACCES);
	/* Guest memory and the VirtIO ring image are installed by this point.
	 * Refuse a queued guest-to-host control before publishing the private
	 * queue: source SAVE cannot transfer such a control either. */
	error = vq_checkpoint_has_descs(&sc->vsd_queues[1], &pending);
	if (error != 0)
		return (error);
	if (pending)
		return (EBUSY);
	old = sc->vsd_ctrlq;
	sc->vsd_ctrlq = sc->vsd_restore_planned;
	sc->vsd_restore_planned = NULL;
	sc->vsd_cfg = sc->vsd_restore_cfg;
	sc->vsd_restore_cfg = 0;
	sc->vsd_restore_vmid = 0;
	sc->vsd_restore_epoch = 0;
	sc->vsd_guest_ready = 0;
	sc->vsd_ready = 0;
	sc->vsd_rekey_wait = false;
	sc->vsd_restored_kill_wait = false;
	sc->vsd_restored_kill_pid = 0;
	memset(sc->vsd_restored_kill_source_id, 0,
	    sizeof(sc->vsd_restored_kill_source_id));
	sc->vsd_restored_kill_deadline = (struct timespec){ 0 };
	sc->vsd_rekey_ack_pending = false;
	sc->vsd_rekey_ack_sent = false;
	sc->vsd_rekey_old_id = sc->vsd_rekey_new_id = 0;
	sc->vsd_rekey_old_epoch = sc->vsd_rekey_new_epoch = 0;
	sc->vsd_rekey_deadline = (struct timespec){ 0 };
	sc->vsd_generation++;
	pci_vtdtr_checkpoint_queue_free(old);
	pthread_cond_broadcast(&sc->vsd_cond);
	return (0);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
int
pci_vtdtr_checkpoint_publish_paused(struct pci_devinst *pi)
{
	if (!pci_vtdtr_checkpoint_is_device(pi))
		return (EINVAL);
	return (pci_vtdtr_checkpoint_publish_sc_paused(pi->pi_arg));
}
#endif

/* Never expose a restored NODE_REKEY to the guest before the validated
 * handoff ticket is attached to this exact device. Caller owns vsd_mtx. */
static bool
pci_vtdtr_rekey_head_awaits_ticket(struct pci_vtdtr_softc *sc)
{
	struct pci_vtdtr_ctrl_entry *entry;

	if (sc->vsd_handoff_ticket_valid ||
	    (entry = STAILQ_FIRST(&sc->vsd_ctrlq->head)) == NULL)
		return (false);
	if (entry->ctrl->pvc_event != VTDTR_DEVICE_NODE_REKEY)
		return (false);
	if (!sc->vsd_ticket_wait) {
		if (clock_gettime(CLOCK_MONOTONIC,
		    &sc->vsd_ticket_deadline) != 0)
			sc->vsd_ticket_deadline = (struct timespec){ 0 };
		else
			sc->vsd_ticket_deadline.tv_sec +=
			    PCI_VTDTR_REKEY_TIMEOUT_SEC;
		sc->vsd_ticket_wait = true;
	}
	return (true);
}

/*
 * The communicator thread that is created when we attach the PCI device. It
 * serves the purpose of draining the control queue of messages and filling the
 * guest memory with the descriptors.
 */
static void *
pci_vtdtr_run(void *xsc)
{
	struct pci_vtdtr_softc *sc = xsc;
	struct vqueue_info *vq = &sc->vsd_queues[0];
	struct pci_vtdtr_ctrl_entry *entry;
	unsigned int count, budget;
	int ready;
	bool rekey, restored_kill;
	uint16_t vmid;
	uint64_t epoch;

	pthread_mutex_lock(&sc->vsd_mtx);
	while (!sc->vsd_stopping) {
		while (!sc->vsd_stopping && (sc->vsd_suspended ||
		    (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) ||
		    (!(sc->vsd_fresh_active && !sc->vsd_fresh_released &&
		    !sc->vsd_fresh_release_busy) && (!vq_has_descs(vq) ||
		    (!sc->vsd_rekey_ack_pending &&
		    !sc->vsd_rekey_receipt_reply_pending &&
		    (sc->vsd_rekey_wait || sc->vsd_restored_kill_wait ||
		    /* Nothing is delivered until the guest applies CLEANUP; the
		     * receive path clears the flag and signals vsd_cond. */
		    sc->vsd_cleanup_unapplied ||
		    !sc->vsd_guest_ready ||
		    pci_vtdtr_cq_empty(sc->vsd_ctrlq) ||
		    pci_vtdtr_rekey_head_awaits_ticket(sc))))))) {
			if (sc->vsd_fresh_requested && !sc->vsd_fresh_active &&
			    !sc->vsd_suspended &&
			    !(sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET)) {
				int error = pthread_cond_timedwait(&sc->vsd_cond,
				    &sc->vsd_mtx, &sc->vsd_fresh_deadline);
				if (error != 0)
					vi_set_needs_reset(&sc->vsd_vs);
			} else if (sc->vsd_rekey_wait || sc->vsd_restored_kill_wait ||
			    sc->vsd_ticket_wait) {
				int error = pthread_cond_timedwait(&sc->vsd_cond,
				    &sc->vsd_mtx, sc->vsd_rekey_wait ?
				    &sc->vsd_rekey_deadline :
				    sc->vsd_restored_kill_wait ?
				    &sc->vsd_restored_kill_deadline :
				    &sc->vsd_ticket_deadline);
				if (error != 0)
					pci_vtdtr_rekey_quarantine(sc);
			} else
				pthread_cond_wait(&sc->vsd_cond, &sc->vsd_mtx);
		}
		if (sc->vsd_stopping)
			break;
		if (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET)
			continue;
		if (sc->vsd_fresh_active && !sc->vsd_fresh_released &&
		    !sc->vsd_fresh_release_busy) {
			/* The guest is running now. No queue descriptor is needed to
			 * finish authorization, and the RPC must not hold vsd_mtx. */
			pthread_mutex_unlock(&sc->vsd_mtx);
			int error = pci_vtdtr_session_authorize(sc->vsd_vmctx);
			if (error != 0)
				error = pci_vtdtr_session_authorize(sc->vsd_vmctx);
			pthread_mutex_lock(&sc->vsd_mtx);
			if (error != 0 && !sc->vsd_stopping)
				vi_set_needs_reset(&sc->vsd_vs);
			continue;
		}
		/* Trace continuity (disabled future feature): rekey state comes only from transfer-ticket replay, which restore refuses. */
		if (sc->vsd_rekey_wait && pci_vtdtr_rekey_expired(sc)) {
			pci_vtdtr_rekey_quarantine(sc);
			continue;
		}
		/* Trace continuity (disabled future feature): restored KILLs come only from transfer-ticket replay, which restore refuses. */
		if (sc->vsd_restored_kill_wait &&
		    pci_vtdtr_deadline_expired(&sc->vsd_restored_kill_deadline)) {
			pci_vtdtr_rekey_quarantine(sc);
			continue;
		}
		/* Trace continuity (disabled future feature): rekey state comes only from transfer-ticket replay, which restore refuses. */
		if (sc->vsd_rekey_receipt_reply_pending) {
			if (!sc->vsd_rekey_wait ||
			    !sc->vsd_handoff_ticket_valid ||
			    vm_get_identity(sc->vsd_vmctx, &vmid, &epoch) != 0 ||
			    vmid != sc->vsd_rekey_new_id ||
			    epoch != sc->vsd_rekey_new_epoch ||
			    !pci_vtdtr_fill_desc(vq,
			    &sc->vsd_rekey_receipt_reply)) {
				pci_vtdtr_rekey_quarantine(sc);
				continue;
			}
			sc->vsd_rekey_receipt_reply_pending = false;
		explicit_bzero(&sc->vsd_rekey_receipt_reply,
			    sizeof(sc->vsd_rekey_receipt_reply));
			pci_vtdtr_poll(vq, 1);
			pthread_cond_broadcast(&sc->vsd_cond);
			continue;
		}
		/* Trace continuity (disabled future feature): rekey state comes only from transfer-ticket replay, which restore refuses. */
		if (sc->vsd_rekey_ack_pending) {
			struct pci_vtdtr_control ack = { 0 };

			if (vm_get_identity(sc->vsd_vmctx, &vmid, &epoch) != 0 ||
			    vmid != sc->vsd_rekey_new_id ||
			    epoch != sc->vsd_rekey_new_epoch) {
				pci_vtdtr_rekey_quarantine(sc);
				continue;
			}
			ack.pvc_event = VTDTR_DEVICE_REKEY_COMMITTED;
			ack.pvc_rekey_old_id = sc->vsd_rekey_old_id;
			ack.pvc_rekey_old_epoch = sc->vsd_rekey_old_epoch;
			ack.pvc_rekey_new_id = sc->vsd_rekey_new_id;
			ack.pvc_rekey_new_epoch = sc->vsd_rekey_new_epoch;
			if (!pci_vtdtr_fill_desc(vq, &ack)) {
				pci_vtdtr_rekey_quarantine(sc);
				continue;
			}
			sc->vsd_rekey_ack_pending = false;
			sc->vsd_rekey_ack_sent = true;
			pci_vtdtr_poll(vq, 1);
			pthread_cond_broadcast(&sc->vsd_cond);
			continue;
		}
		/* Queue contents may have been assembled under an older VM epoch.
		 * Validate the whole batch before exposing any of it to the guest. */
		if (vm_get_identity(sc->vsd_vmctx, &vmid, &epoch) != 0 ||
		    vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0) {
			vi_set_needs_reset(&sc->vsd_vs);
			pci_vtdtr_reset_queue(sc);
			pthread_cond_broadcast(&sc->vsd_cond);
			continue;
		}
		unsigned int checked = 0;
		STAILQ_FOREACH(entry, &sc->vsd_ctrlq->head, entries) {
			if (checked++ >= vq->vq_qsize)
				break;
			if (!pci_vtdtr_ctrl_matches_vm(entry->ctrl, vmid, epoch)) {
				vi_set_needs_reset(&sc->vsd_vs);
				pci_vtdtr_reset_queue(sc);
				pthread_cond_broadcast(&sc->vsd_cond);
				break;
			}
		}
		if (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET)
			continue;
		count = 0;
		ready = 1;
		budget = vq->vq_qsize;
		while (budget-- != 0 && vq_has_descs(vq) &&
		    !pci_vtdtr_cq_empty(sc->vsd_ctrlq) &&
		    !sc->vsd_cleanup_unapplied) {
			entry = STAILQ_FIRST(&sc->vsd_ctrlq->head);
			if (!pci_vtdtr_fill_desc(vq, entry->ctrl))
				break;
			(void)pci_vtdtr_cq_dequeue(sc->vsd_ctrlq);
			if (entry->ctrl->pvc_event == VTDTR_DEVICE_SESSION_STOP)
				sc->vsd_session_stop_delivered = true;
			if (entry->ctrl->pvc_event == VTDTR_DEVICE_SESSION_PREPARE)
				sc->vsd_fresh_prepare_delivered = true;
			if (entry->ctrl->pvc_event == VTDTR_DEVICE_SESSION_COMMIT)
				sc->vsd_fresh_commit_delivered = true;
			if (entry->ctrl->pvc_event != VTDTR_DEVICE_READY)
				ready = 0;
			if (entry->ctrl->pvc_event ==
			    VTDTR_DEVICE_CLEANUP_DTRACED) {
				sc->vsd_cleanup_unapplied = true;
				sc->vsd_cleanup_previous_delivery_id =
				    sc->vsd_cleanup_delivery_id;
				sc->vsd_cleanup_delivery_id =
				    entry->ctrl->pvc_cleanup_delivery_id;
			}
			rekey = entry->ctrl->pvc_event ==
			    VTDTR_DEVICE_NODE_REKEY;
			restored_kill = entry->restored_kill;
			/* Trace continuity (disabled future feature): rekey state comes only from transfer-ticket replay, which restore refuses. */
			if (rekey) {
				sc->vsd_rekey_old_id =
				    entry->ctrl->pvc_rekey_old_id;
				sc->vsd_rekey_old_epoch =
				    entry->ctrl->pvc_rekey_old_epoch;
				sc->vsd_rekey_new_id =
				    entry->ctrl->pvc_rekey_new_id;
				sc->vsd_rekey_new_epoch =
				    entry->ctrl->pvc_rekey_new_epoch;
				sc->vsd_rekey_ack_pending = false;
				sc->vsd_rekey_ack_sent = false;
			}
			/* Trace continuity (disabled future feature): restored KILLs come only from transfer-ticket replay, which restore refuses. */
			if (restored_kill) {
				sc->vsd_restored_kill_wait = true;
				sc->vsd_restored_kill_pid = entry->ctrl->pvc_pid;
				memcpy(sc->vsd_restored_kill_source_id,
				    entry->ctrl->pvc_source_id, 16);
			}
			free(entry->ctrl);
			free(entry);
			count++;
			/* Trace continuity (disabled future feature): rekey state comes only from transfer-ticket replay, which restore refuses. */
			if (rekey) {
				/* No later control or EOF may share this batch. */
				sc->vsd_rekey_wait = true;
				if (clock_gettime(CLOCK_MONOTONIC,
				    &sc->vsd_rekey_deadline) != 0) {
					pci_vtdtr_rekey_quarantine(sc);
				} else
					sc->vsd_rekey_deadline.tv_sec +=
					    PCI_VTDTR_REKEY_TIMEOUT_SEC;
				break;
			}
			/* Trace continuity (disabled future feature): restored KILLs come only from transfer-ticket replay, which restore refuses. */
			if (restored_kill) {
				/* The next saved control may be an ELF. Wait until the
				 * destination guest applies this exact revocation and the
				 * host daemon accepts its KILL_APPLIED observation. */
				if (clock_gettime(CLOCK_MONOTONIC,
				    &sc->vsd_restored_kill_deadline) != 0)
					pci_vtdtr_rekey_quarantine(sc);
				else
					sc->vsd_restored_kill_deadline.tv_sec +=
					    PCI_VTDTR_REKEY_TIMEOUT_SEC;
				break;
			}
		}
		if (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET)
			continue;
		if (count != 0) {
			if (!sc->vsd_rekey_wait &&
			    !sc->vsd_restored_kill_wait &&
			    pci_vtdtr_cq_empty(sc->vsd_ctrlq) && vq_has_descs(vq))
				pci_vtdtr_fill_eof_desc(vq);
			sc->vsd_guest_ready = ready;
		}
		pci_vtdtr_poll(vq, !vq_has_descs(vq));
		pthread_cond_broadcast(&sc->vsd_cond);
	}
	pthread_mutex_unlock(&sc->vsd_mtx);
	return (NULL);
}

/*
 * A simple wrapper function used to reset the control queue
 */
static void
pci_vtdtr_reset_queue(struct pci_vtdtr_softc *sc)
{
	struct pci_vtdtr_ctrl_entry *entry;

	while ((entry = pci_vtdtr_cq_dequeue(sc->vsd_ctrlq)) != NULL) {
		free(entry->ctrl);
		free(entry);
	}
}

static struct pci_vtdtr_control *
vtdtr_elf_event(void *buf, size_t size, size_t offs)
{
	struct pci_vtdtr_control *ctrl;
	size_t maxlen;
	size_t len_to_read;
	uintptr_t current;
	int hasmore;

	ctrl = NULL;

	/*
	 * Compute how much we'll actually be reading.
	 */
	maxlen = size - offs;
	len_to_read = maxlen > PCI_VTDTR_MAXELFLEN ?
	    PCI_VTDTR_MAXELFLEN : maxlen;
	hasmore = maxlen > PCI_VTDTR_MAXELFLEN ? 1 : 0;

	/*
	 * Allocate the control message with the appropriate size to fit
	 * all of the data that we'll be reading in.
	 */
	ctrl = malloc(sizeof(struct pci_vtdtr_control));
	if (ctrl == NULL) {
		fprintf(stderr, "failed to malloc a new control event\n");
		return (NULL);
	}

	/*
	 * Zero the control event.
	 */
	memset(ctrl, 0, sizeof(struct pci_vtdtr_control));
	current = ((uintptr_t)buf) + offs;
	memcpy(ctrl->pvc_elf, (void *)current, len_to_read);

	/*
	 * At this point, we will have returned NULL in any case of failure,
	 * so we don't need to check anything further and can fill in the full
	 * control message and return it.
	 */
	ctrl->pvc_event = VTDTR_DEVICE_ELF;
	ctrl->pvc_elflen = len_to_read;
	ctrl->pvc_totalelflen = size;
	ctrl->pvc_elfhasmore = hasmore;
	return (ctrl);
}

static struct pci_vtdtr_control *
vtdtr_kill_event(pid_t pid, uint16_t vmid, uint64_t epoch,
    const uint8_t source_id[16])
{
	struct pci_vtdtr_control *ctrl;

	ctrl = malloc(sizeof(struct pci_vtdtr_control));
	if (ctrl == NULL) {
		fprintf(stderr, "failed to malloc new control event\n");
		return (NULL);
	}

	memset(ctrl, 0, sizeof(struct pci_vtdtr_control));

	ctrl->pvc_event = VTDTR_DEVICE_KILL;
	ctrl->pvc_pid = pid;
	ctrl->pvc_kill_vmid = vmid;
	ctrl->pvc_kill_epoch = epoch;
	memcpy(ctrl->pvc_source_id, source_id, 16);

	return (ctrl);
}

static struct pci_vtdtr_control *
vtdtr_cleanup_event(uint16_t vmid, uint64_t epoch, uint64_t delivery_id)
{
	struct pci_vtdtr_control *ctrl;

	ctrl = malloc(sizeof(struct pci_vtdtr_control));
	if (ctrl == NULL) {
		fprintf(stderr, "failed to malloc new control event\n");
		return (NULL);
	}

	memset(ctrl, 0, sizeof(struct pci_vtdtr_control));

	ctrl->pvc_event = VTDTR_DEVICE_CLEANUP_DTRACED;
	ctrl->pvc_cleanup_vmid = vmid;
	ctrl->pvc_cleanup_epoch = epoch;
	ctrl->pvc_cleanup_delivery_id = delivery_id;
	return (ctrl);
}

/* 1 accepts, 0 ignores another lifetime, -1 rejects malformed framing. */
static int
pci_vtdtr_elf_target(struct pci_vtdtr_softc *sc, const void *data,
    size_t length, size_t *prefix)
{
	struct hypertrace_vm_envelope target;
	uint16_t id;
	uint64_t epoch;

	*prefix = 0;
	if (length < 4)
		return (-1);
	/* Untargeted templates remain available for initial guest compilation. */
	if (memcmp(data, "\177ELF", 4) == 0)
		return (1);
	if (length < HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 4)
		return (-1);
	hypertrace_envelope_decode(&target, data);
	if (target.magic != HYPERTRACE_TARGET_MAGIC ||
	    target.version != HYPERTRACE_ENVELOPE_VERSION ||
	    target.vmid == 0 || target.vmid >= HYPERTRACE_MAX_VMS ||
	    target.epoch == 0 || target.name_length != 0 ||
	    memcmp((const char *)data + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
	    "\177ELF", 4) != 0)
		return (-1);
	if (vm_get_identity(sc->vsd_vmctx, &id, &epoch) != 0)
		return (-1);
	if (id != target.vmid || epoch != target.epoch)
		return (0);
	*prefix = HYPERTRACE_VM_ENVELOPE_WIRE_SIZE;
	return (1);
}

static bool
pci_vtdtr_kill_matches(struct pci_vtdtr_softc *sc, const dtraced_hdr_t *header)
{
	uint16_t id;
	uint64_t epoch;
	const uint8_t zero_source[16] = { 0 };

	return (header->kill.pid > 1 && header->kill.epoch != 0 &&
	    memcmp(header->kill.source_id, zero_source, 16) != 0 &&
	    vm_get_identity(sc->vsd_vmctx, &id, &epoch) == 0 &&
	    header->kill.vmid == id && header->kill.epoch == epoch);
}

static bool
pci_vtdtr_cleanup_matches(struct pci_vtdtr_softc *sc,
    const dtraced_hdr_t *header)
{
	uint16_t id;
	uint64_t epoch;

	return (header->cleanup.vmid != 0 &&
	    header->cleanup.vmid < HYPERTRACE_MAX_VMS &&
	    header->cleanup.epoch != 0 &&
	    DTRACED_MSG_CLEANUP_DELIVERY_ID(*header) != 0 &&
	    vm_get_identity(sc->vsd_vmctx, &id, &epoch) == 0 &&
	    header->cleanup.vmid == id && header->cleanup.epoch == epoch);
}

/* Caller owns vsd_mtx. A suffix of a saved ELF must stay contiguous. */
static bool
pci_vtdtr_insert_restore_kill(struct pci_vtdtr_ctrlq *queue,
    struct pci_vtdtr_ctrl_entry *entry)
{
	struct pci_vtdtr_ctrl_entry *current, *previous = NULL;
	bool saw_restored = false;

	if (entry->ctrl->pvc_event != VTDTR_DEVICE_KILL)
		return (false);
	STAILQ_FOREACH(current, &queue->head, entries) {
		saw_restored |= current->restored_control;
		/* NODE_REKEY and earlier KILLs keep their order.  Once a saved
		 * ELF or host receipt is at the head, replayed revocations cross
		 * the guest-applied fence before it.  Never split an ELF suffix
		 * after its first fragment has already reached the guest. */
		/* Trace continuity (disabled future feature): restored KILLs come only from transfer-ticket replay, which restore refuses. */
		if (current->restored_control &&
		    current->ctrl->pvc_event != VTDTR_DEVICE_NODE_REKEY &&
		    current->ctrl->pvc_event != VTDTR_DEVICE_KILL &&
		    (current->ctrl->pvc_event != VTDTR_DEVICE_ELF ||
		    current->restored_elf_start)) {
			if (previous == NULL)
				STAILQ_INSERT_HEAD(&queue->head, entry, entries);
			else
				STAILQ_INSERT_AFTER(&queue->head, previous, entry,
				    entries);
			queue->count++;
			entry->restored_kill = true;
			entry->restored_control = true;
			queue->restored_kills++;
			return (true);
		}
		previous = current;
	}
	/* Trace continuity (disabled future feature): restored KILLs come only from transfer-ticket replay, which restore refuses. */
	if (saw_restored) {
		entry->restored_kill = true;
		entry->restored_control = true;
	}
	return (false);
}

/* Only the current transport generation may change device health or queues. */
static bool
pci_vtdtr_publish_room(const struct pci_vtdtr_ctrlq *queue,
    const struct pci_vtdtr_ctrlq *pending)
{
	size_t normal, incoming;

	if (queue->restored_kills > queue->count ||
	    pending->restored_kills > pending->count ||
	    queue->count >= VTDTR_MAX_RESTORE_PENDING - 2 ||
	    pending->count >= VTDTR_MAX_RESTORE_PENDING - 2 - queue->count)
		return (false);
	normal = queue->count - queue->restored_kills;
	incoming = pending->count - pending->restored_kills;
	return (normal < VTDTR_MAX_PENDING &&
	    incoming < VTDTR_MAX_PENDING - normal);
}

static bool
pci_vtdtr_publish(struct pci_vtdtr_softc *sc, struct pci_vtdtr_ctrlq *pending,
    uint64_t generation, bool failed)
{
	struct pci_vtdtr_ctrl_entry *entry;
	bool accepted;

	pthread_mutex_lock(&sc->vsd_mtx);
	/* Backpressure applies to whole frames, so reset cannot splice one.
	 * Restored KILLs have their own bounded reserve; ordinary ELF and live
	 * controls must still fit the original 64 MiB queue budget. Keep two
	 * total slots for guest-applied receipts during the replay barrier. */
	while (!failed && !sc->vsd_stopping && !sc->vsd_session_stop_requested &&
	    generation == sc->vsd_generation &&
	    !(sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) &&
	    pending->count != 0 &&
	    !pci_vtdtr_publish_room(sc->vsd_ctrlq, pending))
		pthread_cond_wait(&sc->vsd_cond, &sc->vsd_mtx);
	if (failed && !sc->vsd_stopping && !sc->vsd_session_stop_requested &&
	    generation == sc->vsd_generation)
		vi_set_needs_reset(&sc->vsd_vs);
	accepted = !failed && !sc->vsd_stopping && !sc->vsd_session_stop_requested &&
	    generation == sc->vsd_generation &&
	    !(sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET);
	while ((entry = pci_vtdtr_cq_dequeue(pending)) != NULL) {
		if (accepted) {
			if (!pci_vtdtr_insert_restore_kill(sc->vsd_ctrlq,
			    entry))
				pci_vtdtr_cq_enqueue(sc->vsd_ctrlq, entry);
		} else {
			free(entry->ctrl);
			free(entry);
		}
	}
	pthread_cond_broadcast(&sc->vsd_cond);
	pthread_mutex_unlock(&sc->vsd_mtx);
	return (accepted);
}

static void
pci_vtdtr_reader_idle(struct pci_vtdtr_softc *sc)
{
	pthread_mutex_lock(&sc->vsd_mtx);
	sc->vsd_reader_active = false;
	pthread_cond_broadcast(&sc->vsd_cond);
	pthread_mutex_unlock(&sc->vsd_mtx);
}

static void *
pci_vtdtr_events(void *xsc)
{
	struct pci_vtdtr_softc *sc = xsc;
	struct pci_vtdtr_ctrlq pending = { 0 };
	struct pci_vtdtr_ctrl_entry *entry;
	struct pci_vtdtr_control *ctrl;
	dtraced_hdr_t header;
	void *buf;
	size_t offset, length, prefix;
	int target_status;
	uint64_t generation, connection;
	uint64_t vmepoch;
	uint16_t vmid;
	bool failed;
	struct timespec wake;

	for (;;) {
		pthread_mutex_lock(&sc->vsd_mtx);
		while (!sc->vsd_stopping && (sc->vsd_checkpoint_paused ||
		    sc->vsd_session_stop_requested))
			pthread_cond_wait(&sc->vsd_cond, &sc->vsd_mtx);
		failed = sc->vsd_stopping;
		if (!failed)
			sc->vsd_reader_active = true;
		pthread_mutex_unlock(&sc->vsd_mtx);
		if (failed)
			return (NULL);
		if (hypertrace_read_epoch(&buf, &header, &generation,
		    &connection) != 0) {
			/* Idle/unconnected is expected; a broken frame loses session state. */
			if (errno != EAGAIN && errno != ENOTCONN) {
				STAILQ_INIT(&pending.head);
				pending.count = 0;
				pending.restored_kills = 0;
				pci_vtdtr_publish(sc, &pending, generation, true);
			}
			pci_vtdtr_reader_idle(sc);
			/* Let a lifecycle stop wake the reader during reconnect backoff. */
			pthread_mutex_lock(&sc->vsd_mtx);
			if (!sc->vsd_stopping &&
			    clock_gettime(CLOCK_MONOTONIC, &wake) == 0) {
				wake.tv_sec += PCI_VTDTR_EVENTSLEEPTIME;
				(void)pthread_cond_timedwait(&sc->vsd_cond,
				    &sc->vsd_mtx, &wake);
			}
			failed = sc->vsd_stopping;
			pthread_mutex_unlock(&sc->vsd_mtx);
			if (failed)
				return (NULL);
			continue;
		}
		STAILQ_INIT(&pending.head);
		pending.count = 0;
		pending.restored_kills = 0;
		failed = false;
		offset = 0;
		length = header.msg_type == DTRACED_MSG_ELF ? header.elf.len : 0;
		prefix = 0;
		if (header.msg_type == DTRACED_MSG_ELF) {
			target_status = pci_vtdtr_elf_target(sc, buf, length, &prefix);
			if (target_status == 0) {
				free(buf);
				STAILQ_INIT(&pending.head);
				pending.count = 0;
				pending.restored_kills = 0;
				if (pci_vtdtr_publish(sc, &pending, generation,
				    false) && hypertrace_ack_epoch(generation, connection,
				    header.elf.delivery_id) != 0)
					(void)pci_vtdtr_publish(sc, &pending,
					    generation, true);
				pci_vtdtr_reader_idle(sc);
				continue;
			}
			if (target_status < 0) {
				failed = true;
				goto assembled;
			}
			if (vm_get_identity(sc->vsd_vmctx, &vmid,
			    &vmepoch) != 0 || vmid == 0 ||
			    vmid >= HYPERTRACE_MAX_VMS || vmepoch == 0) {
				failed = true;
				goto assembled;
			}
			if (prefix != 0) {
				struct hypertrace_vm_envelope target;
				hypertrace_envelope_decode(&target, buf);
				if (target.vmid != vmid || target.epoch != vmepoch) {
					failed = true;
					goto assembled;
				}
			}
			length -= prefix;
		}
		do {
			ctrl = NULL;
			switch (header.msg_type) {
			case DTRACED_MSG_ELF:
				ctrl = vtdtr_elf_event((char *)buf + prefix, length, offset);
				if (ctrl != NULL) {
					memcpy(ctrl->pvc_program_id, header.elf.program_id, 16);
					memcpy(ctrl->pvc_elf_source_id,
					    header.elf.source_id, 16);
					ctrl->pvc_delivery_id =
					    header.elf.delivery_id;
					ctrl->pvc_vmid = vmid;
					ctrl->pvc_epoch = vmepoch;
					offset += ctrl->pvc_elflen;
				}
				break;
			case DTRACED_MSG_KILL:
				if (!pci_vtdtr_kill_matches(sc, &header)) {
					failed = true;
					goto assembled;
				}
				ctrl = vtdtr_kill_event(header.kill.pid,
				    header.kill.vmid, header.kill.epoch,
				    header.kill.source_id);
				break;
			case DTRACED_MSG_CLEANUP:
				if (!pci_vtdtr_cleanup_matches(sc, &header)) {
					failed = true;
					goto assembled;
				}
				ctrl = vtdtr_cleanup_event(header.cleanup.vmid,
				    header.cleanup.epoch,
				    DTRACED_MSG_CLEANUP_DELIVERY_ID(header));
				break;
			}
			entry = ctrl != NULL ? calloc(1, sizeof(*entry)) : NULL;
			if (entry == NULL) {
				free(ctrl);
				failed = true;
				break;
			}
			entry->ctrl = ctrl;
			pci_vtdtr_cq_enqueue(&pending, entry);
		} while (offset < length);
assembled:
		free(buf);
		bool accepted = pci_vtdtr_publish(sc, &pending, generation, failed);
		if (accepted &&
		    (header.msg_type == DTRACED_MSG_ELF ||
		    header.msg_type == DTRACED_MSG_CLEANUP) &&
		    hypertrace_ack_epoch(generation, connection,
		    header.msg_type == DTRACED_MSG_ELF ?
		    header.elf.delivery_id :
		    DTRACED_MSG_CLEANUP_DELIVERY_ID(header)) != 0) {
			STAILQ_INIT(&pending.head);
			pending.count = 0;
			pending.restored_kills = 0;
			(void)pci_vtdtr_publish(sc, &pending, generation, true);
		}
		pci_vtdtr_reader_idle(sc);
	}
}

/*
 * Mostly boilerplate, we initialize everything required for the correct
 * operation of the emulated PCI device, do error checking and finally dispatch
 * the communicator thread and add an event handler for kqueue.
 */
static int
pci_vtdtr_init(struct pci_devinst *pci_inst, nvlist_t *nvl __unused)
{
	struct vmctx *ctx = pci_inst->pi_vmctx;
	struct pci_vtdtr_softc *sc;
	pthread_condattr_t condattr;
	int error;

	if (!hypertrace_initialized()) {
		fprintf(stderr, "virtio-dtrace requires enable_hypertrace=true\n");
		return (EINVAL);
	}
	if (vtdtr_present)
		return (EBUSY);
	if (vm_get_vmid(ctx) == 0)
		return (ENOTSUP);

	sc = calloc(1, sizeof(struct pci_vtdtr_softc));
	if (sc == NULL)
		return (ENOMEM);
	sc->vsd_ctrlq = calloc(1, sizeof(struct pci_vtdtr_ctrlq));
	if (sc->vsd_ctrlq == NULL) {
		free(sc);
		return (ENOMEM);
	}
	STAILQ_INIT(&sc->vsd_ctrlq->head);

	vi_softc_linkup(&sc->vsd_vs, &vtdtr_vi_consts,
	    sc, pci_inst, sc->vsd_queues);
	error = pthread_mutex_init(&sc->vsd_mtx, NULL);
	if (error != 0)
		goto fail_state;
	error = pthread_condattr_init(&condattr);
	if (error != 0)
		goto fail_mutex;
	error = pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC);
	if (error != 0) {
		pthread_condattr_destroy(&condattr);
		goto fail_mutex;
	}
	error = pthread_cond_init(&sc->vsd_cond, &condattr);
	pthread_condattr_destroy(&condattr);
	if (error != 0)
		goto fail_mutex;
	sc->vsd_vs.vs_mtx = &sc->vsd_mtx;
	sc->vsd_vmctx = ctx;
	sc->vsd_ready = 0;

	sc->vsd_queues[0].vq_qsize = VTDTR_RINGSZ;
	sc->vsd_queues[0].vq_notify = pci_vtdtr_notify_tx;
	sc->vsd_queues[1].vq_qsize = VTDTR_RINGSZ;
	sc->vsd_queues[1].vq_notify = pci_vtdtr_notify_rx;

	pci_set_cfgdata16(pci_inst, PCIR_DEVICE, VIRTIO_DEV_DTRACE);
	pci_set_cfgdata16(pci_inst, PCIR_VENDOR, VIRTIO_VENDOR);
	pci_set_cfgdata8(pci_inst, PCIR_CLASS, PCIC_OTHER);
	pci_set_cfgdata16(pci_inst, PCIR_SUBDEV_0, VIRTIO_ID_DTRACE);
	pci_set_cfgdata16(pci_inst, PCIR_SUBVEND_0, VIRTIO_VENDOR);

	if (vi_intr_init(&sc->vsd_vs, 1, fbsdrun_virtio_msix())) {
		error = EIO;
		goto fail_cond;
	}
	vi_set_io_bar(&sc->vsd_vs, 0);
	/* Identity must precede any ELF the host reader can enqueue. */
	pthread_mutex_lock(&sc->vsd_mtx);
	pci_vtdtr_node_id(sc, 0);
	error = (sc->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0 ?
	    EIO : 0;
	pthread_mutex_unlock(&sc->vsd_mtx);
	if (error != 0)
		goto fail_intr;
	error = pthread_create(&sc->vsd_communicator, NULL, pci_vtdtr_run, sc);
	if (error != 0)
		goto fail_intr;
	error = pthread_create(&sc->vsd_reader, NULL, pci_vtdtr_events, sc);
	if (error != 0) {
		pthread_mutex_lock(&sc->vsd_mtx);
		sc->vsd_stopping = true;
		pthread_cond_broadcast(&sc->vsd_cond);
		pthread_mutex_unlock(&sc->vsd_mtx);
		pthread_join(sc->vsd_communicator, NULL);
		goto fail_intr;
	}
	vtdtr_shutdown_sc = sc;
	if (atexit(pci_vtdtr_shutdown) != 0) {
		vtdtr_shutdown_sc = NULL;
		pci_vtdtr_stop_workers(sc);
		error = ENOMEM;
		goto fail_intr;
	}

	vtdtr_present = true;
	return (0);

fail_intr:
	pci_vtdtr_reset_queue(sc);
	pthread_mutex_destroy(&sc->vsd_vs.vs_isr_mtx);
fail_cond:
	pthread_cond_destroy(&sc->vsd_cond);
fail_mutex:
	pthread_mutex_destroy(&sc->vsd_mtx);
fail_state:
	pci_inst->pi_arg = NULL;
	free(sc->vsd_ctrlq);
	free(sc);
	return (error);
}

static const struct pci_devemu pci_de_vdtr = {
	.pe_emu		= "virtio-dtrace",
	.pe_init	= pci_vtdtr_init,
	.pe_barwrite	= vi_pci_write,
	.pe_barread	= vi_pci_read,
#ifdef BHYVE_SNAPSHOT
	/* Fresh-session cut stops external tracing before this device codec.
	 * Payload writes and common VirtIO ring writes participate in tracking. */
	.pe_migration_flags = PCI_MIGRATION_VIRTIO_FLAGS,
	.pe_snapshot = vi_pci_snapshot,
	.pe_snapshot_validate = pci_vtdtr_snapshot_validate,
	.pe_snapshot_extra_capacity = pci_vtdtr_snapshot_extra_capacity,
	.pe_snapshot_compat = vi_pci_snapshot_compat,
	.pe_pause	= vi_pci_pause,
	.pe_resume	= vi_pci_resume,
#endif
};
PCI_EMUL_SET(pci_de_vdtr);
