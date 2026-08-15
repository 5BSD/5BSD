/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/linker_set.h>
#include <sys/param.h>
#include <sys/uio.h>

#include <dev/pci/pcireg.h>
#include <dev/virtio/virtio_ids.h>

#include <errno.h>
#include <pthread.h>
#include <pthread_np.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "iov.h"
#include "mevent.h"
#include "pci_emul.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif
#include "virtio.h"
#include "virtio_fs_backend.h"
#include "virtio_fs_connection.h"
#include "virtio_fs_host.h"
#include "virtio_fs_state.h"
#include "virtio_pci_modern_probes.h"

#define	VTFS_RINGSZ			256U
#define	VTFS_MAX_REQUEST_QUEUES		64U
#define	VTFS_DEFAULT_REQUEST_QUEUES	1U
#define	VTFS_MAX_INFLIGHT		4096U
#define	VTFS_PENDING_BYTES		(64U * 1024U * 1024U)
#define	VTFS_CHECKPOINT_TIMEOUT_SEC	10

struct pci_vtfs_reset {
	struct vqueue_info *vq;
	uint64_t generation;
	int error;
	bool pending;
	bool complete;
};

struct pci_vtfs_reset_completion {
	struct vqueue_info *vq;
	uint64_t generation;
	int error;
};

struct pci_vtfs_softc {
	struct virtio_softc vsc_vs;
	struct virtio_consts vsc_consts;
	pthread_mutex_t vsc_mtx;
	pthread_cond_t vsc_checkpoint_cv;
	struct vqueue_info *vsc_vq;
	struct pci_vtfs_reset *vsc_reset;
	struct virtio_fs_connection *vsc_connection;
	struct mevent *vsc_read_event;
	struct mevent *vsc_write_event;
	struct virtio_fs_backend_hello vsc_offer;
	char *vsc_backend_path;
	char *vsc_backend_identity;
	uint8_t *vsc_checkpoint_backend_state;
	size_t vsc_checkpoint_backend_state_len;
	struct virtio_fs_session vsc_checkpoint_fuse;
	struct virtio_fs_backend_session vsc_checkpoint_backend;
	uint8_t vsc_config[BHYVE_VIRTIO_FS_CONFIG_SIZE];
	bool *vsc_notify_pending;
	bool vsc_callbacks_set;
	bool vsc_checkpoint_lock_held;
	bool vsc_checkpoint_waiting;
	bool vsc_checkpoint_borrowed_suspend;
	bool vsc_guest_suspended;
	bool vsc_reconnecting;
	bool vsc_notifications;
	uint32_t vsc_num_request_queues;
	uint32_t vsc_nvq;
};

struct pci_vtfs_request {
	struct vqueue_info *vq;
	struct vi_req req;
	struct timespec submitted;
	uint64_t generation;
	bool submitted_valid;
};

static void pci_vtfs_notify(void *, struct vqueue_info *);
static int pci_vtfs_receive_notification(void *, const void *, size_t);
static void pci_vtfs_complete(void *, uintptr_t, size_t);
static void pci_vtfs_event(int, enum ev_type, void *);
static int pci_vtfs_sync_events(struct pci_vtfs_softc *);
static void pci_vtfs_reset(void *) __no_lock_analysis;
static int pci_vtfs_suspend_device(void *);
static int pci_vtfs_resume_device(void *);
static int pci_vtfs_control_wait(struct pci_vtfs_softc *)
    __no_lock_analysis;
static int pci_vtfs_begin_quiesce_wait(struct pci_vtfs_softc *)
    __no_lock_analysis;
static bool pci_vtfs_serializer_enter(struct pci_vtfs_softc *) __unused
    __no_lock_analysis;
static void pci_vtfs_serializer_exit(struct pci_vtfs_softc *, bool) __unused
    __no_lock_analysis;
#ifdef BHYVE_SNAPSHOT
/*
 * Snapshot pause retains vsc_mtx until its paired resume callback.  Keep this
 * inter-callback lock transfer explicit and local: ordinary filesystem paths
 * remain subject to thread-safety analysis.
 */
static int pci_vtfs_pause(void *) __no_lock_analysis;
static int pci_vtfs_resume(void *) __no_lock_analysis;
static int pci_vtfs_snapshot(void *, struct vm_snapshot_meta *);
static int pci_vtfs_snapshot_validate(struct vm_snapshot_meta *);
#endif

static bool
pci_vtfs_is_notification_queue(const struct pci_vtfs_softc *sc,
    uint32_t queue_id)
{

	return (sc->vsc_notifications && queue_id == 1);
}

static uint32_t
pci_vtfs_request_queue_id(const struct pci_vtfs_softc *sc, uint32_t queue_id)
{

	/* Queue zero is hiprio; queue one exists only for notifications. */
	return (queue_id == 0 ? 0 :
	    queue_id - (sc->vsc_notifications ? 1 : 0));
}

static uint32_t
pci_vtfs_guest_queue_id(const struct pci_vtfs_softc *sc, uint32_t queue_id)
{

	return (queue_id == 0 ? 0 :
	    queue_id + (sc->vsc_notifications ? 1 : 0));
}

static uint64_t
pci_vtfs_elapsed_ns(const struct pci_vtfs_request *request)
{
	struct timespec now;
	uint64_t seconds, nanoseconds;

	if (!request->submitted_valid ||
	    clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
	    now.tv_sec < request->submitted.tv_sec ||
	    (now.tv_sec == request->submitted.tv_sec &&
	    now.tv_nsec < request->submitted.tv_nsec))
		return (0);
	seconds = (uint64_t)(now.tv_sec - request->submitted.tv_sec);
	nanoseconds = (uint64_t)now.tv_nsec;
	if (nanoseconds < (uint64_t)request->submitted.tv_nsec) {
		seconds--;
		nanoseconds += UINT64_C(1000000000);
	}
	nanoseconds -= (uint64_t)request->submitted.tv_nsec;
	if (seconds > (UINT64_MAX - nanoseconds) / UINT64_C(1000000000))
		return (UINT64_MAX);
	return (seconds * UINT64_C(1000000000) + nanoseconds);
}

static void
pci_vtfs_probe_pressure(struct pci_vtfs_softc *sc, uint32_t queue, int error)
{

	VIRTIO_PROBE_FS_PRESSURE("vtfs", queue,
	    virtio_fs_connection_pending(sc->vsc_connection),
	    virtio_fs_connection_outgoing(sc->vsc_connection), error);
}

static void
pci_vtfs_backend_state_clear(struct pci_vtfs_softc *sc)
{

	free(sc->vsc_checkpoint_backend_state);
	sc->vsc_checkpoint_backend_state = NULL;
	sc->vsc_checkpoint_backend_state_len = 0;
}

static void
pci_vtfs_disconnect_sync(struct pci_vtfs_softc *sc)
{
	bool connected;

	connected = sc->vsc_connection != NULL;
	if (sc->vsc_read_event != NULL) {
		(void)mevent_delete_sync(sc->vsc_read_event);
		sc->vsc_read_event = NULL;
	}
	if (sc->vsc_write_event != NULL) {
		(void)mevent_delete_sync(sc->vsc_write_event);
		sc->vsc_write_event = NULL;
	}
	virtio_fs_connection_destroy(sc->vsc_connection);
	if (connected)
		VIRTIO_PROBE_FS_BACKEND("vtfs", "disconnect", 0, 0);
	sc->vsc_connection = NULL;
	sc->vsc_callbacks_set = false;
}

static int
pci_vtfs_connect(struct pci_vtfs_softc *sc)
{
	int error, fd;

	error = virtio_fs_connection_connect_required(sc->vsc_backend_path,
	    geteuid(), getegid(), &sc->vsc_offer, VTFS_MAX_INFLIGHT,
	    VTFS_MAX_INFLIGHT, VIRTIO_FS_BACKEND_F_CANCEL |
	    (sc->vsc_notifications ? VIRTIO_FS_BACKEND_F_NOTIFICATION : 0) |
	    (sc->vsc_backend_identity == NULL ? 0 :
	    VIRTIO_FS_BACKEND_F_FREEZE |
	    VIRTIO_FS_BACKEND_F_STATE_TRANSFER),
	    pci_vtfs_complete, sc,
	    &sc->vsc_connection);
	if (error != 0) {
		VIRTIO_PROBE_FS_BACKEND("vtfs", "connect", 0, error);
		return (error);
	}
	fd = virtio_fs_connection_fd(sc->vsc_connection);
	sc->vsc_read_event = mevent_add_disabled(fd, EVF_READ,
	    pci_vtfs_event, sc);
	sc->vsc_write_event = mevent_add_disabled(fd, EVF_WRITE,
	    pci_vtfs_event, sc);
	if (sc->vsc_read_event == NULL || sc->vsc_write_event == NULL) {
		pci_vtfs_disconnect_sync(sc);
		return (ENOMEM);
	}
	error = pci_vtfs_sync_events(sc);
	if (error != 0) {
		pci_vtfs_disconnect_sync(sc);
		return (error);
	}
	VIRTIO_PROBE_FS_BACKEND("vtfs", "connect", 0, 0);
	return (0);
}

static int
pci_vtfs_parse_u32(const char *value, uint32_t minimum, uint32_t maximum,
    uint32_t *result)
{
	char *end;
	unsigned long number;

	if (value == NULL || result == NULL)
		return (EINVAL);
	errno = 0;
	number = strtoul(value, &end, 0);
	if (errno != 0 || end == value || *end != '\0' ||
	    number < minimum || number > maximum)
		return (EINVAL);
	*result = (uint32_t)number;
	return (0);
}

static void
pci_vtfs_complete(void *arg, uintptr_t cookie, size_t used)
{
	struct pci_vtfs_softc *sc;
	struct pci_vtfs_request *request;
	bool acquired;
	bool published;

	sc = arg;
	/*
	 * Backend progress invokes us with vsc_mtx held, while synchronous
	 * connection teardown deliberately drops it before draining retained
	 * requests.  The latter still publishes a virtqueue completion, so use
	 * the same lock in both cases rather than relying on the callback's
	 * origin for serialization.
	 */
	acquired = pci_vtfs_serializer_enter(sc);
	request = (struct pci_vtfs_request *)cookie;
	published = request->generation == request->vq->vq_generation &&
	    !vq_is_resetting(request->vq);
	if (published) {
		vq_relchain_req(request->vq, &request->req, (uint32_t)used);
		vq_endchains(request->vq, 1);
	} else
		vq_discard_req(request->vq, &request->req);
	VIRTIO_PROBE_FS_COMPLETE("vtfs", request->vq->vq_num,
	    (uint32_t)used, !published);
	VIRTIO_PROBE_FS_LATENCY("vtfs", request->vq->vq_num,
	    pci_vtfs_elapsed_ns(request), (uint32_t)used,
	    published ? 0 : ESTALE);
	pci_vtfs_probe_pressure(sc, request->vq->vq_num, 0);
	free(request);
	pci_vtfs_serializer_exit(sc, acquired);
}

static void
pci_vtfs_discard(void *arg, uintptr_t cookie)
{
	struct pci_vtfs_softc *sc;
	struct pci_vtfs_request *request;
	bool acquired;

	sc = arg;
	/* See pci_vtfs_complete(): teardown callbacks arrive unlocked. */
	acquired = pci_vtfs_serializer_enter(sc);
	request = (struct pci_vtfs_request *)cookie;
	VIRTIO_PROBE_FS_COMPLETE("vtfs", request->vq->vq_num, 0, 1);
	VIRTIO_PROBE_FS_LATENCY("vtfs", request->vq->vq_num,
	    pci_vtfs_elapsed_ns(request), 0, ECANCELED);
	pci_vtfs_probe_pressure(sc, request->vq->vq_num, ECANCELED);
	vq_discard_req(request->vq, &request->req);
	free(request);
	pci_vtfs_serializer_exit(sc, acquired);
}

static void
pci_vtfs_reset_complete(void *arg, uint32_t queue_id, int error)
{
	struct pci_vtfs_softc *sc;
	struct pci_vtfs_reset *reset;
	bool acquired;

	sc = arg;
	/* Queue destruction may deliver this callback without vsc_mtx held. */
	acquired = pci_vtfs_serializer_enter(sc);
	queue_id = pci_vtfs_guest_queue_id(sc, queue_id);
	if (queue_id >= sc->vsc_nvq)
		goto done;
	reset = &sc->vsc_reset[queue_id];
	if (!reset->pending)
		goto done;
	reset->error = error;
	reset->complete = true;
	VIRTIO_PROBE_FS_QUEUE_RESET("vtfs", queue_id, reset->generation,
	    error);
done:
	pci_vtfs_serializer_exit(sc, acquired);
}

static size_t
pci_vtfs_take_reset_completions(struct pci_vtfs_softc *sc,
    struct pci_vtfs_reset_completion *completions, size_t capacity)
{
	struct pci_vtfs_reset *reset;
	size_t count;

	count = 0;
	for (uint32_t i = 0; i < sc->vsc_nvq; i++) {
		reset = &sc->vsc_reset[i];
		if (!reset->complete)
			continue;
		if (count == capacity)
			break;
		completions[count++] = (struct pci_vtfs_reset_completion) {
			.vq = reset->vq,
			.generation = reset->generation,
			.error = reset->error,
		};
		memset(reset, 0, sizeof(*reset));
	}
	return (count);
}

static int
pci_vtfs_install_callbacks(struct pci_vtfs_softc *sc)
{
	int error;

	if (sc->vsc_callbacks_set ||
	    !virtio_fs_connection_active(sc->vsc_connection))
		return (0);
	error = virtio_fs_connection_set_discard(sc->vsc_connection,
	    pci_vtfs_discard, sc);
	if (error != 0)
		return (error);
	error = virtio_fs_connection_set_reset_complete(sc->vsc_connection,
	    pci_vtfs_reset_complete, sc);
	if (error != 0)
		return (error);
	if (sc->vsc_notifications) {
		error = virtio_fs_connection_set_notification(sc->vsc_connection,
		    pci_vtfs_receive_notification, sc);
		if (error != 0)
			return (error);
	}
	sc->vsc_callbacks_set = true;
	return (0);
}

static int
pci_vtfs_sync_events(struct pci_vtfs_softc *sc)
{
	uint32_t events;
	int error, event_error;

	events = virtio_fs_connection_events(sc->vsc_connection);
	error = 0;
	if (sc->vsc_read_event != NULL &&
	    (events & VIRTIO_FS_CONNECTION_READ) != 0)
		event_error = mevent_enable(sc->vsc_read_event);
	else if (sc->vsc_read_event != NULL)
		event_error = mevent_disable(sc->vsc_read_event);
	else
		event_error = 0;
	if (event_error != 0)
		error = event_error;
	if (sc->vsc_write_event != NULL &&
	    (events & VIRTIO_FS_CONNECTION_WRITE) != 0)
		event_error = mevent_enable(sc->vsc_write_event);
	else if (sc->vsc_write_event != NULL)
		event_error = mevent_disable(sc->vsc_write_event);
	else
		event_error = 0;
	if (error == 0)
		error = event_error;
	return (error);
}

static bool
pci_vtfs_event_blocked(const struct pci_vtfs_softc *sc)
{

	return (sc->vsc_reconnecting || sc->vsc_connection == NULL);
}

static void
pci_vtfs_event(int fd __unused, enum ev_type type, void *arg)
{
	struct pci_vtfs_reset_completion
	    completions[VTFS_MAX_REQUEST_QUEUES + 1];
	struct pci_vtfs_softc *sc;
	size_t completion_count;
	int error, event_error;

	sc = arg;
	pthread_mutex_lock(&sc->vsc_mtx);
	if (pci_vtfs_event_blocked(sc)) {
		pthread_mutex_unlock(&sc->vsc_mtx);
		return;
	}
	error = virtio_fs_connection_progress(sc->vsc_connection,
	    type == EVF_READ, type == EVF_WRITE);
	if (error != 0 && error != EAGAIN && error != EWOULDBLOCK) {
		vi_set_needs_reset(&sc->vsc_vs);
		VIRTIO_PROBE_FS_BACKEND("vtfs", "progress",
		    virtio_fs_connection_pending(sc->vsc_connection), error);
	}
	if (error == 0 || error == EAGAIN || error == EWOULDBLOCK) {
		error = pci_vtfs_install_callbacks(sc);
		if (error != 0)
			vi_set_needs_reset(&sc->vsc_vs);
	}
	if (sc->vsc_callbacks_set) {
		for (uint32_t i = 0; i < sc->vsc_nvq; i++) {
			if (!sc->vsc_notify_pending[i])
				continue;
			sc->vsc_notify_pending[i] = false;
			pci_vtfs_notify(sc, &sc->vsc_vq[i]);
		}
	}
	completion_count = pci_vtfs_take_reset_completions(sc, completions,
	    nitems(completions));
	if (sc->vsc_checkpoint_waiting &&
	    virtio_fs_connection_control_status(sc->vsc_connection) !=
	    EINPROGRESS)
		pthread_cond_broadcast(&sc->vsc_checkpoint_cv);
	event_error = pci_vtfs_sync_events(sc);
	if (event_error != 0) {
		vi_set_needs_reset(&sc->vsc_vs);
		VIRTIO_PROBE_FS_BACKEND("vtfs", "event-arm", 0, event_error);
	}
	pthread_mutex_unlock(&sc->vsc_mtx);
	for (size_t i = 0; i < completion_count; i++) {
		vi_pci_modern_queue_reset_complete(completions[i].vq,
		    completions[i].generation, completions[i].error);
	}
}

static void
pci_vtfs_reset(void *arg)
{
	struct pci_vtfs_softc *sc;
	int error;

	sc = arg;
	/*
	 * Reset is entered with the VirtIO mutex held.  Fence callbacks before
	 * dropping it, then wait for both readiness registrations to disappear.
	 * A callback already selected by kqueue observes vsc_reconnecting and
	 * returns without touching either the old or replacement connection.
	 */
	sc->vsc_reconnecting = true;
	pthread_mutex_unlock(&sc->vsc_mtx);
	pci_vtfs_disconnect_sync(sc);
	pthread_mutex_lock(&sc->vsc_mtx);
	memset(sc->vsc_reset, 0, sc->vsc_nvq *
	    sizeof(*sc->vsc_reset));
	memset(sc->vsc_notify_pending, 0,
	    sc->vsc_nvq *
	    sizeof(*sc->vsc_notify_pending));
	vi_reset_dev(&sc->vsc_vs);
	error = pci_vtfs_connect(sc);
	sc->vsc_reconnecting = false;
	sc->vsc_guest_suspended = false;
	sc->vsc_checkpoint_borrowed_suspend = false;
	pci_vtfs_backend_state_clear(sc);
	if (error != 0)
		vi_set_needs_reset(&sc->vsc_vs);
}

static int
pci_vtfs_qreset(void *arg, struct vqueue_info *vq, uint64_t generation)
{
	struct pci_vtfs_softc *sc;
	struct pci_vtfs_reset *reset;
	size_t discarded;
	int error, event_error;

	sc = arg;
	if (vq->vq_num >= sc->vsc_nvq)
		return (EINVAL);
	if (pci_vtfs_is_notification_queue(sc, vq->vq_num))
		return (0);
	if (pci_vtfs_event_blocked(sc))
		return (EBUSY);
	reset = &sc->vsc_reset[vq->vq_num];
	if (reset->pending)
		return (EBUSY);
	reset->vq = vq;
	reset->generation = generation;
	reset->pending = true;
	sc->vsc_notify_pending[vq->vq_num] = false;
	error = virtio_fs_connection_reset_queue(sc->vsc_connection,
	    pci_vtfs_request_queue_id(sc, vq->vq_num), &discarded);
	VIRTIO_PROBE_FS_QUEUE_RESET("vtfs", vq->vq_num, generation, error);
	pci_vtfs_probe_pressure(sc, vq->vq_num, error);
	if (error != EINPROGRESS)
		memset(reset, 0, sizeof(*reset));
	event_error = pci_vtfs_sync_events(sc);
	if (event_error != 0) {
		vi_set_needs_reset(&sc->vsc_vs);
		/*
		 * A backend cancellation which returned EINPROGRESS still owns the
		 * queue even if readiness rearming failed.  Preserve the asynchronous
		 * reset contract until teardown or a later backend callback retires
		 * that ownership; reporting a synchronous error here would let the
		 * common transport expose the queue for reuse prematurely.
		 */
		return (error == EINPROGRESS ? EINPROGRESS : event_error);
	}
	return (error);
}

static int
pci_vtfs_receive_notification(void *arg, const void *payload, size_t length)
{
	struct pci_vtfs_softc *sc;
	struct vi_req req;
	struct iovec iov[VTFS_RINGSZ];
	struct vqueue_info *vq;
	size_t written;
	int n;

	sc = arg;
	if (payload == NULL || length == 0 ||
	    length > BHYVE_VIRTIO_FS_NOTIFY_BUF_SIZE ||
	    !sc->vsc_notifications || sc->vsc_nvq <= 1)
		return (EPROTO);
	vq = &sc->vsc_vq[1];
	/*
	 * A notification has no request token to protect it after the
	 * connection callback has selected this queue.  Do not consume a guest
	 * buffer while a selective reset owns the queue; the next queue kick
	 * retries the retained frame after reset completion.
	 */
	if (vq_is_resetting(vq))
		return (EAGAIN);
	if (!vq_has_descs(vq))
		return (EAGAIN);
	memset(&req, 0, sizeof(req));
	n = vq_getchain(vq, iov, nitems(iov), &req);
	if (n <= 0)
		return (EPROTO);
	if (!req.ordered || req.readable != 0 || req.writable == 0 ||
	    req.writable_bytes < length) {
		vq_relchain_req(vq, &req, 0);
		vq_endchains(vq, 1);
		return (EPROTO);
	}
	written = buf_to_iov(payload, length, iov, (size_t)n);
	if (written != length) {
		vq_relchain_req(vq, &req, 0);
		vq_endchains(vq, 1);
		return (EPROTO);
	}
	vq_relchain_req(vq, &req, (uint32_t)written);
	vq_endchains(vq, 1);
	return (0);
}

static void
pci_vtfs_notify(void *arg, struct vqueue_info *vq)
{
	struct pci_vtfs_softc *sc;
	struct pci_vtfs_request *request;
	struct iovec iov[VTFS_RINGSZ];
	enum virtio_fs_queue_class queue_class;
	uint16_t budget;
	int error, n;

	sc = arg;
	if (vq->vq_num >= sc->vsc_nvq) {
		vi_set_needs_reset(&sc->vsc_vs);
		return;
	}
	if (pci_vtfs_event_blocked(sc))
		return;
	if (!sc->vsc_callbacks_set) {
		sc->vsc_notify_pending[vq->vq_num] = true;
		return;
	}
	if (pci_vtfs_is_notification_queue(sc, vq->vq_num)) {
		error = virtio_fs_connection_retry_notification(sc->vsc_connection);
		if (error != 0 && error != EAGAIN)
			vi_set_needs_reset(&sc->vsc_vs);
		return;
	}
	queue_class = vq->vq_num == 0 ? VIRTIO_FS_QUEUE_HIPRIO :
	    VIRTIO_FS_QUEUE_REQUEST;
	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
		request = calloc(1, sizeof(*request));
		if (request == NULL) {
			vi_set_needs_reset(&sc->vsc_vs);
			break;
		}
		n = vq_getchain(vq, iov, nitems(iov), &request->req);
		if (n <= 0) {
			free(request);
			break;
		}
		request->vq = vq;
		request->generation = vq->vq_generation;
		request->submitted_valid =
		    clock_gettime(CLOCK_MONOTONIC, &request->submitted) == 0;
		error = virtio_fs_connection_submit_on(sc->vsc_connection,
		    pci_vtfs_request_queue_id(sc, vq->vq_num), queue_class, iov, (size_t)n,
		    request->req.readable, request->req.writable,
		    request->req.ordered,
		    (uintptr_t)request);
		VIRTIO_PROBE_FS_REQUEST("vtfs", vq->vq_num,
		    request->req.readable, request->req.writable, error);
		pci_vtfs_probe_pressure(sc, vq->vq_num, error);
		if (error == 0)
			continue;
		if (error == ENOBUFS || error == ENOSPC || error == EAGAIN ||
		    error == EBUSY) {
			vq_retchain_req(vq, &request->req);
			free(request);
			sc->vsc_notify_pending[vq->vq_num] = true;
			break;
		}
		vq_relchain_req(vq, &request->req, 0);
		free(request);
		vi_set_needs_reset(&sc->vsc_vs);
		break;
	}
	vq_endchains(vq, !vq_has_descs(vq));
	if (pci_vtfs_sync_events(sc) != 0)
		vi_set_needs_reset(&sc->vsc_vs);
}

static int
pci_vtfs_cfgread(void *arg, int offset, int size, uint32_t *value)
{
	struct pci_vtfs_softc *sc;
	size_t config_size;

	sc = arg;
	config_size = sc->vsc_notifications ? BHYVE_VIRTIO_FS_CONFIG_SIZE :
	    BHYVE_VIRTIO_FS_CONFIG_BASE_SIZE;
	if (value == NULL || offset < 0 ||
	    (size != 1 && size != 2 && size != 4) ||
	    (size_t)offset > config_size ||
	    (size_t)size > config_size - (size_t)offset)
		return (EINVAL);
	return (vi_config_read_le(sc->vsc_config, sizeof(sc->vsc_config),
	    offset, size, value));
}

static int
pci_vtfs_control_wait(struct pci_vtfs_softc *sc)
{
	struct timespec deadline;
	int error, status;

	if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0)
		status = errno;
	else
		status = EINPROGRESS;
	if (status != EINPROGRESS) {
		(void)virtio_fs_connection_abort_control(sc->vsc_connection,
		    status);
		vi_set_needs_reset(&sc->vsc_vs);
		return (status);
	}
	deadline.tv_sec += VTFS_CHECKPOINT_TIMEOUT_SEC;
	sc->vsc_checkpoint_waiting = true;
	for (;;) {
		status = virtio_fs_connection_control_status(
		    sc->vsc_connection);
		if (status != EINPROGRESS)
			break;
		error = pthread_cond_timedwait(&sc->vsc_checkpoint_cv,
		    &sc->vsc_mtx, &deadline);
		if (error != 0) {
			status = error;
			break;
		}
	}
	sc->vsc_checkpoint_waiting = false;
	if (status != 0 && status != EIO) {
		(void)virtio_fs_connection_abort_control(sc->vsc_connection,
		    status);
		vi_set_needs_reset(&sc->vsc_vs);
	}
	return (status);
}

static int
pci_vtfs_begin_quiesce_wait(struct pci_vtfs_softc *sc)
{
	struct timespec deadline;
	int error;

	if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0)
		return (errno);
	deadline.tv_sec += VTFS_CHECKPOINT_TIMEOUT_SEC;
	for (;;) {
		error = virtio_fs_connection_begin_quiesce(
		    sc->vsc_connection);
		if (error != EINPROGRESS)
			break;
		error = pci_vtfs_sync_events(sc);
		if (error != 0) {
			(void)virtio_fs_connection_resume(sc->vsc_connection);
			vi_set_needs_reset(&sc->vsc_vs);
			return (error);
		}
		sc->vsc_checkpoint_waiting = true;
		error = pthread_cond_timedwait(&sc->vsc_checkpoint_cv,
		    &sc->vsc_mtx, &deadline);
		sc->vsc_checkpoint_waiting = false;
		if (error != 0) {
			/*
			 * No control frame exists yet, so reopening guest
			 * admission is a complete rollback of the drain owner.
			 */
			virtio_fs_connection_resume(sc->vsc_connection);
			return (error);
		}
	}
	if (error != 0)
		return (error);
	error = pci_vtfs_sync_events(sc);
	if (error != 0) {
		(void)virtio_fs_connection_resume(sc->vsc_connection);
		vi_set_needs_reset(&sc->vsc_vs);
		return (error);
	}
	return (pci_vtfs_control_wait(sc));
}

static bool
pci_vtfs_reset_pending(const struct pci_vtfs_softc *sc)
{

	for (uint32_t i = 0; i < sc->vsc_nvq; i++) {
		if (sc->vsc_reset[i].pending || sc->vsc_reset[i].complete)
			return (true);
	}
	return (false);
}

static void
pci_vtfs_configure_instance_features(struct pci_vtfs_softc *sc)
{

	/*
	 * identity= makes FREEZE and STATE_TRANSFER mandatory during the
	 * authenticated backend handshake.  Only a reconstructible instance
	 * may promise guest-visible suspend.
	 */
	if (sc->vsc_backend_identity != NULL)
		sc->vsc_consts.vc_hv_caps |= VIRTIO_F_SUSPEND;
	else
		sc->vsc_consts.vc_hv_caps &= ~VIRTIO_F_SUSPEND;
}

static bool
pci_vtfs_restored_thaw_state(const struct pci_vtfs_softc *sc,
    const void **state, size_t *state_len)
{

	if (sc->vsc_checkpoint_backend_state == NULL)
		return (false);
	*state = sc->vsc_checkpoint_backend_state;
	*state_len = sc->vsc_checkpoint_backend_state_len;
	return (true);
}

static int
pci_vtfs_suspend_device(void *vsc)
{
	struct pci_vtfs_softc *sc;
	int error;

	sc = vsc;
	if (sc->vsc_connection == NULL || !sc->vsc_callbacks_set ||
	    sc->vsc_reconnecting || pci_vtfs_reset_pending(sc))
		return (EBUSY);
	error = pci_vtfs_begin_quiesce_wait(sc);
	VIRTIO_PROBE_FS_BACKEND("vtfs", "guest-suspend", 0, error);
	if (error == 0)
		sc->vsc_guest_suspended = true;
	return (error);
}

static int
pci_vtfs_resume_device(void *vsc)
{
	struct pci_vtfs_softc *sc;
	const void *state;
	size_t state_len;
	int error;

	sc = vsc;
	if (!sc->vsc_guest_suspended || sc->vsc_connection == NULL)
		return (EINVAL);
	if (pci_vtfs_restored_thaw_state(sc, &state, &state_len))
		error = virtio_fs_connection_begin_thaw(sc->vsc_connection,
		    state, state_len);
	else
		error = virtio_fs_connection_begin_thaw_saved(
		    sc->vsc_connection);
	if (error == 0) {
		error = pci_vtfs_sync_events(sc);
		if (error != 0)
			vi_set_needs_reset(&sc->vsc_vs);
		else
			error = pci_vtfs_control_wait(sc);
	}
	VIRTIO_PROBE_FS_BACKEND("vtfs", "guest-resume", 0, error);
	if (error == 0) {
		sc->vsc_guest_suspended = false;
		pci_vtfs_backend_state_clear(sc);
	}
	return (error);
}

/*
 * Restore preflight is used both by the normal pause-owned restore path and
 * by independent compatibility callers.  The device mutex is deliberately
 * non-recursive, so the latter must acquire it while the former must reuse
 * the current thread's ownership.  Keep this decision outside the snapshot
 * codec so it remains directly testable in builds without BHYVE_SNAPSHOT.
 */
static bool
pci_vtfs_serializer_enter(struct pci_vtfs_softc *sc)
{
	bool acquired;

	acquired = !pthread_mutex_isowned_np(&sc->vsc_mtx);
	if (acquired)
		pthread_mutex_lock(&sc->vsc_mtx);
	return (acquired);
}

static void
pci_vtfs_serializer_exit(struct pci_vtfs_softc *sc, bool acquired)
{

	if (acquired)
		pthread_mutex_unlock(&sc->vsc_mtx);
}

static const struct virtio_consts vtfs_vi_consts = {
	.vc_name = "vtfs",
	.vc_cfgsize = BHYVE_VIRTIO_FS_CONFIG_BASE_SIZE,
	.vc_reset = pci_vtfs_reset,
	.vc_qnotify = pci_vtfs_notify,
	.vc_cfgread = pci_vtfs_cfgread,
	.vc_qreset = pci_vtfs_qreset,
	.vc_suspend = pci_vtfs_suspend_device,
	.vc_resume_device = pci_vtfs_resume_device,
	.vc_hv_caps = VIRTIO_F_RING_RESET,
#ifdef BHYVE_SNAPSHOT
	.vc_pause = pci_vtfs_pause,
	.vc_resume = pci_vtfs_resume,
	.vc_snapshot = pci_vtfs_snapshot,
#endif
};

#ifdef BHYVE_SNAPSHOT
static void
pci_vtfs_checkpoint_state_clear(struct pci_vtfs_softc *sc)
{

	pci_vtfs_backend_state_clear(sc);
	memset(&sc->vsc_checkpoint_fuse, 0, sizeof(sc->vsc_checkpoint_fuse));
	memset(&sc->vsc_checkpoint_backend, 0,
	    sizeof(sc->vsc_checkpoint_backend));
}

static int
pci_vtfs_rollback_quiesce(struct pci_vtfs_softc *sc, int original_error)
{
	int error;

	error = virtio_fs_connection_begin_thaw_saved(sc->vsc_connection);
	if (error == 0) {
		error = pci_vtfs_sync_events(sc);
		if (error != 0)
			vi_set_needs_reset(&sc->vsc_vs);
		else
			error = pci_vtfs_control_wait(sc);
	}
	VIRTIO_PROBE_FS_BACKEND("vtfs", "checkpoint-rollback-thaw",
	    (uint32_t)sc->vsc_checkpoint_backend_state_len, error);
	if (error != 0) {
		vi_set_needs_reset(&sc->vsc_vs);
		return (error);
	}
	return (original_error);
}

static int
pci_vtfs_pause(void *vsc)
{
	struct pci_vtfs_softc *sc;
	struct virtio_fs_backend_session backend;
	struct virtio_fs_session fuse;
	uint8_t *state;
	size_t state_len;
	int error;

	sc = vsc;
	pthread_mutex_lock(&sc->vsc_mtx);
	sc->vsc_checkpoint_lock_held = true;
	sc->vsc_checkpoint_borrowed_suspend = sc->vsc_guest_suspended;
	if (sc->vsc_backend_identity == NULL ||
	    sc->vsc_connection == NULL || !sc->vsc_callbacks_set ||
	    sc->vsc_reconnecting) {
		error = sc->vsc_backend_identity == NULL ? ENOTSUP : EBUSY;
		goto fail;
	}
	if (pci_vtfs_reset_pending(sc)) {
		error = EBUSY;
		goto fail;
	}
	if (!sc->vsc_checkpoint_borrowed_suspend) {
		error = pci_vtfs_begin_quiesce_wait(sc);
		if (error != 0) {
			VIRTIO_PROBE_FS_BACKEND("vtfs",
			    "checkpoint-quiesce", 0, error);
			goto fail;
		}
	}
	memset(&fuse, 0, sizeof(fuse));
	memset(&backend, 0, sizeof(backend));
	state_len =
	    virtio_fs_connection_checkpoint_size(sc->vsc_connection);
	state = malloc(MAX(state_len, 1));
	if (state == NULL) {
		error = sc->vsc_checkpoint_borrowed_suspend ? ENOMEM :
		    pci_vtfs_rollback_quiesce(sc, ENOMEM);
		goto fail;
	}
	error = virtio_fs_connection_checkpoint_copy(sc->vsc_connection,
	    &fuse, &backend, state,
	    state_len, &state_len);
	if (error != 0) {
		free(state);
		if (!sc->vsc_checkpoint_borrowed_suspend)
			error = pci_vtfs_rollback_quiesce(sc, error);
		goto fail;
	}
	/*
	 * A checkpoint can borrow a guest-initiated suspend.  Keep any restored
	 * thaw blob until its replacement has been captured successfully: it is
	 * still needed by resume_device() if this capture fails.
	 */
	pci_vtfs_checkpoint_state_clear(sc);
	sc->vsc_checkpoint_backend_state = state;
	sc->vsc_checkpoint_backend_state_len = state_len;
	sc->vsc_checkpoint_fuse = fuse;
	sc->vsc_checkpoint_backend = backend;
	VIRTIO_PROBE_FS_BACKEND("vtfs", "checkpoint-quiesce",
	    (uint32_t)state_len, 0);
	return (0);

fail:
	sc->vsc_checkpoint_borrowed_suspend = false;
	sc->vsc_checkpoint_lock_held = false;
	pthread_mutex_unlock(&sc->vsc_mtx);
	return (error);
}

static int
pci_vtfs_resume(void *vsc)
{
	struct pci_vtfs_softc *sc;
	int error;

	sc = vsc;
	if (!sc->vsc_checkpoint_lock_held) {
		pthread_mutex_lock(&sc->vsc_mtx);
		sc->vsc_checkpoint_lock_held = true;
	}
	if (sc->vsc_vs.vs_suspended) {
		sc->vsc_guest_suspended = true;
		/*
		 * Keep the restored opaque blob until guest resume.  The
		 * connection also has a local freeze blob, but on a destination
		 * that blob describes the pre-restore backend incarnation.
		 */
		memset(&sc->vsc_checkpoint_fuse, 0,
		    sizeof(sc->vsc_checkpoint_fuse));
		memset(&sc->vsc_checkpoint_backend, 0,
		    sizeof(sc->vsc_checkpoint_backend));
		sc->vsc_checkpoint_borrowed_suspend = false;
		sc->vsc_checkpoint_lock_held = false;
		pthread_mutex_unlock(&sc->vsc_mtx);
		return (0);
	}
	/*
	 * checkpoint_borrowed_suspend describes the destination before restore,
	 * not the restored guest-visible state.  When a runnable image replaces
	 * that suspended destination, the freeze borrowed by checkpoint pause
	 * must be thawed below; otherwise the backend remains quiesced forever
	 * after common checkpoint resume opens queue admission.
	 */
	sc->vsc_guest_suspended = false;
	error = virtio_fs_connection_begin_thaw(sc->vsc_connection,
	    sc->vsc_checkpoint_backend_state,
	    sc->vsc_checkpoint_backend_state_len);
	if (error == 0) {
		error = pci_vtfs_sync_events(sc);
		if (error != 0)
			vi_set_needs_reset(&sc->vsc_vs);
		else
			error = pci_vtfs_control_wait(sc);
	}
	VIRTIO_PROBE_FS_BACKEND("vtfs", "checkpoint-thaw",
	    (uint32_t)sc->vsc_checkpoint_backend_state_len, error);
	if (error == 0)
		pci_vtfs_checkpoint_state_clear(sc);
	sc->vsc_checkpoint_borrowed_suspend = false;
	sc->vsc_checkpoint_lock_held = false;
	pthread_mutex_unlock(&sc->vsc_mtx);
	return (error);
}

static int
pci_vtfs_snapshot(void *vsc, struct vm_snapshot_meta *meta)
{
	struct pci_vtfs_softc *sc;
	struct virtio_fs_state_decoded decoded;
	struct virtio_fs_state_source source;
	struct virtio_fs_backend_session validation_backend;
	struct virtio_fs_session fuse;
	const struct virtio_fs_backend_session *expected_backend;
	uint8_t *blob, *state_copy;
	size_t blob_size, state_len, tag_len, written;
	uint32_t saved_size;
	int error;

	sc = vsc;
	if (sc->vsc_backend_identity == NULL ||
	    (!sc->vsc_checkpoint_lock_held &&
	    meta->op != VM_SNAPSHOT_VALIDATE))
		return (EBUSY);
	expected_backend = &sc->vsc_checkpoint_backend;
	/*
	 * A restored snapshot must be bound to the destination backend's live
	 * contract just as a validation pass is.  The checkpoint fields contain
	 * source state (or are empty on a fresh destination), so using them for
	 * RESTORE would either reject a valid migration or validate against stale
	 * destination state.
	 */
	if (meta->op != VM_SNAPSHOT_SAVE) {
		error = virtio_fs_connection_checkpoint_contract(
		    sc->vsc_connection, &validation_backend);
		if (error != 0)
			return (error);
		expected_backend = &validation_backend;
	}
	tag_len = strnlen((const char *)sc->vsc_config,
	    BHYVE_VIRTIO_FS_TAG_SIZE);
	source = (struct virtio_fs_state_source) {
		.tag = sc->vsc_config,
		.tag_len = tag_len,
		.num_request_queues = sc->vsc_num_request_queues,
		.negotiated_features = sc->vsc_vs.vs_negotiated_caps,
		.fuse_session = &sc->vsc_checkpoint_fuse,
		.backend_session = &sc->vsc_checkpoint_backend,
		.backend_identity = sc->vsc_backend_identity,
		.backend_identity_len = strlen(sc->vsc_backend_identity),
		.backend_state = sc->vsc_checkpoint_backend_state,
		.backend_state_len = sc->vsc_checkpoint_backend_state_len,
	};
	blob = NULL;
	state_copy = NULL;
	if (meta->op == VM_SNAPSHOT_SAVE) {
		error = virtio_fs_state_size(&source, &blob_size);
		if (error != 0)
			goto done;
		if (blob_size > UINT32_MAX) {
			error = EOVERFLOW;
			goto done;
		}
		saved_size = (uint32_t)blob_size;
		SNAPSHOT_LE32_OR_LEAVE(saved_size, meta, error, done);
		blob = malloc(blob_size);
		if (blob == NULL) {
			error = ENOMEM;
			goto done;
		}
		error = virtio_fs_state_encode(&source, blob, blob_size,
		    &written);
		if (error != 0)
			goto done;
		SNAPSHOT_BUF_OR_LEAVE(blob, written, meta, error, done);
		error = 0;
		goto done;
	}

	saved_size = 0;
	SNAPSHOT_LE32_OR_LEAVE(saved_size, meta, error, done);
	if (saved_size < VIRTIO_FS_STATE_HEADER_SIZE ||
	    saved_size > VIRTIO_FS_STATE_HEADER_SIZE +
	    BHYVE_VIRTIO_FS_TAG_SIZE + VIRTIO_FS_STATE_IDENTITY_MAX +
	    VIRTIO_FS_BACKEND_MAX_FRAME) {
		error = E2BIG;
		goto done;
	}
	blob = malloc(saved_size);
	if (blob == NULL) {
		error = ENOMEM;
		goto done;
	}
	SNAPSHOT_BUF_OR_LEAVE(blob, saved_size, meta, error, done);
	error = virtio_fs_state_decode(blob, saved_size, sc->vsc_config,
	    tag_len, sc->vsc_num_request_queues,
	    sc->vsc_vs.vs_negotiated_caps,
	    sc->vsc_backend_identity, strlen(sc->vsc_backend_identity),
	    expected_backend, &decoded);
	if (error != 0)
		goto done;
	if (decoded.negotiated_features !=
	    sc->vsc_vs.vs_negotiated_caps) {
		error = ENOTSUP;
		goto done;
	}
	/*
	 * Decode verifies the complete portable FUSE/backend session and binds
	 * it to this destination's tag, queue topology, negotiated features,
	 * backend identity, and prepared backend session.  Validation must not
	 * publish the FUSE session or replace the opaque backend state.
	 */
	if (meta->op == VM_SNAPSHOT_VALIDATE) {
		error = 0;
		goto done;
	}
	state_len = decoded.backend_state_len;
	state_copy = malloc(MAX(state_len, 1));
	if (state_copy == NULL) {
		error = ENOMEM;
		goto done;
	}
	if (state_len != 0)
		memcpy(state_copy, decoded.backend_state, state_len);
	fuse = decoded.fuse_session;
	error = virtio_fs_connection_restore_session(sc->vsc_connection,
	    &fuse);
	if (error != 0)
		goto done;
	free(sc->vsc_checkpoint_backend_state);
	sc->vsc_checkpoint_backend_state = state_copy;
	sc->vsc_checkpoint_backend_state_len = state_len;
	state_copy = NULL;
	sc->vsc_checkpoint_fuse = fuse;
	error = 0;

done:
	free(state_copy);
	free(blob);
	return (error);
}

static int
pci_vtfs_snapshot_validate(struct vm_snapshot_meta *meta)
{
	struct pci_devinst *pi;
	struct pci_vtfs_softc *sc;
	bool acquired;
	int error;

	if (meta == NULL || meta->op != VM_SNAPSHOT_VALIDATE ||
	    meta->dev_data == NULL)
		return (EINVAL);
	pi = meta->dev_data;
	sc = pi->pi_arg;
	if (sc == NULL)
		return (EINVAL);
	acquired = pci_vtfs_serializer_enter(sc);
	error = vi_pci_snapshot(meta);
	pci_vtfs_serializer_exit(sc, acquired);
	return (error);
}
#endif

static int
pci_vtfs_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_vtfs_softc *sc;
	const char *identity, *path, *queues_value, *tag;
	uint32_t queues;
	bool cond_initialized, intr_initialized, mutex_initialized, packed;
	bool notifications;
	pthread_condattr_t condattr;
	bool condattr_initialized;
	int error;

	path = get_config_value_node(nvl, "path");
	tag = get_config_value_node(nvl, "tag");
	identity = get_config_value_node(nvl, "identity");
	if (path == NULL || tag == NULL)
		return (1);
	if (identity != NULL && (identity[0] == '\0' ||
	    strlen(identity) > VIRTIO_FS_STATE_IDENTITY_MAX))
		return (1);
	queues = VTFS_DEFAULT_REQUEST_QUEUES;
	queues_value = get_config_value_node(nvl, "queues");
	if (queues_value != NULL &&
	    pci_vtfs_parse_u32(queues_value, 1, VTFS_MAX_REQUEST_QUEUES,
	    &queues) != 0)
		return (1);
	notifications = get_config_bool_node_default(nvl, "notifications",
	    false);
	sc = calloc(1, sizeof(*sc));
	if (sc == NULL)
		return (1);
	intr_initialized = false;
	mutex_initialized = false;
	cond_initialized = false;
	condattr_initialized = false;
	sc->vsc_num_request_queues = queues;
	sc->vsc_notifications = notifications;
	sc->vsc_nvq = queues + 1 + (notifications ? 1 : 0);
	sc->vsc_backend_path = strdup(path);
	sc->vsc_backend_identity = identity == NULL ? NULL :
	    strdup(identity);
	sc->vsc_vq = calloc(sc->vsc_nvq, sizeof(*sc->vsc_vq));
	sc->vsc_reset = calloc(sc->vsc_nvq, sizeof(*sc->vsc_reset));
	sc->vsc_notify_pending = calloc(sc->vsc_nvq,
	    sizeof(*sc->vsc_notify_pending));
	if (sc->vsc_backend_path == NULL || sc->vsc_vq == NULL ||
	    sc->vsc_reset == NULL ||
	    sc->vsc_notify_pending == NULL ||
	    (identity != NULL && sc->vsc_backend_identity == NULL))
		goto fail;
	if (pthread_mutex_init(&sc->vsc_mtx, NULL) != 0)
		goto fail;
	mutex_initialized = true;
	if (pthread_condattr_init(&condattr) != 0)
		goto fail;
	condattr_initialized = true;
	if (pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC) != 0 ||
	    pthread_cond_init(&sc->vsc_checkpoint_cv, &condattr) != 0)
		goto fail;
	cond_initialized = true;
	pthread_condattr_destroy(&condattr);
	condattr_initialized = false;
	error = virtio_fs_config_encode_notification(tag, strlen(tag), queues,
	    notifications ? BHYVE_VIRTIO_FS_NOTIFY_BUF_SIZE : 0,
	    sc->vsc_config);
	if (error != 0)
		goto fail;
	sc->vsc_consts = vtfs_vi_consts;
	sc->vsc_consts.vc_nvq = (int)sc->vsc_nvq;
	if (notifications) {
		sc->vsc_consts.vc_cfgsize = BHYVE_VIRTIO_FS_CONFIG_SIZE;
		sc->vsc_consts.vc_hv_caps |= BHYVE_VIRTIO_FS_F_NOTIFICATION;
	}
	packed = get_config_bool_node_default(nvl, "packed", false);
	if (packed)
		sc->vsc_consts.vc_hv_caps |= VIRTIO_F_RING_PACKED;
	vi_softc_linkup(&sc->vsc_vs, &sc->vsc_consts, sc, pi, sc->vsc_vq);
	sc->vsc_vs.vs_mtx = &sc->vsc_mtx;
	for (uint32_t i = 0; i < sc->vsc_nvq; i++)
		sc->vsc_vq[i].vq_qsize = VTFS_RINGSZ;
	if (vi_pci_select_transport(&sc->vsc_vs, nvl,
	    VIRTIO_PCI_MODERN_ONLY) != 0)
		goto fail;
	sc->vsc_offer = (struct virtio_fs_backend_hello) {
		.minimum_version = VIRTIO_FS_BACKEND_VERSION,
		.maximum_version = VIRTIO_FS_BACKEND_VERSION,
		.features = VIRTIO_FS_BACKEND_F_CANCEL |
		    VIRTIO_FS_BACKEND_F_FREEZE |
		    (notifications ? VIRTIO_FS_BACKEND_F_NOTIFICATION : 0) |
		    (identity == NULL ? 0 :
		    VIRTIO_FS_BACKEND_F_STATE_TRANSFER),
		.maximum_message = BHYVE_VIRTIO_FS_MAX_MESSAGE,
		.maximum_inflight = VTFS_MAX_INFLIGHT,
		.maximum_pending_bytes = VTFS_PENDING_BYTES,
	};
	error = pci_vtfs_connect(sc);
	if (error != 0)
		goto fail;
	pci_vtfs_configure_instance_features(sc);
	vi_pci_modern_set_identity(&sc->vsc_vs, VIRTIO_ID_FS);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_STORAGE);
	pci_set_cfgdata8(pi, PCIR_SUBCLASS, PCIS_STORAGE_OTHER);
	if (vi_intr_init(&sc->vsc_vs, 1, fbsdrun_virtio_msix()) != 0)
		goto fail;
	intr_initialized = true;
	if (vi_pci_modern_init(&sc->vsc_vs, 2) != 0)
		goto fail;
	return (0);

fail:
	pci_vtfs_disconnect_sync(sc);
	if (condattr_initialized)
		pthread_condattr_destroy(&condattr);
	if (cond_initialized)
		pthread_cond_destroy(&sc->vsc_checkpoint_cv);
	free(sc->vsc_vs.vs_modern);
	if (intr_initialized)
		pthread_mutex_destroy(&sc->vsc_vs.vs_isr_mtx);
	if (mutex_initialized)
		pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc->vsc_notify_pending);
	free(sc->vsc_reset);
	free(sc->vsc_vq);
#ifdef BHYVE_SNAPSHOT
	pci_vtfs_checkpoint_state_clear(sc);
#endif
	free(sc->vsc_backend_identity);
	free(sc->vsc_backend_path);
	free(sc);
	return (1);
}

static const struct pci_devemu pci_de_vtfs = {
	.pe_emu = "virtio-fs",
	.pe_init = pci_vtfs_init,
	.pe_cfgwrite = vi_pci_modern_cfgwrite,
	.pe_cfgread = vi_pci_modern_cfgread,
	.pe_barwrite = vi_pci_write,
	.pe_barread = vi_pci_read,
#ifdef BHYVE_SNAPSHOT
	.pe_snapshot = vi_pci_snapshot,
	.pe_snapshot_validate = pci_vtfs_snapshot_validate,
	.pe_snapshot_compat = vi_pci_snapshot_compat,
	.pe_pause = vi_pci_pause,
	.pe_resume = vi_pci_resume,
#endif
};
PCI_EMUL_SET(pci_de_vtfs);
