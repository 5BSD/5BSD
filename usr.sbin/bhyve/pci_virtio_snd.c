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
#include <limits.h>
#include <pthread.h>
#include <pthread_np.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "audio.h"
#include "bhyverun.h"
#include "config.h"
#include "mevent.h"
#include "pci_emul.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif
#include "virtio.h"
#include "virtio_pci_modern_probes.h"
#include "virtio_snd_async.h"
#include "virtio_snd_host.h"
#include "virtio_snd_queue.h"

/*
 * Release-ledger anchors for sound-device qualification.  The device has a
 * deterministic null backend and a production, host-dependent OSS backend;
 * neither backend changes the guest-visible protocol contract.
 * VIRTIO_ACTIVATION_ASSERTION: control-queue-completions
 * VIRTIO_ACTIVATION_ASSERTION: four-queue-modern-device
 * VIRTIO_ACTIVATION_ASSERTION: portable-state-snapshot
 * VIRTIO_ACTIVATION_ASSERTION: release-log-and-control-queue
 * VIRTIO_ACTIVATION_ASSERTION: sound-io-dtrace-and-byte-counters
 */

#define	VTSND_RINGSZ		256
#define	VTSND_CONTROLQ		0
#define	VTSND_EVENTQ		1
#define	VTSND_TXQ		2
#define	VTSND_RXQ		3
#define	VTSND_NVQ		4
#define	VTSND_BACKEND_NULL	"null"
#define	VTSND_BACKEND_OSS	"oss"
#define	VTSND_BACKEND_PATH_MAX	64U
#define	PCI_VTSND_STATE_MAGIC	0x444e5356U	/* "VSND", little-endian. */
#define	PCI_VTSND_STATE_VERSION	1U
#define	PCI_VTSND_STATE_HEADER_SIZE	144U
#define	PCI_VTSND_STATE_SIZE	(PCI_VTSND_STATE_HEADER_SIZE + \
	    BHYVE_VTSND_STATE_SIZE)

enum pci_vtsnd_backend {
	VTSND_BACKEND_KIND_NULL = 0,
	VTSND_BACKEND_KIND_OSS = 1,
};

struct pci_vtsnd_softc;

struct pci_vtsnd_pending {
	struct pci_vtsnd_softc *sc;
	struct vqueue_info *vq;
	struct vi_req req;
	struct virtio_snd_host_xfer_claim claim;
	struct iovec writable[BHYVE_VTSND_MAX_CHAIN_SEGMENTS];
	size_t nwritable;
	size_t payload_size;
	bool active;
};

struct pci_vtsnd_softc {
	struct virtio_softc vssc_vs;
	struct vqueue_info vssc_vq[VTSND_NVQ];
	struct virtio_consts vssc_consts;
	pthread_mutex_t vssc_mtx;
	struct virtio_snd_host *vssc_host;
	struct virtio_snd_async *vssc_async;
	struct pci_vtsnd_pending vssc_pending[BHYVE_VTSND_STREAMS];
	struct audio *vssc_audio[BHYVE_VTSND_STREAMS];
	struct mevent *vssc_audio_event[BHYVE_VTSND_STREAMS];
	int (*vssc_progress)(void *, enum virtio_snd_async_direction, void *,
	    size_t, size_t *);
	void *vssc_progress_arg;
	_Atomic uint64_t vssc_playback_bytes;
	_Atomic uint64_t vssc_capture_bytes;
	enum pci_vtsnd_backend vssc_backend;
	char vssc_play_path[VTSND_BACKEND_PATH_MAX];
	char vssc_record_path[VTSND_BACKEND_PATH_MAX];
	bool vssc_resetting;
	unsigned int vssc_debug;
};

/*
 * Transport callbacks normally enter with vs_mtx held, while direct model
 * lifecycle calls do not.  These callbacks preserve that runtime ownership
 * with pthread_mutex_isowned_np(), a conditional transfer the static checker
 * cannot express.  Keep this exception local to those callback boundaries.
 */
static void pci_vtsnd_reset(void *) __no_lock_analysis;
static int pci_vtsnd_qreset(void *, struct vqueue_info *, uint64_t)
    __no_lock_analysis;
static void pci_vtsnd_notify(void *, struct vqueue_info *) __no_lock_analysis;
static int pci_vtsnd_cfgread(void *, int, int, uint32_t *);
static int pci_vtsnd_suspend(void *) __no_lock_analysis;
static int pci_vtsnd_resume_device(void *);
static int pci_vtsnd_backend_ready(void *, uint32_t);
static bool pci_vtsnd_drain_data(struct pci_vtsnd_softc *,
    struct vqueue_info *);
static void pci_vtsnd_disable_audio_event(struct pci_vtsnd_softc *,
    uint32_t);
#ifdef BHYVE_SNAPSHOT
/*
 * These callbacks form one lifecycle operation: pause retains vssc_mtx and
 * resume releases it.  The compiler's intra-procedural lock analysis cannot
 * express that paired ownership transfer, so keep the exception local to the
 * pair rather than disabling analysis for the device or its callers.
 */
static int pci_vtsnd_pause(void *) __no_lock_analysis;
static int pci_vtsnd_resume(void *) __no_lock_analysis;
static int pci_vtsnd_snapshot(void *, struct vm_snapshot_meta *);
static int pci_vtsnd_snapshot_validate(struct vm_snapshot_meta *);
#endif

static const struct virtio_consts vtsnd_vi_consts = {
	.vc_name = "vtsnd",
	.vc_nvq = VTSND_NVQ,
	.vc_cfgsize = BHYVE_VTSND_CONFIG_SIZE,
	.vc_reset = pci_vtsnd_reset,
	.vc_qnotify = pci_vtsnd_notify,
	.vc_cfgread = pci_vtsnd_cfgread,
	.vc_qreset = pci_vtsnd_qreset,
	.vc_suspend = pci_vtsnd_suspend,
	.vc_resume_device = pci_vtsnd_resume_device,
#ifdef BHYVE_SNAPSHOT
	.vc_pause = pci_vtsnd_pause,
	.vc_resume = pci_vtsnd_resume,
#else
	.vc_pause = vi_pci_lifecycle_noop,
	.vc_resume = vi_pci_lifecycle_noop,
#endif
#ifdef BHYVE_SNAPSHOT
	.vc_snapshot = pci_vtsnd_snapshot,
#endif
	/*
	 * PCM completion can be retained on host readiness and is cancelled or
	 * completed by a backend event.  Per-stream ownership prevents stale or
	 * duplicate completions, but does not justify the stronger device-wide
	 * VIRTIO_F_IN_ORDER promise.
	 */
	.vc_hv_caps = VIRTIO_F_RING_RESET | VIRTIO_F_SUSPEND,
};

static bool
pci_vtsnd_backend_valid(const char *backend)
{

	return (backend == NULL || strcmp(backend, VTSND_BACKEND_NULL) == 0 ||
	    strcmp(backend, VTSND_BACKEND_OSS) == 0);
}

static bool
pci_vtsnd_state_path_canonical(const uint8_t *path, bool required)
{
	const uint8_t *end;

	end = memchr(path, '\0', VTSND_BACKEND_PATH_MAX);
	if (end == NULL || (required && end == path))
		return (false);
	for (const uint8_t *p = end + 1;
	    p < path + VTSND_BACKEND_PATH_MAX; p++) {
		if (*p != 0)
			return (false);
	}
	return (true);
}

static int
pci_vtsnd_state_header_validate(const struct pci_vtsnd_softc *sc,
    const uint8_t state[PCI_VTSND_STATE_SIZE])
{
	uint32_t backend;
	bool paths_required;

	if (le32dec(state) != PCI_VTSND_STATE_MAGIC ||
	    le16dec(state + 4) != PCI_VTSND_STATE_VERSION ||
	    le16dec(state + 6) != PCI_VTSND_STATE_HEADER_SIZE ||
	    le32dec(state + 12) != 0)
		return (EINVAL);
	backend = le32dec(state + 8);
	if (backend != VTSND_BACKEND_KIND_NULL &&
	    backend != VTSND_BACKEND_KIND_OSS)
		return (EINVAL);
	paths_required = backend == VTSND_BACKEND_KIND_OSS;
	if (!pci_vtsnd_state_path_canonical(state + 16, paths_required) ||
	    !pci_vtsnd_state_path_canonical(state + 80, paths_required))
		return (EINVAL);
	if (!paths_required &&
	    (state[16] != 0 || state[80] != 0))
		return (EINVAL);
	if (backend != (uint32_t)sc->vssc_backend)
		return (ENOTSUP);
	if (memcmp(state + 16, sc->vssc_play_path,
	    VTSND_BACKEND_PATH_MAX) != 0 ||
	    memcmp(state + 80, sc->vssc_record_path,
	    VTSND_BACKEND_PATH_MAX) != 0)
		return (ENOTSUP);
	return (0);
}

static int __unused
pci_vtsnd_state_encode(struct pci_vtsnd_softc *sc,
    uint8_t state[PCI_VTSND_STATE_SIZE])
{
	int error;

	memset(state, 0, PCI_VTSND_STATE_SIZE);
	le32enc(state, PCI_VTSND_STATE_MAGIC);
	le16enc(state + 4, PCI_VTSND_STATE_VERSION);
	le16enc(state + 6, PCI_VTSND_STATE_HEADER_SIZE);
	le32enc(state + 8, sc->vssc_backend);
	memcpy(state + 16, sc->vssc_play_path, VTSND_BACKEND_PATH_MAX);
	memcpy(state + 80, sc->vssc_record_path, VTSND_BACKEND_PATH_MAX);
	error = virtio_snd_host_state_encode(sc->vssc_host,
	    state + PCI_VTSND_STATE_HEADER_SIZE, BHYVE_VTSND_STATE_SIZE);
	if (error != 0)
		memset(state, 0, PCI_VTSND_STATE_SIZE);
	return (error);
}

static int
pci_vtsnd_state_validate(struct pci_vtsnd_softc *sc, const void *source,
    size_t source_size)
{
	const uint8_t *state;
	int error;

	if (sc == NULL || source == NULL ||
	    source_size != PCI_VTSND_STATE_SIZE)
		return (EINVAL);
	state = source;
	error = pci_vtsnd_state_header_validate(sc, state);
	if (error != 0)
		return (error);
	return (virtio_snd_host_state_validate(
	    state + PCI_VTSND_STATE_HEADER_SIZE, BHYVE_VTSND_STATE_SIZE));
}

static int __unused
pci_vtsnd_state_restore(struct pci_vtsnd_softc *sc, const void *source,
    size_t source_size)
{
	const uint8_t *state;
	int error;

	error = pci_vtsnd_state_validate(sc, source, source_size);
	if (error != 0)
		return (error);
	state = source;
	return (virtio_snd_host_state_restore(sc->vssc_host,
	    state + PCI_VTSND_STATE_HEADER_SIZE, BHYVE_VTSND_STATE_SIZE));
}

static void
pci_vtsnd_account(struct pci_vtsnd_softc *sc,
    enum virtio_snd_async_direction direction, size_t bytes)
{
	uint64_t capture, playback;
	uint32_t queue;

	if (direction == BHYVE_VTSND_ASYNC_PLAYBACK) {
		playback = atomic_fetch_add_explicit(&sc->vssc_playback_bytes,
		    bytes, memory_order_relaxed) + bytes;
		capture = atomic_load_explicit(&sc->vssc_capture_bytes,
		    memory_order_relaxed);
		queue = VTSND_TXQ;
	} else {
		capture = atomic_fetch_add_explicit(&sc->vssc_capture_bytes,
		    bytes, memory_order_relaxed) + bytes;
		playback = atomic_load_explicit(&sc->vssc_playback_bytes,
		    memory_order_relaxed);
		queue = VTSND_RXQ;
	}
	VIRTIO_PROBE_SOUND_IO(sc->vssc_vs.vs_vc->vc_name, queue, bytes,
	    playback, capture);
	if (sc->vssc_debug >= 2)
		fprintf(stderr,
		    "vtsnd: %s bytes=%zu playback_total=%ju "
		    "capture_total=%ju\n",
		    direction == BHYVE_VTSND_ASYNC_PLAYBACK ?
		    "playback" : "capture", bytes, (uintmax_t)playback,
		    (uintmax_t)capture);
}

static int
pci_vtsnd_set_params(void *arg, uint32_t stream_id,
    const struct virtio_snd_host_params *params)
{
	struct audio_params audio_params;
	struct pci_vtsnd_softc *sc;

	sc = arg;
	if (sc->vssc_backend == VTSND_BACKEND_KIND_NULL)
		return (0);
	if (stream_id >= nitems(sc->vssc_audio) ||
	    sc->vssc_audio[stream_id] == NULL ||
	    params->format != BHYVE_VTSND_FMT_S16)
		return (EINVAL);
	audio_params.channels = params->channels;
	audio_params.format = AFMT_S16_LE;
	if (params->rate == BHYVE_VTSND_RATE_44100)
		audio_params.rate = 44100;
	else if (params->rate == BHYVE_VTSND_RATE_48000)
		audio_params.rate = 48000;
	else
		return (EINVAL);
	return (audio_set_params(sc->vssc_audio[stream_id], &audio_params) ==
	    0 ? 0 : EIO);
}

static int
pci_vtsnd_lifecycle(void *arg __unused, uint32_t stream_id __unused)
{
	return (0);
}

static int
pci_vtsnd_playback(void *arg, uint32_t stream_id __unused,
    const void *payload __unused, size_t payload_size)
{
	struct pci_vtsnd_softc *sc;

	sc = arg;
	pci_vtsnd_account(sc, BHYVE_VTSND_ASYNC_PLAYBACK, payload_size);
	return (0);
}

static int
pci_vtsnd_capture(void *arg, uint32_t stream_id __unused, void *payload,
    size_t payload_size)
{
	struct pci_vtsnd_softc *sc;

	sc = arg;
	memset(payload, 0, payload_size);
	pci_vtsnd_account(sc, BHYVE_VTSND_ASYNC_CAPTURE, payload_size);
	return (0);
}

static int
pci_vtsnd_release(void *arg, uint32_t stream_id)
{
	struct pci_vtsnd_softc *sc;
	uint64_t capture, playback;

	sc = arg;
	playback = atomic_load_explicit(&sc->vssc_playback_bytes,
	    memory_order_relaxed);
	capture = atomic_load_explicit(&sc->vssc_capture_bytes,
	    memory_order_relaxed);
	if (sc->vssc_debug >= 1)
		fprintf(stderr,
		    "vtsnd: stream release id=%u playback_bytes=%ju "
		    "capture_bytes=%ju\n", stream_id, (uintmax_t)playback,
		    (uintmax_t)capture);
	return (0);
}

static int
pci_vtsnd_null_progress(void *arg,
    enum virtio_snd_async_direction direction, void *buffer,
    size_t remaining, size_t *progress)
{
	struct pci_vtsnd_softc *sc;
	int error;

	sc = arg;
	if (direction == BHYVE_VTSND_ASYNC_PLAYBACK)
		error = pci_vtsnd_playback(sc, 0, buffer, remaining);
	else if (direction == BHYVE_VTSND_ASYNC_CAPTURE)
		error = pci_vtsnd_capture(sc, 1, buffer, remaining);
	else
		error = EINVAL;
	*progress = error == 0 ? remaining : 0;
	return (error);
}

static int
pci_vtsnd_oss_progress(void *arg,
    enum virtio_snd_async_direction direction, void *buffer,
    size_t remaining, size_t *progress)
{
	struct pci_vtsnd_softc *sc;
	struct audio *audio;
	ssize_t done;
	int saved_errno;

	sc = arg;
	*progress = 0;
	if (direction == BHYVE_VTSND_ASYNC_PLAYBACK)
		audio = sc->vssc_audio[0];
	else if (direction == BHYVE_VTSND_ASYNC_CAPTURE)
		audio = sc->vssc_audio[1];
	else
		return (EINVAL);
	if (audio == NULL)
		return (ENXIO);
	errno = 0;
	if (direction == BHYVE_VTSND_ASYNC_PLAYBACK)
		done = audio_playback_some(audio, buffer, remaining);
	else
		done = audio_record_some(audio, buffer, remaining);
	saved_errno = errno;
	if (done < 0) {
		if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK)
			return (EAGAIN);
		return (saved_errno == 0 ? EIO : saved_errno);
	}
	if (done == 0 || (size_t)done > remaining)
		return (EIO);
	*progress = (size_t)done;
	pci_vtsnd_account(sc, direction, *progress);
	return (0);
}

static void
pci_vtsnd_audio_event(int fd __unused, enum ev_type type, void *arg)
{
	struct pci_vtsnd_pending *pending;
	struct pci_vtsnd_softc *sc;
	ptrdiff_t stream_id;

	pending = arg;
	sc = pending->sc;
	stream_id = pending - sc->vssc_pending;
	if (stream_id < 0 || stream_id >= (ptrdiff_t)nitems(sc->vssc_pending))
		return;
	if ((stream_id == 0 && type != EVF_WRITE) ||
	    (stream_id == 1 && type != EVF_READ))
		return;
	(void)pci_vtsnd_backend_ready(sc, (uint32_t)stream_id);
}

static int
pci_vtsnd_async_progress(void *arg,
    enum virtio_snd_async_direction direction, void *buffer,
    size_t remaining, size_t *progress)
{
	struct pci_vtsnd_softc *sc;

	sc = arg;
	if (sc->vssc_progress == NULL) {
		*progress = 0;
		return (ENXIO);
	}
	return (sc->vssc_progress(sc->vssc_progress_arg, direction, buffer,
	    remaining, progress));
}

/*
 * Advance one retained stream after its host backend reports readiness.
 *
 * Backend event sources must enter through this function rather than call the
 * generic async owner directly.  Holding vssc_mtx gives the completion
 * callback the same serialization as a guest queue notification and excludes
 * queue reset, device reset, release, pause, and teardown while it publishes
 * or discards the retained request.
 */
static int __unused
pci_vtsnd_backend_ready(void *arg, uint32_t stream_id)
{
	struct pci_vtsnd_pending *pending;
	struct pci_vtsnd_softc *sc;
	struct vqueue_info *vq;
	uint64_t generation;
	int error;

	sc = arg;
	if (sc == NULL || stream_id >= nitems(sc->vssc_pending))
		return (EINVAL);
	pthread_mutex_lock(&sc->vssc_mtx);
	pending = &sc->vssc_pending[stream_id];
	if (sc->vssc_resetting)
		error = EBUSY;
	else if (!pending->active) {
		/*
		 * Retire a stale readiness indication while the same lock that
		 * protects pending ownership is held.  Disabling after dropping the
		 * lock can race a guest notification which installs a replacement
		 * job and re-enables this source, leaving that new job stranded.
		 * Terminal active jobs disable the source in async_complete(), also
		 * while this lock is held.
		 */
		pci_vtsnd_disable_audio_event(sc, stream_id);
		error = ENOENT;
	}
	else {
		generation = pending->claim.generation;
		vq = pending->vq;
		error = virtio_snd_async_progress(sc->vssc_async, stream_id,
		    generation);
		/*
		 * The guest may have published more PCM requests in the same kick.
		 * drain_data() stopped when this stream became retained, so a
		 * terminal readiness completion must resume the already-available
		 * suffix.  The device mutex serializes this with reset and control
		 * transitions; immediate completions remain in drain_data()'s finite
		 * queue-sized loop rather than recursively re-entering here.
		 */
		if (error == 0 && !pending->active && !sc->vssc_resetting &&
		    (sc->vssc_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0 &&
		    vq_has_descs(vq) && !pci_vtsnd_drain_data(sc, vq))
			error = EIO;
	}
	pthread_mutex_unlock(&sc->vssc_mtx);
	return (error);
}

static void
pci_vtsnd_async_complete(void *arg, uintptr_t token,
    enum virtio_snd_async_status status, const void *capture,
    size_t capture_size)
{
	struct pci_vtsnd_pending completed, *pending;
	struct pci_vtsnd_softc *sc;
	size_t slot, used;
	bool owned, stale;
	int error, finish_error;

	sc = arg;
	pending = (struct pci_vtsnd_pending *)token;
	owned = false;
	slot = 0;
	for (size_t i = 0; i < nitems(sc->vssc_pending); i++) {
		if (pending == &sc->vssc_pending[i]) {
			owned = true;
			slot = i;
		}
	}
	if (!owned || !pending->active || pending->sc != sc ||
	    pending->vq == NULL || pending->claim.stream_id != slot ||
	    pending->claim.direction !=
	    (slot == 0 ? BHYVE_VTSND_OUTPUT : BHYVE_VTSND_INPUT)) {
		vi_set_needs_reset(&sc->vssc_vs);
		return;
	}
	completed = *pending;
	if (sc->vssc_audio_event[slot] != NULL)
		(void)mevent_disable(sc->vssc_audio_event[slot]);
	stale = sc->vssc_resetting ||
	    completed.req.queue_generation != completed.vq->vq_generation;
	finish_error = virtio_snd_host_xfer_finish(sc->vssc_host,
	    &pending->claim);
	pending->active = false;
	pending->vq = NULL;
	pending->nwritable = 0;
	pending->payload_size = 0;
	if (finish_error != 0) {
		vi_set_needs_reset(&sc->vssc_vs);
		vq_discard_req(completed.vq, &completed.req);
		return;
	}
	if (stale) {
		vq_discard_req(completed.vq, &completed.req);
		return;
	}
	if (completed.claim.direction == BHYVE_VTSND_OUTPUT) {
		error = virtio_snd_queue_playback_complete(completed.writable,
		    completed.nwritable,
		    status == BHYVE_VTSND_ASYNC_OK ? 0 : EIO, &used);
	} else {
		/*
		 * On a backend I/O error the async layer reports no
		 * capture payload (NULL/0).  Complete the request with
		 * the claimed payload size so it is returned to the
		 * guest with a per-request S_IO_ERR status (payload
		 * zeroed, full used length) instead of the zero-size
		 * EINVAL below escalating into a device reset.
		 */
		error = virtio_snd_queue_capture_complete(completed.writable,
		    completed.nwritable,
		    status == BHYVE_VTSND_ASYNC_OK ? capture : NULL,
		    status == BHYVE_VTSND_ASYNC_OK ? capture_size :
		    completed.payload_size,
		    status == BHYVE_VTSND_ASYNC_OK ? 0 : EIO, &used);
	}
	if (error != 0 || used > UINT32_MAX) {
		vi_set_needs_reset(&sc->vssc_vs);
		used = 0;
	}
	vq_relchain_req(completed.vq, &completed.req, (uint32_t)used);
	vq_endchains(completed.vq, !vq_has_descs(completed.vq));
}

static int
pci_vtsnd_cancel_pending(struct pci_vtsnd_softc *sc, uint32_t stream_id)
{
	struct pci_vtsnd_pending *pending;

	if (stream_id >= nitems(sc->vssc_pending))
		return (EINVAL);
	pending = &sc->vssc_pending[stream_id];
	if (!pending->active)
		return (0);
	return (virtio_snd_async_cancel(sc->vssc_async, stream_id,
	    pending->claim.generation));
}

static void
pci_vtsnd_disable_audio_event(struct pci_vtsnd_softc *sc,
    uint32_t stream_id)
{

	if (stream_id < nitems(sc->vssc_audio_event) &&
	    sc->vssc_audio_event[stream_id] != NULL)
		(void)mevent_disable(sc->vssc_audio_event[stream_id]);
}

static void
pci_vtsnd_delete_audio_events(struct pci_vtsnd_softc *sc)
{

	for (uint32_t stream_id = 0;
	    stream_id < nitems(sc->vssc_audio_event); stream_id++) {
		if (sc->vssc_audio_event[stream_id] == NULL)
			continue;
		/*
		 * The callback argument is embedded in sc.  A plain
		 * mevent_delete() can return after an already-selected event
		 * entered the dispatch batch, so acknowledge callback
		 * retirement before destroying either the audio descriptor or
		 * the softc.
		 */
		(void)mevent_delete_sync(sc->vssc_audio_event[stream_id]);
		sc->vssc_audio_event[stream_id] = NULL;
	}
}

static void
pci_vtsnd_reset(void *arg)
{
	struct pci_vtsnd_softc *sc;
	bool already_locked;
	int error, pending_error;

	sc = arg;
	pending_error = 0;
	/*
	 * The common VirtIO status-reset path invokes vc_reset with vs_mtx held.
	 * Sound deliberately uses vssc_mtx as vs_mtx, while direct initialization
	 * and unit-model callers invoke this callback without it.  Retain the
	 * caller's ownership in the first case and acquire it in the second: an
	 * unconditional acquisition would deadlock a guest-issued reset.
	 */
	already_locked = pthread_mutex_isowned_np(&sc->vssc_mtx);
	if (!already_locked)
		pthread_mutex_lock(&sc->vssc_mtx);
	sc->vssc_resetting = true;
	for (uint32_t stream_id = 0; stream_id < nitems(sc->vssc_pending);
	    stream_id++) {
		/*
		 * Disable every backend readiness source even when no retained
		 * request is active.  This closes a notification enabled just
		 * before the common transport serialized this reset callback.
		 */
		pci_vtsnd_disable_audio_event(sc, stream_id);
		if (pci_vtsnd_cancel_pending(sc, stream_id) != 0)
			pending_error = EIO;
	}
	error = virtio_snd_host_reset(sc->vssc_host);
	if (error == 0 && pending_error == 0 &&
	    virtio_snd_async_resume(sc->vssc_async) != 0)
		pending_error = EIO;
	if (error != 0) {
		VIRTIO_PROBE_ERROR(sc->vssc_vs.vs_vc->vc_name,
		    "sound-backend-reset");
		/*
		 * A failed STOP or RELEASE leaves backend ownership live.
		 * vi_set_needs_reset() records the failure while the common
		 * reset path is active and exposes NEEDS_RESET when the driver
		 * starts its next initialization attempt.
		 */
	}
	atomic_store_explicit(&sc->vssc_playback_bytes, 0,
	    memory_order_relaxed);
	atomic_store_explicit(&sc->vssc_capture_bytes, 0,
	    memory_order_relaxed);
	vi_reset_dev(&sc->vssc_vs);
	/*
	 * Common reset clears the old runtime latch.  Reassert it afterwards if
	 * either retained request cancellation or backend stream cleanup failed;
	 * otherwise snapshot admission could reopen over live host ownership.
	 */
	if (error != 0 || pending_error != 0)
		vi_snapshot_restore_incomplete(&sc->vssc_vs);
	sc->vssc_resetting = false;
	if (!already_locked)
		pthread_mutex_unlock(&sc->vssc_mtx);
}

static int
pci_vtsnd_qreset(void *arg, struct vqueue_info *vq,
    uint64_t generation __unused)
{
	struct pci_vtsnd_softc *sc;
	bool already_locked;
	ptrdiff_t queue;
	uint32_t stream_id;
	int error;

	sc = arg;
	queue = vq - sc->vssc_vq;
	if (queue < 0 || queue >= VTSND_NVQ)
		return (EINVAL);
	if (queue != VTSND_TXQ && queue != VTSND_RXQ)
		return (0);
	stream_id = queue == VTSND_TXQ ? 0 : 1;
	/* Queue-reset register writes also enter vc_qreset under vs_mtx. */
	already_locked = pthread_mutex_isowned_np(&sc->vssc_mtx);
	if (!already_locked)
		pthread_mutex_lock(&sc->vssc_mtx);
	pci_vtsnd_disable_audio_event(sc, stream_id);
	error = pci_vtsnd_cancel_pending(sc, stream_id);
	if (!already_locked)
		pthread_mutex_unlock(&sc->vssc_mtx);
	return (error);
}

static int
pci_vtsnd_suspend(void *arg)
{
	struct pci_vtsnd_softc *sc;
	bool already_locked;
	int error;

	sc = arg;
	/*
	 * Quiesce closes new async admission, then recheck while holding the
	 * same lock as a readiness callback already entering completion.  Modern
	 * status writes invoke this callback with vs_mtx held, and this device
	 * aliases vs_mtx to vssc_mtx.  Direct lifecycle callers do not hold it.
	 * Preserve that ownership distinction: trying to lock it unconditionally
	 * here self-deadlocks guest SUSPEND, while omitting the direct-caller lock
	 * would leave a callback race between the empty observation and return.
	 */
	already_locked = pthread_mutex_isowned_np(&sc->vssc_mtx);
	error = virtio_snd_async_quiesce(sc->vssc_async);
	if (error != 0)
		return (error);
	if (!already_locked)
		pthread_mutex_lock(&sc->vssc_mtx);
	error = virtio_snd_async_quiesce(sc->vssc_async);
	if (!already_locked)
		pthread_mutex_unlock(&sc->vssc_mtx);
	return (error);
}

static int
pci_vtsnd_resume_device(void *arg)
{
	struct pci_vtsnd_softc *sc;

	sc = arg;
	return (virtio_snd_async_resume(sc->vssc_async));
}

static int
pci_vtsnd_cfgread(void *arg, int offset, int size, uint32_t *value)
{
	uint8_t config[BHYVE_VTSND_CONFIG_SIZE];
	int error;

	(void)arg;
	error = virtio_snd_host_config_encode(config);
	if (error != 0)
		return (error);
	return (vi_config_read_le(config, sizeof(config), offset, size, value));
}

static bool
pci_vtsnd_drain_data(struct pci_vtsnd_softc *sc, struct vqueue_info *vq)
{
	struct iovec iov[BHYVE_VTSND_MAX_CHAIN_SEGMENTS];
	struct pci_vtsnd_pending *pending;
	struct vi_req req;
	struct virtio_snd_host_xfer_claim claim;
	ptrdiff_t queue;
	size_t payload_size, used;
	uint16_t budget;
	uint32_t stream_id;
	bool drained;
	int error, n;

	queue = vq - sc->vssc_vq;
	if (queue != VTSND_TXQ && queue != VTSND_RXQ) {
		vi_set_needs_reset(&sc->vssc_vs);
		return (false);
	}
	drained = true;
	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
		stream_id = queue == VTSND_TXQ ? 0 : 1;
		pending = &sc->vssc_pending[stream_id];
		if (pending->active)
			break;
		n = vq_getchain(vq, iov, nitems(iov), &req);
		if (n <= 0) {
			if (n < 0) {
				VIRTIO_PROBE_ERROR(sc->vssc_vs.vs_vc->vc_name,
				    "invalid-sound-chain");
				vi_set_needs_reset(&sc->vssc_vs);
				drained = false;
			}
			break;
		}
		if (n > (int)nitems(iov) || !req.ordered ||
		    req.readable == 0 || req.writable == 0 ||
		    req.readable + req.writable != n) {
			error = EINVAL;
		} else if (queue == VTSND_TXQ) {
			error = virtio_snd_queue_playback_prepare(sc->vssc_host,
			    iov, req.readable, &iov[req.readable],
			    req.writable, &claim, &payload_size);
		} else {
			error = virtio_snd_queue_capture_prepare(sc->vssc_host, iov,
			    req.readable, &iov[req.readable],
			    req.writable, &claim, &payload_size);
		}
		if (error != 0) {
			VIRTIO_PROBE_ERROR(sc->vssc_vs.vs_vc->vc_name,
			    "invalid-sound-chain");
			vi_set_needs_reset(&sc->vssc_vs);
			vq_relchain_req(vq, &req, 0);
			drained = false;
			break;
		}
		memset(pending, 0, sizeof(*pending));
		pending->sc = sc;
		pending->vq = vq;
		pending->req = req;
		pending->claim = claim;
		pending->nwritable = (size_t)req.writable;
		pending->payload_size = payload_size;
		memcpy(pending->writable, &iov[req.readable],
		    pending->nwritable * sizeof(pending->writable[0]));
		pending->active = true;
		if (queue == VTSND_TXQ) {
			error = virtio_snd_async_submit_iov(sc->vssc_async,
			    stream_id, BHYVE_VTSND_ASYNC_PLAYBACK,
			    (uintptr_t)pending, claim.generation, iov,
			    (size_t)req.readable, BHYVE_VTSND_PCM_XFER_SIZE,
			    payload_size);
		} else {
			error = virtio_snd_async_submit(sc->vssc_async, stream_id,
			    BHYVE_VTSND_ASYNC_CAPTURE, (uintptr_t)pending,
			    claim.generation, NULL, payload_size);
		}
		if (error != 0) {
			int finish_error;

			pending->active = false;
			pending->vq = NULL;
			finish_error = virtio_snd_host_xfer_finish(sc->vssc_host,
			    &pending->claim);
			if (queue == VTSND_TXQ)
				error = virtio_snd_queue_playback_error(iov,
				    req.readable, &iov[req.readable],
				    req.writable, &used);
			else
				error = virtio_snd_queue_capture_error(iov,
				    req.readable, &iov[req.readable],
				    req.writable, &used);
			if (finish_error != 0 || error != 0 ||
			    used > UINT32_MAX) {
				vi_set_needs_reset(&sc->vssc_vs);
				used = 0;
				drained = false;
			}
			vq_relchain_req(vq, &req, (uint32_t)used);
			if (!drained)
				break;
			continue;
		}
		error = virtio_snd_async_progress(sc->vssc_async, stream_id,
		    claim.generation);
		if (error == EAGAIN || error == EINPROGRESS) {
			if (sc->vssc_audio_event[stream_id] != NULL &&
			    mevent_enable(sc->vssc_audio_event[stream_id]) != 0) {
				vi_set_needs_reset(&sc->vssc_vs);
				(void)pci_vtsnd_cancel_pending(sc, stream_id);
				drained = false;
			}
			break;
		}
		if (pending->active) {
			/*
			 * A terminal async result must have delivered exactly
			 * one completion.  Retire it through cancellation if
			 * the backend owner violated that invariant.
			 */
			vi_set_needs_reset(&sc->vssc_vs);
			(void)pci_vtsnd_cancel_pending(sc, stream_id);
			drained = false;
			break;
		}
		/*
		 * Every terminal result invokes pci_vtsnd_async_complete(),
		 * which owns descriptor publication and error status.
		 */
	}
	vq_endchains(vq, !vq_has_descs(vq));
	return (drained);
}

static bool
pci_vtsnd_fail_data(struct pci_vtsnd_softc *sc, struct vqueue_info *vq)
{
	struct iovec iov[BHYVE_VTSND_MAX_CHAIN_SEGMENTS];
	struct vi_req req;
	ptrdiff_t queue;
	size_t used;
	uint16_t budget;
	bool drained;
	int error, n;

	queue = vq - sc->vssc_vq;
	if (queue != VTSND_TXQ && queue != VTSND_RXQ) {
		vi_set_needs_reset(&sc->vssc_vs);
		return (false);
	}
	drained = true;
	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
		n = vq_getchain(vq, iov, nitems(iov), &req);
		if (n <= 0) {
			if (n < 0) {
				VIRTIO_PROBE_ERROR(sc->vssc_vs.vs_vc->vc_name,
				    "invalid-sound-chain");
				vi_set_needs_reset(&sc->vssc_vs);
				drained = false;
			}
			break;
		}
		if (n > (int)nitems(iov) || !req.ordered ||
		    req.readable == 0 || req.writable == 0 ||
		    req.readable + req.writable != n) {
			error = EINVAL;
		} else if (queue == VTSND_TXQ) {
			error = virtio_snd_queue_playback_error(iov,
			    req.readable, &iov[req.readable], req.writable,
			    &used);
		} else {
			error = virtio_snd_queue_capture_error(iov,
			    req.readable, &iov[req.readable], req.writable,
			    &used);
		}
		if (error != 0 || used > UINT32_MAX) {
			VIRTIO_PROBE_ERROR(sc->vssc_vs.vs_vc->vc_name,
			    "invalid-sound-chain");
			vi_set_needs_reset(&sc->vssc_vs);
			vq_relchain_req(vq, &req, 0);
			drained = false;
			break;
		}
		vq_relchain_req(vq, &req, (uint32_t)used);
	}
	vq_endchains(vq, !vq_has_descs(vq));
	return (drained);
}

static void
pci_vtsnd_notify(void *arg, struct vqueue_info *vq)
{
	struct pci_vtsnd_softc *sc;
	struct iovec iov[BHYVE_VTSND_MAX_CHAIN_SEGMENTS];
	struct vi_req req;
	enum virtio_snd_host_stream_state after[2], before[2], state;
	ptrdiff_t queue;
	size_t used;
	uint16_t budget;
	uint32_t control_code, control_stream_id;
	bool already_locked;
	bool data_failure_latched;
	int error, n;

	sc = arg;
	/*
	 * Common vs_mtx serializes transport access and aliases vssc_mtx, so a
	 * transport kick normally enters with this mutex held.  Unit/model callers
	 * and any future non-transport entry may not.  Preserve the caller's
	 * ownership while keeping guest submission and readiness-driven retained
	 * completion in the same device-private domain.
	 */
	already_locked = pthread_mutex_isowned_np(&sc->vssc_mtx);
	if (!already_locked)
		pthread_mutex_lock(&sc->vssc_mtx);
	queue = vq - sc->vssc_vq;
	if (queue < 0 || queue >= VTSND_NVQ) {
		vi_set_needs_reset(&sc->vssc_vs);
		goto done;
	}
	/*
	 * No stream features request notifications, so event buffers remain
	 * available until reset.  Consuming them would manufacture an event.
	 */
	if (queue == VTSND_EVENTQ) {
		vq_endchains(vq, 0);
		goto done;
	}
	if (queue == VTSND_TXQ || queue == VTSND_RXQ) {
		uint32_t stream_id;

		stream_id = queue == VTSND_TXQ ? 0 : 1;
		error = virtio_snd_host_stream_get(sc->vssc_host, stream_id,
		    &state, NULL);
		if (error != 0) {
			vi_set_needs_reset(&sc->vssc_vs);
			goto done;
		}
		/*
		 * Output data is valid for prebuffering after PREPARE.  Input
		 * buffers may be published early by the guest but cannot be
		 * completed until START makes capture runnable.
		 */
		if ((queue == VTSND_TXQ &&
		    state != BHYVE_VTSND_PREPARED &&
		    state != BHYVE_VTSND_RUNNING) ||
		    (queue == VTSND_RXQ && state != BHYVE_VTSND_RUNNING)) {
			vq_endchains(vq, 0);
			goto done;
		}
		(void)pci_vtsnd_drain_data(sc, vq);
		goto done;
	}

	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
		data_failure_latched = false;
		n = vq_getchain(vq, iov, nitems(iov), &req);
		if (n <= 0) {
			if (n < 0) {
				VIRTIO_PROBE_ERROR(sc->vssc_vs.vs_vc->vc_name,
				    "invalid-sound-chain");
				vi_set_needs_reset(&sc->vssc_vs);
			}
			break;
		}
		if (n > (int)nitems(iov) || !req.ordered ||
		    req.readable == 0 || req.writable == 0 ||
		    req.readable + req.writable != n) {
			error = EINVAL;
		} else {
			error = 0;
			control_code = 0;
			control_stream_id = UINT32_MAX;
			(void)virtio_snd_queue_control_header(iov,
			    req.readable, &control_code, &control_stream_id);
			for (uint32_t stream_id = 0; stream_id < nitems(before);
			    stream_id++) {
				error = virtio_snd_host_stream_get(sc->vssc_host,
				    stream_id, &before[stream_id], NULL);
				if (error != 0)
					break;
			}
			/*
			 * Section 5.14.6.6.5 requires all pending stream I/O
			 * to complete before RELEASE itself completes.  More
			 * importantly for a real backend, retire those requests
			 * before release() frees stream resources.  Prepared
			 * output is consumable prebuffer; stopped output and
			 * input buffers are returned with IO_ERR.
			 */
			if (error == 0 &&
			    control_code == BHYVE_VTSND_R_PCM_RELEASE &&
			    control_stream_id < nitems(before) &&
			    (before[control_stream_id] == BHYVE_VTSND_PREPARED ||
			    before[control_stream_id] == BHYVE_VTSND_STOPPED)) {
				/*
				 * A readiness-driven backend may already own one
				 * retained chain which is no longer visible in the
				 * available ring.  Complete it before draining the
				 * remaining descriptors and before release().
				 */
				if (pci_vtsnd_cancel_pending(sc,
				    control_stream_id) != 0) {
					error = EIO;
					data_failure_latched = true;
					vi_set_needs_reset(&sc->vssc_vs);
				}
				if (control_stream_id == 0 &&
				    before[0] == BHYVE_VTSND_PREPARED &&
				    error == 0 &&
				    !pci_vtsnd_drain_data(sc,
				    &sc->vssc_vq[VTSND_TXQ])) {
					error = EIO;
					data_failure_latched = true;
				}
				/*
				 * A nonblocking backend may retain the final prepared
				 * output request while drain_data() consumes the available
				 * suffix.  RELEASE cannot be published while that request is
				 * still pending, even when the control status would be IO_ERR.
				 * Retire it before failing any remaining available requests.
				 */
				if (error == 0 &&
				    sc->vssc_pending[control_stream_id].active &&
				    pci_vtsnd_cancel_pending(sc,
				    control_stream_id) != 0) {
					error = EIO;
					data_failure_latched = true;
					vi_set_needs_reset(&sc->vssc_vs);
				}
				if (error == 0 &&
				    !pci_vtsnd_fail_data(sc,
				    &sc->vssc_vq[control_stream_id == 0 ?
				    VTSND_TXQ : VTSND_RXQ])) {
					error = EIO;
					data_failure_latched = true;
				}
			}
			if (error == 0)
				error = virtio_snd_queue_control(sc->vssc_host, iov,
				    req.readable, &iov[req.readable],
				    req.writable, &used);
			for (uint32_t stream_id = 0;
			    error == 0 && stream_id < nitems(after); stream_id++)
				error = virtio_snd_host_stream_get(sc->vssc_host,
				    stream_id, &after[stream_id], NULL);
		}
		if (error != 0 || used > UINT32_MAX) {
			VIRTIO_PROBE_ERROR(sc->vssc_vs.vs_vc->vc_name,
			    "invalid-sound-chain");
			if (!data_failure_latched)
				vi_set_needs_reset(&sc->vssc_vs);
			vq_relchain_req(vq, &req, 0);
			break;
		}
		/*
		 * Publish data completions before the START/RELEASE control
		 * completion.  START consumes buffers queued before the command.
		 * RELEASE must complete every remaining stream request first.
		 */
		bool transition_drained;

		transition_drained = true;
		for (uint32_t stream_id = 0; stream_id < nitems(after);
		    stream_id++) {
			if (after[stream_id] == BHYVE_VTSND_RUNNING &&
			    before[stream_id] != BHYVE_VTSND_RUNNING)
				transition_drained &=
				    pci_vtsnd_drain_data(sc,
				    &sc->vssc_vq[stream_id == 0 ?
				    VTSND_TXQ : VTSND_RXQ]);
		}
		if (!transition_drained) {
			/*
			 * A malformed PCM chain makes the mandatory RELEASE
			 * flush impossible.  NEEDS_RESET is already latched by
			 * the data path; do not publish a successful control
			 * response after that failed ordering boundary.
			 */
			vq_relchain_req(vq, &req, 0);
			break;
		}
		vq_relchain_req(vq, &req, (uint32_t)used);
	}
	vq_endchains(vq, !vq_has_descs(vq));
done:
	if (!already_locked)
		pthread_mutex_unlock(&sc->vssc_mtx);
}

#ifdef BHYVE_SNAPSHOT
static int
pci_vtsnd_pause(void *arg)
{
	struct pci_vtsnd_softc *sc;
	int error;

	sc = arg;
	error = virtio_snd_async_quiesce(sc->vssc_async);
	if (error != 0)
		return (error);
	pthread_mutex_lock(&sc->vssc_mtx);
	/*
	 * Close the race with a readiness callback that was already entering
	 * as quiesce observed the final completion.
	 */
	error = virtio_snd_async_quiesce(sc->vssc_async);
	if (error != 0)
		pthread_mutex_unlock(&sc->vssc_mtx);
	return (error);
}

static int
pci_vtsnd_resume(void *arg)
{
	struct pci_vtsnd_softc *sc;
	int error;

	sc = arg;
	/*
	 * State capture/restore is complete before this callback.  A restored
	 * guest-suspended image must retain the async admission fence established
	 * by guest suspend; only the checkpoint's private mutex ownership is being
	 * released here.  In particular, do not let a checkpoint/restore cycle
	 * turn a suspended device into one which accepts host-side audio work while
	 * its common virtqueue state remains stopped.
	 */
	if (sc->vssc_vs.vs_suspended) {
		pthread_mutex_unlock(&sc->vssc_mtx);
		return (0);
	}
	/*
	 * Reopen the async admission gate while still holding the same private
	 * mutex taken by both guest submissions and readiness completions, then
	 * release it.  If the consistency recheck unexpectedly fails, the gate
	 * remains closed but this callback must nevertheless drop the pause-time
	 * lock: vi_pci_resume() retains checkpoint ownership on error and may
	 * invoke us again during its recovery path.  Retaining the mutex here would
	 * turn that retry into an unlock of a lock the retry never acquired.
	 */
	error = virtio_snd_async_resume(sc->vssc_async);
	pthread_mutex_unlock(&sc->vssc_mtx);
	return (error);
}

static int
pci_vtsnd_snapshot(void *arg, struct vm_snapshot_meta *meta)
{
	struct pci_vtsnd_softc *sc;
	uint8_t state[PCI_VTSND_STATE_SIZE];
	int error;

	sc = arg;
	error = 0;
	if (meta->op == VM_SNAPSHOT_SAVE) {
		error = pci_vtsnd_state_encode(sc, state);
		if (error != 0)
			return (error);
	}
	SNAPSHOT_BUF_OR_LEAVE(state, sizeof(state), meta, error, done);
	if (meta->op == VM_SNAPSHOT_VALIDATE)
		error = pci_vtsnd_state_validate(sc, state, sizeof(state));
	else if (meta->op == VM_SNAPSHOT_RESTORE)
		error = pci_vtsnd_state_restore(sc, state, sizeof(state));
	if (error != 0 && meta->op == VM_SNAPSHOT_RESTORE &&
	    virtio_snd_host_restore_incomplete(sc->vssc_host))
		vi_snapshot_restore_incomplete(&sc->vssc_vs);
done:
	return (error);
}

/*
 * Restore preflight deliberately does not invoke pci_vtsnd_pause(), because
 * validation must not quiesce or otherwise touch the external audio backend.
 * It nevertheless reads the same backend identity and stream state that
 * readiness callbacks and guest queue notifications update under vssc_mtx.
 *
 * A commit-time checkpoint reaches this callback with vssc_mtx retained by
 * pci_vtsnd_pause().  Direct preflight does not, so acquire the non-recursive
 * mutex only when this thread does not already own the pause-time lock.  This
 * preserves the paired pause/resume ownership contract while making both
 * validation paths serialize the private codec.
 */
static int
pci_vtsnd_snapshot_validate(struct vm_snapshot_meta *meta)
{
	struct pci_devinst *pi;
	struct pci_vtsnd_softc *sc;
	bool acquired;
	int error;

	if (meta == NULL || meta->op != VM_SNAPSHOT_VALIDATE ||
	    meta->dev_data == NULL)
		return (EINVAL);
	pi = meta->dev_data;
	sc = pi->pi_arg;
	if (sc == NULL)
		return (EINVAL);

	acquired = !pthread_mutex_isowned_np(&sc->vssc_mtx);
	/*
	 * Keep the two ownership cases structurally separate.  Besides making the
	 * lock contract clear to readers, this lets the thread-safety analysis
	 * prove that the conditional unlock matches the conditional acquisition.
	 */
	if (acquired) {
		pthread_mutex_lock(&sc->vssc_mtx);
		error = vi_pci_snapshot(meta);
		pthread_mutex_unlock(&sc->vssc_mtx);
	} else {
		error = vi_pci_snapshot(meta);
	}
	return (error);
}
#endif

static int
pci_vtsnd_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct virtio_snd_async_ops async_ops = {
		.progress = pci_vtsnd_async_progress,
		.complete = pci_vtsnd_async_complete,
	};
	struct virtio_snd_host_ops ops = {
		.set_params = pci_vtsnd_set_params,
		.prepare = pci_vtsnd_lifecycle,
		.start = pci_vtsnd_lifecycle,
		.stop = pci_vtsnd_lifecycle,
		.release = pci_vtsnd_release,
		.playback = pci_vtsnd_playback,
		.capture = pci_vtsnd_capture,
	};
	struct pci_vtsnd_softc *sc;
	const char *backend, *play_path, *record_path, *value;
	bool intr_initialized, mtx_initialized, packed;

	sc = calloc(1, sizeof(*sc));
	if (sc == NULL)
		return (1);
	intr_initialized = false;
	mtx_initialized = false;
	backend = get_config_value_node(nvl, "backend");
	if (!pci_vtsnd_backend_valid(backend)) {
		fprintf(stderr, "virtio-snd: unsupported backend \"%s\"\n",
		    backend);
		goto failed;
	}
	if (backend != NULL && strcmp(backend, VTSND_BACKEND_OSS) == 0) {
		sc->vssc_backend = VTSND_BACKEND_KIND_OSS;
		play_path = get_config_value_node(nvl, "play");
		record_path = get_config_value_node(nvl, "record");
		if (play_path == NULL)
			play_path = "/dev/dsp";
		if (record_path == NULL)
			record_path = "/dev/dsp";
		if (strlcpy(sc->vssc_play_path, play_path,
		    sizeof(sc->vssc_play_path)) >= sizeof(sc->vssc_play_path) ||
		    strlcpy(sc->vssc_record_path, record_path,
		    sizeof(sc->vssc_record_path)) >=
		    sizeof(sc->vssc_record_path)) {
			fprintf(stderr, "virtio-snd: audio path is too long\n");
			goto failed;
		}
	} else {
		sc->vssc_backend = VTSND_BACKEND_KIND_NULL;
		if (get_config_value_node(nvl, "play") != NULL ||
		    get_config_value_node(nvl, "record") != NULL) {
			fprintf(stderr,
			    "virtio-snd: play/record require backend=oss\n");
			goto failed;
		}
	}
	value = getenv("BHYVE_VIRTIO_DEBUG");
	if (value != NULL) {
		char *end;
		unsigned long debug;

		errno = 0;
		debug = strtoul(value, &end, 10);
		if (errno == 0 && end != value && *end == '\0' &&
		    debug <= UINT_MAX)
			sc->vssc_debug = (unsigned int)debug;
	}
	if (pthread_mutex_init(&sc->vssc_mtx, NULL) != 0)
		goto failed;
	mtx_initialized = true;
	ops.arg = sc;
	if (virtio_snd_host_create(&ops, &sc->vssc_host) != 0)
		goto failed;
	async_ops.arg = sc;
	if (virtio_snd_async_create(&async_ops, BHYVE_VTSND_MAX_BUFFER_BYTES,
	    &sc->vssc_async) != 0)
		goto failed;
	for (uint32_t stream_id = 0; stream_id < nitems(sc->vssc_pending);
	    stream_id++)
		sc->vssc_pending[stream_id].sc = sc;
	if (sc->vssc_backend == VTSND_BACKEND_KIND_OSS) {
		sc->vssc_audio[0] = audio_init_nonblock(sc->vssc_play_path, 1);
		sc->vssc_audio[1] = audio_init_nonblock(sc->vssc_record_path, 0);
		if (sc->vssc_audio[0] == NULL || sc->vssc_audio[1] == NULL) {
			fprintf(stderr,
			    "virtio-snd: cannot open OSS playback/capture\n");
			goto failed;
		}
		sc->vssc_audio_event[0] = mevent_add_disabled(
		    audio_fd(sc->vssc_audio[0]), EVF_WRITE,
		    pci_vtsnd_audio_event, &sc->vssc_pending[0]);
		sc->vssc_audio_event[1] = mevent_add_disabled(
		    audio_fd(sc->vssc_audio[1]), EVF_READ,
		    pci_vtsnd_audio_event, &sc->vssc_pending[1]);
		if (sc->vssc_audio_event[0] == NULL ||
		    sc->vssc_audio_event[1] == NULL) {
			fprintf(stderr,
			    "virtio-snd: cannot register OSS readiness events\n");
			goto failed;
		}
		sc->vssc_progress = pci_vtsnd_oss_progress;
	} else
		sc->vssc_progress = pci_vtsnd_null_progress;
	sc->vssc_progress_arg = sc;

	sc->vssc_consts = vtsnd_vi_consts;
	packed = get_config_bool_node_default(nvl, "packed", false);
	if (packed)
		sc->vssc_consts.vc_hv_caps |= VIRTIO_F_RING_PACKED;
	vi_softc_linkup(&sc->vssc_vs, &sc->vssc_consts, sc, pi,
	    sc->vssc_vq);
	sc->vssc_vs.vs_mtx = &sc->vssc_mtx;
	for (size_t i = 0; i < nitems(sc->vssc_vq); i++)
		sc->vssc_vq[i].vq_qsize = VTSND_RINGSZ;
	if (vi_pci_select_transport(&sc->vssc_vs, nvl,
	    VIRTIO_PCI_MODERN_ONLY) != 0)
		goto failed;
	vi_pci_modern_set_identity(&sc->vssc_vs, VIRTIO_ID_SOUND);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_MULTIMEDIA);
	pci_set_cfgdata8(pi, PCIR_SUBCLASS, PCIS_MULTIMEDIA_AUDIO);
	if (vi_intr_init(&sc->vssc_vs, 1, fbsdrun_virtio_msix()) != 0)
		goto failed;
	intr_initialized = true;
	if (vi_pci_modern_init(&sc->vssc_vs, 2) != 0)
		goto failed;
	return (0);

failed:
	pci_vtsnd_delete_audio_events(sc);
	for (uint32_t stream_id = 0;
	    stream_id < nitems(sc->vssc_audio_event); stream_id++) {
		audio_destroy(sc->vssc_audio[stream_id]);
	}
	if (sc->vssc_async != NULL)
		(void)virtio_snd_async_destroy(sc->vssc_async);
	virtio_snd_host_destroy(sc->vssc_host);
	free(sc->vssc_vs.vs_modern);
	if (intr_initialized)
		pthread_mutex_destroy(&sc->vssc_vs.vs_isr_mtx);
	if (mtx_initialized)
		pthread_mutex_destroy(&sc->vssc_mtx);
	free(sc);
	return (1);
}

static const struct pci_devemu pci_de_vtsnd = {
	.pe_emu = "virtio-snd",
	.pe_init = pci_vtsnd_init,
	.pe_cfgwrite = vi_pci_modern_cfgwrite,
	.pe_cfgread = vi_pci_modern_cfgread,
	.pe_barwrite = vi_pci_write,
	.pe_barread = vi_pci_read,
#ifdef BHYVE_SNAPSHOT
	.pe_snapshot = vi_pci_snapshot,
	.pe_snapshot_validate = pci_vtsnd_snapshot_validate,
	.pe_snapshot_compat = vi_pci_snapshot_compat,
	.pe_pause = vi_pci_pause,
	.pe_resume = vi_pci_resume,
#endif
};
PCI_EMUL_SET(pci_de_vtsnd);
