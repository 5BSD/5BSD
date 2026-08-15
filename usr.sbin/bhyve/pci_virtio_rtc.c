/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/linker_set.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/uio.h>

#include <dev/pci/pcireg.h>
#include <dev/virtio/virtio_ids.h>
#include <dev/virtio/rtc/virtio_rtc.h>

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
#include "iov.h"
#include "mevent.h"
#include "pci_emul.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif
#include "virtio.h"
#include "virtio_pci_modern_probes.h"
#include "virtio_rtc_host.h"
#include "virtio_rtc_alarm.h"

/*
 * Release-ledger anchor for request-queue clock replies.
 * VIRTIO_ACTIVATION_ASSERTION: clock-request-and-response
 */

#define	VTRTC_RINGSZ			64
#define	VTRTC_MAXSEGS			64
#define	VTRTC_REQUESTQ			0
#define	VTRTC_ALARMQ			1
#define	VTRTC_NVQ			2
#define	VTRTC_NSEC_PER_SEC		UINT64_C(1000000000)
#define	VTRTC_SNAPSHOT_MAGIC		0x31435452U	/* "RTC1" */
#define	VTRTC_SNAPSHOT_VERSION		2U
#define	VTRTC_ALARM_STATE_SIZE		40U

struct pci_vtrtc_softc {
	struct virtio_softc vrsc_vs;
	struct vqueue_info vrsc_vq[VTRTC_NVQ];
	struct virtio_consts vrsc_consts;
	pthread_mutex_t vrsc_mtx;
	struct virtio_rtc_alarm *vrsc_alarm;
	struct mevent *vrsc_alarm_evp;
	int vrsc_alarm_fd;
	bool vrsc_alarm_offered;
};

static void pci_vtrtc_reset(void *);
static void pci_vtrtc_notify(void *, struct vqueue_info *);
static int pci_vtrtc_suspend(void *);
static int pci_vtrtc_checkpoint_pause(void *);
static void pci_vtrtc_resume_complete(void *);
static int pci_vtrtc_alarm_schedule(struct pci_vtrtc_softc *);
#ifdef BHYVE_SNAPSHOT
static int pci_vtrtc_snapshot(void *, struct vm_snapshot_meta *);
#endif

static const struct virtio_consts vtrtc_vi_consts = {
	.vc_name = "vtrtc",
	.vc_nvq = 1,
	.vc_cfgsize = 0,
	.vc_reset = pci_vtrtc_reset,
	.vc_qnotify = pci_vtrtc_notify,
	.vc_suspend = pci_vtrtc_suspend,
	.vc_resume_device = vi_pci_lifecycle_noop,
	.vc_pause = pci_vtrtc_checkpoint_pause,
	.vc_resume = vi_pci_lifecycle_noop,
	.vc_resume_complete = pci_vtrtc_resume_complete,
#ifdef BHYVE_SNAPSHOT
	.vc_snapshot = pci_vtrtc_snapshot,
#endif
	/* Alarm descriptors are completed by the timer event path. */
	.vc_hv_caps = VIRTIO_F_RING_RESET | VIRTIO_F_SUSPEND,
};

static bool
pci_vtrtc_alarm_negotiated(const struct pci_vtrtc_softc *sc)
{

	return (sc->vrsc_alarm_offered &&
	    (sc->vrsc_vs.vs_negotiated_caps & VIRTIO_RTC_F_ALARM) != 0);
}

static void
pci_vtrtc_alarmq_notify(struct pci_vtrtc_softc *sc)
{
	struct vqueue_info *vq;
	struct iovec iov[VTRTC_MAXSEGS];
	struct vi_req req;
	uint8_t notification[BHYVE_VIRTIO_RTC_ALARM_NOTIFICATION_SIZE];
	size_t capacity, written;
	int error, n;

	if (!pci_vtrtc_alarm_negotiated(sc)) {
		/*
		 * Queue 1 can be present because ALARM was offered even when
		 * the driver declined it.  A notification in that state is a
		 * feature-contract violation, not an empty alarm queue.
		 */
		vi_set_needs_reset(&sc->vrsc_vs);
		return;
	}
	if (!virtio_rtc_alarm_pending(sc->vrsc_alarm))
		return;
	vq = &sc->vrsc_vq[VTRTC_ALARMQ];
	if (!vq_has_descs(vq))
		return;
	n = vq_getchain(vq, iov, nitems(iov), &req);
	if (n <= 0) {
		if (n < 0) {
			VIRTIO_PROBE_ERROR(sc->vrsc_vs.vs_vc->vc_name,
			    "invalid-rtc-alarm-chain");
			vi_set_needs_reset(&sc->vrsc_vs);
		}
		return;
	}
	if (n > (int)nitems(iov) || req.readable != 0 ||
	    req.writable != n) {
		VIRTIO_PROBE_ERROR(sc->vrsc_vs.vs_vc->vc_name,
		    "invalid-rtc-alarm-chain");
		vi_set_needs_reset(&sc->vrsc_vs);
		vq_relchain_req(vq, &req, 0);
		vq_endchains(vq, !vq_has_descs(vq));
		return;
	}
	capacity = count_iov(iov, req.writable);
	error = virtio_rtc_alarm_notify(sc->vrsc_alarm, notification,
	    MIN(capacity, sizeof(notification)), &written);
	if (error != 0) {
		if (error == EMSGSIZE) {
			VIRTIO_PROBE_RTC_ALARM(sc->vrsc_vs.vs_vc->vc_name, 0, 1,
			    error);
			VIRTIO_PROBE_ERROR(sc->vrsc_vs.vs_vc->vc_name,
			    "short-rtc-alarm-buffer");
			vi_set_needs_reset(&sc->vrsc_vs);
			vq_relchain_req(vq, &req, 0);
			vq_endchains(vq, !vq_has_descs(vq));
		} else {
			vq_retchain_req(vq, &req);
		}
		return;
	}
	written = buf_to_iov(notification, written, iov, req.writable);
	VIRTIO_PROBE_RTC_ALARM(sc->vrsc_vs.vs_vc->vc_name, 0, 1, 0);
	vq_relchain_req(vq, &req, (uint32_t)written);
	vq_endchains(vq, !vq_has_descs(vq));
	/*
	 * A delivered alarm remains enabled.  Keep a cancellation sentinel
	 * armed so a later backward wall-clock step can re-establish the next
	 * crossing without polling.
	 */
	(void)pci_vtrtc_alarm_schedule(sc);
}

static int
pci_vtrtc_read_clock(void *arg __unused, uint64_t *reading)
{
	struct timespec now;

	if (clock_gettime(CLOCK_REALTIME, &now) != 0)
		return (errno);
	if (now.tv_sec < 0 ||
	    (uint64_t)now.tv_sec >
	    (UINT64_MAX - (uint64_t)now.tv_nsec) / VTRTC_NSEC_PER_SEC)
		return (EOVERFLOW);
	*reading = (uint64_t)now.tv_sec * VTRTC_NSEC_PER_SEC +
	    (uint64_t)now.tv_nsec;
	return (0);
}

static int
pci_vtrtc_alarm_failure(struct pci_vtrtc_softc *sc, uint64_t alarm_time,
    int error, const char *reason)
{

	VIRTIO_PROBE_RTC_ALARM(sc->vrsc_vs.vs_vc->vc_name, alarm_time, 0,
	    error);
	VIRTIO_PROBE_ERROR(sc->vrsc_vs.vs_vc->vc_name, reason);
	vi_set_needs_reset(&sc->vrsc_vs);
	return (error);
}

static time_t
pci_vtrtc_time_t_max(void)
{

	return ((time_t)((UINTMAX_C(1) << (sizeof(time_t) * NBBY - 1)) - 1));
}

/*
 * Arm one absolute CLOCK_REALTIME timerfd event for either the next
 * expiration or a discontinuous clock change.  FreeBSD timerfd converts
 * realtime deadlines to callouts, but TFD_TIMER_CANCEL_ON_SET makes the fd
 * readable when settimeofday(2) or clock_settime(2) changes the wall clock.
 *
 * Once an enabled alarm has been served while the clock is at or beyond its
 * deadline, arm a far-future cancellation sentinel.  This avoids immediate
 * repeated expiration while retaining an event-driven indication of a
 * backward step that may make the alarm eligible to cross again.
 */
static int
pci_vtrtc_alarm_schedule(struct pci_vtrtc_softc *sc)
{
	struct itimerspec value;
	uint64_t alarm_time, now, verified_now;
	bool enabled, sentinel;
	int error;

	if (!sc->vrsc_alarm_offered || sc->vrsc_alarm_fd < 0)
		return (0);
	memset(&value, 0, sizeof(value));
	error = virtio_rtc_alarm_read(sc->vrsc_alarm, &alarm_time, &enabled);
	if (error != 0)
		return (pci_vtrtc_alarm_failure(sc, 0, error,
		    "rtc-alarm-state-read"));
	if (!enabled) {
		if (timerfd_settime(sc->vrsc_alarm_fd, 0, &value, NULL) != 0) {
			error = errno;
			return (pci_vtrtc_alarm_failure(sc, alarm_time, error,
			    "rtc-alarm-timer-disarm"));
		}
		return (0);
	}
	error = pci_vtrtc_read_clock(sc, &now);
	if (error != 0)
		return (pci_vtrtc_alarm_failure(sc, alarm_time, error,
		    "rtc-alarm-clock-read"));
	(void)virtio_rtc_alarm_observe(sc->vrsc_alarm, now);
	if (virtio_rtc_alarm_pending(sc->vrsc_alarm)) {
		if (timerfd_settime(sc->vrsc_alarm_fd, 0, &value, NULL) != 0) {
			error = errno;
			return (pci_vtrtc_alarm_failure(sc, alarm_time, error,
			    "rtc-alarm-timer-disarm"));
		}
		pci_vtrtc_alarmq_notify(sc);
		return (0);
	}
	sentinel = now >= alarm_time;
	if (sentinel) {
		value.it_value.tv_sec = pci_vtrtc_time_t_max();
		value.it_value.tv_nsec = 0;
	} else {
		value.it_value.tv_sec =
		    (time_t)(alarm_time / VTRTC_NSEC_PER_SEC);
		if ((uint64_t)value.it_value.tv_sec !=
		    alarm_time / VTRTC_NSEC_PER_SEC)
			return (pci_vtrtc_alarm_failure(sc, alarm_time,
			    EOVERFLOW, "rtc-alarm-time-overflow"));
		value.it_value.tv_nsec =
		    (long)(alarm_time % VTRTC_NSEC_PER_SEC);
	}
	if (timerfd_settime(sc->vrsc_alarm_fd,
	    TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &value, NULL) != 0) {
		error = errno;
		/*
		 * timerfd_settime(2) reports an unread cancellation while
		 * still replacing the timer with the requested current-clock
		 * deadline.  The model was observed above, so this is a
		 * successfully handled clock step rather than a device error.
		 */
		if (error == ECANCELED)
			return (0);
		return (pci_vtrtc_alarm_failure(sc, alarm_time, error,
		    "rtc-alarm-timer-settime"));
	}
	if (sentinel) {
		/*
		 * Close the sample-to-arm race.  A backward clock step after
		 * the first sample but before the sentinel became active
		 * cannot cancel that sentinel.  Once it is active, sample
		 * again: an earlier step is visible in this reading and a
		 * later step is guaranteed to cancel the timerfd.
		 */
		error = pci_vtrtc_read_clock(sc, &verified_now);
		if (error != 0)
			return (pci_vtrtc_alarm_failure(sc, alarm_time, error,
			    "rtc-alarm-clock-verify"));
		if (verified_now < alarm_time) {
			(void)virtio_rtc_alarm_observe(sc->vrsc_alarm,
			    verified_now);
			memset(&value, 0, sizeof(value));
			value.it_value.tv_sec =
			    (time_t)(alarm_time / VTRTC_NSEC_PER_SEC);
			if ((uint64_t)value.it_value.tv_sec !=
			    alarm_time / VTRTC_NSEC_PER_SEC)
				return (pci_vtrtc_alarm_failure(sc, alarm_time,
				    EOVERFLOW, "rtc-alarm-time-overflow"));
			value.it_value.tv_nsec =
			    (long)(alarm_time % VTRTC_NSEC_PER_SEC);
			if (timerfd_settime(sc->vrsc_alarm_fd,
			    TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET,
			    &value, NULL) != 0 && errno != ECANCELED)
				return (pci_vtrtc_alarm_failure(sc, alarm_time,
				    errno, "rtc-alarm-timer-race-rearm"));
		}
	}
	return (0);
}

static void
pci_vtrtc_alarm_timerfd(int fd, enum ev_type type __unused, void *arg)
{
	struct pci_vtrtc_softc *sc;
	timerfd_t expirations;
	ssize_t nread;
	int error;

	sc = arg;
	nread = read(fd, &expirations, sizeof(expirations));
	if (nread < 0) {
		error = errno;
		if (error == EAGAIN)
			return;
		if (error != ECANCELED) {
			VS_LOCK(&sc->vrsc_vs);
			(void)pci_vtrtc_alarm_failure(sc, 0, error,
			    "rtc-alarm-timer-read");
			VS_UNLOCK(&sc->vrsc_vs);
			return;
		}
	} else if (nread != (ssize_t)sizeof(expirations)) {
		VS_LOCK(&sc->vrsc_vs);
		(void)pci_vtrtc_alarm_failure(sc, 0, EIO,
		    "rtc-alarm-timer-short-read");
		VS_UNLOCK(&sc->vrsc_vs);
		return;
	}
	VS_LOCK(&sc->vrsc_vs);
	if (!sc->vrsc_vs.vs_quiescing && !sc->vrsc_vs.vs_suspended &&
	    !sc->vrsc_vs.vs_checkpoint_paused)
		(void)pci_vtrtc_alarm_schedule(sc);
	VS_UNLOCK(&sc->vrsc_vs);
}

static int
pci_vtrtc_alarm_disarm(struct pci_vtrtc_softc *sc)
{
	struct itimerspec value;

	if (sc->vrsc_alarm_fd >= 0) {
		memset(&value, 0, sizeof(value));
		if (timerfd_settime(sc->vrsc_alarm_fd, 0, &value, NULL) != 0)
			return (errno);
	}
	return (0);
}

static int
pci_vtrtc_suspend(void *vsc)
{
	struct pci_vtrtc_softc *sc;

	sc = vsc;
	/*
	 * Guest-visible suspend is invoked with vs_mtx held.  The common
	 * quiesce fence is already published, so a timer callback cannot pass
	 * its lifecycle checks after we disarm the timer.
	 */
	return (pci_vtrtc_alarm_disarm(sc));
}

static int
pci_vtrtc_checkpoint_pause(void *vsc)
{
	struct pci_vtrtc_softc *sc;
	int error;

	sc = vsc;
	/*
	 * Checkpoint pause is invoked without vs_mtx.  Taking it here waits for
	 * a SIGEV_THREAD callback which may already be scheduling an alarm, and
	 * makes the following disarm the final timer operation before snapshot.
	 */
	VS_LOCK(&sc->vrsc_vs);
	error = pci_vtrtc_alarm_disarm(sc);
	VS_UNLOCK(&sc->vrsc_vs);
	return (error);
}

static void
pci_vtrtc_resume_complete(void *vsc)
{
	struct pci_vtrtc_softc *sc;
	bool already_locked;

	sc = vsc;
	/*
	 * Guest resume calls this from the status-write path with vrsc_mtx
	 * held, while checkpoint resume calls it after dropping that mutex.
	 * Both callers have already cleared their suspend/quiesce fence.
	 * Rearming earlier can lose an already expired one-shot alarm when its
	 * callback observes either fence.
	 */
	already_locked = pthread_mutex_isowned_np(&sc->vrsc_mtx);
	if (!already_locked)
		VS_LOCK(&sc->vrsc_vs);
	(void)pci_vtrtc_alarm_schedule(sc);
	if (!already_locked)
		VS_UNLOCK(&sc->vrsc_vs);
}

static void
pci_vtrtc_reset(void *vsc)
{
	struct pci_vtrtc_softc *sc;
	struct itimerspec value;
	bool disarm_failed;

	sc = vsc;
	disarm_failed = false;
	if (sc->vrsc_alarm_fd >= 0) {
		memset(&value, 0, sizeof(value));
		if (timerfd_settime(sc->vrsc_alarm_fd, 0, &value, NULL) != 0) {
			/*
			 * The old callback may still be armed.  Reset the
			 * portable alarm model below, but carry the failed host
			 * revocation into the driver's next initialization.
			 */
			VIRTIO_PROBE_ERROR(sc->vrsc_vs.vs_vc->vc_name,
			    "rtc-alarm-reset-disarm");
			disarm_failed = true;
		}
	}
	if (sc->vrsc_alarm != NULL)
		(void)virtio_rtc_alarm_reset(sc->vrsc_alarm);
	vi_reset_dev(&sc->vrsc_vs);
	/*
	 * Common reset clears the previous incarnation's status and runtime
	 * restore latch.  Publish a failed host-timer revocation afterwards:
	 * the old callback may still fire, so neither a fresh driver nor a new
	 * checkpoint may treat this incarnation as fully reconstructed.  A later
	 * successful reset retries the disarm and clears the latch normally.
	 */
	if (disarm_failed)
		vi_snapshot_restore_incomplete(&sc->vrsc_vs);
}

static void
pci_vtrtc_requestq_notify(struct pci_vtrtc_softc *sc,
    struct vqueue_info *vq)
{
	struct iovec iov[VTRTC_MAXSEGS];
	struct vi_req req;
	uint8_t request[BHYVE_VIRTIO_RTC_MAX_REQUEST];
	uint8_t response[BHYVE_VIRTIO_RTC_MAX_RESPONSE];
	size_t decoded_len, insize, outsize, request_copy, written;
	uint16_t budget;
	uint16_t msg_type;
	bool queue_ok;
	int error, n;

	queue_ok = true;
	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
		n = vq_getchain(vq, iov, nitems(iov), &req);
		if (n <= 0) {
			if (n < 0) {
				VIRTIO_PROBE_ERROR(sc->vrsc_vs.vs_vc->vc_name,
				    "invalid-rtc-chain");
				vi_set_needs_reset(&sc->vrsc_vs);
				queue_ok = false;
			}
			break;
		}
		if (n > (int)nitems(iov) || !req.ordered ||
		    req.readable == 0 || req.writable == 0 ||
		    req.readable + req.writable != n) {
			VIRTIO_PROBE_ERROR(sc->vrsc_vs.vs_vc->vc_name,
			    "invalid-rtc-chain");
			vi_set_needs_reset(&sc->vrsc_vs);
			vq_relchain_req(vq, &req, 0);
			queue_ok = false;
			break;
		}
		insize = count_iov(iov, req.readable);
		outsize = count_iov(&iov[req.readable], req.writable);
		decoded_len = MIN(insize, sizeof(request));
		request_copy = decoded_len;
		memset(request, 0, sizeof(request));
		for (int i = 0; i < req.readable && request_copy != 0; i++) {
			size_t count;

			count = MIN(iov[i].iov_len, request_copy);
			memcpy(request + (MIN(insize, sizeof(request)) -
			    request_copy), iov[i].iov_base, count);
			request_copy -= count;
		}
		memset(response, 0, sizeof(response));
		/*
		 * Only the bounded prefix above exists in the local decode buffer.
		 * Section 5.23.6.2 requires extra device-readable bytes to be
		 * ignored, so pass that prefix length to the decoder while retaining
		 * the original guest length for tracing.  Passing insize would
		 * describe storage beyond request[] and can make the decoder's alias
		 * checks reject an otherwise valid oversized request.
		 */
		error = virtio_rtc_process_request_alarm(request, decoded_len,
		    response, MIN(outsize, sizeof(response)),
		    pci_vtrtc_read_clock, sc, sc->vrsc_alarm,
		    pci_vtrtc_alarm_negotiated(sc), &written);
		if (error != 0) {
			VIRTIO_PROBE_ERROR(sc->vrsc_vs.vs_vc->vc_name,
			    "rtc-handler-failure");
			vi_set_needs_reset(&sc->vrsc_vs);
			written = 0;
			queue_ok = false;
		}
		written = buf_to_iov(response, written,
		    &iov[req.readable], req.writable);
		msg_type = insize >= sizeof(uint16_t) ?
		    le16dec(request) : UINT16_MAX;
		VIRTIO_PROBE_RTC_REQUEST(sc->vrsc_vs.vs_vc->vc_name,
		    msg_type, insize, outsize,
		    written == 0 ? UINT8_MAX : response[0]);
		vq_relchain_req(vq, &req, (uint32_t)written);
		if (error != 0)
			break;
	}
	vq_endchains(vq, !vq_has_descs(vq));
	if (queue_ok)
		(void)pci_vtrtc_alarm_schedule(sc);
}

static void
pci_vtrtc_notify(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtrtc_softc *sc;

	sc = vsc;
	if (vq == &sc->vrsc_vq[VTRTC_REQUESTQ])
		pci_vtrtc_requestq_notify(sc, vq);
	else if (vq == &sc->vrsc_vq[VTRTC_ALARMQ])
		pci_vtrtc_alarmq_notify(sc);
	else
		vi_set_needs_reset(&sc->vrsc_vs);
}

#ifdef BHYVE_SNAPSHOT
static int
pci_vtrtc_snapshot(void *vsc, struct vm_snapshot_meta *meta)
{
	struct pci_vtrtc_softc *sc;
	uint8_t alarm_state[VTRTC_ALARM_STATE_SIZE];
	uint64_t now;
	uint32_t magic, version;
	int error;

	sc = vsc;
	magic = VTRTC_SNAPSHOT_MAGIC;
	version = VTRTC_SNAPSHOT_VERSION;
	if (meta->op == VM_SNAPSHOT_SAVE) {
		error = virtio_rtc_alarm_snapshot(sc->vrsc_alarm, alarm_state,
		    sizeof(alarm_state));
		if (error != 0)
			return (error);
	}
	SNAPSHOT_LE32_OR_LEAVE(magic, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(version, meta, error, done);
	if (magic != VTRTC_SNAPSHOT_MAGIC ||
	    version != VTRTC_SNAPSHOT_VERSION)
		error = ENOTSUP;
	else {
		SNAPSHOT_BUF_OR_LEAVE(alarm_state, sizeof(alarm_state), meta,
		    error, done);
		if (meta->op == VM_SNAPSHOT_VALIDATE)
			error = virtio_rtc_alarm_restore_validate(alarm_state,
			    sizeof(alarm_state));
		else if (meta->op == VM_SNAPSHOT_RESTORE) {
			error = pci_vtrtc_read_clock(sc, &now);
			if (error == 0)
				error = virtio_rtc_alarm_restore(sc->vrsc_alarm,
				    alarm_state, sizeof(alarm_state), now);
		} else
			error = 0;
	}
done:
	return (error);
}
#endif

static int
pci_vtrtc_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_vtrtc_softc *sc;
	bool alarm, intr_initialized, packed;

	sc = calloc(1, sizeof(*sc));
	if (sc == NULL)
		return (1);
	sc->vrsc_alarm_fd = -1;
	intr_initialized = false;
	if (pthread_mutex_init(&sc->vrsc_mtx, NULL) != 0)
		goto failed;
	if (virtio_rtc_alarm_create(&sc->vrsc_alarm) != 0)
		goto failed_mtx;

	sc->vrsc_consts = vtrtc_vi_consts;
	packed = get_config_bool_node_default(nvl, "packed", false);
	if (packed)
		sc->vrsc_consts.vc_hv_caps |= VIRTIO_F_RING_PACKED;
	alarm = get_config_bool_node_default(nvl, "alarm", false);
	if (alarm) {
		sc->vrsc_alarm_offered = true;
		sc->vrsc_consts.vc_nvq = VTRTC_NVQ;
		sc->vrsc_consts.vc_hv_caps |= VIRTIO_RTC_F_ALARM;
	}
	vi_softc_linkup(&sc->vrsc_vs, &sc->vrsc_consts, sc, pi,
	    sc->vrsc_vq);
	sc->vrsc_vs.vs_mtx = &sc->vrsc_mtx;
	sc->vrsc_vq[VTRTC_REQUESTQ].vq_qsize = VTRTC_RINGSZ;
	sc->vrsc_vq[VTRTC_ALARMQ].vq_qsize = VTRTC_RINGSZ;
	if (vi_pci_select_transport(&sc->vrsc_vs, nvl,
	    VIRTIO_PCI_MODERN_ONLY) != 0)
		goto failed_mtx;

	vi_pci_modern_set_identity(&sc->vrsc_vs, VIRTIO_ID_CLOCK);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_OTHER);
	if (vi_intr_init(&sc->vrsc_vs, 1, fbsdrun_virtio_msix()))
		goto failed_mtx;
	intr_initialized = true;
	if (vi_pci_modern_init(&sc->vrsc_vs, 2) != 0)
		goto failed_mtx;
	if (alarm) {
		sc->vrsc_alarm_fd = timerfd_create(CLOCK_REALTIME,
		    TFD_CLOEXEC | TFD_NONBLOCK);
		if (sc->vrsc_alarm_fd < 0)
			goto failed_mtx;
		sc->vrsc_alarm_evp = mevent_add(sc->vrsc_alarm_fd, EVF_READ,
		    pci_vtrtc_alarm_timerfd, sc);
		if (sc->vrsc_alarm_evp == NULL) {
			(void)close(sc->vrsc_alarm_fd);
			sc->vrsc_alarm_fd = -1;
			goto failed_mtx;
		}
	}
	return (0);

failed_mtx:
	if (sc->vrsc_alarm_evp != NULL) {
		/*
		 * The alarm callback dereferences sc.  An asynchronous delete only
		 * withdraws future readiness and can leave an already dispatched
		 * callback running against the failure cleanup below.
		 */
		(void)mevent_delete_close_sync(sc->vrsc_alarm_evp);
	}
	else if (sc->vrsc_alarm_fd >= 0)
		(void)close(sc->vrsc_alarm_fd);
	virtio_rtc_alarm_destroy(sc->vrsc_alarm);
	free(sc->vrsc_vs.vs_modern);
	if (intr_initialized)
		pthread_mutex_destroy(&sc->vrsc_vs.vs_isr_mtx);
	pthread_mutex_destroy(&sc->vrsc_mtx);
failed:
	free(sc);
	return (1);
}

static const struct pci_devemu pci_de_vtrtc = {
	.pe_emu = "virtio-rtc",
	.pe_init = pci_vtrtc_init,
	.pe_cfgwrite = vi_pci_modern_cfgwrite,
	.pe_cfgread = vi_pci_modern_cfgread,
	.pe_barwrite = vi_pci_write,
	.pe_barread = vi_pci_read,
#ifdef BHYVE_SNAPSHOT
	.pe_snapshot = vi_pci_snapshot,
	.pe_snapshot_validate = vi_pci_snapshot,
	.pe_snapshot_compat = vi_pci_snapshot_compat,
	.pe_pause = vi_pci_pause,
	.pe_resume = vi_pci_resume,
#endif
};
PCI_EMUL_SET(pci_de_vtrtc);
