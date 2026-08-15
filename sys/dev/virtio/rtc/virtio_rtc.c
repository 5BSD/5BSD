/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

/*
 * Read-only system clock and alarm driver for the VirtIO RTC device.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/bus.h>
#include <sys/clock.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/sglist.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/taskqueue.h>

#include <machine/atomic.h>

#include <dev/virtio/rtc/virtio_rtc.h>
#include <dev/virtio/virtio.h>
#include <dev/virtio/virtio_ids.h>
#include <dev/virtio/virtqueue.h>

#include "clock_if.h"
#include "virtio_if.h"

#define	VTRTC_FEATURES		(VIRTIO_F_RING_RESET | VIRTIO_RTC_F_ALARM)
#define	VTRTC_REQUEST_TIMEOUT	(10 * SBT_1S)
#define	VTRTC_NSEC_PER_SEC	UINT64_C(1000000000)

#define	VTRTC_FLAG_DETACH	0x01
#define	VTRTC_FLAG_FAILED	0x02

struct vtrtc_softc {
	device_t		 dev;
	struct virtqueue	*requestq;
	struct virtqueue	*alarmq;
	struct mtx		 mtx;
	struct mtx		 alarm_mtx;
	struct task		 alarm_task;
	struct virtio_rtc_notif_alarm alarm_notification;
	uint64_t		 features;
	uint64_t		 alarm_time;
	uint64_t		 alarm_count;
	uint64_t		 alarm_observed_time;
	u_int			 flags;
	bool			 mtx_initialized;
	bool			 alarm_mtx_initialized;
	bool			 alarm_task_initialized;
	bool			 request_active;
	bool			 clock_registered;
};

static int	vtrtc_modevent(module_t, int, void *);
static int	vtrtc_probe(device_t);
static int	vtrtc_attach(device_t);
static int	vtrtc_attach_completed(device_t);
static int	vtrtc_detach(device_t);
static int	vtrtc_gettime(device_t, struct timespec *);
static int	vtrtc_settime(device_t, struct timespec *);
static void	vtrtc_requestq_intr(void *);
static void	vtrtc_alarmq_intr(void *);
static void	vtrtc_alarm_task(void *, int);
static int	vtrtc_alarmq_enqueue(struct vtrtc_softc *);
static void	vtrtc_fail_locked(struct vtrtc_softc *);
static int	vtrtc_request(struct vtrtc_softc *, const void *, size_t,
		    void *, size_t, uint32_t *);
static int	vtrtc_status_error(uint8_t);
static bool	vtrtc_zeros(const uint8_t *, size_t);
static int	vtrtc_read_clock(struct vtrtc_softc *, uint64_t *);
static int	vtrtc_validate_clock(struct vtrtc_softc *);
static int	vtrtc_alarm_control(struct vtrtc_softc *, uint64_t, bool);
static int	vtrtc_alarm_set(struct vtrtc_softc *, uint64_t);
static int	vtrtc_sysctl_alarm_time(SYSCTL_HANDLER_ARGS);
static int	vtrtc_sysctl_alarm_count(SYSCTL_HANDLER_ARGS);
static void	vtrtc_setup_sysctl(struct vtrtc_softc *);

static struct virtio_feature_desc vtrtc_feature_desc[] = {
	{ VIRTIO_RTC_F_ALARM, "Alarm" },
	{ VIRTIO_F_RING_RESET, "RingReset" },
	{ 0, NULL }
};

static device_method_t vtrtc_methods[] = {
	DEVMETHOD(device_probe,		vtrtc_probe),
	DEVMETHOD(device_attach,	vtrtc_attach),
	DEVMETHOD(device_detach,	vtrtc_detach),

	DEVMETHOD(virtio_attach_completed, vtrtc_attach_completed),

	DEVMETHOD(clock_gettime,	vtrtc_gettime),
	DEVMETHOD(clock_settime,	vtrtc_settime),

	DEVMETHOD_END
};

static driver_t vtrtc_driver = {
	"vtrtc",
	vtrtc_methods,
	sizeof(struct vtrtc_softc)
};

VIRTIO_DRIVER_MODULE(virtio_rtc, vtrtc_driver, vtrtc_modevent, NULL);
MODULE_VERSION(virtio_rtc, 1);
MODULE_DEPEND(virtio_rtc, virtio, 1, 1, 1);

VIRTIO_SIMPLE_PNPINFO(virtio_rtc, VIRTIO_ID_CLOCK,
    "VirtIO RTC Adapter");

static int
vtrtc_modevent(module_t mod __unused, int type, void *unused __unused)
{

	switch (type) {
	case MOD_LOAD:
	case MOD_QUIESCE:
	case MOD_UNLOAD:
	case MOD_SHUTDOWN:
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static int
vtrtc_probe(device_t dev)
{

	return (VIRTIO_SIMPLE_PROBE(dev, virtio_rtc));
}

static int
vtrtc_attach(device_t dev)
{
	struct vtrtc_softc *sc;
	struct vq_alloc_info vq_info[2];
	int nvqs;
	int error;

	sc = device_get_softc(dev);
	sc->dev = dev;
	mtx_init(&sc->mtx, device_get_nameunit(dev), "VirtIO RTC request",
	    MTX_DEF);
	sc->mtx_initialized = true;
	mtx_init(&sc->alarm_mtx, device_get_nameunit(dev),
	    "VirtIO RTC alarm control", MTX_DEF);
	sc->alarm_mtx_initialized = true;
	virtio_set_feature_desc(dev, vtrtc_feature_desc);

	sc->features = virtio_negotiate_features(dev, VTRTC_FEATURES);
	error = virtio_finalize_features(dev);
	if (error != 0) {
		device_printf(dev, "cannot finalize features: %d\n", error);
		goto fail;
	}

	nvqs = 1;
	VQ_ALLOC_INFO_INIT(&vq_info[0], 0, vtrtc_requestq_intr, sc,
	    &sc->requestq, "%s request", device_get_nameunit(dev));
	if (virtio_with_feature(dev, VIRTIO_RTC_F_ALARM)) {
		VQ_ALLOC_INFO_INIT(&vq_info[1], 0, vtrtc_alarmq_intr, sc,
		    &sc->alarmq, "%s alarm", device_get_nameunit(dev));
		nvqs++;
	}
	error = virtio_alloc_virtqueues(dev, nvqs, vq_info);
	if (error != 0) {
		device_printf(dev, "cannot allocate request virtqueue: %d\n",
		    error);
		goto fail;
	}
	if (sc->alarmq != NULL) {
		TASK_INIT(&sc->alarm_task, 0, vtrtc_alarm_task, sc);
		sc->alarm_task_initialized = true;
	}
	error = virtio_setup_intr(dev, INTR_TYPE_CLK);
	if (error != 0) {
		device_printf(dev, "cannot setup request interrupt: %d\n",
		    error);
		goto fail;
	}
	return (0);

fail:
	vtrtc_detach(dev);
	return (error);
}

static int
vtrtc_attach_completed(device_t dev)
{
	struct vtrtc_softc *sc;
	uint64_t reading;
	int error;

	sc = device_get_softc(dev);
	(void)virtqueue_enable_intr(sc->requestq);
	error = vtrtc_validate_clock(sc);
	if (error != 0)
		return (error);
	if (sc->alarmq != NULL) {
		/*
		 * Section 5.23.6.6 permits a device to retain alarm state over
		 * reset.  Clear both the retained deadline and enable bit before
		 * making any writable alarmq buffer available.
		 */
		error = vtrtc_alarm_control(sc, 0, true);
		if (error != 0)
			return (error);
		mtx_lock(&sc->mtx);
		error = vtrtc_alarmq_enqueue(sc);
		if (error == 0) {
			virtqueue_notify(sc->alarmq);
			(void)virtqueue_enable_intr(sc->alarmq);
		}
		mtx_unlock(&sc->mtx);
		if (error != 0)
			return (error);
	}
	error = vtrtc_read_clock(sc, &reading);
	if (error != 0 || reading / VTRTC_NSEC_PER_SEC >
	    (uint64_t)INT64_MAX)
		return (error != 0 ? error : EOVERFLOW);

	/*
	 * The device reports an absolute UTC-family nanosecond clock.  Prevent
	 * the generic RTC layer from applying a local-time offset.  The device
	 * is read-only, so settime returns EOPNOTSUPP.
	 */
	clock_register_flags(dev, 1, CLOCKF_GETTIME_NO_ADJ |
	    CLOCKF_SETTIME_NO_ADJ);
	sc->clock_registered = true;
	vtrtc_setup_sysctl(sc);
	return (0);
}

static int
vtrtc_detach(device_t dev)
{
	struct vtrtc_softc *sc;
	int last;

	sc = device_get_softc(dev);
	if (sc->mtx_initialized) {
		atomic_set_rel_int(&sc->flags, VTRTC_FLAG_DETACH);
		/*
		 * Pair the detach wakeup with the request wait mutex.  Merely
		 * setting the atomic flag and waking without this handshake can
		 * race the interval between the request loop's flag check and
		 * msleep(), delaying detach until the request timeout.
		 */
		mtx_lock(&sc->mtx);
		wakeup(sc);
		mtx_unlock(&sc->mtx);
	}
	if (sc->clock_registered) {
		clock_unregister(dev);
		sc->clock_registered = false;
	}
	/*
	 * The alarm worker can own a stack-backed request descriptor.  Drain it
	 * after setting DETACH and waking requestq, but before clearing either
	 * queue pointer or destroying its lock.
	 */
	if (sc->alarm_task_initialized) {
		taskqueue_drain(taskqueue_thread, &sc->alarm_task);
		sc->alarm_task_initialized = false;
	}
	if (sc->mtx_initialized)
		mtx_lock(&sc->mtx);
	if (sc->requestq != NULL || sc->alarmq != NULL) {
		if (sc->requestq != NULL)
			virtqueue_disable_intr(sc->requestq);
		if (sc->alarmq != NULL)
			virtqueue_disable_intr(sc->alarmq);
		virtio_stop(dev);
	}
	if (sc->requestq != NULL) {
		last = 0;
		while (virtqueue_drain(sc->requestq, &last) != NULL)
			;
		sc->requestq = NULL;
	}
	if (sc->alarmq != NULL) {
		last = 0;
		while (virtqueue_drain(sc->alarmq, &last) != NULL)
			;
		sc->alarmq = NULL;
	}
	if (sc->mtx_initialized)
		mtx_unlock(&sc->mtx);
	/* Drain callbacks before destroying the mutex they acquire. */
	virtio_teardown_intr(dev);
	if (sc->mtx_initialized) {
		mtx_destroy(&sc->mtx);
		sc->mtx_initialized = false;
	}
	if (sc->alarm_mtx_initialized) {
		mtx_destroy(&sc->alarm_mtx);
		sc->alarm_mtx_initialized = false;
	}
	return (0);
}

static void
vtrtc_requestq_intr(void *xsc)
{
	struct vtrtc_softc *sc;

	sc = xsc;
	/* Serialize with the dequeue/check/msleep sequence in vtrtc_request(). */
	mtx_lock(&sc->mtx);
	wakeup(sc);
	mtx_unlock(&sc->mtx);
}

static int
vtrtc_alarmq_enqueue(struct vtrtc_softc *sc)
{
	struct sglist sg;
	struct sglist_seg segs[2];
	int error;

	if (sc->alarmq == NULL)
		return (ENODEV);
	memset(&sc->alarm_notification, 0,
	    sizeof(sc->alarm_notification));
	sglist_init(&sg, nitems(segs), segs);
	error = sglist_append(&sg, &sc->alarm_notification,
	    sizeof(sc->alarm_notification));
	if (error != 0)
		return (error);
	return (virtqueue_enqueue(sc->alarmq, &sc->alarm_notification, &sg,
	    0, sg.sg_nseg));
}

static void
vtrtc_fail_locked(struct vtrtc_softc *sc)
{
	int last;

	mtx_assert(&sc->mtx, MA_OWNED);
	atomic_set_rel_int(&sc->flags, VTRTC_FLAG_FAILED);
	if (sc->requestq != NULL)
		virtqueue_disable_intr(sc->requestq);
	if (sc->alarmq != NULL)
		virtqueue_disable_intr(sc->alarmq);
	virtio_stop(sc->dev);
	if (sc->requestq != NULL) {
		last = 0;
		while (virtqueue_drain(sc->requestq, &last) != NULL)
			;
	}
	if (sc->alarmq != NULL) {
		last = 0;
		while (virtqueue_drain(sc->alarmq, &last) != NULL)
			;
	}
	wakeup(sc);
}

static void
vtrtc_alarmq_intr(void *xsc)
{
	struct virtio_rtc_notif_alarm *notification;
	struct vtrtc_softc *sc;
	uint32_t used_len;
	bool malformed;
	int error;

	sc = xsc;
	mtx_lock(&sc->mtx);
	/*
	 * Detach sets this admission fence under the same mutex before draining
	 * alarm_task.  Do not enqueue that task after detach's drain has returned
	 * but before the parent tears down this still-live interrupt.
	 */
	if ((atomic_load_acq_int(&sc->flags) & VTRTC_FLAG_DETACH) != 0)
		goto out;
again:
	while ((notification = virtqueue_dequeue(sc->alarmq, &used_len)) !=
	    NULL) {
		malformed = notification != &sc->alarm_notification ||
		    used_len != sizeof(*notification) ||
		    le16toh(notification->head.msg_type) !=
		    VIRTIO_RTC_NOTIF_ALARM ||
		    !vtrtc_zeros(notification->head.reserved,
		    sizeof(notification->head.reserved)) ||
		    le16toh(notification->clock_id) != VIRTIO_RTC_CLOCK_UTC ||
		    !vtrtc_zeros(notification->reserved,
		    sizeof(notification->reserved));
		if (malformed) {
			device_printf(sc->dev,
			    "device returned malformed alarm notification\n");
			atomic_set_rel_int(&sc->flags, VTRTC_FLAG_FAILED);
			wakeup(sc);
			(void)taskqueue_enqueue(taskqueue_thread,
			    &sc->alarm_task);
			break;
		}
		if (sc->alarm_count != UINT64_MAX)
			sc->alarm_count++;
		if ((atomic_load_acq_int(&sc->flags) &
		    (VTRTC_FLAG_DETACH | VTRTC_FLAG_FAILED)) == 0)
			(void)taskqueue_enqueue(taskqueue_thread,
			    &sc->alarm_task);
		error = vtrtc_alarmq_enqueue(sc);
		if (error != 0) {
			device_printf(sc->dev,
			    "cannot replenish alarm queue: %d\n", error);
			atomic_set_rel_int(&sc->flags, VTRTC_FLAG_FAILED);
			wakeup(sc);
			(void)taskqueue_enqueue(taskqueue_thread,
			    &sc->alarm_task);
			break;
		}
		virtqueue_notify(sc->alarmq);
	}
	if ((atomic_load_acq_int(&sc->flags) &
	    (VTRTC_FLAG_DETACH | VTRTC_FLAG_FAILED)) == 0) {
		if (virtqueue_enable_intr(sc->alarmq) != 0) {
			virtqueue_disable_intr(sc->alarmq);
			goto again;
		}
	}
out:
	mtx_unlock(&sc->mtx);
}

static void
vtrtc_alarm_task(void *xsc, int pending __unused)
{
	struct vtrtc_softc *sc;
	uint64_t reading;
	int error;

	sc = xsc;
	if ((atomic_load_acq_int(&sc->flags) & VTRTC_FLAG_DETACH) != 0)
		return;
	if ((atomic_load_acq_int(&sc->flags) & VTRTC_FLAG_FAILED) != 0) {
		/*
		 * Alarm completions run in interrupt context, where a full device
		 * reset is not permitted.  Reclaim every device-owned descriptor
		 * here before a malformed asynchronous completion can leave DMA
		 * active indefinitely.  A concurrent request waiter observes FAILED
		 * after this drain and returns without exposing its stack storage.
		 */
		mtx_lock(&sc->mtx);
		if ((atomic_load_acq_int(&sc->flags) & VTRTC_FLAG_DETACH) == 0)
			vtrtc_fail_locked(sc);
		mtx_unlock(&sc->mtx);
		return;
	}
	error = vtrtc_read_clock(sc, &reading);
	if (error != 0) {
		if ((atomic_load_acq_int(&sc->flags) & VTRTC_FLAG_DETACH) == 0) {
			device_printf(sc->dev,
			    "cannot read clock after alarm notification: %d\n",
			    error);
			mtx_lock(&sc->mtx);
			if ((atomic_load_acq_int(&sc->flags) &
			    VTRTC_FLAG_DETACH) == 0)
				vtrtc_fail_locked(sc);
			mtx_unlock(&sc->mtx);
		}
		return;
	}
	mtx_lock(&sc->mtx);
	sc->alarm_observed_time = reading;
	mtx_unlock(&sc->mtx);
}

static int
vtrtc_request(struct vtrtc_softc *sc, const void *request,
    size_t request_len, void *response, size_t response_len,
    uint32_t *used_lenp)
{
	struct sglist sg;
	struct sglist_seg segs[4];
	sbintime_t deadline, remaining;
	void *cookie;
	uint32_t used_len;
	int error, readable;

	if (request == NULL || response == NULL || request_len == 0 ||
	    response_len == 0 || request_len > PAGE_SIZE ||
	    response_len > PAGE_SIZE || used_lenp == NULL)
		return (EINVAL);
	*used_lenp = 0;

	sglist_init(&sg, nitems(segs), segs);
	error = sglist_append(&sg, __DECONST(void *, request), request_len);
	if (error != 0)
		return (error);
	readable = sg.sg_nseg;
	error = sglist_append(&sg, response, response_len);
	if (error != 0)
		return (error);

	mtx_lock(&sc->mtx);
	while (sc->request_active &&
	    (atomic_load_acq_int(&sc->flags) &
	    (VTRTC_FLAG_DETACH | VTRTC_FLAG_FAILED)) == 0)
		msleep(&sc->request_active, &sc->mtx, 0, "vtrtcq", 0);
	if ((atomic_load_acq_int(&sc->flags) & VTRTC_FLAG_DETACH) != 0) {
		error = ENXIO;
		goto out;
	}
	if ((atomic_load_acq_int(&sc->flags) & VTRTC_FLAG_FAILED) != 0) {
		error = EIO;
		goto out;
	}
	sc->request_active = true;
	error = virtqueue_enqueue(sc->requestq, response, &sg, readable,
	    sg.sg_nseg - readable);
	if (error != 0)
		goto complete;
	virtqueue_notify(sc->requestq);
	deadline = sbinuptime() + VTRTC_REQUEST_TIMEOUT;

	for (;;) {
		cookie = virtqueue_dequeue(sc->requestq, &used_len);
		if (cookie != NULL)
			break;
		if ((atomic_load_acq_int(&sc->flags) &
		    (VTRTC_FLAG_DETACH | VTRTC_FLAG_FAILED)) != 0) {
			error = (atomic_load_acq_int(&sc->flags) &
			    VTRTC_FLAG_DETACH) != 0 ? ENXIO : EIO;
			goto reset;
		}
		if (virtqueue_enable_intr(sc->requestq) != 0)
			continue;
		remaining = deadline - sbinuptime();
		if (remaining <= 0) {
			error = EWOULDBLOCK;
		} else {
			error = msleep_sbt(sc, &sc->mtx, 0, "vtrtcr",
			    remaining, 0, 0);
		}
		if (error == EWOULDBLOCK) {
			device_printf(sc->dev, "request timed out\n");
			error = ETIMEDOUT;
			goto reset;
		}
		if (error != 0)
			goto reset;
	}
	if (cookie != response) {
		device_printf(sc->dev, "request returned unexpected cookie\n");
		error = EIO;
		goto reset;
	}
	if (used_len < sizeof(struct virtio_rtc_resp_head) ||
	    used_len > response_len) {
		device_printf(sc->dev,
		    "request returned invalid response length %u\n", used_len);
		error = EIO;
		goto reset;
	}
	*used_lenp = used_len;
	error = 0;
	goto complete;

reset:
	/*
	 * Both descriptors reference caller-owned stack objects.  Reset and
	 * drain before returning from an incomplete request.
	 */
	vtrtc_fail_locked(sc);
complete:
	sc->request_active = false;
	wakeup(&sc->request_active);
out:
	mtx_unlock(&sc->mtx);
	return (error);
}

static int
vtrtc_status_error(uint8_t status)
{

	switch (status) {
	case VIRTIO_RTC_S_OK:
		return (0);
	case VIRTIO_RTC_S_EOPNOTSUPP:
		return (EOPNOTSUPP);
	case VIRTIO_RTC_S_ENODEV:
		return (ENODEV);
	case VIRTIO_RTC_S_EINVAL:
		return (EINVAL);
	case VIRTIO_RTC_S_EIO:
	default:
		return (EIO);
	}
}

static bool
vtrtc_zeros(const uint8_t *bytes, size_t length)
{
	size_t i;

	for (i = 0; i < length; i++) {
		if (bytes[i] != 0)
			return (false);
	}
	return (true);
}

static int
vtrtc_validate_clock(struct vtrtc_softc *sc)
{
	struct virtio_rtc_req_cfg cfg_req;
	struct virtio_rtc_resp_cfg cfg_resp;
	struct virtio_rtc_req_clock_cap cap_req;
	struct virtio_rtc_resp_clock_cap cap_resp;
	uint32_t expected_flags, used_len;
	int error;

	memset(&cfg_req, 0, sizeof(cfg_req));
	memset(&cfg_resp, 0, sizeof(cfg_resp));
	cfg_req.head.msg_type = htole16(VIRTIO_RTC_REQ_CFG);
	error = vtrtc_request(sc, &cfg_req, sizeof(cfg_req), &cfg_resp,
	    sizeof(cfg_resp), &used_len);
	if (error != 0)
		return (error);
	error = vtrtc_status_error(cfg_resp.head.status);
	if (error != 0)
		return (error);
	if (used_len != sizeof(cfg_resp))
		return (EIO);
	if (!vtrtc_zeros(cfg_resp.head.reserved,
	    sizeof(cfg_resp.head.reserved)) ||
	    !vtrtc_zeros(cfg_resp.reserved, sizeof(cfg_resp.reserved)))
		return (EPROTO);
	if (le16toh(cfg_resp.num_clocks) == 0)
		return (ENODEV);

	memset(&cap_req, 0, sizeof(cap_req));
	memset(&cap_resp, 0, sizeof(cap_resp));
	cap_req.head.msg_type = htole16(VIRTIO_RTC_REQ_CLOCK_CAP);
	cap_req.clock_id = htole16(VIRTIO_RTC_CLOCK_UTC);
	error = vtrtc_request(sc, &cap_req, sizeof(cap_req), &cap_resp,
	    sizeof(cap_resp), &used_len);
	if (error != 0)
		return (error);
	error = vtrtc_status_error(cap_resp.head.status);
	if (error != 0)
		return (error);
	if (used_len != sizeof(cap_resp))
		return (EIO);
	if (!vtrtc_zeros(cap_resp.head.reserved,
	    sizeof(cap_resp.head.reserved)) ||
	    !vtrtc_zeros(cap_resp.reserved, sizeof(cap_resp.reserved)))
		return (EPROTO);
	expected_flags = sc->alarmq != NULL ? VIRTIO_RTC_FLAG_ALARM_CAP : 0;
	if (cap_resp.leap_second_smearing !=
	    VIRTIO_RTC_SMEAR_UNSPECIFIED ||
	    cap_resp.flags != expected_flags)
		return (EPROTO);
	if (cap_resp.type != VIRTIO_RTC_CLOCK_UTC &&
	    cap_resp.type != VIRTIO_RTC_CLOCK_UTC_MAYBE_SMEARED)
		return (ENOTSUP);
	return (0);
}

static int
vtrtc_read_clock(struct vtrtc_softc *sc, uint64_t *reading)
{
	struct virtio_rtc_req_read request;
	struct virtio_rtc_resp_read response;
	uint32_t used_len;
	int error;

	memset(&request, 0, sizeof(request));
	memset(&response, 0, sizeof(response));
	request.head.msg_type = htole16(VIRTIO_RTC_REQ_READ);
	request.clock_id = htole16(VIRTIO_RTC_CLOCK_UTC);
	error = vtrtc_request(sc, &request, sizeof(request), &response,
	    sizeof(response), &used_len);
	if (error != 0)
		return (error);
	error = vtrtc_status_error(response.head.status);
	if (error != 0)
		return (error);
	if (used_len != sizeof(response))
		return (EIO);
	if (!vtrtc_zeros(response.head.reserved,
	    sizeof(response.head.reserved)))
		return (EPROTO);
	*reading = le64toh(response.clock_reading);
	return (0);
}

static int
vtrtc_alarm_control(struct vtrtc_softc *sc, uint64_t alarm_time,
    bool replace_time)
{
	struct virtio_rtc_req_set_alarm set_request;
	struct virtio_rtc_req_set_alarm_enabled disable_request;
	struct virtio_rtc_resp_head response;
	const void *request;
	size_t request_len;
	uint32_t used_len;
	int error;

	if (sc->alarmq == NULL)
		return (EOPNOTSUPP);
	mtx_lock(&sc->alarm_mtx);
	memset(&response, 0, sizeof(response));
	if (replace_time) {
		memset(&set_request, 0, sizeof(set_request));
		set_request.head.msg_type =
		    htole16(VIRTIO_RTC_REQ_SET_ALARM);
		set_request.alarm_time = htole64(alarm_time);
		set_request.clock_id = htole16(VIRTIO_RTC_CLOCK_UTC);
		if (alarm_time != 0)
			set_request.flags = VIRTIO_RTC_FLAG_ALARM_ENABLED;
		request = &set_request;
		request_len = sizeof(set_request);
	} else {
		memset(&disable_request, 0, sizeof(disable_request));
		disable_request.head.msg_type =
		    htole16(VIRTIO_RTC_REQ_SET_ALARM_ENABLED);
		disable_request.clock_id = htole16(VIRTIO_RTC_CLOCK_UTC);
		request = &disable_request;
		request_len = sizeof(disable_request);
	}
	error = vtrtc_request(sc, request, request_len, &response,
	    sizeof(response), &used_len);
	if (error != 0)
		goto out;
	if (used_len != sizeof(response) ||
	    !vtrtc_zeros(response.reserved, sizeof(response.reserved))) {
		error = EPROTO;
		goto out;
	}
	error = vtrtc_status_error(response.status);
	if (error != 0)
		goto out;

	mtx_lock(&sc->mtx);
	sc->alarm_time = alarm_time;
	mtx_unlock(&sc->mtx);
out:
	mtx_unlock(&sc->alarm_mtx);
	return (error);
}

static int
vtrtc_alarm_set(struct vtrtc_softc *sc, uint64_t alarm_time)
{

	/* A zero sysctl write disables while retaining the device deadline. */
	return (vtrtc_alarm_control(sc, alarm_time, alarm_time != 0));
}

static int
vtrtc_sysctl_alarm_time(SYSCTL_HANDLER_ARGS)
{
	struct vtrtc_softc *sc;
	uint64_t alarm_time;
	int error;

	sc = arg1;
	mtx_lock(&sc->mtx);
	alarm_time = sc->alarm_time;
	mtx_unlock(&sc->mtx);
	error = sysctl_handle_64(oidp, &alarm_time, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	return (vtrtc_alarm_set(sc, alarm_time));
}

static int
vtrtc_sysctl_alarm_count(SYSCTL_HANDLER_ARGS)
{
	struct vtrtc_softc *sc;
	uint64_t alarm_count;

	sc = arg1;
	mtx_lock(&sc->mtx);
	alarm_count = sc->alarm_count;
	mtx_unlock(&sc->mtx);
	return (sysctl_handle_64(oidp, NULL, alarm_count, req));
}

static int
vtrtc_sysctl_alarm_observed_time(SYSCTL_HANDLER_ARGS)
{
	struct vtrtc_softc *sc;
	uint64_t observed_time;

	sc = arg1;
	mtx_lock(&sc->mtx);
	observed_time = sc->alarm_observed_time;
	mtx_unlock(&sc->mtx);
	return (sysctl_handle_64(oidp, NULL, observed_time, req));
}

static void
vtrtc_setup_sysctl(struct vtrtc_softc *sc)
{
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid *tree;
	struct sysctl_oid_list *child;

	if (sc->alarmq == NULL)
		return;
	ctx = device_get_sysctl_ctx(sc->dev);
	tree = device_get_sysctl_tree(sc->dev);
	child = SYSCTL_CHILDREN(tree);
	SYSCTL_ADD_PROC(ctx, child, OID_AUTO, "alarm_time_ns",
	    CTLTYPE_U64 | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    vtrtc_sysctl_alarm_time, "QU",
	    "Absolute UTC alarm deadline in nanoseconds; zero disables it");
	SYSCTL_ADD_PROC(ctx, child, OID_AUTO, "alarm_count",
	    CTLTYPE_U64 | CTLFLAG_RD | CTLFLAG_MPSAFE, sc, 0,
	    vtrtc_sysctl_alarm_count, "QU",
	    "Number of validated alarm notifications");
	SYSCTL_ADD_PROC(ctx, child, OID_AUTO, "alarm_observed_time_ns",
	    CTLTYPE_U64 | CTLFLAG_RD | CTLFLAG_MPSAFE, sc, 0,
	    vtrtc_sysctl_alarm_observed_time, "QU",
	    "UTC clock reading obtained after the latest alarm notification");
}

static int
vtrtc_gettime(device_t dev, struct timespec *ts)
{
	struct vtrtc_softc *sc;
	uint64_t reading, seconds;
	int error;

	sc = device_get_softc(dev);
	error = vtrtc_read_clock(sc, &reading);
	if (error != 0)
		return (error);
	seconds = reading / VTRTC_NSEC_PER_SEC;
	if (seconds > (uint64_t)INT64_MAX)
		return (EOVERFLOW);
	ts->tv_sec = (time_t)seconds;
	ts->tv_nsec = (long)(reading % VTRTC_NSEC_PER_SEC);
	return (0);
}

static int
vtrtc_settime(device_t dev __unused, struct timespec *ts __unused)
{

	return (EOPNOTSUPP);
}
