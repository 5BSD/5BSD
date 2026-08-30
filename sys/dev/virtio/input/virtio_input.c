/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

/*
 * VirtIO input frontend for the FreeBSD evdev subsystem.
 *
 * Device configuration is discovered before DRIVER_OK.  Event buffers and
 * the evdev provider are published only from attach_completed(), after the
 * transport has made the device operational.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/sglist.h>
#include <sys/systm.h>
#include <sys/taskqueue.h>

#include <dev/evdev/evdev.h>
#include <dev/evdev/input.h>

#include <dev/virtio/input/virtio_input.h>
#include <dev/virtio/virtio.h>
#include <dev/virtio/virtio_ids.h>
#include <dev/virtio/virtqueue.h>

#include "virtio_if.h"

#define	VTINPUT_EVENT_SLOTS	64
#define	VTINPUT_STATUS_SLOTS	32
#define	VTINPUT_EVENTQ		0
#define	VTINPUT_STATUSQ		1
#define	VTINPUT_FEATURES	VIRTIO_F_RING_RESET

struct vtinput_event_slot {
	struct virtio_input_event event;
};

struct vtinput_status_slot {
	struct virtio_input_event event;
	bool in_use;
};

struct vtinput_softc {
	device_t dev;
	struct virtqueue *eventq;
	struct virtqueue *statusq;
	struct evdev_dev *evdev;
	struct mtx mtx;
	struct task fail_task;
	uint64_t features;
	bool mtx_initialized;
	bool fail_task_initialized;
	bool detaching;
	bool failed;
	bool multitouch;
	char name[129];
	char serial[129];
	struct vtinput_event_slot event_slots[VTINPUT_EVENT_SLOTS];
	struct vtinput_status_slot status_slots[VTINPUT_STATUS_SLOTS];
};

static int	vtinput_modevent(module_t, int, void *);
static int	vtinput_probe(device_t);
static int	vtinput_attach(device_t);
static int	vtinput_attach_completed(device_t);
static int	vtinput_detach(device_t);
static void	vtinput_eventq_intr(void *);
static void	vtinput_statusq_intr(void *);
static void	vtinput_fail_task(void *, int);
static void	vtinput_fail_locked(struct vtinput_softc *);
static void	vtinput_ev_event(struct evdev_dev *, uint16_t, uint16_t,
		    int32_t);
static int	vtinput_cfg_select(struct vtinput_softc *, uint8_t, uint8_t,
		    void *, size_t, uint8_t *);
static int	vtinput_discover(struct vtinput_softc *);
static int	vtinput_enqueue_event(struct vtinput_softc *,
		    struct vtinput_event_slot *);
static int	vtinput_enqueue_status(struct vtinput_softc *,
		    struct vtinput_status_slot *);
static int	vtinput_support_bitmap(struct vtinput_softc *, uint8_t,
		    u_int);
static bool	vtinput_bitmap_test(const uint8_t *, size_t, u_int);

static const struct evdev_methods vtinput_evdev_methods = {
	.ev_event = vtinput_ev_event,
};

static struct virtio_feature_desc vtinput_feature_desc[] = {
	{ VIRTIO_F_RING_RESET, "RingReset" },
	{ 0, NULL }
};

static device_method_t vtinput_methods[] = {
	DEVMETHOD(device_probe,		vtinput_probe),
	DEVMETHOD(device_attach,	vtinput_attach),
	DEVMETHOD(device_detach,	vtinput_detach),
	DEVMETHOD(virtio_attach_completed, vtinput_attach_completed),
	DEVMETHOD_END
};

static driver_t vtinput_driver = {
	"vtinput",
	vtinput_methods,
	sizeof(struct vtinput_softc)
};

VIRTIO_DRIVER_MODULE(virtio_input, vtinput_driver, vtinput_modevent, NULL);
MODULE_VERSION(virtio_input, 1);
MODULE_DEPEND(virtio_input, virtio, 1, 1, 1);
MODULE_DEPEND(virtio_input, evdev, 1, 1, 1);

VIRTIO_SIMPLE_PNPINFO(virtio_input, VIRTIO_ID_INPUT,
    "VirtIO Input Adapter");

static int
vtinput_modevent(module_t mod __unused, int type, void *unused __unused)
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
vtinput_probe(device_t dev)
{

	return (VIRTIO_SIMPLE_PROBE(dev, virtio_input));
}

static bool
vtinput_bitmap_test(const uint8_t *bitmap, size_t bytes, u_int bit)
{

	return (bit / NBBY < bytes &&
	    (bitmap[bit / NBBY] & (1U << (bit % NBBY))) != 0);
}

static int
vtinput_cfg_select(struct vtinput_softc *sc, uint8_t select, uint8_t subsel,
    void *data, size_t capacity, uint8_t *sizep)
{
	uint8_t size;

	virtio_write_dev_config_1(sc->dev,
	    offsetof(struct virtio_input_config, select), select);
	virtio_write_dev_config_1(sc->dev,
	    offsetof(struct virtio_input_config, subsel), subsel);
	size = virtio_read_dev_config_1(sc->dev,
	    offsetof(struct virtio_input_config, size));
	if (size > sizeof(((struct virtio_input_config *)0)->u) ||
	    size > capacity)
		return (EOVERFLOW);
	if (size != 0 && data != NULL)
		virtio_read_device_config_array(sc->dev,
		    offsetof(struct virtio_input_config, u), data, 1, size);
	*sizep = size;
	return (0);
}

static int
vtinput_support_bitmap(struct vtinput_softc *sc, uint8_t type, u_int limit)
{
	uint8_t bitmap[128], size;
	u_int code;
	int error;

	memset(bitmap, 0, sizeof(bitmap));
	error = vtinput_cfg_select(sc, VIRTIO_INPUT_CFG_EV_BITS, type,
	    bitmap, sizeof(bitmap), &size);
	if (error != 0)
		return (error);
	if (size == 0)
		return (0);

	evdev_support_event(sc->evdev, type);
	for (code = 0; code < limit; code++) {
		if (!vtinput_bitmap_test(bitmap, size, code))
			continue;
		switch (type) {
		case EV_KEY:
			evdev_support_key(sc->evdev, code);
			break;
		case EV_REL:
			evdev_support_rel(sc->evdev, code);
			break;
		case EV_MSC:
			evdev_support_msc(sc->evdev, code);
			break;
		case EV_SW:
			evdev_support_sw(sc->evdev, code);
			break;
		case EV_LED:
			evdev_support_led(sc->evdev, code);
			break;
		case EV_SND:
			evdev_support_snd(sc->evdev, code);
			break;
		default:
			break;
		}
	}
	return (0);
}

static int
vtinput_discover(struct vtinput_softc *sc)
{
	struct virtio_input_absinfo abs;
	struct virtio_input_devids ids;
	uint8_t bitmap[128], size;
	u_int code;
	int error;

	sc->evdev = evdev_alloc();
	if (sc->evdev == NULL)
		return (ENOMEM);

	memset(sc->name, 0, sizeof(sc->name));
	error = vtinput_cfg_select(sc, VIRTIO_INPUT_CFG_ID_NAME, 0,
	    sc->name, sizeof(sc->name) - 1, &size);
	if (error != 0)
		return (error);
	if (size == 0)
		strlcpy(sc->name, "VirtIO Input", sizeof(sc->name));
	evdev_set_name(sc->evdev, sc->name);

	memset(sc->serial, 0, sizeof(sc->serial));
	error = vtinput_cfg_select(sc, VIRTIO_INPUT_CFG_ID_SERIAL, 0,
	    sc->serial, sizeof(sc->serial) - 1, &size);
	if (error != 0)
		return (error);
	evdev_set_serial(sc->evdev, sc->serial);
	evdev_set_phys(sc->evdev, device_get_nameunit(sc->dev));

	memset(&ids, 0, sizeof(ids));
	error = vtinput_cfg_select(sc, VIRTIO_INPUT_CFG_ID_DEVIDS, 0,
	    &ids, sizeof(ids), &size);
	if (error != 0)
		return (error);
	if (size == sizeof(ids))
		evdev_set_id(sc->evdev, le16toh(ids.bustype),
		    le16toh(ids.vendor), le16toh(ids.product),
		    le16toh(ids.version));
	else
		evdev_set_id(sc->evdev, BUS_VIRTUAL, 0, 0, 0);

	memset(bitmap, 0, sizeof(bitmap));
	error = vtinput_cfg_select(sc, VIRTIO_INPUT_CFG_PROP_BITS, 0,
	    bitmap, sizeof(bitmap), &size);
	if (error != 0)
		return (error);
	for (code = 0; code < INPUT_PROP_CNT; code++) {
		if (vtinput_bitmap_test(bitmap, size, code))
			evdev_support_prop(sc->evdev, code);
	}

	evdev_support_event(sc->evdev, EV_SYN);
	error = vtinput_support_bitmap(sc, EV_KEY, KEY_CNT);
	if (error != 0)
		return (error);
	error = vtinput_support_bitmap(sc, EV_REL, REL_CNT);
	if (error != 0)
		return (error);
	error = vtinput_support_bitmap(sc, EV_MSC, MSC_CNT);
	if (error != 0)
		return (error);
	error = vtinput_support_bitmap(sc, EV_SW, SW_CNT);
	if (error != 0)
		return (error);
	error = vtinput_support_bitmap(sc, EV_LED, LED_CNT);
	if (error != 0)
		return (error);
	error = vtinput_support_bitmap(sc, EV_SND, SND_CNT);
	if (error != 0)
		return (error);
	error = vtinput_support_bitmap(sc, EV_REP, 0);
	if (error != 0)
		return (error);

	memset(bitmap, 0, sizeof(bitmap));
	error = vtinput_cfg_select(sc, VIRTIO_INPUT_CFG_EV_BITS, EV_ABS,
	    bitmap, sizeof(bitmap), &size);
	if (error != 0)
		return (error);
	if (size != 0)
		evdev_support_event(sc->evdev, EV_ABS);
	sc->multitouch = vtinput_bitmap_test(bitmap, size, ABS_MT_SLOT);
	for (code = 0; code < ABS_CNT; code++) {
		if (!vtinput_bitmap_test(bitmap, size, code))
			continue;
		memset(&abs, 0, sizeof(abs));
		error = vtinput_cfg_select(sc, VIRTIO_INPUT_CFG_ABS_INFO,
		    code, &abs, sizeof(abs), &size);
		if (error != 0 || size != sizeof(abs))
			return (error != 0 ? error : EPROTO);
		evdev_support_abs(sc->evdev, code, le32toh(abs.min),
		    le32toh(abs.max), le32toh(abs.fuzz), le32toh(abs.flat),
		    le32toh(abs.res));
	}
	evdev_set_methods(sc->evdev, sc, &vtinput_evdev_methods);
	return (0);
}

static int
vtinput_attach(device_t dev)
{
	struct vtinput_softc *sc;
	struct vq_alloc_info vq_info[2];
	int error;

	sc = device_get_softc(dev);
	sc->dev = dev;
	mtx_init(&sc->mtx, device_get_nameunit(dev), "VirtIO input",
	    MTX_DEF);
	sc->mtx_initialized = true;
	TASK_INIT(&sc->fail_task, 0, vtinput_fail_task, sc);
	sc->fail_task_initialized = true;
	virtio_set_feature_desc(dev, vtinput_feature_desc);

	sc->features = virtio_negotiate_features(dev, VTINPUT_FEATURES);
	if ((sc->features & VIRTIO_F_VERSION_1) == 0) {
		error = ENXIO;
		goto fail;
	}
	error = virtio_finalize_features(dev);
	if (error != 0)
		goto fail;

	VQ_ALLOC_INFO_INIT(&vq_info[VTINPUT_EVENTQ], 0,
	    vtinput_eventq_intr, sc, &sc->eventq, "%s events",
	    device_get_nameunit(dev));
	VQ_ALLOC_INFO_INIT(&vq_info[VTINPUT_STATUSQ], 0,
	    vtinput_statusq_intr, sc, &sc->statusq, "%s status",
	    device_get_nameunit(dev));
	error = virtio_alloc_virtqueues(dev, nitems(vq_info), vq_info);
	if (error != 0)
		goto fail;
	if (virtqueue_size(sc->eventq) == 0 ||
	    virtqueue_size(sc->statusq) == 0) {
		error = ENXIO;
		goto fail;
	}
	error = virtio_setup_intr(dev, INTR_TYPE_MISC);
	if (error != 0)
		goto fail;
	error = vtinput_discover(sc);
	if (error != 0)
		goto fail;
	return (0);

fail:
	vtinput_detach(dev);
	return (error);
}

static int
vtinput_enqueue_event(struct vtinput_softc *sc,
    struct vtinput_event_slot *slot)
{
	struct sglist sg;
	struct sglist_seg segs[2];
	int error;

	sglist_init(&sg, nitems(segs), segs);
	error = sglist_append(&sg, &slot->event, sizeof(slot->event));
	if (error != 0)
		return (error);
	return (virtqueue_enqueue(sc->eventq, slot, &sg, 0, sg.sg_nseg));
}

static int
vtinput_enqueue_status(struct vtinput_softc *sc,
    struct vtinput_status_slot *slot)
{
	struct sglist sg;
	struct sglist_seg segs[2];
	int error;

	sglist_init(&sg, nitems(segs), segs);
	error = sglist_append(&sg, &slot->event, sizeof(slot->event));
	if (error != 0)
		return (error);
	return (virtqueue_enqueue(sc->statusq, slot, &sg, sg.sg_nseg, 0));
}

static int
vtinput_attach_completed(device_t dev)
{
	struct vtinput_softc *sc;
	u_int enqueued, i;
	int error;

	sc = device_get_softc(dev);
	error = evdev_register_mtx(sc->evdev, &sc->mtx);
	if (error != 0)
		return (error);

	mtx_lock(&sc->mtx);
	enqueued = 0;
	for (i = 0; i < nitems(sc->event_slots); i++) {
		error = vtinput_enqueue_event(sc, &sc->event_slots[i]);
		if (error == ENOSPC)
			break;
		if (error != 0)
			goto out;
		enqueued++;
	}
	if (enqueued == 0) {
		error = ENOSPC;
		goto out;
	}
	error = 0;
	(void)virtqueue_enable_intr(sc->eventq);
	(void)virtqueue_enable_intr(sc->statusq);
	virtqueue_notify(sc->eventq);
out:
	mtx_unlock(&sc->mtx);
	return (error);
}

static void
vtinput_fail_locked(struct vtinput_softc *sc)
{
	struct vtinput_status_slot *status;
	int last;

	mtx_assert(&sc->mtx, MA_OWNED);
	if (sc->eventq != NULL)
		virtqueue_disable_intr(sc->eventq);
	if (sc->statusq != NULL)
		virtqueue_disable_intr(sc->statusq);
	virtio_stop(sc->dev);
	if (sc->eventq != NULL) {
		last = 0;
		while (virtqueue_drain(sc->eventq, &last) != NULL)
			;
	}
	if (sc->statusq != NULL) {
		last = 0;
		while ((status = virtqueue_drain(sc->statusq, &last)) != NULL)
			status->in_use = false;
	}
}

static void
vtinput_fail_task(void *xsc, int pending __unused)
{
	struct vtinput_softc *sc;

	sc = xsc;
	mtx_lock(&sc->mtx);
	if (!sc->detaching && sc->failed)
		vtinput_fail_locked(sc);
	mtx_unlock(&sc->mtx);
}

static void
vtinput_eventq_intr(void *xsc)
{
	struct vtinput_softc *sc;
	struct vtinput_event_slot *slot;
	uint32_t len;
	uint16_t type, code;
	int32_t value;

	sc = xsc;
	mtx_lock(&sc->mtx);
again:
	while ((slot = virtqueue_dequeue(sc->eventq, &len)) != NULL) {
		if (sc->detaching || sc->failed)
			continue;
		if (len == sizeof(slot->event)) {
			type = le16toh(slot->event.type);
			code = le16toh(slot->event.code);
			value = (int32_t)le32toh(slot->event.value);
			if (evdev_push_event(sc->evdev, type, code, value) != 0) {
				device_printf(sc->dev,
				    "device returned invalid event %u/%u/%d\n",
				    type, code, value);
				sc->failed = true;
				(void)taskqueue_enqueue(taskqueue_thread,
				    &sc->fail_task);
				continue;
			}
		} else {
			device_printf(sc->dev,
			    "device returned event with invalid length %u\n",
			    len);
			sc->failed = true;
			(void)taskqueue_enqueue(taskqueue_thread,
			    &sc->fail_task);
			continue;
		}
		if (vtinput_enqueue_event(sc, slot) != 0) {
			device_printf(sc->dev,
			    "cannot replenish event queue\n");
			sc->failed = true;
			(void)taskqueue_enqueue(taskqueue_thread,
			    &sc->fail_task);
		}
	}
	if (!sc->detaching && !sc->failed) {
		virtqueue_notify(sc->eventq);
		/*
		 * The MSIX filter (virtqueue_intr_filter) disabled this
		 * interrupt before scheduling us; re-arm it, and drain any
		 * completion that raced the re-enable.
		 */
		if (virtqueue_enable_intr(sc->eventq) != 0) {
			virtqueue_disable_intr(sc->eventq);
			goto again;
		}
	}
	mtx_unlock(&sc->mtx);
}

static void
vtinput_statusq_intr(void *xsc)
{
	struct vtinput_softc *sc;
	struct vtinput_status_slot *slot;
	uint32_t len;

	sc = xsc;
	mtx_lock(&sc->mtx);
again:
	while ((slot = virtqueue_dequeue(sc->statusq, &len)) != NULL) {
		slot->in_use = false;
		if (!sc->detaching && !sc->failed && len != 0) {
			device_printf(sc->dev,
			    "device returned status with invalid length %u\n",
			    len);
			sc->failed = true;
			(void)taskqueue_enqueue(taskqueue_thread,
			    &sc->fail_task);
		}
	}
	if (!sc->detaching && !sc->failed) {
		/* See vtinput_eventq_intr: re-arm the filtered interrupt. */
		if (virtqueue_enable_intr(sc->statusq) != 0) {
			virtqueue_disable_intr(sc->statusq);
			goto again;
		}
	}
	mtx_unlock(&sc->mtx);
}

static void
vtinput_ev_event(struct evdev_dev *evdev, uint16_t type, uint16_t code,
    int32_t value)
{
	struct vtinput_softc *sc;
	struct vtinput_status_slot *slot;
	u_int i;

	sc = evdev_get_softc(evdev);
	mtx_lock(&sc->mtx);
	if (sc->detaching || sc->failed)
		goto out;
	/*
	 * Multitouch providers may attach MSC_TIMESTAMP to every frame.
	 * Sending it back through the status queue causes the host evdev
	 * provider to emit another timestamp and grows each frame forever.
	 */
	if (sc->multitouch && type == EV_MSC && code == MSC_TIMESTAMP)
		goto out;
	slot = NULL;
	for (i = 0; i < nitems(sc->status_slots); i++) {
		if (!sc->status_slots[i].in_use) {
			slot = &sc->status_slots[i];
			break;
		}
	}
	if (slot == NULL)
		goto out;
	slot->event.type = htole16(type);
	slot->event.code = htole16(code);
	slot->event.value = htole32((uint32_t)value);
	slot->in_use = true;
	if (vtinput_enqueue_status(sc, slot) != 0)
		slot->in_use = false;
	else
		virtqueue_notify(sc->statusq);
out:
	mtx_unlock(&sc->mtx);
}

static int
vtinput_detach(device_t dev)
{
	struct vtinput_softc *sc;
	int last;

	sc = device_get_softc(dev);
	if (sc->mtx_initialized) {
		mtx_lock(&sc->mtx);
		sc->detaching = true;
		mtx_unlock(&sc->mtx);
	}
	if (sc->evdev != NULL) {
		evdev_free(sc->evdev);
		sc->evdev = NULL;
	}
	if (sc->fail_task_initialized) {
		taskqueue_drain(taskqueue_thread, &sc->fail_task);
		sc->fail_task_initialized = false;
	}
	if (sc->mtx_initialized)
		mtx_lock(&sc->mtx);
	if (sc->eventq != NULL || sc->statusq != NULL)
		virtio_stop(dev);
	if (sc->mtx_initialized)
		mtx_unlock(&sc->mtx);

	/*
	 * Tear down the interrupt handlers before invalidating the virtqueue
	 * pointers they dereference.  vtinput_eventq_intr()/vtinput_statusq_intr()
	 * call virtqueue_dequeue(sc->eventq/statusq) unconditionally; a device
	 * interrupt latched just before detach can have its ithread blocked on the
	 * softc mutex, so NULLing the queues (or freeing the ring) while that
	 * handler is still live would fault it.  After teardown_intr() no handler
	 * can run, so the drain below needs no lock.
	 */
	virtio_teardown_intr(dev);

	if (sc->eventq != NULL) {
		last = 0;
		while (virtqueue_drain(sc->eventq, &last) != NULL)
			;
		sc->eventq = NULL;
	}
	if (sc->statusq != NULL) {
		last = 0;
		while (virtqueue_drain(sc->statusq, &last) != NULL)
			;
		sc->statusq = NULL;
	}
	if (sc->mtx_initialized) {
		mtx_destroy(&sc->mtx);
		sc->mtx_initialized = false;
	}
	return (0);
}
