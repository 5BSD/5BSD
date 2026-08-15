/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 Beckhoff Automation GmbH & Co. KG
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
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

/*
 * virtio input device emulation.
 */

#include <sys/param.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>

#include <capsicum_helpers.h>
#endif
#include <sys/ioctl.h>
#include <sys/linker_set.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <dev/evdev/input.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "mevent.h"
#include "pci_emul.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif
#include "virtio.h"

#define VTINPUT_RINGSZ 64
#define VTINPUT_HOST_EVENT_BUDGET VTINPUT_RINGSZ

#define VTINPUT_MAX_PKT_LEN 10
#define VTINPUT_MAX_FRAME_EVENTS 4096

/*
 * Queue definitions.
 */
#define VTINPUT_EVENTQ 0
#define VTINPUT_STATUSQ 1

#define VTINPUT_MAXQ 2

static int pci_vtinput_debug;
#define DPRINTF(params)						\
	do {							\
		if (pci_vtinput_debug) {				\
			EPRINTLN params;				\
			fflush(stderr);				\
		}						\
	} while (0)
#define DPRINTF2(params)					\
	do {							\
		if (pci_vtinput_debug >= 2) {			\
			EPRINTLN params;				\
			fflush(stderr);				\
		}						\
	} while (0)
#define WPRINTF(params) PRINTLN params

enum vtinput_config_select {
	VTINPUT_CFG_UNSET = 0x00,
	VTINPUT_CFG_ID_NAME = 0x01,
	VTINPUT_CFG_ID_SERIAL = 0x02,
	VTINPUT_CFG_ID_DEVIDS = 0x03,
	VTINPUT_CFG_PROP_BITS = 0x10,
	VTINPUT_CFG_EV_BITS = 0x11,
	VTINPUT_CFG_ABS_INFO = 0x12
};

struct vtinput_absinfo {
	uint32_t min;
	uint32_t max;
	uint32_t fuzz;
	uint32_t flat;
	uint32_t res;
} __packed;

struct vtinput_devids {
	uint16_t bustype;
	uint16_t vendor;
	uint16_t product;
	uint16_t version;
} __packed;

struct vtinput_config {
	uint8_t select;
	uint8_t subsel;
	uint8_t size;
	uint8_t reserved[5];
	union {
		char string[128];
		uint8_t bitmap[128];
		struct vtinput_absinfo abs;
		struct vtinput_devids ids;
	} u;
} __packed;

struct vtinput_event {
	uint16_t type;
	uint16_t code;
	uint32_t value;
} __packed;

struct vtinput_event_elem {
	struct vtinput_event event;
	struct vi_req req;
};

struct vtinput_eventqueue {
	struct vtinput_event_elem *events;
	uint32_t size;
	uint32_t idx;
};

/*
 * Per-device softc
 */
struct pci_vtinput_softc {
	struct virtio_softc vsc_vs;
	struct virtio_consts vsc_consts;
	struct vqueue_info vsc_queues[VTINPUT_MAXQ];
	pthread_mutex_t vsc_mtx;
	bool vsc_mtx_initialized;
	char *vsc_evdev;
	dev_t vsc_evdev_rdev;
	int vsc_fd;
	struct vtinput_config vsc_config;
	int vsc_config_valid;
	struct mevent *vsc_evp;
	struct vtinput_eventqueue vsc_eventqueue;
	bool vsc_drop_frame;
	bool vsc_resync_frame;
	bool vsc_discard_host_events;
#ifdef BHYVE_SNAPSHOT
	/* Private mutex ownership retained by a successful checkpoint pause. */
	bool vsc_checkpoint_lock_held;
#endif
};

static void pci_vtinput_reset(void *);
static int pci_vtinput_qreset(void *, struct vqueue_info *, uint64_t);
static int pci_vtinput_cfgread(void *, int, int, uint32_t *);
static int pci_vtinput_cfgwrite(void *, int, int, uint32_t);
static int pci_vtinput_suspend_device(void *);
static int pci_vtinput_resume_device(void *);
static void vtinput_eventqueue_clear(struct vtinput_eventqueue *);
static bool vtinput_eventqueue_frame_complete(
    const struct vtinput_eventqueue *);
static bool vtinput_eventqueue_send_events(struct vtinput_eventqueue *,
    struct vqueue_info *);
static bool vtinput_drain_host_events(struct pci_vtinput_softc *);
#ifdef BHYVE_SNAPSHOT
static int pci_vtinput_pause(void *);
static int pci_vtinput_resume(void *);
static int pci_vtinput_snapshot(void *, struct vm_snapshot_meta *);
static int pci_vtinput_snapshot_validate(struct vm_snapshot_meta *);
#endif

static struct virtio_consts vtinput_vi_consts = {
	.vc_name =	"vtinput",
	.vc_nvq =	VTINPUT_MAXQ,
	.vc_cfgsize =	sizeof(struct vtinput_config),
	.vc_reset =	pci_vtinput_reset,
	.vc_cfgread =	pci_vtinput_cfgread,
	.vc_cfgwrite =	pci_vtinput_cfgwrite,
	.vc_qreset =	pci_vtinput_qreset,
	.vc_suspend =	pci_vtinput_suspend_device,
	.vc_resume_device = pci_vtinput_resume_device,
	.vc_hv_caps =	VIRTIO_F_IN_ORDER | VIRTIO_F_RING_RESET |
	    VIRTIO_F_SUSPEND,
#ifdef BHYVE_SNAPSHOT
	.vc_pause =	pci_vtinput_pause,
	.vc_resume =	pci_vtinput_resume,
	.vc_snapshot =	pci_vtinput_snapshot,
#endif
};

static int
pci_vtinput_suspend_device(void *vsc)
{
	struct pci_vtinput_softc *sc;

	sc = vsc;
	/*
	 * An input frame is atomic at SYN_REPORT.  The common suspend fence
	 * prevents new guest descriptors from being consumed, but a partial
	 * host frame staged before that fence is not an architectural device
	 * result and must not be joined to input received after resume.
	 *
	 * The evdev callback takes the same device mutex.  Once this callback
	 * returns it can still drain the nonblocking host fd while suspended,
	 * but vq_ring_ready() keeps it from staging or publishing guest data.
	 */
	vtinput_eventqueue_clear(&sc->vsc_eventqueue);
	sc->vsc_drop_frame = false;
	sc->vsc_resync_frame = false;
	return (0);
}

static int
pci_vtinput_resume_device(void *vsc __unused)
{

	return (0);
}

static bool
vtinput_drain_host_events(struct pci_vtinput_softc *sc)
{
	struct input_event event;
	unsigned int budget;
	ssize_t len;

	/*
	 * The descriptor is nonblocking.  Drain input that belongs to the old
	 * queue incarnation while reset still holds the VirtIO mutex; otherwise
	 * a quick guest re-enable can let a later mevent callback deliver
	 * pre-reset host events through the replacement queue.
	 */
	if (sc->vsc_evp == NULL || sc->vsc_fd < 0)
		return (true);
	budget = VTINPUT_HOST_EVENT_BUDGET;
	while (budget-- != 0) {
		len = read(sc->vsc_fd, &event, sizeof(event));
		if (len != sizeof(event))
			break;
	}
	if (len == sizeof(event))
		return (false);
	if (len < 0 && errno != EAGAIN)
		WPRINTF(("%s: event drain failed: %s", __func__,
		    strerror(errno)));
	else if (len > 0)
		WPRINTF(("%s: short event during drain: %zd", __func__, len));
	return (true);
}

static void
pci_vtinput_reset(void *vsc)
{
	struct pci_vtinput_softc *sc = vsc;

	DPRINTF(("%s: device reset requested", __func__));
	vi_reset_dev(&sc->vsc_vs);
	sc->vsc_eventqueue.idx = 0;
	sc->vsc_drop_frame = false;
	sc->vsc_resync_frame = false;
	sc->vsc_discard_host_events = !vtinput_drain_host_events(sc);
	memset(&sc->vsc_config, 0, sizeof(sc->vsc_config));
	sc->vsc_config_valid = 0;
}

static int
pci_vtinput_qreset(void *vsc, struct vqueue_info *vq,
    uint64_t generation __unused)
{
	struct pci_vtinput_softc *sc;

	sc = vsc;
	if (vq->vq_num >= VTINPUT_MAXQ)
		return (EINVAL);

	/*
	 * Host events are staged outside guest memory until a complete input
	 * frame is available.  Discard an incomplete frame when the event queue
	 * is reset so it cannot be delivered through a later queue incarnation.
	 * Status-queue operations complete synchronously while vsc_mtx is held.
	 */
	if (vq->vq_num == VTINPUT_EVENTQ) {
		sc->vsc_eventqueue.idx = 0;
		sc->vsc_drop_frame = false;
		sc->vsc_resync_frame = false;
		sc->vsc_discard_host_events = !vtinput_drain_host_events(sc);
	}
	return (0);
}

static void
pci_vtinput_notify_eventq(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtinput_softc *sc;

	DPRINTF(("%s", __func__));
	sc = vsc;
	/*
	 * A complete host frame can be retained when the guest temporarily has
	 * too few writable descriptors.  The guest's next queue kick is the only
	 * guaranteed wakeup in that state, so retry it here rather than waiting
	 * for unrelated host input.
	 */
	if (vtinput_eventqueue_frame_complete(&sc->vsc_eventqueue))
		(void)vtinput_eventqueue_send_events(&sc->vsc_eventqueue, vq);
}

static bool
vtinput_iov_has_exact_size(const struct iovec *iov, int niov, size_t wanted)
{
	size_t total;

	total = 0;
	for (int i = 0; i < niov; i++) {
		if (iov[i].iov_len > SIZE_MAX - total)
			return (false);
		total += iov[i].iov_len;
	}
	return (total == wanted);
}

static void
pci_vtinput_notify_statusq(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtinput_softc *sc = vsc;
	struct iovec iov[VTINPUT_RINGSZ];
	uint32_t completed;
	uint16_t budget;

	completed = 0;
	DPRINTF(("vtinput: status queue notify"));

	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
		/* get descriptor chain */
		struct vi_req req;
		const int n = vq_getchain(vq, iov, nitems(iov), &req);
		if (n <= 0) {
			WPRINTF(("%s: invalid descriptor: %d", __func__, n));
			break;
		}
		if (n > (int)nitems(iov) || req.readable != n ||
		    req.writable != 0) {
			WPRINTF(("%s: invalid status descriptor", __func__));
			vq_relchain_req(vq, &req, 0);
			continue;
		}
		if (!vtinput_iov_has_exact_size(iov, n,
		    sizeof(struct vtinput_event))) {
			WPRINTF(("%s: invalid status event length", __func__));
			vq_relchain_req(vq, &req, 0);
			continue;
		}

		/* get event */
		struct vtinput_event event;
		size_t copied = 0;
		for (int i = 0; i < n && copied < sizeof(event); i++) {
			size_t len;

			if (iov[i].iov_base == NULL && iov[i].iov_len != 0)
				break;
			len = MIN(iov[i].iov_len, sizeof(event) - copied);
			if (len != 0)
				memcpy((uint8_t *)&event + copied,
				    iov[i].iov_base, len);
			copied += len;
		}
		if (copied != sizeof(event)) {
			WPRINTF(("%s: short status event", __func__));
			vq_relchain_req(vq, &req, 0);
			continue;
		}
		const uint16_t type = le16toh(event.type);
		const uint16_t code = le16toh(event.code);
		const int32_t value = (int32_t)le32toh(event.value);

		DPRINTF2(("vtinput: status event type=%u code=%u value=%d",
		    type, code, value));

		/*
		 * on multi touch devices:
		 * - host send EV_MSC to guest
		 * - guest sends EV_MSC back to host
		 * - host writes EV_MSC to evdev
		 * - evdev saves EV_MSC in it's event buffer
		 * - host receives an extra EV_MSC by reading the evdev event
		 *   buffer
		 * - frames become larger and larger
		 * avoid endless loops by ignoring EV_MSC
		 */
		if (type == EV_MSC) {
			vq_relchain_req(vq, &req, 0);
			continue;
		}

		/* send event to evdev */
		struct input_event host_event;
		memset(&host_event, 0, sizeof(host_event));
		host_event.type = type;
		host_event.code = code;
		host_event.value = value;
		if (gettimeofday(&host_event.time, NULL) != 0) {
			WPRINTF(("%s: failed gettimeofday", __func__));
		}
		ssize_t nwritten = write(sc->vsc_fd, &host_event,
		    sizeof(host_event));
		if (nwritten != sizeof(host_event)) {
			if (nwritten < 0)
				WPRINTF(("%s: failed to write host_event: %s",
				    __func__, strerror(errno)));
			else
				WPRINTF(("%s: short host_event write: %zd",
				    __func__, nwritten));
		} else {
			DPRINTF2(("vtinput: wrote host status event type=%u "
			    "code=%u value=%d", host_event.type,
			    host_event.code, host_event.value));
		}

		vq_relchain_req(vq, &req, 0);
		completed++;
	}
	vq_endchains(vq, !vq_has_descs(vq));
	DPRINTF(("vtinput: status queue completed=%u", completed));
}

static int
pci_vtinput_get_bitmap(struct pci_vtinput_softc *sc, int cmd, int count)
{
	unsigned long native[howmany(sizeof(sc->vsc_config.u.bitmap),
	    sizeof(unsigned long))];
	const size_t word_bits = sizeof(unsigned long) * CHAR_BIT;
	size_t bit, bits;

	if (count <= 0 || sc == NULL ||
	    (size_t)count > sizeof(native)) {
		return (-1);
	}

	/*
	 * EVIOCGBIT and EVIOCGPROP expose a native unsigned-long bitmap.
	 * VirtIO exposes a byte bitmap where bit N is bit N % 8 of byte N / 8.
	 * Copying the ioctl buffer byte-for-byte therefore works accidentally
	 * only on little-endian hosts.  Translate bit numbers explicitly.
	 */
	memset(native, 0, sizeof(native));
	memset(sc->vsc_config.u.bitmap, 0, sizeof(sc->vsc_config.u.bitmap));
	if (ioctl(sc->vsc_fd, cmd, native) < 0) {
		return (-1);
	}
	bits = (size_t)count * CHAR_BIT;
	for (bit = 0; bit < bits; bit++) {
		if ((native[bit / word_bits] &
		    (1UL << (bit % word_bits))) != 0)
			sc->vsc_config.u.bitmap[bit / CHAR_BIT] |=
			    (uint8_t)(1U << (bit % CHAR_BIT));
	}

	/* get number of set bytes in bitmap */
	for (int i = count - 1; i >= 0; i--) {
		if (sc->vsc_config.u.bitmap[i]) {
			return i + 1;
		}
	}

	return (-1);
}

static int
pci_vtinput_read_config_id_name(struct pci_vtinput_softc *sc)
{
	char name[128];

	memset(name, 0, sizeof(name));
	if (ioctl(sc->vsc_fd, EVIOCGNAME(sizeof(name) - 1), name) < 0) {
		return (1);
	}

	sc->vsc_config.size = strnlen(name, sizeof(name));
	memcpy(sc->vsc_config.u.string, name, sc->vsc_config.size);

	return (0);
}

static int
pci_vtinput_read_config_id_serial(struct pci_vtinput_softc *sc)
{
	/* serial isn't supported */
	sc->vsc_config.size = 0;

	return (0);
}

static int
pci_vtinput_read_config_id_devids(struct pci_vtinput_softc *sc)
{
	struct input_id devids;
	if (ioctl(sc->vsc_fd, EVIOCGID, &devids)) {
		return (1);
	}

	sc->vsc_config.u.ids.bustype = htole16(devids.bustype);
	sc->vsc_config.u.ids.vendor = htole16(devids.vendor);
	sc->vsc_config.u.ids.product = htole16(devids.product);
	sc->vsc_config.u.ids.version = htole16(devids.version);
	sc->vsc_config.size = sizeof(struct vtinput_devids);

	return (0);
}

static int
pci_vtinput_read_config_prop_bits(struct pci_vtinput_softc *sc)
{
	/*
	 * Evdev bitmap countains 1 bit per count. Additionally evdev bitmaps
	 * are arrays of longs instead of chars. Calculate how many longs are
	 * required for evdev bitmap. Multiply that with sizeof(long) to get the
	 * number of elements.
	 */
	const int count = howmany(INPUT_PROP_CNT, sizeof(long) * 8) *
	    sizeof(long);
	const unsigned int cmd = EVIOCGPROP(count);
	const int size = pci_vtinput_get_bitmap(sc, cmd, count);
	if (size <= 0) {
		return (1);
	}

	sc->vsc_config.size = size;

	return (0);
}

static int
pci_vtinput_read_config_ev_bits(struct pci_vtinput_softc *sc, uint8_t type)
{
	int count;

	switch (type) {
	case EV_KEY:
		count = KEY_CNT;
		break;
	case EV_REL:
		count = REL_CNT;
		break;
	case EV_ABS:
		count = ABS_CNT;
		break;
	case EV_MSC:
		count = MSC_CNT;
		break;
	case EV_SW:
		count = SW_CNT;
		break;
	case EV_LED:
		count = LED_CNT;
		break;
	case EV_SND:
		count = SND_CNT;
		break;
	case EV_REP:
		count = REP_CNT;
		break;
	default:
		return (1);
	}

	/*
	 * Evdev bitmap countains 1 bit per count. Additionally evdev bitmaps
	 * are arrays of longs instead of chars. Calculate how many longs are
	 * required for evdev bitmap. Multiply that with sizeof(long) to get the
	 * number of elements.
	 */
	count = howmany(count, sizeof(long) * 8) * sizeof(long);
	const unsigned int cmd = EVIOCGBIT(type, count);
	const int size = pci_vtinput_get_bitmap(sc, cmd, count);
	if (size <= 0) {
		return (1);
	}

	sc->vsc_config.size = size;

	return (0);
}

static int
pci_vtinput_read_config_abs_info(struct pci_vtinput_softc *sc)
{
	/* get abs information */
	struct input_absinfo abs;
	if (ioctl(sc->vsc_fd, EVIOCGABS(sc->vsc_config.subsel), &abs) < 0) {
		return (1);
	}

	/* save abs information */
	sc->vsc_config.u.abs.min = htole32(abs.minimum);
	sc->vsc_config.u.abs.max = htole32(abs.maximum);
	sc->vsc_config.u.abs.fuzz = htole32(abs.fuzz);
	sc->vsc_config.u.abs.flat = htole32(abs.flat);
	sc->vsc_config.u.abs.res = htole32(abs.resolution);
	sc->vsc_config.size = sizeof(struct vtinput_absinfo);

	return (0);
}

static int
pci_vtinput_read_config(struct pci_vtinput_softc *sc)
{
	/*
	 * select and subsel are driver-owned.  Every other byte is a fresh
	 * device response so an unsupported query cannot expose data from a
	 * previous selection or uninitialized host memory.
	 */
	sc->vsc_config.size = 0;
	memset(sc->vsc_config.reserved, 0, sizeof(sc->vsc_config.reserved));
	memset(&sc->vsc_config.u, 0, sizeof(sc->vsc_config.u));

	switch (sc->vsc_config.select) {
	case VTINPUT_CFG_UNSET:
		return (0);
	case VTINPUT_CFG_ID_NAME:
		return pci_vtinput_read_config_id_name(sc);
	case VTINPUT_CFG_ID_SERIAL:
		return pci_vtinput_read_config_id_serial(sc);
	case VTINPUT_CFG_ID_DEVIDS:
		return pci_vtinput_read_config_id_devids(sc);
	case VTINPUT_CFG_PROP_BITS:
		return pci_vtinput_read_config_prop_bits(sc);
	case VTINPUT_CFG_EV_BITS:
		return pci_vtinput_read_config_ev_bits(
		    sc, sc->vsc_config.subsel);
	case VTINPUT_CFG_ABS_INFO:
		return pci_vtinput_read_config_abs_info(sc);
	default:
		return (1);
	}
}

static int
pci_vtinput_cfgread(void *vsc, int offset, int size, uint32_t *retval)
{
	struct pci_vtinput_softc *sc = vsc;

	if (retval == NULL)
		return (EINVAL);
	*retval = 0;

	/* check for valid offset and size */
	if (offset < 0 || (size != 1 && size != 2 && size != 4) ||
	    (size_t)offset > sizeof(struct vtinput_config) - (size_t)size) {
		WPRINTF(("%s: read to invalid offset/size %d/%d", __func__,
		    offset, size));
		return (0);
	}

	/* read new config values, if select and subsel changed. */
	if (!sc->vsc_config_valid) {
		if (pci_vtinput_read_config(sc) != 0) {
			DPRINTF(("%s: could not read config %d/%d", __func__,
			    sc->vsc_config.select, sc->vsc_config.subsel));
		}
		sc->vsc_config_valid = 1;
	}

	return (vi_config_read_le(&sc->vsc_config, sizeof(sc->vsc_config),
	    offset, size, retval));
}

static int
pci_vtinput_cfgwrite(void *vsc, int offset, int size, uint32_t value)
{
	struct pci_vtinput_softc *sc = vsc;

	/* guest can only write to select and subsel fields */
	if (offset < 0 || (size != 1 && size != 2) ||
	    (size_t)offset > 2 - (size_t)size) {
		WPRINTF(("%s: write to readonly reg %d", __func__, offset));
		return (1);
	}

	/*
	 * The transport passes a host numeric value.  Device configuration is
	 * little-endian, so assign bytes explicitly rather than copying the
	 * host representation.
	 */
	uint8_t *ptr = (uint8_t *)&sc->vsc_config;
	for (int i = 0; i < size; i++)
		ptr[offset + i] = value >> (i * 8);

	/* select/subsel changed, query new config on next cfgread */
	sc->vsc_config_valid = 0;

	return (0);
}

static int
vtinput_eventqueue_add_event(
    struct vtinput_eventqueue *queue, struct input_event *e)
{
	/* check if queue is full */
	if (queue->idx >= queue->size) {
		/* alloc new elements for queue */
		if (queue->size >= VTINPUT_MAX_FRAME_EVENTS) {
			WPRINTF(("%s: input frame exceeds %u events", __func__,
			    VTINPUT_MAX_FRAME_EVENTS));
			return (1);
		}
		const uint32_t newSize = queue->size == 0 ?
		    VTINPUT_MAX_PKT_LEN :
		    MIN(queue->size * 2, VTINPUT_MAX_FRAME_EVENTS);
		void *newPtr = realloc(queue->events,
		    newSize * sizeof(struct vtinput_event_elem));
		if (newPtr == NULL) {
			WPRINTF(("%s: realloc memory for eventqueue failed!",
			    __func__));
			return (1);
		}
		queue->events = newPtr;
		queue->size = newSize;
	}

	/* save event */
	struct vtinput_event *event = &queue->events[queue->idx].event;
	event->type = htole16(e->type);
	event->code = htole16(e->code);
	event->value = htole32(e->value);
	queue->idx++;

	return (0);
}

static void
vtinput_eventqueue_clear(struct vtinput_eventqueue *queue)
{
	/* just reset index to clear queue */
	queue->idx = 0;
}

static bool
vtinput_eventqueue_frame_complete(const struct vtinput_eventqueue *queue)
{
	const struct vtinput_event *event;

	if (queue == NULL || queue->idx == 0 || queue->events == NULL)
		return (false);
	event = &queue->events[queue->idx - 1].event;
	return (le16toh(event->type) == EV_SYN &&
	    le16toh(event->code) == SYN_REPORT);
}

static void
vtinput_eventqueue_drop_events(struct vtinput_eventqueue *queue,
    struct vqueue_info *vq, uint32_t count)
{

	for (uint32_t i = 0; i < count; i++)
		vq_relchain_req(vq, &queue->events[i].req, 0);
}

static bool
vtinput_eventqueue_send_events(
    struct vtinput_eventqueue *queue, struct vqueue_info *vq)
{
	struct iovec iov[VTINPUT_RINGSZ];
	bool consumed;

	consumed = true;

	/*
	 * First iteration through eventqueue:
	 *   Get descriptor chains.
	 */
	for (uint32_t i = 0; i < queue->idx; ++i) {
		/* get descriptor */
		if (!vq_has_descs(vq)) {
			/*
			 * We don't have enough descriptors for the complete frame.
			 * Return chains to the guest in reverse acquisition order, but
			 * retain the host frame.  Its queue kick will retry delivery.
			 */
			while (i != 0) {
				i--;
				vq_retchain_req(vq, &queue->events[i].req);
			}
			DPRINTF(("%s: waiting for descriptors for %u events",
			    __func__, queue->idx));
			consumed = false;
			goto done;
		}

		/* get descriptor chain */
		struct vi_req req;
		const int n = vq_getchain(vq, iov, nitems(iov), &req);
		if (n <= 0) {
			WPRINTF(("%s: invalid descriptor: %d", __func__, n));
			vtinput_eventqueue_drop_events(queue, vq, i);
			goto done;
		}
		if (n > (int)nitems(iov)) {
			WPRINTF(
			    ("%s: invalid number of descriptors in chain: %d",
				__func__, n));
			/* Drop the frame in available-ring order. */
			vtinput_eventqueue_drop_events(queue, vq, i);
			vq_relchain_req(vq, &req, 0);
			goto done;
		}
		if (req.readable != 0 || req.writable != n) {
			WPRINTF(("%s: invalid event descriptor", __func__));
			/* Drop the frame in available-ring order. */
			vtinput_eventqueue_drop_events(queue, vq, i);
			vq_relchain_req(vq, &req, 0);
			goto done;
		}

		/* Fill the buffer, but publish it only after the entire frame fits. */
		size_t copied = 0;
		for (int j = 0; j < n && copied < sizeof(struct vtinput_event);
		    j++) {
			size_t len;

			if (iov[j].iov_base == NULL && iov[j].iov_len != 0)
				break;
			len = MIN(iov[j].iov_len,
			    sizeof(struct vtinput_event) - copied);
			if (len != 0)
				memcpy(iov[j].iov_base,
				    (uint8_t *)&queue->events[i].event + copied,
				    len);
			copied += len;
		}
		if (copied != sizeof(struct vtinput_event)) {
			WPRINTF(("%s: short event buffer", __func__));
			vtinput_eventqueue_drop_events(queue, vq, i);
			vq_relchain_req(vq, &req, 0);
			goto done;
		}
		queue->events[i].req = req;
	}

	/*
	 * Second iteration through eventqueue:
	 *   Send events to guest by releasing chains
	 */
	for (uint32_t i = 0; i < queue->idx; ++i) {
		vq_relchain_req(vq, &queue->events[i].req,
		    sizeof(struct vtinput_event));
	}
done:
	if (consumed) {
		/* Clear a delivered or malformed frame and publish completions. */
		vtinput_eventqueue_clear(queue);
		vq_endchains(vq, !vq_has_descs(vq));
	}
	return (consumed);
}

static int
vtinput_read_event_from_host(int fd, struct input_event *event)
{
	const int len = read(fd, event, sizeof(struct input_event));
	if (len != sizeof(struct input_event)) {
		if (len == -1 && errno != EAGAIN) {
			WPRINTF(("%s: event read failed! len = %d, errno = %d",
			    __func__, len, errno));
		}

		/* host doesn't have more events for us */
		return (1);
	}

	return (0);
}

static bool
vtinput_eventqueue_report_loss(struct vtinput_eventqueue *queue,
    struct vqueue_info *vq)
{
	struct input_event marker;

	/*
	 * Dropping a locally oversized frame is indistinguishable to the guest
	 * from an evdev client overrun: some input state transitions are
	 * missing.  Emit the standard resynchronization frame instead of
	 * silently leaving guest key or axis state stale.  Clearing the queue
	 * first guarantees that the two fixed events fit in the normal
	 * preallocated buffer; allocation failure remains safely bounded.
	 */
	vtinput_eventqueue_clear(queue);
	memset(&marker, 0, sizeof(marker));
	marker.type = EV_SYN;
	marker.code = SYN_DROPPED;
	if (vtinput_eventqueue_add_event(queue, &marker) != 0)
		goto fail;
	marker.code = SYN_REPORT;
	if (vtinput_eventqueue_add_event(queue, &marker) != 0)
		goto fail;
	return (vtinput_eventqueue_send_events(queue, vq));

fail:
	vtinput_eventqueue_clear(queue);
	return (true);
}

static void
vtinput_read_event(int fd __attribute((unused)),
    enum ev_type t __attribute__((unused)), void *arg __attribute__((unused)))
{
	struct pci_vtinput_softc *sc = arg;
	struct virtio_softc *vs = &sc->vsc_vs;
	struct vqueue_info *event_vq;
	unsigned int budget;

	VS_LOCK(vs);
	event_vq = &sc->vsc_queues[VTINPUT_EVENTQ];
	if (sc->vsc_discard_host_events) {
		sc->vsc_discard_host_events = !vtinput_drain_host_events(sc);
		VS_UNLOCK(vs);
		return;
	}

	/* Skip if the device or its independently-resettable event queue is idle. */
	if (!(sc->vsc_vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) ||
	    !vq_ring_ready(event_vq)) {
		/*
		 * Keep the nonblocking evdev descriptor drained while the queue is
		 * inactive.  Otherwise the persistent read event can spin the event
		 * loop and stale input can cross a guest device or queue reset.
		 */
		struct input_event event;
		budget = VTINPUT_HOST_EVENT_BUDGET;
		while (budget-- != 0 &&
		    vtinput_read_event_from_host(sc->vsc_fd, &event) == 0)
			;
		VS_UNLOCK(vs);
		return;
	}
	/* Do not append a new host frame behind one waiting on guest buffers. */
	if (vtinput_eventqueue_frame_complete(&sc->vsc_eventqueue) &&
	    !vtinput_eventqueue_send_events(&sc->vsc_eventqueue, event_vq)) {
		VS_UNLOCK(vs);
		return;
	}

	/* Read one guest-ring-sized batch from the level-triggered host source. */
	struct input_event event;
	budget = VTINPUT_HOST_EVENT_BUDGET;
	while (budget-- != 0 &&
	    vtinput_read_event_from_host(sc->vsc_fd, &event) == 0) {
		/*
		 * evdev inserts SYN_DROPPED when its client queue overruns.
		 * Everything already staged, and every event up to the following
		 * SYN_REPORT, describes state which can no longer be trusted.
		 * Preserve only the loss marker and its terminating SYN_REPORT so
		 * the guest evdev client is told to query current device state.
		 */
		if (event.type == EV_SYN && event.code == SYN_DROPPED) {
			vtinput_eventqueue_clear(&sc->vsc_eventqueue);
			sc->vsc_drop_frame = false;
			sc->vsc_resync_frame = true;
			if (vtinput_eventqueue_add_event(&sc->vsc_eventqueue,
			    &event) != 0)
				sc->vsc_drop_frame = true;
			continue;
		}
		if (sc->vsc_resync_frame &&
		    (event.type != EV_SYN || event.code != SYN_REPORT))
			continue;

		/*
		 * A frame larger than the negotiated guest ring can never be
		 * published atomically.  Stop retaining it at that boundary and
		 * report SYN_DROPPED at its terminator instead of letting a frame
		 * assembled across readiness callbacks drive an oversized descriptor
		 * acquisition loop.
		 */
		if (!sc->vsc_drop_frame &&
		    sc->vsc_eventqueue.idx >= event_vq->vq_qsize)
			sc->vsc_drop_frame = true;

		/* add trustworthy events to our queue */
		if (!sc->vsc_drop_frame &&
		    vtinput_eventqueue_add_event(&sc->vsc_eventqueue, &event) != 0)
			sc->vsc_drop_frame = true;
		else if (!sc->vsc_drop_frame &&
		    (event.type != EV_SYN || event.code != SYN_REPORT))
			DPRINTF(("vtinput: staged event type=%u code=%u value=%d "
			    "count=%u", event.type, event.code, event.value,
			    sc->vsc_eventqueue.idx));

		/* only send events to guest on EV_SYN or SYN_REPORT */
		if (event.type != EV_SYN || event.code != SYN_REPORT) {
			continue;
		}
		if (sc->vsc_drop_frame) {
			sc->vsc_drop_frame = false;
			sc->vsc_resync_frame = false;
			if (!vtinput_eventqueue_report_loss(&sc->vsc_eventqueue,
			    event_vq))
				break;
			continue;
		}

		/* send host events to guest */
		if (!vtinput_eventqueue_send_events(&sc->vsc_eventqueue,
		    event_vq)) {
			sc->vsc_resync_frame = false;
			break;
		}
		sc->vsc_resync_frame = false;
	}
	/* VIRTIO_ACTIVATION_ASSERTION: staged-frame-checkpoint-restore */
	/* VIRTIO_ACTIVATION_ASSERTION: synchronous-event-and-status-completion */

	VS_UNLOCK(vs);
}

#ifdef BHYVE_SNAPSHOT
#define	VTINPUT_SNAPSHOT_MAGIC		0x31504e49U	/* "INP1" on disk */
#define	VTINPUT_SNAPSHOT_VERSION	2U
#define	VTINPUT_SNAPSHOT_STRING_MAX	(1024U * 1024U)

static bool
pci_vtinput_snapshot_config_valid(const struct vtinput_config *config)
{

	if (config->size > sizeof(config->u))
		return (false);
	for (size_t i = 0; i < nitems(config->reserved); i++) {
		if (config->reserved[i] != 0)
			return (false);
	}
	/*
	 * Every live configuration query starts from a zeroed response.  Keep
	 * checkpoint restore inside that production state space: bytes beyond
	 * the advertised payload remain guest-readable even though they carry no
	 * selector-specific value.
	 */
	for (size_t i = config->size; i < sizeof(config->u.bitmap); i++) {
		if (config->u.bitmap[i] != 0)
			return (false);
	}
	return (true);
}

static int
pci_vtinput_pause(void *vsc)
{
	struct pci_vtinput_softc *sc;
	int error;

	sc = vsc;
	if (sc->vsc_checkpoint_lock_held)
		return (EBUSY);
	error = mevent_disable(sc->vsc_evp);
	if (error != 0)
		return (error);
	pthread_mutex_lock(&sc->vsc_mtx);
	sc->vsc_checkpoint_lock_held = true;
	return (0);
}

static int
pci_vtinput_resume(void *vsc)
{
	struct pci_vtinput_softc *sc;
	int error;

	sc = vsc;
	/*
	 * vi_pci_resume() retains common checkpoint ownership after an error and
	 * can retry without a fresh pause.  Do not retain this private mutex
	 * across that return: reset, detach, and a retry need a well-defined
	 * reacquisition point rather than an implicit same-thread assumption.
	 */
	if (!sc->vsc_checkpoint_lock_held) {
		pthread_mutex_lock(&sc->vsc_mtx);
		sc->vsc_checkpoint_lock_held = true;
	}
	error = mevent_enable(sc->vsc_evp);
	sc->vsc_checkpoint_lock_held = false;
	pthread_mutex_unlock(&sc->vsc_mtx);
	return (error);
}

static int
pci_vtinput_snapshot(void *vsc, struct vm_snapshot_meta *meta)
{
	struct pci_vtinput_softc *sc;
	struct vtinput_event_elem *events;
	struct vtinput_config config;
	uint64_t rdev;
	uint32_t count, magic, version;
	uint16_t code, type;
	uint8_t config_valid, drop_frame, resync_frame;
	uint32_t value;
	int error;

	sc = vsc;
	if (meta->op == VM_SNAPSHOT_SAVE &&
	    (sc->vsc_eventqueue.idx > sc->vsc_eventqueue.size ||
	    (sc->vsc_eventqueue.idx != 0 &&
	    sc->vsc_eventqueue.events == NULL)))
		return (EINVAL);
	magic = VTINPUT_SNAPSHOT_MAGIC;
	version = VTINPUT_SNAPSHOT_VERSION;
	rdev = (uint64_t)sc->vsc_evdev_rdev;
	config = sc->vsc_config;
	config_valid = sc->vsc_config_valid != 0;
	drop_frame = sc->vsc_drop_frame;
	resync_frame = sc->vsc_resync_frame;
	count = sc->vsc_eventqueue.idx;
	events = NULL;

	SNAPSHOT_LE32_OR_LEAVE(magic, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(version, meta, error, done);
	if (magic != VTINPUT_SNAPSHOT_MAGIC ||
	    version != VTINPUT_SNAPSHOT_VERSION) {
		error = ENOTSUP;
		goto done;
	}
	SNAPSHOT_LE64_OR_LEAVE(rdev, meta, error, done);
	SNAPSHOT_U8_OR_LEAVE(config_valid, meta, error, done);
	SNAPSHOT_U8_OR_LEAVE(drop_frame, meta, error, done);
	SNAPSHOT_U8_OR_LEAVE(resync_frame, meta, error, done);
	SNAPSHOT_U8_OR_LEAVE(config.select, meta, error, done);
	SNAPSHOT_U8_OR_LEAVE(config.subsel, meta, error, done);
	SNAPSHOT_U8_OR_LEAVE(config.size, meta, error, done);
	SNAPSHOT_BUF_OR_LEAVE(config.reserved, sizeof(config.reserved),
	    meta, error, done);
	SNAPSHOT_BUF_OR_LEAVE(&config.u, sizeof(config.u), meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(count, meta, error, done);
	if (config_valid > 1 || drop_frame > 1 || resync_frame > 1 ||
	    !pci_vtinput_snapshot_config_valid(&config) ||
	    count > VTINPUT_MAX_FRAME_EVENTS ||
	    count > sc->vsc_queues[VTINPUT_EVENTQ].vq_qsize) {
		error = EINVAL;
		goto done;
	}
	if (vm_snapshot_is_loading(meta) && count != 0) {
		events = calloc(count, sizeof(*events));
		if (events == NULL) {
			error = ENOMEM;
			goto done;
		}
	}
	for (uint32_t i = 0; i < count; i++) {
		if (meta->op == VM_SNAPSHOT_SAVE) {
			type = le16toh(sc->vsc_eventqueue.events[i].event.type);
			code = le16toh(sc->vsc_eventqueue.events[i].event.code);
			value = le32toh(sc->vsc_eventqueue.events[i].event.value);
		} else {
			type = 0;
			code = 0;
			value = 0;
		}
		SNAPSHOT_LE16_OR_LEAVE(type, meta, error, done);
		SNAPSHOT_LE16_OR_LEAVE(code, meta, error, done);
		SNAPSHOT_LE32_OR_LEAVE(value, meta, error, done);
		if (vm_snapshot_is_loading(meta)) {
			events[i].event.type = htole16(type);
			events[i].event.code = htole16(code);
			events[i].event.value = htole32(value);
		}
	}
	/*
	 * A resynchronization frame is either a staged SYN_DROPPED marker, or
	 * empty only because allocation failed and the whole frame is already
	 * marked for discard.  Reject impossible combinations before publishing
	 * restored state.
	 */
	if (resync_frame != 0 &&
	    !((count == 0 && drop_frame != 0) ||
	    (count == 1 &&
	    (meta->op == VM_SNAPSHOT_SAVE ?
	    le16toh(sc->vsc_eventqueue.events[0].event.type) :
	    le16toh(events[0].event.type)) == EV_SYN &&
	    (meta->op == VM_SNAPSHOT_SAVE ?
	    le16toh(sc->vsc_eventqueue.events[0].event.code) :
	    le16toh(events[0].event.code)) == SYN_DROPPED))) {
		error = EINVAL;
		goto done;
	}
	error = vm_snapshot_identity_string(sc->vsc_evdev,
	    VTINPUT_SNAPSHOT_STRING_MAX, meta);
	if (error != 0)
		goto done;
	if (vm_snapshot_is_loading(meta) &&
	    rdev != (uint64_t)sc->vsc_evdev_rdev) {
		error = EINVAL;
		goto done;
	}
	if (meta->op == VM_SNAPSHOT_RESTORE) {
		if (count > sc->vsc_eventqueue.size ||
		    sc->vsc_eventqueue.events == NULL) {
			free(sc->vsc_eventqueue.events);
			sc->vsc_eventqueue.events = events;
			sc->vsc_eventqueue.size = count;
			events = NULL;
		} else if (count != 0) {
			memcpy(sc->vsc_eventqueue.events, events,
			    count * sizeof(*events));
		}
		sc->vsc_eventqueue.idx = count;
		sc->vsc_config = config;
		sc->vsc_config_valid = config_valid;
		sc->vsc_drop_frame = drop_frame;
		sc->vsc_resync_frame = resync_frame;
	}
	error = 0;
done:
	free(events);
	return (error);
}

/*
 * Input preflight reads the staged host-event frame and selector cache.  The
 * event callback uses vsc_mtx too, so direct validation needs that boundary.
 * This mutex is recursive by construction, making it safe to compose with
 * checkpoint pause, which already retains it.
 */
static int
pci_vtinput_snapshot_validate(struct vm_snapshot_meta *meta)
{
	struct pci_devinst *pi;
	struct pci_vtinput_softc *sc;
	int error;

	if (meta == NULL || meta->op != VM_SNAPSHOT_VALIDATE ||
	    meta->dev_data == NULL)
		return (EINVAL);
	pi = meta->dev_data;
	sc = pi->pi_arg;
	if (sc == NULL)
		return (EINVAL);

	pthread_mutex_lock(&sc->vsc_mtx);
	error = vi_pci_snapshot(meta);
	pthread_mutex_unlock(&sc->vsc_mtx);
	return (error);
}
#endif

static int
pci_vtinput_legacy_config(nvlist_t *nvl, const char *opts)
{
	if (opts == NULL)
		return (-1);

	/*
	 * parse opts:
	 *   virtio-input,/dev/input/eventX
	 */
	char *cp = strchr(opts, ',');
	if (cp == NULL) {
		set_config_value_node(nvl, "path", opts);
		return (0);
	}
	char *path = strndup(opts, cp - opts);
	set_config_value_node(nvl, "path", path);
	free(path);

	return (pci_parse_legacy_config(nvl, cp + 1));
}

static int
pci_vtinput_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_vtinput_softc *sc;
	struct stat evstat;
	bool intr_initialized, mtx_attr_initialized, packed;
	const char *debug;

	debug = getenv("BHYVE_VTINPUT_DEBUG");
	if (debug != NULL) {
		pci_vtinput_debug = atoi(debug);
		if (pci_vtinput_debug < 1)
			pci_vtinput_debug = 1;
	}

	/*
	 * Keep it here.
	 * Else it's possible to access it uninitialized by jumping to failed.
	 */
	pthread_mutexattr_t mtx_attr;

	sc = calloc(1, sizeof(struct pci_vtinput_softc));
	if (sc == NULL)
		return (-1);
	sc->vsc_fd = -1;
	intr_initialized = false;
	mtx_attr_initialized = false;

	const char *evdev = get_config_value_node(nvl, "path");
	if (evdev == NULL) {
		WPRINTF(("%s: missing required path config value", __func__));
		goto failed;
	}
	sc->vsc_evdev = strdup(evdev);
	if (sc->vsc_evdev == NULL)
		goto failed;

	/*
	 * open evdev by using non blocking I/O:
	 *   read from /dev/input/eventX would block our thread otherwise
	 */
	sc->vsc_fd = open(sc->vsc_evdev, O_RDWR | O_NONBLOCK);
	if (sc->vsc_fd < 0) {
		WPRINTF(("%s: failed to open %s", __func__, sc->vsc_evdev));
		goto failed;
	}
	if (fstat(sc->vsc_fd, &evstat) != 0)
		goto failed;
	sc->vsc_evdev_rdev = evstat.st_rdev;
	DPRINTF(("vtinput: opened host device %s", sc->vsc_evdev));

	/* check if evdev is really a evdev */
	int evversion;
	int error = ioctl(sc->vsc_fd, EVIOCGVERSION, &evversion);
	if (error < 0) {
		WPRINTF(("%s: %s is no evdev", __func__, sc->vsc_evdev));
		goto failed;
	}

	/* gain exclusive access to evdev */
	error = ioctl(sc->vsc_fd, EVIOCGRAB, 1);
	if (error < 0) {
		WPRINTF(("%s: failed to grab %s", __func__, sc->vsc_evdev));
		goto failed;
	}

	if (pthread_mutexattr_init(&mtx_attr)) {
		WPRINTF(("%s: init mutexattr failed", __func__));
		goto failed;
	}
	mtx_attr_initialized = true;
	if (pthread_mutexattr_settype(&mtx_attr, PTHREAD_MUTEX_RECURSIVE)) {
		WPRINTF(("%s: settype mutexattr failed", __func__));
		goto failed;
	}
	if (pthread_mutex_init(&sc->vsc_mtx, &mtx_attr)) {
		WPRINTF(("%s: init mutex failed", __func__));
		goto failed;
	}
	sc->vsc_mtx_initialized = true;
	pthread_mutexattr_destroy(&mtx_attr);
	mtx_attr_initialized = false;

	/* init softc */
	sc->vsc_eventqueue.idx = 0;
	sc->vsc_eventqueue.size = VTINPUT_MAX_PKT_LEN;
	sc->vsc_eventqueue.events = calloc(
	    sc->vsc_eventqueue.size, sizeof(struct vtinput_event_elem));
	sc->vsc_config_valid = 0;
	if (sc->vsc_eventqueue.events == NULL) {
		WPRINTF(("%s: failed to alloc eventqueue", __func__));
		goto failed;
	}

	/* register event handler */
	sc->vsc_evp = mevent_add(sc->vsc_fd, EVF_READ, vtinput_read_event, sc);
	if (sc->vsc_evp == NULL) {
		WPRINTF(("%s: could not register mevent", __func__));
		goto failed;
	}

#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
	cap_rights_init(&rights, CAP_EVENT, CAP_IOCTL, CAP_READ, CAP_WRITE);
	if (caph_rights_limit(sc->vsc_fd, &rights) == -1) {
		errx(EX_OSERR, "Unable to apply rights for sandbox");
	}
#endif

	/* link virtio to softc */
	memcpy(&sc->vsc_consts, &vtinput_vi_consts, sizeof(sc->vsc_consts));
	vi_softc_linkup(
	    &sc->vsc_vs, &sc->vsc_consts, sc, pi, sc->vsc_queues);
	sc->vsc_vs.vs_mtx = &sc->vsc_mtx;

	/* init virtio queues */
	sc->vsc_queues[VTINPUT_EVENTQ].vq_qsize = VTINPUT_RINGSZ;
	sc->vsc_queues[VTINPUT_EVENTQ].vq_notify = pci_vtinput_notify_eventq;
	sc->vsc_queues[VTINPUT_STATUSQ].vq_qsize = VTINPUT_RINGSZ;
	sc->vsc_queues[VTINPUT_STATUSQ].vq_notify = pci_vtinput_notify_statusq;
	if (vi_pci_select_transport(&sc->vsc_vs, nvl,
	    VIRTIO_PCI_MODERN_DEFAULT) != 0)
		goto failed;
	packed = get_config_bool_node_default(nvl, "packed", false);
	if (packed && !vi_pci_is_modern(&sc->vsc_vs)) {
		WPRINTF(("%s: packed queues require transport=modern", __func__));
		goto failed;
	}
	if (packed)
		sc->vsc_consts.vc_hv_caps |= VIRTIO_F_RING_PACKED;

	/* initialize config space */
	if (vi_pci_is_modern(&sc->vsc_vs))
		vi_pci_modern_set_identity(&sc->vsc_vs, VIRTIO_ID_INPUT);
	else {
		/* Preserve the historical identity for compatibility. */
		pci_set_cfgdata16(pi, PCIR_DEVICE,
		    VIRTIO_PCI_COMPAT_INPUT_DEVICE);
		pci_set_cfgdata16(pi, PCIR_VENDOR, VIRTIO_VENDOR);
		pci_set_cfgdata8(pi, PCIR_REVID,
		    VIRTIO_PCI_COMPAT_INPUT_REVISION);
		pci_set_cfgdata16(pi, PCIR_SUBDEV_0,
		    VIRTIO_PCI_COMPAT_INPUT_SUBDEVICE);
		pci_set_cfgdata16(pi, PCIR_SUBVEND_0,
		    VIRTIO_PCI_COMPAT_INPUT_SUBVENDOR);
	}
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_INPUTDEV);
	pci_set_cfgdata8(pi, PCIR_SUBCLASS, PCIS_INPUTDEV_OTHER);

	/* add MSI-X table BAR */
	if (vi_intr_init(&sc->vsc_vs, 1, fbsdrun_virtio_msix()))
		goto failed;
	intr_initialized = true;
	if (vi_pci_is_modern(&sc->vsc_vs)) {
		if (vi_pci_modern_init(&sc->vsc_vs, 2) != 0)
			goto failed;
	} else
		vi_set_io_bar(&sc->vsc_vs, 0);

	return (0);

failed:
	/*
	 * The event callback owns sc as its argument.  Initialization can fail
	 * after registration, including after dispatch has started in embedded
	 * users, so acknowledge deletion before releasing the softc.
	 */
	if (sc->vsc_evp)
		(void)mevent_delete_sync(sc->vsc_evp);
	free(sc->vsc_vs.vs_modern);
	if (intr_initialized)
		pthread_mutex_destroy(&sc->vsc_vs.vs_isr_mtx);
	if (sc->vsc_eventqueue.events)
		free(sc->vsc_eventqueue.events);
	if (sc->vsc_mtx_initialized)
		pthread_mutex_destroy(&sc->vsc_mtx);
	if (mtx_attr_initialized)
		pthread_mutexattr_destroy(&mtx_attr);
	if (sc->vsc_fd >= 0)
		close(sc->vsc_fd);
	free(sc->vsc_evdev);

	free(sc);

	return (-1);
}

static const struct pci_devemu pci_de_vinput = {
	.pe_emu = "virtio-input",
	.pe_init = pci_vtinput_init,
	.pe_legacy_config = pci_vtinput_legacy_config,
	.pe_cfgwrite = vi_pci_modern_cfgwrite,
	.pe_cfgread = vi_pci_modern_cfgread,
	.pe_barwrite = vi_pci_write,
	.pe_barread = vi_pci_read,
#ifdef BHYVE_SNAPSHOT
	.pe_snapshot = vi_pci_snapshot,
	.pe_snapshot_validate = pci_vtinput_snapshot_validate,
	.pe_snapshot_compat = vi_pci_snapshot_compat,
	.pe_pause = vi_pci_pause,
	.pe_resume = vi_pci_resume,
#endif
};
PCI_EMUL_SET(pci_de_vinput);
