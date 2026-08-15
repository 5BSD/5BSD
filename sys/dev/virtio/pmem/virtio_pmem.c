/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Driver for the modern VirtIO persistent-memory device.
 */

#include <sys/param.h>
#include <sys/bio.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/sbuf.h>
#include <sys/sglist.h>
#include <sys/systm.h>
#include <sys/uuid.h>

#include <machine/bus.h>
#include <machine/vm.h>
#include <machine/vmparam.h>

#include <geom/geom.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <dev/acpica/acpivar.h>
#include <dev/nvdimm/nvdimm_var.h>
#include <dev/virtio/pmem/virtio_pmem.h>
#include <dev/virtio/pci/virtio_pci_shmem.h>
#include <dev/virtio/virtio.h>
#include <dev/virtio/virtio_ids.h>
#include <dev/virtio/virtqueue.h>

#include "virtio_if.h"

#define VTPMEM_FEATURES	(VIRTIO_PMEM_F_SHMEM_REGION | VIRTIO_F_RING_RESET)
#define VTPMEM_REQUEST_TIMEOUT	(10 * SBT_1S)

#define VTPMEM_F_DETACH	0x01
#define VTPMEM_F_FAILED		0x02

struct vtpmem_softc {
	device_t		dev;
	struct virtqueue	*requestq;
	struct mtx		mtx;
	struct nvdimm_spa_dev	spa;
	uint64_t		features;
	u_int			flags;
	bool			mtx_initialized;
	bool			spa_initialized;
	bool			request_active;
};

static int	vtpmem_probe(device_t);
static int	vtpmem_attach(device_t);
static int	vtpmem_detach(device_t);
static int	vtpmem_attach_completed(device_t);
static void	vtpmem_requestq_intr(void *);
static void	vtpmem_fail_locked(struct vtpmem_softc *);
static int	vtpmem_flush(void *);
static int	vtpmem_validate_region(struct vtpmem_softc *);

static struct virtio_feature_desc vtpmem_feature_desc[] = {
	{ VIRTIO_PMEM_F_SHMEM_REGION, "SharedMemoryRegion" },
	{ VIRTIO_F_RING_RESET, "RingReset" },
	{ 0, NULL }
};

static device_method_t vtpmem_methods[] = {
	DEVMETHOD(device_probe,		vtpmem_probe),
	DEVMETHOD(device_attach,	vtpmem_attach),
	DEVMETHOD(device_detach,	vtpmem_detach),
	DEVMETHOD(virtio_attach_completed, vtpmem_attach_completed),
	DEVMETHOD_END
};

static driver_t vtpmem_driver = {
	"vtpmem",
	vtpmem_methods,
	sizeof(struct vtpmem_softc),
};

VIRTIO_DRIVER_MODULE(virtio_pmem, vtpmem_driver, NULL, NULL);
MODULE_VERSION(virtio_pmem, 1);
MODULE_DEPEND(virtio_pmem, virtio, 1, 1, 1);
MODULE_DEPEND(virtio_pmem, virtio_pci, 1, 1, 1);
MODULE_DEPEND(virtio_pmem, nvdimm, 1, 1, 1);

VIRTIO_SIMPLE_PNPINFO(virtio_pmem, VIRTIO_ID_PMEM,
    "VirtIO Persistent Memory Adapter");

static int
vtpmem_probe(device_t dev)
{

	if (!virtio_bus_is_modern(dev))
		return (ENXIO);
	return (VIRTIO_SIMPLE_PROBE(dev, virtio_pmem));
}

static int
vtpmem_attach(device_t dev)
{
	struct vtpmem_softc *sc;
	struct vq_alloc_info vq_info;
	int error;

	sc = device_get_softc(dev);
	sc->dev = dev;
	mtx_init(&sc->mtx, device_get_nameunit(dev), "VirtIO PMEM", MTX_DEF);
	sc->mtx_initialized = true;
	virtio_set_feature_desc(dev, vtpmem_feature_desc);
	sc->features = virtio_negotiate_features(dev, VTPMEM_FEATURES);
	error = virtio_finalize_features(dev);
	if (error != 0)
		goto fail;
	if (!virtio_with_feature(dev, VIRTIO_PMEM_F_SHMEM_REGION)) {
		device_printf(dev, "missing shared-memory-region feature\n");
		error = ENXIO;
		goto fail;
	}

	VQ_ALLOC_INFO_INIT(&vq_info, 0, vtpmem_requestq_intr, sc,
	    &sc->requestq, "%s request", device_get_nameunit(dev));
	error = virtio_alloc_virtqueues(dev, 1, &vq_info);
	if (error != 0)
		goto fail;
	error = virtio_setup_intr(dev, INTR_TYPE_BIO);
	if (error != 0)
		goto fail;
	error = vtpmem_validate_region(sc);
	if (error != 0)
		goto fail;
	return (0);

fail:
	vtpmem_detach(dev);
	return (error);
}

static int
vtpmem_attach_completed(device_t dev)
{
	struct vtpmem_softc *sc;
	int error;

	sc = device_get_softc(dev);
	mtx_lock(&sc->mtx);
	(void)virtqueue_enable_intr(sc->requestq);
	mtx_unlock(&sc->mtx);

	/*
	 * nvdimm_spa_dev_init publishes the cdev and GEOM provider only after
	 * the transport is fully ready to service its flush callback.
	 */
	error = nvdimm_spa_dev_init(&sc->spa, device_get_nameunit(dev),
	    10000 + device_get_unit(dev));
	if (error == 0)
		sc->spa_initialized = true;
	else
		nvdimm_spa_dev_fini(&sc->spa);
	return (error);
}

static int
vtpmem_detach(device_t dev)
{
	struct vtpmem_softc *sc;
	int last;

	sc = device_get_softc(dev);
	if (sc->mtx_initialized) {
		mtx_lock(&sc->mtx);
		sc->flags |= VTPMEM_F_DETACH;
		wakeup(sc);
		wakeup(&sc->request_active);
		mtx_unlock(&sc->mtx);
	}
	/* The SPA worker must be gone before requestq can be reclaimed. */
	if (sc->spa_initialized) {
		nvdimm_spa_dev_fini(&sc->spa);
		sc->spa_initialized = false;
	}
	if (sc->mtx_initialized)
		mtx_lock(&sc->mtx);
	if (sc->requestq != NULL) {
		virtqueue_disable_intr(sc->requestq);
		virtio_stop(dev);
		last = 0;
		while (virtqueue_drain(sc->requestq, &last) != NULL)
			;
		sc->requestq = NULL;
	}
	if (sc->mtx_initialized)
		mtx_unlock(&sc->mtx);
	virtio_teardown_intr(dev);
	if (sc->mtx_initialized) {
		mtx_destroy(&sc->mtx);
		sc->mtx_initialized = false;
	}
	return (0);
}

static void
vtpmem_requestq_intr(void *xsc)
{
	struct vtpmem_softc *sc;

	sc = xsc;
	mtx_lock(&sc->mtx);
	wakeup(sc);
	mtx_unlock(&sc->mtx);
}

static void
vtpmem_fail_locked(struct vtpmem_softc *sc)
{
	int last;

	mtx_assert(&sc->mtx, MA_OWNED);
	sc->flags |= VTPMEM_F_FAILED;
	if (sc->requestq != NULL) {
		virtqueue_disable_intr(sc->requestq);
		virtio_stop(sc->dev);
		last = 0;
		while (virtqueue_drain(sc->requestq, &last) != NULL)
			;
	}
	wakeup(sc);
	wakeup(&sc->request_active);
}

static int
vtpmem_flush(void *arg)
{
	struct vtpmem_softc *sc;
	/*
	 * The device-readable request and device-writable response must occupy
	 * two distinct virtqueue descriptors: virtqueue_enqueue() emits one
	 * descriptor per sglist segment, and sglist_append() coalesces a new
	 * range onto the previous segment whenever the two are physically
	 * contiguous.  Two bare adjacent stack locals could therefore merge into
	 * a single readable segment, leaving the device with no writable buffer
	 * for its status word; the host then rejects the chain and every FLUSH
	 * fails (latching VTPMEM_F_FAILED).  Keep them in one object separated by
	 * an explicit pad so the C-guaranteed member offsets force a
	 * non-contiguous, two-segment split regardless of compiler stack layout.
	 */
	struct {
		struct virtio_pmem_req	request;
		uint32_t		_pad;
		struct virtio_pmem_resp	response;
	} buf;
	struct sglist sg;
	struct sglist_seg segs[2];
	sbintime_t deadline, remaining;
	uint32_t used_len;
	void *cookie;
	int error, readable;

	sc = arg;
	buf.request.type = htole32(VIRTIO_PMEM_REQ_TYPE_FLUSH);
	buf.response.ret = htole32(VIRTIO_PMEM_RESP_ERR);
	sglist_init(&sg, nitems(segs), segs);
	error = sglist_append(&sg, &buf.request, sizeof(buf.request));
	if (error != 0)
		return (error);
	readable = sg.sg_nseg;
	error = sglist_append(&sg, &buf.response, sizeof(buf.response));
	if (error != 0)
		return (error);
	KASSERT(sg.sg_nseg == readable + 1,
	    ("vtpmem: request and response collapsed into one descriptor"));

	mtx_lock(&sc->mtx);
	while (sc->request_active && (sc->flags &
	    (VTPMEM_F_DETACH | VTPMEM_F_FAILED)) == 0)
		msleep(&sc->request_active, &sc->mtx, 0, "vtpmemq", 0);
	if ((sc->flags & VTPMEM_F_DETACH) != 0) {
		error = ENXIO;
		goto out;
	}
	if ((sc->flags & VTPMEM_F_FAILED) != 0) {
		error = EIO;
		goto out;
	}
	sc->request_active = true;
	error = virtqueue_enqueue(sc->requestq, &buf.response, &sg, readable,
	    sg.sg_nseg - readable);
	if (error != 0)
		goto complete;
	virtqueue_notify(sc->requestq);
	deadline = sbinuptime() + VTPMEM_REQUEST_TIMEOUT;
	for (;;) {
		cookie = virtqueue_dequeue(sc->requestq, &used_len);
		if (cookie != NULL)
			break;
		if ((sc->flags & (VTPMEM_F_DETACH | VTPMEM_F_FAILED)) != 0) {
			error = (sc->flags & VTPMEM_F_DETACH) != 0 ? ENXIO : EIO;
			goto reset;
		}
		if (virtqueue_enable_intr(sc->requestq) != 0)
			continue;
		remaining = deadline - sbinuptime();
		if (remaining <= 0) {
			error = ETIMEDOUT;
			goto reset;
		}
		error = msleep_sbt(sc, &sc->mtx, 0, "vtpmemf", remaining, 0, 0);
		if (error == EWOULDBLOCK) {
			error = ETIMEDOUT;
			goto reset;
		}
		if (error != 0)
			goto reset;
	}
	if (cookie != &buf.response || used_len != sizeof(buf.response) ||
	    le32toh(buf.response.ret) != VIRTIO_PMEM_RESP_OK) {
		error = EIO;
		goto reset;
	}
	error = 0;
	goto complete;

reset:
	/* Stack request storage cannot outlive an incomplete descriptor. */
	vtpmem_fail_locked(sc);
complete:
	sc->request_active = false;
	wakeup(&sc->request_active);
out:
	mtx_unlock(&sc->mtx);
	return (error);
}

static int
vtpmem_validate_region(struct vtpmem_softc *sc)
{
	struct virtio_pci_shmem_region region;
	int error;

	error = virtio_pci_get_shmem_region(sc->dev,
	    VIRTIO_PMEM_SHMEM_REGION_ID, &region);
	if (error != 0)
		return (error);
	if (region.length == 0 || (region.addr & PAGE_MASK) != 0 ||
	    (region.length & PAGE_MASK) != 0 || region.addr > UINT64_MAX -
	    region.length)
		return (EINVAL);

	/*
	 * With SHMEM_REGION negotiated the region is fully described by shared
	 * memory region ID 0.  VirtIO 1.4 5.16 only makes the device SHOULD set
	 * the start/size config fields to zero, and requires the driver to
	 * ignore them ("MUST NOT use start or stop").  Do not read or validate
	 * them here: a spec-correct host that leaves them non-zero must still
	 * attach, exactly as the Linux guest driver does.
	 */

	/*
	 * Hand the raw guest-physical shmem range to the NVDIMM SPA framework,
	 * which pmap_large_map()s it into KVA from nvdimm_spa_dev_init().  This
	 * deliberately bypasses newbus resource allocation: the range is a
	 * shared-memory BAR window owned by the VirtIO PCI parent rather than an
	 * rman-managed resource, and its bounds/alignment were validated above.
	 * We map it write-back as byte-addressable persistent memory.  Mapping a
	 * BAR-derived guest-physical range this way is the primary
	 * live-validation risk for this driver; it has so far only been
	 * exercised against the bhyve virtio-pmem backend.
	 */
	sc->spa.spa_phys_base = region.addr;
	sc->spa.spa_len = region.length;
	sc->spa.spa_memattr = VM_MEMATTR_WRITE_BACK;
	sc->spa.spa_flush = vtpmem_flush;
	sc->spa.spa_flush_arg = sc;
	return (0);
}
