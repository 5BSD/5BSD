/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/nv.h>

#include <dev/pci/pcireg.h>
#include <dev/virtio/pci/virtio_pci_modern_var.h>
#include <dev/virtio/virtio_config.h>

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "pci_emul.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif
#include "virtio.h"
#include "virtio_admin_pci.h"
#include "virtio_pci_modern_probes.h"

/* VIRTIO_ACTIVATION_ASSERTION: notification-data-32-bit-doorbell */
/* VIRTIO_ACTIVATION_ASSERTION: trivial-queue-index-notification-identifier */

/*
 * Per-device release-ledger anchors for enabled packed data queues.  Each
 * claim also names a device-specific live case; these anchors do not permit
 * one device to stand in for another.
 * VIRTIO_ACTIVATION_ASSERTION: enabled-packed-vt9p-queue
 * VIRTIO_ACTIVATION_ASSERTION: enabled-packed-vtballoon-queue
 * VIRTIO_ACTIVATION_ASSERTION: enabled-packed-vtblk-queue
 * VIRTIO_ACTIVATION_ASSERTION: enabled-packed-vtcon-queue
 * VIRTIO_ACTIVATION_ASSERTION: enabled-packed-vtcrypto-queue
 * VIRTIO_ACTIVATION_ASSERTION: enabled-packed-vtfs-queue
 * VIRTIO_ACTIVATION_ASSERTION: enabled-packed-vtgpu-queue
 * VIRTIO_ACTIVATION_ASSERTION: enabled-packed-vtinput-queue
 * VIRTIO_ACTIVATION_ASSERTION: enabled-packed-vtiommu-queue
 * VIRTIO_ACTIVATION_ASSERTION: enabled-packed-vtmem-queue
 * VIRTIO_ACTIVATION_ASSERTION: enabled-packed-vtpmem-queue
 * VIRTIO_ACTIVATION_ASSERTION: enabled-packed-vtnet-queue
 * VIRTIO_ACTIVATION_ASSERTION: enabled-packed-vtrnd-queue
 * VIRTIO_ACTIVATION_ASSERTION: enabled-packed-vtrtc-queue
 * VIRTIO_ACTIVATION_ASSERTION: enabled-packed-vtscsi-queue
 * VIRTIO_ACTIVATION_ASSERTION: enabled-packed-vtsnd-queue
 * VIRTIO_ACTIVATION_ASSERTION: enabled-packed-vtvsock-queue
 */

#define	VIRTIO_MODERN_COMMON_OFF	0x0000
#define	VIRTIO_MODERN_ISR_OFF		0x1000
#define	VIRTIO_MODERN_DEVICE_OFF	0x2000
#define	VIRTIO_MODERN_NOTIFY_OFF	0x3000
#define	VIRTIO_MODERN_BAR_SIZE		0x4000
#define	VIRTIO_MODERN_QUEUE_SIZE_MAX	32768

/*
 * VirtIO 1.4 allocates device-specific bits at 0--23 and 50--127.  This
 * 64-bit implementation can represent the portion through bit 63.  Network
 * bits 41 and 42 are defined only by section 5.1.3.2's legacy interface and
 * therefore must not escape into this modern transport; bit 41 is instead
 * the modern VIRTIO_F_ADMIN_VQ common feature and is admitted only when a
 * complete administration-queue binding is present.  Legacy-only common
 * bits 24 and 27 are likewise not carried
 * into the modern interface.  Every supported queue/transport feature is
 * listed explicitly below, and a device model must also opt in through
 * vc_hv_caps.
 */
#define	VIRTIO_MODERN_DEVICE_FEATURES_LOW	((1ULL << 24) - 1)
#define	VIRTIO_MODERN_DEVICE_FEATURES_HIGH	(~((1ULL << 50) - 1))
#define	VIRTIO_MODERN_SUPPORTED_FEATURES				\
	(VIRTIO_MODERN_DEVICE_FEATURES_LOW |				\
	 VIRTIO_RING_F_INDIRECT_DESC |					\
	 VIRTIO_RING_F_EVENT_IDX | VIRTIO_F_VERSION_1 |			\
	 VIRTIO_F_ACCESS_PLATFORM |					\
	 VIRTIO_F_RING_PACKED | VIRTIO_F_IN_ORDER |			\
	 VIRTIO_F_NOTIFICATION_DATA | VIRTIO_F_NOTIF_CONFIG_DATA |	\
	 VIRTIO_F_RING_RESET | VIRTIO_F_ADMIN_VQ | VIRTIO_F_SUSPEND |	\
	 VIRTIO_MODERN_DEVICE_FEATURES_HIGH)
#define	VIRTIO_MODERN_TRANSPORT_FEATURES				\
	(VIRTIO_F_VERSION_1 | VIRTIO_F_NOTIFICATION_DATA |		\
	 VIRTIO_F_NOTIF_CONFIG_DATA)

static bool __unused
vi_modern_admin_topology_compatible(const struct virtio_softc *vs,
    uint64_t negotiated_features, uint16_t source_index,
    uint16_t source_count)
{

	if ((negotiated_features & VIRTIO_F_ADMIN_VQ) == 0)
		return (true);
	return (vs->vs_admin_queues != NULL &&
	    source_index == vs->vs_admin_queue_index &&
	    source_count != 0 && source_count == vs->vs_admin_queue_count);
}

#ifdef BHYVE_SNAPSHOT
#define	VIRTIO_MODERN_SNAPSHOT_MAGIC	0x56544d31U	/* "VTM1" */
#define	VIRTIO_MODERN_SNAPSHOT_VERSION	4U
#endif

static int vi_modern_debug;

#define	MODERN_DPRINTF(level, fmt, ...)					\
	do {								\
		if (vi_modern_debug >= (level)) {			\
			EPRINTLN(fmt, ##__VA_ARGS__);			\
			fflush(stderr);					\
		}							\
	} while (0)

uint64_t
vi_modern_device_features(const struct virtio_softc *vs)
{
	uint64_t features;

	features = vs->vs_vc->vc_hv_caps;
	features &= VIRTIO_MODERN_SUPPORTED_FEATURES;
	if (atomic_load_explicit(&vs->vs_dma_domain_ops,
	    memory_order_acquire) == NULL ||
	    vs->vs_vc->vc_access_platform_ineligible)
		features &= ~VIRTIO_F_ACCESS_PLATFORM;
	if (vs->vs_vc->vc_suspend == NULL ||
	    vs->vs_vc->vc_resume_device == NULL)
		features &= ~VIRTIO_F_SUSPEND;
	/*
	 * Publish the administration feature only as a composed interface.  A
	 * device-model capability bit alone is insufficient: validated queue
	 * storage must already have an adapter which owns parsing, completion,
	 * queue drain, and reset.
	 */
	if (vs->vs_admin_binding == NULL || vs->vs_admin_queues == NULL ||
	    vs->vs_admin_queue_count == 0)
		features &= ~VIRTIO_F_ADMIN_VQ;
	features |= VIRTIO_MODERN_TRANSPORT_FEATURES;
	return (features);
}

static bool
vi_modern_driver_features_valid(const struct virtio_softc *vs,
    uint64_t driver_features, uint64_t available)
{

	return ((driver_features & VIRTIO_F_VERSION_1) != 0 &&
	    (driver_features & ~available) == 0 &&
	    (atomic_load_explicit(&vs->vs_dma_domain_ops,
	    memory_order_acquire) == NULL ||
	    (driver_features & VIRTIO_F_ACCESS_PLATFORM) != 0));
}

static bool __unused
vi_modern_shared_memory_compatible(
    const struct virtio_pci_shared_memory_region *source, uint8_t source_count,
    const struct virtio_pci_modern *destination)
{
	const struct virtio_pci_shared_memory_region *dst;
	int i;

	if (source_count != destination->shared_memory_count)
		return (false);
	for (i = 0; i < source_count; i++) {
		dst = &destination->shared_memory[i];
		if (source[i].id != dst->id || source[i].bar != dst->bar ||
		    source[i].offset != dst->offset ||
		    source[i].length != dst->length)
			return (false);
	}
	return (true);
}

#ifdef BHYVE_SNAPSHOT
int
vi_pci_modern_snapshot_transport(struct virtio_softc *vs,
    struct vm_snapshot_meta *meta)
{
	struct virtio_pci_modern saved, *modern;
	struct virtio_pci_shared_memory_region source_regions[
	    VIRTIO_PCI_SHARED_MEMORY_MAX];
	uint64_t available;
	uint32_t bar, magic, version;
	uint16_t source_admin_count, source_admin_index;
	uint8_t config_changed, config_deferred, config_pending, source_count;
	int i, ret;

	modern = vs->vs_modern;
	if (modern == NULL)
		return (EINVAL);
	saved = *modern;

	magic = VIRTIO_MODERN_SNAPSHOT_MAGIC;
	version = VIRTIO_MODERN_SNAPSHOT_VERSION;
	SNAPSHOT_LE32_OR_LEAVE(magic, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(version, meta, ret, done);
	if (magic != VIRTIO_MODERN_SNAPSHOT_MAGIC ||
	    version != VIRTIO_MODERN_SNAPSHOT_VERSION) {
		ret = ENOTSUP;
		goto done;
	}

	SNAPSHOT_LE64_OR_LEAVE(saved.driver_features, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(saved.device_feature_select, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(saved.driver_feature_select, meta, ret, done);
	bar = (uint32_t)saved.bar;
	SNAPSHOT_LE32_OR_LEAVE(bar, meta, ret, done);
	SNAPSHOT_U8_OR_LEAVE(saved.config_generation, meta, ret, done);
	SNAPSHOT_U8_OR_LEAVE(saved.pci_cfg_capoff, meta, ret, done);
	config_changed = saved.config_changed;
	config_pending = saved.config_pending;
	config_deferred = saved.config_deferred;
	SNAPSHOT_U8_OR_LEAVE(config_changed, meta, ret, done);
	SNAPSHOT_U8_OR_LEAVE(config_pending, meta, ret, done);
	SNAPSHOT_U8_OR_LEAVE(config_deferred, meta, ret, done);
	source_count = saved.shared_memory_count;
	SNAPSHOT_U8_OR_LEAVE(source_count, meta, ret, done);
	if (source_count > VIRTIO_PCI_SHARED_MEMORY_MAX) {
		ret = EINVAL;
		goto done;
	}
	for (i = 0; i < source_count; i++) {
		source_regions[i] = saved.shared_memory[i];
		SNAPSHOT_U8_OR_LEAVE(source_regions[i].id, meta, ret, done);
		SNAPSHOT_U8_OR_LEAVE(source_regions[i].bar, meta, ret, done);
		SNAPSHOT_LE64_OR_LEAVE(source_regions[i].offset, meta, ret, done);
		SNAPSHOT_LE64_OR_LEAVE(source_regions[i].length, meta, ret, done);
	}
	source_admin_index = vs->vs_admin_queue_index;
	source_admin_count = vs->vs_admin_queue_count;
	SNAPSHOT_LE16_OR_LEAVE(source_admin_index, meta, ret, done);
	SNAPSHOT_LE16_OR_LEAVE(source_admin_count, meta, ret, done);

	if (!vm_snapshot_is_loading(meta))
		goto done;
	if (bar > INT_MAX || (int)bar != modern->bar ||
	    saved.pci_cfg_capoff != modern->pci_cfg_capoff ||
	    config_changed > 1 || config_pending > 1 ||
	    config_deferred > 1 ||
	    (config_deferred != 0 && config_changed == 0) ||
	    config_deferred != (uint8_t)vs->vs_config_deferred) {
		EPRINTLN("%s: inconsistent restored configuration state",
		    vs->vs_vc->vc_name);
		ret = EINVAL;
		goto done;
	}
	if (!vi_modern_shared_memory_compatible(source_regions, source_count,
	    modern)) {
		EPRINTLN("%s: incompatible restored shared-memory topology",
		    vs->vs_vc->vc_name);
		ret = ENOTSUP;
		goto done;
	}
	if (!vi_modern_admin_topology_compatible(vs,
	    vs->vs_negotiated_caps, source_admin_index, source_admin_count)) {
		EPRINTLN("%s: incompatible restored administration queue "
		    "topology", vs->vs_vc->vc_name);
		ret = ENOTSUP;
		goto done;
	}
	saved.bar = (int)bar;
	saved.config_changed = config_changed;
	saved.config_pending = config_pending;
	saved.config_deferred = config_deferred;
	available = vi_modern_device_features(vs);
	if ((vs->vs_status & VIRTIO_CONFIG_S_FEATURES_OK) != 0 &&
	    (!vi_modern_driver_features_valid(vs, saved.driver_features,
	    available) ||
	    saved.driver_features != vs->vs_negotiated_caps)) {
		EPRINTLN("%s: restored modern feature state is incompatible",
		    vs->vs_vc->vc_name);
		ret = ENOTSUP;
		goto done;
	}
	if (saved.device_feature_select >= 2)
		saved.device_feature_select = 0;
	if (saved.driver_feature_select >= 2)
		saved.driver_feature_select = 0;
	*modern = saved;

done:
	return (ret);
}
#endif

static size_t
vi_modern_common_cfg_size(const struct virtio_softc *vs)
{
	uint64_t features;

	features = vi_modern_device_features(vs);
	if ((features & VIRTIO_F_ADMIN_VQ) != 0)
		return (VIRTIO_PCI_COMMON_ADM_Q_NUM + sizeof(uint16_t));
	if ((features & VIRTIO_F_RING_RESET) != 0)
		return (VIRTIO_PCI_COMMON_Q_RESET + sizeof(uint16_t));
	if ((features & VIRTIO_F_NOTIF_CONFIG_DATA) != 0)
		return (VIRTIO_PCI_COMMON_Q_NDATA + sizeof(uint16_t));
	return (sizeof(struct virtio_pci_common_cfg));
}

bool
vi_pci_is_modern(const struct virtio_softc *vs)
{

	return (vs->vs_transport == VIRTIO_PCI_TRANSPORT_MODERN);
}

int
vi_pci_select_transport(struct virtio_softc *vs, const struct nvlist *nvl,
    enum virtio_pci_transport_policy policy)
{
	const char *name;
	enum virtio_pci_transport transport;

	name = get_config_value_node(nvl, "transport");
	if (name == NULL) {
		transport = policy == VIRTIO_PCI_LEGACY_DEFAULT ?
		    VIRTIO_PCI_TRANSPORT_LEGACY :
		    VIRTIO_PCI_TRANSPORT_MODERN;
	} else if (strcmp(name, "legacy") == 0) {
		if (policy == VIRTIO_PCI_MODERN_ONLY) {
			EPRINTLN("%s: legacy virtio transport is not supported",
			    vs->vs_vc->vc_name);
			return (EINVAL);
		}
		transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	} else if (strcmp(name, "modern") == 0) {
		transport = VIRTIO_PCI_TRANSPORT_MODERN;
	} else {
		EPRINTLN("%s: invalid virtio transport '%s'",
		    vs->vs_vc->vc_name, name);
		return (EINVAL);
	}

	vs->vs_transport = transport;
	return (0);
}

void
vi_pci_modern_set_identity(struct virtio_softc *vs, uint16_t device_type)
{
	struct pci_devinst *pi;

	pi = vs->vs_pi;
	pci_set_cfgdata16(pi, PCIR_VENDOR, VIRTIO_VENDOR);
	pci_set_cfgdata16(pi, PCIR_DEVICE,
	    VIRTIO_PCI_MODERN_DEVICE_BASE + device_type);
	pci_set_cfgdata8(pi, PCIR_REVID, VIRTIO_PCI_MODERN_REVISION);
	pci_set_cfgdata16(pi, PCIR_SUBVEND_0, VIRTIO_VENDOR);
	pci_set_cfgdata16(pi, PCIR_SUBDEV_0,
	    VIRTIO_PCI_MODERN_SUBDEV_BASE + device_type);
}

static int
vi_modern_add_cap(struct virtio_softc *vs, uint8_t type, uint32_t offset,
    uint32_t length)
{
	struct virtio_pci_cap cap;

	memset(&cap, 0, sizeof(cap));
	cap.cap_vndr = PCIY_VENDOR;
	cap.cap_len = sizeof(cap);
	cap.cfg_type = type;
	cap.bar = vs->vs_modern->bar;
	cap.offset = htole32(offset);
	cap.length = htole32(length);
	return (pci_emul_add_capability(vs->vs_pi, (const u_char *)&cap,
	    sizeof(cap)));
}

static int
vi_modern_add_notify_cap(struct virtio_softc *vs)
{
	struct virtio_pci_notify_cap cap;

	memset(&cap, 0, sizeof(cap));
	cap.cap.cap_vndr = PCIY_VENDOR;
	cap.cap.cap_len = sizeof(cap);
	cap.cap.cfg_type = VIRTIO_PCI_CAP_NOTIFY_CFG;
	cap.cap.bar = vs->vs_modern->bar;
	cap.cap.offset = htole32(VIRTIO_MODERN_NOTIFY_OFF);
	cap.cap.length = htole32(4);
	cap.notify_off_multiplier = htole32(0);
	return (pci_emul_add_capability(vs->vs_pi, (const u_char *)&cap,
	    sizeof(cap)));
}

static int
vi_modern_add_pci_cfg_cap(struct virtio_softc *vs)
{
	struct virtio_pci_cfg_cap cap;
	int error;

	memset(&cap, 0, sizeof(cap));
	cap.cap.cap_vndr = PCIY_VENDOR;
	cap.cap.cap_len = sizeof(cap);
	cap.cap.cfg_type = VIRTIO_PCI_CAP_PCI_CFG;
	cap.cap.bar = vs->vs_modern->bar;
	cap.cap.offset = htole32(VIRTIO_MODERN_COMMON_OFF);
	cap.cap.length = htole32(4);
	error = pci_emul_add_capability(vs->vs_pi, (const u_char *)&cap,
	    sizeof(cap));
	if (error == 0)
		vs->vs_modern->pci_cfg_capoff = vs->vs_pi->pi_prevcap;
	return (error);
}

int
vi_pci_modern_add_shared_memory(struct virtio_softc *vs, uint8_t id,
    uint8_t bar, uint64_t offset, uint64_t length)
{
	struct virtio_pci_cap64 cap;
	struct virtio_pci_shared_memory_region *region;
	struct pcibar *region_bar;
	int error, i;

	_Static_assert(sizeof(cap) == 24,
	    "VirtIO PCI shared-memory capability layout changed");

	if (vs == NULL || vs->vs_pi == NULL || vs->vs_modern == NULL ||
	    !VIRTIO_PCI_CAP_BAR_VALID(bar) || length == 0)
		return (EINVAL);
	/*
	 * PCI capabilities describe an immutable device topology.  Devices
	 * register shared-memory regions during construction, before the guest
	 * starts the status handshake.  Do not permit a backend lifecycle path
	 * (or an erroneous late caller) to append a capability after discovery:
	 * the guest could otherwise retain an old capability chain while
	 * checkpoint compatibility records a different topology.
	 */
	if (vs->vs_modern->shared_memory_sealed || vs->vs_status != 0 ||
	    vs->vs_resetting || vs->vs_quiescing || vs->vs_suspended ||
	    vs->vs_checkpoint_paused)
		return (EBUSY);
	region_bar = &vs->vs_pi->pi_bar[bar];
	if ((region_bar->type != PCIBAR_MEM32 &&
	    region_bar->type != PCIBAR_MEM64) ||
	    offset > region_bar->size || length > region_bar->size - offset)
		return (ERANGE);
	for (i = 0; i < vs->vs_modern->shared_memory_count; i++) {
		if (vs->vs_modern->shared_memory[i].id == id)
			return (EEXIST);
	}
	if (vs->vs_modern->shared_memory_count ==
	    VIRTIO_PCI_SHARED_MEMORY_MAX)
		return (ENOSPC);

	memset(&cap, 0, sizeof(cap));
	cap.cap.cap_vndr = PCIY_VENDOR;
	cap.cap.cap_len = sizeof(cap);
	cap.cap.cfg_type = VIRTIO_PCI_CAP_SHARED_MEMORY_CFG;
	cap.cap.bar = bar;
	cap.cap.id = id;
	cap.cap.offset = htole32((uint32_t)offset);
	cap.cap.length = htole32((uint32_t)length);
	cap.offset_hi = htole32((uint32_t)(offset >> 32));
	cap.length_hi = htole32((uint32_t)(length >> 32));
	error = pci_emul_add_capability(vs->vs_pi, (const u_char *)&cap,
	    sizeof(cap));
	if (error != 0)
		return (error > 0 ? error : ENOSPC);

	i = vs->vs_modern->shared_memory_count;
	while (i > 0 && vs->vs_modern->shared_memory[i - 1].id > id) {
		vs->vs_modern->shared_memory[i] =
		    vs->vs_modern->shared_memory[i - 1];
		i--;
	}
	region = &vs->vs_modern->shared_memory[i];
	region->id = id;
	region->bar = bar;
	region->offset = offset;
	region->length = length;
	vs->vs_modern->shared_memory_count++;
	return (0);
}

void
vi_pci_modern_seal_shared_memory(struct virtio_softc *vs)
{

	if (vs != NULL && vs->vs_modern != NULL)
		vs->vs_modern->shared_memory_sealed = true;
}

/*
 * Return true when two half-open shared-memory capability ranges overlap.
 *
 * Capability registration already proves that each range fits in its BAR,
 * but keep the comparison independently overflow-free.  Snapshot
 * compatibility also consumes recorded topology, so it must not depend on
 * callers elsewhere having made offset + length safe.
 */
static bool
vi_modern_shared_memory_regions_overlap(
    const struct virtio_pci_shared_memory_region *a,
    const struct virtio_pci_shared_memory_region *b)
{

	if (a == NULL || b == NULL || a->bar != b->bar || a->length == 0 ||
	    b->length == 0)
		return (false);
	if (a->offset <= b->offset)
		return (b->offset - a->offset < a->length);
	return (a->offset - b->offset < b->length);
}

int
vi_pci_modern_set_shared_memory_backing(struct virtio_softc *vs, uint8_t id,
    void *base, uint64_t length, bool writable)
{
	struct virtio_pci_shared_memory_backing *backing;
	const struct virtio_pci_shared_memory_region *existing_region, *region;
	uint64_t overlap;
	int i;

	if (vs == NULL || vs->vs_modern == NULL || base == NULL || length == 0)
		return (EINVAL);
	if (length > SIZE_MAX)
		return (ERANGE);
	/*
	 * Backing is host-local state.  A lifecycle owner that has fenced guest
	 * BAR accesses may reconstruct it without discarding the negotiated
	 * device state.  Keep this symmetric with the revoke path below.
	 */
	if (vs->vs_status != 0 && !vs->vs_resetting && !vs->vs_quiescing &&
	    !vs->vs_suspended && !vs->vs_checkpoint_paused)
		return (EBUSY);
	region = NULL;
	for (i = 0; i < vs->vs_modern->shared_memory_count; i++) {
		if (vs->vs_modern->shared_memory[i].id == id) {
			region = &vs->vs_modern->shared_memory[i];
			break;
		}
	}
	if (region == NULL)
		return (ENOENT);
	if (region->length != length)
		return (ERANGE);
	for (i = 0; i < vs->vs_shared_memory_backing_count; i++) {
		if (vs->vs_shared_memory_backing[i].id == id)
			return (EEXIST);
		existing_region = NULL;
		for (int j = 0; j < vs->vs_modern->shared_memory_count; j++) {
			if (vs->vs_modern->shared_memory[j].id ==
			    vs->vs_shared_memory_backing[i].id) {
				existing_region =
				    &vs->vs_modern->shared_memory[j];
				break;
			}
		}
		if (!vi_modern_shared_memory_regions_overlap(existing_region,
		    region))
			continue;
		if (vs->vs_shared_memory_backing[i].base == NULL)
			return (EINVAL);
		/*
		 * Overlapping capabilities describe the same PCI bytes.  Permit
		 * them only when both runtime registrations alias those bytes
		 * with the same access policy; otherwise BAR behavior would
		 * depend on shmid sort order.
		 */
		overlap = MAX(existing_region->offset, region->offset);
		if ((uint8_t *)vs->vs_shared_memory_backing[i].base +
		    (overlap - existing_region->offset) !=
		    (uint8_t *)base + (overlap - region->offset) ||
		    vs->vs_shared_memory_backing[i].writable != writable)
			return (EINVAL);
	}
	if (vs->vs_shared_memory_backing_count ==
	    VIRTIO_PCI_SHARED_MEMORY_MAX)
		return (ENOSPC);
	backing = &vs->vs_shared_memory_backing[
	    vs->vs_shared_memory_backing_count++];
	backing->base = base;
	backing->arg = base;
	backing->length = length;
	backing->id = id;
	backing->writable = writable;
	VIRTIO_PROBE_SHARED_MEMORY(vs->vs_vc->vc_name, id, "bind", length,
	    writable);
	return (0);
}

int
vi_pci_modern_set_shared_memory_handler(struct virtio_softc *vs, uint8_t id,
    uint64_t length, bool writable, void *arg,
    int (*read)(void *, uint64_t, int, uint64_t *),
    int (*write)(void *, uint64_t, int, uint64_t))
{
	struct virtio_pci_shared_memory_backing *backing;
	const struct virtio_pci_shared_memory_region *existing_region, *region;
	int i;

	if (vs == NULL || vs->vs_modern == NULL || arg == NULL ||
	    length == 0 || read == NULL || (writable && write == NULL))
		return (EINVAL);
	/* See vi_pci_modern_set_shared_memory_backing(). */
	if (vs->vs_status != 0 && !vs->vs_resetting && !vs->vs_quiescing &&
	    !vs->vs_suspended && !vs->vs_checkpoint_paused)
		return (EBUSY);
	region = NULL;
	for (i = 0; i < vs->vs_modern->shared_memory_count; i++) {
		if (vs->vs_modern->shared_memory[i].id == id) {
			region = &vs->vs_modern->shared_memory[i];
			break;
		}
	}
	if (region == NULL)
		return (ENOENT);
	if (region->length != length)
		return (ERANGE);
	for (i = 0; i < vs->vs_shared_memory_backing_count; i++) {
		if (vs->vs_shared_memory_backing[i].id == id)
			return (EEXIST);
		existing_region = NULL;
		for (int j = 0; j < vs->vs_modern->shared_memory_count; j++) {
			if (vs->vs_modern->shared_memory[j].id ==
			    vs->vs_shared_memory_backing[i].id) {
				existing_region =
				    &vs->vs_modern->shared_memory[j];
				break;
			}
		}
		if (vi_modern_shared_memory_regions_overlap(existing_region,
		    region)) {
			/*
			 * Unlike direct pointers, callback aliases cannot be
			 * proven to describe identical bytes and access policy.
			 * Reject ambiguity rather than making BAR behavior depend
			 * on capability ordering.
			 */
			return (EINVAL);
		}
	}
	if (vs->vs_shared_memory_backing_count ==
	    VIRTIO_PCI_SHARED_MEMORY_MAX)
		return (ENOSPC);
	backing = &vs->vs_shared_memory_backing[
	    vs->vs_shared_memory_backing_count++];
	backing->arg = arg;
	backing->read = read;
	backing->write = write;
	backing->length = length;
	backing->id = id;
	backing->writable = writable;
	VIRTIO_PROBE_SHARED_MEMORY(vs->vs_vc->vc_name, id, "bind-handler",
	    length, writable);
	return (0);
}

int
vi_pci_modern_clear_shared_memory_backing(struct virtio_softc *vs, uint8_t id,
    void *base)
{
	struct virtio_pci_shared_memory_backing *backing;
	uint64_t length;
	bool writable;
	uint8_t i;

	if (vs == NULL || base == NULL)
		return (EINVAL);
	/*
	 * Every lifecycle owner which fences BAR accesses may revoke a
	 * destination-local backing.  Keep this symmetric with installation:
	 * checkpoint restore and guest suspend may need to replace a backing
	 * without first forcing an unrelated reset or dropping the guest's
	 * negotiated state.
	 */
	if (!vs->vs_resetting && !vs->vs_quiescing && !vs->vs_suspended &&
	    !vs->vs_checkpoint_paused)
		return (EBUSY);
	for (i = 0; i < vs->vs_shared_memory_backing_count; i++) {
		backing = &vs->vs_shared_memory_backing[i];
		if (backing->id != id)
			continue;
		if (backing->base != base)
			return (EINVAL);
		length = backing->length;
		writable = backing->writable;
		memmove(backing, backing + 1,
		    (vs->vs_shared_memory_backing_count - i - 1) *
		    sizeof(*backing));
		vs->vs_shared_memory_backing_count--;
		memset(&vs->vs_shared_memory_backing[
		    vs->vs_shared_memory_backing_count], 0, sizeof(*backing));
		VIRTIO_PROBE_SHARED_MEMORY(vs->vs_vc->vc_name, id, "revoke",
		    length, writable);
		return (0);
	}
	return (ENOENT);
}

int
vi_pci_modern_clear_shared_memory_handler(struct virtio_softc *vs, uint8_t id,
    void *arg)
{
	struct virtio_pci_shared_memory_backing *backing;
	uint64_t length;
	bool writable;
	uint8_t i;

	if (vs == NULL || arg == NULL)
		return (EINVAL);
	/* See vi_pci_modern_clear_shared_memory_backing(). */
	if (!vs->vs_resetting && !vs->vs_quiescing && !vs->vs_suspended &&
	    !vs->vs_checkpoint_paused)
		return (EBUSY);
	for (i = 0; i < vs->vs_shared_memory_backing_count; i++) {
		backing = &vs->vs_shared_memory_backing[i];
		if (backing->id != id)
			continue;
		if (backing->base != NULL || backing->arg != arg ||
		    backing->read == NULL)
			return (EINVAL);
		length = backing->length;
		writable = backing->writable;
		memmove(backing, backing + 1,
		    (vs->vs_shared_memory_backing_count - i - 1) *
		    sizeof(*backing));
		vs->vs_shared_memory_backing_count--;
		memset(&vs->vs_shared_memory_backing[
		    vs->vs_shared_memory_backing_count], 0, sizeof(*backing));
		VIRTIO_PROBE_SHARED_MEMORY(vs->vs_vc->vc_name, id,
		    "revoke-handler", length, writable);
		return (0);
	}
	return (ENOENT);
}

int
vi_pci_modern_init(struct virtio_softc *vs, int barnum)
{
	struct virtio_pci_modern *modern;
	const char *debug;
	struct vqueue_info *vq;
	int error, i;

	debug = getenv("BHYVE_VIRTIO_DEBUG");
	if (debug != NULL) {
		vi_modern_debug = atoi(debug);
		if (vi_modern_debug < 1)
			vi_modern_debug = 1;
	}
	if (!vi_pci_is_modern(vs))
		return (EINVAL);
	if (barnum < 0 || barnum > PCIR_MAX_BAR_0 - 1) {
		EPRINTLN("%s: invalid modern virtio BAR %d",
		    vs->vs_vc->vc_name, barnum);
		return (EINVAL);
	}
	if (vs->vs_vc->vc_cfgsize >
	    VIRTIO_MODERN_NOTIFY_OFF - VIRTIO_MODERN_DEVICE_OFF) {
		/*
		 * The fixed BAR layout reserves [0x2000, 0x3000) for the
		 * device-specific configuration capability.  Reject an oversized
		 * model instead of publishing overlapping DEVICE_CFG and
		 * NOTIFY_CFG capabilities.
		 */
		EPRINTLN("%s: modern device configuration is too large (%zu)",
		    vs->vs_vc->vc_name, vs->vs_vc->vc_cfgsize);
		return (E2BIG);
	}
	if ((vs->vs_admin_queue_count == 0) !=
	    (vs->vs_admin_queues == NULL)) {
		EPRINTLN("%s: incomplete staged administration queue storage",
		    vs->vs_vc->vc_name);
		return (EINVAL);
	}
	if (vs->vs_vc->vc_nvq < 0 || vs->vs_vc->vc_nvq > UINT16_MAX ||
	    (vs->vs_vc->vc_nvq != 0 && vs->vs_queues == NULL) ||
	    (vs->vs_admin_queue_count != 0 &&
	    (vs->vs_admin_queue_index < (uint32_t)vs->vs_vc->vc_nvq ||
	    vs->vs_admin_queue_count >
	    UINT32_C(0x10000) - vs->vs_admin_queue_index))) {
		EPRINTLN("%s: invalid ordinary/administration queue namespace",
		    vs->vs_vc->vc_name);
		return (EINVAL);
	}
	for (i = 0; i < vs->vs_vc->vc_nvq; i++) {
		if (vs->vs_queues[i].vq_qsize != 0 &&
		    ((!powerof2(vs->vs_queues[i].vq_qsize) &&
		    (vs->vs_vc->vc_hv_caps & VIRTIO_F_RING_PACKED) == 0) ||
		    vs->vs_queues[i].vq_qsize > VIRTIO_MODERN_QUEUE_SIZE_MAX)) {
			EPRINTLN("%s: invalid modern virtqueue %d size %u",
			    vs->vs_vc->vc_name, i,
			    vs->vs_queues[i].vq_qsize);
			return (EINVAL);
		}
	}
	for (i = 0; i < vs->vs_admin_queue_count; i++) {
		if (vs->vs_admin_queues[i].vq_vs != vs ||
		    vs->vs_admin_queues[i].vq_num !=
		    (uint16_t)(vs->vs_admin_queue_index + i) ||
		    vs->vs_admin_queues[i].vq_qsize == 0 ||
		    ((!powerof2(vs->vs_admin_queues[i].vq_qsize) &&
		    (vs->vs_vc->vc_hv_caps & VIRTIO_F_RING_PACKED) == 0) ||
		    vs->vs_admin_queues[i].vq_qsize >
		    VIRTIO_MODERN_QUEUE_SIZE_MAX)) {
			EPRINTLN("%s: invalid staged administration virtqueue %u "
			    "size %u", vs->vs_vc->vc_name,
			    vs->vs_admin_queues[i].vq_num,
			    vs->vs_admin_queues[i].vq_qsize);
			return (EINVAL);
		}
	}

	modern = calloc(1, sizeof(*modern));
	if (modern == NULL) {
		EPRINTLN("%s: cannot allocate modern virtio state",
		    vs->vs_vc->vc_name);
		return (ENOMEM);
	}
	modern->bar = barnum;
	vs->vs_modern = modern;
	MODERN_DPRINTF(1, "%s: modern transport BAR=%d debug=%d",
	    vs->vs_vc->vc_name, barnum, vi_modern_debug);

	for (i = 0; i < vs->vs_vc->vc_nvq; i++) {
		vq = &vs->vs_queues[i];
		vq->vq_qsize_max = vq->vq_qsize;
	}
	for (i = 0; i < vs->vs_admin_queue_count; i++) {
		vq = &vs->vs_admin_queues[i];
		vq->vq_qsize_max = vq->vq_qsize;
	}

	error = pci_emul_alloc_bar(vs->vs_pi, barnum, PCIBAR_MEM64,
	    VIRTIO_MODERN_BAR_SIZE);
	if (error != 0)
		goto fail;
	error = vi_modern_add_cap(vs, VIRTIO_PCI_CAP_COMMON_CFG,
	    VIRTIO_MODERN_COMMON_OFF, vi_modern_common_cfg_size(vs));
	if (error != 0)
		goto fail;
	error = vi_modern_add_notify_cap(vs);
	if (error != 0)
		goto fail;
	error = vi_modern_add_cap(vs, VIRTIO_PCI_CAP_ISR_CFG,
	    VIRTIO_MODERN_ISR_OFF, 1);
	if (error != 0)
		goto fail;
	if (vs->vs_vc->vc_cfgsize != 0) {
		error = vi_modern_add_cap(vs, VIRTIO_PCI_CAP_DEVICE_CFG,
		    VIRTIO_MODERN_DEVICE_OFF, vs->vs_vc->vc_cfgsize);
		if (error != 0)
			goto fail;
	}
	error = vi_modern_add_pci_cfg_cap(vs);
	if (error != 0)
		goto fail;

	return (0);

fail:
	EPRINTLN("%s: cannot initialize modern virtio PCI transport: %s",
	    vs->vs_vc->vc_name, strerror(error));
	free(vs->vs_modern);
	vs->vs_modern = NULL;
	return (error);
}

static void
vi_modern_config_interrupt(struct virtio_softc *vs)
{

	vi_interrupt(vs, VIRTIO_PCI_ISR_CONFIG, vs->vs_msix_cfg_idx);
}

void
vi_pci_modern_config_dirty(struct virtio_softc *vs)
{

	if (vs->vs_modern != NULL)
		vs->vs_modern->config_changed = true;
}

void
vi_pci_modern_config_changed(struct virtio_softc *vs)
{
	bool lifecycle_fenced;

	if (vs->vs_modern == NULL)
		return;
	/*
	 * Latch any number of unobserved changes into one generation epoch.
	 * config_generation is only eight bits; incrementing for every backend
	 * change could wrap through 256 before the driver observes it and
	 * present the old value, violating VirtIO 1.4 §4.1.4.3.1.  Consume the
	 * latch on the next config_generation read instead.
	 *
	 * This still protects the driver's stable-read sequence:
	 *
	 *     generation = read_generation();
	 *     read_device_configuration();
	 *     if (generation != read_generation())
	 *             retry;
	 *
	 * A change anywhere after the first generation read sets the latch, so
	 * the final generation read consumes it and returns a different value.
	 */
	vi_pci_modern_config_dirty(vs);
	lifecycle_fenced = vs->vs_suspended || vs->vs_checkpoint_paused ||
	    atomic_load_explicit(&vs->vs_quiescing, memory_order_acquire) != 0;
	if (lifecycle_fenced) {
		vs->vs_modern->config_deferred = true;
		return;
	}
	vs->vs_modern->config_deferred = false;
	if (vs->vs_modern->config_pending)
		return;
	vs->vs_modern->config_pending = true;
	vi_modern_config_interrupt(vs);
}

void
vi_pci_config_changed(struct virtio_softc *vs)
{
	bool lifecycle_fenced;

	lifecycle_fenced = vs->vs_suspended || vs->vs_checkpoint_paused ||
	    atomic_load_explicit(&vs->vs_quiescing, memory_order_acquire) != 0;
	if (lifecycle_fenced) {
		vs->vs_config_deferred = true;
		/*
		 * Modern transport keeps its own coalescing state and returns from
		 * vi_pci_modern_config_changed() below.  Legacy has no such helper:
		 * do not fall through and raise an interrupt while checkpoint,
		 * guest-suspend, or an in-progress lifecycle owner still fences the
		 * device.  Resume or failed-pause rollback re-enters once the common
		 * fence opens.
		 */
		if (!vi_pci_is_modern(vs))
			return;
	}
	if (vi_pci_is_modern(vs))
		vi_pci_modern_config_changed(vs);
	else {
		VIRTIO_PROBE_CONFIG_CHANGED(vs->vs_vc->vc_name, 0);
		vi_interrupt(vs, VIRTIO_PCI_ISR_CONFIG, vs->vs_msix_cfg_idx);
	}
}

static void
vi_modern_set_needs_reset(struct virtio_softc *vs, const char *why)
{

	VIRTIO_PROBE_ERROR(vs->vs_vc->vc_name, why);
	vi_set_needs_reset(vs);
}

static void
vi_modern_reset_vq(struct vqueue_info *vq)
{

	vq_packed_completions_reset(vq);
	vq_set_allocated(vq, false);
	vq->vq_layout = VIRTIO_QUEUE_SPLIT;
	vq->vq_last_avail = 0;
	vq->vq_next_used = 0;
	vq->vq_save_used = 0;
	vq->vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	vq->vq_enabled = 0;
	vq->vq_reset = 0;
	vq_set_resetting(vq, false);
	vq->vq_notify_pending = false;
	vq->vq_desc_gpa = 0;
	vq->vq_driver_gpa = 0;
	vq->vq_device_gpa = 0;
	vq->vq_desc = NULL;
	vq->vq_avail = NULL;
	vq->vq_used = NULL;
	vq->vq_packed_desc = NULL;
	vq->vq_packed_driver_event = NULL;
	vq->vq_packed_device_event = NULL;
	vq->vq_packed_next_avail = 0;
	vq->vq_packed_next_used = 0;
	vq->vq_packed_save_used = 0;
	vq->vq_packed_avail_wrap = true;
	vq->vq_packed_used_wrap = true;
	vq->vq_packed_save_used_wrap = true;
	vq->vq_dma_generation = 0;
	vq->vq_dma_generation_valid = false;
	if (vq->vq_qsize_max != 0)
		vq->vq_qsize = vq->vq_qsize_max;
}

void
vi_pci_modern_reset(struct virtio_softc *vs)
{
	struct vqueue_info *vq;
	int i;

	if (vs->vs_modern == NULL)
		return;
	vs->vs_modern->driver_features = 0;
	vs->vs_modern->device_feature_select = 0;
	vs->vs_modern->driver_feature_select = 0;
	vs->vs_modern->config_changed = false;
	vs->vs_modern->config_pending = false;
	vs->vs_modern->config_deferred = false;
	for (i = 0; i < vs->vs_vc->vc_nvq; i++) {
		vq = &vs->vs_queues[i];
		vi_modern_reset_vq(vq);
	}
	for (i = 0; i < vs->vs_admin_queue_count; i++) {
		vq = &vs->vs_admin_queues[i];
		vi_modern_reset_vq(vq);
	}
	virtio_admin_pci_binding_reset(vs->vs_admin_binding);
}

static uint64_t
vi_modern_bad_value(int size)
{

	switch (size) {
	case 1:
		return (UINT8_MAX);
	case 2:
		return (UINT16_MAX);
	case 4:
		return (UINT32_MAX);
	default:
		return (UINT64_MAX);
	}
}

static struct vqueue_info *
vi_modern_selected_vq(struct virtio_softc *vs)
{

	if (vs->vs_curq < 0)
		return (NULL);
	return (vi_pci_queue_lookup(vs, (uint32_t)vs->vs_curq));
}

static uint64_t
vi_modern_common_read(struct virtio_softc *vs, uint64_t offset, int size)
{
	struct vqueue_info *vq;
	uint64_t features;

	vq = vi_modern_selected_vq(vs);
	features = vi_modern_device_features(vs);
	switch (offset) {
	case VIRTIO_PCI_COMMON_DFSELECT:
		if (size == 4)
			return (vs->vs_modern->device_feature_select);
		break;
	case VIRTIO_PCI_COMMON_DF:
		if (size == 4 && vs->vs_modern->device_feature_select < 2)
			return ((uint32_t)(features >>
			    (32 * vs->vs_modern->device_feature_select)));
		if (size == 4)
			return (0);
		break;
	case VIRTIO_PCI_COMMON_GFSELECT:
		if (size == 4)
			return (vs->vs_modern->driver_feature_select);
		break;
	case VIRTIO_PCI_COMMON_GF:
		if (size == 4 && vs->vs_modern->driver_feature_select < 2)
			return ((uint32_t)(vs->vs_modern->driver_features >>
			    (32 * vs->vs_modern->driver_feature_select)));
		if (size == 4)
			return (0);
		break;
	case VIRTIO_PCI_COMMON_MSIX:
		if (size == 2)
			return (vs->vs_msix_cfg_idx);
		break;
	case VIRTIO_PCI_COMMON_NUMQ:
		if (size == 2)
			return (vs->vs_vc->vc_nvq);
		break;
	case VIRTIO_PCI_COMMON_STATUS:
		if (size == 1)
			return (vs->vs_status);
		break;
	case VIRTIO_PCI_COMMON_CFGGENERATION:
		if (size == 1) {
			if (!vs->vs_suspended &&
			    !vs->vs_checkpoint_paused &&
			    vs->vs_modern->config_changed) {
				vs->vs_modern->config_generation++;
				vs->vs_modern->config_changed = false;
				VIRTIO_PROBE_CONFIG_CHANGED(
				    vs->vs_vc->vc_name,
				    vs->vs_modern->config_generation);
			}
			return (vs->vs_modern->config_generation);
		}
		break;
	case VIRTIO_PCI_COMMON_Q_SELECT:
		if (size == 2)
			return (vs->vs_curq);
		break;
	case VIRTIO_PCI_COMMON_Q_SIZE:
		if (size == 2)
			return (vq == NULL ? 0 : vq->vq_qsize);
		break;
	case VIRTIO_PCI_COMMON_Q_MSIX:
		if (size == 2)
			return (vq == NULL ? VIRTIO_MSI_NO_VECTOR :
			    vq->vq_msix_idx);
		break;
	case VIRTIO_PCI_COMMON_Q_ENABLE:
		if (size == 2)
			return (vq == NULL ? 0 : vq->vq_enabled);
		break;
	case VIRTIO_PCI_COMMON_Q_NDATA:
		if (size == 2 &&
		    (vs->vs_negotiated_caps &
		    VIRTIO_F_NOTIF_CONFIG_DATA) != 0)
			return (vq == NULL ? 0 : vq->vq_num);
		break;
	case VIRTIO_PCI_COMMON_Q_RESET:
		if (size == 2 &&
		    (vs->vs_negotiated_caps & VIRTIO_F_RING_RESET) != 0)
			return (vq == NULL ? 0 : vq->vq_reset);
		break;
	case VIRTIO_PCI_COMMON_ADM_Q_IDX:
		if (size == 2 &&
		    (vs->vs_negotiated_caps & VIRTIO_F_ADMIN_VQ) != 0)
			return (vs->vs_admin_queue_index);
		break;
	case VIRTIO_PCI_COMMON_ADM_Q_NUM:
		if (size == 2 &&
		    (vs->vs_negotiated_caps & VIRTIO_F_ADMIN_VQ) != 0)
			return (vs->vs_admin_queue_count);
		break;
	case VIRTIO_PCI_COMMON_Q_NOFF:
		if (size == 2)
			return (0);
		break;
	case VIRTIO_PCI_COMMON_Q_DESCLO:
	case VIRTIO_PCI_COMMON_Q_DESCHI:
	case VIRTIO_PCI_COMMON_Q_AVAILLO:
	case VIRTIO_PCI_COMMON_Q_AVAILHI:
	case VIRTIO_PCI_COMMON_Q_USEDLO:
	case VIRTIO_PCI_COMMON_Q_USEDHI:
		if (size == 4 && vq != NULL) {
			uint64_t address;

			if (offset <= VIRTIO_PCI_COMMON_Q_DESCHI)
				address = vq->vq_desc_gpa;
			else if (offset <= VIRTIO_PCI_COMMON_Q_AVAILHI)
				address = vq->vq_driver_gpa;
			else
				address = vq->vq_device_gpa;
			if ((offset & 4) != 0)
				address >>= 32;
			return ((uint32_t)address);
		}
		if (size == 4)
			return (0);
		break;
	}
	return (vi_modern_bad_value(size));
}

static void
vi_modern_set_address(uint64_t *address, uint64_t offset, uint32_t value)
{

	if ((offset & 4) == 0)
		*address = (*address & 0xffffffff00000000ULL) | value;
	else
		*address = (*address & 0x00000000ffffffffULL) |
		    ((uint64_t)value << 32);
}

static int
vi_modern_map_vq(struct virtio_softc *vs, struct vqueue_info *vq)
{
	struct virtio_packed_desc *packed_desc;
	struct virtio_packed_event *device_event, *driver_event;
	struct vring_avail *avail;
	struct vring_desc *desc;
	struct vring_used *used;
	uint64_t layout_features;
	size_t avail_size, desc_size, used_size;
	bool packed;
	int error;

	packed = (vs->vs_negotiated_caps & VIRTIO_F_RING_PACKED) != 0;
	if (!vq_split_owners_empty(vq))
		return (EBUSY);
	if (packed) {
		if (vq->vq_qsize == 0 ||
		    vq->vq_qsize > VIRTIO_PACKED_QUEUE_SIZE_MAX ||
		    (vq->vq_desc_gpa & 15) != 0 ||
		    (vq->vq_driver_gpa & 3) != 0 ||
		    (vq->vq_device_gpa & 3) != 0)
			return (EINVAL);
		desc_size = sizeof(*packed_desc) * vq->vq_qsize;
		packed_desc = vi_map_dma(vs, vq->vq_desc_gpa, desc_size,
		    VIRTIO_DMA_BIDIRECTIONAL);
		driver_event = vi_map_dma(vs, vq->vq_driver_gpa,
		    sizeof(*driver_event), VIRTIO_DMA_DEVICE_READ);
		device_event = vi_map_dma(vs, vq->vq_device_gpa,
		    sizeof(*device_event), VIRTIO_DMA_DEVICE_WRITE);
		if (packed_desc == NULL || driver_event == NULL ||
		    device_event == NULL)
			return (EFAULT);
		error = vq_packed_completions_init(vq);
		if (error != 0)
			return (error);
		vq->vq_layout = VIRTIO_QUEUE_PACKED;
		vq->vq_desc = NULL;
		vq->vq_avail = NULL;
		vq->vq_used = NULL;
		vq->vq_packed_desc = packed_desc;
		vq->vq_packed_driver_event = driver_event;
		vq->vq_packed_device_event = device_event;
		vq->vq_packed_next_avail = 0;
		vq->vq_packed_next_used = 0;
		vq->vq_packed_save_used = 0;
		vq->vq_packed_avail_wrap = true;
		vq->vq_packed_used_wrap = true;
		vq->vq_packed_save_used_wrap = true;
		vq->vq_dma_generation_valid = false;
		return (0);
	}
	if (vq->vq_qsize == 0 || !powerof2(vq->vq_qsize) ||
	    (vq->vq_desc_gpa & 15) != 0 ||
	    (vq->vq_driver_gpa & 1) != 0 ||
	    (vq->vq_device_gpa & 3) != 0)
		return (EINVAL);
	if (!vq_packed_completions_empty(vq))
		return (EBUSY);

	desc_size = sizeof(struct vring_desc) * vq->vq_qsize;
	avail_size = offsetof(struct vring_avail, ring) +
	    sizeof(uint16_t) * vq->vq_qsize;
	used_size = offsetof(struct vring_used, ring) +
	    sizeof(struct vring_used_elem) * vq->vq_qsize;
	layout_features = vs->vs_negotiated_caps;
	if ((vs->vs_status & VIRTIO_CONFIG_S_FEATURES_OK) == 0) {
		/*
		 * Transitional behavior permits queue setup before feature
		 * finalization.  Conservatively validate every optional layout
		 * byte the device might later accept so finalizing EVENT_IDX
		 * cannot extend an already enabled mapping.
		 */
		layout_features = vi_modern_device_features(vs);
	}
	if ((layout_features & VIRTIO_RING_F_EVENT_IDX) != 0) {
		/*
		 * used_event and avail_event exist only when EVENT_IDX was
		 * negotiated.  Requiring the trailers unconditionally rejects
		 * an otherwise valid ring ending at the last mapped byte.
		 */
		avail_size += sizeof(uint16_t);
		used_size += sizeof(uint16_t);
	}
	desc = vi_map_dma(vs, vq->vq_desc_gpa, desc_size,
	    VIRTIO_DMA_DEVICE_READ);
	avail = vi_map_dma(vs, vq->vq_driver_gpa, avail_size,
	    VIRTIO_DMA_DEVICE_READ);
	used = vi_map_dma(vs, vq->vq_device_gpa, used_size,
	    VIRTIO_DMA_DEVICE_WRITE);
	if (desc == NULL || avail == NULL || used == NULL)
		return (EFAULT);
	vq_packed_completions_fini(vq);
	vq->vq_layout = VIRTIO_QUEUE_SPLIT;
	vq->vq_desc = desc;
	vq->vq_avail = avail;
	vq->vq_used = used;
	vq->vq_packed_desc = NULL;
	vq->vq_packed_driver_event = NULL;
	vq->vq_packed_device_event = NULL;
	vq->vq_dma_generation_valid = false;
	return (0);
}

static int
vi_modern_enable_vq(struct virtio_softc *vs, struct vqueue_info *vq)
{
	struct virtio_dma_lease lease;
	int error;

	/*
	 * Staged administration queues are intentionally fail-closed until the
	 * controller ring adapter owns command completion and queue-local drain.
	 * This also prevents a future mask-only change from routing them through a
	 * device model's ordinary vc_qenable callback.
	 */
	if (vi_pci_queue_is_admin(vs, vq) && vs->vs_admin_binding == NULL)
		return (ENOTSUP);
	lease = (struct virtio_dma_lease) { 0 };
	if (!vi_dma_acquire(vs, &lease))
		return (EBUSY);
	error = vi_modern_map_vq(vs, vq);
	vi_dma_release(vs, &lease);
	if (error != 0)
		return (error);

	vq_set_allocated(vq, true);
	vq->vq_enabled = 1;
	vq->vq_reset = 0;
	vq->vq_last_avail = 0;
	vq->vq_next_used = 0;
	vq->vq_save_used = 0;
	if (vi_pci_queue_is_admin(vs, vq)) {
		error = virtio_admin_pci_binding_enable(vs->vs_admin_binding, vq);
		if (error != 0) {
			vi_modern_reset_vq(vq);
			return (error);
		}
	} else if (vs->vs_vc->vc_qenable != NULL) {
		error = (*vs->vs_vc->vc_qenable)((void *)vs, vq);
		if (error != 0) {
			vi_modern_reset_vq(vq);
			return (error);
		}
	}
	return (0);
}

static bool
vi_modern_queue_layouts_match(struct virtio_softc *vs, uint64_t features)
{
	enum virtio_queue_layout layout;
	int i;

	layout = (features & VIRTIO_F_RING_PACKED) != 0 ?
	    VIRTIO_QUEUE_PACKED : VIRTIO_QUEUE_SPLIT;
	for (i = 0; i < vs->vs_vc->vc_nvq; i++) {
		if (vs->vs_queues[i].vq_enabled != 0 &&
		    vs->vs_queues[i].vq_layout != layout)
			return (false);
	}
	if ((features & VIRTIO_F_ADMIN_VQ) != 0) {
		for (i = 0; i < vs->vs_admin_queue_count; i++) {
			if (vs->vs_admin_queues[i].vq_enabled != 0 &&
			    vs->vs_admin_queues[i].vq_layout != layout)
				return (false);
		}
	}
	return (true);
}

static void
vi_modern_finish_queue_reset(struct virtio_softc *vs,
    struct vqueue_info *vq, int error)
{
	uint64_t generation;

	generation = vq->vq_generation;
	if (error == 0) {
		vi_modern_reset_vq(vq);
		VIRTIO_PROBE_QUEUE_RESET_END(vs->vs_vc->vc_name,
		    vq->vq_num, generation);
		MODERN_DPRINTF(1, "%s: queue reset complete q=%u "
		    "generation=%ju", vs->vs_vc->vc_name, vq->vq_num,
		    (uintmax_t)generation);
	} else {
		/*
		 * A failed backend drain is not a completed queue reset.  Keep
		 * queue_reset asserted and the queue detached so the driver
		 * cannot reconfigure or reuse guest memory which the backend
		 * may still own.  Poison this generation against a duplicate
		 * or late completion; only a full device reset can recover.
		 */
		vq_set_allocated(vq, false);
		vq->vq_notify_pending = false;
		vq->vq_generation++;
		VIRTIO_PROBE_QUEUE_RESET_FAIL(vs->vs_vc->vc_name,
		    vq->vq_num, generation, error);
		MODERN_DPRINTF(1, "%s: queue reset failed q=%u "
		    "generation=%ju error=%d", vs->vs_vc->vc_name,
		    vq->vq_num, (uintmax_t)generation, error);
		vi_modern_set_needs_reset(vs, "virtqueue reset failed");
	}
}

static void
vi_modern_begin_queue_reset(struct virtio_softc *vs,
    struct vqueue_info *vq)
{
	uint64_t generation;
	int error;

	if (vq_is_resetting(vq))
		return;
	vq->vq_generation++;
	generation = vq->vq_generation;
	vq->vq_reset = 1;
	vq_set_resetting(vq, true);
	vq_set_allocated(vq, false);
	vq->vq_notify_pending = false;
	VIRTIO_PROBE_QUEUE_RESET_BEGIN(vs->vs_vc->vc_name, vq->vq_num,
	    generation);
	MODERN_DPRINTF(1, "%s: queue reset begin q=%u generation=%ju",
	    vs->vs_vc->vc_name, vq->vq_num, (uintmax_t)generation);

	error = 0;
	if (vi_pci_queue_is_admin(vs, vq))
		error = virtio_admin_pci_binding_drain(vs->vs_admin_binding, vq);
	else if (vs->vs_vc->vc_qreset != NULL)
		error = (*vs->vs_vc->vc_qreset)((void *)vs, vq, generation);
	/*
	 * A backend is allowed to drop vs_mtx while draining.  A full device
	 * reset can then invalidate this queue incarnation before the callback
	 * returns.  Do not let the stale synchronous completion reset a newly
	 * configured queue; asynchronous completions use the same fence.
	 */
	if (!vq_is_resetting(vq) || vq->vq_generation != generation)
		return;
	if (error == EINPROGRESS)
		return;
	vi_modern_finish_queue_reset(vs, vq, error);
}

void
vi_pci_modern_queue_reset_complete(struct vqueue_info *vq,
    uint64_t generation, int error)
{
	struct virtio_softc *vs;

	vs = vq->vq_vs;
	VS_LOCK(vs);
	if (vq_is_resetting(vq) && vq->vq_generation == generation)
		vi_modern_finish_queue_reset(vs, vq, error);
	VS_UNLOCK(vs);
}

static void
vi_modern_suspend(struct virtio_softc *vs)
{
	bool admin_quiesced;
	int error;
	uint8_t status;

	/*
	 * Publish the queue-ownership fence before asking the backend to drain.
	 * Lockless workers may finish the descriptor they already own, but
	 * vq_ring_ready() prevents them from taking another one.
	 */
	vi_pci_quiesce_enter(vs);
	MODERN_DPRINTF(1, "%s: device suspend begin",
	    vs->vs_vc->vc_name);
	VIRTIO_PROBE_LIFECYCLE(vs->vs_vc->vc_name, "suspend", "begin", 0);
	admin_quiesced = false;
	error = 0;
	if ((vs->vs_negotiated_caps & VIRTIO_F_ADMIN_VQ) != 0)
		error = virtio_admin_pci_binding_quiesce(
		    vs->vs_admin_binding);
	if (error == 0 &&
	    (vs->vs_negotiated_caps & VIRTIO_F_ADMIN_VQ) != 0)
		admin_quiesced = true;
	if (error == 0)
		error = (*vs->vs_vc->vc_suspend)((void *)vs);
	if (error == 0 &&
	    (vs->vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		error = EIO;
	if (error != 0) {
		if (admin_quiesced) {
			int rollback_error;

			rollback_error = virtio_admin_pci_binding_unquiesce(
			    vs->vs_admin_binding);
			/*
			 * A failed release leaves the administration binding with an
			 * unmatched ownership depth.  The device is quarantined below in
			 * either case, but report the rollback failure rather than hiding
			 * it behind an earlier, potentially recoverable backend error.
			 */
			if (rollback_error != 0)
				error = EIO;
		}
		/*
		 * Poison the device before reopening the queue-admission gate.
		 * Otherwise a lockless notifier can observe DRIVER_OK with
		 * neither quiescing nor NEEDS_RESET between these operations
		 * and consume a new chain after the backend failed to suspend.
		 */
		vi_modern_set_needs_reset(vs, "device suspend failed");
		vi_pci_quiesce_exit(vs);
		VIRTIO_PROBE_LIFECYCLE(vs->vs_vc->vc_name, "suspend",
		    "fail", error);
		MODERN_DPRINTF(1, "%s: device suspend failed error=%d",
		    vs->vs_vc->vc_name, error);
		return;
	}

	/*
	 * The backend has returned every in-flight buffer to its used ring.
	 * Suppress subsequent queue/config interrupts before presenting the
	 * completed SUSPEND state to the driver.
	 */
	vs->vs_suspended = true;
	status = vs->vs_status;
	status |= VIRTIO_CONFIG_STATUS_SUSPEND;
	status &= ~VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vs->vs_status = status;
	vi_pci_quiesce_exit(vs);
	VIRTIO_PROBE_LIFECYCLE(vs->vs_vc->vc_name, "suspend", "end", 0);
	MODERN_DPRINTF(1, "%s: device suspend complete",
	    vs->vs_vc->vc_name);
}

static void
vi_modern_resume(struct virtio_softc *vs)
{
	int error;
	uint8_t status;

	vi_pci_quiesce_enter(vs);
	MODERN_DPRINTF(1, "%s: device resume begin",
	    vs->vs_vc->vc_name);
	VIRTIO_PROBE_LIFECYCLE(vs->vs_vc->vc_name, "resume", "begin", 0);
	if ((vs->vs_negotiated_caps & VIRTIO_F_ADMIN_VQ) != 0)
		error = virtio_admin_pci_binding_resume(vs->vs_admin_binding,
		    vs->vs_vc->vc_resume_device, (void *)vs);
	else
		error = (*vs->vs_vc->vc_resume_device)((void *)vs);
	if (error == 0 &&
	    (vs->vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		error = EIO;
	if (error != 0) {
		/*
		 * Preserve one fail-closed transition: vs_suspended already keeps
		 * queues closed here, and publishing NEEDS_RESET before releasing
		 * the lifecycle owner makes that terminal outcome explicit to every
		 * observer.  Recovery still requires a full device reset.
		 */
		vi_modern_set_needs_reset(vs, "device resume failed");
		vi_pci_quiesce_exit(vs);
		VIRTIO_PROBE_LIFECYCLE(vs->vs_vc->vc_name, "resume",
		    "fail", error);
		MODERN_DPRINTF(1, "%s: device resume failed error=%d",
		    vs->vs_vc->vc_name, error);
		return;
	}
	status = vs->vs_status;
	status &= ~VIRTIO_CONFIG_STATUS_SUSPEND;
	status |= VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vs->vs_status = status;
	vs->vs_suspended = false;
	vi_pci_quiesce_exit(vs);
	VIRTIO_PROBE_LIFECYCLE(vs->vs_vc->vc_name, "resume", "end", 0);
	MODERN_DPRINTF(1, "%s: device resume complete",
	    vs->vs_vc->vc_name);
	if (vs->vs_vc->vc_resume_complete != NULL)
		(*vs->vs_vc->vc_resume_complete)((void *)vs);

	if (vs->vs_modern->config_deferred) {
		vs->vs_modern->config_deferred = false;
		vs->vs_config_deferred = false;
		if (!vs->vs_modern->config_pending) {
			vs->vs_modern->config_pending = true;
			vi_modern_config_interrupt(vs);
		}
	}
	vi_pci_notify_ready_queues(vs);
}

static void
vi_modern_status_write(struct virtio_softc *vs, uint8_t status)
{
	const uint8_t driver_status_mask = VIRTIO_CONFIG_STATUS_ACK |
	    VIRTIO_CONFIG_STATUS_DRIVER | VIRTIO_CONFIG_STATUS_DRIVER_OK |
	    VIRTIO_CONFIG_S_FEATURES_OK | VIRTIO_CONFIG_STATUS_FAILED;
	uint64_t features, negotiated_features;
	int error;
	uint8_t old_status, requested_status;

	old_status = vs->vs_status;
	requested_status = status;
	/*
	 * Even a reset write proves that the guest can already have enumerated
	 * the PCI capability chain.  Keep the topology sealed across all later
	 * full device resets.
	 */
	vi_pci_modern_seal_shared_memory(vs);
	MODERN_DPRINTF(2, "%s: modern status write old=%#x requested=%#x "
	    "driver_features=%#jx", vs->vs_vc->vc_name, old_status, status,
	    (uintmax_t)vs->vs_modern->driver_features);
	if (status == 0) {
		/*
		 * Some backends must temporarily drop vs_mtx while draining
		 * host operations.  Keep the old nonzero status visible until
		 * the callback is finished, and reject other transport access
		 * during that interval.  A driver may reclaim queue memory as
		 * soon as it observes zero.
		 */
		vi_pci_reset_device(vs);
		return;
	}
	if (vs->vs_suspended) {
		/*
		 * A suspended driver resumes by setting DRIVER_OK.  Other
		 * nonzero status writes cannot mutate the suspended device,
		 * except that FAILED remains driver-owned and cumulative even
		 * when the driver gives up during lifecycle recovery.
		 */
		vs->vs_status |= requested_status &
		    VIRTIO_CONFIG_STATUS_FAILED;
		if ((requested_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0 &&
		    (vs->vs_status & VIRTIO_CONFIG_STATUS_FAILED) == 0)
			vi_modern_resume(vs);
		VIRTIO_PROBE_STATUS(vs->vs_vc->vc_name, old_status,
		    vs->vs_status);
		return;
	}
	/*
	 * Driver-owned status bits are cumulative until a full reset.  Preserve
	 * every bit previously accepted so a malicious or buggy guest cannot
	 * clear FEATURES_OK, rewrite driver_features, and renegotiate a live
	 * backend.  Reserved and device-owned bits from the guest are ignored.
	 */
	status &= driver_status_mask;
	status |= old_status & (driver_status_mask |
	    VIRTIO_CONFIG_S_NEEDS_RESET);
	if (vs->vs_reset_failed)
		status |= VIRTIO_CONFIG_S_NEEDS_RESET;
	features = vi_modern_device_features(vs);
	if ((status & VIRTIO_CONFIG_S_FEATURES_OK) != 0 &&
	    !vi_modern_driver_features_valid(vs,
	    vs->vs_modern->driver_features, features))
		status &= ~VIRTIO_CONFIG_S_FEATURES_OK;
	/* A modern device must not become ready before features are accepted. */
	if ((status & VIRTIO_CONFIG_S_FEATURES_OK) == 0)
		status &= ~VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vs->vs_status = status;
	if ((old_status & VIRTIO_CONFIG_S_FEATURES_OK) == 0 &&
	    (status & VIRTIO_CONFIG_S_FEATURES_OK) != 0) {
		negotiated_features = vs->vs_modern->driver_features & features;
		/*
		 * A conforming modern driver finalizes features before enabling
		 * queues.  Keep accepting the historically tolerated reverse
		 * order, but do not allow late RING_PACKED negotiation to change
		 * the interpretation of memory already mapped as a split ring
		 * (or vice versa).
		 */
		error = vi_modern_queue_layouts_match(vs,
		    negotiated_features) ? 0 : EINVAL;
		if (error == 0 && vs->vs_vc->vc_apply_features != NULL)
			error = (*vs->vs_vc->vc_apply_features)((void *)vs,
			    negotiated_features);
		if (error != 0) {
			/*
			 * Section 3.1.1 requires the device to clear
			 * FEATURES_OK when it cannot support the selected
			 * subset.  DRIVER_OK cannot survive that rejection,
			 * including when a non-conforming driver combines both
			 * bits in one write.
			 */
			status = vs->vs_status;
			status &= ~(VIRTIO_CONFIG_S_FEATURES_OK |
			    VIRTIO_CONFIG_STATUS_DRIVER_OK);
			vs->vs_status = status;
			vs->vs_negotiated_caps = 0;
		} else {
			vs->vs_negotiated_caps = negotiated_features;
			VIRTIO_PROBE_FEATURES(vs->vs_vc->vc_name,
			    negotiated_features);
		}
	}
	if ((requested_status & VIRTIO_CONFIG_STATUS_SUSPEND) != 0 &&
	    (vs->vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0 &&
	    (vs->vs_status & (VIRTIO_CONFIG_STATUS_FAILED |
	    VIRTIO_CONFIG_S_NEEDS_RESET)) == 0 &&
	    (vs->vs_negotiated_caps & VIRTIO_F_SUSPEND) != 0)
		vi_modern_suspend(vs);
	status = vs->vs_status;
	VIRTIO_PROBE_STATUS(vs->vs_vc->vc_name, old_status, status);
	if ((old_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0 &&
	    (status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0)
		vi_pci_notify_ready_queues(vs);
}

static void
vi_modern_common_write(struct virtio_softc *vs, uint64_t offset, int size,
    uint64_t value)
{
	struct vqueue_info *vq;
	uint64_t mask;
	uint32_t select;

	vq = vi_modern_selected_vq(vs);
	switch (offset) {
	case VIRTIO_PCI_COMMON_DFSELECT:
		if (size == 4)
			vs->vs_modern->device_feature_select = value;
		break;
	case VIRTIO_PCI_COMMON_GFSELECT:
		if (size == 4)
			vs->vs_modern->driver_feature_select = value;
		break;
	case VIRTIO_PCI_COMMON_GF:
		select = vs->vs_modern->driver_feature_select;
		if (size != 4 || select >= 2 ||
		    (vs->vs_status & VIRTIO_CONFIG_S_FEATURES_OK) != 0)
			break;
		mask = UINT32_MAX;
		mask <<= 32 * select;
		vs->vs_modern->driver_features &= ~mask;
		vs->vs_modern->driver_features |=
		    (uint64_t)(uint32_t)value << (32 * select);
		break;
	case VIRTIO_PCI_COMMON_MSIX:
		if (size == 2) {
			if (value == VIRTIO_MSI_NO_VECTOR ||
			    value < (uint64_t)vs->vs_pi->pi_msix.table_count)
				vs->vs_msix_cfg_idx = value;
			else
				vs->vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;
		}
		break;
	case VIRTIO_PCI_COMMON_STATUS:
		if (size == 1)
			vi_modern_status_write(vs, value);
		break;
	case VIRTIO_PCI_COMMON_Q_SELECT:
		if (size == 2)
			vs->vs_curq = value;
		break;
	case VIRTIO_PCI_COMMON_Q_SIZE:
		if (size == 2 && vq != NULL && !vq->vq_enabled &&
		    !vq_is_resetting(vq) && value != 0 &&
		    (powerof2(value) ||
		    (vs->vs_negotiated_caps & VIRTIO_F_RING_PACKED) != 0) &&
		    value <= vq->vq_qsize_max)
			vq->vq_qsize = value;
		break;
	case VIRTIO_PCI_COMMON_Q_MSIX:
		if (size == 2 && vq != NULL && !vq_is_resetting(vq)) {
			if (value == VIRTIO_MSI_NO_VECTOR ||
			    value < (uint64_t)vs->vs_pi->pi_msix.table_count)
				vq->vq_msix_idx = value;
			else
				vq->vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
		}
		break;
	case VIRTIO_PCI_COMMON_Q_ENABLE:
		if (size == 2 && value == 1 && vq != NULL &&
		    !vq->vq_enabled && !vq_is_resetting(vq)) {
			if (vi_modern_enable_vq(vs, vq) != 0)
				vi_modern_set_needs_reset(vs,
				    "invalid virtqueue setup");
			else
				VIRTIO_PROBE_QUEUE_ENABLE(
				    vs->vs_vc->vc_name, vq->vq_num,
				    vq->vq_desc_gpa, vq->vq_device_gpa,
				    vq->vq_qsize);
			MODERN_DPRINTF(2, "%s: modern queue enable q=%u "
			    "enabled=%u size=%u layout=%s",
			    vs->vs_vc->vc_name, vq->vq_num, vq->vq_enabled,
			    vq->vq_qsize,
			    vq->vq_layout == VIRTIO_QUEUE_PACKED ?
			    "packed" : "split");
		}
		break;
	case VIRTIO_PCI_COMMON_Q_RESET:
		if (size == 2 && value == 1 && vq != NULL &&
		    (vs->vs_negotiated_caps & VIRTIO_F_RING_RESET) != 0)
			vi_modern_begin_queue_reset(vs, vq);
		break;
	case VIRTIO_PCI_COMMON_Q_DESCLO:
	case VIRTIO_PCI_COMMON_Q_DESCHI:
		if (size == 4 && vq != NULL && !vq->vq_enabled &&
		    !vq_is_resetting(vq))
			vi_modern_set_address(&vq->vq_desc_gpa, offset, value);
		break;
	case VIRTIO_PCI_COMMON_Q_AVAILLO:
	case VIRTIO_PCI_COMMON_Q_AVAILHI:
		if (size == 4 && vq != NULL && !vq->vq_enabled &&
		    !vq_is_resetting(vq))
			vi_modern_set_address(&vq->vq_driver_gpa, offset, value);
		break;
	case VIRTIO_PCI_COMMON_Q_USEDLO:
	case VIRTIO_PCI_COMMON_Q_USEDHI:
		if (size == 4 && vq != NULL && !vq->vq_enabled &&
		    !vq_is_resetting(vq))
			vi_modern_set_address(&vq->vq_device_gpa, offset, value);
		break;
	}
}

static bool
vi_modern_device_cfg_access_valid(const struct virtio_softc *vs,
    uint64_t offset, int size)
{
	uint64_t relative;

	if (size != 1 && size != 2 && size != 4)
		return (false);
	if (offset < VIRTIO_MODERN_DEVICE_OFF)
		return (false);
	relative = offset - VIRTIO_MODERN_DEVICE_OFF;
	if (relative > vs->vs_vc->vc_cfgsize ||
	    (uint64_t)size > vs->vs_vc->vc_cfgsize - relative)
		return (false);
	return ((offset & (size - 1)) == 0);
}

static const struct virtio_pci_shared_memory_backing *
vi_modern_shared_memory_backing(const struct virtio_softc *vs, uint8_t id)
{

	for (uint8_t i = 0; i < vs->vs_shared_memory_backing_count; i++) {
		if (vs->vs_shared_memory_backing[i].id == id)
			return (&vs->vs_shared_memory_backing[i]);
	}
	return (NULL);
}

static bool
vi_modern_shared_memory_access(struct virtio_softc *vs, int baridx,
    uint64_t offset, int size,
    const struct virtio_pci_shared_memory_region **regionp,
    const struct virtio_pci_shared_memory_backing **backingp,
    uint64_t *relativep)
{
	const struct virtio_pci_shared_memory_backing *backing;
	const struct virtio_pci_shared_memory_region *region;
	uint64_t relative;

	if (size != 1 && size != 2 && size != 4 && size != 8)
		return (false);
	for (uint8_t i = 0; i < vs->vs_modern->shared_memory_count; i++) {
		region = &vs->vs_modern->shared_memory[i];
		if (region->bar != baridx || offset < region->offset)
			continue;
		relative = offset - region->offset;
		if (relative > region->length ||
		    (uint64_t)size > region->length - relative)
			continue;
		backing = vi_modern_shared_memory_backing(vs, region->id);
		/*
		 * Capabilities may legally alias the same BAR bytes.  One alias
		 * can remain unbound while another supplies the destination-local
		 * backing, so keep searching rather than making accessibility
		 * depend on shared-memory ID ordering.  Registration separately
		 * guarantees that multiple bound aliases describe identical
		 * bytes and policy.
		 */
		if (backing == NULL)
			continue;
		if (backing->length != region->length)
			return (false);
		*regionp = region;
		*backingp = backing;
		*relativep = relative;
		return (true);
	}
	return (false);
}

uint64_t
vi_pci_modern_read(struct pci_devinst *pi, int baridx, uint64_t offset,
    int size)
{
	const struct virtio_pci_shared_memory_backing *backing;
	const struct virtio_pci_shared_memory_region *region;
	struct virtio_softc *vs;
	const uint8_t *source;
	uint64_t relative;
	uint32_t value;
	uint64_t result;
	int error;

	vs = pi->pi_arg;
	result = vi_modern_bad_value(size);
	if (vs->vs_modern == NULL)
		return (result);
	if (baridx != vs->vs_modern->bar) {
		VS_LOCK(vs);
		if (!vs->vs_resetting && !vs->vs_quiescing &&
		    !vs->vs_suspended && !vs->vs_checkpoint_paused &&
		    vi_modern_shared_memory_access(vs, baridx, offset, size,
		    &region, &backing, &relative)) {
			if (backing->read != NULL) {
				if (backing->read(backing->arg, relative, size,
				    &result) != 0)
					result = vi_modern_bad_value(size);
				else
					result &= vi_modern_bad_value(size);
			} else {
				source = (const uint8_t *)backing->base + relative;
				switch (size) {
				case 1:
					result = source[0];
					break;
				case 2:
					result = le16dec(source);
					break;
				case 4:
					result = le32dec(source);
					break;
				case 8:
					result = le64dec(source);
					break;
				}
			}
		}
		VS_UNLOCK(vs);
		return (result);
	}
	VS_LOCK(vs);
	if (vs->vs_resetting || vs->vs_quiescing) {
		/*
		 * A reset or lifecycle callback can release vs_mtx while it
		 * waits for backend work to drain.  Keep the status byte
		 * observable, but do not enter transport or device callbacks
		 * until that owner has completed the transition.
		 */
		if (offset == VIRTIO_PCI_COMMON_STATUS && size == 1)
			result = vs->vs_status;
	} else if (offset < vi_modern_common_cfg_size(vs)) {
		result = vi_modern_common_read(vs, offset, size);
	} else if (offset == VIRTIO_MODERN_ISR_OFF && size == 1) {
		result = vi_isr_read(vs);
	} else if (vi_modern_device_cfg_access_valid(vs, offset, size)) {
		value = 0;
		if (vs->vs_vc->vc_cfgread == NULL)
			error = 0;
		else
			error = (*vs->vs_vc->vc_cfgread)((void *)vs,
			    offset - VIRTIO_MODERN_DEVICE_OFF, size, &value);
		if (error == 0) {
			/*
			 * A successful read observes the current configuration.
			 * Clear only interrupt coalescing here.  The independent
			 * generation latch is consumed by a generation read, so
			 * a change during a driver's stable-read sequence cannot
			 * be hidden by this device-configuration access.
			 */
			vs->vs_modern->config_pending = false;
			result = value & vi_modern_bad_value(size);
		}
	}
	VS_UNLOCK(vs);
	return (result);
}

void
vi_pci_modern_write(struct pci_devinst *pi, int baridx, uint64_t offset,
    int size, uint64_t value)
{
	const struct virtio_pci_shared_memory_backing *backing;
	const struct virtio_pci_shared_memory_region *region;
	struct virtio_softc *vs;
	struct vqueue_info *vq;
	uint8_t *destination;
	uint64_t relative;
	uint16_t next_avail, queue;

	vs = pi->pi_arg;
	if (vs->vs_modern == NULL)
		return;
	if (baridx != vs->vs_modern->bar) {
		VS_LOCK(vs);
		if (!vs->vs_resetting && !vs->vs_quiescing &&
		    !vs->vs_suspended && !vs->vs_checkpoint_paused &&
		    vi_modern_shared_memory_access(vs, baridx, offset, size,
		    &region, &backing, &relative) && backing->writable) {
			if (backing->write != NULL) {
				(void)backing->write(backing->arg, relative, size,
				    value & vi_modern_bad_value(size));
			} else {
				destination = (uint8_t *)backing->base + relative;
				switch (size) {
				case 1:
					destination[0] = value;
					break;
				case 2:
					le16enc(destination, value);
					break;
				case 4:
					le32enc(destination, value);
					break;
				case 8:
					le64enc(destination, value);
					break;
				}
			}
		}
		VS_UNLOCK(vs);
		return;
	}
	/*
	 * MMIO exits normally arrive width-limited.  Normalize here too so
	 * PCI_CFG accesses and direct callers have exactly the same register
	 * semantics.
	 */
	value &= vi_modern_bad_value(size);
	VS_LOCK(vs);
	if (vs->vs_resetting) {
		/* The reset callback still owns all transport and queue state. */
	} else if (vs->vs_quiescing) {
		/* A lifecycle callback owns the backend and queue transition. */
	} else if (vs->vs_suspended &&
	    !(offset == VIRTIO_PCI_COMMON_STATUS && size == 1)) {
		/* While suspended, only device-status writes are meaningful. */
	} else if (offset < vi_modern_common_cfg_size(vs)) {
		vi_modern_common_write(vs, offset, size, value);
	} else if (offset == VIRTIO_MODERN_NOTIFY_OFF) {
		if ((vs->vs_negotiated_caps &
		    VIRTIO_F_NOTIFICATION_DATA) != 0) {
			if (size != 4)
				goto out;
			queue = value & UINT16_MAX;
			next_avail = value >> 16;
		} else {
			if (size != 2)
				goto out;
			queue = value;
			next_avail = 0;
		}
		vq = vi_pci_queue_lookup(vs, queue);
		MODERN_DPRINTF(2, "%s: modern notify q=%u next_avail=%u "
		    "status=%#x enabled=%u", vs->vs_vc->vc_name, queue,
		    next_avail, vs->vs_status,
		    vq != NULL ? vq->vq_enabled : 0);
		vi_pci_notify_queue(vs, queue);
	} else if (vi_modern_device_cfg_access_valid(vs, offset, size) &&
	    vs->vs_vc->vc_cfgwrite != NULL) {
		(void)(*vs->vs_vc->vc_cfgwrite)((void *)vs,
		    offset - VIRTIO_MODERN_DEVICE_OFF, size, value);
	}
out:
	VS_UNLOCK(vs);
}

static bool
vi_modern_cfg_window_valid(struct virtio_softc *vs, uint8_t bar,
    uint32_t offset, uint32_t length)
{
	const struct virtio_pci_shared_memory_region *region;
	uint64_t end;
	uint64_t relative;

	if (vs->vs_modern == NULL ||
	    (length != 1 && length != 2 && length != 4) ||
	    (offset & (length - 1)) != 0)
		return (false);
	end = (uint64_t)offset + length;
	if (bar == vs->vs_modern->bar) {
		if (end <= vi_modern_common_cfg_size(vs))
			return (true);
		if (offset >= VIRTIO_MODERN_ISR_OFF &&
		    end <= VIRTIO_MODERN_ISR_OFF + 1)
			return (true);
		if (offset >= VIRTIO_MODERN_DEVICE_OFF &&
		    end <= VIRTIO_MODERN_DEVICE_OFF + vs->vs_vc->vc_cfgsize)
			return (true);
		if (offset >= VIRTIO_MODERN_NOTIFY_OFF &&
		    end <= VIRTIO_MODERN_NOTIFY_OFF + 4)
			return (true);
	}
	/*
	 * Section 4.1.4.9 permits PCI_CFG to select any BAR range published by
	 * another VirtIO Structure capability.  Shared-memory regions commonly
	 * live in a different BAR, so limiting this path to the transport BAR
	 * made those advertised bytes inaccessible through the mandatory
	 * alternative configuration-space window.
	 */
	for (uint8_t i = 0; i < vs->vs_modern->shared_memory_count; i++) {
		region = &vs->vs_modern->shared_memory[i];
		if (region->bar != bar || offset < region->offset)
			continue;
		relative = (uint64_t)offset - region->offset;
		if (relative <= region->length &&
		    length <= region->length - relative)
			return (true);
	}
	return (false);
}

static bool
vi_modern_cfg_access_overlaps(int offset, int bytes, int field_offset,
    int field_length)
{

	if (offset < 0 || field_offset < 0 || field_length <= 0 ||
	    (bytes != 1 && bytes != 2 && bytes != 4))
		return (false);
	return ((int64_t)offset < (int64_t)field_offset + field_length &&
	    (int64_t)field_offset < (int64_t)offset + bytes);
}

static void
vi_modern_cfg_store_field(struct pci_devinst *pi, int offset, int bytes,
    uint32_t value, int field_offset, int field_length)
{
	int byte_offset, i;

	for (i = 0; i < bytes; i++) {
		byte_offset = offset + i;
		if (byte_offset >= field_offset &&
		    byte_offset < field_offset + field_length)
			pci_set_cfgdata8(pi, byte_offset, value >> (i * 8));
	}
}

static uint32_t
vi_modern_cfg_load(struct pci_devinst *pi, int offset, int bytes)
{

	switch (bytes) {
	case 1:
		return (pci_get_cfgdata8(pi, offset));
	case 2:
		return (pci_get_cfgdata8(pi, offset) |
		    (uint32_t)pci_get_cfgdata8(pi, offset + 1) << 8);
	case 4:
		return (pci_get_cfgdata32(pi, offset));
	default:
		return (UINT32_MAX);
	}
}

int
vi_pci_modern_cfgread(struct pci_devinst *pi, int offset, int bytes,
    uint32_t *retval)
{
	struct virtio_softc *vs;
	uint32_t data;
	uint32_t baroff, length;
	int dataoff;
	uint8_t bar, capoff;

	vs = pi->pi_arg;
	if (!vi_pci_is_modern(vs) || vs->vs_modern == NULL)
		return (1);
	capoff = vs->vs_modern->pci_cfg_capoff;
	dataoff = capoff + offsetof(struct virtio_pci_cfg_cap, pci_cfg_data);
	if (!vi_modern_cfg_access_overlaps(offset, bytes, dataoff,
	    sizeof(((struct virtio_pci_cfg_cap *)0)->pci_cfg_data)))
		return (1);
	bar = pci_get_cfgdata8(pi, capoff + VIRTIO_PCI_CAP_BAR);
	baroff = pci_get_cfgdata32(pi, capoff + VIRTIO_PCI_CAP_OFFSET);
	length = pci_get_cfgdata32(pi, capoff + VIRTIO_PCI_CAP_LENGTH);
	if (!vi_modern_cfg_window_valid(vs, bar, baroff, length)) {
		*retval = UINT32_MAX;
		return (0);
	}
	VIRTIO_PROBE_CFG_WINDOW(vs->vs_vc->vc_name, bar, baroff,
	    length, 0);
	data = vi_pci_modern_read(pi, bar, baroff, length);
	for (uint32_t i = 0; i < length; i++)
		pci_set_cfgdata8(pi, dataoff + i, data >> (i * 8));
	*retval = vi_modern_cfg_load(pi, offset, bytes);
	return (0);
}

int
vi_pci_modern_cfgwrite(struct pci_devinst *pi, int offset, int bytes,
    uint32_t value)
{
	struct virtio_softc *vs;
	uint32_t data;
	uint32_t baroff, length;
	int barfield, dataoff, lengthfield, offsetfield;
	uint8_t bar, capoff;

	vs = pi->pi_arg;
	if (!vi_pci_is_modern(vs) || vs->vs_modern == NULL)
		return (1);
	capoff = vs->vs_modern->pci_cfg_capoff;
	barfield = capoff + VIRTIO_PCI_CAP_BAR;
	offsetfield = capoff + VIRTIO_PCI_CAP_OFFSET;
	lengthfield = capoff + VIRTIO_PCI_CAP_LENGTH;
	dataoff = capoff + offsetof(struct virtio_pci_cfg_cap, pci_cfg_data);
	if (vi_modern_cfg_access_overlaps(offset, bytes, barfield, 1) ||
	    vi_modern_cfg_access_overlaps(offset, bytes, offsetfield, 4) ||
	    vi_modern_cfg_access_overlaps(offset, bytes, lengthfield, 4)) {
		/*
		 * These fields are ordinary PCI configuration-space RW fields.
		 * Preserve byte and word writes, including a dword write covering
		 * cap.bar plus the adjacent read-only id and padding bytes.
		 */
		vi_modern_cfg_store_field(pi, offset, bytes, value, barfield, 1);
		vi_modern_cfg_store_field(pi, offset, bytes, value, offsetfield, 4);
		vi_modern_cfg_store_field(pi, offset, bytes, value, lengthfield, 4);
		return (0);
	}
	if (!vi_modern_cfg_access_overlaps(offset, bytes, dataoff,
	    sizeof(((struct virtio_pci_cfg_cap *)0)->pci_cfg_data)))
		return (1);
	/*
	 * Any write overlapping pci_cfg_data updates the ordinary RW backing
	 * bytes, then triggers one BAR access using cap.length bytes starting at
	 * pci_cfg_data[0].  This matters for byte/word PCI configuration writes;
	 * requiring the host access width to equal cap.length is stricter than
	 * VirtIO 1.4 section 4.1.4.9 and differs from established device models.
	 */
	vi_modern_cfg_store_field(pi, offset, bytes, value, dataoff,
	    sizeof(((struct virtio_pci_cfg_cap *)0)->pci_cfg_data));
	bar = pci_get_cfgdata8(pi, capoff + VIRTIO_PCI_CAP_BAR);
	baroff = pci_get_cfgdata32(pi, capoff + VIRTIO_PCI_CAP_OFFSET);
	length = pci_get_cfgdata32(pi, capoff + VIRTIO_PCI_CAP_LENGTH);
	if (vi_modern_cfg_window_valid(vs, bar, baroff, length)) {
		VIRTIO_PROBE_CFG_WINDOW(vs->vs_vc->vc_name, bar, baroff,
		    length, 1);
		data = pci_get_cfgdata32(pi, dataoff);
		vi_pci_modern_write(pi, bar, baroff, length, data);
	}
	return (0);
}
