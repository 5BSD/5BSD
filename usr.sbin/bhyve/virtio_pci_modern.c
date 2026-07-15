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
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "pci_emul.h"
#include "virtio.h"
#include "virtio_pci_modern_probes.h"

#define	VIRTIO_MODERN_COMMON_OFF	0x0000
#define	VIRTIO_MODERN_ISR_OFF		0x1000
#define	VIRTIO_MODERN_DEVICE_OFF	0x2000
#define	VIRTIO_MODERN_NOTIFY_OFF	0x3000
#define	VIRTIO_MODERN_BAR_SIZE		0x4000
#define	VIRTIO_MODERN_QUEUE_SIZE_MAX	32768

/*
 * Virtio 1.4 reserves bits 24--49 for device-independent features.  This
 * backend implements split-ring INDIRECT_DESC, EVENT_IDX, and VERSION_1.
 * Preserve device-specific bits 0--23 and 50--63 for future device models.
 */
#define	VIRTIO_MODERN_DEVICE_FEATURES_LOW	((1ULL << 24) - 1)
#define	VIRTIO_MODERN_DEVICE_FEATURES_HIGH	(~((1ULL << 50) - 1))
#define	VIRTIO_MODERN_SUPPORTED_FEATURES				\
	(VIRTIO_MODERN_DEVICE_FEATURES_LOW | VIRTIO_RING_F_INDIRECT_DESC | \
	 VIRTIO_RING_F_EVENT_IDX | VIRTIO_F_VERSION_1 |			\
	 VIRTIO_MODERN_DEVICE_FEATURES_HIGH)

struct virtio_pci_modern {
	uint64_t driver_features;
	uint32_t device_feature_select;
	uint32_t driver_feature_select;
	int bar;
	uint8_t config_generation;
	uint8_t pci_cfg_capoff;
};

static uint64_t
vi_modern_device_features(const struct virtio_softc *vs)
{
	uint64_t features;

	features = vs->vs_vc->vc_hv_caps;
	features &= VIRTIO_MODERN_SUPPORTED_FEATURES;
	features |= VIRTIO_F_VERSION_1;
	return (features);
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
	pci_set_cfgdata16(pi, PCIR_DEVICE, 0x1040 + device_type);
	pci_set_cfgdata8(pi, PCIR_REVID, 1);
	pci_set_cfgdata16(pi, PCIR_SUBVEND_0, VIRTIO_VENDOR);
	pci_set_cfgdata16(pi, PCIR_SUBDEV_0, 0x0040 + device_type);
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
vi_pci_modern_init(struct virtio_softc *vs, int barnum)
{
	struct virtio_pci_modern *modern;
	struct vqueue_info *vq;
	int error, i;

	if (!vi_pci_is_modern(vs))
		return (EINVAL);
	if (barnum < 0 || barnum > PCIR_MAX_BAR_0 - 1) {
		EPRINTLN("%s: invalid modern virtio BAR %d",
		    vs->vs_vc->vc_name, barnum);
		return (EINVAL);
	}
	for (i = 0; i < vs->vs_vc->vc_nvq; i++) {
		if (vs->vs_queues[i].vq_qsize != 0 &&
		    (!powerof2(vs->vs_queues[i].vq_qsize) ||
		    vs->vs_queues[i].vq_qsize > VIRTIO_MODERN_QUEUE_SIZE_MAX)) {
			EPRINTLN("%s: invalid modern virtqueue %d size %u",
			    vs->vs_vc->vc_name, i,
			    vs->vs_queues[i].vq_qsize);
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

	for (i = 0; i < vs->vs_vc->vc_nvq; i++) {
		vq = &vs->vs_queues[i];
		vq->vq_qsize_max = vq->vq_qsize;
	}

	error = pci_emul_alloc_bar(vs->vs_pi, barnum, PCIBAR_MEM64,
	    VIRTIO_MODERN_BAR_SIZE);
	if (error != 0)
		goto fail;
	error = vi_modern_add_cap(vs, VIRTIO_PCI_CAP_COMMON_CFG,
	    VIRTIO_MODERN_COMMON_OFF, sizeof(struct virtio_pci_common_cfg));
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

/* Caller holds the device mutex, matching other virtio device callbacks. */
static void
vi_modern_config_interrupt(struct virtio_softc *vs)
{

	if (pci_msix_enabled(vs->vs_pi)) {
		if (vs->vs_msix_cfg_idx != VIRTIO_MSI_NO_VECTOR)
			pci_generate_msix(vs->vs_pi, vs->vs_msix_cfg_idx);
	} else {
		vs->vs_isr |= VIRTIO_PCI_ISR_CONFIG;
		pci_generate_msi(vs->vs_pi, 0);
		pci_lintr_assert(vs->vs_pi);
	}
}

void
vi_pci_modern_config_changed(struct virtio_softc *vs)
{

	if (vs->vs_modern == NULL)
		return;
	vs->vs_modern->config_generation++;
	VIRTIO_PROBE_CONFIG_CHANGED(vs->vs_modern->config_generation);
	vi_modern_config_interrupt(vs);
}

static void
vi_modern_set_needs_reset(struct virtio_softc *vs, const char *why)
{

	VIRTIO_PROBE_ERROR(why);
	if ((vs->vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		return;
	vs->vs_status |= VIRTIO_CONFIG_S_NEEDS_RESET;
	if ((vs->vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0)
		vi_modern_config_interrupt(vs);
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
	for (i = 0; i < vs->vs_vc->vc_nvq; i++) {
		vq = &vs->vs_queues[i];
		vq->vq_enabled = 0;
		vq->vq_desc_gpa = 0;
		vq->vq_driver_gpa = 0;
		vq->vq_device_gpa = 0;
		if (vq->vq_qsize_max != 0)
			vq->vq_qsize = vq->vq_qsize_max;
	}
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

	if (vs->vs_curq < 0 || vs->vs_curq >= vs->vs_vc->vc_nvq)
		return (NULL);
	return (&vs->vs_queues[vs->vs_curq]);
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
		if (size == 1)
			return (vs->vs_modern->config_generation);
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
	size_t avail_size, desc_size, used_size;

	if (vq->vq_qsize == 0 || !powerof2(vq->vq_qsize) ||
	    (vq->vq_desc_gpa & 15) != 0 ||
	    (vq->vq_driver_gpa & 1) != 0 ||
	    (vq->vq_device_gpa & 3) != 0)
		return (EINVAL);

	desc_size = sizeof(struct vring_desc) * vq->vq_qsize;
	avail_size = 6 + sizeof(uint16_t) * vq->vq_qsize;
	used_size = 6 + sizeof(struct vring_used_elem) * vq->vq_qsize;
	vq->vq_desc = paddr_guest2host(vs->vs_pi->pi_vmctx,
	    vq->vq_desc_gpa, desc_size);
	vq->vq_avail = paddr_guest2host(vs->vs_pi->pi_vmctx,
	    vq->vq_driver_gpa, avail_size);
	vq->vq_used = paddr_guest2host(vs->vs_pi->pi_vmctx,
	    vq->vq_device_gpa, used_size);
	if (vq->vq_desc == NULL || vq->vq_avail == NULL || vq->vq_used == NULL)
		return (EFAULT);
	return (0);
}

static int
vi_modern_enable_vq(struct virtio_softc *vs, struct vqueue_info *vq)
{
	int error;

	error = vi_modern_map_vq(vs, vq);
	if (error != 0)
		return (error);

	vq->vq_flags = VQ_ALLOC;
	vq->vq_enabled = 1;
	vq->vq_last_avail = 0;
	vq->vq_next_used = 0;
	vq->vq_save_used = 0;
	return (0);
}

static void
vi_modern_status_write(struct virtio_softc *vs, uint8_t status)
{
	uint8_t old_status;

	old_status = vs->vs_status;
	if (status == 0) {
		VIRTIO_PROBE_RESET();
		vs->vs_status = 0;
		(*vs->vs_vc->vc_reset)((void *)vs);
		return;
	}
	if ((status & VIRTIO_CONFIG_S_FEATURES_OK) != 0 &&
	    (vs->vs_modern->driver_features & VIRTIO_F_VERSION_1) == 0)
		status &= ~VIRTIO_CONFIG_S_FEATURES_OK;
	/* NEEDS_RESET is device-owned and remains set until a full reset. */
	status |= old_status & VIRTIO_CONFIG_S_NEEDS_RESET;
	vs->vs_status = status;
	VIRTIO_PROBE_STATUS(old_status, status);
	if ((old_status & VIRTIO_CONFIG_S_FEATURES_OK) == 0 &&
	    (status & VIRTIO_CONFIG_S_FEATURES_OK) != 0) {
		vs->vs_negotiated_caps =
		    (uint32_t)vs->vs_modern->driver_features;
		if (vs->vs_vc->vc_apply_features != NULL)
			(*vs->vs_vc->vc_apply_features)((void *)vs,
			    vs->vs_modern->driver_features);
		VIRTIO_PROBE_FEATURES(vs->vs_modern->driver_features);
	}
}

static void
vi_modern_common_write(struct virtio_softc *vs, uint64_t offset, int size,
    uint64_t value)
{
	struct vqueue_info *vq;
	uint64_t features, mask;
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
		features = vi_modern_device_features(vs);
		mask = UINT32_MAX;
		mask <<= 32 * select;
		vs->vs_modern->driver_features &= ~mask;
		vs->vs_modern->driver_features |=
		    (((uint64_t)(uint32_t)value << (32 * select)) & features);
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
		if (size == 2 && vq != NULL && !vq->vq_enabled && value != 0 &&
		    powerof2(value) && value <= vq->vq_qsize_max)
			vq->vq_qsize = value;
		break;
	case VIRTIO_PCI_COMMON_Q_MSIX:
		if (size == 2 && vq != NULL) {
			if (value == VIRTIO_MSI_NO_VECTOR ||
			    value < (uint64_t)vs->vs_pi->pi_msix.table_count)
				vq->vq_msix_idx = value;
			else
				vq->vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
		}
		break;
	case VIRTIO_PCI_COMMON_Q_ENABLE:
		if (size == 2 && value == 1 && vq != NULL &&
		    !vq->vq_enabled) {
			if (vi_modern_enable_vq(vs, vq) != 0)
				vi_modern_set_needs_reset(vs,
				    "invalid virtqueue setup");
			else
				VIRTIO_PROBE_QUEUE_ENABLE(vq->vq_num,
				    vq->vq_desc_gpa, vq->vq_driver_gpa,
				    vq->vq_device_gpa, vq->vq_qsize);
		}
		break;
	case VIRTIO_PCI_COMMON_Q_DESCLO:
	case VIRTIO_PCI_COMMON_Q_DESCHI:
		if (size == 4 && vq != NULL && !vq->vq_enabled)
			vi_modern_set_address(&vq->vq_desc_gpa, offset, value);
		break;
	case VIRTIO_PCI_COMMON_Q_AVAILLO:
	case VIRTIO_PCI_COMMON_Q_AVAILHI:
		if (size == 4 && vq != NULL && !vq->vq_enabled)
			vi_modern_set_address(&vq->vq_driver_gpa, offset, value);
		break;
	case VIRTIO_PCI_COMMON_Q_USEDLO:
	case VIRTIO_PCI_COMMON_Q_USEDHI:
		if (size == 4 && vq != NULL && !vq->vq_enabled)
			vi_modern_set_address(&vq->vq_device_gpa, offset, value);
		break;
	}
}

uint64_t
vi_pci_modern_read(struct pci_devinst *pi, int baridx, uint64_t offset,
    int size)
{
	struct virtio_softc *vs;
	uint32_t value;
	uint64_t result;
	int error;

	vs = pi->pi_arg;
	result = vi_modern_bad_value(size);
	if (vs->vs_modern == NULL || baridx != vs->vs_modern->bar)
		return (result);
	VS_LOCK(vs);
	if (offset < sizeof(struct virtio_pci_common_cfg)) {
		result = vi_modern_common_read(vs, offset, size);
	} else if (offset == VIRTIO_MODERN_ISR_OFF && size == 1) {
		result = vs->vs_isr;
		vs->vs_isr = 0;
		if (result != 0)
			pci_lintr_deassert(pi);
	} else if (offset >= VIRTIO_MODERN_DEVICE_OFF &&
	    offset + size <= VIRTIO_MODERN_DEVICE_OFF +
	    vs->vs_vc->vc_cfgsize && (size == 1 || size == 2 || size == 4) &&
	    (offset & (size - 1)) == 0) {
		value = 0;
		if (vs->vs_vc->vc_cfgread == NULL)
			error = 0;
		else
			error = (*vs->vs_vc->vc_cfgread)((void *)vs,
			    offset - VIRTIO_MODERN_DEVICE_OFF, size, &value);
		if (error == 0)
			result = value;
	}
	VS_UNLOCK(vs);
	return (result);
}

void
vi_pci_modern_write(struct pci_devinst *pi, int baridx, uint64_t offset,
    int size, uint64_t value)
{
	struct virtio_softc *vs;

	vs = pi->pi_arg;
	if (vs->vs_modern == NULL || baridx != vs->vs_modern->bar)
		return;
	VS_LOCK(vs);
	if (offset < sizeof(struct virtio_pci_common_cfg)) {
		vi_modern_common_write(vs, offset, size, value);
	} else if (offset == VIRTIO_MODERN_NOTIFY_OFF && size == 2) {
		VIRTIO_PROBE_QUEUE_NOTIFY((uint16_t)value);
		vi_pci_notify_queue(vs, value);
	} else if (offset >= VIRTIO_MODERN_DEVICE_OFF &&
	    offset + size <= VIRTIO_MODERN_DEVICE_OFF +
	    vs->vs_vc->vc_cfgsize && (size == 1 || size == 2 || size == 4) &&
	    (offset & (size - 1)) == 0 && vs->vs_vc->vc_cfgwrite != NULL) {
		(void)(*vs->vs_vc->vc_cfgwrite)((void *)vs,
		    offset - VIRTIO_MODERN_DEVICE_OFF, size, value);
	}
	VS_UNLOCK(vs);
}

static bool
vi_modern_cfg_window_valid(struct virtio_softc *vs, uint8_t bar,
    uint32_t offset, uint32_t length)
{
	uint64_t end;

	if (vs->vs_modern == NULL || bar != vs->vs_modern->bar ||
	    (length != 1 && length != 2 && length != 4) ||
	    (offset & (length - 1)) != 0)
		return (false);
	end = (uint64_t)offset + length;
	if (end <= sizeof(struct virtio_pci_common_cfg))
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
	return (false);
}

int
vi_pci_modern_cfgread(struct pci_devinst *pi, int offset, int bytes,
    uint32_t *retval)
{
	struct virtio_softc *vs;
	uint32_t baroff, length;
	uint8_t bar, capoff;

	vs = pi->pi_arg;
	if (!vi_pci_is_modern(vs) || vs->vs_modern == NULL)
		return (1);
	capoff = vs->vs_modern->pci_cfg_capoff;
	if (offset != capoff + offsetof(struct virtio_pci_cfg_cap,
	    pci_cfg_data))
		return (1);
	bar = pci_get_cfgdata8(pi, capoff + VIRTIO_PCI_CAP_BAR);
	baroff = pci_get_cfgdata32(pi, capoff + VIRTIO_PCI_CAP_OFFSET);
	length = pci_get_cfgdata32(pi, capoff + VIRTIO_PCI_CAP_LENGTH);
	if (bytes != (int)length ||
	    !vi_modern_cfg_window_valid(vs, bar, baroff, length)) {
		*retval = UINT32_MAX;
		return (0);
	}
	VIRTIO_PROBE_CFG_WINDOW(bar, baroff, length, 0);
	*retval = vi_pci_modern_read(pi, bar, baroff, length);
	return (0);
}

int
vi_pci_modern_cfgwrite(struct pci_devinst *pi, int offset, int bytes,
    uint32_t value)
{
	struct virtio_softc *vs;
	uint32_t baroff, length;
	uint8_t bar, capoff;

	vs = pi->pi_arg;
	if (!vi_pci_is_modern(vs) || vs->vs_modern == NULL)
		return (1);
	capoff = vs->vs_modern->pci_cfg_capoff;
	if (offset == capoff + VIRTIO_PCI_CAP_BAR && bytes == 1) {
		pci_set_cfgdata8(pi, offset, value);
		return (0);
	}
	if (offset == capoff + VIRTIO_PCI_CAP_OFFSET && bytes == 4) {
		pci_set_cfgdata32(pi, offset, value);
		return (0);
	}
	if (offset == capoff + VIRTIO_PCI_CAP_LENGTH && bytes == 4) {
		pci_set_cfgdata32(pi, offset, value);
		return (0);
	}
	if (offset != capoff + offsetof(struct virtio_pci_cfg_cap,
	    pci_cfg_data))
		return (1);
	bar = pci_get_cfgdata8(pi, capoff + VIRTIO_PCI_CAP_BAR);
	baroff = pci_get_cfgdata32(pi, capoff + VIRTIO_PCI_CAP_OFFSET);
	length = pci_get_cfgdata32(pi, capoff + VIRTIO_PCI_CAP_LENGTH);
	if (bytes == (int)length &&
	    vi_modern_cfg_window_valid(vs, bar, baroff, length)) {
		VIRTIO_PROBE_CFG_WINDOW(bar, baroff, length, 1);
		vi_pci_modern_write(pi, bar, baroff, length, value);
	}
	return (0);
}
