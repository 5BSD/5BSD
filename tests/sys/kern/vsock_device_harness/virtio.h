/* Mock of bhyve virtio.h for the vsock device harness: only the surface the
 * device under test (pci_virtio_vsock.c) references. */
#ifndef MOCK_VIRTIO_H
#define MOCK_VIRTIO_H
#include <sys/endian.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <machine/atomic.h>
#include <sys/uio.h>
#include <dev/virtio/virtio_config.h>
#include <dev/virtio/virtio_ring.h>
#include "virtio_dma.h"
struct pci_devinst;
struct virtio_pci_modern;
struct virtio_packed_desc;
struct virtio_packed_event;
struct vm_snapshot_meta;
enum virtio_pci_transport {
	VIRTIO_PCI_TRANSPORT_LEGACY,
	VIRTIO_PCI_TRANSPORT_MODERN,
};
struct virtio_consts;
struct virtio_admin_pci_binding;
struct virtio_softc {
	struct virtio_consts *vs_vc;
	int vs_flags;
	pthread_mutex_t *vs_mtx;
	pthread_mutex_t vs_isr_mtx;
	struct pci_devinst *vs_pi;
	uint64_t vs_negotiated_caps;
	struct vqueue_info *vs_queues;
	struct vqueue_info *vs_admin_queues;
	uint16_t vs_admin_queue_index;
	uint16_t vs_admin_queue_count;
	struct virtio_admin_pci_binding *vs_admin_binding;
	int vs_curq;
	uint8_t vs_status;
	_Atomic bool vs_resetting;
	bool vs_reset_failed;
	bool vs_restore_incomplete;
	_Atomic unsigned int vs_quiescing;
	bool vs_suspended;
	bool vs_checkpoint_paused;
	bool vs_config_deferred;
	uint8_t vs_isr;
	uint16_t vs_msix_cfg_idx;
	enum virtio_pci_transport vs_transport;
	struct virtio_pci_modern *vs_modern;
};
enum virtio_pci_transport_policy {
	VIRTIO_PCI_LEGACY_DEFAULT,
	VIRTIO_PCI_MODERN_DEFAULT,
	VIRTIO_PCI_MODERN_ONLY,
};
enum virtio_queue_layout {
	VIRTIO_QUEUE_SPLIT,
	VIRTIO_QUEUE_PACKED,
};
struct vqueue_info {
	uint16_t vq_qsize;
	void (*vq_notify)(void *, struct vqueue_info *);
	struct virtio_softc *vq_vs;
	uint16_t vq_num;
	enum virtio_queue_layout vq_layout;
	uint16_t vq_flags;
	uint16_t vq_last_avail;
	uint16_t vq_next_used;
	uint16_t vq_save_used;
	uint16_t vq_msix_idx;
	uint32_t vq_pfn;
	uint16_t vq_qsize_max;
	uint16_t vq_enabled;
	uint16_t vq_reset;
	volatile uint16_t vq_resetting;
	bool vq_notify_pending;
	uint64_t vq_generation;
	uint64_t vq_desc_gpa;
	uint64_t vq_driver_gpa;
	uint64_t vq_device_gpa;
	struct vring_desc *vq_desc;
	struct vring_avail *vq_avail;
	struct vring_used *vq_used;
	struct virtio_packed_desc *vq_packed_desc;
	struct virtio_packed_event *vq_packed_driver_event;
	struct virtio_packed_event *vq_packed_device_event;
	uint16_t vq_packed_next_avail;
	uint16_t vq_packed_next_used;
	uint16_t vq_packed_save_used;
	bool vq_packed_avail_wrap;
	bool vq_packed_used_wrap;
	bool vq_packed_save_used_wrap;
};
struct vi_req {
	int readable, writable;
	uint64_t writable_bytes;
	bool ordered;
	bool lengths_known;
	unsigned int idx;
	uint16_t descriptor_count;
	uint16_t completion_id;
	/* Split acquisition cursor used to prove tail-only request return. */
	uint16_t split_avail_next;
	uint16_t packed_head;
	bool packed_wrap;
	enum virtio_queue_layout queue_layout;
	uint64_t queue_generation;
	bool dma_acquired;
	bool outstanding;
};
struct virtio_consts {
	const char *vc_name;
	int vc_nvq;
	size_t vc_cfgsize;
	void (*vc_reset)(void *);
	void (*vc_qnotify)(void *, struct vqueue_info *);
	int (*vc_cfgread)(void *, int, int, uint32_t *);
	int (*vc_cfgwrite)(void *, int, int, uint32_t);
	int (*vc_apply_features)(void *, uint64_t);
	int (*vc_qenable)(void *, struct vqueue_info *);
	int (*vc_qreset)(void *, struct vqueue_info *, uint64_t);
	int (*vc_suspend)(void *);
	int (*vc_resume_device)(void *);
	void (*vc_resume_complete)(void *);
	void (*vc_restore_suspended)(void *);
	void (*vc_restore_resumed)(void *);
	uint64_t vc_hv_caps;
	bool vc_access_platform_ineligible;
	int (*vc_pause)(void *);
	int (*vc_resume)(void *);
	int (*vc_snapshot)(void *, struct vm_snapshot_meta *);
};
#define VQ_ALLOC 0x01
#define VQ_BROKED 0x02
#define VIRTIO_USE_MSIX 0x01
#define VIRTIO_EVENT_IDX 0x02
#define VIRTIO_BROKED 0x08
#define VRING_PFN 12
#define VRING_ALIGN 4096
#define vring_size_aligned(n) vring_size((n), VRING_ALIGN)
#ifndef VIRTIO_MSI_NO_VECTOR
#define VIRTIO_MSI_NO_VECTOR 0xffff
#endif
#define VS_LOCK(vs) do { if ((vs)->vs_mtx != NULL) \
	pthread_mutex_lock((vs)->vs_mtx); } while (0)
#define VS_UNLOCK(vs) do { if ((vs)->vs_mtx != NULL) \
	pthread_mutex_unlock((vs)->vs_mtx); } while (0)
#define VIRTIO_PCI_COMPAT_VSOCK_DEVICE 0x1013
#define VIRTIO_ID_VSOCK  19
#define VIRTIO_PCI_COMPAT_INPUT_DEVICE 0x1052
#define VIRTIO_ID_INPUT  18
#define VIRTIO_PCI_TRANSITIONAL_ENTROPY 0x1005
#define VIRTIO_ID_ENTROPY 4
#define VIRTIO_PCI_TRANSITIONAL_CONSOLE 0x1003
#define VIRTIO_ID_CONSOLE 3
#define VIRTIO_PCI_TRANSITIONAL_9P 0x1009
#define VIRTIO_ID_9P 9
#define VIRTIO_PCI_TRANSITIONAL_BLOCK 0x1001
#define VIRTIO_ID_BLOCK 2
#define VIRTIO_PCI_TRANSITIONAL_NET 0x1000
#define VIRTIO_ID_NETWORK 1
#define VIRTIO_PCI_TRANSITIONAL_SCSI 0x1004
#define VIRTIO_ID_SCSI 8
#define VIRTIO_ID_BALLOON 5
#define VIRTIO_ID_MEM 24
#define VIRTIO_PCI_COMPAT_INPUT_REVISION 1
#define VIRTIO_PCI_COMPAT_INPUT_SUBVENDOR 0x108e
#define VIRTIO_PCI_COMPAT_INPUT_SUBDEVICE 0x1100
#define VIRTIO_VENDOR    0x1af4
#define VIRTIO_PCI_ISR_CONFIG 0x2
static inline int
vq_is_allocated(const struct vqueue_info *vq)
{
	return ((atomic_load_acq_16(&vq->vq_flags) & VQ_ALLOC) != 0);
}
static inline void
vq_set_allocated(struct vqueue_info *vq, bool allocated)
{
	atomic_store_rel_16(&vq->vq_flags, allocated ? VQ_ALLOC : 0);
}
static inline int
vq_is_resetting(const struct vqueue_info *vq)
{
	return (atomic_load_acq_16(&vq->vq_resetting) != 0);
}
static inline void
vq_set_resetting(struct vqueue_info *vq, bool resetting)
{
	atomic_store_rel_16(&vq->vq_resetting, resetting ? 1 : 0);
}
static inline int
vq_ring_ready(struct vqueue_info *vq)
{
	return (vq_is_allocated(vq) &&
	    !vq_is_resetting(vq) &&
	    !vq->vq_vs->vs_quiescing && !vq->vq_vs->vs_suspended &&
	    !vq->vq_vs->vs_checkpoint_paused &&
	    (vq->vq_vs->vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0);
}
static inline uint16_t
vi16_to_cpu(const struct virtio_softc *vs, uint16_t value)
{
	return ((vs->vs_negotiated_caps & VIRTIO_F_VERSION_1) != 0 ?
	    le16toh(value) : value);
}
static inline uint16_t
vi16_from_cpu(const struct virtio_softc *vs, uint16_t value)
{
	return ((vs->vs_negotiated_caps & VIRTIO_F_VERSION_1) != 0 ?
	    htole16(value) : value);
}
static inline uint16_t
vq_avail_event_idx(const struct vqueue_info *vq)
{
	uint16_t value;
	memcpy(&value, &vq->vq_used->ring[vq->vq_qsize], sizeof(value));
	return (vi16_to_cpu(vq->vq_vs, value));
}
static inline void
vq_set_avail_event_idx(struct vqueue_info *vq, uint16_t value)
{
	uint16_t encoded;
	encoded = vi16_from_cpu(vq->vq_vs, value);
	memcpy(&vq->vq_used->ring[vq->vq_qsize], &encoded, sizeof(encoded));
}
static inline uint16_t
vq_used_event_idx(const struct vqueue_info *vq)
{
	uint16_t value;
	memcpy(&value, &vq->vq_avail->ring[vq->vq_qsize], sizeof(value));
	return (vi16_to_cpu(vq->vq_vs, value));
}
static inline void
vq_kick_enable(struct vqueue_info *vq)
{
	if (vq->vq_vs != NULL &&
	    (vq->vq_vs->vs_negotiated_caps &
	    VIRTIO_RING_F_EVENT_IDX) != 0) {
		vq->vq_used->flags = vi16_from_cpu(vq->vq_vs, 0);
		vq_set_avail_event_idx(vq, vq->vq_last_avail);
	} else
		vq->vq_used->flags = 0;
}
static inline void
vq_kick_disable(struct vqueue_info *vq)
{
	if (vq->vq_vs != NULL &&
	    (vq->vq_vs->vs_negotiated_caps &
	    VIRTIO_RING_F_EVENT_IDX) != 0) {
		vq->vq_used->flags = vi16_from_cpu(vq->vq_vs, 0);
		vq_set_avail_event_idx(vq, vq->vq_last_avail - 1);
	} else
		vq->vq_used->flags = vi16_from_cpu(vq->vq_vs,
		    VRING_USED_F_NO_NOTIFY);
}
void mock_vq_interrupt(struct virtio_softc *, struct vqueue_info *);
static inline void
vq_interrupt(struct virtio_softc *vs, struct vqueue_info *vq)
{
	if (vq_is_resetting(vq))
		return;
	mock_vq_interrupt(vs, vq);
}
int  vq_has_descs(struct vqueue_info *);
int  vq_getchain(struct vqueue_info *, struct iovec *, int, struct vi_req *);
void vq_retchains(struct vqueue_info *, uint16_t);
static inline void
vq_retchain_req(struct vqueue_info *vq, struct vi_req *req)
{

	req->outstanding = false;
	vq_retchains(vq, 1);
}
static inline void
vq_discard_req(struct vqueue_info *vq __unused, struct vi_req *req)
{

#ifdef VQ_DISCARD_REQ_OBSERVER
	VQ_DISCARD_REQ_OBSERVER(vq, req);
#endif
	req->outstanding = false;
}
void vq_relchain(struct vqueue_info *, uint16_t, uint32_t);
static inline void
vq_relchain_req(struct vqueue_info *vq, struct vi_req *req, uint32_t len)
{

	vq_relchain(vq, req->idx, len);
	req->outstanding = false;
}
void vq_relchain_prepare(struct vqueue_info *, uint16_t, uint32_t);
void vq_relchain_publish(struct vqueue_info *);
static inline void
vq_relchain_group(struct vqueue_info *vq, struct vi_req *reqs,
    const uint32_t *lens, unsigned int nreqs)
{
	unsigned int i;

	for (i = 0; i < nreqs; i++)
		vq_relchain_prepare(vq, reqs[i].idx, lens[i]);
	vq_relchain_publish(vq);
}
void vq_endchains(struct vqueue_info *, int);
void vi_softc_linkup(struct virtio_softc *, struct virtio_consts *, void *,
    struct pci_devinst *, struct vqueue_info *);
int  vi_pci_select_transport(struct virtio_softc *, const nvlist_t *,
    enum virtio_pci_transport_policy);
bool vi_pci_is_modern(const struct virtio_softc *);
struct virtio_softc *vi_pci_get_softc(struct pci_devinst *);
bool vi_pci_access_platform_eligible(const struct virtio_softc *);
int vi_set_dma_domain(struct virtio_softc *,
    const struct virtio_dma_domain_ops *, void *, uint32_t);
int vi_clear_dma_domain(struct virtio_softc *);
bool vi_dma_acquire(struct virtio_softc *, struct virtio_dma_lease *);
void vi_dma_release(struct virtio_softc *, struct virtio_dma_lease *);
void *vi_map_dma(struct virtio_softc *, uint64_t, size_t,
    enum virtio_dma_direction);
void vi_pci_notify_queue(struct virtio_softc *, uint64_t);
int vi_pci_stage_admin_queues(struct virtio_softc *, struct vqueue_info *,
    uint16_t, uint16_t);
bool vi_pci_queue_is_admin(const struct virtio_softc *,
    const struct vqueue_info *);
int  vi_pci_lifecycle_noop(void *);
static inline void
vq_packed_completions_reset(struct vqueue_info *vq __unused)
{
}
void vi_pci_quiesce_enter(struct virtio_softc *);
void vi_pci_quiesce_exit(struct virtio_softc *);
void vi_pci_notify_ready_queues(struct virtio_softc *);
int  vi_pci_modern_init(struct virtio_softc *, int);
void vi_pci_modern_set_identity(struct virtio_softc *, uint16_t);
int vi_pci_modern_add_shared_memory(struct virtio_softc *, uint8_t, uint8_t,
    uint64_t, uint64_t);
int vi_pci_modern_set_shared_memory_backing(struct virtio_softc *, uint8_t,
    void *, uint64_t, bool);
void vi_pci_modern_seal_shared_memory(struct virtio_softc *);
int vi_pci_modern_set_shared_memory_handler(struct virtio_softc *, uint8_t,
    uint64_t, bool, void *, int (*)(void *, uint64_t, int, uint64_t *),
    int (*)(void *, uint64_t, int, uint64_t));
void vi_pci_modern_reset(struct virtio_softc *);
void vi_pci_modern_queue_reset_complete(struct vqueue_info *, uint64_t, int);
void vi_pci_modern_config_changed(struct virtio_softc *);
void vi_pci_config_changed(struct virtio_softc *);
uint64_t vi_pci_modern_read(struct pci_devinst *, int, uint64_t, int);
void vi_pci_modern_write(struct pci_devinst *, int, uint64_t, int, uint64_t);
int  vi_pci_modern_cfgread(struct pci_devinst *, int, int, uint32_t *);
int  vi_pci_modern_cfgwrite(struct pci_devinst *, int, int, uint32_t);
int  vi_intr_init(struct virtio_softc *, int, int);
void vi_set_io_bar(struct virtio_softc *, int);
void vi_reset_dev(struct virtio_softc *);
void vi_set_needs_reset(struct virtio_softc *);
void vi_snapshot_restore_incomplete(struct virtio_softc *);
void vi_pci_modern_config_dirty(struct virtio_softc *);
size_t vi_platform_ram_page_size(struct virtio_softc *);
int vi_platform_discard_ram(struct virtio_softc *, uint64_t, size_t);
int vi_platform_undiscard_ram(struct virtio_softc *, uint64_t, size_t);
int vi_platform_reverse_ram(struct virtio_softc *, void *, size_t, uint64_t *);
int vi_config_read_le(const void *, size_t, int, int, uint32_t *);
void vi_interrupt(struct virtio_softc *, uint8_t, uint16_t);
uint64_t vi_pci_read(struct pci_devinst *, int, uint64_t, int);
void vi_pci_write(struct pci_devinst *, int, uint64_t, int, uint64_t);
#ifdef BHYVE_SNAPSHOT
int  vi_pci_snapshot(struct vm_snapshot_meta *);
int  vi_pci_snapshot_compat(struct pci_devinst *,
    struct pci_snapshot_compat *);
int  vi_pci_pause(struct pci_devinst *);
int  vi_pci_resume(struct pci_devinst *);
#endif
#endif
