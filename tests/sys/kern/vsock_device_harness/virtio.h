/* Mock of bhyve virtio.h for the vsock device harness: only the surface the
 * device under test (pci_virtio_vsock.c) references. */
#ifndef MOCK_VIRTIO_H
#define MOCK_VIRTIO_H
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/uio.h>
#include <dev/virtio/virtio_config.h>
#include <dev/virtio/virtio_ring.h>
struct pci_devinst;
struct virtio_pci_modern;
struct vm_snapshot_meta;
enum virtio_pci_transport {
	VIRTIO_PCI_TRANSPORT_LEGACY,
	VIRTIO_PCI_TRANSPORT_MODERN,
};
struct virtio_consts;
struct virtio_softc {
	struct virtio_consts *vs_vc;
	int vs_flags;
	pthread_mutex_t *vs_mtx;
	pthread_mutex_t vs_isr_mtx;
	struct pci_devinst *vs_pi;
	uint32_t vs_negotiated_caps;
	struct vqueue_info *vs_queues;
	int vs_curq;
	uint8_t vs_status;
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
struct vqueue_info {
	uint16_t vq_qsize;
	void (*vq_notify)(void *, struct vqueue_info *);
	struct virtio_softc *vq_vs;
	uint16_t vq_num;
	uint16_t vq_flags;
	uint16_t vq_last_avail;
	uint16_t vq_next_used;
	uint16_t vq_save_used;
	uint16_t vq_msix_idx;
	uint32_t vq_pfn;
	uint16_t vq_qsize_max;
	uint16_t vq_enabled;
	uint64_t vq_desc_gpa;
	uint64_t vq_driver_gpa;
	uint64_t vq_device_gpa;
	struct vring_desc *vq_desc;
	struct vring_avail *vq_avail;
	struct vring_used *vq_used;
};
struct vi_req { uint16_t idx; int readable, writable; };
struct virtio_consts {
	const char *vc_name;
	int vc_nvq;
	size_t vc_cfgsize;
	void (*vc_reset)(void *);
	void (*vc_qnotify)(void *, struct vqueue_info *);
	int (*vc_cfgread)(void *, int, int, uint32_t *);
	int (*vc_cfgwrite)(void *, int, int, uint32_t);
	void (*vc_apply_features)(void *, uint64_t);
	uint64_t vc_hv_caps;
	void (*vc_pause)(void *);
	void (*vc_resume)(void *);
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
#define VIRTIO_DEV_VSOCK 0x1013
#define VIRTIO_ID_VSOCK  19
#define VIRTIO_DEV_INPUT 0x1052
#define VIRTIO_ID_INPUT  18
#define VIRTIO_DEV_RANDOM 0x1005
#define VIRTIO_ID_ENTROPY 4
#define VIRTIO_DEV_CONSOLE 0x1003
#define VIRTIO_ID_CONSOLE 3
#define VIRTIO_DEV_9P 0x1009
#define VIRTIO_ID_9P 9
#define VIRTIO_REV_INPUT 1
#define VIRTIO_SUBVEN_INPUT 0x108e
#define VIRTIO_SUBDEV_INPUT 0x1100
#define VIRTIO_VENDOR    0x1af4
static inline int
vq_ring_ready(struct vqueue_info *vq)
{
	return ((vq->vq_flags & VQ_ALLOC) != 0 &&
	    (vq->vq_vs->vs_transport != VIRTIO_PCI_TRANSPORT_MODERN ||
	    (vq->vq_vs->vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0));
}
static inline void
vq_kick_enable(struct vqueue_info *vq)
{
	vq->vq_used->flags &= ~VRING_USED_F_NO_NOTIFY;
}
static inline void
vq_kick_disable(struct vqueue_info *vq)
{
	vq->vq_used->flags |= VRING_USED_F_NO_NOTIFY;
}
#define VQ_USED_EVENT_IDX(vq) ((vq)->vq_avail->ring[(vq)->vq_qsize])
void mock_vq_interrupt(struct virtio_softc *, struct vqueue_info *);
static inline void
vq_interrupt(struct virtio_softc *vs, struct vqueue_info *vq)
{
	mock_vq_interrupt(vs, vq);
}
int  vq_has_descs(struct vqueue_info *);
int  vq_getchain(struct vqueue_info *, struct iovec *, int, struct vi_req *);
void vq_retchains(struct vqueue_info *, uint16_t);
void vq_relchain(struct vqueue_info *, uint16_t, uint32_t);
void vq_endchains(struct vqueue_info *, int);
void vi_softc_linkup(struct virtio_softc *, struct virtio_consts *, void *,
    struct pci_devinst *, struct vqueue_info *);
int  vi_pci_select_transport(struct virtio_softc *, const nvlist_t *,
    enum virtio_pci_transport_policy);
bool vi_pci_is_modern(const struct virtio_softc *);
void vi_pci_notify_queue(struct virtio_softc *, uint64_t);
int  vi_pci_modern_init(struct virtio_softc *, int);
void vi_pci_modern_set_identity(struct virtio_softc *, uint16_t);
void vi_pci_modern_reset(struct virtio_softc *);
void vi_pci_modern_config_changed(struct virtio_softc *);
uint64_t vi_pci_modern_read(struct pci_devinst *, int, uint64_t, int);
void vi_pci_modern_write(struct pci_devinst *, int, uint64_t, int, uint64_t);
int  vi_pci_modern_cfgread(struct pci_devinst *, int, int, uint32_t *);
int  vi_pci_modern_cfgwrite(struct pci_devinst *, int, int, uint32_t);
int  vi_intr_init(struct virtio_softc *, int, int);
void vi_set_io_bar(struct virtio_softc *, int);
void vi_reset_dev(struct virtio_softc *);
uint64_t vi_pci_read(struct pci_devinst *, int, uint64_t, int);
void vi_pci_write(struct pci_devinst *, int, uint64_t, int, uint64_t);
#endif
