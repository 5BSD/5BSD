/* Mock of bhyve virtio.h for the vsock device harness: only the surface the
 * device under test (pci_virtio_vsock.c) references. */
#ifndef MOCK_VIRTIO_H
#define MOCK_VIRTIO_H
#include <stdint.h>
#include <sys/uio.h>
struct pci_devinst;
struct virtio_softc { void *vs_mtx; };
struct vqueue_info {
	uint16_t vq_qsize;
	void (*vq_notify)(void *, struct vqueue_info *);
};
struct vi_req { uint16_t idx; int readable, writable; };
struct virtio_consts {
	const char *vc_name;
	int vc_nvq;
	size_t vc_cfgsize;
	void (*vc_reset)(void *);
	int (*vc_cfgread)(void *, int, int, uint32_t *);
	int (*vc_cfgwrite)(void *, int, int, uint32_t);
	void (*vc_apply_features)(void *, uint64_t);
	uint64_t vc_hv_caps;
};
#define VIRTIO_DEV_VSOCK 0x1053
#define VIRTIO_VENDOR    0x1af4
int  vq_has_descs(struct vqueue_info *);
int  vq_getchain(struct vqueue_info *, struct iovec *, int, struct vi_req *);
void vq_relchain(struct vqueue_info *, uint16_t, uint32_t);
void vq_endchains(struct vqueue_info *, int);
void vi_softc_linkup(struct virtio_softc *, struct virtio_consts *, void *,
    struct pci_devinst *, struct vqueue_info *);
int  vi_intr_init(struct virtio_softc *, int, int);
void vi_set_io_bar(struct virtio_softc *, int);
void vi_reset_dev(struct virtio_softc *);
uint64_t vi_pci_read(struct pci_devinst *, int, uint64_t, int);
void vi_pci_write(struct pci_devinst *, int, uint64_t, int, uint64_t);
#endif
