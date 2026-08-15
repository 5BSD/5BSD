/*
 * Independent expectations for documented bhyve compatibility extensions.
 *
 * These values are deliberately separate from virtio_1_4_spec.h: they are
 * stable bhyve interfaces which the VirtIO standard does not define.
 */
#ifndef _BHYVE_VIRTIO_COMPAT_H_
#define _BHYVE_VIRTIO_COMPAT_H_

/*
 * bhyve(8), virtio-input: explicit transport=legacy retains the historical
 * modern input device ID while exposing the legacy register interface.
 * VirtIO 1.4 section 4.1.2.1 assigns no transitional input device ID.
 */
#define	BHYVE_COMPAT_VIRTIO_INPUT_LEGACY_DEVICE_ID	0x1052U
#define	BHYVE_COMPAT_VIRTIO_INPUT_LEGACY_REVISION	1U
#define	BHYVE_COMPAT_VIRTIO_INPUT_LEGACY_SUBVENDOR	0x108eU
#define	BHYVE_COMPAT_VIRTIO_INPUT_LEGACY_SUBDEVICE	0x1100U

/*
 * bhyve(8), virtio-vsock: explicit transport=legacy retains the historical
 * non-transitional identity used by the Linux and 5BSD live matrices.
 * VirtIO 1.4 section 4.1.2.1 assigns no transitional vsock device ID.
 */
#define	BHYVE_COMPAT_VIRTIO_VSOCK_LEGACY_DEVICE_ID	0x1013U
#define	BHYVE_COMPAT_VIRTIO_VSOCK_LEGACY_VENDOR	0x1af4U
#define	BHYVE_COMPAT_VIRTIO_VSOCK_LEGACY_SUBDEVICE	19U
#define	BHYVE_COMPAT_VIRTIO_VSOCK_LEGACY_SUBVENDOR	0x1af4U

#endif /* _BHYVE_VIRTIO_COMPAT_H_ */
