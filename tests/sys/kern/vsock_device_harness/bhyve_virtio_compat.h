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

#endif /* _BHYVE_VIRTIO_COMPAT_H_ */
