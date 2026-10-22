/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Private 5BSD VirtIO-net packet provenance extension.  This is deliberately
 * negotiated through the control queue: the standard network feature bitmap
 * has no vendor-reserved bit.  Other devices reply VIRTIO_NET_ERR and retain
 * standard framing.
 */
#ifndef _DEV_VIRTIO_NETWORK_VIRTIO_NET_5BSD_H_
#define _DEV_VIRTIO_NETWORK_VIRTIO_NET_5BSD_H_

#define VIRTIO_NET_CTRL_5BSD		0x80
#define VIRTIO_NET_CTRL_5BSD_PACKET_ID	0
#define VIRTIO_NET_CTRL_5BSD_PACKET_ID_V2	1
#define VIRTIO_NET_5BSD_MAGIC		"5BSDID01"
#define VIRTIO_NET_5BSD_MAGIC_LEN	8
#define VIRTIO_NET_5BSD_ID_LEN		32
#define VIRTIO_NET_5BSD_V2_MAGIC		"5BSDID02"
#define VIRTIO_NET_5BSD_V2_ID_LEN	48
#define VIRTIO_NET_5BSD_CMD_LEN		(2 + VIRTIO_NET_5BSD_MAGIC_LEN + 1)

#endif
