/* SPDX-License-Identifier: BSD-2-Clause */

#include <stdbool.h>
#include <stdint.h>

#include <dev/virtio/vsock/virtio_vsock_var.h>

int
main(void)
{
	if (!virtio_vsock_rx_used_len_valid(0, 0))
		return (1);
	if (!virtio_vsock_rx_used_len_valid(4096, 4096))
		return (2);
	if (virtio_vsock_rx_used_len_valid(4097, 4096))
		return (3);
	if (!virtio_vsock_rx_used_len_valid(UINT32_MAX, UINT32_MAX))
		return (4);
	if (!virtio_vsock_event_used_len_valid(8, 8))
		return (5);
	if (virtio_vsock_event_used_len_valid(7, 8))
		return (6);
	if (virtio_vsock_event_used_len_valid(9, 8))
		return (7);

	return (0);
}
