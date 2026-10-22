/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define TAPGV2RXQUEUED 0x100
#define TAPSV2RXFREEZE 0x101
static int queued_bytes, ioctl_error, ioctl_calls, frozen;
static int
fake_ioctl(int fd, unsigned long request, void *value)
{
	assert(fd == 7 && (request == TAPGV2RXQUEUED ||
	    request == TAPSV2RXFREEZE));
	ioctl_calls++;
	if (ioctl_error != 0) {
		errno = ioctl_error;
		return (-1);
	}
	if (request == TAPGV2RXQUEUED)
		*(int *)value = queued_bytes;
	else
		frozen = *(int *)value;
	return (0);
}
#define ioctl fake_ioctl
struct tap_priv { size_t bbuflen; };
struct net_backend {
	int fd;
	struct tap_priv priv;
	int (*tagging_enable_v2)(struct net_backend *);
	int (*checkpoint_rx_quiescent)(struct net_backend *);
	int (*checkpoint_rx_freeze)(struct net_backend *, bool);
};
#define NET_BE_PRIV(be) (&(be)->priv)
#include "packet-v2-backend-checkpoint.inc"
#include "packet-v2-backend-capability.inc"

static int
enable_v2(struct net_backend *be)
{
	assert(be != NULL);
	return (0);
}

struct vqueue_info { bool allocated, pending, unreadable; };
struct pci_vtnet_softc {
	bool packet_id_v2_enabled;
	uint16_t vsc_max_pairs;
	struct vqueue_info vsc_queues[6];
};
static unsigned
pci_vtnet_txq_index(uint16_t pair)
{
	return (pair * 2 + 1);
}
static int
vq_checkpoint_has_descs(struct vqueue_info *vq, bool *pending)
{
	*pending = false;
	if (!vq->allocated)
		return (0);
	if (vq->unreadable)
		return (EFAULT);
	*pending = vq->pending;
	return (0);
}
#include "packet-v2-checkpoint.inc"

int
main(void)
{
	struct pci_vtnet_softc sc = { .vsc_max_pairs = 3 };

	sc.vsc_queues[5].allocated = sc.vsc_queues[5].pending = true;
	assert(pci_vtnet_v2_tx_quiescent(&sc) == 0);
	sc.packet_id_v2_enabled = true;
	assert(pci_vtnet_v2_tx_quiescent(&sc) == EBUSY);
	sc.vsc_queues[5].pending = false;
	assert(pci_vtnet_v2_tx_quiescent(&sc) == 0);
	sc.vsc_queues[3].allocated = sc.vsc_queues[3].pending = true;
	assert(pci_vtnet_v2_tx_quiescent(&sc) == EBUSY);
	sc.vsc_queues[3].pending = false;
	sc.vsc_queues[3].unreadable = true;
	assert(pci_vtnet_v2_tx_quiescent(&sc) == EFAULT);
	sc.vsc_queues[3].allocated = false;
	assert(pci_vtnet_v2_tx_quiescent(&sc) == 0);
	struct net_backend backend = { .fd = 7 };
	assert(tap_checkpoint_rx_quiescent(&backend) == 0);
	backend.priv.bbuflen = 48;
	assert(tap_checkpoint_rx_quiescent(&backend) == EBUSY);
	assert(ioctl_calls == 1);
	backend.priv.bbuflen = 0;
	queued_bytes = 64;
	assert(tap_checkpoint_rx_quiescent(&backend) == EBUSY);
	queued_bytes = -1;
	assert(tap_checkpoint_rx_quiescent(&backend) == EIO);
	queued_bytes = 0;
	ioctl_error = ENOTTY;
	assert(tap_checkpoint_rx_quiescent(&backend) == ENOTTY);
	ioctl_error = 0;
	assert(tap_checkpoint_rx_quiescent(&backend) == 0);
	assert(tap_checkpoint_rx_freeze(&backend, true) == 0 && frozen == 1);
	assert(tap_checkpoint_rx_freeze(&backend, false) == 0 && frozen == 0);
	ioctl_error = EACCES;
	assert(tap_checkpoint_rx_freeze(&backend, true) == EACCES &&
	    frozen == 0);
	ioctl_error = 0;
	backend.fd = -1;
	assert(tap_checkpoint_rx_freeze(&backend, true) == EBADF);
	backend.tagging_enable_v2 = enable_v2;
	backend.checkpoint_rx_quiescent = tap_checkpoint_rx_quiescent;
	backend.checkpoint_rx_freeze = tap_checkpoint_rx_freeze;
	assert(netbe_tagging_v2_supported(&backend));
	assert(netbe_tagging_enable_v2(&backend) == 0);
	backend.checkpoint_rx_freeze = NULL;
	assert(!netbe_tagging_v2_supported(&backend));
	errno = 0;
	assert(netbe_tagging_enable_v2(&backend) == -1 &&
	    errno == EOPNOTSUPP);
	backend.checkpoint_rx_freeze = tap_checkpoint_rx_freeze;
	backend.checkpoint_rx_quiescent = NULL;
	assert(!netbe_tagging_v2_supported(&backend));
	backend.checkpoint_rx_quiescent = tap_checkpoint_rx_quiescent;
	backend.tagging_enable_v2 = NULL;
	assert(!netbe_tagging_v2_supported(&backend));
	assert(!netbe_tagging_v2_supported(NULL));
	errno = 0;
	assert(netbe_tagging_enable_v2(NULL) == -1 &&
	    errno == EOPNOTSUPP);
	puts("PASS: V2 checkpoint checks TX rings and queued TAP receive packets");
	return (0);
}
