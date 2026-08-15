/* Minimal network backend interface for the VirtIO net device harness. */
#ifndef MOCK_NET_BACKENDS_H
#define MOCK_NET_BACKENDS_H

#include <sys/types.h>
#include <sys/uio.h>

#include "config.h"
#include "mevent.h"

#define VIRTIO_NET_F_CSUM	(1U << 0)
#define VIRTIO_NET_F_GUEST_CSUM	(1U << 1)
#define VIRTIO_NET_F_MTU	(1U << 3)
#define VIRTIO_NET_F_MAC	(1U << 5)
#define VIRTIO_NET_F_GUEST_TSO4	(1U << 7)
#define VIRTIO_NET_F_GUEST_TSO6	(1U << 8)
#define VIRTIO_NET_F_GUEST_ECN	(1U << 9)
#define VIRTIO_NET_F_GUEST_UFO	(1U << 10)
#define VIRTIO_NET_F_HOST_TSO4	(1U << 11)
#define VIRTIO_NET_F_HOST_TSO6	(1U << 12)
#define VIRTIO_NET_F_HOST_ECN	(1U << 13)
#define VIRTIO_NET_F_HOST_UFO	(1U << 14)
#define VIRTIO_NET_F_MRG_RXBUF	(1U << 15)
#define VIRTIO_NET_F_STATUS	(1U << 16)
#define VIRTIO_NET_F_CTRL_VQ	(1U << 17)
#define VIRTIO_NET_F_MQ		(1U << 22)
#define VIRTIO_NET_F_HASH_REPORT (1ULL << 57)
#define VIRTIO_NET_F_RSS	(1ULL << 60)
#define NETBE_MAX_RECORD_SIZE	(65589U + 12U)
#define NETBE_CHECKPOINT_ID_MAX	255

struct virtio_net_rxhdr {
	uint8_t vrh_flags;
	uint8_t vrh_gso_type;
	uint16_t vrh_hdr_len;
	uint16_t vrh_gso_size;
	uint16_t vrh_csum_start;
	uint16_t vrh_csum_offset;
	uint16_t vrh_bufs;
} __packed;

typedef struct net_backend net_backend_t;
typedef void net_be_rxeof_t(int, enum ev_type, void *);

int netbe_init(net_backend_t **, nvlist_t *, net_be_rxeof_t *, void *);
void netbe_cleanup(net_backend_t *);
uint64_t netbe_get_cap(net_backend_t *);
int netbe_set_cap(net_backend_t *, uint64_t, unsigned int);
size_t netbe_get_vnet_hdr_len(net_backend_t *);
const char *netbe_checkpoint_identity(net_backend_t *);
ssize_t netbe_send(net_backend_t *, const struct iovec *, int);
ssize_t netbe_peek_recvlen(net_backend_t *);
ssize_t netbe_recv(net_backend_t *, const struct iovec *, int);
ssize_t netbe_rx_discard(net_backend_t *);
void netbe_rx_disable(net_backend_t *);
void netbe_rx_enable(net_backend_t *);
int netbe_legacy_config(nvlist_t *, const char *);

#endif
