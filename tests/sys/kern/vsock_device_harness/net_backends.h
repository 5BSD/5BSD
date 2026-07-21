/* Minimal network backend interface for the VirtIO net device harness. */
#ifndef MOCK_NET_BACKENDS_H
#define MOCK_NET_BACKENDS_H

#include <sys/types.h>
#include <sys/uio.h>

#include "config.h"
#include "mevent.h"

#define VIRTIO_NET_F_CSUM	(1U << 0)
#define VIRTIO_NET_F_MTU	(1U << 3)
#define VIRTIO_NET_F_MAC	(1U << 5)
#define VIRTIO_NET_F_MRG_RXBUF	(1U << 15)
#define VIRTIO_NET_F_STATUS	(1U << 16)

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
ssize_t netbe_send(net_backend_t *, const struct iovec *, int);
ssize_t netbe_peek_recvlen(net_backend_t *);
ssize_t netbe_recv(net_backend_t *, const struct iovec *, int);
void netbe_rx_disable(net_backend_t *);
void netbe_rx_enable(net_backend_t *);
int netbe_legacy_config(nvlist_t *, const char *);

#endif
