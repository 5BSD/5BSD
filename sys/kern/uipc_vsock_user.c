/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

/* Privileged userspace packet transport for the kernel AF_VSOCK domain. */

#include "opt_mac.h"

#include <sys/param.h>
#include <sys/callout.h>
#include <sys/conf.h>
#include <sys/counter.h>
#include <sys/endian.h>
#include <sys/event.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/selinfo.h>
#include <sys/sdt.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/vsock.h>

#include <kern/uipc_vsock.h>

#include <security/audit/audit.h>
#ifdef MAC
#include <security/mac/mac_framework.h>
#endif

SDT_PROVIDER_DECLARE(vsock);
SDT_PROBE_DEFINE2(vsock, , , provider__attach,
    "uint32_t",	/* guest CID */
    "uint64_t");	/* negotiated device features */
SDT_PROBE_DEFINE1(vsock, , , provider__detach,
    "uint32_t");	/* guest CID */
SDT_PROBE_DEFINE1(vsock, , , provider__reset,
    "uint32_t");	/* guest CID */
SDT_PROBE_DEFINE2(vsock, , , provider__features,
    "uint32_t",	/* guest CID */
    "uint64_t");	/* negotiated device features */
SDT_PROBE_DEFINE4(vsock, , , provider__enqueue,
    "uint32_t",	/* guest CID */
    "uint16_t",	/* packet operation */
    "uint32_t",	/* payload bytes */
    "uint32_t");	/* queue depth */
SDT_PROBE_DEFINE4(vsock, , , provider__dequeue,
    "uint32_t",	/* guest CID */
    "uint16_t",	/* packet operation */
    "uint32_t",	/* payload bytes */
    "uint32_t");	/* queue depth */
SDT_PROBE_DEFINE3(vsock, , , provider__inject,
    "uint32_t",	/* guest CID */
    "uint16_t",	/* packet operation */
    "uint32_t");	/* payload bytes */
SDT_PROBE_DEFINE3(vsock, , , provider__backpressure,
    "uint32_t",	/* guest CID */
    "uint32_t",	/* queue depth */
    "int");	/* control packet */
SDT_PROBE_DEFINE3(vsock, , , provider__reject,
    "uint32_t",	/* guest CID */
    "uint32_t",	/* packet bytes */
    "int");	/* errno */

#define	VSOCK_USER_QUEUE_MAX		128
#define	VSOCK_USER_QUEUE_DATA_HIWAT	64
#define	VSOCK_USER_PROVIDER_BUCKETS	256
#define	VSOCK_USER_PROVIDER_MASK	(VSOCK_USER_PROVIDER_BUCKETS - 1)

struct vsock_user_packet {
	STAILQ_ENTRY(vsock_user_packet) link;
	size_t len;
	uint8_t data[];
};
STAILQ_HEAD(vsock_user_packet_queue, vsock_user_packet);

struct vsock_user_knote {
	LIST_ENTRY(vsock_user_knote) link;
	struct vsock_user_provider *provider;
	struct ucred *cred;
};
LIST_HEAD(vsock_user_knote_list, vsock_user_knote);

struct vsock_user_provider {
	LIST_ENTRY(vsock_user_provider) link;
	struct vsock_user_packet_queue queue;
	struct vsock_user_knote_list knotes;
	struct selinfo sel;
	struct thread *write_thread;
	struct vsock_user_packet *write_packet;
	uint32_t guest_cid;
	uint32_t queue_count;
	u_int read_inflight;
	uint64_t generation;
	uint64_t features;
	bool write_reserved;
	bool registered;
#ifdef MAC
	struct label *provider_label;
	struct ucred *attach_cred;
#endif
};

LIST_HEAD(vsock_user_provider_head, vsock_user_provider);
/*
 * The socket domain owns one stable vsock_user_transport, while this table
 * multiplexes independent VMM descriptors by their remote guest CID.  Socket
 * PCBs retain only the stable transport pointer; provider objects are looked
 * up under vtvsock_mtx for every operation and are never retained across a
 * sleep.  This lets one provider detach without invalidating another guest's
 * PCBs or leaving a sleeping sender with a freed provider pointer.
 */
static struct vsock_user_provider_head
    vsock_user_providers[VSOCK_USER_PROVIDER_BUCKETS];
static u_int vsock_user_provider_count;
static u_int vsock_user_stream_provider_count;
static u_int vsock_user_seqpacket_provider_count;
static struct cdev *vsock_cdev;

SYSCTL_DECL(_kern_vsock);
static int
sysctl_vsock_user_provider_count(SYSCTL_HANDLER_ARGS)
{
	u_int count;

	mtx_lock(&vtvsock_mtx);
	count = vsock_user_provider_count;
	mtx_unlock(&vtvsock_mtx);
	return (SYSCTL_OUT(req, &count, sizeof(count)));
}
SYSCTL_PROC(_kern_vsock, OID_AUTO, userspace_providers,
    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_vsock_user_provider_count, "IU",
    "Number of attached /dev/vsock transport providers");

static int vsock_user_send(struct vtvsock_pcb *, int, struct mbuf *,
    struct sockaddr *, struct mbuf *, struct thread *);
static int vsock_user_send_seqpacket(struct vtvsock_pcb *, bool,
    struct mbuf *, size_t);
static int vsock_user_disconnect(struct vtvsock_pcb *);
static int vsock_user_shutdown(struct vtvsock_pcb *, enum shutdown_how);
static bool vsock_user_tx_ready(struct vtvsock_pcb *);
static int vsock_user_send_pkt(struct vtvsock_pcb *, uint16_t, uint32_t,
    const void *, size_t);
static int vsock_user_send_rst(uint64_t, uint32_t, uint64_t, uint32_t,
    uint16_t);
static void vsock_user_send_credit_update(struct vtvsock_pcb *);

static const struct vtvsock_transport vsock_user_transport = {
	.send = vsock_user_send,
	.disconnect = vsock_user_disconnect,
	.shutdown = vsock_user_shutdown,
	.tx_ready = vsock_user_tx_ready,
	.send_pkt = vsock_user_send_pkt,
	.send_rst = vsock_user_send_rst,
	.send_credit_update = vsock_user_send_credit_update,
};

static bool
vsock_user_features_valid(uint64_t features)
{
	const uint64_t known = VIRTIO_VSOCK_F_STREAM |
	    VIRTIO_VSOCK_F_SEQPACKET | VIRTIO_VSOCK_F_NO_IMPLIED_STREAM;

	return ((features & ~known) == 0);
}

static u_int
vsock_user_bucket(uint64_t guest_cid)
{
	uint32_t hash;

	hash = (uint32_t)guest_cid ^ (uint32_t)(guest_cid >> 32);
	hash ^= hash >> 16;
	hash *= UINT32_C(0x7feb352d);
	hash ^= hash >> 15;
	return (hash & VSOCK_USER_PROVIDER_MASK);
}

static bool
vsock_user_features_support_type(uint64_t features, uint16_t type)
{
	if (type == VIRTIO_VSOCK_TYPE_SEQPACKET)
		return ((features & VIRTIO_VSOCK_F_SEQPACKET) != 0);
	if (type != VIRTIO_VSOCK_TYPE_STREAM)
		return (false);
	return ((features & VIRTIO_VSOCK_F_STREAM) != 0 ||
	    (features & VIRTIO_VSOCK_F_NO_IMPLIED_STREAM) == 0);
}

static bool
vsock_user_supports_type(const struct vsock_user_provider *provider,
    uint16_t type)
{

	return (vsock_user_features_support_type(provider->features, type));
}

static void
vsock_user_feature_counts_add_locked(uint64_t features)
{

	mtx_assert(&vtvsock_mtx, MA_OWNED);
	if (vsock_user_features_support_type(features,
	    VIRTIO_VSOCK_TYPE_STREAM))
		vsock_user_stream_provider_count++;
	if (vsock_user_features_support_type(features,
	    VIRTIO_VSOCK_TYPE_SEQPACKET))
		vsock_user_seqpacket_provider_count++;
}

static void
vsock_user_feature_counts_remove_locked(uint64_t features)
{

	mtx_assert(&vtvsock_mtx, MA_OWNED);
	if (vsock_user_features_support_type(features,
	    VIRTIO_VSOCK_TYPE_STREAM)) {
		KASSERT(vsock_user_stream_provider_count != 0,
		    ("%s: stream provider count underflow", __func__));
		vsock_user_stream_provider_count--;
	}
	if (vsock_user_features_support_type(features,
	    VIRTIO_VSOCK_TYPE_SEQPACKET)) {
		KASSERT(vsock_user_seqpacket_provider_count != 0,
		    ("%s: seqpacket provider count underflow", __func__));
		vsock_user_seqpacket_provider_count--;
	}
}

static struct vsock_user_provider *
vsock_user_lookup_locked(uint64_t guest_cid)
{
	struct vsock_user_provider_head *head;
	struct vsock_user_provider *provider;
	u_int bucket;

	mtx_assert(&vtvsock_mtx, MA_OWNED);
	bucket = vsock_user_bucket(guest_cid);
	head = &vsock_user_providers[bucket];
	LIST_FOREACH(provider, head, link) {
		if (provider->registered && provider->guest_cid == guest_cid)
			return (provider);
	}
	return (NULL);
}

static int
vsock_user_check_access(struct vsock_user_provider *provider,
    struct ucred *cred)
{

	mtx_assert(&vtvsock_mtx, MA_OWNED);
#ifdef MAC
	return (mac_vsock_provider_check_access(cred, provider->guest_cid,
	    provider->provider_label));
#else
	return (0);
#endif
}

static int
vsock_user_check_transport_access(struct vsock_user_provider *provider)
{

#ifdef MAC
	if (provider->attach_cred == NULL)
		return (EACCES);
	return (vsock_user_check_access(provider, provider->attach_cred));
#else
	return (0);
#endif
}

static void *
vsock_user_send_channel(uint64_t guest_cid)
{
	return (&vsock_user_providers[vsock_user_bucket(guest_cid)]);
}

static uint64_t
vsock_user_aggregate_features_locked(void)
{
	uint64_t features;

	mtx_assert(&vtvsock_mtx, MA_OWNED);
	KASSERT(vsock_user_stream_provider_count <=
	    vsock_user_provider_count,
	    ("%s: stream providers %u exceed total %u", __func__,
	    vsock_user_stream_provider_count, vsock_user_provider_count));
	KASSERT(vsock_user_seqpacket_provider_count <=
	    vsock_user_provider_count,
	    ("%s: seqpacket providers %u exceed total %u", __func__,
	    vsock_user_seqpacket_provider_count, vsock_user_provider_count));
	features = 0;
	if (vsock_user_seqpacket_provider_count != 0)
		features |= VIRTIO_VSOCK_F_SEQPACKET;
	if (vsock_user_stream_provider_count != 0)
		features |= VIRTIO_VSOCK_F_STREAM;
	else
		features |= VIRTIO_VSOCK_F_NO_IMPLIED_STREAM;
	return (features);
}

static int
vsock_user_sync_transport_locked(void)
{
	mtx_assert(&vtvsock_mtx, MA_OWNED);
	KASSERT(vsock_user_provider_count != 0,
	    ("%s: no providers", __func__));
	return (vsock_transport_register_locked(&vsock_user_transport,
	    &vsock_user_transport, VSOCK_CID_HOST,
	    vsock_user_aggregate_features_locked()));
}

static void
vsock_user_notify_locked(struct vsock_user_provider *provider)
{
	mtx_assert(&vtvsock_mtx, MA_OWNED);
	selwakeup(&provider->sel);
	KNOTE_LOCKED(&provider->sel.si_note, 0);
}

static void
vsock_user_purge_locked(struct vsock_user_provider *provider)
{
	struct vsock_user_packet *packet;

	mtx_assert(&vtvsock_mtx, MA_OWNED);
	while ((packet = STAILQ_FIRST(&provider->queue)) != NULL) {
		STAILQ_REMOVE_HEAD(&provider->queue, link);
		free(packet, M_VTVSOCK);
	}
	provider->queue_count = 0;
	wakeup(provider);
	wakeup(vsock_user_send_channel(provider->guest_cid));
}

static int
vsock_user_build_locked(struct vsock_user_provider *provider,
    uint64_t src_cid, uint32_t src_port, uint64_t dst_cid,
    uint32_t dst_port, uint16_t type, uint16_t op, uint32_t flags,
    uint32_t buf_alloc, uint32_t fwd_cnt, const void *payload,
    size_t payload_len, bool control)
{
	struct virtio_vsock_hdr *hdr;
	struct vsock_user_packet *packet;
	size_t len;
	bool reserved;

	mtx_assert(&vtvsock_mtx, MA_OWNED);
	if (payload_len > VSOCK_TRANSPORT_MAX_PAYLOAD ||
	    (payload_len != 0 && payload == NULL))
		return (EINVAL);
	if (provider == NULL || dst_cid != provider->guest_cid ||
	    src_cid != VSOCK_CID_HOST)
		return (EHOSTUNREACH);
	if (!provider->registered)
		return (ENXIO);
	if (vsock_user_check_transport_access(provider) != 0)
		return (EACCES);
	if (op != VIRTIO_VSOCK_OP_RST &&
	    !vsock_user_supports_type(provider, type))
		return (EPROTONOSUPPORT);
	reserved = control && provider->write_reserved &&
	    provider->write_thread == curthread;
	if (provider->queue_count >= VSOCK_USER_QUEUE_MAX ||
	    (!reserved && provider->write_reserved &&
	    provider->queue_count >= VSOCK_USER_QUEUE_MAX - 1) ||
	    (!control &&
	    provider->queue_count >= VSOCK_USER_QUEUE_DATA_HIWAT)) {
		SDT_PROBE3(vsock, , , provider__backpressure,
		    provider->guest_cid, provider->queue_count, control);
		return (EWOULDBLOCK);
	}
	len = sizeof(*hdr) + payload_len;
	if (reserved && payload_len == 0 && provider->write_packet != NULL) {
		packet = provider->write_packet;
		provider->write_packet = NULL;
	} else {
		packet = malloc(sizeof(*packet) + len, M_VTVSOCK, M_NOWAIT);
		if (packet == NULL)
			return (ENOMEM);
	}
	packet->len = len;
	hdr = (struct virtio_vsock_hdr *)packet->data;
	hdr->src_cid = htole64(src_cid);
	hdr->dst_cid = htole64(dst_cid);
	hdr->src_port = htole32(src_port);
	hdr->dst_port = htole32(dst_port);
	hdr->len = htole32((uint32_t)payload_len);
	hdr->type = htole16(type);
	hdr->op = htole16(op);
	hdr->flags = htole32(flags);
	hdr->buf_alloc = htole32(buf_alloc);
	hdr->fwd_cnt = htole32(fwd_cnt);
	if (payload_len != 0)
		memcpy(packet->data + sizeof(*hdr), payload, payload_len);
	STAILQ_INSERT_TAIL(&provider->queue, packet, link);
	provider->queue_count++;
	SDT_PROBE4(vsock, , , provider__enqueue, provider->guest_cid, op,
	    (uint32_t)payload_len, provider->queue_count);
	if (reserved)
		provider->write_reserved = false;
	vsock_user_notify_locked(provider);
	counter_u64_add(vtvsock_cnt_tx_packets, 1);
	counter_u64_add(vtvsock_cnt_tx_bytes, payload_len);
	return (0);
}

static int
vsock_user_send_pkt(struct vtvsock_pcb *pcb, uint16_t op, uint32_t flags,
    const void *payload, size_t payload_len)
{
	uint16_t type;

	mtx_assert(&vtvsock_mtx, MA_OWNED);
	type = pcb->so != NULL && pcb->so->so_type == SOCK_SEQPACKET ?
	    VIRTIO_VSOCK_TYPE_SEQPACKET : VIRTIO_VSOCK_TYPE_STREAM;
	return (vsock_user_build_locked(
	    vsock_user_lookup_locked(pcb->remote.svm_cid),
	    pcb->local.svm_cid, pcb->local.svm_port, pcb->remote.svm_cid,
	    pcb->remote.svm_port, type, op, flags, pcb->buf_alloc,
	    pcb->fwd_cnt, payload, payload_len, true));
}

static int
vsock_user_send_rst(uint64_t src_cid, uint32_t src_port, uint64_t dst_cid,
    uint32_t dst_port, uint16_t type)
{
	mtx_assert(&vtvsock_mtx, MA_OWNED);
	return (vsock_user_build_locked(vsock_user_lookup_locked(dst_cid),
	    src_cid, src_port,
	    dst_cid, dst_port, type, VIRTIO_VSOCK_OP_RST, 0, 0, 0,
	    NULL, 0, true));
}

static bool
vsock_user_tx_ready(struct vtvsock_pcb *pcb)
{
	struct vsock_user_provider *provider;

	mtx_assert(&vtvsock_mtx, MA_OWNED);
	provider = vsock_user_lookup_locked(pcb->remote.svm_cid);
	return (provider != NULL && provider->registered &&
	    vsock_user_check_transport_access(provider) == 0 &&
	    vsock_user_supports_type(provider,
	    pcb->so->so_type == SOCK_SEQPACKET ?
	    VIRTIO_VSOCK_TYPE_SEQPACKET : VIRTIO_VSOCK_TYPE_STREAM) &&
	    provider->queue_count < VSOCK_USER_QUEUE_DATA_HIWAT);
}

static void
vsock_user_packet_queue_free(struct vsock_user_packet_queue *queue)
{
	struct vsock_user_packet *packet;

	while ((packet = STAILQ_FIRST(queue)) != NULL) {
		STAILQ_REMOVE_HEAD(queue, link);
		free(packet, M_VTVSOCK);
	}
}

/*
 * Allocate and admit every wire fragment of one SEQPACKET message as a single
 * transaction.  Returning success after queueing only a prefix would leave an
 * unterminated message at the peer; resetting the otherwise healthy connection
 * on ordinary queue pressure is also wrong.  Build outside vtvsock_mtx, then
 * publish all fragments only after capacity and message-wide credit are both
 * available.
 * EOM terminates this message; MSG_EOR independently requests EOR on its final
 * fragment to terminate the enclosing record (VirtIO 1.4 section 5.10.6.6.1).
 */
static int
vsock_user_send_seqpacket(struct vtvsock_pcb *pcb, bool nonblocking,
    struct mbuf *m, size_t total)
{
	struct vsock_user_packet_queue packets;
	struct vsock_user_packet *packet;
	struct vsock_user_provider *provider;
	struct virtio_vsock_hdr *hdr;
	size_t chunk, fragment_count, offset;
	uint32_t credit, packet_flags;
	u_int i, nfrags;
	int alloc_flags, error;
	bool capacity, credit_request_sent;

	fragment_count = howmany(total,
	    (size_t)VSOCK_TRANSPORT_MAX_PAYLOAD);
	if (fragment_count == 0 ||
	    fragment_count > VSOCK_USER_QUEUE_DATA_HIWAT) {
		m_freem(m);
		return (EMSGSIZE);
	}
	nfrags = (u_int)fragment_count;
	alloc_flags = nonblocking ? M_NOWAIT : M_WAITOK;
	STAILQ_INIT(&packets);
	offset = 0;
	for (i = 0; i < nfrags; i++) {
		chunk = MIN(total - offset,
		    (size_t)VSOCK_TRANSPORT_MAX_PAYLOAD);
		packet = malloc(sizeof(*packet) + sizeof(*hdr) + chunk,
		    M_VTVSOCK, alloc_flags | M_ZERO);
		if (packet == NULL) {
			vsock_user_packet_queue_free(&packets);
			m_freem(m);
			return (ENOMEM);
		}
		packet->len = sizeof(*hdr) + chunk;
		m_copydata(m, (int)offset, (int)chunk,
		    packet->data + sizeof(*hdr));
		STAILQ_INSERT_TAIL(&packets, packet, link);
		offset += chunk;
	}

	error = 0;
	credit_request_sent = false;
	mtx_lock(&vtvsock_mtx);
	for (;;) {
		provider = vsock_user_lookup_locked(pcb->remote.svm_cid);
		if (provider == NULL) {
			error = EHOSTUNREACH;
			break;
		}
		if (!provider->registered) {
			error = ENXIO;
			break;
		}
		error = vsock_user_check_transport_access(provider);
		if (error != 0)
			break;
		if (!vsock_user_supports_type(provider,
		    VIRTIO_VSOCK_TYPE_SEQPACKET)) {
			error = EPROTONOSUPPORT;
			break;
		}
		if (pcb->state != VTVSOCK_ESTABLISHED ||
		    (pcb->peer_shutdown & VIRTIO_VSOCK_SHUTDOWN_RCV) != 0) {
			error = EPIPE;
			break;
		}
		if (total > MIN(pcb->peer_buf_alloc, pcb->buf_alloc)) {
			error = EMSGSIZE;
			break;
		}
		capacity = provider->queue_count + nfrags <=
		    VSOCK_USER_QUEUE_DATA_HIWAT;
		credit = 0;
		if (capacity) {
			credit = vtvsock_get_credit(pcb, (uint32_t)total);
			if (credit == total)
				break;
			pcb->tx_cnt -= credit;
		}
		if (nonblocking) {
			error = EWOULDBLOCK;
			break;
		}
		if (capacity) {
			if (!credit_request_sent) {
				(void)vsock_user_send_pkt(pcb,
				    VIRTIO_VSOCK_OP_CREDIT_REQUEST, 0, NULL, 0);
				credit_request_sent = true;
			}
			error = msleep_sbt(&pcb->tx_cnt, &vtvsock_mtx,
			    PSOCK | PCATCH, "vsocktx",
			    pcb->so->so_snd.sb_timeo, 0, 0);
		} else {
			error = msleep_sbt(
			    vsock_user_send_channel(pcb->remote.svm_cid),
			    &vtvsock_mtx, PSOCK | PCATCH, "vsockuq",
			    pcb->so->so_snd.sb_timeo, 0, 0);
		}
		if (error != 0)
			break;
	}
	if (error == 0) {
		i = 0;
		STAILQ_FOREACH(packet, &packets, link) {
			hdr = (struct virtio_vsock_hdr *)packet->data;
			hdr->src_cid = htole64(pcb->local.svm_cid);
			hdr->dst_cid = htole64(pcb->remote.svm_cid);
			hdr->src_port = htole32(pcb->local.svm_port);
			hdr->dst_port = htole32(pcb->remote.svm_port);
			hdr->len = htole32((uint32_t)
			    (packet->len - sizeof(*hdr)));
			hdr->type = htole16(VIRTIO_VSOCK_TYPE_SEQPACKET);
			hdr->op = htole16(VIRTIO_VSOCK_OP_RW);
			packet_flags = 0;
			if (i == nfrags - 1) {
				packet_flags = VIRTIO_VSOCK_SEQ_EOM;
				if ((m->m_flags & M_PROTO1) != 0)
					packet_flags |= VIRTIO_VSOCK_SEQ_EOR;
			}
			hdr->flags = htole32(packet_flags);
			hdr->buf_alloc = htole32(pcb->buf_alloc);
			hdr->fwd_cnt = htole32(pcb->fwd_cnt);
			SDT_PROBE4(vsock, , , provider__enqueue,
			    provider->guest_cid, VIRTIO_VSOCK_OP_RW,
			    le32toh(hdr->len),
			    provider->queue_count + i + 1);
			counter_u64_add(vtvsock_cnt_tx_packets, 1);
			counter_u64_add(vtvsock_cnt_tx_bytes,
			    le32toh(hdr->len));
			i++;
		}
		STAILQ_CONCAT(&provider->queue, &packets);
		provider->queue_count += nfrags;
		vsock_user_notify_locked(provider);
	}
	mtx_unlock(&vtvsock_mtx);
	vsock_user_packet_queue_free(&packets);
	m_freem(m);
	return (error);
}

static int
vsock_user_send(struct vtvsock_pcb *pcb, int flags, struct mbuf *m,
    struct sockaddr *addr __unused, struct mbuf *control,
    struct thread *td __unused)
{
	struct vsock_user_provider *provider;
	uint8_t *payload;
	size_t chunk, offset, total;
	uint32_t credit, packet_flags;
	uint16_t type;
	bool credit_request_sent, nonblocking, seqpacket;
	int error;

	if (control != NULL)
		m_freem(control);
	total = m_length(m, NULL);
	seqpacket = pcb->so->so_type == SOCK_SEQPACKET;
	nonblocking = (flags & VTVSOCK_SEND_F_NONBLOCK) != 0 ||
	    (pcb->so->so_state & SS_NBIO) != 0;
	type = seqpacket ? VIRTIO_VSOCK_TYPE_SEQPACKET :
	    VIRTIO_VSOCK_TYPE_STREAM;
	error = 0;
	offset = 0;
	credit_request_sent = false;
	if (seqpacket && total != 0)
		return (vsock_user_send_seqpacket(pcb, nonblocking, m, total));

	mtx_lock(&vtvsock_mtx);
	provider = vsock_user_lookup_locked(pcb->remote.svm_cid);
	if (provider == NULL) {
		error = EHOSTUNREACH;
		goto out;
	}
	if (!vsock_user_supports_type(provider, type)) {
		error = EPROTONOSUPPORT;
		goto out;
	}
	if (total == 0) {
		if (seqpacket) {
			/*
			 * vsock_send() checked ESTABLISHED before entering the
			 * transport, but provider reset or a concurrent close can
			 * change the PCB before we acquire vtvsock_mtx.  The
			 * non-empty path rechecks this in its credit loop; do the
			 * same for a zero-length SEQPACKET message so no OP_RW is
			 * emitted for a connection that has already closed.
			 */
			if (pcb->state != VTVSOCK_ESTABLISHED ||
			    (pcb->peer_shutdown &
			    VIRTIO_VSOCK_SHUTDOWN_RCV) != 0) {
				error = EPIPE;
				goto out;
			}
			packet_flags = VIRTIO_VSOCK_SEQ_EOM;
			if ((m->m_flags & M_PROTO1) != 0)
				packet_flags |= VIRTIO_VSOCK_SEQ_EOR;
			error = vsock_user_build_locked(provider,
			    pcb->local.svm_cid, pcb->local.svm_port,
			    pcb->remote.svm_cid, pcb->remote.svm_port, type,
			    VIRTIO_VSOCK_OP_RW, packet_flags, pcb->buf_alloc,
			    pcb->fwd_cnt, NULL, 0, false);
		}
		goto out;
	}
	while (offset < total) {
		chunk = MIN(total - offset,
		    (size_t)VSOCK_TRANSPORT_MAX_PAYLOAD);
		for (;;) {
			if (pcb->state != VTVSOCK_ESTABLISHED ||
			    (pcb->peer_shutdown & VIRTIO_VSOCK_SHUTDOWN_RCV) != 0) {
				error = EPIPE;
				goto out;
			}
			credit = vtvsock_get_credit(pcb, (uint32_t)chunk);
			if (credit != 0)
				break;
			if (nonblocking) {
				error = EWOULDBLOCK;
				goto out;
			}
			if (!credit_request_sent) {
				(void)vsock_user_send_pkt(pcb,
				    VIRTIO_VSOCK_OP_CREDIT_REQUEST, 0, NULL, 0);
				credit_request_sent = true;
			}
			/*
			 * Credit updates, reset, and teardown all wake tx_cnt.
			 * Honor SO_SNDTIMEO without polling once per second.
			 */
			error = msleep_sbt(&pcb->tx_cnt, &vtvsock_mtx,
			    PSOCK | PCATCH, "vsocktx",
			    pcb->so->so_snd.sb_timeo, 0, 0);
			if (error != 0)
				goto out;
			provider =
			    vsock_user_lookup_locked(pcb->remote.svm_cid);
			if (provider == NULL) {
				error = EHOSTUNREACH;
				goto out;
			}
		}
		chunk = MIN(chunk, (size_t)credit);
		payload = malloc(chunk, M_VTVSOCK, M_NOWAIT);
		if (payload == NULL) {
			pcb->tx_cnt -= (uint32_t)chunk;
			error = ENOMEM;
			break;
		}
		m_copydata(m, (int)offset, (int)chunk, payload);
		packet_flags = 0;
		error = vsock_user_build_locked(provider,
		    pcb->local.svm_cid, pcb->local.svm_port,
		    pcb->remote.svm_cid, pcb->remote.svm_port, type,
		    VIRTIO_VSOCK_OP_RW, packet_flags, pcb->buf_alloc,
		    pcb->fwd_cnt, payload, chunk, false);
		free(payload, M_VTVSOCK);
		if (error == EWOULDBLOCK && !nonblocking &&
		    pcb->state == VTVSOCK_ESTABLISHED) {
			pcb->tx_cnt -= (uint32_t)chunk;
			/*
			 * A provider dequeue, reset, or detach wakes the
			 * per-CID channel.  Wait for that event instead of
			 * periodically retrying an unchanged full queue.
			 */
			error = msleep_sbt(
			    vsock_user_send_channel(pcb->remote.svm_cid),
			    &vtvsock_mtx, PSOCK | PCATCH, "vsockuq",
			    pcb->so->so_snd.sb_timeo, 0, 0);
			if (error != 0)
				break;
			provider =
			    vsock_user_lookup_locked(pcb->remote.svm_cid);
			if (provider == NULL) {
				error = EHOSTUNREACH;
				break;
			}
			continue;
		}
		if (error != 0) {
			pcb->tx_cnt -= (uint32_t)chunk;
			break;
		}
		offset += chunk;
	}

out:
	if (offset > 0 && offset < total) {
		/*
		 * sosend_generic() has already consumed the whole mbuf from the
		 * caller's uio, so the protocol cannot report the exact prefix sent.
		 * Keeping a STREAM connection alive here would let the caller retry
		 * bytes whose prefix is already queued, duplicating data or silently
		 * gapping the stream.
		 */
		vtvsock_pcb_remove_lists_locked(pcb);
		pcb->state = VTVSOCK_CLOSED;
		vsock_tx_wakeup_locked(pcb);
		(void)vsock_user_send_rst(pcb->local.svm_cid,
		    pcb->local.svm_port, pcb->remote.svm_cid,
		    pcb->remote.svm_port, VIRTIO_VSOCK_TYPE_STREAM);
		wakeup(&pcb->state);
		mtx_unlock(&vtvsock_mtx);
		soisdisconnected(pcb->so);
		m_freem(m);
		return (error != 0 ? error : EIO);
	}
	mtx_unlock(&vtvsock_mtx);
	m_freem(m);
	return (offset > 0 ? 0 : error);
}

static int
vsock_user_disconnect(struct vtvsock_pcb *pcb)
{
	struct socket *so = pcb->so;

	mtx_lock(&vtvsock_mtx);
	if (pcb->state == VTVSOCK_ESTABLISHED) {
		(void)vsock_user_send_pkt(pcb, VIRTIO_VSOCK_OP_SHUTDOWN,
		    VIRTIO_VSOCK_SHUTDOWN_RCV | VIRTIO_VSOCK_SHUTDOWN_SEND,
		    NULL, 0);
		pcb->state = VTVSOCK_CLOSING;
		vsock_tx_wakeup_locked(pcb);
		callout_reset(&pcb->close_callout, VTVSOCK_CLOSE_TIMEOUT,
		    vtvsock_close_timeout, pcb);
		soisdisconnecting(so);
	} else if (pcb->state == VTVSOCK_CONNECTING) {
		callout_stop(&pcb->connect_callout);
		(void)vsock_user_send_pkt(pcb, VIRTIO_VSOCK_OP_RST, 0, NULL, 0);
		vtvsock_pcb_remove_lists_locked(pcb);
		pcb->state = VTVSOCK_CLOSED;
		vsock_tx_wakeup_locked(pcb);
		soisdisconnected(so);
		wakeup(&pcb->state);
	} else if (pcb->state != VTVSOCK_CLOSED) {
		vtvsock_pcb_remove_lists_locked(pcb);
		pcb->state = VTVSOCK_CLOSED;
		vsock_tx_wakeup_locked(pcb);
		soisdisconnected(so);
	}
	mtx_unlock(&vtvsock_mtx);
	return (0);
}

static int
vsock_user_shutdown(struct vtvsock_pcb *pcb, enum shutdown_how how)
{
	struct socket *so = pcb->so;
	uint32_t flags;
	int error;

	switch (how) {
	case SHUT_RD:
		flags = VIRTIO_VSOCK_SHUTDOWN_RCV;
		break;
	case SHUT_WR:
		flags = VIRTIO_VSOCK_SHUTDOWN_SEND;
		break;
	case SHUT_RDWR:
		flags = VIRTIO_VSOCK_SHUTDOWN_RCV |
		    VIRTIO_VSOCK_SHUTDOWN_SEND;
		break;
	default:
		return (EINVAL);
	}
	error = 0;
	mtx_lock(&vtvsock_mtx);
	if (pcb->state == VTVSOCK_ESTABLISHED)
		error = vsock_user_send_pkt(pcb, VIRTIO_VSOCK_OP_SHUTDOWN,
		    flags, NULL, 0);
	mtx_unlock(&vtvsock_mtx);
	/*
	 * Do not make the local half-close permanent unless the peer notification
	 * was queued.  In particular, a full provider queue is recoverable:
	 * shutdown(2) returns EWOULDBLOCK and the caller may retry after POLLOUT.
	 */
	if (error != 0)
		return (error);
	if (how == SHUT_RD || how == SHUT_RDWR) {
		SOCK_RECVBUF_LOCK(so);
		socantrcvmore_locked(so);
	}
	if (how == SHUT_WR || how == SHUT_RDWR) {
		SOCK_SENDBUF_LOCK(so);
		socantsendmore_locked(so);
	}
	return (0);
}

static void
vsock_user_send_credit_update(struct vtvsock_pcb *pcb)
{
	mtx_assert(&vtvsock_mtx, MA_OWNED);
	if (pcb->state == VTVSOCK_ESTABLISHED &&
	    vsock_user_send_pkt(pcb, VIRTIO_VSOCK_OP_CREDIT_UPDATE,
	    0, NULL, 0) == 0)
		pcb->last_fwd_cnt = pcb->fwd_cnt;
}

static void
vsock_user_dtor(void *arg)
{
	struct vsock_user_provider *provider = arg;
	int error;

	mtx_lock(&vtvsock_mtx);
	if (provider->registered) {
		SDT_PROBE1(vsock, , , provider__detach, provider->guest_cid);
		vsock_transport_reset_cid_locked(&vsock_user_transport,
		    provider->guest_cid);
		LIST_REMOVE(provider, link);
		KASSERT(vsock_user_provider_count != 0,
		    ("%s: provider count underflow", __func__));
		vsock_user_provider_count--;
		vsock_user_feature_counts_remove_locked(provider->features);
		provider->registered = false;
		provider->generation++;
		if (vsock_user_provider_count == 0) {
			KASSERT(vsock_user_stream_provider_count == 0 &&
			    vsock_user_seqpacket_provider_count == 0,
			    ("%s: feature providers remain after last detach",
			    __func__));
			vsock_transport_unregister_locked(
			    &vsock_user_transport);
		} else {
			error = vsock_user_sync_transport_locked();
			if (error != 0)
				panic("%s: transport resync failed: %d",
				    __func__, error);
		}
	}
	wakeup(provider);
	wakeup(vsock_user_send_channel(provider->guest_cid));
	vsock_user_notify_locked(provider);
	vsock_user_purge_locked(provider);
	mtx_unlock(&vtvsock_mtx);
	knlist_clear(&provider->sel.si_note, 0);
	seldrain(&provider->sel);
	knlist_destroy(&provider->sel.si_note);
	/*
	 * knlist_clear() detaches subject-owned knotes without invoking their
	 * filter detach callback.  It waits for in-flight filter callbacks, so
	 * their credential contexts can be reclaimed once the list is empty.
	 */
	for (;;) {
		struct vsock_user_knote *ctx;

		mtx_lock(&vtvsock_mtx);
		ctx = LIST_FIRST(&provider->knotes);
		if (ctx != NULL)
			LIST_REMOVE(ctx, link);
		mtx_unlock(&vtvsock_mtx);
		if (ctx == NULL)
			break;
		crfree(ctx->cred);
		free(ctx, M_VTVSOCK);
	}
#ifdef MAC
	if (provider->attach_cred != NULL)
		crfree(provider->attach_cred);
	mac_vsock_provider_label_free(provider->provider_label);
#endif
	free(provider, M_VTVSOCK);
}

static int
vsock_dev_read(struct cdev *dev __unused, struct uio *uio, int ioflag)
{
	struct vsock_user_provider *provider;
	struct vsock_user_packet *packet;
	uint64_t generation;
	int error;

	error = devfs_get_cdevpriv((void **)&provider);
	if (error != 0)
		return (ENXIO);
	if (uio->uio_resid == 0)
		return (0);
	mtx_lock(&vtvsock_mtx);
	error = vsock_user_check_access(provider, uio->uio_td->td_ucred);
	if (error != 0)
		goto out;
	generation = provider->generation;
	for (;;) {
		/*
		 * Serialize dequeue and copyout.  Otherwise reader A can remove
		 * packet 1 and fault in uiomove() while reader B successfully
		 * delivers packet 2; putting packet 1 back afterward would violate
		 * the complete-packet FIFO contract.
		 */
		if (provider->read_inflight == 0 &&
		    (packet = STAILQ_FIRST(&provider->queue)) != NULL)
			break;
		if (!provider->registered) {
			error = ENXIO;
			goto out;
		}
		if ((ioflag & O_NONBLOCK) != 0) {
			error = EWOULDBLOCK;
			goto out;
		}
		error = msleep(provider, &vtvsock_mtx, PCATCH,
		    "vsockur", 0);
		if (error != 0)
			goto out;
		/*
		 * A read that started in the old transport epoch must not consume a
		 * packet produced after reset.  Reset waits for an active copyout,
		 * increments generation, purges the queue, and wakes every waiter.
		 */
		if (provider->generation != generation) {
			error = ECANCELED;
			goto out;
		}
		/*
		 * Authorization may have been revoked while this thread slept.
		 * Revalidate before observing or consuming any newly available
		 * packet.
		 */
		error = vsock_user_check_access(provider,
		    uio->uio_td->td_ucred);
		if (error != 0)
			goto out;
	}
	if ((size_t)uio->uio_resid < packet->len) {
		error = EMSGSIZE;
		goto out;
	}
	STAILQ_REMOVE_HEAD(&provider->queue, link);
	/*
	 * Keep queue_count charged while copyout is in flight.  If uiomove()
	 * faults, the packet is put back at the head and no producer may have
	 * consumed its capacity in the meantime.
	 */
	provider->read_inflight++;
	vsock_user_notify_locked(provider);
	mtx_unlock(&vtvsock_mtx);
	error = uiomove(packet->data, packet->len, uio);
	mtx_lock(&vtvsock_mtx);
	KASSERT(provider->read_inflight > 0,
	    ("%s: read in-flight count underflow", __func__));
	provider->read_inflight--;
	if (error == 0) {
		KASSERT(provider->queue_count > 0,
		    ("%s: queue count underflow", __func__));
		provider->queue_count--;
		SDT_PROBE4(vsock, , , provider__dequeue,
		    provider->guest_cid,
		    le16toh(((struct virtio_vsock_hdr *)packet->data)->op),
		    le32toh(((struct virtio_vsock_hdr *)packet->data)->len),
		    provider->queue_count);
		if (provider->queue_count ==
		    VSOCK_USER_QUEUE_DATA_HIWAT - 1)
			vsock_transport_tx_wakeup_cid_locked(
			    &vsock_user_transport, provider->guest_cid);
	} else {
		/* A failed read consumes no packet; preserve FIFO order. */
		STAILQ_INSERT_HEAD(&provider->queue, packet, link);
		packet = NULL;
	}
	wakeup(provider);
	wakeup(vsock_user_send_channel(provider->guest_cid));
	vsock_user_notify_locked(provider);
	mtx_unlock(&vtvsock_mtx);
	if (packet != NULL)
		free(packet, M_VTVSOCK);
	return (error);
out:
	mtx_unlock(&vtvsock_mtx);
	return (error);
}

static int
vsock_dev_write(struct cdev *dev __unused, struct uio *uio, int ioflag)
{
	struct vsock_user_provider *provider;
	struct virtio_vsock_hdr *hdr;
	struct vsock_user_packet *reply;
	uint8_t *packet;
	uint64_t generation;
	size_t len;
	int error;

	error = devfs_get_cdevpriv((void **)&provider);
	if (error != 0)
		return (ENXIO);
	len = uio->uio_resid;
	if (len < sizeof(*hdr) ||
	    len > sizeof(*hdr) + VSOCK_TRANSPORT_MAX_PAYLOAD) {
		SDT_PROBE3(vsock, , , provider__reject,
		    provider->guest_cid, (uint32_t)len, EMSGSIZE);
		return (EMSGSIZE);
	}
	/*
	 * Processing one inbound packet may synchronously enqueue one control
	 * reply.  Reserve the final queue slot before consuming the caller's uio,
	 * and serialize writers so unrelated control traffic cannot steal it.
	 * This is the userspace-provider equivalent of the virtio driver's RX
	 * reply backpressure.
	 */
	mtx_lock(&vtvsock_mtx);
	if (!provider->registered) {
		mtx_unlock(&vtvsock_mtx);
		return (ENXIO);
	}
	error = vsock_user_check_access(provider, uio->uio_td->td_ucred);
	if (error != 0) {
		mtx_unlock(&vtvsock_mtx);
		return (error);
	}
	generation = provider->generation;
	while (provider->write_thread != NULL ||
	    provider->queue_count >= VSOCK_USER_QUEUE_MAX) {
		if ((ioflag & O_NONBLOCK) != 0) {
			mtx_unlock(&vtvsock_mtx);
			return (EWOULDBLOCK);
		}
		error = msleep(provider, &vtvsock_mtx,
		    PCATCH, "vsockuw", 0);
		if (error != 0) {
			mtx_unlock(&vtvsock_mtx);
			return (error);
		}
		if (!provider->registered) {
			mtx_unlock(&vtvsock_mtx);
			return (ENXIO);
		}
		/*
		 * This write entered before a transport reset and slept without
		 * reserving the writer slot.  Do not admit its old-epoch packet
		 * after reset purged queues and connection state.
		 */
		if (provider->generation != generation) {
			mtx_unlock(&vtvsock_mtx);
			return (ECANCELED);
		}
		/*
		 * A token or the underlying provider claim may have disappeared
		 * while this writer was blocked on queue capacity.
		 */
		error = vsock_user_check_access(provider,
		    uio->uio_td->td_ucred);
		if (error != 0) {
			mtx_unlock(&vtvsock_mtx);
			return (error);
		}
	}
	provider->write_thread = curthread;
	provider->write_reserved = true;
	mtx_unlock(&vtvsock_mtx);
	/*
	 * Allocate the reserved header while sleeping is permitted.  Every
	 * control packet emitted synchronously by vsock_rx_packet() is
	 * header-only, so the reserved queue slot cannot still be lost to an
	 * allocation failure after the provider packet has been consumed.
	 */
	provider->write_packet = malloc(sizeof(*reply) + sizeof(*hdr),
	    M_VTVSOCK, M_WAITOK);
	packet = malloc(len, M_VTVSOCK, M_WAITOK);
	error = uiomove(packet, len, uio);
	if (error != 0) {
		free(packet, M_VTVSOCK);
		goto out;
	}
	hdr = (struct virtio_vsock_hdr *)packet;
	if (le32toh(hdr->len) != len - sizeof(*hdr) ||
	    le64toh(hdr->src_cid) != provider->guest_cid ||
	    le64toh(hdr->dst_cid) != VSOCK_CID_HOST) {
		SDT_PROBE3(vsock, , , provider__reject,
		    provider->guest_cid, (uint32_t)len, EINVAL);
		free(packet, M_VTVSOCK);
		error = EINVAL;
		goto out;
	}
	mtx_lock(&vtvsock_mtx);
	/*
	 * uiomove() above may fault or sleep after the initial authorization
	 * check.  Treat provider authorization as a property of the complete
	 * packet operation: a token/claim revoked during that interval must
	 * prevent the copied packet from entering AF_VSOCK.  Reset and feature
	 * updates wait for write_thread, but checking the epoch as well makes
	 * that serialization explicit and protects future teardown changes.
	 */
	if (!provider->registered || provider->generation != generation)
		error = ECANCELED;
	else
		error = vsock_user_check_access(provider,
		    uio->uio_td->td_ucred);
	if (error != 0) {
		mtx_unlock(&vtvsock_mtx);
		free(packet, M_VTVSOCK);
		goto out;
	}
	if (!vsock_user_supports_type(provider, le16toh(hdr->type))) {
		SDT_PROBE3(vsock, , , provider__reject,
		    provider->guest_cid, (uint32_t)len, EPROTONOSUPPORT);
		/*
		 * A packet using a type this guest did not negotiate is a guest
		 * protocol error, not a provider failure.  VirtIO 1.4 requires
		 * unsupported socket types to receive RST.  The serialized writer
		 * reservation guarantees capacity for this synchronous reply.
		 */
		if (le16toh(hdr->op) != VIRTIO_VSOCK_OP_RST)
			error = vsock_user_build_locked(provider,
			    VSOCK_CID_HOST, le32toh(hdr->dst_port),
			    provider->guest_cid, le32toh(hdr->src_port),
			    le16toh(hdr->type), VIRTIO_VSOCK_OP_RST, 0,
			    0, 0, NULL, 0, true);
		else
			error = 0;
		mtx_unlock(&vtvsock_mtx);
		free(packet, M_VTVSOCK);
		goto out;
	}
	mtx_unlock(&vtvsock_mtx);
	SDT_PROBE3(vsock, , , provider__inject, provider->guest_cid,
	    le16toh(hdr->op), le32toh(hdr->len));
	vsock_rx_packet(&vsock_user_transport, packet, (uint32_t)len);
	free(packet, M_VTVSOCK);
	error = 0;
out:
	mtx_lock(&vtvsock_mtx);
	reply = provider->write_packet;
	provider->write_packet = NULL;
	provider->write_reserved = false;
	provider->write_thread = NULL;
	wakeup(provider);
	vsock_user_notify_locked(provider);
	mtx_unlock(&vtvsock_mtx);
	free(reply, M_VTVSOCK);
	return (error);
}

static int
vsock_dev_ioctl(struct cdev *dev __unused, u_long cmd, caddr_t data,
    int fflag __unused, struct thread *td)
{
	struct vsock_transport_attach *attach;
	struct vsock_user_provider *provider;
	uint64_t features, old_features;
	int error;

	/*
	 * F_SETFL uses FIONBIO to notify file implementations when O_NONBLOCK
	 * changes.  devfs already passes the current descriptor state to read
	 * and write in ioflag, so no per-provider state needs updating here.
	 */
	if (cmd == FIONBIO)
		return (0);
	if (cmd == IOCTL_VM_SOCKETS_GET_LOCAL_CID) {
		mtx_lock(&vtvsock_mtx);
		*(uint32_t *)data = (uint32_t)vtvsock_guest_cid;
		mtx_unlock(&vtvsock_mtx);
		return (0);
	}
	if (cmd == VSOCK_IOC_TRANSPORT_ATTACH) {
		attach = (struct vsock_transport_attach *)data;
		if (attach->version != VSOCK_TRANSPORT_VERSION ||
		    attach->guest_cid < 3 ||
		    attach->guest_cid == VSOCK_CID_ANY ||
		    !vsock_user_features_valid(attach->features) ||
		    attach->reserved[0] != 0 || attach->reserved[1] != 0)
			return (EINVAL);
		AUDIT_ARG_VALUE((long)attach->guest_cid);
		error = priv_check(td, PRIV_DRIVER);
		if (error != 0)
			return (error);
		error = devfs_get_cdevpriv((void **)&provider);
		if (error != 0) {
			provider = malloc(sizeof(*provider), M_VTVSOCK,
			    M_WAITOK | M_ZERO);
			STAILQ_INIT(&provider->queue);
			LIST_INIT(&provider->knotes);
			knlist_init_mtx(&provider->sel.si_note, &vtvsock_mtx);
#ifdef MAC
			provider->provider_label =
			    mac_vsock_provider_label_alloc(M_WAITOK);
			if (provider->provider_label == NULL) {
				knlist_destroy(&provider->sel.si_note);
				free(provider, M_VTVSOCK);
				return (ENOMEM);
			}
#endif
			error = devfs_set_cdevpriv(provider, vsock_user_dtor);
			if (error != 0) {
#ifdef MAC
				mac_vsock_provider_label_free(
				    provider->provider_label);
#endif
				knlist_destroy(&provider->sel.si_note);
				free(provider, M_VTVSOCK);
				return (error);
			}
		}
		mtx_lock(&vtvsock_mtx);
		if (provider->registered) {
			error = EALREADY;
		} else if (vsock_user_lookup_locked(attach->guest_cid) != NULL) {
			error = EADDRINUSE;
		} else {
#ifdef MAC
			/*
			 * The policy records the exact claim that authorized this
			 * provider in provider_label.  Keep that mutation inside the
			 * provider lock so concurrent ATTACH ioctls on one file
			 * cannot race to replace the recorded ownership.
			 */
			error = mac_vsock_provider_check_attach(td->td_ucred,
			    attach->guest_cid, provider->provider_label);
#else
			error = 0;
#endif
			if (error == 0) {
				provider->guest_cid = attach->guest_cid;
				provider->features = attach->features;
				provider->registered = true;
				LIST_INSERT_HEAD(&vsock_user_providers[
				    vsock_user_bucket(provider->guest_cid)],
				    provider, link);
				vsock_user_provider_count++;
				vsock_user_feature_counts_add_locked(
				    provider->features);
				error = vsock_user_sync_transport_locked();
				if (error != 0) {
					LIST_REMOVE(provider, link);
					vsock_user_provider_count--;
					vsock_user_feature_counts_remove_locked(
					    provider->features);
					provider->registered = false;
				} else
					vsock_user_notify_locked(provider);
			}
#ifdef MAC
			if (error == 0)
				provider->attach_cred = crhold(td->td_ucred);
#endif
		}
		mtx_unlock(&vtvsock_mtx);
		if (error != 0)
			return (error);
		SDT_PROBE2(vsock, , , provider__attach,
		    provider->guest_cid, attach->features);
		return (0);
	}
	if (cmd == VSOCK_IOC_TRANSPORT_SET_FEATURES) {
		features = *(uint64_t *)data;
		if (!vsock_user_features_valid(features))
			return (EINVAL);
		error = devfs_get_cdevpriv((void **)&provider);
		if (error != 0)
			return (ENXIO);
		mtx_lock(&vtvsock_mtx);
		error = vsock_user_check_access(provider, td->td_ucred);
		if (error == 0 && !provider->registered)
			error = ENXIO;
		if (error == 0) {
			AUDIT_ARG_VALUE((long)provider->guest_cid);
			while (provider->write_thread != NULL ||
			    provider->read_inflight != 0) {
				error = msleep(provider, &vtvsock_mtx, PCATCH,
				    "vsockuf", 0);
				if (error != 0 || !provider->registered)
					break;
			}
			if (!provider->registered)
				error = ENXIO;
			else if (error == 0)
				error = vsock_user_check_access(provider,
				    td->td_ucred);
		}
		if (error == 0) {
			old_features = provider->features;
			if (old_features != features) {
				/*
				 * A feature epoch is also a packet epoch.  Do not
				 * expose packets queued under the old socket-type
				 * contract after the VMM reports a new negotiation.
				 */
				provider->generation++;
				vsock_user_purge_locked(provider);
				vsock_user_notify_locked(provider);
				vsock_transport_reset_cid_locked(
				    &vsock_user_transport,
				    provider->guest_cid);
				vsock_user_feature_counts_remove_locked(
				    old_features);
				vsock_user_feature_counts_add_locked(features);
			}
			provider->features = features;
			error = vsock_user_sync_transport_locked();
			if (error != 0) {
				if (old_features != features) {
					vsock_user_feature_counts_remove_locked(
					    features);
					vsock_user_feature_counts_add_locked(
					    old_features);
				}
				provider->features = old_features;
			}
		}
		mtx_unlock(&vtvsock_mtx);
		if (error == 0)
			SDT_PROBE2(vsock, , , provider__features,
			    provider->guest_cid, features);
		return (error);
	}
	if (cmd == VSOCK_IOC_TRANSPORT_RESET) {
		error = devfs_get_cdevpriv((void **)&provider);
		if (error != 0)
			return (ENXIO);
		mtx_lock(&vtvsock_mtx);
		error = vsock_user_check_access(provider, td->td_ucred);
		if (error != 0) {
			mtx_unlock(&vtvsock_mtx);
			return (error);
		}
		if (!provider->registered) {
			mtx_unlock(&vtvsock_mtx);
			return (ENXIO);
		}
		AUDIT_ARG_VALUE((long)provider->guest_cid);
		/*
		 * Reads and writes drop the domain lock while copying packets.  Wait
		 * for both directions so reset neither admits a pre-reset inbound
		 * packet nor returns while an old outbound packet is still being
		 * copied to the provider.
		 */
		while (provider->write_thread != NULL ||
		    provider->read_inflight != 0) {
			error = msleep(provider, &vtvsock_mtx, PCATCH,
			    "vsockur", 0);
			if (error != 0) {
				mtx_unlock(&vtvsock_mtx);
				return (error);
			}
		}
		/*
		 * Authorization may have changed while reset slept for an
		 * in-flight copy.  Revalidate at the state-changing commit point.
		 */
		error = vsock_user_check_access(provider, td->td_ucred);
		if (error != 0) {
			mtx_unlock(&vtvsock_mtx);
			return (error);
		}
		/*
		 * Invalidate writers that entered before this reset but were
		 * sleeping for queue capacity or the serialized writer slot.
		 * Active copies have drained above, so every old-epoch packet is
		 * now either queued (and purged below) or completed.
		 */
		provider->generation++;
		vsock_user_purge_locked(provider);
		vsock_user_notify_locked(provider);
		vsock_transport_reset_cid_locked(&vsock_user_transport,
		    provider->guest_cid);
		old_features = provider->features;
		vsock_user_feature_counts_remove_locked(old_features);
		provider->features = 0;
		vsock_user_feature_counts_add_locked(provider->features);
		error = vsock_user_sync_transport_locked();
		if (error != 0) {
			vsock_user_feature_counts_remove_locked(
			    provider->features);
			provider->features = old_features;
			vsock_user_feature_counts_add_locked(
			    provider->features);
		}
		mtx_unlock(&vtvsock_mtx);
		if (error == 0)
			SDT_PROBE1(vsock, , , provider__reset,
			    provider->guest_cid);
		return (error);
	}
	return (ENOTTY);
}

static int
vsock_dev_poll(struct cdev *dev __unused, int events, struct thread *td)
{
	struct vsock_user_provider *provider;
	int revents;

	if (devfs_get_cdevpriv((void **)&provider) != 0)
		return (POLLNVAL);
	revents = 0;
	mtx_lock(&vtvsock_mtx);
	if (vsock_user_check_access(provider, td->td_ucred) != 0) {
		mtx_unlock(&vtvsock_mtx);
		return (POLLERR);
	}
	if ((events & (POLLIN | POLLRDNORM)) != 0) {
		if ((!STAILQ_EMPTY(&provider->queue) &&
		    provider->read_inflight == 0) || !provider->registered)
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(td, &provider->sel);
	}
	if ((events & (POLLOUT | POLLWRNORM)) != 0 && provider->registered &&
	    provider->write_thread == NULL &&
	    provider->queue_count < VSOCK_USER_QUEUE_MAX)
		revents |= events & (POLLOUT | POLLWRNORM);
	else if ((events & (POLLOUT | POLLWRNORM)) != 0)
		selrecord(td, &provider->sel);
	mtx_unlock(&vtvsock_mtx);
	return (revents);
}

static int vsock_dev_kqread(struct knote *, long);
static int vsock_dev_kqwrite(struct knote *, long);
static void vsock_dev_kqdetach(struct knote *);

static const struct filterops vsock_dev_read_filterops = {
	.f_isfd = 1,
	.f_detach = vsock_dev_kqdetach,
	.f_event = vsock_dev_kqread,
};

static const struct filterops vsock_dev_write_filterops = {
	.f_isfd = 1,
	.f_detach = vsock_dev_kqdetach,
	.f_event = vsock_dev_kqwrite,
};

static int
vsock_dev_kqfilter(struct cdev *dev __unused, struct knote *kn)
{
	struct vsock_user_knote *ctx;
	struct vsock_user_provider *provider;
	int error;

	error = devfs_get_cdevpriv((void **)&provider);
	if (error != 0)
		return (error);
	if (kn->kn_filter == EVFILT_READ)
		kn->kn_fop = &vsock_dev_read_filterops;
	else if (kn->kn_filter == EVFILT_WRITE)
		kn->kn_fop = &vsock_dev_write_filterops;
	else
		return (EINVAL);
	ctx = malloc(sizeof(*ctx), M_VTVSOCK, M_WAITOK | M_ZERO);
	ctx->provider = provider;
	ctx->cred = crhold(curthread->td_ucred);
	mtx_lock(&vtvsock_mtx);
	error = vsock_user_check_access(provider, ctx->cred);
	if (error == 0 && !provider->registered)
		error = ENXIO;
	if (error == 0) {
		LIST_INSERT_HEAD(&provider->knotes, ctx, link);
		kn->kn_hook = ctx;
		knlist_add(&provider->sel.si_note, kn, 1);
	}
	mtx_unlock(&vtvsock_mtx);
	if (error != 0) {
		crfree(ctx->cred);
		free(ctx, M_VTVSOCK);
	}
	return (error);
}

static int
vsock_dev_kqwrite(struct knote *kn, long hint __unused)
{
	struct vsock_user_knote *ctx = kn->kn_hook;
	struct vsock_user_provider *provider = ctx->provider;

	mtx_assert(&vtvsock_mtx, MA_OWNED);
	kn->kn_data = 0;
	if (vsock_user_check_access(provider, ctx->cred) != 0)
		return (0);
	return (provider->registered &&
	    provider->write_thread == NULL &&
	    provider->queue_count < VSOCK_USER_QUEUE_MAX);
}

static int
vsock_dev_kqread(struct knote *kn, long hint __unused)
{
	struct vsock_user_knote *ctx = kn->kn_hook;
	struct vsock_user_provider *provider = ctx->provider;
	struct vsock_user_packet *packet;

	mtx_assert(&vtvsock_mtx, MA_OWNED);
	if (vsock_user_check_access(provider, ctx->cred) != 0) {
		kn->kn_data = 0;
		return (0);
	}
	packet = STAILQ_FIRST(&provider->queue);
	kn->kn_data = packet != NULL && provider->read_inflight == 0 ?
	    packet->len : 0;
	return ((packet != NULL && provider->read_inflight == 0) ||
	    !provider->registered);
}

static void
vsock_dev_kqdetach(struct knote *kn)
{
	struct vsock_user_knote *ctx = kn->kn_hook;
	struct vsock_user_provider *provider = ctx->provider;

	mtx_lock(&vtvsock_mtx);
	knlist_remove(&provider->sel.si_note, kn, 1);
	LIST_REMOVE(ctx, link);
	mtx_unlock(&vtvsock_mtx);
	crfree(ctx->cred);
	free(ctx, M_VTVSOCK);
}

static struct cdevsw vsock_cdevsw = {
	.d_version = D_VERSION,
	.d_name = "vsock",
	.d_read = vsock_dev_read,
	.d_write = vsock_dev_write,
	.d_ioctl = vsock_dev_ioctl,
	.d_poll = vsock_dev_poll,
	.d_kqfilter = vsock_dev_kqfilter,
};

int
vsock_cdev_create(void)
{
	/* GET_LOCAL_CID is public; transport attachment checks PRIV_DRIVER. */
	vsock_cdev = make_dev(&vsock_cdevsw, 0, UID_ROOT, GID_WHEEL, 0666,
	    "vsock");
	return (vsock_cdev != NULL ? 0 : ENXIO);
}
