/*
 * Direct userspace tests for the real guest VirtIO transport driver.
 * The socket-domain callbacks and virtqueues are instrumented, but the code
 * under test is sys/dev/virtio/vsock/virtio_vsock.c without copied logic.
 */
#include "transport_kmock.h"

MALLOC_DEFINE(M_VTVSOCK, "vtvsock", "virtio vsock test");
struct mtx vtvsock_mtx;
uint64_t vtvsock_guest_cid;
static uint64_t tx_packets, tx_bytes, rx_packets, rx_bytes, rx_drops, conns;
counter_u64_t vtvsock_cnt_tx_packets = &tx_packets;
counter_u64_t vtvsock_cnt_tx_bytes = &tx_bytes;
counter_u64_t vtvsock_cnt_rx_packets = &rx_packets;
counter_u64_t vtvsock_cnt_rx_bytes = &rx_bytes;
counter_u64_t vtvsock_cnt_rx_drops = &rx_drops;
counter_u64_t vtvsock_cnt_conns = &conns;

void *transport_last_wakeup;
static int register_calls, register_locked_calls, unregister_calls, reset_calls;
static uint64_t registered_cid, registered_features;

void
vsock_transport_register(const struct vtvsock_transport *ops __unused,
    uint64_t cid, uint64_t features)
{
	register_calls++;
	registered_cid = cid;
	registered_features = features;
}

void
vsock_transport_unregister(void)
{
	unregister_calls++;
}

void
vsock_transport_register_locked(const struct vtvsock_transport *ops __unused,
    uint64_t cid, uint64_t features)
{
	register_locked_calls++;
	registered_cid = cid;
	registered_features = features;
}

void vsock_transport_reset_locked(void) { reset_calls++; }
void vsock_rx_packet(void *buf __unused, uint32_t len __unused) {}
void vtvsock_pcb_remove_lists_locked(struct vtvsock_pcb *pcb __unused) {}
void vtvsock_close_timeout(void *arg __unused) {}

uint32_t
vtvsock_get_credit(struct vtvsock_pcb *pcb, uint32_t wanted)
{
	uint32_t used, avail, got;

	used = pcb->tx_cnt - pcb->peer_fwd_cnt;
	avail = used < pcb->peer_buf_alloc ? pcb->peer_buf_alloc - used : 0;
	got = MIN(wanted, avail);
	pcb->tx_cnt += got;
	return (got);
}

#include "virtio_vsock.c"	/* DUT: expose its static helpers to the tests. */

#include <atf-c.h>

static void
reset_state(void)
{
	atomic_store_ptr(&vtvsock_sc, NULL);
	memset(&vtvsock_mtx, 0, sizeof(vtvsock_mtx));
	transport_last_wakeup = NULL;
	register_calls = register_locked_calls = unregister_calls = reset_calls = 0;
	registered_cid = registered_features = 0;
	tx_packets = tx_bytes = rx_packets = rx_bytes = rx_drops = conns = 0;
}

static struct virtio_vsock_hdr *
new_control_packet(void)
{
	struct virtio_vsock_hdr *hdr;

	hdr = calloc(1, sizeof(*hdr));
	ATF_REQUIRE(hdr != NULL);
	hdr->op = htole16(VIRTIO_VSOCK_OP_CREDIT_UPDATE);
	return (hdr);
}

static void
one_seg(struct sglist *sg, struct sglist_seg *seg)
{
	sglist_init(sg, 1, seg);
	sg->sg_nseg = 1;
}

ATF_TC_WITHOUT_HEAD(cid_sanitization);
ATF_TC_BODY(cid_sanitization, tc)
{
	struct fake_device dev;

	reset_state();
	memset(&dev, 0, sizeof(dev));
	ATF_CHECK(vtvsock_sanitize_cid(&dev, 0xfeedface0000000eULL) == 14);
	ATF_CHECK(dev.printf_calls == 0);
	ATF_CHECK(vtvsock_sanitize_cid(&dev, 0x123400000002ULL) ==
	    VSOCK_CID_HOST);
	ATF_CHECK(dev.printf_calls == 1);
}

ATF_TC_WITHOUT_HEAD(tx_ready_descriptor_threshold);
ATF_TC_BODY(tx_ready_descriptor_threshold, tc)
{
	struct vtvsock_softc sc;
	struct virtqueue txvq;

	reset_state();
	memset(&sc, 0, sizeof(sc));
	ATF_CHECK(!vtvsock_virtio_tx_ready(NULL));
	mock_vq_init(&txvq, VTVSOCK_TX_SEGS);
	sc.sc_txvq = &txvq;
	atomic_store_ptr(&vtvsock_sc, &sc);
	ATF_CHECK(vtvsock_virtio_tx_ready(NULL));
	txvq.nfree = VTVSOCK_TX_SEGS - 1;
	ATF_CHECK(!vtvsock_virtio_tx_ready(NULL));
	txvq.nfree = VTVSOCK_TX_SEGS;
	sc.sc_txq_count = 1;
	ATF_CHECK(!vtvsock_virtio_tx_ready(NULL));
}

ATF_TC_WITHOUT_HEAD(enqueue_reclaims_then_retries);
ATF_TC_BODY(enqueue_reclaims_then_retries, tc)
{
	struct vtvsock_softc sc;
	struct virtqueue txvq;
	struct sglist sg;
	struct sglist_seg seg;
	void *old, *new;

	reset_state();
	memset(&sc, 0, sizeof(sc));
	mock_vq_init(&txvq, 1);
	sc.sc_txvq = &txvq;
	old = calloc(1, sizeof(struct virtio_vsock_hdr));
	new = calloc(1, sizeof(struct virtio_vsock_hdr));
	ATF_REQUIRE(old != NULL && new != NULL);
	one_seg(&sg, &seg);
	ATF_REQUIRE(virtqueue_enqueue(&txvq, old, &sg, 1, 0) == 0);
	ATF_REQUIRE(mock_vq_complete(&txvq, old, 0));
	ATF_CHECK(vtvsock_txvq_enqueue(&sc, new, &sg) == 0);
	ATF_CHECK(txvq.entry_count == 1);
	ATF_CHECK(txvq.entries[0].cookie == new);
	ATF_CHECK(txvq.notify_count == 1);
	ATF_CHECK(txvq.nfree == 0);
	ATF_REQUIRE(mock_vq_complete(&txvq, new, 0));
	vtvsock_txvq_reclaim(&sc);
}

ATF_TC_WITHOUT_HEAD(control_queue_bounded);
ATF_TC_BODY(control_queue_bounded, tc)
{
	struct vtvsock_softc sc;
	struct virtqueue txvq;
	struct sglist sg;
	struct sglist_seg seg;
	struct fake_device dev;
	struct virtio_vsock_hdr *blocker, *pkt;

	reset_state();
	memset(&sc, 0, sizeof(sc));
	mock_vq_init(&txvq, 1);
	sc.sc_txvq = &txvq;
	blocker = new_control_packet();
	one_seg(&sg, &seg);
	ATF_REQUIRE(virtqueue_enqueue(&txvq, blocker, &sg, 1, 0) == 0);
	for (int i = 0; i < VTVSOCK_TXQ_MAX; i++) {
		pkt = new_control_packet();
		ATF_CHECK(vtvsock_ctrl_submit(&sc, pkt, &sg) == 0);
	}
	ATF_CHECK(sc.sc_txq_count == VTVSOCK_TXQ_MAX);
	pkt = new_control_packet();
	ATF_CHECK(vtvsock_ctrl_submit(&sc, pkt, &sg) == EWOULDBLOCK);
	ATF_CHECK(sc.sc_txq_count == VTVSOCK_TXQ_MAX);
	ATF_CHECK(sc.sc_txq_drops == 1);

	/* Detach must reclaim both ring-owned and software-queued packets. */
	memset(&dev, 0, sizeof(dev));
	dev.softc = &sc;
	sc.sc_dev = &dev;
	atomic_store_ptr(&vtvsock_sc, &sc);
	ATF_CHECK(vtvsock_detach(&dev) == 0);
	ATF_CHECK(sc.sc_txq_count == 0);
	ATF_CHECK(txvq.entry_count == 0);
}

ATF_TC_WITHOUT_HEAD(partial_ring_is_transient);
ATF_TC_BODY(partial_ring_is_transient, tc)
{
	struct vtvsock_softc sc;
	struct virtqueue txvq;
	struct sglist one, two;
	struct sglist_seg one_seg_store, two_seg_store[2];
	void *blocker, *pkt;

	reset_state();
	memset(&sc, 0, sizeof(sc));
	mock_vq_init(&txvq, 2);
	sc.sc_txvq = &txvq;
	blocker = calloc(1, sizeof(struct virtio_vsock_hdr));
	pkt = calloc(1, sizeof(struct virtio_vsock_hdr));
	ATF_REQUIRE(blocker != NULL && pkt != NULL);
	one_seg(&one, &one_seg_store);
	ATF_REQUIRE(virtqueue_enqueue(&txvq, blocker, &one, 1, 0) == 0);
	sglist_init(&two, 2, two_seg_store);
	two.sg_nseg = 2;
	ATF_CHECK(vtvsock_txvq_enqueue(&sc, pkt, &two) == EWOULDBLOCK);
	ATF_CHECK(txvq.entry_count == 1);
	ATF_CHECK(txvq.entries[0].cookie == blocker);
	ATF_CHECK(txvq.notify_count == 0);
	ATF_REQUIRE(mock_vq_complete(&txvq, blocker, 0));
	vtvsock_txvq_reclaim(&sc);
	kfree(pkt);
}

ATF_TC_WITHOUT_HEAD(tx_interrupt_drains_fifo_and_wakes);
ATF_TC_BODY(tx_interrupt_drains_fifo_and_wakes, tc)
{
	struct vtvsock_softc sc;
	struct virtqueue txvq;
	struct sglist sg;
	struct sglist_seg seg;
	struct virtio_vsock_hdr *blocker, *first, *second;

	reset_state();
	memset(&sc, 0, sizeof(sc));
	mock_vq_init(&txvq, 1);
	sc.sc_txvq = &txvq;
	atomic_store_ptr(&vtvsock_sc, &sc);
	one_seg(&sg, &seg);
	blocker = new_control_packet();
	first = new_control_packet();
	second = new_control_packet();
	ATF_REQUIRE(virtqueue_enqueue(&txvq, blocker, &sg, 1, 0) == 0);
	ATF_REQUIRE(vtvsock_ctrl_submit(&sc, first, &sg) == 0);
	ATF_REQUIRE(vtvsock_ctrl_submit(&sc, second, &sg) == 0);
	ATF_REQUIRE(mock_vq_complete(&txvq, blocker, 0));
	vtvsock_tx_intr(&sc);
	ATF_CHECK(txvq.entries[0].cookie == first);
	ATF_CHECK(sc.sc_txq_count == 1);
	ATF_CHECK(transport_last_wakeup == &sc.sc_txvq);
	ATF_REQUIRE(mock_vq_complete(&txvq, first, 0));
	vtvsock_tx_intr(&sc);
	ATF_CHECK(txvq.entries[0].cookie == second);
	ATF_CHECK(sc.sc_txq_count == 0);
	ATF_REQUIRE(mock_vq_complete(&txvq, second, 0));
	vtvsock_txvq_reclaim(&sc);
}

ATF_TC_WITHOUT_HEAD(transport_reset_recycles_event_and_wakes);
ATF_TC_BODY(transport_reset_recycles_event_and_wakes, tc)
{
	struct vtvsock_softc sc;
	struct virtqueue eventvq, txvq;
	struct fake_device dev;
	struct virtio_vsock_event *evt;

	reset_state();
	memset(&sc, 0, sizeof(sc));
	memset(&dev, 0, sizeof(dev));
	mock_vq_init(&eventvq, 4);
	mock_vq_init(&txvq, VTVSOCK_TX_SEGS);
	dev.softc = &sc;
	dev.config_cid = 0xa5a5a5a50000000eULL;
	sc.sc_dev = &dev;
	sc.sc_eventvq = &eventvq;
	sc.sc_txvq = &txvq;
	sc.sc_features = VIRTIO_VSOCK_F_STREAM | VIRTIO_VSOCK_F_SEQPACKET;
	atomic_store_ptr(&vtvsock_sc, &sc);
	evt = calloc(1, sizeof(*evt));
	ATF_REQUIRE(evt != NULL);
	evt->id = htole32(VIRTIO_VSOCK_EVENT_TRANSPORT_RESET);
	eventvq.entries[0] = (struct mock_vq_entry) {
		.cookie = evt, .len = sizeof(*evt), .ndesc = 1, .complete = true
	};
	eventvq.entry_count = 1;
	eventvq.nfree--;

	vtvsock_event_intr(&sc);
	ATF_CHECK(sc.sc_guest_cid == 14);
	ATF_CHECK(register_locked_calls == 1);
	ATF_CHECK(reset_calls == 1);
	ATF_CHECK(registered_cid == 14);
	ATF_CHECK(registered_features == sc.sc_features);
	ATF_CHECK(transport_last_wakeup == &sc.sc_txvq);
	ATF_CHECK(eventvq.entry_count == 1);
	ATF_CHECK(eventvq.entries[0].cookie == evt);
	ATF_CHECK(eventvq.notify_count == 1);
	ATF_REQUIRE(mock_vq_complete(&eventvq, evt, 0));
	(void)virtqueue_dequeue(&eventvq, NULL);
	kfree(evt);
}

ATF_TC_WITHOUT_HEAD(attach_completed_detach_lifecycle);
ATF_TC_BODY(attach_completed_detach_lifecycle, tc)
{
	struct vtvsock_softc sc;
	struct fake_device dev;
	struct virtqueue *rxvq, *txvq, *eventvq;
	uint64_t offered;

	reset_state();
	memset(&sc, 0, sizeof(sc));
	memset(&dev, 0, sizeof(dev));
	offered = VIRTIO_VSOCK_F_STREAM | VIRTIO_VSOCK_F_SEQPACKET |
	    VIRTIO_VSOCK_F_NO_IMPLIED_STREAM | (1ULL << 63);
	dev.softc = &sc;
	dev.type = VIRTIO_ID_VSOCK;
	dev.config_cid = 14;
	dev.offered_features = offered;
	ATF_REQUIRE(vtvsock_attach(&dev) == 0);
	ATF_CHECK(sc.sc_features == (offered & ~(1ULL << 63)));
	ATF_CHECK(sc.sc_guest_cid == 14);
	ATF_CHECK(register_calls == 0);
	ATF_CHECK(sc.sc_rxvq->notify_count == 0);
	ATF_CHECK(sc.sc_eventvq->notify_count == 0);
	ATF_REQUIRE(vtvsock_attach_completed(&dev) == 0);
	ATF_CHECK(vtvsock_global_softc() == &sc);
	ATF_CHECK(register_calls == 1);
	ATF_CHECK(registered_cid == 14);
	ATF_CHECK(registered_features == sc.sc_features);
	ATF_CHECK(sc.sc_rxvq->notify_count == 1);
	ATF_CHECK(sc.sc_eventvq->notify_count == 1);

	rxvq = sc.sc_rxvq;
	txvq = sc.sc_txvq;
	eventvq = sc.sc_eventvq;
	transport_last_wakeup = NULL;
	ATF_REQUIRE(vtvsock_detach(&dev) == 0);
	ATF_CHECK(vtvsock_global_softc() == NULL);
	ATF_CHECK(unregister_calls == 1);
	ATF_CHECK(dev.stop_calls == 1);
	ATF_CHECK(transport_last_wakeup == &sc.sc_txvq);
	ATF_CHECK(rxvq->entry_count == 0);
	ATF_CHECK(txvq->entry_count == 0);
	ATF_CHECK(eventvq->entry_count == 0);
	kfree(rxvq);
	kfree(txvq);
	kfree(eventvq);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, cid_sanitization);
	ATF_TP_ADD_TC(tp, tx_ready_descriptor_threshold);
	ATF_TP_ADD_TC(tp, enqueue_reclaims_then_retries);
	ATF_TP_ADD_TC(tp, control_queue_bounded);
	ATF_TP_ADD_TC(tp, partial_ring_is_transient);
	ATF_TP_ADD_TC(tp, tx_interrupt_drains_fifo_and_wakes);
	ATF_TP_ADD_TC(tp, transport_reset_recycles_event_and_wakes);
	ATF_TP_ADD_TC(tp, attach_completed_detach_lifecycle);
	return (atf_no_error());
}
