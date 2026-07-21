/*
 * Direct userspace tests for the real guest VirtIO transport driver.
 * The socket-domain callbacks and virtqueues are instrumented, but the code
 * under test is sys/dev/virtio/vsock/virtio_vsock.c without copied logic.
 */
#define VSOCK_REAL_SLEEP 1
#include "transport_kmock.h"

#include <unistd.h>

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
static pthread_cond_t transport_sleep_cv = PTHREAD_COND_INITIALIZER;
static _Atomic(void *) transport_sleep_chan;
static uint64_t transport_wake_generation;
static bool transport_mtx_initialized;
static int register_calls, register_locked_calls, unregister_calls, reset_calls;
static uint64_t registered_cid, registered_features;
static void (*transport_rx_packet_hook)(void *, uint32_t);

int
transport_msleep(void *chan, struct mtx *m, int pri __unused,
    const char *w __unused, int timo __unused)
{
	uint64_t generation;

	generation = transport_wake_generation;
	atomic_store(&transport_sleep_chan, chan);
	while (generation == transport_wake_generation) {
		if (pthread_cond_wait(&transport_sleep_cv, &m->native) != 0)
			abort();
	}
	atomic_store(&transport_sleep_chan, NULL);
	return (0);
}

void
transport_wakeup(void *chan)
{
	transport_last_wakeup = chan;
	if (atomic_load(&transport_sleep_chan) == chan) {
		transport_wake_generation++;
		if (pthread_cond_broadcast(&transport_sleep_cv) != 0)
			abort();
	}
}

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
void
vsock_rx_packet(void *buf, uint32_t len)
{
	if (transport_rx_packet_hook != NULL)
		transport_rx_packet_hook(buf, len);
}
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
	if (transport_mtx_initialized)
		mtx_destroy(&vtvsock_mtx);
	mtx_init(&vtvsock_mtx, "vsock transport test", NULL, MTX_DEF);
	transport_mtx_initialized = true;
	atomic_store(&transport_sleep_chan, NULL);
	transport_wake_generation = 0;
	transport_last_wakeup = NULL;
	register_calls = register_locked_calls = unregister_calls = reset_calls = 0;
	registered_cid = registered_features = 0;
	transport_rx_packet_hook = NULL;
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

struct blocked_sender {
	struct vtvsock_pcb *pcb;
	struct mbuf *m;
	_Atomic bool done;
	int result;
};

struct interrupt_gate {
	_Atomic bool entered;
	_Atomic bool release;
};

static struct interrupt_gate *active_rx_gate;

struct interrupt_runner {
	struct vtvsock_softc *sc;
	_Atomic bool done;
};

struct detach_runner {
	struct fake_device *dev;
	_Atomic bool started;
	_Atomic bool done;
	int result;
};

static bool
wait_for_flag(_Atomic bool *flag, int timeout_ms)
{
	int i;

	for (i = 0; i < timeout_ms; i++) {
		if (atomic_load(flag))
			return (true);
		usleep(1000);
	}
	return (false);
}

static int
join_after_flag(pthread_t thread, _Atomic bool *done, int timeout_ms)
{

	if (!wait_for_flag(done, timeout_ms))
		return (ETIMEDOUT);
	return (pthread_join(thread, NULL));
}

static void
block_on_gate(struct interrupt_gate *gate)
{

	atomic_store(&gate->entered, true);
	while (!atomic_load(&gate->release))
		usleep(100);
}

static void
block_rx_delivery(void *buf __unused, uint32_t len __unused)
{

	block_on_gate(active_rx_gate);
}

static void
block_tx_dequeue(struct virtqueue *vq __unused, void *arg)
{

	block_on_gate(arg);
}

static void *
run_rx_interrupt(void *arg)
{
	struct interrupt_runner *runner = arg;

	vtvsock_rx_intr(runner->sc);
	atomic_store(&runner->done, true);
	return (NULL);
}

static void *
run_tx_interrupt(void *arg)
{
	struct interrupt_runner *runner = arg;

	vtvsock_tx_intr(runner->sc);
	atomic_store(&runner->done, true);
	return (NULL);
}

static void *
run_detach(void *arg)
{
	struct detach_runner *runner = arg;

	atomic_store(&runner->started, true);
	runner->result = vtvsock_detach(runner->dev);
	atomic_store(&runner->done, true);
	return (NULL);
}

static void *
run_blocked_sender(void *arg)
{
	struct blocked_sender *sender = arg;

	sender->result = vtvsock_virtio_send(sender->pcb, 0, sender->m,
	    NULL, NULL, NULL);
	atomic_store(&sender->done, true);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(detach_wakes_tx_ring_blocked_sender);
ATF_TC_BODY(detach_wakes_tx_ring_blocked_sender, tc)
{
	struct blocked_sender sender;
	struct fake_device dev;
	struct mbuf *m;
	struct sglist sg;
	struct sglist_seg seg;
	struct socket so;
	struct virtqueue txvq;
	struct vtvsock_pcb pcb;
	struct vtvsock_softc sc;
	pthread_t thread;
	void *blocker;
	int i;

	reset_state();
	memset(&dev, 0, sizeof(dev));
	memset(&pcb, 0, sizeof(pcb));
	memset(&sc, 0, sizeof(sc));
	memset(&so, 0, sizeof(so));
	mock_vq_init(&txvq, 1);
	sc.sc_dev = &dev;
	sc.sc_txvq = &txvq;
	dev.softc = &sc;
	so.so_type = SOCK_STREAM;
	pcb.so = &so;
	pcb.state = VTVSOCK_ESTABLISHED;
	pcb.local.svm_cid = 14;
	pcb.local.svm_port = 1000;
	pcb.remote.svm_cid = VSOCK_CID_HOST;
	pcb.remote.svm_port = 2000;
	pcb.peer_buf_alloc = 4096;
	blocker = calloc(1, sizeof(struct virtio_vsock_hdr));
	ATF_REQUIRE(blocker != NULL);
	one_seg(&sg, &seg);
	ATF_REQUIRE(virtqueue_enqueue(&txvq, blocker, &sg, 1, 0) == 0);
	atomic_store_ptr(&vtvsock_sc, &sc);

	m = m_get(M_WAITOK, MT_DATA);
	ATF_REQUIRE(m != NULL);
	m->m_len = 1;
	m->m_data[0] = 'X';
	sender = (struct blocked_sender) { .pcb = &pcb, .m = m, .result = -1 };
	ATF_REQUIRE(pthread_create(&thread, NULL, run_blocked_sender, &sender) == 0);
	for (i = 0; i < 5000; i++) {
		if (atomic_load(&transport_sleep_chan) == &sc.sc_txvq)
			break;
		usleep(1000);
	}
	ATF_REQUIRE_MSG(i < 5000, "sender did not block on the TX ring");
	ATF_CHECK(pcb.tx_cnt == 0);

	ATF_REQUIRE(vtvsock_detach(&dev) == 0);
	ATF_REQUIRE_MSG(join_after_flag(thread, &sender.done, 1000) == 0,
	    "TX-ring-blocked sender was not woken within one second");
	ATF_CHECK(sender.result == ENXIO);
	ATF_CHECK(pcb.tx_cnt == 0);
	ATF_CHECK(vtvsock_global_softc() == NULL);
	ATF_CHECK(txvq.entry_count == 0);
	ATF_CHECK(transport_last_wakeup == &sc.sc_txvq);
}

ATF_TC_WITHOUT_HEAD(rx_interrupt_detach_during_delivery);
ATF_TC_BODY(rx_interrupt_detach_during_delivery, tc)
{
	struct detach_runner detach;
	struct fake_device dev;
	struct interrupt_gate gate;
	struct interrupt_runner intr;
	struct sglist sg;
	struct sglist_seg seg;
	struct virtqueue rxvq;
	struct vtvsock_softc sc;
	pthread_t detach_thread, intr_thread;
	void *buf;

	reset_state();
	memset(&detach, 0, sizeof(detach));
	memset(&dev, 0, sizeof(dev));
	memset(&gate, 0, sizeof(gate));
	memset(&intr, 0, sizeof(intr));
	memset(&sc, 0, sizeof(sc));
	mock_vq_init(&rxvq, 1);
	sc.sc_dev = &dev;
	sc.sc_rxvq = &rxvq;
	dev.softc = &sc;
	detach.dev = &dev;
	intr.sc = &sc;
	buf = calloc(1, VTVSOCK_RX_BUFSZ);
	ATF_REQUIRE(buf != NULL);
	one_seg(&sg, &seg);
	ATF_REQUIRE(virtqueue_enqueue(&rxvq, buf, &sg, 0, 1) == 0);
	ATF_REQUIRE(mock_vq_complete(&rxvq, buf, 0));
	atomic_store_ptr(&vtvsock_sc, &sc);
	active_rx_gate = &gate;
	transport_rx_packet_hook = block_rx_delivery;

	ATF_REQUIRE(pthread_create(&intr_thread, NULL, run_rx_interrupt,
	    &intr) == 0);
	ATF_REQUIRE_MSG(wait_for_flag(&gate.entered, 5000),
	    "RX interrupt did not enter socket-domain delivery");
	ATF_CHECK(rxvq.entry_count == 0);	/* handler owns the buffer */

	ATF_REQUIRE(pthread_create(&detach_thread, NULL, run_detach,
	    &detach) == 0);
	ATF_REQUIRE_MSG(join_after_flag(detach_thread, &detach.done, 1000) == 0,
	    "detach did not finish while RX delivery was open");
	ATF_CHECK(detach.result == 0);
	ATF_CHECK(vtvsock_global_softc() == NULL);
	ATF_CHECK(!atomic_load(&intr.done));

	atomic_store(&gate.release, true);
	ATF_REQUIRE_MSG(join_after_flag(intr_thread, &intr.done, 1000) == 0,
	    "RX interrupt did not leave after detach");
	ATF_CHECK(atomic_load(&intr.done));
	ATF_CHECK(rxvq.entry_count == 0);
	ATF_CHECK(rxvq.enable_count == 0);	/* torn-down queue not re-armed */
	ATF_CHECK(rxvq.notify_count == 0);	/* nor notified/refilled */
	active_rx_gate = NULL;
}

ATF_TC_WITHOUT_HEAD(tx_interrupt_serializes_detach);
ATF_TC_BODY(tx_interrupt_serializes_detach, tc)
{
	struct detach_runner detach;
	struct fake_device dev;
	struct interrupt_gate gate;
	struct interrupt_runner intr;
	struct sglist sg;
	struct sglist_seg seg;
	struct virtio_vsock_hdr *pkt;
	struct virtqueue txvq;
	struct vtvsock_softc sc;
	pthread_t detach_thread, intr_thread;
	int enable_count;

	reset_state();
	memset(&detach, 0, sizeof(detach));
	memset(&dev, 0, sizeof(dev));
	memset(&gate, 0, sizeof(gate));
	memset(&intr, 0, sizeof(intr));
	memset(&sc, 0, sizeof(sc));
	mock_vq_init(&txvq, 1);
	sc.sc_dev = &dev;
	sc.sc_txvq = &txvq;
	dev.softc = &sc;
	detach.dev = &dev;
	intr.sc = &sc;
	pkt = new_control_packet();
	one_seg(&sg, &seg);
	ATF_REQUIRE(virtqueue_enqueue(&txvq, pkt, &sg, 1, 0) == 0);
	ATF_REQUIRE(mock_vq_complete(&txvq, pkt, 0));
	txvq.dequeue_hook = block_tx_dequeue;
	txvq.dequeue_hook_arg = &gate;
	atomic_store_ptr(&vtvsock_sc, &sc);

	ATF_REQUIRE(pthread_create(&intr_thread, NULL, run_tx_interrupt,
	    &intr) == 0);
	ATF_REQUIRE_MSG(wait_for_flag(&gate.entered, 5000),
	    "TX interrupt did not enter dequeue while holding the lock");
	ATF_REQUIRE(pthread_create(&detach_thread, NULL, run_detach,
	    &detach) == 0);
	ATF_REQUIRE_MSG(wait_for_flag(&detach.started, 5000),
	    "detach thread did not start");
	ATF_CHECK(!atomic_load(&detach.done));
	ATF_CHECK(vtvsock_global_softc() == &sc);

	atomic_store(&gate.release, true);
	ATF_REQUIRE_MSG(join_after_flag(intr_thread, &intr.done, 1000) == 0,
	    "TX interrupt did not finish");
	ATF_REQUIRE_MSG(join_after_flag(detach_thread, &detach.done, 1000) == 0,
	    "detach did not follow the TX interrupt");
	ATF_CHECK(detach.result == 0);
	ATF_CHECK(vtvsock_global_softc() == NULL);
	ATF_CHECK(txvq.entry_count == 0);
	ATF_CHECK(txvq.enable_count == 1);

	/* A late callback after teardown must return without touching the queue. */
	enable_count = txvq.enable_count;
	vtvsock_tx_intr(&sc);
	ATF_CHECK(txvq.enable_count == enable_count);
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
	ATF_TP_ADD_TC(tp, detach_wakes_tx_ring_blocked_sender);
	ATF_TP_ADD_TC(tp, rx_interrupt_detach_during_delivery);
	ATF_TP_ADD_TC(tp, tx_interrupt_serializes_detach);
	ATF_TP_ADD_TC(tp, attach_completed_detach_lifecycle);
	return (atf_no_error());
}
