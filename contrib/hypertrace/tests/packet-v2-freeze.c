/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define TUN_OPEN 1
#define TUN_L2 2
#define TUN_PROPAGATE_TAG_V2 4
#define IFCOUNTER_OERRORS 1
struct mbuf { bool freed; unsigned length; };
struct ifqueue { pthread_mutex_t mtx; struct mbuf *head; };
struct ifnet;
struct tuntap_softc {
	pthread_mutex_t tun_mtx;
	pthread_cond_t tun_cv;
	unsigned tun_tx_inflight;
	unsigned tun_flags;
	uint16_t tun_bound_vmid;
	uint64_t tun_bound_epoch;
	bool tun_rx_frozen;
	bool tun_rx_freezing;
	bool tun_closing;
	struct ifnet *tun_ifp;
};
struct ifnet { struct tuntap_softc *if_softc; struct ifqueue if_snd; };
#define TUN2IFP(tp) ((tp)->tun_ifp)
#define IFQ_LOCK(q) assert(pthread_mutex_lock(&(q)->mtx) == 0)
#define IFQ_UNLOCK(q) assert(pthread_mutex_unlock(&(q)->mtx) == 0)
#define IFQ_POLL_NOLOCK(q, m) ((m) = (q)->head)
#define TUN_LOCK(tp) assert(pthread_mutex_lock(&(tp)->tun_mtx) == 0)
#define TUN_UNLOCK(tp) assert(pthread_mutex_unlock(&(tp)->tun_mtx) == 0)
#define KASSERT(test, message) assert(test)
#define BPF_MTAP(ifp, m) ((void)0)
#define if_inc_counter(ifp, counter, amount) ((void)0)
#define cv_broadcast(cv) assert(pthread_cond_broadcast(cv) == 0)
static int current_epoch = 1;
static int
mbufid_v2_vm_epoch_current(uint16_t vmid, uint64_t epoch)
{
	return (current_epoch && vmid == 7 && epoch == 42);
}
static void m_freem(struct mbuf *m) { m->freed = true; }

static pthread_mutex_t gate_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cv = PTHREAD_COND_INITIALIZER;
static bool gate_entered, gate_release;
static bool freeze_waiting;
static atomic_uint enqueued;
static void
fixture_cv_wait(pthread_cond_t *cv, pthread_mutex_t *mtx)
{
	assert(pthread_mutex_lock(&gate_mtx) == 0);
	freeze_waiting = true;
	assert(pthread_cond_broadcast(&gate_cv) == 0);
	assert(pthread_mutex_unlock(&gate_mtx) == 0);
	assert(pthread_cond_wait(cv, mtx) == 0);
}
#define cv_wait(cv, mtx) fixture_cv_wait(cv, mtx)
static void
handoff(struct mbuf *m, int *error)
{
	assert(pthread_mutex_lock(&gate_mtx) == 0);
	gate_entered = true;
	assert(pthread_cond_broadcast(&gate_cv) == 0);
	while (!gate_release)
		assert(pthread_cond_wait(&gate_cv, &gate_mtx) == 0);
	assert(pthread_mutex_unlock(&gate_mtx) == 0);
	assert(!m->freed);
	atomic_fetch_add(&enqueued, 1);
	*error = 0;
}
#define IFQ_HANDOFF(ifp, m, error) handoff((m), &(error))
#include "packet-v2-freeze.inc"

struct send_arg {
	struct ifnet *ifp;
	struct mbuf *m;
	int result;
};
static void *
sender(void *arg)
{
	struct send_arg *send = arg;
	send->result = tap_transmit(send->ifp, send->m);
	return (NULL);
}
struct freeze_arg { struct tuntap_softc *tp; atomic_int result; };
static void *
freezer(void *arg)
{
	struct freeze_arg *freeze = arg;
	atomic_store(&freeze->result, tap_v2_rx_freeze(freeze->tp, 1));
	return (NULL);
}
int
main(void)
{
	struct tuntap_softc tp = {
	    .tun_flags = TUN_OPEN | TUN_L2 | TUN_PROPAGATE_TAG_V2,
	    .tun_bound_vmid = 7, .tun_bound_epoch = 42
	};
	struct ifnet ifp = { .if_softc = &tp };
	struct mbuf zero_length = {};
	struct mbuf first = {}, second = {}, third = {}, fourth = {};
	struct send_arg send = { .ifp = &ifp, .m = &first, .result = -1 };
	struct freeze_arg freeze = { .tp = &tp, .result = -1 };
	pthread_t send_thread, freeze_thread;
	bool observed = false;

	assert(pthread_mutex_init(&tp.tun_mtx, NULL) == 0);
	tp.tun_ifp = &ifp;
	assert(pthread_mutex_init(&ifp.if_snd.mtx, NULL) == 0);
	assert(pthread_cond_init(&tp.tun_cv, NULL) == 0);
	assert(tap_v2_rx_freeze(&tp, 2) == EINVAL);
	current_epoch = 0;
	assert(tap_v2_rx_freeze(&tp, 1) == ESTALE && !tp.tun_rx_frozen);
	current_epoch = 1;
	assert(pthread_create(&send_thread, NULL, sender, &send) == 0);
	assert(pthread_mutex_lock(&gate_mtx) == 0);
	while (!gate_entered)
		assert(pthread_cond_wait(&gate_cv, &gate_mtx) == 0);
	assert(pthread_mutex_unlock(&gate_mtx) == 0);
	assert(pthread_create(&freeze_thread, NULL, freezer, &freeze) == 0);
	assert(pthread_mutex_lock(&gate_mtx) == 0);
	while (!freeze_waiting)
		assert(pthread_cond_wait(&gate_cv, &gate_mtx) == 0);
	assert(pthread_mutex_unlock(&gate_mtx) == 0);
	TUN_LOCK(&tp);
	observed = tp.tun_rx_frozen && tp.tun_rx_freezing &&
	    tp.tun_tx_inflight == 1;
	TUN_UNLOCK(&tp);
	assert(observed && atomic_load(&freeze.result) == -1);
	assert(tap_v2_rx_freeze(&tp, 0) == EBUSY && tp.tun_rx_frozen);
	assert(tap_v2_rx_freeze(&tp, 1) == EBUSY && tp.tun_rx_frozen);
	assert(tap_transmit(&ifp, &second) == ENETDOWN && second.freed);
	assert(atomic_load(&enqueued) == 0);
	assert(pthread_mutex_lock(&gate_mtx) == 0);
	gate_release = true;
	assert(pthread_cond_broadcast(&gate_cv) == 0);
	assert(pthread_mutex_unlock(&gate_mtx) == 0);
	assert(pthread_join(send_thread, NULL) == 0);
	assert(pthread_join(freeze_thread, NULL) == 0);
	assert(send.result == 0 && atomic_load(&freeze.result) == 0 &&
	    atomic_load(&enqueued) == 1);
	int queued = -1;
	assert(tap_v2_rx_queued(&tp, &queued) == 0 && queued == 0);
	ifp.if_snd.head = &zero_length;
	assert(tap_v2_rx_queued(&tp, &queued) == 0 && queued == 1);
	ifp.if_snd.head = NULL;
	assert(tap_transmit(&ifp, &third) == ENETDOWN && third.freed);
	assert(tap_v2_rx_freeze(&tp, 0) == 0 && !tp.tun_rx_frozen);
	queued = -1;
	assert(tap_v2_rx_queued(&tp, &queued) == EBUSY && queued == -1);
	tp.tun_closing = true;
	assert(tap_v2_rx_freeze(&tp, 1) == EBUSY && !tp.tun_rx_frozen);
	tp.tun_closing = false;
	assert(tap_transmit(&ifp, &fourth) == 0 &&
	    atomic_load(&enqueued) == 2);
	assert(pthread_cond_destroy(&tp.tun_cv) == 0);
	assert(pthread_mutex_destroy(&tp.tun_mtx) == 0);
	assert(pthread_mutex_destroy(&ifp.if_snd.mtx) == 0);
	puts("PASS: V2 TAP freeze fences enqueue and detects zero-length queued packets");
	return (0);
}
