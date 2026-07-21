/* Tests for the real bhyve split-ring parser and interrupt decision logic. */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <atf-c.h>

#include "pci_emul.h"
#include <bhyve/virtio.h>
#define	MOCK_VIRTIO_H
#include "virtio.c"

struct vmctx { int unused; };

struct guest_region {
	uint64_t gpa;
	size_t len;
	void *host;
};

static struct guest_region g_regions[4];
static int g_region_count;
static int g_interrupts;
static bool g_lintr_asserted;
static bool g_hold_deassert;
static bool g_deassert_entered;
static pthread_mutex_t g_intr_test_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_intr_test_cv = PTHREAD_COND_INITIALIZER;

void *
paddr_guest2host(struct vmctx *ctx __unused, uintptr_t gpa, size_t len)
{
	uint64_t offset;

	for (int i = 0; i < g_region_count; i++) {
		if (gpa < g_regions[i].gpa)
			continue;
		offset = gpa - g_regions[i].gpa;
		if (offset <= g_regions[i].len &&
		    len <= g_regions[i].len - offset)
			return ((uint8_t *)g_regions[i].host + offset);
	}
	return (NULL);
}

void
pci_lintr_deassert(struct pci_devinst *pi __unused)
{
	pthread_mutex_lock(&g_intr_test_mtx);
	if (g_hold_deassert) {
		g_deassert_entered = true;
		pthread_cond_broadcast(&g_intr_test_cv);
		while (g_hold_deassert)
			pthread_cond_wait(&g_intr_test_cv, &g_intr_test_mtx);
	}
	g_lintr_asserted = false;
	pthread_mutex_unlock(&g_intr_test_mtx);
}

void
pci_lintr_assert(struct pci_devinst *pi __unused)
{
	pthread_mutex_lock(&g_intr_test_mtx);
	g_lintr_asserted = true;
	pthread_mutex_unlock(&g_intr_test_mtx);
}

void
pci_generate_msi(struct pci_devinst *pi __unused, int vector __unused)
{
	g_interrupts++;
}

void
pci_generate_msix(struct pci_devinst *pi __unused, int vector __unused)
{
	g_interrupts++;
}

void vi_pci_modern_reset(struct virtio_softc *vs __unused) {}
int pci_emul_alloc_bar(struct pci_devinst *pi __unused, int bar __unused,
    enum pcibar_type type __unused, uint64_t size __unused) { return (0); }
int pci_emul_add_msixcap(struct pci_devinst *pi __unused, int count __unused,
    int bar __unused) { return (0); }
void pci_emul_add_msicap(struct pci_devinst *pi __unused, int count __unused) {}
void pci_lintr_request(struct pci_devinst *pi __unused) {}
bool vi_pci_is_modern(const struct virtio_softc *vs)
{ return (vs->vs_transport == VIRTIO_PCI_TRANSPORT_MODERN); }
uint64_t vi_pci_modern_read(struct pci_devinst *pi __unused,
    int bar __unused, uint64_t off __unused, int size __unused) { return (0); }
void vi_pci_modern_write(struct pci_devinst *pi __unused, int bar __unused,
    uint64_t off __unused, int size __unused, uint64_t val __unused) {}
int pci_msix_table_bar(struct pci_devinst *pi __unused) { return (-1); }
int pci_msix_pba_bar(struct pci_devinst *pi __unused) { return (-1); }
uint64_t pci_emul_msix_tread(struct pci_devinst *pi __unused,
    uint64_t off __unused, int size __unused) { return (0); }
void pci_emul_msix_twrite(struct pci_devinst *pi __unused,
    uint64_t off __unused, int size __unused, uint64_t val __unused) {}
int pci_msix_enabled(struct pci_devinst *pi __unused) { return (0); }

static void
add_region(uint64_t gpa, void *host, size_t len)
{
	ATF_REQUIRE(g_region_count < (int)nitems(g_regions));
	g_regions[g_region_count].gpa = gpa;
	g_regions[g_region_count].host = host;
	g_regions[g_region_count].len = len;
	g_region_count++;
}

static void
setup_queue(struct virtio_softc *vs, struct virtio_consts *vc,
    struct pci_devinst *pi, struct vqueue_info *vq, struct vring_desc *desc,
    struct vring_avail *avail, struct vring_used *used)
{
	memset(vs, 0, sizeof(*vs));
	memset(pi, 0, sizeof(*pi));
	memset(vq, 0, sizeof(*vq));
	memset(desc, 0, 8 * sizeof(*desc));
	memset(avail, 0, 64);
	memset(used, 0, 128);
	vc->vc_name = "core-test";
	vs->vs_vc = vc;
	vs->vs_pi = pi;
	vs->vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	ATF_REQUIRE(vi_intr_init(vs, 1, 0) == 0);
	vq->vq_vs = vs;
	vq->vq_qsize = 8;
	vq->vq_flags = VQ_ALLOC;
	vq->vq_desc = desc;
	vq->vq_avail = avail;
	vq->vq_used = used;
	avail->idx = 1;
	avail->ring[0] = 0;
	g_region_count = 0;
	g_interrupts = 0;
	g_lintr_asserted = false;
	g_hold_deassert = false;
	g_deassert_entered = false;
}

static void
notify_and_interrupt(void *arg, struct vqueue_info *vq)
{

	vq_interrupt(arg, vq);
}

ATF_TC_WITHOUT_HEAD(notify_without_msix_does_not_relock_device);
ATF_TC_BODY(notify_without_msix_does_not_relock_device, tc)
{
	struct virtio_consts vc = {
		.vc_name = "notify-test",
		.vc_nvq = 1,
		.vc_qnotify = notify_and_interrupt,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;
	pthread_mutex_t device_mtx;
	pid_t pid;
	int status;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		alarm(2);
		memset(&vs, 0, sizeof(vs));
		memset(&pi, 0, sizeof(pi));
		memset(&vq, 0, sizeof(vq));
		if (pthread_mutex_init(&device_mtx, NULL) != 0)
			_exit(2);
		vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
		vs.vs_mtx = &device_mtx;
		vq.vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
		if (vi_intr_init(&vs, 1, 0) != 0)
			_exit(3);
		vi_pci_write(&pi, 0, VIRTIO_PCI_QUEUE_NOTIFY, 2, 0);
		_exit(vs.vs_isr == VIRTIO_PCI_ISR_INTR ? 0 : 4);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFEXITED(status));
	if (WIFEXITED(status))
		ATF_CHECK(WEXITSTATUS(status) == 0);
}

struct interrupt_race_ctx {
	struct virtio_softc *vs;
	bool producer_started;
	bool producer_done;
};

static void *
read_isr_thread(void *arg)
{
	struct virtio_softc *vs = arg;

	(void)vi_isr_read(vs);
	return (NULL);
}

static void *
raise_interrupt_thread(void *arg)
{
	struct interrupt_race_ctx *ctx = arg;

	pthread_mutex_lock(&g_intr_test_mtx);
	ctx->producer_started = true;
	pthread_cond_broadcast(&g_intr_test_cv);
	pthread_mutex_unlock(&g_intr_test_mtx);
	vi_interrupt(ctx->vs, VIRTIO_PCI_ISR_INTR, VIRTIO_MSI_NO_VECTOR);
	pthread_mutex_lock(&g_intr_test_mtx);
	ctx->producer_done = true;
	pthread_cond_broadcast(&g_intr_test_cv);
	pthread_mutex_unlock(&g_intr_test_mtx);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(isr_read_serializes_intx);
ATF_TC_BODY(isr_read_serializes_intx, tc)
{
	struct interrupt_race_ctx ctx;
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct timespec deadline;
	pthread_t producer, reader;
	bool completed_while_deasserting;
	int error;

	memset(&ctx, 0, sizeof(ctx));
	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	vs.vs_pi = &pi;
	ATF_REQUIRE(pthread_mutex_init(&vs.vs_isr_mtx, NULL) == 0);
	ctx.vs = &vs;
	vs.vs_isr = VIRTIO_PCI_ISR_INTR;
	pthread_mutex_lock(&g_intr_test_mtx);
	g_lintr_asserted = true;
	g_hold_deassert = true;
	g_deassert_entered = false;
	pthread_mutex_unlock(&g_intr_test_mtx);

	ATF_REQUIRE(pthread_create(&reader, NULL, read_isr_thread, &vs) == 0);
	pthread_mutex_lock(&g_intr_test_mtx);
	while (!g_deassert_entered)
		pthread_cond_wait(&g_intr_test_cv, &g_intr_test_mtx);
	pthread_mutex_unlock(&g_intr_test_mtx);
	ATF_REQUIRE(pthread_create(&producer, NULL, raise_interrupt_thread,
	    &ctx) == 0);

	pthread_mutex_lock(&g_intr_test_mtx);
	while (!ctx.producer_started)
		pthread_cond_wait(&g_intr_test_cv, &g_intr_test_mtx);
	ATF_REQUIRE(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
	deadline.tv_nsec += 100000000;
	if (deadline.tv_nsec >= 1000000000) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000;
	}
	error = 0;
	while (!ctx.producer_done && error == 0)
		error = pthread_cond_timedwait(&g_intr_test_cv,
		    &g_intr_test_mtx, &deadline);
	completed_while_deasserting = ctx.producer_done;
	g_hold_deassert = false;
	pthread_cond_broadcast(&g_intr_test_cv);
	pthread_mutex_unlock(&g_intr_test_mtx);

	ATF_REQUIRE(pthread_join(reader, NULL) == 0);
	ATF_REQUIRE(pthread_join(producer, NULL) == 0);
	ATF_CHECK(!completed_while_deasserting);
	ATF_CHECK(error == ETIMEDOUT);
	ATF_CHECK(vs.vs_isr == VIRTIO_PCI_ISR_INTR);
	ATF_CHECK(g_lintr_asserted);
}

ATF_TC_WITHOUT_HEAD(direct_mapping_validation);
ATF_TC_BODY(direct_mapping_validation, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vring_desc desc[8];
	struct vi_req req;
	struct iovec iov;
	uint8_t payload[16];

	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	add_region(0x1000, payload, sizeof(payload));
	desc[0].addr = 0x1000;
	desc[0].len = sizeof(payload);
	desc[0].flags = VRING_DESC_F_WRITE;
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == 1);
	ATF_CHECK(iov.iov_base == payload);
	ATF_CHECK(req.readable == 0 && req.writable == 1);

	vq.vq_last_avail = 0;
	desc[0].addr = 0xdead0000;
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == -1);

	vq.vq_last_avail = 0;
	desc[0].addr = 0x1000;
	desc[0].len = 4;
	desc[0].flags = VRING_DESC_F_NEXT;
	desc[0].next = 1;
	desc[1].addr = 0xdead0000;
	desc[1].len = 4;
	desc[1].flags = VRING_DESC_F_WRITE;
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == -1);

	vq.vq_last_avail = 0;
	desc[1].addr = 0x1004;
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == 2);
	ATF_CHECK(req.readable == 1 && req.writable == 1);
}

ATF_TC_WITHOUT_HEAD(indirect_mapping_validation);
ATF_TC_BODY(indirect_mapping_validation, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vring_desc desc[8], indirect[1];
	struct vi_req req;
	struct iovec iov;
	uint8_t payload[8];

	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	vs.vs_negotiated_caps = VIRTIO_RING_F_INDIRECT_DESC;
	add_region(0x1000, payload, sizeof(payload));
	add_region(0x2000, indirect, sizeof(indirect));
	memset(indirect, 0, sizeof(indirect));
	indirect[0].addr = 0x1000;
	indirect[0].len = sizeof(payload);
	indirect[0].flags = VRING_DESC_F_WRITE;
	desc[0].addr = 0x2000;
	desc[0].len = sizeof(indirect);
	desc[0].flags = VRING_DESC_F_INDIRECT;
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == 1);
	ATF_CHECK(iov.iov_base == payload && req.writable == 1);

	vq.vq_last_avail = 0;
	desc[0].addr = 0xdead0000;
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == -1);

	vq.vq_last_avail = 0;
	desc[0].addr = 0x2000;
	indirect[0].addr = 0xbeef0000;
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == -1);
}

ATF_TC_WITHOUT_HEAD(event_idx_interrupts);
ATF_TC_BODY(event_idx_interrupts, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vring_desc desc[8];
	struct vring_avail *avail;
	struct vring_used *used;

	avail = (struct vring_avail *)avail_mem.bytes;
	used = (struct vring_used *)used_mem.bytes;
	setup_queue(&vs, &vc, &pi, &vq, desc, avail, used);
	vs.vs_negotiated_caps = VIRTIO_RING_F_EVENT_IDX;
	used->idx = 1;
	avail->ring[vq.vq_qsize] = 0;
	vq_endchains(&vq, 0);
	ATF_CHECK(g_interrupts == 1);

	used->idx = 2;
	avail->ring[vq.vq_qsize] = 2;
	vq_endchains(&vq, 0);
	ATF_CHECK(g_interrupts == 1);

	used->idx = 3;
	avail->ring[vq.vq_qsize] = 2;
	vq_endchains(&vq, 0);
	ATF_CHECK(g_interrupts == 2);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, direct_mapping_validation);
	ATF_TP_ADD_TC(tp, indirect_mapping_validation);
	ATF_TP_ADD_TC(tp, event_idx_interrupts);
	ATF_TP_ADD_TC(tp, notify_without_msix_does_not_relock_device);
	ATF_TP_ADD_TC(tp, isr_read_serializes_intx);
	return (atf_no_error());
}
