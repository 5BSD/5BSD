/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 */

/*
 * The virtio-9p device model on the production VirtIO core: a guest request
 * shaped like a FreeBSD p9fs message in fragmented memory (a P9FS_MTU request
 * and a P9FS_MTU response, one descriptor per page, 66 in all) published as
 * one indirect descriptor.  Features are negotiated through the legacy
 * transport against the device's own offer, and the chain is walked by the
 * production vq_getchain() from pci_vt9p_notify().
 */

#include <sys/param.h>
#include <sys/uio.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include <bhyve/pci_emul.h>
#include <bhyve/virtio.h>

#undef	PCI_EMUL_SET
#define	PCI_EMUL_SET(name)

#include "bhyve/virtio_packed.c"
#include "bhyve/virtio.c"
#include "bhyve/pci_virtio_9p.c"

/* sys/fs/p9fs/p9_client.h P9FS_MTU; sys/dev/virtio/p9fs VT9P_MAX_NSEGS. */
#define	TEST_PAGE_SIZE		4096
#define	TEST_MTU		131072
#define	TEST_OFFSET		512
#define	TEST_BUF_NSEGS		(TEST_MTU / TEST_PAGE_SIZE + 1)
#define	TEST_NSEGS		(2 * TEST_BUF_NSEGS)

#define	TEST_INDIRECT_GPA	UINT64_C(0x100000)
#define	TEST_DATA_GPA		UINT64_C(0x400000)

/* ------------------------------------------------------------------ */
/* Link-boundary stubs for code outside the VirtIO/9P translation units. */

struct vmctx { int unused; };

static struct {
	uint64_t gpa;
	void *host;
	size_t len;
} g_regions[TEST_NSEGS + 1];
static int g_region_count;

static int g_recv_calls;
static size_t g_recv_niov;
static size_t g_recv_bytes;
static struct pci_vt9p_request *g_recv_preq;

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

vm_paddr_t
vm_rev_map_gpa(struct vmctx *ctx __unused, void *mapping __unused)
{

	return ((vm_paddr_t)-1);
}

static void *
test_platform_map(void *arg, uint64_t gpa, size_t len,
    enum virtio_dma_direction direction __unused)
{

	return (paddr_guest2host(arg, gpa, len));
}

static const struct virtio_platform_ops test_platform_ops = {
	.vpo_map_dma = test_platform_map,
	.vpo_msix_enabled = vi_pci_msix_enabled,
	.vpo_raise_msix = vi_pci_raise_msix,
	.vpo_raise_msi = vi_pci_raise_msi,
	.vpo_set_intx = vi_pci_set_intx,
};

int raw_stdio;

/* The device runs on the legacy transport; MSI-X is never enabled. */
bool
vi_pci_is_modern(const struct virtio_softc *vs __unused)
{

	return (false);
}

void
vi_pci_modern_reset(struct virtio_softc *vs __unused)
{

	abort();
}

void
vi_pci_modern_queue_reset_complete(struct vqueue_info *vq __unused,
    uint64_t generation __unused, int error __unused)
{

	abort();
}

void
vi_pci_modern_write(struct pci_devinst *pi __unused, int baridx __unused,
    uint64_t offset __unused, int size __unused, uint64_t value __unused)
{

	abort();
}

int
pci_emul_add_msicap(struct pci_devinst *pi __unused, int msgnum __unused)
{

	return (0);
}

int
pci_emul_add_msixcap(struct pci_devinst *pi __unused, int msgnum __unused,
    int barnum __unused)
{

	abort();
}

int
pci_emul_msix_twrite(struct pci_devinst *pi __unused,
    uint64_t offset __unused, int size __unused, uint64_t value __unused)
{

	abort();
}

int
pci_msix_table_bar(struct pci_devinst *pi __unused)
{

	return (-1);
}

int
pci_msix_pba_bar(struct pci_devinst *pi __unused)
{

	return (-1);
}

int
pci_msix_enabled(struct pci_devinst *pi __unused)
{

	return (0);
}

int
pci_msi_enabled(struct pci_devinst *pi __unused)
{

	return (0);
}

void
pci_generate_msix(struct pci_devinst *pi __unused, int index __unused)
{
}

void
pci_generate_msi(struct pci_devinst *pi __unused, int index __unused)
{
}

void
pci_lintr_request(struct pci_devinst *pi __unused)
{
}

void
pci_lintr_assert(struct pci_devinst *pi __unused)
{
}

void
pci_lintr_deassert(struct pci_devinst *pi __unused)
{
}

int
l9p_connection_recv(struct l9p_connection *conn __unused,
    const struct iovec *iov, size_t niov, void *aux)
{

	g_recv_calls++;
	g_recv_niov = niov;
	g_recv_bytes = 0;
	for (size_t i = 0; i < niov; i++)
		g_recv_bytes += iov[i].iov_len;
	g_recv_preq = aux;
	return (0);
}

int
l9p_connection_init(struct l9p_server *server __unused,
    struct l9p_connection **conn __unused)
{

	abort();
}

void
l9p_connection_free(struct l9p_connection *conn __unused)
{

	abort();
}

void
l9p_connection_close(struct l9p_connection *conn __unused)
{

	abort();
}

/* ------------------------------------------------------------------ */

static struct l9p_connection g_connection;

struct test_ring {
	struct pci_vt9p_softc sc;
	struct pci_devinst pi;
	struct vring_desc desc[VT9P_RINGSZ];
	union {
		max_align_t align;
		uint8_t bytes[sizeof(struct vring_avail) +
		    (VT9P_RINGSZ + 1) * sizeof(uint16_t)];
	} avail;
	union {
		max_align_t align;
		uint8_t bytes[sizeof(struct vring_used) +
		    VT9P_RINGSZ * sizeof(struct vring_used_elem) +
		    sizeof(uint16_t)];
	} used;
	struct vring_desc indirect[TEST_NSEGS];
	uint8_t pages[TEST_NSEGS][TEST_PAGE_SIZE];
};

static void
add_region(uint64_t gpa, void *host, size_t len)
{

	ATF_REQUIRE(g_region_count < (int)nitems(g_regions));
	g_regions[g_region_count].gpa = gpa;
	g_regions[g_region_count].host = host;
	g_regions[g_region_count].len = len;
	g_region_count++;
}

/*
 * One message buffer of TEST_MTU bytes starting TEST_OFFSET into its first
 * page; the guest pages are not adjacent, so each is its own descriptor.
 */
static void
add_buffer(struct test_ring *t, int first, uint16_t flags)
{
	struct vring_desc *d;
	size_t len, resid;

	resid = TEST_MTU;
	for (int i = first; i < first + TEST_BUF_NSEGS; i++) {
		d = &t->indirect[i];
		d->addr = TEST_DATA_GPA + (uint64_t)i * 2 * TEST_PAGE_SIZE;
		len = TEST_PAGE_SIZE;
		if (i == first) {
			d->addr += TEST_OFFSET;
			len -= TEST_OFFSET;
		}
		len = MIN(len, resid);
		d->len = len;
		d->flags = flags;
		if (i + 1 < TEST_NSEGS) {
			d->flags |= VRING_DESC_F_NEXT;
			d->next = i + 1;
		}
		resid -= len;
	}
	ATF_REQUIRE_EQ(resid, 0);
}

static struct test_ring *
setup_ring(void)
{
	struct test_ring *t;
	struct vring_avail *avail;

	t = calloc(1, sizeof(*t));
	ATF_REQUIRE(t != NULL);
	g_region_count = 0;
	g_recv_calls = 0;
	g_recv_niov = 0;
	g_recv_bytes = 0;
	g_recv_preq = NULL;

	t->sc.vsc_consts = vt9p_vi_consts;
	vi_softc_linkup(&t->sc.vsc_vs, &t->sc.vsc_consts, &t->sc, &t->pi,
	    &t->sc.vsc_vq);
	ATF_REQUIRE_EQ(pthread_mutex_init(&t->sc.vsc_mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&t->sc.vsc_reset_cv, NULL), 0);
	t->sc.vsc_vs.vs_mtx = &t->sc.vsc_mtx;
	t->sc.vsc_vs.vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	vi_set_platform_ops(&t->sc.vsc_vs, &test_platform_ops, NULL);
	ATF_REQUIRE_EQ(vi_intr_init(&t->sc.vsc_vs, 1, 0), 0);
	t->sc.vsc_conn = &g_connection;

	t->sc.vsc_vq.vq_qsize = VT9P_RINGSZ;
	t->sc.vsc_vq.vq_flags = VQ_ALLOC;
	t->sc.vsc_vq.vq_desc = t->desc;
	t->sc.vsc_vq.vq_avail = (struct vring_avail *)(void *)t->avail.bytes;
	t->sc.vsc_vq.vq_used = (struct vring_used *)(void *)t->used.bytes;

	add_region(TEST_INDIRECT_GPA, t->indirect, sizeof(t->indirect));
	for (int i = 0; i < TEST_NSEGS; i++)
		add_region(TEST_DATA_GPA + (uint64_t)i * 2 * TEST_PAGE_SIZE,
		    t->pages[i], TEST_PAGE_SIZE);
	add_buffer(t, 0, 0);
	add_buffer(t, TEST_BUF_NSEGS, VRING_DESC_F_WRITE);

	t->desc[0].addr = TEST_INDIRECT_GPA;
	t->desc[0].len = sizeof(t->indirect);
	t->desc[0].flags = VRING_DESC_F_INDIRECT;
	avail = t->sc.vsc_vq.vq_avail;
	avail->ring[0] = 0;
	avail->idx = 1;
	return (t);
}

/* The legacy driver writes its features, then sets DRIVER_OK. */
static void
negotiate(struct test_ring *t, uint64_t features)
{

	vi_pci_write(&t->pi, 0, VIRTIO_PCI_GUEST_FEATURES, 4, features);
	vi_pci_write(&t->pi, 0, VIRTIO_PCI_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER |
	    VIRTIO_CONFIG_STATUS_DRIVER_OK);
}

ATF_TC_WITHOUT_HEAD(fragmented_mtu_request_uses_one_ring_entry);
ATF_TC_BODY(fragmented_mtu_request_uses_one_ring_entry, tc)
{
	struct test_ring *t;
	struct l9p_request req;
	struct vring_used *used;

	t = setup_ring();
	negotiate(t, VIRTIO_9P_F_MOUNT_TAG | VIRTIO_RING_F_INDIRECT_DESC);
	ATF_REQUIRE_MSG((t->sc.vsc_vs.vs_negotiated_caps &
	    VIRTIO_RING_F_INDIRECT_DESC) != 0,
	    "virtio-9p does not offer indirect descriptors (negotiated %#jx)",
	    (uintmax_t)t->sc.vsc_vs.vs_negotiated_caps);

	pci_vt9p_notify(&t->sc, &t->sc.vsc_vq);
	ATF_REQUIRE_EQ_MSG(g_recv_calls, 1,
	    "the indirect request did not reach lib9p");
	ATF_CHECK_EQ(g_recv_niov, TEST_BUF_NSEGS);
	ATF_CHECK_EQ(g_recv_bytes, TEST_MTU);
	ATF_REQUIRE(g_recv_preq != NULL);
	ATF_CHECK_EQ(g_recv_preq->vsr_niov, TEST_NSEGS);
	ATF_CHECK_EQ(g_recv_preq->vsr_respidx, TEST_BUF_NSEGS);
	ATF_CHECK(g_recv_preq->vsr_iov[TEST_NSEGS - 1].iov_base ==
	    t->pages[TEST_NSEGS - 1]);

	/* The response releases the single ring entry the request used. */
	memset(&req, 0, sizeof(req));
	req.lr_aux = g_recv_preq;
	ATF_CHECK_EQ(pci_vt9p_send(&req, NULL, 0, 4096, NULL), 0);
	used = t->sc.vsc_vq.vq_used;
	ATF_CHECK_EQ(used->idx, 1);
	ATF_CHECK_EQ(used->ring[0].id, 0);
	ATF_CHECK_EQ(used->ring[0].len, 4096);
	ATF_CHECK_EQ(t->sc.vsc_active_requests, 0);
	free(t);
}

ATF_TC_WITHOUT_HEAD(indirect_request_needs_negotiation);
ATF_TC_BODY(indirect_request_needs_negotiation, tc)
{
	struct test_ring *t;

	t = setup_ring();
	negotiate(t, VIRTIO_9P_F_MOUNT_TAG);
	ATF_REQUIRE_EQ(t->sc.vsc_vs.vs_negotiated_caps &
	    VIRTIO_RING_F_INDIRECT_DESC, 0);
	pci_vt9p_notify(&t->sc, &t->sc.vsc_vq);
	ATF_CHECK_EQ(g_recv_calls, 0);
	ATF_CHECK_EQ(t->sc.vsc_active_requests, 0);
	free(t);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fragmented_mtu_request_uses_one_ring_entry);
	ATF_TP_ADD_TC(tp, indirect_request_needs_negotiation);
	return (atf_no_error());
}
