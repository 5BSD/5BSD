/*
 * End-to-end PCI post-init test for virtio-iommu.
 *
 * virtio_iommu_pci_test.c proves the post-init transaction ordering with
 * mocked topology, registration, and DMA-domain primitives.  This harness
 * instead links the production VirtIO core, the modern PCI transport, the
 * virtio-iommu PCI model, and every virtio_iommu_* helper, and constructs
 * both functions the way bhyve's pci_emul_init() does for
 *
 *   -s 5,virtio-iommu -s 7,virtio-blk,<img>,transport=modern
 *
 * Only the PCI configuration-space/BAR plumbing (pci_emul.c), the config
 * tree, and guest memory are stubbed.  pci_next() walks the stub bus in
 * bus/slot/function order exactly like pci_emul.c.
 */
#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include <bhyve/pci_emul.h>
#include <bhyve/virtio.h>

#undef PCI_EMUL_SET
#define	PCI_EMUL_SET(name)

#include "bhyve/virtio_packed.c"
#include "bhyve/virtio.c"
#include "bhyve/virtio_pci_modern.c"
#include "bhyve/virtio_iommu_config.c"
#include "bhyve/virtio_iommu_event.c"
#include "bhyve/virtio_iommu_protocol.c"
#include "bhyve/virtio_iommu_queue.c"
#include "bhyve/virtio_iommu_request.c"
#include "bhyve/virtio_iommu_state.c"
#include "bhyve/virtio_iommu_topology.c"
#include "bhyve/pci_virtio_iommu.c"

/* ------------------------------------------------------------------ */
/* Link-boundary stubs for code outside the VirtIO/IOMMU translation units. */

struct vmctx { int unused; };

struct test_config {
	const char *transport;
};

const char *
get_config_value_node(const nvlist_t *parent, const char *name)
{
	const struct test_config *cfg;

	cfg = (const struct test_config *)(const void *)parent;
	if (cfg != NULL && strcmp(name, "transport") == 0)
		return (cfg->transport);
	return (NULL);
}

bool
get_config_bool_node_default(const nvlist_t *parent __unused,
    const char *name __unused, bool def)
{

	return (def);
}

bool
get_config_bool_default(const char *name __unused, bool def)
{

	return (def);
}

int
fbsdrun_virtio_msix(void)
{

	return (1);
}

#ifndef VIRTIO_IOMMU_POST_INIT_GUEST_MEMORY
void *
paddr_guest2host(struct vmctx *ctx __unused, uintptr_t addr __unused,
    size_t len __unused)
{

	return (NULL);
}
#endif

/*
 * Model of pci_emul.c's deferred BAR list.  pci_emul_alloc_bar() records
 * (pi, idx, type) and, for a 64-bit BAR, retypes idx + 1 as its upper half.
 * init_pci() later walks the list and pci_emul_assign_bar() registers each
 * entry by pi->pi_bar[idx].type; with bhyveload (pci.enable_bars defaults
 * on) a MEMHI64 entry reaches modify_bar_registration_error()'s default case
 * and init_pci() fails with EINVAL and no diagnostic.
 */
#define	TEST_BAR_MAX	32
static struct {
	struct pci_devinst *pi;
	int idx;
	enum pcibar_type type;
} test_bars[TEST_BAR_MAX];
static size_t test_bar_count;

void
pci_emul_alloc_bar(struct pci_devinst *pdi, int idx, enum pcibar_type type,
    uint64_t size)
{

	ATF_REQUIRE(idx >= 0 && idx <= PCI_BARMAX);
	ATF_REQUIRE(type != PCIBAR_MEM64 || idx + 1 <= PCI_BARMAX);
	pdi->pi_bar[idx].type = type;
	pdi->pi_bar[idx].size = size;
	if (type == PCIBAR_MEM64)
		pdi->pi_bar[idx + 1].type = PCIBAR_MEMHI64;
	ATF_REQUIRE(test_bar_count < TEST_BAR_MAX);
	test_bars[test_bar_count].pi = pdi;
	test_bars[test_bar_count].idx = idx;
	test_bars[test_bar_count].type = type;
	test_bar_count++;
}

/* pci_emul_assign_bar() + modify_bar_registration_error() for each entry. */
static int
test_assign_bars(void)
{
	struct pci_devinst *pi;
	size_t i;
	int idx;

	for (i = 0; i < test_bar_count; i++) {
		pi = test_bars[i].pi;
		idx = test_bars[i].idx;
		switch (pi->pi_bar[idx].type) {
		case PCIBAR_IO:
		case PCIBAR_MEM32:
		case PCIBAR_MEM64:
			break;
		default:
			fprintf(stderr, "%s BAR %d allocated as type %d but "
			    "now type %d: init_pci() fails with EINVAL\n",
			    pi->pi_d->pe_emu, idx, test_bars[i].type,
			    pi->pi_bar[idx].type);
			return (EINVAL);
		}
	}
	return (0);
}

int
pci_emul_add_capability(struct pci_devinst *pi __unused,
    const u_char *capdata __unused, int caplen __unused)
{

	return (0);
}

int
pci_emul_add_msixcap(struct pci_devinst *pi, int msgnum, int barnum)
{

	/* As pci_emul.c: the table and PBA share one 32-bit memory BAR. */
	ATF_REQUIRE(msgnum >= 1 && barnum >= 0 && barnum <= PCIR_MAX_BAR_0);
	pi->pi_msix.table_bar = barnum;
	pi->pi_msix.pba_bar = barnum;
	pi->pi_msix.table_count = msgnum;
	pci_emul_alloc_bar(pi, barnum, PCIBAR_MEM32, 8192);
	return (0);
}

int
pci_emul_add_msicap(struct pci_devinst *pi __unused, int msgnum __unused)
{

	return (0);
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

/* A stub bus in bus/slot/function order. */
#define	TEST_PCI_MAX	8
static struct pci_devinst *test_bus[TEST_PCI_MAX];
static size_t test_bus_count;

struct pci_devinst *
pci_next(const struct pci_devinst *cursor)
{
	size_t i;

	if (cursor == NULL)
		return (test_bus_count == 0 ? NULL : test_bus[0]);
	for (i = 0; i < test_bus_count; i++) {
		if (test_bus[i] == cursor)
			return (i + 1 < test_bus_count ? test_bus[i + 1] : NULL);
	}
	return (NULL);
}

/* ------------------------------------------------------------------ */
/* A modern virtio-blk-shaped peer built through the production helpers. */

struct test_blk_softc {
	struct virtio_softc vs;
	pthread_mutex_t mtx;
	struct vqueue_info vq[1];
	struct virtio_consts consts;
};

static void
test_blk_reset(void *arg)
{
	struct test_blk_softc *sc;

	sc = arg;
	vi_reset_dev(&sc->vs);
}

static void
test_blk_notify(void *arg __unused, struct vqueue_info *vq __unused)
{
}

static int
test_blk_cfgread(void *arg __unused, int offset __unused, int size __unused,
    uint32_t *value)
{

	*value = 0;
	return (0);
}

static int
test_blk_cfgwrite(void *arg __unused, int offset __unused, int size __unused,
    uint32_t value __unused)
{

	return (0);
}

static int
test_blk_init(struct pci_devinst *pi, const struct test_config *cfg)
{
	struct test_blk_softc *sc;

	sc = calloc(1, sizeof(*sc));
	ATF_REQUIRE(sc != NULL);
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc->mtx, NULL), 0);
	sc->consts = (struct virtio_consts) {
		.vc_name = "vtblk",
		.vc_nvq = 1,
		.vc_cfgsize = 64,
		.vc_reset = test_blk_reset,
		.vc_qnotify = test_blk_notify,
		.vc_cfgread = test_blk_cfgread,
		.vc_cfgwrite = test_blk_cfgwrite,
	};
	vi_softc_linkup(&sc->vs, &sc->consts, sc, pi, sc->vq);
	sc->vs.vs_mtx = &sc->mtx;
	sc->vq[0].vq_qsize = 128;
	if (vi_pci_select_transport(&sc->vs, (const nvlist_t *)(const void *)cfg,
	    VIRTIO_PCI_LEGACY_DEFAULT) != 0)
		return (1);
	if (vi_pci_is_modern(&sc->vs))
		vi_pci_modern_set_identity(&sc->vs, VIRTIO_ID_BLOCK);
	if (vi_intr_init(&sc->vs, 1, fbsdrun_virtio_msix()) != 0)
		return (1);
	if (vi_pci_is_modern(&sc->vs))
		return (vi_pci_modern_init(&sc->vs, 2) != 0);
	vi_set_io_bar(&sc->vs, 0);
	return (0);
}

static struct pci_devemu test_blk_de = {
	.pe_emu = "virtio-blk",
	.pe_barwrite = vi_pci_write,
	.pe_barread = vi_pci_read,
};

static struct pci_devinst *
test_pi(struct pci_devemu *de, int slot)
{
	struct pci_devinst *pi;

	pi = calloc(1, sizeof(*pi));
	ATF_REQUIRE(pi != NULL);
	pi->pi_d = de;
	pi->pi_slot = slot;
	ATF_REQUIRE(test_bus_count < TEST_PCI_MAX);
	test_bus[test_bus_count++] = pi;
	return (pi);
}

static const struct test_config test_legacy = { NULL };
static const struct test_config test_modern = { "modern" };

/*
 * Build the failing host configuration through each device's init path in
 * PCI slot order, as init_pci() does: legacy root disk at 0:3,
 * virtio-iommu at 0:5, and a modern virtio-blk endpoint at 0:7.
 */
static void
test_host_topology(struct pci_devinst **iommu, struct pci_devinst **ep)
{
	struct pci_devinst *root;

	test_bus_count = 0;
	test_bar_count = 0;
	root = test_pi(&test_blk_de, 3);
	*iommu = test_pi((struct pci_devemu *)(uintptr_t)&pci_de_vtiommu, 5);
	*ep = test_pi(&test_blk_de, 7);
	ATF_REQUIRE_EQ(test_blk_init(root, &test_legacy), 0);
	ATF_REQUIRE_EQ(pci_vtiommu_init(*iommu, NULL), 0);
	ATF_REQUIRE_EQ(test_blk_init(*ep, &test_modern), 0);
}

/*
 * Every BAR the IOMMU allocates must still have its allocation type when
 * init_pci() assigns and registers it, and the MSI-X table/PBA BAR must be
 * a 32-bit memory BAR distinct from both halves of the 64-bit modern
 * VirtIO BAR.  Passing the vector count as the MSI-X BAR index put the
 * table in BAR 3, the upper half of BAR 2, and bhyve exited with
 * "Device emulation initialization error".
 */
ATF_TC_WITHOUT_HEAD(msix_bar_does_not_overlap_modern_bar);
ATF_TC_BODY(msix_bar_does_not_overlap_modern_bar, tc)
{
	struct pci_devinst *iommu, *ep;
	struct virtio_softc *vs;
	int msix_bar, modern_bar;

	test_host_topology(&iommu, &ep);
	vs = vi_pci_get_softc(iommu);
	ATF_REQUIRE(vs != NULL);
	ATF_REQUIRE(vs->vs_modern != NULL);
	msix_bar = iommu->pi_msix.table_bar;
	modern_bar = 2;
	ATF_CHECK_EQ(iommu->pi_msix.pba_bar, msix_bar);
	ATF_CHECK_EQ(iommu->pi_bar[modern_bar].type, PCIBAR_MEM64);
	ATF_CHECK_EQ(iommu->pi_bar[modern_bar + 1].type, PCIBAR_MEMHI64);
	if (msix_bar == modern_bar || msix_bar == modern_bar + 1)
		fprintf(stderr, "virtio-iommu MSI-X BAR %d overlaps modern "
		    "BAR %d/%d\n", msix_bar, modern_bar, modern_bar + 1);
	ATF_CHECK(msix_bar != modern_bar && msix_bar != modern_bar + 1);
	ATF_CHECK_EQ(iommu->pi_bar[msix_bar].type, PCIBAR_MEM32);
	/* The endpoint uses the same layout as every other modern device. */
	ATF_CHECK_EQ(ep->pi_msix.table_bar, 1);
	ATF_CHECK_EQ(test_assign_bars(), 0);
}

/*
 * PCI post-init with the production DMA-domain code must bind exactly the
 * modern endpoint and expose it in the VIOT topology.
 */
ATF_TC_WITHOUT_HEAD(host_topology_post_init_binds_endpoint);
ATF_TC_BODY(host_topology_post_init_binds_endpoint, tc)
{
	struct pci_devinst *iommu, *ep;
	struct virtio_softc *ep_vs;
	const uint16_t *endpoints;
	size_t endpoint_count;
	uint16_t bdf;
	int error;

	test_host_topology(&iommu, &ep);
	error = pci_vtiommu_post_init(iommu);
	if (error != 0)
		fprintf(stderr, "pci_vtiommu_post_init: %d (%s)\n", error,
		    strerror(error));
	ATF_CHECK_EQ(error, 0);
	ATF_REQUIRE_EQ(pci_vtiommu_viot_info(iommu, &bdf, &endpoints,
	    &endpoint_count), 0);
	ATF_CHECK_EQ(bdf, 5 << 3);
	ATF_REQUIRE_EQ(endpoint_count, 1U);
	ATF_CHECK_EQ(endpoints[0], 7 << 3);
	ep_vs = vi_pci_get_softc(ep);
	ATF_REQUIRE(ep_vs != NULL);
	ATF_CHECK(atomic_load(&ep_vs->vs_dma_domain_ops) == &vtiommu_dma_ops);
	ATF_CHECK((vi_modern_device_features(ep_vs) &
	    VIRTIO_F_ACCESS_PLATFORM) != 0);
}

#ifndef VIRTIO_IOMMU_POST_INIT_NO_TP
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, msix_bar_does_not_overlap_modern_bar);
	ATF_TP_ADD_TC(tp, host_topology_post_init_binds_endpoint);
	return (atf_no_error());
}
#endif
