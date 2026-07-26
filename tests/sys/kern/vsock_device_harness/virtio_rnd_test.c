/* Fault-injection tests for bhyve's VirtIO entropy device. */
#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

static int test_open(const char *, int, ...);
static int test_close(int);
static ssize_t test_read(int, void *, size_t);
static ssize_t test_readv(int, const struct iovec *, int);

#define open test_open
#define close test_close
#define read test_read
#define readv test_readv
#include "pci_virtio_rnd.c"
#undef open
#undef close
#undef read
#undef readv
#include "virtio_1_4_spec.h"

#undef VIRTIO_F_IN_ORDER
#define	VIRTIO_F_IN_ORDER	VIRTIO14_F_IN_ORDER
#undef VIRTIO_F_SUSPEND
#define	VIRTIO_F_SUSPEND	VIRTIO14_F_SUSPEND

#define	TEST_HOST_RND_READ_LIMIT	(64U * 1024U)

struct nvlist { int unused; };

static int g_open_result, g_read_calls, g_close_calls;
static ssize_t g_read_result;
static int g_read_errno;
static bool g_readv_eintr_once;
static size_t g_readv_bytes;
static int g_descs, g_chain_n, g_readable, g_writable;
static bool g_null_iov;
static size_t g_iov_len;
static uint8_t g_iov[VTRND_MAX_BYTES * 2];
static int g_rel_calls, g_ret_calls, g_end_calls, g_needs_reset;

int
vi_pci_lifecycle_noop(void *vsc __unused)
{

	return (0);
}
static uint32_t g_rel_len;
static uint16_t g_rel_idx[8];
static uint16_t g_next_idx;

static void
reset_mocks(void)
{
	g_open_result = 10;
	g_read_result = 1;
	g_read_errno = EIO;
	g_readv_eintr_once = false;
	g_readv_bytes = 0;
	g_read_calls = g_close_calls = 0;
	g_descs = g_chain_n = g_writable = 1;
	g_readable = 0;
	g_null_iov = false;
	g_iov_len = sizeof(g_iov);
	g_rel_calls = g_ret_calls = g_end_calls = g_needs_reset = 0;
	g_rel_len = UINT32_MAX;
	memset(g_rel_idx, 0, sizeof(g_rel_idx));
	g_next_idx = 7;
}

static int
test_open(const char *path __unused, int flags __unused, ...)
{
	if (g_open_result < 0)
		errno = EIO;
	return (g_open_result);
}

static int
test_close(int fd __unused)
{
	g_close_calls++;
	return (0);
}

static ssize_t
test_read(int fd __unused, void *buf, size_t len)
{
	g_read_calls++;
	if (g_read_result < 0) {
		errno = g_read_errno;
		return (-1);
	}
	if (g_read_result > 0 && len > 0)
		memset(buf, 0xa5, MIN((size_t)g_read_result, len));
	return (g_read_result);
}

static ssize_t
test_readv(int fd __unused, const struct iovec *iov, int iovcnt)
{
	ssize_t left;

	g_read_calls++;
	if (g_readv_eintr_once) {
		g_readv_eintr_once = false;
		errno = EINTR;
		return (-1);
	}
	g_readv_bytes = 0;
	for (int i = 0; i < iovcnt; i++)
		g_readv_bytes += iov[i].iov_len;
	if (g_read_result < 0) {
		errno = g_read_errno;
		return (-1);
	}
	left = g_read_result;
	for (int i = 0; i < iovcnt && left > 0; i++) {
		size_t len = MIN((size_t)left, iov[i].iov_len);

		memset(iov[i].iov_base, 0xa5, len);
		left -= len;
	}
	return (g_read_result - left);
}

int
vq_has_descs(struct vqueue_info *vq __unused)
{
	return (g_descs > 0);
}

int
vq_getchain(struct vqueue_info *vq __unused, struct iovec *iov, int niov,
    struct vi_req *req)
{
	if (g_chain_n <= 0)
		return (g_chain_n);
	ATF_REQUIRE(niov == VTRND_RINGSZ);
	for (int i = 0; i < MIN(g_chain_n, niov); i++) {
		iov[i].iov_base = g_null_iov ? NULL :
		    g_iov + i * sizeof(g_iov) / MIN(g_chain_n, niov);
		iov[i].iov_len = g_iov_len;
	}
	req->idx = g_next_idx++;
	req->readable = g_readable;
	req->writable = g_writable;
	g_descs--;
	return (g_chain_n);
}

void
vq_relchain(struct vqueue_info *vq __unused, uint16_t idx, uint32_t len)
{
	ATF_REQUIRE(g_rel_calls < (int)nitems(g_rel_idx));
	ATF_CHECK_EQ(idx, 7 + g_rel_calls);
	g_rel_idx[g_rel_calls] = idx;
	g_rel_calls++;
	g_rel_len = len;
}

void
vq_retchains(struct vqueue_info *vq __unused, uint16_t count)
{
	g_ret_calls += count;
	g_descs += count;
}

void
vq_endchains(struct vqueue_info *vq __unused, int all_avail __unused)
{
	g_end_calls++;
}

void
vi_softc_linkup(struct virtio_softc *vs, struct virtio_consts *vc,
    void *softc __unused, struct pci_devinst *pi, struct vqueue_info *queues)
{
	memset(vs, 0, sizeof(*vs));
	vs->vs_vc = vc;
	vs->vs_pi = pi;
	vs->vs_queues = queues;
	pi->pi_arg = vs;
	queues->vq_vs = vs;
}

int
vi_pci_select_transport(struct virtio_softc *vs, const nvlist_t *nvl __unused,
    enum virtio_pci_transport_policy policy)
{
	ATF_CHECK(policy == VIRTIO_PCI_LEGACY_DEFAULT);
	vs->vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	return (0);
}

bool vi_pci_is_modern(const struct virtio_softc *vs)
{ return (vs->vs_transport == VIRTIO_PCI_TRANSPORT_MODERN); }
void vi_pci_modern_set_identity(struct virtio_softc *vs __unused,
    uint16_t id __unused) {}
int vi_pci_modern_init(struct virtio_softc *vs __unused, int bar __unused)
{ return (0); }
int vi_intr_init(struct virtio_softc *vs __unused, int bar __unused,
    int msix __unused) { return (0); }
void vi_set_io_bar(struct virtio_softc *vs __unused, int bar __unused) {}
void vi_reset_dev(struct virtio_softc *vs __unused) {}
void vi_set_needs_reset(struct virtio_softc *vs __unused)
{ g_needs_reset++; }
int fbsdrun_virtio_msix(void) { return (1); }
int vi_pci_modern_cfgread(struct pci_devinst *pi __unused,
    int off __unused, int size __unused, uint32_t *val __unused) { return (0); }
int vi_pci_modern_cfgwrite(struct pci_devinst *pi __unused,
    int off __unused, int size __unused, uint32_t val __unused) { return (0); }
uint64_t vi_pci_read(struct pci_devinst *pi __unused, int bar __unused,
    uint64_t off __unused, int size __unused) { return (0); }
void vi_pci_write(struct pci_devinst *pi __unused, int bar __unused,
    uint64_t off __unused, int size __unused, uint64_t val __unused) {}
void pci_set_cfgdata8(struct pci_devinst *pi, int off, uint8_t val)
{ pi->pi_cfgdata[off] = val; }
void pci_set_cfgdata16(struct pci_devinst *pi, int off, uint16_t val)
{ memcpy(&pi->pi_cfgdata[off], &val, sizeof(val)); }

ATF_TC_WITHOUT_HEAD(hostile_descriptors);
ATF_TC_BODY(hostile_descriptors, tc)
{
	struct pci_vtrnd_softc sc;
	struct vqueue_info vq;

	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	sc.vrsc_fd = 10;
	for (int kind = 0; kind < 6; kind++) {
		reset_mocks();
		switch (kind) {
		case 0: g_chain_n = VTRND_RINGSZ + 1; break;
		case 1: g_readable = 1; g_writable = 0; break;
		case 2: g_null_iov = true; break;
		case 3: g_iov_len = 0; break;
		case 4: g_chain_n = -1; break;
		case 5: g_chain_n = 0; break;
		}
		pci_vtrnd_notify(&sc, &vq);
		ATF_CHECK(g_read_calls == 0);
		ATF_CHECK(g_rel_calls == (kind >= 4 ? 0 : 1));
		if (g_rel_calls != 0)
			ATF_CHECK(g_rel_len == 0);
		ATF_CHECK(g_end_calls == 1);
	}
}

ATF_TC_WITHOUT_HEAD(scatter_gather);
ATF_TC_BODY(scatter_gather, tc)
{
	struct pci_vtrnd_softc sc;
	struct vqueue_info vq;

	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	sc.vrsc_fd = 10;
	reset_mocks();
	g_chain_n = 2;
	g_writable = 2;
	g_iov_len = 8;
	g_read_result = 13;
	pci_vtrnd_notify(&sc, &vq);
	ATF_CHECK(g_read_calls == 1);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 13);
	ATF_CHECK(memcmp(g_iov, "\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5", 8) == 0);
	ATF_CHECK(memcmp(g_iov + sizeof(g_iov) / 2,
	    "\xa5\xa5\xa5\xa5\xa5", 5) == 0);
}

ATF_TC_WITHOUT_HEAD(random_read_failures);
ATF_TC_BODY(random_read_failures, tc)
{
	struct pci_vtrnd_softc sc;
	struct vqueue_info vq;

	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	sc.vrsc_fd = 10;
	for (int result = -1; result <= 0; result++) {
		reset_mocks();
		g_read_result = result;
		pci_vtrnd_notify(&sc, &vq);
		ATF_CHECK(g_read_calls == 1);
		ATF_CHECK(g_rel_calls == 0);
		ATF_CHECK(g_ret_calls == 1);
		ATF_CHECK(g_needs_reset == 1);
	}
	reset_mocks();
	g_read_result = -1;
	g_read_errno = EAGAIN;
	pci_vtrnd_notify(&sc, &vq);
	ATF_CHECK(g_rel_calls == 0);
	ATF_CHECK(g_ret_calls == 1);
	ATF_CHECK(g_needs_reset == 1);

	reset_mocks();
	g_readv_eintr_once = true;
	g_read_result = 17;
	pci_vtrnd_notify(&sc, &vq);
	ATF_CHECK(g_read_calls == 2);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 17);
	ATF_CHECK(g_ret_calls == 0 && g_needs_reset == 0);

	reset_mocks();
	g_read_result = 17;
	pci_vtrnd_notify(&sc, &vq);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 17);
}

ATF_TC_WITHOUT_HEAD(read_is_bounded);
ATF_TC_BODY(read_is_bounded, tc)
{
	struct pci_vtrnd_softc sc;
	struct vqueue_info vq;

	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	sc.vrsc_fd = 10;
	reset_mocks();
	g_chain_n = 2;
	g_writable = 2;
	g_iov_len = TEST_HOST_RND_READ_LIMIT;
	g_read_result = TEST_HOST_RND_READ_LIMIT;
	pci_vtrnd_notify(&sc, &vq);

	ATF_CHECK_EQ(g_read_calls, 1);
	ATF_CHECK_EQ(g_readv_bytes, TEST_HOST_RND_READ_LIMIT);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, TEST_HOST_RND_READ_LIMIT);
}

ATF_TC_WITHOUT_HEAD(init_failures);
ATF_TC_BODY(init_failures, tc)
{
	struct pci_devinst pi;
	struct nvlist nvl;

	memset(&pi, 0, sizeof(pi));
	reset_mocks();
	g_open_result = -1;
	ATF_CHECK(pci_vtrnd_init(&pi, &nvl) == 1);
	ATF_CHECK(g_read_calls == 0 && g_close_calls == 0);

	reset_mocks();
	g_read_result = -1;
	ATF_CHECK(pci_vtrnd_init(&pi, &nvl) == 1);
	ATF_CHECK(g_read_calls == 1 && g_close_calls == 1);
}

ATF_TC_WITHOUT_HEAD(in_order_completions);
ATF_TC_BODY(in_order_completions, tc)
{
	struct pci_vtrnd_softc sc;
	struct vqueue_info vq;

	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	sc.vrsc_fd = 10;
	reset_mocks();
	g_descs = 3;
	pci_vtrnd_notify(&sc, &vq);

	ATF_CHECK((vtrnd_vi_consts.vc_hv_caps & VIRTIO_F_IN_ORDER) != 0);
	ATF_CHECK((vtrnd_vi_consts.vc_hv_caps & VIRTIO_F_SUSPEND) != 0);
	ATF_CHECK(vtrnd_vi_consts.vc_suspend == vi_pci_lifecycle_noop);
	ATF_CHECK(vtrnd_vi_consts.vc_resume_device ==
	    vi_pci_lifecycle_noop);
	ATF_CHECK(vtrnd_vi_consts.vc_pause == vi_pci_lifecycle_noop);
	ATF_CHECK(vtrnd_vi_consts.vc_resume == vi_pci_lifecycle_noop);
	ATF_CHECK_EQ(g_read_calls, 3);
	ATF_CHECK_EQ(g_rel_calls, 3);
	ATF_CHECK_EQ(g_rel_idx[0], 7);
	ATF_CHECK_EQ(g_rel_idx[1], 8);
	ATF_CHECK_EQ(g_rel_idx[2], 9);
	ATF_CHECK_EQ(g_end_calls, 1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, hostile_descriptors);
	ATF_TP_ADD_TC(tp, scatter_gather);
	ATF_TP_ADD_TC(tp, random_read_failures);
	ATF_TP_ADD_TC(tp, read_is_bounded);
	ATF_TP_ADD_TC(tp, init_failures);
	ATF_TP_ADD_TC(tp, in_order_completions);
	return (atf_no_error());
}
