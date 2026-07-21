/*
 * Integration test for the bhyve VirtIO entropy interrupt path.  This uses
 * the real device callback and shared VirtIO core with a small guest-memory
 * mapping, while mocking only the PCI/VMM boundary.
 */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "pci_emul.h"
#include <bhyve/virtio.h>
#define	MOCK_VIRTIO_H

static int test_open(const char *, int, ...);
static int test_close(int);
static ssize_t test_read(int, void *, size_t);
static ssize_t test_readv(int, const struct iovec *, int);

#define	open	test_open
#define	close	test_close
#define	read	test_read
#define	readv	test_readv
#include "pci_virtio_rnd.c"
#undef open
#undef close
#undef read
#undef readv

#include "virtio.c"

struct nvlist {
	int unused;
};

static uint8_t g_guest_buf[64];
static int g_read_calls;
static int g_msi_count;
static bool g_lintr_asserted;

static int
test_open(const char *path __unused, int flags __unused, ...)
{

	return (10);
}

static int
test_close(int fd __unused)
{

	return (0);
}

static ssize_t
test_read(int fd __unused, void *buf, size_t len)
{

	g_read_calls++;
	memset(buf, 0xa5, len);
	return ((ssize_t)len);
}

static ssize_t
test_readv(int fd __unused, const struct iovec *iov, int iovcnt)
{
	ssize_t total;

	g_read_calls++;
	total = 0;
	for (int i = 0; i < iovcnt; i++) {
		memset(iov[i].iov_base, 0xa5, iov[i].iov_len);
		total += iov[i].iov_len;
	}
	return (total);
}

void *
paddr_guest2host(struct vmctx *ctx __unused, uintptr_t gpa, size_t len)
{

	if (gpa < 0x1000 || gpa - 0x1000 > sizeof(g_guest_buf) ||
	    len > sizeof(g_guest_buf) - (gpa - 0x1000))
		return (NULL);
	return (&g_guest_buf[gpa - 0x1000]);
}

bool
vi_pci_is_modern(const struct virtio_softc *vs)
{

	return (vs->vs_transport == VIRTIO_PCI_TRANSPORT_MODERN);
}

void
vi_pci_modern_reset(struct virtio_softc *vs __unused)
{
}

uint64_t
vi_pci_modern_read(struct pci_devinst *pi __unused, int bar __unused,
    uint64_t offset __unused, int size __unused)
{

	return (0);
}

void
vi_pci_modern_write(struct pci_devinst *pi __unused, int bar __unused,
    uint64_t offset __unused, int size __unused, uint64_t value __unused)
{
}

int
pci_msix_enabled(struct pci_devinst *pi __unused)
{

	return (0);
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

uint64_t
pci_emul_msix_tread(struct pci_devinst *pi __unused, uint64_t offset __unused,
    int size __unused)
{

	return (0);
}

void
pci_emul_msix_twrite(struct pci_devinst *pi __unused,
    uint64_t offset __unused, int size __unused, uint64_t value __unused)
{
}

void
pci_generate_msi(struct pci_devinst *pi __unused, int vector __unused)
{

	g_msi_count++;
}

void
pci_generate_msix(struct pci_devinst *pi __unused, int vector __unused)
{
}

void
pci_lintr_assert(struct pci_devinst *pi __unused)
{

	g_lintr_asserted = true;
}

void
pci_lintr_deassert(struct pci_devinst *pi __unused)
{

	g_lintr_asserted = false;
}

int
pci_emul_alloc_bar(struct pci_devinst *pi __unused, int bar __unused,
    enum pcibar_type type __unused, uint64_t size __unused)
{

	return (0);
}

int
pci_emul_add_msixcap(struct pci_devinst *pi __unused, int count __unused,
    int bar __unused)
{

	return (0);
}

void
pci_emul_add_msicap(struct pci_devinst *pi __unused, int count __unused)
{
}

void
pci_lintr_request(struct pci_devinst *pi __unused)
{
}

static int
run_entropy_interrupt_path(void)
{
	union {
		max_align_t align;
		uint8_t bytes[64];
	} avail_mem;
	union {
		max_align_t align;
		uint8_t bytes[128];
	} used_mem;
	struct pci_vtrnd_softc sc;
	struct pci_devinst pi;
	struct vring_avail *avail;
	struct vring_used *used;
	struct vring_desc desc[8];
	uint64_t isr;

	memset(&sc, 0, sizeof(sc));
	memset(&pi, 0, sizeof(pi));
	memset(desc, 0, sizeof(desc));
	memset(&avail_mem, 0, sizeof(avail_mem));
	memset(&used_mem, 0, sizeof(used_mem));
	memset(g_guest_buf, 0, sizeof(g_guest_buf));
	g_read_calls = 0;
	g_msi_count = 0;
	g_lintr_asserted = false;
	if (pthread_mutex_init(&sc.vrsc_mtx, NULL) != 0)
		return (1);
	vi_softc_linkup(&sc.vrsc_vs, &vtrnd_vi_consts, &sc, &pi,
	    &sc.vrsc_vq);
	sc.vrsc_vs.vs_mtx = &sc.vrsc_mtx;
	if (vi_intr_init(&sc.vrsc_vs, 1, 0) != 0)
		return (2);
	sc.vrsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	sc.vrsc_fd = 10;
	sc.vrsc_vq.vq_qsize = nitems(desc);
	sc.vrsc_vq.vq_flags = VQ_ALLOC;
	sc.vrsc_vq.vq_desc = desc;
	avail = (struct vring_avail *)avail_mem.bytes;
	used = (struct vring_used *)used_mem.bytes;
	sc.vrsc_vq.vq_avail = avail;
	sc.vrsc_vq.vq_used = used;
	sc.vrsc_vq.vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	desc[0].addr = 0x1000;
	desc[0].len = sizeof(g_guest_buf) / 2;
	desc[0].flags = VRING_DESC_F_WRITE | VRING_DESC_F_NEXT;
	desc[0].next = 1;
	desc[1].addr = 0x1000 + sizeof(g_guest_buf) / 2;
	desc[1].len = sizeof(g_guest_buf) / 2;
	desc[1].flags = VRING_DESC_F_WRITE;
	avail->idx = 1;
	avail->ring[0] = 0;

	/* vi_pci_write() holds the non-recursive device mutex here. */
	vi_pci_write(&pi, 0, VIRTIO_PCI_QUEUE_NOTIFY, 2, 0);

	if (g_read_calls != 1 || used->idx != 1 || used->ring[0].id != 0 ||
	    used->ring[0].len != sizeof(g_guest_buf))
		return (3);
	if (sc.vrsc_vs.vs_isr != VIRTIO_PCI_ISR_INTR || g_msi_count != 1 ||
	    !g_lintr_asserted)
		return (4);
	isr = vi_pci_read(&pi, 0, VIRTIO_PCI_ISR, 1);
	if (isr != VIRTIO_PCI_ISR_INTR || sc.vrsc_vs.vs_isr != 0 ||
	    g_lintr_asserted)
		return (5);
	for (size_t i = 0; i < sizeof(g_guest_buf); i++) {
		if (g_guest_buf[i] != 0xa5)
			return (6);
	}
	return (0);
}

ATF_TC_WITHOUT_HEAD(entropy_notify_interrupt);
ATF_TC_BODY(entropy_notify_interrupt, tc)
{
	pid_t pid;
	int status;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		alarm(2);
		_exit(run_entropy_interrupt_path());
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFEXITED(status));
	if (WIFEXITED(status))
		ATF_CHECK(WEXITSTATUS(status) == 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, entropy_notify_interrupt);
	return (atf_no_error());
}
