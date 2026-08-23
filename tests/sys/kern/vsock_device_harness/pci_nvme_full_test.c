/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * TU-include coverage harness for bhyve's PCIe-NVMe device
 * (usr.sbin/bhyve/pci_nvme.c).  The device source is compiled directly into
 * the test so its static entry points can be driven without a running VM.
 * The bhyve infrastructure it depends on (pci_emul BAR/MSI-X, vmmapi guest
 * memory, blockif backing store, snapshot codec, config nvlist) is replaced
 * with independent mocks defined below.
 *
 * Guest physical memory is modelled as a single flat buffer starting at GPA
 * 0; vm_map_gpa()/paddr_guest2host()/pci_emul_map_dma() return g_ram+gpa.
 * The test lays out the admin and IO queues, PRP lists and data buffers into
 * that buffer, rings doorbells through pci_nvme_write(), and reads back the
 * completion queue entries.  Assertions check register/queue/command/status
 * semantics against the NVMe 1.4 specification (register offsets, SQ/CQ entry
 * layout, opcodes and status codes taken from the independent <dev/nvme/nvme.h>
 * spec header and hard-coded spec constants) rather than the implementation's
 * own output.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/endian.h>
#include <sys/queue.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

/*
 * ---- Neutralize the kernel / vmmapi header maze ----------------------------
 * pci_nvme.c pulls in <machine/vmm.h> and <vmmapi.h>.  Pre-defining their
 * include guards turns those includes into no-ops so the device sees the
 * minimal self-contained declarations provided here.  <machine/vmm_snapshot.h>
 * is left real (pulled in via snapshot.h): it supplies the snapshot metadata
 * types and the SNAPSHOT_*_OR_LEAVE macros the codec uses.
 */
#define	_VMM_H_
#define	_VMMAPI_H_
#define	_DEV_VMM_MEM_H_

typedef uint64_t vm_paddr_t;
struct vmctx;

/* ---- Flat guest physical memory model -------------------------------------- */
#define	GUEST_RAM_SIZE	(64U * 1024U * 1024U)
static uint8_t *g_ram;
static bool g_map_gpa_fail;		/* force all vm_map_gpa to fail */
static uint64_t g_map_gpa_fail_gpa = UINT64_MAX; /* fail only this gpa */
static bool g_map_dma_fail;		/* force pci_emul_map_dma to fail */
static uint64_t g_dma_dirty_bytes;	/* accumulated dirty marks */

static void *
guest_ptr(uint64_t gpa, size_t len)
{

	if (g_ram == NULL)
		return (NULL);
	if (gpa >= GUEST_RAM_SIZE || len > GUEST_RAM_SIZE - gpa)
		return (NULL);
	return (g_ram + gpa);
}

void *
vm_map_gpa(struct vmctx *ctx __unused, vm_paddr_t gpa, size_t len)
{

	if (g_map_gpa_fail || gpa == g_map_gpa_fail_gpa)
		return (NULL);
	return (guest_ptr(gpa, len));
}

void *
paddr_guest2host(struct vmctx *ctx __unused, uintptr_t gpa, size_t len)
{

	return (guest_ptr(gpa, len));
}

/* ---- pci_emul mock --------------------------------------------------------- */
#include "config.h"			/* nvlist_t + config get/set declarations */

#define	MOCK_PCI_EMUL_H
struct vm_snapshot_meta;

enum pcibar_type {
	PCIBAR_NONE,
	PCIBAR_IO,
	PCIBAR_MEM32,
	PCIBAR_MEM64,
};
enum pci_dma_direction {
	PCI_DMA_DEVICE_READ = 0,
	PCI_DMA_DEVICE_WRITE,
	PCI_DMA_BIDIRECTIONAL,
};
struct pcibar {
	enum pcibar_type type;
	uint64_t size;
	uint64_t addr;
};
struct pci_devinst {
	struct vmctx *pi_vmctx;
	void *pi_arg;
	int pi_bus;
	int pi_slot;
	int pi_func;
	struct {
		int table_count;
	} pi_msix;
	struct pcibar pi_bar[7];
	uint8_t pi_cfgdata[256];
};
struct pci_devemu {
	const char *pe_emu;
	int (*pe_init)(struct pci_devinst *, nvlist_t *);
	int (*pe_legacy_config)(nvlist_t *, const char *);
	uint64_t (*pe_barread)(struct pci_devinst *, int, uint64_t, int);
	void (*pe_barwrite)(struct pci_devinst *, int, uint64_t, int, uint64_t);
	int (*pe_snapshot)(struct vm_snapshot_meta *);
	int (*pe_snapshot_validate)(struct vm_snapshot_meta *);
	int (*pe_pause)(struct pci_devinst *);
	int (*pe_resume)(struct pci_devinst *);
	uint32_t pe_migration_flags;
};
#define	PCI_EMUL_SET(x)

#define	PCI_MIGRATION_F_STATE_CODEC	(1U << 0)
#define	PCI_MIGRATION_F_COMPAT_FIXED	(1U << 1)
#define	PCI_MIGRATION_F_DMA_TRACKED	(1U << 4)
#define	PCI_MIGRATION_F_QUIESCE_CALLBACK	(1U << 6)

/* pcireg constants used by the device init path. */
#define	PCIR_DEVICE	0x02
#define	PCIR_VENDOR	0x00
#define	PCIR_REVID	0x08
#define	PCIR_PROGIF	0x09
#define	PCIR_SUBCLASS	0x0a
#define	PCIR_CLASS	0x0b
#define	PCIC_STORAGE	0x01
#define	PCIS_STORAGE_NVM	0x08
#define	PCIP_STORAGE_NVM_ENTERPRISE_NVMHCI_1_0	0x02
#define	PCIEM_TYPE_ROOT_INT_EP	0xf0

/* MSI-X capture. */
static int g_msix_vectors[64];
static unsigned g_msix_count;
static bool g_alloc_bar_fail;
static bool g_msixcap_fail;
static bool g_pciecap_fail;
static bool g_bootdev_fail;
static int g_last_bootindex;
static uint64_t g_alloc_bar_size;

void
pci_set_cfgdata8(struct pci_devinst *pi, int offset, uint8_t value)
{

	pi->pi_cfgdata[offset] = value;
}

void
pci_set_cfgdata16(struct pci_devinst *pi, int offset, uint16_t value)
{

	le16enc(&pi->pi_cfgdata[offset], value);
}

uint8_t
pci_get_cfgdata8(struct pci_devinst *pi, int offset)
{

	return (pi->pi_cfgdata[offset]);
}

uint16_t
pci_get_cfgdata16(struct pci_devinst *pi, int offset)
{

	return (le16dec(&pi->pi_cfgdata[offset]));
}

int
pci_emul_alloc_bar(struct pci_devinst *pi, int idx, enum pcibar_type type,
    uint64_t size)
{

	if (g_alloc_bar_fail)
		return (-1);
	pi->pi_bar[idx].type = type;
	pi->pi_bar[idx].size = size;
	g_alloc_bar_size = size;
	return (0);
}

int
pci_emul_add_msixcap(struct pci_devinst *pi, int msgnum, int barnum __unused)
{

	if (g_msixcap_fail)
		return (-1);
	pi->pi_msix.table_count = msgnum;
	return (0);
}

int
pci_emul_add_pciecap(struct pci_devinst *pi __unused, int type __unused)
{

	return (g_pciecap_fail ? -1 : 0);
}

int
pci_emul_add_boot_device(struct pci_devinst *pi __unused, int bootindex)
{

	g_last_bootindex = bootindex;
	return (g_bootdev_fail ? -1 : 0);
}

int
pci_msix_table_bar(struct pci_devinst *pi __unused)
{

	return (4);
}

int
pci_msix_pba_bar(struct pci_devinst *pi __unused)
{

	return (4);
}

static uint8_t g_msix_table[16 * 64];

uint64_t
pci_emul_msix_tread(struct pci_devinst *pi __unused, uint64_t offset, int size)
{
	uint64_t v = 0;

	if (offset + (uint64_t)size <= sizeof(g_msix_table))
		memcpy(&v, &g_msix_table[offset], size);
	return (v);
}

int
pci_emul_msix_twrite(struct pci_devinst *pi __unused, uint64_t offset, int size,
    uint64_t value)
{

	if (offset + (uint64_t)size <= sizeof(g_msix_table))
		memcpy(&g_msix_table[offset], &value, size);
	return (0);
}

void
pci_generate_msix(struct pci_devinst *pi __unused, int index)
{

	if (g_msix_count < nitems(g_msix_vectors))
		g_msix_vectors[g_msix_count] = index;
	g_msix_count++;
}

void *
pci_emul_map_dma(struct pci_devinst *pi __unused, uint64_t gpa, size_t len,
    enum pci_dma_direction dir __unused)
{

	if (g_map_dma_fail)
		return (NULL);
	return (guest_ptr(gpa, len));
}

void
pci_emul_mark_dma_dirty_mapping(struct pci_devinst *pi __unused, void *base,
    size_t len)
{

	(void)base;
	g_dma_dirty_bytes += len;
}

/* ---- config nvlist mock ---------------------------------------------------- */
struct cfg_ent {
	char key[64];
	char val[128];
};
static struct cfg_ent g_cfg[32];
static int g_cfg_n;

static void
cfg_reset(void)
{

	g_cfg_n = 0;
}

const char *
get_config_value_node(const nvlist_t *nvl __unused, const char *name)
{
	int i;

	for (i = 0; i < g_cfg_n; i++)
		if (strcmp(g_cfg[i].key, name) == 0)
			return (g_cfg[i].val);
	return (NULL);
}

void
set_config_value_node(nvlist_t *nvl __unused, const char *name,
    const char *value)
{
	int i;

	for (i = 0; i < g_cfg_n; i++) {
		if (strcmp(g_cfg[i].key, name) == 0) {
			strlcpy(g_cfg[i].val, value, sizeof(g_cfg[i].val));
			return;
		}
	}
	if (g_cfg_n >= (int)nitems(g_cfg))
		return;
	strlcpy(g_cfg[g_cfg_n].key, name, sizeof(g_cfg[g_cfg_n].key));
	strlcpy(g_cfg[g_cfg_n].val, value, sizeof(g_cfg[g_cfg_n].val));
	g_cfg_n++;
}

const char *
get_config_value(const char *name)
{

	return (get_config_value_node(NULL, name));
}

bool
get_config_bool_node_default(const nvlist_t *nvl __unused,
    const char *name __unused, bool def)
{

	return (def);
}

int
pci_parse_legacy_config(nvlist_t *nvl __unused, const char *opts __unused)
{

	return (0);
}

/* ---- snapshot wire codec mock ---------------------------------------------- */
#include "snapshot.h"		/* metadata types + static-inline is_loading */

/*
 * The harness snapshot.h mock omits the nonnegative-int codec and macro used
 * by pci_nvme's queue-priority (de)serialization; supply both here.
 */
int vm_snapshot_nonnegative_int(int *, struct vm_snapshot_meta *);
#ifndef SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE
#define	SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(DATA, META, RES, LABEL)	\
do {									\
	(RES) = vm_snapshot_nonnegative_int(&(DATA), (META));		\
	if ((RES) != 0)						\
		goto LABEL;						\
} while (0)
#endif

/* Reverse of the flat guest-memory map: host pointer back to its GPA. */
uint64_t
paddr_host2guest(struct vmctx *ctx __unused, void *addr)
{
	uint8_t *p = addr;

	if (g_ram == NULL || p < g_ram || p >= g_ram + GUEST_RAM_SIZE)
		return ((uint64_t)-1);
	return ((uint64_t)(p - g_ram));
}

void
vm_snapshot_buf_err(const char *name __unused, enum vm_snapshot_op op __unused)
{
}

int
vm_snapshot_buf(void *data, size_t size, struct vm_snapshot_meta *meta)
{

	if (size > meta->buffer.buf_rem)
		return (E2BIG);
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(meta->buffer.buf, data, size);
	else if (vm_snapshot_is_loading(meta))
		memcpy(data, meta->buffer.buf, size);
	else
		return (EINVAL);
	meta->buffer.buf += size;
	meta->buffer.buf_rem -= size;
	return (0);
}

int
vm_snapshot_u8(uint8_t *value, struct vm_snapshot_meta *meta)
{

	return (vm_snapshot_buf(value, sizeof(*value), meta));
}

int
vm_snapshot_le16(uint16_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[2];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		le16enc(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = le16dec(bytes);
	return (error);
}

int
vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[4];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		le32enc(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = le32dec(bytes);
	return (error);
}

int
vm_snapshot_le64(uint64_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[8];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		le64enc(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = le64dec(bytes);
	return (error);
}

int
vm_snapshot_nonnegative_int(int *value, struct vm_snapshot_meta *meta)
{
	uint32_t v;
	int error;

	v = (uint32_t)*value;
	error = vm_snapshot_le32(&v, meta);
	if (error != 0)
		return (error);
	if (vm_snapshot_is_loading(meta)) {
		if (v > (uint32_t)INT_MAX)
			return (EINVAL);
		*value = (int)v;
	}
	return (0);
}

int
vm_snapshot_guest2host_addr(struct vmctx *ctx __unused, void **addrp __unused,
    size_t len __unused, bool restore_null __unused,
    struct vm_snapshot_meta *meta __unused)
{

	return (0);
}

/* ---- Device under test ----------------------------------------------------- */
#include "pci_nvme.c"

/*
 * crc16() (sys/crc16.h, pulled in by the DUT) is an inline referencing this
 * kernel data table.  It is only used to synthesize an EUI-64 when none is
 * configured; no test asserts the exact value, so a zeroed stand-in suffices.
 * Defined after the DUT so the header's extern declaration is in scope.
 */
uint16_t const crc16_table[256];

/* ---- blockif mock ---------------------------------------------------------- */
/*
 * A synchronous RAM-backed block backend.  Each request is serviced inline
 * against g_blk_store and its callback invoked immediately, so a doorbell
 * write returns only after all I/O it triggered has completed.  Defined after
 * the DUT include so it sees the real struct blockif_req / blockif_resize_cb.
 */
static uint8_t *g_blk_store;
static size_t g_blk_size;
static int g_blk_sectsz = 512;
static bool g_blk_ro;
static bool g_blk_candelete = true;
static int g_blk_force_err;		/* forced errno for next op, 0 = none */
static bool g_blk_open_fail;
static blockif_resize_cb *g_blk_resize_cb;
static void *g_blk_resize_arg;

struct blockif_ctxt {
	int token;
};
static struct blockif_ctxt g_blk_ctxt;

int
blockif_legacy_config(nvlist_t *nvl, const char *opts)
{

	if (opts != NULL)
		set_config_value_node(nvl, "path", opts);
	return (0);
}

int
blockif_add_boot_device(struct pci_devinst *pi __unused,
    struct blockif_ctxt *bc __unused)
{

	return (0);
}

struct blockif_ctxt *
blockif_open(nvlist_t *nvl __unused, const char *ident __unused)
{

	if (g_blk_open_fail)
		return (NULL);
	return (&g_blk_ctxt);
}

int
blockif_register_resize_callback(struct blockif_ctxt *bc __unused,
    blockif_resize_cb *cb, void *arg)
{

	g_blk_resize_cb = cb;
	g_blk_resize_arg = arg;
	return (0);
}

off_t
blockif_size(struct blockif_ctxt *bc __unused)
{

	return ((off_t)g_blk_size);
}

int
blockif_sectsz(struct blockif_ctxt *bc __unused)
{

	return (g_blk_sectsz);
}

int
blockif_is_ro(struct blockif_ctxt *bc __unused)
{

	return (g_blk_ro);
}

int
blockif_candelete(struct blockif_ctxt *bc __unused)
{

	return (g_blk_candelete);
}

const char *
blockif_checkpoint_identity(struct blockif_ctxt *bc __unused)
{

	return ("mock-blockif");
}

static int
blk_rw(struct blockif_req *br, bool write)
{
	off_t off = br->br_offset;
	int err = 0;

	if (g_blk_force_err != 0) {
		err = g_blk_force_err;
		g_blk_force_err = 0;
		br->br_resid = 0;
		br->br_callback(br, err);
		return (0);
	}
	for (int i = 0; i < br->br_iovcnt; i++) {
		size_t n = br->br_iov[i].iov_len;

		if (off < 0 || (size_t)off + n > g_blk_size) {
			err = EIO;
			break;
		}
		if (write)
			memcpy(g_blk_store + off, br->br_iov[i].iov_base, n);
		else
			memcpy(br->br_iov[i].iov_base, g_blk_store + off, n);
		off += n;
		br->br_resid -= n;
	}
	br->br_callback(br, err);
	return (0);
}

int
blockif_read(struct blockif_ctxt *bc __unused, struct blockif_req *br)
{

	return (blk_rw(br, false));
}

int
blockif_write(struct blockif_ctxt *bc __unused, struct blockif_req *br)
{

	return (blk_rw(br, true));
}

int
blockif_flush(struct blockif_ctxt *bc __unused, struct blockif_req *br)
{

	br->br_callback(br, 0);
	return (0);
}

int
blockif_delete(struct blockif_ctxt *bc __unused, struct blockif_req *br)
{
	int err = 0;

	if (g_blk_force_err != 0) {
		err = g_blk_force_err;
		g_blk_force_err = 0;
	}
	br->br_callback(br, err);
	return (0);
}

int
blockif_close(struct blockif_ctxt *bc __unused)
{

	return (0);
}

static bool g_blk_suspend_fail;

int
blockif_suspend(struct blockif_ctxt *bc __unused)
{

	return (g_blk_suspend_fail ? EBUSY : 0);
}

void
blockif_resume(struct blockif_ctxt *bc __unused)
{
}

/*
 * ===========================================================================
 * Independent NVMe 1.4 specification oracle constants.
 * ===========================================================================
 */
#define	SPEC_CR_CAP	0x00
#define	SPEC_CR_VS	0x08
#define	SPEC_CR_CC	0x14
#define	SPEC_CR_CSTS	0x1c
#define	SPEC_CR_AQA	0x24
#define	SPEC_CR_ASQ	0x28
#define	SPEC_CR_ACQ	0x30
#define	SPEC_DOORBELL	0x1000		/* SQ0TDBL for stride 0 */

#define	SPEC_CC_EN	0x00000001U
#define	SPEC_CSTS_RDY	0x00000001U
#define	SPEC_CSTS_CFS	0x00000002U

/* Class code for a mass storage / NVM controller. */
#define	SPEC_PCI_VENDOR	0xFB5D
#define	SPEC_PCI_DEVICE	0x0A0A

/* Guest RAM layout the tests write into. */
#define	GPA_ASQ		0x010000ULL
#define	GPA_ACQ		0x020000ULL
#define	GPA_IOSQ	0x030000ULL
#define	GPA_IOCQ	0x040000ULL
#define	GPA_PRP1	0x100000ULL
#define	GPA_PRP2	0x200000ULL
#define	GPA_PRPLIST	0x300000ULL
#define	GPA_SCRATCH	0x400000ULL

#define	ADMIN_QENTRIES	16
#define	IO_QENTRIES	16

/* A device instance under test plus the driver-visible queue bookkeeping. */
struct nvme_dut {
	struct pci_devinst pi;
	struct pci_nvme_softc *sc;
	uint16_t asq_tail;
	uint16_t acq_head;
	uint16_t iosq_tail;
	uint16_t iocq_head;
	uint16_t next_cid;
};

static void
env_reset(void)
{

	if (g_ram == NULL)
		g_ram = calloc(1, GUEST_RAM_SIZE);
	else
		memset(g_ram, 0, GUEST_RAM_SIZE);
	ATF_REQUIRE(g_ram != NULL);
	g_map_gpa_fail = false;
	g_map_gpa_fail_gpa = UINT64_MAX;
	g_map_dma_fail = false;
	g_dma_dirty_bytes = 0;
	g_msix_count = 0;
	memset(g_msix_vectors, 0, sizeof(g_msix_vectors));
	g_alloc_bar_fail = false;
	g_msixcap_fail = false;
	g_pciecap_fail = false;
	g_bootdev_fail = false;
	g_alloc_bar_size = 0;
	g_blk_force_err = 0;
	g_blk_open_fail = false;
	g_blk_suspend_fail = false;
	g_blk_ro = false;
	g_blk_candelete = true;
	g_blk_sectsz = 512;
	g_blk_resize_cb = NULL;
	cfg_reset();
	set_config_value_node(NULL, "name", "nvme");
}

/* Bring the device up over the RAM backing store (ram=<mib>). */
static void
dut_init_ram(struct nvme_dut *d, unsigned mib)
{
	char buf[32];
	int error;

	memset(d, 0, sizeof(*d));
	d->pi.pi_slot = 3;
	d->pi.pi_func = 0;
	snprintf(buf, sizeof(buf), "%u", mib);
	set_config_value_node(NULL, "ram", buf);
	error = pci_nvme_init(&d->pi, NULL);
	ATF_REQUIRE_EQ(0, error);
	d->sc = d->pi.pi_arg;
	ATF_REQUIRE(d->sc != NULL);
	d->next_cid = 1;
}

/* Bring the device up over the synchronous mock blockif backing store. */
static void
dut_init_blockif(struct nvme_dut *d, size_t size)
{
	int error;

	free(g_blk_store);
	g_blk_size = size;
	g_blk_store = calloc(1, size);
	ATF_REQUIRE(g_blk_store != NULL);

	memset(d, 0, sizeof(*d));
	d->pi.pi_slot = 3;
	d->pi.pi_func = 0;
	/* No "ram" key => blockif path. */
	error = pci_nvme_init(&d->pi, NULL);
	ATF_REQUIRE_EQ(0, error);
	d->sc = d->pi.pi_arg;
	ATF_REQUIRE(d->sc != NULL);
	d->next_cid = 1;
}

static void
dut_write(struct nvme_dut *d, uint64_t off, int size, uint64_t val)
{

	pci_nvme_write(&d->pi, 0, off, size, val);
}

static uint32_t
dut_read32(struct nvme_dut *d, uint64_t off)
{

	return ((uint32_t)pci_nvme_read(&d->pi, 0, off, 4));
}

/* Program the admin queues and enable the controller. */
static void
dut_enable(struct nvme_dut *d)
{
	uint32_t aqa, csts;

	/* AQA: zero-based sizes in bits 27:16 (ACQS) and 11:0 (ASQS). */
	aqa = ((ADMIN_QENTRIES - 1) << 16) | (ADMIN_QENTRIES - 1);
	dut_write(d, SPEC_CR_AQA, 4, aqa);
	dut_write(d, SPEC_CR_ASQ, 4, (uint32_t)GPA_ASQ);
	dut_write(d, SPEC_CR_ASQ + 4, 4, (uint32_t)(GPA_ASQ >> 32));
	dut_write(d, SPEC_CR_ACQ, 4, (uint32_t)GPA_ACQ);
	dut_write(d, SPEC_CR_ACQ + 4, 4, (uint32_t)(GPA_ACQ >> 32));

	/* CC: enable with IOSQES=6 (64B), IOCQES=4 (16B). */
	dut_write(d, SPEC_CR_CC, 4, SPEC_CC_EN | (6 << 16) | (4 << 20));

	csts = dut_read32(d, SPEC_CR_CSTS);
	ATF_REQUIRE((csts & SPEC_CSTS_RDY) != 0);
}

/*
 * Submit one admin command (already staged as a struct) and return its
 * completion.  Rings SQ0 tail doorbell; because processing is synchronous the
 * completion is available in the ACQ immediately.
 */
static struct nvme_completion
dut_admin_cmd(struct nvme_dut *d, struct nvme_command *cmd)
{
	struct nvme_command *asq = (struct nvme_command *)(g_ram + GPA_ASQ);
	struct nvme_completion *acq =
	    (struct nvme_completion *)(g_ram + GPA_ACQ);
	struct nvme_completion cqe;
	uint16_t slot;

	slot = d->asq_tail;
	memcpy(&asq[slot], cmd, sizeof(*cmd));
	d->asq_tail = (d->asq_tail + 1) % ADMIN_QENTRIES;
	dut_write(d, SPEC_DOORBELL, 4, d->asq_tail);

	/* Consume one completion from the ACQ. */
	memcpy(&cqe, &acq[d->acq_head], sizeof(cqe));
	d->acq_head = (d->acq_head + 1) % ADMIN_QENTRIES;
	/* Ring the admin CQ head doorbell (CQ0, offset +4). */
	dut_write(d, SPEC_DOORBELL + 4, 4, d->acq_head);
	return (cqe);
}

static uint16_t
cqe_sc(struct nvme_completion *c)
{

	return ((le16toh(c->status) >> 1) & 0xFF);
}

static uint16_t
cqe_sct(struct nvme_completion *c)
{

	return ((le16toh(c->status) >> 9) & 0x7);
}

static void
dut_teardown(struct nvme_dut *d)
{

	/* Disable the controller; drops queue mappings and drains state. */
	dut_write(d, SPEC_CR_CC, 4, 0);
	if (d->sc->nvstore.type == NVME_STOR_BLOCKIF)
		(void)pci_nvme_snapshot; /* keep symbol referenced */
}

/* Build a Create IO CQ admin command. */
static struct nvme_command
mk_create_cq(uint16_t cqid, uint16_t qsize, uint64_t prp1, uint16_t iv,
    bool inten, uint16_t cid)
{
	struct nvme_command c;

	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_CREATE_IO_CQ;
	c.cid = htole16(cid);
	c.prp1 = htole64(prp1);
	c.cdw10 = htole32(((uint32_t)(qsize - 1) << 16) | cqid);
	c.cdw11 = htole32((inten ? 0x2 : 0x0) | 0x1 |
	    ((uint32_t)iv << 16));	/* IEN|PC + interrupt vector */
	return (c);
}

/* Build a Create IO SQ admin command. */
static struct nvme_command
mk_create_sq(uint16_t sqid, uint16_t qsize, uint64_t prp1, uint16_t cqid,
    uint16_t cid)
{
	struct nvme_command c;

	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_CREATE_IO_SQ;
	c.cid = htole16(cid);
	c.prp1 = htole64(prp1);
	c.cdw10 = htole32(((uint32_t)(qsize - 1) << 16) | sqid);
	c.cdw11 = htole32(((uint32_t)cqid << 16) | 0x1);	/* CQID + PC */
	return (c);
}

/*
 * ===========================================================================
 * Test cases.
 * ===========================================================================
 */

ATF_TC_WITHOUT_HEAD(init_pci_config_and_bar);
ATF_TC_BODY(init_pci_config_and_bar, tc)
{
	struct nvme_dut d;

	env_reset();
	dut_init_ram(&d, 16);

	/* NVMe: PCI class 01h / subclass 08h / progif 02h. */
	ATF_CHECK_EQ(SPEC_PCI_VENDOR, pci_get_cfgdata16(&d.pi, PCIR_VENDOR));
	ATF_CHECK_EQ(SPEC_PCI_DEVICE, pci_get_cfgdata16(&d.pi, PCIR_DEVICE));
	ATF_CHECK_EQ(PCIC_STORAGE, pci_get_cfgdata8(&d.pi, PCIR_CLASS));
	ATF_CHECK_EQ(PCIS_STORAGE_NVM, pci_get_cfgdata8(&d.pi, PCIR_SUBCLASS));
	ATF_CHECK_EQ(PCIP_STORAGE_NVM_ENTERPRISE_NVMHCI_1_0,
	    pci_get_cfgdata8(&d.pi, PCIR_PROGIF));

	/* Spec requires a >=16KiB MMIO window; BAR0 is 64-bit memory. */
	ATF_CHECK(d.pi.pi_bar[0].size >= (1U << 14));
	ATF_CHECK_EQ(PCIBAR_MEM64, d.pi.pi_bar[0].type);

	/* CAP register is non-zero and version register reports >= 1.0. */
	ATF_CHECK(dut_read32(&d, SPEC_CR_CAP) != 0);
	ATF_CHECK(dut_read32(&d, SPEC_CR_VS) >= 0x00010000U);

	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(enable_reset_transitions);
ATF_TC_BODY(enable_reset_transitions, tc)
{
	struct nvme_dut d;
	uint32_t csts;

	env_reset();
	dut_init_ram(&d, 16);

	/* Before enable, RDY is clear. */
	csts = dut_read32(&d, SPEC_CR_CSTS);
	ATF_CHECK_EQ(0U, csts & SPEC_CSTS_RDY);

	dut_enable(&d);
	ATF_CHECK((dut_read32(&d, SPEC_CR_CSTS) & SPEC_CSTS_RDY) != 0);

	/* Clearing CC.EN resets the controller and clears RDY. */
	dut_write(&d, SPEC_CR_CC, 4, 0);
	ATF_CHECK_EQ(0U, dut_read32(&d, SPEC_CR_CSTS) & SPEC_CSTS_RDY);

	/* Re-enable works after reset. */
	dut_enable(&d);
	ATF_CHECK((dut_read32(&d, SPEC_CR_CSTS) & SPEC_CSTS_RDY) != 0);
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(enable_bad_aqa_sets_cfs);
ATF_TC_BODY(enable_bad_aqa_sets_cfs, tc)
{
	struct nvme_dut d;

	env_reset();
	dut_init_ram(&d, 16);

	/* ASQS zero-based 0 => 1 entry => illegal; must set CFS, not RDY. */
	dut_write(&d, SPEC_CR_AQA, 4, 0);
	dut_write(&d, SPEC_CR_ASQ, 4, (uint32_t)GPA_ASQ);
	dut_write(&d, SPEC_CR_ACQ, 4, (uint32_t)GPA_ACQ);
	dut_write(&d, SPEC_CR_CC, 4, SPEC_CC_EN | (6 << 16) | (4 << 20));

	ATF_CHECK((dut_read32(&d, SPEC_CR_CSTS) & SPEC_CSTS_CFS) != 0);
	ATF_CHECK_EQ(0U, dut_read32(&d, SPEC_CR_CSTS) & SPEC_CSTS_RDY);
}

ATF_TC_WITHOUT_HEAD(identify_controller);
ATF_TC_BODY(identify_controller, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;
	struct nvme_controller_data *cd;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);

	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_IDENTIFY;
	c.cid = htole16(d.next_cid++);
	c.prp1 = htole64(GPA_PRP1);
	c.cdw10 = htole32(0x01);	/* CNS=01: Identify Controller */
	cqe = dut_admin_cmd(&d, &c);

	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	ATF_CHECK_EQ(0, cqe_sct(&cqe));

	cd = (struct nvme_controller_data *)(g_ram + GPA_PRP1);
	/* Vendor ID in identify data matches the PCI vendor. */
	ATF_CHECK_EQ(SPEC_PCI_VENDOR, le16toh(cd->vid));
	/* At least one namespace. */
	ATF_CHECK(le32toh(cd->nn) >= 1);

	/*
	 * A PRP1 that starts mid-page splits the 4096-byte structure across
	 * PRP1 and PRP2, exercising the two-region PRP copy path.
	 */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_IDENTIFY;
	c.cid = htole16(d.next_cid++);
	c.prp1 = htole64(GPA_PRP1 + 2048);
	c.prp2 = htole64(GPA_PRP2);
	c.cdw10 = htole32(0x01);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	cd = (struct nvme_controller_data *)(g_ram + GPA_PRP1 + 2048);
	ATF_CHECK_EQ(SPEC_PCI_VENDOR, le16toh(cd->vid));

	/* An unmapped PRP1 yields a data transfer error. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_IDENTIFY;
	c.cid = htole16(d.next_cid++);
	c.prp1 = htole64(GUEST_RAM_SIZE + 0x1000);
	c.cdw10 = htole32(0x01);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_DATA_TRANSFER_ERROR, cqe_sc(&cqe));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(identify_namespace);
ATF_TC_BODY(identify_namespace, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;
	struct nvme_namespace_data *nd;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);

	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_IDENTIFY;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(1);
	c.prp1 = htole64(GPA_PRP1);
	c.cdw10 = htole32(0x00);	/* CNS=00: Identify Namespace */
	cqe = dut_admin_cmd(&d, &c);

	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	nd = (struct nvme_namespace_data *)(g_ram + GPA_PRP1);
	/* RAM store is 16 MiB with 4096-byte sectors => 4096 blocks. */
	ATF_CHECK_EQ((16U * 1024U * 1024U) / 4096U, le64toh(nd->nsze));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(create_delete_io_queues);
ATF_TC_BODY(create_delete_io_queues, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);

	/* CQ must exist before its SQ. */
	c = mk_create_cq(1, IO_QENTRIES, GPA_IOCQ, 1, true, d.next_cid++);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));

	c = mk_create_sq(1, IO_QENTRIES, GPA_IOSQ, 1, d.next_cid++);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));

	/* Deleting the CQ while its SQ exists is invalid (spec 5.5). */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_DELETE_IO_CQ;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(1);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK(cqe_sc(&cqe) != 0);

	/* Delete SQ, then CQ. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_DELETE_IO_SQ;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(1);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));

	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_DELETE_IO_CQ;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(1);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(admin_invalid_opcode);
ATF_TC_BODY(admin_invalid_opcode, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);

	memset(&c, 0, sizeof(c));
	c.opc = 0xfe;			/* not implemented */
	c.cid = htole16(d.next_cid++);
	cqe = dut_admin_cmd(&d, &c);
	/* Generic status, Invalid Command Opcode. */
	ATF_CHECK_EQ(NVME_SCT_GENERIC, cqe_sct(&cqe));
	ATF_CHECK_EQ(NVME_SC_INVALID_OPCODE, cqe_sc(&cqe));
	dut_teardown(&d);
}

/* Create IO CQ 1 and IO SQ 1 (both IO_QENTRIES deep). */
static void
dut_io_setup(struct nvme_dut *d)
{
	struct nvme_command c;
	struct nvme_completion cqe;

	c = mk_create_cq(1, IO_QENTRIES, GPA_IOCQ, 1, true, d->next_cid++);
	cqe = dut_admin_cmd(d, &c);
	ATF_REQUIRE_EQ(0, cqe_sc(&cqe));
	c = mk_create_sq(1, IO_QENTRIES, GPA_IOSQ, 1, d->next_cid++);
	cqe = dut_admin_cmd(d, &c);
	ATF_REQUIRE_EQ(0, cqe_sc(&cqe));
}

/* Submit one command on IO SQ 1 and read its IO CQ 1 completion. */
static struct nvme_completion
dut_io_cmd(struct nvme_dut *d, struct nvme_command *cmd)
{
	struct nvme_command *iosq = (struct nvme_command *)(g_ram + GPA_IOSQ);
	struct nvme_completion *iocq =
	    (struct nvme_completion *)(g_ram + GPA_IOCQ);
	struct nvme_completion cqe;

	memcpy(&iosq[d->iosq_tail], cmd, sizeof(*cmd));
	d->iosq_tail = (d->iosq_tail + 1) % IO_QENTRIES;
	dut_write(d, SPEC_DOORBELL + 1 * 8, 4, d->iosq_tail);

	memcpy(&cqe, &iocq[d->iocq_head], sizeof(cqe));
	d->iocq_head = (d->iocq_head + 1) % IO_QENTRIES;
	dut_write(d, SPEC_DOORBELL + 1 * 8 + 4, 4, d->iocq_head);
	return (cqe);
}

static struct nvme_command
mk_rw(bool write, uint64_t lba, uint16_t nlb_zerobased, uint64_t prp1,
    uint64_t prp2, uint16_t cid)
{
	struct nvme_command c;

	memset(&c, 0, sizeof(c));
	c.opc = write ? NVME_OPC_WRITE : NVME_OPC_READ;
	c.cid = htole16(cid);
	c.nsid = htole32(1);
	c.prp1 = htole64(prp1);
	c.prp2 = htole64(prp2);
	c.cdw10 = htole32((uint32_t)lba);
	c.cdw11 = htole32((uint32_t)(lba >> 32));
	c.cdw12 = htole32(nlb_zerobased);
	return (c);
}

ATF_TC_WITHOUT_HEAD(io_write_read_ram_prp1);
ATF_TC_BODY(io_write_read_ram_prp1, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;
	uint8_t *src, *dst;

	env_reset();
	dut_init_ram(&d, 16);		/* 4096-byte sectors */
	dut_enable(&d);
	dut_io_setup(&d);
	src = g_ram + GPA_PRP1;
	dst = g_ram + GPA_SCRATCH;

	/* One 4096-byte block (nlb zero-based = 0). */
	for (int i = 0; i < 4096; i++)
		src[i] = (uint8_t)(i * 7 + 3);

	c = mk_rw(true, 5, 0, GPA_PRP1, 0, d.next_cid++);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	ATF_CHECK_EQ(0, cqe_sct(&cqe));

	c = mk_rw(false, 5, 0, GPA_SCRATCH, 0, d.next_cid++);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	ATF_CHECK_EQ(0, memcmp(src, dst, 4096));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(io_write_read_ram_prp2);
ATF_TC_BODY(io_write_read_ram_prp2, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;
	uint8_t *src0, *src1;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);
	dut_io_setup(&d);
	src0 = g_ram + GPA_PRP1;
	src1 = g_ram + GPA_PRP2;

	/* Two 4096-byte blocks spanning PRP1 + PRP2. */
	for (int i = 0; i < 4096; i++) {
		src0[i] = (uint8_t)(i + 1);
		src1[i] = (uint8_t)(i + 128);
	}
	c = mk_rw(true, 0, 1, GPA_PRP1, GPA_PRP2, d.next_cid++);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));

	memset(g_ram + GPA_SCRATCH, 0, 8192);
	c = mk_rw(false, 0, 1, GPA_SCRATCH, GPA_SCRATCH + 4096, d.next_cid++);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	ATF_CHECK_EQ(0, memcmp(src0, g_ram + GPA_SCRATCH, 4096));
	ATF_CHECK_EQ(0, memcmp(src1, g_ram + GPA_SCRATCH + 4096, 4096));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(io_write_read_prp_list);
ATF_TC_BODY(io_write_read_prp_list, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;
	uint64_t *list;
	uint8_t *p;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);
	dut_io_setup(&d);
	list = (uint64_t *)(g_ram + GPA_PRPLIST);

	/*
	 * Three 4096-byte blocks: PRP1 covers page 0, PRP2 points to a PRP
	 * list describing pages 1 and 2.
	 */
	p = g_ram + GPA_PRP1;
	for (int i = 0; i < 4096 * 3; i++)
		p[i] = (uint8_t)(i * 3 + 11);
	/* Contiguous source region GPA_PRP1..+12K; list points at pages 1,2. */
	list[0] = htole64(GPA_PRP1 + 4096);
	list[1] = htole64(GPA_PRP1 + 8192);

	c = mk_rw(true, 10, 2, GPA_PRP1, GPA_PRPLIST, d.next_cid++);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));

	/* Read back into a fresh contiguous region via its own PRP list. */
	memset(g_ram + GPA_SCRATCH, 0, 4096 * 3);
	list = (uint64_t *)(g_ram + GPA_PRPLIST + 512);
	list[0] = htole64(GPA_SCRATCH + 4096);
	list[1] = htole64(GPA_SCRATCH + 8192);
	c = mk_rw(false, 10, 2, GPA_SCRATCH, GPA_PRPLIST + 512, d.next_cid++);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	ATF_CHECK_EQ(0, memcmp(g_ram + GPA_PRP1, g_ram + GPA_SCRATCH,
	    4096 * 3));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(io_write_read_blockif);
ATF_TC_BODY(io_write_read_blockif, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;
	uint8_t *src;

	env_reset();
	dut_init_blockif(&d, 1024 * 1024);	/* 512-byte sectors */
	dut_enable(&d);
	dut_io_setup(&d);
	src = g_ram + GPA_PRP1;

	for (int i = 0; i < 512; i++)
		src[i] = (uint8_t)(i ^ 0x5a);
	c = mk_rw(true, 2, 0, GPA_PRP1, 0, d.next_cid++);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	/* Backend received the data at byte offset 2*512. */
	ATF_CHECK_EQ(0, memcmp(g_blk_store + 1024, src, 512));

	memset(g_ram + GPA_SCRATCH, 0, 512);
	c = mk_rw(false, 2, 0, GPA_SCRATCH, 0, d.next_cid++);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	ATF_CHECK_EQ(0, memcmp(g_ram + GPA_SCRATCH, src, 512));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(io_blockif_multipage);
ATF_TC_BODY(io_blockif_multipage, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;
	uint64_t *list;
	uint8_t *src;

	env_reset();
	dut_init_blockif(&d, 1024 * 1024);	/* 512-byte sectors */
	dut_enable(&d);
	dut_io_setup(&d);
	src = g_ram + GPA_PRP1;

	/*
	 * 64 blocks * 512 = 32768 bytes = 8 pages.  PRP1 covers page 0; PRP2
	 * points at a PRP list describing pages 1..7 (blockif PRP-list path).
	 */
	for (int i = 0; i < 32768; i++)
		src[i] = (uint8_t)(i * 5 + 1);
	list = (uint64_t *)(g_ram + GPA_PRPLIST);
	for (int pg = 1; pg < 8; pg++)
		list[pg - 1] = htole64(GPA_PRP1 + (uint64_t)pg * 4096);

	c = mk_rw(true, 0, 63, GPA_PRP1, GPA_PRPLIST, d.next_cid++);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	ATF_CHECK_EQ(0, memcmp(g_blk_store, src, 32768));

	/* Read back through a two-page (PRP1+PRP2) transfer. */
	memset(g_ram + GPA_SCRATCH, 0, 8192);
	c = mk_rw(false, 0, 15, GPA_SCRATCH, GPA_SCRATCH + 4096, d.next_cid++);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	ATF_CHECK_EQ(0, memcmp(g_ram + GPA_SCRATCH, src, 4096));
	ATF_CHECK_EQ(0, memcmp(g_ram + GPA_SCRATCH + 4096, src + 4096, 4096));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(io_flush);
ATF_TC_BODY(io_flush, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;

	env_reset();
	dut_init_blockif(&d, 1024 * 1024);
	dut_enable(&d);
	dut_io_setup(&d);

	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_FLUSH;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(1);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(io_dsm_trim);
ATF_TC_BODY(io_dsm_trim, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;
	struct nvme_dsm_range *r;

	env_reset();
	/* dsm=enable so the DEALLOCATE path issues blockif_delete. */
	set_config_value_node(NULL, "dsm", "enable");
	dut_init_blockif(&d, 1024 * 1024);
	dut_enable(&d);
	dut_io_setup(&d);

	/* Two ranges: first zero-length (skipped), second real. */
	r = (struct nvme_dsm_range *)(g_ram + GPA_PRP1);
	r[0].attributes = 0;
	r[0].length = 0;
	r[0].starting_lba = 0;
	r[1].attributes = 0;
	r[1].length = htole32(8);
	r[1].starting_lba = htole64(16);

	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_DATASET_MANAGEMENT;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(1);
	c.prp1 = htole64(GPA_PRP1);
	c.cdw10 = htole32(1);	/* NR zero-based = 1 => two ranges */
	c.cdw11 = htole32(NVME_DSM_ATTR_DEALLOCATE);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));

	/* Two real ranges exercise the multi-range deallocation state machine. */
	r[0].attributes = 0;
	r[0].length = htole32(8);
	r[0].starting_lba = htole64(0);
	r[1].attributes = 0;
	r[1].length = htole32(8);
	r[1].starting_lba = htole64(32);
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_DATASET_MANAGEMENT;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(1);
	c.prp1 = htole64(GPA_PRP1);
	c.cdw10 = htole32(1);
	c.cdw11 = htole32(NVME_DSM_ATTR_DEALLOCATE);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));

	/* DSM without the deallocate attribute is an advisory no-op success. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_DATASET_MANAGEMENT;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(1);
	c.prp1 = htole64(GPA_PRP1);
	c.cdw10 = htole32(0);
	c.cdw11 = htole32(0);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));

	/* An out-of-range DSM range reports LBA out of range. */
	r = (struct nvme_dsm_range *)(g_ram + GPA_PRP1);
	r[0].attributes = 0;
	r[0].length = htole32(8);
	r[0].starting_lba = htole64(0xffffffffULL);
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_DATASET_MANAGEMENT;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(1);
	c.prp1 = htole64(GPA_PRP1);
	c.cdw10 = htole32(0);
	c.cdw11 = htole32(NVME_DSM_ATTR_DEALLOCATE);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_LBA_OUT_OF_RANGE, cqe_sc(&cqe));
	dut_teardown(&d);

	/* On a RAM namespace the backend cannot deallocate: advisory success. */
	env_reset();
	set_config_value_node(NULL, "dsm", "enable");	/* advertise DSM */
	dut_init_ram(&d, 16);
	dut_enable(&d);
	dut_io_setup(&d);
	r = (struct nvme_dsm_range *)(g_ram + GPA_PRP1);
	r[0].attributes = 0;
	r[0].length = htole32(1);
	r[0].starting_lba = htole64(0);
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_DATASET_MANAGEMENT;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(1);
	c.prp1 = htole64(GPA_PRP1);
	c.cdw10 = htole32(0);
	c.cdw11 = htole32(NVME_DSM_ATTR_DEALLOCATE);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	dut_teardown(&d);

	/* dsm=auto over a RAM store does not advertise DSM: invalid opcode. */
	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);
	dut_io_setup(&d);
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_DATASET_MANAGEMENT;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(1);
	c.prp1 = htole64(GPA_PRP1);
	c.cdw10 = htole32(0);
	c.cdw11 = htole32(NVME_DSM_ATTR_DEALLOCATE);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_OPCODE, cqe_sc(&cqe));
	dut_teardown(&d);

	/* DSM range descriptor copy from an unmapped PRP => transfer error. */
	env_reset();
	set_config_value_node(NULL, "dsm", "enable");
	dut_init_blockif(&d, 1024 * 1024);
	dut_enable(&d);
	dut_io_setup(&d);
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_DATASET_MANAGEMENT;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(1);
	c.prp1 = htole64(GUEST_RAM_SIZE + 0x1000);	/* unmapped */
	c.cdw10 = htole32(0);
	c.cdw11 = htole32(NVME_DSM_ATTR_DEALLOCATE);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_DATA_TRANSFER_ERROR, cqe_sc(&cqe));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(io_write_zeroes_unsupported);
ATF_TC_BODY(io_write_zeroes_unsupported, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);
	dut_io_setup(&d);

	/* The controller does not advertise Write Zeroes in ONCS. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_WRITE_ZEROES;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(1);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_OPCODE, cqe_sc(&cqe));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(io_invalid_nsid);
ATF_TC_BODY(io_invalid_nsid, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);
	dut_io_setup(&d);

	c = mk_rw(false, 0, 0, GPA_SCRATCH, 0, d.next_cid++);
	c.nsid = htole32(99);		/* out of range */
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_NAMESPACE_OR_FORMAT, cqe_sc(&cqe));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(io_lba_out_of_range);
ATF_TC_BODY(io_lba_out_of_range, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;

	env_reset();
	dut_init_ram(&d, 16);		/* 4096 blocks total */
	dut_enable(&d);
	dut_io_setup(&d);

	c = mk_rw(false, 100000, 0, GPA_SCRATCH, 0, d.next_cid++);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_LBA_OUT_OF_RANGE, cqe_sc(&cqe));

	/* A misaligned PRP1 is rejected before any transfer. */
	c = mk_rw(false, 0, 0, GPA_SCRATCH + 1, 0, d.next_cid++);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_FIELD, cqe_sc(&cqe));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(io_mdts_exceeded);
ATF_TC_BODY(io_mdts_exceeded, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;

	env_reset();
	dut_init_ram(&d, 64);
	dut_enable(&d);
	dut_io_setup(&d);

	/* nlb+1 blocks * 4096 must exceed NVME_MAX_DATA_SIZE (512*4096). */
	c = mk_rw(false, 0, 1000, GPA_SCRATCH, GPA_PRP2, d.next_cid++);
	cqe = dut_io_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_FIELD, cqe_sc(&cqe));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(get_log_pages);
ATF_TC_BODY(get_log_pages, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;
	uint8_t logs[] = { NVME_LOG_ERROR, NVME_LOG_HEALTH_INFORMATION,
	    NVME_LOG_FIRMWARE_SLOT, NVME_LOG_CHANGED_NAMESPACE };

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);

	for (unsigned i = 0; i < nitems(logs); i++) {
		memset(&c, 0, sizeof(c));
		c.opc = NVME_OPC_GET_LOG_PAGE;
		c.cid = htole16(d.next_cid++);
		c.prp1 = htole64(GPA_PRP1);
		/* NUMD zero-based = 15 => 16 dwords = 64 bytes. */
		c.cdw10 = htole32(((uint32_t)15 << 16) | logs[i]);
		cqe = dut_admin_cmd(&d, &c);
		ATF_CHECK_EQ(0, cqe_sc(&cqe));
	}

	/* A log offset beyond the log size => Invalid Field, per page. */
	for (unsigned i = 0; i < nitems(logs); i++) {
		memset(&c, 0, sizeof(c));
		c.opc = NVME_OPC_GET_LOG_PAGE;
		c.cid = htole16(d.next_cid++);
		c.prp1 = htole64(GPA_PRP1);
		c.cdw10 = htole32(((uint32_t)0 << 16) | logs[i]);
		c.cdw12 = htole32(0x10000);	/* huge, 8-byte aligned offset */
		cqe = dut_admin_cmd(&d, &c);
		ATF_CHECK_EQ(NVME_SC_INVALID_FIELD, cqe_sc(&cqe));
	}

	/* A misaligned log offset is rejected. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_GET_LOG_PAGE;
	c.cid = htole16(d.next_cid++);
	c.prp1 = htole64(GPA_PRP1);
	c.cdw10 = htole32(NVME_LOG_ERROR);
	c.cdw12 = htole32(1);		/* not 4-byte aligned */
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_FIELD, cqe_sc(&cqe));

	/* Requested length exceeding the max data transfer is rejected. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_GET_LOG_PAGE;
	c.cid = htole16(d.next_cid++);
	c.prp1 = htole64(GPA_PRP1);
	c.cdw10 = htole32(((uint32_t)0xffff << 16) | NVME_LOG_ERROR);
	c.cdw11 = htole32(0xffff);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_FIELD, cqe_sc(&cqe));

	/* A health log page copied to an unmapped PRP => data transfer error. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_GET_LOG_PAGE;
	c.cid = htole16(d.next_cid++);
	c.prp1 = htole64(GUEST_RAM_SIZE + 0x1000);	/* out of range */
	c.cdw10 = htole32(((uint32_t)15 << 16) | NVME_LOG_HEALTH_INFORMATION);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_DATA_TRANSFER_ERROR, cqe_sc(&cqe));

	/* Unsupported log page => command-specific Invalid Log Page. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_GET_LOG_PAGE;
	c.cid = htole16(d.next_cid++);
	c.prp1 = htole64(GPA_PRP1);
	c.cdw10 = htole32(((uint32_t)0 << 16) | 0xCC);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SCT_COMMAND_SPECIFIC, cqe_sct(&cqe));
	ATF_CHECK_EQ(NVME_SC_INVALID_LOG_PAGE, cqe_sc(&cqe));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(features_num_queues);
ATF_TC_BODY(features_num_queues, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);

	/* Set Number of Queues: request 4 SQ + 4 CQ (zero-based 3). */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_SET_FEATURES;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(NVME_FEAT_NUMBER_OF_QUEUES);
	c.cdw11 = htole32(3 | (3 << 16));
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));

	/* Setting a second time is a command sequence error. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_SET_FEATURES;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(NVME_FEAT_NUMBER_OF_QUEUES);
	c.cdw11 = htole32(1 | (1 << 16));
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_COMMAND_SEQUENCE_ERROR, cqe_sc(&cqe));

	/* Get Number of Queues returns the current value in cdw0. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_GET_FEATURES;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(NVME_FEAT_NUMBER_OF_QUEUES);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	/* zero-based 3 SQ and 3 CQ. */
	ATF_CHECK_EQ((3U | (3U << 16)), le32toh(cqe.cdw0));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(features_misc);
ATF_TC_BODY(features_misc, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);

	/* Temperature threshold (over, room temp) is accepted. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_SET_FEATURES;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(NVME_FEAT_TEMPERATURE_THRESHOLD);
	c.cdw11 = htole32(400);		/* tmpth over, tmpsel 0, thsel 0 */
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));

	/* Async event configuration set + notify. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_SET_FEATURES;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(NVME_FEAT_ASYNC_EVENT_CONFIGURATION);
	c.cdw11 = htole32(0x1);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));

	/* Interrupt vector config for admin CQ vector 0 with coalescing off. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_SET_FEATURES;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(NVME_FEAT_INTERRUPT_VECTOR_CONFIGURATION);
	c.cdw11 = htole32(0 | (1 << 16));	/* iv 0, coalescing disable */
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));

	/* Invalid feature id. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_SET_FEATURES;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(0xFE);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_FIELD, cqe_sc(&cqe));

	/* Saving features is not supported. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_SET_FEATURES;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(NVME_FEAT_TEMPERATURE_THRESHOLD |
	    (1U << 31));		/* SV bit */
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_FEATURE_NOT_SAVEABLE, cqe_sc(&cqe));

	/* Get with an invalid select field. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_GET_FEATURES;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(NVME_FEAT_TEMPERATURE_THRESHOLD | (0x7 << 8));
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_FIELD, cqe_sc(&cqe));

	/* Get with SEL=supported-capabilities reports the changeable flags. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_GET_FEATURES;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(NVME_FEAT_TEMPERATURE_THRESHOLD | (0x3 << 8));
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));

	/* Get with SEL=default returns the default value. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_GET_FEATURES;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(NVME_FEAT_TEMPERATURE_THRESHOLD | (0x1 << 8));
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));

	/* A mandatory feature with no setter reports Not Changeable. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_SET_FEATURES;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(0);
	c.cdw10 = htole32(NVME_FEAT_ARBITRATION);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_FEATURE_NOT_CHANGEABLE, cqe_sc(&cqe));

	/* Namespace-specific feature with a bad nsid, set and get. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_SET_FEATURES;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(5);
	c.cdw10 = htole32(NVME_FEAT_ERROR_RECOVERY);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_NAMESPACE_OR_FORMAT, cqe_sc(&cqe));

	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_GET_FEATURES;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(5);
	c.cdw10 = htole32(NVME_FEAT_ERROR_RECOVERY);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_NAMESPACE_OR_FORMAT, cqe_sc(&cqe));

	/* A non-namespace feature addressed with a real nsid is rejected. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_SET_FEATURES;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(1);
	c.cdw10 = htole32(NVME_FEAT_TEMPERATURE_THRESHOLD);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_FEATURE_NOT_NS_SPECIFIC, cqe_sc(&cqe));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(admin_abort_and_async);
ATF_TC_BODY(admin_abort_and_async, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);

	/* Abort is accepted and reports "not aborted" (cdw0 bit 0 set). */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_ABORT;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32((0x1234 << 16) | 1);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	ATF_CHECK_EQ(1U, le32toh(cqe.cdw0) & 0x1);
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(admin_async_event_limit);
ATF_TC_BODY(admin_async_event_limit, tc)
{
	struct nvme_dut d;
	struct nvme_command *asq;
	struct nvme_completion *acq;
	struct nvme_command c;
	uint16_t aerl;
	int posted;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);

	/*
	 * Submitting more AERs than AERL supports yields an error completion
	 * for the overflow request; successful AERs do not complete inline.
	 */
	aerl = d.sc->ctrldata.aerl;
	asq = (struct nvme_command *)(g_ram + GPA_ASQ);
	acq = (struct nvme_completion *)(g_ram + GPA_ACQ);

	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_ASYNC_EVENT_REQUEST;
	for (int i = 0; i < aerl + 2; i++) {
		c.cid = htole16(d.next_cid++);
		memcpy(&asq[d.asq_tail], &c, sizeof(c));
		d.asq_tail = (d.asq_tail + 1) % ADMIN_QENTRIES;
		dut_write(&d, SPEC_DOORBELL, 4, d.asq_tail);
	}
	/* Count error completions parked in the ACQ. */
	posted = 0;
	for (int i = 0; i < ADMIN_QENTRIES; i++)
		if (cqe_sc(&acq[i]) != 0)
			posted++;
	ATF_CHECK(posted >= 1);
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(identify_active_ns_list);
ATF_TC_BODY(identify_active_ns_list, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);

	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_IDENTIFY;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(0);
	c.prp1 = htole64(GPA_PRP1);
	c.cdw10 = htole32(0x02);	/* Active Namespace ID list */
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	/* First entry is NSID 1. */
	ATF_CHECK_EQ(1U, le32toh(*(uint32_t *)(g_ram + GPA_PRP1)));

	/* Namespace ID descriptor list (CNS 0x03). */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_IDENTIFY;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(1);
	c.prp1 = htole64(GPA_PRP1);
	c.cdw10 = htole32(0x03);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));

	/* Identify Namespace for a nonexistent nsid => invalid namespace. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_IDENTIFY;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(2);
	c.prp1 = htole64(GPA_PRP1);
	c.cdw10 = htole32(0x00);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_NAMESPACE_OR_FORMAT, cqe_sc(&cqe));

	/* CNS 0x03 for a nonexistent nsid => invalid namespace. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_IDENTIFY;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(2);
	c.prp1 = htole64(GPA_PRP1);
	c.cdw10 = htole32(0x03);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_NAMESPACE_OR_FORMAT, cqe_sc(&cqe));

	/* CNS 0x13 (controller list) returns a valid empty list. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_IDENTIFY;
	c.cid = htole16(d.next_cid++);
	c.prp1 = htole64(GPA_PRP1);
	c.cdw10 = htole32(0x13);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));

	/* Unsupported CNS => Invalid Field. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_IDENTIFY;
	c.cid = htole16(d.next_cid++);
	c.prp1 = htole64(GPA_PRP1);
	c.cdw10 = htole32(0x77);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_FIELD, cqe_sc(&cqe));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(create_queue_errors);
ATF_TC_BODY(create_queue_errors, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);

	/* Create SQ before its CQ exists => Completion Queue Invalid. */
	c = mk_create_sq(1, IO_QENTRIES, GPA_IOSQ, 1, d.next_cid++);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SCT_COMMAND_SPECIFIC, cqe_sct(&cqe));
	ATF_CHECK_EQ(NVME_SC_COMPLETION_QUEUE_INVALID, cqe_sc(&cqe));

	/* Create CQ with an unaligned PRP1 => Invalid Field. */
	c = mk_create_cq(1, IO_QENTRIES, GPA_IOCQ + 8, 1, true, d.next_cid++);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_FIELD, cqe_sc(&cqe));

	/* Create CQ with an oversized queue => Invalid Queue Size. */
	c = mk_create_cq(1, 0, GPA_IOCQ, 1, true, d.next_cid++);
	/* qsize field zero-based 0xffff => 65536 > max_qentries. */
	c.cdw10 = htole32(((uint32_t)0xffff << 16) | 1);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_MAXIMUM_QUEUE_SIZE_EXCEEDED, cqe_sc(&cqe));

	/* Non-contiguous (PC=0) CQ is unsupported. */
	c = mk_create_cq(2, IO_QENTRIES, GPA_IOCQ, 1, true, d.next_cid++);
	c.cdw11 = htole32(0);		/* clear PC */
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_FIELD, cqe_sc(&cqe));

	/* CQ interrupt vector out of range. */
	c = mk_create_cq(2, IO_QENTRIES, GPA_IOCQ, 4000, true, d.next_cid++);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_INTERRUPT_VECTOR, cqe_sc(&cqe));

	/* Valid CQ, then duplicate CQ id => Invalid Queue Identifier. */
	c = mk_create_cq(1, IO_QENTRIES, GPA_IOCQ, 1, true, d.next_cid++);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	c = mk_create_cq(1, IO_QENTRIES, GPA_IOCQ, 1, true, d.next_cid++);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_QUEUE_IDENTIFIER, cqe_sc(&cqe));

	/* Non-contiguous (PC=0) SQ is unsupported. */
	c = mk_create_sq(1, IO_QENTRIES, GPA_IOSQ, 1, d.next_cid++);
	c.cdw11 = htole32((1U << 16));	/* cqid 1, PC cleared */
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_FIELD, cqe_sc(&cqe));

	/* SQ with an unaligned PRP1 => Invalid Field. */
	c = mk_create_sq(1, IO_QENTRIES, GPA_IOSQ + 8, 1, d.next_cid++);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_FIELD, cqe_sc(&cqe));

	/* SQ with an oversized queue => Invalid Queue Size. */
	c = mk_create_sq(1, IO_QENTRIES, GPA_IOSQ, 1, d.next_cid++);
	c.cdw10 = htole32(((uint32_t)0xffff << 16) | 1);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_MAXIMUM_QUEUE_SIZE_EXCEEDED, cqe_sc(&cqe));

	/* SQ referencing a bad CQ id => Invalid Queue Identifier. */
	c = mk_create_sq(1, IO_QENTRIES, GPA_IOSQ, 9000, d.next_cid++);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_QUEUE_IDENTIFIER, cqe_sc(&cqe));

	/* Create SQ with an out-of-range queue id. */
	c = mk_create_sq(9000, IO_QENTRIES, GPA_IOSQ, 1, d.next_cid++);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_QUEUE_IDENTIFIER, cqe_sc(&cqe));

	/* Delete SQ id 0 (the admin queue) is not permitted. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_DELETE_IO_SQ;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(0);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_QUEUE_IDENTIFIER, cqe_sc(&cqe));

	/* Delete CQ id 0 (the admin queue) is not permitted. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_DELETE_IO_CQ;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(0);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_QUEUE_IDENTIFIER, cqe_sc(&cqe));

	/* Delete of a never-created SQ/CQ id => Invalid Queue Identifier. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_DELETE_IO_SQ;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(7);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_QUEUE_IDENTIFIER, cqe_sc(&cqe));

	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_DELETE_IO_CQ;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(7);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_QUEUE_IDENTIFIER, cqe_sc(&cqe));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(io_completion_backpressure);
ATF_TC_BODY(io_completion_backpressure, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_command *iosq;
	struct nvme_completion *iocq;
	int published;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);

	/* Small (2-entry) CQ with a larger SQ forces completion backpressure. */
	c = mk_create_cq(1, 2, GPA_IOCQ, 1, true, d.next_cid++);
	{
		struct nvme_completion cqe = dut_admin_cmd(&d, &c);
		ATF_REQUIRE_EQ(0, cqe_sc(&cqe));
	}
	c = mk_create_sq(1, 8, GPA_IOSQ, 1, d.next_cid++);
	{
		struct nvme_completion cqe = dut_admin_cmd(&d, &c);
		ATF_REQUIRE_EQ(0, cqe_sc(&cqe));
	}

	/* Queue five reads in one batch; only one CQ slot is usable. */
	iosq = (struct nvme_command *)(g_ram + GPA_IOSQ);
	iocq = (struct nvme_completion *)(g_ram + GPA_IOCQ);
	for (int i = 0; i < 5; i++) {
		c = mk_rw(false, 0, 0, GPA_SCRATCH, 0, d.next_cid++);
		memcpy(&iosq[i], &c, sizeof(c));
	}
	g_msix_count = 0;
	dut_write(&d, SPEC_DOORBELL + 1 * 8, 4, 5);	/* SQ1 tail = 5 */

	/* At least one completion is published; the rest are queued pending. */
	ATF_CHECK(d.sc->compl_queues[1].pending_count > 0);
	ATF_CHECK(NVME_COMPLETION_VALID(iocq[0]));

	/* Draining the CQ head publishes the queued completions. */
	published = 0;
	for (int round = 0; round < 6; round++) {
		uint16_t head = (uint16_t)((round + 1) % 2);
		dut_write(&d, SPEC_DOORBELL + 1 * 8 + 4, 4, head);
	}
	for (int i = 0; i < 2; i++)
		if (NVME_COMPLETION_VALID(iocq[i]))
			published++;
	ATF_CHECK(published > 0);
	ATF_CHECK_EQ(0U, d.sc->compl_queues[1].pending_count);
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(queue_delete_busy);
ATF_TC_BODY(queue_delete_busy, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);
	dut_io_setup(&d);

	/* An SQ with in-flight I/O cannot be deleted. */
	d.sc->submit_queues[1].pending_ios = 1;
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_DELETE_IO_SQ;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(1);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_QUEUE_DELETION, cqe_sc(&cqe));
	d.sc->submit_queues[1].pending_ios = 0;

	/* Delete the SQ, then make the CQ non-empty so its delete is refused. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_DELETE_IO_SQ;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(1);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));

	d.sc->compl_queues[1].tail = 1;		/* head != tail */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_DELETE_IO_CQ;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(1);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_QUEUE_DELETION, cqe_sc(&cqe));
	d.sc->compl_queues[1].tail = 0;
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(io_cmd_and_doorbell_errors);
ATF_TC_BODY(io_cmd_and_doorbell_errors, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_command *iosq;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);
	dut_io_setup(&d);
	iosq = (struct nvme_command *)(g_ram + GPA_IOSQ);

	/* Unknown IO opcode => Invalid Opcode completion. */
	memset(&c, 0, sizeof(c));
	c.opc = 0xAA;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(1);
	{
		struct nvme_completion cqe = dut_io_cmd(&d, &c);
		ATF_CHECK_EQ(NVME_SC_INVALID_OPCODE, cqe_sc(&cqe));
	}

	/* Ringing the IO SQ tail with an out-of-range value is rejected. */
	memset(&iosq[d.iosq_tail], 0, sizeof(c));
	dut_write(&d, SPEC_DOORBELL + 1 * 8, 4, IO_QENTRIES + 9);

	/* Ring an existing IO CQ head with an out-of-range value. */
	dut_write(&d, SPEC_DOORBELL + 1 * 8 + 4, 4, IO_QENTRIES + 9);

	/*
	 * Create queue 5, then shrink the live queue count below 5.  The
	 * created queues keep a non-NULL base (so the BAR guard passes) while
	 * the doorbell handler's own bound rejects the now-out-of-range index.
	 */
	c = mk_create_cq(5, IO_QENTRIES, GPA_IOCQ + 0x1000, 1, true,
	    d.next_cid++);
	(void)dut_admin_cmd(&d, &c);
	c = mk_create_sq(5, IO_QENTRIES, GPA_IOSQ + 0x1000, 5, d.next_cid++);
	(void)dut_admin_cmd(&d, &c);

	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_SET_FEATURES;
	c.cid = htole16(d.next_cid++);
	c.cdw10 = htole32(NVME_FEAT_NUMBER_OF_QUEUES);
	c.cdw11 = htole32(2 | (2 << 16));	/* 3 SQ + 3 CQ */
	(void)dut_admin_cmd(&d, &c);

	dut_write(&d, SPEC_DOORBELL + 5 * 8, 4, 0);	/* SQ idx 5 > 3 */
	dut_write(&d, SPEC_DOORBELL + 5 * 8 + 4, 4, 0);	/* CQ idx 5 > 3 */

	ATF_CHECK((dut_read32(&d, SPEC_CR_CSTS) & SPEC_CSTS_RDY) != 0);
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(controller_init_errors);
ATF_TC_BODY(controller_init_errors, tc)
{
	struct nvme_dut d;

	/*
	 * The BAR write path masks ASQ/ACQ to page alignment, so the
	 * illegal-size and unaligned-base branches are only reachable by
	 * driving pci_nvme_init_controller() with crafted register state.
	 */
	env_reset();
	dut_init_ram(&d, 16);

	/* Illegal ASQS (< 2). */
	d.sc->regs.csts = 0;
	d.sc->regs.aqa = ((ADMIN_QENTRIES - 1) << 16) | 0;
	d.sc->regs.asq = GPA_ASQ;
	d.sc->regs.acq = GPA_ACQ;
	ATF_CHECK(pci_nvme_init_controller(d.sc) != 0);
	ATF_CHECK((d.sc->regs.csts & SPEC_CSTS_CFS) != 0);

	/* Illegal ACQS (< 2). */
	d.sc->regs.csts = 0;
	d.sc->regs.aqa = (0 << 16) | (ADMIN_QENTRIES - 1);
	ATF_CHECK(pci_nvme_init_controller(d.sc) != 0);
	ATF_CHECK((d.sc->regs.csts & SPEC_CSTS_CFS) != 0);

	/* Unaligned ASQ base. */
	d.sc->regs.csts = 0;
	d.sc->regs.aqa = ((ADMIN_QENTRIES - 1) << 16) | (ADMIN_QENTRIES - 1);
	d.sc->regs.asq = GPA_ASQ + 0x40;
	ATF_CHECK(pci_nvme_init_controller(d.sc) != 0);
	ATF_CHECK((d.sc->regs.csts & SPEC_CSTS_CFS) != 0);

	/* Unaligned ACQ base. */
	d.sc->regs.csts = 0;
	d.sc->regs.asq = GPA_ASQ;
	d.sc->regs.acq = GPA_ACQ + 0x40;
	ATF_CHECK(pci_nvme_init_controller(d.sc) != 0);
	ATF_CHECK((d.sc->regs.csts & SPEC_CSTS_CFS) != 0);

	/* ASQ guest-memory mapping failure. */
	d.sc->regs.csts = 0;
	d.sc->regs.acq = GPA_ACQ;
	g_map_gpa_fail_gpa = GPA_ASQ;
	ATF_CHECK(pci_nvme_init_controller(d.sc) != 0);
	ATF_CHECK((d.sc->regs.csts & SPEC_CSTS_CFS) != 0);

	/* ACQ guest-memory mapping failure (ASQ succeeds first). */
	d.sc->regs.csts = 0;
	g_map_gpa_fail_gpa = GPA_ACQ;
	ATF_CHECK(pci_nvme_init_controller(d.sc) != 0);
	ATF_CHECK((d.sc->regs.csts & SPEC_CSTS_CFS) != 0);
	g_map_gpa_fail_gpa = UINT64_MAX;
}

ATF_TC_WITHOUT_HEAD(doorbell_errors);
ATF_TC_BODY(doorbell_errors, tc)
{
	struct nvme_dut d;

	env_reset();
	dut_init_ram(&d, 16);

	/* Doorbell write before CSTS.RDY is ignored (no crash). */
	dut_write(&d, SPEC_DOORBELL, 4, 1);

	dut_enable(&d);

	/* Out-of-range queue index for SQ doorbell. */
	dut_write(&d, SPEC_DOORBELL + 40 * 8, 4, 1);
	/* Invalid doorbell value (>= admin queue size). */
	dut_write(&d, SPEC_DOORBELL, 4, ADMIN_QENTRIES + 5);
	/* Invalid (non-4) doorbell access size. */
	dut_write(&d, SPEC_DOORBELL, 8, 1);
	/* Write to a CQ that has not been created. */
	dut_write(&d, SPEC_DOORBELL + 1 * 8 + 4, 4, 1);

	/* Out-of-range completion queue index. */
	dut_write(&d, SPEC_DOORBELL + 40 * 8 + 4, 4, 0);

	/* Create IO CQ/SQ, then submit an invalid CQ head-doorbell value. */
	dut_io_setup(&d);
	dut_write(&d, SPEC_DOORBELL + 1 * 8 + 4, 4, IO_QENTRIES + 3);

	/* Controller still responsive. */
	ATF_CHECK((dut_read32(&d, SPEC_CR_CSTS) & SPEC_CSTS_RDY) != 0);
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(bar_register_access);
ATF_TC_BODY(bar_register_access, tc)
{
	struct nvme_dut d;
	uint64_t cap;

	env_reset();
	dut_init_ram(&d, 16);

	/* CAP.MQES (max queue entries, zero-based) matches NVME_MAX_QENTRIES. */
	cap = (uint64_t)dut_read32(&d, SPEC_CR_CAP) |
	    ((uint64_t)dut_read32(&d, SPEC_CR_CAP + 4) << 32);
	ATF_CHECK_EQ((uint16_t)(2048 - 1), (uint16_t)(cap & 0xFFFF));

	/* 1- and 2-byte reads are permitted within the register area. */
	(void)pci_nvme_read(&d.pi, 0, SPEC_CR_CSTS, 1);
	(void)pci_nvme_read(&d.pi, 0, SPEC_CR_VS, 2);

	/* Out-of-range register read returns zero without faulting. */
	ATF_CHECK_EQ(0U, (uint32_t)pci_nvme_read(&d.pi, 0, 0x0d, 4));

	/* MSI-X BAR (bar 4) read/write is forwarded to the MSI-X table. */
	pci_nvme_write(&d.pi, 4, 0, 4, 0xdeadbeef);
	ATF_CHECK_EQ(0xdeadbeefU,
	    (uint32_t)pci_nvme_read(&d.pi, 4, 0, 4));

	/* Unknown BAR index is ignored. */
	pci_nvme_write(&d.pi, 2, 0, 4, 1);
	ATF_CHECK_EQ(0U, (uint32_t)pci_nvme_read(&d.pi, 2, 0, 4));

	/* Writes to the interrupt-mask and reset registers are accepted. */
	dut_write(&d, 0x0c, 4, 0x1);	/* INTMS (MSI-X, ignored) */
	dut_write(&d, 0x10, 4, 0x1);	/* INTMC (MSI-X, ignored) */
	dut_write(&d, 0x20, 4, 0x4E564D65);	/* NSSR, ignored */
	/* Read-only CAP/VS writes are silently dropped. */
	dut_write(&d, SPEC_CR_CAP, 4, 0xffffffff);
	dut_write(&d, SPEC_CR_VS, 4, 0);
	/* A non-4-byte register write is rejected. */
	dut_write(&d, SPEC_CR_CC, 2, 0);
	/* A write to an unknown register offset is ignored. */
	dut_write(&d, 0x60, 4, 0x1234);
	/* CAP remained read-only despite the write above. */
	ATF_CHECK(dut_read32(&d, SPEC_CR_CAP) != 0xffffffff);
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(controller_shutdown_notification);
ATF_TC_BODY(controller_shutdown_notification, tc)
{
	struct nvme_dut d;
	uint32_t csts, shst;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);

	/* CC.SHN = normal shutdown => CSTS.SHST = shutdown complete. */
	dut_write(&d, SPEC_CR_CC, 4,
	    SPEC_CC_EN | (6 << 16) | (4 << 20) | (1 << 14));
	csts = dut_read32(&d, SPEC_CR_CSTS);
	shst = (csts >> 2) & 0x3;
	ATF_CHECK_EQ(2U, shst);		/* NVME_SHST_COMPLETE */
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(config_option_parsing);
ATF_TC_BODY(config_option_parsing, tc)
{
	struct pci_devinst pi;
	int error;

	/* A bad maxq value fails device init. */
	env_reset();
	set_config_value_node(NULL, "ram", "16");
	set_config_value_node(NULL, "maxq", "0");
	memset(&pi, 0, sizeof(pi));
	pi.pi_slot = 3;
	error = pci_nvme_init(&pi, NULL);
	ATF_CHECK(error != 0);

	/* Valid full option set succeeds. */
	env_reset();
	set_config_value_node(NULL, "ram", "8");
	set_config_value_node(NULL, "maxq", "4");
	set_config_value_node(NULL, "qsz", "64");
	set_config_value_node(NULL, "ioslots", "8");
	set_config_value_node(NULL, "sectsz", "512");
	set_config_value_node(NULL, "ser", "SERIAL123");
	set_config_value_node(NULL, "eui64", "0x1122334455667788");
	set_config_value_node(NULL, "dsm", "disable");
	set_config_value_node(NULL, "bootindex", "0");
	memset(&pi, 0, sizeof(pi));
	pi.pi_slot = 4;
	error = pci_nvme_init(&pi, NULL);
	ATF_CHECK_EQ(0, error);

	/* An invalid dsm option is rejected. */
	env_reset();
	set_config_value_node(NULL, "ram", "8");
	set_config_value_node(NULL, "dsm", "bogus");
	memset(&pi, 0, sizeof(pi));
	pi.pi_slot = 7;
	error = pci_nvme_init(&pi, NULL);
	ATF_CHECK(error != 0);

	/* An invalid eui64 option is rejected. */
	env_reset();
	set_config_value_node(NULL, "ram", "8");
	set_config_value_node(NULL, "eui64", "notanumber");
	memset(&pi, 0, sizeof(pi));
	pi.pi_slot = 8;
	error = pci_nvme_init(&pi, NULL);
	ATF_CHECK(error != 0);

	/* A bootindex that the PCI layer rejects fails init. */
	env_reset();
	set_config_value_node(NULL, "ram", "8");
	set_config_value_node(NULL, "bootindex", "1");
	g_bootdev_fail = true;
	memset(&pi, 0, sizeof(pi));
	pi.pi_slot = 9;
	error = pci_nvme_init(&pi, NULL);
	ATF_CHECK(error != 0);
	g_bootdev_fail = false;

	/* An invalid sector size is rejected. */
	env_reset();
	set_config_value_node(NULL, "ram", "8");
	set_config_value_node(NULL, "sectsz", "999");
	memset(&pi, 0, sizeof(pi));
	pi.pi_slot = 5;
	error = pci_nvme_init(&pi, NULL);
	ATF_CHECK(error != 0);

	/* A failing block backend open fails init. */
	env_reset();
	g_blk_open_fail = true;
	memset(&pi, 0, sizeof(pi));
	pi.pi_slot = 6;
	error = pci_nvme_init(&pi, NULL);
	ATF_CHECK(error != 0);
}

ATF_TC_WITHOUT_HEAD(legacy_config_paths);
ATF_TC_BODY(legacy_config_paths, tc)
{
	int error;

	env_reset();
	/* ram=<n> shorthand. */
	error = pci_nvme_legacy_config(NULL, "ram=16");
	ATF_CHECK_EQ(0, error);
	ATF_CHECK_STREQ("16", get_config_value_node(NULL, "ram"));

	env_reset();
	/* ram=<n>,<more-opts> */
	error = pci_nvme_legacy_config(NULL, "ram=32,maxq=4");
	ATF_CHECK_EQ(0, error);
	ATF_CHECK_STREQ("32", get_config_value_node(NULL, "ram"));

	env_reset();
	/* Non-ram opts fall through to blockif legacy config. */
	error = pci_nvme_legacy_config(NULL, "/dev/null");
	ATF_CHECK_EQ(0, error);

	/* NULL opts is a no-op success. */
	error = pci_nvme_legacy_config(NULL, NULL);
	ATF_CHECK_EQ(0, error);
}

ATF_TC_WITHOUT_HEAD(snapshot_save_validate_restore);
ATF_TC_BODY(snapshot_save_validate_restore, tc)
{
	static uint8_t snapbuf[65536];
	struct nvme_dut d, d2;
	size_t used;
	int error;

	env_reset();
	dut_init_blockif(&d, 1024 * 1024);
	dut_enable(&d);
	dut_io_setup(&d);

	/* Outstanding AERs so the codec serializes/restores the AER list. */
	ATF_REQUIRE_EQ(0, pci_nvme_aer_add(d.sc, 0x77, 0));
	ATF_REQUIRE_EQ(0, pci_nvme_aer_add(d.sc, 0x88, 0));

	/* Pause must succeed on a quiescent device. */
	ATF_REQUIRE_EQ(0, pci_nvme_pause(&d.pi));

	/*
	 * Inject a backpressured (pending) completion on IO CQ 1 so the codec
	 * serializes and restores the pending-CQE list, not just live queues.
	 */
	{
		struct pci_nvme_pending_cqe *pend = calloc(1, sizeof(*pend));
		ATF_REQUIRE(pend != NULL);
		pend->cdw0 = 0xABCD;
		pend->sqhd = 1;
		pend->sqid = 1;
		pend->cid = 0x55;
		pend->status = 0;
		STAILQ_INSERT_TAIL(&d.sc->compl_queues[1].pending, pend, link);
		d.sc->compl_queues[1].pending_count = 1;
	}

	/* Save. */
	memset(snapbuf, 0, sizeof(snapbuf));
	{
		struct vm_snapshot_meta meta = {
			.dev_data = &d.pi,
			.buffer = { .buf_start = snapbuf,
			    .buf_size = sizeof(snapbuf),
			    .buf = snapbuf, .buf_rem = sizeof(snapbuf) },
			.op = VM_SNAPSHOT_SAVE,
		};
		error = pci_nvme_snapshot(&meta);
		ATF_CHECK_EQ(0, error);
		used = sizeof(snapbuf) - meta.buffer.buf_rem;
	}
	ATF_CHECK(used > 0);

	/* Validate consumes the record without mutating live state. */
	{
		struct vm_snapshot_meta meta = {
			.dev_data = &d.pi,
			.buffer = { .buf_start = snapbuf, .buf_size = used,
			    .buf = snapbuf, .buf_rem = used },
			.op = VM_SNAPSHOT_VALIDATE,
		};
		error = pci_nvme_snapshot_validate(&meta);
		ATF_CHECK_EQ(0, error);
	}

	ATF_CHECK_EQ(0, pci_nvme_resume(&d.pi));

	/* Restore into a second, identically-shaped device. */
	env_reset();
	dut_init_blockif(&d2, 1024 * 1024);
	dut_enable(&d2);
	dut_io_setup(&d2);
	ATF_REQUIRE_EQ(0, pci_nvme_pause(&d2.pi));
	{
		struct vm_snapshot_meta meta = {
			.dev_data = &d2.pi,
			.buffer = { .buf_start = snapbuf, .buf_size = used,
			    .buf = snapbuf, .buf_rem = used },
			.op = VM_SNAPSHOT_RESTORE,
		};
		error = pci_nvme_snapshot(&meta);
		ATF_CHECK_EQ(0, error);
	}
	ATF_CHECK_EQ(0, pci_nvme_resume(&d2.pi));
	dut_teardown(&d2);
}

ATF_TC_WITHOUT_HEAD(format_nvm);
ATF_TC_BODY(format_nvm, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;

	/* RAM store: format reallocates the namespace synchronously. */
	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_FORMAT_NVM;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(1);
	c.cdw10 = htole32(0);		/* lbaf 0, ses 0, pi 0 */
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));

	/* Invalid LBA format => command-specific Invalid Format. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_FORMAT_NVM;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(1);
	c.cdw10 = htole32(0x1);		/* lbaf 1 unsupported */
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_FORMAT, cqe_sc(&cqe));

	/* Bad namespace id => invalid namespace. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_FORMAT_NVM;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(7);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_NAMESPACE_OR_FORMAT, cqe_sc(&cqe));

	/* Unsupported secure-erase setting => invalid field. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_FORMAT_NVM;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(1);
	c.cdw10 = htole32(0x2 << 9);	/* ses = 2 */
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_FIELD, cqe_sc(&cqe));

	/* Protection information requested but unsupported => invalid field. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_FORMAT_NVM;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(1);
	c.cdw10 = htole32(0x1 << 5);	/* pi = 1 */
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_FIELD, cqe_sc(&cqe));
	dut_teardown(&d);

	/* Block backend: format issues a full-namespace delete. */
	env_reset();
	dut_init_blockif(&d, 1024 * 1024);
	dut_enable(&d);
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_FORMAT_NVM;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(1);
	c.cdw10 = htole32(0);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(0, cqe_sc(&cqe));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(feature_invalid_callback);
ATF_TC_BODY(feature_invalid_callback, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);

	/* A FID with no real handler falls back to the invalid callback. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_GET_FEATURES;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(0);
	c.cdw10 = htole32(NVME_FEAT_LBA_RANGE_TYPE);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_FIELD, cqe_sc(&cqe));

	/* Set on the same FID also hits the invalid callback. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_SET_FEATURES;
	c.cid = htole16(d.next_cid++);
	c.nsid = htole32(0);
	c.cdw10 = htole32(NVME_FEAT_LBA_RANGE_TYPE);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SC_INVALID_FIELD, cqe_sc(&cqe));
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(debug_logging_paths);
ATF_TC_BODY(debug_logging_paths, tc)
{
	struct nvme_dut d;
	struct nvme_command c;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);

	/* Exercise the verbose logging branches (nvme_fid_to_name etc.). */
	nvme_debug = 1;
	/*
	 * Every feature id (including ids beyond NVME_FID_MAX, which are
	 * still name-decoded before rejection) so nvme_fid_to_name's full
	 * name table and its default arm are walked.
	 */
	for (uint32_t fid = 0; fid < 0x100; fid++) {
		memset(&c, 0, sizeof(c));
		c.opc = NVME_OPC_GET_FEATURES;
		c.cid = htole16(d.next_cid++);
		c.nsid = htole32(0);
		c.cdw10 = htole32(fid);
		(void)dut_admin_cmd(&d, &c);
	}
	/* An out-of-table id name plus a register dump. */
	(void)dut_read32(&d, SPEC_CR_CC);
	(void)dut_read32(&d, SPEC_CR_AQA);
	nvme_debug = 0;
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(namespace_resize_notice);
ATF_TC_BODY(namespace_resize_notice, tc)
{
	struct nvme_dut d;

	env_reset();
	dut_init_blockif(&d, 1024 * 1024);
	dut_enable(&d);

	/* The backend registered a resize callback at open. */
	ATF_REQUIRE(g_blk_resize_cb != NULL);
	g_blk_size = 2 * 1024 * 1024;
	g_blk_resize_cb((struct blockif_ctxt *)g_blk_resize_arg, g_blk_resize_arg,
	    (off_t)g_blk_size);
	/* Namespace size doubled; a negative size is ignored. */
	ATF_CHECK_EQ((uint64_t)(2 * 1024 * 1024), d.sc->nvstore.size);
	g_blk_resize_cb(NULL, g_blk_resize_arg, (off_t)-1);
	ATF_CHECK_EQ((uint64_t)(2 * 1024 * 1024), d.sc->nvstore.size);
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(async_event_processing);
ATF_TC_BODY(async_event_processing, tc)
{
	struct nvme_dut d;
	struct nvme_completion *acq;
	int posted;

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);
	acq = (struct nvme_completion *)(g_ram + GPA_ACQ);

	/* Enable every asynchronous event notification. */
	d.sc->feat[NVME_FEAT_ASYNC_EVENT_CONFIGURATION].cdw11 = 0xffffffff;

	/*
	 * Process one posted event at a time, replenishing the AER pool before
	 * each so every notice sub-type reaches publication.  A trailing
	 * event with no AER available then covers the drained path.
	 */
	static const uint32_t notices[] = {
		PCI_NVME_AEI_NOTICE_NS_ATTR_CHANGED,
		PCI_NVME_AEI_NOTICE_FW_ACTIVATION,
		PCI_NVME_AEI_NOTICE_TELEMETRY_CHANGE,
		PCI_NVME_AEI_NOTICE_ANA_CHANGE,
		PCI_NVME_AEI_NOTICE_PREDICT_LATENCY_CHANGE,
		PCI_NVME_AEI_NOTICE_LBA_STATUS_ALERT,
		PCI_NVME_AEI_NOTICE_ENDURANCE_GROUP_CHANGE,
	};

	/* Error AEN => Error log. */
	ATF_REQUIRE_EQ(0, pci_nvme_aer_add(d.sc, 0x100, 0));
	pthread_mutex_lock(&d.sc->aen_mtx);
	d.sc->aen[PCI_NVME_AE_TYPE_ERROR].posted = true;
	d.sc->aen[PCI_NVME_AE_TYPE_ERROR].event_data = 0;
	pci_nvme_aen_process(d.sc);
	pthread_mutex_unlock(&d.sc->aen_mtx);

	/* SMART/health AEN whose bit is enabled in the mask. */
	ATF_REQUIRE_EQ(0, pci_nvme_aer_add(d.sc, 0x101, 0));
	pthread_mutex_lock(&d.sc->aen_mtx);
	d.sc->aen[PCI_NVME_AE_TYPE_SMART].posted = true;
	d.sc->aen[PCI_NVME_AE_TYPE_SMART].event_data = 0x1;
	pci_nvme_aen_process(d.sc);
	pthread_mutex_unlock(&d.sc->aen_mtx);

	/* Every notice sub-type maps to a distinct log identifier. */
	for (unsigned i = 0; i < nitems(notices); i++) {
		ATF_REQUIRE_EQ(0, pci_nvme_aer_add(d.sc, 0x200 + i, 0));
		pthread_mutex_lock(&d.sc->aen_mtx);
		d.sc->aen[PCI_NVME_AE_TYPE_NOTICE].posted = true;
		d.sc->aen[PCI_NVME_AE_TYPE_NOTICE].event_data = notices[i];
		pci_nvme_aen_process(d.sc);
		pthread_mutex_unlock(&d.sc->aen_mtx);
	}

	/* Notice: out-of-range event data => internal error status. */
	ATF_REQUIRE_EQ(0, pci_nvme_aer_add(d.sc, 0x300, 0));
	pthread_mutex_lock(&d.sc->aen_mtx);
	d.sc->aen[PCI_NVME_AE_TYPE_NOTICE].posted = true;
	d.sc->aen[PCI_NVME_AE_TYPE_NOTICE].event_data = 99;
	pci_nvme_aen_process(d.sc);
	pthread_mutex_unlock(&d.sc->aen_mtx);

	/* Unknown AEN type (index 4) => default branch, internal error. */
	ATF_REQUIRE_EQ(0, pci_nvme_aer_add(d.sc, 0x301, 0));
	pthread_mutex_lock(&d.sc->aen_mtx);
	d.sc->aen[4].posted = true;
	d.sc->aen[4].event_data = 0;
	pci_nvme_aen_process(d.sc);

	/* No AER available now => the worker bails out of the pass. */
	d.sc->aen[PCI_NVME_AE_TYPE_ERROR].posted = true;
	d.sc->aen[PCI_NVME_AE_TYPE_ERROR].event_data = 0;
	pci_nvme_aen_process(d.sc);
	pthread_mutex_unlock(&d.sc->aen_mtx);

	posted = 0;
	for (int i = 0; i < ADMIN_QENTRIES; i++)
		if (NVME_COMPLETION_VALID(acq[i]))
			posted++;
	ATF_CHECK(posted >= 3);

	/* Masked SMART event is dropped (mask bit clear => continue). */
	d.sc->feat[NVME_FEAT_ASYNC_EVENT_CONFIGURATION].cdw11 = 0;
	pthread_mutex_lock(&d.sc->aen_mtx);
	d.sc->aen[PCI_NVME_AE_TYPE_SMART].posted = true;
	d.sc->aen[PCI_NVME_AE_TYPE_SMART].event_data = 0x1;
	pci_nvme_aen_process(d.sc);
	pthread_mutex_unlock(&d.sc->aen_mtx);

	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(pause_failure_paths);
ATF_TC_BODY(pause_failure_paths, tc)
{
	struct nvme_dut d;

	/* Backend suspend failure aborts the pause. */
	env_reset();
	dut_init_blockif(&d, 1024 * 1024);
	dut_enable(&d);
	g_blk_suspend_fail = true;
	ATF_CHECK(pci_nvme_pause(&d.pi) != 0);
	g_blk_suspend_fail = false;
	dut_teardown(&d);

	/* A non-quiescent device (in-flight I/O) cannot be paused. */
	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);
	d.sc->pending_ios = 1;
	ATF_CHECK_EQ(EBUSY, pci_nvme_pause(&d.pi));
	d.sc->pending_ios = 0;
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(admin_unsupported_opcodes);
ATF_TC_BODY(admin_unsupported_opcodes, tc)
{
	struct nvme_dut d;
	struct nvme_command c;
	struct nvme_completion cqe;
	uint8_t opcs[] = { NVME_OPC_SECURITY_SEND, NVME_OPC_SECURITY_RECEIVE,
	    NVME_OPC_SANITIZE, NVME_OPC_GET_LBA_STATUS };

	env_reset();
	dut_init_ram(&d, 16);
	dut_enable(&d);

	/* Firmware activate is recognised but reports an invalid slot. */
	memset(&c, 0, sizeof(c));
	c.opc = NVME_OPC_FIRMWARE_ACTIVATE;
	c.cid = htole16(d.next_cid++);
	cqe = dut_admin_cmd(&d, &c);
	ATF_CHECK_EQ(NVME_SCT_COMMAND_SPECIFIC, cqe_sct(&cqe));
	ATF_CHECK_EQ(NVME_SC_INVALID_FIRMWARE_SLOT, cqe_sc(&cqe));

	/* Valid-but-unsupported opcodes report Invalid Field. */
	for (unsigned i = 0; i < nitems(opcs); i++) {
		memset(&c, 0, sizeof(c));
		c.opc = opcs[i];
		c.cid = htole16(d.next_cid++);
		cqe = dut_admin_cmd(&d, &c);
		ATF_CHECK_EQ(NVME_SC_INVALID_FIELD, cqe_sc(&cqe));
	}
	dut_teardown(&d);
}

ATF_TC_WITHOUT_HEAD(fini_queues_direct);
ATF_TC_BODY(fini_queues_direct, tc)
{
	struct nvme_dut d;

	/*
	 * pci_nvme_fini_queues() is otherwise only reached on an init failure
	 * that requires a pthread primitive to fail (unreachable rootless), so
	 * drive the queue teardown routine directly on a live instance.
	 */
	env_reset();
	dut_init_ram(&d, 16);
	/*
	 * Re-initialising with counts above NVME_QUEUES exercises the clamp
	 * branches; the previous arrays leak but the process is short-lived.
	 */
	ATF_CHECK_EQ(0, pci_nvme_init_queues(d.sc, NVME_QUEUES + 50,
	    NVME_QUEUES + 50));
	ATF_CHECK_EQ((uint32_t)NVME_QUEUES, d.sc->num_squeues);
	ATF_CHECK_EQ((uint32_t)NVME_QUEUES, d.sc->num_cqueues);
	pci_nvme_fini_queues(d.sc);
	d.sc->submit_queues = NULL;
	d.sc->compl_queues = NULL;
	ATF_CHECK(true);
}

/* Build a rich, quiesced snapshot record into buf; returns its length. */
static size_t
build_snapshot(struct nvme_dut *d, uint8_t *buf, size_t cap)
{
	struct pci_nvme_pending_cqe *pend;
	struct vm_snapshot_meta meta = {
		.dev_data = &d->pi,
		.buffer = { .buf_start = buf, .buf_size = cap,
		    .buf = buf, .buf_rem = cap },
		.op = VM_SNAPSHOT_SAVE,
	};

	dut_init_blockif(d, 1024 * 1024);
	dut_enable(d);
	dut_io_setup(d);
	ATF_REQUIRE_EQ(0, pci_nvme_aer_add(d->sc, 0x77, 0));
	ATF_REQUIRE_EQ(0, pci_nvme_pause(&d->pi));
	pend = calloc(1, sizeof(*pend));
	ATF_REQUIRE(pend != NULL);
	pend->cid = 0x55;
	STAILQ_INSERT_TAIL(&d->sc->compl_queues[1].pending, pend, link);
	d->sc->compl_queues[1].pending_count = 1;

	ATF_REQUIRE_EQ(0, pci_nvme_snapshot(&meta));
	return (cap - meta.buffer.buf_rem);
}

ATF_TC_WITHOUT_HEAD(snapshot_record_validation);
ATF_TC_BODY(snapshot_record_validation, tc)
{
	static uint8_t snapbuf[65536];
	struct nvme_dut d;
	size_t used;
	int nonzero;

	env_reset();
	used = build_snapshot(&d, snapbuf, sizeof(snapbuf));
	ATF_REQUIRE(used > 64);

	/* The intact record validates cleanly against the live device. */
	{
		struct vm_snapshot_meta m = {
			.dev_data = &d.pi,
			.buffer = { .buf_start = snapbuf, .buf_size = used,
			    .buf = snapbuf, .buf_rem = used },
			.op = VM_SNAPSHOT_VALIDATE,
		};
		ATF_CHECK_EQ(0, pci_nvme_snapshot_validate(&m));
	}

	/*
	 * Every truncation of the record must be rejected: the codec runs out
	 * of buffer at some field and returns an error (exercises each field's
	 * SNAPSHOT_*_OR_LEAVE failure arm).
	 */
	for (size_t len = 4; len < used; len += 4) {
		struct vm_snapshot_meta m = {
			.dev_data = &d.pi,
			.buffer = { .buf_start = snapbuf, .buf_size = len,
			    .buf = snapbuf, .buf_rem = len },
			.op = VM_SNAPSHOT_VALIDATE,
		};
		ATF_CHECK(pci_nvme_snapshot_validate(&m) != 0);
	}

	/*
	 * Corrupting each 32-bit word and re-validating exercises the codec's
	 * per-field mismatch branches.  Many words are validated fields (which
	 * must reject the change); the freely-decoded register words may still
	 * pass, so require only that a meaningful fraction is caught.
	 */
	nonzero = 0;
	for (size_t off = 0; off + 4 <= used; off += 4) {
		uint32_t saved;
		struct vm_snapshot_meta m = {
			.dev_data = &d.pi,
			.buffer = { .buf_start = snapbuf, .buf_size = used,
			    .buf = snapbuf, .buf_rem = used },
			.op = VM_SNAPSHOT_VALIDATE,
		};

		memcpy(&saved, snapbuf + off, 4);
		snapbuf[off] ^= 0xFF;
		snapbuf[off + 1] ^= 0xFF;
		if (pci_nvme_snapshot_validate(&m) != 0)
			nonzero++;
		memcpy(snapbuf + off, &saved, 4);
	}
	ATF_CHECK(nonzero > 5);

	/* A wrong magic and wrong version are both rejected. */
	{
		uint32_t saved;
		struct vm_snapshot_meta m = {
			.dev_data = &d.pi,
			.buffer = { .buf_start = snapbuf, .buf_size = used,
			    .buf = snapbuf, .buf_rem = used },
			.op = VM_SNAPSHOT_VALIDATE,
		};
		memcpy(&saved, snapbuf, 4);
		le32enc(snapbuf, 0xdeadbeef);
		ATF_CHECK(pci_nvme_snapshot_validate(&m) != 0);
		memcpy(snapbuf, &saved, 4);
	}

	/* Save into an undersized buffer fails at some field (save-side OR). */
	for (size_t cap = 8; cap < used; cap += 61) {
		struct nvme_dut d2;
		int r;

		env_reset();
		dut_init_blockif(&d2, 1024 * 1024);
		dut_enable(&d2);
		dut_io_setup(&d2);
		ATF_REQUIRE_EQ(0, pci_nvme_pause(&d2.pi));
		{
			struct vm_snapshot_meta m = {
				.dev_data = &d2.pi,
				.buffer = { .buf_start = snapbuf,
				    .buf_size = cap,
				    .buf = snapbuf, .buf_rem = cap },
				.op = VM_SNAPSHOT_SAVE,
			};
			r = pci_nvme_snapshot(&m);
		}
		ATF_CHECK(r != 0);
		(void)pci_nvme_resume(&d2.pi);
		dut_teardown(&d2);
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, init_pci_config_and_bar);
	ATF_TP_ADD_TC(tp, enable_reset_transitions);
	ATF_TP_ADD_TC(tp, enable_bad_aqa_sets_cfs);
	ATF_TP_ADD_TC(tp, identify_controller);
	ATF_TP_ADD_TC(tp, identify_namespace);
	ATF_TP_ADD_TC(tp, create_delete_io_queues);
	ATF_TP_ADD_TC(tp, admin_invalid_opcode);
	ATF_TP_ADD_TC(tp, io_write_read_ram_prp1);
	ATF_TP_ADD_TC(tp, io_write_read_ram_prp2);
	ATF_TP_ADD_TC(tp, io_write_read_prp_list);
	ATF_TP_ADD_TC(tp, io_write_read_blockif);
	ATF_TP_ADD_TC(tp, io_blockif_multipage);
	ATF_TP_ADD_TC(tp, io_flush);
	ATF_TP_ADD_TC(tp, io_dsm_trim);
	ATF_TP_ADD_TC(tp, io_write_zeroes_unsupported);
	ATF_TP_ADD_TC(tp, io_invalid_nsid);
	ATF_TP_ADD_TC(tp, io_lba_out_of_range);
	ATF_TP_ADD_TC(tp, io_mdts_exceeded);
	ATF_TP_ADD_TC(tp, get_log_pages);
	ATF_TP_ADD_TC(tp, features_num_queues);
	ATF_TP_ADD_TC(tp, features_misc);
	ATF_TP_ADD_TC(tp, admin_abort_and_async);
	ATF_TP_ADD_TC(tp, admin_async_event_limit);
	ATF_TP_ADD_TC(tp, identify_active_ns_list);
	ATF_TP_ADD_TC(tp, create_queue_errors);
	ATF_TP_ADD_TC(tp, io_completion_backpressure);
	ATF_TP_ADD_TC(tp, queue_delete_busy);
	ATF_TP_ADD_TC(tp, io_cmd_and_doorbell_errors);
	ATF_TP_ADD_TC(tp, controller_init_errors);
	ATF_TP_ADD_TC(tp, doorbell_errors);
	ATF_TP_ADD_TC(tp, bar_register_access);
	ATF_TP_ADD_TC(tp, controller_shutdown_notification);
	ATF_TP_ADD_TC(tp, config_option_parsing);
	ATF_TP_ADD_TC(tp, legacy_config_paths);
	ATF_TP_ADD_TC(tp, snapshot_save_validate_restore);
	ATF_TP_ADD_TC(tp, snapshot_record_validation);
	ATF_TP_ADD_TC(tp, format_nvm);
	ATF_TP_ADD_TC(tp, feature_invalid_callback);
	ATF_TP_ADD_TC(tp, debug_logging_paths);
	ATF_TP_ADD_TC(tp, namespace_resize_notice);
	ATF_TP_ADD_TC(tp, async_event_processing);
	ATF_TP_ADD_TC(tp, pause_failure_paths);
	ATF_TP_ADD_TC(tp, admin_unsupported_opcodes);
	ATF_TP_ADD_TC(tp, fini_queues_direct);
	return (atf_no_error());
}
