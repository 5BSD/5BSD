/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * TU-include coverage harness for bhyve's AHCI/SATA PCI device
 * (usr.sbin/bhyve/pci_ahci.c).  The device source is compiled directly into
 * the test so its static command-processing, register, DMA and snapshot paths
 * can be driven without a running VM.  The bhyve infrastructure it depends on
 * (pci_emul BAR/MSI/DMA, guest memory, block_if backend, nvlist config,
 * snapshot codec) is replaced with independent, deterministic mocks defined
 * below.
 *
 * Assertions are checked against the independent SATA/AHCI 1.3.1 + ATA command
 * set oracle (FIS types, command-list/table/PRDT layout, D2H/SDB FIS fields,
 * PxIS/PxTFD/PxCI/PxSACT semantics), NEVER against the implementation's own
 * output.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/endian.h>
#include <sys/ata.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#ifndef BHYVE_SNAPSHOT
#define	BHYVE_SNAPSHOT
#endif

/* ------------------------------------------------------------------ *
 * Independent AHCI/ATA oracle constants (not taken from ahci.h).      *
 * ------------------------------------------------------------------ */
#define	O_FIS_H2D		0x27
#define	O_FIS_D2H		0x34
#define	O_FIS_PIOSETUP		0x5F
#define	O_FIS_SETDEVBITS	0xA1

#define	O_ATA_S_ERR		0x01
#define	O_ATA_S_DRQ		0x08
#define	O_ATA_S_DSC		0x10
#define	O_ATA_S_DF		0x20
#define	O_ATA_S_RDY		0x40
#define	O_ATA_S_BSY		0x80
#define	O_ATA_E_ABRT		0x04

#define	O_PxIS_DHR		0x00000001	/* D2H register FIS */
#define	O_PxIS_PS		0x00000002	/* PIO setup FIS */
#define	O_PxIS_SDB		0x00000008	/* set device bits FIS */
#define	O_PxIS_TFES		0x40000000	/* task file error */
#define	O_PxIS_HBFS		0x20000000	/* host bus fatal error */
#define	O_PxIS_HBDS		0x10000000	/* host bus data error */

#define	O_RFIS_D2H_OFF		0x40
#define	O_RFIS_SDB_OFF		0x58
#define	O_RFIS_PIO_OFF		0x20

/* ------------------------------------------------------------------ *
 * Guest physical memory + DMA mock.                                   *
 * ------------------------------------------------------------------ */
#define	GMEM_SIZE	(32u * 1024 * 1024)
static uint8_t *g_gmem;
static bool g_paddr_fail_en;
static uint64_t g_paddr_fail_gpa;
static bool g_map_dma_fail;
static size_t g_dirty_bytes;

struct vmctx;

static void
gmem_reset(void)
{
	if (g_gmem == NULL)
		g_gmem = calloc(1, GMEM_SIZE);
	else
		memset(g_gmem, 0, GMEM_SIZE);
	g_paddr_fail_en = false;
	g_paddr_fail_gpa = 0;
	g_map_dma_fail = false;
	g_dirty_bytes = 0;
}

void *
paddr_guest2host(struct vmctx *ctx __unused, uintptr_t gpa, size_t len)
{

	if (gpa + len > GMEM_SIZE)
		return (NULL);
	if (g_paddr_fail_en && gpa == g_paddr_fail_gpa)
		return (NULL);
	return (g_gmem + gpa);
}

uintptr_t
paddr_host2guest(struct vmctx *ctx __unused, void *addr)
{

	return ((uintptr_t)((uint8_t *)addr - g_gmem));
}

/* ------------------------------------------------------------------ *
 * config.h nvlist mock (tiny tree of string values + child nodes).   *
 * ------------------------------------------------------------------ */
#include "config.h"

struct nvlist {
	struct nv_ent {
		char key[24];
		char *val;
		struct nvlist *child;
	} ent[40];
	int n;
};

static struct nv_ent *
nv_find(struct nvlist *nvl, const char *key)
{
	int i;

	for (i = 0; i < nvl->n; i++)
		if (strcmp(nvl->ent[i].key, key) == 0)
			return (&nvl->ent[i]);
	return (NULL);
}

static struct nv_ent *
nv_getent(struct nvlist *nvl, const char *key)
{
	struct nv_ent *e;

	e = nv_find(nvl, key);
	if (e != NULL)
		return (e);
	assert(nvl->n < (int)(sizeof(nvl->ent) / sizeof(nvl->ent[0])));
	e = &nvl->ent[nvl->n++];
	strlcpy(e->key, key, sizeof(e->key));
	e->val = NULL;
	e->child = NULL;
	return (e);
}

const char *
get_config_value_node(const nvlist_t *nvl, const char *name)
{
	struct nv_ent *e;

	if (nvl == NULL)
		return (NULL);
	e = nv_find((struct nvlist *)(uintptr_t)nvl, name);
	return (e != NULL ? e->val : NULL);
}

void
set_config_value_node(nvlist_t *nvl, const char *key, const char *val)
{
	struct nv_ent *e;

	e = nv_getent((struct nvlist *)nvl, key);
	free(e->val);
	e->val = val != NULL ? strdup(val) : NULL;
}

nvlist_t *
create_relative_config_node(nvlist_t *nvl, const char *name)
{
	struct nv_ent *e;

	e = nv_getent((struct nvlist *)nvl, name);
	if (e->child == NULL)
		e->child = calloc(1, sizeof(struct nvlist));
	return ((nvlist_t *)e->child);
}

nvlist_t *
find_relative_config_node(nvlist_t *nvl, const char *name)
{
	struct nv_ent *e;

	if (nvl == NULL)
		return (NULL);
	e = nv_find((struct nvlist *)nvl, name);
	return (e != NULL ? (nvlist_t *)e->child : NULL);
}

/* ------------------------------------------------------------------ *
 * pci_emul mock.  Guard out the shipped mock header and provide a     *
 * device-accurate subset (pci_ahci uses .pe_alias / MSI count /       *
 * emulated-DMA map, absent from the shared mock).                     *
 * ------------------------------------------------------------------ */
#define	MOCK_PCI_EMUL_H
struct vm_snapshot_meta;

enum pcibar_type { PCIBAR_NONE, PCIBAR_IO, PCIBAR_MEM32, PCIBAR_MEM64 };
struct pcibar {
	enum pcibar_type type;
	uint64_t size;
	uint64_t addr;
};
struct pci_devinst {
	struct vmctx *pi_vmctx;
	void *pi_arg;
	int pi_slot;
	int pi_func;
	struct pcibar pi_bar[7];
	uint8_t pi_cfgdata[256];
};
struct pci_devemu {
	const char *pe_emu;
	const char *pe_alias;
	int (*pe_init)(struct pci_devinst *, nvlist_t *);
	int (*pe_legacy_config)(nvlist_t *, const char *);
	void (*pe_barwrite)(struct pci_devinst *, int, uint64_t, int, uint64_t);
	uint64_t (*pe_barread)(struct pci_devinst *, int, uint64_t, int);
	int (*pe_snapshot)(struct vm_snapshot_meta *);
	int (*pe_snapshot_validate)(struct vm_snapshot_meta *);
	int (*pe_pause)(struct pci_devinst *);
	int (*pe_resume)(struct pci_devinst *);
	uint32_t pe_migration_flags;
};
#define	PCI_EMUL_SET(x)

#define	PCI_MIGRATION_F_STATE_CODEC	(1U << 0)
#define	PCI_MIGRATION_F_COMPAT_FIXED	(1U << 1)
#define	PCI_MIGRATION_F_COMPAT_CALLBACK	(1U << 2)
#define	PCI_MIGRATION_F_DMA_NONE		(1U << 3)
#define	PCI_MIGRATION_F_DMA_TRACKED	(1U << 4)
#define	PCI_MIGRATION_F_QUIESCE_NONE	(1U << 5)
#define	PCI_MIGRATION_F_QUIESCE_CALLBACK	(1U << 6)

enum pci_dma_direction {
	PCI_DMA_DEVICE_READ = 0,
	PCI_DMA_DEVICE_WRITE,
	PCI_DMA_BIDIRECTIONAL,
};

#define	PCIR_DEVICE			0x02
#define	PCIR_VENDOR			0x00
#define	PCIR_REVID			0x08
#define	PCIR_PROGIF			0x09
#define	PCIR_SUBCLASS			0x0a
#define	PCIR_CLASS			0x0b
#define	PCIC_STORAGE			0x01
#define	PCIS_STORAGE_SATA		0x06
#define	PCIP_STORAGE_SATA_AHCI_1_0	0x01

/* MSI / interrupt bookkeeping. */
static int g_msi_maxmsg;		/* value returned by pci_msi_maxmsgnum */
static int g_msicap_msgnum;
static int g_lintr_asserts, g_lintr_deasserts, g_lintr_requests;
static int g_msi_generated;
static int g_last_msi_index;
static int g_barcount;

void
pci_set_cfgdata8(struct pci_devinst *pi, int off, uint8_t v)
{
	pi->pi_cfgdata[off] = v;
}
void
pci_set_cfgdata16(struct pci_devinst *pi, int off, uint16_t v)
{
	le16enc(&pi->pi_cfgdata[off], v);
}
int
pci_emul_alloc_bar(struct pci_devinst *pi, int idx, enum pcibar_type type,
    uint64_t size)
{
	pi->pi_bar[idx].type = type;
	pi->pi_bar[idx].size = size;
	g_barcount++;
	return (0);
}
void
pci_emul_add_msicap(struct pci_devinst *pi __unused, int msgnum)
{
	g_msicap_msgnum = msgnum;
}
void
pci_lintr_request(struct pci_devinst *pi __unused)
{
	g_lintr_requests++;
}
void
pci_lintr_assert(struct pci_devinst *pi __unused)
{
	g_lintr_asserts++;
}
void
pci_lintr_deassert(struct pci_devinst *pi __unused)
{
	g_lintr_deasserts++;
}
int
pci_msi_maxmsgnum(struct pci_devinst *pi __unused)
{
	return (g_msi_maxmsg);
}
void
pci_generate_msi(struct pci_devinst *pi __unused, int index)
{
	g_msi_generated++;
	g_last_msi_index = index;
}
void *
pci_emul_map_dma(struct pci_devinst *pi __unused, uint64_t gpa, size_t len,
    enum pci_dma_direction dir __unused)
{
	if (g_map_dma_fail)
		return (NULL);
	if (gpa + len > GMEM_SIZE)
		return (NULL);
	return (g_gmem + gpa);
}
void
pci_emul_mark_dma_dirty_mapping(struct pci_devinst *pi __unused, void *addr
    __unused, size_t len)
{
	g_dirty_bytes += len;
}

/* ------------------------------------------------------------------ *
 * block_if mock: in-memory disk with deferred completion.            *
 * ------------------------------------------------------------------ */
#include "block_if.h"

struct blockif_ctxt {
	uint8_t *disk;
	off_t size;
	int sectsz;
	int candelete;
	int ro;
	char ident[BLOCKIF_CHECKPOINT_ID_MAX];
};

/* Test controls for backend behaviour. */
static bool g_open_fail;
static int g_boot_dev_ret;
static int g_submit_err;		/* returned by blockif_read/write/... */
static int g_complete_err;		/* err delivered to completion cb */
static off_t g_disk_size = 8u * 1024 * 1024;
static int g_disk_sectsz = 512;
static int g_disk_candelete;
static int g_disk_ro;
static int g_suspend_calls, g_resume_calls;

/* Deferred completion queue. */
struct pend_io {
	struct blockif_req *br;
	struct blockif_ctxt *bc;
	int err;
	bool live;
};
static struct pend_io g_pend[128];

static void
blk_reset(void)
{
	g_open_fail = false;
	g_boot_dev_ret = 0;
	g_submit_err = 0;
	g_complete_err = 0;
	g_disk_size = 8u * 1024 * 1024;
	g_disk_sectsz = 512;
	g_disk_candelete = 0;
	g_disk_ro = 0;
	g_suspend_calls = g_resume_calls = 0;
	memset(g_pend, 0, sizeof(g_pend));
}

static void
blk_enqueue(struct blockif_ctxt *bc, struct blockif_req *br)
{
	size_t i;

	for (i = 0; i < nitems(g_pend); i++) {
		if (!g_pend[i].live) {
			g_pend[i].br = br;
			g_pend[i].bc = bc;
			g_pend[i].err = g_complete_err;
			g_pend[i].live = true;
			return;
		}
	}
	assert(0 && "pend queue full");
}

/* Run all queued completions (as the blockif worker thread would). */
static int
blockif_pump(void)
{
	size_t i;
	int ran;

	ran = 0;
	/* Loop until quiescent: callbacks may enqueue continuations. */
	for (;;) {
		bool progressed = false;

		for (i = 0; i < nitems(g_pend); i++) {
			if (!g_pend[i].live)
				continue;
			struct blockif_req *br = g_pend[i].br;
			int err = g_pend[i].err;

			g_pend[i].live = false;
			br->br_callback(br, err);
			ran++;
			progressed = true;
		}
		if (!progressed)
			break;
	}
	return (ran);
}

static void
blk_do_io(struct blockif_ctxt *bc, struct blockif_req *br, bool write)
{
	off_t off = br->br_offset;
	int i;

	for (i = 0; i < br->br_iovcnt; i++) {
		size_t n = br->br_iov[i].iov_len;

		if (off < 0 || off + (off_t)n > bc->size)
			continue;
		if (write)
			memcpy(bc->disk + off, br->br_iov[i].iov_base, n);
		else
			memcpy(br->br_iov[i].iov_base, bc->disk + off, n);
		off += n;
	}
}

struct blockif_ctxt *
blockif_open(nvlist_t *nvl __unused, const char *ident)
{
	struct blockif_ctxt *bc;

	if (g_open_fail)
		return (NULL);
	bc = calloc(1, sizeof(*bc));
	bc->size = g_disk_size;
	bc->sectsz = g_disk_sectsz;
	bc->candelete = g_disk_candelete;
	bc->ro = g_disk_ro;
	bc->disk = calloc(1, bc->size);
	strlcpy(bc->ident, ident != NULL ? ident : "disk", sizeof(bc->ident));
	return (bc);
}
int
blockif_legacy_config(nvlist_t *nvl, const char *opts)
{
	if (opts == NULL)
		return (0);
	set_config_value_node(nvl, "path", opts);
	return (0);
}
int
blockif_add_boot_device(struct pci_devinst *pi __unused,
    struct blockif_ctxt *bc __unused)
{
	return (g_boot_dev_ret);
}
off_t
blockif_size(struct blockif_ctxt *bc)
{
	return (bc->size);
}
int
blockif_sectsz(struct blockif_ctxt *bc)
{
	return (bc->sectsz);
}
void
blockif_psectsz(struct blockif_ctxt *bc, int *sz, int *off)
{
	*sz = bc->sectsz;
	*off = 0;
}
void
blockif_chs(struct blockif_ctxt *bc, uint16_t *c, uint8_t *h, uint8_t *s)
{
	*c = 1024;
	*h = 16;
	*s = 63;
	(void)bc;
}
int
blockif_queuesz(struct blockif_ctxt *bc __unused)
{
	return (32);
}
int
blockif_is_ro(struct blockif_ctxt *bc)
{
	return (bc->ro);
}
int
blockif_candelete(struct blockif_ctxt *bc)
{
	return (bc->candelete);
}
const char *
blockif_checkpoint_identity(struct blockif_ctxt *bc)
{
	return (bc->ident);
}
int
blockif_read(struct blockif_ctxt *bc, struct blockif_req *br)
{
	if (g_submit_err != 0)
		return (g_submit_err);
	blk_do_io(bc, br, false);
	blk_enqueue(bc, br);
	return (0);
}
int
blockif_write(struct blockif_ctxt *bc, struct blockif_req *br)
{
	if (g_submit_err != 0)
		return (g_submit_err);
	blk_do_io(bc, br, true);
	blk_enqueue(bc, br);
	return (0);
}
int
blockif_flush(struct blockif_ctxt *bc, struct blockif_req *br)
{
	if (g_submit_err != 0)
		return (g_submit_err);
	blk_enqueue(bc, br);
	return (0);
}
int
blockif_delete(struct blockif_ctxt *bc, struct blockif_req *br)
{
	if (g_submit_err != 0)
		return (g_submit_err);
	blk_enqueue(bc, br);
	return (0);
}
int
blockif_cancel(struct blockif_ctxt *bc __unused, struct blockif_req *br)
{
	size_t i;

	for (i = 0; i < nitems(g_pend); i++) {
		if (g_pend[i].live && g_pend[i].br == br) {
			g_pend[i].live = false;
			return (0);	/* cancelled */
		}
	}
	return (EINVAL);
}
int
blockif_close(struct blockif_ctxt *bc)
{
	if (bc != NULL) {
		free(bc->disk);
		free(bc);
	}
	return (0);
}
int
blockif_suspend(struct blockif_ctxt *bc __unused)
{
	g_suspend_calls++;
	return (0);
}
void
blockif_resume(struct blockif_ctxt *bc __unused)
{
	g_resume_calls++;
}

/* ------------------------------------------------------------------ *
 * snapshot codec mock.                                               *
 * ------------------------------------------------------------------ */
#include <machine/vmm_snapshot.h>

void
vm_snapshot_buf_err(const char *n __unused, const enum vm_snapshot_op op
    __unused)
{
}
int
vm_snapshot_buf(void *data, size_t size, struct vm_snapshot_meta *meta)
{
	if (size > meta->buffer.buf_rem)
		return (E2BIG);
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(meta->buffer.buf, data, size);
	else
		memcpy(data, meta->buffer.buf, size);
	meta->buffer.buf += size;
	meta->buffer.buf_rem -= size;
	return (0);
}
int
vm_snapshot_buf_cmp(void *data, size_t size, struct vm_snapshot_meta *meta)
{
	int rc = 0;

	if (size > meta->buffer.buf_rem)
		return (E2BIG);
	if (memcmp(data, meta->buffer.buf, size) != 0)
		rc = EINVAL;
	meta->buffer.buf += size;
	meta->buffer.buf_rem -= size;
	return (rc);
}
int
vm_snapshot_u8(uint8_t *v, struct vm_snapshot_meta *meta)
{
	return (vm_snapshot_buf(v, sizeof(*v), meta));
}
int
vm_snapshot_le16(uint16_t *v, struct vm_snapshot_meta *meta)
{
	return (vm_snapshot_buf(v, sizeof(*v), meta));
}
int
vm_snapshot_le32(uint32_t *v, struct vm_snapshot_meta *meta)
{
	return (vm_snapshot_buf(v, sizeof(*v), meta));
}
int
vm_snapshot_le64(uint64_t *v, struct vm_snapshot_meta *meta)
{
	return (vm_snapshot_buf(v, sizeof(*v), meta));
}
static int
vm_snapshot_nonnegative_int(int *v, struct vm_snapshot_meta *meta)
{
	uint64_t val;
	int err;

	val = (meta->op == VM_SNAPSHOT_SAVE) ? (uint64_t)*v : 0;
	err = vm_snapshot_buf(&val, sizeof(val), meta);
	if (err != 0)
		return (err);
	if (meta->op != VM_SNAPSHOT_SAVE) {
		if (val > (uint64_t)INT_MAX)
			return (EINVAL);
		*v = (int)val;
	}
	return (0);
}
int
vm_snapshot_guest2host_addr(struct vmctx *ctx __unused, void **addr,
    size_t len, bool restore_null, struct vm_snapshot_meta *meta)
{
	uint64_t gpa;
	int err;

	if (meta->op == VM_SNAPSHOT_SAVE)
		gpa = (*addr == NULL) ? 0 :
		    (uint64_t)((uint8_t *)*addr - g_gmem);
	else
		gpa = 0;
	err = vm_snapshot_buf(&gpa, sizeof(gpa), meta);
	if (err != 0)
		return (err);
	if (meta->op != VM_SNAPSHOT_SAVE) {
		if (gpa == 0 && restore_null) {
			*addr = NULL;
		} else {
			if (gpa + len > GMEM_SIZE)
				return (EFAULT);
			*addr = g_gmem + gpa;
		}
	}
	return (0);
}

/* SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE lives only in the real bhyve snapshot.h;
 * the harness mock omits it, so define it here before the DUT is compiled. */
#define	SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(DATA, META, RES, LABEL) do {	\
	(RES) = vm_snapshot_nonnegative_int(&(DATA), (META));		\
	if ((RES) != 0)							\
		goto LABEL;						\
} while (0)

/* ================================================================== *
 *                     Device Under Test                              *
 * ================================================================== */
#include "pci_ahci.c"

/* ------------------------------------------------------------------ *
 * Fixture helpers.                                                    *
 * ------------------------------------------------------------------ */
#define	CLB_GPA		0x010000ull
#define	FB_GPA		0x020000ull
#define	CTBA_GPA	0x030000ull
#define	DATA_GPA	0x100000ull

static struct pci_devinst g_pi;
static int g_dummy_ctx;

static void
env_reset(void)
{
	gmem_reset();
	blk_reset();
	memset(&g_pi, 0, sizeof(g_pi));
	g_pi.pi_vmctx = (struct vmctx *)&g_dummy_ctx;
	g_pi.pi_slot = 3;
	g_pi.pi_func = 0;
	g_msi_maxmsg = 0;
	g_msicap_msgnum = 0;
	g_lintr_asserts = g_lintr_deasserts = g_lintr_requests = 0;
	g_msi_generated = 0;
	g_last_msi_index = 0;
	g_barcount = 0;
}

/*
 * Build a root nvlist describing 'nhd' ATA disks then 'ncd' ATAPI drives on
 * consecutive ports, and initialize a controller from it.
 */
static struct pci_ahci_softc *
ctrl_init(int nhd, int ncd)
{
	struct nvlist *root;
	nvlist_t *ports, *pn;
	char name[4];
	int p, rc;

	root = calloc(1, sizeof(*root));
	ports = create_relative_config_node((nvlist_t *)root, "port");
	for (p = 0; p < nhd + ncd; p++) {
		snprintf(name, sizeof(name), "%d", p);
		pn = create_relative_config_node(ports, name);
		set_config_value_node(pn, "type", p < nhd ? "hd" : "cd");
		set_config_value_node(pn, "path", "/dev/null");
	}
	rc = pci_ahci_init(&g_pi, (nvlist_t *)root);
	ATF_REQUIRE_EQ(0, rc);
	return (g_pi.pi_arg);
}

static void
pw(struct pci_ahci_softc *sc, int port, uint64_t reg, uint32_t val)
{
	pci_ahci_write(sc->asc_pi, 5, AHCI_OFFSET + port * AHCI_STEP + reg, 4,
	    val);
}

static uint32_t
pr_reg(struct pci_ahci_softc *sc, int port, uint64_t reg)
{
	return ((uint32_t)pci_ahci_read(sc->asc_pi, 5,
	    AHCI_OFFSET + port * AHCI_STEP + reg, 4));
}

/* Bring a port online: program CLB/FB and set ST|FRE so the command list
 * and received-FIS area are mapped into guest memory. */
static void
port_online(struct pci_ahci_softc *sc, int port)
{
	pw(sc, port, AHCI_P_CLB, CLB_GPA & 0xffffffff);
	pw(sc, port, AHCI_P_CLBU, CLB_GPA >> 32);
	pw(sc, port, AHCI_P_FB, FB_GPA & 0xffffffff);
	pw(sc, port, AHCI_P_FBU, FB_GPA >> 32);
	/* Enable receive-FIS and start the engine. */
	pw(sc, port, AHCI_P_IE, 0xFDC000FF);
	pw(sc, port, AHCI_P_CMD, AHCI_P_CMD_FRE | AHCI_P_CMD_ST);
}

static struct ahci_cmd_hdr *
slot_hdr(struct pci_ahci_softc *sc, int port, int slot)
{
	return ((struct ahci_cmd_hdr *)(sc->port[port].cmd_lst +
	    slot * AHCI_CL_SIZE));
}

/* Populate one command slot: command table at CTBA_GPA, cfis body zeroed. */
static uint8_t *
cmd_setup(struct pci_ahci_softc *sc, int port, int slot, int prdtl)
{
	struct ahci_cmd_hdr *hdr = slot_hdr(sc, port, slot);
	uint8_t *cfis = g_gmem + CTBA_GPA;

	memset(cfis, 0, 0x80 + prdtl * sizeof(struct ahci_prdt_entry));
	hdr->flags = 5;			/* cfis length in dwords (unused) */
	hdr->prdtl = prdtl;
	hdr->prdbc = 0;
	hdr->ctba = CTBA_GPA;
	cfis[0] = O_FIS_H2D;
	cfis[1] = 0x80;			/* C bit: command */
	return (cfis);
}

static struct ahci_prdt_entry *
cmd_prdt(uint8_t *cfis)
{
	return ((struct ahci_prdt_entry *)(cfis + 0x80));
}

static void
prdt_set(struct ahci_prdt_entry *prdt, int i, uint64_t dba, uint32_t bytes)
{
	prdt[i].dba = dba;
	prdt[i].reserved = 0;
	prdt[i].dbc = (bytes - 1) & DBCMASK;
}

/*
 * Issue command(s) in the given slot mask and run completions.  Before each
 * command batch, model the guest's interrupt service + error recovery: clear
 * the port interrupt status and release the task-file-error latch so that an
 * earlier aborted command does not wedge dispatch (ahci_write_fis() raises
 * p->waitforclear on any errored FIS).
 */
static void
issue(struct pci_ahci_softc *sc, int port, uint32_t slotmask)
{
	pw(sc, port, AHCI_P_IS, 0xffffffff);
	sc->port[port].waitforclear = 0;
	pw(sc, port, AHCI_P_CI, slotmask);
	blockif_pump();
}

static uint8_t *
rfis_d2h(struct pci_ahci_softc *sc, int port)
{
	return (sc->port[port].rfis + O_RFIS_D2H_OFF);
}
static uint8_t *
rfis_sdb(struct pci_ahci_softc *sc, int port)
{
	return (sc->port[port].rfis + O_RFIS_SDB_OFF);
}

/* ================================================================== *
 *                            Test cases                              *
 * ================================================================== */

ATF_TC_WITHOUT_HEAD(init_and_config_space);
ATF_TC_BODY(init_and_config_space, tc)
{
	struct pci_ahci_softc *sc;
	uint32_t cap;

	env_reset();
	sc = ctrl_init(1, 0);

	/* At least DEF_PORTS (6) implemented ports; port 0 present in PI. */
	ATF_CHECK(sc->ports >= 6);
	ATF_CHECK_EQ(1u, sc->pi & 1u);

	/* AHCI 1.3 version register. */
	ATF_CHECK_EQ(0x10300u, sc->vs);

	/* CAP: 64-bit addressing + staggered spin-up + NCQ advertised. */
	cap = pr_reg(sc, 0, 0) ;	/* not a port reg; use host read below */
	(void)cap;
	cap = (uint32_t)pci_ahci_read(sc->asc_pi, 5, AHCI_CAP, 4);
	ATF_CHECK((cap & AHCI_CAP_64BIT) != 0);
	ATF_CHECK((cap & AHCI_CAP_SNCQ) != 0);
	ATF_CHECK((cap & AHCI_CAP_SSS) != 0);
	/* NP field (bits 4:0) == ports-1. */
	ATF_CHECK_EQ((uint32_t)(sc->ports - 1), cap & AHCI_CAP_NPMASK);

	/* PCI identity: Intel 82801 AHCI, storage/SATA/AHCI class. */
	ATF_CHECK_EQ(0x8086, le16dec(&g_pi.pi_cfgdata[PCIR_VENDOR]));
	ATF_CHECK_EQ(0x2821, le16dec(&g_pi.pi_cfgdata[PCIR_DEVICE]));
	ATF_CHECK_EQ(PCIC_STORAGE, g_pi.pi_cfgdata[PCIR_CLASS]);
	ATF_CHECK_EQ(PCIS_STORAGE_SATA, g_pi.pi_cfgdata[PCIR_SUBCLASS]);
	ATF_CHECK_EQ(PCIP_STORAGE_SATA_AHCI_1_0, g_pi.pi_cfgdata[PCIR_PROGIF]);

	/* ABAR (BAR5) allocated, MSI capability + legacy INTx wired. */
	ATF_CHECK_EQ(PCIBAR_MEM32, g_pi.pi_bar[5].type);
	ATF_CHECK(g_pi.pi_bar[5].size >= AHCI_OFFSET + sc->ports * AHCI_STEP);
	ATF_CHECK(g_msicap_msgnum > 0);
	ATF_CHECK_EQ(1, g_lintr_requests);
}

ATF_TC_WITHOUT_HEAD(init_open_and_boot_failures);
ATF_TC_BODY(init_open_and_boot_failures, tc)
{
	struct nvlist *root;
	nvlist_t *ports, *pn;
	int rc;

	/* blockif_open failure -> pci_ahci_init returns 1. */
	env_reset();
	g_open_fail = true;
	root = calloc(1, sizeof(*root));
	ports = create_relative_config_node((nvlist_t *)root, "port");
	pn = create_relative_config_node(ports, "0");
	set_config_value_node(pn, "type", "hd");
	set_config_value_node(pn, "path", "/dev/null");
	rc = pci_ahci_init(&g_pi, (nvlist_t *)root);
	ATF_CHECK_EQ(1, rc);

	/* boot-device registration failure -> init returns nonzero. */
	env_reset();
	g_boot_dev_ret = ENXIO;
	root = calloc(1, sizeof(*root));
	ports = create_relative_config_node((nvlist_t *)root, "port");
	pn = create_relative_config_node(ports, "0");
	set_config_value_node(pn, "type", "hd");
	set_config_value_node(pn, "path", "/dev/null");
	rc = pci_ahci_init(&g_pi, (nvlist_t *)root);
	ATF_CHECK(rc != 0);

	/* No "port" node at all: init still succeeds with default ports. */
	env_reset();
	root = calloc(1, sizeof(*root));
	rc = pci_ahci_init(&g_pi, (nvlist_t *)root);
	ATF_CHECK_EQ(0, rc);
	ATF_CHECK_EQ(DEF_PORTS,
	    ((struct pci_ahci_softc *)g_pi.pi_arg)->ports);
}

ATF_TC_WITHOUT_HEAD(legacy_config_parsing);
ATF_TC_BODY(legacy_config_parsing, tc)
{
	struct nvlist *root;
	nvlist_t *ports, *p0, *p2;

	env_reset();

	/* Combined "hd:...,cd:..." string builds per-port type/path nodes. */
	root = calloc(1, sizeof(*root));
	ATF_CHECK_EQ(0, pci_ahci_legacy_config((nvlist_t *)root,
	    "hd:/tmp/a,cd:/tmp/b"));
	ports = find_relative_config_node((nvlist_t *)root, "port");
	ATF_REQUIRE(ports != NULL);
	p0 = find_relative_config_node(ports, "0");
	ATF_REQUIRE(p0 != NULL);
	ATF_CHECK_STREQ("hd", get_config_value_node(p0, "type"));
	ATF_CHECK_STREQ("/tmp/a", get_config_value_node(p0, "path"));
	p2 = find_relative_config_node(ports, "1");
	ATF_REQUIRE(p2 != NULL);
	ATF_CHECK_STREQ("cd", get_config_value_node(p2, "type"));
	ATF_CHECK_STREQ("/tmp/b", get_config_value_node(p2, "path"));

	/* Missing type prefix is rejected. */
	root = calloc(1, sizeof(*root));
	ATF_CHECK(pci_ahci_legacy_config((nvlist_t *)root, "/tmp/x") != 0);

	/* NULL opts is a no-op success. */
	root = calloc(1, sizeof(*root));
	ATF_CHECK_EQ(0, pci_ahci_legacy_config((nvlist_t *)root, NULL));

	/* hd/cd single-drive helpers build a port 0 node. */
	root = calloc(1, sizeof(*root));
	ATF_CHECK_EQ(0, pci_ahci_hd_legacy_config((nvlist_t *)root, "/tmp/hd"));
	ports = find_relative_config_node((nvlist_t *)root, "port");
	p0 = find_relative_config_node(ports, "0");
	ATF_CHECK_STREQ("hd", get_config_value_node(p0, "type"));

	root = calloc(1, sizeof(*root));
	ATF_CHECK_EQ(0, pci_ahci_cd_legacy_config((nvlist_t *)root, "/tmp/cd"));
	ports = find_relative_config_node((nvlist_t *)root, "port");
	p0 = find_relative_config_node(ports, "0");
	ATF_CHECK_STREQ("cd", get_config_value_node(p0, "type"));
}

ATF_TC_WITHOUT_HEAD(host_registers);
ATF_TC_BODY(host_registers, tc)
{
	struct pci_ahci_softc *sc;

	env_reset();
	sc = ctrl_init(1, 0);

	/* PI reflects present ports; VS is the AHCI version. */
	ATF_CHECK_EQ(sc->pi,
	    (uint32_t)pci_ahci_read(sc->asc_pi, 5, AHCI_PI, 4));
	ATF_CHECK_EQ(0x10300u,
	    (uint32_t)pci_ahci_read(sc->asc_pi, 5, AHCI_VS, 4));

	/* GHC.IE toggles the global interrupt-enable bit. */
	pci_ahci_write(sc->asc_pi, 5, AHCI_GHC, 4, AHCI_GHC_IE);
	ATF_CHECK((pci_ahci_read(sc->asc_pi, 5, AHCI_GHC, 4) & AHCI_GHC_IE)
	    != 0);
	pci_ahci_write(sc->asc_pi, 5, AHCI_GHC, 4, 0);
	ATF_CHECK((pci_ahci_read(sc->asc_pi, 5, AHCI_GHC, 4) & AHCI_GHC_IE)
	    == 0);

	/* CAP/PI/VS are read-only: writes are ignored. */
	pci_ahci_write(sc->asc_pi, 5, AHCI_CAP, 4, 0);
	ATF_CHECK((pci_ahci_read(sc->asc_pi, 5, AHCI_CAP, 4) & AHCI_CAP_64BIT)
	    != 0);
	pci_ahci_write(sc->asc_pi, 5, AHCI_PI, 4, 0xdeadbeef);
	ATF_CHECK_EQ(sc->pi,
	    (uint32_t)pci_ahci_read(sc->asc_pi, 5, AHCI_PI, 4));

	/* HBA reset (GHC.HR) returns to the AE-enabled idle state. */
	sc->is = 0x3;
	pci_ahci_write(sc->asc_pi, 5, AHCI_GHC, 4, AHCI_GHC_HR);
	ATF_CHECK((sc->ghc & AHCI_GHC_AE) != 0);
	ATF_CHECK_EQ(0u, sc->is);

	/* Unknown/high host offset read returns 0 (default arm). */
	ATF_CHECK_EQ(0u, (uint32_t)pci_ahci_read(sc->asc_pi, 5, 0x40, 4));

	/* Sub-dword read shifts the register right by the byte offset (the
	 * outer MMIO layer masks to the access size). */
	{
		uint32_t vs_b1 = (uint32_t)pci_ahci_read(sc->asc_pi, 5,
		    AHCI_VS + 1, 1);
		ATF_CHECK_EQ((0x10300u >> 8) & 0xff, vs_b1 & 0xff);
	}

	/* Misaligned/oversize accesses are rejected by the MMIO gate. */
	ATF_CHECK_EQ(UINT64_MAX, pci_ahci_read(sc->asc_pi, 5, 1, 4));
	ATF_CHECK_EQ(UINT64_MAX, pci_ahci_read(sc->asc_pi, 4, 0, 4));
}

ATF_TC_WITHOUT_HEAD(port_registers);
ATF_TC_BODY(port_registers, tc)
{
	struct pci_ahci_softc *sc;

	env_reset();
	sc = ctrl_init(1, 0);

	/* CLB/CLBU/FB/FBU are plain read/write pointer registers. */
	pw(sc, 0, AHCI_P_CLB, 0x1000);
	pw(sc, 0, AHCI_P_CLBU, 0x2);
	pw(sc, 0, AHCI_P_FB, 0x3000);
	pw(sc, 0, AHCI_P_FBU, 0x4);
	ATF_CHECK_EQ(0x1000u, pr_reg(sc, 0, AHCI_P_CLB));
	ATF_CHECK_EQ(0x2u, pr_reg(sc, 0, AHCI_P_CLBU));
	ATF_CHECK_EQ(0x3000u, pr_reg(sc, 0, AHCI_P_FB));
	ATF_CHECK_EQ(0x4u, pr_reg(sc, 0, AHCI_P_FBU));

	/* PxIE keeps only the writable interrupt-enable bits. */
	pw(sc, 0, AHCI_P_IE, 0xffffffff);
	ATF_CHECK_EQ(0xFDC000FFu, pr_reg(sc, 0, AHCI_P_IE));

	/* PxSERR is write-one-to-clear. */
	sc->port[0].serr = 0xf0f0;
	pw(sc, 0, AHCI_P_SERR, 0x00f0);
	ATF_CHECK_EQ(0xf000u, pr_reg(sc, 0, AHCI_P_SERR));

	/* PxSACT is set (OR) by writes; cleared by NCQ completion. */
	pw(sc, 0, AHCI_P_SACT, 0x5);
	pw(sc, 0, AHCI_P_SACT, 0x2);
	ATF_CHECK_EQ(0x7u, pr_reg(sc, 0, AHCI_P_SACT));

	/* PxTFD/PxSIG/PxSSTS are read-only: writes ignored. */
	{
		uint32_t tfd = pr_reg(sc, 0, AHCI_P_TFD);
		pw(sc, 0, AHCI_P_TFD, 0xdead);
		ATF_CHECK_EQ(tfd, pr_reg(sc, 0, AHCI_P_TFD));
	}
	/* A present ATA device signals the ATA signature and ready TFD. */
	ATF_CHECK_EQ(0x00000101u, pr_reg(sc, 0, AHCI_P_SIG));
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_SSTS) & ATA_SS_DET_PHY_ONLINE) != 0);

	/* PxSNTF/PxFBS default arm: readable, no side effects on write. */
	pw(sc, 0, AHCI_P_SNTF, 0x1);
	pw(sc, 0, AHCI_P_FBS, 0x1);

	/* Reading an out-of-range port offset falls to the default (0). */
	ATF_CHECK_EQ(0u, pci_ahci_port_read(sc, AHCI_OFFSET + 0x44));
}

ATF_TC_WITHOUT_HEAD(read_dma_transfers_data);
ATF_TC_BODY(read_dma_transfers_data, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis, *d2h;
	struct ahci_prdt_entry *prdt;
	struct ahci_cmd_hdr *hdr;
	int i;

	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);

	/* Seed the disk (LBA 0) with a recognizable pattern. */
	for (i = 0; i < 512; i++)
		sc->port[0].bctx->disk[i] = (uint8_t)(i ^ 0xA5);

	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_READ_DMA48;
	cfis[12] = 1;			/* 1 sector */
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);

	issue(sc, 0, 1u << 0);

	/* Data landed in guest memory. */
	for (i = 0; i < 512; i++)
		ATF_CHECK_EQ((uint8_t)(i ^ 0xA5), g_gmem[DATA_GPA + i]);

	/* D2H FIS posts ready|DSC with no error; PxCI slot cleared. */
	d2h = rfis_d2h(sc, 0);
	ATF_CHECK_EQ(O_FIS_D2H, d2h[0]);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, d2h[2]);
	ATF_CHECK_EQ(0u, pr_reg(sc, 0, AHCI_P_CI) & 1u);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_IS) & O_PxIS_DHR) != 0);

	/* prdbc reflects the full transfer. */
	hdr = slot_hdr(sc, 0, 0);
	ATF_CHECK_EQ(512u, hdr->prdbc);
}

ATF_TC_WITHOUT_HEAD(write_dma_transfers_data);
ATF_TC_BODY(write_dma_transfers_data, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis;
	struct ahci_prdt_entry *prdt;
	int i;

	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);

	for (i = 0; i < 512; i++)
		g_gmem[DATA_GPA + i] = (uint8_t)(i + 7);

	cfis = cmd_setup(sc, 0, 1, 1);
	cfis[2] = ATA_WRITE_DMA48;
	cfis[12] = 1;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);

	issue(sc, 0, 1u << 1);

	for (i = 0; i < 512; i++)
		ATF_CHECK_EQ((uint8_t)(i + 7), sc->port[0].bctx->disk[i]);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);
}

ATF_TC_WITHOUT_HEAD(read_dma_eio_is_taskfile_error);
ATF_TC_BODY(read_dma_eio_is_taskfile_error, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis, *d2h;
	struct ahci_prdt_entry *prdt;

	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);
	g_complete_err = EIO;		/* backend fails the transfer */

	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_READ_DMA48;
	cfis[12] = 1;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);

	issue(sc, 0, 1u << 0);

	/* EIO becomes a per-command task-file error (ERR set, ABORT). */
	d2h = rfis_d2h(sc, 0);
	ATF_CHECK((d2h[2] & O_ATA_S_ERR) != 0);
	ATF_CHECK_EQ(O_ATA_E_ABRT, d2h[3]);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_IS) & O_PxIS_TFES) != 0);
	/* Must NOT escalate to a fatal host-bus error. */
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_IS) & O_PxIS_HBFS) == 0);
}

ATF_TC_WITHOUT_HEAD(read_submit_ebusy_aborts_command);
ATF_TC_BODY(read_submit_ebusy_aborts_command, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis;
	struct ahci_prdt_entry *prdt;

	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);
	g_submit_err = EBUSY;		/* quiesce fence refuses submission */

	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_READ_DMA48;
	cfis[12] = 1;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);

	issue(sc, 0, 1u << 0);

	/* Command is failed back (TFES), bhyve does not abort. */
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_IS) & O_PxIS_TFES) != 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);
}

ATF_TC_WITHOUT_HEAD(read_unmappable_prd_aborts);
ATF_TC_BODY(read_unmappable_prd_aborts, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis;
	struct ahci_prdt_entry *prdt;

	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);
	g_map_dma_fail = true;		/* PRD data base cannot be mapped */

	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_READ_DMA48;
	cfis[12] = 1;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);

	issue(sc, 0, 1u << 0);

	/* build_iov failure -> command abort (task-file error), not HBFS. */
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_IS) & O_PxIS_TFES) != 0);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_IS) & O_PxIS_HBFS) == 0);
}

ATF_TC_WITHOUT_HEAD(read_prd_wrap_aborts);
ATF_TC_BODY(read_prd_wrap_aborts, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis;
	struct ahci_prdt_entry *prdt;

	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);

	/* A PRD whose data base lies wholly outside guest RAM cannot be
	 * mapped; build_iov fails and the command is aborted. */
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_READ_DMA48;
	cfis[12] = 2;			/* 2 sectors */
	prdt = cmd_prdt(cfis);
	prdt[0].dba = (uint64_t)GMEM_SIZE + 0x1000;	/* out of range */
	prdt[0].reserved = 0;
	prdt[0].dbc = (1024 - 1) & DBCMASK;

	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_IS) & O_PxIS_TFES) != 0);
}

ATF_TC_WITHOUT_HEAD(flush_cache);
ATF_TC_BODY(flush_cache, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis;

	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);

	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[2] = ATA_FLUSHCACHE;
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* Flush that the backend refuses -> task-file error. */
	g_complete_err = EIO;
	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[2] = ATA_FLUSHCACHE;
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);
}

ATF_TC_WITHOUT_HEAD(identify_ata);
ATF_TC_BODY(identify_ata, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis, *pio;
	struct ahci_prdt_entry *prdt;
	struct ata_params *id;

	env_reset();
	g_disk_candelete = 1;		/* advertise TRIM in IDENTIFY */
	sc = ctrl_init(1, 0);
	port_online(sc, 0);

	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_ATA_IDENTIFY;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);

	/* A PIO setup FIS precedes the data; D2H completes ready|DSC. */
	pio = sc->port[0].rfis + O_RFIS_PIO_OFF;
	ATF_CHECK_EQ(O_FIS_PIOSETUP, pio[0]);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* IDENTIFY data: LBA + DMA support, 48-bit and DSM/TRIM advertised. */
	id = (struct ata_params *)(g_gmem + DATA_GPA);
	ATF_CHECK((id->capabilities1 & ATA_SUPPORT_LBA) != 0);
	ATF_CHECK((id->support.command2 & ATA_SUPPORT_ADDRESS48) != 0);
	ATF_CHECK_EQ(ATA_SUPPORT_DSM_TRIM, id->support_dsm);

	/* IDENTIFY with prdtl==0 is aborted (no buffer). */
	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[2] = ATA_ATA_IDENTIFY;
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);

	/* ATAPI IDENTIFY on an ATA device is aborted. */
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_ATAPI_IDENTIFY;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);
}

ATF_TC_WITHOUT_HEAD(identify_write_prdt_hbfs);
ATF_TC_BODY(identify_write_prdt_hbfs, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis;
	struct ahci_prdt_entry *prdt;

	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);
	g_map_dma_fail = true;		/* write_prdt cannot map the PRD */

	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_ATA_IDENTIFY;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);

	/* Unmappable PRD in write_prdt is a fatal host-bus error and stops
	 * the command engine (regression fix: HBFS, not HBDS). */
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_IS) & O_PxIS_HBFS) != 0);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_IS) & O_PxIS_HBDS) == 0);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_CMD) & AHCI_P_CMD_ST) == 0);
}

ATF_TC_WITHOUT_HEAD(setfeatures_and_misc_ata);
ATF_TC_BODY(setfeatures_and_misc_ata, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis;

	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);

	/* SET FEATURES / SET XFER DMA mode: accepted. */
	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[2] = ATA_SETFEATURES;
	cfis[3] = ATA_SF_SETXFER;
	cfis[12] = ATA_UDMA0 | 5;
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);
	ATF_CHECK_EQ(5, sc->port[0].xfermode);

	/* SET FEATURES with an unknown subcommand: aborted. */
	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[2] = ATA_SETFEATURES;
	cfis[3] = 0xfe;
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);

	/* SET MULTIPLE with valid power-of-two count. */
	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[2] = ATA_SET_MULTI;
	cfis[12] = 16;
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(16, sc->port[0].mult_sectors);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* SET MULTIPLE with an invalid (non power-of-two) count: aborted. */
	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[2] = ATA_SET_MULTI;
	cfis[12] = 3;
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);

	/* CHECK POWER MODE reports "always on". */
	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[2] = ATA_CHECK_POWER_MODE;
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(0xff, (g_gmem + CTBA_GPA)[12]);

	/* STANDBY IMMEDIATE and friends: succeed silently. */
	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[2] = ATA_STANDBY_IMMEDIATE;
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* SMART / freeze-lock / NOP: aborted (unsupported). */
	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[2] = ATA_SMART_CMD;
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);

	/* Wholly unknown opcode: aborted. */
	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[2] = 0xfd;
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);
}

ATF_TC_WITHOUT_HEAD(read_log_ext);
ATF_TC_BODY(read_log_ext, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis;
	struct ahci_prdt_entry *prdt;
	uint16_t *log;

	env_reset();
	g_disk_candelete = 1;
	sc = ctrl_init(1, 0);
	port_online(sc, 0);

	/* Log directory (page 0). */
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_READ_LOG_EXT;
	cfis[4] = 0x00;
	cfis[12] = 1;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);
	log = (uint16_t *)(g_gmem + DATA_GPA);
	ATF_CHECK_EQ(1, log[0]);	/* version */
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* NCQ command error log (page 0x10). */
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_READ_LOG_EXT;
	cfis[4] = 0x10;
	cfis[12] = 1;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);

	/* SATA NCQ send/receive log (page 0x13) advertises DSM TRIM. */
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_READ_LOG_EXT;
	cfis[4] = 0x13;
	cfis[12] = 1;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(1u, ((uint32_t *)(g_gmem + DATA_GPA))[0]);

	/* Unsupported page is aborted. */
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_READ_LOG_EXT;
	cfis[4] = 0x99;
	cfis[12] = 1;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);

	/* Malformed request (prdtl==0) is aborted. */
	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[2] = ATA_READ_LOG_EXT;
	cfis[4] = 0x00;
	cfis[12] = 1;
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);
}

ATF_TC_WITHOUT_HEAD(dsm_trim);
ATF_TC_BODY(dsm_trim, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis, *buf;
	struct ahci_prdt_entry *prdt;

	env_reset();
	g_disk_candelete = 1;
	sc = ctrl_init(1, 0);
	port_online(sc, 0);

	/* One TRIM range (LBA 8, 4 sectors) then padding zeros. */
	buf = g_gmem + DATA_GPA;
	memset(buf, 0, 512);
	buf[0] = 8;			/* LBA low */
	buf[6] = 4;			/* range length (sectors) */

	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_DATA_SET_MANAGEMENT;
	cfis[3] = ATA_DSM_TRIM;
	cfis[11] = 0;
	cfis[12] = 1;			/* one 512-byte block of ranges */
	cfis[13] = 0;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);

	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);
	ATF_CHECK_EQ(0u, pr_reg(sc, 0, AHCI_P_CI) & 1u);

	/* Oversized DSM (more than one block) is rejected. */
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_DATA_SET_MANAGEMENT;
	cfis[3] = ATA_DSM_TRIM;
	cfis[12] = 2;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);

	/* DSM with an unsupported feature combination is aborted early. */
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_DATA_SET_MANAGEMENT;
	cfis[3] = 0;			/* not TRIM */
	cfis[12] = 1;
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);
}

ATF_TC_WITHOUT_HEAD(ncq_read_write);
ATF_TC_BODY(ncq_read_write, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis, *sdb;
	struct ahci_prdt_entry *prdt;
	int i;

	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);

	for (i = 0; i < 512; i++)
		sc->port[0].bctx->disk[i] = (uint8_t)(0x33 + i);

	/* FPDMA READ QUEUED in slot 2. */
	cfis = cmd_setup(sc, 0, 2, 1);
	cfis[2] = ATA_READ_FPDMA_QUEUED;
	cfis[3] = 1;			/* count low = 1 sector */
	cfis[11] = 0;			/* count high */
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);

	pw(sc, 0, AHCI_P_SACT, 1u << 2);
	issue(sc, 0, 1u << 2);

	for (i = 0; i < 512; i++)
		ATF_CHECK_EQ((uint8_t)(0x33 + i), g_gmem[DATA_GPA + i]);

	/* NCQ completion posts a Set-Device-Bits FIS and clears PxSACT. */
	sdb = rfis_sdb(sc, 0);
	ATF_CHECK_EQ(O_FIS_SETDEVBITS, sdb[0]);
	ATF_CHECK_EQ(0u, pr_reg(sc, 0, AHCI_P_SACT) & (1u << 2));
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_IS) & O_PxIS_SDB) != 0);

	/* FPDMA WRITE QUEUED failing at the backend -> SDB carries error. */
	g_complete_err = EIO;
	for (i = 0; i < 512; i++)
		g_gmem[DATA_GPA + i] = (uint8_t)i;
	cfis = cmd_setup(sc, 0, 3, 1);
	cfis[2] = ATA_WRITE_FPDMA_QUEUED;
	cfis[3] = 1;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	pw(sc, 0, AHCI_P_SACT, 1u << 3);
	issue(sc, 0, 1u << 3);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_IS) & O_PxIS_TFES) != 0);
}

ATF_TC_WITHOUT_HEAD(ncq_send_trim);
ATF_TC_BODY(ncq_send_trim, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis, *buf;
	struct ahci_prdt_entry *prdt;

	env_reset();
	g_disk_candelete = 1;
	sc = ctrl_init(1, 0);
	port_online(sc, 0);

	buf = g_gmem + DATA_GPA;
	memset(buf, 0, 512);
	buf[0] = 16;
	buf[6] = 8;			/* range length */

	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_SEND_FPDMA_QUEUED;
	cfis[13] = ATA_SFPDMA_DSM;	/* subcommand */
	cfis[17] = 0;
	cfis[16] = ATA_DSM_TRIM;
	cfis[11] = 0;
	cfis[3] = 1;			/* one block */
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	pw(sc, 0, AHCI_P_SACT, 1u << 0);
	issue(sc, 0, 1u << 0);

	ATF_CHECK_EQ(O_FIS_SETDEVBITS, rfis_sdb(sc, 0)[0]);
	ATF_CHECK_EQ(0u, pr_reg(sc, 0, AHCI_P_SACT) & 1u);

	/* SEND FPDMA with a bad subcommand is aborted. */
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_SEND_FPDMA_QUEUED;
	cfis[13] = 0x1f;		/* not DSM */
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);
}

ATF_TC_WITHOUT_HEAD(split_transfer_iov_cap);
ATF_TC_BODY(split_transfer_iov_cap, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis;
	struct ahci_prdt_entry *prdt;
	struct ahci_cmd_hdr *hdr;
	int i, prdtl;
	uint32_t total;

	env_reset();
	g_disk_size = 4u * 1024 * 1024;
	sc = ctrl_init(1, 0);
	port_online(sc, 0);

	/* 200 single-sector PRDT entries: the first build_iov pass caps at
	 * BLOCKIF_IOV_MAX (128) descriptors and reports 'more'; the read
	 * completion resubmits the tail. */
	prdtl = 200;
	total = (uint32_t)prdtl;	/* sectors */
	cfis = cmd_setup(sc, 0, 0, prdtl);
	cfis[2] = ATA_READ_DMA48;
	cfis[12] = total & 0xff;
	cfis[13] = (total >> 8) & 0xff;
	prdt = cmd_prdt(cfis);
	for (i = 0; i < prdtl; i++)
		prdt_set(prdt, i, DATA_GPA + (uint64_t)i * 512, 512);

	issue(sc, 0, 1u << 0);

	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);
	hdr = slot_hdr(sc, 0, 0);
	ATF_CHECK_EQ(total * 512u, hdr->prdbc);
}

ATF_TC_WITHOUT_HEAD(non_command_fis_and_reset);
ATF_TC_BODY(non_command_fis_and_reset, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis;

	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);

	/* A control (non-command) H2D FIS asserting SRST sets reset-pending;
	 * a following FIS with SRST cleared performs the COMRESET. */
	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[1] = 0;			/* C bit clear: control FIS */
	cfis[15] = (1 << 2);		/* SRST asserted */
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(1, sc->port[0].reset);
	ATF_CHECK_EQ(0u, pr_reg(sc, 0, AHCI_P_CI) & 1u);

	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[1] = 0;
	cfis[15] = 0;			/* SRST deasserted -> reset now */
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(0, sc->port[0].reset);
	/* After COMRESET the device re-signals the ATA signature. */
	ATF_CHECK_EQ(0x00000101u, pr_reg(sc, 0, AHCI_P_SIG));
}

ATF_TC_WITHOUT_HEAD(unmappable_cmd_list_and_table);
ATF_TC_BODY(unmappable_cmd_list_and_table, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis;

	/* Unmappable command list on PxCMD.ST: HBFS + ST/CR cleared. */
	env_reset();
	sc = ctrl_init(1, 0);
	pw(sc, 0, AHCI_P_CLB, CLB_GPA & 0xffffffff);
	pw(sc, 0, AHCI_P_CLBU, CLB_GPA >> 32);
	pw(sc, 0, AHCI_P_FB, FB_GPA & 0xffffffff);
	pw(sc, 0, AHCI_P_FBU, FB_GPA >> 32);
	g_paddr_fail_en = true;
	g_paddr_fail_gpa = CLB_GPA;
	pw(sc, 0, AHCI_P_CMD, AHCI_P_CMD_FRE | AHCI_P_CMD_ST);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_IS) & O_PxIS_HBFS) != 0);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_CMD) & AHCI_P_CMD_ST) == 0);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_CMD) & AHCI_P_CMD_CR) == 0);

	/* Unmappable received-FIS area on PxCMD.FRE: HBFS + FR cleared. */
	env_reset();
	sc = ctrl_init(1, 0);
	pw(sc, 0, AHCI_P_CLB, CLB_GPA & 0xffffffff);
	pw(sc, 0, AHCI_P_CLBU, CLB_GPA >> 32);
	pw(sc, 0, AHCI_P_FB, FB_GPA & 0xffffffff);
	pw(sc, 0, AHCI_P_FBU, FB_GPA >> 32);
	g_paddr_fail_en = true;
	g_paddr_fail_gpa = FB_GPA;
	pw(sc, 0, AHCI_P_CMD, AHCI_P_CMD_FRE);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_IS) & O_PxIS_HBFS) != 0);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_CMD) & AHCI_P_CMD_FR) == 0);

	/* Unmappable command table (ctba) when a slot runs: HBFS + stop. */
	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_READ_DMA48;
	cfis[12] = 1;
	prdt_set(cmd_prdt(cfis), 0, DATA_GPA, 512);
	g_paddr_fail_en = true;
	g_paddr_fail_gpa = CTBA_GPA;
	issue(sc, 0, 1u << 0);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_IS) & O_PxIS_HBFS) != 0);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_CMD) & AHCI_P_CMD_ST) == 0);
}

ATF_TC_WITHOUT_HEAD(port_stop_cancels_inflight);
ATF_TC_BODY(port_stop_cancels_inflight, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis;
	struct ahci_prdt_entry *prdt;

	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);

	/* Submit a read but do NOT pump: it stays in-flight. */
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_READ_DMA48;
	cfis[12] = 1;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	pw(sc, 0, AHCI_P_CI, 1u << 0);
	ATF_CHECK(sc->port[0].pending != 0);

	/* Clearing PxCMD.ST cancels the outstanding request and clears the
	 * running/CI/SACT state once nothing is pending. */
	pw(sc, 0, AHCI_P_CMD, 0);
	ATF_CHECK_EQ(0u, pr_reg(sc, 0, AHCI_P_CI));
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_CMD) & AHCI_P_CMD_CR) == 0);
	ATF_CHECK_EQ(0u, sc->port[0].pending);
}

ATF_TC_WITHOUT_HEAD(sctl_comreset_and_no_device);
ATF_TC_BODY(sctl_comreset_and_no_device, tc)
{
	struct pci_ahci_softc *sc;

	env_reset();
	sc = ctrl_init(1, 0);

	/* With the engine stopped, writing PxSCTL.DET=RESET triggers a port
	 * reset that re-establishes PHY-online + ATA signature. */
	pw(sc, 0, AHCI_P_SCTL, ATA_SC_DET_RESET);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_SSTS) & ATA_SS_DET_PHY_ONLINE) != 0);
	ATF_CHECK_EQ(0x00000101u, pr_reg(sc, 0, AHCI_P_SIG));

	/* An empty port (index beyond the configured drive) reports no
	 * device present and the "no device" signature after reset. */
	ahci_port_reset(&sc->port[5]);
	ATF_CHECK_EQ(ATA_SS_DET_NO_DEVICE, pr_reg(sc, 5, AHCI_P_SSTS));
	ATF_CHECK_EQ(0xFFFFFFFFu, pr_reg(sc, 5, AHCI_P_SIG));
}

ATF_TC_WITHOUT_HEAD(interrupt_msi_and_legacy);
ATF_TC_BODY(interrupt_msi_and_legacy, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis;
	struct ahci_prdt_entry *prdt;

	/* MSI path: a completed command generates an MSI, not a legacy INTx. */
	env_reset();
	g_msi_maxmsg = 8;
	sc = ctrl_init(1, 0);
	pci_ahci_write(sc->asc_pi, 5, AHCI_GHC, 4, AHCI_GHC_IE);
	port_online(sc, 0);
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_READ_DMA48;
	cfis[12] = 1;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);
	ATF_CHECK(g_msi_generated > 0);
	ATF_CHECK_EQ(0, g_lintr_asserts);

	/* Global IS write path also runs the interrupt aggregator. */
	pci_ahci_write(sc->asc_pi, 5, AHCI_IS, 4, 0xffffffff);

	/* Legacy path: no MSI vectors -> INTx assert on a port interrupt,
	 * deassert when the global IS is fully cleared via GHC toggling. */
	env_reset();
	g_msi_maxmsg = 0;
	sc = ctrl_init(1, 0);
	pci_ahci_write(sc->asc_pi, 5, AHCI_GHC, 4, AHCI_GHC_IE);
	port_online(sc, 0);
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_READ_DMA48;
	cfis[12] = 1;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);
	ATF_CHECK(g_lintr_asserts > 0);

	/* Clear the port IS, then run the host GHC aggregator to deassert. */
	pw(sc, 0, AHCI_P_IS, 0xffffffff);
	pci_ahci_write(sc->asc_pi, 5, AHCI_GHC, 4, 0);
	pci_ahci_write(sc->asc_pi, 5, AHCI_GHC, 4, AHCI_GHC_IE);
	ATF_CHECK(g_lintr_deasserts > 0);
}

/* ------------------------- ATAPI (CD) tests ------------------------ */

static struct pci_ahci_softc *
cd_ctrl(void)
{
	struct pci_ahci_softc *sc;

	sc = ctrl_init(0, 1);		/* port 0 is an ATAPI drive */
	port_online(sc, 0);
	return (sc);
}

/* Build an ATAPI PACKET command with the given SCSI CDB. */
static uint8_t *
packet_setup(struct pci_ahci_softc *sc, int slot, const uint8_t *acmd,
    size_t acmdlen, uint64_t dba, uint32_t dbytes)
{
	uint8_t *cfis = cmd_setup(sc, 0, slot, dbytes ? 1 : 0);

	cfis[2] = ATA_PACKET_CMD;
	memcpy(cfis + 0x40, acmd, acmdlen);
	if (dbytes)
		prdt_set(cmd_prdt(cfis), 0, dba, dbytes);
	return (cfis);
}

ATF_TC_WITHOUT_HEAD(atapi_identify_and_inquiry);
ATF_TC_BODY(atapi_identify_and_inquiry, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis;
	struct ahci_prdt_entry *prdt;
	uint8_t acmd[16];

	env_reset();
	sc = cd_ctrl();

	/* ATAPI IDENTIFY on an ATAPI device returns parameters. */
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_ATAPI_IDENTIFY;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* Plain ATA IDENTIFY on an ATAPI device is aborted. */
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_ATA_IDENTIFY;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);

	/* INQUIRY (standard). */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x12;			/* INQUIRY */
	acmd[4] = 36;
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 64);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(0x05, g_gmem[DATA_GPA]);	/* peripheral: CD-ROM */
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* INQUIRY VPD supported-pages. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x12;
	acmd[1] = 1;			/* EVPD */
	acmd[2] = 0;			/* supported VPD pages */
	acmd[4] = 36;
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 64);
	issue(sc, 0, 1u << 0);

	/* INQUIRY VPD unsupported page -> illegal request sense. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x12;
	acmd[1] = 1;
	acmd[2] = 0x83;
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 64);
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);
	ATF_CHECK_EQ(ATA_SENSE_ILLEGAL_REQUEST, sc->port[0].sense_key);
}

ATF_TC_WITHOUT_HEAD(atapi_misc_commands);
ATF_TC_BODY(atapi_misc_commands, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t acmd[16];

	env_reset();
	sc = cd_ctrl();

	/* TEST UNIT READY -> success. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x00;
	packet_setup(sc, 0, acmd, sizeof(acmd), 0, 0);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* READ CAPACITY reports (blocks-1, 2048). */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x25;
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 8);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(2048u, be32dec(g_gmem + DATA_GPA + 4));

	/* REQUEST SENSE returns the latched key/asc. */
	sc->port[0].sense_key = ATA_SENSE_ILLEGAL_REQUEST;
	sc->port[0].asc = 0x24;
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x03;
	acmd[4] = 64;
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 64);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(0x70 | 0x80, g_gmem[DATA_GPA]);
	ATF_CHECK_EQ(ATA_SENSE_ILLEGAL_REQUEST, g_gmem[DATA_GPA + 2]);

	/* REPORT LUNS: LUN list length 8. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0xA0;
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 16);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(8, g_gmem[DATA_GPA + 3]);

	/* PREVENT/ALLOW MEDIUM REMOVAL -> success. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x1E;
	packet_setup(sc, 0, acmd, sizeof(acmd), 0, 0);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* START/STOP UNIT eject (LoEj=1,Start=0 => code 2) -> illegal req. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x1B;
	acmd[4] = 0x02;
	packet_setup(sc, 0, acmd, sizeof(acmd), 0, 0);
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);

	/* START/STOP UNIT start (code 1) -> success. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x1B;
	acmd[4] = 0x01;
	packet_setup(sc, 0, acmd, sizeof(acmd), 0, 0);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* GET EVENT STATUS NOTIFICATION (polled). */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x4A;
	acmd[1] = 1;			/* polled */
	acmd[8] = 8;
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 8);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* GET EVENT STATUS NOTIFICATION async (unsupported) -> illegal req. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x4A;
	acmd[1] = 0;
	packet_setup(sc, 0, acmd, sizeof(acmd), 0, 0);
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);

	/* An unknown SCSI opcode -> illegal request (invalid command). */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0xFE;
	packet_setup(sc, 0, acmd, sizeof(acmd), 0, 0);
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);

	/* PACKET command on a non-ATAPI device is aborted. */
	{
		struct pci_ahci_softc *hd;
		uint8_t *cfis;

		env_reset();
		hd = ctrl_init(1, 0);
		port_online(hd, 0);
		cfis = cmd_setup(hd, 0, 0, 0);
		cfis[2] = ATA_PACKET_CMD;
		issue(hd, 0, 1u << 0);
		ATF_CHECK((rfis_d2h(hd, 0)[2] & O_ATA_S_ERR) != 0);
	}
}

ATF_TC_WITHOUT_HEAD(atapi_read_toc_formats);
ATF_TC_BODY(atapi_read_toc_formats, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t acmd[16];

	env_reset();
	sc = cd_ctrl();

	/* Format 0 (TOC), LBA addressing. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x43;			/* READ TOC */
	acmd[7] = 0;
	acmd[8] = 40;			/* alloc len */
	acmd[9] = 0x00;			/* format 0 */
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 64);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* Format 0 with MSF addressing. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x43;
	acmd[1] = 0x02;			/* MSF */
	acmd[8] = 40;
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 64);
	issue(sc, 0, 1u << 0);

	/* Format 0 with an invalid start track -> illegal request. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x43;
	acmd[6] = 5;			/* start track >1 and != 0xaa */
	acmd[8] = 40;
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 64);
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);

	/* Format 1 (multi-session). */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x43;
	acmd[8] = 12;
	acmd[9] = 0x40;			/* format 1 */
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 64);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* Format 2 (raw TOC), MSF. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x43;
	acmd[1] = 0x02;
	acmd[8] = 48;
	acmd[9] = 0x80;			/* format 2 */
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 64);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* Reserved format 3 -> illegal request. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x43;
	acmd[9] = 0xc0;			/* format 3 */
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 64);
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);
}

ATF_TC_WITHOUT_HEAD(atapi_mode_sense);
ATF_TC_BODY(atapi_mode_sense, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t acmd[16];

	env_reset();
	sc = cd_ctrl();

	/* MODE SENSE 10: RW error recovery page. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x5A;
	acmd[2] = MODEPAGE_RW_ERROR_RECOVERY;	/* pc=0 */
	acmd[8] = 16;
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 32);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* MODE SENSE 10: CD capabilities page. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x5A;
	acmd[2] = MODEPAGE_CD_CAPABILITIES;
	acmd[8] = 30;
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 64);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* Unknown page (pc=0) -> illegal request. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x5A;
	acmd[2] = 0x15;
	acmd[8] = 16;
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 32);
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);

	/* Saved-values request (pc=3) -> illegal request. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x5A;
	acmd[2] = 0xc0 | MODEPAGE_RW_ERROR_RECOVERY;	/* pc=3 */
	acmd[8] = 16;
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 32);
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);

	/* Changeable-values request (pc=1) -> illegal request. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x5A;
	acmd[2] = 0x40 | MODEPAGE_RW_ERROR_RECOVERY;	/* pc=1 */
	acmd[8] = 16;
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 32);
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);
}

ATF_TC_WITHOUT_HEAD(atapi_read_data);
ATF_TC_BODY(atapi_read_data, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t acmd[16];
	int i;

	env_reset();
	g_disk_size = 8u * 1024 * 1024;
	sc = cd_ctrl();

	for (i = 0; i < 2048; i++)
		sc->port[0].bctx->disk[i] = (uint8_t)(i + 1);

	/* READ(10): 1 logical block (2048 bytes) at LBA 0. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x28;			/* READ_10 */
	be32enc(acmd + 2, 0);		/* LBA */
	be16enc(acmd + 7, 1);		/* length */
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 2048);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);
	for (i = 0; i < 2048; i++)
		ATF_CHECK_EQ((uint8_t)(i + 1), g_gmem[DATA_GPA + i]);

	/* READ(12) with zero length is an immediate success. */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0xA8;			/* READ_12 */
	be32enc(acmd + 6, 0);
	packet_setup(sc, 0, acmd, sizeof(acmd), 0, 0);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* READ(10) that the backend fails -> illegal request sense. */
	g_complete_err = EIO;
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x28;
	be16enc(acmd + 7, 1);
	packet_setup(sc, 0, acmd, sizeof(acmd), DATA_GPA, 2048);
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);
}

/* ------------------------- snapshot tests -------------------------- */

/* vm_snapshot_buffer has const buf_start/buf_size, so a meta must be built
 * by initialization rather than assignment. */
static struct vm_snapshot_meta
mk_meta(void *dev, enum vm_snapshot_op op, uint8_t *buf, size_t sz)
{
	struct vm_snapshot_meta m = {
		.dev_data = dev,
		.dev_name = "ahci",
		.op = op,
		.buffer = {
			.buf_start = buf,
			.buf_size = sz,
			.buf = buf,
			.buf_rem = sz,
		},
	};

	return (m);
}

ATF_TC_WITHOUT_HEAD(snapshot_save_restore_validate);
ATF_TC_BODY(snapshot_save_restore_validate, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *buf;
	size_t bufsz = 256 * 1024;

	env_reset();
	sc = ctrl_init(1, 1);
	port_online(sc, 0);

	buf = calloc(1, bufsz);

	/* SAVE. */
	{
		struct vm_snapshot_meta meta =
		    mk_meta(&g_pi, VM_SNAPSHOT_SAVE, buf, bufsz);
		ATF_CHECK_EQ(0, pci_ahci_snapshot(&meta));
	}
	/* RESTORE into the same controller: all invariants hold. */
	{
		struct vm_snapshot_meta meta =
		    mk_meta(&g_pi, VM_SNAPSHOT_RESTORE, buf, bufsz);
		ATF_CHECK_EQ(0, pci_ahci_snapshot(&meta));
	}
	/* VALIDATE decodes into a scratch copy without disturbing the live
	 * device and reports success. */
	{
		struct vm_snapshot_meta meta =
		    mk_meta(&g_pi, VM_SNAPSHOT_VALIDATE, buf, bufsz);
		ATF_CHECK_EQ(0, pci_ahci_snapshot_validate(&meta));
	}
	/* validate rejects a malformed meta. */
	ATF_CHECK_EQ(EINVAL, pci_ahci_snapshot_validate(NULL));
}

ATF_TC_WITHOUT_HEAD(snapshot_bad_magic);
ATF_TC_BODY(snapshot_bad_magic, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *buf;
	size_t bufsz = 256 * 1024;

	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);
	(void)sc;

	buf = calloc(1, bufsz);
	/* Corrupt the magic in the wire buffer before restore. */
	le32enc(buf, 0xdeadbeef);

	{
		struct vm_snapshot_meta meta =
		    mk_meta(&g_pi, VM_SNAPSHOT_RESTORE, buf, bufsz);
		ATF_CHECK_EQ(ENOTSUP, pci_ahci_snapshot(&meta));
	}
}

ATF_TC_WITHOUT_HEAD(pause_resume_deferred);
ATF_TC_BODY(pause_resume_deferred, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis;
	struct ahci_prdt_entry *prdt;
	struct ahci_cmd_hdr *hdr;
	int i, prdtl;
	uint32_t total;

	env_reset();
	g_disk_size = 4u * 1024 * 1024;
	sc = ctrl_init(1, 0);
	port_online(sc, 0);

	/* Start a split read (first chunk completes with more=true). */
	prdtl = 200;
	total = (uint32_t)prdtl;
	cfis = cmd_setup(sc, 0, 0, prdtl);
	cfis[2] = ATA_READ_DMA48;
	cfis[12] = total & 0xff;
	cfis[13] = (total >> 8) & 0xff;
	prdt = cmd_prdt(cfis);
	for (i = 0; i < prdtl; i++)
		prdt_set(prdt, i, DATA_GPA + (uint64_t)i * 512, 512);

	/* Dispatch the first chunk (in flight, not yet completed). */
	pw(sc, 0, AHCI_P_CI, 1u << 0);
	ATF_CHECK(sc->port[0].pending != 0);

	/* Pause: quiesce fence up.  The in-flight completion that follows
	 * reports 'more' and must be parked rather than resubmitted. */
	ATF_CHECK_EQ(0, pci_ahci_pause(sc->asc_pi));
	ATF_CHECK(g_suspend_calls > 0);
	blockif_pump();
	ATF_CHECK(!STAILQ_EMPTY(&sc->port[0].iodhd));

	/* Resume: parked continuation is resubmitted and finishes. */
	ATF_CHECK_EQ(0, pci_ahci_resume(sc->asc_pi));
	ATF_CHECK(g_resume_calls > 0);
	blockif_pump();
	ATF_CHECK(STAILQ_EMPTY(&sc->port[0].iodhd));
	hdr = slot_hdr(sc, 0, 0);
	ATF_CHECK_EQ(total * 512u, hdr->prdbc);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);
}

ATF_TC_WITHOUT_HEAD(write_read_dispatch_edges);
ATF_TC_BODY(write_read_dispatch_edges, tc)
{
	struct pci_ahci_softc *sc;

	env_reset();
	sc = ctrl_init(1, 0);

	/* Misaligned/undersized register write is dropped by the MMIO gate. */
	pci_ahci_write(sc->asc_pi, 5, AHCI_GHC, 1, 0xff);
	ATF_CHECK((pci_ahci_read(sc->asc_pi, 5, AHCI_GHC, 4) & AHCI_GHC_IE)
	    == 0);

	/* A write past the last implemented port is ignored (no crash). */
	pci_ahci_write(sc->asc_pi, 5,
	    AHCI_OFFSET + (uint64_t)sc->ports * AHCI_STEP + 0x10, 4, 0x1);
	/* A read past the last implemented port returns 0. */
	ATF_CHECK_EQ(0u, (uint32_t)pci_ahci_read(sc->asc_pi, 5,
	    AHCI_OFFSET + (uint64_t)sc->ports * AHCI_STEP + 0x10, 4));
}

ATF_TC_WITHOUT_HEAD(ata_command_variants);
ATF_TC_BODY(ata_command_variants, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis;
	struct ahci_prdt_entry *prdt;
	int i;

	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);

	for (i = 0; i < 512; i++)
		sc->port[0].bctx->disk[i] = (uint8_t)(i + 3);

	/* 28-bit LBA READ (ATA_READ) exercises the legacy LBA/len decode. */
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_READ;
	cfis[4] = 0;			/* LBA 0 */
	cfis[12] = 1;			/* 1 sector */
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);
	for (i = 0; i < 512; i++)
		ATF_CHECK_EQ((uint8_t)(i + 3), g_gmem[DATA_GPA + i]);

	/* 28-bit LBA WRITE (ATA_WRITE) exercises the write decode path. */
	for (i = 0; i < 512; i++)
		g_gmem[DATA_GPA + i] = (uint8_t)(i + 9);
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_WRITE;
	cfis[12] = 1;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);
	for (i = 0; i < 512; i++)
		ATF_CHECK_EQ((uint8_t)(i + 9), sc->port[0].bctx->disk[i]);

	/* SET FEATURES: enable SATA async-notification feature. */
	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[2] = ATA_SETFEATURES;
	cfis[3] = ATA_SF_ENAB_SATA_SF;
	cfis[12] = ATA_SATA_SF_AN;
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* SET FEATURES: enable SATA feature with an unknown selector -> abort. */
	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[2] = ATA_SETFEATURES;
	cfis[3] = ATA_SF_ENAB_SATA_SF;
	cfis[12] = 0x7e;
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);

	/* SET FEATURES: enable write cache -> success. */
	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[2] = ATA_SETFEATURES;
	cfis[3] = ATA_SF_ENAB_WCACHE;
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* SET FEATURES: SET TRANSFER MODE to a PIO mode (no xfermode change). */
	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[2] = ATA_SETFEATURES;
	cfis[3] = ATA_SF_SETXFER;
	cfis[12] = ATA_PIO0;
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* READ LOG DMA EXT (page 0) takes the no-PIO-setup path. */
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_READ_LOG_DMA_EXT;
	cfis[4] = 0x00;
	cfis[12] = 1;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* READ LOG EXT with a malformed register set is aborted. */
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_READ_LOG_EXT;
	cfis[4] = 0x00;
	cfis[5] = 1;			/* nonzero -> invalid */
	cfis[12] = 1;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);
}

ATF_TC_WITHOUT_HEAD(submit_failure_paths);
ATF_TC_BODY(submit_failure_paths, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis, *buf;
	struct ahci_prdt_entry *prdt;
	uint8_t acmd[16];

	/* FLUSH refused at submission -> command failed back (TFES). */
	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);
	g_submit_err = EBUSY;
	cfis = cmd_setup(sc, 0, 0, 0);
	cfis[2] = ATA_FLUSHCACHE;
	issue(sc, 0, 1u << 0);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_IS) & O_PxIS_TFES) != 0);

	/* DSM TRIM delete refused at submission -> command aborted. */
	env_reset();
	g_disk_candelete = 1;
	sc = ctrl_init(1, 0);
	port_online(sc, 0);
	buf = g_gmem + DATA_GPA;
	memset(buf, 0, 512);
	buf[0] = 8;
	buf[6] = 4;
	g_submit_err = EBUSY;
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_DATA_SET_MANAGEMENT;
	cfis[3] = ATA_DSM_TRIM;
	cfis[12] = 1;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);

	/* ATAPI READ refused at submission -> command aborted. */
	env_reset();
	sc = ctrl_init(0, 1);
	port_online(sc, 0);
	g_submit_err = EBUSY;
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x28;			/* READ_10 */
	be16enc(acmd + 7, 1);
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_PACKET_CMD;
	memcpy(cfis + 0x40, acmd, sizeof(acmd));
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 2048);
	issue(sc, 0, 1u << 0);
	ATF_CHECK((rfis_d2h(sc, 0)[2] & O_ATA_S_ERR) != 0);
}

ATF_TC_WITHOUT_HEAD(atapi_start_stop_variants);
ATF_TC_BODY(atapi_start_stop_variants, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t acmd[16];

	env_reset();
	sc = ctrl_init(0, 1);
	port_online(sc, 0);

	/* code 0 (stop). */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x1B;
	acmd[4] = 0x00;
	packet_setup(sc, 0, acmd, sizeof(acmd), 0, 0);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);

	/* code 3 (load). */
	memset(acmd, 0, sizeof(acmd));
	acmd[0] = 0x1B;
	acmd[4] = 0x03;
	packet_setup(sc, 0, acmd, sizeof(acmd), 0, 0);
	issue(sc, 0, 1u << 0);
	ATF_CHECK_EQ(O_ATA_S_RDY | O_ATA_S_DSC, rfis_d2h(sc, 0)[2]);
}

ATF_TC_WITHOUT_HEAD(engine_and_completion_edges);
ATF_TC_BODY(engine_and_completion_edges, tc)
{
	struct pci_ahci_softc *sc;
	uint8_t *cfis;
	struct ahci_prdt_entry *prdt;

	/* CMD write with CLO + ICC bits: both are cleared after being honored. */
	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);
	pw(sc, 0, AHCI_P_CMD, AHCI_P_CMD_FRE | AHCI_P_CMD_ST |
	    AHCI_P_CMD_CLO | AHCI_P_CMD_ACTIVE);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_CMD) & AHCI_P_CMD_CLO) == 0);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_CMD) & AHCI_P_CMD_ICC_MASK) == 0);

	/* Command dispatch with a NULL command list is a fatal host-bus
	 * error that stops the engine. */
	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);
	sc->port[0].cmd_lst = NULL;
	pw(sc, 0, AHCI_P_CI, 1u << 0);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_IS) & O_PxIS_HBFS) != 0);
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_CMD) & AHCI_P_CMD_ST) == 0);

	/* Completion whose command header can no longer be resolved (the
	 * command list was torn down mid-flight) raises a host-bus error. */
	env_reset();
	sc = ctrl_init(1, 0);
	port_online(sc, 0);
	cfis = cmd_setup(sc, 0, 0, 1);
	cfis[2] = ATA_READ_DMA48;
	cfis[12] = 1;
	prdt = cmd_prdt(cfis);
	prdt_set(prdt, 0, DATA_GPA, 512);
	pw(sc, 0, AHCI_P_CI, 1u << 0);		/* in flight */
	sc->port[0].cmd_lst = NULL;		/* list vanishes */
	blockif_pump();
	ATF_CHECK((pr_reg(sc, 0, AHCI_P_IS) & O_PxIS_HBFS) != 0);

	/* Same for the ATAPI completion callback. */
	env_reset();
	sc = ctrl_init(0, 1);
	port_online(sc, 0);
	{
		uint8_t acmd[16];

		memset(acmd, 0, sizeof(acmd));
		acmd[0] = 0x28;
		be16enc(acmd + 7, 1);
		cfis = cmd_setup(sc, 0, 0, 1);
		cfis[2] = ATA_PACKET_CMD;
		memcpy(cfis + 0x40, acmd, sizeof(acmd));
		prdt = cmd_prdt(cfis);
		prdt_set(prdt, 0, DATA_GPA, 2048);
		pw(sc, 0, AHCI_P_CI, 1u << 0);
		sc->port[0].cmd_lst = NULL;
		blockif_pump();
		ATF_CHECK((pr_reg(sc, 0, AHCI_P_IS) & O_PxIS_HBFS) != 0);
	}

	/* Host write to an unimplemented register (CCC control) is ignored. */
	env_reset();
	sc = ctrl_init(1, 0);
	pci_ahci_write(sc->asc_pi, 5, AHCI_CCCC, 4, 0x1);
}

ATF_TC_WITHOUT_HEAD(init_identity_options);
ATF_TC_BODY(init_identity_options, tc)
{
	struct nvlist *root;
	nvlist_t *ports, *pn;
	struct pci_ahci_softc *sc;
	int rc;

	/* Optional per-port identity overrides are consumed at init time. */
	env_reset();
	root = calloc(1, sizeof(*root));
	ports = create_relative_config_node((nvlist_t *)root, "port");
	pn = create_relative_config_node(ports, "0");
	set_config_value_node(pn, "type", "hd");
	set_config_value_node(pn, "path", "/dev/null");
	set_config_value_node(pn, "nmrr", "7200");
	set_config_value_node(pn, "ser", "SN12345");
	set_config_value_node(pn, "rev", "R1");
	set_config_value_node(pn, "model", "TESTMODEL");
	rc = pci_ahci_init(&g_pi, (nvlist_t *)root);
	ATF_REQUIRE_EQ(0, rc);
	sc = g_pi.pi_arg;
	ATF_CHECK_EQ(7200, sc->port[0].ata_ident.media_rotation_rate);

	/* A port node whose "type" is absent is skipped. */
	env_reset();
	root = calloc(1, sizeof(*root));
	ports = create_relative_config_node((nvlist_t *)root, "port");
	pn = create_relative_config_node(ports, "0");
	set_config_value_node(pn, "path", "/dev/null");	/* no type */
	rc = pci_ahci_init(&g_pi, (nvlist_t *)root);
	ATF_CHECK_EQ(0, rc);
	ATF_CHECK_EQ(0u, ((struct pci_ahci_softc *)g_pi.pi_arg)->pi);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, init_and_config_space);
	ATF_TP_ADD_TC(tp, init_open_and_boot_failures);
	ATF_TP_ADD_TC(tp, legacy_config_parsing);
	ATF_TP_ADD_TC(tp, host_registers);
	ATF_TP_ADD_TC(tp, port_registers);
	ATF_TP_ADD_TC(tp, read_dma_transfers_data);
	ATF_TP_ADD_TC(tp, write_dma_transfers_data);
	ATF_TP_ADD_TC(tp, read_dma_eio_is_taskfile_error);
	ATF_TP_ADD_TC(tp, read_submit_ebusy_aborts_command);
	ATF_TP_ADD_TC(tp, read_unmappable_prd_aborts);
	ATF_TP_ADD_TC(tp, read_prd_wrap_aborts);
	ATF_TP_ADD_TC(tp, flush_cache);
	ATF_TP_ADD_TC(tp, identify_ata);
	ATF_TP_ADD_TC(tp, identify_write_prdt_hbfs);
	ATF_TP_ADD_TC(tp, setfeatures_and_misc_ata);
	ATF_TP_ADD_TC(tp, read_log_ext);
	ATF_TP_ADD_TC(tp, dsm_trim);
	ATF_TP_ADD_TC(tp, ncq_read_write);
	ATF_TP_ADD_TC(tp, ncq_send_trim);
	ATF_TP_ADD_TC(tp, split_transfer_iov_cap);
	ATF_TP_ADD_TC(tp, non_command_fis_and_reset);
	ATF_TP_ADD_TC(tp, unmappable_cmd_list_and_table);
	ATF_TP_ADD_TC(tp, port_stop_cancels_inflight);
	ATF_TP_ADD_TC(tp, sctl_comreset_and_no_device);
	ATF_TP_ADD_TC(tp, interrupt_msi_and_legacy);
	ATF_TP_ADD_TC(tp, atapi_identify_and_inquiry);
	ATF_TP_ADD_TC(tp, atapi_misc_commands);
	ATF_TP_ADD_TC(tp, atapi_read_toc_formats);
	ATF_TP_ADD_TC(tp, atapi_mode_sense);
	ATF_TP_ADD_TC(tp, atapi_read_data);
	ATF_TP_ADD_TC(tp, snapshot_save_restore_validate);
	ATF_TP_ADD_TC(tp, snapshot_bad_magic);
	ATF_TP_ADD_TC(tp, pause_resume_deferred);
	ATF_TP_ADD_TC(tp, write_read_dispatch_edges);
	ATF_TP_ADD_TC(tp, ata_command_variants);
	ATF_TP_ADD_TC(tp, submit_failure_paths);
	ATF_TP_ADD_TC(tp, atapi_start_stop_variants);
	ATF_TP_ADD_TC(tp, engine_and_completion_edges);
	ATF_TP_ADD_TC(tp, init_identity_options);
	return (atf_no_error());
}
