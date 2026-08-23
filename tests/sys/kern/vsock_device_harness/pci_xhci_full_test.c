/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * TU-include coverage harness for bhyve's USB 3 xHCI controller
 * (usr.sbin/bhyve/pci_xhci.c).  The device source is compiled directly into the
 * test so its static entry points and command/transfer engines can be driven
 * without a running VM.  The bhyve infrastructure it depends on (pci_emul BAR +
 * MSI + DMA, guest memory, the usb_emul emulated-device backend, the config
 * nvlist tree, and the snapshot codec) is replaced by the mocks below.
 *
 * Guest RAM is modelled as one flat userspace buffer where the guest physical
 * address is the byte offset; pci_emul_map_dma() and paddr_*2*() translate
 * against it.  This lets the test build real command rings, transfer rings,
 * device/input contexts and an event ring in "guest memory" and drive the
 * controller exactly as a guest OS would through the memory-mapped register
 * windows.
 *
 * Assertions are checked against the xHCI 1.2 specification (register layout,
 * TRB type/error codes, event-ring semantics, slot/endpoint context state
 * machine) and the USB device framework -- never against the implementation's
 * own output.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/endian.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/nv.h>		/* pull the libnv namespace before our mocks */

#include <atf-c.h>

/* ---- Guest RAM model -------------------------------------------------------- */
#define	G_RAM_SIZE	(2u * 1024u * 1024u)
static uint8_t *g_ram;
static uint64_t g_map_fail_from;	/* map of gpa >= this returns NULL */
static unsigned g_dirty_calls;

struct vmctx;
typedef uint64_t vm_paddr_t;

/* Referenced by debug.h's PRINTLN family. */
int raw_stdio = 0;

static void
ram_reset(void)
{

	if (g_ram == NULL)
		g_ram = calloc(1, G_RAM_SIZE);
	else
		memset(g_ram, 0, G_RAM_SIZE);
	g_map_fail_from = UINT64_MAX;
	g_dirty_calls = 0;
}

static void *
ram_ptr(uint64_t gpa)
{

	return (g_ram + gpa);
}

/* ---- bhyverun.h paddr helpers ---------------------------------------------- */
void *
paddr_guest2host(struct vmctx *ctx __unused, uintptr_t gpa, size_t len)
{

	if (len == 0 || gpa >= g_map_fail_from)
		return (NULL);
	if (gpa > G_RAM_SIZE || len > G_RAM_SIZE || gpa + len > G_RAM_SIZE)
		return (NULL);
	return (g_ram + gpa);
}

uintptr_t
paddr_host2guest(struct vmctx *ctx __unused, void *addr)
{
	uint8_t *p = addr;

	if (p == NULL || p < g_ram || p >= g_ram + G_RAM_SIZE)
		return ((uintptr_t)-1);
	return ((uintptr_t)(p - g_ram));
}

/* ---- pci_emul mock ---------------------------------------------------------- */
#include <dev/pci/pcireg.h>
#include "config.h"		/* nvlist_t + config accessor prototypes */
#define	__CONFIG_H__		/* block real usr.sbin/bhyve/config.h */

#define	MOCK_PCI_EMUL_H		/* block harness mock pci_emul.h */
#define	_PCI_EMUL_H_		/* block real usr.sbin/bhyve/pci_emul.h */
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
	struct pcibar pi_bar[7];
	uint8_t pi_cfgdata[256];
};

struct pci_devemu {
	const char *pe_emu;
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
#define	PCI_MIGRATION_F_DMA_TRACKED	(1U << 4)
#define	PCI_MIGRATION_F_QUIESCE_CALLBACK	(1U << 6)

/* interrupt + DMA mock state */
static int g_msi_enabled;
static unsigned g_msi_count;
static unsigned g_lintr_assert;
static unsigned g_lintr_deassert;
static int g_lintr_level;
static int g_msicap_ret;
static unsigned g_alloc_bar_calls;
static unsigned g_lintr_request_calls;

static void
pci_reset(void)
{

	g_msi_enabled = 0;
	g_msi_count = 0;
	g_lintr_assert = 0;
	g_lintr_deassert = 0;
	g_lintr_level = 0;
	g_msicap_ret = 0;
	g_alloc_bar_calls = 0;
	g_lintr_request_calls = 0;
}

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

int
pci_emul_alloc_bar(struct pci_devinst *pi, int idx, enum pcibar_type type,
    uint64_t size)
{

	g_alloc_bar_calls++;
	pi->pi_bar[idx].type = type;
	pi->pi_bar[idx].size = size;
	return (0);
}

int
pci_emul_add_msicap(struct pci_devinst *pi __unused, int msgnum __unused)
{

	return (g_msicap_ret);
}

void
pci_lintr_request(struct pci_devinst *pi __unused)
{

	g_lintr_request_calls++;
}

void
pci_lintr_assert(struct pci_devinst *pi __unused)
{

	g_lintr_assert++;
	g_lintr_level = 1;
}

void
pci_lintr_deassert(struct pci_devinst *pi __unused)
{

	g_lintr_deassert++;
	g_lintr_level = 0;
}

void
pci_generate_msi(struct pci_devinst *pi __unused, int idx __unused)
{

	g_msi_count++;
}

int
pci_msi_enabled(struct pci_devinst *pi __unused)
{

	return (g_msi_enabled);
}

void *
pci_emul_map_dma(struct pci_devinst *pi __unused, uint64_t gpa, size_t len,
    enum pci_dma_direction dir __unused)
{

	if (len == 0 || gpa >= g_map_fail_from)
		return (NULL);
	if (gpa > G_RAM_SIZE || len > G_RAM_SIZE || gpa + len > G_RAM_SIZE)
		return (NULL);
	return (g_ram + gpa);
}

void
pci_emul_mark_dma_dirty_mapping(struct pci_devinst *pi __unused,
    void *addr __unused, size_t len __unused)
{

	g_dirty_calls++;
}

/* ---- config / nvlist mock -------------------------------------------------- */
/*
 * A tiny mutable configuration tree standing in for bhyve's config.c wrappers
 * over libnv.  Only the operations pci_xhci.c performs are implemented.
 */
#ifndef NV_TYPE_STRING
#define	NV_TYPE_STRING		4
#endif
#ifndef NV_TYPE_NVLIST
#define	NV_TYPE_NVLIST		5
#endif

struct cfg_ent {
	char *name;
	char *str;		/* non-NULL => string entry */
	nvlist_t *child;	/* non-NULL => nested node */
};

struct nvlist {
	struct cfg_ent ents[32];
	int n;
};

static nvlist_t *
cfg_new(void)
{

	return (calloc(1, sizeof(nvlist_t)));
}

static struct cfg_ent *
cfg_find(nvlist_t *nvl, const char *name)
{
	int i;

	if (nvl == NULL)
		return (NULL);
	for (i = 0; i < nvl->n; i++)
		if (strcmp(nvl->ents[i].name, name) == 0)
			return (&nvl->ents[i]);
	return (NULL);
}

nvlist_t *
create_relative_config_node(nvlist_t *parent, const char *name)
{
	struct cfg_ent *e;

	e = cfg_find(parent, name);
	if (e != NULL && e->child != NULL)
		return (e->child);
	assert(parent->n < (int)nitems(parent->ents));
	e = &parent->ents[parent->n++];
	e->name = strdup(name);
	e->child = cfg_new();
	return (e->child);
}

nvlist_t *
find_relative_config_node(nvlist_t *parent, const char *name)
{
	struct cfg_ent *e;

	e = cfg_find(parent, name);
	return (e != NULL ? e->child : NULL);
}

void
set_config_value_node(nvlist_t *nvl, const char *name, const char *val)
{
	struct cfg_ent *e;

	e = cfg_find(nvl, name);
	if (e == NULL) {
		assert(nvl->n < (int)nitems(nvl->ents));
		e = &nvl->ents[nvl->n++];
		e->name = strdup(name);
	} else
		free(e->str);
	e->str = strdup(val);
}

void
set_config_bool_node(nvlist_t *nvl, const char *name, bool val)
{

	set_config_value_node(nvl, name, val ? "true" : "false");
}

const char *
get_config_value_node(const nvlist_t *nvl, const char *name)
{
	struct cfg_ent *e;

	e = cfg_find(__DECONST(nvlist_t *, nvl), name);
	return (e != NULL ? e->str : NULL);
}

bool
get_config_bool_node_default(const nvlist_t *nvl, const char *name, bool def)
{
	const char *v;

	v = get_config_value_node(nvl, name);
	if (v == NULL)
		return (def);
	return (strcmp(v, "true") == 0 || strcmp(v, "1") == 0);
}

int
pci_parse_legacy_config(nvlist_t *nvl, const char *opt)
{
	char *tofree, *str, *tok, *eq;

	if (opt == NULL)
		return (0);
	tofree = str = strdup(opt);
	while ((tok = strsep(&str, ",")) != NULL) {
		eq = strchr(tok, '=');
		if (eq == NULL)
			continue;
		*eq++ = '\0';
		set_config_value_node(nvl, tok, eq);
	}
	free(tofree);
	return (0);
}

const char *
nvlist_next(const nvlist_t *nvl, int *typep, void **cookiep)
{
	uintptr_t idx = (uintptr_t)*cookiep;
	struct cfg_ent *e;

	if (idx >= (uintptr_t)nvl->n)
		return (NULL);
	e = &__DECONST(nvlist_t *, nvl)->ents[idx];
	*typep = e->child != NULL ? NV_TYPE_NVLIST : NV_TYPE_STRING;
	*cookiep = (void *)(idx + 1);
	return (e->name);
}

const nvlist_t *
nvlist_get_nvlist(const nvlist_t *nvl, const char *name)
{
	struct cfg_ent *e;

	e = cfg_find(__DECONST(nvlist_t *, nvl), name);
	return (e != NULL ? e->child : NULL);
}

/* ---- usb_emul backend mock ------------------------------------------------- */
#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include "usb_emul.h"

/* Controllable mock USB device behaviour. */
static int g_ue_usbver = 3;
static int g_ue_probe_null;
static int g_ue_init_ret;
static int g_ue_reset_ret;		/* >=0 ok */
static int g_ue_stop_ret;
static int g_ue_remove_ret;
static int g_ue_request_err = USB_ERR_NORMAL_COMPLETION;
static int g_ue_data_err = USB_ERR_NORMAL_COMPLETION;
static int g_ue_has_reset = 1;
static int g_ue_has_stop = 1;
static int g_ue_has_data = 1;
static int g_ue_has_request = 1;
static int g_ue_has_snapshot = 1;
static unsigned g_ue_request_calls;
static unsigned g_ue_data_calls;
static unsigned g_ue_reset_calls;
static struct usb_hci *g_last_hci;
static int g_ue_data_cancel;		/* make ue_data report CANCELLED/NAK */

struct mock_usb_softc {
	int magic;
};

static void
mark_processed(struct usb_data_xfer *xfer)
{
	int i, n;

	i = xfer->head;
	for (n = 0; n < xfer->ndata; n++) {
		xfer->data[i].processed = 1;
		xfer->data[i].bdone = xfer->data[i].blen;
		USB_DATA_SET_ERRCODE(&xfer->data[i], USB_ACK);
		i = (i + 1) % USB_MAX_XFER_BLOCKS;
	}
}

static void *
mock_ue_probe(struct usb_hci *hci, nvlist_t *nvl __unused)
{
	struct mock_usb_softc *sc;

	g_last_hci = hci;
	if (g_ue_probe_null)
		return (NULL);
	hci->hci_usbver = g_ue_usbver;
	sc = calloc(1, sizeof(*sc));
	sc->magic = 0x5a5a;
	return (sc);
}

static int
mock_ue_init(void *sc __unused)
{

	return (g_ue_init_ret);
}

static int
mock_ue_request(void *sc __unused, struct usb_data_xfer *xfer)
{

	g_ue_request_calls++;
	if (g_ue_request_err == USB_ERR_NORMAL_COMPLETION)
		mark_processed(xfer);
	return (g_ue_request_err);
}

static int
mock_ue_data(void *sc __unused, struct usb_data_xfer *xfer, int dir __unused,
    int epctx __unused)
{

	g_ue_data_calls++;
	if (g_ue_data_cancel) {
		USB_DATA_SET_ERRCODE(&xfer->data[xfer->head], USB_NAK);
		return (USB_ERR_CANCELLED);
	}
	if (g_ue_data_err == USB_ERR_NORMAL_COMPLETION)
		mark_processed(xfer);
	return (g_ue_data_err);
}

static int
mock_ue_reset(void *sc __unused)
{

	g_ue_reset_calls++;
	return (g_ue_reset_ret);
}

static int
mock_ue_stop(void *sc __unused)
{

	return (g_ue_stop_ret);
}

static int
mock_ue_remove(void *sc __unused)
{

	return (g_ue_remove_ret);
}

static int
mock_ue_snapshot(void *sc __unused, struct vm_snapshot_meta *meta __unused)
{

	return (0);
}

static struct usb_devemu g_mock_ue;

static void
ue_reset(void)
{

	g_ue_usbver = 3;
	g_ue_probe_null = 0;
	g_ue_init_ret = 0;
	g_ue_reset_ret = 0;
	g_ue_stop_ret = 0;
	g_ue_remove_ret = 0;
	g_ue_request_err = USB_ERR_NORMAL_COMPLETION;
	g_ue_data_err = USB_ERR_NORMAL_COMPLETION;
	g_ue_data_cancel = 0;
	g_ue_has_reset = 1;
	g_ue_has_stop = 1;
	g_ue_has_data = 1;
	g_ue_has_request = 1;
	g_ue_has_snapshot = 1;
	g_ue_request_calls = 0;
	g_ue_data_calls = 0;
	g_ue_reset_calls = 0;
	g_last_hci = NULL;

	memset(&g_mock_ue, 0, sizeof(g_mock_ue));
	g_mock_ue.ue_emu = "tablet";
	g_mock_ue.ue_usbver = g_ue_usbver;
	g_mock_ue.ue_usbspeed = USB_SPEED_HIGH;
	g_mock_ue.ue_probe = mock_ue_probe;
	g_mock_ue.ue_init = mock_ue_init;
	g_mock_ue.ue_request = mock_ue_request;
	g_mock_ue.ue_data = mock_ue_data;
	g_mock_ue.ue_reset = mock_ue_reset;
	g_mock_ue.ue_stop = mock_ue_stop;
	g_mock_ue.ue_remove = mock_ue_remove;
	g_mock_ue.ue_snapshot = mock_ue_snapshot;
}

/* Re-apply optional-handler switches after ue_reset(). */
static void
ue_apply(void)
{

	g_mock_ue.ue_usbver = g_ue_usbver;
	g_mock_ue.ue_reset = g_ue_has_reset ? mock_ue_reset : NULL;
	g_mock_ue.ue_stop = g_ue_has_stop ? mock_ue_stop : NULL;
	g_mock_ue.ue_data = g_ue_has_data ? mock_ue_data : NULL;
	g_mock_ue.ue_request = g_ue_has_request ? mock_ue_request : NULL;
	g_mock_ue.ue_snapshot = g_ue_has_snapshot ? mock_ue_snapshot : NULL;
}

struct usb_devemu *
usb_emu_finddev(const char *name)
{

	if (strcmp(name, g_mock_ue.ue_emu) == 0)
		return (&g_mock_ue);
	return (NULL);
}

struct usb_data_xfer_block *
usb_data_xfer_append(struct usb_data_xfer *xfer, void *buf, int blen,
    void *hci_data, int ccs)
{
	struct usb_data_xfer_block *xb;

	if (xfer->ndata >= USB_MAX_XFER_BLOCKS)
		return (NULL);
	xb = &xfer->data[xfer->tail];
	xb->buf = buf;
	xb->blen = blen;
	xb->hci_data = hci_data;
	xb->ccs = ccs;
	xb->processed = 0;
	xb->bdone = 0;
	xfer->ndata++;
	xfer->tail = (xfer->tail + 1) % USB_MAX_XFER_BLOCKS;
	return (xb);
}

/* ---- snapshot codec mock --------------------------------------------------- */
/*
 * Only <machine/vmm_snapshot.h> is pulled here (types + SNAPSHOT_BUF_OR_LEAVE).
 * The real bhyve "snapshot.h" (with the SNAPSHOT_LE*_OR_LEAVE macros and the
 * vm_snapshot_is_loading()/is_restoring() inlines) is included by pci_xhci.c;
 * the codec function bodies are defined after that include so they can use it.
 */
#include <machine/vmm_snapshot.h>

/* ---- Device under test ----------------------------------------------------- */
#include "pci_xhci.c"

/* ---- snapshot codec mock bodies (need pci_xhci.c's snapshot.h) ------------- */
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
	else
		memcpy(data, meta->buffer.buf, size);
	meta->buffer.buf += size;
	meta->buffer.buf_rem -= size;
	return (0);
}

int
vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[sizeof(*value)];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		le32enc(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && meta->op != VM_SNAPSHOT_SAVE)
		*value = le32dec(bytes);
	return (error);
}

int
vm_snapshot_le64(uint64_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[sizeof(*value)];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		le64enc(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && meta->op != VM_SNAPSHOT_SAVE)
		*value = le64dec(bytes);
	return (error);
}

int
vm_snapshot_nonnegative_int(int *value, struct vm_snapshot_meta *meta)
{
	uint32_t encoded;
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		if (*value < 0)
			return (EINVAL);
		encoded = (uint32_t)*value;
	} else
		encoded = 0;
	error = vm_snapshot_le32(&encoded, meta);
	if (error != 0)
		return (error);
	if (vm_snapshot_is_loading(meta)) {
		if (encoded > INT_MAX)
			return (EINVAL);
		*value = (int)encoded;
	}
	return (0);
}

int
vm_snapshot_guest2host_addr(struct vmctx *ctx, void **addrp, size_t len,
    bool restore_null, struct vm_snapshot_meta *meta)
{
	void *hostaddr;
	int ret = 0;
	vm_paddr_t gaddr;
	uint64_t wire_gaddr;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		gaddr = paddr_host2guest(ctx, *addrp);
		if (gaddr == (vm_paddr_t)-1 &&
		    (!restore_null || *addrp != NULL))
			return (EFAULT);
		wire_gaddr = (uint64_t)gaddr;
		SNAPSHOT_LE64_OR_LEAVE(wire_gaddr, meta, ret, done);
	} else if (vm_snapshot_is_loading(meta)) {
		wire_gaddr = 0;
		SNAPSHOT_LE64_OR_LEAVE(wire_gaddr, meta, ret, done);
		gaddr = (vm_paddr_t)wire_gaddr;
		if (gaddr == (vm_paddr_t)-1 && !restore_null)
			return (EFAULT);
		hostaddr = gaddr == (vm_paddr_t)-1 ? NULL :
		    paddr_guest2host(ctx, gaddr, len);
		if (gaddr != (vm_paddr_t)-1 && hostaddr == NULL)
			return (EFAULT);
		if (vm_snapshot_is_restoring(meta))
			*addrp = hostaddr;
	} else
		ret = EINVAL;
done:
	return (ret);
}

/* ==== xHCI 1.2 specification oracles ======================================== */
#define	ORA_CAPLEN		0x20	/* xHCI 5.3.1 CAPLENGTH for this HC */
#define	ORA_HCIVERSION		0x0100	/* xHCI 1.0 register interface */
#define	ORA_MAXSLOTS		64
#define	ORA_MAXPORTS		8
#define	ORA_TRB_SIZE		16	/* xHCI 6.4: a TRB is 16 bytes */
#define	ORA_EVCOUNT		16

/* Guest physical layout used by the tests (all above 0, spec-aligned). */
#define	CR_GPA		0x010000ULL
#define	ERST_GPA	0x011000ULL
#define	EVRING_GPA	0x012000ULL
#define	DCBAA_GPA	0x013000ULL
#define	DEVCTX_GPA	0x014000ULL
#define	INPUT_GPA	0x015000ULL
#define	EP0RING_GPA	0x016000ULL
#define	DATA_GPA	0x017000ULL
#define	EPXRING_GPA	0x018000ULL
#define	INPUT2_GPA	0x019000ULL

static struct pci_devinst *
make_pi(void)
{
	struct pci_devinst *pi;

	pi = calloc(1, sizeof(*pi));
	ATF_REQUIRE(pi != NULL);
	pi->pi_vmctx = (struct vmctx *)(void *)pi;
	return (pi);
}

static nvlist_t *
make_cfg_one_tablet(const char *slotname, const char *device)
{
	nvlist_t *nvl, *slots, *slot;

	nvl = cfg_new();
	slots = create_relative_config_node(nvl, "slot");
	slot = create_relative_config_node(slots, slotname);
	set_config_value_node(slot, "device", device);
	return (nvl);
}

static void
full_reset(void)
{

	ram_reset();
	pci_reset();
	ue_reset();
	ue_apply();
	xhci_in_use = 0;
}

/* Absolute BAR offsets for the register windows (filled in after init). */
struct regmap {
	struct pci_xhci_softc *sc;
	uint32_t dboff;
	uint32_t rtsoff;
};

static void
grab_regmap(struct regmap *rm, struct pci_devinst *pi)
{

	rm->sc = pi->pi_arg;
	rm->dboff = rm->sc->dboff;
	rm->rtsoff = rm->sc->rtsoff;
}

/* Operational register access through the public BAR path. */
static void
op_write(struct pci_devinst *pi, uint32_t reg, uint64_t val)
{

	pci_xhci_write(pi, 0, XHCI_CAPLEN + reg, 4, val);
}

static uint64_t
op_read(struct pci_devinst *pi, uint32_t reg)
{

	return (pci_xhci_read(pi, 0, XHCI_CAPLEN + reg, 4));
}

/* Runtime interrupter register access. */
static void
rt_write(struct regmap *rm, struct pci_devinst *pi, uint32_t ireg, uint64_t val)
{

	pci_xhci_write(pi, 0, rm->rtsoff + 0x20 + ireg, 4, val);
}

/* Program the event ring: ERSTSZ=1, ERST entry, ERSTBA, ERDP. */
static void
setup_event_ring(struct regmap *rm, struct pci_devinst *pi)
{
	struct xhci_event_ring_seg *erst = ram_ptr(ERST_GPA);

	erst->qwEvrsTablePtr = EVRING_GPA;
	erst->dwEvrsTableSize = ORA_EVCOUNT;

	rt_write(rm, pi, 0x08, 1);			/* ERSTSZ = 1 */
	rt_write(rm, pi, 0x10, ERST_GPA & 0xFFFFFFFF);	/* ERSTBA lo */
	rt_write(rm, pi, 0x14, ERST_GPA >> 32);		/* ERSTBA hi */
	rt_write(rm, pi, 0x18, EVRING_GPA & 0xFFFFFFFF);	/* ERDP lo */
	rt_write(rm, pi, 0x1C, EVRING_GPA >> 32);	/* ERDP hi */
	rt_write(rm, pi, 0x00, XHCI_IMAN_INTR_ENA);	/* IMAN enable */
}

/* Program CRCR to point at the command ring with cycle state 1. */
static void
setup_cmd_ring(struct pci_devinst *pi)
{

	op_write(pi, XHCI_CRCR_LO, (CR_GPA & 0xFFFFFFC0) | XHCI_CRCR_LO_RCS);
	op_write(pi, XHCI_CRCR_HI, CR_GPA >> 32);
}

/* Program DCBAAP and the device context base address array. */
static void
setup_dcbaa(struct pci_devinst *pi, uint32_t slot, uint64_t devctx_gpa)
{
	struct xhci_dcbaa *dcbaa = ram_ptr(DCBAA_GPA);

	dcbaa->dcba[slot] = devctx_gpa;
	op_write(pi, XHCI_DCBAAP_LO, DCBAA_GPA & 0xFFFFFFC0);
	op_write(pi, XHCI_DCBAAP_HI, DCBAA_GPA >> 32);
}

/* Write a single TRB into guest memory. */
static void
put_trb(uint64_t gpa, int idx, uint64_t p0, uint32_t d2, uint32_t d3)
{
	struct xhci_trb *t = ram_ptr(gpa);

	t[idx].qwTrb0 = p0;
	t[idx].dwTrb2 = d2;
	t[idx].dwTrb3 = d3;
}

static struct xhci_trb *
ev_trb(int idx)
{

	return (&((struct xhci_trb *)ram_ptr(EVRING_GPA))[idx]);
}

/*
 * The most recently written event ring entry.  Running the controller queues a
 * port-status-change event per attached device before any command runs, so
 * fixed event indices are not portable; each command/transfer that completes
 * writes exactly one event, so the newest entry is the one under test.
 */
static struct xhci_trb *
last_event(struct pci_xhci_softc *sc)
{
	uint32_t c = sc->rtsregs.er_event_count;
	int i = (sc->rtsregs.er_enq_idx - 1 + (int)c) % (int)c;

	return (ev_trb(i));
}

static void
ring_cmd_doorbell(struct regmap *rm, struct pci_devinst *pi)
{

	pci_xhci_write(pi, 0, rm->dboff, 4, 0);
}

static void
ring_ep_doorbell(struct regmap *rm, struct pci_devinst *pi, uint32_t slot,
    uint32_t epid, uint32_t sid)
{

	pci_xhci_write(pi, 0, rm->dboff + slot * 4, 4,
	    XHCI_DB_TARGET_SET(epid) | XHCI_DB_SID_SET(sid));
}

/* Bring the controller up: run + interrupts + all rings programmed. */
static struct pci_devinst *
bring_up(struct regmap *rm)
{
	struct pci_devinst *pi;

	pi = make_pi();
	ATF_REQUIRE_EQ(0, pci_xhci_init(pi, make_cfg_one_tablet("1", "tablet")));
	grab_regmap(rm, pi);
	setup_cmd_ring(pi);
	setup_dcbaa(pi, 1, DEVCTX_GPA);
	setup_event_ring(rm, pi);
	op_write(pi, XHCI_USBCMD, XHCI_CMD_RS | XHCI_CMD_INTE);
	return (pi);
}

/* ========================================================================== */

ATF_TC_WITHOUT_HEAD(init_and_capability_registers);
ATF_TC_BODY(init_and_capability_registers, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;

	full_reset();
	pi = make_pi();
	ATF_REQUIRE_EQ(0, pci_xhci_init(pi, make_cfg_one_tablet("1", "tablet")));
	sc = pi->pi_arg;
	ATF_REQUIRE(sc != NULL);

	/* PCI identity: Intel xHCI, serial-bus/USB/xHCI programming interface. */
	ATF_CHECK_EQ(0x8086, le16dec(&pi->pi_cfgdata[PCIR_VENDOR]));
	ATF_CHECK_EQ(0x1E31, le16dec(&pi->pi_cfgdata[PCIR_DEVICE]));
	ATF_CHECK_EQ(PCIC_SERIALBUS, pi->pi_cfgdata[PCIR_CLASS]);
	ATF_CHECK_EQ(PCIS_SERIALBUS_USB, pi->pi_cfgdata[PCIR_SUBCLASS]);
	ATF_CHECK_EQ(PCIP_SERIALBUS_USB_XHCI, pi->pi_cfgdata[PCIR_PROGIF]);
	ATF_CHECK_EQ(1, g_alloc_bar_calls);
	ATF_CHECK_EQ(1, g_lintr_request_calls);

	/* CAPLENGTH low byte and HCIVERSION high half (xHCI 5.3.1). */
	ATF_CHECK_EQ(ORA_CAPLEN, pci_xhci_read(pi, 0, XHCI_CAPLENGTH, 4) & 0xFF);
	ATF_CHECK_EQ(ORA_HCIVERSION,
	    XHCI_GET_HCIVERSION(pci_xhci_read(pi, 0, XHCI_CAPLENGTH, 4)));

	/* HCSPARAMS1: MaxSlots / MaxPorts (xHCI 5.3.3). */
	{
		uint32_t hcs1 = pci_xhci_read(pi, 0, XHCI_HCSPARAMS1, 4);
		ATF_CHECK_EQ(ORA_MAXSLOTS, hcs1 & 0xFF);
		ATF_CHECK_EQ(ORA_MAXPORTS, (hcs1 >> 24) & 0xFF);
	}

	/* DBOFF/RTSOFF are aligned per xHCI 5.3.7 / 5.3.8. */
	ATF_CHECK_EQ(0, sc->dboff & 0x3);
	ATF_CHECK_EQ(0, sc->rtsoff & 0x1F);
	ATF_CHECK_EQ(sc->dboff, pci_xhci_read(pi, 0, XHCI_DBOFF, 4));
	ATF_CHECK_EQ(sc->rtsoff, pci_xhci_read(pi, 0, XHCI_RTSOFF, 4));

	/* All capability registers are individually readable (xHCI 5.3). */
	ATF_CHECK_EQ(sc->hcsparams2, pci_xhci_read(pi, 0, XHCI_HCSPARAMS2, 4));
	ATF_CHECK_EQ(sc->hcsparams3, pci_xhci_read(pi, 0, XHCI_HCSPARAMS3, 4));
	ATF_CHECK_EQ(sc->hccparams1, pci_xhci_read(pi, 0, XHCI_HCCPARAMS1, 4));
	ATF_CHECK_EQ(sc->hccparams2, pci_xhci_read(pi, 0, XHCI_HCCPRAMS2, 4));
	/* An undefined capability offset reads as zero. */
	ATF_CHECK_EQ(0, pci_xhci_read(pi, 0, 0x1D, 1));

	/* USBSTS reports halted at reset (xHCI 5.4.2, HCH=1). */
	ATF_CHECK((op_read(pi, XHCI_USBSTS) & XHCI_STS_HCH) != 0);

	/* PAGESIZE advertises 4K (bit0) per xHCI 5.4.3. */
	ATF_CHECK_EQ(XHCI_PAGESIZE_4K, op_read(pi, XHCI_PAGESIZE));

	/* A second controller instance is refused. */
	ATF_CHECK_EQ(-1,
	    pci_xhci_init(make_pi(), make_cfg_one_tablet("1", "tablet")));

	/* Registration table wires the documented entry points. */
	ATF_CHECK_STREQ("xhci", pci_de_xhci.pe_emu);
	ATF_CHECK(pci_de_xhci.pe_init == pci_xhci_init);
	ATF_CHECK(pci_de_xhci.pe_barread == pci_xhci_read);
	ATF_CHECK(pci_de_xhci.pe_barwrite == pci_xhci_write);
}

ATF_TC_WITHOUT_HEAD(init_failure_paths);
ATF_TC_BODY(init_failure_paths, tc)
{
	struct pci_devinst *pi;

	/* Unknown device model. */
	full_reset();
	ATF_CHECK_EQ(-1,
	    pci_xhci_init(make_pi(), make_cfg_one_tablet("1", "bogusdev")));

	/* Invalid slot number. */
	full_reset();
	ATF_CHECK_EQ(-1,
	    pci_xhci_init(make_pi(), make_cfg_one_tablet("0", "tablet")));

	/* Duplicate slot. */
	full_reset();
	{
		nvlist_t *nvl, *slots, *s1, *s2;

		/* "1" and "01" are distinct keys that map to the same slot. */
		nvl = cfg_new();
		slots = create_relative_config_node(nvl, "slot");
		s1 = create_relative_config_node(slots, "1");
		set_config_value_node(s1, "device", "tablet");
		s2 = create_relative_config_node(slots, "01");
		set_config_value_node(s2, "device", "tablet");
		ATF_CHECK_EQ(-1, pci_xhci_init(make_pi(), nvl));
	}

	/* Missing device value. */
	full_reset();
	{
		nvlist_t *nvl, *slots, *s1;

		nvl = cfg_new();
		slots = create_relative_config_node(nvl, "slot");
		s1 = create_relative_config_node(slots, "1");
		(void)s1;
		ATF_CHECK_EQ(-1, pci_xhci_init(make_pi(), nvl));
	}

	/* ue_probe failure. */
	full_reset();
	g_ue_probe_null = 1;
	ATF_CHECK_EQ(-1,
	    pci_xhci_init(make_pi(), make_cfg_one_tablet("1", "tablet")));

	/* ue_init failure. */
	full_reset();
	g_ue_init_ret = -1;
	ATF_CHECK_EQ(-1,
	    pci_xhci_init(make_pi(), make_cfg_one_tablet("1", "tablet")));

	/* MSI capability failure unwinds init. */
	full_reset();
	g_msicap_ret = ENXIO;
	pi = make_pi();
	ATF_CHECK_EQ(ENXIO,
	    pci_xhci_init(pi, make_cfg_one_tablet("1", "tablet")));
	ATF_CHECK(pi->pi_arg == NULL);

	/* No configured devices is allowed (empty slot node absent). */
	full_reset();
	ATF_CHECK_EQ(0, pci_xhci_init(make_pi(), cfg_new()));
}

ATF_TC_WITHOUT_HEAD(legacy_config_translation);
ATF_TC_BODY(legacy_config_translation, tc)
{
	nvlist_t *nvl, *slots, *s1;

	full_reset();
	nvl = cfg_new();

	/* NULL opts is a no-op success. */
	ATF_CHECK_EQ(0, pci_xhci_legacy_config(nvl, NULL));

	/* "tablet" becomes slot 1's device; a keyed option is parsed too. */
	ATF_CHECK_EQ(0, pci_xhci_legacy_config(nvl, "tablet"));
	slots = find_relative_config_node(nvl, "slot");
	ATF_REQUIRE(slots != NULL);
	s1 = find_relative_config_node(slots, "1");
	ATF_REQUIRE(s1 != NULL);
	ATF_CHECK_STREQ("tablet", get_config_value_node(s1, "device"));
}

ATF_TC_WITHOUT_HEAD(usb2_and_usb3_port_layout);
ATF_TC_BODY(usb2_and_usb3_port_layout, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;

	/* A USB2 device lands on the USB2 port range; a USB3 on the USB3 range. */
	full_reset();
	g_ue_usbver = 2;
	ue_apply();
	pi = make_pi();
	ATF_REQUIRE_EQ(0, pci_xhci_init(pi, make_cfg_one_tablet("1", "tablet")));
	sc = pi->pi_arg;
	/* USB2 devices start at port 5 (MAX_DEVS/2 + 1). */
	ATF_CHECK(XHCI_DEVINST_PTR(sc, sc->usb2_port_start) != NULL);
	ATF_CHECK_EQ(5, sc->usb2_port_start);
	ATF_CHECK_EQ(1, sc->usb3_port_start);

	/* xECP advertises the USB2 and USB3 protocol capability blocks. */
	{
		uint64_t xecp0 = pci_xhci_read(pi, 0, sc->regsend, 4);
		uint64_t xecp16 = pci_xhci_read(pi, 0, sc->regsend + 16, 4);
		ATF_CHECK_EQ(0x02, (xecp0 >> 24) & 0xFF);	/* USB 2.0 */
		ATF_CHECK_EQ(0x03, (xecp16 >> 24) & 0xFF);	/* USB 3.0 */
	}
}

ATF_TC_WITHOUT_HEAD(operational_register_readwrite);
ATF_TC_BODY(operational_register_readwrite, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;

	/* No device: Run/Stop can be exercised without event-ring setup. */
	full_reset();
	pi = make_pi();
	ATF_REQUIRE_EQ(0, pci_xhci_init(pi, cfg_new()));
	sc = pi->pi_arg;

	/* Writes to the read-only capability window are ignored. */
	pci_xhci_write(pi, 0, 0, 4, 0xffffffff);
	ATF_CHECK_EQ(ORA_CAPLEN, pci_xhci_read(pi, 0, XHCI_CAPLENGTH, 4) & 0xFF);

	/* DNCTRL is a 16-bit RW register. */
	op_write(pi, XHCI_DNCTRL, 0x1234FFFF);
	ATF_CHECK_EQ(0xFFFF, op_read(pi, XHCI_DNCTRL));

	/* CONFIG holds the number of enabled device slots (10 bits). */
	op_write(pi, XHCI_CONFIG, 0xFFFF);
	ATF_CHECK_EQ(0x3FF, op_read(pi, XHCI_CONFIG));

	/* DCBAAP is 64-bit and 64-byte aligned. */
	op_write(pi, XHCI_DCBAAP_LO, DCBAA_GPA & 0xFFFFFFC0);
	op_write(pi, XHCI_DCBAAP_HI, 0);
	ATF_CHECK_EQ(DCBAA_GPA, sc->opregs.dcbaap);
	ATF_CHECK(sc->opregs.dcbaa_p == ram_ptr(DCBAA_GPA));

	/* USBSTS write-1-to-clear on EINT. */
	sc->opregs.usbsts |= XHCI_STS_EINT;
	op_write(pi, XHCI_USBSTS, XHCI_STS_EINT);
	ATF_CHECK((op_read(pi, XHCI_USBSTS) & XHCI_STS_EINT) == 0);

	/* Run/Stop transitions HCH. */
	op_write(pi, XHCI_USBCMD, XHCI_CMD_RS);
	ATF_CHECK((op_read(pi, XHCI_USBSTS) & XHCI_STS_HCH) == 0);
	op_write(pi, XHCI_USBCMD, 0);
	ATF_CHECK((op_read(pi, XHCI_USBSTS) & XHCI_STS_HCH) != 0);

	/* Host controller reset returns to defaults. */
	op_write(pi, XHCI_USBCMD, XHCI_CMD_HCRST);
	ATF_CHECK_EQ(0, sc->opregs.crcr);
	ATF_CHECK_EQ(0, sc->opregs.config);

	/* Out-of-range reads/writes are handled without crashing. */
	pci_xhci_write(pi, 0, sc->regsend + 4 * 32 + 4, 4, 0);
	ATF_CHECK_EQ(0, pci_xhci_read(pi, 0, sc->regsend + 4 * 32 + 4, 4));

	/* Byte- and half-word-sized reads are masked. */
	ATF_CHECK_EQ(ORA_CAPLEN, pci_xhci_read(pi, 0, XHCI_CAPLENGTH, 1));
}

ATF_TC_WITHOUT_HEAD(runtime_registers_and_event_ring_setup);
ATF_TC_BODY(runtime_registers_and_event_ring_setup, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;

	full_reset();
	pi = make_pi();
	ATF_REQUIRE_EQ(0, pci_xhci_init(pi, make_cfg_one_tablet("1", "tablet")));
	sc = pi->pi_arg;
	grab_regmap(&rm, pi);

	/* IMOD is a free RW register. */
	rt_write(&rm, pi, 0x04, 0xDEADBEEF);
	ATF_CHECK_EQ(0xDEADBEEF, sc->rtsregs.intrreg.imod);

	/* MFINDEX write is ignored (RO); read returns current value. */
	pci_xhci_write(pi, 0, rm.rtsoff, 4, 0x1234);
	ATF_CHECK_EQ(0, pci_xhci_read(pi, 0, rm.rtsoff, 4));

	/* A well-formed ERST/ERSTBA/ERDP program maps the event ring. */
	setup_event_ring(&rm, pi);
	ATF_CHECK_EQ(1, sc->rtsregs.intrreg.erstsz);
	ATF_CHECK(sc->rtsregs.erstba_p != NULL);
	ATF_CHECK(sc->rtsregs.erst_p != NULL);
	ATF_CHECK_EQ(ORA_EVCOUNT, sc->rtsregs.er_event_count);
	ATF_CHECK_EQ(EVRING_GPA, sc->rtsregs.er_event_base);

	/* Reading back the interrupter register file. */
	ATF_CHECK_EQ(XHCI_IMAN_INTR_ENA,
	    pci_xhci_read(pi, 0, rm.rtsoff + 0x20, 4) & XHCI_IMAN_INTR_ENA);
	ATF_CHECK_EQ(1, pci_xhci_read(pi, 0, rm.rtsoff + 0x20 + 0x08, 4));

	/* An out-of-range runtime read returns 0. */
	ATF_CHECK_EQ(0, pci_xhci_read(pi, 0, rm.rtsoff + 0x20 + 0x40, 4));
}

ATF_TC_WITHOUT_HEAD(event_ring_setup_rejections);
ATF_TC_BODY(event_ring_setup_rejections, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_event_ring_seg *erst = ram_ptr(ERST_GPA);

	/* ERSTBA programmed while ERSTSZ != 1 raises a host error. */
	full_reset();
	pi = make_pi();
	ATF_REQUIRE_EQ(0, pci_xhci_init(pi, make_cfg_one_tablet("1", "tablet")));
	sc = pi->pi_arg;
	grab_regmap(&rm, pi);
	rt_write(&rm, pi, 0x10, ERST_GPA & 0xFFFFFFFF);
	rt_write(&rm, pi, 0x14, ERST_GPA >> 32);
	ATF_CHECK((sc->opregs.usbsts & XHCI_STS_HSE) != 0);
	ATF_CHECK(sc->rtsregs.erstba_p == NULL);

	/* ERST with a zero table size is rejected. */
	full_reset();
	pi = make_pi();
	ATF_REQUIRE_EQ(0, pci_xhci_init(pi, make_cfg_one_tablet("1", "tablet")));
	sc = pi->pi_arg;
	grab_regmap(&rm, pi);
	erst = ram_ptr(ERST_GPA);
	erst->qwEvrsTablePtr = EVRING_GPA;
	erst->dwEvrsTableSize = 0;
	rt_write(&rm, pi, 0x08, 1);
	rt_write(&rm, pi, 0x10, ERST_GPA & 0xFFFFFFFF);
	rt_write(&rm, pi, 0x14, ERST_GPA >> 32);
	ATF_CHECK((sc->opregs.usbsts & XHCI_STS_HSE) != 0);

	/* ERST pointer misaligned is rejected. */
	full_reset();
	pi = make_pi();
	ATF_REQUIRE_EQ(0, pci_xhci_init(pi, make_cfg_one_tablet("1", "tablet")));
	sc = pi->pi_arg;
	grab_regmap(&rm, pi);
	erst = ram_ptr(ERST_GPA);
	erst->qwEvrsTablePtr = EVRING_GPA | 0x8;	/* not 64-aligned */
	erst->dwEvrsTableSize = ORA_EVCOUNT;
	rt_write(&rm, pi, 0x08, 1);
	rt_write(&rm, pi, 0x10, ERST_GPA & 0xFFFFFFFF);
	rt_write(&rm, pi, 0x14, ERST_GPA >> 32);
	ATF_CHECK((sc->opregs.usbsts & XHCI_STS_HSE) != 0);

	/* Event ring segment map failure. */
	full_reset();
	pi = make_pi();
	ATF_REQUIRE_EQ(0, pci_xhci_init(pi, make_cfg_one_tablet("1", "tablet")));
	sc = pi->pi_arg;
	grab_regmap(&rm, pi);
	erst = ram_ptr(ERST_GPA);
	erst->qwEvrsTablePtr = EVRING_GPA;
	erst->dwEvrsTableSize = ORA_EVCOUNT;
	rt_write(&rm, pi, 0x08, 1);
	rt_write(&rm, pi, 0x10, ERST_GPA & 0xFFFFFFFF);
	g_map_fail_from = EVRING_GPA;			/* ring map fails */
	rt_write(&rm, pi, 0x14, ERST_GPA >> 32);
	ATF_CHECK((sc->opregs.usbsts & XHCI_STS_HSE) != 0);
}

ATF_TC_WITHOUT_HEAD(command_ring_slot_lifecycle);
ATF_TC_BODY(command_ring_slot_lifecycle, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_trb *ev;

	full_reset();
	pi = bring_up(&rm);
	sc = pi->pi_arg;

	/* Enable Slot (xHCI 4.6.3): returns SUCCESS and assigns slot 1. */
	put_trb(CR_GPA, 0, 0, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_ENABLE_SLOT) |
	    XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);

	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_EVENT_CMD_COMPLETE,
	    XHCI_TRB_3_TYPE_GET(ev->dwTrb3));
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SUCCESS,
	    XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
	ATF_CHECK_EQ(1, XHCI_TRB_3_SLOT_GET(ev->dwTrb3));
	ATF_CHECK_EQ(XHCI_ST_ENABLED, XHCI_SLOTDEV_PTR(sc, 1)->dev_slotstate);
	/* Command completion asserts an interrupt (INTE + IMAN ENA + MSI). */
	ATF_CHECK(g_msi_count + g_lintr_assert > 0);

	/* Disable Slot returns SUCCESS and returns the slot to DISABLED. */
	put_trb(CR_GPA, 1, 0, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_DISABLE_SLOT) |
	    XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
	ATF_CHECK_EQ(XHCI_ST_DISABLED, XHCI_SLOTDEV_PTR(sc, 1)->dev_slotstate);

	/* Disabling an already-disabled slot reports SLOT_NOT_ON. */
	put_trb(CR_GPA, 2, 0, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_DISABLE_SLOT) |
	    XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SLOT_NOT_ON,
	    XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Disable of an out-of-range slot reports SLOT_NOT_ON. */
	put_trb(CR_GPA, 3, 0, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_DISABLE_SLOT) |
	    XHCI_TRB_3_SLOT_SET(200) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SLOT_NOT_ON,
	    XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* No-Op command completes with SUCCESS. */
	put_trb(CR_GPA, 4, 0, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_NOOP_CMD) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* An unsupported command type reports TRB error. */
	put_trb(CR_GPA, 5, 0, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_FORCE_EVENT) |
	    XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_TRB, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
}

/*
 * Address a device on slot 1 with an endpoint-0 transfer ring, leaving the
 * controller ready to run control transfers.  Returns the softc.
 */
static struct pci_xhci_softc *
address_slot1(struct regmap *rm, struct pci_devinst *pi, int cr_idx)
{
	struct pci_xhci_softc *sc = pi->pi_arg;
	struct xhci_input_dev_ctx *in = ram_ptr(INPUT_GPA);

	/* Enable slot first. */
	put_trb(CR_GPA, cr_idx, 0, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_ENABLE_SLOT) |
	    XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(rm, pi);

	/* Build the input context: add slot + ep0, ep0 TR at EP0RING_GPA. */
	memset(in, 0, sizeof(*in));
	in->ctx_input.dwInCtx1 = 0x03;
	in->ctx_ep[1].qwEpCtx2 = EP0RING_GPA | 0x1;	/* DCS = 1 */

	put_trb(CR_GPA, cr_idx + 1, INPUT_GPA, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_ADDRESS_DEVICE) |
	    XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(rm, pi);

	return (sc);
}

/* full_reset + bring_up + address slot 1 with an ep0 transfer ring. */
static struct pci_devinst *
setup_addressed(struct regmap *rm)
{
	struct pci_devinst *pi;

	full_reset();
	pi = bring_up(rm);
	(void)address_slot1(rm, pi, 0);
	return (pi);
}

#define	TT(x)	XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_##x)
#define	STREAM_CTX_GPA	0x01A000ULL
#define	STREAMRING1_GPA	0x01B000ULL

ATF_TC_WITHOUT_HEAD(command_address_and_configure);
ATF_TC_BODY(command_address_and_configure, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_dev_ctx *dctx;
	struct xhci_input_dev_ctx *in2;
	struct xhci_trb *ev;

	full_reset();
	pi = bring_up(&rm);
	sc = address_slot1(&rm, pi, 0);
	dctx = ram_ptr(DEVCTX_GPA);
	in2 = ram_ptr(INPUT2_GPA);

	/* Address Device set the slot to ADDRESSED and assigned an address. */
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
	ATF_CHECK_EQ(XHCI_ST_ADDRESSED, XHCI_SLOTDEV_PTR(sc, 1)->dev_slotstate);
	ATF_CHECK_EQ(XHCI_ST_SLCTX_ADDRESSED,
	    XHCI_SCTX_3_SLOT_STATE_GET(dctx->ctx_slot.dwSctx3));
	ATF_CHECK_EQ(1, g_ue_reset_calls);

	/* Configure Endpoint: add a bulk IN endpoint (epid 3). */
	memset(in2, 0, sizeof(*in2));
	in2->ctx_input.dwInCtx1 = 0x01 | XHCI_INCTX_1_ADD_MASK(3);
	in2->ctx_ep[3].qwEpCtx2 = EPXRING_GPA | 0x1;
	put_trb(CR_GPA, 2, INPUT2_GPA, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_CONFIGURE_EP) |
	    XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
	ATF_CHECK_EQ(XHCI_ST_CONFIGURED, XHCI_SLOTDEV_PTR(sc, 1)->dev_slotstate);
	ATF_CHECK_EQ(XHCI_ST_SLCTX_CONFIGURED,
	    XHCI_SCTX_3_SLOT_STATE_GET(dctx->ctx_slot.dwSctx3));

	/* Evaluate Context updates ep0 max packet size only. */
	memset(in2, 0, sizeof(*in2));
	in2->ctx_input.dwInCtx1 = 0x02;
	in2->ctx_ep[1].dwEpCtx1 = XHCI_EPCTX_1_MAXP_SIZE_SET(512);
	put_trb(CR_GPA, 3, INPUT2_GPA, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_EVALUATE_CTX) |
	    XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
	ATF_CHECK_EQ(512,
	    XHCI_EPCTX_1_MAXP_SIZE_GET(dctx->ctx_ep[1].dwEpCtx1));

	/* Deconfigure endpoints (DC bit). */
	put_trb(CR_GPA, 4, 0, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_CONFIGURE_EP) |
	    XHCI_TRB_3_DCEP_BIT | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
	ATF_CHECK_EQ(XHCI_ST_ADDRESSED, XHCI_SLOTDEV_PTR(sc, 1)->dev_slotstate);

	/* Reset Device returns the slot to DEFAULT state. */
	put_trb(CR_GPA, 5, 0, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_RESET_DEVICE) |
	    XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
	ATF_CHECK_EQ(XHCI_ST_DEFAULT, XHCI_SLOTDEV_PTR(sc, 1)->dev_slotstate);
}

ATF_TC_WITHOUT_HEAD(command_error_paths);
ATF_TC_BODY(command_error_paths, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_trb *ev;

	full_reset();
	pi = bring_up(&rm);
	sc = pi->pi_arg;

	/* Address Device on a bad slot (0) reports TRB error. */
	put_trb(CR_GPA, 0, INPUT_GPA, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_ADDRESS_DEVICE) |
	    XHCI_TRB_3_SLOT_SET(0) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_TRB, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Configure EP on a never-enabled slot reports SLOT_NOT_ON. */
	put_trb(CR_GPA, 1, INPUT_GPA, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_CONFIGURE_EP) |
	    XHCI_TRB_3_SLOT_SET(2) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SLOT_NOT_ON,
	    XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Set TR Dequeue on a bad slot reports SLOT_NOT_ON. */
	put_trb(CR_GPA, 2, 0, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_SET_TR_DEQUEUE) |
	    XHCI_TRB_3_SLOT_SET(3) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SLOT_NOT_ON,
	    XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
}

ATF_TC_WITHOUT_HEAD(command_link_and_reset_ep);
ATF_TC_BODY(command_link_and_reset_ep, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_dev_ctx *dctx;
	struct xhci_trb *ev;

	full_reset();
	pi = bring_up(&rm);
	sc = address_slot1(&rm, pi, 0);
	dctx = ram_ptr(DEVCTX_GPA);
	(void)sc;

	/* A Link TRB with toggle-cycle redirects the command ring dequeue. */
	put_trb(CR_GPA, 2, CR_GPA + 3 * ORA_TRB_SIZE, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_LINK) | XHCI_TRB_3_CYCLE_BIT);
	/* target of the link: a No-Op. */
	put_trb(CR_GPA, 3, 0, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_NOOP_CMD) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	/* The No-Op after the link produced a command completion event. */
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_EVENT_CMD_COMPLETE,
	    XHCI_TRB_3_TYPE_GET(ev->dwTrb3));

	/* Stop Endpoint on ep0 leaves the endpoint context STOPPED. */
	put_trb(CR_GPA, 4, 0, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_STOP_EP) |
	    XHCI_TRB_3_EP_SET(1) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
	ATF_CHECK_EQ(XHCI_ST_EPCTX_STOPPED,
	    XHCI_EPCTX_0_EPSTATE_GET(dctx->ctx_ep[1].dwEpCtx0));

	/* Set TR Dequeue with a new ring pointer on the stopped endpoint. */
	put_trb(CR_GPA, 5, EP0RING_GPA | 0x1, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_SET_TR_DEQUEUE) |
	    XHCI_TRB_3_EP_SET(1) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Reset Endpoint on ep0. */
	put_trb(CR_GPA, 6, 0, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_RESET_EP) |
	    XHCI_TRB_3_EP_SET(1) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
}

ATF_TC_WITHOUT_HEAD(control_transfer_and_doorbell);
ATF_TC_BODY(control_transfer_and_doorbell, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_trb *ev;

	full_reset();
	pi = bring_up(&rm);
	sc = pi->pi_arg;
	(void)address_slot1(&rm, pi, 0);

	/*
	 * Build a control transfer on ep0's ring: SETUP, DATA (IN), STATUS
	 * with IOC on the last stage (xHCI 4.11.2.2).
	 */
	put_trb(EP0RING_GPA, 0, 0 /* setup data */, XHCI_TRB_2_BYTES_SET(8),
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_SETUP_STAGE) |
	    XHCI_TRB_3_IDT_BIT | XHCI_TRB_3_CYCLE_BIT);
	put_trb(EP0RING_GPA, 1, DATA_GPA, XHCI_TRB_2_BYTES_SET(8),
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_DATA_STAGE) |
	    XHCI_TRB_3_DIR_IN | XHCI_TRB_3_CHAIN_BIT | XHCI_TRB_3_CYCLE_BIT);
	put_trb(EP0RING_GPA, 2, 0, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_STATUS_STAGE) |
	    XHCI_TRB_3_IOC_BIT | XHCI_TRB_3_CYCLE_BIT);

	ring_ep_doorbell(&rm, pi, 1, 1, 0);

	/* The device request handler ran and a transfer event was posted. */
	ATF_CHECK(g_ue_request_calls >= 1);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_EVENT_TRANSFER, XHCI_TRB_3_TYPE_GET(ev->dwTrb3));
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Doorbell for an empty slot is ignored. */
	ring_ep_doorbell(&rm, pi, 40, 1, 0);
	/* Doorbell with an invalid endpoint is ignored. */
	ring_ep_doorbell(&rm, pi, 1, 99, 0);
	/* Doorbell with an invalid slot is ignored. */
	ring_ep_doorbell(&rm, pi, 0, 1, 0);
}

ATF_TC_WITHOUT_HEAD(bulk_transfer_via_data_endpoint);
ATF_TC_BODY(bulk_transfer_via_data_endpoint, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_input_dev_ctx *in2;
	struct xhci_trb *ev;

	full_reset();
	pi = bring_up(&rm);
	sc = address_slot1(&rm, pi, 0);
	in2 = ram_ptr(INPUT2_GPA);
	(void)sc;

	/* Configure a bulk OUT endpoint at epid 2 with its own ring. */
	memset(in2, 0, sizeof(*in2));
	in2->ctx_input.dwInCtx1 = 0x01 | XHCI_INCTX_1_ADD_MASK(2);
	in2->ctx_ep[2].qwEpCtx2 = EPXRING_GPA | 0x1;
	put_trb(CR_GPA, 2, INPUT2_GPA, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_CONFIGURE_EP) |
	    XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_REQUIRE_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* A NORMAL TRB (bulk OUT) with IOC drives ue_data + a transfer event. */
	put_trb(EPXRING_GPA, 0, DATA_GPA, XHCI_TRB_2_BYTES_SET(64),
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_NORMAL) |
	    XHCI_TRB_3_IOC_BIT | XHCI_TRB_3_CYCLE_BIT);
	ring_ep_doorbell(&rm, pi, 1, 2, 0);
	ATF_CHECK(g_ue_data_calls >= 1);

	/* A second doorbell with the device NAKing exercises the retry path. */
	g_ue_data_cancel = 1;
	put_trb(EPXRING_GPA, 1, DATA_GPA, XHCI_TRB_2_BYTES_SET(64),
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_NORMAL) |
	    XHCI_TRB_3_IOC_BIT | XHCI_TRB_3_CYCLE_BIT);
	ring_ep_doorbell(&rm, pi, 1, 2, 0);
}

ATF_TC_WITHOUT_HEAD(port_registers_and_reset);
ATF_TC_BODY(port_registers_and_reset, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	uint64_t portsc_off;
	uint32_t portsc;

	full_reset();
	pi = bring_up(&rm);
	sc = pi->pi_arg;

	/* PORTSC for the attached USB3 port reports connect + enabled. */
	portsc_off = XHCI_CAPLEN + XHCI_PORTREGS_PORT0 + 1 * XHCI_PORTREGS_SETSZ;
	portsc = pci_xhci_read(pi, 0, portsc_off, 4);
	ATF_CHECK((portsc & XHCI_PS_CCS) != 0);		/* connected */
	ATF_CHECK((portsc & XHCI_PS_PP) != 0);		/* powered */

	/* Writing PR triggers a port reset and posts a PORT_STS_CHANGE event. */
	pci_xhci_write(pi, 0, portsc_off, 4, XHCI_PS_PR);
	portsc = pci_xhci_read(pi, 0, portsc_off, 4);
	ATF_CHECK((portsc & XHCI_PS_PRC) != 0);		/* reset complete */

	/* PORTPMSC and PORTHLPMC are RW scratch registers. */
	pci_xhci_write(pi, 0, portsc_off + 4, 4, 0xABCD);
	ATF_CHECK_EQ(0xABCD, pci_xhci_read(pi, 0, portsc_off + 4, 4));
	pci_xhci_write(pi, 0, portsc_off + 12, 4, 0x1357);
	ATF_CHECK_EQ(0x1357, pci_xhci_read(pi, 0, portsc_off + 12, 4));

	/*
	 * A port index beyond XHCI_MAX_DEVS returns the default USB3 speed.
	 * This lies past the BAR's port window (doorbell space begins there),
	 * so it is exercised through the internal reader directly.
	 */
	ATF_CHECK_EQ(XHCI_PS_SPEED_SET(3),
	    pci_xhci_portregs_read(sc,
	    XHCI_PORTREGS_PORT0 + (XHCI_MAX_DEVS + 2) * XHCI_PORTREGS_SETSZ));

	/* An unaligned port register read returns all-ones. */
	ATF_CHECK_EQ(0xffffffff,
	    pci_xhci_portregs_read(sc, XHCI_PORTREGS_PORT0 + 1 * XHCI_PORTREGS_SETSZ + 2));
	(void)sc;
}

ATF_TC_WITHOUT_HEAD(interrupt_gating_and_erdp);
ATF_TC_BODY(interrupt_gating_and_erdp, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;

	full_reset();
	g_msi_enabled = 1;
	pi = bring_up(&rm);
	sc = pi->pi_arg;

	/* Generate one event (enable slot) -> MSI raised, ERDP busy set. */
	put_trb(CR_GPA, 0, 0, 0,
	    XHCI_TRB_3_TYPE_SET(XHCI_TRB_TYPE_ENABLE_SLOT) |
	    XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ATF_CHECK(g_msi_count >= 1);
	ATF_CHECK((sc->rtsregs.intrreg.erdp & XHCI_ERDP_LO_BUSY) != 0);

	/* Guest acknowledges by writing ERDP with the busy (EHB) bit. */
	rt_write(&rm, pi, 0x18,
	    (EVRING_GPA + ORA_TRB_SIZE) | XHCI_ERDP_LO_BUSY);
	ATF_CHECK((sc->rtsregs.intrreg.erdp & XHCI_ERDP_LO_BUSY) == 0);
	rt_write(&rm, pi, 0x1C, 0);

	/* Disabling IMAN interrupt enable deasserts (no-op for MSI path). */
	rt_write(&rm, pi, 0x00, 0);
	ATF_CHECK((sc->rtsregs.intrreg.iman & XHCI_IMAN_INTR_ENA) == 0);
}

ATF_TC_WITHOUT_HEAD(transfer_ring_exhaustion);
ATF_TC_BODY(transfer_ring_exhaustion, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_input_dev_ctx *in2;
	struct xhci_trb *ev;
	int i;

	pi = setup_addressed(&rm);
	sc = pi->pi_arg;
	in2 = ram_ptr(INPUT2_GPA);

	/* Configure a bulk OUT endpoint. */
	memset(in2, 0, sizeof(*in2));
	in2->ctx_input.dwInCtx1 = 0x01 | XHCI_INCTX_1_ADD_MASK(2);
	in2->ctx_ep[2].qwEpCtx2 = EPXRING_GPA | 0x1;
	put_trb(CR_GPA, 2, INPUT2_GPA, 0,
	    TT(CONFIGURE_EP) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_REQUIRE_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/*
	 * A chain longer than USB_MAX_XFER_BLOCKS overflows the transfer-block
	 * pool; the controller must reject it (xHCI resource error) rather than
	 * overrun.  Every TRB but the last carries the CHAIN bit.
	 */
	for (i = 0; i < 12; i++)
		put_trb(EPXRING_GPA, i, DATA_GPA, XHCI_TRB_2_BYTES_SET(8),
		    TT(NORMAL) | (i < 11 ? XHCI_TRB_3_CHAIN_BIT :
		    XHCI_TRB_3_IOC_BIT) | XHCI_TRB_3_CYCLE_BIT);
	ring_ep_doorbell(&rm, pi, 1, 2, 0);
	/* No crash / overrun; the controller stayed alive. */
	ATF_CHECK((sc->opregs.usbcmd & XHCI_CMD_RS) != 0);
}

ATF_TC_WITHOUT_HEAD(erdp_recompute_and_errors);
ATF_TC_BODY(erdp_recompute_and_errors, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	int i;

	full_reset();
	pi = bring_up(&rm);
	sc = pi->pi_arg;

	/* Produce several events so the ERDP write recomputes the fill level. */
	for (i = 0; i < 3; i++) {
		put_trb(CR_GPA, i, 0, 0,
		    TT(NOOP_CMD) | XHCI_TRB_3_CYCLE_BIT);
		ring_cmd_doorbell(&rm, pi);
	}
	ATF_REQUIRE(sc->rtsregs.er_events_cnt > 0);

	/* Consumer advances ERDP within the ring: fill level is recomputed. */
	rt_write(&rm, pi, 0x18, EVRING_GPA + 1 * ORA_TRB_SIZE);
	rt_write(&rm, pi, 0x1C, 0);
	ATF_CHECK(sc->rtsregs.er_events_cnt < sc->rtsregs.er_event_count);

	/* An ERDP that wraps past the enqueue index takes the other arm. */
	sc->rtsregs.er_events_cnt = 1;
	rt_write(&rm, pi, 0x18,
	    EVRING_GPA + (ORA_EVCOUNT - 1) * ORA_TRB_SIZE);
	rt_write(&rm, pi, 0x1C, 0);

	/* A geometry mismatch at ERDP-high time raises a host error. */
	sc->rtsregs.er_events_cnt = 1;
	((struct xhci_event_ring_seg *)ram_ptr(ERST_GPA))->dwEvrsTableSize = 4;
	rt_write(&rm, pi, 0x1C, 0);
	ATF_CHECK((sc->opregs.usbsts & XHCI_STS_HSE) != 0);

	/* A write to an unhandled runtime offset is ignored. */
	pci_xhci_write(pi, 0, rm.rtsoff + 0x20 + 0x40, 4, 0x5555);
}

ATF_TC_WITHOUT_HEAD(command_ring_bad_pointer);
ATF_TC_BODY(command_ring_bad_pointer, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;

	/* Ringing the command doorbell with no command ring is a host error. */
	full_reset();
	pi = make_pi();
	ATF_REQUIRE_EQ(0, pci_xhci_init(pi, make_cfg_one_tablet("1", "tablet")));
	sc = pi->pi_arg;
	grab_regmap(&rm, pi);
	setup_event_ring(&rm, pi);
	op_write(pi, XHCI_USBCMD, XHCI_CMD_RS | XHCI_CMD_INTE);
	/* cr_p is NULL because CRCR was never programmed. */
	ring_cmd_doorbell(&rm, pi);
	ATF_CHECK((sc->opregs.usbsts & XHCI_STS_HSE) != 0);

	/* Doorbell while the controller is halted is ignored. */
	full_reset();
	pi = bring_up(&rm);
	sc = pi->pi_arg;
	op_write(pi, XHCI_USBCMD, 0);		/* stop -> halted */
	ring_cmd_doorbell(&rm, pi);
}

ATF_TC_WITHOUT_HEAD(dev_intr_backend_notification);
ATF_TC_BODY(dev_intr_backend_notification, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;

	full_reset();
	pi = bring_up(&rm);
	sc = address_slot1(&rm, pi, 0);

	/* A backend interrupt with no data queued is harmless. */
	ATF_CHECK_EQ(0, g_last_hci->hci_intr(g_last_hci, 0x81));

	/* dev_event is a no-op returning success. */
	ATF_CHECK_EQ(0, g_last_hci->hci_event(g_last_hci, USBDEV_ATTACH, NULL));

	/* Out-of-range endpoint context index is rejected. */
	ATF_CHECK_EQ(EINVAL, pci_xhci_dev_intr(g_last_hci, 0x00));
	(void)sc;
}

#ifdef BHYVE_SNAPSHOT
ATF_TC_WITHOUT_HEAD(snapshot_save_restore_roundtrip);
ATF_TC_BODY(snapshot_save_restore_roundtrip, tc)
{
	struct pci_devinst *pi;
	struct regmap rm;
	uint8_t *buf;
	size_t bufsz, used;

	full_reset();
	pi = bring_up(&rm);
	(void)address_slot1(&rm, pi, 0);

	bufsz = 256 * 1024;
	buf = malloc(bufsz);
	ATF_REQUIRE(buf != NULL);

	/* Save. */
	{
		struct vm_snapshot_meta meta = {
			.dev_name = "xhci", .dev_data = pi,
			.op = VM_SNAPSHOT_SAVE,
			.buffer = { .buf = buf, .buf_rem = bufsz,
			    .buf_start = buf, .buf_size = bufsz },
		};
		ATF_REQUIRE_EQ(0, pci_xhci_snapshot(&meta));
		used = bufsz - meta.buffer.buf_rem;
		ATF_CHECK(used > 0);
	}

	/* Validate the produced image against the live device. */
	{
		struct vm_snapshot_meta meta = {
			.dev_name = "xhci", .dev_data = pi,
			.op = VM_SNAPSHOT_VALIDATE,
			.buffer = { .buf = buf, .buf_rem = used,
			    .buf_start = buf, .buf_size = used },
		};
		ATF_CHECK_EQ(0, pci_xhci_snapshot(&meta));
	}

	/* Restore into the same live device. */
	{
		struct vm_snapshot_meta meta = {
			.dev_name = "xhci", .dev_data = pi,
			.op = VM_SNAPSHOT_RESTORE,
			.buffer = { .buf = buf, .buf_rem = used,
			    .buf_start = buf, .buf_size = used },
		};
		ATF_CHECK_EQ(0, pci_xhci_snapshot(&meta));
	}

	/* A corrupted magic is rejected on load. */
	buf[0] ^= 0xff;
	{
		struct vm_snapshot_meta meta = {
			.dev_name = "xhci", .dev_data = pi,
			.op = VM_SNAPSHOT_RESTORE,
			.buffer = { .buf = buf, .buf_rem = used,
			    .buf_start = buf, .buf_size = used },
		};
		ATF_CHECK(pci_xhci_snapshot(&meta) != 0);
	}
	buf[0] ^= 0xff;

	free(buf);
}

/*
 * Serialize one endpoint's transfer state to a buffer (SAVE) and replay a
 * possibly-corrupted copy (RESTORE), exercising pci_xhci_snapshot_ep's
 * per-field validation arms.  The on-wire block layout is fixed:
 *   present(8) nstreams(4) then 8 blocks of
 *   blen(4) bdone(4) buf(8) processed(4) hci(8) ccs(4) streamid(4) trbnext(8)
 *   then ureq_present(8) [ureq(8)] ndata(4) head(4) tail(4)
 */
#define	EPB0		12		/* first transfer block */
#define	EPB_BLEN	(EPB0 + 0)
#define	EPB_PROCESSED	(EPB0 + 16)
#define	EPB_HCI		(EPB0 + 20)
#define	EPB_CCS		(EPB0 + 28)
#define	EPB_STREAMID	(EPB0 + 32)
#define	EPB_UREQ	(EPB0 + 8 * 44)	/* 364 */

static size_t
ep_save(struct pci_xhci_softc *sc, int idx, uint8_t *buf, size_t cap)
{
	struct pci_xhci_dev_emu *dev = XHCI_SLOTDEV_PTR(sc, 1);
	struct vm_snapshot_meta meta = {
		.dev_name = "xhci", .dev_data = sc->xsc_pi,
		.op = VM_SNAPSHOT_SAVE,
		.buffer = { .buf = buf, .buf_rem = cap,
		    .buf_start = buf, .buf_size = cap },
	};

	ATF_REQUIRE_EQ(0, pci_xhci_snapshot_ep(sc, dev, idx, &meta));
	return (cap - meta.buffer.buf_rem);
}

static int
ep_restore(struct pci_xhci_softc *sc, int idx, uint8_t *buf, size_t used)
{
	struct pci_xhci_dev_emu *dev = XHCI_SLOTDEV_PTR(sc, 1);
	struct vm_snapshot_meta meta = {
		.dev_name = "xhci", .dev_data = sc->xsc_pi,
		.op = VM_SNAPSHOT_RESTORE,
		.buffer = { .buf = buf, .buf_rem = used,
		    .buf_start = buf, .buf_size = used },
	};

	return (pci_xhci_snapshot_ep(sc, dev, idx, &meta));
}

ATF_TC_WITHOUT_HEAD(snapshot_endpoint_validation);
ATF_TC_BODY(snapshot_endpoint_validation, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_input_dev_ctx *in2;
	uint8_t good[1024], work[1024];
	size_t used;

	/* --- endpoint 0: present, no streams, empty transfer (ndata == 0) --- */
	pi = setup_addressed(&rm);
	sc = pi->pi_arg;
	used = ep_save(sc, 1, good, sizeof(good));
	ATF_REQUIRE(used > EPB_UREQ);

	/* A "present" flag greater than one is rejected. */
	memcpy(work, good, used); work[0] = 2;
	ATF_CHECK(ep_restore(sc, 1, work, used) != 0);

	/* A stream count that is not a valid power-of-two-plus is rejected. */
	memcpy(work, good, used); work[8] = 3;
	ATF_CHECK(ep_restore(sc, 1, work, used) != 0);

	/* A transfer block longer than 0x1ffff bytes is rejected. */
	memcpy(work, good, used);
	work[EPB_BLEN] = 0x00; work[EPB_BLEN + 1] = 0x00;
	work[EPB_BLEN + 2] = 0x02; work[EPB_BLEN + 3] = 0x00;	/* 0x20000 */
	ATF_CHECK(ep_restore(sc, 1, work, used) != 0);

	/* An out-of-range "processed" completion code is rejected. */
	memcpy(work, good, used); work[EPB_PROCESSED] = 2;
	ATF_CHECK(ep_restore(sc, 1, work, used) != 0);

	/* A cycle-state bit outside {0,1} is rejected. */
	memcpy(work, good, used); work[EPB_CCS] = 2;
	ATF_CHECK(ep_restore(sc, 1, work, used) != 0);

	/* A "ureq present" flag greater than one is rejected. */
	memcpy(work, good, used); work[EPB_UREQ] = 2;
	ATF_CHECK(ep_restore(sc, 1, work, used) != 0);

	/* An ndata beyond USB_MAX_XFER_BLOCKS is rejected. */
	memcpy(work, good, used); work[EPB_UREQ + 8] = 9;	/* ndata */
	ATF_CHECK(ep_restore(sc, 1, work, used) != 0);

	/* --- endpoint 2: a queued (NAK'd) transfer so ndata == 1 --- */
	pi = setup_addressed(&rm);
	sc = pi->pi_arg;
	in2 = ram_ptr(INPUT2_GPA);
	memset(in2, 0, sizeof(*in2));
	in2->ctx_input.dwInCtx1 = 0x01 | XHCI_INCTX_1_ADD_MASK(2);
	in2->ctx_ep[2].qwEpCtx2 = EPXRING_GPA | 0x1;
	put_trb(CR_GPA, 2, INPUT2_GPA, 0,
	    TT(CONFIGURE_EP) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	g_ue_data_cancel = 1;
	put_trb(EPXRING_GPA, 0, DATA_GPA, XHCI_TRB_2_BYTES_SET(32),
	    TT(NORMAL) | XHCI_TRB_3_IOC_BIT | XHCI_TRB_3_CYCLE_BIT);
	ring_ep_doorbell(&rm, pi, 1, 2, 0);
	ATF_REQUIRE(XHCI_SLOTDEV_PTR(sc, 1)->eps[2].ep_xfer->ndata > 0);

	used = ep_save(sc, 2, good, sizeof(good));

	/* A non-zero stream id on a non-stream endpoint block is rejected. */
	memcpy(work, good, used); work[EPB_STREAMID] = 1;
	ATF_CHECK(ep_restore(sc, 2, work, used) != 0);

	/* A misaligned HCI (TRB) back-pointer is rejected. */
	memcpy(work, good, used); work[EPB_HCI] |= 0x08;
	ATF_CHECK(ep_restore(sc, 2, work, used) != 0);
}

ATF_TC_WITHOUT_HEAD(snapshot_streams_and_queued_xfer);
ATF_TC_BODY(snapshot_streams_and_queued_xfer, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_input_dev_ctx *in2;
	struct xhci_stream_ctx *sctx;
	struct xhci_trb *ev;
	uint8_t *buf;
	size_t used;

	pi = setup_addressed(&rm);
	sc = pi->pi_arg;
	in2 = ram_ptr(INPUT2_GPA);
	sctx = ram_ptr(STREAM_CTX_GPA);

	/* Configure a non-stream bulk OUT endpoint (epid 2). */
	memset(in2, 0, sizeof(*in2));
	in2->ctx_input.dwInCtx1 = 0x01 | XHCI_INCTX_1_ADD_MASK(2) |
	    XHCI_INCTX_1_ADD_MASK(3);
	in2->ctx_ep[2].qwEpCtx2 = EPXRING_GPA | 0x1;
	/* And a streams-capable endpoint (epid 3). */
	memset(sctx, 0, 8 * sizeof(*sctx));
	sctx[1].qwSctx0 = STREAMRING1_GPA |
	    XHCI_SCTX_0_SCT_SET(XHCI_SCTX_0_SCT_PRIM_TR_RING) | 0x1;
	in2->ctx_ep[3].dwEpCtx0 = XHCI_EPCTX_0_MAXP_STREAMS_SET(1) |
	    XHCI_EPCTX_0_LSA_SET(1);
	in2->ctx_ep[3].qwEpCtx2 = STREAM_CTX_GPA | 0x1;
	put_trb(CR_GPA, 2, INPUT2_GPA, 0,
	    TT(CONFIGURE_EP) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_REQUIRE_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Leave a queued (NAK'd) transfer on ep2 so ndata survives the save. */
	g_ue_data_cancel = 1;
	put_trb(EPXRING_GPA, 0, DATA_GPA, XHCI_TRB_2_BYTES_SET(32),
	    TT(NORMAL) | XHCI_TRB_3_IOC_BIT | XHCI_TRB_3_CYCLE_BIT);
	ring_ep_doorbell(&rm, pi, 1, 2, 0);
	ATF_REQUIRE(XHCI_SLOTDEV_PTR(sc, 1)->eps[2].ep_xfer->ndata > 0);

	buf = malloc(256 * 1024);
	ATF_REQUIRE(buf != NULL);
	{
		struct vm_snapshot_meta meta = {
			.dev_name = "xhci", .dev_data = pi,
			.op = VM_SNAPSHOT_SAVE,
			.buffer = { .buf = buf, .buf_rem = 256 * 1024,
			    .buf_start = buf, .buf_size = 256 * 1024 },
		};
		ATF_REQUIRE_EQ(0, pci_xhci_snapshot(&meta));
		used = 256 * 1024 - meta.buffer.buf_rem;
	}
	{
		struct vm_snapshot_meta meta = {
			.dev_name = "xhci", .dev_data = pi,
			.op = VM_SNAPSHOT_VALIDATE,
			.buffer = { .buf = buf, .buf_rem = used,
			    .buf_start = buf, .buf_size = used },
		};
		ATF_CHECK_EQ(0, pci_xhci_snapshot(&meta));
	}
	{
		struct vm_snapshot_meta meta = {
			.dev_name = "xhci", .dev_data = pi,
			.op = VM_SNAPSHOT_RESTORE,
			.buffer = { .buf = buf, .buf_rem = used,
			    .buf_start = buf, .buf_size = used },
		};
		ATF_CHECK_EQ(0, pci_xhci_snapshot(&meta));
	}
	free(buf);
}

/* Fixed byte offsets of the operational/runtime fields in the device image. */
#define	SNAP_DCBAA_P	88
#define	SNAP_ERSTBA	116
#define	SNAP_ERSTBA_P	132
#define	SNAP_ERST_P	140
#define	SNAP_EVCOUNT	148
#define	SNAP_EVBASE	152
#define	SNAP_ER_DEQ_SEG	160
#define	SNAP_DEVMASK	180
#define	SNAP_RESTORE_IDX 184
#define	SNAP_DNAME	188
/* one present device: sanity(restore_idx+dname)=132, portregs=16 -> maps@332 */
#define	SNAP_MAPS1	332
#define	SNAP_DEVCTX	336

static int
snap_op(struct pci_devinst *pi, uint8_t *buf, size_t used, enum vm_snapshot_op op)
{
	struct vm_snapshot_meta meta = {
		.dev_name = "xhci", .dev_data = pi, .op = op,
		.buffer = { .buf = buf, .buf_rem = used,
		    .buf_start = buf, .buf_size = used },
	};

	return (pci_xhci_snapshot(&meta));
}

ATF_TC_WITHOUT_HEAD(snapshot_main_validation);
ATF_TC_BODY(snapshot_main_validation, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	uint8_t *good, *work;
	size_t used;

	pi = setup_addressed(&rm);
	sc = pi->pi_arg;
	good = malloc(256 * 1024);
	work = malloc(256 * 1024);
	ATF_REQUIRE(good != NULL && work != NULL);

	/* A live event-ring geometry that no longer matches its ERST fails SAVE. */
	sc->rtsregs.er_event_count = 8;		/* real mapped table size is 16 */
	ATF_CHECK(snap_op(pi, work, 256 * 1024, VM_SNAPSHOT_SAVE) != 0);
	sc->rtsregs.er_event_count = ORA_EVCOUNT;

	/* Produce a known-good image to corrupt. */
	{
		struct vm_snapshot_meta meta = {
			.dev_name = "xhci", .dev_data = pi,
			.op = VM_SNAPSHOT_SAVE,
			.buffer = { .buf = good, .buf_rem = 256 * 1024,
			    .buf_start = good, .buf_size = 256 * 1024 },
		};
		ATF_REQUIRE_EQ(0, pci_xhci_snapshot(&meta));
		used = 256 * 1024 - meta.buffer.buf_rem;
	}

	/* VALIDATE is non-destructive; use it for the load-time validation arms. */
	ATF_CHECK_EQ(0, snap_op(pi, good, used, VM_SNAPSHOT_VALIDATE));

	/* An unmappable device-context-base-array pointer is rejected. */
	memcpy(work, good, used); le64enc(work + SNAP_DCBAA_P, 0x300000ULL);
	ATF_CHECK(snap_op(pi, work, used, VM_SNAPSHOT_VALIDATE) != 0);

	/* An unmappable ERST base pointer is rejected. */
	memcpy(work, good, used); le64enc(work + SNAP_ERSTBA_P, 0x300000ULL);
	ATF_CHECK(snap_op(pi, work, used, VM_SNAPSHOT_VALIDATE) != 0);

	/* An unmappable event-ring segment pointer is rejected. */
	memcpy(work, good, used); le64enc(work + SNAP_ERST_P, 0x300000ULL);
	ATF_CHECK(snap_op(pi, work, used, VM_SNAPSHOT_VALIDATE) != 0);

	/* An event-ring base that does not match the mapped ring is rejected. */
	memcpy(work, good, used); le64enc(work + SNAP_EVBASE, 0x300000ULL);
	ATF_CHECK(snap_op(pi, work, used, VM_SNAPSHOT_VALIDATE) != 0);

	/* A non-zero dequeue segment (multi-segment rings unsupported). */
	memcpy(work, good, used); le32enc(work + SNAP_ER_DEQ_SEG, 1);
	ATF_CHECK(snap_op(pi, work, used, VM_SNAPSHOT_VALIDATE) != 0);

	/* A device presence mask that differs from the live topology. */
	memcpy(work, good, used); le32enc(work + SNAP_DEVMASK, 0xdead);
	ATF_CHECK(snap_op(pi, work, used, VM_SNAPSHOT_VALIDATE) != 0);

	/* A restore index that does not match its device slot. */
	memcpy(work, good, used); le32enc(work + SNAP_RESTORE_IDX, 5);
	ATF_CHECK(snap_op(pi, work, used, VM_SNAPSHOT_VALIDATE) != 0);

	/* A device-model name that differs from the live device. */
	memcpy(work, good, used); work[SNAP_DNAME] ^= 0xff;
	ATF_CHECK(snap_op(pi, work, used, VM_SNAPSHOT_VALIDATE) != 0);

	/* A slot->device map entry out of range is rejected. */
	memcpy(work, good, used); le32enc(work + SNAP_MAPS1, 99);
	ATF_CHECK(snap_op(pi, work, used, VM_SNAPSHOT_VALIDATE) != 0);

	/* A slot->device map entry that disagrees with the live topology. */
	memcpy(work, good, used); le32enc(work + SNAP_MAPS1, 2);
	ATF_CHECK(snap_op(pi, work, used, VM_SNAPSHOT_VALIDATE) != 0);

	/* An unmappable device-context pointer is rejected. */
	memcpy(work, good, used); le64enc(work + SNAP_DEVCTX, 0x300000ULL);
	ATF_CHECK(snap_op(pi, work, used, VM_SNAPSHOT_VALIDATE) != 0);

	/* A device model without a snapshot handler is unsupported. */
	g_mock_ue.ue_snapshot = NULL;
	ATF_CHECK(snap_op(pi, good, used, VM_SNAPSHOT_VALIDATE) != 0);
	g_mock_ue.ue_snapshot = mock_ue_snapshot;

	/*
	 * The ERST table size disagreeing with the serialized event count is
	 * only caught during the committing restore remap, so drive RESTORE.
	 */
	memcpy(work, good, used); le32enc(work + SNAP_EVCOUNT, 8);
	ATF_CHECK(snap_op(pi, work, used, VM_SNAPSHOT_RESTORE) != 0);

	/*
	 * A device-context pointer that decodes to a different guest address
	 * than the DCBAA resolves is only caught on the committing restore.
	 */
	memcpy(work, good, used); le64enc(work + SNAP_DEVCTX, 0x100000ULL);
	ATF_CHECK(snap_op(pi, work, used, VM_SNAPSHOT_RESTORE) != 0);

	/* A null device context with an active slot state is inconsistent. */
	memcpy(work, good, used); le64enc(work + SNAP_DEVCTX, UINT64_MAX);
	ATF_CHECK(snap_op(pi, work, used, VM_SNAPSHOT_RESTORE) != 0);

	/*
	 * A null ERST paired with a non-zero event count is inconsistent.  The
	 * pointer-presence relationship is only realized on the committing
	 * restore (VALIDATE keeps the live pointers), so drive RESTORE last.
	 */
	memcpy(work, good, used);
	le64enc(work + SNAP_ERSTBA, 0);
	le64enc(work + SNAP_ERSTBA_P, UINT64_MAX);	/* -1 decodes to NULL */
	le64enc(work + SNAP_ERST_P, UINT64_MAX);
	le32enc(work + SNAP_EVCOUNT, 5);
	le64enc(work + SNAP_EVBASE, 0);
	ATF_CHECK(snap_op(pi, work, used, VM_SNAPSHOT_RESTORE) != 0);

	free(good);
	free(work);
}

ATF_TC_WITHOUT_HEAD(snapshot_negative_cases);
ATF_TC_BODY(snapshot_negative_cases, tc)
{
	struct pci_devinst *pi;
	struct regmap rm;
	uint8_t *buf, *good;
	size_t used;

	pi = setup_addressed(&rm);
	buf = malloc(256 * 1024);
	good = malloc(256 * 1024);
	ATF_REQUIRE(buf != NULL && good != NULL);

	/* Produce a known-good image. */
	{
		struct vm_snapshot_meta meta = {
			.dev_name = "xhci", .dev_data = pi,
			.op = VM_SNAPSHOT_SAVE,
			.buffer = { .buf = good, .buf_rem = 256 * 1024,
			    .buf_start = good, .buf_size = 256 * 1024 },
		};
		ATF_REQUIRE_EQ(0, pci_xhci_snapshot(&meta));
		used = 256 * 1024 - meta.buffer.buf_rem;
	}

	/* A version mismatch (second LE32 word) is refused. */
	memcpy(buf, good, used);
	buf[4] ^= 0xff;
	{
		struct vm_snapshot_meta meta = {
			.dev_name = "xhci", .dev_data = pi,
			.op = VM_SNAPSHOT_RESTORE,
			.buffer = { .buf = buf, .buf_rem = used,
			    .buf_start = buf, .buf_size = used },
		};
		ATF_CHECK(pci_xhci_snapshot(&meta) != 0);
	}

	/* A capability-register mismatch (CAPLENGTH word) is refused. */
	memcpy(buf, good, used);
	buf[8] ^= 0xff;
	{
		struct vm_snapshot_meta meta = {
			.dev_name = "xhci", .dev_data = pi,
			.op = VM_SNAPSHOT_RESTORE,
			.buffer = { .buf = buf, .buf_rem = used,
			    .buf_start = buf, .buf_size = used },
		};
		ATF_CHECK(pci_xhci_snapshot(&meta) != 0);
	}

	/*
	 * Corrupt individual serialized operational-register fields and confirm
	 * each is rejected on restore.  The layout is a fixed LE sequence:
	 * magic(4) version(4) then nine capability words (36) then
	 * usbcmd(4) usbsts(4) pgsz(4) dnctrl(4) crcr(8) dcbaap(8) config(4).
	 */
#define	OFF_USBCMD	(4 + 4 + 36)
#define	OFF_PGSZ	(OFF_USBCMD + 8)
#define	OFF_CONFIG	(OFF_USBCMD + 4 + 4 + 4 + 4 + 8 + 8)
	/* An impossible PAGESIZE value is refused. */
	memcpy(buf, good, used);
	buf[OFF_PGSZ] ^= 0x02;
	{
		struct vm_snapshot_meta meta = {
			.dev_name = "xhci", .dev_data = pi,
			.op = VM_SNAPSHOT_RESTORE,
			.buffer = { .buf = buf, .buf_rem = used,
			    .buf_start = buf, .buf_size = used },
		};
		ATF_CHECK(pci_xhci_snapshot(&meta) != 0);
	}
	/* USBCMD reserved bits set is refused. */
	memcpy(buf, good, used);
	buf[OFF_USBCMD + 3] = 0xff;
	{
		struct vm_snapshot_meta meta = {
			.dev_name = "xhci", .dev_data = pi,
			.op = VM_SNAPSHOT_RESTORE,
			.buffer = { .buf = buf, .buf_rem = used,
			    .buf_start = buf, .buf_size = used },
		};
		ATF_CHECK(pci_xhci_snapshot(&meta) != 0);
	}
	/* A CONFIG slot count beyond the maximum is refused. */
	memcpy(buf, good, used);
	buf[OFF_CONFIG] = 0xff;
	buf[OFF_CONFIG + 1] = 0x03;
	{
		struct vm_snapshot_meta meta = {
			.dev_name = "xhci", .dev_data = pi,
			.op = VM_SNAPSHOT_RESTORE,
			.buffer = { .buf = buf, .buf_rem = used,
			    .buf_start = buf, .buf_size = used },
		};
		ATF_CHECK(pci_xhci_snapshot(&meta) != 0);
	}

	/* An event-ring segment size other than one is refused (offset 108). */
	memcpy(buf, good, used);
	buf[108] = 2;
	{
		struct vm_snapshot_meta meta = {
			.dev_name = "xhci", .dev_data = pi,
			.op = VM_SNAPSHOT_RESTORE,
			.buffer = { .buf = buf, .buf_rem = used,
			    .buf_start = buf, .buf_size = used },
		};
		ATF_CHECK(pci_xhci_snapshot(&meta) != 0);
	}

	/* An out-of-range MFINDEX is refused (offset 96). */
	memcpy(buf, good, used);
	buf[98] = 0xff;
	{
		struct vm_snapshot_meta meta = {
			.dev_name = "xhci", .dev_data = pi,
			.op = VM_SNAPSHOT_RESTORE,
			.buffer = { .buf = buf, .buf_rem = used,
			    .buf_start = buf, .buf_size = used },
		};
		ATF_CHECK(pci_xhci_snapshot(&meta) != 0);
	}

	/* A truncated image surfaces the codec error at several depths. */
	{
		size_t depth;
		for (depth = 4; depth < used; depth += 40) {
			struct vm_snapshot_meta meta = {
				.dev_name = "xhci", .dev_data = pi,
				.op = VM_SNAPSHOT_RESTORE,
				.buffer = { .buf = buf, .buf_rem = depth,
				    .buf_start = buf, .buf_size = depth },
			};
			memcpy(buf, good, used);
			(void)pci_xhci_snapshot(&meta);
		}
	}

	free(buf);
	free(good);
}

ATF_TC_WITHOUT_HEAD(pause_resume_fence);
ATF_TC_BODY(pause_resume_fence, tc)
{
	struct pci_devinst *pi;
	struct regmap rm;

	full_reset();
	pi = bring_up(&rm);

	/* Pause acquires the fence; a second pause is rejected. */
	ATF_CHECK_EQ(0, pci_xhci_pause(pi));
	ATF_CHECK_EQ(EINVAL, pci_xhci_pause(pi));

	/* Resume releases it; a second resume is rejected. */
	ATF_CHECK_EQ(0, pci_xhci_resume(pi));
	ATF_CHECK_EQ(EINVAL, pci_xhci_resume(pi));

	/* A paused controller drops backend interrupts (fence honored). */
	(void)address_slot1(&rm, pi, 0);
	ATF_CHECK_EQ(0, pci_xhci_pause(pi));
	ATF_CHECK_EQ(0, g_last_hci->hci_intr(g_last_hci, 0x81));
	ATF_CHECK_EQ(0, pci_xhci_resume(pi));
}
#endif /* BHYVE_SNAPSHOT */

ATF_TC_WITHOUT_HEAD(port_link_state_writes);
ATF_TC_BODY(port_link_state_writes, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	uint64_t p1;

	full_reset();
	pi = bring_up(&rm);
	sc = pi->pi_arg;
	p1 = XHCI_CAPLEN + XHCI_PORTREGS_PORT0 + 1 * XHCI_PORTREGS_SETSZ;

	/*
	 * Link-state write (LWS) to U3 then U0 posts a resume change event.
	 * A guest keeps PP asserted across the write (the PORTSC write mask
	 * drops any power bit the guest omits).
	 */
	pci_xhci_write(pi, 0, p1, 4,
	    XHCI_PS_PP | XHCI_PS_LWS | XHCI_PS_PLS_SET(3));
	ATF_CHECK_EQ(3, XHCI_PS_PLS_GET(pci_xhci_read(pi, 0, p1, 4)));
	pci_xhci_write(pi, 0, p1, 4,
	    XHCI_PS_PP | XHCI_PS_LWS | XHCI_PS_PLS_SET(0));
	ATF_CHECK_EQ(0, XHCI_PS_PLS_GET(pci_xhci_read(pi, 0, p1, 4)));

	/* A write with no LWS is a status/control write, not a PLS change. */
	pci_xhci_write(pi, 0, p1, 4, XHCI_PS_PP | XHCI_PS_CSC); /* clears CSC */
	pci_xhci_write(pi, 0, p1, 4, XHCI_PS_PP | XHCI_PS_PED); /* disable req */

	/* An unhandled link state (e.g. 5) with LWS is ignored gracefully. */
	pci_xhci_write(pi, 0, p1, 4,
	    XHCI_PS_PP | XHCI_PS_LWS | XHCI_PS_PLS_SET(5));

	/* Warm port reset. */
	pci_xhci_write(pi, 0, p1, 4, XHCI_PS_WPR);

	/* An unaligned port-register write hits the default arm. */
	pci_xhci_write(pi, 0, p1 + 2, 4, 0);

	/* Writes routed to internal helper for BAR-unreachable edges. */
	pci_xhci_portregs_write(sc, XHCI_PORTREGS_PORT0, 0);	/* port 0 */
	pci_xhci_portregs_write(sc,
	    XHCI_PORTREGS_PORT0 + 4 * XHCI_PORTREGS_SETSZ, XHCI_PS_LWS);
	(void)sc;
}

ATF_TC_WITHOUT_HEAD(transfer_trb_variants);
ATF_TC_BODY(transfer_trb_variants, tc)
{
	struct pci_devinst *pi;
	struct regmap rm;

	/* SETUP without IDT is rejected (xHCI 6.4.1.2.1). */
	pi = setup_addressed(&rm);
	put_trb(EP0RING_GPA, 0, 0, XHCI_TRB_2_BYTES_SET(8),
	    TT(SETUP_STAGE) | XHCI_TRB_3_IOC_BIT | XHCI_TRB_3_CYCLE_BIT);
	ring_ep_doorbell(&rm, pi, 1, 1, 0);
	ATF_CHECK_EQ(0, g_ue_request_calls);

	/* A NORMAL TRB inside a control-scope batch is rejected. */
	pi = setup_addressed(&rm);
	put_trb(EP0RING_GPA, 0, 0x1122334455667788ULL, XHCI_TRB_2_BYTES_SET(8),
	    TT(SETUP_STAGE) | XHCI_TRB_3_IDT_BIT | XHCI_TRB_3_CHAIN_BIT |
	    XHCI_TRB_3_CYCLE_BIT);
	put_trb(EP0RING_GPA, 1, DATA_GPA, XHCI_TRB_2_BYTES_SET(8),
	    TT(NORMAL) | XHCI_TRB_3_CYCLE_BIT);
	ring_ep_doorbell(&rm, pi, 1, 1, 0);

	/* Immediate-data (IDT) OUT data stage copies from the TRB itself. */
	pi = setup_addressed(&rm);
	put_trb(EP0RING_GPA, 0, 0x1122334455667788ULL, XHCI_TRB_2_BYTES_SET(8),
	    TT(SETUP_STAGE) | XHCI_TRB_3_IDT_BIT | XHCI_TRB_3_CHAIN_BIT |
	    XHCI_TRB_3_CYCLE_BIT);
	put_trb(EP0RING_GPA, 1, 0xDEADBEEFULL, XHCI_TRB_2_BYTES_SET(8),
	    TT(DATA_STAGE) | XHCI_TRB_3_IDT_BIT | XHCI_TRB_3_CHAIN_BIT |
	    XHCI_TRB_3_CYCLE_BIT);
	put_trb(EP0RING_GPA, 2, 0, 0,
	    TT(STATUS_STAGE) | XHCI_TRB_3_IOC_BIT | XHCI_TRB_3_CYCLE_BIT);
	ring_ep_doorbell(&rm, pi, 1, 1, 0);
	ATF_CHECK(g_ue_request_calls >= 1);

	/* An IDT data stage that is too large is rejected. */
	pi = setup_addressed(&rm);
	put_trb(EP0RING_GPA, 0, 0x1122334455667788ULL, XHCI_TRB_2_BYTES_SET(8),
	    TT(SETUP_STAGE) | XHCI_TRB_3_IDT_BIT | XHCI_TRB_3_CHAIN_BIT |
	    XHCI_TRB_3_CYCLE_BIT);
	put_trb(EP0RING_GPA, 1, 0, XHCI_TRB_2_BYTES_SET(64),
	    TT(DATA_STAGE) | XHCI_TRB_3_IDT_BIT | XHCI_TRB_3_CHAIN_BIT |
	    XHCI_TRB_3_CYCLE_BIT);
	ring_ep_doorbell(&rm, pi, 1, 1, 0);

	/* A zero-length data stage yields a NULL buffer (valid). */
	pi = setup_addressed(&rm);
	put_trb(EP0RING_GPA, 0, 0x1122334455667788ULL, XHCI_TRB_2_BYTES_SET(8),
	    TT(SETUP_STAGE) | XHCI_TRB_3_IDT_BIT | XHCI_TRB_3_CHAIN_BIT |
	    XHCI_TRB_3_CYCLE_BIT);
	put_trb(EP0RING_GPA, 1, 0, XHCI_TRB_2_BYTES_SET(0),
	    TT(DATA_STAGE) | XHCI_TRB_3_CHAIN_BIT | XHCI_TRB_3_CYCLE_BIT);
	put_trb(EP0RING_GPA, 2, 0, 0,
	    TT(STATUS_STAGE) | XHCI_TRB_3_IOC_BIT | XHCI_TRB_3_CYCLE_BIT);
	ring_ep_doorbell(&rm, pi, 1, 1, 0);

	/* A data stage whose buffer cannot be mapped reports a data-buf error. */
	pi = setup_addressed(&rm);
	put_trb(EP0RING_GPA, 0, 0x1122334455667788ULL, XHCI_TRB_2_BYTES_SET(8),
	    TT(SETUP_STAGE) | XHCI_TRB_3_IDT_BIT | XHCI_TRB_3_CHAIN_BIT |
	    XHCI_TRB_3_CYCLE_BIT);
	put_trb(EP0RING_GPA, 1, DATA_GPA, XHCI_TRB_2_BYTES_SET(16),
	    TT(DATA_STAGE) | XHCI_TRB_3_CHAIN_BIT | XHCI_TRB_3_CYCLE_BIT);
	put_trb(EP0RING_GPA, 2, 0, 0,
	    TT(STATUS_STAGE) | XHCI_TRB_3_IOC_BIT | XHCI_TRB_3_CYCLE_BIT);
	g_map_fail_from = DATA_GPA;
	ring_ep_doorbell(&rm, pi, 1, 1, 0);
	g_map_fail_from = UINT64_MAX;
}

ATF_TC_WITHOUT_HEAD(transfer_noop_and_event_data);
ATF_TC_BODY(transfer_noop_and_event_data, tc)
{
	struct pci_devinst *pi;
	struct regmap rm;
	struct xhci_input_dev_ctx *in2;
	struct xhci_trb *ev;

	pi = setup_addressed(&rm);
	in2 = ram_ptr(INPUT2_GPA);

	/* Configure a bulk IN endpoint (epid 3) with its own ring. */
	memset(in2, 0, sizeof(*in2));
	in2->ctx_input.dwInCtx1 = 0x01 | XHCI_INCTX_1_ADD_MASK(3);
	in2->ctx_ep[3].qwEpCtx2 = EPXRING_GPA | 0x1;
	put_trb(CR_GPA, 2, INPUT2_GPA, 0,
	    TT(CONFIGURE_EP) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(pi->pi_arg);
	ATF_REQUIRE_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* A NORMAL IN transfer followed by an EVENT_DATA TRB with IOC. */
	put_trb(EPXRING_GPA, 0, DATA_GPA, XHCI_TRB_2_BYTES_SET(32),
	    TT(NORMAL) | XHCI_TRB_3_CHAIN_BIT | XHCI_TRB_3_CYCLE_BIT);
	put_trb(EPXRING_GPA, 1, 0xCAFE, 0,
	    TT(EVENT_DATA) | XHCI_TRB_3_IOC_BIT | XHCI_TRB_3_CYCLE_BIT);
	ring_ep_doorbell(&rm, pi, 1, 3, 0);
	ATF_CHECK(g_ue_data_calls >= 1);

	/* A NOOP transfer TRB is accepted and self-completes. */
	put_trb(EPXRING_GPA, 2, 0, 0,
	    TT(NOOP) | XHCI_TRB_3_IOC_BIT | XHCI_TRB_3_CYCLE_BIT);
	ring_ep_doorbell(&rm, pi, 1, 3, 0);
}

ATF_TC_WITHOUT_HEAD(event_ring_full_handling);
ATF_TC_BODY(event_ring_full_handling, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	int i;

	full_reset();
	pi = bring_up(&rm);
	sc = pi->pi_arg;

	/*
	 * Queue more No-Op commands than the 16-entry event ring can hold
	 * without the guest advancing ERDP.  The controller must post an
	 * event-ring-full host controller event and halt on host error.
	 */
	for (i = 0; i < 40; i++)
		put_trb(CR_GPA, i, 0, 0, TT(NOOP_CMD) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);

	/*
	 * The ring saturated at its usable capacity without overflowing
	 * (xHCI 4.9.4: the last entry is reserved for the ring-full event),
	 * and the enqueue index stayed within bounds.
	 */
	ATF_CHECK(sc->rtsregs.er_events_cnt >= sc->rtsregs.er_event_count - 1);
	ATF_CHECK((uint32_t)sc->rtsregs.er_enq_idx < sc->rtsregs.er_event_count);

	/*
	 * Drive the reserved-slot ring-full event deterministically: with the
	 * ring one short of full and the next enqueue slot's cycle bit equal to
	 * the producer cycle state, insert_event must emit a Host Controller
	 * event with the Event Ring Full completion code (xHCI 6.4.2.1).
	 */
	{
		struct xhci_trb evt, *slot;
		int idx;

		sc->rtsregs.er_events_cnt = sc->rtsregs.er_event_count - 1;
		slot = &sc->rtsregs.erst_p[sc->rtsregs.er_enq_idx];
		slot->dwTrb3 = (slot->dwTrb3 & ~1U) | (sc->rtsregs.event_pcs & 1U);
		idx = sc->rtsregs.er_enq_idx;
		pci_xhci_set_evtrb(&evt, 1, XHCI_TRB_ERROR_SUCCESS,
		    XHCI_TRB_EVENT_PORT_STS_CHANGE);
		ATF_CHECK_EQ(XHCI_TRB_ERROR_EV_RING_FULL,
		    pci_xhci_insert_event(sc, &evt, 0));
		ATF_CHECK_EQ(XHCI_TRB_EVENT_HOST_CTRL,
		    XHCI_TRB_3_TYPE_GET(ev_trb(idx)->dwTrb3));
		ATF_CHECK_EQ(XHCI_TRB_ERROR_EV_RING_FULL,
		    XHCI_TRB_2_ERROR_GET(ev_trb(idx)->dwTrb2));
	}
}

ATF_TC_WITHOUT_HEAD(parse_devices_limits);
ATF_TC_BODY(parse_devices_limits, tc)
{
	nvlist_t *nvl, *slots, *s;
	char name[8];
	int i;

	/* More than four USB3 devices exceeds the per-speed maximum. */
	full_reset();
	nvl = cfg_new();
	slots = create_relative_config_node(nvl, "slot");
	for (i = 1; i <= 6; i++) {
		snprintf(name, sizeof(name), "%d", i);
		s = create_relative_config_node(slots, name);
		set_config_value_node(s, "device", "tablet");
	}
	ATF_CHECK_EQ(-1, pci_xhci_init(make_pi(), nvl));

	/* A non-nvlist variable directly under the slot node is rejected. */
	full_reset();
	nvl = cfg_new();
	slots = create_relative_config_node(nvl, "slot");
	set_config_value_node(slots, "bogus", "value");
	ATF_CHECK_EQ(-1, pci_xhci_init(make_pi(), nvl));
}

ATF_TC_WITHOUT_HEAD(command_error_matrix);
ATF_TC_BODY(command_error_matrix, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_input_dev_ctx *in = ram_ptr(INPUT_GPA);
	struct xhci_trb *ev;

	pi = setup_addressed(&rm);
	sc = pi->pi_arg;
	in = ram_ptr(INPUT_GPA);

	/* Address Device with an invalid input control context. */
	memset(in, 0, sizeof(*in));
	in->ctx_input.dwInCtx1 = 0x02;	/* not slot+ep0 */
	put_trb(CR_GPA, 2, INPUT_GPA, 0,
	    TT(ADDRESS_DEVICE) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_TRB, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Address Device whose input context cannot be mapped. */
	put_trb(CR_GPA, 3, INPUT_GPA, 0,
	    TT(ADDRESS_DEVICE) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	g_map_fail_from = INPUT_GPA;
	ring_cmd_doorbell(&rm, pi);
	g_map_fail_from = UINT64_MAX;
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_PARAMETER, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Configure EP with an invalid input control context. */
	memset(in, 0, sizeof(*in));
	in->ctx_input.dwInCtx0 = 0x03;	/* illegal drop bits */
	put_trb(CR_GPA, 4, INPUT_GPA, 0,
	    TT(CONFIGURE_EP) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_TRB, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Evaluate Context with an invalid input control context. */
	memset(in, 0, sizeof(*in));
	in->ctx_input.dwInCtx0 = 0x04;
	put_trb(CR_GPA, 5, INPUT_GPA, 0,
	    TT(EVALUATE_CTX) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_TRB, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Reset Endpoint with an out-of-range endpoint id. */
	put_trb(CR_GPA, 6, 0, 0,
	    TT(RESET_EP) | XHCI_TRB_3_EP_SET(0) | XHCI_TRB_3_SLOT_SET(1) |
	    XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_TRB, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Set TR Dequeue on a running endpoint reports a context-state error. */
	put_trb(CR_GPA, 7, EP0RING_GPA | 0x1, 0,
	    TT(SET_TR_DEQUEUE) | XHCI_TRB_3_EP_SET(1) | XHCI_TRB_3_SLOT_SET(1) |
	    XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_CONTEXT_STATE,
	    XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
}

ATF_TC_WITHOUT_HEAD(streams_endpoint);
ATF_TC_BODY(streams_endpoint, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_input_dev_ctx *in2;
	struct xhci_stream_ctx *sctx;
	struct xhci_trb *ev;

	pi = setup_addressed(&rm);
	sc = pi->pi_arg;
	in2 = ram_ptr(INPUT2_GPA);
	sctx = ram_ptr(STREAM_CTX_GPA);

	/* Primary stream context array with one usable stream (id 1). */
	memset(sctx, 0, 8 * sizeof(*sctx));
	sctx[1].qwSctx0 = STREAMRING1_GPA |
	    XHCI_SCTX_0_SCT_SET(XHCI_SCTX_0_SCT_PRIM_TR_RING) | 0x1;

	/* Configure a streams-capable bulk IN endpoint (epid 3). */
	memset(in2, 0, sizeof(*in2));
	in2->ctx_input.dwInCtx1 = 0x01 | XHCI_INCTX_1_ADD_MASK(3);
	in2->ctx_ep[3].dwEpCtx0 = XHCI_EPCTX_0_MAXP_STREAMS_SET(1) |
	    XHCI_EPCTX_0_LSA_SET(1);
	in2->ctx_ep[3].qwEpCtx2 = STREAM_CTX_GPA | 0x1;
	put_trb(CR_GPA, 2, INPUT2_GPA, 0,
	    TT(CONFIGURE_EP) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_REQUIRE_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Invalid stream ids on the doorbell are silently dropped. */
	ring_ep_doorbell(&rm, pi, 1, 3, 0);		/* streamid 0 */
	ring_ep_doorbell(&rm, pi, 1, 3, 65535);		/* any-stream */
	ring_ep_doorbell(&rm, pi, 1, 3, 65534);		/* prime */
	ATF_CHECK_EQ(0, g_ue_data_calls);

	/* A valid primary-stream transfer is delivered to the device. */
	put_trb(STREAMRING1_GPA, 0, DATA_GPA, XHCI_TRB_2_BYTES_SET(16),
	    TT(NORMAL) | XHCI_TRB_3_IOC_BIT | XHCI_TRB_3_CYCLE_BIT);
	ring_ep_doorbell(&rm, pi, 1, 3, 1);
	ATF_CHECK(g_ue_data_calls >= 1);

	/* Stop the endpoint, then relocate its stream transfer ring. */
	put_trb(CR_GPA, 3, 0, 0,
	    TT(STOP_EP) | XHCI_TRB_3_EP_SET(3) | XHCI_TRB_3_SLOT_SET(1) |
	    XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/*
	 * Relocate the primary stream's transfer ring.  The completed transfer
	 * rewrote the stream context's ring pointer (clearing its SCT field), so
	 * the guest re-publishes a valid stream context before Set TR Dequeue.
	 */
	sctx[1].qwSctx0 = STREAMRING1_GPA |
	    XHCI_SCTX_0_SCT_SET(XHCI_SCTX_0_SCT_PRIM_TR_RING) | 0x1;
	put_trb(CR_GPA, 4, STREAMRING1_GPA | 0x1,
	    XHCI_TRB_2_STREAM_SET(1),
	    TT(SET_TR_DEQUEUE) | XHCI_TRB_3_EP_SET(3) | XHCI_TRB_3_SLOT_SET(1) |
	    XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
}

ATF_TC_WITHOUT_HEAD(dev_intr_resume_and_disabled);
ATF_TC_BODY(dev_intr_resume_and_disabled, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	uint64_t p1;

	pi = setup_addressed(&rm);
	sc = pi->pi_arg;

	/* Suspend the port link (U3); a backend interrupt raises a resume. */
	p1 = XHCI_CAPLEN + XHCI_PORTREGS_PORT0 + 1 * XHCI_PORTREGS_SETSZ;
	pci_xhci_write(pi, 0, p1, 4,
	    XHCI_PS_PP | XHCI_PS_LWS | XHCI_PS_PLS_SET(3));
	ATF_CHECK_EQ(0, g_last_hci->hci_intr(g_last_hci, 0x81)); /* ep1 IN */

	/* An interrupt for a disabled endpoint is a no-op. */
	ATF_CHECK_EQ(0, g_last_hci->hci_intr(g_last_hci, 0x82)); /* ep2 IN */
	(void)sc;
}

ATF_TC_WITHOUT_HEAD(host_controller_reset_with_device);
ATF_TC_BODY(host_controller_reset_with_device, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;

	pi = setup_addressed(&rm);
	sc = pi->pi_arg;

	/* HCRST tears down assigned slots and returns to the halted default. */
	op_write(pi, XHCI_USBCMD, XHCI_CMD_HCRST);
	ATF_CHECK((op_read(pi, XHCI_USBSTS) & XHCI_STS_HCH) != 0);
	ATF_CHECK_EQ(XHCI_ST_DISABLED, XHCI_SLOTDEV_PTR(sc, 1)->dev_slotstate);
	ATF_CHECK(sc->rtsregs.erstba_p == NULL);
}

#ifdef BHYVE_SNAPSHOT
ATF_TC_WITHOUT_HEAD(snapshot_after_control_transfer);
ATF_TC_BODY(snapshot_after_control_transfer, tc)
{
	struct pci_devinst *pi;
	struct regmap rm;
	uint8_t *buf;
	size_t used;

	pi = setup_addressed(&rm);

	/* Run a control transfer so ep0's xfer carries a setup request. */
	put_trb(EP0RING_GPA, 0, 0x1122334455667788ULL, XHCI_TRB_2_BYTES_SET(8),
	    TT(SETUP_STAGE) | XHCI_TRB_3_IDT_BIT | XHCI_TRB_3_CHAIN_BIT |
	    XHCI_TRB_3_CYCLE_BIT);
	put_trb(EP0RING_GPA, 1, 0, 0,
	    TT(STATUS_STAGE) | XHCI_TRB_3_IOC_BIT | XHCI_TRB_3_CYCLE_BIT);
	ring_ep_doorbell(&rm, pi, 1, 1, 0);

	buf = malloc(256 * 1024);
	ATF_REQUIRE(buf != NULL);
	{
		struct vm_snapshot_meta meta = {
			.dev_name = "xhci", .dev_data = pi,
			.op = VM_SNAPSHOT_SAVE,
			.buffer = { .buf = buf, .buf_rem = 256 * 1024,
			    .buf_start = buf, .buf_size = 256 * 1024 },
		};
		ATF_REQUIRE_EQ(0, pci_xhci_snapshot(&meta));
		used = 256 * 1024 - meta.buffer.buf_rem;
	}
	{
		struct vm_snapshot_meta meta = {
			.dev_name = "xhci", .dev_data = pi,
			.op = VM_SNAPSHOT_RESTORE,
			.buffer = { .buf = buf, .buf_rem = used,
			    .buf_start = buf, .buf_size = used },
		};
		ATF_CHECK_EQ(0, pci_xhci_snapshot(&meta));
	}
	free(buf);
}
#endif

ATF_TC_WITHOUT_HEAD(doorbell_register_read);
ATF_TC_BODY(doorbell_register_read, tc)
{
	struct pci_devinst *pi;
	struct regmap rm;

	full_reset();
	pi = bring_up(&rm);
	/* Doorbell registers always read as zero (xHCI 5.6). */
	ATF_CHECK_EQ(0, pci_xhci_read(pi, 0, rm.dboff, 4));
	ATF_CHECK_EQ(0, pci_xhci_read(pi, 0, rm.dboff + 4, 4));
}

ATF_TC_WITHOUT_HEAD(transfer_link_and_bad_type);
ATF_TC_BODY(transfer_link_and_bad_type, tc)
{
	struct pci_devinst *pi;
	struct regmap rm;
	struct xhci_input_dev_ctx *in2;
	struct xhci_trb *ev;

	/* A control transfer ring that threads through a Link TRB. */
	pi = setup_addressed(&rm);
	put_trb(EP0RING_GPA, 0, 0x1122334455667788ULL, XHCI_TRB_2_BYTES_SET(8),
	    TT(SETUP_STAGE) | XHCI_TRB_3_IDT_BIT | XHCI_TRB_3_CHAIN_BIT |
	    XHCI_TRB_3_CYCLE_BIT);
	put_trb(EP0RING_GPA, 1, EP0RING_GPA + 2 * ORA_TRB_SIZE, 0,
	    TT(LINK) | XHCI_TRB_3_CHAIN_BIT | XHCI_TRB_3_CYCLE_BIT);
	put_trb(EP0RING_GPA, 2, 0, 0,
	    TT(STATUS_STAGE) | XHCI_TRB_3_IOC_BIT | XHCI_TRB_3_CYCLE_BIT);
	ring_ep_doorbell(&rm, pi, 1, 1, 0);
	ATF_CHECK(g_ue_request_calls >= 1);

	/* An unexpected TRB type on a bulk endpoint is rejected. */
	pi = setup_addressed(&rm);
	in2 = ram_ptr(INPUT2_GPA);
	memset(in2, 0, sizeof(*in2));
	in2->ctx_input.dwInCtx1 = 0x01 | XHCI_INCTX_1_ADD_MASK(2);
	in2->ctx_ep[2].qwEpCtx2 = EPXRING_GPA | 0x1;
	put_trb(CR_GPA, 2, INPUT2_GPA, 0,
	    TT(CONFIGURE_EP) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(pi->pi_arg);
	ATF_REQUIRE_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	put_trb(EPXRING_GPA, 0, 0, 0,
	    XHCI_TRB_3_TYPE_SET(30) | XHCI_TRB_3_IOC_BIT | XHCI_TRB_3_CYCLE_BIT);
	ring_ep_doorbell(&rm, pi, 1, 2, 0);
}

ATF_TC_WITHOUT_HEAD(command_state_errors);
ATF_TC_BODY(command_state_errors, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_trb *ev;

	full_reset();
	pi = bring_up(&rm);
	sc = pi->pi_arg;

	/* Enable a slot but do not address it. */
	put_trb(CR_GPA, 0, 0, 0, TT(ENABLE_SLOT) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);

	/* Configure Endpoint before Address Device is a context-state error. */
	put_trb(CR_GPA, 1, INPUT_GPA, 0,
	    TT(CONFIGURE_EP) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_CONTEXT_STATE,
	    XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Deconfigure (DC) before Address Device is also context-state. */
	put_trb(CR_GPA, 2, 0, 0,
	    TT(CONFIGURE_EP) | XHCI_TRB_3_DCEP_BIT | XHCI_TRB_3_SLOT_SET(1) |
	    XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_CONTEXT_STATE,
	    XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Now address the slot and stop ep0. */
	pi = setup_addressed(&rm);
	sc = pi->pi_arg;
	put_trb(CR_GPA, 2, 0, 0,
	    TT(STOP_EP) | XHCI_TRB_3_EP_SET(1) | XHCI_TRB_3_SLOT_SET(1) |
	    XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);

	/* Set TR Dequeue with a non-zero stream id on a non-stream endpoint. */
	put_trb(CR_GPA, 3, EP0RING_GPA | 0x1, XHCI_TRB_2_STREAM_SET(1),
	    TT(SET_TR_DEQUEUE) | XHCI_TRB_3_EP_SET(1) | XHCI_TRB_3_SLOT_SET(1) |
	    XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_STREAM_TYPE,
	    XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
}

ATF_TC_WITHOUT_HEAD(insert_event_geometry_errors);
ATF_TC_BODY(insert_event_geometry_errors, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_trb e;

	pci_xhci_set_evtrb(&e, 1, XHCI_TRB_ERROR_SUCCESS,
	    XHCI_TRB_EVENT_PORT_STS_CHANGE);

	/* ERSTSZ that no longer reads as 1 fails the geometry gate. */
	full_reset();
	pi = bring_up(&rm);
	sc = pi->pi_arg;
	sc->rtsregs.intrreg.erstsz = 2;
	ATF_CHECK_EQ(XHCI_TRB_ERROR_EV_RING_FULL,
	    pci_xhci_insert_event(sc, &e, 0));
	ATF_CHECK((sc->opregs.usbsts & XHCI_STS_HSE) != 0);

	/* An enqueue index at/past the ring size is rejected. */
	full_reset();
	pi = bring_up(&rm);
	sc = pi->pi_arg;
	sc->rtsregs.er_enq_idx = (int)sc->rtsregs.er_event_count;
	ATF_CHECK_EQ(XHCI_TRB_ERROR_EV_RING_FULL,
	    pci_xhci_insert_event(sc, &e, 0));

	/* An event-base + size that overflows 64 bits is rejected. */
	full_reset();
	pi = bring_up(&rm);
	sc = pi->pi_arg;
	{
		struct xhci_event_ring_seg *erst = ram_ptr(ERST_GPA);
		uint64_t huge = UINT64_MAX - 8;

		sc->rtsregs.er_event_base = huge;
		erst->qwEvrsTablePtr = huge;
		erst->dwEvrsTableSize = sc->rtsregs.er_event_count;
		ATF_CHECK_EQ(XHCI_TRB_ERROR_EV_RING_FULL,
		    pci_xhci_insert_event(sc, &e, 0));
	}
}

ATF_TC_WITHOUT_HEAD(dev_intr_resume_repeat);
ATF_TC_BODY(dev_intr_resume_repeat, tc)
{
	struct pci_devinst *pi;
	struct regmap rm;
	uint64_t p1;

	pi = setup_addressed(&rm);
	p1 = XHCI_CAPLEN + XHCI_PORTREGS_PORT0 + 1 * XHCI_PORTREGS_SETSZ;
	pci_xhci_write(pi, 0, p1, 4,
	    XHCI_PS_PP | XHCI_PS_LWS | XHCI_PS_PLS_SET(3));

	/* First backend interrupt raises resume and sets PLC. */
	ATF_CHECK_EQ(0, g_last_hci->hci_intr(g_last_hci, 0x81));
	/* A second interrupt with PLC already set short-circuits. */
	ATF_CHECK_EQ(0, g_last_hci->hci_intr(g_last_hci, 0x81));
}

/* Enable slot 1 on a freshly brought-up controller (command index 0). */
static struct pci_devinst *
setup_enabled(struct regmap *rm)
{
	struct pci_devinst *pi;

	full_reset();
	pi = bring_up(rm);
	put_trb(CR_GPA, 0, 0, 0, TT(ENABLE_SLOT) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(rm, pi);
	return (pi);
}

ATF_TC_WITHOUT_HEAD(address_device_error_states);
ATF_TC_BODY(address_device_error_states, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_input_dev_ctx *in;
	struct xhci_trb *ev;

	/* Address Device on a never-enabled (DISABLED) slot -> SLOT_NOT_ON. */
	full_reset();
	pi = bring_up(&rm);
	sc = pi->pi_arg;
	in = ram_ptr(INPUT_GPA);
	memset(in, 0, sizeof(*in));
	in->ctx_input.dwInCtx1 = 0x03;
	in->ctx_ep[1].qwEpCtx2 = EP0RING_GPA | 0x1;
	put_trb(CR_GPA, 0, INPUT_GPA, 0,
	    TT(ADDRESS_DEVICE) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SLOT_NOT_ON,
	    XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Address Device whose endpoint-0 ring cannot be mapped -> PARAMETER. */
	pi = setup_enabled(&rm);
	sc = pi->pi_arg;
	in = ram_ptr(INPUT_GPA);
	memset(in, 0, sizeof(*in));
	in->ctx_input.dwInCtx1 = 0x03;
	in->ctx_ep[1].qwEpCtx2 = 0x1F0000ULL | 0x1;	/* unmappable ring */
	put_trb(CR_GPA, 1, INPUT_GPA, 0,
	    TT(ADDRESS_DEVICE) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	g_map_fail_from = 0x1F0000ULL;
	ring_cmd_doorbell(&rm, pi);
	g_map_fail_from = UINT64_MAX;
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_PARAMETER, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Address Device when the device reset handler fails -> ENDP_NOT_ON. */
	pi = setup_enabled(&rm);
	sc = pi->pi_arg;
	in = ram_ptr(INPUT_GPA);
	memset(in, 0, sizeof(*in));
	in->ctx_input.dwInCtx1 = 0x03;
	in->ctx_ep[1].qwEpCtx2 = EP0RING_GPA | 0x1;
	g_ue_reset_ret = -1;
	put_trb(CR_GPA, 1, INPUT_GPA, 0,
	    TT(ADDRESS_DEVICE) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	g_ue_reset_ret = 0;
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_ENDP_NOT_ON,
	    XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Re-addressing a CONFIGURED slot is a context-state error. */
	pi = setup_addressed(&rm);
	sc = pi->pi_arg;
	{
		struct xhci_input_dev_ctx *in2 = ram_ptr(INPUT2_GPA);
		memset(in2, 0, sizeof(*in2));
		in2->ctx_input.dwInCtx1 = 0x01 | XHCI_INCTX_1_ADD_MASK(2);
		in2->ctx_ep[2].qwEpCtx2 = EPXRING_GPA | 0x1;
		put_trb(CR_GPA, 2, INPUT2_GPA, 0,
		    TT(CONFIGURE_EP) | XHCI_TRB_3_SLOT_SET(1) |
		    XHCI_TRB_3_CYCLE_BIT);
		ring_cmd_doorbell(&rm, pi);
	}
	in = ram_ptr(INPUT_GPA);
	memset(in, 0, sizeof(*in));
	in->ctx_input.dwInCtx1 = 0x03;
	in->ctx_ep[1].qwEpCtx2 = EP0RING_GPA | 0x1;
	put_trb(CR_GPA, 3, INPUT_GPA, 0,
	    TT(ADDRESS_DEVICE) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_CONTEXT_STATE,
	    XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
}

ATF_TC_WITHOUT_HEAD(config_and_eval_more_paths);
ATF_TC_BODY(config_and_eval_more_paths, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_dev_ctx *dctx;
	struct xhci_input_dev_ctx *in2;
	struct xhci_trb *ev;

	pi = setup_addressed(&rm);
	sc = pi->pi_arg;
	dctx = ram_ptr(DEVCTX_GPA);

	/* Configure EP whose endpoint ring cannot be mapped -> PARAMETER. */
	in2 = ram_ptr(INPUT2_GPA);
	memset(in2, 0, sizeof(*in2));
	in2->ctx_input.dwInCtx1 = 0x01 | XHCI_INCTX_1_ADD_MASK(2);
	in2->ctx_ep[2].qwEpCtx2 = 0x1F0000ULL | 0x1;
	put_trb(CR_GPA, 2, INPUT2_GPA, 0,
	    TT(CONFIGURE_EP) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	g_map_fail_from = 0x1F0000ULL;
	ring_cmd_doorbell(&rm, pi);
	g_map_fail_from = UINT64_MAX;
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_PARAMETER, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Evaluate Context updating both the slot and endpoint-0 contexts. */
	memset(in2, 0, sizeof(*in2));
	in2->ctx_input.dwInCtx1 = 0x03;		/* slot + control ctx */
	in2->ctx_slot.dwSctx1 = 0xBEEF;		/* max exit latency */
	in2->ctx_ep[1].dwEpCtx1 = XHCI_EPCTX_1_MAXP_SIZE_SET(256);
	put_trb(CR_GPA, 3, INPUT2_GPA, 0,
	    TT(EVALUATE_CTX) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
	ATF_CHECK_EQ(0xBEEF, dctx->ctx_slot.dwSctx1 & 0xFFFF);
	ATF_CHECK_EQ(256, XHCI_EPCTX_1_MAXP_SIZE_GET(dctx->ctx_ep[1].dwEpCtx1));

	/* Reset Endpoint whose device reset handler fails -> ENDP_NOT_ON. */
	g_ue_reset_ret = -1;
	put_trb(CR_GPA, 4, 0, 0,
	    TT(RESET_EP) | XHCI_TRB_3_EP_SET(1) | XHCI_TRB_3_SLOT_SET(1) |
	    XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	g_ue_reset_ret = 0;
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_ENDP_NOT_ON,
	    XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
}

ATF_TC_WITHOUT_HEAD(operational_register_reads);
ATF_TC_BODY(operational_register_reads, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;

	full_reset();
	pi = bring_up(&rm);
	sc = pi->pi_arg;

	/* Every operational register read path returns its live value. */
	ATF_CHECK_EQ(sc->opregs.usbcmd, op_read(pi, XHCI_USBCMD));
	ATF_CHECK_EQ(sc->opregs.usbsts & 0xFFFFFFFF, op_read(pi, XHCI_USBSTS));
	ATF_CHECK_EQ(XHCI_PAGESIZE_4K, op_read(pi, XHCI_PAGESIZE));
	ATF_CHECK_EQ(sc->opregs.dnctrl, op_read(pi, XHCI_DNCTRL));
	/* CRCR reads back only the command-ring-running bit (xHCI 5.4.5). */
	ATF_CHECK_EQ(sc->opregs.crcr & XHCI_CRCR_LO_CRR, op_read(pi, XHCI_CRCR_LO));
	ATF_CHECK_EQ(0, op_read(pi, XHCI_CRCR_HI));
	/* DCBAAP is split across two 32-bit halves (xHCI 5.4.6). */
	ATF_CHECK_EQ(DCBAA_GPA & 0xFFFFFFFF, op_read(pi, XHCI_DCBAAP_LO));
	ATF_CHECK_EQ(DCBAA_GPA >> 32, op_read(pi, XHCI_DCBAAP_HI));
	ATF_CHECK_EQ(sc->opregs.config, op_read(pi, XHCI_CONFIG));
}

ATF_TC_WITHOUT_HEAD(unsupported_commands);
ATF_TC_BODY(unsupported_commands, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_trb *ev;
	uint32_t types[] = {
		XHCI_TRB_TYPE_NEGOTIATE_BW, XHCI_TRB_TYPE_SET_LATENCY_TOL,
		XHCI_TRB_TYPE_GET_PORT_BW, XHCI_TRB_TYPE_FORCE_HEADER,
	};
	unsigned i;

	full_reset();
	pi = bring_up(&rm);
	sc = pi->pi_arg;

	/* Each optional/unimplemented command reports a TRB error (xHCI 4.6). */
	for (i = 0; i < nitems(types); i++) {
		put_trb(CR_GPA, i, 0, 0,
		    XHCI_TRB_3_TYPE_SET(types[i]) | XHCI_TRB_3_CYCLE_BIT);
		ring_cmd_doorbell(&rm, pi);
		ev = last_event(sc);
		ATF_CHECK_EQ(XHCI_TRB_ERROR_TRB,
		    XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
	}
}

ATF_TC_WITHOUT_HEAD(extended_capability_reads);
ATF_TC_BODY(extended_capability_reads, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	uint32_t base;

	full_reset();
	pi = bring_up(&rm);
	sc = pi->pi_arg;
	base = sc->regsend;

	/* The Supported Protocol capabilities name the USB revisions. */
	ATF_CHECK_EQ(0x20425355, pci_xhci_read(pi, 0, base + 4, 4)); /* "USB " */
	ATF_CHECK_EQ(0x20425355, pci_xhci_read(pi, 0, base + 20, 4));
	/* Reserved dwords read back as zero. */
	ATF_CHECK_EQ(0, pci_xhci_read(pi, 0, base + 12, 4));
	ATF_CHECK_EQ(0, pci_xhci_read(pi, 0, base + 28, 4));
	/* The USB2 / USB3 protocol-defined words carry the compat port base. */
	ATF_CHECK_EQ(sc->usb2_port_start & 0xFF,
	    pci_xhci_read(pi, 0, base + 8, 4) & 0xFF);
	ATF_CHECK_EQ(sc->usb3_port_start & 0xFF,
	    pci_xhci_read(pi, 0, base + 24, 4) & 0xFF);
	/* An offset past the defined xECP words reads as zero. */
	ATF_CHECK_EQ(0, pci_xhci_read(pi, 0, base + 32, 4));
}

ATF_TC_WITHOUT_HEAD(more_command_and_doorbell_edges);
ATF_TC_BODY(more_command_and_doorbell_edges, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_dcbaa *dcbaa;
	struct xhci_trb *ev, *ep0tr;

	pi = setup_addressed(&rm);
	sc = pi->pi_arg;

	/* Set TR Dequeue with an out-of-range endpoint id. */
	put_trb(CR_GPA, 2, 0, 0,
	    TT(SET_TR_DEQUEUE) | XHCI_TRB_3_EP_SET(0) | XHCI_TRB_3_SLOT_SET(1) |
	    XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_TRB, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* A device context whose DCBAA entry is NULL fails lookups. */
	dcbaa = ram_ptr(DCBAA_GPA);
	dcbaa->dcba[1] = 0;
	put_trb(CR_GPA, 3, 0, 0,
	    TT(RESET_DEVICE) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_PARAMETER, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
	dcbaa->dcba[1] = DEVCTX_GPA;

	/* A doorbell whose next TRB is a RESERVED type is ignored. */
	ep0tr = ram_ptr(EP0RING_GPA);
	ep0tr[0].qwTrb0 = 0;
	ep0tr[0].dwTrb2 = 0;
	ep0tr[0].dwTrb3 = XHCI_TRB_3_CYCLE_BIT;	/* type 0 = RESERVED */
	ring_ep_doorbell(&rm, pi, 1, 1, 0);
	ATF_CHECK_EQ(0, g_ue_request_calls);
}

ATF_TC_WITHOUT_HEAD(eval_context_state_and_maps);
ATF_TC_BODY(eval_context_state_and_maps, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;
	struct xhci_trb *ev;

	full_reset();
	pi = bring_up(&rm);
	sc = pi->pi_arg;

	/* Enable a slot but leave it un-addressed (state ENABLED < DEFAULT). */
	put_trb(CR_GPA, 0, 0, 0, TT(ENABLE_SLOT) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);

	/* Evaluate Context before the slot reaches DEFAULT is a state error. */
	put_trb(CR_GPA, 1, INPUT_GPA, 0,
	    TT(EVALUATE_CTX) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	ring_cmd_doorbell(&rm, pi);
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_CONTEXT_STATE,
	    XHCI_TRB_2_ERROR_GET(ev->dwTrb2));

	/* Reset Endpoint whose input context cannot be mapped is addressed. */
	pi = setup_addressed(&rm);
	sc = pi->pi_arg;

	/* Configure EP whose input context cannot be mapped -> PARAMETER. */
	put_trb(CR_GPA, 2, INPUT2_GPA, 0,
	    TT(CONFIGURE_EP) | XHCI_TRB_3_SLOT_SET(1) | XHCI_TRB_3_CYCLE_BIT);
	{
		struct xhci_input_dev_ctx *in2 = ram_ptr(INPUT2_GPA);
		memset(in2, 0, sizeof(*in2));
		in2->ctx_input.dwInCtx1 = 0x01 | XHCI_INCTX_1_ADD_MASK(2);
		in2->ctx_ep[2].qwEpCtx2 = EPXRING_GPA | 0x1;
	}
	g_map_fail_from = INPUT2_GPA;
	ring_cmd_doorbell(&rm, pi);
	g_map_fail_from = UINT64_MAX;
	ev = last_event(sc);
	ATF_CHECK_EQ(XHCI_TRB_ERROR_PARAMETER, XHCI_TRB_2_ERROR_GET(ev->dwTrb2));
}

ATF_TC_WITHOUT_HEAD(portregs_unpowered_write);
ATF_TC_BODY(portregs_unpowered_write, tc)
{
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct regmap rm;

	full_reset();
	pi = bring_up(&rm);
	sc = pi->pi_arg;

	/*
	 * Clearing PP and then writing PORTSC exercises the unpowered-port
	 * guard (xHCI 5.4.8: writes to an unpowered port are dropped).
	 */
	sc->portregs[3].portsc &= ~XHCI_PS_PP;	/* port 4 */
	pci_xhci_portregs_write(sc,
	    XHCI_PORTREGS_PORT0 + 4 * XHCI_PORTREGS_SETSZ,
	    XHCI_PS_LWS | XHCI_PS_PLS_SET(0));

	/* A write to a genuinely unattached (but powered) port is accepted. */
	pci_xhci_portregs_write(sc,
	    XHCI_PORTREGS_PORT0 + 3 * XHCI_PORTREGS_SETSZ,
	    XHCI_PS_PP | XHCI_PS_LWS | XHCI_PS_PLS_SET(0));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, init_and_capability_registers);
	ATF_TP_ADD_TC(tp, init_failure_paths);
	ATF_TP_ADD_TC(tp, legacy_config_translation);
	ATF_TP_ADD_TC(tp, usb2_and_usb3_port_layout);
	ATF_TP_ADD_TC(tp, operational_register_readwrite);
	ATF_TP_ADD_TC(tp, runtime_registers_and_event_ring_setup);
	ATF_TP_ADD_TC(tp, event_ring_setup_rejections);
	ATF_TP_ADD_TC(tp, command_ring_slot_lifecycle);
	ATF_TP_ADD_TC(tp, command_address_and_configure);
	ATF_TP_ADD_TC(tp, command_error_paths);
	ATF_TP_ADD_TC(tp, command_link_and_reset_ep);
	ATF_TP_ADD_TC(tp, control_transfer_and_doorbell);
	ATF_TP_ADD_TC(tp, bulk_transfer_via_data_endpoint);
	ATF_TP_ADD_TC(tp, port_registers_and_reset);
	ATF_TP_ADD_TC(tp, interrupt_gating_and_erdp);
	ATF_TP_ADD_TC(tp, transfer_ring_exhaustion);
	ATF_TP_ADD_TC(tp, erdp_recompute_and_errors);
	ATF_TP_ADD_TC(tp, command_ring_bad_pointer);
	ATF_TP_ADD_TC(tp, dev_intr_backend_notification);
	ATF_TP_ADD_TC(tp, port_link_state_writes);
	ATF_TP_ADD_TC(tp, transfer_trb_variants);
	ATF_TP_ADD_TC(tp, transfer_noop_and_event_data);
	ATF_TP_ADD_TC(tp, event_ring_full_handling);
	ATF_TP_ADD_TC(tp, parse_devices_limits);
	ATF_TP_ADD_TC(tp, command_error_matrix);
	ATF_TP_ADD_TC(tp, streams_endpoint);
	ATF_TP_ADD_TC(tp, dev_intr_resume_and_disabled);
	ATF_TP_ADD_TC(tp, host_controller_reset_with_device);
	ATF_TP_ADD_TC(tp, doorbell_register_read);
	ATF_TP_ADD_TC(tp, transfer_link_and_bad_type);
	ATF_TP_ADD_TC(tp, command_state_errors);
	ATF_TP_ADD_TC(tp, insert_event_geometry_errors);
	ATF_TP_ADD_TC(tp, dev_intr_resume_repeat);
	ATF_TP_ADD_TC(tp, address_device_error_states);
	ATF_TP_ADD_TC(tp, config_and_eval_more_paths);
	ATF_TP_ADD_TC(tp, operational_register_reads);
	ATF_TP_ADD_TC(tp, unsupported_commands);
	ATF_TP_ADD_TC(tp, extended_capability_reads);
	ATF_TP_ADD_TC(tp, more_command_and_doorbell_edges);
	ATF_TP_ADD_TC(tp, eval_context_state_and_maps);
	ATF_TP_ADD_TC(tp, portregs_unpowered_write);
#ifdef BHYVE_SNAPSHOT
	ATF_TP_ADD_TC(tp, snapshot_save_restore_roundtrip);
	ATF_TP_ADD_TC(tp, snapshot_after_control_transfer);
	ATF_TP_ADD_TC(tp, snapshot_endpoint_validation);
	ATF_TP_ADD_TC(tp, snapshot_streams_and_queued_xfer);
	ATF_TP_ADD_TC(tp, snapshot_main_validation);
	ATF_TP_ADD_TC(tp, snapshot_negative_cases);
	ATF_TP_ADD_TC(tp, pause_resume_fence);
#endif
	return (atf_no_error());
}
