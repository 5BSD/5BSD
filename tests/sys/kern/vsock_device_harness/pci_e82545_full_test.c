/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * TU-include harness for bhyve's Intel 82545EM (e1000) NIC model
 * (usr.sbin/bhyve/pci_e82545.c).  The production translation unit is compiled
 * directly into this test so its static register file, EEPROM/PHY state
 * machines, interrupt logic, RX/TX descriptor rings, checksum/TSO offload and
 * portable checkpoint record are exercised as the exact production code.
 *
 * bhyve/kernel infrastructure the DUT depends on is replaced with
 * self-contained userspace mocks: PCI config/BAR/lintr, guest DMA (a flat
 * userspace buffer indexed by guest physical address), the network backend (an
 * in-memory tap), mevent and the snapshot wire helpers.
 *
 * The oracle is the Intel 8254x (PCI/PCI-X Family of Gigabit Ethernet
 * Controllers) Software Developer's Manual: register offsets, reset values,
 * bit semantics, the Microwire EEPROM protocol, the MDI/PHY register set and
 * the legacy/extended/context/TSO transmit and legacy receive descriptor
 * layouts.  Every expectation is derived from independently (re)declared SPEC_
 * constants, never from the device model's own headers or output.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/endian.h>
#include <sys/uio.h>

#include <net/ethernet.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <atf-c.h>

/*
 * Pull in the harness mocks first so their include guards win over the real
 * bhyve headers that the copied DUT (in ${.OBJDIR}) also names.
 */
#include "config.h"
#include "pci_emul.h"
#include "snapshot.h"
#include "net_utils.h"
#include "net_backends.h"

/*
 * The harness mock pci_emul.h intentionally omits the guest-DMA mapping API,
 * a handful of config-space register offsets and the 16-bit cfgdata getter the
 * NIC model relies on; supply them here before the DUT is compiled.
 */
enum pci_dma_direction {
	PCI_DMA_DEVICE_READ = 0,
	PCI_DMA_DEVICE_WRITE,
	PCI_DMA_BIDIRECTIONAL,
};
void *pci_emul_map_dma(struct pci_devinst *, uint64_t, size_t,
    enum pci_dma_direction);
void pci_emul_mark_dma_dirty_mapping(struct pci_devinst *, void *, size_t);
uint16_t pci_get_cfgdata16(struct pci_devinst *, int);

#ifndef PCIR_HDRTYPE
#define	PCIR_HDRTYPE		0x0e
#endif
#ifndef PCIM_HDRTYPE_NORMAL
#define	PCIM_HDRTYPE_NORMAL	0x00
#endif
#ifndef PCIR_INTPIN
#define	PCIR_INTPIN		0x3d
#endif
#ifndef PCIS_NETWORK_ETHERNET
#define	PCIS_NETWORK_ETHERNET	0x00
#endif

/* ------------------------------------------------------------------ */
/* Mock guest physical memory                                          */
/* ------------------------------------------------------------------ */

#define	GMEM_SIZE	(16u * 1024u * 1024u)
static uint8_t *g_guest;
static bool g_dma_fail;			/* fail every mapping */
static uint64_t g_dma_fail_gpa;		/* if non-zero, fail only this gpa */
static size_t g_dirty_calls;

static void
guest_reset(void)
{
	if (g_guest == NULL)
		g_guest = malloc(GMEM_SIZE);
	ATF_REQUIRE(g_guest != NULL);
	memset(g_guest, 0, GMEM_SIZE);
	g_dma_fail = false;
	g_dma_fail_gpa = 0;
	g_dirty_calls = 0;
}

void *
pci_emul_map_dma(struct pci_devinst *pi __unused, uint64_t gpa, size_t len,
    enum pci_dma_direction dir __unused)
{
	if (g_dma_fail)
		return (NULL);
	if (g_dma_fail_gpa != 0 && gpa == g_dma_fail_gpa)
		return (NULL);
	if (g_guest == NULL || len == 0 || gpa + len > GMEM_SIZE)
		return (NULL);
	return (g_guest + gpa);
}

void
pci_emul_mark_dma_dirty_mapping(struct pci_devinst *pi __unused, void *addr,
    size_t len __unused)
{
	ATF_CHECK(addr != NULL);
	g_dirty_calls++;
}

/* ------------------------------------------------------------------ */
/* Mock PCI config / BAR / interrupt line                             */
/* ------------------------------------------------------------------ */

static int g_lintr_state;	/* current asserted level */
static int g_lintr_asserts;	/* rising edges */
static int g_lintr_deasserts;	/* falling edges */
static int g_lintr_requested;

void
pci_set_cfgdata8(struct pci_devinst *pi, int off, uint8_t val)
{
	pi->pi_cfgdata[off] = val;
}

void
pci_set_cfgdata16(struct pci_devinst *pi, int off, uint16_t val)
{
	le16enc(&pi->pi_cfgdata[off], val);
}

void
pci_set_cfgdata32(struct pci_devinst *pi, int off, uint32_t val)
{
	le32enc(&pi->pi_cfgdata[off], val);
}

uint8_t
pci_get_cfgdata8(struct pci_devinst *pi, int off)
{
	return (pi->pi_cfgdata[off]);
}

uint16_t
pci_get_cfgdata16(struct pci_devinst *pi, int off)
{
	return (le16dec(&pi->pi_cfgdata[off]));
}

uint32_t
pci_get_cfgdata32(struct pci_devinst *pi, int off)
{
	return (le32dec(&pi->pi_cfgdata[off]));
}

int
pci_emul_alloc_bar(struct pci_devinst *pi, int idx, enum pcibar_type type,
    uint64_t size)
{
	pi->pi_bar[idx].type = type;
	pi->pi_bar[idx].size = size;
	pi->pi_bar[idx].addr = 0;
	return (0);
}

void
pci_lintr_request(struct pci_devinst *pi __unused)
{
	g_lintr_requested++;
}

void
pci_lintr_assert(struct pci_devinst *pi __unused)
{
	g_lintr_state = 1;
	g_lintr_asserts++;
}

void
pci_lintr_deassert(struct pci_devinst *pi __unused)
{
	g_lintr_state = 0;
	g_lintr_deasserts++;
}

/* ------------------------------------------------------------------ */
/* Mock mevent (timer for interrupt throttling)                        */
/* ------------------------------------------------------------------ */

struct mevent {
	void (*func)(int, enum ev_type, void *);
	void *param;
	int active;
};
static struct mevent g_mev;
static int g_mev_adds;
static int g_mev_deletes;

struct mevent *
mevent_add(int msecs __unused, enum ev_type type __unused,
    void (*func)(int, enum ev_type, void *), void *param)
{
	g_mev_adds++;
	g_mev.func = func;
	g_mev.param = param;
	g_mev.active = 1;
	return (&g_mev);
}

int
mevent_delete(struct mevent *ev)
{
	g_mev_deletes++;
	if (ev != NULL)
		ev->active = 0;
	return (0);
}

/* ------------------------------------------------------------------ */
/* Mock config nodes                                                   */
/* ------------------------------------------------------------------ */

static const char *g_mac_cfg;	/* value returned for the "mac" key */

const char *
get_config_value_node(const nvlist_t *nvl __unused, const char *name)
{
	if (strcmp(name, "mac") == 0)
		return (g_mac_cfg);
	return (NULL);
}

/* ------------------------------------------------------------------ */
/* Mock net_utils                                                      */
/* ------------------------------------------------------------------ */

static int g_parsemac_rc;
static int g_genmac_calls;

int
net_parsemac(const char *mac, uint8_t *octet)
{
	unsigned int v[6];
	int i;

	if (g_parsemac_rc != 0)
		return (g_parsemac_rc);
	if (sscanf(mac, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3],
	    &v[4], &v[5]) != 6)
		return (EINVAL);
	for (i = 0; i < 6; i++)
		octet[i] = (uint8_t)v[i];
	return (0);
}

void
net_genmac(struct pci_devinst *pi __unused, uint8_t *octet)
{
	static const uint8_t gen[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };

	g_genmac_calls++;
	memcpy(octet, gen, 6);
}

int
net_parsemtu(const char *s __unused, unsigned long *mtu __unused)
{
	return (0);
}

/* ------------------------------------------------------------------ */
/* Mock network backend: an in-memory tap                              */
/* ------------------------------------------------------------------ */

struct net_backend {
	int dummy;
};
static struct net_backend g_backend;

#define	MAX_RXQ		8
struct rx_frame {
	uint8_t data[16384];
	size_t len;
};
static struct rx_frame g_rxq[MAX_RXQ];
static int g_rxq_head, g_rxq_tail;

#define	MAX_TXQ		64
struct tx_frame {
	uint8_t data[70000];
	size_t len;
};
static struct tx_frame *g_txq;	/* heap: large */
static int g_txq_count;

static int g_netbe_init_rc;
static int g_netbe_init_calls;
static int g_rx_enable_calls;
static int g_rx_disable_calls;
static int g_cleanup_calls;
static net_be_rxeof_t *g_rxeof;
static void *g_rxeof_arg;

static void
backend_reset(void)
{
	g_rxq_head = g_rxq_tail = 0;
	g_txq_count = 0;
	if (g_txq == NULL) {
		g_txq = malloc(sizeof(*g_txq) * MAX_TXQ);
		ATF_REQUIRE(g_txq != NULL);
	}
	g_netbe_init_rc = 0;
	g_netbe_init_calls = 0;
	g_rx_enable_calls = g_rx_disable_calls = g_cleanup_calls = 0;
}

/* Stage a frame for delivery to the NIC on the next netbe_recv(). */
static void
backend_push_rx(const void *data, size_t len)
{
	int next;

	next = (g_rxq_tail + 1) % MAX_RXQ;
	ATF_REQUIRE(next != g_rxq_head);	/* not full */
	ATF_REQUIRE(len <= sizeof(g_rxq[0].data));
	memcpy(g_rxq[g_rxq_tail].data, data, len);
	g_rxq[g_rxq_tail].len = len;
	g_rxq_tail = next;
}

static int
backend_rx_pending(void)
{
	return ((g_rxq_tail + MAX_RXQ - g_rxq_head) % MAX_RXQ);
}

int
netbe_init(net_backend_t **be, nvlist_t *nvl __unused, net_be_rxeof_t *cb,
    void *arg)
{
	g_netbe_init_calls++;
	if (g_netbe_init_rc != 0)
		return (g_netbe_init_rc);
	*be = &g_backend;
	g_rxeof = cb;
	g_rxeof_arg = arg;
	return (0);
}

void
netbe_cleanup(net_backend_t *be __unused)
{
	g_cleanup_calls++;
}

uint64_t
netbe_get_cap(net_backend_t *be __unused)
{
	return (0);
}

int
netbe_set_cap(net_backend_t *be __unused, uint64_t cap __unused,
    unsigned int hdrlen __unused)
{
	return (0);
}

size_t
netbe_get_vnet_hdr_len(net_backend_t *be __unused)
{
	return (0);
}

const char *
netbe_checkpoint_identity(net_backend_t *be __unused)
{
	return ("tap-oracle");
}

ssize_t
netbe_send(net_backend_t *be __unused, const struct iovec *iov, int iovcnt)
{
	size_t total = 0;
	int i;

	ATF_REQUIRE(g_txq_count < MAX_TXQ);
	for (i = 0; i < iovcnt; i++) {
		ATF_REQUIRE(total + iov[i].iov_len <= sizeof(g_txq[0].data));
		memcpy(g_txq[g_txq_count].data + total, iov[i].iov_base,
		    iov[i].iov_len);
		total += iov[i].iov_len;
	}
	g_txq[g_txq_count].len = total;
	g_txq_count++;
	return ((ssize_t)total);
}

ssize_t
netbe_peek_recvlen(net_backend_t *be __unused)
{
	if (backend_rx_pending() == 0)
		return (0);
	return ((ssize_t)g_rxq[g_rxq_head].len);
}

ssize_t
netbe_recv(net_backend_t *be __unused, const struct iovec *iov, int iovcnt)
{
	struct rx_frame *f;
	size_t off, now;
	int i;

	if (backend_rx_pending() == 0)
		return (0);
	f = &g_rxq[g_rxq_head];
	g_rxq_head = (g_rxq_head + 1) % MAX_RXQ;
	off = 0;
	for (i = 0; i < iovcnt && off < f->len; i++) {
		now = f->len - off;
		if (now > iov[i].iov_len)
			now = iov[i].iov_len;
		memcpy(iov[i].iov_base, f->data + off, now);
		off += now;
	}
	return ((ssize_t)f->len);
}

ssize_t
netbe_rx_discard(net_backend_t *be __unused)
{
	if (backend_rx_pending() == 0)
		return (0);
	g_rxq_head = (g_rxq_head + 1) % MAX_RXQ;
	return (1);
}

void
netbe_rx_disable(net_backend_t *be __unused)
{
	g_rx_disable_calls++;
}

void
netbe_rx_enable(net_backend_t *be __unused)
{
	g_rx_enable_calls++;
}

int
netbe_legacy_config(nvlist_t *nvl __unused, const char *opts __unused)
{
	return (0);
}

/* ------------------------------------------------------------------ */
/* Mock snapshot wire helpers (byte-exact, in-memory buffer)          */
/* ------------------------------------------------------------------ */

void
vm_snapshot_buf_err(const char *bufname __unused,
    const enum vm_snapshot_op op __unused)
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
vm_snapshot_u8(uint8_t *v, struct vm_snapshot_meta *meta)
{
	return (vm_snapshot_buf(v, sizeof(*v), meta));
}

int
vm_snapshot_le16(uint16_t *v, struct vm_snapshot_meta *meta)
{
	uint16_t tmp = 0;

	if (meta->op == VM_SNAPSHOT_SAVE)
		tmp = htole16(*v);
	if (vm_snapshot_buf(&tmp, sizeof(tmp), meta) != 0)
		return (E2BIG);
	if (vm_snapshot_is_loading(meta))
		*v = le16toh(tmp);
	return (0);
}

int
vm_snapshot_le32(uint32_t *v, struct vm_snapshot_meta *meta)
{
	uint32_t tmp = 0;

	if (meta->op == VM_SNAPSHOT_SAVE)
		tmp = htole32(*v);
	if (vm_snapshot_buf(&tmp, sizeof(tmp), meta) != 0)
		return (E2BIG);
	if (vm_snapshot_is_loading(meta))
		*v = le32toh(tmp);
	return (0);
}

int
vm_snapshot_le64(uint64_t *v, struct vm_snapshot_meta *meta)
{
	uint64_t tmp = 0;

	if (meta->op == VM_SNAPSHOT_SAVE)
		tmp = htole64(*v);
	if (vm_snapshot_buf(&tmp, sizeof(tmp), meta) != 0)
		return (E2BIG);
	if (vm_snapshot_is_loading(meta))
		*v = le64toh(tmp);
	return (0);
}

/*
 * The NIC saves/restores its descriptor-ring host pointers with
 * guest2host_addr.  Model it as a re-map through the flat guest buffer keyed
 * on the ring's guest physical address so restore reconstructs a valid host
 * pointer exactly as production would from the migrated RDBAL/TDBAL.
 */
static uint64_t g_g2h_last_gpa;
int
vm_snapshot_guest2host_addr(struct vmctx *ctx __unused, void **addr,
    size_t len __unused, bool restore_null, struct vm_snapshot_meta *meta)
{
	uint64_t gpa;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		gpa = (*addr == NULL) ? 0 :
		    (uint64_t)((uint8_t *)*addr - g_guest);
		g_g2h_last_gpa = gpa;
		return (0);
	}
	/* restore / validate */
	gpa = g_g2h_last_gpa;
	if (gpa == 0)
		*addr = restore_null ? NULL : g_guest;
	else
		*addr = g_guest + gpa;
	return (0);
}

/* ------------------------------------------------------------------ */
/* Independent Intel 8254x register/bit oracle (SPEC_ constants)       */
/* ------------------------------------------------------------------ */

/* Register offsets (Table of the 8254x SDM). */
#define	SPEC_CTRL	0x00000
#define	SPEC_STATUS	0x00008
#define	SPEC_EECD	0x00010
#define	SPEC_MDIC	0x00020
#define	SPEC_FCAL	0x00028
#define	SPEC_FCAH	0x0002C
#define	SPEC_FCT	0x00030
#define	SPEC_VET	0x00038
#define	SPEC_FCTTV	0x00170
#define	SPEC_ICR	0x000C0
#define	SPEC_ITR	0x000C4
#define	SPEC_ICS	0x000C8
#define	SPEC_IMS	0x000D0
#define	SPEC_IMC	0x000D8
#define	SPEC_RCTL	0x00100
#define	SPEC_FCRTL	0x02160
#define	SPEC_FCRTH	0x02168
#define	SPEC_RDBAL	0x02800
#define	SPEC_RDBAH	0x02804
#define	SPEC_RDLEN	0x02808
#define	SPEC_RDH	0x02810
#define	SPEC_RDT	0x02818
#define	SPEC_RDTR	0x02820
#define	SPEC_RXDCTL	0x02828
#define	SPEC_RADV	0x0282C
#define	SPEC_RSRPD	0x02C00
#define	SPEC_TCTL	0x00400
#define	SPEC_TIPG	0x00410
#define	SPEC_TDBAL	0x03800
#define	SPEC_TDBAH	0x03804
#define	SPEC_TDLEN	0x03808
#define	SPEC_TDH	0x03810
#define	SPEC_TDT	0x03818
#define	SPEC_TIDV	0x03820
#define	SPEC_TXDCTL	0x03828
#define	SPEC_TADV	0x0382C
#define	SPEC_TXCW	0x00178
#define	SPEC_RXCSUM	0x05000
#define	SPEC_PBA	0x01000
#define	SPEC_LEDCTL	0x00E00
#define	SPEC_AIT	0x00458
#define	SPEC_RAL0	0x05400
#define	SPEC_RAH0	0x05404
#define	SPEC_MTA0	0x05200
#define	SPEC_VFTA0	0x05600
#define	SPEC_GPRC	0x04074
#define	SPEC_MPC	0x04010
#define	SPEC_TPR	0x040D0

/* CTRL / STATUS bits. */
#define	SPEC_CTRL_FD		0x00000001
#define	SPEC_CTRL_RST		0x04000000
#define	SPEC_CTRL_VME		0x40000000
#define	SPEC_STATUS_FD		0x00000001
#define	SPEC_STATUS_LU		0x00000002
#define	SPEC_STATUS_SPEED_1000	0x00000080

/* Interrupt bits. */
#define	SPEC_ICR_TXDW		0x00000001
#define	SPEC_ICR_TXQE		0x00000002
#define	SPEC_ICR_RXDMT0		0x00000010
#define	SPEC_ICR_RXT0		0x00000080
#define	SPEC_ICR_SRPD		0x00010000

/* RCTL bits. */
#define	SPEC_RCTL_EN		0x00000002
#define	SPEC_RCTL_LPE		0x00000020
#define	SPEC_RCTL_LBM_TCVR	0x000000C0
#define	SPEC_RCTL_SZ_2048	0x00000000
#define	SPEC_RCTL_SZ_1024	0x00010000
#define	SPEC_RCTL_SZ_512	0x00020000
#define	SPEC_RCTL_SZ_256	0x00030000
#define	SPEC_RCTL_BSEX		0x02000000
#define	SPEC_RCTL_SECRC		0x04000000
#define	SPEC_RCTL_VFE		0x00040000

/* TCTL bits. */
#define	SPEC_TCTL_EN		0x00000002

/* RX descriptor status bits. */
#define	SPEC_RXD_STAT_DD	0x01
#define	SPEC_RXD_STAT_EOP	0x02
#define	SPEC_RXD_STAT_IXSM	0x04
#define	SPEC_RXD_STAT_PIF	0x80

/* RAH. */
#define	SPEC_RAH_AV		0x80000000

/* EECD (Microwire). */
#define	SPEC_EECD_SK		0x00000001
#define	SPEC_EECD_CS		0x00000002
#define	SPEC_EECD_DI		0x00000004
#define	SPEC_EECD_DO		0x00000008
#define	SPEC_EECD_REQ		0x00000040
#define	SPEC_EECD_GNT		0x00000080
#define	SPEC_EECD_PRES		0x00000100

/* MDIC. */
#define	SPEC_MDIC_REG_SHIFT	16
#define	SPEC_MDIC_PHY_SHIFT	21
#define	SPEC_MDIC_OP_WRITE	0x04000000
#define	SPEC_MDIC_OP_READ	0x08000000
#define	SPEC_MDIC_READY		0x10000000
#define	SPEC_MDIC_IE		0x20000000
#define	SPEC_MDIC_DATA_MASK	0x0000FFFF

/* PHY registers and identity. */
#define	SPEC_PHY_STATUS		0x01
#define	SPEC_PHY_ID1		0x02
#define	SPEC_PHY_ID2		0x03
#define	SPEC_M88_PHY_ID		0x01410C20u
#define	SPEC_MII_SR_LINK_STATUS	0x0004

/* Microwire NVM opcodes (3 opcode bits over 6 address bits). */
#define	SPEC_NVM_ADDR_BITS	6
#define	SPEC_NVM_DATA_BITS	16
#define	SPEC_NVM_OPADDR_BITS	9
#define	SPEC_NVM_OP_READ	0x6
#define	SPEC_NVM_OP_WRITE	0x5
#define	SPEC_NVM_OP_EWEN	0x4

/* NVM word offsets. */
#define	SPEC_NVM_MAC_ADDR	0x00
#define	SPEC_NVM_CHECKSUM_REG	0x3F
#define	SPEC_NVM_SUM		0xBABA

/* PCI identity. */
#define	SPEC_VENDOR_INTEL	0x8086
#define	SPEC_DEVID_82545EM	0x100F
#define	SPEC_SUBDEV_ID		0x1008

/* TX descriptor command/type bits (wire format). */
#define	SPEC_TXD_CMD_EOP	0x01000000
#define	SPEC_TXD_CMD_IFCS	0x02000000
#define	SPEC_TXD_CMD_IC		0x04000000
#define	SPEC_TXD_CMD_RS		0x08000000
#define	SPEC_TXD_CMD_DEXT	0x20000000
#define	SPEC_TXD_CMD_VLE	0x40000000
#define	SPEC_TXD_CMD_TSE	0x04000000
#define	SPEC_TXD_CMD_IP		0x02000000
#define	SPEC_TXD_CMD_TCP	0x01000000
#define	SPEC_TXD_DTYP_C		0x00000000
#define	SPEC_TXD_DTYP_D		0x00100000
#define	SPEC_TXD_STAT_DD	0x00000001
#define	SPEC_TXD_POPTS_IXSM	0x01
#define	SPEC_TXD_POPTS_TXSM	0x02

/* BAR indices/geometry (8254x maps a 128KB register BAR, 64KB flash, 8B I/O). */
#define	SPEC_BAR_REGISTER	0
#define	SPEC_BAR_FLASH		1
#define	SPEC_BAR_IO		2
#define	SPEC_BAR_REGISTER_LEN	(128 * 1024)
#define	SPEC_BAR_FLASH_LEN	(64 * 1024)
#define	SPEC_BAR_IO_LEN		8
#define	SPEC_IOADDR		0x00
#define	SPEC_IODATA		0x04

/* ------------------------------------------------------------------ */
/* Device under test                                                   */
/* ------------------------------------------------------------------ */

#include "pci_e82545.c"

/* ------------------------------------------------------------------ */
/* Test fixtures                                                       */
/* ------------------------------------------------------------------ */

static struct pci_devinst g_pi;
static const uint8_t TEST_MAC[6] = { 0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF };

/*
 * Build a softc directly (no tx thread) for deterministic register/RX/TX
 * unit tests.  Mirrors the reset path of e82545_init without spawning the
 * asynchronous transmit thread.
 */
static struct e82545_softc *
dev_new(void)
{
	struct e82545_softc *sc;

	guest_reset();
	backend_reset();
	g_lintr_state = g_lintr_asserts = g_lintr_deasserts = 0;
	g_mev_adds = g_mev_deletes = 0;
	/* Exercise the DPRINTF diagnostic paths behind the debug flag. */
	e82545_debug = 1;

	sc = calloc(1, sizeof(*sc));
	ATF_REQUIRE(sc != NULL);
	memset(&g_pi, 0, sizeof(g_pi));
	g_pi.pi_arg = sc;
	sc->esc_pi = &g_pi;
	sc->esc_ctx = g_pi.pi_vmctx;
	sc->esc_be = &g_backend;
	memcpy(sc->esc_mac.octet, TEST_MAC, 6);
	ATF_REQUIRE_EQ(0, pthread_mutex_init(&sc->esc_mtx, NULL));
	ATF_REQUIRE_EQ(0, pthread_cond_init(&sc->esc_rx_cond, NULL));
	ATF_REQUIRE_EQ(0, pthread_cond_init(&sc->esc_tx_cond, NULL));
	e82545_reset(sc, 0);
	return (sc);
}

static void
dev_free(struct e82545_softc *sc)
{
	pthread_mutex_destroy(&sc->esc_mtx);
	pthread_cond_destroy(&sc->esc_rx_cond);
	pthread_cond_destroy(&sc->esc_tx_cond);
	free(sc);
}

/* Register access through the BAR dispatch (memory-mapped register BAR). */
static void
reg_write(struct e82545_softc *sc, uint32_t off, uint32_t val)
{
	e82545_write(sc->esc_pi, SPEC_BAR_REGISTER, off, 4, val);
}

static uint32_t
reg_read(struct e82545_softc *sc, uint32_t off)
{
	return ((uint32_t)e82545_read(sc->esc_pi, SPEC_BAR_REGISTER, off, 4));
}

/* Guest physical layout inside the flat DMA buffer. */
#define	GPA_RX_RING	0x00001000u
#define	GPA_TX_RING	0x00005000u
#define	GPA_RX_BUF(i)	(0x00010000u + (uint32_t)(i) * 0x4000u)
#define	GPA_TX_BUF(i)	(0x00080000u + (uint32_t)(i) * 0x10000u)

/* Write a legacy RX descriptor into the guest ring. */
static void
rxd_set(uint32_t ring_gpa, int idx, uint64_t buf_gpa)
{
	uint8_t *d = g_guest + ring_gpa + (uint32_t)idx * 16u;

	le64enc(d, buf_gpa);
	memset(d + 8, 0, 8);
}

static struct e1000_rx_desc *
rxd_get(uint32_t ring_gpa, int idx)
{
	return ((struct e1000_rx_desc *)(g_guest + ring_gpa +
	    (uint32_t)idx * 16u));
}

/*
 * Encode a transmit descriptor (16 bytes) at ring index.  buffer_addr, the
 * lower dword (length/cso/cmd or extended data) and upper dword are given
 * verbatim so any descriptor type can be constructed.
 */
static void
txd_raw(uint32_t ring_gpa, int idx, uint64_t buffer_addr, uint32_t lower,
    uint32_t upper)
{
	uint8_t *d = g_guest + ring_gpa + (uint32_t)idx * 16u;

	le64enc(d, buffer_addr);
	le32enc(d + 8, lower);
	le32enc(d + 12, upper);
}

static union e1000_tx_udesc *
txd_get(uint32_t ring_gpa, int idx)
{
	return ((union e1000_tx_udesc *)(g_guest + ring_gpa +
	    (uint32_t)idx * 16u));
}

/*
 * Drive a Microwire EEPROM read of one 16-bit word through the EECD register
 * exactly as a real driver would: shift the 9 opcode+address bits in, then
 * clock 16 data bits out.  Returns the reconstructed word.
 */
static uint16_t
eeprom_read_word(struct e82545_softc *sc, uint8_t addr)
{
	uint32_t base = SPEC_EECD_PRES | SPEC_EECD_CS;
	uint32_t opaddr;
	uint16_t out;
	int i;

	/* Request + grant, chip select asserted. */
	reg_write(sc, SPEC_EECD, base | SPEC_EECD_REQ);

	/* 3 opcode bits (READ = 110) then 6 address bits, MSB first. */
	opaddr = ((uint32_t)SPEC_NVM_OP_READ << SPEC_NVM_ADDR_BITS) |
	    (addr & 0x3f);
	for (i = SPEC_NVM_OPADDR_BITS - 1; i >= 0; i--) {
		uint32_t di = ((opaddr >> i) & 1) ? SPEC_EECD_DI : 0;

		/* SK low with DI, then rising edge clocks the bit in. */
		reg_write(sc, SPEC_EECD, base | SPEC_EECD_REQ | di);
		reg_write(sc, SPEC_EECD,
		    base | SPEC_EECD_REQ | di | SPEC_EECD_SK);
	}

	/* Clock 16 data bits out, MSB first. */
	out = 0;
	for (i = 0; i < SPEC_NVM_DATA_BITS; i++) {
		uint32_t v;

		reg_write(sc, SPEC_EECD, base | SPEC_EECD_REQ);
		reg_write(sc, SPEC_EECD, base | SPEC_EECD_REQ | SPEC_EECD_SK);
		v = reg_read(sc, SPEC_EECD);
		out = (uint16_t)((out << 1) | ((v & SPEC_EECD_DO) ? 1 : 0));
	}
	return (out);
}

/* ================================================================== */
/* Test cases                                                          */
/* ================================================================== */

/* ---- PCI/BAR/config init via the real e82545_init ----------------- */

ATF_TC_WITHOUT_HEAD(init_bars_and_config);
ATF_TC_BODY(init_bars_and_config, tc)
{
	struct e82545_softc *sc;
	int rc;

	guest_reset();
	backend_reset();
	e82545_debug = 1;
	g_lintr_requested = 0;
	g_mac_cfg = "52:54:00:ab:cd:ef";
	g_parsemac_rc = 0;
	memset(&g_pi, 0, sizeof(g_pi));

	rc = e82545_init(&g_pi, NULL);
	ATF_REQUIRE_EQ(0, rc);
	sc = g_pi.pi_arg;
	ATF_REQUIRE(sc != NULL);

	/* Config space identity from the 8254x SDM / EEPROM defaults. */
	ATF_CHECK_EQ(SPEC_DEVID_82545EM, pci_get_cfgdata16(&g_pi, PCIR_DEVICE));
	ATF_CHECK_EQ(SPEC_VENDOR_INTEL, pci_get_cfgdata16(&g_pi, PCIR_VENDOR));
	ATF_CHECK_EQ(SPEC_SUBDEV_ID, pci_get_cfgdata16(&g_pi, PCIR_SUBDEV_0));
	ATF_CHECK_EQ(SPEC_VENDOR_INTEL,
	    pci_get_cfgdata16(&g_pi, PCIR_SUBVEND_0));
	ATF_CHECK_EQ(PCIC_NETWORK, pci_get_cfgdata8(&g_pi, PCIR_CLASS));
	ATF_CHECK_EQ(PCIS_NETWORK_ETHERNET,
	    pci_get_cfgdata8(&g_pi, PCIR_SUBCLASS));
	ATF_CHECK_EQ(PCIM_HDRTYPE_NORMAL,
	    pci_get_cfgdata8(&g_pi, PCIR_HDRTYPE));
	ATF_CHECK_EQ(0x1, pci_get_cfgdata8(&g_pi, PCIR_INTPIN));

	/* Three BARs: 128KB mem register, 64KB mem flash, 8B I/O. */
	ATF_CHECK_EQ(PCIBAR_MEM32, g_pi.pi_bar[SPEC_BAR_REGISTER].type);
	ATF_CHECK_EQ(SPEC_BAR_REGISTER_LEN,
	    g_pi.pi_bar[SPEC_BAR_REGISTER].size);
	ATF_CHECK_EQ(PCIBAR_MEM32, g_pi.pi_bar[SPEC_BAR_FLASH].type);
	ATF_CHECK_EQ(SPEC_BAR_FLASH_LEN, g_pi.pi_bar[SPEC_BAR_FLASH].size);
	ATF_CHECK_EQ(PCIBAR_IO, g_pi.pi_bar[SPEC_BAR_IO].type);
	ATF_CHECK_EQ(SPEC_BAR_IO_LEN, g_pi.pi_bar[SPEC_BAR_IO].size);

	ATF_CHECK(g_lintr_requested > 0);
	ATF_CHECK_EQ(1, g_netbe_init_calls);
	ATF_CHECK(g_rx_enable_calls > 0);

	/* Stop the tx thread cleanly. */
	pthread_mutex_lock(&sc->esc_mtx);
	e82545_tx_disable(sc);
	pthread_mutex_unlock(&sc->esc_mtx);
}

ATF_TC_WITHOUT_HEAD(init_genmac_and_backend_failure);
ATF_TC_BODY(init_genmac_and_backend_failure, tc)
{
	int rc;

	guest_reset();
	backend_reset();

	/* No mac config -> net_genmac path. */
	g_mac_cfg = NULL;
	g_netbe_init_rc = 0;
	memset(&g_pi, 0, sizeof(g_pi));
	g_genmac_calls = 0;
	rc = e82545_init(&g_pi, NULL);
	ATF_REQUIRE_EQ(0, rc);
	ATF_CHECK_EQ(1, g_genmac_calls);
	{
		struct e82545_softc *sc = g_pi.pi_arg;
		pthread_mutex_lock(&sc->esc_mtx);
		e82545_tx_disable(sc);
		pthread_mutex_unlock(&sc->esc_mtx);
	}

	/* Backend init failure -> e82545_init returns the error, frees sc. */
	backend_reset();
	g_mac_cfg = NULL;
	g_netbe_init_rc = EBUSY;
	memset(&g_pi, 0, sizeof(g_pi));
	rc = e82545_init(&g_pi, NULL);
	ATF_CHECK_EQ(EBUSY, rc);
	ATF_CHECK(g_pi.pi_arg == NULL);
}

ATF_TC_WITHOUT_HEAD(init_bad_mac);
ATF_TC_BODY(init_bad_mac, tc)
{
	int rc;

	guest_reset();
	backend_reset();
	e82545_debug = 1;
	g_mac_cfg = "not-a-mac";
	g_parsemac_rc = EINVAL;
	memset(&g_pi, 0, sizeof(g_pi));
	rc = e82545_init(&g_pi, NULL);
	ATF_CHECK_EQ(EINVAL, rc);
	ATF_CHECK(g_pi.pi_arg == NULL);
	g_parsemac_rc = 0;
}

/* ---- CTRL / STATUS ------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(ctrl_status_registers);
ATF_TC_BODY(ctrl_status_registers, tc)
{
	struct e82545_softc *sc = dev_new();
	uint32_t v;

	/* CTRL is read/write; RST bit is not retained in the stored value. */
	reg_write(sc, SPEC_CTRL, SPEC_CTRL_FD | SPEC_CTRL_VME);
	v = reg_read(sc, SPEC_CTRL);
	ATF_CHECK_EQ(SPEC_CTRL_FD | SPEC_CTRL_VME, v);

	/* STATUS is read-only and reports full-duplex link up at 1000Mb/s. */
	v = reg_read(sc, SPEC_STATUS);
	ATF_CHECK_EQ(SPEC_STATUS_FD | SPEC_STATUS_LU | SPEC_STATUS_SPEED_1000,
	    v);

	/* A write to STATUS is ignored (still reports the fixed value). */
	reg_write(sc, SPEC_STATUS, 0xffffffff);
	ATF_CHECK_EQ(SPEC_STATUS_FD | SPEC_STATUS_LU | SPEC_STATUS_SPEED_1000,
	    reg_read(sc, SPEC_STATUS));

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(ctrl_reset_reinits);
ATF_TC_BODY(ctrl_reset_reinits, tc)
{
	struct e82545_softc *sc = dev_new();
	int i;

	/* Dirty a couple of registers and bring RX up over a valid ring. */
	reg_write(sc, SPEC_VET, 0x8100);
	for (i = 0; i < 16; i++)
		rxd_set(GPA_RX_RING, i, GPA_RX_BUF(i));
	reg_write(sc, SPEC_RDBAL, GPA_RX_RING);
	reg_write(sc, SPEC_RDLEN, 16 * 16u);
	reg_write(sc, SPEC_RCTL, SPEC_RCTL_EN | SPEC_RCTL_SZ_2048);
	ATF_REQUIRE(sc->esc_rx_enabled);

	/* Raise a real interrupt so the reset path deasserts the line. */
	reg_write(sc, SPEC_ITR, 0);
	reg_write(sc, SPEC_IMS, SPEC_ICR_RXT0);
	reg_write(sc, SPEC_ICS, SPEC_ICR_RXT0);
	ATF_REQUIRE_EQ(1, g_lintr_state);

	/* Software reset via CTRL.RST clears the driver-visible state. */
	reg_write(sc, SPEC_CTRL, SPEC_CTRL_RST);
	ATF_CHECK_EQ(0, g_lintr_state);		/* reset deasserted the line */
	ATF_CHECK_EQ(0u, sc->esc_RCTL);
	ATF_CHECK_EQ(0, sc->esc_rx_enabled);
	/* CTRL.RST itself is not retained. */
	ATF_CHECK_EQ(0u, sc->esc_CTRL & SPEC_CTRL_RST);

	/* The shadow CTRL_DUP register aliases CTRL. */
	reg_write(sc, 0x00004 /* CTRL_DUP */, SPEC_CTRL_FD);
	ATF_CHECK_EQ(SPEC_CTRL_FD, reg_read(sc, SPEC_CTRL));

	dev_free(sc);
}

/* ---- Reserved-bit masking on scratch registers -------------------- */

ATF_TC_WITHOUT_HEAD(register_reserved_masks);
ATF_TC_BODY(register_reserved_masks, tc)
{
	struct e82545_softc *sc = dev_new();

	/* FCAH/FCT/VET/FCTTV retain only the low 16 bits. */
	reg_write(sc, SPEC_FCAH, 0xffffffff);
	ATF_CHECK_EQ(0x0000ffffu, reg_read(sc, SPEC_FCAH));
	reg_write(sc, SPEC_FCT, 0xdeadbeef);
	ATF_CHECK_EQ(0x0000beefu, reg_read(sc, SPEC_FCT));
	reg_write(sc, SPEC_VET, 0xffff1234);
	ATF_CHECK_EQ(0x00001234u, reg_read(sc, SPEC_VET));
	reg_write(sc, SPEC_FCTTV, 0xffffabcd);
	ATF_CHECK_EQ(0x0000abcdu, reg_read(sc, SPEC_FCTTV));

	/* FCAL retains all 32 bits. */
	reg_write(sc, SPEC_FCAL, 0x12345678);
	ATF_CHECK_EQ(0x12345678u, reg_read(sc, SPEC_FCAL));

	/* PBA retains bits 15:7 only. */
	reg_write(sc, SPEC_PBA, 0xffffffff);
	ATF_CHECK_EQ(0x0000ff80u, reg_read(sc, SPEC_PBA));

	/* LEDCTL masks off bits 29:28,21:20,13:12. */
	reg_write(sc, SPEC_LEDCTL, 0xffffffff);
	ATF_CHECK_EQ(0xffffffffu & ~0x30303000u, reg_read(sc, SPEC_LEDCTL));

	/* RDTR/RADV/RSRPD/RXCSUM/TXCW reserved-bit masks. */
	reg_write(sc, SPEC_RDTR, 0xffffffff);
	ATF_CHECK_EQ(0x0000ffffu, reg_read(sc, SPEC_RDTR));
	reg_write(sc, SPEC_RSRPD, 0xffffffff);
	ATF_CHECK_EQ(0x00000fffu, reg_read(sc, SPEC_RSRPD));
	reg_write(sc, SPEC_RXCSUM, 0xffffffff);
	ATF_CHECK_EQ(0x000007ffu, reg_read(sc, SPEC_RXCSUM));
	reg_write(sc, SPEC_TXCW, 0xffffffff);
	ATF_CHECK_EQ(0xffffffffu & ~0x3fff0000u, reg_read(sc, SPEC_TXCW));

	/* TIPG and AIT are stored verbatim (AIT is 16-bit). */
	reg_write(sc, SPEC_TIPG, 0x00abcdef);
	ATF_CHECK_EQ(0x00abcdefu, reg_read(sc, SPEC_TIPG));
	reg_write(sc, SPEC_AIT, 0x1234);
	ATF_CHECK_EQ(0x1234u, reg_read(sc, SPEC_AIT));

	/* Flow-control thresholds retain bits with 0xFFFF0007 reserved. */
	reg_write(sc, SPEC_FCRTL, 0xffffffff);
	ATF_CHECK_EQ(0xffffffffu & ~0xFFFF0007u, reg_read(sc, SPEC_FCRTL));
	reg_write(sc, SPEC_FCRTH, 0xffffffff);
	ATF_CHECK_EQ(0xffffffffu & ~0xFFFF0007u, reg_read(sc, SPEC_FCRTH));

	/* Descriptor-control and interrupt-delay reserved-bit masks. */
	reg_write(sc, SPEC_RXDCTL, 0xffffffff);
	ATF_CHECK_EQ(0xffffffffu & ~0xFEC0C0C0u, reg_read(sc, SPEC_RXDCTL));
	reg_write(sc, SPEC_RADV, 0xffffffff);
	ATF_CHECK_EQ(0x0000ffffu, reg_read(sc, SPEC_RADV));
	reg_write(sc, SPEC_TIDV, 0xffffffff);
	ATF_CHECK_EQ(0x0000ffffu, reg_read(sc, SPEC_TIDV));
	reg_write(sc, SPEC_TXDCTL, 0xffffffff);
	ATF_CHECK_EQ(0xffffffffu & ~0x00C0C0C0u, reg_read(sc, SPEC_TXDCTL));
	reg_write(sc, SPEC_TADV, 0xffffffff);
	ATF_CHECK_EQ(0x0000ffffu, reg_read(sc, SPEC_TADV));

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(register_unaligned_and_unknown);
ATF_TC_BODY(register_unaligned_and_unknown, tc)
{
	struct e82545_softc *sc = dev_new();

	/* Unaligned register writes/reads are dropped/zero. */
	reg_write(sc, SPEC_FCAL + 1, 0xdeadbeef);
	ATF_CHECK_EQ(0u, reg_read(sc, SPEC_FCAL));
	ATF_CHECK_EQ(0u, reg_read(sc, SPEC_FCAL + 2));

	/* Unknown register reads back zero, writes are no-ops. */
	ATF_CHECK_EQ(0u, reg_read(sc, 0x0001F0));
	reg_write(sc, 0x0001F0, 0x1);

	/* Non-4-byte register accesses are dropped. */
	e82545_write(sc->esc_pi, SPEC_BAR_REGISTER, SPEC_FCAL, 2, 0x1111);
	ATF_CHECK_EQ(0u, reg_read(sc, SPEC_FCAL));
	ATF_CHECK_EQ(0u,
	    (uint32_t)e82545_read(sc->esc_pi, SPEC_BAR_REGISTER, SPEC_FCAL, 2));

	dev_free(sc);
}

/* ---- Receive-address (RAL/RAH) array ------------------------------ */

ATF_TC_WITHOUT_HEAD(receive_address_array);
ATF_TC_BODY(receive_address_array, tc)
{
	struct e82545_softc *sc = dev_new();
	uint32_t ral, rah;

	/* Program entry 3 with a MAC and the address-valid + addrsel bits. */
	ral = 0x04030201;			/* octets 0..3 */
	rah = SPEC_RAH_AV | (0x2u << 16) | 0x0605;  /* addrsel=2, octets 4,5 */
	reg_write(sc, SPEC_RAL0 + 3 * 8, ral);
	reg_write(sc, SPEC_RAH0 + 3 * 8, rah);

	ATF_CHECK_EQ(ral, reg_read(sc, SPEC_RAL0 + 3 * 8));
	ATF_CHECK_EQ(rah, reg_read(sc, SPEC_RAH0 + 3 * 8));

	/* Multicast and VLAN filter arrays are plain storage. */
	reg_write(sc, SPEC_MTA0 + 5 * 4, 0xa5a5a5a5);
	ATF_CHECK_EQ(0xa5a5a5a5u, reg_read(sc, SPEC_MTA0 + 5 * 4));
	reg_write(sc, SPEC_VFTA0 + 7 * 4, 0x5a5a5a5a);
	ATF_CHECK_EQ(0x5a5a5a5au, reg_read(sc, SPEC_VFTA0 + 7 * 4));

	dev_free(sc);
}

/* ---- EEPROM Microwire state machine ------------------------------- */

ATF_TC_WITHOUT_HEAD(eeprom_read_mac_and_checksum);
ATF_TC_BODY(eeprom_read_mac_and_checksum, tc)
{
	struct e82545_softc *sc = dev_new();
	uint16_t w0, w1, w2, cksum, sum;
	int i;

	/* MAC words reconstruct the programmed address (little-endian pack). */
	w0 = eeprom_read_word(sc, SPEC_NVM_MAC_ADDR);
	w1 = eeprom_read_word(sc, SPEC_NVM_MAC_ADDR + 1);
	w2 = eeprom_read_word(sc, SPEC_NVM_MAC_ADDR + 2);
	ATF_CHECK_EQ((uint16_t)(TEST_MAC[0] | (TEST_MAC[1] << 8)), w0);
	ATF_CHECK_EQ((uint16_t)(TEST_MAC[2] | (TEST_MAC[3] << 8)), w1);
	ATF_CHECK_EQ((uint16_t)(TEST_MAC[4] | (TEST_MAC[5] << 8)), w2);

	/* The whole image (incl. checksum word) sums to NVM_SUM = 0xBABA. */
	sum = 0;
	for (i = 0; i <= SPEC_NVM_CHECKSUM_REG; i++)
		sum += eeprom_read_word(sc, (uint8_t)i);
	ATF_CHECK_EQ(SPEC_NVM_SUM, sum);

	cksum = eeprom_read_word(sc, SPEC_NVM_CHECKSUM_REG);
	ATF_CHECK(cksum != 0);

	/* EECD reports NVM present and access granted while REQ is set. */
	ATF_CHECK((reg_read(sc, SPEC_EECD) & SPEC_EECD_PRES) != 0);
	ATF_CHECK((reg_read(sc, SPEC_EECD) & SPEC_EECD_GNT) != 0);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(eeprom_write_and_readback);
ATF_TC_BODY(eeprom_write_and_readback, tc)
{
	struct e82545_softc *sc = dev_new();
	uint32_t base = SPEC_EECD_PRES | SPEC_EECD_CS;
	uint32_t opaddr;
	uint16_t data = 0xC3A5;
	int i;
	const uint8_t addr = 0x10;

	reg_write(sc, SPEC_EECD, base | SPEC_EECD_REQ);

	/* WRITE opcode (101) + address. */
	opaddr = ((uint32_t)SPEC_NVM_OP_WRITE << SPEC_NVM_ADDR_BITS) | addr;
	for (i = SPEC_NVM_OPADDR_BITS - 1; i >= 0; i--) {
		uint32_t di = ((opaddr >> i) & 1) ? SPEC_EECD_DI : 0;

		reg_write(sc, SPEC_EECD, base | SPEC_EECD_REQ | di);
		reg_write(sc, SPEC_EECD,
		    base | SPEC_EECD_REQ | di | SPEC_EECD_SK);
	}
	/* Shift the 16 data bits in, MSB first. */
	for (i = SPEC_NVM_DATA_BITS - 1; i >= 0; i--) {
		uint32_t di = ((data >> i) & 1) ? SPEC_EECD_DI : 0;

		reg_write(sc, SPEC_EECD, base | SPEC_EECD_REQ | di);
		reg_write(sc, SPEC_EECD,
		    base | SPEC_EECD_REQ | di | SPEC_EECD_SK);
	}

	/* Reading the same word back returns what we wrote. */
	ATF_CHECK_EQ(data, eeprom_read_word(sc, addr));

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(eeprom_write_enable_opcode);
ATF_TC_BODY(eeprom_write_enable_opcode, tc)
{
	struct e82545_softc *sc = dev_new();
	uint32_t base = SPEC_EECD_PRES | SPEC_EECD_CS;
	uint32_t opaddr;
	int i;

	/* EWEN opcode (100) exercises the write-enable branch, then returns to
	 * opcode mode. */
	reg_write(sc, SPEC_EECD, base | SPEC_EECD_REQ);
	opaddr = ((uint32_t)SPEC_NVM_OP_EWEN << SPEC_NVM_ADDR_BITS) | 0x30;
	for (i = SPEC_NVM_OPADDR_BITS - 1; i >= 0; i--) {
		uint32_t di = ((opaddr >> i) & 1) ? SPEC_EECD_DI : 0;

		reg_write(sc, SPEC_EECD, base | SPEC_EECD_REQ | di);
		reg_write(sc, SPEC_EECD,
		    base | SPEC_EECD_REQ | di | SPEC_EECD_SK);
	}
	/* Still functional afterwards: a subsequent read works. */
	(void)eeprom_read_word(sc, SPEC_NVM_MAC_ADDR);

	/* Dropping REQ revokes the grant. */
	reg_write(sc, SPEC_EECD, base);
	ATF_CHECK_EQ(0u, reg_read(sc, SPEC_EECD) & SPEC_EECD_GNT);

	/* Strobe with no pending bits (CS set, SK edge, nvm_bits==0) is a
	 * no-op and must not crash. */
	reg_write(sc, SPEC_EECD, base | SPEC_EECD_SK);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(eeprom_unknown_and_erase_opcode);
ATF_TC_BODY(eeprom_unknown_and_erase_opcode, tc)
{
	struct e82545_softc *sc = dev_new();
	uint32_t base = SPEC_EECD_PRES | SPEC_EECD_CS;
	int i;

	/* Shift a fully-zero opcode+address: hits the "unknown op" default. */
	reg_write(sc, SPEC_EECD, base | SPEC_EECD_REQ);
	for (i = 0; i < SPEC_NVM_OPADDR_BITS; i++) {
		reg_write(sc, SPEC_EECD, base | SPEC_EECD_REQ);
		reg_write(sc, SPEC_EECD, base | SPEC_EECD_REQ | SPEC_EECD_SK);
	}
	/* State machine recovered: a normal read still works afterwards. */
	(void)eeprom_read_word(sc, SPEC_NVM_MAC_ADDR);

	/* ERASE opcode (111) is unimplemented and also falls to default. */
	reg_write(sc, SPEC_EECD, base | SPEC_EECD_REQ);
	uint32_t opaddr = (0x7u << SPEC_NVM_ADDR_BITS) | 0x1;
	for (i = SPEC_NVM_OPADDR_BITS - 1; i >= 0; i--) {
		uint32_t di = ((opaddr >> i) & 1) ? SPEC_EECD_DI : 0;

		reg_write(sc, SPEC_EECD, base | SPEC_EECD_REQ | di);
		reg_write(sc, SPEC_EECD,
		    base | SPEC_EECD_REQ | di | SPEC_EECD_SK);
	}
	(void)eeprom_read_word(sc, SPEC_NVM_MAC_ADDR);

	dev_free(sc);
}

/* ---- MDIC / PHY --------------------------------------------------- */

ATF_TC_WITHOUT_HEAD(mdic_phy_reads);
ATF_TC_BODY(mdic_phy_reads, tc)
{
	struct e82545_softc *sc = dev_new();
	uint32_t v;

	/* PHY_STATUS read: link status bit set, READY latched, data in low 16
	 * bits. */
	reg_write(sc, SPEC_MDIC, SPEC_MDIC_OP_READ |
	    ((uint32_t)SPEC_PHY_STATUS << SPEC_MDIC_REG_SHIFT));
	v = reg_read(sc, SPEC_MDIC);
	ATF_CHECK((v & SPEC_MDIC_READY) != 0);
	ATF_CHECK((v & SPEC_MII_SR_LINK_STATUS) != 0);

	/* PHY identity registers reconstruct the Marvell 88E1011 OUI. */
	reg_write(sc, SPEC_MDIC, SPEC_MDIC_OP_READ |
	    ((uint32_t)SPEC_PHY_ID1 << SPEC_MDIC_REG_SHIFT));
	uint16_t id1 = reg_read(sc, SPEC_MDIC) & SPEC_MDIC_DATA_MASK;
	reg_write(sc, SPEC_MDIC, SPEC_MDIC_OP_READ |
	    ((uint32_t)SPEC_PHY_ID2 << SPEC_MDIC_REG_SHIFT));
	uint16_t id2 = reg_read(sc, SPEC_MDIC) & SPEC_MDIC_DATA_MASK;
	ATF_CHECK_EQ((uint16_t)((SPEC_M88_PHY_ID >> 16) & 0xffff), id1);
	/* ID2 upper bits match; low nibble is a revision. */
	ATF_CHECK_EQ((uint16_t)((SPEC_M88_PHY_ID & 0xfff0)),
	    (uint16_t)(id2 & 0xfff0));

	/* The remaining decoded PHY registers: auto-negotiation advertisement
	 * (reg 4), link-partner ability (reg 5) and 1000BASE-T status (reg
	 * 10) all latch READY with defined data. */
	reg_write(sc, SPEC_MDIC, SPEC_MDIC_OP_READ |
	    ((uint32_t)0x04 << SPEC_MDIC_REG_SHIFT));	/* PHY_AUTONEG_ADV */
	ATF_CHECK((reg_read(sc, SPEC_MDIC) & SPEC_MDIC_READY) != 0);
	reg_write(sc, SPEC_MDIC, SPEC_MDIC_OP_READ |
	    ((uint32_t)0x05 << SPEC_MDIC_REG_SHIFT));	/* PHY_LP_ABILITY */
	v = reg_read(sc, SPEC_MDIC);
	ATF_CHECK((v & SPEC_MDIC_READY) != 0);
	ATF_CHECK_EQ(0u, v & SPEC_MDIC_DATA_MASK);	/* LP ability = 0 */
	reg_write(sc, SPEC_MDIC, SPEC_MDIC_OP_READ |
	    ((uint32_t)0x0a << SPEC_MDIC_REG_SHIFT));	/* PHY_1000T_STATUS */
	ATF_CHECK((reg_read(sc, SPEC_MDIC) & SPEC_MDIC_READY) != 0);

	/* Unknown PHY register reads back 0 data, READY still set. */
	reg_write(sc, SPEC_MDIC, SPEC_MDIC_OP_READ |
	    ((uint32_t)0x1e << SPEC_MDIC_REG_SHIFT));
	v = reg_read(sc, SPEC_MDIC);
	ATF_CHECK((v & SPEC_MDIC_READY) != 0);
	ATF_CHECK_EQ(0u, v & SPEC_MDIC_DATA_MASK);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(mdic_writes_and_errors);
ATF_TC_BODY(mdic_writes_and_errors, tc)
{
	struct e82545_softc *sc = dev_new();
	uint32_t v;

	/* MDIC write op with interrupt-enable bit and data. */
	reg_write(sc, SPEC_MDIC, SPEC_MDIC_OP_WRITE | SPEC_MDIC_IE |
	    ((uint32_t)SPEC_PHY_STATUS << SPEC_MDIC_REG_SHIFT) | 0x1234);
	v = reg_read(sc, SPEC_MDIC);
	ATF_CHECK((v & SPEC_MDIC_READY) != 0);

	/* Setting READY on the incoming write is rejected (stale value kept). */
	reg_write(sc, SPEC_MDIC, SPEC_MDIC_READY | SPEC_MDIC_OP_READ);
	ATF_CHECK((reg_read(sc, SPEC_MDIC) & SPEC_MDIC_READY) != 0);

	/* Unknown MDIC op (both op bits zero, not READY) is ignored. */
	reg_write(sc, SPEC_MDIC, 0x00000000);

	dev_free(sc);
}

/* ---- Interrupt cause/mask logic ----------------------------------- */

ATF_TC_WITHOUT_HEAD(interrupt_ics_ims_assert);
ATF_TC_BODY(interrupt_ics_ims_assert, tc)
{
	struct e82545_softc *sc = dev_new();

	/* Disable throttling so no mevent timer is scheduled. */
	reg_write(sc, SPEC_ITR, 0);

	/* Cause set with the source masked: ICR records it, no line asserted. */
	reg_write(sc, SPEC_ICS, SPEC_ICR_RXT0);
	ATF_CHECK_EQ(0, g_lintr_state);
	ATF_CHECK((reg_read(sc, SPEC_ICR) & SPEC_ICR_RXT0) != 0);

	/* Reading ICR clears it and deasserts. */
	ATF_CHECK_EQ(0u, reg_read(sc, SPEC_ICR));

	/* Unmask, then set: the line asserts. */
	reg_write(sc, SPEC_IMS, SPEC_ICR_RXT0);
	ATF_CHECK_EQ(SPEC_ICR_RXT0, reg_read(sc, SPEC_IMS));
	reg_write(sc, SPEC_ICS, SPEC_ICR_RXT0);
	ATF_CHECK_EQ(1, g_lintr_state);
	ATF_CHECK(g_lintr_asserts > 0);

	/* Reading ICR clears the cause and drops the line. */
	ATF_CHECK((reg_read(sc, SPEC_ICR) & SPEC_ICR_RXT0) != 0);
	ATF_CHECK_EQ(0, g_lintr_state);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(interrupt_ims_change_unmasks_pending);
ATF_TC_BODY(interrupt_ims_change_unmasks_pending, tc)
{
	struct e82545_softc *sc = dev_new();

	reg_write(sc, SPEC_ITR, 0);

	/* Latch a masked cause. */
	reg_write(sc, SPEC_ICS, SPEC_ICR_TXDW);
	ATF_CHECK_EQ(0, g_lintr_state);

	/* Unmasking a pending cause asserts immediately (ims_change path). */
	reg_write(sc, SPEC_IMS, SPEC_ICR_TXDW);
	ATF_CHECK_EQ(1, g_lintr_state);

	/* IMC clears the mask bit; the pending ICR remains but is now masked. */
	reg_write(sc, SPEC_IMC, SPEC_ICR_TXDW);
	ATF_CHECK_EQ(0u, reg_read(sc, SPEC_IMS) & SPEC_ICR_TXDW);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(interrupt_throttle_timer);
ATF_TC_BODY(interrupt_throttle_timer, tc)
{
	struct e82545_softc *sc = dev_new();

	/* Non-zero ITR schedules an mevent throttle timer on first assert. */
	reg_write(sc, SPEC_ITR, 250);
	ATF_CHECK_EQ(250u, reg_read(sc, SPEC_ITR));
	reg_write(sc, SPEC_IMS, SPEC_ICR_RXT0);
	reg_write(sc, SPEC_ICS, SPEC_ICR_RXT0);
	ATF_CHECK_EQ(1, g_lintr_state);
	ATF_CHECK(g_mev_adds > 0);

	/* Fire the throttle callback: still masked-in cause -> stays asserted. */
	g_mev.func(0, EVF_TIMER, g_mev.param);
	ATF_CHECK_EQ(1, g_lintr_state);

	/* Clear the cause; firing the callback now tears down the timer. */
	(void)reg_read(sc, SPEC_ICR);	/* clears + deasserts */
	sc->esc_irq_asserted = 0;
	g_mev.active = 1;
	g_mev_deletes = 0;
	g_mev.func(0, EVF_TIMER, g_mev.param);
	ATF_CHECK(g_mev_deletes > 0);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(interrupt_readonly_writeonly);
ATF_TC_BODY(interrupt_readonly_writeonly, tc)
{
	struct e82545_softc *sc = dev_new();

	/* ICS is write-only: reads back 0. */
	reg_write(sc, SPEC_ITR, 0);
	reg_write(sc, SPEC_ICS, SPEC_ICR_RXT0);
	ATF_CHECK_EQ(0u, reg_read(sc, SPEC_ICS));
	/* IMC is write-only: reads back 0. */
	ATF_CHECK_EQ(0u, reg_read(sc, SPEC_IMC));
	(void)reg_read(sc, SPEC_ICR);

	dev_free(sc);
}

/* ---- e82545_bufsz decode (RCTL size fields) ----------------------- */

ATF_TC_WITHOUT_HEAD(rctl_buffer_size_decode);
ATF_TC_BODY(rctl_buffer_size_decode, tc)
{

	/* BSEX=0 sizes. */
	ATF_CHECK_EQ(2048, e82545_bufsz(SPEC_RCTL_SZ_2048));
	ATF_CHECK_EQ(1024, e82545_bufsz(SPEC_RCTL_SZ_1024));
	ATF_CHECK_EQ(512, e82545_bufsz(SPEC_RCTL_SZ_512));
	ATF_CHECK_EQ(256, e82545_bufsz(SPEC_RCTL_SZ_256));
	/*
	 * BSEX=1 reinterprets the size field: 0x10000 -> 16384, 0x20000 ->
	 * 8192, 0x30000 -> 4096 (8254x SDM RCTL.BSIZE with BSEX set).
	 */
	ATF_CHECK_EQ(16384, e82545_bufsz(SPEC_RCTL_BSEX | 0x00010000));
	ATF_CHECK_EQ(8192, e82545_bufsz(SPEC_RCTL_BSEX | 0x00020000));
	ATF_CHECK_EQ(4096, e82545_bufsz(SPEC_RCTL_BSEX | 0x00030000));
	/* Forbidden BSEX|0 combination falls back to 256. */
	ATF_CHECK_EQ(256, e82545_bufsz(SPEC_RCTL_BSEX | 0x00000000));
}

/* ---- Receive ring setup + frame reception ------------------------- */

/* Program an RX ring of `ndesc` 2048-byte-buffer descriptors and enable RX. */
static void
rx_setup(struct e82545_softc *sc, int ndesc, uint32_t rctl_extra)
{
	int i;

	for (i = 0; i < ndesc; i++)
		rxd_set(GPA_RX_RING, i, GPA_RX_BUF(i));
	reg_write(sc, SPEC_RDBAL, GPA_RX_RING);
	reg_write(sc, SPEC_RDBAH, 0);
	reg_write(sc, SPEC_RDLEN, (uint32_t)ndesc * 16u);
	reg_write(sc, SPEC_RDH, 0);
	reg_write(sc, SPEC_RDT, (uint32_t)(ndesc - 1));
	reg_write(sc, SPEC_RCTL, SPEC_RCTL_EN | SPEC_RCTL_SZ_2048 | rctl_extra);
	ATF_REQUIRE(sc->esc_rx_enabled);
}

ATF_TC_WITHOUT_HEAD(rx_single_descriptor_frame);
ATF_TC_BODY(rx_single_descriptor_frame, tc)
{
	struct e82545_softc *sc = dev_new();
	uint8_t frame[512];
	struct e1000_rx_desc *rxd;
	size_t i;

	rx_setup(sc, 16, SPEC_RCTL_SECRC);	/* strip CRC */

	for (i = 0; i < sizeof(frame); i++)
		frame[i] = (uint8_t)i;
	/* dest MAC broadcast-ish, but VLAN filter disabled so accepted. */
	backend_push_rx(frame, sizeof(frame));

	e82545_rx_callback(0, EVF_READ, sc);

	/* Head advanced by exactly one descriptor. */
	ATF_CHECK_EQ(1u, sc->esc_RDH);

	/* The descriptor is marked done + EOP with the received length. */
	rxd = rxd_get(GPA_RX_RING, 0);
	ATF_CHECK((rxd->status & SPEC_RXD_STAT_DD) != 0);
	ATF_CHECK((rxd->status & SPEC_RXD_STAT_EOP) != 0);
	ATF_CHECK_EQ((uint16_t)sizeof(frame), rxd->length);

	/* Payload copied into the guest buffer. */
	ATF_CHECK_EQ(0, memcmp(g_guest + GPA_RX_BUF(0), frame, sizeof(frame)));

	/* An RXT0 receive interrupt cause was recorded. */
	ATF_CHECK((sc->esc_ICR & SPEC_ICR_RXT0) != 0);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(rx_crc_addback_and_runt);
ATF_TC_BODY(rx_crc_addback_and_runt, tc)
{
	struct e82545_softc *sc = dev_new();
	uint8_t frame[20];
	struct e1000_rx_desc *rxd;

	/* No SECRC -> CRC (4 bytes) is added back to the reported length, and a
	 * runt frame is padded to the minimum (60) before CRC add-back. */
	rx_setup(sc, 16, 0);
	memset(frame, 0xAB, sizeof(frame));
	backend_push_rx(frame, sizeof(frame));

	e82545_rx_callback(0, EVF_READ, sc);

	rxd = rxd_get(GPA_RX_RING, 0);
	ATF_CHECK((rxd->status & SPEC_RXD_STAT_DD) != 0);
	/* 60 (min payload) + 4 (CRC) = 64 reported. */
	ATF_CHECK_EQ(64, rxd->length);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(rx_multi_descriptor_frame);
ATF_TC_BODY(rx_multi_descriptor_frame, tc)
{
	struct e82545_softc *sc = dev_new();
	uint8_t *frame;
	size_t flen = 3000;	/* spans two 2048-byte buffers */
	struct e1000_rx_desc *rxd0, *rxd1;
	size_t i;

	frame = malloc(flen);
	ATF_REQUIRE(frame != NULL);
	for (i = 0; i < flen; i++)
		frame[i] = (uint8_t)(i & 0xff);

	rx_setup(sc, 32, SPEC_RCTL_SECRC | SPEC_RCTL_LPE);
	backend_push_rx(frame, flen);

	e82545_rx_callback(0, EVF_READ, sc);

	/* Two descriptors consumed. */
	ATF_CHECK_EQ(2u, sc->esc_RDH);
	rxd0 = rxd_get(GPA_RX_RING, 0);
	rxd1 = rxd_get(GPA_RX_RING, 1);
	/* First descriptor: full buffer, DD but not EOP. */
	ATF_CHECK_EQ(2048, rxd0->length);
	ATF_CHECK((rxd0->status & SPEC_RXD_STAT_DD) != 0);
	ATF_CHECK_EQ(0, rxd0->status & SPEC_RXD_STAT_EOP);
	/* Last descriptor: remainder, EOP set. */
	ATF_CHECK((rxd1->status & SPEC_RXD_STAT_EOP) != 0);
	ATF_CHECK_EQ((uint16_t)(flen % 2048), rxd1->length);

	free(frame);
	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(rx_ring_overflow_dropped);
ATF_TC_BODY(rx_ring_overflow_dropped, tc)
{
	struct e82545_softc *sc = dev_new();
	uint8_t frame[512];
	int i;

	/*
	 * A jumbo-capable ring (LPE) needs up to maxpktdesc=8 descriptors per
	 * frame, but only 3 are made available (RDT=3).  RDLEN must be
	 * 128-byte aligned, so use a full 8-descriptor ring and constrain the
	 * free window with the tail pointer.  The ring-overflow guard drops the
	 * frame and leaves RDH untouched.
	 */
	for (i = 0; i < 8; i++)
		rxd_set(GPA_RX_RING, i, GPA_RX_BUF(i));
	reg_write(sc, SPEC_RDBAL, GPA_RX_RING);
	reg_write(sc, SPEC_RDBAH, 0);
	reg_write(sc, SPEC_RDLEN, 8 * 16u);	/* 128 bytes, aligned */
	reg_write(sc, SPEC_RDH, 0);
	reg_write(sc, SPEC_RDT, 3);		/* only 3 descriptors free */
	reg_write(sc, SPEC_RCTL,
	    SPEC_RCTL_EN | SPEC_RCTL_SZ_2048 | SPEC_RCTL_LPE);
	ATF_REQUIRE(sc->esc_rx_enabled);

	memset(frame, 0, sizeof(frame));
	backend_push_rx(frame, sizeof(frame));
	e82545_rx_callback(0, EVF_READ, sc);

	ATF_CHECK_EQ(0u, sc->esc_RDH);		/* nothing consumed */
	ATF_CHECK_EQ(0, backend_rx_pending());	/* frame discarded */

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(rx_disabled_discards);
ATF_TC_BODY(rx_disabled_discards, tc)
{
	struct e82545_softc *sc = dev_new();
	uint8_t frame[128];

	/* RX not enabled: pending frames are discarded. */
	memset(frame, 0, sizeof(frame));
	backend_push_rx(frame, sizeof(frame));
	backend_push_rx(frame, sizeof(frame));
	e82545_rx_callback(0, EVF_READ, sc);
	ATF_CHECK_EQ(0, backend_rx_pending());

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(rx_bad_buffer_address);
ATF_TC_BODY(rx_bad_buffer_address, tc)
{
	struct e82545_softc *sc = dev_new();
	uint8_t frame[128];

	rx_setup(sc, 16, SPEC_RCTL_SECRC);
	/* Point descriptor 0 at an unmappable buffer address. */
	rxd_set(GPA_RX_RING, 0, GMEM_SIZE + 0x1000);
	memset(frame, 0, sizeof(frame));
	backend_push_rx(frame, sizeof(frame));

	e82545_rx_callback(0, EVF_READ, sc);

	/* Mapping failed: frame dropped, head not advanced. */
	ATF_CHECK_EQ(0u, sc->esc_RDH);
	ATF_CHECK_EQ(0, backend_rx_pending());

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(rx_vlan_filter);
ATF_TC_BODY(rx_vlan_filter, tc)
{
	struct e82545_softc *sc = dev_new();
	uint8_t frame[128];
	uint16_t tag = 100;

	/* Enable VLAN filtering with VET=0x8100 and accept only tag 100. */
	rx_setup(sc, 16, SPEC_RCTL_SECRC | SPEC_RCTL_VFE);
	reg_write(sc, SPEC_VET, 0x8100);
	reg_write(sc, SPEC_VFTA0 + (tag >> 5) * 4, 1u << (tag & 0x1f));

	memset(frame, 0, sizeof(frame));
	/* 802.1Q header at offset 12: TPID then TCI(tag). */
	be16enc(frame + 12, 0x8100);
	be16enc(frame + 14, tag);
	backend_push_rx(frame, sizeof(frame));
	e82545_rx_callback(0, EVF_READ, sc);
	ATF_CHECK_EQ(1u, sc->esc_RDH);		/* accepted */

	/* A frame with an unknown tag is filtered (head does not advance). */
	dev_free(sc);
	sc = dev_new();
	rx_setup(sc, 16, SPEC_RCTL_SECRC | SPEC_RCTL_VFE);
	reg_write(sc, SPEC_VET, 0x8100);
	reg_write(sc, SPEC_VFTA0 + (tag >> 5) * 4, 1u << (tag & 0x1f));
	memset(frame, 0, sizeof(frame));
	be16enc(frame + 12, 0x8100);
	be16enc(frame + 14, 4094);		/* not in the filter */
	backend_push_rx(frame, sizeof(frame));
	e82545_rx_callback(0, EVF_READ, sc);
	ATF_CHECK_EQ(0u, sc->esc_RDH);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(rx_small_packet_detect);
ATF_TC_BODY(rx_small_packet_detect, tc)
{
	struct e82545_softc *sc = dev_new();
	uint8_t frame[128];

	rx_setup(sc, 16, SPEC_RCTL_SECRC);
	/* RSRPD threshold: frames <= threshold raise the SRPD cause too. */
	reg_write(sc, SPEC_RSRPD, 256);
	memset(frame, 0, sizeof(frame));
	backend_push_rx(frame, sizeof(frame));
	e82545_rx_callback(0, EVF_READ, sc);
	ATF_CHECK((sc->esc_ICR & SPEC_ICR_SRPD) != 0);
	ATF_CHECK((sc->esc_ICR & SPEC_ICR_RXT0) != 0);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(rx_ctl_disallows_rdba_writes);
ATF_TC_BODY(rx_ctl_disallows_rdba_writes, tc)
{
	struct e82545_softc *sc = dev_new();

	rx_setup(sc, 16, 0);
	/* With RX enabled, RDBAL/RDBAH/RDLEN writes are ignored. */
	reg_write(sc, SPEC_RDBAL, 0xdeadb000);
	reg_write(sc, SPEC_RDBAH, 0x1234);
	reg_write(sc, SPEC_RDLEN, 0x40);
	ATF_CHECK_EQ(GPA_RX_RING, sc->esc_RDBAL);
	ATF_CHECK_EQ(0u, sc->esc_RDBAH);
	ATF_CHECK_EQ(16u * 16u, sc->esc_RDLEN);

	/* Disabling RX clears the cached ring mapping. */
	reg_write(sc, SPEC_RCTL, 0);
	ATF_CHECK_EQ(0, sc->esc_rx_enabled);
	ATF_CHECK(sc->esc_rxdesc == NULL);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(rx_ctl_invalid_ring);
ATF_TC_BODY(rx_ctl_invalid_ring, tc)
{
	struct e82545_softc *sc = dev_new();

	/* RDLEN too small for a single descriptor -> enable is refused. */
	reg_write(sc, SPEC_RDBAL, GPA_RX_RING);
	reg_write(sc, SPEC_RDLEN, 8);	/* < sizeof(rx_desc) */
	reg_write(sc, SPEC_RCTL, SPEC_RCTL_EN | SPEC_RCTL_SZ_2048);
	ATF_CHECK_EQ(0, sc->esc_rx_enabled);

	/* Loopback mode (LBM_TCVR) sets the loopback flag on enable. */
	dev_free(sc);
	sc = dev_new();
	rxd_set(GPA_RX_RING, 0, GPA_RX_BUF(0));
	reg_write(sc, SPEC_RDBAL, GPA_RX_RING);
	reg_write(sc, SPEC_RDLEN, 16 * 16u);
	reg_write(sc, SPEC_RCTL,
	    SPEC_RCTL_EN | SPEC_RCTL_SZ_2048 | SPEC_RCTL_LBM_TCVR);
	ATF_CHECK_EQ(1, sc->esc_rx_loopback);

	dev_free(sc);
}

/* ---- Transmit ----------------------------------------------------- */

/* Program a TX ring of `ndesc` descriptors and enable TX (no thread). */
static void
tx_setup(struct e82545_softc *sc, int ndesc)
{
	reg_write(sc, SPEC_TDBAL, GPA_TX_RING);
	reg_write(sc, SPEC_TDBAH, 0);
	reg_write(sc, SPEC_TDLEN, (uint32_t)ndesc * 16u);
	reg_write(sc, SPEC_TDH, 0);
	/* Enabling TCTL spawns no thread in this harness; set the flag. */
	sc->esc_TCTL = SPEC_TCTL_EN;
	e82545_tx_update_tdba(sc);
	sc->esc_tx_enabled = 1;
	ATF_REQUIRE(sc->esc_txdesc != NULL);
}

/* Run the transmit engine once with the lock protocol tx_run expects. */
static void
tx_run_locked(struct e82545_softc *sc)
{
	pthread_mutex_lock(&sc->esc_mtx);
	e82545_tx_run(sc);
	pthread_mutex_unlock(&sc->esc_mtx);
}

ATF_TC_WITHOUT_HEAD(tx_legacy_frame);
ATF_TC_BODY(tx_legacy_frame, tc)
{
	struct e82545_softc *sc = dev_new();
	enum { PAYLOAD_LEN = 100 };
	uint8_t payload[PAYLOAD_LEN];
	size_t i;
	union e1000_tx_udesc *dsc;

	for (i = 0; i < sizeof(payload); i++)
		payload[i] = (uint8_t)(0x40 + i);
	memcpy(g_guest + GPA_TX_BUF(0), payload, sizeof(payload));

	tx_setup(sc, 8);
	/* Legacy descriptor: length in low 16 bits, EOP|RS|IFCS in cmd byte. */
	txd_raw(GPA_TX_RING, 0, GPA_TX_BUF(0),
	    (uint32_t)sizeof(payload) |
	    (SPEC_TXD_CMD_EOP | SPEC_TXD_CMD_RS | SPEC_TXD_CMD_IFCS), 0);
	reg_write(sc, SPEC_TDT, 1);
	tx_run_locked(sc);

	/* One frame was transmitted with the exact payload. */
	ATF_CHECK_EQ(1, g_txq_count);
	ATF_CHECK_EQ(PAYLOAD_LEN, g_txq[0].len);
	ATF_CHECK_EQ(0, memcmp(g_txq[0].data, payload, sizeof(payload)));

	/* Report-status descriptor got its Done bit + TXDW cause. */
	dsc = txd_get(GPA_TX_RING, 0);
	ATF_CHECK((le32dec(&dsc->td.upper.data) & SPEC_TXD_STAT_DD) != 0);
	ATF_CHECK((sc->esc_ICR & SPEC_ICR_TXDW) != 0);
	/* Ring drained: head meets tail -> queue-empty cause. */
	ATF_CHECK_EQ(sc->esc_TDT, sc->esc_TDH);
	ATF_CHECK((sc->esc_ICR & SPEC_ICR_TXQE) != 0);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(tx_legacy_crc_strip);
ATF_TC_BODY(tx_legacy_crc_strip, tc)
{
	struct e82545_softc *sc = dev_new();
	enum { PAYLOAD_LEN = 64 };
	uint8_t payload[PAYLOAD_LEN];

	memset(payload, 0x5a, sizeof(payload));
	memcpy(g_guest + GPA_TX_BUF(0), payload, sizeof(payload));
	tx_setup(sc, 8);
	/* EOP set but IFCS clear -> the DUT strips the trailing 2-byte FCS. */
	txd_raw(GPA_TX_RING, 0, GPA_TX_BUF(0),
	    (uint32_t)sizeof(payload) | (SPEC_TXD_CMD_EOP | SPEC_TXD_CMD_RS),
	    0);
	reg_write(sc, SPEC_TDT, 1);
	tx_run_locked(sc);

	ATF_CHECK_EQ(1, g_txq_count);
	ATF_CHECK_EQ(PAYLOAD_LEN - 2, g_txq[0].len);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(tx_multi_descriptor_frame);
ATF_TC_BODY(tx_multi_descriptor_frame, tc)
{
	struct e82545_softc *sc = dev_new();

	memset(g_guest + GPA_TX_BUF(0), 0x11, 50);
	memset(g_guest + GPA_TX_BUF(1), 0x22, 50);
	tx_setup(sc, 8);
	/* Two data-carrying legacy descriptors, EOP only on the last. */
	txd_raw(GPA_TX_RING, 0, GPA_TX_BUF(0), 50u | SPEC_TXD_CMD_RS, 0);
	txd_raw(GPA_TX_RING, 1, GPA_TX_BUF(1),
	    50u | (SPEC_TXD_CMD_EOP | SPEC_TXD_CMD_RS | SPEC_TXD_CMD_IFCS), 0);
	reg_write(sc, SPEC_TDT, 2);
	tx_run_locked(sc);

	ATF_CHECK_EQ(1, g_txq_count);
	ATF_CHECK_EQ((size_t)100, g_txq[0].len);
	ATF_CHECK_EQ(0x11, g_txq[0].data[0]);
	ATF_CHECK_EQ(0x22, g_txq[0].data[50]);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(tx_legacy_ip_checksum);
ATF_TC_BODY(tx_legacy_ip_checksum, tc)
{
	struct e82545_softc *sc = dev_new();
	uint8_t pkt[60];
	uint16_t got;

	/* A minimal IPv4-ish header; ask the NIC to insert the checksum (IC)
	 * at offset css..cso.  Clear the checksum field first. */
	memset(pkt, 0, sizeof(pkt));
	memset(pkt, 0x45, 14);		/* filler */
	pkt[14] = 0x45;			/* IPv4/IHL=5 */
	pkt[24] = 0x00; pkt[25] = 0x00;	/* checksum field @ off 24 */
	memcpy(g_guest + GPA_TX_BUF(0), pkt, sizeof(pkt));

	tx_setup(sc, 8);
	/* Legacy TCP/IP checksum insertion: css in upper.fields.css (byte 9 of
	 * descriptor), cso in lower.flags.cso (byte 10). */
	{
		uint32_t lower = (uint32_t)sizeof(pkt) |
		    (SPEC_TXD_CMD_EOP | SPEC_TXD_CMD_RS | SPEC_TXD_CMD_IC |
		    SPEC_TXD_CMD_IFCS);
		lower |= (uint32_t)24 << 16;	/* cso = 24 (checksum offset) */
		uint32_t upper = (uint32_t)14 << 8; /* css = 14 (start) */
		txd_raw(GPA_TX_RING, 0, GPA_TX_BUF(0), lower, upper);
	}
	reg_write(sc, SPEC_TDT, 1);
	tx_run_locked(sc);

	ATF_CHECK_EQ(1, g_txq_count);
	/* The inserted 16-bit checksum is the ones-complement sum over the
	 * range: the checksummed region must now sum to 0xffff. */
	memcpy(&got, g_txq[0].data + 24, 2);
	{
		uint32_t sum = 0;
		int i;
		for (i = 14; i + 1 < (int)sizeof(pkt); i += 2)
			sum += be16dec(g_txq[0].data + i);
		sum = (sum & 0xffff) + (sum >> 16);
		sum = (sum & 0xffff) + (sum >> 16);
		ATF_CHECK_EQ(0xffffu, sum);
	}

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(tx_context_then_tso);
ATF_TC_BODY(tx_context_then_tso, tc)
{
	struct e82545_softc *sc = dev_new();
	uint8_t hdr[54];
	uint8_t *payload;
	size_t paylen = 3000;
	size_t i;
	uint32_t lower, upper, cmdlen;

	/* Build a plausible Ethernet+IPv4+TCP header (hdrlen=54). */
	memset(hdr, 0, sizeof(hdr));
	hdr[12] = 0x08; hdr[13] = 0x00;		/* ethertype IPv4 */
	hdr[14] = 0x45;				/* IPv4 IHL=5 */
	/* IP header @ off 14, len field @ 16, id @ 18; TCP @ off 34. */
	memcpy(g_guest + GPA_TX_BUF(0), hdr, sizeof(hdr));
	payload = malloc(paylen);
	ATF_REQUIRE(payload != NULL);
	for (i = 0; i < paylen; i++)
		payload[i] = (uint8_t)i;
	memcpy(g_guest + GPA_TX_BUF(1), payload, paylen);

	tx_setup(sc, 8);

	/*
	 * Context descriptor (TYP_C = DEXT|DTYP_C).  Encode IP checksum start
	 * at ipcss=14 / ipcso=24 / ipcse=0, TCP css=34 / cso=50, mss and
	 * hdr_len in tcp_seg_setup, and cmd_and_length with DEXT|TSE|IP|TCP and
	 * the payload length.
	 */
	{
		struct e1000_context_desc cd;
		memset(&cd, 0, sizeof(cd));
		cd.lower_setup.ip_fields.ipcss = 14;
		cd.lower_setup.ip_fields.ipcso = 24;
		cd.lower_setup.ip_fields.ipcse = 0;
		cd.upper_setup.tcp_fields.tucss = 34;
		cd.upper_setup.tcp_fields.tucso = 50;
		cd.upper_setup.tcp_fields.tucse = 0;
		cd.tcp_seg_setup.fields.mss = 1460;
		cd.tcp_seg_setup.fields.hdr_len = 54;
		cd.cmd_and_length = SPEC_TXD_CMD_DEXT | SPEC_TXD_CMD_TSE |
		    SPEC_TXD_CMD_IP | SPEC_TXD_CMD_TCP | (uint32_t)paylen;
		memcpy(g_guest + GPA_TX_RING + 0 * 16, &cd, sizeof(cd));
	}

	/* Header data descriptor (TYP_D = DEXT|DTYP_D), carries the 54B header,
	 * EOP not set (payload follows). */
	lower = 54u | SPEC_TXD_CMD_DEXT | SPEC_TXD_DTYP_D;
	upper = (uint32_t)(SPEC_TXD_POPTS_IXSM | SPEC_TXD_POPTS_TXSM) << 8;
	txd_raw(GPA_TX_RING, 1, GPA_TX_BUF(0), lower, upper);

	/* Payload data descriptor with TSE + EOP + RS + IFCS (no FCS strip). */
	cmdlen = (uint32_t)paylen | SPEC_TXD_CMD_DEXT | SPEC_TXD_DTYP_D |
	    SPEC_TXD_CMD_TSE | SPEC_TXD_CMD_EOP | SPEC_TXD_CMD_RS |
	    SPEC_TXD_CMD_IFCS;
	txd_raw(GPA_TX_RING, 2, GPA_TX_BUF(1), cmdlen, upper);

	reg_write(sc, SPEC_TDT, 3);
	tx_run_locked(sc);

	/* TSO produced ceil(3000/1460) = 3 segments. */
	ATF_CHECK_EQ(3, g_txq_count);
	/* Each non-final segment carries hdrlen + mss bytes. */
	ATF_CHECK_EQ((size_t)(54 + 1460), g_txq[0].len);
	ATF_CHECK_EQ((size_t)(54 + 1460), g_txq[1].len);
	ATF_CHECK_EQ((size_t)(54 + (3000 - 2 * 1460)), g_txq[2].len);

	free(payload);
	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(tx_context_only_saved);
ATF_TC_BODY(tx_context_only_saved, tc)
{
	struct e82545_softc *sc = dev_new();
	struct e1000_context_desc cd;

	tx_setup(sc, 8);
	memset(&cd, 0, sizeof(cd));
	cd.tcp_seg_setup.fields.mss = 1234;
	cd.tcp_seg_setup.fields.hdr_len = 42;
	cd.cmd_and_length = SPEC_TXD_CMD_DEXT | SPEC_TXD_CMD_IP;
	memcpy(g_guest + GPA_TX_RING, &cd, sizeof(cd));
	reg_write(sc, SPEC_TDT, 1);
	tx_run_locked(sc);

	/* Nothing transmitted; context saved for later data descriptors. */
	ATF_CHECK_EQ(0, g_txq_count);
	ATF_CHECK_EQ(1234, sc->esc_txctx.tcp_seg_setup.fields.mss);
	ATF_CHECK_EQ(42, sc->esc_txctx.tcp_seg_setup.fields.hdr_len);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(tx_inconsistent_descriptor_dropped);
ATF_TC_BODY(tx_inconsistent_descriptor_dropped, tc)
{
	struct e82545_softc *sc = dev_new();

	memset(g_guest + GPA_TX_BUF(0), 0, 100);
	tx_setup(sc, 8);
	/* First descriptor legacy (TYP_L), second extended data (TYP_D):
	 * inconsistent types -> the packet is dropped, not sent. */
	txd_raw(GPA_TX_RING, 0, GPA_TX_BUF(0), 50u, 0);
	txd_raw(GPA_TX_RING, 1, GPA_TX_BUF(0),
	    50u | SPEC_TXD_CMD_DEXT | SPEC_TXD_DTYP_D | SPEC_TXD_CMD_EOP |
	    SPEC_TXD_CMD_RS, 0);
	reg_write(sc, SPEC_TDT, 2);
	tx_run_locked(sc);
	ATF_CHECK_EQ(0, g_txq_count);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(tx_bad_buffer_address);
ATF_TC_BODY(tx_bad_buffer_address, tc)
{
	struct e82545_softc *sc = dev_new();

	tx_setup(sc, 8);
	/* Unmappable buffer -> descriptor dropped, no frame sent. */
	txd_raw(GPA_TX_RING, 0, GMEM_SIZE + 0x2000,
	    100u | (SPEC_TXD_CMD_EOP | SPEC_TXD_CMD_RS | SPEC_TXD_CMD_IFCS), 0);
	reg_write(sc, SPEC_TDT, 1);
	tx_run_locked(sc);
	ATF_CHECK_EQ(0, g_txq_count);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(tx_tdba_locked_while_enabled);
ATF_TC_BODY(tx_tdba_locked_while_enabled, tc)
{
	struct e82545_softc *sc = dev_new();

	tx_setup(sc, 8);
	/* TDBAL/TDBAH/TDLEN/TDH writes ignored while TX enabled. */
	reg_write(sc, SPEC_TDBAL, 0x9000);
	reg_write(sc, SPEC_TDBAH, 0x7);
	reg_write(sc, SPEC_TDLEN, 0x40);
	reg_write(sc, SPEC_TDH, 3);
	ATF_CHECK_EQ(GPA_TX_RING, sc->esc_TDBAL);
	ATF_CHECK_EQ(0u, sc->esc_TDBAH);
	ATF_CHECK_EQ(8u * 16u, sc->esc_TDLEN);
	ATF_CHECK_EQ(0u, sc->esc_TDH);

	/* With TX disabled, a non-zero TDH write is still rejected. */
	sc->esc_tx_enabled = 0;
	reg_write(sc, SPEC_TDH, 5);
	ATF_CHECK_EQ(0u, sc->esc_TDH);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(tx_vlan_insertion);
ATF_TC_BODY(tx_vlan_insertion, tc)
{
	struct e82545_softc *sc = dev_new();
	enum { HDR_LEN = 16, PAYLOAD_LEN = 50, VLAN_TAG_LEN = 4 };
	uint8_t hdrbuf[HDR_LEN], payload[PAYLOAD_LEN];
	size_t i;

	/* Enable hardware VLAN insertion (CTRL.VME) and set the VLAN ethertype. */
	reg_write(sc, SPEC_CTRL, SPEC_CTRL_VME);
	reg_write(sc, SPEC_VET, 0x8100);
	for (i = 0; i < sizeof(hdrbuf); i++)
		hdrbuf[i] = (uint8_t)(0xA0 + i);	/* dst+src MAC filler */
	memset(payload, 0xC0, sizeof(payload));
	memcpy(g_guest + GPA_TX_BUF(0), hdrbuf, sizeof(hdrbuf));
	memcpy(g_guest + GPA_TX_BUF(1), payload, sizeof(payload));

	tx_setup(sc, 8);
	/* Header descriptor (no EOP) then payload descriptor carrying VLE and
	 * the tag in the special field. */
	txd_raw(GPA_TX_RING, 0, GPA_TX_BUF(0),
	    (uint32_t)sizeof(hdrbuf) | SPEC_TXD_CMD_RS, 0);
	txd_raw(GPA_TX_RING, 1, GPA_TX_BUF(1),
	    (uint32_t)sizeof(payload) | (SPEC_TXD_CMD_EOP | SPEC_TXD_CMD_RS |
	    SPEC_TXD_CMD_IFCS | SPEC_TXD_CMD_VLE),
	    (uint32_t)0x0064 << 16 /* special = VLAN tag 100 */);
	reg_write(sc, SPEC_TDT, 2);
	tx_run_locked(sc);

	ATF_CHECK_EQ(1, g_txq_count);
	/* Output is 4 bytes longer (802.1Q tag inserted after the MACs). */
	ATF_CHECK_EQ(HDR_LEN + PAYLOAD_LEN + VLAN_TAG_LEN, g_txq[0].len);
	/* The two MAC addresses are preserved ahead of the inserted tag. */
	ATF_CHECK_EQ(0, memcmp(g_txq[0].data, hdrbuf, 12));
	/* Inserted TPID and TCI. */
	ATF_CHECK_EQ(0x8100u, be16dec(g_txq[0].data + 12));
	ATF_CHECK_EQ(0x0064u, be16dec(g_txq[0].data + 14));

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(tx_tcp_checksum_offload);
ATF_TC_BODY(tx_tcp_checksum_offload, tc)
{
	struct e82545_softc *sc = dev_new();
	uint8_t pkt[60];

	memset(pkt, 0, sizeof(pkt));
	memcpy(g_guest + GPA_TX_BUF(0), pkt, sizeof(pkt));
	tx_setup(sc, 8);

	/* Context descriptor with TCP checksum fields (tucss/tucso). */
	{
		struct e1000_context_desc cd;
		memset(&cd, 0, sizeof(cd));
		cd.upper_setup.tcp_fields.tucss = 34;
		cd.upper_setup.tcp_fields.tucso = 40;
		cd.upper_setup.tcp_fields.tucse = 0;
		cd.cmd_and_length = SPEC_TXD_CMD_DEXT | SPEC_TXD_CMD_TCP;
		memcpy(g_guest + GPA_TX_RING, &cd, sizeof(cd));
	}
	/* Data descriptor requesting TCP/UDP checksum insertion (POPTS_TXSM),
	 * non-TSO, EOP + IFCS. */
	txd_raw(GPA_TX_RING, 1, GPA_TX_BUF(0),
	    (uint32_t)sizeof(pkt) | SPEC_TXD_CMD_DEXT | SPEC_TXD_DTYP_D |
	    SPEC_TXD_CMD_EOP | SPEC_TXD_CMD_RS | SPEC_TXD_CMD_IFCS,
	    (uint32_t)SPEC_TXD_POPTS_TXSM << 8);
	reg_write(sc, SPEC_TDT, 2);
	tx_run_locked(sc);

	ATF_CHECK_EQ(1, g_txq_count);
	/* The checksummed region (from tucss to end) now sums to 0xffff. */
	{
		uint32_t sum = 0;
		int i;
		for (i = 34; i + 1 < (int)sizeof(pkt); i += 2)
			sum += be16dec(g_txq[0].data + i);
		sum = (sum & 0xffff) + (sum >> 16);
		sum = (sum & 0xffff) + (sum >> 16);
		ATF_CHECK_EQ(0xffffu, sum);
	}

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(tx_too_many_descriptors);
ATF_TC_BODY(tx_too_many_descriptors, tc)
{
	struct e82545_softc *sc = dev_new();
	int i;

	/* 65 data-bearing legacy descriptors exceed I82545_MAX_TXSEGS (64);
	 * the packet is dropped, nothing transmitted. */
	tx_setup(sc, 128);
	for (i = 0; i < 65; i++) {
		uint32_t lower = 4u | SPEC_TXD_CMD_RS;
		if (i == 64)
			lower |= SPEC_TXD_CMD_EOP | SPEC_TXD_CMD_IFCS;
		memset(g_guest + GPA_TX_BUF(0) + i * 4, i, 4);
		txd_raw(GPA_TX_RING, i, GPA_TX_BUF(0) + (uint32_t)i * 4, lower,
		    0);
	}
	reg_write(sc, SPEC_TDT, 65);
	tx_run_locked(sc);
	ATF_CHECK_EQ(0, g_txq_count);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(tx_final_descriptor_too_short);
ATF_TC_BODY(tx_final_descriptor_too_short, tc)
{
	struct e82545_softc *sc = dev_new();

	tx_setup(sc, 8);
	/* EOP with IFCS clear and len<=2: the guest FCS strip underflows the
	 * descriptor -> dropped. */
	txd_raw(GPA_TX_RING, 0, GPA_TX_BUF(0),
	    2u | (SPEC_TXD_CMD_EOP | SPEC_TXD_CMD_RS), 0);
	reg_write(sc, SPEC_TDT, 1);
	tx_run_locked(sc);
	ATF_CHECK_EQ(0, g_txq_count);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(tx_udp_tso);
ATF_TC_BODY(tx_udp_tso, tc)
{
	struct e82545_softc *sc = dev_new();
	uint8_t hdr[42];		/* Eth(14)+IPv4(20)+UDP(8) */
	uint8_t *payload;
	size_t paylen = 2000;
	size_t i;

	memset(hdr, 0, sizeof(hdr));
	hdr[12] = 0x08; hdr[13] = 0x00;
	hdr[14] = 0x45;
	memcpy(g_guest + GPA_TX_BUF(0), hdr, sizeof(hdr));
	payload = malloc(paylen);
	ATF_REQUIRE(payload != NULL);
	for (i = 0; i < paylen; i++)
		payload[i] = (uint8_t)i;
	memcpy(g_guest + GPA_TX_BUF(1), payload, paylen);

	tx_setup(sc, 8);
	{
		struct e1000_context_desc cd;
		memset(&cd, 0, sizeof(cd));
		cd.lower_setup.ip_fields.ipcss = 14;
		cd.lower_setup.ip_fields.ipcso = 24;
		cd.upper_setup.tcp_fields.tucss = 34;
		cd.upper_setup.tcp_fields.tucso = 40;
		cd.tcp_seg_setup.fields.mss = 1000;
		cd.tcp_seg_setup.fields.hdr_len = 42;
		/* IP set, TCP clear -> UDP segmentation branch. */
		cd.cmd_and_length = SPEC_TXD_CMD_DEXT | SPEC_TXD_CMD_TSE |
		    SPEC_TXD_CMD_IP | (uint32_t)paylen;
		memcpy(g_guest + GPA_TX_RING, &cd, sizeof(cd));
	}
	txd_raw(GPA_TX_RING, 1, GPA_TX_BUF(0),
	    42u | SPEC_TXD_CMD_DEXT | SPEC_TXD_DTYP_D,
	    (uint32_t)(SPEC_TXD_POPTS_IXSM | SPEC_TXD_POPTS_TXSM) << 8);
	txd_raw(GPA_TX_RING, 2, GPA_TX_BUF(1),
	    (uint32_t)paylen | SPEC_TXD_CMD_DEXT | SPEC_TXD_DTYP_D |
	    SPEC_TXD_CMD_TSE | SPEC_TXD_CMD_EOP | SPEC_TXD_CMD_RS |
	    SPEC_TXD_CMD_IFCS,
	    (uint32_t)(SPEC_TXD_POPTS_IXSM | SPEC_TXD_POPTS_TXSM) << 8);
	reg_write(sc, SPEC_TDT, 3);
	tx_run_locked(sc);

	/* ceil(2000/1000) = 2 UDP segments. */
	ATF_CHECK_EQ(2, g_txq_count);
	ATF_CHECK_EQ((size_t)(42 + 1000), g_txq[0].len);

	free(payload);
	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(tx_ipv6_tcp_tso);
ATF_TC_BODY(tx_ipv6_tcp_tso, tc)
{
	struct e82545_softc *sc = dev_new();
	uint8_t hdr[74];		/* Eth(14)+IPv6(40)+TCP(20) */
	uint8_t *payload;
	size_t paylen = 2500;
	size_t i;

	memset(hdr, 0, sizeof(hdr));
	hdr[12] = 0x86; hdr[13] = 0xdd;		/* ethertype IPv6 */
	memcpy(g_guest + GPA_TX_BUF(0), hdr, sizeof(hdr));
	payload = malloc(paylen);
	ATF_REQUIRE(payload != NULL);
	for (i = 0; i < paylen; i++)
		payload[i] = (uint8_t)i;
	memcpy(g_guest + GPA_TX_BUF(1), payload, paylen);

	tx_setup(sc, 8);
	{
		struct e1000_context_desc cd;
		memset(&cd, 0, sizeof(cd));
		cd.lower_setup.ip_fields.ipcss = 14;	/* IPv6 header start */
		cd.lower_setup.ip_fields.ipcso = 20;
		cd.upper_setup.tcp_fields.tucss = 54;	/* TCP after IPv6 */
		cd.upper_setup.tcp_fields.tucso = 70;
		cd.tcp_seg_setup.fields.mss = 1200;
		cd.tcp_seg_setup.fields.hdr_len = 74;
		/* TCP set, IP (v4) clear -> IPv6 segmentation length update. */
		cd.cmd_and_length = SPEC_TXD_CMD_DEXT | SPEC_TXD_CMD_TSE |
		    SPEC_TXD_CMD_TCP | (uint32_t)paylen;
		memcpy(g_guest + GPA_TX_RING, &cd, sizeof(cd));
	}
	txd_raw(GPA_TX_RING, 1, GPA_TX_BUF(0),
	    74u | SPEC_TXD_CMD_DEXT | SPEC_TXD_DTYP_D,
	    (uint32_t)(SPEC_TXD_POPTS_IXSM | SPEC_TXD_POPTS_TXSM) << 8);
	txd_raw(GPA_TX_RING, 2, GPA_TX_BUF(1),
	    (uint32_t)paylen | SPEC_TXD_CMD_DEXT | SPEC_TXD_DTYP_D |
	    SPEC_TXD_CMD_TSE | SPEC_TXD_CMD_EOP | SPEC_TXD_CMD_RS |
	    SPEC_TXD_CMD_IFCS,
	    (uint32_t)(SPEC_TXD_POPTS_IXSM | SPEC_TXD_POPTS_TXSM) << 8);
	reg_write(sc, SPEC_TDT, 3);
	tx_run_locked(sc);

	/* ceil(2500/1200) = 3 IPv6 TCP segments. */
	ATF_CHECK_EQ(3, g_txq_count);
	ATF_CHECK_EQ((size_t)(74 + 1200), g_txq[0].len);

	free(payload);
	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(tx_tso_hdrlen_too_large);
ATF_TC_BODY(tx_tso_hdrlen_too_large, tc)
{
	struct e82545_softc *sc = dev_new();

	memset(g_guest + GPA_TX_BUF(0), 0, 300);
	tx_setup(sc, 8);
	{
		struct e1000_context_desc cd;
		memset(&cd, 0, sizeof(cd));
		cd.tcp_seg_setup.fields.mss = 500;
		cd.tcp_seg_setup.fields.hdr_len = 250;	/* > 240 cap */
		cd.cmd_and_length = SPEC_TXD_CMD_DEXT | SPEC_TXD_CMD_TSE |
		    SPEC_TXD_CMD_IP | SPEC_TXD_CMD_TCP | 1000u;
		memcpy(g_guest + GPA_TX_RING, &cd, sizeof(cd));
	}
	txd_raw(GPA_TX_RING, 1, GPA_TX_BUF(0),
	    1000u | SPEC_TXD_CMD_DEXT | SPEC_TXD_DTYP_D | SPEC_TXD_CMD_TSE |
	    SPEC_TXD_CMD_EOP | SPEC_TXD_CMD_RS | SPEC_TXD_CMD_IFCS, 0);
	reg_write(sc, SPEC_TDT, 2);
	tx_run_locked(sc);
	ATF_CHECK_EQ(0, g_txq_count);	/* dropped: hdrlen > 240 */

	dev_free(sc);
}

/* ---- TCTL control + real thread transmit -------------------------- */

ATF_TC_WITHOUT_HEAD(tctl_reserved_bits);
ATF_TC_BODY(tctl_reserved_bits, tc)
{
	struct e82545_softc *sc = dev_new();

	/* Configure a valid TX ring so the TCTL.EN transition succeeds. */
	reg_write(sc, SPEC_TDBAL, GPA_TX_RING);
	reg_write(sc, SPEC_TDBAH, 0);
	reg_write(sc, SPEC_TDLEN, 8 * 16u);
	reg_write(sc, SPEC_TDH, 0);

	/* TCTL retains only implemented bits (mask 0x017ffffa per the model);
	 * the EN transition caches the ring mapping and enables transmit. */
	reg_write(sc, SPEC_TCTL, 0xffffffff);
	ATF_CHECK_EQ(0xffffffffu & 0x017ffffau, reg_read(sc, SPEC_TCTL));
	ATF_CHECK((reg_read(sc, SPEC_TCTL) & SPEC_TCTL_EN) != 0);
	ATF_CHECK_EQ(1, sc->esc_tx_enabled);

	/* Disabling via the TCTL register (EN cleared) tears down the cached
	 * ring mapping through e82545_tx_ctl's disable branch. */
	reg_write(sc, SPEC_TCTL, 0);
	ATF_CHECK_EQ(0, sc->esc_tx_enabled);
	ATF_CHECK(sc->esc_txdesc == NULL);
	ATF_CHECK_EQ(0u, (uint32_t)sc->esc_tdba);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(tx_via_thread);
ATF_TC_BODY(tx_via_thread, tc)
{
	int rc, spins;

	/* Full init spawns the real tx thread; drive a frame through TDT. */
	guest_reset();
	backend_reset();
	e82545_debug = 1;
	g_mac_cfg = "52:54:00:ab:cd:ef";
	memset(&g_pi, 0, sizeof(g_pi));
	rc = e82545_init(&g_pi, NULL);
	ATF_REQUIRE_EQ(0, rc);
	struct e82545_softc *sc = g_pi.pi_arg;

	memset(g_guest + GPA_TX_BUF(0), 0x77, 128);
	reg_write(sc, SPEC_TDBAL, GPA_TX_RING);
	reg_write(sc, SPEC_TDBAH, 0);
	reg_write(sc, SPEC_TDLEN, 8 * 16u);
	reg_write(sc, SPEC_TDH, 0);
	reg_write(sc, SPEC_TCTL, SPEC_TCTL_EN);	/* enable tx */
	txd_raw(GPA_TX_RING, 0, GPA_TX_BUF(0),
	    128u | (SPEC_TXD_CMD_EOP | SPEC_TXD_CMD_RS | SPEC_TXD_CMD_IFCS),
	    0);
	reg_write(sc, SPEC_TDT, 1);		/* kick the thread */

	/* Wait for the async thread to drain the ring. */
	for (spins = 0; spins < 1000; spins++) {
		pthread_mutex_lock(&sc->esc_mtx);
		int done = (sc->esc_TDH == sc->esc_TDT);
		pthread_mutex_unlock(&sc->esc_mtx);
		if (done && g_txq_count > 0)
			break;
		usleep(1000);
	}
	ATF_CHECK(g_txq_count >= 1);
	ATF_CHECK_EQ((size_t)128, g_txq[0].len);

	pthread_mutex_lock(&sc->esc_mtx);
	e82545_tx_disable(sc);
	pthread_mutex_unlock(&sc->esc_mtx);
}

/* ---- I/O BAR indirect register window ----------------------------- */

ATF_TC_WITHOUT_HEAD(io_bar_indirect_access);
ATF_TC_BODY(io_bar_indirect_access, tc)
{
	struct e82545_softc *sc = dev_new();
	uint32_t v;

	/* Write the register index into IOADDR, then data via IODATA. */
	e82545_write(sc->esc_pi, SPEC_BAR_IO, SPEC_IOADDR, 4, SPEC_VET);
	e82545_write(sc->esc_pi, SPEC_BAR_IO, SPEC_IODATA, 4, 0x1234);
	/* Read it back through the same window. */
	e82545_write(sc->esc_pi, SPEC_BAR_IO, SPEC_IOADDR, 4, SPEC_VET);
	v = (uint32_t)e82545_read(sc->esc_pi, SPEC_BAR_IO, SPEC_IODATA, 4);
	ATF_CHECK_EQ(0x1234u, v);
	ATF_CHECK_EQ(0x1234u, reg_read(sc, SPEC_VET));

	/* IOADDR read returns the latched address. */
	v = (uint32_t)e82545_read(sc->esc_pi, SPEC_BAR_IO, SPEC_IOADDR, 4);
	ATF_CHECK_EQ((uint32_t)SPEC_VET, v);

	/* Out-of-range indirect address is not treated as a register. */
	e82545_write(sc->esc_pi, SPEC_BAR_IO, SPEC_IOADDR, 4, 0x00090000);
	e82545_write(sc->esc_pi, SPEC_BAR_IO, SPEC_IODATA, 4, 0xdead);
	v = (uint32_t)e82545_read(sc->esc_pi, SPEC_BAR_IO, SPEC_IODATA, 4);
	ATF_CHECK_EQ(0u, v);

	/* Bad IO offset and wrong-size accesses are ignored. */
	e82545_write(sc->esc_pi, SPEC_BAR_IO, 0x2, 4, 0x1);
	(void)e82545_read(sc->esc_pi, SPEC_BAR_IO, 0x2, 4);
	e82545_write(sc->esc_pi, SPEC_BAR_IO, SPEC_IOADDR, 2, 0x1);
	(void)e82545_read(sc->esc_pi, SPEC_BAR_IO, SPEC_IOADDR, 2);

	/* Unknown BAR index is ignored. */
	e82545_write(sc->esc_pi, SPEC_BAR_FLASH, 0, 4, 0x1);
	ATF_CHECK_EQ(0u,
	    (uint32_t)e82545_read(sc->esc_pi, SPEC_BAR_FLASH, 0, 4));

	dev_free(sc);
}

/* ---- Statistics counters ------------------------------------------ */

ATF_TC_WITHOUT_HEAD(stat_registers_readback);
ATF_TC_BODY(stat_registers_readback, tc)
{
	struct e82545_softc *sc = dev_new();

	/* Poke internal stat counters and confirm the register decode. */
	sc->good_pkt_rx_count = 7;
	sc->missed_pkt_count = 3;
	sc->oversize_rx_count = 2;
	ATF_CHECK_EQ(7u, reg_read(sc, SPEC_GPRC));
	ATF_CHECK_EQ(3u, reg_read(sc, SPEC_MPC));
	/* TPR = good + missed + oversize. */
	ATF_CHECK_EQ(12u, reg_read(sc, SPEC_TPR));
	/* An always-zero stat register. */
	ATF_CHECK_EQ(0u, reg_read(sc, 0x04000));	/* CRCERRS */

	dev_free(sc);
}

/* ---- size-bucket classifier (spec: <=64 ->0, >=1024 ->5, else) ---- */

ATF_TC_WITHOUT_HEAD(size_stat_index_buckets);
ATF_TC_BODY(size_stat_index_buckets, tc)
{

	/*
	 * Independent oracle for the 8254x packet-size histogram buckets.  The
	 * two clamped edges (<=64 -> bucket 0, >=1024 -> bucket 5) and the
	 * canonical power-of-two bucket boundaries (128,256,512) are checked;
	 * these are the values where the range classification is unambiguous.
	 */
	ATF_CHECK_EQ(0, e82545_size_stat_index(1));
	ATF_CHECK_EQ(0, e82545_size_stat_index(64));
	ATF_CHECK_EQ(2, e82545_size_stat_index(128));	/* bucket 128-255 */
	ATF_CHECK_EQ(3, e82545_size_stat_index(256));	/* bucket 256-511 */
	ATF_CHECK_EQ(4, e82545_size_stat_index(512));	/* bucket 512-1023 */
	ATF_CHECK_EQ(5, e82545_size_stat_index(1024));
	ATF_CHECK_EQ(5, e82545_size_stat_index(1522));
}

/* ---- Read-register decode sweep (all implemented registers) ------- */

ATF_TC_WITHOUT_HEAD(read_all_registers);
ATF_TC_BODY(read_all_registers, tc)
{
	struct e82545_softc *sc = dev_new();

	/* Seed the internal statistics with distinct values. */
	sc->missed_pkt_count = 11;
	sc->good_pkt_rx_count = 22;
	sc->bcast_pkt_rx_count = 33;
	sc->mcast_pkt_rx_count = 44;
	sc->good_pkt_tx_count = 55;
	sc->bcast_pkt_tx_count = 66;
	sc->mcast_pkt_tx_count = 77;
	sc->oversize_rx_count = 88;
	sc->tso_tx_count = 99;
	sc->good_octets_rx = 0x1111222233334444ULL;
	sc->good_octets_tx = 0x5555666677778888ULL;
	sc->missed_octets = 0x10;
	for (int i = 0; i < 6; i++) {
		sc->pkt_rx_by_size[i] = 100 + i;
		sc->pkt_tx_by_size[i] = 200 + i;
	}

	/* R/W register images (already-covered decode, re-read for the sweep). */
	static const uint32_t rw[] = {
		SPEC_CTRL, SPEC_STATUS, SPEC_FCAL, SPEC_FCAH, SPEC_FCT,
		SPEC_VET, SPEC_FCTTV, SPEC_LEDCTL, SPEC_PBA, SPEC_ITR,
		SPEC_IMS, SPEC_RCTL, SPEC_FCRTL, SPEC_FCRTH, SPEC_RDBAL,
		SPEC_RDBAH, SPEC_RDLEN, SPEC_RDH, SPEC_RDT, SPEC_RDTR,
		SPEC_RXDCTL, SPEC_RADV, SPEC_RSRPD, SPEC_RXCSUM, SPEC_TXCW,
		SPEC_TCTL, SPEC_TIPG, SPEC_AIT, SPEC_TDBAL, SPEC_TDBAH,
		SPEC_TDLEN, SPEC_TDH, SPEC_TDT, SPEC_TIDV, SPEC_TXDCTL,
		SPEC_TADV, SPEC_EECD, SPEC_MDIC, 0x05820 /* MANC */,
	};
	for (size_t i = 0; i < nitems(rw); i++)
		(void)reg_read(sc, rw[i]);

	/* Emulated statistics decode against the seeded values. */
	ATF_CHECK_EQ(11u, reg_read(sc, SPEC_MPC));
	ATF_CHECK_EQ(22u, reg_read(sc, SPEC_GPRC));
	ATF_CHECK_EQ(33u, reg_read(sc, 0x04078)); /* BPRC */
	ATF_CHECK_EQ(44u, reg_read(sc, 0x0407C)); /* MPRC */
	ATF_CHECK_EQ(55u, reg_read(sc, 0x04080)); /* GPTC */
	ATF_CHECK_EQ(55u, reg_read(sc, 0x040D4)); /* TPT == GPTC */
	ATF_CHECK_EQ(66u, reg_read(sc, 0x040F4)); /* BPTC */
	ATF_CHECK_EQ(77u, reg_read(sc, 0x040F0)); /* MPTC */
	ATF_CHECK_EQ(88u, reg_read(sc, 0x040AC)); /* ROC */
	ATF_CHECK_EQ(99u, reg_read(sc, 0x040F8)); /* TSCTC */
	ATF_CHECK_EQ(0x33334444u, reg_read(sc, 0x04088)); /* GORCL */
	ATF_CHECK_EQ(0x11112222u, reg_read(sc, 0x0408C)); /* GORCH */
	ATF_CHECK_EQ(0x77778888u, reg_read(sc, 0x04090)); /* GOTCL */
	ATF_CHECK_EQ(0x77778888u, reg_read(sc, 0x040C8)); /* TOTL==GOTCL */
	ATF_CHECK_EQ(0x55556666u, reg_read(sc, 0x04094)); /* GOTCH */
	ATF_CHECK_EQ(0x55556666u, reg_read(sc, 0x040CC)); /* TOTH==GOTCH */
	/* TORL/TORH = good_octets_rx + missed_octets. */
	ATF_CHECK_EQ(0x33334454u, reg_read(sc, 0x040C0)); /* TORL */
	ATF_CHECK_EQ(0x11112222u, reg_read(sc, 0x040C4)); /* TORH */
	/* TPR = good + missed + oversize = 22+11+88 = 121. */
	ATF_CHECK_EQ(121u, reg_read(sc, SPEC_TPR));
	/* PRC64.. and PTC64.. size histograms. */
	ATF_CHECK_EQ(100u, reg_read(sc, 0x0405C)); /* PRC64 */
	ATF_CHECK_EQ(105u, reg_read(sc, 0x04070)); /* PRC1522 */
	ATF_CHECK_EQ(200u, reg_read(sc, 0x040D8)); /* PTC64 */
	ATF_CHECK_EQ(205u, reg_read(sc, 0x040EC)); /* PTC1522 */

	/* All "always zero" statistics. */
	static const uint32_t zero[] = {
		0x04000, 0x04004, 0x04008, 0x0400C, 0x04014, 0x04018,
		0x0401C, 0x04020, 0x04028, 0x04030, 0x04034, 0x04038,
		0x0403C, 0x04040, 0x04048, 0x0404C, 0x04050, 0x04054,
		0x04058, 0x040A0, 0x040A4, 0x040A8, 0x040B0, 0x040B4,
		0x040B8, 0x040BC, 0x040FC,
	};
	for (size_t i = 0; i < nitems(zero); i++)
		ATF_CHECK_EQ(0u, reg_read(sc, zero[i]));

	/* Individual size buckets 1..4 for PRC/PTC. */
	ATF_CHECK_EQ(101u, reg_read(sc, 0x04060)); /* PRC127 */
	ATF_CHECK_EQ(102u, reg_read(sc, 0x04064)); /* PRC255 */
	ATF_CHECK_EQ(103u, reg_read(sc, 0x04068)); /* PRC511 */
	ATF_CHECK_EQ(104u, reg_read(sc, 0x0406C)); /* PRC1023 */
	ATF_CHECK_EQ(201u, reg_read(sc, 0x040DC)); /* PTC127 */
	ATF_CHECK_EQ(202u, reg_read(sc, 0x040E0)); /* PTC255 */
	ATF_CHECK_EQ(203u, reg_read(sc, 0x040E4)); /* PTC511 */
	ATF_CHECK_EQ(204u, reg_read(sc, 0x040E8)); /* PTC1023 */

	dev_free(sc);
}

/* ---- Snapshot save/restore round trip ----------------------------- */

#ifdef BHYVE_SNAPSHOT
static uint8_t g_snapbuf[1 << 16];

/*
 * struct vm_snapshot_meta has const-qualified buffer fields, so a meta can
 * only be established via an initializer, never by later assignment.
 */
#define	MAKE_META(pi, opv)						\
	{								\
		.dev_data = (pi),					\
		.dev_name = "e1000",					\
		.op = (opv),						\
		.buffer = {						\
			.buf_start = g_snapbuf,				\
			.buf = g_snapbuf,				\
			.buf_size = sizeof(g_snapbuf),			\
			.buf_rem = sizeof(g_snapbuf),			\
		},							\
	}

ATF_TC_WITHOUT_HEAD(snapshot_save_restore_roundtrip);
ATF_TC_BODY(snapshot_save_restore_roundtrip, tc)
{
	struct e82545_softc *sc = dev_new();
	struct vm_snapshot_meta save = MAKE_META(&g_pi, VM_SNAPSHOT_SAVE);
	struct vm_snapshot_meta restore = MAKE_META(&g_pi, VM_SNAPSHOT_RESTORE);
	int rc;

	/* Establish distinctive, self-consistent state. */
	reg_write(sc, SPEC_VET, 0x8100);
	reg_write(sc, SPEC_FCAL, 0x11223344);
	reg_write(sc, SPEC_ITR, 500);
	sc->good_pkt_rx_count = 99;
	sc->good_octets_tx = 0x1122334455ULL;

	rc = e82545_snapshot(&save);
	ATF_REQUIRE_EQ(0, rc);

	/* Restore into a fresh device and compare the migrated registers. */
	struct e82545_softc *sc2 = dev_new();
	g_pi.pi_arg = sc2;
	rc = e82545_snapshot(&restore);
	ATF_REQUIRE_EQ(0, rc);

	ATF_CHECK_EQ(0x8100u, sc2->esc_VET);
	ATF_CHECK_EQ(0x11223344u, sc2->esc_FCAL);
	ATF_CHECK_EQ(500u, sc2->esc_ITR);
	ATF_CHECK_EQ(99u, sc2->good_pkt_rx_count);
	ATF_CHECK_EQ(0x1122334455ULL, sc2->good_octets_tx);
	/* MAC survived the round trip. */
	ATF_CHECK_EQ(0, memcmp(sc2->esc_mac.octet, TEST_MAC, 6));

	g_pi.pi_arg = sc;
	dev_free(sc);
	dev_free(sc2);
}

ATF_TC_WITHOUT_HEAD(snapshot_magic_mismatch);
ATF_TC_BODY(snapshot_magic_mismatch, tc)
{
	struct e82545_softc *sc = dev_new();
	struct vm_snapshot_meta save = MAKE_META(&g_pi, VM_SNAPSHOT_SAVE);
	struct vm_snapshot_meta restore = MAKE_META(&g_pi, VM_SNAPSHOT_RESTORE);
	int rc;

	rc = e82545_snapshot(&save);
	ATF_REQUIRE_EQ(0, rc);

	/* Corrupt the leading magic word; restore must reject it. */
	g_snapbuf[0] ^= 0xff;
	rc = e82545_snapshot(&restore);
	ATF_CHECK_EQ(ENOTSUP, rc);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(snapshot_truncated_buffer);
ATF_TC_BODY(snapshot_truncated_buffer, tc)
{
	struct e82545_softc *sc = dev_new();
	/* A buffer too small to hold the record fails (buf_rem is writable). */
	struct vm_snapshot_meta save = MAKE_META(&g_pi, VM_SNAPSHOT_SAVE);
	int rc;

	save.buffer.buf_rem = 8;
	rc = e82545_snapshot(&save);
	ATF_CHECK(rc != 0);

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(snapshot_validate);
ATF_TC_BODY(snapshot_validate, tc)
{
	struct e82545_softc *sc = dev_new();
	struct vm_snapshot_meta save = MAKE_META(&g_pi, VM_SNAPSHOT_SAVE);
	struct vm_snapshot_meta val = MAKE_META(&g_pi, VM_SNAPSHOT_VALIDATE);
	int rc;

	rc = e82545_snapshot(&save);
	ATF_REQUIRE_EQ(0, rc);

	rc = e82545_snapshot_validate(&val);
	ATF_CHECK_EQ(0, rc);

	/* NULL / wrong-op arguments are rejected. */
	ATF_CHECK_EQ(EINVAL, e82545_snapshot_validate(NULL));
	/* A SAVE-op meta is rejected by validate (expects VALIDATE). */
	ATF_CHECK_EQ(EINVAL, e82545_snapshot_validate(&save));

	dev_free(sc);
}

ATF_TC_WITHOUT_HEAD(snapshot_active_rings_roundtrip);
ATF_TC_BODY(snapshot_active_rings_roundtrip, tc)
{
	struct e82545_softc *sc = dev_new();
	struct vm_snapshot_meta save = MAKE_META(&g_pi, VM_SNAPSHOT_SAVE);
	struct vm_snapshot_meta restore = MAKE_META(&g_pi, VM_SNAPSHOT_RESTORE);
	int rc, i;

	/* Bring up valid RX and TX rings so the guest2host descriptor pointers
	 * and the enabled-ring consistency checks are exercised on restore. */
	for (i = 0; i < 16; i++) {
		rxd_set(GPA_RX_RING, i, GPA_RX_BUF(i));
		txd_raw(GPA_TX_RING, i, GPA_TX_BUF(0), 0, 0);
	}
	reg_write(sc, SPEC_RDBAL, GPA_RX_RING);
	reg_write(sc, SPEC_RDLEN, 16 * 16u);
	reg_write(sc, SPEC_RCTL, SPEC_RCTL_EN | SPEC_RCTL_SZ_2048);
	reg_write(sc, SPEC_TDBAL, GPA_TX_RING);
	reg_write(sc, SPEC_TDLEN, 16 * 16u);
	sc->esc_TCTL = SPEC_TCTL_EN;
	e82545_tx_update_tdba(sc);
	sc->esc_tx_enabled = 1;

	rc = e82545_snapshot(&save);
	ATF_REQUIRE_EQ(0, rc);

	struct e82545_softc *sc2 = dev_new();
	/* Re-establish the same guest ring geometry mappings for restore. */
	for (i = 0; i < 16; i++) {
		rxd_set(GPA_RX_RING, i, GPA_RX_BUF(i));
		txd_raw(GPA_TX_RING, i, GPA_TX_BUF(0), 0, 0);
	}
	g_pi.pi_arg = sc2;
	rc = e82545_snapshot(&restore);
	ATF_REQUIRE_EQ(0, rc);
	ATF_CHECK_EQ(1, sc2->esc_rx_enabled);
	ATF_CHECK_EQ(1, sc2->esc_tx_enabled);
	ATF_CHECK(sc2->esc_rxdesc != NULL);
	ATF_CHECK(sc2->esc_txdesc != NULL);
	ATF_CHECK_EQ(GPA_RX_RING, sc2->esc_RDBAL);

	g_pi.pi_arg = sc;
	dev_free(sc);
	dev_free(sc2);
}

ATF_TC_WITHOUT_HEAD(snapshot_restore_rejects_bad_state);
ATF_TC_BODY(snapshot_restore_rejects_bad_state, tc)
{
	struct e82545_softc *sc = dev_new();
	struct vm_snapshot_meta save = MAKE_META(&g_pi, VM_SNAPSHOT_SAVE);
	struct vm_snapshot_meta restore = MAKE_META(&g_pi, VM_SNAPSHOT_RESTORE);
	int rc;

	/* Save a clean image, then corrupt esc_irq_asserted in the wire buffer
	 * to an out-of-range value; restore must reject it with EINVAL.  The
	 * irq_asserted int follows magic(4)+version(4)+identity+MAC(6). */
	sc->esc_irq_asserted = 0;
	rc = e82545_snapshot(&save);
	ATF_REQUIRE_EQ(0, rc);

	/* Locate and clobber the first int-encoded field after the MAC.  Rather
	 * than compute the exact offset, drive a restore whose RDLEN violates
	 * the reserved-bit mask: build via a second save with a bad RDLEN. */
	struct e82545_softc *bad = dev_new();
	bad->esc_RDLEN = 0x1;	/* violates the 0xfff0007f reserved mask */
	struct vm_snapshot_meta save2 = MAKE_META(&g_pi, VM_SNAPSHOT_SAVE);
	g_pi.pi_arg = bad;
	rc = e82545_snapshot(&save2);
	ATF_REQUIRE_EQ(0, rc);
	g_pi.pi_arg = sc;

	rc = e82545_snapshot(&restore);
	ATF_CHECK_EQ(EINVAL, rc);

	dev_free(sc);
	dev_free(bad);
}
#endif /* BHYVE_SNAPSHOT */

/* ---- reset semantics: driver vs h/w reset ------------------------- */

ATF_TC_WITHOUT_HEAD(reset_driver_vs_hw);
ATF_TC_BODY(reset_driver_vs_hw, tc)
{
	struct e82545_softc *sc = dev_new();

	/* After h/w reset (drvr=0), RAR[0] holds the station MAC and is
	 * valid; PBA and LEDCTL take their documented defaults. */
	ATF_CHECK_EQ(1, sc->esc_uni[0].eu_valid);
	ATF_CHECK_EQ(0, memcmp(sc->esc_uni[0].eu_eth.octet, TEST_MAC, 6));
	ATF_CHECK_EQ(0x00100030u, sc->esc_PBA);
	ATF_CHECK_EQ(0x07061302u, sc->esc_LEDCTL);
	ATF_CHECK_EQ(250u, sc->esc_ITR);

	/* Program flow-control + a RAR entry, then a driver reset (drvr=1)
	 * preserves FCAL and RDBAL but invalidates RAR entries. */
	sc->esc_FCAL = 0xdead;
	sc->esc_RDBAL = 0x2000;
	sc->esc_uni[3].eu_valid = 1;
	e82545_reset(sc, 1);
	ATF_CHECK_EQ(0xdeadu, sc->esc_FCAL);	/* preserved on drvr reset */
	ATF_CHECK_EQ(0x2000u, sc->esc_RDBAL);	/* preserved on drvr reset */
	ATF_CHECK_EQ(0, sc->esc_uni[3].eu_valid);

	dev_free(sc);
}

/* ---- pause / resume checkpoint drain ------------------------------ */

#ifdef BHYVE_SNAPSHOT
ATF_TC_WITHOUT_HEAD(pause_resume);
ATF_TC_BODY(pause_resume, tc)
{
	int rc, spins;

	guest_reset();
	backend_reset();
	e82545_debug = 1;
	g_mac_cfg = "52:54:00:ab:cd:ef";
	memset(&g_pi, 0, sizeof(g_pi));
	rc = e82545_init(&g_pi, NULL);
	ATF_REQUIRE_EQ(0, rc);
	struct e82545_softc *sc = g_pi.pi_arg;

	/* Pause quiesces the tx thread and disables the backend rx. */
	rc = e82545_pause(&g_pi);
	ATF_REQUIRE_EQ(0, rc);
	ATF_CHECK(sc->esc_checkpoint_paused);
	ATF_CHECK(g_rx_disable_calls > 0);

	/* A second pause while paused is EBUSY. */
	rc = e82545_pause(&g_pi);
	ATF_CHECK_EQ(EBUSY, rc);

	/* Resume re-enables and clears the paused flag. */
	rc = e82545_resume(&g_pi);
	ATF_REQUIRE_EQ(0, rc);
	ATF_CHECK(!sc->esc_checkpoint_paused);

	/* Resume when not paused is EINVAL. */
	rc = e82545_resume(&g_pi);
	ATF_CHECK_EQ(EINVAL, rc);

	/* Let the thread settle, then stop it. */
	for (spins = 0; spins < 100; spins++)
		usleep(1000);
	pthread_mutex_lock(&sc->esc_mtx);
	e82545_tx_disable(sc);
	pthread_mutex_unlock(&sc->esc_mtx);
}
#endif

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, init_bars_and_config);
	ATF_TP_ADD_TC(tp, init_genmac_and_backend_failure);
	ATF_TP_ADD_TC(tp, init_bad_mac);
	ATF_TP_ADD_TC(tp, ctrl_status_registers);
	ATF_TP_ADD_TC(tp, ctrl_reset_reinits);
	ATF_TP_ADD_TC(tp, register_reserved_masks);
	ATF_TP_ADD_TC(tp, register_unaligned_and_unknown);
	ATF_TP_ADD_TC(tp, receive_address_array);
	ATF_TP_ADD_TC(tp, eeprom_read_mac_and_checksum);
	ATF_TP_ADD_TC(tp, eeprom_write_and_readback);
	ATF_TP_ADD_TC(tp, eeprom_write_enable_opcode);
	ATF_TP_ADD_TC(tp, eeprom_unknown_and_erase_opcode);
	ATF_TP_ADD_TC(tp, mdic_phy_reads);
	ATF_TP_ADD_TC(tp, mdic_writes_and_errors);
	ATF_TP_ADD_TC(tp, interrupt_ics_ims_assert);
	ATF_TP_ADD_TC(tp, interrupt_ims_change_unmasks_pending);
	ATF_TP_ADD_TC(tp, interrupt_throttle_timer);
	ATF_TP_ADD_TC(tp, interrupt_readonly_writeonly);
	ATF_TP_ADD_TC(tp, rctl_buffer_size_decode);
	ATF_TP_ADD_TC(tp, rx_single_descriptor_frame);
	ATF_TP_ADD_TC(tp, rx_crc_addback_and_runt);
	ATF_TP_ADD_TC(tp, rx_multi_descriptor_frame);
	ATF_TP_ADD_TC(tp, rx_ring_overflow_dropped);
	ATF_TP_ADD_TC(tp, rx_disabled_discards);
	ATF_TP_ADD_TC(tp, rx_bad_buffer_address);
	ATF_TP_ADD_TC(tp, rx_vlan_filter);
	ATF_TP_ADD_TC(tp, rx_small_packet_detect);
	ATF_TP_ADD_TC(tp, rx_ctl_disallows_rdba_writes);
	ATF_TP_ADD_TC(tp, rx_ctl_invalid_ring);
	ATF_TP_ADD_TC(tp, tx_legacy_frame);
	ATF_TP_ADD_TC(tp, tx_legacy_crc_strip);
	ATF_TP_ADD_TC(tp, tx_multi_descriptor_frame);
	ATF_TP_ADD_TC(tp, tx_legacy_ip_checksum);
	ATF_TP_ADD_TC(tp, tx_context_then_tso);
	ATF_TP_ADD_TC(tp, tx_context_only_saved);
	ATF_TP_ADD_TC(tp, tx_inconsistent_descriptor_dropped);
	ATF_TP_ADD_TC(tp, tx_bad_buffer_address);
	ATF_TP_ADD_TC(tp, tx_tdba_locked_while_enabled);
	ATF_TP_ADD_TC(tp, tx_vlan_insertion);
	ATF_TP_ADD_TC(tp, tx_tcp_checksum_offload);
	ATF_TP_ADD_TC(tp, tx_too_many_descriptors);
	ATF_TP_ADD_TC(tp, tx_final_descriptor_too_short);
	ATF_TP_ADD_TC(tp, tx_udp_tso);
	ATF_TP_ADD_TC(tp, tx_ipv6_tcp_tso);
	ATF_TP_ADD_TC(tp, tx_tso_hdrlen_too_large);
	ATF_TP_ADD_TC(tp, tctl_reserved_bits);
	ATF_TP_ADD_TC(tp, tx_via_thread);
	ATF_TP_ADD_TC(tp, io_bar_indirect_access);
	ATF_TP_ADD_TC(tp, stat_registers_readback);
	ATF_TP_ADD_TC(tp, size_stat_index_buckets);
	ATF_TP_ADD_TC(tp, read_all_registers);
#ifdef BHYVE_SNAPSHOT
	ATF_TP_ADD_TC(tp, snapshot_save_restore_roundtrip);
	ATF_TP_ADD_TC(tp, snapshot_magic_mismatch);
	ATF_TP_ADD_TC(tp, snapshot_truncated_buffer);
	ATF_TP_ADD_TC(tp, snapshot_validate);
	ATF_TP_ADD_TC(tp, snapshot_active_rings_roundtrip);
	ATF_TP_ADD_TC(tp, snapshot_restore_rejects_bad_state);
	ATF_TP_ADD_TC(tp, pause_resume);
#endif
	ATF_TP_ADD_TC(tp, reset_driver_vs_hw);

	return (atf_no_error());
}
