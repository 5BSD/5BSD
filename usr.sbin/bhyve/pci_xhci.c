/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2014 Leon Dang <ldang@nahannisys.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
   XHCI options:
    -s <n>,xhci,{devices}

   devices:
     tablet             USB tablet mouse
 */

#include <sys/param.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#include <dev/usb/usbdi.h>
#include <dev/usb/usb.h>
#include <dev/usb/usb_freebsd.h>
#include <xhcireg.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "pci_emul.h"
#include "pci_xhci.h"
#ifdef BHYVE_SNAPSHOT
#include "pci_xhci_model.h"
#include "snapshot.h"
#endif
#include "usb_emul.h"


static int xhci_debug = 0;
#define	DPRINTF(params) if (xhci_debug) PRINTLN params
#define	WPRINTF(params) PRINTLN params


#define	XHCI_NAME		"xhci"
#define	XHCI_MAX_DEVS		8	/* 4 USB3 + 4 USB2 devs */

#define	XHCI_MAX_SLOTS		64	/* min allowed by Windows drivers */

#define	XHCI_ERST_MAX		0	/* max 2^entries event ring seg tbl */

#define	XHCI_CAPLEN		(4*8)	/* offset of op register space */
#define	XHCI_HCCPRAMS2		0x1C	/* offset of HCCPARAMS2 register */
#define	XHCI_PORTREGS_START	0x400
#define	XHCI_DOORBELL_MAX	256

#define	XHCI_STREAMS_MAX	1	/* 4-15 in XHCI spec */

/*
 * A command ring does not carry a size.  Stop a corrupt ring from keeping the
 * emulation thread in an unbounded Link TRB cycle.  This is a liveness guard,
 * not an architectural queue-size limit.
 */
#define	XHCI_COMMAND_TRB_BUDGET	65536
#define	XHCI_EVENT_RING_SEGMENT_MAX	65536

#ifdef BHYVE_SNAPSHOT
#define	XHCI_SNAPSHOT_MAGIC	0x31434858U	/* "XHC1" on disk */
#define	XHCI_SNAPSHOT_VERSION	1U
#endif

/* caplength and hci-version registers */
#define	XHCI_SET_CAPLEN(x)		((x) & 0xFF)
#define	XHCI_SET_HCIVERSION(x)		(((x) & 0xFFFF) << 16)
#define	XHCI_GET_HCIVERSION(x)		(((x) >> 16) & 0xFFFF)

/* hcsparams1 register */
#define	XHCI_SET_HCSP1_MAXSLOTS(x)	((x) & 0xFF)
#define	XHCI_SET_HCSP1_MAXINTR(x)	(((x) & 0x7FF) << 8)
#define	XHCI_SET_HCSP1_MAXPORTS(x)	((uint32_t)((x) & 0xFF) << 24)

/* hcsparams2 register */
#define	XHCI_SET_HCSP2_IST(x)		((x) & 0x0F)
#define	XHCI_SET_HCSP2_ERSTMAX(x)	(((x) & 0x0F) << 4)
#define	XHCI_SET_HCSP2_MAXSCRATCH_HI(x)	(((x) & 0x1F) << 21)
#define	XHCI_SET_HCSP2_MAXSCRATCH_LO(x)	(((x) & 0x1F) << 27)

/* hcsparams3 register */
#define	XHCI_SET_HCSP3_U1EXITLATENCY(x)	((x) & 0xFF)
#define	XHCI_SET_HCSP3_U2EXITLATENCY(x)	(((x) & 0xFFFF) << 16)

/* hccparams1 register */
#define	XHCI_SET_HCCP1_AC64(x)		((x) & 0x01)
#define	XHCI_SET_HCCP1_BNC(x)		(((x) & 0x01) << 1)
#define	XHCI_SET_HCCP1_CSZ(x)		(((x) & 0x01) << 2)
#define	XHCI_SET_HCCP1_PPC(x)		(((x) & 0x01) << 3)
#define	XHCI_SET_HCCP1_PIND(x)		(((x) & 0x01) << 4)
#define	XHCI_SET_HCCP1_LHRC(x)		(((x) & 0x01) << 5)
#define	XHCI_SET_HCCP1_LTC(x)		(((x) & 0x01) << 6)
#define	XHCI_SET_HCCP1_NSS(x)		(((x) & 0x01) << 7)
#define	XHCI_SET_HCCP1_PAE(x)		(((x) & 0x01) << 8)
#define	XHCI_SET_HCCP1_SPC(x)		(((x) & 0x01) << 9)
#define	XHCI_SET_HCCP1_SEC(x)		(((x) & 0x01) << 10)
#define	XHCI_SET_HCCP1_CFC(x)		(((x) & 0x01) << 11)
#define	XHCI_SET_HCCP1_MAXPSA(x)	(((x) & 0x0F) << 12)
#define	XHCI_SET_HCCP1_XECP(x)		(((x) & 0xFFFF) << 16)

/* hccparams2 register */
#define	XHCI_SET_HCCP2_U3C(x)		((x) & 0x01)
#define	XHCI_SET_HCCP2_CMC(x)		(((x) & 0x01) << 1)
#define	XHCI_SET_HCCP2_FSC(x)		(((x) & 0x01) << 2)
#define	XHCI_SET_HCCP2_CTC(x)		(((x) & 0x01) << 3)
#define	XHCI_SET_HCCP2_LEC(x)		(((x) & 0x01) << 4)
#define	XHCI_SET_HCCP2_CIC(x)		(((x) & 0x01) << 5)

/* other registers */
#define	XHCI_SET_DOORBELL(x)		((x) & ~0x03)
#define	XHCI_SET_RTSOFFSET(x)		((x) & ~0x0F)

/* register masks */
#define	XHCI_PS_PLS_MASK		(0xF << 5)	/* port link state */
#define	XHCI_PS_SPEED_MASK		(0xF << 10)	/* port speed */
#define	XHCI_PS_PIC_MASK		(0x3 << 14)	/* port indicator */

/* port register set */
#define	XHCI_PORTREGS_BASE		0x400		/* base offset */
#define	XHCI_PORTREGS_PORT0		0x3F0
#define	XHCI_PORTREGS_SETSZ		0x10		/* size of a set */

#define	MASK_64_HI(x)			((x) & ~0xFFFFFFFFULL)
#define	MASK_64_LO(x)			((x) & 0xFFFFFFFFULL)

#define	FIELD_REPLACE(a,b,m,s)		(((a) & ~((m) << (s))) | \
					(((b) & (m)) << (s)))
#define	FIELD_COPY(a,b,m,s)		(((a) & ~((m) << (s))) | \
					(((b) & ((m) << (s)))))

#define	SNAP_DEV_NAME_LEN 128

struct pci_xhci_trb_ring {
	uint64_t ringaddr;		/* current dequeue guest address */
	uint32_t ccs;			/* consumer cycle state */
};

/* device endpoint transfer/stream rings */
struct pci_xhci_dev_ep {
	union {
		struct xhci_trb		*_epu_tr;
		struct xhci_stream_ctx	*_epu_sctx;
	} _ep_trbsctx;
#define	ep_tr		_ep_trbsctx._epu_tr
#define	ep_sctx		_ep_trbsctx._epu_sctx

	/*
	 * Caches the value of MaxPStreams from the endpoint context
	 * when an endpoint is initialized and is used to validate the
	 * use of ep_ringaddr vs ep_sctx_trbs[] as well as the length
	 * of ep_sctx_trbs[].
	 */
	uint32_t ep_MaxPStreams;
	uint32_t ep_NumStreams;
	union {
		struct pci_xhci_trb_ring _epu_trb;
		struct pci_xhci_trb_ring *_epu_sctx_trbs;
	} _ep_trb_rings;
#define	ep_ringaddr	_ep_trb_rings._epu_trb.ringaddr
#define	ep_ccs		_ep_trb_rings._epu_trb.ccs
#define	ep_sctx_trbs	_ep_trb_rings._epu_sctx_trbs

	struct usb_data_xfer *ep_xfer;	/* transfer chain */
};

/* device context base address array: maps slot->device context */
struct xhci_dcbaa {
	uint64_t dcba[USB_MAX_DEVICES+1]; /* xhci_dev_ctx ptrs */
};

/* port status registers */
struct pci_xhci_portregs {
	uint32_t	portsc;		/* port status and control */
	uint32_t	portpmsc;	/* port pwr mgmt status & control */
	uint32_t	portli;		/* port link info */
	uint32_t	porthlpmc;	/* port hardware LPM control */
} __packed;
#define	XHCI_PS_SPEED_SET(x)	(((x) & 0xF) << 10)

/* xHC operational registers */
struct pci_xhci_opregs {
	uint32_t	usbcmd;		/* usb command */
	uint32_t	usbsts;		/* usb status */
	uint32_t	pgsz;		/* page size */
	uint32_t	dnctrl;		/* device notification control */
	uint64_t	crcr;		/* command ring control */
	uint64_t	dcbaap;		/* device ctx base addr array ptr */
	uint32_t	config;		/* configure */

	/* guest mapped addresses: */
	struct xhci_trb	*cr_p;		/* crcr dequeue */
	struct xhci_dcbaa *dcbaa_p;	/* dev ctx array ptr */
};

/* xHC runtime registers */
struct pci_xhci_rtsregs {
	uint32_t	mfindex;	/* microframe index */
	struct {			/* interrupter register set */
		uint32_t	iman;	/* interrupter management */
		uint32_t	imod;	/* interrupter moderation */
		uint32_t	erstsz;	/* event ring segment table size */
		uint32_t	rsvd;
		uint64_t	erstba;	/* event ring seg-tbl base addr */
		uint64_t	erdp;	/* event ring dequeue ptr */
	} intrreg __packed;

	/* guest mapped addresses */
	struct xhci_event_ring_seg *erstba_p;
	struct xhci_trb *erst_p;	/* event ring segment tbl */
	int		er_deq_seg;	/* event ring dequeue segment */
	int		er_enq_idx;	/* event ring enqueue index - xHCI */
	int		er_enq_seg;	/* event ring enqueue segment */
	uint32_t	er_events_cnt;	/* number of events in ER */
	uint32_t	event_pcs;	/* producer cycle state flag */
};


struct pci_xhci_softc;


/*
 * USB device emulation container.
 * This is referenced from usb_hci->hci_sc; 1 pci_xhci_dev_emu for each
 * emulated device instance.
 */
struct pci_xhci_dev_emu {
	struct pci_xhci_softc	*xsc;

	/* XHCI contexts */
	struct xhci_dev_ctx	*dev_ctx;
	struct pci_xhci_dev_ep	eps[XHCI_MAX_ENDPOINTS];
	int			dev_slotstate;

	struct usb_devemu	*dev_ue;	/* USB emulated dev */
	void			*dev_sc;	/* device's softc */
	bool			dev_initialized;

	struct usb_hci		hci;
};

struct pci_xhci_softc {
	struct pci_devinst *xsc_pi;

	pthread_mutex_t	mtx;

	uint32_t	caplength;	/* caplen & hciversion */
	uint32_t	hcsparams1;	/* structural parameters 1 */
	uint32_t	hcsparams2;	/* structural parameters 2 */
	uint32_t	hcsparams3;	/* structural parameters 3 */
	uint32_t	hccparams1;	/* capability parameters 1 */
	uint32_t	dboff;		/* doorbell offset */
	uint32_t	rtsoff;		/* runtime register space offset */
	uint32_t	hccparams2;	/* capability parameters 2 */

	uint32_t	regsend;	/* end of configuration registers */

	struct pci_xhci_opregs  opregs;
	struct pci_xhci_rtsregs rtsregs;

	struct pci_xhci_portregs *portregs;
	struct pci_xhci_dev_emu  **devices; /* XHCI[port] = device */
	struct pci_xhci_dev_emu  **slots;   /* slots assigned from 1 */

	int		usb2_port_start;
	int		usb3_port_start;

#ifdef BHYVE_SNAPSHOT
	/*
	 * Checkpoint ownership fence.  Set under sc->mtx between pe_pause and
	 * pe_resume; asynchronous backend completions observe it under the
	 * same mutex and must not reach guest memory while it is set.
	 */
	bool		snapshot_paused;
#endif
};


/* port and slot numbering start from 1 */
#define	XHCI_PORTREG_PTR(x,n)	&((x)->portregs[(n) - 1])
#define	XHCI_DEVINST_PTR(x,n)	((x)->devices[(n) - 1])
#define	XHCI_SLOTDEV_PTR(x,n)	((x)->slots[(n) - 1])

#define	XHCI_HALTED(sc)		((sc)->opregs.usbsts & XHCI_STS_HCH)

static int xhci_in_use;

/* map USB errors to XHCI */
static const int xhci_usb_errors[USB_ERR_MAX] = {
	[USB_ERR_NORMAL_COMPLETION]	= XHCI_TRB_ERROR_SUCCESS,
	[USB_ERR_PENDING_REQUESTS]	= XHCI_TRB_ERROR_RESOURCE,
	[USB_ERR_NOT_STARTED]		= XHCI_TRB_ERROR_ENDP_NOT_ON,
	[USB_ERR_INVAL]			= XHCI_TRB_ERROR_INVALID,
	[USB_ERR_NOMEM]			= XHCI_TRB_ERROR_RESOURCE,
	[USB_ERR_CANCELLED]		= XHCI_TRB_ERROR_STOPPED,
	[USB_ERR_BAD_ADDRESS]		= XHCI_TRB_ERROR_PARAMETER,
	[USB_ERR_BAD_BUFSIZE]		= XHCI_TRB_ERROR_PARAMETER,
	[USB_ERR_BAD_FLAG]		= XHCI_TRB_ERROR_PARAMETER,
	[USB_ERR_NO_CALLBACK]		= XHCI_TRB_ERROR_STALL,
	[USB_ERR_IN_USE]		= XHCI_TRB_ERROR_RESOURCE,
	[USB_ERR_NO_ADDR]		= XHCI_TRB_ERROR_RESOURCE,
	[USB_ERR_NO_PIPE]               = XHCI_TRB_ERROR_RESOURCE,
	[USB_ERR_ZERO_NFRAMES]          = XHCI_TRB_ERROR_UNDEFINED,
	[USB_ERR_ZERO_MAXP]             = XHCI_TRB_ERROR_UNDEFINED,
	[USB_ERR_SET_ADDR_FAILED]       = XHCI_TRB_ERROR_RESOURCE,
	[USB_ERR_NO_POWER]              = XHCI_TRB_ERROR_ENDP_NOT_ON,
	[USB_ERR_TOO_DEEP]              = XHCI_TRB_ERROR_RESOURCE,
	[USB_ERR_IOERROR]               = XHCI_TRB_ERROR_TRB,
	[USB_ERR_NOT_CONFIGURED]        = XHCI_TRB_ERROR_ENDP_NOT_ON,
	[USB_ERR_TIMEOUT]               = XHCI_TRB_ERROR_CMD_ABORTED,
	[USB_ERR_SHORT_XFER]            = XHCI_TRB_ERROR_SHORT_PKT,
	[USB_ERR_STALLED]               = XHCI_TRB_ERROR_STALL,
	[USB_ERR_INTERRUPTED]           = XHCI_TRB_ERROR_CMD_ABORTED,
	[USB_ERR_DMA_LOAD_FAILED]       = XHCI_TRB_ERROR_DATA_BUF,
	[USB_ERR_BAD_CONTEXT]           = XHCI_TRB_ERROR_TRB,
	[USB_ERR_NO_ROOT_HUB]           = XHCI_TRB_ERROR_UNDEFINED,
	[USB_ERR_NO_INTR_THREAD]        = XHCI_TRB_ERROR_UNDEFINED,
	[USB_ERR_NOT_LOCKED]            = XHCI_TRB_ERROR_UNDEFINED,
};
#define	USB_TO_XHCI_ERR(e)	((e) < USB_ERR_MAX ? xhci_usb_errors[(e)] : \
				XHCI_TRB_ERROR_INVALID)

static int pci_xhci_insert_event(struct pci_xhci_softc *sc,
    struct xhci_trb *evtrb, int do_intr);
static void pci_xhci_dump_trb(struct xhci_trb *trb);
static void pci_xhci_assert_interrupt(struct pci_xhci_softc *sc);
static void pci_xhci_reset_slot(struct pci_xhci_softc *sc, int slot);
static void pci_xhci_reset_port(struct pci_xhci_softc *sc, int portn, int warm);
static int pci_xhci_update_ep_ring(struct pci_xhci_softc *sc,
    struct pci_xhci_dev_emu *dev, struct pci_xhci_dev_ep *devep,
    struct xhci_endp_ctx *ep_ctx, uint32_t streamid,
    uint64_t ringaddr, int ccs);
static int pci_xhci_validate_slot(uint32_t slot);

static void *
pci_xhci_map_dir(struct pci_xhci_softc *sc, uint64_t gpa, size_t len,
    enum pci_dma_direction direction)
{

	if (len == 0 || gpa > UINT64_MAX - len)
		return (NULL);
	return (pci_emul_map_dma(sc->xsc_pi, gpa, len, direction));
}

static void *
pci_xhci_map(struct pci_xhci_softc *sc, uint64_t gpa, size_t len)
{

	return (pci_xhci_map_dir(sc, gpa, len, PCI_DMA_DEVICE_READ));
}

static void *
pci_xhci_map_write(struct pci_xhci_softc *sc, uint64_t gpa, size_t len)
{

	return (pci_xhci_map_dir(sc, gpa, len, PCI_DMA_DEVICE_WRITE));
}

static void *
pci_xhci_map_bidir(struct pci_xhci_softc *sc, uint64_t gpa, size_t len)
{

	return (pci_xhci_map_dir(sc, gpa, len, PCI_DMA_BIDIRECTIONAL));
}

static bool
pci_xhci_trb_device_writes(uint32_t epid, uint32_t trbflags)
{

	if (XHCI_TRB_3_TYPE_GET(trbflags) == XHCI_TRB_TYPE_DATA_STAGE)
		return ((trbflags & XHCI_TRB_3_DIR_IN) != 0);
	/* Endpoint-context indices are odd for IN and even for OUT. */
	return (epid != 1 && (epid & 1U) != 0);
}

static void
pci_xhci_host_error(struct pci_xhci_softc *sc)
{

	sc->opregs.usbcmd &= ~XHCI_CMD_RS;
	sc->opregs.usbsts |= XHCI_STS_HCH | XHCI_STS_HSE;
	pci_xhci_assert_interrupt(sc);
}

static void
pci_xhci_set_evtrb(struct xhci_trb *evtrb, uint64_t port, uint32_t errcode,
    uint32_t evtype)
{
	evtrb->qwTrb0 = port << 24;
	evtrb->dwTrb2 = XHCI_TRB_2_ERROR_SET(errcode);
	evtrb->dwTrb3 = XHCI_TRB_3_TYPE_SET(evtype);
}


/* controller reset */
static void
pci_xhci_reset(struct pci_xhci_softc *sc)
{
	int i;

	sc->opregs.usbcmd = 0;
	sc->opregs.usbsts = XHCI_STS_HCH;
	sc->opregs.pgsz = XHCI_PAGESIZE_4K;
	sc->opregs.dnctrl = 0;
	sc->opregs.crcr = 0;
	sc->opregs.dcbaap = 0;
	sc->opregs.config = 0;
	sc->opregs.cr_p = NULL;
	sc->opregs.dcbaa_p = NULL;
	memset(&sc->rtsregs, 0, sizeof(sc->rtsregs));

	sc->rtsregs.event_pcs = 1;

	for (i = 1; i <= XHCI_MAX_SLOTS; i++) {
		pci_xhci_reset_slot(sc, i);
	}
}

static uint32_t
pci_xhci_usbcmd_write(struct pci_xhci_softc *sc, uint32_t cmd)
{
	int do_intr = 0;
	int i;

	if (cmd & XHCI_CMD_HCRST) {
		pci_xhci_reset(sc);
		return (sc->opregs.usbcmd);
	}

	if (cmd & XHCI_CMD_RS) {
		do_intr = (sc->opregs.usbcmd & XHCI_CMD_RS) == 0;

		sc->opregs.usbcmd |= XHCI_CMD_RS;
		sc->opregs.usbsts &= ~XHCI_STS_HCH;
		sc->opregs.usbsts |= XHCI_STS_PCD;

		/* Queue port change event on controller run from stop */
		if (do_intr)
			for (i = 1; i <= XHCI_MAX_DEVS; i++) {
				struct pci_xhci_dev_emu *dev;
				struct pci_xhci_portregs *port;
				struct xhci_trb		evtrb;

				if ((dev = XHCI_DEVINST_PTR(sc, i)) == NULL)
					continue;

				port = XHCI_PORTREG_PTR(sc, i);
				port->portsc |= XHCI_PS_CSC | XHCI_PS_CCS;
				port->portsc &= ~XHCI_PS_PLS_MASK;

				/*
				 * XHCI 4.19.3 USB2 RxDetect->Polling,
				 *             USB3 Polling->U0
				 */
				if (dev->hci.hci_usbver == 2)
					port->portsc |=
					    XHCI_PS_PLS_SET(UPS_PORT_LS_POLL);
				else
					port->portsc |=
					    XHCI_PS_PLS_SET(UPS_PORT_LS_U0);

				pci_xhci_set_evtrb(&evtrb, i,
				    XHCI_TRB_ERROR_SUCCESS,
				    XHCI_TRB_EVENT_PORT_STS_CHANGE);

				if (pci_xhci_insert_event(sc, &evtrb, 0) !=
				    XHCI_TRB_ERROR_SUCCESS)
					break;
			}
	} else {
		sc->opregs.usbcmd &= ~XHCI_CMD_RS;
		sc->opregs.usbsts |= XHCI_STS_HCH;
		sc->opregs.usbsts &= ~XHCI_STS_PCD;
	}

	/* start execution of schedule; stop when set to 0 */
	cmd = (cmd & ~XHCI_CMD_RS) | (sc->opregs.usbcmd & XHCI_CMD_RS);

	cmd &= ~(XHCI_CMD_CSS | XHCI_CMD_CRS);

	if (do_intr)
		pci_xhci_assert_interrupt(sc);

	return (cmd);
}

static void
pci_xhci_portregs_write(struct pci_xhci_softc *sc, uint64_t offset,
    uint64_t value)
{
	struct xhci_trb		evtrb;
	struct pci_xhci_portregs *p;
	int port;
	uint32_t oldpls, newpls;

	if (sc->portregs == NULL)
		return;

	port = (offset - XHCI_PORTREGS_PORT0) / XHCI_PORTREGS_SETSZ;
	offset = (offset - XHCI_PORTREGS_PORT0) % XHCI_PORTREGS_SETSZ;

	DPRINTF(("pci_xhci: portregs wr offset 0x%lx, port %u: 0x%lx",
	        offset, port, value));

	if (port < 1 || port > XHCI_MAX_DEVS) {
		DPRINTF(("pci_xhci: portregs_write invalid port %d",
		    port));
		return;
	}

	if (XHCI_DEVINST_PTR(sc, port) == NULL) {
		DPRINTF(("pci_xhci: portregs_write to unattached port %d",
		     port));
	}

	p = XHCI_PORTREG_PTR(sc, port);
	switch (offset) {
	case 0:
		/* port reset or warm reset */
		if (value & (XHCI_PS_PR | XHCI_PS_WPR)) {
			pci_xhci_reset_port(sc, port, value & XHCI_PS_WPR);
			break;
		}

		if ((p->portsc & XHCI_PS_PP) == 0) {
			WPRINTF(("pci_xhci: portregs_write to unpowered "
			         "port %d", port));
			break;
		}

		/* Port status and control register  */
		oldpls = XHCI_PS_PLS_GET(p->portsc);
		newpls = XHCI_PS_PLS_GET(value);

		p->portsc &= XHCI_PS_PED | XHCI_PS_PLS_MASK |
		             XHCI_PS_SPEED_MASK | XHCI_PS_PIC_MASK;

		if (XHCI_DEVINST_PTR(sc, port))
			p->portsc |= XHCI_PS_CCS;

		p->portsc |= (value &
		              ~(XHCI_PS_OCA |
		                XHCI_PS_PR  |
			        XHCI_PS_PED |
			        XHCI_PS_PLS_MASK   |	/* link state */
			        XHCI_PS_SPEED_MASK |
			        XHCI_PS_PIC_MASK   |	/* port indicator */
			        XHCI_PS_LWS | XHCI_PS_DR | XHCI_PS_WPR));

		/* clear control bits */
		p->portsc &= ~(value &
		               (XHCI_PS_CSC |
		                XHCI_PS_PEC |
		                XHCI_PS_WRC |
		                XHCI_PS_OCC |
		                XHCI_PS_PRC |
		                XHCI_PS_PLC |
		                XHCI_PS_CEC |
		                XHCI_PS_CAS));

		/* port disable request; for USB3, don't care */
		if (value & XHCI_PS_PED)
			DPRINTF(("Disable port %d request", port));

		if (!(value & XHCI_PS_LWS))
			break;

		DPRINTF(("Port new PLS: %d", newpls));
		switch (newpls) {
		case 0: /* U0 */
		case 3: /* U3 */
			if (oldpls != newpls) {
				p->portsc &= ~XHCI_PS_PLS_MASK;
				p->portsc |= XHCI_PS_PLS_SET(newpls) |
				             XHCI_PS_PLC;

				if (oldpls != 0 && newpls == 0) {
					pci_xhci_set_evtrb(&evtrb, port,
					    XHCI_TRB_ERROR_SUCCESS,
					    XHCI_TRB_EVENT_PORT_STS_CHANGE);

					pci_xhci_insert_event(sc, &evtrb, 1);
				}
			}
			break;

		default:
			DPRINTF(("Unhandled change port %d PLS %u",
			         port, newpls));
			break;
		}
		break;
	case 4:
		/* Port power management status and control register  */
		p->portpmsc = value;
		break;
	case 8:
		/* Port link information register */
		DPRINTF(("pci_xhci attempted write to PORTLI, port %d",
		        port));
		break;
	case 12:
		/*
		 * Port hardware LPM control register.
		 * For USB3, this register is reserved.
		 */
		p->porthlpmc = value;
		break;
	default:
		DPRINTF(("pci_xhci: unaligned portreg write offset %#lx",
		    offset));
		break;
	}
}

static struct xhci_dev_ctx *
pci_xhci_get_dev_ctx(struct pci_xhci_softc *sc, uint32_t slot)
{
	uint64_t devctx_addr;
	struct xhci_dev_ctx *devctx;

	if (slot == 0 || slot > XHCI_MAX_SLOTS ||
	    XHCI_SLOTDEV_PTR(sc, slot) == NULL ||
	    sc->opregs.dcbaa_p == NULL)
		return (NULL);

	devctx_addr = sc->opregs.dcbaa_p->dcba[slot];

	if (devctx_addr == 0) {
		DPRINTF(("get_dev_ctx devctx_addr == 0"));
		return (NULL);
	}

	DPRINTF(("pci_xhci: get dev ctx, slot %u devctx addr %016lx",
	        slot, devctx_addr));
	devctx = pci_xhci_map_bidir(sc, devctx_addr & ~0x3FUL,
	    sizeof(*devctx));

	return (devctx);
}

static struct xhci_trb *
pci_xhci_trb_next(struct pci_xhci_softc *sc, struct xhci_trb *curtrb,
    uint64_t *guestaddr)
{
	struct xhci_trb *next;
	uint64_t nextaddr;

	if (curtrb == NULL || guestaddr == NULL)
		return (NULL);

	if (XHCI_TRB_3_TYPE_GET(curtrb->dwTrb3) == XHCI_TRB_TYPE_LINK) {
		nextaddr = curtrb->qwTrb0 & ~0xFUL;
	} else {
		if (*guestaddr > UINT64_MAX - sizeof(struct xhci_trb))
			return (NULL);
		nextaddr = *guestaddr + sizeof(struct xhci_trb);
	}
	*guestaddr = nextaddr;
	next = pci_xhci_map(sc, nextaddr, sizeof(*next));

	return (next);
}

static void
pci_xhci_assert_interrupt(struct pci_xhci_softc *sc)
{

	sc->rtsregs.intrreg.erdp |= XHCI_ERDP_LO_BUSY;
	sc->rtsregs.intrreg.iman |= XHCI_IMAN_INTR_PEND;
	sc->opregs.usbsts |= XHCI_STS_EINT;

	/* only trigger interrupt if permitted */
	if ((sc->opregs.usbcmd & XHCI_CMD_INTE) &&
	    (sc->rtsregs.intrreg.iman & XHCI_IMAN_INTR_ENA)) {
		if (pci_msi_enabled(sc->xsc_pi))
			pci_generate_msi(sc->xsc_pi, 0);
		else
			pci_lintr_assert(sc->xsc_pi);
	}
}

static void
pci_xhci_deassert_interrupt(struct pci_xhci_softc *sc)
{

	if (!pci_msi_enabled(sc->xsc_pi))
		pci_lintr_deassert(sc->xsc_pi);
}

static int
pci_xhci_ep_num_streams(const struct xhci_endp_ctx *ep_ctx,
    uint32_t *maxpstreamsp, uint32_t *nstreamsp)
{
	uint32_t maxpstreams;

	if (ep_ctx == NULL || nstreamsp == NULL)
		return (EINVAL);
	maxpstreams = XHCI_EPCTX_0_MAXP_STREAMS_GET(ep_ctx->dwEpCtx0);
	if (maxpstreams > XHCI_STREAMS_MAX)
		return (EINVAL);
	if (maxpstreamsp != NULL)
		*maxpstreamsp = maxpstreams;
	*nstreamsp = maxpstreams == 0 ? 0 : 1U << (maxpstreams + 1);
	return (0);
}

#ifdef BHYVE_SNAPSHOT
static bool
pci_xhci_num_streams_valid(uint32_t nstreams)
{
	uint32_t maxpstreams;

	if (nstreams == 0)
		return (true);
	for (maxpstreams = 1; maxpstreams <= XHCI_STREAMS_MAX;
	    maxpstreams++) {
		if (nstreams == (1U << (maxpstreams + 1)))
			return (true);
	}
	return (false);
}
#endif

static int
pci_xhci_prepare_ep(struct pci_xhci_softc *sc, struct xhci_endp_ctx *ep_ctx,
    struct pci_xhci_dev_ep *devep)
{
	struct xhci_stream_ctx *sctx;
	struct pci_xhci_trb_ring *sctx_trbs;
	struct usb_data_xfer *xfer;
	uint32_t i, maxpstreams, nstreams;
	int error;

	if (sc == NULL || ep_ctx == NULL || devep == NULL)
		return (EINVAL);
	memset(devep, 0, sizeof(*devep));
	error = pci_xhci_ep_num_streams(ep_ctx, &maxpstreams, &nstreams);
	if (error != 0)
		return (error);

	sctx = NULL;
	sctx_trbs = NULL;
	if (maxpstreams > 0) {
		DPRINTF(("prepare endpoint with %u streams", nstreams));
		sctx = pci_xhci_map_bidir(sc, ep_ctx->qwEpCtx2 &
		    XHCI_EPCTX_2_TR_DQ_PTR_MASK, nstreams * sizeof(*sctx));
		if (sctx == NULL)
			return (EFAULT);
		sctx_trbs = calloc(nstreams, sizeof(*sctx_trbs));
		if (sctx_trbs == NULL)
			return (ENOMEM);
		for (i = 0; i < nstreams; i++) {
			sctx_trbs[i].ringaddr = sctx[i].qwSctx0 &
			    XHCI_SCTX_0_TR_DQ_PTR_MASK;
			sctx_trbs[i].ccs = XHCI_SCTX_0_DCS_GET(sctx[i].qwSctx0);
		}
	} else {
		DPRINTF(("prepare endpoint with no streams"));
		if (pci_xhci_map(sc, ep_ctx->qwEpCtx2 &
		    XHCI_EPCTX_2_TR_DQ_PTR_MASK, sizeof(struct xhci_trb)) == NULL)
			return (EFAULT);
	}

	xfer = calloc(1, sizeof(*xfer));
	if (xfer == NULL) {
		free(sctx_trbs);
		return (ENOMEM);
	}
	error = pthread_mutex_init(&xfer->mtx, NULL);
	if (error != 0) {
		free(xfer);
		free(sctx_trbs);
		return (error);
	}

	devep->ep_MaxPStreams = maxpstreams;
	devep->ep_NumStreams = nstreams;
	devep->ep_xfer = xfer;
	if (nstreams > 0) {
		devep->ep_sctx = sctx;
		devep->ep_sctx_trbs = sctx_trbs;
	} else {
		devep->ep_ringaddr = ep_ctx->qwEpCtx2 &
		    XHCI_EPCTX_2_TR_DQ_PTR_MASK;
		devep->ep_ccs = XHCI_EPCTX_2_DCS_GET(ep_ctx->qwEpCtx2);
		devep->ep_tr = pci_xhci_map_bidir(sc, devep->ep_ringaddr,
		    sizeof(*devep->ep_tr));
		DPRINTF(("prepare endpoint TR DCS %x", devep->ep_ccs));
	}
	return (0);
}

static void
pci_xhci_free_ep(struct pci_xhci_dev_ep *devep)
{

	if (devep->ep_NumStreams > 0)
		free(devep->ep_sctx_trbs);
	if (devep->ep_xfer != NULL) {
		pthread_mutex_destroy(&devep->ep_xfer->mtx);
		free(devep->ep_xfer->ureq);
		free(devep->ep_xfer);
	}
	memset(devep, 0, sizeof(*devep));
}

static void
pci_xhci_disable_ep(struct pci_xhci_softc *sc,
    struct pci_xhci_dev_emu *dev, int epid)
{
	struct xhci_dev_ctx *dev_ctx;
	struct xhci_endp_ctx *ep_ctx;

	DPRINTF(("pci_xhci disable_ep %d", epid));

	dev_ctx = dev->dev_ctx;
	if (dev_ctx != NULL) {
		ep_ctx = &dev_ctx->ctx_ep[epid];
		ep_ctx->dwEpCtx0 = (ep_ctx->dwEpCtx0 & ~0x7) |
		    XHCI_ST_EPCTX_DISABLED;
		pci_emul_mark_dma_dirty_mapping(sc->xsc_pi, ep_ctx,
		    sizeof(*ep_ctx));
	}
	pci_xhci_free_ep(&dev->eps[epid]);
}


/* reset device at slot and data structures related to it */
static void
pci_xhci_reset_slot(struct pci_xhci_softc *sc, int slot)
{
	struct pci_xhci_dev_emu *dev;
	int i;

	dev = XHCI_SLOTDEV_PTR(sc, slot);

	if (!dev) {
		DPRINTF(("xhci reset unassigned slot (%d)?", slot));
	} else {
		for (i = 1; i < XHCI_MAX_ENDPOINTS; i++)
			pci_xhci_free_ep(&dev->eps[i]);
		dev->dev_ctx = NULL;
		dev->hci.hci_address = 0;
		dev->dev_slotstate = XHCI_ST_DISABLED;
	}
}

static int
pci_xhci_insert_event(struct pci_xhci_softc *sc, struct xhci_trb *evtrb,
    int do_intr)
{
	struct pci_xhci_rtsregs *rts;
	uint64_t	erdp, event_base, event_bytes;
	uint32_t	event_count;
	int		erdp_idx;
	int		err;
	struct xhci_trb *evtrbptr;

	err = XHCI_TRB_ERROR_SUCCESS;

	rts = &sc->rtsregs;
	event_count = rts->erstba_p != NULL ?
	    rts->erstba_p->dwEvrsTableSize : 0;
	if (rts->erstba_p == NULL || rts->erst_p == NULL ||
	    rts->intrreg.erstsz != 1 || event_count == 0 ||
	    event_count > XHCI_EVENT_RING_SEGMENT_MAX ||
	    rts->er_enq_idx < 0 || (uint32_t)rts->er_enq_idx >= event_count) {
		pci_xhci_host_error(sc);
		return (XHCI_TRB_ERROR_EV_RING_FULL);
	}
	event_base = rts->erstba_p->qwEvrsTablePtr;
	event_bytes = (uint64_t)event_count * sizeof(struct xhci_trb);
	if (event_base > UINT64_MAX - event_bytes) {
		pci_xhci_host_error(sc);
		return (XHCI_TRB_ERROR_EV_RING_FULL);
	}

	erdp = rts->intrreg.erdp & ~0xF;
	if (erdp < event_base || erdp >= event_base + event_bytes ||
	    (erdp - event_base) % sizeof(struct xhci_trb) != 0)
		erdp_idx = -1;
	else
		erdp_idx = (erdp - event_base) / sizeof(struct xhci_trb);

	DPRINTF(("pci_xhci: insert event 0[%lx] 2[%x] 3[%x]",
	         evtrb->qwTrb0, evtrb->dwTrb2, evtrb->dwTrb3));
	DPRINTF(("\terdp idx %d/seg %d, enq idx %d/seg %d, pcs %u",
	         erdp_idx, rts->er_deq_seg, rts->er_enq_idx,
	         rts->er_enq_seg, rts->event_pcs));
	DPRINTF(("\t(erdp=0x%lx, erst=0x%lx, tblsz=%u, do_intr %d)",
		 erdp, rts->erstba_p->qwEvrsTablePtr,
	         rts->erstba_p->dwEvrsTableSize, do_intr));

	evtrbptr = &rts->erst_p[rts->er_enq_idx];

	/* TODO: multi-segment table */
	if (rts->er_events_cnt >= event_count) {
		DPRINTF(("pci_xhci[%d] cannot insert event; ring full",
		         __LINE__));
		err = XHCI_TRB_ERROR_EV_RING_FULL;
		goto done;
	}

	if (rts->er_events_cnt == event_count - 1) {
		struct xhci_trb	errev;

		if ((evtrbptr->dwTrb3 & 0x1) == (rts->event_pcs & 0x1)) {

			DPRINTF(("pci_xhci[%d] insert evt err: ring full",
			         __LINE__));

			errev.qwTrb0 = 0;
			errev.dwTrb2 = XHCI_TRB_2_ERROR_SET(
			                    XHCI_TRB_ERROR_EV_RING_FULL);
			errev.dwTrb3 = XHCI_TRB_3_TYPE_SET(
			                    XHCI_TRB_EVENT_HOST_CTRL) |
			               rts->event_pcs;
			rts->er_events_cnt++;
			memcpy(&rts->erst_p[rts->er_enq_idx], &errev,
			       sizeof(struct xhci_trb));
			pci_emul_mark_dma_dirty_mapping(sc->xsc_pi,
			    &rts->erst_p[rts->er_enq_idx], sizeof(struct xhci_trb));
			rts->er_enq_idx = (rts->er_enq_idx + 1) % event_count;
			err = XHCI_TRB_ERROR_EV_RING_FULL;
			do_intr = 1;

			goto done;
		}
	} else {
		rts->er_events_cnt++;
	}

	evtrb->dwTrb3 &= ~XHCI_TRB_3_CYCLE_BIT;
	evtrb->dwTrb3 |= rts->event_pcs;

	memcpy(&rts->erst_p[rts->er_enq_idx], evtrb, sizeof(struct xhci_trb));
	pci_emul_mark_dma_dirty_mapping(sc->xsc_pi,
	    &rts->erst_p[rts->er_enq_idx], sizeof(struct xhci_trb));
	rts->er_enq_idx = (rts->er_enq_idx + 1) % event_count;

	if (rts->er_enq_idx == 0)
		rts->event_pcs ^= 1;

done:
	if (do_intr)
		pci_xhci_assert_interrupt(sc);

	return (err);
}

static uint32_t
pci_xhci_cmd_enable_slot(struct pci_xhci_softc *sc, uint32_t *slot)
{
	struct pci_xhci_dev_emu *dev;
	uint32_t	cmderr;
	int		i;

	cmderr = XHCI_TRB_ERROR_NO_SLOTS;
	if (sc->portregs != NULL)
		for (i = 1; i <= XHCI_MAX_SLOTS; i++) {
			dev = XHCI_SLOTDEV_PTR(sc, i);
			if (dev && dev->dev_slotstate == XHCI_ST_DISABLED) {
				*slot = i;
				dev->dev_slotstate = XHCI_ST_ENABLED;
				cmderr = XHCI_TRB_ERROR_SUCCESS;
				dev->hci.hci_address = i;
				break;
			}
		}

	DPRINTF(("pci_xhci enable slot (error=%d) slot %u",
		cmderr != XHCI_TRB_ERROR_SUCCESS, *slot));

	return (cmderr);
}

static uint32_t
pci_xhci_cmd_disable_slot(struct pci_xhci_softc *sc, uint32_t slot)
{
	struct pci_xhci_dev_emu *dev;
	uint32_t cmderr;
	int i;

	DPRINTF(("pci_xhci disable slot %u", slot));

	if (sc->portregs == NULL) {
		cmderr = XHCI_TRB_ERROR_NO_SLOTS;
		goto done;
	}

	cmderr = pci_xhci_validate_slot(slot);
	if (cmderr != XHCI_TRB_ERROR_SUCCESS)
		goto done;

	dev = XHCI_SLOTDEV_PTR(sc, slot);
	if (dev) {
		if (dev->dev_slotstate == XHCI_ST_DISABLED) {
			cmderr = XHCI_TRB_ERROR_SLOT_NOT_ON;
		} else {
			for (i = 1; i < XHCI_MAX_ENDPOINTS; i++)
				pci_xhci_disable_ep(sc, dev, i);
			dev->dev_ctx = NULL;
			dev->hci.hci_address = 0;
			dev->dev_slotstate = XHCI_ST_DISABLED;
		}
	} else
		cmderr = XHCI_TRB_ERROR_SLOT_NOT_ON;

done:
	return (cmderr);
}

static uint32_t
pci_xhci_cmd_reset_device(struct pci_xhci_softc *sc, uint32_t slot)
{
	struct pci_xhci_dev_emu *dev;
	struct xhci_dev_ctx     *dev_ctx;
	uint32_t	cmderr;
	int		i;

	if (sc->portregs == NULL) {
		cmderr = XHCI_TRB_ERROR_NO_SLOTS;
		goto done;
	}

	DPRINTF(("pci_xhci reset device slot %u", slot));

	cmderr = pci_xhci_validate_slot(slot);
	if (cmderr != XHCI_TRB_ERROR_SUCCESS)
		goto done;

	dev = XHCI_SLOTDEV_PTR(sc, slot);
	if (!dev || dev->dev_slotstate == XHCI_ST_DISABLED) {
		cmderr = XHCI_TRB_ERROR_SLOT_NOT_ON;
	} else {
		dev_ctx = pci_xhci_get_dev_ctx(sc, slot);
		if (dev_ctx == NULL) {
			cmderr = XHCI_TRB_ERROR_PARAMETER;
			goto done;
		}
		dev->dev_slotstate = XHCI_ST_DEFAULT;
		dev->hci.hci_address = 0;

		/* slot state */
		dev_ctx->ctx_slot.dwSctx3 = FIELD_REPLACE(
		    dev_ctx->ctx_slot.dwSctx3, XHCI_ST_SLCTX_DEFAULT,
		    0x1F, 27);

		/* number of contexts */
		dev_ctx->ctx_slot.dwSctx0 = FIELD_REPLACE(
		    dev_ctx->ctx_slot.dwSctx0, 1, 0x1F, 27);

		/* Reset Device preserves endpoint 0 and disables all others. */
		for (i = 2; i < XHCI_MAX_ENDPOINTS; i++)
			pci_xhci_disable_ep(sc, dev, i);
		dev_ctx->ctx_slot.dwSctx3 &= ~0xffU;
		pci_emul_mark_dma_dirty_mapping(sc->xsc_pi, dev_ctx,
		    sizeof(*dev_ctx));
	}

done:
	return (cmderr);
}

static uint32_t
pci_xhci_cmd_address_device(struct pci_xhci_softc *sc, uint32_t slot,
    struct xhci_trb *trb)
{
	struct pci_xhci_dev_emu	*dev;
	struct pci_xhci_dev_ep prepared;
	struct xhci_input_dev_ctx *input_ctx;
	struct xhci_slot_ctx	*islot_ctx;
	struct xhci_dev_ctx	*dev_ctx;
	struct xhci_endp_ctx	*ep0_ctx;
	uint32_t		cmderr;
	bool			bsr;
	int			error;

	memset(&prepared, 0, sizeof(prepared));

	cmderr = pci_xhci_validate_slot(slot);
	if (cmderr != XHCI_TRB_ERROR_SUCCESS)
		goto done;
	input_ctx = pci_xhci_map(sc, trb->qwTrb0 & ~0xFUL,
	    sizeof(*input_ctx));
	if (input_ctx == NULL) {
		cmderr = XHCI_TRB_ERROR_PARAMETER;
		goto done;
	}
	islot_ctx = &input_ctx->ctx_slot;
	ep0_ctx = &input_ctx->ctx_ep[1];

	DPRINTF(("pci_xhci: address device, input ctl: D 0x%08x A 0x%08x,",
	        input_ctx->ctx_input.dwInCtx0, input_ctx->ctx_input.dwInCtx1));
	DPRINTF(("          slot %08x %08x %08x %08x",
	        islot_ctx->dwSctx0, islot_ctx->dwSctx1,
	        islot_ctx->dwSctx2, islot_ctx->dwSctx3));
	DPRINTF(("          ep0  %08x %08x %016lx %08x",
	        ep0_ctx->dwEpCtx0, ep0_ctx->dwEpCtx1, ep0_ctx->qwEpCtx2,
	        ep0_ctx->dwEpCtx4));

	/* when setting address: drop-ctx=0, add-ctx=slot+ep0 */
	if (input_ctx->ctx_input.dwInCtx0 != 0 ||
	    input_ctx->ctx_input.dwInCtx1 != 0x03) {
		DPRINTF(("pci_xhci: address device, input ctl invalid"));
		cmderr = XHCI_TRB_ERROR_TRB;
		goto done;
	}

	/* assign address to slot */
	dev_ctx = pci_xhci_get_dev_ctx(sc, slot);
	if (dev_ctx == NULL) {
		cmderr = XHCI_TRB_ERROR_PARAMETER;
		goto done;
	}

	DPRINTF(("pci_xhci: address device, dev ctx"));
	DPRINTF(("          slot %08x %08x %08x %08x",
	        dev_ctx->ctx_slot.dwSctx0, dev_ctx->ctx_slot.dwSctx1,
	        dev_ctx->ctx_slot.dwSctx2, dev_ctx->ctx_slot.dwSctx3));

	dev = XHCI_SLOTDEV_PTR(sc, slot);
	if (dev == NULL || dev->dev_slotstate == XHCI_ST_DISABLED) {
		cmderr = XHCI_TRB_ERROR_SLOT_NOT_ON;
		goto done;
	}
	if (dev->dev_slotstate != XHCI_ST_ENABLED &&
	    dev->dev_slotstate != XHCI_ST_DEFAULT) {
		cmderr = XHCI_TRB_ERROR_CONTEXT_STATE;
		goto done;
	}
	error = pci_xhci_prepare_ep(sc, ep0_ctx, &prepared);
	if (error != 0) {
		cmderr = error == ENOMEM ? XHCI_TRB_ERROR_RESOURCE :
		    XHCI_TRB_ERROR_PARAMETER;
		goto done;
	}

	if (dev->dev_ue->ue_reset == NULL ||
	    dev->dev_ue->ue_reset(dev->dev_sc) < 0) {
		cmderr = XHCI_TRB_ERROR_ENDP_NOT_ON;
		goto done;
	}
	bsr = (trb->dwTrb3 & XHCI_TRB_3_BSR_BIT) != 0;

	memcpy(&dev_ctx->ctx_slot, islot_ctx, sizeof(struct xhci_slot_ctx));
	dev_ctx->ctx_slot.dwSctx3 = XHCI_SCTX_3_SLOT_STATE_SET(bsr ?
	    XHCI_ST_SLCTX_DEFAULT : XHCI_ST_SLCTX_ADDRESSED);
	if (!bsr)
		dev_ctx->ctx_slot.dwSctx3 |= XHCI_SCTX_3_DEV_ADDR_SET(slot);

	memcpy(&dev_ctx->ctx_ep[1], ep0_ctx, sizeof(struct xhci_endp_ctx));
	ep0_ctx = &dev_ctx->ctx_ep[1];
	ep0_ctx->dwEpCtx0 = (ep0_ctx->dwEpCtx0 & ~0x7) |
	    XHCI_EPCTX_0_EPSTATE_SET(XHCI_ST_EPCTX_RUNNING);
	pci_xhci_free_ep(&dev->eps[1]);
	dev->eps[1] = prepared;
	memset(&prepared, 0, sizeof(prepared));
	dev->dev_ctx = dev_ctx;
	dev->hci.hci_address = bsr ? 0 : slot;
	dev->dev_slotstate = bsr ? XHCI_ST_DEFAULT : XHCI_ST_ADDRESSED;
	pci_emul_mark_dma_dirty_mapping(sc->xsc_pi, dev_ctx,
	    sizeof(*dev_ctx));

	DPRINTF(("pci_xhci: address device, output ctx"));
	DPRINTF(("          slot %08x %08x %08x %08x",
	        dev_ctx->ctx_slot.dwSctx0, dev_ctx->ctx_slot.dwSctx1,
	        dev_ctx->ctx_slot.dwSctx2, dev_ctx->ctx_slot.dwSctx3));
	DPRINTF(("          ep0  %08x %08x %016lx %08x",
	        ep0_ctx->dwEpCtx0, ep0_ctx->dwEpCtx1, ep0_ctx->qwEpCtx2,
	        ep0_ctx->dwEpCtx4));

done:
	pci_xhci_free_ep(&prepared);
	return (cmderr);
}

static uint32_t
pci_xhci_cmd_config_ep(struct pci_xhci_softc *sc, uint32_t slot,
    struct xhci_trb *trb)
{
	struct xhci_input_dev_ctx *input_ctx;
	struct pci_xhci_dev_emu	*dev;
	struct pci_xhci_dev_ep prepared[XHCI_MAX_ENDPOINTS] = { 0 };
	struct xhci_dev_ctx	*dev_ctx = NULL;
	struct xhci_endp_ctx	*ep_ctx, *iep_ctx;
	uint32_t	cmderr, prepared_mask;
	int		error, i;

	prepared_mask = 0;

	DPRINTF(("pci_xhci config_ep slot %u", slot));

	cmderr = pci_xhci_validate_slot(slot);
	if (cmderr != XHCI_TRB_ERROR_SUCCESS)
		goto done;

	dev = XHCI_SLOTDEV_PTR(sc, slot);
	if (dev == NULL || dev->dev_slotstate == XHCI_ST_DISABLED) {
		cmderr = XHCI_TRB_ERROR_SLOT_NOT_ON;
		goto done;
	}

	if ((trb->dwTrb3 & XHCI_TRB_3_DCEP_BIT) != 0) {
		DPRINTF(("pci_xhci config_ep - deconfigure ep slot %u",
		        slot));
		if (dev->dev_slotstate < XHCI_ST_ADDRESSED) {
			cmderr = XHCI_TRB_ERROR_CONTEXT_STATE;
			goto done;
		}
		dev_ctx = pci_xhci_get_dev_ctx(sc, slot);
		if (dev_ctx == NULL) {
			cmderr = XHCI_TRB_ERROR_PARAMETER;
			goto done;
		}
		if (dev->dev_ue->ue_stop != NULL &&
		    dev->dev_ue->ue_stop(dev->dev_sc) < 0) {
			cmderr = XHCI_TRB_ERROR_ENDP_NOT_ON;
			goto done;
		}

		dev->dev_slotstate = XHCI_ST_ADDRESSED;

		/* number of contexts */
		dev_ctx->ctx_slot.dwSctx0 = FIELD_REPLACE(
		    dev_ctx->ctx_slot.dwSctx0, 1, 0x1F, 27);

		/* slot state */
		dev_ctx->ctx_slot.dwSctx3 = FIELD_REPLACE(
		    dev_ctx->ctx_slot.dwSctx3, XHCI_ST_SLCTX_ADDRESSED,
		    0x1F, 27);

		/* disable endpoints */
		for (i = 2; i < 32; i++)
			pci_xhci_disable_ep(sc, dev, i);

		cmderr = XHCI_TRB_ERROR_SUCCESS;

		goto done;
	}

	if (dev->dev_slotstate < XHCI_ST_ADDRESSED) {
		DPRINTF(("pci_xhci: config_ep slotstate x%x != addressed",
		        dev->dev_slotstate));
		cmderr = XHCI_TRB_ERROR_CONTEXT_STATE;
		goto done;
	}

	/* In addressed/configured state;
	 * for each drop endpoint ctx flag:
	 *   ep->state = DISABLED
	 * for each add endpoint ctx flag:
	 *   cp(ep-in, ep-out)
	 *   ep->state = RUNNING
	 * for each drop+add endpoint flag:
	 *   reset ep resources
	 *   cp(ep-in, ep-out)
	 *   ep->state = RUNNING
	 * if input->DisabledCtx[2-31] < 30: (at least 1 ep not disabled)
	 *   slot->state = configured
	 */

	input_ctx = pci_xhci_map(sc, trb->qwTrb0 & ~0xFUL,
	    sizeof(*input_ctx));
	if (input_ctx == NULL) {
		cmderr = XHCI_TRB_ERROR_PARAMETER;
		goto done;
	}
	dev_ctx = dev->dev_ctx;
	if (dev_ctx == NULL) {
		cmderr = XHCI_TRB_ERROR_CONTEXT_STATE;
		goto done;
	}
	DPRINTF(("pci_xhci: config_ep inputctx: D:x%08x A:x%08x 7:x%08x",
		input_ctx->ctx_input.dwInCtx0, input_ctx->ctx_input.dwInCtx1,
	        input_ctx->ctx_input.dwInCtx7));
	if ((input_ctx->ctx_input.dwInCtx0 & 0x03) != 0 ||
	    (input_ctx->ctx_input.dwInCtx1 & 0x03) != 0x01) {
		cmderr = XHCI_TRB_ERROR_TRB;
		goto done;
	}
	for (i = 2; i < XHCI_MAX_ENDPOINTS; i++) {
		if ((input_ctx->ctx_input.dwInCtx1 &
		    XHCI_INCTX_1_ADD_MASK(i)) == 0)
			continue;
		error = pci_xhci_prepare_ep(sc, &input_ctx->ctx_ep[i],
		    &prepared[i]);
		if (error != 0) {
			cmderr = error == ENOMEM ? XHCI_TRB_ERROR_RESOURCE :
			    XHCI_TRB_ERROR_PARAMETER;
			goto done;
		}
		prepared_mask |= XHCI_INCTX_1_ADD_MASK(i);
	}

	for (i = 2; i < XHCI_MAX_ENDPOINTS; i++) {
		ep_ctx = &dev_ctx->ctx_ep[i];

		if ((input_ctx->ctx_input.dwInCtx0 &
		    XHCI_INCTX_0_DROP_MASK(i)) != 0 ||
		    (prepared_mask & XHCI_INCTX_1_ADD_MASK(i)) != 0) {
			DPRINTF((" config ep - dropping ep %d", i));
			pci_xhci_disable_ep(sc, dev, i);
		}

		if ((prepared_mask & XHCI_INCTX_1_ADD_MASK(i)) != 0) {
			iep_ctx = &input_ctx->ctx_ep[i];

			DPRINTF((" enable ep[%d]  %08x %08x %016lx %08x",
			   i, iep_ctx->dwEpCtx0, iep_ctx->dwEpCtx1,
			   iep_ctx->qwEpCtx2, iep_ctx->dwEpCtx4));

			memcpy(ep_ctx, iep_ctx, sizeof(struct xhci_endp_ctx));
			dev->eps[i] = prepared[i];
			memset(&prepared[i], 0, sizeof(prepared[i]));
			prepared_mask &= ~XHCI_INCTX_1_ADD_MASK(i);

			/* ep state */
			ep_ctx->dwEpCtx0 = FIELD_REPLACE(
			    ep_ctx->dwEpCtx0, XHCI_ST_EPCTX_RUNNING, 0x7, 0);
		}
	}

	/* slot state to configured */
	dev_ctx->ctx_slot.dwSctx3 = FIELD_REPLACE(
	    dev_ctx->ctx_slot.dwSctx3, XHCI_ST_SLCTX_CONFIGURED, 0x1F, 27);
	dev_ctx->ctx_slot.dwSctx0 = FIELD_COPY(
	    dev_ctx->ctx_slot.dwSctx0, input_ctx->ctx_slot.dwSctx0, 0x1F, 27);
	dev->dev_slotstate = XHCI_ST_CONFIGURED;

	DPRINTF(("EP configured; slot %u [0]=0x%08x [1]=0x%08x [2]=0x%08x "
	         "[3]=0x%08x",
	    slot, dev_ctx->ctx_slot.dwSctx0, dev_ctx->ctx_slot.dwSctx1,
	    dev_ctx->ctx_slot.dwSctx2, dev_ctx->ctx_slot.dwSctx3));

done:
	if (cmderr == XHCI_TRB_ERROR_SUCCESS && dev_ctx != NULL)
		pci_emul_mark_dma_dirty_mapping(sc->xsc_pi, dev_ctx,
		    sizeof(*dev_ctx));
	for (i = 2; i < XHCI_MAX_ENDPOINTS; i++) {
		if ((prepared_mask & XHCI_INCTX_1_ADD_MASK(i)) != 0)
			pci_xhci_free_ep(&prepared[i]);
	}
	return (cmderr);
}

static uint32_t
pci_xhci_cmd_reset_ep(struct pci_xhci_softc *sc, uint32_t slot,
    struct xhci_trb *trb)
{
	struct pci_xhci_dev_emu	*dev;
	struct pci_xhci_dev_ep *devep;
	struct xhci_dev_ctx	*dev_ctx;
	struct xhci_endp_ctx	*ep_ctx;
	uint32_t	cmderr, epid;
	uint32_t	type;

	epid = XHCI_TRB_3_EP_GET(trb->dwTrb3);

	DPRINTF(("pci_xhci: reset ep %u: slot %u", epid, slot));

	cmderr = pci_xhci_validate_slot(slot);
	if (cmderr != XHCI_TRB_ERROR_SUCCESS)
		goto done;

	dev = XHCI_SLOTDEV_PTR(sc, slot);
	if (dev == NULL || dev->dev_slotstate == XHCI_ST_DISABLED) {
		cmderr = XHCI_TRB_ERROR_SLOT_NOT_ON;
		goto done;
	}

	type = XHCI_TRB_3_TYPE_GET(trb->dwTrb3);

	if (type == XHCI_TRB_TYPE_STOP_EP &&
	    (trb->dwTrb3 & XHCI_TRB_3_SUSP_EP_BIT) != 0) {
		/* XXX suspend endpoint for 10ms */
	}

	if (epid < 1 || epid > 31) {
		DPRINTF(("pci_xhci: reset ep: invalid epid %u", epid));
		cmderr = XHCI_TRB_ERROR_TRB;
		goto done;
	}

	dev_ctx = dev->dev_ctx;
	if (dev_ctx == NULL) {
		cmderr = XHCI_TRB_ERROR_CONTEXT_STATE;
		goto done;
	}

	ep_ctx = &dev_ctx->ctx_ep[epid];
	devep = &dev->eps[epid];

	if (type == XHCI_TRB_TYPE_RESET_EP &&
	    (dev->dev_ue->ue_reset == NULL ||
	    dev->dev_ue->ue_reset(dev->dev_sc) < 0)) {
		cmderr = XHCI_TRB_ERROR_ENDP_NOT_ON;
		goto done;
	}
	if (devep->ep_xfer != NULL) {
		USB_DATA_XFER_LOCK(devep->ep_xfer);
		USB_DATA_XFER_RESET(devep->ep_xfer);
		USB_DATA_XFER_UNLOCK(devep->ep_xfer);
	}

	ep_ctx->dwEpCtx0 = (ep_ctx->dwEpCtx0 & ~0x7) | XHCI_ST_EPCTX_STOPPED;

	if (devep->ep_NumStreams == 0)
		ep_ctx->qwEpCtx2 = devep->ep_ringaddr | devep->ep_ccs;
	pci_emul_mark_dma_dirty_mapping(sc->xsc_pi, ep_ctx, sizeof(*ep_ctx));

	DPRINTF(("pci_xhci: reset ep[%u] %08x %08x %016lx %08x",
	        epid, ep_ctx->dwEpCtx0, ep_ctx->dwEpCtx1, ep_ctx->qwEpCtx2,
	        ep_ctx->dwEpCtx4));

done:
	return (cmderr);
}


static uint32_t
pci_xhci_find_stream(struct pci_xhci_softc *sc __unused,
    struct xhci_endp_ctx *ep,
    struct pci_xhci_dev_ep *devep, uint32_t streamid)
{
	struct xhci_stream_ctx *sctx;

	if (devep->ep_NumStreams == 0 || devep->ep_sctx == NULL ||
	    devep->ep_sctx_trbs == NULL)
		return (XHCI_TRB_ERROR_TRB);

	if (devep->ep_MaxPStreams > XHCI_STREAMS_MAX)
		return (XHCI_TRB_ERROR_INVALID_SID);

	if (XHCI_EPCTX_0_LSA_GET(ep->dwEpCtx0) == 0) {
		DPRINTF(("pci_xhci: find_stream; LSA bit not set"));
		return (XHCI_TRB_ERROR_INVALID_SID);
	}

	/* only support primary stream */
	if (streamid == 0 || streamid >= devep->ep_NumStreams)
		return (XHCI_TRB_ERROR_STREAM_TYPE);

	sctx = &devep->ep_sctx[streamid];
	if (!XHCI_SCTX_0_SCT_GET(sctx->qwSctx0))
		return (XHCI_TRB_ERROR_STREAM_TYPE);

	return (XHCI_TRB_ERROR_SUCCESS);
}


static uint32_t
pci_xhci_cmd_set_tr(struct pci_xhci_softc *sc, uint32_t slot,
    struct xhci_trb *trb)
{
	struct pci_xhci_dev_emu	*dev;
	struct pci_xhci_dev_ep	*devep;
	struct xhci_dev_ctx	*dev_ctx;
	struct xhci_endp_ctx	*ep_ctx;
	struct xhci_trb		*newtr;
	uint64_t		newaddr;
	uint32_t	cmderr, epid;
	uint32_t	streamid;

	cmderr = pci_xhci_validate_slot(slot);
	if (cmderr != XHCI_TRB_ERROR_SUCCESS)
		goto done;

	dev = XHCI_SLOTDEV_PTR(sc, slot);
	if (dev == NULL || dev->dev_slotstate == XHCI_ST_DISABLED) {
		cmderr = XHCI_TRB_ERROR_SLOT_NOT_ON;
		goto done;
	}

	DPRINTF(("pci_xhci set_tr: new-tr x%016lx, SCT %u DCS %u",
	         (trb->qwTrb0 & ~0xF),  (uint32_t)((trb->qwTrb0 >> 1) & 0x7),
	         (uint32_t)(trb->qwTrb0 & 0x1)));
	DPRINTF(("                 stream-id %u, slot %u, epid %u, C %u",
		 (trb->dwTrb2 >> 16) & 0xFFFF,
	         XHCI_TRB_3_SLOT_GET(trb->dwTrb3),
	         XHCI_TRB_3_EP_GET(trb->dwTrb3), trb->dwTrb3 & 0x1));

	epid = XHCI_TRB_3_EP_GET(trb->dwTrb3);
	if (epid < 1 || epid > 31) {
		DPRINTF(("pci_xhci: set_tr_deq: invalid epid %u", epid));
		cmderr = XHCI_TRB_ERROR_TRB;
		goto done;
	}

	dev_ctx = dev->dev_ctx;
	if (dev_ctx == NULL) {
		cmderr = XHCI_TRB_ERROR_CONTEXT_STATE;
		goto done;
	}

	ep_ctx = &dev_ctx->ctx_ep[epid];
	devep = &dev->eps[epid];

	switch (XHCI_EPCTX_0_EPSTATE_GET(ep_ctx->dwEpCtx0)) {
	case XHCI_ST_EPCTX_STOPPED:
	case XHCI_ST_EPCTX_ERROR:
		break;
	default:
		DPRINTF(("pci_xhci cmd set_tr invalid state %x",
		        XHCI_EPCTX_0_EPSTATE_GET(ep_ctx->dwEpCtx0)));
		cmderr = XHCI_TRB_ERROR_CONTEXT_STATE;
		goto done;
	}

	streamid = XHCI_TRB_2_STREAM_GET(trb->dwTrb2);
	if (devep->ep_NumStreams > 0) {
		cmderr = pci_xhci_find_stream(sc, ep_ctx, devep, streamid);
		if (cmderr == XHCI_TRB_ERROR_SUCCESS) {
			newaddr = trb->qwTrb0 & ~0xFUL;
			newtr = pci_xhci_map(sc, newaddr, sizeof(*newtr));
			if (newtr == NULL) {
				cmderr = XHCI_TRB_ERROR_PARAMETER;
				goto done;
			}
			devep->ep_sctx[streamid].qwSctx0 = trb->qwTrb0;
			pci_emul_mark_dma_dirty_mapping(sc->xsc_pi,
			    &devep->ep_sctx[streamid],
			    sizeof(devep->ep_sctx[streamid]));
			devep->ep_sctx_trbs[streamid].ringaddr =
			    newaddr;
			devep->ep_sctx_trbs[streamid].ccs =
			    XHCI_EPCTX_2_DCS_GET(trb->qwTrb0);
		}
	} else {
		if (streamid != 0) {
			DPRINTF(("pci_xhci cmd set_tr streamid %x != 0",
			        streamid));
			cmderr = XHCI_TRB_ERROR_STREAM_TYPE;
			goto done;
		}
		newaddr = trb->qwTrb0 & ~0xFUL;
		newtr = pci_xhci_map(sc, newaddr, sizeof(*newtr));
		if (newtr == NULL) {
			cmderr = XHCI_TRB_ERROR_PARAMETER;
			goto done;
		}
		ep_ctx->qwEpCtx2 = newaddr | (trb->qwTrb0 & 0x1);
		devep->ep_ringaddr = newaddr;
		devep->ep_ccs = trb->qwTrb0 & 0x1;
		devep->ep_tr = newtr;

		DPRINTF(("pci_xhci set_tr first TRB:"));
		pci_xhci_dump_trb(devep->ep_tr);
	}
	ep_ctx->dwEpCtx0 = (ep_ctx->dwEpCtx0 & ~0x7) | XHCI_ST_EPCTX_STOPPED;
	pci_emul_mark_dma_dirty_mapping(sc->xsc_pi, ep_ctx, sizeof(*ep_ctx));

done:
	return (cmderr);
}

static uint32_t
pci_xhci_cmd_eval_ctx(struct pci_xhci_softc *sc, uint32_t slot,
    struct xhci_trb *trb)
{
	struct xhci_input_dev_ctx *input_ctx;
	struct pci_xhci_dev_emu *dev;
	struct xhci_slot_ctx      *islot_ctx;
	struct xhci_dev_ctx       *dev_ctx;
	struct xhci_endp_ctx      *ep0_ctx;
	uint32_t cmderr;

	cmderr = pci_xhci_validate_slot(slot);
	if (cmderr != XHCI_TRB_ERROR_SUCCESS)
		goto done;
	dev = XHCI_SLOTDEV_PTR(sc, slot);
	if (dev == NULL || dev->dev_slotstate == XHCI_ST_DISABLED) {
		cmderr = XHCI_TRB_ERROR_SLOT_NOT_ON;
		goto done;
	}
	if (dev->dev_slotstate < XHCI_ST_DEFAULT) {
		cmderr = XHCI_TRB_ERROR_CONTEXT_STATE;
		goto done;
	}
	input_ctx = pci_xhci_map(sc, trb->qwTrb0 & ~0xFUL,
	    sizeof(*input_ctx));
	if (input_ctx == NULL) {
		cmderr = XHCI_TRB_ERROR_PARAMETER;
		goto done;
	}
	islot_ctx = &input_ctx->ctx_slot;
	ep0_ctx = &input_ctx->ctx_ep[1];

	DPRINTF(("pci_xhci: eval ctx, input ctl: D 0x%08x A 0x%08x,",
	        input_ctx->ctx_input.dwInCtx0, input_ctx->ctx_input.dwInCtx1));
	DPRINTF(("          slot %08x %08x %08x %08x",
	        islot_ctx->dwSctx0, islot_ctx->dwSctx1,
	        islot_ctx->dwSctx2, islot_ctx->dwSctx3));
	DPRINTF(("          ep0  %08x %08x %016lx %08x",
	        ep0_ctx->dwEpCtx0, ep0_ctx->dwEpCtx1, ep0_ctx->qwEpCtx2,
	        ep0_ctx->dwEpCtx4));

	/* Evaluate Context may update only the slot and endpoint-0 contexts. */
	if (input_ctx->ctx_input.dwInCtx0 != 0 ||
	    (input_ctx->ctx_input.dwInCtx1 & ~0x03U) != 0) {
		DPRINTF(("pci_xhci: eval ctx, input ctl invalid"));
		cmderr = XHCI_TRB_ERROR_TRB;
		goto done;
	}

	/* assign address to slot; in this emulation, slot_id = address */
	dev_ctx = pci_xhci_get_dev_ctx(sc, slot);
	if (dev_ctx == NULL) {
		cmderr = XHCI_TRB_ERROR_PARAMETER;
		goto done;
	}

	DPRINTF(("pci_xhci: eval ctx, dev ctx"));
	DPRINTF(("          slot %08x %08x %08x %08x",
	        dev_ctx->ctx_slot.dwSctx0, dev_ctx->ctx_slot.dwSctx1,
	        dev_ctx->ctx_slot.dwSctx2, dev_ctx->ctx_slot.dwSctx3));

	if (input_ctx->ctx_input.dwInCtx1 & 0x01) {	/* slot ctx */
		/* set max exit latency */
		dev_ctx->ctx_slot.dwSctx1 = FIELD_COPY(
		    dev_ctx->ctx_slot.dwSctx1, input_ctx->ctx_slot.dwSctx1,
		    0xFFFF, 0);

		/* set interrupter target */
		dev_ctx->ctx_slot.dwSctx2 = FIELD_COPY(
		    dev_ctx->ctx_slot.dwSctx2, input_ctx->ctx_slot.dwSctx2,
		    0x3FF, 22);
	}
	if (input_ctx->ctx_input.dwInCtx1 & 0x02) {	/* control ctx */
		/* set max packet size */
		dev_ctx->ctx_ep[1].dwEpCtx1 = FIELD_COPY(
		    dev_ctx->ctx_ep[1].dwEpCtx1, ep0_ctx->dwEpCtx1,
		    0xFFFF, 16);

		ep0_ctx = &dev_ctx->ctx_ep[1];
	}
	pci_emul_mark_dma_dirty_mapping(sc->xsc_pi, dev_ctx,
	    sizeof(*dev_ctx));

	DPRINTF(("pci_xhci: eval ctx, output ctx"));
	DPRINTF(("          slot %08x %08x %08x %08x",
	        dev_ctx->ctx_slot.dwSctx0, dev_ctx->ctx_slot.dwSctx1,
	        dev_ctx->ctx_slot.dwSctx2, dev_ctx->ctx_slot.dwSctx3));
	DPRINTF(("          ep0  %08x %08x %016lx %08x",
	        ep0_ctx->dwEpCtx0, ep0_ctx->dwEpCtx1, ep0_ctx->qwEpCtx2,
	        ep0_ctx->dwEpCtx4));

done:
	return (cmderr);
}

static int
pci_xhci_complete_commands(struct pci_xhci_softc *sc)
{
	struct xhci_trb	evtrb;
	struct xhci_trb	*trb;
	uint64_t	crcr;
	uint32_t	ccs;		/* cycle state (XHCI 4.9.2) */
	uint32_t	type;
	uint32_t	slot;
	uint32_t	cmderr;
	uint32_t	budget;
	int		error;

	error = 0;
	sc->opregs.crcr |= XHCI_CRCR_LO_CRR;

	trb = sc->opregs.cr_p;
	ccs = sc->opregs.crcr & XHCI_CRCR_LO_RCS;
	crcr = sc->opregs.crcr & ~0xF;
	if (trb == NULL) {
		pci_xhci_host_error(sc);
		sc->opregs.crcr &= ~XHCI_CRCR_LO_CRR;
		return (EFAULT);
	}

	for (budget = 0; budget < XHCI_COMMAND_TRB_BUDGET; budget++) {
		sc->opregs.cr_p = trb;

		type = XHCI_TRB_3_TYPE_GET(trb->dwTrb3);

		if ((trb->dwTrb3 & XHCI_TRB_3_CYCLE_BIT) !=
		    (ccs & XHCI_TRB_3_CYCLE_BIT))
			break;

		DPRINTF(("pci_xhci: cmd type 0x%x, Trb0 x%016lx dwTrb2 x%08x"
		        " dwTrb3 x%08x, TRB_CYCLE %u/ccs %u",
		        type, trb->qwTrb0, trb->dwTrb2, trb->dwTrb3,
		        trb->dwTrb3 & XHCI_TRB_3_CYCLE_BIT, ccs));

		cmderr = XHCI_TRB_ERROR_SUCCESS;
		evtrb.dwTrb2 = 0;
		evtrb.dwTrb3 = (ccs & XHCI_TRB_3_CYCLE_BIT) |
		      XHCI_TRB_3_TYPE_SET(XHCI_TRB_EVENT_CMD_COMPLETE);
		slot = 0;

		switch (type) {
		case XHCI_TRB_TYPE_LINK:			/* 0x06 */
			if (trb->dwTrb3 & XHCI_TRB_3_TC_BIT)
				ccs ^= XHCI_CRCR_LO_RCS;
			break;

		case XHCI_TRB_TYPE_ENABLE_SLOT:			/* 0x09 */
			cmderr = pci_xhci_cmd_enable_slot(sc, &slot);
			break;

		case XHCI_TRB_TYPE_DISABLE_SLOT:		/* 0x0A */
			slot = XHCI_TRB_3_SLOT_GET(trb->dwTrb3);
			cmderr = pci_xhci_cmd_disable_slot(sc, slot);
			break;

		case XHCI_TRB_TYPE_ADDRESS_DEVICE:		/* 0x0B */
			slot = XHCI_TRB_3_SLOT_GET(trb->dwTrb3);
			cmderr = pci_xhci_cmd_address_device(sc, slot, trb);
			break;

		case XHCI_TRB_TYPE_CONFIGURE_EP:		/* 0x0C */
			slot = XHCI_TRB_3_SLOT_GET(trb->dwTrb3);
			cmderr = pci_xhci_cmd_config_ep(sc, slot, trb);
			break;

		case XHCI_TRB_TYPE_EVALUATE_CTX:		/* 0x0D */
			slot = XHCI_TRB_3_SLOT_GET(trb->dwTrb3);
			cmderr = pci_xhci_cmd_eval_ctx(sc, slot, trb);
			break;

		case XHCI_TRB_TYPE_RESET_EP:			/* 0x0E */
			DPRINTF(("Reset Endpoint on slot %d", slot));
			slot = XHCI_TRB_3_SLOT_GET(trb->dwTrb3);
			cmderr = pci_xhci_cmd_reset_ep(sc, slot, trb);
			break;

		case XHCI_TRB_TYPE_STOP_EP:			/* 0x0F */
			DPRINTF(("Stop Endpoint on slot %d", slot));
			slot = XHCI_TRB_3_SLOT_GET(trb->dwTrb3);
			cmderr = pci_xhci_cmd_reset_ep(sc, slot, trb);
			break;

		case XHCI_TRB_TYPE_SET_TR_DEQUEUE:		/* 0x10 */
			slot = XHCI_TRB_3_SLOT_GET(trb->dwTrb3);
			cmderr = pci_xhci_cmd_set_tr(sc, slot, trb);
			break;

		case XHCI_TRB_TYPE_RESET_DEVICE:		/* 0x11 */
			slot = XHCI_TRB_3_SLOT_GET(trb->dwTrb3);
			cmderr = pci_xhci_cmd_reset_device(sc, slot);
			break;

		case XHCI_TRB_TYPE_FORCE_EVENT:			/* 0x12 */
			cmderr = XHCI_TRB_ERROR_TRB;
			break;

		case XHCI_TRB_TYPE_NEGOTIATE_BW:		/* 0x13 */
			cmderr = XHCI_TRB_ERROR_TRB;
			break;

		case XHCI_TRB_TYPE_SET_LATENCY_TOL:		/* 0x14 */
			cmderr = XHCI_TRB_ERROR_TRB;
			break;

		case XHCI_TRB_TYPE_GET_PORT_BW:			/* 0x15 */
			cmderr = XHCI_TRB_ERROR_TRB;
			break;

		case XHCI_TRB_TYPE_FORCE_HEADER:		/* 0x16 */
			cmderr = XHCI_TRB_ERROR_TRB;
			break;

		case XHCI_TRB_TYPE_NOOP_CMD:			/* 0x17 */
			break;

		default:
			DPRINTF(("pci_xhci: unsupported cmd %x", type));
			cmderr = XHCI_TRB_ERROR_TRB;
			break;
		}

		if (type != XHCI_TRB_TYPE_LINK) {
			/*
			 * insert command completion event and assert intr
			 */
			evtrb.qwTrb0 = crcr;
			evtrb.dwTrb2 |= XHCI_TRB_2_ERROR_SET(cmderr);
			evtrb.dwTrb3 |= XHCI_TRB_3_SLOT_SET(slot);
			DPRINTF(("pci_xhci: command 0x%x result: 0x%x",
			        type, cmderr));
			if (pci_xhci_insert_event(sc, &evtrb, 1) !=
			    XHCI_TRB_ERROR_SUCCESS) {
				error = EIO;
				break;
			}
		}

		trb = pci_xhci_trb_next(sc, trb, &crcr);
		if (trb == NULL) {
			pci_xhci_host_error(sc);
			error = EFAULT;
			break;
		}
	}
	if (budget == XHCI_COMMAND_TRB_BUDGET) {
		pci_xhci_host_error(sc);
		error = ELOOP;
	}

	sc->opregs.crcr = crcr | (sc->opregs.crcr & XHCI_CRCR_LO_CA) | ccs;
	sc->opregs.crcr &= ~XHCI_CRCR_LO_CRR;
	return (error);
}

static void
pci_xhci_dump_trb(struct xhci_trb *trb)
{
	static const char *trbtypes[] = {
		"RESERVED",
		"NORMAL",
		"SETUP_STAGE",
		"DATA_STAGE",
		"STATUS_STAGE",
		"ISOCH",
		"LINK",
		"EVENT_DATA",
		"NOOP",
		"ENABLE_SLOT",
		"DISABLE_SLOT",
		"ADDRESS_DEVICE",
		"CONFIGURE_EP",
		"EVALUATE_CTX",
		"RESET_EP",
		"STOP_EP",
		"SET_TR_DEQUEUE",
		"RESET_DEVICE",
		"FORCE_EVENT",
		"NEGOTIATE_BW",
		"SET_LATENCY_TOL",
		"GET_PORT_BW",
		"FORCE_HEADER",
		"NOOP_CMD"
	};
	uint32_t type;

	type = XHCI_TRB_3_TYPE_GET(trb->dwTrb3);
	DPRINTF(("pci_xhci: trb[@%p] type x%02x %s 0:x%016lx 2:x%08x 3:x%08x",
	         trb, type,
	         type <= XHCI_TRB_TYPE_NOOP_CMD ? trbtypes[type] : "INVALID",
	         trb->qwTrb0, trb->dwTrb2, trb->dwTrb3));
}

static int
pci_xhci_xfer_complete(struct pci_xhci_softc *sc, struct usb_data_xfer *xfer,
     uint32_t slot, uint32_t epid, int *do_intr)
{
	struct pci_xhci_dev_emu *dev;
	struct pci_xhci_dev_ep	*devep;
	struct xhci_dev_ctx	*dev_ctx;
	struct xhci_endp_ctx	*ep_ctx;
	struct xhci_trb		*trb;
	struct xhci_trb		evtrb;
	uint32_t trbflags;
	uint32_t edtla;
	int i, err;

	dev = XHCI_SLOTDEV_PTR(sc, slot);
	if (dev == NULL || epid == 0 || epid >= XHCI_MAX_ENDPOINTS ||
	    xfer->head >= USB_MAX_XFER_BLOCKS ||
	    xfer->ndata > USB_MAX_XFER_BLOCKS)
		return (XHCI_TRB_ERROR_PARAMETER);
	devep = &dev->eps[epid];
	dev_ctx = pci_xhci_get_dev_ctx(sc, slot);
	if (dev_ctx == NULL) {
		return XHCI_TRB_ERROR_PARAMETER;
	}

	ep_ctx = &dev_ctx->ctx_ep[epid];

	err = XHCI_TRB_ERROR_SUCCESS;
	*do_intr = 0;
	edtla = 0;

	/* go through list of TRBs and insert event(s) */
	for (i = xfer->head; xfer->ndata > 0; ) {
		evtrb.qwTrb0 = (uint64_t)xfer->data[i].hci_data;
		trb = pci_xhci_map(sc, evtrb.qwTrb0, sizeof(*trb));
		if (trb == NULL)
			return (XHCI_TRB_ERROR_DATA_BUF);
		trbflags = trb->dwTrb3;

		DPRINTF(("pci_xhci: xfer[%d] done?%u:%d trb %x %016lx %x "
		         "(err %d) IOC?%d",
		     i, xfer->data[i].processed, xfer->data[i].blen,
		     XHCI_TRB_3_TYPE_GET(trbflags), evtrb.qwTrb0,
		     trbflags, err,
		     trb->dwTrb3 & XHCI_TRB_3_IOC_BIT ? 1 : 0));

		if (!xfer->data[i].processed) {
			xfer->head = i;
			break;
		}

		xfer->ndata--;
		edtla += xfer->data[i].bdone;
		if (pci_xhci_trb_device_writes(epid, trbflags) &&
		    xfer->data[i].buf != NULL && xfer->data[i].bdone > 0) {
			if ((uint32_t)xfer->data[i].bdone >
			    XHCI_TRB_2_BYTES_GET(trb->dwTrb2))
				return (XHCI_TRB_ERROR_DATA_BUF);
			pci_emul_mark_dma_dirty_mapping(sc->xsc_pi,
			    xfer->data[i].buf, (size_t)xfer->data[i].bdone);
		}

		trb->dwTrb3 = (trb->dwTrb3 & ~0x1) | (xfer->data[i].ccs);
		pci_emul_mark_dma_dirty_mapping(sc->xsc_pi, trb, sizeof(*trb));

		err = pci_xhci_update_ep_ring(sc, dev, devep, ep_ctx,
		    xfer->data[i].streamid, xfer->data[i].trbnext,
		    xfer->data[i].ccs);
		if (err != XHCI_TRB_ERROR_SUCCESS)
			break;

		/* Only interrupt if IOC or short packet */
		if (!(trb->dwTrb3 & XHCI_TRB_3_IOC_BIT) &&
		    !((err == XHCI_TRB_ERROR_SHORT_PKT) &&
		      (trb->dwTrb3 & XHCI_TRB_3_ISP_BIT))) {

			i = (i + 1) % USB_MAX_XFER_BLOCKS;
			continue;
		}

		evtrb.dwTrb2 = XHCI_TRB_2_ERROR_SET(err) |
		               XHCI_TRB_2_REM_SET(xfer->data[i].blen);

		evtrb.dwTrb3 = XHCI_TRB_3_TYPE_SET(XHCI_TRB_EVENT_TRANSFER) |
		    XHCI_TRB_3_SLOT_SET(slot) | XHCI_TRB_3_EP_SET(epid);

		if (XHCI_TRB_3_TYPE_GET(trbflags) == XHCI_TRB_TYPE_EVENT_DATA) {
			DPRINTF(("pci_xhci EVENT_DATA edtla %u", edtla));
			evtrb.qwTrb0 = trb->qwTrb0;
			evtrb.dwTrb2 = (edtla & 0xFFFFF) |
			         XHCI_TRB_2_ERROR_SET(err);
			evtrb.dwTrb3 |= XHCI_TRB_3_ED_BIT;
			edtla = 0;
		}

		*do_intr = 1;

		err = pci_xhci_insert_event(sc, &evtrb, 0);
		if (err != XHCI_TRB_ERROR_SUCCESS) {
			break;
		}

		i = (i + 1) % USB_MAX_XFER_BLOCKS;
	}

	return (err);
}

static int
pci_xhci_update_ep_ring(struct pci_xhci_softc *sc,
    struct pci_xhci_dev_emu *dev __unused, struct pci_xhci_dev_ep *devep,
    struct xhci_endp_ctx *ep_ctx, uint32_t streamid, uint64_t ringaddr, int ccs)
{

	if (devep->ep_NumStreams != 0) {
		if (streamid == 0 || streamid >= devep->ep_NumStreams ||
		    devep->ep_sctx == NULL || devep->ep_sctx_trbs == NULL)
			return (XHCI_TRB_ERROR_INVALID_SID);
		devep->ep_sctx[streamid].qwSctx0 = (ringaddr & ~0xFUL) |
		                                   (ccs & 0x1);

		devep->ep_sctx_trbs[streamid].ringaddr = ringaddr & ~0xFUL;
		devep->ep_sctx_trbs[streamid].ccs = ccs & 0x1;
		ep_ctx->qwEpCtx2 = (ep_ctx->qwEpCtx2 & ~0x1) | (ccs & 0x1);
		pci_emul_mark_dma_dirty_mapping(sc->xsc_pi,
		    &devep->ep_sctx[streamid],
		    sizeof(devep->ep_sctx[streamid]));

		DPRINTF(("xhci update ep-ring stream %d, addr %lx",
		    streamid, devep->ep_sctx[streamid].qwSctx0));
	} else {
		struct xhci_trb *next;

		next = pci_xhci_map(sc, ringaddr & ~0xFUL, sizeof(*next));
		if (next == NULL)
			return (XHCI_TRB_ERROR_DATA_BUF);
		devep->ep_ringaddr = ringaddr & ~0xFUL;
		devep->ep_ccs = ccs & 0x1;
		devep->ep_tr = next;
		ep_ctx->qwEpCtx2 = (ringaddr & ~0xFUL) | (ccs & 0x1);

		DPRINTF(("xhci update ep-ring, addr %lx",
		    (devep->ep_ringaddr | devep->ep_ccs)));
	}
	pci_emul_mark_dma_dirty_mapping(sc->xsc_pi, ep_ctx, sizeof(*ep_ctx));
	return (XHCI_TRB_ERROR_SUCCESS);
}

static int
pci_xhci_validate_slot(uint32_t slot)
{
	if (slot == 0)
		return (XHCI_TRB_ERROR_TRB);
	else if (slot > XHCI_MAX_SLOTS)
		return (XHCI_TRB_ERROR_SLOT_NOT_ON);
	else
		return (XHCI_TRB_ERROR_SUCCESS);
}

/*
 * Outstanding transfer still in progress (device NAK'd earlier) so retry
 * the transfer again to see if it succeeds.
 */
static int
pci_xhci_try_usb_xfer(struct pci_xhci_softc *sc,
    struct pci_xhci_dev_emu *dev, struct pci_xhci_dev_ep *devep,
    struct xhci_endp_ctx *ep_ctx, uint32_t slot, uint32_t epid)
{
	struct usb_data_xfer *xfer;
	int		err;
	int		do_intr;

	ep_ctx->dwEpCtx0 = FIELD_REPLACE(
		    ep_ctx->dwEpCtx0, XHCI_ST_EPCTX_RUNNING, 0x7, 0);
	pci_emul_mark_dma_dirty_mapping(sc->xsc_pi, ep_ctx, sizeof(*ep_ctx));

	err = 0;
	do_intr = 0;

	xfer = devep->ep_xfer;
	USB_DATA_XFER_LOCK(xfer);

	/* outstanding requests queued up */
	if (dev->dev_ue->ue_data != NULL) {
		err = dev->dev_ue->ue_data(dev->dev_sc, xfer,
		            epid & 0x1 ? USB_XFER_IN : USB_XFER_OUT, epid/2);
		if (err == USB_ERR_CANCELLED) {
			if (USB_DATA_GET_ERRCODE(&xfer->data[xfer->head]) ==
			    USB_NAK)
				err = XHCI_TRB_ERROR_SUCCESS;
		} else {
			err = pci_xhci_xfer_complete(sc, xfer, slot, epid,
			                             &do_intr);
			if (err == XHCI_TRB_ERROR_SUCCESS && do_intr) {
				pci_xhci_assert_interrupt(sc);
			}


			/* XXX should not do it if error? */
			USB_DATA_XFER_RESET(xfer);
		}
	}

	USB_DATA_XFER_UNLOCK(xfer);


	return (err);
}


static int
pci_xhci_handle_transfer(struct pci_xhci_softc *sc,
    struct pci_xhci_dev_emu *dev, struct pci_xhci_dev_ep *devep,
    struct xhci_endp_ctx *ep_ctx, struct xhci_trb *trb, uint32_t slot,
    uint32_t epid, uint64_t addr, uint32_t ccs, uint32_t streamid)
{
	struct xhci_trb *setup_trb;
	struct usb_data_xfer *xfer;
	struct usb_data_xfer_block *xfer_block;
	void		*buf;
	size_t		blen;
	uint64_t	val;
	uint32_t	trbflags;
	int		do_intr, err;
	int		do_retry;

	ep_ctx->dwEpCtx0 = FIELD_REPLACE(ep_ctx->dwEpCtx0,
	                                 XHCI_ST_EPCTX_RUNNING, 0x7, 0);
	pci_emul_mark_dma_dirty_mapping(sc->xsc_pi, ep_ctx, sizeof(*ep_ctx));

	xfer = devep->ep_xfer;
	if (xfer == NULL)
		return (XHCI_TRB_ERROR_ENDP_NOT_ON);
	USB_DATA_XFER_LOCK(xfer);

	DPRINTF(("pci_xhci handle_transfer slot %u", slot));

retry:
	err = XHCI_TRB_ERROR_INVALID;
	do_retry = 0;
	do_intr = 0;
	setup_trb = NULL;

	while (1) {
		pci_xhci_dump_trb(trb);

		trbflags = trb->dwTrb3;

		if (XHCI_TRB_3_TYPE_GET(trbflags) != XHCI_TRB_TYPE_LINK &&
		    (trbflags & XHCI_TRB_3_CYCLE_BIT) !=
		    (ccs & XHCI_TRB_3_CYCLE_BIT)) {
			DPRINTF(("Cycle-bit changed trbflags %x, ccs %x",
			    trbflags & XHCI_TRB_3_CYCLE_BIT, ccs));
			break;
		}

		xfer_block = NULL;

		switch (XHCI_TRB_3_TYPE_GET(trbflags)) {
		case XHCI_TRB_TYPE_LINK:
			if (trb->dwTrb3 & XHCI_TRB_3_TC_BIT)
				ccs ^= 0x1;

			xfer_block = usb_data_xfer_append(xfer, NULL, 0,
			                                  (void *)addr, ccs);
			if (xfer_block == NULL) {
				err = XHCI_TRB_ERROR_RESOURCE;
				goto errout;
			}
			xfer_block->processed = 1;
			break;

		case XHCI_TRB_TYPE_SETUP_STAGE:
			if ((trbflags & XHCI_TRB_3_IDT_BIT) == 0 ||
			    XHCI_TRB_2_BYTES_GET(trb->dwTrb2) != 8) {
				DPRINTF(("pci_xhci: invalid setup trb"));
				err = XHCI_TRB_ERROR_TRB;
				goto errout;
			}
			setup_trb = trb;

			val = trb->qwTrb0;
			if (!xfer->ureq) {
				xfer->ureq = malloc(
				           sizeof(struct usb_device_request));
				if (xfer->ureq == NULL) {
					err = XHCI_TRB_ERROR_RESOURCE;
					goto errout;
				}
			}
			memcpy(xfer->ureq, &val,
			       sizeof(struct usb_device_request));

			xfer_block = usb_data_xfer_append(xfer, NULL, 0,
			                                  (void *)addr, ccs);
			if (xfer_block == NULL) {
				err = XHCI_TRB_ERROR_RESOURCE;
				goto errout;
			}
			xfer_block->processed = 1;
			break;

		case XHCI_TRB_TYPE_NORMAL:
		case XHCI_TRB_TYPE_ISOCH:
			if (setup_trb != NULL) {
				DPRINTF(("pci_xhci: trb not supposed to be in "
				         "ctl scope"));
				err = XHCI_TRB_ERROR_TRB;
				goto errout;
			}
			/* fall through */

		case XHCI_TRB_TYPE_DATA_STAGE:
			blen = trb->dwTrb2 & 0x1FFFF;
			if ((trbflags & XHCI_TRB_3_IDT_BIT) != 0) {
				if (blen > sizeof(trb->qwTrb0) ||
				    pci_xhci_trb_device_writes(epid, trbflags)) {
					err = XHCI_TRB_ERROR_TRB;
					goto errout;
				}
				buf = &trb->qwTrb0;
			} else if (blen == 0) {
				buf = NULL;
			} else {
				buf = pci_xhci_map_dir(sc, trb->qwTrb0, blen,
				    pci_xhci_trb_device_writes(epid, trbflags) ?
				    PCI_DMA_DEVICE_WRITE : PCI_DMA_DEVICE_READ);
				if (buf == NULL) {
					err = XHCI_TRB_ERROR_DATA_BUF;
					goto errout;
				}
			}
			xfer_block = usb_data_xfer_append(xfer, buf, blen,
			    (void *)addr, ccs);
			if (xfer_block == NULL) {
				err = XHCI_TRB_ERROR_RESOURCE;
				goto errout;
			}
			break;

		case XHCI_TRB_TYPE_STATUS_STAGE:
			xfer_block = usb_data_xfer_append(xfer, NULL, 0,
			                                  (void *)addr, ccs);
			if (xfer_block == NULL) {
				err = XHCI_TRB_ERROR_RESOURCE;
				goto errout;
			}
			break;

		case XHCI_TRB_TYPE_NOOP:
			xfer_block = usb_data_xfer_append(xfer, NULL, 0,
			                                  (void *)addr, ccs);
			if (xfer_block == NULL) {
				err = XHCI_TRB_ERROR_RESOURCE;
				goto errout;
			}
			xfer_block->processed = 1;
			break;

		case XHCI_TRB_TYPE_EVENT_DATA:
			xfer_block = usb_data_xfer_append(xfer, NULL, 0,
			                                  (void *)addr, ccs);
			if (xfer_block == NULL) {
				err = XHCI_TRB_ERROR_RESOURCE;
				goto errout;
			}
			if ((epid > 1) && (trbflags & XHCI_TRB_3_IOC_BIT)) {
				xfer_block->processed = 1;
			}
			break;

		default:
			DPRINTF(("pci_xhci: handle xfer unexpected trb type "
			         "0x%x",
			         XHCI_TRB_3_TYPE_GET(trbflags)));
			err = XHCI_TRB_ERROR_TRB;
			goto errout;
		}

		trb = pci_xhci_trb_next(sc, trb, &addr);
		if (trb == NULL) {
			err = XHCI_TRB_ERROR_DATA_BUF;
			goto errout;
		}

		DPRINTF(("pci_xhci: next trb: 0x%lx", (uint64_t)trb));

		if (xfer_block) {
			xfer_block->trbnext = addr;
			xfer_block->streamid = streamid;
		}

		if (!setup_trb && !(trbflags & XHCI_TRB_3_CHAIN_BIT) &&
		    XHCI_TRB_3_TYPE_GET(trbflags) != XHCI_TRB_TYPE_LINK) {
			break;
		}

		/* handle current batch that requires interrupt on complete */
		if (trbflags & XHCI_TRB_3_IOC_BIT) {
			DPRINTF(("pci_xhci: trb IOC bit set"));
			if (epid == 1)
				do_retry = 1;
			break;
		}
	}

	DPRINTF(("pci_xhci[%d]: xfer->ndata %u", __LINE__, xfer->ndata));

	if (xfer->ndata <= 0)
		goto errout;

	if (epid == 1) {
		int usberr;

		if (dev->dev_ue->ue_request != NULL)
			usberr = dev->dev_ue->ue_request(dev->dev_sc, xfer);
		else
			usberr = USB_ERR_NOT_STARTED;
		err = USB_TO_XHCI_ERR(usberr);
		if (err == XHCI_TRB_ERROR_SUCCESS ||
		    err == XHCI_TRB_ERROR_STALL ||
		    err == XHCI_TRB_ERROR_SHORT_PKT) {
			err = pci_xhci_xfer_complete(sc, xfer, slot, epid,
			    &do_intr);
			if (err != XHCI_TRB_ERROR_SUCCESS)
				do_retry = 0;
		}

	} else {
		/* handle data transfer */
		err = pci_xhci_try_usb_xfer(sc, dev, devep, ep_ctx, slot,
		    epid);
	}

errout:
	if (err == XHCI_TRB_ERROR_EV_RING_FULL)
		DPRINTF(("pci_xhci[%d]: event ring full", __LINE__));

	if (!do_retry && err != XHCI_TRB_ERROR_SUCCESS &&
	    err != XHCI_TRB_ERROR_EV_RING_FULL)
		USB_DATA_XFER_RESET(xfer);

	if (!do_retry)
		USB_DATA_XFER_UNLOCK(xfer);

	if (do_intr)
		pci_xhci_assert_interrupt(sc);

	if (do_retry) {
		USB_DATA_XFER_RESET(xfer);
		DPRINTF(("pci_xhci[%d]: retry:continuing with next TRBs",
		         __LINE__));
		goto retry;
	}

	if (epid == 1)
		USB_DATA_XFER_RESET(xfer);

	return (err);
}

static void
pci_xhci_device_doorbell(struct pci_xhci_softc *sc, uint32_t slot,
    uint32_t epid, uint32_t streamid)
{
	struct pci_xhci_dev_emu *dev;
	struct pci_xhci_dev_ep	*devep;
	struct xhci_dev_ctx	*dev_ctx;
	struct xhci_endp_ctx	*ep_ctx;
	struct pci_xhci_trb_ring *sctx_tr;
	struct xhci_trb	*trb;
	uint64_t	ringaddr;
	uint32_t	ccs;
	int		error;

	DPRINTF(("pci_xhci doorbell slot %u epid %u stream %u",
	    slot, epid, streamid));

	if (slot == 0 || slot > XHCI_MAX_SLOTS) {
		DPRINTF(("pci_xhci: invalid doorbell slot %u", slot));
		return;
	}

	if (epid == 0 || epid >= XHCI_MAX_ENDPOINTS) {
		DPRINTF(("pci_xhci: invalid endpoint %u", epid));
		return;
	}

	dev = XHCI_SLOTDEV_PTR(sc, slot);
	if (dev == NULL) {
		DPRINTF(("pci_xhci: doorbell for empty slot %u", slot));
		return;
	}
	devep = &dev->eps[epid];
	dev_ctx = pci_xhci_get_dev_ctx(sc, slot);
	if (!dev_ctx) {
		return;
	}
	ep_ctx = &dev_ctx->ctx_ep[epid];

	sctx_tr = NULL;

	DPRINTF(("pci_xhci: device doorbell ep[%u] %08x %08x %016lx %08x",
	        epid, ep_ctx->dwEpCtx0, ep_ctx->dwEpCtx1, ep_ctx->qwEpCtx2,
	        ep_ctx->dwEpCtx4));

	if (ep_ctx->qwEpCtx2 == 0)
		return;

	/* handle pending transfers */
	if (devep->ep_xfer == NULL) {
		DPRINTF(("pci_xhci: doorbell for disabled endpoint %u", epid));
		return;
	}
	if (devep->ep_xfer->ndata > 0) {
		pci_xhci_try_usb_xfer(sc, dev, devep, ep_ctx, slot, epid);
		return;
	}

	/* get next trb work item */
	if (devep->ep_NumStreams != 0) {
		/*
		 * Stream IDs of 0, 65535 (any stream), and 65534
		 * (prime) are invalid.
		 */
		if (streamid == 0 || streamid == 65534 || streamid == 65535) {
			DPRINTF(("pci_xhci: invalid stream %u", streamid));
			return;
		}

		error = pci_xhci_find_stream(sc, ep_ctx, devep, streamid);
		if (error != XHCI_TRB_ERROR_SUCCESS) {
			DPRINTF(("pci_xhci: invalid stream %u: %d",
			    streamid, error));
			return;
		}
		sctx_tr = &devep->ep_sctx_trbs[streamid];
		ringaddr = sctx_tr->ringaddr;
		ccs = sctx_tr->ccs;
		trb = pci_xhci_map(sc, sctx_tr->ringaddr & ~0xFUL,
		    sizeof(*trb));
		if (trb == NULL) {
			DPRINTF(("pci_xhci: invalid stream ring address"));
			return;
		}
		DPRINTF(("doorbell, stream %u, ccs %lx, trb ccs %x",
		        streamid, ep_ctx->qwEpCtx2 & XHCI_TRB_3_CYCLE_BIT,
		        trb->dwTrb3 & XHCI_TRB_3_CYCLE_BIT));
	} else {
		if (streamid != 0) {
			DPRINTF(("pci_xhci: invalid stream %u", streamid));
			return;
		}
		ringaddr = devep->ep_ringaddr;
		ccs = devep->ep_ccs;
		trb = devep->ep_tr;
		if (trb == NULL) {
			DPRINTF(("pci_xhci: invalid endpoint ring address"));
			return;
		}
		DPRINTF(("doorbell, ccs %lx, trb ccs %x",
		        ep_ctx->qwEpCtx2 & XHCI_TRB_3_CYCLE_BIT,
		        trb->dwTrb3 & XHCI_TRB_3_CYCLE_BIT));
	}

	if (XHCI_TRB_3_TYPE_GET(trb->dwTrb3) == 0) {
		DPRINTF(("pci_xhci: ring %lx trb[%lx] EP %u is RESERVED?",
		        ep_ctx->qwEpCtx2, devep->ep_ringaddr, epid));
		return;
	}

	pci_xhci_handle_transfer(sc, dev, devep, ep_ctx, trb, slot, epid,
	                         ringaddr, ccs, streamid);
}

static void
pci_xhci_dbregs_write(struct pci_xhci_softc *sc, uint64_t offset,
    uint64_t value)
{

	offset = (offset - sc->dboff) / sizeof(uint32_t);

	DPRINTF(("pci_xhci: doorbell write offset 0x%lx: 0x%lx",
	        offset, value));

	if (XHCI_HALTED(sc)) {
		DPRINTF(("pci_xhci: controller halted"));
		return;
	}

	if (offset == 0)
		pci_xhci_complete_commands(sc);
	else if (sc->portregs != NULL)
		pci_xhci_device_doorbell(sc, offset,
		   XHCI_DB_TARGET_GET(value), XHCI_DB_SID_GET(value));
}

static void
pci_xhci_rtsregs_write(struct pci_xhci_softc *sc, uint64_t offset,
    uint64_t value)
{
	struct pci_xhci_rtsregs *rts;

	offset -= sc->rtsoff;

	if (offset == 0) {
		DPRINTF(("pci_xhci attempted write to MFINDEX"));
		return;
	}

	DPRINTF(("pci_xhci: runtime regs write offset 0x%lx: 0x%lx",
	        offset, value));

	offset -= 0x20;		/* start of intrreg */

	rts = &sc->rtsregs;

	switch (offset) {
	case 0x00:
		if (value & XHCI_IMAN_INTR_PEND)
			rts->intrreg.iman &= ~XHCI_IMAN_INTR_PEND;
		rts->intrreg.iman = (value & XHCI_IMAN_INTR_ENA) |
		                    (rts->intrreg.iman & XHCI_IMAN_INTR_PEND);

		if (!(value & XHCI_IMAN_INTR_ENA))
			pci_xhci_deassert_interrupt(sc);

		break;

	case 0x04:
		rts->intrreg.imod = value;
		break;

	case 0x08:
		rts->intrreg.erstsz = value & 0xFFFF;
		break;

	case 0x10:
		/* ERSTBA low bits */
		rts->intrreg.erstba = MASK_64_HI(sc->rtsregs.intrreg.erstba) |
		                      (value & ~0x3F);
		break;

	case 0x14:
		/* ERSTBA high bits */
		{
			uint64_t event_bytes, event_gpa;
			uint32_t event_count;

		rts->intrreg.erstba = (value << 32) |
		    MASK_64_LO(sc->rtsregs.intrreg.erstba);

		rts->erstba_p = pci_xhci_map(sc,
		    rts->intrreg.erstba & ~0x3FUL, sizeof(*rts->erstba_p));
		if (rts->erstba_p == NULL || rts->intrreg.erstsz != 1) {
			rts->erstba_p = NULL;
			rts->erst_p = NULL;
			pci_xhci_host_error(sc);
			break;
		}
		event_count = rts->erstba_p->dwEvrsTableSize;
		event_gpa = rts->erstba_p->qwEvrsTablePtr & ~0x3FUL;
		if (event_count == 0 ||
		    event_count > XHCI_EVENT_RING_SEGMENT_MAX) {
			rts->erstba_p = NULL;
			rts->erst_p = NULL;
			pci_xhci_host_error(sc);
			break;
		}
		event_bytes = (uint64_t)event_count * sizeof(struct xhci_trb);
		if (event_gpa > UINT64_MAX - event_bytes ||
		    (rts->erst_p = pci_xhci_map_write(sc, event_gpa,
		    event_bytes)) == NULL) {
			rts->erstba_p = NULL;
			rts->erst_p = NULL;
			pci_xhci_host_error(sc);
			break;
		}

		rts->er_enq_idx = 0;
		rts->er_events_cnt = 0;

		DPRINTF(("pci_xhci: wr erstba erst (%p) ptr 0x%lx, sz %u",
		        rts->erstba_p,
		        rts->erstba_p->qwEvrsTablePtr,
		        rts->erstba_p->dwEvrsTableSize));
		break;
		}

	case 0x18:
		/* ERDP low bits */
		rts->intrreg.erdp =
		    MASK_64_HI(sc->rtsregs.intrreg.erdp) |
		    (rts->intrreg.erdp & XHCI_ERDP_LO_BUSY) |
		    (value & ~0xF);
		if (value & XHCI_ERDP_LO_BUSY) {
			rts->intrreg.erdp &= ~XHCI_ERDP_LO_BUSY;
			rts->intrreg.iman &= ~XHCI_IMAN_INTR_PEND;
		}

		rts->er_deq_seg = XHCI_ERDP_LO_SINDEX(value);

		break;

	case 0x1C:
		/* ERDP high bits */
		rts->intrreg.erdp = (value << 32) |
		    MASK_64_LO(sc->rtsregs.intrreg.erdp);

		if (rts->er_events_cnt > 0 && rts->erstba_p != NULL &&
		    rts->erst_p != NULL) {
			uint64_t erdp;
			uint64_t event_base, event_bytes;
			int erdp_i;

			erdp = rts->intrreg.erdp & ~0xF;
			event_base = rts->erstba_p->qwEvrsTablePtr;
			event_bytes = (uint64_t)rts->erstba_p->dwEvrsTableSize *
			    sizeof(struct xhci_trb);
			if (event_bytes == 0 || event_base > UINT64_MAX - event_bytes ||
			    erdp < event_base || erdp >= event_base + event_bytes ||
			    (erdp - event_base) % sizeof(struct xhci_trb) != 0) {
				pci_xhci_host_error(sc);
				break;
			}
			erdp_i = (erdp - event_base) / sizeof(struct xhci_trb);

			if (erdp_i <= rts->er_enq_idx)
				rts->er_events_cnt = rts->er_enq_idx - erdp_i;
			else
				rts->er_events_cnt =
				          rts->erstba_p->dwEvrsTableSize -
				          (erdp_i - rts->er_enq_idx);

			DPRINTF(("pci_xhci: erdp 0x%lx, events cnt %u",
			        erdp, rts->er_events_cnt));
		}

		break;

	default:
		DPRINTF(("pci_xhci attempted write to RTS offset 0x%lx",
		        offset));
		break;
	}
}

static uint64_t
pci_xhci_portregs_read(struct pci_xhci_softc *sc, uint64_t offset)
{
	struct pci_xhci_portregs *portregs;
	int port;
	uint32_t reg;

	if (sc->portregs == NULL)
		return (0);

	port = (offset - XHCI_PORTREGS_PORT0) / XHCI_PORTREGS_SETSZ;
	offset = (offset - XHCI_PORTREGS_PORT0) % XHCI_PORTREGS_SETSZ;

	if (port > XHCI_MAX_DEVS) {
		DPRINTF(("pci_xhci: portregs_read port %d >= XHCI_MAX_DEVS",
		    port));

		/* return default value for unused port */
		return (XHCI_PS_SPEED_SET(3));
	}

	portregs = XHCI_PORTREG_PTR(sc, port);
	switch (offset) {
	case 0:
		reg = portregs->portsc;
		break;
	case 4:
		reg = portregs->portpmsc;
		break;
	case 8:
		reg = portregs->portli;
		break;
	case 12:
		reg = portregs->porthlpmc;
		break;
	default:
		DPRINTF(("pci_xhci: unaligned portregs read offset %#lx",
		    offset));
		reg = 0xffffffff;
		break;
	}

	DPRINTF(("pci_xhci: portregs read offset 0x%lx port %u -> 0x%x",
	        offset, port, reg));

	return (reg);
}

static void
pci_xhci_hostop_write(struct pci_xhci_softc *sc, uint64_t offset,
    uint64_t value)
{
	offset -= XHCI_CAPLEN;

	if (offset < 0x400)
		DPRINTF(("pci_xhci: hostop write offset 0x%lx: 0x%lx",
		         offset, value));

	switch (offset) {
	case XHCI_USBCMD:
		sc->opregs.usbcmd = pci_xhci_usbcmd_write(sc, value & 0x3F0F);
		break;

	case XHCI_USBSTS:
		/* clear bits on write */
		sc->opregs.usbsts &= ~(value &
		      (XHCI_STS_HSE|XHCI_STS_EINT|XHCI_STS_PCD|XHCI_STS_SSS|
		       XHCI_STS_RSS|XHCI_STS_SRE|XHCI_STS_CNR));
		break;

	case XHCI_PAGESIZE:
		/* read only */
		break;

	case XHCI_DNCTRL:
		sc->opregs.dnctrl = value & 0xFFFF;
		break;

	case XHCI_CRCR_LO:
		if (sc->opregs.crcr & XHCI_CRCR_LO_CRR) {
			sc->opregs.crcr &= ~(XHCI_CRCR_LO_CS|XHCI_CRCR_LO_CA);
			sc->opregs.crcr |= value &
			                   (XHCI_CRCR_LO_CS|XHCI_CRCR_LO_CA);
		} else {
			sc->opregs.crcr = MASK_64_HI(sc->opregs.crcr) |
			           (value & (0xFFFFFFC0 | XHCI_CRCR_LO_RCS));
		}
		break;

	case XHCI_CRCR_HI:
		if (!(sc->opregs.crcr & XHCI_CRCR_LO_CRR)) {
			sc->opregs.crcr = MASK_64_LO(sc->opregs.crcr) |
			                  (value << 32);

			sc->opregs.cr_p = pci_xhci_map(sc,
			    sc->opregs.crcr & ~0xF, sizeof(*sc->opregs.cr_p));
		}

		if (sc->opregs.crcr & XHCI_CRCR_LO_CS) {
			/* Stop operation of Command Ring */
		}

		if (sc->opregs.crcr & XHCI_CRCR_LO_CA) {
			/* Abort command */
		}

		break;

	case XHCI_DCBAAP_LO:
		sc->opregs.dcbaap = MASK_64_HI(sc->opregs.dcbaap) |
		                    (value & 0xFFFFFFC0);
		break;

	case XHCI_DCBAAP_HI:
		sc->opregs.dcbaap =  MASK_64_LO(sc->opregs.dcbaap) |
		                     (value << 32);
		sc->opregs.dcbaa_p = pci_xhci_map(sc,
		    sc->opregs.dcbaap & ~0x3FUL, sizeof(*sc->opregs.dcbaa_p));

		DPRINTF(("pci_xhci: opregs dcbaap = 0x%lx (vaddr 0x%lx)",
		    sc->opregs.dcbaap, (uint64_t)sc->opregs.dcbaa_p));
		break;

	case XHCI_CONFIG:
		sc->opregs.config = value & 0x03FF;
		break;

	default:
		if (offset >= 0x400)
			pci_xhci_portregs_write(sc, offset, value);

		break;
	}
}


static void
pci_xhci_write(struct pci_devinst *pi, int baridx __unused, uint64_t offset,
    int size __unused, uint64_t value)
{
	struct pci_xhci_softc *sc;

	sc = pi->pi_arg;

	assert(baridx == 0);

	pthread_mutex_lock(&sc->mtx);
	if (offset < XHCI_CAPLEN)	/* read only registers */
		WPRINTF(("pci_xhci: write RO-CAPs offset %ld", offset));
	else if (offset < sc->dboff)
		pci_xhci_hostop_write(sc, offset, value);
	else if (offset < sc->rtsoff)
		pci_xhci_dbregs_write(sc, offset, value);
	else if (offset < sc->regsend)
		pci_xhci_rtsregs_write(sc, offset, value);
	else
		WPRINTF(("pci_xhci: write invalid offset %ld", offset));

	pthread_mutex_unlock(&sc->mtx);
}

static uint64_t
pci_xhci_hostcap_read(struct pci_xhci_softc *sc, uint64_t offset)
{
	uint64_t	value;

	switch (offset) {
	case XHCI_CAPLENGTH:	/* 0x00 */
		value = sc->caplength;
		break;

	case XHCI_HCSPARAMS1:	/* 0x04 */
		value = sc->hcsparams1;
		break;

	case XHCI_HCSPARAMS2:	/* 0x08 */
		value = sc->hcsparams2;
		break;

	case XHCI_HCSPARAMS3:	/* 0x0C */
		value = sc->hcsparams3;
		break;

	case XHCI_HCCPARAMS1:	/* 0x10 */
		value = sc->hccparams1;
		break;

	case XHCI_DBOFF:	/* 0x14 */
		value = sc->dboff;
		break;

	case XHCI_RTSOFF:	/* 0x18 */
		value = sc->rtsoff;
		break;

	case XHCI_HCCPRAMS2:	/* 0x1C */
		value = sc->hccparams2;
		break;

	default:
		value = 0;
		break;
	}

	DPRINTF(("pci_xhci: hostcap read offset 0x%lx -> 0x%lx",
	        offset, value));

	return (value);
}

static uint64_t
pci_xhci_hostop_read(struct pci_xhci_softc *sc, uint64_t offset)
{
	uint64_t value;

	offset = (offset - XHCI_CAPLEN);

	switch (offset) {
	case XHCI_USBCMD:	/* 0x00 */
		value = sc->opregs.usbcmd;
		break;

	case XHCI_USBSTS:	/* 0x04 */
		value = sc->opregs.usbsts;
		break;

	case XHCI_PAGESIZE:	/* 0x08 */
		value = sc->opregs.pgsz;
		break;

	case XHCI_DNCTRL:	/* 0x14 */
		value = sc->opregs.dnctrl;
		break;

	case XHCI_CRCR_LO:	/* 0x18 */
		value = sc->opregs.crcr & XHCI_CRCR_LO_CRR;
		break;

	case XHCI_CRCR_HI:	/* 0x1C */
		value = 0;
		break;

	case XHCI_DCBAAP_LO:	/* 0x30 */
		value = sc->opregs.dcbaap & 0xFFFFFFFF;
		break;

	case XHCI_DCBAAP_HI:	/* 0x34 */
		value = (sc->opregs.dcbaap >> 32) & 0xFFFFFFFF;
		break;

	case XHCI_CONFIG:	/* 0x38 */
		value = sc->opregs.config;
		break;

	default:
		if (offset >= 0x400)
			value = pci_xhci_portregs_read(sc, offset);
		else
			value = 0;

		break;
	}

	if (offset < 0x400)
		DPRINTF(("pci_xhci: hostop read offset 0x%lx -> 0x%lx",
		        offset, value));

	return (value);
}

static uint64_t
pci_xhci_dbregs_read(struct pci_xhci_softc *sc __unused,
    uint64_t offset __unused)
{
	/* read doorbell always returns 0 */
	return (0);
}

static uint64_t
pci_xhci_rtsregs_read(struct pci_xhci_softc *sc, uint64_t offset)
{
	uint32_t	value;

	offset -= sc->rtsoff;
	value = 0;

	if (offset == XHCI_MFINDEX) {
		value = sc->rtsregs.mfindex;
	} else if (offset >= 0x20) {
		int item;
		uint32_t *p;

		offset -= 0x20;
		item = offset % 32;

		if (offset >= sizeof(sc->rtsregs.intrreg))
			return (0);

		p = &sc->rtsregs.intrreg.iman;
		p += item / sizeof(uint32_t);
		value = *p;
	}

	DPRINTF(("pci_xhci: rtsregs read offset 0x%lx -> 0x%x",
	        offset, value));

	return (value);
}

static uint64_t
pci_xhci_xecp_read(struct pci_xhci_softc *sc, uint64_t offset)
{
	uint32_t	value;

	offset -= sc->regsend;
	value = 0;

	switch (offset) {
	case 0:
		/* rev major | rev minor | next-cap | cap-id */
		value = (0x02 << 24) | (4 << 8) | XHCI_ID_PROTOCOLS;
		break;
	case 4:
		/* name string = "USB" */
		value = 0x20425355;
		break;
	case 8:
		/* psic | proto-defined | compat # | compat offset */
		value = ((XHCI_MAX_DEVS/2) << 8) | sc->usb2_port_start;
		break;
	case 12:
		break;
	case 16:
		/* rev major | rev minor | next-cap | cap-id */
		value = (0x03 << 24) | XHCI_ID_PROTOCOLS;
		break;
	case 20:
		/* name string = "USB" */
		value = 0x20425355;
		break;
	case 24:
		/* psic | proto-defined | compat # | compat offset */
		value = ((XHCI_MAX_DEVS/2) << 8) | sc->usb3_port_start;
		break;
	case 28:
		break;
	default:
		DPRINTF(("pci_xhci: xecp invalid offset 0x%lx", offset));
		break;
	}

	DPRINTF(("pci_xhci: xecp read offset 0x%lx -> 0x%x",
	        offset, value));

	return (value);
}


static uint64_t
pci_xhci_read(struct pci_devinst *pi, int baridx __unused, uint64_t offset,
    int size)
{
	struct pci_xhci_softc *sc;
	uint32_t	value;

	sc = pi->pi_arg;

	assert(baridx == 0);

	pthread_mutex_lock(&sc->mtx);
	if (offset < XHCI_CAPLEN)
		value = pci_xhci_hostcap_read(sc, offset);
	else if (offset < sc->dboff)
		value = pci_xhci_hostop_read(sc, offset);
	else if (offset < sc->rtsoff)
		value = pci_xhci_dbregs_read(sc, offset);
	else if (offset < sc->regsend)
		value = pci_xhci_rtsregs_read(sc, offset);
	else if (offset < (sc->regsend + 4*32))
		value = pci_xhci_xecp_read(sc, offset);
	else {
		value = 0;
		WPRINTF(("pci_xhci: read invalid offset %ld", offset));
	}

	pthread_mutex_unlock(&sc->mtx);

	switch (size) {
	case 1:
		value &= 0xFF;
		break;
	case 2:
		value &= 0xFFFF;
		break;
	case 4:
		value &= 0xFFFFFFFF;
		break;
	}

	return (value);
}

static void
pci_xhci_reset_port(struct pci_xhci_softc *sc, int portn, int warm)
{
	struct pci_xhci_portregs *port;
	struct pci_xhci_dev_emu	*dev;
	struct xhci_trb		evtrb;
	int	error;

	if (portn < 1 || portn > XHCI_MAX_DEVS)
		return;

	DPRINTF(("xhci reset port %d", portn));

	port = XHCI_PORTREG_PTR(sc, portn);
	dev = XHCI_DEVINST_PTR(sc, portn);
	if (dev) {
		port->portsc &= ~(XHCI_PS_PLS_MASK | XHCI_PS_PR | XHCI_PS_PRC);
		port->portsc |= XHCI_PS_PED |
		    XHCI_PS_SPEED_SET(dev->hci.hci_speed);

		if (warm && dev->hci.hci_usbver == 3) {
			port->portsc |= XHCI_PS_WRC;
		}

		if ((port->portsc & XHCI_PS_PRC) == 0) {
			port->portsc |= XHCI_PS_PRC;

			pci_xhci_set_evtrb(&evtrb, portn,
			     XHCI_TRB_ERROR_SUCCESS,
			     XHCI_TRB_EVENT_PORT_STS_CHANGE);
			error = pci_xhci_insert_event(sc, &evtrb, 1);
			if (error != XHCI_TRB_ERROR_SUCCESS)
				DPRINTF(("xhci reset port insert event "
				         "failed"));
		}
	}
}

static void
pci_xhci_init_port(struct pci_xhci_softc *sc, int portn)
{
	struct pci_xhci_portregs *port;
	struct pci_xhci_dev_emu	*dev;

	port = XHCI_PORTREG_PTR(sc, portn);
	dev = XHCI_DEVINST_PTR(sc, portn);
	if (dev) {
		port->portsc = XHCI_PS_CCS |		/* connected */
		               XHCI_PS_PP;		/* port power */

		if (dev->hci.hci_usbver == 2) {
			port->portsc |= XHCI_PS_PLS_SET(UPS_PORT_LS_POLL) |
			    XHCI_PS_SPEED_SET(dev->hci.hci_speed);
		} else {
			port->portsc |= XHCI_PS_PLS_SET(UPS_PORT_LS_U0) |
			    XHCI_PS_PED | /* enabled */
			    XHCI_PS_SPEED_SET(dev->hci.hci_speed);
		}

		DPRINTF(("Init port %d 0x%x", portn, port->portsc));
	} else {
		port->portsc = XHCI_PS_PLS_SET(UPS_PORT_LS_RX_DET) | XHCI_PS_PP;
		DPRINTF(("Init empty port %d 0x%x", portn, port->portsc));
	}
}

static int
pci_xhci_dev_intr(struct usb_hci *hci, int epctx)
{
	struct pci_xhci_dev_emu *dev;
	struct xhci_dev_ctx	*dev_ctx;
	struct xhci_trb		evtrb;
	struct pci_xhci_softc	*sc;
	struct pci_xhci_portregs *p;
	struct xhci_endp_ctx	*ep_ctx;
	int	error = 0;
	int	dir_in;
	int	epid;

	dir_in = epctx & 0x80;
	epid = epctx & ~0x80;

	/* HW endpoint contexts are 0-15; convert to epid based on dir */
	epid = (epid * 2) + (dir_in ? 1 : 0);

	if (epid < 1 || epid > 31)
		return (EINVAL);

	dev = hci->hci_sc;
	sc = dev->xsc;
	pthread_mutex_lock(&sc->mtx);

#ifdef BHYVE_SNAPSHOT
	/*
	 * Checkpoint ownership fence: guest RAM has (or is being) serialized,
	 * so an asynchronous backend completion must not insert events or
	 * complete transfers into guest memory until pe_resume.  Drop the
	 * doorbell; the device rings again on the next backend event, losing
	 * at most one transient input notification across the boundary.
	 */
	if (sc->snapshot_paused)
		goto done;
#endif

	/* check if device is ready; OS has to initialise it */
	if (sc->rtsregs.erstba_p == NULL ||
	    (sc->opregs.usbcmd & XHCI_CMD_RS) == 0 ||
	    dev->dev_ctx == NULL)
		goto done;

	p = XHCI_PORTREG_PTR(sc, hci->hci_port);

	/* raise event if link U3 (suspended) state */
	if (XHCI_PS_PLS_GET(p->portsc) == 3) {
		p->portsc &= ~XHCI_PS_PLS_MASK;
		p->portsc |= XHCI_PS_PLS_SET(UPS_PORT_LS_RESUME);
		if ((p->portsc & XHCI_PS_PLC) != 0)
			goto done;

		p->portsc |= XHCI_PS_PLC;

		pci_xhci_set_evtrb(&evtrb, hci->hci_port,
		      XHCI_TRB_ERROR_SUCCESS, XHCI_TRB_EVENT_PORT_STS_CHANGE);
		error = pci_xhci_insert_event(sc, &evtrb, 0);
		if (error != XHCI_TRB_ERROR_SUCCESS)
			goto done;
	}

	dev_ctx = dev->dev_ctx;
	ep_ctx = &dev_ctx->ctx_ep[epid];
	if ((ep_ctx->dwEpCtx0 & 0x7) == XHCI_ST_EPCTX_DISABLED) {
		DPRINTF(("xhci device interrupt on disabled endpoint %d",
		         epid));
		goto done;
	}

	DPRINTF(("xhci device interrupt on endpoint %d", epid));

	pci_xhci_device_doorbell(sc, hci->hci_port, epid, 0);

done:
	pthread_mutex_unlock(&sc->mtx);
	return (error);
}

static int
pci_xhci_dev_event(struct usb_hci *hci, enum hci_usbev evid __unused,
    void *param __unused)
{
	DPRINTF(("xhci device event port %d", hci->hci_port));
	return (0);
}

/*
 * Each controller contains a "slot" node which contains a list of
 * child nodes each of which is a device.  Each slot node's name
 * corresponds to a specific controller slot.  These nodes
 * contain a "device" variable identifying the device model of the
 * USB device.  For example:
 *
 * pci.0.1.0
 *          .device="xhci"
 *          .slot
 *               .1
 *                 .device="tablet"
 */
static int
pci_xhci_legacy_config(nvlist_t *nvl, const char *opts)
{
	char node_name[16];
	nvlist_t *slots_nvl, *slot_nvl;
	char *cp, *opt, *str, *tofree;
	int slot;

	if (opts == NULL)
		return (0);

	slots_nvl = create_relative_config_node(nvl, "slot");
	slot = 1;
	tofree = str = strdup(opts);
	while ((opt = strsep(&str, ",")) != NULL) {
		/* device[=<config>] */
		cp = strchr(opt, '=');
		if (cp != NULL) {
			*cp = '\0';
			cp++;
		}

		snprintf(node_name, sizeof(node_name), "%d", slot);
		slot++;
		slot_nvl = create_relative_config_node(slots_nvl, node_name);
		set_config_value_node(slot_nvl, "device", opt);

		/*
		 * NB: Given that we split on commas above, the legacy
		 * format only supports a single option.
		 */
		if (cp != NULL && *cp != '\0')
			pci_parse_legacy_config(slot_nvl, cp);
	}
	free(tofree);
	return (0);
}

static int
pci_xhci_free_devices(struct pci_xhci_softc *sc)
{
	struct pci_xhci_dev_emu *dev;
	int error, i, j;

	error = 0;
	if (sc->devices != NULL) {
		for (i = 1; i <= XHCI_MAX_DEVS; i++) {
			dev = XHCI_DEVINST_PTR(sc, i);
			if (dev == NULL)
				continue;
			if (dev->dev_initialized && dev->dev_ue != NULL &&
			    dev->dev_ue->ue_remove != NULL &&
			    dev->dev_ue->ue_remove(dev->dev_sc) != 0 && error == 0)
				error = EIO;
			for (j = 1; j < XHCI_MAX_ENDPOINTS; j++)
				pci_xhci_free_ep(&dev->eps[j]);
			free(dev->dev_sc);
			free(dev);
		}
	}
	free(sc->portregs);
	free(sc->devices);
	free(sc->slots);
	sc->portregs = NULL;
	sc->devices = NULL;
	sc->slots = NULL;
	return (error);
}

static int
pci_xhci_parse_devices(struct pci_xhci_softc *sc, nvlist_t *nvl)
{
	struct pci_xhci_dev_emu	*dev;
	struct usb_devemu	*ue;
	const nvlist_t *slots_nvl, *slot_nvl;
	const char *name, *device;
	char	*cp;
	void	*devsc, *cookie;
	long	slot;
	int	type, usb3_port, usb2_port, i, ndevices;

	usb3_port = sc->usb3_port_start;
	usb2_port = sc->usb2_port_start;

	sc->devices = calloc(XHCI_MAX_DEVS, sizeof(struct pci_xhci_dev_emu *));
	sc->slots = calloc(XHCI_MAX_SLOTS, sizeof(struct pci_xhci_dev_emu *));
	if (sc->devices == NULL || sc->slots == NULL)
		goto bad;

	ndevices = 0;

	slots_nvl = find_relative_config_node(nvl, "slot");
	if (slots_nvl == NULL)
		goto portsfinal;

	cookie = NULL;
	while ((name = nvlist_next(slots_nvl, &type, &cookie)) != NULL) {
		if (usb2_port == ((sc->usb2_port_start) + XHCI_MAX_DEVS / 2) ||
		    usb3_port == ((sc->usb3_port_start) + XHCI_MAX_DEVS / 2)) {
			WPRINTF(("pci_xhci max number of USB 2 or 3 "
			     "devices reached, max %d", XHCI_MAX_DEVS/2));
			goto bad;
		}

		if (type != NV_TYPE_NVLIST) {
			EPRINTLN(
			    "pci_xhci: config variable '%s' under slot node",
			     name);
			goto bad;
		}

		slot = strtol(name, &cp, 0);
		if (*cp != '\0' || slot <= 0 || slot > XHCI_MAX_SLOTS) {
			EPRINTLN("pci_xhci: invalid slot '%s'", name);
			goto bad;
		}

		if (XHCI_SLOTDEV_PTR(sc, slot) != NULL) {
			EPRINTLN("pci_xhci: duplicate slot '%s'", name);
			goto bad;
		}

		slot_nvl = nvlist_get_nvlist(slots_nvl, name);
		device = get_config_value_node(slot_nvl, "device");
		if (device == NULL) {
			EPRINTLN(
			    "pci_xhci: missing \"device\" value for slot '%s'",
				name);
			goto bad;
		}

		ue = usb_emu_finddev(device);
		if (ue == NULL || ue->ue_probe == NULL || ue->ue_init == NULL) {
			EPRINTLN("pci_xhci: unknown device model \"%s\"",
			    device);
			goto bad;
		}

		DPRINTF(("pci_xhci adding device %s", device));

		dev = calloc(1, sizeof(struct pci_xhci_dev_emu));
		if (dev == NULL)
			goto bad;
		dev->xsc = sc;
		dev->hci.hci_sc = dev;
		dev->hci.hci_intr = pci_xhci_dev_intr;
		dev->hci.hci_event = pci_xhci_dev_event;
		dev->hci.hci_speed = USB_SPEED_MAX;
		dev->hci.hci_usbver = -1;

		devsc = ue->ue_probe(&dev->hci, __DECONST(nvlist_t *, slot_nvl));
		if (devsc == NULL) {
			free(dev);
			goto bad;
		}
		dev->dev_sc = devsc;

		if (dev->hci.hci_usbver == -1)
			dev->hci.hci_usbver = ue->ue_usbver;

		if (dev->hci.hci_usbver == 2) {
			if (usb2_port == sc->usb2_port_start +
			    XHCI_MAX_DEVS / 2) {
				WPRINTF(("pci_xhci max number of USB 2 devices "
				     "reached, max %d", XHCI_MAX_DEVS / 2));
				free(dev->dev_sc);
				free(dev);
				goto bad;
			}
			dev->hci.hci_port = usb2_port;
			usb2_port++;
		} else {
			if (usb3_port == sc->usb3_port_start +
			    XHCI_MAX_DEVS / 2) {
				WPRINTF(("pci_xhci max number of USB 3 devices "
				     "reached, max %d", XHCI_MAX_DEVS / 2));
				free(dev->dev_sc);
				free(dev);
				goto bad;
			}
			dev->hci.hci_port = usb3_port;
			usb3_port++;
		}
		XHCI_DEVINST_PTR(sc, dev->hci.hci_port) = dev;

		dev->hci.hci_address = 0;
		dev->dev_ue = ue;
		if (ue->ue_init(dev->dev_sc))
			goto bad;
		dev->dev_initialized = true;

		if (dev->hci.hci_speed == USB_SPEED_MAX)
			dev->hci.hci_speed = ue->ue_usbspeed;

		XHCI_SLOTDEV_PTR(sc, slot) = dev;
		ndevices++;
	}

portsfinal:
	sc->portregs = calloc(XHCI_MAX_DEVS, sizeof(struct pci_xhci_portregs));
	if (sc->portregs == NULL)
		goto bad;

	if (ndevices > 0) {
		for (i = 1; i <= XHCI_MAX_DEVS; i++) {
			pci_xhci_init_port(sc, i);
		}
	} else {
		WPRINTF(("pci_xhci no USB devices configured"));
	}
	return (0);

bad:
	(void)pci_xhci_free_devices(sc);
	return (-1);
}

static int
pci_xhci_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_xhci_softc *sc;
	int	error;

	if (xhci_in_use) {
		WPRINTF(("pci_xhci controller already defined"));
		return (-1);
	}
	xhci_in_use = 1;

	sc = calloc(1, sizeof(struct pci_xhci_softc));
	if (sc == NULL) {
		xhci_in_use = 0;
		return (ENOMEM);
	}
	error = pthread_mutex_init(&sc->mtx, NULL);
	if (error != 0) {
		xhci_in_use = 0;
		free(sc);
		return (error);
	}
	pi->pi_arg = sc;
	sc->xsc_pi = pi;

	sc->usb2_port_start = (XHCI_MAX_DEVS/2) + 1;
	sc->usb3_port_start = 1;

	/* discover devices */
	error = pci_xhci_parse_devices(sc, nvl);
	if (error < 0)
		goto done;
	else
		error = 0;

	sc->caplength = XHCI_SET_CAPLEN(XHCI_CAPLEN) |
	                XHCI_SET_HCIVERSION(0x0100);
	sc->hcsparams1 = XHCI_SET_HCSP1_MAXPORTS(XHCI_MAX_DEVS) |
	                 XHCI_SET_HCSP1_MAXINTR(1) |	/* interrupters */
	                 XHCI_SET_HCSP1_MAXSLOTS(XHCI_MAX_SLOTS);
	sc->hcsparams2 = XHCI_SET_HCSP2_ERSTMAX(XHCI_ERST_MAX) |
	                 XHCI_SET_HCSP2_IST(0x04);
	sc->hcsparams3 = 0;				/* no latency */
	sc->hccparams1 = XHCI_SET_HCCP1_AC64(1) |	/* 64-bit addrs */
	                 XHCI_SET_HCCP1_NSS(1) |	/* no 2nd-streams */
	                 XHCI_SET_HCCP1_SPC(1) |	/* short packet */
	                 XHCI_SET_HCCP1_MAXPSA(XHCI_STREAMS_MAX);
	sc->hccparams2 = XHCI_SET_HCCP2_LEC(1) |
	                 XHCI_SET_HCCP2_U3C(1);
	sc->dboff = XHCI_SET_DOORBELL(XHCI_CAPLEN + XHCI_PORTREGS_START +
	            XHCI_MAX_DEVS * sizeof(struct pci_xhci_portregs));

	/* dboff must be 32-bit aligned */
	if (sc->dboff & 0x3)
		sc->dboff = (sc->dboff + 0x3) & ~0x3;

	/* rtsoff must be 32-bytes aligned */
	sc->rtsoff = XHCI_SET_RTSOFFSET(sc->dboff + (XHCI_MAX_SLOTS+1) * 32);
	if (sc->rtsoff & 0x1F)
		sc->rtsoff = (sc->rtsoff + 0x1F) & ~0x1F;

	DPRINTF(("pci_xhci dboff: 0x%x, rtsoff: 0x%x", sc->dboff,
	        sc->rtsoff));

	sc->opregs.usbsts = XHCI_STS_HCH;
	sc->opregs.pgsz = XHCI_PAGESIZE_4K;

	pci_xhci_reset(sc);

	sc->regsend = sc->rtsoff + 0x20 + 32;		/* only 1 intrpter */

	/*
	 * Set extended capabilities pointer to be after regsend;
	 * value of xecp field is 32-bit offset.
	 */
	sc->hccparams1 |= XHCI_SET_HCCP1_XECP(sc->regsend/4);

	pci_set_cfgdata16(pi, PCIR_DEVICE, 0x1E31);
	pci_set_cfgdata16(pi, PCIR_VENDOR, 0x8086);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_SERIALBUS);
	pci_set_cfgdata8(pi, PCIR_SUBCLASS, PCIS_SERIALBUS_USB);
	pci_set_cfgdata8(pi, PCIR_PROGIF,PCIP_SERIALBUS_USB_XHCI);
	pci_set_cfgdata8(pi, PCI_USBREV, PCI_USB_REV_3_0);

	error = pci_emul_add_msicap(pi, 1);
	if (error != 0)
		goto done;

	/* regsend + xecp registers */
	pci_emul_alloc_bar(pi, 0, PCIBAR_MEM32, sc->regsend + 4*32);
	DPRINTF(("pci_xhci pci_emu_alloc: %d", sc->regsend + 4*32));


	pci_lintr_request(pi);

done:
	if (error) {
		xhci_in_use = 0;
		pi->pi_arg = NULL;
		(void)pci_xhci_free_devices(sc);
		pthread_mutex_destroy(&sc->mtx);
		free(sc);
	}

	return (error);
}

#ifdef BHYVE_SNAPSHOT
/*
 * Validation must observe the address encoded by the incoming record without
 * publishing it into the live controller.  The generic helper deliberately
 * leaves pointers untouched for VM_SNAPSHOT_VALIDATE, which is appropriate
 * for most callers but would make xHCI's pointer-presence relationships test
 * the destination's old state.  Decode through a private RESTORE cursor; the
 * caller either supplies temporary storage or restores its backed-up state.
 */
static int
pci_xhci_snapshot_guest_addr(struct vmctx *ctx, void **addrp, size_t len,
    bool restore_null, struct vm_snapshot_meta *meta)
{
	struct vm_snapshot_meta decode = {
		.dev_name = meta->dev_name,
		.dev_data = meta->dev_data,
		.dev_req = meta->dev_req,
		.buffer = {
			.buf_start = meta->buffer.buf_start,
			.buf_size = meta->buffer.buf_size,
			.buf = meta->buffer.buf,
			.buf_rem = meta->buffer.buf_rem,
		},
		.op = VM_SNAPSHOT_RESTORE,
	};
	int error;

	if (meta->op != VM_SNAPSHOT_VALIDATE)
		return (vm_snapshot_guest2host_addr(ctx, addrp, len, restore_null,
		    meta));
	error = vm_snapshot_guest2host_addr(ctx, addrp, len, restore_null,
	    &decode);
	meta->buffer.buf = decode.buffer.buf;
	meta->buffer.buf_rem = decode.buffer.buf_rem;
	return (error);
}

static bool
pci_xhci_guest_addr_matches(struct pci_xhci_softc *sc, const void *addr,
    uint64_t expected)
{
	vm_paddr_t actual;

	if (addr == NULL)
		return (expected == 0);
	actual = paddr_host2guest(sc->xsc_pi->pi_vmctx,
	    __DECONST(void *, addr));
	return (actual != (vm_paddr_t)-1 && (uint64_t)actual == expected);
}

static void
pci_xhci_map_devs_slots(struct pci_xhci_softc *sc, int maps[])
{
	int i, j;
	struct pci_xhci_dev_emu *dev, *slot;

	memset(maps, 0, sizeof(maps[0]) * (XHCI_MAX_SLOTS + 1));

	for (i = 1; i <= XHCI_MAX_SLOTS; i++) {
		for (j = 1; j <= XHCI_MAX_DEVS; j++) {
			slot = XHCI_SLOTDEV_PTR(sc, i);
			dev = XHCI_DEVINST_PTR(sc, j);

			if (slot != NULL && slot == dev)
				maps[i] = j;
		}
	}
}

static int
pci_xhci_snapshot_ep(struct pci_xhci_softc *sc, struct pci_xhci_dev_emu *dev,
    int idx, struct vm_snapshot_meta *meta)
{
	int active, k;
	int ret = 0;
	bool prepared_valid;
	size_t map_len;
	uint32_t nstreams;
	uint64_t hci_data_gpa, present, total_len;
	struct usb_data_xfer validation_xfer;
	struct usb_device_request validation_ureq;
	struct usb_data_xfer *xfer;
	struct usb_data_xfer_block *xfer_block;
	struct pci_xhci_dev_ep prepared;

	/* some sanity checks */
	present = 0;
	hci_data_gpa = 0;
	xfer = NULL;
	prepared_valid = false;
	memset(&prepared, 0, sizeof(prepared));
	if (meta->op == VM_SNAPSHOT_SAVE) {
		xfer = dev->eps[idx].ep_xfer;
		present = xfer != NULL;
	}

	SNAPSHOT_LE64_OR_LEAVE(present, meta, ret, done);
	if (present > 1) {
		ret = EINVAL;
		goto done;
	}
	if (present == 0) {
		if (meta->op == VM_SNAPSHOT_RESTORE)
			pci_xhci_free_ep(&dev->eps[idx]);
		ret = 0;
		goto done;
	}
	if (meta->op == VM_SNAPSHOT_SAVE)
		nstreams = dev->eps[idx].ep_NumStreams;
	SNAPSHOT_LE32_OR_LEAVE(nstreams, meta, ret, done);
	if (!pci_xhci_num_streams_valid(nstreams)) {
		ret = EINVAL;
		goto done;
	}

	if (meta->op == VM_SNAPSHOT_VALIDATE) {
		memset(&validation_xfer, 0, sizeof(validation_xfer));
		xfer = &validation_xfer;
	} else if (meta->op == VM_SNAPSHOT_RESTORE) {
		ret = pci_xhci_prepare_ep(sc, &dev->dev_ctx->ctx_ep[idx],
		    &prepared);
		if (ret != 0)
			goto done;
		prepared_valid = true;
		if (prepared.ep_NumStreams != nstreams) {
			ret = EINVAL;
			goto done;
		}
		xfer = prepared.ep_xfer;
	}
	if (xfer == NULL) {
		ret = EINVAL;
		goto done;
	}

	/* save / restore proper */
	for (k = 0; k < USB_MAX_XFER_BLOCKS; k++) {
		xfer_block = &xfer->data[k];

		SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(xfer_block->blen, meta, ret,
		    done);
		SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(xfer_block->bdone, meta, ret,
		    done);
		if (xfer_block->blen < 0 || xfer_block->bdone < 0) {
			ret = EINVAL;
			goto done;
		}
		total_len = (uint64_t)xfer_block->blen + xfer_block->bdone;
		if (total_len > 0x1ffff) {
			ret = EINVAL;
			goto done;
		}
		map_len = total_len == 0 ? 1 : (size_t)total_len;
		ret = pci_xhci_snapshot_guest_addr(sc->xsc_pi->pi_vmctx,
		    &xfer_block->buf, map_len, true, meta);
		if (ret != 0)
			goto done;
		SNAPSHOT_LE32_OR_LEAVE(xfer_block->processed, meta, ret, done);
		if ((xfer_block->processed & 0xffU) > 1 ||
		    (xfer_block->processed >> 8) > USB_SHORT) {
			ret = EINVAL;
			goto done;
		}
		if (meta->op == VM_SNAPSHOT_SAVE)
			hci_data_gpa = (uintptr_t)xfer_block->hci_data;
		SNAPSHOT_LE64_OR_LEAVE(hci_data_gpa, meta, ret, done);
		if (vm_snapshot_is_loading(meta)) {
			if (hci_data_gpa > UINTPTR_MAX) {
				ret = EOVERFLOW;
				goto done;
			}
			xfer_block->hci_data = (void *)(uintptr_t)hci_data_gpa;
		}
		SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(xfer_block->ccs, meta, ret,
		    done);
		SNAPSHOT_LE32_OR_LEAVE(xfer_block->streamid, meta, ret, done);
		SNAPSHOT_LE64_OR_LEAVE(xfer_block->trbnext, meta, ret, done);
		if (xfer_block->ccs < 0 || xfer_block->ccs > 1) {
			ret = EINVAL;
			goto done;
		}
	}

	if (meta->op == VM_SNAPSHOT_SAVE)
		present = xfer->ureq != NULL;
	SNAPSHOT_LE64_OR_LEAVE(present, meta, ret, done);
	if (present > 1) {
		ret = EINVAL;
		goto done;
	}
	if (present != 0) {
		/* xfer->ureq is not allocated at restore time */
		if (meta->op == VM_SNAPSHOT_VALIDATE) {
			xfer->ureq = &validation_ureq;
		} else if (meta->op == VM_SNAPSHOT_RESTORE) {
			xfer->ureq = malloc(sizeof(struct usb_device_request));
			if (xfer->ureq == NULL) {
				ret = ENOMEM;
				goto done;
			}
		}

		SNAPSHOT_BUF_OR_LEAVE(xfer->ureq,
				      sizeof(struct usb_device_request),
				      meta, ret, done);
	}

	SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(xfer->ndata, meta, ret, done);
	SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(xfer->head, meta, ret, done);
	SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(xfer->tail, meta, ret, done);
	if (xfer->ndata < 0 || xfer->ndata > USB_MAX_XFER_BLOCKS ||
	    xfer->head >= USB_MAX_XFER_BLOCKS ||
	    xfer->head < 0 || xfer->tail >= USB_MAX_XFER_BLOCKS ||
	    xfer->tail < 0 || xfer->tail !=
	    (xfer->head + xfer->ndata) % USB_MAX_XFER_BLOCKS) {
		ret = EINVAL;
		goto done;
	}
	active = xfer->head;
	for (k = 0; k < xfer->ndata; k++) {
		xfer_block = &xfer->data[active];
		if ((nstreams == 0 && xfer_block->streamid != 0) ||
		    (nstreams != 0 && (xfer_block->streamid == 0 ||
		    xfer_block->streamid >= nstreams))) {
			ret = EINVAL;
			goto done;
		}
		active = (active + 1) % USB_MAX_XFER_BLOCKS;
	}
	active = xfer->head;
	for (k = 0; k < xfer->ndata; k++) {
		xfer_block = &xfer->data[active];
		hci_data_gpa = (uintptr_t)xfer_block->hci_data;
		if ((hci_data_gpa & 0xFULL) != 0 ||
		    pci_xhci_map(sc, hci_data_gpa,
		    sizeof(struct xhci_trb)) == NULL ||
		    (xfer_block->trbnext & 0xFULL) != 0 ||
		    pci_xhci_map(sc, xfer_block->trbnext,
		    sizeof(struct xhci_trb)) == NULL) {
			ret = EINVAL;
			goto done;
		}
		active = (active + 1) % USB_MAX_XFER_BLOCKS;
	}

done:
	if (meta->op == VM_SNAPSHOT_RESTORE && prepared_valid) {
		if (ret == 0) {
			pci_xhci_free_ep(&dev->eps[idx]);
			dev->eps[idx] = prepared;
			prepared_valid = false;
		}
		if (prepared_valid)
			pci_xhci_free_ep(&prepared);
	}
	return (ret);
}

static int
pci_xhci_snapshot(struct vm_snapshot_meta *meta)
{
	int i, j;
	int ret = 0;
	int restore_idx;
	uint32_t magic, version;
	uint32_t event_count;
	uint64_t event_base, event_bytes, erstba, erdp;
	uint32_t device_mask, expected_device_mask;
	uint32_t expected_caplength, expected_hcsparams1, expected_hcsparams2;
	uint32_t expected_hcsparams3, expected_hccparams1, expected_hccparams2;
	uint32_t expected_dboff, expected_rtsoff, expected_regsend;
	uint32_t saved_caplength, saved_hcsparams1, saved_hcsparams2;
	uint32_t saved_hcsparams3, saved_hccparams1, saved_hccparams2;
	uint32_t saved_dboff, saved_rtsoff, saved_regsend;
	int saved_usb2_port_start, saved_usb3_port_start;
	int expected_usb2_port_start, expected_usb3_port_start;
	struct pci_devinst *pi;
	struct pci_xhci_softc *sc;
	struct pci_xhci_portregs *port;
	struct pci_xhci_opregs opregs_backup;
	struct pci_xhci_rtsregs rtsregs_backup;
	struct pci_xhci_portregs portregs_backup[XHCI_MAX_DEVS];
	struct pci_xhci_dev_emu *dev;
	struct usb_hci hci_backup[XHCI_MAX_DEVS];
	struct xhci_dev_ctx *dev_ctx_backup[XHCI_MAX_DEVS];
	int slotstate_backup[XHCI_MAX_DEVS];
	char dname[SNAP_DEV_NAME_LEN];
	int maps[XHCI_MAX_SLOTS + 1];
	int expected_maps[XHCI_MAX_SLOTS + 1];

	pi = meta->dev_data;
	sc = pi->pi_arg;
	pthread_mutex_lock(&sc->mtx);
	for (i = 1; i <= XHCI_MAX_DEVS; i++) {
		dev = XHCI_DEVINST_PTR(sc, i);
		if (dev != NULL)
			hci_backup[i - 1] = dev->hci;
		if (dev != NULL)
			dev_ctx_backup[i - 1] = dev->dev_ctx;
	}
	if (meta->op == VM_SNAPSHOT_VALIDATE) {
		opregs_backup = sc->opregs;
		rtsregs_backup = sc->rtsregs;
		memcpy(portregs_backup, sc->portregs, sizeof(portregs_backup));
		for (i = 1; i <= XHCI_MAX_DEVS; i++) {
			dev = XHCI_DEVINST_PTR(sc, i);
			if (dev != NULL) {
				slotstate_backup[i - 1] = dev->dev_slotstate;
			}
		}
	}
	expected_caplength = sc->caplength;
	expected_hcsparams1 = sc->hcsparams1;
	expected_hcsparams2 = sc->hcsparams2;
	expected_hcsparams3 = sc->hcsparams3;
	expected_hccparams1 = sc->hccparams1;
	expected_dboff = sc->dboff;
	expected_rtsoff = sc->rtsoff;
	expected_hccparams2 = sc->hccparams2;
	expected_regsend = sc->regsend;
	expected_usb2_port_start = sc->usb2_port_start;
	expected_usb3_port_start = sc->usb3_port_start;
	saved_caplength = expected_caplength;
	saved_hcsparams1 = expected_hcsparams1;
	saved_hcsparams2 = expected_hcsparams2;
	saved_hcsparams3 = expected_hcsparams3;
	saved_hccparams1 = expected_hccparams1;
	saved_dboff = expected_dboff;
	saved_rtsoff = expected_rtsoff;
	saved_hccparams2 = expected_hccparams2;
	saved_regsend = expected_regsend;
	saved_usb2_port_start = expected_usb2_port_start;
	saved_usb3_port_start = expected_usb3_port_start;
	expected_device_mask = 0;
	for (i = 1; i <= XHCI_MAX_DEVS; i++) {
		if (XHCI_DEVINST_PTR(sc, i) != NULL)
			expected_device_mask |= 1U << (i - 1);
	}
	device_mask = expected_device_mask;
	pci_xhci_map_devs_slots(sc, expected_maps);
	memset(maps, 0, sizeof(maps));
	event_count = 0;
	event_base = 0;
	magic = XHCI_SNAPSHOT_MAGIC;
	version = XHCI_SNAPSHOT_VERSION;

	SNAPSHOT_LE32_OR_LEAVE(magic, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(version, meta, ret, done);
	if (vm_snapshot_is_loading(meta) &&
	    (magic != XHCI_SNAPSHOT_MAGIC ||
	    version != XHCI_SNAPSHOT_VERSION)) {
		ret = ENOTSUP;
		goto done;
	}

	SNAPSHOT_LE32_OR_LEAVE(saved_caplength, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(saved_hcsparams1, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(saved_hcsparams2, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(saved_hcsparams3, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(saved_hccparams1, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(saved_dboff, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(saved_rtsoff, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(saved_hccparams2, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(saved_regsend, meta, ret, done);
	if (vm_snapshot_is_loading(meta) &&
	    (saved_caplength != expected_caplength ||
	    saved_hcsparams1 != expected_hcsparams1 ||
	    saved_hcsparams2 != expected_hcsparams2 ||
	    saved_hcsparams3 != expected_hcsparams3 ||
	    saved_hccparams1 != expected_hccparams1 ||
	    saved_dboff != expected_dboff ||
	    saved_rtsoff != expected_rtsoff ||
	    saved_hccparams2 != expected_hccparams2 ||
	    saved_regsend != expected_regsend)) {
		ret = EINVAL;
		goto done;
	}

	/* opregs */
	SNAPSHOT_LE32_OR_LEAVE(sc->opregs.usbcmd, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(sc->opregs.usbsts, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(sc->opregs.pgsz, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(sc->opregs.dnctrl, meta, ret, done);
	SNAPSHOT_LE64_OR_LEAVE(sc->opregs.crcr, meta, ret, done);
	SNAPSHOT_LE64_OR_LEAVE(sc->opregs.dcbaap, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(sc->opregs.config, meta, ret, done);

	/* opregs.cr_p */
	ret = pci_xhci_snapshot_guest_addr(pi->pi_vmctx,
	    (void **)&sc->opregs.cr_p, sizeof(*sc->opregs.cr_p), true, meta);
	if (ret != 0)
		goto done;

	/* opregs.dcbaa_p */
	ret = pci_xhci_snapshot_guest_addr(pi->pi_vmctx,
	    (void **)&sc->opregs.dcbaa_p, sizeof(*sc->opregs.dcbaa_p), true,
	    meta);
	if (ret != 0)
		goto done;
	if (vm_snapshot_is_loading(meta) &&
	    (sc->opregs.pgsz != XHCI_PAGESIZE_4K ||
	    (sc->opregs.usbcmd & ~0x3F0FU) != 0 ||
	    (sc->opregs.usbsts & ~(XHCI_STS_HCH | XHCI_STS_HSE |
	    XHCI_STS_EINT | XHCI_STS_PCD | XHCI_STS_SSS | XHCI_STS_RSS |
	    XHCI_STS_SRE | XHCI_STS_CNR | XHCI_STS_HCE)) != 0 ||
	    (sc->opregs.dnctrl & ~0xFFFFU) != 0 ||
	    (sc->opregs.config & ~0x3FFU) != 0 ||
	    (sc->opregs.config & XHCI_CONFIG_SLOTS_MASK) > XHCI_MAX_SLOTS ||
	    !pci_xhci_guest_addr_matches(sc, sc->opregs.cr_p,
	    sc->opregs.crcr & ~0xFULL) ||
	    !pci_xhci_guest_addr_matches(sc, sc->opregs.dcbaa_p,
	    sc->opregs.dcbaap & ~0x3FULL))) {
		ret = EINVAL;
		goto done;
	}

	/* rtsregs */
	SNAPSHOT_LE32_OR_LEAVE(sc->rtsregs.mfindex, meta, ret, done);

	/* rtsregs.intrreg */
	SNAPSHOT_LE32_OR_LEAVE(sc->rtsregs.intrreg.iman, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(sc->rtsregs.intrreg.imod, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(sc->rtsregs.intrreg.erstsz, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(sc->rtsregs.intrreg.rsvd, meta, ret, done);
	/* Do not form typed pointers to packed MMIO register members. */
	erstba = sc->rtsregs.intrreg.erstba;
	erdp = sc->rtsregs.intrreg.erdp;
	SNAPSHOT_LE64_OR_LEAVE(erstba, meta, ret, done);
	SNAPSHOT_LE64_OR_LEAVE(erdp, meta, ret, done);
	if (vm_snapshot_is_loading(meta)) {
		sc->rtsregs.intrreg.erstba = erstba;
		sc->rtsregs.intrreg.erdp = erdp;
	}

	/* rtsregs.erstba_p */
	ret = pci_xhci_snapshot_guest_addr(pi->pi_vmctx,
	    (void **)&sc->rtsregs.erstba_p,
	    sizeof(*sc->rtsregs.erstba_p), true, meta);
	if (ret != 0)
		goto done;

	/* rtsregs.erst_p */
	ret = pci_xhci_snapshot_guest_addr(pi->pi_vmctx,
	    (void **)&sc->rtsregs.erst_p, sizeof(*sc->rtsregs.erst_p), true,
	    meta);
	if (ret != 0)
		goto done;
	/*
	 * The ERST entry lives in guest memory.  The first restore preflight
	 * deliberately runs before checkpoint RAM is published, so it must not
	 * derive the event-ring geometry from the destination's stale ERST.
	 * Carry the immutable geometry in the device record and compare it with
	 * the restored ERST only during the committing restore pass.
	 */
	if (meta->op == VM_SNAPSHOT_SAVE && sc->rtsregs.erstba_p != NULL) {
		event_count = sc->rtsregs.erstba_p->dwEvrsTableSize;
		event_base = sc->rtsregs.erstba_p->qwEvrsTablePtr;
	}
	SNAPSHOT_LE32_OR_LEAVE(event_count, meta, ret, done);
	SNAPSHOT_LE64_OR_LEAVE(event_base, meta, ret, done);
	if (vm_snapshot_is_loading(meta) &&
	    ((sc->rtsregs.mfindex & ~0x3FFFU) != 0 ||
	    (sc->rtsregs.intrreg.iman &
	    ~(XHCI_IMAN_INTR_PEND | XHCI_IMAN_INTR_ENA)) != 0 ||
	    sc->rtsregs.intrreg.erstsz > 1 ||
	    sc->rtsregs.intrreg.rsvd != 0 ||
	    !pci_xhci_guest_addr_matches(sc, sc->rtsregs.erstba_p,
	    sc->rtsregs.intrreg.erstba & ~0x3FULL))) {
		ret = EINVAL;
		goto done;
	}
	if (vm_snapshot_is_loading(meta)) {
		if ((sc->rtsregs.erstba_p == NULL) !=
		    (sc->rtsregs.erst_p == NULL) ||
		    (sc->rtsregs.erstba_p == NULL &&
		    (event_count != 0 || event_base != 0)) ||
		    (sc->rtsregs.erstba_p != NULL &&
		    (sc->rtsregs.intrreg.erstsz != 1 || event_count == 0 ||
		    event_count > XHCI_EVENT_RING_SEGMENT_MAX ||
		    (event_base & 0x3FULL) != 0))) {
			ret = EINVAL;
			goto done;
		}
		if (event_count != 0) {
			event_bytes = (uint64_t)event_count *
			    sizeof(struct xhci_trb);
			if (event_base > UINT64_MAX - event_bytes ||
			    !pci_xhci_guest_addr_matches(sc,
			    sc->rtsregs.erst_p, event_base) ||
			    pci_xhci_map(sc, event_base,
			    (size_t)event_bytes) == NULL) {
				ret = EINVAL;
				goto done;
			}
		}
	}
	if (meta->op == VM_SNAPSHOT_RESTORE) {
		if (sc->opregs.cr_p != NULL) {
			sc->opregs.cr_p = pci_xhci_map(sc,
			    sc->opregs.crcr & ~0xFUL, sizeof(*sc->opregs.cr_p));
			if (sc->opregs.cr_p == NULL) {
				ret = EINVAL;
				goto done;
			}
		}
		if (sc->opregs.dcbaa_p != NULL) {
			sc->opregs.dcbaa_p = pci_xhci_map(sc,
			    sc->opregs.dcbaap & ~0x3FUL,
			    sizeof(*sc->opregs.dcbaa_p));
			if (sc->opregs.dcbaa_p == NULL) {
				ret = EINVAL;
				goto done;
			}
		}
		if (sc->rtsregs.erstba_p != NULL) {
			sc->rtsregs.erstba_p = pci_xhci_map(sc,
			    sc->rtsregs.intrreg.erstba & ~0x3FUL,
			    sizeof(*sc->rtsregs.erstba_p));
			if (sc->rtsregs.erstba_p == NULL ||
			    sc->rtsregs.erstba_p->dwEvrsTableSize != event_count ||
			    sc->rtsregs.erstba_p->qwEvrsTablePtr != event_base) {
				ret = EINVAL;
				goto done;
			}
			event_bytes = (uint64_t)event_count *
			    sizeof(struct xhci_trb);
			sc->rtsregs.erst_p = pci_xhci_map_write(sc, event_base,
			    (size_t)event_bytes);
			if (sc->rtsregs.erst_p == NULL) {
				ret = EINVAL;
				goto done;
			}
		} else if (sc->rtsregs.erst_p != NULL) {
			ret = EINVAL;
			goto done;
		}
	}

	SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(sc->rtsregs.er_deq_seg, meta, ret,
	    done);
	SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(sc->rtsregs.er_enq_idx, meta, ret,
	    done);
	SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(sc->rtsregs.er_enq_seg, meta, ret,
	    done);
	SNAPSHOT_LE32_OR_LEAVE(sc->rtsregs.er_events_cnt, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(sc->rtsregs.event_pcs, meta, ret, done);
	if (vm_snapshot_is_loading(meta) &&
	    (sc->rtsregs.er_deq_seg != 0 || sc->rtsregs.er_enq_seg != 0 ||
	    sc->rtsregs.event_pcs > 1 || sc->rtsregs.er_enq_idx < 0 ||
	    ((sc->rtsregs.erstba_p == NULL) !=
	    (sc->rtsregs.erst_p == NULL)) ||
	    (sc->rtsregs.erstba_p == NULL &&
	    (sc->rtsregs.er_enq_idx != 0 ||
	    sc->rtsregs.er_events_cnt != 0)) ||
	    (sc->rtsregs.erstba_p != NULL &&
	    ((uint32_t)sc->rtsregs.er_enq_idx >=
	    event_count || sc->rtsregs.er_events_cnt > event_count)))) {
		ret = EINVAL;
		goto done;
	}
	SNAPSHOT_LE32_OR_LEAVE(device_mask, meta, ret, done);
	if (vm_snapshot_is_loading(meta) &&
	    device_mask != expected_device_mask) {
		ret = EINVAL;
		goto done;
	}

	/* sanity checking */
	for (i = 1; i <= XHCI_MAX_DEVS; i++) {
		dev = XHCI_DEVINST_PTR(sc, i);
		if (dev == NULL)
			continue;

		if (meta->op == VM_SNAPSHOT_SAVE)
			restore_idx = i;
		SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(restore_idx, meta, ret, done);

		/* check if the restored device (when restoring) is sane */
		if (restore_idx != i) {
			EPRINTLN("%s: idx not matching: actual: %d, "
			    "expected: %d", __func__, restore_idx, i);
			ret = EINVAL;
			goto done;
		}

		if (meta->op == VM_SNAPSHOT_SAVE) {
			memset(dname, 0, sizeof(dname));
			strncpy(dname, dev->dev_ue->ue_emu, sizeof(dname) - 1);
		}

		SNAPSHOT_BUF_OR_LEAVE(dname, sizeof(dname), meta, ret, done);

		if (vm_snapshot_is_loading(meta)) {
			dname[sizeof(dname) - 1] = '\0';
			if (strcmp(dev->dev_ue->ue_emu, dname)) {
				EPRINTLN("%s: device names mismatch: "
				    "actual: %s, expected: %s",
				    __func__, dname, dev->dev_ue->ue_emu);

				ret = EINVAL;
				goto done;
			}
		}
	}

	/* portregs */
	for (i = 1; i <= XHCI_MAX_DEVS; i++) {
		port = XHCI_PORTREG_PTR(sc, i);
		dev = XHCI_DEVINST_PTR(sc, i);

		if (dev == NULL)
			continue;

		uint32_t portsc = port->portsc;
		uint32_t portpmsc = port->portpmsc;
		uint32_t portli = port->portli;
		uint32_t porthlpmc = port->porthlpmc;

		SNAPSHOT_LE32_OR_LEAVE(portsc, meta, ret, done);
		SNAPSHOT_LE32_OR_LEAVE(portpmsc, meta, ret, done);
		SNAPSHOT_LE32_OR_LEAVE(portli, meta, ret, done);
		SNAPSHOT_LE32_OR_LEAVE(porthlpmc, meta, ret, done);
		if (vm_snapshot_is_loading(meta)) {
			port->portsc = portsc;
			port->portpmsc = portpmsc;
			port->portli = portli;
			port->porthlpmc = porthlpmc;
		}
	}

	/* slots */
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(maps, expected_maps, sizeof(maps));

	for (i = 1; i <= XHCI_MAX_SLOTS; i++) {
		SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(maps[i], meta, ret, done);

		if (meta->op == VM_SNAPSHOT_SAVE) {
			dev = XHCI_SLOTDEV_PTR(sc, i);
		} else if (vm_snapshot_is_loading(meta)) {
			if (maps[i] < 0 || maps[i] > XHCI_MAX_DEVS) {
				ret = EINVAL;
				goto done;
			}
			if (maps[i] != expected_maps[i]) {
				ret = EINVAL;
				goto done;
			}
			dev = XHCI_SLOTDEV_PTR(sc, i);
		} else {
			/* error */
			ret = EINVAL;
			goto done;
		}

		if (dev == NULL)
			continue;

		struct xhci_dev_ctx *saved_dev_ctx;

		saved_dev_ctx = NULL;
		ret = pci_xhci_snapshot_guest_addr(pi->pi_vmctx,
		    (void **)&dev->dev_ctx, sizeof(*dev->dev_ctx), true, meta);
		if (ret != 0)
			goto done;
		if (meta->op == VM_SNAPSHOT_RESTORE && dev->dev_ctx != NULL) {
			saved_dev_ctx = dev->dev_ctx;
			dev->dev_ctx = pci_xhci_get_dev_ctx(sc, i);
			if (dev->dev_ctx == NULL || dev->dev_ctx != saved_dev_ctx) {
				ret = EINVAL;
				goto done;
			}
		}
		if (meta->op == VM_SNAPSHOT_RESTORE && dev->dev_ctx == NULL) {
			for (j = 1; j < XHCI_MAX_ENDPOINTS; j++)
				pci_xhci_free_ep(&dev->eps[j]);
		}

		if (dev->dev_ctx != NULL) {
			for (j = 1; j < XHCI_MAX_ENDPOINTS; j++) {
				ret = pci_xhci_snapshot_ep(sc, dev, j, meta);
				if (ret != 0)
					goto done;
			}
		}

		SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(dev->dev_slotstate, meta, ret,
		    done);
		if (vm_snapshot_is_loading(meta) &&
		    (dev->dev_slotstate < XHCI_ST_DISABLED ||
		    dev->dev_slotstate > XHCI_ST_CONFIGURED ||
		    (dev->dev_slotstate >= XHCI_ST_DEFAULT &&
		    dev->dev_ctx == NULL) ||
		    (dev->dev_slotstate == XHCI_ST_DISABLED &&
		    dev->dev_ctx != NULL))) {
			ret = EINVAL;
			goto done;
		}

		/* devices[i]->dev_sc */
		if (dev->dev_ue->ue_snapshot == NULL) {
			ret = EOPNOTSUPP;
			goto done;
		}
		ret = dev->dev_ue->ue_snapshot(dev->dev_sc, meta);
		if (ret != 0)
			goto done;

		/* devices[i]->hci */
		SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(dev->hci.hci_address, meta,
		    ret, done);
		SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(dev->hci.hci_port, meta, ret,
		    done);
		SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(dev->hci.hci_speed, meta, ret,
		    done);
		SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(dev->hci.hci_usbver, meta, ret,
		    done);
		if (vm_snapshot_is_loading(meta) &&
		    (dev->hci.hci_port != hci_backup[i - 1].hci_port ||
		    dev->hci.hci_speed != hci_backup[i - 1].hci_speed ||
		    dev->hci.hci_usbver != hci_backup[i - 1].hci_usbver ||
		    dev->hci.hci_address < 0 ||
		    dev->hci.hci_address > XHCI_MAX_SLOTS ||
		    (dev->dev_slotstate < XHCI_ST_ADDRESSED &&
		    dev->hci.hci_address != 0))) {
			ret = EINVAL;
			goto done;
		}
	}

	SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(saved_usb2_port_start, meta, ret,
	    done);
	SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(saved_usb3_port_start, meta, ret,
	    done);
	if (vm_snapshot_is_loading(meta) &&
	    (saved_usb2_port_start != expected_usb2_port_start ||
	    saved_usb3_port_start != expected_usb3_port_start)) {
		ret = EINVAL;
		goto done;
	}

done:
	if (meta->op == VM_SNAPSHOT_VALIDATE) {
		sc->opregs = opregs_backup;
		sc->rtsregs = rtsregs_backup;
		memcpy(sc->portregs, portregs_backup, sizeof(portregs_backup));
		for (i = 1; i <= XHCI_MAX_DEVS; i++) {
			dev = XHCI_DEVINST_PTR(sc, i);
			if (dev != NULL) {
				dev->dev_slotstate = slotstate_backup[i - 1];
				dev->hci = hci_backup[i - 1];
				dev->dev_ctx = dev_ctx_backup[i - 1];
			}
		}
	}
	pthread_mutex_unlock(&sc->mtx);
	return (ret);
}

/*
 * Quiesce ownership fence for in-flight USB work.  Every guest-memory
 * mutation by this device happens under sc->mtx: vCPU BAR accesses are
 * stopped before device pause, and asynchronous backend completions enter
 * through pci_xhci_dev_intr(), which takes the mutex and honors
 * sc->snapshot_paused.  Draining therefore reduces to acquiring the mutex
 * once and publishing the fence.  Acquire it against a bounded monotonic
 * deadline so a wedged worker fails the pause (and the checkpoint) instead
 * of hanging it; on timeout nothing has been fenced and the device remains
 * fully usable.
 */
#define	PCI_XHCI_DRAIN_TIMEOUT_NS	2000000000ULL	/* 2 s */
#define	PCI_XHCI_DRAIN_POLL_NS		200000L		/* 200 us */

static int
pci_xhci_pause(struct pci_devinst *pi)
{
	struct pci_xhci_softc *sc;
	struct timespec deadline, now, poll;
	int error;

	sc = pi->pi_arg;
	if (sc == NULL || sc->snapshot_paused)
		return (EINVAL);
	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return (errno != 0 ? errno : EINVAL);
	deadline = pci_xhci_drain_deadline(now, PCI_XHCI_DRAIN_TIMEOUT_NS);
	for (;;) {
		error = pthread_mutex_trylock(&sc->mtx);
		if (error == 0)
			break;
		if (error != EBUSY)
			return (error);
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			return (errno != 0 ? errno : EINVAL);
		if (pci_xhci_drain_deadline_expired(now, deadline))
			return (ETIMEDOUT);
		poll.tv_sec = 0;
		poll.tv_nsec = PCI_XHCI_DRAIN_POLL_NS;
		(void)nanosleep(&poll, NULL);
	}
	sc->snapshot_paused = true;
	pthread_mutex_unlock(&sc->mtx);
	return (0);
}

static int
pci_xhci_resume(struct pci_devinst *pi)
{
	struct pci_xhci_softc *sc;

	sc = pi->pi_arg;
	if (sc == NULL || !sc->snapshot_paused)
		return (EINVAL);
	pthread_mutex_lock(&sc->mtx);
	sc->snapshot_paused = false;
	pthread_mutex_unlock(&sc->mtx);
	return (0);
}
#endif

static const struct pci_devemu pci_de_xhci = {
	.pe_emu =	"xhci",
	.pe_init =	pci_xhci_init,
	.pe_legacy_config = pci_xhci_legacy_config,
	.pe_barwrite =	pci_xhci_write,
	.pe_barread =	pci_xhci_read,
#ifdef BHYVE_SNAPSHOT
	.pe_snapshot =	pci_xhci_snapshot,
	.pe_snapshot_validate = pci_xhci_snapshot,
	.pe_pause =	pci_xhci_pause,
	.pe_resume =	pci_xhci_resume,
	.pe_migration_flags = PCI_MIGRATION_F_STATE_CODEC |
	    PCI_MIGRATION_F_COMPAT_FIXED | PCI_MIGRATION_F_DMA_TRACKED |
	    PCI_MIGRATION_F_QUIESCE_CALLBACK,
#endif
};
PCI_EMUL_SET(pci_de_xhci);
