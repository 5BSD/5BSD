/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2016 Alex Teaca <iateaca@FreeBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
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
 *
 */

#include <sys/param.h>
#include <sys/endian.h>
#ifdef BHYVE_SNAPSHOT
#include <machine/vmm_snapshot.h>
#endif
#include <pthread.h>
#include <stdbool.h>
#include <time.h>

#include "pci_hda.h"
#include "pci_hda_model.h"
#include "bhyverun.h"
#include "config.h"
#include "pci_emul.h"
#include "hdac_reg.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif

/*
 * HDA defines
 */
#define PCIR_HDCTL		0x40
#define INTEL_VENDORID		0x8086
#define HDA_INTEL_82801G	0x27d8

#define HDA_IOSS_NO		0x08
#define HDA_OSS_NO		0x04
#define HDA_ISS_NO		0x04
#define HDA_CODEC_MAX		0x0f
#define HDA_LAST_OFFSET						\
	(0x2084 + ((HDA_ISS_NO) * 0x20) + ((HDA_OSS_NO) * 0x20))
#define HDA_CORB_ENTRY_LEN	0x04
#define HDA_RIRB_ENTRY_LEN	0x08
#define HDA_BDL_ENTRY_LEN	0x10
#define HDA_DMA_PIB_ENTRY_LEN	0x08
#define HDA_STREAM_TAGS_CNT	0x10
#define HDA_STREAM_REGS_BASE	0x80
#define HDA_STREAM_REGS_LEN	0x20

#define HDA_DMA_ACCESS_LEN	(sizeof(uint32_t))
#define HDA_BDL_MAX_LEN		0x0100

#define HDAC_SDSTS_FIFORDY	(1 << 5)

#define HDA_RIRBSTS_IRQ_MASK	(HDAC_RIRBSTS_RINTFL | HDAC_RIRBSTS_RIRBOIS)
#define HDA_STATESTS_IRQ_MASK	((1 << HDA_CODEC_MAX) - 1)
#define HDA_SDSTS_IRQ_MASK					\
	(HDAC_SDSTS_DESE | HDAC_SDSTS_FIFOE | HDAC_SDSTS_BCIS)

/* The portable checkpoint record model must describe this exact geometry. */
static_assert(HDA_ISS_NO == HDA_SNAPSHOT_ISS_NO, "HDA geometry drift");
static_assert(HDA_OSS_NO == HDA_SNAPSHOT_OSS_NO, "HDA geometry drift");
static_assert(HDA_IOSS_NO == HDA_SNAPSHOT_IOSS_NO, "HDA geometry drift");
static_assert(HDA_STREAM_TAGS_CNT == HDA_SNAPSHOT_STREAM_TAGS_CNT,
    "HDA geometry drift");
static_assert(HDA_BDL_MAX_LEN == HDA_SNAPSHOT_BDL_MAX_LEN,
    "HDA geometry drift");
static_assert(HDA_DMA_ACCESS_LEN == HDA_SNAPSHOT_DMA_ACCESS_LEN,
    "HDA geometry drift");

/*
 * HDA data structures
 */

struct hda_softc;

typedef void (*hda_set_reg_handler)(struct hda_softc *sc, uint32_t offset,
		uint32_t old);

struct hda_bdle {
	uint32_t addrl;
	uint32_t addrh;
	uint32_t len;
	uint32_t ioc;
} __packed;

struct hda_bdle_desc {
	void *addr;
	uint8_t ioc;
	uint32_t len;
};

struct hda_codec_cmd_ctl {
	const char *name;
	void *dma_vaddr;
	uint8_t run;
	uint16_t rp;
	uint16_t size;
	uint16_t wp;
};

struct hda_stream_desc {
	uint8_t dir;
	uint8_t run;
	uint8_t stream;

	/* bp is the no. of bytes transferred in the current bdle */
	uint32_t bp;
	/* be is the no. of bdles transferred in the bdl */
	uint32_t be;

	uint32_t bdl_cnt;
	uint32_t cbl;
	struct hda_bdle_desc bdl[HDA_BDL_MAX_LEN];
};

struct hda_softc {
	struct pci_devinst *pci_dev;
	pthread_mutex_t mtx;
	uint32_t regs[HDA_LAST_OFFSET];

	uint8_t lintr;
	uint16_t rirb_cnt;
	uint64_t wall_clock_start;

	struct hda_codec_cmd_ctl corb;
	struct hda_codec_cmd_ctl rirb;

	uint8_t codecs_no;
	struct hda_codec_inst *codecs[HDA_CODEC_MAX];

	/* Base Address of the DMA Position Buffer */
	void *dma_pib_vaddr;

	struct hda_stream_desc streams[HDA_IOSS_NO];
	/* 2 tables for output and input */
	uint8_t stream_map[2][HDA_STREAM_TAGS_CNT];

#ifdef BHYVE_SNAPSHOT
	/* Set while checkpoint pause ownership retains sc->mtx. */
	bool snapshot_paused;
#endif
};

/*
 * HDA module function declarations
 */
static inline void hda_set_reg_by_offset(struct hda_softc *sc, uint32_t offset,
    uint32_t value);
static inline uint32_t hda_get_reg_by_offset(struct hda_softc *sc,
    uint32_t offset);
static inline void hda_set_field_by_offset(struct hda_softc *sc,
    uint32_t offset, uint32_t mask, uint32_t value);

static struct hda_softc *hda_init(nvlist_t *nvl);
static void hda_update_intr(struct hda_softc *sc);
static void hda_response_interrupt(struct hda_softc *sc);
static int hda_codec_constructor(struct hda_softc *sc,
    struct hda_codec_class *codec, const char *play, const char *rec);
static struct hda_codec_class *hda_find_codec_class(const char *name);

static int hda_send_command(struct hda_softc *sc, uint32_t verb);
static int hda_notify_codecs(struct hda_softc *sc, uint8_t run,
    uint8_t stream, uint8_t dir);
static void hda_reset(struct hda_softc *sc);
static void hda_reset_regs(struct hda_softc *sc);
static void hda_stream_reset(struct hda_softc *sc, uint8_t stream_ind);
static int hda_stream_start(struct hda_softc *sc, uint8_t stream_ind);
static int hda_stream_stop(struct hda_softc *sc, uint8_t stream_ind);
static uint32_t hda_read(struct hda_softc *sc, uint32_t offset);
static int hda_write(struct hda_softc *sc, uint32_t offset, uint8_t size,
    uint32_t value);

static inline void hda_print_cmd_ctl_data(struct hda_codec_cmd_ctl *p);
static int hda_corb_start(struct hda_softc *sc);
static int hda_corb_run(struct hda_softc *sc);
static int hda_rirb_start(struct hda_softc *sc);

static void *hda_dma_get_vaddr(struct hda_softc *sc, uint64_t dma_paddr,
    size_t len, enum pci_dma_direction direction);
static void hda_dma_st_dword(void *dma_vaddr, uint32_t data);
static uint32_t hda_dma_ld_dword(void *dma_vaddr);

static inline uint8_t hda_get_stream_by_offsets(uint32_t offset,
    uint8_t reg_offset);
static inline uint32_t hda_get_offset_stream(uint8_t stream_ind);

static void hda_set_gctl(struct hda_softc *sc, uint32_t offset, uint32_t old);
static void hda_set_statests(struct hda_softc *sc, uint32_t offset,
    uint32_t old);
static void hda_set_corbwp(struct hda_softc *sc, uint32_t offset, uint32_t old);
static void hda_set_corbrp(struct hda_softc *sc, uint32_t offset, uint32_t old);
static void hda_set_corbctl(struct hda_softc *sc, uint32_t offset,
    uint32_t old);
static void hda_set_rirbctl(struct hda_softc *sc, uint32_t offset,
    uint32_t old);
static void hda_set_rirbwp(struct hda_softc *sc, uint32_t offset, uint32_t old);
static void hda_set_rirbsts(struct hda_softc *sc, uint32_t offset,
    uint32_t old);
static void hda_set_dpiblbase(struct hda_softc *sc, uint32_t offset,
    uint32_t old);
static void hda_set_sdctl(struct hda_softc *sc, uint32_t offset, uint32_t old);
static void hda_set_sdctl2(struct hda_softc *sc, uint32_t offset, uint32_t old);
static void hda_set_sdsts(struct hda_softc *sc, uint32_t offset, uint32_t old);

static int hda_signal_state_change(struct hda_codec_inst *hci);
static int hda_response(struct hda_codec_inst *hci, uint32_t response,
    uint8_t unsol);
static int hda_transfer(struct hda_codec_inst *hci, uint8_t stream,
    uint8_t dir, uint8_t *buf, size_t count);

static void hda_set_pib(struct hda_softc *sc, uint8_t stream_ind, uint32_t pib);
static uint64_t hda_get_clock_ns(void);

/*
 * PCI HDA function declarations
 */
static int pci_hda_init(struct pci_devinst *pi, nvlist_t *nvl);
static void pci_hda_write(struct pci_devinst *pi, int baridx, uint64_t offset,
    int size, uint64_t value);
static uint64_t pci_hda_read(struct pci_devinst *pi, int baridx,
    uint64_t offset, int size);
#ifdef BHYVE_SNAPSHOT
static int pci_hda_snapshot(struct vm_snapshot_meta *meta);
static int pci_hda_pause(struct pci_devinst *pi);
static int pci_hda_resume(struct pci_devinst *pi);
#endif
/*
 * HDA global data
 */

static const hda_set_reg_handler hda_set_reg_table[] = {
	[HDAC_GCTL] = hda_set_gctl,
	[HDAC_STATESTS] = hda_set_statests,
	[HDAC_CORBWP] = hda_set_corbwp,
	[HDAC_CORBRP] = hda_set_corbrp,
	[HDAC_CORBCTL] = hda_set_corbctl,
	[HDAC_RIRBWP] = hda_set_rirbwp,
	[HDAC_RIRBCTL] = hda_set_rirbctl,
	[HDAC_RIRBSTS] = hda_set_rirbsts,
	[HDAC_DPIBLBASE] = hda_set_dpiblbase,

#define HDAC_ISTREAM(n, iss, oss)				\
	[_HDAC_ISDCTL(n, iss, oss)] = hda_set_sdctl,		\
	[_HDAC_ISDCTL(n, iss, oss) + 2] = hda_set_sdctl2,	\
	[_HDAC_ISDSTS(n, iss, oss)] = hda_set_sdsts,		\

#define HDAC_OSTREAM(n, iss, oss)				\
	[_HDAC_OSDCTL(n, iss, oss)] = hda_set_sdctl,		\
	[_HDAC_OSDCTL(n, iss, oss) + 2] = hda_set_sdctl2,	\
	[_HDAC_OSDSTS(n, iss, oss)] = hda_set_sdsts,		\

	HDAC_ISTREAM(0, HDA_ISS_NO, HDA_OSS_NO)
	HDAC_ISTREAM(1, HDA_ISS_NO, HDA_OSS_NO)
	HDAC_ISTREAM(2, HDA_ISS_NO, HDA_OSS_NO)
	HDAC_ISTREAM(3, HDA_ISS_NO, HDA_OSS_NO)

	HDAC_OSTREAM(0, HDA_ISS_NO, HDA_OSS_NO)
	HDAC_OSTREAM(1, HDA_ISS_NO, HDA_OSS_NO)
	HDAC_OSTREAM(2, HDA_ISS_NO, HDA_OSS_NO)
	HDAC_OSTREAM(3, HDA_ISS_NO, HDA_OSS_NO)
};

static const uint16_t hda_corb_sizes[] = {
	[HDAC_CORBSIZE_CORBSIZE_2]	= 2,
	[HDAC_CORBSIZE_CORBSIZE_16]	= 16,
	[HDAC_CORBSIZE_CORBSIZE_256]	= 256,
	[HDAC_CORBSIZE_CORBSIZE_MASK]	= 0,
};

static const uint16_t hda_rirb_sizes[] = {
	[HDAC_RIRBSIZE_RIRBSIZE_2]	= 2,
	[HDAC_RIRBSIZE_RIRBSIZE_16]	= 16,
	[HDAC_RIRBSIZE_RIRBSIZE_256]	= 256,
	[HDAC_RIRBSIZE_RIRBSIZE_MASK]	= 0,
};

static const struct hda_ops hops = {
	.signal		= hda_signal_state_change,
	.response	= hda_response,
	.transfer	= hda_transfer,
};

static const struct pci_devemu pci_de_hda = {
	.pe_emu		= "hda",
	.pe_init	= pci_hda_init,
	.pe_barwrite	= pci_hda_write,
	.pe_barread	= pci_hda_read,
#ifdef BHYVE_SNAPSHOT
	.pe_snapshot	= pci_hda_snapshot,
	.pe_snapshot_validate = pci_hda_snapshot,
	.pe_pause	= pci_hda_pause,
	.pe_resume	= pci_hda_resume,
	.pe_migration_flags = PCI_MIGRATION_F_STATE_CODEC |
	    PCI_MIGRATION_F_COMPAT_FIXED | PCI_MIGRATION_F_DMA_TRACKED |
	    PCI_MIGRATION_F_QUIESCE_CALLBACK,
#endif
};
PCI_EMUL_SET(pci_de_hda);

SET_DECLARE(hda_codec_class_set, struct hda_codec_class);

#if DEBUG_HDA == 1
FILE *dbg;
#endif

/*
 * HDA module function definitions
 */

static inline void
hda_set_reg_by_offset(struct hda_softc *sc, uint32_t offset, uint32_t value)
{
	assert(offset < HDA_LAST_OFFSET);
	sc->regs[offset] = value;
}

static inline uint32_t
hda_get_reg_by_offset(struct hda_softc *sc, uint32_t offset)
{
	assert(offset < HDA_LAST_OFFSET);
	return sc->regs[offset];
}

static inline void
hda_set_field_by_offset(struct hda_softc *sc, uint32_t offset,
    uint32_t mask, uint32_t value)
{
	uint32_t reg_value = 0;

	reg_value = hda_get_reg_by_offset(sc, offset);

	reg_value &= ~mask;
	reg_value |= (value & mask);

	hda_set_reg_by_offset(sc, offset, reg_value);
}

static struct hda_softc *
hda_init(nvlist_t *nvl)
{
	struct hda_softc *sc = NULL;
	struct hda_codec_class *codec = NULL;
	const char *value;
	char *play;
	char *rec;
	int err;
	pthread_mutexattr_t attr;

#if DEBUG_HDA == 1
	dbg = fopen(DEBUG_HDA_FILE, "w+");
#endif

	sc = calloc(1, sizeof(*sc));
	if (!sc)
		return (NULL);
	err = pthread_mutexattr_init(&attr);
	if (err != 0) {
		free(sc);
		return (NULL);
	}
	err = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	if (err == 0)
		err = pthread_mutex_init(&sc->mtx, &attr);
	pthread_mutexattr_destroy(&attr);
	if (err != 0) {
		free(sc);
		return (NULL);
	}

	hda_reset_regs(sc);

	/*
	 * TODO search all configured codecs
	 * For now we play with one single codec
	 */
	codec = hda_find_codec_class("hda_codec");
	if (codec) {
		value = get_config_value_node(nvl, "play");
		if (value == NULL)
			play = NULL;
		else if ((play = strdup(value)) == NULL) {
			pthread_mutex_destroy(&sc->mtx);
			free(sc);
			return (NULL);
		} else
			;
		value = get_config_value_node(nvl, "rec");
		if (value == NULL)
			rec = NULL;
		else if ((rec = strdup(value)) == NULL) {
			free(play);
			pthread_mutex_destroy(&sc->mtx);
			free(sc);
			return (NULL);
		} else
			;
		DPRINTF("play: %s rec: %s", play != NULL ? play : "(none)",
		    rec != NULL ? rec : "(none)");
		if (play != NULL || rec != NULL) {
			err = hda_codec_constructor(sc, codec, play, rec);
			if (err != 0) {
				free(play);
				free(rec);
				pthread_mutex_destroy(&sc->mtx);
				free(sc);
				return (NULL);
			}
		}
		free(play);
		free(rec);
	}

	return (sc);
}

static void
hda_update_intr(struct hda_softc *sc)
{
	struct pci_devinst *pi = sc->pci_dev;
	uint32_t intctl = hda_get_reg_by_offset(sc, HDAC_INTCTL);
	uint32_t intsts = 0;
	uint32_t sdsts = 0;
	uint32_t rirbsts = 0;
	uint32_t wakeen = 0;
	uint32_t statests = 0;
	uint32_t off = 0;
	int i;

	/* update the CIS bits */
	rirbsts = hda_get_reg_by_offset(sc, HDAC_RIRBSTS);
	if (rirbsts & (HDAC_RIRBSTS_RINTFL | HDAC_RIRBSTS_RIRBOIS))
		intsts |= HDAC_INTSTS_CIS;

	wakeen = hda_get_reg_by_offset(sc, HDAC_WAKEEN);
	statests = hda_get_reg_by_offset(sc, HDAC_STATESTS);
	if (statests & wakeen)
		intsts |= HDAC_INTSTS_CIS;

	/* update the SIS bits */
	for (i = 0; i < HDA_IOSS_NO; i++) {
		off = hda_get_offset_stream(i);
		sdsts = hda_get_reg_by_offset(sc, off + HDAC_SDSTS);
		if (sdsts & HDAC_SDSTS_BCIS)
			intsts |= (1 << i);
	}

	/* update the GIS bit */
	if (intsts)
		intsts |= HDAC_INTSTS_GIS;

	hda_set_reg_by_offset(sc, HDAC_INTSTS, intsts);

	if ((intctl & HDAC_INTCTL_GIE) && ((intsts &			\
		~HDAC_INTSTS_GIS) & intctl)) {
		if (!sc->lintr) {
			pci_lintr_assert(pi);
			sc->lintr = 1;
		}
	} else {
		if (sc->lintr) {
			pci_lintr_deassert(pi);
			sc->lintr = 0;
		}
	}
}

static void
hda_response_interrupt(struct hda_softc *sc)
{
	uint8_t rirbctl = hda_get_reg_by_offset(sc, HDAC_RIRBCTL);

	if ((rirbctl & HDAC_RIRBCTL_RINTCTL) && sc->rirb_cnt != 0) {
		sc->rirb_cnt = 0;
		hda_set_field_by_offset(sc, HDAC_RIRBSTS, HDAC_RIRBSTS_RINTFL,
				HDAC_RIRBSTS_RINTFL);
		hda_update_intr(sc);
	}
}

static int
hda_codec_constructor(struct hda_softc *sc, struct hda_codec_class *codec,
    const char *play, const char *rec)
{
	struct hda_codec_inst *hci = NULL;

	if (sc->codecs_no >= HDA_CODEC_MAX)
		return (-1);

	hci = calloc(1, sizeof(struct hda_codec_inst));
	if (!hci)
		return (-1);

	hci->hda = sc;
	hci->hops = &hops;
	hci->cad = sc->codecs_no;
	hci->codec = codec;

	if (!codec->init) {
		DPRINTF("This codec does not implement the init function");
		free(hci);
		return (-1);
	}
	if (codec->init(hci, play, rec) != 0) {
		free(hci);
		return (-1);
	}
	sc->codecs[sc->codecs_no++] = hci;
	return (0);
}

static struct hda_codec_class *
hda_find_codec_class(const char *name)
{
	struct hda_codec_class **pdpp = NULL, *pdp = NULL;

	SET_FOREACH(pdpp, hda_codec_class_set) {
		pdp = *pdpp;
		if (!strcmp(pdp->name, name)) {
			return (pdp);
		}
	}

	return (NULL);
}

static int
hda_send_command(struct hda_softc *sc, uint32_t verb)
{
	struct hda_codec_inst *hci = NULL;
	struct hda_codec_class *codec = NULL;
	uint8_t cad = (verb >> HDA_CMD_CAD_SHIFT) & 0x0f;

	if (cad >= sc->codecs_no)
		return (-1);

	DPRINTF("cad: 0x%x verb: 0x%x", cad, verb);

	hci = sc->codecs[cad];
	assert(hci);

	codec = hci->codec;
	assert(codec);

	if (!codec->command) {
		DPRINTF("This codec does not implement the command function");
		return (-1);
	}

	return (codec->command(hci, verb));
}

static int
hda_notify_codecs(struct hda_softc *sc, uint8_t run, uint8_t stream,
    uint8_t dir)
{
	struct hda_codec_inst *hci = NULL;
	struct hda_codec_class *codec = NULL;
	int err;
	int i;

	/* Notify each codec */
	for (i = 0; i < sc->codecs_no; i++) {
		hci = sc->codecs[i];
		assert(hci);

		codec = hci->codec;
		assert(codec);

		if (codec->notify) {
			err = codec->notify(hci, run, stream, dir);
			if (!err)
				break;
		}
	}

	return (i == sc->codecs_no ? (-1) : 0);
}

static void
hda_reset(struct hda_softc *sc)
{
	int i;
	struct hda_codec_inst *hci = NULL;
	struct hda_codec_class *codec = NULL;

	if (sc->lintr != 0 && sc->pci_dev != NULL) {
		pci_lintr_deassert(sc->pci_dev);
		sc->lintr = 0;
	}

	for (i = 0; i < HDA_IOSS_NO; i++) {
		if (sc->streams[i].run)
			(void)hda_stream_stop(sc, i);
		memset(&sc->streams[i], 0, sizeof(sc->streams[i]));
	}
	memset(&sc->corb, 0, sizeof(sc->corb));
	memset(&sc->rirb, 0, sizeof(sc->rirb));
	sc->dma_pib_vaddr = NULL;
	sc->rirb_cnt = 0;
	hda_reset_regs(sc);

	/* Reset each codec */
	for (i = 0; i < sc->codecs_no; i++) {
		hci = sc->codecs[i];
		assert(hci);

		codec = hci->codec;
		assert(codec);

		if (codec->reset)
			codec->reset(hci);
	}

	sc->wall_clock_start = hda_get_clock_ns();
}

static void
hda_reset_regs(struct hda_softc *sc)
{
	uint32_t off = 0;
	uint8_t i;

	DPRINTF("Reset the HDA controller registers ...");

	memset(sc->regs, 0, sizeof(sc->regs));
	memset(sc->stream_map, UINT8_MAX, sizeof(sc->stream_map));

	hda_set_reg_by_offset(sc, HDAC_GCAP,
			HDAC_GCAP_64OK |
			(HDA_ISS_NO << HDAC_GCAP_ISS_SHIFT) |
			(HDA_OSS_NO << HDAC_GCAP_OSS_SHIFT));
	hda_set_reg_by_offset(sc, HDAC_VMAJ, 0x01);
	hda_set_reg_by_offset(sc, HDAC_OUTPAY, 0x3c);
	hda_set_reg_by_offset(sc, HDAC_INPAY, 0x1d);
	hda_set_reg_by_offset(sc, HDAC_CORBSIZE,
	    HDAC_CORBSIZE_CORBSZCAP_256 | HDAC_CORBSIZE_CORBSIZE_256);
	hda_set_reg_by_offset(sc, HDAC_RIRBSIZE,
	    HDAC_RIRBSIZE_RIRBSZCAP_256 | HDAC_RIRBSIZE_RIRBSIZE_256);

	for (i = 0; i < HDA_IOSS_NO; i++) {
		off = hda_get_offset_stream(i);
		hda_set_reg_by_offset(sc, off + HDAC_SDFIFOS, HDA_FIFO_SIZE);
	}
}

static void
hda_stream_reset(struct hda_softc *sc, uint8_t stream_ind)
{
	struct hda_stream_desc *st = &sc->streams[stream_ind];
	uint32_t off = hda_get_offset_stream(stream_ind);

	DPRINTF("Reset the HDA stream: 0x%x", stream_ind);
	if (st->run)
		(void)hda_stream_stop(sc, stream_ind);

	/* Reset the Stream Descriptor registers */
	memset(sc->regs + HDA_STREAM_REGS_BASE + off, 0,
	    HDA_STREAM_REGS_LEN * sizeof(sc->regs[0]));

	/* Reset the Stream Descriptor */
	memset(st, 0, sizeof(*st));

	hda_set_field_by_offset(sc, off + HDAC_SDSTS,
	    HDAC_SDSTS_FIFORDY, HDAC_SDSTS_FIFORDY);
	hda_set_field_by_offset(sc, off + HDAC_SDCTL0,
	    HDAC_SDCTL_SRST, HDAC_SDCTL_SRST);
}

static int
hda_stream_start(struct hda_softc *sc, uint8_t stream_ind)
{
	struct hda_stream_desc *st;
	struct hda_stream_desc next = { 0 };
	struct hda_bdle_desc *bdle_desc = NULL;
	struct hda_bdle *bdle = NULL;
	uint32_t lvi = 0;
	uint32_t bdl_cnt = 0;
	uint64_t bdpl = 0;
	uint64_t bdpu = 0;
	uint64_t bdl_paddr = 0;
	void *bdl_vaddr = NULL;
	uint32_t bdle_sz = 0;
	uint64_t bdle_addrl = 0;
	uint64_t bdle_addrh = 0;
	uint64_t bdle_paddr = 0;
	void *bdle_vaddr = NULL;
	uint32_t off;
	uint32_t sdctl = 0;
	uint32_t cbl = 0;
	uint64_t total = 0;
	uint8_t strm = 0;
	uint8_t dir = 0;

	if (stream_ind >= HDA_IOSS_NO)
		return (-1);
	st = &sc->streams[stream_ind];
	if (st->run)
		return (-1);
	off = hda_get_offset_stream(stream_ind);

	sdctl = hda_get_reg_by_offset(sc, off + HDAC_SDCTL0);
	strm = (sdctl >> 20) & 0x0f;
	dir = stream_ind >= HDA_ISS_NO;
	if (strm == 0 || (sc->stream_map[dir][strm] != UINT8_MAX &&
	    sc->stream_map[dir][strm] != stream_ind))
		return (-1);

	lvi = hda_get_reg_by_offset(sc, off + HDAC_SDLVI);
	cbl = hda_get_reg_by_offset(sc, off + HDAC_SDCBL);
	bdpl = hda_get_reg_by_offset(sc, off + HDAC_SDBDPL);
	bdpu = hda_get_reg_by_offset(sc, off + HDAC_SDBDPU);

	bdl_cnt = lvi + 1;
	if (bdl_cnt == 0 || bdl_cnt > HDA_BDL_MAX_LEN || cbl == 0 ||
	    cbl % HDA_DMA_ACCESS_LEN != 0)
		return (-1);

	bdl_paddr = (bdpl & ~UINT64_C(0x7f)) | (bdpu << 32);
	bdl_vaddr = hda_dma_get_vaddr(sc, bdl_paddr,
	    HDA_BDL_ENTRY_LEN * bdl_cnt, PCI_DMA_DEVICE_READ);
	if (!bdl_vaddr) {
		DPRINTF("Fail to get the guest virtual address");
		return (-1);
	}

	DPRINTF("stream: 0x%x bdl_cnt: 0x%x bdl_paddr: 0x%lx",
	    stream_ind, bdl_cnt, bdl_paddr);

	bdle = (struct hda_bdle *)bdl_vaddr;
	for (size_t i = 0; i < bdl_cnt; i++, bdle++) {
		bdle_sz = le32toh(bdle->len);
		if (bdle_sz == 0 || bdle_sz % HDA_DMA_ACCESS_LEN != 0)
			return (-1);

		bdle_addrl = le32toh(bdle->addrl);
		bdle_addrh = le32toh(bdle->addrh);

		bdle_paddr = bdle_addrl | (bdle_addrh << 32);
		if (bdle_paddr > UINT64_MAX - bdle_sz ||
		    total > UINT32_MAX - bdle_sz)
			return (-1);
		/*
		 * Output streams consume guest memory; input streams produce it.
		 * Record that distinction at the mapping boundary so migration can
		 * conservatively capture device DMA which races an epoch change.
		 */
		bdle_vaddr = hda_dma_get_vaddr(sc, bdle_paddr, bdle_sz,
		    dir ? PCI_DMA_DEVICE_READ : PCI_DMA_DEVICE_WRITE);
		if (!bdle_vaddr) {
			DPRINTF("Fail to get the guest virtual address");
			return (-1);
		}

		bdle_desc = &next.bdl[i];
		bdle_desc->addr = bdle_vaddr;
		bdle_desc->len = bdle_sz;
		bdle_desc->ioc = le32toh(bdle->ioc) != 0;
		total += bdle_sz;

		DPRINTF("bdle: 0x%zx bdle_sz: 0x%x", i, bdle_sz);
	}

	/* The cyclic buffer may end before the final descriptor, but it must
	 * be fully backed by the BDL. */
	if (total < cbl)
		return (-1);

	DPRINTF("strm: 0x%x, dir: 0x%x", strm, dir);

	next.bdl_cnt = bdl_cnt;
	next.cbl = cbl;
	next.stream = strm;
	next.dir = dir;
	*st = next;
	sc->stream_map[dir][strm] = stream_ind;

	hda_set_pib(sc, stream_ind, 0);

	st->run = 1;

	hda_notify_codecs(sc, 1, strm, dir);

	return (0);
}

static int
hda_stream_stop(struct hda_softc *sc, uint8_t stream_ind)
{
	struct hda_stream_desc *st;
	uint8_t strm;
	uint8_t dir;

	if (stream_ind >= HDA_IOSS_NO)
		return (-1);
	st = &sc->streams[stream_ind];
	strm = st->stream;
	dir = st->dir;

	DPRINTF("stream: 0x%x, strm: 0x%x, dir: 0x%x", stream_ind, strm, dir);

	st->run = 0;

	hda_notify_codecs(sc, 0, strm, dir);
	if (strm < HDA_STREAM_TAGS_CNT && sc->stream_map[dir][strm] == stream_ind)
		sc->stream_map[dir][strm] = UINT8_MAX;

	return (0);
}

static uint32_t
hda_read(struct hda_softc *sc, uint32_t offset)
{
	if (offset == HDAC_WALCLK)
		return (24 * (hda_get_clock_ns() -			\
			sc->wall_clock_start) / 1000);

	return (hda_get_reg_by_offset(sc, offset));
}

static int
hda_write(struct hda_softc *sc, uint32_t offset, uint8_t size, uint32_t value)
{
	uint32_t old = hda_get_reg_by_offset(sc, offset);
	uint32_t masks[] = {0x00000000, 0x000000ff, 0x0000ffff,
			0x00ffffff, 0xffffffff};
	hda_set_reg_handler set_reg_handler = NULL;

	if (offset < nitems(hda_set_reg_table))
		set_reg_handler = hda_set_reg_table[offset];

	hda_set_field_by_offset(sc, offset, masks[size], value);

	if (set_reg_handler)
		set_reg_handler(sc, offset, old);

	return (0);
}

#if DEBUG_HDA == 1
static inline void
hda_print_cmd_ctl_data(struct hda_codec_cmd_ctl *p)
{
	DPRINTF("%s size: %d", p->name, p->size);
	DPRINTF("%s dma_vaddr: %p", p->name, p->dma_vaddr);
	DPRINTF("%s wp: 0x%x", p->name, p->wp);
	DPRINTF("%s rp: 0x%x", p->name, p->rp);
}
#else
static inline void
hda_print_cmd_ctl_data(struct hda_codec_cmd_ctl *p __unused) {}
#endif

static int
hda_corb_start(struct hda_softc *sc)
{
	struct hda_codec_cmd_ctl *corb = &sc->corb;
	uint8_t corbsize = 0;
	uint64_t corblbase = 0;
	uint64_t corbubase = 0;
	uint64_t corbpaddr = 0;

	corb->name = "CORB";

	corbsize = hda_get_reg_by_offset(sc, HDAC_CORBSIZE) &		\
		   HDAC_CORBSIZE_CORBSIZE_MASK;
	corb->size = hda_corb_sizes[corbsize];

	if (!corb->size) {
		DPRINTF("Invalid corb size");
		return (-1);
	}

	corblbase = hda_get_reg_by_offset(sc, HDAC_CORBLBASE);
	corbubase = hda_get_reg_by_offset(sc, HDAC_CORBUBASE);

	corbpaddr = (corblbase & ~UINT64_C(0x7f)) | (corbubase << 32);
	DPRINTF("CORB dma_paddr: %p", (void *)corbpaddr);

	corb->dma_vaddr = hda_dma_get_vaddr(sc, corbpaddr,
	    HDA_CORB_ENTRY_LEN * corb->size, PCI_DMA_DEVICE_READ);
	if (!corb->dma_vaddr) {
		DPRINTF("Fail to get the guest virtual address");
		return (-1);
	}

	corb->wp = hda_get_reg_by_offset(sc, HDAC_CORBWP);
	corb->rp = hda_get_reg_by_offset(sc, HDAC_CORBRP);

	corb->run = 1;

	hda_print_cmd_ctl_data(corb);

	return (0);
}

static int
hda_corb_run(struct hda_softc *sc)
{
	struct hda_codec_cmd_ctl *corb = &sc->corb;
	uint32_t verb = 0;
	int err;

	corb->wp = hda_get_reg_by_offset(sc, HDAC_CORBWP);
	if (corb->wp >= corb->size) {
		DPRINTF("Invalid HDAC_CORBWP %u >= size %u", corb->wp,
		    corb->size);
		return (-1);
	}

	while (corb->rp != corb->wp && corb->run) {
		corb->rp++;
		corb->rp %= corb->size;

		verb = hda_dma_ld_dword((uint8_t *)corb->dma_vaddr +
		    HDA_CORB_ENTRY_LEN * corb->rp);

		err = hda_send_command(sc, verb);
		if (err != 0) {
			hda_set_field_by_offset(sc, HDAC_CORBSTS,
			    HDAC_CORBSTS_CMEI, HDAC_CORBSTS_CMEI);
			corb->run = 0;
			/*
			 * Publish the consumed read pointer and clear the
			 * guest-visible CORBRUN so the register file matches the
			 * stopped engine.  Otherwise CORBCTL advertises the DMA
			 * engine as running while it is dead, and the advanced
			 * internal rp is lost, leaving the failed verb to be
			 * reprocessed on the next start.
			 */
			hda_set_reg_by_offset(sc, HDAC_CORBRP, corb->rp);
			hda_set_field_by_offset(sc, HDAC_CORBCTL,
			    HDAC_CORBCTL_CORBRUN, 0);
			return (err);
		}
	}

	hda_set_reg_by_offset(sc, HDAC_CORBRP, corb->rp);

	if (corb->run)
		hda_response_interrupt(sc);

	return (0);
}

static int
hda_rirb_start(struct hda_softc *sc)
{
	struct hda_codec_cmd_ctl *rirb = &sc->rirb;
	uint8_t rirbsize = 0;
	uint64_t rirblbase = 0;
	uint64_t rirbubase = 0;
	uint64_t rirbpaddr = 0;

	rirb->name = "RIRB";

	rirbsize = hda_get_reg_by_offset(sc, HDAC_RIRBSIZE) &		\
		   HDAC_RIRBSIZE_RIRBSIZE_MASK;
	rirb->size = hda_rirb_sizes[rirbsize];

	if (!rirb->size) {
		DPRINTF("Invalid rirb size");
		return (-1);
	}

	rirblbase = hda_get_reg_by_offset(sc, HDAC_RIRBLBASE);
	rirbubase = hda_get_reg_by_offset(sc, HDAC_RIRBUBASE);

	rirbpaddr = (rirblbase & ~UINT64_C(0x7f)) | (rirbubase << 32);
	DPRINTF("RIRB dma_paddr: %p", (void *)rirbpaddr);

	rirb->dma_vaddr = hda_dma_get_vaddr(sc, rirbpaddr,
	    HDA_RIRB_ENTRY_LEN * rirb->size, PCI_DMA_DEVICE_WRITE);
	if (!rirb->dma_vaddr) {
		DPRINTF("Fail to get the guest virtual address");
		return (-1);
	}

	rirb->wp = hda_get_reg_by_offset(sc, HDAC_RIRBWP);
	rirb->rp = 0x0000;

	rirb->run = 1;

	hda_print_cmd_ctl_data(rirb);

	return (0);
}

static void *
hda_dma_get_vaddr(struct hda_softc *sc, uint64_t dma_paddr, size_t len,
    enum pci_dma_direction direction)
{
	struct pci_devinst *pi = sc->pci_dev;

	if (pi == NULL || len == 0)
		return (NULL);

	return (pci_emul_map_dma(pi, dma_paddr, len, direction));
}

static void
hda_dma_st_dword(void *dma_vaddr, uint32_t data)
{
	le32enc(dma_vaddr, data);
}

static uint32_t
hda_dma_ld_dword(void *dma_vaddr)
{
	return (le32dec(dma_vaddr));
}

static inline uint8_t
hda_get_stream_by_offsets(uint32_t offset, uint8_t reg_offset)
{
	uint8_t stream_ind = (offset - reg_offset) >> 5;

	assert(stream_ind < HDA_IOSS_NO);

	return (stream_ind);
}

static inline uint32_t
hda_get_offset_stream(uint8_t stream_ind)
{
	return (stream_ind << 5);
}

static void
hda_set_gctl(struct hda_softc *sc, uint32_t offset, uint32_t old __unused)
{
	uint32_t value = hda_get_reg_by_offset(sc, offset);

	if (!(value & HDAC_GCTL_CRST)) {
		hda_reset(sc);
	}
}

static void
hda_set_statests(struct hda_softc *sc, uint32_t offset, uint32_t old)
{
	uint32_t value = hda_get_reg_by_offset(sc, offset);

	hda_set_reg_by_offset(sc, offset, old);

	/* clear the corresponding bits written by the software (guest) */
	hda_set_field_by_offset(sc, offset, value & HDA_STATESTS_IRQ_MASK, 0);

	hda_update_intr(sc);
}

static void
hda_set_corbwp(struct hda_softc *sc, uint32_t offset __unused,
    uint32_t old __unused)
{
	hda_corb_run(sc);
}

static void
hda_set_corbrp(struct hda_softc *sc, uint32_t offset, uint32_t old)
{
	uint32_t value = hda_get_reg_by_offset(sc, offset);

	if ((value & HDAC_CORBRP_CORBRPRST) != 0) {
		hda_set_reg_by_offset(sc, offset, 0);
		sc->corb.rp = 0;
	} else {
		hda_set_reg_by_offset(sc, offset, old);
	}
}

static void
hda_set_corbctl(struct hda_softc *sc, uint32_t offset, uint32_t old)
{
	uint32_t value = hda_get_reg_by_offset(sc, offset);
	int err;
	struct hda_codec_cmd_ctl *corb = NULL;

	if (value & HDAC_CORBCTL_CORBRUN) {
		if (!(old & HDAC_CORBCTL_CORBRUN)) {
			err = hda_corb_start(sc);
			if (err != 0) {
				hda_set_field_by_offset(sc, offset,
				    HDAC_CORBCTL_CORBRUN, 0);
				hda_set_field_by_offset(sc, HDAC_CORBSTS,
				    HDAC_CORBSTS_CMEI, HDAC_CORBSTS_CMEI);
				return;
			}
		}
	} else {
		corb = &sc->corb;
		memset(corb, 0, sizeof(*corb));
	}

	if (corb == NULL && hda_corb_run(sc) != 0)
		hda_update_intr(sc);
}

static void
hda_set_rirbctl(struct hda_softc *sc, uint32_t offset, uint32_t old __unused)
{
	uint32_t value = hda_get_reg_by_offset(sc, offset);
	int err;
	struct hda_codec_cmd_ctl *rirb = NULL;

	if (value & HDAC_RIRBCTL_RIRBDMAEN) {
		err = hda_rirb_start(sc);
		if (err != 0) {
			hda_set_field_by_offset(sc, offset,
			    HDAC_RIRBCTL_RIRBDMAEN, 0);
			hda_set_field_by_offset(sc, HDAC_RIRBSTS,
			    HDAC_RIRBSTS_RIRBOIS, HDAC_RIRBSTS_RIRBOIS);
			hda_update_intr(sc);
		}
	} else {
		rirb = &sc->rirb;
		memset(rirb, 0, sizeof(*rirb));
	}
}

static void
hda_set_rirbwp(struct hda_softc *sc, uint32_t offset, uint32_t old)
{
	uint32_t value = hda_get_reg_by_offset(sc, offset);

	if ((value & HDAC_RIRBWP_RIRBWPRST) != 0) {
		hda_set_reg_by_offset(sc, offset, 0);
		sc->rirb.wp = 0;
		sc->rirb_cnt = 0;
	} else {
		hda_set_reg_by_offset(sc, offset, old);
	}
}

static void
hda_set_rirbsts(struct hda_softc *sc, uint32_t offset, uint32_t old)
{
	uint32_t value = hda_get_reg_by_offset(sc, offset);

	hda_set_reg_by_offset(sc, offset, old);

	/* clear the corresponding bits written by the software (guest) */
	hda_set_field_by_offset(sc, offset, value & HDA_RIRBSTS_IRQ_MASK, 0);

	hda_update_intr(sc);
}

static void
hda_set_dpiblbase(struct hda_softc *sc, uint32_t offset, uint32_t old)
{
	uint32_t value = hda_get_reg_by_offset(sc, offset);
	uint64_t dpiblbase = 0;
	uint64_t dpibubase = 0;
	uint64_t dpibpaddr = 0;

	if ((value & HDAC_DPLBASE_DPLBASE_DMAPBE) != (old &		\
				HDAC_DPLBASE_DPLBASE_DMAPBE)) {
		if (value & HDAC_DPLBASE_DPLBASE_DMAPBE) {
			dpiblbase = value & HDAC_DPLBASE_DPLBASE_MASK;
			dpibubase = hda_get_reg_by_offset(sc, HDAC_DPIBUBASE);

			dpibpaddr = dpiblbase | (dpibubase << 32);
			DPRINTF("DMA Position In Buffer dma_paddr: %p",
			    (void *)dpibpaddr);

			sc->dma_pib_vaddr = hda_dma_get_vaddr(sc, dpibpaddr,
			    HDA_DMA_PIB_ENTRY_LEN * HDA_IOSS_NO,
			    PCI_DMA_DEVICE_WRITE);
			if (!sc->dma_pib_vaddr) {
				DPRINTF("Fail to get the guest \
					 virtual address");
				hda_set_field_by_offset(sc, offset,
				    HDAC_DPLBASE_DPLBASE_DMAPBE, 0);
			}
		} else {
			DPRINTF("DMA Position In Buffer Reset");
			sc->dma_pib_vaddr = NULL;
		}
	}
}

static void
hda_set_sdctl(struct hda_softc *sc, uint32_t offset, uint32_t old)
{
	uint8_t stream_ind = hda_get_stream_by_offsets(offset, HDAC_SDCTL0);
	uint32_t value = hda_get_reg_by_offset(sc, offset);
	int err;

	DPRINTF("stream_ind: 0x%x old: 0x%x value: 0x%x",
	    stream_ind, old, value);

	if (value & HDAC_SDCTL_SRST) {
		hda_stream_reset(sc, stream_ind);
		return;
	}

	if ((value & HDAC_SDCTL_RUN) != (old & HDAC_SDCTL_RUN)) {
		if (value & HDAC_SDCTL_RUN) {
			err = hda_stream_start(sc, stream_ind);
			if (err != 0) {
				hda_set_field_by_offset(sc, offset,
				    HDAC_SDCTL_RUN, 0);
				hda_set_field_by_offset(sc,
				    hda_get_offset_stream(stream_ind) + HDAC_SDSTS,
				    HDAC_SDSTS_DESE, HDAC_SDSTS_DESE);
				hda_update_intr(sc);
			}
		} else {
			(void)hda_stream_stop(sc, stream_ind);
		}
	}
}

static void
hda_set_sdctl2(struct hda_softc *sc, uint32_t offset, uint32_t old __unused)
{
	uint32_t value = hda_get_reg_by_offset(sc, offset);

	hda_set_field_by_offset(sc, offset - 2, 0x00ff0000, value << 16);
}

static void
hda_set_sdsts(struct hda_softc *sc, uint32_t offset, uint32_t old)
{
	uint32_t value = hda_get_reg_by_offset(sc, offset);

	hda_set_reg_by_offset(sc, offset, old);

	/* clear the corresponding bits written by the software (guest) */
	hda_set_field_by_offset(sc, offset, value & HDA_SDSTS_IRQ_MASK, 0);

	hda_update_intr(sc);
}

static int
hda_signal_state_change(struct hda_codec_inst *hci)
{
	struct hda_softc *sc = NULL;
	uint32_t sdiwake = 0;

	assert(hci);
	assert(hci->hda);

	DPRINTF("cad: 0x%x", hci->cad);

	sc = hci->hda;
	pthread_mutex_lock(&sc->mtx);
	sdiwake = 1 << hci->cad;

	hda_set_field_by_offset(sc, HDAC_STATESTS, sdiwake, sdiwake);
	hda_update_intr(sc);
	pthread_mutex_unlock(&sc->mtx);

	return (0);
}

static int
hda_response(struct hda_codec_inst *hci, uint32_t response, uint8_t unsol)
{
	struct hda_softc *sc = NULL;
	struct hda_codec_cmd_ctl *rirb = NULL;
	uint32_t response_ex = 0;
	uint16_t rintcnt = 0;

	assert(hci);
	assert(hci->cad < HDA_CODEC_MAX);

	response_ex = hci->cad | unsol;

	sc = hci->hda;
	assert(sc);
	pthread_mutex_lock(&sc->mtx);

	rirb = &sc->rirb;

	if (rirb->run) {
		rirb->wp++;
		rirb->wp %= rirb->size;

		hda_dma_st_dword((uint8_t *)rirb->dma_vaddr +
		    HDA_RIRB_ENTRY_LEN * rirb->wp, response);
		hda_dma_st_dword((uint8_t *)rirb->dma_vaddr +
		    HDA_RIRB_ENTRY_LEN * rirb->wp + 0x04, response_ex);
		pci_emul_mark_dma_dirty_mapping(sc->pci_dev,
		    (uint8_t *)rirb->dma_vaddr + HDA_RIRB_ENTRY_LEN * rirb->wp,
		    HDA_RIRB_ENTRY_LEN);

		hda_set_reg_by_offset(sc, HDAC_RIRBWP, rirb->wp);

		sc->rirb_cnt++;
	}

	rintcnt = hda_get_reg_by_offset(sc, HDAC_RINTCNT) &
	    HDAC_RINTCNT_MASK;
	if (rintcnt == 0)
		rintcnt = 256;
	if (sc->rirb_cnt >= rintcnt)
		hda_response_interrupt(sc);
	pthread_mutex_unlock(&sc->mtx);

	return (0);
}

static int
hda_transfer(struct hda_codec_inst *hci, uint8_t stream, uint8_t dir,
    uint8_t *buf, size_t count)
{
	struct hda_softc *sc = NULL;
	struct hda_stream_desc *st = NULL;
	struct hda_bdle_desc *bdl = NULL;
	struct hda_bdle_desc *bdle_desc = NULL;
	uint8_t stream_ind = 0;
	uint32_t lpib = 0;
	uint32_t off = 0;
	size_t left = 0;
	uint8_t irq = 0;

	if (hci == NULL || hci->hda == NULL || buf == NULL ||
	    count == 0 || count % HDA_DMA_ACCESS_LEN != 0 || dir > 1)
		return (-1);

	if (!stream) {
		DPRINTF("Invalid stream");
		return (-1);
	}

	sc = hci->hda;
	pthread_mutex_lock(&sc->mtx);

	if (stream >= HDA_STREAM_TAGS_CNT)
		goto fail;
	stream_ind = sc->stream_map[dir][stream];

	if ((!dir && stream_ind >= HDA_ISS_NO) ||
	    (dir && (stream_ind < HDA_ISS_NO || stream_ind >= HDA_IOSS_NO)))
		goto fail;

	st = &sc->streams[stream_ind];
	if (!st->run) {
		DPRINTF("Stream 0x%x stopped", stream);
		goto fail;
	}

	if (st->stream != stream || st->bdl_cnt == 0 || st->cbl == 0 ||
	    st->bdl_cnt > HDA_BDL_MAX_LEN || st->be >= st->bdl_cnt ||
	    st->bp >= st->bdl[st->be].len)
		goto fail;

	off = hda_get_offset_stream(stream_ind);

	lpib = hda_get_reg_by_offset(sc, off + HDAC_SDLPIB);

	bdl = st->bdl;

	left = count;
	while (left) {
		bdle_desc = &bdl[st->be];
		if (lpib >= st->cbl)
			goto fail;

		if (dir)
			memcpy(buf, (uint8_t *)bdle_desc->addr + st->bp,
			    HDA_DMA_ACCESS_LEN);
		else {
			memcpy((uint8_t *)bdle_desc->addr + st->bp, buf,
			    HDA_DMA_ACCESS_LEN);
			pci_emul_mark_dma_dirty_mapping(sc->pci_dev,
			    (uint8_t *)bdle_desc->addr + st->bp,
			    HDA_DMA_ACCESS_LEN);
		}

		buf += HDA_DMA_ACCESS_LEN;
		st->bp += HDA_DMA_ACCESS_LEN;
		lpib += HDA_DMA_ACCESS_LEN;
		left -= HDA_DMA_ACCESS_LEN;

		if (lpib == st->cbl) {
			st->bp = 0;
			st->be = 0;
			lpib = 0;
		} else if (st->bp == bdle_desc->len) {
			st->bp = 0;
			if (bdle_desc->ioc)
				irq = 1;
			st->be++;
			if (st->be == st->bdl_cnt) {
				st->be = 0;
				lpib = 0;
			}
			bdle_desc = &bdl[st->be];
		}
	}

	hda_set_pib(sc, stream_ind, lpib);

	if (irq) {
		hda_set_field_by_offset(sc, off + HDAC_SDSTS,
				HDAC_SDSTS_BCIS, HDAC_SDSTS_BCIS);
		hda_update_intr(sc);
	}
	pthread_mutex_unlock(&sc->mtx);
	return (0);
fail:
	pthread_mutex_unlock(&sc->mtx);
	return (-1);
}

static void
hda_set_pib(struct hda_softc *sc, uint8_t stream_ind, uint32_t pib)
{
	uint32_t off = hda_get_offset_stream(stream_ind);

	hda_set_reg_by_offset(sc, off + HDAC_SDLPIB, pib);
	/* LPIB Alias */
	hda_set_reg_by_offset(sc, 0x2000 + off + HDAC_SDLPIB, pib);
	if (sc->dma_pib_vaddr) {
		le32enc((uint8_t *)sc->dma_pib_vaddr + stream_ind *
		    HDA_DMA_PIB_ENTRY_LEN, pib);
		pci_emul_mark_dma_dirty_mapping(sc->pci_dev,
		    (uint8_t *)sc->dma_pib_vaddr + stream_ind *
		    HDA_DMA_PIB_ENTRY_LEN, sizeof(uint32_t));
	}
}

static uint64_t hda_get_clock_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		abort();

	return (ts.tv_sec * 1000000000LL + ts.tv_nsec);
}

/*
 * PCI HDA function definitions
 */
static int
pci_hda_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct hda_softc *sc = NULL;

	assert(pi != NULL);

	pci_set_cfgdata16(pi, PCIR_VENDOR, INTEL_VENDORID);
	pci_set_cfgdata16(pi, PCIR_DEVICE, HDA_INTEL_82801G);

	pci_set_cfgdata8(pi, PCIR_SUBCLASS, PCIS_MULTIMEDIA_HDA);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_MULTIMEDIA);

	/* select the Intel HDA mode */
	pci_set_cfgdata8(pi, PCIR_HDCTL, 0x01);

	/* allocate one BAR register for the Memory address offsets */
	pci_emul_alloc_bar(pi, 0, PCIBAR_MEM32, HDA_LAST_OFFSET);

	/* allocate an IRQ pin for our slot */
	pci_lintr_request(pi);

	sc = hda_init(nvl);
	if (!sc)
		return (-1);

	sc->pci_dev = pi;
	pi->pi_arg = sc;

	return (0);
}

static void
pci_hda_write(struct pci_devinst *pi, int baridx, uint64_t offset, int size,
    uint64_t value)
{
	struct hda_softc *sc = pi->pi_arg;
	int err;

	if (sc == NULL || baridx != 0 || size < 1 || size > 4 ||
	    offset >= HDA_LAST_OFFSET)
		return;

	DPRINTF("offset: 0x%lx value: 0x%lx", offset, value);

	pthread_mutex_lock(&sc->mtx);
	err = hda_write(sc, offset, size, value);
	pthread_mutex_unlock(&sc->mtx);
	if (err != 0)
		DPRINTF("invalid HDA write offset 0x%lx", offset);
}

static uint64_t
pci_hda_read(struct pci_devinst *pi, int baridx, uint64_t offset, int size)
{
	struct hda_softc *sc = pi->pi_arg;
	uint64_t value = 0;

	if (sc == NULL || baridx != 0 || size < 1 || size > 4 ||
	    offset >= HDA_LAST_OFFSET)
		return (UINT64_MAX);

	pthread_mutex_lock(&sc->mtx);
	value = hda_read(sc, offset);
	pthread_mutex_unlock(&sc->mtx);

	DPRINTF("offset: 0x%lx value: 0x%lx", offset, value);

	return (value);
}

#ifdef BHYVE_SNAPSHOT
#define	HDA_SNAPSHOT_MAGIC	0x31414448U	/* "HDA1" on disk */
#define	HDA_SNAPSHOT_VERSION	1U

/*
 * Portable controller checkpoint record, decoded into host representation.
 * Every field crosses the wire as a fixed-width little-endian value; no host
 * pointer is ever serialized.  DMA mappings (CORB/RIRB rings, the DMA
 * position buffer and the per-stream BDL) are derived state and are
 * reconstructed on restore from the restored register file and guest memory,
 * exactly as the running device derives them at start time.
 */
struct hda_snapshot_rec {
	uint32_t regs[HDA_LAST_OFFSET];
	uint8_t codecs_no;
	uint8_t lintr;
	uint16_t rirb_cnt;
	uint64_t wall_clock_elapsed;
	struct {
		uint8_t run;
		uint16_t rp;
		uint16_t wp;
		uint16_t size;
	} corb, rirb;
	uint8_t st_dir[HDA_IOSS_NO];
	uint8_t st_run[HDA_IOSS_NO];
	uint8_t st_stream[HDA_IOSS_NO];
	uint32_t st_bp[HDA_IOSS_NO];
	uint32_t st_be[HDA_IOSS_NO];
	uint32_t st_bdl_cnt[HDA_IOSS_NO];
	uint32_t st_cbl[HDA_IOSS_NO];
	uint8_t stream_map[2][HDA_STREAM_TAGS_CNT];
};

static void
hda_snapshot_capture(const struct hda_softc *sc, struct hda_snapshot_rec *rec)
{
	const struct hda_stream_desc *st;
	uint8_t i;

	memcpy(rec->regs, sc->regs, sizeof(rec->regs));
	rec->codecs_no = sc->codecs_no;
	rec->lintr = sc->lintr;
	rec->rirb_cnt = sc->rirb_cnt;
	rec->wall_clock_elapsed = hda_get_clock_ns() - sc->wall_clock_start;
	rec->corb.run = sc->corb.run;
	rec->corb.rp = sc->corb.rp;
	rec->corb.wp = sc->corb.wp;
	rec->corb.size = sc->corb.size;
	rec->rirb.run = sc->rirb.run;
	rec->rirb.rp = sc->rirb.rp;
	rec->rirb.wp = sc->rirb.wp;
	rec->rirb.size = sc->rirb.size;
	for (i = 0; i < HDA_IOSS_NO; i++) {
		st = &sc->streams[i];
		rec->st_dir[i] = st->dir;
		rec->st_run[i] = st->run;
		rec->st_stream[i] = st->stream;
		rec->st_bp[i] = st->bp;
		rec->st_be[i] = st->be;
		rec->st_bdl_cnt[i] = st->bdl_cnt;
		rec->st_cbl[i] = st->cbl;
	}
	memcpy(rec->stream_map, sc->stream_map, sizeof(rec->stream_map));
}

/*
 * Side-effect-free range validation shared by the VALIDATE preflight and the
 * RESTORE commit.  Guest-memory-dependent checks (BDL shape, cursor versus
 * buffer-entry length) belong to the restore commit; nothing here touches
 * guest memory or the destination device.
 */
static bool
hda_snapshot_rec_valid(const struct hda_softc *sc,
    const struct hda_snapshot_rec *rec)
{
	uint8_t i;

	if (rec->codecs_no != sc->codecs_no)
		return (false);
	if (rec->lintr != 0 && rec->lintr != 1)
		return (false);
	if (!hda_snapshot_cmd_ctl_valid(rec->corb.run, rec->corb.rp,
	    rec->corb.wp, rec->corb.size))
		return (false);
	if (!hda_snapshot_cmd_ctl_valid(rec->rirb.run, rec->rirb.rp,
	    rec->rirb.wp, rec->rirb.size))
		return (false);
	for (i = 0; i < HDA_IOSS_NO; i++) {
		if (!hda_snapshot_stream_valid(i, rec->st_dir[i],
		    rec->st_run[i], rec->st_stream[i], rec->st_bp[i],
		    rec->st_be[i], rec->st_bdl_cnt[i], rec->st_cbl[i]))
			return (false);
	}
	if (!hda_snapshot_stream_map_valid(rec->stream_map, rec->st_dir,
	    rec->st_run, rec->st_stream))
		return (false);
	return (true);
}

/*
 * Rebuild one stream descriptor.  A running stream re-derives its BDL from
 * the restored register file and restored guest memory with the same
 * validation hda_stream_start() applies, and additionally requires the
 * derived shape to match the serialized cursors.
 */
static int
hda_snapshot_restore_stream(struct hda_softc *sc, struct hda_stream_desc *st,
    uint8_t stream_ind, const struct hda_snapshot_rec *rec)
{
	struct hda_bdle *bdle;
	void *bdl_vaddr, *bdle_vaddr;
	uint64_t bdl_paddr, bdle_paddr, total;
	uint32_t off, bdl_cnt, bdle_sz;
	size_t i;

	memset(st, 0, sizeof(*st));
	st->dir = rec->st_dir[stream_ind];
	st->stream = rec->st_stream[stream_ind];
	st->bp = rec->st_bp[stream_ind];
	st->be = rec->st_be[stream_ind];
	st->bdl_cnt = rec->st_bdl_cnt[stream_ind];
	st->cbl = rec->st_cbl[stream_ind];
	if (rec->st_run[stream_ind] == 0)
		return (0);

	off = hda_get_offset_stream(stream_ind);
	bdl_cnt = hda_get_reg_by_offset(sc, off + HDAC_SDLVI) + 1;
	if (bdl_cnt != st->bdl_cnt ||
	    hda_get_reg_by_offset(sc, off + HDAC_SDCBL) != st->cbl)
		return (EINVAL);
	bdl_paddr = ((uint64_t)hda_get_reg_by_offset(sc, off + HDAC_SDBDPL) &
	    ~UINT64_C(0x7f)) |
	    ((uint64_t)hda_get_reg_by_offset(sc, off + HDAC_SDBDPU) << 32);
	bdl_vaddr = hda_dma_get_vaddr(sc, bdl_paddr,
	    HDA_BDL_ENTRY_LEN * bdl_cnt, PCI_DMA_DEVICE_READ);
	if (bdl_vaddr == NULL)
		return (EINVAL);

	total = 0;
	bdle = (struct hda_bdle *)bdl_vaddr;
	for (i = 0; i < bdl_cnt; i++, bdle++) {
		bdle_sz = le32toh(bdle->len);
		if (bdle_sz == 0 || bdle_sz % HDA_DMA_ACCESS_LEN != 0)
			return (EINVAL);
		bdle_paddr = le32toh(bdle->addrl) |
		    ((uint64_t)le32toh(bdle->addrh) << 32);
		if (bdle_paddr > UINT64_MAX - bdle_sz ||
		    total > UINT32_MAX - bdle_sz)
			return (EINVAL);
		bdle_vaddr = hda_dma_get_vaddr(sc, bdle_paddr, bdle_sz,
		    st->dir ? PCI_DMA_DEVICE_READ : PCI_DMA_DEVICE_WRITE);
		if (bdle_vaddr == NULL)
			return (EINVAL);
		st->bdl[i].addr = bdle_vaddr;
		st->bdl[i].len = bdle_sz;
		st->bdl[i].ioc = le32toh(bdle->ioc) != 0;
		total += bdle_sz;
	}
	if (total < st->cbl)
		return (EINVAL);
	if (st->bp >= st->bdl[st->be].len)
		return (EINVAL);
	st->run = 1;
	return (0);
}

static int
hda_snapshot_publish(struct hda_softc *sc, const struct hda_snapshot_rec *rec)
{
	struct hda_stream_desc *newstreams;
	struct hda_codec_cmd_ctl *ctl;
	void *corb_vaddr = NULL, *rirb_vaddr = NULL, *pib_vaddr = NULL;
	uint64_t paddr;
	uint32_t dplbase;
	uint8_t i;
	int err;

	newstreams = calloc(HDA_IOSS_NO, sizeof(*newstreams));
	if (newstreams == NULL)
		return (ENOMEM);

	/*
	 * Commit the inert register file first so the fallible mappings below
	 * observe the restored bases, then perform every guest-memory mapping
	 * into locals.  Live device resources (CORB/RIRB/PIB DMA pointers and
	 * the per-stream descriptors) are published only after every fallible
	 * step has succeeded, so a mapping failure on any segment leaves the
	 * device unchanged instead of half-restored (some streams running with
	 * live BDL mappings while later ones are not).
	 */
	memcpy(sc->regs, rec->regs, sizeof(sc->regs));
	sc->rirb_cnt = rec->rirb_cnt;
	/*
	 * Unsigned wraparound keeps subsequent HDAC_WALCLK reads continuing
	 * from the serialized elapsed time regardless of the destination's
	 * monotonic clock origin.
	 */
	sc->wall_clock_start = hda_get_clock_ns() - rec->wall_clock_elapsed;
	memcpy(sc->stream_map, rec->stream_map, sizeof(sc->stream_map));

	if (rec->corb.run) {
		paddr = ((uint64_t)hda_get_reg_by_offset(sc, HDAC_CORBLBASE) &
		    ~UINT64_C(0x7f)) |
		    ((uint64_t)hda_get_reg_by_offset(sc, HDAC_CORBUBASE) << 32);
		corb_vaddr = hda_dma_get_vaddr(sc, paddr,
		    HDA_CORB_ENTRY_LEN * rec->corb.size, PCI_DMA_DEVICE_READ);
		if (corb_vaddr == NULL) {
			err = EINVAL;
			goto fail;
		}
	}

	if (rec->rirb.run) {
		paddr = ((uint64_t)hda_get_reg_by_offset(sc, HDAC_RIRBLBASE) &
		    ~UINT64_C(0x7f)) |
		    ((uint64_t)hda_get_reg_by_offset(sc, HDAC_RIRBUBASE) << 32);
		rirb_vaddr = hda_dma_get_vaddr(sc, paddr,
		    HDA_RIRB_ENTRY_LEN * rec->rirb.size, PCI_DMA_DEVICE_WRITE);
		if (rirb_vaddr == NULL) {
			err = EINVAL;
			goto fail;
		}
	}

	dplbase = hda_get_reg_by_offset(sc, HDAC_DPIBLBASE);
	if ((dplbase & HDAC_DPLBASE_DPLBASE_DMAPBE) != 0) {
		paddr = (dplbase & HDAC_DPLBASE_DPLBASE_MASK) |
		    ((uint64_t)hda_get_reg_by_offset(sc, HDAC_DPIBUBASE) << 32);
		pib_vaddr = hda_dma_get_vaddr(sc, paddr,
		    HDA_DMA_PIB_ENTRY_LEN * HDA_IOSS_NO, PCI_DMA_DEVICE_WRITE);
		if (pib_vaddr == NULL) {
			err = EINVAL;
			goto fail;
		}
	}

	for (i = 0; i < HDA_IOSS_NO; i++) {
		err = hda_snapshot_restore_stream(sc, &newstreams[i], i, rec);
		if (err != 0)
			goto fail;
	}

	/* Every fallible step succeeded; commit live resources atomically. */
	ctl = &sc->corb;
	memset(ctl, 0, sizeof(*ctl));
	ctl->name = "CORB";
	ctl->run = rec->corb.run;
	ctl->rp = rec->corb.rp;
	ctl->wp = rec->corb.wp;
	ctl->size = rec->corb.size;
	ctl->dma_vaddr = corb_vaddr;

	ctl = &sc->rirb;
	memset(ctl, 0, sizeof(*ctl));
	ctl->name = "RIRB";
	ctl->run = rec->rirb.run;
	ctl->rp = rec->rirb.rp;
	ctl->wp = rec->rirb.wp;
	ctl->size = rec->rirb.size;
	ctl->dma_vaddr = rirb_vaddr;

	sc->dma_pib_vaddr = pib_vaddr;
	memcpy(sc->streams, newstreams, HDA_IOSS_NO * sizeof(*newstreams));
	free(newstreams);

	/* The interrupt line level is derived state; recompute it. */
	sc->lintr = 0;
	hda_update_intr(sc);
	return (0);

fail:
	free(newstreams);
	return (err);
}

static void
hda_snapshot_restart_streams(struct hda_softc *sc)
{
	const struct hda_stream_desc *st;
	uint8_t i;

	for (i = 0; i < HDA_IOSS_NO; i++) {
		st = &sc->streams[i];
		if (!st->run)
			continue;
		/*
		 * Re-arm the codec's audio context from the restored
		 * converter format.  hda_stream_start() ignores the codec
		 * notification result at run time; restoring keeps the same
		 * contract, and the codec-shape check has already rejected a
		 * destination whose backend configuration differs.
		 */
		(void)hda_notify_codecs(sc, 1, st->stream, st->dir);
	}
}

static int
pci_hda_snapshot(struct vm_snapshot_meta *meta)
{
	struct hda_codec_inst *hci;
	struct hda_snapshot_rec *rec;
	struct pci_devinst *pi;
	struct hda_softc *sc;
	uint32_t magic, version, r;
	uint8_t i;
	int ret;

	if (meta == NULL || meta->dev_data == NULL)
		return (EINVAL);
	pi = meta->dev_data;
	sc = pi->pi_arg;
	if (sc == NULL)
		return (EINVAL);
	rec = calloc(1, sizeof(*rec));
	if (rec == NULL)
		return (ENOMEM);
	/* The mutex is recursive; checkpoint pause may already retain it. */
	pthread_mutex_lock(&sc->mtx);

	magic = HDA_SNAPSHOT_MAGIC;
	version = HDA_SNAPSHOT_VERSION;
	SNAPSHOT_LE32_OR_LEAVE(magic, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(version, meta, ret, done);
	if (vm_snapshot_is_loading(meta) &&
	    (magic != HDA_SNAPSHOT_MAGIC ||
	    version != HDA_SNAPSHOT_VERSION)) {
		ret = ENOTSUP;
		goto done;
	}

	if (meta->op == VM_SNAPSHOT_SAVE)
		hda_snapshot_capture(sc, rec);

	SNAPSHOT_U8_OR_LEAVE(rec->codecs_no, meta, ret, done);
	SNAPSHOT_U8_OR_LEAVE(rec->lintr, meta, ret, done);
	SNAPSHOT_LE16_OR_LEAVE(rec->rirb_cnt, meta, ret, done);
	SNAPSHOT_LE64_OR_LEAVE(rec->wall_clock_elapsed, meta, ret, done);
	for (r = 0; r < HDA_LAST_OFFSET; r++)
		SNAPSHOT_LE32_OR_LEAVE(rec->regs[r], meta, ret, done);
	SNAPSHOT_U8_OR_LEAVE(rec->corb.run, meta, ret, done);
	SNAPSHOT_LE16_OR_LEAVE(rec->corb.rp, meta, ret, done);
	SNAPSHOT_LE16_OR_LEAVE(rec->corb.wp, meta, ret, done);
	SNAPSHOT_LE16_OR_LEAVE(rec->corb.size, meta, ret, done);
	SNAPSHOT_U8_OR_LEAVE(rec->rirb.run, meta, ret, done);
	SNAPSHOT_LE16_OR_LEAVE(rec->rirb.rp, meta, ret, done);
	SNAPSHOT_LE16_OR_LEAVE(rec->rirb.wp, meta, ret, done);
	SNAPSHOT_LE16_OR_LEAVE(rec->rirb.size, meta, ret, done);
	for (i = 0; i < HDA_IOSS_NO; i++) {
		SNAPSHOT_U8_OR_LEAVE(rec->st_dir[i], meta, ret, done);
		SNAPSHOT_U8_OR_LEAVE(rec->st_run[i], meta, ret, done);
		SNAPSHOT_U8_OR_LEAVE(rec->st_stream[i], meta, ret, done);
		SNAPSHOT_LE32_OR_LEAVE(rec->st_bp[i], meta, ret, done);
		SNAPSHOT_LE32_OR_LEAVE(rec->st_be[i], meta, ret, done);
		SNAPSHOT_LE32_OR_LEAVE(rec->st_bdl_cnt[i], meta, ret, done);
		SNAPSHOT_LE32_OR_LEAVE(rec->st_cbl[i], meta, ret, done);
	}
	SNAPSHOT_BUF_OR_LEAVE(rec->stream_map, sizeof(rec->stream_map),
	    meta, ret, done);
	if (vm_snapshot_is_loading(meta) && !hda_snapshot_rec_valid(sc, rec)) {
		ret = EINVAL;
		goto done;
	}

	if (meta->op == VM_SNAPSHOT_RESTORE) {
		ret = hda_snapshot_publish(sc, rec);
		if (ret != 0)
			goto done;
	}

	/*
	 * Codec sub-records follow the controller record.  A codec class
	 * without a state codec makes the checkpoint fail closed before any
	 * record is mutated on the wire beyond this device's allocation.
	 */
	for (i = 0; i < sc->codecs_no; i++) {
		hci = sc->codecs[i];
		if (hci->codec->snapshot == NULL) {
			ret = ENOTSUP;
			goto done;
		}
		ret = hci->codec->snapshot(hci, meta);
		if (ret != 0)
			goto done;
	}

	if (meta->op == VM_SNAPSHOT_RESTORE)
		hda_snapshot_restart_streams(sc);
	ret = 0;

done:
	pthread_mutex_unlock(&sc->mtx);
	free(rec);
	return (ret);
}

/*
 * All guest-visible mutation (register file, streams, CORB/RIRB, guest
 * memory DMA) happens under sc->mtx: BAR accesses take it directly and the
 * codec audio threads take it inside hda_transfer()/hda_response().
 * Acquiring and retaining the mutex is therefore a complete ownership fence;
 * this mirrors the uart backend's pause policy.  The audio backend itself
 * (an open OSS device) is external state and is deliberately not serialized;
 * a restore destination reconstructs it from its own play/rec configuration.
 */
static int
pci_hda_pause(struct pci_devinst *pi)
{
	struct hda_softc *sc;

	sc = pi->pi_arg;
	if (sc == NULL || sc->snapshot_paused)
		return (EINVAL);
	pthread_mutex_lock(&sc->mtx);
	sc->snapshot_paused = true;
	return (0);
}

static int
pci_hda_resume(struct pci_devinst *pi)
{
	struct hda_softc *sc;

	sc = pi->pi_arg;
	if (sc == NULL || !sc->snapshot_paused)
		return (EINVAL);
	sc->snapshot_paused = false;
	pthread_mutex_unlock(&sc->mtx);
	return (0);
}
#endif	/* BHYVE_SNAPSHOT */
