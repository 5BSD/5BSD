/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * TU-include harness for bhyve's Intel HD Audio controller (pci_hda.c).
 *
 * The controller device model is compiled directly into the test so its
 * register file, CORB/RIRB rings, stream descriptors, BDL walk, interrupt
 * logic and portable checkpoint record are exercised as the exact production
 * code.  bhyve infrastructure is mocked in this file: PCI config/BAR/lintr,
 * guest DMA (a flat userspace buffer indexed by guest physical address), the
 * snapshot wire helpers, and a single synthetic codec registered through the
 * real linker set.  The oracle is the Intel HDA specification (register reset
 * values, CORB/RIRB ring semantics, RIRB response entry layout, stream/BDL
 * geometry rules) and independently-computed constants -- never the device
 * model's own output.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/endian.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <atf-c.h>

/*
 * Pull in the harness mocks first so their include guards win over the real
 * bhyve headers that the copied DUT (in ${.OBJDIR}) also names.
 */
#include "config.h"
#include "pci_emul.h"

/*
 * The harness mock pci_emul.h intentionally omits the guest-DMA mapping API
 * and the multimedia class codes pci_hda.c relies on; supply them here before
 * the DUT is compiled.
 */
enum pci_dma_direction {
	PCI_DMA_DEVICE_READ = 0,
	PCI_DMA_DEVICE_WRITE,
};
void *pci_emul_map_dma(struct pci_devinst *, uint64_t, size_t,
    enum pci_dma_direction);
void pci_emul_mark_dma_dirty_mapping(struct pci_devinst *, void *, size_t);

#ifndef PCIC_MULTIMEDIA
#define	PCIC_MULTIMEDIA		0x04
#endif
#ifndef PCIS_MULTIMEDIA_HDA
#define	PCIS_MULTIMEDIA_HDA	0x03
#endif

/* Snapshot metadata type + wire-helper prototypes for the mock definitions. */
#include "snapshot.h"

/* ------------------------------------------------------------------ */
/* Mock guest physical memory                                          */
/* ------------------------------------------------------------------ */

#define	GMEM_SIZE	(16u * 1024u * 1024u)
static uint8_t *g_guest;
static bool g_dma_fail;		/* fail every mapping */
static uint64_t g_dma_fail_gpa;	/* if non-zero, fail only this gpa */
static size_t g_dirty_calls;
static size_t g_dirty_bytes;

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
	g_dirty_bytes = 0;
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
    size_t len)
{
	ATF_CHECK(addr != NULL);
	g_dirty_calls++;
	g_dirty_bytes += len;
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
/* Mock config nodes                                                   */
/* ------------------------------------------------------------------ */

static const char *g_play = "/dev/dsp0";
static const char *g_rec = "/dev/dsp0";

const char *
get_config_value_node(const nvlist_t *nvl __unused, const char *name)
{
	if (strcmp(name, "play") == 0)
		return (g_play);
	if (strcmp(name, "rec") == 0)
		return (g_rec);
	return (NULL);
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
	uint16_t tmp;

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
	uint32_t tmp;

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
	uint64_t tmp;

	if (meta->op == VM_SNAPSHOT_SAVE)
		tmp = htole64(*v);
	if (vm_snapshot_buf(&tmp, sizeof(tmp), meta) != 0)
		return (E2BIG);
	if (vm_snapshot_is_loading(meta))
		*v = le64toh(tmp);
	return (0);
}

int
vm_snapshot_guest2host_addr(struct vmctx *ctx __unused, void **addr __unused,
    size_t len __unused, bool rnull __unused,
    struct vm_snapshot_meta *meta __unused)
{
	return (0);
}

/* ------------------------------------------------------------------ */
/* Device under test                                                   */
/* ------------------------------------------------------------------ */

/* BHYVE_SNAPSHOT is supplied by the Makefile CFLAGS. */
#include "pci_hda.c"

/* ------------------------------------------------------------------ */
/* Synthetic codec registered through the real linker set              */
/* ------------------------------------------------------------------ */

#define	MOCK_RESP(verb)		((uint32_t)((verb) + 0x1234u))

static int mock_init_calls;
static int mock_init_rc;
static char mock_last_play[64];
static char mock_last_rec[64];
static int mock_reset_calls;
static int mock_command_calls;
static uint32_t mock_last_verb;
static int mock_command_fail;	/* if set, command returns -1 (no response) */
static uint8_t mock_command_unsol;
static int mock_notify_calls;
static int mock_notify_rc;	/* return value from notify */
static uint8_t mock_last_run, mock_last_stream, mock_last_dir;
static uint8_t mock_codec_state = 0xAB;
static uint8_t mock_restored_state;
static int mock_snapshot_calls;

static int
mock_codec_init(struct hda_codec_inst *hci, const char *play, const char *rec)
{
	mock_init_calls++;
	/* Copy: hda_init frees the strdup'd config strings after we return. */
	mock_last_play[0] = mock_last_rec[0] = '\0';
	if (play != NULL)
		strlcpy(mock_last_play, play, sizeof(mock_last_play));
	if (rec != NULL)
		strlcpy(mock_last_rec, rec, sizeof(mock_last_rec));
	hci->priv = &mock_codec_state;
	return (mock_init_rc);
}

static int
mock_codec_reset(struct hda_codec_inst *hci __unused)
{
	mock_reset_calls++;
	return (0);
}

static int
mock_codec_command(struct hda_codec_inst *hci, uint32_t verb)
{
	mock_command_calls++;
	mock_last_verb = verb;
	if (mock_command_fail)
		return (-1);
	hci->hops->response(hci, MOCK_RESP(verb), mock_command_unsol);
	return (0);
}

static int
mock_codec_notify(struct hda_codec_inst *hci __unused, uint8_t run,
    uint8_t stream, uint8_t dir)
{
	mock_notify_calls++;
	mock_last_run = run;
	mock_last_stream = stream;
	mock_last_dir = dir;
	return (mock_notify_rc);
}

static int
mock_codec_snapshot(struct hda_codec_inst *hci __unused,
    struct vm_snapshot_meta *meta)
{
	uint8_t v = mock_codec_state;
	int ret;

	mock_snapshot_calls++;
	ret = vm_snapshot_u8(&v, meta);
	if (ret != 0)
		return (ret);
	if (vm_snapshot_is_restoring(meta))
		mock_restored_state = v;
	return (0);
}

static struct hda_codec_class mock_codec = {
	.name = "hda_codec",
	.init = mock_codec_init,
	.reset = mock_codec_reset,
	.command = mock_codec_command,
	.notify = mock_codec_notify,
	.snapshot = mock_codec_snapshot,
};
HDA_EMUL_SET(mock_codec);

static void
mock_reset_counters(void)
{
	mock_init_calls = 0;
	mock_init_rc = 0;
	mock_reset_calls = 0;
	mock_command_calls = 0;
	mock_last_verb = 0;
	mock_command_fail = 0;
	mock_command_unsol = 0;
	mock_notify_calls = 0;
	mock_notify_rc = 0;
	mock_snapshot_calls = 0;
	mock_restored_state = 0;
}

/* ------------------------------------------------------------------ */
/* Register / memory helpers                                           */
/* ------------------------------------------------------------------ */

/* Guest-physical layout inside the flat DMA buffer. */
#define	GPA_CORB	0x00001000u
#define	GPA_RIRB	0x00002000u
#define	GPA_DPIB	0x00003000u
#define	GPA_BDL		0x00004000u
#define	GPA_DATA0	0x00010000u
#define	GPA_DATA1	0x00020000u

/* Stream register block base for descriptor index i. */
#define	SREG(i, r)	(((uint32_t)(i) << 5) + (uint32_t)(r))

static struct pci_devinst *
hda_new(bool with_codec)
{
	struct pci_devinst *pi;

	pi = calloc(1, sizeof(*pi));
	ATF_REQUIRE(pi != NULL);
	mock_reset_counters();
	g_lintr_state = 0;
	g_lintr_asserts = 0;
	g_lintr_deasserts = 0;
	g_lintr_requested = 0;
	if (with_codec) {
		g_play = "/dev/dsp0";
		g_rec = "/dev/dsp0";
	} else {
		g_play = NULL;
		g_rec = NULL;
	}
	ATF_REQUIRE_EQ(0, pci_hda_init(pi, NULL));
	return (pi);
}

static struct hda_softc *
hda_sc(struct pci_devinst *pi)
{
	return ((struct hda_softc *)pi->pi_arg);
}

static void
wr(struct pci_devinst *pi, uint32_t off, int size, uint32_t val)
{
	pci_hda_write(pi, 0, off, size, val);
}

static uint32_t
rd(struct pci_devinst *pi, uint32_t off)
{
	return ((uint32_t)pci_hda_read(pi, 0, off, 4));
}

/* Write a single BDL entry into guest memory. */
static void
bdl_put(uint32_t bdl_gpa, unsigned idx, uint64_t addr, uint32_t len,
    uint32_t ioc)
{
	uint8_t *e = g_guest + bdl_gpa + idx * HDA_BDL_ENTRY_LEN;

	le32enc(e + 0, (uint32_t)(addr & 0xffffffffu));
	le32enc(e + 4, (uint32_t)(addr >> 32));
	le32enc(e + 8, len);
	le32enc(e + 12, ioc);
}

/*
 * Program and start one stream descriptor with a single-entry BDL of the
 * given length pointing at data_gpa, cyclic-buffer-length == len, stream tag
 * strm.  Returns after issuing the RUN write.
 */
static void
stream_program(struct pci_devinst *pi, unsigned i, uint64_t bdl_gpa,
    uint64_t data_gpa, uint32_t len, uint32_t ioc, uint8_t strm)
{
	bdl_put(bdl_gpa, 0, data_gpa, len, ioc);
	wr(pi, SREG(i, HDAC_SDBDPL), 4, (uint32_t)(bdl_gpa & 0xffffffffu));
	wr(pi, SREG(i, HDAC_SDBDPU), 4, (uint32_t)(bdl_gpa >> 32));
	wr(pi, SREG(i, HDAC_SDCBL), 4, len);
	wr(pi, SREG(i, HDAC_SDLVI), 4, 0);		/* bdl_cnt == 1 */
	wr(pi, SREG(i, HDAC_SDCTL2), 1, (uint32_t)strm << 4);
	wr(pi, SREG(i, HDAC_SDCTL0), 1, HDAC_SDCTL_RUN);
}

/* ================================================================== */
/* Tests                                                              */
/* ================================================================== */

ATF_TC_WITHOUT_HEAD(pci_init_and_reset_defaults);
ATF_TC_BODY(pci_init_and_reset_defaults, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;

	guest_reset();
	pi = hda_new(true);
	sc = hda_sc(pi);

	/* PCI identity: Intel 82801G HDA controller. */
	ATF_CHECK_EQ(0x8086, le16dec(&pi->pi_cfgdata[PCIR_VENDOR]));
	ATF_CHECK_EQ(0x27d8, le16dec(&pi->pi_cfgdata[PCIR_DEVICE]));
	ATF_CHECK_EQ(PCIS_MULTIMEDIA_HDA, pi->pi_cfgdata[PCIR_SUBCLASS]);
	ATF_CHECK_EQ(PCIC_MULTIMEDIA, pi->pi_cfgdata[PCIR_CLASS]);
	ATF_CHECK_EQ(0x01, pi->pi_cfgdata[PCIR_HDCTL]);

	/* BAR0 is a 32-bit memory BAR covering the register file. */
	ATF_CHECK_EQ(PCIBAR_MEM32, pi->pi_bar[0].type);
	ATF_CHECK_EQ(HDA_LAST_OFFSET, pi->pi_bar[0].size);
	ATF_CHECK_EQ(1, g_lintr_requested);

	/* One synthetic codec constructed with the configured play/rec. */
	ATF_CHECK_EQ(1, sc->codecs_no);
	ATF_CHECK_EQ(1, mock_init_calls);
	ATF_CHECK_STREQ("/dev/dsp0", mock_last_play);
	ATF_CHECK_STREQ("/dev/dsp0", mock_last_rec);

	/*
	 * HDA reset register values (Intel HDA spec, GCAP/version/ring size).
	 * GCAP: 64-bit OK, 4 input + 4 output streams.
	 */
	ATF_CHECK_EQ(HDAC_GCAP_64OK | (HDA_ISS_NO << HDAC_GCAP_ISS_SHIFT) |
	    (HDA_OSS_NO << HDAC_GCAP_OSS_SHIFT), rd(pi, HDAC_GCAP));
	ATF_CHECK_EQ(0x01, rd(pi, HDAC_VMAJ));
	ATF_CHECK_EQ(0x3c, rd(pi, HDAC_OUTPAY));
	ATF_CHECK_EQ(0x1d, rd(pi, HDAC_INPAY));
	ATF_CHECK_EQ(HDAC_CORBSIZE_CORBSZCAP_256 | HDAC_CORBSIZE_CORBSIZE_256,
	    rd(pi, HDAC_CORBSIZE));
	ATF_CHECK_EQ(HDAC_RIRBSIZE_RIRBSZCAP_256 | HDAC_RIRBSIZE_RIRBSIZE_256,
	    rd(pi, HDAC_RIRBSIZE));
	/* Every stream advertises the FIFO size. */
	for (unsigned i = 0; i < HDA_IOSS_NO; i++)
		ATF_CHECK_EQ(HDA_FIFO_SIZE, rd(pi, SREG(i, HDAC_SDFIFOS)));

	free(pi);
}

ATF_TC_WITHOUT_HEAD(init_without_codec_config);
ATF_TC_BODY(init_without_codec_config, tc __unused)
{
	struct pci_devinst *pi;

	guest_reset();
	/* No play/rec configured: codec class found but not constructed. */
	pi = hda_new(false);
	ATF_CHECK_EQ(0, hda_sc(pi)->codecs_no);
	ATF_CHECK_EQ(0, mock_init_calls);
	free(pi);
}

ATF_TC_WITHOUT_HEAD(mmio_access_guards);
ATF_TC_BODY(mmio_access_guards, tc __unused)
{
	struct pci_devinst *pi;
	struct pci_devinst empty = { 0 };

	guest_reset();
	pi = hda_new(true);

	/* Out-of-range and wrong-BAR reads read back all-ones. */
	ATF_CHECK_EQ(UINT64_MAX, pci_hda_read(pi, 0, HDA_LAST_OFFSET, 4));
	ATF_CHECK_EQ(UINT64_MAX, pci_hda_read(pi, 1, 0, 4));
	ATF_CHECK_EQ(UINT64_MAX, pci_hda_read(pi, 0, 0, 0));
	ATF_CHECK_EQ(UINT64_MAX, pci_hda_read(pi, 0, 0, 5));
	/* No pi_arg -> no device. */
	ATF_CHECK_EQ(UINT64_MAX, pci_hda_read(&empty, 0, 0, 4));

	/* Bad writes are silently ignored (must not crash or mutate). */
	wr(pi, HDA_LAST_OFFSET, 4, 0xffffffff);
	wr(pi, 0, 0, 0xffffffff);		/* size 0 */
	pci_hda_write(pi, 1, 0, 4, 0xffffffff);	/* wrong bar */
	pci_hda_write(&empty, 0, 0, 4, 0xffffffff);
	pci_hda_write(pi, 0, 0, 5, 0xffffffff);	/* size 5 */

	/* Wall clock read takes the synthesized branch and is monotone-ish. */
	(void)pci_hda_read(pi, 0, HDAC_WALCLK, 4);

	free(pi);
}

/*
 * Full CORB -> codec -> RIRB path: a verb placed in the CORB ring is consumed
 * by the DMA engine, dispatched to the codec, and the codec response is
 * written into the RIRB ring at the correct slot with the correct extended
 * dword (codec address in the low nibble).
 */
ATF_TC_WITHOUT_HEAD(corb_rirb_verb_roundtrip);
ATF_TC_BODY(corb_rirb_verb_roundtrip, tc __unused)
{
	struct pci_devinst *pi;
	const uint32_t verb = 0x000f0000;	/* GET_PARAMETER-ish */
	uint32_t resp, resp_ex;

	guest_reset();
	pi = hda_new(true);

	/* Point the rings at guest memory. */
	wr(pi, HDAC_CORBLBASE, 4, GPA_CORB);
	wr(pi, HDAC_CORBUBASE, 4, 0);
	wr(pi, HDAC_RIRBLBASE, 4, GPA_RIRB);
	wr(pi, HDAC_RIRBUBASE, 4, 0);

	/* The engine consumes rp+1 first; stage the verb at CORB entry 1. */
	le32enc(g_guest + GPA_CORB + 1 * HDA_CORB_ENTRY_LEN, verb);

	/* Start RIRB then CORB DMA engines. */
	wr(pi, HDAC_RIRBCTL, 1, HDAC_RIRBCTL_RIRBDMAEN);
	wr(pi, HDAC_CORBCTL, 1, HDAC_CORBCTL_CORBRUN);
	ATF_CHECK_EQ(HDAC_CORBCTL_CORBRUN,
	    rd(pi, HDAC_CORBCTL) & HDAC_CORBCTL_CORBRUN);

	/* Kick the write pointer: this drives one verb through the codec. */
	wr(pi, HDAC_CORBWP, 2, 1);

	ATF_CHECK_EQ(1, mock_command_calls);
	ATF_CHECK_EQ(verb, mock_last_verb);
	/* Read pointer advanced to the consumed slot. */
	ATF_CHECK_EQ(1, rd(pi, HDAC_CORBRP) & 0xff);
	/* RIRB write pointer advanced to slot 1. */
	ATF_CHECK_EQ(1, rd(pi, HDAC_RIRBWP) & 0xff);

	/* RIRB entry 1: dword0 = response, dword1 = response_ex (cad 0). */
	resp = le32dec(g_guest + GPA_RIRB + 1 * HDA_RIRB_ENTRY_LEN);
	resp_ex = le32dec(g_guest + GPA_RIRB + 1 * HDA_RIRB_ENTRY_LEN + 4);
	ATF_CHECK_EQ(MOCK_RESP(verb), resp);
	ATF_CHECK_EQ(0u, resp_ex);
	ATF_CHECK(g_dirty_calls > 0);

	free(pi);
}

/* A verb the codec rejects stops the CORB engine and latches CMEI. */
ATF_TC_WITHOUT_HEAD(corb_command_error_stops_engine);
ATF_TC_BODY(corb_command_error_stops_engine, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;

	guest_reset();
	pi = hda_new(true);
	sc = hda_sc(pi);
	wr(pi, HDAC_CORBLBASE, 4, GPA_CORB);
	wr(pi, HDAC_RIRBLBASE, 4, GPA_RIRB);
	le32enc(g_guest + GPA_CORB + 1 * HDA_CORB_ENTRY_LEN, 0x00abcdef);
	wr(pi, HDAC_RIRBCTL, 1, HDAC_RIRBCTL_RIRBDMAEN);
	wr(pi, HDAC_CORBCTL, 1, HDAC_CORBCTL_CORBRUN);

	mock_command_fail = 1;
	wr(pi, HDAC_CORBWP, 2, 1);

	/* Command memory error interrupt latched; engine stopped. */
	ATF_CHECK_EQ(HDAC_CORBSTS_CMEI,
	    rd(pi, HDAC_CORBSTS) & HDAC_CORBSTS_CMEI);
	ATF_CHECK_EQ(0u, rd(pi, HDAC_CORBCTL) & HDAC_CORBCTL_CORBRUN);
	/* The consumed read pointer is published (failed verb not replayed). */
	ATF_CHECK_EQ(1, rd(pi, HDAC_CORBRP) & 0xff);
	ATF_CHECK_EQ(0, sc->corb.run);

	free(pi);
}

/* Invalid ring size codes make the DMA-start handlers fail closed. */
ATF_TC_WITHOUT_HEAD(corb_rirb_invalid_size);
ATF_TC_BODY(corb_rirb_invalid_size, tc __unused)
{
	struct pci_devinst *pi;

	guest_reset();
	pi = hda_new(true);
	wr(pi, HDAC_CORBLBASE, 4, GPA_CORB);
	wr(pi, HDAC_RIRBLBASE, 4, GPA_RIRB);

	/* Reserved size code -> hda_corb_sizes[] == 0 -> start fails. */
	wr(pi, HDAC_CORBSIZE, 1, HDAC_CORBSIZE_CORBSIZE_MASK);
	wr(pi, HDAC_CORBCTL, 1, HDAC_CORBCTL_CORBRUN);
	ATF_CHECK_EQ(0u, rd(pi, HDAC_CORBCTL) & HDAC_CORBCTL_CORBRUN);
	ATF_CHECK_EQ(HDAC_CORBSTS_CMEI,
	    rd(pi, HDAC_CORBSTS) & HDAC_CORBSTS_CMEI);

	wr(pi, HDAC_RIRBSIZE, 1, HDAC_RIRBSIZE_RIRBSIZE_MASK);
	wr(pi, HDAC_RIRBCTL, 1, HDAC_RIRBCTL_RIRBDMAEN);
	ATF_CHECK_EQ(0u, rd(pi, HDAC_RIRBCTL) & HDAC_RIRBCTL_RIRBDMAEN);
	ATF_CHECK_EQ(HDAC_RIRBSTS_RIRBOIS,
	    rd(pi, HDAC_RIRBSTS) & HDAC_RIRBSTS_RIRBOIS);

	free(pi);
}

/* DMA mapping failure makes ring/pib/stream starts fail closed. */
ATF_TC_WITHOUT_HEAD(dma_mapping_failures);
ATF_TC_BODY(dma_mapping_failures, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;

	guest_reset();
	pi = hda_new(true);
	sc = hda_sc(pi);
	wr(pi, HDAC_CORBLBASE, 4, GPA_CORB);
	wr(pi, HDAC_RIRBLBASE, 4, GPA_RIRB);

	g_dma_fail = true;
	wr(pi, HDAC_CORBCTL, 1, HDAC_CORBCTL_CORBRUN);
	ATF_CHECK_EQ(0u, rd(pi, HDAC_CORBCTL) & HDAC_CORBCTL_CORBRUN);
	wr(pi, HDAC_RIRBCTL, 1, HDAC_RIRBCTL_RIRBDMAEN);
	ATF_CHECK_EQ(0u, rd(pi, HDAC_RIRBCTL) & HDAC_RIRBCTL_RIRBDMAEN);

	/* DMA position buffer mapping failure clears the enable bit. */
	wr(pi, HDAC_DPIBUBASE, 4, 0);
	wr(pi, HDAC_DPIBLBASE, 4, GPA_DPIB | HDAC_DPLBASE_DPLBASE_DMAPBE);
	ATF_CHECK_EQ(0u, rd(pi, HDAC_DPIBLBASE) & HDAC_DPLBASE_DPLBASE_DMAPBE);
	ATF_CHECK(sc->dma_pib_vaddr == NULL);

	/* Direct: zero-length and paddr-overflow mappings are refused. */
	ATF_CHECK(hda_dma_get_vaddr(sc, 0, 0, PCI_DMA_DEVICE_READ) == NULL);
	g_dma_fail = false;
	ATF_CHECK(hda_dma_get_vaddr(sc, 0, 0, PCI_DMA_DEVICE_READ) == NULL);

	free(pi);
}

/* DMA position buffer enable then disable. */
ATF_TC_WITHOUT_HEAD(dma_position_buffer_toggle);
ATF_TC_BODY(dma_position_buffer_toggle, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;

	guest_reset();
	pi = hda_new(true);
	sc = hda_sc(pi);

	wr(pi, HDAC_DPIBUBASE, 4, 0);
	wr(pi, HDAC_DPIBLBASE, 4, GPA_DPIB | HDAC_DPLBASE_DPLBASE_DMAPBE);
	ATF_CHECK(sc->dma_pib_vaddr == g_guest + GPA_DPIB);

	/* Writing with the enable bit unchanged is a no-op. */
	wr(pi, HDAC_DPIBLBASE, 4, GPA_DPIB | HDAC_DPLBASE_DPLBASE_DMAPBE);
	ATF_CHECK(sc->dma_pib_vaddr == g_guest + GPA_DPIB);

	/* Clearing the enable bit resets the pointer. */
	wr(pi, HDAC_DPIBLBASE, 4, GPA_DPIB);
	ATF_CHECK(sc->dma_pib_vaddr == NULL);

	free(pi);
}

/*
 * Output stream: program a BDL, run it, and drive a playback transfer that
 * the device reads out of guest memory dword by dword, wrapping the cyclic
 * buffer and raising BCIS on the interrupt-on-completion entry.
 */
ATF_TC_WITHOUT_HEAD(output_stream_transfer);
ATF_TC_BODY(output_stream_transfer, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;
	const unsigned si = HDA_ISS_NO;		/* first output descriptor */
	const uint8_t strm = 3;
	const uint32_t len = 16;		/* cyclic buffer length */
	uint8_t out[16];
	uint32_t pib;

	guest_reset();
	pi = hda_new(true);
	sc = hda_sc(pi);

	/* Enable the DMA position buffer to exercise hda_set_pib fully. */
	wr(pi, HDAC_DPIBUBASE, 4, 0);
	wr(pi, HDAC_DPIBLBASE, 4, GPA_DPIB | HDAC_DPLBASE_DPLBASE_DMAPBE);

	/* Fill guest data buffer with a known ramp. */
	for (uint32_t k = 0; k < len; k++)
		g_guest[GPA_DATA0 + k] = (uint8_t)(0x10 + k);

	/*
	 * Two BDL entries of 8 bytes each (cbl == 16).  IOC on the first entry
	 * fires when its byte cursor completes, which happens strictly before
	 * the cyclic buffer wraps at cbl -- the wrap branch would otherwise
	 * swallow the interrupt-on-completion.
	 */
	bdl_put(GPA_BDL, 0, GPA_DATA0, 8, 1 /*ioc*/);
	bdl_put(GPA_BDL, 1, GPA_DATA0 + 8, 8, 0);
	wr(pi, SREG(si, HDAC_SDBDPL), 4, GPA_BDL);
	wr(pi, SREG(si, HDAC_SDBDPU), 4, 0);
	wr(pi, SREG(si, HDAC_SDCBL), 4, len);
	wr(pi, SREG(si, HDAC_SDLVI), 4, 1);		/* bdl_cnt == 2 */
	wr(pi, SREG(si, HDAC_SDCTL2), 1, (uint32_t)strm << 4);
	wr(pi, SREG(si, HDAC_SDCTL0), 1, HDAC_SDCTL_RUN);

	ATF_REQUIRE_EQ(1, sc->streams[si].run);
	ATF_CHECK_EQ(strm, sc->streams[si].stream);
	ATF_CHECK_EQ(1, sc->streams[si].dir);	/* output */
	ATF_CHECK_EQ(si, sc->stream_map[1][strm]);
	ATF_CHECK_EQ(1, mock_notify_calls);
	ATF_CHECK_EQ(1, mock_last_run);
	/* PIB reset to 0 at start. */
	ATF_CHECK_EQ(0u, rd(pi, SREG(si, HDAC_SDLPIB)));

	/* Playback the whole cyclic buffer (device reads guest -> out). */
	ATF_REQUIRE_EQ(0, hda_transfer(sc->codecs[0], strm, 1, out, len));
	for (uint32_t k = 0; k < len; k++)
		ATF_CHECK_EQ((uint8_t)(0x10 + k), out[k]);

	/* Exactly one cyclic buffer consumed -> LPIB wrapped back to 0. */
	pib = rd(pi, SREG(si, HDAC_SDLPIB));
	ATF_CHECK_EQ(0u, pib);
	/* Position buffer updated in guest memory. */
	ATF_CHECK_EQ(0u, le32dec(g_guest + GPA_DPIB + si * HDA_DMA_PIB_ENTRY_LEN));
	/* IOC entry raised BCIS. */
	ATF_CHECK_EQ(HDAC_SDSTS_BCIS,
	    rd(pi, SREG(si, HDAC_SDSTS)) & HDAC_SDSTS_BCIS);

	/* Guest clears BCIS (write-1-to-clear) via the SDSTS handler. */
	wr(pi, SREG(si, HDAC_SDSTS), 1, HDAC_SDSTS_BCIS);
	ATF_CHECK_EQ(0u, rd(pi, SREG(si, HDAC_SDSTS)) & HDAC_SDSTS_BCIS);

	free(pi);
}

/*
 * Input stream: the device writes captured audio into guest memory and marks
 * it dirty.  Transfer only part of the cyclic buffer so LPIB advances without
 * wrapping.
 */
ATF_TC_WITHOUT_HEAD(input_stream_transfer);
ATF_TC_BODY(input_stream_transfer, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;
	const unsigned si = 0;			/* first input descriptor */
	const uint8_t strm = 5;
	const uint32_t len = 32;
	uint8_t in[8];

	guest_reset();
	pi = hda_new(true);
	sc = hda_sc(pi);

	stream_program(pi, si, GPA_BDL, GPA_DATA1, len, 0 /*no ioc*/, strm);
	ATF_REQUIRE_EQ(1, sc->streams[si].run);
	ATF_CHECK_EQ(0, sc->streams[si].dir);	/* input */
	ATF_CHECK_EQ(si, sc->stream_map[0][strm]);

	for (unsigned k = 0; k < sizeof(in); k++)
		in[k] = (uint8_t)(0xA0 + k);

	g_dirty_calls = 0;
	ATF_REQUIRE_EQ(0, hda_transfer(sc->codecs[0], strm, 0, in, sizeof(in)));
	for (unsigned k = 0; k < sizeof(in); k++)
		ATF_CHECK_EQ((uint8_t)(0xA0 + k), g_guest[GPA_DATA1 + k]);
	ATF_CHECK(g_dirty_calls > 0);

	/* LPIB advanced by the transferred byte count, no wrap. */
	ATF_CHECK_EQ((uint32_t)sizeof(in), rd(pi, SREG(si, HDAC_SDLPIB)));

	free(pi);
}

/* Stream start rejects malformed BDL/geometry programming. */
ATF_TC_WITHOUT_HEAD(stream_start_rejections);
ATF_TC_BODY(stream_start_rejections, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;
	const unsigned si = HDA_ISS_NO;

	guest_reset();
	pi = hda_new(true);
	sc = hda_sc(pi);

	/* Out-of-range descriptor index (direct), start and stop. */
	ATF_CHECK_EQ(-1, hda_stream_start(sc, HDA_IOSS_NO));
	ATF_CHECK_EQ(-1, hda_stream_stop(sc, HDA_IOSS_NO));

	/* Stream tag 0 never runs: RUN write is rejected, DESE latched. */
	bdl_put(GPA_BDL, 0, GPA_DATA0, 16, 0);
	wr(pi, SREG(si, HDAC_SDBDPL), 4, GPA_BDL);
	wr(pi, SREG(si, HDAC_SDCBL), 4, 16);
	wr(pi, SREG(si, HDAC_SDLVI), 4, 0);
	wr(pi, SREG(si, HDAC_SDCTL0), 1, HDAC_SDCTL_RUN);	/* tag 0 */
	ATF_CHECK_EQ(0u, rd(pi, SREG(si, HDAC_SDCTL0)) & HDAC_SDCTL_RUN);
	ATF_CHECK_EQ(HDAC_SDSTS_DESE,
	    rd(pi, SREG(si, HDAC_SDSTS)) & HDAC_SDSTS_DESE);
	ATF_CHECK_EQ(0, sc->streams[si].run);

	/* cbl == 0 is rejected (direct programming + start). */
	wr(pi, SREG(si, HDAC_SDCTL2), 1, 2u << 4);
	wr(pi, SREG(si, HDAC_SDCBL), 4, 0);
	ATF_CHECK_EQ(-1, hda_stream_start(sc, si));

	/* cbl not dword-aligned. */
	wr(pi, SREG(si, HDAC_SDCBL), 4, 6);
	ATF_CHECK_EQ(-1, hda_stream_start(sc, si));

	/* bdl_cnt too large (LVI+1 > HDA_BDL_MAX_LEN). */
	wr(pi, SREG(si, HDAC_SDCBL), 4, 16);
	wr(pi, SREG(si, HDAC_SDLVI), 4, HDA_BDL_MAX_LEN);
	ATF_CHECK_EQ(-1, hda_stream_start(sc, si));
	wr(pi, SREG(si, HDAC_SDLVI), 4, 0);

	/* BDL entry length 0. */
	bdl_put(GPA_BDL, 0, GPA_DATA0, 0, 0);
	ATF_CHECK_EQ(-1, hda_stream_start(sc, si));

	/* BDL entry length not dword-aligned. */
	bdl_put(GPA_BDL, 0, GPA_DATA0, 6, 0);
	ATF_CHECK_EQ(-1, hda_stream_start(sc, si));

	/* Total BDL coverage smaller than the cyclic buffer length. */
	bdl_put(GPA_BDL, 0, GPA_DATA0, 8, 0);
	wr(pi, SREG(si, HDAC_SDCBL), 4, 16);
	ATF_CHECK_EQ(-1, hda_stream_start(sc, si));

	/* A per-BDLE mapping failure aborts the walk. */
	bdl_put(GPA_BDL, 0, GPA_DATA0, 16, 0);
	wr(pi, SREG(si, HDAC_SDCBL), 4, 16);
	g_dma_fail_gpa = GPA_DATA0;
	ATF_CHECK_EQ(-1, hda_stream_start(sc, si));
	g_dma_fail_gpa = 0;

	/* A BDL-base mapping failure aborts before the walk begins. */
	g_dma_fail_gpa = GPA_BDL;
	ATF_CHECK_EQ(-1, hda_stream_start(sc, si));
	g_dma_fail_gpa = 0;

	free(pi);
}

/* Starting an already-running descriptor and tag collisions are rejected. */
ATF_TC_WITHOUT_HEAD(stream_double_start_and_tag_collision);
ATF_TC_BODY(stream_double_start_and_tag_collision, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;
	const unsigned si = HDA_ISS_NO;		/* output 0 */
	const unsigned sj = HDA_ISS_NO + 1;	/* output 1 */
	const uint8_t strm = 4;

	guest_reset();
	pi = hda_new(true);
	sc = hda_sc(pi);

	stream_program(pi, si, GPA_BDL, GPA_DATA0, 16, 0, strm);
	ATF_REQUIRE_EQ(1, sc->streams[si].run);

	/* Re-issuing RUN on the running descriptor is a no-op (still runs). */
	ATF_CHECK_EQ(-1, hda_stream_start(sc, si));

	/* A second descriptor claiming the same tag/direction is refused. */
	bdl_put(GPA_BDL + 0x100, 0, GPA_DATA1, 16, 0);
	wr(pi, SREG(sj, HDAC_SDBDPL), 4, GPA_BDL + 0x100);
	wr(pi, SREG(sj, HDAC_SDCBL), 4, 16);
	wr(pi, SREG(sj, HDAC_SDLVI), 4, 0);
	wr(pi, SREG(sj, HDAC_SDCTL2), 1, (uint32_t)strm << 4);
	wr(pi, SREG(sj, HDAC_SDCTL0), 1, HDAC_SDCTL_RUN);
	ATF_CHECK_EQ(0, sc->streams[sj].run);

	free(pi);
}

/* SRST resets a running stream descriptor and stops it. */
ATF_TC_WITHOUT_HEAD(stream_reset);
ATF_TC_BODY(stream_reset, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;
	const unsigned si = HDA_ISS_NO;
	const uint8_t strm = 6;

	guest_reset();
	pi = hda_new(true);
	sc = hda_sc(pi);

	stream_program(pi, si, GPA_BDL, GPA_DATA0, 16, 0, strm);
	ATF_REQUIRE_EQ(1, sc->streams[si].run);

	/* SRST bit -> stream reset -> FIFORDY set, SRST latched, stopped. */
	wr(pi, SREG(si, HDAC_SDCTL0), 1, HDAC_SDCTL_SRST);
	ATF_CHECK_EQ(0, sc->streams[si].run);
	ATF_CHECK_EQ(HDAC_SDSTS_FIFORDY,
	    rd(pi, SREG(si, HDAC_SDSTS)) & HDAC_SDSTS_FIFORDY);
	ATF_CHECK_EQ(HDAC_SDCTL_SRST,
	    rd(pi, SREG(si, HDAC_SDCTL0)) & HDAC_SDCTL_SRST);
	/* Tag released. */
	ATF_CHECK_EQ(UINT8_MAX, sc->stream_map[1][strm]);

	/* Stopping via clearing RUN on a stopped stream is a no-op path. */
	wr(pi, SREG(si, HDAC_SDCTL0), 1, 0);

	free(pi);
}

/* Explicit RUN->stop of a running stream via clearing the RUN bit. */
ATF_TC_WITHOUT_HEAD(stream_stop_via_run_clear);
ATF_TC_BODY(stream_stop_via_run_clear, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;
	const unsigned si = 0;
	const uint8_t strm = 2;

	guest_reset();
	pi = hda_new(true);
	sc = hda_sc(pi);

	stream_program(pi, si, GPA_BDL, GPA_DATA0, 16, 0, strm);
	ATF_REQUIRE_EQ(1, sc->streams[si].run);

	/* Clear RUN (preserve tag bits): stream stops, tag released. */
	wr(pi, SREG(si, HDAC_SDCTL0), 1, 0);
	ATF_CHECK_EQ(0, sc->streams[si].run);
	ATF_CHECK_EQ(UINT8_MAX, sc->stream_map[0][strm]);
	ATF_CHECK_EQ(2, mock_notify_calls);	/* start + stop */
	ATF_CHECK_EQ(0, mock_last_run);

	free(pi);
}

/* hda_transfer argument validation and state-machine rejections. */
ATF_TC_WITHOUT_HEAD(transfer_rejections);
ATF_TC_BODY(transfer_rejections, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;
	struct hda_codec_inst *hci;
	const unsigned si = HDA_ISS_NO;
	const uint8_t strm = 7;
	uint8_t buf[8] = { 0 };

	guest_reset();
	pi = hda_new(true);
	sc = hda_sc(pi);
	hci = sc->codecs[0];

	/* Early argument checks (no lock taken). */
	ATF_CHECK_EQ(-1, hda_transfer(NULL, strm, 1, buf, 4));
	ATF_CHECK_EQ(-1, hda_transfer(hci, strm, 1, NULL, 4));
	ATF_CHECK_EQ(-1, hda_transfer(hci, strm, 1, buf, 0));
	ATF_CHECK_EQ(-1, hda_transfer(hci, strm, 1, buf, 3));	/* not %4 */
	ATF_CHECK_EQ(-1, hda_transfer(hci, strm, 2, buf, 4));	/* dir > 1 */
	ATF_CHECK_EQ(-1, hda_transfer(hci, 0, 1, buf, 4));	/* tag 0 */

	/* Tag out of range. */
	ATF_CHECK_EQ(-1, hda_transfer(hci, HDA_STREAM_TAGS_CNT, 1, buf, 4));

	/* Tag not mapped to any descriptor. */
	ATF_CHECK_EQ(-1, hda_transfer(hci, strm, 1, buf, 4));

	/* Direction mismatch: map an output descriptor, transfer as input. */
	stream_program(pi, si, GPA_BDL, GPA_DATA0, 16, 0, strm);
	ATF_REQUIRE_EQ(1, sc->streams[si].run);
	ATF_CHECK_EQ(-1, hda_transfer(hci, strm, 0, buf, 4));

	/* Mapped + running but tag mismatch on the descriptor. */
	sc->streams[si].stream = strm + 1;
	ATF_CHECK_EQ(-1, hda_transfer(hci, strm, 1, buf, 4));
	sc->streams[si].stream = strm;

	/* Mapped tag but descriptor stopped. */
	sc->streams[si].run = 0;
	ATF_CHECK_EQ(-1, hda_transfer(hci, strm, 1, buf, 4));

	free(pi);
}

/* GCTL controlled reset clears device state and deasserts the line. */
ATF_TC_WITHOUT_HEAD(gctl_reset);
ATF_TC_BODY(gctl_reset, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;
	const unsigned si = HDA_ISS_NO;

	guest_reset();
	pi = hda_new(true);
	sc = hda_sc(pi);

	/* Bring the interrupt line high via a codec state-change signal. */
	wr(pi, HDAC_INTCTL, 4, HDAC_INTCTL_GIE | 0x40000000);
	wr(pi, HDAC_WAKEEN, 2, 0x0001);
	ATF_REQUIRE_EQ(0, hda_signal_state_change(sc->codecs[0]));
	ATF_REQUIRE_EQ(1, g_lintr_state);

	/* Run a stream so reset must tear it down too. */
	stream_program(pi, si, GPA_BDL, GPA_DATA0, 16, 0, 1);
	ATF_REQUIRE_EQ(1, sc->streams[si].run);

	/* Writing GCTL with CRST clear triggers the controller reset. */
	wr(pi, HDAC_GCTL, 4, 0);
	ATF_CHECK_EQ(0, sc->streams[si].run);
	ATF_CHECK_EQ(0, g_lintr_state);
	ATF_CHECK(mock_reset_calls > 0);
	/* Registers back to reset defaults. */
	ATF_CHECK_EQ(HDAC_GCAP_64OK | (HDA_ISS_NO << HDAC_GCAP_ISS_SHIFT) |
	    (HDA_OSS_NO << HDAC_GCAP_OSS_SHIFT), rd(pi, HDAC_GCAP));

	/* Writing GCTL with CRST set does not reset. */
	mock_reset_calls = 0;
	wr(pi, HDAC_GCTL, 4, HDAC_GCTL_CRST);
	ATF_CHECK_EQ(0, mock_reset_calls);

	free(pi);
}

/* State-change status / wake-enable interrupt gating and clearing. */
ATF_TC_WITHOUT_HEAD(statests_interrupt);
ATF_TC_BODY(statests_interrupt, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;

	guest_reset();
	pi = hda_new(true);
	sc = hda_sc(pi);

	/* Without GIE, a state change latches STATESTS but no line. */
	wr(pi, HDAC_WAKEEN, 2, 0x0001);
	ATF_REQUIRE_EQ(0, hda_signal_state_change(sc->codecs[0]));
	ATF_CHECK_EQ(0x0001, rd(pi, HDAC_STATESTS) & 0x0001);
	ATF_CHECK_EQ(0, g_lintr_state);

	/* Enable global + controller interrupt and re-signal: line asserts. */
	wr(pi, HDAC_INTCTL, 4, HDAC_INTCTL_GIE | 0x40000000);
	ATF_REQUIRE_EQ(0, hda_signal_state_change(sc->codecs[0]));
	ATF_CHECK_EQ(1, g_lintr_state);
	ATF_CHECK_EQ(HDAC_INTSTS_CIS | HDAC_INTSTS_GIS,
	    rd(pi, HDAC_INTSTS) & (HDAC_INTSTS_CIS | HDAC_INTSTS_GIS));

	/* Guest clears the STATESTS bit (write-1-to-clear) -> line drops. */
	wr(pi, HDAC_STATESTS, 2, 0x0001);
	ATF_CHECK_EQ(0u, rd(pi, HDAC_STATESTS) & 0x0001);
	ATF_CHECK_EQ(0, g_lintr_state);

	free(pi);
}

/* RIRB response-count interrupt, and RIRBSTS/RIRBWP/CORBRP control writes. */
ATF_TC_WITHOUT_HEAD(rirb_response_interrupt_and_pointer_resets);
ATF_TC_BODY(rirb_response_interrupt_and_pointer_resets, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;

	guest_reset();
	pi = hda_new(true);
	sc = hda_sc(pi);

	wr(pi, HDAC_CORBLBASE, 4, GPA_CORB);
	wr(pi, HDAC_RIRBLBASE, 4, GPA_RIRB);
	le32enc(g_guest + GPA_CORB + 1 * HDA_CORB_ENTRY_LEN, 0x00010203);

	/* Interrupt after a single response. */
	wr(pi, HDAC_RINTCNT, 2, 1);
	wr(pi, HDAC_INTCTL, 4, HDAC_INTCTL_GIE | HDAC_INTSTS_CIS);
	wr(pi, HDAC_RIRBCTL, 1,
	    HDAC_RIRBCTL_RIRBDMAEN | HDAC_RIRBCTL_RINTCTL);
	wr(pi, HDAC_CORBCTL, 1, HDAC_CORBCTL_CORBRUN);
	wr(pi, HDAC_CORBWP, 2, 1);

	ATF_CHECK_EQ(HDAC_RIRBSTS_RINTFL,
	    rd(pi, HDAC_RIRBSTS) & HDAC_RIRBSTS_RINTFL);
	ATF_CHECK_EQ(1, g_lintr_state);

	/* Guest clears RINTFL -> line drops. */
	wr(pi, HDAC_RIRBSTS, 1, HDAC_RIRBSTS_RINTFL);
	ATF_CHECK_EQ(0u, rd(pi, HDAC_RIRBSTS) & HDAC_RIRBSTS_RINTFL);
	ATF_CHECK_EQ(0, g_lintr_state);

	/* RIRBWP reset bit zeroes the write pointer and count. */
	wr(pi, HDAC_RIRBWP, 2, HDAC_RIRBWP_RIRBWPRST);
	ATF_CHECK_EQ(0u, rd(pi, HDAC_RIRBWP) & 0xff);
	ATF_CHECK_EQ(0, sc->rirb.wp);
	ATF_CHECK_EQ(0, sc->rirb_cnt);
	/* RIRBWP without reset bit is preserved at its old value. */
	wr(pi, HDAC_RIRBWP, 2, 0x0005);
	ATF_CHECK_EQ(0u, rd(pi, HDAC_RIRBWP) & 0xff);

	/* CORBRP reset bit zeroes the read pointer. */
	wr(pi, HDAC_CORBRP, 2, HDAC_CORBRP_CORBRPRST);
	ATF_CHECK_EQ(0u, rd(pi, HDAC_CORBRP) & 0xff);
	ATF_CHECK_EQ(0, sc->corb.rp);
	/* CORBRP without reset bit keeps the old value. */
	wr(pi, HDAC_CORBRP, 2, 0x0007);
	ATF_CHECK_EQ(0u, rd(pi, HDAC_CORBRP) & 0xff);

	free(pi);
}

/* CORBWP kick with wp beyond the ring size fails the run harmlessly. */
ATF_TC_WITHOUT_HEAD(corb_run_wp_out_of_range);
ATF_TC_BODY(corb_run_wp_out_of_range, tc __unused)
{
	struct pci_devinst *pi;

	guest_reset();
	pi = hda_new(true);
	wr(pi, HDAC_CORBLBASE, 4, GPA_CORB);
	wr(pi, HDAC_RIRBLBASE, 4, GPA_RIRB);
	wr(pi, HDAC_RIRBCTL, 1, HDAC_RIRBCTL_RIRBDMAEN);
	wr(pi, HDAC_CORBCTL, 1, HDAC_CORBCTL_CORBRUN);

	/* wp == 512 >= size 256; run bails and dispatches nothing. */
	wr(pi, HDAC_CORBWP, 2, 512);
	ATF_CHECK_EQ(0, mock_command_calls);

	free(pi);
}

/* CORBCTL stop path clears the CORB command control block. */
ATF_TC_WITHOUT_HEAD(corb_stop_clears_state);
ATF_TC_BODY(corb_stop_clears_state, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;

	guest_reset();
	pi = hda_new(true);
	sc = hda_sc(pi);
	wr(pi, HDAC_CORBLBASE, 4, GPA_CORB);
	wr(pi, HDAC_RIRBLBASE, 4, GPA_RIRB);
	wr(pi, HDAC_RIRBCTL, 1, HDAC_RIRBCTL_RIRBDMAEN);
	wr(pi, HDAC_CORBCTL, 1, HDAC_CORBCTL_CORBRUN);
	ATF_REQUIRE_EQ(1, sc->corb.run);

	/* Clearing CORBRUN memsets the CORB control block. */
	wr(pi, HDAC_CORBCTL, 1, 0);
	ATF_CHECK_EQ(0, sc->corb.run);
	ATF_CHECK(sc->corb.dma_vaddr == NULL);

	/* RIRB stop likewise. */
	wr(pi, HDAC_RIRBCTL, 1, 0);
	ATF_CHECK_EQ(0, sc->rirb.run);

	free(pi);
}

/* hda_response with the RIRB engine stopped drops the response. */
ATF_TC_WITHOUT_HEAD(response_without_running_rirb);
ATF_TC_BODY(response_without_running_rirb, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;

	guest_reset();
	pi = hda_new(true);
	sc = hda_sc(pi);

	/* Not started: run == 0 -> no DMA write, wp unchanged. */
	ATF_REQUIRE_EQ(0, hda_response(sc->codecs[0], 0xdeadbeef, 0x10));
	ATF_CHECK_EQ(0, sc->rirb.wp);
	ATF_CHECK_EQ(0, sc->rirb_cnt);

	free(pi);
}

/* Codec dispatch and construction edge cases exercised directly. */
ATF_TC_WITHOUT_HEAD(codec_dispatch_edges);
ATF_TC_BODY(codec_dispatch_edges, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;
	struct hda_codec_inst hci = { 0 };
	struct hda_codec_class cls = { 0 };

	guest_reset();
	pi = hda_new(true);
	sc = hda_sc(pi);

	/* Codec address beyond the populated codec count. */
	ATF_CHECK_EQ(-1, hda_send_command(sc, 5u << HDA_CMD_CAD_SHIFT));

	/* A codec class without a command handler. */
	hci.hda = sc;
	hci.codec = &cls;
	hci.cad = 0;
	sc->codecs[0] = &hci;
	sc->codecs_no = 1;
	ATF_CHECK_EQ(-1, hda_send_command(sc, 0));

	/* notify with no handler falls through to failure. */
	ATF_CHECK_EQ(-1, hda_notify_codecs(sc, 1, 3, 1));

	/* A codec whose only notify returns error also fails. */
	cls.notify = mock_codec_notify;
	mock_notify_rc = -1;
	ATF_CHECK_EQ(-1, hda_notify_codecs(sc, 1, 3, 1));
	mock_notify_rc = 0;
	ATF_CHECK_EQ(0, hda_notify_codecs(sc, 1, 3, 1));

	/* Restore real codec bookkeeping before teardown. */
	sc->codecs[0] = NULL;
	sc->codecs_no = 0;
	free(pi);
}

/* hda_codec_constructor failure branches. */
ATF_TC_WITHOUT_HEAD(codec_constructor_failures);
ATF_TC_BODY(codec_constructor_failures, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;
	struct hda_codec_class no_init = { .name = "x" };
	struct hda_codec_class bad_init = {
		.name = "x", .init = mock_codec_init
	};

	guest_reset();
	pi = hda_new(false);		/* no codec constructed yet */
	sc = hda_sc(pi);

	/* Class with no init handler. */
	ATF_CHECK_EQ(-1, hda_codec_constructor(sc, &no_init, NULL, NULL));

	/* init handler that reports failure. */
	mock_init_rc = -1;
	ATF_CHECK_EQ(-1, hda_codec_constructor(sc, &bad_init, "p", "r"));
	mock_init_rc = 0;

	/* Codec table already full. */
	sc->codecs_no = HDA_CODEC_MAX;
	ATF_CHECK_EQ(-1, hda_codec_constructor(sc, &bad_init, "p", "r"));
	sc->codecs_no = 0;

	free(pi);
}

/* find_codec_class returns NULL for an unknown name. */
ATF_TC_WITHOUT_HEAD(find_codec_class_lookup);
ATF_TC_BODY(find_codec_class_lookup, tc __unused)
{
	ATF_CHECK(hda_find_codec_class("hda_codec") == &mock_codec);
	ATF_CHECK(hda_find_codec_class("does-not-exist") == NULL);
}

/*
 * Full checkpoint round-trip: save a device with a running output stream,
 * running CORB/RIRB rings and an active DMA position buffer, then restore into
 * a fresh device backed by the same guest memory and verify the register file,
 * ring geometry and stream descriptors are faithfully rebuilt.
 */
static void
build_active_device(struct pci_devinst *pi)
{
	const unsigned si = HDA_ISS_NO;
	const uint8_t strm = 3;

	wr(pi, HDAC_CORBLBASE, 4, GPA_CORB);
	wr(pi, HDAC_RIRBLBASE, 4, GPA_RIRB);
	wr(pi, HDAC_DPIBUBASE, 4, 0);
	wr(pi, HDAC_DPIBLBASE, 4, GPA_DPIB | HDAC_DPLBASE_DPLBASE_DMAPBE);
	wr(pi, HDAC_RIRBCTL, 1, HDAC_RIRBCTL_RIRBDMAEN);
	wr(pi, HDAC_CORBCTL, 1, HDAC_CORBCTL_CORBRUN);
	stream_program(pi, si, GPA_BDL, GPA_DATA0, 16, 1, strm);
}

ATF_TC_WITHOUT_HEAD(snapshot_save_restore_roundtrip);
ATF_TC_BODY(snapshot_save_restore_roundtrip, tc __unused)
{
	struct pci_devinst *src, *dst;
	struct hda_softc *ssc, *dsc;
	struct vm_snapshot_meta meta = { 0 };
	uint8_t *buf;
	size_t buflen = 256 * 1024;
	const unsigned si = HDA_ISS_NO;

	guest_reset();
	buf = malloc(buflen);
	ATF_REQUIRE(buf != NULL);

	src = hda_new(true);
	ssc = hda_sc(src);
	build_active_device(src);
	ATF_REQUIRE_EQ(1, ssc->streams[si].run);

	/* SAVE. */
	meta.dev_data = src;
	meta.op = VM_SNAPSHOT_SAVE;
	meta.buffer.buf = buf;
	meta.buffer.buf_rem = buflen;
	ATF_REQUIRE_EQ(0, pci_hda_snapshot(&meta));
	ATF_CHECK(mock_snapshot_calls > 0);

	/* RESTORE into a fresh device sharing the same guest memory. */
	dst = hda_new(true);
	dsc = hda_sc(dst);
	memset(&meta, 0, sizeof(meta));
	meta.dev_data = dst;
	meta.op = VM_SNAPSHOT_RESTORE;
	meta.buffer.buf = buf;
	meta.buffer.buf_rem = buflen;
	ATF_REQUIRE_EQ(0, pci_hda_snapshot(&meta));

	/* Register file matches byte-for-byte. */
	ATF_CHECK_EQ(0, memcmp(ssc->regs, dsc->regs, sizeof(ssc->regs)));
	/* Ring geometry rebuilt. */
	ATF_CHECK_EQ(ssc->corb.run, dsc->corb.run);
	ATF_CHECK_EQ(ssc->corb.size, dsc->corb.size);
	ATF_CHECK(dsc->corb.dma_vaddr != NULL);
	ATF_CHECK_EQ(ssc->rirb.run, dsc->rirb.run);
	ATF_CHECK(dsc->rirb.dma_vaddr != NULL);
	ATF_CHECK(dsc->dma_pib_vaddr != NULL);
	/* Stream descriptor rebuilt and re-armed. */
	ATF_CHECK_EQ(1, dsc->streams[si].run);
	ATF_CHECK_EQ(ssc->streams[si].stream, dsc->streams[si].stream);
	ATF_CHECK_EQ(ssc->streams[si].cbl, dsc->streams[si].cbl);
	ATF_CHECK_EQ(ssc->streams[si].bdl_cnt, dsc->streams[si].bdl_cnt);
	ATF_CHECK_EQ(si, dsc->stream_map[1][ssc->streams[si].stream]);
	ATF_CHECK_EQ(mock_codec_state, mock_restored_state);

	/* The restored stream is usable: playback reads guest memory. */
	{
		uint8_t out[16];
		for (uint32_t k = 0; k < 16; k++)
			g_guest[GPA_DATA0 + k] = (uint8_t)(0x55 + k);
		ATF_CHECK_EQ(0, hda_transfer(dsc->codecs[0],
		    dsc->streams[si].stream, 1, out, 16));
		for (uint32_t k = 0; k < 16; k++)
			ATF_CHECK_EQ((uint8_t)(0x55 + k), out[k]);
	}

	free(src);
	free(dst);
	free(buf);
}

/* VALIDATE consumes the wire record without mutating the device. */
ATF_TC_WITHOUT_HEAD(snapshot_validate);
ATF_TC_BODY(snapshot_validate, tc __unused)
{
	struct pci_devinst *src, *dst;
	struct hda_softc *dsc;
	struct vm_snapshot_meta meta = { 0 };
	uint8_t *buf;
	size_t buflen = 256 * 1024;

	guest_reset();
	buf = malloc(buflen);
	ATF_REQUIRE(buf != NULL);

	src = hda_new(true);
	build_active_device(src);
	memset(&meta, 0, sizeof(meta));
	meta.dev_data = src;
	meta.op = VM_SNAPSHOT_SAVE;
	meta.buffer.buf = buf;
	meta.buffer.buf_rem = buflen;
	ATF_REQUIRE_EQ(0, pci_hda_snapshot(&meta));

	dst = hda_new(true);
	dsc = hda_sc(dst);
	memset(&meta, 0, sizeof(meta));
	meta.dev_data = dst;
	meta.op = VM_SNAPSHOT_VALIDATE;
	meta.buffer.buf = buf;
	meta.buffer.buf_rem = buflen;
	ATF_CHECK_EQ(0, pci_hda_snapshot(&meta));
	/* No streams were started on the destination by VALIDATE. */
	ATF_CHECK_EQ(0, dsc->streams[HDA_ISS_NO].run);

	free(src);
	free(dst);
	free(buf);
}

/* Snapshot error paths. */
ATF_TC_WITHOUT_HEAD(snapshot_error_paths);
ATF_TC_BODY(snapshot_error_paths, tc __unused)
{
	struct pci_devinst *src, *dst;
	struct vm_snapshot_meta meta = { 0 };
	struct pci_devinst empty = { 0 };
	uint8_t *buf;
	size_t buflen = 256 * 1024;

	guest_reset();
	buf = malloc(buflen);
	ATF_REQUIRE(buf != NULL);

	/* NULL meta / dev_data / softc. */
	ATF_CHECK_EQ(EINVAL, pci_hda_snapshot(NULL));
	memset(&meta, 0, sizeof(meta));
	meta.op = VM_SNAPSHOT_SAVE;
	ATF_CHECK_EQ(EINVAL, pci_hda_snapshot(&meta));
	meta.dev_data = &empty;			/* pi_arg == NULL */
	ATF_CHECK_EQ(EINVAL, pci_hda_snapshot(&meta));

	/* Save a valid record from an active device. */
	src = hda_new(true);
	build_active_device(src);
	memset(&meta, 0, sizeof(meta));
	meta.dev_data = src;
	meta.op = VM_SNAPSHOT_SAVE;
	meta.buffer.buf = buf;
	meta.buffer.buf_rem = buflen;
	ATF_REQUIRE_EQ(0, pci_hda_snapshot(&meta));

	/* Restore into a device with a different codec count -> EINVAL. */
	dst = hda_new(false);			/* codecs_no == 0 */
	memset(&meta, 0, sizeof(meta));
	meta.dev_data = dst;
	meta.op = VM_SNAPSHOT_RESTORE;
	meta.buffer.buf = buf;
	meta.buffer.buf_rem = buflen;
	ATF_CHECK_EQ(EINVAL, pci_hda_snapshot(&meta));
	free(dst);

	/* Restore with all DMA mappings failing -> publish fails EINVAL. */
	dst = hda_new(true);
	memset(&meta, 0, sizeof(meta));
	meta.dev_data = dst;
	meta.op = VM_SNAPSHOT_RESTORE;
	meta.buffer.buf = buf;
	meta.buffer.buf_rem = buflen;
	g_dma_fail = true;
	ATF_CHECK_EQ(EINVAL, pci_hda_snapshot(&meta));
	g_dma_fail = false;
	free(dst);

	/* Loading a record with a bad magic -> ENOTSUP. */
	dst = hda_new(true);
	memset(&meta, 0, sizeof(meta));
	meta.dev_data = dst;
	meta.op = VM_SNAPSHOT_RESTORE;
	le32enc(buf, 0xdeadbeef);		/* corrupt magic */
	meta.buffer.buf = buf;
	meta.buffer.buf_rem = buflen;
	ATF_CHECK_EQ(ENOTSUP, pci_hda_snapshot(&meta));
	free(dst);

	/* A tiny output buffer makes the SAVE wire helpers fail (E2BIG). */
	memset(&meta, 0, sizeof(meta));
	meta.dev_data = src;
	meta.op = VM_SNAPSHOT_SAVE;
	meta.buffer.buf = buf;
	meta.buffer.buf_rem = 4;		/* room for magic only */
	ATF_CHECK(pci_hda_snapshot(&meta) != 0);

	free(src);
	free(buf);
}

/*
 * The staged/atomic restore commit: a mapping failure on any single derived
 * resource (RIRB ring, DMA position buffer, or a per-stream BDL) must abort the
 * whole restore -- the device is never left half-restored with some live
 * resources published and others not.
 */
ATF_TC_WITHOUT_HEAD(snapshot_publish_partial_failures);
ATF_TC_BODY(snapshot_publish_partial_failures, tc __unused)
{
	struct pci_devinst *src, *dst;
	struct hda_softc *dsc;
	struct vm_snapshot_meta meta = { 0 };
	uint8_t *buf;
	size_t buflen = 256 * 1024;
	const unsigned si = HDA_ISS_NO;
	uint64_t fail_at[3];

	guest_reset();
	buf = malloc(buflen);
	ATF_REQUIRE(buf != NULL);

	src = hda_new(true);
	build_active_device(src);
	meta.dev_data = src;
	meta.op = VM_SNAPSHOT_SAVE;
	meta.buffer.buf = buf;
	meta.buffer.buf_rem = buflen;
	ATF_REQUIRE_EQ(0, pci_hda_snapshot(&meta));

	/* RIRB ring, DMA position buffer, and per-stream BDL data buffer. */
	fail_at[0] = GPA_RIRB;
	fail_at[1] = GPA_DPIB;
	fail_at[2] = GPA_DATA0;
	for (unsigned k = 0; k < 3; k++) {
		dst = hda_new(true);
		dsc = hda_sc(dst);
		memset(&meta, 0, sizeof(meta));
		meta.dev_data = dst;
		meta.op = VM_SNAPSHOT_RESTORE;
		meta.buffer.buf = buf;
		meta.buffer.buf_rem = buflen;
		g_dma_fail_gpa = fail_at[k];
		ATF_CHECK_EQ(EINVAL, pci_hda_snapshot(&meta));
		g_dma_fail_gpa = 0;
		/* No live resource was published on the aborted restore. */
		ATF_CHECK_EQ(0, dsc->streams[si].run);
		ATF_CHECK(dsc->corb.dma_vaddr == NULL);
		ATF_CHECK(dsc->rirb.dma_vaddr == NULL);
		ATF_CHECK(dsc->dma_pib_vaddr == NULL);
		free(dst);
	}

	free(src);
	free(buf);
}

/* A codec without a snapshot handler makes the checkpoint fail closed. */
ATF_TC_WITHOUT_HEAD(snapshot_codec_without_handler);
ATF_TC_BODY(snapshot_codec_without_handler, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;
	struct vm_snapshot_meta meta = { 0 };
	struct hda_codec_class no_snap;
	uint8_t *buf;
	size_t buflen = 256 * 1024;

	guest_reset();
	buf = malloc(buflen);
	ATF_REQUIRE(buf != NULL);
	pi = hda_new(true);
	sc = hda_sc(pi);

	/* Repoint the live codec at a class lacking a snapshot callback. */
	no_snap = mock_codec;
	no_snap.snapshot = NULL;
	sc->codecs[0]->codec = &no_snap;

	memset(&meta, 0, sizeof(meta));
	meta.dev_data = pi;
	meta.op = VM_SNAPSHOT_SAVE;
	meta.buffer.buf = buf;
	meta.buffer.buf_rem = buflen;
	ATF_CHECK_EQ(ENOTSUP, pci_hda_snapshot(&meta));

	sc->codecs[0]->codec = &mock_codec;
	free(pi);
	free(buf);
}

/* Direct coverage of hda_snapshot_restore_stream rejection branches. */
ATF_TC_WITHOUT_HEAD(restore_stream_rejections);
ATF_TC_BODY(restore_stream_rejections, tc __unused)
{
	struct pci_devinst *pi;
	struct hda_softc *sc;
	struct hda_stream_desc st;
	struct hda_snapshot_rec rec;
	const unsigned si = HDA_ISS_NO;
	const uint32_t off = si << 5;

	guest_reset();
	pi = hda_new(true);
	sc = hda_sc(pi);

	memset(&rec, 0, sizeof(rec));

	/* Stopped stream: copies scalar fields and returns success. */
	rec.st_run[si] = 0;
	rec.st_stream[si] = 4;
	rec.st_cbl[si] = 16;
	rec.st_bdl_cnt[si] = 1;
	ATF_CHECK_EQ(0, hda_snapshot_restore_stream(sc, &st, si, &rec));
	ATF_CHECK_EQ(0, st.run);
	ATF_CHECK_EQ(4, st.stream);

	/* Running stream whose bdl_cnt disagrees with SDLVI -> EINVAL. */
	rec.st_run[si] = 1;
	rec.st_dir[si] = 1;
	rec.st_bdl_cnt[si] = 1;
	rec.st_cbl[si] = 16;
	hda_set_reg_by_offset(sc, off + HDAC_SDLVI, 4);	/* bdl_cnt 5 != 1 */
	ATF_CHECK_EQ(EINVAL, hda_snapshot_restore_stream(sc, &st, si, &rec));

	/* cbl disagreement. */
	hda_set_reg_by_offset(sc, off + HDAC_SDLVI, 0);	/* bdl_cnt 1 */
	hda_set_reg_by_offset(sc, off + HDAC_SDCBL, 32);
	ATF_CHECK_EQ(EINVAL, hda_snapshot_restore_stream(sc, &st, si, &rec));
	hda_set_reg_by_offset(sc, off + HDAC_SDCBL, 16);

	/* BDL base maps to failing region -> EINVAL. */
	hda_set_reg_by_offset(sc, off + HDAC_SDBDPL, GPA_BDL);
	hda_set_reg_by_offset(sc, off + HDAC_SDBDPU, 0);
	g_dma_fail = true;
	ATF_CHECK_EQ(EINVAL, hda_snapshot_restore_stream(sc, &st, si, &rec));
	g_dma_fail = false;

	/* BDL entry length invalid -> EINVAL. */
	bdl_put(GPA_BDL, 0, GPA_DATA0, 0, 0);
	ATF_CHECK_EQ(EINVAL, hda_snapshot_restore_stream(sc, &st, si, &rec));

	/* Total coverage below cbl -> EINVAL. */
	bdl_put(GPA_BDL, 0, GPA_DATA0, 8, 0);
	ATF_CHECK_EQ(EINVAL, hda_snapshot_restore_stream(sc, &st, si, &rec));

	/* Byte cursor past the buffer-entry length -> EINVAL. */
	bdl_put(GPA_BDL, 0, GPA_DATA0, 16, 0);
	rec.st_bp[si] = 64;
	ATF_CHECK_EQ(EINVAL, hda_snapshot_restore_stream(sc, &st, si, &rec));

	/* A well-formed running record succeeds. */
	rec.st_bp[si] = 0;
	ATF_CHECK_EQ(0, hda_snapshot_restore_stream(sc, &st, si, &rec));
	ATF_CHECK_EQ(1, st.run);

	free(pi);
}

/* Pause/resume ownership fence transitions. */
ATF_TC_WITHOUT_HEAD(pause_resume);
ATF_TC_BODY(pause_resume, tc __unused)
{
	struct pci_devinst *pi;
	struct pci_devinst empty = { 0 };

	guest_reset();
	pi = hda_new(true);

	ATF_CHECK_EQ(EINVAL, pci_hda_pause(&empty));	/* no softc */
	ATF_CHECK_EQ(EINVAL, pci_hda_resume(&empty));

	ATF_CHECK_EQ(0, pci_hda_pause(pi));
	ATF_CHECK_EQ(EINVAL, pci_hda_pause(pi));		/* already paused */
	ATF_CHECK_EQ(0, pci_hda_resume(pi));
	ATF_CHECK_EQ(EINVAL, pci_hda_resume(pi));	/* not paused */

	free(pi);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, pci_init_and_reset_defaults);
	ATF_TP_ADD_TC(tp, init_without_codec_config);
	ATF_TP_ADD_TC(tp, mmio_access_guards);
	ATF_TP_ADD_TC(tp, corb_rirb_verb_roundtrip);
	ATF_TP_ADD_TC(tp, corb_command_error_stops_engine);
	ATF_TP_ADD_TC(tp, corb_rirb_invalid_size);
	ATF_TP_ADD_TC(tp, dma_mapping_failures);
	ATF_TP_ADD_TC(tp, dma_position_buffer_toggle);
	ATF_TP_ADD_TC(tp, output_stream_transfer);
	ATF_TP_ADD_TC(tp, input_stream_transfer);
	ATF_TP_ADD_TC(tp, stream_start_rejections);
	ATF_TP_ADD_TC(tp, stream_double_start_and_tag_collision);
	ATF_TP_ADD_TC(tp, stream_reset);
	ATF_TP_ADD_TC(tp, stream_stop_via_run_clear);
	ATF_TP_ADD_TC(tp, transfer_rejections);
	ATF_TP_ADD_TC(tp, gctl_reset);
	ATF_TP_ADD_TC(tp, statests_interrupt);
	ATF_TP_ADD_TC(tp, rirb_response_interrupt_and_pointer_resets);
	ATF_TP_ADD_TC(tp, corb_run_wp_out_of_range);
	ATF_TP_ADD_TC(tp, corb_stop_clears_state);
	ATF_TP_ADD_TC(tp, response_without_running_rirb);
	ATF_TP_ADD_TC(tp, codec_dispatch_edges);
	ATF_TP_ADD_TC(tp, codec_constructor_failures);
	ATF_TP_ADD_TC(tp, find_codec_class_lookup);
	ATF_TP_ADD_TC(tp, snapshot_save_restore_roundtrip);
	ATF_TP_ADD_TC(tp, snapshot_validate);
	ATF_TP_ADD_TC(tp, snapshot_error_paths);
	ATF_TP_ADD_TC(tp, snapshot_publish_partial_failures);
	ATF_TP_ADD_TC(tp, snapshot_codec_without_handler);
	ATF_TP_ADD_TC(tp, restore_stream_rejections);
	ATF_TP_ADD_TC(tp, pause_resume);
	return (atf_no_error());
}
