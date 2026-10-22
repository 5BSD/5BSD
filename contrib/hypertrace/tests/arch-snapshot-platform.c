/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 */

/*
 * Native harness for the ARM64 platform-device checkpoint records added to
 * bhyve: PL031 RTC (rtc_pl031.c) and PL011 UART (uart_pl011.c, with the real
 * uart_backend.c receive FIFO).  The production sources are compiled
 * unchanged with -DBHYVE_SNAPSHOT.  Only the mevent loop, configuration
 * lookup and the four snapshot buffer primitives are shims; the primitives
 * reproduce the semantics of usr.sbin/bhyve/snapshot.c (little-endian
 * scalars, load on RESTORE and VALIDATE, store on SAVE).  No guest, device
 * node or VM is involved.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <atf-c.h>

#include <machine/vmm_snapshot.h>

#include "mevent.h"
#include "rtc_pl031.h"
#include "snapshot.h"
#include "uart_backend.h"
#include "uart_emul.h"

int raw_stdio;
static int intr_asserts, intr_deasserts, timer_updates;

/* Shims. */
struct mevent *
mevent_add(int fd __unused, enum ev_type type __unused,
    void (*func)(int, enum ev_type, void *) __unused, void *param __unused)
{
	static int token;

	return ((struct mevent *)&token);
}

int
mevent_timer_update(struct mevent *evp __unused, int msecs __unused)
{

	timer_updates++;
	return (0);
}

int
mevent_enable(struct mevent *evp __unused)
{
	return (0);
}

int
mevent_disable(struct mevent *evp __unused)
{
	return (0);
}

int
mevent_delete_close(struct mevent *evp __unused)
{
	return (0);
}

bool
get_config_bool_default(const char *name __unused, bool def)
{
	return (def);
}

void
vm_snapshot_buf_err(const char *bufname __unused,
    const enum vm_snapshot_op op __unused)
{
}

int
vm_snapshot_buf(void *data, size_t data_size, struct vm_snapshot_meta *meta)
{
	struct vm_snapshot_buffer *buffer;

	buffer = &meta->buffer;
	if (buffer->buf_rem < data_size)
		return (E2BIG);
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(buffer->buf, data, data_size);
	else if (vm_snapshot_is_loading(meta))
		memcpy(data, buffer->buf, data_size);
	else
		return (EINVAL);
	buffer->buf += data_size;
	buffer->buf_rem -= data_size;
	return (0);
}

int
vm_snapshot_u8(uint8_t *value, struct vm_snapshot_meta *meta)
{
	return (vm_snapshot_buf(value, 1, meta));
}

int
vm_snapshot_le16(uint16_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t b[2];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		b[0] = *value;
		b[1] = *value >> 8;
	}
	error = vm_snapshot_buf(b, 2, meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = (uint16_t)(b[0] | b[1] << 8);
	return (error);
}

int
vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t b[4];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		for (int i = 0; i < 4; i++)
			b[i] = (uint8_t)(*value >> (8 * i));
	error = vm_snapshot_buf(b, 4, meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = (uint32_t)b[0] | (uint32_t)b[1] << 8 |
		    (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
	return (error);
}

static void
intr_assert(void *arg __unused)
{
	intr_asserts++;
}

static void
intr_deassert(void *arg __unused)
{
	intr_deasserts++;
}

/* A fresh metadata object per use: its buffer bounds are const members. */
#define	META(p, n, mode) (&(struct vm_snapshot_meta){			\
	.buffer = {							\
		.buf_start = (p),					\
		.buf_size = (n),					\
		.buf = (p),						\
		.buf_rem = (n),						\
	},								\
	.op = (mode),							\
})

#define	RTCDR	0x000
#define	RTCMR	0x004
#define	RTCLR	0x008
#define	RTCIMSC	0x010
#define	RTCRIS	0x014
#define	RTCMIS	0x018

ATF_TC_WITHOUT_HEAD(pl031_round_trip);
ATF_TC_BODY(pl031_round_trip, tc)
{
	struct rtc_pl031_softc *src, *dst;
	struct vm_snapshot_meta *meta;
	uint8_t buf[64];
	size_t used;
	uint32_t src_dr, dst_dr;

	src = rtc_pl031_init(intr_assert, intr_deassert, NULL);
	/* Guest sets its RTC one hour behind host time and arms a match. */
	rtc_pl031_write(src, RTCLR, (uint32_t)time(NULL) - 3600);
	rtc_pl031_write(src, RTCMR, (uint32_t)time(NULL) + 600);
	rtc_pl031_write(src, RTCIMSC, 1);
	meta = META(buf, sizeof(buf), VM_SNAPSHOT_SAVE);
	ATF_REQUIRE_EQ(rtc_pl031_snapshot(src, meta), 0);
	used = sizeof(buf) - meta->buffer.buf_rem;
	ATF_CHECK_EQ(used, 15);
	src_dr = rtc_pl031_read(src, RTCDR);

	dst = rtc_pl031_init(intr_assert, intr_deassert, NULL);
	meta = META(buf, used, VM_SNAPSHOT_RESTORE);
	ATF_REQUIRE_EQ(rtc_pl031_snapshot(dst, meta), 0);
	ATF_CHECK_EQ(meta->buffer.buf_rem, 0);
	dst_dr = rtc_pl031_read(dst, RTCDR);
	/* The RTC follows wall-clock time: at most one second apart. */
	ATF_CHECK((uint32_t)(dst_dr - src_dr) <= 1);
	ATF_CHECK_EQ(rtc_pl031_read(dst, RTCMR), rtc_pl031_read(src, RTCMR));
	ATF_CHECK_EQ(rtc_pl031_read(dst, RTCLR), rtc_pl031_read(src, RTCLR));
	ATF_CHECK_EQ(rtc_pl031_read(dst, RTCIMSC), 1);
}

ATF_TC_WITHOUT_HEAD(pl031_validate_rejects_and_is_pure);
ATF_TC_BODY(pl031_validate_rejects_and_is_pure, tc)
{
	struct rtc_pl031_softc *sc;
	struct vm_snapshot_meta *meta;
	uint8_t good[15], buf[15];
	int asserts, deasserts, updates;

	sc = rtc_pl031_init(intr_assert, intr_deassert, NULL);
	meta = META(good, sizeof(good), VM_SNAPSHOT_SAVE);
	ATF_REQUIRE_EQ(rtc_pl031_snapshot(sc, meta), 0);
	asserts = intr_asserts;
	deasserts = intr_deasserts;
	updates = timer_updates;
	memcpy(buf, good, sizeof(buf));
	meta = META(buf, sizeof(buf), VM_SNAPSHOT_VALIDATE);
	ATF_CHECK_EQ(rtc_pl031_snapshot(sc, meta), 0);
	ATF_CHECK_EQ(intr_asserts, asserts);
	ATF_CHECK_EQ(intr_deasserts, deasserts);
	ATF_CHECK_EQ(timer_updates, updates);
	/* imsc, ris, prev_mis live at offsets 12, 13, 14. */
	for (int field = 12; field < 15; field++) {
		memcpy(buf, good, sizeof(buf));
		buf[field] = 2;
		meta = META(buf, sizeof(buf), VM_SNAPSHOT_VALIDATE);
		ATF_CHECK_EQ(rtc_pl031_snapshot(sc, meta), EINVAL);
	}
	memcpy(buf, good, sizeof(buf));
	buf[12] = 1;		/* imsc */
	buf[13] = 1;		/* ris */
	buf[14] = 0;		/* prev_mis must equal ris & imsc */
	meta = META(buf, sizeof(buf), VM_SNAPSHOT_VALIDATE);
	ATF_CHECK_EQ(rtc_pl031_snapshot(sc, meta), EINVAL);
	meta = META(good, sizeof(good) - 1, VM_SNAPSHOT_VALIDATE);
	ATF_CHECK_EQ(rtc_pl031_snapshot(sc, meta), E2BIG);
}

#define	UARTDR		0x00
#define	UARTFR		0x06
#define	UARTIBRD	0x09
#define	UARTFBRD	0x0a
#define	UARTLCR_H	0x0b
#define	UARTCR		0x0c
#define	UARTIFLS	0x0d
#define	UARTIMSC	0x0e
#define	UARTRIS		0x0f

static size_t
pl011_save(struct uart_pl011_softc *sc, uint8_t *buf, size_t size)
{
	struct vm_snapshot_meta *meta;

	meta = META(buf, size, VM_SNAPSHOT_SAVE);
	ATF_REQUIRE_EQ(uart_pl011_snapshot(sc, meta), 0);
	return (size - meta->buffer.buf_rem);
}

ATF_TC_WITHOUT_HEAD(pl011_round_trip);
ATF_TC_BODY(pl011_round_trip, tc)
{
	struct uart_pl011_softc *src, *dst;
	struct vm_snapshot_meta *meta;
	static uint8_t buf[4096];
	size_t used;
	static const int regs[] = { UARTIBRD, UARTFBRD, UARTLCR_H, UARTCR,
	    UARTIFLS, UARTIMSC, UARTRIS, UARTFR };

	src = uart_pl011_init(intr_assert, intr_deassert, NULL);
	ATF_REQUIRE(src != NULL);
	uart_pl011_write(src, UARTIBRD, 26);
	uart_pl011_write(src, UARTFBRD, 3);
	uart_pl011_write(src, UARTLCR_H, 0x70);	/* 8N1, FIFOs enabled */
	uart_pl011_write(src, UARTCR, 0x301);
	uart_pl011_write(src, UARTIFLS, 0x12);
	uart_pl011_write(src, UARTIMSC, 0x50);
	used = pl011_save(src, buf, sizeof(buf));
	ATF_REQUIRE(used > 16);

	dst = uart_pl011_init(intr_assert, intr_deassert, NULL);
	ATF_REQUIRE(dst != NULL);
	meta = META(buf, used, VM_SNAPSHOT_VALIDATE);
	ATF_CHECK_EQ(uart_pl011_snapshot(dst, meta), 0);
	/* VALIDATE must leave the destination at reset state. */
	ATF_CHECK_EQ(uart_pl011_read(dst, UARTIBRD), 0);
	meta = META(buf, used, VM_SNAPSHOT_RESTORE);
	ATF_REQUIRE_EQ(uart_pl011_snapshot(dst, meta), 0);
	ATF_CHECK_EQ(meta->buffer.buf_rem, 0);
	for (size_t i = 0; i < nitems(regs); i++)
		ATF_CHECK_EQ_MSG(uart_pl011_read(dst, regs[i]),
		    uart_pl011_read(src, regs[i]), "register %#x", regs[i]);
	/* Pause and resume are idempotent for checkpoint unwinding. */
	ATF_CHECK_EQ(uart_pl011_pause(dst), 0);
	ATF_CHECK_EQ(uart_pl011_pause(dst), 0);
	used = pl011_save(dst, buf, sizeof(buf));	/* paused path */
	ATF_CHECK_EQ(uart_pl011_resume(dst), 0);
	ATF_CHECK_EQ(uart_pl011_resume(dst), 0);
}

ATF_TC_WITHOUT_HEAD(pl011_validate_rejects);
ATF_TC_BODY(pl011_validate_rejects, tc)
{
	struct uart_pl011_softc *sc;
	struct vm_snapshot_meta *meta;
	static uint8_t good[4096], buf[4096];
	size_t used;
	static const struct {
		size_t offset;		/* little-endian 16-bit field */
		uint16_t value;
	} bad[] = {
		{ 0, 0x0800 },		/* irq_state beyond UARTIMSC_MASK */
		{ 2, 0x0010 },		/* rsr */
		{ 4, 0x0038 },		/* cr reserved bits */
		{ 6, 0x0040 },		/* ifls */
		{ 8, 0x0800 },		/* imsc */
		{ 10, 0x0100 },		/* lcr_h */
		{ 14, 0x0040 },		/* fbrd */
	};

	sc = uart_pl011_init(intr_assert, intr_deassert, NULL);
	used = pl011_save(sc, good, sizeof(good));
	for (size_t i = 0; i < nitems(bad); i++) {
		memcpy(buf, good, used);
		buf[bad[i].offset] = (uint8_t)bad[i].value;
		buf[bad[i].offset + 1] = (uint8_t)(bad[i].value >> 8);
		meta = META(buf, used, VM_SNAPSHOT_VALIDATE);
		ATF_CHECK_EQ_MSG(uart_pl011_snapshot(sc, meta), EINVAL,
		    "field at %zu", bad[i].offset);
	}
	/* A receive FIFO whose count exceeds its size is refused. */
	memcpy(buf, good, used);
	buf[16 + 8] = 0xff;	/* rxfifo.num low byte */
	buf[16 + 9] = 0xff;
	meta = META(buf, used, VM_SNAPSHOT_VALIDATE);
	ATF_CHECK_EQ(uart_pl011_snapshot(sc, meta), EINVAL);
	for (size_t cut = 0; cut < used; cut += 7) {
		meta = META(good, cut, VM_SNAPSHOT_VALIDATE);
		ATF_CHECK(uart_pl011_snapshot(sc, meta) != 0);
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, pl031_round_trip);
	ATF_TP_ADD_TC(tp, pl031_validate_rejects_and_is_pure);
	ATF_TP_ADD_TC(tp, pl011_round_trip);
	ATF_TP_ADD_TC(tp, pl011_validate_rejects);
	return (atf_no_error());
}
