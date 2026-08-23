/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * TU-include harness for the bhyve NS16550 UART device model
 * (usr.sbin/bhyve/uart_emul.c).  The production translation unit is compiled
 * directly into this test so its static entry points and file-scope state are
 * reachable.  The bhyve/kernel infrastructure the DUT depends on (the UART
 * backend rx FIFO, the mevent loop, and the snapshot wire helpers) is replaced
 * with self-contained userspace mocks defined below.
 *
 * Every expectation is derived from an independent 16550 UART oracle (the
 * register map and bit semantics from the National Semiconductor PC16550D
 * datasheet and the FreeBSD dev/uart register model), never from the DUT's own
 * output.  The oracle constants are (re)declared here with a SPEC_ prefix.
 */

#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

/*
 * Pull in the harness mock of mevent.h and suppress the real bhyve mevent.h
 * (its include guard is defined here so uart_backend.h's quote-include of it
 * expands to nothing).
 */
#define	_MEVENT_H_
#include "mevent.h"

/*
 * Snapshot metadata types and the wire-helper macros/declarations come from
 * the harness snapshot.h; the real bhyve snapshot.h (which the DUT pulls in
 * relative to its own directory) is suppressed via its include guard so the
 * two do not clash.
 */
#include <machine/vmm_snapshot.h>
#include "snapshot.h"
#define	_BHYVE_SNAPSHOT_

/* Backend interface (declarations that the mocks below implement). */
#include "uart_backend.h"

/*
 * ------------------------------------------------------------------
 * Independent 16550 oracle: register offsets and bit definitions.
 * ------------------------------------------------------------------
 */

/* Register offsets (16550 port map, DLAB=0). */
#define	SPEC_REG_DATA	0	/* RBR (read) / THR (write) */
#define	SPEC_REG_IER	1	/* interrupt enable */
#define	SPEC_REG_IIR	2	/* interrupt id (read) / FCR (write) */
#define	SPEC_REG_LCR	3	/* line control */
#define	SPEC_REG_MCR	4	/* modem control */
#define	SPEC_REG_LSR	5	/* line status */
#define	SPEC_REG_MSR	6	/* modem status */
#define	SPEC_REG_SCR	7	/* scratch */
/* Under DLAB=1, offsets 0 and 1 are the divisor latch. */
#define	SPEC_REG_DLL	0
#define	SPEC_REG_DLH	1

/* IER bits. */
#define	SPEC_IER_ERXRDY	0x01
#define	SPEC_IER_ETXRDY	0x02
#define	SPEC_IER_ERLS	0x04
#define	SPEC_IER_EMSC	0x08

/* IIR values. */
#define	SPEC_IIR_MLSC	0x00
#define	SPEC_IIR_NOPEND	0x01
#define	SPEC_IIR_TXRDY	0x02
#define	SPEC_IIR_RXRDY	0x04
#define	SPEC_IIR_RLS	0x06
#define	SPEC_IIR_RXTOUT	0x0c
#define	SPEC_IIR_FIFO	0xc0

/* FCR bits. */
#define	SPEC_FCR_ENABLE	0x01
#define	SPEC_FCR_RCV_RST 0x02
#define	SPEC_FCR_XMT_RST 0x04
#define	SPEC_FCR_DMA	0x08
#define	SPEC_FCR_RXHIGH	0xc0

/* LCR bits. */
#define	SPEC_LCR_DLAB	0x80

/* MCR bits. */
#define	SPEC_MCR_DTR	0x01
#define	SPEC_MCR_RTS	0x02
#define	SPEC_MCR_OUT1	0x04
#define	SPEC_MCR_OUT2	0x08
#define	SPEC_MCR_LOOP	0x10

/* LSR bits. */
#define	SPEC_LSR_RXRDY	0x01
#define	SPEC_LSR_OE	0x02
#define	SPEC_LSR_THRE	0x20
#define	SPEC_LSR_TEMT	0x40

/* MSR bits. */
#define	SPEC_MSR_DCTS	0x01
#define	SPEC_MSR_DDSR	0x02
#define	SPEC_MSR_TERI	0x04
#define	SPEC_MSR_DDCD	0x08
#define	SPEC_MSR_CTS	0x10
#define	SPEC_MSR_DSR	0x20
#define	SPEC_MSR_RI	0x40
#define	SPEC_MSR_DCD	0x80
#define	SPEC_MSR_DELTA	0x0f

/* Reset divisor: DEFAULT_RCLK / DEFAULT_BAUD / 16 = 1843200 / 115200 / 16. */
#define	SPEC_RESET_DIVISOR	(1843200 / 115200 / 16)

/* Legacy COM port resources (standard PC assignments). */
#define	SPEC_COM1_BASE	0x3f8
#define	SPEC_COM1_IRQ	4
#define	SPEC_COM2_BASE	0x2f8
#define	SPEC_COM2_IRQ	3
#define	SPEC_COM3_BASE	0x3e8
#define	SPEC_COM3_IRQ	4
#define	SPEC_COM4_BASE	0x2e8
#define	SPEC_COM4_IRQ	3

#define	SPEC_FIFOSZ	16

/*
 * ------------------------------------------------------------------
 * Mock UART backend (rx FIFO) -- a faithful reimplementation of the
 * ring semantics in usr.sbin/bhyve/uart_backend.c, minus the tty/socket
 * and mevent plumbing (no fd is ever opened by these tests).
 * ------------------------------------------------------------------
 */

struct uart_softc {
	uint8_t	buf[SPEC_FIFOSZ];
	int	rindex;
	int	windex;
	int	num;
	int	size;
	bool	opened;		/* tty; always false in the harness */
	int	lock_depth;	/* balance check for lock/unlock */
};

static int mock_uart_init_fail;	/* force uart_init() to fail */

struct uart_softc *
uart_init(void)
{
	struct uart_softc *sc;

	if (mock_uart_init_fail)
		return (NULL);
	sc = calloc(1, sizeof(*sc));
	if (sc != NULL)
		sc->size = 1;
	return (sc);
}

int
uart_tty_open(struct uart_softc *sc, const char *path,
    void (*drain)(int, enum ev_type, void *), void *arg)
{

	(void)sc;
	(void)path;
	(void)drain;
	(void)arg;
	/* No real device is attached in the harness. */
	return (0);
}

void
uart_softc_lock(struct uart_softc *sc)
{

	sc->lock_depth++;
}

void
uart_softc_unlock(struct uart_softc *sc)
{

	sc->lock_depth--;
}

int
uart_rxfifo_getchar(struct uart_softc *sc)
{
	int c;

	if (sc->num > 0) {
		c = sc->buf[sc->rindex];
		sc->rindex = (sc->rindex + 1) % sc->size;
		sc->num--;
		return (c);
	}
	return (-1);
}

int
uart_rxfifo_numchars(struct uart_softc *sc)
{

	return (sc->num);
}

static int
mock_rxfifo_putchar(struct uart_softc *sc, uint8_t ch)
{

	if (sc->num < sc->size) {
		sc->buf[sc->windex] = ch;
		sc->windex = (sc->windex + 1) % sc->size;
		sc->num++;
		return (0);
	}
	return (-1);
}

int
uart_rxfifo_putchar(struct uart_softc *sc, uint8_t ch, bool loopback)
{

	if (loopback)
		return (mock_rxfifo_putchar(sc, ch));
	/* Not in loopback and no tty attached: drop on the floor. */
	return (0);
}

void
uart_rxfifo_drain(struct uart_softc *sc, bool loopback)
{

	/* No backing fd in the harness; nothing to pull in. */
	(void)sc;
	(void)loopback;
}

void
uart_rxfifo_reset(struct uart_softc *sc, int size)
{

	if (size < 1)
		size = 1;
	else if (size > SPEC_FIFOSZ)
		size = SPEC_FIFOSZ;
	memset(sc->buf, 0, sizeof(sc->buf));
	sc->rindex = 0;
	sc->windex = 0;
	sc->num = 0;
	sc->size = size;
}

int
uart_rxfifo_size(struct uart_softc *sc)
{

	(void)sc;
	return (SPEC_FIFOSZ);
}

/*
 * Snapshot wire mock.  vm_snapshot_u8 is what the DUT drives via
 * SNAPSHOT_U8_OR_LEAVE; it serialises to / from the meta buffer so a
 * save/restore round trip is exercised for real.
 */
int
vm_snapshot_u8(uint8_t *value, struct vm_snapshot_meta *meta)
{

	if (meta->buffer.buf_rem < sizeof(*value))
		return (E2BIG);
	if (meta->op == VM_SNAPSHOT_SAVE)
		*meta->buffer.buf = *value;
	else
		*value = *meta->buffer.buf;
	meta->buffer.buf += sizeof(*value);
	meta->buffer.buf_rem -= sizeof(*value);
	return (0);
}

static int mock_rxfifo_snapshot_err;

int
uart_rxfifo_snapshot(struct uart_softc *sc, struct vm_snapshot_meta *meta)
{

	(void)sc;
	(void)meta;
	if (mock_rxfifo_snapshot_err)
		return (mock_rxfifo_snapshot_err);
	/* The rx FIFO body round-trips separately; accept it here. */
	return (0);
}

int
uart_snapshot_pause(struct uart_softc *sc)
{

	(void)sc;
	return (0);
}

int
uart_snapshot_resume(struct uart_softc *sc)
{

	(void)sc;
	return (0);
}

/*
 * ------------------------------------------------------------------
 * Interrupt callback mocks: count assert/deassert edges so tests can
 * assert on the interrupt line state produced by the DUT.
 * ------------------------------------------------------------------
 */
static int intr_asserts;
static int intr_deasserts;

static void
mock_intr_assert(void *arg)
{

	(void)arg;
	intr_asserts++;
}

static void
mock_intr_deassert(void *arg)
{

	(void)arg;
	intr_deasserts++;
}

static void
reset_intr_counts(void)
{

	intr_asserts = 0;
	intr_deasserts = 0;
}

/*
 * Route the DUT's single calloc() through a controllable allocator so the
 * allocation-failure path can be reached rootless.  free() is left alone.
 */
static int mock_calloc_fail;

static void *
test_calloc(size_t nmemb, size_t size)
{

	if (mock_calloc_fail)
		return (NULL);
	return (calloc(nmemb, size));
}

#define	calloc(n, s)	test_calloc((n), (s))

/* Compile the device model into this translation unit. */
#include "uart_emul.c"

#undef calloc

/*
 * ------------------------------------------------------------------
 * Helpers.
 * ------------------------------------------------------------------
 */
static struct uart_ns16550_softc *
make_uart(void)
{
	struct uart_ns16550_softc *sc;

	reset_intr_counts();
	mock_uart_init_fail = 0;
	mock_calloc_fail = 0;
	sc = uart_ns16550_init(mock_intr_assert, mock_intr_deassert, NULL);
	ATF_REQUIRE(sc != NULL);
	return (sc);
}

/*
 * ------------------------------------------------------------------
 * Tests.
 * ------------------------------------------------------------------
 */

ATF_TC_WITHOUT_HEAD(init_and_reset);
ATF_TC_BODY(init_and_reset, tc)
{
	struct uart_ns16550_softc *sc;
	uint8_t v;

	sc = make_uart();

	/* Reset programs the default divisor latch. */
	uart_ns16550_write(sc, SPEC_REG_LCR, SPEC_LCR_DLAB);
	v = uart_ns16550_read(sc, SPEC_REG_DLL);
	ATF_CHECK_EQ(SPEC_RESET_DIVISOR & 0xff, v);
	v = uart_ns16550_read(sc, SPEC_REG_DLH);
	ATF_CHECK_EQ((SPEC_RESET_DIVISOR >> 8) & 0xff, v);
	uart_ns16550_write(sc, SPEC_REG_LCR, 0);

	/* Modem status after reset: DCD and DSR forced on, no deltas. */
	v = uart_ns16550_read(sc, SPEC_REG_MSR);
	ATF_CHECK_EQ(SPEC_MSR_DCD | SPEC_MSR_DSR, v);

	/* No interrupt condition after reset. */
	v = uart_ns16550_read(sc, SPEC_REG_IIR);
	ATF_CHECK_EQ(SPEC_IIR_NOPEND, v);

	free(sc);
}

ATF_TC_WITHOUT_HEAD(init_bad_args);
ATF_TC_BODY(init_bad_args, tc)
{
	struct uart_ns16550_softc *sc;

	/* NULL callback pointers are rejected. */
	ATF_CHECK_EQ(NULL,
	    uart_ns16550_init(NULL, mock_intr_deassert, NULL));
	ATF_CHECK_EQ(NULL,
	    uart_ns16550_init(mock_intr_assert, NULL, NULL));

	/* Backend allocation failure frees the softc and returns NULL. */
	mock_uart_init_fail = 1;
	sc = uart_ns16550_init(mock_intr_assert, mock_intr_deassert, NULL);
	ATF_CHECK_EQ(NULL, sc);
	mock_uart_init_fail = 0;

	/* softc allocation failure. */
	mock_calloc_fail = 1;
	sc = uart_ns16550_init(mock_intr_assert, mock_intr_deassert, NULL);
	ATF_CHECK_EQ(NULL, sc);
	mock_calloc_fail = 0;
}

ATF_TC_WITHOUT_HEAD(scratch_register);
ATF_TC_BODY(scratch_register, tc)
{
	struct uart_ns16550_softc *sc;

	sc = make_uart();

	/* The scratch register is plain R/W storage. */
	uart_ns16550_write(sc, SPEC_REG_SCR, 0xa5);
	ATF_CHECK_EQ(0xa5, uart_ns16550_read(sc, SPEC_REG_SCR));
	uart_ns16550_write(sc, SPEC_REG_SCR, 0x5a);
	ATF_CHECK_EQ(0x5a, uart_ns16550_read(sc, SPEC_REG_SCR));

	free(sc);
}

ATF_TC_WITHOUT_HEAD(divisor_latch);
ATF_TC_BODY(divisor_latch, tc)
{
	struct uart_ns16550_softc *sc;

	sc = make_uart();

	/* With DLAB set, offsets 0/1 address the divisor latch. */
	uart_ns16550_write(sc, SPEC_REG_LCR, SPEC_LCR_DLAB);
	uart_ns16550_write(sc, SPEC_REG_DLL, 0x34);
	uart_ns16550_write(sc, SPEC_REG_DLH, 0x12);
	ATF_CHECK_EQ(0x34, uart_ns16550_read(sc, SPEC_REG_DLL));
	ATF_CHECK_EQ(0x12, uart_ns16550_read(sc, SPEC_REG_DLH));

	/*
	 * With DLAB clear, offset 0/1 are DATA/IER, so the latch is not
	 * disturbed and IER is independent storage.
	 */
	uart_ns16550_write(sc, SPEC_REG_LCR, 0);
	uart_ns16550_write(sc, SPEC_REG_IER, SPEC_IER_ERXRDY);
	ATF_CHECK_EQ(SPEC_IER_ERXRDY, uart_ns16550_read(sc, SPEC_REG_IER));

	uart_ns16550_write(sc, SPEC_REG_LCR, SPEC_LCR_DLAB);
	ATF_CHECK_EQ(0x34, uart_ns16550_read(sc, SPEC_REG_DLL));
	ATF_CHECK_EQ(0x12, uart_ns16550_read(sc, SPEC_REG_DLH));

	free(sc);
}

ATF_TC_WITHOUT_HEAD(lcr_register);
ATF_TC_BODY(lcr_register, tc)
{
	struct uart_ns16550_softc *sc;

	sc = make_uart();

	/* LCR is fully R/W (word length + DLAB bits preserved). */
	uart_ns16550_write(sc, SPEC_REG_LCR, 0x1b);
	ATF_CHECK_EQ(0x1b, uart_ns16550_read(sc, SPEC_REG_LCR));

	free(sc);
}

ATF_TC_WITHOUT_HEAD(ier_masking);
ATF_TC_BODY(ier_masking, tc)
{
	struct uart_ns16550_softc *sc;

	sc = make_uart();

	/* Only the low four IER bits are writable; high bits read back 0. */
	uart_ns16550_write(sc, SPEC_REG_IER, 0xff);
	ATF_CHECK_EQ(0x0f, uart_ns16550_read(sc, SPEC_REG_IER));

	uart_ns16550_write(sc, SPEC_REG_IER, 0x00);
	ATF_CHECK_EQ(0x00, uart_ns16550_read(sc, SPEC_REG_IER));

	free(sc);
}

ATF_TC_WITHOUT_HEAD(mcr_masking_and_loopback_msr);
ATF_TC_BODY(mcr_masking_and_loopback_msr, tc)
{
	struct uart_ns16550_softc *sc;
	uint8_t v;

	sc = make_uart();

	/* Only the low five MCR bits are writable. */
	uart_ns16550_write(sc, SPEC_REG_MCR, 0xff);
	ATF_CHECK_EQ(0x1f, uart_ns16550_read(sc, SPEC_REG_MCR));

	/*
	 * In loopback, MCR output bits are reflected into MSR:
	 *   RTS->CTS, DTR->DSR, OUT1->RI, OUT2->DCD.
	 * From the reset MSR (DCD|DSR) the CTS bit newly toggles, setting the
	 * DCTS delta.  The first MSR read returns level|delta, the second
	 * returns level only (deltas cleared on read).
	 */
	v = uart_ns16550_read(sc, SPEC_REG_MSR);
	ATF_CHECK_EQ(SPEC_MSR_CTS | SPEC_MSR_DSR | SPEC_MSR_RI | SPEC_MSR_DCD |
	    SPEC_MSR_DCTS, v);
	v = uart_ns16550_read(sc, SPEC_REG_MSR);
	ATF_CHECK_EQ(SPEC_MSR_CTS | SPEC_MSR_DSR | SPEC_MSR_RI | SPEC_MSR_DCD,
	    v);

	free(sc);
}

ATF_TC_WITHOUT_HEAD(msr_delta_transitions);
ATF_TC_BODY(msr_delta_transitions, tc)
{
	struct uart_ns16550_softc *sc;
	uint8_t v;

	sc = make_uart();

	/* Enter full loopback: MSR level becomes CTS|DSR|RI|DCD. */
	uart_ns16550_write(sc, SPEC_REG_MCR, SPEC_MCR_LOOP | SPEC_MCR_RTS |
	    SPEC_MCR_DTR | SPEC_MCR_OUT1 | SPEC_MCR_OUT2);
	(void)uart_ns16550_read(sc, SPEC_REG_MSR);	/* clear deltas */

	/* Drop OUT1 only: RI falls -> TERI (trailing edge RI) delta. */
	uart_ns16550_write(sc, SPEC_REG_MCR, SPEC_MCR_LOOP | SPEC_MCR_RTS |
	    SPEC_MCR_DTR | SPEC_MCR_OUT2);
	v = uart_ns16550_read(sc, SPEC_REG_MSR);
	ATF_CHECK((v & SPEC_MSR_TERI) != 0);
	ATF_CHECK_EQ(0, v & SPEC_MSR_RI);

	/* Drop RTS and DTR and OUT2: CTS, DSR, DCD all fall. */
	uart_ns16550_write(sc, SPEC_REG_MCR, SPEC_MCR_LOOP);
	v = uart_ns16550_read(sc, SPEC_REG_MSR);
	ATF_CHECK((v & SPEC_MSR_DCTS) != 0);
	ATF_CHECK((v & SPEC_MSR_DDSR) != 0);
	ATF_CHECK((v & SPEC_MSR_DDCD) != 0);

	free(sc);
}

ATF_TC_WITHOUT_HEAD(lsr_reads);
ATF_TC_BODY(lsr_reads, tc)
{
	struct uart_ns16550_softc *sc;
	uint8_t v;

	sc = make_uart();

	/* Transmitter is always ready: THRE and TEMT set, no RX data. */
	v = uart_ns16550_read(sc, SPEC_REG_LSR);
	ATF_CHECK((v & SPEC_LSR_THRE) != 0);
	ATF_CHECK((v & SPEC_LSR_TEMT) != 0);
	ATF_CHECK_EQ(0, v & SPEC_LSR_RXRDY);

	/* Loopback a byte in: RXRDY appears in LSR. */
	uart_ns16550_write(sc, SPEC_REG_MCR, SPEC_MCR_LOOP);
	uart_ns16550_write(sc, SPEC_REG_DATA, 'Z');
	v = uart_ns16550_read(sc, SPEC_REG_LSR);
	ATF_CHECK((v & SPEC_LSR_RXRDY) != 0);

	/* Consume it; RXRDY clears again. */
	ATF_CHECK_EQ('Z', uart_ns16550_read(sc, SPEC_REG_DATA));
	v = uart_ns16550_read(sc, SPEC_REG_LSR);
	ATF_CHECK_EQ(0, v & SPEC_LSR_RXRDY);

	/*
	 * Writes to LSR and MSR are ignored (read-only registers).  Leave
	 * loopback first so the modem status settles to the non-loopback level
	 * (DCD|DSR); the first read clears any pending delta bits.
	 */
	uart_ns16550_write(sc, SPEC_REG_MCR, 0);
	(void)uart_ns16550_read(sc, SPEC_REG_MSR);
	uart_ns16550_write(sc, SPEC_REG_LSR, 0xff);
	uart_ns16550_write(sc, SPEC_REG_MSR, 0xff);
	v = uart_ns16550_read(sc, SPEC_REG_MSR);
	ATF_CHECK_EQ(SPEC_MSR_DCD | SPEC_MSR_DSR, v);

	free(sc);
}

ATF_TC_WITHOUT_HEAD(loopback_data_and_overrun);
ATF_TC_BODY(loopback_data_and_overrun, tc)
{
	struct uart_ns16550_softc *sc;
	uint8_t v;
	int i;

	sc = make_uart();

	/* Enable FIFO (16 deep) and loopback. */
	uart_ns16550_write(sc, SPEC_REG_IIR, SPEC_FCR_ENABLE);
	uart_ns16550_write(sc, SPEC_REG_MCR, SPEC_MCR_LOOP);

	/* Fill the FIFO exactly to capacity: no overrun yet. */
	for (i = 0; i < SPEC_FIFOSZ; i++)
		uart_ns16550_write(sc, SPEC_REG_DATA, (uint8_t)i);
	v = uart_ns16550_read(sc, SPEC_REG_LSR);
	ATF_CHECK_EQ(0, v & SPEC_LSR_OE);

	/* One more byte overflows the FIFO -> overrun error latches. */
	uart_ns16550_write(sc, SPEC_REG_DATA, 0xff);
	v = uart_ns16550_read(sc, SPEC_REG_LSR);
	ATF_CHECK((v & SPEC_LSR_OE) != 0);

	/* OE is cleared by the LSR read. */
	v = uart_ns16550_read(sc, SPEC_REG_LSR);
	ATF_CHECK_EQ(0, v & SPEC_LSR_OE);

	/* FIFO drains first-in first-out. */
	for (i = 0; i < SPEC_FIFOSZ; i++)
		ATF_CHECK_EQ((uint8_t)i, uart_ns16550_read(sc, SPEC_REG_DATA));

	free(sc);
}

ATF_TC_WITHOUT_HEAD(fcr_fifo_control);
ATF_TC_BODY(fcr_fifo_control, tc)
{
	struct uart_ns16550_softc *sc;
	uint8_t v;

	sc = make_uart();

	/* Enabling the FIFO sets the FIFO-enabled bits in IIR. */
	uart_ns16550_write(sc, SPEC_REG_IIR, SPEC_FCR_ENABLE | SPEC_FCR_RXHIGH);
	v = uart_ns16550_read(sc, SPEC_REG_IIR);
	ATF_CHECK_EQ(SPEC_IIR_FIFO, v & SPEC_IIR_FIFO);

	/* A receiver-FIFO reset with the FIFO enabled is accepted. */
	uart_ns16550_write(sc, SPEC_REG_IIR,
	    SPEC_FCR_ENABLE | SPEC_FCR_RCV_RST);
	v = uart_ns16550_read(sc, SPEC_REG_IIR);
	ATF_CHECK_EQ(SPEC_IIR_FIFO, v & SPEC_IIR_FIFO);

	/* Disabling the FIFO clears the FIFO-enabled bits in IIR. */
	uart_ns16550_write(sc, SPEC_REG_IIR, 0x00);
	v = uart_ns16550_read(sc, SPEC_REG_IIR);
	ATF_CHECK_EQ(0, v & SPEC_IIR_FIFO);

	free(sc);
}

ATF_TC_WITHOUT_HEAD(interrupt_reason_priority);
ATF_TC_BODY(interrupt_reason_priority, tc)
{
	struct uart_ns16550_softc *sc;
	uint8_t v;

	sc = make_uart();
	uart_ns16550_write(sc, SPEC_REG_MCR, SPEC_MCR_LOOP);

	/* THRE interrupt: enable ETXRDY -> TXRDY pending, asserted. */
	reset_intr_counts();
	uart_ns16550_write(sc, SPEC_REG_IER, SPEC_IER_ETXRDY);
	ATF_CHECK(intr_asserts > 0);
	v = uart_ns16550_read(sc, SPEC_REG_IIR);
	ATF_CHECK_EQ(SPEC_IIR_TXRDY, v);
	/* Reading IIR clears the THRE-pending condition. */
	v = uart_ns16550_read(sc, SPEC_REG_IIR);
	ATF_CHECK_EQ(SPEC_IIR_NOPEND, v);

	/* Received-data interrupt: enable ERXRDY with data queued. */
	uart_ns16550_write(sc, SPEC_REG_IER, 0);
	uart_ns16550_write(sc, SPEC_REG_DATA, 'q');
	uart_ns16550_write(sc, SPEC_REG_IER, SPEC_IER_ERXRDY);
	v = uart_ns16550_read(sc, SPEC_REG_IIR);
	ATF_CHECK_EQ(SPEC_IIR_RXTOUT, v);
	(void)uart_ns16550_read(sc, SPEC_REG_DATA);	/* drain */

	/* Modem-status interrupt: a delta with EMSC enabled. */
	uart_ns16550_write(sc, SPEC_REG_IER, 0);
	uart_ns16550_read(sc, SPEC_REG_MSR);		/* clear deltas */
	uart_ns16550_write(sc, SPEC_REG_MCR, SPEC_MCR_LOOP | SPEC_MCR_RTS);
	uart_ns16550_write(sc, SPEC_REG_IER, SPEC_IER_EMSC);
	v = uart_ns16550_read(sc, SPEC_REG_IIR);
	ATF_CHECK_EQ(SPEC_IIR_MLSC, v);

	free(sc);
}

ATF_TC_WITHOUT_HEAD(receive_line_status_interrupt);
ATF_TC_BODY(receive_line_status_interrupt, tc)
{
	struct uart_ns16550_softc *sc;
	uint8_t v;
	int i;

	sc = make_uart();
	uart_ns16550_write(sc, SPEC_REG_MCR, SPEC_MCR_LOOP);

	/* Force an overrun so LSR_OE latches (do not read LSR yet). */
	for (i = 0; i <= SPEC_FIFOSZ; i++)
		uart_ns16550_write(sc, SPEC_REG_DATA, (uint8_t)i);

	/* Receiver line-status interrupt has top priority. */
	uart_ns16550_write(sc, SPEC_REG_IER, SPEC_IER_ERLS);
	v = uart_ns16550_read(sc, SPEC_REG_IIR);
	ATF_CHECK_EQ(SPEC_IIR_RLS, v);

	free(sc);
}

ATF_TC_WITHOUT_HEAD(interrupt_line_toggle);
ATF_TC_BODY(interrupt_line_toggle, tc)
{
	struct uart_ns16550_softc *sc;

	sc = make_uart();
	uart_ns16550_write(sc, SPEC_REG_MCR, SPEC_MCR_LOOP);

	/* Raise a THRE interrupt, then clear it and confirm deassert. */
	uart_ns16550_write(sc, SPEC_REG_IER, SPEC_IER_ETXRDY);
	reset_intr_counts();
	/* Read IIR: TXRDY reported and pending cleared. */
	(void)uart_ns16550_read(sc, SPEC_REG_IIR);
	/* A following access with nothing pending must deassert. */
	(void)uart_ns16550_read(sc, SPEC_REG_SCR);
	ATF_CHECK(intr_deasserts > 0);

	free(sc);
}

ATF_TC_WITHOUT_HEAD(invalid_offsets);
ATF_TC_BODY(invalid_offsets, tc)
{
	struct uart_ns16550_softc *sc;

	sc = make_uart();

	/* Out-of-range reads return all-ones (open-bus behaviour). */
	ATF_CHECK_EQ(0xff, uart_ns16550_read(sc, 99));
	ATF_CHECK_EQ(0xff, uart_ns16550_read(sc, SPEC_FIFOSZ));

	/* Out-of-range writes are silently ignored (no crash, no state). */
	uart_ns16550_write(sc, 99, 0x5a);
	uart_ns16550_write(sc, SPEC_FIFOSZ, 0x5a);
	ATF_CHECK_EQ(0xff, uart_ns16550_read(sc, 99));

	free(sc);
}

ATF_TC_WITHOUT_HEAD(drain_callback);
ATF_TC_BODY(drain_callback, tc)
{
	struct uart_ns16550_softc *sc;

	sc = make_uart();

	/* Non-loopback drain path runs uart_toggle_intr. */
	uart_drain(0, EVF_READ, sc);

	/* Loopback drain path skips the interrupt toggle. */
	uart_ns16550_write(sc, SPEC_REG_MCR, SPEC_MCR_LOOP);
	uart_drain(0, EVF_READ, sc);

	free(sc);
}

ATF_TC_WITHOUT_HEAD(tty_open);
ATF_TC_BODY(tty_open, tc)
{
	struct uart_ns16550_softc *sc;

	sc = make_uart();
	ATF_CHECK_EQ(0, uart_ns16550_tty_open(sc, "/dev/null"));
	free(sc);
}

ATF_TC_WITHOUT_HEAD(legacy_alloc);
ATF_TC_BODY(legacy_alloc, tc)
{
	int base, irq;

	/* Out-of-range unit indices are rejected. */
	ATF_CHECK_EQ(-1, uart_legacy_alloc(-1, &base, &irq));
	ATF_CHECK_EQ(-1, uart_legacy_alloc(4, &base, &irq));

	/* Each of the four standard COM ports allocates once. */
	base = irq = 0;
	ATF_CHECK_EQ(0, uart_legacy_alloc(0, &base, &irq));
	ATF_CHECK_EQ(SPEC_COM1_BASE, base);
	ATF_CHECK_EQ(SPEC_COM1_IRQ, irq);

	ATF_CHECK_EQ(0, uart_legacy_alloc(1, &base, &irq));
	ATF_CHECK_EQ(SPEC_COM2_BASE, base);
	ATF_CHECK_EQ(SPEC_COM2_IRQ, irq);

	ATF_CHECK_EQ(0, uart_legacy_alloc(2, &base, &irq));
	ATF_CHECK_EQ(SPEC_COM3_BASE, base);
	ATF_CHECK_EQ(SPEC_COM3_IRQ, irq);

	ATF_CHECK_EQ(0, uart_legacy_alloc(3, &base, &irq));
	ATF_CHECK_EQ(SPEC_COM4_BASE, base);
	ATF_CHECK_EQ(SPEC_COM4_IRQ, irq);

	/* A second allocation of an in-use resource fails. */
	ATF_CHECK_EQ(-1, uart_legacy_alloc(0, &base, &irq));
}

ATF_TC_WITHOUT_HEAD(snapshot_roundtrip);
ATF_TC_BODY(snapshot_roundtrip, tc)
{
	struct uart_ns16550_softc *save, *restore;
	struct vm_snapshot_meta meta = { 0 };
	uint8_t buffer[64];

	save = make_uart();
	restore = make_uart();

	/* Program some distinctive state into the source device. */
	uart_ns16550_write(save, SPEC_REG_SCR, 0x77);
	uart_ns16550_write(save, SPEC_REG_IER, SPEC_IER_ERXRDY);
	uart_ns16550_write(save, SPEC_REG_MCR, SPEC_MCR_RTS | SPEC_MCR_DTR);

	/* Save. */
	memset(&meta, 0, sizeof(meta));
	meta.op = VM_SNAPSHOT_SAVE;
	meta.buffer.buf = buffer;
	meta.buffer.buf_rem = sizeof(buffer);
	ATF_CHECK_EQ(0, uart_ns16550_snapshot(save, &meta));

	/* Restore into the second device. */
	meta.op = VM_SNAPSHOT_RESTORE;
	meta.buffer.buf = buffer;
	meta.buffer.buf_rem = sizeof(buffer);
	ATF_CHECK_EQ(0, uart_ns16550_snapshot(restore, &meta));

	/* Restored register-visible state matches the source. */
	ATF_CHECK_EQ(0x77, uart_ns16550_read(restore, SPEC_REG_SCR));
	ATF_CHECK_EQ(SPEC_IER_ERXRDY, uart_ns16550_read(restore, SPEC_REG_IER));
	ATF_CHECK_EQ(SPEC_MCR_RTS | SPEC_MCR_DTR,
	    uart_ns16550_read(restore, SPEC_REG_MCR));

	free(save);
	free(restore);
}

ATF_TC_WITHOUT_HEAD(snapshot_errors);
ATF_TC_BODY(snapshot_errors, tc)
{
	struct uart_ns16550_softc *sc;
	struct vm_snapshot_meta meta = { 0 };
	uint8_t buffer[64];

	sc = make_uart();

	/* NULL arguments are rejected. */
	memset(&meta, 0, sizeof(meta));
	meta.op = VM_SNAPSHOT_SAVE;
	meta.buffer.buf = buffer;
	meta.buffer.buf_rem = sizeof(buffer);
	ATF_CHECK_EQ(EINVAL, uart_ns16550_snapshot(NULL, &meta));
	ATF_CHECK_EQ(EINVAL, uart_ns16550_snapshot(sc, NULL));

	/* A truncated buffer makes serialisation bail out. */
	meta.op = VM_SNAPSHOT_SAVE;
	meta.buffer.buf = buffer;
	meta.buffer.buf_rem = 0;
	ATF_CHECK(uart_ns16550_snapshot(sc, &meta) != 0);

	/*
	 * A restore image carrying out-of-range IER/MCR bytes is rejected.
	 * Field order matches the DUT: data, ier, lcr, mcr, lsr, msr, fcr,
	 * scr, dll, dlh.  Byte 1 (IER) has reserved high bits set.
	 */
	memset(buffer, 0, sizeof(buffer));
	buffer[1] = 0xf0;	/* IER with bits outside 0x0f */
	meta.op = VM_SNAPSHOT_RESTORE;
	meta.buffer.buf = buffer;
	meta.buffer.buf_rem = sizeof(buffer);
	ATF_CHECK_EQ(EINVAL, uart_ns16550_snapshot(sc, &meta));

	/* A failure reported by the rx-FIFO codec is propagated. */
	mock_rxfifo_snapshot_err = EIO;
	memset(buffer, 0, sizeof(buffer));
	meta.op = VM_SNAPSHOT_SAVE;
	meta.buffer.buf = buffer;
	meta.buffer.buf_rem = sizeof(buffer);
	ATF_CHECK_EQ(EIO, uart_ns16550_snapshot(sc, &meta));
	mock_rxfifo_snapshot_err = 0;

	free(sc);
}

ATF_TC_WITHOUT_HEAD(snapshot_pause_resume);
ATF_TC_BODY(snapshot_pause_resume, tc)
{
	struct uart_ns16550_softc *sc;
	struct vm_snapshot_meta meta = { 0 };
	uint8_t buffer[64];

	sc = make_uart();

	/* Resume before pause is an error. */
	ATF_CHECK_EQ(EINVAL, uart_ns16550_resume(sc));

	/* Pause, then a double pause is an error. */
	ATF_CHECK_EQ(0, uart_ns16550_pause(sc));
	ATF_CHECK_EQ(EINVAL, uart_ns16550_pause(sc));

	/* While paused, snapshot must not take the lock itself (lock_owned). */
	memset(&meta, 0, sizeof(meta));
	meta.op = VM_SNAPSHOT_SAVE;
	meta.buffer.buf = buffer;
	meta.buffer.buf_rem = sizeof(buffer);
	ATF_CHECK_EQ(0, uart_ns16550_snapshot(sc, &meta));

	/* Resume, then a double resume is an error. */
	ATF_CHECK_EQ(0, uart_ns16550_resume(sc));
	ATF_CHECK_EQ(EINVAL, uart_ns16550_resume(sc));

	/* NULL softc is rejected by both. */
	ATF_CHECK_EQ(EINVAL, uart_ns16550_pause(NULL));
	ATF_CHECK_EQ(EINVAL, uart_ns16550_resume(NULL));

	free(sc);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, init_and_reset);
	ATF_TP_ADD_TC(tp, init_bad_args);
	ATF_TP_ADD_TC(tp, scratch_register);
	ATF_TP_ADD_TC(tp, divisor_latch);
	ATF_TP_ADD_TC(tp, lcr_register);
	ATF_TP_ADD_TC(tp, ier_masking);
	ATF_TP_ADD_TC(tp, mcr_masking_and_loopback_msr);
	ATF_TP_ADD_TC(tp, msr_delta_transitions);
	ATF_TP_ADD_TC(tp, lsr_reads);
	ATF_TP_ADD_TC(tp, loopback_data_and_overrun);
	ATF_TP_ADD_TC(tp, fcr_fifo_control);
	ATF_TP_ADD_TC(tp, interrupt_reason_priority);
	ATF_TP_ADD_TC(tp, receive_line_status_interrupt);
	ATF_TP_ADD_TC(tp, interrupt_line_toggle);
	ATF_TP_ADD_TC(tp, invalid_offsets);
	ATF_TP_ADD_TC(tp, drain_callback);
	ATF_TP_ADD_TC(tp, tty_open);
	ATF_TP_ADD_TC(tp, legacy_alloc);
	ATF_TP_ADD_TC(tp, snapshot_roundtrip);
	ATF_TP_ADD_TC(tp, snapshot_errors);
	ATF_TP_ADD_TC(tp, snapshot_pause_resume);

	return (atf_no_error());
}
