/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Model tests for the STRUCT_VATPIT snapshot codec.  The real kernel
 * vatpit.c is compiled against the harness's shadow kernel headers; uptime
 * is test-controlled, so restore can be performed on a "destination" whose
 * uptime differs wildly from the "source" and the guest-visible counter and
 * IRQ0 callout deadline can be asserted exactly.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include <machine/vmm.h>
#include <machine/vmm_snapshot.h>
#include <sys/systm.h>	/* harness shadow: mock uptime/callout surface */

/* Test-visible globals consumed by the shadow <sys/systm.h>. */
struct bintime kmock_uptime;
int tc_precexp = 5;

/* Stub surface required by vatpit.c. */
static struct vatpit *kmock_vatpit;
static u_int kmock_atpic_pulses;
static u_int kmock_ioapic_pulses;

struct vatpit *
vm_atpit(struct vm *vm __unused)
{

	return (kmock_vatpit);
}

int
vatpic_pulse_irq(struct vm *vm __unused, int irq)
{

	ATF_REQUIRE_EQ(0, irq);
	kmock_atpic_pulses++;
	return (0);
}

int
vioapic_pulse_irq(struct vm *vm __unused, int irq)
{

	ATF_REQUIRE_EQ(2, irq);
	kmock_ioapic_pulses++;
	return (0);
}

/* Userspace implementation of the snapshot buffer cursor. */
int
vm_snapshot_buf(void *data, size_t data_size, struct vm_snapshot_meta *meta)
{
	struct vm_snapshot_buffer *buffer;

	buffer = &meta->buffer;
	if (buffer->buf_rem < data_size)
		return (E2BIG);
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(buffer->buf, data, data_size);
	else if (meta->op == VM_SNAPSHOT_RESTORE)
		memcpy(data, buffer->buf, data_size);
	else
		return (EINVAL);
	buffer->buf += data_size;
	buffer->buf_rem -= data_size;
	return (0);
}

void
vm_snapshot_buf_err(const char *bufname __unused,
    const enum vm_snapshot_op op __unused)
{
}

#include "../../../../sys/amd64/vmm/io/vatpit.c"

/*
 * Exact wire size of the generation-2 record:
 * magic(4) + freq(16) + 3 * (mode(4) + initial(2) + elapsed(16) + cr(2) +
 * ol(2) + slatched(1) + status(1) + crbyte(4) + frbyte(4) + armed(1) +
 * remaining(16)) = 179.
 */
#define	GEN2_RECORD_SIZE	179
#define	GEN2_CH0_ARMED_OFF	56
#define	GEN2_CH0_REMSEC_OFF	57

static struct bintime
ticks_bt(uint64_t ticks)
{
	struct bintime bt, freq_bt;

	FREQ2BT(PIT_8254_FREQ, &freq_bt);
	bt.sec = ticks / PIT_8254_FREQ;
	bt.frac = freq_bt.frac * (ticks % PIT_8254_FREQ);
	return (bt);
}

static void
advance_ticks(uint64_t ticks)
{
	struct bintime bt;

	bt = ticks_bt(ticks);
	bintime_add(&kmock_uptime, &bt);
}

static void
pit_write8(int port, uint8_t val)
{
	uint32_t eax;

	eax = val;
	ATF_REQUIRE_EQ(0, vatpit_handler(NULL, false, port, 1, &eax));
}

static uint8_t
pit_read8(int port)
{
	uint32_t eax;

	eax = 0;
	ATF_REQUIRE_EQ(0, vatpit_handler(NULL, true, port, 1, &eax));
	return ((uint8_t)eax);
}

static uint16_t
pit_latch_read_cntr0(void)
{
	uint16_t lsb, msb;

	/* Latch command: counter 0, rw bits 0. */
	pit_write8(TIMER_MODE, TIMER_SEL0 | TIMER_LATCH);
	lsb = pit_read8(TIMER_CNTR0);
	msb = pit_read8(TIMER_CNTR0);
	return ((uint16_t)(msb << 8 | lsb));
}

static int
do_snapshot(struct vatpit *vatpit, enum vm_snapshot_op op, uint8_t *buf,
    size_t len, size_t *consumed)
{
	struct vm_snapshot_meta meta = {
		.dev_name = "vatpit",
		.dev_req = STRUCT_VATPIT,
		.buffer = {
			.buf_start = buf,
			.buf_size = len,
			.buf = buf,
			.buf_rem = len,
		},
		.op = op,
	};
	int ret;

	ret = vatpit_snapshot(vatpit, &meta);
	if (consumed != NULL)
		*consumed = len - meta.buffer.buf_rem;
	return (ret);
}

static struct vatpit *
new_pit(time_t sec, uint64_t frac)
{

	kmock_uptime.sec = sec;
	kmock_uptime.frac = frac;
	kmock_vatpit = vatpit_init(NULL);
	return (kmock_vatpit);
}

ATF_TC_WITHOUT_HEAD(destination_uptime_differential);
ATF_TC_BODY(destination_uptime_differential, tc)
{
	struct vatpit *src, *dst;
	struct bintime exp_bt, period_bt;
	struct {
		time_t sec;
		uint64_t frac;
	} dst_uptime[2] = {
		/* Destination far younger and far older than the source. */
		{ 3, (uint64_t)1 << 62 },
		{ 2000000, 12345 },
	};
	uint8_t buf[512];
	size_t consumed;
	sbintime_t target;
	u_int i;

	src = new_pit(1000, 0);
	/* Counter 0, LSB+MSB, mode 2 (rate generator), initial = 10000. */
	pit_write8(TIMER_MODE, TIMER_SEL0 | TIMER_16BIT | TIMER_RATEGEN);
	pit_write8(TIMER_CNTR0, 0x10);
	pit_write8(TIMER_CNTR0, 0x27);
	ATF_REQUIRE_EQ(1, src->channel[0].callout.c_resets);

	advance_ticks(3000);
	ATF_REQUIRE_EQ(7000, pit_latch_read_cntr0());

	ATF_REQUIRE_EQ(0, do_snapshot(src, VM_SNAPSHOT_SAVE, buf, sizeof(buf),
	    &consumed));
	ATF_REQUIRE_EQ(GEN2_RECORD_SIZE, consumed);

	for (i = 0; i < nitems(dst_uptime); i++) {
		kmock_atpic_pulses = kmock_ioapic_pulses = 0;
		dst = new_pit(dst_uptime[i].sec, dst_uptime[i].frac);
		ATF_REQUIRE_EQ(0, do_snapshot(dst, VM_SNAPSHOT_RESTORE, buf,
		    GEN2_RECORD_SIZE, NULL));

		ATF_CHECK_EQ(10000, dst->channel[0].initial);
		ATF_CHECK_EQ(TIMER_RATEGEN, dst->channel[0].mode);

		/* Guest-visible counter continues from the source value. */
		ATF_CHECK_EQ(7000, pit_latch_read_cntr0());

		/*
		 * The IRQ0 deadline is the serialized remaining time (7000
		 * ticks) measured from *destination* uptime.
		 */
		ATF_REQUIRE_EQ(1, dst->channel[0].callout.c_resets);
		ATF_REQUIRE(callout_active(&dst->channel[0].callout));
		ATF_CHECK_EQ(C_ABSOLUTE, dst->channel[0].callout.c_kmock_flags);
		exp_bt = kmock_uptime;
		period_bt = ticks_bt(7000);
		bintime_add(&exp_bt, &period_bt);
		target = bttosbt(exp_bt);
		ATF_CHECK_EQ(target, dst->channel[0].callout.c_sbt);

		/* Counter keeps counting on the destination clock. */
		advance_ticks(2000);
		ATF_CHECK_EQ(5000, pit_latch_read_cntr0());

		/* Fire at the deadline: one IRQ0 pulse, periodic rearm. */
		advance_ticks(5000);
		kmock_callout_fire(&dst->channel[0].callout);
		ATF_CHECK_EQ(1, kmock_atpic_pulses);
		ATF_CHECK_EQ(1, kmock_ioapic_pulses);
		ATF_REQUIRE_EQ(2, dst->channel[0].callout.c_resets);
		period_bt = ticks_bt(10000);
		bintime_add(&exp_bt, &period_bt);
		ATF_CHECK_EQ(bttosbt(exp_bt), dst->channel[0].callout.c_sbt);

		vatpit_cleanup(dst);
	}
	kmock_vatpit = src;
	vatpit_cleanup(src);
}

ATF_TC_WITHOUT_HEAD(expired_oneshot_not_rearmed);
ATF_TC_BODY(expired_oneshot_not_rearmed, tc)
{
	struct vatpit *src, *dst;
	uint8_t buf[512];
	size_t consumed;

	src = new_pit(50, 0);
	/* Counter 0, LSB+MSB, mode 0 (interrupt on terminal count), 100. */
	pit_write8(TIMER_MODE, TIMER_SEL0 | TIMER_16BIT | TIMER_INTTC);
	pit_write8(TIMER_CNTR0, 100);
	pit_write8(TIMER_CNTR0, 0);
	ATF_REQUIRE_EQ(1, src->channel[0].callout.c_resets);

	/* Let the one-shot fire on the source before the checkpoint. */
	advance_ticks(150);
	kmock_atpic_pulses = kmock_ioapic_pulses = 0;
	kmock_callout_fire(&src->channel[0].callout);
	ATF_REQUIRE_EQ(1, kmock_atpic_pulses);
	ATF_REQUIRE(!callout_active(&src->channel[0].callout));

	ATF_REQUIRE_EQ(0, do_snapshot(src, VM_SNAPSHOT_SAVE, buf, sizeof(buf),
	    &consumed));
	ATF_REQUIRE_EQ(GEN2_RECORD_SIZE, consumed);

	dst = new_pit(7, 0);
	kmock_atpic_pulses = kmock_ioapic_pulses = 0;
	ATF_REQUIRE_EQ(0, do_snapshot(dst, VM_SNAPSHOT_RESTORE, buf,
	    GEN2_RECORD_SIZE, NULL));

	/* No spurious rearm and hence no spurious IRQ0 on the destination. */
	ATF_CHECK_EQ(0, dst->channel[0].callout.c_resets);
	ATF_CHECK(!callout_active(&dst->channel[0].callout));
	ATF_CHECK_EQ(0, kmock_atpic_pulses);

	/* The free-running counter continues from the source position. */
	ATF_CHECK_EQ(50, pit_latch_read_cntr0());
	advance_ticks(30);
	ATF_CHECK_EQ(20, pit_latch_read_cntr0());

	vatpit_cleanup(dst);
	kmock_vatpit = src;
	vatpit_cleanup(src);
}

/* Serialize a generation-1 (absolute source uptime) record. */
static size_t
put_bytes(uint8_t *buf, size_t off, const void *data, size_t len)
{

	memcpy(buf + off, data, len);
	return (off + len);
}

ATF_TC_WITHOUT_HEAD(gen1_record_rejected);
ATF_TC_BODY(gen1_record_rejected, tc)
{
	struct vatpit *dst;
	struct bintime freq_bt, bt;
	uint8_t buf[512];
	uint16_t initial;
	int32_t mode, zero32;
	uint8_t zero8;
	size_t off;
	int i;

	memset(buf, 0, sizeof(buf));
	FREQ2BT(PIT_8254_FREQ, &freq_bt);
	off = 0;
	off = put_bytes(buf, off, &freq_bt.sec, sizeof(freq_bt.sec));
	off = put_bytes(buf, off, &freq_bt.frac, sizeof(freq_bt.frac));
	zero32 = 0;
	zero8 = 0;
	for (i = 0; i < 3; i++) {
		mode = (i == 0) ? TIMER_RATEGEN : TIMER_INTTC;
		initial = (i == 0) ? 10000 : 0;
		bt.sec = 1000;	/* absolute source uptime */
		bt.frac = 0;
		off = put_bytes(buf, off, &mode, sizeof(mode));
		off = put_bytes(buf, off, &initial, sizeof(initial));
		off = put_bytes(buf, off, &bt.sec, sizeof(bt.sec));
		off = put_bytes(buf, off, &bt.frac, sizeof(bt.frac));
		off = put_bytes(buf, off, &zero8, 1);	/* cr[0] */
		off = put_bytes(buf, off, &zero8, 1);	/* cr[1] */
		off = put_bytes(buf, off, &zero8, 1);	/* ol[0] */
		off = put_bytes(buf, off, &zero8, 1);	/* ol[1] */
		off = put_bytes(buf, off, &zero8, 1);	/* slatched */
		off = put_bytes(buf, off, &zero8, 1);	/* status */
		off = put_bytes(buf, off, &zero32, sizeof(zero32)); /* crbyte */
		off = put_bytes(buf, off, &zero32, sizeof(zero32)); /* frbyte */
		bt.sec = 1000;
		bt.frac = 0x1234;
		off = put_bytes(buf, off, &bt.sec, sizeof(bt.sec));
		off = put_bytes(buf, off, &bt.frac, sizeof(bt.frac));
	}
	ATF_REQUIRE_EQ(172, off);	/* historical record size */

	dst = new_pit(9, 0);
	ATF_CHECK(do_snapshot(dst, VM_SNAPSHOT_RESTORE, buf, off, NULL) != 0);
	/* Nothing was published to the destination. */
	ATF_CHECK_EQ(0, dst->channel[0].initial);
	ATF_CHECK_EQ(0, dst->channel[0].callout.c_resets);
	vatpit_cleanup(dst);
}

ATF_TC_WITHOUT_HEAD(validator_rejects_tampered_records);
ATF_TC_BODY(validator_rejects_tampered_records, tc)
{
	struct vatpit *src, *dst;
	uint8_t buf[512], tampered[512];
	size_t consumed;

	src = new_pit(100, 0);
	pit_write8(TIMER_MODE, TIMER_SEL0 | TIMER_16BIT | TIMER_RATEGEN);
	pit_write8(TIMER_CNTR0, 0x10);
	pit_write8(TIMER_CNTR0, 0x27);
	advance_ticks(500);
	ATF_REQUIRE_EQ(0, do_snapshot(src, VM_SNAPSHOT_SAVE, buf, sizeof(buf),
	    &consumed));
	ATF_REQUIRE_EQ(GEN2_RECORD_SIZE, consumed);

	/* Zeroed magic: rejected before publication. */
	memcpy(tampered, buf, sizeof(buf));
	memset(tampered, 0, 4);
	dst = new_pit(4, 0);
	ATF_CHECK_EQ(EINVAL, do_snapshot(dst, VM_SNAPSHOT_RESTORE, tampered,
	    GEN2_RECORD_SIZE, NULL));
	ATF_CHECK_EQ(0, dst->channel[0].initial);
	vatpit_cleanup(dst);

	/* Out-of-range armed flag. */
	memcpy(tampered, buf, sizeof(buf));
	tampered[GEN2_CH0_ARMED_OFF] = 2;
	dst = new_pit(4, 0);
	ATF_CHECK_EQ(EINVAL, do_snapshot(dst, VM_SNAPSHOT_RESTORE, tampered,
	    GEN2_RECORD_SIZE, NULL));
	vatpit_cleanup(dst);

	/* Remaining time beyond one period (1s >> 10000 ticks). */
	memcpy(tampered, buf, sizeof(buf));
	tampered[GEN2_CH0_REMSEC_OFF] = 1;
	dst = new_pit(4, 0);
	ATF_CHECK_EQ(EINVAL, do_snapshot(dst, VM_SNAPSHOT_RESTORE, tampered,
	    GEN2_RECORD_SIZE, NULL));
	ATF_CHECK_EQ(0, dst->channel[0].callout.c_resets);
	vatpit_cleanup(dst);

	kmock_vatpit = src;
	vatpit_cleanup(src);
}

ATF_TC_WITHOUT_HEAD(live_output_latch_still_busy);
ATF_TC_BODY(live_output_latch_still_busy, tc)
{
	struct vatpit *src;
	uint8_t buf[512];

	src = new_pit(30, 0);
	pit_write8(TIMER_MODE, TIMER_SEL0 | TIMER_16BIT | TIMER_RATEGEN);
	pit_write8(TIMER_CNTR0, 0x10);
	pit_write8(TIMER_CNTR0, 0x27);
	advance_ticks(100);

	/* Latch and consume only one byte: checkpoint must refuse. */
	pit_write8(TIMER_MODE, TIMER_SEL0 | TIMER_LATCH);
	(void)pit_read8(TIMER_CNTR0);
	ATF_CHECK_EQ(EBUSY, do_snapshot(src, VM_SNAPSHOT_SAVE, buf,
	    sizeof(buf), NULL));

	/* Consuming the second byte unblocks it. */
	(void)pit_read8(TIMER_CNTR0);
	ATF_CHECK_EQ(0, do_snapshot(src, VM_SNAPSHOT_SAVE, buf, sizeof(buf),
	    NULL));
	vatpit_cleanup(src);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, destination_uptime_differential);
	ATF_TP_ADD_TC(tp, expired_oneshot_not_rearmed);
	ATF_TP_ADD_TC(tp, gen1_record_rejected);
	ATF_TP_ADD_TC(tp, validator_rejects_tampered_records);
	ATF_TP_ADD_TC(tp, live_output_latch_still_busy);
	return (atf_no_error());
}
