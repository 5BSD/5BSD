/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Model tests for the STRUCT_VRTC snapshot codec, focused on the restore
 * validator vrtc_snapshot_state_valid().  A migrating guest controls the
 * serialized base_rtctime; an out-of-range value would flow into
 * secs_to_rtc() on the next guest RTC read and index bin2bcd_data[] past its
 * 100 entries via ct.year / 100 -- a guest-visible out-of-bounds read.  The
 * validator must reject negative and overflowing values while still accepting
 * the VRTC_BROKEN_TIME (-1) sentinel and the exact representable maximum.
 *
 * The real vrtc.c is compiled against the harness's shadow kernel headers.
 * clocktime<->timespec conversion is delegated to libc so vrtc_init()'s
 * secs_to_rtc(0) path builds a valid 1970-01-01 register set.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/clock.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <atf-c.h>

#include <machine/vmm.h>
#include <machine/vmm_snapshot.h>
#include <sys/systm.h>	/* harness shadow: extern decls for the globals below */

/* Test-visible globals consumed by the shadow <sys/systm.h>. */
struct bintime kmock_uptime = { .sec = 12345, .frac = 0 };
int tc_precexp = 5;

/*
 * BCD lookup table indexed by a binary value in [0, 99]; matches the libkern
 * bin2bcd_data[] the kernel indexes from rtcset().
 */
u_char const bin2bcd_data[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
};

/* Kernel clocktime<->timespec, over libc gmtime_r()/timegm(). */
void
clock_ts_to_ct(const struct timespec *ts, struct clocktime *ct)
{
	struct tm tm;
	time_t t = ts->tv_sec;

	memset(&tm, 0, sizeof(tm));
	gmtime_r(&t, &tm);
	ct->year = tm.tm_year + 1900;
	ct->mon = tm.tm_mon + 1;
	ct->day = tm.tm_mday;
	ct->hour = tm.tm_hour;
	ct->min = tm.tm_min;
	ct->sec = tm.tm_sec;
	ct->dow = tm.tm_wday;
	ct->nsec = ts->tv_nsec;
}

int
clock_ct_to_ts(const struct clocktime *ct, struct timespec *ts)
{
	struct tm tm;

	memset(&tm, 0, sizeof(tm));
	tm.tm_year = ct->year - 1900;
	tm.tm_mon = ct->mon - 1;
	tm.tm_mday = ct->day;
	tm.tm_hour = ct->hour;
	tm.tm_min = ct->min;
	tm.tm_sec = ct->sec;
	ts->tv_sec = timegm(&tm);
	ts->tv_nsec = ct->nsec;
	return (0);
}

/* Stub surface required by vrtc.c. */
static struct vrtc *kmock_vrtc;
static u_int kmock_atpic_pulses;
static u_int kmock_ioapic_pulses;

struct vrtc *
vm_rtc(struct vm *vm __unused)
{

	return (kmock_vrtc);
}

int
vatpic_pulse_irq(struct vm *vm __unused, int irq __unused)
{

	kmock_atpic_pulses++;
	return (0);
}

int
vioapic_pulse_irq(struct vm *vm __unused, int irq __unused)
{

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

#include "../../../../sys/amd64/vmm/io/vrtc.c"

/*
 * Wire size: addr(4) + base_rtctime(8) + sizeof(struct rtcdev)(128) = 140.
 * base_rtctime is serialized immediately after addr, so it lives at offset 4.
 */
#define	VRTC_RECORD_SIZE	140
#define	VRTC_BASE_RTCTIME_OFF	4

static int
do_snapshot(struct vrtc *vrtc, enum vm_snapshot_op op, uint8_t *buf,
    size_t len, size_t *consumed)
{
	struct vm_snapshot_meta meta = {
		.dev_name = "vrtc",
		.dev_req = STRUCT_VRTC,
		.buffer = {
			.buf_start = buf,
			.buf_size = len,
			.buf = buf,
			.buf_rem = len,
		},
		.op = op,
	};
	int ret;

	ret = vrtc_snapshot(vrtc, &meta);
	if (consumed != NULL)
		*consumed = len - meta.buffer.buf_rem;
	return (ret);
}

/*
 * Save 'src' after forcing its base_rtctime to 'rtctime'.  The SAVE path does
 * not validate, so this produces a wire image carrying an arbitrary (possibly
 * illegal) base_rtctime for the restore-side checks below.
 */
static void
save_with_base(struct vrtc *src, time_t rtctime, uint8_t *buf, size_t len)
{
	size_t consumed;

	VRTC_LOCK(src);
	src->base_rtctime = rtctime;
	VRTC_UNLOCK(src);
	ATF_REQUIRE_EQ(0, do_snapshot(src, VM_SNAPSHOT_SAVE, buf, len,
	    &consumed));
	ATF_REQUIRE_EQ(VRTC_RECORD_SIZE, consumed);
}

ATF_TC_WITHOUT_HEAD(base_rtctime_round_trip);
ATF_TC_BODY(base_rtctime_round_trip, tc)
{
	struct vrtc *src, *dst;
	uint8_t buf[256];
	time_t saved;

	src = vrtc_init(NULL);
	kmock_vrtc = src;
	saved = 1700000000;	/* 2023-11-14, well inside range */
	save_with_base(src, saved, buf, sizeof(buf));

	dst = vrtc_init(NULL);
	kmock_vrtc = dst;
	ATF_REQUIRE_EQ(0, do_snapshot(dst, VM_SNAPSHOT_RESTORE, buf,
	    VRTC_RECORD_SIZE, NULL));
	ATF_CHECK_EQ(saved, dst->base_rtctime);

	vrtc_cleanup(dst);
	kmock_vrtc = src;
	vrtc_cleanup(src);
}

ATF_TC_WITHOUT_HEAD(restore_rejects_negative_base_rtctime);
ATF_TC_BODY(restore_rejects_negative_base_rtctime, tc)
{
	struct vrtc *src, *dst;
	uint8_t buf[256];
	time_t before;

	src = vrtc_init(NULL);
	kmock_vrtc = src;
	/* Negative but NOT the broken sentinel: still illegal. */
	save_with_base(src, (time_t)-2, buf, sizeof(buf));

	dst = vrtc_init(NULL);
	kmock_vrtc = dst;
	before = dst->base_rtctime;
	ATF_CHECK_EQ(EINVAL, do_snapshot(dst, VM_SNAPSHOT_RESTORE, buf,
	    VRTC_RECORD_SIZE, NULL));
	/* Rejected before publication: destination state is untouched. */
	ATF_CHECK_EQ(before, dst->base_rtctime);

	vrtc_cleanup(dst);
	kmock_vrtc = src;
	vrtc_cleanup(src);
}

ATF_TC_WITHOUT_HEAD(restore_accepts_broken_sentinel);
ATF_TC_BODY(restore_accepts_broken_sentinel, tc)
{
	struct vrtc *src, *dst;
	uint8_t buf[256];

	src = vrtc_init(NULL);
	kmock_vrtc = src;
	/*
	 * VRTC_BROKEN_TIME is (time_t)-1 -- a *negative* value the validator
	 * must nonetheless accept.  A naive "reject if < 0" check would wrongly
	 * drop a legitimately-halted RTC snapshot; this pins the exception.
	 */
	save_with_base(src, VRTC_BROKEN_TIME, buf, sizeof(buf));

	dst = vrtc_init(NULL);
	kmock_vrtc = dst;
	ATF_REQUIRE_EQ(0, do_snapshot(dst, VM_SNAPSHOT_RESTORE, buf,
	    VRTC_RECORD_SIZE, NULL));
	ATF_CHECK_EQ(VRTC_BROKEN_TIME, dst->base_rtctime);

	vrtc_cleanup(dst);
	kmock_vrtc = src;
	vrtc_cleanup(src);
}

ATF_TC_WITHOUT_HEAD(restore_bounds_base_rtctime);
ATF_TC_BODY(restore_bounds_base_rtctime, tc)
{
	struct vrtc *src, *dst;
	uint8_t buf[256];
	time_t before;

	src = vrtc_init(NULL);
	kmock_vrtc = src;

	/* Exactly VRTC_MAX_RTCTIME (23:59:59 on 9999-12-31) is representable. */
	save_with_base(src, VRTC_MAX_RTCTIME, buf, sizeof(buf));
	dst = vrtc_init(NULL);
	kmock_vrtc = dst;
	ATF_CHECK_EQ(0, do_snapshot(dst, VM_SNAPSHOT_RESTORE, buf,
	    VRTC_RECORD_SIZE, NULL));
	ATF_CHECK_EQ(VRTC_MAX_RTCTIME, dst->base_rtctime);
	vrtc_cleanup(dst);

	/* One second past the maximum overflows secs_to_rtc(): rejected. */
	kmock_vrtc = src;
	save_with_base(src, VRTC_MAX_RTCTIME + 1, buf, sizeof(buf));
	dst = vrtc_init(NULL);
	kmock_vrtc = dst;
	before = dst->base_rtctime;
	ATF_CHECK_EQ(EINVAL, do_snapshot(dst, VM_SNAPSHOT_RESTORE, buf,
	    VRTC_RECORD_SIZE, NULL));
	ATF_CHECK_EQ(before, dst->base_rtctime);
	vrtc_cleanup(dst);

	kmock_vrtc = src;
	vrtc_cleanup(src);
}

/*
 * Cross-check the validator's upper bound against the actual danger it guards:
 * feeding VRTC_MAX_RTCTIME to secs_to_rtc() must keep the century index
 * (ct.year / 100) within bin2bcd_data[]'s 100 entries, while one second more
 * would push ct.year to 10000 and index entry 100 -- out of bounds.
 */
ATF_TC_WITHOUT_HEAD(max_rtctime_matches_bcd_table_bound);
ATF_TC_BODY(max_rtctime_matches_bcd_table_bound, tc)
{
	struct timespec ts;
	struct clocktime ct;

	ts.tv_sec = VRTC_MAX_RTCTIME;
	ts.tv_nsec = 0;
	clock_ts_to_ct(&ts, &ct);
	ATF_CHECK_EQ(9999, ct.year);
	ATF_CHECK(ct.year / 100 < 100);

	ts.tv_sec = VRTC_MAX_RTCTIME + 1;
	clock_ts_to_ct(&ts, &ct);
	ATF_CHECK_EQ(10000, ct.year);
	ATF_CHECK(ct.year / 100 >= 100);	/* would read past the table */
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, base_rtctime_round_trip);
	ATF_TP_ADD_TC(tp, restore_rejects_negative_base_rtctime);
	ATF_TP_ADD_TC(tp, restore_accepts_broken_sentinel);
	ATF_TP_ADD_TC(tp, restore_bounds_base_rtctime);
	ATF_TP_ADD_TC(tp, max_rtctime_matches_bcd_table_bound);
	return (atf_no_error());
}
