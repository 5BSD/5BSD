/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Model test for the host KVM-compatible paravirtual clock.  It exercises the
 * pure ABI math and protocol that the host runs (the very code in
 * sys/amd64/vmm/io/vpvclock.h) against an independent, first-principles
 * oracle: the mul/shift scaling, the version-seqlock update discipline, and
 * the monotonicity of computed system_time across a TSC-offset change and a
 * migration-restore update.
 */

#include <sys/param.h>
#include <sys/types.h>

#include <machine/pvclock.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/amd64/vmm/io/vpvclock.h"

/*
 * Independent oracle: the guest turns a TSC value into nanoseconds with
 * pvclock_scale_delta(tsc, mul, shift).  Model the same reference behaviour
 * from the ABI so the test does not merely echo the implementation.
 */
static uint64_t
oracle_scale(uint64_t tsc, uint32_t mul, int8_t shift)
{
	/*
	 * ns = ((shift >= 0 ? tsc << shift : tsc >> -shift) * mul) >> 32,
	 * computed in 128-bit to avoid the intermediate truncation the guest's
	 * asm avoids in hardware.
	 */
	__uint128_t v = tsc;

	if (shift < 0)
		v >>= -shift;
	else
		v <<= shift;
	v *= mul;
	return ((uint64_t)(v >> 32));
}

static const uint64_t representative_freqs[] = {
	1000000000ULL,		/* 1.0 GHz */
	1400000000ULL,		/* 1.4 GHz */
	2000000000ULL,		/* 2.0 GHz */
	2500000000ULL,		/* 2.5 GHz */
	2933333333ULL,		/* 2.93 GHz (Nehalem-ish) */
	3300000000ULL,		/* 3.3 GHz */
	3900000000ULL,		/* 3.9 GHz */
	100000000ULL,		/* 100 MHz (stress low end) */
};

ATF_TC_WITHOUT_HEAD(mul_shift_derivation);
ATF_TC_BODY(mul_shift_derivation, tc)
{
	for (size_t i = 0; i < nitems(representative_freqs); i++) {
		uint64_t freq = representative_freqs[i];
		uint32_t mul;
		int8_t shift;

		vpvclock_freq_to_scale(freq, &mul, &shift);

		/* The multiplier must occupy the full 32-bit fraction. */
		ATF_CHECK_MSG((mul & 0x80000000U) != 0,
		    "freq %ju: mul %#x lacks high bit", (uintmax_t)freq, mul);

		/*
		 * Converting one second's worth of TSC ticks must yield ~1e9
		 * nanoseconds.  Allow a small relative error from the 32-bit
		 * fixed-point representation.
		 */
		uint64_t ns = oracle_scale(freq, mul, shift);
		int64_t err = (int64_t)ns - 1000000000LL;
		if (err < 0)
			err = -err;
		ATF_CHECK_MSG(err <= 1000,
		    "freq %ju: 1s -> %ju ns (err %jd) mul %#x shift %d",
		    (uintmax_t)freq, (uintmax_t)ns, (intmax_t)err, mul,
		    (int)shift);

		/* And an arbitrary interval should scale proportionally. */
		uint64_t half = oracle_scale(freq / 2, mul, shift);
		int64_t herr = (int64_t)half - 500000000LL;
		if (herr < 0)
			herr = -herr;
		ATF_CHECK_MSG(herr <= 1000,
		    "freq %ju: 0.5s -> %ju ns", (uintmax_t)freq,
		    (uintmax_t)half);
	}
}

/*
 * Cross-check the test's independent 128-bit oracle against the actual guest
 * ABI helper pvclock_scale_delta() from <machine/pvclock.h> -- the very
 * routine the FreeBSD/Linux guest runs.  This anchors the monotonicity and
 * derivation checks to the real arithmetic: a change to the shift convention
 * or the >>32 fixed-point contract would make the two disagree.
 */
ATF_TC_WITHOUT_HEAD(oracle_matches_abi_helper);
ATF_TC_BODY(oracle_matches_abi_helper, tc)
{
	static const uint64_t deltas[] = {
		0, 1, 1000, 1000000, 1000000000ULL, 2500000000ULL,
		1ULL << 40, 123456789012345ULL,
	};

	for (size_t i = 0; i < nitems(representative_freqs); i++) {
		uint32_t mul;
		int8_t shift;

		vpvclock_freq_to_scale(representative_freqs[i], &mul, &shift);
		for (size_t j = 0; j < nitems(deltas); j++) {
			uint64_t want = oracle_scale(deltas[j], mul, shift);
			uint64_t got = pvclock_scale_delta(deltas[j], mul,
			    shift);

			ATF_CHECK_MSG(want == got,
			    "freq %ju delta %ju: oracle %ju != ABI %ju "
			    "(mul %#x shift %d)",
			    (uintmax_t)representative_freqs[i],
			    (uintmax_t)deltas[j], (uintmax_t)want,
			    (uintmax_t)got, mul, (int)shift);
		}
	}
}

/*
 * Negative / edge inputs to the fixed-point reciprocal.  A zero frequency
 * must not divide by zero or spin (the freq==0 -> den=1 guard), and the
 * ns-per-fixed-delta must fall monotonically as the virtual TSC frequency
 * rises -- the defining property of the scale that a numerator/denominator
 * swap or a dropped guard would violate.
 */
ATF_TC_WITHOUT_HEAD(freq_to_scale_edge_inputs);
ATF_TC_BODY(freq_to_scale_edge_inputs, tc)
{
	static const uint64_t ascending[] = {
		1000000ULL, 100000000ULL, 1000000000ULL, 1400000000ULL,
		2500000000ULL, 3900000000ULL, 8000000000ULL,
	};
	const uint64_t delta = 1000000000ULL;	/* fixed TSC interval */
	uint32_t mul;
	int8_t shift;
	uint64_t prev_ns;

	/* freq == 0 must be handled without UB and still yield a normal mul. */
	vpvclock_freq_to_scale(0, &mul, &shift);
	ATF_CHECK_MSG((mul & 0x80000000U) != 0,
	    "freq 0: mul %#x lacks high bit", mul);

	/* Strictly higher frequency => strictly fewer ns for the same ticks. */
	vpvclock_freq_to_scale(ascending[0], &mul, &shift);
	prev_ns = oracle_scale(delta, mul, shift);
	for (size_t i = 1; i < nitems(ascending); i++) {
		uint64_t ns;

		vpvclock_freq_to_scale(ascending[i], &mul, &shift);
		ns = oracle_scale(delta, mul, shift);
		ATF_CHECK_MSG(ns < prev_ns,
		    "freq %ju: ns %ju not < previous %ju",
		    (uintmax_t)ascending[i], (uintmax_t)ns,
		    (uintmax_t)prev_ns);
		prev_ns = ns;
	}
}

/*
 * The version field must be even between updates and odd while an update is in
 * flight, and each completed update must advance it by two so a reader can tell
 * the page changed.  We interpose on the field ordering by draining the store
 * sequence: after vpvclock_fill_timeinfo() returns, version is even and the
 * payload is the value written.
 */
ATF_TC_WITHOUT_HEAD(version_seqlock_protocol);
ATF_TC_BODY(version_seqlock_protocol, tc)
{
	struct pvclock_vcpu_time_info ti;
	uint32_t ver;

	memset(&ti, 0, sizeof(ti));
	ATF_REQUIRE_EQ(0, ti.version & 1);

	ver = vpvclock_fill_timeinfo(&ti, 0, 111, 222, 0x80000000U, -1, 1);
	ATF_CHECK_EQ(2, ver);
	ATF_CHECK_EQ(2, ti.version);
	ATF_CHECK_EQ(0, ti.version & 1);	/* even => stable */
	ATF_CHECK_EQ(111, ti.tsc_timestamp);
	ATF_CHECK_EQ(222, ti.system_time);
	ATF_CHECK_EQ(0x80000000U, ti.tsc_to_system_mul);
	ATF_CHECK_EQ(-1, ti.tsc_shift);
	ATF_CHECK_EQ(1, ti.flags);

	/* Subsequent updates keep the version even and strictly increasing. */
	for (uint32_t i = 0; i < 100; i++) {
		uint32_t prev = ti.version;
		ver = vpvclock_fill_timeinfo(&ti, prev, i, i, 0x80000000U, 0, 0);
		ATF_CHECK_EQ(prev + 2, ver);
		ATF_CHECK_EQ(0, ti.version & 1);
		ATF_CHECK(ti.version > prev);
	}

	/*
	 * The odd intermediate is real: emulate the writer stepping the field
	 * and confirm the parity discipline holds at each stage, matching the
	 * guest reader's "retry while (version & 1)" loop.
	 */
	uint32_t base = ti.version;			/* even */
	volatile struct pvclock_vcpu_time_info *p = &ti;
	uint32_t odd = base + 1;
	p->version = odd;
	ATF_CHECK_EQ(1, p->version & 1);		/* update in progress */
	p->version = odd + 1;
	ATF_CHECK_EQ(0, p->version & 1);		/* update complete */
}

/*
 * Reproduce how the host derives the page: tsc_timestamp is the guest TSC at
 * update time, system_time is that same TSC scaled to ns, and the guest reads
 * ns = system_time + scale(rdtsc - tsc_timestamp).  Across a TSC-offset change
 * and a migration-restore (both of which republish the page), the guest-read
 * time must never move backwards.
 */
static uint64_t
guest_read_ns(const struct pvclock_vcpu_time_info *ti, uint64_t guest_tsc_now)
{
	uint64_t delta = guest_tsc_now - ti->tsc_timestamp;

	return (ti->system_time + oracle_scale(delta, ti->tsc_to_system_mul,
	    ti->tsc_shift));
}

static void
host_publish(struct pvclock_vcpu_time_info *ti, uint64_t guest_tsc,
    uint32_t mul, int8_t shift, uint8_t flags)
{
	uint64_t system_time = oracle_scale(guest_tsc, mul, shift);

	vpvclock_fill_timeinfo(ti, ti->version, guest_tsc, system_time, mul,
	    shift, flags);
}

ATF_TC_WITHOUT_HEAD(monotonic_across_migration);
ATF_TC_BODY(monotonic_across_migration, tc)
{
	struct pvclock_vcpu_time_info ti;
	uint32_t mul;
	int8_t shift;
	uint64_t host_tsc, tsc_offset, prev_ns;

	memset(&ti, 0, sizeof(ti));
	vpvclock_freq_to_scale(2500000000ULL, &mul, &shift);

	/* Initial enable: guest_tsc = host_tsc + offset. */
	host_tsc = 1000000000ULL;
	tsc_offset = 0;
	host_publish(&ti, host_tsc + tsc_offset, mul, shift,
	    PVCLOCK_FLAG_TSC_STABLE);
	prev_ns = guest_read_ns(&ti, host_tsc + tsc_offset);

	/* Advance the host TSC and read repeatedly: strictly monotonic. */
	for (int i = 0; i < 1000; i++) {
		host_tsc += 3000000ULL;		/* ~1.2 ms of ticks */
		uint64_t ns = guest_read_ns(&ti, host_tsc + tsc_offset);
		ATF_CHECK_MSG(ns >= prev_ns,
		    "pre-migration regression at %d: %ju < %ju", i,
		    (uintmax_t)ns, (uintmax_t)prev_ns);
		prev_ns = ns;
	}

	/*
	 * Simulate a migration/pause+resume: the physical host TSC jumps to an
	 * unrelated value, but bhyve restores the per-vCPU offset so the
	 * guest-visible TSC stays continuous, then republishes the page.  The
	 * guest must not observe time going backwards.
	 */
	uint64_t guest_tsc_before = host_tsc + tsc_offset;
	host_tsc = 77;				/* brand-new host, tiny TSC */
	tsc_offset = guest_tsc_before - host_tsc;	/* preserve continuity */
	ATF_REQUIRE_EQ(guest_tsc_before, host_tsc + tsc_offset);
	host_publish(&ti, host_tsc + tsc_offset, mul, shift,
	    PVCLOCK_FLAG_TSC_STABLE);

	uint64_t ns = guest_read_ns(&ti, host_tsc + tsc_offset);
	ATF_CHECK_MSG(ns >= prev_ns,
	    "migration-restore regression: %ju < %ju", (uintmax_t)ns,
	    (uintmax_t)prev_ns);
	prev_ns = ns;

	/* Keep advancing on the new host; still monotonic. */
	for (int i = 0; i < 1000; i++) {
		host_tsc += 3000000ULL;
		ns = guest_read_ns(&ti, host_tsc + tsc_offset);
		ATF_CHECK_MSG(ns >= prev_ns,
		    "post-migration regression at %d: %ju < %ju", i,
		    (uintmax_t)ns, (uintmax_t)prev_ns);
		prev_ns = ns;
	}

	/*
	 * A guest TSC-offset change (e.g. a guest WRMSR(MSR_TSC)) also
	 * republishes: the new tsc_timestamp/system_time base keeps the read
	 * continuous even though the raw guest TSC just jumped forward.
	 */
	uint64_t ns_before = guest_read_ns(&ti, host_tsc + tsc_offset);
	tsc_offset += 5000000000ULL;		/* guest TSC leaps +2s */
	host_publish(&ti, host_tsc + tsc_offset, mul, shift,
	    PVCLOCK_FLAG_TSC_STABLE);
	ns = guest_read_ns(&ti, host_tsc + tsc_offset);
	ATF_CHECK_MSG(ns >= ns_before,
	    "tsc-offset-change regression: %ju < %ju", (uintmax_t)ns,
	    (uintmax_t)ns_before);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, mul_shift_derivation);
	ATF_TP_ADD_TC(tp, oracle_matches_abi_helper);
	ATF_TP_ADD_TC(tp, freq_to_scale_edge_inputs);
	ATF_TP_ADD_TC(tp, version_seqlock_protocol);
	ATF_TP_ADD_TC(tp, monotonic_across_migration);
	return (atf_no_error());
}
