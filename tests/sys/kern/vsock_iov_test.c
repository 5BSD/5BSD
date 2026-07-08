/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Unit tests for the bhyve virtio-vsock device's bounded scatter/gather copy
 * helpers (usr.sbin/bhyve/pci_virtio_vsock_iov.h).  These are the routines a
 * malicious guest's descriptor chain flows through, so their memory-safety
 * invariant matters: none of them may read or write past iov[niov - 1].
 *
 * The device guarantees niov <= VTVSOCK_MAX_IOV by clamping the vq_getchain()
 * return (which can exceed the iov[] array).  These tests verify the helpers
 * honor niov even when the descriptors *beyond* niov are booby-trapped with an
 * invalid pointer and a huge length -- a helper that looped past niov would
 * fault or corrupt, failing the test.
 */

#include <sys/param.h>
#include <sys/uio.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "pci_virtio_vsock_iov.h"

#define	NREAL	4		/* real descriptors */
#define	NSLOTS	128		/* total array slots; [NREAL..] are poison */

/*
 * Fill iov[0..nreal-1] with the given buffers and poison every slot after with
 * an unmapped base and a huge length, so any helper that walks past nreal
 * faults (base deref) or over-copies (length).
 */
static void
poison_fill(struct iovec *iov, int nslots, struct iovec *real, int nreal)
{
	int i;

	for (i = 0; i < nreal; i++)
		iov[i] = real[i];
	for (; i < nslots; i++) {
		iov[i].iov_base = (void *)(uintptr_t)0xdeadbeef;
		iov[i].iov_len = SIZE_MAX;
	}
}

ATF_TC_WITHOUT_HEAD(total_honors_niov);
ATF_TC_BODY(total_honors_niov, tc)
{
	struct iovec iov[NSLOTS];
	uint8_t b0[10], b1[20], b2[30], b3[40];
	struct iovec real[NREAL] = {
		{ b0, sizeof(b0) }, { b1, sizeof(b1) },
		{ b2, sizeof(b2) }, { b3, sizeof(b3) },
	};

	poison_fill(iov, NSLOTS, real, NREAL);
	/* Sums only the first NREAL; must not touch the poisoned tail. */
	ATF_CHECK_EQ(10 + 20 + 30 + 40, iov_total(iov, NREAL));
	/* Degenerate counts. */
	ATF_CHECK_EQ(0, iov_total(iov, 0));
	ATF_CHECK_EQ(10, iov_total(iov, 1));
}

ATF_TC_WITHOUT_HEAD(copyin_honors_niov_and_len);
ATF_TC_BODY(copyin_honors_niov_and_len, tc)
{
	struct iovec iov[NSLOTS];
	uint8_t s0[4] = { 1, 2, 3, 4 };
	uint8_t s1[4] = { 5, 6, 7, 8 };
	struct iovec real[2] = { { s0, 4 }, { s1, 4 } };
	uint8_t dst[64];

	poison_fill(iov, NSLOTS, real, 2);

	/* Ask for more than the 8 real bytes: copies exactly 8, no tail touch. */
	memset(dst, 0xAA, sizeof(dst));
	ATF_CHECK_EQ(8, iov_copyin(dst, sizeof(dst), iov, 2));
	ATF_CHECK_EQ(0, memcmp(dst, "\x01\x02\x03\x04\x05\x06\x07\x08", 8));
	ATF_CHECK_EQ(0xAA, dst[8]);	/* untouched past what was copied */

	/* Ask for fewer bytes than available: copies exactly len. */
	memset(dst, 0xAA, sizeof(dst));
	ATF_CHECK_EQ(3, iov_copyin(dst, 3, iov, 2));
	ATF_CHECK_EQ(0, memcmp(dst, "\x01\x02\x03", 3));
	ATF_CHECK_EQ(0xAA, dst[3]);

	/* len 0 copies nothing. */
	ATF_CHECK_EQ(0, iov_copyin(dst, 0, iov, 2));
}

ATF_TC_WITHOUT_HEAD(copyin_offset_honors_niov);
ATF_TC_BODY(copyin_offset_honors_niov, tc)
{
	struct iovec iov[NSLOTS];
	uint8_t s0[4] = { 1, 2, 3, 4 };
	uint8_t s1[4] = { 5, 6, 7, 8 };
	struct iovec real[2] = { { s0, 4 }, { s1, 4 } };
	uint8_t dst[64];

	poison_fill(iov, NSLOTS, real, 2);

	/* Skip the first 4 (whole first descriptor), read the next 4. */
	memset(dst, 0xAA, sizeof(dst));
	ATF_CHECK_EQ(4, iov_copyin_offset(dst, 4, iov, 2, 4));
	ATF_CHECK_EQ(0, memcmp(dst, "\x05\x06\x07\x08", 4));

	/* Skip into the middle of the first descriptor. */
	memset(dst, 0xAA, sizeof(dst));
	ATF_CHECK_EQ(4, iov_copyin_offset(dst, 4, iov, 2, 2));
	ATF_CHECK_EQ(0, memcmp(dst, "\x03\x04\x05\x06", 4));

	/* Skip past everything real: copies nothing (no poison touch). */
	ATF_CHECK_EQ(0, iov_copyin_offset(dst, 4, iov, 2, 8));
}

ATF_TC_WITHOUT_HEAD(copyout_honors_niov_and_offset);
ATF_TC_BODY(copyout_honors_niov_and_offset, tc)
{
	struct iovec iov[NSLOTS];
	uint8_t d0[4], d1[4];
	struct iovec real[2] = { { d0, 4 }, { d1, 4 } };
	const uint8_t src[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	size_t off;

	poison_fill(iov, NSLOTS, real, 2);
	memset(d0, 0, sizeof(d0));
	memset(d1, 0, sizeof(d1));

	/* Write all 8 across the two 4-byte descriptors. */
	off = 0;
	ATF_CHECK_EQ(8, iov_copyout(src, 8, iov, 2, &off));
	ATF_CHECK_EQ(8, off);
	ATF_CHECK_EQ(0, memcmp(d0, "\x01\x02\x03\x04", 4));
	ATF_CHECK_EQ(0, memcmp(d1, "\x05\x06\x07\x08", 4));

	/* Ask to write more than capacity: writes exactly 8, no tail touch. */
	off = 0;
	ATF_CHECK_EQ(8, iov_copyout(src, 64, iov, 2, &off));

	/* Offset skips the first descriptor. */
	memset(d1, 0, sizeof(d1));
	off = 4;
	ATF_CHECK_EQ(4, iov_copyout(src, 4, iov, 2, &off));
	ATF_CHECK_EQ(8, off);
	ATF_CHECK_EQ(0, memcmp(d1, "\x01\x02\x03\x04", 4));
}

/*
 * The exact scenario the vq_getchain clamp defends against: a chain longer
 * than the iov[] array.  The device clamps the count to VTVSOCK_MAX_IOV before
 * calling these helpers; here we emulate that clamp with a small niov over a
 * huge poisoned array and confirm the helpers never walk into the tail.
 */
ATF_TC_WITHOUT_HEAD(clamp_contract_no_overrun);
ATF_TC_BODY(clamp_contract_no_overrun, tc)
{
	struct iovec iov[NSLOTS];
	uint8_t bytes[NREAL];
	struct iovec real[NREAL];
	uint8_t dst[NREAL];
	size_t off;
	int i;

	for (i = 0; i < NREAL; i++) {
		bytes[i] = (uint8_t)(i + 1);
		real[i].iov_base = &bytes[i];
		real[i].iov_len = 1;		/* one byte each */
	}
	poison_fill(iov, NSLOTS, real, NREAL);

	/* Clamped count == NREAL; the poisoned NSLOTS-NREAL tail is off limits. */
	ATF_CHECK_EQ(NREAL, iov_total(iov, NREAL));

	ATF_CHECK_EQ(NREAL, iov_copyin(dst, sizeof(dst), iov, NREAL));
	ATF_CHECK_EQ(0, memcmp(dst, "\x01\x02\x03\x04", NREAL));

	off = 0;
	ATF_CHECK_EQ(NREAL, iov_copyout(bytes, NREAL, iov, NREAL, &off));

	ATF_CHECK_EQ(NREAL, iov_copyin_offset(dst, sizeof(dst), iov, NREAL, 0));
}

/* Exercise iov_copyout's partial-skip branch (0 < skip < cap). */
ATF_TC_WITHOUT_HEAD(copyout_partial_offset);
ATF_TC_BODY(copyout_partial_offset, tc)
{
	struct iovec iov[NSLOTS];
	uint8_t d0[4], d1[4];
	struct iovec real[2] = { { d0, 4 }, { d1, 4 } };
	const uint8_t src[6] = { 1, 2, 3, 4, 5, 6 };
	size_t off;

	poison_fill(iov, NSLOTS, real, 2);
	memset(d0, 0xEE, sizeof(d0));
	memset(d1, 0xEE, sizeof(d1));

	/* Start 2 bytes into the first 4-byte descriptor, write 6 bytes. */
	off = 2;
	ATF_CHECK_EQ(6, iov_copyout(src, 6, iov, 2, &off));
	ATF_CHECK_EQ(8, off);
	/* d0[0..1] untouched (skipped), d0[2..3] = 1,2; d1[0..3] = 3,4,5,6. */
	ATF_CHECK_EQ(0xEE, d0[0]);
	ATF_CHECK_EQ(0xEE, d0[1]);
	ATF_CHECK_EQ(0, memcmp(&d0[2], "\x01\x02", 2));
	ATF_CHECK_EQ(0, memcmp(d1, "\x03\x04\x05\x06", 4));
}

/* iov_has_null_base flags a NULL descriptor (bad guest address). */
ATF_TC_WITHOUT_HEAD(null_base_detection);
ATF_TC_BODY(null_base_detection, tc)
{
	uint8_t b[8];
	struct iovec iov[3] = { { b, 4 }, { NULL, 4 }, { b, 4 } };

	ATF_CHECK(iov_has_null_base(iov, 3));	/* middle is NULL */
	ATF_CHECK(iov_has_null_base(iov, 2));	/* still sees the NULL */
	ATF_CHECK(!iov_has_null_base(iov, 1));	/* only the first, non-NULL */
	ATF_CHECK(!iov_has_null_base(iov, 0));	/* nothing to check */
}

/* Deterministic PRNG (LCG) so any fuzz failure reproduces bit-for-bit. */
static uint32_t fuzz_state;
static uint32_t
fuzz_rand(void)
{
	fuzz_state = fuzz_state * 1103515245u + 12345u;
	return (fuzz_state >> 8);
}

/*
 * Randomized differential test: build random iov layouts (0..8 descriptors,
 * each 0..16 bytes, non-contiguous with GUARD bytes between them) and compare
 * every helper against a naive flat-concatenation reference over many
 * iterations.  This catches off-by-one / boundary bugs the fixed cases above
 * cannot enumerate; the guard bytes additionally detect any write that spills
 * from one descriptor into the next.  Empty descriptors (len 0) are included.
 */
ATF_TC_WITHOUT_HEAD(differential_fuzz);
ATF_TC_BODY(differential_fuzz, tc)
{
	const uint8_t GUARD = 0x7E;
	int iter;

	fuzz_state = 0x12345678u;

	for (iter = 0; iter < 5000; iter++) {
		uint8_t mem[512];
		struct iovec iov[8];
		size_t base[8];
		uint8_t flat[128];
		int niov, i, g;
		size_t total, pos, k;
		uint8_t fillbyte;

		memset(mem, GUARD, sizeof(mem));
		niov = (int)(fuzz_rand() % 9);		/* 0..8 descriptors */
		total = 0;
		pos = 0;
		fillbyte = 0;
		for (i = 0; i < niov; i++) {
			size_t len = fuzz_rand() % 17;	/* 0..16 bytes */

			base[i] = pos;
			iov[i].iov_base = &mem[pos];
			iov[i].iov_len = len;
			/* Known content per byte, mirrored into the flat model. */
			for (k = 0; k < len; k++) {
				uint8_t v = (uint8_t)(fillbyte++ ^ 0x55);
				mem[pos + k] = v;
				flat[total + k] = v;
			}
			pos += len + 4;			/* guard gap */
			total += len;
		}

		/* iov_total must equal the flat length. */
		ATF_REQUIRE_EQ(total, iov_total(iov, niov));

		/* iov_copyin: first min(reqlen,total) bytes of the flat view. */
		{
			uint8_t dst[256];
			size_t reqlen = fuzz_rand() % 200;
			size_t exp = reqlen < total ? reqlen : total;

			memset(dst, 0xAA, sizeof(dst));
			ATF_REQUIRE_EQ(exp, iov_copyin(dst, reqlen, iov, niov));
			ATF_REQUIRE_EQ(0, memcmp(dst, flat, exp));
			ATF_REQUIRE_EQ(0xAA, dst[exp]);	/* nothing beyond */
		}

		/* iov_copyin_offset: min(reqlen, total-skip) bytes from skip. */
		{
			uint8_t dst[256];
			size_t skip = fuzz_rand() % 160;
			size_t reqlen = fuzz_rand() % 200;
			size_t avail = skip < total ? total - skip : 0;
			size_t exp = reqlen < avail ? reqlen : avail;

			memset(dst, 0xBB, sizeof(dst));
			ATF_REQUIRE_EQ(exp,
			    iov_copyin_offset(dst, reqlen, iov, niov, skip));
			if (exp > 0)
				ATF_REQUIRE_EQ(0, memcmp(dst, flat + skip, exp));
			ATF_REQUIRE_EQ(0xBB, dst[exp]);
		}

		/* iov_copyout: writes min(reqlen, total-start) bytes from start. */
		{
			uint8_t src[256];
			uint8_t expflat[128];
			size_t start = fuzz_rand() % 160;
			size_t reqlen = fuzz_rand() % 200;
			size_t off = start;
			size_t avail = start < total ? total - start : 0;
			size_t exp = reqlen < avail ? reqlen : avail;
			size_t fpos;

			for (k = 0; k < sizeof(src); k++)
				src[k] = (uint8_t)(fuzz_rand() & 0xff);

			memcpy(expflat, flat, total);
			for (k = 0; k < exp; k++)
				expflat[start + k] = src[k];

			ATF_REQUIRE_EQ(exp,
			    iov_copyout(src, reqlen, iov, niov, &off));
			ATF_REQUIRE_EQ(start + exp, off);

			/* Reconstruct the flat view from the iov; compare. */
			fpos = 0;
			for (i = 0; i < niov; i++) {
				ATF_REQUIRE_EQ(0, memcmp(&mem[base[i]],
				    &expflat[fpos], iov[i].iov_len));
				fpos += iov[i].iov_len;
			}
			/* Guard bytes after each descriptor must be intact. */
			for (i = 0; i < niov; i++)
				for (g = 0; g < 4; g++)
					ATF_REQUIRE_EQ(GUARD, mem[base[i] +
					    iov[i].iov_len + g]);
		}
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, total_honors_niov);
	ATF_TP_ADD_TC(tp, copyin_honors_niov_and_len);
	ATF_TP_ADD_TC(tp, copyin_offset_honors_niov);
	ATF_TP_ADD_TC(tp, copyout_honors_niov_and_offset);
	ATF_TP_ADD_TC(tp, copyout_partial_offset);
	ATF_TP_ADD_TC(tp, null_base_detection);
	ATF_TP_ADD_TC(tp, clamp_contract_no_overrun);
	ATF_TP_ADD_TC(tp, differential_fuzz);

	return (atf_no_error());
}
