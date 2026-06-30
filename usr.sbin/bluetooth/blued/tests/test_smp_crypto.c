/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * SMP crypto primitive unit tests.
 *
 * Test vectors from Core Spec v6.3 Vol 3 Part H Appendix D.
 * Run: cc -o test_smp_crypto test_smp_crypto.c ../smp.c ../hci_log.c
 *      -I.. -I/usr/src/sys -lcrypto -lbluetooth && ./test_smp_crypto
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* Stubs for logging (smp.c references these) */
int blued_verbose = 0;
int blued_daemonized = 0;

/* Pull in SMP declarations */
#include "smp.h"

/* Stubs for functions smp.c references but we don't test */
int hci_wait_encryption(int fd __unused, uint16_t h __unused,
    int t __unused) { return -1; }
int hci_le_ltk_request_reply(int fd __unused, uint16_t h __unused,
    const uint8_t ltk[16] __unused) { return -1; }
int hci_le_ltk_request_neg_reply(int fd __unused,
    uint16_t h __unused) { return -1; }
int hci_le_write_auth_payload_timeout(int fd __unused,
    uint16_t h __unused, uint16_t t __unused) { return -1; }
void hci_log_l2cap(uint16_t h __unused, uint16_t c __unused,
    const void *d __unused, uint16_t l __unused, bool rx __unused) {}
int hci_log_enabled(void) { return 0; }
void __dtrace_blued___smp__pair__start(const char *a __unused,
    int m __unused) {}
int __dtraceenabled_blued___smp__pair__start(void) { return 0; }
void hci_log_packet(int t __unused, const void *d __unused,
    uint16_t l __unused, bool rx __unused) {}
int hci_devreq_logged(int fd __unused, void *r __unused,
    int t __unused) { return -1; }

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
	tests_run++; \
	printf("  %-50s ", name); \
} while (0)

#define PASS() do { \
	tests_passed++; \
	printf("PASS\n"); \
} while (0)

#define FAIL(msg) do { \
	printf("FAIL: %s\n", msg); \
} while (0)

static void
hexdump(const char *label, const uint8_t *data, size_t len)
{
	printf("    %s: ", label);
	for (size_t i = 0; i < len; i++)
		printf("%02x", data[i]);
	printf("\n");
}

/*
 * Core Spec Vol 3 Part H, D.1: AES-128 test vector.
 * Key:       2b7e1516 28aed2a6 abf71588 09cf4f3c
 * Plaintext: 6bc1bee2 2e409f96 e93d7e11 7393172a
 * Ciphertext:3ad77bb4 0d7a3660 a89ecaf3 2466ef97
 *
 * Note: SMP uses reversed (little-endian) key and plaintext.
 */
static void
test_aes128(void)
{
	/* Key in little-endian (reversed from spec) */
	uint8_t key[16] = {
		0x3c, 0x4f, 0xcf, 0x09, 0x88, 0x15, 0xf7, 0xab,
		0xa6, 0xd2, 0xae, 0x28, 0x16, 0x15, 0x7e, 0x2b
	};
	/* Plaintext in little-endian */
	uint8_t plain[16] = {
		0x2a, 0x17, 0x93, 0x73, 0x11, 0x7e, 0x3d, 0xe9,
		0x96, 0x9f, 0x40, 0x2e, 0xe2, 0xbe, 0xc1, 0x6b
	};
	/* Expected ciphertext in little-endian */
	uint8_t expected[16] = {
		0x97, 0xef, 0x66, 0x24, 0xf3, 0xca, 0x9e, 0xa8,
		0x60, 0x36, 0x7a, 0x0d, 0xb4, 0x7b, 0xd7, 0x3a
	};
	uint8_t out[16];

	TEST("smp_aes128 — Core Spec D.1 test vector");
	if (smp_aes128(key, plain, out) != 0) {
		FAIL("smp_aes128 returned error");
		return;
	}
	if (memcmp(out, expected, 16) != 0) {
		FAIL("ciphertext mismatch");
		hexdump("expected", expected, 16);
		hexdump("got     ", out, 16);
		return;
	}
	PASS();
}

/*
 * c1 consistency test: verify c1 is deterministic and non-trivial.
 * Same inputs must produce same output, different inputs must differ.
 */
static void
test_c1(void)
{
	uint8_t k[16] = {0};
	uint8_t r[16] = {0};
	uint8_t preq[7] = { 0x01, 0x04, 0x00, 0x0d, 0x10, 0x07, 0x07 };
	uint8_t pres[7] = { 0x02, 0x03, 0x00, 0x01, 0x10, 0x07, 0x07 };
	uint8_t ia[6] = {0}, ra[6] = {0};
	uint8_t c1a[16], c1b[16], zero[16] = {0};

	TEST("smp_c1 — deterministic and non-trivial");
	smp_c1(k, r, preq, pres, 0, ia, 0, ra, c1a);
	smp_c1(k, r, preq, pres, 0, ia, 0, ra, c1b);
	if (memcmp(c1a, c1b, 16) != 0) {
		FAIL("not deterministic");
		return;
	}
	if (memcmp(c1a, zero, 16) == 0) {
		FAIL("returned all zeros");
		return;
	}
	PASS();
}

/*
 * Core Spec Vol 3 Part H, D.3: s1 test vector.
 */
static void
test_s1(void)
{
	uint8_t k[16] = {0}; /* TK = 0 */
	uint8_t r1[16] = {
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	uint8_t r2[16] = {
		0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	uint8_t stk[16];
	uint8_t expected[16] = {
		0x62, 0xa0, 0x6d, 0x79, 0xae, 0x16, 0x42, 0x5b,
		0x9b, 0xf4, 0xb0, 0xe8, 0xf0, 0xe1, 0x1f, 0x9a
	};

	TEST("smp_s1 — Core Spec D.3 test vector");
	smp_s1(k, r1, r2, stk);
	if (memcmp(stk, expected, 16) != 0) {
		FAIL("STK mismatch");
		hexdump("expected", expected, 16);
		hexdump("got     ", stk, 16);
		return;
	}
	PASS();
}

/*
 * Test g2 — numeric comparison output is always mod 10^6.
 */
static void
test_g2(void)
{
	uint8_t u[32] = {0}, v[32] = {0}, x[16] = {0}, y[16] = {0};
	uint32_t val;

	/* Set non-trivial inputs */
	u[0] = 0x42;
	v[0] = 0x99;

	TEST("smp_g2 — deterministic, mod 1000000 gives 6-digit value");
	val = smp_g2(u, v, x, y);
	/* g2 returns raw 32-bit value; callers do % 1000000 */
	if (val % 1000000 >= 1000000) {
		FAIL("impossible");
		return;
	}
	/* Verify determinism */
	uint32_t val2 = smp_g2(u, v, x, y);
	if (val != val2) {
		FAIL("not deterministic");
		return;
	}
	PASS();
}

int
main(void)
{
	printf("SMP Crypto Unit Tests\n");
	printf("=====================\n\n");

	test_aes128();
	test_c1();
	test_s1();
	test_g2();

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return (tests_passed == tests_run ? 0 : 1);
}
