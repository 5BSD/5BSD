/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for the advertising-data (AD structure) parser.
 *
 * print_adv_data() walks the length-prefixed AD structures received in
 * LE advertising / scan-response reports -- fully attacker-controlled
 * data broadcast over the air.  It sub-parses names and UUID lists into
 * fixed stack buffers, so a malformed length field is exactly the kind
 * of bug this harness hunts for.
 *
 * Output is redirected to /dev/null so the parser's fprintf() calls do
 * not drown the fuzzer; only memory-safety matters here.
 *
 * Reference: Core Spec Vol 3 Part C Section 11 (AD format),
 *            CSS (Supplement to the Core Specification) Part A.
 */

#include <sys/types.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Provided by hccontrol/adv_data.c */
void	print_adv_data(int len, uint8_t *advdata);

/*
 * adv_data.c pulls in hci_manufacturer2str() (a large table living in
 * hccontrol/util.c that we do not want to link).  Stub it, as the ATF
 * adv_data_test does.
 */
char const *
hci_manufacturer2str(int id __unused)
{

	return ("FuzzManufacturer");
}

int
LLVMFuzzerInitialize(int *argc __unused, char ***argv __unused)
{

	/*
	 * Silence the parser's hex dump on stdout.  Deliberately leave
	 * stderr alone: the sanitizer runtime reports there, and hiding
	 * it would mask exactly the failures this harness exists to find.
	 */
	if (freopen("/dev/null", "w", stdout) == NULL)
		abort();
	return (0);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t *copy;

	/*
	 * len is an int in the API; an AD payload is at most 31 bytes for
	 * legacy and 0x0672 for extended advertising.  Cap generously and
	 * copy into an exact-sized buffer so ASan flags reads past the end.
	 */
	if (size > 4096)
		size = 4096;
	copy = malloc(size == 0 ? 1 : size);
	if (copy == NULL)
		abort();
	if (size != 0)
		memcpy(copy, data, size);

	print_adv_data((int)size, copy);

	free(copy);
	return (0);
}
