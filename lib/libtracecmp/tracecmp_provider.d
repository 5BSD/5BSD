/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * opcode: TRACECMP_OP_HELLO (1, protocol negotiation), _OPEN (2), _STATS (3).
 * size: the FIDL request or reply header size.
 */
provider tracecmp {
	probe open(const char *, int);
	probe send(uint16_t, size_t, int);
	probe receive(uint16_t, size_t, int);
	probe reject(uint16_t, int);
};
