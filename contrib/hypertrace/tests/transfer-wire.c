/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "dtraced_transfer_wire.h"

static void
seal(uint8_t *wire, size_t length)
{
	assert(SHA256(wire, length - SHA256_DIGEST_LENGTH,
	    wire + length - SHA256_DIGEST_LENGTH) != NULL);
}

int
main(void)
{
	uint8_t token[16] = { 7 };
	uint8_t wrong[16] = { 8 };
	uint8_t zero_token[16] = {};
	uint8_t empty[64] = {};
	memcpy(empty, "HTX1", 4);
	memcpy(empty + 4, token, sizeof(token));
	seal(empty, sizeof(empty));
	assert(dtraced_transfer_wire_valid(empty, sizeof(empty), token));
	memset(empty + 4, 0, sizeof(zero_token));
	seal(empty, sizeof(empty));
	assert(!dtraced_transfer_wire_valid(empty, sizeof(empty), zero_token));
	memcpy(empty + 4, token, sizeof(token));
	seal(empty, sizeof(empty));
	assert(!dtraced_transfer_wire_valid(empty, sizeof(empty), wrong));
	assert(!dtraced_transfer_wire_valid(empty, sizeof(empty) - 1, token));
	empty[28] = 1;
	seal(empty, sizeof(empty));
	assert(!dtraced_transfer_wire_valid(empty, sizeof(empty), token));
	empty[28] = 0;
	empty[24] = 1;
	seal(empty, sizeof(empty));
	assert(!dtraced_transfer_wire_valid(empty, sizeof(empty), token));

	uint8_t populated[32 + 3 + 4 + 5 + 32] = {};
	memcpy(populated, "HTX1", 4);
	memcpy(populated + 4, token, sizeof(token));
	dtraced_wire_put_u32(populated + 20, 3);
	dtraced_wire_put_u32(populated + 24, 1);
	memcpy(populated + 32, "abc", 3);
	dtraced_wire_put_u32(populated + 35, 5);
	memcpy(populated + 39, "frame", 5);
	seal(populated, sizeof(populated));
	assert(dtraced_transfer_wire_valid(populated, sizeof(populated), token));
	populated[40] ^= 1;
	assert(!dtraced_transfer_wire_valid(populated, sizeof(populated), token));
	populated[40] ^= 1;
	dtraced_wire_put_u32(populated + 35, 6);
	seal(populated, sizeof(populated));
	assert(!dtraced_transfer_wire_valid(populated, sizeof(populated), token));
	dtraced_wire_put_u32(populated + 35, 4);
	seal(populated, sizeof(populated));
	assert(!dtraced_transfer_wire_valid(populated, sizeof(populated), token));
	return (0);
}
