/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <sha256.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct restore_state {
	const void *hypertrace_private_image;
	size_t hypertrace_private_length;
};

#include "restore-private-image.inc"

int
main(void)
{
	uint8_t image[64] = { 'V', 'D', 'R', '1' };
	uint8_t expected[SHA256_DIGEST_LENGTH];
	struct restore_state state = {
		.hypertrace_private_image = image,
		.hypertrace_private_length = sizeof(image),
	};

	hypertrace_private_image_digest(&state, expected);
	assert(hypertrace_private_image_unchanged(&state, expected) == 0);
	image[31] ^= 0x80;
	assert(hypertrace_private_image_unchanged(&state, expected) == EPROTO);
	image[31] ^= 0x80;
	assert(hypertrace_private_image_unchanged(&state, expected) == 0);
	state.hypertrace_private_length--;
	assert(hypertrace_private_image_unchanged(&state, expected) == EPROTO);
	state.hypertrace_private_length = 0;
	assert(hypertrace_private_image_unchanged(&state, expected) == EINVAL);
	state.hypertrace_private_image = NULL;
	assert(hypertrace_private_image_unchanged(&state, expected) == EINVAL);
	puts("PASS: private image changes fail before publication");
	return (0);
}
