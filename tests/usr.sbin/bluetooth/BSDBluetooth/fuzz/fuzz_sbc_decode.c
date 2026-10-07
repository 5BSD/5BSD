/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
#include <sys/types.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "bt.h"
#include "sbc_encode.h"

int LLVMFuzzerTestOneInput(const uint8_t *, size_t);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct bt_config cfg = {0};
	struct sbc_encode sbc = {0};
	uint8_t *frame;
	size_t consumed;

	if (size < 4 || size > 1024)
		return (0);
	/* Exact allocation makes ASan detect reads past the supplied frame. */
	frame = malloc(size);
	if (frame == NULL)
		return (0);
	memcpy(frame, data, size);
	cfg.freq = data[1] >> 6;
	cfg.blocks = (data[1] >> 4) & 3;
	cfg.chmode = (data[1] >> 2) & 3;
	cfg.allocm = (data[1] >> 1) & 1;
	cfg.bands = data[1] & 1;
	cfg.handle.sbc_enc = &sbc;
	sbc.rem_data_ptr = frame;
	consumed = sbc_decode_frame(&cfg, size * 8);
	assert(consumed <= size);
	assert(sbc.rem_len <= 256);
	if (consumed == 0)
		assert(sbc.rem_len == 0);
	free(frame);
	return (0);
}
