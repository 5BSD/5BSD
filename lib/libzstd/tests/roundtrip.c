/* SPDX-License-Identifier: BSD-2-Clause */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zstd.h>

#define CHECK(c) do { if (!(c)) { \
	fprintf(stderr, "line %d: %s\n", __LINE__, #c); return (1); \
} } while (0)

int
main(void)
{
	const size_t length = 4 * 1024 * 1024;
	const size_t capacity = ZSTD_compressBound(length);
	unsigned char *input = malloc(length), *output = malloc(length);
	void *compressed = malloc(capacity);
	ZSTD_CCtx *context = ZSTD_createCCtx();
	size_t size, decoded, i;
	int workers;

	CHECK(input != NULL && output != NULL && compressed != NULL && context != NULL);
	for (i = 0; i < length; i++)
		input[i] = (unsigned char)((i * 31 + i / 1024) % 251);
	for (workers = 0; workers <= 4; workers += 4) {
		CHECK(!ZSTD_isError(ZSTD_CCtx_setParameter(context, ZSTD_c_nbWorkers, workers)));
		CHECK(!ZSTD_isError(ZSTD_CCtx_setParameter(context, ZSTD_c_checksumFlag, 1)));
		size = ZSTD_compress2(context, compressed, capacity, input, length);
		CHECK(!ZSTD_isError(size) && size > 1);
		decoded = ZSTD_decompress(output, length, compressed, size);
		CHECK(decoded == length && memcmp(input, output, length) == 0);
		CHECK(ZSTD_isError(ZSTD_decompress(output, length, compressed, size - 1)));
	}
	CHECK(!ZSTD_isError(ZSTD_freeCCtx(context)));
	free(compressed);
	free(output);
	free(input);
	return (0);
}
