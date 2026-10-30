/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LIBSA_VERITY_READ_H_
#define _LIBSA_VERITY_READ_H_
#include <geom/verity/g_verity_verify.h>

/*
 * Single-threaded loader reader. Caller authenticates root, retains exclusive
 * ownership of fd until the reader is retired, and supplies private disjoint
 * cache/scratch/output memory. No allocation, device registration or trust
 * decision occurs here. Every returned data block is authenticated on each read.
 */
struct verity_file {
	struct g_verity_cache cache;
	int fd;
	void *data, *hashes;
	unsigned busy;
};
int verity_file_init(struct verity_file *, int, const struct g_verity_root *,
    uint64_t *, void *, size_t, void *, void *);
int verity_file_read(struct verity_file *, uint64_t, size_t, void *);
#endif
