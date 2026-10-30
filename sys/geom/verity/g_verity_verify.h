/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _GEOM_VERITY_VERIFY_H_
#define _GEOM_VERITY_VERIFY_H_
#include <sys/types.h>

#define G_VERITY_LEVELS 16
struct g_verity_layout {
	uint64_t data_bytes;
	uint64_t tree_bytes;
	uint64_t offsets[G_VERITY_LEVELS]; /* leaf-first levels, root-first disk */
	uint32_t block_size;
	uint32_t levels;
};

/* Wire descriptor: explicit big-endian fields, never a native struct dump. */
#define G_VERITY_ROOT_BYTES 384
#define G_VERITY_ROOT_TYPE "bip_root_descriptor"
struct g_verity_root {
	struct g_verity_layout layout;
	uint8_t root_hash[32];
	uint8_t salt[256];
	uint32_t salt_len;
	uint32_t filesystem;
};
/* Structural validation only: successful decode is NOT authentication. */
int g_verity_root_decode(const void *, size_t, struct g_verity_root *);
#ifdef _KERNEL
/* Unique preload descriptor parsing only; caller establishes boot trust. */
int g_verity_preload_decode(struct g_verity_root *);
#endif

/* Reader fills the entire buffer or returns an errno; tree selects hash media. */
typedef int g_verity_read_t(void *, int, uint64_t, void *, size_t);
int g_verity_layout(uint64_t, uint32_t, struct g_verity_layout *);
/*
 * Geometry, salt and root must be authenticated by the caller. Buffers are
 * distinct, each at least block_size bytes, private throughout verification.
 * The reader may not retain buffer references. Output is untouched on error.
 * This core neither authenticates a descriptor nor configures a GEOM provider.
 */
int g_verity_verify(uint64_t, uint32_t, const void *, size_t, const uint8_t[32],
    uint64_t, g_verity_read_t *, void *, void *, void *, void *);
/*
 * Arbitrary byte range. Three distinct block-sized scratch buffers and a
 * length-sized output buffer must be private and nonoverlapping. Invalid
 * arguments leave output untouched. I/O/authentication failure zeros the entire
 * requested output; callers must propagate the error, never deliver it as data.
 * Zero-length reads through end-of-media succeed without backing I/O. The third
 * scratch buffer retains one authenticated leaf hash block within this request;
 * no cache survives return and no allocation is used. Each data block is read
 * and hashed. The caller must bound request size and concurrency.
 */
int g_verity_read_range(uint64_t, uint32_t, const void *, size_t,
    const uint8_t[32], uint64_t, size_t, g_verity_read_t *, void *, void *,
    void *, void *, void *);

/* Optional bounded direct-mapped cache. Caller authenticates root, owns all
 * memory and serializes initialization/reads/rebinding/teardown. root and cache
 * storage must remain private and unmodified between calls. Each entry needs
 * one uint64_t tag and block_size bytes; zero entries is supported. init validates
 * geometry and clears tags, but does not authenticate root. Failed init leaves
 * the old binding unchanged; caller must handle the error. No allocation or
 * kernel provider lifecycle is implemented here. */
struct g_verity_cache {
	struct g_verity_root root;
	uint64_t *tags;
	void *blocks;
	size_t entries;
	unsigned initialized;
};
int g_verity_cache_init(struct g_verity_cache *, const struct g_verity_root *,
    uint64_t *, void *, size_t);
/* Two private block-sized scratch buffers, separate from cache/output. Same
 * range/error contract as g_verity_read_range. Every data block is freshly read
 * and hashed; only retained root-authenticated hash bytes are reused. */
int g_verity_cached_read_range(struct g_verity_cache *, uint64_t, size_t,
    g_verity_read_t *, void *, void *, void *, void *);

#endif
