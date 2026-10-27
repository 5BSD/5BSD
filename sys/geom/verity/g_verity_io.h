/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _GEOM_VERITY_IO_H_
#define _GEOM_VERITY_IO_H_
#include <geom/verity/g_verity_verify.h>
struct g_consumer;
/* One backing provider: filesystem bytes followed by the root-first hash tree. */
struct g_verity_backing {
	struct g_consumer *consumer;
	uint64_t data_bytes;
	uint64_t tree_bytes;
	uint32_t block_size;
};
/*
 * Called under topology lock with a read-open consumer. Parameters must come
 * from authenticated metadata. This checks geometry, not authenticity. Caller
 * owns/pins the consumer and must prevent rebind/teardown until all I/O drains.
 */
int g_verity_backing_bind(struct g_verity_backing *, struct g_consumer *,
    uint64_t, uint32_t);
/* Sleeping worker only, no topology lock. Uses caller-owned block buffer. */
int g_verity_backing_read(void *, int, uint64_t, void *, size_t);
/* Optional request-local data batching. The caller owns a distinct private
 * buffer, at most maxphys bytes, disjoint from verifier scratch/output buffers,
 * and serializes all calls. Initialize anew for
 * each nonempty request; never share a window across verification workers.
 * Only the requested range rounded to verification blocks may be fetched.
 * Bytes in this window are UNVERIFIED: the core must authenticate every block
 * copied from it. The existing consumer lifetime contract still applies.
 */
struct g_verity_read_window {
	struct g_verity_backing *backing;
	void *buffer;
	uint64_t first, end, cached_offset;
	size_t capacity, valid;
};
int g_verity_window_init(struct g_verity_read_window *,
    struct g_verity_backing *, uint64_t, size_t, void *, size_t);
int g_verity_window_read(void *, int, uint64_t, void *, size_t);
#endif
