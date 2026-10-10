/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BSD_CACHE_H_
#define _BSD_CACHE_H_
#include <sys/types.h>

#include <notify_pressure.h>
#include <stddef.h>
#include <stdint.h>
#define BSD_CACHE_AUTOMATIC   1U
#define BSD_CACHE_KEY_MAX     255U
#define BSD_CACHE_VALUE_MAX   (16U * 1024 * 1024)
#define BSD_CACHE_ENTRIES_MAX 65536U
struct bsd_cache;
/* Lookup is also the validity check; a hit returns a caller-owned copy. */
enum bsd_cache_result {
	BSD_CACHE_ERROR = -1,
	BSD_CACHE_MISS = 0,
	BSD_CACHE_HIT = 1
};
enum bsd_cache_reason {
	BSD_CACHE_LIMIT,
	BSD_CACHE_PRESSURE,
	BSD_CACHE_REPLACED,
	BSD_CACHE_REMOVED,
	BSD_CACHE_PURGED,
	BSD_CACHE_DESTROYED
};
typedef void (*bsd_cache_evicted_fn)(const char *, const void *, size_t,
    enum bsd_cache_reason, void *);
struct bsd_cache_stats {
	size_t entries, cost, entry_limit, cost_limit;
	uint64_t hits, misses, evictions;
	unsigned pressure;
	int notification_error;
};
__BEGIN_DECLS
/* Simple default: shared automatic notifications, no eviction callback. */
int bsd_cache_open(size_t, size_t, struct bsd_cache **);
enum bsd_cache_result bsd_cache_lookup(struct bsd_cache *, const char *, void *,
    size_t *);
int bsd_cache_create(size_t, size_t, unsigned, bsd_cache_evicted_fn, void *,
    struct bsd_cache **);
/* Capture before rebuilding; token is scoped to this cache's lifetime. */
int bsd_cache_generation(struct bsd_cache *, uint64_t *);
int bsd_cache_put_if_current(struct bsd_cache *, const char *, const void *,
    size_t, size_t, uint64_t);
int bsd_cache_put(struct bsd_cache *, const char *, const void *, size_t,
    size_t);
int bsd_cache_get(struct bsd_cache *, const char *, void *, size_t *);
int bsd_cache_remove(struct bsd_cache *, const char *);
int bsd_cache_purge(struct bsd_cache *);
int bsd_cache_set_limits(struct bsd_cache *, size_t, size_t);
int bsd_cache_set_pressure(struct bsd_cache *, unsigned);
int bsd_cache_get_stats(struct bsd_cache *, struct bsd_cache_stats *);
int bsd_cache_destroy(struct bsd_cache *);
__END_DECLS
#endif
