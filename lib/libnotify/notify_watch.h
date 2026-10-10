/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _NOTIFY_WATCH_H_
#define _NOTIFY_WATCH_H_

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>

#define NOTIFY_WATCH_MAX_BYTES (64U * 1024)
#define NOTIFY_WATCH_MAX_SUBSCRIBERS 1024U
#define NOTIFY_WATCH_RESET 1U

struct notify_watch;
struct notify_watcher;
struct notify_watch_cursor {
	uint64_t epoch;
	uint64_t generation;
};

/*
 * Provider-side latest-state storage, independent of transport and authority.
 * The provider validates/authorizes its typed data and wakes its event loop
 * after publish. Values must have canonical bytes (including padding).
 * Store access is synchronized. The caller must serialize calls using the
 * same watcher, including close; create/destroy require exclusive ownership.
 * Inherited objects reject operations with ECHILD before touching locks.
 * close is void: it sets errno and leaves an inherited object unchanged.
 * A child may create fresh objects.
 */
__BEGIN_DECLS
int notify_watch_create(size_t, size_t, struct notify_watch **);
/* EBUSY while any watcher remains; no implicit cancellation or dangling refs. */
int notify_watch_destroy(struct notify_watch *);
/* 1 changed, 0 identical, -1 error. No allocation after create. */
int notify_watch_publish(struct notify_watch *, const void *, size_t);
/* NULL cursor starts with the current snapshot; resume detects epoch changes. */
int notify_watch_open(struct notify_watch *, const struct notify_watch_cursor *,
    struct notify_watcher **);
void notify_watch_close(struct notify_watcher *);
int notify_watch_begin(struct notify_watcher *);
int notify_watch_cancel(struct notify_watcher *);
/*
 * 1 copied and completed, 0 still pending, -1 error. EMSGSIZE sets *length to
 * the required size and leaves the watch pending. Other outputs change only
 * on success. A successful copy advances the cursor atomically; cancellation
 * does not. The provider owns delivery failure handling after the copy.
 */
int notify_watch_take(struct notify_watcher *, void *, size_t, size_t *,
    struct notify_watch_cursor *, uint32_t *);
__END_DECLS
#endif
