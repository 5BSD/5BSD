/*- SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "notify_watch.h"

struct notify_watch {
	pthread_mutex_t lock;
	struct notify_watch_cursor cursor;
	size_t capacity, length, limit, subscribers;
	unsigned char data[];
};

struct notify_watcher {
	struct notify_watch *store;
	struct notify_watch_cursor cursor;
	bool pending;
};

static int watch_lock(struct notify_watch *store)
    __trylocks_exclusive(0, store->lock);

static int
watch_lock(struct notify_watch *store) __no_lock_analysis
{
	int error;

	error = pthread_mutex_lock(&store->lock);
	if (error != 0)
		errno = error;
	return (error == 0 ? 0 : -1);
}

int
notify_watch_create(size_t capacity, size_t subscribers,
    struct notify_watch **result)
{
	struct notify_watch *store;
	int error;

	if (result == NULL)
		return (errno = EINVAL, -1);
	*result = NULL;
	if (capacity == 0 || capacity > NOTIFY_WATCH_MAX_BYTES ||
	    subscribers == 0 || subscribers > NOTIFY_WATCH_MAX_SUBSCRIBERS)
		return (errno = EINVAL, -1);
	store = calloc(1, sizeof(*store) + capacity);
	if (store == NULL)
		return (-1);
	error = pthread_mutex_init(&store->lock, NULL);
	if (error != 0) {
		free(store);
		return (errno = error, -1);
	}
	do {
		arc4random_buf(&store->cursor.epoch, sizeof(store->cursor.epoch));
	} while (store->cursor.epoch == 0);
	store->capacity = capacity;
	store->limit = subscribers;
	*result = store;
	return (0);
}

int
notify_watch_destroy(struct notify_watch *store)
{
	if (store == NULL)
		return (errno = EINVAL, -1);
	if (store->subscribers != 0)
		return (errno = EBUSY, -1);
	(void)pthread_mutex_destroy(&store->lock);
	free(store);
	return (0);
}

int
notify_watch_publish(struct notify_watch *store, const void *data, size_t length)
{
	if (store == NULL || (data == NULL && length != 0))
		return (errno = EINVAL, -1);
	if (length > store->capacity)
		return (errno = EMSGSIZE, -1);
	if (watch_lock(store) != 0)
		return (-1);
	if (store->cursor.generation != 0 && store->length == length &&
	    (length == 0 || memcmp(store->data, data, length) == 0)) {
		(void)pthread_mutex_unlock(&store->lock);
		return (0);
	}
	if (store->cursor.generation == UINT64_MAX) {
		(void)pthread_mutex_unlock(&store->lock);
		return (errno = EOVERFLOW, -1);
	}
	if (length != 0)
		memcpy(store->data, data, length);
	store->length = length;
	store->cursor.generation++;
	(void)pthread_mutex_unlock(&store->lock);
	return (1);
}

int
notify_watch_open(struct notify_watch *store,
    const struct notify_watch_cursor *cursor, struct notify_watcher **result)
{
	struct notify_watcher *watcher;
	int error;

	if (result == NULL)
		return (errno = EINVAL, -1);
	*result = NULL;
	if (store == NULL || (cursor != NULL &&
	    ((cursor->epoch == 0) != (cursor->generation == 0))))
		return (errno = EINVAL, -1);
	if (watch_lock(store) != 0)
		return (-1);
	error = 0;
	if (store->subscribers == store->limit)
		error = ENOSPC;
	else if (cursor != NULL && cursor->epoch == store->cursor.epoch &&
	    cursor->generation > store->cursor.generation)
		error = EINVAL;
	if (error != 0) {
		(void)pthread_mutex_unlock(&store->lock);
		return (errno = error, -1);
	}
	watcher = calloc(1, sizeof(*watcher));
	if (watcher == NULL) {
		(void)pthread_mutex_unlock(&store->lock);
		return (-1);
	}
	watcher->store = store;
	if (cursor != NULL)
		watcher->cursor = *cursor;
	store->subscribers++;
	(void)pthread_mutex_unlock(&store->lock);
	*result = watcher;
	return (0);
}

void
notify_watch_close(struct notify_watcher *watcher)
{
	struct notify_watch *store;

	if (watcher == NULL)
		return;
	store = watcher->store;
	if (watch_lock(store) != 0)
		return;
	store->subscribers--;
	(void)pthread_mutex_unlock(&store->lock);
	free(watcher);
}

int
notify_watch_begin(struct notify_watcher *watcher)
{
	if (watcher == NULL)
		return (errno = EINVAL, -1);
	if (watcher->pending)
		return (errno = EBUSY, -1);
	watcher->pending = true;
	return (0);
}

int
notify_watch_cancel(struct notify_watcher *watcher)
{
	if (watcher == NULL)
		return (errno = EINVAL, -1);
	watcher->pending = false;
	return (0);
}

int
notify_watch_take(struct notify_watcher *watcher, void *data, size_t capacity,
    size_t *length, struct notify_watch_cursor *cursor, uint32_t *flags)
{
	struct notify_watch *store;

	if (watcher == NULL || length == NULL || cursor == NULL || flags == NULL ||
	    (data == NULL && capacity != 0))
		return (errno = EINVAL, -1);
	if (!watcher->pending)
		return (errno = ENOENT, -1);
	store = watcher->store;
	if (watch_lock(store) != 0)
		return (-1);
	if (store->cursor.generation == 0 ||
	    (watcher->cursor.epoch == store->cursor.epoch &&
	    watcher->cursor.generation == store->cursor.generation)) {
		(void)pthread_mutex_unlock(&store->lock);
		return (0);
	}
	if (capacity < store->length) {
		*length = store->length;
		(void)pthread_mutex_unlock(&store->lock);
		return (errno = EMSGSIZE, -1);
	}
	if (store->length != 0)
		memcpy(data, store->data, store->length);
	*length = store->length;
	*cursor = store->cursor;
	*flags = watcher->cursor.epoch != 0 &&
	    watcher->cursor.epoch != store->cursor.epoch ? NOTIFY_WATCH_RESET : 0;
	watcher->cursor = store->cursor;
	watcher->pending = false;
	(void)pthread_mutex_unlock(&store->lock);
	return (1);
}
