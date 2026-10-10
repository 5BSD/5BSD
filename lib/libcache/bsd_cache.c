/* SPDX-License-Identifier: BSD-2-Clause */
#include <errno.h>
#include <notify.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bsd_cache.h"

struct cache_entry {
	struct cache_entry *next, *prev;
	size_t length, cost;
	char key[BSD_CACHE_KEY_MAX + 1];
	unsigned char value[];
};
struct bsd_cache {
	pthread_mutex_t lock;
	pthread_t watcher;
	pid_t owner;
	atomic_bool stopping;
	bool automatic, destroying;
	unsigned effective_pressure;
	struct cache_entry *first, *last;
	struct bsd_cache_stats stats;
	bsd_cache_evicted_fn callback;
	void *argument;
};
static int cache_lock(struct bsd_cache *c) __trylocks_exclusive(0, c->lock);
static int
cache_lock(struct bsd_cache *c) __no_lock_analysis
{
	int error;
	if (c == NULL)
		return (errno = EINVAL, -1);
	if (c->owner != getpid())
		return (errno = ECHILD, -1);
	error = pthread_mutex_lock(&c->lock);
	return (error == 0 ? 0 : (errno = error, -1));
}
static bool
valid_key(const char *key)
{
	return (key != NULL && key[0] != '\0' &&
	    strnlen(key, BSD_CACHE_KEY_MAX + 1) <= BSD_CACHE_KEY_MAX);
}
static struct cache_entry *
find_entry(struct bsd_cache *c, const char *key)
{
	for (struct cache_entry *e = c->first; e != NULL; e = e->next)
		if (strcmp(e->key, key) == 0)
			return (e);
	return (NULL);
}
static void
unlink_entry(struct bsd_cache *c, struct cache_entry *e)
{
	if (e->prev != NULL)
		e->prev->next = e->next;
	else
		c->first = e->next;
	if (e->next != NULL)
		e->next->prev = e->prev;
	else
		c->last = e->prev;
	c->stats.entries--;
	c->stats.cost -= e->cost;
}
static void
link_first(struct bsd_cache *c, struct cache_entry *e)
{
	e->prev = NULL;
	e->next = c->first;
	if (c->first != NULL)
		c->first->prev = e;
	else
		c->last = e;
	c->first = e;
	c->stats.entries++;
	c->stats.cost += e->cost;
}
static void
limits(struct bsd_cache *c, size_t *entries, size_t *cost)
{
	*entries = c->stats.entry_limit;
	*cost = c->stats.cost_limit;
	if (c->effective_pressure == NOTIFY_PRESSURE_WARNING) {
		*entries /= 2;
		*cost /= 2;
	} else if (c->effective_pressure == NOTIFY_PRESSURE_CRITICAL)
		*entries = *cost = 0;
}
static struct cache_entry *
trim(struct bsd_cache *c)
{
	struct cache_entry *trash = NULL, *e;
	size_t entries, cost;
	limits(c, &entries, &cost);
	while (c->last != NULL &&
	    (c->stats.entries > entries || c->stats.cost > cost)) {
		e = c->last;
		unlink_entry(c, e);
		e->next = trash;
		trash = e;
		c->stats.evictions++;
	}
	return (trash);
}
static void
dispose(struct bsd_cache *c, struct cache_entry *e,
    enum bsd_cache_reason reason)
{
	while (e != NULL) {
		struct cache_entry *next = e->next;
		if (c->callback != NULL)
			c->callback(e->key, e->value, e->length, reason,
			    c->argument);
		free(e);
		e = next;
	}
}
int
bsd_cache_put(struct bsd_cache *c, const char *key, const void *value,
    size_t length, size_t cost)
{
	struct cache_entry *e, *old, *trash;
	size_t entries, budget;
	if (!valid_key(key) || (value == NULL && length != 0) ||
	    length > BSD_CACHE_VALUE_MAX || cost < length)
		return (errno = EINVAL, -1);
	e = malloc(sizeof(*e) + length);
	if (e == NULL)
		return (-1);
	e->length = length;
	e->cost = cost;
	strlcpy(e->key, key, sizeof(e->key));
	if (length != 0)
		memcpy(e->value, value, length);
	if (cache_lock(c) != 0) {
		free(e);
		return (-1);
	}
	limits(c, &entries, &budget);
	if (c->destroying || entries == 0 || cost > budget) {
		pthread_mutex_unlock(&c->lock);
		free(e);
		return (errno = EAGAIN, -1);
	}
	old = find_entry(c, key);
	if (old != NULL) {
		unlink_entry(c, old);
		old->next = NULL;
	}
	/* Evict before adding, avoiding cost overflow near SIZE_MAX. */
	trash = NULL;
	while (c->last != NULL &&
	    (c->stats.entries >= entries || c->stats.cost > budget - cost)) {
		struct cache_entry *victim = c->last;
		unlink_entry(c, victim);
		victim->next = trash;
		trash = victim;
		c->stats.evictions++;
	}
	link_first(c, e);
	pthread_mutex_unlock(&c->lock);
	dispose(c, old, BSD_CACHE_REPLACED);
	dispose(c, trash, BSD_CACHE_LIMIT);
	return (0);
}
int
bsd_cache_get(struct bsd_cache *c, const char *key, void *value, size_t *length)
{
	struct cache_entry *e;
	if (!valid_key(key) || length == NULL ||
	    (value == NULL && *length != 0))
		return (errno = EINVAL, -1);
	if (cache_lock(c) != 0)
		return (-1);
	e = find_entry(c, key);
	if (e == NULL) {
		c->stats.misses++;
		pthread_mutex_unlock(&c->lock);
		return (errno = ENOENT, -1);
	}
	if (*length < e->length) {
		*length = e->length;
		pthread_mutex_unlock(&c->lock);
		return (errno = ENOMEM, -1);
	}
	if (e->length != 0)
		memcpy(value, e->value, e->length);
	*length = e->length;
	unlink_entry(c, e);
	link_first(c, e);
	c->stats.hits++;
	pthread_mutex_unlock(&c->lock);
	return (0);
}
int
bsd_cache_remove(struct bsd_cache *c, const char *key)
{
	struct cache_entry *e;
	if (!valid_key(key))
		return (errno = EINVAL, -1);
	if (cache_lock(c) != 0)
		return (-1);
	e = find_entry(c, key);
	if (e != NULL) {
		unlink_entry(c, e);
		e->next = NULL;
	}
	pthread_mutex_unlock(&c->lock);
	if (e == NULL)
		return (errno = ENOENT, -1);
	dispose(c, e, BSD_CACHE_REMOVED);
	return (0);
}
int
bsd_cache_purge(struct bsd_cache *c)
{
	struct cache_entry *trash;
	if (cache_lock(c) != 0)
		return (-1);
	trash = c->first;
	c->first = c->last = NULL;
	c->stats.entries = c->stats.cost = 0;
	pthread_mutex_unlock(&c->lock);
	dispose(c, trash, BSD_CACHE_PURGED);
	return (0);
}
int
bsd_cache_set_limits(struct bsd_cache *c, size_t entries, size_t cost)
{
	struct cache_entry *trash;
	if (entries == 0 || entries > BSD_CACHE_ENTRIES_MAX || cost == 0)
		return (errno = EINVAL, -1);
	if (cache_lock(c) != 0)
		return (-1);
	c->stats.entry_limit = entries;
	c->stats.cost_limit = cost;
	trash = trim(c);
	pthread_mutex_unlock(&c->lock);
	dispose(c, trash, BSD_CACHE_LIMIT);
	return (0);
}
int
bsd_cache_set_pressure(struct bsd_cache *c, unsigned level)
{
	struct cache_entry *trash;
	if (level > NOTIFY_PRESSURE_UNKNOWN)
		return (errno = EINVAL, -1);
	if (cache_lock(c) != 0)
		return (-1);
	c->stats.pressure = level;
	if (level != NOTIFY_PRESSURE_UNKNOWN)
		c->effective_pressure = level;
	trash = trim(c);
	pthread_mutex_unlock(&c->lock);
	dispose(c, trash, BSD_CACHE_PRESSURE);
	return (0);
}
int
bsd_cache_get_stats(struct bsd_cache *c, struct bsd_cache_stats *out)
{
	if (out == NULL)
		return (errno = EINVAL, -1);
	if (cache_lock(c) != 0)
		return (-1);
	*out = c->stats;
	pthread_mutex_unlock(&c->lock);
	return (0);
}
static void *
watch_pressure(void *argument)
{
	struct bsd_cache *c = argument;
	struct notify_client *client = NULL;
	struct notify_state_watch_reply state;
	int error;
	while (!atomic_load(&c->stopping)) {
		error = client == NULL && notify_client_open(&client) == -1 ?
		    errno :
		    0;
		if (error == 0 &&
		    notify_state_watch(client, NOTIFY_PRESSURE_TOPIC, &state,
			250) == -1)
			error = errno;
		if (error == 0)
			(void)bsd_cache_set_pressure(c,
			    state.present &&
				    state.state <= NOTIFY_PRESSURE_UNKNOWN ?
				state.state :
				NOTIFY_PRESSURE_UNKNOWN);
		else if (error != EAGAIN) {
			(void)bsd_cache_set_pressure(c,
			    NOTIFY_PRESSURE_UNKNOWN);
			if (client != NULL)
				notify_client_close(client);
			client = NULL;
		}
		if (cache_lock(c) == 0) {
			c->stats.notification_error = error == EAGAIN ? 0 :
									error;
			pthread_mutex_unlock(&c->lock);
		}
		/* Retry failures at most once a second, without delaying
		 * destruction. */
		if (error != 0 && error != EAGAIN)
			for (unsigned i = 0;
			    i < 10 && !atomic_load(&c->stopping); i++)
				usleep(100000);
	}
	if (client != NULL)
		notify_client_close(client);
	return (NULL);
}
int
bsd_cache_create(size_t entries, size_t cost, unsigned flags,
    bsd_cache_evicted_fn callback, void *argument, struct bsd_cache **out)
{
	struct bsd_cache *c;
	int error;
	if (out == NULL)
		return (errno = EINVAL, -1);
	*out = NULL;
	if (entries == 0 || entries > BSD_CACHE_ENTRIES_MAX || cost == 0 ||
	    (flags & ~BSD_CACHE_AUTOMATIC) != 0)
		return (errno = EINVAL, -1);
	c = calloc(1, sizeof(*c));
	if (c == NULL)
		return (-1);
	c->owner = getpid();
	c->callback = callback;
	c->argument = argument;
	c->stats.entry_limit = entries;
	c->stats.cost_limit = cost;
	c->stats.pressure = NOTIFY_PRESSURE_UNKNOWN;
	atomic_init(&c->stopping, false);
	error = pthread_mutex_init(&c->lock, NULL);
	if (error != 0) {
		free(c);
		return (errno = error, -1);
	}
	if ((flags & BSD_CACHE_AUTOMATIC) != 0) {
		c->automatic = true;
		error = pthread_create(&c->watcher, NULL, watch_pressure, c);
		if (error != 0) {
			pthread_mutex_destroy(&c->lock);
			free(c);
			return (errno = error, -1);
		}
	}
	*out = c;
	return (0);
}
int
bsd_cache_destroy(struct bsd_cache *c)
{
	struct cache_entry *trash;
	int error;
	if (c == NULL)
		return (errno = EINVAL, -1);
	if (c->owner != getpid())
		return (errno = ECHILD, -1);
	if (c->automatic) {
		if (pthread_equal(pthread_self(), c->watcher))
			return (errno = EDEADLK, -1);
		atomic_store(&c->stopping, true);
		error = pthread_join(c->watcher, NULL);
		if (error != 0)
			return (errno = error, -1);
	}
	c->destroying = true;
	trash = c->first;
	c->first = c->last = NULL;
	c->stats.entries = c->stats.cost = 0;
	dispose(c, trash, BSD_CACHE_DESTROYED);
	pthread_mutex_destroy(&c->lock);
	free(c);
	return (0);
}
