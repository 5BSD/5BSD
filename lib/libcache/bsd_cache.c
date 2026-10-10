/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/tree.h>

#include <errno.h>
#include <notify.h>
#include <pthread.h>
#include <service_runtime.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bsd_cache.h"

struct cache_entry {
	struct cache_entry *next, *prev;
	RB_ENTRY(cache_entry) index;
	size_t length, cost;
	char key[BSD_CACHE_KEY_MAX + 1];
	unsigned char value[];
};
static int
entry_compare(struct cache_entry *a, struct cache_entry *b)
{
	return (strcmp(a->key, b->key));
}
RB_HEAD(cache_index, cache_entry);
RB_GENERATE_STATIC(cache_index, cache_entry, index, entry_compare);

struct bsd_cache {
	pthread_mutex_t lock;
	struct cache_watch *watch;
	struct bsd_cache *watch_next, *delivery_next;
	bool observing;
	uint64_t watch_epoch, watch_generation;
	pid_t owner;
	bool automatic, destroying, generation_exhausted;
	uint64_t generation;
	unsigned effective_pressure;
	struct cache_entry *first, *last;
	struct cache_index index;
	struct bsd_cache_stats stats;
	bsd_cache_evicted_fn callback;
	void *argument;
};
/* One process-local registry; the last cache joins its watcher. */
struct cache_watch {
	pid_t owner;
	pthread_mutex_t lock;
	pthread_cond_t changed;
	pthread_t thread;
	struct bsd_cache *head;
	bool started, stopping;
};
static _Atomic(struct cache_watch *) process_watch;

static struct cache_watch *
get_watch(void)
{
	struct cache_watch *old, *watch;
	int error;

	old = atomic_load(&process_watch);
	if (old != NULL && old->owner == getpid())
		return (old);
	watch = calloc(1, sizeof(*watch));
	if (watch == NULL)
		return (NULL);
	watch->owner = getpid();
	error = pthread_mutex_init(&watch->lock, NULL);
	if (error != 0) {
		free(watch);
		return (errno = error, NULL);
	}
	error = pthread_cond_init(&watch->changed, NULL);
	if (error != 0) {
		pthread_mutex_destroy(&watch->lock);
		free(watch);
		return (errno = error, NULL);
	}
	/* A fork child never touches the parent's possibly locked registry. */
	while (!atomic_compare_exchange_weak(&process_watch, &old, watch)) {
		if (old != NULL && old->owner == getpid()) {
			pthread_cond_destroy(&watch->changed);
			pthread_mutex_destroy(&watch->lock);
			free(watch);
			return (old);
		}
	}
	return (watch);
}

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
	struct cache_entry probe;

	strlcpy(probe.key, key, sizeof(probe.key));
	return (RB_FIND(cache_index, &c->index, &probe));
}
static void
unlink_entry(struct bsd_cache *c, struct cache_entry *e)
{
	RB_REMOVE(cache_index, &c->index, e);
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
	RB_INSERT(cache_index, &c->index, e);
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
static void
invalidate_generation(struct bsd_cache *c)
{
	if (c->generation == UINT64_MAX)
		c->generation_exhausted = true;
	else
		c->generation++;
}
int
bsd_cache_generation(struct bsd_cache *c, uint64_t *out)
{
	if (out == NULL)
		return (errno = EINVAL, -1);
	if (cache_lock(c) != 0)
		return (-1);
	if (c->generation_exhausted) {
		pthread_mutex_unlock(&c->lock);
		return (errno = EOVERFLOW, -1);
	}
	*out = c->generation;
	pthread_mutex_unlock(&c->lock);
	return (0);
}
static int
admission_error(struct bsd_cache *c, size_t cost, const uint64_t *generation,
    size_t *entries, size_t *budget)
{
	if (generation != NULL &&
	    (c->generation_exhausted || *generation != c->generation))
		return (ESTALE);
	limits(c, entries, budget);
	return (c->destroying || *entries == 0 || cost > *budget ? EAGAIN : 0);
}
static int
cache_put(struct bsd_cache *c, const char *key, const void *value,
    size_t length, size_t cost, const uint64_t *generation)
{
	struct cache_entry *e, *old, *trash;
	size_t entries, budget;
	int error;
	if (!valid_key(key) || (value == NULL && length != 0) ||
	    length > BSD_CACHE_VALUE_MAX || cost < length)
		return (errno = EINVAL, -1);
	/* Avoid copying values that are already known to be inadmissible. */
	if (cache_lock(c) != 0)
		return (-1);
	error = admission_error(c, cost, generation, &entries, &budget);
	pthread_mutex_unlock(&c->lock);
	if (error != 0)
		return (errno = error, -1);
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
	/* Pressure, invalidation or limits may have changed while copying. */
	error = admission_error(c, cost, generation, &entries, &budget);
	if (error != 0) {
		pthread_mutex_unlock(&c->lock);
		free(e);
		return (errno = error, -1);
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
	invalidate_generation(c);
	pthread_mutex_unlock(&c->lock);
	dispose(c, old, BSD_CACHE_REPLACED);
	dispose(c, trash, BSD_CACHE_LIMIT);
	return (0);
}
int
bsd_cache_put(struct bsd_cache *c, const char *key, const void *value,
    size_t length, size_t cost)
{
	return (cache_put(c, key, value, length, cost, NULL));
}
int
bsd_cache_put_if_current(struct bsd_cache *c, const char *key,
    const void *value, size_t length, size_t cost, uint64_t generation)
{
	return (cache_put(c, key, value, length, cost, &generation));
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
enum bsd_cache_result
bsd_cache_lookup(struct bsd_cache *c, const char *key, void *value,
    size_t *length)
{
	int saved_errno = errno;
	if (bsd_cache_get(c, key, value, length) == 0) {
		errno = saved_errno;
		return (BSD_CACHE_HIT);
	}
	if (errno == ENOENT) {
		errno = saved_errno;
		return (BSD_CACHE_MISS);
	}
	return (BSD_CACHE_ERROR);
}
int
bsd_cache_open(size_t entries, size_t cost, struct bsd_cache **out)
{
	return (bsd_cache_create(entries, cost, BSD_CACHE_AUTOMATIC, NULL, NULL,
	    out));
}
int
bsd_cache_remove(struct bsd_cache *c, const char *key)
{
	struct cache_entry *e;
	if (!valid_key(key))
		return (errno = EINVAL, -1);
	if (cache_lock(c) != 0)
		return (-1);
	invalidate_generation(c);
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
	invalidate_generation(c);
	trash = c->first;
	c->first = c->last = NULL;
	RB_INIT(&c->index);
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
	invalidate_generation(c);
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
	if (level != NOTIFY_PRESSURE_UNKNOWN) {
		if (c->effective_pressure != level)
			invalidate_generation(c);
		c->effective_pressure = level;
	}
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
static void
observe_pressure(struct bsd_cache *c,
    const struct notify_state_watch_reply *state, uint64_t *epoch,
    uint64_t *generation)
{
	/* Latest-state watching can coalesce a critical/recovery transition.
	 * Drop cached entries when history is missing, even if now normal. */
	if (*epoch == 0 || *epoch != state->watch_epoch ||
	    (*generation != state->generation &&
		(*generation == UINT64_MAX ||
		    state->generation != *generation + 1)))
		(void)bsd_cache_purge(c);
	*epoch = state->watch_epoch;
	*generation = state->generation;
	(void)bsd_cache_set_pressure(c,
	    state->present && state->state <= NOTIFY_PRESSURE_UNKNOWN ?
		state->state :
		NOTIFY_PRESSURE_UNKNOWN);
}
static void *
watch_pressure(void *argument)
{
	struct cache_watch *watch = argument;
	struct bsd_cache *c, *delivery, *next;
	struct notify_client *client = NULL;
	struct notify_state_watch_reply state;
	int error;
	bool watch_idle, have_state = false;

	for (;;) {
		pthread_mutex_lock(&watch->lock);
		if (watch->stopping) {
			pthread_mutex_unlock(&watch->lock);
			break;
		}
		pthread_mutex_unlock(&watch->lock);
		watch_idle = false;
		/* One deadline covers discovery, HELLO, reconnect and watch. */
		error = service_budget_begin(1000) == -1 ? errno : 0;
		if (error == 0) {
			if (client == NULL && notify_client_open(&client) == -1)
				error = errno;
			if (error == 0 && notify_state_watch(client,
			    NOTIFY_PRESSURE_TOPIC, &state, 250) == -1) {
				error = errno;
				watch_idle = error == EAGAIN;
			}
			service_budget_end();
		}
		if (error == 0)
			have_state = true;
		else if (!watch_idle) {
			have_state = false;
			if (client != NULL)
				notify_client_close(client);
			client = NULL;
		}
		/* Pin a bounded-by-registration snapshot, with no allocation.
		 * Callbacks run without the registry lock and can create caches;
		 * those registrations participate in the next delivery. */
		pthread_mutex_lock(&watch->lock);
		delivery = watch->head;
		for (c = delivery; c != NULL; c = c->watch_next) {
			c->observing = true;
			c->delivery_next = c->watch_next;
		}
		pthread_mutex_unlock(&watch->lock);
		for (c = delivery; c != NULL; c = next) {
			next = c->delivery_next;
			if (have_state && (error == 0 || c->watch_epoch == 0))
				observe_pressure(c, &state, &c->watch_epoch,
				    &c->watch_generation);
			else if (!watch_idle)
				(void)bsd_cache_set_pressure(c, NOTIFY_PRESSURE_UNKNOWN);
			if (cache_lock(c) == 0) {
				c->stats.notification_error = watch_idle ? 0 : error;
				pthread_mutex_unlock(&c->lock);
			}
			pthread_mutex_lock(&watch->lock);
			c->observing = false;
			pthread_cond_broadcast(&watch->changed);
			pthread_mutex_unlock(&watch->lock);
		}
		if (error != 0 && !watch_idle) {
			for (unsigned i = 0; i < 10; i++) {
				pthread_mutex_lock(&watch->lock);
				bool empty = watch->head == NULL;
				pthread_mutex_unlock(&watch->lock);
				if (empty)
					break;
				usleep(100000);
			}
		}
	}
	if (client != NULL)
		notify_client_close(client);
	return (NULL);
}

static int
watch_register(struct bsd_cache *c)
{
	struct cache_watch *watch;
	int error;

	watch = get_watch();
	if (watch == NULL)
		return (errno);
	pthread_mutex_lock(&watch->lock);
	while (watch->stopping) {
		/* A callback cannot wait for its own thread to finish. */
		if (pthread_equal(pthread_self(), watch->thread)) {
			pthread_mutex_unlock(&watch->lock);
			return (EAGAIN);
		}
		pthread_cond_wait(&watch->changed, &watch->lock);
	}
	if (!watch->started) {
		error = pthread_create(&watch->thread, NULL, watch_pressure, watch);
		if (error != 0) {
			pthread_mutex_unlock(&watch->lock);
			return (error);
		}
		watch->started = true;
	}
	c->watch = watch;
	c->watch_next = watch->head;
	watch->head = c;
	pthread_cond_broadcast(&watch->changed);
	pthread_mutex_unlock(&watch->lock);
	return (0);
}

static int
watch_unregister(struct bsd_cache *c)
{
	struct cache_watch *watch = c->watch;
	struct bsd_cache **link;
	bool last;
	int error;

	/* Any pinned peer could otherwise deadlock its watcher's callback. */
	if (pthread_equal(pthread_self(), watch->thread))
		return (EDEADLK);
	pthread_mutex_lock(&watch->lock);
	for (link = &watch->head; *link != c; link = &(*link)->watch_next)
		;
	*link = c->watch_next;
	last = watch->head == NULL;
	if (last)
		watch->stopping = true;
	while (c->observing)
		pthread_cond_wait(&watch->changed, &watch->lock);
	pthread_mutex_unlock(&watch->lock);
	if (last) {
		error = pthread_join(watch->thread, NULL);
		if (error != 0)
			return (error);
		pthread_mutex_lock(&watch->lock);
		watch->started = watch->stopping = false;
		pthread_cond_broadcast(&watch->changed);
		pthread_mutex_unlock(&watch->lock);
	}
	return (0);
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
	RB_INIT(&c->index);
	c->callback = callback;
	c->argument = argument;
	c->stats.entry_limit = entries;
	c->stats.cost_limit = cost;
	c->stats.pressure = NOTIFY_PRESSURE_UNKNOWN;
	error = pthread_mutex_init(&c->lock, NULL);
	if (error != 0) {
		free(c);
		return (errno = error, -1);
	}
	if ((flags & BSD_CACHE_AUTOMATIC) != 0) {
		c->automatic = true;
		error = watch_register(c);
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
		error = watch_unregister(c);
		if (error != 0)
			return (errno = error, -1);
	}
	c->destroying = true;
	trash = c->first;
	c->first = c->last = NULL;
	RB_INIT(&c->index);
	c->stats.entries = c->stats.cost = 0;
	dispose(c, trash, BSD_CACHE_DESTROYED);
	pthread_mutex_destroy(&c->lock);
	free(c);
	return (0);
}
