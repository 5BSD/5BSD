/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/event.h>

#include <channel.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "service_runtime.h"

static _Thread_local uint64_t budget_end;
static _Thread_local pid_t budget_owner;
static uint64_t
add_ms(uint64_t a, uint64_t b)
{
	return (UINT64_MAX - a < b ? UINT64_MAX : a + b);
}
uint64_t
service_monotime_ms(void)
{
	struct timespec ts;
	/* CLOCK_MONOTONIC is always available on supported FreeBSD kernels. */
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		abort();
	return ((uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
int
service_retry_init(struct service_retry *r, uint32_t initial, uint32_t maximum)
{
	if (r == NULL || initial == 0 || maximum < initial)
		return (errno = EINVAL, -1);
	*r = (struct service_retry) { .initial_ms = initial,
		.maximum_ms = maximum };
	return (0);
}
bool
service_retry_ready(const struct service_retry *r, uint64_t now)
{
	return (now >= r->next_ms);
}
void
service_retry_result(struct service_retry *r, uint64_t now, bool success)
{
	if (success) {
		r->next_ms = r->delay_ms = 0;
		return;
	}
	r->delay_ms = r->delay_ms == 0 ?
	    r->initial_ms :
	    (r->delay_ms > r->maximum_ms / 2 ? r->maximum_ms : r->delay_ms * 2);
	r->next_ms = add_ms(now, r->delay_ms);
}
static void
increment(uint64_t *v)
{
	if (*v != UINT64_MAX)
		++*v;
}
bool
service_health_record(struct service_health *h, int error)
{
	bool changed = (h->last_error == 0) != (error == 0);
	if (error == 0) {
		increment(&h->successes);
		h->consecutive_failures = 0;
	} else {
		increment(&h->failures);
		increment(&h->consecutive_failures);
	}
	if (changed)
		increment(&h->changes);
	h->last_error = error;
	return (changed);
}
int
service_budget_begin(uint32_t ms)
{
	if (ms == 0 || ms == UINT32_MAX)
		return (errno = EINVAL, -1);
	if (budget_owner == getpid() && budget_end != 0)
		return (errno = EBUSY, -1);
	budget_owner = getpid();
	budget_end = add_ms(service_monotime_ms(), ms);
	return (0);
}
void
service_budget_end(void)
{
	budget_end = 0;
}
int
service_budget_timeout(uint32_t *ms)
{
	uint64_t now, left;
	if (ms == NULL)
		return (errno = EINVAL, -1);
	if (budget_end == 0 || budget_owner != getpid())
		return (0);
	now = service_monotime_ms();
	if (now >= budget_end)
		return (errno = ETIMEDOUT, -1);
	left = budget_end - now;
	if (left < *ms)
		*ms = (uint32_t)left;
	return (0);
}
int
service_drain_wait(int (*done)(void *), void *arg, uint32_t ms)
{
	uint64_t end, now, left;
	struct timespec pause;
	int result;
	if (done == NULL)
		return (errno = EINVAL, -1);
	end = add_ms(service_monotime_ms(), ms);
	for (;;) {
		result = done(arg);
		if (result != 0)
			return (result > 0 ? 0 : -1);
		now = service_monotime_ms();
		if (now >= end)
			return (errno = ETIMEDOUT, -1);
		left = end - now;
		pause = (struct timespec) { .tv_nsec = (left < 10 ? left : 10) *
			    1000000 };
		if (nanosleep(&pause, NULL) == -1 && errno != EINTR)
			return (-1);
	}
}
struct lease {
	uint64_t owner, id;
};
struct service_lease_set {
	size_t capacity, count;
	uint64_t serial;
	struct lease entries[];
};
int
service_lease_set_create(size_t capacity, struct service_lease_set **out)
{
	struct service_lease_set *s;
	if (out == NULL || capacity == 0 || capacity > 65536)
		return (errno = EINVAL, -1);
	*out = NULL;
	s = calloc(1, sizeof(*s) + capacity * sizeof(s->entries[0]));
	if (s == NULL)
		return (-1);
	s->capacity = capacity;
	*out = s;
	return (0);
}
void
service_lease_set_destroy(struct service_lease_set *s)
{
	free(s);
}
int
service_lease_acquire(struct service_lease_set *s, uint64_t owner, uint64_t *id)
{
	size_t i;
	if (s == NULL || owner == 0 || id == NULL)
		return (errno = EINVAL, -1);
	if (s->count == s->capacity)
		return (errno = ENOSPC, -1);
	if (s->serial == UINT64_MAX)
		return (errno = EOVERFLOW, -1);
	for (i = 0; i < s->capacity; i++) {
		if (s->entries[i].id != 0)
			continue;
		s->entries[i] = (struct lease) { owner, ++s->serial };
		*id = s->serial;
		s->count++;
		return (0);
	}
	return (errno = ENOSPC, -1);
}
int
service_lease_release(struct service_lease_set *s, uint64_t owner, uint64_t id)
{
	size_t i;
	if (s == NULL || owner == 0 || id == 0)
		return (errno = EINVAL, -1);
	for (i = 0; i < s->capacity; i++) {
		if (s->entries[i].id != id || s->entries[i].owner != owner)
			continue;
		s->entries[i] = (struct lease) { 0 };
		s->count--;
		return (0);
	}
	return (errno = ENOENT, -1);
}
void
service_lease_release_owner(struct service_lease_set *s, uint64_t owner)
{
	size_t i;
	for (i = 0; i < s->capacity; i++) {
		if (s->entries[i].id != 0 && s->entries[i].owner == owner) {
			s->entries[i] = (struct lease) { 0 };
			s->count--;
		}
	}
}
size_t
service_lease_count(const struct service_lease_set *s)
{
	return (s->count);
}

int
service_channels_wait(int kq, struct service_channel_slot *slots, size_t count,
    int listener, int timeout_ms)
{
	struct kevent changes[513], events[513];
	struct timespec timeout;
	unsigned char ready[256] = { 0 };
	int nchanges = 0, n, wants, listener_ready = 0;
	size_t i;
	if (kq < 0 || count > 256 || (count != 0 && slots == NULL) ||
	    timeout_ms < -1)
		return (errno = EINVAL, -1);
	if (listener >= 0) {
		EV_SET(&changes[nchanges], listener, EVFILT_READ,
		    EV_ADD | EV_ENABLE, 0, 0, NULL);
		nchanges++;
	}
	for (i = 0; i < count; i++) {
		slots[i].error = 0;
		if (slots[i].channel == NULL)
			continue;
		wants = channel_wants_write(slots[i].channel);
		if (wants == -1) {
			slots[i].error = errno;
			timeout_ms = 0;
			continue;
		}
		EV_SET(&changes[nchanges], channel_fd(slots[i].channel),
		    EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0,
		    (void *)(uintptr_t)(i + 1));
		nchanges++;
		EV_SET(&changes[nchanges], channel_fd(slots[i].channel),
		    EVFILT_WRITE, EV_ADD | (wants ? EV_ENABLE : EV_DISABLE), 0,
		    0, (void *)(uintptr_t)(i + 1));
		nchanges++;
	}
	timeout = (struct timespec) {
		.tv_sec = timeout_ms < 0 ? 0 : timeout_ms / 1000,
		.tv_nsec = timeout_ms < 0 ? 0 : (timeout_ms % 1000) * 1000000L
	};
	n = kevent(kq, changes, nchanges, events, 513,
	    timeout_ms == -1 ? NULL : &timeout);
	if (n == -1)
		return (errno == EINTR ? 0 : -1);
	for (int e = 0; e < n; e++) {
		uintptr_t tag = (uintptr_t)events[e].udata;
		if (tag == 0) {
			if (events[e].flags & (EV_ERROR | EV_EOF))
				return (errno = EPIPE, -1);
			listener_ready = 1;
			continue;
		}
		if (tag > count)
			return (errno = EPROTO, -1);
		i = tag - 1;
		if (events[e].flags & EV_ERROR)
			slots[i].error = events[e].data != 0 ? events[e].data :
							       EIO;
		if (events[e].flags & EV_EOF)
			ready[i] |= 4;
		ready[i] |= events[e].filter == EVFILT_READ ? 1 : 2;
	}
	for (i = 0; i < count; i++) {
		int result = 0;
		if (slots[i].channel == NULL || slots[i].error != 0)
			continue;
		if (ready[i] & 2)
			result = channel_flush(slots[i].channel);
		if (result == 0 && (ready[i] & 1))
			result = channel_dispatch(slots[i].channel);
		if (result == -1)
			slots[i].error = errno != 0 ? errno : EIO;
		else if (ready[i] & 4)
			slots[i].error = ECONNRESET;
	}
	return (listener_ready);
}
