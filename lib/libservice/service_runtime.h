/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _SERVICE_RUNTIME_H_
#define _SERVICE_RUNTIME_H_
#include <sys/cdefs.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Caller serializes these value objects. Milliseconds use CLOCK_MONOTONIC. */
struct service_retry {
	uint64_t next_ms;
	uint32_t initial_ms, maximum_ms, delay_ms;
};
struct service_health {
	uint64_t successes, failures, consecutive_failures, changes;
	int last_error;
};
struct service_lease_set;
struct channel;
struct service_channel_slot {
	struct channel *channel;
	int error;
};
__BEGIN_DECLS
uint64_t service_monotime_ms(void);
int service_retry_init(struct service_retry *, uint32_t, uint32_t);
bool service_retry_ready(const struct service_retry *, uint64_t);
void service_retry_result(struct service_retry *, uint64_t, bool);
/* Returns true on a transition between healthy and failed. Saturating counts.
 */
bool service_health_record(struct service_health *, int);
/* A thread-local, non-nestable RPC budget; includes discovery and HELLO calls.
 * Applies to libservice RPC waits, not arbitrary code, mutexes or kernel I/O.
 * End on every exit path. Forked children do not inherit an active budget. */
int service_budget_begin(uint32_t);
void service_budget_end(void);
int service_budget_timeout(uint32_t *);
/* Poll a nonblocking completion predicate against one absolute deadline.
 * Predicate: 1 complete, 0 pending, -1 failure. No signals or cancellation. */
int service_drain_wait(int (*)(void *), void *, uint32_t);
/* Bounded, session-owned leases. Nonzero IDs never reused within a set.
 * Owners are provider-assigned nonzero IDs, never untrusted wire identities. */
int service_lease_set_create(size_t, struct service_lease_set **);
void service_lease_set_destroy(struct service_lease_set *);
int service_lease_acquire(struct service_lease_set *, uint64_t, uint64_t *);
int service_lease_release(struct service_lease_set *, uint64_t, uint64_t);
void service_lease_release_owner(struct service_lease_set *, uint64_t);
size_t service_lease_count(const struct service_lease_set *);
/* Borrowed channels, at most 256. One dispatch batch per ready slot.
 * Channel errors go in slot.error; returns listener readiness, or -1 for
 * listener/kevent errors. Use a dedicated kqueue; caller closes sessions
 * before slot reuse and releases their leases. Callbacks must not destroy
 * channels or recursively enter this helper. */
int service_channels_wait(int, struct service_channel_slot *, size_t, int, int);
__END_DECLS
#endif
