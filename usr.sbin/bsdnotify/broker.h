/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NOTIFY_BROKER_H_
#define	_NOTIFY_BROKER_H_

#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>

#include <notify.h>
#include <notify_server.h>

struct notify_broker;
struct notify_broker_client;

struct notify_broker *notify_broker_create(void);
void	notify_broker_destroy(struct notify_broker *);
struct notify_broker_client *notify_broker_add(
	    struct notify_broker *, const char *, size_t);
void	notify_broker_remove(struct notify_broker *,
	    struct notify_broker_client *);
int	notify_broker_subscribe(struct notify_broker *,
	    struct notify_broker_client *, const char *, size_t);
int	notify_broker_unsubscribe(struct notify_broker *,
	    struct notify_broker_client *, const char *, size_t);
int	notify_broker_publish(struct notify_broker *,
	    struct notify_broker_client *, const char *, size_t,
	    const void *, size_t);
int	notify_broker_state_set(struct notify_broker *,
	    struct notify_broker_client *, const char *, size_t, uint64_t,
	    struct notify_state_reply *);
int	notify_broker_state_get(struct notify_broker *, const char *,
	    size_t, struct notify_state_reply *);
int	notify_broker_state_clear(struct notify_broker *,
	    struct notify_broker_client *, const char *, size_t);
uint64_t notify_broker_epoch(const struct notify_broker *);
void	notify_broker_test_set_sequence(struct notify_broker *, uint64_t);
int	notify_broker_timer(struct notify_broker *,
	    struct notify_broker_client *, uint64_t);
ssize_t	notify_broker_next(struct notify_broker_client *,
	    struct notify_event *, size_t);
void	notify_broker_stats(const struct notify_broker_client *,
	    struct notify_stats *);

#endif
