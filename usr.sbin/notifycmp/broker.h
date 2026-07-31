/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NOTIFYCMP_BROKER_H_
#define	_NOTIFYCMP_BROKER_H_

#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>

#include <notifycmp.h>

struct notifycmp_broker;
struct notifycmp_broker_client;

struct notifycmp_broker *notifycmp_broker_create(void);
void	notifycmp_broker_destroy(struct notifycmp_broker *);
struct notifycmp_broker_client *notifycmp_broker_add(
	    struct notifycmp_broker *, const char *, size_t);
void	notifycmp_broker_remove(struct notifycmp_broker *,
	    struct notifycmp_broker_client *);
int	notifycmp_broker_subscribe(struct notifycmp_broker *,
	    struct notifycmp_broker_client *, const char *, size_t);
int	notifycmp_broker_unsubscribe(struct notifycmp_broker *,
	    struct notifycmp_broker_client *, const char *, size_t);
int	notifycmp_broker_publish(struct notifycmp_broker *,
	    struct notifycmp_broker_client *, const char *, size_t,
	    const void *, size_t);
int	notifycmp_broker_timer(struct notifycmp_broker *,
	    struct notifycmp_broker_client *, uint64_t);
ssize_t	notifycmp_broker_next(struct notifycmp_broker_client *,
	    struct notifycmp_event *, size_t);
void	notifycmp_broker_stats(const struct notifycmp_broker_client *,
	    struct notifycmp_stats *);

#endif
