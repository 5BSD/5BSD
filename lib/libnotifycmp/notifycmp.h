/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NOTIFYCMP_H_
#define	_NOTIFYCMP_H_

#include <sys/types.h>

#include <stddef.h>

#include "notifycmp_protocol.h"

struct notifycmp_client;

__BEGIN_DECLS
int	notifycmp_client_open(struct notifycmp_client **);
/* Consumes fd on every call with a valid fd and result pointer. */
int	notifycmp_client_adopt(int, struct notifycmp_client **);
void	notifycmp_client_close(struct notifycmp_client *);
int	notifycmp_subscribe(struct notifycmp_client *, const char *);
int	notifycmp_unsubscribe(struct notifycmp_client *, const char *);
int	notifycmp_publish(struct notifycmp_client *, const char *,
	    const void *, size_t);
int	notifycmp_state_set(struct notifycmp_client *, const char *, uint64_t);
int	notifycmp_state_get(struct notifycmp_client *, const char *,
	    struct notifycmp_state_reply *);
ssize_t	notifycmp_next(struct notifycmp_client *, struct notifycmp_event *,
	    size_t, uint32_t);
int	notifycmp_timer_add(struct notifycmp_client *, uint64_t, uint32_t,
	    uint32_t);
int	notifycmp_timer_cancel(struct notifycmp_client *, uint64_t);
int	notifycmp_stats(struct notifycmp_client *, struct notifycmp_stats *);
__END_DECLS

#endif
