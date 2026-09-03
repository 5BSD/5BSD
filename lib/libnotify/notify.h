/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NOTIFY_H_
#define	_NOTIFY_H_

#include <sys/types.h>

#include <stddef.h>

#include "notify_protocol.h"

struct notify_client;

__BEGIN_DECLS
int	notify_client_open(struct notify_client **);
/* Consumes fd on every call with a valid fd and result pointer. */
int	notify_client_adopt(int, struct notify_client **);
void	notify_client_close(struct notify_client *);
int	notify_subscribe(struct notify_client *, const char *);
int	notify_unsubscribe(struct notify_client *, const char *);
int	notify_publish(struct notify_client *, const char *,
	    const void *, size_t);
int	notify_state_set(struct notify_client *, const char *, uint64_t);
int	notify_state_get(struct notify_client *, const char *,
	    struct notify_state_reply *);
int	notify_state_clear(struct notify_client *, const char *);
ssize_t	notify_next(struct notify_client *, struct notify_event *,
	    size_t, uint32_t);
int	notify_timer_add(struct notify_client *, uint64_t, uint32_t,
	    uint32_t);
int	notify_timer_cancel(struct notify_client *, uint64_t);
int	notify_stats(struct notify_client *, struct notify_stats *);
__END_DECLS

#endif
