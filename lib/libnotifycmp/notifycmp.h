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
void	notifycmp_client_close(struct notifycmp_client *);
int	notifycmp_subscribe(struct notifycmp_client *, const char *);
int	notifycmp_unsubscribe(struct notifycmp_client *, const char *);
int	notifycmp_publish(struct notifycmp_client *, const char *,
	    const void *, size_t);
ssize_t	notifycmp_next(struct notifycmp_client *, struct notifycmp_event *,
	    size_t, uint32_t);
int	notifycmp_timer_add(struct notifycmp_client *, uint64_t, uint32_t,
	    uint32_t);
int	notifycmp_timer_cancel(struct notifycmp_client *, uint64_t);
int	notifycmp_stats(struct notifycmp_client *, struct notifycmp_stats *);
int	notifycmp_validate_topic(const char *, size_t);
int	notifycmp_validate_message(const struct notifycmp_msg *, size_t,
	    enum notifycmp_message_role);
int	notifycmp_message_init(struct notifycmp_msg *, uint16_t, uint32_t);
int	notifycmp_message_init_reply(struct notifycmp_msg *,
	    const struct notifycmp_msg *, int);
__END_DECLS

#endif
