/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NOTIFYCMP_POLICY_H_
#define	_NOTIFYCMP_POLICY_H_

#include <stdbool.h>
#include <stddef.h>

#include <notifycmp_protocol.h>

#define	NOTIFYCMP_POLICY_TOPIC_MAX	NOTIFYCMP_MAX_SUBSCRIPTIONS

struct notifycmp_policy_topic {
	size_t	length;
	char	name[NOTIFYCMP_MAX_TOPIC];
};

struct notifycmp_policy {
	struct notifycmp_policy_topic
	    publish[NOTIFYCMP_POLICY_TOPIC_MAX];
	struct notifycmp_policy_topic
	    subscribe[NOTIFYCMP_POLICY_TOPIC_MAX];
	size_t	npublish;
	size_t	nsubscribe;
	bool	publish_all;
	bool	subscribe_all;
	bool	timers;
};

int	notifycmp_policy_parse(const char *, struct notifycmp_policy *);
bool	notifycmp_policy_can_publish(const struct notifycmp_policy *,
	    const char *, size_t);
bool	notifycmp_policy_can_subscribe(const struct notifycmp_policy *,
	    const char *, size_t);

#endif
