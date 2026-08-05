/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NOTIFYCMP_POLICY_H_
#define	_NOTIFYCMP_POLICY_H_

#include <stdbool.h>
#include <stddef.h>

#include <notifycmp_protocol.h>

#define	NOTIFYCMP_POLICY_TOPIC_MAX	NOTIFYCMP_MAX_SUBSCRIPTIONS
#define	NOTIFYCMP_POLICY_CLIENT_MAX	256
#define	NOTIFYCMP_POLICY_FILE_MAX	(64 * 1024)

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

struct notifycmp_policy_client {
	char	label[NOTIFYCMP_MAX_PUBLISHER + 1];
	struct notifycmp_policy policy;
};

struct notifycmp_policy_db {
	struct notifycmp_policy_client clients[NOTIFYCMP_POLICY_CLIENT_MAX];
	size_t nclients;
};

int	notifycmp_policy_parse(const char *, struct notifycmp_policy *);
int	notifycmp_policy_db_parse(const char *, struct notifycmp_policy_db *);
int	notifycmp_policy_db_load(const char *, struct notifycmp_policy_db *);
const struct notifycmp_policy *notifycmp_policy_db_lookup(
	    const struct notifycmp_policy_db *, const char *);
bool	notifycmp_policy_can_publish(const struct notifycmp_policy *,
	    const char *, size_t);
bool	notifycmp_policy_can_subscribe(const struct notifycmp_policy *,
	    const char *, size_t);

#endif
