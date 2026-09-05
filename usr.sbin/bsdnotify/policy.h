/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NOTIFY_POLICY_H_
#define	_NOTIFY_POLICY_H_

#include <stdbool.h>
#include <stddef.h>

#include <notify_protocol.h>

#define	NOTIFY_POLICY_TOPIC_MAX	NOTIFY_MAX_SUBSCRIPTIONS
#define	NOTIFY_POLICY_CLIENT_MAX	256
#define	NOTIFY_POLICY_FILE_MAX	(64 * 1024)

struct notify_policy_topic {
	size_t	length;
	char	name[NOTIFY_MAX_TOPIC];
};

struct notify_policy {
	struct notify_policy_topic
	    publish[NOTIFY_POLICY_TOPIC_MAX];
	struct notify_policy_topic
	    subscribe[NOTIFY_POLICY_TOPIC_MAX];
	size_t	npublish;
	size_t	nsubscribe;
	bool	publish_all;
	bool	subscribe_all;
	bool	timers;
};

struct notify_policy_client {
	char	label[NOTIFY_MAX_PUBLISHER + 1];
	struct notify_policy policy;
};

struct notify_policy_db {
	struct notify_policy_client clients[NOTIFY_POLICY_CLIENT_MAX];
	size_t nclients;
};

int	notify_policy_parse(const char *, struct notify_policy *);
int	notify_policy_db_parse(const char *, struct notify_policy_db *);
int	notify_policy_db_load(const char *, struct notify_policy_db *);
int	notify_policy_db_load_fd(int, struct notify_policy_db *);
const struct notify_policy *notify_policy_db_lookup(
	    const struct notify_policy_db *, const char *);
bool	notify_policy_can_publish(const struct notify_policy *,
	    const char *, size_t);
bool	notify_policy_can_subscribe(const struct notify_policy *,
	    const char *, size_t);

#endif
