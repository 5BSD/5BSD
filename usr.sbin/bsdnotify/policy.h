/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NOTIFY_POLICY_H_
#define	_NOTIFY_POLICY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <notify_protocol.h>

#define	NOTIFY_POLICY_TOPIC_MAX	NOTIFY_MAX_SUBSCRIPTIONS
#define	NOTIFY_POLICY_CLIENT_MAX	256
#define	NOTIFY_POLICY_FILE_MAX	(64 * 1024)

/*
 * Tiers (docs/ipc-anointments-design.md, "bsdnotify").  Which tier a session
 * is on is decided by the endpoint it was accepted on, never by the client:
 *   open   = NOTIFY_INTERFACE        ("system.Notify"), resolvable by every
 *            session; policy from the conf "default {}" block.
 *   system = NOTIFY_SYSTEM_INTERFACE ("system.Notify.System"), gated by the
 *            "system.notify.system" anointment at switchboard; policy from
 *            "clients { <label> {} }" when the label is listed, else from
 *            "system_default {}".
 */
#define	NOTIFY_TIER_OPEN	0U
#define	NOTIFY_TIER_SYSTEM	1U

/*
 * One policy entry.  An exact topic matches only itself.  A prefix pattern
 * ("user.*" in the conf) is stored with prefix=true and name="user"; it
 * matches "user.x" and "user.x.y" but neither "user" nor "users.x".
 */
struct notify_policy_topic {
	size_t	length;		/* of name: the prefix part for patterns */
	bool	prefix;
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
	struct notify_policy open_default;	/* "default": open tier */
	struct notify_policy system_default;	/* "system_default": gated */
	bool	has_default;		/* block present in the file */
	bool	has_system_default;	/* block present in the file */
	struct notify_policy_client clients[NOTIFY_POLICY_CLIENT_MAX];
	size_t nclients;
};

int	notify_policy_parse(const char *, struct notify_policy *);
/* Compiled-in per-tier defaults used when the conf omits the block. */
void	notify_policy_builtin_open(struct notify_policy *);
void	notify_policy_builtin_system(struct notify_policy *);
int	notify_policy_db_parse(const char *, struct notify_policy_db *);
int	notify_policy_db_load(const char *, struct notify_policy_db *);
int	notify_policy_db_load_fd(int, struct notify_policy_db *);
const struct notify_policy *notify_policy_db_lookup(
	    const struct notify_policy_db *, const char *);
/*
 * The policy governing a session: tier NOTIFY_TIER_OPEN -> open_default,
 * ignoring clients{} entirely; NOTIFY_TIER_SYSTEM -> the clients{} entry for
 * label if present, else system_default.  NULL for an unknown tier.
 */
const struct notify_policy *notify_policy_db_select(
	    const struct notify_policy_db *, uint32_t tier, const char *label);
bool	notify_policy_can_publish(const struct notify_policy *,
	    const char *, size_t);
bool	notify_policy_can_subscribe(const struct notify_policy *,
	    const char *, size_t);

#endif
