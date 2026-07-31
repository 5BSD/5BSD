/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <ucl.h>

#include <notifycmp.h>

#include "policy.h"

static int
parse_topics(const ucl_object_t *root, const char *key,
    struct notifycmp_policy_topic topics[static NOTIFYCMP_POLICY_TOPIC_MAX],
    size_t *count, bool *all)
{
	const ucl_object_t *array, *entry;
	ucl_object_iter_t iterator;
	const char *name;
	size_t length;

	array = ucl_object_lookup(root, key);
	if (array == NULL)
		return (0);
	if (ucl_object_type(array) != UCL_ARRAY) {
		errno = EINVAL;
		return (-1);
	}
	iterator = NULL;
	while ((entry = ucl_object_iterate(array, &iterator, true)) != NULL) {
		if (ucl_object_type(entry) != UCL_STRING ||
		    *count == NOTIFYCMP_POLICY_TOPIC_MAX) {
			errno = EINVAL;
			return (-1);
		}
		name = ucl_object_tostring(entry);
		length = strlen(name);
		if (strcmp(name, "*") == 0) {
			if (*all || *count != 0) {
				errno = EINVAL;
				return (-1);
			}
			*all = true;
			continue;
		}
		if (*all || notifycmp_validate_topic(name, length) == -1)
			return (-1);
		for (size_t i = 0; i < *count; i++)
			if (topics[i].length == length &&
			    memcmp(topics[i].name, name, length) == 0) {
				errno = EEXIST;
				return (-1);
			}
		topics[*count].length = length;
		memcpy(topics[*count].name, name, length);
		(*count)++;
	}
	return (0);
}

int
notifycmp_policy_parse(const char *json, struct notifycmp_policy *policy)
{
	static const char *const names[] = {
		"publish", "subscribe", "timers"
	};
	const ucl_object_t *entry, *timers;
	ucl_object_t *root;
	struct ucl_parser *parser;
	ucl_object_iter_t iterator;
	const char *key;
	size_t i;
	int error;

	if (json == NULL || policy == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(policy, 0, sizeof(*policy));
	parser = ucl_parser_new(0);
	if (parser == NULL)
		return (-1);
	if (!ucl_parser_add_string(parser, json, strlen(json))) {
		errno = EINVAL;
		goto fail;
	}
	root = ucl_parser_get_object(parser);
	if (root == NULL || ucl_object_type(root) != UCL_OBJECT) {
		errno = EINVAL;
		goto fail;
	}
	iterator = NULL;
	while ((entry = ucl_object_iterate(root, &iterator, true)) != NULL) {
		key = ucl_object_key(entry);
		for (i = 0; i < nitems(names); i++)
			if (strcmp(key, names[i]) == 0)
				break;
		if (i == nitems(names)) {
			errno = EINVAL;
			goto fail_root;
		}
	}
	timers = ucl_object_lookup(root, "timers");
	if (timers != NULL) {
		if (ucl_object_type(timers) != UCL_BOOLEAN) {
			errno = EINVAL;
			goto fail_root;
		}
		policy->timers = ucl_object_toboolean(timers);
	}
	if (parse_topics(root, "publish", policy->publish, &policy->npublish,
	    &policy->publish_all) == -1 ||
	    parse_topics(root, "subscribe", policy->subscribe,
	    &policy->nsubscribe, &policy->subscribe_all) == -1)
		goto fail_root;
	ucl_object_unref(root);
	ucl_parser_free(parser);
	return (0);

fail_root:
	error = errno;
	ucl_object_unref(root);
	errno = error;
fail:
	error = errno;
	ucl_parser_free(parser);
	errno = error;
	return (-1);
}

static bool
topic_allowed(const struct notifycmp_policy_topic *topics, size_t count,
    bool all, const char *topic, size_t length)
{
	size_t i;

	if (all)
		return (true);
	for (i = 0; i < count; i++)
		if (topics[i].length == length &&
		    memcmp(topics[i].name, topic, length) == 0)
			return (true);
	return (false);
}

bool
notifycmp_policy_can_publish(const struct notifycmp_policy *policy,
    const char *topic, size_t length)
{

	return (policy != NULL && topic_allowed(policy->publish,
	    policy->npublish, policy->publish_all, topic, length));
}

bool
notifycmp_policy_can_subscribe(const struct notifycmp_policy *policy,
    const char *topic, size_t length)
{

	return (policy != NULL && topic_allowed(policy->subscribe,
	    policy->nsubscribe, policy->subscribe_all, topic, length));
}
