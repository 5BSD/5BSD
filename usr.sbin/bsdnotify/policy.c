/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ucl.h>

#include <notify.h>
#include <notify_server.h>

#include "policy.h"

static bool
valid_client_label(const char *label, size_t length)
{
	bool separator;
	size_t i;
	unsigned char character;

	if (label == NULL || length < 3 || length > NOTIFY_MAX_PUBLISHER ||
	    label[0] == '/' || label[length - 1] == '/')
		return (false);
	separator = false;
	for (i = 0; i < length; i++) {
		character = (unsigned char)label[i];
		if (character == '/') {
			if (i != 0 && label[i - 1] == '/')
				return (false);
			separator = true;
			continue;
		}
		if (!((character >= 'a' && character <= 'z') ||
		    (character >= 'A' && character <= 'Z') ||
		    (character >= '0' && character <= '9') || character == '.' ||
		    character == '_' || character == '-'))
			return (false);
	}
	return (separator);
}

static int
parse_topics(const ucl_object_t *root, const char *key,
    struct notify_policy_topic topics[static NOTIFY_POLICY_TOPIC_MAX],
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
		    *count == NOTIFY_POLICY_TOPIC_MAX) {
			errno = EINVAL;
			return (-1);
		}
		name = ucl_object_tostring(entry);
		if (name == NULL) {
			errno = EINVAL;
			return (-1);
		}
		length = strlen(name);
		if (strcmp(name, "*") == 0) {
			if (*all || *count != 0) {
				errno = EINVAL;
				return (-1);
			}
			*all = true;
			continue;
		}
		if (*all || notify_validate_topic(name, length) == -1)
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
notify_policy_parse(const char *json, struct notify_policy *policy)
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
		if (key == NULL) {
			errno = EINVAL;
			goto fail_root;
		}
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
topic_allowed(const struct notify_policy_topic *topics, size_t count,
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
notify_policy_can_publish(const struct notify_policy *policy,
    const char *topic, size_t length)
{

	return (policy != NULL && topic_allowed(policy->publish,
	    policy->npublish, policy->publish_all, topic, length));
}

bool
notify_policy_can_subscribe(const struct notify_policy *policy,
    const char *topic, size_t length)
{

	return (policy != NULL && topic_allowed(policy->subscribe,
	    policy->nsubscribe, policy->subscribe_all, topic, length));
}

static int
policy_db_from_root(const ucl_object_t *root, struct notify_policy_db *db)
{
	const ucl_object_t *clients, *entry, *top;
	ucl_object_iter_t iterator;
	char *encoded;
	const char *label;
	size_t length;

	if (root == NULL || ucl_object_type(root) != UCL_OBJECT ||
	    ucl_object_lookup(root, "clients") == NULL) {
		errno = EINVAL;
		return (-1);
	}
	iterator = NULL;
	while ((top = ucl_object_iterate(root, &iterator, true)) != NULL) {
		const char *key = ucl_object_key(top);

		if (key == NULL || strcmp(key, "clients") != 0) {
			errno = EINVAL;
			return (-1);
		}
	}
	clients = ucl_object_lookup(root, "clients");
	if (ucl_object_type(clients) != UCL_OBJECT) {
		errno = EINVAL;
		return (-1);
	}
	iterator = NULL;
	while ((entry = ucl_object_iterate(clients, &iterator, true)) != NULL) {
		if (db->nclients == NOTIFY_POLICY_CLIENT_MAX ||
		    ucl_object_type(entry) != UCL_OBJECT) {
			errno = E2BIG;
			return (-1);
		}
		label = ucl_object_key(entry);
		length = label != NULL ? strlen(label) : 0;
		if (!valid_client_label(label, length)) {
			errno = EINVAL;
			return (-1);
		}
		if (notify_policy_db_lookup(db, label) != NULL) {
			errno = EEXIST;
			return (-1);
		}
		encoded = ucl_object_emit(entry, UCL_EMIT_JSON_COMPACT);
		if (encoded == NULL)
			return (-1);
		if (notify_policy_parse(encoded,
		    &db->clients[db->nclients].policy) == -1) {
			free(encoded);
			return (-1);
		}
		free(encoded);
		memcpy(db->clients[db->nclients].label, label, length + 1);
		db->nclients++;
	}
	return (0);
}

int
notify_policy_db_parse(const char *text, struct notify_policy_db *db)
{
	struct ucl_parser *parser;
	ucl_object_t *root;
	int error, result;

	if (text == NULL || db == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(db, 0, sizeof(*db));
	parser = ucl_parser_new(0);
	if (parser == NULL)
		return (-1);
	if (!ucl_parser_add_string(parser, text, strlen(text))) {
		errno = EINVAL;
		goto fail;
	}
	root = ucl_parser_get_object(parser);
	result = policy_db_from_root(root, db);
	error = result == -1 ? (errno != 0 ? errno : EINVAL) : 0;
	ucl_object_unref(root);
	ucl_parser_free(parser);
	errno = error;
	return (result);
fail:
	error = errno;
	ucl_parser_free(parser);
	errno = error;
	return (-1);
}

int
notify_policy_db_load(const char *path, struct notify_policy_db *db)
{
	int fd;

	if (path == NULL || db == NULL) {
		errno = EINVAL;
		return (-1);
	}
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1)
		return (-1);
	return (notify_policy_db_load_fd(fd, db));
}

/*
 * Load the policy from an already-open descriptor (takes ownership; closes it).
 * A born-in-capmode daemon gets this fd from service_config_open(3) over the
 * serviced-delivered Config directory, never a global path.
 */
int
notify_policy_db_load_fd(int fd, struct notify_policy_db *db)
{
	struct stat status;
	char *text;
	ssize_t amount;
	size_t done;
	int error, result;

	if (fd < 0 || db == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (fstat(fd, &status) == -1)
		goto fail;
	if (!S_ISREG(status.st_mode)) {
		errno = EINVAL;
		goto fail;
	}
	if (status.st_uid != 0 && status.st_uid != geteuid()) {
		errno = EPERM;
		goto fail;
	}
	if ((status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
		errno = EPERM;
		goto fail;
	}
	if (status.st_size < 0 || status.st_size > NOTIFY_POLICY_FILE_MAX) {
		errno = EFBIG;
		goto fail;
	}
	text = malloc(NOTIFY_POLICY_FILE_MAX + 2);
	if (text == NULL)
		goto fail;
	done = 0;
	for (;;) {
		amount = read(fd, text + done,
		    NOTIFY_POLICY_FILE_MAX + 1 - done);
		if (amount == -1 && errno == EINTR)
			continue;
		if (amount == -1)
			goto fail_text;
		if (amount == 0)
			break;
		done += (size_t)amount;
		if (done > NOTIFY_POLICY_FILE_MAX) {
			errno = EFBIG;
			goto fail_text;
		}
	}
	close(fd);
	if (memchr(text, '\0', done) != NULL) {
		errno = EINVAL;
		goto fail_text_closed;
	}
	text[done] = '\0';
	result = notify_policy_db_parse(text, db);
	error = result == -1 ? errno : 0;
	free(text);
	errno = error;
	return (result);

fail_text:
	error = errno != 0 ? errno : EIO;
	free(text);
	close(fd);
	errno = error;
	return (-1);
fail_text_closed:
	error = errno;
	free(text);
	errno = error;
	return (-1);
fail:
	error = errno != 0 ? errno : EIO;
	close(fd);
	errno = error;
	return (-1);
}

const struct notify_policy *
notify_policy_db_lookup(const struct notify_policy_db *db,
    const char *label)
{
	size_t i;

	if (db == NULL || label == NULL)
		return (NULL);
	for (i = 0; i < db->nclients; i++)
		if (strcmp(db->clients[i].label, label) == 0)
			return (&db->clients[i].policy);
	return (NULL);
}
