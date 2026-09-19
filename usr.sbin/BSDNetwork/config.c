/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
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

#include "config.h"

void
networkcmp_config_defaults(struct networkcmp_config *config)
{

	memset(config, 0, sizeof(*config));
	/*
	 * The historical effective non-admin grant: outbound resolve, TCP
	 * connect, and connected UDP over both address families, internal
	 * destination ranges denied (the N2 SSRF default stands).
	 */
	config->default_policy.ipv4 = true;
	config->default_policy.ipv6 = true;
	config->default_policy.allow_connect = true;
	config->default_policy.allow_udp = true;
	config->default_policy.resolve = true;
	config->default_policy.allow_internal = false;
	config->default_policy.max_results = 16;
}

static bool
valid_client_label(const char *label, size_t length)
{
	size_t i;
	unsigned char character;

	if (label == NULL || length == 0 ||
	    length > NETWORKCMP_CONFIG_LABEL_MAX)
		return (false);
	for (i = 0; i < length; i++) {
		character = (unsigned char)label[i];
		if (!((character >= 'a' && character <= 'z') ||
		    (character >= 'A' && character <= 'Z') ||
		    (character >= '0' && character <= '9') ||
		    character == '.' || character == '_' ||
		    character == '-' || character == '/'))
			return (false);
	}
	return (true);
}

/*
 * Apply one policy object onto *policy, which arrives holding the values it
 * inherits (the default policy for a clients{} entry; the compiled-in default
 * for the default{} block itself).  The schema is closed: every key must be
 * one of the known policy dimensions and every value must be a boolean.
 */
static int
parse_policy_object(const ucl_object_t *object,
    struct networkcmp_policy *policy)
{
	static const struct {
		const char	*key;
		size_t		 offset;
	} dimensions[] = {
		{ "resolve",	offsetof(struct networkcmp_policy, resolve) },
		{ "connect",	offsetof(struct networkcmp_policy,
				    allow_connect) },
		{ "udp",	offsetof(struct networkcmp_policy, allow_udp) },
		{ "inet4",	offsetof(struct networkcmp_policy, ipv4) },
		{ "inet6",	offsetof(struct networkcmp_policy, ipv6) },
		{ "internal",	offsetof(struct networkcmp_policy,
				    allow_internal) },
	};
	const ucl_object_t *entry;
	ucl_object_iter_t iterator;
	const char *key;
	size_t i;

	if (ucl_object_type(object) != UCL_OBJECT) {
		errno = EINVAL;
		return (-1);
	}
	iterator = NULL;
	while ((entry = ucl_object_iterate(object, &iterator, true)) != NULL) {
		key = ucl_object_key(entry);
		/* A chained value means the key appears more than once. */
		if (key == NULL || entry->next != NULL) {
			errno = EINVAL;
			return (-1);
		}
		for (i = 0; i < nitems(dimensions); i++)
			if (strcmp(key, dimensions[i].key) == 0)
				break;
		if (i == nitems(dimensions) ||
		    ucl_object_type(entry) != UCL_BOOLEAN) {
			errno = EINVAL;
			return (-1);
		}
		*(bool *)(void *)((char *)policy + dimensions[i].offset) =
		    ucl_object_toboolean(entry);
	}
	/* The resolve result ceiling follows the resolve dimension. */
	policy->max_results = policy->resolve ? 16 : 0;
	return (0);
}

static int
config_from_root(const ucl_object_t *root, struct networkcmp_config *config)
{
	const ucl_object_t *clients, *defaults, *entry, *top;
	ucl_object_iter_t iterator;
	const char *label;
	size_t length;
	bool listed;

	if (root == NULL || ucl_object_type(root) != UCL_OBJECT) {
		errno = EINVAL;
		return (-1);
	}
	/* Closed top-level schema: only "default" and "clients". */
	iterator = NULL;
	while ((top = ucl_object_iterate(root, &iterator, true)) != NULL) {
		const char *key = ucl_object_key(top);

		if (key == NULL || top->next != NULL ||
		    (strcmp(key, "default") != 0 &&
		    strcmp(key, "clients") != 0)) {
			errno = EINVAL;
			return (-1);
		}
	}
	defaults = ucl_object_lookup(root, "default");
	if (defaults != NULL &&
	    parse_policy_object(defaults, &config->default_policy) == -1)
		return (-1);
	clients = ucl_object_lookup(root, "clients");
	if (clients == NULL)
		return (0);
	if (ucl_object_type(clients) != UCL_OBJECT) {
		errno = EINVAL;
		return (-1);
	}
	iterator = NULL;
	while ((entry = ucl_object_iterate(clients, &iterator, true)) != NULL) {
		if (config->nclients == NETWORKCMP_CONFIG_CLIENT_MAX) {
			errno = E2BIG;
			return (-1);
		}
		label = ucl_object_key(entry);
		length = label != NULL ? strlen(label) : 0;
		if (!valid_client_label(label, length)) {
			errno = EINVAL;
			return (-1);
		}
		/*
		 * Duplicate labels are malformed.  libucl chains repeated keys
		 * onto entry->next rather than yielding them separately, so
		 * check the chain as well as the accumulated table.
		 */
		(void)networkcmp_config_lookup(config, label, &listed);
		if (listed || entry->next != NULL) {
			errno = EEXIST;
			return (-1);
		}
		/* Unspecified dimensions inherit from the default policy. */
		config->clients[config->nclients].policy =
		    config->default_policy;
		if (parse_policy_object(entry,
		    &config->clients[config->nclients].policy) == -1)
			return (-1);
		memcpy(config->clients[config->nclients].label, label,
		    length + 1);
		config->nclients++;
	}
	return (0);
}

int
networkcmp_config_parse(const char *text, struct networkcmp_config *config)
{
	struct ucl_parser *parser;
	ucl_object_t *root;
	int error, result;

	if (text == NULL || config == NULL) {
		errno = EINVAL;
		return (-1);
	}
	networkcmp_config_defaults(config);
	parser = ucl_parser_new(0);
	if (parser == NULL)
		return (-1);
	if (!ucl_parser_add_string(parser, text, strlen(text))) {
		ucl_parser_free(parser);
		errno = EINVAL;
		return (-1);
	}
	root = ucl_parser_get_object(parser);
	result = config_from_root(root, config);
	error = result == -1 ? (errno != 0 ? errno : EINVAL) : 0;
	ucl_object_unref(root);
	ucl_parser_free(parser);
	if (result == -1) {
		/* A partial parse must never leak through (fail-soft). */
		networkcmp_config_defaults(config);
	}
	errno = error;
	return (result);
}

int
networkcmp_config_load_fd(struct networkcmp_config *config, int fd)
{
	struct stat status;
	char *text;
	ssize_t amount;
	size_t done;
	int error, result;

	if (config == NULL || fd < 0) {
		errno = EINVAL;
		return (-1);
	}
	networkcmp_config_defaults(config);
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
	if (status.st_size < 0 || status.st_size > NETWORKCMP_CONFIG_FILE_MAX) {
		errno = EFBIG;
		goto fail;
	}
	text = malloc(NETWORKCMP_CONFIG_FILE_MAX + 2);
	if (text == NULL)
		goto fail;
	done = 0;
	for (;;) {
		amount = read(fd, text + done,
		    NETWORKCMP_CONFIG_FILE_MAX + 1 - done);
		if (amount == -1 && errno == EINTR)
			continue;
		if (amount == -1)
			goto fail_text;
		if (amount == 0)
			break;
		done += (size_t)amount;
		if (done > NETWORKCMP_CONFIG_FILE_MAX) {
			errno = EFBIG;
			goto fail_text;
		}
	}
	close(fd);
	fd = -1;
	if (memchr(text, '\0', done) != NULL) {
		errno = EINVAL;
		goto fail_text;
	}
	text[done] = '\0';
	result = networkcmp_config_parse(text, config);
	error = result == -1 ? errno : 0;
	free(text);
	errno = error;
	return (result);

fail_text:
	error = errno != 0 ? errno : EIO;
	free(text);
	if (fd >= 0)
		close(fd);
	errno = error;
	return (-1);
fail:
	error = errno != 0 ? errno : EIO;
	close(fd);
	errno = error;
	return (-1);
}

int
networkcmp_config_load(struct networkcmp_config *config, const char *path)
{
	int fd;

	if (config == NULL || path == NULL) {
		errno = EINVAL;
		return (-1);
	}
	networkcmp_config_defaults(config);
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1) {
		/* A missing file is the shipped-defaults case, not an error. */
		if (errno == ENOENT)
			return (0);
		return (-1);
	}
	return (networkcmp_config_load_fd(config, fd));
}

const struct networkcmp_policy *
networkcmp_config_lookup(const struct networkcmp_config *config,
    const char *label, bool *listed)
{
	size_t i;

	if (listed != NULL)
		*listed = false;
	if (config == NULL)
		return (NULL);
	if (label != NULL)
		for (i = 0; i < config->nclients; i++)
			if (strcmp(config->clients[i].label, label) == 0) {
				if (listed != NULL)
					*listed = true;
				return (&config->clients[i].policy);
			}
	return (&config->default_policy);
}

int
networkcmp_config_session_policy(const struct networkcmp_config *config,
    const char *label, service_rights_t rights,
    struct networkcmp_policy *policy, const char **source)
{
	const struct networkcmp_policy *resolved;
	bool listed;

	if (config == NULL || policy == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (service_rights_allow(rights, SERVICE_RIGHTS_ADMIN)) {
		if (networkcmp_policy_from_rights(policy, rights) == -1)
			return (-1);
		if (source != NULL)
			*source = "admin";
		return (0);
	}
	resolved = networkcmp_config_lookup(config, label, &listed);
	*policy = *resolved;
	if (source != NULL)
		*source = listed ? "label" : "default";
	return (0);
}
