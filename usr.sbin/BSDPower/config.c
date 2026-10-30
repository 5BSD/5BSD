/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * BSDPower per-label policy: which labels may suspend the machine.  The policy is a
 * bounded data-only input; unknown or ambiguous grants reject the whole file.
 */
#include <sys/stat.h>
#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ucl.h>

#include "config.h"

void
powercmp_config_defaults(struct powercmp_config *config)
{

	memset(config, 0, sizeof(*config));
	config->default_suspend = false;	/* deny by default */
	config->nclients = 0;
}

static bool
valid_label(const char *label, size_t length)
{
	size_t i;
	unsigned char c;

	if (label == NULL || length == 0 || length > POWERCMP_CONFIG_LABEL_MAX)
		return (false);
	for (i = 0; i < length; i++) {
		c = (unsigned char)label[i];
		if (!(c == '.' || c == '-' || c == '_' ||
		    (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
		    (c >= 'A' && c <= 'Z')))
			return (false);
	}
	return (true);
}

/* Validate length-delimited keys before any C-string lookup. */
static bool
valid_keys(const ucl_object_t *obj, const char *const *keys, size_t count)
{
	const ucl_object_t *entry;
	ucl_object_iter_t it = NULL;
	size_t i;

	if (obj == NULL || ucl_object_type(obj) != UCL_OBJECT)
		return (false);
	while ((entry = ucl_object_iterate(obj, &it, true)) != NULL) {
		if (entry->key == NULL || strlen(entry->key) != entry->keylen ||
		    entry->next != NULL)
			return (false);
		for (i = 0; i < count; i++)
			if (strcmp(entry->key, keys[i]) == 0)
				break;
		if (i == count)
			return (false);
	}
	return (true);
}

static bool
valid_permissions(const ucl_object_t *obj)
{
	static const char *const keys[] = { "suspend", "inhibit" };
	const ucl_object_t *entry;
	ucl_object_iter_t it = NULL;

	if (!valid_keys(obj, keys, sizeof(keys) / sizeof(keys[0])))
		return (false);
	while ((entry = ucl_object_iterate(obj, &it, true)) != NULL)
		if (ucl_object_type(entry) != UCL_BOOLEAN)
			return (false);
	return (true);
}

/* Called only after validating the entire permission object. */
static bool
object_set_flag(const ucl_object_t *obj, const char *key)
{
	const ucl_object_t *v;

	v = ucl_object_lookup(obj, key);
	return (v != NULL && ucl_object_toboolean(v));
}

static int
config_parse(const char *text, struct powercmp_config *config)
{
	static const char *const keys[] = { "default", "clients" };
	struct ucl_parser *parser;
	const ucl_object_t *root, *def, *clients, *entry;
	ucl_object_iter_t it;
	const char *label;
	size_t label_len;
	int result;

	parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_IMPLICIT_ARRAYS);
	if (parser == NULL)
		return (errno = ENOMEM, -1);
	result = -1;
	if (!ucl_parser_add_chunk_full(parser, (const unsigned char *)text,
	    strlen(text), 0, UCL_DUPLICATE_ERROR, UCL_PARSE_UCL) ||
	    ucl_parser_get_error(parser) != NULL)
		goto out;
	root = ucl_parser_get_object(parser);
	if (!valid_keys(root, keys, sizeof(keys) / sizeof(keys[0])))
		goto out_root;

	def = ucl_object_lookup(root, "default");
	if (def != NULL) {
		if (!valid_permissions(def))
			goto out_root;
		config->default_suspend = object_set_flag(def, "suspend");
		config->default_inhibit = object_set_flag(def, "inhibit");
	}

	clients = ucl_object_lookup(root, "clients");
	if (clients != NULL) {
		if (ucl_object_type(clients) != UCL_OBJECT)
			goto out_root;
		it = NULL;
		while ((entry = ucl_object_iterate(clients, &it, true)) != NULL) {
			if (entry->next != NULL || !valid_permissions(entry))
				goto out_root;
			label = ucl_object_key(entry);
			label_len = entry->keylen;
			if (!valid_label(label, label_len) ||
			    config->nclients >= POWERCMP_MAX_CLIENTS)
				goto out_root;
			(void)strlcpy(config->clients[config->nclients].label,
			    label, sizeof(config->clients[0].label));
			config->clients[config->nclients].may_suspend =
			    object_set_flag(entry, "suspend");
			config->clients[config->nclients].may_inhibit =
			    object_set_flag(entry, "inhibit");
			config->nclients++;
		}
	}
	result = 0;
out_root:
	ucl_object_unref(__DECONST(ucl_object_t *, root));
out:
	ucl_parser_free(parser);
	if (result == -1)
		errno = EINVAL;
	return (result);
}

int
powercmp_config_load_fd(struct powercmp_config *config, int fd)
{
	struct stat status, after;
	struct powercmp_config candidate;
	char *text;
	ssize_t amount;
	size_t done;
	int error, result;

	if (config == NULL) {
		if (fd >= 0)
			(void)close(fd);
		return (errno = EINVAL, -1);
	}
	powercmp_config_defaults(config);
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
	if (status.st_size < 0 || status.st_size > POWERCMP_CONFIG_FILE_MAX) {
		errno = EFBIG;
		goto fail;
	}
	text = malloc(POWERCMP_CONFIG_FILE_MAX + 2);
	if (text == NULL)
		goto fail;
	done = 0;
	for (;;) {
		amount = pread(fd, text + done,
		    POWERCMP_CONFIG_FILE_MAX + 1 - done, (off_t)done);
		if (amount == -1 && errno == EINTR)
			continue;
		if (amount == -1)
			goto fail_text;
		if (amount == 0)
			break;
		done += (size_t)amount;
		if (done > POWERCMP_CONFIG_FILE_MAX) {
			errno = EFBIG;
			goto fail_text;
		}
	}
	if (fstat(fd, &after) == -1)
		goto fail_text;
	if (done != (size_t)status.st_size || after.st_size != status.st_size ||
	    after.st_mode != status.st_mode || after.st_uid != status.st_uid ||
	    after.st_gid != status.st_gid ||
	    timespeccmp(&after.st_mtim, &status.st_mtim, !=) ||
	    timespeccmp(&after.st_ctim, &status.st_ctim, !=)) {
		errno = EINVAL;
		goto fail_text;
	}
	(void)close(fd);
	fd = -1;
	if (memchr(text, '\0', done) != NULL) {
		errno = EINVAL;
		goto fail_text;
	}
	text[done] = '\0';
	powercmp_config_defaults(&candidate);
	result = config_parse(text, &candidate);
	error = result == -1 ? errno : 0;
	free(text);
	if (result == -1) {
		powercmp_config_defaults(config);
		return (errno = error, -1);
	}
	*config = candidate;
	return (0);
fail_text:
	error = errno;
	free(text);
	if (fd >= 0)
		(void)close(fd);
	powercmp_config_defaults(config);
	return (errno = error, -1);
fail:
	error = errno;
	if (fd >= 0)
		(void)close(fd);
	powercmp_config_defaults(config);
	return (errno = error, -1);
}

int
powercmp_config_load(struct powercmp_config *config, const char *path)
{
	int fd;

	if (config == NULL)
		return (errno = EINVAL, -1);
	powercmp_config_defaults(config);
	if (path == NULL)
		return (errno = EINVAL, -1);
	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
	if (fd == -1) {
		powercmp_config_defaults(config);
		return (errno == ENOENT ? 0 : -1);
	}
	return (powercmp_config_load_fd(config, fd));
}

bool
powercmp_config_permits_suspend(const struct powercmp_config *config,
    const char *label)
{
	size_t i;

	if (config == NULL || label == NULL || label[0] == '\0')
		return (false);
	for (i = 0; i < config->nclients; i++)
		if (strcmp(config->clients[i].label, label) == 0)
			return (config->clients[i].may_suspend);
	return (config->default_suspend);
}

bool
powercmp_config_permits_inhibit(const struct powercmp_config *config,
    const char *label)
{
	size_t i;
	if (config == NULL || label == NULL || label[0] == '\0')
		return (false);
	for (i = 0; i < config->nclients; i++)
		if (strcmp(config->clients[i].label, label) == 0)
			return (config->clients[i].may_inhibit);
	return (config->default_inhibit);
}
