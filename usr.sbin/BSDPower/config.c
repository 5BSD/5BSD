/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * BSDTime per-label policy: which labels may suspend the machine.  Mirrors the
 * hardened UCL load of the sibling providers (BSDSysctl/BSDNetwork).
 */
#include <sys/stat.h>

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

/* Read a boolean "set" member from a client/default object (absent => false). */
static bool
object_set_flag(const ucl_object_t *obj)
{
	const ucl_object_t *v;

	v = ucl_object_lookup(obj, "set");
	return (v != NULL && ucl_object_toboolean(v));
}

static int
config_parse(const char *text, struct powercmp_config *config)
{
	struct ucl_parser *parser;
	const ucl_object_t *root, *def, *clients, *entry;
	ucl_object_iter_t it;
	const char *label;
	size_t label_len;
	int result;

	parser = ucl_parser_new(0);
	if (parser == NULL)
		return (errno = ENOMEM, -1);
	result = -1;
	if (!ucl_parser_add_string(parser, text, strlen(text)) ||
	    ucl_parser_get_error(parser) != NULL)
		goto out;
	root = ucl_parser_get_object(parser);
	if (root == NULL || ucl_object_type(root) != UCL_OBJECT)
		goto out_root;

	def = ucl_object_lookup(root, "default");
	if (def != NULL) {
		if (ucl_object_type(def) != UCL_OBJECT)
			goto out_root;
		config->default_suspend = object_set_flag(def);
	}

	clients = ucl_object_lookup(root, "clients");
	if (clients != NULL) {
		if (ucl_object_type(clients) != UCL_OBJECT)
			goto out_root;
		it = NULL;
		while ((entry = ucl_object_iterate(clients, &it, true)) != NULL) {
			if (ucl_object_type(entry) != UCL_OBJECT)
				goto out_root;
			label = ucl_object_key(entry);
			label_len = label != NULL ? strlen(label) : 0;
			if (!valid_label(label, label_len) ||
			    config->nclients >= POWERCMP_MAX_CLIENTS)
				goto out_root;
			(void)strlcpy(config->clients[config->nclients].label,
			    label, sizeof(config->clients[0].label));
			config->clients[config->nclients].may_suspend =
			    object_set_flag(entry);
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
	struct stat status;
	char *text;
	ssize_t amount;
	size_t done;
	int error, result;

	if (config == NULL || fd < 0)
		return (errno = EINVAL, -1);
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
		amount = read(fd, text + done, POWERCMP_CONFIG_FILE_MAX + 1 - done);
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
	(void)close(fd);
	fd = -1;
	if (memchr(text, '\0', done) != NULL) {
		errno = EINVAL;
		goto fail_text;
	}
	text[done] = '\0';
	powercmp_config_defaults(config);
	result = config_parse(text, config);
	error = result == -1 ? errno : 0;
	free(text);
	if (result == -1) {
		powercmp_config_defaults(config);
		return (errno = error, -1);
	}
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

	if (config == NULL || path == NULL)
		return (errno = EINVAL, -1);
	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
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
