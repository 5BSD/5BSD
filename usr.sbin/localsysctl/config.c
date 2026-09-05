/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ucl.h>

#include "config.h"

/* A conservative default: read a few harmless identity/inventory keys, no writes. */
static const char *const default_read[] = {
	"kern.ostype", "kern.osrelease", "kern.osreldate", "kern.version",
	"kern.hostname", "hw.machine", "hw.ncpu", "hw.physmem"
};

void
sysctlcmp_config_defaults(struct sysctlcmp_config *config)
{
	size_t i;

	memset(config, 0, sizeof(*config));
	for (i = 0; i < nitems(default_read) &&
	    i < SYSCTLCMP_MAX_PREFIXES; i++)
		(void)strlcpy(config->default_acl.read[i], default_read[i],
		    SYSCTLCMP_MAX_PREFIX);
	config->default_acl.nread = i;
	config->default_acl.nwrite = 0;
}

/* Dotted-path prefix match: name == prefix, or name starts with prefix ".". */
static bool
prefix_match(const char *name, const char *prefix)
{
	size_t n;

	n = strlen(prefix);
	if (n == 0)
		return (false);
	if (strncmp(name, prefix, n) != 0)
		return (false);
	return (name[n] == '\0' || name[n] == '.');
}

static bool
valid_label(const char *label, size_t length)
{
	size_t i;
	unsigned char c;

	if (label == NULL || length == 0 || length > SYSCTLCMP_CONFIG_LABEL_MAX)
		return (false);
	for (i = 0; i < length; i++) {
		c = (unsigned char)label[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '.' || c == '_' ||
		    c == '-' || c == '/'))
			return (false);
	}
	return (true);
}

/* Parse a UCL array of sysctl-name-prefix strings into a fixed list. */
static int
parse_prefix_array(const ucl_object_t *array,
    char dest[][SYSCTLCMP_MAX_PREFIX], size_t *count)
{
	const ucl_object_t *elem;
	ucl_object_iter_t it;
	const char *s;
	size_t n;

	if (ucl_object_type(array) != UCL_ARRAY)
		return (-1);
	n = 0;
	it = NULL;
	while ((elem = ucl_object_iterate(array, &it, true)) != NULL) {
		if (ucl_object_type(elem) != UCL_STRING || n >=
		    SYSCTLCMP_MAX_PREFIXES)
			return (-1);
		s = ucl_object_tostring(elem);
		if (s == NULL || s[0] == '\0' ||
		    strlen(s) >= SYSCTLCMP_MAX_PREFIX)
			return (-1);
		(void)strlcpy(dest[n], s, SYSCTLCMP_MAX_PREFIX);
		n++;
	}
	*count = n;
	return (0);
}

/* Closed schema: only "read" and "write" keys, each a string array. */
static int
parse_acl_object(const ucl_object_t *object, struct sysctlcmp_acl *acl)
{
	const ucl_object_t *cur;
	ucl_object_iter_t it;
	const char *key;

	if (ucl_object_type(object) != UCL_OBJECT)
		return (-1);
	it = NULL;
	while ((cur = ucl_object_iterate(object, &it, true)) != NULL) {
		key = ucl_object_key(cur);
		if (key == NULL)
			return (-1);
		if (strcmp(key, "read") == 0) {
			if (parse_prefix_array(cur, acl->read, &acl->nread) == -1)
				return (-1);
		} else if (strcmp(key, "write") == 0) {
			if (parse_prefix_array(cur, acl->write,
			    &acl->nwrite) == -1)
				return (-1);
		} else {
			return (-1);	/* unknown key */
		}
	}
	return (0);
}

static int
config_parse(const char *text, struct sysctlcmp_config *config)
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
		config->default_acl.nread = 0;
		config->default_acl.nwrite = 0;
		if (parse_acl_object(def, &config->default_acl) == -1)
			goto out_root;
	}

	clients = ucl_object_lookup(root, "clients");
	if (clients != NULL) {
		if (ucl_object_type(clients) != UCL_OBJECT)
			goto out_root;
		it = NULL;
		while ((entry = ucl_object_iterate(clients, &it, true)) != NULL) {
			label = ucl_object_key(entry);
			label_len = label != NULL ? strlen(label) : 0;
			if (!valid_label(label, label_len) ||
			    config->nclients >= SYSCTLCMP_MAX_CLIENTS)
				goto out_root;
			(void)strlcpy(config->clients[config->nclients].label,
			    label, sizeof(config->clients[0].label));
			if (parse_acl_object(entry,
			    &config->clients[config->nclients].acl) == -1)
				goto out_root;
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
sysctlcmp_config_load_fd(struct sysctlcmp_config *config, int fd)
{
	struct stat status;
	char *text;
	ssize_t amount;
	size_t done;
	int error, result;

	if (config == NULL || fd < 0)
		return (errno = EINVAL, -1);
	sysctlcmp_config_defaults(config);
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
	if (status.st_size < 0 || status.st_size > SYSCTLCMP_CONFIG_FILE_MAX) {
		errno = EFBIG;
		goto fail;
	}
	text = malloc(SYSCTLCMP_CONFIG_FILE_MAX + 2);
	if (text == NULL)
		goto fail;
	done = 0;
	for (;;) {
		amount = read(fd, text + done,
		    SYSCTLCMP_CONFIG_FILE_MAX + 1 - done);
		if (amount == -1 && errno == EINTR)
			continue;
		if (amount == -1)
			goto fail_text;
		if (amount == 0)
			break;
		done += (size_t)amount;
		if (done > SYSCTLCMP_CONFIG_FILE_MAX) {
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
	/* Reset to defaults, then let the file override. */
	sysctlcmp_config_defaults(config);
	result = config_parse(text, config);
	error = result == -1 ? errno : 0;
	free(text);
	if (result == -1)
		sysctlcmp_config_defaults(config);
	errno = error;
	return (result);

fail_text:
	error = errno != 0 ? errno : EIO;
	free(text);
	if (fd >= 0)
		close(fd);
	sysctlcmp_config_defaults(config);
	errno = error;
	return (-1);
fail:
	error = errno != 0 ? errno : EIO;
	close(fd);
	sysctlcmp_config_defaults(config);
	errno = error;
	return (-1);
}

int
sysctlcmp_config_load(struct sysctlcmp_config *config, const char *path)
{
	int fd;

	if (config == NULL || path == NULL)
		return (errno = EINVAL, -1);
	sysctlcmp_config_defaults(config);
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1) {
		if (errno == ENOENT)
			return (0);	/* defaults */
		return (-1);
	}
	return (sysctlcmp_config_load_fd(config, fd));
}

bool
sysctlcmp_config_permits(const struct sysctlcmp_config *config,
    const char *label, const char *name, bool write)
{
	const struct sysctlcmp_acl *acl;
	size_t i, n;

	if (config == NULL || name == NULL || name[0] == '\0')
		return (false);
	acl = &config->default_acl;
	if (label != NULL) {
		for (i = 0; i < config->nclients; i++) {
			if (strcmp(config->clients[i].label, label) == 0) {
				acl = &config->clients[i].acl;
				break;
			}
		}
	}
	if (write) {
		n = acl->nwrite;
		for (i = 0; i < n; i++)
			if (prefix_match(name, acl->write[i]))
				return (true);
		return (false);
	}
	n = acl->nread;
	for (i = 0; i < n; i++)
		if (prefix_match(name, acl->read[i]))
			return (true);
	return (false);
}
