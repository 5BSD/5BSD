/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "tracecmp_policy.h"

static char *
trim(char *text)
{
	char *end;

	while (isspace((unsigned char)*text))
		text++;
	if (*text == '\0')
		return (text);
	end = text + strlen(text) - 1;
	while (end > text && isspace((unsigned char)*end))
		*end-- = '\0';
	return (text);
}

static bool
label_valid(const char *label)
{
	size_t i, length;
	unsigned char c;

	length = strlen(label);
	if (length == 0 || length >= TRACECMP_POLICY_LABEL_SIZE ||
	    label[0] == '.' || label[length - 1] == '.')
		return (false);
	for (i = 0; i < length; i++) {
		c = (unsigned char)label[i];
		if (!((c >= 'a' && c <= 'z') ||
		    (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '.' || c == '_' ||
		    c == '-'))
			return (false);
		if (c == '.' && i != 0 && label[i - 1] == '.')
			return (false);
	}
	return (true);
}

bool
tracecmp_policy_allows(const struct tracecmp_policy *policy,
    const char *label)
{
	size_t i;

	if (policy == NULL || label == NULL || label[0] == '\0')
		return (false);
	for (i = 0; i < policy->count; i++)
		if (strcmp(policy->labels[i], label) == 0)
			return (true);
	return (false);
}

int
tracecmp_policy_load(const char *path, struct tracecmp_policy *policy)
{
	int fd;

	if (path == NULL || policy == NULL)
		return (errno = EINVAL, -1);
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1) {
		if (errno == ENOENT) {
			memset(policy, 0, sizeof(*policy));
			return (0);
		}
		return (-1);
	}
	return (tracecmp_policy_load_fd(fd, policy));
}

/*
 * Load the trace policy from an already-open descriptor (takes ownership;
 * closes it).  A born-in-capmode daemon gets this fd from service_config_open(3)
 * over the serviced-delivered Config directory, never a global path.
 */
int
tracecmp_policy_load_fd(int fd, struct tracecmp_policy *policy)
{
	char line[256], *entry, *comment, *raw;
	FILE *file;
	struct stat status;
	size_t i, line_length;
	int error;

	if (fd < 0 || policy == NULL)
		return (errno = EINVAL, -1);
	memset(policy, 0, sizeof(*policy));
	if (fstat(fd, &status) == -1) {
		error = errno;
		close(fd);
		return (errno = error, -1);
	}
	if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() ||
	    (status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
		close(fd);
		return (errno = EACCES, -1);
	}
	if (status.st_size < 0 || status.st_size > TRACECMP_POLICY_FILE_MAX) {
		close(fd);
		return (errno = EFBIG, -1);
	}
	file = fdopen(fd, "r");
	if (file == NULL) {
		error = errno;
		close(fd);
		return (errno = error, -1);
	}
	while ((raw = fgetln(file, &line_length)) != NULL) {
		if (line_length >= sizeof(line)) {
			error = E2BIG;
			goto fail;
		}
		if (memchr(raw, '\0', line_length) != NULL) {
			error = EINVAL;
			goto fail;
		}
		memcpy(line, raw, line_length);
		line[line_length] = '\0';
		comment = strchr(line, '#');
		if (comment != NULL)
			*comment = '\0';
		entry = trim(line);
		if (*entry == '\0')
			continue;
		if (strcmp(entry, "*") == 0 || !label_valid(entry) ||
		    policy->count == nitems(policy->labels)) {
			error = EINVAL;
			goto fail;
		}
		for (i = 0; i < policy->count; i++)
			if (strcmp(policy->labels[i], entry) == 0) {
				error = EEXIST;
				goto fail;
			}
		strlcpy(policy->labels[policy->count++], entry,
		    sizeof(policy->labels[0]));
	}
	if (ferror(file)) {
		error = errno != 0 ? errno : EIO;
		goto fail;
	}
	if (fclose(file) == -1)
		return (-1);
	return (0);

fail:
	(void) fclose(file);
	memset(policy, 0, sizeof(*policy));
	errno = error;
	return (-1);
}
