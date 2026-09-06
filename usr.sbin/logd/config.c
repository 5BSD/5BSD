/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ucl.h>

#include "config.h"
#include "store.h"

void
logcmp_config_default(struct logcmp_config *config)
{

	if (config == NULL)
		return;
	memset(config, 0, sizeof(*config));
	config->ring_size = LOGCMP_RING_SIZE_DEFAULT;
	config->fallback_drain_ms = LOGCMP_DRAIN_MS_DEFAULT;
	config->segment_size = LOGCMP_SEGMENT_SIZE_DEFAULT;
	config->max_segments = LOGCMP_MAX_SEGMENTS_DEFAULT;
	config->minimum_severity = LOGCMP_MINIMUM_SEVERITY_DEFAULT;
	config->rate_limit_interval_ms = LOGCMP_RATE_INTERVAL_MS_DEFAULT;
	config->rate_limit_burst = LOGCMP_RATE_BURST_DEFAULT;
	config->ingress_shards = LOGCMP_INGRESS_SHARDS_DEFAULT;
	config->max_sessions = LOGCMP_MAX_SESSIONS_DEFAULT;
	config->drain_batch = LOGCMP_DRAIN_BATCH_DEFAULT;
	config->retention_max_age = LOGCMP_RETENTION_MAX_AGE_DEFAULT;
	config->retention_max_bytes = LOGCMP_RETENTION_MAX_BYTES_DEFAULT;
}

static int
severity_from_object(const ucl_object_t *object, uint32_t *severity)
{
	const char *name;
	int64_t value;

	if (ucl_object_type(object) == UCL_INT) {
		value = ucl_object_toint(object);
		if (value < 1 || value > 24)
			return (errno = ERANGE, -1);
		*severity = (uint32_t)value;
		return (0);
	}
	if (ucl_object_type(object) != UCL_STRING)
		return (errno = EINVAL, -1);
	name = ucl_object_tostring(object);
	if (strcmp(name, "trace") == 0)
		*severity = LOGCMP_SEVERITY_TRACE;
	else if (strcmp(name, "debug") == 0)
		*severity = LOGCMP_SEVERITY_DEBUG;
	else if (strcmp(name, "info") == 0)
		*severity = LOGCMP_SEVERITY_INFO;
	else if (strcmp(name, "warn") == 0)
		*severity = LOGCMP_SEVERITY_WARN;
	else if (strcmp(name, "error") == 0)
		*severity = LOGCMP_SEVERITY_ERROR;
	else if (strcmp(name, "fatal") == 0)
		*severity = LOGCMP_SEVERITY_FATAL;
	else
		return (errno = EINVAL, -1);
	return (0);
}

static int
from_root(const ucl_object_t *root, struct logcmp_config *config)
{
	static const char *const names[] = {
		"ring_size", "fallback_drain_ms", "segment_size", "max_segments",
		"minimum_severity", "rate_limit_interval_ms", "rate_limit_burst",
		"ingress_shards", "max_sessions", "drain_batch",
		"retention_max_age", "retention_max_bytes"
	};
	const ucl_object_t *entry, *object;
	ucl_object_iter_t iterator;
	const char *key;
	int64_t value;
	size_t i;

	if (root == NULL || ucl_object_type(root) != UCL_OBJECT) {
		errno = EINVAL;
		return (-1);
	}
	iterator = NULL;
	while ((entry = ucl_object_iterate(root, &iterator, true)) != NULL) {
		key = ucl_object_key(entry);
		for (i = 0; i < nitems(names); i++)
			if (strcmp(key, names[i]) == 0)
				break;
		if (i == nitems(names) ||
		    (strcmp(key, "minimum_severity") == 0 ?
		    ucl_object_type(entry) != UCL_INT &&
		    ucl_object_type(entry) != UCL_STRING :
		    ucl_object_type(entry) != UCL_INT)) {
			errno = EINVAL;
			return (-1);
		}
	}
	object = ucl_object_lookup(root, "ring_size");
	if (object != NULL) {
		value = ucl_object_toint(object);
		if (value < LOGCMP_RING_SIZE_MIN || value > LOGCMP_RING_SIZE_MAX ||
		    (value & (value - 1)) != 0) {
			errno = ERANGE;
			return (-1);
		}
		config->ring_size = (uint32_t)value;
	}
	object = ucl_object_lookup(root, "fallback_drain_ms");
	if (object != NULL) {
		value = ucl_object_toint(object);
		if (value < LOGCMP_DRAIN_MS_MIN || value > LOGCMP_DRAIN_MS_MAX) {
			errno = ERANGE;
			return (-1);
		}
		config->fallback_drain_ms = (uint32_t)value;
	}
	object = ucl_object_lookup(root, "segment_size");
	if (object != NULL) {
		value = ucl_object_toint(object);
		if (value < LOGCMP_SEGMENT_SIZE_MIN ||
		    value > LOGCMP_SEGMENT_SIZE_MAX) {
			errno = ERANGE;
			return (-1);
		}
		config->segment_size = (uint64_t)value;
	}
	object = ucl_object_lookup(root, "max_segments");
	if (object != NULL) {
		value = ucl_object_toint(object);
		if (value < LOGCMP_MAX_SEGMENTS_MIN ||
		    value > LOGCMP_MAX_SEGMENTS_MAX) {
			errno = ERANGE;
			return (-1);
		}
		config->max_segments = (uint32_t)value;
	}
	object = ucl_object_lookup(root, "minimum_severity");
	if (object != NULL && severity_from_object(object,
	    &config->minimum_severity) == -1)
		return (-1);
	object = ucl_object_lookup(root, "rate_limit_interval_ms");
	if (object != NULL) {
		value = ucl_object_toint(object);
		if (value < 0 || value > LOGCMP_RATE_INTERVAL_MS_MAX)
			return (errno = ERANGE, -1);
		config->rate_limit_interval_ms = (uint32_t)value;
	}
	object = ucl_object_lookup(root, "rate_limit_burst");
	if (object != NULL) {
		value = ucl_object_toint(object);
		if (value < 0 || value > LOGCMP_RATE_BURST_MAX)
			return (errno = ERANGE, -1);
		config->rate_limit_burst = (uint32_t)value;
	}
	object = ucl_object_lookup(root, "ingress_shards");
	if (object != NULL) {
		value = ucl_object_toint(object);
		if (value < LOGCMP_INGRESS_SHARDS_MIN ||
		    value > LOGCMP_INGRESS_SHARDS_MAX)
			return (errno = ERANGE, -1);
		config->ingress_shards = (uint32_t)value;
	}
	object = ucl_object_lookup(root, "max_sessions");
	if (object != NULL) {
		value = ucl_object_toint(object);
		if (value < LOGCMP_MAX_SESSIONS_MIN ||
		    value > LOGCMP_MAX_SESSIONS_MAX)
			return (errno = ERANGE, -1);
		config->max_sessions = (uint32_t)value;
	}
	object = ucl_object_lookup(root, "drain_batch");
	if (object != NULL) {
		value = ucl_object_toint(object);
		if (value < LOGCMP_DRAIN_BATCH_MIN ||
		    value > LOGCMP_DRAIN_BATCH_MAX)
			return (errno = ERANGE, -1);
		config->drain_batch = (uint32_t)value;
	}
	object = ucl_object_lookup(root, "retention_max_age");
	if (object != NULL) {
		value = ucl_object_toint(object);
		if (value < 0 ||
		    (uint64_t)value > LOGCMP_RETENTION_MAX_AGE_MAX)
			return (errno = ERANGE, -1);
		config->retention_max_age = (uint64_t)value;
	}
	object = ucl_object_lookup(root, "retention_max_bytes");
	if (object != NULL) {
		value = ucl_object_toint(object);
		if (value < 0 ||
		    (uint64_t)value > LOGCMP_RETENTION_MAX_BYTES_MAX)
			return (errno = ERANGE, -1);
		config->retention_max_bytes = (uint64_t)value;
	}
	if ((config->rate_limit_interval_ms == 0) !=
	    (config->rate_limit_burst == 0))
		return (errno = EINVAL, -1);
	return (0);
}

static int
finish_parse(struct ucl_parser *parser, struct logcmp_config *config)
{
	ucl_object_t *root;
	int error, result;

	root = ucl_parser_get_object(parser);
	result = from_root(root, config);
	error = result == -1 ? errno : 0;
	if (root != NULL)
		ucl_object_unref(root);
	ucl_parser_free(parser);
	errno = error;
	return (result);
}

int
logcmp_config_parse(const char *text, struct logcmp_config *config)
{
	struct ucl_parser *parser;

	if (text == NULL || config == NULL) {
		errno = EINVAL;
		return (-1);
	}
	logcmp_config_default(config);
	parser = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
	if (parser == NULL)
		return (-1);
	if (!ucl_parser_add_string(parser, text, strlen(text))) {
		ucl_parser_free(parser);
		errno = EINVAL;
		return (-1);
	}
	return (finish_parse(parser, config));
}

int
logcmp_config_load(const char *path, struct logcmp_config *config)
{
	int fd;

	if (path == NULL || config == NULL)
		return (errno = EINVAL, -1);
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1)
		return (-1);
	return (logcmp_config_load_fd(fd, config));
}

/*
 * Load the managed config from an already-open descriptor (takes ownership;
 * closes it).  A born-in-capmode daemon gets this fd from service_config_open(3)
 * over the serviced-delivered Config directory, never a global path.
 */
int
logcmp_config_load_fd(int fd, struct logcmp_config *config)
{
	struct stat status;
	char *text;
	ssize_t amount;
	size_t done;
	int error, result;

	if (fd < 0 || config == NULL)
		return (errno = EINVAL, -1);
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
	if (status.st_size < 0 || status.st_size > LOGCMP_CONFIG_MAX_SIZE) {
		errno = EFBIG;
		goto fail;
	}
	/*
	 * Do not trust the stat size after validation: even an authorized writer
	 * can replace or extend a configuration while it is being read.  Read to
	 * EOF through the already-open descriptor and retain one byte of overflow
	 * space so growth is rejected instead of silently ignored.
	 */
	text = malloc(LOGCMP_CONFIG_MAX_SIZE + 2);
	if (text == NULL)
		goto fail;
	done = 0;
	for (;;) {
		amount = read(fd, text + done,
		    LOGCMP_CONFIG_MAX_SIZE + 1 - done);
		if (amount == -1 && errno == EINTR)
			continue;
		if (amount == -1) {
			error = errno;
			free(text);
			close(fd);
			return (errno = error, -1);
		}
		if (amount == 0)
			break;
		done += (size_t)amount;
		if (done > LOGCMP_CONFIG_MAX_SIZE) {
			free(text);
			close(fd);
			return (errno = EFBIG, -1);
		}
	}
	close(fd);
	if (memchr(text, '\0', done) != NULL) {
		free(text);
		return (errno = EINVAL, -1);
	}
	text[done] = '\0';
	result = logcmp_config_parse(text, config);
	error = result == -1 ? errno : 0;
	free(text);
	errno = error;
	return (result);

fail:
	error = errno != 0 ? errno : EIO;
	close(fd);
	errno = error;
	return (-1);
}
