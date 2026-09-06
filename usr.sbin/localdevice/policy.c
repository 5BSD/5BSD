/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * localdevice(8) policy: default-deny per-label device access, with an optional
 * UCL overlay delivered as a bundle Config/ file.  Modeled on tzfsd(8)'s
 * open_paths policy loader.
 */
#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <ucl.h>

#include "policy.h"

bool
devicecmp_valid_device_name(const char *name)
{
	size_t length;

	if (name == NULL)
		return (false);
	length = strnlen(name, DEVICECMP_MAX_NAME);
	if (length == 0 || length >= DEVICECMP_MAX_NAME)
		return (false);
	/* A single /dev leaf: no separator, no leading dot, never "..". */
	if (name[0] == '.' || strchr(name, '/') != NULL ||
	    strcmp(name, "..") == 0)
		return (false);
	return (true);
}

void
devicecmp_config_defaults(struct devicecmp_config *cfg)
{

	memset(cfg, 0, sizeof(*cfg));
}

uint32_t
devicecmp_policy_lookup(const struct devicecmp_config *cfg, const char *label,
    const char *device, const unsigned long **ioctlsp, unsigned *nioctlsp)
{
	unsigned i;

	if (ioctlsp != NULL)
		*ioctlsp = NULL;
	if (nioctlsp != NULL)
		*nioctlsp = 0;
	if (label == NULL || label[0] == '\0' || device == NULL)
		return (0);
	for (i = 0; i < cfg->nentries; i++) {
		const struct devicecmp_device_policy *pol = &cfg->entries[i];

		if (strcmp(pol->label, label) != 0 ||
		    strcmp(pol->device, device) != 0)
			continue;
		if (ioctlsp != NULL)
			*ioctlsp = pol->ioctls;
		if (nioctlsp != NULL)
			*nioctlsp = pol->nioctls;
		return (pol->rights);
	}
	return (0);
}

void
devicecmp_policy_list(const struct devicecmp_config *cfg, const char *label,
    uint32_t cursor, struct devicecmp_list_entry *out, uint32_t max,
    uint32_t *countp, uint32_t *nextp)
{
	uint32_t count, matched;
	unsigned i;

	count = 0;
	matched = 0;
	*countp = 0;
	*nextp = 0;
	if (cfg == NULL || out == NULL || max == 0 ||
	    label == NULL || label[0] == '\0')
		return;
	if (max > DEVICECMP_LIST_MAX)
		max = DEVICECMP_LIST_MAX;
	for (i = 0; i < cfg->nentries; i++) {
		const struct devicecmp_device_policy *pol = &cfg->entries[i];

		/* Label-scoped: only entries owned by this label are visible. */
		if (strcmp(pol->label, label) != 0)
			continue;
		if (matched < cursor) {
			matched++;
			continue;
		}
		if (count >= max) {
			/* More matches remain: hand back the next filtered index. */
			*nextp = matched;
			break;
		}
		memset(&out[count], 0, sizeof(out[count]));
		strlcpy(out[count].name, pol->device, sizeof(out[count].name));
		out[count].rights = pol->rights;
		out[count].flags = pol->nioctls > 0 ?
		    DEVICECMP_LIST_FLAG_IOCTL_WHITELIST : 0;
		count++;
		matched++;
	}
	*countp = count;
}

static int
copy_string(char *destination, size_t capacity, const ucl_object_t *object)
{
	const char *value;

	if (object == NULL || ucl_object_type(object) != UCL_STRING ||
	    (value = ucl_object_tostring(object)) == NULL || value[0] == '\0' ||
	    strlcpy(destination, value, capacity) >= capacity)
		return (errno = EINVAL, -1);
	return (0);
}

static int
parse_rights(const ucl_object_t *array, uint32_t *out)
{
	const ucl_object_t *rv;
	ucl_object_iter_t it = NULL;
	uint32_t rights = 0;

	if (ucl_object_type(array) != UCL_ARRAY)
		return (errno = EINVAL, -1);
	while ((rv = ucl_object_iterate(array, &it, true)) != NULL) {
		const char *s = ucl_object_tostring(rv);

		if (s == NULL)
			return (errno = EINVAL, -1);
		if (strcmp(s, "read") == 0)
			rights |= DEVICECMP_RIGHT_READ;
		else if (strcmp(s, "write") == 0)
			rights |= DEVICECMP_RIGHT_WRITE;
		else if (strcmp(s, "ioctl") == 0)
			rights |= DEVICECMP_RIGHT_IOCTL;
		else if (strcmp(s, "mmap") == 0)
			rights |= DEVICECMP_RIGHT_MMAP;
		else if (strcmp(s, "seek") == 0)
			rights |= DEVICECMP_RIGHT_SEEK;
		else if (strcmp(s, "event") == 0)
			rights |= DEVICECMP_RIGHT_EVENT;
		else
			return (errno = EINVAL, -1);
	}
	if (rights == 0)
		return (errno = EINVAL, -1);
	*out = rights;
	return (0);
}

static int
parse_ioctls(const ucl_object_t *array, struct devicecmp_device_policy *pol)
{
	const ucl_object_t *iv;
	ucl_object_iter_t it = NULL;

	if (ucl_object_type(array) != UCL_ARRAY)
		return (errno = EINVAL, -1);
	pol->nioctls = 0;
	while ((iv = ucl_object_iterate(array, &it, true)) != NULL) {
		int64_t v;

		if (pol->nioctls >= DEVICECMP_MAX_IOCTLS ||
		    ucl_object_type(iv) != UCL_INT)
			return (errno = EINVAL, -1);
		v = ucl_object_toint(iv);
		if (v < 0)
			return (errno = EINVAL, -1);
		pol->ioctls[pol->nioctls++] = (unsigned long)v;
	}
	/* An ioctl whitelist is only meaningful when ioctl access is granted. */
	if (pol->nioctls != 0 && (pol->rights & DEVICECMP_RIGHT_IOCTL) == 0)
		return (errno = EINVAL, -1);
	return (0);
}

int
devicecmp_config_load_fd(struct devicecmp_config *cfg, int fd)
{
	struct devicecmp_config saved;
	struct ucl_parser *p;
	const ucl_object_t *root, *devices, *ent;
	ucl_object_iter_t it = NULL;
	struct stat sb;
	int error;

	if (cfg == NULL || fd < 0)
		return (errno = EINVAL, -1);
	saved = *cfg;
	if (fstat(fd, &sb) == -1)
		return (-1);
	if (!S_ISREG(sb.st_mode) || sb.st_size > 1024 * 1024 ||
	    (sb.st_mode & (S_IWGRP | S_IWOTH)) != 0)
		return (errno = EPERM, -1);
	p = ucl_parser_new(UCL_PARSER_DEFAULT);
	if (p == NULL)
		return (errno = ENOMEM, -1);
	if (!ucl_parser_add_fd(p, fd)) {
		ucl_parser_free(p);
		return (errno = EINVAL, -1);
	}
	root = ucl_parser_get_object(p);
	if (root == NULL || ucl_object_type(root) != UCL_OBJECT) {
		if (root != NULL)
			ucl_object_unref(__DECONST(ucl_object_t *, root));
		ucl_parser_free(p);
		return (errno = EINVAL, -1);
	}

	cfg->nentries = 0;
	devices = ucl_object_lookup(root, "devices");
	if (devices != NULL) {
		if (ucl_object_type(devices) != UCL_ARRAY)
			goto invalid;
		while ((ent = ucl_object_iterate(devices, &it, true)) != NULL) {
			struct devicecmp_device_policy *pol;
			const ucl_object_t *lb, *dv, *ri, *io;

			if (cfg->nentries >= DEVICECMP_MAX_POLICY ||
			    ucl_object_type(ent) != UCL_OBJECT)
				goto invalid;
			pol = &cfg->entries[cfg->nentries];
			memset(pol, 0, sizeof(*pol));
			lb = ucl_object_lookup(ent, "label");
			dv = ucl_object_lookup(ent, "device");
			ri = ucl_object_lookup(ent, "rights");
			if (lb == NULL || dv == NULL || ri == NULL ||
			    copy_string(pol->label, sizeof(pol->label), lb) == -1 ||
			    copy_string(pol->device, sizeof(pol->device), dv) == -1 ||
			    !devicecmp_valid_device_name(pol->device) ||
			    parse_rights(ri, &pol->rights) == -1)
				goto invalid;
			io = ucl_object_lookup(ent, "ioctls");
			if (io != NULL && parse_ioctls(io, pol) == -1)
				goto invalid;
			cfg->nentries++;
		}
	}

	ucl_object_unref(__DECONST(ucl_object_t *, root));
	ucl_parser_free(p);
	return (0);

invalid:
	error = errno != 0 ? errno : EINVAL;
	*cfg = saved;
	ucl_object_unref(__DECONST(ucl_object_t *, root));
	ucl_parser_free(p);
	errno = error;
	return (-1);
}
