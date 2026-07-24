/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include "namespace.h"
#include <sys/envfd.h>
#include <sys/specialfd.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "un-namespace.h"
#include "libc_private.h"

int
envfd_create(const char *name, const struct envfd_create_options *options)
{
	struct specialfd_envfd args;
	size_t namelen;

	if (name == NULL || options == NULL) {
		errno = EINVAL;
		return (-1);
	}
	namelen = strnlen(name, ENVFD_NAME_MAX);
	if (namelen == 0) {
		errno = EINVAL;
		return (-1);
	}
	if (namelen == ENVFD_NAME_MAX) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	memset(&args, 0, sizeof(args));
	memcpy(&args.options, options, sizeof(args.options));
	memcpy(args.name, name, namelen + 1);
	return (__sys___specialfd(SPECIALFD_ENVFD, &args, sizeof(args)));
}
