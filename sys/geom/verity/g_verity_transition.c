/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/endian.h>
#ifdef _KERNEL
#include <sys/systm.h>
#include <sys/errno.h>
#else
#include <errno.h>
#include <stdint.h>
#include <string.h>
#endif
#include "g_verity_transition.h"

/* Require canonical ASCII and zero padding, not just a convenient first NUL. */
static int
transition_string(const unsigned char *p, size_t size, int slash, int colon)
{
	size_t i, end;
	unsigned char c;

	for (end = 0; end < size && p[end] != 0; end++) {
		c = p[end];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '_' || c == '.' ||
		    c == '+' || c == '-' || (slash && c == '/') ||
		    (colon && c == ':')))
			return (EINVAL);
	}
	if (end == 0 || end == size)
		return (EINVAL);
	for (i = end; i < size; i++)
		if (p[i] != 0)
			return (EINVAL);
	return (0);
}

static int
transition_components(const char *path)
{
	const char *start, *end;
	size_t length;

	start = path + (path[0] == '/');
	for (;;) {
		end = strchr(start, '/');
		length = end == NULL ? strlen(start) : (size_t)(end - start);
		if (length == 0 || (length == 1 && start[0] == '.') ||
		    (length == 2 && start[0] == '.' && start[1] == '.'))
			return (EINVAL);
		if (end == NULL)
			return (0);
		start = end + 1;
	}
}

int
g_verity_transition_decode(const void *data, size_t length,
    struct g_verity_transition *output)
{
	const unsigned char *wire = data;
	struct g_verity_transition value;

	if (data == NULL || output == NULL || length != G_VERITY_TRANSITION_BYTES)
		return (EINVAL);
	if (memcmp(wire, "5BSDBOOT", 8) != 0 ||
	    be32dec(wire + 8) != G_VERITY_TRANSITION_VERSION ||
	    be32dec(wire + 12) != G_VERITY_TRANSITION_BYTES)
		return (EINVAL);
	memset(&value, 0, sizeof(value));
	memcpy(value.descriptor_sha256, wire + 16, sizeof(value.descriptor_sha256));
	value.workers = be32dec(wire + 48);
	value.transport_fs = be32dec(wire + 52);
	value.cache_blocks = be64dec(wire + 56);
	value.window_bytes = be64dec(wire + 64);
	value.buffer_bytes = be64dec(wire + 72);
	if (value.workers == 0 || (value.transport_fs != 1 && value.transport_fs != 2) ||
	    value.cache_blocks > INT64_MAX || value.window_bytes == 0 ||
	    value.window_bytes > INT64_MAX || value.buffer_bytes == 0 ||
	    value.buffer_bytes > INT64_MAX)
		return (EINVAL);
	if (transition_string(wire + 80, sizeof(value.transport_device), 1,
	    value.transport_fs == 1) != 0 ||
	    transition_string(wire + 1104, sizeof(value.image), 1, 0) != 0 ||
	    transition_string(wire + 2128, sizeof(value.provider), 0, 0) != 0)
		return (EINVAL);
	memcpy(value.transport_device, wire + 80, sizeof(value.transport_device));
	memcpy(value.image, wire + 1104, sizeof(value.image));
	memcpy(value.provider, wire + 2128, sizeof(value.provider));
	if ((value.transport_fs == 1 && strncmp(value.transport_device, "/dev/", 5) != 0) ||
	    (value.transport_fs == 2 && value.transport_device[0] == '/') ||
	    strncmp(value.image, "/boot/", 6) != 0 ||
	    transition_components(value.transport_device) != 0 ||
	    transition_components(value.image) != 0 ||
	    transition_components(value.provider) != 0)
		return (EINVAL);
	*output = value;
	return (0);
}
