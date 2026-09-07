/* SPDX-License-Identifier: BSD-2-Clause */

#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sysctlcmp.h>

struct sysctlcmp_client {
	bool open;
};

static struct sysctlcmp_client fake_client;

static int
fail(const char *operation)
{
	const char *requested;

	requested = getenv("SYSCTLCMP_TEST_FAIL");
	if (requested != NULL && strcmp(requested, operation) == 0) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

int
sysctlcmp_client_open(struct sysctlcmp_client **clientp)
{
	if (clientp == NULL || fail("open") == -1)
		return (-1);
	fake_client.open = true;
	*clientp = &fake_client;
	return (0);
}

void
sysctlcmp_client_close(struct sysctlcmp_client *client)
{
	if (client == &fake_client) {
		client->open = false;
		if (getenv("SYSCTLCMP_TEST_TRACE_CLOSE") != NULL)
			fprintf(stderr, "client-closed\n");
	}
}

static int
valid(struct sysctlcmp_client *client, const char *operation)
{
	if (client != &fake_client || !client->open) {
		errno = EINVAL;
		return (-1);
	}
	return (fail(operation));
}

int
sysctlcmp_get(struct sysctlcmp_client *client, const char *name, void *buf,
    size_t *lenp)
{
	static const char text[] = "test-value";
	static const unsigned char bytes[] = { 0xde, 0xad, 0xbe };
	uint32_t number;
	const void *value;
	size_t len;

	if (valid(client, "get") == -1)
		return (-1);
	if (name == NULL || buf == NULL ||
	    lenp == NULL)
		return (-1);
	if (strcmp(name, "test.text") == 0) {
		value = text;
		len = sizeof(text);
	} else if (strcmp(name, "test.number") == 0) {
		number = 42;
		value = &number;
		len = sizeof(number);
	} else if (strcmp(name, "test.bytes") == 0) {
		value = bytes;
		len = sizeof(bytes);
	} else {
		errno = ENOENT;
		return (-1);
	}
	if (*lenp < len) {
		*lenp = len;
		errno = ENOMEM;
		return (-1);
	}
	memcpy(buf, value, len);
	*lenp = len;
	return (0);
}

int
sysctlcmp_set(struct sysctlcmp_client *client, const char *name,
    const void *value, size_t len)
{
	if (valid(client, "set") == -1)
		return (-1);
	if (name == NULL || strcmp(name, "test.write") != 0 || value == NULL ||
	    len != sizeof("enabled") || memcmp(value, "enabled", len) != 0) {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

int
sysctlcmp_oidfmt(struct sysctlcmp_client *client, const char *name,
    unsigned int *kindp, char *fmt, size_t *lenp)
{
	static const char format[] = "A";

	if (valid(client, "fmt") == -1)
		return (-1);
	if (name == NULL ||
	    strcmp(name, "test.text") != 0 || kindp == NULL || fmt == NULL ||
	    lenp == NULL || *lenp < sizeof(format)) {
		errno = EINVAL;
		return (-1);
	}
	*kindp = 0x1234;
	memcpy(fmt, format, sizeof(format));
	*lenp = sizeof(format);
	return (0);
}

int
sysctlcmp_describe(struct sysctlcmp_client *client, const char *name,
    char *buf, size_t *lenp)
{
	static const char description[] = "test description";

	if (valid(client, "descr") == -1)
		return (-1);
	if (name == NULL ||
	    strcmp(name, "test.text") != 0 || buf == NULL || lenp == NULL ||
	    *lenp < sizeof(description)) {
		errno = EINVAL;
		return (-1);
	}
	memcpy(buf, description, sizeof(description));
	*lenp = sizeof(description);
	return (0);
}

int
sysctlcmp_next(struct sysctlcmp_client *client, const char *name, char *buf,
    size_t *lenp)
{
	const char *next;
	size_t len;

	if (valid(client, "list") == -1)
		return (-1);
	if (name == NULL || buf == NULL ||
	    lenp == NULL)
		return (-1);
	if (strcmp(name, "") == 0)
		next = "test.alpha";
	else if (strcmp(name, "test.alpha") == 0 ||
	    strcmp(name, "test.beta") == 0)
		next = "test.omega";
	else {
		errno = ENOENT;
		return (-1);
	}
	len = strlen(next) + 1;
	if (*lenp < len) {
		*lenp = len;
		errno = ENOMEM;
		return (-1);
	}
	memmove(buf, next, len);
	*lenp = len;
	return (0);
}
