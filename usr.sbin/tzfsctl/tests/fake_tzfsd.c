/* SPDX-License-Identifier: BSD-2-Clause */

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <trustedzfs.h>
#include "tzfsd.h"

struct tzfsd_client {
	bool open;
};

static struct tzfsd_client fake_client;

static bool
fail_at(const char *operation)
{
	const char *requested;

	requested = getenv("TZFS_TEST_FAIL");
	return (requested != NULL && strcmp(requested, operation) == 0);
}

struct tzfsd_client *
tzfsd_connect(void)
{
	if (fail_at("connect")) {
		errno = ENOENT;
		return (NULL);
	}
	fake_client.open = true;
	return (&fake_client);
}

void
tzfsd_close(struct tzfsd_client *client)
{
	if (client == &fake_client) {
		client->open = false;
		if (getenv("TZFS_TEST_TRACE_CLOSE") != NULL)
			fprintf(stderr, "client-closed\n");
	}
}

static int
validate_client(struct tzfsd_client *client, const char *operation)
{
	if (client != &fake_client || !client->open) {
		errno = EINVAL;
		return (-1);
	}
	if (fail_at(operation)) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

static int
check_number(const char *name, uint64_t actual)
{
	const char *value;
	char *end;
	uint64_t expected;

	value = getenv(name);
	if (value == NULL)
		return (0);
	errno = 0;
	expected = strtoull(value, &end, 0);
	if (errno != 0 || *value == '\0' || *end != '\0' || expected != actual) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

int
tzfsd_request(struct tzfsd_client *client, const struct tzfsd_req *req,
    struct tzfsd_grant *grant)
{
	int fd;

	if (validate_client(client, "request") == -1)
		return (-1);
	if (req == NULL || grant == NULL || strcmp(req->dataset, "claim") != 0 ||
	    req->flags != 0 || req->owner_uid != 0 || req->owner_gid != 0 ||
	    check_number("TZFS_EXPECT_RIGHTS", req->rights) == -1 ||
	    check_number("TZFS_EXPECT_LIFETIME", req->lifetime) == -1) {
		if (errno == 0)
			errno = EINVAL;
		return (-1);
	}
	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (fd == -1)
		return (-1);
	memset(grant, 0, sizeof(*grant));
	grant->handle_fd = fd;
	strlcpy(grant->dataset, "pool/components/claim",
	    sizeof(grant->dataset));
	return (0);
}

int
tzfsd_release(struct tzfsd_client *client, const char *dataset)
{
	if (validate_client(client, "release") == -1)
		return (-1);
	if (dataset == NULL || strcmp(dataset, "claim") != 0) {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

int
tzfsd_ping(struct tzfsd_client *client)
{
	return (validate_client(client, "ping"));
}

int
tzfsd_mount_dir(int handle_fd, int rdonly)
{
	if (handle_fd < 0 || rdonly != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (fail_at("mount")) {
		errno = EIO;
		return (-1);
	}
	return (open("/dev/null", O_RDONLY | O_CLOEXEC));
}
