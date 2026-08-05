/* SPDX-License-Identifier: BSD-2-Clause */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <kldmgr.h>

struct kldmgr_client { int open; };
static struct kldmgr_client client;

int
kldmgr_client_open(struct kldmgr_client **result)
{
	const char *failure;

	if (result == NULL)
		return (errno = EINVAL, -1);
	failure = getenv("CMP_TEST_FAIL");
	if (failure != NULL && strcmp(failure, "open") == 0)
		return (errno = EIO, -1);
	client.open = 1;
	*result = &client;
	return (0);
}

void
kldmgr_client_close(struct kldmgr_client *value)
{
	if (value == &client)
		client.open = 0;
}

static int
module_op(struct kldmgr_client *value, const char *name, int *id,
    const char *operation, int result)
{
	const char *failure;

	if (value != &client || !value->open || name == NULL || id == NULL)
		return (errno = EINVAL, -1);
	failure = getenv("CMP_TEST_FAIL");
	if (failure != NULL && strcmp(failure, operation) == 0)
		return (errno = EIO, -1);
	*id = result;
	return (0);
}

int
kldmgr_load(struct kldmgr_client *value, const char *name, int *id)
{
	return (module_op(value, name, id, "load", 17));
}

int
kldmgr_unload(struct kldmgr_client *value, const char *name, int *id)
{
	return (module_op(value, name, id, "unload", 23));
}

int
kldmgr_list(struct kldmgr_client *value, struct kldmgr_list_entry *entries,
    size_t capacity, size_t *count)
{
	const char *failure;

	if (value != &client || !value->open || entries == NULL || capacity < 2 ||
	    count == NULL)
		return (errno = EINVAL, -1);
	failure = getenv("CMP_TEST_FAIL");
	if (failure != NULL && strcmp(failure, "list") == 0)
		return (errno = EIO, -1);
	memset(entries, 0, sizeof(*entries) * 2);
	entries[0].id = 3;
	strlcpy(entries[0].name, "zfs.ko", sizeof(entries[0].name));
	entries[1].id = 9;
	strlcpy(entries[1].name, "dtrace.ko", sizeof(entries[1].name));
	*count = 2;
	return (0);
}
