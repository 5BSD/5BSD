/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <filesystemcmp.h>

struct filesystemcmp_client { int open; };
struct filesystemcmp_path_context { uint32_t namespace_id; int open; };

static struct filesystemcmp_client client;
static struct filesystemcmp_path_context context;

static int
fail(const char *operation)
{
	const char *requested;

	requested = getenv("CMP_TEST_FAIL");
	if (requested != NULL && strcmp(requested, operation) == 0) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

int
filesystemcmp_open(struct filesystemcmp_client **result)
{
	if (result == NULL || fail("open") == -1)
		return (-1);
	client.open = 1;
	*result = &client;
	return (0);
}

void
filesystemcmp_close(struct filesystemcmp_client *value)
{
	if (value == &client) {
		client.open = 0;
		if (getenv("CMP_TEST_TRACE_CLOSE") != NULL)
			fprintf(stderr, "client-closed\n");
	}
}

int
filesystemcmp_hello(struct filesystemcmp_client *value,
    struct filesystemcmp_hello_reply *hello)
{
	if (value != &client || !client.open || hello == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (fail("hello") == -1)
		return (-1);
	*hello = (struct filesystemcmp_hello_reply){
	    .version = 1,
	    .features = FILESYSTEMCMP_FEATURE_INLINE_IO |
	        FILESYSTEMCMP_FEATURE_PERSISTENT |
	        FILESYSTEMCMP_FEATURE_BUNDLE,
	    .max_bytes = 4096,
	    .max_objects = 16,
	};
	return (0);
}

int
filesystemcmp_path_context_open(uint32_t namespace_id,
    struct filesystemcmp_path_context **result)
{
	if (result == NULL || namespace_id < FILESYSTEMCMP_NAMESPACE_SCRATCH ||
	    namespace_id > FILESYSTEMCMP_NAMESPACE_BUNDLE || fail("context") == -1)
		return (-1);
	context = (struct filesystemcmp_path_context){ namespace_id, 1 };
	*result = &context;
	return (0);
}

void
filesystemcmp_path_context_close(struct filesystemcmp_path_context *value)
{
	if (value == &context) {
		context.open = 0;
		if (getenv("CMP_TEST_TRACE_CONTEXT_CLOSE") != NULL)
			fprintf(stderr, "context-closed\n");
	}
}

int
filesystemcmp_path_lookup(struct filesystemcmp_path_context *value,
    const char *path, struct filesystemcmp_handle_reply *reply)
{
	if (value != &context || !context.open || path == NULL || reply == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (fail("lookup") == -1)
		return (-1);
	*reply = (struct filesystemcmp_handle_reply){
	    .handle = { .object = 7, .generation = 9 },
	    .type = FILESYSTEMCMP_TYPE_REGULAR,
	};
	return (0);
}

int
filesystemcmp_path_stat(struct filesystemcmp_path_context *value,
    struct filesystemcmp_handle handle, struct filesystemcmp_stat_reply *status)
{
	if (value != &context || !context.open || handle.object != 7 ||
	    handle.generation != 9 || status == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (fail("stat") == -1)
		return (-1);
	*status = (struct filesystemcmp_stat_reply){
	    .size = 11, .inode = 12, .modified_sec = 13, .mode = 0600,
	    .type = FILESYSTEMCMP_TYPE_REGULAR,
	};
	return (0);
}

int
filesystemcmp_path_close_handle(struct filesystemcmp_path_context *value,
    struct filesystemcmp_handle handle)
{
	if (value != &context || !context.open || handle.object != 7 ||
	    handle.generation != 9) {
		errno = EINVAL;
		return (-1);
	}
	return (fail("close-handle"));
}
