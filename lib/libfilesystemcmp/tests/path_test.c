/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "filesystemcmp.h"

struct filesystemcmp_client {
	int unused;
};

static struct filesystemcmp_client fake_client;
static struct filesystemcmp_handle last_directory;
static char last_name[FILESYSTEMCMP_NAME_MAX + 1];
static unsigned int close_count;

struct fake_object {
	uint64_t parent;
	const char *name;
	uint32_t type;
};

static const struct fake_object objects[] = {
	[1] = { 0, "", FILESYSTEMCMP_TYPE_DIRECTORY },
	[2] = { 1, "a", FILESYSTEMCMP_TYPE_DIRECTORY },
	[3] = { 2, "b", FILESYSTEMCMP_TYPE_DIRECTORY },
	[4] = { 2, "file", FILESYSTEMCMP_TYPE_REGULAR },
	[5] = { 1, "other", FILESYSTEMCMP_TYPE_DIRECTORY },
};

int
filesystemcmp_open(struct filesystemcmp_client **client)
{

	*client = &fake_client;
	return (0);
}

void
filesystemcmp_close(struct filesystemcmp_client *client __unused)
{
}

int
filesystemcmp_open_namespace(struct filesystemcmp_client *client __unused,
    uint32_t namespace_id, struct filesystemcmp_handle *root)
{

	if (namespace_id != FILESYSTEMCMP_NAMESPACE_SCRATCH) {
		errno = ENOENT;
		return (-1);
	}
	*root = (struct filesystemcmp_handle){ 1, 1 };
	return (0);
}

int
filesystemcmp_lookup(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle directory, const char *name,
    struct filesystemcmp_handle_reply *reply)
{
	size_t i;

	for (i = 2; i < nitems(objects); i++) {
		if (objects[i].parent == directory.object &&
		    strcmp(objects[i].name, name) == 0) {
			reply->handle = (struct filesystemcmp_handle){ i, 1 };
			reply->type = objects[i].type;
			return (0);
		}
	}
	errno = ENOENT;
	return (-1);
}

int
filesystemcmp_dup(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle object,
    struct filesystemcmp_handle_reply *reply)
{

	reply->handle = object;
	reply->type = objects[object.object].type;
	return (0);
}

int
filesystemcmp_close_handle(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle object __unused)
{

	close_count++;
	return (0);
}

ssize_t
filesystemcmp_pread(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle object, void *buffer, size_t length,
    uint64_t offset)
{
	static const char contents[] = "data";
	size_t available;

	if (object.object != 4 || offset > sizeof(contents) - 1) {
		errno = EINVAL;
		return (-1);
	}
	available = sizeof(contents) - 1 - (size_t)offset;
	if (length > available)
		length = available;
	memcpy(buffer, contents + offset, length);
	return ((ssize_t)length);
}

ssize_t
filesystemcmp_pwrite(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle object, const void *buffer, size_t length,
    uint64_t offset __unused)
{

	if (object.object == 0 || (length != 0 && buffer == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	return ((ssize_t)length);
}

int
filesystemcmp_stat(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle object,
    struct filesystemcmp_stat_reply *reply)
{

	if (object.object == 0 || reply == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(reply, 0, sizeof(*reply));
	reply->type = objects[object.object].type;
	reply->size = reply->type == FILESYSTEMCMP_TYPE_REGULAR ? 4 : 0;
	return (0);
}

int
filesystemcmp_sync(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle object)
{

	if (object.object == 0) {
		errno = EBADF;
		return (-1);
	}
	return (0);
}

int
filesystemcmp_create(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle directory, const char *name,
    uint32_t flags __unused, uint32_t mode __unused,
    struct filesystemcmp_handle_reply *reply)
{

	last_directory = directory;
	strlcpy(last_name, name, sizeof(last_name));
	reply->handle = (struct filesystemcmp_handle){ 99, 1 };
	reply->type = FILESYSTEMCMP_TYPE_REGULAR;
	return (0);
}

int
filesystemcmp_unlink(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle directory, const char *name,
    uint32_t flags __unused)
{

	last_directory = directory;
	strlcpy(last_name, name, sizeof(last_name));
	return (0);
}

int
filesystemcmp_rename(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle old_directory, const char *old_name,
    struct filesystemcmp_handle new_directory __unused,
    const char *new_name __unused, uint32_t flags __unused)
{

	last_directory = old_directory;
	strlcpy(last_name, old_name, sizeof(last_name));
	return (0);
}

static void *
path_worker(void *argument)
{
	struct filesystemcmp_path_context *context;
	char cwd[32];
	unsigned i;

	context = argument;
	for (i = 0; i < 200; i++) {
		if (filesystemcmp_path_chdir(context,
		    (i & 1) == 0 ? "/a/b" : "/other") == -1 ||
		    filesystemcmp_path_getcwd(context, cwd, sizeof(cwd)) == -1 ||
		    (strcmp(cwd, "/a/b") != 0 &&
		    strcmp(cwd, "/other") != 0))
			return ((void *)1);
	}
	return (NULL);
}

ATF_TC(cwd_semantics);
ATF_TC_HEAD(cwd_semantics, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "logical cwd resolves relative and absolute paths within its root");
}
ATF_TC_BODY(cwd_semantics, tc)
{
	struct filesystemcmp_path_context *context, *independent;
	struct filesystemcmp_handle_reply reply;
	char cwd[32];

	ATF_REQUIRE_EQ(0, filesystemcmp_path_context_open(
	    FILESYSTEMCMP_NAMESPACE_SCRATCH, &context));
	ATF_REQUIRE_EQ(0, filesystemcmp_path_context_open(
	    FILESYSTEMCMP_NAMESPACE_SCRATCH, &independent));
	ATF_REQUIRE_EQ(0, filesystemcmp_path_getcwd(context, cwd, sizeof(cwd)));
	ATF_CHECK_STREQ("/", cwd);
	ATF_REQUIRE_EQ(0, filesystemcmp_path_chdir(context, "a//./b"));
	ATF_REQUIRE_EQ(0, filesystemcmp_path_getcwd(context, cwd, sizeof(cwd)));
	ATF_CHECK_STREQ("/a/b", cwd);
	ATF_REQUIRE_EQ(0, filesystemcmp_path_lookup(context, "../file", &reply));
	ATF_CHECK_EQ(4, reply.handle.object);
	ATF_REQUIRE_EQ(0, filesystemcmp_path_chdir(context, "/other"));
	ATF_REQUIRE_EQ(0, filesystemcmp_path_getcwd(context, cwd, sizeof(cwd)));
	ATF_CHECK_STREQ("/other", cwd);
	ATF_REQUIRE_EQ(0, filesystemcmp_path_chdir(context, "../../../"));
	ATF_REQUIRE_EQ(0, filesystemcmp_path_getcwd(context, cwd, sizeof(cwd)));
	ATF_CHECK_STREQ("/", cwd);
	ATF_REQUIRE_EQ(0, filesystemcmp_path_getcwd(independent, cwd,
	    sizeof(cwd)));
	ATF_CHECK_STREQ("/", cwd);
	filesystemcmp_path_context_close(independent);
	filesystemcmp_path_context_close(context);
}

ATF_TC(chdir_atomic);
ATF_TC_HEAD(chdir_atomic, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "failed and non-directory chdir operations preserve cwd");
}
ATF_TC_BODY(chdir_atomic, tc)
{
	struct filesystemcmp_path_context *context;
	struct filesystemcmp_handle_reply reply;
	char cwd[32];

	ATF_REQUIRE_EQ(0, filesystemcmp_path_context_open(
	    FILESYSTEMCMP_NAMESPACE_SCRATCH, &context));
	ATF_REQUIRE_EQ(0, filesystemcmp_path_chdir(context, "/a"));
	ATF_CHECK_EQ(-1, filesystemcmp_path_chdir(context, "missing"));
	ATF_CHECK_EQ(ENOENT, errno);
	ATF_CHECK_EQ(-1, filesystemcmp_path_chdir(context, "file"));
	ATF_CHECK_EQ(ENOTDIR, errno);
	ATF_CHECK_EQ(-1, filesystemcmp_path_lookup(context, "file/.", &reply));
	ATF_CHECK_EQ(ENOTDIR, errno);
	ATF_REQUIRE_EQ(0, filesystemcmp_path_getcwd(context, cwd, sizeof(cwd)));
	ATF_CHECK_STREQ("/a", cwd);
	filesystemcmp_path_context_close(context);
}

ATF_TC(parent_operations);
ATF_TC_HEAD(parent_operations, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "path mutations pass only a resolved parent handle and basename");
}
ATF_TC_BODY(parent_operations, tc)
{
	struct filesystemcmp_path_context *context;
	struct filesystemcmp_handle_reply reply;

	ATF_REQUIRE_EQ(0, filesystemcmp_path_context_open(
	    FILESYSTEMCMP_NAMESPACE_SCRATCH, &context));
	ATF_REQUIRE_EQ(0, filesystemcmp_path_create(context, "/a/new", 0,
	    0600, &reply));
	ATF_CHECK_EQ(2, last_directory.object);
	ATF_CHECK_STREQ("new", last_name);
	ATF_REQUIRE_EQ(0, filesystemcmp_path_unlink(context, "a/file", 0));
	ATF_CHECK_EQ(2, last_directory.object);
	ATF_CHECK_STREQ("file", last_name);
	errno = 0;
	ATF_CHECK_EQ(-1, filesystemcmp_path_create(context, "/", 0, 0600,
	    &reply));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, filesystemcmp_path_create(context, "a/.", 0, 0600,
	    &reply));
	ATF_CHECK_EQ(EINVAL, errno);
	filesystemcmp_path_context_close(context);
}

ATF_TC(handle_operations);
ATF_TC_HEAD(handle_operations, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "path-only clients can consume and release returned handles");
}
ATF_TC_BODY(handle_operations, tc)
{
	struct filesystemcmp_path_context *context;
	struct filesystemcmp_handle_reply object;
	struct filesystemcmp_stat_reply status;
	char data[5] = {};

	ATF_REQUIRE_EQ(0, filesystemcmp_path_context_open(
	    FILESYSTEMCMP_NAMESPACE_SCRATCH, &context));
	ATF_REQUIRE_EQ(0, filesystemcmp_path_lookup(context, "/a/file",
	    &object));
	ATF_REQUIRE_EQ(4, filesystemcmp_path_pread(context, object.handle,
	    data, 4, 0));
	ATF_CHECK_STREQ("data", data);
	ATF_REQUIRE_EQ(2, filesystemcmp_path_pwrite(context, object.handle,
	    "ok", 2, 0));
	ATF_REQUIRE_EQ(0, filesystemcmp_path_stat(context, object.handle,
	    &status));
	ATF_CHECK_EQ(FILESYSTEMCMP_TYPE_REGULAR, status.type);
	ATF_CHECK_EQ(4, status.size);
	ATF_REQUIRE_EQ(0, filesystemcmp_path_sync(context, object.handle));
	ATF_REQUIRE_EQ(0, filesystemcmp_path_close_handle(context,
	    object.handle));
	filesystemcmp_path_context_close(context);
}

ATF_TC(context_resource_lifecycle);
ATF_TC_HEAD(context_resource_lifecycle, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "closing a path context releases its cwd chain and namespace root");
}
ATF_TC_BODY(context_resource_lifecycle, tc)
{
	struct filesystemcmp_path_context *context;
	unsigned int before;

	before = close_count;
	ATF_REQUIRE_EQ(0, filesystemcmp_path_context_open(
	    FILESYSTEMCMP_NAMESPACE_SCRATCH, &context));
	filesystemcmp_path_context_close(context);
	ATF_CHECK_EQ(before + 1, close_count);

	before = close_count;
	ATF_REQUIRE_EQ(0, filesystemcmp_path_context_open(
	    FILESYSTEMCMP_NAMESPACE_SCRATCH, &context));
	ATF_REQUIRE_EQ(0, filesystemcmp_path_chdir(context, "/a/b"));
	filesystemcmp_path_context_close(context);
	ATF_CHECK_EQ(before + 3, close_count);
}

ATF_TC(concurrent_context);
ATF_TC_HEAD(concurrent_context, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "one path context serializes concurrent cwd operations safely");
}
ATF_TC_BODY(concurrent_context, tc)
{
	struct filesystemcmp_path_context *context;
	pthread_t first, second;
	void *result;

	ATF_REQUIRE_EQ(0, filesystemcmp_path_context_open(
	    FILESYSTEMCMP_NAMESPACE_SCRATCH, &context));
	ATF_REQUIRE_EQ(0, pthread_create(&first, NULL, path_worker, context));
	ATF_REQUIRE_EQ(0, pthread_create(&second, NULL, path_worker, context));
	ATF_REQUIRE_EQ(0, pthread_join(first, &result));
	ATF_CHECK_EQ(NULL, result);
	ATF_REQUIRE_EQ(0, pthread_join(second, &result));
	ATF_CHECK_EQ(NULL, result);
	filesystemcmp_path_context_close(context);
}

ATF_TC(boundaries_and_fork);
ATF_TC_HEAD(boundaries_and_fork, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "path limits, empty paths, small buffers, and fork fail safely");
}
ATF_TC_BODY(boundaries_and_fork, tc)
{
	struct filesystemcmp_path_context *context;
	struct filesystemcmp_handle_reply reply;
	char long_path[FILESYSTEMCMP_PATH_MAX + 2], tiny[1];
	pid_t child;
	int status;

	ATF_REQUIRE_EQ(0, filesystemcmp_path_context_open(
	    FILESYSTEMCMP_NAMESPACE_SCRATCH, &context));
	errno = 0;
	ATF_CHECK_EQ(-1, filesystemcmp_path_lookup(context, "", &reply));
	ATF_CHECK_EQ(ENOENT, errno);
	memset(long_path, 'a', sizeof(long_path));
	long_path[sizeof(long_path) - 1] = '\0';
	errno = 0;
	ATF_CHECK_EQ(-1, filesystemcmp_path_lookup(context, long_path, &reply));
	ATF_CHECK_EQ(ENAMETOOLONG, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, filesystemcmp_path_getcwd(context, tiny,
	    sizeof(tiny)));
	ATF_CHECK_EQ(ERANGE, errno);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0)
		_exit(filesystemcmp_path_chdir(context, "/") == -1 &&
		    errno == EINVAL ? 0 : 1);
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	filesystemcmp_path_context_close(context);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, cwd_semantics);
	ATF_TP_ADD_TC(tp, chdir_atomic);
	ATF_TP_ADD_TC(tp, parent_operations);
	ATF_TP_ADD_TC(tp, handle_operations);
	ATF_TP_ADD_TC(tp, context_resource_lifecycle);
	ATF_TP_ADD_TC(tp, concurrent_context);
	ATF_TP_ADD_TC(tp, boundaries_and_fork);
	return (atf_no_error());
}
