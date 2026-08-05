#include <sys/stat.h>
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "scratch.h"

static struct scratch_store *
new_store(uint64_t bytes, uint32_t objects, uint32_t file_bytes)
{
	struct scratch_limits limits;
	struct scratch_store *store;

	limits.max_bytes = bytes;
	limits.max_objects = objects;
	limits.max_file_bytes = file_bytes;
	ATF_REQUIRE_EQ(0, scratch_store_create(&limits, &store));
	return (store);
}

static struct filesystemcmp_handle
root_handle(struct scratch_store *store)
{
	struct filesystemcmp_handle root;

	ATF_REQUIRE_EQ(0, scratch_root(store, &root));
	return (root);
}

static struct filesystemcmp_handle
create_file(struct scratch_store *store, struct filesystemcmp_handle dir,
    const char *name)
{
	struct filesystemcmp_handle file;

	ATF_REQUIRE_EQ(0, scratch_create(store, dir, name, strlen(name),
	    FILESYSTEMCMP_CREATE_EXCLUSIVE, 0666, &file));
	return (file);
}

ATF_TC(lifecycle);
ATF_TC_HEAD(lifecycle, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "create, lookup, write, read, stat, truncate, and unlink lifecycle");
}
ATF_TC_BODY(lifecycle, tc)
{
	struct scratch_store *store;
	struct filesystemcmp_handle root, file, found;
	struct filesystemcmp_stat_reply stat;
	char data[16];

	store = new_store(1024, 16, 512);
	root = root_handle(store);
	file = create_file(store, root, "hello");
	ATF_CHECK_EQ(2, scratch_objects(store));
	ATF_CHECK_EQ(5, scratch_write(store, file, 0, "world", 5));
	memset(data, 0, sizeof(data));
	ATF_CHECK_EQ(5, scratch_read(store, file, 0, data, sizeof(data)));
	ATF_CHECK_STREQ("world", data);
	ATF_CHECK_EQ(0, scratch_lookup(store, root, "hello", 5, &found));
	ATF_CHECK_EQ(file.object, found.object);
	ATF_CHECK_EQ(file.generation, found.generation);
	ATF_CHECK_EQ(0, scratch_stat(store, file, &stat));
	ATF_CHECK_EQ(5, stat.size);
	ATF_CHECK_EQ(FILESYSTEMCMP_TYPE_REGULAR, stat.type);
	ATF_CHECK_EQ(S_IFREG, stat.mode & S_IFMT);
	ATF_CHECK_EQ(0, scratch_open(store, file,
	    FILESYSTEMCMP_OPEN_WRITE | FILESYSTEMCMP_OPEN_TRUNCATE));
	ATF_CHECK_EQ(0, scratch_bytes(store));
	ATF_CHECK_EQ(0, scratch_unlink(store, root, "hello", 5));
	ATF_CHECK_EQ(1, scratch_objects(store));
	ATF_CHECK_EQ(-1, scratch_lookup(store, root, "hello", 5, &found));
	ATF_CHECK_EQ(ENOENT, errno);
	scratch_store_destroy(store);
}

ATF_TC(name_security);
ATF_TC_HEAD(name_security, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "path traversal, separators, NULs, empty and oversized names fail");
}
ATF_TC_BODY(name_security, tc)
{
	struct scratch_store *store;
	struct filesystemcmp_handle root, file;
	char oversized[FILESYSTEMCMP_NAME_MAX + 1];
	const char embedded[] = {'a', '\0', 'b'};
	const char *bad[] = {"", ".", "..", "a/b", "/root"};
	size_t i;

	store = new_store(1024, 16, 512);
	root = root_handle(store);
	for (i = 0; i < nitems(bad); i++) {
		ATF_CHECK_EQ(-1, scratch_create(store, root, bad[i],
		    strlen(bad[i]), 0, 0600, &file));
		ATF_CHECK_EQ(EINVAL, errno);
	}
	ATF_CHECK_EQ(-1, scratch_create(store, root, embedded,
	    sizeof(embedded), 0, 0600, &file));
	ATF_CHECK_EQ(EINVAL, errno);
	memset(oversized, 'x', sizeof(oversized));
	ATF_CHECK_EQ(-1, scratch_create(store, root, oversized,
	    sizeof(oversized), 0, 0600, &file));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(1, scratch_objects(store));
	scratch_store_destroy(store);
}

ATF_TC(quotas_atomic);
ATF_TC_HEAD(quotas_atomic, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "byte, per-file and object quotas fail atomically with ENOSPC");
}
ATF_TC_BODY(quotas_atomic, tc)
{
	struct scratch_store *store;
	struct filesystemcmp_handle root, a, b, unused;
	char data[16];

	store = new_store(10, 3, 8);
	root = root_handle(store);
	a = create_file(store, root, "a");
	b = create_file(store, root, "b");
	ATF_CHECK_EQ(-1, scratch_create(store, root, "c", 1, 0, 0600,
	    &unused));
	ATF_CHECK_EQ(ENOSPC, errno);
	ATF_REQUIRE_EQ(8, scratch_write(store, a, 0, "12345678", 8));
	ATF_CHECK_EQ(-1, scratch_write(store, a, 8, "x", 1));
	ATF_CHECK_EQ(ENOSPC, errno);
	ATF_CHECK_EQ(-1, scratch_write(store, b, 0, "abc", 3));
	ATF_CHECK_EQ(ENOSPC, errno);
	ATF_CHECK_EQ(8, scratch_bytes(store));
	memset(data, 0, sizeof(data));
	ATF_CHECK_EQ(8, scratch_read(store, a, 0, data, sizeof(data)));
	ATF_CHECK_STREQ("12345678", data);
	scratch_store_destroy(store);
}

ATF_TC(stale_handle_aba);
ATF_TC_HEAD(stale_handle_aba, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "object-slot reuse increments generation and rejects stale handles");
}
ATF_TC_BODY(stale_handle_aba, tc)
{
	struct scratch_store *store;
	struct filesystemcmp_handle root, old, replacement;
	char byte;

	store = new_store(64, 2, 64);
	root = root_handle(store);
	old = create_file(store, root, "old");
	ATF_REQUIRE_EQ(0, scratch_unlink(store, root, "old", 3));
	replacement = create_file(store, root, "new");
	ATF_CHECK_EQ(old.object, replacement.object);
	ATF_CHECK(old.generation != replacement.generation);
	ATF_CHECK_EQ(-1, scratch_read(store, old, 0, &byte, 1));
	ATF_CHECK_EQ(ESTALE, errno);
	ATF_CHECK_EQ(-1, scratch_write(store, old, 0, "x", 1));
	ATF_CHECK_EQ(ESTALE, errno);
	scratch_store_destroy(store);
}

ATF_TC(directories);
ATF_TC_HEAD(directories, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "nested directories enforce type and non-empty removal rules");
}
ATF_TC_BODY(directories, tc)
{
	struct scratch_store *store;
	struct filesystemcmp_handle root, dir, file;

	store = new_store(128, 8, 128);
	root = root_handle(store);
	ATF_REQUIRE_EQ(0, scratch_create(store, root, "dir", 3,
	    FILESYSTEMCMP_CREATE_DIRECTORY, 0777, &dir));
	file = create_file(store, dir, "file");
	ATF_CHECK_EQ(-1, scratch_unlink(store, root, "dir", 3));
	ATF_CHECK_EQ(ENOTEMPTY, errno);
	ATF_CHECK_EQ(-1, scratch_create(store, file, "bad", 3, 0, 0600,
	    &dir));
	ATF_CHECK_EQ(ENOTDIR, errno);
	ATF_REQUIRE_EQ(0, scratch_unlink(store, dir, "file", 4));
	ATF_CHECK_EQ(0, scratch_unlink(store, root, "dir", 3));
	scratch_store_destroy(store);
}

ATF_TC(rename_rules);
ATF_TC_HEAD(rename_rules, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "rename moves objects without overwriting or losing data");
}
ATF_TC_BODY(rename_rules, tc)
{
	struct scratch_store *store;
	struct filesystemcmp_handle root, dir, file, collision, found;
	char data[4] = {};

	store = new_store(128, 8, 128);
	root = root_handle(store);
	ATF_REQUIRE_EQ(0, scratch_create(store, root, "dir", 3,
	    FILESYSTEMCMP_CREATE_DIRECTORY, 0700, &dir));
	file = create_file(store, root, "a");
	collision = create_file(store, dir, "exists");
	(void)collision;
	ATF_REQUIRE_EQ(3, scratch_write(store, file, 0, "abc", 3));
	ATF_CHECK_EQ(-1, scratch_rename(store, root, "a", 1, dir, "exists",
	    6));
	ATF_CHECK_EQ(EEXIST, errno);
	ATF_REQUIRE_EQ(0, scratch_rename(store, root, "a", 1, dir, "b", 1));
	ATF_CHECK_EQ(-1, scratch_lookup(store, root, "a", 1, &found));
	ATF_CHECK_EQ(ENOENT, errno);
	ATF_REQUIRE_EQ(0, scratch_lookup(store, dir, "b", 1, &found));
	ATF_CHECK_EQ(3, scratch_read(store, found, 0, data, sizeof(data)));
	ATF_CHECK_STREQ("abc", data);
	scratch_store_destroy(store);
}

ATF_TC(sparse_and_bounds);
ATF_TC_HEAD(sparse_and_bounds, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "sparse writes zero-fill holes and arithmetic bounds are checked");
}
ATF_TC_BODY(sparse_and_bounds, tc)
{
	struct scratch_store *store;
	struct filesystemcmp_handle root, file;
	uint8_t data[8];

	store = new_store(64, 4, 64);
	root = root_handle(store);
	file = create_file(store, root, "sparse");
	ATF_REQUIRE_EQ(1, scratch_write(store, file, 4, "x", 1));
	memset(data, 0xff, sizeof(data));
	ATF_REQUIRE_EQ(5, scratch_read(store, file, 0, data, sizeof(data)));
	ATF_CHECK_EQ(0, data[0]);
	ATF_CHECK_EQ(0, data[3]);
	ATF_CHECK_EQ('x', data[4]);
	ATF_CHECK_EQ(-1, scratch_write(store, file, UINT64_MAX, "x", 1));
	ATF_CHECK_EQ(EINVAL, errno);
	scratch_store_destroy(store);
}

ATF_TC(model_sequence);
ATF_TC_HEAD(model_sequence, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "deterministic randomized writes match a reference byte-array model");
}
ATF_TC_BODY(model_sequence, tc)
{
	struct scratch_store *store;
	struct filesystemcmp_handle root, file;
	uint8_t model[4096], actual[4096], input[64];
	uint32_t state;
	size_t offset, length, model_size, i, iteration;
	ssize_t result;

	store = new_store(sizeof(model), 4, sizeof(model));
	root = root_handle(store);
	file = create_file(store, root, "model");
	memset(model, 0, sizeof(model));
	model_size = 0;
	state = 0x5bc0ffeeU;
	for (iteration = 0; iteration < 5000; iteration++) {
		state = state * 1664525U + 1013904223U;
		offset = state % sizeof(model);
		state = state * 1664525U + 1013904223U;
		length = state % sizeof(input);
		if (offset + length > sizeof(model))
			length = sizeof(model) - offset;
		for (i = 0; i < length; i++)
			input[i] = (uint8_t)(iteration + i);
		result = scratch_write(store, file, offset, input, length);
		ATF_REQUIRE_EQ((ssize_t)length, result);
		memcpy(model + offset, input, length);
		if (offset + length > model_size)
			model_size = offset + length;
		if (iteration % 97 == 0) {
			memset(actual, 0xa5, sizeof(actual));
			ATF_REQUIRE_EQ((ssize_t)model_size,
			    scratch_read(store, file, 0, actual,
			    sizeof(actual)));
			ATF_CHECK_EQ(0, memcmp(model, actual, model_size));
		}
	}
	scratch_store_destroy(store);
}

ATF_TC(capability_mode);
ATF_TC_HEAD(capability_mode, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "the complete scratch lifecycle works after entering capability mode");
}
ATF_TC_BODY(capability_mode, tc)
{
	struct scratch_store *store;
	struct filesystemcmp_handle root, file;
	char data[4] = {};
	pid_t pid;
	int status;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (cap_enter() == -1)
			_exit(10);
		store = new_store(128, 8, 128);
		root = root_handle(store);
		file = create_file(store, root, "cap");
		if (scratch_write(store, file, 0, "yes", 3) != 3 ||
		    scratch_read(store, file, 0, data, sizeof(data)) != 3 ||
		    memcmp(data, "yes", 3) != 0 ||
		    scratch_unlink(store, root, "cap", 3) == -1)
			_exit(11);
		scratch_store_destroy(store);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
}

ATF_TC(session_isolation);
ATF_TC_HEAD(session_isolation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "private stores cannot resolve or use another session's handles");
}
ATF_TC_BODY(session_isolation, tc)
{
	struct scratch_store *first, *second;
	struct filesystemcmp_handle root1, root2, file1, file2, found;
	char data;

	first = new_store(128, 8, 128);
	second = new_store(128, 8, 128);
	root1 = root_handle(first);
	root2 = root_handle(second);
	file1 = create_file(first, root1, "private");
	ATF_REQUIRE_EQ(1, scratch_write(first, file1, 0, "a", 1));
	ATF_CHECK_EQ(-1, scratch_lookup(second, root2, "private", 7, &found));
	ATF_CHECK_EQ(ENOENT, errno);
	/*
	 * Numeric handles can coincide across sessions.  They identify objects
	 * only within their channel and must never grant cross-store authority.
	 */
	file2 = create_file(second, root2, "other");
	ATF_CHECK_EQ(file1.object, file2.object);
	ATF_CHECK_EQ(0, scratch_read(second, file1, 0, &data, 1));
	ATF_CHECK_EQ(1, scratch_read(first, file1, 0, &data, 1));
	ATF_CHECK_EQ('a', data);
	scratch_store_destroy(first);
	scratch_store_destroy(second);
}

ATF_TC(generation_churn);
ATF_TC_HEAD(generation_churn, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "thousands of slot reuse cycles never resurrect an old handle");
}
ATF_TC_BODY(generation_churn, tc)
{
	struct scratch_store *store;
	struct filesystemcmp_handle root, first, current;
	char name[32], byte;
	unsigned i;

	store = new_store(64, 2, 64);
	root = root_handle(store);
	first = create_file(store, root, "first");
	ATF_REQUIRE_EQ(0, scratch_unlink(store, root, "first", 5));
	for (i = 0; i < 10000; i++) {
		snprintf(name, sizeof(name), "f%u", i);
		ATF_REQUIRE_EQ(0, scratch_create(store, root, name,
		    strlen(name), FILESYSTEMCMP_CREATE_EXCLUSIVE, 0600,
		    &current));
		ATF_CHECK_EQ(first.object, current.object);
		ATF_CHECK(current.generation != first.generation);
		ATF_CHECK_EQ(-1, scratch_read(store, first, 0, &byte, 1));
		ATF_CHECK_EQ(ESTALE, errno);
		ATF_REQUIRE_EQ(0, scratch_unlink(store, root, name,
		    strlen(name)));
	}
	scratch_store_destroy(store);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, lifecycle);
	ATF_TP_ADD_TC(tp, name_security);
	ATF_TP_ADD_TC(tp, quotas_atomic);
	ATF_TP_ADD_TC(tp, stale_handle_aba);
	ATF_TP_ADD_TC(tp, directories);
	ATF_TP_ADD_TC(tp, rename_rules);
	ATF_TP_ADD_TC(tp, sparse_and_bounds);
	ATF_TP_ADD_TC(tp, model_sequence);
	ATF_TP_ADD_TC(tp, capability_mode);
	ATF_TP_ADD_TC(tp, session_isolation);
	ATF_TP_ADD_TC(tp, generation_churn);
	return (atf_no_error());
}
