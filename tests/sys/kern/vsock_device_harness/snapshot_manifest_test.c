#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

/*
 * Pull in the production implementation so the standalone sanitizer harness
 * exercises the exact parser and publication code without a running VM.
 */
#include "checkpoint_manifest.c"

static int fsync_calls;
static int fsync_fail_call;
static int write_inject;

int __real_fsync(int);
ssize_t __real_write(int, const void *, size_t);

int
__wrap_fsync(int fd)
{

	fsync_calls++;
	if (fsync_fail_call != 0 && fsync_calls == fsync_fail_call) {
		errno = EIO;
		return (-1);
	}
	return (__real_fsync(fd));
}

ssize_t
__wrap_write(int fd, const void *buffer, size_t length)
{

	if (write_inject == 1) {
		write_inject = 0;
		errno = EINTR;
		return (-1);
	}
	if (write_inject == 2) {
		write_inject = 0;
		return (0);
	}
	return (__real_write(fd, buffer, length));
}

static int
make_file_at(int dirfd, const char *name, const char *contents)
{
	int fd;

	fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(checkpoint_write_all(fd, contents, strlen(contents)), 0);
	ATF_REQUIRE_EQ(close(fd), 0);
	return (0);
}

ATF_TC_WITHOUT_HEAD(manifest_validation);
ATF_TC_BODY(manifest_validation, tc)
{
	struct checkpoint_manifest manifest;
	bool is_manifest;
	char path[] = "/tmp/bhyve-manifest-legacy.XXXXXX";
	const char malformed[] = CHECKPOINT_MANIFEST_MAGIC
	    "data=../escape\nkern=k\nmeta=m\n";
	int fd;

	ATF_CHECK(checkpoint_member_valid("checkpoint.data.1234"));
	ATF_CHECK(!checkpoint_member_valid(""));
	ATF_CHECK(!checkpoint_member_valid("."));
	ATF_CHECK(!checkpoint_member_valid(".."));
	ATF_CHECK(!checkpoint_member_valid("../data"));
	ATF_CHECK(!checkpoint_member_valid("dir/data"));
	memset(&manifest, 0, sizeof(manifest));
	strlcpy(manifest.data,
	    "checkpoint.data.00000000000000000000000000000000",
	    sizeof(manifest.data));
	strlcpy(manifest.kern,
	    "checkpoint.kern.00000000000000000000000000000000",
	    sizeof(manifest.kern));
	strlcpy(manifest.meta,
	    "checkpoint.meta.11111111111111111111111111111111",
	    sizeof(manifest.meta));
	ATF_CHECK(!checkpoint_manifest_valid_for("checkpoint", &manifest));
	strlcpy(manifest.meta,
	    "checkpoint.meta.00000000000000000000000000000000",
	    sizeof(manifest.meta));
	ATF_CHECK(checkpoint_manifest_valid_for("checkpoint", &manifest));
	ATF_CHECK(!checkpoint_manifest_valid_for("other", &manifest));

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(checkpoint_write_all(fd, "legacy", 6), 0);
	ATF_REQUIRE_EQ(close(fd), 0);
	ATF_CHECK_EQ(checkpoint_manifest_read(path, &manifest, &is_manifest), 0);
	ATF_CHECK(!is_manifest);

	fd = open(path, O_WRONLY | O_TRUNC);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(checkpoint_write_all(fd, malformed,
	    sizeof(malformed) - 1), 0);
	ATF_REQUIRE_EQ(close(fd), 0);
	ATF_CHECK_EQ(checkpoint_manifest_read(path, &manifest, &is_manifest),
	    EINVAL);
	ATF_CHECK(!is_manifest);
	ATF_REQUIRE_EQ(unlink(path), 0);
}

ATF_TC_WITHOUT_HEAD(manifest_atomic_publication);
ATF_TC_BODY(manifest_atomic_publication, tc)
{
	struct checkpoint_manifest current, old, replacement;
	bool is_manifest;
	char directory[] = "/tmp/bhyve-manifest.XXXXXX";
	char canonical[PATH_MAX];
	char *first_tmp, *second_tmp;
	bool published;
	int dirfd;

	ATF_REQUIRE(mkdtemp(directory) != NULL);
	dirfd = open(directory, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dirfd >= 0);
	ATF_REQUIRE(snprintf(canonical, sizeof(canonical), "%s/checkpoint",
	    directory) > 0);

	memset(&old, 0, sizeof(old));
	ATF_REQUIRE_EQ(checkpoint_generation_names("checkpoint", &old,
	    &first_tmp), 0);
	make_file_at(dirfd, old.data, "old-data");
	make_file_at(dirfd, old.kern, "old-kern");
	make_file_at(dirfd, old.meta, "old-meta");
	ATF_REQUIRE_EQ(checkpoint_publish(dirfd, "checkpoint", first_tmp, &old,
	    &published), 0);
	ATF_CHECK(published);
	ATF_REQUIRE_EQ(checkpoint_manifest_read(canonical, &current,
	    &is_manifest), 0);
	ATF_CHECK(is_manifest);
	ATF_CHECK_EQ(strcmp(current.data, old.data), 0);

	/*
	 * Creating a complete replacement generation cannot change which
	 * checkpoint is visible.  Only the final manifest rename publishes it.
	 */
	memset(&replacement, 0, sizeof(replacement));
	ATF_REQUIRE_EQ(checkpoint_generation_names("checkpoint", &replacement,
	    &second_tmp), 0);
	make_file_at(dirfd, replacement.data, "new-data");
	make_file_at(dirfd, replacement.kern, "new-kern");
	make_file_at(dirfd, replacement.meta, "new-meta");
	ATF_REQUIRE_EQ(checkpoint_manifest_read(canonical, &current,
	    &is_manifest), 0);
	ATF_CHECK_EQ(strcmp(current.data, old.data), 0);

	ATF_REQUIRE_EQ(checkpoint_publish(dirfd, "checkpoint", second_tmp,
	    &replacement, &published), 0);
	ATF_CHECK(published);
	ATF_REQUIRE_EQ(checkpoint_manifest_read(canonical, &current,
	    &is_manifest), 0);
	ATF_CHECK(is_manifest);
	ATF_CHECK_EQ(strcmp(current.data, replacement.data), 0);
	ATF_CHECK_EQ(strcmp(current.kern, replacement.kern), 0);
	ATF_CHECK_EQ(strcmp(current.meta, replacement.meta), 0);

	ATF_REQUIRE_EQ(unlinkat(dirfd, old.data, 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, old.kern, 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, old.meta, 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, replacement.data, 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, replacement.kern, 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, replacement.meta, 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, "checkpoint", 0), 0);
	ATF_REQUIRE_EQ(close(dirfd), 0);
	ATF_REQUIRE_EQ(rmdir(directory), 0);
	free(first_tmp);
	free(second_tmp);
}

ATF_TC_WITHOUT_HEAD(manifest_failure_atomicity);
ATF_TC_BODY(manifest_failure_atomicity, tc)
{
	struct checkpoint_manifest current, old, replacement;
	bool is_manifest, published;
	char directory[] = "/tmp/bhyve-manifest-fail.XXXXXX";
	char canonical[PATH_MAX];
	char *first_tmp, *second_tmp;
	int dirfd, fd;

	ATF_REQUIRE(mkdtemp(directory) != NULL);
	dirfd = open(directory, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dirfd >= 0);
	ATF_REQUIRE(snprintf(canonical, sizeof(canonical), "%s/checkpoint",
	    directory) > 0);
	ATF_REQUIRE_EQ(checkpoint_generation_names("checkpoint", &old,
	    &first_tmp), 0);
	make_file_at(dirfd, old.data, "old-data");
	make_file_at(dirfd, old.kern, "old-kern");
	make_file_at(dirfd, old.meta, "old-meta");
	ATF_REQUIRE_EQ(checkpoint_publish(dirfd, "checkpoint", first_tmp, &old,
	    &published), 0);

	ATF_REQUIRE_EQ(checkpoint_generation_names("checkpoint", &replacement,
	    &second_tmp), 0);
	make_file_at(dirfd, replacement.data, "new-data");
	make_file_at(dirfd, replacement.kern, "new-kern");
	make_file_at(dirfd, replacement.meta, "new-meta");

	/* A manifest-file fsync error leaves the old checkpoint selected. */
	fsync_calls = 0;
	fsync_fail_call = 1;
	ATF_CHECK_EQ(checkpoint_publish(dirfd, "checkpoint", second_tmp,
	    &replacement, &published), EIO);
	ATF_CHECK(!published);
	fsync_fail_call = 0;
	ATF_REQUIRE_EQ(checkpoint_manifest_read(canonical, &current,
	    &is_manifest), 0);
	ATF_CHECK_EQ(strcmp(current.data, old.data), 0);

	/*
	 * Failure to fsync the directory occurs after atomic rename.  Report the
	 * durability error, but mark the new generation visible so its members
	 * are never removed out from under the manifest.
	 */
	fsync_calls = 0;
	fsync_fail_call = 2;
	ATF_CHECK_EQ(checkpoint_publish(dirfd, "checkpoint", second_tmp,
	    &replacement, &published), EIO);
	ATF_CHECK(published);
	fsync_fail_call = 0;
	ATF_REQUIRE_EQ(checkpoint_manifest_read(canonical, &current,
	    &is_manifest), 0);
	ATF_CHECK_EQ(strcmp(current.data, replacement.data), 0);

	fd = openat(dirfd, "write-test", O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	write_inject = 1;
	ATF_CHECK_EQ(checkpoint_write_all(fd, "ok", 2), 0);
	write_inject = 2;
	ATF_CHECK_EQ(checkpoint_write_all(fd, "bad", 3), EIO);
	ATF_REQUIRE_EQ(close(fd), 0);

	ATF_REQUIRE_EQ(unlinkat(dirfd, old.data, 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, old.kern, 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, old.meta, 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, replacement.data, 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, replacement.kern, 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, replacement.meta, 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, "write-test", 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, "checkpoint", 0), 0);
	ATF_REQUIRE_EQ(close(dirfd), 0);
	ATF_REQUIRE_EQ(rmdir(directory), 0);
	free(first_tmp);
	free(second_tmp);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, manifest_validation);
	ATF_TP_ADD_TC(tp, manifest_atomic_publication);
	ATF_TP_ADD_TC(tp, manifest_failure_atomicity);
	return (atf_no_error());
}
