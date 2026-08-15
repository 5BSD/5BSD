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
static int close_inject;
static int write_inject;

int __real_close(int);
int __real_fsync(int);
ssize_t __real_write(int, const void *, size_t);
int __wrap_close(int);
int __wrap_fsync(int);
ssize_t __wrap_write(int, const void *, size_t);

int
__wrap_close(int fd)
{

	if (close_inject != 0) {
		close_inject--;
		(void)__real_close(fd);
		errno = EIO;
		return (-1);
	}
	return (__real_close(fd));
}

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

static int
replace_file(const char *path, const char *contents)
{
	int fd, error;

	fd = open(path, O_WRONLY | O_TRUNC);
	ATF_REQUIRE(fd >= 0);
	error = checkpoint_write_all(fd, contents, strlen(contents));
	ATF_REQUIRE_EQ(close(fd), 0);
	return (error);
}

static int
verify_manifest_at(int dirfd, const struct checkpoint_manifest *manifest)
{
	int data_fd, error, kern_fd, meta_fd;

	error = checkpoint_manifest_open_verified_at(dirfd, manifest, &data_fd,
	    &kern_fd, &meta_fd);
	if (error != 0)
		return (error);
	ATF_REQUIRE_EQ(close(data_fd), 0);
	ATF_REQUIRE_EQ(close(kern_fd), 0);
	ATF_REQUIRE_EQ(close(meta_fd), 0);
	return (0);
}

ATF_TC_WITHOUT_HEAD(manifest_validation);
ATF_TC_BODY(manifest_validation, tc)
{
	struct checkpoint_manifest before, manifest;
	bool is_manifest;
	char nonterminated_base[NAME_MAX + 1];
	char maximum_base[NAME_MAX + 1];
	char path[] = "/tmp/bhyve-manifest-legacy.XXXXXX";
	char symlink_path[PATH_MAX];
	char *temporary;
	const char missing_identity[] = CHECKPOINT_MANIFEST_MAGIC
	    "data=../escape\nkern=k\nmeta=m\n";
	const char wrong_order[] = CHECKPOINT_MANIFEST_MAGIC
	    "machine=" CHECKPOINT_MACHINE_ABI "\n"
	    "architecture=amd64\n"
	    "data=d\nkern=k\nmeta=m\n";
	const char empty_architecture[] = CHECKPOINT_MANIFEST_MAGIC
	    "architecture=\n"
	    "machine=" CHECKPOINT_MACHINE_ABI "\n"
	    "data=d\nkern=k\nmeta=m\n";
	const char oversized_architecture[] = CHECKPOINT_MANIFEST_MAGIC
	    "architecture=abcdefghijklmnop\n"
	    "machine=" CHECKPOINT_MACHINE_ABI "\n"
	    "data=d\nkern=k\nmeta=m\n";
	const char trailing_field[] = CHECKPOINT_MANIFEST_MAGIC
	    "architecture=amd64\n"
	    "machine=" CHECKPOINT_MACHINE_ABI "\n"
	    "data=d\nkern=k\nmeta=m\nextra=value\n";
	const char truncated[] = CHECKPOINT_MANIFEST_MAGIC
	    "architecture=amd64\n"
	    "machine=" CHECKPOINT_MACHINE_ABI "\n"
	    "data=d\nkern=k\nmeta=m";
	int fd;

	ATF_CHECK_EQ(checkpoint_manifest_read(NULL, &manifest, &is_manifest),
	    EINVAL);
	ATF_CHECK_EQ(checkpoint_manifest_read(path, NULL, &is_manifest),
	    EINVAL);
	ATF_CHECK_EQ(checkpoint_manifest_read(path, &manifest, NULL), EINVAL);
	ATF_CHECK(checkpoint_member_valid("checkpoint.data.1234"));
	memset(nonterminated_base, 'x', sizeof(nonterminated_base));
	memset(&manifest, 0, sizeof(manifest));
	ATF_CHECK(!checkpoint_manifest_valid_for(nonterminated_base,
	    &manifest));
	ATF_CHECK(!checkpoint_member_valid(""));
	ATF_CHECK(!checkpoint_member_valid("."));
	ATF_CHECK(!checkpoint_member_valid(".."));
	ATF_CHECK(!checkpoint_member_valid("../data"));
	ATF_CHECK(!checkpoint_member_valid("dir/data"));
	memset(maximum_base, 'x', sizeof(maximum_base) - 1);
	maximum_base[sizeof(maximum_base) - 1] = '\0';
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
	ATF_REQUIRE_EQ(checkpoint_write_all(fd, "invalid", 7), 0);
	ATF_REQUIRE_EQ(close(fd), 0);
	ATF_CHECK_EQ(checkpoint_manifest_read(path, &manifest, &is_manifest),
	    EINVAL);
	ATF_CHECK(!is_manifest);
	ATF_REQUIRE(snprintf(symlink_path, sizeof(symlink_path), "%s.link",
	    path) > 0);
	ATF_REQUIRE_EQ(symlink(path, symlink_path), 0);
	before = manifest;
	is_manifest = true;
	ATF_CHECK(checkpoint_manifest_read(symlink_path, &manifest,
	    &is_manifest) != 0);
	ATF_CHECK(!is_manifest);
	ATF_CHECK_EQ(memcmp(&manifest, &before, sizeof(manifest)), 0);
	ATF_REQUIRE_EQ(unlink(symlink_path), 0);

	/* Name generation is also output-atomic on an overlong member. */
	memset(&manifest, 0xa5, sizeof(manifest));
	before = manifest;
	temporary = (char *)(uintptr_t)1;
	ATF_CHECK_EQ(checkpoint_generation_names(maximum_base, &manifest,
	    &temporary), ENAMETOOLONG);
	ATF_CHECK_EQ(memcmp(&manifest, &before, sizeof(manifest)), 0);
	ATF_CHECK_EQ(temporary, NULL);

	ATF_REQUIRE_EQ(replace_file(path, missing_identity), 0);
	memset(&manifest, 0xa5, sizeof(manifest));
	before = manifest;
	ATF_CHECK_EQ(checkpoint_manifest_read(path, &manifest, &is_manifest),
	    EINVAL);
	ATF_CHECK(!is_manifest);
	ATF_CHECK_EQ(memcmp(&manifest, &before, sizeof(manifest)), 0);
	ATF_REQUIRE_EQ(replace_file(path, wrong_order), 0);
	ATF_CHECK_EQ(checkpoint_manifest_read(path, &manifest, &is_manifest),
	    EINVAL);
	ATF_CHECK(!is_manifest);
	ATF_CHECK_EQ(memcmp(&manifest, &before, sizeof(manifest)), 0);
	ATF_REQUIRE_EQ(replace_file(path, empty_architecture), 0);
	ATF_CHECK_EQ(checkpoint_manifest_read(path, &manifest, &is_manifest),
	    EINVAL);
	ATF_CHECK(!is_manifest);
	ATF_CHECK_EQ(memcmp(&manifest, &before, sizeof(manifest)), 0);
	ATF_REQUIRE_EQ(replace_file(path, oversized_architecture), 0);
	ATF_CHECK_EQ(checkpoint_manifest_read(path, &manifest, &is_manifest),
	    EINVAL);
	ATF_CHECK(!is_manifest);
	ATF_CHECK_EQ(memcmp(&manifest, &before, sizeof(manifest)), 0);
	ATF_REQUIRE_EQ(replace_file(path, trailing_field), 0);
	ATF_CHECK_EQ(checkpoint_manifest_read(path, &manifest, &is_manifest),
	    EINVAL);
	ATF_CHECK(!is_manifest);
	ATF_CHECK_EQ(memcmp(&manifest, &before, sizeof(manifest)), 0);
	ATF_REQUIRE_EQ(replace_file(path, truncated), 0);
	ATF_CHECK_EQ(checkpoint_manifest_read(path, &manifest, &is_manifest),
	    EINVAL);
	ATF_CHECK(!is_manifest);
	ATF_CHECK_EQ(memcmp(&manifest, &before, sizeof(manifest)), 0);
	ATF_REQUIRE_EQ(unlink(path), 0);
}

ATF_TC_WITHOUT_HEAD(noncurrent_manifest_header_rejected);
ATF_TC_BODY(noncurrent_manifest_header_rejected, tc)
{
	struct checkpoint_manifest before, manifest;
	bool is_manifest;
	char path[] = "/tmp/bhyve-manifest-foreign.XXXXXX";
	char *temporary;
	const char foreign[] = "BHYVE-CHECKPOINT-MANIFEST-4\n"
	    "architecture="
#if defined(__amd64__)
	    "amd64\n"
#elif defined(__aarch64__)
	    "arm64\n"
#elif defined(__riscv)
	    "riscv64\n"
#else
	    "unknown\n"
#endif
	    "machine=" CHECKPOINT_MACHINE_ABI "\n"
	    "data=checkpoint.data.00000000000000000000000000000000\n"
	    "kern=checkpoint.kern.00000000000000000000000000000000\n"
	    "meta=checkpoint.meta.00000000000000000000000000000000\n";
	int fd;

	memset(&manifest, 0, sizeof(manifest));
	ATF_REQUIRE_EQ(checkpoint_generation_names("checkpoint", &manifest,
	    &temporary), 0);
	ATF_CHECK_EQ(manifest.format_version, 3);
	ATF_CHECK(strcmp(manifest.architecture,
	    checkpoint_host_architecture()) == 0);
	ATF_CHECK(strcmp(manifest.machine, CHECKPOINT_MACHINE_ABI) == 0);
	ATF_CHECK(checkpoint_manifest_compatible(&manifest));
	strlcpy(manifest.architecture, "different-arch",
	    sizeof(manifest.architecture));
	ATF_CHECK(!checkpoint_manifest_compatible(&manifest));
	strlcpy(manifest.architecture, checkpoint_host_architecture(),
	    sizeof(manifest.architecture));
	strlcpy(manifest.machine, "different-machine",
	    sizeof(manifest.machine));
	ATF_CHECK(!checkpoint_manifest_compatible(&manifest));
	strlcpy(manifest.machine, "foreign-machine-abi",
	    sizeof(manifest.machine));
	ATF_CHECK(!checkpoint_manifest_compatible(&manifest));
	free(temporary);
	before = manifest;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(checkpoint_write_all(fd, foreign,
	    sizeof(foreign) - 1), 0);
	ATF_REQUIRE_EQ(close(fd), 0);
	ATF_REQUIRE_EQ(checkpoint_manifest_read(path, &manifest, &is_manifest),
	    EINVAL);
	ATF_CHECK(!is_manifest);
	ATF_CHECK_EQ(memcmp(&manifest, &before, sizeof(manifest)), 0);

	is_manifest = true;
	close_inject = 1;
	ATF_CHECK_EQ(checkpoint_manifest_read(path, &manifest, &is_manifest),
	    EINVAL);
	ATF_CHECK(!is_manifest);
	ATF_CHECK_EQ(memcmp(&manifest, &before, sizeof(manifest)), 0);
	ATF_REQUIRE_EQ(unlink(path), 0);
}

ATF_TC_WITHOUT_HEAD(raw_three_file_format_rejected);
ATF_TC_BODY(raw_three_file_format_rejected, tc)
{
	struct checkpoint_manifest before, manifest;
	bool exists, is_manifest;
	char directory[] = "/tmp/bhyve-manifest-raw.XXXXXX";
	int dirfd;

	ATF_REQUIRE(mkdtemp(directory) != NULL);
	dirfd = open(directory, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dirfd >= 0);
	make_file_at(dirfd, "checkpoint", "raw-guest-memory");
	make_file_at(dirfd, "checkpoint.kern", "raw-kernel-state");
	make_file_at(dirfd, "checkpoint.meta", "raw-metadata");

	memset(&manifest, 0xa5, sizeof(manifest));
	before = manifest;
	exists = false;
	is_manifest = true;
	ATF_CHECK_EQ(checkpoint_manifest_read_at(dirfd, "checkpoint",
	    &manifest, &exists, &is_manifest), EINVAL);
	ATF_CHECK(exists);
	ATF_CHECK(!is_manifest);
	ATF_CHECK_EQ(memcmp(&manifest, &before, sizeof(manifest)), 0);

	ATF_REQUIRE_EQ(unlinkat(dirfd, "checkpoint", 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, "checkpoint.kern", 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, "checkpoint.meta", 0), 0);
	ATF_REQUIRE_EQ(close(dirfd), 0);
	ATF_REQUIRE_EQ(rmdir(directory), 0);
}

ATF_TC_WITHOUT_HEAD(manifest_rejects_nonregular_files);
ATF_TC_BODY(manifest_rejects_nonregular_files, tc)
{
	struct checkpoint_manifest before, manifest;
	bool exists, is_manifest;
	char directory[] = "/tmp/bhyve-manifest-fifo.XXXXXX";
	char fifo_path[PATH_MAX];
	char *temporary;
	int data_fd, dirfd, kern_fd, meta_fd;

	ATF_REQUIRE(mkdtemp(directory) != NULL);
	dirfd = open(directory, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dirfd >= 0);
	ATF_REQUIRE(snprintf(fifo_path, sizeof(fifo_path), "%s/manifest-fifo",
	    directory) > 0);
	ATF_REQUIRE_EQ(mkfifo(fifo_path, 0600), 0);
	memset(&manifest, 0xa5, sizeof(manifest));
	before = manifest;
	is_manifest = true;
	ATF_CHECK_EQ(checkpoint_manifest_read(fifo_path, &manifest,
	    &is_manifest), EINVAL);
	ATF_CHECK(!is_manifest);
	ATF_CHECK_EQ(memcmp(&manifest, &before, sizeof(manifest)), 0);
	exists = false;
	is_manifest = true;
	ATF_CHECK_EQ(checkpoint_manifest_read_at(dirfd, "manifest-fifo",
	    &manifest, &exists, &is_manifest), EINVAL);
	ATF_CHECK(exists);
	ATF_CHECK(!is_manifest);
	ATF_CHECK_EQ(memcmp(&manifest, &before, sizeof(manifest)), 0);
	ATF_REQUIRE_EQ(unlink(fifo_path), 0);

	ATF_REQUIRE_EQ(checkpoint_generation_names("checkpoint", &manifest,
	    &temporary), 0);
	make_file_at(dirfd, manifest.kern, "kern-member");
	make_file_at(dirfd, manifest.meta, "meta-member");
	ATF_REQUIRE(snprintf(fifo_path, sizeof(fifo_path), "%s/%s", directory,
	    manifest.data) > 0);
	ATF_REQUIRE_EQ(mkfifo(fifo_path, 0600), 0);
	data_fd = kern_fd = meta_fd = 99;
	ATF_CHECK_EQ(checkpoint_manifest_open_verified_at(dirfd, &manifest,
	    &data_fd, &kern_fd, &meta_fd), EINVAL);
	ATF_CHECK_EQ(data_fd, -1);
	ATF_CHECK_EQ(kern_fd, -1);
	ATF_CHECK_EQ(meta_fd, -1);
	ATF_REQUIRE_EQ(unlink(fifo_path), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, manifest.kern, 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, manifest.meta, 0), 0);
	ATF_REQUIRE_EQ(close(dirfd), 0);
	ATF_REQUIRE_EQ(rmdir(directory), 0);
	free(temporary);
}

ATF_TC_WITHOUT_HEAD(manifest_member_integrity);
ATF_TC_BODY(manifest_member_integrity, tc)
{
	struct checkpoint_manifest alias, manifest, parsed;
	bool is_manifest, published;
	char directory[] = "/tmp/bhyve-manifest-integrity.XXXXXX";
	char canonical[PATH_MAX], data_path[PATH_MAX], kern_path[PATH_MAX];
	char meta_path[PATH_MAX];
	char *alias_tmp, *temporary;
	int data_fd, dirfd, kern_fd, meta_fd;

	ATF_REQUIRE(mkdtemp(directory) != NULL);
	dirfd = open(directory, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dirfd >= 0);
	ATF_REQUIRE(snprintf(canonical, sizeof(canonical), "%s/checkpoint",
	    directory) > 0);
	ATF_REQUIRE_EQ(checkpoint_generation_names("checkpoint", &manifest,
	    &temporary), 0);
	make_file_at(dirfd, manifest.data, "data-member");
	make_file_at(dirfd, manifest.kern, "kern-member");
	make_file_at(dirfd, manifest.meta, "meta-member");
	ATF_REQUIRE_EQ(checkpoint_publish(dirfd, "checkpoint", temporary,
	    &manifest, &published), 0);
	ATF_CHECK(published);
	ATF_CHECK_EQ(verify_manifest_at(dirfd, &manifest), 0);
	ATF_CHECK_EQ(strlen(manifest.data_sha256),
	    CHECKPOINT_SHA256_HEX_LEN);
	ATF_CHECK_EQ(strlen(manifest.kern_sha256),
	    CHECKPOINT_SHA256_HEX_LEN);
	ATF_CHECK_EQ(strlen(manifest.meta_sha256),
	    CHECKPOINT_SHA256_HEX_LEN);

	ATF_REQUIRE_EQ(checkpoint_manifest_read(canonical, &parsed,
	    &is_manifest), 0);
	ATF_CHECK(is_manifest);
	ATF_CHECK_EQ(parsed.format_version, 3);
	ATF_CHECK_EQ(verify_manifest_at(dirfd, &parsed), 0);
	ATF_REQUIRE_EQ(symlinkat("checkpoint", dirfd, "checkpoint-link"), 0);
	parsed = manifest;
	is_manifest = true;
	ATF_CHECK(checkpoint_manifest_read_at(dirfd, "checkpoint-link",
	    &parsed, &(bool){ false }, &is_manifest) != 0);
	ATF_CHECK(!is_manifest);
	ATF_CHECK_EQ(memcmp(&parsed, &manifest, sizeof(parsed)), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, "checkpoint-link", 0), 0);
	ATF_CHECK_EQ(checkpoint_manifest_open_verified_at(dirfd, &parsed,
	    &data_fd, &data_fd, &meta_fd), EINVAL);
	/* Output storage must not corrupt the manifest before validation. */
	manifest = parsed;
	ATF_CHECK_EQ(checkpoint_manifest_open_verified_at(dirfd, &parsed,
	    (int *)(void *)&parsed.format_version, &kern_fd, &meta_fd), EINVAL);
	ATF_CHECK_EQ(memcmp(&parsed, &manifest, sizeof(parsed)), 0);
	ATF_CHECK_EQ(checkpoint_manifest_open_verified_at(dirfd, &parsed,
	    &data_fd, (int *)(void *)((char *)&kern_fd + 1), &meta_fd), EINVAL);
	ATF_REQUIRE_EQ(checkpoint_manifest_open_verified_at(dirfd, &parsed,
	    &data_fd, &kern_fd, &meta_fd), 0);
	ATF_CHECK((fcntl(data_fd, F_GETFD) & FD_CLOEXEC) != 0);
	ATF_CHECK((fcntl(kern_fd, F_GETFD) & FD_CLOEXEC) != 0);
	ATF_CHECK((fcntl(meta_fd, F_GETFD) & FD_CLOEXEC) != 0);
	ATF_REQUIRE_EQ(close(data_fd), 0);
	ATF_REQUIRE_EQ(close(kern_fd), 0);
	ATF_REQUIRE_EQ(close(meta_fd), 0);

	ATF_REQUIRE(snprintf(data_path, sizeof(data_path), "%s/%s",
	    directory, manifest.data) > 0);
	ATF_REQUIRE_EQ(replace_file(data_path, "data-membeR"), 0);
	ATF_CHECK_EQ(verify_manifest_at(dirfd, &parsed), EILSEQ);
	ATF_REQUIRE_EQ(replace_file(data_path, "data-member"), 0);
	ATF_CHECK_EQ(verify_manifest_at(dirfd, &parsed), 0);
	ATF_REQUIRE(snprintf(kern_path, sizeof(kern_path), "%s/%s",
	    directory, manifest.kern) > 0);
	ATF_REQUIRE_EQ(replace_file(kern_path, "kern-membeR"), 0);
	ATF_CHECK_EQ(verify_manifest_at(dirfd, &parsed), EILSEQ);
	ATF_REQUIRE_EQ(replace_file(kern_path, "kern-member"), 0);
	ATF_CHECK_EQ(verify_manifest_at(dirfd, &parsed), 0);
	ATF_REQUIRE(snprintf(meta_path, sizeof(meta_path), "%s/%s",
	    directory, manifest.meta) > 0);
	ATF_REQUIRE_EQ(replace_file(meta_path, "meta-membeR"), 0);
	ATF_CHECK_EQ(verify_manifest_at(dirfd, &parsed), EILSEQ);
	ATF_REQUIRE_EQ(replace_file(meta_path, "meta-member"), 0);
	ATF_CHECK_EQ(verify_manifest_at(dirfd, &parsed), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, manifest.data, 0), 0);
	ATF_REQUIRE_EQ(symlinkat(manifest.kern, dirfd, manifest.data), 0);
	ATF_CHECK(verify_manifest_at(dirfd, &parsed) != 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, manifest.data, 0), 0);

	/*
	 * Matching version-3 digests do not make one inode valid for two
	 * independently decoded checkpoint domains.
	 */
	ATF_REQUIRE_EQ(checkpoint_generation_names("alias", &alias,
	    &alias_tmp), 0);
	make_file_at(dirfd, alias.data, "same-member");
	make_file_at(dirfd, alias.kern, "same-member");
	make_file_at(dirfd, alias.meta, "same-member");
	ATF_REQUIRE_EQ(checkpoint_publish(dirfd, "alias", alias_tmp, &alias,
	    &published), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, alias.meta, 0), 0);
	ATF_REQUIRE_EQ(linkat(dirfd, alias.kern, dirfd, alias.meta, 0), 0);
	ATF_CHECK_EQ(verify_manifest_at(dirfd, &alias), EINVAL);
	ATF_REQUIRE_EQ(unlinkat(dirfd, alias.data, 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, alias.kern, 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, alias.meta, 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, "alias", 0), 0);
	free(alias_tmp);

	ATF_REQUIRE_EQ(unlinkat(dirfd, manifest.kern, 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, manifest.meta, 0), 0);
	ATF_REQUIRE_EQ(unlinkat(dirfd, "checkpoint", 0), 0);
	ATF_REQUIRE_EQ(close(dirfd), 0);
	ATF_REQUIRE_EQ(rmdir(directory), 0);
	free(temporary);
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

ATF_TC_WITHOUT_HEAD(manifest_publication_rejects_invalid_topology);
ATF_TC_BODY(manifest_publication_rejects_invalid_topology, tc)
{
	struct checkpoint_manifest manifest, invalid;
	char directory[] = "/tmp/bhyve-manifest-invalid.XXXXXX";
	char *temporary;
	bool published;
	int dirfd;

	ATF_REQUIRE(mkdtemp(directory) != NULL);
	dirfd = open(directory, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dirfd >= 0);
	ATF_REQUIRE_EQ(checkpoint_generation_names("checkpoint", &manifest,
	    &temporary), 0);

	published = true;
	ATF_CHECK_EQ(checkpoint_publish(dirfd, "checkpoint", temporary,
	    &manifest, NULL), EINVAL);
	ATF_CHECK_EQ(checkpoint_publish(-1, "checkpoint", temporary, &manifest,
	    &published), EINVAL);
	ATF_CHECK(!published);
	ATF_CHECK_EQ(checkpoint_publish(dirfd, "../checkpoint", temporary,
	    &manifest, &published), EINVAL);
	ATF_CHECK(!published);
	ATF_CHECK_EQ(checkpoint_publish(dirfd, "checkpoint", "../temporary",
	    &manifest, &published), EINVAL);
	ATF_CHECK(!published);

	invalid = manifest;
	invalid.meta[0] = invalid.meta[0] == 'x' ? 'y' : 'x';
	ATF_CHECK_EQ(checkpoint_publish(dirfd, "checkpoint", temporary,
	    &invalid, &published), EINVAL);
	ATF_CHECK(!published);
	ATF_CHECK_EQ(checkpoint_publish(dirfd, "checkpoint",
	    "checkpoint.manifest.00000000000000000000000000000000.tmp",
	    &manifest, &published), EINVAL);
	ATF_CHECK(!published);
	ATF_CHECK_EQ(faccessat(dirfd, "checkpoint", F_OK, 0), -1);
	ATF_CHECK_EQ(errno, ENOENT);

	free(temporary);
	ATF_REQUIRE_EQ(close(dirfd), 0);
	ATF_REQUIRE_EQ(rmdir(directory), 0);
}

ATF_TC_WITHOUT_HEAD(manifest_failure_atomicity);
ATF_TC_BODY(manifest_failure_atomicity, tc)
{
	struct checkpoint_manifest current, old, replacement, replacement_before;
	bool exists, is_manifest, published;
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
	current = old;
	exists = false;
	is_manifest = true;
	close_inject = 1;
	ATF_CHECK_EQ(checkpoint_manifest_read_at(dirfd, "checkpoint", &current,
	    &exists, &is_manifest), EIO);
	ATF_CHECK(exists);
	ATF_CHECK(!is_manifest);
	ATF_CHECK_EQ(memcmp(&current, &old, sizeof(current)), 0);

	ATF_REQUIRE_EQ(checkpoint_generation_names("checkpoint", &replacement,
	    &second_tmp), 0);
	make_file_at(dirfd, replacement.data, "new-data");
	make_file_at(dirfd, replacement.kern, "new-kern");
	make_file_at(dirfd, replacement.meta, "new-meta");
	replacement_before = replacement;

	/* A manifest-file fsync error leaves the old checkpoint selected. */
	fsync_calls = 0;
	fsync_fail_call = 1;
	ATF_CHECK_EQ(checkpoint_publish(dirfd, "checkpoint", second_tmp,
	    &replacement, &published), EIO);
	ATF_CHECK(!published);
	ATF_CHECK_EQ(memcmp(&replacement, &replacement_before,
	    sizeof(replacement)), 0);
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
	ATF_TP_ADD_TC(tp, noncurrent_manifest_header_rejected);
	ATF_TP_ADD_TC(tp, raw_three_file_format_rejected);
	ATF_TP_ADD_TC(tp, manifest_rejects_nonregular_files);
	ATF_TP_ADD_TC(tp, manifest_member_integrity);
	ATF_TP_ADD_TC(tp, manifest_atomic_publication);
	ATF_TP_ADD_TC(tp, manifest_publication_rejects_invalid_topology);
	ATF_TP_ADD_TC(tp, manifest_failure_atomicity);
	return (atf_no_error());
}
