/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/wait.h>
#include <trustedzfs.h>
#include "zfshandle_test_helpers.h"

#define CONTENDERS 8
#define CAPACITY 4

static void
race_limit(int parent, bool snapshots)
{
	pid_t children[CONTENDERS];
	int barrier[2], successes = 0, denied = 0, status;
	char name[32], start = 'x';

	ATF_REQUIRE_EQ(0, pipe(barrier));
	for (unsigned i = 0; i < CONTENDERS; i++) {
		children[i] = fork();
		ATF_REQUIRE(children[i] >= 0);
		if (children[i] == 0) {
			int result, error;

			close(barrier[1]);
			if (read(barrier[0], &start, 1) != 1)
				_exit(99);
			close(barrier[0]);
			snprintf(name, sizeof(name), "%s%u", snapshots ? "snap" : "child", i);
			result = snapshots ? tzfs_snapshot(parent, name) :
			    tzfs_create(parent, name, 0);
			error = errno;
			if (result >= 0) {
				if (!snapshots)
					close(result);
				_exit(0);
			}
			if (error != EDQUOT)
				dprintf(STDERR_FILENO, "%s: unexpected errno %d\n", name, error);
			_exit(error == EDQUOT ? 42 : 99);
		}
	}
	close(barrier[0]);
	for (unsigned i = 0; i < CONTENDERS; i++)
		ATF_REQUIRE_EQ(1, write(barrier[1], &start, 1));
	close(barrier[1]);
	for (unsigned i = 0; i < CONTENDERS; i++) {
		ATF_REQUIRE_EQ(children[i], waitpid(children[i], &status, 0));
		ATF_REQUIRE(WIFEXITED(status));
		ATF_REQUIRE(WEXITSTATUS(status) == 0 || WEXITSTATUS(status) == 42);
		successes += WEXITSTATUS(status) == 0;
		denied += WEXITSTATUS(status) == 42;
	}
	ATF_CHECK_EQ(CAPACITY, successes);
	ATF_CHECK_EQ(CONTENDERS - CAPACITY, denied);
}

ATF_TC_WITH_CLEANUP(capability_count_limits);
ATF_TC_HEAD(capability_count_limits, tc)
{
	atf_tc_set_md_var(tc, "descr", "Root capability operations honor atomic ZFS count limits");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(capability_count_limits, tc)
{
	char dataset[256];
	struct zfd_get_one_prop_args property;
	int parent, child, clone;

	zht_require(tc);
	zht_pool_create(tc);
	snprintf(dataset, sizeof(dataset), "%s/data", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", dataset));
	parent = tzfs_open(dataset, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(parent >= 0);
	ATF_REQUIRE_EQ(0, tzfs_set_prop_uint64(parent, "filesystem_limit", CAPACITY));
	ATF_REQUIRE_EQ(0, tzfs_set_prop_uint64(parent, "snapshot_limit", CAPACITY));
	race_limit(parent, false);
	race_limit(parent, true);
	memset(&property, 0, sizeof(property));
	strlcpy(property.zgo_name, "filesystem_count", sizeof(property.zgo_name));
	ATF_REQUIRE_EQ(0, ioctl(parent, ZFD_GET_ONE_PROP, &property));
	ATF_CHECK_EQ(0, property.zgo_is_string);
	ATF_CHECK_EQ(CAPACITY, property.zgo_intval);
	memset(&property, 0, sizeof(property));
	strlcpy(property.zgo_name, "snapshot_count", sizeof(property.zgo_name));
	ATF_REQUIRE_EQ(0, ioctl(parent, ZFD_GET_ONE_PROP, &property));
	ATF_CHECK_EQ(0, property.zgo_is_string);
	ATF_CHECK_EQ(CAPACITY, property.zgo_intval);

	/* Changing an authorized property is explicit and remains possible;
	 * this test does not claim that the property itself is immutable. */
	ATF_REQUIRE_EQ(0, tzfs_set_prop_uint64(parent, "filesystem_limit", CAPACITY + 1));
	child = tzfs_create(parent, "extra", 0);
	ATF_REQUIRE(child >= 0);
	ATF_REQUIRE_EQ(0, tzfs_set_prop_uint64(parent, "snapshot_limit", CAPACITY + 1));
	ATF_REQUIRE_EQ(0, tzfs_snapshot(child, "origin"));
	clone = tzfs_clone(parent, child, "origin", "overlimit");
	ATF_CHECK_ERRNO(EDQUOT, clone == -1);
	if (clone >= 0)
		close(clone);
	ATF_CHECK_ERRNO(EDQUOT, tzfs_snapshot(parent, "overlimit") == -1);

	/* Scoped credentials must not change the ordinary administrator's
	 * credentials or ordinary ZFS semantics outside capability operations. */
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s/ambient", dataset));
	ATF_REQUIRE_EQ(0, zht_systemf("zfs snapshot %s@ambient", dataset));
	close(child);
	close(parent);
}
ATF_TC_CLEANUP(capability_count_limits, tc)
{
	zht_pool_cleanup(tc);
}
ATF_TC_WITH_CLEANUP(capability_refquota);
ATF_TC_HEAD(capability_refquota, tc)
{
	atf_tc_set_md_var(tc, "descr", "Capability property updates install a real write quota");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(capability_refquota, tc)
{
	const size_t block = 1024 * 1024;
	char dataset[256], *buffer;
	int parent, directory, file, error = 0;
	ssize_t written;

	zht_require(tc);
	zht_pool_create(tc);
	snprintf(dataset, sizeof(dataset), "%s/data", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", dataset));
	parent = tzfs_open(dataset, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(parent >= 0);
	ATF_REQUIRE_EQ(0, tzfs_set_prop_uint64(parent, "refquota", 16 * block));
	/* The normal pipeline rejects writes to read-only accounting properties. */
	ATF_CHECK_EQ(-1, tzfs_set_prop_uint64(parent, "used", 1));
	/* Exercise the untrusted typed input boundary of the normal pipeline. */
	ATF_CHECK_EQ(-1, tzfs_set_prop_string(parent, "refquota", "unlimited"));
	ATF_CHECK_EQ(-1, tzfs_set_prop_uint64(parent, "mountpoint", 1));
	ATF_CHECK_EQ(-1, tzfs_set_prop_uint64(parent, "compression", UINT64_MAX));
	ATF_CHECK_EQ(-1, tzfs_set_prop_uint64(parent, "unknown_property", 1));
	ATF_CHECK_EQ(-1, tzfs_set_prop_uint64(parent, "test:annotation", 1));
	ATF_REQUIRE_EQ(0, tzfs_set_prop_string(parent, "test:annotation", "valid"));
	directory = tzfs_mount(parent, false);
	ATF_REQUIRE_MSG(directory >= 0, "mount: %s", strerror(errno));
	file = openat(directory, "payload", O_CREAT | O_EXCL | O_RDWR, 0600);
	ATF_REQUIRE(file >= 0);
	buffer = malloc(block);
	ATF_REQUIRE(buffer != NULL);
	arc4random_buf(buffer, block);
	for (unsigned i = 0; i < 64; i++) {
		written = write(file, buffer, block);
		if (written < 0 || fsync(file) < 0) {
			error = errno;
			break;
		}
		ATF_REQUIRE(written > 0);
	}
	ATF_REQUIRE_MSG(error == EDQUOT || error == ENOSPC,
	    "64 MiB write attempt did not encounter the 16 MiB quota: errno=%d", error);
	ATF_REQUIRE_EQ(0, tzfs_set_prop_uint64(parent, "refquota", 32 * block));
	ATF_REQUIRE_EQ((ssize_t)block, write(file, buffer, block));
	ATF_REQUIRE_EQ(0, fsync(file));
	free(buffer);
	close(file);
	close(directory);
	close(parent);
}
ATF_TC_CLEANUP(capability_refquota, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(capability_transfer_limits);
ATF_TC_HEAD(capability_transfer_limits, tc)
{
	atf_tc_set_md_var(tc, "descr", "Rename and receive enforce destination filesystem and snapshot limits");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(capability_transfer_limits, tc)
{
	char dataset[256];
	int root, source, destination, receiver, occupied, stream;

	zht_require(tc);
	zht_pool_create(tc);
	snprintf(dataset, sizeof(dataset), "%s/data", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", dataset));
	root = tzfs_open(dataset, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(root >= 0);
	source = tzfs_create(root, "source", 0);
	destination = tzfs_create(root, "destination", ZHF_SUBTREE);
	receiver = tzfs_create(root, "receiver", ZHF_SUBTREE);
	ATF_REQUIRE(source >= 0 && destination >= 0 && receiver >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(source, "origin"));
	stream = open("stream.zfs", O_CREAT | O_EXCL | O_RDWR, 0600);
	ATF_REQUIRE(stream >= 0);
	ATF_REQUIRE_EQ(0, tzfs_send(source, "origin", NULL, stream, 0));

	ATF_REQUIRE_EQ(0, tzfs_set_prop_uint64(destination, "filesystem_limit", 1));
	ATF_REQUIRE_EQ(0, tzfs_set_prop_uint64(destination, "snapshot_limit", 1));
	occupied = tzfs_create(destination, "occupied", 0);
	ATF_REQUIRE(occupied >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(destination, "occupied"));
	ATF_CHECK_ERRNO(EDQUOT, tzfs_rename(root, "source", "destination/moved") == -1);
	ATF_REQUIRE_EQ(0, tzfs_set_prop_uint64(destination, "filesystem_limit", 2));
	ATF_CHECK_ERRNO(EDQUOT, tzfs_rename(root, "source", "destination/moved") == -1);
	ATF_REQUIRE_EQ(0, tzfs_set_prop_uint64(destination, "snapshot_limit", 2));
	ATF_REQUIRE_EQ(0, tzfs_rename(root, "source", "destination/moved"));
	close(occupied);

	ATF_REQUIRE_EQ(0, tzfs_set_prop_uint64(receiver, "filesystem_limit", 1));
	ATF_REQUIRE_EQ(0, tzfs_set_prop_uint64(receiver, "snapshot_limit", 1));
	occupied = tzfs_create(receiver, "occupied", 0);
	ATF_REQUIRE(occupied >= 0);
	ATF_REQUIRE_EQ(0, lseek(stream, 0, SEEK_SET));
	ATF_CHECK_ERRNO(EDQUOT, tzfs_recv(receiver, "received@origin", stream, false) == -1);
	ATF_REQUIRE_EQ(0, tzfs_destroy(receiver, "occupied"));
	close(occupied);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(receiver, "occupied"));
	ATF_REQUIRE_EQ(0, lseek(stream, 0, SEEK_SET));
	ATF_CHECK_ERRNO(EDQUOT, tzfs_recv(receiver, "received@origin", stream, false) == -1);
	ATF_REQUIRE_EQ(0, tzfs_set_prop_uint64(receiver, "snapshot_limit", 2));
	ATF_REQUIRE_EQ(0, lseek(stream, 0, SEEK_SET));
	ATF_REQUIRE_EQ(0, tzfs_recv(receiver, "received@origin", stream, false));
	close(stream);
	close(source);
	close(destination);
	close(receiver);
	close(root);
}
ATF_TC_CLEANUP(capability_transfer_limits, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(rename_authority);
ATF_TC_HEAD(rename_authority, tc)
{
	atf_tc_set_md_var(tc, "descr", "Rename requires authority over both namespace endpoints");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(rename_authority, tc)
{
	char dataset[256], expected[512];
	struct zfd_info_args before, after;
	int parent, leaf, sibling;

	zht_require(tc);
	zht_pool_create(tc);
	snprintf(dataset, sizeof(dataset), "%s/data", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", dataset));
	parent = tzfs_open(dataset, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(parent >= 0);
	leaf = tzfs_create(parent, "leaf", 0);
	sibling = tzfs_create(parent, "foreign", 0);
	ATF_REQUIRE(leaf >= 0 && sibling >= 0);
	ATF_REQUIRE_EQ(0, tzfs_info(leaf, &before));
	ATF_REQUIRE_ERRNO(ENOTCAPABLE, tzfs_rename(leaf, NULL, "foreign/moved") == -1);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE, tzfs_rename(leaf, NULL, "renamed") == -1);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE, tzfs_rename(parent, NULL, "moved") == -1);
	ATF_REQUIRE_EQ(0, tzfs_info(leaf, &after));
	ATF_CHECK_STREQ(before.zi_name, after.zi_name);
	ATF_CHECK_EQ(before.zi_ds_guid, after.zi_ds_guid);
	ATF_REQUIRE_EQ(0, tzfs_rename(parent, "leaf", "foreign/moved"));
	ATF_REQUIRE_EQ(0, tzfs_info(leaf, &after));
	snprintf(expected, sizeof(expected), "%s/foreign/moved", dataset);
	ATF_CHECK_STREQ(expected, after.zi_name);
	ATF_CHECK_EQ(before.zi_ds_guid, after.zi_ds_guid);
	close(sibling);
	close(leaf);
	close(parent);
}
ATF_TC_CLEANUP(rename_authority, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, capability_count_limits);
	ATF_TP_ADD_TC(tp, capability_refquota);
	ATF_TP_ADD_TC(tp, capability_transfer_limits);
	ATF_TP_ADD_TC(tp, rename_authority);
	return (atf_no_error());
}
