/* SPDX-License-Identifier: BSD-2-Clause */
/* Disposable VM only: real ZFS handle mounts and a rejecting MAC policy. */
#include <sys/types.h>
#include <sys/linker.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <trustedzfs.h>

static unsigned
metric(const char *name)
{
	char key[128];
	unsigned value;
	size_t size = sizeof(value);
	snprintf(key, sizeof(key), "security.mac.anon_mount_test.%s", name);
	ATF_REQUIRE_EQ(0, sysctlbyname(key, &value, &size, NULL, 0));
	ATF_REQUIRE_EQ(sizeof(value), size);
	return (value);
}

static unsigned
mounts(void)
{
	struct statfs *entries;
	int count = getmntinfo(&entries, MNT_NOWAIT);
	ATF_REQUIRE(count > 0);
	return ((unsigned)count);
}

ATF_TC_WITH_CLEANUP(admission);
ATF_TC_HEAD(admission, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(admission, tc)
{
	char pool[64], command[1024], cwd[512];
	FILE *record;
	unsigned baseline, phase, expected_calls = 0;
	int fd, zfd, otherfd, module, deny, status;
	pid_t child;

	/* Refuse to run unless the explicit VM-only module was staged. */
	ATF_REQUIRE(access("/boot/kernel/mac_anon_mount_test.ko", R_OK) == 0);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(pool, sizeof(pool), "bip_admission_%ld", (long)getpid());
	record = fopen("pool-name", "w"); ATF_REQUIRE(record != NULL);
	ATF_REQUIRE(fprintf(record, "%ld\n", (long)getpid()) > 0);
	ATF_REQUIRE_EQ(0, fclose(record));
	fd = open("vdev.img", O_CREAT | O_EXCL | O_RDWR, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, ftruncate(fd, 128 * 1024 * 1024)); close(fd);
	snprintf(command, sizeof(command), "/sbin/zpool create -O mountpoint=none %s %s/vdev.img", pool, cwd);
	ATF_REQUIRE_EQ(0, system(command));
	zfd = tzfs_open(pool, ZH_MOUNT, 0); ATF_REQUIRE(zfd >= 0);
	module = kldload("/boot/kernel/mac_anon_mount_test.ko");
	ATF_REQUIRE_MSG(module >= 0, "kldload: %s", strerror(errno));
	baseline = mounts();
	for (phase = 0; phase < 2; phase++) {
		deny = phase == 0;
		ATF_REQUIRE_EQ(0, sysctlbyname("security.mac.anon_mount_test.deny", NULL, NULL, &deny, sizeof(deny)));
		child = fork(); ATF_REQUIRE(child >= 0);
		if (child == 0) {
			struct statfs st;
			if (setuid(65534) != 0) _exit(2);
			for (int attempt = 0; attempt < (deny ? 16 : 1); attempt++) {
				errno = 0;
				fd = tzfs_mount(zfd, false);
				if (deny) {
					if (fd != -1 || errno != EACCES) _exit(3);
				} else {
					if (fd < 0 || fstatfs(fd, &st) != 0 || strcmp(st.f_fstypename, "zfs") != 0) _exit(4);
					close(fd);
				}
			}
			close(zfd); _exit(0);
		}
		ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
		ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0, "phase %u child status %#x", phase, status);
		expected_calls += deny ? 16 : 1;
		ATF_REQUIRE_EQ(expected_calls, metric("checked"));
		ATF_REQUIRE_EQ(65534, metric("actor_uid"));
		ATF_REQUIRE_EQ(0, metric("filesystem_uid"));
		if (deny) {
			ATF_REQUIRE_EQ(baseline, mounts());
			ATF_REQUIRE_EQ(16, metric("created"));
			ATF_REQUIRE_EQ(16, metric("destroyed"));
		}
	}
	/* A second handle must pass current open policy when joining the cache. */
	otherfd = tzfs_open(pool, ZH_MOUNT, 0); ATF_REQUIRE(otherfd >= 0);
	deny = 1;
	ATF_REQUIRE_EQ(0, sysctlbyname("security.mac.anon_mount_test.deny_open", NULL, NULL, &deny, sizeof(deny)));
	ATF_REQUIRE_ERRNO(EACCES, tzfs_mount(otherfd, false) == -1);
	ATF_REQUIRE_EQ(17, metric("checked"));
	ATF_REQUIRE_EQ(baseline + 1, mounts());
	deny = 0;
	ATF_REQUIRE_EQ(0, sysctlbyname("security.mac.anon_mount_test.deny_open", NULL, NULL, &deny, sizeof(deny)));
	fd = tzfs_mount(otherfd, false); ATF_REQUIRE(fd >= 0);
	/* Persist actual data before leaving the mount orphaned. Reopening must
	 * recover this dataset, not merely return some usable ZFS root. */
	{
		int data = openat(fd, "identity-marker", O_CREAT | O_EXCL | O_RDWR,
		    0600);
		ATF_REQUIRE(data >= 0);
		ATF_REQUIRE_EQ(16, write(data, "original-dataset", 16));
		ATF_REQUIRE_EQ(0, fsync(data));
		ATF_REQUIRE_EQ(0, close(data));
	}
	close(fd); close(otherfd);
	ATF_REQUIRE_EQ(baseline + 1, mounts());
	/* Force final-anchor teardown to leave an orphan, then deny access to
	 * that existing mount independently of creation admission. */
	deny = 1;
	ATF_REQUIRE_EQ(0, sysctlbyname("security.mac.anon_mount_test.deny_unmount", NULL, NULL, &deny, sizeof(deny)));
	close(zfd);
	ATF_REQUIRE_EQ(baseline + 1, mounts());
	ATF_REQUIRE_EQ(16, metric("destroyed"));
	ATF_REQUIRE_EQ(0, sysctlbyname("security.mac.anon_mount_test.deny", NULL, NULL, &deny, sizeof(deny)));
	ATF_REQUIRE_EQ(0, sysctlbyname("security.mac.anon_mount_test.deny_open", NULL, NULL, &deny, sizeof(deny)));
	zfd = tzfs_open(pool, ZH_MOUNT, 0); ATF_REQUIRE(zfd >= 0);
	/* An orphan's mount mode cannot be changed by a new handle. */
	ATF_REQUIRE_ERRNO(EEXIST, tzfs_mount(zfd, true) == -1);
	ATF_REQUIRE_EQ(17, metric("checked"));
	ATF_REQUIRE_EQ(17, metric("created"));
	ATF_REQUIRE_ERRNO(EACCES, tzfs_mount(zfd, false) == -1);
	ATF_REQUIRE_EQ(17, metric("checked")); /* No creation attempted. */
	ATF_REQUIRE_EQ(17, metric("created"));
	ATF_REQUIRE_EQ(baseline + 1, mounts());
	deny = 0;
	ATF_REQUIRE_EQ(0, sysctlbyname("security.mac.anon_mount_test.deny_open", NULL, NULL, &deny, sizeof(deny)));
	ATF_REQUIRE_EQ(0, sysctlbyname("security.mac.anon_mount_test.deny_unmount", NULL, NULL, &deny, sizeof(deny)));
	fd = tzfs_mount(zfd, false); ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(17, metric("checked"));
	{
		char contents[32];
		int data = openat(fd, "identity-marker", O_RDONLY);
		ATF_REQUIRE(data >= 0);
		ATF_REQUIRE_EQ(16, read(data, contents, sizeof(contents)));
		ATF_REQUIRE_EQ(0, memcmp(contents, "original-dataset", 16));
		ATF_REQUIRE_EQ(0, close(data));
	}
	close(fd);
	close(zfd);
	for (int i = 0; i < 100 && metric("created") != metric("destroyed"); i++) usleep(50000);
	ATF_REQUIRE_EQ(17, metric("created"));
	ATF_REQUIRE_EQ(17, metric("destroyed"));
	ATF_REQUIRE_EQ(baseline, mounts());
	/* The reverse mismatch must also fail, without replacing the mount. */
	deny = 0;
	ATF_REQUIRE_EQ(0, sysctlbyname("security.mac.anon_mount_test.deny", NULL, NULL, &deny, sizeof(deny)));
	zfd = tzfs_open(pool, ZH_MOUNT, 0); ATF_REQUIRE(zfd >= 0);
	fd = tzfs_mount(zfd, true); ATF_REQUIRE(fd >= 0);
	{
		struct statfs st;
		ATF_REQUIRE_EQ(0, fstatfs(fd, &st));
		ATF_REQUIRE((st.f_flags & MNT_RDONLY) != 0);
	}
	otherfd = tzfs_open(pool, ZH_MOUNT, 0); ATF_REQUIRE(otherfd >= 0);
	ATF_REQUIRE_ERRNO(EROFS, tzfs_mount(otherfd, false) == -1);
	ATF_REQUIRE_EQ(18, metric("checked"));
	ATF_REQUIRE_EQ(18, metric("created"));
	ATF_REQUIRE_EQ(baseline + 1, mounts());
	close(otherfd); close(fd); close(zfd);
	for (int i = 0; i < 100 && metric("created") != metric("destroyed"); i++) usleep(50000);
	ATF_REQUIRE_EQ(18, metric("destroyed"));
	ATF_REQUIRE_EQ(baseline, mounts());
	ATF_REQUIRE_EQ(0, kldunload(module));
}
static void
cleanup_pool(void)
{
	char command[128];
	long identifier;
	FILE *record;
	int module = kldfind("mac_anon_mount_test");
	if (module >= 0) (void)kldunload(module);
	record = fopen("pool-name", "r");
	if (record != NULL) {
		if (fscanf(record, "%ld", &identifier) == 1 && identifier > 0) {
			snprintf(command, sizeof(command), "/sbin/zpool destroy -f bip_admission_%ld", identifier);
			ATF_CHECK_EQ(0, system(command));
		}
		fclose(record);
	}
}
ATF_TC_CLEANUP(admission, tc)
{
	cleanup_pool();
}

/* Reuse the same private pool record and cleanup as admission. */
ATF_TC_WITH_CLEANUP(identity_collision);
ATF_TC_HEAD(identity_collision, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(identity_collision, tc)
{
	char pool[64], other[80], command[1024], cwd[512], contents[16];
	struct statfs original, candidate;
	struct { int fd; fsid_t fsid; } injection;
	FILE *record;
	unsigned baseline;
	int disk, a, b, ar, br, markerfd, module, value;

	ATF_REQUIRE(access("/boot/kernel/mac_anon_mount_test.ko", R_OK) == 0);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(pool, sizeof(pool), "bip_admission_%ld", (long)getpid());
	snprintf(other, sizeof(other), "%s/other", pool);
	record = fopen("pool-name", "w"); ATF_REQUIRE(record != NULL);
	ATF_REQUIRE(fprintf(record, "%ld\n", (long)getpid()) > 0);
	ATF_REQUIRE_EQ(0, fclose(record));
	disk = open("vdev.img", O_CREAT | O_EXCL | O_RDWR, 0600);
	ATF_REQUIRE(disk >= 0);
	ATF_REQUIRE_EQ(0, ftruncate(disk, 128 * 1024 * 1024)); close(disk);
	snprintf(command, sizeof(command), "/sbin/zpool create -O mountpoint=none %s %s/vdev.img", pool, cwd);
	ATF_REQUIRE_EQ(0, system(command));
	snprintf(command, sizeof(command), "/sbin/zfs create %s", other);
	ATF_REQUIRE_EQ(0, system(command));
	module = kldload("/boot/kernel/mac_anon_mount_test.ko");
	ATF_REQUIRE(module >= 0);
	value = 0;
	ATF_REQUIRE_EQ(0, sysctlbyname("security.mac.anon_mount_test.deny", NULL, NULL, &value, sizeof(value)));
	baseline = mounts();
	a = tzfs_open(pool, ZH_MOUNT, 0); ATF_REQUIRE(a >= 0);
	b = tzfs_open(other, ZH_MOUNT, 0); ATF_REQUIRE(b >= 0);
	ar = tzfs_mount(a, false); ATF_REQUIRE(ar >= 0);
	br = tzfs_mount(b, false); ATF_REQUIRE(br >= 0);
	ATF_REQUIRE_EQ(0, fstatfs(ar, &original));
	ATF_REQUIRE_EQ(0, fstatfs(br, &candidate));
	ATF_REQUIRE(memcmp(&original.f_fsid, &candidate.f_fsid, sizeof(fsid_t)) != 0);
	markerfd = openat(ar, "belongs-to-original", O_CREAT | O_EXCL | O_RDWR, 0600);
	ATF_REQUIRE(markerfd >= 0);
	ATF_REQUIRE_EQ(8, write(markerfd, "original", 8));
	ATF_REQUIRE_EQ(0, fsync(markerfd));
	close(br); close(b);
	ATF_REQUIRE_EQ(baseline + 1, mounts());
	injection.fd = ar; injection.fsid = candidate.f_fsid;
	ATF_REQUIRE_EQ(0, sysctlbyname("security.mac.anon_mount_test.alias_fsid", NULL, NULL, &injection, sizeof(injection)));
	value = 1;
	ATF_REQUIRE_EQ(0, sysctlbyname("security.mac.anon_mount_test.deny_unmount", NULL, NULL, &value, sizeof(value)));
	close(ar); close(a);
	value = 0;
	ATF_REQUIRE_EQ(0, sysctlbyname("security.mac.anon_mount_test.deny_unmount", NULL, NULL, &value, sizeof(value)));
	b = tzfs_open(other, ZH_MOUNT, 0); ATF_REQUIRE(b >= 0);
	/* The colliding locator must not confer ownership or trigger cleanup
	 * of the other dataset. Teardown is allowed while testing rejection. */
	ATF_REQUIRE_ERRNO(ESTALE, tzfs_mount(b, false) == -1);
	ATF_REQUIRE_EQ(baseline + 1, mounts());
	ATF_REQUIRE_EQ(8, pread(markerfd, contents, sizeof(contents), 0));
	ATF_REQUIRE_EQ(0, memcmp(contents, "original", 8));
	injection.fd = markerfd; injection.fsid = original.f_fsid;
	ATF_REQUIRE_EQ(0, sysctlbyname("security.mac.anon_mount_test.alias_fsid", NULL, NULL, &injection, sizeof(injection)));
	close(markerfd);
	a = tzfs_open(pool, ZH_MOUNT, 0); ATF_REQUIRE(a >= 0);
	ar = tzfs_mount(a, false); ATF_REQUIRE(ar >= 0);
	markerfd = openat(ar, "belongs-to-original", O_RDONLY);
	ATF_REQUIRE(markerfd >= 0);
	ATF_REQUIRE_EQ(8, read(markerfd, contents, sizeof(contents)));
	ATF_REQUIRE_EQ(0, memcmp(contents, "original", 8));
	close(markerfd); close(ar); close(a);
	br = tzfs_mount(b, false); ATF_REQUIRE(br >= 0);
	ATF_REQUIRE_ERRNO(ENOENT, openat(br, "belongs-to-original", O_RDONLY) == -1);
	close(br); close(b);
	ATF_REQUIRE_EQ(baseline, mounts());
	ATF_REQUIRE_EQ(metric("created"), metric("destroyed"));
	ATF_REQUIRE_EQ(0, kldunload(module));
}
ATF_TC_CLEANUP(identity_collision, tc)
{
	cleanup_pool();
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, admission);
	ATF_TP_ADD_TC(tp, identity_collision);
	return (atf_no_error());
}
