/* SPDX-License-Identifier: BSD-2-Clause */
/* Run the disk test only in a disposable VM with an explicit scratch-device input. */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <trustedzfs.h>
#include "protected_storage.h"
#include "zfshandle_test_helpers.h"

static void
spec_init(struct capsule_storage *spec, const char *device)
{
	memset(spec, 0, sizeof(*spec));
	strlcpy(spec->recipient, "test.Store/provider", sizeof(spec->recipient));
	strlcpy(spec->pool, zht_pool, sizeof(spec->pool));
	snprintf(spec->dataset, sizeof(spec->dataset), "%s/protected", zht_pool);
	strlcpy(spec->devices[0], device, sizeof(spec->devices[0]));
	spec->ndevices = 1;
	spec->rights = ZH_ALL_RIGHTS;
}

ATF_TC_WITHOUT_HEAD(no_ambient_anchor);
ATF_TC_BODY(no_ambient_anchor, tc)
{
	struct capsule_config cfg;
	struct capsule_storage spec = {0};
	int file;
	(void)tc;

	config_init_defaults(&cfg);
	strlcpy(cfg.hostuuid, "57061ee3-7587-4a12-9447-2ac2b0e947fe", sizeof(cfg.hostuuid));
	ATF_CHECK_ERRNO(EPERM, protected_storage_prepare(&cfg) == -1);
	cfg.nstorage = 1;
	ATF_CHECK_ERRNO(EPERM, protected_storage_prepare(&cfg) == -1);
	ATF_CHECK_ERRNO(EPERM, protected_storage_derive("test.Store/provider") == -1);
	ATF_CHECK_ERRNO(EINVAL, protected_storage_open(&spec) == -1);
	file = open("ordinary-vdev", O_CREAT | O_WRONLY, 0600);
	ATF_REQUIRE(file >= 0); close(file);
	spec.ndevices = 1; spec.pool_guid = 1; spec.dataset_guid = 2;
	spec.rights = ZH_IMPLICIT_RIGHTS;
	strlcpy(spec.devices[0], "ordinary-vdev", sizeof(spec.devices[0]));
	ATF_CHECK_ERRNO(EACCES, protected_storage_open(&spec) == -1);
}

ATF_TC_WITH_CLEANUP(disk_import_and_binding);
ATF_TC_HEAD(disk_import_and_binding, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
	atf_tc_set_md_var(tc, "descr", "import only the explicit scratch disk and bind the pool/dataset GUIDs before delegation");
}
ATF_TC_BODY(disk_import_and_binding, tc)
{
	struct capsule_storage spec, bad;
	struct zfd_info_args info;
	char input[1024], device[1024], name[256];
	FILE *file;
	int fd, childfd, status;
	pid_t child;

	snprintf(input, sizeof(input), "%s/scratch-device", atf_tc_get_config_var(tc, "srcdir"));
	file = fopen(input, "r");
	ATF_REQUIRE_MSG(file != NULL, "explicit disposable scratch-device input required");
	ATF_REQUIRE(fgets(device, sizeof(device), file) != NULL);
	ATF_REQUIRE_EQ(EOF, fgetc(file)); fclose(file);
	device[strcspn(device, "\n")] = '\0';
	/* This test is destructive to its explicit input: accept the VM role only. */
	ATF_REQUIRE_STREQ("/dev/vtbd1", device);
	zht_require(tc);
	zht_poolname(tc, zht_pool, sizeof(zht_pool));
	ATF_REQUIRE_EQ(0, zht_systemf("zpool create -f -o cachefile=none -O mountpoint=none %s %s", zht_pool, device));
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s/protected", zht_pool));
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s/sibling", zht_pool));
	spec_init(&spec, device);
	fd = tzfs_open(spec.dataset, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_info(fd, &info));
	spec.pool_guid = info.zi_pool_guid; spec.dataset_guid = info.zi_ds_guid;
	close(fd);
	ATF_REQUIRE_EQ(0, zht_systemf("zpool export %s", zht_pool));
	fd = protected_storage_open(&spec);
	ATF_REQUIRE_MSG(fd >= 0, "explicit pool import failed: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, tzfs_info(fd, &info));
	ATF_CHECK_EQ(spec.pool_guid, info.zi_pool_guid);
	ATF_CHECK_EQ(spec.dataset_guid, info.zi_ds_guid);
	bad = spec; bad.pool_guid ^= 1;
	ATF_CHECK_ERRNO(EACCES, protected_storage_open(&bad) == -1);
	bad = spec; bad.dataset_guid ^= 1;
	ATF_CHECK_ERRNO(EACCES, protected_storage_open(&bad) == -1);
	bad = spec; strlcpy(bad.devices[0], "/dev/null", sizeof(bad.devices[0]));
	ATF_CHECK_ERRNO(EACCES, protected_storage_open(&bad) == -1);
	bad = spec; snprintf(bad.dataset, sizeof(bad.dataset), "%s/sibling", zht_pool);
	ATF_CHECK_ERRNO(EACCES, protected_storage_open(&bad) == -1);
	bad = spec; bad.ndevices = 2;
	strlcpy(bad.devices[1], device, sizeof(bad.devices[1]));
	ATF_CHECK_ERRNO(EINVAL, protected_storage_open(&bad) == -1);

	/* Deriving a delivery descriptor does not narrow or consume its anchor. */
	ATF_REQUIRE_EQ(0, cap_xfer_limit(fd, CAP_XFER_NONE));
	childfd = tzfs_derive(fd, ZH_IMPLICIT_RIGHTS | ZH_CREATE | ZH_PROPS_WRITE);
	ATF_REQUIRE(childfd >= 0);
	ATF_REQUIRE_EQ(0, cap_xfer_limit(childfd, CAP_XFER_ONCE));
	child = fork(); ATF_REQUIRE(child >= 0);
	if (child == 0) {
		int made;
		close(fd);
		if (cap_enter() != 0 || open("/dev/zfs", O_RDWR) != -1 ||
		    tzfs_openat(childfd, "../sibling", ZH_IMPLICIT_RIGHTS, 0) != -1)
			_exit(1);
		made = tzfs_create(childfd, "created", ZHF_SUBTREE);
		if (made < 0) _exit(2);
		close(made); close(childfd); _exit(0);
	}
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0, "confined worker status %#x", status);
	close(childfd);
	ATF_REQUIRE_EQ(0, tzfs_info(fd, &info));
	ATF_CHECK_EQ(ZH_ALL_RIGHTS, info.zi_rights);
	close(fd);
	/* The same input works again after the first consumer closes. */
	fd = protected_storage_open(&spec); ATF_REQUIRE(fd >= 0); close(fd);
	ATF_REQUIRE_EQ(0, zht_systemf("zpool destroy %s", zht_pool));
	/* A regular-file-backed pool must fail even with matching GUIDs. */
	zht_pool_create(tc);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s/protected", zht_pool));
	snprintf(name, sizeof(name), "%s/protected", zht_pool);
	fd = tzfs_open(name, ZH_ALL_RIGHTS, ZHF_SUBTREE); ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_info(fd, &info)); close(fd);
	spec.pool_guid = info.zi_pool_guid; spec.dataset_guid = info.zi_ds_guid;
	ATF_CHECK_ERRNO(EACCES, protected_storage_open(&spec) == -1);
}
ATF_TC_CLEANUP(disk_import_and_binding, tc)
{
	char pool[128];
	zht_poolname(tc, pool, sizeof(pool));
	for (unsigned i = 0; i < 20; i++) {
		if (zht_systemf("zpool destroy -f %s", pool) == 0) return;
		usleep(100000);
	}
	fprintf(stderr, "could not destroy scratch pool %s\n", pool);
	exit(1);
}
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, no_ambient_anchor);
	ATF_TP_ADD_TC(tp, disk_import_and_binding);
	return atf_no_error();
}
