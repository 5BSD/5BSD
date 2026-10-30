/* SPDX-License-Identifier: BSD-2-Clause */
/* Real descriptor rejection and real ZFS provisioning; no ioctl doubles. */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <trustedzfs.h>
#include "bsdfilesystem.h"
#include "zfshandle_test_helpers.h"

static void
initialize(struct bsdfilesystem_state *state)
{
	memset(state, 0, sizeof(*state));
	state->persistent_fd = state->ephemeral_fd = state->boot_fd = -1;
	state->lease_fd = state->root_fd = state->zfs_fd = -1;
	bsdfilesystem_config_defaults(&state->cfg);
}

ATF_TC_WITHOUT_HEAD(invalid_resources);
ATF_TC_BODY(invalid_resources, tc)
{
	struct bsdfilesystem_state state;
	int file, directory, pipes[2], sockets[2], descriptors[4];

	file = open("ordinary", O_CREAT | O_RDWR, 0600);
	directory = open(".", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(file >= 0 && directory >= 0);
	ATF_REQUIRE_EQ(0, pipe(pipes));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sockets));
	descriptors[0] = file; descriptors[1] = directory;
	descriptors[2] = pipes[0]; descriptors[3] = sockets[0];
	for (unsigned i = 0; i < nitems(descriptors); i++) {
		initialize(&state);
		ATF_CHECK_EQ(-1, bsdfilesystem_layout_provision_fd(&state, descriptors[i]));
		ATF_CHECK(fcntl(descriptors[i], F_GETFD) >= 0);
		ATF_CHECK_EQ(-1, state.persistent_fd);
		ATF_CHECK_EQ(-1, state.ephemeral_fd);
		ATF_CHECK_EQ(-1, state.boot_fd);
		strlcpy(state.cfg.persistent, "outside/data", sizeof(state.cfg.persistent));
		ATF_CHECK_ERRNO(EINVAL,
		    bsdfilesystem_layout_provision_fd(&state, descriptors[i]) == -1);
	}
	close(file); close(directory); close(pipes[0]); close(pipes[1]);
	close(sockets[0]); close(sockets[1]);
}

static int
confined_provision(int base, bool write_data)
{
	struct bsdfilesystem_state state;
	char contents[8] = {0};
	int directory, file;

	initialize(&state);
	strlcpy(state.cfg.pool, zht_pool, sizeof(state.cfg.pool));
	snprintf(state.cfg.base, sizeof(state.cfg.base), "%s/delegated", zht_pool);
	snprintf(state.cfg.persistent, sizeof(state.cfg.persistent), "%s/delegated/state", zht_pool);
	snprintf(state.cfg.ephemeral, sizeof(state.cfg.ephemeral), "%s/delegated/transient", zht_pool);
	strlcpy(state.cfg.ephemeral_sync, "standard", sizeof(state.cfg.ephemeral_sync));
	if (cap_enter() == -1 || bsdfilesystem_layout_provision_fd(&state, base) == -1)
		return (1);
	/* An existing sibling cannot be reached through the delegated base. */
	if (tzfs_openat(base, "../outside", ZH_ALL_RIGHTS, ZHF_SUBTREE) != -1)
		return (2);
	directory = tzfs_mount(state.persistent_fd, false);
	if (directory == -1)
		return (3);
	file = openat(directory, "retained", write_data ? O_RDWR | O_CREAT : O_RDONLY, 0600);
	if (file == -1)
		return (4);
	if (write_data) {
		if (write(file, "persist", 7) != 7 || fsync(file) == -1)
			return (5);
	} else if (read(file, contents, sizeof(contents)) != 7 ||
	    strcmp(contents, "persist") != 0)
		return (6);
	close(file);
	close(directory);
	close(state.boot_fd);
	close(state.ephemeral_fd);
	close(state.persistent_fd);
	return (0);
}

ATF_TC_WITH_CLEANUP(bounded_provision);
ATF_TC_HEAD(bounded_provision, tc)
{
	atf_tc_set_md_var(tc, "descr", "provision and reuse a delegated subtree in Capsicum without a raw device or pool handle");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(bounded_provision, tc)
{
	struct bsdfilesystem_state state;
	char name[256];
	pid_t child;
	int base, narrow, pool, root, status;

	zht_require(tc);
	zht_pool_create(tc);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create -o mountpoint=none %s/delegated", zht_pool));
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create -o mountpoint=none %s/outside", zht_pool));
	snprintf(name, sizeof(name), "%s/delegated", zht_pool);
	base = tzfs_open(name, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(base >= 0);
	initialize(&state);
	strlcpy(state.cfg.base, name, sizeof(state.cfg.base));
	snprintf(state.cfg.persistent, sizeof(state.cfg.persistent), "%s/state", name);
	snprintf(state.cfg.ephemeral, sizeof(state.cfg.ephemeral), "%s/transient", name);
	narrow = tzfs_derive(base, ZH_IMPLICIT_RIGHTS);
	ATF_REQUIRE(narrow >= 0);
	ATF_CHECK_ERRNO(EACCES, bsdfilesystem_layout_provision_fd(&state, narrow) == -1);
	close(narrow);
	pool = tzfs_pool_open(zht_pool, ZH_ALL_RIGHTS);
	ATF_REQUIRE(pool >= 0);
	ATF_CHECK_EQ(-1, bsdfilesystem_layout_provision_fd(&state, pool));
	root = tzfs_pool_root_open(pool, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(root >= 0);
	ATF_CHECK_ERRNO(EACCES, bsdfilesystem_layout_provision_fd(&state, root) == -1);
	close(root);
	close(pool);
	for (unsigned pass = 0; pass < 2; pass++) {
		child = fork();
		ATF_REQUIRE(child >= 0);
		if (child == 0)
			_exit(confined_provision(base, pass == 0));
		ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "confined provisioning pass %u status=%#x", pass, status);
	}
	close(base);
}
ATF_TC_CLEANUP(bounded_provision, tc)
{
	char pool[128];

	zht_poolname(tc, pool, sizeof(pool));
	/* Anonymous-mount teardown may finish after the worker exits. A leak
	 * must fail cleanup instead of being hidden by the shared helper. */
	for (unsigned attempt = 0; attempt < 20; attempt++) {
		if (zht_systemf("zpool destroy -f %s", pool) == 0)
			return;
		usleep(100000);
	}
	fprintf(stderr, "could not destroy test pool %s\n", pool);
	exit(EXIT_FAILURE);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, invalid_resources);
	ATF_TP_ADD_TC(tp, bounded_provision);
	return (atf_no_error());
}
