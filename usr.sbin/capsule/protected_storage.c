/* SPDX-License-Identifier: BSD-2-Clause */
/* Boot-only storage acquisition. No ambient discovery or executable-name grants. */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/zfshandle.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/systeminfo.h>
#include <libzfs.h>
#include <libzutil.h>
#include <trustedzfs.h>
#include "protected_storage.h"

static struct capsule_config retained_policy;
static int *anchors;
static bool prepared;


/* Every leaf, including spares/cache devices, must be an explicit block device.
 * File-backed pools are unsuitable: their bytes could be writable ordinary data.
 * Compare device identities so an approved stable /dev/gptid alias works. */
static int
check_vdev(nvlist_t *vdev, const dev_t *devices, unsigned count,
    unsigned *seen, unsigned depth)
{
	static const char *const arrays[] = {
	    ZPOOL_CONFIG_CHILDREN, ZPOOL_CONFIG_SPARES, ZPOOL_CONFIG_L2CACHE
	};
	nvlist_t **children;
	const char *type, *path;
	struct stat st;
	uint_t nchildren;
	unsigned i, j;
	bool branch;

	if (depth > 32 || nvlist_lookup_string(vdev, ZPOOL_CONFIG_TYPE, &type) != 0)
		return (-1);
	branch = nvlist_exists(vdev, ZPOOL_CONFIG_CHILDREN);
	if (branch) {
		if (strcmp(type, VDEV_TYPE_ROOT) != 0 &&
		    strcmp(type, VDEV_TYPE_MIRROR) != 0 &&
		    strcmp(type, VDEV_TYPE_RAIDZ) != 0 &&
		    strcmp(type, VDEV_TYPE_REPLACING) != 0 &&
		    strcmp(type, VDEV_TYPE_SPARE) != 0)
			return (-1);
	} else {
		if (strcmp(type, VDEV_TYPE_DISK) != 0 ||
		    nvlist_lookup_string(vdev, ZPOOL_CONFIG_PATH, &path) != 0 ||
		    strncmp(path, "/dev/", 5) != 0 || stat(path, &st) != 0 ||
		    !S_ISCHR(st.st_mode))
			return (-1);
		for (i = 0; i < count; i++)
			if (devices[i] == st.st_rdev)
				break;
		if (i == count)
			return (-1);
		*seen |= 1U << i;
	}
	for (i = 0; i < nitems(arrays); i++) {
		if (!nvlist_exists(vdev, arrays[i]))
			continue;
		if (nvlist_lookup_nvlist_array(vdev, arrays[i], &children, &nchildren) != 0 ||
		    (i == 0 && nchildren == 0) || nchildren > 1024)
			return (-1);
		for (j = 0; j < nchildren; j++)
			if (check_vdev(children[j], devices, count, seen, depth + 1) != 0)
				return (-1);
	}
	return (0);
}

static int
check_pool(nvlist_t *pool, const struct capsule_storage *spec,
    const dev_t *devices)
{
	nvlist_t *tree;
	const char *name;
	uint64_t guid;
	unsigned seen = 0;

	if (pool == NULL ||
	    nvlist_lookup_string(pool, ZPOOL_CONFIG_POOL_NAME, &name) != 0 ||
	    nvlist_lookup_uint64(pool, ZPOOL_CONFIG_POOL_GUID, &guid) != 0 ||
	    guid != spec->pool_guid || strcmp(name, spec->pool) != 0 ||
	    nvlist_lookup_nvlist(pool, ZPOOL_CONFIG_VDEV_TREE, &tree) != 0 ||
	    check_vdev(tree, devices, spec->ndevices, &seen, 0) != 0 ||
	    seen != (1U << spec->ndevices) - 1)
		return (errno = EACCES, -1);
	return (0);
}

/* libzfs import does not perform zpool(8)'s userland force-import check.
 * Require the same host and MMP safety conditions; recovery is a separate path. */
bool
protected_storage_import_allowed(nvlist_t *candidate)
{
	nvlist_t *load;
	uint64_t state, host = 0, local_host, mmp;

	if (nvlist_lookup_uint64(candidate, ZPOOL_CONFIG_POOL_STATE, &state) != 0 ||
	    nvlist_lookup_nvlist(candidate, ZPOOL_CONFIG_LOAD_INFO, &load) != 0)
		return (false);
	if (state != POOL_STATE_EXPORTED && state != POOL_STATE_ACTIVE)
		return (false);
	if (nvlist_exists(load, ZPOOL_CONFIG_HOSTID)) {
		if (nvlist_lookup_uint64(load, ZPOOL_CONFIG_HOSTID, &host) != 0)
			return (false);
	} else if (nvlist_exists(candidate, ZPOOL_CONFIG_HOSTID) &&
	    nvlist_lookup_uint64(candidate, ZPOOL_CONFIG_HOSTID, &host) != 0)
		return (false);
	/* get_system_hostid() accepts ZFS_HOSTID for OpenZFS tests. Boot policy
	 * must use the kernel identity, and an unset identity cannot establish
	 * ownership of a pool that was not cleanly exported. */
	local_host = (unsigned long)gethostid() & HOSTID_MASK;
	if (state == POOL_STATE_ACTIVE && (local_host == 0 || host != local_host))
		return (false);
	if (nvlist_exists(load, ZPOOL_CONFIG_MMP_STATE) &&
	    (nvlist_lookup_uint64(load, ZPOOL_CONFIG_MMP_STATE, &mmp) != 0 ||
	    mmp != MMP_STATE_INACTIVE))
		return (false);
	return (true);
}

static int
protected_storage_acquire(const struct capsule_storage *spec, bool bootstrap)
{
	libzfs_handle_t *zfs = NULL;
	zpool_handle_t *pool = NULL;
	nvlist_t *pools = NULL, *candidate = NULL, *props = NULL, *config;
	nvpair_t *pair = NULL;
	importargs_t args = {0};
	libpc_handle_t importer = {0};
	struct zfd_info_args info = {0};
	struct zfd_stat_args ds = {0};
	struct stat st;
	dev_t devices[CAPSULE_STORAGE_DEVICES_MAX];
	char *paths[CAPSULE_STORAGE_DEVICES_MAX];
	int fd = -1, error = EACCES;
	unsigned i, j;

	if (spec == NULL || spec->ndevices == 0 ||
	    spec->ndevices > CAPSULE_STORAGE_DEVICES_MAX ||
	    spec->pool_guid == 0 || spec->dataset_guid == 0 ||
	    (spec->rights & ~ZH_ALL_RIGHTS) != 0 ||
	    (spec->rights & ZH_IMPLICIT_RIGHTS) != ZH_IMPLICIT_RIGHTS)
		return (errno = EINVAL, -1);
	for (i = 0; i < spec->ndevices; i++) {
		if (stat(spec->devices[i], &st) != 0 || !S_ISCHR(st.st_mode))
			return (errno = EACCES, -1);
		devices[i] = st.st_rdev;
		paths[i] = __DECONST(char *, spec->devices[i]);
		for (j = 0; j < i; j++)
			if (devices[j] == devices[i])
				return (errno = EINVAL, -1);
	}
	/* Require a boot-loaded module. libzfs must not invoke a module loader. */
	if (stat("/dev/zfs", &st) != 0 || !S_ISCHR(st.st_mode))
		return (errno = ENXIO, -1);
	zfs = libzfs_init();
	if (zfs == NULL)
		return (-1);
	libzfs_print_on_error(zfs, B_FALSE);
	pool = zpool_open_canfail(zfs, spec->pool);
	if (pool == NULL) {
		args.path = paths;
		args.paths = spec->ndevices;
		args.guid = spec->pool_guid;
		/* No cache, default scan, force, destroyed pools or rewind flags. */
		importer.lpc_lib_handle = zfs;
		importer.lpc_ops = &libzfs_config_ops;
		pools = zpool_search_import(&importer, &args);
		while (pools != NULL && (pair = nvlist_next_nvpair(pools, pair)) != NULL) {
			if (nvpair_value_nvlist(pair, &config) != 0 || candidate != NULL)
				goto out;
			candidate = config;
		}
		if (candidate == NULL || check_pool(candidate, spec, devices) != 0 ||
		    !protected_storage_import_allowed(candidate))
			goto out;
		if (nvlist_alloc(&props, NV_UNIQUE_NAME, 0) != 0 ||
		    nvlist_add_string(props, "cachefile", "none") != 0)
			goto out;
		/* This imports only the selected pool; it does not mount datasets. */
		if (zpool_import_props(zfs, candidate, NULL, props, ZFS_IMPORT_ONLY) != 0)
			goto out;
		pool = zpool_open_canfail(zfs, spec->pool);
	}
	if (pool == NULL || check_pool(zpool_get_config(pool, NULL), spec, devices) != 0)
		goto out;
	fd = tzfs_open(spec->dataset, spec->rights, ZHF_SUBTREE);
	if (fd < 0) {
		error = errno;
		goto out;
	}
	if (tzfs_info(fd, &info) != 0 || tzfs_stat(fd, &ds) != 0 ||
	    !info.zi_valid || info.zi_pool_guid != spec->pool_guid ||
	    info.zi_ds_guid != spec->dataset_guid || ds.zs_ds_guid != spec->dataset_guid ||
	    info.zi_flags != ZHF_SUBTREE || info.zi_rights != spec->rights ||
	    strcmp(info.zi_name, spec->dataset) != 0 || strchr(info.zi_name, '/') == NULL ||
	    (!bootstrap && tzfs_limit_dataset_ioctls_by_rights(fd, spec->rights, ZHF_SUBTREE) != 0)) {
		close(fd);
		fd = -1;
	}
out:
	if (pool != NULL)
		zpool_close(pool);
	if (props != NULL)
		nvlist_free(props);
	if (pools != NULL)
		nvlist_free(pools);
	libzfs_fini(zfs);
	if (fd == -1)
		errno = error;
	return (fd);
}

int
protected_storage_open(const struct capsule_storage *spec)
{
	return (protected_storage_acquire(spec, false));
}

/* Establish the configured host identity before libzfs imports a pool.
 * Verify both values before publishing any handles.
 * Any partial setup failure is fatal to startup; no pool is imported. */
static int
prepare_host_identity(const char *uuid)
{
	unsigned long id, actual_id;
	char actual_uuid[37];
	size_t size;

	if (!config_hostid(uuid, &id))
		return (errno = EINVAL, -1);
	if (sysctlbyname("kern.hostuuid", NULL, NULL, __DECONST(char *, uuid),
	    strlen(uuid) + 1) != 0 ||
	    sysctlbyname("kern.hostid", NULL, NULL, &id, sizeof(id)) != 0)
		return (-1);
	size = sizeof(actual_uuid);
	if (sysctlbyname("kern.hostuuid", actual_uuid, &size, NULL, 0) != 0)
		return (-1);
	if (size != sizeof(actual_uuid) || memcmp(uuid, actual_uuid, size) != 0)
		return (errno = EIO, -1);
	size = sizeof(actual_id);
	if (sysctlbyname("kern.hostid", &actual_id, &size, NULL, 0) != 0)
		return (-1);
	if (size != sizeof(actual_id) || actual_id != id)
		return (errno = EIO, -1);
	return (0);
}

int
protected_storage_prepare(const struct capsule_config *cfg)
{
	unsigned i;
	int *pending = NULL, saved;
	struct capsule_config retained = {0};

	if (cfg == NULL)
		return (errno = EINVAL, -1);
	if (prepared)
		return (config_boot_policy_equal(cfg, &retained_policy) ? 0 : (errno = EPERM, -1));
	if (cfg->nstorage == 0 && cfg->hostuuid[0] == '\0')
		return (0);
	if (getpid() != 1 || cfg->nstorage > CAPSULE_STORAGE_MAX)
		return (errno = EPERM, -1);
	/* Allocate independent policy and bookkeeping before boot side effects. */
	if (config_copy(&retained, cfg) != 0)
		return (-1);
	if (cfg->nstorage != 0) {
		pending = malloc(cfg->nstorage * sizeof(*pending));
		if (pending == NULL) {
			saved = ENOMEM;
			goto release;
		}
	}
	for (i = 0; i < cfg->nstorage; i++)
		pending[i] = -1;
	if (prepare_host_identity(cfg->hostuuid) != 0)
		goto fail;
	for (i = 0; i < cfg->nstorage; i++) {
		pending[i] = protected_storage_acquire(&cfg->storage[i], true);
		if (pending[i] == -1)
			goto fail;
	}
	/* Publish anchors only after all descriptor limits succeed. */
	for (i = 0; i < cfg->nstorage; i++) {
		if (tzfs_limit_dataset_ioctls_by_rights(pending[i],
		    cfg->storage[i].rights, ZHF_SUBTREE) == -1)
			goto fail;
		if (pending[i] == -1 || cap_xfer_limit(pending[i], CAP_XFER_NONE) == -1 ||
		    cap_clofork_limit(pending[i], CAP_CLOFORK_LOCKED) == -1 ||
		    cap_cloexec_limit(pending[i], CAP_CLOEXEC_LOCKED) == -1)
			goto fail;
	}
	retained_policy = retained;
	anchors = pending;
	prepared = true;
	return (0);
fail:
	saved = errno;
	for (i = 0; i < cfg->nstorage; i++) {
		if (pending[i] >= 0) close(pending[i]);
	}
release:
	free(pending);
	config_free(&retained);
	return (errno = saved, -1);
}


int
protected_storage_derive(const char *recipient)
{
	unsigned i;
	int fd;

	if (getpid() != 1)
		return (errno = EPERM, -1);
	if (!prepared)
		return (errno = ENOENT, -1);
	for (i = 0; i < retained_policy.nstorage; i++)
		if (strcmp(retained_policy.storage[i].recipient, recipient) == 0) {
			fd = tzfs_derive(anchors[i], retained_policy.storage[i].rights);
			if (fd == -1)
				return (-1);
			return (fd);
		}
	return (errno = ENOENT, -1);
}


