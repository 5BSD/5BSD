/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Linux sysfs(2) filesystem-type enumeration for x86 Linux ABIs.
 */

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/systm.h>

#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>

/* Expose registered filesystems under names accepted by Linux applications. */
static const struct {
	const char *bsd_name;
	const char *linux_name;
} linux_sysfs_types[] = {
	{ "zfs", "zfs" },
	{ "tmpfs", "tmpfs" },
	{ "devfs", "devtmpfs" },
	{ "linprocfs", "proc" },
	{ "linsysfs", "sysfs" },
	{ "ext2fs", "ext2" },
	{ "msdosfs", "vfat" },
	{ "fusefs", "fuse" },
	{ "nfs", "nfs" },
};

static bool
linux_sysfs_registered(const char *name)
{
	struct vfsconf *vfc;

	vfc = vfs_byname(name);
	if (vfc == NULL)
		return (false);
	vfs_unref_vfsconf(vfc);
	return (true);
}

int
linux_sysfs(struct thread *td, struct linux_sysfs_args *uap)
{
	char *name;
	const char *result;
	size_t i, index, count;
	int error;
	bool found;

	if (uap->option < 1 || uap->option > 3)
		return (EINVAL);
	name = NULL;
	if (uap->option == 1) {
		name = malloc(PATH_MAX, M_TEMP, M_WAITOK);
		error = copyinstr((const void *)(uintptr_t)uap->arg1,
		    name, PATH_MAX, NULL);
		if (error != 0) {
			free(name, M_TEMP);
			return (error);
		}
	}
	index = 0;
	count = 0;
	found = false;
	result = NULL;
	for (i = 0; i < nitems(linux_sysfs_types); i++) {
		if (!linux_sysfs_registered(linux_sysfs_types[i].bsd_name))
			continue;
		if (uap->option == 1 &&
		    strcmp(name, linux_sysfs_types[i].linux_name) == 0) {
			index = count;
			found = true;
		}
		if (uap->option == 2 && count == uap->arg1)
			result = linux_sysfs_types[i].linux_name;
		count++;
	}
	if (uap->option == 1) {
		free(name, M_TEMP);
		if (!found)
			return (EINVAL);
		td->td_retval[0] = index;
		return (0);
	}
	if (uap->option == 3) {
		td->td_retval[0] = count;
		return (0);
	}
	if (result == NULL)
		return (EINVAL);
	return (copyout(result, (void *)(uintptr_t)uap->arg2,
	    strlen(result) + 1));
}
