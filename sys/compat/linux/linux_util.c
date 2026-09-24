/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1994 Christos Zoulas
 * Copyright (c) 1995 Frank van der Linden
 * Copyright (c) 1995 Scott Bartram
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *	from: svr4_util.c,v 1.5 1995/01/22 23:44:50 christos Exp
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/jail.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/stdarg.h>
#include <sys/syscallsubr.h>
#include <sys/vnode.h>

#include <compat/linux/linux_dtrace.h>
#include <compat/linux/linux_mib.h>
#include <compat/linux/linux_util.h>

MALLOC_DEFINE(M_LINUX, "linux", "Linux mode structures");
MALLOC_DEFINE(M_EPOLL, "lepoll", "Linux events structures");

FEATURE(linuxulator_v4l, "V4L ioctl wrapper support in the linuxulator");
FEATURE(linuxulator_v4l2, "V4L2 ioctl wrapper support in the linuxulator");

/**
 * Special DTrace provider for the linuxulator.
 *
 * In this file we define the provider for the entire linuxulator. All
 * modules (= files of the linuxulator) use it.
 *
 * We define a different name depending on the emulated bitsize, see
 * ../../<ARCH>/linux{,32}/linux.h, e.g.:
 *      native bitsize          = linuxulator
 *      amd64, 32bit emulation  = linuxulator32
 */
LIN_SDT_PROVIDER_DEFINE(linuxulator);
LIN_SDT_PROVIDER_DEFINE(linuxulator32);

char linux_emul_path[MAXPATHLEN] = "/compat/linux";

SYSCTL_STRING(_compat_linux, OID_AUTO, emul_path, CTLFLAG_RWTUN,
    linux_emul_path, sizeof(linux_emul_path),
    "Linux runtime environment path");

int
linux_pwd_onexec(struct thread *td)
{
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, linux_emul_path);
	error = namei(&nd);
	if (error != 0) {
		/* Do not prevent execution if altroot is non-existent. */
		pwd_altroot(td, NULL);
		return (0);
	}
	NDFREE_PNBUF(&nd);
	pwd_altroot(td, nd.ni_vp);
	vrele(nd.ni_vp);
	return (0);
}

void
linux_pwd_onexec_native(struct thread *td)
{

	pwd_altroot(td, NULL);
}

void
linux_msg(const struct thread *td, const char *fmt, ...)
{
	va_list ap;
	struct proc *p;

	if (linux_debug == 0)
		return;

	p = td->td_proc;
	printf("linux: jid %d pid %d (%s): ", p->p_ucred->cr_prison->pr_id,
	    (int)p->p_pid, p->p_comm);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

struct device_element
{
	TAILQ_ENTRY(device_element) list;
	struct linux_device_handler entry;
};

static TAILQ_HEAD(, device_element) devices =
	TAILQ_HEAD_INITIALIZER(devices);

static struct linux_device_handler null_handler =
	{ "mem", "mem", "null", "null", 1, 3, 1};

DATA_SET(linux_device_handler_set, null_handler);

char *
linux_driver_get_name_dev(device_t dev)
{
	struct device_element *de;
	const char *device_name = device_get_name(dev);

	if (device_name == NULL)
		return (NULL);
	TAILQ_FOREACH(de, &devices, list) {
		if (strcmp(device_name, de->entry.bsd_driver_name) == 0)
			return (de->entry.linux_driver_name);
	}

	return (NULL);
}

int
linux_driver_get_major_minor(const char *node, int *major, int *minor)
{
	struct device_element *de;
	unsigned long devno;
	size_t sz;

	if (node == NULL || major == NULL || minor == NULL)
		return (1);

	sz = sizeof("pts/") - 1;
	if (strncmp(node, "pts/", sz) == 0 && node[sz] != '\0') {
		/*
		 * Linux checks major and minors of the slave device
		 * to make sure it's a pty device, so let's make him
		 * believe it is.
		 */
		devno = strtoul(node + sz, NULL, 10);
		*major = 136 + (devno / 256);
		*minor = devno % 256;
		return (0);
	}

	sz = sizeof("dri/card") - 1;
	if (strncmp(node, "dri/card", sz) == 0 && node[sz] != '\0') {
		devno = strtoul(node + sz, NULL, 10);
		*major = 226 + (devno / 256);
		*minor = devno % 256;
		return (0);
	}
	sz = sizeof("dri/controlD") - 1;
	if (strncmp(node, "dri/controlD", sz) == 0 && node[sz] != '\0') {
		devno = strtoul(node + sz, NULL, 10);
		*major = 226 + (devno / 256);
		*minor = devno % 256;
		return (0);
	}
	sz = sizeof("dri/renderD") - 1;
	if (strncmp(node, "dri/renderD", sz) == 0 && node[sz] != '\0') {
		devno = strtoul(node + sz, NULL, 10);
		*major = 226 + (devno / 256);
		*minor = devno % 256;
		return (0);
	}
	sz = sizeof("drm/") - 1;
	if (strncmp(node, "drm/", sz) == 0 && node[sz] != '\0') {
		devno = strtoul(node + sz, NULL, 10);
		*major = 226 + (devno / 256);
		*minor = devno % 256;
		return (0);
	}

	TAILQ_FOREACH(de, &devices, list) {
		if (strcmp(node, de->entry.bsd_device_name) == 0) {
			*major = de->entry.linux_major;
			*minor = de->entry.linux_minor;
			return (0);
		}
	}

	return (1);
}

int
linux_vn_get_major_minor(const struct vnode *vp, int *major, int *minor)
{
	int error;

	if (vp->v_type != VCHR)
		return (ENOTBLK);
	dev_lock();
	if (vp->v_rdev == NULL) {
		dev_unlock();
		return (ENXIO);
	}
	error = linux_driver_get_major_minor(devtoname(vp->v_rdev),
	    major, minor);
	dev_unlock();
	return (error);
}

void
translate_vnhook_major_minor(struct vnode *vp, struct stat *sb)
{
	int major, minor;

	if (vn_isdisk(vp)) {
		sb->st_mode &= ~S_IFMT;
		sb->st_mode |= S_IFBLK;
	}

	/*
	 * Return the same st_dev for every devfs instance.  The reason
	 * for this is to work around an idiosyncrasy of glibc getttynam()
	 * implementation: it checks whether st_dev returned for fd 0
	 * is the same as st_dev returned for the target of /proc/self/fd/0
	 * symlink, and with linux chroots having their own devfs instance,
	 * the check will fail if you chroot into it.
	 */
	if (rootdevmp != NULL && vp->v_mount->mnt_vfc == rootdevmp->mnt_vfc)
		sb->st_dev = rootdevmp->mnt_stat.f_fsid.val[0];

	if (linux_vn_get_major_minor(vp, &major, &minor) == 0)
		sb->st_rdev = makedev(major, minor);
}

char *
linux_get_char_devices(void)
{
	struct device_element *de;
	char *temp, *string, *last;
	char formated[256];
	int current_size = 0, string_size = 1024;

	string = malloc(string_size, M_LINUX, M_WAITOK);
	string[0] = '\000';
	last = "";
	TAILQ_FOREACH(de, &devices, list) {
		if (!de->entry.linux_char_device)
			continue;
		temp = string;
		if (strcmp(last, de->entry.bsd_driver_name) != 0) {
			last = de->entry.bsd_driver_name;

			snprintf(formated, sizeof(formated), "%3d %s\n",
				 de->entry.linux_major,
				 de->entry.linux_device_name);
			if (strlen(formated) + current_size
			    >= string_size) {
				string_size *= 2;
				string = malloc(string_size,
				    M_LINUX, M_WAITOK);
				bcopy(temp, string, current_size);
				free(temp, M_LINUX);
			}
			strcat(string, formated);
			current_size = strlen(string);
		}
	}

	return (string);
}

void
linux_free_get_char_devices(char *string)
{

	free(string, M_LINUX);
}

static int linux_major_starting = 200;

int
linux_device_register_handler(struct linux_device_handler *d)
{
	struct device_element *de;

	if (d == NULL)
		return (EINVAL);

	de = malloc(sizeof(*de), M_LINUX, M_WAITOK);
	if (d->linux_major < 0) {
		d->linux_major = linux_major_starting++;
	}
	bcopy(d, &de->entry, sizeof(*d));

	/* Add the element to the list, sorted on span. */
	TAILQ_INSERT_TAIL(&devices, de, list);

	return (0);
}

int
linux_device_unregister_handler(struct linux_device_handler *d)
{
	struct device_element *de;

	if (d == NULL)
		return (EINVAL);

	TAILQ_FOREACH(de, &devices, list) {
		if (bcmp(d, &de->entry, sizeof(*d)) == 0) {
			TAILQ_REMOVE(&devices, de, list);
			free(de, M_LINUX);

			return (0);
		}
	}

	return (EINVAL);
}

/* Legacy mountinfo IDs are positive signed ints (including in libmount). */
struct linux_mount_entry {
	LIST_ENTRY(linux_mount_entry) link;
	struct mount *mp;
	int generation;
	int id;
};
static LIST_HEAD(, linux_mount_entry) linux_mount_entries =
    LIST_HEAD_INITIALIZER(linux_mount_entries);
static struct mtx linux_mount_mtx;
MTX_SYSINIT(linux_mount_ids, &linux_mount_mtx, "Linux mount IDs", MTX_DEF);
static struct unrhdr *linux_mount_unr;
static eventhandler_tag linux_unmount_tag;

static void
linux_mount_unmounted(void *arg, struct mount *mp, struct thread *td)
{
	struct linux_mount_entry *entry;

	mtx_lock(&linux_mount_mtx);
	LIST_FOREACH(entry, &linux_mount_entries, link) {
		if (entry->mp == mp && entry->generation == mp->mnt_gen) {
			LIST_REMOVE(entry, link);
			break;
		}
	}
	mtx_unlock(&linux_mount_mtx);
	if (entry != NULL) {
		free_unr(linux_mount_unr, entry->id);
		free(entry, M_LINUX);
	}
}

void
linux_mount_id_init(void)
{
	linux_mount_unr = new_unrhdr(1, INT_MAX, NULL);
	linux_unmount_tag = EVENTHANDLER_REGISTER(vfs_unmounted,
	    linux_mount_unmounted, NULL, EVENTHANDLER_PRI_ANY);
}

void
linux_mount_id_uninit(void)
{
	struct linux_mount_entry *entry;

	EVENTHANDLER_DEREGISTER(vfs_unmounted, linux_unmount_tag);
	/* All Linuxulator consumers are gone before linux_common unloads. */
	while ((entry = LIST_FIRST(&linux_mount_entries)) != NULL) {
		LIST_REMOVE(entry, link);
		free_unr(linux_mount_unr, entry->id);
		free(entry, M_LINUX);
	}
	delete_unrhdr(linux_mount_unr);
}

/* The caller must keep mp alive, for example with a locked vnode. */
uint64_t
linux_mount_id(struct mount *mp)
{
	struct linux_mount_entry *entry, *candidate = NULL;
	int id = 0;

	if (mp == NULL)
		return (0);
again:
	/* Serialize the final insertion with unmount's transition and callback. */
	MNT_ILOCK(mp);
	if ((mp->mnt_kern_flag & MNTK_UNMOUNT) != 0) {
		MNT_IUNLOCK(mp);
		goto out;
	}
	mtx_lock(&linux_mount_mtx);
	LIST_FOREACH(entry, &linux_mount_entries, link) {
		if (entry->mp == mp && entry->generation == mp->mnt_gen) {
			id = entry->id;
			break;
		}
	}
	if (entry == NULL && candidate != NULL) {
		candidate->mp = mp;
		candidate->generation = mp->mnt_gen;
		id = candidate->id;
		LIST_INSERT_HEAD(&linux_mount_entries, candidate, link);
		candidate = NULL;
	}
	mtx_unlock(&linux_mount_mtx);
	MNT_IUNLOCK(mp);
	if (id == 0) {
		candidate = malloc(sizeof(*candidate), M_LINUX, M_WAITOK);
		candidate->id = alloc_unr(linux_mount_unr);
		if (candidate->id == -1) {
			free(candidate, M_LINUX);
			return (0);
		}
		goto again;
	}
out:
	if (candidate != NULL) {
		free_unr(linux_mount_unr, candidate->id);
		free(candidate, M_LINUX);
	}
	return (id);
}

/* A file reference alone does not prevent forced unmount from reclaiming vp. */
uint64_t
linux_vnode_mount_id(struct vnode *vp)
{
	uint64_t id;

	vn_lock(vp, LK_SHARED | LK_RETRY);
	id = VN_IS_DOOMED(vp) ? 0 : linux_mount_id(vp->v_mount);
	VOP_UNLOCK(vp);
	return (id);
}
