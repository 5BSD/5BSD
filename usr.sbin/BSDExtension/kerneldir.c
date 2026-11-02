/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The running kernel's module directory for bsdextension(8).
 *
 * The hardware-driver class reads the directory's linker.hints and root loads
 * check and load module files from it, so it must be the directory of the
 * kernel that is running, and the same directory the kernel resolves when the
 * broker loads by absolute path.  The manifest delivers /boot by descriptor.
 * The directory's name comes from the pathname of kernel file id 1, which the
 * loader recorded at boot and nothing changes afterwards (kern.bootfile is a
 * root-writable string and is not used).  A directory is accepted only while
 * its kernel file carries the running kernel's GNU build-id (kern.build_id,
 * computed by the kernel from its own image).
 *
 * The directory is opened once, and reopened by name beneath /boot before and
 * after every use that leads to a load (sysext_kernel_dir_check()):
 *
 *  - the same directory (device and inode) with the running kernel: used;
 *  - another directory under that name (installkernel renames kernel to
 *    kernel.old and installs a new kernel directory; a mount over it) that
 *    holds the running kernel: adopted, the handle is replaced and logged;
 *  - another directory, or the same one whose kernel file was replaced in
 *    place (a kernel package upgrade before the reboot): refused and logged.
 *    Its modules belong to another kernel; loading them into this one is
 *    never right, so driver and root loads wait for the reboot.
 *
 * A root that replaces /boot itself, or edits files in place, still defeats a
 * path-based load; mac_veriexec(4) is the control against a compromised root.
 */

#include <sys/param.h>
#include <sys/elf.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "bsdextension.h"

#define	BUILD_ID_NOTES_MAX	(64 * 1024)	/* bound on PT_NOTE contents */
#define	BUILD_ID_PHDRS_MAX	64

int sysext_boot_dirfd = -1;
char sysext_kernel_dir[MAXPATHLEN];

/* The kernel directory's name beneath /boot and the kernel file's name. */
static char kernel_dir_name[NAME_MAX + 1];
static char kernel_file_name[NAME_MAX + 1];
static pthread_mutex_t kernel_dir_lock = PTHREAD_MUTEX_INITIALIZER;

#ifdef BSDEXTENSION_TESTING
const char *sysext_test_build_id;
#endif

static int
running_build_id(char *out, size_t outlen)
{
	size_t len = outlen;

#ifdef BSDEXTENSION_TESTING
	if (sysext_test_build_id != NULL) {
		if (strlcpy(out, sysext_test_build_id, outlen) >= outlen)
			return (ENAMETOOLONG);
		return (0);
	}
#endif
	/* CTLFLAG_CAPRD: readable in capability mode. */
	if (sysctlbyname("kern.build_id", out, &len, NULL, 0) == -1)
		return (errno);
	if (len == 0 || memchr(out, '\0', len) == NULL || out[0] == '\0')
		return (EINVAL);
	return (0);
}

static int
read_all(int fd, void *buf, size_t len, off_t off)
{
	ssize_t n;

	n = pread(fd, buf, len, off);
	if (n == -1)
		return (errno);
	return ((size_t)n == len ? 0 : EFTYPE);
}

/*
 * The hex GNU build-id note of a native ELF file, from its PT_NOTE segments.
 * Every size and offset is bounded; anything unexpected is EFTYPE.
 */
int
sysext_elf_build_id(int fd, char *out, size_t outlen)
{
	static const char hex[] = "0123456789abcdef";
	Elf_Ehdr eh;
	Elf_Phdr ph[BUILD_ID_PHDRS_MAX];
	Elf_Note nh;
	unsigned char *notes;
	size_t pos, namesz, descsz, i;
	int error, n;

	if ((error = read_all(fd, &eh, sizeof(eh), 0)) != 0)
		return (error);
	if (!IS_ELF(eh) || eh.e_ident[EI_CLASS] != ELF_TARG_CLASS ||
	    eh.e_ident[EI_DATA] != ELF_TARG_DATA ||
	    eh.e_phentsize != sizeof(Elf_Phdr) || eh.e_phnum == 0 ||
	    eh.e_phnum > BUILD_ID_PHDRS_MAX)
		return (EFTYPE);
	if ((error = read_all(fd, ph, eh.e_phnum * sizeof(Elf_Phdr),
	    (off_t)eh.e_phoff)) != 0)
		return (error);
	for (n = 0; n < eh.e_phnum; n++) {
		if (ph[n].p_type != PT_NOTE || ph[n].p_filesz == 0 ||
		    ph[n].p_filesz > BUILD_ID_NOTES_MAX)
			continue;
		if ((notes = malloc(ph[n].p_filesz)) == NULL)
			return (ENOMEM);
		if ((error = read_all(fd, notes, ph[n].p_filesz,
		    (off_t)ph[n].p_offset)) != 0) {
			free(notes);
			return (error);
		}
		for (pos = 0; ph[n].p_filesz - pos >= sizeof(nh);) {
			memcpy(&nh, notes + pos, sizeof(nh));
			pos += sizeof(nh);
			namesz = roundup2((size_t)nh.n_namesz, 4);
			descsz = roundup2((size_t)nh.n_descsz, 4);
			if (namesz > ph[n].p_filesz - pos ||
			    descsz > ph[n].p_filesz - pos - namesz)
				break;
			if (nh.n_type == NT_GNU_BUILD_ID && nh.n_namesz == 4 &&
			    memcmp(notes + pos, "GNU", 4) == 0) {
				if (nh.n_descsz == 0 ||
				    nh.n_descsz * 2 + 1 > outlen) {
					free(notes);
					return (EFTYPE);
				}
				for (i = 0; i < nh.n_descsz; i++) {
					out[2 * i] =
					    hex[notes[pos + namesz + i] >> 4];
					out[2 * i + 1] =
					    hex[notes[pos + namesz + i] & 0xf];
				}
				out[2 * i] = '\0';
				free(notes);
				return (0);
			}
			pos += namesz + descsz;
		}
		free(notes);
	}
	return (EFTYPE);
}

/* The directory's kernel file is the running kernel; detail says why not. */
static bool
holds_running_kernel(int dirfd, char *detail, size_t detaillen)
{
	char running[SYSEXT_BUILD_ID_MAX], found[SYSEXT_BUILD_ID_MAX];
	struct stat st;
	int fd, error;

	if ((error = running_build_id(running, sizeof(running))) != 0) {
		(void)snprintf(detail, detaillen, "kern.build_id: %s",
		    strerror(error));
		return (false);
	}
	/* Refuse a non-regular file before an open that could block. */
	if (fstatat(dirfd, kernel_file_name, &st, AT_SYMLINK_NOFOLLOW) == -1 ||
	    !S_ISREG(st.st_mode)) {
		(void)snprintf(detail, detaillen, "%s/%s is not a regular file",
		    sysext_kernel_dir, kernel_file_name);
		return (false);
	}
	fd = openat(dirfd, kernel_file_name, O_RDONLY | O_NOFOLLOW |
	    O_CLOEXEC | O_NONBLOCK);
	if (fd == -1) {
		(void)snprintf(detail, detaillen, "%s/%s: %s",
		    sysext_kernel_dir, kernel_file_name, strerror(errno));
		return (false);
	}
	error = sysext_elf_build_id(fd, found, sizeof(found));
	(void)close(fd);
	if (error != 0) {
		(void)snprintf(detail, detaillen, "%s/%s: no build-id: %s",
		    sysext_kernel_dir, kernel_file_name, strerror(error));
		return (false);
	}
	if (strcmp(found, running) != 0) {
		(void)snprintf(detail, detaillen, "%s/%s (build-id %s) is not "
		    "the running kernel (build-id %s)", sysext_kernel_dir,
		    kernel_file_name, found, running);
		return (false);
	}
	return (true);
}

static int
open_kernel_dir(void)
{

	return (openat(sysext_boot_dirfd, kernel_dir_name, O_RDONLY |
	    O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
}

int
sysext_kernel_dir_open(void)
{
	char name[MAXPATHLEN], path[MAXPATHLEN], detail[384];
	const char *dir, *file;
	int fd, error;

	if (sysext_boot_dirfd < 0)
		return (EBADF);
	/* File id 1 is the kernel; its pathname is the loader's boot path. */
	if ((error = sysext_kld_stat(1, name, sizeof(name), path,
	    sizeof(path))) != 0)
		return (error);
	if (strncmp(path, SYSEXT_BOOT_DIR "/", sizeof(SYSEXT_BOOT_DIR)) != 0) {
		syslog(LOG_WARNING, "kernel %s was not booted from %s", path,
		    SYSEXT_BOOT_DIR);
		return (ENOENT);
	}
	dir = path + sizeof(SYSEXT_BOOT_DIR);
	file = strchr(dir, '/');
	if (file != NULL && file != dir &&
	    (size_t)(file - dir) < sizeof(kernel_dir_name)) {
		memcpy(kernel_dir_name, dir, file - dir);
		kernel_dir_name[file - dir] = '\0';
	}
	if (file == NULL || file == dir || strchr(file + 1, '/') != NULL ||
	    file[1] == '\0' || (size_t)(file - dir) >= sizeof(kernel_dir_name) ||
	    strcmp(kernel_dir_name, ".") == 0 ||
	    strcmp(kernel_dir_name, "..") == 0) {
		kernel_dir_name[0] = '\0';
		syslog(LOG_WARNING, "kernel %s is not in a directory of %s",
		    path, SYSEXT_BOOT_DIR);
		return (ENOENT);
	}
	(void)strlcpy(kernel_file_name, file + 1, sizeof(kernel_file_name));
	(void)snprintf(sysext_kernel_dir, sizeof(sysext_kernel_dir), "%s/%s",
	    SYSEXT_BOOT_DIR, kernel_dir_name);
	if ((fd = open_kernel_dir()) == -1)
		return (errno);
	if (!holds_running_kernel(fd, detail, sizeof(detail))) {
		syslog(LOG_WARNING, "%s: %s", sysext_kernel_dir, detail);
		(void)close(fd);
		return (ESTALE);
	}
	sysext_driver_dirfd = fd;
	return (0);
}

int
sysext_kernel_dir_check(char *detail, size_t detaillen)
{
	struct stat held, now;
	char why[384];
	int fd, error = 0;

	detail[0] = '\0';
	if (sysext_driver_dirfd < 0 || sysext_boot_dirfd < 0) {
		(void)snprintf(detail, detaillen, "the running kernel's module "
		    "directory is not available");
		return (ENOENT);
	}
	pthread_mutex_lock(&kernel_dir_lock);
	fd = open_kernel_dir();
	if (fd == -1 || fstat(fd, &now) == -1 ||
	    fstat(sysext_driver_dirfd, &held) == -1) {
		error = errno;
		(void)snprintf(detail, detaillen, "%s: %s", sysext_kernel_dir,
		    strerror(error));
		goto out;
	}
	if (now.st_dev == held.st_dev && now.st_ino == held.st_ino) {
		if (!holds_running_kernel(sysext_driver_dirfd, why,
		    sizeof(why))) {
			error = ESTALE;
			(void)snprintf(detail, detaillen, "%s; loads wait for "
			    "the reboot", why);
		}
		goto out;
	}
	if (!holds_running_kernel(fd, why, sizeof(why))) {
		error = ESTALE;
		(void)snprintf(detail, detaillen, "%s was replaced since the "
		    "broker started: %s; loads wait for the reboot",
		    sysext_kernel_dir, why);
		goto out;
	}
	/* A new directory with the running kernel: replace the handle. */
	if (dup3(fd, sysext_driver_dirfd, O_CLOEXEC) == -1) {
		error = errno;
		(void)snprintf(detail, detaillen, "%s: %s", sysext_kernel_dir,
		    strerror(error));
		goto out;
	}
	syslog(LOG_NOTICE, "%s was replaced by a directory with the running "
	    "kernel; using the new directory", sysext_kernel_dir);
out:
	if (error != 0)
		syslog(LOG_WARNING, "kernel directory refused: %s", detail);
	pthread_mutex_unlock(&kernel_dir_lock);
	if (fd != -1)
		(void)close(fd);
	return (error);
}

/* The running kernel file's name, for dependencies the kernel provides. */
const char *
sysext_kernel_file_name(void)
{

	return (kernel_file_name);
}
