/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Preloaded by the frontend-runtime-open/-provider/-module suites.  It keeps
 * libdtrace away from the real tracing device and kernel linker:
 *  - open() of any /dev/dtrace/ path is answered from a scripted table: a
 *    descriptor for /dev/null standing in for the device, or an errno.  The
 *    real /dev/dtrace is never opened.
 *  - kldload() is recorded and always fails (EPERM); modfind() is scripted.
 *  - sysctlbyname("debug.dtrace.providers" / "kern.bootfile") is scripted.
 *  - ioctl() on a stand-in descriptor (one that refers to /dev/null) goes to
 *    a callback installed by the harness; other ioctls pass through.
 *  - kldnext/kldstat/kldfirstmod/modnext/modstat can be redirected to a
 *    harness-supplied module list (dt_module.c's kernel enumeration).
 *  - getrlimit() can be made to fail.
 * The harness configures it through the frontend_shim_* functions and must
 * check frontend_shim_active() before exercising a device path.
 */
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "frontend-runtime-shim.h"

static struct frontend_shim_dev devs[32];
static int ndevs;
static int kldloads;
static char kldload_names[8][64];
static int modfind_result[3] = { -1, -1, -1 };	/* dtraceall, linux64elf, linuxelf */
static const char *providers;		/* NULL: sysctl fails with ENOENT */
static int providers_enomem_once;
static const char *bootfile;		/* NULL: sysctl fails */
static int bootfile_set;
static frontend_shim_ioctl_f *ioctl_cb;
static void *ioctl_arg;
static int getrlimit_fail;
static const struct frontend_shim_kld *klds;
static int nklds, kld_active;
static int opens_seen;

int
frontend_shim_active(void)
{
	return (1);
}

void
frontend_shim_reset(void)
{
	ndevs = 0;
	kldloads = 0;
	modfind_result[0] = modfind_result[1] = modfind_result[2] = -1;
	providers = NULL;
	providers_enomem_once = 0;
	bootfile = NULL;
	bootfile_set = 0;
	ioctl_cb = NULL;
	getrlimit_fail = 0;
	opens_seen = 0;
}

void
frontend_shim_dev(const char *path, int err)
{
	if (ndevs < 32) {
		devs[ndevs].path = path;
		devs[ndevs].err = err;
		devs[ndevs].count = 0;
		ndevs++;
	}
}

int
frontend_shim_opens(const char *path)
{
	int i, n = 0;

	for (i = 0; i < ndevs; i++)
		if (path == NULL || strcmp(devs[i].path, path) == 0)
			n += devs[i].count;
	return (path == NULL ? opens_seen : n);
}

void
frontend_shim_modfind(int dtraceall, int linux64, int linux32)
{
	modfind_result[0] = dtraceall;
	modfind_result[1] = linux64;
	modfind_result[2] = linux32;
}

int
frontend_shim_kldloads(char names[][64], int max)
{
	int i;

	for (i = 0; i < kldloads && i < max && i < 8; i++)
		memcpy(names[i], kldload_names[i], 64);
	return (kldloads);
}

void
frontend_shim_providers(const char *list, int enomem_once)
{
	providers = list;
	providers_enomem_once = enomem_once;
}

void
frontend_shim_bootfile(const char *path)
{
	bootfile = path;
	bootfile_set = 1;
}

void
frontend_shim_ioctl(frontend_shim_ioctl_f *cb, void *arg)
{
	ioctl_cb = cb;
	ioctl_arg = arg;
}

void
frontend_shim_getrlimit_fail(int on)
{
	getrlimit_fail = on;
}

void
frontend_shim_klds(const struct frontend_shim_kld *list, int n)
{
	klds = list;
	nklds = n;
	kld_active = list != NULL;
}

static int
is_standin(int fd)
{
	struct stat a, b;

	return (fstat(fd, &a) == 0 && stat("/dev/null", &b) == 0 &&
	    S_ISCHR(a.st_mode) && a.st_rdev == b.st_rdev);
}

int
open(const char *path, int flags, ...)
{
	static int (*real)(const char *, int, ...);
	va_list ap;
	int mode = 0, i;

	va_start(ap, flags);
	if (flags & O_CREAT)
		mode = va_arg(ap, int);
	va_end(ap);
	if (strncmp(path, "/dev/dtrace/", 12) == 0 ||
	    strcmp(path, "/dev/dtrace") == 0) {
		opens_seen++;
		for (i = 0; i < ndevs; i++) {
			if (strcmp(devs[i].path, path) != 0)
				continue;
			devs[i].count++;
			if (devs[i].err != 0) {
				errno = devs[i].err;
				return (-1);
			}
			if (real == NULL)
				real = (int (*)(const char *, int, ...))dlsym(
				    RTLD_NEXT, "open");
			return (real("/dev/null", O_RDWR | (flags & O_CLOEXEC)));
		}
		errno = ENOENT;
		return (-1);
	}
	if (real == NULL)
		real = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open");
	return (real(path, flags, mode));
}

int
kldload(const char *name)
{
	if (kldloads < 8)
		(void) strlcpy(kldload_names[kldloads], name, 64);
	kldloads++;
	errno = EPERM;
	return (-1);
}

int
modfind(const char *name)
{
	static int (*real)(const char *);

	if (strcmp(name, "dtraceall") == 0)
		return (modfind_result[0] < 0 ? (errno = ENOENT, -1) :
		    modfind_result[0]);
	if (strcmp(name, "linux64elf") == 0)
		return (modfind_result[1] < 0 ? (errno = ENOENT, -1) :
		    modfind_result[1]);
	if (strcmp(name, "linuxelf") == 0)
		return (modfind_result[2] < 0 ? (errno = ENOENT, -1) :
		    modfind_result[2]);
	if (real == NULL)
		real = (int (*)(const char *))dlsym(RTLD_NEXT, "modfind");
	return (real(name));
}

int
sysctlbyname(const char *name, void *old, size_t *oldlen, const void *new,
    size_t newlen)
{
	static int (*real)(const char *, void *, size_t *, const void *,
	    size_t);
	size_t len;

	if (strcmp(name, "debug.dtrace.providers") == 0) {
		if (providers == NULL) {
			errno = ENOENT;
			return (-1);
		}
		len = strlen(providers) + 1;
		if (len == 1) {		/* "" models an empty provider list */
			*oldlen = 0;
			return (0);
		}
		if (old == NULL) {
			*oldlen = providers_enomem_once ? len / 2 + 1 : len;
			return (0);
		}
		if (providers_enomem_once == 2) {	/* buffer read fails */
			errno = EIO;
			return (-1);
		}
		if (*oldlen < len) {
			providers_enomem_once = 0;
			*oldlen = len;
			errno = ENOMEM;
			return (-1);
		}
		memcpy(old, providers, len);
		*oldlen = len;
		return (0);
	}
	if (strcmp(name, "kern.bootfile") == 0 && bootfile_set) {
		if (bootfile == NULL) {
			errno = ENOENT;
			return (-1);
		}
		len = strlen(bootfile) + 1;
		if (old != NULL && *oldlen >= len)
			memcpy(old, bootfile, len);
		*oldlen = len;
		return (0);
	}
	if (real == NULL)
		real = (int (*)(const char *, void *, size_t *, const void *,
		    size_t))dlsym(RTLD_NEXT, "sysctlbyname");
	return (real(name, old, oldlen, new, newlen));
}

int
ioctl(int fd, unsigned long request, ...)
{
	static int (*real)(int, unsigned long, ...);
	va_list ap;
	void *arg;

	va_start(ap, request);
	arg = va_arg(ap, void *);
	va_end(ap);
	if (ioctl_cb != NULL && is_standin(fd))
		return (ioctl_cb(ioctl_arg, fd, request, arg));
	if (real == NULL)
		real = (int (*)(int, unsigned long, ...))dlsym(RTLD_NEXT,
		    "ioctl");
	return (real(fd, request, arg));
}

int
getrlimit(int resource, struct rlimit *rlp)
{
	static int (*real)(int, struct rlimit *);

	if (getrlimit_fail) {
		errno = EINVAL;
		return (-1);
	}
	if (real == NULL)
		real = (int (*)(int, struct rlimit *))dlsym(RTLD_NEXT,
		    "getrlimit");
	return (real(resource, rlp));
}

/* ---- kernel linker enumeration ---------------------------------------- */

int
kldnext(int fileid)
{
	static int (*real)(int);
	int i;

	if (!kld_active) {
		if (real == NULL)
			real = (int (*)(int))dlsym(RTLD_NEXT, "kldnext");
		return (real(fileid));
	}
	for (i = 0; i < nklds; i++)
		if (klds[i].fileid > fileid)
			return (klds[i].fileid);
	return (0);
}

int
kldstat(int fileid, struct kld_file_stat *st)
{
	static int (*real)(int, struct kld_file_stat *);
	int i;

	if (!kld_active) {
		if (real == NULL)
			real = (int (*)(int, struct kld_file_stat *))dlsym(
			    RTLD_NEXT, "kldstat");
		return (real(fileid, st));
	}
	for (i = 0; i < nklds; i++) {
		if (klds[i].fileid != fileid)
			continue;
		if (klds[i].stat_fails) {
			errno = ENOENT;
			return (-1);
		}
		(void) strlcpy(st->name, klds[i].name, sizeof (st->name));
		(void) strlcpy(st->pathname, klds[i].path,
		    sizeof (st->pathname));
		st->id = fileid;
		st->address = (caddr_t)(uintptr_t)klds[i].address;
		st->size = 0x100000;
		return (0);
	}
	errno = ENOENT;
	return (-1);
}

/* Module ids are fileid * 100 + index + 1. */
int
kldfirstmod(int fileid)
{
	static int (*real)(int);
	int i;

	if (!kld_active) {
		if (real == NULL)
			real = (int (*)(int))dlsym(RTLD_NEXT, "kldfirstmod");
		return (real(fileid));
	}
	for (i = 0; i < nklds; i++)
		if (klds[i].fileid == fileid && klds[i].modnames[0] != NULL)
			return (fileid * 100 + 1);
	return (0);
}

int
modnext(int modid)
{
	static int (*real)(int);
	int f = modid / 100, k = modid % 100, i;

	if (!kld_active) {
		if (real == NULL)
			real = (int (*)(int))dlsym(RTLD_NEXT, "modnext");
		return (real(modid));
	}
	for (i = 0; i < nklds; i++)
		if (klds[i].fileid == f)
			return (k < 8 && klds[i].modnames[k] != NULL ?
			    modid + 1 : 0);
	return (0);
}

int
modstat(int modid, struct module_stat *ms)
{
	static int (*real)(int, struct module_stat *);
	int f = modid / 100, k = modid % 100 - 1, i;

	if (!kld_active) {
		if (real == NULL)
			real = (int (*)(int, struct module_stat *))dlsym(
			    RTLD_NEXT, "modstat");
		return (real(modid, ms));
	}
	for (i = 0; i < nklds; i++) {
		if (klds[i].fileid != f || k < 0 || k >= 8 ||
		    klds[i].modnames[k] == NULL)
			continue;
		if (strcmp(klds[i].modnames[k], "!fail") == 0) {
			errno = ENOENT;
			return (-1);
		}
		(void) strlcpy(ms->name, klds[i].modnames[k],
		    sizeof (ms->name));
		ms->id = modid;
		return (0);
	}
	errno = ENOENT;
	return (-1);
}
