/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Preloaded by pid-placement.py: records FASTTRAPIOC_MAKEPROBE requests made
 * on the placeholder fasttrap descriptor the harness registers, and accepts
 * them (or refuses one probe type on request).  Opening the DTrace helper
 * device never reaches the kernel: depending on the selected mode the open
 * fails with ENOENT, or returns an inert descriptor whose
 * DTRACEHIOC_ADDDOF requests are recorded and then accepted or refused.
 * All other opens and ioctls pass through unchanged.
 */
#include <sys/types.h>
#include <sys/ioctl.h>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/dtrace.h>
#include <sys/fasttrap.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int capture_fd = -1, fail_type = -1;
static fasttrap_probe_spec_t *specs[256];
static int nspecs;

/* GETINSTR: 0 refuse (ENOENT), 1 answer nop (0x90); queried pcs recorded. */
static int getinstr_mode, ngetinstr;
static uint64_t getinstr_pc[64];

/* Helper device: 0 open fails (ENOENT), 1 accept ADDDOF, 2 refuse ADDDOF. */
static int helper_mode, helper_fd = -1, helper_opens;
static dof_helper_t helpers[64];
static int nhelpers;

void
pidcap_fail(int type)
{
	fail_type = type;
}

void
pidcap_getinstr(int mode)
{
	getinstr_mode = mode;
}

int
pidcap_getinstr_count(void)
{
	return (ngetinstr);
}

uint64_t
pidcap_getinstr_pc(int i)
{
	return (i >= 0 && i < ngetinstr ? getinstr_pc[i] : 0);
}

void
pidcap_helper(int mode)
{
	helper_mode = mode;
}

int
pidcap_helper_opens(void)
{
	return (helper_opens);
}

int
pidcap_helper_count(void)
{
	return (nhelpers);
}

const dof_helper_t *
pidcap_helper_get(int i)
{
	return (i >= 0 && i < nhelpers ? &helpers[i] : NULL);
}

int
open(const char *path, int flags, ...)
{
	static int (*real)(const char *, int, ...);
	va_list ap;
	int mode = 0, fd;

	if (flags & O_CREAT) {
		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);
	}
	if (real == NULL)
		real = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT,
		    "open");
	if (path != NULL && strcmp(path, "/dev/dtrace/helper") == 0) {
		pthread_mutex_lock(&lock);
		helper_opens++;
		pthread_mutex_unlock(&lock);
		if (helper_mode == 0) {
			errno = ENOENT;
			return (-1);
		}
		fd = real("/dev/null", O_RDONLY | O_CLOEXEC);
		helper_fd = fd;
		return (fd);
	}
	return (real(path, flags, mode));
}

void
pidcap_set(int fd)
{
	capture_fd = fd;
}

int
pidcap_count(void)
{
	int n;

	pthread_mutex_lock(&lock);
	n = nspecs;
	pthread_mutex_unlock(&lock);
	return (n);
}

const fasttrap_probe_spec_t *
pidcap_get(int i)
{
	return (i >= 0 && i < nspecs ? specs[i] : NULL);
}

void
pidcap_reset(void)
{
	pthread_mutex_lock(&lock);
	while (nspecs > 0)
		free(specs[--nspecs]);
	nhelpers = 0;
	helper_opens = 0;
	ngetinstr = 0;
	pthread_mutex_unlock(&lock);
}

int
ioctl(int fd, unsigned long request, ...)
{
	static int (*real)(int, unsigned long, ...);
	const fasttrap_probe_spec_t *ftp;
	va_list ap;
	void *arg;
	size_t len;

	va_start(ap, request);
	arg = va_arg(ap, void *);
	va_end(ap);
	if (fd == helper_fd && helper_fd >= 0 &&
	    request == DTRACEHIOC_ADDDOF) {
		pthread_mutex_lock(&lock);
		if (nhelpers < 64)
			helpers[nhelpers++] = *(const dof_helper_t *)arg;
		pthread_mutex_unlock(&lock);
		if (helper_mode == 2) {
			errno = EINVAL;
			return (-1);
		}
		return (0);
	}
	if (fd == capture_fd && capture_fd >= 0 &&
	    request == FASTTRAPIOC_GETINSTR) {
		fasttrap_instr_query_t *q = arg;

		pthread_mutex_lock(&lock);
		if (ngetinstr < 64)
			getinstr_pc[ngetinstr++] = q->ftiq_pc;
		pthread_mutex_unlock(&lock);
		if (getinstr_mode == 0) {
			errno = ENOENT;
			return (-1);
		}
		q->ftiq_instr = 0x90;
		return (0);
	}
	if (fd == capture_fd && capture_fd >= 0 &&
	    request == FASTTRAPIOC_MAKEPROBE) {
		ftp = arg;
		if ((int)ftp->ftps_type == fail_type) {
			errno = EINVAL;
			return (-1);
		}
		pthread_mutex_lock(&lock);
		if (nspecs == 256 || ftp->ftps_noffs > 65536) {
			pthread_mutex_unlock(&lock);
			return (-1);
		}
		len = sizeof (*ftp) + ftp->ftps_noffs * sizeof (uint64_t);
		specs[nspecs] = malloc(len);
		if (specs[nspecs] == NULL) {
			pthread_mutex_unlock(&lock);
			return (-1);
		}
		memcpy(specs[nspecs], ftp, sizeof (*ftp) - sizeof (uint64_t) +
		    ftp->ftps_noffs * sizeof (uint64_t));
		nspecs++;
		pthread_mutex_unlock(&lock);
		return (0);
	}
	if (real == NULL)
		real = (int (*)(int, unsigned long, ...))dlsym(RTLD_NEXT,
		    "ioctl");
	return (real(fd, request, arg));
}
