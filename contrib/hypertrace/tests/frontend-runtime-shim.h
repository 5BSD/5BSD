/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Interface of frontend-runtime-shim.so (see frontend-runtime-shim.c).
 * Harnesses resolve these with dlsym(RTLD_DEFAULT, ...) so that a missing
 * preload is detected before any device path is exercised.
 */
#ifndef FRONTEND_RUNTIME_SHIM_H
#define	FRONTEND_RUNTIME_SHIM_H

struct frontend_shim_dev {
	const char *path;
	int err;		/* 0: open succeeds with a stand-in fd */
	int count;
};

struct frontend_shim_kld {
	int fileid;
	const char *name;
	const char *path;
	unsigned long address;
	int stat_fails;
	const char *modnames[9];	/* NULL-terminated; "!fail" fails modstat */
};

typedef int frontend_shim_ioctl_f(void *, int, unsigned long, void *);

#endif
