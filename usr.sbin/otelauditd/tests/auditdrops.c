/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Preloaded into otelauditd(8) by otelauditd_test: AUDITPIPE_GET_DROPS
 * reports a drop count that grows by 3 on every call, as if the audit
 * pipe's queue overflowed between reads, so the drop counter path runs
 * without an audit storm.  Every other ioctl reaches the kernel.
 */

#include <sys/types.h>
#include <sys/ioctl.h>

#include <security/audit/audit_ioctl.h>

#include <dlfcn.h>
#include <stdarg.h>
#include <stdint.h>

int	ioctl(int, unsigned long, ...);

int
ioctl(int fd, unsigned long req, ...)
{
	static int (*real)(int, unsigned long, ...);
	static uint64_t drops;
	va_list ap;
	void *arg;

	va_start(ap, req);
	arg = va_arg(ap, void *);
	va_end(ap);
	if (req == AUDITPIPE_GET_DROPS) {
		drops += 3;
		*(uint64_t *)arg = drops;
		return (0);
	}
	if (real == NULL)
		real = (int (*)(int, unsigned long, ...))dlsym(RTLD_NEXT,
		    "ioctl");
	return (real(fd, req, arg));
}
