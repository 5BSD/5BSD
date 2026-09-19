/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Inert logcmp_log(3) for the ctl fuzz harnesses.  ctl_gatt.c logs its
 * reclaim events through the Log capability; a fuzzer is hermetic and links
 * no IPC libraries, so it stubs the sink out.  (The bsd.test.mk ctl tests
 * link the real liblogcmp instead, so this stub is fuzz-only.)
 */
#include <stdarg.h>

void	logcmp_log(int priority, const char *fmt, ...);
void	logcmp_vlog(int priority, const char *fmt, va_list ap);

void
logcmp_log(int priority, const char *fmt, ...)
{
	(void)priority;
	(void)fmt;
}

void
logcmp_vlog(int priority, const char *fmt, va_list ap)
{
	(void)priority;
	(void)fmt;
	(void)ap;
}
