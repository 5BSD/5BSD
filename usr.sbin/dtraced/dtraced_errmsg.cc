/*-
 * Copyright (c) 2020 Domagoj Stolfa
 * Copyright (c) 2021 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from Arm Limited.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from the Kenneth Hayter Scholarship Fund.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <err.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "dtraced_errmsg.h"
#include "dtraced_misc.h"

#include <mutex>

#define DTRACED_SYSLOG

static int quiet;
static std::mutex io_mtx;

void
be_quiet(void)
{

	quiet = 1;
}

void
dump_errmsg(const char *file, int line, const char *msg, ...)
{
	va_list ap;
	if (msg) {
		{
			std::lock_guard lk(io_mtx);
			fprintf(stderr, "ERROR: %s:%d ", file, line);
			va_start(ap, msg);
			vfprintf(stderr, msg, ap);
			va_end(ap);
			fprintf(stderr, "\n");
		}
#ifdef DTRACED_SYSLOG
		va_start(ap, msg);
		vsyslog(LOG_ERR, msg, ap);
		va_end(ap);
#endif /* DTRACED_SYSLOG */
	}
}

void
dump_warnmsg(const char *file, int line, const char *msg, ...)
{
	va_list ap;

	if (quiet)
		return;

	if (msg) {
		{
			std::lock_guard lk(io_mtx);
			fprintf(stderr, "WARNING: %s:%d ", file, line);
			va_start(ap, msg);
			vfprintf(stderr, msg, ap);
			va_end(ap);
			fprintf(stderr, "\n");
		}
#ifdef DTRACED_SYSLOG
		va_start(ap, msg);
		vsyslog(LOG_WARNING, msg, ap);
		va_end(ap);
#endif /* DTRACED_SYSLOG */
	}
}

#ifdef DTRACED_DEBUG
void
dump_debugmsg(const char *file, int line, const char *msg, ...)
{
	va_list ap;

	if (quiet)
		return;

	if (msg) {
		{
			std::lock_guard lk(io_mtx);
			fprintf(stdout, "DEBUG: %s:%d ", file, line);
			va_start(ap, msg);
			vfprintf(stdout, msg, ap);
			va_end(ap);
			fprintf(stdout, "\n");
		}
#ifdef DTRACED_SYSLOG
		va_start(ap, msg);
		vsyslog(LOG_DEBUG, msg, ap);
		va_end(ap);
#endif /* DTRACED_SYSLOG */
	}
}
#endif /* DTRACED_DEBUG */

void
dump_logmsg(const char *file, int line, const char *msg, ...)
{
	va_list ap;
	if (msg) {
		{
			std::lock_guard lk(io_mtx);
			fprintf(stdout, "LOG: %s:%d ", file, line);
			va_start(ap, msg);
			vfprintf(stdout, msg, ap);
			va_end(ap);
			fprintf(stdout, "\n");
		}
#ifdef DTRACED_SYSLOG
		va_start(ap, msg);
		vsyslog(LOG_INFO, msg, ap);
		va_end(ap);
#endif /* DTRACED_SYSLOG */
	}
}
