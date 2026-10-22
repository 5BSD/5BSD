/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Shared helpers for the frontend-runtime-* harnesses: a check() counter and,
 * with -DWITH_FAULTS (no sanitizers), malloc/calloc/realloc interposers that
 * fail the Nth allocation after arm(N).  FreeBSD libc exports __malloc,
 * __calloc and __realloc, which the interposers call when not failing.
 */
#ifndef FRONTEND_FAULTS_H
#define	FRONTEND_FAULTS_H

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static int failures, checks;

static void __attribute__((format(printf, 2, 3)))
check(int ok, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;
	failures++;
	printf("FAIL ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	fflush(stdout);
}

static int
summary(void)
{
	printf("%s %d checks, %d failures\n", failures ? "FAIL" : "PASS",
	    checks, failures);
	return (failures != 0);
}

#ifdef WITH_FAULTS
#include <dlfcn.h>
#include <execinfo.h>
#include <string.h>

extern void *__malloc(size_t);
extern void *__calloc(size_t, size_t);
extern void *__realloc(void *, size_t);
static long fault_at, fault_count;
static int fault_hit, fault_skipped;
/*
 * Functions whose allocation failures are not injected because a known bug
 * outside the suite's files makes them crash (reported separately).
 */
static const char *const *fault_skip_fns;
static const char *const *fault_skip_libs;	/* substrings of object paths */
static int in_skip_check;

static int
fault_skip(void)
{
	void *frames[24];
	Dl_info info;
	int n, i, k, skip = 0;

	if ((fault_skip_fns == NULL && fault_skip_libs == NULL) ||
	    in_skip_check)
		return (0);
	in_skip_check = 1;
	Dl_info self;
	int libs_done = 0;

	(void) dladdr((void *)fault_skip, &self);
	n = backtrace(frames, 24);
	for (i = 0; i < n && !skip; i++) {
		if (dladdr(frames[i], &info) == 0)
			continue;
		/*
		 * Libraries are matched on the allocation's immediate caller:
		 * the first frame outside this harness and libc.
		 */
		if (!libs_done && info.dli_fname != NULL &&
		    strcmp(info.dli_fname, self.dli_fname) != 0 &&
		    strstr(info.dli_fname, "libc.so") == NULL) {
			libs_done = 1;
			for (k = 0; fault_skip_libs != NULL &&
			    fault_skip_libs[k] != NULL; k++)
				if (strstr(info.dli_fname,
				    fault_skip_libs[k]) != NULL)
					skip = 1;
		}
		if (info.dli_sname == NULL)
			continue;
		for (k = 0; fault_skip_fns != NULL &&
		    fault_skip_fns[k] != NULL; k++)
			if (strcmp(info.dli_sname, fault_skip_fns[k]) == 0)
				skip = 1;
	}
	in_skip_check = 0;
	return (skip);
}

static int
fault_now(void)
{
	if (fault_at != 0 && !in_skip_check && ++fault_count == fault_at) {
		if (fault_skip()) {
			fault_skipped++;
			fault_at++;	/* fail the next one instead */
			return (0);
		}
		fault_hit = 1;
		if (getenv("FAULT_BT") != NULL) {	/* debugging aid */
			void *bt[32];

			in_skip_check = 1;
			backtrace_symbols_fd(bt, backtrace(bt, 32), 2);
			in_skip_check = 0;
		}
		errno = ENOMEM;
		return (1);
	}
	return (0);
}

void *
malloc(size_t n)
{
	return (fault_now() ? NULL : __malloc(n));
}

void *
calloc(size_t n, size_t m)
{
	return (fault_now() ? NULL : __calloc(n, m));
}

void *
realloc(void *p, size_t n)
{
	return (fault_now() ? NULL : __realloc(p, n));
}

/* arm(N) fails the Nth allocation from now; arm(0) disarms (keeps hit). */
static void
arm(long n)
{
	fault_at = n;
	fault_count = 0;
	if (n != 0)
		fault_hit = 0;
}
#endif

#endif
