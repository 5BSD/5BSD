/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Allocation fault injector for frontend-codegen-oom (LD_PRELOAD).  While
 * armed with fcg_oom_arm(n), the n-th allocation request (malloc, calloc,
 * realloc, strdup) fails with ENOMEM and every later request succeeds; the
 * driver disarms after each compilation and reads how many requests were
 * made and whether the injected failure happened.  With a target set by
 * fcg_oom_target(name), only requests made with function 'name' among the
 * nearest call frames are counted, so a sweep reaches the failure paths of
 * that function directly.
 */
#include <sys/types.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *(*real_malloc)(size_t);
static void *(*real_calloc)(size_t, size_t);
static void *(*real_realloc)(void *, size_t);
static long countdown, requests;
static int armed, hit, resolving, walking;

/* calloc() may be needed by dlsym() itself while we resolve the symbols. */
static char bootstrap[4096];
static size_t bootused;

static void
resolve(void)
{
	if (real_malloc != NULL || resolving)
		return;
	resolving = 1;
	real_calloc = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
	real_malloc = (void *(*)(size_t))dlsym(RTLD_NEXT, "malloc");
	real_realloc = (void *(*)(void *, size_t))dlsym(RTLD_NEXT, "realloc");
	resolving = 0;
}

/*
 * Is the target function among the nearest call frames of this request?
 * The target is "start:size", a function's address range relative to the
 * load base of libdtrace (static functions have no dynamic symbol name).
 */
static unsigned long tstart, tsize;

static int
targeted(void)
{
	void *pcs[12];
	int i, n, found = 0;

	if (tsize == 0)
		return (1);
	if (walking)
		return (0);
	walking = 1;
	n = backtrace(pcs, 12);
	for (i = 1; i < n && !found; i++) {
		Dl_info dli;
		unsigned long off;

		if (dladdr(pcs[i], &dli) == 0 || dli.dli_fname == NULL ||
		    strstr(dli.dli_fname, "libdtrace") == NULL)
			continue;
		off = (unsigned long)pcs[i] - (unsigned long)dli.dli_fbase;
		if (off >= tstart && off < tstart + tsize)
			found = 1;
	}
	walking = 0;
	return (found);
}

static int
inject(void)
{
	if (!armed || walking || !targeted())
		return (0);
	requests++;
	if (--countdown == 0) {
		hit = 1;
		errno = ENOMEM;
		return (1);
	}
	return (0);
}

void *
malloc(size_t n)
{
	resolve();
	if (inject())
		return (NULL);
	return (real_malloc(n));
}

void *
calloc(size_t a, size_t b)
{
	if (real_calloc == NULL) {
		size_t n = (a * b + 15) & ~(size_t)15;

		if (resolving && bootused + n <= sizeof (bootstrap)) {
			void *p = bootstrap + bootused;
			bootused += n;
			return (p);
		}
		resolve();
	}
	if (inject())
		return (NULL);
	return (real_calloc(a, b));
}

void *
realloc(void *p, size_t n)
{
	resolve();
	if (inject())
		return (NULL);
	return (real_realloc(p, n));
}

void
free(void *p)
{
	static void (*real_free)(void *);

	if ((char *)p >= bootstrap && (char *)p < bootstrap + sizeof (bootstrap))
		return;
	if (real_free == NULL)
		real_free = (void (*)(void *))dlsym(RTLD_NEXT, "free");
	real_free(p);
}

char *
strdup(const char *s)
{
	size_t n = strlen(s) + 1;
	char *d = malloc(n);

	if (d != NULL)
		memcpy(d, s, n);
	return (d);
}

void
fcg_oom_arm(long n)
{
	countdown = n;
	requests = 0;
	hit = 0;
	armed = n > 0;
}

long
fcg_oom_requests(void)
{
	return (requests);
}

int
fcg_oom_hit(void)
{
	return (hit);
}

void
fcg_oom_target(const char *range)
{
	tstart = tsize = 0;
	if (range != NULL && *range != '\0')
		(void) sscanf(range, "%lx:%lx", &tstart, &tsize);
}
