/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Live-allocation accounting for frontend-codegen-unit's leak checks
 * (LD_PRELOAD; LeakSanitizer is not available on this platform).  Every
 * malloc/calloc/realloc/strdup result is added and every free subtracted
 * (by malloc_usable_size); at exit the live byte and block counts are
 * printed as "LIVE <bytes> <blocks>".
 */
#include <dlfcn.h>
#include <malloc_np.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *(*rm)(size_t), *(*rc)(size_t, size_t), *(*rr)(void *, size_t);
static void (*rf)(void *);
static long live, nlive;
static int inres;
static char boot[8192];
static size_t bu;

static void
res(void)
{
	if (rm != NULL || inres)
		return;
	inres = 1;
	rc = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
	rm = (void *(*)(size_t))dlsym(RTLD_NEXT, "malloc");
	rr = (void *(*)(void *, size_t))dlsym(RTLD_NEXT, "realloc");
	rf = (void (*)(void *))dlsym(RTLD_NEXT, "free");
	inres = 0;
}

static void
add(void *p)
{
	if (p != NULL) {
		live += malloc_usable_size(p);
		nlive++;
	}
}

static void
del(void *p)
{
	if (p != NULL) {
		live -= malloc_usable_size(p);
		nlive--;
	}
}

void *
malloc(size_t n)
{
	void *p;

	res();
	p = rm(n);
	add(p);
	return (p);
}

void *
calloc(size_t a, size_t b)
{
	void *p;

	if (rc == NULL) {
		if (inres) {
			p = boot + bu;
			bu += (a * b + 15) & ~(size_t)15;
			return (p);
		}
		res();
	}
	p = rc(a, b);
	add(p);
	return (p);
}

void *
realloc(void *o, size_t n)
{
	void *p;

	res();
	if (o != NULL)
		del(o);
	p = rr(o, n);
	if (p != NULL)
		add(p);
	else if (o != NULL)
		add(o);
	return (p);
}

void
free(void *p)
{
	if ((char *)p >= boot && (char *)p < boot + sizeof (boot))
		return;
	res();
	del(p);
	rf(p);
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

__attribute__((destructor)) static void
report(void)
{
	fprintf(stderr, "LIVE %ld %ld\n", live, nlive);
}
