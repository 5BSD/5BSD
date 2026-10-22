/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Late-load target for pid-placement.py:
 *   pid-late-target LIB BASEFILE NONELIB [cycle]
 * dlopen()s NONELIB (no probes of interest), then LIB, records LIB's load
 * base and the address of ht_late (from dladdr, independently of libproc)
 * as one line of BASEFILE, and calls ht_late.  With "cycle" it then
 * dlclose()s LIB, loads it again and records a second line.  Exits 0 on
 * success.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static int
load(const char *lib, FILE *o)
{
	int (*f)(int);
	Dl_info di;
	void *h;

	if ((h = dlopen(lib, RTLD_NOW)) == NULL ||
	    (f = (int (*)(int))dlsym(h, "ht_late")) == NULL ||
	    dladdr((void *)f, &di) == 0)
		return (-1);
	fprintf(o, "%p %p\n", di.dli_fbase, (void *)f);
	fflush(o);
	if (f(5) != 35)
		return (-1);
	return (dlclose(h));
}

int
main(int argc, char **argv)
{
	FILE *o;
	void *none;

	if (argc < 4 || (none = dlopen(argv[3], RTLD_NOW)) == NULL)
		return (2);
	if ((o = fopen(argv[2], "w")) == NULL)
		return (3);
	if (load(argv[1], o) != 0)
		return (1);
	if (argc > 4 && strcmp(argv[4], "cycle") == 0 && load(argv[1], o) != 0)
		return (1);
	fclose(o);
	return (dlclose(none) == 0 ? 0 : 1);
}
