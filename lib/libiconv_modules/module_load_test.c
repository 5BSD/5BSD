/* SPDX-License-Identifier: BSD-2-Clause */
/* Qualify dynamic module resolution without using host conversion data. */
#include <sys/param.h>
#include <dlfcn.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char **argv)
{
	char expected[MAXPATHLEN], resolved[MAXPATHLEN], loaded[MAXPATHLEN];
	const char *directory;
	void *handle, *entry;
	Dl_info info;

	if (argc != 3)
		errx(1, "usage: module_load_test library entrypoint");
	directory = getenv("LD_LIBRARY_PATH");
	if (directory == NULL || strchr(directory, ':') != NULL)
		errx(1, "expected one declared runtime directory");
	if (snprintf(expected, sizeof(expected), "%s/%s", directory, argv[1]) >=
	    (int)sizeof(expected))
		errx(1, "module path too long");
	if (realpath(expected, resolved) == NULL)
		err(1, "%s", expected);
	handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	if (handle == NULL)
		errx(1, "dlopen: %s", dlerror());
	entry = dlsym(handle, argv[2]);
	if (entry == NULL)
		errx(1, "dlsym: %s", dlerror());
	if (dladdr(entry, &info) == 0 || realpath(info.dli_fname, loaded) == NULL)
		errx(1, "cannot identify loaded module");
	if (strcmp(resolved, loaded) != 0)
		errx(1, "unexpected module: %s (expected %s)", loaded, resolved);
	if (dlclose(handle) != 0)
		errx(1, "dlclose: %s", dlerror());
	return (0);
}
