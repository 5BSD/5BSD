/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

/* Exercise a linked libdl consumer and open the explicit build artifact. */
int
main(int argc, char **argv)
{
	void *filter, *self, *symbol;
	void *(*open_fn)(const char *, int);
	void *(*sym_fn)(void *, const char *);
	int (*close_fn)(void *);
	char *(*error_fn)(void);
	Dl_info origin;

	assert(argc == 2);
	filter = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	if (filter == NULL) {
		fprintf(stderr, "%s\n", dlerror());
		return (1);
	}
	open_fn = (void *(*)(const char *, int))dlsym(filter, "dlopen");
	sym_fn = (void *(*)(void *, const char *))dlsym(filter, "dlsym");
	close_fn = (int (*)(void *))dlsym(filter, "dlclose");
	error_fn = (char *(*)(void))dlsym(filter, "dlerror");
	assert(open_fn != NULL && sym_fn != NULL && close_fn != NULL && error_fn != NULL);
	/* Normal relocation resolves loader services through rtld. Explicit
	 * dlsym(filter, ...) can expose libc weak stubs; do not call those. */
	self = dlopen(NULL, RTLD_NOW);
	assert(self != NULL);
	symbol = dlsym(self, "printf");
	assert(symbol != NULL);
	assert(dladdr(symbol, &origin) != 0);
	assert(origin.dli_fname != NULL);
	(void)dlerror();
	assert(dlsym(self, "__5bsd_libdl_test_missing_symbol_9c7487") == NULL);
	assert(dlerror() != NULL);
	assert(dlclose(self) == 0);
	assert(dlclose(filter) == 0);
	return (0);
}
