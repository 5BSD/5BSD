/* SPDX-License-Identifier: BSD-2-Clause */
/* Exercise explicit shared libraries and verify the provider of each symbol. */
#include <sys/param.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *
resolve(void *handle, const char *name, const char *expected)
{
	Dl_info information;
	char actual[PATH_MAX];
	void *symbol;

	dlerror();
	symbol = dlsym(handle, name);
	if (symbol == NULL || dlerror() != NULL ||
	    dladdr(symbol, &information) == 0 || information.dli_fname == NULL ||
	    realpath(information.dli_fname, actual) == NULL ||
	    strcmp(actual, expected) != 0) {
		fprintf(stderr, "incorrect shared provider for %s\n", name);
		return (NULL);
	}
	return (symbol);
}

int
main(int argc, char **argv)
{
	const char unterminated[4] = { 'a', 'b', 'c', 'd' };
	char library[PATH_MAX];
	size_t (*bounded_length)(const char *, size_t);
	div_t (*divide)(int, int);
	div_t positive, negative;
	void *handle;

	if (argc != 2 || argv[1][0] != '/') {
		fprintf(stderr, "usage: shared_runtime /absolute/library/path\n");
		return (1);
	}
	handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	if (handle == NULL) {
		fprintf(stderr, "dlopen %s: %s\n", argv[1], dlerror());
		return (2);
	}
	if (realpath(argv[1], library) == NULL)
		return (3);
	bounded_length = (size_t (*)(const char *, size_t))resolve(handle, "strnlen", library);
	divide = (div_t (*)(int, int))resolve(handle, "div", library);
	if (bounded_length == NULL || divide == NULL)
		return (3);
	positive = divide(17, 5);
	negative = divide(-17, 5);
	if (positive.quot != 3 || positive.rem != 2 ||
	    negative.quot != -3 || negative.rem != -2 ||
	    bounded_length("", 8) != 0 || bounded_length("hello", 0) != 0 ||
	    bounded_length("hello", 3) != 3 || bounded_length("hello", 8) != 5 ||
	    bounded_length(unterminated, sizeof(unterminated)) != 4)
		return (4);
	if (dlclose(handle) != 0)
		return (5);
	puts("shared-runtime: ok");
	return (0);
}
