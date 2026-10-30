/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/stat.h>
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include "libunbound/unbound.h"

int
main(int argc, char **argv)
{
	struct stat expected, actual;
	struct ub_ctx *ctx;
	struct ub_result *result;
	Dl_info info;
	void *symbol;
	const unsigned char address[] = { 192, 0, 2, 42 };

	assert(argc == 4);
	assert(stat(argv[1], &expected) == 0);
	symbol = dlsym(RTLD_DEFAULT, "ub_resolve");
	assert(symbol != NULL && dladdr(symbol, &info) != 0);
	assert(stat(info.dli_fname, &actual) == 0);
	assert(expected.st_dev == actual.st_dev &&
	    expected.st_ino == actual.st_ino);
	ctx = ub_ctx_create();
	assert(ctx != NULL);
	assert(ub_ctx_config(ctx, argv[3]) != 0);
	ub_ctx_delete(ctx);
	for (int i = 0; i < 8; i++) {
		ctx = ub_ctx_create();
		assert(ctx != NULL);
		assert(ub_ctx_config(ctx, argv[2]) == 0);
		result = NULL;
		assert(ub_resolve(ctx, "host.example.test.", 1, 1, &result) == 0);
		assert(result != NULL && result->rcode == 0 && result->havedata);
		assert(!result->nxdomain && !result->bogus);
		assert(result->data[0] != NULL && result->data[1] == NULL);
		assert(result->len[0] == sizeof(address));
		assert(memcmp(result->data[0], address, sizeof(address)) == 0);
		ub_resolve_free(result);
		result = NULL;
		assert(ub_resolve(ctx, "missing.example.test.", 1, 1, &result) == 0);
		assert(result != NULL && result->rcode == 3 && result->nxdomain);
		assert(!result->havedata && !result->bogus);
		ub_resolve_free(result);
		result = NULL;
		assert(ub_resolve(ctx, "host.example.test.", 28, 1, &result) == 0);
		assert(result != NULL && result->rcode == 0 && !result->nxdomain);
		assert(!result->havedata && !result->bogus);
		ub_resolve_free(result);
		ub_ctx_delete(ctx);
	}
	puts("native Unbound: config rejection, eight context lifecycles, local A/NXDOMAIN/NODATA passed");
	return (0);
}
