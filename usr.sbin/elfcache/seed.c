/* SPDX-License-Identifier: BSD-2-Clause */
/* Minimal signed provider: no crypto, cache parser, signing keys or issuer. */
#include <sys/types.h>
#include <sys/cap_authority.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <err.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct cap_cache_domain_result result;
	int fd = syscall(SYS_cap_process, CAP_CACHE_DOMAIN_GET_LAYOUT, -1, 0, &result);
	if (fd < 0 || (result.flags & CAP_CACHE_DOMAIN_SEED) == 0)
		errx(1, "seed requires an issuer-bound seed authority");
	close(fd);
	if (argc < 2 || argc > 65)
		errx(1, "seed requires 1..64 library basenames");
	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == 0 || strchr(argv[i], '/') != NULL || strlen(argv[i]) > 255)
			errx(1, "invalid seed library basename");
		if (dlopen(argv[i], RTLD_LAZY | RTLD_LOCAL) == NULL)
			errx(1, "seed %s: %s", argv[i], dlerror());
	}
	return (0);
}
