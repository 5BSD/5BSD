/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Helper for aggregate-walk.c (separate unit: <sys/user.h> declares a
 * struct session that clashes with the harness's).  Returns the start of
 * this process's mapping containing addr, from kinfo_getvmmap(3), or 0.
 */
#include <sys/types.h>
#include <sys/user.h>

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <libutil.h>

uint64_t aw_mapping_start(uintptr_t addr);

uint64_t
aw_mapping_start(uintptr_t addr)
{
	struct kinfo_vmentry *vm;
	uint64_t start = 0;
	int cnt, i;

	if ((vm = kinfo_getvmmap(getpid(), &cnt)) == NULL)
		return (0);
	for (i = 0; i < cnt; i++)
		if (addr >= vm[i].kve_start && addr < vm[i].kve_end)
			start = vm[i].kve_start;
	free(vm);
	return (start);
}
