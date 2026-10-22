/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Test-only libvmmapi client for the bhyvectl suite: prepares model state
 * that bhyvectl itself cannot create (interrupt info, wired guest memory,
 * named device memory mappings).  Runs with the vmm model preloaded.
 */
#include <sys/types.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vmmapi.h>

int
main(int argc, char **argv)
{
	struct vmctx *ctx;

	if (argc < 3 || (ctx = vm_open(argv[2])) == NULL)
		return (2);
	if (strcmp(argv[1], "intinfo") == 0 && argc == 4)
		return (vm_set_intinfo(vm_vcpu_open(ctx, 0), strtoull(argv[3], NULL, 0)) != 0);
	if (strcmp(argv[1], "wired") == 0 && argc == 4) {
		vm_set_memflags(ctx, VM_MEM_F_WIRED);
		return (vm_setup_memory(ctx, strtoull(argv[3], NULL, 0), VM_MMAP_ALL) != 0);
	}
	if (strcmp(argv[1], "devmem") == 0 && argc == 6) {
		int segid;
		size_t len = strtoull(argv[4], NULL, 0);
		if (vm_create_devmem_auto(ctx, argv[3], len, &segid) == MAP_FAILED)
			return (1);
		return (vm_mmap_memseg(ctx, strtoull(argv[5], NULL, 0), segid, 0, len,
		    PROT_READ | PROT_WRITE) != 0);
	}
	return (2);
}
