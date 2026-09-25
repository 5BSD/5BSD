/* SPDX-License-Identifier: BSD-2-Clause */

#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Minimal types for the allocation-only paths extracted by regress.py. */
typedef uint64_t bus_addr_t;
struct mrsas_softc { void *mrsas_dev; };
struct mrsas_dcmd_frame { int unused; };
struct command_frame { struct mrsas_dcmd_frame dcmd; };
struct mrsas_mfi_cmd { struct command_frame *frame; };
struct mrsas_tmp_dcmd { void *tag; void *mem; bus_addr_t addr; };

#define M_NOWAIT 1
#define M_ZERO 2
#define M_MRSAS 1
#define M_QLNXBUF 2

static struct command_frame frame;
static struct mrsas_mfi_cmd command = { &frame };
static int fail_command, fail_alloc, allocations, releases, zero_calls;
static void *allocated;

static void *
test_malloc(size_t size, int type __unused, int flags)
{

	assert((flags & M_NOWAIT) != 0);
	allocations++;
	if (fail_alloc)
		return (NULL);
	allocated = malloc(size);
	assert(allocated != NULL);
	memset(allocated, (flags & M_ZERO) != 0 ? 0 : 0xa5, size);
	return (allocated);
}

static void
test_bzero(void *ptr, size_t size)
{

	assert(ptr != NULL);
	zero_calls++;
	memset(ptr, 0, size);
}

static struct mrsas_mfi_cmd *
mrsas_get_mfi_cmd(struct mrsas_softc *sc __unused)
{

	return (fail_command ? NULL : &command);
}

static void
mrsas_release_mfi_cmd(struct mrsas_mfi_cmd *cmd)
{

	assert(cmd == &command);
	releases++;
}

static void
test_stop_after_alloc(struct mrsas_tmp_dcmd *tmp)
{
	const unsigned char *p;

	assert(tmp != NULL);
	p = (const unsigned char *)tmp;
	for (size_t i = 0; i < sizeof(*tmp); i++)
		assert(p[i] == 0);
	free(tmp);
	allocated = NULL;
}

#define malloc test_malloc
#define bzero test_bzero
#define device_printf(...) ((void)0)
#include "allocation_paths.inc"
#undef malloc
#undef bzero

int
main(int argc, char **argv)
{
	struct mrsas_softc sc = {0};
	unsigned char *p;
	int (*query)(struct mrsas_softc *);

	assert(argc == 2);
	if (strcmp(argv[1], "qlnx") == 0) {
		fail_alloc = 1;
		assert(qlnx_zalloc(64) == NULL);
		assert(zero_calls == 0);
		fail_alloc = 0;
		p = qlnx_zalloc(64);
		assert(p != NULL && zero_calls == 1);
		for (size_t i = 0; i < 64; i++)
			assert(p[i] == 0);
		free(p);
		return (0);
	}
	query = strcmp(argv[1], "pd") == 0 ?
	    mrsas_get_pd_list : mrsas_get_ld_list;
	fail_command = 1;
	assert(query(&sc) != 0);
	assert(allocations == 0 && releases == 0);
	fail_command = 0;
	fail_alloc = 1;
	assert(query(&sc) == ENOMEM);
	assert(allocations == 1 && releases == 1);
	fail_alloc = 0;
	assert(query(&sc) == 0);
	assert(allocations == 2 && releases == 1 && allocated == NULL);
	/* The successful prefix retains its command for the DMA path. */
	mrsas_release_mfi_cmd(&command);
	assert(releases == 2);
	return (0);
}
