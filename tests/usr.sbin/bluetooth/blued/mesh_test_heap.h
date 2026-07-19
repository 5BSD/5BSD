/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _MESH_TEST_HEAP_H_
#define _MESH_TEST_HEAP_H_

/*
 * Heap-allocate a large mesh struct so it never lands on a test's automatic
 * stack frame.
 *
 * struct mesh_sim, struct meshd_node and struct mesh_mgr each embed
 * per-node forwarding tables, replay lists and model state; they are well
 * over 100 KB by value (mesh_mgr is ~260 KB) and grow whenever any embedded
 * mesh struct grows.  A single such value on the stack overflows the small
 * frame an ATF test case runs in, which surfaces as diverse, spurious
 * failures.  MESH_HEAP() keeps only a pointer on the stack, so these structs
 * may grow freely.
 *
 * The cleanup attribute frees the block on every scope exit -- normal return
 * or early return alike.  An ATF_REQUIRE failure tears the whole test process
 * down, so nothing leaks on that path either.
 */

#include <stdlib.h>

#include <atf-c.h>

static inline void
mesh_test_freep(void *pp)
{

	free(*(void **)pp);
}

static inline void *
mesh_test_zalloc(size_t n)
{
	void *p = calloc(1, n);

	ATF_REQUIRE_MSG(p != NULL, "calloc(%zu) failed", n);
	return (p);
}

#define	MESH_HEAP(type, name)						\
	type *name __attribute__((__cleanup__(mesh_test_freep))) =	\
	    mesh_test_zalloc(sizeof(*name))

#endif /* _MESH_TEST_HEAP_H_ */
