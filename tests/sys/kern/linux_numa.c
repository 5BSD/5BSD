/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * NUMA memory-policy syscalls on a single-/multi-domain host: get_mempolicy
 * (MPOL_F_MEMS_ALLOWED reports the node set; default policy otherwise),
 * set_mempolicy / mbind / set_mempolicy_home_node validation and acceptance,
 * migrate_pages, and move_pages residency query (mapped pages -> node 0,
 * unmapped -> -ENOENT).  Exit status = failed check number.
 */
#include "linux_test.h"

#define	SYS_set_mempolicy		238
#define	SYS_get_mempolicy		239
#define	SYS_mbind			237
#define	SYS_migrate_pages		256
#define	SYS_move_pages			279
#define	SYS_set_mempolicy_home_node	450

#define	MPOL_DEFAULT		0
#define	MPOL_PREFERRED		1
#define	MPOL_BIND		2
#define	MPOL_F_NODE		0x01
#define	MPOL_F_ADDR		0x02
#define	MPOL_F_MEMS_ALLOWED	0x04
#define	MPOL_MF_MOVE		0x02
#define	ENOENT_		2

static int
test(int argc __attribute__((unused)), char **argv __attribute__((unused)),
    char **envp __attribute__((unused)))
{
	unsigned long nmask, addrs[4];
	int policy, status[4];
	long r, p, i;

	/* 1: MPOL_F_MEMS_ALLOWED reports a non-empty node set. */
	nmask = 0;
	r = call(SYS_get_mempolicy, (long)&policy, (long)&nmask, 64, 0,
	    MPOL_F_MEMS_ALLOWED, 0);
	if (r != 0) { msgnum("get_mempolicy mems_allowed ", r); return (1); }
	if ((nmask & 1) == 0) { msgnum("allowed nodes ", nmask); return (1); }

	/* 2: no flags -> policy is MPOL_DEFAULT. */
	policy = 0x55;
	r = call(SYS_get_mempolicy, (long)&policy, 0, 0, 0, 0, 0);
	if (r != 0 || policy != MPOL_DEFAULT) { msgnum("default policy ", policy); return (2); }

	/* 3: bad get_mempolicy flag combinations -> EINVAL. */
	if (call(SYS_get_mempolicy, (long)&policy, 0, 0, 0, 0x40, 0) != -EINVAL) return (3);
	if (call(SYS_get_mempolicy, (long)&policy, 0, 0, 0,
	    MPOL_F_MEMS_ALLOWED | MPOL_F_NODE, 0) != -EINVAL) return (3);

	/* 4: set_mempolicy - default and a valid bind accept; bad reject. */
	if (call(SYS_set_mempolicy, MPOL_DEFAULT, 0, 0, 0, 0, 0) != 0) return (4);
	nmask = 1;			/* node 0 */
	if (call(SYS_set_mempolicy, MPOL_BIND, (long)&nmask, 64, 0, 0, 0) != 0) return (4);
	if (call(SYS_set_mempolicy, 99, 0, 0, 0, 0, 0) != -EINVAL) return (4);
	nmask = 0;			/* empty set with BIND */
	if (call(SYS_set_mempolicy, MPOL_BIND, (long)&nmask, 64, 0, 0, 0) != -EINVAL) return (4);
	nmask = 1UL << 40;		/* node way out of range */
	if (call(SYS_set_mempolicy, MPOL_BIND, (long)&nmask, 64, 0, 0, 0) != -EINVAL) return (4);

	/* 5: mbind over a real mapping accepts; validation rejects. */
	p = call(SYS_mmap, 0, 4 * PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p < 0) return (5);
	nmask = 1;
	if (call(SYS_mbind, p, 4 * PAGE, MPOL_BIND, (long)&nmask, 64, 0) != 0) return (5);
	if (call(SYS_mbind, p, 4 * PAGE, 99, (long)&nmask, 64, 0) != -EINVAL) return (5);
	if (call(SYS_mbind, p, 4 * PAGE, MPOL_BIND, (long)&nmask, 64, 0x80) != -EINVAL) return (5);
	if (call(SYS_mbind, p + 1, 4 * PAGE, MPOL_BIND, (long)&nmask, 64, 0) != -EINVAL) return (5);

	/* 6: set_mempolicy_home_node validation. */
	if (call(SYS_set_mempolicy_home_node, p, 4 * PAGE, 0, 0, 0, 0) != 0) return (6);
	if (call(SYS_set_mempolicy_home_node, p, 4 * PAGE, 999, 0, 0, 0) != -EINVAL) return (6);
	if (call(SYS_set_mempolicy_home_node, p, 4 * PAGE, 0, 1, 0, 0) != -EINVAL) return (6);

	/* 7: move_pages residency query - mapped pages report node 0. */
	for (i = 0; i < 4; i++) {
		addrs[i] = (unsigned long)(p + i * PAGE);
		*(volatile char *)addrs[i] = 1;		/* fault them in */
		status[i] = -777;
	}
	r = call(SYS_move_pages, 0, 4, (long)addrs, 0, (long)status, 0);
	if (r != 0) { msgnum("move_pages query ", r); return (7); }
	for (i = 0; i < 4; i++)
		if (status[i] != 0) { msgnum("page node ", status[i]); return (7); }

	/* 8: an unmapped page reports -ENOENT. */
	(void)sys2(SYS_munmap, p + 3 * PAGE, PAGE);
	status[0] = -777;
	addrs[0] = (unsigned long)(p + 3 * PAGE);
	r = call(SYS_move_pages, 0, 1, (long)addrs, 0, (long)status, 0);
	if (r != 0) return (8);
	if (status[0] != -ENOENT_) { msgnum("unmapped node ", status[0]); return (8); }

	/* 9: move_pages validation. */
	if (call(SYS_move_pages, 0, 0, (long)addrs, 0, (long)status, 0) != 0) return (9);
	if (call(SYS_move_pages, 0, 1, (long)addrs, 0, (long)status, 0x40) != -EINVAL) return (9);

	/* 10: migrate_pages accepts and reports 0 pages left unmigrated. */
	{
		unsigned long from = 1, to = 1;

		if (call(SYS_migrate_pages, 0, 64, (long)&from, (long)&to, 0, 0) != 0) return (10);
	}
	(void)sys2(SYS_munmap, p, 3 * PAGE);
	return (0);
}
