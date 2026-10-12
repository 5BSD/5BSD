/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * pfctl(8) side of the 5BSD "jail" rule option: resolve jail names to
 * jail ids when a ruleset is parsed and print them back by name.
 */

#include <sys/types.h>
#include <sys/jail.h>

#include <jail.h>
#include <stdio.h>
#include <stdlib.h>

void	print_op(u_int8_t, const char *, const char *);
int	pfctl_jail_getid(const char *);
void	pfctl_print_jail(u_int8_t, int, int);

/* PF_OP_EQ / PF_OP_NE from net/pfvar.h, without its dependencies. */
#define	PFJ_OP_EQ	2
#define	PFJ_OP_NE	3

int
pfctl_jail_getid(const char *name)
{
	/* "0" names the host itself (prison0). */
	if (name[0] == '0' && name[1] == '\0')
		return (0);
	return (jail_getid(name));
}

void
pfctl_print_jail(u_int8_t op, int j1, int j2)
{
	char a1[MAXHOSTNAMELEN], a2[16];
	char *n = NULL;

	if ((op == PFJ_OP_EQ || op == PFJ_OP_NE) && j1 > 0)
		n = jail_getname(j1);
	if (n != NULL)
		snprintf(a1, sizeof(a1), "%s", n);
	else
		snprintf(a1, sizeof(a1), "%d", j1);
	free(n);
	snprintf(a2, sizeof(a2), "%d", j2);
	printf(" jail");
	print_op(op, a1, a2);
}
