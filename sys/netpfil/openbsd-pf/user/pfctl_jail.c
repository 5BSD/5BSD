/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * pfctl(8) side of the 5BSD "jail" rule option: print the option.  A rule
 * that names its jail prints the name (the kernel keeps the jail id in
 * step with the jail of that name); a numeric jail id prints as is.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>

#include <stdio.h>

void	print_op(u_int8_t, const char *, const char *);
void	pfctl_print_jail(const struct pf_rule_jail *);

void
pfctl_print_jail(const struct pf_rule_jail *j)
{
	char a1[16], a2[16];

	printf(" jail");
	if (j->byname) {
		print_op(j->op, j->name, j->name);
		return;
	}
	snprintf(a1, sizeof(a1), "%d", j->jid[0]);
	snprintf(a2, sizeof(a2), "%d", j->jid[1]);
	print_op(j->op, a1, a2);
}
