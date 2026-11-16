/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Count syscalls by (execname, probefunc); print the table on END */

syscall:::entry
/* @bsdinstruments-predicate */
{
    @counts[execname, probefunc] = count();
}

dtrace:::END
{
    printa("%-24s %-30s %@d\n", @counts);
}
