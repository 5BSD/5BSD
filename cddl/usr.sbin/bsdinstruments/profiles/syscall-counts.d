/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Count every syscall by name; print the table on END */

syscall:::entry
/* @bsdinstruments-predicate */
{
    @counts[probefunc] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printa("%-30s %@d\n", @counts);
}
