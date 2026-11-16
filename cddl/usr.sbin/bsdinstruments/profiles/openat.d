/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every openat(2) call with the path argument */

syscall::openat:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: openat(_, \"%s\")\n",
           execname, pid, copyinstr(arg1));
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
