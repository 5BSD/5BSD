/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every write(2) entry with fd and length */

syscall::write:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: write(fd=%d, %d)\n",
           execname, pid, (int)arg0, (size_t)arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
