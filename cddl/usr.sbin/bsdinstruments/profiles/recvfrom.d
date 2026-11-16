/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every recvfrom(2) entry */

syscall::recvfrom:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: recvfrom(fd=%d, %d)\n",
           execname, pid, (int)arg0, (size_t)arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
