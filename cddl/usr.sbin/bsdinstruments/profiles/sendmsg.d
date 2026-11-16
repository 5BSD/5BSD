/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every sendmsg(2) entry */

syscall::sendmsg:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: sendmsg(fd=%d)\n",
           execname, pid, (int)arg0);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
