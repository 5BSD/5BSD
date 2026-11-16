/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every sched:::sleep event */

sched:::sleep
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched sleep\n", execname, pid, tid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
