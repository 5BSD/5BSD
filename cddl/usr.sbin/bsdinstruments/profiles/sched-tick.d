/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every sched:::tick event */

sched:::tick
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched tick\n", execname, pid, tid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
