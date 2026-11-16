/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every sched:::enqueue event */

sched:::enqueue
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched enqueue\n", execname, pid, tid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
