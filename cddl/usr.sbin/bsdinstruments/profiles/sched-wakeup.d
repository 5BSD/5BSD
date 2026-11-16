/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every sched:::wakeup event */

sched:::wakeup
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched wakeup\n", execname, pid, tid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
