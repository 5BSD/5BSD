/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every sched:::on-cpu event */

sched:::on-cpu
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched on-cpu cpu=%d\n", execname, pid, tid, cpu);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
