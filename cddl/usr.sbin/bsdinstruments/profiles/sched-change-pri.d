/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every sched:::change-pri event */

sched:::change-pri
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched change-pri\n", execname, pid, tid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
