/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print sched priority change events (change-pri + lend-pri) */

sched:::change-pri,
sched:::lend-pri
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched %s\n", execname, pid, tid, probename);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
