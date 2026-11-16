/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every sched::: provider event */

sched:::change-pri,
sched:::dequeue,
sched:::enqueue,
sched:::lend-pri,
sched:::load-change,
sched:::off-cpu,
sched:::on-cpu,
sched:::preempt,
sched:::remain-cpu,
sched:::sleep,
sched:::surrender,
sched:::tick,
sched:::wakeup
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched %s\n", execname, pid, tid, probename);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
