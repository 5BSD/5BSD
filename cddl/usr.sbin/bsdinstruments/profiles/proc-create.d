/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every proc:::create event */

proc:::create
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: proc create\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
