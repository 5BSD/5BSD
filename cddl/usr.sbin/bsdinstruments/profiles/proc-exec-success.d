/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every proc:::exec-success event */

proc:::exec-success
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: proc exec-success\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
