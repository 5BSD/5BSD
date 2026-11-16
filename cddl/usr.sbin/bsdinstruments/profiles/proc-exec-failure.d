/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every proc:::exec-failure event with errno */

proc:::exec-failure
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: proc exec-failure errno=%d\n", execname, pid, (int)arg0);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
