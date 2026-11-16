/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every proc:::signal-clear event */

proc:::signal-clear
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: proc signal-clear\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
