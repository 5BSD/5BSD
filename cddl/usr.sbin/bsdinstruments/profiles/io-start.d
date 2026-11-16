/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every block-I/O start event */

io:::start
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: io start\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
