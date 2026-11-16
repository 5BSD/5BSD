/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every block-I/O done event */

io:::done
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: io done\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
