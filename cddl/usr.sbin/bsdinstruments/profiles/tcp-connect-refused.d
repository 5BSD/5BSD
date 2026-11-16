/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every tcp:::connect-refused */

tcp:::connect-refused
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp connect-refused\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
