/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every tcp:::connect-established */

tcp:::connect-established
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp connect-established\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
