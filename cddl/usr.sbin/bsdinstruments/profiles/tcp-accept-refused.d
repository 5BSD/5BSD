/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every tcp:::accept-refused */

tcp:::accept-refused
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp accept-refused\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
