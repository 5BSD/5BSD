/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every tcp accept event (established + refused) */

tcp:::accept-established,
tcp:::accept-refused
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp %s\n", execname, pid, probename);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
