/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every tcp connection initialization event (accept + connect lifecycle) */

tcp:::accept-established,
tcp:::accept-refused,
tcp:::connect-established,
tcp:::connect-refused,
tcp:::connect-request
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp %s\n", execname, pid, probename);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
