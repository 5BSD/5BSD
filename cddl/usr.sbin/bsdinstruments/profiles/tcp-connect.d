/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every tcp connect lifecycle event (request + established + refused) */

tcp:::connect-request,
tcp:::connect-established,
tcp:::connect-refused
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp %s\n", execname, pid, probename);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
