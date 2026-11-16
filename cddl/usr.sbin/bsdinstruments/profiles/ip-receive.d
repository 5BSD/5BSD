/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every ip:::receive event */

ip:::receive
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: ip recv\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
