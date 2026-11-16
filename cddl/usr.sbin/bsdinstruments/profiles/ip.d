/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every IP send and receive event */

ip:::send
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: ip send\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

ip:::receive
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: ip recv\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
