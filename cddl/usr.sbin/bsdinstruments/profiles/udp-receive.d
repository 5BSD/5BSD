/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every udp:::receive event */

udp:::receive
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: udp recv len=%d\n", execname, pid, args[2]->ip_plength);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
