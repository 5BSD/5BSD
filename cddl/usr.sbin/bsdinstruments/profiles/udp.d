/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every UDP send and receive with payload length */

udp:::send
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: udp send len=%d\n", execname, pid, args[2]->ip_plength);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

udp:::receive
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: udp recv len=%d\n", execname, pid, args[2]->ip_plength);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
