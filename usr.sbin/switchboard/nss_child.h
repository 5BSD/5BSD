/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_NSS_CHILD_H
#define SWITCHBOARD_NSS_CHILD_H
#include <sys/cdefs.h>
/* Child of pdfork only. All three descriptors must be distinct and >= 3.
 * The caller supplies private request/reply pipes and a harmless stderr fd.
 * Never returns: failed isolation or exec exits with status 126. */
void sb_nss_child_exec(const char *, int, int, int) __dead2;
#endif
