/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef MANIFEST_TRUST_PROBE_SHIM_H
#define MANIFEST_TRUST_PROBE_SHIM_H
#include <sys/cdefs.h>
void panic(const char *, ...) __dead2 __printflike(1, 2);
#endif
