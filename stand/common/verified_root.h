/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LOADER_VERIFIED_ROOT_H_
#define _LOADER_VERIFIED_ROOT_H_
#include <geom/verity/g_verity_verify.h>
#include <geom/verity/g_verity_transition.h>
/* Caller owns G_VERITY_ROOT_BYTES of output; unchanged on failure. */
ssize_t verified_root_read(int, const char *, unsigned char *);
/* Caller owns G_VERITY_TRANSITION_BYTES of output; unchanged on failure. */
ssize_t verified_transition_read(int, const char *, unsigned char *);
#endif
