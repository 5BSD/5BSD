/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_OOM_PROTECT_H
#define SWITCHBOARD_OOM_PROTECT_H
#include <sys/types.h>
#include <stdbool.h>
/* Caller owns an unreaped, launch-gated child; never accept a client PID. */
int svc_oom_protect(pid_t, bool, bool);
#endif
