/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * The audit token interface as the T0 pins call it: through syscall(2) at
 * the numbers syscalls.master gives it, as they were first run on a tree
 * that only reserved them (where every call failed with ENOSYS).  The
 * libc wrappers are checked against these in audit_token_test:libc_wrappers.
 */

#ifndef _AUDIT_TOKEN_PINS_H_
#define	_AUDIT_TOKEN_PINS_H_

#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/user.h>

#include <bsm/audit.h>
#include <bsm/libbsm.h>

#include <stdint.h>
#include <unistd.h>

/* The numbers reserved in sys/kern/syscalls.master. */
#define	PIN_SYS_audit_token_get		1012
#define	PIN_SYS_audit_token_check	1013
#define	PIN_SYS_pdopentoken		1014
_Static_assert(SYS_audit_token_get == PIN_SYS_audit_token_get, "moved");
_Static_assert(SYS_audit_token_check == PIN_SYS_audit_token_check, "moved");
_Static_assert(SYS_pdopentoken == PIN_SYS_pdopentoken, "moved");

static inline int
pin_audit_token_get(int pd, pid_t pid, int flags, audit_token_t *out)
{
	return (syscall(PIN_SYS_audit_token_get, pd, pid, flags, out));
}

static inline int
pin_audit_token_check(const audit_token_t *tok, int flags)
{
	return (syscall(PIN_SYS_audit_token_check, tok, flags));
}

static inline int
pin_pdopentoken(const audit_token_t *tok, int flags)
{
	return (syscall(PIN_SYS_pdopentoken, tok, flags));
}

/* The kinfo_proc fields. */
#define	KP_UNIQUEID(kp)	((kp)->ki_uniqueid)
#define	KP_EXECGEN(kp)	((kp)->ki_execgen)
#define	KP_IMAGEID(kp)	((kp)->ki_imageid)

#endif /* !_AUDIT_TOKEN_PINS_H_ */
