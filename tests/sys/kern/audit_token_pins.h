/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * The audit token interface as the T0 pins call it: through syscall(2) at
 * the numbers syscalls.master reserves for it, so that the same program
 * builds on a tree that only reserves them (where every call fails with
 * ENOSYS) and on one that implements them.
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

#ifndef AUDIT_TOKEN_MAY_EXEC
/* A tree without the implementation has no type ... */
typedef struct audit_token {
	uint64_t	__at_w[8];
} audit_token_t;

#define	AUDIT_TOKEN_MAY_EXEC	0x00000001
#define	AUDIT_TOKEN_MAY_EXIT	0x00000002
#endif

#ifndef _BSM_AUDIT_TOKEN_ACCESSORS
/*
 * ... and no accessors.  The layout below is audit_token(3)'s private one;
 * nothing but these fallbacks reads it, and they are only reached after a
 * call that cannot succeed there.
 */

static inline pid_t
audit_token_to_pid(audit_token_t t)
{
	return ((pid_t)(uint32_t)t.__at_w[3]);
}
static inline uint64_t
audit_token_to_uniqueid(audit_token_t t)
{
	return (t.__at_w[0]);
}
static inline uint64_t
audit_token_to_execgen(audit_token_t t)
{
	return (t.__at_w[1]);
}
static inline uint64_t
audit_token_to_imageid(audit_token_t t)
{
	return (t.__at_w[2]);
}
static inline int
audit_token_to_jid(audit_token_t t)
{
	return ((int)(t.__at_w[3] >> 32));
}
static inline uid_t
audit_token_to_euid(audit_token_t t)
{
	return ((uid_t)(uint32_t)t.__at_w[4]);
}
static inline uid_t
audit_token_to_ruid(audit_token_t t)
{
	return ((uid_t)(t.__at_w[4] >> 32));
}
static inline gid_t
audit_token_to_egid(audit_token_t t)
{
	return ((gid_t)(uint32_t)t.__at_w[5]);
}
static inline gid_t
audit_token_to_rgid(audit_token_t t)
{
	return ((gid_t)(t.__at_w[5] >> 32));
}
static inline uid_t
audit_token_to_auid(audit_token_t t)
{
	return ((uid_t)(uint32_t)t.__at_w[6]);
}
static inline pid_t
audit_token_to_asid(audit_token_t t)
{
	return ((pid_t)(t.__at_w[6] >> 32));
}
#endif /* !_BSM_AUDIT_TOKEN_ACCESSORS */

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

/*
 * The kinfo_proc fields; before T0 they are the last three spare longs,
 * which the kernel leaves zero.
 */
#if KI_NSPARE_LONG == 10
#define	KP_UNIQUEID(kp)	((uint64_t)(kp)->ki_sparelongs[7])
#define	KP_EXECGEN(kp)	((uint64_t)(kp)->ki_sparelongs[8])
#define	KP_IMAGEID(kp)	((uint64_t)(kp)->ki_sparelongs[9])
#else
#define	KP_UNIQUEID(kp)	((kp)->ki_uniqueid)
#define	KP_EXECGEN(kp)	((kp)->ki_execgen)
#define	KP_IMAGEID(kp)	((kp)->ki_imageid)
#endif

#endif /* !_AUDIT_TOKEN_PINS_H_ */
