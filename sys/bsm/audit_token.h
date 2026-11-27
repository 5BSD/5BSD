/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * The kernel's view of the audit token (audit_token(3)): accessors for the
 * opaque audit_token_t of <bsm/audit.h>, and the functions that fill and
 * look up tokens (kern_audit_token.c).  Programs use libbsm's accessors.
 */

#ifndef _BSM_AUDIT_TOKEN_H_
#define	_BSM_AUDIT_TOKEN_H_

#ifndef _KERNEL
#error "<bsm/audit_token.h> is for the kernel; programs use <bsm/libbsm.h>"
#endif

#include <bsm/audit.h>
#include <bsm/audit_token_internal.h>

static __inline uint64_t
audit_token_to_uniqueid(const audit_token_t *t)
{
	return (t->__at_w[AUDIT_TOKEN_W_UNIQUEID]);
}

static __inline uint64_t
audit_token_to_execgen(const audit_token_t *t)
{
	return (t->__at_w[AUDIT_TOKEN_W_EXECGEN]);
}

static __inline uint64_t
audit_token_to_imageid(const audit_token_t *t)
{
	return (t->__at_w[AUDIT_TOKEN_W_IMAGEID]);
}

static __inline pid_t
audit_token_to_pid(const audit_token_t *t)
{
	return ((pid_t)AUDIT_TOKEN_LO(t, AUDIT_TOKEN_W_PID_JID));
}

static __inline int
audit_token_to_jid(const audit_token_t *t)
{
	return ((int)AUDIT_TOKEN_HI(t, AUDIT_TOKEN_W_PID_JID));
}

static __inline uid_t
audit_token_to_euid(const audit_token_t *t)
{
	return ((uid_t)AUDIT_TOKEN_LO(t, AUDIT_TOKEN_W_UIDS));
}

static __inline uid_t
audit_token_to_ruid(const audit_token_t *t)
{
	return ((uid_t)AUDIT_TOKEN_HI(t, AUDIT_TOKEN_W_UIDS));
}

static __inline gid_t
audit_token_to_egid(const audit_token_t *t)
{
	return ((gid_t)AUDIT_TOKEN_LO(t, AUDIT_TOKEN_W_GIDS));
}

static __inline gid_t
audit_token_to_rgid(const audit_token_t *t)
{
	return ((gid_t)AUDIT_TOKEN_HI(t, AUDIT_TOKEN_W_GIDS));
}

static __inline au_id_t
audit_token_to_auid(const audit_token_t *t)
{
	return ((au_id_t)AUDIT_TOKEN_LO(t, AUDIT_TOKEN_W_AUDIT));
}

static __inline au_asid_t
audit_token_to_asid(const audit_token_t *t)
{
	return ((au_asid_t)AUDIT_TOKEN_HI(t, AUDIT_TOKEN_W_AUDIT));
}

struct proc;
struct thread;

/* The token of curthread's process, with curthread's credential. */
void	audit_token_fill(struct thread *td, audit_token_t *tok);
/* The token of p, with p's credential; p is locked. */
void	audit_token_fill_proc(struct proc *p, audit_token_t *tok);
/* Whether the locked p is the process tok names. */
bool	audit_token_match_proc(struct proc *p, const audit_token_t *tok,
	    int flags);
/* The process tok names, locked, or NULL. */
struct proc *audit_token_find(const audit_token_t *tok, int flags);
/* 0 if the process tok names exists, else ESRCH. */
int	audit_token_check(const audit_token_t *tok, int flags);

/* The boot's offset of the sequences (proc0_init() only). */
uint64_t audit_token_boot_offset(void);
/* The next exec generation (fork, exec) and image id (exec). */
uint64_t audit_token_next_execgen(void);
uint64_t audit_token_next_imageid(void);

#endif /* !_BSM_AUDIT_TOKEN_H_ */
