/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * The audit token (audit_token(3)): an opaque identity of a process at one
 * point of its life, owned by BSM.  It carries three 64-bit ids beside the
 * pid, jail and user, group and audit ids:
 *
 * uniqueid	set at fork from a sequence kern_fork.c keeps under
 *		procid_lock, never changes and is never reused;
 * execgen	new at fork and at every exec (audit_token_next_execgen());
 * imageid	the credential's (cr_imageid): new at every exec
 *		(audit_token_next_imageid()), shared with forks through the
 *		credential, kept by setuid; 0 for credentials the kernel makes
 *		(crget(), proc0 and kernel processes), which have no image.
 *
 * They are counters, not secrets: what a token authorizes is decided by
 * whoever was handed it, never by its being unguessable.
 *
 * A token names a process when its pid, uniqueid and execgen match
 * (AUDIT_TOKEN_MAY_EXEC ignores the execgen); an exited process matches
 * only with AUDIT_TOKEN_MAY_EXIT.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/file.h>
#include <sys/jail.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/procdesc.h>
#include <sys/sx.h>
#include <sys/sysproto.h>
#include <sys/ucred.h>

#include <machine/atomic.h>

#include <bsm/audit_token.h>
#include <security/audit/audit.h>

/* The last exec generation and image id handed out; 64 bits, no wrap. */
static uint64_t audit_token_execgen_seq;
static uint64_t audit_token_imageid_seq;

uint64_t
audit_token_next_execgen(void)
{
	return (atomic_fetchadd_64(&audit_token_execgen_seq, 1) + 1);
}

uint64_t
audit_token_next_imageid(void)
{
	return (atomic_fetchadd_64(&audit_token_imageid_seq, 1) + 1);
}

static void
audit_token_fill_cred(audit_token_t *tok, struct proc *p, uint64_t execgen,
    struct ucred *cred)
{
	tok->__at_w[AUDIT_TOKEN_W_UNIQUEID] = p->p_uniqueid;
	tok->__at_w[AUDIT_TOKEN_W_EXECGEN] = execgen;
	tok->__at_w[AUDIT_TOKEN_W_IMAGEID] = cred->cr_imageid;
	tok->__at_w[AUDIT_TOKEN_W_PID_JID] = AUDIT_TOKEN_PAIR(p->p_pid,
	    cred->cr_prison->pr_id);
	tok->__at_w[AUDIT_TOKEN_W_UIDS] = AUDIT_TOKEN_PAIR(cred->cr_uid,
	    cred->cr_ruid);
	tok->__at_w[AUDIT_TOKEN_W_GIDS] = AUDIT_TOKEN_PAIR(cred->cr_gid,
	    cred->cr_rgid);
	tok->__at_w[AUDIT_TOKEN_W_AUDIT] = AUDIT_TOKEN_PAIR(
	    cred->cr_audit.ai_auid, cred->cr_audit.ai_asid);
	tok->__at_w[AUDIT_TOKEN_W_RESERVED] = 0;
}

/*
 * The token of curthread's process with the thread's credential, as a
 * carrier stamps it at the event.  p_execgen is read without the process
 * lock: only an exec of this process changes it.
 */
void
audit_token_fill(struct thread *td, audit_token_t *tok)
{
	KASSERT(td == curthread, ("audit_token_fill: td %p not curthread",
	    td));
	audit_token_fill_cred(tok, td->td_proc, td->td_proc->p_execgen,
	    td->td_ucred);
}

void
audit_token_fill_proc(struct proc *p, audit_token_t *tok)
{
	PROC_LOCK_ASSERT(p, MA_OWNED);
	audit_token_fill_cred(tok, p, p->p_execgen, p->p_ucred);
}

/*
 * Whether the locked p is the process tok names: same pid and uniqueid,
 * and same execgen unless AUDIT_TOKEN_MAY_EXEC.  Whether p has exited is
 * the caller's question.
 */
bool
audit_token_match_proc(struct proc *p, const audit_token_t *tok, int flags)
{
	PROC_LOCK_ASSERT(p, MA_OWNED);
	return (p->p_pid == audit_token_to_pid(tok) &&
	    p->p_uniqueid == audit_token_to_uniqueid(tok) &&
	    ((flags & AUDIT_TOKEN_MAY_EXEC) != 0 ||
	    p->p_execgen == audit_token_to_execgen(tok)));
}

/*
 * The process tok names, locked, or NULL.  A process that has begun to
 * exit (P_WEXIT), zombies included, is found only with
 * AUDIT_TOKEN_MAY_EXIT.
 */
struct proc *
audit_token_find(const audit_token_t *tok, int flags)
{
	struct proc *p;
	pid_t pid;

	pid = audit_token_to_pid(tok);
	if (pid < 0 || pid > PID_MAX)
		return (NULL);
	p = pfind_any(pid);
	if (p == NULL)
		return (NULL);
	if (!audit_token_match_proc(p, tok, flags) ||
	    ((flags & AUDIT_TOKEN_MAY_EXIT) == 0 &&
	    (p->p_flag & P_WEXIT) != 0)) {
		PROC_UNLOCK(p);
		return (NULL);
	}
	return (p);
}

int
audit_token_check(const audit_token_t *tok, int flags)
{
	struct proc *p;

	p = audit_token_find(tok, flags);
	if (p == NULL)
		return (ESRCH);
	PROC_UNLOCK(p);
	return (0);
}

/*
 * Fill tok from the locked p and unlock it; an exited p is refused unless
 * AUDIT_TOKEN_MAY_EXIT.
 */
static int
audit_token_get_locked(struct proc *p, int flags, audit_token_t *tok)
{
	int error;

	error = 0;
	if ((flags & AUDIT_TOKEN_MAY_EXIT) == 0 && (p->p_flag & P_WEXIT) != 0)
		error = ESRCH;
	else
		audit_token_fill_proc(p, tok);
	PROC_UNLOCK(p);
	return (error);
}

/*
 * audit_token_get(2): the token of the process a process descriptor names
 * (pd >= 0, pid 0), of the caller (pd -1, pid 0), or of a process by pid
 * (pd -1, pid > 0).  The descriptor is the authority: it needs no further
 * check.  By pid, a process the caller may not see (p_cansee()) does not
 * exist, and capability mode refuses the lookup.
 */
int
sys_audit_token_get(struct thread *td, struct audit_token_get_args *uap)
{
	audit_token_t tok;
	struct file *fp;
	struct proc *p;
	int error;

	if (uap->pd >= 0)
		AUDIT_ARG_FD(uap->pd);
	AUDIT_ARG_PID(uap->pid);
	AUDIT_ARG_VALUE(uap->flags);
	if ((uap->flags & ~AUDIT_TOKEN_MAY_EXIT) != 0 || uap->pid < 0 ||
	    (uap->pd >= 0 && uap->pid != 0))
		return (EINVAL);
	if (uap->pd < -1)
		return (EBADF);

	fp = NULL;
	if (uap->pd >= 0) {
		/*
		 * proctree_lock keeps pd_proc; the file is dropped only after
		 * both locks, as its close may take proctree_lock.
		 */
		sx_slock(&proctree_lock);
		error = fget_procdesc(td, uap->pd, &cap_pdgetpid_rights, EBADF,
		    &fp, NULL, &p);
		if (error == 0)
			error = audit_token_get_locked(p, uap->flags, &tok);
		sx_sunlock(&proctree_lock);
		if (fp != NULL)
			fdrop(fp, td);
	} else if (uap->pid == 0) {
		p = td->td_proc;
		PROC_LOCK(p);
		error = audit_token_get_locked(p, uap->flags, &tok);
	} else if (IN_CAPABILITY_MODE(td)) {
		error = ECAPMODE;
	} else {
		error = pget(uap->pid, PGET_NOTID, &p);
		if (error == 0) {
			if (p_cansee(td, p) != 0) {
				PROC_UNLOCK(p);
				error = ESRCH;
			} else
				error = audit_token_get_locked(p, uap->flags,
				    &tok);
		}
	}
	if (error != 0)
		return (error);
	return (copyout(&tok, uap->out, sizeof(tok)));
}

/*
 * audit_token_check(2): 0 if the process the token names exists and the
 * caller may see it, else ESRCH.  In capability mode only the caller and
 * its descendants can match, so a sandbox cannot probe the process table.
 */
int
sys_audit_token_check(struct thread *td, struct audit_token_check_args *uap)
{
	audit_token_t tok;
	struct proc *p;
	int error;

	AUDIT_ARG_VALUE(uap->flags);
	if ((uap->flags & ~(AUDIT_TOKEN_MAY_EXEC | AUDIT_TOKEN_MAY_EXIT)) != 0)
		return (EINVAL);
	error = copyin(uap->tok, &tok, sizeof(tok));
	if (error != 0)
		return (error);
	AUDIT_ARG_PID(audit_token_to_pid(&tok));

	sx_slock(&proctree_lock);
	p = audit_token_find(&tok, uap->flags);
	if (p == NULL) {
		error = ESRCH;
	} else {
		if ((IN_CAPABILITY_MODE(td) && !inferior(p)) ||
		    p_cansee(td, p) != 0)
			error = ESRCH;
		PROC_UNLOCK(p);
	}
	sx_sunlock(&proctree_lock);
	return (error);
}
