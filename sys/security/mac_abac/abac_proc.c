/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * ABAC Process Checks
 *
 * Handles process-related access checks and privilege grants.
 * These checks control inter-process operations like debugging,
 * signaling, and scheduler manipulation.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/ucred.h>

#include <security/mac/mac_policy.h>

#include "mac_abac.h"

/*
 * abac_proc_check_debug - Check if subject can debug target process
 *
 * This controls ptrace(), procfs access, and other debugging operations.
 * The subject is the debugger, the object is the process being debugged.
 *
 * Context constraints are checked against the SUBJECT (debugger) credential,
 * allowing rules like "deny debug if debugger is sandboxed" or
 * "deny debug from within jails".
 */
int
abac_proc_check_debug(struct ucred *cred, struct proc *p)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Get subject (debugger) label from credential */
	if (cred == NULL || cred->cr_label == NULL) {
		return (0);
	}
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object (target process) label from its credential */
	if (p == NULL || p->p_ucred == NULL || p->p_ucred->cr_label == NULL) {
		return (0);
	}
	obj = SLOT(p->p_ucred->cr_label);
	if (obj == NULL)
		obj = &abac_default_subject;  /* Processes use subject default */

	/* Evaluate rules - pass target process for object context checks */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_DEBUG, p);

	/* In permissive mode, don't enforce */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * abac_proc_check_sched - Check if subject can affect target's scheduling
 *
 * Controls setpriority(), sched_setscheduler(), etc.
 */
int
abac_proc_check_sched(struct ucred *cred, struct proc *p)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Get subject label */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object (target process) label */
	if (p == NULL || p->p_ucred == NULL || p->p_ucred->cr_label == NULL)
		return (0);
	obj = SLOT(p->p_ucred->cr_label);
	if (obj == NULL)
		obj = &abac_default_subject;

	/* Evaluate rules - pass target process for object context checks */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_SCHED, p);

	/* Permissive mode handling */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * abac_proc_check_signal - Check if subject can send signal to target
 *
 * Controls kill(), sigqueue(), etc.
 */
int
abac_proc_check_signal(struct ucred *cred, struct proc *p, int signum)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Get subject label */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object (target process) label */
	if (p == NULL || p->p_ucred == NULL || p->p_ucred->cr_label == NULL)
		return (0);
	obj = SLOT(p->p_ucred->cr_label);
	if (obj == NULL)
		obj = &abac_default_subject;

	/* Evaluate rules - pass target process for object context checks */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_SIGNAL, p);

	/* Permissive mode handling */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * abac_proc_check_wait - Check if subject can wait on target process
 *
 * Controls wait4(), waitpid(), waitid() on processes.
 * The subject is the waiting process, the object is the process being waited on.
 */
int
abac_proc_check_wait(struct ucred *cred, struct proc *p)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Get subject label */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object (target process) label */
	if (p == NULL || p->p_ucred == NULL || p->p_ucred->cr_label == NULL)
		return (0);
	obj = SLOT(p->p_ucred->cr_label);
	if (obj == NULL)
		obj = &abac_default_subject;

	/* Evaluate rules - pass target process for object context checks */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_WAIT, p);

	/* Permissive mode handling */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * Privilege check - invoked before a process uses a privilege
 *
 * This is called before any privileged operation. Unlike priv_grant,
 * which is called to check if a policy grants privileges, priv_check
 * is for denying use of privileges that would otherwise be granted.
 *
 * Use cases:
 *   - Prevent sandboxed processes from using certain privileges
 *   - Restrict privilege use based on process labels
 *
 * Note: priv_check returns 0 to allow (let other policies decide),
 * or EPERM to deny the privilege use.
 */
int
abac_priv_check(struct ucred *cred, int priv)
{
	struct abac_label *subj;

	ABAC_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		return (0);

	/*
	 * For now, we don't restrict privilege use.
	 * This hook is here for future expansion to allow rules like:
	 *   deny priv type=untrusted -> priv:PRIV_VFS_SETGID
	 *
	 * TODO: Add privilege-based rules support.
	 */
	return (0);
}

/*
 * Privilege grant - always deny (return EPERM)
 *
 * This prevents the policy from granting additional privileges.
 * We only restrict, never expand, access.
 */
int
abac_priv_grant(struct ucred *cred, int priv)
{

	return (EPERM);
}
