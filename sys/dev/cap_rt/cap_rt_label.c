/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cap_rt — MACF credential label management.
 *
 * Each process credential carries a unique 64-bit nonce that is:
 *   - Inherited on fork (same nonce → same program identity)
 *   - Rotated on exec (new nonce → new program identity)
 *   - Kernel-assigned, unforgeable
 *
 * The nonce is stored in a per-credential MAC label slot allocated
 * by MAC_POLICY_SET.  The exec transition hook runs with the process
 * lock held, so this policy must be registered as a static boot-time
 * policy (MPC_LOADTIME_FLAG_NOTLATE).
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/imgact.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sdt.h>
#include <sys/ucred.h>
#include <sys/vnode.h>

#include <security/mac/mac_policy.h>

#include "cap_rt_label.h"

MALLOC_DECLARE(M_CAP_RT);

struct cap_rt_label {
	uint64_t	cl_nonce;
};

static int cap_rt_label_slot;

SDT_PROVIDER_DEFINE(cap_rt_nonce);
SDT_PROBE_DEFINE3(cap_rt_nonce, , , assign,
    "struct ucred *", "uint64_t", "pid_t");
SDT_PROBE_DEFINE2(cap_rt_nonce, , , copy,
    "uint64_t", "uint64_t");
SDT_PROBE_DEFINE5(cap_rt_nonce, , , exec__rotate,
    "pid_t", "struct ucred *", "struct ucred *", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE3(cap_rt_nonce, , , backfill,
    "struct ucred *", "uint64_t", "pid_t");

#define	SLOT(l)		((struct cap_rt_label *)mac_label_get((l), cap_rt_label_slot))
#define	SLOT_SET(l, v)	mac_label_set((l), cap_rt_label_slot, (uintptr_t)(v))

static void
cap_rt_label_gen_nonce(struct cap_rt_label *cl)
{

	/* Nonce 0 reserved. */
	do {
		arc4random_buf(&cl->cl_nonce, sizeof(cl->cl_nonce));
	} while (cl->cl_nonce == 0);
}

static void
cap_rt_cred_init_label(struct label *label)
{
	struct cap_rt_label *cl;

	cl = malloc(sizeof(*cl), M_CAP_RT, M_WAITOK | M_ZERO);
	SLOT_SET(label, cl);
}

static void
cap_rt_cred_create_init(struct ucred *cred)
{
	struct cap_rt_label *cl;

	cl = SLOT(cred->cr_label);
	if (cl != NULL) {
		cap_rt_label_gen_nonce(cl);
		SDT_PROBE3(cap_rt_nonce, , , assign, cred, cl->cl_nonce,
		    (curthread != NULL ? curthread->td_proc->p_pid : -1));
	}
}

static void
cap_rt_cred_copy_label(struct label *src, struct label *dest)
{
	struct cap_rt_label *scl, *dcl;

	scl = SLOT(src);
	dcl = SLOT(dest);
	if (scl != NULL && dcl != NULL) {
		*dcl = *scl;
		SDT_PROBE2(cap_rt_nonce, , , copy, scl->cl_nonce,
		    dcl->cl_nonce);
	}
}

static void
cap_rt_cred_destroy_label(struct label *label)
{
	struct cap_rt_label *cl;

	cl = SLOT(label);
	if (cl != NULL) {
		free(cl, M_CAP_RT);
		SLOT_SET(label, NULL);
	}
}

static int
cap_rt_execve_will_transition(struct ucred *old, struct vnode *vp,
    struct label *vplabel, struct label *interpvplabel,
    struct image_params *imgp, struct label *execlabel)
{

	return (1);
}

static void
cap_rt_execve_transition(struct ucred *old, struct ucred *new,
    struct vnode *vp, struct label *vplabel,
    struct label *interpvplabel, struct image_params *imgp,
    struct label *execlabel)
{
	struct cap_rt_label *cl;
	uint64_t old_nonce, new_nonce;

	old_nonce = cap_rt_proc_nonce(old);
	cl = SLOT(new->cr_label);
	if (cl != NULL) {
		cap_rt_label_gen_nonce(cl);
		new_nonce = cl->cl_nonce;
		SDT_PROBE5(cap_rt_nonce, , , exec__rotate,
		    curthread->td_proc->p_pid, old, new, old_nonce,
		    new_nonce);
	}
}

uint64_t
cap_rt_proc_nonce(struct ucred *cred)
{
	struct cap_rt_label *cl, *newcl;

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	cl = SLOT(cred->cr_label);
	if (cl == NULL) {
		/*
		 * Backfill missing labels for credentials that predate
		 * policy registration.  Use M_NOWAIT because this accessor
		 * is used from no-sleep contexts such as MAC hooks.
		 */
		newcl = malloc(sizeof(*newcl), M_CAP_RT, M_NOWAIT | M_ZERO);
		if (newcl == NULL)
			return (0);
		cap_rt_label_gen_nonce(newcl);

		mtx_lock(&cred->cr_mtx);
		cl = SLOT(cred->cr_label);
		if (cl == NULL) {
			SLOT_SET(cred->cr_label, newcl);
			cl = newcl;
			newcl = NULL;
			SDT_PROBE3(cap_rt_nonce, , , backfill, cred,
			    cl->cl_nonce,
			    (curthread != NULL ? curthread->td_proc->p_pid : -1));
		}
		mtx_unlock(&cred->cr_mtx);

		if (newcl != NULL)
			free(newcl, M_CAP_RT);
	}
	return (cl->cl_nonce);
}

static struct mac_policy_ops cap_rt_label_mac_ops = {
	.mpo_cred_init_label = cap_rt_cred_init_label,
	.mpo_cred_create_init = cap_rt_cred_create_init,
	.mpo_cred_copy_label = cap_rt_cred_copy_label,
	.mpo_cred_destroy_label = cap_rt_cred_destroy_label,
	.mpo_vnode_execve_will_transition = cap_rt_execve_will_transition,
	.mpo_vnode_execve_transition = cap_rt_execve_transition,
};

MAC_POLICY_SET(&cap_rt_label_mac_ops, mac_cap_rt, "CAP_RT credential nonce",
    MPC_LOADTIME_FLAG_NOTLATE, &cap_rt_label_slot);
