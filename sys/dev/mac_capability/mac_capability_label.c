/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * mac_capability — MACF credential label management.
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

#include "mac_capability_label.h"

MALLOC_DECLARE(M_MAC_CAPABILITY);

struct mac_capability_label {
	uint64_t	cl_nonce;
};

static int mac_capability_label_slot;

SDT_PROVIDER_DEFINE(mac_capability_nonce);
SDT_PROBE_DEFINE3(mac_capability_nonce, , , assign,
    "struct ucred *", "uint64_t", "pid_t");
SDT_PROBE_DEFINE2(mac_capability_nonce, , , copy,
    "uint64_t", "uint64_t");
SDT_PROBE_DEFINE5(mac_capability_nonce, , , exec__rotate,
    "pid_t", "struct ucred *", "struct ucred *", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE3(mac_capability_nonce, , , backfill,
    "struct ucred *", "uint64_t", "pid_t");

#define	SLOT(l)		((struct mac_capability_label *)mac_label_get((l), mac_capability_label_slot))
#define	SLOT_SET(l, v)	mac_label_set((l), mac_capability_label_slot, (uintptr_t)(v))

static void
mac_capability_label_gen_nonce(struct mac_capability_label *cl)
{

	/* Nonce 0 reserved. */
	do {
		arc4random_buf(&cl->cl_nonce, sizeof(cl->cl_nonce));
	} while (cl->cl_nonce == 0);
}

static void
mac_capability_cred_init_label(struct label *label)
{
	struct mac_capability_label *cl;

	cl = malloc(sizeof(*cl), M_MAC_CAPABILITY, M_WAITOK | M_ZERO);
	SLOT_SET(label, cl);
}

static void
mac_capability_cred_create_init(struct ucred *cred)
{
	struct mac_capability_label *cl;

	cl = SLOT(cred->cr_label);
	if (cl != NULL) {
		mac_capability_label_gen_nonce(cl);
		SDT_PROBE3(mac_capability_nonce, , , assign, cred, cl->cl_nonce,
		    (curthread != NULL ? curthread->td_proc->p_pid : -1));
	}
}

static void
mac_capability_cred_copy_label(struct label *src, struct label *dest)
{
	struct mac_capability_label *scl, *dcl;

	scl = SLOT(src);
	dcl = SLOT(dest);
	if (dcl == NULL)
		return;
	if (scl != NULL) {
		*dcl = *scl;
		SDT_PROBE2(mac_capability_nonce, , , copy, scl->cl_nonce,
		    dcl->cl_nonce);
	} else {
		mac_capability_label_gen_nonce(dcl);
		SDT_PROBE3(mac_capability_nonce, , , backfill, NULL,
		    dcl->cl_nonce, curthread->td_proc->p_pid);
	}
}

static void
mac_capability_cred_destroy_label(struct label *label)
{
	struct mac_capability_label *cl;

	cl = SLOT(label);
	if (cl != NULL) {
		free(cl, M_MAC_CAPABILITY);
		SLOT_SET(label, NULL);
	}
}

static int
mac_capability_execve_will_transition(struct ucred *old, struct vnode *vp,
    struct label *vplabel, struct label *interpvplabel,
    struct image_params *imgp, struct label *execlabel)
{

	return (SLOT(old->cr_label) != NULL);
}

static void
mac_capability_execve_transition(struct ucred *old, struct ucred *new,
    struct vnode *vp, struct label *vplabel,
    struct label *interpvplabel, struct image_params *imgp,
    struct label *execlabel)
{
	struct mac_capability_label *cl;
	uint64_t old_nonce __diagused, new_nonce __diagused;

	old_nonce = mac_capability_proc_nonce(old);
	cl = SLOT(new->cr_label);
	if (cl != NULL) {
		mac_capability_label_gen_nonce(cl);
		new_nonce = cl->cl_nonce;
		SDT_PROBE5(mac_capability_nonce, , , exec__rotate,
		    curthread->td_proc->p_pid, old, new, old_nonce,
		    new_nonce);
	}
}

uint64_t
mac_capability_proc_nonce(struct ucred *cred)
{
	struct mac_capability_label *cl, *newcl;

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	cl = SLOT(cred->cr_label);
	if (cl == NULL) {
		/*
		 * Backfill missing labels for credentials that predate
		 * policy registration.  Use M_NOWAIT because this accessor
		 * is used from no-sleep contexts such as MAC hooks.
		 */
		newcl = malloc(sizeof(*newcl), M_MAC_CAPABILITY, M_NOWAIT | M_ZERO);
		if (newcl == NULL)
			return (0);
		mac_capability_label_gen_nonce(newcl);

		mtx_lock(&cred->cr_mtx);
		cl = SLOT(cred->cr_label);
		if (cl == NULL) {
			SLOT_SET(cred->cr_label, newcl);
			cl = newcl;
			newcl = NULL;
			SDT_PROBE3(mac_capability_nonce, , , backfill, cred,
			    cl->cl_nonce,
			    (curthread != NULL ? curthread->td_proc->p_pid : -1));
		}
		mtx_unlock(&cred->cr_mtx);

		if (newcl != NULL)
			free(newcl, M_MAC_CAPABILITY);
	}
	return (cl->cl_nonce);
}

static struct mac_policy_ops mac_capability_label_mac_ops = {
	.mpo_cred_init_label = mac_capability_cred_init_label,
	.mpo_cred_create_init = mac_capability_cred_create_init,
	.mpo_cred_copy_label = mac_capability_cred_copy_label,
	.mpo_cred_destroy_label = mac_capability_cred_destroy_label,
	.mpo_vnode_execve_will_transition = mac_capability_execve_will_transition,
	.mpo_vnode_execve_transition = mac_capability_execve_transition,
};

MAC_POLICY_SET(&mac_capability_label_mac_ops, mac_mac_capability, "MAC_CAPABILITY credential nonce",
    MPC_LOADTIME_FLAG_NOTLATE, &mac_capability_label_slot);
