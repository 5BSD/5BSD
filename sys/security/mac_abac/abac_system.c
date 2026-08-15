/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * ABAC System-Level Access Checks
 *
 * Handles system-level operations: kld, reboot, sysctl, mount, etc.
 * These operations don't have traditional object labels - we check
 * against the subject's credential and a synthetic "system" label.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <sys/vnode.h>

#include <machine/atomic.h>
#include <machine/cpu.h>

#include <security/mac/mac_policy.h>

#include "mac_abac.h"

/*
 * Synthetic label for system objects (kld, reboot, sysctl, etc.)
 *
 * Since system operations don't have traditional object labels,
 * we use a synthetic label "type=system" to allow rules like:
 *   deny kld type=untrusted -> type=system
 *   allow kld type=admin -> type=system
 *
 * Initialization states:
 *   0 = not initialized
 *   1 = initialization in progress
 *   2 = initialized
 */
static struct abac_label abac_system_label;
static volatile int abac_system_label_state = 0;

static void
abac_system_label_init(void)
{

	/*
	 * Use atomic compare-and-set to avoid race condition where
	 * multiple threads could simultaneously initialize the label.
	 * Only one thread will succeed in transitioning 0 -> 1.
	 */
	if (atomic_load_acq_int(&abac_system_label_state) == 2)
		return;

	if (!atomic_cmpset_int(&abac_system_label_state, 0, 1)) {
		/*
		 * Another thread is initializing or already initialized.
		 * Spin until initialization is complete.
		 */
		while (atomic_load_acq_int(&abac_system_label_state) != 2)
			cpu_spinwait();
		return;
	}

	/* We won the race - initialize the label */
	abac_system_label.vl_npairs = 1;
	strlcpy(abac_system_label.vl_pairs[0].vp_key, "type",
	    sizeof(abac_system_label.vl_pairs[0].vp_key));
	strlcpy(abac_system_label.vl_pairs[0].vp_value, "system",
	    sizeof(abac_system_label.vl_pairs[0].vp_value));
	abac_system_label.vl_hash = abac_label_hash("type=system\n", 12);

	/* Mark initialization complete with release semantics */
	atomic_store_rel_int(&abac_system_label_state, 2);
}

/*
 * kld_check_load - Check if credential can load a kernel module
 *
 * vp is the vnode of the module being loaded. If the module has a label,
 * we check against that; otherwise we use the system label.
 */
int
abac_kld_check_load(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Use vnode label if available, otherwise system label */
	if (vplabel != NULL) {
		obj = SLOT(vplabel);
		if (obj == NULL)
			obj = &abac_default_object;
	} else {
		abac_system_label_init();
		obj = &abac_system_label;
	}

	/* Check kld operation - maps to exec since we're loading code */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_EXEC, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * kld_check_stat - Check if credential can query loaded modules
 *
 * This is a subject-only check - no object involved.
 */
int
abac_kld_check_stat(struct ucred *cred)
{
	struct abac_label *subj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	abac_system_label_init();

	/* Check stat against system label */
	error = abac_rules_check(cred, subj, &abac_system_label,
	    ABAC_OP_STAT, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * system_check_reboot - Check if credential can reboot the system
 */
int
abac_system_check_reboot(struct ucred *cred, int howto)
{
	struct abac_label *subj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	abac_system_label_init();

	/* Check write against system label - reboot modifies system state */
	error = abac_rules_check(cred, subj, &abac_system_label,
	    ABAC_OP_WRITE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * system_check_sysctl - Check if credential can access sysctl
 *
 * This is called for every sysctl access. Be careful about performance.
 */
int
abac_system_check_sysctl(struct ucred *cred, struct sysctl_oid *oidp,
    void *arg1, int arg2, struct sysctl_req *req)
{
	struct abac_label *subj;
	uint32_t op;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	abac_system_label_init();

	/* Determine if read or write based on request */
	if (req != NULL && req->newptr != NULL)
		op = ABAC_OP_WRITE;
	else
		op = ABAC_OP_READ;

	error = abac_rules_check(cred, subj, &abac_system_label, op, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * system_check_acct - Check if credential can enable/disable accounting
 */
int
abac_system_check_acct(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Use vnode label if provided, otherwise system label */
	if (vp != NULL && vplabel != NULL) {
		obj = SLOT(vplabel);
		if (obj == NULL)
			obj = &abac_default_object;
	} else {
		abac_system_label_init();
		obj = &abac_system_label;
	}

	error = abac_rules_check(cred, subj, obj, ABAC_OP_WRITE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * system_check_swapon - Check if credential can enable swap
 */
int
abac_system_check_swapon(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Use vnode label if provided, otherwise system label */
	if (vp != NULL && vplabel != NULL) {
		obj = SLOT(vplabel);
		if (obj == NULL)
			obj = &abac_default_object;
	} else {
		abac_system_label_init();
		obj = &abac_system_label;
	}

	error = abac_rules_check(cred, subj, obj, ABAC_OP_WRITE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * system_check_swapoff - Check if credential can disable swap
 */
int
abac_system_check_swapoff(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Use vnode label if provided, otherwise system label */
	if (vp != NULL && vplabel != NULL) {
		obj = SLOT(vplabel);
		if (obj == NULL)
			obj = &abac_default_object;
	} else {
		abac_system_label_init();
		obj = &abac_system_label;
	}

	error = abac_rules_check(cred, subj, obj, ABAC_OP_WRITE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * mount_check_stat - Check if credential can stat a mount point
 */
int
abac_mount_check_stat(struct ucred *cred, struct mount *mp,
    struct label *mplabel)
{
	struct abac_label *subj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	abac_system_label_init();

	error = abac_rules_check(cred, subj, &abac_system_label,
	    ABAC_OP_STAT, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * BSM Audit system checks
 *
 * These control access to BSM audit operations. The AUDIT operation
 * allows rules like:
 *   deny audit type=untrusted -> type=system
 */

/*
 * system_check_audit - Check if credential can submit an audit record
 */
int
abac_system_check_audit(struct ucred *cred, void *record, int length)
{
	struct abac_label *subj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	abac_system_label_init();

	error = abac_rules_check(cred, subj, &abac_system_label,
	    ABAC_OP_AUDIT, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * system_check_auditctl - Check if credential can change audit log file
 */
int
abac_system_check_auditctl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Use vnode label if provided, otherwise system label */
	if (vp != NULL && vplabel != NULL) {
		obj = SLOT(vplabel);
		if (obj == NULL)
			obj = &abac_default_object;
	} else {
		abac_system_label_init();
		obj = &abac_system_label;
	}

	error = abac_rules_check(cred, subj, obj, ABAC_OP_AUDIT, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * system_check_auditon - Check if credential can configure audit system
 */
int
abac_system_check_auditon(struct ucred *cred, int cmd)
{
	struct abac_label *subj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	abac_system_label_init();

	error = abac_rules_check(cred, subj, &abac_system_label,
	    ABAC_OP_AUDIT, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}
