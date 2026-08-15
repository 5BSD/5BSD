/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * ABAC POSIX Semaphore Label Management
 *
 * Handles POSIX semaphore label lifecycle and access checks.
 * Semaphore labels are inherited from the creating credential.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/ucred.h>
#include <sys/ksem.h>

#include <security/mac/mac_policy.h>

#include "mac_abac.h"

/*
 * POSIX semaphore label lifecycle
 */

void
abac_posixsem_init_label(struct label *label)
{
	struct abac_label *vl;

	vl = abac_label_alloc(M_WAITOK);
	SLOT_SET(label, vl);
}

void
abac_posixsem_destroy_label(struct label *label)
{
	struct abac_label *vl;

	vl = SLOT(label);
	if (vl != NULL)
		abac_label_free(vl);
	SLOT_SET(label, NULL);
}

/*
 * POSIX semaphore creation - inherit label from creating credential
 */
void
abac_posixsem_create(struct ucred *cred, struct ksem *ks,
    struct label *kslabel)
{
	struct abac_label *credlabel, *slabel;

	if (cred == NULL || cred->cr_label == NULL || kslabel == NULL)
		return;

	credlabel = SLOT(cred->cr_label);
	slabel = SLOT(kslabel);

	if (credlabel != NULL && slabel != NULL)
		abac_label_copy(credlabel, slabel);
}

/*
 * POSIX semaphore access checks
 */

int
abac_posixsem_check_getvalue(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (kslabel == NULL)
		return (0);
	obj = SLOT(kslabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(active_cred, subj, obj, ABAC_OP_READ, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_posixsem_check_open(struct ucred *cred, struct ksem *ks,
    struct label *kslabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (kslabel == NULL)
		return (0);
	obj = SLOT(kslabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_OPEN, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_posixsem_check_post(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (kslabel == NULL)
		return (0);
	obj = SLOT(kslabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* post = increment = write operation */
	error = abac_rules_check(active_cred, subj, obj, ABAC_OP_WRITE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_posixsem_check_setmode(struct ucred *cred, struct ksem *ks,
    struct label *kslabel, mode_t mode)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (kslabel == NULL)
		return (0);
	obj = SLOT(kslabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_WRITE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_posixsem_check_setowner(struct ucred *cred, struct ksem *ks,
    struct label *kslabel, uid_t uid, gid_t gid)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (kslabel == NULL)
		return (0);
	obj = SLOT(kslabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_WRITE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_posixsem_check_stat(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (kslabel == NULL)
		return (0);
	obj = SLOT(kslabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(active_cred, subj, obj, ABAC_OP_STAT, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_posixsem_check_unlink(struct ucred *cred, struct ksem *ks,
    struct label *kslabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (kslabel == NULL)
		return (0);
	obj = SLOT(kslabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_UNLINK, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_posixsem_check_wait(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (kslabel == NULL)
		return (0);
	obj = SLOT(kslabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* wait = decrement = read operation (blocking read) */
	error = abac_rules_check(active_cred, subj, obj, ABAC_OP_READ, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}
