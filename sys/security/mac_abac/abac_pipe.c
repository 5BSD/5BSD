/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * ABAC Pipe Label Management
 *
 * Handles pipe label lifecycle and access checks.
 * Pipe labels are inherited from the creating credential.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/selinfo.h>
#include <sys/pipe.h>
#include <sys/ucred.h>

#include <security/mac/mac_policy.h>

#include "mac_abac.h"

/*
 * Pipe label lifecycle
 */

void
abac_pipe_init_label(struct label *label)
{
	struct abac_label *vl;

	vl = abac_label_alloc(M_WAITOK);
	SLOT_SET(label, vl);
}

void
abac_pipe_destroy_label(struct label *label)
{
	struct abac_label *vl;

	vl = SLOT(label);
	if (vl != NULL)
		abac_label_free(vl);
	SLOT_SET(label, NULL);
}

void
abac_pipe_copy_label(struct label *src, struct label *dest)
{
	struct abac_label *srcvl, *dstvl;

	if (src == NULL || dest == NULL)
		return;

	srcvl = SLOT(src);
	dstvl = SLOT(dest);

	if (srcvl != NULL && dstvl != NULL)
		abac_label_copy(srcvl, dstvl);
}

/*
 * Pipe creation - inherit label from creating credential
 */
void
abac_pipe_create(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	struct abac_label *credlabel, *plabel;

	if (cred == NULL || cred->cr_label == NULL || pplabel == NULL)
		return;

	credlabel = SLOT(cred->cr_label);
	plabel = SLOT(pplabel);

	if (credlabel != NULL && plabel != NULL)
		abac_label_copy(credlabel, plabel);
}

/*
 * Pipe access checks
 *
 * For pipe operations, the subject is the process credential and
 * the object is the pipe label. This allows rules like:
 *   deny read type=untrusted -> type=secret
 *   deny write type=sandbox -> *
 */

int
abac_pipe_check_ioctl(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel, unsigned long cmd, void *data)
{

	/* ioctl on pipes is always allowed - typically FIONREAD etc. */
	ABAC_CHECK_ENABLED();
	return (0);
}

int
abac_pipe_check_poll(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{

	/* poll is always allowed - no security impact */
	ABAC_CHECK_ENABLED();
	return (0);
}

int
abac_pipe_check_read(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object label from pipe */
	if (pplabel == NULL)
		return (0);
	obj = SLOT(pplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Evaluate rules */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_READ, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_pipe_check_relabel(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel, struct label *newlabel)
{

	/* Pipe relabeling not supported in ABAC */
	ABAC_CHECK_ENABLED();
	return (EACCES);
}

int
abac_pipe_check_stat(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object label from pipe */
	if (pplabel == NULL)
		return (0);
	obj = SLOT(pplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Evaluate rules */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_STAT, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_pipe_check_write(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object label from pipe */
	if (pplabel == NULL)
		return (0);
	obj = SLOT(pplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Evaluate rules */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_WRITE, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}
