/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
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

/*
 * A pipe holds its creator's label (none for an unlabelled creator: NULL,
 * type=unlabeled).
 */
void
abac_pipe_init_label(struct label *label)
{

	SLOT_SET(label, NULL);
}

void
abac_pipe_destroy_label(struct label *label)
{

	abac_label_free(SLOT(label));
	SLOT_SET(label, NULL);
}

void
abac_pipe_copy_label(struct label *src, struct label *dest)
{

	if (src == NULL || dest == NULL)
		return;
	abac_label_share(dest, abac_slot, SLOT(src));
}

/*
 * Pipe creation - inherit label from creating credential
 */
void
abac_pipe_create(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	if (cred == NULL || cred->cr_label == NULL || pplabel == NULL)
		return;

	abac_label_share(pplabel, abac_slot, SLOT(cred->cr_label));
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
abac_pipe_check_read(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_LIVE(ABAC_OP_READ);
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

	ABAC_CHECK_LIVE(ABAC_OP_STAT);
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

	ABAC_CHECK_LIVE(ABAC_OP_WRITE);
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
