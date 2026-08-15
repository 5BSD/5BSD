/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * ABAC Kernel Environment Checks
 *
 * Controls access to kernel environment variables (kenv).
 * These are boot-time and runtime kernel parameters.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/ucred.h>

#include <security/mac/mac_policy.h>

#include "mac_abac.h"

/*
 * Synthetic label for kenv objects
 */
static struct abac_label abac_kenv_object = {
	.vl_hash = 0,  /* Computed at runtime if needed */
	.vl_npairs = 1,
	.vl_pairs = {
		{ .vp_key = "type", .vp_value = "kenv" }
	}
};

/*
 * abac_kenv_check_dump - Check if subject can dump all kenv variables
 *
 * Controls kenv(2) with KENV_DUMP.
 */
int
abac_kenv_check_dump(struct ucred *cred)
{
	struct abac_label *subj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);

	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	error = abac_rules_check(cred, subj, &abac_kenv_object,
	    ABAC_OP_READ, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * abac_kenv_check_get - Check if subject can get a kenv variable
 *
 * Controls kenv(2) with KENV_GET.
 */
int
abac_kenv_check_get(struct ucred *cred, char *name)
{
	struct abac_label *subj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);

	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	error = abac_rules_check(cred, subj, &abac_kenv_object,
	    ABAC_OP_READ, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * abac_kenv_check_set - Check if subject can set a kenv variable
 *
 * Controls kenv(2) with KENV_SET.
 */
int
abac_kenv_check_set(struct ucred *cred, char *name, char *value)
{
	struct abac_label *subj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);

	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	error = abac_rules_check(cred, subj, &abac_kenv_object,
	    ABAC_OP_WRITE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * abac_kenv_check_unset - Check if subject can unset a kenv variable
 *
 * Controls kenv(2) with KENV_UNSET.
 */
int
abac_kenv_check_unset(struct ucred *cred, char *name)
{
	struct abac_label *subj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);

	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	error = abac_rules_check(cred, subj, &abac_kenv_object,
	    ABAC_OP_WRITE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}
