/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 *
 * ABAC Credential Label Management
 *
 * Handles credential (process) label lifecycle and checks.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/sbuf.h>
#include <sys/syslog.h>
#include <sys/ucred.h>
#include <sys/vnode.h>
#include <sys/imgact.h>

#include <bsm/audit.h>

#include <security/mac/mac_policy.h>

#include "mac_abac.h"
#include "abac_dtrace.h"

/*
 * Credential label lifecycle
 */

/*
 * A credential nobody labelled has no label (NULL: type=unlabeled).  A
 * copy shares its source's label, which is never modified while shared;
 * a relabel points the new credential at the requested label.
 */
void
abac_cred_init_label(struct label *label)
{

	SLOT_SET(label, NULL);
}

void
abac_cred_destroy_label(struct label *label)
{

	abac_label_free(SLOT(label));
	SLOT_SET(label, NULL);
}

void
abac_cred_copy_label(struct label *src, struct label *dest)
{

	if (src == NULL || dest == NULL)
		return;
	abac_label_share(dest, abac_slot, SLOT(src));
}

/*
 * newlabel is the label internalized from the request; with no mac_abac
 * element it has no label, which (as the default label it used to be
 * initialized with) makes the credential unlabelled.
 */
void
abac_cred_relabel(struct ucred *cred, struct label *newlabel)
{

	/*
	 * Credentials created before this policy was loaded have no MAC label.
	 * SLOT() dereferences its struct label argument, so guard the whole label
	 * pointer rather than only checking the per-policy slot afterwards.
	 */
	if (cred == NULL || cred->cr_label == NULL || newlabel == NULL)
		return;
	abac_label_share(cred->cr_label, abac_slot, SLOT(newlabel));
}

int
abac_cred_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed)
{
	struct abac_label *vl;
	char buf[ABAC_MAX_LABEL_LEN];
	const char *p;
	int len;

	if (strcmp(element_name, "mac_abac") != 0)
		return (0);

	(*claimed)++;

	/*
	 * mac_cred_externalize_label() may pass a NULL credential label for a
	 * credential that predates this policy's load.  Treat it as having no
	 * mac_abac element rather than passing NULL to SLOT() and faulting.
	 */
	if (label == NULL)
		return (0);

	vl = SLOT(label);
	if (vl == NULL)
		vl = &abac_default_subject;
	if (vl->vl_npairs == 0)
		return (0);

	/* Reconstruct label string */
	len = abac_label_to_string(vl, buf, sizeof(buf));
	if (len <= 0)
		return (0);

	/*
	 * Output the label in comma-separated format for user display.
	 * Convert newlines to commas.
	 */
	for (p = buf; *p != '\0'; p++) {
		if (*p == '\n') {
			if (*(p + 1) != '\0')
				sbuf_putc(sb, ',');
		} else {
			sbuf_putc(sb, *p);
		}
	}

	return (0);
}

int
abac_cred_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed)
{
	struct abac_label *vl;
	char *converted, *p;
	size_t len;
	int error;

	if (strcmp(element_name, "mac_abac") != 0)
		return (0);

	(*claimed)++;

	/* A label holding the request, private until a relabel shares it. */
	vl = SLOT(label);
	if (vl == NULL) {
		vl = abac_label_alloc(M_WAITOK);
		if (vl == NULL)
			return (ENOMEM);
		SLOT_SET(label, vl);
	}

	/*
	 * Convert from comma-separated format (user input) to
	 * newline-separated format (internal storage).
	 */
	len = strlen(element_data);
	if (len >= ABAC_MAX_LABEL_LEN)
		return (EINVAL);

	converted = malloc(len + 2, M_TEMP, M_WAITOK);

	for (p = converted; *element_data != '\0'; element_data++) {
		if (*element_data == ',')
			*p++ = '\n';
		else
			*p++ = *element_data;
	}
	if (p > converted && *(p - 1) != '\n')
		*p++ = '\n';
	*p = '\0';

	error = abac_label_parse(converted, strlen(converted), vl);
	free(converted, M_TEMP);

	return (error);
}

/*
 * Credential checks
 */

int
abac_cred_check_relabel(struct ucred *cred, struct label *newlabel)
{
	struct abac_label *cur, *newvl;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || newlabel == NULL)
		return (0);

	cur = (cred->cr_label != NULL) ? SLOT(cred->cr_label) : NULL;
	newvl = SLOT(newlabel);
	/* No mac_abac element: the request is the default label. */
	if (newvl == NULL)
		newvl = &abac_default_subject;

	return (abac_label_check_relabel(cred, cur, newvl, "cred"));
}

/*
 * No credential-change hook (setuid and the rest, setcred, the audit
 * credential calls): mac_abac allows them all, and a hook that allows in
 * every case only makes the framework walk.  Add one with the rules that
 * need it.
 */

/*
 * Central label-integrity gate for every path on which a subject chooses a
 * label.  A real change requires PRIV_MAC_PARTITION and the caller's current
 * label must dominate the requested label.  This invariant is deliberately
 * independent of permissive mode.
 */
int
abac_label_check_relabel(struct ucred *cred, const struct abac_label *cur,
    const struct abac_label *newlabel, const char *what)
{
	int error;

	/* An unlabelled subject has the default label. */
	if (cur == NULL)
		cur = &abac_default_subject;
	/* Preserve compatibility with calls that leave our label unchanged. */
	if (abac_label_equal(cur, newlabel))
		return (0);

	if (cred == NULL)
		return (EPERM);

	error = priv_check_cred(cred, PRIV_MAC_PARTITION);
	if (error != 0) {
		if (abac_log_level >= ABAC_LOG_DENY)
			log(LOG_WARNING,
			    "abac: %s relabel denied (unprivileged) pid %d uid %d\n",
			    what, curproc != NULL ? curproc->p_pid : 0,
			    (int)cred->cr_uid);
		return (EPERM);
	}

	if (!abac_label_dominates(cur, newlabel)) {
		if (abac_log_level >= ABAC_LOG_DENY)
			log(LOG_WARNING,
			    "abac: %s relabel denied (no-upgrade) pid %d uid %d\n",
			    what, curproc != NULL ? curproc->p_pid : 0,
			    (int)cred->cr_uid);
		return (EPERM);
	}

	return (0);
}
