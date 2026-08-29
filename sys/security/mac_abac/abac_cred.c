/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
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

void
abac_cred_init_label(struct label *label)
{
	struct abac_label *vl;

	vl = abac_label_alloc(M_WAITOK);
	if (vl != NULL) {
		abac_label_set_default(vl, true);  /* true = subject label */
		/* DTrace: default subject label assigned */
		SDT_PROBE1(abac, label, extattr, default, 1);
	}
	SLOT_SET(label, vl);
}

void
abac_cred_destroy_label(struct label *label)
{
	struct abac_label *vl;

	vl = SLOT(label);
	if (vl != NULL)
		abac_label_free(vl);
	SLOT_SET(label, NULL);
}

void
abac_cred_copy_label(struct label *src, struct label *dest)
{
	struct abac_label *srcvl, *dstvl;

	if (src == NULL || dest == NULL)
		return;

	srcvl = SLOT(src);
	dstvl = SLOT(dest);

	if (srcvl != NULL && dstvl != NULL)
		abac_label_copy(srcvl, dstvl);
}

void
abac_cred_relabel(struct ucred *cred, struct label *newlabel)
{
	struct abac_label *vl, *newvl;

	/*
	 * Credentials created before this policy was loaded have no MAC label.
	 * SLOT() dereferences its struct label argument, so guard the whole label
	 * pointer rather than only checking the per-policy slot afterwards.
	 */
	if (cred == NULL || cred->cr_label == NULL || newlabel == NULL)
		return;

	vl = SLOT(cred->cr_label);
	newvl = SLOT(newlabel);

	if (vl != NULL && newvl != NULL)
		abac_label_copy(newvl, vl);
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
	if (vl == NULL || vl->vl_npairs == 0)
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

	vl = SLOT(label);
	if (vl == NULL)
		return (ENOMEM);

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
	if (newvl == NULL)
		return (0);

	return (abac_label_check_relabel(cred, cur, newvl, "cred"));
}

int
abac_cred_check_setuid(struct ucred *cred, uid_t uid)
{

	ABAC_CHECK_ENABLED();
	return (0);
}

int
abac_cred_check_setgid(struct ucred *cred, gid_t gid)
{

	ABAC_CHECK_ENABLED();
	return (0);
}

int
abac_cred_check_setgroups(struct ucred *cred, int ngroups, gid_t *gidset)
{

	ABAC_CHECK_ENABLED();
	return (0);
}

/*
 * Extended credential check hooks
 *
 * These provide fine-grained control over credential changes.
 * For now they're stubs that always allow, but they can be extended
 * to support rules like:
 *   deny setcred type=untrusted -> *
 */

int
abac_cred_check_seteuid(struct ucred *cred, uid_t euid)
{

	ABAC_CHECK_ENABLED();
	return (0);
}

int
abac_cred_check_setegid(struct ucred *cred, gid_t egid)
{

	ABAC_CHECK_ENABLED();
	return (0);
}

int
abac_cred_check_setreuid(struct ucred *cred, uid_t ruid, uid_t euid)
{

	ABAC_CHECK_ENABLED();
	return (0);
}

int
abac_cred_check_setregid(struct ucred *cred, gid_t rgid, gid_t egid)
{

	ABAC_CHECK_ENABLED();
	return (0);
}

int
abac_cred_check_setresuid(struct ucred *cred, uid_t ruid, uid_t euid,
    uid_t suid)
{

	ABAC_CHECK_ENABLED();
	return (0);
}

int
abac_cred_check_setresgid(struct ucred *cred, gid_t rgid, gid_t egid,
    gid_t sgid)
{

	ABAC_CHECK_ENABLED();
	return (0);
}

/*
 * abac_cred_check_setcred - Check new-style credential change
 *
 * This is the newer API for credential changes, used by setcred().
 * The 'flags' parameter indicates which credential fields are being changed.
 */
int
abac_cred_check_setcred(u_int flags, const struct ucred *old_cred,
    struct ucred *new_cred)
{

	ABAC_CHECK_ENABLED();
	return (0);
}

/*
 * BSM Audit credential checks
 *
 * Control who can modify audit session information.
 */
int
abac_cred_check_setaudit(struct ucred *cred, struct auditinfo *ai)
{

	ABAC_CHECK_ENABLED();
	return (0);
}

int
abac_cred_check_setaudit_addr(struct ucred *cred, struct auditinfo_addr *aia)
{

	ABAC_CHECK_ENABLED();
	return (0);
}

int
abac_cred_check_setauid(struct ucred *cred, uid_t auid)
{

	ABAC_CHECK_ENABLED();
	return (0);
}

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
