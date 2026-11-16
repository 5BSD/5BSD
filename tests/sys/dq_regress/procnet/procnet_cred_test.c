/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Credential changes of unattached processes, as before stage 1c.
 *
 * Stage 1c refuses setcred(2), NODE_OP_SET_CRED and __mac_set_proc(2) with
 * EPERM for an ATTACHED process (I5, D137).  For any other process
 * setuid/setgid/setgroups/setresuid, setcred(2) and mac_set_proc(2) must
 * succeed and fail exactly as before, including the order of EINVAL/EFAULT
 * against EPERM.
 *
 * Expectations from 3f330ee172d: kern_prot.c sys_setcred(),
 * user_setcred(), user_setcred_copyin_supp_groups(), kern_setcred(),
 * sys_setgroups(), kern_setgroups(); mac_syscalls.c sys___mac_set_proc()
 * and mac_set_proc_prepare(); mac_internal.h (an unclaimed label element
 * is EINVAL).
 */

#include <sys/param.h>
#include <sys/mac.h>
#include <sys/syscall.h>
#include <sys/ucred.h>

#include "procnet_common.h"

/* --- setuid(2) family ------------------------------------------------ */

static int
setuid_unpriv(void *arg __unused)
{
	uid_t r, e, s;

	/* To oneself: allowed. */
	if (setuid(PN_UID) != 0)
		return (PN_X_WRONG);
	if (seteuid(PN_UID) != 0)
		return (PN_X_WRONG);
	if (getresuid(&r, &e, &s) != 0 || r != PN_UID || e != PN_UID ||
	    s != PN_UID)
		return (PN_X_WRONG);
	/* To anyone else: EPERM, credentials unchanged. */
	if (setuid(0) != -1 || errno != EPERM)
		return (errno == 0 ? PN_X_WRONG : errno);
	if (setuid(PN_UID + 1) != -1 || errno != EPERM)
		return (PN_X_WRONG);
	if (seteuid(0) != -1 || errno != EPERM)
		return (PN_X_WRONG);
	if (setreuid(-1, PN_UID + 1) != -1 || errno != EPERM)
		return (PN_X_WRONG);
	if (setresuid(-1, -1, 0) != -1 || errno != EPERM)
		return (PN_X_WRONG);
	if (setgid(0) != -1 || errno != EPERM)
		return (PN_X_WRONG);
	if (setegid(PN_GID + 1) != -1 || errno != EPERM)
		return (PN_X_WRONG);
	if (getresuid(&r, &e, &s) != 0 || r != PN_UID || e != PN_UID ||
	    s != PN_UID)
		return (PN_X_WRONG);
	return (0);
}

ATF_TC(setuid_family_unpriv);
ATF_TC_HEAD(setuid_family_unpriv, tc)
{
	atf_tc_set_md_var(tc, "descr", "an unprivileged process may set its "
	    "own ids and gets EPERM for any other, ids unchanged");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(setuid_family_unpriv, tc)
{

	PN_CHECK_ERRNO(0, pn_child(setuid_unpriv, NULL, PN_UID, PN_GID),
	    "unprivileged setuid family");
}

static int
setuid_root(void *arg __unused)
{
	uid_t r, e, s;
	gid_t rg, eg, sg;

	if (setresgid(PN_GID, PN_GID + 1, PN_GID + 2) != 0)
		return (errno);
	if (setresuid(PN_UID, PN_UID + 1, 0) != 0)
		return (errno);
	if (getresuid(&r, &e, &s) != 0 || r != PN_UID || e != PN_UID + 1 ||
	    s != 0)
		return (PN_X_WRONG);
	if (getresgid(&rg, &eg, &sg) != 0 || rg != PN_GID ||
	    eg != PN_GID + 1 || sg != PN_GID + 2)
		return (PN_X_WRONG);
	/* The saved uid 0 lets the effective uid go back to 0. */
	if (seteuid(0) != 0)
		return (errno);
	/* Then setuid(2) as root sets all three. */
	if (setuid(PN_UID + 5) != 0)
		return (errno);
	if (getresuid(&r, &e, &s) != 0 || r != PN_UID + 5 ||
	    e != PN_UID + 5 || s != PN_UID + 5)
		return (PN_X_WRONG);
	/* And it is gone for good. */
	if (seteuid(0) != -1 || errno != EPERM)
		return (PN_X_WRONG);
	return (0);
}

ATF_TC(setuid_family_root);
ATF_TC_HEAD(setuid_family_root, tc)
{
	atf_tc_set_md_var(tc, "descr", "root sets real, effective and saved "
	    "ids, comes back through a saved 0, and drops for good");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(setuid_family_root, tc)
{

	PN_CHECK_ERRNO(0, pn_child(setuid_root, NULL, 0, 0),
	    "root setuid family");
}

/* --- setgroups(2) ---------------------------------------------------- */

static int
setgroups_root(void *arg __unused)
{
	gid_t g[4] = { 7, 5, 6, 5 }, out[NGROUPS_MAX + 1];
	int n, i, have5, have6, have7;

	if (setgroups(4, g) != 0)
		return (errno);
	n = getgroups(nitems(out), out);
	if (n < 0)
		return (errno);
	have5 = have6 = have7 = 0;
	for (i = 0; i < n; i++) {
		have5 += out[i] == 5;
		have6 += out[i] == 6;
		have7 += out[i] == 7;
	}
	if (!have5 || !have6 || !have7)
		return (PN_X_WRONG);
	/* Too many, negative: EINVAL. */
	if (setgroups(1 << 20, g) != -1 || errno != EINVAL)
		return (PN_X_WRONG);
	if (setgroups(-1, g) != -1 || errno != EINVAL)
		return (PN_X_WRONG);
	/* A bad pointer with a sane count: EFAULT. */
	if (setgroups(2, (gid_t *)(uintptr_t)8) != -1 || errno != EFAULT)
		return (PN_X_WRONG);
	/* Empty is allowed. */
	if (setgroups(0, g) != 0)
		return (errno);
	return (0);
}

ATF_TC(setgroups_root);
ATF_TC_HEAD(setgroups_root, tc)
{
	atf_tc_set_md_var(tc, "descr", "root setgroups(2) works; too many "
	    "or negative is EINVAL, a bad pointer EFAULT, none allowed");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(setgroups_root, tc)
{

	PN_CHECK_ERRNO(0, pn_child(setgroups_root, NULL, 0, 0),
	    "root setgroups");
}

static int
setgroups_unpriv(void *arg __unused)
{
	gid_t g[1] = { PN_GID };

	/* The size check comes first: EINVAL, not EPERM. */
	if (setgroups(1 << 20, g) != -1 || errno != EINVAL)
		return (PN_X_WRONG);
	/* The copyin second: EFAULT, not EPERM. */
	if (setgroups(2, (gid_t *)(uintptr_t)8) != -1 || errno != EFAULT)
		return (PN_X_WRONG);
	/* Even the current set: EPERM. */
	if (setgroups(1, g) != -1 || errno != EPERM)
		return (PN_X_WRONG);
	return (0);
}

ATF_TC(setgroups_unpriv);
ATF_TC_HEAD(setgroups_unpriv, tc)
{
	atf_tc_set_md_var(tc, "descr", "unprivileged setgroups(2): EINVAL "
	    "and EFAULT before EPERM; EPERM even for the current set");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(setgroups_unpriv, tc)
{

	PN_CHECK_ERRNO(0, pn_child(setgroups_unpriv, NULL, PN_UID, PN_GID),
	    "unprivileged setgroups");
}

/* --- setcred(2) ------------------------------------------------------ */

static int
pn_setcred(u_int flags, const struct setcred *wc, size_t size)
{

	return (PN_ERR(syscall(SYS_setcred, flags, wc, size)));
}

static int
setcred_root(void *arg __unused)
{
	struct setcred wc;
	gid_t groups[2] = { 9, 8 };
	uid_t r, e, s;
	gid_t rg, eg, sg, out[16];
	int e1, n;

	/* No flags: a no-op that succeeds. */
	memset(&wc, 0, sizeof(wc));
	if ((e1 = pn_setcred(0, &wc, sizeof(wc))) != 0)
		return (e1);
	/* Unknown flag: EINVAL. */
	if (pn_setcred(0x80000000u, &wc, sizeof(wc)) != EINVAL)
		return (PN_X_WRONG);
	/* Wrong size: EINVAL. */
	if (pn_setcred(SETCREDF_UID, &wc, sizeof(wc) - 1) != EINVAL)
		return (PN_X_WRONG);
	if (pn_setcred(SETCREDF_UID, &wc, sizeof(wc) + 8) != EINVAL)
		return (PN_X_WRONG);
	/* Bad pointer: EFAULT. */
	if (pn_setcred(SETCREDF_UID, (const struct setcred *)(uintptr_t)8,
	    sizeof(wc)) != EFAULT)
		return (PN_X_WRONG);
	/* Too many supplementary groups: EINVAL. */
	memset(&wc, 0, sizeof(wc));
	wc.sc_supp_groups_nb = 1 << 20;
	wc.sc_supp_groups = groups;
	if (pn_setcred(SETCREDF_SUPP_GROUPS, &wc, sizeof(wc)) != EINVAL)
		return (PN_X_WRONG);

	/* Everything at once. */
	memset(&wc, 0, sizeof(wc));
	wc.sc_uid = PN_UID + 1;
	wc.sc_ruid = PN_UID;
	wc.sc_svuid = PN_UID + 2;
	wc.sc_gid = PN_GID + 1;
	wc.sc_rgid = PN_GID;
	wc.sc_svgid = PN_GID + 2;
	wc.sc_supp_groups_nb = 2;
	wc.sc_supp_groups = groups;
	if ((e1 = pn_setcred(SETCREDF_UID | SETCREDF_RUID | SETCREDF_SVUID |
	    SETCREDF_GID | SETCREDF_RGID | SETCREDF_SVGID |
	    SETCREDF_SUPP_GROUPS, &wc, sizeof(wc))) != 0)
		return (e1);
	if (getresuid(&r, &e, &s) != 0 || r != PN_UID || e != PN_UID + 1 ||
	    s != PN_UID + 2)
		return (PN_X_WRONG);
	if (getresgid(&rg, &eg, &sg) != 0 || rg != PN_GID ||
	    eg != PN_GID + 1 || sg != PN_GID + 2)
		return (PN_X_WRONG);
	n = getgroups(nitems(out), out);
	if (n < 2)
		return (PN_X_WRONG);
	/* Now unprivileged: even a no-op is EPERM. */
	memset(&wc, 0, sizeof(wc));
	if (pn_setcred(0, &wc, sizeof(wc)) != EPERM)
		return (PN_X_WRONG);
	return (0);
}

ATF_TC(setcred_root);
ATF_TC_HEAD(setcred_root, tc)
{
	atf_tc_set_md_var(tc, "descr", "setcred(2) as root: argument errors "
	    "(flags, size, pointer, group count) and a full change, after "
	    "which the process is unprivileged and gets EPERM");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(setcred_root, tc)
{

	PN_CHECK_ERRNO(0, pn_child(setcred_root, NULL, 0, 0), "root setcred");
}

static int
setcred_unpriv(void *arg __unused)
{
	struct setcred wc;
	gid_t groups[1] = { PN_GID };
	int e1;

	memset(&wc, 0, sizeof(wc));
	/* Argument errors come before the privilege check. */
	if ((e1 = pn_setcred(0x80000000u, &wc, sizeof(wc))) != EINVAL)
		return (e1 == 0 ? PN_X_WRONG : e1);
	if (pn_setcred(0, &wc, sizeof(wc) - 1) != EINVAL)
		return (PN_X_WRONG);
	if (pn_setcred(0, (const struct setcred *)(uintptr_t)8,
	    sizeof(wc)) != EFAULT)
		return (PN_X_WRONG);
	wc.sc_supp_groups_nb = 1 << 20;
	wc.sc_supp_groups = groups;
	if (pn_setcred(SETCREDF_SUPP_GROUPS, &wc, sizeof(wc)) != EINVAL)
		return (PN_X_WRONG);
	wc.sc_supp_groups_nb = 1;
	wc.sc_supp_groups = (gid_t *)(uintptr_t)8;
	if (pn_setcred(SETCREDF_SUPP_GROUPS, &wc, sizeof(wc)) != EFAULT)
		return (PN_X_WRONG);
	/* Then EPERM: a no-op, its own uid, root. */
	memset(&wc, 0, sizeof(wc));
	if (pn_setcred(0, &wc, sizeof(wc)) != EPERM)
		return (PN_X_WRONG);
	wc.sc_uid = PN_UID;
	if (pn_setcred(SETCREDF_UID, &wc, sizeof(wc)) != EPERM)
		return (PN_X_WRONG);
	wc.sc_uid = 0;
	if (pn_setcred(SETCREDF_UID, &wc, sizeof(wc)) != EPERM)
		return (PN_X_WRONG);
	if (geteuid() != PN_UID)
		return (PN_X_WRONG);
	return (0);
}

ATF_TC(setcred_unpriv);
ATF_TC_HEAD(setcred_unpriv, tc)
{
	atf_tc_set_md_var(tc, "descr", "unprivileged setcred(2): EINVAL and "
	    "EFAULT before EPERM; EPERM even for a no-op");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(setcred_unpriv, tc)
{

	PN_CHECK_ERRNO(0, pn_child(setcred_unpriv, NULL, PN_UID, PN_GID),
	    "unprivileged setcred");
}

/* --- MAC labels ------------------------------------------------------ */

static int
mac_unknown(void *arg __unused)
{
	struct mac m;
	char text[] = "procnet_no_such_policy/x";
	mac_t label;
	int e1;

	/* An element no policy claims: EINVAL. */
	if (mac_from_text(&label, text) != 0)
		return (PN_X_SETUP);
	e1 = PN_ERR(mac_set_proc(label));
	mac_free(label);
	if (e1 != EINVAL)
		return (e1 == 0 ? PN_X_WRONG : e1);
	/* A bad struct mac pointer: EFAULT. */
	if (PN_ERR(syscall(SYS___mac_set_proc, (void *)(uintptr_t)8)) !=
	    EFAULT)
		return (PN_X_WRONG);
	/* A zero-length buffer: EINVAL (mac_check_structmac_consistent). */
	m.m_buflen = 0;
	m.m_string = text;
	if (PN_ERR(syscall(SYS___mac_set_proc, &m)) != EINVAL)
		return (PN_X_WRONG);
	/* setcred(2) with the label goes the same way, before EPERM. */
	return (0);
}

static int
setcred_label(void *arg __unused)
{
	struct setcred wc;
	struct mac m;
	char text[] = "procnet_no_such_policy/x";

	memset(&wc, 0, sizeof(wc));
	m.m_buflen = sizeof(text);
	m.m_string = text;
	wc.sc_label = &m;
	if (pn_setcred(SETCREDF_MAC_LABEL, &wc, sizeof(wc)) != EINVAL)
		return (PN_X_WRONG);
	wc.sc_label = (void *)(uintptr_t)8;
	if (pn_setcred(SETCREDF_MAC_LABEL, &wc, sizeof(wc)) != EFAULT)
		return (PN_X_WRONG);
	return (0);
}

ATF_TC(mac_set_proc_errors);
ATF_TC_HEAD(mac_set_proc_errors, tc)
{
	atf_tc_set_md_var(tc, "descr", "mac_set_proc(2) and setcred(2) with "
	    "SETCREDF_MAC_LABEL: an unclaimed element is EINVAL, a bad "
	    "pointer EFAULT, for root and unprivileged alike (before EPERM)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mac_set_proc_errors, tc)
{
	mac_t label;

	if (mac_prepare_process_label(&label) != 0 && errno == ENOSYS)
		atf_tc_skip("no MAC framework");
	PN_CHECK_ERRNO(0, pn_child(mac_unknown, NULL, 0, 0),
	    "root mac_set_proc");
	PN_CHECK_ERRNO(0, pn_child(mac_unknown, NULL, PN_UID, PN_GID),
	    "unprivileged mac_set_proc");
	PN_CHECK_ERRNO(0, pn_child(setcred_label, NULL, 0, 0),
	    "root setcred label");
	PN_CHECK_ERRNO(0, pn_child(setcred_label, NULL, PN_UID, PN_GID),
	    "unprivileged setcred label");
}

static int
mac_roundtrip(void *arg __unused)
{
	mac_t label;
	char *text;
	int e1;

	/*
	 * Setting the label the process already has is allowed by every
	 * policy that labels credentials (and EINVAL when none does).
	 */
	if (mac_prepare_process_label(&label) != 0)
		return (PN_X_SETUP);
	if (mac_get_proc(label) != 0) {
		e1 = errno;
		mac_free(label);
		return (e1 == EINVAL ? 0 : e1);
	}
	if (mac_to_text(label, &text) != 0)
		return (PN_X_SETUP);
	e1 = PN_ERR(mac_set_proc(label));
	if (e1 == EINVAL && text[0] == '\0')
		e1 = 0;
	free(text);
	mac_free(label);
	return (e1);
}

ATF_TC(mac_set_proc_same_label);
ATF_TC_HEAD(mac_set_proc_same_label, tc)
{
	atf_tc_set_md_var(tc, "descr", "mac_set_proc(2) of the process's own "
	    "label succeeds as before (no EPERM for an unattached process)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mac_set_proc_same_label, tc)
{
	mac_t label;

	if (mac_prepare_process_label(&label) != 0)
		atf_tc_skip("mac_prepare_process_label: %s", strerror(errno));
	mac_free(label);
	/*
	 * To be confirmed: with policies loaded that label processes, the
	 * policy decides; the expectation is only that the outcome does not
	 * differ between the kernels, and both allow a no-change relabel.
	 */
	PN_CHECK_ERRNO(0, pn_child(mac_roundtrip, NULL, 0, 0),
	    "root relabel to the same label");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, setuid_family_unpriv);
	ATF_TP_ADD_TC(tp, setuid_family_root);
	ATF_TP_ADD_TC(tp, setgroups_root);
	ATF_TP_ADD_TC(tp, setgroups_unpriv);
	ATF_TP_ADD_TC(tp, setcred_root);
	ATF_TP_ADD_TC(tp, setcred_unpriv);
	ATF_TP_ADD_TC(tp, mac_set_proc_errors);
	ATF_TP_ADD_TC(tp, mac_set_proc_same_label);
	return (atf_no_error());
}
