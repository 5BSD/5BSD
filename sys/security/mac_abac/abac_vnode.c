/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * ABAC Vnode Label Management
 *
 * Handles vnode label lifecycle, extattr integration, and access checks.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/sbuf.h>
#include <sys/ucred.h>
#include <sys/vnode.h>
#include <sys/extattr.h>
#include <sys/imgact.h>
#include <sys/acl.h>

#include <machine/atomic.h>

#include <security/mac/mac_policy.h>

#include "mac_abac.h"
#include "abac_dtrace.h"

/*
 * Statistics - defined in mac_abac.c, updated here
 */
extern uint64_t abac_labels_read;
extern uint64_t abac_labels_default;

/*
 * Configurable extended attribute name - defined in mac_abac.c
 */
extern char abac_extattr_name[64];

/*
 * Vnode label lifecycle
 */

void
abac_vnode_init_label(struct label *label)
{

	/*
	 * Don't allocate here - labels are allocated on-demand when
	 * extattr is read. This saves ~5KB per vnode for unlabeled files.
	 * Most vnodes have no label, so this is a significant memory savings.
	 */
	SLOT_SET(label, NULL);
}

void
abac_vnode_destroy_label(struct label *label)
{
	struct abac_label *vl;

	vl = SLOT(label);
	/* Don't free sentinel marker or NULL */
	if (vl != NULL && vl != ABAC_LABEL_NEEDS_LOAD)
		abac_label_free(vl);
	SLOT_SET(label, NULL);
}

void
abac_vnode_copy_label(struct label *src, struct label *dest)
{
	struct abac_label *srcvl, *dstvl;

	/* NULL check label pointers before accessing slots */
	if (src == NULL || dest == NULL)
		return;

	srcvl = SLOT(src);
	dstvl = SLOT(dest);

	/*
	 * Handle sentinel markers and NULL:
	 * - If src is NULL or sentinel, dest should be the same (no alloc needed)
	 * - If src has a real label, we need to copy it
	 */
	if (srcvl == NULL || srcvl == ABAC_LABEL_NEEDS_LOAD) {
		/* Free any existing dest label before overwriting */
		if (dstvl != NULL && dstvl != ABAC_LABEL_NEEDS_LOAD)
			abac_label_free(dstvl);
		SLOT_SET(dest, srcvl);
		return;
	}

	/* Source has a real label - allocate dest if needed */
	if (dstvl == NULL || dstvl == ABAC_LABEL_NEEDS_LOAD) {
		dstvl = abac_label_alloc(M_WAITOK);
		if (dstvl == NULL)
			return;
		SLOT_SET(dest, dstvl);
	}

	abac_label_copy(srcvl, dstvl);
}

/*
 * Helper function to read label from extended attribute.
 * Used by both associate_extattr (UFS multilabel) and lazy_load (ZFS).
 *
 * This function allocates a label structure ONLY if the extattr exists
 * and contains a valid label. If no extattr exists, the slot is set to
 * NULL (meaning "use default"). This saves ~5KB per unlabeled vnode.
 */
static void
abac_vnode_read_extattr(struct vnode *vp, struct label *vplabel)
{
	struct abac_label *old, *vl;
	char *buf;
	int buflen, error;

	/* Free any existing label to prevent leaks on refresh/re-read */
	old = SLOT(vplabel);
	if (old != NULL && old != ABAC_LABEL_NEEDS_LOAD) {
		SLOT_SET(vplabel, NULL);
		abac_label_free(old);
	}

	/*
	 * Allocate buffer on heap - ABAC_MAX_LABEL_LEN (4KB) is allocated
	 * on the heap for consistency with other label operations and to
	 * reduce kernel stack pressure.
	 *
	 * M_WAITOK guarantees success (kernel will sleep until memory
	 * is available, or panic if impossible).
	 */
	buf = malloc(ABAC_MAX_LABEL_LEN, M_TEMP, M_WAITOK | M_ZERO);

	/*
	 * Read the label from the system:mac_abac extended attribute.
	 */
	buflen = ABAC_MAX_LABEL_LEN - 1;

	error = vn_extattr_get(vp, IO_NODELOCKED, ABAC_EXTATTR_NAMESPACE,
	    abac_extattr_name, &buflen, buf, curthread);

	if (error == ENOATTR || error == EOPNOTSUPP) {
		/*
		 * No label on this vnode - leave slot as NULL.
		 * Check paths will use abac_default_object.
		 */
		free(buf, M_TEMP);
		SLOT_SET(vplabel, NULL);
		/* DTrace: default label assigned */
		SDT_PROBE1(abac, label, extattr, default, 0);
		atomic_add_64(&abac_labels_default, 1);
		return;
	} else if (error != 0) {
		/*
		 * Error reading extattr - leave slot as NULL (use default).
		 */
		free(buf, M_TEMP);
		SLOT_SET(vplabel, NULL);
		return;
	}

	/*
	 * Extattr exists - allocate label structure and parse.
	 * This is the only path that allocates memory.
	 */
	vl = abac_label_alloc(M_WAITOK);
	if (vl == NULL) {
		/* Allocation failed - use default */
		free(buf, M_TEMP);
		SLOT_SET(vplabel, NULL);
		return;
	}

	buf[buflen] = '\0';
	error = abac_label_parse(buf, buflen, vl);
	if (error != 0) {
		/* Parse failed - free label, use default */
		free(buf, M_TEMP);
		abac_label_free(vl);
		SLOT_SET(vplabel, NULL);
		return;
	}

	free(buf, M_TEMP);

	/* Success - store allocated label in slot */
	SLOT_SET(vplabel, vl);

	/* DTrace: label read from extattr (pass hash for efficiency) */
	SDT_PROBE2(abac, label, extattr, read, vl->vl_hash, vp);
	atomic_add_64(&abac_labels_read, 1);
}

/*
 * Refresh vnode label by re-reading from extended attribute.
 * Called via ABAC_SYS_REFRESH syscall for live relabeling.
 */
void
abac_vnode_refresh_label(struct vnode *vp, struct label *vplabel)
{

	/* read_extattr handles freeing any existing label */
	abac_vnode_read_extattr(vp, vplabel);
}

/*
 * Associate vnode label from extended attribute (UFS with multilabel).
 */
int
abac_vnode_associate_extattr(struct mount *mp, struct label *mplabel,
    struct vnode *vp, struct label *vplabel)
{

	abac_vnode_read_extattr(vp, vplabel);
	return (0);
}

/*
 * Associate vnode label for single-label filesystems (ZFS, tmpfs, etc).
 *
 * This hook is called during vnode allocation (getnewvnode), before the
 * vnode is fully initialized. On ZFS, the vnode is not ready for VOP
 * operations at this point - attempting vn_extattr_get() will crash.
 *
 * Instead of reading the extattr here, we set the slot to a sentinel
 * marker (ABAC_LABEL_NEEDS_LOAD). The actual extattr read happens lazily
 * on first access check (see abac_vnode_lazy_load).
 *
 * This avoids allocating ~5KB per vnode - memory is only allocated if
 * the vnode actually has a label in its extattr.
 */
void
abac_vnode_associate_singlelabel(struct mount *mp, struct label *mplabel,
    struct vnode *vp, struct label *vplabel)
{

	/* Mark for lazy loading - don't allocate yet */
	SLOT_SET(vplabel, ABAC_LABEL_NEEDS_LOAD);
}

/*
 * Lazy load vnode label from extended attribute.
 *
 * Called during access checks when the slot contains ABAC_LABEL_NEEDS_LOAD.
 * At this point the vnode should be fully initialized and ready for VOP
 * operations.
 *
 * This function checks for the sentinel marker and, if present, attempts
 * to read the extattr. If extattr exists, a label is allocated and parsed.
 * If not, the slot is set to NULL (use default).
 *
 * Multiple threads may race here but that's harmless - worst case we do
 * redundant reads, and the last one wins (all should produce same result).
 */
void
abac_vnode_lazy_load(struct vnode *vp, struct label *vplabel)
{
	struct abac_label *vl;

	if (vp == NULL || vplabel == NULL)
		return;

	vl = SLOT(vplabel);

	/* Check if lazy load is needed (sentinel marker) */
	if (vl != ABAC_LABEL_NEEDS_LOAD)
		return;

	/*
	 * Slot has sentinel marker - try to read extattr.
	 * read_extattr will set slot to either a valid label pointer
	 * (if extattr exists) or NULL (if no extattr, use default).
	 */
	abac_vnode_read_extattr(vp, vplabel);
}

int
abac_vnode_create_extattr(struct ucred *cred, struct mount *mp,
    struct label *mplabel, struct vnode *dvp, struct label *dvplabel,
    struct vnode *vp, struct label *vplabel, struct componentname *cnp)
{

	/*
	 * Stub: New files get the default object label assigned in
	 * abac_vnode_init_label(). Setting extattr automatically on
	 * file creation is not implemented - use mac_abac_ctl label set.
	 */
	return (0);
}


/*
 * Vnode access checks
 *
 * NOTE: Currently only check_exec is fully implemented with rule evaluation.
 * All other vnode check hooks are stubs that always return 0 (allow).
 * This is intentional for the initial implementation - enforcement of
 * read/write/mmap/etc operations would require careful analysis of the
 * performance impact and proper rule configuration by administrators.
 *
 * To enable enforcement for additional operations:
 * 1. Copy the pattern from abac_vnode_check_exec()
 * 2. Use the appropriate ABAC_OP_* constant
 * 3. Test thoroughly with realistic workloads
 */

int
abac_vnode_check_access(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object label from vnode */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Evaluate rules */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_ACCESS, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_chdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(dvp, dvplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (dvplabel == NULL)
		return (0);
	obj = SLOT(dvplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_CHDIR, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_chroot(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(dvp, dvplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (dvplabel == NULL)
		return (0);
	obj = SLOT(dvplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Use CHDIR for chroot - both are directory access checks */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_CHDIR, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_create(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp, struct vattr *vap)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(dvp, dvplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Check against parent directory label */
	if (dvplabel == NULL)
		return (0);
	obj = SLOT(dvplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_CREATE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_deleteacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Use WRITE as proxy for ACL modification */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_WRITE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_deleteextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	/*
	 * Always protect our own label attribute from deletion.
	 * This prevents unauthorized removal of security labels.
	 */
	if (attrnamespace == ABAC_EXTATTR_NAMESPACE &&
	    name != NULL && strcmp(name, abac_extattr_name) == 0) {
		/* Get subject label from credential */
		if (cred == NULL || cred->cr_label == NULL)
			return (EPERM);
		subj = SLOT(cred->cr_label);
		if (subj == NULL)
			subj = &abac_default_subject;

		/* Get object label from vnode */
		if (vplabel == NULL)
			return (EPERM);
		obj = SLOT(vplabel);
		if (obj == NULL)
			obj = &abac_default_object;

		/* Check setextattr operation - deletion is a form of modification */
		error = abac_rules_check(cred, subj, obj, ABAC_OP_SETEXTATTR, NULL);

		/* In permissive mode, log but allow */
		if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
			return (0);

		return (error);
	}

	return (0);
}

int
abac_vnode_check_exec(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct image_params *imgp, struct label *execlabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL) {
		return (0);
	}
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object label from vnode */
	if (vplabel == NULL) {
		return (0);
	}
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Evaluate rules - no target process for vnode ops */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_EXEC, NULL);

	/* In permissive mode, don't enforce */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_getacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Use STAT as proxy for reading ACLs */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_STAT, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_getextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	/*
	 * Optionally protect reading of our label attribute.
	 * This can prevent information disclosure about security labels.
	 *
	 * Only check for our specific attribute - don't block other extattrs.
	 */
	if (attrnamespace == ABAC_EXTATTR_NAMESPACE &&
	    name != NULL && strcmp(name, abac_extattr_name) == 0) {
		/* Get subject label from credential */
		if (cred == NULL || cred->cr_label == NULL)
			return (0);  /* Allow if no cred - kernel internal */
		subj = SLOT(cred->cr_label);
		if (subj == NULL)
			subj = &abac_default_subject;

		/* Get object label from vnode */
		if (vplabel == NULL)
			return (0);
		obj = SLOT(vplabel);
		if (obj == NULL)
			obj = &abac_default_object;

		/* Check getextattr operation */
		error = abac_rules_check(cred, subj, obj, ABAC_OP_GETEXTATTR, NULL);

		/* In permissive mode, log but allow */
		if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
			return (0);

		return (error);
	}

	return (0);
}

int
abac_vnode_check_link(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Check against target file's label */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_LINK, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_listextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Use GETEXTATTR as proxy for listing extattrs */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_GETEXTATTR, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(dvp, dvplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (dvplabel == NULL)
		return (0);
	obj = SLOT(dvplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_LOOKUP, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_mmap(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot, int flags)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object label from vnode */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Evaluate rules */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_MMAP, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * abac_vnode_check_mprotect - Check mprotect() protection changes
 *
 * Called when a process attempts to change the protection of a memory
 * mapping that is backed by a vnode. This is useful for W^X enforcement:
 * preventing the same memory from being both writable and executable.
 *
 * The 'prot' parameter contains the new protection flags (PROT_READ,
 * PROT_WRITE, PROT_EXEC).
 *
 * Use cases:
 *   - Prevent untrusted processes from making memory executable
 *   - Enforce W^X policy on file-backed mappings
 */
int
abac_vnode_check_mprotect(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object label from vnode */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Evaluate rules */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_MPROTECT, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_open(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object label from vnode */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Evaluate rules */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_OPEN, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_poll(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Use READ as proxy for poll - checking readability */
	error = abac_rules_check(active_cred, subj, obj, ABAC_OP_READ, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_read(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	/* Get subject label from credential */
	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object label from vnode */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Evaluate rules */
	error = abac_rules_check(active_cred, subj, obj, ABAC_OP_READ, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_readdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(dvp, dvplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (dvplabel == NULL)
		return (0);
	obj = SLOT(dvplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_READDIR, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_readlink(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object label from vnode */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Evaluate rules - use READ since readlink is reading symlink target */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_READ, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Use SETEXTATTR as proxy for relabeling */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_SETEXTATTR, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_rename_from(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Check against source file's label */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_RENAME, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_rename_to(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    int samedir, struct componentname *cnp)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(dvp, dvplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Check against target directory's label */
	if (dvplabel == NULL)
		return (0);
	obj = SLOT(dvplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_RENAME, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_revoke(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Use WRITE as proxy for revoke - modifies file state */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_WRITE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_setacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type, struct acl *acl)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Use WRITE as proxy for ACL modification */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_WRITE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/*
	 * Always protect our own label attribute from modification.
	 * This prevents unauthorized changes to security labels.
	 *
	 * Note: mac_abac_ctl uses this path to set labels, so rules must
	 * allow setextattr for administrative processes. Example:
	 *   allow setextattr type=admin -> *
	 *   deny setextattr * -> *
	 *
	 * IMPORTANT: Do NOT call lazy_load here when setting our label.
	 * On ZFS, lazy_load triggers VOP_GETEXTATTR inside VOP_SETEXTATTR,
	 * causing a nested VOP that can fail with EPERM. Since we're about
	 * to overwrite the label anyway, we don't need the current value.
	 */
	if (attrnamespace == ABAC_EXTATTR_NAMESPACE &&
	    name != NULL && strcmp(name, abac_extattr_name) == 0) {
		/* Get subject label from credential */
		if (cred == NULL || cred->cr_label == NULL)
			return (EPERM);
		subj = SLOT(cred->cr_label);
		if (subj == NULL)
			subj = &abac_default_subject;

		/* Get object label from vnode */
		if (vplabel == NULL)
			return (EPERM);
		obj = SLOT(vplabel);
		if (obj == NULL || obj == ABAC_LABEL_NEEDS_LOAD)
			obj = &abac_default_object;

		/* Check setextattr operation */
		error = abac_rules_check(cred, subj, obj, ABAC_OP_SETEXTATTR, NULL);

		/* In permissive mode, log but allow */
		if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
			return (0);

		return (error);
	}

	return (0);
}

int
abac_vnode_check_setflags(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, u_long flags)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Use WRITE as proxy for setting file flags */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_WRITE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_setmode(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, mode_t mode)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Use WRITE as proxy for chmod */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_WRITE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_setowner(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, uid_t uid, gid_t gid)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Use WRITE as proxy for chown */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_WRITE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_setutimes(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct timespec atime, struct timespec mtime)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Use WRITE as proxy for utimes */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_WRITE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_stat(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(active_cred, subj, obj, ABAC_OP_STAT, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_unlink(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Check against target file's label */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_UNLINK, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_vnode_check_write(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	/* Lazy load label from extattr if needed (ZFS) */
	abac_vnode_lazy_load(vp, vplabel);

	/* Get subject label from credential */
	if (active_cred == NULL || active_cred->cr_label == NULL)
		return (0);
	subj = SLOT(active_cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object label from vnode */
	if (vplabel == NULL)
		return (0);
	obj = SLOT(vplabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Evaluate rules */
	error = abac_rules_check(active_cred, subj, obj, ABAC_OP_WRITE, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * Check mmap protection downgrade (W^X enforcement).
 *
 * This hook is called when mmap() protections might be downgraded
 * (e.g., from RWX to RX or RW). This is the companion to mprotect()
 * for W^X enforcement.
 *
 * Unlike check_mprotect which returns an error, this hook modifies
 * the protection bits directly by clearing disallowed combinations.
 *
 * For example, to enforce W^X on untrusted code:
 *   - If PROT_WRITE and PROT_EXEC are both set, clear PROT_EXEC
 *
 * Currently we don't modify protections - this is a stub for future
 * W^X policy implementation. To enable, rules would look like:
 *   deny mmap type=untrusted -> *   (with PROT_WRITE|PROT_EXEC check)
 */
void
abac_vnode_check_mmap_downgrade(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int *prot)
{
	/*
	 * Stub implementation - does not modify protections.
	 *
	 * A full W^X implementation would:
	 * 1. Get subject/object labels
	 * 2. Check if policy requires W^X for this combination
	 * 3. If (*prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)
	 *    then *prot &= ~PROT_EXEC;
	 */
	(void)cred;
	(void)vp;
	(void)vplabel;
	(void)prot;
}

/*
 * Set vnode label in extended attribute.
 *
 * This hook is called when a label needs to be written to persistent
 * storage (extended attribute). It's typically invoked after
 * vnode_check_relabel approves the label change.
 *
 * The intlabel parameter contains the new label to write.
 *
 * Returns 0 on success, error code on failure.
 */
int
abac_vnode_setlabel_extattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *intlabel)
{
	struct abac_label *newlabel;
	char *buf;
	int error, len;

	ABAC_CHECK_ENABLED();

	if (intlabel == NULL)
		return (EINVAL);

	newlabel = SLOT(intlabel);
	if (newlabel == NULL)
		return (EINVAL);

	/*
	 * Allocate buffer on heap for consistency with other label
	 * operations and to reduce kernel stack pressure.
	 */
	buf = malloc(ABAC_MAX_LABEL_LEN, M_TEMP, M_WAITOK);

	/* Serialize label to string format */
	len = abac_label_to_string(newlabel, buf, ABAC_MAX_LABEL_LEN);
	if (len < 0) {
		free(buf, M_TEMP);
		return (EINVAL);
	}

	/* Write to extended attribute */
	error = vn_extattr_set(vp, UIO_SYSSPACE, ABAC_EXTATTR_NAMESPACE,
	    abac_extattr_name, len, buf, curthread);

	free(buf, M_TEMP);

	if (error == 0 && vplabel != NULL) {
		/* Update in-memory label - allocate if needed */
		struct abac_label *vl = SLOT(vplabel);
		if (vl == NULL || vl == ABAC_LABEL_NEEDS_LOAD) {
			vl = abac_label_alloc(M_WAITOK);
			if (vl != NULL) {
				SLOT_SET(vplabel, vl);
				abac_label_copy(newlabel, vl);
			}
		} else {
			abac_label_copy(newlabel, vl);
		}
	}

	return (error);
}

/*
 * Mount label lifecycle
 */

void
abac_mount_init_label(struct label *label)
{

	SLOT_SET(label, NULL);
}

void
abac_mount_destroy_label(struct label *label)
{

	SLOT_SET(label, NULL);
}
