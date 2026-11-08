/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue resolution, the kernel-core shim (D125): the per-pwddesc
 * attachment record and its inheritance (D123, D147), the atomic ATTACH
 * commit (D138, D148), the lookup intents and their content-keyed slots
 * (D126), and the choke point namei_setup calls (D127).  Compiled always;
 * nothing here does anything until dev/dq registers its vector, and no
 * attachment can exist before that.
 *
 * Lock order added: FILEDESC_SLOCK -> PROC_LOCK -> PWDDESC_XLOCK (ATTACH,
 * pd_replace, do_fork's late inheritance).  fdrop of dr_cwd/dr_root and the
 * binding release always happen after unlocking.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/refcount.h>
#include <sys/dqres.h>
#include <sys/socket.h>
#include <sys/sx.h>
#include <sys/un.h>
#include <sys/vnode.h>

#include <dev/dq/dq.h>

static MALLOC_DEFINE(M_DQRES, "dqres", "DescriptorQueue attachments");

const struct dqres_ops *dqres_ops;

void
dqres_register(const struct dqres_ops *ops)
{

	KASSERT(dqres_ops == NULL, ("dqres: second registration"));
	atomic_store_rel_ptr((volatile uintptr_t *)&dqres_ops, (uintptr_t)ops);
}

bool
dqres_proc_attached(struct proc *p)
{
	struct pwddesc *pdp;

	pdp = atomic_load_ptr(&p->p_pd);
	return (pdp != NULL && atomic_load_ptr(&pdp->pd_dqres) != NULL);
}

/*
 * Records.
 */

struct dqres *
dqres_alloc(int mflags)
{

	return (malloc(sizeof(struct dqres), M_DQRES, mflags | M_ZERO));
}

void
dqres_free_unused(struct dqres *dr)
{

	free(dr, M_DQRES);
}

bool
dqres_same_binding(const struct dqres *a, const struct dqres *b)
{

	return ((a == NULL ? NULL : a->dr_binding) ==
	    (b == NULL ? NULL : b->dr_binding));
}

/*
 * Copy oldpdp's record into newpdp (D123), with oldpdp exclusively locked
 * and newpdp not yet published.  The record comes from *preallocp, which
 * the caller allocated before taking the lock and must be non-NULL when
 * oldpdp is attached.  An fhold overflow marks the start dead (EIO later).
 */
void
dqres_pd_inherit_locked(struct pwddesc *newpdp, struct pwddesc *oldpdp,
    struct dqres **preallocp)
{
	struct dqres *odr, *ndr;

	PWDDESC_ASSERT_XLOCKED(oldpdp);
	odr = oldpdp->pd_dqres;
	if (odr == NULL)
		return;
	ndr = *preallocp;
	KASSERT(ndr != NULL, ("dqres: inheritance without a record"));
	*preallocp = NULL;
	dqres_ops->dro_hold(odr->dr_binding);
	ndr->dr_binding = odr->dr_binding;
	ndr->dr_flags = odr->dr_flags;
	if (odr->dr_cwd != NULL) {
		if (fhold(odr->dr_cwd))
			ndr->dr_cwd = odr->dr_cwd;
		else
			ndr->dr_flags |= DR_CWD_DEAD;
	}
	if (odr->dr_root != NULL) {
		if (fhold(odr->dr_root))
			ndr->dr_root = odr->dr_root;
		else
			ndr->dr_flags |= DR_ROOT_DEAD;
	}
	newpdp->pd_dqres = ndr;
}

/*
 * The last reference to a record's pwddesc is gone (pddrop) or the record
 * was replaced: release it with no lock held.  fdrop with a NULL thread
 * attributes a CLOSE to the kernel, not to whoever dropped the last
 * reference.
 */
void
dqres_pd_release(struct dqres *dr)
{

	if (dr == NULL)
		return;
	if (dr->dr_cwd != NULL)
		fdrop(dr->dr_cwd, NULL);
	if (dr->dr_root != NULL)
		fdrop(dr->dr_root, NULL);
	if (dr->dr_binding != NULL)
		dqres_ops->dro_rele(dr->dr_binding);
	free(dr, M_DQRES);
}

/*
 * do_fork (D147): the child's pwddesc was chosen before fdcopy, which can
 * sleep; an ATTACH may have committed in between.  Before the child can
 * run, under PROC_LOCK(p1) -> PWDDESC_XLOCK(p1->p_pd) (ATTACH's own
 * section), give the child the parent's binding if it differs.  The
 * record is allocated with both mutexes dropped, then the test is
 * repeated (0c: no M_WAITOK under the mutexes).
 */
void
dqres_fork_late(struct proc *p1, struct pwddesc *child)
{
	struct pwddesc *pdp;
	struct dqres *prealloc, *stale;

	if (dqres_ops == NULL)
		return;
	prealloc = NULL;
	stale = NULL;
	for (;;) {
		PROC_LOCK(p1);
		pdp = p1->p_pd;
		if (pdp == child) {
			/* pdshare: the record is shared with the pwddesc. */
			PROC_UNLOCK(p1);
			break;
		}
		PWDDESC_XLOCK(pdp);
		if (dqres_same_binding(pdp->pd_dqres, child->pd_dqres)) {
			PWDDESC_XUNLOCK(pdp);
			PROC_UNLOCK(p1);
			break;
		}
		if (pdp->pd_dqres != NULL && prealloc == NULL) {
			PWDDESC_XUNLOCK(pdp);
			PROC_UNLOCK(p1);
			prealloc = dqres_alloc(M_WAITOK);
			continue;
		}
		stale = child->pd_dqres;
		child->pd_dqres = NULL;
		dqres_pd_inherit_locked(child, pdp, &prealloc);
		PWDDESC_XUNLOCK(pdp);
		PROC_UNLOCK(p1);
		break;
	}
	dqres_pd_release(stale);
	if (prealloc != NULL)
		dqres_free_unused(prealloc);
}

/*
 * ATTACH (D138, D148).  p is held by the caller.  The table is held under
 * a brief PROC_LOCK (0c), then FILEDESC_SLOCK -> PROC_LOCK ->
 * PWDDESC_XLOCK, every precondition re-checked inside, the table scanned
 * for the queue's own file, and the record installed together with
 * P2_NO_NEW_PRIVS (D150), all in one section.
 */
int
dqres_attach(struct thread *td, struct proc *p, struct dqres_binding *b,
    struct file *qfp)
{
	struct filedesc *fdp;
	struct fdescenttbl *fdt;
	struct pwddesc *pdp;
	struct dqres *dr;
	int error, i;

	if (dqres_ops == NULL)
		return (ENXIO);
	if (p == td->td_proc)
		return (EBUSY);
	PROC_LOCK(p);
	if ((p->p_flag & P_WEXIT) != 0) {
		PROC_UNLOCK(p);
		return (ESRCH);
	}
	fdp = fdhold(p);
	PROC_UNLOCK(p);
	if (fdp == NULL)
		return (ESRCH);
	dr = dqres_alloc(M_WAITOK);

	FILEDESC_SLOCK(fdp);
	PROC_LOCK(p);
	pdp = p->p_pd;
	if (pdp == NULL || p->p_fd != fdp) {
		error = pdp == NULL ? ESRCH : EBUSY;
		PROC_UNLOCK(p);
		goto out;
	}
	/* Under PROC_LOCK, before the pwddesc mutex (review, low). */
	error = p_candebug(td, p);
	if (error != 0) {
		PROC_UNLOCK(p);
		goto out;
	}
	PWDDESC_XLOCK(pdp);
	if ((p->p_flag & P_WEXIT) != 0) {
		error = ESRCH;
		goto unlock;
	}
	/*
	 * P_EXEC: exec'd since fork (D137; set at the commit point under
	 * PROC_LOCK and not inherited by fork).  A shared pwddesc or table
	 * (pdrfork without RFFDG, Linux CLONE_FS, CLONE_FILES) could carry
	 * the attachment to a process nobody attached (D124, B3).
	 */
	if ((p->p_flag & (P_EXEC | P_INEXEC)) != 0 || pdp->pd_procs != 1 ||
	    refcount_load(&fdp->fd_refcnt) != 1 || pdp->pd_dqres != NULL) {
		error = EBUSY;
		goto unlock;
	}
	fdt = fdp->fd_files;
	for (i = 0; i < fdt->fdt_nfiles; i++) {
		if (fdt->fdt_ofiles[i].fde_file == qfp) {
			error = EBUSY;
			goto unlock;
		}
	}
	dqres_ops->dro_hold(b);
	dr->dr_binding = b;
	pdp->pd_dqres = dr;
	dr = NULL;
	p->p_flag2 |= P2_NO_NEW_PRIVS;
unlock:
	PWDDESC_XUNLOCK(pdp);
	PROC_UNLOCK(p);
out:
	FILEDESC_SUNLOCK(fdp);
	fddrop(fdp);
	if (dr != NULL)
		dqres_free_unused(dr);
	return (error);
}

/*
 * I5 (D137): a credential change an attached process may not make
 * (setcred, __mac_set_proc, CAP_AUTH_INSTALL).  PROC_LOCK held: ATTACH
 * installs the record under it.
 */
bool
dqres_cred_change_refused(struct proc *p)
{

	PROC_LOCK_ASSERT(p, MA_OWNED);
	return (p->p_pd != NULL && p->p_pd->pd_dqres != NULL);
}

int
dqres_kpath_refused(struct thread *td)
{

	if (dqres_ops == NULL || (td->td_pflags2 & TDP2_DQ_NORESOLVE) != 0 ||
	    !dqres_proc_attached(td->td_proc))
		return (0);
	return (EPERM);
}

/*
 * Intents (D126).
 */

void
dq_intent_enter(struct thread *td, struct dq_intent *di, uint32_t op,
    uint32_t flags)
{

	/* Slot 1's ERELOOKUP must never reach syscallret (B1). */
	KASSERT((flags & DQI_PATH2) == 0 || (flags & DQI_NO_ERESTART) != 0,
	    ("dq: DQI_PATH2 intent without DQI_NO_ERESTART"));
	bzero(di, sizeof(*di));
	di->di_op = op;
	di->di_flags = flags;
	di->di_syscall = td->td_sa.code;
	di->di_prev = td->td_dqintent;
	td->td_dqintent = di;
}

void
dq_intent_slot(struct dq_intent *di, int slot, const char *path,
    enum uio_seg seg, int dirfd)
{
	struct dq_islot *s;

	KASSERT(slot >= 0 && slot < DQ_INTENT_SLOTS, ("dq: slot %d", slot));
	s = &di->di_slot[slot];
	s->ds_path = path;
	s->ds_seg = seg;
	s->ds_dirfd = dirfd;
	s->ds_state = DQS_DECLARED;
	/* Only slot 1 of a DQI_PATH2 intent rides on slot 0's event. */
	s->ds_flags = (slot == 1 && (di->di_flags & DQI_PATH2) != 0) ?
	    DQS_F_PATH2 : 0;
}

/*
 * A kernel copy of a path the kernel looks up later through a buffer of
 * its own (AF_UNIX names, kldload's file, mount options): the slot matches
 * that lookup by content (the bytes and the directory descriptor), not by
 * pointer.  It must be consulted ahead with dqres_consult_slot; kpath need
 * only live until then.
 */
void
dq_intent_slot_content(struct dq_intent *di, int slot, const char *kpath,
    int dirfd)
{

	dq_intent_slot(di, slot, kpath, UIO_SYSSPACE, dirfd);
	di->di_slot[slot].ds_flags |= DQS_F_CONTENT;
}

static void
dq_islot_forget(struct dq_islot *s)
{

	if (s->ds_start_vp != NULL) {
		vrele(s->ds_start_vp);
		s->ds_start_vp = NULL;
	}
	if (s->ds_rdir_vp != NULL) {
		vrele(s->ds_rdir_vp);
		s->ds_rdir_vp = NULL;
	}
	if (s->ds_bytes != NULL) {
		free(s->ds_bytes, M_TEMP);
		s->ds_bytes = NULL;
	}
	s->ds_len = 0;
	s->ds_start_kind = 0;
	s->ds_rflags = 0;
	if (s->ds_state != DQS_UNUSED)
		s->ds_state = DQS_DECLARED;
	s->ds_flags &= ~DQS_F_AHEAD;
}

void
dq_intent_leave(struct thread *td, struct dq_intent *di)
{
	int i;

	KASSERT(td->td_dqintent == di, ("dq: intent %p left out of order",
	    di));
	for (i = 0; i < DQ_INTENT_SLOTS; i++)
		dq_islot_forget(&di->di_slot[i]);
	td->td_dqintent = di->di_prev;
}

static int
dq_islot_find(struct dq_intent *di, struct nameidata *ndp)
{
	struct dq_islot *s;
	int i;

	for (i = 0; i < DQ_INTENT_SLOTS; i++) {
		s = &di->di_slot[i];
		if (s->ds_state == DQS_UNUSED ||
		    s->ds_seg != ndp->ni_segflg || s->ds_dirfd != ndp->ni_dirfd)
			continue;
		if ((s->ds_flags & DQS_F_CONTENT) == 0) {
			if (s->ds_path == ndp->ni_dirp)
				return (i);
		} else if (s->ds_bytes != NULL &&
		    strcmp(s->ds_bytes, ndp->ni_cnd.cn_pnbuf) == 0)
			return (i);
	}
	return (-1);
}

/* D127: 1 user-origin, 2 kernel consumer, 3 kernel-origin. */
static uint32_t
dq_islot_class(struct dq_intent *di, struct dq_islot *s)
{

	if ((di->di_flags & DQI_KERNEL) != 0)
		return (3);
	if ((di->di_flags & DQI_USER) != 0 &&
	    (s->ds_flags & DQS_F_KCONSUMER) == 0)
		return (1);
	return (2);
}

static uint32_t
dq_class_rflags(uint32_t class)
{

	return (class == 1 ? DQ_RF_USER : class == 2 ? DQ_RF_KCONSUMER : 0);
}

static uint32_t
dq_rflags(struct nameidata *ndp, uint32_t class)
{
	struct componentname *cnp;
	uint32_t rf;

	cnp = &ndp->ni_cnd;
	rf = dq_class_rflags(class);
	if ((ndp->ni_lcf & NI_LCF_STRICTREL) != 0)
		rf |= DQ_RF_STRICTREL;
	if ((cnp->cn_flags & RBENEATH) != 0)
		rf |= DQ_RF_BENEATH;
	if ((cnp->cn_flags & RINROOT) != 0)
		rf |= DQ_RF_RINROOT;
	if ((cnp->cn_flags & FOLLOW) == 0)
		rf |= DQ_RF_NOFOLLOW;
	if ((cnp->cn_flags & EMPTYPATH) != 0)
		rf |= DQ_RF_EMPTYPATH;
	if ((cnp->cn_flags & NOSYMLINKS) != 0)
		rf |= DQ_RF_NOSYMLINKS;
	if ((cnp->cn_flags & NOMAGICLINKS) != 0)
		rf |= DQ_RF_NOMAGICLINKS;
	if ((cnp->cn_flags & NOXDEV) != 0)
		rf |= DQ_RF_NOXDEV;
	if ((cnp->cn_flags & TRAILINGSLASH) != 0)
		rf |= DQ_RF_TRAILINGSLASH;
	return (rf);
}

/*
 * A start hint: vn_fullpath can look ".." up (vop_stdvptocnp), a kernel
 * lookup of the consultation itself, exempt.  The path is relative to the
 * process's root.
 */
static int
dq_fullpath(struct vnode *vp, char **retbuf, char **freebuf)
{
	int error, save;

	DQRES_NORESOLVE_ENTER(save);
	error = vn_fullpath(vp, retbuf, freebuf);
	DQRES_NORESOLVE_LEAVE(save);
	return (error);
}

/*
 * Consult a declared slot before its own namei (slot 1 of a DQI_PATH2
 * intent, or dqres_consult_slot): copy the declared path, derive the
 * slot's own start kind from its leading '/' and its dirfd, and hold the
 * start it names now: the cwd or the dirfd's vnode, or for an absolute
 * path both roots namei may start at (the ABI root it tries first and the
 * process root of its restart).  The first namei checks it starts there.
 * *hintp is the start hint (best effort, *freep to free; none for an
 * absolute path).
 */
static int
dq_islot_fetch(struct thread *td, struct dq_islot *s, char **hintp,
    char **freep)
{
	struct pwd *pwd;
	struct vnode *vp;
	char *buf;
	size_t len;
	int error;

	*hintp = *freep = NULL;
	buf = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
	if (s->ds_seg == UIO_SYSSPACE)
		error = copystr(s->ds_path, buf, MAXPATHLEN, &len);
	else
		error = copyinstr(s->ds_path, buf, MAXPATHLEN, &len);
	if (error != 0) {
		free(buf, M_TEMP);
		return (error);
	}
	s->ds_bytes = buf;
	s->ds_len = len - 1;
	if ((s->ds_flags & DQS_F_CONTENT) != 0)
		s->ds_path = NULL;	/* the caller's copy may go now */
	vp = NULL;
	if (buf[0] == '/') {
		s->ds_start_kind = DQ_START_REAL_ROOT;
		pwd = pwd_hold(td);
		vref(pwd->pwd_adir);
		s->ds_start_vp = pwd->pwd_adir;
		vref(pwd->pwd_rdir);
		s->ds_rdir_vp = pwd->pwd_rdir;
		pwd_drop(pwd);
		return (0);
	} else if (s->ds_dirfd == AT_FDCWD) {
		s->ds_start_kind = DQ_START_REAL_CWD;
		pwd = pwd_hold(td);
		vp = pwd->pwd_cdir;
		vref(vp);
		pwd_drop(pwd);
	} else {
		s->ds_start_kind = DQ_START_REAL_DIRFD;
		/* A bad dirfd fails the namei itself; no hint then. */
		if (fgetvp(td, s->ds_dirfd, &cap_no_rights, &vp) != 0)
			vp = NULL;
	}
	s->ds_start_vp = vp;
	if (vp != NULL && dq_fullpath(vp, hintp, freep) != 0)
		*hintp = *freep = NULL;
	return (0);
}

/*
 * Does a carried slot's namei start where the controller was told?  An
 * absolute path starts at the ABI root, or at the process root when namei
 * restarted there (ISRESTARTED).
 */
static bool
dq_islot_start_same(struct dq_islot *s, struct nameidata *ndp,
    struct vnode *dp)
{

	if (s->ds_start_vp == dp)
		return (true);
	return (s->ds_start_kind == DQ_START_REAL_ROOT &&
	    (ndp->ni_cnd.cn_flags & ISRESTARTED) != 0 && s->ds_rdir_vp == dp);
}

/*
 * A carried slot (DQS_CARRIED or bound) whose namei differs from what
 * the controller saw.  It never waits here: slot 1 of a DQI_PATH2 intent
 * drops both slots and answers ERELOOKUP (kern_renameat and kern_linkat
 * loop, consulting both again; dq_intent_enter asserted they are
 * DQI_NO_ERESTART, so this never reaches syscallret); a slot consulted
 * ahead answers EIO.
 */
static int
dq_islot_mismatch(struct dq_intent *di, struct dq_islot *s)
{

	if ((s->ds_flags & DQS_F_PATH2) != 0) {
		MPASS((di->di_flags & (DQI_PATH2 | DQI_NO_ERESTART)) ==
		    (DQI_PATH2 | DQI_NO_ERESTART));
		dq_islot_forget(&di->di_slot[0]);
		dq_islot_forget(s);
		return (ERELOOKUP);
	}
	dq_islot_forget(s);
	return (EIO);
}

/*
 * The choke point, from namei_setup with the start computed (dp, the root
 * vnode actually used for an absolute path, 0c item 3), references held
 * and no lock taken (D149).  0 continues the lookup unchanged; an errno
 * ends it (namei_setup releases what it took).
 */
int
dqres_namei(struct nameidata *ndp, struct vnode *dp, bool abs)
{
	struct componentname *cnp;
	struct thread *td;
	struct pwddesc *pdp;
	struct dqres *dr;
	struct dq_intent *di;
	struct dq_islot *s, *s1;
	struct dqres_req rq;
	char *fullpath, *freepath, *hint2, *freehint2;
	size_t len;
	uint32_t rflags, start_kind;
	int error, slot;
	bool carried, same;

	td = curthread;
	if (dqres_ops == NULL)
		return (0);
	pdp = td->td_proc->p_pd;
	dr = atomic_load_ptr(&pdp->pd_dqres);
	if (dr == NULL)
		return (0);
	cnp = &ndp->ni_cnd;
	di = td->td_dqintent;
	slot = di != NULL ? dq_islot_find(di, ndp) : -1;
	s = slot >= 0 ? &di->di_slot[slot] : NULL;
	carried = s != NULL &&
	    (s->ds_flags & (DQS_F_PATH2 | DQS_F_AHEAD)) != 0 &&
	    (s->ds_state == DQS_CARRIED || s->ds_state == DQS_PASSED);
	/*
	 * An exempt region skips every lookup except one a carried slot
	 * names: that was consulted before the region and is checked here
	 * (never consulted again).
	 */
	if ((td->td_pflags2 & TDP2_DQ_NORESOLVE) != 0 && !carried)
		return (0);

	bzero(&rq, sizeof(rq));
	if (s != NULL) {
		rq.rq_class = dq_islot_class(di, s);
		rq.rq_op = di->di_op;
		rq.rq_mode = di->di_mode;
		rq.rq_object = di->di_drs_object;
		rq.rq_syscall = di->di_syscall;
		rq.rq_expected_locks = di->di_expected_locks;
		rq.rq_no_erestart = (di->di_flags & DQI_NO_ERESTART) != 0;
	} else {
		/*
		 * Unmarked: a ledger failure (M2), counted.  A user-space
		 * path is consulted anyway as INTERNAL (fail closed by the
		 * controller).  A kernel-space one outside an exempt region
		 * is refused: an exempt site, a refusal or a mark covers
		 * every kernel-space lookup the ledger knows, and one a
		 * racing ATTACH exposes mid-syscall fails closed.
		 */
		dqres_ops->dro_unmarked(dr->dr_binding);
		if (ndp->ni_segflg != UIO_USERSPACE)
			return (EPERM);
		rq.rq_class = 2;
		rq.rq_op = DQ_ROP_INTERNAL;
		rq.rq_syscall = td->td_sa.code;
	}
	if (abs)
		start_kind = DQ_START_REAL_ROOT;
	else if (ndp->ni_dirfd == AT_FDCWD && ndp->ni_startdir == NULL)
		start_kind = DQ_START_REAL_CWD;
	else
		start_kind = DQ_START_REAL_DIRFD;
	rflags = dq_rflags(ndp, rq.rq_class);
	len = strlen(cnp->cn_pnbuf);

	if (carried && s->ds_state == DQS_CARRIED) {
		/*
		 * Consulted before this namei: the first namei binds the
		 * slot when it resolves the bytes the controller saw from
		 * the start it was told, and records its lookup flags.
		 */
		if (s->ds_start_kind == start_kind && s->ds_len == len &&
		    memcmp(s->ds_bytes, cnp->cn_pnbuf, len) == 0 &&
		    dq_islot_start_same(s, ndp, dp)) {
			s->ds_rflags = rflags;
			s->ds_state = DQS_PASSED;
			return (0);
		}
		return (dq_islot_mismatch(di, s));
	}
	if (s != NULL && s->ds_state == DQS_PASSED) {
		/*
		 * A restart: identical content reuses the PASS.  A carried
		 * slot's lookup flags were never posted, so only its bytes
		 * and start are compared (a snapshot's CREATE and DELETE
		 * of the same consulted name, the linker's two classes).
		 */
		same = s->ds_start_kind == start_kind &&
		    (carried || s->ds_rflags == rflags) && s->ds_len == len &&
		    memcmp(s->ds_bytes, cnp->cn_pnbuf, len) == 0 &&
		    (carried ? dq_islot_start_same(s, ndp, dp) :
		    s->ds_start_vp == dp);
		if (same)
			return (0);
		if (carried)
			return (dq_islot_mismatch(di, s));
	}

	rq.rq_rflags = rflags;
	rq.rq_start_kind = start_kind;
	rq.rq_path = cnp->cn_pnbuf;
	rq.rq_pathlen = len;
	/* ERESTART only from a slot's first consultation (D149). */
	rq.rq_may_restart = s != NULL && s->ds_state == DQS_DECLARED &&
	    (di->di_flags & DQI_NO_ERESTART) == 0;
	s1 = NULL;
	hint2 = freehint2 = NULL;
	if (slot == 0 && (di->di_slot[1].ds_flags & DQS_F_PATH2) != 0) {
		/*
		 * RENAME, LINK: one event, both paths (§1-i.2).  Slot 1 is
		 * carried afresh with every consultation of slot 0, with
		 * its own start kind and hint.
		 */
		s1 = &di->di_slot[1];
		dq_islot_forget(s1);
		error = dq_islot_fetch(td, s1, &hint2, &freehint2);
		if (error != 0) {
			dq_islot_forget(s1);
			return (error);
		}
		rq.rq_path2 = s1->ds_bytes;
		rq.rq_path2len = s1->ds_len;
		rq.rq_start2_kind = s1->ds_start_kind;
		if (hint2 != NULL) {
			rq.rq_startpath2 = hint2;
			rq.rq_startpath2len = strlen(hint2);
			rq.rq_rflags |= DQ_RF_STARTPATH2_VALID;
		}
	}
	/* The start hint (D131): best effort, relative to the process root. */
	freepath = NULL;
	if (start_kind != DQ_START_REAL_ROOT && dp != NULL &&
	    dq_fullpath(dp, &fullpath, &freepath) == 0) {
		rq.rq_startpath = fullpath;
		rq.rq_startpathlen = strlen(fullpath);
		rq.rq_rflags |= DQ_RF_STARTPATH_VALID;
	}
	error = dqres_ops->dro_consult(td, dr->dr_binding, &rq);
	free(freepath, M_TEMP);
	free(freehint2, M_TEMP);
	if (error != 0) {
		if (s1 != NULL)
			dq_islot_forget(s1);
		return (error);
	}
	if (s != NULL) {
		dq_islot_forget(s);
		s->ds_bytes = malloc(len + 1, M_TEMP, M_WAITOK);
		memcpy(s->ds_bytes, cnp->cn_pnbuf, len + 1);
		s->ds_len = len;
		s->ds_start_kind = start_kind;
		s->ds_rflags = rflags;
		if (dp != NULL) {
			vref(dp);
			s->ds_start_vp = dp;
		}
		s->ds_state = DQS_PASSED;
		if (s1 != NULL)
			s1->ds_state = DQS_CARRIED;
	}
	return (0);
}

/*
 * Consult a declared slot ahead of its lookup (DQS_F_AHEAD): for a lookup
 * the syscall makes under a lock, with a mount busied or inside an exempt
 * region (swapon and swapoff under swdev_syscall_lock, the quotaon file,
 * kldload's file, mount options, AF_UNIX names), called before that state
 * is entered.  The path is copied, consulted with its own start kind and
 * hint, and the slot is CARRIED until its namei binds it; that namei never
 * waits (EIO on any difference, including a different start vnode).  0
 * when nothing is to be consulted.
 */
int
dqres_consult_slot(struct thread *td, int slot)
{
	struct pwddesc *pdp;
	struct dqres *dr;
	struct dq_intent *di;
	struct dq_islot *s;
	struct dqres_req rq;
	char *hint, *freehint;
	int error;

	KASSERT(slot >= 0 && slot < DQ_INTENT_SLOTS, ("dq: slot %d", slot));
	di = td->td_dqintent;
	if (dqres_ops == NULL || di == NULL ||
	    (td->td_pflags2 & TDP2_DQ_NORESOLVE) != 0)
		return (0);
	s = &di->di_slot[slot];
	if (s->ds_state != DQS_DECLARED || (s->ds_flags & DQS_F_PATH2) != 0)
		return (0);
	pdp = td->td_proc->p_pd;
	dr = atomic_load_ptr(&pdp->pd_dqres);
	if (dr == NULL)
		return (0);
	error = dq_islot_fetch(td, s, &hint, &freehint);
	if (error != 0) {
		dq_islot_forget(s);
		return (error);
	}
	bzero(&rq, sizeof(rq));
	rq.rq_class = dq_islot_class(di, s);
	rq.rq_rflags = dq_class_rflags(rq.rq_class);
	rq.rq_op = di->di_op;
	rq.rq_mode = di->di_mode;
	rq.rq_object = di->di_drs_object;
	rq.rq_syscall = di->di_syscall;
	rq.rq_expected_locks = di->di_expected_locks;
	rq.rq_no_erestart = (di->di_flags & DQI_NO_ERESTART) != 0;
	rq.rq_may_restart = !rq.rq_no_erestart;
	rq.rq_start_kind = s->ds_start_kind;
	rq.rq_path = s->ds_bytes;
	rq.rq_pathlen = s->ds_len;
	if (hint != NULL) {
		rq.rq_startpath = hint;
		rq.rq_startpathlen = strlen(hint);
		rq.rq_rflags |= DQ_RF_STARTPATH_VALID;
	}
	error = dqres_ops->dro_consult(td, dr->dr_binding, &rq);
	free(freehint, M_TEMP);
	if (error != 0) {
		dq_islot_forget(s);
		return (error);
	}
	s->ds_flags |= DQS_F_AHEAD;
	s->ds_state = DQS_CARRIED;
	return (0);
}

/*
 * An AF_UNIX name (BIND, CONNECT): the user's own name although the kernel
 * copied the address first, so it is class 1, consulted at the syscall's
 * entry (kern_bindat, kern_connectat, kern_sendit with an address) with no
 * lock held.  A path name is consulted ahead in a content slot of di, which
 * the caller keeps published (*enteredp) until the protocol's own lookup
 * of the same bytes from the same dirfd has run; that lookup is checked
 * against the consulted start and never waits (the datagram send runs it
 * under SOCK_IO_SEND_LOCK).  An abstract (Linux) name, first byte NUL, is
 * looked up nowhere: it is posted with DQ_RF_ABSTRACT, start NONE and the
 * name's bytes after the NUL (they may hold more NULs; the length is
 * exact).
 */
int
dqres_consult_sun(struct thread *td, struct dq_intent *di, uint32_t op,
    int dirfd, const struct sockaddr *sa, bool *enteredp)
{
	const struct sockaddr_un *sun;
	struct pwddesc *pdp;
	struct dqres *dr;
	struct dqres_req rq;
	char *buf;
	ssize_t len;
	int error;

	*enteredp = false;
	if (sa == NULL || sa->sa_family != AF_LOCAL || dqres_ops == NULL ||
	    (td->td_pflags2 & TDP2_DQ_NORESOLVE) != 0)
		return (0);
	pdp = td->td_proc->p_pd;
	dr = atomic_load_ptr(&pdp->pd_dqres);
	if (dr == NULL)
		return (0);
	sun = (const struct sockaddr_un *)sa;
	len = (ssize_t)sa->sa_len - (ssize_t)offsetof(struct sockaddr_un,
	    sun_path);
	if (len <= 0)
		return (0);		/* unnamed: nothing is looked up */
	if (len > (ssize_t)sizeof(sun->sun_path))
		len = sizeof(sun->sun_path);
	buf = malloc(len + 1, M_TEMP, M_WAITOK);
	memcpy(buf, sun->sun_path, len);
	buf[len] = '\0';
	if (buf[0] != '\0') {
		dq_intent_enter(td, di, op, DQI_USER);
		dq_intent_slot_content(di, 0, buf, dirfd);
		error = dqres_consult_slot(td, 0);
		free(buf, M_TEMP);
		if (error != 0)
			dq_intent_leave(td, di);
		else
			*enteredp = true;
		return (error);
	}
	bzero(&rq, sizeof(rq));
	rq.rq_class = 1;
	rq.rq_op = op;
	rq.rq_syscall = td->td_sa.code;
	rq.rq_may_restart = true;	/* nothing done yet: a restart is clean */
	rq.rq_rflags = DQ_RF_USER | DQ_RF_ABSTRACT;
	rq.rq_start_kind = DQ_START_NONE;
	rq.rq_path = buf + 1;
	rq.rq_pathlen = len - 1;
	error = dqres_ops->dro_consult(td, dr->dr_binding, &rq);
	free(buf, M_TEMP);
	return (error);
}

/*
 * socket(2), socketpair(2) (D139): the requester's own request, class 1,
 * consulted after socreate_find and before the jail's address-family test
 * and any descriptor slot, so a refusal leaves nothing behind and a
 * restart is clean.  A dead controller is EACCES here (D136, dev/dq).
 */
int
dqres_consult_socket(struct thread *td, uint32_t op, int domain, int type,
    int protocol)
{
	struct pwddesc *pdp;
	struct dqres *dr;
	struct dqres_req rq;

	KASSERT(op == DQ_ROP_SOCKET || op == DQ_ROP_SOCKETPAIR,
	    ("dq: socket op %u", op));
	if (dqres_ops == NULL || (td->td_pflags2 & TDP2_DQ_NORESOLVE) != 0)
		return (0);
	pdp = td->td_proc->p_pd;
	dr = atomic_load_ptr(&pdp->pd_dqres);
	if (dr == NULL)
		return (0);
	bzero(&rq, sizeof(rq));
	rq.rq_class = 1;
	rq.rq_op = op;
	rq.rq_syscall = td->td_sa.code;
	rq.rq_may_restart = true;	/* nothing done yet: a restart is clean */
	rq.rq_rflags = DQ_RF_USER;
	rq.rq_start_kind = DQ_START_NONE;
	rq.rq_path = "";
	rq.rq_domain = domain;
	rq.rq_type = type;
	rq.rq_protocol = protocol;
	return (dqres_ops->dro_consult(td, dr->dr_binding, &rq));
}
