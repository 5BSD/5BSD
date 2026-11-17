/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue resolution: the kernel-core half of an attachment
 * (design 11, stage 1c).  An attached process has a pwddesc whose
 * pd_dqres points at a struct dqres; the binding it names is the queue's
 * and is owned by dev/dq through a vector of operations registered once.
 * Kernel-only.
 */

#ifndef _SYS_DQRES_H_
#define	_SYS_DQRES_H_

#ifdef _KERNEL

#include <sys/types.h>
#include <sys/_uio.h>
#include <sys/caprights.h>
#include <sys/sdt.h>

struct dqres_binding;
struct fdinstall_gate;
struct filedesc;
struct dq_ident_file;
struct dq_object;
struct dq_setattr_body;
struct file;
struct nameidata;
struct proc;
struct pwd;
struct pwddesc;
struct thread;
struct vnode;

/*
 * The per-pwddesc record (D123).  dr_binding is shared and refcounted
 * through the vector.  dr_cwd and dr_root are served directories (D169),
 * each holding one file reference of its own: set by a CHDIR or CHROOT
 * answered FD, fchdir/fchroot of a served directory and ATTACH's starts;
 * cleared by a real chdir or chroot in the pwd_* functions.  A pwddesc is
 * attached when pd_dqres != NULL.  Written under PWDDESC_XLOCK; read with
 * the pwd in one section (D177).
 */
struct dqres {
	struct dqres_binding	*dr_binding;
	struct file		*dr_cwd;
	struct file		*dr_root;
	u_int			 dr_flags;
#define	DR_CWD_DEAD		0x0001	/* fhold overflowed at inheritance */
#define	DR_ROOT_DEAD		0x0002
};

/*
 * A start snapshot (D177): an attached process's served cwd and root,
 * each held with fhold (or NULL), and DR_CWD_DEAD/DR_ROOT_DEAD for a
 * record that has none or whose file could not be held.  Taken with the
 * pwd by pwd_hold_dqres, or alone by pwd_dqres_proc; released with
 * dqres_snap_release, with no lock held.  All zero for an unattached
 * process.
 */
struct dqres_snap {
	struct file	*dsn_cwd;
	struct file	*dsn_root;
	u_int		 dsn_flags;	/* DR_CWD_DEAD, DR_ROOT_DEAD */
};

/*
 * A served answer (1c-iii): what the controller's FD, ATTR, LINK or OK
 * reply carried, held by the intent until the completion takes it.
 */
struct dqres_answer {
	uint32_t	 da_kind;	/* DQ_RESOLVE_*; 0 = none */
	uint32_t	 da_mflags;	/* FD: DQ_MINT_F_* */
	uint32_t	 da_okind;	/* FD: DQ_KIND_* */
	struct dq_object *da_obj;	/* FD: linked, the creation reference;
					   dro_bind or dro_answer_release */
	struct dq_ident_file *da_ident;	/* FD, ATTR, LINK: M_TEMP copy */
	char		*da_target;	/* LINK, REAL: M_TEMP, NUL-terminated */
	size_t		 da_targetlen;
	uint64_t	 da_qgid;	/* the queue (Linux served mount ids) */
	cap_rights_t	 da_rights;	/* FD: the policy's dp_rights */
	uint64_t	 da_objid;	/* FD: the object's id (audit) */
	struct fdswap	*da_swap;	/* SWAP: M_TEMP carrier of the real
					   file (sys/fdswap.h);
					   dqres_take_file takes the file
					   out, dqres_install puts it back
					   and installs; dro_answer_release
					   drops what is left */
	uint32_t	 da_swflags;	/* SWAP: DQ_SWAP_F_* of the reply */
	bool		 da_swcreated;	/* SWAP: DQ_SWAP_F_CREATED honoured
					   by the completion */
};

/*
 * The lookup intent (D126): declared on the stack of a user-origin entry
 * point (or of a kernel-consumer one, DQI_USER clear) and published in
 * td_dqintent for the syscall's duration.  A lookup belongs to slot i when
 * (ni_dirp, ni_segflg, ni_dirfd) match what the entry point declared;
 * each slot caches what was consulted (start, rflags, path bytes) and the
 * answer, so a restart with identical content reuses PASS and any change
 * consults again.
 *
 * A slot can be consulted before its own namei: slot 1 of a DQI_PATH2
 * intent (RENAME, LINK) is carried in slot 0's event, and a slot whose
 * lookup runs under a lock or a busied mount (swapon, swapoff, quotaon)
 * is consulted ahead by dqres_consult_slot().  Such a slot is CARRIED
 * until its first namei binds it: identical bytes and start kind (and
 * the start vnode held when the event was posted) take the PASS and
 * record that namei's own start vnode and rflags; later lookups of the
 * slot compare against those.  A carried slot never waits at its namei:
 * any difference answers ERELOOKUP (DQS_F_PATH2: the caller loops and
 * both paths are consulted again) or EIO (DQS_F_AHEAD).  A carried slot is
 * checked even inside an exempt region.  A content slot
 * (dq_intent_slot_content) matches a kernel-space lookup by its bytes and
 * dirfd instead of its pointer, for a path the kernel copies again before
 * looking it up (AF_UNIX names, kldload's file, mount options).
 */
#define	DQ_INTENT_SLOTS		4

struct dq_islot {
	const char	*ds_path;	/* the syscall's path argument */
	enum uio_seg	 ds_seg;
	int		 ds_dirfd;
	uint32_t	 ds_start_kind;	/* of the last consultation */
	uint32_t	 ds_rflags;
	struct vnode	*ds_start_vp;	/* vref'd; released at leave */
	struct vnode	*ds_rdir_vp;	/* carried absolute path: the process
					   root of an ABI-root restart */
	const cap_rights_t *ds_rights;	/* the rights the slot's lookup needs
					   of its dirfd (dq_intent_slot_rights);
					   NULL: none beyond CAP_LOOKUP */
	uint32_t	 ds_frf;	/* fetched: DQ_RF_STRICTREL, _BENEATH
					   of the slot's own start (1c-iii-b),
					   DQS_FRF_UNUSABLE */
	int		 ds_ferr;	/* fetched: the error the slot's own
					   lookup will give (round 4) */
#define	DQS_FRF_UNUSABLE	0x80000000	/* a real start its own namei
						   refuses: PASS only (never
						   posted) */
	uint64_t	 ds_start_obj;	/* DQ_START_SERVED: the served start's
					   object id (never reused on its
					   queue; 1c-iii-b) */
	struct file	*ds_root;	/* fetched: the served root of the
					   start's snapshot (D177), held */
	bool		 ds_rootdead;	/* fetched: DR_ROOT_DEAD in it */
	char		*ds_real;	/* a REAL answer (M_TEMP): a restart,
					   or a carried slot's own lookup,
					   applies it without waiting (D167) */
	char		*ds_bytes;	/* M_TEMP copy of the path consulted */
	size_t		 ds_len;
	uint8_t		 ds_state;
#define	DQS_UNUSED		0
#define	DQS_DECLARED		1	/* matched by the declaration */
#define	DQS_PASSED		2	/* consulted, PASS cached */
#define	DQS_CARRIED		3	/* consulted before its own namei,
					   not yet bound to it */
	uint8_t		 ds_flags;
#define	DQS_F_PATH2		0x01	/* slot 1 of a DQI_PATH2 intent */
#define	DQS_F_AHEAD		0x02	/* consulted by dqres_consult_slot */
#define	DQS_F_KCONSUMER		0x04	/* class 2 in a DQI_USER intent
					   (dq_intent_slot_kconsumer) */
#define	DQS_F_CONTENT		0x08	/* matched by content, not pointer */
};

struct dq_intent {
	uint32_t	 di_op;		/* DQ_ROP_* of dev/dq/dq.h */
	uint32_t	 di_flags;
#define	DQI_USER		0x0001	/* user-origin (class 1) */
#define	DQI_KCONSUMER		0x0002	/* the object goes to the kernel
					   (class 2) */
#define	DQI_NO_ERESTART		0x0004	/* the caller misreads ERESTART */
#define	DQI_PATH2		0x0008	/* slot 1 is the second path of a
					   two-path operation, carried in slot
					   0's event; the caller loops on
					   ERELOOKUP (needs DQI_NO_ERESTART) */
#define	DQI_KERNEL		0x0010	/* kernel-origin (class 3): the exec
					   interpreter lookups */
	uint32_t	 di_mode;	/* open flags, mkdir mode, ... */
	uint32_t	 di_expected_locks; /* shared/read locks the caller holds
					   while consulting (0 everywhere in 1c-i) */
	uint64_t	 di_drs_object;
	uint32_t	 di_syscall;
	struct dq_islot	 di_slot[DQ_INTENT_SLOTS];
	struct dq_intent *di_prev;	/* an outer intent */
	/*
	 * Served answers (1c-iii, D157-D161).  di_accept is the served kinds
	 * (DQ_RACCEPT(DQ_RESOLVE_*)) the entry point can complete, declared
	 * only through dq_intent_enter_served (DQI_SERVED); slot 0 of a
	 * class-1, unrestricted real-start lookup accepts them besides PASS.
	 * di_res holds the answer between dqres_namei's EDQRESOLVED and the
	 * wrapper's completion (DQI_COMPLETING); dq_intent_leave releases
	 * anything not taken.
	 */
	uint32_t	 di_accept;
	uint32_t	 di_cmode;	/* drs_cmode: creation mode after umask */
	uint64_t	 di_dev;	/* drs_dev: mknod */
	const struct dq_setattr_body *di_setattr; /* SETATTR, TRUNCATE */
	const char	*di_text;	/* SYMLINK: the target (path2), kernel */
	size_t		 di_textlen;
	struct dqres_answer di_res;
	/*
	 * A served start (1c-iii-b): the answer came from a lookup that
	 * started at a served directory.  di_startcaps are that
	 * descriptor's capabilities (ni_filecaps, rights only), intersected
	 * with the policy's rights at install (D159); di_resflags are the
	 * lookup's NIRES_* (O_RESOLVE_BENEATH is inherited from
	 * NIRES_BENEATH).
	 */
	uint64_t	 di_startobj;
	cap_rights_t	 di_startrights;
	uint32_t	 di_startfcntls;
	uint32_t	 di_resflags;
	bool		 di_startlimited; /* di_startrights apply */
	int16_t		 di_startnioctls; /* -1: all */
	u_long		*di_startioctls; /* M_TEMP copy of the start's list */
};
#define	DQI_SERVED		0x0020	/* di_accept declared */
#define	DQI_COMPLETING		0x0040	/* the completion runs: no lookup */
#define	DQI_REALFD		0x0080	/* funlinkat/frmdirat named a real
					   descriptor: a served path is
					   EDEADLK (D170) */

/* What a consultation asks (filled by kern_dqres.c, posted by dev/dq). */
struct dqres_req {
	uint32_t	 rq_op;
	uint32_t	 rq_rflags;	/* DQ_RF_* of dev/dq/dq.h */
	uint32_t	 rq_start_kind;	/* DQ_START_* */
	uint32_t	 rq_class;	/* 1, 2 or 3 (D127) */
	uint32_t	 rq_mode;
	uint32_t	 rq_syscall;
	uint32_t	 rq_expected_locks;
	bool		 rq_may_restart; /* the first consultation of a slot in
					   namei_setup, ERESTART allowed */
	bool		 rq_no_erestart; /* DQI_NO_ERESTART: the caller loops
					   on EAGAIN, so EAGAIN becomes EIO */
	uint64_t	 rq_object;
	const char	*rq_path;
	size_t		 rq_pathlen;
	const char	*rq_path2;
	size_t		 rq_path2len;
	const char	*rq_startpath;	/* best effort, may be NULL */
	size_t		 rq_startpathlen;
	uint32_t	 rq_start2_kind; /* path2's own (DQ_START_*), or 0 */
	const char	*rq_startpath2;	/* path2's start hint, may be NULL */
	size_t		 rq_startpath2len;
	int		 rq_domain;	/* SOCKET, SOCKETPAIR (1c-ii) */
	int		 rq_type;
	int		 rq_protocol;
	uint32_t	 rq_accept;	/* DQ_RACCEPT(...) (1c-iii) */
	uint64_t	 rq_start;	/* DQ_START_SERVED: the object (iii-b) */
	uint64_t	 rq_start2;	/* path2's served start */
	uint32_t	 rq_cmode;
	uint64_t	 rq_dev;
	const struct dq_setattr_body *rq_setattr; /* appended to the body */
	uint64_t	 rq_root;	/* the served root's object, or 0
					   (D184: "/" and ".." for the
					   controller) */
	const char	*rq_rootpath;	/* its di_path, the 5th string */
	size_t		 rq_rootpathlen;
};

/*
 * The vector dev/dq registers (D125).  consult posts RESOLVE on the
 * binding's queue and waits; it answers 0 with the answer's kind in
 * *ans (PASS, or a served kind of rq_accept) or an errno.  It never
 * returns ERESTART unless rq_may_restart.  bind turns an FD answer's
 * object into a referenced, uninstalled file in the calling thread's
 * credential (consuming da_obj in every case; a failure retires it);
 * answer_release retires an FD answer's object nobody bound.  file_ident
 * copies a served file's identity (ENOTTY for any other file) with its
 * queue's id and whether the queue has closed.
 */
struct dqres_ops {
	void	(*dro_hold)(struct dqres_binding *);
	void	(*dro_rele)(struct dqres_binding *);
	int	(*dro_consult)(struct thread *, struct dqres_binding *,
		    const struct dqres_req *, struct dqres_answer *);
	void	(*dro_unmarked)(struct dqres_binding *); /* M2 counter */
	void	(*dro_exdev)(struct dqres_binding *);	/* ds2_resolve_exdev */
	int	(*dro_bind)(struct thread *, struct dqres_answer *, int,
		    struct file **);
	void	(*dro_answer_release)(struct thread *, struct dqres_answer *);
	int	(*dro_file_ident)(struct file *, struct dq_ident_file *,
		    uint64_t *, bool *);
	bool	(*dro_queue_closed)(uint64_t);	/* gone or DQ_Q_CLOSING */
	/* The queues the process owns die (DQRES_OWNER_GONE). */
	void	(*dro_owner_gone)(struct proc *);
	/*
	 * 1c-iii-b.  start: a served descriptor as a lookup start, its
	 * kind and id; EACCES when the caller is unattached (the binding
	 * NULL), EDEADLK when attached to another queue or holding this one,
	 * EIO once revoked or closing, ENOTTY for another file.  setattr:
	 * the object-level setattr (D96) without the O_PATH gate.  target:
	 * a served symlink's target (M_TEMP), EINVAL for another kind.
	 */
	int	(*dro_start)(struct thread *, struct dqres_binding *,
		    struct file *, uint32_t *, uint64_t *);
	int	(*dro_setattr)(struct thread *, struct file *,
		    struct dq_setattr_body *);
	int	(*dro_target)(struct file *, char **, size_t *);
	/*
	 * 1c-iii-c.  file_kind and file_objid: a served file's DQ_KIND_*
	 * and object id, both fixed at creation, so they take no lock
	 * (chroot_refuse_vdir_fds calls file_kind under the pwddesc mutex).
	 */
	uint32_t (*dro_file_kind)(struct file *);
	uint64_t (*dro_file_objid)(struct file *);
	/*
	 * The install gate of the binding's queue (finstall_refed_gate) for
	 * a SWAP answer: enter refuses with EIO once the queue has died and
	 * otherwise holds the queue's mutex, which the death takes first,
	 * until exit.  Entered and left at once it is the advisory test.
	 */
	void	(*dro_swap_gate)(struct dqres_binding *,
		    struct fdinstall_gate *);
};

void	dqres_register(const struct dqres_ops *ops);
extern const struct dqres_ops *dqres_ops;

/*
 * DTrace: the dqres provider (kern_dqres.c).  dqres:::namei-served (op,
 * answer kind, errno): a lookup from a served start returned.
 */
SDT_PROVIDER_DECLARE(dqres);
SDT_PROBE_DECLARE(dqres, , , namei__served);

/* Is the process attached?  Racy fast test; the slow paths lock. */
bool	dqres_proc_attached(struct proc *p);

/* pwddesc lifecycle (kern_descrip.c, kern_fork.c). */
void	dqres_pd_inherit_locked(struct pwddesc *newpdp, struct pwddesc *oldpdp,
	    struct dqres **preallocp);
struct dqres *dqres_alloc(int mflags);
void	dqres_free_unused(struct dqres *dr);
void	dqres_pd_release(struct dqres *dr);
bool	dqres_same_binding(const struct dqres *a, const struct dqres *b);
void	dqres_fork_late(struct proc *p1, struct pwddesc *child);
void	pd_replace(struct thread *td, struct pwddesc *newpdp);

/*
 * Attaching (dev/dq's DQ_IOC_ATTACH, D138/D148).  *cwdfpp and *rootfpp
 * (held served directories of the queue, or NULL: ATTACH's starts, D169)
 * are consumed and set to NULL on success.
 */
int	dqres_attach(struct thread *td, struct proc *p,
	    struct dqres_binding *b, struct file *qfp, struct file **cwdfpp,
	    struct file **rootfpp, uint32_t flags);
/*
 * ATTACH's open-directory rule (kern_descrip.c, D184: the controller
 * chooses the confinement): with a served root, the child's table under
 * chroot(2)'s rule (kern.chroot_allow_open_directories, EPERM); with
 * nodirs, root or not, any open real directory is EBUSY.  Called with
 * FILEDESC_SLOCK and PWDDESC_XLOCK held.
 */
int	dqres_attach_dirs_check(struct filedesc *fdp, struct pwddesc *pdp,
	    bool root, bool nodirs);

/* Intents. */
void	dq_intent_enter(struct thread *td, struct dq_intent *di, uint32_t op,
	    uint32_t flags);
void	dq_intent_slot(struct dq_intent *di, int slot, const char *path,
	    enum uio_seg seg, int dirfd);
void	dq_intent_enter_served(struct thread *td, struct dq_intent *di,
	    uint32_t op, uint32_t flags, uint32_t accept);
void	dq_intent_leave(struct thread *td, struct dq_intent *di);
/* The rights a slot's own lookup needs of its dirfd (beyond CAP_LOOKUP). */
static __inline void
dq_intent_slot_rights(struct dq_intent *di, int slot,
    const cap_rights_t *rights)
{

	di->di_slot[slot].ds_rights = rights;
}
bool	dqres_inject_drop(struct thread *td);
int	dqres_consult_slot(struct thread *td, int slot);
void	dq_intent_slot_content(struct dq_intent *di, int slot,
	    const char *kpath, int dirfd);

/* A slot whose object goes to the kernel, in an otherwise class-1 intent. */
static __inline void
dq_intent_slot_kconsumer(struct dq_intent *di, int slot)
{

	di->di_slot[slot].ds_flags |= DQS_F_KCONSUMER;
}

/*
 * The choke point (namei_setup): consult when attached.  dp is the start
 * namei computed (the root vnode used for an absolute path); abs is true
 * for an absolute path; snap is namei_setup's snapshot, whose served root
 * is posted with the event and must contain every served answer (D184).
 */
int	dqres_namei(struct nameidata *ndp, struct vnode *dp, bool abs,
	    const struct dqres_snap *snap, bool *realp);

/*
 * Served starts (1c-iii-b, D162-D165, D167, D170, D172).
 *
 * dqres_lookup_start: fgetvp_lookup_start found a vnode-less descriptor
 * (held) at ni_dirfd: 0 makes it a served start (a served directory with
 * a non-empty path in a process attached to its queue, or any served
 * descriptor for an O_EMPTY_PATH open); otherwise ENOTDIR (so the
 * AT_EMPTY_PATH fallbacks run), EACCES (unattached) or EDEADLK (attached
 * elsewhere) for a served directory outside its attachment (D163), or EIO
 * (revoked, closing).
 *
 * dqres_namei_served: namei_setup's served branch, consuming fp: the
 * D165 pre-checks, the consultation from the served start, the I8
 * post-checks; EDQRESOLVED for a served answer, an errno, or 0 with
 * *realp set when the answer was REAL and cn_pnbuf now holds the real
 * absolute path namei continues from (the caller sets ni_rootdir and
 * ISRESTARTED and starts at the root).
 *
 * dqres_namei_symlink: namei's symlink loop, after the link was read into
 * cn_pnbuf (dp the link's directory, referenced, unlocked): an absolute
 * target under the served root of snap (namei_setup's snapshot, held by
 * namei until it returns) re-enters there (D172 (a)); otherwise a PASSed
 * class-1 lookup's re-consultation (D172 (b)); 0 to continue, *realp as
 * above, EDQRESOLVED or an errno.
 */
int	dqres_lookup_start(struct nameidata *ndp, struct file *fp);
bool	namei_cap_dotdot(void);	/* vfs.lookup_cap_dotdot (vfs_lookup.c) */
#define	DQRES_START_DIRFD	0	/* a served dirfd (1c-iii-b) */
#define	DQRES_START_CWD		1	/* the served cwd (1c-iii-c) */
#define	DQRES_START_ROOT	2	/* the served root */
int	dqres_namei_served(struct nameidata *ndp, struct file *fp, int how,
	    const struct dqres_snap *snap, bool capdotdot, bool *realp);
int	dqres_namei_symlink(struct nameidata *ndp, struct vnode *dp,
	    const struct dqres_snap *snap, bool *realp);

/*
 * Virtual cwd and root (1c-iii-c, D169, D174, D175, D177).
 *
 * pwd_hold_dqres (kern_descrip.c): the pwd and the start snapshot in one
 * PWDDESC_XLOCK section; pwd_dqres_proc: a process's snapshot alone (p
 * held by the caller, or curproc).  dqres_set_cwd and dqres_set_root
 * (kern_descrip.c) install a served directory, consuming its reference
 * (the root under chroot's open-directory rule).  dqres_namei_setup_start
 * is namei_setup's served cwd or root start (D175); dqres_present_* give
 * D174's presented paths against a viewer; dqres_getcwd,
 * dqres_proc_dirpath and dqres_execpath are their consumers.
 */
struct pwd *pwd_hold_dqres(struct thread *td, struct dqres_snap *snap);
void	pwd_dqres_proc(struct proc *p, struct dqres_snap *snap);
void	dqres_snap_drop(struct dqres_snap *snap);

/* Release a snapshot (no lock held); unattached ones are all zero. */
static __inline void
dqres_snap_release(struct dqres_snap *snap)
{

	if (__predict_false(snap->dsn_cwd != NULL || snap->dsn_root != NULL))
		dqres_snap_drop(snap);
	snap->dsn_flags = 0;
}

/* Does the snapshot name a served (or dead) cwd or root? */
static __inline bool
dqres_snap_served(const struct dqres_snap *snap)
{

	return (snap->dsn_cwd != NULL || snap->dsn_root != NULL ||
	    snap->dsn_flags != 0);
}

void	dqres_set_cwd(struct thread *td, struct file *fp);
int	dqres_set_root(struct thread *td, struct file *fp);
bool	dqres_file_is_dir(struct file *fp);
int	dqres_namei_setup_start(struct nameidata *ndp,
	    const struct dqres_snap *snap, bool capdotdot, bool *realp);
int	dqres_present_viewer(struct thread *viewer, uint64_t qgid,
	    const char *path, size_t pathlen, char *out, size_t outsz);
int	dqres_present_file(struct thread *viewer, struct file *fp, char *out,
	    size_t outsz);
bool	dqres_served_root(struct thread *td);
int	dqres_getcwd(struct thread *td, char *buf, size_t *buflenp);
int	dqres_proc_dirpath(struct thread *viewer, struct proc *p, bool root,
	    char *buf, size_t len);
int	dqres_fchdir_file(struct thread *td, int fd,
	    const cap_rights_t *rights, struct file **fpp);
int	dqres_dir_check(struct thread *td, struct file *fp);
int	dqres_take_dir(struct thread *td, struct dq_intent *di,
	    struct file **fpp);
int	dqres_execpath(struct thread *td, const char *fname, char **pathp);
/*
 * funlinkat/frmdirat's descriptor (D170), before namei: a served one is
 * returned held (0) and names the event's drs_object; ENOTTY for any
 * other, which the caller takes as a vnode and marks with
 * dqres_unlink_realfd (a served path is then EDEADLK).
 */
int	dqres_unlink_fd(struct thread *td, int fd, const cap_rights_t *rights,
	    struct file **fpp);
void	dqres_unlink_realfd(struct thread *td);

/*
 * AF_UNIX names: *enteredp says di was entered (a path name, consulted in
 * a content slot); the caller leaves it after the protocol's lookup.
 */
struct sockaddr;
int	dqres_consult_sun(struct thread *td, struct dq_intent *di, uint32_t op,
	    int dirfd, const struct sockaddr *sa, bool *enteredp);

/*
 * socket(2) and socketpair(2) of an attached process (D139): one event
 * with the protocol as socreate_find resolved it, no path, start NONE;
 * called with no descriptor slot taken and no lock held.  0 is PASS.
 */
int	dqres_consult_socket(struct thread *td, uint32_t op, int domain,
	    int type, int protocol);

/*
 * EDQRESOLVED containment (D157): the only consumer.  A marked wrapper
 * whose intent was entered with dq_intent_enter_served runs its completion
 * when the impl returned EDQRESOLVED (unless the fault injection drops it),
 * with DQI_COMPLETING set: a completion makes no lookup.
 */
#define	DQRES_SERVED(td, di, error, completion) do {			\
	if (__predict_false((error) == EDQRESOLVED) &&			\
	    !dqres_inject_drop(td)) {					\
		(di)->di_flags |= DQI_COMPLETING;			\
		(error) = (completion);					\
		(di)->di_flags &= ~DQI_COMPLETING;			\
	}								\
} while (0)

/*
 * Completion helpers (1c-iii-a, kern_dqres.c).  Each takes what the answer
 * holds; the intent releases the rest at leave.
 */
struct stat;
struct statfs;
struct ucred;
const struct dq_ident_file *dqres_ident(struct dq_intent *di, uint32_t kind);
void	dqres_ident_to_stat(const struct dq_ident_file *di, struct ucred *cred,
	    struct stat *sb);
void	dqres_ident_to_statfs(const struct dq_ident_file *di,
	    struct statfs *sf);
int	dqres_ident_pathconf(const struct dq_ident_file *di, int name,
	    long *valuep);
int	dqres_ident_access(const struct dq_ident_file *di, int accmode,
	    struct ucred *cred);
int	dqres_take_file(struct thread *td, struct dq_intent *di, int flags,
	    struct file **fpp);
int	dqres_take_file_raw(struct thread *td, struct dq_intent *di,
	    int fflags, struct file **fpp);
int	dqres_install(struct thread *td, struct dq_intent *di, struct file *fp,
	    int flags, int *fdp);
int	dqres_setattr_apply(struct thread *td, struct file *fp,
	    const struct dq_setattr_body *sb);
void	dqres_setattr_priv(struct thread *td, struct dq_setattr_body *sb,
	    uint32_t which);
int	dqres_emptypath_file(struct thread *td, int fd,
	    const cap_rights_t *rights, struct file **fpp);
int	dqres_file_setattr(struct thread *td, struct file *fp,
	    struct dq_setattr_body *sb);
int	dqres_file_target(struct file *fp, char **targetp, size_t *lenp);
int	dqres_file_ident(struct file *fp, struct dq_ident_file *ident,
	    uint64_t *qgidp, bool *closedp);
/* Is path at or under root, at a component boundary (D174)? */
bool	dqres_path_under(const char *root, size_t rlen, const char *path,
	    size_t plen);
/* Is the queue with this id closing or gone (true without dev/dq)? */
bool	dqres_queue_closed(uint64_t qgid);
/* mac_veriexec registers whether it enforces (O_VERIFY on served files). */
void	dqres_register_veriexec(bool (*enforcing)(void));

/*
 * A queue closed (dev/dq, after its objects are revoked): consumers that
 * keep per-queue state keyed by the queue's id (the Linux ABI's served
 * mount ids) free it here, so dev/dq never calls into them.
 */
#ifdef _SYS_EVENTHANDLER_H_
typedef void (*dq_queue_closed_fn)(void *, uint64_t);
EVENTHANDLER_DECLARE(dq_queue_closed, dq_queue_closed_fn);
#endif

/* I5 (D137, D153). */
bool	dqres_cred_change_refused(struct proc *p);

/*
 * A kernel-space path an attached process hands a driver or subsystem
 * that cannot be consulted where it is looked up (md vnode attach, a CTL
 * block backend file, veriexec manifest entries, ZFS file opens and cache
 * files, imgact_binmisc entries, vfs.try_reclaim_vnode, alq files, OES
 * mute paths, pNFS nfssvc paths, netgraph ksocket AF_LOCAL names, a core
 * file after a late ATTACH): EPERM for an attached caller outside an
 * exempt region, 0 otherwise.
 */
int	dqres_kpath_refused(struct thread *td);

/*
 * Exempt regions (D127): lookups the kernel makes for itself while
 * running in an attached process's thread (linker search, firmware,
 * mountroot, VFS_MOUNT's own lookups, vn_fullpath's VOP_VPTOCNP,
 * the NFS server's lookups for its clients, ...): only paths the kernel
 * computes.  A carried slot's lookup is still checked inside a region.
 * Every other kernel-space lookup by an attached thread is a ledger
 * failure: counted in ds2_resolve_unmarked, dq:::resolve-unmarked, and
 * refused with EPERM.  The flag is the current thread's own; save nests
 * the regions.
 */
#define	DQRES_NORESOLVE_ENTER(save) do {				\
	(save) = curthread->td_pflags2 & TDP2_DQ_NORESOLVE;		\
	curthread->td_pflags2 |= TDP2_DQ_NORESOLVE;			\
} while (0)
#define	DQRES_NORESOLVE_LEAVE(save) do {				\
	if ((save) == 0)						\
		curthread->td_pflags2 &= ~TDP2_DQ_NORESOLVE;		\
} while (0)
/* One exempt call (namei, vn_open, ...) with a value. */
#define	DQRES_EXEMPT(call) __extension__ ({				\
	int _dq_save;							\
	__typeof(call) _dq_ret;						\
									\
	DQRES_NORESOLVE_ENTER(_dq_save);				\
	_dq_ret = (call);						\
	DQRES_NORESOLVE_LEAVE(_dq_save);				\
	_dq_ret;							\
})

/*
 * A queue dies with the process that opened it.  Called by that process
 * where it exits, execs or leaves a descriptor table it shares (exit1,
 * do_execve, fdunshare, fork1's RFCFDG), with no lock held: every queue it
 * owns fails closed there, whoever else still holds the queue's file.  The
 * flag is the process's own and is never cleared, so the test needs no
 * lock; a process that never opened a queue pays for the test alone.
 */
#define	DQRES_OWNER_GONE(p) do {					\
	if (__predict_false(((p)->p_flag2 & P2_DQOWNER) != 0) &&	\
	    dqres_ops != NULL)						\
		dqres_ops->dro_owner_gone(p);				\
} while (0)

#define	DQRES_ATTACHED_TD(td)						\
	(__predict_false(dqres_ops != NULL && dqres_proc_attached((td)->td_proc)))

#endif /* _KERNEL */
#endif /* !_SYS_DQRES_H_ */
