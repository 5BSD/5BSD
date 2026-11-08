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

struct dqres_binding;
struct file;
struct nameidata;
struct proc;
struct pwddesc;
struct thread;
struct vnode;

/*
 * The per-pwddesc record (D123).  dr_binding is shared and refcounted
 * through the vector; dr_cwd and dr_root are served directories (stage 1c
 * series iii; always NULL in series i).  A pwddesc is attached when
 * pd_dqres != NULL.  Written under PWDDESC_XLOCK.
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
};

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
};

/*
 * The vector dev/dq registers (D125).  consult posts RESOLVE on the
 * binding's queue and waits; it answers 0 for PASS or an errno.  It never
 * returns ERESTART unless rq_may_restart.
 */
struct dqres_ops {
	void	(*dro_hold)(struct dqres_binding *);
	void	(*dro_rele)(struct dqres_binding *);
	int	(*dro_consult)(struct thread *, struct dqres_binding *,
		    const struct dqres_req *);
	void	(*dro_unmarked)(struct dqres_binding *); /* M2 counter */
};

void	dqres_register(const struct dqres_ops *ops);
extern const struct dqres_ops *dqres_ops;

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

/* Attaching (dev/dq's DQ_IOC_ATTACH, D138/D148). */
int	dqres_attach(struct thread *td, struct proc *p,
	    struct dqres_binding *b, struct file *qfp);

/* Intents. */
void	dq_intent_enter(struct thread *td, struct dq_intent *di, uint32_t op,
	    uint32_t flags);
void	dq_intent_slot(struct dq_intent *di, int slot, const char *path,
	    enum uio_seg seg, int dirfd);
void	dq_intent_leave(struct thread *td, struct dq_intent *di);
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
 * for an absolute path.
 */
int	dqres_namei(struct nameidata *ndp, struct vnode *dp, bool abs);

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

#define	DQRES_ATTACHED_TD(td)						\
	(__predict_false(dqres_ops != NULL && dqres_proc_attached((td)->td_proc)))

#endif /* _KERNEL */
#endif /* !_SYS_DQRES_H_ */
