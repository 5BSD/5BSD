/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * squeue: the native 5BSD completion-ring engine shared by the native
 * squeue_* syscalls and the Linux io_uring front-end.  This header holds the
 * kernel-internal engine types, the front-end description, and the engine KPI.
 *
 * Includers must already have pulled in <sys/queue.h>, <sys/callout.h>,
 * <sys/selinfo.h>, <sys/lock.h>, <sys/mutex.h>, <sys/uio.h>, <vm/vm.h>,
 * <vm/vm_object.h> and <sys/io_uring.h> (for the on-ring structures).
 */
#ifndef _SYS_SQUEUE_H_
#define	_SYS_SQUEUE_H_

#ifdef _KERNEL
#include <sys/cpuset.h>
#include <sys/sx.h>
#include <sys/taskqueue.h>

#define	SQ_MAX_ENTRIES		32768
#define	SQ_MAX_CQ_ENTRIES	(SQ_MAX_ENTRIES * 2)	/* IORING_SETUP_CQSIZE */
#define	SQ_MSG_DONTWAIT	0x40	/* Linux MSG_DONTWAIT */
#define	SQ_MAX_REG_FILES	4096
#define	SQ_MAX_REG_BUFS	1024
#define	SQ_MAX_PBUFS		65536
#define	SQ_BAD_RING_STATE	(-4096) /* KPI only; front ends map errno */
#define	SQ_WORKER_BOUND	0
#define	SQ_WORKER_UNBOUND	1
#define	SQ_WORKER_CLASSES	2
#define	SQ_LINUX_ETIME		62	/* Linux ETIME (no BSD equivalent) */
#define	SQ_LINUX_EBADFD	77	/* Linux EBADFD (BSD has no equivalent) */

/* Shared admission masks are also used by the Linux query front end. */
#define SQ_SUPPORTED_SETUP_FLAGS (IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP | \
    IORING_SETUP_NO_SQARRAY | IORING_SETUP_SUBMIT_ALL | \
    IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_R_DISABLED | \
    IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG | \
    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SQE128 | \
    IORING_SETUP_SQE_MIXED | \
    IORING_SETUP_CQE32 | IORING_SETUP_CQE_MIXED | \
    IORING_SETUP_SQ_REWIND | IORING_SETUP_NO_MMAP | \
    IORING_SETUP_REGISTERED_FD_ONLY | IORING_SETUP_SQPOLL | \
    IORING_SETUP_SQ_AFF | IORING_SETUP_ATTACH_WQ)
#define SQ_SUPPORTED_ENTER_FLAGS (IORING_ENTER_GETEVENTS | \
    IORING_ENTER_EXT_ARG | IORING_ENTER_ABS_TIMER | \
    IORING_ENTER_REGISTERED_RING | IORING_ENTER_EXT_ARG_REG | \
    IORING_ENTER_NO_IOWAIT | IORING_ENTER_SQ_WAKEUP | \
    IORING_ENTER_SQ_WAIT)
#define SQ_SUPPORTED_FEATURE_FLAGS (IORING_FEAT_SINGLE_MMAP | \
    IORING_FEAT_NODROP | IORING_FEAT_SUBMIT_STABLE | \
    IORING_FEAT_RW_CUR_POS | IORING_FEAT_CUR_PERSONALITY | \
    IORING_FEAT_FAST_POLL | IORING_FEAT_POLL_32BITS | \
    IORING_FEAT_SQPOLL_NONFIXED | IORING_FEAT_EXT_ARG | \
    IORING_FEAT_RSRC_TAGS | IORING_FEAT_CQE_SKIP | \
    IORING_FEAT_LINKED_FILE | IORING_FEAT_REG_REG_RING | \
    IORING_FEAT_MIN_TIMEOUT | \
    IORING_FEAT_NO_IOWAIT)
#define SQ_SUPPORTED_SQE_FLAGS (IOSQE_FIXED_FILE | IOSQE_IO_DRAIN | \
    IOSQE_IO_LINK | IOSQE_IO_HARDLINK | IOSQE_ASYNC | \
    IOSQE_BUFFER_SELECT | IOSQE_CQE_SKIP_SUCCESS)

/*
 * Sentinel returned by the ABI-neutral core for an opcode it does not handle
 * itself; sq_issue_op then routes the request to the front-end's issue_ext
 * hook.  Byte counts are >= 0 and real errnos are small-negative, so INT32_MIN
 * never collides with a real result.
 */
#define	SQ_NOTHANDLED		INT32_MIN
#define	SQ_EXT_PENDING		(INT32_MIN + 1)

/* Request lifecycle. */
enum sq_state {
	SQ_ST_NEW = 0,		/* freshly prepped, not yet issued */
	SQ_ST_ARMED,		/* async op waiting on ctx->pending */
	SQ_ST_READY,		/* resolved, on ctx->ready, CQE not yet posted */
};

struct sq_bpf_set;
struct squeue_ctx;
struct sq_buf_table;
struct sq_buf_backing;
struct sq_pbuf_ring;
struct sq_zcrx;
struct sq_issuer;
struct sq_file_node;
struct filecaps;

/*
 * A single tracked request.  Members reachable only from the owning thread
 * (link_next while a chain is being built) need no lock; membership on the
 * ctx->pending / ctx->ready / ctx->drain lists and the state/res fields are
 * protected by ctx->mtx.
 */
struct sq_req {
	TAILQ_ENTRY(sq_req)	entry;		/* pending / ready / drain */
	struct squeue_ctx	*ctx;
	struct sq_req		*link_next;	/* next SQE in this link chain */
	struct io_uring_sqe	sqe;		/* private, stable copy */
	struct callout		co;		/* TIMEOUT */
	uint64_t		user_data;
	uint8_t			opcode;
	uint8_t			sqe_flags;
	enum sq_state		state;
	int32_t			res;		/* completion result */
	uint32_t		cflags;		/* CQE flags */
	bool			posted;		/* op already posted its CQE(s) */
	bool			retry;		/* fast-poll: re-issue when ready */
	bool			tmo_count;	/* count-based timeout armed */
	uint32_t		tmo_target;	/* cq_count value that fires it */
	/*
	 * Fields below are appended (never inserted) and are touched only by
	 * the ABI-neutral engine, never by a front-end.  Keeping them at the
	 * end preserves the offsets of every field the Linux front-end reads,
	 * so the engine and the io_uring module stay binary-compatible.
	 */
	TAILQ_ENTRY(sq_req)	wq;		/* async worker-pool queue */
	/* async worker offload (IOSQE_ASYNC file I/O): set on the submitting
	 * thread, consumed and cleared by the worker before the req is readied */
	struct file		*ofp;		/* held target file */
	struct uio		*ouio;		/* prepared user-space uio */
	struct vmspace		*ovm;		/* owner address space (ref held) */
	bool			owrite;		/* offloaded op is a write */
	bool			ocur;		/* use current file offset */
	bool			multishot;	/* POLL_ADD multishot: stay armed */
	int			rw_foflags;	/* translated per-I/O policy */
	struct sq_buf_table	*buf_table;	/* held fixed-buffer generation */
	struct uio		*buf_uio;	/* immutable kernel-address template */
	struct sq_req		*link_timeout;	/* deadline owned until detached */
	struct sq_req		*link_target;	/* protected by ctx->mtx */
	int64_t			timeout_sec, timeout_nsec;
	TAILQ_ENTRY(sq_req)	issue_entry;	/* ctx->issuing */
	struct thread		*issuer;	/* running submitter or worker */
	bool			issuing;
	bool			worker_owned;
	bool			work_queued;	/* protected by sq_wq_mtx */
	uint8_t		worker_class;	/* SQ_WORKER_BOUND or SQ_WORKER_UNBOUND */
	bool			cancel_requested;
	bool			on_poll;
	bool			poll_delete;
	int			prep_error; /* native errno, before chain side effects */
	uint64_t		pbuf_want;	/* READV bound copied during preparation */
	uint64_t		pbuf_addr;	/* selected provided buffer */
	uint32_t		pbuf_len;
	uint16_t		pbuf_bid;
	bool			pbuf_selected;
	bool			poll_first;	/* skip first issue and arm readiness */
	bool			net_multishot;	/* Linux recv/accept repeated CQEs */
	uint32_t		pbuf_cap;	/* original provided-buffer capacity */
	bool			complete_eagain; /* do not arm a fast-poll retry */
	uint32_t		net_mshot_remaining; /* optional recv byte limit */
	uint32_t		recvmsg_namelen; /* multishot output reservation */
	uint32_t		recvmsg_controllen;
	bool			net_bundle;	/* Linux SEND/RECV provided-buffer bundle */
	struct sq_pbuf_ring	*pbuf_ring;	/* held registered-ring selection */
	uint16_t		pbuf_ring_count; /* selected entries awaiting commit */
	struct file		*match_fp;	/* held file identity for cancellation */
	struct sq_file_node	*file_node;	/* held fixed-file generation */
	uint32_t		timeout_repeats; /* remaining multishot expirations */
	int			timeout_ticks;	/* relative interval after preparation */
	struct ucred		*cred;		/* held registered personality */
	uint64_t		cqe_extra1;	/* large-CQE extension */
	uint64_t		cqe_extra2;
	bool			cqe_big;	/* consumes a 32-byte CQE */
	uintptr_t		poll_id;	/* private held-file kqueue ident */
	int			poll_event_error; /* CAP_EVENT/bad-fd result */
	bool			poll_ring_target; /* avoid ring-file cycle */
	struct filecaps		*poll_caps; /* captured raw EPOLL_WAIT rights */
	int			poll_capture_error;
	bool			poll_use_held_fd;
	/* Front-end asynchronous wait; callback only schedules completion work. */
	void			*ext_arg;
	void			(*ext_cancel)(void *);
	bool			ext_poll_seen; /* guarded by ctx->mtx */
	struct squeue_ctx	*poll_target_ctx; /* held by internal poll proxy */
	/* Prepared Linux OPENAT2/CONNECT data for request BPF filters. */
	uint8_t		bpf_pdu[24];

};

/*
 * Ring layout (offsets reported to userspace via sq_off/cq_off, so the exact
 * placement is private).  Region 0 (SQ_RING & CQ_RING, single mmap): this
 * header + cqes[] + the SQ index array.  Region 1 (SQES): io_uring_sqe[].
 */
struct sq_rings {
	uint32_t	sq_head;
	uint32_t	sq_tail;
	uint32_t	cq_head;
	uint32_t	cq_tail;
	uint32_t	sq_ring_mask;
	uint32_t	cq_ring_mask;
	uint32_t	sq_ring_entries;
	uint32_t	cq_ring_entries;
	uint32_t	sq_dropped;
	uint32_t	sq_flags;
	uint32_t	cq_flags;
	uint32_t	cq_overflow;
};

TAILQ_HEAD(sq_reqq, sq_req);

/*
 * A completion that could not be written to the CQ because it was full.
 * Backlogged in submission order and flushed into the CQ as the application
 * drains it, so a completion is never lost (IORING_FEAT_NODROP).
 */
struct sq_ovfl {
	TAILQ_ENTRY(sq_ovfl)	entry;
	uint64_t		user_data;
	int32_t			res;
	uint32_t		cflags;
	uint64_t		extra1;
	uint64_t		extra2;
	bool			big;
};
TAILQ_HEAD(sq_ovflq, sq_ovfl);

/* A single application-provided buffer (PROVIDE_BUFFERS / BUFFER_SELECT). */
struct sq_pbuf {
	TAILQ_ENTRY(sq_pbuf)	entry;
	uint16_t		bgid;	/* buffer group */
	uint16_t		bid;	/* buffer id within the group */
	uint64_t		addr;
	uint32_t		len;
};
TAILQ_HEAD(sq_pbufq, sq_pbuf);
TAILQ_HEAD(sq_pbuf_ringq, sq_pbuf_ring);
TAILQ_HEAD(sq_zcrxq, sq_zcrx);

/* ABI-neutral arguments for a copied receive-area registration. */
struct sq_zcrx_reg {
	uintptr_t	area_addr;
	uint64_t	area_len;
	uintptr_t	rq_addr;
	uint64_t	rq_size;
	uint32_t	rq_entries;
	uint32_t	id;
	uint32_t	rx_buf_len;
	uint32_t	head_off;
	uint32_t	tail_off;
	uint32_t	rqes_off;
	uint64_t	mmap_offset;
	bool		rq_user;
};
struct sq_personality;
LIST_HEAD(sq_personalityq, sq_personality);

/* A selected provided buffer returned to an ABI front-end batch operation. */
struct sq_pbuf_desc {
	uint64_t	addr;
	uint32_t	len;	/* length exposed to this operation */
	uint32_t	cap;	/* original length, used when returning it */
	uint16_t	bid;
	struct sq_pbuf_ring *ring; /* non-NULL for registered ring selection */
};

struct squeue_ctx {
	struct mtx	mtx;
	struct selinfo	sel;		/* poll/kqueue on CQ readiness */
	vm_object_t	obj;		/* wired ring backing store */
	struct sq_buf_backing *ring_user; /* pinned NO_MMAP ring pages */
	struct sq_buf_backing *sqes_user; /* pinned NO_MMAP SQE pages */
	char		*kva;		/* kernel mapping of obj */
	vm_size_t	objsize;	/* total object/kva size */
	vm_size_t	ring_region;	/* bytes of region 0 (page-rounded) */
	vm_size_t	sqes_off;	/* obj offset of the SQES region */
	vm_size_t	sqes_size;
	struct sq_rings *rings;
	struct io_uring_cqe *cqes;
	uint32_t	*sq_array;
	struct io_uring_sqe *sqes;
	uint32_t	sq_entries;
	uint32_t	cq_entries;
	uint32_t	sqe_stride;
	uint32_t	cqe_stride;
	uint32_t	sq_mask;
	uint32_t	cq_mask;
	uint32_t	setup_flags;
	bool		is_linux;	/* front-end ABI: Linux vs native 5BSD */
	/* Front-end hook for ABI-specific (non-neutral) opcodes; NULL = none. */
	int32_t		(*issue_ext)(struct squeue_ctx *, struct sq_req *,
			    struct thread *);
	/* Front-end errno translator (BSD errno -> negative ABI errno). */
	int		(*err_xlate)(int);
	int		cq_waiters;
	/* async request tracking (all under mtx) */
	struct sq_reqq	pending;	/* SQ_ST_ARMED reqs */
	struct sq_reqq	ready;		/* SQ_ST_READY reqs, need draining */
	struct sq_reqq	drain;		/* chain heads held by a barrier */
	int		npending;	/* length of pending */
	uint32_t	cq_count;	/* real completions, for count timeouts */
	/* registered resources (set once, read under mtx) */
	struct sq_buf_table *reg_bufs;	/* REGISTER_BUFFERS */
	uint32_t	reg_nbufs;
	struct sq_file_node **reg_files; /* refcounted registered-file generations */
	uint32_t	reg_nfiles;
	struct sq_pbufq pbufs;		/* PROVIDE_BUFFERS pool */
	struct sq_pbuf_ringq pbuf_rings;	/* registered provided-buffer rings */
	struct sq_zcrxq zcrx;		/* copied receive-area registrations */
	uint32_t	zcrx_next_id;
	uint32_t	npbufs;		/* provided buffers held (bounded) */
	struct sq_reqq	polls;		/* armed POLL_ADD requests */
	int		npolls;
	/*
	 * Appended (never inserted) so the offsets of every field the Linux
	 * front-end reads stay fixed and the engine/module remain binary-
	 * compatible.  refs covers the ring file, in-flight jobs, the SQPOLL
	 * thread and attached child contexts.  It outlives all users of its
	 * ring backing and shared worker controls.
	 */
	int		refs;
	/*
	 * Per-ring kqueue used for readiness: armed POLL_ADD targets and
	 * fast-poll retry fds are registered here (plus a user event, so a
	 * single kevent wait covers completions and target readiness).  Created
	 * lazily on first readiness need; held as a file * (its transient fd is
	 * closed).  Engine-internal - a front-end never touches it.
	 */
	struct file	*kqfp;

	struct sq_ovflq	overflow;	/* CQEs awaiting CQ space (NODROP backlog) */
	uint32_t	noverflow;	/* current backlog length (bounded) */
	/* Registered eventfd and ordinary-versus-worker-only notification mode. */
	struct file	*eventfd_fp;	/* held eventfd reference, or NULL */
	struct eventfd	*eventfd;	/* efd to signal (eventfd_fp->f_data) */
	int		mmap_bad_offset_errno;	/* front-end mapping policy */
	bool		(*op_supported)(uint8_t);	/* extension probe contribution */
	int		(*rw_flags)(uint32_t, int *);
	int		(*prepare_ext)(struct sq_req *);
	struct sq_reqq	issuing;
	struct sx	kq_sx;
	struct task	kq_wake_task;
	struct sx	register_sx;
	struct sx	files_sx; /* table lifetime and sleeping capability copies */
	struct sq_issuer *submitter;
	bool		disabled;
	bool		restrictions_registered;
	bool		restricted;
	uint8_t		allowed_ops[IORING_OP_LAST];
	uint8_t		allowed_register[IORING_REGISTER_LAST];
	uint8_t		allowed_sqe_flags, required_sqe_flags;
	/* Fixed-file automatic-allocation window, appended for ABI stability. */
	uint32_t	file_alloc_start;
	uint32_t	file_alloc_end;
	uint32_t	file_alloc_hint;
	/* Clock used by absolute EXT_ARG completion waits. */
	clockid_t	wait_clockid;
	int		(*clockid_xlate)(clockid_t, clockid_t *);
	int		(*register_query)(struct thread *, void *, uint32_t);
	/* REGISTER_EVENTFD_ASYNC: notify only when worker work becomes ready. */
	bool		eventfd_async;
	/* Ring creator identity used by zero-copy registered-buffer cloning. */
	struct uidinfo	*owner_uid;
	struct vmspace	*owner_vm;
	struct sq_personalityq personalities;
	uint16_t	personality_next;
	/* IOWQ limits and affinity live on worker_root.  sq_wq_mtx protects
	 * the owner fields for ordinary and SQPOLL ATTACH_WQ chains. */
	uint32_t	worker_max[2];
	uint32_t	worker_active[2];
	cpuset_t	worker_affinity;
	bool		worker_affinity_set;
	uintptr_t	poll_next_id;	/* private poll knote namespace */
	struct sx	mmap_sx;	/* excludes ring mapping during resize */
	/* A registered parameter region may be kernel-owned or pinned user pages. */
	vm_object_t	param_obj;
	char		*param_kva;
	vm_size_t	param_size;
	struct sq_buf_backing *param_user;
	bool		param_wait_arg;
	/* SQPOLL runs in the creator process so copyin/fget use its VM and fds. */
	struct cv	sqpoll_cv;
	/* The first ring owns the poller; attached rings hold its context alive. */
	struct squeue_ctx *sqpoll_root;
	TAILQ_HEAD(, squeue_ctx) sqpoll_members;
	TAILQ_ENTRY(squeue_ctx) sqpoll_member_entry;
	uint64_t sqpoll_pass;
	uint64_t sqpoll_seen;
	bool sqpoll_linked;
	bool sqpoll_busy;
	TAILQ_ENTRY(squeue_ctx) sqpoll_done_entry;
	struct thread	*sqpoll_td;
	uint32_t	sqpoll_wake_seq;
	uint32_t	sqpoll_idle_ms;
	uint32_t	sqpoll_group_idle_ms;
	uint32_t	sqpoll_aff_cpu;
	int		sqpoll_start_error;
	bool		sqpoll_ready;
	bool		sqpoll_running;
	bool		sqpoll_stop;
	bool		sqpoll_dead;
	void		(*sqpoll_thread_init)(struct thread *);
	int32_t		(*ext_poll)(struct sq_req *, struct thread *);
	bool		closing; /* last ring-file close: discard deferred work */
	int		(*register_ext)(struct squeue_ctx *, struct thread *,
		    uint32_t, void *, uint32_t);
	/* Lazily allocated bitmap of legacy provided-buffer groups. */
	uint64_t	*legacy_pbuf_groups;
	/* Canonical owner of IOWQ limits/affinity for ATTACH_WQ chains. */
	struct squeue_ctx *worker_root;
	/* Immutable classic-BPF request-filter chains, protected by mtx. */
	struct sq_bpf_filter *bpf_filters[IORING_OP_LAST];
	uint8_t	bpf_deny[IORING_OP_LAST];
	uint8_t	bpf_active;
};

/*
 * Front-end description passed to kern_squeue_setup: which ABI the ring serves
 * and how it translates errnos / handles non-core opcodes.  A native ("squeue")
 * front-end passes is_linux=false and NULL hooks; the Linux io_uring front-end
 * passes its translator and opcode extension.
 */
struct sq_frontend {
	bool		is_linux;
	int		(*err_xlate)(int);
	int32_t		(*issue_ext)(struct squeue_ctx *, struct sq_req *,
			    struct thread *);
	int		mmap_bad_offset_errno;	/* zero selects native EINVAL */
	bool		(*op_supported)(uint8_t);	/* extension probe contribution */
	int		(*rw_flags)(uint32_t, int *);
	int		(*prepare_ext)(struct sq_req *);
	int		(*clockid_xlate)(clockid_t, clockid_t *);
	int		(*register_query)(struct thread *, void *, uint32_t);
	uint32_t	feature_flags;	/* ABI-specific io_uring feature bits */
	/* Linux threads need emuldata when the shared poller joins the process. */
	void		(*sqpoll_thread_init)(struct thread *);
	int32_t		(*ext_poll)(struct sq_req *, struct thread *);
	int		(*register_ext)(struct squeue_ctx *, struct thread *,
		    uint32_t, void *, uint32_t);
};

/* Engine helpers a front-end's issue_ext hook may call. */
void	sq_post_cqe(struct squeue_ctx *ctx, uint64_t user_data,
	    int32_t res, uint32_t cflags);
void	sq_post_multishot_cqe(struct squeue_ctx *ctx, struct sq_req *req,
	    int32_t res, uint32_t cflags);
void	sq_wake(struct squeue_ctx *ctx);
int	sq_ext_park(struct sq_req *req, void *arg, void (*cancel)(void *),
	    void (*activate)(void *));
void	sq_ext_finish(struct sq_req *req, int32_t res);
int	sq_ext_poll_start(struct squeue_ctx *ctx, struct thread *td);
int32_t	sq_result(struct squeue_ctx *ctx, struct thread *td, int error);
int32_t	sq_err(struct squeue_ctx *ctx, int bsd_errno);
int	sq_select_buffer(struct squeue_ctx *ctx, struct sq_req *req,
	    uint64_t want);
int	sq_select_buffer_batch(struct squeue_ctx *ctx, uint16_t bgid,
	    uint64_t want, struct sq_pbuf_desc *bufs, uint32_t maxbufs,
	    uint32_t maxlegacy, uint32_t *nbufsp);
void	sq_return_buffer_batch(struct squeue_ctx *ctx, uint16_t bgid,
	    const struct sq_pbuf_desc *bufs, uint32_t nbufs);
bool	sq_commit_buffer_batch(struct squeue_ctx *ctx, uint16_t bgid,
	    const struct sq_pbuf_desc *bufs, uint32_t nbufs, uint32_t used,
	    uint32_t consumed);
bool	sq_buffer_group_empty(struct squeue_ctx *ctx, uint16_t bgid);
int	sq_prepare_fixed_buffer(struct squeue_ctx *ctx, struct sq_req *req,
	    uint64_t uaddr, uint32_t len, bool vec);
void	sq_recycle_buffer(struct sq_req *req);
uint32_t sq_consume_buffer(struct sq_req *req, uint32_t consumed);
typedef int (*sq_zcrx_publish_t)(void *, const struct sq_zcrx_reg *);
int	sq_zcrx_register_nodev(struct squeue_ctx *ctx, struct sq_zcrx_reg *reg,
	    struct thread *td, sq_zcrx_publish_t publish, void *cookie);
int	sq_zcrx_refill(struct squeue_ctx *ctx, uint32_t id);
bool	sq_zcrx_exists(struct squeue_ctx *ctx, uint32_t id);
int32_t	sq_zcrx_recv(struct squeue_ctx *ctx, struct sq_req *req,
	    struct thread *td, uint32_t id);

/* Engine KPI: both the native squeue_* syscalls and the Linux front-end. */
int	kern_squeue_setup(struct thread *td, uint32_t entries,
	    struct io_uring_params *params, const struct sq_frontend *fe,
	    int *fdp);
void	kern_squeue_setup_abort(struct thread *td, int value, uint32_t flags);
int	kern_squeue_enter(struct thread *td, int fd, uint32_t to_submit,
	    uint32_t min_complete, uint32_t flags, const void *arg, size_t argsz);
/* copy_sigset translates the calling ABI; NULL selects native sigset_t. */
int	kern_squeue_enter_sigmask(struct thread *td, int fd, uint32_t to_submit,
	    uint32_t min_complete, uint32_t flags, const void *arg,
	    size_t argsz, int (*copy_sigset)(const void *, size_t, sigset_t *));
int	kern_squeue_register(struct thread *td, int fd, uint32_t op,
	    void *arg, uint32_t nr_args);
int	kern_squeue_bpf_task_register(struct sq_bpf_set **setp, void *arg,
	    uint32_t nr_args);
struct sq_bpf_set *kern_squeue_bpf_task_clone(const struct sq_bpf_set *source);
void	kern_squeue_bpf_task_free(struct sq_bpf_set *set);
int	kern_squeue_bpf_task_attach(struct thread *td, int fd,
	    const struct sq_bpf_set *set);
int	sq_install_registered_fd(struct squeue_ctx *ctx, struct thread *td,
	    int index, int *fdp);
int	sq_install_held_fd(struct sq_req *req, struct thread *td, int *fdp);
int	sq_install_direct_fd(struct squeue_ctx *ctx, struct thread *td, int fd,
	    uint32_t file_index, int32_t *resultp);
int	sq_install_direct_fds(struct squeue_ctx *ctx, struct thread *td,
	    int fds[2], uint32_t file_index, uint64_t result_uptr);

#endif /* _KERNEL */
#endif /* _SYS_SQUEUE_H_ */
