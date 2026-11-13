/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Shared harness of the DescriptorQueue tests.
 *
 * The controller is a thread of the test process serving one or more
 * objects from memory; requesters are forked children (D86: until RESOLVE
 * installs served descriptors the minted fd reaches a requester by
 * inheritance, and the controller's own process is refused with EDEADLK).
 * The queue is O_CLOFORK (dq_open), so a child holds the object and not
 * the queue.  Results travel back over a pipe.  The oracle is a real
 * temporary file holding the same bytes, whose identity the object
 * presents (dq_ident_from_stat); the tests compare the two answers field
 * by field.
 */

#ifndef _DQ_TEST_H_
#define	_DQ_TEST_H_

#include <sys/types.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include <libdq.h>

#define	DQT_MAX_OBJECTS		8
#define	DQT_MAX_SEQS		4096
#define	DQT_MAX_HELD		64
#define	DQT_MAX_INTERRUPTS	64
#define	DQT_MAX_LOCKS		32
#define	DQT_MAX_IOCTL_IN	64
#define	DQT_MAX_RESOLVES	1024
#define	DQT_RPATH		128
#define	DQT_READERS_MAX		2
#define	DQT_PATH_MAX		1024

/* Default wait for a controller-side condition, in milliseconds. */
#define	DQT_WAIT_MS		5000

/*
 * An object is served from memory (data, len: READ and GETATTR answered by
 * the harness, every other event answered with serve_errno or EIO, locks
 * with ENOLCK) or from a backing file (backing != -1: every event goes to
 * dq_serve_file() with the object's lock state and identity copy).
 */
struct dqt_object {
	uint64_t	 id;
	int		 fd;		/* in the controller process */
	const unsigned char *data;	/* the bytes served */
	size_t		 len;
	struct dq_ident_file ident;	/* the GETATTR answer / serve copy */
	int		 read_errno;	/* 0: serve bytes; else this errno */
	int		 serve_errno;	/* != 0: answer every 1b event with it */
	int		 backing;	/* -1, or the file dq_serve_file serves */
	struct dq_serve_state *lockstate;	/* the queue's (dqt_ctl), shared */
	struct dq_serve_opts sopts;
	unsigned	 reads;		/* READ events seen */
	unsigned	 getattrs;	/* GETATTR events seen */
	unsigned	 closes;	/* CLOSE records seen */
	unsigned	 served;	/* records handed to dq_serve_file */
	unsigned	 serve_failures;	/* dq_serve_file returned -1 */
	/* The last body of each kind, for field assertions. */
	struct dq_write_body last_write;
	struct dq_setattr_body last_setattr;
	struct dq_fsync_body last_fsync;
	struct dq_fallocate_body last_fallocate;
	struct dq_fspacectl_body last_fspacectl;
	struct dq_ioctl_body last_ioctl;
	unsigned char	 last_ioctl_in[DQT_MAX_IOCTL_IN];
	/* Every LOCK and UNLOCK_ALL body, in delivery order. */
	struct dq_lock_body locks[DQT_MAX_LOCKS];
	int		 nlocks;
	struct dq_unlock_all_body unlocks[DQT_MAX_LOCKS];
	int		 nunlocks;
};

/* An event the controller read but was told not to answer. */
struct dqt_held {
	uint64_t	 id;
	uint64_t	 object;
	uint32_t	 op;
	uint32_t	 len;		/* READ: dr_len */
	uint64_t	 offset;	/* READ: dr_offset */
};

enum dqt_order {
	DQT_ORDER_FIFO,			/* answer a batch in delivery order */
	DQT_ORDER_REVERSE,		/* answer a batch last first */
};

struct dqt_ctl {
	int		 q;		/* the queue, -1 once closed */
	pthread_t	 thr[DQT_READERS_MAX];
	int		 nthr;
	pthread_mutex_t	 mtx;
	pthread_cond_t	 cv;
	bool		 stop;
	bool		 paused;	/* do not read the queue */
	bool		 hold_replies;	/* read, record, do not answer */
	int		 reply_delay_ms;
	enum dqt_order	 order;
	struct dqt_object objs[DQT_MAX_OBJECTS];
	int		 nobjs;

	/* What the controller saw, under mtx. */
	unsigned	 events[DQ_OP_REPLY + 1];
	unsigned	 records;
	unsigned	 reads;		/* successful read(2) calls */
	unsigned	 paused_reads;	/* batches read while paused (none expected) */
	uint64_t	 seqs[DQT_MAX_SEQS];
	int		 nseqs;
	uint64_t	 last_seq;
	unsigned	 gaps;		/* de_seq jumps (drops) */
	unsigned	 reply_failures;
	int		 last_reply_errno;
	struct dq_caller last_caller;
	struct dqt_held	 held[DQT_MAX_HELD];
	int		 nheld;
	/* Every READ body seen, in delivery order. */
	struct dqt_read_seen {
		uint64_t	 object;
		uint64_t	 offset;
		uint32_t	 len;
	}		 rd[DQT_MAX_SEQS];
	int		 nrd;
	/* Every WRITE body seen (offset, length, flags), in delivery order. */
	struct dqt_write_seen {
		uint64_t	 object;
		uint64_t	 offset;
		uint32_t	 len;
		uint32_t	 flags;
	}		 wr[DQT_MAX_SEQS];
	int		 nwr;
	uint64_t	 interrupted[DQT_MAX_INTERRUPTS];
	/* Per operation: the sequence and caller of the last record. */
	uint64_t	 op_seq[DQ_OP_REPLY + 1];
	struct dq_caller op_caller[DQ_OP_REPLY + 1];
	/*
	 * RESOLVE (1c): every event recorded; answered PASS unless its path
	 * contains resolve_fail_match (then resolve_fail_errno) or
	 * resolve_hold_match or its op is resolve_hold_op (then held, see
	 * dqt_held), or its op has an errno in resolve_errno[].
	 */
	struct dqt_resolve_seen {
		uint64_t	 id;
		uint32_t	 op, cls, rflags, mode, syscall, caller_flags;
		uint32_t	 start_kind, start2_kind, accept, cmode;
		int32_t		 pid;
		int32_t		 domain, type, protocol;	/* sockets */
		uint32_t	 pathlen;	/* exact: abstract names */
		char		 path[DQT_RPATH], path2[DQT_RPATH];
		char		 startpath2[DQT_RPATH];
	}		 rs[DQT_MAX_RESOLVES];
	int		 nrs;
	int		 resolve_errno[DQ_ROP_MAX + 1];
	char		 resolve_fail_match[DQT_RPATH];
	int		 resolve_fail_errno;
	char		 resolve_hold_match[DQT_RPATH];
	uint32_t	 resolve_hold_op;	/* 0: none */
	/* dq_serve_file lock owners: one table per queue (POSIX owners span
	   the objects of one identity), made at the first backing mint. */
	struct dq_serve_state *lockstate;
	int		 ninterrupted;
};

/*
 * Fail (not skip) unless the capability plane is on (PID 1 is capsule) and
 * the queue device exists: a case that pins what a supervisor's exit or an
 * attachment does must not pass in a guest that tested nothing.
 */
void	dqt_require_plane(void);
/*
 * Fail on a test kernel (options DQ_TEST_OPEN) that was booted without
 * debug.dq.unverified_open="1"; a kernel without the option passes.
 */
void	dqt_require_test_access(void);
/* Fails, never skips, when the queue device is absent or refuses. */
int	dqt_open_queue(void);
void	dqt_init(struct dqt_ctl *c);		/* queue + 1 reader thread */
void	dqt_init_manual(struct dqt_ctl *c);	/* queue, no reader thread */
void	dqt_start(struct dqt_ctl *c, int nreaders);
void	dqt_stop(struct dqt_ctl *c);		/* join the readers */
void	dqt_close_queue(struct dqt_ctl *c);	/* readers stopped, queue closed */
void	dqt_fini(struct dqt_ctl *c);		/* everything */

void	dqt_pause(struct dqt_ctl *c);
void	dqt_resume(struct dqt_ctl *c);
void	dqt_hold(struct dqt_ctl *c, bool hold);

/* The oracle: a real file of these bytes in the test's work directory. */
int	dqt_make_oracle(const char *name, const void *data, size_t len,
	    char *path, size_t pathlen);
void	dqt_ident_of(int fd, const char *path, struct dq_ident_file *ident,
	    struct stat *st, struct statfs *sfs);
void	dqt_fill(unsigned char *buf, size_t len, unsigned seed);

/* Mint an object presenting the oracle's identity and serving data. */
struct dqt_object *dqt_mint(struct dqt_ctl *c, int oracle_fd,
	    const char *path, const void *data, size_t len,
	    const struct dq_policy *pol);
struct dqt_object *dqt_mint_ident(struct dqt_ctl *c,
	    const struct dq_ident_file *ident, const struct dq_policy *pol,
	    const void *data, size_t len);
struct dqt_object *dqt_mint_ident_flags(struct dqt_ctl *c,
	    const struct dq_ident_file *ident, const struct dq_policy *pol,
	    uint32_t mflags, const void *data, size_t len);
/*
 * Mint an object served from a backing file through dq_serve_file(): the
 * identity is the backing file's at path, pol NULL is the write-serving
 * policy (dp_write = DQ_EVENT) and mflags DQ_MINT_F_WRITE makes the
 * descriptor writable.  The object owns a lock state; dqt_fini destroys it.
 */
struct dqt_object *dqt_mint_backing(struct dqt_ctl *c, int backing_fd,
	    const char *path, const struct dq_policy *pol, uint32_t mflags);
/* dq_policy_default() with dp_write = DQ_EVENT. */
void	dqt_policy_write(struct dq_policy *pol);
struct dqt_object *dqt_object_by_id(struct dqt_ctl *c, uint64_t id);

/*
 * Requesters.  fn runs in a forked child and fills result (resultlen
 * bytes), which the parent receives over a pipe.  dqt_run_child does the
 * whole round trip and requires a clean exit; the spawn/wait pair lets a
 * test run several children at once or signal one.
 */
typedef void (*dqt_child_fn)(void *arg, void *result);
struct dqt_child {
	pid_t		 pid;
	int		 pipefd;
};
void	dqt_spawn(struct dqt_child *ch, dqt_child_fn fn, void *arg);
int	dqt_wait(struct dqt_child *ch, void *result, size_t resultlen);
void	dqt_run_child(dqt_child_fn fn, void *arg, void *result,
	    size_t resultlen);

/* A system call result: return value and errno. */
struct dqt_rr {
	long		 rv;
	int		 err;
};

/* Controller-side waits and queries. */
bool	dqt_wait_events(struct dqt_ctl *c, uint32_t op, unsigned n, int ms);
bool	dqt_wait_held(struct dqt_ctl *c, int n, int ms);
bool	dqt_wait_interrupts(struct dqt_ctl *c, int n, int ms);
/* Wait until the object has seen n LOCK bodies. */
bool	dqt_wait_locks(struct dqt_ctl *c, struct dqt_object *o, int n, int ms);
void	dqt_stats(struct dqt_ctl *c, struct dq_stats *st);
void	dqt_stats2(struct dqt_ctl *c, struct dq_stats2 *st);
void	dqt_msleep(int ms);
/* Poll the queue's statistics until pred(st, arg) holds or ms elapse. */
typedef bool (*dqt_stats_pred)(const struct dq_stats *st, uintptr_t arg);
bool	dqt_wait_stats(struct dqt_ctl *c, dqt_stats_pred pred, uintptr_t arg,
	    int ms);

/*
 * A private fdescfs instance at DQT_FDESC_DIR in the test's work directory
 * (as tests/sys/file/fsetattr_test.c mounts one): the guest may not mount
 * fdescfs on /dev/fd.  option is an extra mount option ("rdlnk") or NULL;
 * the test's ATF cleanup calls dqt_umount_fdesc.
 */
#define	DQT_FDESC_DIR		"fdesc"
void	dqt_mount_fdesc(const char *option);
void	dqt_umount_fdesc(void);
bool	dqt_sysctl_get_uint(const char *name, u_int *value);
void	dqt_sysctl_set_uint(const char *name, u_int value);

/* Field-by-field oracle comparisons (ATF_CHECK_EQ_MSG per field). */
void	dqt_check_stat_eq(const struct stat *served, const struct stat *want);
void	dqt_check_statfs_eq(const struct statfs *served,
	    const struct statfs *want);


/*
 * Pages.  dqt_touch reads (or writes wval, then reads) one byte of a
 * mapping and returns 0, or the signal (SIGBUS, SIGSEGV) the access
 * raised; for single-threaded requesters only.  dqt_sync is a pair of
 * pipes for lock-step between the test and one requester: the child posts
 * on toparent[1] and waits on tochild[0], the test the reverse.
 */
int	dqt_touch(volatile unsigned char *p, bool write, unsigned char wval,
	    unsigned char *val);
struct dqt_sync {
	int		 tochild[2];
	int		 toparent[2];
};
void	dqt_sync_init(struct dqt_sync *s);
void	dqt_sync_post(int fd);
bool	dqt_sync_wait(int fd, int ms);


/*
 * Resolution (1c).  dqt_attach_spawn pdforks a requester, attaches it to
 * the controller's queue before it runs fn (a child that has not exec'd,
 * holding no queue descriptor: dq_open is O_CLOFORK), and returns its
 * process descriptor; dqt_attach_wait collects the result and the exit
 * status.  dqt_find_resolve returns the index (from `from`) of the first
 * recorded RESOLVE whose path or second path contains match, of op (0:
 * any), or -1; dqt_count_resolve counts them.
 */
struct dqt_achild {
	pid_t		 pid;
	int		 pd;
	int		 pipefd;
};
void	dqt_attach_spawn(struct dqt_ctl *c, struct dqt_achild *ch,
	    dqt_child_fn fn, void *arg);
int	dqt_attach_wait(struct dqt_achild *ch, void *result, size_t resultlen);
int	dqt_find_resolve(struct dqt_ctl *c, const char *match, uint32_t op,
	    int from);
int	dqt_count_resolve(struct dqt_ctl *c, const char *match, uint32_t op);

#endif /* !_DQ_TEST_H_ */
