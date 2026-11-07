/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Shared harness of the DescriptorQueue tests; see dq_test.h.
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dq_test.h"

#define	DQT_READ_BUFSIZE	65536
#define	DQT_POLL_MS		50

/*
 * Queue and controller threads
 */

int
dqt_open_queue(void)
{
	int q;

	q = dq_open();
	if (q == -1) {
		if (errno == ENOENT)
			atf_tc_skip("%s: %s", DQ_DEVICE, strerror(errno));
		atf_tc_fail("%s: %s", DQ_DEVICE, strerror(errno));
	}
	return (q);
}

static void
dqt_record_seq(struct dqt_ctl *c, uint64_t seq)
{

	if (c->nseqs < DQT_MAX_SEQS)
		c->seqs[c->nseqs++] = seq;
	/* Online gap counting is only meaningful with one reader. */
	if (c->nthr == 1 && c->last_seq != 0 && seq != c->last_seq + 1)
		c->gaps++;
	if (seq > c->last_seq)
		c->last_seq = seq;
}

struct dqt_pending_reply {
	uint64_t	 id;
	int		 error;
	const void	*data;
	size_t		 len;
};

/* Decide one record under the mutex; the reply itself is made later. */
static bool
dqt_handle_record(struct dqt_ctl *c, const struct dq_event *ev,
    struct dqt_pending_reply *pr)
{
	const struct dq_read_body *rb;
	const struct dq_interrupt_body *ib;
	struct dqt_object *o;
	size_t bodylen;
	const void *body;

	body = dq_event_body(ev, &bodylen);
	c->records++;
	if (ev->de_op <= DQ_OP_REPLY)
		c->events[ev->de_op]++;
	dqt_record_seq(c, ev->de_seq);
	c->last_caller = ev->de_caller;
	o = dqt_object_by_id(c, ev->de_object);

	switch (ev->de_op) {
	case DQ_OP_READ:
		if (o != NULL)
			o->reads++;
		if (bodylen < sizeof(*rb))
			return (false);
		rb = body;
		if (c->nrd < DQT_MAX_SEQS) {
			c->rd[c->nrd].object = ev->de_object;
			c->rd[c->nrd].offset = rb->dr_offset;
			c->rd[c->nrd].len = rb->dr_len;
			c->nrd++;
		}
		if (c->hold_replies) {
			if (c->nheld < DQT_MAX_HELD) {
				c->held[c->nheld].id = ev->de_id;
				c->held[c->nheld].object = ev->de_object;
				c->held[c->nheld].op = ev->de_op;
				c->held[c->nheld].len = rb->dr_len;
				c->held[c->nheld].offset = rb->dr_offset;
				c->nheld++;
			}
			return (false);
		}
		pr->id = ev->de_id;
		if (o == NULL) {
			pr->error = EIO;
			pr->len = 0;
		} else if (o->read_errno != 0) {
			pr->error = o->read_errno;
			pr->len = 0;
		} else {
			pr->error = 0;
			/* A short answer is the end of the file. */
			if (rb->dr_offset >= o->len)
				pr->len = 0;
			else
				pr->len = MIN((size_t)rb->dr_len,
				    o->len - (size_t)rb->dr_offset);
			pr->data = o->data + rb->dr_offset;
		}
		return (true);
	case DQ_OP_GETATTR:
		if (o != NULL)
			o->getattrs++;
		if (c->hold_replies) {
			if (c->nheld < DQT_MAX_HELD) {
				c->held[c->nheld].id = ev->de_id;
				c->held[c->nheld].object = ev->de_object;
				c->held[c->nheld].op = ev->de_op;
				c->held[c->nheld].len = 0;
				c->held[c->nheld].offset = 0;
				c->nheld++;
			}
			return (false);
		}
		pr->id = ev->de_id;
		if (o == NULL) {
			pr->error = EIO;
			pr->len = 0;
		} else {
			pr->error = 0;
			pr->data = &o->ident;
			pr->len = sizeof(o->ident);
		}
		return (true);
	case DQ_OP_CLOSE:
		if (o != NULL)
			o->closes++;
		return (false);
	case DQ_OP_INTERRUPT:
		if (bodylen >= sizeof(*ib)) {
			ib = body;
			if (c->ninterrupted < DQT_MAX_INTERRUPTS)
				c->interrupted[c->ninterrupted++] = ib->din_id;
		}
		return (false);
	default:
		return (false);
	}
}

static void
dqt_process_batch(struct dqt_ctl *c, const char *buf, size_t len)
{
	const struct dq_event *recs[DQT_READ_BUFSIZE / sizeof(struct dq_event)];
	struct dqt_pending_reply replies[nitems(recs)];
	const struct dq_event *ev;
	int i, n, nreplies, step, start;

	n = 0;
	for (ev = dq_event_first(buf, len); ev != NULL;
	    ev = dq_event_next(buf, len, ev)) {
		if ((size_t)n < nitems(recs))
			recs[n++] = ev;
	}

	pthread_mutex_lock(&c->mtx);
	c->reads++;
	if (c->paused)
		c->paused_reads++;
	nreplies = 0;
	/* Reverse the batch when asked: the replies land last first. */
	if (c->order == DQT_ORDER_REVERSE) {
		start = n - 1;
		step = -1;
	} else {
		start = 0;
		step = 1;
	}
	for (i = start; i >= 0 && i < n; i += step) {
		if (dqt_handle_record(c, recs[i], &replies[nreplies]))
			nreplies++;
	}
	pthread_mutex_unlock(&c->mtx);

	if (nreplies == 0)
		return;
	if (c->reply_delay_ms > 0)
		dqt_msleep(c->reply_delay_ms);
	for (i = 0; i < nreplies; i++) {
		if (dq_reply(c->q, replies[i].id, replies[i].error,
		    replies[i].data, replies[i].len) == -1) {
			pthread_mutex_lock(&c->mtx);
			c->reply_failures++;
			c->last_reply_errno = errno;
			pthread_mutex_unlock(&c->mtx);
		}
	}
}

static void *
dqt_reader(void *arg)
{
	struct dqt_ctl *c = arg;
	struct pollfd pfd;
	struct timespec ts;
	char *buf;
	ssize_t got;
	int q;

	buf = malloc(DQT_READ_BUFSIZE);
	if (buf == NULL)
		return (NULL);
	for (;;) {
		pthread_mutex_lock(&c->mtx);
		while (c->paused && !c->stop) {
			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_nsec += DQT_POLL_MS * 1000000L;
			if (ts.tv_nsec >= 1000000000L) {
				ts.tv_sec++;
				ts.tv_nsec -= 1000000000L;
			}
			pthread_cond_timedwait(&c->cv, &c->mtx, &ts);
		}
		q = c->q;
		if (c->stop || q == -1) {
			pthread_mutex_unlock(&c->mtx);
			break;
		}
		pthread_mutex_unlock(&c->mtx);

		pfd.fd = q;
		pfd.events = POLLIN;
		pfd.revents = 0;
		if (poll(&pfd, 1, DQT_POLL_MS) <= 0)
			continue;
		if ((pfd.revents & (POLLIN | POLLHUP)) == 0)
			continue;
		/*
		 * A pause set while this thread was in poll: go back and park
		 * rather than read what a test wants left on the queue.
		 */
		pthread_mutex_lock(&c->mtx);
		if (c->paused) {
			pthread_mutex_unlock(&c->mtx);
			continue;
		}
		pthread_mutex_unlock(&c->mtx);
		/*
		 * The queue is non-blocking: with two readers both wake on
		 * poll and the loser must not sleep in read(2) forever.
		 */
		if (dq_read_events(q, buf, DQT_READ_BUFSIZE, &got) == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			break;	/* ENXIO: the queue is gone */
		}
		dqt_process_batch(c, buf, (size_t)got);
	}
	free(buf);
	return (NULL);
}

void
dqt_init_manual(struct dqt_ctl *c)
{
	int i;

	memset(c, 0, sizeof(*c));
	c->q = dqt_open_queue();
	ATF_REQUIRE_EQ(0, pthread_mutex_init(&c->mtx, NULL));
	ATF_REQUIRE_EQ(0, pthread_cond_init(&c->cv, NULL));
	for (i = 0; i < DQT_MAX_OBJECTS; i++)
		c->objs[i].fd = -1;
}

void
dqt_start(struct dqt_ctl *c, int nreaders)
{
	int flags, i;

	ATF_REQUIRE(nreaders >= 1 && nreaders <= DQT_READERS_MAX);
	flags = fcntl(c->q, F_GETFL);
	ATF_REQUIRE(flags != -1);
	ATF_REQUIRE_EQ(0, fcntl(c->q, F_SETFL, flags | O_NONBLOCK));
	c->nthr = nreaders;
	for (i = 0; i < nreaders; i++)
		ATF_REQUIRE_EQ(0, pthread_create(&c->thr[i], NULL, dqt_reader,
		    c));
}

void
dqt_init(struct dqt_ctl *c)
{

	dqt_init_manual(c);
	dqt_start(c, 1);
}

void
dqt_stop(struct dqt_ctl *c)
{
	int i;

	pthread_mutex_lock(&c->mtx);
	c->stop = true;
	pthread_cond_broadcast(&c->cv);
	pthread_mutex_unlock(&c->mtx);
	for (i = 0; i < c->nthr; i++)
		(void)pthread_join(c->thr[i], NULL);
	c->nthr = 0;
}

void
dqt_close_queue(struct dqt_ctl *c)
{

	dqt_stop(c);
	if (c->q != -1) {
		(void)close(c->q);
		c->q = -1;
	}
}

void
dqt_fini(struct dqt_ctl *c)
{
	int i;

	dqt_stop(c);
	for (i = 0; i < c->nobjs; i++) {
		if (c->objs[i].fd != -1) {
			(void)close(c->objs[i].fd);
			c->objs[i].fd = -1;
		}
	}
	if (c->q != -1) {
		(void)close(c->q);
		c->q = -1;
	}
	pthread_cond_destroy(&c->cv);
	pthread_mutex_destroy(&c->mtx);
}

void
dqt_pause(struct dqt_ctl *c)
{

	pthread_mutex_lock(&c->mtx);
	c->paused = true;
	pthread_mutex_unlock(&c->mtx);
	/* A reader already past the check finishes its current batch. */
	dqt_msleep(2 * DQT_POLL_MS);
}

void
dqt_resume(struct dqt_ctl *c)
{

	pthread_mutex_lock(&c->mtx);
	c->paused = false;
	pthread_cond_broadcast(&c->cv);
	pthread_mutex_unlock(&c->mtx);
}

void
dqt_hold(struct dqt_ctl *c, bool hold)
{

	pthread_mutex_lock(&c->mtx);
	c->hold_replies = hold;
	pthread_mutex_unlock(&c->mtx);
}

/*
 * Oracle and objects
 */

void
dqt_fill(unsigned char *buf, size_t len, unsigned seed)
{
	size_t i;
	uint32_t x;

	/* A small LCG: deterministic, no two objects alike. */
	x = seed * 2654435761u + 1;
	for (i = 0; i < len; i++) {
		x = x * 1103515245u + 12345u;
		buf[i] = (unsigned char)(x >> 16);
	}
}

int
dqt_make_oracle(const char *name, const void *data, size_t len, char *path,
    size_t pathlen)
{
	const char *p;
	ssize_t n;
	size_t off;
	int fd;

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE_MSG(fd != -1, "open %s: %s", name, strerror(errno));
	p = data;
	for (off = 0; off < len; off += (size_t)n) {
		n = write(fd, p + off, len - off);
		ATF_REQUIRE_MSG(n > 0, "write %s: %s", name, strerror(errno));
	}
	ATF_REQUIRE_EQ(0, fsync(fd));
	ATF_REQUIRE_EQ(0, close(fd));
	/* The presented path must be absolute and normalized. */
	ATF_REQUIRE_MSG(realpath(name, path) != NULL, "realpath %s: %s", name,
	    strerror(errno));
	ATF_REQUIRE(strlen(path) < pathlen);
	/* Read-only, so F_GETFL of the oracle matches the served fd (I13). */
	fd = open(path, O_RDONLY);
	ATF_REQUIRE_MSG(fd != -1, "open %s: %s", path, strerror(errno));
	return (fd);
}

void
dqt_ident_of(int fd, const char *path, struct dq_ident_file *ident,
    struct stat *st, struct statfs *sfs)
{

	ATF_REQUIRE_EQ(0, fstat(fd, st));
	ATF_REQUIRE_EQ(0, fstatfs(fd, sfs));
	ATF_REQUIRE_MSG(dq_ident_from_stat(ident, path, st, sfs, fd) == 0,
	    "dq_ident_from_stat: %s", strerror(errno));
}

struct dqt_object *
dqt_mint_ident(struct dqt_ctl *c, const struct dq_ident_file *ident,
    const struct dq_policy *pol, const void *data, size_t len)
{
	struct dqt_object *o;
	int reason;

	ATF_REQUIRE(c->nobjs < DQT_MAX_OBJECTS);
	o = &c->objs[c->nobjs];
	memset(o, 0, sizeof(*o));
	o->ident = *ident;
	o->data = data;
	o->len = len;
	reason = DQ_REASON_NONE;
	ATF_REQUIRE_MSG(dq_mint_file(c->q, ident, pol, &o->id, &o->fd,
	    &reason) == 0, "dq_mint_file: %s (reason %d)", strerror(errno),
	    reason);
	ATF_REQUIRE(o->fd >= 0);
	ATF_REQUIRE(o->id != 0);
	pthread_mutex_lock(&c->mtx);
	c->nobjs++;
	pthread_mutex_unlock(&c->mtx);
	return (o);
}

struct dqt_object *
dqt_mint(struct dqt_ctl *c, int oracle_fd, const char *path, const void *data,
    size_t len, const struct dq_policy *pol)
{
	struct dq_ident_file *ident;
	struct dq_policy defpol;
	struct dqt_object *o;
	struct statfs sfs;
	struct stat st;

	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	dqt_ident_of(oracle_fd, path, ident, &st, &sfs);
	if (pol == NULL) {
		dq_policy_default(&defpol);
		pol = &defpol;
	}
	o = dqt_mint_ident(c, ident, pol, data, len);
	free(ident);
	return (o);
}

struct dqt_object *
dqt_object_by_id(struct dqt_ctl *c, uint64_t id)
{
	int i;

	for (i = 0; i < c->nobjs; i++) {
		if (c->objs[i].id == id)
			return (&c->objs[i]);
	}
	return (NULL);
}

/*
 * Requesters
 */

void
dqt_spawn(struct dqt_child *ch, dqt_child_fn fn, void *arg)
{
	int pfd[2];

	ATF_REQUIRE_EQ(0, pipe(pfd));
	ch->pid = fork();
	ATF_REQUIRE_MSG(ch->pid != -1, "fork: %s", strerror(errno));
	if (ch->pid == 0) {
		char result[4096];

		(void)close(pfd[0]);
		memset(result, 0, sizeof(result));
		fn(arg, result);
		/* The parent reads what it expects; the rest is ignored. */
		(void)write(pfd[1], result, sizeof(result));
		_exit(0);
	}
	(void)close(pfd[1]);
	ch->pipefd = pfd[0];
}

int
dqt_wait(struct dqt_child *ch, void *result, size_t resultlen)
{
	char *p;
	ssize_t n;
	size_t off;
	int status;

	ATF_REQUIRE(resultlen <= 4096);
	p = result;
	for (off = 0; off < resultlen; off += (size_t)n) {
		n = read(ch->pipefd, p + off, resultlen - off);
		if (n <= 0)
			break;
	}
	(void)close(ch->pipefd);
	ch->pipefd = -1;
	ATF_REQUIRE_MSG(waitpid(ch->pid, &status, 0) == ch->pid, "waitpid: %s",
	    strerror(errno));
	return (status);
}

void
dqt_run_child(dqt_child_fn fn, void *arg, void *result, size_t resultlen)
{
	struct dqt_child ch;
	int status;

	dqt_spawn(&ch, fn, arg);
	status = dqt_wait(&ch, result, resultlen);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "requester child failed, status %#x", status);
}

/*
 * Waits and queries
 */

void
dqt_msleep(int ms)
{
	struct timespec ts;

	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (ms % 1000) * 1000000L;
	while (nanosleep(&ts, &ts) == -1 && errno == EINTR)
		continue;
}

static bool
dqt_wait_cond(struct dqt_ctl *c, bool (*cond)(struct dqt_ctl *, uintptr_t,
    uintptr_t), uintptr_t a, uintptr_t b, int ms)
{
	int waited;
	bool ok;

	for (waited = 0;; waited += 10) {
		pthread_mutex_lock(&c->mtx);
		ok = cond(c, a, b);
		pthread_mutex_unlock(&c->mtx);
		if (ok || waited >= ms)
			return (ok);
		dqt_msleep(10);
	}
}

static bool
dqt_cond_events(struct dqt_ctl *c, uintptr_t op, uintptr_t n)
{

	return (c->events[op] >= (unsigned)n);
}

static bool
dqt_cond_held(struct dqt_ctl *c, uintptr_t n, uintptr_t unused __unused)
{

	return (c->nheld >= (int)n);
}

static bool
dqt_cond_interrupts(struct dqt_ctl *c, uintptr_t n, uintptr_t unused __unused)
{

	return (c->ninterrupted >= (int)n);
}

bool
dqt_wait_events(struct dqt_ctl *c, uint32_t op, unsigned n, int ms)
{

	return (dqt_wait_cond(c, dqt_cond_events, op, n, ms));
}

bool
dqt_wait_held(struct dqt_ctl *c, int n, int ms)
{

	return (dqt_wait_cond(c, dqt_cond_held, (uintptr_t)n, 0, ms));
}

bool
dqt_wait_interrupts(struct dqt_ctl *c, int n, int ms)
{

	return (dqt_wait_cond(c, dqt_cond_interrupts, (uintptr_t)n, 0, ms));
}

void
dqt_stats(struct dqt_ctl *c, struct dq_stats *st)
{

	ATF_REQUIRE_MSG(dq_get_stats(c->q, st) == 0, "DQ_IOC_GET_STATS: %s",
	    strerror(errno));
}

bool
dqt_wait_stats(struct dqt_ctl *c, dqt_stats_pred pred, uintptr_t arg, int ms)
{
	struct dq_stats st;
	int waited;

	for (waited = 0;; waited += 10) {
		dqt_stats(c, &st);
		if (pred(&st, arg))
			return (true);
		if (waited >= ms)
			return (false);
		dqt_msleep(10);
	}
}

/* As tests/sys/file/fsetattr_test.c mount_fdesc(), plus one option. */
void
dqt_mount_fdesc(const char *option)
{
	struct iovec iov[6];
	u_int n;

	ATF_REQUIRE_EQ(0, mkdir(DQT_FDESC_DIR, 0755));
	iov[0].iov_base = __DECONST(char *, "fstype");
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = __DECONST(char *, "fdescfs");
	iov[1].iov_len = sizeof("fdescfs");
	iov[2].iov_base = __DECONST(char *, "fspath");
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = __DECONST(char *, DQT_FDESC_DIR);
	iov[3].iov_len = sizeof(DQT_FDESC_DIR);
	n = 4;
	if (option != NULL) {
		/* A flag option: a name with an empty value. */
		iov[4].iov_base = __DECONST(char *, option);
		iov[4].iov_len = strlen(option) + 1;
		iov[5].iov_base = NULL;
		iov[5].iov_len = 0;
		n = 6;
	}
	if (nmount(iov, n, 0) != 0)
		atf_tc_fail("mount fdescfs: %s", strerror(errno));
}

void
dqt_umount_fdesc(void)
{

	(void)unmount(DQT_FDESC_DIR, MNT_FORCE);
}

bool
dqt_sysctl_get_uint(const char *name, u_int *value)
{
	size_t len;

	len = sizeof(*value);
	return (sysctlbyname(name, value, &len, NULL, 0) == 0);
}

void
dqt_sysctl_set_uint(const char *name, u_int value)
{

	ATF_REQUIRE_MSG(sysctlbyname(name, NULL, NULL, &value,
	    sizeof(value)) == 0, "sysctl %s=%u: %s", name, value,
	    strerror(errno));
}

/*
 * Comparisons
 */

#define	DQT_EQ(field)							\
	ATF_CHECK_EQ_MSG((long long)want->field, (long long)served->field,	\
	    "%s: served %lld want %lld", #field, (long long)served->field,	\
	    (long long)want->field)

void
dqt_check_stat_eq(const struct stat *served, const struct stat *want)
{

	DQT_EQ(st_dev);
	DQT_EQ(st_ino);
	DQT_EQ(st_nlink);
	DQT_EQ(st_mode);
	DQT_EQ(st_uid);
	DQT_EQ(st_gid);
	DQT_EQ(st_rdev);
	DQT_EQ(st_atim.tv_sec);
	DQT_EQ(st_atim.tv_nsec);
	DQT_EQ(st_mtim.tv_sec);
	DQT_EQ(st_mtim.tv_nsec);
	DQT_EQ(st_ctim.tv_sec);
	DQT_EQ(st_ctim.tv_nsec);
	DQT_EQ(st_birthtim.tv_sec);
	DQT_EQ(st_birthtim.tv_nsec);
	DQT_EQ(st_size);
	DQT_EQ(st_blocks);
	DQT_EQ(st_blksize);
	DQT_EQ(st_flags);
	DQT_EQ(st_gen);
	DQT_EQ(st_filerev);
	/*
	 * st_bsdflags is not part of the identity: the kernel answers 0
	 * for a served file (dq_ident_to_stat), where a real one carries
	 * SFBSD_MNTPOINT only for a mount point.
	 */
	ATF_CHECK_EQ_MSG(0, served->st_bsdflags, "st_bsdflags: served %#x",
	    served->st_bsdflags);
}

void
dqt_check_statfs_eq(const struct statfs *served, const struct statfs *want)
{

	/* The kernel forces f_version on both sides. */
	ATF_CHECK_EQ(STATFS_VERSION, served->f_version);
	DQT_EQ(f_type);
	DQT_EQ(f_flags);
	DQT_EQ(f_bsize);
	DQT_EQ(f_iosize);
	DQT_EQ(f_blocks);
	DQT_EQ(f_bfree);
	DQT_EQ(f_bavail);
	DQT_EQ(f_files);
	DQT_EQ(f_ffree);
	DQT_EQ(f_syncwrites);
	DQT_EQ(f_asyncwrites);
	DQT_EQ(f_syncreads);
	DQT_EQ(f_asyncreads);
	DQT_EQ(f_nvnodelistsize);
	DQT_EQ(f_namemax);
	DQT_EQ(f_owner);
	DQT_EQ(f_fsid.val[0]);
	DQT_EQ(f_fsid.val[1]);
	ATF_CHECK_STREQ(want->f_fstypename, served->f_fstypename);
	ATF_CHECK_STREQ(want->f_mntfromname, served->f_mntfromname);
	ATF_CHECK_STREQ(want->f_mntonname, served->f_mntonname);
}
