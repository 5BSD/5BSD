/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Mappings of a served file (D102, D103): the dq pager fills faulting pages
 * with READ events (page-aligned offsets, the run clipped at the presented
 * size and max_io, a short reply zero-filling to the end of the page),
 * writes dirty pages of shared writable mappings back with WRITE_ASYNC
 * (msync, fsync, the page daemon, the last unmap and close), and answers
 * SIGBUS where a vnode would and where the controller fails.  Requesters
 * are forked children (the controller must never touch its own served
 * mappings: a fault there waits for itself until the deadline, declared);
 * the oracle is a real file of the same bytes mapped the same way.
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <libutil.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

#define	NPAGES		3
#define	TAIL		100
#define	DATA_LEN	(NPAGES * 4096 + TAIL)
#define	MAPLEN		((NPAGES + 1) * 4096)

static unsigned char data[DATA_LEN];
static char backing_path[DQT_PATH_MAX];
static char oracle_path[DQT_PATH_MAX];

struct fixture {
	struct dqt_ctl	 c;
	struct dqt_object *o;
	int		 backing;	/* O_RDWR, served through dq_serve_file */
	int		 oracle;	/* the same bytes, O_RDWR */
};

static int
open_rw(const char *name, char *path)
{
	int fd;

	fd = dqt_make_oracle(name, data, sizeof(data), path, DQT_PATH_MAX);
	(void)close(fd);
	fd = open(path, O_RDWR);
	ATF_REQUIRE_MSG(fd != -1, "open %s: %s", path, strerror(errno));
	return (fd);
}

/* A writable object that allows shared writable mappings. */
static void
policy_shared(struct dq_policy *pol, uint32_t events, int deadline_ms)
{

	dqt_policy_write(pol);
	pol->dp_mmap_shared_write = DQ_ALLOW;
	pol->dp_events = events;
	pol->dp_deadline_ms = deadline_ms;
}

static void
setup_pol(struct fixture *f, unsigned seed, const struct dq_policy *pol,
    uint32_t mflags)
{

	ATF_REQUIRE_EQ(4096, getpagesize());
	dqt_fill(data, sizeof(data), seed);
	f->backing = open_rw("backing", backing_path);
	f->oracle = open_rw("oracle", oracle_path);
	dqt_init(&f->c);
	f->o = dqt_mint_backing(&f->c, f->backing, backing_path, pol, mflags);
}

static void
setup(struct fixture *f, unsigned seed)
{
	struct dq_policy pol;

	policy_shared(&pol, 0, DQ_DEADLINE_DEFAULT);
	setup_pol(f, seed, &pol, DQ_MINT_F_WRITE);
}

static void
teardown(struct fixture *f)
{

	dqt_fini(&f->c);
	(void)close(f->backing);
	(void)close(f->oracle);
}

/* Every READ the pager posted is page-aligned and within the size. */
static void
check_fault_reads(struct dqt_ctl *c, uint64_t size)
{
	int i;

	pthread_mutex_lock(&c->mtx);
	for (i = 0; i < c->nrd; i++) {
		ATF_CHECK_EQ_MSG(0, c->rd[i].offset % 4096, "READ at %ju",
		    (uintmax_t)c->rd[i].offset);
		ATF_CHECK_MSG(c->rd[i].offset + c->rd[i].len <= roundup2(size,
		    4096), "READ [%ju, +%u) past the last page",
		    (uintmax_t)c->rd[i].offset, c->rd[i].len);
	}
	pthread_mutex_unlock(&c->mtx);
}

struct map_arg {
	int		 sfd, ofd;
	int		 flags;
	int		 prot;
};

struct map_res {
	int		 serr, oerr;		/* mmap errnos */
	int		 same;			/* bytes equal over the map */
	int		 sig;			/* a signal touching it */
	unsigned char	 tail_s, tail_o;	/* a byte past EOF in the page */
};

static void
child_map_compare(void *arg, void *result)
{
	struct map_arg *a = arg;
	struct map_res *r = result;
	unsigned char *s, *o;
	size_t i;

	s = mmap(NULL, DATA_LEN, a->prot, a->flags, a->sfd, 0);
	r->serr = s == MAP_FAILED ? errno : 0;
	o = mmap(NULL, DATA_LEN, a->prot, a->flags, a->ofd, 0);
	r->oerr = o == MAP_FAILED ? errno : 0;
	if (s == MAP_FAILED || o == MAP_FAILED)
		return;
	r->same = 1;
	for (i = 0; i < DATA_LEN; i += 512) {
		unsigned char v;

		r->sig = dqt_touch(s + i, false, 0, &v);
		if (r->sig != 0) {
			r->same = 0;
			return;
		}
		if (v != o[i])
			r->same = 0;
	}
	if (memcmp(s, o, DATA_LEN) != 0)
		r->same = 0;
	/* The rest of the last page reads as zeros on both. */
	r->tail_s = s[DATA_LEN + 10];
	r->tail_o = o[DATA_LEN + 10];
}

ATF_TC(read_oracle);
ATF_TC_HEAD(read_oracle, tc)
{
	atf_tc_set_md_var(tc, "descr", "MAP_PRIVATE and MAP_SHARED read "
	    "mappings hold the real file's bytes, zeros past EOF in the last "
	    "page; every fault READ is page-aligned and within the last page");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(read_oracle, tc)
{
	struct fixture f;
	struct map_arg a;
	struct map_res r;
	int k;

	setup(&f, 1);
	for (k = 0; k < 2; k++) {
		a.sfd = f.o->fd;
		a.ofd = f.oracle;
		a.prot = PROT_READ;
		a.flags = k == 0 ? MAP_PRIVATE : MAP_SHARED;
		memset(&r, 0, sizeof(r));
		dqt_run_child(child_map_compare, &a, &r, sizeof(r));
		ATF_CHECK_EQ(r.oerr, r.serr);
		ATF_CHECK_EQ_MSG(0, r.sig, "signal %d", r.sig);
		ATF_CHECK_MSG(r.same, "flags %#x: bytes differ", a.flags);
		ATF_CHECK_EQ(0, r.tail_s);
		ATF_CHECK_EQ(r.tail_o, r.tail_s);
	}
	dqt_lock(&f.c);
	ATF_CHECK(f.c.events[DQ_OP_READ] >= 1);
	dqt_unlock(&f.c);
	check_fault_reads(&f.c, DATA_LEN);
	teardown(&f);
}

struct prot_res {
	int		 e[4];
};

static void
child_shared_write(void *arg, void *result)
{
	int *fds = arg;
	struct prot_res *r = result;
	void *p;
	int i;

	for (i = 0; i < 4; i++) {
		if (fds[i] == -1)
			continue;
		p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fds[i],
		    0);
		r->e[i] = p == MAP_FAILED ? errno : 0;
		if (p != MAP_FAILED)
			(void)munmap(p, 4096);
	}
}

ATF_TC(shared_write_rules);
ATF_TC_HEAD(shared_write_rules, tc)
{
	atf_tc_set_md_var(tc, "descr", "a shared PROT_WRITE mapping needs "
	    "DQ_MINT_F_WRITE and dp_mmap_shared_write = ALLOW: EACCES for a "
	    "read-only object (as for a read-only real file) and for a "
	    "writable one under DENY");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(shared_write_rules, tc)
{
	struct fixture f;
	struct dqt_object *ro, *deny;
	struct dq_policy pol;
	struct prot_res r;
	int fds[4], oro;

	setup(&f, 2);
	dq_policy_default(&pol);
	ro = dqt_mint_backing(&f.c, f.backing, backing_path, &pol, 0);
	dqt_policy_write(&pol);
	deny = dqt_mint_backing(&f.c, f.backing, backing_path, &pol,
	    DQ_MINT_F_WRITE);
	oro = open(oracle_path, O_RDONLY);
	ATF_REQUIRE(oro != -1);
	fds[0] = f.o->fd;
	fds[1] = ro->fd;
	fds[2] = deny->fd;
	fds[3] = oro;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_shared_write, fds, &r, sizeof(r));
	ATF_CHECK_EQ(0, r.e[0]);
	ATF_CHECK_EQ(EACCES, r.e[1]);
	ATF_CHECK_EQ(r.e[3], r.e[1]);
	ATF_CHECK_EQ(EACCES, r.e[2]);
	(void)close(oro);
	teardown(&f);
}

struct cow_res {
	int		 sig_cow, sig_new, sig_shared;
	unsigned char	 cow;
};

static void
child_cow_revoke(void *arg, void *result)
{
	struct dqt_sync *s = arg;
	struct cow_res *r = result;
	unsigned char *p, *q;
	int *fdp;

	fdp = (int *)(void *)(s + 1);
	p = mmap(NULL, MAPLEN, PROT_READ | PROT_WRITE, MAP_PRIVATE, *fdp, 0);
	q = mmap(NULL, MAPLEN, PROT_READ, MAP_SHARED, *fdp, 0);
	if (p == MAP_FAILED || q == MAP_FAILED)
		_exit(3);
	/* A private copy of page 0, and page 0 of the shared map resident. */
	(void)dqt_touch(p, true, 0x5a, NULL);
	(void)dqt_touch(q, false, 0, NULL);
	dqt_sync_post(s->toparent[1]);
	(void)dqt_sync_wait(s->tochild[0], DQT_WAIT_MS);
	/* Revoked: the copy is the process's own; the object's pages are gone. */
	r->sig_cow = dqt_touch(p, false, 0, &r->cow);
	r->sig_new = dqt_touch(p + 4096, false, 0, NULL);
	r->sig_shared = dqt_touch(q, false, 0, NULL);
}

ATF_TC(private_cow_and_revoke);
ATF_TC_HEAD(private_cow_and_revoke, tc)
{
	atf_tc_set_md_var(tc, "descr", "after DQ_IOC_REVOKE a private copy "
	    "made by a write survives; a page never faulted in and the shared "
	    "mapping's pages raise SIGBUS");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(private_cow_and_revoke, tc)
{
	struct fixture f;
	struct {
		struct dqt_sync s;
		int fd;
	} a;
	struct dqt_child ch;
	struct cow_res r;

	setup(&f, 3);
	dqt_sync_init(&a.s);
	a.fd = f.o->fd;
	dqt_spawn(&ch, child_cow_revoke, &a);
	ATF_REQUIRE(dqt_sync_wait(a.s.toparent[0], DQT_WAIT_MS));
	ATF_REQUIRE_EQ(0, dq_revoke(f.c.q, f.o->id));
	dqt_sync_post(a.s.tochild[1]);
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(0, r.sig_cow);
	ATF_CHECK_EQ(0x5a, r.cow);
	ATF_CHECK_EQ(SIGBUS, r.sig_new);
	ATF_CHECK_EQ(SIGBUS, r.sig_shared);
	teardown(&f);
}

struct wb_res {
	int		 sig;
	int		 msync_rv, msync_err;
	int		 seen;		/* the backing file had the bytes */
};

struct wb_arg {
	int		 fd, backing;
	int		 do_msync;	/* else munmap + close, no msync */
};

static void
child_shared_writeback(void *arg, void *result)
{
	struct wb_arg *a = arg;
	struct wb_res *r = result;
	unsigned char *p, got[4];

	p = mmap(NULL, DATA_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, a->fd, 0);
	if (p == MAP_FAILED)
		_exit(3);
	r->sig = dqt_touch(p + 5000, true, 0xa1, NULL);
	r->sig |= dqt_touch(p + 5001, true, 0xa2, NULL);
	if (a->do_msync) {
		r->msync_rv = msync(p, DATA_LEN, MS_SYNC);
		r->msync_err = r->msync_rv == -1 ? errno : 0;
		/* MS_SYNC returned after the controller wrote it. */
		if (pread(a->backing, got, 2, 5000) == 2 && got[0] == 0xa1 &&
		    got[1] == 0xa2)
			r->seen = 1;
	}
	(void)munmap(p, DATA_LEN);
	(void)close(a->fd);
}

ATF_TC(msync_writeback);
ATF_TC_HEAD(msync_writeback, tc)
{
	atf_tc_set_md_var(tc, "descr", "a store to a shared writable mapping "
	    "is written back by msync(MS_SYNC) as WRITE_ASYNC (page-aligned, "
	    "dw_flags 0, kernel caller), and msync returns after the "
	    "controller wrote it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(msync_writeback, tc)
{
	struct fixture f;
	struct wb_arg a;
	struct wb_res r;
	int i;

	setup(&f, 4);
	a.fd = f.o->fd;
	a.backing = f.backing;
	a.do_msync = 1;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_shared_writeback, &a, &r, sizeof(r));
	ATF_CHECK_EQ(0, r.sig);
	ATF_CHECK_EQ_MSG(0, r.msync_rv, "msync: %s", strerror(r.msync_err));
	ATF_CHECK(r.seen);
	dqt_lock(&f.c);
	ATF_REQUIRE(f.c.events[DQ_OP_WRITE_ASYNC] >= 1);
	dqt_unlock(&f.c);
	pthread_mutex_lock(&f.c.mtx);
	for (i = 0; i < f.c.nwr; i++) {
		ATF_CHECK_EQ(0, f.c.wr[i].offset % 4096);
		ATF_CHECK_EQ(0, f.c.wr[i].flags);
	}
	ATF_CHECK((f.c.op_caller[DQ_OP_WRITE_ASYNC].dc_flags &
	    DQ_CALLER_F_KERNEL) != 0);
	pthread_mutex_unlock(&f.c.mtx);
	teardown(&f);
}

ATF_TC(msync_refused);
ATF_TC_HEAD(msync_refused, tc)
{
	atf_tc_set_md_var(tc, "descr", "a controller that refuses the "
	    "WRITE_ASYNC makes msync(MS_SYNC) fail with EIO; the page stays "
	    "dirty");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(msync_refused, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_ident_file *id;
	struct dq_policy pol;
	struct wb_arg a;
	struct wb_res r;
	struct statfs sfs;
	struct stat sb;
	int oracle;

	dqt_fill(data, sizeof(data), 5);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	id = calloc(1, sizeof(*id));
	ATF_REQUIRE(id != NULL);
	dqt_ident_of(oracle, oracle_path, id, &sb, &sfs);
	policy_shared(&pol, 0, DQ_DEADLINE_DEFAULT);
	o = dqt_mint_ident_flags(&c, id, &pol, DQ_MINT_F_WRITE, data,
	    sizeof(data));
	free(id);
	o->serve_errno = EIO;	/* every WRITE_ASYNC refused */
	a.fd = o->fd;
	a.backing = oracle;
	a.do_msync = 1;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_shared_writeback, &a, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.msync_rv);
	ATF_CHECK_EQ(EIO, r.msync_err);
	dqt_lock(&c);
	ATF_CHECK(c.events[DQ_OP_WRITE_ASYNC] >= 1);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(munmap_close_writes_back);
ATF_TC_HEAD(munmap_close_writes_back, tc)
{
	atf_tc_set_md_var(tc, "descr", "dirty pages left by munmap and close "
	    "without msync are written back (WRITE_ASYNC) before CLOSE, which "
	    "carries the kernel caller; no data is lost");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(munmap_close_writes_back, tc)
{
	struct fixture f;
	struct dq_policy pol;
	struct dqt_child ch;
	struct wb_arg a;
	struct wb_res r;
	unsigned char got[2];

	policy_shared(&pol, DQ_EVENTS_CLOSE, DQ_DEADLINE_DEFAULT);
	setup_pol(&f, 6, &pol, DQ_MINT_F_WRITE);
	a.fd = f.o->fd;
	a.backing = f.backing;
	a.do_msync = 0;
	dqt_spawn(&ch, child_shared_writeback, &a);
	/* The child holds the only other reference: the last close is its. */
	(void)close(f.o->fd);
	f.o->fd = -1;
	dqt_collect(&ch, &r, sizeof(r));
	ATF_REQUIRE(dqt_wait_events(&f.c, DQ_OP_CLOSE, 1, 4 * DQT_WAIT_MS));
	pthread_mutex_lock(&f.c.mtx);
	ATF_CHECK(f.c.events[DQ_OP_WRITE_ASYNC] >= 1);
	ATF_CHECK_MSG(f.c.op_seq[DQ_OP_WRITE_ASYNC] < f.c.op_seq[DQ_OP_CLOSE],
	    "WRITE_ASYNC seq %ju after CLOSE seq %ju",
	    (uintmax_t)f.c.op_seq[DQ_OP_WRITE_ASYNC],
	    (uintmax_t)f.c.op_seq[DQ_OP_CLOSE]);
	ATF_CHECK((f.c.op_caller[DQ_OP_CLOSE].dc_flags &
	    DQ_CALLER_F_KERNEL) != 0);
	pthread_mutex_unlock(&f.c.mtx);
	ATF_REQUIRE_EQ(2, pread(f.backing, got, 2, 5000));
	ATF_CHECK_EQ(0xa1, got[0]);
	ATF_CHECK_EQ(0xa2, got[1]);
	teardown(&f);
}

struct bus_res {
	int		 sig_err, sig_eof, sig_ok;
};

static void
child_sigbus(void *arg, void *result)
{
	int *fds = arg;
	struct bus_res *r = result;
	unsigned char *p, *q;

	/* fds[0]: an object whose reads fail; fds[1]: a healthy one. */
	p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fds[0], 0);
	q = mmap(NULL, MAPLEN + 4096, PROT_READ, MAP_SHARED, fds[1], 0);
	if (p == MAP_FAILED || q == MAP_FAILED)
		_exit(3);
	r->sig_err = dqt_touch(p, false, 0, NULL);
	r->sig_ok = dqt_touch(q + DATA_LEN - 1, false, 0, NULL);
	/* A whole page past the end of the file, as a vnode answers. */
	r->sig_eof = dqt_touch(q + MAPLEN, false, 0, NULL);
}

ATF_TC(sigbus_cases);
ATF_TC_HEAD(sigbus_cases, tc)
{
	atf_tc_set_md_var(tc, "descr", "SIGBUS for a fault the controller "
	    "answers with an error and for a page wholly past the end of the "
	    "file (as on the real file); the last partial page is readable");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sigbus_cases, tc)
{
	struct fixture f;
	struct dqt_object *bad;
	struct bus_res r;
	int fds[2];

	setup(&f, 7);
	bad = dqt_mint_ident(&f.c, &f.o->ident, NULL, data, sizeof(data));
	bad->read_errno = EIO;
	fds[0] = bad->fd;
	fds[1] = f.o->fd;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_sigbus, fds, &r, sizeof(r));
	ATF_CHECK_EQ(SIGBUS, r.sig_err);
	ATF_CHECK_EQ(0, r.sig_ok);
	ATF_CHECK_EQ(SIGBUS, r.sig_eof);
	teardown(&f);
}

static void
child_touch_page(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct bus_res *r = result;
	unsigned char *p;

	p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		_exit(3);
	r->sig_err = dqt_touch(p, false, 0, NULL);
}

ATF_TC(sigbus_deadline);
ATF_TC_HEAD(sigbus_deadline, tc)
{
	atf_tc_set_md_var(tc, "descr", "a fault whose READ is not answered "
	    "within the object's deadline raises SIGBUS and posts INTERRUPT "
	    "for the delivered READ");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sigbus_deadline, tc)
{
	struct fixture f;
	struct dq_policy pol;
	struct bus_res r;

	policy_shared(&pol, 0, 300);
	setup_pol(&f, 8, &pol, DQ_MINT_F_WRITE);
	dqt_hold(&f.c, true);
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_touch_page, &f.o->fd, &r, sizeof(r));
	ATF_CHECK_EQ(SIGBUS, r.sig_err);
	ATF_CHECK(dqt_wait_interrupts(&f.c, 1, DQT_WAIT_MS));
	dqt_hold(&f.c, false);
	teardown(&f);
}

static volatile sig_atomic_t alarms;

static void
on_alarm(int sig __unused)
{

	alarms++;
}

struct i12_res {
	int		 sig;
	int		 alarms;
	unsigned char	 v;
};

static void
child_fault_signals(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct i12_res *r = result;
	struct sigaction sa;
	unsigned char *p;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_alarm;	/* caught, no SA_RESTART */
	(void)sigaction(SIGALRM, &sa, NULL);
	(void)sigaction(SIGCHLD, &sa, NULL);
	p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		_exit(3);
	/*
	 * Blocks in the fault while the controller holds the READ.  The
	 * handlers cannot run before the fault returns (its wait catches the
	 * first signal, then goes on without catching), so they are counted
	 * afterwards.
	 */
	r->sig = dqt_touch(p + 7, false, 0, &r->v);
	r->alarms = alarms;
}

ATF_TC(fault_survives_signals);
ATF_TC_HEAD(fault_survives_signals, tc)
{
	atf_tc_set_md_var(tc, "descr", "I12: caught signals (SIGALRM, SIGCHLD) "
	    "sent while a fault waits for its READ are no SIGBUS: the fault "
	    "completes with the bytes the controller sends after them, and the "
	    "handlers run once it has");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fault_survives_signals, tc)
{
	struct fixture f;
	struct dqt_child ch;
	struct i12_res r;

	setup(&f, 9);
	dqt_hold(&f.c, true);
	dqt_spawn(&ch, child_fault_signals, &f.o->fd);
	/* The READ was delivered: the child is inside the fault's wait. */
	ATF_REQUIRE(dqt_wait_held(&f.c, 1, DQT_WAIT_MS));
	dqt_lock(&f.c);
	ATF_CHECK_EQ(DQ_OP_READ, f.c.held[0].op);
	ATF_REQUIRE_EQ(0, f.c.held[0].offset);
	dqt_unlock(&f.c);
	ATF_REQUIRE_EQ(0, kill(ch.pid, SIGALRM));
	ATF_REQUIRE_EQ(0, kill(ch.pid, SIGCHLD));
	/* A caught signal must not end the fault: no INTERRUPT. */
	dqt_msleep(200);
	dqt_lock(&f.c);
	ATF_CHECK_EQ(0, f.c.ninterrupted);
	ATF_REQUIRE_EQ(0, dq_reply(f.c.q, f.c.held[0].id, 0, data,
	    MIN(f.c.held[0].len, sizeof(data))));
	dqt_unlock(&f.c);
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(0, r.sig, "signal %d", r.sig);
	ATF_CHECK_MSG(r.alarms >= 1, "handlers ran %d times", r.alarms);
	ATF_CHECK_EQ(data[7], r.v);
	dqt_hold(&f.c, false);
	teardown(&f);
}

struct mincore_res {
	char		 vs[NPAGES + 1], vo[NPAGES + 1];
	int		 es, eo;
};

static void
child_mincore(void *arg, void *result)
{
	int *fds = arg;
	struct mincore_res *r = result;
	unsigned char *s, *o;

	s = mmap(NULL, MAPLEN, PROT_READ, MAP_SHARED, fds[0], 0);
	o = mmap(NULL, MAPLEN, PROT_READ, MAP_SHARED, fds[1], 0);
	if (s == MAP_FAILED || o == MAP_FAILED)
		_exit(3);
	(void)dqt_touch(s, false, 0, NULL);
	(void)dqt_touch(s + 2 * 4096, false, 0, NULL);
	(void)dqt_touch(o, false, 0, NULL);
	(void)dqt_touch(o + 2 * 4096, false, 0, NULL);
	r->es = mincore(s, MAPLEN, r->vs) == -1 ? errno : 0;
	r->eo = mincore(o, MAPLEN, r->vo) == -1 ? errno : 0;
}

ATF_TC(mincore_residency);
ATF_TC_HEAD(mincore_residency, tc)
{
	atf_tc_set_md_var(tc, "descr", "mincore reports the faulted pages of a "
	    "served mapping resident, as for the real file, and the untouched "
	    "ones not (the dq pager reads no pages ahead)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mincore_residency, tc)
{
	struct fixture f;
	struct mincore_res r;
	int fds[2];

	setup(&f, 10);
	fds[0] = f.o->fd;
	fds[1] = f.oracle;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_mincore, fds, &r, sizeof(r));
	ATF_REQUIRE_EQ(0, r.es);
	ATF_REQUIRE_EQ(0, r.eo);
	ATF_CHECK((r.vs[0] & MINCORE_INCORE) != 0);
	ATF_CHECK((r.vs[2] & MINCORE_INCORE) != 0);
	ATF_CHECK_EQ(r.vo[0] & MINCORE_INCORE, r.vs[0] & MINCORE_INCORE);
	ATF_CHECK_EQ(r.vo[2] & MINCORE_INCORE, r.vs[2] & MINCORE_INCORE);
	ATF_CHECK_EQ(0, r.vs[1] & MINCORE_INCORE);
	ATF_CHECK_EQ(0, r.vs[3] & MINCORE_INCORE);
	teardown(&f);
}

struct inval_res {
	unsigned char	 before, after;
	int		 sig;
};

static void
child_invalidate(void *arg, void *result)
{
	struct dqt_sync *s = arg;
	struct inval_res *r = result;
	unsigned char *p;
	int *fdp;

	fdp = (int *)(void *)(s + 1);
	p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, *fdp, 0);
	if (p == MAP_FAILED)
		_exit(3);
	r->sig = dqt_touch(p + 9, false, 0, &r->before);
	dqt_sync_post(s->toparent[1]);
	(void)dqt_sync_wait(s->tochild[0], DQT_WAIT_MS);
	r->sig |= dqt_touch(p + 9, false, 0, &r->after);
}

ATF_TC(invalidate_through_mapping);
ATF_TC_HEAD(invalidate_through_mapping, tc)
{
	atf_tc_set_md_var(tc, "descr", "the controller changes the backing "
	    "bytes and pushes INVALIDATE: an existing mapping, never unmapped, "
	    "sees the new bytes at its next access (a new READ)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(invalidate_through_mapping, tc)
{
	struct fixture f;
	struct {
		struct dqt_sync s;
		int fd;
	} a;
	struct dqt_child ch;
	struct inval_res r;
	unsigned char nb;
	unsigned reads;

	setup(&f, 11);
	dqt_sync_init(&a.s);
	a.fd = f.o->fd;
	dqt_spawn(&ch, child_invalidate, &a);
	ATF_REQUIRE(dqt_sync_wait(a.s.toparent[0], DQT_WAIT_MS));
	reads = dqt_events(&f.c, DQ_OP_READ);
	nb = (unsigned char)~data[9];
	ATF_REQUIRE_EQ(1, pwrite(f.backing, &nb, 1, 9));
	ATF_REQUIRE_MSG(dq_push_invalidate(f.c.q, f.o->id, 0, 0) == 0,
	    "INVALIDATE: %s", strerror(errno));
	dqt_sync_post(a.s.tochild[1]);
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(0, r.sig);
	ATF_CHECK_EQ(data[9], r.before);
	ATF_CHECK_EQ(nb, r.after);
	dqt_lock(&f.c);
	ATF_CHECK(f.c.events[DQ_OP_READ] > reads);
	dqt_unlock(&f.c);
	teardown(&f);
}

static void
child_fork_revoke(void *arg, void *result)
{
	struct dqt_sync *s = arg;
	struct bus_res *r = result;
	unsigned char *p;
	int *fdp, status;
	pid_t pid;

	fdp = (int *)(void *)(s + 1);
	p = mmap(NULL, 2 * 4096, PROT_READ, MAP_SHARED, *fdp, 0);
	if (p == MAP_FAILED)
		_exit(3);
	(void)dqt_touch(p, false, 0, NULL);
	pid = fork();
	if (pid == 0) {
		/* The grandchild inherits the mapping. */
		dqt_sync_post(s->toparent[1]);
		(void)dqt_sync_wait(s->tochild[0], DQT_WAIT_MS);
		_exit(dqt_touch(p + 4096, false, 0, NULL));
	}
	(void)waitpid(pid, &status, 0);
	r->sig_err = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

ATF_TC(fork_mapping_revoke);
ATF_TC_HEAD(fork_mapping_revoke, tc)
{
	atf_tc_set_md_var(tc, "descr", "a forked child's inherited mapping "
	    "raises SIGBUS after DQ_IOC_REVOKE");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fork_mapping_revoke, tc)
{
	struct fixture f;
	struct {
		struct dqt_sync s;
		int fd;
	} a;
	struct dqt_child ch;
	struct bus_res r;

	setup(&f, 12);
	dqt_sync_init(&a.s);
	a.fd = f.o->fd;
	dqt_spawn(&ch, child_fork_revoke, &a);
	ATF_REQUIRE(dqt_sync_wait(a.s.toparent[0], DQT_WAIT_MS));
	ATF_REQUIRE_EQ(0, dq_revoke(f.c.q, f.o->id));
	dqt_sync_post(a.s.tochild[1]);
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(SIGBUS, r.sig_err);
	teardown(&f);
}

struct vm_res {
	int		 found;
	int		 type;
	char		 path[PATH_MAX];
	uint64_t	 size, fileid;
};

static void
child_vmmap(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct vm_res *r = result;
	struct kinfo_vmentry *kv;
	unsigned char *p;
	int i, n;

	p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		_exit(3);
	(void)dqt_touch(p, false, 0, NULL);
	kv = kinfo_getvmmap(getpid(), &n);
	if (kv == NULL)
		_exit(4);
	for (i = 0; i < n; i++) {
		if (kv[i].kve_start != (uintptr_t)p)
			continue;
		r->found = 1;
		r->type = kv[i].kve_type;
		(void)strlcpy(r->path, kv[i].kve_path, sizeof(r->path));
		r->size = kv[i].kve_vn_size;
		r->fileid = kv[i].kve_vn_fileid;
	}
	free(kv);
}

ATF_TC(vmmap_identity);
ATF_TC_HEAD(vmmap_identity, tc)
{
	atf_tc_set_md_var(tc, "descr", "kinfo_getvmmap (procstat -v) shows a "
	    "served mapping as a vnode mapping with the presented path, size "
	    "and file id");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(vmmap_identity, tc)
{
	struct fixture f;
	struct vm_res r;

	setup(&f, 13);
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_vmmap, &f.o->fd, &r, sizeof(r));
	ATF_REQUIRE(r.found);
	ATF_CHECK_EQ(KVME_TYPE_VNODE, r.type);
	ATF_CHECK_STREQ(backing_path, r.path);
	ATF_CHECK_EQ(DATA_LEN, r.size);
	ATF_CHECK_EQ(f.o->ident.di_ino, r.fileid);
	teardown(&f);
}

struct short_res {
	int		 sig;
	struct dqt_rr	 rd;
};

static void
child_short(void *arg, void *result)
{
	int *fds = arg;
	struct short_res *r = result;
	unsigned char *p, buf[64];

	p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fds[0], 0);
	if (p == MAP_FAILED)
		_exit(3);
	r->sig = dqt_touch(p + 4000, false, 0, NULL);
	r->rd.rv = pread(fds[1], buf, sizeof(buf), 4000);
	r->rd.err = r->rd.rv == -1 ? errno : 0;
}

ATF_TC(short_reply_inside_size);
ATF_TC_HEAD(short_reply_inside_size, tc)
{
	atf_tc_set_md_var(tc, "descr", "a READ answered short while the "
	    "presented size says the bytes exist is an error, not zeros: "
	    "SIGBUS for a fault, EIO for a DQ_CACHE_DATA read");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(short_reply_inside_size, tc)
{
	struct fixture f;
	struct dqt_object *m, *d;
	struct dq_policy pol;
	struct short_res r;
	int fds[2];

	setup(&f, 14);
	/* Both present DATA_LEN bytes and serve only 100. */
	dq_policy_default(&pol);
	m = dqt_mint_ident(&f.c, &f.o->ident, &pol, data, 100);
	pol.dp_cache = DQ_CACHE_DATA;
	d = dqt_mint_ident(&f.c, &f.o->ident, &pol, data, 100);
	fds[0] = m->fd;
	fds[1] = d->fd;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_short, fds, &r, sizeof(r));
	ATF_CHECK_EQ(SIGBUS, r.sig);
	ATF_CHECK_EQ(-1, r.rd.rv);
	ATF_CHECK_EQ(EIO, r.rd.err);
	teardown(&f);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, read_oracle);
	ATF_TP_ADD_TC(tp, shared_write_rules);
	ATF_TP_ADD_TC(tp, private_cow_and_revoke);
	ATF_TP_ADD_TC(tp, msync_writeback);
	ATF_TP_ADD_TC(tp, msync_refused);
	ATF_TP_ADD_TC(tp, munmap_close_writes_back);
	ATF_TP_ADD_TC(tp, sigbus_cases);
	ATF_TP_ADD_TC(tp, sigbus_deadline);
	ATF_TP_ADD_TC(tp, fault_survives_signals);
	ATF_TP_ADD_TC(tp, mincore_residency);
	ATF_TP_ADD_TC(tp, invalidate_through_mapping);
	ATF_TP_ADD_TC(tp, fork_mapping_revoke);
	ATF_TP_ADD_TC(tp, vmmap_identity);
	ATF_TP_ADD_TC(tp, short_reply_inside_size);
	return (atf_no_error());
}
