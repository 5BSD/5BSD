/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Data: read(2) and its relatives on a served file are READ events the
 * controller answers from memory, and the requester cannot tell them from
 * the real file holding the same bytes.  Requesters run in forked children
 * (the controller process would get EDEADLK); the oracle is the real file.
 */

#include <sys/param.h>
#include <sys/module.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <aio.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dqt.h"

#define	DATA_LEN	20000
#define	MAX_CALLS	8

static unsigned char data[DATA_LEN];
static unsigned char data2[DATA_LEN];
static char oracle_path[DQT_PATH_MAX];

struct io_arg {
	int		 fd;
	size_t		 chunk;
	off_t		 offsets[MAX_CALLS];
	int		 noffsets;
};

struct io_res {
	long		 rv[MAX_CALLS];
	int		 err[MAX_CALLS];
	int		 n;
	uint64_t	 hash;		/* of every byte returned, in order */
};

/* read(2) in chunks until end of file. */
static void
child_read_all(void *arg, void *result)
{
	struct io_arg *a = arg;
	struct io_res *r = result;
	unsigned char *all, *buf;
	size_t total;
	ssize_t n;

	size_t cap;

	/* Room for the whole file however it is chunked. */
	cap = a->chunk > DATA_LEN ? a->chunk + 1 : DATA_LEN * 2;
	buf = malloc(a->chunk);
	all = malloc(cap);
	total = 0;
	r->n = 0;
	for (;;) {
		n = read(a->fd, buf, a->chunk);
		if (r->n < MAX_CALLS) {
			r->rv[r->n] = n;
			r->err[r->n] = n == -1 ? errno : 0;
			r->n++;
		}
		if (n <= 0)
			break;
		if (total + (size_t)n <= cap) {
			memcpy(all + total, buf, (size_t)n);
			total += (size_t)n;
		}
	}
	r->hash = dqt_digest(all, total);
	free(all);
	free(buf);
}

/* One pread(2) per offset. */
static void
child_pread(void *arg, void *result)
{
	struct io_arg *a = arg;
	struct io_res *r = result;
	unsigned char *all, *buf;
	size_t total;
	ssize_t n;
	int i;

	buf = malloc(a->chunk);
	all = malloc(a->chunk * MAX_CALLS);
	total = 0;
	for (i = 0; i < a->noffsets; i++) {
		n = pread(a->fd, buf, a->chunk, a->offsets[i]);
		r->rv[i] = n;
		r->err[i] = n == -1 ? errno : 0;
		if (n > 0) {
			memcpy(all + total, buf, (size_t)n);
			total += (size_t)n;
		}
	}
	r->n = a->noffsets;
	r->hash = dqt_digest(all, total);
	free(all);
	free(buf);
}

/* readv(2) with three uneven pieces. */
static void
child_readv(void *arg, void *result)
{
	struct io_arg *a = arg;
	struct io_res *r = result;
	struct iovec iov[3];
	unsigned char *buf;
	ssize_t n;

	buf = malloc(11100);
	iov[0].iov_base = buf;
	iov[0].iov_len = 100;
	iov[1].iov_base = buf + 100;
	iov[1].iov_len = 4000;
	iov[2].iov_base = buf + 4100;
	iov[2].iov_len = 7000;
	n = readv(a->fd, iov, 3);
	r->rv[0] = n;
	r->err[0] = n == -1 ? errno : 0;
	r->n = 1;
	r->hash = dqt_digest(buf, n > 0 ? (size_t)n : 0);
	free(buf);
}

/* read(2) of length 0, then lseek(2) past the end and read(2). */
static void
child_zero_and_past_eof(void *arg, void *result)
{
	struct io_arg *a = arg;
	struct io_res *r = result;
	unsigned char buf[16];

	r->rv[0] = read(a->fd, buf, 0);
	r->err[0] = r->rv[0] == -1 ? errno : 0;
	r->rv[1] = lseek(a->fd, a->offsets[0], SEEK_SET);
	r->err[1] = r->rv[1] == -1 ? errno : 0;
	r->rv[2] = read(a->fd, buf, sizeof(buf));
	r->err[2] = r->rv[2] == -1 ? errno : 0;
	r->n = 3;
	r->hash = 0;
}

static void
check_same(const struct io_res *served, const struct io_res *oracle)
{
	int i;

	ATF_CHECK_EQ(oracle->n, served->n);
	for (i = 0; i < oracle->n && i < served->n; i++) {
		ATF_CHECK_EQ_MSG(oracle->rv[i], served->rv[i],
		    "call %d: served %ld oracle %ld", i, served->rv[i],
		    oracle->rv[i]);
		ATF_CHECK_EQ_MSG(oracle->err[i], served->err[i],
		    "call %d: served errno %d oracle errno %d", i,
		    served->err[i], oracle->err[i]);
	}
	ATF_CHECK_EQ_MSG(oracle->hash, served->hash, "bytes differ");
}

ATF_TC(read_oracle);
ATF_TC_HEAD(read_oracle, tc)
{
	atf_tc_set_md_var(tc, "descr", "read(2) to end of file returns the "
	    "same byte and return value sequence as the real file");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(read_oracle, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct io_arg a;
	struct io_res served, oracle_res;
	int oracle;

	dqt_fill(data, sizeof(data), 11);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);

	memset(&a, 0, sizeof(a));
	a.chunk = 4096;
	a.fd = o->fd;
	dqt_run_child(child_read_all, &a, &served, sizeof(served));
	a.fd = oracle;
	dqt_run_child(child_read_all, &a, &oracle_res, sizeof(oracle_res));
	check_same(&served, &oracle_res);
	ATF_CHECK_EQ(dqt_digest(data, sizeof(data)), served.hash);
	/* 20000/4096: four full chunks, one short, one at EOF. */
	ATF_CHECK_EQ(6, served.n);
	dqt_lock(&c);
	ATF_CHECK_EQ(6, c.events[DQ_OP_READ]);
	ATF_CHECK_EQ(0, c.reply_failures);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(pread_oracle);
ATF_TC_HEAD(pread_oracle, tc)
{
	atf_tc_set_md_var(tc, "descr", "pread(2) at offsets inside, straddling "
	    "and past the end of the file matches the real file");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(pread_oracle, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct io_arg a;
	struct io_res served, oracle_res;
	int oracle;

	dqt_fill(data, sizeof(data), 12);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);

	memset(&a, 0, sizeof(a));
	a.chunk = 5000;
	a.noffsets = 7;
	a.offsets[0] = 0;
	a.offsets[1] = 1;
	a.offsets[2] = 4095;
	a.offsets[3] = 4096;
	a.offsets[4] = DATA_LEN - 1;
	a.offsets[5] = DATA_LEN;
	a.offsets[6] = DATA_LEN + 10000;
	a.fd = o->fd;
	dqt_run_child(child_pread, &a, &served, sizeof(served));
	a.fd = oracle;
	dqt_run_child(child_pread, &a, &oracle_res, sizeof(oracle_res));
	check_same(&served, &oracle_res);
	ATF_CHECK_EQ(1, served.rv[4]);
	ATF_CHECK_EQ(0, served.rv[5]);
	ATF_CHECK_EQ(0, served.rv[6]);
	/* pread never moves the shared offset. */
	ATF_CHECK_EQ(0, lseek(o->fd, 0, SEEK_CUR));
	dqt_lock(&c);
	ATF_CHECK_EQ(7, c.events[DQ_OP_READ]);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(readv_oracle);
ATF_TC_HEAD(readv_oracle, tc)
{
	atf_tc_set_md_var(tc, "descr", "readv(2) fills uneven iovecs as the "
	    "real file does");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(readv_oracle, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct io_arg a;
	struct io_res served, oracle_res;
	int oracle;

	dqt_fill(data, sizeof(data), 13);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);

	memset(&a, 0, sizeof(a));
	a.fd = o->fd;
	dqt_run_child(child_readv, &a, &served, sizeof(served));
	a.fd = oracle;
	dqt_run_child(child_readv, &a, &oracle_res, sizeof(oracle_res));
	check_same(&served, &oracle_res);
	ATF_CHECK_EQ(11100, served.rv[0]);
	ATF_CHECK_EQ(dqt_digest(data, 11100), served.hash);
	/* One uio, one event: the iovecs are not visible to the controller. */
	dqt_lock(&c);
	ATF_CHECK_EQ(1, c.events[DQ_OP_READ]);
	ATF_CHECK_EQ(11100, c.rd[0].len);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}

struct aio_res {
	long		 rv;
	int		 err;
	long		 ret;
	int		 reterr;
	uint64_t	 hash;
};

static void
child_aio_read(void *arg, void *result)
{
	struct io_arg *a = arg;
	struct aio_res *r = result;
	struct aiocb cb, *done;
	unsigned char *buf;

	buf = calloc(1, a->chunk);
	memset(&cb, 0, sizeof(cb));
	cb.aio_fildes = a->fd;
	cb.aio_buf = buf;
	cb.aio_nbytes = a->chunk;
	cb.aio_offset = a->offsets[0];
	r->rv = aio_read(&cb);
	r->err = r->rv == -1 ? errno : 0;
	r->ret = -1;
	r->reterr = 0;
	if (r->rv == 0) {
		done = NULL;
		r->ret = aio_waitcomplete(&done, NULL);
		r->reterr = r->ret == -1 ? errno : 0;
		if (r->ret > 0)
			r->hash = dqt_digest(buf, (size_t)r->ret);
	}
	free(buf);
}

ATF_TC(aio_read_oracle);
ATF_TC_HEAD(aio_read_oracle, tc)
{
	atf_tc_set_md_var(tc, "descr", "aio_read(2) on a served file: refused "
	    "as unsafe unless vfs.aio.enable_unsafe, served by the aio daemon "
	    "otherwise");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(aio_read_oracle, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct io_arg a;
	struct aio_res served, oracle_res;
	size_t len;
	int oracle, unsafe;

	ATF_REQUIRE_MSG(modfind("aio") != -1, "aio module: %s",
	    strerror(errno));
	len = sizeof(unsafe);
	ATF_REQUIRE_EQ(0, sysctlbyname("vfs.aio.enable_unsafe", &unsafe, &len,
	    NULL, 0));
	dqt_fill(data, sizeof(data), 14);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);

	memset(&a, 0, sizeof(a));
	a.chunk = 6000;
	a.offsets[0] = 1000;
	a.fd = o->fd;
	dqt_run_child(child_aio_read, &a, &served, sizeof(served));
	a.fd = oracle;
	dqt_run_child(child_aio_read, &a, &oracle_res, sizeof(oracle_res));
	ATF_CHECK_EQ(0, oracle_res.rv);
	ATF_CHECK_EQ(6000, oracle_res.ret);
	if (unsafe == 0) {
		/*
		 * aio_queue_file (vfs_aio.c) calls only a local DTYPE_VNODE
		 * safe; a DTYPE_DQ descriptor is refused with EOPNOTSUPP at
		 * submission unless vfs.aio.enable_unsafe is set.  A
		 * difference from the real file; recorded for stage 1b.
		 */
		ATF_CHECK_EQ(-1, served.rv);
		ATF_CHECK_EQ(EOPNOTSUPP, served.err);
		dqt_lock(&c);
		ATF_CHECK_EQ(0, c.events[DQ_OP_READ]);
		dqt_unlock(&c);
	} else {
		ATF_CHECK_EQ(0, served.rv);
		ATF_CHECK_EQ(6000, served.ret);
		ATF_CHECK_EQ(oracle_res.hash, served.hash);
		ATF_CHECK_EQ(dqt_digest(data + 1000, 6000), served.hash);
		dqt_lock(&c);
		ATF_CHECK_EQ(1, c.events[DQ_OP_READ]);
		dqt_unlock(&c);
		/*
		 * The aio daemon posted it: a kernel process, so the caller
		 * is flagged DQ_CALLER_F_KERNEL with pid 0 and carries the
		 * requester's credential (aio_process_rw swaps td_ucred).
		 */
		dqt_lock(&c);
		ATF_CHECK((c.last_caller.dc_flags & DQ_CALLER_F_KERNEL) != 0);
		ATF_CHECK_EQ(0, c.last_caller.dc_pid);
		ATF_CHECK_EQ(getuid(), c.last_caller.dc_uid);
		dqt_unlock(&c);
	}
	dqt_fini(&c);
	(void)close(oracle);
	if (unsafe == 0) {
		/*
		 * The pin above holds today; the real file's answer is the
		 * one owed.  A kernel that closes the difference reports an
		 * unexpected pass here.
		 */
		atf_tc_expect_fail("recorded difference: aio_read of a served "
		    "file is EOPNOTSUPP without vfs.aio.enable_unsafe");
		ATF_CHECK_EQ(oracle_res.rv, served.rv);
		ATF_CHECK_EQ(oracle_res.ret, served.ret);
	}
}

ATF_TC(chunk_boundaries);
ATF_TC_HEAD(chunk_boundaries, tc)
{
	atf_tc_set_md_var(tc, "descr", "a read larger than kern.dq.max_io is "
	    "chunked into ordered READ events");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(chunk_boundaries, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct io_arg a;
	struct io_res served;
	unsigned char *big;
	size_t len;
	u_int max_io;
	int oracle;

	ATF_REQUIRE(dqt_sysctl_get_uint("kern.dq.max_io", &max_io));
	len = 2 * (size_t)max_io + 100;
	big = malloc(len);
	ATF_REQUIRE(big != NULL);
	dqt_fill(big, len, 15);
	oracle = dqt_make_oracle("oracle", big, len, oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, big, len, NULL);

	memset(&a, 0, sizeof(a));
	a.chunk = len;
	a.fd = o->fd;
	dqt_run_child(child_read_all, &a, &served, sizeof(served));
	ATF_CHECK_EQ(2, served.n);
	ATF_CHECK_EQ((long)len, served.rv[0]);
	ATF_CHECK_EQ(0, served.rv[1]);
	ATF_CHECK_EQ(dqt_digest(big, len), served.hash);
	/* Three chunks for the first read, one zero-length answer for the second. */
	dqt_lock(&c);
	ATF_REQUIRE_EQ(4, c.nrd);
	ATF_CHECK_EQ(0, c.rd[0].offset);
	ATF_CHECK_EQ(max_io, c.rd[0].len);
	ATF_CHECK_EQ(max_io, c.rd[1].offset);
	ATF_CHECK_EQ(max_io, c.rd[1].len);
	ATF_CHECK_EQ(2 * (uint64_t)max_io, c.rd[2].offset);
	ATF_CHECK_EQ(100, c.rd[2].len);
	ATF_CHECK_EQ(len, c.rd[3].offset);
	dqt_unlock(&c);
	/* Sequence numbers are consecutive: nothing was dropped. */
	dqt_lock(&c);
	ATF_CHECK_EQ(0, c.gaps);
	dqt_unlock(&c);
	dqt_fini(&c);
	free(big);
	(void)close(oracle);
}

ATF_TC(eof_short_reply);
ATF_TC_HEAD(eof_short_reply, tc)
{
	atf_tc_set_md_var(tc, "descr", "a short READ reply ends the read; a "
	    "zero-length reply is end of file");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(eof_short_reply, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct io_arg a;
	struct io_res served, oracle_res;
	int oracle;

	dqt_fill(data, 1000, 16);
	oracle = dqt_make_oracle("oracle", data, 1000, oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, 1000, NULL);

	memset(&a, 0, sizeof(a));
	a.chunk = 2000;
	a.fd = o->fd;
	dqt_run_child(child_read_all, &a, &served, sizeof(served));
	a.fd = oracle;
	dqt_run_child(child_read_all, &a, &oracle_res, sizeof(oracle_res));
	check_same(&served, &oracle_res);
	ATF_CHECK_EQ(1000, served.rv[0]);
	ATF_CHECK_EQ(0, served.rv[1]);
	dqt_lock(&c);
	ATF_REQUIRE_EQ(2, c.nrd);
	ATF_CHECK_EQ(0, c.rd[0].offset);
	ATF_CHECK_EQ(2000, c.rd[0].len);
	ATF_CHECK_EQ(1000, c.rd[1].offset);
	ATF_CHECK_EQ(2000, c.rd[1].len);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(read_zero_and_past_eof);
ATF_TC_HEAD(read_zero_and_past_eof, tc)
{
	atf_tc_set_md_var(tc, "descr", "read(2) of length 0 posts nothing; "
	    "lseek(2) past the end then read(2) answers 0 as the real file");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(read_zero_and_past_eof, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct io_arg a;
	struct io_res served, oracle_res;
	int oracle;

	dqt_fill(data, sizeof(data), 17);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);

	memset(&a, 0, sizeof(a));
	a.offsets[0] = DATA_LEN + 100;
	a.fd = o->fd;
	dqt_run_child(child_zero_and_past_eof, &a, &served, sizeof(served));
	a.fd = oracle;
	dqt_run_child(child_zero_and_past_eof, &a, &oracle_res,
	    sizeof(oracle_res));
	check_same(&served, &oracle_res);
	ATF_CHECK_EQ(0, served.rv[0]);
	ATF_CHECK_EQ(DATA_LEN + 100, served.rv[1]);
	ATF_CHECK_EQ(0, served.rv[2]);
	/* Only the read past the end reached the controller. */
	dqt_lock(&c);
	ATF_REQUIRE_EQ(1, c.nrd);
	ATF_CHECK_EQ(DATA_LEN + 100, c.rd[0].offset);
	ATF_CHECK_EQ(16, c.rd[0].len);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(seek_data_hole);
ATF_TC_HEAD(seek_data_hole, tc)
{
	atf_tc_set_md_var(tc, "descr", "lseek(2) is local: SET/CUR/END as the "
	    "real file, SEEK_DATA/SEEK_HOLE as one extent [0, size)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(seek_data_hole, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	int oracle;

	dqt_fill(data, sizeof(data), 18);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);

	/* The forms a real file answers from its size and offset. */
	ATF_CHECK_EQ(lseek(oracle, 0, SEEK_END), lseek(o->fd, 0, SEEK_END));
	ATF_CHECK_EQ(DATA_LEN, lseek(o->fd, 0, SEEK_CUR));
	ATF_CHECK_EQ(lseek(oracle, -100, SEEK_END), lseek(o->fd, -100, SEEK_END));
	ATF_CHECK_EQ(lseek(oracle, 50, SEEK_CUR), lseek(o->fd, 50, SEEK_CUR));
	ATF_CHECK_EQ(lseek(oracle, 7, SEEK_SET), lseek(o->fd, 7, SEEK_SET));
	errno = 0;
	ATF_CHECK_EQ(-1, lseek(o->fd, -1, SEEK_SET));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, lseek(o->fd, -(DATA_LEN + 1), SEEK_END));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(OFF_MAX, lseek(o->fd, OFF_MAX, SEEK_SET));
	errno = 0;
	ATF_CHECK_EQ(-1, lseek(o->fd, 1, SEEK_CUR));
	ATF_CHECK_EQ(EOVERFLOW, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, lseek(o->fd, 0, 99));
	ATF_CHECK_EQ(EINVAL, errno);
	/* A rejected seek leaves the offset where it was. */
	ATF_CHECK_EQ(OFF_MAX, lseek(o->fd, 0, SEEK_CUR));

	/*
	 * SEEK_DATA/SEEK_HOLE: one extent covering [0, size), as
	 * vop_stdioctl answers for a filesystem without hole reporting.  A
	 * real file's answer depends on its filesystem (ZFS reports a fresh
	 * file as a hole until its transaction group syncs), so the
	 * documented values are asserted instead of the oracle's.
	 */
	ATF_CHECK_EQ(0, lseek(o->fd, 0, SEEK_DATA));
	ATF_CHECK_EQ(DATA_LEN - 1, lseek(o->fd, DATA_LEN - 1, SEEK_DATA));
	ATF_CHECK_EQ(DATA_LEN, lseek(o->fd, 0, SEEK_HOLE));
	ATF_CHECK_EQ(DATA_LEN, lseek(o->fd, 123, SEEK_HOLE));
	errno = 0;
	ATF_CHECK_EQ(-1, lseek(o->fd, DATA_LEN, SEEK_DATA));
	ATF_CHECK_EQ(ENXIO, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, lseek(o->fd, -1, SEEK_HOLE));
	ATF_CHECK_EQ(ENXIO, errno);
	/* Seeking is local: no event reached the controller. */
	dqt_lock(&c);
	ATF_CHECK_EQ(0, c.records);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}

struct shared_arg {
	int		 fd;
	size_t		 chunk;
};

struct shared_res {
	size_t		 total[2];
	int		 err[2];
};

struct shared_thr {
	struct shared_arg *a;
	size_t		 total;
	int		 err;
};

static void *
shared_reader(void *arg)
{
	struct shared_thr *t = arg;
	unsigned char *buf;
	ssize_t n;

	buf = malloc(t->a->chunk);
	for (;;) {
		n = read(t->a->fd, buf, t->a->chunk);
		if (n < 0) {
			t->err = errno;
			break;
		}
		if (n == 0)
			break;
		t->total += (size_t)n;
	}
	free(buf);
	return (NULL);
}

static void
child_shared_offset(void *arg, void *result)
{
	struct shared_arg *a = arg;
	struct shared_res *r = result;
	struct shared_thr t[2];
	pthread_t thr[2];
	int i;

	for (i = 0; i < 2; i++) {
		t[i].a = a;
		t[i].total = 0;
		t[i].err = 0;
		pthread_create(&thr[i], NULL, shared_reader, &t[i]);
	}
	for (i = 0; i < 2; i++) {
		pthread_join(thr[i], NULL);
		r->total[i] = t[i].total;
		r->err[i] = t[i].err;
	}
}

ATF_TC(shared_offset_two_threads);
ATF_TC_HEAD(shared_offset_two_threads, tc)
{
	atf_tc_set_md_var(tc, "descr", "two threads reading one descriptor "
	    "advance the shared offset once per byte (foffset_lock_uio)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(shared_offset_two_threads, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct shared_arg a;
	struct shared_res r;
	uint64_t seen[DATA_LEN / 1000];
	int i, j, n, oracle;

	dqt_fill(data, sizeof(data), 19);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);

	a.fd = o->fd;
	a.chunk = 1000;
	dqt_run_child(child_shared_offset, &a, &r, sizeof(r));
	ATF_CHECK_EQ(0, r.err[0]);
	ATF_CHECK_EQ(0, r.err[1]);
	ATF_CHECK_EQ(DATA_LEN, r.total[0] + r.total[1]);
	/*
	 * Every chunk offset below the size was asked exactly once; the
	 * reads that found the end asked at the size and were answered 0.
	 */
	n = 0;
	dqt_lock(&c);
	for (i = 0; i < c.nrd; i++) {
		if (c.rd[i].offset >= DATA_LEN) {
			ATF_CHECK_EQ(DATA_LEN, c.rd[i].offset);
			continue;
		}
		ATF_CHECK_EQ(0, c.rd[i].offset % 1000);
		for (j = 0; j < n; j++)
			ATF_CHECK_MSG(seen[j] != c.rd[i].offset,
			    "offset %ju asked twice", (uintmax_t)c.rd[i].offset);
		if (n < (int)nitems(seen))
			seen[n++] = c.rd[i].offset;
	}
	dqt_unlock(&c);
	ATF_CHECK_EQ(DATA_LEN / 1000, n);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(two_objects_same_identity);
ATF_TC_HEAD(two_objects_same_identity, tc)
{
	atf_tc_set_md_var(tc, "descr", "two objects presenting one identity "
	    "serve their own bytes; nothing leaks between them");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(two_objects_same_identity, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o1, *o2;
	struct dq_policy pol;
	struct io_arg a;
	struct io_res r1, r2;
	struct stat st1, st2;
	int oracle;

	dqt_fill(data, sizeof(data), 20);
	dqt_fill(data2, sizeof(data2), 21);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	/*
	 * The controller keeps the times: each object stamps its own access
	 * time at its own reads (C7b), and two objects of one identity do
	 * not share one until the identity group (C10).
	 */
	dq_policy_default(&pol);
	pol.dp_flags = DQ_PF_NO_STAMP;
	o1 = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	o2 = dqt_mint(&c, oracle, oracle_path, data2, sizeof(data2), &pol);
	ATF_CHECK(o1->id != o2->id);

	memset(&a, 0, sizeof(a));
	a.chunk = 4096;
	a.fd = o1->fd;
	dqt_run_child(child_read_all, &a, &r1, sizeof(r1));
	a.fd = o2->fd;
	dqt_run_child(child_read_all, &a, &r2, sizeof(r2));
	ATF_CHECK_EQ(dqt_digest(data, sizeof(data)), r1.hash);
	ATF_CHECK_EQ(dqt_digest(data2, sizeof(data2)), r2.hash);
	ATF_CHECK(r1.hash != r2.hash);
	/* Same identity: fstat cannot tell them apart. */
	ATF_REQUIRE_EQ(0, fstat(o1->fd, &st1));
	ATF_REQUIRE_EQ(0, fstat(o2->fd, &st2));
	dqt_check_stat_eq(&st1, &st2);
	dqt_lock(&c);
	ATF_CHECK_EQ(6, o1->reads);
	ATF_CHECK_EQ(6, o2->reads);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(read_error_reply);
ATF_TC_HEAD(read_error_reply, tc)
{
	atf_tc_set_md_var(tc, "descr", "a controller errno in a READ reply is "
	    "the requester's read(2) errno");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(read_error_reply, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct io_arg a;
	struct io_res served;
	int oracle;

	dqt_fill(data, sizeof(data), 22);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	dqt_object_read_errno(&c, o, EACCES);

	memset(&a, 0, sizeof(a));
	a.chunk = 4096;
	a.fd = o->fd;
	dqt_run_child(child_read_all, &a, &served, sizeof(served));
	ATF_CHECK_EQ(1, served.n);
	ATF_CHECK_EQ(-1, served.rv[0]);
	ATF_CHECK_EQ(EACCES, served.err[0]);
	dqt_lock(&c);
	ATF_CHECK_EQ(0, c.reply_failures);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}

/*
 * T-A02: st_atime after a read of a served file whose controller sends no
 * attributes, on a presented file system with and without MNT_NOATIME.
 */
struct atime_res {
	long		 rv;
	struct stat	 before, after;
};

static void
child_read_atime(void *arg, void *result)
{
	struct atime_res *r = result;
	int fd = *(int *)arg;
	char buf[16];

	(void)fstat(fd, &r->before);
	dqt_msleep(20);
	r->rv = read(fd, buf, sizeof(buf));
	(void)fstat(fd, &r->after);
}

ATF_TC(atime_after_read);
ATF_TC_HEAD(atime_after_read, tc)
{
	atf_tc_set_md_var(tc, "descr", "st_atime after a read of a served "
	    "file (T-A02)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(atime_after_read, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_ident_file *ident;
	struct dq_policy pol;
	struct atime_res r;
	struct statfs sfs;
	struct stat st;
	int fd, oracle;

	dqt_fill(data, sizeof(data), 61);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	dqt_ident_of(oracle, oracle_path, ident, &st, &sfs);
	ident->di_statfs.ds_flags &= ~(uint64_t)MNT_NOATIME;
	dq_policy_default(&pol);
	dqt_init(&c);
	o = dqt_mint_ident(&c, ident, &pol, data, sizeof(data));
	fd = o->fd;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_read_atime, &fd, &r, sizeof(r));
	ATF_REQUIRE_EQ(16, r.rv);
	/*
	 * No attributes came: the kernel stamps the access time, as a local
	 * file system's read does (it stayed where it was).
	 */
	ATF_CHECK(timespeccmp(&r.after.st_atim, &r.before.st_atim, >));

	/* DQ_PF_NO_STAMP: the controller keeps the times; none moves. */
	pol.dp_flags = DQ_PF_NO_STAMP;
	o = dqt_mint_ident(&c, ident, &pol, data, sizeof(data));
	fd = o->fd;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_read_atime, &fd, &r, sizeof(r));
	ATF_REQUIRE_EQ(16, r.rv);
	ATF_CHECK(timespeccmp(&r.after.st_atim, &r.before.st_atim, ==));
	pol.dp_flags = 0;

	/* Presented MNT_NOATIME: never stamped. */
	ident->di_statfs.ds_flags |= MNT_NOATIME;
	o = dqt_mint_ident(&c, ident, &pol, data, sizeof(data));
	fd = o->fd;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_read_atime, &fd, &r, sizeof(r));
	ATF_REQUIRE_EQ(16, r.rv);
	ATF_CHECK(timespeccmp(&r.after.st_atim, &r.before.st_atim, ==));
	free(ident);
	dqt_fini(&c);
	(void)close(oracle);
}

/*
 * Review 2: the access time a read stamps when no attributes came, as
 * ffs_read and zfs_read stamp it: a read at the end of the file (0 bytes)
 * stamps it too, and a presented MNT_RDONLY file system never does.
 */
static void
child_read_atime_eof(void *arg, void *result)
{
	struct atime_res *r = result;
	int fd = *(int *)arg;
	char buf[16];

	(void)lseek(fd, 0, SEEK_END);
	(void)fstat(fd, &r->before);
	dqt_msleep(20);
	r->rv = read(fd, buf, sizeof(buf));
	(void)fstat(fd, &r->after);
}

ATF_TC(atime_eof_and_rdonly);
ATF_TC_HEAD(atime_eof_and_rdonly, tc)
{
	atf_tc_set_md_var(tc, "descr", "st_atime after a served read at the "
	    "end of the file moves, and on a presented MNT_RDONLY file system "
	    "never does (review 2)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(atime_eof_and_rdonly, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_ident_file *ident;
	struct dq_policy pol;
	struct atime_res r;
	struct statfs sfs;
	struct stat st;
	int fd, oracle;

	dqt_fill(data, sizeof(data), 63);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	dqt_ident_of(oracle, oracle_path, ident, &st, &sfs);
	ident->di_statfs.ds_flags &= ~(uint64_t)(MNT_NOATIME | MNT_RDONLY);
	dq_policy_default(&pol);
	dqt_init(&c);

	/* At the end of the file: 0 bytes, stamped. */
	o = dqt_mint_ident(&c, ident, &pol, data, sizeof(data));
	fd = o->fd;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_read_atime_eof, &fd, &r, sizeof(r));
	ATF_REQUIRE_EQ(0, r.rv);
	ATF_CHECK_MSG(timespeccmp(&r.after.st_atim, &r.before.st_atim, >),
	    "a read at the end of the file left st_atime");

	/* Presented MNT_RDONLY: never stamped. */
	ident->di_statfs.ds_flags |= MNT_RDONLY;
	o = dqt_mint_ident(&c, ident, &pol, data, sizeof(data));
	fd = o->fd;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_read_atime, &fd, &r, sizeof(r));
	ATF_REQUIRE_EQ(16, r.rv);
	ATF_CHECK_MSG(timespeccmp(&r.after.st_atim, &r.before.st_atim, ==),
	    "a read on a read-only file system moved st_atime");
	free(ident);
	dqt_fini(&c);
	(void)close(oracle);
}

/*
 * T-A28: a signal, caught by a handler installed without SA_RESTART,
 * during a read of a served regular file that the controller answers
 * 300 ms later.  A local file system's read completes, and so does this
 * one under the default policy (DQ_PF_INTR would end it EINTR, see
 * dq_concurrency_test:sigalrm_read_intr).
 */
static volatile sig_atomic_t alrm_seen;

static void
on_alrm(int sig __unused)
{

	alrm_seen++;
}

struct norestart_res {
	struct dqt_rr	 rr;
	int		 signals;
};

static void
child_read_norestart(void *arg, void *result)
{
	struct norestart_res *r = result;
	struct sigaction sa;
	int fd = *(int *)arg;
	char buf[16];

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_alrm;
	(void)sigaction(SIGALRM, &sa, NULL);
	DQT_RR(r->rr, read(fd, buf, sizeof(buf)));
	r->signals = alrm_seen;
}

ATF_TC(sigalrm_no_restart);
ATF_TC_HEAD(sigalrm_no_restart, tc)
{
	atf_tc_set_md_var(tc, "descr", "SIGALRM without SA_RESTART during a "
	    "served read the controller answers late (T-A28)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sigalrm_no_restart, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct norestart_res r;
	struct dqt_child ch;
	int fd, oracle;

	dqt_fill(data, sizeof(data), 62);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	dqt_hold(&c, true);
	fd = o->fd;
	dqt_spawn(&ch, child_read_norestart, &fd);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	ATF_REQUIRE(dqt_wait_wmesg(ch.pid, DQT_WMESG_REPLY, DQT_WAIT_MS));
	ATF_REQUIRE_EQ(0, kill(ch.pid, SIGALRM));
	dqt_msleep(300);
	/* The wait did not end: the answer is taken. */
	ATF_CHECK_EQ(0, dq_reply(c.q, dqt_held_id(&c, 0), 0, data, 16));
	memset(&r, 0, sizeof(r));
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(1, r.signals);
	/*
	 * The read completes, as a local file system's, and the handler
	 * runs after it (it ended EINTR with the signal, D192).
	 */
	ATF_CHECK_EQ_MSG(16, r.rr.rv, "read: %s", strerror(r.rr.err));
	dqt_lock(&c);
	ATF_CHECK_EQ(0, c.ninterrupted);
	dqt_unlock(&c);
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(same_identity_atime_diverges);
ATF_TC_HEAD(same_identity_atime_diverges, tc)
{
	atf_tc_set_md_var(tc, "descr", "pin (review 1 L7): two objects of one "
	    "identity stamp their own access times, where two opens of one "
	    "file share the inode's; the identity group (C10) flips it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(same_identity_atime_diverges, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o1, *o2;
	struct atime_res r1, r2;
	struct stat st1, st2;
	int fd, oracle;

	dqt_fill(data, sizeof(data), 27);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o1 = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	o2 = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	fd = o1->fd;
	memset(&r1, 0, sizeof(r1));
	dqt_run_child(child_read_atime, &fd, &r1, sizeof(r1));
	ATF_REQUIRE_EQ(16, r1.rv);
	fd = o2->fd;
	memset(&r2, 0, sizeof(r2));
	dqt_run_child(child_read_atime, &fd, &r2, sizeof(r2));
	ATF_REQUIRE_EQ(16, r2.rv);
	ATF_REQUIRE_EQ(0, fstat(o1->fd, &st1));
	ATF_REQUIRE_EQ(0, fstat(o2->fd, &st2));
	/* Pin: each kept its own stamp (one file would show one atime). */
	ATF_CHECK(timespeccmp(&st1.st_atim, &st2.st_atim, !=));
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(eintr_reply_refused);
ATF_TC_HEAD(eintr_reply_refused, tc)
{
	atf_tc_set_md_var(tc, "descr", "a controller's EINTR is never the "
	    "requester's: with no signal it is EIO and a bad reply (D193)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(eintr_reply_refused, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_stats2 st0, st1;
	struct io_arg a;
	struct io_res served;
	int oracle;

	dqt_fill(data, sizeof(data), 23);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	dqt_object_read_errno(&c, o, EINTR);
	dqt_stats2(&c, &st0);
	memset(&a, 0, sizeof(a));
	a.chunk = 4096;
	a.fd = o->fd;
	dqt_run_child(child_read_all, &a, &served, sizeof(served));
	ATF_CHECK_EQ(1, served.n);
	ATF_CHECK_EQ(-1, served.rv[0]);
	ATF_CHECK_EQ(EIO, served.err[0]);
	dqt_stats2(&c, &st1);
	ATF_CHECK_EQ(1, st1.ds2_bad_replies - st0.ds2_bad_replies);
	dqt_fini(&c);
	(void)close(oracle);
}

/*
 * D192 (B1): thread A of a process waits in a read of an object with no
 * deadline, which the controller never answers; thread B calls _exit.
 * The exit single-threads the process, and A's non-catching wait must see
 * it within a slice.
 */
static void *
read_forever(void *arg)
{
	char buf[16];

	(void)read(*(int *)arg, buf, sizeof(buf));
	return (NULL);
}

ATF_TC(read_deadline0_exit_sibling);
ATF_TC_HEAD(read_deadline0_exit_sibling, tc)
{
	atf_tc_set_md_var(tc, "descr", "a sibling's _exit ends a read that "
	    "waits with no deadline, within a slice; the controller gets the "
	    "INTERRUPT (D192)");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(read_deadline0_exit_sibling, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	pthread_t thr;
	int64_t start, ms;
	int fd, go[2], oracle, status;
	pid_t pid;
	char ch;

	dqt_fill(data, sizeof(data), 24);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dq_policy_default(&pol);
	pol.dp_deadline_ms = 0;
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	dqt_hold(&c, true);
	ATF_REQUIRE_EQ(0, pipe(go));
	fd = o->fd;
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		if (pthread_create(&thr, NULL, read_forever, &fd) != 0)
			_exit(3);
		if (read(go[0], &ch, 1) != 1)
			_exit(4);
		_exit(0);
	}
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	start = dqt_now_ms();
	ATF_REQUIRE_EQ(1, write(go[1], "g", 1));
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ms = dqt_now_ms() - start;
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK_MSG(ms < 1500, "the exit took %jd ms", (intmax_t)ms);
	ATF_CHECK(dqt_wait_interrupts(&c, 1, DQT_WAIT_MS));
	(void)close(go[0]);
	(void)close(go[1]);
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
}

/*
 * Review 2: as read_deadline0_exit_sibling, but thread B calls abort(3):
 * a signal that dumps core (RLIMIT_CORE 0 still single-threads for the
 * dump).  sigexit marks the process exiting (P2_WEXIT) and single-threads
 * with SINGLE_NO_EXIT, which sets no P_SINGLE_EXIT, and no SIGKILL is
 * delivered after P2_WEXIT; A's wait must still see it within a slice.
 */
static bool
reaped_within(pid_t pid, int *status, int ms)
{
	int64_t end;
	pid_t rv;

	end = dqt_now_ms() + ms;
	for (;;) {
		rv = waitpid(pid, status, WNOHANG);
		ATF_REQUIRE_MSG(rv != -1, "waitpid: %s", strerror(errno));
		if (rv == pid)
			return (true);
		if (dqt_now_ms() >= end)
			return (false);
		dqt_msleep(10);
	}
}

ATF_TC(read_deadline0_abort_sibling);
ATF_TC_HEAD(read_deadline0_abort_sibling, tc)
{
	atf_tc_set_md_var(tc, "descr", "a sibling's abort(3), a signal that "
	    "dumps core, ends a read that waits with no deadline within a "
	    "slice; the controller gets the INTERRUPT (review 2)");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(read_deadline0_abort_sibling, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct rlimit rl;
	pthread_t thr;
	int64_t start, ms;
	int fd, go[2], oracle, status;
	bool reaped;
	pid_t pid;
	char ch;

	dqt_fill(data, sizeof(data), 27);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dq_policy_default(&pol);
	pol.dp_deadline_ms = 0;
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	dqt_hold(&c, true);
	ATF_REQUIRE_EQ(0, pipe(go));
	fd = o->fd;
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		rl.rlim_cur = rl.rlim_max = 0;
		if (setrlimit(RLIMIT_CORE, &rl) != 0)
			_exit(2);
		if (pthread_create(&thr, NULL, read_forever, &fd) != 0)
			_exit(3);
		if (read(go[0], &ch, 1) != 1)
			_exit(4);
		abort();
	}
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	start = dqt_now_ms();
	ATF_REQUIRE_EQ(1, write(go[1], "g", 1));
	reaped = reaped_within(pid, &status, 10000);
	ms = dqt_now_ms() - start;
	if (!reaped) {
		/* Release the read, so the process can finish dying. */
		(void)dq_reply(c.q, dqt_held_id(&c, 0), 0, data, 16);
		ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	}
	ATF_CHECK_MSG(reaped, "the process was still dying 10 s after the "
	    "abort, its read waiting for the controller");
	ATF_CHECK_MSG(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT,
	    "status %#x", status);
	ATF_CHECK_MSG(ms < 1500, "the abort took %jd ms", (intmax_t)ms);
	ATF_CHECK(dqt_wait_interrupts(&c, 1, DQT_WAIT_MS));
	(void)close(go[0]);
	(void)close(go[1]);
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
}

/*
 * D192 (B1): a signal storm during an uninterruptible wait does not make
 * it spin: the waiter sleeps its slices whatever is pending.
 */
struct storm_res {
	struct dqt_rr	 rr;
	long		 cpu_ms;
};

static volatile sig_atomic_t storm_seen;

static void
on_storm(int sig __unused)
{

	storm_seen++;
}

static void
child_read_storm(void *arg, void *result)
{
	struct storm_res *r = result;
	struct sigaction sa;
	struct rusage ru0, ru1;
	int fd = *(int *)arg;
	char buf[16];

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_storm;
	sa.sa_flags = SA_RESTART;
	(void)sigaction(SIGUSR1, &sa, NULL);
	(void)getrusage(RUSAGE_THREAD, &ru0);
	DQT_RR(r->rr, read(fd, buf, sizeof(buf)));
	(void)getrusage(RUSAGE_THREAD, &ru1);
	/* The read's own CPU time, user and system, from before it. */
	r->cpu_ms = (ru1.ru_utime.tv_sec - ru0.ru_utime.tv_sec) * 1000 +
	    (ru1.ru_utime.tv_usec - ru0.ru_utime.tv_usec) / 1000 +
	    (ru1.ru_stime.tv_sec - ru0.ru_stime.tv_sec) * 1000 +
	    (ru1.ru_stime.tv_usec - ru0.ru_stime.tv_usec) / 1000;
}

struct unintr_res {
	struct dqt_rr	 rr;
	long		 ms;
	int		 signals;
};

static void
child_read_sigint(void *arg, void *result)
{
	struct unintr_res *r = result;
	struct sigaction sa;
	int fd = *(int *)arg;
	int64_t start;
	char buf[16];

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_storm;	/* caught, no SA_RESTART */
	(void)sigaction(SIGINT, &sa, NULL);
	start = dqt_now_ms();
	DQT_RR(r->rr, read(fd, buf, sizeof(buf)));
	r->ms = (long)(dqt_now_ms() - start);
	r->signals = storm_seen;
}

ATF_TC(deadline_unintr);
ATF_TC_HEAD(deadline_unintr, tc)
{
	atf_tc_set_md_var(tc, "descr", "a SIGINT storm during a read of a "
	    "200 ms object the controller never answers: the read ends EIO "
	    "at its deadline, not EINTR (rev 8 3.5, D192)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(deadline_unintr, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct unintr_res r;
	struct dqt_child ch;
	int fd, i, oracle;

	dqt_fill(data, sizeof(data), 26);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dq_policy_default(&pol);
	pol.dp_deadline_ms = 200;
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	dqt_hold(&c, true);
	fd = o->fd;
	dqt_spawn(&ch, child_read_sigint, &fd);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	for (i = 0; i < 200; i++)
		if (kill(ch.pid, SIGINT) != 0)
			break;
	memset(&r, 0, sizeof(r));
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.rr.rv);
	ATF_CHECK_EQ(EIO, r.rr.err);
	ATF_CHECK_MSG(r.ms >= 150 && r.ms < 1500, "the read took %ld ms",
	    r.ms);
	ATF_CHECK(r.signals >= 1);
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(signal_storm_no_spin);
ATF_TC_HEAD(signal_storm_no_spin, tc)
{
	atf_tc_set_md_var(tc, "descr", "10000 signals during a 2 s "
	    "uninterruptible read wait: the read completes and its thread "
	    "spends no more than a little CPU time (D192)");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(signal_storm_no_spin, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct storm_res r;
	struct dqt_child ch;
	int fd, i, oracle;

	dqt_fill(data, sizeof(data), 25);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	dqt_hold(&c, true);
	fd = o->fd;
	dqt_spawn(&ch, child_read_storm, &fd);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	for (i = 0; i < 10000; i++) {
		if (kill(ch.pid, SIGUSR1) != 0)
			break;
		if (i % 50 == 0)
			dqt_msleep(10);
	}
	ATF_CHECK_EQ(0, dq_reply(c.q, dqt_held_id(&c, 0), 0, data, 16));
	memset(&r, 0, sizeof(r));
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(16, r.rr.rv, "read: %s", strerror(r.rr.err));
	/*
	 * The handler runs once the read returns (pending signals merge);
	 * the waiting thread itself did nearly nothing for 2 s.
	 */
	printf("the reader used %ld ms of CPU\n", r.cpu_ms);
	ATF_CHECK_MSG(r.cpu_ms < 50, "the reader used %ld ms of CPU",
	    r.cpu_ms);
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, read_oracle);
	ATF_TP_ADD_TC(tp, pread_oracle);
	ATF_TP_ADD_TC(tp, readv_oracle);
	ATF_TP_ADD_TC(tp, aio_read_oracle);
	ATF_TP_ADD_TC(tp, chunk_boundaries);
	ATF_TP_ADD_TC(tp, eof_short_reply);
	ATF_TP_ADD_TC(tp, read_zero_and_past_eof);
	ATF_TP_ADD_TC(tp, seek_data_hole);
	ATF_TP_ADD_TC(tp, shared_offset_two_threads);
	ATF_TP_ADD_TC(tp, two_objects_same_identity);
	ATF_TP_ADD_TC(tp, read_error_reply);
	ATF_TP_ADD_TC(tp, atime_after_read);
	ATF_TP_ADD_TC(tp, atime_eof_and_rdonly);
	ATF_TP_ADD_TC(tp, sigalrm_no_restart);
	ATF_TP_ADD_TC(tp, eintr_reply_refused);
	ATF_TP_ADD_TC(tp, same_identity_atime_diverges);
	ATF_TP_ADD_TC(tp, read_deadline0_exit_sibling);
	ATF_TP_ADD_TC(tp, read_deadline0_abort_sibling);
	ATF_TP_ADD_TC(tp, signal_storm_no_spin);
	ATF_TP_ADD_TC(tp, deadline_unintr);
	return (atf_no_error());
}
