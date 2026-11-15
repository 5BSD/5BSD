/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * dp_cache = DQ_CACHE_DATA (D103): read(2) is served from the object's
 * pages, a miss posts READ for whole pages, INVALIDATE drops clean pages,
 * an accepted WRITE updates the resident pages (a refused one does not),
 * fsync flushes dirty mapping pages (WRITE_ASYNC) before posting FSYNC,
 * and a SETIDENT that shrinks the file trims the cache.
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

#define	DATA_LEN	(3 * 4096 + 500)

static unsigned char data[DATA_LEN];
static char path[DQT_PATH_MAX];

static void
policy_data(struct dq_policy *pol, bool write)
{

	if (write)
		dqt_policy_write(pol);
	else
		dq_policy_default(pol);
	pol->dp_cache = DQ_CACHE_DATA;
	if (write)
		pol->dp_mmap_shared_write = DQ_ALLOW;
}

struct rd_arg {
	int		 fd;
	off_t		 off;
	size_t		 len;
	unsigned char	 wbyte;		/* pwrite mode: this byte at off */
	int		 write;
};

struct rd_res {
	struct dqt_rr	 r;
	unsigned char	 buf[16];	/* the first bytes read */
	uint64_t	 hash;		/* FNV-1a of all of them */
};

static uint64_t
digest(const unsigned char *p, size_t len)
{
	uint64_t h;
	size_t i;

	h = 14695981039346656037ULL;
	for (i = 0; i < len; i++) {
		h ^= p[i];
		h *= 1099511628211ULL;
	}
	return (h);
}

static void
child_io(void *arg, void *result)
{
	struct rd_arg *a = arg;
	struct rd_res *r = result;

	if (a->write)
		r->r.rv = pwrite(a->fd, &a->wbyte, 1, a->off);
	else {
		unsigned char *b;

		b = malloc(a->len);
		r->r.rv = b == NULL ? -1 : pread(a->fd, b, a->len, a->off);
		if (r->r.rv > 0) {
			memcpy(r->buf, b, MIN((size_t)r->r.rv, sizeof(r->buf)));
			r->hash = digest(b, (size_t)r->r.rv);
		}
		free(b);
	}
	r->r.err = r->r.rv == -1 ? errno : 0;
}

static void
do_io(int fd, int write, off_t off, size_t len, unsigned char wbyte,
    struct rd_res *r)
{
	struct rd_arg a;

	a.fd = fd;
	a.write = write;
	a.off = off;
	a.len = len;
	a.wbyte = wbyte;
	memset(r, 0, sizeof(*r));
	dqt_run_child(child_io, &a, r, sizeof(*r));
}

static struct dqt_object *
mint_memory(struct dqt_ctl *c, int oracle)
{
	struct dq_policy pol;

	policy_data(&pol, false);
	return (dqt_mint(c, oracle, path, data, sizeof(data), &pol));
}

ATF_TC(second_read_cached);
ATF_TC_HEAD(second_read_cached, tc)
{
	atf_tc_set_md_var(tc, "descr", "the first read posts page-aligned READs; "
	    "a second read of the same bytes, by another process, posts "
	    "nothing and returns the same bytes");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(second_read_cached, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct rd_res r;
	unsigned reads;
	int i, oracle;

	dqt_fill(data, sizeof(data), 1);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), path,
	    sizeof(path));
	dqt_init(&c);
	o = mint_memory(&c, oracle);
	do_io(o->fd, 0, 0, DATA_LEN, 0, &r);
	ATF_REQUIRE_EQ(DATA_LEN, r.r.rv);
	ATF_CHECK(r.hash == digest(data, DATA_LEN));
	reads = dqt_events(&c, DQ_OP_READ);
	ATF_CHECK(reads >= 1);
	dqt_lock(&c);
	for (i = 0; i < c.nrd; i++)
		ATF_CHECK_EQ(0, c.rd[i].offset % 4096);
	dqt_unlock(&c);
	do_io(o->fd, 0, 0, DATA_LEN, 0, &r);
	ATF_REQUIRE_EQ(DATA_LEN, r.r.rv);
	ATF_CHECK(r.hash == digest(data, DATA_LEN));
	dqt_lock(&c);
	ATF_CHECK_EQ(reads, c.events[DQ_OP_READ]);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(invalidate_reposts);
ATF_TC_HEAD(invalidate_reposts, tc)
{
	atf_tc_set_md_var(tc, "descr", "after INVALIDATE the next read posts "
	    "READ again and sees the controller's new bytes");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(invalidate_reposts, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct rd_res r;
	unsigned reads;
	int oracle;

	dqt_fill(data, sizeof(data), 2);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), path,
	    sizeof(path));
	dqt_init(&c);
	o = mint_memory(&c, oracle);
	do_io(o->fd, 0, 0, DATA_LEN, 0, &r);
	ATF_REQUIRE_EQ(DATA_LEN, r.r.rv);
	reads = dqt_events(&c, DQ_OP_READ);
	pthread_mutex_lock(&c.mtx);
	data[4100] = (unsigned char)~data[4100];
	pthread_mutex_unlock(&c.mtx);
	ATF_REQUIRE_EQ(0, dq_push_invalidate(c.q, o->id, 4096, 4096));
	do_io(o->fd, 0, 4100, 1, 0, &r);
	ATF_REQUIRE_EQ(1, r.r.rv);
	ATF_CHECK_EQ(data[4100], r.buf[0]);
	dqt_lock(&c);
	ATF_CHECK(c.events[DQ_OP_READ] > reads);
	dqt_unlock(&c);
	/* The pages outside the range stayed. */
	reads = dqt_events(&c, DQ_OP_READ);
	do_io(o->fd, 0, 0, 100, 0, &r);
	dqt_lock(&c);
	ATF_CHECK_EQ(reads, c.events[DQ_OP_READ]);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(write_after_acceptance);
ATF_TC_HEAD(write_after_acceptance, tc)
{
	atf_tc_set_md_var(tc, "descr", "a WRITE the controller refuses leaves "
	    "the cached bytes as they were; an accepted one replaces them, "
	    "and neither later read posts a READ");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(write_after_acceptance, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct dqt_child ch;
	struct rd_arg a;
	struct rd_res r;
	unsigned reads;
	int backing;

	dqt_fill(data, sizeof(data), 3);
	backing = dqt_make_oracle("backing", data, sizeof(data), path,
	    sizeof(path));
	(void)close(backing);
	backing = open(path, O_RDWR);
	ATF_REQUIRE(backing != -1);
	dqt_init(&c);
	policy_data(&pol, true);
	o = dqt_mint_backing(&c, backing, path, &pol, DQ_MINT_F_WRITE);
	do_io(o->fd, 0, 0, DATA_LEN, 0, &r);
	ATF_REQUIRE_EQ(DATA_LEN, r.r.rv);
	reads = dqt_events(&c, DQ_OP_READ);

	dqt_hold(&c, true);
	a.fd = o->fd;
	a.write = 1;
	a.off = 10;
	a.len = 1;
	a.wbyte = (unsigned char)~data[10];
	dqt_spawn(&ch, child_io, &a);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	dqt_lock(&c);
	ATF_REQUIRE_EQ(DQ_OP_WRITE, c.held[0].op);
	ATF_REQUIRE_EQ(0, dq_reply(c.q, c.held[0].id, EIO, NULL, 0));
	dqt_unlock(&c);
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(EIO, r.r.err);
	dqt_hold(&c, false);
	do_io(o->fd, 0, 10, 1, 0, &r);
	ATF_CHECK_EQ(data[10], r.buf[0]);
	dqt_lock(&c);
	ATF_CHECK_EQ(reads, c.events[DQ_OP_READ]);
	dqt_unlock(&c);

	do_io(o->fd, 1, 10, 1, (unsigned char)~data[10], &r);
	ATF_REQUIRE_EQ(1, r.r.rv);
	do_io(o->fd, 0, 10, 1, 0, &r);
	ATF_CHECK_EQ((unsigned char)~data[10], r.buf[0]);
	dqt_lock(&c);
	ATF_CHECK_EQ(reads, c.events[DQ_OP_READ]);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(backing);
}

static void
child_map_fsync(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct dqt_rr *r = result;
	unsigned char *p;

	p = mmap(NULL, DATA_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		_exit(3);
	if (dqt_touch(p + 4096 + 3, true, 0xc3, NULL) != 0)
		_exit(4);
	r->rv = fsync(fd);
	r->err = r->rv == -1 ? errno : 0;
}

ATF_TC(fsync_flushes_first);
ATF_TC_HEAD(fsync_flushes_first, tc)
{
	atf_tc_set_md_var(tc, "descr", "fsync writes the dirty pages of a "
	    "shared mapping back (WRITE_ASYNC) before it posts FSYNC");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fsync_flushes_first, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct dqt_rr r;
	unsigned char got;
	int backing;

	dqt_fill(data, sizeof(data), 4);
	backing = dqt_make_oracle("backing", data, sizeof(data), path,
	    sizeof(path));
	(void)close(backing);
	backing = open(path, O_RDWR);
	ATF_REQUIRE(backing != -1);
	dqt_init(&c);
	policy_data(&pol, true);
	o = dqt_mint_backing(&c, backing, path, &pol, DQ_MINT_F_WRITE);
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_map_fsync, &o->fd, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(0, r.rv, "fsync: %s", strerror(r.err));
	dqt_lock(&c);
	ATF_REQUIRE(c.events[DQ_OP_WRITE_ASYNC] >= 1);
	ATF_REQUIRE_EQ(1, c.events[DQ_OP_FSYNC]);
	ATF_CHECK(c.op_seq[DQ_OP_WRITE_ASYNC] < c.op_seq[DQ_OP_FSYNC]);
	dqt_unlock(&c);
	ATF_REQUIRE_EQ(1, pread(backing, &got, 1, 4096 + 3));
	ATF_CHECK_EQ(0xc3, got);
	dqt_fini(&c);
	(void)close(backing);
}

ATF_TC(shrink_trims_cache);
ATF_TC_HEAD(shrink_trims_cache, tc)
{
	atf_tc_set_md_var(tc, "descr", "a SETIDENT that shrinks the file trims "
	    "the cache: a read returns the new size's bytes and nothing past "
	    "it, without asking the controller for cached pages");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(shrink_trims_cache, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_ident_file *id;
	struct rd_res r;
	struct stat sb;
	int oracle;

	dqt_fill(data, sizeof(data), 5);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), path,
	    sizeof(path));
	dqt_init(&c);
	o = mint_memory(&c, oracle);
	do_io(o->fd, 0, 0, DATA_LEN, 0, &r);
	ATF_REQUIRE_EQ(DATA_LEN, r.r.rv);
	id = calloc(1, sizeof(*id));
	ATF_REQUIRE(id != NULL);
	*id = o->ident;
	id->di_size = 4096 + 10;
	pthread_mutex_lock(&c.mtx);
	o->len = 4096 + 10;
	o->ident = *id;
	pthread_mutex_unlock(&c.mtx);
	ATF_REQUIRE_EQ(0, dq_set_ident(c.q, o->id, id));
	free(id);
	do_io(o->fd, 0, 0, DATA_LEN, 0, &r);
	ATF_CHECK_EQ(4096 + 10, r.r.rv);
	ATF_CHECK(r.hash == digest(data, 4096 + 10));
	ATF_REQUIRE_EQ(0, fstat(o->fd, &sb));
	ATF_CHECK_EQ(4096 + 10, sb.st_size);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, second_read_cached);
	ATF_TP_ADD_TC(tp, invalidate_reposts);
	ATF_TP_ADD_TC(tp, write_after_acceptance);
	ATF_TP_ADD_TC(tp, fsync_flushes_first);
	ATF_TP_ADD_TC(tp, shrink_trims_cache);
	return (atf_no_error());
}
