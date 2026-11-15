/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * FSYNC (D97, N10): fsync(2), fdatasync(2) and aio_fsync(2) post FSYNC with
 * the fo_fsync mode word whenever the object's policy serves writes,
 * whatever the descriptor's own access mode; under dp_write = DENY nothing
 * can be dirty and the answer is 0 without an event.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <aio.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

#define	DATA_LEN	4096

static unsigned char data[DATA_LEN];
static char path[DQT_PATH_MAX];

struct fsync_res {
	struct dqt_rr	 fsync, fdatasync, aio_full, aio_data;
};

static void
aio_one(int fd, int op, struct dqt_rr *r)
{
	const struct aiocb *list[1];
	struct aiocb cb;

	memset(&cb, 0, sizeof(cb));
	cb.aio_fildes = fd;
	if (aio_fsync(op, &cb) == -1) {
		r->rv = -1;
		r->err = errno;
		return;
	}
	list[0] = &cb;
	while (aio_error(&cb) == EINPROGRESS)
		(void)aio_suspend(list, 1, NULL);
	r->err = aio_error(&cb);
	r->rv = aio_return(&cb);
}

static void
child_fsyncs(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct fsync_res *r = result;

	r->fsync.rv = fsync(fd);
	r->fsync.err = r->fsync.rv == -1 ? errno : 0;
	r->fdatasync.rv = fdatasync(fd);
	r->fdatasync.err = r->fdatasync.rv == -1 ? errno : 0;
	aio_one(fd, O_SYNC, &r->aio_full);
	aio_one(fd, O_DSYNC, &r->aio_data);
}

static struct dqt_object *
setup(struct dqt_ctl *c, int *backing, const struct dq_policy *pol,
    uint32_t mflags)
{

	dqt_fill(data, sizeof(data), 7);
	*backing = dqt_make_oracle("backing", data, sizeof(data), path,
	    sizeof(path));
	(void)close(*backing);
	*backing = open(path, O_RDWR);
	ATF_REQUIRE(*backing != -1);
	dqt_init(c);
	return (dqt_mint_backing(c, *backing, path, pol, mflags));
}

ATF_TC(fsync_events);
ATF_TC_HEAD(fsync_events, tc)
{
	atf_tc_set_md_var(tc, "descr", "fsync posts FSYNC with mode FULL (0), "
	    "fdatasync with DATA (1), and both succeed when the controller "
	    "does; aio_fsync posts the same from the aio daemon when aio(4) "
	    "accepts the descriptor");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fsync_events, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct fsync_res r;
	u_int unsafe;
	int backing;

	o = setup(&c, &backing, NULL, DQ_MINT_F_WRITE);
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_fsyncs, &o->fd, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(0, r.fsync.rv, "fsync: %s", strerror(r.fsync.err));
	ATF_CHECK_EQ_MSG(0, r.fdatasync.rv, "fdatasync: %s",
	    strerror(r.fdatasync.err));
	ATF_REQUIRE(dqt_wait_events(&c, DQ_OP_FSYNC, 2, DQT_WAIT_MS));
	if (dqt_sysctl_get_uint("vfs.aio.enable_unsafe", &unsafe) &&
	    unsafe == 0 && r.aio_full.rv == -1) {
		/* aio(4) refuses a descriptor that is not a local vnode. */
		ATF_CHECK_MSG(r.aio_full.err == EOPNOTSUPP || r.aio_full.err == EINVAL,
		    "aio_fsync: %s", strerror(r.aio_full.err));
		dqt_lock(&c);
		ATF_CHECK_EQ(2, c.events[DQ_OP_FSYNC]);
		dqt_unlock(&c);
	} else {
		ATF_CHECK_EQ(0, r.aio_full.rv);
		ATF_CHECK_EQ(0, r.aio_data.rv);
		ATF_CHECK(dqt_wait_events(&c, DQ_OP_FSYNC, 4, DQT_WAIT_MS));
	}
	dqt_lock(&c);
	ATF_CHECK_EQ(DQ_FSYNC_DATA, o->last_fsync.dfs_mode);
	ATF_CHECK_EQ(0, o->last_fsync.dfs_pad0);
	ATF_CHECK_EQ(0, c.reply_failures);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(backing);
}

ATF_TC(fsync_errors);
ATF_TC_HEAD(fsync_errors, tc)
{
	atf_tc_set_md_var(tc, "descr", "an allowed errno reaches the "
	    "caller (EINVAL, ENOSPC); one outside FSYNC's allow-list (EPERM) "
	    "arrives as EIO");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fsync_errors, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_ident_file *id;
	struct dq_policy pol;
	struct fsync_res r;
	struct dq_stats2 st;
	struct statfs sfs;
	struct stat sb;
	int oracle;

	dqt_fill(data, sizeof(data), 8);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), path,
	    sizeof(path));
	dqt_init(&c);
	id = calloc(1, sizeof(*id));
	ATF_REQUIRE(id != NULL);
	dqt_ident_of(oracle, path, id, &sb, &sfs);
	dqt_policy_write(&pol);
	o = dqt_mint_ident_flags(&c, id, &pol, DQ_MINT_F_WRITE, data,
	    sizeof(data));
	free(id);
	o->serve_errno = EINVAL;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_fsyncs, &o->fd, &r, sizeof(r));
	ATF_CHECK_EQ(EINVAL, r.fsync.err);
	/* K-N3: ENOSPC, EDQUOT and ESTALE joined the FSYNC list. */
	o->serve_errno = ENOSPC;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_fsyncs, &o->fd, &r, sizeof(r));
	ATF_CHECK_EQ(ENOSPC, r.fsync.err);
	o->serve_errno = EPERM;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_fsyncs, &o->fd, &r, sizeof(r));
	ATF_CHECK_EQ(EIO, r.fsync.err);
	ATF_CHECK_EQ(EIO, r.fdatasync.err);
	dqt_stats2(&c, &st);
	ATF_CHECK(st.ds2_bad_replies >= 2);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(readonly_descriptor);
ATF_TC_HEAD(readonly_descriptor, tc)
{
	atf_tc_set_md_var(tc, "descr", "N10: a descriptor minted without "
	    "DQ_MINT_F_WRITE on a write-serving object still posts FSYNC "
	    "(another descriptor may have written)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(readonly_descriptor, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct fsync_res r;
	int backing;

	o = setup(&c, &backing, NULL, 0);
	ATF_CHECK_EQ(O_RDONLY, fcntl(o->fd, F_GETFL) & O_ACCMODE);
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_fsyncs, &o->fd, &r, sizeof(r));
	ATF_CHECK_EQ(0, r.fsync.rv);
	ATF_CHECK(dqt_wait_events(&c, DQ_OP_FSYNC, 2, DQT_WAIT_MS));
	dqt_fini(&c);
	(void)close(backing);
}

ATF_TC(write_deny_local);
ATF_TC_HEAD(write_deny_local, tc)
{
	atf_tc_set_md_var(tc, "descr", "dp_write = DENY: fsync and fdatasync "
	    "answer 0 locally, in the controller process too, and post "
	    "nothing");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(write_deny_local, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	int backing;

	dq_policy_default(&pol);
	o = setup(&c, &backing, &pol, 0);
	ATF_CHECK_EQ(0, fsync(o->fd));
	ATF_CHECK_EQ(0, fdatasync(o->fd));
	dqt_msleep(100);
	dqt_lock(&c);
	ATF_CHECK_EQ(0, c.records);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(backing);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fsync_events);
	ATF_TP_ADD_TC(tp, fsync_errors);
	ATF_TP_ADD_TC(tp, readonly_descriptor);
	ATF_TP_ADD_TC(tp, write_deny_local);
	return (atf_no_error());
}
