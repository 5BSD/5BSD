/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Dispatch-layer falsification tests for lib9p's request.c.  A minimal
 * connection is wired to a recording backend so the dispatcher can be driven
 * without a real transport or filesystem.  These pin down two prior bugs:
 *
 *   - l9p_dispatch_tstat() used "type &= L9P_QTDIR" where it meant "&",
 *     rewriting the Rstat qid.type actually sent to the client and erasing
 *     every non-directory type bit (symlink, auth, append, ...).
 *   - create/link/rename/mkdir/... did not reject "." / ".." / a name with
 *     an embedded '/', letting a client smuggle a path into a single
 *     directory entry.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fcall.h"
#include "lib9p.h"
#include "fid.h"
#include "hashtable.h"
#include "backend/backend.h"

/* Recording backend state shared by the stub operations. */
struct rec {
	int	stat_calls;
	int	create_calls;
	int	mkdir_calls;
	int	symlink_calls;
	int	link_calls;
	uint8_t	stat_type;	/* qid.type the stub reports for Tstat */
};

static struct rec rec;

static int
stub_stat(void *softc __unused, struct l9p_request *req)
{

	rec.stat_calls++;
	memset(&req->lr_resp.rstat.stat, 0, sizeof(req->lr_resp.rstat.stat));
	req->lr_resp.rstat.stat.qid.type = rec.stat_type;
	req->lr_resp.rstat.stat.qid.path = UINT64_C(0x1122334455667788);
	return (0);
}

static int
stub_create(void *softc __unused, struct l9p_request *req __unused)
{

	rec.create_calls++;
	return (0);
}

static int
stub_mkdir(void *softc __unused, struct l9p_request *req __unused)
{

	rec.mkdir_calls++;
	return (0);
}

static int
stub_symlink(void *softc __unused, struct l9p_request *req __unused)
{

	rec.symlink_calls++;
	return (0);
}

static int
stub_link(void *softc __unused, struct l9p_request *req __unused)
{

	rec.link_calls++;
	return (0);
}

static void
stub_freefid(void *softc __unused, struct l9p_fid *fid __unused)
{
}

static struct l9p_backend be;
static struct l9p_server server;

static void
setup(struct l9p_connection *conn)
{

	memset(&rec, 0, sizeof(rec));
	memset(&be, 0, sizeof(be));
	be.stat = stub_stat;
	be.create = stub_create;
	be.mkdir = stub_mkdir;
	be.symlink = stub_symlink;
	be.link = stub_link;
	be.freefid = stub_freefid;

	memset(&server, 0, sizeof(server));
	server.ls_backend = &be;
	server.ls_max_version = L9P_2000L;

	memset(conn, 0, sizeof(*conn));
	conn->lc_server = &server;
	conn->lc_version = L9P_2000L;
	conn->lc_msize = 8192;
	conn->lc_max_io_size = 8168;
	ht_init(&conn->lc_files, 16);
}

static struct l9p_fid *
add_fid(struct l9p_connection *conn, uint32_t fidno, uint32_t flags)
{
	struct l9p_fid *f;

	f = l9p_connection_alloc_fid(conn, fidno);
	ATF_REQUIRE(f != NULL);
	f->lo_flags |= flags | L9P_LO_ISVALID;
	return (f);
}

/*
 * A Tstat reply must carry back exactly the qid.type the backend reported.
 * The historical "&= L9P_QTDIR" collapsed every non-directory type to zero.
 */
ATF_TC_WITHOUT_HEAD(tstat_preserves_symlink_qid_type);
ATF_TC_BODY(tstat_preserves_symlink_qid_type, tc)
{
	struct l9p_connection conn;
	struct l9p_request req;

	setup(&conn);
	(void)add_fid(&conn, 1, 0);

	rec.stat_type = L9P_QTSYMLINK;
	memset(&req, 0, sizeof(req));
	req.lr_conn = &conn;
	req.lr_req.hdr.type = L9P_TSTAT;
	req.lr_req.hdr.fid = 1;

	ATF_REQUIRE_EQ(l9p_dispatch_request(&req), 0);
	ATF_CHECK_EQ(rec.stat_calls, 1);
	/* With the bug this is 0 (0x02 & 0x80), mistyping the link. */
	ATF_CHECK_EQ(req.lr_resp.rstat.stat.qid.type, L9P_QTSYMLINK);
}

/*
 * An auth fid ORs in QTAUTH before the directory test; the buggy "&="
 * then erased QTAUTH as well.  Verify both bits survive.
 */
ATF_TC_WITHOUT_HEAD(tstat_preserves_auth_qid_type);
ATF_TC_BODY(tstat_preserves_auth_qid_type, tc)
{
	struct l9p_connection conn;
	struct l9p_request req;

	setup(&conn);
	(void)add_fid(&conn, 1, L9P_LO_ISAUTH);

	rec.stat_type = L9P_QTSYMLINK;
	memset(&req, 0, sizeof(req));
	req.lr_conn = &conn;
	req.lr_req.hdr.type = L9P_TSTAT;
	req.lr_req.hdr.fid = 1;

	ATF_REQUIRE_EQ(l9p_dispatch_request(&req), 0);
	ATF_CHECK((req.lr_resp.rstat.stat.qid.type & L9P_QTAUTH) != 0);
	ATF_CHECK((req.lr_resp.rstat.stat.qid.type & L9P_QTSYMLINK) != 0);
}

/*
 * A directory Tstat must still set the fid's directory flag; the "&" fix
 * keeps that path working.
 */
ATF_TC_WITHOUT_HEAD(tstat_marks_directory_fid);
ATF_TC_BODY(tstat_marks_directory_fid, tc)
{
	struct l9p_connection conn;
	struct l9p_request req;
	struct l9p_fid *f;

	setup(&conn);
	f = add_fid(&conn, 1, 0);

	rec.stat_type = L9P_QTDIR;
	memset(&req, 0, sizeof(req));
	req.lr_conn = &conn;
	req.lr_req.hdr.type = L9P_TSTAT;
	req.lr_req.hdr.fid = 1;

	ATF_REQUIRE_EQ(l9p_dispatch_request(&req), 0);
	ATF_CHECK_EQ(req.lr_resp.rstat.stat.qid.type, L9P_QTDIR);
	ATF_CHECK(l9p_fid_isdir(f));
}

/*
 * Tcreate/Tmkdir/Tsymlink/Tlink must reject a name that is not a single
 * non-dot path component, and must not reach the backend when they do.
 */
ATF_TC_WITHOUT_HEAD(create_rejects_non_component_names);
ATF_TC_BODY(create_rejects_non_component_names, tc)
{
	static const char *bad[] = { "..", ".", "a/b", "", "/x", "d/" };
	struct l9p_connection conn;
	struct l9p_request req;
	size_t i;

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		setup(&conn);
		(void)add_fid(&conn, 1, L9P_LO_ISDIR);

		memset(&req, 0, sizeof(req));
		req.lr_conn = &conn;
		req.lr_req.hdr.type = L9P_TCREATE;
		req.lr_req.hdr.fid = 1;
		req.lr_req.tcreate.name = __DECONST(char *, bad[i]);
		ATF_CHECK_EQ(l9p_dispatch_request(&req), EINVAL);
		ATF_CHECK_EQ(rec.create_calls, 0);

		memset(&req, 0, sizeof(req));
		req.lr_conn = &conn;
		req.lr_req.hdr.type = L9P_TMKDIR;
		req.lr_req.hdr.fid = 1;
		req.lr_req.tmkdir.name = __DECONST(char *, bad[i]);
		ATF_CHECK_EQ(l9p_dispatch_request(&req), EINVAL);
		ATF_CHECK_EQ(rec.mkdir_calls, 0);

		memset(&req, 0, sizeof(req));
		req.lr_conn = &conn;
		req.lr_req.hdr.type = L9P_TSYMLINK;
		req.lr_req.hdr.fid = 1;
		req.lr_req.tsymlink.name = __DECONST(char *, bad[i]);
		ATF_CHECK_EQ(l9p_dispatch_request(&req), EINVAL);
		ATF_CHECK_EQ(rec.symlink_calls, 0);
	}
}

/*
 * A well-formed single-component create name must pass validation and reach
 * the backend -- proving the check is not simply rejecting everything.
 */
ATF_TC_WITHOUT_HEAD(create_accepts_plain_component);
ATF_TC_BODY(create_accepts_plain_component, tc)
{
	struct l9p_connection conn;
	struct l9p_request req;

	setup(&conn);
	(void)add_fid(&conn, 1, L9P_LO_ISDIR);

	memset(&req, 0, sizeof(req));
	req.lr_conn = &conn;
	req.lr_req.hdr.type = L9P_TCREATE;
	req.lr_req.hdr.fid = 1;
	req.lr_req.tcreate.name = __DECONST(char *, "newfile");
	req.lr_req.tcreate.perm = 0644;
	ATF_REQUIRE_EQ(l9p_dispatch_request(&req), 0);
	ATF_CHECK_EQ(rec.create_calls, 1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, tstat_preserves_symlink_qid_type);
	ATF_TP_ADD_TC(tp, tstat_preserves_auth_qid_type);
	ATF_TP_ADD_TC(tp, tstat_marks_directory_fid);
	ATF_TP_ADD_TC(tp, create_rejects_non_component_names);
	ATF_TP_ADD_TC(tp, create_accepts_plain_component);
	return (atf_no_error());
}
