/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fcall.h"
#include "lib9p.h"

static void
setup_request(struct l9p_request *request, struct l9p_connection *connection,
    struct l9p_server *server, uint32_t msize, const char *version)
{

	memset(server, 0, sizeof(*server));
	server->ls_max_version = L9P_2000L;
	memset(connection, 0, sizeof(*connection));
	connection->lc_server = server;
	connection->lc_version = L9P_INVALID_VERSION;
	connection->lc_msize = 8192;
	connection->lc_max_io_size = 4096;
	memset(request, 0, sizeof(*request));
	request->lr_conn = connection;
	request->lr_req.version.hdr.type = L9P_TVERSION;
	request->lr_req.version.msize = msize;
	request->lr_req.version.version = __DECONST(char *, version);
}

ATF_TC_WITHOUT_HEAD(msize_overhead_boundary);
ATF_TC_BODY(msize_overhead_boundary, tc)
{
	struct l9p_connection connection;
	struct l9p_request request;
	struct l9p_server server;

	setup_request(&request, &connection, &server, 24, "9P2000.L");
	ATF_CHECK_EQ(l9p_dispatch_request(&request), EINVAL);
	ATF_CHECK_EQ(connection.lc_version, L9P_INVALID_VERSION);
	ATF_CHECK_EQ(connection.lc_msize, 8192);
	ATF_CHECK_EQ(connection.lc_max_io_size, 4096);
	ATF_CHECK_EQ(request.lr_resp.version.version, NULL);
	ATF_CHECK_EQ(request.lr_resp.version.msize, 0);

	setup_request(&request, &connection, &server, 25, "9P2000.L");
	ATF_REQUIRE_EQ(l9p_dispatch_request(&request), 0);
	ATF_CHECK_EQ(connection.lc_version, L9P_2000L);
	ATF_CHECK_EQ(connection.lc_msize, 25);
	ATF_CHECK_EQ(connection.lc_max_io_size, 1);
	ATF_CHECK_STREQ(request.lr_resp.version.version, "9P2000.L");
	ATF_CHECK_EQ(request.lr_resp.version.msize, 25);
	free(request.lr_resp.version.version);
}

ATF_TC_WITHOUT_HEAD(rejected_version_is_atomic);
ATF_TC_BODY(rejected_version_is_atomic, tc)
{
	struct l9p_connection connection;
	struct l9p_request request;
	struct l9p_server server;

	setup_request(&request, &connection, &server, 8192, "not-9P");
	ATF_CHECK_EQ(l9p_dispatch_request(&request), ENOSYS);
	ATF_CHECK_EQ(connection.lc_version, L9P_INVALID_VERSION);
	ATF_CHECK_EQ(connection.lc_msize, 8192);
	ATF_CHECK_EQ(connection.lc_max_io_size, 4096);
	ATF_CHECK_EQ(request.lr_resp.version.version, NULL);
	ATF_CHECK_EQ(request.lr_resp.version.msize, 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, msize_overhead_boundary);
	ATF_TP_ADD_TC(tp, rejected_version_is_atomic);
	return (atf_no_error());
}
