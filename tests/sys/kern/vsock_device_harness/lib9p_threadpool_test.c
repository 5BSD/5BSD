/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <atf-c.h>

#include "lib9p.h"
#include "threadpool.h"

ATF_TC_WITHOUT_HEAD(connection_dispatch_is_serial);
ATF_TC_BODY(connection_dispatch_is_serial, tc)
{
	struct l9p_threadpool tp;
	struct l9p_worker *worker;
	unsigned int responders, workers;

	ATF_REQUIRE_EQ(l9p_threadpool_init(&tp, L9P_NUMTHREADS), 0);
	responders = 0;
	workers = 0;
	LIST_FOREACH(worker, &tp.ltp_workers, ltw_link) {
		if (worker->ltw_responder)
			responders++;
		else
			workers++;
	}
	ATF_CHECK_EQ(L9P_NUMTHREADS, 1);
	ATF_CHECK_EQ(responders, 1);
	ATF_CHECK_EQ(workers, 1);
	ATF_CHECK_EQ(l9p_threadpool_shutdown(&tp), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, connection_dispatch_is_serial);
	return (atf_no_error());
}
