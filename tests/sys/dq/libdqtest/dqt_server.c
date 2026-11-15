/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * A controller thread that hands every record of a queue to a dq_handler_t
 * through dq_dispatch(): the loop the served-tree and served-start tests
 * each had a copy of.  See dq_test.h.
 */

#include <sys/param.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

static void *
dqt_server_main(void *arg)
{
	struct dqt_server *sv = arg;
	struct pollfd pfd[2];

	while (!atomic_load(&sv->stop)) {
		pfd[0].fd = sv->q;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		pfd[1].fd = sv->wake[0];
		pfd[1].events = POLLIN;
		pfd[1].revents = 0;
		if (poll(pfd, 2, -1) == -1) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (pfd[1].revents != 0 || atomic_load(&sv->stop))
			break;
		/* The queue was closed under the loop (by a handler). */
		if ((pfd[0].revents & POLLNVAL) != 0)
			break;
		if ((pfd[0].revents & (POLLIN | POLLHUP)) != 0 &&
		    dq_dispatch(sv->q, sv->handler, sv->arg) == -1 &&
		    errno != EAGAIN && errno != EINTR)
			break;
	}
	return (NULL);
}

void
dqt_server_start(struct dqt_server *sv, int q, dq_handler_t handler,
    void *arg)
{
	int flags;

	memset(sv, 0, sizeof(*sv));
	sv->q = q;
	sv->handler = handler;
	sv->arg = arg;
	atomic_init(&sv->stop, false);
	ATF_REQUIRE_EQ(0, pipe2(sv->wake, O_CLOEXEC));
	/* Non-blocking, as dq_dispatch's read must not sleep past a stop. */
	flags = fcntl(q, F_GETFL);
	ATF_REQUIRE(flags != -1);
	ATF_REQUIRE_EQ(0, fcntl(q, F_SETFL, flags | O_NONBLOCK));
	ATF_REQUIRE_EQ(0, pthread_create(&sv->thr, NULL, dqt_server_main,
	    sv));
	sv->running = true;
}

void
dqt_server_stop_async(struct dqt_server *sv)
{

	atomic_store(&sv->stop, true);
}

void
dqt_server_stop(struct dqt_server *sv)
{
	char b = 's';

	if (!sv->running)
		return;
	atomic_store(&sv->stop, true);
	(void)write(sv->wake[1], &b, 1);
	(void)pthread_join(sv->thr, NULL);
	(void)close(sv->wake[0]);
	(void)close(sv->wake[1]);
	sv->running = false;
}
