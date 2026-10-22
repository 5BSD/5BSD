/*-
 * Copyright (c) 2020 Domagoj Stolfa
 * Copyright (c) 2021 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from Arm Limited.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from the Kenneth Hayter Scholarship Fund.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/event.h>

#include <sys/wait.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced_connection.h"
#include "dtraced_errmsg.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

namespace dtraced {

void
closefd_generic(int *fd)
{

	if (*fd != -1)
		close(*fd);
}

void
cleanup_pidfile(struct pidfh **pfh)
{

	if (*pfh)
		if (pidfile_remove(*pfh))
			ERR("Could not remove pidfile: %m");
}

/* Caller owns this child until it transfers a timed-out PID to pidlist. */
int
waitpid_timeout(pid_t pid, struct timespec *timeout)
{
	struct timespec start, now, elapsed;
	const struct timespec interval = { 0, 10000000 };
	int status;
	pid_t result;

	if (pid <= 1 || timeout == nullptr || timeout->tv_sec < 0 ||
	    timeout->tv_nsec < 0 || timeout->tv_nsec >= 1000000000) {
		errno = EINVAL;
		return (-1);
	}
	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		return (-1);
	for (;;) {
		result = waitpid(pid, &status, WNOHANG);
		if (result == pid)
			return (status);
		if (result == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			return (-1);
		elapsed.tv_sec = now.tv_sec - start.tv_sec;
		elapsed.tv_nsec = now.tv_nsec - start.tv_nsec;
		if (elapsed.tv_nsec < 0) {
			elapsed.tv_sec--;
			elapsed.tv_nsec += 1000000000;
		}
		if (elapsed.tv_sec > timeout->tv_sec ||
		    (elapsed.tv_sec == timeout->tv_sec &&
		    elapsed.tv_nsec >= timeout->tv_nsec)) {
			errno = ETIMEDOUT;
			return (-1);
		}
		(void)nanosleep(&interval, nullptr);
	}
}

int
event(state &s, int kq, const struct kevent *changelist, int nchanges,
    struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
	int new_events;

	new_events = 0;
	while (s.shutdown.load() == 0 && new_events == 0) {
		new_events = kevent(kq, changelist, nchanges, eventlist,
		    nevents, timeout);
		if (new_events == -1)
			return (-1);
	}

	return (new_events);
}

}
