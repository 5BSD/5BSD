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

int
waitpid_timeout(pid_t pid, struct timespec *timeout)
{

	struct kevent change, event;
	int kq, ret, status;

	EV_SET(&change, pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, NULL);

	kq = kqueue();
	if (kq == -1) {
		ERR("kqueue() failed: %s", strerror(errno));
		abort();
	}

	ret = kevent(kq, &change, 1, &event, 1, timeout);
	status = 0xdeadbeef;

	switch (ret) {
	case -1:
		ERR("kevent() error %s (pid=%d)",
		    strerror(errno), pid);
		break;
	case 0:
		status = -1;
		WARN("dtrace timed out (pid=%d)",
		    pid);
		break;
	case 1:
		status = event.data;
		break;
	default:
		break;
	}

	return (status);
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
