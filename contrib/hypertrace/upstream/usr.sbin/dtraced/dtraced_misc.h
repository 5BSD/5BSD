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

#ifndef _DTRACED_MISC_H_
#define _DTRACED_MISC_H_

#include <sys/types.h>
#include <sys/event.h>

#include <dirent.h>
#include <libutil.h>
#include <time.h>

#include "_dtraced_connection.h"

#define unlikely(x) __predict_false(x)

#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define __NOSANITIZE_THREAD __attribute__((no_sanitize("thread")))
#else
#define __NOSANITIZE_THREAD
#endif /* __has_feature(thread_sanitizer) */
#else
#define __NOSANITIZE_THREAD
#endif /* defined(__has_feature) */

#define __cleanup(fn) __attribute__((__cleanup__(fn)))
#define __maybe_unused(x) ((void)x)

#define DTRACED_SLEEPTIME		10000	/* microseconds */
#define DTRACED_EVENTSLEEPTIME		1	/* seconds */
#define DTRACED_CLOSEFD_SLEEPTIME	5	/* seconds */
#define DTRACED_WAITPID_SLEEPTIME	10	/* seconds */

namespace dtraced {

class state;

void closefd_generic(int *);
void cleanup_pidfile(struct pidfh **);
int  waitpid_timeout(pid_t, struct timespec *);
int event(state &, int, const struct kevent *, int, struct kevent *, int,
    const struct timespec *);
}

#endif // _DTRACED_MISC_H_
