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

#ifndef _DTRACED_STATE_H_
#define _DTRACED_STATE_H_

#include <sys/types.h>
#include <sys/param.h>
#include <sys/event.h>

#include <semaphore.h>

#include "_dtraced_connection.h"
#include "dtraced.h"
#include "dtraced_directory.h"

#include <array>
#include <condition_variable>
#include <list>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_set>
#include <vector>

namespace dtraced {

class job;

/*
 * dtraced state structure. This contains everything relevant to dtraced's
 * state management, such as files that exist, connected sockets, etc.
 */
class state {
	const char **argv; /* needed in case we need to re-exec. */
	int ctrlmachine;   /* is this a control machine? */

	bool setup_threads(void);
	bool setup_socket(void);

	bool destroy_socket(void);

	bool dispatch_read(client_fd *, struct kevent &);
	bool dispatch_write(client_fd *, struct kevent &);
	bool handle_event(struct kevent &);
	bool dispatch_event(struct kevent &);

	bool handle_job(job *);

	std::thread inboundtd; /* inbound monitoring thread */
	std::thread basetd;    /* base monitoring thread */

	size_t threadpool_size; /* size of the thread pool (workers) */
	std::vector<std::thread> workers; /* thread pool for the joblist */

	std::thread socktd; /* config socket thread */
	int sockfd;	    /* config socket filedesc */

	std::thread dtt_listentd; /* read() on dtt_fd */
	std::thread dtt_writetd;  /* write() on dtt_fd */
    public:

	dir *inbounddir;  /* /var/ddtrace/inbound */
	dir *outbounddir; /* /var/ddtrace/outbound */
	dir *basedir;	  /* /var/ddtrace/base */

	/*
	 * Sockets.
	 */
	std::mutex sockfdsmtx;
	std::unordered_set<client_fd *> sockfds;

	/*
	 * Configuration socket.
	 */
	std::mutex sockmtx; /* config socket mutex */
	sem_t socksema;	    /* config socket semaphore */

	/*
	 * dttransport fd and threads
	 */
	int dtt_fd;		  /* dttransport filedesc */

	/*
	 * Thread pool management.
	 */
	std::mutex joblistmtx; /* joblist mutex */
	std::list<job *> joblist;
	std::mutex dispatched_jobsmtx; /* dispatched joblist mutex */

	/* jobs to be picked up by the workers */
	std::list<job *> dispatched_jobs;
	std::condition_variable
	    dispatched_jobscv; /* dispatched joblist condvar */

	/*
	 * Children management.
	 */
	std::thread killtd; /* handle sending kill(SIGTERM) to the guest */
	std::mutex killmtx; /* mutex of the kill list */
	std::queue<pid_t> pids_to_kill; /* a list of pids to kill */
	std::condition_variable killcv; /* kill list condvar */
	std::thread reaptd;		/* handle reaping children */

	std::unordered_set<pid_t> pidlist; /* a list of pids running */
	std::mutex pidlistmtx;		   /* mutex of the pidlist */

	/*
	 * filedesc management.
	 */
	/* dead file descriptor list (to close) */
	std::unordered_set<client_fd *> deadfds;
	std::mutex deadfdsmtx; /* mutex for deadfds */
	std::thread closetd;   /* file descriptor closing thread */

	std::condition_variable jobcleancv; /* job cleaning thread condvar */
	std::thread jobcleantd;		    /* job cleaning thread */

	/*
	 * Consumer threads
	 */
	std::thread consumer_listentd; /* handle consumer messages */
	std::thread consumer_writetd;  /* send messages to consumers */

	std::atomic_int shutdown; /* shutdown flag */
	int nosha;		  /* do we want to checksum? */
	int kq_hdl;		  /* event loop kqueue */

	std::list<std::array<char, DTRACED_PROGIDENTLEN>> identlist;
	std::mutex identlistmtx; /* mutex protecting the ident list */

	state() = default;
	~state() = default;

	bool initialize(int, int, int, const char **);
	bool finalize(void);
	[[noreturn]] void re_exec(void);
	bool is_control_machine(void);

	bool accept_new_connection(void);
	void process_consumers(void);
	void process_joblist(void);
	void close_filedescs(void);
	void manage_children(void);
	void reap_children(void);
	void clean_jobs(void);

	int socket(void);

	void kill_socket(client_fd *);

	bool send_info_async(client_fd *);
};

void _broadcast_shutdown(state &, const char *, int);
#define broadcast_shutdown(_a) _broadcast_shutdown((_a), __FILE__, __LINE__)

}

#endif // _DTRACED_STATE_H_
