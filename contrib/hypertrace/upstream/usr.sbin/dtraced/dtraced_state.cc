/*-
 * Copyright (c) 2020 Domagoj Stolfa
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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_dttransport.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

namespace dtraced {

const static int DTRACED_BACKLOG_SIZE = 10000;

bool
state::setup_threads(void)
{
	this->workers.resize(this->threadpool_size);
	for (size_t i = 0; i < this->threadpool_size; i++)
		this->workers[i] = std::thread(&state::process_joblist, this);

	sem_init(&this->socksema, 0, 0);

	if (this->ctrlmachine == 0) {
		this->dtt_listentd = std::thread(&dtraced::listen_dttransport, this);
		this->dtt_writetd = std::thread(&dtraced::write_dttransport, this);
	}

	this->socktd = std::thread(&state::process_consumers, this);
	this->inboundtd = std::thread(&dir::listen, this->inbounddir);
	this->basetd = std::thread(&dir::listen, this->basedir);
	this->killtd = std::thread(&state::manage_children, this);
	this->reaptd = std::thread(&state::reap_children, this);
	this->closetd = std::thread(&state::close_filedescs, this);
	this->jobcleantd = std::thread(&state::clean_jobs, this);

	return (true);
}

bool
state::setup_socket(void)
{
	int err;
	struct sockaddr_un addr;
	size_t l;

	this->sockfd = ::socket(PF_UNIX, SOCK_STREAM, 0);
	if (this->sockfd == -1) {
		ERR("Failed to create unix: %m");
		return (false);
	}

	memset(&addr, 0, sizeof(addr));

	addr.sun_family = PF_UNIX;
	l = strlcpy(addr.sun_path, DTRACED_SOCKPATH, sizeof(addr.sun_path));
	if (l >= sizeof(addr.sun_path)) {
		ERR("failed to copy %s into sockaddr (%zu)", DTRACED_SOCKPATH,
		    l);
		close(this->sockfd);
		this->sockfd = -1;
		if (err != 0)
			ERR("failed to destroy sockmtx: %m");

		return (false);
	}

	if (remove(DTRACED_SOCKPATH) != 0) {
		if (errno != ENOENT) {
			ERR("failed to remove %s: %m", DTRACED_SOCKPATH);
			return (false);
		}
	}

	err = bind(this->sockfd, (struct sockaddr *)&addr, sizeof(addr));
	if (err != 0) {
		ERR("failed to bind to %d: %m", this->sockfd);
		close(this->sockfd);
		this->sockfd = -1;
		if (err != 0)
			ERR("failed to destroy sockmtx: %m");

		return (false);
	}

	return (true);
}

bool
state::initialize(int ctrlmachine, int nosha, int n_threads, const char **argv)
{
	this->ctrlmachine = ctrlmachine;
	this->argv = argv;
	this->nosha = nosha;
	this->threadpool_size = n_threads;

	if (this->ctrlmachine == 0) {
		this->dtt_fd = open("/dev/dttransport",
		    O_RDWR | O_CLOEXEC | O_NONBLOCK);
		if (this->dtt_fd == -1) {
			ERR("failed to open /dev/dttransport: %m");
			return (false);
		}
	}

	this->outbounddir = new dir(OUTBOUNDDIR, &process_outbound);
	if (this->outbounddir == NULL) {
		ERR("failed creating outbound directory: %m");
		return (false);
	}

	this->inbounddir = new dir(INBOUNDDIR, &process_inbound);
	if (this->inbounddir == NULL) {
		ERR("failed creating inbound directory: %m");
		return (false);
	}

	this->basedir = new dir(BASEDIR, &process_base);
	if (this->basedir == NULL) {
		ERR("failed creating base directory: %m");
		return (false);
	}

	this->outbounddir->state = this;
	this->inbounddir->state = this;
	this->basedir->state = this;

	if (!this->setup_socket()) {
		ERR("failed to set up the socket");
		return (false);
	}

	if (!this->outbounddir->populate_existing()) {
		ERR("failed to populate outbound existing files");
		return (false);
	}

	if (!this->inbounddir->populate_existing()) {
		ERR("failed to populate inbound existing files");
		return (false);
	}

	if (!this->basedir->populate_existing()) {
		ERR("failed to populate base existing files");
		return (false);
	}

	if (!this->setup_threads()) {
		ERR("failed to set up threads");
		return (false);
	}

	return (true);
}

bool
state::destroy_socket(void)
{
	if (close(this->sockfd) != 0) {
		ERR("failed to close %d: %m", this->sockfd);
		return (false);
	}

	this->sockfd = -1;

	if (remove(DTRACED_SOCKPATH) != 0) {
		ERR("failed to remove %s: %m", DTRACED_SOCKPATH);
		return (false);
	}

	return (true);
}

bool
state::finalize(void)
{
	size_t i;

	/*
	 * Give all the threads a chance to stop.
	 */
	this->socktd.join();
	if (this->ctrlmachine == 0) {
		this->dtt_listentd.join();
		this->dtt_writetd.join();
	}

	this->inboundtd.join();
	this->basetd.join();

	{
		std::lock_guard lk(this->dispatched_jobsmtx);
		this->dispatched_jobscv.notify_all();
	}

	for (i = 0; i < this->threadpool_size; i++) {
		this->workers[i].join();
	}

	this->killtd.join();
	this->reaptd.join();
	this->closetd.join();
	this->jobcleantd.join();

	{
		std::lock_guard lk(this->joblistmtx);
		for (; !this->joblist.empty(); this->joblist.pop_front())
			delete this->joblist.front();
	}

	{
		std::lock_guard lk(this->dispatched_jobsmtx);
		for (; !this->dispatched_jobs.empty();
		     this->dispatched_jobs.pop_front())
			delete this->dispatched_jobs.front();
	}

	delete this->outbounddir;
	delete this->inbounddir;
	delete this->basedir;

	sem_destroy(&this->socksema);

	if (!this->destroy_socket())
		return (false);

	if (this->ctrlmachine == 0) {
		close(this->dtt_fd);
		this->dtt_fd = -1;
	}

	return (true);
}

void
_broadcast_shutdown(state &s, const char *errfile, int errline)
{
	fprintf(stderr, "%s (line %d): broadcasting shutdown\n", errfile,
	    errline);
	s.shutdown.store(1);

	{
		std::lock_guard lk(s.dispatched_jobsmtx);
		s.dispatched_jobscv.notify_all();
	}

	{
		std::lock_guard lk(s.killmtx);
		s.killcv.notify_all();
	}

	{
		std::lock_guard lk(s.deadfdsmtx);
		s.jobcleancv.notify_all();
	}
}

bool
state::accept_new_connection(void)
{
	int connsockfd;
	int on = 1;
	dtd_initmsg_t initmsg;

	memset(&initmsg, 0, sizeof(initmsg));

	connsockfd = accept(this->sockfd, NULL, 0);
	if (connsockfd == -1) {
		ERR("accept() failed: %m");
		return (false);
	}

	if (setsockopt(connsockfd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on))) {
		close(connsockfd);
		ERR("setsockopt() failed: %m");
		return (false);
	}

	initmsg.kind = DTRACED_KIND_DTRACED;
	if (send(connsockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		close(connsockfd);
		ERR("send() initmsg to connsockfd failed: %m");
		return (false);
	}

	memset(&initmsg, 0, sizeof(initmsg));
	if (recv(connsockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		close(connsockfd);
		ERR("recv() get initmsg failed: %m");
		return (false);
	}

	client_fd *dfdp = new client_fd(this->kq_hdl, connsockfd, initmsg);
	if (dfdp == nullptr) {
		LOG("new client_fd() failed");
		close(connsockfd);
		return (false);
	}

	client_fd &dfd = *dfdp;
	if (!dfd.enable_rw((void *)dfdp)) {
		close(connsockfd);
		delete dfdp;
		return (false);
	}

	LOG("accept(%d, %x, 0x%x, %s)", dfd.fd, dfd.kind, dfd.subs, dfd.ident);

	{
		std::lock_guard lk(this->sockfdsmtx);
		this->sockfds.insert(dfdp);
	}

	if (dfd.is_subscribed(DTD_SUB_INFO))
		this->send_info_async(dfdp);

	return (true);
}

void
state::kill_socket(client_fd *dfdp)
{
	client_fd &dfd = *dfdp;

	/* Remove it from the socket list and shutdown */
	{
		std::lock_guard lk(this->sockfdsmtx);
		this->sockfds.erase(dfdp);
	}

	dfd.shutdown();

	/*
	 * Add it to the deadfds list and let it get cleaned up by other
	 * threads.
	 */
	std::unique_lock lk(this->deadfdsmtx);
	this->deadfds.insert(dfdp);
	this->jobcleancv.notify_all();
}

bool
state::send_info_async(client_fd *dfdp)
{
	job *j;

	j = new job(SEND_INFO, dfdp);
	if (j == nullptr)
		return (false);

	std::unique_lock lk(this->joblistmtx);
	this->joblist.push_back(j);
	return (true);
}

int
state::socket(void)
{

	return (this->sockfd);
}

bool
state::is_control_machine(void)
{

	return (this->ctrlmachine != 0);
}

[[noreturn]] void
state::re_exec(void)
{

	execve(this->argv[0], (char *const *)this->argv, NULL);
	abort();
}

bool
state::handle_event(struct kevent &event)
{
	client_fd *dfdp = (client_fd *)event.udata;
	int efd = event.ident;

	if (efd == sockfd && event.flags & EV_ERROR) {
		ERR("error on %s: %m", DTRACED_SOCKPATH);
		return (false);
	}

	if (efd == sockfd && event.flags & EV_EOF) {
		ERR("EOF on %s: %m", DTRACED_SOCKPATH);
		return (false);
	}

	if (event.flags & EV_ERROR || event.flags & EV_EOF) {
		assert(efd != sockfd && "EOF || ERROR on sockfd");
		assert(efd == dfdp->fd);

		if (disable_rw(this->kq_hdl, efd)) {
			ERR("disable_rw() failed: %m");
			return (false);
		}

		this->kill_socket(dfdp);
		if (event.flags & EV_ERROR)
			ERR("event error: %m");
	} else if (efd == sockfd) {
		/*
		 * New connection incoming. dfd is NULL so we
		 * don't have to release it.
		 */
		assert(event.filter == EVFILT_READ);

		if (!this->accept_new_connection())
			return (true);
	} else if (event.filter == EVFILT_READ) {
		assert(efd != sockfd && "read on sockfd");
		assert(efd == dfdp->fd);

		if (!this->dispatch_read(dfdp, event))
			return (false);
	} else if (event.filter == EVFILT_WRITE) {
		assert(efd != sockfd && "write on sockfd");
		assert(efd == dfdp->fd);

		if (!this->dispatch_write(dfdp, event))
			return (false);
	}

	return (true);
}

void
state::process_consumers(void)
{
	int new_events, err, sockfd;
	__cleanup(closefd_generic) int kq = -1;
	struct timespec ts;
	struct kevent event[1] = { {} };

	sockfd = this->sockfd;
	if (sockfd == -1)
		return;

	err = listen(sockfd, DTRACED_BACKLOG_SIZE);
	if (err != 0) {
		ERR("failed to listen on %d: %m", sockfd);
		broadcast_shutdown(*this);
		return;
	}

	kq = kqueue();
	if (kq == -1) {
		ERR("failed to create dtraced socket kqueue: %m");
		broadcast_shutdown(*this);
		return;
	}

	if (enable_fd(kq, sockfd, EVFILT_READ, NULL)) {
		ERR("failed to register listening socket kevent: %m");
		close(kq);
		broadcast_shutdown(*this);
		return;
	}

	this->kq_hdl = kq;
	(void) sem_post(&this->socksema);

	ts.tv_sec = DTRACED_EVENTSLEEPTIME;
	ts.tv_nsec = 0;
	for (;;) {
		new_events = dtraced::event(*this, kq, NULL, 0, event, 1, &ts);

		if (this->shutdown.load())
			break;

		if (new_events == -1) {
			ERR("dtraced::event failed: %m");
			broadcast_shutdown(*this);
			return;
		}

		for (int i = 0; i < new_events; i++) {
			if (!this->handle_event(event[i]))
				ERR("failed to handle event");
		}
	}

	return;
}

bool
state::dispatch_read(client_fd *dfdp, struct kevent &event)
{
	/*
	 * Disable the EVFILT_READ event so we don't get spammed by it.
	 */
	if (disable_fd(this->kq_hdl, dfdp->fd, EVFILT_READ)) {
		ERR("disable_fd() failed with: %m");
		return (false);
	}

	/*
	 * If the file descriptor did not state it ever wants READDATA to work
	 * on dtraced, we will simply ignore it and report a warning.
	 */
	if (!dfdp->is_subscribed(DTD_SUB_READDATA)) {
		WARN("socket %d tried to READDATA, but is not subscribed (%lx)",
		    dfdp->fd, dfdp->subs);
		return (true);
	}

	if (!this->dispatch_event(event)) {
		ERR("dispatch_event() failed");
		return (false);
	}

	return (true);
}

bool
state::dispatch_write(client_fd *dfdp, struct kevent &event)
{
	client_fd &dfd = *dfdp;

	if (disable_fd(this->kq_hdl, dfd.fd, EVFILT_WRITE)) {
		ERR("disable_fd() failed with: %m");
		return (false);
	}

	bool dispatch = false;

	std::unique_lock lk(this->joblistmtx);
	for (job *job : this->joblist) {
		if (job->connsockfd == dfdp)
			dispatch = true;
	}

	/*
	 * If we have a job to dispatch to the socket, we tell a worker thread
	 * to actually do the action.
	 */
	if (dispatch && !this->dispatch_event(event)) {
		ERR("dispatch_event() failed");
		/*
		 * Necessary because broadcast_shutdown acquires a few locks.
		 */
		lk.unlock();
		return (false);
	}

	return (true);
}

bool
state::dispatch_event(struct kevent &event)
{
	client_fd *dfdp;
	job *j;
	int efd;

	efd = (int)event.ident;

	if (event.filter == EVFILT_READ) {
		dfdp = (client_fd *)event.udata;

		/*
		 * Read is a little bit more complicated than write, because we
		 * have to read in the actual event and put it in the
		 * /var/ddtrace/base directory for the directory monitoring
		 * kqueues to wake up and process it further.
		 */
		j = new job(READ_DATA, dfdp);
		if (j == nullptr) {
			ERR("new job(READ_DATA, %s) failed with: %m", dfdp->ident);
			abort(); // Allocation failure
		}

		std::lock_guard lk(this->dispatched_jobsmtx);
		this->dispatched_jobs.push_front(j);
		this->dispatched_jobscv.notify_all();

	} else if (event.filter == EVFILT_WRITE) {
		/*
		 * Go through the joblist, and if we find a job which has our
		 * file descriptor as the destination, we put it in the dispatch
		 * list.
		 */

		for (auto it = this->joblist.begin();
		     it != this->joblist.end();) {
			j = *it;
			client_fd &dfd = *j->connsockfd;
			if (dfd.fd == efd) {
				it = this->joblist.erase(it);
				std::lock_guard lk(this->dispatched_jobsmtx);
				this->dispatched_jobs.push_back(j);
				this->dispatched_jobscv.notify_all();
			} else
				++it;
		}

	} else {
		ERR("Unexpected event flags: %d", event.flags);
		return (false);
	}

	return (true);
}

void
state::close_filedescs(void)
{
	while (this->shutdown.load() == 0) {
		sleep(DTRACED_CLOSEFD_SLEEPTIME);
		std::lock_guard lk(this->deadfdsmtx);
		for (auto it = this->deadfds.begin();
		     it != this->deadfds.end();) {
			client_fd *dfdp = *it;

			/*
			 * If it's still referenced somewhere, we don't close
			 * it. We'll pick it up on the next run.
			 */
			if (dfdp->is_dead()) {
				++it;
				continue;
			}

			if (dfdp->cleaned_up) {
				/*
				 * We haven't cleaned our jobs up yet. Delay the
				 * closing of this file descriptor until we do.
				 */
				++it;
				continue;
			}

			it = this->deadfds.erase(it);
			dfdp->close();
			delete dfdp;
		}
	}
}

void
state::manage_children(void)
{
	pid_t pid;

	while (1) {
		/*
		 * Wait for a notification that we need to kill a process
		 */
		std::unique_lock lk(this->killmtx);
		this->killcv.wait(lk, [this] {
			return (!this->pids_to_kill.empty() ||
			    this->shutdown.load());
		});

		/*
		 * No need to unlock here due to RAII.
		 */
		if (unlikely(this->shutdown.load()))
			return;

		pid = this->pids_to_kill.front();
		this->pids_to_kill.pop();
		lk.unlock();

		{
			std::lock_guard lk(this->pidlistmtx);
			this->pidlist.erase(pid);
		}

		LOG("kill %d", pid);
		if (kill(pid, SIGTERM)) {
			assert(errno != EINVAL);
			assert(errno != EPERM);

			if (errno == ESRCH)
				ERR("pid %d does not exist", pid);
		}
	}
}

void
state::reap_children(void)
{
	int status, rv;

	for (;;) {
		usleep(DTRACED_SLEEPTIME * 100);
		do {
			rv = waitpid(-1, &status, WNOHANG);
		} while (rv != -1 && rv != 0);

		if (this->shutdown.load() != 0)
			return;
	}
}

void
state::clean_jobs(void)
{
	int woken;

	while (1) {
		woken = 0;
		std::unique_lock lk(this->deadfdsmtx);
		while (this->shutdown.load() == 0 &&
		    (this->deadfds.empty() || woken == 0)) {
			this->jobcleancv.wait(lk);
			woken = 1;
		}

		if (unlikely(this->shutdown.load() != 0))
			return;

		/*
		 * Delete any jobs that our dead file descriptors have started.
		 * We don't need to do anything with them, as the initiating
		 * process is gone.
		 */
		for (client_fd *dfdp : this->deadfds) {
			client_fd &dfd = *dfdp;

			std::lock_guard lk(this->joblistmtx);
			for (auto it = this->joblist.begin();
			     it != this->joblist.end();) {
				job *j = *it;
				if (j->initiator() == dfd.id) {
					it = this->joblist.erase(it);
					delete j;
				} else
					++it;
			}
			dfd.cleaned_up = true;
		}
	}
}

bool
state::handle_job(job *j)
{
	switch (j->kind) {
	case READ_DATA:
		return (j->read_data(*this));

	case KILL:
		return (j->send_kill());

	case NOTIFY_ELFWRITE:
		return (j->send_elf());

	case CLEANUP:
		return (j->send_cleanup());

	case SEND_INFO:
		return (j->send_info(*this));

	default:
		ERR("unknown job: %d", j->kind);
		abort();
	}

	// XXX: Waiting for C++23.
	// std::unreachable();
	return (false);
}

void
state::process_joblist(void)
{
	job *curjob;

	while (1) {
		std::unique_lock lk(this->dispatched_jobsmtx);
		this->dispatched_jobscv.wait(lk, [this] {
			return (!this->dispatched_jobs.empty() ||
			    this->shutdown.load() != 0);
		});

		if (unlikely(this->shutdown.load() != 0))
			break;

		curjob = this->dispatched_jobs.front();
		this->dispatched_jobs.pop_front();
		lk.unlock();

		if (!this->handle_job(curjob))
			ERR("failed to handle job kind %d", curjob->kind);
		delete curjob;
	}
}

}
