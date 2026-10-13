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
#include <sys/stat.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

#include <atomic>

#define SOCKFD_NAME "sub.sock"

namespace dtraced {

char INBOUNDDIR[MAXPATHLEN]  = "/var/ddtrace/inbound/";
char OUTBOUNDDIR[MAXPATHLEN] = "/var/ddtrace/outbound/";
char BASEDIR[MAXPATHLEN]     = "/var/ddtrace/base/";

bool
dir::write_data(unsigned char *data, size_t nbytes)
{
	dtraced::state *s;
	char donename[MAXPATHLEN];
	size_t dirpathlen;
	char tmpfile[MAXPATHLEN];
	__cleanup(closefd_generic) int fd = -1;

	{
		std::lock_guard lk(this->dirmtx);
		s = this->state;

		if (s == NULL) {
			ERR("state is NULL in write_data()");
			return (false);
		}

		sprintf(tmpfile, "%s.elf.XXXXXXXXXXXXXXX",
		    this->dirpath.c_str());
		dirpathlen = this->dirpath.length();
	}

	fd = mkstemp(tmpfile);
	if (fd == -1) {
		ERR("mkstemp() failed with: %m");
		return (false);
	}

	if (write(fd, data, nbytes) < 0) {
		ERR("write() failed with: %m");
		return (false);
	}

	strncpy(donename, tmpfile, dirpathlen);
	strcpy(donename + dirpathlen, tmpfile + dirpathlen + 1);
	if (rename(tmpfile, donename)) {
		ERR("rename() failed %s -> %s: %m", tmpfile, donename);
		return (false);
	}

	return (true);
}

bool
dir::process(void)
{
	bool r;
	struct dirent *file;

	while (file = readdir(this->dirp), file != NULL) {
		r = this->processfn(*this, file);
		if (!r)
			break;
	}

	rewinddir(this->dirp);
	return (r);
}

bool
dir::listen(void)
{
	int rval;
	__cleanup(closefd_generic) int kq = -1;
	struct kevent ev = {}, ev_data = {};
	dtraced::state *s;
	struct timespec ts;

	s = this->state;

	if ((kq = kqueue()) == -1) {
		ERR("failed to create a kqueue %m");
		return (false);
	}

	EV_SET(&ev, this->dirfd, EVFILT_VNODE, EV_ADD | EV_CLEAR | EV_ENABLE,
	    NOTE_WRITE, 0, (void *)this);

	ts.tv_sec = DTRACED_EVENTSLEEPTIME;
	ts.tv_nsec = 0;
	for (;;) {
		rval = dtraced::event(*s, kq, &ev, 1, &ev_data, 1, &ts);

		if (s->shutdown.load())
			break;

		if (rval < 0) {
			ERR("dtraced::event failed on %s: %m",
			    this->dirpath.c_str());
			broadcast_shutdown(*s);
			return (false);
		}

		if (ev_data.flags == EV_ERROR) {
			ERR("dtraced::event got EV_ERROR on %s: %m",
			    this->dirpath.c_str());
			continue;
		}

		if (rval > 0) {
			if (!this->process()) {
				ERR("failed to process new files in %s",
				    this->dirpath.c_str());
				broadcast_shutdown(*s);
				return (false);
			}
		}
	}

	return (true);
}

bool
dir::memorized(const std::string &p)
{

	return (this->existing_files.find(p) != this->existing_files.end());
}

bool
dir::rmpath(const std::string &p)
{

	return (this->existing_files.erase(p) > 0);
}

bool
dir::memorize_file(struct dirent *f)
{
	if (f == NULL) {
		ERR("dirent is NULL");
		return (false);
	}

	if (strcmp(f->d_name, SOCKFD_NAME) == 0)
		return (true);

	if (f->d_name[0] == '.')
		return (true);

	this->existing_files.insert(std::string(f->d_name));
	return (true);
}

static const size_t FILESET_SIZE = 1 << 26;

dir::dir(const char *path, foreach_fn_t fn)
    : dirpath(path)
    , existing_files(FILESET_SIZE)
    , processfn(fn)
{
	bool retry;

	retry = true;
againmkdir:
	/*
	 * XXX: This might be better handled with exceptions in the future, or
	 * maybe a different way to structure the code so that RAII still works
	 * with an optional return type, but for now let's just abort() on error
	 * since this code was C.
	 */
	this->dirfd = open(path, O_RDONLY | O_DIRECTORY);
	if (this->dirfd == -1) {
		if (retry && errno == ENOENT) {
			if (mkdir(path, 0700) != 0) {
				ERR("failed to mkdir %s: %m", path);
				abort();
			} else {
				retry = false;
				goto againmkdir;
			}
		}

		ERR("failed to open %s: %m", path);
		abort();
	}

	this->dirp = fdopendir(this->dirfd);
	if (this->dirp == NULL) {
		ERR("fdopendir(%d) failed for %s: %m", this->dirfd,
		    this->dirpath.c_str());
		(void)close(this->dirfd);
		abort();
	}
}

dir::~dir()
{

	(void)close(this->dirfd);
	(void)closedir(this->dirp);
}

bool
dir::file_exists(const char *f)
{

	return (faccessat(this->dirfd, f, F_OK, 0) == 0);
}

bool
dir::populate_existing(void)
{
	struct dirent *file;

	while (file = readdir(this->dirp), file != NULL)
		this->existing_files.insert(std::string(file->d_name));

	rewinddir(this->dirp);
	return (true);
}

bool
process_inbound(dir &dir, struct dirent *f)
{
	job *job;
	dtraced::state *s;
	pid_t pid;
	int status;
	char *argv[7] = { 0 };
	unsigned char ident_to_delete[DTRACED_PROGIDENTLEN];
	std::string d_name_s, fullpath;

	memset(ident_to_delete, 0, sizeof(ident_to_delete));

	status = 0;
	s = dir.state;

	if (s == NULL) {
		ERR("state is NULL");
		return (false);
	}

	if (f == NULL) {
		ERR("dirent is NULL");
		return (false);
	}

	if (strcmp(f->d_name, SOCKFD_NAME) == 0)
		return (true);

	if (f->d_name[0] == '.')
		return (true);

	d_name_s = std::string(f->d_name);
	if (dir.memorized(d_name_s))
		return (true);
	fullpath = dir.full_path();
	fullpath += d_name_s;
	DEBUG("processing %s", fullpath.c_str());

	if (s->is_control_machine()) {
		/*
		 * If we have a host configuration of dtraced
		 * we simply send off the ELF file to dtrace(1).
		 *
		 * We iterate over all our known dtrace(1)s that have
		 * registered with dtraced and send off the file path
		 * to them. They will parse said file path (we assume
		 * they won't be writing over it since this requires root
		 * anyway) and decide if the file is meant for them to
		 * process. There may be more dtrace(1) instances that
		 * want to process the same file in the future.
		 */
		std::lock_guard lk(s->sockfdsmtx);
		for (client_fd *dfdp : s->sockfds) {
			client_fd &dfd = *dfdp;

			if (dfd.kind != DTRACED_KIND_CONSUMER)
				continue;

			if (!dfd.is_subscribed(DTD_SUB_ELFWRITE))
				continue;

			job = new dtraced::job(NOTIFY_ELFWRITE, dfdp);
			if (job == nullptr) {
				ERR("new job(NOTIFY_ELFWRITE, %s) failed: %m",
				    dfdp->ident);
				abort();
			}

			notify_elfwrite_job &ne = job->notify_elfwrite_get();
			ne.path = strdup(f->d_name);
			ne.pathlen = strlen(f->d_name);
			ne.dir = &dir;
			ne.nosha = 1;

			if (ne.path == NULL) {
				ERR("failed to strdup() f->d_name: %m");
				abort();
			}

			{
				std::lock_guard lk(s->joblistmtx);
				s->joblist.push_back(job);
			}

			if (!dfd.re_enable_write())
				ERR("re_enable_write() failed with: %m");
		}
	} else {
		int stdout_rdr[2];
		int stdin_rdr[2];
		size_t num_idents;

		if (pipe(stdout_rdr) != 0) {
			ERR("pipe(stdout) failed: %m");
			return (false);
		}

		if (pipe(stdin_rdr) != 0) {
			ERR("pipe(stdin) failed: %m");
			return (false);
		}

		/*
		 * Count up how many identifiers we have. We will need to use
		 * this both in the child and parent.
		 */
		{
			std::lock_guard lk(s->identlistmtx);
			num_idents = s->identlist.size();
		}

		pid = fork();

		/*
		 * We don't wait for the process as we don't really care about
		 * it. We will just save the pid as running and kill it whenever
		 * a message arrives to do so.
		 */
		if (pid == -1) {
			ERR("fork() failed: %m");
			return (false);
		} else if (num_idents > 0 && pid > 0) {
			size_t current;
			int wait_for_pid = 0;
			struct timespec timeout = {};
			int remove = 1, rv = 0;
			char msg[] = "DEL ident";
			__cleanup(closefd_generic) int kq = kqueue();
			struct kevent ev, ev_data;

			if (kq == -1) {
				ERR("Failed to create timeout kq");
				return (false);
			}

			close(stdin_rdr[0]);
			close(stdout_rdr[1]);

			LOG("write num_idents = %d\n", num_idents);
			if (write(stdin_rdr[1], &num_idents,
			    sizeof(num_idents)) == -1) {
				ERR("write(%zu) failed: %m", num_idents);
				return (false);
			}

			/*
			 * There is a race condition between the fork and
			 * traversal of this list. We could have added a new
			 * identifier to our list. However, because we always
			 * append to the list rather than randomly insert them,
			 * we can simply count up how many identifiers we've
			 * sent and don't need to worry about snapshotting the
			 * original state of the list in another list.
			 */
			std::unique_lock lk(s->identlistmtx);
			current = 0;
			for (auto it = s->identlist.begin();
			     it != s->identlist.end() && current < num_idents;
			     ++it, ++current) {
				auto ident = *it;
				LOG("write ident %hhx%hhx%hhx\n", ident[0],
				    ident[1], ident[2]);
				if (write(stdin_rdr[1], ident.data(),
				    DTRACED_PROGIDENTLEN) == -1) {
					ERR("write(stdin) failed: %m");
					return (false);
				}
			}
			lk.unlock();

			/*
			 * This will give us the identifier that matched and
			 * needs to be deleted. We give the child 10 seconds to
			 * give us the identifier, otherwise we simply kill it.
			 * This avoids a deadlock in dtraced in the case of a
			 * bug in dtrace(1).
			 */
			timeout.tv_sec = DTRACED_WAITPID_SLEEPTIME;
			timeout.tv_nsec = 0;

			EV_SET(&ev, stdout_rdr[0], EVFILT_READ,
			    EV_ADD | EV_CLEAR | EV_ENABLE, 0, 0, 0);
			LOG("waiting for %d", pid);
			rv = kevent(kq, &ev, 1, &ev_data, 1, &timeout);

			if (rv < 0) {
				ERR("kevent() failed: %m");
				return (false);
			} else if (rv == 0) {
				/* Timeout */
				ERR("killing %d", pid);
				kill(pid, SIGKILL);
				waitpid(pid, &status, 0);
				return (true);
			}

			/*
			 * It should be safe to read at this point due to the
			 * kevent above, ensuring that we have data to read
			 * here.
			 */
			if ((rv = read(stdout_rdr[0], msg,
			    sizeof(msg))) == -1) {
				ERR("read() failed: %m");
				remove = 0;
			}

			if (rv != sizeof(msg) && rv != 0) {
				WARN("Expected a read of %zu bytes, "
				     "but got %zu. Not removing ident",
				    sizeof(msg), rv, pid);
				remove = 0;
				goto failmsg;
			}

			msg[sizeof(msg) - 1] = '\0';

			DEBUG("Got message: %s", msg);
			if (strcmp(msg, "FAIL FAIL") == 0) {
				remove = 0;
				wait_for_pid = 1;
				goto failmsg;
			}

			if (strcmp(msg, "DEL ident") != 0) {
				kill(pid, SIGKILL);
				WARN("Expected DEL ident, but got %s",
				    msg);
				goto failmsg;
			}

			/*
			 * It should be safe to read at this point due to the
			 * kevent above, ensuring that we have data to read
			 * here.
			 */
			if ((rv = read(stdout_rdr[0], ident_to_delete,
			    DTRACED_PROGIDENTLEN)) == -1) {
				ERR("read() failed: %m");
				remove = 0;
			}

			if (rv != DTRACED_PROGIDENTLEN && rv != 0) {
				WARN("Expected a read of %zu bytes, "
				     "but got %zu. Not removing ident.",
				    DTRACED_PROGIDENTLEN, rv, pid);
				remove = 0;
			}

failmsg:
			close(stdout_rdr[0]);
			close(stdin_rdr[1]);

			/*
			 * Remove the entry that the child tells us from the
			 * identlist.
			 */
			if (remove) {
				std::lock_guard lk(s->identlistmtx);
				for (auto it = s->identlist.begin();
				     it != s->identlist.end();) {
					auto ident = *it;
					int r;

					r = memcmp(ident_to_delete,
					    ident.data(), DTRACED_PROGIDENTLEN);
					if (r == 0) {
						it = s->identlist.erase(it);
						break;
					} else
						++it;
				}
			}

			/*
			 * There's no need to waitpid_timeout() here because
			 * we've already run through the kevent above and sent
			 * SIGKILL if we timed out.
			 */
			if (wait_for_pid != 0) {
				LOG("waitpid(%d)", pid);
				waitpid(pid, &status, 0);
				LOG("joined %d, status %d", pid, status);
			} else {
				std::lock_guard lk(s->pidlistmtx);
				s->pidlist.insert(pid);
			}
		} else if (num_idents == 0 && pid > 0) {
			struct timespec timeout;
			int status;

			__maybe_unused(status);

			timeout.tv_sec = DTRACED_WAITPID_SLEEPTIME;
			timeout.tv_nsec = 0;
			LOG("waitpid_timeout(%d) (timeout=10s)", pid);
			status = waitpid_timeout(pid, &timeout);
			__maybe_unused(status);
			LOG("joined %d, status %d", pid, status);
		} else if (pid == 0) {
			int last = 0;

			close(stdout_rdr[0]);
			if (dup2(stdout_rdr[1], STDOUT_FILENO) == -1) {
				ERR("dup2(stdout) failed: %m");
				exit(EXIT_FAILURE);
			}

			close(stdin_rdr[1]);
			if (dup2(stdin_rdr[0], STDIN_FILENO) == -1) {
				ERR("dup2(stdin) failed: %m");
				exit(EXIT_FAILURE);
			}

			/*
			 * We want dtrace to be as quiet as possible, so we pass
			 * the '-q' flag.
			 */
			argv[last] = strdup("/usr/sbin/dtrace");
			if (argv[last++] == NULL)
				abort();

			argv[last] = strdup("-Y");
			if (argv[last++] == NULL)
				abort();

			argv[last] = (char *)fullpath.c_str();
			if (argv[last++] == NULL)
				abort();

#if 0
			argv[last] = strdup("-v");
			if (argv[last++] == NULL)
				abort();

			argv[last] = strdup("-v");
			if (argv[last++] == NULL)
				abort();
#endif

			if (num_idents > 0) {
				argv[last] = strdup("-N");
				if (argv[last++] == NULL)
					abort();

			} else
				argv[last++] = NULL;

			argv[last] = NULL;

			execve("/usr/sbin/dtrace", argv, NULL);
			exit(EXIT_FAILURE);
		}
	}

	return (dir.memorize_file(f));
}

static void
dtraced_copyfile(const char *src, int fd_dst, const char *dst)
{
	__cleanup(closefd_generic) int fd = -1;
	__cleanup(closefd_generic) int newfd = -1;
	struct stat sb;
	size_t len;

	memset(&sb, 0, sizeof(struct stat));

	fd = open(src, O_RDONLY);
	if (fd == -1)
		ERR("Failed to open %s: %m", src);

	if (fstat(fd, &sb)) {
		ERR("Failed to fstat %s (%d): %m", src, fd);
		return;
	}

	len = sb.st_size;

	std::vector<char> buf(len);
	if (read(fd, buf.data(), len) < 0) {
		ERR("Failed to read %zu bytes from %s (%d): %m", len, src, fd);
		return;
	}

	if (write(fd_dst, buf.data(), len) < 0) {
		ERR("failed to write %zu bytes to %s (%d): %m", len, dst,
		    newfd);
		return;
	}
}

bool
process_base(dir &dir, struct dirent *f)
{
	state *s;
	int status = 0, fd = -1;
	pid_t pid;
	char *argv[5];
	char fullarg[MAXPATHLEN*2 + 1] = { 0 };
	size_t offset;
	char donename[MAXPATHLEN] = { 0 };
	char tmpfile[MAXPATHLEN];
	size_t dirpathlen = 0;
	std::string d_name_s, fullpath;

	__maybe_unused(status);

	{
		std::lock_guard lk(dir.dirmtx);
		s = dir.state;

		if (s == NULL) {
			ERR("state is NULL in base directory monitoring thread");
			return (false);
		}

		if (f == NULL) {
			ERR("dirent is NULL in base directory monitoring thread");
			return (false);
		}

		if (strcmp(f->d_name, SOCKFD_NAME) == 0)
			return (true);

		if (f->d_name[0] == '.')
			return (true);


		/*
		 * Exit early if the file doesn't exist. There is definitely
		 * multiple race conditions here, but it doesn't really matter
		 * as we don't expect this to ever happen if communication
		 * happens through dtraced itself.
		 */
		d_name_s = std::string(f->d_name);
		if (!dir.file_exists(f->d_name)) {
			ERR("%s%s does not exist", dir.full_path().c_str(),
			    f->d_name);
			(void)dir.rmpath(d_name_s);
			return (false);
		}

		if (dir.memorized(d_name_s))
			return (true);

		DEBUG("processing %s", f->d_name);
		fullpath = dir.full_path();
	}

	fullpath += d_name_s;

	{
		std::lock_guard lk(s->outbounddir->dirmtx);
		sprintf(tmpfile, "%s.elf.XXXXXXXXXXXXXXX",
		    s->outbounddir->full_path().c_str());
		dirpathlen = strlen(s->outbounddir->full_path().c_str());

		fd = mkstemp(tmpfile);
		if (fd == -1) {
			ERR("mkstemp(%s) failed: %m", tmpfile);
			abort();
		}

		strncpy(donename, tmpfile, dirpathlen);
		strcpy(donename + dirpathlen, tmpfile + dirpathlen + 1);
	}

	dtraced_copyfile(fullpath.c_str(), fd, tmpfile);

	LOG("create file %s", donename);
	if (rename(tmpfile, donename))
		ERR("failed to rename %s to %s: %m", tmpfile, donename);

	pid = fork();

	if (pid == -1) {
		ERR("fork() failed: %m");
		return (false);
	} else if (pid > 0) {
		struct timespec ts;

		ts.tv_nsec = 0;
		ts.tv_sec = DTRACED_WAITPID_SLEEPTIME;
		status = waitpid_timeout(pid, &ts);
	} else {
		argv[0] = strdup("/usr/sbin/dtrace");
		if (argv[0] == NULL)
			abort();

		argv[1] = strdup("-q");
		if (argv[1] == NULL)
			abort();

		argv[2] = strdup("-Y");
		if (argv[2] == NULL)
			abort();

		strcpy(fullarg, fullpath.c_str());
		offset = strlen(fullarg);
		strcpy(fullarg + offset, ",host");
		argv[3] = strdup(fullarg);
		if (argv[3] == NULL)
			abort();

		argv[4] = NULL;
		LOG("spawn dtrace: %s %s %s %s", argv[0], argv[1], argv[2],
		    argv[3]);
		execve("/usr/sbin/dtrace", argv, NULL);
		exit(EXIT_FAILURE);
	}

	return (dir.memorize_file(f));
}

bool
process_outbound(dir &dir, struct dirent *f)
{
	job *job;
	state *s;
	std::string d_name_s;

	s = dir.state;
	if (s == NULL) {
		ERR("state is NULL");
		return (false);
	}

	if (f == NULL) {
		ERR("dirent is NULL");
		return (false);
	}

	if (strcmp(f->d_name, SOCKFD_NAME) == 0)
		return (true);

	if (f->d_name[0] == '.')
		return (true);

	{
		/*
		 * Exit early if the file doesn't exist. There is definitely
		 * multiple race conditions here, but it doesn't really matter
		 * as we don't expect this to ever happen if communication
		 * happens through dtraced itself.
		 */
		d_name_s = std::string(f->d_name);
		std::lock_guard lk(dir.dirmtx);
		if (!dir.file_exists(f->d_name)) {
			ERR("%s%s does not exist", dir.full_path().c_str(),
			    f->d_name);
			dir.rmpath(d_name_s);
			return (false);
		}

		if (dir.memorized(d_name_s))
			return (true);
	}

	std::unique_lock lk(s->sockfdsmtx);
	for (client_fd *dfdp : s->sockfds) {
		client_fd &dfd = *dfdp;

		if (dfd.kind != DTRACED_KIND_FORWARDER)
			continue;

		if (!dfd.is_subscribed(DTD_SUB_ELFWRITE))
			continue;

		job = new dtraced::job(NOTIFY_ELFWRITE, dfdp);
		if (job == NULL) {
			ERR("new job(NOTIFY_ELFWRITE, %s) failed: %m",
			    dfdp->ident);
			abort();
		}

		notify_elfwrite_job &ne = job->notify_elfwrite_get();
		ne.path = strdup(f->d_name);
		ne.pathlen = strlen(f->d_name);
		ne.dir = &dir;
		ne.nosha = s->nosha;

		if (ne.path == NULL) {
			ERR("Failed to strdup() f->d_name: %m");
			abort();
		}

		{
			std::lock_guard lk(s->joblistmtx);
			s->joblist.push_back(job);
		}

		if (!dfd.re_enable_write())
			ERR("re_enable_write() failed with: %m");
	}
	lk.unlock();

	return (dir.memorize_file(f));
}

}
