/*-
 * Copyright (c) 2023 Domagoj Stolfa
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

#ifndef _DTRACED_JOB_H_
#define _DTRACED_JOB_H_

#include <sys/event.h>

#include "_dtraced_connection.h"
#include "dtraced.h"
#include "dtraced_directory.h"
#include "dtraced_id.h"

namespace dtraced {

enum job_kind {
	NOTIFY_ELFWRITE = 1,
	KILL,
	READ_DATA,
	CLEANUP,
	SEND_INFO,
	JOB_LAST
};

struct notify_elfwrite_job {
	size_t pathlen; /* how long is path? */
	char *path;	/* path to file (based on dir) */
	dir *dir;	/* base directory of path */
	bool nosha;	/* do we want to checksum? */
	durable_delivery *replay; /* recovered guest token, owned by job */
	uint16_t replay_vmid;
	uint64_t replay_epoch;
	/* Host forwarder: pending HTD4 recorded before the spool was memorized
	 * or recovered at admission; the send reuses its delivery ID. Owned. */
	durable_delivery *recorded;
};

struct kill_job {
	pid_t pid;     /* pid to kill */
	uint16_t vmid; /* vmid to kill the pid on */
	uint64_t epoch; /* target VM lifetime */
	uint8_t source_id[DTRACED_PROGRAM_ID_LEN];
};

// XXX: this is a bit annoying because we can't use a std::vector in a union.
using cleanup_job = std::vector<std::string>;

class job {
	union _job_union {
		notify_elfwrite_job notif_elf;
		kill_job kill;
		cleanup_job *cleanup;
	} j;

	uint64_t init_id;
	uint64_t id;
	char ident_str[256];   /* identifier string */

	void tag(void);

    public:
	job_kind kind;
	client_fd *connsockfd; /* which socket do we send this on? */
	bool handoff_deferred = false; /* no bytes sent; worker retains job */
	uint16_t handoff_vmid = 0; /* source of an identified host consumer ELF */
	uint64_t handoff_epoch = 0;
	uint64_t cleanup_delivery_id = 0; /* stable over a deferred retry */
	bool cleanup_journaled = false;

	job() = delete;
	job(job_kind, client_fd *);
	~job();

	notify_elfwrite_job &notify_elfwrite_get(void);
	kill_job &kill_get(void);
	cleanup_job *&cleanup_get(void);
	uint64_t initiator(void) const;

	bool send_elf(void);
	bool send_kill(state &);
	bool send_info(state &);
	bool send_cleanup(state &);
	bool read_data(state &);
};

inline uint64_t
job::initiator(void) const
{

	return (this->init_id);
}

inline notify_elfwrite_job &
job::notify_elfwrite_get(void)
{

	return (this->j.notif_elf);
}

inline kill_job &
job::kill_get(void)
{

	return (this->j.kill);
}

inline cleanup_job *&
job::cleanup_get(void)
{

	return (this->j.cleanup);
}

}

#endif // _DTRACED_JOB_H_
