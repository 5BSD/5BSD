/*-
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

#ifndef __DTRACED_CONNECTION_H_
#define __DTRACED_CONNECTION_H_

#include <sys/types.h>

#include "dtraced.h"

#include <atomic>
#include <string>

#define DTRACED_FDIDENTLEN             128ull

namespace dtraced {

class client_fd {
	friend class state;

    protected:
	int kq;			  /* the kqueue this fd belongs to */
	int fd;			  /* the actual filedesc */
	uint64_t subs;		  /* events that efd subscribed to */
	std::atomic_int count {}; /* reference count */
    public:
	client_fd() = delete;
	client_fd(int, int, dtd_initmsg_t);
	~client_fd();

	bool cleaned_up;		/* has this fd been cleaned up */
	uint64_t id;			/* initiator id */
	int kind;			/* consumer/forwarder */
	char ident[DTRACED_FDIDENTLEN]; /* human-readable identifier */

	void acquire(void);
	void release(void);

	bool enable_read(void *);
	bool enable_write(void *);
	bool enable_rw(void *);
	bool re_enable_read(void);
	bool re_enable_write(void);
	bool re_enable_rw(void);
	bool disable_read(void);
	bool disable_write(void);
	bool disable_rw(void);
	void close(void);
	void shutdown(void);

	int get_fd(void);
	bool is_dead(void);
	bool is_subscribed(unsigned long long);

	bool recv(void *, size_t);
	bool send(void *, size_t);
	ssize_t send_ack(void);
	ssize_t send_nak(void);

	operator std::string(void) const;
};

}

#endif // __DTRACED_CONNECTION_H_
