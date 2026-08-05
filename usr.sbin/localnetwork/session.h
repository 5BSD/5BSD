/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NETWORKCMP_SESSION_H_
#define	_NETWORKCMP_SESSION_H_

#include <sys/types.h>

#include <stdbool.h>
#include <networkcmp_protocol.h>

#define	NETWORKCMP_SESSION_MAX_SOCKETS	64

struct networkcmp_session_socket {
	int			fd;
	uint64_t		generation;
	uint32_t		family;
	uint32_t		type;
	bool			connect_started;
	bool			connect_complete;
};

struct networkcmp_session {
	uint32_t	limit;
	struct networkcmp_session_socket
	    sockets[NETWORKCMP_SESSION_MAX_SOCKETS];
};

int	networkcmp_session_init(struct networkcmp_session *, uint32_t);
void	networkcmp_session_destroy(struct networkcmp_session *);
struct networkcmp_session_socket *networkcmp_session_lookup(
	    struct networkcmp_session *, struct networkcmp_handle);
int	networkcmp_session_allocate(struct networkcmp_session *, int, uint32_t,
	    uint32_t, struct networkcmp_handle *);
int	networkcmp_session_socket(struct networkcmp_session *,
	    const struct networkcmp_socket_request *,
	    struct networkcmp_handle_reply *);
int	networkcmp_session_close(struct networkcmp_session *,
	    struct networkcmp_handle);
int	networkcmp_session_connect_status(struct networkcmp_session *,
	    struct networkcmp_handle);
int	networkcmp_session_setopt(struct networkcmp_session *,
	    struct networkcmp_handle, uint32_t, uint32_t, const void *, size_t);

#endif
