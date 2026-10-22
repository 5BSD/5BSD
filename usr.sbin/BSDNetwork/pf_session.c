/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The PF endpoint belongs to BSDNetwork, but its sessions use dedicated
 * workers.  The parent requests /dev/pf from BSDFilesystem.  Each worker
 * inherits only a descriptor narrowed to one read-only state-export ioctl,
 * the bind to a jail's vnet, and one transfer to its client.
 *
 * /dev/pf acts on the vnet of the jail that opened it, here the host's.
 * The worker learns the client's jail from the kernel-stamped sender of its
 * request; for a jailed client it binds the still-unused descriptor to that
 * jail's vnet (DIOCBINDJAIL, which the kernel allows only for a descendant
 * of the opener's and the caller's jail and only before any other ioctl),
 * then drops the bind right, so the client reads its own vnet's states.  A
 * client in a jail without its own vnet shares its parent's.
 *
 * The session speaks bsd.network.v1 NetworkPf (generated C server bindings):
 * GetProtocolInfo first, then one OpenStates.  A second OpenStates fails
 * with EALREADY, a request before negotiation or a malformed frame ends the
 * session, and the worker exits NETWORK_PF_SESSION_MS after it started.
 */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <channel.h>
#include <fidl/bsd.network.v1/c/bsd.h>
#include <libservice.h>
#include <filesystemcmp.h>
#include <networkcmp.h>

#include "pf_session.h"

struct pf_session {
	struct fidl_bsd_connection *connection;
	int pf_fd;
	int open_error;
	bool negotiated;
	bool done;		/* the one OpenStates was answered */
	bool violated;		/* protocol violation: end the session */
};

bool
network_pf_admit(service_rights_t rights)
{

	return (service_rights_allow(rights, NETWORK_PF_RIGHT_READ));
}

int
network_pf_open(struct service_context *context)
{
	static const unsigned long commands[] = { DIOCGETSTATES,
	    DIOCBINDJAIL };
	cap_rights_t rights;
	int fd, error;

	if (context == NULL)
		return (errno = ENODEV, -1);
	if (service_open_isolated(context, "/dev/pf",
	    SERVICE_OPEN_READ | SERVICE_OPEN_IOCTL, 0, &fd) == -1)
		return (-1);
	cap_rights_init(&rights, CAP_READ, CAP_FSTAT, CAP_IOCTL);
	if (cap_rights_limit(fd, &rights) == -1 ||
	    cap_ioctls_limit(fd, commands, nitems(commands)) == -1 ||
	    cap_fcntls_limit(fd, 0) == -1 ||
	    service_harden_fd(fd, SERVICE_HARDEN_XFER_ONCE |
	    SERVICE_HARDEN_CLOFORK_ONCE) == -1) {
		error = errno;
		(void)close(fd);
		return (errno = error, -1);
	}
	return (fd);
}

/*
 * Give the descriptor the client's vnet and leave it only the state export.
 * Returns 0 or an errno; on error the descriptor must not be delivered.
 */
static int
pf_bind_client(int pf_fd, const struct channel_sender *sender)
{
	static const unsigned long commands[] = { DIOCGETSTATES };
	int jid;

	if (sender == NULL)
		return (EPERM);
	jid = sender->prison_id;
	if (jid != 0 && ioctl(pf_fd, DIOCBINDJAIL, &jid) == -1)
		return (errno);
	if (cap_ioctls_limit(pf_fd, commands, nitems(commands)) == -1)
		return (errno);
	return (0);
}

static void
pf_protocol_info(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *value __unused)
{
	struct pf_session *session = argument;
	struct bsd_network_v1_ProtocolInfo info = {
		.wire_version = NETWORKCMP_WIRE_VERSION
	};

	if (bsd_network_v1_NetworkPf_GetProtocolInfo_reply(connection, request,
	    &info) != 0) {
		session->violated = true;
		return;
	}
	session->negotiated = true;
}

static void
pf_open_states(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *value __unused)
{
	struct pf_session *session = argument;
	struct bsd_network_v1_NetworkPf_OpenStates_Result result = { 0 };
	int error;

	/* The record rule: nothing before negotiation. */
	if (!session->negotiated) {
		session->violated = true;
		fidl_bsd_connection_close(connection, EPROTO);
		return;
	}
	if (session->done)
		error = EALREADY;
	else if (session->pf_fd < 0)
		error = session->open_error;
	else
		error = pf_bind_client(session->pf_fd,
		    channel_message_sender(fidl_bsd_request_native(request)));
	session->done = true;
	if (error == 0) {
		result.tag = bsd_network_v1_NetworkPf_OpenStates_Result_response_tag;
		result.value.response.pf = session->pf_fd;
	} else {
		result.tag = bsd_network_v1_NetworkPf_OpenStates_Result_err_tag;
		result.value.err = (uint32_t)error;
	}
	if (bsd_network_v1_NetworkPf_OpenStates_reply(connection, request,
	    &result) != 0)
		session->violated = true;
	/* Delivered or refused, the worker's copy goes either way. */
	if (session->pf_fd >= 0) {
		(void)close(session->pf_fd);
		session->pf_fd = -1;
	}
}

static long
elapsed_ms(const struct timespec *started)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return (NETWORK_PF_SESSION_MS);
	return ((now.tv_sec - started->tv_sec) * 1000 +
	    (now.tv_nsec - started->tv_nsec) / 1000000);
}

/*
 * Serve one PF session on session_fd (consumed).  pf_fd is the narrowed
 * descriptor (consumed), or -1 with open_error the reason it is missing.
 * Returns 0 when the one OpenStates was answered and nothing violated the
 * protocol, 1 otherwise.
 */
int
network_pf_serve(int session_fd, int pf_fd, int open_error)
{
	static const struct bsd_network_v1_NetworkPf_server handlers = {
		.GetProtocolInfo = pf_protocol_info,
		.OpenStates = pf_open_states,
	};
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	struct pf_session session;
	struct timespec started;
	long elapsed = 0;
	int error;

	memset(&session, 0, sizeof(session));
	session.pf_fd = pf_fd;
	session.open_error = open_error != 0 ? open_error : EIO;
	/* Requests carry no descriptors; the one reply carries at most one. */
	options.max_pending_requests = 2;
	options.max_queued_messages = 2;
	options.max_queued_bytes = 1024;
	options.max_queued_fds = 1;
	error = fidl_bsd_connection_create_with_options(session_fd,
	    FIDL_BSD_SERVER, &options, &session.connection);
	if (error != 0) {
		(void)close(session_fd);
		if (pf_fd >= 0)
			(void)close(pf_fd);
		return (1);
	}
	/* The descriptor is hardened for exactly this one transfer. */
	fidl_bsd_connection_preserve_sent_inheritance(session.connection);
	if (bsd_network_v1_NetworkPf_bind(session.connection, &handlers,
	    &session) != 0 || clock_gettime(CLOCK_MONOTONIC, &started) == -1)
		goto done;
	while (!session.violated &&
	    (elapsed = elapsed_ms(&started)) < NETWORK_PF_SESSION_MS) {
		error = fidl_bsd_connection_poll(session.connection,
		    (int)(NETWORK_PF_SESSION_MS - elapsed));
		if (error != 0 && error != ETIMEDOUT && error != EAGAIN)
			break;
	}
	/* A frame the bindings refused before any handler ran (a peer that
	 * merely went away is not a violation). */
	error = fidl_bsd_connection_error(session.connection);
	if (error != 0 && error != EPIPE && error != ECONNRESET &&
	    error != ECANCELED && error != ETIMEDOUT && error != ENOTCONN)
		session.violated = true;
done:
	if (session.pf_fd >= 0)
		(void)close(session.pf_fd);
	fidl_bsd_connection_destroy(session.connection);
	return (session.done && !session.violated ? 0 : 1);
}
