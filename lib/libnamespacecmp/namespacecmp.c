/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The system.Namespace client, moved out of libservice: service_enter_namespace(3), service_destroy_namespace(3) and service_namespace_info(3).
 * The record protocol and behaviour are unchanged.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/jail.h>

#include <libservice.h>
#include <libservice_session.h>
#include <bsdnamespace_proto.h>
#include "namespacecmp.h"

/*
 * Bound for the system.Namespace control calls.  Without a finite
 * timeout a provider that is up-but-wedged (accepted the connection but never
 * replies) would block the calling daemon thread forever.  A crashed provider is
 * already handled -- the channel reset delivers ECONNRESET -- so this only
 * covers the wedged case; 30s is generous for a jail create.
 */
#define	SERVICE_CONTROL_CALL_TIMEOUT_MS	30000

static struct service_session *service_namespace_session;
#define SESSIONS_FORGET() do { service_namespace_session = NULL; } while (0)
static bool
service_provider_status_valid(int32_t status)
{

	return (status >= 0 && status <= ELAST);
}

static bool
service_provider_all_zero(const void *data, size_t length)
{
	const unsigned char *bytes = data;
	size_t i;

	for (i = 0; i < length; i++)
		if (bytes[i] != 0)
			return (false);
	return (true);
}

static int
service_provider_protocol_error(struct service_session *session, int fd)
{

	if (fd >= 0)
		(void)close(fd);
	(void)service_session_fail(session, EPROTO);
	errno = EPROTO;
	return (-1);
}


/*
 * One process-wide provider session, opened by name on first use.  A
 * session that failed terminally (the provider died or was relaunched) is
 * replaced; a session inherited across fork or pdfork belongs to the parent
 * and is abandoned (libservice's fork handling severs its channel).
 */
static pthread_mutex_t service_state_lock = PTHREAD_MUTEX_INITIALIZER;
static pid_t service_session_owner;

static int
service_cached_session_get(const char *name, struct service_session **slot)
    __no_lock_analysis
{
	struct service_session *candidate;
	int error, fd;

	error = pthread_mutex_lock(&service_state_lock);
	if (error != 0)
		return (errno = error, -1);
	if (service_session_owner != getpid()) {
		/* Never close an inherited session: it is the parent's. */
		SESSIONS_FORGET();
		service_session_owner = getpid();
	}
	if (*slot != NULL) {
		struct service_session *dead = NULL;

		if (service_session_is_dead(*slot)) {
			dead = *slot;
			*slot = NULL;
		}
		(void)pthread_mutex_unlock(&service_state_lock);
		if (dead == NULL)
			return (0);
		service_session_close(dead);
	} else
		(void)pthread_mutex_unlock(&service_state_lock);

	if (service_open(name, &fd) == -1)
		return (-1);
	if (service_session_create(fd, &candidate) == -1) {
		error = errno;
		(void)close(fd);
		errno = error;
		return (-1);
	}

	error = pthread_mutex_lock(&service_state_lock);
	if (error != 0) {
		service_session_close(candidate);
		errno = error;
		return (-1);
	}
	if (*slot == NULL) {
		*slot = candidate;
		candidate = NULL;
	}
	(void)pthread_mutex_unlock(&service_state_lock);
	if (candidate != NULL)
		service_session_close(candidate);
	return (0);
}

/*
 * Confine this process to its namespace (jail) via bsdnamespace(8).  Consumer self-
 * service, uniform with storage/modules: libservice opens a system.Namespace
 * channel by name (pulling bsdnamespace up on demand), asks it to create the jail
 * rooted at `path` (named/scoped by this process's unforgeable channel label),
 * and jail_attach_jd(2)s the process to the returned descriptor.  The
 * descriptor carries bsdnamespace's root credential, so a non-root caller may attach
 * itself.  The program's library calls this when it decides to confine — jails
 * are a weak, opt-in confinement and switchboard is not involved at all.  hostname
 * and ip4_addr may be NULL/empty.
 *
 * `flags` selects the jail lifetime: 0 for a persistent jail (reused by this
 * process's label across restarts, outliving the consumer), or
 * SERVICE_NS_EPHEMERAL for a jail whose lifetime is bound to this process.  In
 * the ephemeral case bsdnamespace's per-client worker holds the jail's owning
 * descriptor and drops it when this process disconnects, so the jail is torn
 * down when the process exits; libservice itself only attaches.  Returns 0, or
 * -1 with errno.
 */

int
service_enter_namespace(struct service_context *context, const char *path,
    const char *hostname, const char *ip4_addr, unsigned flags)
{

	/* Old signature: no IPv6 address; identical persistent/ephemeral flags. */
	return (service_enter_namespace_ex(context, path, hostname, ip4_addr,
	    "", flags));
}

/*
 * As service_enter_namespace(3), but additionally accepts an IPv6 address
 * (ip6_addr, "" or NULL = none) and the full SERVICE_NS_* flag set, including
 * SERVICE_NS_VNET to give the jail its own virtual network stack (vnet=new).
 * vnet takes no dedicated argument — pass SERVICE_NS_VNET in flags.  All other
 * behaviour (channel caching, directory-fd drop before attach, non-owning jd
 * attach-then-close) is identical.  The delivered jd is the client's own attach
 * descriptor; the daemon set CAP_XFER_ONCE, consumed to NONE at the client by
 * the reply-send, so it is not re-delegable and no extra attenuation is applied.
 * Returns 0, or -1 with errno.
 */
int
service_enter_namespace_ex(struct service_context *context, const char *path,
    const char *hostname, const char *ip4_addr, const char *ip6_addr,
    unsigned flags)
{
	struct bsdnamespace_request rq;
	struct bsdnamespace_reply rp;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	options.timeout_ms = SERVICE_CONTROL_CALL_TIMEOUT_MS;
	int jd = -1, saved;

	if (path == NULL || path[0] != '/' ||
	    (flags & ~(SERVICE_NS_EPHEMERAL | SERVICE_NS_VNET))) {
		errno = EINVAL;
		return (-1);
	}
	if (strnlen(path, sizeof(rq.path)) >= sizeof(rq.path) ||
	    (hostname != NULL &&
	    strnlen(hostname, sizeof(rq.hostname)) >= sizeof(rq.hostname)) ||
	    (ip4_addr != NULL &&
	    strnlen(ip4_addr, sizeof(rq.ip4_addr)) >= sizeof(rq.ip4_addr)) ||
	    (ip6_addr != NULL &&
	    strnlen(ip6_addr, sizeof(rq.ip6_addr)) >= sizeof(rq.ip6_addr))) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (-1);
	}

	/* Reuse the process-wide system.Namespace channel. */
	if (service_cached_session_get(BSDNAMESPACE_SERVICE_NAME,
	    &service_namespace_session) == -1)
		return (-1);

	memset(&rq, 0, sizeof(rq));
	rq.op = BSDNAMESPACE_OP_ENTER_JAIL;
	if (flags & SERVICE_NS_EPHEMERAL)
		rq.flags |= BSDNAMESPACE_F_EPHEMERAL;
	if (flags & SERVICE_NS_VNET)
		rq.flags |= BSDNAMESPACE_F_VNET;
	(void)strlcpy(rq.path, path, sizeof(rq.path));
	if (hostname != NULL)
		(void)strlcpy(rq.hostname, hostname, sizeof(rq.hostname));
	if (ip4_addr != NULL)
		(void)strlcpy(rq.ip4_addr, ip4_addr, sizeof(rq.ip4_addr));
	if (ip6_addr != NULL)
		(void)strlcpy(rq.ip6_addr, ip6_addr, sizeof(rq.ip6_addr));

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &rq;
	outgoing.length = sizeof(rq);
	memset(&rp, 0, sizeof(rp));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &rp;
	incoming.capacity = sizeof(rp);
	incoming.fds = &jd;
	incoming.fd_capacity = 1;
	if (service_session_call(service_namespace_session, &outgoing, &incoming,
	    &options) == -1) {
		if (errno == EMSGSIZE)
			return (service_provider_protocol_error(
			    service_namespace_session, -1));
		return (-1);
	}
	if (incoming.length != sizeof(rp) || rp._reserved != 0 ||
	    !service_provider_status_valid(rp.status) ||
	    (rp.status == 0 ? incoming.nfds != 1 : incoming.nfds != 0))
		return (service_provider_protocol_error(service_namespace_session,
		    incoming.nfds != 0 ? jd : -1));
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}

	/*
	 * A process about to be confined must not retain an open directory
	 * descriptor: the kernel's jail-attach path (pwd_chroot_chdir ->
	 * chroot_refuse_vdir_fds) refuses the attach with EPERM if any is held,
	 * because a directory fd pointing outside the new root is an escape
	 * vector (fchdir(2) out of the jail).  Dropping them is an intrinsic part
	 * of entering the namespace; the owning jaildesc (jd) is not a directory.
	 */
	{
		int fd, maxfd = getdtablesize();
		struct stat dsb;

		for (fd = 0; fd < maxfd; fd++) {
			if (fd == jd)
				continue;
			if (fstat(fd, &dsb) == 0 && S_ISDIR(dsb.st_mode))
				(void)close(fd);
		}
	}

	/*
	 * The descriptor's root credential authorizes this attach; it is a
	 * non-owning descriptor, so closing it after attaching is correct for
	 * both persistent and ephemeral jails.  An ephemeral jail's lifetime is
	 * anchored by bsdnamespace's per-client worker (which holds the jail's owning
	 * descriptor and drops it when this process disconnects), not by this fd.
	 */
	if (jail_attach_jd(jd) == -1) {
		saved = errno;
		(void)close(jd);
		errno = saved;
		return (-1);
	}
	(void)close(jd);
	return (0);
}

/*
 * Destroy the caller's namespace (jail) via bsdnamespace (BSDNAMESPACE_OP_DESTROY_JAIL).
 * The jail acted on is the ONE scoped by this process's unforgeable channel
 * label (bsdnamespace derives its name), so a caller can never name another's jail.
 * Carries no fd in either direction.  Returns 0 once the jail is gone, or -1
 * with errno (ENOENT if the caller has no jail).
 */
int
service_destroy_namespace(struct service_context *context)
{
	struct bsdnamespace_control_request rq;
	struct bsdnamespace_reply rp;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	options.timeout_ms = SERVICE_CONTROL_CALL_TIMEOUT_MS;

	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (-1);
	}

	/* Reuse the process-wide system.Namespace channel. */
	if (service_cached_session_get(BSDNAMESPACE_SERVICE_NAME,
	    &service_namespace_session) == -1)
		return (-1);

	memset(&rq, 0, sizeof(rq));
	rq.op = BSDNAMESPACE_OP_DESTROY_JAIL;
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &rq;
	outgoing.length = sizeof(rq);
	memset(&rp, 0, sizeof(rp));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &rp;
	incoming.capacity = sizeof(rp);
	if (service_session_call(service_namespace_session, &outgoing, &incoming,
	    &options) == -1) {
		if (errno == EMSGSIZE)
			return (service_provider_protocol_error(
			    service_namespace_session, -1));
		return (-1);
	}
	if (incoming.length != sizeof(rp) || incoming.nfds != 0 ||
	    rp._reserved != 0 || !service_provider_status_valid(rp.status))
		return (service_provider_protocol_error(service_namespace_session, -1));
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	return (0);
}

/*
 * Report the caller's namespace (jail) via bsdnamespace (BSDNAMESPACE_OP_LIST_JAILS).  A
 * label owns at most one jail, so this reports exactly zero or one: out->present
 * is 1 with jid/path/hostname/ip4_addr/ip6_addr/flags filled when the caller has
 * a jail, 0 (and the other fields zeroed) when it has none.  The op is inherently
 * owner-scoped (bsdnamespace names the caller's own jail from its label).  Carries no
 * fd in either direction.  Returns 0 (present==0 is still success), or -1 with
 * errno on a real lookup failure.
 */
int
service_namespace_info(struct service_context *context,
    struct service_namespace_info *out)
{
	struct bsdnamespace_control_request rq;
	struct bsdnamespace_list_reply rp;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	options.timeout_ms = SERVICE_CONTROL_CALL_TIMEOUT_MS;

	if (out == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(out, 0, sizeof(*out));
	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (-1);
	}

	/* Reuse the process-wide system.Namespace channel. */
	if (service_cached_session_get(BSDNAMESPACE_SERVICE_NAME,
	    &service_namespace_session) == -1)
		return (-1);

	memset(&rq, 0, sizeof(rq));
	rq.op = BSDNAMESPACE_OP_LIST_JAILS;
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &rq;
	outgoing.length = sizeof(rq);
	memset(&rp, 0, sizeof(rp));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &rp;
	incoming.capacity = sizeof(rp);
	if (service_session_call(service_namespace_session, &outgoing, &incoming,
	    &options) == -1) {
		if (errno == EMSGSIZE)
			return (service_provider_protocol_error(
			    service_namespace_session, -1));
		return (-1);
	}
	if (incoming.length != sizeof(rp) || incoming.nfds != 0 ||
	    !service_provider_status_valid(rp.status) ||
	    (rp.flags & ~(BSDNAMESPACE_F_VNET | BSDNAMESPACE_F_EPHEMERAL)) != 0 ||
	    (rp.status == 0 && rp.present != 0 && rp.present != 1) ||
	    (rp.status != 0 && (rp.present != 0 || rp.jid != -1 ||
	    rp.flags != 0 ||
	    !service_provider_all_zero(rp.path, sizeof(rp.path)) ||
	    !service_provider_all_zero(rp.hostname, sizeof(rp.hostname)) ||
	    !service_provider_all_zero(rp.ip4_addr, sizeof(rp.ip4_addr)) ||
	    !service_provider_all_zero(rp.ip6_addr, sizeof(rp.ip6_addr)))))
		return (service_provider_protocol_error(service_namespace_session, -1));
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	if (rp.present == 0) {
		if (rp.jid != -1 || rp.flags != 0 ||
		    !service_provider_all_zero(rp.path, sizeof(rp.path)) ||
		    !service_provider_all_zero(rp.hostname, sizeof(rp.hostname)) ||
		    !service_provider_all_zero(rp.ip4_addr, sizeof(rp.ip4_addr)) ||
		    !service_provider_all_zero(rp.ip6_addr, sizeof(rp.ip6_addr)))
			return (service_provider_protocol_error(
			    service_namespace_session, -1));
		return (0);
	}
	if (rp.jid <= 0)
		return (service_provider_protocol_error(service_namespace_session, -1));
	/* Bound every daemon-supplied string before copying it out. */
	if (rp.path[0] != '/' ||
	    strnlen(rp.path, sizeof(rp.path)) >= sizeof(rp.path) ||
	    strnlen(rp.hostname, sizeof(rp.hostname)) >= sizeof(rp.hostname) ||
	    strnlen(rp.ip4_addr, sizeof(rp.ip4_addr)) >= sizeof(rp.ip4_addr) ||
	    strnlen(rp.ip6_addr, sizeof(rp.ip6_addr)) >= sizeof(rp.ip6_addr))
		return (service_provider_protocol_error(service_namespace_session, -1));
	out->present = 1;
	out->jid = rp.jid;
	/* Map the wire BSDNAMESPACE_F_* bits back to the public SERVICE_NS_* set. */
	out->flags = 0;
	if ((rp.flags & BSDNAMESPACE_F_VNET) != 0)
		out->flags |= SERVICE_NS_VNET;
	if ((rp.flags & BSDNAMESPACE_F_EPHEMERAL) != 0)
		out->flags |= SERVICE_NS_EPHEMERAL;
	(void)strlcpy(out->path, rp.path, sizeof(out->path));
	(void)strlcpy(out->hostname, rp.hostname, sizeof(out->hostname));
	(void)strlcpy(out->ip4_addr, rp.ip4_addr, sizeof(out->ip4_addr));
	(void)strlcpy(out->ip6_addr, rp.ip6_addr, sizeof(out->ip6_addr));
	return (0);
}
