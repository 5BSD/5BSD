/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The system.Namespace client: service_enter_namespace(3),
 * service_enter_namespace_ex(3), service_destroy_namespace(3) and
 * service_namespace_info(3) over bsd.namespace.v1 (namespacecmp.fidl).
 *
 * One process-wide session, opened by name on first use and negotiated with
 * GetProtocolInfo.  Transport failures, timeouts and malformed replies drop
 * it (the next call reopens it, which also replaces a session to a provider
 * that died or was relaunched); application errors keep it.  A session
 * inherited across fork or pdfork belongs to the parent and is abandoned.
 * The session must outlive an ephemeral Enter: the provider anchors that
 * jail's lifetime to it.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/jail.h>
#include <sys/stat.h>

#include <errno.h>
#include <fidl/bsd.namespace.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <service_runtime.h>
#include <bsdnamespace_proto.h>

#include "namespacecmp.h"

/*
 * Bound for the system.Namespace control calls.  Without a finite
 * timeout a provider that is up-but-wedged (accepted the connection but never
 * replies) would block the calling daemon thread forever.  A crashed provider is
 * already handled -- the transport reports the reset -- so this only covers
 * the wedged case; 30s is generous for a jail create.
 */
#define	NAMESPACECMP_CALL_TIMEOUT_MS	30000

static pthread_mutex_t namespacecmp_lock = PTHREAD_MUTEX_INITIALIZER;
static struct fidl_bsd_connection *namespacecmp_connection;
static pid_t namespacecmp_owner;
static bool namespacecmp_negotiated;

struct completion {
	bool done, malformed;
	int error;
	int fd;
	struct service_namespace_info *info;
};

static void
malformed(struct completion *result)
{
	result->malformed = true;
	result->error = EPROTO;
}

static void
domain_error(struct completion *result, uint32_t error)
{
	if (error == 0 || error > ELAST)
		malformed(result);
	else
		result->error = (int)error;
}

/* Copy a provider string out, refusing an embedded NUL or overflow. */
static bool
copy_string(char *out, size_t outsz, const char *in, size_t len)
{

	if (len >= outsz || (len != 0 && memchr(in, '\0', len) != NULL))
		return (false);
	if (len != 0)
		memcpy(out, in, len);
	out[len] = '\0';
	return (true);
}

static void
info_reply(void *context, int error,
    struct bsd_namespace_v1_ProtocolInfo *value)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (!error && (value == NULL ||
	    value->wire_version != BSDNAMESPACE_WIRE_VERSION)) {
		result->malformed = true;
		result->error = EPROTONOSUPPORT;
	}
}

static void
enter_reply(void *context, int error,
    struct bsd_namespace_v1_Namespace_Enter_Result *v)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (v == NULL)
		malformed(result);
	else if (v->tag == bsd_namespace_v1_Namespace_Enter_Result_err_tag)
		domain_error(result, v->value.err);
	else if (v->tag != bsd_namespace_v1_Namespace_Enter_Result_response_tag)
		malformed(result);
	else {
		result->fd = fidl_bsd_take_fd(&v->value.response.jail);
		if (result->fd < 0)
			malformed(result);
	}
}

static void
destroy_reply(void *context, int error,
    struct bsd_namespace_v1_Namespace_Destroy_Result *v)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (v == NULL)
		malformed(result);
	else if (v->tag == bsd_namespace_v1_Namespace_Destroy_Result_err_tag)
		domain_error(result, v->value.err);
	else if (v->tag !=
	    bsd_namespace_v1_Namespace_Destroy_Result_response_tag)
		malformed(result);
}

static void
list_reply(void *context, int error,
    struct bsd_namespace_v1_Namespace_List_Result *v)
{
	struct completion *result = context;
	struct service_namespace_info *out = result->info;
	const struct bsd_namespace_v1_JailInfo *jail;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (v == NULL) {
		malformed(result);
		return;
	}
	if (v->tag == bsd_namespace_v1_Namespace_List_Result_err_tag) {
		domain_error(result, v->value.err);
		return;
	}
	if (v->tag != bsd_namespace_v1_Namespace_List_Result_response_tag) {
		malformed(result);
		return;
	}
	jail = v->value.response.jail;
	if (jail == NULL)
		return;			/* the caller has no jail */
	/* Bound every provider-supplied value before copying it out. */
	if (jail->jid <= 0 ||
	    (jail->flags & ~(BSDNAMESPACE_F_VNET | BSDNAMESPACE_F_EPHEMERAL)) !=
	    0 || jail->path_size == 0 || jail->path[0] != '/' ||
	    !copy_string(out->path, sizeof(out->path), jail->path,
	    jail->path_size) ||
	    !copy_string(out->hostname, sizeof(out->hostname), jail->hostname,
	    jail->hostname_size) ||
	    !copy_string(out->ip4_addr, sizeof(out->ip4_addr), jail->ip4_addr,
	    jail->ip4_addr_size) ||
	    !copy_string(out->ip6_addr, sizeof(out->ip6_addr), jail->ip6_addr,
	    jail->ip6_addr_size)) {
		memset(out, 0, sizeof(*out));
		malformed(result);
		return;
	}
	out->present = 1;
	out->jid = jail->jid;
	/* Map the wire BSDNAMESPACE_F_* bits back to the public SERVICE_NS_* set. */
	out->flags = 0;
	if ((jail->flags & BSDNAMESPACE_F_VNET) != 0)
		out->flags |= SERVICE_NS_VNET;
	if ((jail->flags & BSDNAMESPACE_F_EPHEMERAL) != 0)
		out->flags |= SERVICE_NS_EPHEMERAL;
}

/* Drop the cached session.  Caller holds namespacecmp_lock. */
static void
session_drop(void)
{

	if (namespacecmp_connection != NULL && namespacecmp_owner == getpid())
		fidl_bsd_connection_destroy(namespacecmp_connection);
	namespacecmp_connection = NULL;
	namespacecmp_owner = 0;
	namespacecmp_negotiated = false;
}

/*
 * Open the process-wide session on first use.  A session inherited across
 * fork is the parent's: forget it without closing it.  Caller holds
 * namespacecmp_lock.
 */
static int
session_get(void)
{
	int error, fd;

	if (namespacecmp_connection != NULL && namespacecmp_owner == getpid())
		return (0);
	namespacecmp_connection = NULL;
	namespacecmp_negotiated = false;
	if (service_open(BSDNAMESPACE_SERVICE_NAME, &fd) == -1)
		return (-1);
	error = fidl_bsd_connection_create(fd, FIDL_BSD_CLIENT,
	    &namespacecmp_connection);
	if (error != 0) {
		namespacecmp_connection = NULL;
		(void)close(fd);
		return (errno = error, -1);
	}
	namespacecmp_owner = getpid();
	return (0);
}

/*
 * Wait for one completion with the lock held.  Transport failures, timeouts
 * and malformed replies drop the session; application errors keep it.
 */
static int
finish_locked(int error, struct completion *result,
    const struct timespec *deadline)
{

	if (error == 0)
		error = fidl_bsd_sync_wait(namespacecmp_connection,
		    &result->done, deadline);
	if (error == 0 && result->malformed)
		error = result->error;
	/* A reply failed by the transport (the peer closed) is not an
	 * application error: the session is gone. */
	if (error == 0 && result->error != 0 &&
	    fidl_bsd_connection_error(namespacecmp_connection) != 0)
		error = result->error;
	if (error != 0) {
		session_drop();
		return (errno = error, -1);
	}
	if (result->error != 0)
		return (errno = result->error, -1);
	return (0);
}

/* Open or reuse the session and negotiate.  Caller holds namespacecmp_lock. */
static int
begin_locked(struct timespec *deadline)
{
	struct completion result = { .fd = -1 };
	struct fidl_bsd_empty empty = { 0 };
	uint32_t timeout_ms = NAMESPACECMP_CALL_TIMEOUT_MS, txid;
	int error;

	/* A caller's service_budget_begin(3) bounds the whole operation. */
	if (service_budget_timeout(&timeout_ms) == -1)
		return (-1);
	if ((error = fidl_bsd_sync_deadline(deadline, timeout_ms)) != 0)
		return (errno = error, -1);
	if (session_get() == -1)
		return (-1);
	if (namespacecmp_negotiated)
		return (0);
	error = bsd_namespace_v1_Namespace_GetProtocolInfo(
	    namespacecmp_connection, &empty, info_reply, &result, &txid);
	if (finish_locked(error, &result, deadline) == -1)
		return (-1);
	namespacecmp_negotiated = true;
	return (0);
}

/*
 * Confine this process to its namespace (jail) via bsdnamespace(8).  Consumer self-
 * service, uniform with storage/modules: libnamespacecmp opens a system.Namespace
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
 * down when the process exits; this library itself only attaches.  Returns 0, or
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
	struct completion result = { .fd = -1 };
	struct bsd_namespace_v1_EnterRequest request;
	struct timespec deadline;
	uint32_t txid;
	int jd, rc, saved;

	if (path == NULL || path[0] != '/' ||
	    (flags & ~(SERVICE_NS_EPHEMERAL | SERVICE_NS_VNET))) {
		errno = EINVAL;
		return (-1);
	}
	if (hostname == NULL)
		hostname = "";
	if (ip4_addr == NULL)
		ip4_addr = "";
	if (ip6_addr == NULL)
		ip6_addr = "";
	/* The legacy record's field sizes, NUL included. */
	if (strnlen(path, PATH_MAX) >= PATH_MAX ||
	    strnlen(hostname, 64) >= 64 || strnlen(ip4_addr, 64) >= 64 ||
	    strnlen(ip6_addr, 64) >= 64) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	if (flags & SERVICE_NS_EPHEMERAL)
		request.flags |= BSDNAMESPACE_F_EPHEMERAL;
	if (flags & SERVICE_NS_VNET)
		request.flags |= BSDNAMESPACE_F_VNET;
	request.path = path;
	request.path_size = strlen(path);
	request.hostname = hostname;
	request.hostname_size = strlen(hostname);
	request.ip4_addr = ip4_addr;
	request.ip4_addr_size = strlen(ip4_addr);
	request.ip6_addr = ip6_addr;
	request.ip6_addr_size = strlen(ip6_addr);

	pthread_mutex_lock(&namespacecmp_lock);
	rc = begin_locked(&deadline);
	if (rc == 0)
		rc = finish_locked(bsd_namespace_v1_Namespace_Enter(
		    namespacecmp_connection, &request, enter_reply, &result,
		    &txid), &result, &deadline);
	pthread_mutex_unlock(&namespacecmp_lock);
	if (rc == -1) {
		saved = errno;
		if (result.fd >= 0)
			(void)close(result.fd);
		errno = saved;
		return (-1);
	}
	jd = result.fd;

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
 * Destroy the caller's namespace (jail) via bsdnamespace.
 * The jail acted on is the ONE scoped by this process's unforgeable channel
 * label (bsdnamespace derives its name), so a caller can never name another's jail.
 * Carries no fd in either direction.  Returns 0 once the jail is gone, or -1
 * with errno (ENOENT if the caller has no jail).
 */
int
service_destroy_namespace(struct service_context *context)
{
	struct completion result = { .fd = -1 };
	struct fidl_bsd_empty empty = { 0 };
	struct timespec deadline;
	uint32_t txid;
	int rc;

	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (-1);
	}
	pthread_mutex_lock(&namespacecmp_lock);
	rc = begin_locked(&deadline);
	if (rc == 0)
		rc = finish_locked(bsd_namespace_v1_Namespace_Destroy(
		    namespacecmp_connection, &empty, destroy_reply, &result,
		    &txid), &result, &deadline);
	pthread_mutex_unlock(&namespacecmp_lock);
	return (rc);
}

/*
 * Report the caller's namespace (jail) via bsdnamespace.  A
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
	struct completion result = { .fd = -1 };
	struct fidl_bsd_empty empty = { 0 };
	struct timespec deadline;
	uint32_t txid;
	int rc, saved;

	if (out == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(out, 0, sizeof(*out));
	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (-1);
	}
	result.info = out;
	pthread_mutex_lock(&namespacecmp_lock);
	rc = begin_locked(&deadline);
	if (rc == 0)
		rc = finish_locked(bsd_namespace_v1_Namespace_List(
		    namespacecmp_connection, &empty, list_reply, &result,
		    &txid), &result, &deadline);
	pthread_mutex_unlock(&namespacecmp_lock);
	if (rc == -1) {
		saved = errno;
		memset(out, 0, sizeof(*out));
		errno = saved;
	}
	return (rc);
}
