/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The system.VM client: service_vsock_listen(3), service_vsock_connect(3) and
 * service_vsock_list(3) over bsd.vm.v1 (vmcmp.fidl).
 *
 * One process-wide session, opened by name on first use and negotiated with
 * GetProtocolInfo.  Transport failures, timeouts and malformed replies drop
 * it (the next call reopens it, which also replaces a session to a provider
 * that died or was relaunched); application errors keep it.  A session
 * inherited across fork or pdfork belongs to the parent and is abandoned.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/vsock.h>

#include <errno.h>
#include <fidl/bsd.vm.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <service_runtime.h>
#include <bsdvm_proto.h>

#include "vmcmp.h"

#define	VMCMP_CALL_TIMEOUT_MS	30000

static pthread_mutex_t vmcmp_lock = PTHREAD_MUTEX_INITIALIZER;
static struct fidl_bsd_connection *vmcmp_connection;
static pid_t vmcmp_owner;
static bool vmcmp_negotiated;

struct completion {
	bool done, malformed;
	int error;
	uint32_t index;			/* Bind: requested window index */
	uint32_t cid, port;		/* Bind: the bound endpoint */
	int fd;
	struct bsd_vm_v1_Window window;
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

/* A concrete port inside some label's window. */
static bool
window_port(uint32_t port)
{
	return (port >= VMD_PORT_BASE &&
	    port < VMD_PORT_BASE + VMD_LABEL_WINDOWS * VMD_PORTS_PER_LABEL);
}

static void
info_reply(void *context, int error, struct bsd_vm_v1_ProtocolInfo *value)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (!error &&
	    (value == NULL || value->wire_version != VMD_WIRE_VERSION)) {
		result->malformed = true;
		result->error = EPROTONOSUPPORT;
	}
}

static void
bind_reply(void *context, int error, struct bsd_vm_v1_VM_Bind_Result *v)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (v == NULL)
		malformed(result);
	else if (v->tag == bsd_vm_v1_VM_Bind_Result_err_tag)
		domain_error(result, v->value.err);
	else if (v->tag != bsd_vm_v1_VM_Bind_Result_response_tag)
		malformed(result);
	else {
		/* Retain the descriptor first so a bad reply cannot leak it. */
		int fd = fidl_bsd_take_fd(&v->value.response.listener);
		uint32_t cid = v->value.response.cid;
		uint32_t port = v->value.response.port;

		/* The bound port must be our index inside an owned window. */
		if (fd < 0 || cid != VMADDR_CID_LOCAL || !window_port(port) ||
		    (port - VMD_PORT_BASE) % VMD_PORTS_PER_LABEL !=
		    result->index) {
			if (fd >= 0)
				(void)close(fd);
			malformed(result);
			return;
		}
		result->fd = fd;
		result->cid = cid;
		result->port = port;
	}
}

static void
connect_reply(void *context, int error, struct bsd_vm_v1_VM_Connect_Result *v)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (v == NULL)
		malformed(result);
	else if (v->tag == bsd_vm_v1_VM_Connect_Result_err_tag)
		domain_error(result, v->value.err);
	else if (v->tag != bsd_vm_v1_VM_Connect_Result_response_tag)
		malformed(result);
	else {
		int fd = fidl_bsd_take_fd(&v->value.response.socket);

		if (fd < 0) {
			malformed(result);
			return;
		}
		result->fd = fd;
	}
}

static void
list_reply(void *context, int error, struct bsd_vm_v1_VM_List_Result *v)
{
	struct completion *result = context;
	const struct bsd_vm_v1_Window *w;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (v == NULL) {
		malformed(result);
		return;
	}
	if (v->tag == bsd_vm_v1_VM_List_Result_err_tag) {
		domain_error(result, v->value.err);
		return;
	}
	if (v->tag != bsd_vm_v1_VM_List_Result_response_tag) {
		malformed(result);
		return;
	}
	/* Strict: an owned, aligned window of the fixed width. */
	w = &v->value.response;
	if (w->cid != VMADDR_CID_LOCAL || w->port_count != VMD_PORTS_PER_LABEL ||
	    !window_port(w->port_base) ||
	    (w->port_base - VMD_PORT_BASE) % VMD_PORTS_PER_LABEL != 0 ||
	    w->port_limit != w->port_base + w->port_count) {
		malformed(result);
		return;
	}
	result->window = *w;
}

/* Drop the cached session.  Caller holds vmcmp_lock. */
static void
session_drop(void)
{

	if (vmcmp_connection != NULL && vmcmp_owner == getpid())
		fidl_bsd_connection_destroy(vmcmp_connection);
	vmcmp_connection = NULL;
	vmcmp_owner = 0;
	vmcmp_negotiated = false;
}

/*
 * Open the process-wide session on first use.  A session inherited across
 * fork is the parent's: forget it without closing it.  Caller holds
 * vmcmp_lock.
 */
static int
session_get(void)
{
	int error, fd;

	if (vmcmp_connection != NULL && vmcmp_owner == getpid())
		return (0);
	vmcmp_connection = NULL;
	vmcmp_negotiated = false;
	if (service_open(VMD_SERVICE_NAME, &fd) == -1)
		return (-1);
	error = fidl_bsd_connection_create(fd, FIDL_BSD_CLIENT,
	    &vmcmp_connection);
	if (error != 0) {
		vmcmp_connection = NULL;
		(void)close(fd);
		return (errno = error, -1);
	}
	vmcmp_owner = getpid();
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
		error = fidl_bsd_sync_wait(vmcmp_connection, &result->done,
		    deadline);
	if (error == 0 && result->malformed)
		error = result->error;
	/* A reply failed by the transport (the peer closed) is not an
	 * application error: the session is gone. */
	if (error == 0 && result->error != 0 &&
	    fidl_bsd_connection_error(vmcmp_connection) != 0)
		error = result->error;
	if (error != 0) {
		session_drop();
		return (errno = error, -1);
	}
	if (result->error != 0)
		return (errno = result->error, -1);
	return (0);
}

/* Open or reuse the session and negotiate.  Caller holds vmcmp_lock. */
static int
begin_locked(struct timespec *deadline)
{
	struct completion result = { .fd = -1 };
	struct fidl_bsd_empty empty = { 0 };
	uint32_t timeout_ms = VMCMP_CALL_TIMEOUT_MS, txid;
	int error;

	/* A caller's service_budget_begin(3) bounds the whole operation. */
	if (service_budget_timeout(&timeout_ms) == -1)
		return (-1);
	if ((error = fidl_bsd_sync_deadline(deadline, timeout_ms)) != 0)
		return (errno = error, -1);
	if (session_get() == -1)
		return (-1);
	if (vmcmp_negotiated)
		return (0);
	error = bsd_vm_v1_VM_GetProtocolInfo(vmcmp_connection, &empty,
	    info_reply, &result, &txid);
	if (finish_locked(error, &result, deadline) == -1)
		return (-1);
	vmcmp_negotiated = true;
	return (0);
}

/* Close a descriptor a failed call may have received, preserving errno. */
static int
fail_closing(struct completion *result)
{
	int error = errno;

	if (result->fd >= 0)
		(void)close(result->fd);
	return (errno = error, -1);
}

int
service_vsock_listen(struct service_context *context, unsigned port,
    unsigned backlog, unsigned *cidp, unsigned *portp, int *fdp)
{
	struct completion result = { .fd = -1 };
	struct bsd_vm_v1_BindRequest request;
	struct timespec deadline;
	uint32_t txid;
	int rc;

	if (fdp == NULL || port >= VMD_PORTS_PER_LABEL)
		return (errno = EINVAL, -1);
	*fdp = -1;
	if (service_context_check(context) != 0)
		return (errno = EINVAL, -1);
	request.index = port;
	request.backlog = backlog;
	result.index = port;

	pthread_mutex_lock(&vmcmp_lock);
	rc = begin_locked(&deadline);
	if (rc == 0)
		rc = finish_locked(bsd_vm_v1_VM_Bind(vmcmp_connection, &request,
		    bind_reply, &result, &txid), &result, &deadline);
	pthread_mutex_unlock(&vmcmp_lock);
	if (rc == -1)
		return (fail_closing(&result));
	if (cidp != NULL)
		*cidp = result.cid;
	if (portp != NULL)
		*portp = result.port;
	*fdp = result.fd;
	return (0);
}

int
service_vsock_connect(struct service_context *context, unsigned cid,
    unsigned port, int *fdp)
{
	struct completion result = { .fd = -1 };
	struct bsd_vm_v1_ConnectRequest request;
	struct timespec deadline;
	uint32_t txid;
	int rc;

	/* 0xffffffff == VMADDR_CID_ANY: never a valid connect target. */
	if (fdp == NULL || cid == 0xffffffffu)
		return (errno = EINVAL, -1);
	*fdp = -1;
	if (service_context_check(context) != 0)
		return (errno = EINVAL, -1);
	request.cid = cid;
	request.port = port;

	pthread_mutex_lock(&vmcmp_lock);
	rc = begin_locked(&deadline);
	if (rc == 0)
		rc = finish_locked(bsd_vm_v1_VM_Connect(vmcmp_connection,
		    &request, connect_reply, &result, &txid), &result,
		    &deadline);
	pthread_mutex_unlock(&vmcmp_lock);
	if (rc == -1)
		return (fail_closing(&result));
	*fdp = result.fd;
	return (0);
}

int
service_vsock_list(struct service_context *context, unsigned *cidp,
    unsigned *port_basep, unsigned *port_countp)
{
	struct completion result = { .fd = -1 };
	struct fidl_bsd_empty empty = { 0 };
	struct timespec deadline;
	uint32_t txid;
	int rc;

	if (service_context_check(context) != 0)
		return (errno = EINVAL, -1);

	pthread_mutex_lock(&vmcmp_lock);
	rc = begin_locked(&deadline);
	if (rc == 0)
		rc = finish_locked(bsd_vm_v1_VM_List(vmcmp_connection, &empty,
		    list_reply, &result, &txid), &result, &deadline);
	pthread_mutex_unlock(&vmcmp_lock);
	if (rc == -1)
		return (-1);
	if (cidp != NULL)
		*cidp = result.window.cid;
	if (port_basep != NULL)
		*port_basep = result.window.port_base;
	if (port_countp != NULL)
		*port_countp = result.window.port_count;
	return (0);
}
