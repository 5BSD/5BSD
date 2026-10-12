/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsddevice(8): the system.Device capability provider.  A socket-free
 * service_provider, born in capability mode: switchboard delivers /dev as a
 * directory descriptor (manifest directories = ["/dev"]) and bsddevice opens
 * named leaves beneath it with openat(2), narrows the descriptor to exactly the
 * per-label policy rights, and hands it back over the client's own
 * mac_capability channel.  Default-deny: a label/device pair with no policy
 * entry is refused.  Mirrors bsdcrypto(8)'s accept/pdfork worker structure.
 * Sessions speak FIDL bsd.device.v1 (lib/libdevicecmp/devicecmp.fidl).
 */
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <devicecmp.h>
#include <fidl/bsd.device.v1/c/bsd.h>
#include <libservice.h>
#include <service_runtime.h>

#include "policy.h"
#include "bsddevice_probes.h"
#ifdef BSDDEVICE_TESTING
#include "bsddevice_test.h"
#endif

#define	DEVICECMP_NAME		"system.Device"
#define	DEVICECMP_CONFIG_FILE	"device.conf"

static int devdir = -1;			/* borrowed /dev directory descriptor */
static struct devicecmp_config config;	/* compiled default-deny + overlay */

struct device_worker {
	char	label[DEVICECMP_LABEL_MAX];
	bool	negotiated;
};

/*
 * Open the requested /dev leaf under the retained /dev directory descriptor and
 * return a Capsicum-narrowed, single-transfer descriptor for delivery.  Returns
 * the fd (>=0) with *granted set to the rights actually granted, or -1 with
 * errno (EACCES when policy does not grant the label this device/rights).
 */
static int
grant_open(const char *label, uint32_t wanted, const char *name,
    uint32_t *granted)
{
	const unsigned long *ioctls;
	cap_rights_t rights;
	uint32_t maxr, effective;
	unsigned nioctls;
	int flags, fd, saved;

	*granted = 0;
	if (!devicecmp_valid_device_name(name))
		return (errno = EINVAL, -1);
	maxr = devicecmp_policy_lookup(&config, label, name, &ioctls, &nioctls);
	if (maxr == 0)
		return (errno = EACCES, -1);
	effective = wanted & maxr & DEVICECMP_RIGHT_ALL;
	if (effective == 0)
		return (errno = EACCES, -1);

	/*
	 * Derive open flags from the granted read/write rights.  An ioctl-,
	 * mmap-, seek-, or event-only grant still needs an open mode; O_RDONLY
	 * is the least-authority base for a control/event descriptor.
	 */
	if ((effective & (DEVICECMP_RIGHT_READ | DEVICECMP_RIGHT_WRITE)) ==
	    (DEVICECMP_RIGHT_READ | DEVICECMP_RIGHT_WRITE))
		flags = O_RDWR;
	else if (effective & DEVICECMP_RIGHT_WRITE)
		flags = O_WRONLY;
	else
		flags = O_RDONLY;
	flags |= O_CLOEXEC | O_NONBLOCK | O_NOCTTY;

	fd = openat(devdir, name, flags);
	if (fd == -1)
		return (-1);

	cap_rights_init(&rights, CAP_FSTAT);
	if (effective & DEVICECMP_RIGHT_READ)
		cap_rights_set(&rights, CAP_READ);
	if (effective & DEVICECMP_RIGHT_WRITE)
		cap_rights_set(&rights, CAP_WRITE);
	if (effective & DEVICECMP_RIGHT_IOCTL)
		cap_rights_set(&rights, CAP_IOCTL);
	if (effective & DEVICECMP_RIGHT_MMAP)
		cap_rights_set(&rights, CAP_MMAP);
	if (effective & DEVICECMP_RIGHT_SEEK)
		cap_rights_set(&rights, CAP_SEEK);
	if (effective & DEVICECMP_RIGHT_EVENT)
		cap_rights_set(&rights, CAP_EVENT);
	if (cap_rights_limit(fd, &rights) == -1)
		goto fail;

	/*
	 * A delivered CAP_IOCTL descriptor must NEVER be able to issue every ioctl
	 * the node supports.  Apply the per-device command whitelist when policy
	 * carries one; when the ioctl right is granted with NO whitelist (a policy
	 * that says "ioctl" but lists no commands), fail closed with an EMPTY set
	 * (deny every ioctl) rather than leaving CAP_IOCTL unrestricted -- an
	 * unbounded ioctl grant is not a valid grant.
	 */
	if (effective & DEVICECMP_RIGHT_IOCTL) {
		if (nioctls == 0)
			syslog(LOG_WARNING, "policy grants ioctl on %s with no command "
			    "whitelist; denying all ioctls (fail-closed)", name);
		if (cap_ioctls_limit(fd, ioctls, nioctls) == -1)
			goto fail;
	}

	/*
	 * Harden for delivery: the descriptor may be transferred exactly once
	 * (this SCM_RIGHTS reply to the client) and no further, survives exactly
	 * one more fork, and is close-on-exec locked.
	 */
	if (service_harden_fd(fd, SERVICE_HARDEN_XFER_ONCE |
	    SERVICE_HARDEN_CLOFORK_ONCE) == -1)
		goto fail;

	*granted = effective;
	return (fd);

fail:
	saved = errno;
	(void)close(fd);
	errno = saved;
	return (-1);
}

/*
 * bsd.device.v1 method handlers.  Every method requires a negotiated session.
 * A failed reply closes the connection.  The request-done probe keeps the
 * historical DEVICECMP_OP_* codes (0 is protocol negotiation).
 */
static bool
ready(struct device_worker *worker, struct fidl_bsd_connection *connection,
    uint32_t opcode)
{
	if (worker->negotiated)
		return (true);
	BSDDEVICE_PROBE_REQUEST_DONE(opcode, -EPROTO, EPROTO);
	fidl_bsd_connection_close(connection, EPROTO);
	return (false);
}

static void
completed(struct fidl_bsd_connection *connection, uint32_t opcode, int error,
    int transport_error)
{
	BSDDEVICE_PROBE_REQUEST_DONE(opcode, -error, transport_error);
	if (transport_error != 0)
		fidl_bsd_connection_close(connection, transport_error);
}

static void
protocol_info(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct device_worker *worker = argument;
	struct bsd_device_v1_ProtocolInfo info = { DEVICECMP_WIRE_VERSION };
	int error;

	error = bsd_device_v1_Device_GetProtocolInfo_reply(connection, request,
	    &info);
	worker->negotiated = error == 0;
	completed(connection, 0, 0, error);
}

static void
open_device(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_device_v1_OpenRequest *value)
{
	struct device_worker *worker = argument;
	struct bsd_device_v1_Device_Open_Result reply = { 0 };
	char name[DEVICECMP_MAX_NAME];
	uint32_t granted = 0;
	int error, fd = -1;

	if (!ready(worker, connection, DEVICECMP_OP_OPEN))
		return;
	/* A single leaf without embedded NULs; the schema bounds the length. */
	if (value->name_size == 0 || value->name_size >= sizeof(name) ||
	    memchr(value->name, '\0', value->name_size) != NULL) {
		name[0] = '\0';
		error = EINVAL;
	} else {
		memcpy(name, value->name, value->name_size);
		name[value->name_size] = '\0';
		fd = grant_open(worker->label, value->rights, name, &granted);
		error = fd >= 0 ? 0 : errno;
		BSDDEVICE_PROBE_OPEN(worker->label, name, granted, error);
	}
	if (error == 0) {
		reply.tag = bsd_device_v1_Device_Open_Result_response_tag;
		reply.value.response.device = fd;
		reply.value.response.rights = granted;
	} else {
		reply.tag = bsd_device_v1_Device_Open_Result_err_tag;
		reply.value.err = (uint32_t)error;
	}
	/* The bindings send a private duplicate; ours is closed either way. */
	completed(connection, DEVICECMP_OP_OPEN, error,
	    bsd_device_v1_Device_Open_reply(connection, request, &reply));
	if (fd >= 0)
		(void)close(fd);
}

static void
list_devices(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_device_v1_ListRequest *value)
{
	struct device_worker *worker = argument;
	struct bsd_device_v1_Device_List_Result reply = { 0 };
	struct devicecmp_list_entry entries[DEVICECMP_LIST_MAX];
	struct bsd_device_v1_DeviceEntry out[DEVICECMP_LIST_MAX];
	uint32_t count = 0, next = 0;

	if (!ready(worker, connection, DEVICECMP_OP_LIST))
		return;
	/*
	 * Strictly label-scoped: the walk filters on worker->label -- the
	 * connecting channel's unforgeable identity -- never a wire argument.
	 * Default-deny: a label with no policy entry lists empty.
	 */
	memset(entries, 0, sizeof(entries));
	devicecmp_policy_list(&config, worker->label, value->cursor, entries,
	    DEVICECMP_LIST_MAX, &count, &next);
	BSDDEVICE_PROBE_LIST(worker->label, value->cursor, count, 0);
	for (uint32_t i = 0; i < count; i++) {
		out[i].name = entries[i].name;
		out[i].name_size = strnlen(entries[i].name,
		    sizeof(entries[i].name));
		out[i].rights = entries[i].rights;
		out[i].flags = entries[i].flags;
	}
	reply.tag = bsd_device_v1_Device_List_Result_response_tag;
	reply.value.response.entries = out;
	reply.value.response.entries_size = count;
	reply.value.response.next_cursor = next;
	completed(connection, DEVICECMP_OP_LIST, 0,
	    bsd_device_v1_Device_List_reply(connection, request, &reply));
}

/* Serve one client on its own worker channel until it disconnects. */
static int
serve_session(int fd, const char *label)
{
	static const struct bsd_device_v1_Device_server handlers = {
		.GetProtocolInfo = protocol_info,
		.Open = open_device,
		.List = list_devices
	};
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	struct fidl_bsd_connection *connection;
	struct device_worker state;

	memset(&state, 0, sizeof(state));
	strlcpy(state.label, label, sizeof(state.label));
	/* One request at a time; requests carry no descriptors. */
	options.max_pending_requests = 1;
	options.max_queued_messages = 16;
	options.max_queued_bytes = 64 * 1024;
	options.max_queued_fds = 1;
	if (fidl_bsd_connection_create_with_options(fd, FIDL_BSD_SERVER,
	    &options, &connection) != 0) {
		(void)close(fd);
		return (1);
	}
	/*
	 * grant_open() hardens each delivered descriptor itself (transfer
	 * once, survive one more fork, close-on-exec locked); keep that state.
	 */
	fidl_bsd_connection_preserve_sent_inheritance(connection);
	if (bsd_device_v1_Device_bind(connection, &handlers, &state) != 0) {
		fidl_bsd_connection_destroy(connection);
		return (1);
	}
	/* Peer close or a protocol violation ends the session. */
	while (fidl_bsd_connection_poll(connection, -1) == 0)
		;
	fidl_bsd_connection_destroy(connection);
	return (0);
}

#ifdef BSDDEVICE_TESTING
/*
 * Test entrypoint: run the real per-label serve path against a caller-owned
 * channel descriptor with a caller-supplied client label.  It opens the /dev
 * directory descriptor exactly as production's switchboard-delivered one but omits
 * the switchboard-only sandbox wrappers (worker protect/authority-drop/cap_enter)
 * so the ATF process keeps running.  Policy is installed out-of-band via
 * bsddevice_test_set_config(); default-deny plus per-device Capsicum rights
 * narrowing are the true isolation properties this exercises end-to-end.
 */
void
bsddevice_test_set_config(const struct devicecmp_config *cfg)
{

	config = *cfg;
}

int
bsddevice_test_serve(int fd, const char *label)
{

	if (fd < 0 || label == NULL ||
	    strnlen(label, DEVICECMP_LABEL_MAX) == 0 ||
	    strnlen(label, DEVICECMP_LABEL_MAX) == DEVICECMP_LABEL_MAX)
		return (errno = EINVAL, -1);
	if (devdir < 0) {
		devdir = open("/dev", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
		if (devdir < 0)
			return (-1);
	}
	return (serve_session(fd, label));
}
#endif /* BSDDEVICE_TESTING */

#ifndef BSDDEVICE_TESTING
static int
worker(int fd, const char *label)
{
	setproctitle("-BSDDevice: %s", label);

	/*
	 * The retained /dev directory descriptor is already open, so the worker
	 * needs no privileges and no further forks/IPC/exec; it only reads its
	 * channel and openat(2)s beneath devdir.
	 */
	if (service_worker_enter_capability_mode(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOFDRECV |
	    SERVICE_PROTECT_NOEXEC | SERVICE_PROTECT_NOSOCK) == -1)
		return (1);
	return (serve_session(fd, label));
}

static int
start_session(int fd, const char *peer_label, int *pdp)
{
	int pd;
	pid_t pid;
	char label[DEVICECMP_LABEL_MAX];

	if (strnlen(peer_label, sizeof(label)) == 0 ||
	    strnlen(peer_label, sizeof(label)) == sizeof(label))
		return (errno = EINVAL, -1);
	strlcpy(label, peer_label, sizeof(label));
	pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON | PD_NOWAITPID);
	if (pid == -1)
		return (-1);
	if (pid == 0)
		_exit(worker(fd, label));
	*pdp = pd;	/* parent tracks the worker's process descriptor */
	return (0);
}

#define	DEVICECMP_MAX_WORKERS	4096u

struct device_worker_ent {
	struct service_process process; /* First: shared teardown owns this node. */
	char label[64];
};

#define	DEVICE_MAX_LABEL_WORKERS	64u

/* The caller serializes admission and removal using authenticated labels. */
static bool
device_worker_admit(const struct service_process *workers, const char *label)
{
	unsigned same = 0;

	for (; workers != NULL; workers = workers->next)
		if (strcmp(((const struct device_worker_ent *)workers)->label, label) == 0 &&
		    ++same >= DEVICE_MAX_LABEL_WORKERS)
			return (false);
	return (true);
}


static void
device_worker_ent_remove(struct service_process **head,
    struct service_process *w, size_t *count)
{
	struct service_process **cursor;
	int status;

	for (cursor = head; *cursor != NULL && *cursor != w;
	    cursor = &(*cursor)->next)
		;
	if (*cursor == w)
		*cursor = w->next;
	(void)pdwait(w->pd, &status, WEXITED | WNOHANG, NULL, NULL);
	(void)close(w->pd);
	free(w);
	if (*count != 0)
		(*count)--;
}

/* Stop admission workers before acknowledging provider shutdown. */
static int
device_workers_stop(struct service_process **head, size_t *count)
{
	int result;

	result = service_processes_stop(head);
	*count = 0;
	return (result);
}

/*
 * Load the optional per-label device policy from the bundle Config/ file.  Done
 * before entering capability mode so the path fallback works for a legacy
 * launch; the compiled-in config is default-deny, so a missing file is fine.
 */
static void
load_policy(void)
{
	int cfgfd;

	devicecmp_config_defaults(&config);
	if (service_config_open(DEVICECMP_CONFIG_FILE, &cfgfd) == -1) {
		if (errno != ENOENT)
			syslog(LOG_WARNING, "config %s: %m",
			    DEVICECMP_CONFIG_FILE);
		return;
	}
	if (devicecmp_config_load_fd(&config, cfgfd) == -1)
		syslog(LOG_WARNING, "config %s: %m (default-deny stands)",
		    DEVICECMP_CONFIG_FILE);
	(void)close(cfgfd);
}

int
main(void)
{
	struct service_process *workers = NULL;
	struct service_identity id;
	struct service_listener *listener;
	struct service_provider *provider = NULL;
	struct kevent event, change;
	size_t nworkers = 0;
	int fd, kq = -1, result = 1;

	service_set_proctitle();
	openlog("bsddevice", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	load_policy();

	/*
	 * Born in capability mode: switchboard delivered /dev as a directory
	 * descriptor (manifest directories = ["/dev"]); open device leaves
	 * beneath it with openat(2) rather than by global path.
	 */
	if (service_resource_dir("/dev", &devdir) == -1)
		goto out;

	/*
	 * Self-harden the accept/fork parent.  It must still pdfork workers and
	 * receive connection descriptors, so NOFORK/NOFDRECV are not applied;
	 * NOPRIVS is safe because /dev is already open (mirrors bsdcrypto).
	 */
	if (devdir < 0 || service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_provider_expose(provider, DEVICECMP_NAME, &listener) == -1)
		goto out;

	/*
	 * A kqueue drives the accept loop AND watches each worker's process
	 * descriptor so the live-worker count stays bounded (DEVICECMP_MAX_WORKERS):
	 * a client cannot fork-bomb the broker by churning connections.
	 */
	kq = kqueuex(KQUEUE_CLOEXEC);
	if (kq == -1)
		goto out;
	EV_SET(&change, service_listener_fd(listener), EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, listener);
	if (kevent(kq, &change, 1, NULL, 0, NULL) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		goto out;

	for (;;) {
		struct service_process *w;

		if (kevent(kq, NULL, 0, &event, 1, NULL) == -1) {
			if (errno == EINTR)
				continue;
			goto out;
		}
		if (event.filter == EVFILT_PROCDESC) {
			device_worker_ent_remove(&workers, event.udata,
			    &nworkers);
			continue;
		}
		memset(&id, 0, sizeof(id));
		id.size = sizeof(id);
		if (service_listener_accept(listener, &id, &fd) == -1) {
			if (errno == EINTR)
				continue;
			if (service_provider_quiescing(provider) == 1) {
				if (nworkers != 0) {
					if (service_provider_quiesce_complete(provider,
					    EBUSY) == 0)
						continue;
					if (errno != EINVAL)
						goto out;
				}
				result = 0;
			}
			goto out;
		}
		if (nworkers >= DEVICECMP_MAX_WORKERS ||
		    !device_worker_admit(workers, id.client_label)) {
			syslog(LOG_WARNING, "worker limit reached; dropping %s",
			    id.client_label);
			(void)close(fd);
			continue;
		}
		w = calloc(1, sizeof(struct device_worker_ent));
		if (w == NULL || start_session(fd, id.client_label,
		    &w->pd) == -1) {
			syslog(LOG_WARNING, "session for %s rejected: %m",
			    id.client_label);
			free(w);
			(void)close(fd);
			continue;
		}
		(void)close(fd);
		EV_SET(&change, w->pd, EVFILT_PROCDESC, EV_ADD | EV_ENABLE,
		    NOTE_EXIT, 0, w);
		if (service_harden_fd(w->pd, 0) == -1 ||
		    kevent(kq, &change, 1, NULL, 0, NULL) == -1) {
			int status;

			/*
			 * Cannot watch it.  The child runs under a PD_DAEMON
			 * descriptor, so close(pd) would NOT kill it -- it would
			 * keep serving its client as an unwatched, unreapable
			 * orphan still holding the delivered /dev dirfd.  KILL,
			 * reap, then drop our handle.  It is not on the list yet
			 * and was never counted (nworkers++ is below), so leave
			 * nworkers untouched (device_worker_ent_remove would
			 * decrement it and could not kill a live PD_DAEMON child).
			 */
			syslog(LOG_WARNING, "procdesc watch for %s: %m",
			    id.client_label);
			(void)pdkill(w->pd, SIGKILL);
			while (pdwait(w->pd, &status, WEXITED, NULL, NULL) == -1 &&
			    errno == EINTR)
				;
			(void)close(w->pd);
			free(w);
			continue;
		}
		strlcpy(((struct device_worker_ent *)w)->label,
		    id.client_label, sizeof(((struct device_worker_ent *)w)->label));
		w->next = workers;
		workers = w;
		nworkers++;
	}
out:
	if (device_workers_stop(&workers, &nworkers) == -1)
		result = 1;
	if (kq != -1)
		close(kq);
	if (result == 0 && service_provider_quiesce_complete(provider, 0) == -1)
		result = 1;
	if (provider != NULL)
		service_provider_destroy(provider);
	return (result);
}
#endif /* !BSDDEVICE_TESTING */
