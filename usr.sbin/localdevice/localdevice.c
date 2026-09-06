/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * localdevice(8): the system.Device capability provider.  A socket-free
 * service_provider, born in capability mode: serviced delivers /dev as a
 * directory descriptor (manifest directories = ["/dev"]) and localdevice opens
 * named leaves beneath it with openat(2), narrows the descriptor to exactly the
 * per-label policy rights, and hands it back over the client's own
 * mac_capability channel.  Default-deny: a label/device pair with no policy
 * entry is refused.  Mirrors localcrypto(8)'s accept/pdfork worker structure.
 */
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/procdesc.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <channel.h>
#include <devicecmp_protocol.h>
#include <libservice.h>

#include "policy.h"
#include "localdevice_probes.h"
#ifdef LOCALDEVICE_TESTING
#include "localdevice_test.h"
#endif

#define	DEVICECMP_NAME		"system.Device"
#define	DEVICECMP_CONFIG_FILE	"device.conf"

static int devdir = -1;			/* borrowed /dev directory descriptor */
static struct devicecmp_config config;	/* compiled default-deny + overlay */

struct device_worker {
	char	label[DEVICECMP_LABEL_MAX];
};

/*
 * Open the requested /dev leaf under the retained /dev directory descriptor and
 * return a Capsicum-narrowed, single-transfer descriptor for delivery.  Returns
 * the fd (>=0) with *granted set to the rights actually granted, or -1 with
 * errno (EACCES when policy does not grant the label this device/rights).
 */
static int
grant_open(const char *label, const struct devicecmp_open_body *body,
    const char *name, uint32_t *granted)
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
	effective = body->rights & maxr & DEVICECMP_RIGHT_ALL;
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
	 * A delivered CAP_IOCTL descriptor must not be able to issue every ioctl
	 * the node supports; apply the per-device command whitelist when policy
	 * carries one.
	 */
	if ((effective & DEVICECMP_RIGHT_IOCTL) && nioctls > 0 &&
	    cap_ioctls_limit(fd, ioctls, nioctls) == -1)
		goto fail;

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

/* Per-client channel request handler. */
static void
request(struct channel *c __unused, struct channel_message *m, void *arg)
{
	const struct devicecmp_msg *in;
	const struct devicecmp_open_body *body;
	struct device_worker *worker = arg;
	struct devicecmp_msg out;
	struct {
		struct devicecmp_msg msg;
		struct devicecmp_open_body body;
	} open_out;
	struct {
		struct devicecmp_msg msg;
		struct devicecmp_hello_reply hello;
	} hello_out;
	struct {
		struct devicecmp_msg msg;
		struct devicecmp_list_reply list;
	} list_out;
	const void *reply_data;
	size_t reply_length;
	uint32_t granted;
	int fd, error, deliver_fd;

	fd = -1;
	error = EPROTO;
	granted = 0;
	reply_data = NULL;
	reply_length = 0;
	memset(&out, 0, sizeof(out));
	memset(&open_out, 0, sizeof(open_out));
	memset(&hello_out, 0, sizeof(hello_out));
	memset(&list_out, 0, sizeof(list_out));

	in = channel_message_data(m);
	if (channel_message_length(m) >= sizeof(*in) &&
	    channel_message_fd_count(m) == 0 &&
	    in->magic == DEVICECMP_MAGIC &&
	    in->version == DEVICECMP_ABI_VERSION) {
		out.opcode = in->opcode;
		if (in->opcode == DEVICECMP_OP_HELLO &&
		    channel_message_length(m) == sizeof(*in)) {
			error = 0;
		} else if (in->opcode == DEVICECMP_OP_OPEN &&
		    channel_message_length(m) >= sizeof(*in) + sizeof(*body)) {
			const char *name;
			size_t name_length, header;

			body = (const struct devicecmp_open_body *)(in + 1);
			name = (const char *)(body + 1);
			name_length = body->name_length;
			header = sizeof(*in) + sizeof(*body);
			/*
			 * The name (name_length bytes, trailing NUL included)
			 * must exactly fill the message and be NUL-terminated.
			 */
			if (name_length == 0 ||
			    name_length > DEVICECMP_MAX_NAME ||
			    channel_message_length(m) != header + name_length ||
			    name[name_length - 1] != '\0') {
				error = EINVAL;
			} else {
				fd = grant_open(worker->label, body, name,
				    &granted);
				error = fd >= 0 ? 0 : errno;
				LOCALDEVICE_PROBE_OPEN(worker->label, name,
				    granted, error);
			}
		} else if (in->opcode == DEVICECMP_OP_LIST &&
		    channel_message_length(m) ==
		    sizeof(*in) + sizeof(struct devicecmp_list_request)) {
			const struct devicecmp_list_request *lreq;

			lreq = (const struct devicecmp_list_request *)(in + 1);
			/*
			 * Additive fields must be zero (message hygiene).  The
			 * enumeration is strictly label-scoped: it filters on
			 * worker->label — the connecting channel's unforgeable
			 * identity — never a wire argument, so a caller can only
			 * ever see its own devices.  Default-deny holds: a label
			 * with no policy entry lists empty.
			 */
			if (lreq->flags != 0 || lreq->reserved[0] != 0 ||
			    lreq->reserved[1] != 0) {
				error = EINVAL;
			} else {
				devicecmp_policy_list(&config, worker->label,
				    lreq->cursor, list_out.list.entries,
				    DEVICECMP_LIST_MAX, &list_out.list.count,
				    &list_out.list.next_cursor);
				error = 0;
				LOCALDEVICE_PROBE_LIST(worker->label,
				    lreq->cursor, list_out.list.count, error);
			}
		}
	}

	out.magic = DEVICECMP_MAGIC;
	out.version = DEVICECMP_ABI_VERSION;
	out.status = error == 0 ? 0 : -error;

	switch (out.opcode) {
	case DEVICECMP_OP_HELLO:
		hello_out.msg = out;
		hello_out.hello.version = DEVICECMP_ABI_VERSION;
		reply_data = &hello_out;
		reply_length = sizeof(hello_out);
		break;
	case DEVICECMP_OP_OPEN:
		open_out.msg = out;
		open_out.body.rights = granted;
		reply_data = &open_out;
		reply_length = sizeof(open_out);
		break;
	case DEVICECMP_OP_LIST:
		/*
		 * Success carries the full fixed-size list body (client
		 * validates the exact length).  On error reply header-only, so
		 * a malformed or unauthorized request is never amplified into a
		 * full-size list buffer.
		 */
		if (error == 0) {
			list_out.msg = out;
			reply_data = &list_out;
			reply_length = sizeof(list_out);
		} else {
			reply_data = &out;
			reply_length = sizeof(out);
		}
		break;
	default:
		reply_data = &out;
		reply_length = sizeof(out);
		break;
	}

	deliver_fd = (error == 0 && out.opcode == DEVICECMP_OP_OPEN) ? 1 : 0;
	(void)channel_send_reply(m, &(struct channel_outgoing){
	    .size = sizeof(struct channel_outgoing),
	    .data = reply_data,
	    .length = reply_length,
	    .fds = deliver_fd != 0 ? &fd : NULL,
	    .nfds = deliver_fd });
	if (fd >= 0)
		(void)close(fd);
	channel_message_free(m);
}

/* Serve one client on its own worker channel until it disconnects. */
static int
serve_session(int fd, const char *label)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct device_worker state;
	struct channel *channel;
	int ready, result, wants_write;

	memset(&state, 0, sizeof(state));
	strlcpy(state.label, label, sizeof(state.label));
	channel = NULL;
	result = 1;
	if (channel_create(fd, &options, &channel) == -1)
		goto out;
	if (channel_set_request_handler(channel, request, &state) == -1)
		goto out;
	result = 0;
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1) {
			result = 1;
			break;
		}
		ready = channel_wait(channel, wants_write, -1);
		if (ready == -1) {
			result = 1;
			break;
		}
		if ((ready & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(channel) == -1) {
			result = 1;
			break;
		}
		if ((ready & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(channel) == -1)
			break;
	}
out:
	if (channel != NULL)
		channel_destroy(channel);
	return (result);
}

#ifdef LOCALDEVICE_TESTING
/*
 * Test entrypoint: run the real per-label serve path against a caller-owned
 * channel descriptor with a caller-supplied client label.  It opens the /dev
 * directory descriptor exactly as production's serviced-delivered one but omits
 * the serviced-only sandbox wrappers (worker protect/authority-drop/cap_enter)
 * so the ATF process keeps running.  Policy is installed out-of-band via
 * localdevice_test_set_config(); default-deny plus per-device Capsicum rights
 * narrowing are the true isolation properties this exercises end-to-end.
 */
void
localdevice_test_set_config(const struct devicecmp_config *cfg)
{

	config = *cfg;
}

int
localdevice_test_serve(int fd, const char *label)
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
#endif /* LOCALDEVICE_TESTING */

#ifndef LOCALDEVICE_TESTING
static int
worker(int fd, const char *label)
{

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
start_session(int fd, const char *peer_label)
{
	int pd;
	pid_t pid;
	char label[DEVICECMP_LABEL_MAX];

	if (strnlen(peer_label, sizeof(label)) == 0 ||
	    strnlen(peer_label, sizeof(label)) == sizeof(label))
		return (errno = EINVAL, -1);
	strlcpy(label, peer_label, sizeof(label));
	pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
	if (pid == -1)
		return (-1);
	if (pid == 0)
		_exit(worker(fd, label));
	(void)close(pd);
	return (0);
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
	struct service_identity id;
	struct service_listener *listener;
	struct service_provider *provider;
	int fd;

	service_set_proctitle();
	openlog("localdevice", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	load_policy();

	/*
	 * Born in capability mode: serviced delivered /dev as a directory
	 * descriptor (manifest directories = ["/dev"]); open device leaves
	 * beneath it with openat(2) rather than by global path.
	 */
	if (service_resource_dir("/dev", &devdir) == -1)
		return (1);

	/*
	 * Self-harden the accept/fork parent.  It must still pdfork workers and
	 * receive connection descriptors, so NOFORK/NOFDRECV are not applied;
	 * NOPRIVS is safe because /dev is already open (mirrors localcrypto).
	 */
	if (devdir < 0 || service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_provider_expose(provider, DEVICECMP_NAME, &listener) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		return (1);

	for (;;) {
		memset(&id, 0, sizeof(id));
		id.size = sizeof(id);
		if (service_listener_accept(listener, &id, &fd) == -1)
			return (1);
		if (start_session(fd, id.client_label) == -1)
			syslog(LOG_WARNING, "session for %s rejected: %m",
			    id.client_label);
		(void)close(fd);
	}
}
#endif /* !LOCALDEVICE_TESTING */
