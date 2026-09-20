/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * BSDPower -- the system.Power capability provider.  A client holds a
 * system.Power channel and asks the broker for the supported ACPI sleep states
 * (STATES, unprivileged) or, when the per-label policy permits, to put the
 * machine to sleep (SUSPEND -- ioctl(2) on /dev/acpi, which needs privilege the
 * sandboxed caller lacks).  Ambient-authority provider (like BSDSysctl/BSDTime):
 * runs outside capability mode; the per-label policy (power.conf) is the
 * security boundary.  reboot/halt stay with capsule(8); BSDPower owns sleep.
 * Default-deny: no label may suspend unless power.conf grants it.
 */
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/procdesc.h>
#include <sys/sysctl.h>

#include <dev/acpica/acpiio.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <channel.h>
#include <libservice.h>

#include "powercmp_protocol.h"
#include "config.h"
#include "BSDPower_probes.h"

static struct powercmp_config g_config;
static int g_acpi_fd = -1;		/* /dev/acpi, narrowed to CAP_IOCTL/REQSLPSTATE */
static uint32_t g_states;		/* supported sleep-state mask, cached at startup */

struct session {
	const char			*label;
	const struct powercmp_config	*config;
	int				 error;
};

/*
 * Read hw.acpi.supported_sleep_state ("S3 S4 S5") into a bitmask: bit N set
 * when SN is supported.  Unprivileged; empty/absent yields 0.
 */
static uint32_t
supported_states(void)
{
	char buf[64];
	size_t len = sizeof(buf) - 1;
	uint32_t mask = 0;
	const char *p;

	if (sysctlbyname("hw.acpi.supported_sleep_state", buf, &len, NULL, 0)
	    == -1)
		return (0);
	buf[len] = '\0';
	for (p = buf; *p != '\0'; p++)
		if ((*p == 'S' || *p == 's') && p[1] >= '1' && p[1] <= '5')
			mask |= (uint32_t)1 << (p[1] - '0');
	return (mask);
}

static void
init_reply(struct powercmp_msg *reply, const struct powercmp_msg *request,
    int status)
{

	memset(reply, 0, sizeof(*reply));
	reply->magic = POWERCMP_MAGIC;
	reply->version = POWERCMP_ABI_VERSION;
	reply->opcode = request->opcode;
	reply->status = status;
}

static int
send_status(struct channel_message *request_message,
    const struct powercmp_msg *request, int status)
{
	struct powercmp_msg reply;

	init_reply(&reply, request, status);
	if (powercmp_validate_message(&reply, sizeof(reply),
	    POWERCMP_MESSAGE_REPLY) == -1)
		return (-1);
	return (channel_send_reply(request_message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(&reply, sizeof(reply))));
}

static int
send_body(struct channel_message *request_message,
    const struct powercmp_msg *request, const struct powercmp_body *value)
{
	uint8_t buffer[POWERCMP_MAX_MESSAGE];
	struct powercmp_msg *reply;
	struct powercmp_body *body;
	size_t length;

	memset(buffer, 0, sizeof(buffer));
	reply = (void *)buffer;
	init_reply(reply, request, 0);
	body = (void *)(reply + 1);
	*body = *value;
	length = sizeof(*reply) + sizeof(*body);
	if (powercmp_validate_message(reply, length, POWERCMP_MESSAGE_REPLY) ==
	    -1)
		return (-1);
	return (channel_send_reply(request_message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(buffer, length)));
}

static void
handle_request(struct channel *channel __unused,
    struct channel_message *message, void *argument)
{
	const struct powercmp_msg *request;
	const struct powercmp_body *body;
	struct session *session;
	struct powercmp_body out;
	size_t message_len;
	uint16_t opcode;
	int result, status;

	session = argument;
	request = channel_message_data(message);
	message_len = channel_message_length(message);
	opcode = UINT16_MAX;
	result = 0;
	status = 0;
	if (request != NULL && message_len >= sizeof(*request))
		opcode = request->opcode;

	if (channel_message_fd_count(message) != 0 ||
	    powercmp_validate_message(request, message_len,
	    POWERCMP_MESSAGE_REQUEST) == -1) {
		status = EPROTO;
		session->error = status;
		(void)send_status(message, request, -status);
		goto out;
	}
	body = (const void *)(request + 1);

	switch (request->opcode) {
	case POWERCMP_OP_HELLO:
		result = send_status(message, request, 0);
		break;
	case POWERCMP_OP_STATES:
		memset(&out, 0, sizeof(out));
		out.supported = g_states;	/* cached pre-capmode at startup */
		result = send_body(message, request, &out);
		break;
	case POWERCMP_OP_SUSPEND: {
		int state;

		if (message_len != sizeof(*request) + sizeof(*body)) {
			status = EPROTO;
			result = send_status(message, request, -status);
			break;
		}
		if (!powercmp_config_permits_suspend(session->config,
		    session->label)) {
			status = EPERM;
			result = send_status(message, request, -status);
			break;
		}
		if (body->state < 1 || body->state > 5) {
			status = EINVAL;
			result = send_status(message, request, -status);
			break;
		}
		if (g_acpi_fd < 0) {
			status = ENODEV;
			result = send_status(message, request, -status);
			break;
		}
		state = (int)body->state;
		if (ioctl(g_acpi_fd, ACPIIO_REQSLPSTATE, &state) == -1) {
			status = errno;
			result = send_status(message, request, -status);
			break;
		}
		BSDPOWER_PROBE_SUSPEND(session->label, state);
		syslog(LOG_NOTICE, "suspend to S%d requested by %s", state,
		    session->label);
		result = send_status(message, request, 0);
		break;
	}
	default:
		status = EOPNOTSUPP;
		result = send_status(message, request, -status);
		break;
	}
	if (result == -1)
		session->error = errno;
out:
	BSDPOWER_PROBE_REQUEST(session->label, opcode, status);
	channel_message_free(message);
}

static int
serve_session(int fd, const char *label, const struct powercmp_config *config)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct channel *channel;
	struct session session;
	int ready, wants_write;

	if (fd < 0 || label == NULL || label[0] == '\0' || config == NULL)
		return (errno = EINVAL, -1);
	memset(&session, 0, sizeof(session));
	session.label = label;
	session.config = config;
	if (channel_create(fd, &options, &channel) == -1)
		return (1);
	if (channel_set_request_handler(channel, handle_request,
	    &session) == -1) {
		channel_destroy(channel);
		return (1);
	}
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1)
			break;
		ready = channel_wait(channel, wants_write, -1);
		if (ready <= 0)
			break;
		if ((ready & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(channel) == -1)
			break;
		if ((ready & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(channel) == -1)
			break;
		if (session.error != 0)
			break;
	}
	channel_destroy(channel);
	return (0);
}

/*
 * Per-client worker.  BSDPower is born in capability mode: g_acpi_fd (already
 * narrowed to CAP_IOCTL/ACPIIO_REQSLPSTATE), g_config, and g_states were
 * established before the pdfork, so each worker inherits them and reaches the
 * device only through the pre-limited descriptor.  The per-label policy in
 * handle_request remains the authorization boundary.
 */
static int
worker(int fd, const char *label)
{

	service_worker_drop_inherited_authority();
	return (serve_session(fd, label, &g_config));
}

int
main(void)
{
	struct service_identity identity;
	struct service_listener *listener;
	struct service_provider *provider;
	cap_rights_t rights;
	const unsigned long acpi_ioctls[] = { ACPIIO_REQSLPSTATE };
	int error, fd, cfgfd, devdir;

	openlog("BSDPower", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	powercmp_config_defaults(&g_config);
	if (service_config_open(POWERCMP_CONFIG_NAME, &cfgfd) == -1) {
		if (errno != ENOENT)
			syslog(LOG_WARNING, "policy config unavailable; using "
			    "built-in default (deny all suspend): %m");
	} else if (powercmp_config_load_fd(&g_config, cfgfd) == -1) {
		syslog(LOG_WARNING, "policy config rejected; using built-in "
		    "default (deny all suspend): %m");
	}
	/*
	 * Cache the supported sleep-state mask now (hw.acpi.supported_sleep_state
	 * is CTLFLAG_CAPRD, so this one read is valid even though the process is
	 * born in capability mode).  The set is static for the life of the boot.
	 */
	g_states = supported_states();
	/*
	 * Reach /dev/acpi through the delivered /dev directory capability (never a
	 * global path) and narrow it to CAP_IOCTL limited to ACPIIO_REQSLPSTATE
	 * before entering capability mode.  Fail-soft: STATES still works without
	 * it, SUSPEND returns ENODEV.
	 */
	if (service_resource_dir("/dev", &devdir) == -1) {
		syslog(LOG_WARNING, "/dev capability unavailable; SUSPEND "
		    "disabled: %m");
	} else {
		/* devdir is borrowed from libservice (do not close it). */
		g_acpi_fd = openat(devdir, "acpi", O_RDWR | O_CLOEXEC);
		if (g_acpi_fd == -1) {
			syslog(LOG_WARNING, "/dev/acpi unavailable; SUSPEND "
			    "disabled: %m");
		} else {
			cap_rights_init(&rights, CAP_IOCTL, CAP_FSTAT);
			if (cap_rights_limit(g_acpi_fd, &rights) == -1 ||
			    cap_ioctls_limit(g_acpi_fd, acpi_ioctls,
			    nitems(acpi_ioctls)) == -1) {
				syslog(LOG_WARNING, "cannot narrow /dev/acpi; "
				    "SUSPEND disabled: %m");
				(void)close(g_acpi_fd);
				g_acpi_fd = -1;
			}
		}
	}
	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL) == -1 ||
	    service_provider_expose(provider, POWERCMP_INTERFACE,
	    &listener) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		goto fail;
	for (;;) {
		pid_t pid;
		int pd;

		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		if (service_listener_accept(listener, &identity, &fd) == -1) {
			error = errno;
			if (service_provider_quiescing(provider) == 1) {
				int st;

				st = service_provider_quiesce_complete(provider,
				    0);
				closelog();
				return (st == 0 ? 0 : 1);
			}
			errno = error;
			if (errno == EINTR)
				continue;
			goto fail;
		}
		pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
		if (pid == -1) {
			syslog(LOG_WARNING, "pdfork for %s: %m",
			    identity.client_label);
			(void)close(fd);
			continue;
		}
		if (pid == 0) {
			if (service_worker_protect(SERVICE_PROTECT_EXTERNAL) ==
			    -1) {
				syslog(LOG_ERR, "worker protection: %m");
				_exit(1);
			}
			_exit(worker(fd, identity.client_label));
		}
		(void)close(fd);
		(void)close(pd);
	}
fail:
	syslog(LOG_ERR, "initialization or service loop: %m");
	return (1);
}
