/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsdsysctl: the system.Sysctl capability provider.  A client holds a
 * system.Sysctl channel and asks the broker to read (and, policy permitting,
 * write) kernel sysctl variables by name, instead of calling sysctl(3) itself
 * or forking a Casper cap_sysctl helper.  __sysctlbyname(2) is capability-mode
 * enabled, so each client is served INLINE in the single token-holding process
 * (the gate token is close-on-fork, so a pdfork worker could not inherit it),
 * performing the sysctl directly after a per-label policy check; no Casper is
 * involved.
 */

#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <channel.h>
#include <libservice.h>
#include <sysctlcmp.h>
#include <sysctlcmp_server.h>

#include "config.h"
#include "bsdsysctl_probes.h"

#ifndef SYSCTLCMP_TESTING
/* Loaded once in main() before the provider sandboxes. */
static struct sysctlcmp_config g_config;
#endif

/*
 * Per-session idle deadline.  Because clients are served inline and
 * sequentially in the single token-holding process, a client that connects and
 * never sends a complete request must not pin serve_session forever and wedge
 * the accept loop for everyone else.  Drop a session idle this long; the client
 * reconnects for its next call.
 */
#define	BSDSYSCTL_SESSION_IDLE_SEC	30

/*
 * The held "system" gate token covering SYS_GATE_SYSCTL, dup'd in main() before
 * entering capability mode.  Capability mode confines the raw __sysctl(2) to
 * CTLFLAG_CAPRD/CAPWR nodes, so a GET/SET of an arbitrary node goes THROUGH this
 * token (service_system_sysctl -> kernel_sysctl with SCTL_GATED).  -1 when no
 * token is held (a unit test, or fail-soft), in which case gate_sysctl() falls
 * back to a direct __sysctlbyname(2) subject to whatever confinement applies.
 */
static int g_sysctl_token = -1;

/*
 * Read and/or write a sysctl by name.  When the gate token is held, resolve the
 * name to a MIB (sysctlnametomib(3) uses the CAPRW name2oid magic sysctl, which
 * works in capability mode) and perform the op THROUGH the token; otherwise do
 * a direct __sysctlbyname(2).  Shape mirrors sysctlbyname(3).
 */
static int
gate_sysctl(const char *name, void *oldp, size_t *oldlenp, const void *newp,
    size_t newlen)
{
	int mib[CTL_MAXNAME];
	size_t miblen;

	if (g_sysctl_token >= 0) {
		miblen = nitems(mib);
		if (sysctlnametomib(name, mib, &miblen) == -1)
			return (-1);
		return (service_system_sysctl(g_sysctl_token, mib,
		    (unsigned int)miblen, oldp, oldlenp, newp, newlen));
	}
	return (sysctlbyname(name, oldp, oldlenp, newp, newlen));
}

struct session {
	const char			*label;
	const struct sysctlcmp_config	*config;
	int				 error;
};

/* Header-only reply (HELLO, or an error status = -errno). */
static int
send_status(struct channel_message *request_message,
    const struct sysctlcmp_msg *request, int status)
{
	uint8_t buffer[sizeof(struct sysctlcmp_msg)];
	struct sysctlcmp_msg *reply;

	reply = (void *)buffer;
	if (sysctlcmp_message_init_reply(reply, request, status) == -1)
		return (-1);
	if (sysctlcmp_validate_message(reply, sizeof(*reply),
	    SYSCTLCMP_MESSAGE_REPLY) == -1)
		return (-1);
	return (channel_send_reply(request_message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(buffer, sizeof(*reply))));
}

/* Success reply carrying value_length bytes (0 for a SET). */
static int
send_value(struct channel_message *request_message,
    const struct sysctlcmp_msg *request, const void *value, size_t value_len)
{
	uint8_t buffer[SYSCTLCMP_MAX_MESSAGE];
	struct sysctlcmp_msg *reply;
	struct sysctlcmp_body *body;
	size_t length;

	if (value_len > SYSCTLCMP_MAX_VALUE)
		return (errno = EOVERFLOW, -1);
	memset(buffer, 0, sizeof(struct sysctlcmp_msg) +
	    sizeof(struct sysctlcmp_body));
	reply = (void *)buffer;
	if (sysctlcmp_message_init_reply(reply, request, 0) == -1)
		return (-1);
	body = (void *)(reply + 1);
	body->name_length = 0;
	body->reserved = 0;
	body->value_length = (uint32_t)value_len;
	if (value_len != 0)
		memcpy(body + 1, value, value_len);
	length = sizeof(*reply) + sizeof(*body) + value_len;
	if (sysctlcmp_validate_message(reply, length,
	    SYSCTLCMP_MESSAGE_REPLY) == -1)
		return (-1);
	return (channel_send_reply(request_message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(buffer, length)));
}

/*
 * Introspection via the CTL_SYSCTL magic MIBs (all through __sysctl(2), which is
 * capability-mode enabled).  oid[0]=0 selects CTL_SYSCTL; oid[1] the sub-op.
 */
static int
do_oidfmt(const char *name, void *buf, size_t *buflen)
{
	int oid[CTL_MAXNAME + 2];
	size_t n;

	n = CTL_MAXNAME;
	if (sysctlnametomib(name, oid + 2, &n) == -1)
		return (-1);
	oid[0] = 0;
	oid[1] = 4;			/* CTL_SYSCTL_OIDFMT */
	/* Reply value is exactly {uint32_t kind; char fmt[]} -- our wire layout. */
	return (sysctl(oid, (u_int)(n + 2), buf, buflen, NULL, 0));
}

/*
 * Convert a client-supplied value STRING to the binary form the target OID
 * expects, based on its CTLTYPE (as sysctl(8) does).  The sysctlcmp wire sends
 * a SET value as text; a typed node (int/long/64-bit, signed or unsigned) needs
 * that text parsed into its native binary width before the write, or the ASCII
 * bytes would be stored verbatim as the value.  For CTLTYPE_STRING the bytes
 * pass through unchanged; a node/opaque node cannot be set from text (EINVAL).
 * The binary value is written into `out` (capacity `outcap`) and its length to
 * *outlen.  Returns 0, or -1 with errno (EINVAL malformed/unsettable, ENOMEM
 * buffer too small).
 */
static int
set_encode_value(const char *name, const char *sval, size_t slen, void *out,
    size_t outcap, size_t *outlen)
{
	uint8_t fmtbuf[128];
	char numbuf[64];
	size_t fmtlen, n, sz;
	uint32_t kind;
	char *end;
	bool is_signed;

	fmtlen = sizeof(fmtbuf);
	if (do_oidfmt(name, fmtbuf, &fmtlen) == -1)
		return (-1);
	if (fmtlen < sizeof(uint32_t)) {
		errno = EINVAL;
		return (-1);
	}
	memcpy(&kind, fmtbuf, sizeof(kind));

	if ((kind & CTLTYPE) == CTLTYPE_STRING) {
		if (slen > outcap) {
			errno = ENOMEM;
			return (-1);
		}
		memcpy(out, sval, slen);
		*outlen = slen;
		return (0);
	}

	/* Numeric node: parse the NUL-terminated text (decimal/hex/octal). */
	if (slen == 0) {
		errno = EINVAL;
		return (-1);
	}
	n = (slen < sizeof(numbuf)) ? slen : sizeof(numbuf) - 1;
	memcpy(numbuf, sval, n);
	numbuf[n] = '\0';

	switch (kind & CTLTYPE) {
	case CTLTYPE_INT:	sz = sizeof(int);	is_signed = true;  break;
	case CTLTYPE_UINT:	sz = sizeof(u_int);	is_signed = false; break;
	case CTLTYPE_LONG:	sz = sizeof(long);	is_signed = true;  break;
	case CTLTYPE_ULONG:	sz = sizeof(u_long);	is_signed = false; break;
	case CTLTYPE_S8:	sz = 1;			is_signed = true;  break;
	case CTLTYPE_U8:	sz = 1;			is_signed = false; break;
	case CTLTYPE_S16:	sz = 2;			is_signed = true;  break;
	case CTLTYPE_U16:	sz = 2;			is_signed = false; break;
	case CTLTYPE_S32:	sz = 4;			is_signed = true;  break;
	case CTLTYPE_U32:	sz = 4;			is_signed = false; break;
	case CTLTYPE_S64:	sz = 8;			is_signed = true;  break;
	case CTLTYPE_U64:	sz = 8;			is_signed = false; break;
	default:		/* NODE / OPAQUE: not settable from text */
		errno = EINVAL;
		return (-1);
	}
	if (outcap < sz) {
		errno = ENOMEM;
		return (-1);
	}
	errno = 0;
	if (is_signed) {
		long long v = strtoll(numbuf, &end, 0);

		if (end == numbuf || *end != '\0' || errno != 0) {
			errno = EINVAL;
			return (-1);
		}
		switch (sz) {
		case 1: { int8_t t = (int8_t)v; memcpy(out, &t, 1); break; }
		case 2: { int16_t t = (int16_t)v; memcpy(out, &t, 2); break; }
		case 4: { int32_t t = (int32_t)v; memcpy(out, &t, 4); break; }
		default: { int64_t t = (int64_t)v; memcpy(out, &t, 8); break; }
		}
	} else {
		unsigned long long v = strtoull(numbuf, &end, 0);

		if (end == numbuf || *end != '\0' || errno != 0) {
			errno = EINVAL;
			return (-1);
		}
		switch (sz) {
		case 1: { uint8_t t = (uint8_t)v; memcpy(out, &t, 1); break; }
		case 2: { uint16_t t = (uint16_t)v; memcpy(out, &t, 2); break; }
		case 4: { uint32_t t = (uint32_t)v; memcpy(out, &t, 4); break; }
		default: { uint64_t t = (uint64_t)v; memcpy(out, &t, 8); break; }
		}
	}
	*outlen = sz;
	return (0);
}

static int
do_descr(const char *name, void *buf, size_t *buflen)
{
	int oid[CTL_MAXNAME + 2];
	size_t n;

	n = CTL_MAXNAME;
	if (sysctlnametomib(name, oid + 2, &n) == -1)
		return (-1);
	oid[0] = 0;
	oid[1] = 5;			/* CTL_SYSCTL_OIDDESCR */
	return (sysctl(oid, (u_int)(n + 2), buf, buflen, NULL, 0));
}

/*
 * Enumeration that never reveals a name outside the caller's read policy:
 * walk CTL_SYSCTL_NEXT from name (or the root for ""), resolving each next oid
 * to a name and skipping any the label may not read, until a permitted name is
 * found or the tree ends (ENOENT).
 */
static int
do_next(const struct session *session, const char *name, char *out,
    size_t *outlen)
{
	int walk[CTL_MAXNAME + 2], noid[CTL_MAXNAME], qname[CTL_MAXNAME + 2];
	char nm[SYSCTLCMP_MAX_NAME];
	size_t start, nlen, nmlen, nn;

	walk[0] = 0;
	walk[1] = 2;			/* CTL_SYSCTL_NEXT */
	if (name != NULL && name[0] != '\0') {
		start = CTL_MAXNAME;
		if (sysctlnametomib(name, walk + 2, &start) == -1)
			return (-1);
		start += 2;
	} else {
		start = 2;		/* start from the root */
	}
	for (;;) {
		nlen = sizeof(noid);
		if (sysctl(walk, (u_int)start, noid, &nlen, NULL, 0) == -1)
			return (-1);	/* ENOENT past the last variable */
		nn = nlen / sizeof(int);
		qname[0] = 0;
		qname[1] = 1;		/* CTL_SYSCTL_NAME */
		memcpy(qname + 2, noid, nlen);
		nmlen = sizeof(nm);
		if (sysctl(qname, (u_int)(nn + 2), nm, &nmlen, NULL, 0) == -1)
			return (-1);
		if (sysctlcmp_config_permits(session->config, session->label,
		    nm, false)) {
			if (nmlen > *outlen)
				return (errno = ENOMEM, -1);
			memcpy(out, nm, nmlen);
			*outlen = nmlen;
			return (0);
		}
		/* Not permitted: advance past it and keep walking. */
		walk[0] = 0;
		walk[1] = 2;
		memcpy(walk + 2, noid, nlen);
		start = nn + 2;
	}
}

static void
handle_request(struct channel *channel __unused,
    struct channel_message *message, void *argument)
{
	const struct sysctlcmp_msg *request;
	const struct sysctlcmp_body *body;
	struct session *session;
	const char *name;
	const void *newp;
	uint8_t value[SYSCTLCMP_MAX_VALUE];
	size_t message_len, value_len, newlen;
	uint32_t bytes;
	uint16_t opcode;
	int result, status, transport_error;

	session = argument;
	request = channel_message_data(message);
	message_len = channel_message_length(message);
	opcode = UINT16_MAX;
	bytes = 0;
	result = 0;
	status = 0;
	transport_error = 0;
	if (request != NULL && message_len >= sizeof(*request))
		opcode = request->opcode;
	BSDSYSCTL_PROBE_REQUEST_START(session->label, opcode);

	if (channel_message_fd_count(message) != 0 ||
	    sysctlcmp_validate_message(request, message_len,
	    SYSCTLCMP_MESSAGE_REQUEST) == -1) {
		status = EPROTO;
		session->error = status;
		goto out;
	}
	switch (request->opcode) {
	case SYSCTLCMP_OP_HELLO:
		result = send_status(message, request, 0);
		break;
	case SYSCTLCMP_OP_GET:
		body = (const void *)(request + 1);
		name = (const char *)(body + 1);
		if (!sysctlcmp_config_permits(session->config, session->label,
		    name, false)) {
			status = EPERM;
			result = send_status(message, request, -status);
			break;
		}
		value_len = sizeof(value);
		if (gate_sysctl(name, value, &value_len, NULL, 0) == -1) {
			status = errno;
			result = send_status(message, request, -status);
		} else {
			bytes = (uint32_t)value_len;
			result = send_value(message, request, value, value_len);
		}
		break;
	case SYSCTLCMP_OP_SET: {
		uint8_t enc[512];
		size_t enclen;

		body = (const void *)(request + 1);
		name = (const char *)(body + 1);
		newlen = body->value_length;
		newp = (const uint8_t *)(body + 1) + body->name_length;
		bytes = (uint32_t)newlen;
		if (!sysctlcmp_config_permits(session->config, session->label,
		    name, true)) {
			status = EPERM;
			result = send_status(message, request, -status);
			break;
		}
		/*
		 * The wire value is text; encode it to the OID's native binary
		 * type before the (gated) write, or the ASCII bytes would be
		 * stored as the value.
		 */
		if (set_encode_value(name, (const char *)newp, newlen, enc,
		    sizeof(enc), &enclen) == -1) {
			status = errno;
			result = send_status(message, request, -status);
			break;
		}
		if (gate_sysctl(name, NULL, NULL, enc, enclen) == -1) {
			status = errno;
			result = send_status(message, request, -status);
		} else {
			result = send_value(message, request, NULL, 0);
		}
		break;
	}
	case SYSCTLCMP_OP_OIDFMT:
		body = (const void *)(request + 1);
		name = (const char *)(body + 1);
		if (!sysctlcmp_config_permits(session->config, session->label,
		    name, false)) {
			status = EPERM;
			result = send_status(message, request, -status);
			break;
		}
		value_len = sizeof(value);
		if (do_oidfmt(name, value, &value_len) == -1) {
			status = errno;
			result = send_status(message, request, -status);
		} else {
			bytes = (uint32_t)value_len;
			result = send_value(message, request, value, value_len);
		}
		break;
	case SYSCTLCMP_OP_DESCR:
		body = (const void *)(request + 1);
		name = (const char *)(body + 1);
		if (!sysctlcmp_config_permits(session->config, session->label,
		    name, false)) {
			status = EPERM;
			result = send_status(message, request, -status);
			break;
		}
		value_len = sizeof(value);
		if (do_descr(name, value, &value_len) == -1) {
			status = errno;
			result = send_status(message, request, -status);
		} else {
			bytes = (uint32_t)value_len;
			result = send_value(message, request, value, value_len);
		}
		break;
	case SYSCTLCMP_OP_NEXT:
		/* The cursor name is not gated; do_next() filters the results. */
		body = (const void *)(request + 1);
		name = (const char *)(body + 1);
		value_len = sizeof(value);
		if (do_next(session, name, (char *)value, &value_len) == -1) {
			status = errno;
			result = send_status(message, request, -status);
		} else {
			bytes = (uint32_t)value_len;
			result = send_value(message, request, value, value_len);
		}
		break;
	default:
		status = EOPNOTSUPP;
		result = send_status(message, request, -status);
		break;
	}
	if (result == -1) {
		transport_error = errno;
		session->error = transport_error;
	}
out:
	BSDSYSCTL_PROBE_REQUEST_DONE(session->label, opcode, bytes, status,
	    transport_error);
	channel_message_free(message);
}

static int
serve_session(int fd, const char *label, const struct sysctlcmp_config *config)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct channel *channel;
	struct session session;
	struct timespec now, last;
	int ready, wants_write;

	if (fd < 0 || label == NULL || label[0] == '\0' || config == NULL)
		return (errno = EINVAL, -1);
	memset(&session, 0, sizeof(session));
	session.label = label;
	session.config = config;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		(void)close(fd);
		return (1);
	}
	/*
	 * channel_create() consumes (closes) fd on success, leaves it on failure.
	 * Close it here on failure and never after return -- the caller must not
	 * close it again (a double-close that, once any fd is allocated between the
	 * two closes, would tear down an unrelated live descriptor).
	 */
	if (channel_create(fd, &options, &channel) == -1) {
		(void)close(fd);
		return (1);
	}
	if (channel_set_request_handler(channel, handle_request,
	    &session) == -1) {
		channel_destroy(channel);
		return (1);
	}
	/*
	 * BSDSysctl holds a close-on-fork-locked gate token, so it serves each
	 * client INLINE and sequentially in the single token-holding process
	 * (no pdfork).  A client that connects and never sends a complete request
	 * would otherwise pin this on an infinite channel_wait and wedge the accept
	 * loop, denying service to every other client.  Bound the session by idle
	 * time; the client reconnects for its next call.
	 */
	last = now;
	for (;;) {
		long elapsed_ms, remaining_ms;

		wants_write = channel_wants_write(channel);
		if (wants_write == -1)
			break;
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
			break;
		elapsed_ms = (now.tv_sec - last.tv_sec) * 1000 +
		    (now.tv_nsec - last.tv_nsec) / 1000000;
		remaining_ms = (long)BSDSYSCTL_SESSION_IDLE_SEC * 1000 -
		    elapsed_ms;
		if (remaining_ms <= 0)
			break;			/* idle too long: drop the session */
		ready = channel_wait(channel, wants_write,
		    remaining_ms > INT_MAX ? INT_MAX : (int)remaining_ms);
		if (ready < 0)
			break;
		if (ready == 0)
			break;			/* idle deadline elapsed */
		last = now;			/* activity: re-arm the deadline */
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
	return (session.error == 0 ? 0 : 1);
}

#ifdef SYSCTLCMP_TESTING
#include "bsdsysctl_test.h"

int
sysctlcmp_test_serve(int fd, const char *label,
    const struct sysctlcmp_config *config)
{

	return (serve_session(fd, label, config));
}
#else

int
main(void)
{
	struct service_identity identity;
	struct service_listener *listener;
	struct service_provider *provider;
	int error, fd, cfgfd;

	openlog("bsdsysctl", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	/*
	 * Per-label policy, via the switchboard-delivered Config directory
	 * descriptor.  Fail-soft: a missing/malformed config keeps the built-in
	 * default ACL (a small safe read set, no writes).
	 */
	sysctlcmp_config_defaults(&g_config);
	if (service_config_open(SYSCTLCMP_CONFIG_NAME, &cfgfd) == -1) {
		if (errno != ENOENT)
			syslog(LOG_WARNING, "policy config unavailable; using "
			    "built-in default sysctl policy: %m");
	} else if (sysctlcmp_config_load_fd(&g_config, cfgfd) == -1) {
		syslog(LOG_WARNING, "policy config rejected; using built-in "
		    "default sysctl policy: %m");
	}
	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL) == -1 ||
	    service_provider_expose(provider, SYSCTLCMP_INTERFACE,
	    &listener) == -1)
		goto fail;
	/*
	 * bsdsysctl is BORN IN CAPABILITY MODE.  __sysctl(2) in capmode is
	 * confined to CTLFLAG_CAPRD/CAPWR nodes, so GET/SET of an arbitrary node
	 * go THROUGH a held SYS_GATE_SYSCTL token (gate_sysctl -> kernel_sysctl
	 * with SCTL_GATED); introspection (name2oid/oidfmt/descr/next) uses the
	 * CAPRD magic sysctls directly.  The token is delivered close-on-fork, so
	 * only the holder can use it: serve each client INLINE (no per-client
	 * pdfork worker, which could not inherit the token).  Dup the token
	 * before entering capmode; fail-soft if none was delivered.
	 */
	if (service_system_token_dup(&g_sysctl_token) == -1) {
		syslog(LOG_WARNING, "no sysctl capability; GET/SET of "
		    "capmode-confined nodes will fail: %m");
		g_sysctl_token = -1;
	}
	if (service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		goto fail;
	for (;;) {
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		if (service_listener_accept(listener, &identity, &fd) == -1) {
			error = errno;
			if (service_provider_quiescing(provider) == 1) {
				int status;

				status = service_provider_quiesce_complete(
				    provider, 0);
				closelog();
				return (status == 0 ? 0 : 1);
			}
			errno = error;
			if (errno == EINTR)
				continue;
			goto fail;
		}
		/*
		 * Serve inline: the CLOFORK token cannot cross a fork, so the
		 * holder itself handles the session.  A per-label policy check
		 * in handle_request remains the access boundary.
		 */
		/* serve_session owns fd (channel_create consumes it, or closes it on
		 * failure) -- do not close it again here. */
		(void)serve_session(fd, identity.client_label, &g_config);
	}
fail:
	syslog(LOG_ERR, "initialization or service loop: %m");
	return (1);
}
#endif /* !SYSCTLCMP_TESTING */
