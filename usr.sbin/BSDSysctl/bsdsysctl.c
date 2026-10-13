/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsdsysctl: the system.Sysctl capability provider.  A client holds a
 * system.Sysctl channel and asks the broker to read (and, policy permitting,
 * write) kernel sysctl variables by name, instead of calling sysctl(3) itself
 * or forking a Casper cap_sysctl helper.  __sysctlbyname(2) is capability-mode
 * enabled, so client channels are multiplexed in the single token-holding process
 * (the gate token is close-on-fork, so a pdfork worker could not inherit it),
 * performing the sysctl directly after a per-label policy check; no Casper is
 * involved.  Sessions speak FIDL bsd.sysctl.v1 (lib/libsysctlcmp/sysctlcmp.fidl).
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/route.h>

#include <errno.h>
#include <fcntl.h>
#include <libservice.h>
#include <limits.h>
#include <service_runtime.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fidl/bsd.sysctl.v1/c/bsd.h>
#include <sysctlcmp.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "bsdsysctl_probes.h"
#include "trace_pressure.h"
#include "config.h"
#include "interfaces.h"

#ifndef SYSCTLCMP_TESTING
/* Loaded once in main() before the provider sandboxes. */
static struct sysctlcmp_config g_config;
#endif

/* Bound idle sessions and total channel/memory use in the token holder. */
#define BSDSYSCTL_SESSION_IDLE_MS 30000U
#define BSDSYSCTL_MAX_SESSIONS 128
#define BSDSYSCTL_MAX_LABEL_SESSIONS 16

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

static int
read_interfaces(void *context __unused, void *data, size_t *length)
{
	int mib[] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLISTL, 0 };

	if (g_sysctl_token >= 0)
		return (service_system_sysctl(g_sysctl_token, mib, nitems(mib),
		    data, length, NULL, 0));
	return (sysctl(mib, nitems(mib), data, length, NULL, 0));
}

struct session {
	char				*label;
	struct fidl_bsd_connection	*connection;
	uint64_t			 last_request_ms;
	bool				 activity;
	bool				 negotiated;
	const struct sysctlcmp_config	*config;
	int				 error;
};

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

/*
 * bsd.sysctl.v1 method handlers.  Every method but GetProtocolInfo requires a
 * negotiated session.  A reply that cannot be sent closes the connection, and
 * the reactor then reclaims the session.  The request probes keep the
 * historical SYSCTLCMP_OP_* codes (0 is protocol negotiation).
 */
static bool
session_ready(struct session *session, struct fidl_bsd_connection *connection,
    uint16_t opcode)
{

	BSDSYSCTL_PROBE_REQUEST_START(session->label, opcode);
	if (session->negotiated) {
		session->activity = true;
		return (true);
	}
	session->error = EPROTO;
	BSDSYSCTL_PROBE_REQUEST_DONE(session->label, opcode, 0, EPROTO, 0);
	fidl_bsd_connection_close(connection, EPROTO);
	return (false);
}

static void
request_done(struct session *session, struct fidl_bsd_connection *connection,
    uint16_t opcode, uint32_t bytes, int status, int transport_error)
{

	if (transport_error != 0) {
		session->error = transport_error;
		fidl_bsd_connection_close(connection, transport_error);
	}
	BSDSYSCTL_PROBE_REQUEST_DONE(session->label, opcode, bytes, status,
	    transport_error);
}

/*
 * A received name as a C string: a sysctl name never contains a NUL.  Returns
 * 0, or EINVAL for an embedded NUL (or, except for Next, an empty name).
 */
static int
request_name(const char *data, size_t size, bool allow_empty, char *out)
{

	if (size >= SYSCTLCMP_MAX_NAME ||
	    memchr(data, '\0', size) != NULL || (size == 0 && !allow_empty))
		return (EINVAL);
	memcpy(out, data, size);
	out[size] = '\0';
	return (0);
}

static void
protocol_info(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct session *session = argument;
	struct bsd_sysctl_v1_ProtocolInfo info = { SYSCTLCMP_WIRE_VERSION };
	int error;

	BSDSYSCTL_PROBE_REQUEST_START(session->label, 0);
	session->activity = true;
	error = bsd_sysctl_v1_Sysctl_GetProtocolInfo_reply(connection, request,
	    &info);
	session->negotiated = error == 0;
	request_done(session, connection, 0, 0, 0, error);
}

/* Value-returning reads: Get, OidFormat, Describe and Next. */
#define VALUE_REPLY(method, opcode_value, allow_empty, gated, produce)       static void                                                                  method##_handler(void *argument, struct fidl_bsd_connection *connection,        struct fidl_bsd_request *request, struct bsd_sysctl_v1_NameRequest *in) {                                                                            	struct session *session = argument;                                  	struct bsd_sysctl_v1_Sysctl_##method##_Result reply = { 0 };         	uint8_t value[SYSCTLCMP_MAX_VALUE];                                  	char name[SYSCTLCMP_MAX_NAME];                                       	size_t value_len = sizeof(value);                                    	uint32_t bytes = 0;                                                  	int status;                                                                                                                                       	if (!session_ready(session, connection, opcode_value))               		return;                                                      	status = request_name(in->name, in->name_size, allow_empty, name);   	if (status == 0 && gated &&                                          	    !sysctlcmp_config_permits(session->config, session->label, name, 	    false))                                                          		status = EPERM;                                              	if (status == 0 && produce == -1)                                    		status = errno;                                              	if (status != 0) {                                                   		reply.tag = bsd_sysctl_v1_Sysctl_##method##_Result_err_tag;  		reply.value.err = (uint32_t)status;                          	} else {                                                             		bytes = (uint32_t)value_len;                                 		reply.tag =                                                  		    bsd_sysctl_v1_Sysctl_##method##_Result_response_tag;    		reply.value.response.value = value;                          		reply.value.response.value_size = value_len;                 	}                                                                    	request_done(session, connection, opcode_value, bytes, status,       	    bsd_sysctl_v1_Sysctl_##method##_reply(connection, request,       	    &reply));                                                        }
VALUE_REPLY(Get, SYSCTLCMP_OP_GET, false, true,
    gate_sysctl(name, value, &value_len, NULL, 0))
VALUE_REPLY(OidFormat, SYSCTLCMP_OP_OIDFMT, false, true,
    do_oidfmt(name, value, &value_len))
VALUE_REPLY(Describe, SYSCTLCMP_OP_DESCR, false, true,
    do_descr(name, value, &value_len))
/* The Next cursor is not gated; do_next() filters the results. */
VALUE_REPLY(Next, SYSCTLCMP_OP_NEXT, true, false,
    do_next(session, name, (char *)value, &value_len))

static void
set_handler(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_sysctl_v1_SetRequest *in)
{
	struct session *session = argument;
	struct bsd_sysctl_v1_Sysctl_Set_Result reply = { 0 };
	/*
	 * Size the encode buffer to the protocol's value cap so any write the
	 * wire accepts can actually be encoded.
	 */
	uint8_t enc[SYSCTLCMP_MAX_VALUE];
	char name[SYSCTLCMP_MAX_NAME];
	size_t enclen;
	int status;

	if (!session_ready(session, connection, SYSCTLCMP_OP_SET))
		return;
	status = request_name(in->name, in->name_size, false, name);
	if (status == 0 && !sysctlcmp_config_permits(session->config,
	    session->label, name, true))
		status = EPERM;
	/*
	 * The wire value is text; encode it to the OID's native binary type
	 * before the (gated) write, or the ASCII bytes would be stored as the
	 * value.
	 */
	if (status == 0 && set_encode_value(name, (const char *)in->value,
	    in->value_size, enc, sizeof(enc), &enclen) == -1)
		status = errno;
	if (status == 0 && gate_sysctl(name, NULL, NULL, enc, enclen) == -1)
		status = errno;
	reply.tag = status != 0 ? bsd_sysctl_v1_Sysctl_Set_Result_err_tag :
	    bsd_sysctl_v1_Sysctl_Set_Result_response_tag;
	if (status != 0)
		reply.value.err = (uint32_t)status;
	request_done(session, connection, SYSCTLCMP_OP_SET,
	    (uint32_t)in->value_size, status,
	    bsd_sysctl_v1_Sysctl_Set_reply(connection, request, &reply));
}

static void
interfaces_handler(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct session *session = argument;
	struct bsd_sysctl_v1_Sysctl_ListInterfaces_Result reply = { 0 };
	struct sysctlcmp_interface entries[SYSCTLCMP_MAX_INTERFACES];
	struct bsd_sysctl_v1_Interface out[SYSCTLCMP_MAX_INTERFACES];
	size_t count = 0;
	uint32_t bytes = 0;
	int status = 0;

	if (!session_ready(session, connection, SYSCTLCMP_OP_INTERFACES))
		return;
	if (!sysctlcmp_config_permits(session->config, session->label,
	    SYSCTLCMP_INTERFACES_POLICY, false))
		status = EPERM;
	else if (sysctlcmp_interfaces_collect(read_interfaces, NULL, entries,
	    &count) == -1)
		status = errno;
	if (status != 0) {
		reply.tag = bsd_sysctl_v1_Sysctl_ListInterfaces_Result_err_tag;
		reply.value.err = (uint32_t)status;
	} else {
		for (size_t i = 0; i < count; i++) {
			out[i].index = entries[i].index;
			out[i].flags = entries[i].flags;
			out[i].mtu = entries[i].mtu;
			out[i].link_state = entries[i].link_state;
			out[i].name = entries[i].name;
			out[i].name_size = strnlen(entries[i].name,
			    sizeof(entries[i].name));
		}
		bytes = (uint32_t)(count * sizeof(*entries));
		reply.tag =
		    bsd_sysctl_v1_Sysctl_ListInterfaces_Result_response_tag;
		reply.value.response.interfaces = out;
		reply.value.response.interfaces_size = count;
	}
	request_done(session, connection, SYSCTLCMP_OP_INTERFACES, bytes,
	    status, bsd_sysctl_v1_Sysctl_ListInterfaces_reply(connection,
	    request, &reply));
}

/* A connection the bindings closed for a malformed or unknown frame. */
static bool
protocol_rejection(int error)
{

	return (error != 0 && error != EPIPE && error != ECONNRESET &&
	    error != ECANCELED && error != ETIMEDOUT && error != ENOTCONN);
}

static int
monotonic_ms(uint64_t *result)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return (-1);
	*result = (uint64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
	return (0);
}

static void
session_close(struct session *session)
{
	if (session->connection != NULL)
		fidl_bsd_connection_destroy(session->connection);
	free(session->label);
	memset(session, 0, sizeof(*session));
}

/* Consumes fd, including on failure. Slots stay at stable addresses. */
static int
session_open(struct session *session, int fd, const char *label,
    const struct sysctlcmp_config *config)
{
	static const struct bsd_sysctl_v1_Sysctl_server handlers = {
		.GetProtocolInfo = protocol_info,
		.Get = Get_handler,
		.Set = set_handler,
		.OidFormat = OidFormat_handler,
		.Describe = Describe_handler,
		.Next = Next_handler,
		.ListInterfaces = interfaces_handler
	};
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	int error;

	memset(session, 0, sizeof(*session));
	session->label = strdup(label);
	session->config = config;
	if (session->label == NULL ||
	    monotonic_ms(&session->last_request_ms) == -1) {
		error = errno;
		BSDSYSCTL_TRACE_SESSION_OPEN_FAILURE(1, error);
		close(fd);
		session_close(session);
		return (errno = error, -1);
	}
	/* One request at a time; requests carry no descriptors. */
	options.max_pending_requests = 1;
	options.max_queued_messages = 8;
	options.max_queued_bytes = 64 * 1024;
	options.max_queued_fds = 0;
	error = fidl_bsd_connection_create_with_options(fd, FIDL_BSD_SERVER,
	    &options, &session->connection);
	if (error != 0) {
		BSDSYSCTL_TRACE_SESSION_OPEN_FAILURE(1, error);
		session->connection = NULL;
		close(fd);
		session_close(session);
		return (errno = error, -1);
	}
	error = bsd_sysctl_v1_Sysctl_bind(session->connection, &handlers,
	    session);
	if (error != 0) {
		BSDSYSCTL_TRACE_SESSION_OPEN_FAILURE(2, error);
		session_close(session);
		return (errno = error, -1);
	}
	return (0);
}

/* Admission consumes fd; one label cannot fill the entire session table. */
static int
sessions_admit(struct session *sessions, size_t count, int fd,
    const char *label, const struct sysctlcmp_config *config)
{
	size_t i, free_slot, matching;

	free_slot = count;
	matching = 0;
	for (i = 0; i < count; i++) {
		if (sessions[i].connection == NULL) {
			if (free_slot == count)
				free_slot = i;
		} else if (strcmp(sessions[i].label, label) == 0)
			matching++;
	}
	if (free_slot == count || matching >= BSDSYSCTL_MAX_LABEL_SESSIONS) {
		BSDSYSCTL_TRACE_SESSION_LIMIT(free_slot == count, matching);
		close(fd);
		return (errno = ENOSPC, -1);
	}
	return (session_open(&sessions[free_slot], fd, label, config));
}

/* One bounded dispatch batch per ready session; no client owns the loop. */
static int
sessions_wait(int kq, struct session *sessions, size_t count, int listener_fd,
    uint32_t idle_ms, int *failed)
{
	struct fidl_bsd_connection_slot slots[BSDSYSCTL_MAX_SESSIONS];
	uint64_t now = service_monotime_ms(), wait_ms = INT_MAX;
	size_t i;
	bool active = false;
	int error, ready;
	for (i = 0; i < count; i++) {
		if (sessions[i].connection != NULL) {
			uint64_t elapsed = now - sessions[i].last_request_ms;
			if (elapsed >= idle_ms) {
				BSDSYSCTL_TRACE_SESSION_CLOSE_REASON(1, ETIMEDOUT);
				session_close(&sessions[i]);
			} else {
				active = true;
				if (idle_ms - elapsed < wait_ms)
					wait_ms = idle_ms - elapsed;
			}
		}
		sessions[i].activity = false;
		slots[i].connection = sessions[i].connection;
	}
	if (!active && listener_fd == -1)
		return (0);
	error = fidl_bsd_connections_wait(kq, slots, count, listener_fd,
	    active ? (int)wait_ms : -1, &ready);
	if (error != 0)
		return (errno = error, -1);
	now = service_monotime_ms();
	for (i = 0; i < count; i++) {
		if (sessions[i].activity)
			sessions[i].last_request_ms = now;
		if (slots[i].error != 0 && sessions[i].error == 0 &&
		    protocol_rejection(slots[i].error)) {
			/* A frame the bindings refused before any handler. */
			BSDSYSCTL_PROBE_REQUEST_START(sessions[i].label,
			    UINT16_MAX);
			BSDSYSCTL_PROBE_REQUEST_DONE(sessions[i].label,
			    UINT16_MAX, 0, EPROTO, 0);
			sessions[i].error = EPROTO;
		}
		if (slots[i].error != 0 || sessions[i].error != 0 ||
		    (sessions[i].connection != NULL &&
			now - sessions[i].last_request_ms >= idle_ms)) {
			BSDSYSCTL_TRACE_SESSION_CLOSE_REASON(
			    slots[i].error != 0 ? 2 : sessions[i].error != 0 ? 3 : 1,
			    slots[i].error != 0 ? slots[i].error :
			    sessions[i].error != 0 ? sessions[i].error : ETIMEDOUT);
			if (sessions[i].error != 0)
				*failed = 1;
			session_close(&sessions[i]);
		}
	}
	return (ready);
}

#ifdef SYSCTLCMP_TESTING
#include "bsdsysctl_test.h"

int
sysctlcmp_test_serve_many(const int *fds, const char *const *labels,
    size_t count, const struct sysctlcmp_config *config, uint32_t idle_ms)
{
	struct session sessions[BSDSYSCTL_MAX_SESSIONS] = {0};
	size_t i;
	int kq, failed = 0;
	bool active;

	if (count == 0 || count > BSDSYSCTL_MAX_SESSIONS || fds == NULL ||
	    labels == NULL || config == NULL || idle_ms == 0 || idle_ms > INT_MAX)
		return (errno = EINVAL, -1);
	for (i = 0; i < count; i++)
		if (fds[i] < 0 || labels[i] == NULL || labels[i][0] == '\0')
			return (errno = EINVAL, -1);
	kq = kqueue();
	if (kq == -1) {
		for (i = 0; i < count; i++)
			close(fds[i]);
		return (1);
	}
	for (i = 0; i < count; i++) {
		if (sessions_admit(sessions, count, fds[i], labels[i], config) == -1)
			failed = 1;
	}
	do {
		if (sessions_wait(kq, sessions, count, -1, idle_ms, &failed) == -1) {
			failed = 1;
			break;
		}
		active = false;
		for (i = 0; i < count; i++)
			active |= sessions[i].connection != NULL;
	} while (active);
	for (i = 0; i < count; i++)
		session_close(&sessions[i]);
	close(kq);
	return (failed);
}

int
sysctlcmp_test_serve(int fd, const char *label,
    const struct sysctlcmp_config *config)
{
	return (sysctlcmp_test_serve_many(&fd, &label, 1, config,
	    BSDSYSCTL_SESSION_IDLE_MS));
}
#else

int
main(void)
{
	struct service_identity identity;
	struct service_listener *listener;
	struct service_provider *provider;
	struct session sessions[BSDSYSCTL_MAX_SESSIONS] = {0};
	size_t i;
	int error, fd, cfgfd, ready, failed = 0, kq = -1;

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
	 * only the holder can use it: multiplex channels here (no per-client
	 * pdfork worker, which could not inherit the token).  Dup the token
	 * before entering capmode; fail-soft if none was delivered.
	 */
	if (service_system_token_dup(&g_sysctl_token) == -1) {
		syslog(LOG_WARNING, "no sysctl capability; GET/SET of "
		    "capmode-confined nodes will fail: %m");
		g_sysctl_token = -1;
	}
	kq = kqueue();
	if (kq == -1)
		goto fail;
	if (service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		goto fail;
	for (;;) {
		ready = sessions_wait(kq, sessions, nitems(sessions),
		    service_listener_fd(listener), BSDSYSCTL_SESSION_IDLE_MS, &failed);
		if (ready == -1)
			goto fail;
		if (ready == 0)
			continue;
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		if (service_listener_accept(listener, &identity, &fd) == -1) {
			error = errno;
			if (service_provider_quiescing(provider) == 1) {
				int status;

				for (i = 0; i < nitems(sessions); i++)
					session_close(&sessions[i]);
				status = service_provider_quiesce_complete(
				    provider, 0);
				close(kq);
				closelog();
				return (status == 0 ? 0 : 1);
			}
			errno = error;
			if (errno == EINTR)
				continue;
			goto fail;
		}
		(void)sessions_admit(sessions, nitems(sessions), fd,
		    identity.client_label, &g_config);
	}
fail:
	syslog(LOG_ERR, "initialization or service loop: %m");
	if (kq != -1)
		close(kq);
	for (i = 0; i < nitems(sessions); i++)
		session_close(&sessions[i]);
	return (1);
}
#endif /* !SYSCTLCMP_TESTING */
