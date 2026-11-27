/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Shared by nested_supervisor_test and its helper programs
 * (nested_supervisor_helper, the set-uid nested_supervisor_setid).
 */
#ifndef _NESTED_SUPERVISOR_H_
#define	_NESTED_SUPERVISOR_H_

#include <stdint.h>

#define	NSH_DEVICE		"/dev/mac_capability"

/* nested_supervisor_helper modes. */
#define	NSH_MODE_LOOKUP		"lookup"	/* NR1: name tag */
#define	NSH_MODE_NOROUTE	"noroute"	/* NR6 */

#define	NSH_NR1_NAME		"org.test.nr1.served"
#define	NSH_NR1_TAG		"nr1-get-descriptor"
#define	NSH_NR1_SESSION		"nr1-session"

/* Helper exit statuses: which step failed. */
enum {
	NSH_EXIT_OK = 0,
	NSH_EXIT_USAGE = 64,
	NSH_EXIT_INFO,		/* MAC_CAP_PROCESS_INFO failed */
	NSH_EXIT_PRESENT,	/* a route where none is pinned, or none */
	NSH_EXIT_GET,		/* MAC_CAP_PROCESS_GET: unexpected answer */
	NSH_EXIT_SEND,		/* send on the GET descriptor failed */
	NSH_EXIT_LOOKUP,	/* service_open: unexpected answer */
	NSH_EXIT_SESSION,	/* send on the session failed */
	NSH_EXIT_SETUID,	/* the set-id program could not drop root */
	NSH_EXIT_EXEC = 127	/* exec of the helper failed */
};

static inline const char *
nsh_exit_name(int status)
{

	switch (status) {
	case NSH_EXIT_OK:	return ("ok");
	case NSH_EXIT_USAGE:	return ("usage");
	case NSH_EXIT_INFO:	return ("MAC_CAP_PROCESS_INFO failed");
	case NSH_EXIT_PRESENT:	return ("route presence not as pinned");
	case NSH_EXIT_GET:	return ("MAC_CAP_PROCESS_GET not as pinned");
	case NSH_EXIT_SEND:	return ("send on the GET descriptor failed");
	case NSH_EXIT_LOOKUP:	return ("service_open not as pinned");
	case NSH_EXIT_SESSION:	return ("send on the session failed");
	case NSH_EXIT_SETUID:	return ("setuid(getuid()) failed");
	case NSH_EXIT_EXEC:	return ("exec failed");
	default:		return ("killed or unknown");
	}
}

/* What the set-uid program sends over the route it kept (NR8). */
struct nsh_setid_report {
	int32_t		issetugid;
	uint32_t	ruid;
	uint32_t	euid;
	int32_t		info_err;
	uint32_t	present;
	uint32_t	pad;
	uint64_t	generation;
	int32_t		get_err;
	uint32_t	pad2;
};

#endif /* !_NESTED_SUPERVISOR_H_ */
