/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Exec helper for mac_capability tests.  Being exec'd rotates the process
 * nonce, which is the whole point — callers fork+exec this binary
 * so the child runs under a different nonce.
 *
 * Modes:
 *   <fd>        Check that fd was closed by FD_CLOEXEC.
 *               Returns 0 if EBADF (closed), 1 if still open.
 *   kldnext     Try kldnext(0).  Returns 0 if denied (EPERM),
 *               1 if allowed.
 *   auth_kldnext <tokenfd> <readyfd> <gofd>
 *               Authorize on tokenfd, notify readyfd, wait for gofd,
 *               close tokenfd, then try kldnext(0).
 *               Returns 0 if denied (revoked), 1 if allowed.
 *   claim_hold <gate_hex> <readyfd> <gofd>
 *               Connect to "system" and claim <gate_hex> under this
 *               (exec-rotated) nonce, notify readyfd, then block on gofd
 *               so the claim stays live for the parent's test.  Used to
 *               plant a second owner's claim ahead of the parent's in the
 *               claim list (SYS_OP_CLAIM inserts at the head).
 *               Returns 3 on connect/claim failure, 0 once released.
 *   kenv_set     Try kenv(KENV_SET) under this nonce with no claim/auth.
 *               Returns 1 if allowed, 0 if denied (EPERM).
 *   sysctl_named <name>
 *               Read the named integer sysctl then write it back to its own
 *               value, under this (foreign) nonce.  Returns 5 if resolution/
 *               read failed (name lookup wrongly gated), 1 if the write was
 *               allowed, 0 if the write was denied.  Used to probe per-OID
 *               SYSCTL isolation.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/kenv.h>
#include <sys/linker.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <fcntl.h>
#include <kenv.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_identity_proto.h"
#include "mac_capability_system_proto.h"

/* A short, reversible kenv variable used only to probe the KENV gate. */
#define	KENV_PROBE_NAME	"mac_cap_gate_probe"

static int
sys_connect(void)
{
	struct mac_capability_connect_args ca;
	int ctl;

	/*
	 * Plain open (this helper is a PROG, not an ATF test, so it cannot use
	 * the atf-based mac_capability_open() from the test helper header).
	 */
	ctl = open("/dev/mac_capability", O_RDWR);
	if (ctl < 0)
		return (-1);
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, "system", sizeof(ca.name));
	if (ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca) != 0) {
		close(ctl);
		return (-1);
	}
	close(ctl);
	return (ca.fd);
}

static int
sys_call_claim(int fd, uint32_t gates)
{
	struct mac_capability_call_args ca;
	struct sys_request req;

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_CLAIM;
	req.gates = gates;

	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_len = 0;

	return (ioctl(fd, MAC_CAPABILITY_CALL, &ca));
}

static int
try_kenv_set(void)
{
	char value[] = "1";

	if (kenv(KENV_SET, KENV_PROBE_NAME, value, (int)sizeof(value)) == 0)
		return (1);	/* allowed */
	return (0);		/* denied (EPERM) or other failure */
}

static int
sys_call_authorize(int token_fd)
{
	struct mac_capability_call_args ca;
	struct sys_request req;

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_AUTHORIZE;

	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_len = 0;

	return (ioctl(token_fd, MAC_CAPABILITY_CALL, &ca));
}

/*
 * Connect to an arbitrary named service (plain open; this is a PROG and
 * cannot use the atf-based helper header).  Returns the instance fd or -1.
 */
static int
connect_named(const char *name)
{
	struct mac_capability_connect_args ca;
	int ctl;

	ctl = open("/dev/mac_capability", O_RDWR);
	if (ctl < 0)
		return (-1);
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, name, sizeof(ca.name));
	if (ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca) != 0) {
		close(ctl);
		return (-1);
	}
	close(ctl);
	return (ca.fd);
}

/*
 * Read this process's own program nonce via the identity service
 * (IDENTITY_OP_SELF).  Returns 0 and stores the nonce on success, -1 if the
 * identity service is unavailable or the call fails.
 */
static int
read_self_nonce(uint64_t *out)
{
	struct mac_capability_call_args ca;
	struct identity_request req;
	struct identity_reply reply;
	int fd;

	fd = connect_named("identity");
	if (fd < 0)
		return (-1);
	memset(&req, 0, sizeof(req));
	req.op = IDENTITY_OP_SELF;
	memset(&reply, 0, sizeof(reply));
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply = &reply;
	ca.reply_len = sizeof(reply);
	if (ioctl(fd, MAC_CAPABILITY_CALL, &ca) != 0) {
		(void)close(fd);
		return (-1);
	}
	(void)close(fd);
	if (reply.status != IDENTITY_STATUS_OK)
		return (-1);
	*out = reply.nonce;
	return (0);
}

/*
 * A benign, reversible sysctl write used only to probe the SYSCTL gate:
 * kern.maxfiles is read and then written back to its own current value, so a
 * gate-allowed write mutates nothing.  __sysctl(2) is SYF_CAPENABLED, so it
 * reaches the mac_capability sysctl hook even inside capability mode (unlike
 * kenv(2), which is not capability-enabled and returns ECAPMODE before any MAC
 * hook runs).  The hook only gates writes (newptr != NULL), never reads.
 */
#define	SYSCTL_PROBE_NAME	"kern.maxfiles"

static int
sysctl_read_int(int *val)
{
	size_t sz = sizeof(*val);

	return (sysctlbyname(SYSCTL_PROBE_NAME, val, &sz, NULL, 0));
}

static int
sysctl_write_same(int val)
{

	/* 0 = gate allowed the write, -1 = denied (EPERM) or other error. */
	return (sysctlbyname(SYSCTL_PROBE_NAME, NULL, NULL, &val, sizeof(val)));
}

int
main(int argc, char **argv)
{
	char buf;

	if (argc == 5 && strcmp(argv[1], "auth_kldnext") == 0) {
		int token_fd, readyfd, gofd;

		token_fd = (int)strtol(argv[2], NULL, 10);
		readyfd = (int)strtol(argv[3], NULL, 10);
		gofd = (int)strtol(argv[4], NULL, 10);

		if (sys_call_authorize(token_fd) != 0)
			return (3);
		if (write(readyfd, "r", 1) != 1)
			return (4);
		if (read(gofd, &buf, 1) != 1)
			return (5);
		(void)close(token_fd);
		if (kldnext(0) < 0 && errno == EPERM)
			return (0);
		return (1);
	}

	if (argc == 5 && strcmp(argv[1], "claim_hold") == 0) {
		int svc, readyfd, gofd;
		uint32_t gates;

		gates = (uint32_t)strtoul(argv[2], NULL, 0);
		readyfd = (int)strtol(argv[3], NULL, 10);
		gofd = (int)strtol(argv[4], NULL, 10);

		svc = sys_connect();
		if (svc < 0)
			return (3);
		if (sys_call_claim(svc, gates) != 0)
			return (3);
		if (write(readyfd, "r", 1) != 1)
			return (4);
		if (read(gofd, &buf, 1) != 1)
			return (5);
		return (0);
	}

	if (argc == 3 && strcmp(argv[1], "self_nonce") == 0) {
		int writefd;
		uint64_t nonce;

		writefd = (int)strtol(argv[2], NULL, 10);
		if (read_self_nonce(&nonce) != 0)
			return (3);	/* identity service unavailable */
		if (write(writefd, &nonce, sizeof(nonce)) != (ssize_t)sizeof(nonce))
			return (4);
		return (0);
	}

	if (argc == 3 && strcmp(argv[1], "sysctl_named") == 0) {
		int val;
		size_t sz = sizeof(val);

		/*
		 * Per-OID isolation probe under a fresh (foreign) nonce.  Read
		 * the named integer OID (also exercises name resolution, which
		 * must never be gated) then write it back to its own value.
		 * Exit 5 if resolution/read failed (a bug: name lookup gated),
		 * 1 if the write was allowed, 0 if the write was denied.
		 */
		if (sysctlbyname(argv[2], &val, &sz, NULL, 0) != 0)
			return (5);
		return (sysctlbyname(argv[2], NULL, NULL, &val,
		    sizeof(val)) == 0 ? 1 : 0);
	}

	if (argc != 2)
		return (2);

	if (strcmp(argv[1], "sysctl_probe") == 0) {
		int val;

		/*
		 * Foreign-nonce probe of the SYSCTL gate (NOT capmode: a capmode
		 * sysctl write is separately blocked by capsicum unless the OID is
		 * CTLFLAG_CAPWR, which would confound the gate result).  First a
		 * read BY NAME — sysctlbyname(3) resolves the name via the
		 * CTL_SYSCTL NAME2OID magic node, which must NOT be gated (exit 5
		 * would mean name resolution broke under the claim).  Then a
		 * write-back of the OID's own value: a real, gate-worthy write.
		 */
		if (sysctl_read_int(&val) != 0)
			return (5);	/* name resolution / read was gated (bug) */
		/* 1 = write allowed, 0 = write denied (gate works). */
		return (sysctl_write_same(val) == 0 ? 1 : 0);
	}

	if (strcmp(argv[1], "kenv_set") == 0)
		return (try_kenv_set());

	if (strcmp(argv[1], "kldnext") == 0) {
		if (kldnext(0) < 0 && errno == EPERM)
			return (0);	/* denied — gate works */
		return (1);		/* allowed */
	}

	/* Default: FD_CLOEXEC check */
	{
		int fd;

		fd = (int)strtol(argv[1], NULL, 10);
		if (fcntl(fd, F_GETFD) == -1 && errno == EBADF)
			return (0);
	}
	return (1);
}
