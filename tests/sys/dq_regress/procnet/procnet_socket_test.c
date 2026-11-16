/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * socket(2) and socketpair(2) of unattached processes.
 *
 * Stage 1c-ii split socreate() into socreate_find() (protocol lookup and
 * the PR_CAPATTACH test) and socreate_proto() (the socket), with the
 * consultation and prison_check_af() between them, and moved falloc()
 * after all of that in kern_socket():
 *
 *     MAC -> find -> (consult) -> prison_check_af -> falloc -> proto
 *
 * Before (3f330ee172d, uipc_syscalls.c kern_socket()):
 *
 *     MAC -> falloc -> socreate (find, PR_CAPATTACH, prison_check_af,
 *                                 pr_attach)
 *
 * Socket errno order with a full descriptor table: 1c-ii briefly let an
 * unknown domain/type/protocol, ECAPMODE and a jail's family refusal win
 * over EMFILE for every process; the order was restored (D155 amended), so
 * the fdfull_order_* cases assert upstream's EMFILE on every kernel.  The
 * pre1c configuration variable no longer changes them.  Everything here,
 * including fdfull_unchanged (pr_attach errors such as EPERM for raw
 * sockets still come after falloc), must be identical on both kernels.
 *
 * kern_socketpair() always created both sockets before falloc(), so its
 * order is unchanged.
 *
 * Expectations from 3f330ee172d: uipc_socket.c socreate(),
 * uipc_domain.c pffindproto() (5BSD: exact, then wildcard pr_protocol 0,
 * then the first of the type for protocol 0), raw_ip.c rip_attach() and
 * raw_ip6.c rip6_attach() (priv_check before the protocol range),
 * tcp_usrreq.c/udp_usrreq.c (PR_CAPATTACH), rtsock.c and uipc_usrreq.c.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <netinet/in.h>

#include <jail.h>

#include "procnet_common.h"


struct sockcase {
	int	domain;
	int	type;
	int	protocol;
	int	err_root;	/* expected errno as root */
	int	err_unpriv;	/* expected errno unprivileged */
	bool	inet6;		/* needs INET6 */
};

static const struct sockcase sockcases[] = {
	{ AF_UNIX, SOCK_STREAM, 0, 0, 0, false },
	{ AF_UNIX, SOCK_DGRAM, 0, 0, 0, false },
	{ AF_UNIX, SOCK_SEQPACKET, 0, 0, 0, false },
	/* pr_protocol 0 is a wildcard: any protocol number is accepted. */
	{ AF_UNIX, SOCK_STREAM, 12345, 0, 0, false },
	{ AF_UNIX, SOCK_DGRAM, -1, 0, 0, false },
	{ AF_UNIX, SOCK_RAW, 0, EPROTOTYPE, EPROTOTYPE, false },
	{ AF_UNIX, 0, 0, EPROTONOSUPPORT, EPROTONOSUPPORT, false },
	{ AF_UNIX, 99, 0, EPROTOTYPE, EPROTOTYPE, false },
	{ AF_UNIX, 99, 7, EPROTONOSUPPORT, EPROTONOSUPPORT, false },
	{ AF_UNIX, -1, 0, EPROTOTYPE, EPROTOTYPE, false },
	/* An unknown bit in type is part of the type. */
	{ AF_UNIX, SOCK_STREAM | 0x01000000, 0, EPROTOTYPE, EPROTOTYPE,
	    false },
	{ AF_UNSPEC, SOCK_STREAM, 0, EAFNOSUPPORT, EAFNOSUPPORT, false },
	{ -1, SOCK_STREAM, 0, EAFNOSUPPORT, EAFNOSUPPORT, false },
	{ 255, SOCK_STREAM, 0, EAFNOSUPPORT, EAFNOSUPPORT, false },
	{ 255, 99, 99, EAFNOSUPPORT, EAFNOSUPPORT, false },
	{ AF_INET, SOCK_STREAM, 0, 0, 0, false },
	{ AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, false },
	{ AF_INET, SOCK_DGRAM, 0, 0, 0, false },
	{ AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0, 0, false },
	{ AF_INET, SOCK_STREAM, IPPROTO_UDP, EPROTONOSUPPORT,
	    EPROTONOSUPPORT, false },
	{ AF_INET, SOCK_DGRAM, IPPROTO_TCP, EPROTONOSUPPORT,
	    EPROTONOSUPPORT, false },
	{ AF_INET, SOCK_STREAM, 9999, EPROTONOSUPPORT, EPROTONOSUPPORT,
	    false },
	{ AF_INET, 99, 0, EPROTOTYPE, EPROTOTYPE, false },
	{ AF_INET, 0, 0, EPROTONOSUPPORT, EPROTONOSUPPORT, false },
	/* Raw IP: priv_check in rip_attach, then the protocol range. */
	{ AF_INET, SOCK_RAW, 0, 0, EPERM, false },
	{ AF_INET, SOCK_RAW, IPPROTO_ICMP, 0, EPERM, false },
	{ AF_INET, SOCK_RAW, 9999, EPROTONOSUPPORT, EPERM, false },
	{ AF_INET, SOCK_RAW, -1, EPROTONOSUPPORT, EPERM, false },
	{ AF_ROUTE, SOCK_RAW, 0, 0, 0, false },
	{ AF_ROUTE, SOCK_RAW, AF_INET, 0, 0, false },
	{ AF_ROUTE, SOCK_DGRAM, 0, EPROTOTYPE, EPROTOTYPE, false },
	{ AF_INET6, SOCK_STREAM, 0, 0, 0, true },
	{ AF_INET6, SOCK_DGRAM, IPPROTO_UDP, 0, 0, true },
	{ AF_INET6, SOCK_STREAM, IPPROTO_UDP, EPROTONOSUPPORT,
	    EPROTONOSUPPORT, true },
	{ AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, 0, EPERM, true },
	{ AF_INET6, SOCK_RAW, 9999, EPROTONOSUPPORT, EPERM, true },
};

static bool
have_inet6(void)
{

	return (feature_present("inet6") != 0);
}

/* socket(2), closing a success; errno or 0. */
static int
sock_err(int d, int t, int p)
{
	int fd;

	fd = socket(d, t, p);
	if (fd == -1)
		return (errno);
	close(fd);
	return (0);
}

static int
pair_err(int d, int t, int p)
{
	int sv[2];

	if (socketpair(d, t, p, sv) == -1)
		return (errno);
	close(sv[0]);
	close(sv[1]);
	return (0);
}

struct matrix_arg {
	bool	root;
	char	msg[512];
};

static int
matrix_child(void *arg)
{
	struct matrix_arg *ma = arg;
	const struct sockcase *c;
	size_t i;
	int got, want, bad;
	bool v6;

	v6 = have_inet6();
	bad = 0;
	for (i = 0; i < nitems(sockcases); i++) {
		c = &sockcases[i];
		if (c->inet6 && !v6)
			continue;
		want = ma->root ? c->err_root : c->err_unpriv;
		got = sock_err(c->domain, c->type, c->protocol);
		if (got != want) {
			fprintf(stderr, "socket(%d, %#x, %d): expected %s, "
			    "got %s\n", c->domain, c->type, c->protocol,
			    pn_errname(want), pn_errname(got));
			bad++;
		}
	}
	return (bad == 0 ? 0 : PN_X_WRONG);
}

ATF_TC(socket_matrix_root);
ATF_TC_HEAD(socket_matrix_root, tc)
{
	atf_tc_set_md_var(tc, "descr", "socket(2) over domains, types and "
	    "protocols, known and unknown, as root");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(socket_matrix_root, tc)
{
	struct matrix_arg ma = { .root = true };

	PN_CHECK_ERRNO(0, pn_child(matrix_child, &ma, 0, 0),
	    "matrix as root (details on stderr)");
}

ATF_TC(socket_matrix_unpriv);
ATF_TC_HEAD(socket_matrix_unpriv, tc)
{
	atf_tc_set_md_var(tc, "descr", "socket(2) over domains, types and "
	    "protocols, unprivileged: raw IP is EPERM, even for a protocol "
	    "out of range");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(socket_matrix_unpriv, tc)
{
	struct matrix_arg ma = { .root = false };

	PN_CHECK_ERRNO(0, pn_child(matrix_child, &ma, PN_UID, PN_GID),
	    "unprivileged matrix (details on stderr)");
}

ATF_TC(socket_protocol_reported);
ATF_TC_HEAD(socket_protocol_reported, tc)
{
	atf_tc_set_md_var(tc, "descr", "SO_PROTOCOL/SO_TYPE: an AF_UNIX "
	    "socket created with an arbitrary protocol reports 0; TCP and "
	    "UDP created with 0 report their protocol");
}
ATF_TC_BODY(socket_protocol_reported, tc)
{
	socklen_t len;
	int fd, v;

	fd = socket(AF_UNIX, SOCK_STREAM, 12345);
	ATF_REQUIRE(fd >= 0);
	len = sizeof(v);
	ATF_REQUIRE(getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &v, &len) == 0);
	ATF_CHECK_EQ(0, v);
	len = sizeof(v);
	ATF_REQUIRE(getsockopt(fd, SOL_SOCKET, SO_TYPE, &v, &len) == 0);
	ATF_CHECK_EQ(SOCK_STREAM, v);
	close(fd);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	ATF_REQUIRE(fd >= 0);
	len = sizeof(v);
	ATF_REQUIRE(getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &v, &len) == 0);
	ATF_CHECK_EQ(IPPROTO_TCP, v);
	close(fd);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ATF_REQUIRE(fd >= 0);
	len = sizeof(v);
	ATF_REQUIRE(getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &v, &len) == 0);
	ATF_CHECK_EQ(IPPROTO_UDP, v);
	close(fd);
}

static void
check_flags(int fd, bool cloexec, bool nonblock, const char *what)
{
	int fdf, fl;

	fdf = fcntl(fd, F_GETFD);
	fl = fcntl(fd, F_GETFL);
	ATF_REQUIRE(fdf != -1 && fl != -1);
	ATF_CHECK_MSG(((fdf & FD_CLOEXEC) != 0) == cloexec,
	    "%s: FD_CLOEXEC %s", what, cloexec ? "missing" : "set");
	ATF_CHECK_MSG(((fl & O_NONBLOCK) != 0) == nonblock,
	    "%s: O_NONBLOCK %s", what, nonblock ? "missing" : "set");
}

ATF_TC(socket_type_flags);
ATF_TC_HEAD(socket_type_flags, tc)
{
	atf_tc_set_md_var(tc, "descr", "SOCK_CLOEXEC, SOCK_NONBLOCK and "
	    "SOCK_CLOFORK in type: set on the descriptor, stripped from the "
	    "type, and an error does not depend on them");
}
ATF_TC_BODY(socket_type_flags, tc)
{
	socklen_t len;
	int fd, sv[2], v;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(fd >= 0);
	check_flags(fd, false, false, "plain");
	close(fd);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	ATF_REQUIRE(fd >= 0);
	check_flags(fd, true, false, "SOCK_CLOEXEC");
	close(fd);

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	ATF_REQUIRE(fd >= 0);
	check_flags(fd, false, true, "SOCK_NONBLOCK");
	len = sizeof(v);
	ATF_REQUIRE(getsockopt(fd, SOL_SOCKET, SO_TYPE, &v, &len) == 0);
	ATF_CHECK_EQ(SOCK_DGRAM, v);
	close(fd);

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    0);
	ATF_REQUIRE(fd >= 0);
	check_flags(fd, true, true, "both");
	close(fd);

#ifdef SOCK_CLOFORK
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOFORK, 0);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK((fcntl(fd, F_GETFD) & FD_CLOFORK) != 0);
	close(fd);
#endif

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC |
	    SOCK_NONBLOCK, 0, sv) == 0);
	check_flags(sv[0], true, true, "pair[0]");
	check_flags(sv[1], true, true, "pair[1]");
	close(sv[0]);
	close(sv[1]);

	PN_CHECK_ERRNO(EAFNOSUPPORT, sock_err(255, SOCK_STREAM |
	    SOCK_NONBLOCK | SOCK_CLOEXEC, 0), "flags with a bad domain");
	PN_CHECK_ERRNO(EPROTOTYPE, sock_err(AF_UNIX, 99 | SOCK_NONBLOCK, 0),
	    "flags with a bad type");
	PN_CHECK_ERRNO(EAFNOSUPPORT, pair_err(255, SOCK_STREAM |
	    SOCK_CLOEXEC, 0), "pair flags with a bad domain");
}

static int
capmode_child(void *arg)
{
	bool root = *(bool *)arg;
	int bad;

	if (cap_enter() != 0)
		return (errno == ENOSYS ? PN_X_SETUP : errno);
	bad = 0;
#define	CAPCHK(want, got) do {						\
	int _w = (want), _g = (got);					\
	if (_w != _g) {							\
		fprintf(stderr, "capmode %s: expected %s, got %s\n",	\
		    #got, pn_errname(_w), pn_errname(_g));		\
		bad++;							\
	}								\
} while (0)
	CAPCHK(0, sock_err(AF_UNIX, SOCK_STREAM, 0));
	CAPCHK(0, sock_err(AF_UNIX, SOCK_DGRAM, 0));
	CAPCHK(0, sock_err(AF_INET, SOCK_STREAM, 0));
	CAPCHK(0, sock_err(AF_INET, SOCK_DGRAM, 0));
	/* No PR_CAPATTACH: ECAPMODE, also before rip_attach's EPERM. */
	CAPCHK(ECAPMODE, sock_err(AF_INET, SOCK_RAW, 0));
	CAPCHK(ECAPMODE, sock_err(AF_INET, SOCK_RAW, 9999));
	CAPCHK(ECAPMODE, sock_err(AF_ROUTE, SOCK_RAW, 0));
	/* The lookup comes first: its errors win over ECAPMODE. */
	CAPCHK(EAFNOSUPPORT, sock_err(255, SOCK_STREAM, 0));
	CAPCHK(EPROTOTYPE, sock_err(AF_UNIX, 99, 0));
	CAPCHK(EPROTONOSUPPORT, sock_err(AF_INET, SOCK_DGRAM, IPPROTO_TCP));
	CAPCHK(EPROTOTYPE, sock_err(AF_ROUTE, SOCK_DGRAM, 0));
	/* socketpair(2) the same way. */
	CAPCHK(0, pair_err(AF_UNIX, SOCK_STREAM, 0));
	CAPCHK(ECAPMODE, pair_err(AF_ROUTE, SOCK_RAW, 0));
	CAPCHK(ECAPMODE, pair_err(AF_INET, SOCK_RAW, 0));
	CAPCHK(EAFNOSUPPORT, pair_err(255, SOCK_STREAM, 0));
	/* TCP may be created; socketpair of it is EOPNOTSUPP as ever. */
	CAPCHK(EOPNOTSUPP, pair_err(AF_INET, SOCK_STREAM, 0));
#undef CAPCHK
	(void)root;
	return (bad == 0 ? 0 : PN_X_WRONG);
}

ATF_TC(socket_capmode);
ATF_TC_HEAD(socket_capmode, tc)
{
	atf_tc_set_md_var(tc, "descr", "in capability mode: PR_CAPATTACH "
	    "protocols are allowed, others ECAPMODE (before EPERM); lookup "
	    "errors win over ECAPMODE; root and unprivileged alike");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(socket_capmode, tc)
{
	bool root;

	if (feature_present("security_capability_mode") == 0)
		atf_tc_skip("no capability mode");
	root = true;
	PN_CHECK_ERRNO(0, pn_child(capmode_child, &root, 0, 0),
	    "capability mode as root (details on stderr)");
	root = false;
	PN_CHECK_ERRNO(0, pn_child(capmode_child, &root, PN_UID, PN_GID),
	    "capability mode unprivileged (details on stderr)");
}

ATF_TC(socketpair_matrix);
ATF_TC_HEAD(socketpair_matrix, tc)
{
	atf_tc_set_md_var(tc, "descr", "socketpair(2): AF_UNIX types connect "
	    "both ways; INET is EOPNOTSUPP; lookup errors as socket(2); "
	    "unprivileged raw is EPERM");
	atf_tc_set_md_var(tc, "require.user", "root");
}

static int
pair_unpriv(void *arg __unused)
{

	if (pair_err(AF_INET, SOCK_RAW, 0) != EPERM)
		return (PN_X_WRONG);
	if (pair_err(AF_UNIX, SOCK_STREAM, 0) != 0)
		return (PN_X_WRONG);
	return (0);
}

ATF_TC_BODY(socketpair_matrix, tc)
{
	static const int types[] = { SOCK_STREAM, SOCK_DGRAM,
	    SOCK_SEQPACKET };
	char c;
	size_t i;
	int sv[2];

	for (i = 0; i < nitems(types); i++) {
		ATF_REQUIRE_MSG(socketpair(AF_UNIX, types[i], 0, sv) == 0,
		    "type %d: %s", types[i], strerror(errno));
		ATF_CHECK(write(sv[0], "a", 1) == 1);
		ATF_CHECK(read(sv[1], &c, 1) == 1 && c == 'a');
		ATF_CHECK(write(sv[1], "b", 1) == 1);
		ATF_CHECK(read(sv[0], &c, 1) == 1 && c == 'b');
		close(sv[0]);
		close(sv[1]);
	}
	PN_CHECK_ERRNO(0, pair_err(AF_UNIX, SOCK_STREAM, 777),
	    "AF_UNIX pair, any protocol");
	PN_CHECK_ERRNO(EOPNOTSUPP, pair_err(AF_INET, SOCK_STREAM, 0),
	    "INET stream pair");
	PN_CHECK_ERRNO(EOPNOTSUPP, pair_err(AF_INET, SOCK_DGRAM, 0),
	    "INET dgram pair");
	PN_CHECK_ERRNO(EOPNOTSUPP, pair_err(AF_ROUTE, SOCK_RAW, 0),
	    "route pair");
	PN_CHECK_ERRNO(EAFNOSUPPORT, pair_err(255, SOCK_STREAM, 0),
	    "bad domain pair");
	PN_CHECK_ERRNO(EPROTOTYPE, pair_err(AF_UNIX, SOCK_RAW, 0),
	    "AF_UNIX raw pair");
	PN_CHECK_ERRNO(EPROTONOSUPPORT, pair_err(AF_INET, SOCK_DGRAM,
	    IPPROTO_TCP), "INET dgram/tcp pair");
	PN_CHECK_ERRNO(EPROTONOSUPPORT, pair_err(AF_INET, SOCK_RAW, 9999),
	    "raw pair, protocol out of range");
	PN_CHECK_ERRNO(0, pn_child(pair_unpriv, NULL, PN_UID, PN_GID),
	    "unprivileged pairs");
}

/* --- full descriptor table ------------------------------------------- */

struct fdfull_arg {
	bool	pre1c;
	bool	capmode;
	bool	root;
};

static int
fdfull_unchanged_child(void *arg)
{
	struct fdfull_arg *fa = arg;
	int bad;

	if (pn_fill_fdtable() < 0)
		return (PN_X_SETUP);
	bad = 0;
#define	FCHK(want, got) do {						\
	int _w = (want), _g = (got);					\
	if (_w != _g) {							\
		fprintf(stderr, "full table %s: expected %s, got %s\n",	\
		    #got, pn_errname(_w), pn_errname(_g));		\
		bad++;							\
	}								\
} while (0)
	FCHK(EMFILE, sock_err(AF_UNIX, SOCK_STREAM, 0));
	FCHK(EMFILE, sock_err(AF_INET, SOCK_DGRAM, 0));
	FCHK(EMFILE, sock_err(AF_ROUTE, SOCK_RAW, 0));
	/* pr_attach errors were and are after falloc(): EMFILE. */
	if (fa->root) {
		FCHK(EMFILE, sock_err(AF_INET, SOCK_RAW, 9999));
	} else {
		FCHK(EMFILE, sock_err(AF_INET, SOCK_RAW, 0));
	}
	/* socketpair(2): the sockets first, then falloc(). */
	FCHK(EMFILE, pair_err(AF_UNIX, SOCK_STREAM, 0));
	FCHK(EMFILE, pair_err(AF_UNIX, SOCK_DGRAM, 0));
	/* soconnect2() comes after falloc(): EMFILE, not EOPNOTSUPP. */
	FCHK(EMFILE, pair_err(AF_INET, SOCK_STREAM, 0));
	/* Lookup errors were always before falloc() for a pair. */
	FCHK(EAFNOSUPPORT, pair_err(255, SOCK_STREAM, 0));
	FCHK(EPROTOTYPE, pair_err(AF_UNIX, 99, 0));
	if (!fa->root) {
		/* rip_attach in socreate before falloc(): EPERM. */
		FCHK(EPERM, pair_err(AF_INET, SOCK_RAW, 0));
	}
	/* accept(2)-like slot users are unaffected: dup is EMFILE. */
	FCHK(EMFILE, PN_ERR(dup(0)));
#undef FCHK
	return (bad == 0 ? 0 : PN_X_WRONG);
}

ATF_TC(fdfull_unchanged);
ATF_TC_HEAD(fdfull_unchanged, tc)
{
	atf_tc_set_md_var(tc, "descr", "with a full descriptor table: valid "
	    "sockets, pr_attach failures (raw EPERM, raw protocol range) and "
	    "socketpair(2) give the same errno as before");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fdfull_unchanged, tc)
{
	struct fdfull_arg fa;

	memset(&fa, 0, sizeof(fa));
	fa.root = true;
	PN_CHECK_ERRNO(0, pn_child(fdfull_unchanged_child, &fa, 0, 0),
	    "full table as root (details on stderr)");
	fa.root = false;
	PN_CHECK_ERRNO(0, pn_child(fdfull_unchanged_child, &fa, PN_UID,
	    PN_GID), "full table unprivileged (details on stderr)");
}

/*
 * Full table: upstream's order, EMFILE before the lookup error.
 */
static int
fdfull_order_child(void *arg)
{
	struct fdfull_arg *fa = arg;
	int bad;

	/* Fill first: open(2) is not allowed in capability mode. */
	if (pn_fill_fdtable() < 0)
		return (PN_X_SETUP);
	if (fa->capmode && cap_enter() != 0)
		return (PN_X_SETUP);
	bad = 0;
#define	OCHK(newerr, got) do {						\
	int _w = EMFILE, _g = (got); (void)(newerr);		\
	if (_w != _g) {							\
		fprintf(stderr, "full table %s: expected %s, got %s\n",	\
		    #got, pn_errname(_w), pn_errname(_g));		\
		bad++;							\
	}								\
} while (0)
	if (fa->capmode) {
		OCHK(ECAPMODE, sock_err(AF_ROUTE, SOCK_RAW, 0));
		OCHK(ECAPMODE, sock_err(AF_INET, SOCK_RAW, 0));
	} else {
		OCHK(EAFNOSUPPORT, sock_err(255, SOCK_STREAM, 0));
		OCHK(EAFNOSUPPORT, sock_err(AF_UNSPEC, SOCK_STREAM, 0));
		OCHK(EPROTOTYPE, sock_err(AF_UNIX, 99, 0));
		OCHK(EPROTOTYPE, sock_err(AF_UNIX, SOCK_RAW, 0));
		OCHK(EPROTONOSUPPORT, sock_err(AF_UNIX, 0, 0));
		OCHK(EPROTONOSUPPORT, sock_err(AF_INET, SOCK_DGRAM,
		    IPPROTO_TCP));
		OCHK(EPROTONOSUPPORT, sock_err(AF_INET, SOCK_STREAM, 9999));
	}
#undef OCHK
	return (bad == 0 ? 0 : PN_X_WRONG);
}

ATF_TC(fdfull_order_lookup);
ATF_TC_HEAD(fdfull_order_lookup, tc)
{
	atf_tc_set_md_var(tc, "descr", "DOCUMENTED CHANGE (D139/D155): with "
	    "a full table socket(2) with a bad domain/type/protocol is the "
	    "EMFILE before the lookup errno, as upstream");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fdfull_order_lookup, tc)
{
	struct fdfull_arg fa;

	memset(&fa, 0, sizeof(fa));
	fa.pre1c = pn_pre1c(tc);
	PN_CHECK_ERRNO(0, pn_child(fdfull_order_child, &fa, 0, 0),
	    "order as root (details on stderr)");
	PN_CHECK_ERRNO(0, pn_child(fdfull_order_child, &fa, PN_UID, PN_GID),
	    "order unprivileged (details on stderr)");
}

ATF_TC(fdfull_order_capmode);
ATF_TC_HEAD(fdfull_order_capmode, tc)
{
	atf_tc_set_md_var(tc, "descr", "DOCUMENTED CHANGE (D139/D155): with "
	    "a full table in capability mode, a non-PR_CAPATTACH socket is "
	    "EMFILE before ECAPMODE, as upstream");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fdfull_order_capmode, tc)
{
	struct fdfull_arg fa;

	if (feature_present("security_capability_mode") == 0)
		atf_tc_skip("no capability mode");
	memset(&fa, 0, sizeof(fa));
	fa.pre1c = pn_pre1c(tc);
	fa.capmode = true;
	PN_CHECK_ERRNO(0, pn_child(fdfull_order_child, &fa, 0, 0),
	    "capmode order (details on stderr)");
}

/* --- a jail without IPv4 (and IPv6) ---------------------------------- */

#define	NOINET_JAIL	"procnet_noinet"

static int
noinet_jail(void)
{
	int jid;

	jid = jail_setv(JAIL_CREATE, "name", NOINET_JAIL, "path", "/",
	    "ip4", "disable", "ip6", "disable", "persist", NULL, NULL);
	if (jid < 0)
		jid = jail_setv(JAIL_CREATE, "name", NOINET_JAIL, "path", "/",
		    "ip4", "disable", "persist", NULL, NULL);
	if (jid < 0)
		atf_tc_skip("jail_setv: %s", jail_errmsg);
	return (jid);
}

struct jail_arg {
	int	jid;
	bool	pre1c;
	bool	full;
	bool	v6;
	bool	unpriv;		/* drop privileges after the attach */
};

static int
jail_child(void *arg)
{
	struct jail_arg *ja = arg;
	int bad, inet_err;

	if (jail_attach(ja->jid) != 0)
		return (PN_X_SETUP);
	if (ja->unpriv)
		pn_drop(PN_UID, PN_GID);
	if (ja->full && pn_fill_fdtable() < 0)
		return (PN_X_SETUP);
	/*
	 * prison_check_af() refuses AF_INET: socreate() maps it to
	 * EPROTONOSUPPORT.  With a full table EMFILE comes first, as upstream.
	 */
	inet_err = ja->full ? EMFILE : EPROTONOSUPPORT;
	bad = 0;
#define	JCHK(want, got) do {						\
	int _w = (want), _g = (got);					\
	if (_w != _g) {							\
		fprintf(stderr, "jail%s %s: expected %s, got %s\n",	\
		    ja->full ? " (full table)" : "", #got,		\
		    pn_errname(_w), pn_errname(_g));			\
		bad++;							\
	}								\
} while (0)
	JCHK(inet_err, sock_err(AF_INET, SOCK_STREAM, 0));
	JCHK(inet_err, sock_err(AF_INET, SOCK_DGRAM, 0));
	JCHK(inet_err, sock_err(AF_INET, SOCK_RAW, 0));
	if (ja->v6)
		JCHK(inet_err, sock_err(AF_INET6, SOCK_STREAM, 0));
	/* The lookup still comes first. */
	JCHK(ja->full ? EMFILE : EPROTONOSUPPORT,
	    sock_err(AF_INET, SOCK_DGRAM, IPPROTO_TCP));
	JCHK(ja->full ? EMFILE : EPROTOTYPE,
	    sock_err(AF_INET, 99, 0));
	/* Families the jail allows. */
	JCHK(ja->full ? EMFILE : 0, sock_err(AF_UNIX, SOCK_STREAM, 0));
	/* socketpair(2): the jail test was always before falloc(). */
	JCHK(EPROTONOSUPPORT, pair_err(AF_INET, SOCK_STREAM, 0));
	JCHK(ja->full ? EMFILE : 0, pair_err(AF_UNIX, SOCK_STREAM, 0));
#undef JCHK
	return (bad == 0 ? 0 : PN_X_WRONG);
}

ATF_TC_WITH_CLEANUP(jail_noinet);
ATF_TC_HEAD(jail_noinet, tc)
{
	atf_tc_set_md_var(tc, "descr", "in a jail with ip4=disable: INET "
	    "sockets are EPROTONOSUPPORT, AF_UNIX works; socketpair(2) the "
	    "same; with a free descriptor table on both kernels");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_noinet, tc)
{
	struct jail_arg ja;

	memset(&ja, 0, sizeof(ja));
	ja.jid = noinet_jail();
	ja.v6 = have_inet6();
	{
		char ip6[16] = "";
		char jidstr[16];

		snprintf(jidstr, sizeof(jidstr), "%d", ja.jid);
		if (jail_getv(0, "jid", jidstr, "ip6", ip6, NULL) < 0 ||
		    strcmp(ip6, "disable") != 0)
			ja.v6 = false;
	}
	PN_CHECK_ERRNO(0, pn_child(jail_child, &ja, 0, 0),
	    "jail as root (details on stderr)");
	ja.unpriv = true;
	PN_CHECK_ERRNO(0, pn_child(jail_child, &ja, 0, 0),
	    "jail unprivileged (details on stderr)");
}
ATF_TC_CLEANUP(jail_noinet, tc)
{
	int jid;

	jid = jail_getid(NOINET_JAIL);
	if (jid > 0)
		(void)jail_remove(jid);
}

ATF_TC_WITH_CLEANUP(fdfull_order_jail);
ATF_TC_HEAD(fdfull_order_jail, tc)
{
	atf_tc_set_md_var(tc, "descr", "DOCUMENTED CHANGE (D139/D155): in a "
	    "jail with ip4=disable and a full table, socket(AF_INET) is "
	    "EMFILE before EPROTONOSUPPORT, as upstream; "
	    "socketpair(2) unchanged");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fdfull_order_jail, tc)
{
	struct jail_arg ja;

	memset(&ja, 0, sizeof(ja));
	ja.jid = noinet_jail();
	ja.full = true;
	ja.pre1c = pn_pre1c(tc);
	ja.v6 = false;
	PN_CHECK_ERRNO(0, pn_child(jail_child, &ja, 0, 0),
	    "full table in the jail (details on stderr)");
}
ATF_TC_CLEANUP(fdfull_order_jail, tc)
{
	int jid;

	jid = jail_getid(NOINET_JAIL);
	if (jid > 0)
		(void)jail_remove(jid);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, socket_matrix_root);
	ATF_TP_ADD_TC(tp, socket_matrix_unpriv);
	ATF_TP_ADD_TC(tp, socket_protocol_reported);
	ATF_TP_ADD_TC(tp, socket_type_flags);
	ATF_TP_ADD_TC(tp, socket_capmode);
	ATF_TP_ADD_TC(tp, socketpair_matrix);
	ATF_TP_ADD_TC(tp, fdfull_unchanged);
	ATF_TP_ADD_TC(tp, fdfull_order_lookup);
	ATF_TP_ADD_TC(tp, fdfull_order_capmode);
	ATF_TP_ADD_TC(tp, jail_noinet);
	ATF_TP_ADD_TC(tp, fdfull_order_jail);
	return (atf_no_error());
}
