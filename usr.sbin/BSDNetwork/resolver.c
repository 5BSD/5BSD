/*
 * resolver.c - capability-mode-safe getaddrinfo(3) replacement for the
 * bsdnetwork daemon.
 *
 * The daemon's per-connection workers run under cap_enter(2); after that
 * point no path may be opened and libc getaddrinfo(3) is unusable (it opens
 * /etc/resolv.conf, /etc/hosts and /etc/services on demand).  Before
 * workers fork, netresolve_init() reads resolv.conf through the filesystem
 * provider and retains read-only descriptors for /etc/hosts and
 * /etc/services.  The parent periodically refreshes nameservers through the
 * filesystem provider; existing workers read a shared, read-only generation.
 * netresolve() serves lookups in capability mode using retained descriptors,
 * pure in-memory parsing, and fresh UDP or TCP sockets connected to a
 * configured nameserver with connectat(2).
 *
 * This code parses untrusted DNS responses; every field is bounds-checked
 * before use and the number of collected results is capped.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/capsicum.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <poll.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libservice.h>
#include "resolver.h"

/* ---- retained pre-cap_enter state ------------------------------------- */
static struct __res_state	g_res;
static int			g_hostsfd = -1;
static int			g_servfd = -1;

/* ---- tunables / bounds ------------------------------------------------ */
#define	RSLV_MAX_RESULTS	32	/* cap on collected addresses          */
#define	RSLV_MAX_NS		8	/* cap on nameservers we will try      */
#define	RSLV_HOSTS_BUFSZ	(64 * 1024)	/* /etc/hosts snapshot cap     */
#define	RSLV_SERV_BUFSZ		(1024 * 1024)	/* /etc/services snapshot cap  */
#define	RSLV_DFL_RETRANS	5	/* seconds, if g_res.retrans unset     */
#define	RSLV_DFL_RETRY		2	/* attempts, if g_res.retry unset      */
#define	RSLV_MAX_RETRANS	30	/* bound each UDP/TCP exchange in sec */
#define	RSLV_MAX_CNAME_HOPS	16	/* reject cyclic or excessive chains */

/*
 * Initial nameservers parsed from the delivered /etc/resolv.conf.  Workers
 * retain this process-local snapshot as a fallback if the shared writer dies.
 * DNS queries normally read the latest complete shared generation.
 */
static union res_sockaddr_union	g_ns[RSLV_MAX_NS];
static int			g_nns;

#define	RSLV_CONFIG_PATH		"/etc/resolv.conf"
#define	RSLV_INSTALLER_CONFIG_PATH	"/tmp/bsdinstall_etc/resolv.conf"

/*
 * Installer media deliberately makes /etc/resolv.conf an absolute symlink to
 * a writable tmpfs file.  bsdfilesystem refuses symlinks at a policy-granted leaf, as
 * it must: following an arbitrary replacement would turn an exact-path grant
 * into ambient pathname authority.  ELOOP is the usual O_NOFOLLOW result;
 * FreeBSD's O_RESOLVE_BENEATH reports EMLINK for this absolute-link case.
 * Retry only those two errors and only at the installer's exact, separately
 * policy-granted target.  All other failures retain their original meaning.
 */
static int
open_resolver_config(struct service_context *ctx, int *fdp)
{
	int error;

	if (service_open_isolated(ctx, RSLV_CONFIG_PATH, SERVICE_OPEN_READ, 0,
	    fdp) == 0)
		return (0);
	error = errno;
	if (error != ELOOP && error != EMLINK)
		return (-1);
	return (service_open_isolated(ctx, RSLV_INSTALLER_CONFIG_PATH,
	    SERVICE_OPEN_READ, 0, fdp));
}

struct rslv_addr {
	int	family;
	union {
		struct in_addr	v4;
		struct in6_addr	v6;
	} a;
};

struct rslv_port {
	int		socktype;	/* SOCK_STREAM / SOCK_DGRAM             */
	int		proto;		/* IPPROTO_TCP / IPPROTO_UDP           */
	uint16_t	port;		/* host byte order                     */
};

/*
 * The parent refreshes nameservers while long-lived workers serve requests.
 * Workers remap this anonymous object read-only, with CAP_MMAP_R rights, before
 * entering capability mode.  Atomic bytes and a sequence number let each DNS
 * query take one complete generation without a control fd per worker.
 */
struct rslv_nameservers {
	_Atomic uint32_t generation;
	_Atomic uint32_t count;
	_Atomic unsigned char bytes[sizeof(g_ns)];
};
static struct rslv_nameservers *g_nameservers;
static int g_nameservers_fd = -1;

static void
nameservers_publish(const union res_sockaddr_union *servers, int count)
{
	const unsigned char *bytes;
	size_t i;

	if (g_nameservers == NULL)
		return;
	bytes = (const unsigned char *)(const void *)servers;
	(void)atomic_fetch_add_explicit(&g_nameservers->generation, 1,
	    memory_order_seq_cst);
	atomic_store_explicit(&g_nameservers->count, (uint32_t)count,
	    memory_order_seq_cst);
	for (i = 0; i < sizeof(g_ns); i++)
		atomic_store_explicit(&g_nameservers->bytes[i], bytes[i],
		    memory_order_seq_cst);
	(void)atomic_fetch_add_explicit(&g_nameservers->generation, 1,
	    memory_order_seq_cst);
}

static int
nameservers_snapshot(union res_sockaddr_union *servers)
{
	unsigned char *bytes;
	uint32_t before, after, count;
	int attempt;
	size_t i;

	if (g_nameservers != NULL) {
		bytes = (unsigned char *)(void *)servers;
		for (attempt = 0; attempt < 64; attempt++) {
			before = atomic_load_explicit(&g_nameservers->generation,
			    memory_order_seq_cst);
			if ((before & 1) != 0)
				continue;
			count = atomic_load_explicit(&g_nameservers->count,
			    memory_order_seq_cst);
			if (count > RSLV_MAX_NS)
				break;
			for (i = 0; i < sizeof(g_ns); i++)
				bytes[i] = atomic_load_explicit(
				    &g_nameservers->bytes[i], memory_order_seq_cst);
			after = atomic_load_explicit(&g_nameservers->generation,
			    memory_order_seq_cst);
			if (before == after)
				return ((int)count);
		}
	}
	/* A dead writer cannot stall DNS forever; use the startup snapshot. */
	memcpy(servers, g_ns, sizeof(g_ns));
	return (g_nns);
}

static int
nameservers_share_init(void)
{
	int fd;
	void *mapping;

	fd = shm_open(SHM_ANON, O_RDWR | O_CLOEXEC, 0600);
	if (fd == -1)
		return (-1);
	if (ftruncate(fd, sizeof(*g_nameservers)) == -1) {
		(void)close(fd);
		return (-1);
	}
	mapping = mmap(NULL, sizeof(*g_nameservers), PROT_READ | PROT_WRITE,
	    MAP_SHARED, fd, 0);
	if (mapping == MAP_FAILED) {
		(void)close(fd);
		return (-1);
	}
	g_nameservers = mapping;
	g_nameservers_fd = fd;
	atomic_init(&g_nameservers->generation, 0);
	atomic_init(&g_nameservers->count, 0);
	nameservers_publish(g_ns, g_nns);
	return (0);
}

int
netresolve_worker_enter(void)
{
	cap_rights_t rights;
	void *mapping;

	if (g_nameservers == NULL)
		return (0);
	if (g_nameservers_fd == -1)
		return (0);
	cap_rights_init(&rights, CAP_MMAP_R);
	if (cap_rights_limit(g_nameservers_fd, &rights) == -1)
		return (-1);
	mapping = mmap(NULL, sizeof(*g_nameservers), PROT_READ, MAP_SHARED,
	    g_nameservers_fd, 0);
	if (mapping == MAP_FAILED)
		return (-1);
	(void)munmap(g_nameservers, sizeof(*g_nameservers));
	g_nameservers = mapping;
	(void)close(g_nameservers_fd);
	g_nameservers_fd = -1;
	return (0);
}

static int
nameservers_load(struct service_context *ctx,
    union res_sockaddr_union *servers, int *countp)
{
	char buf[8192];
	char *cursor, *line, *kw, *val, *save;
	ssize_t r;
	int fd, count;

	memset(servers, 0, sizeof(g_ns));
	*countp = 0;
	if (open_resolver_config(ctx, &fd) == -1)
		return (errno == ENOENT ? 0 : -1);
	do {
		r = pread(fd, buf, sizeof(buf) - 1, 0);
	} while (r == -1 && errno == EINTR);
	(void)close(fd);
	if (r == -1)
		return (-1);
	buf[r] = '\0';
	cursor = buf;
	count = 0;
	while ((line = strsep(&cursor, "\n")) != NULL &&
	    count < RSLV_MAX_NS) {
		kw = strtok_r(line, " \t", &save);
		if (kw == NULL || strcmp(kw, "nameserver") != 0)
			continue;
		val = strtok_r(NULL, " \t\r", &save);
		if (val == NULL)
			continue;
		memset(&servers[count], 0, sizeof(servers[count]));
		if (inet_pton(AF_INET, val,
		    &servers[count].sin.sin_addr) == 1) {
			servers[count].sin.sin_family = AF_INET;
			servers[count].sin.sin_len = sizeof(servers[count].sin);
			servers[count].sin.sin_port = htons(53);
			count++;
		} else if (inet_pton(AF_INET6, val,
		    &servers[count].sin6.sin6_addr) == 1) {
			servers[count].sin6.sin6_family = AF_INET6;
			servers[count].sin6.sin6_len = sizeof(servers[count].sin6);
			servers[count].sin6.sin6_port = htons(53);
			count++;
		}
	}
	*countp = count;
	return (0);
}

int
netresolve_refresh(struct service_context *ctx)
{
	union res_sockaddr_union servers[RSLV_MAX_NS];
	int count;

	if (ctx == NULL)
		return (errno = EINVAL, -1);
	if (nameservers_load(ctx, servers, &count) == -1)
		return (-1);
	if (count == g_nns && memcmp(servers, g_ns, sizeof(g_ns)) == 0)
		return (0);
	memcpy(g_ns, servers, sizeof(g_ns));
	g_nns = count;
	nameservers_publish(g_ns, g_nns);
	return (0);
}

/* =====================================================================
 * init
 * ===================================================================== */
int
netresolve_init(struct service_context *ctx)
{
	int shared_error;

	/*
	 * res_ninit sets up the query machinery (id, options, retrans/retry).
	 * Born in capability mode it cannot read /etc/resolv.conf (that open is
	 * denied), which is fine: the state is still initialized and we supply
	 * the nameservers ourselves below.
	 */
	(void)res_ninit(&g_res);

	/* Nameserver updates reach workers through the shared generation. */
	g_nns = 0;
	memset(g_ns, 0, sizeof(g_ns));
	shared_error = nameservers_share_init() == -1 ? errno : 0;
	(void)netresolve_refresh(ctx);

	/*
	 * hosts/services on demand through the filesystem provider (born in
	 * capability mode, no path open).  Best-effort: DNS and numeric literals
	 * still work without them.
	 */
	if (service_open_isolated(ctx, "/etc/hosts", SERVICE_OPEN_READ, 0,
	    &g_hostsfd) == -1)
		g_hostsfd = -1;
	if (service_open_isolated(ctx, "/etc/services", SERVICE_OPEN_READ, 0,
	    &g_servfd) == -1)
		g_servfd = -1;
	if (shared_error != 0)
		return (errno = shared_error, -1);
	return (0);
}

/* =====================================================================
 * small helpers
 * ===================================================================== */

/*
 * Snapshot an already-open descriptor into buf.  Reads up to bufsz-1 bytes
 * starting at file offset 0, NUL-terminates.  Returns bytes read (>=0) or -1
 * on error.  A file larger than the buffer is truncated to the prefix that
 * fits; this keeps the read strictly bounded.
 *
 * pread() with an explicit offset is used rather than lseek()+read(): the
 * per-connection workers are pdfork()'d children that inherit g_hostsfd /
 * g_servfd and therefore share the underlying file offset.  A stateful
 * lseek+read would race between concurrent workers; pread carries its own
 * offset and does not touch the shared one.
 */
static ssize_t
read_snapshot(int fd, char *buf, size_t bufsz)
{
	size_t off = 0;
	ssize_t n;

	if (fd < 0 || bufsz == 0)
		return (-1);
	while (off < bufsz - 1) {
		n = pread(fd, buf + off, bufsz - 1 - off, (off_t)off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (n == 0)
			break;
		off += (size_t)n;
	}
	buf[off] = '\0';
	return ((ssize_t)off);
}

/* Return non-zero if s is non-empty and all decimal digits. */
static int
all_digits(const char *s)
{

	if (s == NULL || *s == '\0')
		return (0);
	for (; *s != '\0'; s++)
		if (*s < '0' || *s > '9')
			return (0);
	return (1);
}

/* Strip an unquoted '#' comment in place. */
static void
strip_comment(char *line)
{
	char *h = strchr(line, '#');

	if (h != NULL)
		*h = '\0';
}

/* =====================================================================
 * service resolution
 * ===================================================================== */

/*
 * Resolve a service name for a specific protocol against the /etc/services
 * snapshot.  Returns port in host order (0..65535) or -1 if not found.
 */
static int
serv_lookup_file(const char *serv, const char *proto)
{
	static char buf[RSLV_SERV_BUFSZ];
	char *line, *lasts_line;
	ssize_t got;

	got = read_snapshot(g_servfd, buf, sizeof(buf));
	if (got < 0)
		return (-1);

	for (line = strtok_r(buf, "\n", &lasts_line); line != NULL;
	    line = strtok_r(NULL, "\n", &lasts_line)) {
		char *tok, *lasts_tok, *slash;
		char *name, *portproto;
		long portval;
		int matched;

		strip_comment(line);

		name = strtok_r(line, " \t\r", &lasts_tok);
		if (name == NULL)
			continue;
		portproto = strtok_r(NULL, " \t\r", &lasts_tok);
		if (portproto == NULL)
			continue;

		slash = strchr(portproto, '/');
		if (slash == NULL)
			continue;
		*slash = '\0';
		if (strcasecmp(slash + 1, proto) != 0)
			continue;
		if (!all_digits(portproto))
			continue;
		portval = strtol(portproto, NULL, 10);
		if (portval < 0 || portval > 65535)
			continue;

		/* Name matches the canonical entry name? */
		matched = (strcasecmp(name, serv) == 0);
		/* ...or any alias token remaining on the line? */
		while (!matched &&
		    (tok = strtok_r(NULL, " \t\r", &lasts_tok)) != NULL) {
			if (strcasecmp(tok, serv) == 0)
				matched = 1;
		}
		if (matched)
			return ((int)portval);
	}
	return (-1);
}

/*
 * Resolve serv for a given protocol into a host-order port.
 *   NULL          -> 0
 *   AI_NUMERICSERV/all-digits -> numeric value
 *   named         -> /etc/services lookup for that proto
 * Returns 0 and sets *port on success; -1 if the name is unknown for proto.
 */
static int
serv_port(const char *serv, int flags, const char *proto, uint16_t *port)
{
	long v;
	int p;

	if (serv == NULL) {
		*port = 0;
		return (0);
	}
	if ((flags & AI_NUMERICSERV) != 0 || all_digits(serv)) {
		if (!all_digits(serv))
			return (-1);	/* AI_NUMERICSERV but not numeric */
		v = strtol(serv, NULL, 10);
		if (v < 0 || v > 65535)
			return (-1);
		*port = (uint16_t)v;
		return (0);
	}
	p = serv_lookup_file(serv, proto);
	if (p < 0)
		return (-1);
	*port = (uint16_t)p;
	return (0);
}

/*
 * Build the set of (socktype,proto,port) tuples to emit, honoring the
 * requested socktype and the service name.  Returns the count (>=1), or
 * a negative EAI_* code.
 */
static int
build_portset(const char *serv, const struct addrinfo *hints,
    struct rslv_port out[2])
{
	int flags = hints ? hints->ai_flags : 0;
	int socktype = hints ? hints->ai_socktype : 0;
	int want_stream, want_dgram, n = 0;
	uint16_t port;

	want_stream = (socktype == 0 || socktype == SOCK_STREAM);
	want_dgram = (socktype == 0 || socktype == SOCK_DGRAM);

	if (want_stream && serv_port(serv, flags, "tcp", &port) == 0) {
		out[n].socktype = SOCK_STREAM;
		out[n].proto = IPPROTO_TCP;
		out[n].port = port;
		n++;
	}
	if (want_dgram && serv_port(serv, flags, "udp", &port) == 0) {
		out[n].socktype = SOCK_DGRAM;
		out[n].proto = IPPROTO_UDP;
		out[n].port = port;
		n++;
	}
	if (n == 0)
		return (-EAI_SERVICE);
	return (n);
}

/* =====================================================================
 * host resolution: /etc/hosts
 * ===================================================================== */

/*
 * Scan the /etc/hosts snapshot for lines whose canonical name or an alias
 * matches host (case-insensitive).  Appends matching addresses (respecting
 * the family filter) to addrs and, on the first match, copies the canonical
 * (first) name into canon.  Returns the number of addresses collected.
 */
static int
hosts_lookup(const char *host, int family, struct rslv_addr *addrs,
    int max, char *canon, size_t canonsz)
{
	static char buf[RSLV_HOSTS_BUFSZ];
	char *line, *lasts_line;
	ssize_t got;
	int n = 0;

	if (canonsz > 0)
		canon[0] = '\0';

	got = read_snapshot(g_hostsfd, buf, sizeof(buf));
	if (got < 0)
		return (0);

	for (line = strtok_r(buf, "\n", &lasts_line);
	    line != NULL && n < max;
	    line = strtok_r(NULL, "\n", &lasts_line)) {
		char *addrtok, *nametok, *lasts_tok;
		char *cname;
		struct rslv_addr ra;
		int matched = 0;

		strip_comment(line);

		addrtok = strtok_r(line, " \t\r", &lasts_tok);
		if (addrtok == NULL)
			continue;

		/* Parse the address literal, subject to the family filter. */
		memset(&ra, 0, sizeof(ra));
		if ((family == AF_UNSPEC || family == AF_INET) &&
		    inet_pton(AF_INET, addrtok, &ra.a.v4) == 1) {
			ra.family = AF_INET;
		} else if ((family == AF_UNSPEC || family == AF_INET6) &&
		    inet_pton(AF_INET6, addrtok, &ra.a.v6) == 1) {
			ra.family = AF_INET6;
		} else {
			continue;	/* wrong family or malformed literal */
		}

		cname = NULL;
		while ((nametok = strtok_r(NULL, " \t\r", &lasts_tok)) !=
		    NULL) {
			if (cname == NULL)
				cname = nametok;
			if (strcasecmp(nametok, host) == 0)
				matched = 1;
		}
		if (!matched)
			continue;

		if (canonsz > 0 && canon[0] == '\0' && cname != NULL) {
			strncpy(canon, cname, canonsz - 1);
			canon[canonsz - 1] = '\0';
		}
		addrs[n++] = ra;
	}
	return (n);
}

/* =====================================================================
 * host resolution: DNS over freshly-created sockets
 * ===================================================================== */

/*
 * Parse A or AAAA records owned by the question or its CNAME target.  Every
 * rdata access is bounds-checked and the result count is capped at max.
 * Returns addresses appended, or -1 for a malformed answer chain.
 */
static int
dns_parse(const u_char *ans, int anslen, const char *host, int want,
    struct rslv_addr *addrs, int max, int *n, char *canon, size_t canonsz)
{
	ns_msg msg;
	ns_rr rr;
	char owner[NS_MAXDNAME], target[NS_MAXDNAME];
	const u_char *rdata;
	size_t rdlen;
	int count, i, hops, consumed, added = 0;
	bool found;

	if (anslen <= 0)
		return (-1);
	if (ns_initparse(ans, anslen, &msg) < 0)
		return (-1);
	if (strlcpy(owner, host, sizeof(owner)) >= sizeof(owner))
		return (-1);

	count = ns_msg_count(msg, ns_s_an);
	/* Do not expose partial results from a malformed answer section. */
	for (i = 0; i < count; i++) {
		if (ns_parserr(&msg, ns_s_an, i, &rr) < 0)
			return (-1);
	}
	/* Resolve only CNAMEs reachable from the question, in any RR order. */
	for (hops = 0; hops <= RSLV_MAX_CNAME_HOPS; hops++) {
		found = false;
		for (i = 0; i < count; i++) {
			if (ns_parserr(&msg, ns_s_an, i, &rr) < 0)
				return (-1);
			if (ns_rr_class(rr) != ns_c_in ||
			    ns_rr_type(rr) != ns_t_cname ||
			    ns_samename(ns_rr_name(rr), owner) != 1)
				continue;
			if (found)
				return (-1);
			rdata = ns_rr_rdata(rr);
			rdlen = ns_rr_rdlen(rr);
			if (rdata < ans || rdata > ans + anslen ||
			    rdlen > (size_t)(ans + anslen - rdata))
				return (-1);
			consumed = ns_name_uncompress(ans, ans + anslen, rdata,
			    target, sizeof(target));
			if (consumed < 0 || (size_t)consumed != rdlen)
				return (-1);
			found = true;
		}
		if (!found)
			break;
		if (hops == RSLV_MAX_CNAME_HOPS ||
		    ns_samename(owner, target) == 1)
			return (-1);
		(void)strlcpy(owner, target, sizeof(owner));
	}
	/* Validate every matching address before exposing any of them. */
	for (i = 0; i < count; i++) {
		if (ns_parserr(&msg, ns_s_an, i, &rr) < 0)
			return (-1);
		if (ns_rr_class(rr) != ns_c_in ||
		    (int)ns_rr_type(rr) != want ||
		    ns_samename(ns_rr_name(rr), owner) != 1)
			continue;
		rdata = ns_rr_rdata(rr);
		rdlen = ns_rr_rdlen(rr);
		if (rdata < ans || rdata > ans + anslen ||
		    rdlen > (size_t)(ans + anslen - rdata) ||
		    rdlen != (want == ns_t_a ? 4 : 16))
			return (-1);
	}
	for (i = 0; i < count && *n < max; i++) {
		if (ns_parserr(&msg, ns_s_an, i, &rr) < 0)
			return (-1);
		if (ns_rr_class(rr) != ns_c_in ||
		    (int)ns_rr_type(rr) != want ||
		    ns_samename(ns_rr_name(rr), owner) != 1)
			continue;

		rdata = ns_rr_rdata(rr);
		rdlen = ns_rr_rdlen(rr);

		/* Defense in depth: rdata must lie fully inside the message. */
		if (rdata < ans || rdata > ans + anslen ||
		    rdlen > (size_t)(ans + anslen - rdata))
			return (-1);

		if (want == ns_t_a) {
			if (rdlen != 4)
				return (-1);
			addrs[*n].family = AF_INET;
			memset(&addrs[*n].a, 0, sizeof(addrs[*n].a));
			memcpy(&addrs[*n].a.v4, rdata, 4);
		} else {	/* ns_t_aaaa */
			if (rdlen != 16)
				return (-1);
			addrs[*n].family = AF_INET6;
			memset(&addrs[*n].a, 0, sizeof(addrs[*n].a));
			memcpy(&addrs[*n].a.v6, rdata, 16);
		}

		/* Owner name of the address record is the canonical name. */
		if (canonsz > 0 && canon[0] == '\0') {
			strncpy(canon, ns_rr_name(rr), canonsz - 1);
			canon[canonsz - 1] = '\0';
		}
		(*n)++;
		added++;
	}
	return (added);
}

/* Return -1 for an unrelated/invalid reply, -2 for a server error, 1 for
 * truncation, or 0 for a complete answer. */
static int
dns_reply_status(const u_char *ans, int anslen, const u_char *qbuf,
    const char *host, int rrtype)
{
	ns_msg msg;
	char qname[NS_MAXDNAME];
	int consumed, qend, rcode;

	if (anslen < NS_HFIXEDSZ || ans[0] != qbuf[0] ||
	    ans[1] != qbuf[1] || (ans[2] & 0x80) == 0 ||
	    (ans[2] & 0x78) != 0 || ans[4] != 0 || ans[5] != 1)
		return (-1);
	consumed = ns_name_uncompress(ans, ans + anslen,
	    ans + NS_HFIXEDSZ, qname, sizeof(qname));
	if (consumed < 0 || consumed > anslen - NS_HFIXEDSZ - 4)
		return (-1);
	qend = NS_HFIXEDSZ + consumed;
	if (ans[qend] != 0 || ans[qend + 1] != rrtype ||
	    ans[qend + 2] != 0 || ans[qend + 3] != ns_c_in ||
	    ns_samename(qname, host) != 1)
		return (-1);
	rcode = ans[3] & 0x0f;
	if (rcode != ns_r_noerror && rcode != ns_r_nxdomain)
		return (-2);
	/* A TC reply may end inside an RR, so only parse complete messages. */
	if ((ans[2] & 0x02) != 0)
		return (1);
	return (ns_initparse(ans, anslen, &msg) == 0 ? 0 : -1);
}

/* All TCP operations share one monotonic deadline, including connect. */
static int
dns_wait(int fd, short events, const struct timespec *deadline)
{
	struct timespec now;
	struct pollfd pfd;
	int64_t remaining, ms;
	int pr;

	pfd.fd = fd;
	pfd.events = events;
	for (;;) {
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
			return (-1);
		remaining = ((int64_t)deadline->tv_sec - now.tv_sec) *
		    1000000000 + deadline->tv_nsec - now.tv_nsec;
		if (remaining <= 0)
			return (-1);
		ms = (remaining + 999999) / 1000000;
		if (ms > INT_MAX)
			ms = INT_MAX;
		pfd.revents = 0;
		pr = poll(&pfd, 1, (int)ms);
		if (pr > 0)
			return ((pfd.revents & events) != 0 ? 0 : -1);
		if (pr < 0 && errno != EINTR)
			return (-1);
	}
}

static int
dns_tcp_transfer(int fd, u_char *buf, size_t len, bool sending,
    const struct timespec *deadline)
{
	size_t done = 0;
	ssize_t n;

	while (done < len) {
		if (dns_wait(fd, sending ? POLLOUT : POLLIN, deadline) == -1)
			return (-1);
		if (sending)
			n = send(fd, buf + done, len - done, MSG_NOSIGNAL);
		else
			n = recv(fd, buf + done, len - done, 0);
		if (n > 0) {
			done += (size_t)n;
			continue;
		}
		if (n == -1 && (errno == EINTR || errno == EAGAIN))
			continue;
		return (-1);
	}
	return (0);
}

/* DNS over TCP uses a two-byte length prefix in each direction. */
static int
dns_tcp_query(const struct sockaddr *sa, socklen_t salen, u_char *qbuf,
    int qlen, u_char *ans, int timeout)
{
	struct timespec deadline;
	u_char prefix[2];
	int s, error, len, result = -1;
	socklen_t errorlen;

	if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1)
		return (-1);
	deadline.tv_sec += timeout;
	s = socket(sa->sa_family, SOCK_STREAM, 0);
	if (s == -1)
		return (-1);
	if (fcntl(s, F_SETFL, O_NONBLOCK) == -1)
		goto done;
	if (connectat(s, s, sa, salen) == -1) {
		if (errno != EINPROGRESS ||
		    dns_wait(s, POLLOUT, &deadline) == -1)
			goto done;
		errorlen = sizeof(error);
		if (getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &errorlen) == -1 ||
		    error != 0)
			goto done;
	}
	prefix[0] = (u_char)(qlen >> 8);
	prefix[1] = (u_char)qlen;
	if (dns_tcp_transfer(s, prefix, sizeof(prefix), true, &deadline) == -1 ||
	    dns_tcp_transfer(s, qbuf, (size_t)qlen,
	    true, &deadline) == -1 ||
	    dns_tcp_transfer(s, prefix, sizeof(prefix), false, &deadline) == -1)
		goto done;
	len = ((int)prefix[0] << 8) | prefix[1];
	if (len < NS_HFIXEDSZ || len > NS_MAXMSG ||
	    dns_tcp_transfer(s, ans, (size_t)len, false, &deadline) == -1)
		goto done;
	result = len;
done:
	(void)close(s);
	return (result);
}

/*
 * Issue one DNS query of the given record type for host, trying each
 * configured nameserver with retransmission.  Appends results to addrs.
 * Returns the number of addresses added, or -1 if no server answered.
 */
static int
dns_query(const char *host, int rrtype, struct rslv_addr *addrs, int max,
    int *n, char *canon, size_t canonsz)
{
	union res_sockaddr_union srv[RSLV_MAX_NS];
	u_char qbuf[NS_PACKETSZ];
	u_char *ans;
	int nsrv, qlen, attempt, s, retrans, retry, added_total = 0;
	int answered = 0;

	/* Snapshot one complete nameserver generation for this query. */
	nsrv = nameservers_snapshot(srv);
	if (nsrv <= 0)
		return (-1);

	qlen = res_nmkquery(&g_res, ns_o_query, host, ns_c_in, rrtype, NULL,
	    0, NULL, qbuf, (int)sizeof(qbuf));
	if (qlen <= 0)
		return (-1);

	ans = malloc(NS_MAXMSG);
	if (ans == NULL)
		return (-1);

	retrans = g_res.retrans > 0 ? g_res.retrans : RSLV_DFL_RETRANS;
	if (retrans > RSLV_MAX_RETRANS)
		retrans = RSLV_MAX_RETRANS;
	retry = g_res.retry > 0 ? g_res.retry : RSLV_DFL_RETRY;

	for (attempt = 0; attempt < retry && !answered; attempt++) {
		int ns;

		for (ns = 0; ns < nsrv && !answered; ns++) {
			struct sockaddr *sa = (struct sockaddr *)&srv[ns];
			socklen_t salen;
			struct timespec deadline;
			ssize_t sent, rlen;
			int added, status;

			if (sa->sa_family == AF_INET)
				salen = sizeof(struct sockaddr_in);
			else if (sa->sa_family == AF_INET6)
				salen = sizeof(struct sockaddr_in6);
			else
				continue;

			s = socket(sa->sa_family, SOCK_DGRAM, 0);
			if (s < 0)
				continue;

			/*
			 * Born in capability mode: connect(2) and sendto(2) with
			 * an explicit destination address are not capmode-legal
			 * (the address is ambient authority).  connectat(2) IS,
			 * and for an INET datagram socket the kernel's soconnectat
			 * falls back to pr_connect (the dirfd is irrelevant, so
			 * pass the socket itself as a real, non-AT_FDCWD fd) --
			 * so connect the socket to the nameserver, then send and
			 * recv on the now-connected socket with no address.
			 */
			if (connectat(s, s, sa, salen) == -1) {
				(void)close(s);
				continue;
			}
			sent = send(s, qbuf, (size_t)qlen, 0);
			if (sent != qlen) {
				(void)close(s);
				continue;
			}

			if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1) {
				(void)close(s);
				continue;
			}
			deadline.tv_sec += retrans;
			status = -1;
			while (dns_wait(s, POLLIN, &deadline) == 0) {
				rlen = recv(s, ans, NS_MAXMSG, 0);
				if (rlen == -1 && errno == EINTR)
					continue;
				if (rlen <= 0)
					break;
				/* A stray reply must not discard this server's turn. */
				status = dns_reply_status(ans, (int)rlen, qbuf,
				    host, rrtype);
				if (status != -1)
					break;
			}

			(void)close(s);
			if (status < 0)
				continue;
			if (status == 1) {
				/* Truncated UDP data is never treated as an answer. */
				rlen = dns_tcp_query(sa, salen, qbuf, qlen, ans,
				    retrans);
				if (rlen < 0 || dns_reply_status(ans, (int)rlen,
				    qbuf, host, rrtype) != 0)
					continue;
			}
			if ((ans[3] & 0x0f) == ns_r_nxdomain) {
				answered = 1;
				continue;
			}

			added = dns_parse(ans, (int)rlen, host, rrtype, addrs, max,
			    n, canon, canonsz);
			if (added < 0)
				continue;	/* malformed: try next server */

			/*
			 * A well-formed response (even an empty answer, i.e.
			 * NODATA/NXDOMAIN) means this server spoke; stop
			 * retransmitting.
			 */
			answered = 1;
			added_total += added;
		}
	}

	free(ans);
	return (answered ? added_total : -1);
}

/*
 * AI_V4MAPPED support (RFC 3493).  Query A records for host and append each as
 * an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to addrs, which the caller then
 * emits as AF_INET6 results.  Returns the number appended (>=0).
 */
static int
dns_query_v4mapped(const char *host, struct rslv_addr *addrs, int max, int *n,
    char *canon, size_t canonsz)
{
	struct rslv_addr tmp[RSLV_MAX_RESULTS];
	int tn = 0, i, added = 0;

	(void)dns_query(host, ns_t_a, tmp, RSLV_MAX_RESULTS, &tn, canon, canonsz);
	for (i = 0; i < tn && *n < max; i++) {
		struct in6_addr mapped;

		if (tmp[i].family != AF_INET)
			continue;
		memset(&mapped, 0, sizeof(mapped));
		mapped.s6_addr[10] = 0xff;
		mapped.s6_addr[11] = 0xff;
		memcpy(&mapped.s6_addr[12], &tmp[i].a.v4, 4);
		addrs[*n].family = AF_INET6;
		memset(&addrs[*n].a, 0, sizeof(addrs[*n].a));
		addrs[*n].a.v6 = mapped;
		(*n)++;
		added++;
	}
	return (added);
}

/* =====================================================================
 * assembly
 * ===================================================================== */

static struct addrinfo *
make_node(const struct rslv_addr *ra, const struct rslv_port *pp)
{
	struct addrinfo *ai;

	ai = calloc(1, sizeof(*ai));
	if (ai == NULL)
		return (NULL);
	ai->ai_family = ra->family;
	ai->ai_socktype = pp->socktype;
	ai->ai_protocol = pp->proto;

	if (ra->family == AF_INET) {
		struct sockaddr_in *sin;

		sin = calloc(1, sizeof(*sin));
		if (sin == NULL) {
			free(ai);
			return (NULL);
		}
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(*sin);
		sin->sin_port = htons(pp->port);
		sin->sin_addr = ra->a.v4;
		ai->ai_addr = (struct sockaddr *)sin;
		ai->ai_addrlen = sizeof(*sin);
	} else {
		struct sockaddr_in6 *sin6;

		sin6 = calloc(1, sizeof(*sin6));
		if (sin6 == NULL) {
			free(ai);
			return (NULL);
		}
		sin6->sin6_family = AF_INET6;
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_port = htons(pp->port);
		sin6->sin6_scope_id = 0;
		sin6->sin6_addr = ra->a.v6;
		ai->ai_addr = (struct sockaddr *)sin6;
		ai->ai_addrlen = sizeof(*sin6);
	}
	return (ai);
}

/* =====================================================================
 * public entry points
 * ===================================================================== */

void
netfreeaddrinfo(struct addrinfo *res)
{
	struct addrinfo *ai, *next;

	for (ai = res; ai != NULL; ai = next) {
		next = ai->ai_next;
		free(ai->ai_canonname);
		free(ai->ai_addr);
		free(ai);
	}
}

int
netresolve(const char *host, const char *serv, const struct addrinfo *hints,
    struct addrinfo **res)
{
	struct rslv_addr addrs[RSLV_MAX_RESULTS];
	struct rslv_port ports[2];
	char canon[NS_MAXDNAME];
	struct addrinfo *head = NULL, *tail = NULL;
	int family, flags, nports, naddr = 0;
	int i, j, ret;

	if (res == NULL)
		return (EAI_FAIL);
	*res = NULL;
	canon[0] = '\0';

	family = hints ? hints->ai_family : AF_UNSPEC;
	flags = hints ? hints->ai_flags : 0;

	if (family != AF_UNSPEC && family != AF_INET && family != AF_INET6)
		return (EAI_FAMILY);
	if (hints != NULL && hints->ai_socktype != 0 &&
	    hints->ai_socktype != SOCK_STREAM &&
	    hints->ai_socktype != SOCK_DGRAM)
		return (EAI_SOCKTYPE);
	if (host == NULL && serv == NULL)
		return (EAI_NONAME);

	/* Service / port set (host-independent). */
	nports = build_portset(serv, hints, ports);
	if (nports < 0)
		return (-nports);

	/* ---- host resolution ---- */
	if (host == NULL) {
		/* Passive -> wildcard; otherwise loopback. */
		if (family == AF_UNSPEC || family == AF_INET) {
			addrs[naddr].family = AF_INET;
			memset(&addrs[naddr].a, 0, sizeof(addrs[naddr].a));
			addrs[naddr].a.v4.s_addr = (flags & AI_PASSIVE) ?
			    htonl(INADDR_ANY) : htonl(INADDR_LOOPBACK);
			naddr++;
		}
		if (family == AF_UNSPEC || family == AF_INET6) {
			struct in6_addr any = IN6ADDR_ANY_INIT;
			struct in6_addr lo = IN6ADDR_LOOPBACK_INIT;

			addrs[naddr].family = AF_INET6;
			memset(&addrs[naddr].a, 0, sizeof(addrs[naddr].a));
			addrs[naddr].a.v6 = (flags & AI_PASSIVE) ? any : lo;
			naddr++;
		}
	} else {
		struct in_addr v4;
		struct in6_addr v6;
		int is_numeric = 0;

		if ((family == AF_UNSPEC || family == AF_INET) &&
		    inet_pton(AF_INET, host, &v4) == 1) {
			addrs[naddr].family = AF_INET;
			memset(&addrs[naddr].a, 0, sizeof(addrs[naddr].a));
			addrs[naddr].a.v4 = v4;
			naddr++;
			is_numeric = 1;
		} else if ((family == AF_UNSPEC || family == AF_INET6) &&
		    inet_pton(AF_INET6, host, &v6) == 1) {
			addrs[naddr].family = AF_INET6;
			memset(&addrs[naddr].a, 0, sizeof(addrs[naddr].a));
			addrs[naddr].a.v6 = v6;
			naddr++;
			is_numeric = 1;
		}

		if (is_numeric) {
			if (flags & AI_CANONNAME) {
				strncpy(canon, host, sizeof(canon) - 1);
				canon[sizeof(canon) - 1] = '\0';
			}
		} else if (flags & AI_NUMERICHOST) {
			return (EAI_NONAME);
		} else {
			/* /etc/hosts first, then DNS. */
			naddr = hosts_lookup(host, family, addrs,
			    RSLV_MAX_RESULTS, canon, sizeof(canon));

			if (naddr == 0) {
				if (family == AF_UNSPEC ||
				    family == AF_INET)
					(void)dns_query(host, ns_t_a, addrs,
					    RSLV_MAX_RESULTS, &naddr, canon,
					    sizeof(canon));
				if (family == AF_UNSPEC ||
				    family == AF_INET6)
					(void)dns_query(host, ns_t_aaaa,
					    addrs, RSLV_MAX_RESULTS, &naddr,
					    canon, sizeof(canon));
				/*
				 * AI_V4MAPPED / AI_ALL (RFC 3493), meaningful
				 * only for an AF_INET6 query: when no native
				 * AAAA was found — or AI_ALL was also set —
				 * fetch A records and append them as
				 * IPv4-mapped IPv6.  AI_ADDRCONFIG is accepted
				 * but is a documented no-op here: this in-process
				 * resolver does not enumerate the host's own
				 * configured source families, so it never
				 * suppresses a family on that basis.
				 */
				if (family == AF_INET6 &&
				    (flags & AI_V4MAPPED) != 0 &&
				    (naddr == 0 || (flags & AI_ALL) != 0))
					(void)dns_query_v4mapped(host, addrs,
					    RSLV_MAX_RESULTS, &naddr, canon,
					    sizeof(canon));
			}

			if (naddr == 0)
				return (EAI_NONAME);

			/* Canonical name requested but numeric literal used. */
			if ((flags & AI_CANONNAME) == 0)
				canon[0] = '\0';
		}
	}

	if (naddr == 0)
		return (EAI_NONAME);

	/* ---- assemble the addrinfo list ---- */
	for (i = 0; i < naddr; i++) {
		for (j = 0; j < nports; j++) {
			struct addrinfo *node = make_node(&addrs[i], &ports[j]);

			if (node == NULL) {
				ret = EAI_MEMORY;
				goto fail;
			}
			if (head == NULL) {
				head = tail = node;
				if ((flags & AI_CANONNAME) &&
				    canon[0] != '\0') {
					node->ai_canonname = strdup(canon);
					if (node->ai_canonname == NULL) {
						/*
						 * head == node here; the fail
						 * label frees head, so freeing
						 * node too would double-free.
						 */
						ret = EAI_MEMORY;
						goto fail;
					}
				}
			} else {
				tail->ai_next = node;
				tail = node;
			}
		}
	}

	if (head == NULL)
		return (EAI_NONAME);
	*res = head;
	return (0);

fail:
	netfreeaddrinfo(head);
	*res = NULL;
	return (ret);
}
