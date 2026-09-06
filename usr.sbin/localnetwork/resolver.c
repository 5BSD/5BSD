/*
 * resolver.c - capability-mode-safe getaddrinfo(3) replacement for the
 * localnetwork daemon.
 *
 * The daemon's per-connection workers run under cap_enter(2); after that
 * point no path may be opened and libc getaddrinfo(3) is unusable (it opens
 * /etc/resolv.conf, /etc/hosts and /etc/services on demand).  netresolve_init()
 * is therefore called once BEFORE cap_enter: it parses resolv.conf via
 * res_ninit() and retains read-only descriptors for /etc/hosts and
 * /etc/services.  netresolve() then serves lookups in capability mode using
 * only those already-open descriptors, pure in-memory parsing, and freshly
 * created UDP sockets (socket/sendto/recvfrom/poll are all capability-mode
 * legal on a socket the process itself creates).
 *
 * This code parses untrusted DNS responses; every field is bounds-checked
 * before use and the number of collected results is capped.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/*
 * Nameservers parsed from the delivered /etc/resolv.conf.  Born in capability
 * mode, we cannot let res_ninit(3) read resolv.conf by path, so we parse it
 * ourselves and drive the query send loop from this list rather than
 * res_getservers(3) (which would read the res_state's own, unpopulated, list).
 */
static union res_sockaddr_union	g_ns[RSLV_MAX_NS];
static int			g_nns;

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

/* =====================================================================
 * init
 * ===================================================================== */
int
netresolve_init(struct service_context *ctx)
{
	char buf[8192];
	char *cursor, *line, *kw, *val, *save;
	ssize_t r;
	int fd;

	/*
	 * res_ninit sets up the query machinery (id, options, retrans/retry).
	 * Born in capability mode it cannot read /etc/resolv.conf (that open is
	 * denied), which is fine: the state is still initialized and we supply
	 * the nameservers ourselves below.
	 */
	(void)res_ninit(&g_res);

	/*
	 * Nameservers: parse the plane-delivered /etc/resolv.conf ourselves.
	 * Absent/unreadable -> no nameservers (DNS is skipped; /etc/hosts and
	 * numeric literals still resolve).
	 */
	g_nns = 0;
	if (service_open_isolated(ctx, "/etc/resolv.conf", SERVICE_OPEN_READ, 0,
	    &fd) == 0) {
		r = pread(fd, buf, sizeof(buf) - 1, 0);
		(void)close(fd);
		if (r > 0) {
			buf[r] = '\0';
			cursor = buf;
			while ((line = strsep(&cursor, "\n")) != NULL &&
			    g_nns < RSLV_MAX_NS) {
				kw = strtok_r(line, " \t", &save);
				if (kw == NULL || strcmp(kw, "nameserver") != 0)
					continue;
				val = strtok_r(NULL, " \t\r", &save);
				if (val == NULL)
					continue;
				memset(&g_ns[g_nns], 0, sizeof(g_ns[g_nns]));
				if (inet_pton(AF_INET, val,
				    &g_ns[g_nns].sin.sin_addr) == 1) {
					g_ns[g_nns].sin.sin_family = AF_INET;
					g_ns[g_nns].sin.sin_len =
					    sizeof(g_ns[g_nns].sin);
					g_ns[g_nns].sin.sin_port = htons(53);
					g_nns++;
				} else if (inet_pton(AF_INET6, val,
				    &g_ns[g_nns].sin6.sin6_addr) == 1) {
					g_ns[g_nns].sin6.sin6_family = AF_INET6;
					g_ns[g_nns].sin6.sin6_len =
					    sizeof(g_ns[g_nns].sin6);
					g_ns[g_nns].sin6.sin6_port = htons(53);
					g_nns++;
				}
			}
		}
	}

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
 * host resolution: DNS over freshly-created UDP sockets
 * ===================================================================== */

/*
 * Parse a DNS response (ans, anslen) collecting A (want ns_t_a) or AAAA
 * (want ns_t_aaaa) records into addrs.  Every rdata access is bounds-checked
 * against [ans, ans+anslen) and the result count is capped at max.  Returns
 * the number of addresses appended (>=0), or -1 if the message is malformed.
 */
static int
dns_parse(const u_char *ans, int anslen, int want, struct rslv_addr *addrs,
    int max, int *n, char *canon, size_t canonsz)
{
	ns_msg msg;
	ns_rr rr;
	int count, i, added = 0;

	if (anslen <= 0)
		return (-1);
	if (ns_initparse(ans, anslen, &msg) < 0)
		return (-1);

	count = ns_msg_count(msg, ns_s_an);
	for (i = 0; i < count && *n < max; i++) {
		const u_char *rdata;
		size_t rdlen;

		if (ns_parserr(&msg, ns_s_an, i, &rr) < 0)
			break;
		if ((int)ns_rr_type(rr) != want)
			continue;

		rdata = ns_rr_rdata(rr);
		rdlen = ns_rr_rdlen(rr);

		/* Defense in depth: rdata must lie fully inside the message. */
		if (rdata < ans || rdata > ans + anslen ||
		    rdlen > (size_t)(ans + anslen - rdata))
			continue;

		if (want == ns_t_a) {
			if (rdlen != 4)
				continue;
			addrs[*n].family = AF_INET;
			memset(&addrs[*n].a, 0, sizeof(addrs[*n].a));
			memcpy(&addrs[*n].a.v4, rdata, 4);
		} else {	/* ns_t_aaaa */
			if (rdlen != 16)
				continue;
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

	/* Nameservers come from the resolv.conf we parsed in netresolve_init. */
	if (g_nns <= 0)
		return (-1);
	nsrv = g_nns;
	memcpy(srv, g_ns, (size_t)nsrv * sizeof(srv[0]));

	qlen = res_nmkquery(&g_res, ns_o_query, host, ns_c_in, rrtype, NULL,
	    0, NULL, qbuf, (int)sizeof(qbuf));
	if (qlen <= 0)
		return (-1);

	ans = malloc(NS_MAXMSG);
	if (ans == NULL)
		return (-1);

	retrans = g_res.retrans > 0 ? g_res.retrans : RSLV_DFL_RETRANS;
	retry = g_res.retry > 0 ? g_res.retry : RSLV_DFL_RETRY;

	for (attempt = 0; attempt < retry && !answered; attempt++) {
		int ns;

		for (ns = 0; ns < nsrv && !answered; ns++) {
			struct sockaddr *sa = (struct sockaddr *)&srv[ns];
			socklen_t salen;
			struct pollfd pfd;
			ssize_t sent, rlen;
			int added, pr;

			if (sa->sa_family == AF_INET)
				salen = sizeof(struct sockaddr_in);
			else if (sa->sa_family == AF_INET6)
				salen = sizeof(struct sockaddr_in6);
			else
				continue;

			s = socket(sa->sa_family, SOCK_DGRAM, 0);
			if (s < 0)
				continue;

			sent = sendto(s, qbuf, (size_t)qlen, 0, sa, salen);
			if (sent != qlen) {
				(void)close(s);
				continue;
			}

			pfd.fd = s;
			pfd.events = POLLIN;
			pfd.revents = 0;
			pr = poll(&pfd, 1, retrans * 1000);
			if (pr <= 0 || (pfd.revents & POLLIN) == 0) {
				(void)close(s);
				continue;	/* timeout/error: next server */
			}

			rlen = recvfrom(s, ans, NS_MAXMSG, 0, NULL, NULL);
			(void)close(s);
			if (rlen <= 0)
				continue;

			added = dns_parse(ans, (int)rlen, rrtype, addrs, max,
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
						netfreeaddrinfo(node);
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
