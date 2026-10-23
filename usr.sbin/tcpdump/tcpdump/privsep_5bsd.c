/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * The privileged-operation interface of OpenBSD tcpdump(8) (privsep.h),
 * implemented in-process on top of the public libpcap API.
 *
 * OpenBSD splits tcpdump into a privileged parent and a chrooted child that
 * talk over a socket and build a pcap_t from a passed bpf(4) descriptor by
 * filling in libpcap's private structure.  5BSD's libpcap does not allow
 * that, so this file replaces privsep.c, privsep_pcap.c and
 * privsep_fdpass.c: every priv_*() call is served directly through
 * pcap_create(3), pcap_open_offline(3), pcap_compile(3) and the libc
 * resolvers.  The packet printers, output format and options are OpenBSD's
 * unchanged.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pcap.h>
#include <rpc/rpc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "interface.h"
#include "privsep.h"

#define	PF_OSFP_FILE	"/etc/pf.os"	/* sbin/pfctl/pfctl_parser.h */

int	priv_fd = -1;
volatile pid_t child_pid = -1;	/* no privileged process (privsep.c) */

static int	 priv_argc;
static char	**priv_argv;
static pcap_t	*priv_pcap;

extern void	set_slave_signals(void);
extern char	*read_infile(char *);
extern char	*copy_argv(char * const *);

__dead void
priv_exec(int argc __unused, char *argv[] __unused)
{
	errx(1, "-P is not supported");
}

int
priv_init(char *execpath __unused, int argc, char **argv)
{
	priv_argc = argc;
	priv_argv = argv;
	set_slave_signals();
	return (0);
}

void
priv_init_done(void)
{
}

/*
 * The filter expression comes from the command line (or -F file), as the
 * OpenBSD privileged process reads it.
 */
static char *
priv_filter_expression(void)
{
	char *infile = NULL;
	int ch, saved_optind, saved_opterr;

	saved_optind = optind;
	saved_opterr = opterr;
	optreset = 1;
	optind = 1;
	opterr = 0;
	while ((ch = getopt(priv_argc, priv_argv,
	    "AaB:c:D:deE:fF:i:IlLnNOopqr:s:StT:vw:xXy:")) != -1) {
		if (ch == 'F')
			infile = optarg;
	}
	ch = optind;
	optreset = 1;
	optind = saved_optind;
	opterr = saved_opterr;

	if (infile != NULL)
		return (read_infile(infile));
	return (copy_argv(&priv_argv[ch]));
}

struct bpf_program *
priv_pcap_setfilter(pcap_t *hpcap, int oflag, u_int32_t netmask)
{
	struct bpf_program *fcode;
	char *expr;

	if ((fcode = calloc(1, sizeof(*fcode))) == NULL) {
		snprintf(pcap_geterr(hpcap), PCAP_ERRBUF_SIZE,
		    "out of memory");
		return (NULL);
	}
	expr = priv_filter_expression();
	if (pcap_compile(hpcap, fcode, expr != NULL ? expr : "", oflag,
	    netmask) == -1 || pcap_setfilter(hpcap, fcode) == -1) {
		free(fcode);
		return (NULL);
	}
	return (fcode);
}

pcap_t *
priv_pcap_live(const char *dev, int slen, int prom, int to_ms,
    char *ebuf, u_int dlt, u_int dirfilt, u_int fildrop)
{
	pcap_t *p;

	if (dev == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "No interface specified");
		return (NULL);
	}
	if (fildrop != BPF_FILDROP_PASS) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
		    "-B: bpf(4) filter drop is not supported");
		return (NULL);
	}
	if ((p = pcap_create(dev, ebuf)) == NULL)
		return (NULL);
	/* As OpenBSD: pflog(4) headers need at least 160 bytes. */
	(void)pcap_set_snaplen(p, slen);
	(void)pcap_set_promisc(p, prom);
	(void)pcap_set_timeout(p, to_ms);
	(void)pcap_set_buffer_size(p, 32768);
	/*
	 * 5BSD: deliver packets as they arrive rather than when the bpf(4)
	 * buffer fills or the read timeout expires (FreeBSD tcpdump's
	 * --immediate-mode, which tests and scripts rely on).
	 */
	(void)pcap_set_immediate_mode(p, 1);
	if (pcap_activate(p) < 0)
		goto bad;
	if (dlt != (u_int)-1 && pcap_set_datalink(p, dlt) == -1)
		goto bad;
	if (pcap_datalink(p) == DLT_PFLOG && slen < 160) {
		pcap_close(p);
		return (priv_pcap_live(dev, 160, prom, to_ms, ebuf, dlt,
		    dirfilt, fildrop));
	}
	/* -D in filters out outgoing packets and vice versa. */
	if (dirfilt == BPF_DIRECTION_OUT) {
		if (pcap_setdirection(p, PCAP_D_IN) == -1)
			goto bad;
	} else if (dirfilt == BPF_DIRECTION_IN) {
		if (pcap_setdirection(p, PCAP_D_OUT) == -1)
			goto bad;
	}
	priv_pcap = p;
	return (p);
bad:
	snprintf(ebuf, PCAP_ERRBUF_SIZE, "%s: %s", dev, pcap_geterr(p));
	pcap_close(p);
	return (NULL);
}

pcap_t *
priv_pcap_offline(const char *fname, char *errbuf)
{
	return (pcap_open_offline(fname, errbuf));
}

pcap_dumper_t *
priv_pcap_dump_open(pcap_t *p, char *fname)
{
	return (pcap_dump_open(p, fname));
}

int
priv_pcap_stats(struct pcap_stat *ps)
{
	if (priv_pcap == NULL)
		return (-1);
	return (pcap_stats(priv_pcap, ps));
}

int
priv_open_pfosfp(void)
{
	int fd;

	if ((fd = open(PF_OSFP_FILE, O_RDONLY | O_CLOEXEC)) == -1)
		warn("%s", PF_OSFP_FILE);
	return (fd);
}

size_t
priv_gethostbyaddr(char *addr, size_t addr_len, int af, char *res,
    size_t res_len)
{
	struct hostent *hp;

	if ((hp = gethostbyaddr(addr, addr_len, af)) == NULL)
		return (0);
	return (strlcpy(res, hp->h_name, res_len) + 1);
}

size_t
priv_ether_ntohost(char *name, size_t name_len, struct ether_addr *e)
{
	char hostname[MAXHOSTNAMELEN + 1];

	if (ether_ntohost(hostname, e) != 0)
		return (0);
	return (strlcpy(name, hostname, name_len) + 1);
}

size_t
priv_getrpcbynumber(int rpc, char *progname, size_t progname_len)
{
	struct rpcent *re;

	if ((re = getrpcbynumber(rpc)) == NULL)
		return (0);
	return (strlcpy(progname, re->r_name, progname_len) + 1);
}

void
priv_getserventries(void)
{
	setservent(1);
}

size_t
priv_getserventry(char *name, size_t name_len, int *port, char *prot,
    size_t prot_len)
{
	struct servent *sp;

	if ((sp = getservent()) == NULL) {
		endservent();
		return (0);
	}
	strlcpy(name, sp->s_name, name_len);
	*port = sp->s_port;
	return (strlcpy(prot, sp->s_proto, prot_len) + 1);
}

void
priv_getprotoentries(void)
{
	setprotoent(1);
}

size_t
priv_getprotoentry(char *name, size_t name_len, int *num)
{
	struct protoent *pe;

	if ((pe = getprotoent()) == NULL) {
		endprotoent();
		return (0);
	}
	strlcpy(name, pe->p_name, name_len);
	*num = pe->p_proto;
	return (1);
}

struct tm *
priv_localtime(const time_t *t)
{
	return (localtime(t));
}

/* OpenBSD getexecpath(): only needed to re-exec the privileged part. */
int
getexecpath(char *buf, size_t len)
{
	if (len == 0)
		return (-1);
	buf[0] = '\0';
	return (0);
}
