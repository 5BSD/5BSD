/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux inet_diag wire ABI for NETLINK_SOCK_DIAG. */
#include "opt_inet.h"
#include "opt_inet6.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/ucred.h>
#include <sys/proc.h>
#include <sys/un.h>
#include <sys/unpcb.h>
#include <net/vnet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_fsm.h>
#include <netinet/cc/cc.h>
#include <netinet6/ip6_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netlink/netlink.h>
#include <netlink/netlink_ctl.h>
#include <netlink/netlink_var.h>

#define DIAG_BY_FAMILY 20
#define DIAG_INET 2
#define DIAG_INET6 10
#define DIAG_MAX_ROWS 131072

struct diag_id {
	uint16_t sport, dport;
	uint32_t src[4], dst[4], ifindex, cookie[2];
};
struct diag_req {
	uint8_t family, protocol, extensions, pad;
	uint32_t states;
	struct diag_id id;
};
struct diag_msg {
	uint8_t family, state, timer, retrans;
	struct diag_id id;
	uint32_t expires, rqueue, wqueue, uid, inode;
};
CTASSERT(sizeof(struct diag_req) == 56);
CTASSERT(sizeof(struct diag_msg) == 72);

#if defined(INET) || defined(INET6)
/* Stable Linux TCP_INFO prefix, through tcpi_total_retrans. */
struct diag_tcp_info {
	uint8_t state, ca_state, retransmits, probes, backoff, options, wscale, flags;
	uint32_t rto, ato, snd_mss, rcv_mss, unacked, sacked, lost, retrans, fackets;
	uint32_t last_data_sent, last_ack_sent, last_data_recv, last_ack_recv;
	uint32_t pmtu, rcv_ssthresh, rtt, rttvar, snd_ssthresh, snd_cwnd;
	uint32_t advmss, reordering, rcv_rtt, rcv_space, total_retrans;
};
CTASSERT(sizeof(struct diag_tcp_info) == 104);
struct inet_diag_row {
	struct diag_msg msg;
	struct diag_tcp_info info;
	uint32_t memory[9], meminfo[4];
	char congestion[16];
	uint8_t tos, tclass, shutdown;
	bool full, tcp, automatic;
};

/* Forward-only inet_diag predicates; validate all targets before taking locks. */
struct diag_bc_op {
	uint8_t code, yes;
	uint16_t no;
};
struct diag_hostcond {
	uint8_t family, prefix;
	uint16_t pad;
	int32_t port;
};
struct diag_filter {
	const uint8_t *code;
	size_t length;
};

static int
sock_diag_validate_filter(const struct diag_filter *filter)
{
	struct diag_bc_op op;
	struct diag_hostcond host;
	bool *boundary;
	size_t off, need, address;
	int error = EINVAL;

	if (filter->length < sizeof(op))
		return (EINVAL);
	boundary = mallocarray(filter->length + 1, sizeof(*boundary),
	    M_TEMP, M_WAITOK | M_ZERO);
	for (off = 0; off < filter->length; off += op.yes) {
		if (filter->length - off < sizeof(op))
			goto out;
		memcpy(&op, filter->code + off, sizeof(op));
		need = sizeof(op);
		switch (op.code) {
		case 0: case 1: case 6:
			break;
		case 2: case 3: case 4: case 5: case 9: case 11: case 12:
			need += 4;
			break;
		case 7: case 8:
			need += sizeof(host);
			if (filter->length - off < need)
				goto out;
			memcpy(&host, filter->code + off + sizeof(op), sizeof(host));
			if (host.family == 0)
				address = 0;
			else if (host.family == DIAG_INET)
				address = 4;
			else if (host.family == DIAG_INET6)
				address = 16;
			else
				goto out;
			if (host.prefix > address * 8)
				goto out;
			need += address;
			break;
		case 10: case 13:
			/* Linux marks and cgroup membership have no native counterpart. */
			error = EOPNOTSUPP;
			goto out;
		default:
			goto out;
		}
		if (need > filter->length - off || op.yes < need ||
		    op.yes > filter->length - off || (op.yes & 3) != 0)
			goto out;
		if (op.code != 0 && (op.no < need ||
		    op.no > filter->length - off + 4 || (op.no & 3) != 0))
			goto out;
		boundary[off] = true;
	}
	boundary[filter->length] = true;
	for (off = 0; off < filter->length; off += op.yes) {
		memcpy(&op, filter->code + off, sizeof(op));
		if (op.code != 0 && off + op.no <= filter->length &&
		    !boundary[off + op.no])
			goto out;
	}
	error = 0;
out:
	free(boundary, M_TEMP);
	return (error);
}

static int
sock_diag_parse_filter(struct nlmsghdr *hdr, struct diag_req *req,
    struct diag_filter *filter, bool dump)
{
	const uint8_t *data = (const uint8_t *)(hdr + 1) + sizeof(*req);
	size_t left = hdr->nlmsg_len - sizeof(*hdr) - sizeof(*req), step;
	struct nlattr attr;
	uint32_t protocol;

	bzero(filter, sizeof(*filter));
	while (left != 0) {
		if (left < sizeof(attr))
			return (EINVAL);
		memcpy(&attr, data, sizeof(attr));
		if (attr.nla_len < sizeof(attr) || attr.nla_len > left)
			return (EINVAL);
		step = roundup2(attr.nla_len, 4);
		if (step > left)
			return (EINVAL);
		switch (attr.nla_type & 0x3fff) {
		case 1:
			filter->code = data + sizeof(attr);
			filter->length = attr.nla_len - sizeof(attr);
			break;
		case 2:
			return (EOPNOTSUPP);
		case 3:
			if (attr.nla_len != sizeof(attr) + sizeof(protocol))
				return (EINVAL);
			memcpy(&protocol, data + sizeof(attr), sizeof(protocol));
			if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
				return (EPROTONOSUPPORT);
			req->protocol = protocol;
			break;
		}
		left -= step;
		data += step;
	}
	return (dump && filter->code != NULL ?
	    sock_diag_validate_filter(filter) : 0);
}

static bool
sock_diag_prefix(const uint8_t *left, const uint8_t *right, uint8_t bits)
{
	size_t bytes = bits / 8;

	return (memcmp(left, right, bytes) == 0 &&
	    ((bits & 7) == 0 ||
	    ((left[bytes] ^ right[bytes]) & (0xff << (8 - (bits & 7)))) == 0));
}

static bool
sock_diag_filter(const struct diag_filter *filter,
    const struct inet_diag_row *row)
{
	struct diag_bc_op op;
	struct diag_hostcond host;
	const uint8_t *argument, *address;
	size_t off = 0;
	uint16_t port, wanted;
	uint32_t device;
	bool yes;

	if (filter->code == NULL)
		return (true);
	while (off < filter->length) {
		memcpy(&op, filter->code + off, sizeof(op));
		argument = filter->code + off + sizeof(op);
		yes = true;
		switch (op.code) {
		case 0:
			break;
		case 1:
			yes = false;
			break;
		case 2: case 3: case 4: case 5: case 11: case 12:
			port = ntohs(op.code == 2 || op.code == 3 || op.code == 11 ?
			    row->msg.id.sport : row->msg.id.dport);
			memcpy(&wanted, argument + 2, sizeof(wanted));
			yes = op.code == 2 || op.code == 4 ? port >= wanted :
			    op.code == 3 || op.code == 5 ? port <= wanted : port == wanted;
			break;
		case 6:
			yes = row->automatic;
			break;
		case 7: case 8:
			memcpy(&host, argument, sizeof(host));
			port = ntohs(op.code == 7 ? row->msg.id.sport : row->msg.id.dport);
			if (host.port != -1 && host.port != port) {
				yes = false;
				break;
			}
			address = (const uint8_t *)(op.code == 7 ?
			    row->msg.id.src : row->msg.id.dst);
			if (host.family != 0 && host.family != row->msg.family) {
				static const uint8_t mapped[12] = { 0,0,0,0,0,0,0,0,0,0,255,255 };
				if (host.family != DIAG_INET || row->msg.family != DIAG_INET6 ||
				    memcmp(address, mapped, sizeof(mapped)) != 0) {
					yes = false;
					break;
				}
				address += 12;
			}
			yes = sock_diag_prefix(address, argument + sizeof(host), host.prefix);
			break;
		case 9:
			memcpy(&device, argument, sizeof(device));
			yes = device == row->msg.id.ifindex;
			break;
		}
		off += yes ? op.yes : op.no;
	}
	return (off == filter->length);
}

static void
sock_diag_extensions(struct inpcb *inp, struct inet_diag_row *row)
{
	struct socket *so = inp->inp_socket;
	struct xsocket xs;
	struct tcp_info ti;
	struct tcpcb *tp;
	struct diag_tcp_info *info = &row->info;
	uint32_t mss, unacked;

	if (so == NULL)
		return;
	row->full = true;
	sotoxsocket(so, &xs);
	row->memory[0] = xs.so_rcv.sb_mbcnt;
	row->memory[1] = xs.so_rcv.sb_hiwat;
	row->memory[2] = xs.so_snd.sb_mbcnt;
	row->memory[3] = xs.so_snd.sb_hiwat;
	row->memory[5] = xs.so_snd.sb_mbcnt;
	row->meminfo[0] = row->memory[0];
	row->meminfo[1] = row->memory[5];
	row->meminfo[3] = row->memory[2];
	SOCK_LOCK(so);
	if (SOLISTENING(so)) {
		row->memory[1] = so->sol_sbrcv_hiwat;
		row->memory[3] = so->sol_sbsnd_hiwat;
	} else {
		SOCKBUF_LOCK(&so->so_rcv);
		row->shutdown = (so->so_rcv.sb_state & SBS_CANTRCVMORE) ? 1 : 0;
		SOCKBUF_UNLOCK(&so->so_rcv);
		SOCKBUF_LOCK(&so->so_snd);
		if (so->so_snd.sb_state & SBS_CANTSENDMORE)
			row->shutdown |= 2;
		SOCKBUF_UNLOCK(&so->so_snd);
	}
	SOCK_UNLOCK(so);
	row->tos = inp->inp_ip_tos;
#ifdef INET6
	if (row->msg.family == DIAG_INET6 && inp->in6p_outputopts != NULL &&
	    inp->in6p_outputopts->ip6po_tclass >= 0)
		row->tclass = inp->in6p_outputopts->ip6po_tclass;
#endif
	if (!row->tcp)
		return;
	tp = intotcpcb(inp);
	tcp_fill_info(tp, &ti);
	info->state = row->msg.state;
	info->backoff = MIN(tp->t_rxtshift, UINT8_MAX);
	info->options = ti.tcpi_options & (TCPI_OPT_TIMESTAMPS | TCPI_OPT_SACK |
	    TCPI_OPT_WSCALE | TCPI_OPT_ECN);
	if (ti.tcpi_options & TCPI_OPT_TFO)
		info->options |= 32;
	info->wscale = ti.tcpi_snd_wscale | (ti.tcpi_rcv_wscale << 4);
	info->rto = ti.tcpi_rto;
	info->snd_mss = ti.tcpi_snd_mss;
	info->rcv_mss = ti.tcpi_rcv_mss;
	info->last_data_recv = ti.tcpi_last_data_recv / 1000;
	info->rtt = ti.tcpi_rtt;
	info->rttvar = ti.tcpi_rttvar;
	mss = ti.tcpi_snd_mss;
	if (mss != 0) {
		info->snd_ssthresh = ti.tcpi_snd_ssthresh / mss +
		    (ti.tcpi_snd_ssthresh % mss != 0);
		info->snd_cwnd = ti.tcpi_snd_cwnd / mss +
		    (ti.tcpi_snd_cwnd % mss != 0);
		unacked = ti.tcpi_snd_max - ti.tcpi_snd_una;
		info->unacked = unacked / mss + (unacked % mss != 0);
	}
	info->rcv_space = ti.tcpi_rcv_space;
	info->total_retrans = ti.tcpi_snd_rexmitpack;
	if (tp->t_cc != NULL)
		strlcpy(row->congestion, strcmp(tp->t_cc->name, "newreno") == 0 ?
		    "reno" : tp->t_cc->name, sizeof(row->congestion));
}

static bool
sock_diag_add_extensions(struct nl_writer *nw, uint8_t ext,
    const struct inet_diag_row *row)
{
	if (!row->full)
		return (true);
	return (nlattr_add_u8(nw, 8, row->shutdown) &&
	    (!(ext & 1) || nlattr_add(nw, 1, sizeof(row->meminfo), row->meminfo)) &&
	    (!(ext & 2) || !row->tcp ||
	    nlattr_add(nw, 2, sizeof(row->info), &row->info)) &&
	    (!(ext & 8) || row->congestion[0] == '\0' ||
	    nlattr_add(nw, 4, strlen(row->congestion) + 1, row->congestion)) &&
	    (!(ext & 16) || nlattr_add_u8(nw, 5, row->tos)) &&
	    (!(ext & 32) || row->msg.family != DIAG_INET6 ||
	    nlattr_add_u8(nw, 6, row->tclass)) &&
	    (!(ext & 64) || nlattr_add(nw, 7, sizeof(row->memory), row->memory)));
}

static void
sock_diag_fill(struct inpcb *inp, bool tcp, struct diag_msg *row)
{
	static const uint8_t states[] = { 7, 10, 2, 3, 1, 8, 4, 11, 9, 5, 6 };
	struct xtcpcb xt;
	struct xinpcb xi, *x;
	struct xsocket *so;

	bzero(row, sizeof(*row));
	if (tcp) {
		tcp_inptoxtp(inp, &xt);
		x = &xt.xt_inp;
		row->state = xt.t_state >= 0 && xt.t_state < nitems(states) ?
		    states[xt.t_state] : 7;
		if (row->state == 6) {
			row->timer = 3;
			row->expires = MAX(xt.tt_2msl, 0);
		} else if (xt.tt_rexmt > 0) {
			row->timer = 1;
			row->expires = xt.tt_rexmt;
		} else if (xt.tt_persist > 0) {
			row->timer = 4;
			row->expires = xt.tt_persist;
		} else if (xt.tt_keep > 0) {
			row->timer = 2;
			row->expires = xt.tt_keep;
		} else if (xt.tt_2msl > 0) {
			row->timer = row->state == 6 ? 3 : 2;
			row->expires = xt.tt_2msl;
		}
		row->retrans = row->state == 6 ? 0 :
		    MIN(intotcpcb(inp)->t_rxtshift, UINT8_MAX);
	} else {
		in_pcbtoxinpcb(inp, &xi);
		x = &xi;
		row->state = (xi.xi_socket.so_state & SS_ISCONNECTED) ? 1 : 7;
	}
	so = &x->xi_socket;
	row->family = (inp->inp_vflag & INP_IPV6PROTO) ? DIAG_INET6 : DIAG_INET;
	row->id.sport = x->inp_inc.inc_lport;
	row->id.dport = x->inp_inc.inc_fport;
	if (row->family == DIAG_INET6) {
		if (x->inp_vflag & INP_IPV6) {
			memcpy(row->id.src, &x->inp_inc.inc6_laddr, 16);
			memcpy(row->id.dst, &x->inp_inc.inc6_faddr, 16);
		} else {
			row->id.src[2] = row->id.dst[2] = htonl(0xffff);
			row->id.src[3] = x->inp_inc.inc_laddr.s_addr;
			row->id.dst[3] = x->inp_inc.inc_faddr.s_addr;
		}
	} else {
		row->id.src[0] = x->inp_inc.inc_laddr.s_addr;
		row->id.dst[0] = x->inp_inc.inc_faddr.s_addr;
	}
	row->id.cookie[0] = inp->inp_gencnt;
	row->id.cookie[1] = inp->inp_gencnt >> 32;
	row->inode = tcp && row->state == 6 ? 0 : so->xso_gen;
	row->uid = tcp && row->state == 6 ? 0 : inp->inp_cred->cr_uid;
	row->rqueue = tcp && row->state == 10 ? so->so_qlen : so->so_rcv.sb_cc;
	row->wqueue = tcp && row->state == 10 ? so->so_qlimit : so->so_snd.sb_cc;
	if (tcp && row->state == 6)
		row->rqueue = row->wqueue = 0;
}

static bool
sock_diag_match(const struct diag_req *req, const struct diag_msg *row,
    bool dump)
{
	if (req->family != 0 && req->family != row->family)
		return (false);
	if (dump)
		return ((req->states & (1U <<
		    (req->protocol == IPPROTO_TCP && row->state == 7 ? 13 : row->state))) != 0 &&
		    (req->id.sport == 0 || req->id.sport == row->id.sport) &&
		    (req->id.dport == 0 || req->id.dport == row->id.dport));
	return (req->id.sport == row->id.sport &&
	    req->id.dport == row->id.dport &&
	    memcmp(req->id.src, row->id.src, sizeof(row->id.src)) == 0 &&
	    memcmp(req->id.dst, row->id.dst, sizeof(row->id.dst)) == 0);
}

/* Copy under PCB locks, then release all locks before allocating replies. */
static int
sock_diag_snapshot(const struct diag_req *req, struct ucred *cred, bool dump,
    const struct diag_filter *filter, struct inet_diag_row **result, size_t *count)
{
	struct inpcbinfo *info = req->protocol == IPPROTO_TCP ? &V_tcbinfo : &V_udbinfo;
	struct inpcb *inp;
	struct inet_diag_row row, *rows;
	size_t capacity, n;
	bool overflow;

	capacity = MIN((size_t)info->ipi_count + 64, DIAG_MAX_ROWS);
	for (int attempt = 0; attempt < 4; attempt++) {
		struct inpcb_iterator iter = INP_ALL_ITERATOR(info, INPLOOKUP_RLOCKPCB);
		rows = mallocarray(capacity, sizeof(*rows), M_TEMP, M_WAITOK);
		n = 0;
		overflow = false;
		while ((inp = inp_next(&iter)) != NULL) {
			if (inp->inp_lport == 0 || cr_canseeinpcb(cred, inp) != 0 ||
			    (inp->inp_socket == NULL && (req->protocol != IPPROTO_TCP ||
			    intotcpcb(inp)->t_state != TCPS_TIME_WAIT)))
				continue;
			bzero(&row, sizeof(row));
			row.tcp = req->protocol == IPPROTO_TCP;
			row.automatic = (inp->inp_flags & INP_ANONPORT) != 0;
			sock_diag_fill(inp, row.tcp, &row.msg);
			if (!sock_diag_match(req, &row.msg, dump) ||
			    (dump && !sock_diag_filter(filter, &row)))
				continue;
			sock_diag_extensions(inp, &row);
			if (n == capacity)
				overflow = true;
			else
				rows[n++] = row;
		}
		if (!overflow) {
			*result = rows;
			*count = n;
			return (0);
		}
		free(rows, M_TEMP);
		if (capacity == DIAG_MAX_ROWS)
			return (E2BIG);
		capacity = MIN(capacity * 2, DIAG_MAX_ROWS);
	}
	return (EAGAIN);
}
#endif

/* Linux UNIX_DIAG uses a different request and reply layout from inet_diag. */
struct unix_diag_req {
	uint8_t family, protocol;
	uint16_t pad;
	uint32_t states, inode, show, cookie[2];
};
struct unix_diag_msg {
	uint8_t family, type, state, pad;
	uint32_t inode, cookie[2];
};
CTASSERT(sizeof(struct unix_diag_req) == 24);
CTASSERT(sizeof(struct unix_diag_msg) == 16);

static int
sock_diag_unix(struct nlmsghdr *hdr, struct nl_pstate *npt)
{
	struct unix_diag_req req;
	struct unix_diag_msg msg;
	uint32_t vfs[2], maj, min, *icons;
	struct unp_diag *rows, *row;
	size_t count, i;
	bool dump, found;
	int error;

	if (hdr->nlmsg_len < sizeof(*hdr) + sizeof(req))
		return (EINVAL);
	memcpy(&req, hdr + 1, sizeof(req));
	if (hdr->nlmsg_len != sizeof(*hdr) + sizeof(req))
		return (EOPNOTSUPP);
	dump = (hdr->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP;
	if (!dump && req.inode == 0)
		return (EINVAL);
	error = unp_diag_snapshot(nlp_get_cred(npt->nlp), (req.show & 2) != 0,
	    (req.show & 8) != 0, &rows, &count, &icons);
	if (error != 0)
		return (error);
	found = false;
	for (i = 0; i < count; i++) {
		row = &rows[i];
		if ((row->state & (SQ_COMP | SQ_INCOMP)) != 0)
			continue;
		bzero(&msg, sizeof(msg));
		msg.family = 1;
		msg.type = row->type == SOCK_SEQPACKET ? 5 : row->type;
		msg.state = row->listening ? 10 :
		    (row->state & SS_ISCONNECTED) != 0 ? 1 : 7;
		msg.inode = row->id;
		msg.cookie[0] = row->id;
		msg.cookie[1] = row->id >> 32;
		if (dump) {
			if ((req.states & (1U << msg.state)) == 0)
				continue;
		} else {
			if (req.inode != msg.inode)
				continue;
			if (!(req.cookie[0] == UINT32_MAX && req.cookie[1] == UINT32_MAX) &&
			    memcmp(req.cookie, msg.cookie, sizeof(req.cookie)) != 0) {
				error = ESTALE;
				break;
			}
		}
		found = true;
		if (row->icon_count > (UINT16_MAX - sizeof(struct nlattr)) / sizeof(uint32_t)) {
			error = E2BIG;
			break;
		}
		if (!nlmsg_add(npt->nw, hdr->nlmsg_pid, hdr->nlmsg_seq,
		    DIAG_BY_FAMILY, dump ? NLM_F_MULTI : 0, sizeof(msg))) {
			error = ENOMEM;
			break;
		}
		memcpy(nlmsg_reserve_object(npt->nw, struct unix_diag_msg), &msg, sizeof(msg));
		vfs[0] = row->vfs_ino;
		maj = major(row->vfs_dev);
		min = minor(row->vfs_dev);
		/* UNIX_DIAG_VFS exposes Linux kernel dev_t (12:20), not stat encoding. */
		vfs[1] = ((maj & 0xfff) << 20) | (min & 0xfffff);

		if (((req.show & 1) != 0 && row->namelen != 0 &&
		    !nlattr_add(npt->nw, 0, row->namelen, row->name)) ||
		    ((req.show & 2) != 0 && row->has_vfs &&
		    !nlattr_add(npt->nw, 1, sizeof(vfs), vfs)) ||
		    ((req.show & 4) != 0 && row->has_peer &&
		    !nlattr_add_u32(npt->nw, 2, row->peer)) ||
		    ((req.show & 8) != 0 && row->listening &&
		    !nlattr_add(npt->nw, 3, row->icon_count * sizeof(uint32_t),
		    row->icon_count != 0 ? &icons[row->icon_offset] : NULL)) ||
		    ((req.show & 16) != 0 &&
		    !nlattr_add(npt->nw, 4, 2 * sizeof(uint32_t), &row->rqueue)) ||
		    ((req.show & 32) != 0 &&
		    !nlattr_add(npt->nw, 5, sizeof(row->memory), row->memory)) ||
		    !nlattr_add_u8(npt->nw, 6, row->shutdown) ||
		    ((req.show & 64) != 0 && !nlattr_add_u32(npt->nw, 7, row->uid))) {
			nlmsg_abort(npt->nw);
			error = ENOMEM;
			break;
		}
		if (!nlmsg_end(npt->nw)) {
			error = ENOMEM;
			break;
		}
		if (!dump)
			break;
	}
	free(icons, M_TEMP);
	free(rows, M_TEMP);
	if (!dump && !found && error == 0)
		error = ENOENT;
	if (dump && !nlmsg_end_dump(npt->nw, error, hdr))
		return (ENOMEM);
	return (error);
}

static int
sock_diag_handle(struct nlmsghdr *hdr, struct nl_pstate *npt)
{
	if (hdr->nlmsg_type != DIAG_BY_FAMILY)
		return (EOPNOTSUPP);
	if (hdr->nlmsg_len < sizeof(*hdr) + 2)
		return (EINVAL);
	if (*(const uint8_t *)(hdr + 1) == 1)
		return (sock_diag_unix(hdr, npt));
#if defined(INET) || defined(INET6)
	struct diag_req req;
	struct diag_filter filter;
	struct inet_diag_row *rows;
	size_t count, i;
	bool dump;
	int error;

	if (hdr->nlmsg_type != DIAG_BY_FAMILY)
		return (EOPNOTSUPP);
	if (hdr->nlmsg_len < sizeof(*hdr) + sizeof(req))
		return (EINVAL);
	memcpy(&req, hdr + 1, sizeof(req));
	dump = (hdr->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP;
	error = sock_diag_parse_filter(hdr, &req, &filter, dump);
	if (error != 0)
		return (error);
	if (req.family != DIAG_INET && req.family != DIAG_INET6 &&
	    !(dump && req.family == 0))
		return (EAFNOSUPPORT);
	if (req.protocol != IPPROTO_TCP && req.protocol != IPPROTO_UDP)
		return (EPROTONOSUPPORT);
#ifndef INET
	if (req.family == DIAG_INET)
		return (EAFNOSUPPORT);
#endif
#ifndef INET6
	if (req.family == DIAG_INET6)
		return (EAFNOSUPPORT);
#endif
	/* Linux UDP exact queries historically reverse the endpoint tuple. */
	if (!dump && req.protocol == IPPROTO_UDP) {
		uint16_t port = req.id.sport;
		uint32_t addr[4];
		req.id.sport = req.id.dport;
		req.id.dport = port;
		memcpy(addr, req.id.src, sizeof(addr));
		memcpy(req.id.src, req.id.dst, sizeof(addr));
		memcpy(req.id.dst, addr, sizeof(addr));
	}
	error = sock_diag_snapshot(&req, nlp_get_cred(npt->nlp), dump, &filter, &rows, &count);
	if (error != 0)
		return (error);
	if (!dump && count == 0) {
		free(rows, M_TEMP);
		return (ENOENT);
	}
	if (!dump) {
		for (i = 0; i < count; i++)
			if ((req.id.cookie[0] == UINT32_MAX && req.id.cookie[1] == UINT32_MAX) ||
			    memcmp(req.id.cookie, rows[i].msg.id.cookie, sizeof(req.id.cookie)) == 0)
				break;
		if (i == count) {
			free(rows, M_TEMP);
			return (req.protocol == IPPROTO_UDP ? ESTALE : ENOENT);
		}
		rows[0] = rows[i];
		count = 1;
	}
	for (i = 0; i < count; i++) {
		if (!nlmsg_add(npt->nw, hdr->nlmsg_pid, hdr->nlmsg_seq,
		    DIAG_BY_FAMILY, dump ? NLM_F_MULTI : 0, sizeof(rows[i].msg))) {
			error = ENOMEM;
			break;
		}
		memcpy(nlmsg_reserve_object(npt->nw, struct diag_msg),
		    &rows[i].msg, sizeof(rows[i].msg));
		if (!sock_diag_add_extensions(npt->nw, req.extensions, &rows[i])) {
			nlmsg_abort(npt->nw);
			error = ENOMEM;
			break;
		}
		if (!nlmsg_end(npt->nw)) {
			error = ENOMEM;
			break;
		}
		if (!dump)
			break;
	}
	free(rows, M_TEMP);
	if (dump && !nlmsg_end_dump(npt->nw, error, hdr))
		return (ENOMEM);
	return (error);
#else
	return (EPROTONOSUPPORT);
#endif
}

static void
sock_diag_init(void *arg __unused)
{
	netlink_register_proto(NETLINK_SOCK_DIAG, "NETLINK_SOCK_DIAG", sock_diag_handle);
}
SYSINIT(sock_diag, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD, sock_diag_init, NULL);
static void
sock_diag_uninit(void *arg __unused)
{
	netlink_unregister_proto(NETLINK_SOCK_DIAG);
}
SYSUNINIT(sock_diag, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD, sock_diag_uninit, NULL);
