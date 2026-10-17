/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002 - 2008 Henning Brauer
 * Copyright (c) 2012 Gleb Smirnoff <glebius@FreeBSD.org>
 * Copyright (c) 2026 The 5BSD Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * 5BSD extension: SCTP in OpenBSD PF, derived from FreeBSD pf (the SCTP
 * parts of FreeBSD sys/netpfil/pf/pf.c and pf_norm.c).
 *
 * pf_setup_pdesc() validates the chunks of an SCTP packet and notes the
 * chunk types and the INIT/INIT-ACK initiate tag.  States follow the
 * association (COOKIE_WAIT .. SHUTDOWN_PENDING, CLOSED) with the sctp.*
 * timeouts, and pin each peer's verification tag in its pf_state_scrub;
 * packets with another tag are dropped.  An INIT on a closed state
 * replaces it.  "block return" answers with an ABORT.  NAT and rdr do
 * not change SCTP ports.
 *
 * Multihoming: the addresses an endpoint lists in INIT, INIT-ACK and
 * ASCONF chunks get states of their own, evaluated against the ruleset
 * as packets of the association (or created from the original rule with
 * "allow-related").  This runs after the packet has been filtered, with
 * the PF lock held, from pf_sctp_multihome_delayed().  The addresses are
 * kept per verification tag so that states are created for every
 * address pair of a multihomed association.
 */

#include "openbsd_compat.h"

#include <net/pfvar.h>
#include <net/pfvar_priv.h>

#include <netinet/sctp.h>
#include <netinet/sctp_header.h>
#include <netinet/sctp_crc32.h>
#include <netinet6/ip6_var.h>

SDT_PROBE_DEFINE4(pf, sctp, multihome, test, "struct pfi_kif *",
    "struct pf_rule *", "struct mbuf *", "int");
SDT_PROBE_DEFINE2(pf, sctp, multihome, add, "uint32_t",
    "struct pf_sctp_source *");
SDT_PROBE_DEFINE3(pf, sctp, multihome, remove, "uint32_t",
    "struct pf_state *", "struct pf_sctp_source *");
SDT_PROBE_DEFINE4(pf, sctp, multihome_scan, entry, "int",
    "int", "struct pf_pdesc *", "int");
SDT_PROBE_DEFINE2(pf, sctp, multihome_scan, param, "uint16_t", "uint16_t");
SDT_PROBE_DEFINE2(pf, sctp, multihome_scan, ipv4, "struct in_addr *",
    "int");
SDT_PROBE_DEFINE2(pf, sctp, multihome_scan, ipv6, "struct in6_addr *",
    "int");

/* Most addresses remembered per verification tag. */
#define	PF_SCTP_MAX_ENDPOINTS		8

struct pf_sctp_source {
	sa_family_t			af;
	struct pf_addr			addr;
	TAILQ_ENTRY(pf_sctp_source)	entry;
};
TAILQ_HEAD(pf_sctp_sources, pf_sctp_source);

struct pf_sctp_endpoint {
	uint32_t			v_tag;
	struct pf_sctp_sources		sources;
	RB_ENTRY(pf_sctp_endpoint)	entry;
};

static int
pf_sctp_endpoint_compare(struct pf_sctp_endpoint *a,
    struct pf_sctp_endpoint *b)
{
	return (a->v_tag < b->v_tag ? -1 : a->v_tag > b->v_tag);
}

RB_HEAD(pf_sctp_endpoints, pf_sctp_endpoint);
RB_GENERATE_STATIC(pf_sctp_endpoints, pf_sctp_endpoint, entry,
    pf_sctp_endpoint_compare);

VNET_DEFINE_STATIC(struct pf_sctp_endpoints, pf_sctp_endpoints);
#define	V_pf_sctp_endpoints	VNET(pf_sctp_endpoints)

static struct mtx pf_sctp_endpoints_mtx;
MTX_SYSINIT(pf_sctp_endpoints_mtx, &pf_sctp_endpoints_mtx,
    "pf SCTP endpoints", MTX_DEF);
#define	PF_SCTP_ENDPOINTS_LOCK()	mtx_lock(&pf_sctp_endpoints_mtx)
#define	PF_SCTP_ENDPOINTS_UNLOCK()	mtx_unlock(&pf_sctp_endpoints_mtx)

/* A state to create (ADD_IP) or close (DEL_IP) for a listed address. */
struct pf_sctp_multihome_job {
	TAILQ_ENTRY(pf_sctp_multihome_job)	next;
	struct pf_pdesc				pd;
	struct pf_addr				src;
	struct pf_addr				dst;
	int					op;
	int					extra;
};
TAILQ_HEAD(pf_sctp_multihome_jobs, pf_sctp_multihome_job);

static void
pf_sctp_set_protostate(struct pf_state *st, int which, u_int8_t newstate)
{
	PF_SDT3(state, state, transition, st, which, newstate);
	if (which == PF_PEER_DST || which == PF_PEER_BOTH)
		st->dst.state = newstate;
	if (which == PF_PEER_SRC || which == PF_PEER_BOTH)
		st->src.state = newstate;
}

/* Point a job's packet description at its own addresses and header. */
static void
pf_sctp_job_pd(struct pf_sctp_multihome_job *j)
{
	struct pf_pdesc *pd = &j->pd;

	pd->src = &j->src;
	pd->dst = &j->dst;
	pf_addrcpy(&pd->nsaddr, &j->src, pd->af);
	pf_addrcpy(&pd->ndaddr, &j->dst, pd->af);
	pd->sport = &pd->hdr.sctp.src_port;
	pd->dport = &pd->hdr.sctp.dest_port;
	pd->pcksum = &pd->sctp_dummy_sum;
}

/*
 * Walk the address parameters of an INIT, INIT-ACK or ASCONF chunk.
 * Malformed parameters drop the packet.  With jobs set, queue a job for
 * every listed address of the packet's address family.
 */
static int
pf_sctp_multihome_scan(int start, int len, struct pf_pdesc *pd, int op,
    bool asconf, struct pf_sctp_multihome_jobs *jobs)
{
	struct pf_sctp_multihome_job *job;
	struct pf_addr a;
	int off = 0;

	SDT_PROBE4(pf, sctp, multihome_scan, entry, start, len, pd, op);

	while (off < len) {
		struct sctp_paramhdr h;
		u_int16_t plen;

		if (!pf_pull_hdr(pd->m, start + off, &h, sizeof(h), NULL,
		    pd->af))
			return (PF_DROP);

		/* Parameters are at least 4 bytes. */
		plen = ntohs(h.param_length);
		if (plen < 4)
			return (PF_DROP);

		SDT_PROBE2(pf, sctp, multihome_scan, param,
		    ntohs(h.param_type), plen);

		switch (ntohs(h.param_type)) {
		case SCTP_IPV4_ADDRESS: {
			struct in_addr t;

			if (plen != sizeof(struct sctp_paramhdr) + sizeof(t))
				return (PF_DROP);
			if (!pf_pull_hdr(pd->m, start + off + sizeof(h), &t,
			    sizeof(t), NULL, pd->af))
				return (PF_DROP);
			if (jobs == NULL || pd->af != AF_INET)
				break;
			if (in_nullhost(t))
				t.s_addr = pd->src->v4.s_addr;
			SDT_PROBE2(pf, sctp, multihome_scan, ipv4, &t, op);
			memset(&a, 0, sizeof(a));
			a.v4 = t;
			goto job;
		}
#ifdef INET6
		case SCTP_IPV6_ADDRESS: {
			struct in6_addr t;

			if (plen != sizeof(struct sctp_paramhdr) + sizeof(t))
				return (PF_DROP);
			if (!pf_pull_hdr(pd->m, start + off + sizeof(h), &t,
			    sizeof(t), NULL, pd->af))
				return (PF_DROP);
			if (jobs == NULL || pd->af != AF_INET6)
				break;
			if (memcmp(&t, &pd->src->v6, sizeof(t)) == 0)
				break;
			if (memcmp(&t, &in6addr_any, sizeof(t)) == 0)
				memcpy(&t, &pd->src->v6, sizeof(t));
			SDT_PROBE2(pf, sctp, multihome_scan, ipv6, &t, op);
			memset(&a, 0, sizeof(a));
			a.v6 = t;
			goto job;
		}
#endif /* INET6 */
		case SCTP_ADD_IP_ADDRESS:
		case SCTP_DEL_IP_ADDRESS: {
			struct sctp_asconf_paramhdr ah;
			int ret;

			/* Address changes do not nest. */
			if (asconf)
				return (PF_DROP);
			if (!pf_pull_hdr(pd->m, start + off, &ah, sizeof(ah),
			    NULL, pd->af))
				return (PF_DROP);
			if (ntohs(ah.ph.param_length) < sizeof(ah))
				return (PF_DROP);
			ret = pf_sctp_multihome_scan(start + off + sizeof(ah),
			    ntohs(ah.ph.param_length) - sizeof(ah), pd,
			    ntohs(h.param_type), true, jobs);
			if (ret != PF_PASS)
				return (ret);
			break;
		}
		default:
			break;
		}
		goto next;
job:
		/*
		 * States are created later, after the packet has been
		 * filtered and the state lock released: the new states'
		 * keys cannot be inserted from here.
		 */
		/*
		 * Each job is a rule evaluation under PF_LOCK: one packet
		 * may list thousands of addresses.  pf keeps at most
		 * PF_SCTP_MAX_ENDPOINTS per association; queue no more.
		 */
		{
			struct pf_sctp_multihome_job *j;
			int n = 0;

			TAILQ_FOREACH(j, jobs, next)
				n++;
			if (n >= PF_SCTP_MAX_ENDPOINTS)
				goto next;
		}
		job = malloc(sizeof(*job), M_PF, M_NOWAIT | M_ZERO);
		if (job == NULL)
			return (PF_DROP);
		memcpy(&job->pd, pd, sizeof(job->pd));
		pf_addrcpy(&job->src, &a, pd->af);
		pf_addrcpy(&job->dst, pd->dst, pd->af);
		pf_sctp_job_pd(job);
		job->op = op;
		TAILQ_INSERT_TAIL(jobs, job, next);
next:
		off += roundup(plen, 4);
	}

	return (PF_PASS);
}

/*
 * Walk the chunks of an SCTP packet, as FreeBSD's pf_scan_sctp(): check
 * their lengths and the rules for bundling, note the chunk types and the
 * initiate tag in pd, and (with jobs) collect the multihome addresses.
 */
static int
pf_sctp_scan(struct pf_pdesc *pd, struct pf_sctp_multihome_jobs *jobs)
{
	struct sctp_chunkhdr ch = { };
	int chunk_off = sizeof(struct sctphdr);
	int chunk_start;
	int ret;

	pd->sctp_flags = 0;
	while (pd->off + chunk_off < pd->tot_len) {
		if (!pf_pull_hdr(pd->m, pd->off + chunk_off, &ch, sizeof(ch),
		    NULL, pd->af))
			return (PF_DROP);

		/* Length includes the header, this must be at least 4. */
		if (ntohs(ch.chunk_length) < 4)
			return (PF_DROP);

		chunk_start = chunk_off;
		chunk_off += roundup(ntohs(ch.chunk_length), 4);

		switch (ch.chunk_type) {
		case SCTP_INITIATION:
		case SCTP_INITIATION_ACK: {
			struct sctp_init_chunk init;

			if (!pf_pull_hdr(pd->m, pd->off + chunk_start, &init,
			    sizeof(init), NULL, pd->af))
				return (PF_DROP);

			/* RFC 9260 3.3.2: the Initiate Tag is never 0. */
			if (init.init.initiate_tag == 0)
				return (PF_DROP);
			if (init.init.num_inbound_streams == 0)
				return (PF_DROP);
			if (init.init.num_outbound_streams == 0)
				return (PF_DROP);
			if (ntohl(init.init.a_rwnd) < SCTP_MIN_RWND)
				return (PF_DROP);

			/* RFC 9260 3.1: an INIT has a zero verification tag. */
			if (ch.chunk_type == SCTP_INITIATION &&
			    pd->hdr.sctp.v_tag != 0)
				return (PF_DROP);

			pd->sctp_initiate_tag = init.init.initiate_tag;
			if (ch.chunk_type == SCTP_INITIATION)
				pd->sctp_flags |= PFDESC_SCTP_INIT;
			else
				pd->sctp_flags |= PFDESC_SCTP_INIT_ACK;

			if (ntohs(init.ch.chunk_length) < sizeof(init))
				return (PF_DROP);
			ret = pf_sctp_multihome_scan(
			    pd->off + chunk_start + sizeof(init),
			    ntohs(init.ch.chunk_length) - sizeof(init), pd,
			    SCTP_ADD_IP_ADDRESS, false, jobs);
			if (ret != PF_PASS)
				return (ret);
			break;
		}
		case SCTP_ABORT_ASSOCIATION:
			pd->sctp_flags |= PFDESC_SCTP_ABORT;
			break;
		case SCTP_SHUTDOWN:
		case SCTP_SHUTDOWN_ACK:
			pd->sctp_flags |= PFDESC_SCTP_SHUTDOWN;
			break;
		case SCTP_SHUTDOWN_COMPLETE:
			pd->sctp_flags |= PFDESC_SCTP_SHUTDOWN_COMPLETE;
			break;
		case SCTP_COOKIE_ECHO:
			pd->sctp_flags |= PFDESC_SCTP_COOKIE;
			break;
		case SCTP_COOKIE_ACK:
			pd->sctp_flags |= PFDESC_SCTP_COOKIE_ACK;
			break;
		case SCTP_DATA:
			pd->sctp_flags |= PFDESC_SCTP_DATA;
			break;
		case SCTP_HEARTBEAT_REQUEST:
			pd->sctp_flags |= PFDESC_SCTP_HEARTBEAT;
			break;
		case SCTP_HEARTBEAT_ACK:
			pd->sctp_flags |= PFDESC_SCTP_HEARTBEAT_ACK;
			break;
		case SCTP_ASCONF:
			pd->sctp_flags |= PFDESC_SCTP_ASCONF;
			if (ntohs(ch.chunk_length) <
			    sizeof(struct sctp_asconf_chunk))
				return (PF_DROP);
			ret = pf_sctp_multihome_scan(pd->off + chunk_start +
			    sizeof(struct sctp_asconf_chunk),
			    ntohs(ch.chunk_length) -
			    sizeof(struct sctp_asconf_chunk), pd,
			    SCTP_ADD_IP_ADDRESS, false, jobs);
			if (ret != PF_PASS)
				return (ret);
			break;
		default:
			pd->sctp_flags |= PFDESC_SCTP_OTHER;
			break;
		}
	}

	/* Validate chunk lengths vs. packet length. */
	if (pd->off + chunk_off != pd->tot_len)
		return (PF_DROP);

	/*
	 * INIT, INIT_ACK or SHUTDOWN_COMPLETE chunks must always be the only
	 * one in a packet.
	 */
	if ((pd->sctp_flags & PFDESC_SCTP_INIT) &&
	    (pd->sctp_flags & ~PFDESC_SCTP_INIT))
		return (PF_DROP);
	if ((pd->sctp_flags & PFDESC_SCTP_INIT_ACK) &&
	    (pd->sctp_flags & ~PFDESC_SCTP_INIT_ACK))
		return (PF_DROP);
	if ((pd->sctp_flags & PFDESC_SCTP_SHUTDOWN_COMPLETE) &&
	    (pd->sctp_flags & ~PFDESC_SCTP_SHUTDOWN_COMPLETE))
		return (PF_DROP);
	/* RFC 9260 3.3.7: DATA chunks MUST NOT be bundled with ABORT. */
	if ((pd->sctp_flags & PFDESC_SCTP_ABORT) &&
	    (pd->sctp_flags & PFDESC_SCTP_DATA))
		return (PF_DROP);

	return (PF_PASS);
}

/* pf_setup_pdesc(): the SCTP common header and chunks. */
int
pf_sctp_setup_pdesc(struct pf_pdesc *pd, u_short *reason)
{
	struct sctphdr *sh = &pd->hdr.sctp;

	if (!pf_pull_hdr(pd->m, pd->off, sh, sizeof(*sh), reason, pd->af))
		return (PF_DROP);
	pd->hdrlen = sizeof(*sh);
	if (pd->off + pd->hdrlen > pd->tot_len ||
	    sh->src_port == 0 || sh->dest_port == 0) {
		REASON_SET(reason, PFRES_SHORT);
		return (PF_DROP);
	}
	pd->p_len = pd->tot_len - pd->off - pd->hdrlen;
	pd->sport = &sh->src_port;
	pd->dport = &sh->dest_port;
	/*
	 * The CRC32c does not cover the IP header, and NAT never changes
	 * SCTP ports: nothing to fix up, but pf_patch_16() wants a target.
	 */
	pd->pcksum = &pd->sctp_dummy_sum;

	if (pf_sctp_scan(pd, NULL) != PF_PASS) {
		REASON_SET(reason, PFRES_NORM);
		return (PF_DROP);
	}
	return (PF_PASS);
}

/*
 * pf_create_state(): an SCTP state starts with an INIT, or with an address
 * of a multihomed association.  Its peers keep their verification tags in
 * scrub memory.
 */
int
pf_sctp_create_state(struct pf_pdesc *pd, struct pf_state *st,
    u_short *reason)
{
	if ((pd->sctp_flags & (PFDESC_SCTP_INIT | PFDESC_SCTP_ADD_IP)) == 0) {
		REASON_SET(reason, PFRES_NORM);
		return (PF_DROP);
	}
	if ((st->src.scrub == NULL &&
	    (st->src.scrub = pf_state_scrub_get()) == NULL) ||
	    (st->dst.scrub == NULL &&
	    (st->dst.scrub = pf_state_scrub_get()) == NULL)) {
		REASON_SET(reason, PFRES_MEMORY);
		return (PF_DROP);	/* pf_normalize_tcp_cleanup() frees */
	}
	st->dst.scrub->pfss_v_tag = pd->sctp_initiate_tag;
	return (PF_PASS);
}

/* The peer of st that sent the packet pd. */
static struct pf_state_peer *
pf_sctp_src_peer(struct pf_pdesc *pd, struct pf_state *st, int dir)
{
	if (dir == st->direction)
		return (PF_REVERSED_KEY(st->key, pd->af) ? &st->dst : &st->src);
	return (PF_REVERSED_KEY(st->key, pd->af) ? &st->src : &st->dst);
}

/*
 * pf_test_state(): follow the association.  Returns PF_DROP for packets
 * with the wrong verification tag, and with *stp NULL when an INIT
 * replaces a closed state (pf_test() then evaluates the rules).
 */
int
pf_sctp_test_state(struct pf_pdesc *pd, struct pf_state **stp,
    u_short *reason)
{
	struct pf_state *st = *stp;
	struct pf_state_peer *src, *dst, *vsrc;
	int psrc;

	if (pd->dir == st->direction) {
		src = &st->src;
		dst = &st->dst;
		psrc = PF_PEER_SRC;
	} else {
		src = &st->dst;
		dst = &st->src;
		psrc = PF_PEER_DST;
	}

	if ((src->state >= PF_SCTPS_SHUTDOWN_SENT ||
	    src->state == PF_SCTPS_CLOSED) &&
	    (dst->state >= PF_SCTPS_SHUTDOWN_SENT ||
	    dst->state == PF_SCTPS_CLOSED) &&
	    (pd->sctp_flags & PFDESC_SCTP_INIT)) {
		/* pf_state_key_attach() reuses the key of a closed state. */
		pf_sctp_set_protostate(st, PF_PEER_BOTH, PF_SCTPS_CLOSED);
		pf_update_state_timeout(st, PFTM_PURGE);
		pf_state_unref(st);
		*stp = NULL;
		return (PF_DROP);
	}

	/*
	 * Allow tags to be updated, in case of retransmission of
	 * INIT/INIT_ACK chunks.
	 */
	vsrc = pf_sctp_src_peer(pd, st, pd->dir);
	if (vsrc->scrub != NULL) {
		if (vsrc->state <= PF_SCTPS_COOKIE_WAIT)
			vsrc->scrub->pfss_v_tag = pd->hdr.sctp.v_tag;
		else if (vsrc->scrub->pfss_v_tag != pd->hdr.sctp.v_tag) {
			REASON_SET(reason, PFRES_BADSTATE);
			return (PF_DROP);
		}
	}

	if (pd->sctp_flags & PFDESC_SCTP_INIT) {
		if (src->state < PF_SCTPS_COOKIE_WAIT) {
			pf_sctp_set_protostate(st, psrc, PF_SCTPS_COOKIE_WAIT);
			pf_update_state_timeout(st, PFTM_SCTP_OPENING);
		}
	}
	if (pd->sctp_flags & PFDESC_SCTP_INIT_ACK) {
		if (dst->scrub != NULL && dst->scrub->pfss_v_tag == 0)
			dst->scrub->pfss_v_tag = pd->sctp_initiate_tag;
	}
	if (pd->sctp_flags & (PFDESC_SCTP_COOKIE | PFDESC_SCTP_HEARTBEAT_ACK)) {
		if (src->state < PF_SCTPS_ESTABLISHED) {
			pf_sctp_set_protostate(st, psrc, PF_SCTPS_ESTABLISHED);
			pf_update_state_timeout(st, PFTM_SCTP_ESTABLISHED);
		}
	}
	if (pd->sctp_flags & (PFDESC_SCTP_SHUTDOWN |
	    PFDESC_SCTP_SHUTDOWN_COMPLETE)) {
		if (src->state < PF_SCTPS_SHUTDOWN_PENDING) {
			pf_sctp_set_protostate(st, psrc,
			    PF_SCTPS_SHUTDOWN_PENDING);
			pf_update_state_timeout(st, PFTM_SCTP_CLOSING);
		}
	}
	if (pd->sctp_flags & (PFDESC_SCTP_SHUTDOWN_COMPLETE |
	    PFDESC_SCTP_ABORT)) {
		pf_sctp_set_protostate(st, psrc, PF_SCTPS_CLOSED);
		pf_update_state_timeout(st, PFTM_SCTP_CLOSED);
	}

	st->expire = getuptime();
	return (PF_PASS);
}

/* pf_state_key_attach(): a closed SCTP state gives way to a new INIT. */
int
pf_sctp_state_reusable(const struct pf_state *st)
{
	return (st->src.state == PF_SCTPS_CLOSED &&
	    st->dst.state == PF_SCTPS_CLOSED);
}

static void
pf_sctp_endpoint_remove(uint32_t v_tag, struct pf_state *st,
    struct pf_addr *addr, sa_family_t af)
{
	struct pf_sctp_endpoint key, *ep;
	struct pf_sctp_source *i, *tmp;

	key.v_tag = v_tag;
	ep = RB_FIND(pf_sctp_endpoints, &V_pf_sctp_endpoints, &key);
	if (ep == NULL)
		return;
	TAILQ_FOREACH_SAFE(i, &ep->sources, entry, tmp) {
		if (i->af == af && pf_addr_compare(&i->addr, addr, af) == 0) {
			SDT_PROBE3(pf, sctp, multihome, remove, v_tag, st, i);
			TAILQ_REMOVE(&ep->sources, i, entry);
			free(i, M_PF);
			break;
		}
	}
	if (TAILQ_EMPTY(&ep->sources)) {
		RB_REMOVE(pf_sctp_endpoints, &V_pf_sctp_endpoints, ep);
		free(ep, M_PF);
	}
}

/* pf_detach_state(): forget the addresses the state's peers announced. */
void
pf_sctp_detach_state(struct pf_state *st)
{
	struct pf_state_key *skw = st->key[PF_SK_WIRE];
	struct pf_state_key *sks = st->key[PF_SK_STACK];

	if (skw == NULL || sks == NULL || sks->proto != IPPROTO_SCTP ||
	    st->src.scrub == NULL || st->dst.scrub == NULL)
		return;

	PF_SCTP_ENDPOINTS_LOCK();
	pf_sctp_endpoint_remove(st->dst.scrub->pfss_v_tag, st,
	    &skw->addr[st->direction == PF_OUT], skw->af);
	/* Other direction. */
	pf_sctp_endpoint_remove(st->src.scrub->pfss_v_tag, st,
	    &skw->addr[st->direction == PF_IN], skw->af);
	PF_SCTP_ENDPOINTS_UNLOCK();
}

static void
pf_sctp_multihome_add_addr(struct pf_pdesc *pd, struct pf_addr *a,
    uint32_t v_tag)
{
	struct pf_sctp_endpoint key = { .v_tag = v_tag };
	struct pf_sctp_source *i;
	struct pf_sctp_endpoint *ep;
	int count;

	PF_SCTP_ENDPOINTS_LOCK();
	ep = RB_FIND(pf_sctp_endpoints, &V_pf_sctp_endpoints, &key);
	if (ep == NULL) {
		ep = malloc(sizeof(*ep), M_PF, M_NOWAIT);
		if (ep == NULL)
			goto out;
		ep->v_tag = v_tag;
		TAILQ_INIT(&ep->sources);
		RB_INSERT(pf_sctp_endpoints, &V_pf_sctp_endpoints, ep);
	}

	/* Avoid inserting duplicates. */
	count = 0;
	TAILQ_FOREACH(i, &ep->sources, entry) {
		count++;
		if (i->af == pd->af && pf_addr_compare(&i->addr, a, pd->af) == 0)
			goto out;
	}

	/* Limit the number of addresses per endpoint. */
	if (count >= PF_SCTP_MAX_ENDPOINTS)
		goto out;

	i = malloc(sizeof(*i), M_PF, M_NOWAIT | M_ZERO);
	if (i == NULL)
		goto out;
	i->af = pd->af;
	pf_addrcpy(&i->addr, a, pd->af);
	TAILQ_INSERT_TAIL(&ep->sources, i, entry);
	SDT_PROBE2(pf, sctp, multihome, add, v_tag, i);
out:
	PF_SCTP_ENDPOINTS_UNLOCK();
}

/* Create the state of a listed address, as FreeBSD (SCTP_ADD_IP_ADDRESS). */
static void
pf_sctp_multihome_add(struct pf_pdesc *pd, struct pf_state *st,
    struct pf_addr *osrc, struct pf_sctp_multihome_job *j,
    struct pf_sctp_multihome_jobs *jobs)
{
	struct pf_sctp_endpoint key, *ep;
	struct pf_sctp_source *i;
	struct pf_sctp_multihome_job *nj;
	struct pf_rule *r = &pf_default_rule, *a = NULL;
	struct pf_ruleset *rs = NULL;
	struct pf_state *sm = NULL;
	u_short reason = 0;
	uint32_t v_tag;
	int ret;

	v_tag = pd->sctp_initiate_tag;
	if (v_tag == 0) {
		struct pf_state_peer *p = (st->direction == pd->dir) ?
		    &st->src : &st->dst;

		if (p->scrub != NULL)
			v_tag = p->scrub->pfss_v_tag;
	}

	/*
	 * Avoid duplicating states.  We'll already have created a state
	 * based on the source address of the packet, but SCTP endpoints may
	 * also list this address again in the INIT(_ACK) parameters.
	 */
	if (pf_addr_compare(&j->src, osrc, pd->af) == 0)
		return;

	j->pd.sctp_flags |= PFDESC_SCTP_ADD_IP;
	if (st->rule.ptr->rule_flag & PFRULE_ALLOW_RELATED)
		j->pd.related_rule = st->rule.ptr;
	PF_ASSERT_LOCKED();
	ret = pf_test_rule(&j->pd, &r, &sm, &a, &rs, &reason);
	SDT_PROBE4(pf, sctp, multihome, test, pd->kif, r, pd->m, ret);
	if (ret == PF_DROP || sm == NULL)
		return;

	/* Inherit v_tag values. */
	if (sm->src.scrub != NULL && sm->dst.scrub != NULL &&
	    st->src.scrub != NULL && st->dst.scrub != NULL) {
		if (sm->direction == st->direction) {
			sm->src.scrub->pfss_v_tag = st->src.scrub->pfss_v_tag;
			sm->dst.scrub->pfss_v_tag = st->dst.scrub->pfss_v_tag;
		} else {
			sm->src.scrub->pfss_v_tag = st->dst.scrub->pfss_v_tag;
			sm->dst.scrub->pfss_v_tag = st->src.scrub->pfss_v_tag;
		}
	}

	/*
	 * Only add the address if we've actually allowed the state.  Tag 0
	 * (an INIT's) never names an endpoint.
	 */
	if (v_tag != 0)
		pf_sctp_multihome_add_addr(pd, &j->src, v_tag);

	if (j->extra || pd->hdr.sctp.v_tag == 0)
		return;

	/*
	 * We need to do this for each of our source addresses.  Find those
	 * based on the verification tag.
	 */
	key.v_tag = pd->hdr.sctp.v_tag;
	PF_SCTP_ENDPOINTS_LOCK();
	ep = RB_FIND(pf_sctp_endpoints, &V_pf_sctp_endpoints, &key);
	if (ep != NULL) {
		TAILQ_FOREACH(i, &ep->sources, entry) {
			/* SCTP can intermingle IPv4 and IPv6. */
			if (i->af != pd->af)
				continue;
			nj = malloc(sizeof(*nj), M_PF, M_NOWAIT | M_ZERO);
			if (nj == NULL)
				continue;
			memcpy(&nj->pd, &j->pd, sizeof(nj->pd));
			pf_addrcpy(&nj->src, &j->src, pd->af);
			/* New destination address! */
			pf_addrcpy(&nj->dst, &i->addr, pd->af);
			pf_sctp_job_pd(nj);
			nj->op = j->op;
			nj->extra = 1;
			TAILQ_INSERT_TAIL(jobs, nj, next);
		}
	}
	PF_SCTP_ENDPOINTS_UNLOCK();
}

/* Start closing the state of a removed address (SCTP_DEL_IP_ADDRESS). */
static void
pf_sctp_multihome_del(struct pf_sctp_multihome_job *j)
{
	struct pf_state_key_cmp key;
	struct pf_state *sm;

	memset(&key, 0, sizeof(key));
	key.af = j->pd.af;
	key.proto = IPPROTO_SCTP;
	key.rdomain = j->pd.rdomain;
	pf_addrcpy(&key.addr[j->pd.sidx], j->pd.src, key.af);
	pf_addrcpy(&key.addr[j->pd.didx], j->pd.dst, key.af);
	key.port[j->pd.sidx] = j->pd.hdr.sctp.src_port;
	key.port[j->pd.didx] = j->pd.hdr.sctp.dest_port;
	key.hash = pf_pkt_hash(key.af, key.proto, &key.addr[0], &key.addr[1],
	    key.port[0], key.port[1]);

	sm = pf_find_state_all(&key, j->pd.dir, NULL);
	if (sm == NULL)
		return;
	pf_sctp_set_protostate(sm,
	    j->pd.dir == sm->direction ? PF_PEER_SRC : PF_PEER_DST,
	    PF_SCTPS_SHUTDOWN_PENDING);
	pf_update_state_timeout(sm, PFTM_SCTP_CLOSING);
}

/*
 * pf_test(), after filtering: give the addresses a passed INIT, INIT-ACK
 * or ASCONF lists states of their own.  The packet's state st holds the
 * pre-translation addresses (NAT has rewritten pd's by now).  Takes the
 * PF lock if pf_test() does not hold it yet.
 */
void
pf_sctp_multihome_delayed(struct pf_pdesc *pd, struct pf_state *st,
    int action, int *pf_locked)
{
	struct pf_sctp_multihome_jobs jobs = TAILQ_HEAD_INITIALIZER(jobs);
	struct pf_sctp_multihome_job *j;
	struct pf_state_key *sk;
	struct pf_pdesc tpd;
	struct pf_addr osrc, odst;

	if (st == NULL || action != PF_PASS || pd->m == NULL ||
	    (pd->sctp_flags & PFDESC_SCTP_ADD_IP) != 0 ||
	    (pd->sctp_flags & (PFDESC_SCTP_INIT | PFDESC_SCTP_INIT_ACK |
	    PFDESC_SCTP_ASCONF)) == 0)
		return;
	sk = st->key[pd->dir == PF_IN ? PF_SK_WIRE : PF_SK_STACK];
	if (sk == NULL || sk->af != pd->af || sk->proto != IPPROTO_SCTP)
		return;

	/* The packet as it arrived, before any translation. */
	pf_addrcpy(&osrc, &sk->addr[pd->sidx], pd->af);
	pf_addrcpy(&odst, &sk->addr[pd->didx], pd->af);
	memcpy(&tpd, pd, sizeof(tpd));
	tpd.src = &osrc;
	tpd.dst = &odst;
	tpd.naf = tpd.af;
	tpd.hdr.sctp.src_port = sk->port[pd->sidx];
	tpd.hdr.sctp.dest_port = sk->port[pd->didx];
	tpd.osport = tpd.nsport = tpd.hdr.sctp.src_port;
	tpd.odport = tpd.ndport = tpd.hdr.sctp.dest_port;
	tpd.destchg = 0;
	tpd.related_rule = NULL;
	if (pf_sctp_scan(&tpd, &jobs) != PF_PASS)
		goto free;

	if (TAILQ_EMPTY(&jobs))
		return;
	if (*pf_locked == 0) {
		PF_LOCK();
		*pf_locked = 1;
	}
	while ((j = TAILQ_FIRST(&jobs)) != NULL) {
		switch (j->op) {
		case SCTP_ADD_IP_ADDRESS:
			pf_sctp_multihome_add(&tpd, st, &osrc, j, &jobs);
			break;
		case SCTP_DEL_IP_ADDRESS:
			pf_sctp_multihome_del(j);
			break;
		}
		TAILQ_REMOVE(&jobs, j, next);
		free(j, M_PF);
	}
	return;
free:
	while ((j = TAILQ_FIRST(&jobs)) != NULL) {
		TAILQ_REMOVE(&jobs, j, next);
		free(j, M_PF);
	}
}

/* pf_test_state_icmp(): the quoted SCTP header completes the state key. */
int
pf_sctp_icmp_key(struct pf_pdesc *pd2, struct pf_state_key_cmp *key,
    u_short *reason)
{
	struct sctphdr *sh = &pd2->hdr.sctp;

	/* Ports and verification tag: the 8 bytes every error quotes. */
	memset(sh, 0, sizeof(*sh));
	if (!pf_pull_hdr(pd2->m, pd2->off, sh, 8, reason, pd2->af))
		return (PF_DROP);
	key->port[pd2->sidx] = sh->src_port;
	key->port[pd2->didx] = sh->dest_port;
	key->hash = pf_pkt_hash(pd2->af, pd2->proto, pd2->src, pd2->dst,
	    sh->src_port, sh->dest_port);
	return (PF_PASS);
}

/* pf_test_state_icmp(): the quoted packet must carry the state's tag. */
int
pf_sctp_icmp_vtag(struct pf_pdesc *pd, struct pf_pdesc *pd2,
    struct pf_state *st, u_short *reason)
{
	struct pf_state_peer *src;

	/* The quoted packet travelled opposite to the ICMP error. */
	src = pf_sctp_src_peer(pd, st, pd->dir == PF_IN ? PF_OUT : PF_IN);
	if (src->scrub != NULL &&
	    src->scrub->pfss_v_tag != pd2->hdr.sctp.v_tag) {
		REASON_SET(reason, PFRES_BADSTATE);
		return (PF_DROP);
	}
	return (PF_PASS);
}

/* "block return": answer an SCTP packet with an ABORT chunk. */
void
pf_sctp_send_abort(struct pf_pdesc *pd, struct pf_rule *r)
{
	struct mbuf *m;
	struct ip *h;
#ifdef INET6
	struct ip6_hdr *h6;
#endif
	struct sctphdr *hdr;
	struct sctp_chunkhdr *chunk;
	int hlen, len;
	uint32_t sum;

	switch (pd->af) {
	case AF_INET:
		hlen = sizeof(struct ip);
		break;
#ifdef INET6
	case AF_INET6:
		hlen = sizeof(struct ip6_hdr);
		break;
#endif
	default:
		return;
	}
	len = hlen + sizeof(*hdr) + sizeof(*chunk);

	m = m_gethdr(M_NOWAIT, MT_DATA);
	if (m == NULL)
		return;
	if (PF_MTAG_W(m) == NULL) {
		m_freem(m);
		return;
	}
	PF_MTAG_W(m)->flags |= PF_TAG_GENERATED;
	if (r->scrub_flags & PFSTATE_SETPRIO)
		pf_mtag_setprio(PF_MTAG_W(m), r->set_prio[0]);
	if (r->qid)
		PF_MTAG_W(m)->qid = r->qid;
	m->m_pkthdr.ph_rtableid = pd->rdomain;
	m->m_data += max_linkhdr;
	m->m_pkthdr.len = m->m_len = len;
	m->m_pkthdr.rcvif = NULL;
	memset(m->m_data, 0, len);

	switch (pd->af) {
	case AF_INET:
		h = mtod(m, struct ip *);
		h->ip_v = IPVERSION;
		h->ip_hl = sizeof(*h) >> 2;
		h->ip_p = IPPROTO_SCTP;
		h->ip_len = htons(len);
		h->ip_ttl = r->return_ttl ? r->return_ttl : ip_defttl;
		h->ip_src = pd->dst->v4;
		h->ip_dst = pd->src->v4;
		break;
#ifdef INET6
	case AF_INET6:
		h6 = mtod(m, struct ip6_hdr *);
		h6->ip6_vfc = IPV6_VERSION;
		h6->ip6_nxt = IPPROTO_SCTP;
		h6->ip6_plen = htons(len - hlen);
		h6->ip6_hlim = r->return_ttl ? r->return_ttl : ip6_defhlim;
		memcpy(&h6->ip6_src, &pd->dst->v6, sizeof(struct in6_addr));
		memcpy(&h6->ip6_dst, &pd->src->v6, sizeof(struct in6_addr));
		break;
#endif
	}

	hdr = (struct sctphdr *)(mtod(m, caddr_t) + hlen);
	hdr->src_port = pd->hdr.sctp.dest_port;
	hdr->dest_port = pd->hdr.sctp.src_port;
	hdr->v_tag = pd->sctp_initiate_tag;
	hdr->checksum = 0;

	chunk = (struct sctp_chunkhdr *)(hdr + 1);
	chunk->chunk_type = SCTP_ABORT_ASSOCIATION;
	chunk->chunk_length = htons(sizeof(*chunk));

	sum = sctp_calculate_cksum(m, hlen);
	hdr->checksum = sum;

	switch (pd->af) {
	case AF_INET:
		ip_send(m);
		break;
#ifdef INET6
	case AF_INET6:
		ip6_send(m);
		break;
#endif
	}
}

/* A destroyed vnet has no states left; free what might remain. */
static void
pf_sctp_vnet_uninit(const void *unused __unused)
{
	struct pf_sctp_endpoint *ep, *tmp;
	struct pf_sctp_source *i;

	PF_SCTP_ENDPOINTS_LOCK();
	RB_FOREACH_SAFE(ep, pf_sctp_endpoints, &V_pf_sctp_endpoints, tmp) {
		while ((i = TAILQ_FIRST(&ep->sources)) != NULL) {
			TAILQ_REMOVE(&ep->sources, i, entry);
			free(i, M_PF);
		}
		RB_REMOVE(pf_sctp_endpoints, &V_pf_sctp_endpoints, ep);
		free(ep, M_PF);
	}
	PF_SCTP_ENDPOINTS_UNLOCK();
}
VNET_SYSUNINIT(pf_sctp_vnet_uninit, SI_SUB_PROTO_FIREWALL, SI_ORDER_SECOND,
    pf_sctp_vnet_uninit, NULL);
