/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002 - 2008 Henning Brauer
 * Copyright (c) 2012 Gleb Smirnoff <glebius@FreeBSD.org>
 * Copyright (c) 2021 Rubicon Communications, LLC (Netgate)
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
 * 5BSD extension: layer-2 ("ether") rules, derived from FreeBSD pf
 * (Kristof Provost's Ethernet filtering for Rubicon Communications /
 * Netgate: pf_test_eth_rule(), the keth anchor walk and rulesets in
 * FreeBSD sys/netpfil/pf/pf.c, pf_ioctl.c and pf_ruleset.c).
 *
 * Ether rules form their own ruleset, with their own anchors, beside
 * OpenBSD PF's.  They are evaluated without state from the link-layer
 * pfil(9) hooks, which are only linked while the main ether ruleset is
 * not empty.  The last matching rule (or the first "quick" one) decides;
 * a packet that matches no rule passes.  A passing rule can tag the
 * packet for the IP rules ("tag"), set its queue, send it through a
 * dummynet(4) pipe or queue at layer 2 ("dnpipe"/"dnqueue") or transmit
 * it unchanged on another interface ("bridge-to").
 *
 * Rulesets change through the OpenBSD transaction ioctls with the
 * element type PF_TRANS_ETH; rules are added and read with the 5BSD
 * DIOC*ETHRULE* ioctls, dispatched here from pf_freebsd.c.  Ruleset
 * changes hold pf_lock for writing; the packet path holds it for
 * reading, so a rule and the tables it uses stay valid while evaluated.
 */

#include "openbsd_compat.h"

#include <sys/counter.h>

#include <net/ethernet.h>
#include <net/if_types.h>
#include <net/pfvar.h>
#include <net/pfvar_priv.h>

#include <netinet/ip_var.h>
#include <netinet/ip_dn_flow.h>
#include <netpfil/dummynet/dn_packet.h>

/* FreeBSD's pf:eth:test_rule probes, with the same arguments. */
SDT_PROBE_DEFINE3(pf, eth, test_rule, entry, "int", "struct ifnet *",
    "struct mbuf *");
SDT_PROBE_DEFINE2(pf, eth, test_rule, test, "int", "struct pf_keth_rule *");
SDT_PROBE_DEFINE3(pf, eth, test_rule, mismatch, "int",
    "struct pf_keth_rule *", "char *");
SDT_PROBE_DEFINE2(pf, eth, test_rule, match, "int", "struct pf_keth_rule *");
SDT_PROBE_DEFINE2(pf, eth, test_rule, final_match, "int",
    "struct pf_keth_rule *");
SDT_PROBE_DEFINE3(pf, eth, dummynet, submit, "struct pf_keth_rule *",
    "uint32_t", "uint32_t");
SDT_PROBE_DEFINE2(pf, eth, dummynet, reinject, "int", "struct ifnet *");
SDT_PROBE_DEFINE2(pf, eth, bridge_to, transmit, "struct pf_keth_rule *",
    "struct ifnet *");
SDT_PROBE_DEFINE1(pf, eth, hook, link, "int");

/* OpenBSD PF functions without a prototype in its headers. */
struct pfi_kif	*pf_kif_setup(struct pfi_kif *);
void		 pf_addr_copyout(struct pf_addr_wrap *);
int		 pf_addr_wrap_neq(struct pf_addr_wrap *, struct pf_addr_wrap *);
u_int16_t	 pf_qname2qid(char *, int);
void		 pf_qid_unref(u_int16_t);
extern struct sx pfioctl_rw;

/* ------------------------------------------------------------------ */
/* Rulesets and anchors                                                */
/* ------------------------------------------------------------------ */

struct pf_keth_rule;
struct pf_keth_anchor;
TAILQ_HEAD(pf_keth_ruleq, pf_keth_rule);

struct pf_keth_ruleset {
	struct pf_keth_ruleq	 rules[2];
	struct pf_keth_rules {
		struct pf_keth_ruleq	*rules;
		int			 open;
		u_int32_t		 ticket;
	} active, inactive;
	struct pf_keth_anchor	*anchor;	/* NULL: the main ruleset */
};

RB_HEAD(pf_keth_anchor_global, pf_keth_anchor);
RB_HEAD(pf_keth_anchor_node, pf_keth_anchor);
struct pf_keth_anchor {
	RB_ENTRY(pf_keth_anchor)	 entry_node;
	RB_ENTRY(pf_keth_anchor)	 entry_global;
	struct pf_keth_anchor		*parent;
	struct pf_keth_anchor_node	 children;
	char				 name[PF_ANCHOR_NAME_SIZE];
	char				 path[MAXPATHLEN];
	struct pf_keth_ruleset		 ruleset;
	int				 refcnt;	/* anchor rules */
};

#define	PFE_SKIP_IFP		0
#define	PFE_SKIP_DIR		1
#define	PFE_SKIP_PROTO		2
#define	PFE_SKIP_SRC_ADDR	3
#define	PFE_SKIP_DST_ADDR	4
#define	PFE_SKIP_SRC_IP_ADDR	5
#define	PFE_SKIP_DST_IP_ADDR	6
#define	PFE_SKIP_COUNT		7

struct pf_keth_rule {
	struct pf_eth_rule		 r;	/* as loaded, tag ids and tables set */
	TAILQ_ENTRY(pf_keth_rule)	 entries;
	struct pf_keth_rule		*skip[PFE_SKIP_COUNT];
	struct pf_keth_anchor		*anchor;
	struct pfi_kif			*kif;
	struct pfi_kif			*bridge_to;
	counter_u64_t			 evaluations;
	counter_u64_t			 packets[2];
	counter_u64_t			 bytes[2];
	time_t				 last_active;
};

static __inline int
pf_keth_anchor_compare(struct pf_keth_anchor *a, struct pf_keth_anchor *b)
{
	int c = strcmp(a->path, b->path);

	return (c ? (c < 0 ? -1 : 1) : 0);
}

RB_GENERATE_STATIC(pf_keth_anchor_global, pf_keth_anchor, entry_global,
    pf_keth_anchor_compare);
RB_GENERATE_STATIC(pf_keth_anchor_node, pf_keth_anchor, entry_node,
    pf_keth_anchor_compare);

/* Per-vnet: the main ruleset and the anchors under it. */
VNET_DEFINE_STATIC(struct pf_keth_ruleset *, pf_keth);
VNET_DEFINE_STATIC(struct pf_keth_anchor_global, pf_keth_anchors);
VNET_DEFINE_STATIC(int, pf_keth_nanchors);
#define	V_pf_keth		VNET(pf_keth)
#define	V_pf_keth_anchors	VNET(pf_keth_anchors)
#define	V_pf_keth_nanchors	VNET(pf_keth_nanchors)

static void
pf_init_keth(struct pf_keth_ruleset *rs)
{
	memset(rs, 0, sizeof(*rs));
	TAILQ_INIT(&rs->rules[0]);
	TAILQ_INIT(&rs->rules[1]);
	rs->active.rules = &rs->rules[0];
	rs->inactive.rules = &rs->rules[1];
}

static struct pf_keth_anchor *
pf_find_keth_anchor(const char *path)
{
	struct pf_keth_anchor *key, *found;

	key = malloc(sizeof(*key), M_PF, M_NOWAIT | M_ZERO);
	if (key == NULL)
		return (NULL);
	strlcpy(key->path, path, sizeof(key->path));
	found = RB_FIND(pf_keth_anchor_global, &V_pf_keth_anchors, key);
	free(key, M_PF);
	return (found);
}

static struct pf_keth_ruleset *
pf_find_keth_ruleset(const char *path)
{
	struct pf_keth_anchor *anchor;

	while (*path == '/')
		path++;
	if (*path == '\0')
		return (V_pf_keth);
	anchor = pf_find_keth_anchor(path);
	return (anchor != NULL ? &anchor->ruleset : NULL);
}

static struct pf_keth_ruleset *
pf_find_or_create_keth_ruleset(const char *path)
{
	struct pf_keth_anchor *anchor = NULL, *dup, *parent = NULL;
	struct pf_keth_ruleset *ruleset;
	char *p, *q, *r;

	PF_ASSERT_LOCKED();

	while (*path == '/')
		path++;
	if (*path == '\0')
		return (V_pf_keth);
	if ((ruleset = pf_find_keth_ruleset(path)) != NULL)
		return (ruleset);
	p = malloc(MAXPATHLEN, M_PF, M_NOWAIT | M_ZERO);
	if (p == NULL)
		return (NULL);
	strlcpy(p, path, MAXPATHLEN);
	while (parent == NULL && (q = strrchr(p, '/')) != NULL) {
		*q = 0;
		if ((ruleset = pf_find_keth_ruleset(p)) != NULL) {
			parent = ruleset->anchor;
			break;
		}
	}
	if (q == NULL)
		q = p;
	else
		q++;
	strlcpy(p, path, MAXPATHLEN);
	if (*q == '\0') {
		free(p, M_PF);
		return (NULL);
	}
	while ((r = strchr(q, '/')) != NULL || *q) {
		if (r != NULL)
			*r = 0;
		if (*q == '\0' || strlen(q) >= PF_ANCHOR_NAME_SIZE ||
		    (parent != NULL && strlen(parent->path) >=
		    MAXPATHLEN - PF_ANCHOR_NAME_SIZE - 1) ||
		    V_pf_keth_nanchors >= PF_ANCHOR_HIWAT) {
			free(p, M_PF);
			return (NULL);
		}
		anchor = malloc(sizeof(*anchor), M_PF, M_NOWAIT | M_ZERO);
		if (anchor == NULL) {
			free(p, M_PF);
			return (NULL);
		}
		RB_INIT(&anchor->children);
		strlcpy(anchor->name, q, sizeof(anchor->name));
		if (parent != NULL) {
			strlcpy(anchor->path, parent->path,
			    sizeof(anchor->path));
			strlcat(anchor->path, "/", sizeof(anchor->path));
		}
		strlcat(anchor->path, anchor->name, sizeof(anchor->path));
		if ((dup = RB_INSERT(pf_keth_anchor_global, &V_pf_keth_anchors,
		    anchor)) != NULL) {
			free(anchor, M_PF);
			free(p, M_PF);
			return (NULL);
		}
		if (parent != NULL) {
			anchor->parent = parent;
			if ((dup = RB_INSERT(pf_keth_anchor_node,
			    &parent->children, anchor)) != NULL) {
				RB_REMOVE(pf_keth_anchor_global,
				    &V_pf_keth_anchors, anchor);
				free(anchor, M_PF);
				free(p, M_PF);
				return (NULL);
			}
		}
		pf_init_keth(&anchor->ruleset);
		anchor->ruleset.anchor = anchor;
		V_pf_keth_nanchors++;
		parent = anchor;
		if (r != NULL)
			q = r + 1;
		else
			*q = 0;
	}
	free(p, M_PF);
	return (&anchor->ruleset);
}

static void
pf_remove_if_empty_keth_ruleset(struct pf_keth_ruleset *ruleset)
{
	struct pf_keth_anchor *parent;

	PF_ASSERT_LOCKED();

	while (ruleset != NULL) {
		if (ruleset == V_pf_keth || ruleset->anchor == NULL ||
		    !RB_EMPTY(&ruleset->anchor->children) ||
		    ruleset->anchor->refcnt > 0 ||
		    !TAILQ_EMPTY(ruleset->active.rules) ||
		    !TAILQ_EMPTY(ruleset->inactive.rules) ||
		    ruleset->inactive.open)
			return;
		RB_REMOVE(pf_keth_anchor_global, &V_pf_keth_anchors,
		    ruleset->anchor);
		if ((parent = ruleset->anchor->parent) != NULL)
			RB_REMOVE(pf_keth_anchor_node, &parent->children,
			    ruleset->anchor);
		free(ruleset->anchor, M_PF);
		V_pf_keth_nanchors--;
		if (parent == NULL)
			return;
		ruleset = &parent->ruleset;
	}
}

/* Point an anchor rule at its ruleset, as pf_anchor_setup() does. */
static int
pf_keth_anchor_setup(struct pf_keth_rule *r, const struct pf_keth_ruleset *s,
    const char *name)
{
	struct pf_keth_ruleset *ruleset;
	char *p, *path;

	r->anchor = NULL;
	r->r.anchor_relative = 0;
	r->r.anchor_wildcard = 0;
	if (name[0] == '\0')
		return (0);
	path = malloc(MAXPATHLEN, M_PF, M_NOWAIT | M_ZERO);
	if (path == NULL)
		return (1);
	if (name[0] == '/')
		strlcpy(path, name + 1, MAXPATHLEN);
	else {
		/* relative path */
		r->r.anchor_relative = 1;
		if (s->anchor == NULL || s->anchor->path[0] == '\0')
			path[0] = 0;
		else
			strlcpy(path, s->anchor->path, MAXPATHLEN);
		while (name[0] == '.' && name[1] == '.' && name[2] == '/') {
			if (path[0] == '\0') {
				free(path, M_PF);
				return (1);
			}
			if ((p = strrchr(path, '/')) != NULL)
				*p = 0;
			else
				path[0] = 0;
			r->r.anchor_relative++;
			name += 3;
		}
		if (path[0])
			strlcat(path, "/", MAXPATHLEN);
		strlcat(path, name, MAXPATHLEN);
	}
	if ((p = strrchr(path, '/')) != NULL && strcmp(p, "/*") == 0) {
		r->r.anchor_wildcard = 1;
		*p = 0;
	}
	ruleset = pf_find_or_create_keth_ruleset(path);
	free(path, M_PF);
	if (ruleset == NULL || ruleset->anchor == NULL)
		return (1);
	r->anchor = ruleset->anchor;
	r->anchor->refcnt++;
	return (0);
}

/* The anchor call as the rule was loaded, as pf_anchor_copyout() does. */
static int
pf_keth_anchor_copyout(const struct pf_keth_ruleset *rs,
    const struct pf_keth_rule *r, char *anchor_call, size_t len)
{
	char a[MAXPATHLEN], *p;
	int i;

	anchor_call[0] = '\0';
	if (r->anchor == NULL)
		return (0);
	if (!r->r.anchor_relative) {
		strlcpy(anchor_call, "/", len);
		strlcat(anchor_call, r->anchor->path, len);
	} else {
		if (rs->anchor == NULL)
			a[0] = 0;
		else
			strlcpy(a, rs->anchor->path, sizeof(a));
		for (i = 1; i < r->r.anchor_relative; ++i) {
			if ((p = strrchr(a, '/')) == NULL)
				p = a;
			*p = 0;
			strlcat(anchor_call, "../", len);
		}
		if (strncmp(a, r->anchor->path, strlen(a)) != 0)
			return (1);
		if (strlen(r->anchor->path) > strlen(a))
			strlcat(anchor_call, r->anchor->path + (a[0] ?
			    strlen(a) + 1 : 0), len);
	}
	if (r->r.anchor_wildcard)
		strlcat(anchor_call, anchor_call[0] ? "/*" : "*", len);
	return (0);
}

static void
pf_keth_anchor_remove(struct pf_keth_rule *r)
{
	if (r->anchor == NULL)
		return;
	if (r->anchor->refcnt <= 0) {
		printf("%s: broken refcount\n", __func__);
		r->anchor = NULL;
		return;
	}
	if (--r->anchor->refcnt == 0)
		pf_remove_if_empty_keth_ruleset(&r->anchor->ruleset);
	r->anchor = NULL;
}

/* ------------------------------------------------------------------ */
/* Rules and transactions                                              */
/* ------------------------------------------------------------------ */

static void
pf_keth_rule_counters_free(struct pf_keth_rule *rule)
{
	int i;

	if (rule->evaluations != NULL)
		counter_u64_free(rule->evaluations);
	for (i = 0; i < 2; i++) {
		if (rule->packets[i] != NULL)
			counter_u64_free(rule->packets[i]);
		if (rule->bytes[i] != NULL)
			counter_u64_free(rule->bytes[i]);
	}
}

/* Release what pf_eth_addrule() took, with PF_LOCK held. */
static void
pf_free_eth_rule(struct pf_keth_rule *rule)
{
	PF_ASSERT_LOCKED();

	if (rule->r.tag)
		pf_tag_unref(rule->r.tag);
	if (rule->r.match_tag)
		pf_tag_unref(rule->r.match_tag);
	if (rule->r.qid)
		pf_qid_unref(rule->r.qid);
	pfi_kif_unref(rule->bridge_to, PFI_KIF_REF_RULE);
	pfi_kif_unref(rule->kif, PFI_KIF_REF_RULE);
	pf_tbladdr_remove(&rule->r.ipsrc.addr);
	pf_tbladdr_remove(&rule->r.ipdst.addr);
	pf_keth_anchor_remove(rule);
	pf_keth_rule_counters_free(rule);
	free(rule, M_PF);
}

static void
pf_keth_purge(struct pf_keth_ruleq *rules)
{
	struct pf_keth_rule *rule;

	while ((rule = TAILQ_FIRST(rules)) != NULL) {
		TAILQ_REMOVE(rules, rule, entries);
		pf_free_eth_rule(rule);
	}
}

int
pf_eth_begin(u_int32_t *ticket, const char *anchor)
{
	struct pf_keth_ruleset *rs;

	PF_ASSERT_LOCKED();

	if ((rs = pf_find_or_create_keth_ruleset(anchor)) == NULL)
		return (EINVAL);
	pf_keth_purge(rs->inactive.rules);
	*ticket = ++rs->inactive.ticket;
	rs->inactive.open = 1;
	return (0);
}

void
pf_eth_rollback(u_int32_t ticket, const char *anchor)
{
	struct pf_keth_ruleset *rs;

	PF_ASSERT_LOCKED();

	rs = pf_find_keth_ruleset(anchor);
	if (rs == NULL || !rs->inactive.open || ticket != rs->inactive.ticket)
		return;
	pf_keth_purge(rs->inactive.rules);
	rs->inactive.open = 0;
	pf_remove_if_empty_keth_ruleset(rs);
}

int
pf_eth_ticket_valid(u_int32_t ticket, const char *anchor)
{
	struct pf_keth_ruleset *rs;

	PF_ASSERT_LOCKED();

	rs = pf_find_keth_ruleset(anchor);
	return (rs != NULL && rs->inactive.open &&
	    ticket == rs->inactive.ticket);
}

#define	PF_SET_SKIP_STEPS(i)					\
	do {							\
		while (head[i] != cur) {			\
			head[i]->skip[i] = cur;			\
			head[i] = TAILQ_NEXT(head[i], entries);	\
		}						\
	} while (0)

static void
pf_eth_calc_skip_steps(struct pf_keth_ruleq *rules)
{
	struct pf_keth_rule *cur, *prev, *head[PFE_SKIP_COUNT];
	int i;

	cur = TAILQ_FIRST(rules);
	prev = cur;
	for (i = 0; i < PFE_SKIP_COUNT; ++i)
		head[i] = cur;
	while (cur != NULL) {
		if (cur->kif != prev->kif || cur->r.ifnot != prev->r.ifnot)
			PF_SET_SKIP_STEPS(PFE_SKIP_IFP);
		if (cur->r.direction != prev->r.direction)
			PF_SET_SKIP_STEPS(PFE_SKIP_DIR);
		if (cur->r.proto != prev->r.proto)
			PF_SET_SKIP_STEPS(PFE_SKIP_PROTO);
		if (memcmp(&cur->r.src, &prev->r.src, sizeof(cur->r.src)) != 0)
			PF_SET_SKIP_STEPS(PFE_SKIP_SRC_ADDR);
		if (memcmp(&cur->r.dst, &prev->r.dst, sizeof(cur->r.dst)) != 0)
			PF_SET_SKIP_STEPS(PFE_SKIP_DST_ADDR);
		if (cur->r.ipsrc.neg != prev->r.ipsrc.neg ||
		    pf_addr_wrap_neq(&cur->r.ipsrc.addr, &prev->r.ipsrc.addr))
			PF_SET_SKIP_STEPS(PFE_SKIP_SRC_IP_ADDR);
		if (cur->r.ipdst.neg != prev->r.ipdst.neg ||
		    pf_addr_wrap_neq(&cur->r.ipdst.addr, &prev->r.ipdst.addr))
			PF_SET_SKIP_STEPS(PFE_SKIP_DST_IP_ADDR);
		prev = cur;
		cur = TAILQ_NEXT(cur, entries);
	}
	for (i = 0; i < PFE_SKIP_COUNT; ++i)
		PF_SET_SKIP_STEPS(i);
}

int
pf_eth_commit(u_int32_t ticket, const char *anchor)
{
	struct pf_keth_ruleset *rs;
	struct pf_keth_ruleq *rules;

	PF_ASSERT_LOCKED();

	rs = pf_find_keth_ruleset(anchor);
	if (rs == NULL)
		return (EINVAL);
	if (!rs->inactive.open || ticket != rs->inactive.ticket)
		return (EBUSY);

	pf_eth_calc_skip_steps(rs->inactive.rules);
	/* The packet path reads the rules with pf_lock held for reading. */
	rules = rs->active.rules;
	rs->active.rules = rs->inactive.rules;
	rs->inactive.rules = rules;
	rs->active.ticket = rs->inactive.ticket;

	pf_keth_purge(rs->inactive.rules);
	rs->inactive.open = 0;
	pf_remove_if_empty_keth_ruleset(rs);
	return (0);
}

/* Take the table of an "l3" address, as FreeBSD's pfr_eth_attach_table(). */
static int
pf_eth_tbladdr_setup(struct pf_keth_ruleset *ers, struct pf_addr_wrap *aw)
{
	struct pf_ruleset *rs;
	int error;

	if (aw->type != PF_ADDR_TABLE)
		return (0);
	rs = pf_find_or_create_ruleset(ers->anchor != NULL ?
	    ers->anchor->path : "");
	if (rs == NULL)
		return (ENOMEM);
	error = pf_tbladdr_setup(rs, aw, PR_NOWAIT) ? ENOMEM : 0;
	pf_remove_if_empty_ruleset(rs);
	return (error);
}

static int
pf_eth_addr_valid(const struct pf_rule_addr *a)
{
	if (a->port_op != PF_OP_NONE)
		return (0);
	switch (a->addr.type) {
	case PF_ADDR_ADDRMASK:
		return (1);
	case PF_ADDR_TABLE:
		return (strnlen(a->addr.v.tblname, sizeof(a->addr.v.tblname)) <
		    sizeof(a->addr.v.tblname) && a->addr.v.tblname[0] != '\0');
	default:
		return (0);
	}
}

static int
pf_eth_rule_check(struct pfioc_eth_rule *pr)
{
	struct pf_eth_rule *r = &pr->rule;
	int i;

	if (strnlen(pr->anchor, sizeof(pr->anchor)) >= sizeof(pr->anchor) ||
	    strnlen(pr->anchor_call, sizeof(pr->anchor_call)) >=
	    sizeof(pr->anchor_call))
		return (ENAMETOOLONG);
	if (strnlen(r->ifname, sizeof(r->ifname)) >= sizeof(r->ifname) ||
	    strnlen(r->bridge_to, sizeof(r->bridge_to)) >=
	    sizeof(r->bridge_to) ||
	    strnlen(r->tagname, sizeof(r->tagname)) >= sizeof(r->tagname) ||
	    strnlen(r->match_tagname, sizeof(r->match_tagname)) >=
	    sizeof(r->match_tagname) ||
	    strnlen(r->qname, sizeof(r->qname)) >= sizeof(r->qname))
		return (EINVAL);
	for (i = 0; i < PF_ETH_LABEL_COUNT; i++)
		if (strnlen(r->label[i], sizeof(r->label[i])) >=
		    sizeof(r->label[i]))
			return (EINVAL);
	if (r->action != PF_PASS && r->action != PF_DROP)
		return (EINVAL);
	if (r->direction != PF_INOUT && r->direction != PF_IN &&
	    r->direction != PF_OUT)
		return (EINVAL);
	if (r->dnflags & ~PF_DN_IS_PIPE)
		return (EINVAL);
	if (!pf_eth_addr_valid(&r->ipsrc) || !pf_eth_addr_valid(&r->ipdst))
		return (EINVAL);
	if (r->bridge_to[0] != '\0' && pr->anchor_call[0] != '\0')
		return (EINVAL);
	return (0);
}

static int
pf_eth_addrule(struct pfioc_eth_rule *pr)
{
	struct pf_keth_ruleset *ruleset;
	struct pf_keth_rule *rule, *tail;
	struct pfi_kif *kif = NULL, *bkif = NULL;
	int error, i;

	if ((error = pf_eth_rule_check(pr)) != 0)
		return (error);

	rule = malloc(sizeof(*rule), M_PF, M_WAITOK | M_ZERO);
	rule->r = pr->rule;
	rule->r.ipsrc.addr.p.tbl = NULL;
	rule->r.ipdst.addr.p.tbl = NULL;
	rule->r.tag = rule->r.match_tag = rule->r.qid = 0;
	rule->r.evaluations = 0;
	rule->r.packets[0] = rule->r.packets[1] = 0;
	rule->r.bytes[0] = rule->r.bytes[1] = 0;
	rule->r.last_active = 0;
	rule->evaluations = counter_u64_alloc(M_WAITOK);
	for (i = 0; i < 2; i++) {
		rule->packets[i] = counter_u64_alloc(M_WAITOK);
		rule->bytes[i] = counter_u64_alloc(M_WAITOK);
	}
	if (rule->r.ifname[0] != '\0')
		kif = pfi_kif_alloc(rule->r.ifname, M_WAITOK);
	if (rule->r.bridge_to[0] != '\0')
		bkif = pfi_kif_alloc(rule->r.bridge_to, M_WAITOK);

	NET_LOCK();
	PF_LOCK();
	ruleset = pf_find_keth_ruleset(pr->anchor);
	if (ruleset == NULL || pr->ticket != ruleset->inactive.ticket ||
	    !ruleset->inactive.open) {
		error = ruleset == NULL ? EINVAL : EBUSY;
		PF_UNLOCK();
		NET_UNLOCK();
		pfi_kif_free(kif);
		pfi_kif_free(bkif);
		pf_keth_rule_counters_free(rule);
		free(rule, M_PF);
		return (error);
	}

	/* From here on pf_free_eth_rule() releases whatever was taken. */
	rule->kif = pf_kif_setup(kif);
	rule->bridge_to = pf_kif_setup(bkif);
	if (rule->r.tagname[0] != '\0' &&
	    (rule->r.tag = pf_tagname2tag(rule->r.tagname, 1)) == 0)
		error = EBUSY;
	if (rule->r.match_tagname[0] != '\0' &&
	    (rule->r.match_tag = pf_tagname2tag(rule->r.match_tagname,
	    1)) == 0)
		error = EBUSY;
	if (rule->r.qname[0] != '\0' &&
	    (rule->r.qid = pf_qname2qid(rule->r.qname, 1)) == 0)
		error = EBUSY;
	if (error == 0)
		error = pf_eth_tbladdr_setup(ruleset, &rule->r.ipsrc.addr);
	if (error == 0)
		error = pf_eth_tbladdr_setup(ruleset, &rule->r.ipdst.addr);
	if (error == 0 && pf_keth_anchor_setup(rule, ruleset, pr->anchor_call))
		error = EINVAL;
	if (error != 0) {
		pf_free_eth_rule(rule);
		PF_UNLOCK();
		NET_UNLOCK();
		return (error);
	}

	tail = TAILQ_LAST(ruleset->inactive.rules, pf_keth_ruleq);
	rule->r.nr = (tail != NULL) ? tail->r.nr + 1 : 0;
	TAILQ_INSERT_TAIL(ruleset->inactive.rules, rule, entries);
	PF_UNLOCK();
	NET_UNLOCK();
	return (0);
}

static int
pf_eth_getrules(struct pfioc_eth_rule *pr)
{
	struct pf_keth_ruleset *rs;
	struct pf_keth_rule *tail;

	if (strnlen(pr->anchor, sizeof(pr->anchor)) >= sizeof(pr->anchor))
		return (ENAMETOOLONG);
	PF_LOCK();
	if ((rs = pf_find_keth_ruleset(pr->anchor)) == NULL) {
		PF_UNLOCK();
		return (ENOENT);
	}
	pr->ticket = rs->active.ticket;
	tail = TAILQ_LAST(rs->active.rules, pf_keth_ruleq);
	pr->nr = (tail != NULL) ? tail->r.nr + 1 : 0;
	PF_UNLOCK();
	return (0);
}

static int
pf_eth_getrule(struct pfioc_eth_rule *pr)
{
	struct pf_keth_ruleset *rs;
	struct pf_keth_rule *rule;
	int i;

	if (strnlen(pr->anchor, sizeof(pr->anchor)) >= sizeof(pr->anchor))
		return (ENAMETOOLONG);
	PF_LOCK();
	if ((rs = pf_find_keth_ruleset(pr->anchor)) == NULL) {
		PF_UNLOCK();
		return (ENOENT);
	}
	if (pr->ticket != rs->active.ticket) {
		PF_UNLOCK();
		return (EBUSY);
	}
	TAILQ_FOREACH(rule, rs->active.rules, entries)
		if (rule->r.nr == pr->nr)
			break;
	if (rule == NULL) {
		PF_UNLOCK();
		return (ENOENT);
	}
	pr->rule = rule->r;
	pf_addr_copyout(&pr->rule.ipsrc.addr);
	pf_addr_copyout(&pr->rule.ipdst.addr);
	pr->rule.evaluations = counter_u64_fetch(rule->evaluations);
	for (i = 0; i < 2; i++) {
		pr->rule.packets[i] = counter_u64_fetch(rule->packets[i]);
		pr->rule.bytes[i] = counter_u64_fetch(rule->bytes[i]);
	}
	pr->rule.last_active = rule->last_active;
	if (pf_keth_anchor_copyout(rs, rule, pr->anchor_call,
	    sizeof(pr->anchor_call))) {
		PF_UNLOCK();
		return (EBUSY);
	}
	if (pr->action == PF_GET_CLR_CNTR) {
		counter_u64_zero(rule->evaluations);
		for (i = 0; i < 2; i++) {
			counter_u64_zero(rule->packets[i]);
			counter_u64_zero(rule->bytes[i]);
		}
	}
	PF_UNLOCK();
	return (0);
}

/* DIOCGETETHRULESETS and DIOCGETETHRULESET, as their OpenBSD siblings. */
static int
pf_eth_getrulesets(struct pfioc_ruleset *pr, int one)
{
	struct pf_keth_ruleset *ruleset;
	struct pf_keth_anchor *anchor;
	u_int32_t nr = 0;

	if (strnlen(pr->path, sizeof(pr->path)) >= sizeof(pr->path))
		return (ENAMETOOLONG);
	PF_LOCK();
	if ((ruleset = pf_find_keth_ruleset(pr->path)) == NULL) {
		PF_UNLOCK();
		return (ENOENT);
	}
	/* Count the children, or stop at child number pr->nr. */
	if (ruleset->anchor == NULL) {
		RB_FOREACH(anchor, pf_keth_anchor_global, &V_pf_keth_anchors)
			if (anchor->parent == NULL && nr++ == pr->nr && one)
				break;
	} else {
		RB_FOREACH(anchor, pf_keth_anchor_node,
		    &ruleset->anchor->children)
			if (nr++ == pr->nr && one)
				break;
	}
	if (!one) {
		pr->nr = nr;
		PF_UNLOCK();
		return (0);
	}
	if (anchor == NULL) {
		PF_UNLOCK();
		return (EBUSY);
	}
	strlcpy(pr->name, anchor->name, sizeof(pr->name));
	if (ruleset->anchor != NULL)
		strlcpy(pr->path, ruleset->anchor->path, sizeof(pr->path));
	else
		pr->path[0] = '\0';
	PF_UNLOCK();
	return (0);
}

int
pf_eth_is_ioctl(u_long cmd)
{
	switch (cmd) {
	case DIOCADDETHRULE:
	case DIOCGETETHRULES:
	case DIOCGETETHRULE:
	case DIOCGETETHRULESETS:
	case DIOCGETETHRULESET:
		return (1);
	}
	return (0);
}

/* The DIOC*ETHRULE* ioctls, with pfioctl()'s permission checks. */
int
pf_eth_ioctl(u_long cmd, caddr_t addr, int flags)
{
	int error;

	if (cmd == DIOCADDETHRULE && securelevel > 1)
		return (EPERM);
	if (!(flags & FWRITE) && (cmd == DIOCADDETHRULE ||
	    (cmd == DIOCGETETHRULE &&
	    ((struct pfioc_eth_rule *)addr)->action == PF_GET_CLR_CNTR)))
		return (EACCES);

	rw_enter_write(&pfioctl_rw);
	switch (cmd) {
	case DIOCADDETHRULE:
		error = pf_eth_addrule((struct pfioc_eth_rule *)addr);
		break;
	case DIOCGETETHRULES:
		error = pf_eth_getrules((struct pfioc_eth_rule *)addr);
		break;
	case DIOCGETETHRULE:
		error = pf_eth_getrule((struct pfioc_eth_rule *)addr);
		break;
	case DIOCGETETHRULESETS:
		error = pf_eth_getrulesets((struct pfioc_ruleset *)addr, 0);
		break;
	case DIOCGETETHRULESET:
		error = pf_eth_getrulesets((struct pfioc_ruleset *)addr, 1);
		break;
	default:
		error = ENODEV;
		break;
	}
	rw_exit_write(&pfioctl_rw);
	return (error);
}

/* ------------------------------------------------------------------ */
/* Packet path                                                         */
/* ------------------------------------------------------------------ */

struct pf_keth_anchor_stackframe {
	struct pf_keth_ruleset	*rs;
	struct pf_keth_rule	*r;
	struct pf_keth_anchor	*child;
	int			 match;
};

static void
pf_step_into_keth_anchor(struct pf_keth_anchor_stackframe *stack, int *depth,
    struct pf_keth_ruleset **rs, struct pf_keth_rule **r, int *match)
{
	struct pf_keth_anchor_stackframe *f;

	*match = 0;
	if (*depth >= PF_ANCHOR_STACK_MAX) {
		printf("%s: anchor stack overflow on %s\n",
		    __func__, (*r)->anchor->name);
		*r = TAILQ_NEXT(*r, entries);
		return;
	}
	f = stack + (*depth)++;
	f->rs = *rs;
	f->r = *r;
	f->match = 0;
	if ((*r)->r.anchor_wildcard) {
		struct pf_keth_anchor_node *parent = &(*r)->anchor->children;

		if ((f->child = RB_MIN(pf_keth_anchor_node, parent)) == NULL) {
			*r = NULL;
			return;
		}
		*rs = &f->child->ruleset;
	} else {
		f->child = NULL;
		*rs = &(*r)->anchor->ruleset;
	}
	*r = TAILQ_FIRST((*rs)->active.rules);
}

static int
pf_step_out_of_keth_anchor(struct pf_keth_anchor_stackframe *stack,
    int *depth, struct pf_keth_ruleset **rs, struct pf_keth_rule **r,
    int *match)
{
	struct pf_keth_anchor_stackframe *f;
	struct pf_keth_rule *fr;
	int quick = 0;

	do {
		if (*depth <= 0)
			break;
		f = stack + *depth - 1;
		fr = f->r;
		if (f->child != NULL) {
			/* A wildcard anchor: on to the next child. */
			if (*match) {
				/* If any of "*" matched, "foo/ *" matched. */
				f->match = 1;
				*match = 0;
			}
			f->child = RB_NEXT(pf_keth_anchor_node,
			    &fr->anchor->children, f->child);
			if (f->child != NULL) {
				*rs = &f->child->ruleset;
				*r = TAILQ_FIRST((*rs)->active.rules);
				if (*r == NULL)
					continue;
				else
					break;
			}
		}
		(*depth)--;
		*rs = f->rs;
		if (f->match || *match)
			quick = fr->r.quick;
		*r = TAILQ_NEXT(fr, entries);
	} while (*r == NULL);

	return (quick);
}

static int
pf_match_eth_addr(const u_int8_t *a, const struct pf_eth_addr *r)
{
	int i, match = 1;

	/* Always matches if not set */
	if (!r->isset)
		return (!r->neg);
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		if ((a[i] & r->mask[i]) != (r->addr[i] & r->mask[i])) {
			match = 0;
			break;
		}
	}
	return (match ^ (r->neg != 0));
}

static int
pf_match_eth_tag(struct pf_keth_rule *r, int *tag, int mtag)
{
	if (*tag == -1)
		*tag = mtag;
	return ((!r->r.match_tag_not && r->r.match_tag == *tag) ||
	    (r->r.match_tag_not && r->r.match_tag != *tag));
}

static void
pf_bridge_to(struct pf_keth_rule *r, struct ifnet *ifp, struct mbuf *m)
{
	SDT_PROBE2(pf, eth, bridge_to, transmit, r, ifp);
	/* If we don't have the interface drop the packet. */
	if (ifp == NULL) {
		m_freem(m);
		return;
	}
	switch (ifp->if_type) {
	case IFT_ETHER:
	case IFT_XETHER:
	case IFT_L2VLAN:
	case IFT_BRIDGE:
	case IFT_IEEE8023ADLAG:
		break;
	default:
		m_freem(m);
		return;
	}
	(void)ifp->if_transmit(ifp, m);
}

/* Forget the layer-2 dummynet pass, and dummynet's own rule tag. */
static void
pf_eth_dn_clear(struct mbuf *m)
{
	struct pkthdr_pf *t;
	struct m_tag *mtag;

	if ((t = PF_MTAG_W(m)) != NULL)
		t->dn_flags &= ~PF_DN_TAG_ETHER;
	mtag = m_tag_locate(m, MTAG_IPFW_RULE, 0, NULL);
	if (mtag != NULL)
		m_tag_delete(m, mtag);
}

static int
pf_test_eth_rule(int dir, struct pfi_kif *kif, struct ifnet *ifp,
    struct mbuf **m0)
{
	struct ip ip;
#ifdef INET6
	struct ip6_hdr ip6;
#endif
	struct pf_keth_anchor_stackframe anchor_stack[PF_ANCHOR_STACK_MAX];
	struct mbuf *m = *m0;
	struct ether_header *e;
	struct pf_keth_rule *r, *rm;
	struct pf_keth_ruleset *ruleset;
	struct pf_addr *src = NULL, *dst = NULL;
	struct pkthdr_pf *t;
	struct ifnet *bridge_ifp = NULL;
	struct ip_fw_args dnflow;
	sa_family_t af = 0;
	u_int16_t proto, dnpipe;
	int asd = 0, match = 0, tag = -1, bridge = 0;
	u_int8_t action, dnflags;

	NET_EPOCH_ASSERT();

	SDT_PROBE3(pf, eth, test_rule, entry, dir, ifp, m);

	if (PF_MTAG_R(m)->dn_flags & PF_DN_TAG_ETHER) {
		/*
		 * Dummynet reinjects packets after their delay.  We have
		 * already filtered them: pass once (we may see the packet on
		 * both the input and the output hooks).
		 */
		SDT_PROBE2(pf, eth, dummynet, reinject, dir, ifp);
		pf_eth_dn_clear(m);
		return (PF_PASS);
	}

	if (__predict_false(m->m_len < sizeof(struct ether_header)) &&
	    (m = *m0 = m_pullup(*m0, sizeof(struct ether_header))) == NULL) {
		DPFPRINTF(LOG_NOTICE, "%s: m_len < sizeof(struct ether_header)"
		    ", pullup failed", __func__);
		return (PF_DROP);
	}
	e = mtod(m, struct ether_header *);
	proto = ntohs(e->ether_type);

	switch (proto) {
	case ETHERTYPE_IP:
		if (m_length(m, NULL) < (sizeof(struct ether_header) +
		    sizeof(ip)))
			return (PF_DROP);
		af = AF_INET;
		m_copydata(m, sizeof(struct ether_header), sizeof(ip),
		    (caddr_t)&ip);
		src = (struct pf_addr *)&ip.ip_src;
		dst = (struct pf_addr *)&ip.ip_dst;
		break;
#ifdef INET6
	case ETHERTYPE_IPV6:
		if (m_length(m, NULL) < (sizeof(struct ether_header) +
		    sizeof(ip6)))
			return (PF_DROP);
		af = AF_INET6;
		m_copydata(m, sizeof(struct ether_header), sizeof(ip6),
		    (caddr_t)&ip6);
		src = (struct pf_addr *)&ip6.ip6_src;
		dst = (struct pf_addr *)&ip6.ip6_dst;
		break;
#endif
	}

	rw_enter_read(&pf_lock);

	ruleset = V_pf_keth;
	for (r = TAILQ_FIRST(ruleset->active.rules), rm = NULL; r != NULL;) {
		counter_u64_add(r->evaluations, 1);
		SDT_PROBE2(pf, eth, test_rule, test, r->r.nr, r);

		if (pfi_kif_match_ifp(r->kif, kif, ifp) == r->r.ifnot) {
			SDT_PROBE3(pf, eth, test_rule, mismatch, r->r.nr, r,
			    "kif");
			r = r->skip[PFE_SKIP_IFP];
		} else if (r->r.direction && r->r.direction != dir) {
			SDT_PROBE3(pf, eth, test_rule, mismatch, r->r.nr, r,
			    "dir");
			r = r->skip[PFE_SKIP_DIR];
		} else if (r->r.proto && r->r.proto != proto) {
			SDT_PROBE3(pf, eth, test_rule, mismatch, r->r.nr, r,
			    "proto");
			r = r->skip[PFE_SKIP_PROTO];
		} else if (!pf_match_eth_addr(e->ether_shost, &r->r.src)) {
			SDT_PROBE3(pf, eth, test_rule, mismatch, r->r.nr, r,
			    "src");
			r = r->skip[PFE_SKIP_SRC_ADDR];
		} else if (!pf_match_eth_addr(e->ether_dhost, &r->r.dst)) {
			SDT_PROBE3(pf, eth, test_rule, mismatch, r->r.nr, r,
			    "dst");
			r = r->skip[PFE_SKIP_DST_ADDR];
		} else if (src != NULL && PF_MISMATCHAW_IFP(&r->r.ipsrc.addr, src,
		    af, r->r.ipsrc.neg, kif, ifp, M_GETFIB(m))) {
			SDT_PROBE3(pf, eth, test_rule, mismatch, r->r.nr, r,
			    "ip_src");
			r = r->skip[PFE_SKIP_SRC_IP_ADDR];
		} else if (dst != NULL && PF_MISMATCHAW_IFP(&r->r.ipdst.addr, dst,
		    af, r->r.ipdst.neg, kif, ifp, M_GETFIB(m))) {
			SDT_PROBE3(pf, eth, test_rule, mismatch, r->r.nr, r,
			    "ip_dst");
			r = r->skip[PFE_SKIP_DST_IP_ADDR];
		} else if (r->r.match_tag && !pf_match_eth_tag(r, &tag,
		    PF_MTAG_R(m)->tag)) {
			SDT_PROBE3(pf, eth, test_rule, mismatch, r->r.nr, r,
			    "match_tag");
			r = TAILQ_NEXT(r, entries);
		} else {
			if (r->r.tag)
				tag = r->r.tag;
			if (r->anchor == NULL) {
				/* Rule matches */
				rm = r;
				SDT_PROBE2(pf, eth, test_rule, match, r->r.nr,
				    r);
				if (r->r.quick)
					break;
				r = TAILQ_NEXT(r, entries);
			} else
				pf_step_into_keth_anchor(anchor_stack, &asd,
				    &ruleset, &r, &match);
		}
		if (r == NULL && pf_step_out_of_keth_anchor(anchor_stack, &asd,
		    &ruleset, &r, &match))
			break;
	}

	r = rm;

	SDT_PROBE2(pf, eth, test_rule, final_match,
	    (r != NULL ? (int)r->r.nr : -1), r);

	/* Default to pass. */
	if (r == NULL) {
		rw_exit_read(&pf_lock);
		return (PF_PASS);
	}

	/* Execute action. */
	counter_u64_add(r->packets[dir == PF_OUT], 1);
	counter_u64_add(r->bytes[dir == PF_OUT], m_length(m, NULL));
	r->last_active = time_second;	/* a racy word store is fine */

	/* Shortcut. Don't tag if we're just going to drop anyway. */
	if (r->r.action == PF_DROP) {
		rw_exit_read(&pf_lock);
		return (PF_DROP);
	}

	if (tag > 0 || r->r.qid != 0 || r->r.dnpipe != 0) {
		if ((t = PF_MTAG_W(m)) == NULL) {
			rw_exit_read(&pf_lock);
			return (PF_DROP);
		}
		if (tag > 0)
			t->tag = tag;
		if (r->r.qid != 0)
			t->qid = r->r.qid;
	}

	action = r->r.action;
	if (r->bridge_to != NULL) {
		bridge = 1;
		bridge_ifp = r->bridge_to->pfik_ifp;
	}
	dnpipe = r->r.dnpipe;
	dnflags = r->r.dnflags;
	if (dnpipe != 0)
		SDT_PROBE3(pf, eth, dummynet, submit, r, dnpipe, dir);
	rw_exit_read(&pf_lock);

	if (dnpipe != 0) {
		/* Drop packet if dummynet is not loaded. */
		if (ip_dn_io_ptr == NULL)
			return (PF_DROP);

		/*
		 * We don't have port numbers here, so flows can only be told
		 * apart by their IP addresses, but it's better than nothing.
		 */
		memset(&dnflow, 0, sizeof(dnflow));
		dnflow.rule.info = dnpipe | IPFW_IS_DUMMYNET;
		if (dnflags & PF_DN_IS_PIPE)
			dnflow.rule.info |= IPFW_IS_PIPE;
		dnflow.f_id.extra = dnflow.rule.info;
		dnflow.flags = (dir == PF_IN) ? IPFW_ARGS_IN : IPFW_ARGS_OUT;
		dnflow.flags |= IPFW_ARGS_ETHER;
		dnflow.ifp = ifp;
		switch (af) {
		case AF_INET:
			dnflow.f_id.addr_type = 4;
			dnflow.f_id.src_ip = ntohl(src->v4.s_addr);
			dnflow.f_id.dst_ip = ntohl(dst->v4.s_addr);
			break;
#ifdef INET6
		case AF_INET6:
			dnflow.flags |= IPFW_ARGS_IP6;
			dnflow.f_id.addr_type = 6;
			dnflow.f_id.src_ip6 = src->v6;
			dnflow.f_id.dst_ip6 = dst->v6;
			break;
#endif
		}

		if ((t = PF_MTAG_W(m)) == NULL)
			return (PF_DROP);
		t->dn_flags |= PF_DN_TAG_ETHER;
		ip_dn_io_ptr(m0, &dnflow);
		if (*m0 == NULL)
			return (action);	/* queued in or dropped by dummynet */
		pf_eth_dn_clear(*m0);
	}

	if (action == PF_PASS && bridge) {
		pf_bridge_to(r, bridge_ifp, *m0);
		*m0 = NULL; /* We've eaten the packet. */
	}

	return (action);
}

static int
pf_test_eth(int dir, struct ifnet *ifp, struct mbuf **m0)
{
	struct pfi_kif *kif;

	M_ASSERTPKTHDR(*m0);
	NET_EPOCH_ASSERT();

	if (!pf_status.running)
		return (PF_PASS);

	kif = (struct pfi_kif *)ifp->if_pf_kif;
	if (kif == NULL) {
		DPFPRINTF(LOG_ERR, "%s: kif == NULL, if_xname %s", __func__,
		    ifp->if_xname);
		return (PF_DROP);
	}
	if (kif->pfik_flags & PFI_IFLAG_SKIP)
		return (PF_PASS);
	if ((*m0)->m_flags & M_SKIP_FIREWALL)
		return (PF_PASS);
	if (__predict_false(!M_WRITABLE(*m0))) {
		*m0 = m_unshare(*m0, M_NOWAIT);
		if (*m0 == NULL)
			return (PF_DROP);
	}

	/* Stateless! */
	return (pf_test_eth_rule(dir, kif, ifp, m0));
}

static pfil_return_t
pf_eth_result(int action, struct mbuf **m)
{
	if (*m == NULL)
		return (PFIL_CONSUMED);
	if (action != PF_PASS) {
		m_freem(*m);
		*m = NULL;
		return (PFIL_DROPPED);
	}
	return (PFIL_PASS);
}

static pfil_return_t
pf_eth_check_in(struct mbuf **m, struct ifnet *ifp, int flags,
    void *ruleset, struct inpcb *inp)
{
	return (pf_eth_result(pf_test_eth(PF_IN, ifp, m), m));
}

static pfil_return_t
pf_eth_check_out(struct mbuf **m, struct ifnet *ifp, int flags,
    void *ruleset, struct inpcb *inp)
{
	return (pf_eth_result(pf_test_eth(PF_OUT, ifp, m), m));
}

/* ------------------------------------------------------------------ */
/* pfil(9) link-layer hooks                                            */
/* ------------------------------------------------------------------ */

/*
 * As in FreeBSD, the hooks are only linked while the main ether ruleset
 * has rules, so that the ether pfil head costs nothing otherwise.
 */
static struct sx pf_eth_hook_sx;
SX_SYSINIT(pf_eth_hook, &pf_eth_hook_sx, "pf ether hooks");

VNET_DEFINE_STATIC(pfil_hook_t, pf_eth_in_hook);
VNET_DEFINE_STATIC(pfil_hook_t, pf_eth_out_hook);
VNET_DEFINE_STATIC(int, pf_eth_hooked);
VNET_DEFINE_STATIC(int, pf_eth_closing);	/* vnet teardown: never hook */
#define	V_pf_eth_in_hook	VNET(pf_eth_in_hook)
#define	V_pf_eth_out_hook	VNET(pf_eth_out_hook)
#define	V_pf_eth_hooked		VNET(pf_eth_hooked)
#define	V_pf_eth_closing	VNET(pf_eth_closing)

static void
pf_eth_hook(void)
{
	struct pfil_hook_args pha = {
		.pa_version = PFIL_VERSION,
		.pa_modname = "pf",
		.pa_type = PFIL_TYPE_ETHERNET,
	};
	struct pfil_link_args pla = {
		.pa_version = PFIL_VERSION,
	};
	int ret __diagused;

	sx_assert(&pf_eth_hook_sx, SA_XLOCKED);
	if (V_pf_eth_hooked)
		return;

	pha.pa_mbuf_chk = pf_eth_check_in;
	pha.pa_flags = PFIL_IN;
	pha.pa_rulname = "eth-in";
	V_pf_eth_in_hook = pfil_add_hook(&pha);
	pla.pa_flags = PFIL_IN | PFIL_HEADPTR | PFIL_HOOKPTR;
	pla.pa_head = V_link_pfil_head;
	pla.pa_hook = V_pf_eth_in_hook;
	ret = pfil_link(&pla);
	MPASS(ret == 0);
	pha.pa_mbuf_chk = pf_eth_check_out;
	pha.pa_flags = PFIL_OUT;
	pha.pa_rulname = "eth-out";
	V_pf_eth_out_hook = pfil_add_hook(&pha);
	pla.pa_flags = PFIL_OUT | PFIL_HEADPTR | PFIL_HOOKPTR;
	pla.pa_head = V_link_pfil_head;
	pla.pa_hook = V_pf_eth_out_hook;
	ret = pfil_link(&pla);
	MPASS(ret == 0);
	V_pf_eth_hooked = 1;
	SDT_PROBE1(pf, eth, hook, link, 1);
}

static void
pf_eth_unhook(void)
{
	sx_assert(&pf_eth_hook_sx, SA_XLOCKED);
	if (!V_pf_eth_hooked)
		return;
	pfil_remove_hook(V_pf_eth_in_hook);
	pfil_remove_hook(V_pf_eth_out_hook);
	V_pf_eth_hooked = 0;
	SDT_PROBE1(pf, eth, hook, link, 0);
}

/* After a transaction: link the hooks while there are ether rules. */
void
pf_eth_hook_update(void)
{
	int want;

	sx_xlock(&pf_eth_hook_sx);
	PF_LOCK();
	want = !V_pf_eth_closing && V_pf_keth != NULL &&
	    !TAILQ_EMPTY(V_pf_keth->active.rules);
	PF_UNLOCK();
	if (want)
		pf_eth_hook();
	else
		pf_eth_unhook();
	sx_xunlock(&pf_eth_hook_sx);
}

/* ------------------------------------------------------------------ */
/* Per-vnet setup and teardown                                         */
/* ------------------------------------------------------------------ */

void
pf_eth_vnet_init(void)
{
	struct pf_keth_ruleset *rs;

	rs = malloc(sizeof(*rs), M_PF, M_WAITOK | M_ZERO);
	pf_init_keth(rs);
	RB_INIT(&V_pf_keth_anchors);
	V_pf_keth_nanchors = 0;
	V_pf_eth_closing = 0;
	V_pf_keth = rs;
}

/* Unlink the hooks; the caller then waits for the packets in flight. */
void
pf_eth_vnet_unhook(void)
{
	sx_xlock(&pf_eth_hook_sx);
	V_pf_eth_closing = 1;
	pf_eth_unhook();
	sx_xunlock(&pf_eth_hook_sx);
}

/* Empty one ruleset by committing an empty transaction. */
static void
pf_eth_flush_ruleset(const char *path)
{
	u_int32_t ticket;

	if (pf_eth_begin(&ticket, path) == 0)
		(void)pf_eth_commit(ticket, path);
}

/*
 * Free every ether rule and anchor, before the tables and interfaces the
 * rules refer to go away.
 */
void
pf_eth_vnet_fini(void)
{
	struct pf_keth_anchor *a;
	char *path;
	int found;

	path = malloc(MAXPATHLEN, M_PF, M_WAITOK);
	NET_LOCK();
	PF_LOCK();
	pf_eth_flush_ruleset("");
	/*
	 * Anchors only hold references from anchor rules: once every ruleset
	 * is empty, the last reference dropped has removed each anchor.
	 */
	do {
		found = 0;
		RB_FOREACH(a, pf_keth_anchor_global, &V_pf_keth_anchors) {
			if (!TAILQ_EMPTY(a->ruleset.active.rules) ||
			    !TAILQ_EMPTY(a->ruleset.inactive.rules) ||
			    a->ruleset.inactive.open) {
				strlcpy(path, a->path, MAXPATHLEN);
				found = 1;
				break;
			}
		}
		if (found)
			pf_eth_flush_ruleset(path);
	} while (found);
	if (!RB_EMPTY(&V_pf_keth_anchors))
		printf("pf: vnet %p torn down with ether anchors left\n",
		    curvnet);
	PF_UNLOCK();
	NET_UNLOCK();
	free(path, M_PF);
	free(V_pf_keth, M_PF);
	V_pf_keth = NULL;
}
