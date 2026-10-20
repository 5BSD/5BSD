/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002,2003 Henning Brauer
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
 * pfctl(8) side of the 5BSD "ether" rules (layer-2 rules, as in FreeBSD
 * pf; derived from FreeBSD pfctl.c, pfctl_parser.c and pf_ruleset.c):
 * the parsed ether rules and their inline anchors, loading them into a
 * transaction (element type PF_TRANS_ETH), and showing, listing and
 * flushing the kernel's ether rules.  parse.y holds the grammar.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/tree.h>

#include <net/if.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/pfvar.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "pfctl_parser.h"
#include "pfctl.h"

#define	ETH_INDENT(d, o)	do {					\
				if (o) {				\
					int i_;				\
					for (i_ = 0; i_ < (d); i_++)	\
						printf("  ");		\
				}					\
			} while (0)

void	print_fromto(struct pf_rule_addr *, pf_osfp_t, struct pf_rule_addr *,
	    sa_family_t, u_int8_t, int);

struct pfctl_eth_anchor;

struct pfctl_eth_rule {
	TAILQ_ENTRY(pfctl_eth_rule)	 entries;
	struct pf_eth_rule		 r;
	struct pfctl_eth_anchor		*anchor;
};
TAILQ_HEAD(pfctl_eth_rules, pfctl_eth_rule);

struct pfctl_eth_anchor {
	char				 name[PF_ANCHOR_NAME_SIZE];
	char				 path[PATH_MAX];
	struct pfctl_eth_rules		 rules;
	int				 nrules;
	int				 inline_;	/* has a rule block */
};

struct pfctl_eth {
	struct pfctl_eth_anchor		*eastack[PFCTL_ANCHOR_STACK_DEPTH];
	struct pfctl_eth_anchor		*eanchor;	/* being parsed */
	struct pfctl_eth_anchor		*ealast;	/* last brace closed */
	u_int32_t			 nr;
};

static struct pfctl_eth_anchor *
pfctl_eth_anchor_new(const char *name, const char *path)
{
	struct pfctl_eth_anchor *a;

	if ((a = calloc(1, sizeof(*a))) == NULL)
		err(1, "%s: calloc", __func__);
	TAILQ_INIT(&a->rules);
	if (strlcpy(a->name, name, sizeof(a->name)) >= sizeof(a->name) ||
	    strlcpy(a->path, path, sizeof(a->path)) >= sizeof(a->path))
		errx(1, "%s: anchor name too long: %s", __func__, path);
	return (a);
}

/* pfctl_rules(): the root of the rules parsed for anchor anchorname. */
void
pfctl_eth_init(struct pfctl *pf, const char *anchorname)
{
	struct pfctl_eth *eth;

	if ((eth = calloc(1, sizeof(*eth))) == NULL)
		err(1, "%s: calloc", __func__);
	eth->eanchor = pfctl_eth_anchor_new("", anchorname);
	eth->eastack[0] = eth->eanchor;
	pf->eth = eth;
}

/* parse.y: stepping into "ether anchor ... {". */
void
pfctl_eth_brace_open(struct pfctl *pf)
{
	struct pfctl_eth *eth = pf->eth;
	char ta[PF_ANCHOR_NAME_SIZE];

	pf->asd++;
	/* The anchor rule uses eastack[asd + 1]. */
	if (pf->asd >= PFCTL_ANCHOR_STACK_DEPTH - 1)
		errx(1, "etherpfa_anchor: anchors too deep");
	pf->bn++;
	/* A holding ruleset, until the anchor rule tells where it goes. */
	snprintf(ta, sizeof(ta), "_%d", pf->bn);
	eth->eanchor = pfctl_eth_anchor_new(ta, ta);
	eth->eanchor->inline_ = 1;
	eth->eastack[pf->asd] = eth->eanchor;
}

/* parse.y: the closing brace. */
void
pfctl_eth_brace_close(struct pfctl *pf)
{
	struct pfctl_eth *eth = pf->eth;

	eth->ealast = eth->eanchor;
	pf->asd--;
	eth->eanchor = eth->eastack[pf->asd];
}

/*
 * parse.y: an "ether anchor" rule.  Returns the anchor call and sets
 * *anchor to the inline ruleset (NULL for a reference by name), or
 * returns NULL with *errstr set.
 */
const char *
pfctl_eth_anchor_rule(struct pfctl *pf, const char *name,
    struct pfctl_eth_anchor **anchor, const char **errstr)
{
	struct pfctl_eth *eth = pf->eth;
	struct pfctl_eth_anchor *a, *parent;
	struct pfctl_eth_rule *r;
	char path[PATH_MAX];

	*anchor = NULL;
	if (eth->eastack[pf->asd + 1] == NULL) {
		if (name == NULL) {
			*errstr = "anchors without explicit rules must "
			    "specify a name";
			return (NULL);
		}
		return (name);
	}

	/* Move the inline rules to their place. */
	a = eth->ealast;
	eth->eastack[pf->asd + 1] = NULL;
	if (name != NULL) {
		if (strchr(name, '/') != NULL) {
			*errstr = "anchor paths containing '/' cannot be used "
			    "for inline anchors.";
			return (NULL);
		}
		parent = eth->eastack[pf->asd];
		TAILQ_FOREACH(r, &parent->rules, entries)
			if (r->anchor != NULL && r->anchor->inline_ &&
			    strcmp(r->anchor->name, name) == 0) {
				*errstr = "inline anchor already exists";
				return (NULL);
			}
		if (parent->path[0] != '\0')
			snprintf(path, sizeof(path), "%s/%s", parent->path,
			    name);
		else
			strlcpy(path, name, sizeof(path));
		if (strlcpy(a->name, name, sizeof(a->name)) >= sizeof(a->name) ||
		    strlcpy(a->path, path, sizeof(a->path)) >= sizeof(a->path)) {
			*errstr = "anchor name too long";
			return (NULL);
		}
	}
	*anchor = a;
	return (a->name);
}

/* parse.y: one expanded ether rule, into the ruleset being parsed. */
void
pfctl_eth_append_rule(struct pfctl *pf, struct pf_eth_rule *r,
    const char *anchor_call, struct pfctl_eth_anchor *anchor)
{
	struct pfctl_eth *eth = pf->eth;
	struct pfctl_eth_rule *rule;
	const char *p;

	if ((rule = calloc(1, sizeof(*rule))) == NULL)
		err(1, "%s: calloc", __func__);
	rule->r = *r;
	rule->r.nr = eth->nr++;
	if (anchor == NULL && anchor_call[0] != '\0') {
		/* A reference by name; not part of the parsed anchors. */
		if ((p = strrchr(anchor_call, '/')) != NULL && p[1] != '\0' &&
		    strcmp(p, "/*") != 0)
			p++;
		else
			p = anchor_call;
		anchor = pfctl_eth_anchor_new("", anchor_call);
		if (strlcpy(anchor->name, p, sizeof(anchor->name)) >=
		    sizeof(anchor->name))
			errx(1, "%s: anchor name too long: %s", __func__,
			    anchor_call);
	}
	rule->anchor = anchor;
	TAILQ_INSERT_TAIL(&eth->eanchor->rules, rule, entries);
	eth->eanchor->nrules++;
}

/* Open the transaction of one ether ruleset. */
int
pfctl_eth_trans(struct pfctl *pf, const char *path)
{
	int osize = pf->trans->pfrb_size;

	if (pfctl_add_trans(pf->trans, PF_TRANS_ETH, path))
		return (1);
	if (pfctl_trans(pf->dev, pf->trans, DIOCXBEGIN, osize))
		return (5);
	return (0);
}

static int pfctl_eth_load_ruleset(struct pfctl *, char *,
    struct pfctl_eth_anchor *, int);

static int
pfctl_eth_load_rule(struct pfctl *pf, char *path, struct pfctl_eth_rule *r,
    int depth)
{
	struct pfioc_eth_rule pr;
	const char *name;

	memset(&pr, 0, sizeof(pr));
	if (strlcpy(pr.anchor, path, sizeof(pr.anchor)) >= sizeof(pr.anchor))
		errx(1, "%s: strlcpy", __func__);
	if (r->anchor != NULL)
		name = r->anchor->inline_ ? r->anchor->name : r->anchor->path;
	else
		name = "";
	if ((pf->opts & PF_OPT_NOACTION) == 0) {
		pr.ticket = pfctl_get_ticket(pf->trans, PF_TRANS_ETH, path);
		pr.rule = r->r;
		if (strlcpy(pr.anchor_call, name, sizeof(pr.anchor_call)) >=
		    sizeof(pr.anchor_call))
			errx(1, "%s: strlcpy", __func__);
		if (ioctl(pf->dev, DIOCADDETHRULE, &pr) == -1)
			err(1, "DIOCADDETHRULE");
	}
	if (pf->opts & PF_OPT_VERBOSE) {
		ETH_INDENT(depth, !(pf->opts & PF_OPT_VERBOSE2));
		print_eth_rule(&r->r, r->anchor != NULL ? r->anchor->name : "",
		    pf->opts & (PF_OPT_VERBOSE2 | PF_OPT_DEBUG));
	}
	return (0);
}

static int
pfctl_eth_load_ruleset(struct pfctl *pf, char *path,
    struct pfctl_eth_anchor *a, int depth)
{
	struct pfctl_eth_rule *r;
	int error, len = strlen(path), brace = 0;

	if (depth) {
		/* An inline anchor, relative to its parent. */
		snprintf(&path[len], PATH_MAX - len, "%s%s",
		    path[0] ? "/" : "", a->name);
		if (TAILQ_FIRST(&a->rules) != NULL) {
			brace++;
			if (pf->opts & PF_OPT_VERBOSE)
				printf(" {\n");
			if ((pf->opts & PF_OPT_NOACTION) == 0 &&
			    (error = pfctl_eth_trans(pf, path))) {
				printf("%s: pfctl_eth_trans %d\n", __func__,
				    error);
				goto error;
			}
		} else if (pf->opts & PF_OPT_VERBOSE)
			printf("\n");
	} else
		snprintf(path, PATH_MAX, "%s", a->path);

	while ((r = TAILQ_FIRST(&a->rules)) != NULL) {
		TAILQ_REMOVE(&a->rules, r, entries);
		if ((error = pfctl_eth_load_rule(pf, path, r, depth)))
			goto error;
		if (r->anchor != NULL && r->anchor->inline_) {
			/*
			 * Expanded anchor rules share the inline ruleset and
			 * the first one loads it; like pfctl's IP anchors,
			 * the anchors are not freed before pfctl exits.
			 */
			if ((error = pfctl_eth_load_ruleset(pf, path,
			    r->anchor, depth + 1)))
				goto error;
		} else if (pf->opts & PF_OPT_VERBOSE)
			printf("\n");
		free(r);
	}
	if (brace && pf->opts & PF_OPT_VERBOSE) {
		ETH_INDENT(depth - 1, (pf->opts & PF_OPT_VERBOSE));
		printf("}\n");
	}
	path[len] = '\0';
	return (0);

error:
	path[len] = '\0';
	return (error);
}

/* pfctl_rules(): load the parsed ether rules (or print them, with -n). */
int
pfctl_eth_load(struct pfctl *pf)
{
	char *path;
	int error;

	if (pf->eth == NULL)
		return (0);
	if ((path = calloc(1, PATH_MAX)) == NULL)
		err(1, "%s: calloc", __func__);
	error = pfctl_eth_load_ruleset(pf, path, pf->eth->eastack[0], 0);
	free(path);
	free(pf->eth->eastack[0]);
	free(pf->eth);
	pf->eth = NULL;
	return (error);
}

/* -F ethernet: commit an empty ether ruleset. */
int
pfctl_eth_clear_rules(int dev, int opts, const char *anchorname)
{
	struct pfr_buffer t;

	memset(&t, 0, sizeof(t));
	t.pfrb_type = PFRB_TRANS;
	if (pfctl_add_trans(&t, PF_TRANS_ETH, anchorname) ||
	    pfctl_trans(dev, &t, DIOCXBEGIN, 0) ||
	    pfctl_trans(dev, &t, DIOCXCOMMIT, 0)) {
		pfctl_err(opts, 1, "%s", __func__);
		return (1);
	}
	if ((opts & PF_OPT_QUIET) == 0)
		fprintf(stderr, "Ethernet rules cleared\n");
	return (0);
}

static void
pfctl_print_eth_rule_counters(struct pf_eth_rule *rule, int opts)
{
	if (opts & PF_OPT_VERBOSE) {
		printf("  [ Evaluations: %-8llu  Packets: %-8llu  "
		    "Bytes: %-10llu]\n",
		    (unsigned long long)rule->evaluations,
		    (unsigned long long)(rule->packets[0] +
		    rule->packets[1]),
		    (unsigned long long)(rule->bytes[0] +
		    rule->bytes[1]));
	}
	if (opts & PF_OPT_VERBOSE2) {
		char timestr[30];
		time_t t = (time_t)rule->last_active;

		if (t != 0) {
			strlcpy(timestr, ctime(&t), sizeof(timestr));
			timestr[strcspn(timestr, "\n")] = '\0';
		} else
			snprintf(timestr, sizeof(timestr), "N/A");
		printf("  [ Last Active Time: %s ]\n", timestr);
	}
}

static int
pfctl_eth_get_rulesets(int dev, const char *path, struct pfioc_ruleset *pr)
{
	memset(pr, 0, sizeof(*pr));
	if (strlcpy(pr->path, path, sizeof(pr->path)) >= sizeof(pr->path))
		return (ENAMETOOLONG);
	if (ioctl(dev, DIOCGETETHRULESETS, pr) == -1)
		return (errno);
	return (0);
}

static int
pfctl_eth_get_ruleset(int dev, const char *path, u_int32_t nr,
    struct pfioc_ruleset *pr)
{
	memset(pr, 0, sizeof(*pr));
	if (strlcpy(pr->path, path, sizeof(pr->path)) >= sizeof(pr->path))
		return (ENAMETOOLONG);
	pr->nr = nr;
	if (ioctl(dev, DIOCGETETHRULESET, pr) == -1)
		return (errno);
	return (0);
}

/* -s ether, -s all, -z: the kernel's ether rules. */
int
pfctl_eth_show_rules(int dev, char *path, int opts, int format,
    char *anchorname, int depth, int wildcard)
{
	struct pfioc_eth_rule pr;
	struct pfioc_ruleset rs;
	char anchor_call[PATH_MAX];
	u_int32_t mnr, nr;
	int brace, len = strlen(path), ret;
	int dotitle = opts & PF_OPT_SHOWALL;
	char *npath, *p;

	if (depth > PF_ANCHOR_STACK_MAX) {
		warnx("%s: max stack depth exceeded for %s", __func__, path);
		return (-1);
	}

	/*
	 * Truncate a trailing / and * on an anchorname before searching for
	 * the ruleset, this is syntactic sugar that doesn't actually make it
	 * to the kernel.
	 */
	if ((p = strrchr(anchorname, '/')) != NULL &&
	    p[1] == '*' && p[2] == '\0')
		p[0] = '\0';

	if (anchorname[0] == '/') {
		if ((npath = calloc(1, PATH_MAX)) == NULL)
			err(1, "%s: calloc", __func__);
		snprintf(npath, PATH_MAX, "%s", anchorname);
	} else {
		if (path[0])
			snprintf(&path[len], PATH_MAX - len, "/%s", anchorname);
		else
			snprintf(&path[len], PATH_MAX - len, "%s", anchorname);
		npath = path;
	}

	/*
	 * If this anchor was called with a wildcard path, go through
	 * the rulesets in the anchor rather than the rules.
	 */
	if (wildcard && (opts & PF_OPT_RECURSE)) {
		if ((ret = pfctl_eth_get_rulesets(dev, npath, &rs)) != 0) {
			warnc(ret, "DIOCGETETHRULESETS");
			goto out;
		}
		mnr = rs.nr;
		for (nr = 0; nr < mnr; ++nr) {
			if ((ret = pfctl_eth_get_ruleset(dev, npath, nr,
			    &rs)) != 0)
				errc(1, ret, "DIOCGETETHRULESET");
			ETH_INDENT(depth, !(opts & PF_OPT_VERBOSE));
			printf("ether anchor \"%s\" all {\n", rs.name);
			pfctl_eth_show_rules(dev, npath, opts, format, rs.name,
			    depth + 1, 0);
			ETH_INDENT(depth, !(opts & PF_OPT_VERBOSE));
			printf("}\n");
		}
		goto out;
	}

	memset(&pr, 0, sizeof(pr));
	if (strlcpy(pr.anchor, npath, sizeof(pr.anchor)) >= sizeof(pr.anchor))
		errx(1, "%s: anchor name too long", __func__);
	if (ioctl(dev, DIOCGETETHRULES, &pr) == -1) {
		if (format != PFCTL_SHOW_NOTHING &&
		    (errno != ENOENT || depth == 0))
			warn("DIOCGETETHRULES");
		ret = -1;
		goto out_err;
	}
	mnr = pr.nr;
	for (nr = 0; nr < mnr; nr++) {
		brace = 0;
		pr.nr = nr;
		pr.action = (opts & PF_OPT_CLRRULECTRS) ? PF_GET_CLR_CNTR :
		    PF_GET_NONE;
		if (ioctl(dev, DIOCGETETHRULE, &pr) == -1) {
			warn("DIOCGETETHRULE");
			ret = -1;
			goto out_err;
		}
		strlcpy(anchor_call, pr.anchor_call, sizeof(anchor_call));
		if (format == PFCTL_SHOW_NOTHING)
			continue;
		if (anchor_call[0] &&
		    ((((p = strrchr(anchor_call, '_')) != NULL) &&
		    (p == anchor_call || *(--p) == '/')) ||
		    (opts & PF_OPT_RECURSE))) {
			brace++;
			int aclen = strlen(anchor_call);
			if (anchor_call[aclen - 1] == '*')
				anchor_call[aclen - 2] = '\0';
		}
		if (dotitle) {
			pfctl_print_title("ETHER RULES:");
			dotitle = 0;
		}
		ETH_INDENT(depth, !(opts & PF_OPT_VERBOSE));
		print_eth_rule(&pr.rule, anchor_call,
		    opts & (PF_OPT_VERBOSE2 | PF_OPT_DEBUG));
		if (brace)
			printf(" {\n");
		else
			printf("\n");
		pfctl_print_eth_rule_counters(&pr.rule, opts);
		if (brace) {
			pfctl_eth_show_rules(dev, npath, opts, format,
			    anchor_call, depth + 1, pr.rule.anchor_wildcard);
			ETH_INDENT(depth, !(opts & PF_OPT_VERBOSE));
			printf("}\n");
		}
	}
out:
	ret = 0;
out_err:
	if (npath != path)
		free(npath);
	path[len] = '\0';
	return (ret);
}

/* -s Anchors: the ether anchors, after the IP ones. */
int
pfctl_eth_show_anchors(int dev, int opts, const char *anchorname)
{
	struct pfioc_ruleset rs;
	char sub[PATH_MAX];
	u_int32_t mnr, nr;
	int ret;

	if ((ret = pfctl_eth_get_rulesets(dev, anchorname, &rs)) != 0) {
		if (ret != ENOENT)
			errc(1, ret, "DIOCGETETHRULESETS");
		return (-1);
	}
	mnr = rs.nr;
	for (nr = 0; nr < mnr; nr++) {
		if ((ret = pfctl_eth_get_ruleset(dev, anchorname, nr,
		    &rs)) != 0)
			errc(1, ret, "DIOCGETETHRULESET");
		if (!strcmp(rs.name, PF_RESERVED_ANCHOR))
			continue;
		sub[0] = '\0';
		if (rs.path[0]) {
			strlcat(sub, rs.path, sizeof(sub));
			strlcat(sub, "/", sizeof(sub));
		}
		strlcat(sub, rs.name, sizeof(sub));
		if (sub[0] != '_' || (opts & PF_OPT_VERBOSE))
			printf("  %s\n", sub);
		if (pfctl_eth_show_anchors(dev, opts, sub))
			return (-1);
	}
	return (0);
}

static void
print_eth_addr(const struct pf_eth_addr *a)
{
	int i, masklen = PF_ETH_ADDR_LEN * 8;
	int seen_unset = 0;

	printf("%s%02x:%02x:%02x:%02x:%02x:%02x", a->neg ? "! " : "",
	    a->addr[0], a->addr[1], a->addr[2], a->addr[3], a->addr[4],
	    a->addr[5]);

	/* A prefix mask prints as its length. */
	for (i = 0; i < PF_ETH_ADDR_LEN * 8; i++) {
		int isset = a->mask[i / 8] & (0x80 >> (i % 8));

		if (!seen_unset) {
			if (isset)
				continue;
			seen_unset = 1;
			masklen = i;
		} else if (isset)
			break;	/* Not a prefix: print the whole mask. */
	}
	if (masklen == PF_ETH_ADDR_LEN * 8)
		return;
	if (i == PF_ETH_ADDR_LEN * 8) {
		printf("/%d", masklen);
		return;
	}
	printf("&%02x:%02x:%02x:%02x:%02x:%02x",
	    a->mask[0], a->mask[1], a->mask[2], a->mask[3], a->mask[4],
	    a->mask[5]);
}

void
print_eth_rule(struct pf_eth_rule *r, const char *anchor_call,
    int rule_numbers)
{
	int i;

	if (rule_numbers)
		printf("@%u ", r->nr);

	printf("ether ");
	if (anchor_call[0]) {
		if (anchor_call[0] == '_')
			printf("anchor");
		else
			printf("anchor \"%s\"", anchor_call);
	} else
		printf("%s", r->action == PF_DROP ? "block" : "pass");
	if (r->direction == PF_IN)
		printf(" in");
	else if (r->direction == PF_OUT)
		printf(" out");

	if (r->quick)
		printf(" quick");
	if (r->ifname[0]) {
		if (r->ifnot)
			printf(" on ! %s", r->ifname);
		else
			printf(" on %s", r->ifname);
	}
	if (r->bridge_to[0])
		printf(" bridge-to %s", r->bridge_to);
	if (r->proto)
		printf(" proto 0x%04x", r->proto);

	if (r->src.isset) {
		printf(" from ");
		print_eth_addr(&r->src);
	}
	if (r->dst.isset) {
		printf(" to ");
		print_eth_addr(&r->dst);
	}
	printf(" l3");
	print_fromto(&r->ipsrc, PF_OSFP_ANY, &r->ipdst,
	    r->proto == ETHERTYPE_IPV6 ? AF_INET6 : AF_INET, 0, 0);

	for (i = 0; i < PF_ETH_LABEL_COUNT && r->label[i][0]; i++)
		printf(" label \"%s\"", r->label[i]);
	if (r->ridentifier)
		printf(" ridentifier %u", r->ridentifier);

	if (r->qname[0])
		printf(" queue %s", r->qname);
	if (r->tagname[0])
		printf(" tag %s", r->tagname);
	if (r->match_tagname[0]) {
		if (r->match_tag_not)
			printf(" !");
		printf(" tagged %s", r->match_tagname);
	}
	if (r->dnpipe)
		printf(" %s %d",
		    r->dnflags & PF_DN_IS_PIPE ? "dnpipe" : "dnqueue",
		    r->dnpipe);
}
