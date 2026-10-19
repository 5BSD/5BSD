/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * pf(4) ioctl paths no other test reaches: DIOCGETRULE transactions
 * (stale, foreign, exhausted tickets), DIOCCHANGERULE with route labels,
 * port range validation in DIOCADDRULE/DIOCCHANGERULE, the queue ioctls
 * (queues are refused at commit), source nodes and the state/source
 * limiter lookups by id.
 *
 * Every case replaces the main ruleset of its pf instance: they run in
 * their own vnet jail (Makefile: execenv=jail) and skip anywhere else.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/pfvar.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

/* Tag ids pf hands out (pf_ioctl.c TAGID_MAX). */
#define	TAGID_MAX	50000

#ifndef PF_ANCHOR_STACK_MAX
#define	PF_ANCHOR_STACK_MAX	64
#endif

static int dev = -1;

static void
require_own_jail(void)
{
	int jailed = 0;
	size_t len = sizeof(jailed);

	if (sysctlbyname("security.jail.jailed", &jailed, &len, NULL, 0) != 0 ||
	    jailed == 0)
		atf_tc_skip("replaces the main ruleset: run in a vnet jail "
		    "(execenv=jail)");
}

#define COMMON_HEAD() do {						\
	require_own_jail();						\
	dev = open("/dev/pf", O_RDWR);					\
	if (dev == -1)							\
		atf_tc_skip("Failed to open /dev/pf");			\
} while (0)

#define COMMON_CLEANUP() do {						\
	if (dev != -1)							\
		close(dev);						\
} while (0)

#define GLUE_HEAD(name)							\
ATF_TC_HEAD(name, tc)							\
{									\
	atf_tc_set_md_var(tc, "require.user", "root");			\
	atf_tc_set_md_var(tc, "require.kmods", "pf");			\
}

static void
run(const char *cmd)
{
	if (system(cmd) != 0)
		atf_tc_fail("command failed: %s", cmd);
}

static void
quiet(const char *cmd)
{
	(void)system(cmd);
}

/* A minimal valid rule: pass, IPv4, no translation, no rtable. */
static void
init_rule(struct pf_rule *r)
{
	memset(r, 0, sizeof(*r));
	r->action = PF_PASS;
	r->direction = PF_IN;
	r->af = AF_INET;
	r->proto = IPPROTO_TCP;
	r->rtableid = -1;
	r->onrdomain = -1;
	r->src.addr.type = PF_ADDR_ADDRMASK;
	r->dst.addr.type = PF_ADDR_ADDRMASK;
	r->nat.addr.type = PF_ADDR_NONE;
	r->rdr.addr.type = PF_ADDR_NONE;
	r->route.addr.type = PF_ADDR_NONE;
}

static u_int32_t
change_ticket(const char *anchor)
{
	static struct pfioc_rule pcr;

	memset(&pcr, 0, sizeof(pcr));
	strlcpy(pcr.anchor, anchor, sizeof(pcr.anchor));
	pcr.action = PF_CHANGE_GET_TICKET;
	ATF_REQUIRE_MSG(ioctl(dev, DIOCCHANGERULE, &pcr) == 0,
	    "PF_CHANGE_GET_TICKET %s: %s", anchor, strerror(errno));
	return (pcr.ticket);
}

static u_int32_t
rule_count(int fd, const char *anchor, u_int32_t *ticket)
{
	static struct pfioc_rule pr;

	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor, sizeof(pr.anchor));
	ATF_REQUIRE_MSG(ioctl(fd, DIOCGETRULES, &pr) == 0,
	    "DIOCGETRULES %s: %s", anchor, strerror(errno));
	if (ticket != NULL)
		*ticket = pr.ticket;
	return (pr.nr);
}

static int
get_rule(int fd, const char *anchor, u_int32_t ticket, struct pfioc_rule *pr)
{
	memset(pr, 0, sizeof(*pr));
	strlcpy(pr->anchor, anchor, sizeof(pr->anchor));
	pr->ticket = ticket;
	return (ioctl(fd, DIOCGETRULE, pr));
}

static void
trans_one(struct pfioc_trans *io, struct pfioc_trans_e *ioe,
    const char *anchor)
{
	memset(io, 0, sizeof(*io));
	memset(ioe, 0, sizeof(*ioe));
	ioe->type = PF_TRANS_RULESET;
	strlcpy(ioe->anchor, anchor, sizeof(ioe->anchor));
	io->size = 1;
	io->esize = sizeof(*ioe);
	io->array = ioe;
}

/*
 * DIOCGETRULES opens a GETRULE transaction (pf_init_tgetrule); a reload
 * makes it stale, other descriptors cannot use it, each descriptor has a
 * bounded number, and close releases them (pf_cleanup_tgetrule).
 */
ATF_TC_WITH_CLEANUP(getrule_ticket);
GLUE_HEAD(getrule_ticket)

ATF_TC_BODY(getrule_ticket, tc)
{
	static struct pfioc_rule pr;
	u_int32_t ticket, ticket2;
	int dev2, i, n, err;

	COMMON_HEAD();

	run("printf 'pass in proto tcp\\npass out proto udp\\n' | "
	    "pfctl -q -a fgt -f -");

	ATF_REQUIRE_EQ(rule_count(dev, "fgt", &ticket), 2);
	ATF_REQUIRE(get_rule(dev, "fgt", ticket, &pr) == 0);
	ATF_CHECK_EQ(pr.nr, 0);
	ATF_CHECK_EQ(pr.rule.direction, PF_IN);
	ATF_CHECK_EQ(pr.rule.proto, IPPROTO_TCP);
	ATF_REQUIRE(get_rule(dev, "fgt", ticket, &pr) == 0);
	ATF_CHECK_EQ(pr.nr, 1);
	ATF_CHECK_EQ(pr.rule.direction, PF_OUT);
	ATF_CHECK_EQ(pr.rule.proto, IPPROTO_UDP);
	/* The transaction walked past the last rule. */
	ATF_CHECK_ERRNO(ENOENT, get_rule(dev, "fgt", ticket, &pr) == -1);

	/* Stale: the anchor was reloaded after DIOCGETRULES. */
	(void)rule_count(dev, "fgt", &ticket);
	run("echo 'pass in proto icmp' | pfctl -q -a fgt -f -");
	ATF_CHECK_ERRNO(EBUSY, get_rule(dev, "fgt", ticket, &pr) == -1);

	/* Unknown ticket (the counter starts at 1). */
	ATF_CHECK_ERRNO(ENXIO, get_rule(dev, "fgt", 0, &pr) == -1);

	/* Tickets belong to the descriptor that opened them. */
	dev2 = open("/dev/pf", O_RDWR);
	ATF_REQUIRE(dev2 != -1);
	ATF_REQUIRE_EQ(rule_count(dev2, "fgt", &ticket2), 1);
	ATF_CHECK_ERRNO(ENXIO, get_rule(dev, "fgt", ticket2, &pr) == -1);
	ATF_CHECK(get_rule(dev2, "fgt", ticket2, &pr) == 0);
	close(dev2);

	/* Unknown and unterminated anchors. */
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, "fg-none", sizeof(pr.anchor));
	ATF_CHECK_ERRNO(EINVAL, ioctl(dev, DIOCGETRULES, &pr) == -1);
	memset(pr.anchor, 'a', sizeof(pr.anchor));
	ATF_CHECK_ERRNO(ENAMETOOLONG, ioctl(dev, DIOCGETRULES, &pr) == -1);

	/* A descriptor holds at most PF_ANCHOR_STACK_MAX * 8 tickets. */
	dev2 = open("/dev/pf", O_RDWR);
	ATF_REQUIRE(dev2 != -1);
	err = 0;
	for (n = 0; n < 4 * PF_ANCHOR_STACK_MAX * 8; n++) {
		memset(&pr, 0, sizeof(pr));
		strlcpy(pr.anchor, "fgt", sizeof(pr.anchor));
		if (ioctl(dev2, DIOCGETRULES, &pr) != 0) {
			err = errno;
			break;
		}
	}
	ATF_CHECK_EQ_MSG(err, EBUSY, "errno %d after %d tickets", err, n);
	ATF_CHECK_EQ(n, PF_ANCHOR_STACK_MAX * 8);
	close(dev2);

	/* Closing released them all, and their anchor references. */
	for (i = 0; i < 4; i++) {
		dev2 = open("/dev/pf", O_RDWR);
		ATF_REQUIRE(dev2 != -1);
		ATF_CHECK_EQ(rule_count(dev2, "fgt", NULL), 1);
		close(dev2);
	}

	/* A ticket still open on dev keeps its walk across a flush. */
	ATF_REQUIRE_EQ(rule_count(dev, "fgt", &ticket), 1);
	run("pfctl -q -a fgt -Fr");
	ATF_CHECK_ERRNO(EBUSY, get_rule(dev, "fgt", ticket, &pr) == -1);
}

ATF_TC_CLEANUP(getrule_ticket, tc)
{
	quiet("pfctl -q -a fgt -Fr");
	COMMON_CLEANUP();
}

/*
 * DIOCCHANGERULE: tickets, add/remove, route labels taken and released
 * through pf_addr_setup/pf_rm_rule and copied out by name.
 */
ATF_TC_WITH_CLEANUP(changerule_rtlabel);
GLUE_HEAD(changerule_rtlabel)

ATF_TC_BODY(changerule_rtlabel, tc)
{
	static struct pfioc_rule pcr, pr;
	u_int32_t gticket, ticket;
	int i;

	COMMON_HEAD();

	run("echo 'pass in proto tcp' | pfctl -q -a fgc -f -");

	/* PF_CHANGE_GET_TICKET bumps the version: GETRULE goes stale. */
	ATF_REQUIRE_EQ(rule_count(dev, "fgc", &gticket), 1);
	ticket = change_ticket("fgc");
	ATF_CHECK_ERRNO(EBUSY, get_rule(dev, "fgc", gticket, &pr) == -1);

	memset(&pcr, 0, sizeof(pcr));
	strlcpy(pcr.anchor, "fgc", sizeof(pcr.anchor));
	init_rule(&pcr.rule);
	pcr.rule.src.addr.type = PF_ADDR_RTLABEL;
	strlcpy(pcr.rule.src.addr.v.rtlabelname, "fglabel",
	    sizeof(pcr.rule.src.addr.v.rtlabelname));
	pcr.action = PF_CHANGE_ADD_TAIL;
	pcr.ticket = ticket;
	ATF_REQUIRE_MSG(ioctl(dev, DIOCCHANGERULE, &pcr) == 0,
	    "PF_CHANGE_ADD_TAIL: %s", strerror(errno));
	/* The change consumed the ticket. */
	ATF_CHECK_ERRNO(EINVAL, ioctl(dev, DIOCCHANGERULE, &pcr) == -1);

	ATF_REQUIRE_EQ(rule_count(dev, "fgc", &gticket), 2);
	ATF_REQUIRE(get_rule(dev, "fgc", gticket, &pr) == 0);
	ATF_REQUIRE(get_rule(dev, "fgc", gticket, &pr) == 0);
	ATF_CHECK_EQ(pr.rule.src.addr.type, PF_ADDR_RTLABEL);
	ATF_CHECK_STREQ(pr.rule.src.addr.v.rtlabelname, "fglabel");
	run("pfctl -a fgc -sr | grep -q 'from route \"fglabel\"'");

	/* Share the label between rules, then release every reference. */
	for (i = 0; i < 16; i++) {
		pcr.action = (i % 2) ? PF_CHANGE_ADD_HEAD : PF_CHANGE_ADD_TAIL;
		pcr.ticket = change_ticket("fgc");
		ATF_REQUIRE(ioctl(dev, DIOCCHANGERULE, &pcr) == 0);
	}
	ATF_REQUIRE_EQ(rule_count(dev, "fgc", NULL), 18);
	for (i = 0; i < 17; i++) {
		memset(&pcr, 0, sizeof(pcr));
		strlcpy(pcr.anchor, "fgc", sizeof(pcr.anchor));
		pcr.action = PF_CHANGE_REMOVE;
		pcr.nr = 0;
		pcr.ticket = change_ticket("fgc");
		ATF_REQUIRE(ioctl(dev, DIOCCHANGERULE, &pcr) == 0);
	}
	ATF_REQUIRE_EQ(rule_count(dev, "fgc", &gticket), 1);
	ATF_REQUIRE(get_rule(dev, "fgc", gticket, &pr) == 0);
	ATF_CHECK_STREQ(pr.rule.src.addr.v.rtlabelname, "fglabel");

	/* The label is still known by name after the other references went. */
	memset(&pcr, 0, sizeof(pcr));
	strlcpy(pcr.anchor, "fgc", sizeof(pcr.anchor));
	init_rule(&pcr.rule);
	pcr.rule.dst.addr.type = PF_ADDR_RTLABEL;
	strlcpy(pcr.rule.dst.addr.v.rtlabelname, "fgother",
	    sizeof(pcr.rule.dst.addr.v.rtlabelname));
	pcr.action = PF_CHANGE_ADD_BEFORE;
	pcr.nr = 0;
	pcr.ticket = change_ticket("fgc");
	ATF_REQUIRE(ioctl(dev, DIOCCHANGERULE, &pcr) == 0);
	ATF_REQUIRE_EQ(rule_count(dev, "fgc", &gticket), 2);
	ATF_REQUIRE(get_rule(dev, "fgc", gticket, &pr) == 0);
	ATF_CHECK_STREQ(pr.rule.dst.addr.v.rtlabelname, "fgother");
	ATF_REQUIRE(get_rule(dev, "fgc", gticket, &pr) == 0);
	ATF_CHECK_STREQ(pr.rule.src.addr.v.rtlabelname, "fglabel");

	/* Removing a rule that is not there. */
	pcr.action = PF_CHANGE_REMOVE;
	pcr.nr = 42;
	pcr.ticket = change_ticket("fgc");
	ATF_CHECK_ERRNO(EINVAL, ioctl(dev, DIOCCHANGERULE, &pcr) == -1);

	/* Actions out of range, unknown anchor. */
	pcr.action = PF_CHANGE_NONE;
	ATF_CHECK_ERRNO(EINVAL, ioctl(dev, DIOCCHANGERULE, &pcr) == -1);
	pcr.action = PF_CHANGE_GET_TICKET + 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(dev, DIOCCHANGERULE, &pcr) == -1);
	memset(&pcr, 0, sizeof(pcr));
	strlcpy(pcr.anchor, "fg-none", sizeof(pcr.anchor));
	pcr.action = PF_CHANGE_GET_TICKET;
	ATF_CHECK_ERRNO(EINVAL, ioctl(dev, DIOCCHANGERULE, &pcr) == -1);
}

ATF_TC_CLEANUP(changerule_rtlabel, tc)
{
	quiet("pfctl -q -a fgc -Fr");
	COMMON_CLEANUP();
}

static int
change_ports(u_int8_t op, u_int16_t lo, u_int16_t hi)
{
	static struct pfioc_rule pcr;

	memset(&pcr, 0, sizeof(pcr));
	strlcpy(pcr.anchor, "fgp", sizeof(pcr.anchor));
	init_rule(&pcr.rule);
	pcr.rule.dst.port_op = op;
	pcr.rule.dst.port[0] = htons(lo);
	pcr.rule.dst.port[1] = htons(hi);
	pcr.action = PF_CHANGE_ADD_TAIL;
	pcr.ticket = change_ticket("fgp");
	return (ioctl(dev, DIOCCHANGERULE, &pcr));
}

static int
add_ports(u_int32_t ticket, u_int8_t op, u_int16_t lo, u_int16_t hi,
    int rdr)
{
	static struct pfioc_rule pr;

	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, "fgp", sizeof(pr.anchor));
	pr.ticket = ticket;
	init_rule(&pr.rule);
	if (rdr) {
		/* proxy_port is in host order (PF_ORDER_HOST). */
		pr.rule.rdr.port_op = op;
		pr.rule.rdr.proxy_port[0] = lo;
		pr.rule.rdr.proxy_port[1] = hi;
	} else {
		pr.rule.src.port_op = op;
		pr.rule.src.port[0] = htons(lo);
		pr.rule.src.port[1] = htons(hi);
	}
	return (ioctl(dev, DIOCADDRULE, &pr));
}

/* pf_validate_range() through DIOCCHANGERULE and DIOCADDRULE. */
ATF_TC_WITH_CLEANUP(port_ranges);
GLUE_HEAD(port_ranges)

ATF_TC_BODY(port_ranges, tc)
{
	struct pfioc_trans io;
	static struct pfioc_trans_e ioe;
	static struct pfioc_rule pr;

	COMMON_HEAD();

	run("echo 'pass in proto tcp' | pfctl -q -a fgp -f -");

	/* 1000:999 selects nothing, 1000><900 and 1000><1000 nothing,
	 * 1000<>999 everything: all refused. */
	ATF_CHECK_ERRNO(EINVAL, change_ports(PF_OP_RRG, 1000, 999) == -1);
	ATF_CHECK_ERRNO(EINVAL, change_ports(PF_OP_IRG, 1000, 900) == -1);
	ATF_CHECK_ERRNO(EINVAL, change_ports(PF_OP_IRG, 1000, 1000) == -1);
	ATF_CHECK_ERRNO(EINVAL, change_ports(PF_OP_XRG, 1000, 999) == -1);
	ATF_CHECK_EQ(rule_count(dev, "fgp", NULL), 1);
	ATF_CHECK(change_ports(PF_OP_IRG, 900, 1000) == 0);
	ATF_CHECK(change_ports(PF_OP_RRG, 1000, 1000) == 0);
	ATF_CHECK(change_ports(PF_OP_XRG, 1000, 1001) == 0);
	ATF_CHECK_EQ(rule_count(dev, "fgp", NULL), 4);

	trans_one(&io, &ioe, "fgp");
	ATF_REQUIRE(ioctl(dev, DIOCXBEGIN, &io) == 0);
	ATF_CHECK_ERRNO(EINVAL, add_ports(ioe.ticket, PF_OP_RRG, 2, 1, 0) == -1);
	ATF_CHECK_ERRNO(EINVAL, add_ports(ioe.ticket, PF_OP_IRG, 5, 5, 0) == -1);
	ATF_CHECK_ERRNO(EINVAL, add_ports(ioe.ticket, PF_OP_XRG, 9, 8, 0) == -1);
	ATF_CHECK_ERRNO(EINVAL, add_ports(ioe.ticket, PF_OP_RRG, 2000, 1000,
	    1) == -1);
	ATF_CHECK_ERRNO(EBUSY, add_ports(ioe.ticket + 1, PF_OP_IRG, 900, 1000,
	    0) == -1);
	ATF_CHECK(add_ports(ioe.ticket, PF_OP_IRG, 900, 1000, 0) == 0);
	ATF_CHECK(add_ports(ioe.ticket, PF_OP_RRG, 1000, 2000, 1) == 0);

	/* An address type of none is refused by DIOCADDRULE. */
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, "fgp", sizeof(pr.anchor));
	pr.ticket = ioe.ticket;
	init_rule(&pr.rule);
	pr.rule.src.addr.type = PF_ADDR_NONE;
	ATF_CHECK_ERRNO(EINVAL, ioctl(dev, DIOCADDRULE, &pr) == -1);

	ATF_REQUIRE(ioctl(dev, DIOCXCOMMIT, &io) == 0);
	ATF_CHECK_EQ(rule_count(dev, "fgp", NULL), 2);
	run("pfctl -a fgp -sr | grep -q 'port 900 >< 1000'");
}

ATF_TC_CLEANUP(port_ranges, tc)
{
	quiet("pfctl -q -a fgp -Fr");
	COMMON_CLEANUP();
}

static int
add_queue(u_int32_t ticket, const char *name, const char *parent,
    const char *ifname, u_int flags)
{
	static struct pfioc_queue q;

	memset(&q, 0, sizeof(q));
	q.ticket = ticket;
	strlcpy(q.queue.qname, name, sizeof(q.queue.qname));
	strlcpy(q.queue.parent, parent, sizeof(q.queue.parent));
	strlcpy(q.queue.ifname, ifname, sizeof(q.queue.ifname));
	q.queue.flags = flags;
	q.queue.linkshare.m2.absolute = 1000000;
	return (ioctl(dev, DIOCADDQUEUE, &q));
}

static u_int32_t
queue_count(u_int32_t *ticket)
{
	static struct pfioc_queue pq;

	memset(&pq, 0, sizeof(pq));
	ATF_REQUIRE_MSG(ioctl(dev, DIOCGETQUEUES, &pq) == 0,
	    "DIOCGETQUEUES: %s", strerror(errno));
	if (ticket != NULL)
		*ticket = pq.ticket;
	return (pq.nr);
}

/*
 * Queues: DIOCADDQUEUE fills the inactive list, rollback frees it
 * (pf_free_queues), and committing a queue on a real interface fails
 * because 5BSD's disciplines refuse it (openbsd_ifq.c).
 */
ATF_TC_WITH_CLEANUP(queues);
GLUE_HEAD(queues)

ATF_TC_BODY(queues, tc)
{
	static struct pfioc_queue pq;
	static struct pfioc_qstats pqs;
	struct pfioc_trans io;
	static struct pfioc_trans_e ioe;
	char buf[256];
	u_int32_t ticket;

	COMMON_HEAD();

	quiet("ifconfig lo0 up");
	run("echo pass | pfctl -q -f -");

	ATF_CHECK_EQ(queue_count(&ticket), 0);
	memset(&pq, 0, sizeof(pq));
	pq.ticket = ticket;
	pq.nr = 0;
	ATF_CHECK_ERRNO(EBUSY, ioctl(dev, DIOCGETQUEUE, &pq) == -1);
	pq.ticket = ticket + 1;
	ATF_CHECK_ERRNO(EBUSY, ioctl(dev, DIOCGETQUEUE, &pq) == -1);
	memset(&pqs, 0, sizeof(pqs));
	pqs.ticket = ticket;
	pqs.buf = buf;
	pqs.nbytes = sizeof(buf);
	ATF_CHECK_ERRNO(EBUSY, ioctl(dev, DIOCGETQSTATS, &pqs) == -1);

	/*
	 * 5BSD refuses queue definitions at DIOCADDQUEUE (pf_freebsd.c), so a
	 * transaction never holds half of a queue tree: every add fails,
	 * whatever its arguments, and nothing is left after a rollback.
	 */
	trans_one(&io, &ioe, "");
	ATF_REQUIRE(ioctl(dev, DIOCXBEGIN, &io) == 0);
	ATF_CHECK_ERRNO(EOPNOTSUPP, add_queue(ioe.ticket, "fgroot", "", "lo0",
	    PFQS_ROOTCLASS) == -1);
	ATF_CHECK_ERRNO(EOPNOTSUPP, add_queue(ioe.ticket + 1, "fgroot", "",
	    "lo0", PFQS_ROOTCLASS) == -1);
	memset(&pq, 0, sizeof(pq));
	pq.ticket = ioe.ticket;
	memset(pq.queue.qname, 'q', sizeof(pq.queue.qname));
	ATF_CHECK_ERRNO(EOPNOTSUPP, ioctl(dev, DIOCADDQUEUE, &pq) == -1);
	ATF_REQUIRE(ioctl(dev, DIOCXROLLBACK, &io) == 0);
	ATF_CHECK_EQ(queue_count(NULL), 0);

	/* The refused queues went back to the inactive list: drop them. */
	trans_one(&io, &ioe, "");
	ATF_REQUIRE(ioctl(dev, DIOCXBEGIN, &io) == 0);
	ATF_REQUIRE(ioctl(dev, DIOCXROLLBACK, &io) == 0);
	ATF_CHECK_EQ(queue_count(NULL), 0);
}

ATF_TC_CLEANUP(queues, tc)
{
	quiet("pfctl -q -F all");
	COMMON_CLEANUP();
}

/* Local ICMP through pf on lo0, for source nodes and limiters. */
static void
lo0_ping(void)
{
	quiet("ifconfig lo0 inet 127.0.0.1/8 up");
	quiet("pfctl -q -e > /dev/null 2>&1");
	run("ping -c 1 -t 2 127.0.0.1 > /dev/null");
}

/* DIOCGETSRCNODES sizing and copy, DIOCKILLSRCNODES by address. */
ATF_TC_WITH_CLEANUP(srcnodes);
GLUE_HEAD(srcnodes)

ATF_TC_BODY(srcnodes, tc)
{
	struct pfioc_src_nodes psn;
	struct pfioc_src_node_kill psnk;
	struct pf_src_node *sn;
	size_t i, n;
	int found;

	COMMON_HEAD();

	run("printf 'pass\\npass out quick on lo0 inet proto icmp "
	    "keep state (source-track rule)\\n' | pfctl -q -f -");
	lo0_ping();

	memset(&psn, 0, sizeof(psn));
	ATF_REQUIRE(ioctl(dev, DIOCGETSRCNODES, &psn) == 0);
	ATF_REQUIRE_MSG(psn.psn_len >= sizeof(*sn), "psn_len %zu",
	    psn.psn_len);
	psn.psn_buf = malloc(psn.psn_len);
	ATF_REQUIRE(psn.psn_buf != NULL);
	ATF_REQUIRE(ioctl(dev, DIOCGETSRCNODES, &psn) == 0);
	n = psn.psn_len / sizeof(*sn);
	found = 0;
	for (i = 0; i < n; i++) {
		sn = &psn.psn_src_nodes[i];
		if (sn->af == AF_INET &&
		    sn->addr.v4.s_addr == htonl(INADDR_LOOPBACK)) {
			found = 1;
			ATF_CHECK(sn->states >= 1);
			ATF_CHECK_EQ(sn->kif, NULL);
		}
	}
	ATF_CHECK_MSG(found, "no source node for 127.0.0.1 among %zu", n);
	free(psn.psn_buf);

	/* Kill a source that does not exist, then 127.0.0.1. */
	memset(&psnk, 0, sizeof(psnk));
	psnk.psnk_af = AF_INET;
	psnk.psnk_src.addr.type = PF_ADDR_ADDRMASK;
	psnk.psnk_src.addr.v.a.addr.v4.s_addr = inet_addr("203.0.113.1");
	psnk.psnk_src.addr.v.a.mask.v4.s_addr = 0xffffffff;
	ATF_REQUIRE(ioctl(dev, DIOCKILLSRCNODES, &psnk) == 0);
	ATF_CHECK_EQ(psnk.psnk_killed, 0);

	psnk.psnk_src.addr.v.a.addr.v4.s_addr = htonl(INADDR_LOOPBACK);
	ATF_REQUIRE(ioctl(dev, DIOCKILLSRCNODES, &psnk) == 0);
	ATF_CHECK(psnk.psnk_killed >= 1);

	memset(&psn, 0, sizeof(psn));
	ATF_REQUIRE(ioctl(dev, DIOCGETSRCNODES, &psn) == 0);
	ATF_CHECK_EQ(psn.psn_len, 0);
	ATF_CHECK(ioctl(dev, DIOCCLRSRCNODES) == 0);
}

ATF_TC_CLEANUP(srcnodes, tc)
{
	quiet("pfctl -q -d; pfctl -q -F all");
	COMMON_CLEANUP();
}

/*
 * State and source limiters looked up by id (pf_statelim_rb_find,
 * pf_sourcelim_rb_find, pf_source_rb_find), DIOCCLRSOURCE, and the
 * DIOCADDSTATELIM argument checks.
 */
ATF_TC_WITH_CLEANUP(limiters);
GLUE_HEAD(limiters)

ATF_TC_BODY(limiters, tc)
{
	struct pfioc_statelim stl;
	struct pfioc_sourcelim srl;
	struct pfioc_source sr;
	struct pfioc_source_entry key, ent[4];
	struct pfioc_source_kill sk;

	COMMON_HEAD();

	run("printf '"
	    "state limiter \"fgstl\" id 7 limit 100\\n"
	    "source limiter \"fgsrl\" id 9 entries 16 limit 8\\n"
	    "pass\\n"
	    "pass out quick on lo0 inet proto icmp source limiter \"fgsrl\"\\n"
	    "pass out quick on lo0 inet proto udp state limiter \"fgstl\"\\n"
	    "' | pfctl -q -f -");

	memset(&stl, 0, sizeof(stl));
	stl.id = 7;
	ATF_REQUIRE(ioctl(dev, DIOCGETSTATELIM, &stl) == 0);
	ATF_CHECK_STREQ(stl.name, "fgstl");
	ATF_CHECK_EQ(stl.limit, 100);
	stl.id = 8;
	ATF_CHECK_ERRNO(ENOENT, ioctl(dev, DIOCGETSTATELIM, &stl) == -1);
	stl.id = 1;
	ATF_REQUIRE(ioctl(dev, DIOCGETNSTATELIM, &stl) == 0);
	ATF_CHECK_EQ(stl.id, 7);

	/* DIOCADDSTATELIM refuses bad arguments before the ticket. */
	memset(&stl, 0, sizeof(stl));
	strlcpy(stl.name, "fgbad", sizeof(stl.name));
	stl.id = 0;
	stl.limit = 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(dev, DIOCADDSTATELIM, &stl) == -1);
	stl.id = 3;
	stl.limit = 0;
	ATF_CHECK_ERRNO(EINVAL, ioctl(dev, DIOCADDSTATELIM, &stl) == -1);
	stl.limit = 1;
	stl.rate.limit = 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(dev, DIOCADDSTATELIM, &stl) == -1);
	stl.rate.limit = 0;
	memset(stl.name, 'n', sizeof(stl.name));
	ATF_CHECK_ERRNO(ENAMETOOLONG,
	    ioctl(dev, DIOCADDSTATELIM, &stl) == -1);
	strlcpy(stl.name, "fgbad", sizeof(stl.name));
	stl.ticket = 0xdeadbeef;
	ATF_CHECK_ERRNO(EBUSY, ioctl(dev, DIOCADDSTATELIM, &stl) == -1);

	memset(&srl, 0, sizeof(srl));
	srl.id = 9;
	ATF_REQUIRE(ioctl(dev, DIOCGETSOURCELIM, &srl) == 0);
	ATF_CHECK_STREQ(srl.name, "fgsrl");
	ATF_CHECK_EQ(srl.entries, 16);
	ATF_CHECK_EQ(srl.limit, 8);
	ATF_CHECK_EQ(srl.inet_prefix, 32);
	srl.id = 10;
	ATF_CHECK_ERRNO(ESRCH, ioctl(dev, DIOCGETSOURCELIM, &srl) == -1);

	lo0_ping();

	/* Find the entry the ping created, then look it up exactly. */
	memset(&sr, 0, sizeof(sr));
	memset(&key, 0, sizeof(key));
	memset(ent, 0, sizeof(ent));
	sr.id = 9;
	sr.entry_size = sizeof(key);
	sr.key = &key;
	sr.entries = ent;
	sr.entrieslen = sizeof(ent);
	ATF_REQUIRE_MSG(ioctl(dev, DIOCGETNSOURCE, &sr) == 0,
	    "DIOCGETNSOURCE: %s", strerror(errno));
	ATF_REQUIRE(sr.entrieslen >= sizeof(ent[0]));
	ATF_CHECK_EQ(ent[0].af, AF_INET);
	ATF_CHECK_EQ(ent[0].addr.v4.s_addr, htonl(INADDR_LOOPBACK));

	key = ent[0];
	memset(ent, 0, sizeof(ent));
	sr.entrieslen = sizeof(ent);
	ATF_REQUIRE_MSG(ioctl(dev, DIOCGETSOURCE, &sr) == 0,
	    "DIOCGETSOURCE: %s", strerror(errno));
	ATF_CHECK_EQ(sr.entrieslen, sizeof(ent[0]));
	ATF_CHECK_EQ(ent[0].addr.v4.s_addr, htonl(INADDR_LOOPBACK));
	ATF_CHECK(ent[0].admitted >= 1);
	ATF_CHECK_EQ(sr.limit, 8);

	sr.entrieslen = sizeof(ent);
	key.addr.v4.s_addr = inet_addr("127.0.0.2");
	ATF_CHECK_ERRNO(ENOENT, ioctl(dev, DIOCGETSOURCE, &sr) == -1);
	key.addr.v4.s_addr = htonl(INADDR_LOOPBACK);
	sr.id = 10;
	ATF_CHECK_ERRNO(ESRCH, ioctl(dev, DIOCGETSOURCE, &sr) == -1);
	sr.id = 9;
	sr.entry_size = sizeof(key) + 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(dev, DIOCGETSOURCE, &sr) == -1);
	sr.entry_size = sizeof(key);
	sr.entrieslen = sizeof(ent[0]) - 1;
	ATF_CHECK_ERRNO(EMSGSIZE, ioctl(dev, DIOCGETSOURCE, &sr) == -1);
	sr.entrieslen = sizeof(ent);
	memset(sr.name, 's', sizeof(sr.name));
	ATF_CHECK_ERRNO(ENAMETOOLONG, ioctl(dev, DIOCGETSOURCE, &sr) == -1);
	memset(sr.name, 0, sizeof(sr.name));

	/* DIOCCLRSOURCE */
	memset(&sk, 0, sizeof(sk));
	sk.id = 9;
	sk.af = key.af;
	sk.rdomain = key.rdomain;
	sk.addr = key.addr;
	sk.rmstates = 1;
	ATF_CHECK_ERRNO(EOPNOTSUPP, ioctl(dev, DIOCCLRSOURCE, &sk) == -1);
	sk.rmstates = 0;
	sk.id = 10;
	ATF_CHECK_ERRNO(ESRCH, ioctl(dev, DIOCCLRSOURCE, &sk) == -1);
	sk.id = 9;
	ATF_CHECK(ioctl(dev, DIOCCLRSOURCE, &sk) == 0);
	ATF_CHECK_ERRNO(ENOENT, ioctl(dev, DIOCCLRSOURCE, &sk) == -1);
	ATF_CHECK_ERRNO(ENOENT, ioctl(dev, DIOCGETSOURCE, &sr) == -1);
}

ATF_TC_CLEANUP(limiters, tc)
{
	quiet("pfctl -q -d; pfctl -q -F all");
	COMMON_CLEANUP();
}

/*
 * A rule DIOCADDRULE refuses after pf_rule_copyin() (here: a stale ticket)
 * releases the tag ids copyin took.  Leaked, enough of them exhaust the
 * ids and no new tag name can be used (EBUSY).
 */
ATF_TC_WITH_CLEANUP(refused_rule_tags);
ATF_TC_HEAD(refused_rule_tags, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "pf");
	atf_tc_set_md_var(tc, "timeout", "900");
}

ATF_TC_BODY(refused_rule_tags, tc)
{
	static struct pfioc_rule pr;
	struct pfioc_trans io;
	struct pfioc_trans_e ioe;
	u_int32_t ticket;
	int i;

	COMMON_HEAD();

	trans_one(&io, &ioe, "");
	ATF_REQUIRE_MSG(ioctl(dev, DIOCXBEGIN, &io) == 0, "DIOCXBEGIN: %s",
	    strerror(errno));
	ticket = ioe.ticket;

	for (i = 0; i <= TAGID_MAX; i++) {
		memset(&pr, 0, sizeof(pr));
		init_rule(&pr.rule);
		snprintf(pr.rule.tagname, sizeof(pr.rule.tagname), "lt%05d", i);
		snprintf(pr.rule.match_tagname, sizeof(pr.rule.match_tagname),
		    "lm%05d", i);
		pr.ticket = ticket + 1;		/* stale: refused */
		ATF_REQUIRE_MSG(ioctl(dev, DIOCADDRULE, &pr) == -1 &&
		    errno == EBUSY, "stale DIOCADDRULE %d: %s", i,
		    strerror(errno));
	}

	memset(&pr, 0, sizeof(pr));
	init_rule(&pr.rule);
	strlcpy(pr.rule.tagname, "after", sizeof(pr.rule.tagname));
	pr.ticket = ticket;
	ATF_CHECK_MSG(ioctl(dev, DIOCADDRULE, &pr) == 0,
	    "a new tag after %d refused rules: %s (tag ids leaked)",
	    TAGID_MAX + 1, strerror(errno));
	(void)ioctl(dev, DIOCXROLLBACK, &io);
	COMMON_CLEANUP();
}

ATF_TC_CLEANUP(refused_rule_tags, tc)
{
	quiet("pfctl -q -F all");
}

/*
 * DIOCGETRULES takes an anchor reference for its transaction; when the
 * descriptor already holds the most transactions it may (EBUSY), the
 * reference must be dropped, or the anchor is never freed.
 */
static u_int
anchor_count(void)
{
	u_int n = 0;
	size_t len = sizeof(n);

	ATF_REQUIRE_MSG(sysctlbyname("net.pf.vnet_count.anchors", &n, &len,
	    NULL, 0) == 0, "net.pf.vnet_count.anchors: %s", strerror(errno));
	return (n);
}

ATF_TC_WITH_CLEANUP(getrules_limit_anchor);
GLUE_HEAD(getrules_limit_anchor)

ATF_TC_BODY(getrules_limit_anchor, tc)
{
	static struct pfioc_rule pr;
	u_int before;
	int fd, i, busy = 0;

	COMMON_HEAD();
	before = anchor_count();
	run("printf 'pass in proto tcp\\n' | pfctl -q -a fglim -f -");
	ATF_REQUIRE(anchor_count() > before);

	fd = open("/dev/pf", O_RDWR);
	ATF_REQUIRE(fd != -1);
	for (i = 0; i < 600; i++) {
		memset(&pr, 0, sizeof(pr));
		strlcpy(pr.anchor, "fglim", sizeof(pr.anchor));
		if (ioctl(fd, DIOCGETRULES, &pr) == -1) {
			ATF_REQUIRE_EQ(errno, EBUSY);
			busy++;
		}
	}
	ATF_REQUIRE_MSG(busy > 0, "the transaction limit was never reached");
	close(fd);

	run("pfctl -q -a fglim -F rules");
	ATF_CHECK_EQ_MSG(anchor_count(), before,
	    "%u anchors before, %u after (anchor references leaked)",
	    before, anchor_count());
	COMMON_CLEANUP();
}

ATF_TC_CLEANUP(getrules_limit_anchor, tc)
{
	quiet("pfctl -q -a fglim -F all");
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, getrule_ticket);
	ATF_TP_ADD_TC(tp, changerule_rtlabel);
	ATF_TP_ADD_TC(tp, port_ranges);
	ATF_TP_ADD_TC(tp, queues);
	ATF_TP_ADD_TC(tp, srcnodes);
	ATF_TP_ADD_TC(tp, limiters);
	ATF_TP_ADD_TC(tp, refused_rule_tags);
	ATF_TP_ADD_TC(tp, getrules_limit_anchor);

	return (atf_no_error());
}
