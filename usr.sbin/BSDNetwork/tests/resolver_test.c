/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/capsicum.h>
#include <sys/wait.h>
#include <atf-c.h>

/* Exercise the resolver's internal DNS path with a local nameserver. */
#include "../resolver.c"

ATF_TC(reply_validation);
ATF_TC_HEAD(reply_validation, tc)
{
	atf_tc_set_md_var(tc, "descr", "DNS reply identity and question checks");
}
ATF_TC_BODY(reply_validation, tc)
{
	u_char query[NS_PACKETSZ], reply[NS_PACKETSZ];
	int len;

	ATF_REQUIRE(res_ninit(&g_res) == 0);
	len = res_nmkquery(&g_res, ns_o_query, "example.test", ns_c_in,
	    ns_t_a, NULL, 0, NULL, query, sizeof(query));
	ATF_REQUIRE(len > NS_HFIXEDSZ + 2);
	memcpy(reply, query, (size_t)len);
	reply[2] |= 0x80;
	ATF_CHECK_EQ(dns_reply_status(reply, len, query, "example.test",
	    ns_t_a), 0);
	reply[2] |= 0x02;
	ATF_CHECK_EQ(dns_reply_status(reply, len, query, "example.test",
	    ns_t_a), 1);
	reply[2] &= ~0x02;
	reply[13] = 'x';
	ATF_CHECK_EQ(dns_reply_status(reply, len, query, "example.test",
	    ns_t_a), -1);
	reply[13] = query[13];
	reply[2] |= 0x08;
	ATF_CHECK_EQ(dns_reply_status(reply, len, query, "example.test",
	    ns_t_a), -1);
	reply[2] &= ~0x08;
	reply[3] = ns_r_servfail;
	ATF_CHECK_EQ(dns_reply_status(reply, len, query, "example.test",
	    ns_t_a), -2);
	reply[3] = 0;
	reply[0] ^= 1;
	ATF_CHECK_EQ(dns_reply_status(reply, len, query, "example.test",
	    ns_t_a), -1);
	res_nclose(&g_res);
}

ATF_TC(ignores_bad_udp_reply);
ATF_TC_HEAD(ignores_bad_udp_reply, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A bad UDP packet does not discard a later valid answer");
}

static size_t
append_test_a(u_char *packet, size_t at, const u_char *owner,
    size_t ownerlen, u_char last_octet)
{
	memcpy(packet + at, owner, ownerlen);
	at += ownerlen;
	memset(packet + at, 0, 10);
	packet[at + 1] = ns_t_a;
	packet[at + 3] = ns_c_in;
	packet[at + 9] = 4;
	at += 10;
	packet[at++] = 192;
	packet[at++] = 0;
	packet[at++] = 2;
	packet[at++] = last_octet;
	return (at);
}

ATF_TC(answer_owner_chain);
ATF_TC_HEAD(answer_owner_chain, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Only the question or a valid CNAME target supplies addresses");
}
ATF_TC_BODY(answer_owner_chain, tc)
{
	static const u_char other[] =
	    { 5, 'o', 't', 'h', 'e', 'r', 4, 't', 'e', 's', 't', 0 };
	static const u_char alias[] =
	    { 5, 'a', 'l', 'i', 'a', 's', 4, 't', 'e', 's', 't', 0 };
	static const u_char question_owner[] = { 0xc0, 0x0c };
	struct rslv_addr addrs[2];
	char canon[NS_MAXDNAME];
	u_char query[NS_PACKETSZ], reply[NS_PACKETSZ + 128];
	u_char alias_owner[2];
	size_t at, alias_offset;
	int qlen, n;

	ATF_REQUIRE(res_ninit(&g_res) == 0);
	qlen = res_nmkquery(&g_res, ns_o_query, "example.test", ns_c_in,
	    ns_t_a, NULL, 0, NULL, query, sizeof(query));
	ATF_REQUIRE(qlen > NS_HFIXEDSZ);
	memcpy(reply, query, (size_t)qlen);
	reply[2] |= 0x80;
	reply[3] = 0x80;
	reply[7] = 1;
	at = append_test_a(reply, (size_t)qlen, other, sizeof(other), 44);
	n = 0;
	canon[0] = '\0';
	ATF_CHECK_EQ(dns_parse(reply, (int)at, "example.test", ns_t_a,
	    addrs, 2, &n, canon, sizeof(canon)), 0);
	ATF_CHECK_EQ(n, 0);

	/* The CNAME target can be compressed as the following A owner. */
	reply[7] = 2;
	at = (size_t)qlen;
	memcpy(reply + at, question_owner, sizeof(question_owner));
	at += sizeof(question_owner);
	memset(reply + at, 0, 10);
	reply[at + 1] = ns_t_cname;
	reply[at + 3] = ns_c_in;
	reply[at + 9] = sizeof(alias);
	at += 10;
	alias_offset = at;
	memcpy(reply + at, alias, sizeof(alias));
	at += sizeof(alias);
	alias_owner[0] = 0xc0 | (u_char)(alias_offset >> 8);
	alias_owner[1] = (u_char)alias_offset;
	at = append_test_a(reply, at, alias_owner, sizeof(alias_owner), 45);
	n = 0;
	canon[0] = '\0';
	ATF_CHECK_EQ(dns_parse(reply, (int)at, "example.test", ns_t_a,
	    addrs, 2, &n, canon, sizeof(canon)), 1);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_STREQ(canon, "alias.test");
	if (n == 1)
		ATF_CHECK_EQ(((const u_char *)&addrs[0].a.v4)[3], 45);
	/* A later malformed address must not leak the earlier valid one. */
	reply[7] = 3;
	{
		size_t second = at;

		at = append_test_a(reply, at, alias_owner,
		    sizeof(alias_owner), 46);
		reply[second + sizeof(alias_owner) + 9] = 3;
	}
	n = 0;
	canon[0] = '\0';
	ATF_CHECK_EQ(dns_parse(reply, (int)at, "example.test", ns_t_a,
	    addrs, 2, &n, canon, sizeof(canon)), -1);
	ATF_CHECK_EQ(n, 0);
	ATF_CHECK_STREQ(canon, "");

	/* A compression pointer back to itself must be rejected. */
	reply[7] = 1;
	at = alias_offset;
	reply[at - 1] = 2;
	reply[at] = 0xc0 | (u_char)(at >> 8);
	reply[at + 1] = (u_char)at;
	n = 0;
	ATF_CHECK_EQ(dns_parse(reply, (int)at + 2, "example.test",
	    ns_t_a, addrs, 2, &n, canon, sizeof(canon)), -1);
	ATF_CHECK_EQ(n, 0);
	res_nclose(&g_res);
}
ATF_TC_BODY(ignores_bad_udp_reply, tc)
{
	struct sockaddr_in sa, peer;
	struct rslv_addr addrs[1];
	struct in_addr expected;
	socklen_t salen = sizeof(sa), peerlen = sizeof(peer);
	char canon[NS_MAXDNAME] = "";
	u_char query[NS_PACKETSZ], answer[NS_PACKETSZ + 16];
	int udp, n = 0, status, added;
	ssize_t qlen;
	pid_t server;

	udp = socket(AF_INET, SOCK_DGRAM, 0);
	ATF_REQUIRE(udp >= 0);
	memset(&sa, 0, sizeof(sa));
	sa.sin_len = sizeof(sa);
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ATF_REQUIRE(bind(udp, (struct sockaddr *)&sa, sizeof(sa)) == 0);
	ATF_REQUIRE(getsockname(udp, (struct sockaddr *)&sa, &salen) == 0);
	ATF_REQUIRE(res_ninit(&g_res) == 0);
	g_res.retrans = 1;
	g_res.retry = 1;
	memset(g_ns, 0, sizeof(g_ns));
	g_ns[0].sin = sa;
	g_nns = 1;
	server = fork();
	ATF_REQUIRE(server >= 0);
	if (server == 0) {
		alarm(5);
		qlen = recvfrom(udp, query, sizeof(query), 0,
		    (struct sockaddr *)&peer, &peerlen);
		if (qlen <= NS_HFIXEDSZ || qlen > NS_PACKETSZ)
			_exit(1);
		memcpy(answer, query, (size_t)qlen);
		answer[2] |= 0x80;
		answer[3] = 0x80;
		answer[6] = 0;
		answer[7] = 1;
		memset(answer + qlen, 0, 16);
		answer[qlen] = 0xc0;
		answer[qlen + 1] = 0x0c;
		answer[qlen + 3] = ns_t_a;
		answer[qlen + 5] = ns_c_in;
		answer[qlen + 11] = 4;
		answer[qlen + 12] = 192;
		answer[qlen + 13] = 0;
		answer[qlen + 14] = 2;
		answer[qlen + 15] = 43;
		answer[0] ^= 1;
		if (sendto(udp, answer, (size_t)qlen + 16, 0,
		    (struct sockaddr *)&peer, peerlen) != qlen + 16)
			_exit(2);
		answer[0] ^= 1;
		if (sendto(udp, answer, (size_t)qlen + 16, 0,
		    (struct sockaddr *)&peer, peerlen) != qlen + 16)
			_exit(3);
		_exit(0);
	}
	added = dns_query("example.test", ns_t_a, addrs, 1, &n,
	    canon, sizeof(canon));
	ATF_REQUIRE(waitpid(server, &status, 0) == server);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "test nameserver failed: status %d", status);
	ATF_CHECK_EQ(added, 1);
	ATF_CHECK_EQ(n, 1);
	ATF_REQUIRE(inet_pton(AF_INET, "192.0.2.43", &expected) == 1);
	if (n == 1)
		ATF_CHECK(memcmp(&addrs[0].a.v4, &expected, sizeof(expected)) == 0);
	res_nclose(&g_res);
	close(udp);
}

/* The child sends a truncated datagram, then a framed TCP A record. */
static void
serve_truncated_then_tcp(int udp, int tcp)
{
	struct sockaddr_in peer;
	socklen_t peerlen = sizeof(peer);
	u_char query[NS_PACKETSZ], answer[NS_PACKETSZ + 16], prefix[2];
	ssize_t n;
	int conn, len;

	alarm(5);
	n = recvfrom(udp, query, sizeof(query), 0,
	    (struct sockaddr *)&peer, &peerlen);
	if (n <= NS_HFIXEDSZ || n > NS_PACKETSZ)
		_exit(1);
	query[2] |= 0x82;
	query[3] = 0x80;
	if (sendto(udp, query, (size_t)n, 0,
	    (struct sockaddr *)&peer, peerlen) != n)
		_exit(2);
	conn = accept(tcp, NULL, NULL);
	if (conn < 0 || recv(conn, prefix, 2, MSG_WAITALL) != 2)
		_exit(3);
	len = ((int)prefix[0] << 8) | prefix[1];
	if (len <= NS_HFIXEDSZ || len > NS_PACKETSZ ||
	    recv(conn, query, (size_t)len, MSG_WAITALL) != len)
		_exit(4);
	memcpy(answer, query, (size_t)len);
	answer[2] |= 0x80;
	answer[2] &= ~0x02;
	answer[3] = 0x80;
	answer[6] = 0;
	answer[7] = 1;
	memset(answer + len, 0, 16);
	answer[len] = 0xc0;
	answer[len + 1] = 0x0c;
	answer[len + 3] = ns_t_a;
	answer[len + 5] = ns_c_in;
	answer[len + 11] = 4;
	answer[len + 12] = 192;
	answer[len + 13] = 0;
	answer[len + 14] = 2;
	answer[len + 15] = 42;
	len += 16;
	prefix[0] = (u_char)(len >> 8);
	prefix[1] = (u_char)len;
	if (send(conn, prefix, 1, MSG_NOSIGNAL) != 1)
		_exit(5);
	usleep(10000);
	if (send(conn, prefix + 1, 1, MSG_NOSIGNAL) != 1 ||
	    send(conn, answer, (size_t)len, MSG_NOSIGNAL) != len)
		_exit(6);
	close(conn);
	_exit(0);
}

ATF_TC(truncated_udp_falls_back_to_tcp);
ATF_TC_HEAD(truncated_udp_falls_back_to_tcp, tc)
{
	atf_tc_set_md_var(tc, "descr", "Truncated UDP answers retry over TCP");
}
ATF_TC_BODY(truncated_udp_falls_back_to_tcp, tc)
{
	struct sockaddr_in sa;
	struct {
		int added;
		int n;
		struct in_addr addr;
	} result;
	struct in_addr expected;
	socklen_t salen = sizeof(sa);
	int udp, tcp, resultfd[2], status;
	pid_t server, client;

	tcp = socket(AF_INET, SOCK_STREAM, 0);
	ATF_REQUIRE(tcp >= 0);
	memset(&sa, 0, sizeof(sa));
	sa.sin_len = sizeof(sa);
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ATF_REQUIRE(bind(tcp, (struct sockaddr *)&sa, sizeof(sa)) == 0);
	ATF_REQUIRE(getsockname(tcp, (struct sockaddr *)&sa, &salen) == 0);
	ATF_REQUIRE(listen(tcp, 1) == 0);
	udp = socket(AF_INET, SOCK_DGRAM, 0);
	ATF_REQUIRE(udp >= 0);
	ATF_REQUIRE(bind(udp, (struct sockaddr *)&sa, sizeof(sa)) == 0);
	ATF_REQUIRE(res_ninit(&g_res) == 0);
	g_res.retrans = 1;
	g_res.retry = 1;
	memset(g_ns, 0, sizeof(g_ns));
	g_ns[0].sin = sa;
	g_nns = 1;
	server = fork();
	ATF_REQUIRE(server >= 0);
	if (server == 0)
		serve_truncated_then_tcp(udp, tcp);
	ATF_REQUIRE(pipe(resultfd) == 0);
	client = fork();
	ATF_REQUIRE(client >= 0);
	if (client == 0) {
		struct rslv_addr addrs[2];
		char canon[NS_MAXDNAME] = "";

		alarm(5);
		close(resultfd[0]);
		if (cap_enter() == -1)
			_exit(7);
		memset(&result, 0, sizeof(result));
		result.added = dns_query("example.test", ns_t_a, addrs, 2,
		    &result.n, canon, sizeof(canon));
		if (result.n == 1)
			result.addr = addrs[0].a.v4;
		if (write(resultfd[1], &result, sizeof(result)) !=
		    sizeof(result))
			_exit(8);
		_exit(0);
	}
	close(resultfd[1]);
	ATF_REQUIRE(read(resultfd[0], &result, sizeof(result)) ==
	    sizeof(result));
	close(resultfd[0]);
	ATF_REQUIRE(waitpid(client, &status, 0) == client);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "capability-mode resolver failed: status %d", status);
	ATF_REQUIRE(waitpid(server, &status, 0) == server);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "test nameserver failed: status %d", status);
	ATF_CHECK_EQ(result.added, 1);
	ATF_CHECK_EQ(result.n, 1);
	ATF_REQUIRE(inet_pton(AF_INET, "192.0.2.42", &expected) == 1);
	if (result.n == 1)
		ATF_CHECK(memcmp(&result.addr, &expected, sizeof(expected)) == 0);
	res_nclose(&g_res);
	close(udp);
	close(tcp);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, reply_validation);
	ATF_TP_ADD_TC(tp, ignores_bad_udp_reply);
	ATF_TP_ADD_TC(tp, answer_owner_chain);
	ATF_TP_ADD_TC(tp, truncated_udp_falls_back_to_tcp);
	return (atf_no_error());
}
