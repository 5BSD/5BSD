/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * Writes input/golden_tokens: one record per group of tokens, with fixed
 * times and values, covering every token type libbsm can print that a
 * program can make (the attribute tokens take a kernel structure).  The
 * expected praudit output beside it was made by the praudit and libbsm the
 * trail was first checked with (before the procident token existed), so
 * the praudit_golden_* cases show that every existing token prints as it
 * did.  Not built with the tests: the trail is checked in.
 *
 *	cc -o mkgolden mkgolden.c -lbsm && ./mkgolden > input/golden_tokens
 */

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include <bsm/audit_internal.h>
#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	NTOK	32

static const struct timeval when = { 1764000000, 123000 };

/* Write a record: a 32-bit header (plain or extended), the tokens, a trailer. */
static void
record(short event, token_t **toks, int n, int ex)
{
	static u_char body[MAX_AUDIT_RECORD_SIZE];
	u_char buf[MAX_AUDIT_HEADER_SIZE + AUDIT_TRAILER_SIZE];
	struct auditinfo_addr aia;
	token_t *hdr, *trl;
	size_t len, used, total;
	int i;

	used = 0;
	for (i = 0; i < n; i++) {
		len = sizeof(body) - used;
		if (toks[i] == NULL || au_close_token(toks[i], body + used,
		    &len) != 0)
			errx(1, "token %d", i);
		used += len;
	}
	memset(&aia, 0, sizeof(aia));
	aia.ai_termid.at_type = AU_IPv4;
	aia.ai_termid.at_addr[0] = htonl(0x0a000001);
	total = used + AUDIT_TRAILER_SIZE + (ex ? AUDIT_HEADER_EX_SIZE(&aia) :
	    AUDIT_HEADER_SIZE);
	if (ex)
		hdr = au_to_header32_ex_tm(total, event, 0, when, &aia);
	else
		hdr = au_to_header32_tm(total, event, 0, when);
	trl = au_to_trailer(total);
	len = sizeof(buf);
	if (hdr == NULL || au_close_token(hdr, buf, &len) != 0)
		errx(1, "header");
	fwrite(buf, len, 1, stdout);
	fwrite(body, used, 1, stdout);
	len = sizeof(buf);
	if (trl == NULL || au_close_token(trl, buf, &len) != 0)
		errx(1, "trailer");
	fwrite(buf, len, 1, stdout);
}

int
main(void)
{
	token_t *t[NTOK];
	au_tid_t tid = { 0x1234, 0x0a000001 };
	au_tid_addr_t tidx4, tidx6;
	struct ipc_perm perm;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct sockaddr_un sun;
	struct in_addr ia;
	struct in6_addr ia6;
	struct ip ip;
	gid_t groups[3] = { 0, 5, 20 };
	char *argv[] = { "golden", "-x", "arg", NULL };
	char *envp[] = { "HOME=/root", "TERM=vt100", NULL };
	struct timeval ft = { 1764000001, 0 };
	int n;

	memset(&tidx4, 0, sizeof(tidx4));
	tidx4.at_port = 0x1234;
	tidx4.at_type = AU_IPv4;
	tidx4.at_addr[0] = htonl(0x0a000001);
	memset(&tidx6, 0, sizeof(tidx6));
	tidx6.at_port = 0x5678;
	tidx6.at_type = AU_IPv6;
	tidx6.at_addr[0] = htonl(0x20010db8);
	tidx6.at_addr[3] = htonl(1);

	/* Subjects. */
	n = 0;
	t[n++] = au_to_subject32(1001, 1002, 1003, 1004, 1005, 4242, 77, &tid);
	t[n++] = au_to_subject32_ex(1001, 0, 0, 1004, 1005, 4243, 78, &tidx4);
	t[n++] = au_to_subject32_ex(1001, 0, 0, 1004, 1005, 4244, 79, &tidx6);
	t[n++] = au_to_subject64(1001, 1002, 1003, 1004, 1005, 4245, 80, &tid);
	t[n++] = au_to_subject64_ex(1001, 1002, 1003, 1004, 1005, 4246, 81,
	    &tidx6);
	t[n++] = au_to_return32(0, 7);
	record(AUE_EXECVE, t, n, 0);

	/* Processes, 64-bit return, the extended header. */
	n = 0;
	t[n++] = au_to_process32(1001, 1002, 1003, 1004, 1005, 4250, 82, &tid);
	t[n++] = au_to_process32_ex(1001, 1002, 1003, 1004, 1005, 4251, 83,
	    &tidx4);
	t[n++] = au_to_process64(1001, 1002, 1003, 1004, 1005, 4252, 84, &tid);
	t[n++] = au_to_process64_ex(1001, 1002, 1003, 1004, 1005, 4253, 85,
	    &tidx6);
	t[n++] = au_to_return64(13, 0xffffffffffffffffULL);
	record(AUE_KILL, t, n, 1);

	/* Arguments and text. */
	n = 0;
	t[n++] = au_to_arg32(1, "fd", 3);
	t[n++] = au_to_arg64(2, "offset", 0x123456789abcdefULL);
	t[n++] = au_to_text("golden text, with a comma");
	t[n++] = au_to_path("/usr/tests/golden");
	t[n++] = au_to_exec_args(argv);
	t[n++] = au_to_exec_env(envp);
	t[n++] = au_to_zonename("golden-jail");
	t[n++] = au_to_exit(3, 0);
	t[n++] = au_to_seq(99);
	t[n++] = au_to_return32(0, 0);
	record(AUE_OPEN_RWTC, t, n, 0);

	/* Network. */
	n = 0;
	ia.s_addr = htonl(0xc0000201);
	t[n++] = au_to_in_addr(&ia);
	memset(&ia6, 0, sizeof(ia6));
	ia6.s6_addr[0] = 0x20;
	ia6.s6_addr[1] = 0x01;
	ia6.s6_addr[15] = 0x02;
	t[n++] = au_to_in_addr_ex(&ia6);
	memset(&ip, 0, sizeof(ip));
	ip.ip_v = 4;
	ip.ip_hl = 5;
	ip.ip_tos = 0x10;
	ip.ip_len = htons(84);
	ip.ip_id = htons(0x4242);
	ip.ip_ttl = 64;
	ip.ip_p = IPPROTO_ICMP;
	ip.ip_src.s_addr = htonl(0xc0000201);
	ip.ip_dst.s_addr = htonl(0xc0000202);
	t[n++] = au_to_ip(&ip);
	t[n++] = au_to_iport(htons(8080));
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(22);
	sin.sin_addr.s_addr = htonl(0xc0000203);
	t[n++] = au_to_sock_inet32(&sin);
	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_len = sizeof(sin6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(443);
	sin6.sin6_addr = ia6;
	t[n++] = au_to_sock_inet128(&sin6);
	memset(&sun, 0, sizeof(sun));
	sun.sun_len = sizeof(sun);
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, "/var/run/golden.sock", sizeof(sun.sun_path));
	t[n++] = au_to_sock_unix(&sun);
	t[n++] = au_to_socket_ex(AF_INET, SOCK_STREAM,
	    (struct sockaddr *)&sin, (struct sockaddr *)&sin);
	t[n++] = au_to_return32(0, 5);
	record(AUE_CONNECT, t, n, 0);

	/* IPC, opaque and data, groups, privileges, file. */
	n = 0;
	t[n++] = au_to_ipc(AT_IPC_SHM, 12);
	memset(&perm, 0, sizeof(perm));
	perm.uid = 1001;
	perm.gid = 1002;
	perm.cuid = 1003;
	perm.cgid = 1004;
	perm.mode = 0640;
	perm.seq = 5;
	perm.key = 0x5eed;
	t[n++] = au_to_ipc_perm(&perm);
	t[n++] = au_to_opaque("\001\002\003\377", 4);
	t[n++] = au_to_data(AUP_HEX, AUR_INT32, 2, "\001\002\003\004\005\006\007\010");
	t[n++] = au_to_data(AUP_STRING, AUR_CHAR, 6, "golden");
	t[n++] = au_to_data(AUP_DECIMAL, AUR_SHORT, 2, "\000\001\000\002");
	t[n++] = au_to_newgroups(3, groups);
	t[n++] = au_to_upriv(1, "proc_setid");
	t[n++] = au_to_privset("effective", "file_read,proc_setid");
	t[n++] = au_to_file("golden.trail", ft);
	t[n++] = au_to_return32(1, (u_int32_t)-1);
	record(AUE_SHMGET, t, n, 0);

	return (0);
}
