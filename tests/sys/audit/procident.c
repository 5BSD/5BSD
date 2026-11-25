/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * The procident token (AUT_PROCIDENT, 0xc0) of kernel audit records: the
 * subject's audit token ids (audit_token(3)), written after the return
 * token and before the trailer, under the negative audit policy
 * `noprocident' (AUDIT_NOPROCIDENT): the token is written unless the policy
 * names it.  The token is read here from the raw record bytes, so the
 * format is checked independently of libbsm's parser; praudit's and
 * auditreduce's handling of it is checked separately.
 *
 * On a tree without the token these cases fail: no token, no policy bit,
 * no auditreduce -U.
 */

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <bsm/audit_kevents.h>
#include <bsm/audit_uevents.h>
#include <bsm/libbsm.h>
#include <security/audit/audit_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"

#define	PIN_SYS_audit_token_get	1012

#ifndef AUT_PROCIDENT
#define	AUT_PROCIDENT		0xc0
#endif
#ifndef AUDIT_NOPROCIDENT
#define	AUDIT_NOPROCIDENT	0x00010000
#endif

/* Token id, body length, then the version 1 body (audit.log(5)). */
#define	PROCIDENT_V1_SIZE	(1 + 2 + 57)

/* The ids of a process as audit_token_get(2) gives them. */
struct ids {
	pid_t		pid;
	uint64_t	uniqueid;
	uint64_t	execgen;
	uint64_t	imageid;
	int		jid;
};

/* The procident token as read from a record. */
struct procident {
	u_int		len;		/* token length, id included */
	u_int		version;
	uint64_t	uniqueid;
	uint64_t	execgen;
	uint64_t	imageid;
	int32_t		jid;
	uint64_t	r_uniqueid;
	uint64_t	r_execgen;
	int32_t		r_pid;
	uint64_t	image_after;
};

/* What a record looked like: its event, subject pid and token order. */
struct record {
	u_short		event;
	pid_t		subj_pid;
	int		ntok;
	u_char		ids[64];	/* token ids in order */
	bool		has_procident;
	struct procident pi;
	u_char		*raw;
	int		rawlen;
};

static uint64_t
be64(const u_char *p)
{
	return (be64dec(p));
}

/* The ids by pid; fails on a tree without the call. */
static void
ids_get(pid_t pid, struct ids *ids)
{
	uint64_t w[8];

	ATF_REQUIRE(signal(SIGSYS, SIG_IGN) != SIG_ERR);
	ATF_REQUIRE_EQ_MSG(0, syscall(PIN_SYS_audit_token_get, -1, pid, 0, w),
	    "audit_token_get(%d): %s", (int)pid, strerror(errno));
	/* The layout audit_token(3) keeps private, read by this test only. */
	ids->uniqueid = w[0];
	ids->execgen = w[1];
	ids->imageid = w[2];
	ids->pid = (pid_t)(uint32_t)w[3];
	ids->jid = (int)(w[3] >> 32);
}

static void
procident_decode(const u_char *t, u_int len, struct procident *pi)
{
	ATF_REQUIRE_MSG(len >= PROCIDENT_V1_SIZE,
	    "procident token of %u bytes", len);
	pi->len = len;
	ATF_REQUIRE_EQ_MSG(len - 3, be16dec(t + 1),
	    "body length %u in a token of %u bytes", be16dec(t + 1), len);
	pi->version = t[3];
	pi->uniqueid = be64(t + 4);
	pi->execgen = be64(t + 12);
	pi->imageid = be64(t + 20);
	pi->jid = (int32_t)be32dec(t + 28);
	pi->r_uniqueid = be64(t + 32);
	pi->r_execgen = be64(t + 40);
	pi->r_pid = (int32_t)be32dec(t + 48);
	pi->image_after = be64(t + 52);
}

/* Split one record into what the cases look at. */
static void
record_parse(u_char *buf, int reclen, struct record *r)
{
	tokenstr_t tok;
	int off;

	memset(r, 0, sizeof(*r));
	r->raw = buf;
	r->rawlen = reclen;
	for (off = 0; off < reclen; off += tok.len) {
		ATF_REQUIRE_MSG(au_fetch_tok(&tok, buf + off, reclen - off) == 0,
		    "unparseable token at offset %d", off);
		if (r->ntok < (int)sizeof(r->ids))
			r->ids[r->ntok++] = tok.id;
		switch (tok.id) {
		case AUT_HEADER32:
			r->event = tok.tt.hdr32.e_type;
			break;
		case AUT_HEADER32_EX:
			r->event = tok.tt.hdr32_ex.e_type;
			break;
		case AUT_SUBJECT32:
			r->subj_pid = tok.tt.subj32.pid;
			break;
		case AUT_SUBJECT32_EX:
			r->subj_pid = tok.tt.subj32_ex.pid;
			break;
		case AUT_PROCIDENT:
			r->has_procident = true;
			procident_decode(tok.data, tok.len, &r->pi);
			break;
		}
	}
}

/* Read records until one of `event' from `pid' comes; blocks until then. */
static void
record_wait(FILE *pipestream, u_short event, pid_t pid, struct record *r)
{
	u_char *buf;
	int reclen;

	for (;;) {
		reclen = au_read_rec(pipestream, &buf);
		ATF_REQUIRE_MSG(reclen > 0, "au_read_rec: %s", strerror(errno));
		record_parse(buf, reclen, r);
		if (r->event == event && r->subj_pid == pid)
			return;
		free(buf);
	}
}

/*
 * A child that execs cat(1) on a pipe: its ids before the exec, after it,
 * and the audit record of its execve(2).
 */
static void
exec_record(FILE *pipestream, struct ids *pre, struct ids *post,
    struct record *r)
{
	int in[2], out[2], status;
	pid_t pid;
	char c;

	ATF_REQUIRE_EQ(0, pipe(in));
	ATF_REQUIRE_EQ(0, pipe(out));
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		char *const argv[] = { __DECONST(char *, "cat"), NULL };

		(void)close(in[1]);
		(void)close(out[0]);
		if (read(in[0], &c, 1) != 1 || write(out[1], "x", 1) != 1)
			_exit(1);
		if (dup2(in[0], STDIN_FILENO) == -1 ||
		    dup2(out[1], STDOUT_FILENO) == -1)
			_exit(1);
		execv("/bin/cat", argv);
		_exit(1);
	}
	ATF_REQUIRE_EQ(0, close(in[0]));
	ATF_REQUIRE_EQ(0, close(out[1]));
	ids_get(pid, pre);
	ATF_REQUIRE_EQ(1, write(in[1], "g", 1));
	ATF_REQUIRE_EQ(1, read(out[0], &c, 1));
	/* cat(1) echoes once it runs: the exec is done. */
	ATF_REQUIRE_EQ(1, write(in[1], "e", 1));
	ATF_REQUIRE_EQ(1, read(out[0], &c, 1));
	ATF_REQUIRE_EQ('e', c);
	ids_get(pid, post);
	ATF_REQUIRE_EQ(0, close(in[1]));
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_REQUIRE_EQ(0, close(out[0]));
	record_wait(pipestream, AUE_EXECVE, pid, r);
}

/*
 * The kernel audit policy, saved in a file of the work directory for the
 * cleanup and set to `policy' with the 32-bit A_SETPOLICY.
 */
static void
policy_set(int policy)
{
	FILE *fp;
	int old;

	ATF_REQUIRE_EQ(0, auditon(A_GETPOLICY, &old, sizeof(old)));
	fp = fopen("audit_policy", "r");
	if (fp == NULL) {
		fp = fopen("audit_policy", "wx");
		ATF_REQUIRE(fp != NULL);
		ATF_REQUIRE(fprintf(fp, "%d\n", old) > 0);
	}
	ATF_REQUIRE_EQ(0, fclose(fp));
	ATF_REQUIRE_EQ_MSG(0, auditon(A_SETPOLICY, &policy, sizeof(policy)),
	    "A_SETPOLICY %#x: %s", policy, strerror(errno));
}

static void
policy_restore(void)
{
	FILE *fp;
	int old;

	fp = fopen("audit_policy", "r");
	if (fp == NULL)
		return;
	if (fscanf(fp, "%d", &old) != 1 ||
	    auditon(A_SETPOLICY, &old, sizeof(old)) != 0)
		fprintf(stderr, "the audit policy was not restored\n");
	(void)fclose(fp);
}

static void
check_procident_last(const struct record *r)
{
	ATF_REQUIRE_MSG(r->has_procident, "no procident token in the record");
	ATF_REQUIRE(r->ntok >= 3);
	ATF_CHECK_EQ_MSG(AUT_TRAILER, r->ids[r->ntok - 1], "last token %#x",
	    r->ids[r->ntok - 1]);
	ATF_CHECK_EQ_MSG(AUT_PROCIDENT, r->ids[r->ntok - 2],
	    "token before the trailer %#x", r->ids[r->ntok - 2]);
	ATF_CHECK_MSG(r->ids[r->ntok - 3] == AUT_RETURN32 ||
	    r->ids[r->ntok - 3] == AUT_RETURN64,
	    "token before procident %#x", r->ids[r->ntok - 3]);
}

ATF_TC_WITH_CLEANUP(procident_token);
ATF_TC_HEAD(procident_token, tc)
{
	atf_tc_set_md_var(tc, "descr", "An execve record carries the "
	    "pre-exec ids and the new image id after the return token");
}
ATF_TC_BODY(procident_token, tc)
{
	struct pollfd fds[1];
	struct ids pre, post;
	struct record r;
	FILE *pipestream;

	pipestream = setup(fds, "ex");
	policy_set(AUDIT_CNT);
	exec_record(pipestream, &pre, &post, &r);
	check_procident_last(&r);
	ATF_CHECK_EQ(PROCIDENT_V1_SIZE, r.pi.len);
	ATF_CHECK_EQ(1, r.pi.version);
	/* The subject as it was when execve(2) started ... */
	ATF_CHECK_EQ(pre.uniqueid, r.pi.uniqueid);
	ATF_CHECK_EQ(pre.execgen, r.pi.execgen);
	ATF_CHECK_EQ(pre.imageid, r.pi.imageid);
	ATF_CHECK_EQ(pre.jid, r.pi.jid);
	/* ... and the image it runs after it. */
	ATF_CHECK_EQ(post.imageid, r.pi.image_after);
	ATF_CHECK(post.imageid != pre.imageid);
	/* No responsibility yet (slice R1). */
	ATF_CHECK_EQ(0, r.pi.r_uniqueid);
	ATF_CHECK_EQ(0, r.pi.r_execgen);
	ATF_CHECK_EQ(0, r.pi.r_pid);
	free(r.raw);
	ATF_REQUIRE_EQ(0, fclose(pipestream));
}
ATF_TC_CLEANUP(procident_token, tc)
{
	policy_restore();
	cleanup();
}

/* praudit's default, raw and XML forms of the token. */
ATF_TC_WITH_CLEANUP(procident_printed);
ATF_TC_HEAD(procident_printed, tc)
{
	atf_tc_set_md_var(tc, "descr", "libbsm prints the procident token");
}
ATF_TC_BODY(procident_printed, tc)
{
	struct pollfd fds[1];
	struct ids pre, post;
	struct record r;
	tokenstr_t tok;
	FILE *pipestream, *mem;
	char want[256], *buf;
	size_t size;
	int off;

	pipestream = setup(fds, "ex");
	policy_set(AUDIT_CNT);
	exec_record(pipestream, &pre, &post, &r);
	check_procident_last(&r);
	for (off = 0; off < r.rawlen; off += tok.len) {
		ATF_REQUIRE_EQ(0, au_fetch_tok(&tok, r.raw + off,
		    r.rawlen - off));
		if (tok.id == AUT_PROCIDENT)
			break;
	}
	mem = open_memstream(&buf, &size);
	ATF_REQUIRE(mem != NULL);
	au_print_flags_tok(mem, &tok, __DECONST(char *, ","), AU_OFLAG_NONE);
	ATF_REQUIRE_EQ(0, fclose(mem));
	snprintf(want, sizeof(want), "procident,1,%ju,%ju,%ju,%d,0,0,0,%ju",
	    (uintmax_t)pre.uniqueid, (uintmax_t)pre.execgen,
	    (uintmax_t)pre.imageid, pre.jid, (uintmax_t)post.imageid);
	ATF_CHECK_STREQ(want, buf);
	free(buf);

	mem = open_memstream(&buf, &size);
	ATF_REQUIRE(mem != NULL);
	au_print_flags_tok(mem, &tok, __DECONST(char *, ","), AU_OFLAG_RAW);
	ATF_REQUIRE_EQ(0, fclose(mem));
	snprintf(want, sizeof(want), "%u,1,%ju,%ju,%ju,%d,0,0,0,%ju",
	    AUT_PROCIDENT, (uintmax_t)pre.uniqueid, (uintmax_t)pre.execgen,
	    (uintmax_t)pre.imageid, pre.jid, (uintmax_t)post.imageid);
	ATF_CHECK_STREQ(want, buf);
	free(buf);

	mem = open_memstream(&buf, &size);
	ATF_REQUIRE(mem != NULL);
	au_print_flags_tok(mem, &tok, __DECONST(char *, ","), AU_OFLAG_XML);
	ATF_REQUIRE_EQ(0, fclose(mem));
	snprintf(want, sizeof(want), "<procident version=\"1\" "
	    "uniqueid=\"%ju\" execgen=\"%ju\" imageid=\"%ju\" jid=\"%d\" "
	    "r_uniqueid=\"0\" r_execgen=\"0\" r_pid=\"0\" "
	    "image_after=\"%ju\" />",
	    (uintmax_t)pre.uniqueid, (uintmax_t)pre.execgen,
	    (uintmax_t)pre.imageid, pre.jid, (uintmax_t)post.imageid);
	ATF_CHECK_STREQ(want, buf);
	free(buf);
	free(r.raw);
	ATF_REQUIRE_EQ(0, fclose(pipestream));
}
ATF_TC_CLEANUP(procident_printed, tc)
{
	policy_restore();
	cleanup();
}

/* auditreduce -U, -G and -I select the record by the subject's ids. */
ATF_TC_WITH_CLEANUP(procident_auditreduce);
ATF_TC_HEAD(procident_auditreduce, tc)
{
	atf_tc_set_md_var(tc, "require.progs", "auditreduce");
}
ATF_TC_BODY(procident_auditreduce, tc)
{
	struct pollfd fds[1];
	struct ids pre, post;
	struct record r;
	FILE *pipestream, *fp;
	char cmd[256];
	struct stat sb;

	pipestream = setup(fds, "ex");
	policy_set(AUDIT_CNT);
	exec_record(pipestream, &pre, &post, &r);
	check_procident_last(&r);
	fp = fopen("trail", "w");
	ATF_REQUIRE(fp != NULL);
	ATF_REQUIRE_EQ(1, fwrite(r.raw, r.rawlen, 1, fp));
	ATF_REQUIRE_EQ(0, fclose(fp));

#define	REDUCE(opt, val, out) do {					\
	snprintf(cmd, sizeof(cmd), "auditreduce %s %ju trail > %s",	\
	    (opt), (uintmax_t)(val), (out));				\
	ATF_REQUIRE_EQ_MSG(0, system(cmd), "%s failed", cmd);		\
} while (0)
	REDUCE("-U", pre.uniqueid, "u_hit");
	REDUCE("-U", pre.uniqueid + 1, "u_miss");
	REDUCE("-G", pre.execgen, "g_hit");
	REDUCE("-G", post.execgen, "g_miss");
	REDUCE("-I", pre.imageid, "i_hit");
	REDUCE("-I", post.imageid, "i_miss");
#undef REDUCE
	ATF_REQUIRE_EQ(0, stat("u_hit", &sb));
	ATF_CHECK_EQ(r.rawlen, sb.st_size);
	ATF_REQUIRE_EQ(0, stat("g_hit", &sb));
	ATF_CHECK_EQ(r.rawlen, sb.st_size);
	ATF_REQUIRE_EQ(0, stat("i_hit", &sb));
	ATF_CHECK_EQ(r.rawlen, sb.st_size);
	ATF_REQUIRE_EQ(0, stat("u_miss", &sb));
	ATF_CHECK_EQ(0, sb.st_size);
	ATF_REQUIRE_EQ(0, stat("g_miss", &sb));
	ATF_CHECK_EQ(0, sb.st_size);
	ATF_REQUIRE_EQ(0, stat("i_miss", &sb));
	ATF_CHECK_EQ(0, sb.st_size);
	free(r.raw);
	ATF_REQUIRE_EQ(0, fclose(pipestream));
}
ATF_TC_CLEANUP(procident_auditreduce, tc)
{
	policy_restore();
	cleanup();
}

/* With `noprocident' the token is not written; the shipped policy writes it. */
ATF_TC_WITH_CLEANUP(procident_policy);
ATF_TC_HEAD(procident_policy, tc)
{
}
ATF_TC_BODY(procident_policy, tc)
{
	struct pollfd fds[1];
	struct ids pre, post;
	struct record r;
	FILE *pipestream;
	int i;

	pipestream = setup(fds, "ex");
	policy_set(AUDIT_CNT | AUDIT_NOPROCIDENT);
	exec_record(pipestream, &pre, &post, &r);
	ATF_CHECK_MSG(!r.has_procident,
	    "procident written with the noprocident policy");
	for (i = 0; i < r.ntok; i++)
		ATF_CHECK(r.ids[i] != AUT_PROCIDENT);
	ATF_CHECK_EQ(AUT_TRAILER, r.ids[r.ntok - 1]);
	free(r.raw);

	/* contrib/openbsm/etc/audit_control: policy:cnt,argv */
	policy_set(AUDIT_CNT | AUDIT_ARGV);
	exec_record(pipestream, &pre, &post, &r);
	check_procident_last(&r);
	free(r.raw);
	ATF_REQUIRE_EQ(0, fclose(pipestream));
}
ATF_TC_CLEANUP(procident_policy, tc)
{
	policy_restore();
	cleanup();
}

/*
 * A_GETPOLICY reports the bit after A_SETPOLICY set it, with both the
 * 32-bit and the 64-bit lengths each way; libbsm names it.
 */
ATF_TC_WITH_CLEANUP(procident_policy_lengths);
ATF_TC_HEAD(procident_policy_lengths, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(procident_policy_lengths, tc)
{
	char buf[128];
	int64_t p64;
	int p32;

	policy_set(AUDIT_CNT | AUDIT_NOPROCIDENT);
	ATF_REQUIRE_EQ(0, auditon(A_GETPOLICY, &p32, sizeof(p32)));
	ATF_CHECK_EQ(AUDIT_CNT | AUDIT_NOPROCIDENT, p32);
	p64 = 0;
	ATF_REQUIRE_EQ(0, auditon(A_GETPOLICY, &p64, sizeof(p64)));
	ATF_CHECK_EQ(AUDIT_CNT | AUDIT_NOPROCIDENT, p64);

	p64 = AUDIT_CNT;
	ATF_REQUIRE_EQ(0, auditon(A_SETPOLICY, &p64, sizeof(p64)));
	ATF_REQUIRE_EQ(0, auditon(A_GETPOLICY, &p32, sizeof(p32)));
	ATF_CHECK_EQ(AUDIT_CNT, p32);
	p64 = AUDIT_CNT | AUDIT_NOPROCIDENT;
	ATF_REQUIRE_EQ_MSG(0, auditon(A_SETPOLICY, &p64, sizeof(p64)),
	    "64-bit A_SETPOLICY: %s", strerror(errno));
	p64 = 0;
	ATF_REQUIRE_EQ(0, auditon(A_GETPOLICY, &p64, sizeof(p64)));
	ATF_CHECK_EQ(AUDIT_CNT | AUDIT_NOPROCIDENT, p64);
	ATF_REQUIRE_EQ(0, auditon(A_GETPOLICY, &p32, sizeof(p32)));
	ATF_CHECK_EQ(AUDIT_CNT | AUDIT_NOPROCIDENT, p32);

	/* An unknown bit is still refused, both ways. */
	p32 = AUDIT_CNT | 0x00020000;
	ATF_CHECK_EQ(-1, auditon(A_SETPOLICY, &p32, sizeof(p32)));
	ATF_CHECK_EQ(EINVAL, errno);
	p64 = AUDIT_CNT | 0x00020000;
	ATF_CHECK_EQ(-1, auditon(A_SETPOLICY, &p64, sizeof(p64)));
	ATF_CHECK_EQ(EINVAL, errno);

	/* libbsm's policy names (audit_control(5)). */
	ATF_REQUIRE_EQ_MSG(0, au_strtopol("cnt,noprocident", &p32),
	    "au_strtopol: noprocident is not a policy name");
	ATF_CHECK_EQ(AUDIT_CNT | AUDIT_NOPROCIDENT, p32);
	ATF_REQUIRE_EQ(0, au_strtopol("cnt,argv", &p32));
	ATF_CHECK_EQ(0, p32 & AUDIT_NOPROCIDENT);
	ATF_REQUIRE(au_poltostr(AUDIT_CNT | AUDIT_NOPROCIDENT, sizeof(buf),
	    buf) > 0);
	ATF_CHECK_STREQ("cnt,noprocident", buf);
}
ATF_TC_CLEANUP(procident_policy_lengths, tc)
{
	policy_restore();
}

/* A record a program submits with audit(2) is not rewritten. */
ATF_TC_WITH_CLEANUP(procident_userland_none);
ATF_TC_HEAD(procident_userland_none, tc)
{
}
ATF_TC_BODY(procident_userland_none, tc)
{
	struct pollfd fds[1];
	struct record r;
	FILE *pipestream;
	tokenstr_t tok;
	char text[64];
	u_char *buf;
	int aufd, reclen, off;
	bool mine;

	pipestream = setup(fds, "ex");
	policy_set(AUDIT_CNT);
	snprintf(text, sizeof(text), "procident_userland_none %d", getpid());
	aufd = au_open();
	ATF_REQUIRE(aufd != -1);
	ATF_REQUIRE_EQ(0, au_write(aufd, au_to_me()));
	ATF_REQUIRE_EQ(0, au_write(aufd, au_to_text(text)));
	ATF_REQUIRE_EQ(0, au_write(aufd, au_to_return32(0, 0)));
	ATF_REQUIRE_EQ_MSG(0, au_close(aufd, AU_TO_WRITE, AUE_at_create),
	    "au_close: %s", strerror(errno));
	/*
	 * Any user event; user records reach every pipe unconditionally
	 * (audit_pipe_submit_user()).
	 */
	for (mine = false; !mine; free(buf)) {
		reclen = au_read_rec(pipestream, &buf);
		ATF_REQUIRE(reclen > 0);
		for (off = 0; off < reclen; off += tok.len) {
			ATF_REQUIRE_EQ(0, au_fetch_tok(&tok, buf + off,
			    reclen - off));
			if (tok.id == AUT_TEXT &&
			    strcmp(tok.tt.text.text, text) == 0)
				mine = true;
		}
		if (mine)
			record_parse(buf, reclen, &r);
	}
	ATF_CHECK(!r.has_procident);
	ATF_CHECK_EQ(AUT_TRAILER, r.ids[r.ntok - 1]);
	ATF_REQUIRE_EQ(0, fclose(pipestream));
}
ATF_TC_CLEANUP(procident_userland_none, tc)
{
	policy_restore();
	cleanup();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, procident_token);
	ATF_TP_ADD_TC(tp, procident_printed);
	ATF_TP_ADD_TC(tp, procident_auditreduce);
	ATF_TP_ADD_TC(tp, procident_policy);
	ATF_TP_ADD_TC(tp, procident_policy_lengths);
	ATF_TP_ADD_TC(tp, procident_userland_none);
	return (atf_no_error());
}
