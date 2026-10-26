/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Deterministic BSM records for the otelauditd tests, built with the
 * libbsm token constructors.
 */

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/queue.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <bsm/audit.h>
#include <bsm/audit_internal.h>
#include <bsm/audit_kevents.h>
#include <bsm/audit_record.h>
#include <bsm/libbsm.h>

#include <err.h>
#include <stdlib.h>
#include <string.h>

#include "bsmgen.h"

static token_t *
header(enum bsmgen_header h, int size, u_short event, time_t sec, int ms)
{
	struct timeval tv;

	tv.tv_sec = sec;
	tv.tv_usec = ms * 1000;
	switch (h) {
	case BSMGEN_H32:
		return (au_to_header32_tm(size, event, 0, tv));
	case BSMGEN_H64:
		return (au_to_header64_tm(size, event, 0, tv));
	case BSMGEN_H64_EX: {
		/* libbsm has no header64_ex constructor: hand-encode it. */
		token_t *t;
		u_char *p;

		t = calloc(1, sizeof(*t));
		if (t == NULL || (t->t_data = calloc(1, 34)) == NULL)
			errx(1, "bsmgen: allocation");
		t->len = 34;
		p = t->t_data;
		p[0] = AUT_HEADER64_EX;
		be32enc(p + 1, (uint32_t)size);
		p[5] = AUDIT_HEADER_VERSION_OPENBSM;
		be16enc(p + 6, event);
		be16enc(p + 8, 0);
		be32enc(p + 10, AU_IPv4);
		be32enc(p + 14, 0x7f000001);
		be64enc(p + 18, (uint64_t)sec);
		be64enc(p + 26, (uint64_t)ms);
		return (t);
	}
	case BSMGEN_H32_EX:
	default: {
		struct auditinfo_addr aia;

		memset(&aia, 0, sizeof(aia));
		aia.ai_termid.at_type = AU_IPv4;
		aia.ai_termid.at_addr[0] = htonl(0x7f000001);
		return (au_to_header32_ex_tm(size, event, 0, tv, &aia));
	}
	}
}

u_char *
bsmgen_record(enum bsmgen_header h, u_short event, time_t sec, int ms,
    void **tokens, int ntokens, size_t *lenp)
{
	token_t *hdr, *trl, *t;
	u_char *buf;
	size_t size, off;
	int i;

	hdr = header(h, 0, event, sec, ms);
	trl = au_to_trailer(0);
	if (hdr == NULL || trl == NULL)
		errx(1, "bsmgen: token allocation");
	size = hdr->len + trl->len;
	for (i = 0; i < ntokens; i++)
		size += ((token_t *)tokens[i])->len;
	au_free_token(hdr);
	au_free_token(trl);
	hdr = header(h, (int)size, event, sec, ms);
	trl = au_to_trailer((int)size);
	buf = malloc(size);
	if (hdr == NULL || trl == NULL || buf == NULL)
		errx(1, "bsmgen: allocation");
	memcpy(buf, hdr->t_data, hdr->len);
	off = hdr->len;
	for (i = 0; i < ntokens; i++) {
		t = tokens[i];
		memcpy(buf + off, t->t_data, t->len);
		off += t->len;
		au_free_token(t);
	}
	memcpy(buf + off, trl->t_data, trl->len);
	au_free_token(hdr);
	au_free_token(trl);
	*lenp = size;
	return (buf);
}

static void
emit(FILE *f, u_char *buf, size_t len)
{

	if (fwrite(buf, 1, len, f) != len)
		err(1, "bsmgen: write");
	free(buf);
}

static void
emit_file_token(FILE *f)
{
	struct timeval tv = { 1700000000, 0 };
	token_t *t;

	t = au_to_file("20231114221320.not_terminated", tv);
	if (t == NULL || fwrite(t->t_data, 1, t->len, f) != t->len)
		err(1, "bsmgen: file token");
	au_free_token(t);
}

/*
 * The standard trail, at 1700000000 + i seconds:
 *  0 AUE_EXECVE   header32     subject32 auid=1001 euid=0 pid=4242,
 *                              exec_args, path, return32 success
 *  1 AUE_OPEN_R   header32_ex  subject32_ex auid=-1 euid=1001 pid=77,
 *                              path, text, exec_env, empty text,
 *                              return32 failure 13
 *  2 event 65000  header64     subject64 pid=9, return64 success 7
 *  3 AUE_EXECVE   header64_ex* subject64_ex pid=10, return64 failure 2
 * (*hand-encoded: libbsm has no header64_ex constructor.)
 * With "corrupt", record 0's path token length overruns the record.
 */
int
bsmgen_trail(FILE *f, int with_file_tokens, int corrupt)
{
	au_tid_t tid;
	au_tid_addr_t tidx;
	void *tok[6];
	char a0[] = "ls", a1[] = "-l", a2[] = "a b\"c\\d";
	char e0[] = "SECRET=hunter2";
	char *argv[] = { a0, a1, a2, NULL };
	char *envp[] = { e0, NULL };
	u_char *buf;
	size_t len;

	memset(&tid, 0, sizeof(tid));
	memset(&tidx, 0, sizeof(tidx));
	tidx.at_type = AU_IPv4;
	if (with_file_tokens)
		emit_file_token(f);

	tok[0] = au_to_subject32(1001, 0, 0, 1001, 1001, 4242, 5, &tid);
	tok[1] = au_to_exec_args(argv);
	tok[2] = au_to_path("/bin/ls");
	tok[3] = au_to_return32(0, 0);
	buf = bsmgen_record(BSMGEN_H32, AUE_EXECVE, 1700000000, 250, tok, 4,
	    &len);
	if (corrupt) {
		/* Make the path token claim more bytes than the record has. */
		u_char *p = memmem(buf, len, "\043\000\010/bin/ls", 10);

		if (p == NULL)
			errx(1, "bsmgen: path token not found");
		p[1] = p[2] = 0xff;
	}
	emit(f, buf, len);

	tok[0] = au_to_subject32_ex(AU_DEFAUDITID, 1001, 20, 1001, 20, 77, 6,
	    &tidx);
	tok[1] = au_to_path("/etc/master.passwd");
	tok[2] = au_to_text("note \"q\" \\ x");
	tok[3] = au_to_exec_env(envp);
	tok[4] = au_to_text("");
	tok[5] = au_to_return32(13, (u_int32_t)-1);
	buf = bsmgen_record(BSMGEN_H32_EX, AUE_OPEN_R, 1700000001, 0, tok, 6,
	    &len);
	emit(f, buf, len);

	tok[0] = au_to_subject64(0, 0, 0, 0, 0, 9, 7, &tid);
	tok[1] = au_to_return64(0, 7);
	buf = bsmgen_record(BSMGEN_H64, 65000, 1700000002, 0, tok, 2, &len);
	emit(f, buf, len);

	tok[0] = au_to_subject64_ex(0, 0, 0, 0, 0, 10, 7, &tidx);
	tok[1] = au_to_return64(2, 0);
	buf = bsmgen_record(BSMGEN_H64_EX, AUE_EXECVE, 1700000003, 0, tok, 2,
	    &len);
	emit(f, buf, len);

	if (with_file_tokens)
		emit_file_token(f);
	return (4);
}
