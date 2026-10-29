/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Unit tests for the BSM record to log record conversion.
 */

#include <sys/types.h>
#include <sys/endian.h>

#include <bsm/audit.h>
#include <bsm/audit_kevents.h>
#include <bsm/audit_uevents.h>
#include <bsm/audit_record.h>
#include <bsm/libbsm.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "auditrec.h"
#include "bsmgen.h"

static struct auditrec_events events;

static void
load_events(void)
{

	ATF_REQUIRE_EQ(auditrec_events_load(&events), 0);
	ATF_REQUIRE(events.n > 100);
}

/* The attribute named key, or NULL. */
static const struct oe_kv *
attr(const struct oe_event *ev, const char *key)
{
	size_t i;

	for (i = 0; i < ev->nattrs; i++)
		if (strcmp(ev->attrs[i].key, key) == 0)
			return (&ev->attrs[i]);
	return (NULL);
}

static void
check_str(const struct oe_event *ev, const char *key, const char *value)
{
	const struct oe_kv *kv;

	kv = attr(ev, key);
	ATF_REQUIRE_MSG(kv != NULL, "no attribute %s", key);
	ATF_CHECK_EQ(kv->type, OE_VAL_STRING);
	ATF_CHECK_STREQ(kv->s, value);
}

static void
check_int(const struct oe_event *ev, const char *key, int64_t value)
{
	const struct oe_kv *kv;

	kv = attr(ev, key);
	ATF_REQUIRE_MSG(kv != NULL, "no attribute %s", key);
	ATF_CHECK_EQ(kv->type, OE_VAL_INT);
	ATF_CHECK_EQ(kv->i, value);
}

/* Read the records of the standard trail back with au_read_rec(3). */
static int
read_trail(u_char **recs, int *lens, int max, int files, int corrupt)
{
	FILE *f;
	int n;

	f = tmpfile();
	ATF_REQUIRE(f != NULL);
	(void)bsmgen_trail(f, files, corrupt);
	rewind(f);
	for (n = 0; n < max; n++) {
		lens[n] = au_read_rec(f, &recs[n]);
		if (lens[n] == -1)
			break;
	}
	fclose(f);
	return (n);
}

ATF_TC_WITHOUT_HEAD(event_table);
ATF_TC_BODY(event_table, tc)
{
	const struct auditrec_event *e;

	load_events();
	e = auditrec_event_find(&events, AUE_EXECVE);
	ATF_REQUIRE(e != NULL);
	ATF_CHECK_STREQ(e->name, "AUE_EXECVE");
	ATF_CHECK_STREQ(e->desc, "execve(2)");
	ATF_CHECK(auditrec_event_find(&events, 65000) == NULL);
	auditrec_events_free(&events);
	ATF_CHECK(auditrec_event_find(&events, AUE_EXECVE) == NULL);
}

ATF_TC_WITHOUT_HEAD(convert_trail);
ATF_TC_BODY(convert_trail, tc)
{
	struct oe_event ev;
	u_char *recs[8];
	int lens[8], n, i;
	char body[AUDITREC_BODY_MAX], probe[64];
	struct auditrec_attrs at;

	load_events();
	n = read_trail(recs, lens, 8, 1, 0);
	ATF_REQUIRE_EQ(n, 6);

	/* Trail file tokens are not events. */
	ATF_CHECK_EQ(auditrec_convert(&events, recs[0], lens[0], &ev, body,
	    sizeof(body), probe, sizeof(probe), &at), 0);
	ATF_CHECK_EQ(auditrec_convert(&events, recs[5], lens[5], &ev, body,
	    sizeof(body), probe, sizeof(probe), &at), 0);

	ATF_REQUIRE_EQ(auditrec_convert(&events, recs[1], lens[1], &ev, body,
	    sizeof(body), probe, sizeof(probe), &at), 1);
	ATF_CHECK_STREQ(ev.probe, "AUE_EXECVE");
	ATF_CHECK_STREQ(ev.profile, "audit");
	ATF_CHECK_EQ(ev.pid, 4242);
	ATF_CHECK_EQ(ev.ts.tv_sec, 1700000000);
	ATF_CHECK_EQ(ev.ts.tv_nsec, 250000000L);
	ATF_CHECK_STREQ(ev.body, "AUE_EXECVE execve(2) auid=1001 euid=0 "
	    "egid=0 ruid=1001 pid=4242 args=\"ls -l a b\\\"c\\\\d\" "
	    "path=/bin/ls "
	    "result=success:0");
	ATF_CHECK_EQ(ev.severity, OE_SEV_INFO);
	ATF_CHECK_EQ(ev.ctx.flags, OE_CTX_PID | OE_CTX_UID | OE_CTX_RUID |
	    OE_CTX_GID | OE_CTX_RGID);
	ATF_CHECK_EQ(ev.ctx.uid, 0);
	ATF_CHECK_EQ(ev.ctx.ruid, 1001);
	check_str(&ev, "user.id", "1001");
	check_str(&ev, "otelauditd.result", "success");
	check_int(&ev, "otelauditd.return", 0);
	check_str(&ev, "file.path", "/bin/ls");
	ATF_CHECK_EQ(ev.nattrs, 4);

	ATF_REQUIRE_EQ(auditrec_convert(&events, recs[2], lens[2], &ev, body,
	    sizeof(body), probe, sizeof(probe), &at), 1);
	ATF_CHECK_STREQ(ev.probe, "AUE_OPEN_R");
	ATF_CHECK_EQ(ev.pid, 77);
	ATF_CHECK_STREQ(ev.body, "AUE_OPEN_R open(2) - read auid=- euid=1001 "
	    "egid=20 ruid=1001 pid=77 path=/etc/master.passwd "
	    "text=\"note \\\"q\\\" \\\\ x\" text=\"\" result=failure:13");
	/* A failed open is a warning; an unset audit user is left out. */
	ATF_CHECK_EQ(ev.severity, OE_SEV_WARN);
	ATF_CHECK(attr(&ev, "user.id") == NULL);
	check_str(&ev, "otelauditd.result", "failure");
	check_int(&ev, "otelauditd.return", 13);
	check_str(&ev, "file.path", "/etc/master.passwd");
	ATF_CHECK_EQ(ev.ctx.gid, 20);
	/* exec_env tokens never leak. */
	ATF_CHECK(strstr(ev.body, "hunter2") == NULL);

	ATF_REQUIRE_EQ(auditrec_convert(&events, recs[3], lens[3], &ev, body,
	    sizeof(body), probe, sizeof(probe), &at), 1);
	ATF_CHECK_STREQ(ev.probe, "event_65000");
	ATF_CHECK_STREQ(ev.body, "event_65000 auid=0 euid=0 egid=0 ruid=0 "
	    "pid=9 result=success:7");

	ATF_REQUIRE_EQ(auditrec_convert(&events, recs[4], lens[4], &ev, body,
	    sizeof(body), probe, sizeof(probe), &at), 1);
	ATF_CHECK_EQ(ev.ts.tv_sec, 1700000003);
	ATF_CHECK_STREQ(ev.body, "AUE_EXECVE execve(2) auid=0 euid=0 egid=0 "
	    "ruid=0 pid=10 result=failure:2");
	ATF_CHECK_EQ(ev.severity, OE_SEV_WARN);
	ATF_CHECK(attr(&ev, "file.path") == NULL);

	for (i = 0; i < n; i++)
		free(recs[i]);
	auditrec_events_free(&events);
}

ATF_TC_WITHOUT_HEAD(malformed);
ATF_TC_BODY(malformed, tc)
{
	struct oe_event ev;
	u_char *recs[8], junk[4] = { 0xee, 0, 0, 0 };
	int lens[8], n, i;
	char body[AUDITREC_BODY_MAX], probe[64];
	struct auditrec_attrs at;

	load_events();
	n = read_trail(recs, lens, 8, 0, 1);
	ATF_REQUIRE_EQ(n, 4);
	ATF_CHECK_EQ(auditrec_convert(&events, recs[0], lens[0], &ev, body,
	    sizeof(body), probe, sizeof(probe), &at), -1);
	ATF_CHECK_EQ(auditrec_convert(&events, recs[1], lens[1], &ev, body,
	    sizeof(body), probe, sizeof(probe), &at), 1);
	/* A record cut inside its first token. */
	ATF_CHECK_EQ(auditrec_convert(&events, recs[1], 3, &ev, body,
	    sizeof(body), probe, sizeof(probe), &at), -1);
	/* Cut inside a later token. */
	ATF_CHECK_EQ(auditrec_convert(&events, recs[1], lens[1] - 20, &ev,
	    body, sizeof(body), probe, sizeof(probe), &at), -1);
	ATF_CHECK_EQ(auditrec_convert(&events, junk, sizeof(junk), &ev, body,
	    sizeof(body), probe, sizeof(probe), &at), -1);
	ATF_CHECK_EQ(auditrec_convert(&events, recs[0], 0, &ev, body,
	    sizeof(body), probe, sizeof(probe), &at), -1);
	for (i = 0; i < n; i++)
		free(recs[i]);
	auditrec_events_free(&events);
}

ATF_TC_WITHOUT_HEAD(truncated_body);
ATF_TC_BODY(truncated_body, tc)
{
	struct oe_event ev;
	u_char *recs[8];
	int lens[8], n, i;
	char body[24], probe[8];
	struct auditrec_attrs at;

	load_events();
	n = read_trail(recs, lens, 8, 0, 0);
	ATF_REQUIRE_EQ(auditrec_convert(&events, recs[0], lens[0], &ev, body,
	    sizeof(body), probe, sizeof(probe), &at), 1);
	/* Small buffers truncate but stay terminated. */
	ATF_CHECK_EQ(strlen(ev.body), sizeof(body) - 1);
	ATF_CHECK_STREQ(ev.probe, "AUE_EXE");
	for (i = 0; i < n; i++)
		free(recs[i]);
	auditrec_events_free(&events);
}

/*
 * Severity from the outcome and the event's classes: a failed login is
 * an error, a successful one informational, and a record without a
 * return token (or without a subject) informational with no outcome.
 */
ATF_TC_WITHOUT_HEAD(severity);
ATF_TC_BODY(severity, tc)
{
	struct oe_event ev;
	struct auditrec_attrs at;
	au_tid_t tid;
	void *tok[2];
	u_char *rec;
	size_t len;
	char body[AUDITREC_BODY_MAX], probe[64];

	load_events();
	ATF_REQUIRE(events.error_classes != 0);
	memset(&tid, 0, sizeof(tid));

	tok[0] = au_to_subject32(1001, 1001, 1001, 1001, 1001, 99, 0, &tid);
	tok[1] = au_to_return64(EPERM, 0);
	rec = bsmgen_record(BSMGEN_H32, AUE_login, 1700000000, 0, tok, 2,
	    &len);
	ATF_REQUIRE_EQ(auditrec_convert(&events, rec, (int)len, &ev, body,
	    sizeof(body), probe, sizeof(probe), &at), 1);
	ATF_CHECK_EQ(ev.severity, OE_SEV_ERROR);
	check_str(&ev, "otelauditd.result", "failure");
	free(rec);

	tok[0] = au_to_subject32(1001, 1001, 1001, 1001, 1001, 99, 0, &tid);
	tok[1] = au_to_return64(0, 5);
	rec = bsmgen_record(BSMGEN_H32, AUE_login, 1700000000, 0, tok, 2,
	    &len);
	ATF_REQUIRE_EQ(auditrec_convert(&events, rec, (int)len, &ev, body,
	    sizeof(body), probe, sizeof(probe), &at), 1);
	ATF_CHECK_EQ(ev.severity, OE_SEV_INFO);
	check_int(&ev, "otelauditd.return", 5);
	free(rec);

	/* Unknown event: a failure is a warning. */
	tok[0] = au_to_return32(EPERM, 0);
	rec = bsmgen_record(BSMGEN_H32, 65001, 1700000000, 0, tok, 1, &len);
	ATF_REQUIRE_EQ(auditrec_convert(&events, rec, (int)len, &ev, body,
	    sizeof(body), probe, sizeof(probe), &at), 1);
	ATF_CHECK_EQ(ev.severity, OE_SEV_WARN);
	ATF_CHECK_EQ(ev.ctx.flags, 0);
	free(rec);

	/* Only the first path becomes file.path, cut to the buffer. */
	{
		char longpath[1200];
		void *ptok[2];

		memset(longpath, 'p', sizeof(longpath) - 1);
		longpath[0] = '/';
		longpath[sizeof(longpath) - 1] = '\0';
		ptok[0] = au_to_path(longpath);
		ptok[1] = au_to_path("/second");
		rec = bsmgen_record(BSMGEN_H32, AUE_OPEN_R, 1700000000, 0, ptok,
		    2, &len);
		ATF_REQUIRE_EQ(auditrec_convert(&events, rec, (int)len, &ev,
		    body, sizeof(body), probe, sizeof(probe), &at), 1);
		ATF_REQUIRE(attr(&ev, "file.path") != NULL);
		ATF_CHECK_EQ(strlen(attr(&ev, "file.path")->s),
		    sizeof(at.path) - 1);
		ATF_CHECK(strstr(ev.body, "path=/second") != NULL);
		free(rec);
	}

	tok[0] = au_to_text("no outcome");
	rec = bsmgen_record(BSMGEN_H32, AUE_login, 1700000000, 0, tok, 1,
	    &len);
	ATF_REQUIRE_EQ(auditrec_convert(&events, rec, (int)len, &ev, body,
	    sizeof(body), probe, sizeof(probe), &at), 1);
	ATF_CHECK_EQ(ev.severity, OE_SEV_INFO);
	ATF_CHECK_EQ(ev.nattrs, 0);
	free(rec);
	auditrec_events_free(&events);
}

/* Splitting an auditpipe read that holds several records. */
ATF_TC_WITHOUT_HEAD(record_len);
ATF_TC_BODY(record_len, tc)
{
	void *tok[1];
	u_char *a, *b, *both, junk[4] = { 0xee, 0, 0, 0 };
	size_t alen, blen;

	tok[0] = au_to_text("first");
	a = bsmgen_record(BSMGEN_H32, AUE_EXECVE, 1700000000, 0, tok, 1,
	    &alen);
	tok[0] = au_to_text("second record");
	b = bsmgen_record(BSMGEN_H64_EX, AUE_EXECVE, 1700000000, 0, tok, 1,
	    &blen);
	both = malloc(alen + blen);
	ATF_REQUIRE(both != NULL);
	memcpy(both, a, alen);
	memcpy(both + alen, b, blen);
	ATF_CHECK_EQ(auditrec_record_len(both, (int)(alen + blen)), (int)alen);
	ATF_CHECK_EQ(auditrec_record_len(both + alen, (int)blen), (int)blen);
	/* A record cut short, a non-header token, nothing. */
	ATF_CHECK_EQ(auditrec_record_len(both, (int)alen - 1), -1);
	ATF_CHECK_EQ(auditrec_record_len(junk, sizeof(junk)), -1);
	ATF_CHECK_EQ(auditrec_record_len(both, 0), -1);
	/* A record that does not start with a header token. */
	{
		tokenstr_t hdr;

		ATF_REQUIRE(au_fetch_tok(&hdr, a, (int)alen) == 0);
		ATF_CHECK_EQ(auditrec_record_len(a + hdr.len,
		    (int)(alen - hdr.len)), -1);
	}
	/* Header byte counts that cannot be right (big-endian at 1..4). */
	be32enc(a + 1, 1);
	ATF_CHECK_EQ(auditrec_record_len(a, (int)alen), -1);
	be32enc(a + 1, (uint32_t)alen + 100);
	ATF_CHECK_EQ(auditrec_record_len(a, (int)alen), -1);
	tok[0] = au_to_text("x");
	free(a);
	a = bsmgen_record(BSMGEN_H32_EX, AUE_EXECVE, 1, 0, tok, 1, &alen);
	ATF_CHECK_EQ(auditrec_record_len(a, (int)alen), (int)alen);
	free(a);
	tok[0] = au_to_text("y");
	a = bsmgen_record(BSMGEN_H64, AUE_EXECVE, 1, 0, tok, 1, &alen);
	ATF_CHECK_EQ(auditrec_record_len(a, (int)alen), (int)alen);
	free(a);
	free(b);
	free(both);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, event_table);
	ATF_TP_ADD_TC(tp, convert_trail);
	ATF_TP_ADD_TC(tp, malformed);
	ATF_TP_ADD_TC(tp, truncated_body);
	ATF_TP_ADD_TC(tp, severity);
	ATF_TP_ADD_TC(tp, record_len);
	return (atf_no_error());
}
