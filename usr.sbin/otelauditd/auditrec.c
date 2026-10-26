/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * BSM audit records to OpenTelemetry log records.
 *
 * Each record becomes one log record: the timestamp is the record's
 * header time, the probe is the event name (for example AUE_EXECVE),
 * process.pid is the subject's pid, and the body is a single line in
 * the spirit of "praudit -l":
 *
 *	AUE_EXECVE execve(2) auid=1001 euid=0 egid=0 ruid=1001 pid=42
 *	    result=success:0 path=/bin/ls args="ls -l"
 *
 * Environment strings (exec_env tokens) are never exported.
 */

#include <sys/types.h>

#include <bsm/libbsm.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auditrec.h"

static int
event_cmp(const void *a, const void *b)
{
	const struct auditrec_event *x = a, *y = b;

	return ((x->number > y->number) - (x->number < y->number));
}

void
auditrec_events_free(struct auditrec_events *t)
{
	size_t i;

	for (i = 0; i < t->n; i++) {
		free(t->ev[i].name);
		free(t->ev[i].desc);
	}
	free(t->ev);
	t->ev = NULL;
	t->n = 0;
}

int
auditrec_events_load(struct auditrec_events *t)
{
	struct au_event_ent *e;
	struct auditrec_event *v;

	t->ev = NULL;
	t->n = 0;
	setauevent();
	while ((e = getauevent()) != NULL) {
		v = reallocarray(t->ev, t->n + 1, sizeof(*v));
		if (v == NULL)
			goto fail;
		t->ev = v;
		v[t->n].number = e->ae_number;
		v[t->n].name = strdup(e->ae_name);
		v[t->n].desc = strdup(e->ae_desc);
		t->n++;
		if (v[t->n - 1].name == NULL || v[t->n - 1].desc == NULL)
			goto fail;
	}
	endauevent();
	qsort(t->ev, t->n, sizeof(*t->ev), event_cmp);
	return (0);
fail:
	endauevent();
	auditrec_events_free(t);
	return (-1);
}

const struct auditrec_event *
auditrec_event_find(const struct auditrec_events *t, au_event_t number)
{
	struct auditrec_event key;

	key.number = number;
	return (t->n == 0 ? NULL : bsearch(&key, t->ev, t->n,
	    sizeof(*t->ev), event_cmp));
}

struct body {
	char	*buf;
	size_t	 len;
	size_t	 cap;
};

static void
put(struct body *b, const char *fmt, ...) __printflike(2, 3);

static void
put(struct body *b, const char *fmt, ...)
{
	va_list ap;
	int r;

	if (b->len >= b->cap)
		return;
	va_start(ap, fmt);
	r = vsnprintf(b->buf + b->len, b->cap - b->len, fmt, ap);
	va_end(ap);
	b->len += r > 0 ? (size_t)r : 0;
}

/* Append " key=<value>" quoting values with spaces or quotes. */
static void
put_str(struct body *b, const char *key, const char *s, size_t len)
{
	size_t i;
	int quote;

	len = strnlen(s, len);		/* lengths include the NUL */
	quote = len == 0 || strcspn(s, " \t\"\\") < len;
	put(b, " %s=%s", key, quote ? "\"" : "");
	for (i = 0; i < len; i++) {
		put(b, "%s%c", s[i] == '"' || s[i] == '\\' ? "\\" : "",
		    s[i]);
	}
	if (quote)
		put(b, "\"");
}

static void
put_id(struct body *b, const char *key, u_int32_t id)
{

	if (id == (u_int32_t)-1)
		put(b, " %s=-", key);
	else
		put(b, " %s=%u", key, id);
}

#define	SUBJECT(b, s, pidp) do {					\
	put_id((b), "auid", (s).auid);					\
	put_id((b), "euid", (s).euid);					\
	put_id((b), "egid", (s).egid);					\
	put_id((b), "ruid", (s).ruid);					\
	put(b, " pid=%u", (s).pid);					\
	*(pidp) = (pid_t)(s).pid;					\
} while (0)

int
auditrec_convert(const struct auditrec_events *t, u_char *rec, int len,
    struct oe_event *ev, char *bodybuf, size_t bodylen, char *probe,
    size_t probelen)
{
	const struct auditrec_event *e;
	struct body b;
	tokenstr_t tok;
	u_int16_t type;
	u_int32_t i;
	u_int64_t sec, msec;
	pid_t pid;
	int off;

	memset(ev, 0, sizeof(*ev));
	if (len <= 0 || au_fetch_tok(&tok, rec, len) == -1)
		return (-1);
	switch (tok.id) {
	case AUT_HEADER32:
		type = tok.tt.hdr32.e_type;
		sec = tok.tt.hdr32.s;
		msec = tok.tt.hdr32.ms;
		break;
	case AUT_HEADER32_EX:
		type = tok.tt.hdr32_ex.e_type;
		sec = tok.tt.hdr32_ex.s;
		msec = tok.tt.hdr32_ex.ms;
		break;
	case AUT_HEADER64:
		type = tok.tt.hdr64.e_type;
		sec = tok.tt.hdr64.s;
		msec = tok.tt.hdr64.ms;
		break;
	case AUT_HEADER64_EX:
		type = tok.tt.hdr64_ex.e_type;
		sec = tok.tt.hdr64_ex.s;
		msec = tok.tt.hdr64_ex.ms;
		break;
	default:
		/* Trail file tokens and anything else without a header. */
		return (0);
	}

	b.buf = bodybuf;
	b.len = 0;
	b.cap = bodylen;
	bodybuf[0] = '\0';
	e = auditrec_event_find(t, type);
	if (e != NULL) {
		snprintf(probe, probelen, "%s", e->name);
		put(&b, "%s %s", e->name, e->desc);
	} else {
		snprintf(probe, probelen, "event_%u", type);
		put(&b, "event_%u", type);
	}
	pid = 0;
	for (off = (int)tok.len; off < len; off += (int)tok.len) {
		if (au_fetch_tok(&tok, rec + off, len - off) == -1)
			return (-1);
		switch (tok.id) {
		case AUT_SUBJECT32:
			SUBJECT(&b, tok.tt.subj32, &pid);
			break;
		case AUT_SUBJECT32_EX:
			SUBJECT(&b, tok.tt.subj32_ex, &pid);
			break;
		case AUT_SUBJECT64:
			SUBJECT(&b, tok.tt.subj64, &pid);
			break;
		case AUT_SUBJECT64_EX:
			SUBJECT(&b, tok.tt.subj64_ex, &pid);
			break;
		case AUT_RETURN32:
			put(&b, " result=%s:%u", tok.tt.ret32.status == 0 ?
			    "success" : "failure", tok.tt.ret32.status == 0 ?
			    tok.tt.ret32.ret : tok.tt.ret32.status);
			break;
		case AUT_RETURN64:
			put(&b, " result=%s:%ju", tok.tt.ret64.err == 0 ?
			    "success" : "failure", tok.tt.ret64.err == 0 ?
			    (uintmax_t)tok.tt.ret64.val :
			    (uintmax_t)tok.tt.ret64.err);
			break;
		case AUT_PATH:
			put_str(&b, "path", tok.tt.path.path,
			    tok.tt.path.len);
			break;
		case AUT_TEXT:
			put_str(&b, "text", tok.tt.text.text,
			    tok.tt.text.len);
			break;
		case AUT_EXEC_ARGS:
			put(&b, " args=\"");
			for (i = 0; i < tok.tt.execarg.count &&
			    i < AUDIT_MAX_ARGS; i++) {
				const char *a = tok.tt.execarg.text[i];

				put(&b, "%s", i > 0 ? " " : "");
				for (; *a != '\0'; a++)
					put(&b, "%s%c", *a == '"' ||
					    *a == '\\' ? "\\" : "", *a);
			}
			put(&b, "\"");
			break;
		default:
			/* exec_env, attributes, arguments, trailer... */
			break;
		}
	}
	ev->ts.tv_sec = (time_t)sec;
	ev->ts.tv_nsec = (long)(msec % 1000) * 1000000L;
	ev->profile = AUDITREC_PROFILE;
	ev->probe = probe;
	ev->pid = pid;
	ev->execname = "";
	ev->body = bodybuf;
	return (1);
}
