/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The parts of consume-records that need libdtrace's private structures
 * (dt_impl.h): the dt_buf_t growable buffer and dtrace_sleep()'s process
 * notification delivery.  Kept in a separate translation unit because
 * dt_impl.h and the dtrace(4) model in consume-ingestion.c share names.
 */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dt_impl.h>
#include <dt_buf.h>
#include <dt_proc.h>

#define	CR_INTERNAL
#include "consume-records.h"

const int cr_EDT_BRICKED = EDT_BRICKED;
const int cr_EDT_DIRABORT = EDT_DIRABORT;
const int cr_EDT_BADRVAL = EDT_BADRVAL;
const int cr_EDT_NOMEM = EDT_NOMEM;
const int cr_EDT_BADNORMAL = EDT_BADNORMAL;
const int cr_EDT_BADTRUNC = EDT_BADTRUNC;
const int cr_EDT_BADSETOPT = EDT_BADSETOPT;
const int cr_EDT_BADSTACKPC = EDT_BADSTACKPC;
const int cr_EDT_DMISMATCH = EDT_DMISMATCH;
const int cr_EDT_BADAGG = EDT_BADAGG;
const int cr_EDT_ERRABORT = EDT_ERRABORT;
const int cr_EDT_NOBUFFERED = EDT_NOBUFFERED;
const int cr_EDT_DROPABORT = EDT_DROPABORT;
const int cr_DT_ACT_CLEAR = DT_ACT_CLEAR;
const int cr_DT_ACT_TRUNC = DT_ACT_TRUNC;

#define	CHECK(cond, ...) do {						\
	if (!(cond)) {							\
		(void) snprintf(msg, len, __VA_ARGS__);			\
		return (-1);						\
	}								\
} while (0)

/*
 * dt_buf_t: writes align the cursor up to the requested alignment, grow the
 * buffer by doubling as often as needed, and concatenation appends the
 * source's written bytes.  Without allocation failures every write lands.
 */
int
cr_buf_cases(dtrace_hdl_t *dtp, char *msg, size_t len)
{
	dt_buf_t a, b;
	static const char five[5] = "abcde";
	uint64_t eight = 0x1122334455667788ULL;
	unsigned char *p;
	size_t i;

	dt_buf_create(dtp, &a, "a", 0);
	CHECK(dt_buf_error(&a) == 0 && a.dbu_len == _dtrace_bufsize,
	    "default length: err %d len %zu\n", dt_buf_error(&a), a.dbu_len);
	dt_buf_destroy(dtp, &a);

	dt_buf_create(dtp, &a, "a", 4);
	dt_buf_write(dtp, &a, five, 5, 1);		/* 0..4, grows to 8 */
	dt_buf_write(dtp, &a, &eight, 8, 8);		/* 8..15, grows to 16 */
	CHECK(dt_buf_len(&a) == 16 && a.dbu_len == 16 && a.dbu_resizes == 2,
	    "growth: len %zu size %zu resizes %d\n", dt_buf_len(&a),
	    a.dbu_len, a.dbu_resizes);
	dt_buf_write(dtp, &a, five, 5, 1);		/* 16..20 */
	CHECK(dt_buf_offset(&a, 8) == 24 && dt_buf_offset(&a, 1) == 21,
	    "offsets %zu %zu\n", dt_buf_offset(&a, 8), dt_buf_offset(&a, 1));
	/* 21 bytes need a third doubling (16 -> 32). */
	{
		char big[100];

		memset(big, 'z', sizeof (big));
		dt_buf_write(dtp, &a, big, sizeof (big), 1);
	}
	/* 21 + 100 > 64: one write that needs two doublings (32 -> 128). */
	CHECK(a.dbu_len == 128 && a.dbu_resizes == 5 && dt_buf_len(&a) == 121,
	    "double growth: size %zu resizes %d len %zu\n", a.dbu_len,
	    a.dbu_resizes, dt_buf_len(&a));
	p = dt_buf_ptr(&a);
	CHECK(memcmp(p, five, 5) == 0 && memcmp(p + 8, &eight, 8) == 0 &&
	    memcmp(p + 16, five, 5) == 0 && p[5] == 0 && p[120] == 'z',
	    "contents\n");

	dt_buf_create(dtp, &b, "b", 8);
	dt_buf_write(dtp, &b, "xy", 2, 1);
	dt_buf_concat(dtp, &b, &a, 4);			/* 2 -> pad to 4 */
	CHECK(dt_buf_len(&b) == 4 + 121 && memcmp((char *)dt_buf_ptr(&b) +
	    4, five, 5) == 0, "concat len %zu\n", dt_buf_len(&b));
	dt_buf_reset(dtp, &b);
	CHECK(dt_buf_len(&b) == 0 && dt_buf_error(&b) == 0, "reset\n");
	p = dt_buf_claim(dtp, &a);
	CHECK(p != NULL && a.dbu_buf == NULL && a.dbu_len == 0, "claim\n");
	free(p);
	/* A claimed buffer is recreated by reset at its recorded length. */
	a.dbu_len = 32;
	dt_buf_reset(dtp, &a);
	CHECK(a.dbu_buf != NULL && a.dbu_len == 32 && dt_buf_len(&a) == 0,
	    "reset after claim: len %zu\n", a.dbu_len);
	for (i = 0; i < 2; i++) {
		dt_buf_t *bp = i == 0 ? &a : &b;

		dt_buf_destroy(dtp, bp);
	}
	return (0);
}

/*
 * The same operations under allocation failure: a buffer whose allocation
 * failed records EDT_NOMEM, later writes fail silently but set the handle's
 * errno, concatenation propagates the source error, and claim frees and
 * returns NULL.  fail_next(n) makes the nth following malloc() fail.
 */
int
cr_buf_fault_cases(dtrace_hdl_t *dtp, void (*fail_next)(long), char *msg,
    size_t len)
{
	dt_buf_t a, b;
	unsigned char *p;

	fail_next(1);
	dt_buf_create(dtp, &a, "a", 16);
	fail_next(0);
	CHECK(dt_buf_error(&a) == EDT_NOMEM && a.dbu_buf == NULL,
	    "create failure: err %d\n", dt_buf_error(&a));
	(void) dt_set_errno(dtp, 0);
	dt_buf_write(dtp, &a, "x", 1, 1);
	CHECK(dtrace_errno(dtp) == EDT_NOMEM && dt_buf_len(&a) == 0,
	    "write after failure: errno %d\n", dtrace_errno(dtp));
	/* Reset retries the allocation. */
	dt_buf_reset(dtp, &a);
	CHECK(dt_buf_error(&a) == 0 && a.dbu_buf != NULL, "reset retry\n");

	dt_buf_create(dtp, &b, "b", 4);
	fail_next(1);
	dt_buf_write(dtp, &b, "0123456789", 10, 1);	/* growth fails */
	fail_next(0);
	CHECK(dt_buf_error(&b) == EDT_NOMEM && dt_buf_len(&b) == 0 &&
	    b.dbu_len == 4, "growth failure: err %d\n", dt_buf_error(&b));
	/* An error source poisons a clean destination. */
	(void) dt_set_errno(dtp, 0);
	dt_buf_concat(dtp, &a, &b, 1);
	CHECK(dt_buf_error(&a) == EDT_NOMEM && dtrace_errno(dtp) == EDT_NOMEM,
	    "concat error: err %d\n", dt_buf_error(&a));
	/* A destination already in error is left alone by a clean concat. */
	dt_buf_reset(dtp, &b);
	dt_buf_concat(dtp, &a, &b, 1);
	CHECK(dt_buf_error(&a) == EDT_NOMEM, "concat into error\n");
	p = dt_buf_claim(dtp, &a);
	CHECK(p == NULL && a.dbu_buf == NULL, "claim of failed buffer\n");
	dt_buf_destroy(dtp, &a);
	dt_buf_destroy(dtp, &b);
	return (0);
}

/* ---------------- dtrace_sleep() and process notifications ---------- */

static char cr_notes[512];
static size_t cr_noteslen;

static void
cr_prochdlr(struct ps_prochandle *P, const char *err, void *arg)
{
	(void) arg;
	cr_noteslen += snprintf(cr_notes + cr_noteslen,
	    sizeof (cr_notes) - cr_noteslen, "%p:%s;", (void *)P,
	    err == NULL ? "(none)" : err);
}

static void
cr_queue(dtrace_hdl_t *dtp, dt_proc_t *dpr, const char *err)
{
	dt_proc_hash_t *dph = dtp->dt_procs;
	dt_proc_notify_t *n = malloc(sizeof (*n));

	memset(n, 0, sizeof (*n));
	n->dprn_dpr = dpr;
	strlcpy(n->dprn_errmsg, err, sizeof (n->dprn_errmsg));
	pthread_mutex_lock(&dph->dph_lock);
	n->dprn_next = dph->dph_notify;
	dph->dph_notify = n;
	pthread_mutex_unlock(&dph->dph_lock);
}

/*
 * dtrace_sleep() waits until the earliest of statusrate, aggrate and
 * switchrate (only statusrate for non-switching buffers) and then delivers
 * every queued notification -- also when that deadline has already passed.
 * An empty message is delivered as NULL.  Returns the elapsed nanoseconds
 * of the waiting call through *waited.
 */
int
cr_sleep_cases(dtrace_hdl_t *dtp, char *msg, size_t len)
{
	dt_proc_t fake[2];
	hrtime_t t0, t1;
	char want[256];

	memset(fake, 0, sizeof (fake));
	fake[0].dpr_proc = (struct ps_prochandle *)&fake[0];
	fake[1].dpr_proc = (struct ps_prochandle *)&fake[1];

	/* No handler: notifications are discarded. */
	cr_queue(dtp, &fake[0], "");
	dtp->dt_laststatus = dtp->dt_lastagg = dtp->dt_lastswitch = 0;
	dtrace_sleep(dtp);
	CHECK(dtp->dt_procs->dph_notify == NULL, "unhandled list kept\n");

	CHECK(dtrace_handle_proc(dtp, cr_prochdlr, NULL) == 0, "handler\n");
	/* Deadlines in the past (all last times zero): no wait. */
	cr_noteslen = 0;
	cr_queue(dtp, &fake[0], "");
	cr_queue(dtp, &fake[1], "gone");
	t0 = gethrtime();
	dtrace_sleep(dtp);
	t1 = gethrtime();
	/* The list is LIFO: fake[1] was queued last. */
	snprintf(want, sizeof (want), "%p:gone;%p:(none);", (void *)&fake[1],
	    (void *)&fake[0]);
	CHECK(strcmp(cr_notes, want) == 0 && t1 - t0 < NANOSEC / 2,
	    "past deadline: notes \"%s\" want \"%s\", %lld ns\n", cr_notes,
	    want, (long long)(t1 - t0));

	/*
	 * A deadline 0.9999 s ahead: the wait spans a second boundary of
	 * the absolute timeout and returns at the deadline.  Only the
	 * status deadline counts for a ring buffer, so the near aggrate
	 * and switchrate deadlines are ignored.
	 */
	cr_noteslen = 0;
	cr_notes[0] = '\0';
	dtp->dt_options[DTRACEOPT_BUFPOLICY] = DTRACEOPT_BUFPOLICY_RING;
	dtp->dt_options[DTRACEOPT_STATUSRATE] = NANOSEC - 100000;
	dtp->dt_options[DTRACEOPT_AGGRATE] = 1;
	dtp->dt_options[DTRACEOPT_SWITCHRATE] = 1;
	cr_queue(dtp, &fake[1], "late");
	t0 = gethrtime();
	dtp->dt_laststatus = t0;
	dtp->dt_lastagg = dtp->dt_lastswitch = t0;
	dtrace_sleep(dtp);
	t1 = gethrtime();
	snprintf(want, sizeof (want), "%p:late;", (void *)&fake[1]);
	CHECK(strcmp(cr_notes, want) == 0 && t1 - t0 >= NANOSEC / 2,
	    "timed wait: notes \"%s\", %lld ns\n", cr_notes,
	    (long long)(t1 - t0));

	/* A switching buffer takes the earliest rate (switchrate, 20ms). */
	dtp->dt_options[DTRACEOPT_BUFPOLICY] = DTRACEOPT_BUFPOLICY_SWITCH;
	dtp->dt_options[DTRACEOPT_STATUSRATE] = 10LL * NANOSEC;
	dtp->dt_options[DTRACEOPT_AGGRATE] = 10LL * NANOSEC;
	dtp->dt_options[DTRACEOPT_SWITCHRATE] = 20000000;
	t0 = gethrtime();
	dtp->dt_laststatus = dtp->dt_lastagg = dtp->dt_lastswitch = t0;
	dtrace_sleep(dtp);
	t1 = gethrtime();
	CHECK(t1 - t0 >= 10000000 && t1 - t0 < 5LL * NANOSEC,
	    "switchrate wait %lld ns\n", (long long)(t1 - t0));
	return (0);
}
