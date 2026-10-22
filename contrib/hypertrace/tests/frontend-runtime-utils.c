/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit and property tests for the libdtrace support code in dt_string.c,
 * dt_list.c, dt_inttab.c and dt_strtab.c, called through the exported
 * internal entry points of the library under test.
 *
 * Oracles (independent of the implementation under test):
 *  - escapes: the C escape rules (octal up to three digits, unbounded \x,
 *    the single-character escapes including \' and \?) applied by a
 *    reference decoder in this file, plus string literals compiled by cc
 *    into escape-fixtures.h by the driver (a cc differential); escapes that
 *    C does not define are kept verbatim ("\q" stays two characters);
 *  - strchr2esc: round trip through the reference decoder;
 *  - strbadidnum: strtoull(3) whole-string acceptance, else the first byte
 *    outside [A-Za-z0-9_`];
 *  - dt_list / dt_inttab / dt_strtab: array models kept by this harness.
 * With -DWITH_FAULTS (built without sanitizers) malloc/calloc/realloc are
 * interposed and every allocation of each operation is failed in turn; the
 * oracle is a clean documented failure (NULL / -1 / EDT_NOMEM) with the
 * structure still usable and equal to the model.
 */
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dt_impl.h>
#include <dt_inttab.h>
#include <dt_list.h>
#include <dt_string.h>
#include <dt_strtab.h>

#include "escape-fixtures.h"

static int failures, checks;

static void
check(int ok, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;
	failures++;
	printf("FAIL ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

#ifdef WITH_FAULTS
extern void *__malloc(size_t);
extern void *__calloc(size_t, size_t);
extern void *__realloc(void *, size_t);
static long fault_at, fault_count;
static int fault_hit;

static int
fault_now(void)
{
	if (fault_at != 0 && ++fault_count == fault_at) {
		fault_hit = 1;
		errno = ENOMEM;
		return (1);
	}
	return (0);
}

void *
malloc(size_t n)
{
	return (fault_now() ? NULL : __malloc(n));
}

void *
calloc(size_t n, size_t m)
{
	return (fault_now() ? NULL : __calloc(n, m));
}

void *
realloc(void *p, size_t n)
{
	return (fault_now() ? NULL : __realloc(p, n));
}

static void
arm(long n)
{
	fault_at = n;
	fault_count = 0;
	if (n != 0)
		fault_hit = 0;	/* disarming keeps the outcome */
}
#endif

/* Reference C escape decoder. */
static size_t
ref_unescape(const char *s, char *out)
{
	size_t n = 0;
	const char *p;
	unsigned v;
	int k;

	for (p = s; *p != '\0'; p++) {
		if (*p != '\\') {
			out[n++] = *p;
			continue;
		}
		p++;
		if (*p == '\0')
			break;		/* dangling backslash is dropped */
		if (*p >= '0' && *p <= '7') {
			for (v = 0, k = 0; k < 3 && *p >= '0' && *p <= '7';
			    k++, p++)
				v = v * 8 + (unsigned)(*p - '0');
			p--;
			out[n++] = (char)v;
			continue;
		}
		if (*p == 'x') {
			for (v = 0; isxdigit((unsigned char)p[1]); p++)
				v = v * 16 + (unsigned)(isdigit((unsigned char)
				    p[1]) ? p[1] - '0' :
				    tolower((unsigned char)p[1]) - 'a' + 10);
			out[n++] = (char)v;
			continue;
		}
		switch (*p) {
		case 'a': out[n++] = '\a'; break;
		case 'b': out[n++] = '\b'; break;
		case 'f': out[n++] = '\f'; break;
		case 'n': out[n++] = '\n'; break;
		case 'r': out[n++] = '\r'; break;
		case 't': out[n++] = '\t'; break;
		case 'v': out[n++] = '\v'; break;
		case '"': out[n++] = '"'; break;
		case '\'': out[n++] = '\''; break;
		case '?': out[n++] = '?'; break;
		case '\\': out[n++] = '\\'; break;
		default:
			out[n++] = '\\';
			out[n++] = *p;
		}
	}
	out[n] = '\0';
	return (n);
}

static void
test_escapes(void)
{
	static const char *const extra[] = {
		"", "plain", "\\q", "trail\\", "\\x", "\\xg",
		"\\x4142", "\\XAB", "\\8\\9", "\\0", "\\00a", "\\1234",
		"\\x1f\\xAa\\xfF", "a\\\\b\\\"c",
	};
	char buf[256], ref[256];
	size_t i, n, rn;

	/* cc differential: fixtures compiled by the C compiler. */
	for (i = 0; i < sizeof (fixtures) / sizeof (fixtures[0]); i++) {
		(void) strlcpy(buf, fixtures[i].source, sizeof (buf));
		n = stresc2chr(buf);
		check(n == fixtures[i].len &&
		    memcmp(buf, fixtures[i].bytes, n) == 0,
		    "stresc2chr cc fixture %zu (%s): len %zu want %zu", i,
		    fixtures[i].source, n, fixtures[i].len);
		rn = ref_unescape(fixtures[i].source, ref);
		check(rn == n && memcmp(ref, buf, n) == 0,
		    "reference decoder disagrees with cc on %s",
		    fixtures[i].source);
	}
	for (i = 0; i < sizeof (extra) / sizeof (extra[0]); i++) {
		(void) strlcpy(buf, extra[i], sizeof (buf));
		n = stresc2chr(buf);
		rn = ref_unescape(extra[i], ref);
		check(n == rn && memcmp(buf, ref, n) == 0,
		    "stresc2chr(%s) differs from reference", extra[i]);
	}
	/* Spot values fixed by the C standard / D semantics. */
	(void) strlcpy(buf, "\\q", sizeof (buf));
	check(stresc2chr(buf) == 2 && strcmp(buf, "\\q") == 0,
	    "unknown escape kept verbatim");
	(void) strlcpy(buf, "\\x4142", sizeof (buf));
	check(stresc2chr(buf) == 1 && buf[0] == (char)0x42,
	    "unbounded \\x keeps low byte");
}

/* D character constants use the same escapes (regression: '\'' and '\?'
 * used to keep the backslash).  An array dimension 40 - '\'' is 1 only if
 * the constant is 39; a two-byte value makes the dimension negative. */
static void
test_char_constants(dtrace_hdl_t *dtp)
{
	static const char *const progs[] = {
		"int x[40 - '\\''];\nBEGIN { trace(sizeof (x)); }",
		"int y[64 - '\\?'];\nBEGIN { trace(sizeof (y)); }",
		"int z[35 - '\\\"'];\nBEGIN { trace(sizeof (z)); }",
	};
	size_t i;

	for (i = 0; i < sizeof (progs) / sizeof (progs[0]); i++)
		check(dtrace_program_strcompile(dtp, progs[i],
		    DTRACE_PROBESPEC_NAME, 0, 0, NULL) != NULL,
		    "char constant program %zu: %s", i,
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
}

static void
test_chr2esc(void)
{
	char in[300], dec[1300];
	char *e;
	size_t i, n;
	unsigned seed = 12345;
	int t;

	/* Every byte value 1..255 individually, then random strings. */
	for (i = 1; i < 256; i++) {
		in[0] = (char)i;
		e = strchr2esc(in, 1);
		check(e != NULL, "strchr2esc alloc");
		if (e == NULL)
			continue;
		n = ref_unescape(e, dec);
		check(n == 1 && dec[0] == (char)i,
		    "round trip of byte %zu via %s", i, e);
		/* Printable non-special bytes are not escaped. */
		if (i >= '!' && i <= '~' && i != '"' && i != '\\')
			check(strlen(e) == 1, "printable %zu escaped", i);
		else if (i == ' ')
			check(strcmp(e, " ") == 0, "space escaped");
		else if (strchr("\a\b\f\n\r\t\v\"\\", (int)i) != NULL)
			check(strlen(e) == 2 && e[0] == '\\',
			    "single escape for %zu: %s", i, e);
		else
			check(strlen(e) == 4 && e[0] == '\\',
			    "octal escape for %zu: %s", i, e);
		free(e);
	}
	for (t = 0; t < 2000; t++) {
		n = (seed = seed * 1103515245 + 12345) % 64;
		for (i = 0; i < n; i++) {
			seed = seed * 1103515245 + 12345;
			in[i] = (char)(1 + (seed >> 16) % 255);
		}
		e = strchr2esc(in, n);
		check(e != NULL && ref_unescape(e, dec) == n &&
		    memcmp(dec, in, n) == 0, "random round trip %d", t);
		free(e);
	}
	/* An embedded NUL is encoded as \0 and ends the conversion. */
	memcpy(in, "ab\0cd", 5);
	e = strchr2esc(in, 5);
	check(e != NULL && strcmp(e, "ab\\0") == 0, "stops after NUL: %s",
	    e ? e : "(null)");
	free(e);
}

static const char *
ref_badidnum(const char *s)
{
	char *end;
	const char *p;

	if (*s == '\0')
		return (s);
	errno = 0;
	(void) strtoull(s, &end, 0);
	if (errno == 0 && *end == '\0')
		return (NULL);
	for (p = s; *p != '\0'; p++)
		if (!isalnum((unsigned char)*p) && *p != '_' && *p != '`')
			return (p);
	return (NULL);
}

static void
test_misc_strings(void)
{
	static const char *const ids[] = {
		"", "0", "123", "0x1F", "077", "-1", " 12", "abc", "a_b`c",
		"a-b", "x y", "99999999999999999999999", "0x", "1.5", "_",
		"genunix`kmem_alloc", "a+", "09",
	};
	static const struct { const char *in, *out; } hy[] = {
		{ "", "" }, { "a__b", "a-b" }, { "__", "-" },
		{ "a___b", "a-_b" }, { "a____b", "a--b" }, { "_a_", "_a_" },
		{ "x__y__z", "x-y-z" },
	};
	static const struct { const char *s; int g; } gl[] = {
		{ "", 0 }, { "abc", 0 }, { "a*", 1 }, { "a?", 1 },
		{ "[ab]", 1 }, { "a\\b", 1 }, { "a]b", 0 },
	};
	char buf[64];
	size_t i;

	for (i = 0; i < sizeof (ids) / sizeof (ids[0]); i++)
		check(strbadidnum(ids[i]) == NULL ? ref_badidnum(ids[i]) ==
		    NULL : ref_badidnum(ids[i]) != NULL &&
		    strbadidnum(ids[i]) - ids[i] ==
		    ref_badidnum(ids[i]) - ids[i], "strbadidnum(%s)", ids[i]);
	check(strbadidnum("a-b") != NULL && *strbadidnum("a-b") == '-',
	    "strbadidnum points at the bad byte");
	for (i = 0; i < sizeof (hy) / sizeof (hy[0]); i++) {
		(void) strlcpy(buf, hy[i].in, sizeof (buf));
		check(strhyphenate(buf) == buf && strcmp(buf, hy[i].out) == 0,
		    "strhyphenate(%s) = %s", hy[i].in, buf);
	}
	for (i = 0; i < sizeof (gl) / sizeof (gl[0]); i++)
		check(strisglob(gl[i].s) == gl[i].g, "strisglob(%s)", gl[i].s);
	check(strcmp(strbasename("/a/b/c"), "c") == 0, "basename path");
	check(strcmp(strbasename("c"), "c") == 0, "basename plain");
	check(strcmp(strbasename("/a/"), "") == 0, "basename trailing /");
}

typedef struct node {
	dt_list_t link;
	int value;
} node_t;

static int
list_matches(dt_list_t *l, node_t **model, int n)
{
	node_t *p;
	int i = 0;

	for (p = dt_list_next(l); p != NULL; p = dt_list_next(p), i++)
		if (i >= n || p != model[i])
			return (0);
	if (i != n)
		return (0);
	/* Backward walk must mirror the forward one. */
	for (p = dt_list_prev(l), i = n - 1; p != NULL;
	    p = dt_list_prev(p), i--)
		if (i < 0 || p != model[i])
			return (0);
	return (i == -1);
}

static void
test_list(void)
{
	node_t nodes[200], *model[200];
	dt_list_t l;
	unsigned seed = 7;
	int n = 0, i, j, op, v;

	memset(&l, 0, sizeof (l));
	for (i = 0; i < 200; i++)
		nodes[i].value = i;
	for (i = 0; i < 200; i++) {
		seed = seed * 1103515245 + 12345;
		op = (seed >> 16) % 4;
		if (op == 0) {
			dt_list_append(&l, &nodes[i]);
			model[n++] = &nodes[i];
		} else if (op == 1) {
			dt_list_prepend(&l, &nodes[i]);
			memmove(model + 1, model, n * sizeof (model[0]));
			model[0] = &nodes[i];
			n++;
		} else if (op == 2) {
			/* insert after position j; j == -1 means NULL */
			j = n == 0 ? -1 : (int)((seed >> 8) % (n + 1)) - 1;
			dt_list_insert(&l, j < 0 ? NULL : model[j], &nodes[i]);
			if (j < 0 || j == n - 1) {
				model[n++] = &nodes[i];	/* appended */
			} else {
				memmove(model + j + 2, model + j + 1,
				    (n - j - 1) * sizeof (model[0]));
				model[j + 1] = &nodes[i];
				n++;
			}
		} else if (n > 0) {
			j = (seed >> 8) % n;
			dt_list_delete(&l, model[j]);
			memmove(model + j, model + j + 1,
			    (n - j - 1) * sizeof (model[0]));
			n--;
		}
		check(list_matches(&l, model, n), "list model step %d op %d",
		    i, op);
	}
	for (i = 0; i < n; i++) {
		v = model[i]->value;
		check(dt_in_list(&l, &v, sizeof (v)) == model[i],
		    "dt_in_list finds %d", v);
	}
	v = 1000;
	check(dt_in_list(&l, &v, sizeof (v)) == NULL, "dt_in_list misses");
	memset(&l, 0, sizeof (l));
	check(dt_in_list(&l, &v, sizeof (v)) == NULL, "dt_in_list empty");
}

static void
test_inttab(dtrace_hdl_t *dtp)
{
	uint64_t vals[600], out[600];
	uint_t flags[600];
	int idx[600], n = 0, i, j, r;
	unsigned seed = 99;
	dt_inttab_t *ip = dt_inttab_create(dtp);

	check(ip != NULL, "inttab create");
	if (ip == NULL)
		return;
	for (i = 0; i < 600; i++) {
		seed = seed * 1103515245 + 12345;
		uint64_t v = (seed >> 16) % 40 + ((uint64_t)(seed & 1) << 40);
		uint_t f = (seed >> 8) % 3 == 0 ? 0 : DT_INT_SHARED;
		int want = n;

		/* Shared values reuse an existing shared entry if present. */
		if (f & DT_INT_SHARED)
			for (j = 0; j < n; j++)
				if (vals[j] == v && flags[j] == f) {
					want = j;
					break;
				}
		r = dt_inttab_insert(ip, v, f);
		check(r == want, "inttab insert %d: got %d want %d", i, r, want);
		if (want == n) {
			vals[n] = v;
			flags[n] = f;
			idx[n] = r;
			n++;
		}
	}
	check(dt_inttab_size(ip) == (uint_t)n, "inttab size");
	dt_inttab_write(ip, out);
	for (i = 0; i < n; i++)
		check(out[i] == vals[i] && idx[i] == i, "inttab write %d", i);
	dt_inttab_destroy(ip);
}

typedef struct { char buf[8192]; size_t len; int calls, stop; } sink_t;

static ssize_t
sink(const char *p, size_t n, size_t off, void *arg)
{
	sink_t *s = arg;

	if (s->stop && s->calls++ >= s->stop - 1)
		return (0);
	if (off != s->len)
		return (-1);
	memcpy(s->buf + s->len, p, n);
	s->len += n;
	return ((ssize_t)n);
}

static void
test_strtab(size_t bufsz)
{
	static char strs[300][24];
	char model[8192];
	ssize_t offs[300], r;
	size_t msize = 1;
	int i, j;
	unsigned seed = (unsigned)bufsz;
	dt_strtab_t *sp = dt_strtab_create(bufsz);
	sink_t s;

	check(sp != NULL, "strtab create %zu", bufsz);
	if (sp == NULL)
		return;
	model[0] = '\0';
	check(dt_strtab_empty(sp) && dt_strtab_size(sp) == 1, "empty strtab");
	check(dt_strtab_index(sp, "") == 0 && dt_strtab_index(sp, NULL) == 0,
	    "empty string is offset 0");
	for (i = 0; i < 300; i++) {
		seed = seed * 1103515245 + 12345;
		(void) snprintf(strs[i], sizeof (strs[i]), "s%u_%.*s",
		    (seed >> 16) % 120, (int)((seed >> 8) % 12),
		    "abcdefghijkl");
		for (j = 0; j < i; j++)
			if (strcmp(strs[j], strs[i]) == 0)
				break;
		r = dt_strtab_insert(sp, strs[i]);
		if (j < i) {
			check(r == offs[j], "dup insert returns first offset");
			offs[i] = offs[j];
			continue;
		}
		check(r == (ssize_t)msize, "insert offset %zd want %zu", r,
		    msize);
		offs[i] = r;
		memcpy(model + msize, strs[i], strlen(strs[i]) + 1);
		msize += strlen(strs[i]) + 1;
	}
	check(!dt_strtab_empty(sp) && dt_strtab_size(sp) == msize,
	    "strtab size");
	for (i = 0; i < 300; i++)
		check(dt_strtab_index(sp, strs[i]) == offs[i], "index %d", i);
	check(dt_strtab_index(sp, "absent-string") == -1, "absent index");
	memset(&s, 0, sizeof (s));
	check(dt_strtab_write(sp, sink, &s) == (ssize_t)msize &&
	    s.len == msize && memcmp(s.buf, model, msize) == 0,
	    "strtab write image");
	/* A writer that stops at once: no bytes, but the table is not empty. */
	memset(&s, 0, sizeof (s));
	s.stop = 1;
	check(dt_strtab_write(sp, sink, &s) == -1, "stopped write is -1");
	dt_strtab_destroy(sp);
}

#ifdef WITH_FAULTS
static void
fault_sweep(dtrace_hdl_t *dtp)
{
	long n;
	int done;

	for (n = 1, done = 0; !done && n < 100; n++) {	/* create */
		arm(n);
		dt_strtab_t *sp = dt_strtab_create(16);
		arm(0);
		if (!fault_hit) {
			check(sp != NULL, "strtab create unfaulted");
			done = 1;
		} else
			check(sp == NULL, "strtab create fault %ld clean", n);
		if (sp != NULL)
			dt_strtab_destroy(sp);
	}
	for (n = 1, done = 0; !done && n < 100; n++) {	/* insert */
		dt_strtab_t *sp = dt_strtab_create(8);
		ssize_t r;
		sink_t s;

		(void) dt_strtab_insert(sp, "abc");
		arm(n);
		r = dt_strtab_insert(sp, "a-long-string-over-buffers");
		arm(0);
		if (!fault_hit) {
			check(r == 5, "insert unfaulted");
			done = 1;
		} else {
			check(r == -1 && dt_strtab_size(sp) == 5 &&
			    dt_strtab_index(sp, "a-long-string-over-buffers") ==
			    -1, "strtab insert fault %ld clean", n);
			memset(&s, 0, sizeof (s));
			check(dt_strtab_write(sp, sink, &s) == 5 &&
			    memcmp(s.buf, "\0abc\0", 5) == 0,
			    "strtab image intact after fault %ld", n);
			check(dt_strtab_insert(sp, "xy") == 5,
			    "strtab usable after fault %ld", n);
		}
		dt_strtab_destroy(sp);
	}
	for (n = 1, done = 0; !done && n < 10; n++) {	/* inttab */
		dt_inttab_t *ip;
		int r = 0;

		arm(n);
		ip = dt_inttab_create(dtp);
		if (ip != NULL)
			r = dt_inttab_insert(ip, 5, 0);
		arm(0);
		if (!fault_hit) {
			check(ip != NULL && r == 0, "inttab unfaulted");
			done = 1;
		} else
			check((ip == NULL || r == -1) &&
			    dtrace_errno(dtp) == EDT_NOMEM,
			    "inttab fault %ld clean", n);
		if (ip != NULL) {
			if (r == -1)
				check(dt_inttab_size(ip) == 0 &&
				    dt_inttab_insert(ip, 5, 0) == 0,
				    "inttab usable after fault");
			dt_inttab_destroy(ip);
		}
	}
	for (n = 1, done = 0; !done && n < 10; n++) {	/* strchr2esc */
		char *e;

		arm(n);
		e = strchr2esc("a\nb", 3);
		arm(0);
		if (!fault_hit) {
			check(e != NULL && strcmp(e, "a\\nb") == 0,
			    "strchr2esc unfaulted");
			done = 1;
		} else
			check(e == NULL, "strchr2esc fault clean");
		free(e);
	}
}
#endif

int
main(void)
{
	int err;
	dtrace_hdl_t *dtp = dtrace_open(DTRACE_VERSION,
	    DTRACE_O_NODEV | DTRACE_O_NOSYS, &err);

	if (dtp == NULL) {
		printf("FAIL dtrace_open %d\n", err);
		return (1);
	}
	test_escapes();
	test_char_constants(dtp);
	test_chr2esc();
	test_misc_strings();
	test_list();
	test_inttab(dtp);
	test_strtab(1);
	test_strtab(7);
	test_strtab(4096);
#ifdef WITH_FAULTS
	fault_sweep(dtp);
#endif
	dtrace_close(dtp);
	printf("%s %d checks, %d failures\n", failures ? "FAIL" : "PASS",
	    checks, failures);
	exit(failures != 0);
}
