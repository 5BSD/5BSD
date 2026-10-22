/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * printf()/printa()/print() formatting through the actual libdtrace, offline.
 *
 * Four kinds of evidence, none captured from the library:
 *
 *  - record formatting (dtrace_printf_create/dtrace_fprintf with records
 *    built here): integer and floating-point conversions are compared with
 *    C snprintf(3) of the record value, using the size prefix that
 *    dt_printf_validate() gives a 64-bit (or long double) argument; the
 *    D-specific conversions (%a %A %C %S %k %Y %T %P %I) with their
 *    documented forms, the model's symbol table (consume-ingestion.c) and
 *    the stand-in resolver of printf-conversions-shim.c;
 *  - the pickled format (dtrace_printf_format) and dt_printf_dup() against
 *    the canonical flag order of dt_printf_format;
 *  - D compilation: each conversion's type check accepts the documented
 *    argument types and rejects others with its [D_TAG] and prototype text;
 *  - consumption through the modeled dtrace(4) vector of
 *    consume-ingestion.c (printa grouping, aggregation-value conversions,
 *    system(), freopen(), buffered output) and print() of CTF types that
 *    are built here with libctf, with text expectations derived from the
 *    ::print -tn rules in dt_print.c and JSON checked by the driver.
 *
 * No tracing device, kernel, daemon or network resolver is used.
 */

#include <dt_impl.h>
#include <dt_printf.h>
#include <dt_module.h>
#include <ctf_impl.h>

#include <sys/resource.h>
#include <sys/wait.h>

#include <dlfcn.h>
#include <locale.h>
#include <time.h>
#include <wchar.h>

#define	main consume_ingestion_main
#include "consume-ingestion.c"
#undef main

static void
pass(const char *name)
{
	passes++;
	printf("PASS %s\n", name);
}

/* ------------------------------------------------------------------ */
/* Record builder.                                                     */

struct rb {
	dtrace_recdesc_t rec[16];
	uint_t n;
	size_t len;
	_Alignas(16) char buf[8192];
};

static void
rb_reset(struct rb *b)
{
	memset(b, 0, sizeof (*b));
}

static dtrace_recdesc_t *
rb_put(struct rb *b, uint32_t act, const void *p, uint32_t size,
    uint16_t align, uint64_t arg)
{
	dtrace_recdesc_t *r = &b->rec[b->n++];

	assert(b->n <= 16);
	if (align == 0)
		align = (size == 1 || size == 2 || size == 4 || size == 8 ||
		    size == 16) ? size : 1;
	b->len = (b->len + align - 1) & ~(size_t)(align - 1);
	assert(b->len + size <= sizeof (b->buf));
	memset(r, 0, sizeof (*r));
	r->dtrd_action = act;
	r->dtrd_size = size;
	r->dtrd_offset = b->len;
	r->dtrd_alignment = align;
	r->dtrd_arg = arg;
	if (p != NULL)
		memcpy(b->buf + b->len, p, size);
	b->len += size;
	return (r);
}

static dtrace_hdl_t *H;		/* vector handle with the model's symbols */
static dtrace_hdl_t *N;		/* NODEV handle: no vector */

static char *
render(dtrace_hdl_t *dtp, const char *fmt, struct rb *b, int *rc, int *err)
{
	char *text = NULL;
	size_t len = 0;
	void *pfv;
	FILE *f;

	if ((pfv = dtrace_printf_create(dtp, fmt)) == NULL) {
		*rc = -2;
		*err = dtrace_errno(dtp);
		return (strdup(""));
	}
	f = open_memstream(&text, &len);
	assert(f != NULL);
	*rc = dtrace_fprintf(dtp, f, pfv, NULL, b->rec, b->n, b->buf, b->len);
	*err = *rc < 0 ? dtrace_errno(dtp) : 0;
	fclose(f);
	dt_printf_destroy(pfv);
	return (text);
}

static void
want_out_h(dtrace_hdl_t *dtp, const char *name, const char *fmt, struct rb *b,
    const char *want)
{
	int rc, err;
	char *got = render(dtp, fmt, b, &rc, &err);

	if (rc < 0) {
		char msg[256];

		snprintf(msg, sizeof (msg), "rc %d: %s\n", rc,
		    dtrace_errmsg(dtp, err));
		fail(name, fmt, want, msg);
	} else if (strcmp(got, want) != 0)
		fail(name, fmt, want, got);
	else
		pass(name);
	free(got);
}

static void
want_out(const char *name, const char *fmt, struct rb *b, const char *want)
{
	want_out_h(H, name, fmt, b, want);
}

static void
want_err_h(dtrace_hdl_t *dtp, const char *name, const char *fmt, struct rb *b,
    int edt)
{
	int rc, err;
	char *got = render(dtp, fmt, b, &rc, &err);

	if (rc >= 0 || err != edt) {
		char msg[256];

		snprintf(msg, sizeof (msg), "rc %d err %d (%s) output \"%s\"\n",
		    rc, err, dtrace_errmsg(dtp, err), got);
		fail(name, fmt, dtrace_errmsg(dtp, edt), msg);
	} else
		pass(name);
	free(got);
}

static void
want_err(const char *name, const char *fmt, struct rb *b, int edt)
{
	want_err_h(H, name, fmt, b, edt);
}

/* ------------------------------------------------------------------ */
/* Integer conversions against snprintf(3).                            */

struct iconv {
	const char *name;	/* D conversion name */
	int sign;		/* pfprint_sint (1) or pfprint_uint (0) */
};

static const struct iconv iconvs[] = {
	{ "i", 1 }, { "hd", 1 }, { "hi", 1 }, { "ld", 1 }, { "li", 1 },
	{ "lld", 1 }, { "lli", 1 },
	{ "d", 0 }, { "u", 0 }, { "o", 0 }, { "x", 0 }, { "X", 0 },
	{ "ho", 0 }, { "hu", 0 }, { "hx", 0 }, { "hX", 0 },
	{ "lo", 0 }, { "lu", 0 }, { "lx", 0 }, { "lX", 0 },
	{ "llo", 0 }, { "llu", 0 }, { "llx", 0 }, { "llX", 0 },
};

/*
 * The C format and argument for a D integer record: the record value is
 * sign- or zero-extended from its size; an explicit h, l or ll names the
 * argument type; without one, an 8-byte record is printed with "ll" (what
 * dt_printf_validate() produces for a 64-bit argument) and a narrower one
 * as int.  dtrace_printf_create() keeps the conversion name as given, so the
 * C conversion is the name itself; %d has no signedness (pfprint_dint).
 */
static void
int_oracle(char *out, size_t outlen, const char *flags, const char *name,
    int sign, const void *rec, size_t size)
{
	char fmt[64];
	size_t nl = strlen(name);
	char conv = name[nl - 1];
	uint64_t v = 0;

	switch (size) {
	case 1: v = sign ? (uint64_t)(int64_t)*(const int8_t *)rec :
	    *(const uint8_t *)rec; break;
	case 2: v = sign ? (uint64_t)(int64_t)*(const int16_t *)rec :
	    *(const uint16_t *)rec; break;
	case 4: v = sign ? (uint64_t)(int64_t)*(const int32_t *)rec :
	    *(const uint32_t *)rec; break;
	case 8: v = *(const uint64_t *)rec; break;
	default: abort();
	}
	if (nl >= 3 && name[0] == 'l' && name[1] == 'l') {
		snprintf(fmt, sizeof (fmt), "%%%s%s", flags, name);
		snprintf(out, outlen, fmt, (long long)v);
	} else if (name[0] == 'l') {
		snprintf(fmt, sizeof (fmt), "%%%s%s", flags, name);
		snprintf(out, outlen, fmt, (long)v);
	} else if (name[0] != 'h' && size == 8) {
		snprintf(fmt, sizeof (fmt), "%%%sll%c", flags, conv);
		snprintf(out, outlen, fmt, (long long)v);
	} else {
		snprintf(fmt, sizeof (fmt), "%%%s%s", flags, name);
		snprintf(out, outlen, fmt, (int)v);
	}
}

static void
case_integers(void)
{
	static const char *const flagsets[] = { "", "#", "08", "-6", "-08", "'",
	    "7", "9.7", "+",
	    " ", "#012.5", "-+10" };
	static const int64_t values[] = { 0, 1, -1, 42, -42, 127, -128, 255,
	    32767, -32768, 65535, 0x7fffffff, -0x7fffffffLL - 1, 0xffffffffLL,
	    5000000000LL, -5000000000LL, INT64_MAX, INT64_MIN };
	static const size_t sizes[] = { 1, 2, 4, 8 };
	unsigned ok = 0, bad = 0;
	size_t c, f, v, s;
	struct rb b;

	for (c = 0; c < sizeof (iconvs) / sizeof (iconvs[0]); c++)
	for (f = 0; f < sizeof (flagsets) / sizeof (flagsets[0]); f++)
	for (s = 0; s < 4; s++)
	for (v = 0; v < sizeof (values) / sizeof (values[0]); v++) {
		char fmt[64], want[128], *got;
		int rc, err;

		snprintf(fmt, sizeof (fmt), "<%%%s%s>", flagsets[f],
		    iconvs[c].name);
		rb_reset(&b);
		rb_put(&b, DTRACEACT_DIFEXPR, &values[v], sizes[s], 0, 0);
		want[0] = '<';
		int_oracle(want + 1, sizeof (want) - 2, flagsets[f],
		    iconvs[c].name, iconvs[c].sign, &values[v], sizes[s]);
		strlcat(want, ">", sizeof (want));
		got = render(H, fmt, &b, &rc, &err);
		if (rc < 0 || strcmp(got, want) != 0) {
			if (bad++ < 8)
				fail("integer-conversions", fmt, want, got);
		} else
			ok++;
		free(got);
	}
	if (bad == 0)
		pass("integer-conversions");
	printf("integer conversions: %u matched snprintf, %u differed\n",
	    ok, bad);
}

/*
 * The regressions behind pfprint_int(): a format without a size prefix
 * describing a 64-bit record, and an "ll" format describing a 32-bit record,
 * print the record value, as the equivalent compiler-produced format does.
 */
static void
case_integer_widths(void)
{
	int64_t big = 5000000000LL;
	int32_t m1 = -1;
	int16_t s16 = -2;
	uint32_t u32 = 0xfffffffeU;
	struct rb b;

	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &big, 8, 0, 0);
	want_out("width-unprefixed-64bit-d", "%d", &b, "5000000000");
	want_out("width-unprefixed-64bit-x", "%x", &b, "12a05f200");
	want_out("width-unprefixed-64bit-i", "%i", &b, "5000000000");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &m1, 4, 0, 0);
	want_out("width-ll-on-32bit-signed", "%lld", &b, "-1");
	want_out("width-l-on-32bit-signed", "%ld", &b, "-1");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &u32, 4, 0, 0);
	want_out("width-ll-on-32bit-unsigned", "%llu", &b, "4294967294");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &s16, 2, 0, 0);
	want_out("width-h-on-16bit", "%hd", &b, "-2");
	want_out("width-hx-on-16bit", "%hx", &b, "fffe");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &big, 8, 0, 0);
	want_out("width-h-on-64bit", "%hu", &b, "61952"); /* 5e9 & 0xffff */
}

static void
case_chars_pointers(void)
{
	int8_t a = 'A';
	int16_t z = 'z';
	int32_t q = '?';
	uint64_t p64 = 0xffffffff80001010ULL;
	uint32_t p32 = 0x8001000;
	struct rb b;
	char want[64];

	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &a, 1, 0, 0);
	want_out("char-1", "[%c]", &b, "[A]");
	want_out("char-width", "[%-3c]", &b, "[A  ]");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &z, 2, 0, 0);
	want_out("char-2", "%c", &b, "z");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &q, 4, 0, 0);
	want_out("char-4", "%c", &b, "?");
	want_out("wide-char-lc", "%lc", &b, "?");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &p64, 8, 0, 0);
	snprintf(want, sizeof (want), "%p", (void *)(uintptr_t)p64);
	want_out("pointer-64", "%p", &b, want);
	snprintf(want, sizeof (want), "%20p", (void *)(uintptr_t)p64);
	want_out("pointer-width", "%20p", &b, want);
	/* %? is the pointer width of the data model: 16 for LP64. */
	snprintf(want, sizeof (want), "%16p", (void *)(uintptr_t)p64);
	want_out("pointer-question", "%?p", &b, want);
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &p32, 4, 0, 0);
	snprintf(want, sizeof (want), "%p", (void *)(uintptr_t)p32);
	want_out("pointer-32", "%p", &b, want);
	/* A 3-byte record has no integer type. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, "abc", 3, 1, 0);
	want_err("int-size-3-signed", "%i", &b, EDT_DMISMATCH);
	want_err("int-size-3-unsigned", "%u", &b, EDT_DMISMATCH);
	want_err("int-size-3-d", "%d", &b, EDT_DMISMATCH);
}

static void
case_floats(void)
{
	static const char *const convs[] = { "e", "E", "f", "g", "G" };
	static const char *const flags[] = { "", "+", "12.3", "-14.6", "#" };
	static const double dv[] = { 0.0, 1.5, -2.25, 1e10, 3.0e-5, 123456.789 };
	unsigned bad = 0, ok = 0;
	size_t c, f, i;
	struct rb b;

	for (c = 0; c < 5; c++)
	for (f = 0; f < 5; f++)
	for (i = 0; i < sizeof (dv) / sizeof (dv[0]); i++) {
		char fmt[32], cfmt[32], want[128], *got;
		float fl = (float)dv[i];
		long double ld = (long double)dv[i] / 3;
		int rc, err, k;

		for (k = 0; k < 4; k++) {
			rb_reset(&b);
			switch (k) {
			case 0:	/* float record, double conversion */
				rb_put(&b, DTRACEACT_DIFEXPR, &fl, 4, 0, 0);
				snprintf(fmt, sizeof (fmt), "%%%s%s",
				    flags[f], convs[c]);
				snprintf(want, sizeof (want), fmt, (double)fl);
				break;
			case 1:	/* double record */
				rb_put(&b, DTRACEACT_DIFEXPR, &dv[i], 8, 0,
				    0);
				snprintf(fmt, sizeof (fmt), "%%%s%s",
				    flags[f], convs[c]);
				snprintf(want, sizeof (want), fmt, dv[i]);
				break;
			case 2:	/* long double record, %L conversion */
				rb_put(&b, DTRACEACT_DIFEXPR, &ld, 16, 0, 0);
				snprintf(fmt, sizeof (fmt), "%%%sL%s",
				    flags[f], convs[c]);
				snprintf(want, sizeof (want), fmt, ld);
				break;
			default: /* long double record, no "L" given */
				rb_put(&b, DTRACEACT_DIFEXPR, &ld, 16, 0, 0);
				snprintf(fmt, sizeof (fmt), "%%%s%s",
				    flags[f], convs[c]);
				snprintf(cfmt, sizeof (cfmt), "%%%sL%s",
				    flags[f], convs[c]);
				snprintf(want, sizeof (want), cfmt, ld);
				break;
			}
			got = render(H, fmt, &b, &rc, &err);
			if (rc < 0 || strcmp(got, want) != 0) {
				if (bad++ < 8)
					fail("float-conversions", fmt, want,
					    got);
			} else
				ok++;
			free(got);
		}
	}
	if (bad == 0)
		pass("float-conversions");
	printf("float conversions: %u matched snprintf, %u differed\n", ok,
	    bad);

	/* An "L" conversion of a double record passes a long double. */
	{
		double d = 1.5;

		rb_reset(&b);
		rb_put(&b, DTRACEACT_DIFEXPR, &d, 8, 0, 0);
		want_out("float-L-on-double", "%Lf", &b, "1.500000");
		rb_reset(&b);
		rb_put(&b, DTRACEACT_DIFEXPR, "abc", 3, 1, 0);
		want_err("float-size-3", "%f", &b, EDT_DMISMATCH);
	}
}

/* ------------------------------------------------------------------ */
/* Strings and escapes.                                                */

static void
case_strings(void)
{
	struct rb b;
	static const char esc[] = { 'a', '\t', 'b', '"', 'c', '\\', 'd', 1,
	    ' ', 0x7f, (char)0x80, '\a', '\b', '\f', '\n', '\r', '\v', 'z' };
	int8_t nl = '\n', x = 'x';
	int16_t q2 = '"';
	int32_t bs = '\\';
	int64_t big = 'y';
	wchar_t ws[4] = { L'h', L'i', 0, 0 };

	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, "hello\0\0\0", 8, 1, 0);
	want_out("string-plain", "[%s]", &b, "[hello]");
	want_out("string-width", "[%8s]", &b, "[   hello]");
	want_out("string-left", "[%-8s]", &b, "[hello   ]");
	want_out("string-precision", "[%.3s]", &b, "[hel]");
	want_out("string-width-precision", "[%6.2s]", &b, "[    he]");
	/* A record without a NUL is bounded by its size. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, "abcdef", 4, 1, 0);
	want_out("string-unterminated", "%s", &b, "abcd");

	/*
	 * %S: strchr2esc() escapes the C escapes, '"' and '\\', and writes
	 * other non-graphic bytes as three octal digits; space is literal.
	 */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, esc, sizeof (esc), 1, 0);
	want_out("string-escaped", "%S", &b,
	    "a\\tb\\\"c\\\\d\\001 \\177\\200\\a\\b\\f\\n\\r\\vz");
	/* Escaping stops at (and shows) the first NUL. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, "ab\0cd", 5, 1, 0);
	want_out("string-escaped-nul", "%S", &b, "ab\\0");

	/* %C: one character, escaped. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &nl, 1, 0, 0);
	want_out("char-escaped-newline", "%C", &b, "\\n");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &x, 1, 0, 0);
	want_out("char-escaped-plain", "[%3C]", &b, "[  x]");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &q2, 2, 0, 0);
	want_out("char-escaped-2", "%C", &b, "\\\"");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &bs, 4, 0, 0);
	want_out("char-escaped-4", "%C", &b, "\\\\");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &big, 8, 0, 0);
	want_err("char-escaped-8", "%C", &b, EDT_DMISMATCH);

	/* %ls: a wchar_t array. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, ws, sizeof (ws), 4, 0);
	want_out("wide-string", "[%ls]", &b, "[hi]");
	want_out("wide-string-width", "[%4ls]", &b, "[  hi]");
	want_out("wide-string-w", "[%ws]", &b, "[hi]");
	{
		int32_t wc = 'W';

		rb_reset(&b);
		rb_put(&b, DTRACEACT_DIFEXPR, &wc, 4, 0, 0);
		want_out("wide-char-w", "[%wc]", &b, "[W]");
	}

	/* %% consumes no record; literal text passes through. */
	rb_reset(&b);
	want_out("percent-only", "100%%", &b, "100%");
	want_out("literal-only", "plain text", &b, "plain text");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, "ok\0", 3, 1, 0);
	want_out("percent-between", "%% %s %%", &b, "% ok %");
}

/* ------------------------------------------------------------------ */
/* Addresses, stacks, modules.                                         */

#define	KVM_FAULT	0xffffffff80001000ULL	/* model: kernel`vm_fault */
#define	KSCHED		0xffffffff80002000ULL	/* model: kernel`sched_tick */

/* The model's symbols plus one whose name outgrows a 256-byte guess. */
#define	KLONG		0xffffffff80003000ULL
static char longname[301];

static int
long_lookup(void *varg, GElf_Addr addr, GElf_Sym *sym, dtrace_syminfo_t *si)
{
	if (addr < KLONG || addr >= KLONG + 0x10)
		return (model_lookup(varg, addr, sym, si));
	if (sym != NULL) {
		memset(sym, 0, sizeof (*sym));
		sym->st_value = KLONG;
		sym->st_size = 0x10;
	}
	if (si != NULL) {
		si->dts_object = "kernel";
		si->dts_name = longname;
		si->dts_id = 0;
	}
	return (0);
}

static const dtrace_vector_t long_vector = {
	.dtv_ioctl = model_ioctl,
	.dtv_lookup_by_addr = long_lookup,
	.dtv_status = model_status,
	.dtv_sysconf = model_sysconf,
};

static void
case_long_symbol(void)
{
	int err;
	dtrace_hdl_t *h = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS |
	    DTRACE_O_LP64, &err, &long_vector, &M);
	uint64_t a = KLONG + 4;
	struct rb b;
	char want[400];

	if (h == NULL) {
		fail("addr-long-symbol", "open", "", "");
		return;
	}
	/*
	 * "kernel`<name>+0x4" of 256 characters (exactly the first buffer,
	 * which then has no room for the NUL) and of 311.
	 */
	{
		static const size_t len[] = { 245, 300 };
		size_t i;

		for (i = 0; i < 2; i++) {
			char nm[64];

			memset(longname, 'n', len[i]);
			longname[len[i]] = '\0';
			rb_reset(&b);
			rb_put(&b, DTRACEACT_DIFEXPR, &a, 8, 0, 0);
			snprintf(want, sizeof (want), "kernel`%s+0x4",
			    longname);
			snprintf(nm, sizeof (nm), "addr-long-symbol-%zu",
			    strlen(want));
			want_out_h(h, nm, "%a", &b, want);
		}
	}
	dtrace_close(h);
}

static void
case_addresses(void)
{
	uint64_t exact = KVM_FAULT, off = KVM_FAULT + 0x10;
	uint64_t modonly = 0xffffffff80050000ULL, none = 0x1234;
	uint32_t small = 0x4321;
	uint64_t pair[2], guest[2];
	struct rb b;
	char want[96];

	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &exact, 8, 0, 0);
	want_out("addr-exact-symbol", "%a", &b, "kernel`vm_fault");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &off, 8, 0, 0);
	want_out("addr-symbol-offset", "[%-24a]", &b,
	    "[kernel`vm_fault+0x10    ]");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &modonly, 8, 0, 0);
	want_out("addr-module-only", "%a", &b, "kernel`0xffffffff80050000");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &none, 8, 0, 0);
	want_out("addr-unknown", "%a", &b, "0x1234");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &small, 4, 0, 0);
	want_out("addr-32bit", "%a", &b, "0x4321");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, "ab", 2, 0, 0);
	want_err("addr-size-2", "%a", &b, EDT_DMISMATCH);

	/* %A: with a vector (or pid 0) the address is printed raw. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &none, 8, 0, 0);
	want_out("uaddr-64", "%A", &b, "0x1234");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &small, 4, 0, 0);
	want_out("uaddr-32", "%A", &b, "0x4321");
	pair[0] = 0;
	pair[1] = 0x401000;
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, pair, 16, 8, 0);
	want_out("uaddr-pid-pair", "%A", &b, "0x401000");
	/* A guest-tagged pid names the guest and its process. */
	guest[0] = HYPERTRACE_USTACK_ENCODE(3, 77);
	guest[1] = 0x401000;
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, guest, 16, 8, 0);
	snprintf(want, sizeof (want), "guest[%u]:pid[%u]`0x%llx", 3U, 77U,
	    0x401000ULL);
	want_out("uaddr-guest", "%A", &b, want);
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, "abc", 3, 1, 0);
	want_err("uaddr-size-3", "%A", &b, EDT_DMISMATCH);
	/* Without a vector, %A uses the "target" macro's pid (0 here). */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &none, 8, 0, 0);
	want_out_h(N, "uaddr-nodev-target", "%A", &b, "0x1234");

	/* mod()/umod() records select the module printers. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_MOD, &off, 8, 0, 0);
	want_out("mod-record", "[%s]", &b, "[kernel]");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_MOD, &none, 8, 0, 0);
	want_out("mod-record-unknown", "%s", &b, "0x1234");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_UMOD, pair, 16, 8, 0);
	want_out("umod-record", "%s", &b, "0x401000");
}

static void
case_stacks(void)
{
	uint64_t frames[4] = { KVM_FAULT + 0x10, KSCHED, 0x1234, 0 };
	uint32_t f32[2] = { 0x4321, 0x99 };
	int32_t dynw = -6, posw = 3;
	uint64_t ust[4] = { 0, 0x401000, 0x402000, 0 };
	uint64_t ust0[1] = { 0 };
	struct rb b;

	/*
	 * dt_print_stack(): a newline, then each frame on its own line,
	 * indented by the stackindent option and printed with the
	 * conversion's format.  pfprint_stack() sets stackindent for the
	 * conversion: a left-justified width becomes the indentation (its
	 * documented semantic), otherwise there is none.
	 */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_STACK, frames, sizeof (frames), 8, 4);
	want_out("stack-default", "%k", &b,
	    "\nkernel`vm_fault+0x10\nkernel`sched_tick\n0x1234\n");
	want_out("stack-left-width-indent", "%-4k", &b,
	    "\n    kernel`vm_fault+0x10\n    kernel`sched_tick\n    0x1234\n");
	want_out("stack-right-width", "%22k", &b,
	    "\n  kernel`vm_fault+0x10\n     kernel`sched_tick\n"
	    "                0x1234\n");
	/* A negative dynamic width is a left-justified one. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &dynw, 4, 0, 0);
	rb_put(&b, DTRACEACT_STACK, frames, sizeof (frames), 8, 4);
	want_out("stack-negative-dynwidth", "%*k", &b,
	    "\n      kernel`vm_fault+0x10\n      kernel`sched_tick\n"
	    "      0x1234\n");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &posw, 4, 0, 0);
	rb_put(&b, DTRACEACT_STACK, frames, sizeof (frames), 8, 4);
	want_out("stack-left-dynwidth", "%-*k", &b,
	    "\n   kernel`vm_fault+0x10\n   kernel`sched_tick\n   0x1234\n");
	/* 32-bit program counters. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_STACK, f32, sizeof (f32), 4, 2);
	want_out("stack-32bit", "%-1k", &b, "\n 0x4321\n 0x99\n");
	/* A stack record with no frames is malformed. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_STACK, frames, sizeof (frames), 8, 0);
	want_err("stack-zero-frames", "%k", &b, EDT_BADSTACKPC);
	/* %k of a record that is no stack: an error, not an assertion. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, frames, 8, 8, 0);
	want_err("stack-not-a-stack", "%k", &b, EDT_DMISMATCH);
	/* User stacks with a vector print raw addresses. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_USTACK, ust, sizeof (ust), 8,
	    DTRACE_USTACK_ARG(3, 0));
	want_out("ustack-raw", "%-2k", &b, "\n  0x401000\n  0x402000\n");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_USTACK, ust0, sizeof (ust0), 8,
	    DTRACE_USTACK_ARG(0, 0));
	want_out("ustack-empty", "[%k]", &b, "[]");
	/* jstack() records print like ustack() ones. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_JSTACK, ust, sizeof (ust), 8,
	    DTRACE_USTACK_ARG(3, 0));
	want_out("jstack-raw", "%-1k", &b, "\n 0x401000\n 0x402000\n");
}

/* ------------------------------------------------------------------ */
/* Times, ports and addresses (resolver stand-ins).                    */

static void
case_times(void)
{
	/* 2024-12-31 00:00:00 UTC: a Tuesday in ISO week-year 2025. */
	uint64_t t1 = 1735603200ULL * 1000000000ULL;
	/* 2021-01-01 12:34:56 UTC: a Friday in ISO week-year 2020. */
	uint64_t t2 = 1609504496ULL * 1000000000ULL + 999;
	uint64_t t0 = 0;
	struct rb b;

	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &t0, 8, 0, 0);
	want_out("time-Y-epoch", "%Y", &b, "1970 Jan  1 00:00:00");
	want_out("time-T-epoch", "%T", &b, "Thu, 01 Jan 1970 00:00:00 UTC");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &t1, 8, 0, 0);
	want_out("time-Y-year-end", "%Y", &b, "2024 Dec 31 00:00:00");
	want_out("time-T-calendar-year", "%T", &b,
	    "Tue, 31 Dec 2024 00:00:00 UTC");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &t2, 8, 0, 0);
	want_out("time-Y-year-start", "[%22Y]", &b,
	    "[  2021 Jan  1 12:34:56]");
	want_out("time-T-year-start", "%T", &b,
	    "Fri, 01 Jan 2021 12:34:56 UTC");
}

static unsigned *shim_serv, *shim_host, *shim_node, *shim_frees;
static int *shim_serv_erange, *shim_host_erange;

static void
case_resolvers(void)
{
	uint16_t ssh = 22, other = 65001;
	struct rb b;
	unsigned before;

	if (shim_serv == NULL) {
		fail("resolver-shim", "dlsym", "preloaded shim", "absent");
		return;
	}
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &ssh, 2, 0, 0);
	want_out("port-service-name", "%P", &b, "ssh");
	*shim_serv_erange = 1;
	want_out("port-resolver-error", "%P", &b, "22");
	*shim_serv_erange = 0;
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &other, 2, 0, 0);
	want_out("port-unknown", "[%6P]", &b, "[ 65001]");

	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, "192.0.2.7\0\0\0\0\0\0", 16, 1, 0);
	want_out("inet4-host-name", "%I", &b, "host-a.example");
	*shim_host_erange = 1;
	want_out("inet4-resolver-error", "%I", &b, "192.0.2.7");
	*shim_host_erange = 0;
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, "192.0.2.8\0\0\0\0\0\0", 16, 1, 0);
	want_out("inet4-unknown", "%I", &b, "192.0.2.8");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, "2001:db8::7\0\0\0\0\0", 16, 1, 0);
	before = *shim_frees;
	want_out("inet6-host-name", "%I", &b, "host-b.example");
	if (*shim_frees != before + 1)
		fail("inet6-hostent-released", "freehostent", "1 call",
		    "missing\n");
	else
		pass("inet6-hostent-released");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, "2001:db8::8\0\0\0\0\0", 16, 1, 0);
	want_out("inet6-unknown", "%I", &b, "2001:db8::8");
	/* Text that is not an address is printed without any lookup. */
	before = *shim_host + *shim_node;
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, "not-an-address\0\0", 16, 1, 0);
	want_out("inet-not-an-address", "%I", &b, "not-an-address");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, "zz:yy\0\0\0", 8, 1, 0);
	want_out("inet6-not-an-address", "%I", &b, "zz:yy");
	if (*shim_host + *shim_node != before)
		fail("inet-no-lookup-for-text", "resolver calls", "0",
		    "lookups made for non-address text\n");
	else
		pass("inet-no-lookup-for-text");
}

/* ------------------------------------------------------------------ */
/* Dynamic width/precision records and record errors.                  */

static void
case_dynamic_records(void)
{
	int8_t w1 = 6;
	int16_t w2 = -6;
	int64_t w8 = 4, p8 = 2;
	int32_t v = 7;
	struct rb b;

	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &w1, 1, 0, 0);
	rb_put(&b, DTRACEACT_DIFEXPR, &v, 4, 0, 0);
	want_out("dyn-width-int8", "[%*i]", &b, "[     7]");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &w2, 2, 0, 0);
	rb_put(&b, DTRACEACT_DIFEXPR, &v, 4, 0, 0);
	want_out("dyn-width-int16-negative", "[%*i]", &b, "[7     ]");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &w8, 8, 0, 0);
	rb_put(&b, DTRACEACT_DIFEXPR, &p8, 8, 0, 0);
	rb_put(&b, DTRACEACT_DIFEXPR, "abcdef", 6, 1, 0);
	want_out("dyn-width-precision-int64", "[%*.*s]", &b, "[  ab]");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, "abc", 3, 1, 0);
	rb_put(&b, DTRACEACT_DIFEXPR, &v, 4, 0, 0);
	want_err("dyn-width-size-3", "%*i", &b, EDT_DMISMATCH);
	rb_reset(&b);
	want_err("dyn-width-no-record", "%*i", &b, EDT_DMISMATCH);
	want_err("dyn-precision-no-record", "%.*i", &b, EDT_DMISMATCH);
	want_err("value-no-record", "%i", &b, EDT_DMISMATCH);
	/* The width record lies past the data. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &v, 4, 0, 0);
	b.rec[0].dtrd_offset = 4000;
	b.len = 8;
	want_err("dyn-width-offset", "%*i", &b, EDT_DOFFSET);
	/* A misaligned width record. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, NULL, 8, 1, 0);
	b.rec[0].dtrd_offset = 1;
	b.rec[0].dtrd_size = 4;
	b.rec[0].dtrd_alignment = 4;
	want_err("dyn-width-misaligned", "%*i", &b, EDT_DALIGN);
	/* The value record extends past the data. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &v, 4, 0, 0);
	b.len = 2;
	want_err("value-offset", "%i", &b, EDT_DOFFSET);
	/* Alignment 0 is not checked. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &v, 4, 0, 0);
	b.rec[0].dtrd_alignment = 0;
	want_out("value-alignment-zero", "%i", &b, "7");
	/* An aggregation conversion outside printa(). */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, &v, 4, 0, 0);
	want_err("agg-conversion-without-aggregation", "%@i", &b,
	    EDT_DMISMATCH);
	/* A format with only a prefix reports whether records remain. */
	{
		void *pfv = dtrace_printf_create(H, "text");
		int rc;
		FILE *f = fopen("/dev/null", "w");

		rc = dtrace_fprintf(H, f, pfv, NULL, b.rec, 1, b.buf, b.len);
		if (rc != 1)
			fail("prefix-only-with-record", "rc", "1", "other\n");
		else
			pass("prefix-only-with-record");
		rc = dtrace_fprintf(H, f, pfv, NULL, b.rec, 0, b.buf, b.len);
		if (rc != 0)
			fail("prefix-only-no-record", "rc", "0", "other\n");
		else
			pass("prefix-only-no-record");
		dt_printf_destroy(pfv);
		pfv = dtrace_printf_create(H, "");
		rc = dtrace_fprintf(H, f, pfv, NULL, b.rec, 0, b.buf, b.len);
		if (rc != 0)
			fail("empty-format", "rc", "0", "other\n");
		else
			pass("empty-format");
		dt_printf_destroy(pfv);
		fclose(f);
	}
}

/* ------------------------------------------------------------------ */
/* Format parsing, pickling and duplication.                           */

static void
case_parse_errors(void)
{
	static const char *const bad[] = {
		"%**d",		/* two dynamic widths */
		"%.*.*d",	/* two dots */
		"%5.3.1d",	/* two dots */
		"%1$d",		/* positional */
		"%5%",		/* %% with flags */
		"abc%",		/* conversion name missing */
		"%z",		/* undefined */
		"%hhd",		/* undefined (no hh) */
		"%llllllllx",	/* modifier run is capped, then undefined */
	};
	size_t i;

	for (i = 0; i < sizeof (bad) / sizeof (bad[0]); i++) {
		char name[64];

		snprintf(name, sizeof (name), "parse-error-%zu", i);
		if (dtrace_printf_create(H, bad[i]) != NULL ||
		    dtrace_errno(H) != EDT_COMPILER)
			fail(name, bad[i], "EDT_COMPILER", "accepted\n");
		else
			pass(name);
	}
	if (dtrace_printa_create(H, "%z") != NULL)
		fail("printa-create-error", "%z", "NULL", "accepted\n");
	else
		pass("printa-create-error");
}

/*
 * dtrace_printf_format() writes each conversion in the fixed flag order
 * '#', '0', '-', '+', '*', ".*", '\'', ' ', '@', then width and ".prec",
 * then the conversion: its name when the output format is %s, else the
 * derived pfd_fmt (dtrace_printf_create copies the name there).
 */
static void
case_pickle(void)
{
	static const struct { const char *in, *out; } pk[] = {
		{ "plain", "plain" },
		{ "a%db", "a%db" },
		{ "%-#08x", "%#-8x" },	/* '0' is cleared by '-' */
		{ "%0-8x", "%-8x" },
		{ "%-08x", "%-8x" },
		{ "%+ 'd", "%+' d" },
		{ "%*.*s", "%*.*s" },
		{ "%@d %@-10.3llu", "%@d %-@10.3llu" },
		{ "%?p", "%16p" },
		{ "%12.4Y|%k|%a|%S", "%12.4Y|%k|%a|%S" },
		{ "%%x", "%%x" },
		{ "%ls %lc %Lf", "%ls %lc %Lf" },
		{ "%5-3d", "%-3d" },	/* a later width replaces the first */
		{ "%wc %ws", "%lc %ls" },	/* printf(3) spellings */
	};
	size_t i;
	char buf[128];

	for (i = 0; i < sizeof (pk) / sizeof (pk[0]); i++) {
		void *pfv = dtrace_printf_create(H, pk[i].in);
		size_t n;
		char name[64];

		snprintf(name, sizeof (name), "pickle-%zu", i);
		memset(buf, 'X', sizeof (buf));
		n = pfv == NULL ? SIZE_MAX :
		    dtrace_printf_format(H, pfv, buf, sizeof (buf));
		if (n != strlen(pk[i].out) || strcmp(buf, pk[i].out) != 0)
			fail(name, pk[i].in, pk[i].out, pfv ? buf : "(null)");
		else
			pass(name);
		if (pfv != NULL) {
			char small[4], *p;
			dt_pfargv_t *copy;

			/* Truncation still reports the full length. */
			memset(small, 'X', sizeof (small));
			if (dtrace_printf_format(H, pfv, small,
			    sizeof (small)) != strlen(pk[i].out) ||
			    strncmp(small, pk[i].out, MIN(sizeof (small),
			    strlen(pk[i].out))) != 0)
				fail(name, "truncated", pk[i].out,
				    "(unterminated prefix differs)\n");
			if (dtrace_printf_format(H, pfv, NULL, 0) !=
			    strlen(pk[i].out))
				fail(name, "length query", pk[i].out, "");
			/* A copy pickles identically and owns its text. */
			copy = dt_printf_dup(pfv);
			dt_printf_destroy(pfv);
			p = calloc(1, 128);
			if (copy == NULL || dtrace_printf_format(H, copy, p,
			    128) != strlen(pk[i].out) ||
			    strcmp(p, pk[i].out) != 0)
				fail(name, "dup", pk[i].out, p);
			if (copy != NULL)
				dt_printf_destroy(copy);
			free(p);
		}
	}
	if (dtrace_printf_format(H, NULL, buf, sizeof (buf)) != SIZE_MAX ||
	    dtrace_errno(H) != EINVAL)
		fail("pickle-null", "NULL fmtdata", "EINVAL", "");
	else
		pass("pickle-null");
	{
		void *pfv = dtrace_printf_create(H, "%d");

		if (dtrace_printf_format(H, pfv, NULL, 4) != SIZE_MAX ||
		    dtrace_errno(H) != EINVAL)
			fail("pickle-null-buffer", "NULL s", "EINVAL", "");
		else
			pass("pickle-null-buffer");
		dt_printf_destroy(pfv);
	}
	if (dt_printf_dup(NULL) != NULL)
		fail("dup-null", "NULL", "NULL", "copy\n");
	else
		pass("dup-null");
}

/*
 * Malformed format data is rejected rather than read past: dt_pfargv_t is
 * opaque to callers, so each corruption below is written into a real one.
 */
static void
case_pickle_malformed(void)
{
	char buf[64];
	dt_pfargv_t *pfv;
	dt_pfconv_t fake;
	static const char outside[] = "outside";
	dt_pfargv_t *copy;

	pfv = dtrace_printf_create(H, "a%db");
	pfv->pfv_argc++;		/* one descriptor more than listed */
	if (dtrace_printf_format(H, pfv, buf, sizeof (buf)) != SIZE_MAX ||
	    dtrace_errno(H) != EINVAL)
		fail("pickle-short-list", "argc", "EINVAL", "");
	else
		pass("pickle-short-list");
	pfv->pfv_argc--;
	pfv->pfv_argv->pfd_prefix = NULL;	/* "a" without its text */
	if (dtrace_printf_format(H, pfv, buf, sizeof (buf)) != SIZE_MAX ||
	    dtrace_errno(H) != EINVAL)
		fail("pickle-null-prefix", "prefix", "EINVAL", "");
	else
		pass("pickle-null-prefix");
	dt_printf_destroy(pfv);

	pfv = dtrace_printf_create(H, "%d");
	memcpy(&fake, pfv->pfv_argv->pfd_conv, sizeof (fake));
	fake.pfc_ofmt = NULL;
	pfv->pfv_argv->pfd_conv = &fake;
	if (dtrace_printf_format(H, pfv, buf, sizeof (buf)) != SIZE_MAX ||
	    dtrace_errno(H) != EINVAL)
		fail("pickle-null-conversion", "ofmt", "EINVAL", "");
	else
		pass("pickle-null-conversion");
	fake.pfc_ofmt = "d";
	fake.pfc_name = NULL;
	if (dtrace_printf_format(H, pfv, buf, sizeof (buf)) != SIZE_MAX)
		fail("pickle-null-name", "name", "EINVAL", "");
	else
		pass("pickle-null-name");
	pfv->pfv_argv->pfd_conv = dt_pfdict_lookup(H, "d");
	memset(pfv->pfv_argv->pfd_fmt, 'd', sizeof (pfv->pfv_argv->pfd_fmt));
	if (dtrace_printf_format(H, pfv, buf, sizeof (buf)) != SIZE_MAX ||
	    dtrace_errno(H) != EINVAL)
		fail("pickle-unterminated-fmt", "pfd_fmt", "EINVAL", "");
	else
		pass("pickle-unterminated-fmt");
	dt_printf_destroy(pfv);

	/* Prefix lengths that overflow size_t. */
	pfv = dtrace_printf_create(H, "ab%dcd");
	pfv->pfv_argv->pfd_preflen = SIZE_MAX;
	pfv->pfv_argv->pfd_next->pfd_preflen = 2;
	if (dtrace_printf_format(H, pfv, NULL, 0) != SIZE_MAX ||
	    dtrace_errno(H) != EOVERFLOW)
		fail("pickle-overflow", "preflen", "EOVERFLOW", "");
	else
		pass("pickle-overflow");
	/* A prefix that is not inside the format text is copied as is. */
	pfv->pfv_argv->pfd_preflen = 7;
	pfv->pfv_argv->pfd_prefix = outside;
	copy = dt_printf_dup(pfv);
	if (copy == NULL || copy->pfv_argv->pfd_prefix != outside ||
	    copy->pfv_argv->pfd_next->pfd_prefix !=
	    copy->pfv_format + 4)
		fail("dup-foreign-prefix", "prefix pointers",
		    "outside kept; inner relocated", "");
	else
		pass("dup-foreign-prefix");
	/* A prefix that starts inside but runs past the text is not moved. */
	pfv->pfv_argv->pfd_prefix = pfv->pfv_format + 1;
	pfv->pfv_argv->pfd_preflen = 50;
	if (copy != NULL)
		dt_printf_destroy(copy);
	copy = dt_printf_dup(pfv);
	if (copy == NULL ||
	    copy->pfv_argv->pfd_prefix != pfv->pfv_format + 1)
		fail("dup-overlong-prefix", "prefix", "original kept", "");
	else
		pass("dup-overlong-prefix");
	if (copy != NULL)
		dt_printf_destroy(copy);
	/* A prefix that starts before the text is not moved either. */
	{
		uintptr_t before = (uintptr_t)pfv->pfv_format - 1;

		pfv->pfv_argv->pfd_prefix = (const char *)before;
		pfv->pfv_argv->pfd_preflen = 1;
		copy = dt_printf_dup(pfv);
		if (copy == NULL ||
		    (uintptr_t)copy->pfv_argv->pfd_prefix != before)
			fail("dup-prefix-before-text", "prefix", "kept", "");
		else
			pass("dup-prefix-before-text");
		if (copy != NULL)
			dt_printf_destroy(copy);
		/* At the start of the text it is relocated. */
		pfv->pfv_argv->pfd_prefix = pfv->pfv_format;
		copy = dt_printf_dup(pfv);
		if (copy == NULL || copy->pfv_argv->pfd_prefix !=
		    copy->pfv_format)
			fail("dup-prefix-at-start", "prefix", "relocated", "");
		else
			pass("dup-prefix-at-start");
		if (copy != NULL)
			dt_printf_destroy(copy);
	}
	pfv->pfv_argv->pfd_prefix = pfv->pfv_format;
	pfv->pfv_argv->pfd_preflen = 2;
	dt_printf_destroy(pfv);
}

/* ------------------------------------------------------------------ */
/* sprintf, system, freopen.                                           */

static char outdir[1024];

static int liberr_abort;

static int
liberr_cb(const dtrace_errdata_t *d, void *arg)
{
	(void) arg;
	event("liberr: %s", d->dteda_msg);
	return (liberr_abort ? DTRACE_HANDLE_ABORT : DTRACE_HANDLE_OK);
}

static void
case_sprintf_system_freopen(void)
{
	char path[1100], path2[1100], cmd[2400], *text = NULL;
	size_t tlen = 0;
	struct rb b;
	void *pfv, *restore;
	FILE *f, *chk;
	int rc;
	char line[512];
	dtrace_probedata_t pd;
	dtrace_eprobedesc_t epd;
	dtrace_probedesc_t prd;

	memset(&pd, 0, sizeof (pd));
	memset(&epd, 0, sizeof (epd));
	memset(&prd, 0, sizeof (prd));
	pd.dtpda_handle = H;
	pd.dtpda_edesc = &epd;
	pd.dtpda_pdesc = &prd;
	epd.dtepd_epid = 5;
	prd.dtpd_id = 4;
	strlcpy(prd.dtpd_provider, "test", sizeof (prd.dtpd_provider));
	strlcpy(prd.dtpd_mod, "kernel", sizeof (prd.dtpd_mod));
	strlcpy(prd.dtpd_func, "alpha", sizeof (prd.dtpd_func));
	strlcpy(prd.dtpd_name, "entry", sizeof (prd.dtpd_name));
	snprintf(path, sizeof (path), "%s/freopen-a.txt", outdir);
	snprintf(path2, sizeof (path2), "%s/system.txt", outdir);
	unlink(path);
	unlink(path2);

	/* dtrace_sprintf: the result is the handle's sprintf buffer. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, "abc\0", 4, 1, 0);
	pfv = dtrace_printf_create(H, "x=%s;");
	rc = dtrace_sprintf(H, NULL, pfv, b.rec, b.n, b.buf, b.len);
	if (rc != 1 || strcmp(H->dt_sprintf_buf, "x=abc;") != 0)
		fail("sprintf-buffer", "dt_sprintf_buf", "x=abc;",
		    H->dt_sprintf_buf ? H->dt_sprintf_buf : "(null)");
	else
		pass("sprintf-buffer");
	/* A second call replaces the buffer. */
	rc = dtrace_sprintf(H, NULL, pfv, b.rec, b.n, b.buf, b.len);
	if (rc != 1 || strcmp(H->dt_sprintf_buf, "x=abc;") != 0)
		fail("sprintf-again", "dt_sprintf_buf", "x=abc;", "");
	else
		pass("sprintf-again");
	dt_printf_destroy(pfv);
	/* A formatting error frees the buffer and reports the error. */
	pfv = dtrace_printf_create(H, "%d");
	rc = dtrace_sprintf(H, NULL, pfv, b.rec, 0, b.buf, b.len);
	if (rc != -1 || dtrace_errno(H) != EDT_DMISMATCH)
		fail("sprintf-error", "rc", "-1 EDT_DMISMATCH", "");
	else
		pass("sprintf-error");
	/*
	 * Regression: the buffer freed after an error must not be freed again
	 * by the next call (ASan reports the double free).
	 */
	if (H->dt_sprintf_buf != NULL)
		fail("sprintf-error-buffer-released", "dt_sprintf_buf", "NULL",
		    "dangling\n");
	else
		pass("sprintf-error-buffer-released");
	/* dtrace_system shares the error. */
	rc = dtrace_system(H, stdout, pfv, &pd, b.rec, 0, b.buf, b.len);
	if (rc != -1)
		fail("system-format-error", "rc", "-1", "");
	else
		pass("system-format-error");
	dt_printf_destroy(pfv);

	/* dtrace_system runs the formatted command after flushing fp. */
	/* D "%%" is a literal '%': the command is printf '%s' ran > path. */
	snprintf(cmd, sizeof (cmd), "printf '%%%%s' %%s > %s", path2);
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, "ran\0", 4, 1, 0);
	pfv = dtrace_printf_create(H, cmd);
	f = open_memstream(&text, &tlen);
	fprintf(f, "before");
	rc = dtrace_system(H, f, pfv, &pd, b.rec, b.n, b.buf, b.len);
	chk = fopen(path2, "r");
	if (rc != 1 || tlen != 6 || chk == NULL ||
	    fgets(line, sizeof (line), chk) == NULL ||
	    strcmp(line, "ran") != 0)
		fail("system-command", cmd, "ran (fp flushed first)", text);
	else
		pass("system-command");
	if (chk != NULL)
		fclose(chk);
	fclose(f);
	free(text);
	dt_printf_destroy(pfv);

	/*
	 * dtrace_freopen (FreeBSD): output goes to the named file until the
	 * restore form (the "." sentinel the compiler gives freopen("")).
	 */
	reset_model();	/* empties the event log */
	restore = dtrace_printf_create(H, DT_FREOPEN_RESTORE);
	rc = dtrace_freopen(H, stdout, restore, &pd, b.rec, 0, b.buf, b.len);
	if (rc != 0 || H->dt_freopen_fp != NULL)
		fail("freopen-restore-noop", "rc", "0 and no redirection", "");
	else
		pass("freopen-restore-noop");
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, path, strlen(path) + 1, 1, 0);
	pfv = dtrace_printf_create(H, "%s");
	rc = dtrace_freopen(H, stdout, pfv, &pd, b.rec, b.n, b.buf, b.len);
	if (rc != 1 || H->dt_freopen_fp == NULL)
		fail("freopen-open", path, "redirected", "");
	else
		pass("freopen-open");
	{
		struct rb v;
		int32_t n = 41;

		rb_reset(&v);
		rb_put(&v, DTRACEACT_DIFEXPR, &n, 4, 0, 0);
		want_out("freopen-redirects-output", "%i", &v, "");
	}
	/* Reopening the same file replaces the redirection. */
	rc = dtrace_freopen(H, stdout, pfv, &pd, b.rec, b.n, b.buf, b.len);
	if (rc != 1 || H->dt_freopen_fp == NULL)
		fail("freopen-reopen", path, "redirected", "");
	else
		pass("freopen-reopen");
	rc = dtrace_freopen(H, stdout, restore, &pd, b.rec, 0, b.buf, b.len);
	chk = fopen(path, "r");
	if (rc != 0 || H->dt_freopen_fp != NULL || chk == NULL ||
	    fgets(line, sizeof (line), chk) == NULL ||
	    strcmp(line, "41") != 0)
		fail("freopen-restore", path, "41", "");
	else
		pass("freopen-restore");
	if (chk != NULL)
		fclose(chk);
	/* A format with literal text names the file too. */
	{
		void *pf2;
		char fmt[1200], want[1200];
		struct rb v;
		int32_t n = 42;

		snprintf(fmt, sizeof (fmt), "%s/freopen-%%s.txt", outdir);
		snprintf(want, sizeof (want), "%s/freopen-b.txt", outdir);
		unlink(want);
		pf2 = dtrace_printf_create(H, fmt);
		rb_reset(&v);
		rb_put(&v, DTRACEACT_DIFEXPR, "b\0", 2, 1, 0);
		rc = dtrace_freopen(H, stdout, pf2, &pd, v.rec, v.n, v.buf,
		    v.len);
		rb_reset(&v);
		rb_put(&v, DTRACEACT_DIFEXPR, &n, 4, 0, 0);
		want_out("freopen-prefix-redirects", "%i", &v, "");
		(void) dtrace_freopen(H, stdout, restore, &pd, v.rec, 0,
		    v.buf, v.len);
		chk = fopen(want, "r");
		if (rc != 1 || chk == NULL || fgets(line, sizeof (line),
		    chk) == NULL || strcmp(line, "42") != 0)
			fail("freopen-prefix", fmt, "42 in freopen-b.txt", "");
		else
			pass("freopen-prefix");
		if (chk != NULL)
			fclose(chk);
		dt_printf_destroy(pf2);
	}
	/* A NULL stream only formats. */
	rc = dtrace_freopen(H, NULL, pfv, &pd, b.rec, b.n, b.buf, b.len);
	if (rc != 1 || H->dt_freopen_fp != NULL)
		fail("freopen-null-stream", "rc", "1, no redirection", "");
	else
		pass("freopen-null-stream");
	dt_printf_destroy(pfv);
	/* An unopenable file is a library error, not a lost stream. */
	rb_reset(&b);
	rb_put(&b, DTRACEACT_DIFEXPR, "/nonexistent-dir/x\0", 19, 1, 0);
	pfv = dtrace_printf_create(H, "%s");
	/* Without an error handler the error aborts consumption. */
	rc = dtrace_freopen(H, stdout, pfv, &pd, b.rec, b.n, b.buf, b.len);
	if (rc != -1 || dtrace_errno(H) != EDT_ERRABORT)
		fail("freopen-unopenable-no-handler", "rc", "EDT_ERRABORT", "");
	else
		pass("freopen-unopenable-no-handler");
	(void) dtrace_handle_err(H, liberr_cb, NULL);
	rc = dtrace_freopen(H, stdout, pfv, &pd, b.rec, b.n, b.buf, b.len);
	fflush(eventfp);
	snprintf(line, sizeof (line), "liberr: error on enabled probe ID 5 "
	    "(ID 4: test:kernel:alpha:entry): couldn't freopen() "
	    "\"/nonexistent-dir/x\": %s\n", strerror(ENOENT));
	if (rc != 1 || H->dt_freopen_fp != NULL || strcmp(events, line) != 0)
		fail("freopen-unopenable", "liberr", line, events);
	else
		pass("freopen-unopenable");
	liberr_abort = 1;
	rc = dtrace_freopen(H, stdout, pfv, &pd, b.rec, b.n, b.buf, b.len);
	if (rc != -1 || dtrace_errno(H) != EDT_ERRABORT)
		fail("freopen-unopenable-abort", "rc", "EDT_ERRABORT", "");
	else
		pass("freopen-unopenable-abort");
	liberr_abort = 0;
	/* A format error is returned before any open. */
	rc = dtrace_freopen(H, stdout, pfv, &pd, b.rec, 0, b.buf, b.len);
	if (rc != -1)
		fail("freopen-format-error", "rc", "-1", "");
	else
		pass("freopen-format-error");
	dt_printf_destroy(pfv);
	dt_printf_destroy(restore);

	/* Discarded output refuses formatting. */
	H->dt_output_discarded = 1;
	pfv = dtrace_printf_create(H, "x");
	rc = dtrace_sprintf(H, NULL, pfv, b.rec, 0, b.buf, b.len);
	if (rc != -1 || dtrace_errno(H) != ESHUTDOWN)
		fail("sprintf-discarded", "rc", "ESHUTDOWN", "");
	else
		pass("sprintf-discarded");
	H->dt_output_discarded = 0;
	dt_printf_destroy(pfv);
}

/* dtrace_fprinta() with records that cannot name aggregations. */
static void
case_fprinta_records(void)
{
	struct rb b;
	uint32_t id = 1;
	void *pfv = dtrace_printa_create(H, "%@d");
	int rc;

	rb_reset(&b);
	rb_put(&b, DTRACEACT_PRINTA, &id, 4, 0, 0);
	rb_put(&b, DTRACEACT_DIFEXPR, &id, 4, 0, 0);
	b.rec[0].dtrd_uarg = b.rec[1].dtrd_uarg = 9;
	rc = dtrace_fprinta(H, stdout, pfv, NULL, b.rec, b.n, b.buf, b.len);
	if (rc != -1 || dtrace_errno(H) != EDT_BADAGG)
		fail("fprinta-mixed-actions", "rc", "EDT_BADAGG", "");
	else
		pass("fprinta-mixed-actions");
	rc = dtrace_fprinta(H, stdout, pfv, NULL, b.rec, 0, b.buf, b.len);
	if (rc != -1 || dtrace_errno(H) != EDT_BADAGG)
		fail("fprinta-no-records", "rc", "EDT_BADAGG", "");
	else
		pass("fprinta-no-records");
	/*
	 * Two variables of one printa() that the walk cannot join: ID 0 is
	 * DTRACE_AGGVARIDNONE.
	 */
	b.rec[1].dtrd_action = DTRACEACT_PRINTA;
	memset(b.buf, 0, b.len);
	rc = dtrace_fprinta(H, stdout, pfv, NULL, b.rec, b.n, b.buf, b.len);
	if (rc != -1 || dtrace_errno(H) != EDT_BADAGGVAR)
		fail("fprinta-joined-unknown", "rc", "EDT_BADAGGVAR",
		    dtrace_errmsg(H, dtrace_errno(H)));
	else
		pass("fprinta-joined-unknown");
	b.rec[1].dtrd_action = DTRACEACT_DIFEXPR;
	/* One aggregation variable and nothing snapshotted: no output. */
	rc = dtrace_fprinta(H, stdout, pfv, NULL, b.rec, 1, b.buf, b.len);
	if (rc != 1)
		fail("fprinta-empty", "rc", "1", "");
	else
		pass("fprinta-empty");
	dt_printf_destroy(pfv);
}

/* %? is 8 columns in the ILP32 data model. */
static void
case_ilp32_pointer_width(void)
{
	int err;
	dtrace_hdl_t *h32 = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV |
	    DTRACE_O_NOSYS | DTRACE_O_ILP32, &err);
	void *pfv;
	char buf[32];

	if (h32 == NULL) {
		fail("pointer-question-ilp32", "open", "", dtrace_errmsg(NULL,
		    err));
		return;
	}
	pfv = dtrace_printf_create(h32, "%?p");
	if (pfv == NULL || dtrace_printf_format(h32, pfv, buf,
	    sizeof (buf)) != 3 || strcmp(buf, "%8p") != 0)
		fail("pointer-question-ilp32", "%?p", "%8p", buf);
	else
		pass("pointer-question-ilp32");
	if (pfv != NULL)
		dt_printf_destroy(pfv);
	dtrace_close(h32);
}

/*
 * Output errors: dt_printf() fails on a stream that cannot be written, and
 * each piece of the format reports it.
 */
static void
case_output_errors(void)
{
	static const struct { const char *name, *fmt; int nrec; } c[] = {
		{ "write-error-prefix", "abc%i", 1 },
		{ "write-error-conversion", "%i", 1 },
		{ "write-error-percent", "%%", 0 },
	};
	FILE *ro = fopen("/dev/null", "r");
	int32_t v = 1;
	struct rb b;
	size_t i;

	for (i = 0; i < sizeof (c) / sizeof (c[0]); i++) {
		void *pfv = dtrace_printf_create(H, c[i].fmt);
		int rc;

		rb_reset(&b);
		rb_put(&b, DTRACEACT_DIFEXPR, &v, 4, 0, 0);
		rc = dtrace_fprintf(H, ro, pfv, NULL, b.rec, c[i].nrec, b.buf,
		    b.len);
		if (rc != -1 || dtrace_errno(H) != EBADF)
			fail(c[i].name, c[i].fmt, "-1 EBADF", dtrace_errmsg(H,
			    dtrace_errno(H)));
		else
			pass(c[i].name);
		dt_printf_destroy(pfv);
	}
	fclose(ro);
}

/* system() itself failing (no process may be created) is reported. */
static void
case_system_fork_failure(void)
{
	pid_t pid;
	int status;

	fflush(stdout);
	if ((pid = fork()) == 0) {
		struct rlimit rl = { 0, 0 };
		struct rb b;
		void *pfv = dtrace_printf_create(H, "true");
		dtrace_probedata_t pd;
		int rc;

		memset(&pd, 0, sizeof (pd));
		rb_reset(&b);
		(void) setrlimit(RLIMIT_NPROC, &rl);
		rc = dtrace_system(H, stdout, pfv, &pd, b.rec, 0, b.buf, b.len);
		/* exit(), not _exit(): the child's coverage is flushed. */
		exit(rc == -1 && dtrace_errno(H) == EAGAIN ? 0 : 1);
	}
	if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		fail("system-fork-failure", "rc", "-1 EAGAIN", "");
	else
		pass("system-fork-failure");
}

/* ------------------------------------------------------------------ */
/* Compile-time validation.                                            */

static int
compiles(const char *prog, char *msg, size_t msglen)
{
	dtrace_prog_t *p = dtrace_program_strcompile(H, prog,
	    DTRACE_PROBESPEC_NAME, DTRACE_C_ETAGS, 0, NULL);

	if (p == NULL) {
		strlcpy(msg, dtrace_errmsg(H, dtrace_errno(H)), msglen);
		return (0);
	}
	msg[0] = '\0';
	return (1);
}

#define	DECLS	"struct cs { char name[8]; int w[4]; char cc; short sh; " \
	"unsigned short us; long lg; unsigned long ul; long long ll; " \
	"float fl; double db; long double ld; int64_t i64; uint64_t u64; " \
	"int *ip; char cm[2][3]; unsigned long long ull; };\n" \
	"typedef uint64_t my64_t; typedef my64_t my64b_t; typedef int myint_t;\n"
#define	SP	"((struct cs *)arg0)"

static void
v_accept(const char *name, const char *body)
{
	char prog[2048], msg[1024];

	snprintf(prog, sizeof (prog), "test:::entry { %s }", body);
	if (!compiles(prog, msg, sizeof (msg)))
		fail(name, body, "compiles", msg);
	else
		pass(name);
}

static void
v_reject(const char *name, const char *body, const char *tag,
    const char *detail)
{
	char prog[2048], msg[1024];

	snprintf(prog, sizeof (prog), "test:::entry { %s }", body);
	if (compiles(prog, msg, sizeof (msg)))
		fail(name, body, tag, "compiled\n");
	else if (strstr(msg, tag) == NULL ||
	    (detail != NULL && strstr(msg, detail) == NULL))
		fail(name, body, detail ? detail : tag, msg);
	else
		pass(name);
}

static void
case_validation(void)
{
	char msg[1024];

	/* The declarations persist in the handle's C container. */
	(void) compiles(DECLS, msg, sizeof (msg));
	/* Accepted argument types for each kind of check. */
	v_accept("check-addr-pointer", "printf(\"%p\", " SP "->ip);");
	v_accept("check-addr-int", "printf(\"%p\", arg1);");
	v_accept("check-kaddr-symaddr", "@ks[func(arg1)] = count(); "
	    "printa(\"%a %@d\", @ks);");
	v_accept("check-kaddr-int", "printf(\"%a\", arg1);");
	v_accept("check-kaddr-pointer", "printf(\"%a\", " SP "->ip);");
	v_accept("check-uaddr-usymaddr", "@us[ufunc(arg1)] = count(); "
	    "printa(\"%A %@d\", @us);");
	v_accept("check-stack", "@st[stack()] = count(); "
	    "printa(\"%k %@d\", @st);");
	v_accept("check-time", "printf(\"%Y %T\", timestamp, walltimestamp);");
	v_accept("check-str-string", "printf(\"%s %S\", \"a\", \"b\");");
	v_accept("check-str-chararray", "printf(\"%s\", " SP "->name);");
	v_accept("check-wstr", "printf(\"%ls\", " SP "->w);");
	v_accept("check-csi", "printf(\"%c %C\", " SP "->cc, " SP "->sh);");
	v_accept("check-fp", "printf(\"%e %f %g\", " SP "->fl, " SP "->db, "
	    SP "->ld);");
	v_accept("check-fp-long-double", "printf(\"%Lf\", " SP "->ld);");
	v_accept("check-xint", "printf(\"%i %o %u %x\", 1, 2, 3, 4);");
	v_accept("check-dint-signed", "printf(\"%d\", " SP "->sh);");
	v_accept("check-dint-unsigned", "printf(\"%d\", " SP "->us);");
	v_accept("check-type-short", "printf(\"%hd %hu\", " SP "->sh, "
	    SP "->us);");
	v_accept("check-xshort", "printf(\"%hx %hX\", " SP "->sh, " SP "->us);");
	v_accept("check-type-long", "printf(\"%ld %lu\", " SP "->lg, "
	    SP "->ul);");
	v_accept("check-xlong", "printf(\"%lx %lX\", " SP "->lg, " SP "->ul);");
	v_accept("check-xlonglong", "printf(\"%llx\", " SP "->ll);");
	v_accept("check-xlonglong-int64", "printf(\"%llx %llX\", " SP "->i64, "
	    SP "->u64);");
	v_accept("check-xlonglong-typedef", "printf(\"%llx\", (my64b_t)arg0);");
	v_accept("check-port", "printf(\"%P\", (uint16_t)arg0);");
	v_accept("check-inet", "printf(\"%I\", \"127.0.0.1\");");
	v_accept("check-percent", "printf(\"100%%\");");
	v_accept("check-dynamic", "printf(\"%*.*d\", 4, 2, 7);");
	v_accept("check-flags", "printf(\"%#-+ '08.3x\", 1);");
	v_accept("check-agg-printa", "@a = count(); @b = sum(1); "
	    "printa(\"%@u %@d\", @a, @b);");
	v_accept("check-freopen-restore", "freopen(\"\");");
	v_accept("check-system", "system(\"true %d\", 1);");

	/* Rejections, each with its tag and the documented prototype. */
	v_reject("check-addr-string", "printf(\"%p\", \"s\");",
	    "D_PRINTF_ARG_TYPE", "prototype: pointer or integer");
	v_reject("check-kaddr-string", "printf(\"%a\", \"s\");",
	    "D_PRINTF_ARG_TYPE", "prototype: pointer or integer");
	v_reject("check-uaddr-int-no-target", "printf(\"%A\", arg0);",
	    "D_PRINTF_ARG_TYPE", "prototype: pointer or integer (with -p/-c)");
	v_reject("check-stack-int", "@sti[1] = count(); "
	    "printa(\"%k %@d\", @sti);",
	    "D_PRINTF_ARG_TYPE", "prototype: stack");
	v_reject("check-time-int32", "printf(\"%Y\", 1);",
	    "D_PRINTF_ARG_TYPE", "prototype: int64_t");
	v_reject("check-time-string", "printf(\"%T\", \"s\");",
	    "D_PRINTF_ARG_TYPE", "prototype: int64_t");
	v_reject("check-str-int", "printf(\"%s\", 1);",
	    "D_PRINTF_ARG_TYPE", "prototype: char [] or string");
	v_reject("check-str-intarray", "printf(\"%s\", " SP "->w);",
	    "D_PRINTF_ARG_TYPE", "prototype: char [] or string");
	v_reject("check-str-2d-array", "printf(\"%s\", " SP "->cm);",
	    "D_PRINTF_ARG_TYPE", "prototype: char [] or string");
	v_reject("check-wstr-chararray", "printf(\"%ls\", " SP "->name);",
	    "D_PRINTF_ARG_TYPE", "prototype: wchar_t []");
	v_reject("check-wstr-int", "printf(\"%ls\", 1);",
	    "D_PRINTF_ARG_TYPE", "prototype: wchar_t []");
	v_reject("check-wstr-2d", "printf(\"%ls\", " SP "->cm);",
	    "D_PRINTF_ARG_TYPE", "prototype: wchar_t []");
	v_reject("check-csi-long", "printf(\"%c\", " SP "->lg);",
	    "D_PRINTF_ARG_TYPE", "prototype: char, short, or int");
	v_reject("check-fp-int", "printf(\"%f\", 1);",
	    "D_PRINTF_ARG_TYPE", "prototype: float, double, or long double");
	v_reject("check-xint-string", "printf(\"%x\", \"s\");",
	    "D_PRINTF_ARG_TYPE", "prototype: char, short, int, long, or long");
	v_reject("check-dint-string", "printf(\"%d\", \"s\");",
	    "D_PRINTF_ARG_TYPE", "prototype: char, short, int, long, or long");
	v_reject("check-type-short-int", "printf(\"%hd\", 1);",
	    "D_PRINTF_ARG_TYPE", "prototype: short");
	v_reject("check-xshort-int", "printf(\"%hx\", 1);",
	    "D_PRINTF_ARG_TYPE", "prototype: short");
	v_reject("check-xlong-int", "printf(\"%lx\", 1);",
	    "D_PRINTF_ARG_TYPE", "prototype: long");
	v_reject("check-xlonglong-int", "printf(\"%llx\", (myint_t)1);",
	    "D_PRINTF_ARG_TYPE", "prototype: long long");
	v_reject("check-xlonglong-plain-int", "printf(\"%llX\", 1);",
	    "D_PRINTF_ARG_TYPE", "prototype: long long");
	v_reject("check-port-int", "printf(\"%P\", 1);",
	    "D_PRINTF_ARG_TYPE", "prototype: uint16_t");
	v_reject("check-long-double-double", "printf(\"%Lf\", " SP "->db);",
	    "D_PRINTF_ARG_TYPE", "prototype: long double");
	v_reject("check-dyn-missing", "printf(\"%*d\");",
	    "D_PRINTF_DYN_PROTO", "missing a corresponding \"*\" argument");
	v_reject("check-dynprec-missing", "printf(\"%.*d\");",
	    "D_PRINTF_DYN_PROTO", "missing a corresponding \".*\" argument");
	v_reject("check-dyn-type", "printf(\"%.*d\", \"w\", 1);",
	    "D_PRINTF_DYN_TYPE", "conversion: % .* d");
	v_reject("check-agg-in-printf", "printf(\"%@d\", 1);",
	    "D_PRINTF_AGG_CONV", "is not for use with printf( )");
	v_reject("check-arg-missing", "printf(\"%d %d\", 1);",
	    "D_PRINTF_ARG_PROTO", "conversion #2 (%d) is missing");
	v_reject("check-arg-extra", "printf(\"%d\", 1, 2);",
	    "D_PRINTF_ARG_EXTRA", "only 1 arguments required");
	v_reject("check-empty", "printf(\"\");",
	    "D_PRINTF_FMT_EMPTY", "format string is empty");
	v_reject("check-parse-error", "printf(\"%z\", 1);",
	    "", "format conversion #1 is undefined: %z");
	v_reject("check-two-stars", "printf(\"%**d\", 1, 2, 3);",
	    "", "more than one '*' specified for the output width");
	v_reject("check-two-stars-precision", "printf(\"%.**d\", 1, 2, 3);",
	    "", "more than one '*' specified for the output precision");
	v_reject("check-csi-string", "printf(\"%c\", \"s\");",
	    "D_PRINTF_ARG_TYPE", "prototype: char, short, or int");
	v_accept("check-xlonglong-unsigned", "printf(\"%llx\", " SP "->ull);");
	v_reject("check-two-dots", "printf(\"%.1.2d\", 1);",
	    "", "more than one '.'");
	v_reject("check-positional", "printf(\"%1$d\", 1);",
	    "", "unsupported positional format");
	v_reject("check-percent-flags", "printf(\"%-%\");",
	    "", "cannot be combined with other format flags");
	v_reject("check-name-missing", "printf(\"abc%\");",
	    "", "name expected before end of format string");

	/* printa() key signatures must match (fresh aggregations each). */
	v_reject("printa-key-count", "@ka1[1] = count(); @kb1[1, 2] = "
	    "count(); printa(@ka1, @kb1);", "D_PRINTA_AGGKEY",
	    "@ka1 has 1 key, @kb1 has 2 keys");
	v_reject("printa-key-count-plural", "@ka2[1, 2] = count(); "
	    "@kb2[1] = count(); printa(@ka2, @kb2);", "D_PRINTA_AGGKEY",
	    "@ka2 has 2 keys, @kb2 has 1 key");
	v_reject("printa-key-type", "@ka3[1] = count(); @kb3[\"s\"] = "
	    "count(); printa(@ka3, @kb3);", "D_PRINTA_AGGPROTO",
	    "@kb3[ ] key #1 is incompatible with @ka3");
	v_accept("printa-keys-match", "@ka4[1, \"s\"] = count(); "
	    "@kb4[2, \"t\"] = sum(1); printa(@ka4, @kb4);");
}

/* With a nonzero "target" pid, %A also takes integers and pointers. */
static void
case_validation_target(void)
{
	dt_ident_t *idp = dt_idhash_lookup(H->dt_macros, "target");
	uint_t saved;

	if (idp == NULL) {
		fail("check-uaddr-target", "target macro", "present", "");
		return;
	}
	saved = idp->di_id;
	idp->di_id = 4242;
	v_accept("check-uaddr-target-int", "printf(\"%A\", arg0);");
	v_accept("check-uaddr-target-pointer", "printf(\"%A\", " SP "->ip);");
	v_reject("check-uaddr-target-string", "printf(\"%A\", \"s\");",
	    "D_PRINTF_ARG_TYPE", "prototype: pointer or integer (with -p/-c)");
	idp->di_id = saved;
}

/*
 * HyperTrace compilation skips the type checks and size prefixes: the
 * pickled format keeps the conversion as written.
 */
static void
case_validation_hypertrace(void)
{
	dtrace_hdl_t *saved = H;
	dtrace_prog_t *p;
	dtrace_stmtdesc_t *sdp;
	dt_stmt_t *stp;
	char buf[64];
	int err;

	H = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS | DTRACE_O_LP64,
	    &err, &vector, &M);
	if (H == NULL) {
		fail("hypertrace-printf", "open", "", "");
		H = saved;
		return;
	}
	dtrace_enable_hypertrace(H);
	p = dtrace_program_strcompile(H, "test:::entry { printf(\"%d %f "
	    "%s\", arg0, arg1, arg2); }", DTRACE_PROBESPEC_NAME, 0, 0, NULL);
	stp = p != NULL ? dt_list_next(&p->dp_stmts) : NULL;
	sdp = stp != NULL ? stp->ds_desc : NULL;
	if (sdp == NULL || sdp->dtsd_fmtdata == NULL ||
	    dtrace_printf_format(H, sdp->dtsd_fmtdata, buf, sizeof (buf)) ==
	    SIZE_MAX || strcmp(buf, "%d %f %s") != 0)
		fail("hypertrace-printf", "pickled format", "%d %f %s",
		    p == NULL ? dtrace_errmsg(H, dtrace_errno(H)) : buf);
	else
		pass("hypertrace-printf");
	dtrace_close(H);
	H = saved;
}

/* ------------------------------------------------------------------ */
/* Consumption through the model: printa and aggregation values.       */

static void
case_printa_model(void)
{
	const char *name = "printa-grouped";
	static const char *const opts[] = { "quiet", NULL, NULL };
	struct session s;

	reset_model();
	if (open_session(&s, name, opts,
	    "test:::entry { @s[probefunc] = sum(arg1); @c[probefunc] = "
	    "count(); @a[probefunc] = avg(arg1); @d[probefunc] = "
	    "stddev(arg1); } "
	    "test:::return { printa(\"%s:%@d:%@u:%@d:%@d:%@d\\n\", "
	    "@s, @c, @a, @d); }") == 0) {
		/*
		 * Each aggregation tuple begins with the aggregation variable
		 * ID record (1 to 4 in order of first use), then the key.
		 */
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), S("alpha"),
		    AGG(2, 1), N(2), S("alpha"), AGG(0, 1), N(3), S("alpha"),
		    AGG(2, 1), N(4), S("alpha"), AGG(2, 1)));
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), S("alpha"),
		    AGG(6, 1), N(2), S("alpha"), AGG(0, 1), N(3), S("alpha"),
		    AGG(6, 1), N(4), S("alpha"), AGG(6, 1)));
		fire(0, "test:kernel:beta:entry", 0, VALS(N(1), S("beta"),
		    AGG(-5, 1), N(2), S("beta"), AGG(0, 1), N(3), S("beta"),
		    AGG(-5, 1), N(4), S("beta"), AGG(-5, 1)));
		/* printa() records the variable IDs it prints. */
		fire(0, "test:kernel:alpha:return", 0, VALS(N(1), N(2), N(3),
		    N(4)));
		if (dtrace_aggregate_snap(s.dtp) != 0 || consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		/*
		 * alpha: sum 8, count 2, avg 4, stddev of {2,6} = 2.
		 * beta: sum -5, count 1, avg -5, stddev 0.  The fifth %@d
		 * re-converts the last aggregation (stddev).  Sorted by value
		 * of the first aggregation: beta (-5) first.
		 */
		check(name, &s, "beta:-5:1:-5:0:0\nalpha:8:2:4:2:2\n", NULL);
	}
	close_session(&s);
}

/*
 * A joined printa() types each %@ conversion by the aggregation in its
 * position (dt_cc.c, fixed): after a count(), a sum's %@d is still signed.
 * D's %d is signed: -5 is expected.
 */
static void
case_printa_count_first(void)
{
	static const char *const opts[] = { "quiet", NULL, NULL };
	struct session s;

	reset_model();
	if (open_session(&s, "printa-count-first", opts,
	    "test:::entry { @c[probefunc] = count(); @s[probefunc] = "
	    "sum(arg1); } test:::return { printa(\"%s %@d %@d\\n\", @c, "
	    "@s); }") == 0) {
		fire(0, "test:kernel:beta:entry", 0, VALS(N(1), S("beta"),
		    AGG(0, 1), N(2), S("beta"), AGG(-5, 1)));
		fire(0, "test:kernel:alpha:return", 0, VALS(N(1), N(2)));
		if (dtrace_aggregate_snap(s.dtp) != 0 || consume(&s) != 0)
			fail("printa-count-first", "consume", "", "");
		fflush(s.out);
		if (strcmp(s.text, "beta 1 -5\n") == 0)
			pass("printa-count-first");
		else
			fail("printa-count-first", "output", "beta 1 -5\n",
			    s.text);
	}
	close_session(&s);
}

static void
case_printa_single(void)
{
	const char *name = "printa-single-normalized";
	static const char *const opts[] = { "quiet", NULL, NULL };
	struct session s;

	reset_model();
	if (open_session(&s, name, opts,
	    "test:::entry { @s[probefunc] = sum(arg1); @q = quantize(arg1); "
	    "@l = lquantize(arg1, 0, 10, 5); "
	    "@g = llquantize(arg1, 10, 0, 2, 10); } "
	    "test:::return { normalize(@s, 4); printa(\"[%s %@d]\\n\", @s); "
	    "printa(\"<%@d>\", @q); printa(\"{%@d}\", @l); "
	    "printa(\"(%@d)\", @g); }") == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), S("alpha"),
		    AGG(-40, 1), N(2), AGG(3, 1), N(3), AGG(3, 1), N(4),
		    AGG(3, 1)));
		/* normalize(): variable ID and factor; then four printa(). */
		fire(0, "test:kernel:alpha:return", 0, VALS(N(1), N(4), N(1),
		    N(2), N(3), N(4)));
		if (dtrace_aggregate_snap(s.dtp) != 0 || consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		/*
		 * The normalized negative sum divides as a signed value.
		 * Histograms print their bars (dt_print_quantize et al.);
		 * only the first line is compared here.
		 */
		fflush(s.out);
		if (strncmp(s.text, "[alpha -10]\n<", 13) != 0)
			fail(name, "output", "[alpha -10]\\n<...", s.text);
		else if (strstr(s.text, "value  ------------- Distribution"
		    " ------------- count") == NULL)
			fail(name, "histogram", "distribution header", s.text);
		else
			check(name, &s, NULL, NULL);
	}
	close_session(&s);
}

/* printa() and printf() to buffered output (fp == NULL). */
static char *bufd;
static size_t bufdlen;
static FILE *bufdfp;
static int bufd_abort;

static int
buffered_cb(const dtrace_bufdata_t *bd, void *arg)
{
	(void) arg;
	fprintf(bufdfp, "<%s|%#x>", bd->dtbda_buffered, bd->dtbda_flags);
	return (bufd_abort ? DTRACE_HANDLE_ABORT : DTRACE_HANDLE_OK);
}

static void
case_printa_buffered(void)
{
	const char *name = "printa-buffered";
	static const char *const opts[] = { "quiet", NULL, NULL };
	struct session s;
	char want[512];
	int rc;

	reset_model();
	bufdfp = open_memstream(&bufd, &bufdlen);
	if (open_session(&s, name, opts,
	    "test:::entry { @c[probefunc] = count(); } "
	    "test:::return { printa(\"k=%s v=%@u;\", @c); }") == 0) {
		if (dtrace_handle_buffered(s.dtp, buffered_cb, NULL) != 0)
			fail(name, "handler", "", "");
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), S("alpha"),
		    AGG(0, 1)));
		fire(0, "test:kernel:alpha:return", 0, VALS(N(1)));
		rc = dtrace_aggregate_snap(s.dtp) != 0 ? -2 :
		    dtrace_consume(s.dtp, NULL, probe_cb, rec_cb, NULL);
		fflush(bufdfp);
		/*
		 * Each printa() piece is flushed with its role: the prefix
		 * "k=" (AGGFORMAT), the key (AGGKEY), " v=" (AGGFORMAT), the
		 * value (AGGVAL) and the trailing ";" (AGGFORMAT|AGGLAST).
		 */
		snprintf(want, sizeof (want),
		    "<k=|%#x><alpha|%#x>< v=|%#x><1|%#x><;|%#x>",
		    DTRACE_BUFDATA_AGGFORMAT, DTRACE_BUFDATA_AGGKEY,
		    DTRACE_BUFDATA_AGGFORMAT, DTRACE_BUFDATA_AGGVAL,
		    DTRACE_BUFDATA_AGGFORMAT | DTRACE_BUFDATA_AGGLAST);
		if (rc != 0 || bufd == NULL || strstr(bufd, want) == NULL)
			fail(name, "buffered pieces", want, bufd);
		else
			pass(name);
	}
	close_session(&s);

	/* A handler abort stops printa() with EDT_DIRABORT. */
	reset_model();
	bufd_abort = 1;
	fclose(bufdfp);
	free(bufd);
	bufd = NULL;
	bufdfp = open_memstream(&bufd, &bufdlen);
	if (open_session(&s, "printa-buffered-abort", opts,
	    "test:::entry { @c[probefunc] = count(); } "
	    "test:::return { printa(\"k=%s v=%@u\", @c); }") == 0) {
		(void) dtrace_handle_buffered(s.dtp, buffered_cb, NULL);
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), S("alpha"),
		    AGG(0, 1)));
		fire(0, "test:kernel:alpha:return", 0, VALS(N(1)));
		rc = dtrace_aggregate_snap(s.dtp) != 0 ? -2 :
		    dtrace_consume(s.dtp, NULL, probe_cb, rec_cb, NULL);
		if (rc != -1 || dtrace_errno(s.dtp) != EDT_DIRABORT)
			fail("printa-buffered-abort", "rc", "EDT_DIRABORT",
			    dtrace_errmsg(s.dtp, dtrace_errno(s.dtp)));
		else
			pass("printa-buffered-abort");
	}
	close_session(&s);
	bufd_abort = 0;
	fclose(bufdfp);
	free(bufd);
	bufd = NULL;
	bufdfp = NULL;
}

/*
 * A joined printa() stopped by its buffered-output handler: the handler's
 * abort ends the printa() at once (no later tuple is formatted) and is the
 * error reported.
 */
static void
case_printa_joined_abort(void)
{
	static const char *const opts[] = { "quiet", NULL, NULL };
	struct session s;
	char want[64];
	int rc;

	reset_model();
	bufd_abort = 1;
	bufdfp = open_memstream(&bufd, &bufdlen);
	if (open_session(&s, "printa-joined-abort", opts,
	    "test:::entry { @c[probefunc] = count(); @s[probefunc] = "
	    "sum(arg1); } test:::return { printa(\"%s %@d %@d\", @c, @s); }")
	    == 0) {
		(void) dtrace_handle_buffered(s.dtp, buffered_cb, NULL);
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), S("alpha"),
		    AGG(0, 1), N(2), S("alpha"), AGG(3, 1)));
		fire(0, "test:kernel:beta:entry", 0, VALS(N(1), S("beta"),
		    AGG(0, 1), N(2), S("beta"), AGG(4, 1)));
		fire(0, "test:kernel:alpha:return", 0, VALS(N(1), N(2)));
		rc = dtrace_aggregate_snap(s.dtp) != 0 ? -2 :
		    dtrace_consume(s.dtp, NULL, probe_cb, rec_cb, NULL);
		fflush(bufdfp);
		/* One tuple key reached the handler, which aborted. */
		snprintf(want, sizeof (want), "<alpha|%#x>",
		    DTRACE_BUFDATA_AGGKEY);
		if (rc != -1 || dtrace_errno(s.dtp) != EDT_DIRABORT)
			fail("printa-joined-abort", "rc", "EDT_DIRABORT",
			    dtrace_errmsg(s.dtp, dtrace_errno(s.dtp)));
		else if (bufd == NULL || strcmp(bufd, want) != 0)
			fail("printa-joined-abort", "pieces", want, bufd);
		else
			pass("printa-joined-abort");
	}
	close_session(&s);
	bufd_abort = 0;
	fclose(bufdfp);
	free(bufd);
	bufd = NULL;
	bufdfp = NULL;
}

/* printa() whose format has a trailing conversion and no suffix. */
static void
case_printa_value_last(void)
{
	const char *name = "printa-value-last";
	static const char *const opts[] = { "quiet", NULL, NULL };
	struct session s;

	reset_model();
	if (open_session(&s, name, opts,
	    "test:::entry { @c[probefunc, arg1] = count(); } "
	    "test:::return { printa(\"%-6s%3d%@4u\", @c); }") == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), S("alpha"),
		    N(7), AGG(0, 1)));
		fire(0, "test:kernel:alpha:return", 0, VALS(N(1)));
		if (dtrace_aggregate_snap(s.dtp) != 0 || consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		check(name, &s, "alpha   7   1", NULL);
	}
	close_session(&s);
}

/* ------------------------------------------------------------------ */
/* print(): CTF types built with libctf in the "C" container.          */

static ctf_file_t *
cdefs(dtrace_hdl_t *dtp)
{
	return (dtp->dt_cdefs->dm_ctfp);
}

static char *
print_type(dtrace_hdl_t *dtp, const char *tn, const void *data, size_t len,
    int *rc)
{
	char *text = NULL;
	size_t tl = 0;
	FILE *f = open_memstream(&text, &tl);

	*rc = dtrace_print(dtp, f, tn, (caddr_t)data, len);
	fclose(f);
	return (text);
}

static void
want_print(const char *name, ctf_id_t id, const void *data, size_t len,
    const char *want)
{
	char tn[64];
	int rc;
	char *got;

	snprintf(tn, sizeof (tn), "C`%ld", id);
	got = print_type(H, tn, data, len, &rc);
	if (rc != (int)len)
		fail(name, "rc", "record length", got);
	else if (strcmp(got, want) != 0)
		fail(name, tn, want, got);
	else
		pass(name);
	free(got);
}

static ctf_id_t
add_int(ctf_file_t *fp, const char *name, uint_t format, uint_t bits)
{
	ctf_encoding_t e = { format, 0, bits };

	return (ctf_add_integer(fp, CTF_ADD_ROOT, name, &e));
}

static ctf_id_t pt_ints, pt_chars, pt_fp, pt_fptr, pt_bits, pt_struct;
static ctf_id_t pt_nested, pt_arr2, pt_nonstr, pt_str6, pt_union, pt_enum;
static ctf_id_t pt_weird, pt_fwd, pt_fwdarr, pt_badarr, pt_badmem;
static ctf_id_t pt_unknown, pt_fn, pt_unknown15, pt_c16arr, pt_deep;
static ctf_id_t pt_sshort_t, pt_slong_t, pt_sllong_t, pt_badarr_holder;

/* Bit offset of a member, from the CTF itself. */
static ulong_t
moff(ctf_id_t s, const char *m)
{
	ctf_membinfo_t mi;

	if (ctf_member_info(cdefs(H), s, m, &mi) == CTF_ERR) {
		fprintf(stderr, "member %s of %ld: %s\n", m, s,
		    ctf_errmsg(ctf_errno(cdefs(H))));
		abort();
	}
	return (mi.ctm_offset);
}

static ctf_dmdef_t *
member_def(ctf_id_t s, const char *m)
{
	ctf_dtdef_t *dtd = ctf_dtd_lookup(cdefs(H), s);
	ctf_dmdef_t *dmd;

	for (dmd = ctf_list_next(&dtd->dtd_u.dtu_members); dmd != NULL;
	    dmd = ctf_list_next(dmd))
		if (strcmp(dmd->dmd_name, m) == 0)
			return (dmd);
	fprintf(stderr, "no member %s of %ld\n", m, s);
	abort();
}

/*
 * libctf lays members out at byte boundaries; bit-fields are placed here
 * the way a compiler (and ctfconvert) records them.
 */
static void
set_member_bits(ctf_id_t s, const char *m, ulong_t bits)
{
	member_def(s, m)->dmd_offset = bits;
	cdefs(H)->ctf_flags |= LCTF_DIRTY;
}

static void
set_size(ctf_id_t s, size_t size)
{
	ctf_dtd_lookup(cdefs(H), s)->dtd_data.ctt_size = size;
	cdefs(H)->ctf_flags |= LCTF_DIRTY;
}

/*
 * libctf sizes a member from committed types only, so the fixture is built
 * in phases with ctf_update() between them.
 */
static int
build_print_types(void)
{
	ctf_file_t *fp = cdefs(H);
	ctf_id_t i8, i16, i32, i64, u8, u32, chr, odd, big, va, i3, u5, u12;
	ctf_id_t flt, dbl, ldbl, cplx, ip, fn, fnp, inner, carr, arr3, td;
	ctf_id_t list, fwdp, c16, u100, u64, half, d32, l64, ss, sl, sll;
	ctf_id_t anon, unarr, mid;
	ctf_arinfo_t ar;
	ctf_encoding_t fe = { 0, 0, 0 };
	ctf_funcinfo_t fi;

	/* Phase 1: base types. */
	i8 = add_int(fp, "pt_i8", CTF_INT_SIGNED, 8);
	i16 = add_int(fp, "pt_i16", CTF_INT_SIGNED, 16);
	i32 = add_int(fp, "pt_i32", CTF_INT_SIGNED, 32);
	i64 = add_int(fp, "pt_i64", CTF_INT_SIGNED, 64);
	u8 = add_int(fp, "pt_u8", 0, 8);
	u32 = add_int(fp, "pt_u32", 0, 32);
	chr = add_int(fp, "pt_char", CTF_INT_SIGNED | CTF_INT_CHAR, 8);
	odd = add_int(fp, "pt_u24", 0, 24);	/* not a power-of-two size */
	big = add_int(fp, "pt_u128", 0, 128);	/* wider than 64 bits */
	va = add_int(fp, "pt_va", CTF_INT_VARARGS, 32);
	i3 = add_int(fp, "pt_i3", CTF_INT_SIGNED, 3);
	u5 = add_int(fp, "pt_u5", 0, 5);
	u12 = add_int(fp, "pt_u12", 0, 12);
	fe.cte_format = CTF_FP_SINGLE; fe.cte_bits = 32;
	flt = ctf_add_float(fp, CTF_ADD_ROOT, "pt_float", &fe);
	fe.cte_format = CTF_FP_DOUBLE; fe.cte_bits = 64;
	dbl = ctf_add_float(fp, CTF_ADD_ROOT, "pt_double", &fe);
	fe.cte_format = CTF_FP_LDOUBLE; fe.cte_bits = 128;
	ldbl = ctf_add_float(fp, CTF_ADD_ROOT, "pt_ldouble", &fe);
	fe.cte_format = CTF_FP_CPLX; fe.cte_bits = 64;
	cplx = ctf_add_float(fp, CTF_ADD_ROOT, "pt_cplx", &fe);
	pt_enum = ctf_add_enum(fp, CTF_ADD_ROOT, "pt_enum");
	ctf_add_enumerator(fp, pt_enum, "PT_RED", 1);
	ctf_add_enumerator(fp, pt_enum, "PT_BLUE", 2);
	pt_fwd = ctf_add_forward(fp, CTF_ADD_ROOT, "pt_fwd", CTF_K_STRUCT);
	c16 = add_int(fp, "pt_c16", CTF_INT_SIGNED | CTF_INT_CHAR, 16);
	u100 = add_int(fp, "pt_u100", 0, 100);
	u64 = add_int(fp, "pt_u64", 0, 64);
	fe.cte_format = CTF_FP_SINGLE; fe.cte_bits = 16;
	half = ctf_add_float(fp, CTF_ADD_ROOT, "pt_half", &fe);
	fe.cte_format = CTF_FP_DOUBLE; fe.cte_bits = 32;
	d32 = ctf_add_float(fp, CTF_ADD_ROOT, "pt_d32", &fe);
	fe.cte_format = CTF_FP_LDOUBLE; fe.cte_bits = 64;
	l64 = ctf_add_float(fp, CTF_ADD_ROOT, "pt_l64", &fe);
	/* Integer spellings other compilers' CTF uses. */
	ss = add_int(fp, "signed short", CTF_INT_SIGNED, 16);
	sl = add_int(fp, "signed long", CTF_INT_SIGNED, 64);
	sll = add_int(fp, "signed long long", CTF_INT_SIGNED, 64);
	if (ctf_update(fp) == CTF_ERR)
		return (-1);

	/* Phase 2: derived types and aggregate shells. */
	td = ctf_add_typedef(fp, CTF_ADD_ROOT, "pt_td_t", i32);
	ip = ctf_add_pointer(fp, CTF_ADD_ROOT, i32);
	fwdp = ctf_add_pointer(fp, CTF_ADD_ROOT, pt_fwd);
	fi.ctc_return = i32; fi.ctc_argc = 0; fi.ctc_flags = 0;
	fn = pt_fn = ctf_add_function(fp, CTF_ADD_ROOT, &fi, NULL);
	ar.ctr_contents = chr; ar.ctr_index = i32; ar.ctr_nelems = 6;
	carr = pt_str6 = ctf_add_array(fp, CTF_ADD_ROOT, &ar);
	ar.ctr_nelems = 3;
	pt_nonstr = ctf_add_array(fp, CTF_ADD_ROOT, &ar);
	ar.ctr_contents = i32; ar.ctr_nelems = 3;
	arr3 = ctf_add_array(fp, CTF_ADD_ROOT, &ar);
	ar.ctr_contents = pt_fwd; ar.ctr_nelems = 2;
	pt_fwdarr = ctf_add_array(fp, CTF_ADD_ROOT, &ar);
	ar.ctr_contents = i32; ar.ctr_nelems = 2;
	pt_badarr = ctf_add_array(fp, CTF_ADD_ROOT, &ar);
	inner = ctf_add_struct(fp, CTF_ADD_ROOT, "pt_inner");
	pt_union = ctf_add_union(fp, CTF_ADD_ROOT, "pt_union");
	/* Types that become kind CTF_K_UNKNOWN and 15, as in damaged CTF. */
	pt_unknown = ctf_add_struct(fp, CTF_ADD_ROOT, "pt_unknown_s");
	pt_unknown15 = ctf_add_struct(fp, CTF_ADD_ROOT, "pt_unknown15_s");
	pt_sshort_t = ctf_add_typedef(fp, CTF_ADD_ROOT, "pt_sshort_t", ss);
	pt_slong_t = ctf_add_typedef(fp, CTF_ADD_ROOT, "pt_slong_t", sl);
	pt_sllong_t = ctf_add_typedef(fp, CTF_ADD_ROOT, "pt_sllong_t", sll);
	ar.ctr_contents = c16; ar.ctr_nelems = 2;
	pt_c16arr = ctf_add_array(fp, CTF_ADD_ROOT, &ar);
	anon = ctf_add_union(fp, CTF_ADD_ROOT, NULL);
	mid = ctf_add_struct(fp, CTF_ADD_ROOT, "pt_mid");
	pt_deep = ctf_add_struct(fp, CTF_ADD_ROOT, "pt_deep");
	pt_badarr_holder = ctf_add_struct(fp, CTF_ADD_ROOT, "pt_holder");
	if (ctf_update(fp) == CTF_ERR)
		return (-1);
	fnp = ctf_add_pointer(fp, CTF_ADD_ROOT, fn);

	/* Phase 3: members of types used as members. */
	ctf_add_member(fp, inner, "x", i32);
	ctf_add_member(fp, inner, "y", i16);
	ctf_add_member(fp, pt_union, "i", u32);
	ctf_add_member(fp, pt_union, "c", carr);
	ctf_add_member(fp, anon, "ai", i32);
	ctf_add_member(fp, anon, "au", u32);
	ctf_add_member(fp, pt_badarr_holder, "m", pt_badarr);
	ctf_add_member(fp, pt_badarr_holder, "n", i32);
	if (ctf_update(fp) == CTF_ERR)
		return (-1);
	ctf_add_member(fp, mid, "in", inner);
	ar.ctr_contents = pt_union; ar.ctr_nelems = 2;
	unarr = ctf_add_array(fp, CTF_ADD_ROOT, &ar);
	if (ctf_update(fp) == CTF_ERR)
		return (-1);
	ctf_add_member(fp, pt_deep, "m", mid);

	/* Phase 4: arrays of those, and the fixtures. */
	ar.ctr_contents = inner; ar.ctr_nelems = 2;
	list = ctf_add_array(fp, CTF_ADD_ROOT, &ar);
	ar.ctr_contents = arr3; ar.ctr_nelems = 2;
	pt_arr2 = ctf_add_array(fp, CTF_ADD_ROOT, &ar);
	pt_ints = ctf_add_struct(fp, CTF_ADD_ROOT, "pt_ints");
	pt_chars = ctf_add_struct(fp, CTF_ADD_ROOT, "pt_chars");
	pt_fp = ctf_add_struct(fp, CTF_ADD_ROOT, "pt_fp");
	pt_fptr = ctf_add_struct(fp, CTF_ADD_ROOT, "pt_fptr");
	pt_bits = ctf_add_struct(fp, CTF_ADD_ROOT, "pt_bits");
	pt_struct = ctf_add_struct(fp, CTF_ADD_ROOT, "pt_struct");
	pt_nested = ctf_add_struct(fp, CTF_ADD_ROOT, "pt_nested");
	pt_weird = ctf_add_struct(fp, CTF_ADD_ROOT, "pt_weird");
	pt_badmem = ctf_add_struct(fp, CTF_ADD_ROOT, "pt_badmem");
	if (ctf_update(fp) == CTF_ERR)
		return (-1);

	if (ctf_add_member(fp, pt_ints, "a", i8) == CTF_ERR ||
	    ctf_add_member(fp, pt_ints, "b", i16) == CTF_ERR ||
	    ctf_add_member(fp, pt_ints, "c", i32) == CTF_ERR ||
	    ctf_add_member(fp, pt_ints, "d", i64) == CTF_ERR ||
	    ctf_add_member(fp, pt_ints, "e", odd) == CTF_ERR ||
	    ctf_add_member(fp, pt_ints, "f", big) == CTF_ERR ||
	    ctf_add_member(fp, pt_ints, "z", big) == CTF_ERR ||
	    ctf_add_member(fp, pt_ints, "g", va) == CTF_ERR ||
	    ctf_add_member(fp, pt_ints, "t", td) == CTF_ERR ||
	    ctf_add_member(fp, pt_ints, "c16", c16) == CTF_ERR ||
	    ctf_add_member(fp, pt_ints, "small", big) == CTF_ERR ||
	    ctf_add_member(fp, pt_ints, "h100", u100) == CTF_ERR ||
	    ctf_add_member(fp, pt_chars, "p", chr) == CTF_ERR ||
	    ctf_add_member(fp, pt_chars, "z", chr) == CTF_ERR ||
	    ctf_add_member(fp, pt_chars, "np", chr) == CTF_ERR ||
	    ctf_add_member(fp, pt_chars, "u", u8) == CTF_ERR ||
	    ctf_add_member(fp, pt_fp, "f", flt) == CTF_ERR ||
	    ctf_add_member(fp, pt_fp, "d", dbl) == CTF_ERR ||
	    ctf_add_member(fp, pt_fp, "l", ldbl) == CTF_ERR ||
	    ctf_add_member(fp, pt_fp, "c", cplx) == CTF_ERR ||
	    ctf_add_member(fp, pt_fp, "h", half) == CTF_ERR ||
	    ctf_add_member(fp, pt_fp, "d32", d32) == CTF_ERR ||
	    ctf_add_member(fp, pt_fp, "l64", l64) == CTF_ERR ||
	    ctf_add_member(fp, pt_fptr, "dp", ip) == CTF_ERR ||
	    ctf_add_member(fp, pt_fptr, "fp", fnp) == CTF_ERR ||
	    ctf_add_member(fp, pt_fptr, "un", fnp) == CTF_ERR ||
	    ctf_add_member(fp, pt_bits, "lo", i3) == CTF_ERR ||
	    ctf_add_member(fp, pt_bits, "hi", u5) == CTF_ERR ||
	    ctf_add_member(fp, pt_bits, "w", odd) == CTF_ERR ||
	    ctf_add_member(fp, pt_bits, "sh", u8) == CTF_ERR ||
	    ctf_add_member(fp, pt_bits, "sp", u12) == CTF_ERR ||
	    ctf_add_member(fp, pt_bits, "wide", big) == CTF_ERR ||
	    ctf_add_member(fp, pt_bits, "u64", u64) == CTF_ERR ||
	    ctf_add_member(fp, pt_struct, "name", carr) == CTF_ERR ||
	    ctf_add_member(fp, pt_struct, "v", arr3) == CTF_ERR ||
	    ctf_add_member(fp, pt_struct, "p", ip) == CTF_ERR ||
	    ctf_add_member(fp, pt_nested, "in", inner) == CTF_ERR ||
	    ctf_add_member(fp, pt_nested, "after", i32) == CTF_ERR ||
	    ctf_add_member(fp, pt_nested, "list", list) == CTF_ERR ||
	    ctf_add_member(fp, pt_weird, "e", pt_enum) == CTF_ERR ||
	    ctf_add_member(fp, pt_weird, "u", pt_union) == CTF_ERR ||
	    ctf_add_member(fp, pt_weird, "anon", anon) == CTF_ERR ||
	    ctf_add_member(fp, pt_weird, "ua", unarr) == CTF_ERR ||
	    ctf_add_member(fp, pt_weird, "fw", fwdp) == CTF_ERR ||
	    ctf_add_member(fp, pt_badmem, "ok", i32) == CTF_ERR ||
	    ctf_add_member(fp, pt_badmem, "bad", pt_unknown) == CTF_ERR ||
	    ctf_add_member(fp, pt_badmem, "bad2", pt_unknown15) == CTF_ERR) {
		fprintf(stderr, "ctf_add_member: %s\n",
		    ctf_errmsg(ctf_errno(fp)));
		return (-1);
	}
	if (ctf_update(fp) == CTF_ERR)
		return (-1);

	/*
	 * Bit-fields: lo:3 at bit 0, hi:5 at 3, w:24 at 8, sh:8 at 33 (a
	 * byte-sized field off a byte boundary), sp:12 at 46 (spanning three
	 * bytes) and wide:128 at bit 68.
	 */
	set_member_bits(pt_bits, "lo", 0);
	set_member_bits(pt_bits, "hi", 3);
	set_member_bits(pt_bits, "w", 8);
	set_member_bits(pt_bits, "sh", 33);
	set_member_bits(pt_bits, "sp", 46);
	set_member_bits(pt_bits, "wide", 68);
	set_member_bits(pt_bits, "u64", 202);	/* a 64-bit field over 9 bytes */
	set_size(pt_bits, 40);
	/* The bad array element type and the unknown kind. */
	ctf_dtd_lookup(fp, pt_badarr)->dtd_u.dtu_arr.ctr_contents = 0x7ffe;
	ctf_dtd_lookup(fp, pt_unknown)->dtd_data.ctt_info =
	    LCTF_TYPE_INFO(fp, CTF_K_UNKNOWN, 1, 0);
	ctf_dtd_lookup(fp, pt_unknown15)->dtd_data.ctt_info =
	    LCTF_TYPE_INFO(fp, CTF_K_UNKNOWN, 1, 0);
	fp->ctf_flags |= LCTF_DIRTY;
	return (ctf_update(fp) == CTF_ERR ? -1 : 0);
}

static void
case_print_types(void)
{
	ctf_file_t *fp;
	unsigned char raw[128];

	if (build_print_types() != 0) {
		fail("print-types", "ctf_update", "", ctf_errmsg(
		    ctf_errno(cdefs(H))));
		return;
	}
	fp = cdefs(H);

	/*
	 * dt_print_member(): each member on its own line as
	 * "<indent><type> <name> = <value>", 4 columns per depth; integers in
	 * %#x style (zero is "0"), characters quoted, structs opened with "{"
	 * and closed by dt_print_trailing_braces().  A member whose width or
	 * offset is not a whole number of bytes, wider than 8 bytes, or not as
	 * wide as its type, gets " :<bits>".
	 */
	memset(raw, 0, sizeof (raw));
	raw[moff(pt_ints, "a") / 8] = 0xff;
	raw[moff(pt_ints, "b") / 8] = 0x34;
	raw[moff(pt_ints, "b") / 8 + 1] = 0x12;
	{
		uint64_t d = 0x1122334455667788ULL;

		memcpy(raw + moff(pt_ints, "d") / 8, &d, 8);
	}
	raw[moff(pt_ints, "e") / 8] = 0x56;
	raw[moff(pt_ints, "e") / 8 + 1] = 0x34;
	raw[moff(pt_ints, "e") / 8 + 2] = 0x12;
	/* f = 0x0102030405060708090a0b0c0d0e0f00; z = 0 */
	{
		size_t o = moff(pt_ints, "f") / 8, k;

		/* byte of significance k is 16 - k, the lowest 0 */
		for (k = 1; k < 16; k++)
			raw[o + k] = (unsigned char)(16 - k);
		raw[o] = 0;
	}
	raw[moff(pt_ints, "t") / 8] = 9;
	raw[moff(pt_ints, "c16") / 8] = 'A';
	raw[moff(pt_ints, "small") / 8] = 5;
	want_print("print-integers", pt_ints, raw, ctf_type_size(fp, pt_ints),
	    "struct pt_ints {\n"
	    "    pt_i8 a = 0xff\n"
	    "    pt_i16 b = 0x1234\n"
	    "    pt_i32 c = 0\n"
	    "    pt_i64 d = 0x1122334455667788\n"
	    "    pt_u24 e :24 = 0x123456\n"
	    "    pt_u128 f :128 = 0x102030405060708090a0b0c0d0e0f00\n"
	    "    pt_u128 z :128 = 0\n"
	    "    pt_va g = ...\n"
	    "    pt_td_t t = 0x9\n"
	    "    pt_c16 c16 = 0x41\n"
	    "    pt_u128 small :128 = 0x5\n"
	    "    pt_u100 h100 :100 = <unsupported bit-field width 100>\n"
	    "}");

	memset(raw, 0, sizeof (raw));
	raw[0] = 'q'; raw[1] = 0; raw[2] = 7; raw[3] = 9;
	want_print("print-chars", pt_chars, raw, 4,
	    "struct pt_chars {\n"
	    "    pt_char p = 'q'\n"
	    "    pt_char z = '\\0'\n"
	    "    pt_char np = '\\007'\n"
	    "    pt_u8 u = 0x9\n"
	    "}");

	{
		float f = 1.5f;
		double d = -2.25;
		long double l = 3.0L;
		char want[512];

		memset(raw, 0, sizeof (raw));
		memcpy(raw + moff(pt_fp, "f") / 8, &f, 4);
		memcpy(raw + moff(pt_fp, "d") / 8, &d, 8);
		memcpy(raw + moff(pt_fp, "l") / 8, &l, sizeof (l));
		/* dt_print_float(): %+.7e, %+.7e and %+.16LE. */
		snprintf(want, sizeof (want),
		    "struct pt_fp {\n"
		    "    pt_float f = %+.7e\n"
		    "    pt_double d = %+.7e\n"
		    "    pt_ldouble l = %+.16LE\n"
		    "    pt_cplx c = <unknown encoding>\n"
		    "    pt_half h = <unknown encoding>\n"
		    "    pt_d32 d32 = <unknown encoding>\n"
		    "    pt_l64 l64 = <unknown encoding>\n"
		    "}", (double)f, d, l);
		want_print("print-floats", pt_fp, raw, ctf_type_size(fp,
		    pt_fp), want);
	}
	{
		uint64_t p[3] = { 0x1000, KVM_FAULT, 0x1234 };

		want_print("print-pointers", pt_fptr, p, sizeof (p),
		    "struct pt_fptr {\n"
		    "    pt_i32 *dp = 0x1000\n"
		    "    pt_i32 (*)() fp = kernel`vm_fault\n"
		    "    pt_i32 (*)() un = 0x1234\n"
		    "}");
	}
	{
		/* Values placed at the bit offsets set above. */
		uint64_t lo64 = 0, hi64 = 0;

		lo64 |= 0x5ULL;			/* lo */
		lo64 |= 0x15ULL << 3;		/* hi */
		lo64 |= 0xabcdefULL << 8;	/* w */
		lo64 |= 0x7fULL << 33;		/* sh */
		lo64 |= 0xa5cULL << 46;		/* sp */
		hi64 |= 0xfULL << 4;		/* wide: nonzero */
		memset(raw, 0, sizeof (raw));
		memcpy(raw, &lo64, 8);
		memcpy(raw + 8, &hi64, 8);
		/* u64 = 0x0123456789abcdef at bit 202 = byte 25, bit 2. */
		{
			unsigned __int128 w = (unsigned __int128)
			    0x0123456789abcdefULL << 2;

			memcpy(raw + 25, &w, 9);
		}
		want_print("print-bitfields", pt_bits, raw, 40,
		    "struct pt_bits {\n"
		    "    pt_i3 lo :3 = 0x5\n"
		    "    pt_u5 hi :5 = 0x15\n"
		    "    pt_u24 w :24 = 0xabcdef\n"
		    "    pt_u8 sh :8 = 0x7f\n"
		    "    pt_u12 sp :12 = 0xa5c\n"
		    "    pt_u128 wide :128 = <unsupported bit-field width 128>\n"
		    "    pt_u64 u64 :64 = 0x123456789abcdef\n"
		    "}");
	}
	{
		int32_t v3[3] = { 1, 2, 0x30 };

		memset(raw, 0, sizeof (raw));
		memcpy(raw + moff(pt_struct, "name") / 8, "abc", 4);
		memcpy(raw + moff(pt_struct, "v") / 8, v3, sizeof (v3));
		want_print("print-arrays", pt_struct, raw, ctf_type_size(fp,
		    pt_struct),
		    "struct pt_struct {\n"
		    "    pt_char [6] name = [ \"abc\" ]\n"
		    "    pt_i32 [3] v = [ 0x1, 0x2, 0x30 ]\n"
		    "    pt_i32 *p = 0\n"
		    "}");
	}
	{
		ulong_t in = moff(pt_nested, "in") / 8;
		ulong_t list = moff(pt_nested, "list") / 8;
		ctf_id_t inner = ctf_lookup_by_name(fp, "struct pt_inner");
		size_t isz = ctf_type_size(fp, inner);
		ulong_t x = moff(inner, "x") / 8, y = moff(inner, "y") / 8;
		int32_t i32;
		int16_t i16;

		memset(raw, 0, sizeof (raw));
		i32 = 1; memcpy(raw + in + x, &i32, 4);
		i16 = 2; memcpy(raw + in + y, &i16, 2);
		i32 = 3; memcpy(raw + moff(pt_nested, "after") / 8, &i32, 4);
		i32 = 4; memcpy(raw + list + x, &i32, 4);
		i16 = 5; memcpy(raw + list + y, &i16, 2);
		i32 = 6; memcpy(raw + list + isz + x, &i32, 4);
		i16 = 7; memcpy(raw + list + isz + y, &i16, 2);
		want_print("print-nested", pt_nested, raw, ctf_type_size(fp,
		    pt_nested),
		    "struct pt_nested {\n"
		    "    struct pt_inner in = {\n"
		    "        pt_i32 x = 0x1\n"
		    "        pt_i16 y = 0x2\n"
		    "    }\n"
		    "    pt_i32 after = 0x3\n"
		    "    struct pt_inner [2] list = [ \n"
		    "        struct pt_inner {\n"
		    "            pt_i32 x = 0x4\n"
		    "            pt_i16 y = 0x5\n"
		    "        }, \n"
		    "        struct pt_inner {\n"
		    "            pt_i32 x = 0x6\n"
		    "            pt_i16 y = 0x7\n"
		    "        }\n"
		    "    ]\n"
		    "}");
	}
	{
		int32_t a[6] = { 1, 2, 3, 4, 5, 6 };

		want_print("print-2d-array", pt_arr2, a, sizeof (a),
		    "pt_i32 [2][3] [ [ 0x1, 0x2, 0x3 ], [ 0x4, 0x5, 0x6 ] ]\n");
	}
	{
		/* Wide "characters" are not characters (8 bits only). */
		uint16_t c2[2] = { 'h', 'i' };
		ctf_id_t inner = ctf_lookup_by_name(fp, "struct pt_inner");
		int32_t x = 1;
		int16_t y = 2;

		want_print("print-wide-char-array", pt_c16arr, c2, 4,
		    "pt_c16 [2] [ 0x68, 0x69 ]\n");
		/* Two structures end together: both braces close. */
		memset(raw, 0, sizeof (raw));
		memcpy(raw + moff(inner, "x") / 8, &x, 4);
		memcpy(raw + moff(inner, "y") / 8, &y, 2);
		want_print("print-deep-close", pt_deep, raw, ctf_type_size(fp,
		    pt_deep),
		    "struct pt_deep {\n"
		    "    struct pt_mid m = {\n"
		    "        struct pt_inner in = {\n"
		    "            pt_i32 x = 0x1\n"
		    "            pt_i16 y = 0x2\n"
		    "        }\n"
		    "    }\n"
		    "}");
	}
	{
		unsigned char ns[3] = { 'a', 1, 'b' };
		unsigned char full[3] = { 'x', 'y', 'z' };
		unsigned char hi[6] = { 'h', 'i', 0, 'j', 0, 0 };

		want_print("print-char-array-nonstring", pt_nonstr, ns, 3,
		    "pt_char [3] [ 'a', '\\001', 'b' ]\n");
		want_print("print-char-array-unterminated", pt_nonstr, full, 3,
		    "pt_char [3] [ 'x', 'y', 'z' ]\n");
		/* A top-level string drops the brackets (print("foo")). */
		want_print("print-toplevel-string", pt_str6, hi, 6,
		    "pt_char [6] \"hi\"\n");
	}
	{
		uint32_t one = 1;

		memset(raw, 0, sizeof (raw));
		memcpy(raw + moff(pt_weird, "e") / 8, &one, 4);
		memcpy(raw + moff(pt_weird, "u") / 8, "AB", 3);
		want_print("print-enum-union-forward", pt_weird, raw,
		    ctf_type_size(fp, pt_weird),
		    "struct pt_weird {\n"
		    "    enum pt_enum e = PT_RED\n"
		    "    union pt_union u = {\n"
		    "        pt_u32 i = 0x4241\n"
		    "        pt_char [6] c = [ \"AB\" ]\n"
		    "    }\n"
		    /* An anonymous union is named "union ": no extra space. */
		    "    union anon = {\n"
		    "        pt_i32 ai = 0\n"
		    "        pt_u32 au = 0\n"
		    "    }\n"
		    "    union pt_union [2] ua = [ \n"
		    "        union pt_union {\n"
		    "            pt_u32 i = 0\n"
		    "            pt_char [6] c = [ \"\" ]\n"
		    "        }, \n"
		    "        union pt_union {\n"
		    "            pt_u32 i = 0\n"
		    "            pt_char [6] c = [ \"\" ]\n"
		    "        }\n"
		    "    ]\n"
		    "    struct pt_fwd *fw = 0\n"
		    "}");
	}
	{
		uint32_t v = 7;
		uint64_t z[2] = { 0, 0 };
		char want[128];

		want_print("print-enum-unnamed", pt_enum, &v, 4,
		    "enum pt_enum 7\n");
		/* A function type has no size: dt_print_hex() says so. */
		want_print("print-function-type", pt_fn, z, 8,
		    "pt_i32 () <invalid size 0>\n");
		want_print("print-forward", pt_fwd, z, 8,
		    "struct pt_fwd <forward decl>\n");
		want_print("print-forward-array", pt_fwdarr, z, 8,
		    "struct pt_fwd [2] [ <forward decl>, <forward decl> ]\n");
		/*
		 * The damaged element type also defeats ctf_type_name(), so
		 * the type is named "<id>" (dt_print_type_name()).
		 */
		{
			char tn[32], nm[64], *got;
			int rc;

			if (ctf_type_name(fp, pt_badarr, nm, sizeof (nm)) ==
			    NULL)
				snprintf(nm, sizeof (nm), "<%ld>", pt_badarr);
			snprintf(tn, sizeof (tn), "C`%ld", pt_badarr);
			got = print_type(H, tn, z, 8, &rc);
			snprintf(want, sizeof (want),
			    "%s <invalid type %lu>\n", nm, 0x7ffeUL);
			if (rc != 8 || strcmp(got, want) != 0)
				fail("print-invalid-element", tn, want, got);
			else
				pass("print-invalid-element");
			free(got);
		}
		{
			char tn[32], *got;
			int rc;

			memset(raw, 0, sizeof (raw));
			raw[0] = 3;
			snprintf(tn, sizeof (tn), "C`%ld", pt_badmem);
			got = print_type(H, tn, raw, 8, &rc);
			snprintf(want, sizeof (want),
			    "struct pt_badmem {\n    pt_i32 ok = 0x3\n"
			    "    bad = <invalid type %ld>"
			    "    bad2 = <invalid type %ld>}", pt_unknown,
			    pt_unknown15);
			if (rc != 8 || strcmp(got, want) != 0)
				fail("print-invalid-member", tn, want, got);
			else
				pass("print-invalid-member");
			free(got);
		}
	}
}

/* A top-level type of unknown kind: the invalid-type line, unnamed. */
static void
case_print_unknown(void)
{
	char tn[32], want[64], *got;
	uint64_t z = 0;
	int rc;

	snprintf(tn, sizeof (tn), "C`%ld", pt_unknown);
	snprintf(want, sizeof (want), " = <invalid type %ld>", pt_unknown);
	got = print_type(H, tn, &z, 8, &rc);
	if (rc != 8 || strcmp(got, want) != 0)
		fail("print-unknown-kind", tn, want, got);
	else
		pass("print-unknown-kind");
	free(got);
}

/*
 * A process module (dm_pid != 0) names one of its libraries' containers:
 * "module`lib`id".  Library indexes outside dm_libctfp fall back to trace().
 */
static void
case_print_pid_module(void)
{
	dt_module_t *dmp = dt_module_create(H, "pt_pidmod");
	ctf_file_t *libs[1];
	char tn[64], *got;
	int rc;
	int32_t v = 0x2a;
	static const char *const bad[] = { "pt_pidmod`1`%ld",
	    "pt_pidmod`-1`%ld", "pt_pidmod`0" };
	size_t i;

	if (dmp == NULL) {
		fail("print-pid-module", "dt_module_create", "", "");
		return;
	}
	libs[0] = cdefs(H);
	dmp->dm_pid = 4242;
	dmp->dm_nctflibs = 1;
	dmp->dm_libctfp = libs;
	snprintf(tn, sizeof (tn), "pt_pidmod`0`%ld",
	    ctf_lookup_by_name(cdefs(H), "pt_i32"));
	got = print_type(H, tn, &v, 4, &rc);
	if (rc != 4 || strcmp(got, "pt_i32 0x2a\n") != 0)
		fail("print-pid-module", tn, "pt_i32 0x2a\n", got);
	else
		pass("print-pid-module");
	free(got);
	for (i = 0; i < sizeof (bad) / sizeof (bad[0]); i++) {
		char nm[64];

		snprintf(tn, sizeof (tn), bad[i],
		    ctf_lookup_by_name(cdefs(H), "pt_i32"));
		snprintf(nm, sizeof (nm), "print-pid-module-bad-%zu", i);
		got = print_type(H, tn, &v, 4, &rc);
		if (rc != 0 || got[0] != '\0')
			fail(nm, tn, "0, no output", got);
		else
			pass(nm);
		free(got);
	}
	dmp->dm_pid = 0;
	dmp->dm_nctflibs = 0;
	dmp->dm_libctfp = NULL;
}


/*
 * Structured print(): dtrace_format_print() emits one "type" instance per
 * visited member (ctf_type_visit order) with object-name (first instance
 * only), member-name, name, ctfid and the value; the driver checks the
 * JSON written here against the CTF layout.
 */
static void
case_format_print_direct(void)
{
	static const struct { const char *name; ctf_id_t *id; } t[] = {
		{ "ints", &pt_ints }, { "chars", &pt_chars }, { "fp", &pt_fp },
		{ "fptr", &pt_fptr }, { "bits", &pt_bits },
		{ "struct", &pt_struct }, { "nested", &pt_nested },
		{ "arr2", &pt_arr2 }, { "nonstr", &pt_nonstr },
		{ "str6", &pt_str6 }, { "weird", &pt_weird },
		{ "enum", &pt_enum }, { "fwd", &pt_fwd },
		{ "fwdarr", &pt_fwdarr }, { "badarr", &pt_badarr },
		{ "badmem", &pt_badmem }, { "unknown", &pt_unknown },
	};
	unsigned char raw[128];
	FILE *json;
	size_t i;
	int bad = 0;

	if (pt_ints == 0)
		return;
	memset(raw, 0, sizeof (raw));
	for (i = 0; i < sizeof (raw); i++)
		raw[i] = (unsigned char)(i * 7 + 1);
	memcpy(raw, "hi\0", 3);	/* the str6 fixture: "hi" */
	json = fopen("format-print.json", "w");
	assert(json != NULL);
	xo_set_style(NULL, XO_STYLE_JSON);
	dtrace_set_outfp(json);
	(void) dtrace_oformat_configure(H);
	xo_open_container("format-print");
	xo_open_list("cases");
	for (i = 0; i < sizeof (t) / sizeof (t[0]); i++) {
		char tn[32];
		int rc;

		xo_open_instance("cases");
		xo_emit("{:case/%s}{:ctfid/%ld}", t[i].name, *t[i].id);
		snprintf(tn, sizeof (tn), "C`%ld", *t[i].id);
		rc = dtrace_format_print(H, json, tn, (caddr_t)raw, 64);
		if (rc != 64) {
			fprintf(stderr, "format-print %s rc %d\n", t[i].name,
			    rc);
			bad++;
		}
		xo_close_instance("cases");
	}
	xo_close_list("cases");
	xo_close_container("format-print");
	xo_finish();
	/* A fresh default handle for the next structured case. */
	xo_destroy(NULL);
	xo_set_style(NULL, XO_STYLE_TEXT);
	dtrace_set_outfp(stdout);
	(void) dtrace_oformat_configure(H);
	fclose(json);
	/* Raw bytes and member layout (from the CTF) for the driver. */
	json = fopen("format-print.raw", "w");
	fwrite(raw, 1, sizeof (raw), json);
	fclose(json);
	json = fopen("format-print-layout.json", "w");
	fprintf(json, "{");
	for (i = 0; i < sizeof (t) / sizeof (t[0]); i++) {
		static const char *const mem[][14] = {
			{ "ints", "a", "b", "c", "d", "e", "f", "z", "t", "c16",
			    "small", "h100", NULL },
			{ "chars", "p", "z", "np", "u", NULL },
			{ "fp", "f", "d", "l", "c", NULL },
			{ "struct", "name", "v", "p", NULL },
			{ "bits", "lo", "hi", "w", "sh", "sp", "wide", NULL },
			{ "badmem", "ok", "bad", NULL },
		};
		size_t m, k;

		for (m = 0; m < sizeof (mem) / sizeof (mem[0]); m++) {
			if (strcmp(mem[m][0], t[i].name) != 0)
				continue;
			fprintf(json, "%s\"%s\": {", i ? ", " : "", t[i].name);
			for (k = 1; mem[m][k] != NULL; k++)
				fprintf(json, "%s\"%s\": %lu", k > 1 ? ", " : "",
				    mem[m][k], moff(*t[i].id, mem[m][k]));
			fprintf(json, "}");
		}
	}
	fprintf(json, "%s\"unknown_id\": %ld, \"badarr_id\": %ld}\n",
	    ", ", pt_unknown, pt_badarr);
	fclose(json);
	if (bad)
		fail("format-print-direct", "rc", "64 for every type", "");
	else
		pass("format-print-direct");
}

/* A module without CTF falls back to trace() (dt_module_getctf() fails). */
static void
case_print_no_ctf(void)
{
	dt_module_t *dmp = dt_module_create(H, "pt_noctf");
	int32_t v = 1;
	char *got;
	int rc;

	if (dmp == NULL) {
		fail("print-module-without-ctf", "create", "", "");
		return;
	}
	/* Loaded, with no CTF data and no file: nothing is opened. */
	dmp->dm_flags |= DT_DM_LOADED;
	got = print_type(H, "pt_noctf`1", &v, 4, &rc);
	if (rc != 0 || got[0] != '\0')
		fail("print-module-without-ctf", "pt_noctf`1", "0", got);
	else
		pass("print-module-without-ctf");
	free(got);
}

/*
 * printf() type checks against CTF other compilers produce: the "signed"
 * spellings of short, long and long long, and an array whose element type
 * cannot be resolved (damaged CTF), which no string or name check accepts.
 */
static void
case_validation_ctf(void)
{
	char prog[512];

	if (pt_sshort_t == 0)
		return;
	v_accept("check-xshort-signed-spelling",
	    "printf(\"%hx\", (pt_sshort_t)arg0);");
	v_accept("check-xlong-signed-spelling",
	    "printf(\"%lx\", (pt_slong_t)arg0);");
	v_accept("check-xlonglong-signed-spelling",
	    "printf(\"%llx\", (pt_sllong_t)arg0);");
	snprintf(prog, sizeof (prog), "printf(\"%%s\", "
	    "((struct pt_holder *)arg0)->m);");
	v_reject("check-str-damaged-array", prog, "D_PRINTF_ARG_TYPE",
	    "prototype: char [] or string");
	snprintf(prog, sizeof (prog), "printf(\"%%ls\", "
	    "((struct pt_holder *)arg0)->m);");
	v_reject("check-wstr-damaged-array", prog, "D_PRINTF_ARG_TYPE",
	    "prototype: wchar_t []");
	snprintf(prog, sizeof (prog), "printf(\"%%hx\", "
	    "((struct pt_holder *)arg0)->m);");
	v_reject("check-xshort-unnamed", prog, "D_PRINTF_ARG_TYPE",
	    "prototype: short");
	snprintf(prog, sizeof (prog), "printf(\"%%lx\", "
	    "((struct pt_holder *)arg0)->m);");
	v_reject("check-xlong-unnamed", prog, "D_PRINTF_ARG_TYPE",
	    "prototype: long");
	snprintf(prog, sizeof (prog), "printf(\"%%llx\", "
	    "((struct pt_holder *)arg0)->m);");
	v_reject("check-xlonglong-unnamed", prog, "D_PRINTF_ARG_TYPE",
	    "prototype: long long");
}

/*
 * Type names that dt_print_prepare() cannot resolve fall back to trace():
 * dtrace_print() returns 0 without output.
 */
static void
case_print_fallbacks(void)
{
	static const char *const names[] = { "noquote", "nomodule`1", "C`0",
	    "C`999999" };
	unsigned char raw[8] = { 0 };
	size_t i;

	for (i = 0; i < sizeof (names) / sizeof (names[0]); i++) {
		int rc, rc2;
		char *got = print_type(H, names[i], raw, 8, &rc), nm[64];
		FILE *null = fopen("/dev/null", "w");

		rc2 = dtrace_format_print(H, null, names[i], (caddr_t)raw, 8);
		fclose(null);
		snprintf(nm, sizeof (nm), "print-fallback-%zu", i);
		if (rc != 0 || rc2 != 0 || got[0] != '\0')
			fail(nm, names[i], "0 and no output", got);
		else
			pass(nm);
		free(got);
	}
}

/* print() through the model, text and structured output. */
static void
case_print_model(void)
{
	const char *name = "print-model-json";
	static const char *const opts[] = { "quiet", NULL, NULL };
	struct session s;
	FILE *json;
	struct {
		int32_t a;
		char s[6];
		char pad[2];
		int32_t v[2];
		/*
		 * libctf, the D compiler's layout engine, starts each member
		 * on a byte boundary (_ctf_add_member()), bit-fields included.
		 */
		uint8_t lo, hi, pad2[2];
		uint32_t e;
		char np[3];
	} v;

	memset(&v, 0, sizeof (v));
	v.a = -2;
	memcpy(v.s, "json", 5);
	v.v[0] = 3; v.v[1] = 4;
	v.lo = 5; v.hi = 9;
	v.e = 2;
	v.np[0] = 'a'; v.np[1] = 1; v.np[2] = 'b';
	reset_model();
	json = fopen("print-model.json", "w");
	assert(json != NULL);
	xo_set_style(NULL, XO_STYLE_JSON);
	dtrace_set_outfp(json);
	if (open_session(&s, name, opts,
	    "enum pm_e { PM_A = 1, PM_B = 2 }; "
	    "struct pm { int a; char s[6]; int v[2]; unsigned int lo:3; "
	    "unsigned int hi:5; enum pm_e e; char np[3]; }; "
	    "test:::entry { print(*(struct pm *)arg0); }") == 0) {
		if (dtrace_oformat_configure(s.dtp) != 0)
			fail(name, "configure", "", "");
		dtrace_oformat_setup(s.dtp);
		fire(0, "test:kernel:alpha:entry", 0, VALS(B(&v,
		    sizeof (v))));
		if (dtrace_aggregate_snap(s.dtp) != 0 || consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		dtrace_oformat_teardown(s.dtp);
		check(name, &s, "", NULL);
	}
	close_session(&s);
	xo_destroy(NULL);
	xo_set_style(NULL, XO_STYLE_TEXT);
	dtrace_set_outfp(stdout);
	fclose(json);
}

/* ------------------------------------------------------------------ */

/*
 * Regression: print() output follows dt_printf()'s routing like any other
 * record -- to the buffered-output handler when consuming with a NULL
 * stream (it used to write through a NULL FILE), and nowhere once output
 * is discarded.
 */
static void
case_print_buffered(void)
{
	static const char *const opts[] = { "quiet", NULL, NULL };
	struct session s;
	char want[128];
	int rc;

	reset_model();
	bufdfp = open_memstream(&bufd, &bufdlen);
	if (open_session(&s, "print-buffered", opts,
	    "test:::entry { print((int)arg0); }") == 0) {
		(void) dtrace_handle_buffered(s.dtp, buffered_cb, NULL);
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(0x2a)));
		rc = dtrace_consume(s.dtp, NULL, probe_cb, rec_cb, NULL);
		fflush(bufdfp);
		/* The ::print -tn line for a top-level int (dt_print_member). */
		snprintf(want, sizeof (want), "<int 0x2a\n|%#x>", 0);
		if (rc != 0 || bufd == NULL || strstr(bufd, "int 0x2a\n") ==
		    NULL)
			fail("print-buffered", "buffered pieces", want, bufd);
		else
			pass("print-buffered");
	}
	close_session(&s);
	fclose(bufdfp);
	free(bufd);
	bufd = NULL;
	bufdfp = NULL;
	/* Direct call with output discarded: refused, nothing written. */
	if (pt_ints != 0) {
		char tn[32], *got;
		int32_t v = 1;

		snprintf(tn, sizeof (tn), "C`%ld", ctf_lookup_by_name(cdefs(H),
		    "pt_i32"));
		H->dt_output_discarded = 1;
		got = print_type(H, tn, &v, 4, &rc);
		H->dt_output_discarded = 0;
		if (rc != -1 || dtrace_errno(H) != ESHUTDOWN || got[0] != '\0')
			fail("print-discarded", tn, "-1 ESHUTDOWN, no output",
			    got);
		else
			pass("print-discarded");
		free(got);
	}
}

static const struct {
	const char *name;
	void (*fn)(void);
} cases[] = {
	{ "integers", case_integers },
	{ "integer_widths", case_integer_widths },
	{ "chars_pointers", case_chars_pointers },
	{ "floats", case_floats },
	{ "strings", case_strings },
	{ "addresses", case_addresses },
	{ "long_symbol", case_long_symbol },
	{ "stacks", case_stacks },
	{ "times", case_times },
	{ "resolvers", case_resolvers },
	{ "dynamic_records", case_dynamic_records },
	{ "parse_errors", case_parse_errors },
	{ "pickle", case_pickle },
	{ "pickle_malformed", case_pickle_malformed },
	{ "sprintf_system_freopen", case_sprintf_system_freopen },
	{ "fprinta_records", case_fprinta_records },
	{ "ilp32_pointer_width", case_ilp32_pointer_width },
	{ "output_errors", case_output_errors },
	{ "system_fork_failure", case_system_fork_failure },
	{ "validation", case_validation },
	{ "validation_target", case_validation_target },
	{ "validation_hypertrace", case_validation_hypertrace },
	{ "print_types", case_print_types },
	{ "print_fallbacks", case_print_fallbacks },
	{ "print_pid_module", case_print_pid_module },
	{ "print_unknown", case_print_unknown },
	{ "print_no_ctf", case_print_no_ctf },
	{ "validation_ctf", case_validation_ctf },
	{ "format_print_direct", case_format_print_direct },
	{ "printa_model", case_printa_model },
	{ "printa_single", case_printa_single },
	{ "printa_count_first", case_printa_count_first },
	{ "printa_buffered", case_printa_buffered },
	{ "printa_joined_abort", case_printa_joined_abort },
	{ "printa_value_last", case_printa_value_last },
	{ "print_buffered", case_print_buffered },
	{ "print_model", case_print_model },
};

int
main(int argc, char **argv)
{
	size_t i;
	int err;
	void *self = dlopen(NULL, RTLD_NOW);

	if (argc != 2) {
		fprintf(stderr, "usage: printf-conversions outdir\n");
		return (2);
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	strlcpy(outdir, argv[1], sizeof (outdir));
	setenv("TZ", "UTC", 1);
	tzset();
	shim_serv = dlsym(self, "pcs_serv_calls");
	shim_host = dlsym(self, "pcs_host_calls");
	shim_node = dlsym(self, "pcs_node_calls");
	shim_frees = dlsym(self, "pcs_node_frees");
	shim_serv_erange = dlsym(self, "pcs_serv_erange");
	shim_host_erange = dlsym(self, "pcs_host_erange");

	check_phaseup();
	reset_model();
	H = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS | DTRACE_O_LP64,
	    &err, &vector, &M);
	N = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV | DTRACE_O_NOSYS, &err);
	if (H == NULL || N == NULL) {
		printf("FAIL open: %s\n", dtrace_errmsg(NULL, err));
		return (1);
	}
	(void) dtrace_setopt(H, "strsize", "256");

	/*
	 * PC_CASES (comma separated, without "case_") selects groups, e.g. to
	 * show regressions against an older library one group at a time.
	 */
	for (i = 0; i < sizeof (cases) / sizeof (cases[0]); i++) {
		const char *only = getenv("PC_CASES");
		char want[64];

		snprintf(want, sizeof (want), ",%s,", cases[i].name);
		if (only != NULL) {
			char list[1024];

			snprintf(list, sizeof (list), ",%s,", only);
			if (strstr(list, want) == NULL)
				continue;
		}
		cases[i].fn();
	}

	dtrace_close(H);
	dtrace_close(N);
	reset_model();
	printf("%d passed, %d failed\n", passes, failures);
	exit(failures != 0);
}
