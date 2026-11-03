/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * HyperTrace program ELF writer/parser (dt_elf.cc) qualification matrix.
 *
 * Oracles (none of them is an observed output pasted back):
 *  - round trip: a program compiled by the D compiler is written with
 *    dtrace_elf_create() and read back with dtrace_elf_parse(); every
 *    serialized field of the parsed program (statements, ECB probe
 *    descriptions, predicates, actions, DIF objects and their tables,
 *    printf descriptors, aggregation identifiers, enabled probes) must equal
 *    the compiled original.  A second dtrace_elf_create() of the same program
 *    must produce an equally parseable file.  Every manifest written next to a
 *    file is checked again by the Python driver's independent ELF32 decoder
 *    and by llvm-readelf.
 *  - rejection: each malformed input is built by changing one field that a
 *    specific validation rule in dt_elf.cc constrains; the parse must fail
 *    with that rule's error class and message.
 *  - fault injection (elf-fault-shim.so, preloaded): the Nth call of one
 *    libelf/libc/libdtrace allocation or I/O function returns its documented
 *    failure value.  The writer must then report failure (never return
 *    success for an incomplete file) with the message of the failing call,
 *    and neither writer nor parser may leak tracked allocations or crash.
 *
 * NODEV (kernel CTF read from /boot/kernel) or NODEV|NOSYS; no tracing
 * device, no daemon.  Every case that can terminate the process runs in a
 * forked child that ends with exit().
 */

#include <dt_impl.h>
#include <dt_program.h>
#include <dt_printf.h>
#include <dt_elf.h>

#include <sys/elf32.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <dlfcn.h>
#include <openssl/sha.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef SHT_DTRACE_elf
#define	SHT_DTRACE_elf	0x6eeeeee0
#endif

static const char *outdir;
static int failures, checks, tolerated;

#define	CHECK(cond, ...) do {						\
	checks++;							\
	if (!(cond)) {							\
		failures++;						\
		fprintf(stdout, "FAIL %s:%d: ", __func__, __LINE__);	\
		fprintf(stdout, __VA_ARGS__);				\
		fputc('\n', stdout);					\
		fflush(stdout);						\
	}								\
} while (0)

/* Fault-injection controls exported by the preloaded shim. */
static void (*fault_arm)(const char *, long, int);
static int (*fault_disarm)(void);
static void (*fault_track)(int);
static long (*fault_live)(void);
static void (*fault_forget_all)(void);

static void
load_shim(void)
{
	fault_arm = (void (*)(const char *, long, int))dlsym(RTLD_DEFAULT,
	    "fault_arm");
	fault_disarm = (int (*)(void))dlsym(RTLD_DEFAULT, "fault_disarm");
	fault_track = (void (*)(int))dlsym(RTLD_DEFAULT, "fault_track");
	fault_live = (long (*)(void))dlsym(RTLD_DEFAULT, "fault_live");
	fault_forget_all = (void (*)(void))dlsym(RTLD_DEFAULT,
	    "fault_forget_all");
	if (fault_arm == NULL || fault_disarm == NULL || fault_track == NULL ||
	    fault_live == NULL || fault_forget_all == NULL) {
		fprintf(stderr, "elf-fault-shim.so is not preloaded\n");
		exit(2);
	}
}

static dtrace_hdl_t *
open_handle(int nosys)
{
	int err;
	dtrace_hdl_t *h = dtrace_open(DTRACE_VERSION,
	    DTRACE_O_NODEV | (nosys ? DTRACE_O_NOSYS : 0), &err);
	if (h == NULL) {
		fprintf(stderr, "dtrace_open: %s\n", dtrace_errmsg(NULL, err));
		exit(2);
	}
	return (h);
}

static dtrace_prog_t *
compile(dtrace_hdl_t *h, const char *src)
{
	dtrace_prog_t *p = dtrace_program_strcompile(h, src,
	    DTRACE_PROBESPEC_NAME, DTRACE_C_ZDEFS | 0x1000, 0, NULL);
	if (p == NULL) {
		fprintf(stdout, "FAIL compile %s: %s\n", src,
		    dtrace_errmsg(h, dtrace_errno(h)));
		exit(3);
	}
	return (p);
}

static char *
path_of(const char *fmt, ...)
{
	static char buf[8][1024];
	static int slot;
	char name[512];
	va_list va;
	va_start(va, fmt);
	vsnprintf(name, sizeof(name), fmt, va);
	va_end(va);
	slot = (slot + 1) % 8;
	snprintf(buf[slot], sizeof(buf[slot]), "%s/%s", outdir, name);
	return (buf[slot]);
}

/* dtrace_elf_create() into a fresh file; returns its result. */
static int
create_file(dtrace_hdl_t *h, dtrace_prog_t *p, const char *path, char *msg)
{
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		perror(path);
		exit(2);
	}
	msg[0] = '\0';
	int r = dtrace_elf_create(h, p, ELFDATA2LSB, fd, path, msg);
	close(fd);
	return (r);
}

static dtrace_prog_t *
parse_fd(dtrace_hdl_t *h, int fd, const char *path, int rslv, int *err,
    char *msg, dtrace_prog_t *old)
{
	msg[0] = '\0';
	*err = -1;
	return (dtrace_elf_parse(h, fd, path, rslv, err, msg, old));
}

static dtrace_prog_t *
parse_file(dtrace_hdl_t *h, const char *path, int rslv, int *err, char *msg,
    dtrace_prog_t *old)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror(path);
		exit(2);
	}
	dtrace_prog_t *q = parse_fd(h, fd, path, rslv, err, msg, old);
	close(fd);
	return (q);
}

/* ---------------------------------------------------------------------
 * Deep comparison of an original and a parsed program.
 */
static int
same_bytes(const void *a, const void *b, size_t n)
{
	if (n == 0)
		return (1);
	if (a == NULL || b == NULL)
		return (0);
	return (memcmp(a, b, n) == 0);
}

static int
same_difo(const char *what, const dtrace_difo_t *a, const dtrace_difo_t *b)
{
	int ok = 1;
	if (a == NULL || b == NULL) {
		CHECK(a == b, "%s: DIFO presence differs", what);
		return (a == b);
	}
#define	FIELD(f) do { CHECK(a->f == b->f, "%s: " #f " %ju != %ju", what,	\
	(uintmax_t)a->f, (uintmax_t)b->f); ok &= a->f == b->f; } while (0)
	FIELD(dtdo_len);
	FIELD(dtdo_intlen);
	FIELD(dtdo_strlen);
	FIELD(dtdo_symlen);
	FIELD(dtdo_varlen);
	FIELD(dtdo_destructive);
	FIELD(dtdo_rtype.dtdt_kind);
	FIELD(dtdo_rtype.dtdt_ckind);
	FIELD(dtdo_rtype.dtdt_flags);
	FIELD(dtdo_rtype.dtdt_size);
	if (!ok)
		return (0);
	CHECK(same_bytes(a->dtdo_buf, b->dtdo_buf,
	    a->dtdo_len * sizeof(dif_instr_t)), "%s: instructions differ", what);
	CHECK(same_bytes(a->dtdo_inttab, b->dtdo_inttab,
	    a->dtdo_intlen * sizeof(uint64_t)), "%s: integer table differs",
	    what);
	CHECK(same_bytes(a->dtdo_strtab, b->dtdo_strtab, a->dtdo_strlen),
	    "%s: string table differs", what);
	CHECK(same_bytes(a->dtdo_symtab, b->dtdo_symtab, a->dtdo_symlen),
	    "%s: symbol table differs", what);
	for (uint_t i = 0; i < a->dtdo_varlen; i++) {
		const dtrace_difv_t *x = &a->dtdo_vartab[i], *y = &b->dtdo_vartab[i];
		CHECK(x->dtdv_name == y->dtdv_name && x->dtdv_id == y->dtdv_id &&
		    x->dtdv_kind == y->dtdv_kind && x->dtdv_scope == y->dtdv_scope &&
		    x->dtdv_flags == y->dtdv_flags &&
		    memcmp(&x->dtdv_type, &y->dtdv_type, sizeof(x->dtdv_type)) == 0 &&
		    x->dtdv_ctfid == y->dtdv_ctfid &&
		    strcmp(x->dtdv_object, y->dtdv_object) == 0,
		    "%s: variable %u differs", what, i);
		/* Process-local pointers are never taken from the file. */
		CHECK(y->dtdv_sym == NULL && y->dtdv_ctfp == NULL &&
		    y->dtdv_tf == NULL && y->dtdv_stack == NULL,
		    "%s: variable %u carries a foreign pointer", what, i);
	}
	return (1);
#undef FIELD
}

static void
same_fmt(const char *what, const dt_pfargv_t *a, const dt_pfargv_t *b)
{
	if (a == NULL || b == NULL) {
		CHECK(a == b, "%s: format presence differs", what);
		return;
	}
	CHECK(strcmp(a->pfv_format, b->pfv_format) == 0 &&
	    a->pfv_argc == b->pfv_argc && a->pfv_flags == b->pfv_flags,
	    "%s: format header differs (%s/%s)", what, a->pfv_format,
	    b->pfv_format);
	const dt_pfargd_t *x = a->pfv_argv, *y = b->pfv_argv;
	for (; x != NULL && y != NULL; x = x->pfd_next, y = y->pfd_next) {
		/* dt_printf reads a prefix only when its length is non-zero, and
		 * then as a whole string (freopen's restore marker). */
		const char *px = x->pfd_prefix ? x->pfd_prefix : "";
		CHECK(x->pfd_preflen == y->pfd_preflen &&
		    (x->pfd_preflen == 0 || strcmp(px, y->pfd_prefix) == 0) &&
		    memcmp(x->pfd_fmt, y->pfd_fmt, 8) == 0 &&
		    x->pfd_flags == y->pfd_flags && x->pfd_width == y->pfd_width &&
		    x->pfd_dynwidth == y->pfd_dynwidth &&
		    x->pfd_prec == y->pfd_prec,
		    "%s: argument descriptor differs: prefix '%s'/'%s' %zu/%zu "
		    "fmt '%.8s'/'%.8s' flags %u/%u width %d/%d dyn %d/%d prec %d/%d",
		    what, px, y->pfd_prefix, x->pfd_preflen, y->pfd_preflen,
		    x->pfd_fmt, y->pfd_fmt, x->pfd_flags, y->pfd_flags,
		    x->pfd_width, y->pfd_width, x->pfd_dynwidth, y->pfd_dynwidth,
		    x->pfd_prec, y->pfd_prec);
		CHECK((x->pfd_conv == NULL) == (y->pfd_conv == NULL) &&
		    (x->pfd_conv == NULL ||
		    strcmp(x->pfd_conv->pfc_name, y->pfd_conv->pfc_name) == 0),
		    "%s: conversion differs", what);
	}
	CHECK(x == NULL && y == NULL, "%s: descriptor count differs", what);
}

static int
count_stmts(dtrace_prog_t *p)
{
	int n = 0;
	for (dt_stmt_t *s = dt_list_next(&p->dp_stmts); s; s = dt_list_next(s))
		n++;
	return (n);
}

static void
compare_programs(const char *name, dtrace_prog_t *a, dtrace_prog_t *b)
{
	char what[256];
	CHECK(count_stmts(a) == count_stmts(b), "%s: statement count %d != %d",
	    name, count_stmts(a), count_stmts(b));
	CHECK(a->dp_dofversion == b->dp_dofversion &&
	    a->dp_rflags == b->dp_rflags && a->dp_exec == b->dp_exec &&
	    a->dp_pid == b->dp_pid && a->dp_neprobes == b->dp_neprobes,
	    "%s: program header differs", name);
	CHECK(memcmp(a->dp_ident, b->dp_ident, DT_PROG_IDENTLEN) == 0 &&
	    memcmp(a->dp_srcident, b->dp_srcident, DT_PROG_IDENTLEN) == 0,
	    "%s: identifiers differ", name);
	CHECK(same_bytes(a->dp_eprobes, b->dp_eprobes,
	    a->dp_neprobes * sizeof(dtrace_probedesc_t)),
	    "%s: enabled probes differ", name);
	dt_stmt_t *x = dt_list_next(&a->dp_stmts), *y = dt_list_next(&b->dp_stmts);
	dt_stmt_t *px = NULL, *py = NULL;
	for (int i = 0; x != NULL && y != NULL;
	     i++, px = x, py = y, x = dt_list_next(x), y = dt_list_next(y)) {
		dtrace_stmtdesc_t *s = x->ds_desc, *t = y->ds_desc;
		snprintf(what, sizeof(what), "%s stmt %d", name, i);
		dtrace_ecbdesc_t *e = s->dtsd_ecbdesc, *f = t->dtsd_ecbdesc;
		CHECK(memcmp(&e->dted_probe, &f->dted_probe,
		    sizeof(e->dted_probe)) == 0 && e->dted_uarg == f->dted_uarg,
		    "%s: probe description differs", what);
		/* ECB sharing between adjacent statements is preserved. */
		if (px != NULL)
			CHECK((px->ds_desc->dtsd_ecbdesc == e) ==
			    (py->ds_desc->dtsd_ecbdesc == f),
			    "%s: ECB sharing differs", what);
		same_difo(what, e->dted_pred.dtpdd_difo, f->dted_pred.dtpdd_difo);
		CHECK(memcmp(&s->dtsd_descattr, &t->dtsd_descattr,
		    sizeof(s->dtsd_descattr)) == 0 &&
		    memcmp(&s->dtsd_stmtattr, &t->dtsd_stmtattr,
		    sizeof(s->dtsd_stmtattr)) == 0, "%s: attributes differ", what);
		same_fmt(what, s->dtsd_fmtdata, t->dtsd_fmtdata);
		if (s->dtsd_aggdata == NULL || t->dtsd_aggdata == NULL) {
			CHECK(s->dtsd_aggdata == t->dtsd_aggdata,
			    "%s: aggregation identifier presence", what);
		} else {
			dt_ident_t *ia = s->dtsd_aggdata, *ib = t->dtsd_aggdata;
			CHECK(strcmp(ia->di_name, ib->di_name) == 0 &&
			    ia->di_id == ib->di_id && ia->di_kind == ib->di_kind &&
			    ia->di_flags == ib->di_flags &&
			    ia->di_vers == ib->di_vers &&
			    memcmp(&ia->di_attr, &ib->di_attr,
			    sizeof(ia->di_attr)) == 0,
			    "%s: aggregation identifier differs", what);
		}
		dtrace_actdesc_t *ae = s->dtsd_action, *be = t->dtsd_action;
		int k = 0;
		/* A clause without actions stays without actions. */
		for (; ae != NULL || be != NULL;) {
			char awhat[300];
			snprintf(awhat, sizeof(awhat), "%s action %d", what, k++);
			CHECK(ae != NULL && be != NULL, "%s: action missing", awhat);
			if (ae == NULL || be == NULL)
				break;
			CHECK(ae->dtad_kind == be->dtad_kind &&
			    ae->dtad_ntuple == be->dtad_ntuple &&
			    ae->dtad_arg == be->dtad_arg &&
			    ae->dtad_return == be->dtad_return,
			    "%s: kind %d/%d arg %ju/%ju", awhat, ae->dtad_kind,
			    be->dtad_kind, (uintmax_t)ae->dtad_arg,
			    (uintmax_t)be->dtad_arg);
			same_difo(awhat, ae->dtad_difo, be->dtad_difo);
			int last_a = ae == s->dtsd_action_last;
			int last_b = be == t->dtsd_action_last;
			CHECK(last_a == last_b, "%s: span end differs", awhat);
			if (last_a || last_b)
				break;
			ae = ae->dtad_next;
			be = be->dtad_next;
		}
	}
	CHECK(x == NULL && y == NULL, "%s: statement lists differ", name);
}

/* Records written for the Python driver's independent decoder. */
static void
write_manifest(const char *elfpath, dtrace_prog_t *p)
{
	char path[1100];
	snprintf(path, sizeof(path), "%s.manifest", elfpath);
	FILE *f = fopen(path, "w");
	if (f == NULL) {
		perror(path);
		exit(2);
	}
	int nstmt = 0;
	/* Distinct actions and ECBs, in serialization order. */
	const void *seen[4096];
	int nseen = 0, nact = 0, necb = 0;
	for (dt_stmt_t *s = dt_list_next(&p->dp_stmts); s; s = dt_list_next(s)) {
		dtrace_stmtdesc_t *sd = s->ds_desc;
		nstmt++;
		int found = 0;
		for (int i = 0; i < nseen; i++)
			found |= seen[i] == sd->dtsd_ecbdesc;
		if (!found) {
			seen[nseen++] = sd->dtsd_ecbdesc;
			necb++;
			dtrace_difo_t *d = sd->dtsd_ecbdesc->dted_pred.dtpdd_difo;
			if (d != NULL) {
				fprintf(f, "difo %u", d->dtdo_len);
				for (uint_t i = 0; i < d->dtdo_len; i++)
					fprintf(f, " %u", d->dtdo_buf[i]);
				fputc('\n', f);
			}
		}
		for (dtrace_actdesc_t *a = sd->dtsd_ecbdesc->dted_action; a;
		    a = a->dtad_next) {
			found = 0;
			for (int i = 0; i < nseen; i++)
				found |= seen[i] == a;
			if (found)
				continue;
			seen[nseen++] = a;
			nact++;
			fprintf(f, "action %d %u %ju %d\n", a->dtad_kind,
			    a->dtad_ntuple, (uintmax_t)a->dtad_arg, a->dtad_return);
			if (a->dtad_difo != NULL) {
				dtrace_difo_t *d = a->dtad_difo;
				fprintf(f, "difo %u", d->dtdo_len);
				for (uint_t i = 0; i < d->dtdo_len; i++)
					fprintf(f, " %u", d->dtdo_buf[i]);
				fputc('\n', f);
			}
		}
	}
	fprintf(f, "statements %d\nactions %d\necbs %d\n", nstmt, nact, necb);
	fprintf(f, "sizes difo %zu actdesc %zu ecbdesc %zu stmt %zu prog %zu "
	    "difv %zu pfargv %zu pfargd %zu ident %zu probedesc %zu\n",
	    sizeof(dt_elf_difo_t), sizeof(dt_elf_actdesc_t),
	    sizeof(dt_elf_ecbdesc_t), sizeof(dt_elf_stmt_t),
	    sizeof(dt_elf_prog_t), sizeof(dtrace_difv_t),
	    sizeof(dt_elf_pfargv_t), sizeof(dt_elf_pfargd_t),
	    sizeof(dt_elf_ident_t), sizeof(dtrace_probedesc_t));
	fclose(f);
}

/* ---------------------------------------------------------------------
 * Byte-level helpers for building malformed inputs.
 */
typedef struct {
	unsigned char *b;
	size_t n;
} blob_t;

static blob_t
slurp(const char *path)
{
	blob_t r = { NULL, 0 };
	int fd = open(path, O_RDONLY);
	struct stat st;
	if (fd < 0 || fstat(fd, &st) != 0) {
		perror(path);
		exit(2);
	}
	r.n = st.st_size;
	r.b = malloc(r.n + 64);
	if (r.b == NULL || read(fd, r.b, r.n) != (ssize_t)r.n) {
		perror(path);
		exit(2);
	}
	close(fd);
	return (r);
}

static void
spit(const char *path, const unsigned char *b, size_t n)
{
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 || write(fd, b, n) != (ssize_t)n) {
		perror(path);
		exit(2);
	}
	close(fd);
}

static Elf32_Shdr *
shdr_at(blob_t *e, unsigned i)
{
	Elf32_Ehdr *h = (Elf32_Ehdr *)e->b;
	return ((Elf32_Shdr *)(e->b + h->e_shoff + i * h->e_shentsize));
}

static unsigned
shnum(blob_t *e)
{
	Elf32_Ehdr *h = (Elf32_Ehdr *)e->b;
	return (h->e_shnum != 0 ? h->e_shnum : shdr_at(e, 0)->sh_size);
}

static const char *
shname(blob_t *e, unsigned i)
{
	Elf32_Shdr *str = shdr_at(e, shdr_at(e, 0)->sh_link);
	return ((const char *)e->b + str->sh_offset + shdr_at(e, i)->sh_name);
}

/* Index of the nth (0-based) section named 'name', or 0. */
static unsigned
find_sec(blob_t *e, const char *name, int nth)
{
	for (unsigned i = 1; i < shnum(e); i++)
		if (strcmp(shname(e, i), name) == 0 && nth-- == 0)
			return (i);
	return (0);
}

static void *
sec_data(blob_t *e, unsigned i)
{
	return (e->b + shdr_at(e, i)->sh_offset);
}

/* Parse a mutated copy and require the documented rejection. */
static void
expect_reject(dtrace_hdl_t *h, const char *label, blob_t *e, int code,
    const char *text, dtrace_prog_t *old)
{
	char msg[HYPERTRACE_ERRMSGLEN];
	int err;
	const char *path = path_of("reject-%s.elf", label);
	spit(path, e->b, e->n);
	dtrace_prog_t *q = parse_file(h, path, 0, &err, msg, old);
	CHECK(q == NULL && err == code && strstr(msg, text) != NULL,
	    "%s: got prog=%p err=%d msg='%s', want err=%d '%s'", label,
	    (void *)q, err, msg, code, text);
	if (q != NULL)
		dt_program_destroy(h, q);
}

static dtrace_prog_t *
expect_accept(dtrace_hdl_t *h, const char *label, blob_t *e,
    dtrace_prog_t *old)
{
	char msg[HYPERTRACE_ERRMSGLEN];
	int err;
	const char *path = path_of("accept-%s.elf", label);
	spit(path, e->b, e->n);
	dtrace_prog_t *q = parse_file(h, path, 0, &err, msg, old);
	CHECK(q != NULL && err == 0, "%s: rejected err=%d msg='%s'", label,
	    err, msg);
	return (q);
}

static blob_t
copy_blob(blob_t *e)
{
	blob_t r = { malloc(e->n + 64), e->n };
	memcpy(r.b, e->b, e->n);
	return (r);
}

/* Run fn in a forked child; the child's exit status reports its checks. */
static void
in_child(const char *label, void (*fn)(void *), void *arg)
{
	const char *inline_label = getenv("ELF_MATRIX_INLINE");
	if (inline_label != NULL) {
		/* Debugging aid: run one case in this process. */
		if (strcmp(inline_label, label) == 0)
			fn(arg);
		return;
	}
	fflush(stdout);
	pid_t pid = fork();
	if (pid == 0) {
		failures = 0;
		fn(arg);
		fflush(stdout);
		exit(failures ? 1 : 0);
	}
	int st;
	waitpid(pid, &st, 0);
	checks++;
	if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
		failures++;
		printf("FAIL child %s: status 0x%x\n", label, st);
	}
}

/* ---------------------------------------------------------------------
 * Round trips.  One program per action kind the parser accepts, plus
 * printf/printa descriptors, predicates, shared ECBs and variable tables.
 */
static const char *const corpus[] = {
	"BEGIN { trace(1); }",
	"BEGIN /timestamp != 0/ { x = timestamp; trace(x + 3); } "
	    "END { trace(\"done\"); }",
	"BEGIN { printf(\"a=%d b=%s c=%x%% d=%-8.3d\\n\", 1, \"s\", 2, 3); }",
	"BEGIN { printf(\"%*d|%.*s\", 4, 5, 2, \"xyz\"); }",
	"BEGIN { printf(\"plain text only\\n\"); }",
	"BEGIN { @c[1, \"k\"] = count(); @s = sum(7); @mn = min(1); "
	    "@mx = max(2); @a = avg(3); @sd = stddev(4); "
	    "printa(\"%d %s %@d\\n\", @c); printa(@s); }",
	"BEGIN { @q = quantize(1); @l = lquantize(2, 0, 10, 2); "
	    "@ll = llquantize(3, 10, 0, 4, 10); trunc(@q, 1); clear(@l); "
	    "normalize(@ll, 2); denormalize(@ll); }",
	"BEGIN { stack(); stack(3); ustack(); ustack(4, 32); jstack(); }",
	"BEGIN { sym(arg0); mod(arg0); usym(arg0); umod(arg0); uaddr(arg0); }",
	"BEGIN { tracemem(arg0, 16); tracemem(arg0, 16, arg1); }",
	"BEGIN { printm(8, (uintptr_t *)arg0); }",
	"BEGIN { immstack(); immstack(5); }",
	"BEGIN { stop(); raise(9); system(\"echo %d\", 1); "
	    "freopen(\"/dev/null\"); }",
	"BEGIN { breakpoint(); panic(); chill(10); }",
	"BEGIN { self->spec = speculation(); speculate(self->spec); trace(1); } "
	    "END { commit(self->spec); } ERROR { discard(1); }",
	"BEGIN { setopt(\"quiet\"); exit(0); }",
	"BEGIN { self->t = 1; this->c = self->t + 2; a[1] = this->c; "
	    "trace(a[1]); trace(strlen(\"abcdef\")); }",
	"BEGIN, END { trace(1); trace(2); } BEGIN { trace(3); }",
	"BEGIN {}",
};

/* The source rule: options carried in the program do not change round trips;
 * eprobes and identifiers are copied verbatim. */
static void
roundtrip_one(dtrace_hdl_t *h, int i, dtrace_prog_t *p, const char *tag)
{
	char msg[HYPERTRACE_ERRMSGLEN], name[64];
	int err;
	snprintf(name, sizeof(name), "%s-%d", tag, i);
	const char *path = path_of("%s.elf", name);
	/* Allocation ownership: creation must release everything it made. */
	fault_forget_all();
	fault_track(1);
	int r = create_file(h, p, path, msg);
	fault_track(0);
	CHECK(r == 0, "%s: create failed %d %s", name, r, msg);
	CHECK(fault_live() == 0, "%s: writer leaked %ld allocations", name,
	    fault_live());
	write_manifest(path, p);
	dtrace_prog_t *q = parse_file(h, path, 0, &err, msg, p);
	CHECK(q != NULL, "%s: parse failed %d %s", name, err, msg);
	if (q == NULL)
		return;
	compare_programs(name, p, q);
	/* Writing the same program again must give an equivalent file. */
	const char *again = path_of("%s-again.elf", name);
	r = create_file(h, p, again, msg);
	CHECK(r == 0, "%s: second create failed %d %s", name, r, msg);
	dtrace_prog_t *q2 = parse_file(h, again, 0, &err, msg, p);
	CHECK(q2 != NULL, "%s: second file rejected %d %s", name, err, msg);
	if (q2 != NULL) {
		compare_programs(name, p, q2);
		blob_t a = slurp(path), b = slurp(again);
		CHECK(a.n == b.n && memcmp(a.b, b.b, a.n) == 0,
		    "%s: repeated serialization differs", name);
		free(a.b);
		free(b.b);
		dt_program_destroy(h, q2);
	}
	/* A parsed program serializes to the same file again. */
	const char *re = path_of("%s-reparsed.elf", name);
	r = create_file(h, q, re, msg);
	CHECK(r == 0, "%s: create from parsed program failed", name);
	dtrace_prog_t *q3 = parse_file(h, re, 0, &err, msg, p);
	CHECK(q3 != NULL, "%s: reparsed file rejected %s", name, msg);
	if (q3 != NULL) {
		compare_programs(name, p, q3);
		dt_program_destroy(h, q3);
	}
	dt_program_destroy(h, q);
}

static void
scenario_roundtrip(void)
{
	dtrace_hdl_t *h = open_handle(0);
	(void)dtrace_setopt(h, "destructive", NULL);
	for (size_t i = 0; i < sizeof(corpus) / sizeof(corpus[0]); i++) {
		dtrace_prog_t *p = compile(h, corpus[i]);
		if (strstr(corpus[i], "immstack") != NULL) {
			/* Forwarding turns immstack into printimmstack. */
			dtrace_prog_t *v = dtrace_vprog_from(h, p, 0);
			CHECK(v != NULL, "vprog_from immstack");
			if (v != NULL)
				roundtrip_one(h, (int)i, v, "vprog");
		}
		roundtrip_one(h, (int)i, p, "program");
	}
	/* Relocated (HyperTrace-linked) programs carry symbols and casts. */
	const char *linked[] = {
		"BEGIN { trace(curthread->td_tid); "
		    "trace(curthread->td_proc->p_pid); }",
		"BEGIN { this->p = (struct thread *)arg0; trace(this->p->td_tid); }",
	};
	for (int i = 0; i < 2; i++) {
		dtrace_prog_t *p = compile(h, linked[i]);
		char msg[HYPERTRACE_ERRMSGLEN] = "";
		int r = hypertrace_link(h, p, msg);
		CHECK(r == 0, "link %d: %d %s", i, r, msg);
		roundtrip_one(h, i, p, "linked");
	}
	/* Enabled probes are copied, in order. */
	dtrace_prog_t *p = compile(h, corpus[0]);
	p->dp_neprobes = 3;
	p->dp_eprobes = calloc(3, sizeof(dtrace_probedesc_t));
	for (int i = 0; i < 3; i++) {
		p->dp_eprobes[i].dtpd_id = 100 + i;
		snprintf(p->dp_eprobes[i].dtpd_provider, DTRACE_PROVNAMELEN,
		    "prov%d", i);
		snprintf(p->dp_eprobes[i].dtpd_name, DTRACE_NAMELEN, "n%d", i);
	}
	p->dp_exec = 1;
	p->dp_pid = 4242;
	p->dp_rflags = 2;
	roundtrip_one(h, 0, p, "eprobes");
	dtrace_close(h);
}

static void crafted_resolver_with(dtrace_hdl_t *);

/* With _HYPERTRACE_LOG_ELF set, a HyperTrace handle traces the parser's
 * decisions on stderr; logging must not change any round trip. */
static void
scenario_logged(void)
{
	char logpath[1100];
	snprintf(logpath, sizeof(logpath), "%s/elf-log.txt", outdir);
	int fd = open(logpath, O_RDWR | O_CREAT | O_TRUNC, 0600);
	int saved = dup(STDERR_FILENO);
	dup2(fd, STDERR_FILENO);
	setenv("_HYPERTRACE_LOG_ELF", "1", 1);
	dtrace_hdl_t *h = open_handle(0);
	dtrace_enable_hypertrace(h);
	for (size_t i = 0; i < sizeof(corpus) / sizeof(corpus[0]); i++)
		roundtrip_one(h, (int)i, compile(h, corpus[i]), "logged");
	crafted_resolver_with(h);
	dtrace_close(h);
	fflush(stderr);
	dup2(saved, STDERR_FILENO);
	blob_t log = slurp(logpath);
	log.b[log.n] = '\0';
	CHECK(strstr((char *)log.b, "elf: allocated difo") != NULL &&
	    strstr((char *)log.b, "elf: append statement") != NULL &&
	    strstr((char *)log.b, "elf: failed to resolve") != NULL,
	    "ELF log is missing parser events");
	close(fd);
}

/* ---------------------------------------------------------------------
 * Programs that the compiler does not produce but the writer accepts.
 */
static void
crafted_haserror(void *arg)
{
	(void)arg;
	dtrace_hdl_t *h = open_handle(1);
	char msg[HYPERTRACE_ERRMSGLEN];
	int err;
	dtrace_prog_t *p = compile(h, corpus[0]);
	p->dp_haserror = 1;
	strlcpy(p->dp_err, "guest reported: no such probe", DT_PROG_ERRLEN);
	const char *path = path_of("haserror.elf");
	CHECK(create_file(h, p, path, msg) == 0, "haserror create: %s", msg);
	/* The program record carries only the error; parsing propagates it. */
	dtrace_prog_t *q = parse_file(h, path, 0, &err, msg, NULL);
	CHECK(q == NULL && err == E_HYPERTRACE_PROPAGATED &&
	    strcmp(msg, "guest reported: no such probe") == 0,
	    "haserror parse: err=%d msg=%s", err, msg);
	blob_t e = slurp(path);
	CHECK(find_sec(&e, ".dtrace_stmtdesc", 0) == 0,
	    "haserror file serialized statements");
	/* An error without text propagates as an empty message. */
	p->dp_err[0] = '\0';
	path = path_of("haserror-empty.elf");
	CHECK(create_file(h, p, path, msg) == 0, "haserror create: %s", msg);
	q = parse_file(h, path, 0, &err, msg, NULL);
	CHECK(q == NULL && err == E_HYPERTRACE_PROPAGATED && msg[0] == '\0',
	    "haserror-empty parse: err=%d msg=%s", err, msg);
	dtrace_close(h);
}

static void
crafted_empty(void *arg)
{
	(void)arg;
	dtrace_hdl_t *h = open_handle(1);
	char msg[HYPERTRACE_ERRMSGLEN];
	int err;
	dtrace_prog_t *p = dt_program_create(h);
	const char *path = path_of("empty.elf");
	CHECK(create_file(h, p, path, msg) == 0, "empty create: %s", msg);
	dtrace_prog_t *q = parse_file(h, path, 0, &err, msg, NULL);
	CHECK(q == NULL && err == E_HYPERTRACE_ELFPARSE &&
	    strstr(msg, "has no statements") != NULL, "empty parse: %d %s",
	    err, msg);
	dtrace_close(h);
}

/* A statement without actions (what the compiler emits for "BEGIN {}") is
 * written without action references in its statement and ECB records. */
static void expect_reject(dtrace_hdl_t *, const char *, blob_t *, int,
    const char *, dtrace_prog_t *);
static blob_t copy_blob(blob_t *);

static void
crafted_no_actions(void *arg)
{
	(void)arg;
	dtrace_hdl_t *h = open_handle(1);
	char msg[HYPERTRACE_ERRMSGLEN];
	int err;
	dtrace_prog_t *p = compile(h, corpus[0]);
	dtrace_stmtdesc_t *sd = ((dt_stmt_t *)dt_list_next(&p->dp_stmts))->ds_desc;
	sd->dtsd_action = NULL;
	sd->dtsd_action_last = NULL;
	sd->dtsd_ecbdesc->dted_action = NULL;
	const char *path = path_of("no-actions.elf");
	CHECK(create_file(h, p, path, msg) == 0, "no-actions create: %s", msg);
	blob_t e = slurp(path);
	unsigned s = find_sec(&e, ".dtrace_stmtdesc", 0);
	unsigned c = find_sec(&e, ".dtrace_ecbdesc", 0);
	CHECK(s && ((dt_elf_stmt_t *)sec_data(&e, s))->dtes_action == 0 &&
	    c && ((dt_elf_ecbdesc_t *)sec_data(&e, c))->dtee_action == 0,
	    "no-actions references");
	/* ... and is read back as a statement without actions. */
	dtrace_prog_t *q = parse_file(h, path, 0, &err, msg, NULL);
	CHECK(q != NULL, "no-actions parse: %d %s", err, msg);
	if (q != NULL)
		compare_programs("no-actions", p, q);
	/* Exactly one of first/last action missing is malformed. */
	blob_t m = copy_blob(&e);
	((dt_elf_stmt_t *)sec_data(&m, s))->dtes_action_last = s;
	expect_reject(h, "half-action-span", &m, E_HYPERTRACE_ELFPARSE,
	    "invalid statement action graph", NULL);
	m = copy_blob(&e);
	((dt_elf_stmt_t *)sec_data(&m, s))->dtes_ecbdesc = 0;
	expect_reject(h, "statement-without-ecb", &m, E_HYPERTRACE_ELFPARSE,
	    "invalid statement action graph", NULL);
	/* Without an ECB either, the statement has no ECB reference. */
	sd->dtsd_ecbdesc = NULL;
	CHECK(create_file(h, p, path_of("no-ecb.elf"), msg) == 0,
	    "no-ecb create: %s", msg);
	blob_t f = slurp(path_of("no-ecb.elf"));
	s = find_sec(&f, ".dtrace_stmtdesc", 0);
	CHECK(s && ((dt_elf_stmt_t *)sec_data(&f, s))->dtes_ecbdesc == 0 &&
	    find_sec(&f, ".dtrace_ecbdesc", 0) == 0, "no-ecb references");
	exit(failures ? 1 : 0); /* the handle owns a statement we broke */
}

/* A first action without a last action is an inconsistent statement: the
 * writer must refuse it instead of producing a file. */
static void
crafted_no_last(void *arg)
{
	(void)arg;
	dtrace_hdl_t *h = open_handle(1);
	char msg[HYPERTRACE_ERRMSGLEN];
	dtrace_prog_t *p = compile(h, corpus[0]);
	dtrace_stmtdesc_t *sd = ((dt_stmt_t *)dt_list_next(&p->dp_stmts))->ds_desc;
	sd->dtsd_action_last = NULL;
	int r = create_file(h, p, path_of("no-last.elf"), msg);
	CHECK(r == E_HYPERTRACE_ELFCREATE &&
	    strstr(msg, "action last is NULL, but first is not") != NULL &&
	    strstr(msg, path_of("no-last.elf")) != NULL,
	    "no-last create: %d %s", r, msg);
	exit(failures ? 1 : 0); /* the handle owns a statement we broke */
}

/* A file is accepted for oldpgp when its identifier or its source
 * identifier is oldpgp's identifier; otherwise the parser asks the peer to
 * resend (E_HYPERTRACE_AGAIN) and remembers the file's source identifier. */
static void
crafted_identifiers(void *arg)
{
	int failmsg = arg != NULL;
	int pfd[2];
	if (pipe(pfd) != 0)
		exit(2);
	dtrace_hdl_t *h = open_handle(1);
	if (failmsg)
		dtrace_set_failmsg_needed(h);
	char msg[HYPERTRACE_ERRMSGLEN];
	int err;
	dtrace_prog_t *old = compile(h, corpus[0]);
	dtrace_prog_t *p = compile(h, corpus[1]);
	/* Derived program: new identity, source is 'old'. */
	memcpy(p->dp_srcident, old->dp_ident, DT_PROG_IDENTLEN);
	memset(p->dp_ident, 0x5a, DT_PROG_IDENTLEN);
	const char *path = path_of("derived-%d.elf", failmsg);
	CHECK(create_file(h, p, path, msg) == 0, "derived create");
	dtrace_prog_t *q = parse_file(h, path, 0, &err, msg, old);
	CHECK(q != NULL, "derived program rejected: %d %s", err, msg);
	/* Unrelated program. */
	dtrace_prog_t *other = compile(h, corpus[2]);
	int saved_out = dup(STDOUT_FILENO);
	fflush(stdout);
	dup2(pfd[1], STDOUT_FILENO);
	q = parse_file(h, path, 0, &err, msg, other);
	dup2(saved_out, STDOUT_FILENO);
	CHECK(q == NULL && err == E_HYPERTRACE_AGAIN, "unrelated: %d %s", err,
	    msg);
	char saved[DT_PROG_IDENTLEN];
	dtrace_get_srcident(saved);
	CHECK(memcmp(saved, old->dp_ident, DT_PROG_IDENTLEN) == 0,
	    "saved source identifier");
	char out[64] = "";
	int fl = fcntl(pfd[0], F_GETFL);
	fcntl(pfd[0], F_SETFL, fl | O_NONBLOCK);
	ssize_t n = read(pfd[0], out, sizeof(out));
	if (failmsg)
		CHECK(n == 10 && memcmp(out, "FAIL FAIL", 10) == 0,
		    "failure message %zd", n);
	else
		CHECK(n < 0 && errno == EAGAIN, "unexpected output %zd", n);
	dtrace_close(h);
}

/* Compile identifiers: a known source identifier is acknowledged on stdout
 * with "DEL ident\0" + identifier; an unknown one fails.  A base program
 * (no source identifier, not marked for execution) is none of them: it is
 * acknowledged with no identifier. */
static void
crafted_compile_idents(void *arg)
{
	/* 0 found, 1 unknown, 2 ack fails, 3 identifier write fails,
	 * 4 unknown without a failure message, 5 base program,
	 * 6 no source identifier but marked for execution */
	int mode = (int)(intptr_t)arg;
	int pfd[2];
	if (pipe(pfd) != 0)
		exit(2);
	dtrace_hdl_t *h = open_handle(1);
	char msg[HYPERTRACE_ERRMSGLEN];
	int err;
	dtrace_prog_t *p = compile(h, corpus[0]);
	if (mode < 5)
		memset(p->dp_srcident, 0x33, DT_PROG_IDENTLEN);
	if (mode == 6)
		p->dp_exec = DT_PROG_EXEC;
	const char *path = path_of("idents-%d.elf", mode);
	CHECK(create_file(h, p, path, msg) == 0, "idents create");
	char idents[2 * DT_PROG_IDENTLEN];
	memset(idents, 0x11, sizeof(idents));
	if (mode != 1 && mode != 4 && mode < 5)
		memcpy(idents + DT_PROG_IDENTLEN, p->dp_srcident,
		    DT_PROG_IDENTLEN);
	CHECK(dtrace_compile_idents_set(h, idents, 2) == 0, "idents set");
	if (mode == 1 || mode == 6)
		dtrace_set_failmsg_needed(h);
	int saved = dup(STDOUT_FILENO);
	fflush(stdout);
	if (mode == 2)
		close(STDOUT_FILENO);
	else
		dup2(pfd[1], STDOUT_FILENO);
	if (mode == 3)
		fault_arm("write", 1, 0);
	dtrace_prog_t *q = parse_file(h, path, 0, &err, msg, NULL);
	fault_disarm();
	dup2(saved, STDOUT_FILENO);
	char out[2 * DT_PROG_IDENTLEN + 64];
	fcntl(pfd[0], F_SETFL, O_NONBLOCK);
	ssize_t n = read(pfd[0], out, sizeof(out));
	if (mode == 0 || mode == 5) {
		CHECK(q != NULL && n == 10 + DT_PROG_IDENTLEN &&
		    memcmp(out, "DEL ident", 10) == 0 &&
		    memcmp(out + 10, p->dp_srcident, DT_PROG_IDENTLEN) == 0,
		    "found: q=%p n=%zd %s", (void *)q, n, msg);
	} else if (mode == 1 || mode == 6) {
		CHECK(q == NULL && err == E_HYPERTRACE_IDENT_NOTFOUND &&
		    n == 10 && memcmp(out, "FAIL FAIL", 10) == 0,
		    "unknown: %d %zd", err, n);
	} else if (mode == 4) {
		CHECK(q == NULL && err == E_HYPERTRACE_IDENT_NOTFOUND && n < 0,
		    "unknown without message: %d %zd", err, n);
	} else {
		CHECK(q == NULL && err == E_HYPERTRACE_SYS &&
		    strstr(msg, "acknowledgement failed") != NULL &&
		    (mode == 2 || (n == 10 && memcmp(out, "DEL ident", 10) == 0)),
		    "ack failure %d: %d %s", mode, err, msg);
	}
	dtrace_close(h);
}

/* Resolver: an empty target is for all hosts; a target that matches neither
 * the host name nor FreeBSD-<osrelease> drops its statement. */
static void
crafted_resolver_with(dtrace_hdl_t *h)
{
	char msg[HYPERTRACE_ERRMSGLEN], host[256];
	int err;
	gethostname(host, sizeof(host));
	dtrace_prog_t *p = compile(h, "BEGIN { trace(1); } END { trace(2); } "
	    "ERROR { trace(3); }");
	dt_stmt_t *s = dt_list_next(&p->dp_stmts);
	/* stmt 0 keeps an empty target. */
	s = dt_list_next(s);
	strlcpy(s->ds_desc->dtsd_ecbdesc->dted_probe.dtpd_target,
	    "no-such-host-*", DTRACE_TARGETNAMELEN);
	s = dt_list_next(s);
	strlcpy(s->ds_desc->dtsd_ecbdesc->dted_probe.dtpd_target, host,
	    DTRACE_TARGETNAMELEN);
	p->dp_rflags = 1; /* host name matching */
	const char *path = path_of("resolver-%p.elf", (void *)h);
	CHECK(create_file(h, p, path, msg) == 0, "resolver create");
	dtrace_prog_t *q = parse_file(h, path, 1, &err, msg, NULL);
	CHECK(q != NULL && count_stmts(q) == 2, "resolver kept %d",
	    q ? count_stmts(q) : -1);
	if (q != NULL) {
		dt_stmt_t *a = dt_list_next(&q->dp_stmts);
		dt_stmt_t *b = dt_list_next(a);
		CHECK(a->ds_desc->dtsd_ecbdesc->dted_probe.dtpd_target[0] == 0 &&
		    strcmp(b->ds_desc->dtsd_ecbdesc->dted_probe.dtpd_target,
		    host) == 0, "resolver kept the wrong statements");
	}
	/* Without resolution every statement is kept. */
	q = parse_file(h, path, 0, &err, msg, NULL);
	CHECK(q != NULL && count_stmts(q) == 3, "unresolved count");
}

static void
crafted_resolver(void *arg)
{
	(void)arg;
	dtrace_hdl_t *h = open_handle(1);
	crafted_resolver_with(h);
	dtrace_close(h);
}

/* A conversion descriptor without its conversion cannot be serialized. */
static void
crafted_missing_conversion(void *arg)
{
	(void)arg;
	dtrace_hdl_t *h = open_handle(1);
	char msg[HYPERTRACE_ERRMSGLEN];
	dtrace_prog_t *p = compile(h, corpus[2]);
	dtrace_stmtdesc_t *sd = ((dt_stmt_t *)dt_list_next(&p->dp_stmts))->ds_desc;
	dt_pfargd_t *pfd = ((dt_pfargv_t *)sd->dtsd_fmtdata)->pfv_argv;
	CHECK(pfd != NULL && pfd->pfd_fmt[0] != '\0', "descriptor present");
	pfd->pfd_conv = NULL;
	int r = create_file(h, p, path_of("missing-conversion.elf"), msg);
	CHECK(r == E_HYPERTRACE_ELFCREATE &&
	    strstr(msg, "format conversion is missing") != NULL,
	    "missing conversion: %d %s", r, msg);
	exit(failures ? 1 : 0); /* the handle owns a descriptor we broke */
}

/* A program-list entry without a statement description writes no
 * statement section, and the writer reports the missing section. */
static void
crafted_null_statement(void *arg)
{
	int which = (int)(intptr_t)arg;
	dtrace_hdl_t *h = open_handle(1);
	char msg[HYPERTRACE_ERRMSGLEN];
	dtrace_prog_t *p = compile(h, "BEGIN { trace(1); } END { trace(2); }");
	dt_stmt_t *st = dt_list_next(&p->dp_stmts);
	if (which)
		st = dt_list_next(st);
	st->ds_desc = NULL;
	int r = create_file(h, p, path_of("null-statement-%d.elf", which), msg);
	CHECK(r == E_HYPERTRACE_ELFCREATE && strstr(msg, "elf_getdata(") != NULL,
	    "null statement %d: %d %s", which, r, msg);
	exit(failures ? 1 : 0); /* the handle owns the list we broke */
}

static void
scenario_crafted(void)
{
	in_child("missing-conversion", crafted_missing_conversion, NULL);
	in_child("null-statement-0", crafted_null_statement, (void *)0);
	in_child("null-statement-1", crafted_null_statement, (void *)1);
	in_child("haserror", crafted_haserror, NULL);
	in_child("empty", crafted_empty, NULL);
	in_child("no-actions", crafted_no_actions, NULL);
	in_child("no-last", crafted_no_last, NULL);
	in_child("identifiers", crafted_identifiers, NULL);
	in_child("identifiers-failmsg", crafted_identifiers, (void *)1);
	for (intptr_t m = 0; m < 7; m++)
		in_child("compile-idents", crafted_compile_idents, (void *)m);
	in_child("resolver", crafted_resolver, NULL);
}

/* ---------------------------------------------------------------------
 * Targeted malformed inputs, one validation rule each.
 */
static blob_t
make_file(dtrace_hdl_t *h, dtrace_prog_t *p, const char *label)
{
	char msg[HYPERTRACE_ERRMSGLEN];
	const char *path = path_of("base-%s.elf", label);
	int r = create_file(h, p, path, msg);
	if (r != 0) {
		printf("FAIL base %s: %d %s\n", label, r, msg);
		exit(1);
	}
	return (slurp(path));
}

static dif_instr_t *
difo_insns(blob_t *e, unsigned sec, uint64_t *len)
{
	dt_elf_difo_t *d = sec_data(e, sec);
	*len = d->dted_len;
	return (d->dted_buf);
}

static void
scenario_mutate(void)
{
	dtrace_hdl_t *h = open_handle(0);
	blob_t m;

	/* printf descriptors */
	dtrace_prog_t *pf = compile(h, corpus[2]);
	blob_t e = make_file(h, pf, "printf");
	unsigned s = find_sec(&e, ".dtrace_pfv_argv", 0);
	CHECK(s != 0, "printf file has descriptors");
	m = copy_blob(&e);
	memset(((dt_elf_pfargd_t *)sec_data(&m, s))->epfd_fmt, 'A', 8);
	expect_reject(h, "pfd-format-unterminated", &m,
	    E_HYPERTRACE_ELFPARSE, "invalid format argument record", pf);
	m = copy_blob(&e);
	((dt_elf_pfargd_t *)sec_data(&m, s))->epfd_preflen = 1 << 20;
	expect_reject(h, "pfd-prefix-length", &m, E_HYPERTRACE_ELFPARSE,
	    "invalid format argument record", pf);
	s = find_sec(&e, ".dtrace_fmtdata", 0);
	m = copy_blob(&e);
	shdr_at(&m, s)->sh_size = 4;
	expect_reject(h, "fmtdata-truncated", &m, E_HYPERTRACE_ELFPARSE,
	    "ELF fmtdata is NULL", pf);
	m = copy_blob(&e);
	((dt_elf_pfargv_t *)sec_data(&m, s))->epfv_format = 1 << 30;
	expect_reject(h, "fmtdata-format-offset", &m, E_HYPERTRACE_ELFPARSE,
	    "ELF fmtdata is NULL", pf);
	m = copy_blob(&e);
	shdr_at(&m, s)->sh_type = SHT_NOBITS;
	expect_reject(h, "fmtdata-nobits", &m, E_HYPERTRACE_ELFPARSE,
	    "ELF fmtdata is NULL", pf);
	m = copy_blob(&e);
	shdr_at(&m, find_sec(&m, ".dtrace_pfv_argv", 0))->sh_type = SHT_NOBITS;
	expect_reject(h, "pfd-nobits", &m, E_HYPERTRACE_ELFPARSE,
	    "invalid format argument record", pf);
	m = copy_blob(&e);
	((dt_elf_pfargv_t *)sec_data(&m, s))->epfv_argc = 129;
	expect_reject(h, "fmtdata-argc", &m, E_HYPERTRACE_ELFPARSE,
	    "invalid format argument count or flags", pf);

	/* aggregation identifiers */
	dtrace_prog_t *ag = compile(h, corpus[5]);
	e = make_file(h, ag, "aggregation");
	s = find_sec(&e, ".dtrace_ident", 0);
	CHECK(s != 0, "aggregation identifiers present");
	m = copy_blob(&e);
	shdr_at(&m, s)->sh_size = 4;
	expect_reject(h, "ident-truncated", &m, E_HYPERTRACE_ELFPARSE,
	    "ELF action identifier data is NULL", ag);
	m = copy_blob(&e);
	shdr_at(&m, s)->sh_type = SHT_NOBITS;
	expect_reject(h, "ident-nobits", &m, E_HYPERTRACE_ELFPARSE,
	    "ELF action identifier data is NULL", ag);
	m = copy_blob(&e);
	((dt_elf_ident_t *)sec_data(&m, s))->edi_name = 1 << 30;
	expect_reject(h, "ident-name-offset", &m, E_HYPERTRACE_ELFPARSE,
	    "ELF action identifier data is NULL", ag);

	/* Cycle inside a statement's action span, and a terminal back-edge
	 * into the span accepted by the statement graph check. */
	dtrace_prog_t *sp = compile(h,
	    "BEGIN { @span[1, 2] = count(); trace(5); }");
	e = make_file(h, sp, "span");
	unsigned s0 = find_sec(&e, ".dtrace_stmtdesc", 0);
	unsigned s1 = find_sec(&e, ".dtrace_stmtdesc", 1);
	dt_elf_stmt_t *st0 = sec_data(&e, s0);
	CHECK(s1 != 0 && st0->dtes_action != st0->dtes_action_last,
	    "multi-action span");
	dt_elf_actdesc_t *first = sec_data(&e, st0->dtes_action);
	unsigned second = first->dtea_next;
	CHECK(second != st0->dtes_action_last, "span has three actions");
	m = copy_blob(&e);
	((dt_elf_actdesc_t *)sec_data(&m, second))->dtea_next =
	    st0->dtes_action;
	expect_reject(h, "span-cycle", &m, E_HYPERTRACE_ELFPARSE,
	    "cyclic action chain", sp);
	m = copy_blob(&e);
	((dt_elf_actdesc_t *)sec_data(&m, st0->dtes_action_last))->dtea_next =
	    st0->dtes_action;
	((dt_elf_stmt_t *)sec_data(&m, s1))->dtes_action = st0->dtes_action;
	expect_reject(h, "terminal-backedge", &m, E_HYPERTRACE_ELFPARSE,
	    "cyclic action chain", sp);

	/* DIF tables */
	dtrace_prog_t *tp = compile(h, "BEGIN { trace(\"text\"); }");
	e = make_file(h, tp, "strings");
	s = find_sec(&e, ".difo_strtab", 0);
	m = copy_blob(&e);
	((char *)sec_data(&m, s))[shdr_at(&m, s)->sh_size - 1] = 'X';
	expect_reject(h, "strtab-unterminated", &m, E_HYPERTRACE_ELFPARSE,
	    "DIF table size does not match", tp);
	/* An empty integer table referenced with length 0 is a valid,
	 * empty table: a DIFO that no longer uses its integers parses with
	 * no integer table. */
	dtrace_prog_t *ip = compile(h, corpus[0]);
	e = make_file(h, ip, "integers");
	unsigned d = find_sec(&e, ".dtrace_difo", 0);
	s = find_sec(&e, ".difo_inttab", 0);
	m = copy_blob(&e);
	uint64_t len;
	dif_instr_t *ins = difo_insns(&m, d, &len);
	for (uint64_t i = 0; i < len; i++)
		if (DIF_INSTR_OP(ins[i]) == DIF_OP_SETX)
			ins[i] = DIF_INSTR_FMT(DIF_OP_MOV, 0, 0,
			    DIF_INSTR_RD(ins[i]));
	((dt_elf_difo_t *)sec_data(&m, d))->dted_intlen = 0;
	shdr_at(&m, s)->sh_size = 0;
	dtrace_prog_t *q = expect_accept(h, "empty-inttab", &m, ip);
	if (q != NULL) {
		dt_stmt_t *qs = dt_list_next(&q->dp_stmts);
		dtrace_difo_t *qd = qs->ds_desc->dtsd_action->dtad_difo;
		CHECK(qd->dtdo_intlen == 0 && qd->dtdo_inttab == NULL,
		    "empty integer table materialized");
	}

	/* Instruction references */
	dtrace_prog_t *bp = compile(h,
	    "BEGIN { x = timestamp; trace(x > 2 ? 1 : 2); }");
	e = make_file(h, bp, "branches");
	int done = 0;
	for (unsigned k = 0; !done && (d = find_sec(&e, ".dtrace_difo", k)); k++) {
		ins = difo_insns(&e, d, &len);
		for (uint64_t i = 1; i < len; i++) {
			uint_t op = DIF_INSTR_OP(ins[i]);
			if (op < DIF_OP_BA || op > DIF_OP_BLEU)
				continue;
			m = copy_blob(&e);
			difo_insns(&m, d, &len)[i] = DIF_INSTR_BRANCH(op, i);
			expect_reject(h, "branch-to-self", &m,
			    E_HYPERTRACE_ELFPARSE,
			    "invalid DIF instruction reference", bp);
			done = 1;
			break;
		}
	}
	CHECK(done, "no branch instruction found");
	dtrace_prog_t *up = compile(h, "BEGIN { trace(curthread->td_tid); }");
	e = make_file(h, up, "symbols");
	done = 0;
	for (unsigned k = 0; !done && (d = find_sec(&e, ".dtrace_difo", k)); k++) {
		ins = difo_insns(&e, d, &len);
		for (uint64_t i = 0; i < len; i++) {
			uint_t op = DIF_INSTR_OP(ins[i]);
			if (op != DIF_OP_USETX && op != DIF_OP_TYPECAST)
				continue;
			m = copy_blob(&e);
			dt_elf_difo_t *md = sec_data(&m, d);
			md->dted_buf[i] = DIF_INSTR_FMT(op, 0xff, 0xff,
			    DIF_INSTR_RD(ins[i]));
			expect_reject(h, "symbol-out-of-range", &m,
			    E_HYPERTRACE_ELFPARSE,
			    "invalid DIF instruction reference", up);
			done = 1;
			break;
		}
	}
	CHECK(done, "no symbol instruction found");

	/* Sections whose data is absent from the file (SHT_NOBITS). */
	e = make_file(h, ip, "nobits");
	m = copy_blob(&e);
	shdr_at(&m, 2)->sh_type = SHT_NOBITS;
	expect_reject(h, "program-nobits", &m, E_HYPERTRACE_ELFPARSE,
	    "invalid program record", ip);
	m = copy_blob(&e);
	shdr_at(&m, 1)->sh_type = SHT_NOBITS;
	expect_reject(h, "names-nobits", &m, E_HYPERTRACE_ELFPARSE,
	    "elf_strptr(", ip);
	m = copy_blob(&e);
	shdr_at(&m, find_sec(&m, ".dtrace_stmtdesc", 0))->sh_type = SHT_NOBITS;
	expect_reject(h, "statement-nobits", &m, E_HYPERTRACE_ELFPARSE,
	    "ELF statement section data is NULL", ip);
	static const struct { const char *sec, *text; } nobits[] = {
		{ ".dtrace_ecbdesc", "truncated or misaligned ECB description" },
		{ ".dtrace_actdesc", "invalid terminal action reference" },
		{ ".dtrace_difo", "invalid DIF instruction array" },
	};
	for (size_t k = 0; k < sizeof(nobits) / sizeof(nobits[0]); k++) {
		m = copy_blob(&e);
		shdr_at(&m, find_sec(&m, nobits[k].sec, 0))->sh_type = SHT_NOBITS;
		expect_reject(h, nobits[k].sec + 1, &m, E_HYPERTRACE_ELFPARSE,
		    nobits[k].text, ip);
	}
	m = copy_blob(&e);
	s = find_sec(&m, ".difo_inttab", 0);
	shdr_at(&m, s)->sh_type = SHT_NOBITS;
	expect_reject(h, "table-nobits", &m, E_HYPERTRACE_ELFPARSE,
	    "DIF table size does not match", ip);
	/* Opcode 0 is not a DIF instruction. */
	m = copy_blob(&e);
	d = find_sec(&m, ".dtrace_difo", 0);
	difo_insns(&m, d, &len)[0] = 0;
	expect_reject(h, "opcode-zero", &m, E_HYPERTRACE_ELFPARSE,
	    "invalid DIF instruction reference", ip);

	/* A string table that nothing uses may be empty. */
	e = make_file(h, tp, "unused-strings");
	m = copy_blob(&e);
	d = find_sec(&m, ".dtrace_difo", 0);
	ins = difo_insns(&m, d, &len);
	for (uint64_t i = 0; i < len; i++)
		if (DIF_INSTR_OP(ins[i]) == DIF_OP_SETS)
			ins[i] = DIF_INSTR_MOV(0, DIF_INSTR_RD(ins[i]));
	((dt_elf_difo_t *)sec_data(&m, d))->dted_strlen = 0;
	shdr_at(&m, ((dt_elf_difo_t *)sec_data(&m, d))->dted_strtab)->sh_size = 0;
	q = expect_accept(h, "empty-strtab", &m, tp);

	/* Variable type kinds: any of CTF, string, none or bottom. */
	dtrace_prog_t *vp = compile(h, "BEGIN { gx = 1; trace(gx); }");
	e = make_file(h, vp, "variables");
	s = find_sec(&e, ".dtrace_vartab", 0);
	CHECK(s != 0, "variable table present");
	m = copy_blob(&e);
	((dtrace_difv_t *)sec_data(&m, s))->dtdv_type.dtdt_kind = DIF_TYPE_NONE;
	q = expect_accept(h, "variable-kind-none", &m, vp);

	/* A print() type reference outside the identifier name table. */
	{
		dtrace_prog_t *pp = compile(h,
		    "BEGIN { print(curthread->td_tid); }");
		e = make_file(h, pp, "print-strdata");
		s = find_sec(&e, ".dtrace_stmtdesc", 0);
		CHECK(s != 0, "statement present");
		m = copy_blob(&e);
		CHECK(((dt_elf_stmt_t *)sec_data(&m, s))->dtes_strdata != 0,
		    "print() reference serialized");
		((dt_elf_stmt_t *)sec_data(&m, s))->dtes_strdata = 1 << 30;
		expect_reject(h, "strdata-outside-table", &m,
		    E_HYPERTRACE_ELFPARSE, "invalid statement string data", pp);
		q = expect_accept(h, "strdata", &e, pp);
		dt_stmt_t *st = q != NULL ? dt_list_next(&q->dp_stmts) : NULL;
		CHECK(st != NULL && st->ds_desc->dtsd_strdata != NULL,
		    "print() reference restored");
	}

	/*
	 * Every record section, for every record type the parser reads:
	 * data that is not in the file (elf_getdata() fails: the section lies
	 * past the end) is rejected, not read.  (A section at an odd offset
	 * is no test of alignment: libelf copies section data into a buffer
	 * of its own, elf_getdata().)
	 */
	static const struct {
		int prog;	/* 0: printf program, 1: aggregations */
		const char *sec;
	} recs[] = {
		{ 0, ".dtrace_prog" }, { 0, ".dtrace_stmtdesc" },
		{ 0, ".dtrace_actdesc" }, { 0, ".dtrace_ecbdesc" },
		{ 0, ".dtrace_difo" }, { 0, ".dtrace_fmtdata" },
		{ 0, ".dtrace_pfv_argv" }, { 1, ".dtrace_ident" },
	};
	for (size_t k = 0; k < sizeof(recs) / sizeof(recs[0]); k++) {
		dtrace_prog_t *rp = recs[k].prog ? ag : pf;
		e = make_file(h, rp, recs[k].prog ? "rec-agg" : "rec-printf");
		s = find_sec(&e, recs[k].sec, 0);
		CHECK(s != 0, "%s present", recs[k].sec);
		char label[64];
		m = copy_blob(&e);
		shdr_at(&m, s)->sh_offset = (Elf64_Off)m.n + 4096;
		snprintf(label, sizeof(label), "%s-past-end", recs[k].sec + 1);
		expect_reject(h, label, &m, E_HYPERTRACE_ELFPARSE, "", rp);
	}
	dtrace_close(h);
}

/* ---------------------------------------------------------------------
 * Options (process-global tables: one variant per process).
 */
struct optcase {
	const char *name;
	const char *value;
};

static const struct optcase opt_rt_null[] = {
	{ "destructive", NULL }, { "bufsize", "4m" }, { "nspec", "2" },
	{ NULL, NULL } };
static const struct optcase opt_drt_null[] = {
	{ "quiet", NULL }, { NULL, NULL } };
static const struct optcase opt_ct[] = {
	{ "define", "HT_A=1" }, { "incdir", "/usr/obj" }, { "undef", "HT_B" },
	{ "zdefs", NULL }, { "flowindent", NULL }, { "rawbytes", NULL },
	{ "switchrate", "10hz" }, { NULL, NULL } };

static int64_t
getopt_value(dtrace_hdl_t *h, const char *name)
{
	dtrace_optval_t v = -2;
	if (dtrace_getopt(h, name, &v) != 0)
		return (-3);
	return (v);
}

static void
scenario_options(const char *variant)
{
	const struct optcase *set = strcmp(variant, "rt-null") == 0 ? opt_rt_null :
	    strcmp(variant, "drt-null") == 0 ? opt_drt_null : opt_ct;
	dtrace_hdl_t *host = open_handle(1);
	char msg[HYPERTRACE_ERRMSGLEN];
	int err;
	dtrace_enable_hypertrace(host);
	for (const struct optcase *o = set; o->name; o++)
		CHECK(dtrace_setopt(host, o->name, o->value) == 0, "setopt %s",
		    o->name);
	dtrace_prog_t *p = compile(host, corpus[0]);
	const char *path = path_of("options-%s.elf", variant);
	CHECK(create_file(host, p, path, msg) == 0, "options create %s", msg);
	write_manifest(path, p);
	blob_t e = slurp(path);
	unsigned s = find_sec(&e, ".dtrace_opts", 0);
	CHECK(s != 0, "options section present");
	/* Every set option is serialized once, in table order. */
	int records = 0;
	for (size_t off = 0; off < shdr_at(&e, s)->sh_size;) {
		struct { char n[64]; uint64_t o; size_t l; } *r =
		    (void *)((char *)sec_data(&e, s) + off);
		int known = 0;
		for (const struct optcase *o = set; o->name; o++)
			known |= strcmp(o->name, r->n) == 0;
		CHECK(known, "unexpected option record %s", r->n);
		records++;
		off += sizeof(*r) + r->l;
	}
	int nset = 0;
	for (const struct optcase *o = set; o->name; o++)
		nset++;
	CHECK(records == nset, "option records %d != %d", records, nset);

	dtrace_hdl_t *guest = open_handle(1);
	dtrace_set_guest(guest);
	/* Reference: the same options set directly on a guest handle. */
	dtrace_hdl_t *ref = open_handle(1);
	for (const struct optcase *o = set; o->name; o++)
		(void)dtrace_setopt(ref, o->name, o->value);
	const char *probe[] = { "destructive", "bufsize", "quiet", "flowindent",
	    "rawbytes", NULL };
	int64_t before[8];
	for (int i = 0; probe[i]; i++)
		before[i] = getopt_value(guest, probe[i]);
	/* An active guest handle must not change its options. */
	guest->dt_active = 1;
	dtrace_prog_t *q = parse_file(guest, path, 0, &err, msg, NULL);
	CHECK(q != NULL, "active guest parse %s", msg);
	for (int i = 0; probe[i]; i++)
		CHECK(getopt_value(guest, probe[i]) == before[i],
		    "active guest changed %s", probe[i]);
	guest->dt_active = 0;
	q = parse_file(guest, path, 0, &err, msg, NULL);
	CHECK(q != NULL, "guest parse %s", msg);
	for (int i = 0; probe[i]; i++)
		CHECK(getopt_value(guest, probe[i]) ==
		    getopt_value(ref, probe[i]), "guest option %s %jd != %jd",
		    probe[i], (intmax_t)getopt_value(guest, probe[i]),
		    (intmax_t)getopt_value(ref, probe[i]));

	/* Malformed option sections. */
	size_t first = 0;
	{
		struct { char n[64]; uint64_t o; size_t l; } *r = sec_data(&e, s);
		first = sizeof(*r) + r->l;
	}
	blob_t m = copy_blob(&e);
	strlcpy((char *)sec_data(&m, s), "nosuchoption", 64);
	expect_reject(guest, "option-unknown", &m, E_HYPERTRACE_LIBDTRACE,
	    "dtrace_setopt(nosuchoption): failed", NULL);
	m = copy_blob(&e);
	((char *)sec_data(&m, s))[0] = '\0';
	q = expect_accept(guest, "option-unnamed", &m, NULL);
	if (records > 1) {
		m = copy_blob(&e);
		size_t *l = (size_t *)((char *)sec_data(&m, s) + 72);
		*l += 1;
		expect_reject(guest, "option-misaligned", &m,
		    E_HYPERTRACE_ELFPARSE, "truncated or misaligned option", NULL);
		m = copy_blob(&e);
		shdr_at(&m, s)->sh_size = first + 8;
		expect_reject(guest, "option-truncated", &m,
		    E_HYPERTRACE_ELFPARSE, "truncated or misaligned option", NULL);
	}
	m = copy_blob(&e);
	memset(sec_data(&m, s), 'N', 64);
	expect_reject(guest, "option-name-unterminated", &m,
	    E_HYPERTRACE_ELFPARSE, "invalid option name, length or argument",
	    NULL);
	/* An empty option section sets nothing. */
	m = copy_blob(&e);
	shdr_at(&m, s)->sh_size = 0;
	q = expect_accept(guest, "option-empty", &m, NULL);
	m = copy_blob(&e);
	shdr_at(&m, s)->sh_type = SHT_NOBITS;
	expect_reject(guest, "option-nobits", &m, E_HYPERTRACE_ELFPARSE,
	    "missing option section data", NULL);
	m = copy_blob(&e);
	shdr_at(&m, s)->sh_offset = (Elf32_Off)(m.n + 4096);
	expect_reject(guest, "option-beyond-file", &m, E_HYPERTRACE_ELFPARSE,
	    "elf_getdata(", NULL);
	dtrace_close(guest);
	dtrace_close(ref);
	dtrace_close(host);
}

/* ---------------------------------------------------------------------
 * Input channels and the checksum wrapper.
 */
static const char *io_base, *io_sum;
static dtrace_prog_t *io_prog;

static void
write_checksummed(const char *dst, const char *src)
{
	blob_t e = slurp(src);
	unsigned char *buf = malloc(e.n + 32);
	SHA256(e.b, e.n, buf);
	memcpy(buf + 32, e.b, e.n);
	spit(dst, buf, e.n + 32);
	free(buf);
	free(e.b);
}

struct iocase {
	const char *label;
	const char *fn;		/* injected function, NULL for none */
	long nth;
	int mode;
	int checksummed;
	int want;		/* expected error class, 0 for success */
	const char *text;
};

static const struct iocase iocases[] = {
	/* EINTR is retried, for plain and checksummed input. */
	{ "read-eintr", "read", 0, 1, 0, 0, NULL },
	{ "read-error", "read", 0, 0, 0, E_HYPERTRACE_ELFPARSE, "read(" },
	{ "read-eintr-sum", "read", 1, 1, 1, 0, NULL },
	{ "read-eof-sum-body", "read", 2, 2, 1, E_HYPERTRACE_SYS, "read(" },
	{ "write-eintr-temp", "write", 0, 1, 1, 0, NULL },
	{ "write-zero-temp", "write", 0, 2, 1, E_HYPERTRACE_SYS, "write(" },
	{ "write-fail-temp", "write", 0, 0, 1, E_HYPERTRACE_SYS, "write(" },
	{ "mkstemp", "mkstemp", 0, 0, 1, E_HYPERTRACE_SYS, "mkstemp(" },
	{ "unlink", "unlink", 0, 0, 1, E_HYPERTRACE_SYS, "unlink(" },
	{ "fstat-program", "fstat", 0, 0, 0, E_HYPERTRACE_SYS, "fstat(" },
	{ "fstat-checksum", "fstat", 1, 0, 1, E_HYPERTRACE_SYS, "fstat(" },
	{ "lseek-start", "lseek", 0, 0, 0, E_HYPERTRACE_ELFPARSE, "lseek(" },
	{ "lseek-checksum", "lseek", 1, 0, 1, E_HYPERTRACE_CHECKSUM, "lseek(" },
	{ "lseek-body", "lseek", 2, 0, 1, E_HYPERTRACE_CHECKSUM, "lseek(" },
	{ "lseek-elf", "lseek", 1, 0, 0, E_HYPERTRACE_ELFPARSE, "lseek(" },
	{ "sha256", "SHA256", 0, 0, 1, E_HYPERTRACE_CHECKSUM, "SHA256(" },
	{ "elf-version", "elf_version", 0, 0, 0, E_HYPERTRACE_ELFPARSE,
	    "elf_version(" },
	{ "elf-kind", "elf_kind", 0, 0, 0, E_HYPERTRACE_ELFPARSE, "elf_kind(" },
	{ "elf-class", "gelf_getclass", 0, 0, 0, E_HYPERTRACE_ELFPARSE,
	    "gelf_getclass(" },
	{ "shdrstrndx", "elf_getshdrstrndx", 0, 0, 0, E_HYPERTRACE_ELFPARSE,
	    "elf_getshdrstrndx(" },
	{ "shdrnum", "elf_getshdrnum", 0, 0, 0, E_HYPERTRACE_ELFPARSE,
	    "elf_getshdrnum(" },
	{ "getshdr-scan", "gelf_getshdr", 0, 0, 0, E_HYPERTRACE_ELFPARSE,
	    "gelf_getshdr(" },
};

static void
io_case(void *arg)
{
	const struct iocase *c = arg;
	dtrace_hdl_t *h = open_handle(1);
	char msg[HYPERTRACE_ERRMSGLEN];
	int err;
	const char *path = c->checksummed ? io_sum : io_base;
	int fd = open(path, O_RDONLY);
	fault_forget_all();
	fault_track(1);
	if (c->fn != NULL)
		fault_arm(c->fn, c->nth, c->mode);
	dtrace_prog_t *q = parse_fd(h, fd, path, 0, &err, msg, NULL);
	int fired = fault_disarm();
	CHECK(c->fn == NULL || fired, "%s: fault not reached", c->label);
	if (c->want == 0) {
		CHECK(q != NULL, "%s: rejected %d %s", c->label, err, msg);
		if (q != NULL) {
			compare_programs(c->label, io_prog, q);
			dt_program_destroy(h, q);
		}
	} else {
		CHECK(q == NULL && err == c->want && strstr(msg, c->text) != NULL,
		    "%s: err=%d msg='%s'", c->label, err, msg);
	}
	fault_track(0);
	CHECK(fault_live() == 0, "%s: leaked %ld", c->label, fault_live());
	close(fd);
	dtrace_close(h);
}

static void
io_special(void *arg)
{
	(void)arg;
	dtrace_hdl_t *h = open_handle(1);
	char msg[HYPERTRACE_ERRMSGLEN];
	int err;
	/* A seekable non-regular file is not a checksummed program. */
	int fd = open("/dev/zero", O_RDONLY);
	dtrace_prog_t *q = parse_fd(h, fd, "/dev/zero", 0, &err, msg, NULL);
	CHECK(q == NULL && err == E_HYPERTRACE_CHECKSUM &&
	    strstr(msg, "invalid checksummed file size") != NULL,
	    "/dev/zero: %d %s", err, msg);
	close(fd);
	/* A pipe cannot be rewound. */
	int pfd[2];
	pipe(pfd);
	write(pfd[1], "\177ELF", 4);
	q = parse_fd(h, pfd[0], "pipe", 0, &err, msg, NULL);
	CHECK(q == NULL && err == E_HYPERTRACE_ELFPARSE &&
	    strstr(msg, "lseek(") != NULL, "pipe: %d %s", err, msg);
	/* Larger than the transport bound (sparse file). */
	const char *big = path_of("oversized-checksummed.bin");
	fd = open(big, O_RDWR | O_CREAT | O_TRUNC, 0600);
	ftruncate(fd, 64 * 1024 * 1024 + 1);
	q = parse_fd(h, fd, big, 0, &err, msg, NULL);
	CHECK(q == NULL && err == E_HYPERTRACE_CHECKSUM &&
	    strstr(msg, "invalid checksummed file size") != NULL,
	    "oversized: %d %s", err, msg);
	close(fd);
	unlink(big);
	/* Checksum over bytes that start like ELF but are not valid. */
	unsigned char junk[64];
	memset(junk, 0, sizeof(junk));
	memcpy(junk + 32, "\177ELFjunk", 8);
	SHA256(junk + 32, 32, junk);
	const char *jp = path_of("checksummed-junk.bin");
	spit(jp, junk, sizeof(junk));
	q = parse_file(h, jp, 0, &err, msg, NULL);
	CHECK(q == NULL && err == E_HYPERTRACE_ELFPARSE &&
	    strstr(msg, "elf_begin(") != NULL, "junk: %d %s", err, msg);
	/* A checksum mismatch in the 3rd and 4th magic bytes. */
	for (int i = 1; i < 4; i++) {
		memcpy(junk + 32, "\177ELF", 4);
		junk[32 + i] = 'x';
		spit(jp, junk, sizeof(junk));
		q = parse_file(h, jp, 0, &err, msg, NULL);
		CHECK(q == NULL && err == E_HYPERTRACE_ELFPARSE &&
		    strstr(msg, "not an ELF file") != NULL, "magic %d: %s", i,
		    msg);
	}
	dtrace_close(h);
}

static void
scenario_io(void)
{
	dtrace_hdl_t *h = open_handle(1);
	char msg[HYPERTRACE_ERRMSGLEN];
	io_prog = compile(h, corpus[2]);
	io_base = strdup(path_of("io-base.elf"));
	io_sum = strdup(path_of("io-base.sum"));
	CHECK(create_file(h, io_prog, io_base, msg) == 0, "io base");
	write_checksummed(io_sum, io_base);
	for (size_t i = 0; i < sizeof(iocases) / sizeof(iocases[0]); i++)
		in_child(iocases[i].label, io_case, (void *)&iocases[i]);
	in_child("io-special", io_special, NULL);
}

/* ---------------------------------------------------------------------
 * Fault matrices.  For each program and injected function, the Nth call
 * fails for N = 0, 1, ... until a run no longer reaches the Nth call.
 */
struct wfn {
	const char *fn;
	const char *text;	/* message of the failing call, NULL: any */
	int code;		/* expected class, -1: any non-zero */
};

static const struct wfn writer_fns[] = {
	{ "dt_alloc", "allocation failed", E_HYPERTRACE_SYS },
	{ "calloc", "malloc for eop failed", E_HYPERTRACE_SYS },
	{ "elf_version", "elf_version(", E_HYPERTRACE_ELFCREATE },
	{ "elf_begin", "elf_begin(", E_HYPERTRACE_ELFCREATE },
	{ "elf32_newehdr", "elf32_newehdr(", E_HYPERTRACE_ELFCREATE },
	{ "elf32_newphdr", "elf_newphdr(", E_HYPERTRACE_ELFCREATE },
	{ "elf_newscn", "elf_newscn(", E_HYPERTRACE_ELFCREATE },
	{ "elf_newdata", "elf_newdata(", E_HYPERTRACE_ELFCREATE },
	{ "elf32_getshdr", "elf32_getshdr(", E_HYPERTRACE_ELFCREATE },
	{ "elf_getdata", "elf_getdata(", E_HYPERTRACE_ELFCREATE },
	{ "elf_getscn", "elf32_getshdr(", E_HYPERTRACE_ELFCREATE },
	{ "elf_update", "elf_update(", E_HYPERTRACE_ELFCREATE },
	{ "new", "ELF writer allocation failed", E_HYPERTRACE_SYS },
};

/* Writer programs: printf with prefixes, aggregation identifiers, shared
 * ECBs with predicates, and (in the options process) exported options. */
static const char *const writer_programs[] = {
	"BEGIN { printf(\"a=%d b=%s c=%x\\n\", 1, \"s\", 2); }",
	"BEGIN { @c[1, \"k\"] = count(); printa(\"%d %s %@d\\n\", @c); }",
	"BEGIN /timestamp != 0/ { x = timestamp; self->y = x; trace(x); "
	    "trace(\"s\"); trace(self->y); }",
	"BEGIN { printf(\"%d\", 1); }",
};

static dtrace_hdl_t *mx_h;
static dtrace_prog_t *mx_prog;
static const struct wfn *mx_fn;
static long mx_nth;
static const char *mx_label;

/* Exit status: 0 fault handled, 2 fault not reached (success checked). */
static void
writer_fault_child(void *arg)
{
	(void)arg;
	char msg[HYPERTRACE_ERRMSGLEN];
	int err;
	const char *path = path_of("wfault-%s-%s-%ld.elf", mx_label,
	    mx_fn->fn, mx_nth);
	fault_forget_all();
	fault_track(1);
	fault_arm(mx_fn->fn, mx_nth, 0);
	int r = create_file(mx_h, mx_prog, path, msg);
	int fired = fault_disarm();
	fault_track(0);
	CHECK(fault_live() == 0, "%s %s#%ld: writer leaked %ld", mx_label,
	    mx_fn->fn, mx_nth, fault_live());
	if (fired && r != 0) {
		CHECK(msg[0] != '\0' &&
		    (mx_fn->code == -1 || r == mx_fn->code) &&
		    (mx_fn->text == NULL || strstr(msg, mx_fn->text) != NULL),
		    "%s %s#%ld: r=%d msg='%s'", mx_label, mx_fn->fn, mx_nth, r,
		    msg);
		unlink(path);
		return;
	}
	if (fired) {
		/* A tolerated failure must still yield a faithful file. */
		dtrace_prog_t *q = parse_file(mx_h, path, 0, &err, msg, mx_prog);
		CHECK(q != NULL, "%s %s#%ld: success reported for an "
		    "unparseable file: %s", mx_label, mx_fn->fn, mx_nth, msg);
		if (q != NULL)
			compare_programs(mx_label, mx_prog, q);
		tolerated++;
		unlink(path);
		return;
	}
	CHECK(r == 0, "%s %s#%ld: unfaulted create %d %s", mx_label,
	    mx_fn->fn, mx_nth, r, msg);
	dtrace_prog_t *q = parse_file(mx_h, path, 0, &err, msg, mx_prog);
	CHECK(q != NULL, "%s: unfaulted parse %s", mx_label, msg);
	if (q != NULL)
		compare_programs(mx_label, mx_prog, q);
	unlink(path);
	fflush(stdout);
	exit(failures ? 3 : 2);
}

static long
fault_loop(const char *what, void (*child)(void *))
{
	long n;
	for (n = 0; n < 4096; n++) {
		mx_nth = n;
		fflush(stdout);
		pid_t pid = fork();
		if (pid == 0) {
			failures = 0;
			child(NULL);
			fflush(stdout);
			exit(failures ? 1 : 0);
		}
		int st;
		waitpid(pid, &st, 0);
		checks++;
		if (WIFEXITED(st) && WEXITSTATUS(st) == 2)
			break;
		if (WIFEXITED(st) && WEXITSTATUS(st) == 3) {
			failures++;
			printf("FAIL %s %s#%ld: unfaulted run failed\n", what,
			    mx_fn->fn, n);
			break;
		}
		if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
			failures++;
			printf("FAIL %s %s#%ld: status 0x%x\n", what, mx_fn->fn,
			    n, st);
		}
	}
	return (n);
}

static void
scenario_wfault(const char *optvariant)
{
	mx_h = open_handle(1);
	if (optvariant != NULL) {
		dtrace_enable_hypertrace(mx_h);
		const struct optcase *set = strcmp(optvariant, "rt-null") == 0 ?
		    opt_rt_null : strcmp(optvariant, "drt-null") == 0 ?
		    opt_drt_null : opt_ct;
		for (const struct optcase *o = set; o->name; o++)
			(void)dtrace_setopt(mx_h, o->name, o->value);
	}
	size_t np = optvariant ? 1 : sizeof(writer_programs) /
	    sizeof(writer_programs[0]);
	for (size_t i = 0; i < np; i++) {
		char label[64];
		snprintf(label, sizeof(label), "%s%zu", optvariant ?
		    optvariant : "w", i);
		mx_label = strdup(label);
		mx_prog = compile(mx_h, writer_programs[i]);
		for (size_t f = 0; f < sizeof(writer_fns) / sizeof(writer_fns[0]);
		    f++) {
			mx_fn = &writer_fns[f];
			long n = fault_loop(label, writer_fault_child);
			printf("wfault %s %s positions %ld\n", label, mx_fn->fn, n);
		}
	}
}

static const char *const parser_fns[] = { "dt_alloc", "calloc", "strdup",
	"elf_getscn", "elf_getdata", "gelf_getshdr", "new" };
static const char *mx_path;

static void
parser_fault_child(void *arg)
{
	(void)arg;
	char msg[HYPERTRACE_ERRMSGLEN];
	int err;
	fault_forget_all();
	fault_track(1);
	int fd = open(mx_path, O_RDONLY);
	fault_arm(mx_fn->fn, mx_nth, 0);
	dtrace_prog_t *q = parse_fd(mx_h, fd, mx_path, 0, &err, msg, mx_prog);
	int fired = fault_disarm();
	close(fd);
	if (fired) {
		CHECK(q == NULL && err != 0 && msg[0] != '\0',
		    "%s %s#%ld: q=%p err=%d msg='%s'", mx_label, mx_fn->fn,
		    mx_nth, (void *)q, err, msg);
	} else {
		CHECK(q != NULL, "%s: unfaulted parse %d %s", mx_label, err, msg);
		if (q != NULL)
			compare_programs(mx_label, mx_prog, q);
	}
	if (q != NULL)
		dt_program_destroy(mx_h, q);
	fault_track(0);
	CHECK(fault_live() == 0, "%s %s#%ld: parser leaked %ld", mx_label,
	    mx_fn->fn, mx_nth, fault_live());
	if (!fired) {
		fflush(stdout);
		exit(failures ? 3 : 2);
	}
}

static void
scenario_pfault(void)
{
	mx_h = open_handle(1);
	for (size_t i = 0; i < sizeof(writer_programs) /
	    sizeof(writer_programs[0]); i++) {
		char label[64], msg[HYPERTRACE_ERRMSGLEN];
		snprintf(label, sizeof(label), "p%zu", i);
		mx_label = strdup(label);
		mx_prog = compile(mx_h, writer_programs[i]);
		if (i == 0) {
			/* Enabled probes are copied into a new allocation. */
			mx_prog->dp_neprobes = 2;
			mx_prog->dp_eprobes = calloc(2, sizeof(dtrace_probedesc_t));
			mx_prog->dp_eprobes[1].dtpd_id = 7;
		}
		mx_path = strdup(path_of("pfault-%zu.elf", i));
		CHECK(create_file(mx_h, mx_prog, mx_path, msg) == 0,
		    "pfault base %s", msg);
		struct wfn w = { NULL, NULL, -1 };
		for (size_t f = 0; f < sizeof(parser_fns) / sizeof(parser_fns[0]);
		    f++) {
			w.fn = parser_fns[f];
			mx_fn = &w;
			long n = fault_loop(label, parser_fault_child);
			printf("pfault %s %s positions %ld\n", label, w.fn, n);
		}
	}
}

int
main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "usage: %s scenario outdir [variant]\n", argv[0]);
		return (2);
	}
	outdir = argv[2];
	load_shim();
	setvbuf(stdout, NULL, _IOLBF, 0);
	const char *sc = argv[1];
	if (strcmp(sc, "roundtrip") == 0)
		scenario_roundtrip();
	else if (strcmp(sc, "crafted") == 0)
		scenario_crafted();
	else if (strcmp(sc, "mutate") == 0)
		scenario_mutate();
	else if (strcmp(sc, "options") == 0 && argc == 4)
		scenario_options(argv[3]);
	else if (strcmp(sc, "logged") == 0)
		scenario_logged();
	else if (strcmp(sc, "io") == 0)
		scenario_io();
	else if (strcmp(sc, "wfault") == 0)
		scenario_wfault(argc == 4 ? argv[3] : NULL);
	else if (strcmp(sc, "pfault") == 0)
		scenario_pfault();
	else {
		fprintf(stderr, "unknown scenario %s\n", sc);
		return (2);
	}
	printf("%s %s: %d checks, %d failures\n", failures ? "FAIL" : "PASS",
	    sc, checks, failures);
	return (failures ? 1 : 0);
}
