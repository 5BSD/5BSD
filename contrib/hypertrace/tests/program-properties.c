/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Property and contract tests for program construction, DOF generation,
 * program analysis and the open-addressing hash map in libdtrace
 * (dt_program.c, dt_dof.c, dt_analysis.c, dt_hashmap.c).
 *
 * Every expected value is derived independently of the code under test:
 *  - hash map: the C side logs each operation, its result and the table
 *    layout; program-properties.py replays the log against its own
 *    MurmurHash3_x86_32 + linear probing + backward-shift deletion model;
 *  - DOF: buffers are written to files and parsed by the driver with an
 *    independent parser that applies the dof_hdr_t/dof_sec_t layout and the
 *    link rules of the kernel loader (dtrace_dof_slurp, dtrace_dof_ecbdesc,
 *    dtrace_dof_difo, dtrace_dof_relocate) in uts/common/dtrace/dtrace.c;
 *  - headers: text expected from the documented dtrace -h layout;
 *  - analysis: Graphviz output and action dumps from the documented action
 *    classifications;
 *  - program identity: dtrace_program_compiled_digest().
 *
 * Built twice: with ASan/UBSan (all cases), and with -DPP_FAULT without
 * sanitizers, where malloc/calloc/dt_alloc/dt_zalloc are interposed to fail
 * on a chosen call (allocation-failure cases only).  NODEV/NOSYS or a model
 * vector through dtrace_vopen(); no device, kernel, daemon or guest.
 */

#include <dt_impl.h>
#include <dt_program.h>
#include <dt_provider.h>
#include <dt_printf.h>
#include <dt_hashmap.h>
#include <dt_analysis.h>
#include <dt_hypertrace.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <dev/vmm/vmm_param.h>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int dt_prog_verify(void *, dtrace_prog_t *, dtrace_prog_t *);
extern int dt_prog_verify_difo(void *, dtrace_difo_t *, dtrace_difo_t *,
    char *, char *);
extern void *dt_verictx_init(dtrace_hdl_t *);
extern void dt_verictx_teardown(void *);
extern size_t dt_verictx_mark(void *);
extern void dt_verictx_rewind(void *, size_t);
extern const char *dtrace_get_varname(uint32_t);

static int passes, failures;

static void
result(const char *name, int ok, const char *fmt, ...)
{
	va_list ap;

	if (ok) {
		passes++;
		printf("PASS %s\n", name);
		return;
	}
	failures++;
	printf("FAIL %s: ", name);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

#define	CHECK(name, cond)	result((name), (cond), "%s (line %d)", #cond, \
	__LINE__)

/* ------------------------------------------------------------------ */
/* Allocation fault injection (PP_FAULT build only).                   */

#ifdef PP_FAULT
static int fail_at = -1;	/* fail the Nth counted allocation */
static int alloc_count;
static int fault_hit;

static int
should_fail(void)
{
	if (fail_at < 0)
		return (0);
	if (alloc_count++ == fail_at) {
		fault_hit = 1;
		return (1);
	}
	return (0);
}

void *
malloc(size_t n)
{
	static void *(*real)(size_t);

	if (real == NULL)
		real = (void *(*)(size_t))dlsym(RTLD_NEXT, "malloc");
	if (should_fail()) {
		errno = ENOMEM;
		return (NULL);
	}
	return (real(n));
}

void *
calloc(size_t n, size_t s)
{
	static void *(*real)(size_t, size_t);

	if (real == NULL)
		real = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
	if (should_fail()) {
		errno = ENOMEM;
		return (NULL);
	}
	return (real(n, s));
}

/* fault_hit accumulates over every armed window of one scenario run. */
void *
realloc(void *p, size_t n)
{
	static void *(*real)(void *, size_t);

	if (real == NULL)
		real = (void *(*)(void *, size_t))dlsym(RTLD_NEXT, "realloc");
	if (should_fail()) {
		errno = ENOMEM;
		return (NULL);
	}
	return (real(p, n));
}

static void
arm(int n)
{
	fail_at = n;
	alloc_count = 0;
}

static void
disarm(void)
{
	fail_at = -1;
}
#endif

/* ------------------------------------------------------------------ */
/* Helpers.                                                            */

static dtrace_hdl_t *
open_nodev(void)
{
	int err;
	dtrace_hdl_t *dtp = dtrace_open(DTRACE_VERSION,
	    DTRACE_O_NODEV | DTRACE_O_NOSYS, &err);

	if (dtp == NULL) {
		fprintf(stderr, "dtrace_open: %s\n", dtrace_errmsg(NULL, err));
		exit(2);
	}
	return (dtp);
}

static dtrace_prog_t *
compile(dtrace_hdl_t *dtp, const char *src, uint_t cflags)
{
	dtrace_prog_t *p = dtrace_program_strcompile(dtp, src,
	    DTRACE_PROBESPEC_NAME, cflags | DTRACE_C_ZDEFS, 0, NULL);

	if (p == NULL)
		fprintf(stderr, "compile [%s]: %s\n", src,
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
	return (p);
}

/* Capture stderr written while fn runs. */
static char *
capture_stderr(void (*fn)(void *), void *arg)
{
	char path[] = "stderr-XXXXXX";
	int fd = mkstemp(path), saved;
	struct stat sb;
	char *buf;

	if (fd < 0)
		abort();
	fflush(stderr);
	saved = dup(2);
	dup2(fd, 2);
	fn(arg);
	fflush(stderr);
	dup2(saved, 2);
	close(saved);
	fstat(fd, &sb);
	buf = calloc(1, sb.st_size + 1);
	pread(fd, buf, sb.st_size, 0);
	close(fd);
	unlink(path);
	return (buf);
}

static char *
capture_file(void (*fn)(FILE *, void *), void *arg)
{
	char *buf = NULL;
	size_t len = 0;
	FILE *fp = open_memstream(&buf, &len);

	fn(fp, arg);
	fclose(fp);
	return (buf);
}

static void
write_blob(const char *path, const void *p, size_t n)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	if (fd < 0 || write(fd, p, n) != (ssize_t)n)
		abort();
	close(fd);
}

/* A stream whose writes fail after a byte budget (for fprintf errors). */
static int budget;

static int
budget_write(void *cookie, const char *buf, int len)
{
	(void) cookie;
	(void) buf;
	if (budget < len) {
		errno = ENOSPC;
		return (-1);
	}
	budget -= len;
	return (len);
}

static FILE *
budget_stream(int n)
{
	FILE *fp = funopen(NULL, NULL, budget_write, NULL, NULL);

	budget = n;
	setvbuf(fp, NULL, _IONBF, 0);
	return (fp);
}

/* ------------------------------------------------------------------ */
/* dt_hashmap: logged operations for the Python reference model.       */

static FILE *hlog;

static void
hex(FILE *fp, const unsigned char *k, size_t n)
{
	for (size_t i = 0; i < n; i++)
		fprintf(fp, "%02x", k[i]);
}

static void
snapshot(dt_hashmap_t *hm, unsigned char (*pool)[32])
{
	fprintf(hlog, "T");
	for (size_t i = 0; i < hm->dthm_size; i++) {
		dt_hashbucket_t *b = &hm->dthm_table[i];

		if (b->key == NULL)
			continue;
		fprintf(hlog, " %zu:", i);
		hex(hlog, b->key, b->keysize);
		fprintf(hlog, ":%lu", (unsigned long)(uintptr_t)b->data);
		/* Unmanaged keys must be the caller's own storage. */
		if (pool != NULL && !b->key_ismanaged &&
		    ((unsigned char *)b->key < pool[0] ||
		    (unsigned char *)b->key >= pool[12]))
			fprintf(hlog, ":copied");
	}
	fprintf(hlog, " n=%zu\n", hm->dthm_nitems);
}

static uint64_t rng = 0x5bd1e995;

static uint32_t
next_rand(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return ((uint32_t)rng);
}

static int
count_cb(void *k, size_t ks, void *d, void *arg)
{
	(void) k;
	(void) ks;
	(void) d;
	return (++*(int *)arg >= 3 ? -7 : 0);
}

static void
hashmap_property(size_t size, size_t keylen, int unaligned, uint32_t flags,
    int nops)
{
	static unsigned char storage[64 * 32 + 1];
	unsigned char (*pool)[32] = (unsigned char (*)[32])(storage +
	    (unaligned ? 1 : 0));
	dt_hashmap_t *hm = dt_hashmap_create(size);
	int npool = 12;

	fprintf(hlog, "MAP %zu %zu %u %d\n", size, keylen, flags, unaligned);
	/* A small key universe so collisions, duplicates and misses occur. */
	for (int i = 0; i < npool; i++)
		for (size_t j = 0; j < keylen; j++)
			pool[i][j] = (unsigned char)next_rand();
	for (int op = 0; op < nops; op++) {
		int k = next_rand() % npool, what = next_rand() % 3;
		void *r;

		if (what == 0) {
			int rc = dt_hashmap_insert(hm, pool[k], keylen,
			    (void *)(uintptr_t)(op + 1), flags);

			fprintf(hlog, "I ");
			hex(hlog, pool[k], keylen);
			fprintf(hlog, " %d %d\n", op + 1, rc);
		} else if (what == 1) {
			r = dt_hashmap_lookup(hm, pool[k], keylen);
			fprintf(hlog, "L ");
			hex(hlog, pool[k], keylen);
			fprintf(hlog, " %lu\n", (unsigned long)(uintptr_t)r);
		} else {
			r = dt_hashmap_delete(hm, pool[k], keylen);
			fprintf(hlog, "D ");
			hex(hlog, pool[k], keylen);
			fprintf(hlog, " %lu\n", (unsigned long)(uintptr_t)r);
		}
		snapshot(hm, (flags & DTH_MANAGED) ? NULL : pool);
	}
	dt_hashmap_free(hm, 1);
}

static void
dump_cb(void *arg)
{
	dt_hashmap_dump(arg, "hm");
}

static void
case_hashmap(void)
{
	dt_hashmap_t *hm;
	unsigned char a[8] = "abcdefg", b[8] = "abcdefg", c[8] = "zzzzzzz";
	int n = 0;
	char *dump;

	hlog = fopen("hashmap.log", "w");
	hashmap_property(7, 3, 0, DTH_MANAGED, 400);
	hashmap_property(5, 4, 0, DTH_MANAGED, 400);
	hashmap_property(5, 8, 1, DTH_MANAGED, 400);
	hashmap_property(16, 8, 0, 0, 400);
	hashmap_property(3, 5, 0, 0, 300);
	hashmap_property(1, 2, 0, DTH_MANAGED, 50);
	hashmap_property(64, 1, 0, DTH_MANAGED, 600);
	fclose(hlog);

	errno = 0;
	CHECK("hashmap-create-zero", dt_hashmap_create(0) == NULL &&
	    errno == EINVAL);
	hm = dt_hashmap_create(4);
	CHECK("hashmap-flags-exclusive", dt_hashmap_insert(hm, a, 8, a,
	    DTH_MANAGED | DTH_POINTER) == EINVAL && hm->dthm_nitems == 0);

	/*
	 * DTH_POINTER keys are compared by identity (dt_hashmap.h): two
	 * equal-content keys at different addresses are distinct entries and
	 * each is found, and deleted, only through its own pointer.
	 */
	CHECK("hashmap-pointer-insert", dt_hashmap_insert(hm, a, 8,
	    (void *)1, DTH_POINTER) == 0 && dt_hashmap_insert(hm, b, 8,
	    (void *)2, DTH_POINTER) == 0 && hm->dthm_nitems == 2);
	CHECK("hashmap-pointer-identity",
	    dt_hashmap_lookup(hm, a, 8) == (void *)1 &&
	    dt_hashmap_lookup(hm, b, 8) == (void *)2 &&
	    dt_hashmap_lookup(hm, c, 8) == NULL);
	CHECK("hashmap-pointer-delete", dt_hashmap_delete(hm, b, 8) ==
	    (void *)2 && dt_hashmap_lookup(hm, b, 8) == NULL &&
	    dt_hashmap_lookup(hm, a, 8) == (void *)1 && hm->dthm_nitems == 1);
	/* Re-inserting the same pointer is a no-op that keeps the value. */
	CHECK("hashmap-pointer-reinsert", dt_hashmap_insert(hm, a, 8,
	    (void *)9, DTH_POINTER) == 0 && dt_hashmap_lookup(hm, a, 8) ==
	    (void *)1 && hm->dthm_nitems == 1);
	dt_hashmap_free(hm, 0);

	/*
	 * A key's hash depends only on its bytes: an entry inserted through a
	 * 32-bit aligned key is found, and deleted, through an unaligned copy
	 * of the same bytes (and vice versa), for every multiple-of-4 length.
	 */
	{
		static uint32_t aligned[64];
		static unsigned char shifted[64 * 4 + 1];
		int found = 0, deleted = 0, tried = 0;

		hm = dt_hashmap_create(1021);
		for (uint32_t len = 4; len <= 16; len += 4) {
			for (uint32_t v = 0; v < 16; v++, tried++) {
				for (uint32_t j = 0; j < len / 4; j++)
					aligned[j] = v * 2654435761u + j + len;
				memcpy(shifted + 1, aligned, len);
				dt_hashmap_insert(hm, aligned, len,
				    (void *)(uintptr_t)(v + 1), DTH_MANAGED);
				found += dt_hashmap_lookup(hm, shifted + 1, len) ==
				    (void *)(uintptr_t)(v + 1);
				deleted += dt_hashmap_delete(hm, shifted + 1,
				    len) == (void *)(uintptr_t)(v + 1);
				dt_hashmap_insert(hm, shifted + 1, len,
				    (void *)(uintptr_t)(v + 1), DTH_MANAGED);
				found += dt_hashmap_lookup(hm, aligned, len) ==
				    (void *)(uintptr_t)(v + 1);
				deleted += dt_hashmap_delete(hm, aligned, len) ==
				    (void *)(uintptr_t)(v + 1);
			}
			/* Each length needs its own map (one key size per map). */
			dt_hashmap_free(hm, 1);
			hm = dt_hashmap_create(1021);
		}
		CHECK("hashmap-alignment-independent", found == 2 * tried &&
		    deleted == 2 * tried && hm->dthm_nitems == 0);
		dt_hashmap_free(hm, 1);
	}

	/* Full table: inserting a new key fails with ENOSPC, lookups miss. */
	hm = dt_hashmap_create(2);
	{
		static uint32_t k[3] = { 1, 2, 3 };

		CHECK("hashmap-full", dt_hashmap_insert(hm, &k[0], 4,
		    (void *)1, DTH_MANAGED) == 0 && dt_hashmap_insert(hm, &k[1],
		    4, (void *)2, DTH_MANAGED) == 0 && dt_hashmap_insert(hm,
		    &k[2], 4, (void *)3, DTH_MANAGED) == ENOSPC &&
		    dt_hashmap_lookup(hm, &k[2], 4) == NULL &&
		    dt_hashmap_delete(hm, &k[2], 4) == NULL &&
		    dt_hashmap_insert(hm, &k[1], 4, (void *)5, DTH_MANAGED) ==
		    0 && dt_hashmap_lookup(hm, &k[1], 4) == (void *)2);
		/* Iteration visits occupied buckets and stops on < 0. */
		CHECK("hashmap-iter-all", dt_hashmap_iter(hm, count_cb, &n) ==
		    0 && n == 2);
		dump = capture_stderr(dump_cb, hm);
		CHECK("hashmap-dump", dump != NULL &&
		    strstr(dump, "hm[0] = [") != NULL &&
		    strstr(dump, "hm[1] = [") != NULL &&
		    strstr(dump, ", 4] => 0x") != NULL);
		free(dump);
	}
	dt_hashmap_free(hm, 1);
	/* Only occupied buckets are dumped. */
	hm = dt_hashmap_create(16);
	{
		static uint32_t one = 1;

		dt_hashmap_insert(hm, &one, 4, (void *)1, 0);
		dump = capture_stderr(dump_cb, hm);
		CHECK("hashmap-dump-sparse", dump != NULL &&
		    strchr(dump, '\n') != NULL &&
		    strchr(dump, '\n')[1] == '\0');
		free(dump);
	}
	dt_hashmap_free(hm, 0);
	hm = dt_hashmap_create(8);
	for (uint32_t i = 0; i < 5; i++) {
		static uint32_t k[5];

		k[i] = i * 77;
		dt_hashmap_insert(hm, &k[i], 4, (void *)(uintptr_t)(i + 1), 0);
	}
	n = 0;
	CHECK("hashmap-iter-stop", dt_hashmap_iter(hm, count_cb, &n) == -7 &&
	    n == 3);
	dt_hashmap_free(hm, 0);
}

/* ------------------------------------------------------------------ */
/* dt_analysis.                                                        */

struct graph_arg {
	dtrace_hdl_t *dtp;
	dtrace_prog_t *pgp;
};

static void
graph_fn(FILE *fp, void *arg)
{
	struct graph_arg *g = arg;

	dtrace_graph_program(g->dtp, g->pgp, fp);
}

static void
dump_actions_fn(void *arg)
{
	dtrace_dump_actions(arg);
}

static void
dump_ecbs_fn(void *arg)
{
	dtrace_dump_ecbs(arg);
}

static dtrace_difo_t *
make_difo(const dif_instr_t *code, size_t n)
{
	dtrace_difo_t *dp = calloc(1, sizeof (*dp));

	dp->dtdo_buf = malloc(n * sizeof (dif_instr_t));
	memcpy(dp->dtdo_buf, code, n * sizeof (dif_instr_t));
	dp->dtdo_len = n;
	dp->dtdo_refcnt = 1;
	return (dp);
}

/* Append one statement with the given actions to a program. */
static dtrace_stmtdesc_t *
add_stmt(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, const char *target,
    const char *prov, const char *name, int nact, const int *kinds,
    dtrace_difo_t **difos, const uint64_t *args)
{
	dtrace_probedesc_t pd;
	dtrace_ecbdesc_t *edp;
	dtrace_stmtdesc_t *sdp;

	memset(&pd, 0, sizeof (pd));
	strlcpy(pd.dtpd_target, target, sizeof (pd.dtpd_target));
	strlcpy(pd.dtpd_provider, prov, sizeof (pd.dtpd_provider));
	strlcpy(pd.dtpd_name, name, sizeof (pd.dtpd_name));
	edp = dt_ecbdesc_create(dtp, &pd);
	sdp = dtrace_stmt_create(dtp, edp);
	for (int i = 0; i < nact; i++) {
		dtrace_actdesc_t *ap = dtrace_stmt_action(dtp, sdp);

		ap->dtad_kind = kinds[i];
		ap->dtad_difo = difos != NULL ? difos[i] : NULL;
		ap->dtad_arg = args != NULL ? args[i] : 0;
	}
	dtrace_stmt_add(dtp, pgp, sdp);
	dt_ecbdesc_release(dtp, edp);
	return (sdp);
}

static void
case_analysis(void)
{
	dtrace_hdl_t *dtp = open_nodev();
	struct graph_arg g = { dtp, NULL };
	char *dot, *dump, *p;
	dtrace_prog_t *pgp;

	/*
	 * A subroutine call that is the first DIF instruction is graphed:
	 * trace(rand()) assembles to "call rand, %r1; ret %r1".
	 */
	g.pgp = compile(dtp, "BEGIN { trace(rand()); }", 0);
	dot = g.pgp ? capture_file(graph_fn, &g) : NULL;
	CHECK("graph-call-first-instruction", dot != NULL &&
	    strstr(dot, "\"rand\" [ label = \"rand()\" ];\n") != NULL &&
	    strstr(dot, "\"rand\" -> \":::BEGIN\"\n") != NULL &&
	    strstr(dot, "\":::BEGIN\" -> \"rand\"\n") != NULL);
	free(dot);

	/* Labels are exactly "name()" (no bytes past the terminator). */
	g.pgp = compile(dtp, "BEGIN { trace(strlen(\"abc\") + "
	    "rand()); }", 0);
	dot = g.pgp ? capture_file(graph_fn, &g) : NULL;
	CHECK("graph-call-labels", dot != NULL &&
	    strstr(dot, "\"strlen\" [ label = \"strlen()\" ];\n") != NULL &&
	    strstr(dot, "\"rand\" [ label = \"rand()\" ];\n") != NULL);
	free(dot);

	/*
	 * Clause-local variables are named "<probe>:<var>" (the documented
	 * prefix), so stores and loads are edges between the clause and that
	 * node, never self-edges of the probe.
	 */
	g.pgp = compile(dtp, "BEGIN { this->c = 1; trace(this->c); } "
	    "END { self->t = 2; }", 0);
	dot = g.pgp ? capture_file(graph_fn, &g) : NULL;
	CHECK("graph-clause-local", dot != NULL &&
	    strstr(dot, "\":::BEGIN:c\" [ label = \":::BEGIN:c "
	    "(clause-local)\" ];\n") != NULL &&
	    strstr(dot, "\":::BEGIN\" -> \":::BEGIN:c\"\n") != NULL &&
	    strstr(dot, "\":::BEGIN:c\" -> \":::BEGIN\"\n") != NULL &&
	    strstr(dot, "\":::BEGIN\" -> \":::BEGIN\"") == NULL &&
	    strstr(dot, "\"t\" [ label = \"t (thread-local)\" ];\n") != NULL &&
	    strstr(dot, "\":::END\" -> \"t\"\n") != NULL);
	free(dot);

	/* args[]/regs[]/uregs[] loads (LDGA), unknown arrays and scopes. */
	pgp = dt_program_create(dtp);
	{
		dif_instr_t code[] = {
			DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 3),
			DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_REGS, 4, 3),
			DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_UREGS, 5, 3),
			DIF_INSTR_LDA(DIF_OP_LDGA, 0x7f, 6, 3),
			DIF_INSTR_RET(3),
		};
		dtrace_difo_t *dp = make_difo(code, 5);
		int kinds[] = { DTRACEACT_DIFEXPR, DTRACEACT_SPECULATE,
		    DTRACEAGG_COUNT, DTRACEACT_STOP };
		dtrace_difo_t *difos[] = { dp, NULL, NULL, NULL };

		dp->dtdo_strtab = malloc(4);
		memcpy(dp->dtdo_strtab, "odd", 4);
		dp->dtdo_strlen = 4;
		dp->dtdo_vartab = calloc(1, sizeof (dtrace_difv_t));
		dp->dtdo_varlen = 1;
		dp->dtdo_vartab[0].dtdv_scope = 9;	/* not a DIFV_SCOPE_* */
		dp->dtdo_vartab[0].dtdv_flags = DIFV_F_REF;
		add_stmt(dtp, pgp, "", "test", "ldga", 4, kinds, difos, NULL);
	}
	g.pgp = pgp;
	dot = capture_file(graph_fn, &g);
	CHECK("graph-ldga-arrays", dot != NULL &&
	    strstr(dot, "\"args(2)\" [ label = \"args(2) (global)\" ];\n") !=
	    NULL && strstr(dot, "\"args(2)\" -> \"test:::ldga\"\n") != NULL &&
	    strstr(dot, "\"regs(4)\" [ label") != NULL &&
	    strstr(dot, "\"uregs(5)\" [ label") != NULL &&
	    strstr(dot, "(6)") == NULL &&
	    strstr(dot, "\"odd\" [ label = \"odd (unknown scope)\" ];\n") !=
	    NULL && strstr(dot, "\"odd\" -> \"test:::ldga\"\n") != NULL);
	free(dot);
	CHECK("varname", strcmp(dtrace_get_varname(DIF_VAR_ARGS), "args") ==
	    0 && strcmp(dtrace_get_varname(DIF_VAR_REGS), "regs") == 0 &&
	    strcmp(dtrace_get_varname(DIF_VAR_UREGS), "uregs") == 0 &&
	    dtrace_get_varname(DIF_VAR_CURTHREAD) == NULL);
	dt_program_destroy(dtp, pgp);

	/*
	 * Action dumps: one "ACTION RETURNS" block per action, followed by
	 * the action's documented heading (stack kinds print their frame
	 * count).  Built from explicit action descriptions, one per kind.
	 */
	{
		static const struct { int kind; const char *head; int difo; }
		    acts[] = {
			{ DTRACEACT_NONE, "", 0 },
			{ DTRACEACT_DIFEXPR, "", 1 },
			{ DTRACEACT_EXIT, "EXIT\n", 1 },
			{ DTRACEACT_PRINTF, "PRINTF\n", 1 },
			{ DTRACEACT_PRINTA, "PRINTA\n", 1 },
			{ DTRACEACT_TRACEMEM, "TRACEMEM\n", 1 },
			{ DTRACEACT_TRACEMEM_DYNSIZE, "TRACEMEM_DYNSIZE\n", 1 },
			{ DTRACEACT_PRINTM, "PRINTM\n", 1 },
			{ DTRACEACT_STACK, "STACK 7\n", 0 },
			{ DTRACEACT_USTACK, "USTACK 7\n", 0 },
			{ DTRACEACT_JSTACK, "JSTACK 7\n", 0 },
			{ DTRACEACT_IMMSTACK, "IMMSTACK 7\n", 0 },
			{ DTRACEACT_PRINTIMMSTACK, "PRINTIMMSTACK\n", 0 },
			{ DTRACEAGG_COUNT, "COUNT\n", 0 },
			{ DTRACEAGG_MIN, "MIN\n", 1 },
			{ DTRACEAGG_MAX, "MAX\n", 1 },
			{ DTRACEAGG_AVG, "AVG\n", 1 },
			{ DTRACEAGG_SUM, "SUM\n", 1 },
			{ DTRACEAGG_STDDEV, "STDDEV\n", 1 },
			{ DTRACEAGG_QUANTIZE, "quantize( ): (7, ", 1 },
			{ DTRACEAGG_LQUANTIZE, "LQUANTIZE\n", 1 },
			{ DTRACEAGG_LLQUANTIZE, "LLQUANTIZE\n", 1 },
			{ DTRACEACT_STOP, "STOP\n", 0 },
			{ DTRACEACT_RAISE, "RAISE\n", 1 },
			{ DTRACEACT_SYSTEM, "SYSTEM\n", 1 },
			{ DTRACEACT_PANIC, "PANIC\n", 0 },
			{ DTRACEACT_CHILL, "CHILL\n", 1 },
			{ DTRACEACT_BREAKPOINT, "BREAKPOINT\n", 0 },
			{ DTRACEACT_COMMIT, "COMMIT\n", 1 },
			{ DTRACEACT_DISCARD, "DISCARD\n", 1 },
			{ DTRACEACT_FREOPEN, "", 0 },
		};
		enum { NA = sizeof (acts) / sizeof (acts[0]) };
		int kinds[NA];
		dtrace_difo_t *difos[NA];
		uint64_t args[NA];
		dif_instr_t ret[] = { DIF_INSTR_RET(0) };
		int ok = 1;

		pgp = dt_program_create(dtp);
		for (int i = 0; i < NA; i++) {
			kinds[i] = acts[i].kind;
			difos[i] = acts[i].difo ? make_difo(ret, 1) : NULL;
			args[i] = 7;
		}
		add_stmt(dtp, pgp, "", "test", "dump", NA, kinds, difos, args);
		{
			int k1[] = { DTRACEACT_STOP };
			dtrace_stmtdesc_t *s = add_stmt(dtp, pgp, "", "test",
			    "pred", 1, k1, NULL, NULL);

			s->dtsd_ecbdesc->dted_pred.dtpdd_difo =
			    make_difo(ret, 1);
		}
		dump = capture_stderr(dump_actions_fn, pgp);
		p = dump;
		for (int i = 0; i < NA && ok; i++) {
			if ((p = strstr(p, "\nACTION RETURNS: NO\n")) == NULL) {
				ok = 0;
				break;
			}
			p += strlen("\nACTION RETURNS: NO\n");
			if (strncmp(p, acts[i].head, strlen(acts[i].head)) != 0)
				ok = 0;
			if (acts[i].difo && strstr(p, "DIFO ") == NULL)
				ok = 0;
		}
		if (getenv("PP_DEBUG")) fprintf(stdout, "%s", dump);
		CHECK("dump-actions-kinds", ok &&
		    strstr(dump, ":test:::dump ==>\n") != NULL &&
		    strstr(dump, ":test:::pred ==>\n\nPredicate:\n") != NULL);
		free(dump);
		dump = capture_stderr(dump_ecbs_fn, pgp);
		CHECK("dump-ecbs", strncmp(dump, "DTrace: Dumping ECBs...\n",
		    24) == 0 && strstr(dump, "Predicate:\n") != NULL &&
		    strstr(dump, "BREAKPOINT\n") != NULL);
		free(dump);
		dt_program_destroy(dtp, pgp);
	}
	dtrace_close(dtp);
}

/*
 * dtrace_modref_action() over every action kind with the documented
 * classification (see analysis-modref.py for the D-compiled subset).
 */
static bool
modref_check(int modref, int cumulative, const dtrace_probedesc_t *pd,
    FILE *out)
{
	(void) cumulative;
	(void) pd;
	fprintf(out, "%d\n", modref);
	return (true);
}

static void
case_modref_kinds(void)
{
	enum { GM = 1, GR = 2, TM = 4, TR = 8, CM = 16, CR = 32, MM = 64,
	    MR = 128, SM = 256, SR = 512, ALL = 1023 };
	static const struct { int kind; int want; } k[] = {
		{ DTRACEACT_NONE, 0 }, { DTRACEACT_STOP, 0 },
		{ DTRACEACT_RAISE, 0 }, { DTRACEACT_PRINTF, 0 },
		{ DTRACEACT_PRINTA, 0 }, { DTRACEACT_PRINTM, 0 },
		{ DTRACEACT_EXIT, MM }, { DTRACEACT_TRACEMEM, MM },
		{ DTRACEACT_TRACEMEM_DYNSIZE, MM },
		{ DTRACEACT_USTACK, MR | MM }, { DTRACEACT_JSTACK, MR | MM },
		{ DTRACEACT_SPECULATIVE, SR | SM },
		{ DTRACEACT_SPECULATE, SR | SM }, { DTRACEACT_DISCARD, SR | SM },
		{ DTRACEACT_COMMIT, SR | SM | MM },
		{ DTRACEACT_PROC, ALL }, { DTRACEACT_USYM, ALL },
		{ DTRACEACT_UMOD, ALL }, { DTRACEACT_UADDR, ALL },
		{ DTRACEACT_PROC_DESTRUCTIVE, ALL }, { DTRACEACT_SYSTEM, ALL },
		{ DTRACEACT_FREOPEN, ALL }, { DTRACEACT_PROC_CONTROL, ALL },
		{ DTRACEACT_KERNEL, ALL }, { DTRACEACT_STACK, ALL },
		{ DTRACEACT_SYM, ALL }, { DTRACEACT_MOD, ALL },
		{ DTRACEACT_KERNEL_DESTRUCTIVE, ALL },
		{ DTRACEACT_BREAKPOINT, ALL }, { DTRACEACT_PANIC, ALL },
		{ DTRACEACT_CHILL, ALL }, { DTRACEAGG_COUNT, ALL },
	};
	enum { NK = sizeof (k) / sizeof (k[0]) };
	dtrace_hdl_t *dtp = open_nodev();
	dtrace_prog_t *pgp = dt_program_create(dtp);
	int kinds[NK + 1], ok = 1, i = 0;
	dtrace_difo_t *difos[NK + 1] = { 0 };
	char *buf = NULL, *p;
	size_t len = 0;
	FILE *fp = open_memstream(&buf, &len);

	for (i = 0; i < NK; i++)
		kinds[i] = k[i].kind;
	/* A DIF expression whose vartab names every scope and both flags. */
	{
		dif_instr_t code[] = { DIF_INSTR_RET(0) };
		dtrace_difo_t *dp = make_difo(code, 1);
		static const uint8_t scopes[] = { DIFV_SCOPE_GLOBAL,
		    DIFV_SCOPE_THREAD, DIFV_SCOPE_LOCAL, 7 };

		dp->dtdo_vartab = calloc(8, sizeof (dtrace_difv_t));
		dp->dtdo_varlen = 8;
		for (int j = 0; j < 8; j++) {
			dp->dtdo_vartab[j].dtdv_scope = scopes[j % 4];
			dp->dtdo_vartab[j].dtdv_flags = j < 4 ? DIFV_F_MOD :
			    DIFV_F_REF;
		}
		kinds[NK] = DTRACEACT_DIFEXPR;
		difos[NK] = dp;
	}
	add_stmt(dtp, pgp, "", "test", "modref", NK + 1, kinds, difos, NULL);
	dtrace_analyze_program_modref(pgp, modref_check, fp);
	fclose(fp);
	p = buf;
	for (i = 0; i < NK && ok; i++) {
		ok = atoi(p) == k[i].want;
		p = strchr(p, '\n') + 1;
	}
	CHECK("modref-action-kinds", ok && atoi(p) ==
	    (GM | TM | CM | GR | TR | CR));
	free(buf);
	dt_program_destroy(dtp, pgp);
	dtrace_close(dtp);
}

/* ------------------------------------------------------------------ */
/* dt_dof: DOF buffers written for the driver's independent parser.    */

static FILE *dofman, *dofjson;

/*
 * The program's own structure as JSON (input to the DOF encoder): the
 * driver decodes the DOF independently and compares the two.
 */
static void
json_str(FILE *fp, const char *s, size_t n)
{
	fputc('"', fp);
	for (size_t i = 0; i < n && s[i] != '\0'; i++) {
		unsigned char c = s[i];

		if (c == '"' || c == '\\')
			fprintf(fp, "\\%c", c);
		else if (c < 0x20 || c >= 0x7f)
			fprintf(fp, "\\u%04x", c);
		else
			fputc(c, fp);
	}
	fputc('"', fp);
}

static void
json_difo(FILE *fp, const dtrace_difo_t *dp)
{
	if (dp == NULL) {
		fprintf(fp, "null");
		return;
	}
	fprintf(fp, "{\"rtype\":[%u,%u,%u,%u],\"buf\":[",
	    dp->dtdo_rtype.dtdt_kind, dp->dtdo_rtype.dtdt_ckind,
	    dp->dtdo_rtype.dtdt_flags, dp->dtdo_rtype.dtdt_size);
	for (uint_t i = 0; i < dp->dtdo_len; i++)
		fprintf(fp, "%s%u", i ? "," : "", dp->dtdo_buf[i]);
	fprintf(fp, "],\"int\":[");
	for (uint_t i = 0; i < dp->dtdo_intlen; i++)
		fprintf(fp, "%s%ju", i ? "," : "",
		    (uintmax_t)dp->dtdo_inttab[i]);
	fprintf(fp, "],\"str\":[");
	for (uint_t i = 0; i < dp->dtdo_strlen; i++)
		fprintf(fp, "%s%u", i ? "," : "",
		    (unsigned char)dp->dtdo_strtab[i]);
	fprintf(fp, "],\"var\":[");
	for (uint_t i = 0; i < dp->dtdo_varlen; i++) {
		const dtrace_difv_t *v = &dp->dtdo_vartab[i];

		fprintf(fp, "%s[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u]", i ? "," : "",
		    v->dtdv_name, v->dtdv_id, v->dtdv_kind, v->dtdv_scope,
		    v->dtdv_flags, v->dtdv_type.dtdt_kind,
		    v->dtdv_type.dtdt_ckind, v->dtdv_type.dtdt_flags,
		    v->dtdv_type.dtdt_pad, v->dtdv_type.dtdt_size);
	}
	fprintf(fp, "],\"krel\":%u,\"urel\":%u,\"xl\":%u,\"xlm\":[",
	    dp->dtdo_krelen, dp->dtdo_urelen, dp->dtdo_xlmlen);
	for (uint_t i = 0; i < dp->dtdo_xlmlen; i++) {
		dt_node_t *mnp = dp->dtdo_xlmtab[i];

		fprintf(fp, "%s[\"%s\",%d]", i ? "," : "", mnp->dn_membname,
		    mnp->dn_membexpr->dn_xlator->dx_arg);
	}
	fprintf(fp, "],\"kr\":[");
	for (uint_t i = 0; i < dp->dtdo_krelen; i++)
		fprintf(fp, "%s[%u,%u,%ju,%ju]", i ? "," : "",
		    dp->dtdo_kreltab[i].dofr_name, dp->dtdo_kreltab[i].dofr_type,
		    (uintmax_t)dp->dtdo_kreltab[i].dofr_offset,
		    (uintmax_t)dp->dtdo_kreltab[i].dofr_data);
	fprintf(fp, "],\"ur\":[");
	for (uint_t i = 0; i < dp->dtdo_urelen; i++)
		fprintf(fp, "%s[%u,%u,%ju,%ju]", i ? "," : "",
		    dp->dtdo_ureltab[i].dofr_name, dp->dtdo_ureltab[i].dofr_type,
		    (uintmax_t)dp->dtdo_ureltab[i].dofr_offset,
		    (uintmax_t)dp->dtdo_ureltab[i].dofr_data);
	fprintf(fp, "]}");
}

static void
json_program(FILE *fp, const char *name, dtrace_prog_t *pgp)
{
	dtrace_ecbdesc_t *last = NULL;
	int first = 1;

	fprintf(fp, "{\"case\":\"%s\",\"ecbs\":[", name);
	for (dt_stmt_t *stp = dt_list_next(&pgp->dp_stmts); stp != NULL;
	    stp = dt_list_next(stp)) {
		dtrace_ecbdesc_t *edp = stp->ds_desc->dtsd_ecbdesc;
		const dtrace_probedesc_t *pd = &edp->dted_probe;
		dt_stmt_t *owner = stp;
		const char *fmt;

		if (edp == last)
			continue;
		last = edp;
		fprintf(fp, "%s{\"probe\":[", first ? "" : ",");
		first = 0;
		json_str(fp, pd->dtpd_provider, sizeof (pd->dtpd_provider));
		fputc(',', fp);
		json_str(fp, pd->dtpd_mod, sizeof (pd->dtpd_mod));
		fputc(',', fp);
		json_str(fp, pd->dtpd_func, sizeof (pd->dtpd_func));
		fputc(',', fp);
		json_str(fp, pd->dtpd_name, sizeof (pd->dtpd_name));
		fprintf(fp, "],\"id\":%u,\"vmid\":%u,\"uarg\":%ju,\"pred\":",
		    pd->dtpd_id, pd->dtpd_vmid, (uintmax_t)edp->dted_uarg);
		json_difo(fp, edp->dted_pred.dtpdd_difo);
		fprintf(fp, ",\"actions\":[");
		/* Each statement's string applies to all of its actions. */
		fmt = NULL;
		for (dtrace_actdesc_t *ap = edp->dted_action; ap != NULL;
		    ap = ap->dtad_next) {
			if (owner != NULL && ap == owner->ds_desc->dtsd_action) {
				dtrace_stmtdesc_t *sdp = owner->ds_desc;

				fmt = sdp->dtsd_fmtdata != NULL ?
				    ((dt_pfargv_t *)sdp->dtsd_fmtdata)->
				    pfv_format : sdp->dtsd_strdata;
				owner = dt_list_next(owner);
			}
			fprintf(fp, "%s{\"kind\":%u,\"ntuple\":%u,\"arg\":%ju,"
			    "\"uarg\":%ju,\"fmt\":", ap == edp->dted_action ?
			    "" : ",", ap->dtad_kind, ap->dtad_ntuple,
			    (uintmax_t)ap->dtad_arg, (uintmax_t)ap->dtad_uarg);
			if (fmt != NULL)
				json_str(fp, fmt, SIZE_MAX);
			else
				fprintf(fp, "null");
			fprintf(fp, ",\"difo\":");
			json_difo(fp, ap->dtad_difo);
			fputc('}', fp);
		}
		fprintf(fp, "]}");
	}
	fprintf(fp, "]}\n");
}

static int
emit_dof(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, uint_t flags,
    const char *name)
{
	dof_hdr_t *dof = pgp != NULL ? dtrace_dof_create(dtp, pgp, flags) :
	    NULL;
	char path[128];

	if (dof == NULL) {
		fprintf(dofman, "%s error %s\n", name,
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		return (-1);
	}
	snprintf(path, sizeof (path), "dof-%s.bin", name);
	write_blob(path, dof, dof->dofh_filesz);
	fprintf(dofman, "%s file %s\n", name, path);
	dtrace_dof_destroy(dtp, dof);
	return (0);
}

/*
 * Programs whose DOF the driver checks against D semantics: the probe
 * descriptions, predicates, action kinds, format strings and DIFO tables
 * named in program-properties.py for each case.
 */
static const struct {
	const char *name, *src;
} dof_programs[] = {
	{ "trace", "BEGIN { trace(1); }" },
	{ "pred-printf", "BEGIN /timestamp > 5/ { printf(\"%d %s\\n\", 42, "
	    "\"text\"); }" },
	{ "printa", "BEGIN { @c[1, \"k\"] = count(); @s = sum(7); "
	    "printa(\"%d %s %@d\\n\", @c); }" },
	{ "vars", "BEGIN { x = 1; self->t = 2; this->c = x + self->t; "
	    "trace(this->c); } END { trace(x); exit(0); }" },
	{ "empty", "BEGIN { }" },
	{ "two-ecb", "test:kernel:alpha:entry { trace(arg0); trace(arg1); } "
	    "test:kernel:beta:return { printf(\"%s\", \"b\"); }" },
	{ "print-type", "BEGIN { print(3); print(\"s\"); }" },
	{ "uarg", "dtrace:::BEGIN, dtrace:::END { trace(\"x\"); }" },
};

static int
geterr_cb(const dtrace_errdata_t *d, void *arg)
{
	(void) d;
	(void) arg;
	return (DTRACE_HANDLE_OK);
}

static void
case_dof(void)
{
	dtrace_hdl_t *dtp = open_nodev();
	dtrace_prog_t *pgp;
	dof_hdr_t *dof;
	char name[64];

	dofman = fopen("dof.manifest", "w");
	dofjson = fopen("dof-programs.json", "w");
	for (size_t i = 0; i < sizeof (dof_programs) /
	    sizeof (dof_programs[0]); i++) {
		pgp = compile(dtp, dof_programs[i].src, 0);
		CHECK(dof_programs[i].name, pgp != NULL);
		if (pgp == NULL) {
			fprintf(dofman, "%s error compile\n",
			    dof_programs[i].name);
			continue;
		}
		json_program(dofjson, dof_programs[i].name, pgp);
		emit_dof(dtp, pgp, 0, dof_programs[i].name);
		snprintf(name, sizeof (name), "%s-strip", dof_programs[i].name);
		emit_dof(dtp, pgp, DTRACE_D_STRIP, name);
	}

	/*
	 * Dynamic translation (-xlate=dynamic, option "late"): probe argument
	 * members become XLATE/XLARG references through the DIFO's XLTAB to
	 * imported translators (XLIMPORT) listing only referenced members.
	 */
	{
		static const struct { const char *name, *src; } xp[] = {
			{ "xlate-import", "struct yy { int a; int b; }; "
			    "provider foo { probe bar(struct yy *x); }; "
			    "foo:::bar { trace(args[0]->a); }" },
			{ "xlate-import2", "struct zz { int a; int b; "
			    "int c; }; provider fob { probe bar(int x, "
			    "struct zz *y); }; fob:::bar { trace(args[1]->c); "
			    "trace(args[1]->a); }" },
		};
		dtrace_hdl_t *xh = open_nodev();

		dtrace_prog_t *xps[2];

		(void) dtrace_setopt(xh, "late", "dynamic");
		/*
		 * Both are compiled first: the first program's DOF is then
		 * built with a translator (the second's) newer than its
		 * reference table.
		 */
		for (size_t i = 0; i < 2; i++) {
			xps[i] = compile(xh, xp[i].src, 0);
			CHECK(xp[i].name, xps[i] != NULL);
		}
		for (size_t i = 0; i < 2; i++) {
			dtrace_prog_t *xp_pgp = xps[i];

			if (xp_pgp == NULL)
				continue;
			json_program(dofjson, xp[i].name, xp_pgp);
			/*
			 * The type checker types XLATE/XLARG (the translator
			 * member's type): the program links, and its DOF is the
			 * same, with its translator references.
			 */
			{
				hypertrace_errmsg_t lmsg;
				char lname[64];

				snprintf(lname, sizeof (lname), "%s-links",
				    xp[i].name);
				result(lname, hypertrace_link(xh, xp_pgp,
				    lmsg) == 0, "%s", lmsg);
			}
			emit_dof(xh, xp_pgp, 0, xp[i].name);
			snprintf(name, sizeof (name), "%s-strip", xp[i].name);
			emit_dof(xh, xp_pgp, DTRACE_D_STRIP, name);
			dt_program_destroy(xh, xp_pgp);	/* frees dp_xrefs */
		}
		dtrace_close(xh);
	}

	/*
	 * Kernel and user relocations (dtrace -G / linkmode output): each
	 * table is emitted as a RELTAB with a KRELHDR or URELHDR naming the
	 * DIFO's string table and its integer table as the target.
	 */
	{
		dtrace_prog_t *rp = dt_program_create(dtp);
		dif_instr_t code[] = { DIF_INSTR_SETX(0, 1), DIF_INSTR_SETX(1, 2),
		    DIF_INSTR_RET(1) };
		dtrace_difo_t *dp = make_difo(code, 3);
		int kinds[] = { DTRACEACT_DIFEXPR };

		dp->dtdo_inttab = calloc(2, sizeof (uint64_t));
		dp->dtdo_intlen = 2;
		dp->dtdo_strtab = malloc(12);
		memcpy(dp->dtdo_strtab, "\0ksym\0usym\0", 12);
		dp->dtdo_strlen = 12;
		dp->dtdo_kreltab = calloc(1, sizeof (dof_relodesc_t));
		dp->dtdo_krelen = 1;
		dp->dtdo_kreltab[0].dofr_name = 1;
		dp->dtdo_kreltab[0].dofr_type = DOF_RELO_SETX;
		dp->dtdo_kreltab[0].dofr_offset = 0;
		dp->dtdo_ureltab = calloc(2, sizeof (dof_relodesc_t));
		dp->dtdo_urelen = 2;
		dp->dtdo_ureltab[0].dofr_name = 6;
		dp->dtdo_ureltab[0].dofr_type = DOF_RELO_SETX;
		dp->dtdo_ureltab[0].dofr_offset = 8;
		dp->dtdo_ureltab[0].dofr_data = 3;
		dp->dtdo_ureltab[1].dofr_name = 6;
		dp->dtdo_ureltab[1].dofr_type = DOF_RELO_SETX;
		dp->dtdo_ureltab[1].dofr_offset = 8;
		dp->dtdo_rtype.dtdt_kind = DIF_TYPE_CTF;
		dp->dtdo_rtype.dtdt_size = 8;
		add_stmt(dtp, rp, "", "test", "relo", 1, kinds, &dp, NULL);
		{
			/* A DIFO with no instruction buffer at all. */
			dtrace_difo_t *empty = calloc(1, sizeof (*empty));

			empty->dtdo_rtype.dtdt_kind = DIF_TYPE_CTF;
			empty->dtdo_rtype.dtdt_size = 4;
			/* ...and a variable table with no entries. */
			empty->dtdo_vartab = calloc(1, sizeof (dtrace_difv_t));
			add_stmt(dtp, rp, "", "test", "empty", 1, kinds,
			    &empty, NULL);
		}
		json_program(dofjson, "relocations", rp);
		emit_dof(dtp, rp, 0, "relocations");
		emit_dof(dtp, rp, DTRACE_D_STRIP, "relocations-strip");
		dt_program_destroy(dtp, rp);
	}

	/* A format the DOF writer cannot render fails the whole DOF. */
	{
		dtrace_prog_t *fp_pgp = compile(dtp,
		    "BEGIN { printf(\"x%d\", 1); }", 0);
		dt_stmt_t *stp = dt_list_next(&fp_pgp->dp_stmts);
		dt_pfargv_t *pfv = stp->ds_desc->dtsd_fmtdata;
		dt_pfargd_t *saved = pfv->pfv_argv;

		pfv->pfv_argv = NULL;
		CHECK("dof-bad-format", dtrace_dof_create(dtp, fp_pgp, 0) ==
		    NULL && dtrace_errno(dtp) == EINVAL);
		pfv->pfv_argv = saved;
		/*
		 * A rendered format of UINT_MAX bytes or more cannot be
		 * stored (dof_stridx_t); sizing does not read the prefix.
		 */
		{
			size_t len = saved->pfd_preflen;

			saved->pfd_preflen = UINT_MAX;
			CHECK("dof-format-overflow", dtrace_dof_create(dtp,
			    fp_pgp, 0) == NULL &&
			    dtrace_errno(dtp) == EOVERFLOW);
			saved->pfd_preflen = len;
		}
		dt_program_destroy(dtp, fp_pgp);
	}

	/* Unknown flag bits are rejected before any work. */
	pgp = compile(dtp, "BEGIN { trace(1); }", 0);
	CHECK("dof-bad-flags", dtrace_dof_create(dtp, pgp, ~DTRACE_D_MASK) ==
	    NULL && dtrace_errno(dtp) == EINVAL);

	/* Configuration values that do not fit the header's uint8_t. */
	{
		uint_t *f[] = { &dtp->dt_conf.dtc_difversion,
		    &dtp->dt_conf.dtc_difintregs,
		    &dtp->dt_conf.dtc_diftupregs };
		int ok = 1;

		for (int i = 0; i < 3; i++) {
			uint_t saved = *f[i];

			*f[i] = 300;
			ok &= dtrace_dof_create(dtp, pgp, 0) == NULL &&
			    dtrace_errno(dtp) == EOVERFLOW &&
			    dtrace_getopt_dof(dtp) == NULL;
			*f[i] = saved;
		}
		CHECK("dof-hdr-overflow", ok);
	}

	/* The header's data model follows the CTF model. */
	dtp->dt_conf.dtc_ctfmodel = CTF_MODEL_ILP32;
	dof = dtrace_dof_create(dtp, pgp, 0);
	CHECK("dof-ilp32-model", dof != NULL &&
	    dof->dofh_ident[DOF_ID_MODEL] == DOF_MODEL_ILP32);
	if (dof != NULL)
		dtrace_dof_destroy(dtp, dof);
	dtp->dt_conf.dtc_ctfmodel = CTF_MODEL_LP64;

	/* Option DOF: one OPTDESC entry per option that is set. */
	(void) dtrace_setopt(dtp, "bufsize", "4m");
	(void) dtrace_setopt(dtp, "quiet", NULL);
	dof = dtrace_getopt_dof(dtp);
	if (dof != NULL) {
		write_blob("dof-options.bin", dof, dof->dofh_filesz);
		fprintf(dofman, "options file dof-options.bin\n");
		dtrace_dof_destroy(dtp, dof);
	}

	/* The error program DOF exists only once ERROR is handled. */
	CHECK("dof-geterr-none", dtrace_geterr_dof(dtp) == NULL &&
	    dtrace_errno(dtp) == EDT_BADERROR);
	if (dtrace_handle_err(dtp, geterr_cb, NULL) == 0 &&
	    (dof = dtrace_geterr_dof(dtp)) != NULL) {
		json_program(dofjson, "errprog", dtp->dt_errprog);
		write_blob("dof-errprog.bin", dof, dof->dofh_filesz);
		fprintf(dofman, "errprog file dof-errprog.bin\n");
		dtrace_dof_destroy(dtp, dof);
	} else {
		fprintf(dofman, "errprog error %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
	}
	dtrace_close(dtp);
	fclose(dofjson);
	fclose(dofman);
}

/* ------------------------------------------------------------------ */
/* A scripted dtrace(4) vector for dtrace_program_exec(),              */
/* dtrace_augment_tracing() and dtrace_vprobes_create().               */

static struct {
	int enable_errno;	/* ENABLE/AUGMENT fail with this errno */
	int n_desc;		/* descriptions reported by ENABLE */
	int n_matched;
	int providers;		/* PROVIDER succeeds (implicit providers) */
	int vprobe_errno;
	unsigned enables, augments, vprobes;
	size_t last_dof_size;
	int last_vmid, last_neprobes;
	uint64_t last_epoch;
	unsigned unexpected;
} V;

static int
vec_ioctl(void *arg, u_long cmd, void *data)
{
	(void) arg;
	cmd &= 0xffffffffUL;
	if (cmd == (DTRACEIOC_CONF & 0xffffffffUL)) {
		dtrace_conf_t *c = data;

		memset(c, 0, sizeof (*c));
		c->dtc_difversion = DIF_VERSION;
		c->dtc_difintregs = DIF_DIR_NREGS;
		c->dtc_diftupregs = DIF_DTR_NREGS;
		c->dtc_ctfmodel = CTF_MODEL_NATIVE;
		return (0);
	}
	if (cmd == (DTRACEIOC_PROVIDER & 0xffffffffUL)) {
		dtrace_providerdesc_t *pvd = data;
		dtrace_attribute_t at = { DTRACE_STABILITY_EVOLVING,
		    DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON };

		if (!V.providers || (strcmp(pvd->dtvd_name, "dtrace") != 0 &&
		    strcmp(pvd->dtvd_name, "test") != 0))
			return (errno = ESRCH, -1);
		memset(&pvd->dtvd_priv, 0, sizeof (pvd->dtvd_priv));
		pvd->dtvd_attr.dtpa_provider = pvd->dtvd_attr.dtpa_mod =
		    pvd->dtvd_attr.dtpa_func = pvd->dtvd_attr.dtpa_name =
		    pvd->dtvd_attr.dtpa_args = at;
		return (0);
	}
	if (cmd == (DTRACEIOC_PROBEMATCH & 0xffffffffUL) ||
	    cmd == (DTRACEIOC_PROBES & 0xffffffffUL) ||
	    cmd == (DTRACEIOC_PROBEARG & 0xffffffffUL))
		return (errno = ESRCH, -1);
	if (cmd == (DTRACEIOC_ENABLE & 0xffffffffUL) ||
	    cmd == (DTRACEIOC_AUGMENT & 0xffffffffUL)) {
		dtrace_enable_io_t *io = data;
		dof_hdr_t *dof = io->dof;

		if (cmd == (DTRACEIOC_ENABLE & 0xffffffffUL))
			V.enables++;
		else
			V.augments++;
		V.last_dof_size = dof != NULL ? dof->dofh_loadsz : 0;
		V.last_vmid = io->vmid;
		V.last_epoch = io->epoch;
		if (V.enable_errno != 0)
			return (errno = V.enable_errno, -1);
		/* The driver fills ps[] with what it matched. */
		for (int i = 0; i < V.n_desc && i < io->ps_bufsize /
		    (int)sizeof (dtrace_probedesc_t); i++) {
			memset(&io->ps[i], 0, sizeof (io->ps[i]));
			io->ps[i].dtpd_id = i + 1;
			snprintf(io->ps[i].dtpd_provider,
			    sizeof (io->ps[i].dtpd_provider), "test");
			snprintf(io->ps[i].dtpd_name,
			    sizeof (io->ps[i].dtpd_name), "p%d", i);
		}
		io->n_desc = V.n_desc;
		io->n_matched = V.n_matched;
		return (0);
	}
	if (cmd == (DTRACEIOC_VPROBE_CREATE & 0xffffffffUL)) {
		dtrace_vprobe_io_t *io = data;

		V.vprobes++;
		V.last_vmid = io->vmid;
		V.last_neprobes = io->neprobes;
		V.last_epoch = io->epoch;
		if (V.vprobe_errno != 0)
			return (errno = V.vprobe_errno, -1);
		return (0);
	}
	V.unexpected++;
	return (errno = ENOTTY, -1);
}

static const dtrace_vector_t vec = { .dtv_ioctl = vec_ioctl };

static dtrace_hdl_t *
open_vec(void)
{
	int err;
	dtrace_hdl_t *dtp = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS |
	    DTRACE_O_LP64, &err, &vec, NULL);

	if (dtp == NULL) {
		fprintf(stderr, "dtrace_vopen: %s\n", dtrace_errmsg(NULL, err));
		exit(2);
	}
	return (dtp);
}

static dtrace_hdl_t *vp_dtp;
static dtrace_prog_t *vp_pgp;
static int vp_rc;

static void
vprobe_call(void *arg)
{
	(void) arg;
	vp_rc = dtrace_vprobes_create(vp_dtp, vp_pgp);
}

static void
case_exec(void)
{
	static const struct { int in, out; } map[] = {
		/* dtrace_program_exec() maps driver errors to library ones. */
		{ EINVAL, EDT_DIFINVAL }, { EFAULT, EDT_DIFFAULT },
		{ E2BIG, EDT_DIFSIZE }, { EBUSY, EDT_ENABLING_ERR },
		{ EPERM, EPERM },
	};
	dtrace_hdl_t *dtp;
	dtrace_prog_t *pgp;
	dtrace_proginfo_t info;
	int ok = 1;

	memset(&V, 0, sizeof (V));
	dtp = open_vec();
	pgp = compile(dtp, "BEGIN { trace(1); } END { trace(2); }", 0);
	for (size_t i = 0; i < sizeof (map) / sizeof (map[0]); i++) {
		V.enable_errno = map[i].in;
		if (dtrace_program_exec(dtp, pgp, &info) != -1 ||
		    dtrace_errno(dtp) != map[i].out)
			ok = 0;
	}
	CHECK("exec-errno-mapping", ok && V.enables == 5);
	V.enable_errno = 0;

	/* Reported descriptions become the program's enabled probes. */
	V.n_desc = 3;
	V.n_matched = 4;
	CHECK("exec-eprobes", dtrace_program_exec(dtp, pgp, &info) == 0 &&
	    info.dpi_matches == 4 && pgp->dp_neprobes == 3 &&
	    pgp->dp_eprobes != NULL && pgp->dp_eprobes[2].dtpd_id == 3 &&
	    strcmp(pgp->dp_eprobes[1].dtpd_name, "p1") == 0);
	/* A later enabling with none replaces them. */
	V.n_desc = 0;
	CHECK("exec-eprobes-cleared", dtrace_program_exec(dtp, pgp, NULL) ==
	    0 && pgp->dp_neprobes == 0 && pgp->dp_eprobes == NULL);
	/* A driver claiming more descriptions than the buffer holds. */
	V.n_desc = DTRACE_MIN_NPROBES + 1;
	CHECK("exec-n-desc-overflow", dtrace_program_exec(dtp, pgp, NULL) ==
	    -1 && dtrace_errno(dtp) == EDT_DIFSIZE);
	V.n_desc = -1;
	CHECK("exec-n-desc-negative", dtrace_program_exec(dtp, pgp, NULL) ==
	    -1 && dtrace_errno(dtp) == EDT_DIFSIZE);
	V.n_desc = 2;
	CHECK("exec-eprobes-again", dtrace_program_exec(dtp, pgp, NULL) == 0 &&
	    pgp->dp_neprobes == 2);

	/*
	 * dtrace_program_info(): destructive actions and speculations make
	 * no record; a string trace() does; aggregations are counted.
	 */
	{
		dtrace_prog_t *ip;

		(void) dtrace_setopt(dtp, "destructive", NULL);
		ip = compile(dtp, "BEGIN { system(\"x\"); trace(\"s\"); "
		    "@a = count(); } END { stop(); }", 0);
		memset(&info, 0xa5, sizeof (info));
		dtrace_program_info(dtp, ip, &info);
		CHECK("program-info", ip != NULL && info.dpi_recgens == 1 &&
		    info.dpi_aggregates == 1 && info.dpi_speculations == 0 &&
		    info.dpi_matches == 0);
		dtrace_program_info(dtp, ip, NULL);
	}

	/* The DOF cannot be built: exec fails before the driver is used. */
	dtp->dt_conf.dtc_diftupregs = 1000;
	V.enables = 0;
	CHECK("exec-dof-failure", dtrace_program_exec(dtp, pgp, NULL) == -1 &&
	    dtrace_errno(dtp) == EOVERFLOW && V.enables == 0 &&
	    dtrace_augment_tracing(dtp, pgp) == -1 && V.augments == 0);
	dtp->dt_conf.dtc_diftupregs = DIF_DTR_NREGS;

	/* Augmenting submits the program's DOF with its VM identity. */
	pgp->dp_vmid = 3;
	pgp->dp_vmepoch = 0x1234;
	ok = 1;
	for (size_t i = 0; i < sizeof (map) / sizeof (map[0]); i++) {
		V.enable_errno = map[i].in;
		if (dtrace_augment_tracing(dtp, pgp) != -1 ||
		    dtrace_errno(dtp) != map[i].out)
			ok = 0;
	}
	V.enable_errno = 0;
	CHECK("augment", ok && dtrace_augment_tracing(dtp, pgp) == 0 &&
	    V.augments == 6 && V.last_vmid == 3 && V.last_epoch == 0x1234 &&
	    V.last_dof_size > sizeof (dof_hdr_t));

	/* Virtual probes are created from the enabled probe list. */
	CHECK("vprobes-create", dtrace_vprobes_create(dtp, pgp) == 0 &&
	    V.vprobes == 1 && V.last_neprobes == 2 && V.last_vmid == 3 &&
	    V.last_epoch == 0x1234);
	/* A driver failure is reported on stderr and returned. */
	V.vprobe_errno = ENOENT;
	vp_dtp = dtp;
	vp_pgp = pgp;
	{
		char *err = capture_stderr(vprobe_call, NULL);

		CHECK("vprobes-create-failure", vp_rc == -1 && err != NULL &&
		    strcmp(err, "DTRACEIOC_VPROBE_CREATE: No such file or "
		    "directory\n") == 0);
		free(err);
	}
	dt_program_destroy(dtp, pgp);	/* frees dp_eprobes */
	CHECK("exec-model-ioctls", V.unexpected == 0);
	dtrace_close(dtp);

	/* Without a device every ioctl fails with EBADF (not remapped). */
	dtp = open_nodev();
	pgp = compile(dtp, "BEGIN { trace(1); }", 0);
	CHECK("exec-nodev", dtrace_program_exec(dtp, pgp, NULL) == -1 &&
	    dtrace_errno(dtp) == EBADF);
	dtrace_close(dtp);
}

/* ------------------------------------------------------------------ */
/* dtrace -h headers (dtrace_program_header) and USDT provider DOF.    */

#define	PROVIDER_SRC	"provider my { probe ent__ry(int, char *); " \
	"probe empty(); probe three(int, long, char); };"

static const char *header_want_probe[] = {
	"#define\tMY_ENT_RY(arg0, arg1) \\\n\t__dtrace_my___ent__ry(arg0, "
	    "arg1)\n#define\tMY_ENT_RY_ENABLED() \\\n"
	    "\t__dtraceenabled_my___ent__ry()\n",
	"#define\tMY_EMPTY() \\\n\t__dtrace_my___empty()\n"
	    "#define\tMY_EMPTY_ENABLED() \\\n\t__dtraceenabled_my___empty()\n",
	"#define\tMY_THREE(arg0, arg1, arg2) \\\n\t__dtrace_my___three(arg0, "
	    "arg1, arg2)\n#define\tMY_THREE_ENABLED() \\\n"
	    "\t__dtraceenabled_my___three()\n",
};
static const char *header_want_decl[] = {
	"extern void __dtrace_my___ent__ry(int, char *);\n"
	    "extern int __dtraceenabled_my___ent__ry(void);\n",
	"extern void __dtrace_my___empty(void);\n"
	    "extern int __dtraceenabled_my___empty(void);\n",
	"extern void __dtrace_my___three(int, long, char);\n"
	    "extern int __dtraceenabled_my___three(void);\n",
};
static const char *header_want_empty[] = {
	"#define\tMY_ENT_RY(arg0, arg1)\n#define\tMY_ENT_RY_ENABLED() (0)\n",
	"#define\tMY_EMPTY()\n#define\tMY_EMPTY_ENABLED() (0)\n",
	"#define\tMY_THREE(arg0, arg1, arg2)\n"
	    "#define\tMY_THREE_ENABLED() (0)\n",
};

/* Each block appears exactly once, between the given section markers. */
static int
in_section(const char *text, const char *from, const char *to,
    const char *block)
{
	const char *a = strstr(text, from), *b, *p;

	if (a == NULL || (b = strstr(a + strlen(from), to)) == NULL)
		return (0);
	p = strstr(a, block);
	return (p != NULL && p + strlen(block) <= b + strlen(to) &&
	    strstr(p + 1, block) == NULL);
}

static char *
header_text(dtrace_hdl_t *dtp, const char *fname, int *rc)
{
	char *buf = NULL;
	size_t len = 0;
	FILE *fp = open_memstream(&buf, &len);

	*rc = dtrace_program_header(dtp, fp, fname);
	fclose(fp);
	return (buf);
}

static void
case_header(void)
{
	static const char head[] = "#ifndef\t_MY_FILE_H\n#define\t_MY_FILE_H\n\n"
	    "#include <unistd.h>\n\n#ifdef\t__cplusplus\nextern \"C\" {\n"
	    "#endif\n\n#include <sys/sdt.h>\n\n#if _DTRACE_VERSION\n\n";
	static const char tail[] = "\n#endif\n\n\n#ifdef\t__cplusplus\n}\n"
	    "#endif\n\n#endif\t/* _MY_FILE_H */\n";
	dtrace_hdl_t *dtp;
	char *text, *bare;
	int rc, ok = 1, failed_all = 1;
	size_t full;

	memset(&V, 0, sizeof (V));
	V.providers = 1;	/* "dtrace" etc. are implicit (kernel) */
	dtp = open_vec();
	(void) compile(dtp, PROVIDER_SRC " dtrace:::BEGIN { trace(1); }", 0);
	text = header_text(dtp, "/some/dir/my-file.h", &rc);
	for (int i = 0; i < 3; i++) {
		ok &= in_section(text, "#if _DTRACE_VERSION\n", "\n\n",
		    header_want_probe[i]);
		ok &= in_section(text, "\n\n", "\n#else\n",
		    header_want_decl[i]);
		ok &= in_section(text, "\n#else\n", "\n#endif\n",
		    header_want_empty[i]);
	}
	CHECK("header-text", rc == 0 && ok &&
	    strncmp(text, head, strlen(head)) == 0 &&
	    strlen(text) > strlen(tail) &&
	    strcmp(text + strlen(text) - strlen(tail), tail) == 0 &&
	    /* implicit providers (dtrace) are not declared */
	    strstr(text, "\tDTRACE_") == NULL && strstr(text, "__dtrace_dtrace") == NULL);
	full = strlen(text);
	if (getenv("PP_DEBUG"))
		printf("rc %d ok %d head %d\n", rc, ok,
		    strncmp(text, head, strlen(head)));

	/* A bare file name (no directory) gives the same guard. */
	bare = header_text(dtp, "my-file.h", &rc);
	CHECK("header-bare-name", rc == 0 && strcmp(bare, text) == 0);
	free(bare);

	/* Without a file name there is no include guard. */
	bare = header_text(dtp, NULL, &rc);
	CHECK("header-no-guard", rc == 0 && strncmp(bare, "#include "
	    "<unistd.h>\n\n", 21) == 0 && strstr(bare, "#ifndef") == NULL &&
	    strlen(bare) + strlen("#ifndef\t_MY_FILE_H\n#define\t_MY_FILE_H\n\n")
	    + strlen("\n#endif\t/* _MY_FILE_H */\n") == full);
	free(bare);

	/* Every write failure is reported, whatever byte it happens at. */
	for (size_t n = 0; n < full; n++) {
		FILE *fp = budget_stream((int)n);

		if (dtrace_program_header(dtp, fp, "/some/dir/my-file.h") != -1)
			failed_all = 0;
		fclose(fp);
	}
	{
		FILE *fp = budget_stream((int)full);

		CHECK("header-write-errors", failed_all &&
		    dtrace_program_header(dtp, fp, "/some/dir/my-file.h") == 0);
		fclose(fp);
	}

	/* A '-' in a provider name doubles in function names. */
	{
		dt_provider_t *pvp = dt_provider_lookup(dtp, "my");

		strlcpy(pvp->pv_desc.dtvd_name, "my-prov",
		    sizeof (pvp->pv_desc.dtvd_name));
		bare = header_text(dtp, NULL, &rc);
		CHECK("header-provider-dash", rc == 0 &&
		    strstr(bare, "#define\tMY_PROV_EMPTY() \\\n"
		    "\t__dtrace_my__prov___empty()\n") != NULL &&
		    strstr(bare, "extern int __dtraceenabled_my__prov___empty("
		    "void);\n") != NULL);
		free(bare);
		strlcpy(pvp->pv_desc.dtvd_name, "my",
		    sizeof (pvp->pv_desc.dtvd_name));
	}
	free(text);
	dtrace_close(dtp);
}

/* Instance table the driver expects in the provider DOF. */
static const struct {
	const char *probe, *func;
	uint32_t off;
	int enabled;
} instances[] = {
	{ "ent-ry", "main", 0x10, 0 }, { "ent-ry", "main", 0x24, 0 },
	{ "ent-ry", "main", 0x30, 0 },
	{ "ent-ry", "worker", 0x8, 1 }, { "ent-ry", "worker", 0x40, 0 },
	{ "empty", "main", 0x100, 0 },
	{ "three", "aux", 0x200, 1 },
};

static void
define_instances(dtrace_hdl_t *dtp, int with_enabled, FILE *man)
{
	dt_provider_t *pvp = dt_provider_lookup(dtp, "my");

	for (size_t i = 0; i < sizeof (instances) / sizeof (instances[0]);
	    i++) {
		dt_probe_t *prp;

		if (instances[i].enabled && !with_enabled)
			continue;
		prp = dt_probe_lookup(pvp, instances[i].probe);
		if (prp == NULL || dt_probe_define(pvp, prp, instances[i].func,
		    instances[i].func, instances[i].off,
		    instances[i].enabled) != 0)
			fprintf(stderr, "define %s failed\n", instances[i].probe);
		fprintf(man, "%s %s %u %d\n", instances[i].probe,
		    instances[i].func, instances[i].off, instances[i].enabled);
	}
}

static void
case_provider_dof(void)
{
	dtrace_hdl_t *dtp;
	FILE *man;
	dtrace_prog_t *pgp;

	dofman = fopen("dof.manifest", "a");

	/* Declared provider without probe sites: nothing to export. */
	dtp = open_nodev();
	pgp = compile(dtp, PROVIDER_SRC, 0);
	CHECK("dof-provider-no-sites", dtrace_dof_create(dtp, pgp,
	    DTRACE_D_PROBES) == NULL && dtrace_errno(dtp) == EDT_NOPROBES);
	man = fopen("provider-full.instances", "w");
	define_instances(dtp, 1, man);
	fclose(man);
	emit_dof(dtp, pgp, DTRACE_D_PROBES | DTRACE_D_STRIP, "provider-full");
	dtrace_close(dtp);

	/* Without is-enabled sites the provider has no PRENOFFS section. */
	dtp = open_nodev();
	pgp = compile(dtp, PROVIDER_SRC, 0);
	man = fopen("provider-plain.instances", "w");
	define_instances(dtp, 0, man);
	fclose(man);
	emit_dof(dtp, pgp, DTRACE_D_PROBES | DTRACE_D_STRIP, "provider-plain");
	dtrace_close(dtp);

	/* Implicit (kernel) providers are skipped when exporting. */
	memset(&V, 0, sizeof (V));
	V.providers = 1;
	dtp = open_vec();
	pgp = compile(dtp, PROVIDER_SRC " dtrace:::BEGIN { trace(1); }", 0);
	man = fopen("provider-impl.instances", "w");
	define_instances(dtp, 1, man);
	fclose(man);
	emit_dof(dtp, pgp, DTRACE_D_PROBES | DTRACE_D_STRIP, "provider-impl");
	dtrace_close(dtp);

	/* With static translation nothing is exported for the provider. */
	dtp = open_nodev();
	pgp = compile(dtp, "struct xx { int a; int b; }; "
	    "translator struct xx < int x > { a = x + 1; b = x * 2; }; "
	    "provider my { probe ent__ry(int x) : (struct xx x); "
	    "probe empty(); probe three(int, long, char); };", 0);
	man = fopen("provider-static.instances", "w");
	define_instances(dtp, 1, man);
	fclose(man);
	emit_dof(dtp, pgp, DTRACE_D_PROBES | DTRACE_D_STRIP, "provider-static");
	dtrace_close(dtp);

	/*
	 * Translated provider arguments with dynamic translation: the
	 * translator is exported (XLEXPORT, one DIFO per member) and listed
	 * in the provider's PREXPORT section.
	 */
	dtp = open_nodev();
	(void) dtrace_setopt(dtp, "late", "dynamic");
	pgp = compile(dtp, "struct xx { int a; int b; }; "
	    "translator struct xx < int x > { a = x + 1; b = x * 2; }; "
	    "provider my { probe ent__ry(int x) : (struct xx x); "
	    "probe empty(); probe three(int, long, char); }; "
	    "provider other { probe one(int x) : (struct xx x); };", 0);
	{
		/* A second provider using the same translator. */
		dt_provider_t *opv = dt_provider_lookup(dtp, "other");

		(void) dt_probe_define(opv, dt_probe_lookup(opv, "one"), "f",
		    "f", 4, 0);
	}
	man = fopen("provider-xlate.instances", "w");
	define_instances(dtp, 1, man);
	fclose(man);
	emit_dof(dtp, pgp, DTRACE_D_PROBES | DTRACE_D_STRIP, "provider-xlate");
	dtrace_close(dtp);
	fclose(dofman);
}


static struct {
	void *ctx;
	dtrace_difo_t *b, *g;
	char *target;
	int rc;
} vd_args;

static void
verify_difo_call(void *arg)
{
	(void) arg;
	vd_args.rc = dt_prog_verify_difo(vd_args.ctx, vd_args.b, vd_args.g,
	    vd_args.target, vd_args.target);
}

/* dt_prog_verify_difo() with its diagnostics (stderr) discarded. */
static int
vd_quiet(void *ctx, dtrace_difo_t *b, dtrace_difo_t *g, char *target)
{
	char *msg;

	vd_args.ctx = ctx;
	vd_args.b = b;
	vd_args.g = g;
	vd_args.target = target;
	msg = capture_stderr(verify_difo_call, NULL);
	free(msg);
	return (vd_args.rc);
}

/* ------------------------------------------------------------------ */
/* dt_prog_verify_difo: one field at a time.  A returned (guest) DIFO  */
/* may differ from the host's only by the documented relocations       */
/* (USETX->SETX into an added constant, ULOAD/UULOAD->ld*, TYPECAST->  */
/* NOP, PUSHTV BOTTOM->CTF) and variable sizes; everything else must   */
/* match and every type must be well formed.                           */

static dtrace_difo_t *
difo_clone(const dtrace_difo_t *b)
{
	dtrace_difo_t *d = calloc(1, sizeof (*d));

	*d = *b;
#define	DUP(f, n)	if (b->f != NULL) { d->f = calloc(1, (n) + 32); \
	memcpy(d->f, b->f, (n)); }
	DUP(dtdo_buf, b->dtdo_len * sizeof (dif_instr_t));
	DUP(dtdo_inttab, b->dtdo_intlen * sizeof (uint64_t));
	DUP(dtdo_strtab, b->dtdo_strlen);
	DUP(dtdo_symtab, b->dtdo_symlen);
	DUP(dtdo_vartab, b->dtdo_varlen * sizeof (dtrace_difv_t));
#undef DUP
	return (d);
}

static void
difo_release(dtrace_difo_t *d)
{
	free(d->dtdo_buf);
	free(d->dtdo_inttab);
	free(d->dtdo_strtab);
	free(d->dtdo_symtab);
	free(d->dtdo_vartab);
	free(d);
}

/* A host DIFO with every table populated and each relocatable opcode. */
static dtrace_difo_t *
difo_base(void)
{
	static dif_instr_t code[] = {
		DIF_INSTR_USETX(0, 1),			/* 0 */
		DIF_INSTR_LOAD(DIF_OP_ULOAD, 1, 2),	/* 1 */
		DIF_INSTR_LOAD(DIF_OP_UULOAD, 2, 3),	/* 2 */
		DIF_INSTR_NOP,				/* 3: typecast slot */
		DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, DIF_TYPE_BOTTOM, 0, 3),	/* 4 */
		DIF_INSTR_SETX(0, 4),			/* 5 */
		DIF_INSTR_RET(4),			/* 6 */
	};
	static uint64_t ints[] = { 7 };
	static dtrace_difv_t vars[2];
	static dtrace_difo_t b;

	code[3] = DIF_INSTR_FMT(DIF_OP_TYPECAST, 0, 0, 4);
	memset(&b, 0, sizeof (b));
	b.dtdo_buf = code;
	b.dtdo_len = 7;
	b.dtdo_inttab = ints;
	b.dtdo_intlen = 1;
	b.dtdo_strtab = "\0xv\0";
	b.dtdo_strlen = 4;
	b.dtdo_symtab = "\0sym";
	b.dtdo_symlen = 5;
	memset(vars, 0, sizeof (vars));
	vars[0].dtdv_name = 1;
	vars[0].dtdv_id = DIF_VAR_OTHER_UBASE + 40;
	vars[0].dtdv_kind = DIFV_KIND_SCALAR;
	vars[0].dtdv_scope = DIFV_SCOPE_GLOBAL;
	vars[0].dtdv_flags = DIFV_F_REF;
	vars[0].dtdv_type.dtdt_kind = DIF_TYPE_CTF;
	vars[0].dtdv_type.dtdt_size = 8;
	vars[1] = vars[0];
	vars[1].dtdv_id++;
	vars[1].dtdv_type.dtdt_kind = DIF_TYPE_STRING;
	vars[1].dtdv_type.dtdt_flags = DIF_TF_BYREF;
	b.dtdo_vartab = vars;
	b.dtdo_varlen = 2;
	b.dtdo_rtype.dtdt_kind = DIF_TYPE_CTF;
	b.dtdo_rtype.dtdt_ckind = CTF_K_INTEGER;
	b.dtdo_rtype.dtdt_size = 8;
	return (difo_clone(&b));
}

/* The guest form of difo_base(): every relocation applied. */
static dtrace_difo_t *
difo_guest(const dtrace_difo_t *b)
{
	dtrace_difo_t *g = difo_clone(b);

	g->dtdo_intlen = 2;
	g->dtdo_inttab[1] = 0xfeed;
	g->dtdo_buf[0] = DIF_INSTR_SETX(1, 1);
	g->dtdo_buf[1] = DIF_INSTR_LOAD(DIF_OP_LDX, 1, 2);
	g->dtdo_buf[2] = DIF_INSTR_LOAD(DIF_OP_ULDUW, 2, 3);
	g->dtdo_buf[3] = DIF_INSTR_NOP;
	g->dtdo_buf[4] = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, DIF_TYPE_CTF, 0, 3);
	return (g);
}

typedef void (*mutate_f)(dtrace_difo_t *b, dtrace_difo_t *g);

#define	MUT(name, body)	static void name(dtrace_difo_t *b, \
	dtrace_difo_t *g) { (void) b; (void) g; body; }
MUT(m_len, g->dtdo_len--)
MUT(m_buf_null_b, free(b->dtdo_buf); b->dtdo_buf = NULL)
MUT(m_buf_null_g, free(g->dtdo_buf); g->dtdo_buf = NULL)
MUT(m_intlen, b->dtdo_intlen = 3)
MUT(m_strlen, g->dtdo_strlen--)
MUT(m_symlen, g->dtdo_symlen--)
MUT(m_varlen, g->dtdo_varlen--)
MUT(m_destructive, g->dtdo_destructive = 1)
MUT(m_rkind, g->dtdo_rtype.dtdt_kind = 9)
MUT(m_rflags, g->dtdo_rtype.dtdt_flags = 0x4)
MUT(m_rpad, g->dtdo_rtype.dtdt_pad = 1)
MUT(m_rkind_change, g->dtdo_rtype.dtdt_kind = DIF_TYPE_STRING)
MUT(m_rckind, g->dtdo_rtype.dtdt_ckind = CTF_K_POINTER)
MUT(m_rsize, g->dtdo_rtype.dtdt_size = 4)
MUT(m_rflag_change, g->dtdo_rtype.dtdt_flags = DIF_TF_BYREF)
MUT(m_int_null_b, free(b->dtdo_inttab); b->dtdo_inttab = NULL)
MUT(m_int_null_g, b->dtdo_intlen = 0; g->dtdo_buf[0] = DIF_INSTR_SETX(0, 1);
    b->dtdo_buf[0] = DIF_INSTR_SETX(0, 1); free(g->dtdo_inttab);
    g->dtdo_inttab = NULL)
MUT(m_int_null_g2, free(g->dtdo_inttab); g->dtdo_inttab = NULL)
MUT(m_str_null_b, free(b->dtdo_strtab); b->dtdo_strtab = NULL)
MUT(m_str_null_g, free(g->dtdo_strtab); g->dtdo_strtab = NULL)
MUT(m_sym_null_b, free(b->dtdo_symtab); b->dtdo_symtab = NULL)
MUT(m_sym_null_g, free(g->dtdo_symtab); g->dtdo_symtab = NULL)
MUT(m_var_null_b, free(b->dtdo_vartab); b->dtdo_vartab = NULL)
MUT(m_var_null_g, free(g->dtdo_vartab); g->dtdo_vartab = NULL)
MUT(m_int_value, g->dtdo_inttab[0] = 8)
MUT(m_str_value, g->dtdo_strtab[1] = 'y')
MUT(m_sym_value, g->dtdo_symtab[1] = 'S')
MUT(m_v_kind, g->dtdo_vartab[0].dtdv_type.dtdt_kind = 9)
MUT(m_v_flags, g->dtdo_vartab[0].dtdv_type.dtdt_flags = 4)
MUT(m_v_pad, g->dtdo_vartab[0].dtdv_type.dtdt_pad = 1)
MUT(m_v_name, g->dtdo_vartab[0].dtdv_name = 0)
MUT(m_v_id, g->dtdo_vartab[0].dtdv_id++)
MUT(m_v_vkind, g->dtdo_vartab[0].dtdv_kind = DIFV_KIND_ARRAY)
MUT(m_v_scope, g->dtdo_vartab[0].dtdv_scope = DIFV_SCOPE_THREAD)
MUT(m_v_vflags, g->dtdo_vartab[0].dtdv_flags = DIFV_F_MOD)
MUT(m_v_tkind, g->dtdo_vartab[0].dtdv_type.dtdt_kind = DIF_TYPE_STRING)
MUT(m_v_tckind, g->dtdo_vartab[0].dtdv_type.dtdt_ckind = 3)
MUT(m_v_tflags, g->dtdo_vartab[0].dtdv_type.dtdt_flags = DIF_TF_BYUREF)
MUT(m_v_object, g->dtdo_vartab[0].dtdv_object[0] = 1)
MUT(m_usetx_op, g->dtdo_buf[0] = DIF_INSTR_FMT(DIF_OP_NOP, 0, 0, 1))
MUT(m_usetx_rd, g->dtdo_buf[0] = DIF_INSTR_SETX(1, 2))
MUT(m_usetx_idx, g->dtdo_buf[0] = DIF_INSTR_SETX(5, 1))
MUT(m_uload_op, g->dtdo_buf[1] = DIF_INSTR_LOAD(DIF_OP_ULDX, 1, 2))
MUT(m_uload_r1, g->dtdo_buf[1] = DIF_INSTR_LOAD(DIF_OP_LDX, 3, 2))
MUT(m_uload_rd, g->dtdo_buf[1] = DIF_INSTR_LOAD(DIF_OP_LDX, 1, 5))
MUT(m_uload_r2, g->dtdo_buf[1] = DIF_INSTR_FMT(DIF_OP_LDX, 1, 1, 2))
MUT(m_uuload_op, g->dtdo_buf[2] = DIF_INSTR_LOAD(DIF_OP_LDX, 2, 3))
MUT(m_uuload_r1, g->dtdo_buf[2] = DIF_INSTR_LOAD(DIF_OP_ULDSB, 3, 3))
MUT(m_typecast, g->dtdo_buf[3] = DIF_INSTR_FMT(DIF_OP_TYPECAST, 0, 0, 4))
MUT(m_pushtv_op, g->dtdo_buf[4] = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR,
    DIF_TYPE_CTF, 0, 3))
MUT(m_pushtv_type, g->dtdo_buf[4] = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV,
    DIF_TYPE_STRING, 0, 3))
MUT(m_pushtv_rs, g->dtdo_buf[4] = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV,
    DIF_TYPE_CTF, 0, 4))
MUT(m_exact, g->dtdo_buf[5] = DIF_INSTR_SETX(0, 5))
MUT(m_added_unused, g->dtdo_intlen = 3)

MUT(m_usetx_nop_noadd, g->dtdo_intlen = 1; g->dtdo_buf[0] = DIF_INSTR_NOP)
MUT(m_usetx_idx_noadd, g->dtdo_intlen = 1; g->dtdo_buf[0] =
    DIF_INSTR_SETX(5, 1))
MUT(m_uload_alu, g->dtdo_buf[1] = DIF_INSTR_FMT(DIF_OP_ADD, 1, 1, 2))
MUT(m_uuload_rd, g->dtdo_buf[2] = DIF_INSTR_LOAD(DIF_OP_ULDUW, 2, 5))
MUT(m_uuload_r2, g->dtdo_buf[2] = DIF_INSTR_FMT(DIF_OP_ULDUW, 2, 1, 3))
MUT(m_pushtv_r2, g->dtdo_buf[4] = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV,
    DIF_TYPE_CTF, 2, 3))

/* Two USETX: one resolved to an added constant, one to an existing one. */
static void
a_mixed_reloc(dtrace_difo_t *b, dtrace_difo_t *g)
{
	b->dtdo_buf[5] = DIF_INSTR_USETX(0, 4);
	g->dtdo_buf[5] = DIF_INSTR_SETX(0, 4);
}

/* Accepted variants. */
MUT(a_empty, b->dtdo_len = g->dtdo_len = 0; b->dtdo_intlen = 0;
    g->dtdo_intlen = 0)
MUT(a_var_none, b->dtdo_vartab[0].dtdv_type.dtdt_kind = DIF_TYPE_NONE;
    g->dtdo_vartab[0].dtdv_type.dtdt_kind = DIF_TYPE_NONE)
MUT(a_var_bottom, b->dtdo_vartab[0].dtdv_type.dtdt_kind = DIF_TYPE_BOTTOM;
    g->dtdo_vartab[0].dtdv_type.dtdt_kind = DIF_TYPE_BOTTOM)
MUT(a_rtype_none, b->dtdo_rtype.dtdt_kind = DIF_TYPE_NONE;
    g->dtdo_rtype.dtdt_kind = DIF_TYPE_NONE; b->dtdo_rtype.dtdt_ckind = 0;
    g->dtdo_rtype.dtdt_ckind = 0)
MUT(a_rtype_string, b->dtdo_rtype.dtdt_kind = DIF_TYPE_STRING;
    g->dtdo_rtype.dtdt_kind = DIF_TYPE_STRING)
MUT(a_pushtv_ctf, b->dtdo_buf[4] = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV,
    DIF_TYPE_CTF, 0, 3))
MUT(a_pushtv_string, b->dtdo_buf[4] = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV,
    DIF_TYPE_STRING, 0, 3); g->dtdo_buf[4] = b->dtdo_buf[4])

MUT(m_bottom_to_none, b->dtdo_rtype.dtdt_kind = DIF_TYPE_BOTTOM;
    g->dtdo_rtype.dtdt_kind = DIF_TYPE_NONE)
MUT(a_bottom_rtype, b->dtdo_rtype.dtdt_kind = DIF_TYPE_BOTTOM;
    b->dtdo_rtype.dtdt_ckind = 0; b->dtdo_rtype.dtdt_size = 0)
MUT(a_varsize, g->dtdo_vartab[0].dtdv_type.dtdt_size = 16)
MUT(a_no_reloc, g->dtdo_intlen = 1; g->dtdo_buf[0] = DIF_INSTR_SETX(0, 1))

static void
case_verify_difo(void)
{
	static const struct { const char *name; mutate_f fn; int accept; }
	    muts[] = {
		{ "len", m_len, 0 }, { "buf-null-base", m_buf_null_b, 0 },
		{ "buf-null-guest", m_buf_null_g, 0 }, { "intlen", m_intlen, 0 },
		{ "strlen", m_strlen, 0 }, { "symlen", m_symlen, 0 },
		{ "varlen", m_varlen, 0 }, { "destructive", m_destructive, 0 },
		{ "rtype-kind-invalid", m_rkind, 0 },
		{ "rtype-flags-invalid", m_rflags, 0 },
		{ "rtype-pad", m_rpad, 0 }, { "rtype-kind", m_rkind_change, 0 },
		{ "rtype-ckind", m_rckind, 0 }, { "rtype-size", m_rsize, 0 },
		{ "rtype-flags", m_rflag_change, 0 },
		{ "inttab-null-base", m_int_null_b, 0 },
		{ "inttab-null-guest-only", m_int_null_g, 0 },
		{ "inttab-null-guest", m_int_null_g2, 0 },
		{ "strtab-null-base", m_str_null_b, 0 },
		{ "strtab-null-guest", m_str_null_g, 0 },
		{ "symtab-null-base", m_sym_null_b, 0 },
		{ "symtab-null-guest", m_sym_null_g, 0 },
		{ "vartab-null-base", m_var_null_b, 0 },
		{ "vartab-null-guest", m_var_null_g, 0 },
		{ "inttab-value", m_int_value, 0 },
		{ "strtab-value", m_str_value, 0 },
		{ "symtab-value", m_sym_value, 0 },
		{ "var-type-invalid", m_v_kind, 0 },
		{ "var-type-flags-invalid", m_v_flags, 0 },
		{ "var-type-pad", m_v_pad, 0 }, { "var-name", m_v_name, 0 },
		{ "var-id", m_v_id, 0 }, { "var-kind", m_v_vkind, 0 },
		{ "var-scope", m_v_scope, 0 }, { "var-flags", m_v_vflags, 0 },
		{ "var-type-kind", m_v_tkind, 0 },
		{ "var-type-ckind", m_v_tckind, 0 },
		{ "var-type-flags", m_v_tflags, 0 },
		{ "var-object", m_v_object, 0 },
		{ "usetx-opcode", m_usetx_op, 0 }, { "usetx-rd", m_usetx_rd, 0 },
		{ "usetx-index", m_usetx_idx, 0 },
		{ "uload-opcode", m_uload_op, 0 }, { "uload-r1", m_uload_r1, 0 },
		{ "uload-rd", m_uload_rd, 0 }, { "uload-r2", m_uload_r2, 0 },
		{ "uuload-opcode", m_uuload_op, 0 },
		{ "uuload-r1", m_uuload_r1, 0 },
		{ "typecast-kept", m_typecast, 0 },
		{ "pushtv-opcode", m_pushtv_op, 0 },
		{ "pushtv-type", m_pushtv_type, 0 },
		{ "pushtv-register", m_pushtv_rs, 0 },
		{ "exact-instruction", m_exact, 0 },
		{ "added-constant-unused", m_added_unused, 0 },
		{ "usetx-nop", m_usetx_nop_noadd, 0 },
		{ "usetx-index-range", m_usetx_idx_noadd, 0 },
		{ "uload-alu", m_uload_alu, 0 },
		{ "uuload-rd", m_uuload_rd, 0 },
		{ "uuload-r2", m_uuload_r2, 0 },
		{ "pushtv-r2", m_pushtv_r2, 0 },
		{ "empty-difo", a_empty, 1 },
		{ "usetx-mixed-relocation", a_mixed_reloc, 1 },
		{ "var-type-none", a_var_none, 1 },
		{ "var-type-bottom", a_var_bottom, 1 },
		{ "rtype-none", a_rtype_none, 1 },
		{ "rtype-string", a_rtype_string, 1 },
		{ "pushtv-ctf-kept", a_pushtv_ctf, 1 },
		{ "pushtv-string-kept", a_pushtv_string, 1 },
		/* The linker never resolves BOTTOM to NONE (relocateRet). */
		{ "bottom-rtype-to-none", m_bottom_to_none, 0 },
		/* BOTTOM resolved to an 8-byte by-value CTF integer. */
		{ "bottom-rtype-resolved", a_bottom_rtype, 1 },
		{ "variable-size-reconciled", a_varsize, 1 },
		/* The guest resolves user symbols; an existing slot is as
		 * good as an added one (vprog-transform's relocation case). */
		{ "usetx-to-existing-constant", a_no_reloc, 1 },
	};
	dtrace_hdl_t *dtp = open_nodev();
	void *ctx = dt_verictx_init(dtp);
	char target[] = "test:::verify";
	int bad = 0;
	char *errs;

	/* The fully relocated guest DIFO verifies against the host's. */
	{
		dtrace_difo_t *b = difo_base(), *g = difo_guest(b);

		CHECK("verify-difo-relocated", dt_prog_verify_difo(ctx, b, g,
		    target, target) == 0);
		difo_release(b);
		difo_release(g);
	}
	dt_verictx_rewind(ctx, 0);
	errs = NULL;
	for (size_t i = 0; i < sizeof (muts) / sizeof (muts[0]); i++) {
		dtrace_difo_t *b = difo_base(), *g = difo_guest(b);
		int v;
		char *msg;

		muts[i].fn(b, g);
		vd_args.ctx = ctx;
		vd_args.b = b;
		vd_args.g = g;
		vd_args.target = target;
		msg = capture_stderr(verify_difo_call, NULL);
		v = vd_args.rc;
		free(msg);
		if ((v == 0) != muts[i].accept) {
			printf("verify-difo %s: got %d\n", muts[i].name, v);
			bad++;
		}
		difo_release(b);
		difo_release(g);
	}
	{
		static const uint8_t ld[] = { DIF_OP_LDSB, DIF_OP_LDSH,
		    DIF_OP_LDSW, DIF_OP_LDX, DIF_OP_LDUB, DIF_OP_LDUH,
		    DIF_OP_LDUW };
		static const uint8_t uld[] = { DIF_OP_ULDSB, DIF_OP_ULDSH,
		    DIF_OP_ULDSW, DIF_OP_ULDX, DIF_OP_ULDUB, DIF_OP_ULDUH,
		    DIF_OP_ULDUW };

		/* ULOAD/UULOAD may become any kernel/user load width. */
		for (int i = 0; i < 7; i++) {
			dtrace_difo_t *b = difo_base(), *g = difo_guest(b);

			g->dtdo_buf[1] = DIF_INSTR_LOAD(ld[i], 1, 2);
			g->dtdo_buf[2] = DIF_INSTR_LOAD(uld[i], 2, 3);
			if (vd_quiet(ctx, b, g, target) != 0) {
				printf("verify-difo load width %d rejected\n", i);
				bad++;
			}
			difo_release(b);
			difo_release(g);
		}
	}
	CHECK("verify-difo-fields", bad == 0);
	(void) errs;

	/* Argument checks: no context, no handle, no DIFO. */
	{
		dtrace_difo_t *b = difo_base(), *g = difo_guest(b);
		dtrace_hdl_t *saved = *(dtrace_hdl_t **)ctx;

		CHECK("verify-difo-null-args", dt_prog_verify_difo(NULL, b, g,
		    target, target) != 0 && dt_prog_verify_difo(ctx, NULL, g,
		    target, target) != 0 && dt_prog_verify_difo(ctx, b, NULL,
		    target, target) != 0);
		*(dtrace_hdl_t **)ctx = NULL;
		CHECK("verify-difo-null-handle", dt_prog_verify_difo(ctx, b, g,
		    target, target) != 0);
		*(dtrace_hdl_t **)ctx = saved;
		difo_release(b);
		difo_release(g);
	}

	/*
	 * A ULOAD/UULOAD that only feeds a by-reference RET may be removed
	 * (NOP) when the return type keeps its by-reference flag.
	 */
	{
		dif_instr_t code[] = { DIF_INSTR_LOAD(DIF_OP_ULOAD, 1, 2),
		    DIF_INSTR_RET(2) };
		dif_instr_t ucode[] = { DIF_INSTR_LOAD(DIF_OP_UULOAD, 1, 2),
		    DIF_INSTR_RET(2) };
		dtrace_difo_t *b = make_difo(code, 2), *g;
		int r1, r2, r3, r4, r5;

		b->dtdo_rtype.dtdt_kind = DIF_TYPE_STRING;
		b->dtdo_rtype.dtdt_flags = DIF_TF_BYREF;
		g = difo_clone(b);
		g->dtdo_buf[0] = DIF_INSTR_NOP;
		r1 = dt_prog_verify_difo(ctx, b, g, target, target);
		/* The RET must return the loaded register. */
		b->dtdo_buf[1] = g->dtdo_buf[1] = DIF_INSTR_RET(3);
		r2 = vd_quiet(ctx, b, g, target);
		b->dtdo_buf[1] = g->dtdo_buf[1] = DIF_INSTR_RET(2);
		/* By-value results cannot drop the load. */
		b->dtdo_rtype.dtdt_flags = g->dtdo_rtype.dtdt_flags = 0;
		b->dtdo_rtype.dtdt_kind = g->dtdo_rtype.dtdt_kind =
		    DIF_TYPE_CTF;
		r3 = vd_quiet(ctx, b, g, target);
		/* The same for user loads. */
		memcpy(b->dtdo_buf, ucode, sizeof (ucode));
		b->dtdo_rtype.dtdt_kind = g->dtdo_rtype.dtdt_kind =
		    DIF_TYPE_STRING;
		b->dtdo_rtype.dtdt_flags = g->dtdo_rtype.dtdt_flags =
		    DIF_TF_BYUREF;
		r4 = dt_prog_verify_difo(ctx, b, g, target, target);
		/* Only a NOP may replace it, keeping the same reference kind. */
		g->dtdo_buf[0] = DIF_INSTR_FMT(DIF_OP_ADD, 1, 1, 2);
		r5 = vd_quiet(ctx, b, g, target);
		g->dtdo_buf[0] = DIF_INSTR_NOP;
		g->dtdo_rtype.dtdt_flags = DIF_TF_BYREF;
		r5 |= vd_quiet(ctx, b, g, target) == 0;
		g->dtdo_rtype.dtdt_flags = DIF_TF_BYUREF;
		memcpy(b->dtdo_buf, code, sizeof (code));
		g->dtdo_buf[0] = DIF_INSTR_FMT(DIF_OP_ADD, 1, 1, 2);
		b->dtdo_rtype.dtdt_flags = g->dtdo_rtype.dtdt_flags =
		    DIF_TF_BYREF;
		r5 |= vd_quiet(ctx, b, g, target) == 0;
		g->dtdo_buf[0] = DIF_INSTR_NOP;
		g->dtdo_rtype.dtdt_flags = DIF_TF_BYUREF;
		r5 |= vd_quiet(ctx, b, g, target) == 0;
		b->dtdo_buf[1] = g->dtdo_buf[1] = DIF_INSTR_RET(3);
		r5 |= vd_quiet(ctx, b, g, target) == 0;
		memcpy(b->dtdo_buf, ucode, sizeof (ucode));
		g->dtdo_buf[1] = b->dtdo_buf[1];
		b->dtdo_rtype.dtdt_flags = g->dtdo_rtype.dtdt_flags = 0;
		r5 |= vd_quiet(ctx, b, g, target) == 0;
		b->dtdo_buf[1] = g->dtdo_buf[1] = DIF_INSTR_RET(3);
		b->dtdo_rtype.dtdt_flags = g->dtdo_rtype.dtdt_flags =
		    DIF_TF_BYUREF;
		r5 |= vd_quiet(ctx, b, g, target) == 0;
		b->dtdo_buf[1] = g->dtdo_buf[1] = DIF_INSTR_RET(2);
		g->dtdo_rtype.dtdt_flags = DIF_TF_BYREF;
		r5 |= vd_quiet(ctx, b, g, target) == 0;
		g->dtdo_rtype.dtdt_flags = DIF_TF_BYUREF;
		g->dtdo_buf[0] = DIF_INSTR_FMT(DIF_OP_ADD, 1, 1, 2);
		r5 |= vd_quiet(ctx, b, g, target) == 0;
		g->dtdo_buf[0] = DIF_INSTR_NOP;
		/* A load at the end of the DIFO has no RET to feed. */
		b->dtdo_len = g->dtdo_len = 1;
		r5 |= vd_quiet(ctx, b, g, target) == 0;
		memcpy(b->dtdo_buf, code, sizeof (code));
		r5 |= vd_quiet(ctx, b, g, target) == 0;
		{
			/*
			 * With a BOTTOM (unresolved) host return type the flags
			 * are not compared up front, so the elision itself
			 * must require the same by-reference kind.
			 */
			const dif_instr_t *codes[] = { code, ucode };
			int e = 0;

			for (int c = 0; c < 2; c++) {
				memcpy(b->dtdo_buf, codes[c], sizeof (code));
				b->dtdo_len = g->dtdo_len = 2;
				g->dtdo_buf[0] = DIF_INSTR_NOP;
				g->dtdo_buf[1] = b->dtdo_buf[1];
				b->dtdo_rtype.dtdt_kind = DIF_TYPE_BOTTOM;
				g->dtdo_rtype.dtdt_kind = DIF_TYPE_STRING;
				b->dtdo_rtype.dtdt_flags = DIF_TF_BYREF;
				g->dtdo_rtype.dtdt_flags = DIF_TF_BYUREF;
				e += vd_quiet(ctx, b, g, target) != 0;
				g->dtdo_rtype.dtdt_flags = DIF_TF_BYREF;
				e += vd_quiet(ctx, b, g, target) == 0;
				/* No by-reference flag at all. */
				b->dtdo_rtype.dtdt_flags = 0;
				g->dtdo_rtype.dtdt_flags = 0;
				g->dtdo_rtype.dtdt_kind = DIF_TYPE_CTF;
				e += vd_quiet(ctx, b, g, target) != 0;
			}
			r5 |= e != 6;
		}
		CHECK("verify-difo-load-elision", r1 == 0 && r2 != 0 &&
		    r3 != 0 && r4 == 0 && r5 != 0);
		dt_difo_free(dtp, b);
		difo_release(g);
	}

	/*
	 * Variables already accepted in this verification (the context) fix
	 * the type of the same variable in later DIFOs.
	 */
	{
		dtrace_difo_t *b = difo_base(), *g = difo_guest(b);
		dtrace_difo_t *b2 = difo_base(), *g2 = difo_guest(b2);
		dtrace_prog_t *p = dt_program_create(dtp);
		int kinds[] = { DTRACEACT_DIFEXPR };
		int r1, r2, r3, r4;

		/* A linked (guest-form) DIFO verifies against itself. */
		add_stmt(dtp, p, "", "test", "ctx", 1, kinds, &g, NULL);
		/* Self-verification adds the program's DIFOs to the context. */
		r1 = dt_prog_verify(ctx, p, p);
		r2 = dt_prog_verify_difo(ctx, b2, g2, target, target);
		g2->dtdo_vartab[0].dtdv_type.dtdt_ckind = 5;
		b2->dtdo_vartab[0].dtdv_type.dtdt_ckind = 5;
		r3 = vd_quiet(ctx, b2, g2, target);
		b2->dtdo_vartab[0].dtdv_type.dtdt_ckind = 0;
		g2->dtdo_vartab[0].dtdv_type.dtdt_ckind = 0;
		b2->dtdo_vartab[0].dtdv_type.dtdt_flags = DIF_TF_BYREF;
		g2->dtdo_vartab[0].dtdv_type.dtdt_flags = DIF_TF_BYREF;
		r3 = r3 && vd_quiet(ctx, b2, g2, target) != 0;
		b2->dtdo_vartab[0].dtdv_type.dtdt_flags = 0;
		g2->dtdo_vartab[0].dtdv_type.dtdt_flags = 0;
		/* (pad is rejected per DIFO; the context check is redundant.) */
		g2->dtdo_vartab[0].dtdv_type.dtdt_kind = DIF_TYPE_STRING;
		b2->dtdo_vartab[0].dtdv_type.dtdt_kind = DIF_TYPE_STRING;
		r3 = r3 && vd_quiet(ctx, b2, g2, target) != 0;
		g2->dtdo_vartab[0].dtdv_type.dtdt_kind = DIF_TYPE_CTF;
		b2->dtdo_vartab[0].dtdv_type.dtdt_kind = DIF_TYPE_CTF;
		/* A larger size in the new DIFO grows the accepted one. */
		g2->dtdo_vartab[0].dtdv_type.dtdt_size = 32;
		r4 = dt_prog_verify_difo(ctx, b2, g2, target, target);
		if (getenv("PP_DEBUG"))
			printf("ctx %d %d %d %d %u\n", r1, r2, r3, r4,
			    g->dtdo_vartab[0].dtdv_type.dtdt_size);
		CHECK("verify-difo-context-types", r1 == 0 && r2 == 0 &&
		    r3 != 0 && r4 == 0 &&
		    g->dtdo_vartab[0].dtdv_type.dtdt_size == 32);
		dt_verictx_rewind(ctx, 0);
		dt_program_destroy(dtp, p);
		difo_release(b);
		difo_release(b2);
		difo_release(g2);
	}
	/*
	 * BOTTOM host return types (dt_prog_bottom_rtype_ok): register-sized
	 * by-value CTF results, the compiled size kept, and the load-elision
	 * rule when the by-reference kind is not preserved.
	 */
	{
		static const struct { dtrace_diftype_t rt; int accept; } br[] = {
			{ { DIF_TYPE_CTF, CTF_K_INTEGER, 0, 0, 1 }, 1 },
			{ { DIF_TYPE_CTF, CTF_K_INTEGER, 0, 0, 2 }, 1 },
			{ { DIF_TYPE_CTF, CTF_K_ENUM, 0, 0, 0 }, 1 },
			{ { DIF_TYPE_CTF, CTF_K_FLOAT, 0, 0, 8 }, 1 },
			{ { DIF_TYPE_CTF, CTF_K_INTEGER, 0, 0, 6 }, 0 },
		};
		dif_instr_t ret[] = { DIF_INSTR_RET(0) };
		dif_instr_t ld[] = { DIF_INSTR_LOAD(DIF_OP_ULOAD, 1, 2),
		    DIF_INSTR_RET(2) };
		dif_instr_t uld[] = { DIF_INSTR_LOAD(DIF_OP_UULOAD, 1, 2),
		    DIF_INSTR_RET(2) };
		dtrace_difo_t *b = make_difo(ret, 1), *g;
		int e = 0;

		b->dtdo_rtype.dtdt_kind = DIF_TYPE_BOTTOM;
		g = difo_clone(b);
		for (size_t i = 0; i < sizeof (br) / sizeof (br[0]); i++) {
			g->dtdo_rtype = br[i].rt;
			if ((vd_quiet(ctx, b, g, target) == 0) != br[i].accept) {
				printf("bottom rtype %zu wrong\n", i);
				e++;
			}
		}
		dt_difo_free(dtp, b);
		difo_release(g);
		/* By-value BOTTOM resolved to an 8-byte integer: no elision. */
		b = make_difo(ld, 2);
		b->dtdo_rtype.dtdt_kind = DIF_TYPE_BOTTOM;
		g = difo_clone(b);
		g->dtdo_buf[0] = DIF_INSTR_NOP;
		g->dtdo_rtype = (dtrace_diftype_t){ DIF_TYPE_CTF, CTF_K_INTEGER,
		    0, 0, 8 };
		e += vd_quiet(ctx, b, g, target) == 0;
		/* BYUREF string resolved with BYREF added: kind not kept. */
		b->dtdo_rtype.dtdt_flags = DIF_TF_BYUREF;
		g->dtdo_rtype = (dtrace_diftype_t){ DIF_TYPE_STRING, 0,
		    DIF_TF_BYUREF | DIF_TF_BYREF, 0, 256 };
		e += vd_quiet(ctx, b, g, target) == 0;
		memcpy(b->dtdo_buf, uld, sizeof (uld));
		e += vd_quiet(ctx, b, g, target) == 0;
		/* ...while a kept kind still allows it. */
		g->dtdo_rtype.dtdt_flags = DIF_TF_BYUREF | DIF_TF_BYREF;
		b->dtdo_rtype.dtdt_flags = DIF_TF_BYUREF | DIF_TF_BYREF;
		e += vd_quiet(ctx, b, g, target) != 0;
		dt_difo_free(dtp, b);
		difo_release(g);
		CHECK("verify-difo-bottom-rtype-sizes", e == 0);
	}

	/* Mark and rewind bracket the accepted DIFO set. */
	CHECK("verictx-mark", dt_verictx_mark(ctx) == 0 &&
	    dt_verictx_mark(NULL) == 0);
	dt_verictx_rewind(NULL, 0);
	dt_verictx_teardown(ctx);
	dt_verictx_teardown(NULL);
	dtrace_close(dtp);
}

/* ------------------------------------------------------------------ */
/* dt_prog_verify: a returned program must match the host program in   */
/* every statement, ECB, action and DIFO (relocations aside), and its  */
/* enabled-probe report must be covered by the host's selectors.       */

#define	VSRC	"test:kernel:a*:entry /arg0/ { printf(\"%d\\n\", arg0); " \
	"@c[arg1] = count(); } dtrace:::END { printf(\"%s\", \"x\"); " \
	"trace(2); }"

static struct {
	void *ctx;
	dtrace_prog_t *a, *b;
	int rc;
} pv_args;

static void
prog_verify_call(void *arg)
{
	(void) arg;
	pv_args.rc = dt_prog_verify(pv_args.ctx, pv_args.a, pv_args.b);
}

static int
pv_quiet(void *ctx, dtrace_prog_t *a, dtrace_prog_t *b)
{
	free(capture_stderr((pv_args.ctx = ctx, pv_args.a = a, pv_args.b = b,
	    prog_verify_call), NULL));
	return (pv_args.rc);
}

static dtrace_stmtdesc_t *
nth_stmt(dtrace_prog_t *p, int n)
{
	dt_stmt_t *stp = dt_list_next(&p->dp_stmts);

	while (n-- > 0)
		stp = dt_list_next(stp);
	return (stp->ds_desc);
}

/* A guest report naming the host's selector-matched probes. */
static void
set_eprobes(dtrace_prog_t *p, int n)
{
	p->dp_eprobes = calloc(n > 0 ? n : 1, sizeof (dtrace_probedesc_t));
	p->dp_neprobes = n;
	for (int i = 0; i < n; i++) {
		dtrace_probedesc_t *d = &p->dp_eprobes[i];

		d->dtpd_id = 10 + i;
		strlcpy(d->dtpd_provider, "test", sizeof (d->dtpd_provider));
		strlcpy(d->dtpd_mod, "kernel", sizeof (d->dtpd_mod));
		strlcpy(d->dtpd_func, i == 0 ? "alpha" : "always",
		    sizeof (d->dtpd_func));
		strlcpy(d->dtpd_name, "entry", sizeof (d->dtpd_name));
	}
}

typedef void (*pmut_f)(dtrace_prog_t *a, dtrace_prog_t *b);
#define	PMUT(name, body) static void name(dtrace_prog_t *a, \
	dtrace_prog_t *b) { (void) a; (void) b; body; }

static dt_ident_t agg_noname;
static dtrace_hdl_t *pv_dtp;

PMUT(p_dofversion, b->dp_dofversion++)
PMUT(p_rflags, b->dp_rflags ^= 1)
PMUT(p_exec, b->dp_exec ^= 1)
PMUT(p_desc_null, ((dt_stmt_t *)dt_list_next(&b->dp_stmts))->ds_desc = NULL)
PMUT(p_desc_null_base, ((dt_stmt_t *)dt_list_next(&a->dp_stmts))->ds_desc =
    NULL)
PMUT(p_ecb_null, nth_stmt(b, 0)->dtsd_ecbdesc = NULL)
PMUT(p_name_unterminated, memset(nth_stmt(b, 0)->dtsd_ecbdesc->dted_probe.
    dtpd_name, 'x', DTRACE_NAMELEN))
PMUT(p_name_unterminated_base, memset(nth_stmt(a, 0)->dtsd_ecbdesc->
    dted_probe.dtpd_name, 'x', DTRACE_NAMELEN))
PMUT(p_name, nth_stmt(b, 0)->dtsd_ecbdesc->dted_probe.dtpd_name[0] = 'E')
PMUT(p_probe_id, nth_stmt(b, 0)->dtsd_ecbdesc->dted_probe.dtpd_id = 4)
PMUT(p_descattr, nth_stmt(b, 0)->dtsd_descattr.dtat_data++)
PMUT(p_stmtattr, nth_stmt(b, 0)->dtsd_stmtattr.dtat_name++)
PMUT(p_aggdata_null, for (int i = 0; i < 4; i++)
    nth_stmt(b, i)->dtsd_aggdata = NULL)
PMUT(p_aggdata_name, for (int i = 0; i < 4; i++)
    if (nth_stmt(b, i)->dtsd_aggdata != NULL) {
	    agg_noname = *(dt_ident_t *)nth_stmt(b, i)->dtsd_aggdata;
	    agg_noname.di_name = NULL;
	    nth_stmt(b, i)->dtsd_aggdata = &agg_noname; })
PMUT(p_aggdata_id, for (int i = 0; i < 4; i++)
    if (nth_stmt(b, i)->dtsd_aggdata != NULL) {
	    agg_noname = *(dt_ident_t *)nth_stmt(b, i)->dtsd_aggdata;
	    agg_noname.di_id++;
	    nth_stmt(b, i)->dtsd_aggdata = &agg_noname; })
PMUT(p_uarg, nth_stmt(b, 0)->dtsd_ecbdesc->dted_uarg++)
PMUT(p_pred_null, nth_stmt(b, 0)->dtsd_ecbdesc->dted_pred.dtpdd_difo = NULL)
PMUT(p_pred_difo, nth_stmt(b, 0)->dtsd_ecbdesc->dted_pred.dtpdd_difo->
    dtdo_destructive = 1)
PMUT(p_span_loop, nth_stmt(b, 0)->dtsd_action_last->dtad_next =
    nth_stmt(b, 0)->dtsd_action)
PMUT(p_span_base_loop, nth_stmt(a, 0)->dtsd_action_last->dtad_next =
    nth_stmt(a, 0)->dtsd_action)
PMUT(p_no_actions, nth_stmt(b, 0)->dtsd_action = NULL;
    nth_stmt(b, 0)->dtsd_action_last = NULL)
PMUT(p_base_no_actions, nth_stmt(a, 0)->dtsd_action = NULL;
    nth_stmt(a, 0)->dtsd_action_last = NULL)
PMUT(p_act_difo_null, nth_stmt(b, 0)->dtsd_action->dtad_difo = NULL)
PMUT(p_act_kind, nth_stmt(b, 0)->dtsd_action->dtad_kind = DTRACEACT_DIFEXPR)
PMUT(p_act_ntuple, nth_stmt(b, 0)->dtsd_action->dtad_ntuple++)
PMUT(p_act_arg, nth_stmt(b, 0)->dtsd_action->dtad_arg++)
PMUT(p_act_return, nth_stmt(b, 0)->dtsd_action->dtad_return ^= 1)
PMUT(p_act_uarg, nth_stmt(b, 0)->dtsd_action->dtad_uarg = 0)
PMUT(p_act_uarg_base, nth_stmt(a, 0)->dtsd_action->dtad_uarg = 0)
PMUT(p_act_difo, nth_stmt(b, 0)->dtsd_action->dtad_difo->dtdo_destructive = 1)
PMUT(p_span_shorter, {
	dtrace_stmtdesc_t *sd = nth_stmt(b, 1);	/* tuple + count */
	sd->dtsd_action_last = sd->dtsd_action; })
PMUT(p_extra_stmt, {
	dtrace_stmtdesc_t *sd = dtrace_stmt_create(pv_dtp,
	    nth_stmt(b, 0)->dtsd_ecbdesc);
	dtrace_stmt_add(pv_dtp, b, sd); })
PMUT(p_extra_stmt_base, {
	dtrace_stmtdesc_t *sd = dtrace_stmt_create(pv_dtp,
	    nth_stmt(a, 0)->dtsd_ecbdesc);
	dtrace_stmt_add(pv_dtp, a, sd); })
PMUT(p_ep_count, set_eprobes(b, 1); free(b->dp_eprobes); b->dp_eprobes = NULL)
PMUT(p_ep_null, b->dp_neprobes = 0; b->dp_eprobes = calloc(1, 64))
PMUT(p_ep_huge, set_eprobes(b, 1); b->dp_neprobes = 64 * 1024 + 1)
PMUT(p_ep_order, set_eprobes(b, 2); b->dp_eprobes[1].dtpd_id = 10)
PMUT(p_ep_limit, set_eprobes(b, 1); b->dp_eprobes[0].dtpd_id = (1U << 20) + 1)
PMUT(p_ep_vmid, set_eprobes(b, 1); b->dp_eprobes[0].dtpd_vmid = 2)
PMUT(p_ep_unterminated, set_eprobes(b, 1);
    memset(b->dp_eprobes[0].dtpd_func, 'f', DTRACE_FUNCNAMELEN))
PMUT(p_ep_provider, set_eprobes(b, 1); b->dp_eprobes[0].dtpd_provider[0] = 0)
PMUT(p_ep_provider_unterminated, set_eprobes(b, 1);
    memset(b->dp_eprobes[0].dtpd_provider, 'p', DTRACE_PROVNAMELEN))
PMUT(p_ep_target_unterminated, set_eprobes(b, 1);
    memset(b->dp_eprobes[0].dtpd_target, 't', DTRACE_TARGETNAMELEN))
PMUT(p_ep_mod_unterminated, set_eprobes(b, 1);
    memset(b->dp_eprobes[0].dtpd_mod, 'm', DTRACE_MODNAMELEN))
PMUT(p_ep_name, set_eprobes(b, 1); b->dp_eprobes[0].dtpd_name[0] = 0)
PMUT(p_ep_uncovered, set_eprobes(b, 1);
    strlcpy(b->dp_eprobes[0].dtpd_func, "beta", DTRACE_FUNCNAMELEN))
PMUT(p_ep_uncovered_mod, set_eprobes(b, 1);
    strlcpy(b->dp_eprobes[0].dtpd_mod, "zfs", DTRACE_MODNAMELEN))
PMUT(p_ep_uncovered_name, set_eprobes(b, 1);
    strlcpy(b->dp_eprobes[0].dtpd_name, "return", DTRACE_NAMELEN))
PMUT(p_ep_end, set_eprobes(b, 2);
    strlcpy(b->dp_eprobes[1].dtpd_provider, "dtrace", DTRACE_PROVNAMELEN);
    b->dp_eprobes[1].dtpd_mod[0] = b->dp_eprobes[1].dtpd_func[0] = 0;
    strlcpy(b->dp_eprobes[1].dtpd_name, "END", DTRACE_NAMELEN))
PMUT(p_ep_two, set_eprobes(b, 2))
PMUT(p_ecb_null_base, nth_stmt(a, 0)->dtsd_ecbdesc = NULL)
PMUT(p_aggdata_name_base, for (int i = 0; i < 4; i++)
    if (nth_stmt(a, i)->dtsd_aggdata != NULL) {
	    agg_noname = *(dt_ident_t *)nth_stmt(a, i)->dtsd_aggdata;
	    agg_noname.di_name = NULL;
	    nth_stmt(a, i)->dtsd_aggdata = &agg_noname; })
PMUT(p_aggdata_kind, for (int i = 0; i < 4; i++)
    if (nth_stmt(a, i)->dtsd_aggdata != NULL) {
	    agg_noname = *(dt_ident_t *)nth_stmt(a, i)->dtsd_aggdata;
	    agg_noname.di_kind = DT_IDENT_SCALAR;
	    nth_stmt(a, i)->dtsd_aggdata = &agg_noname;
	    nth_stmt(b, i)->dtsd_aggdata = &agg_noname; })
PMUT(p_last_null, nth_stmt(b, 1)->dtsd_action_last = NULL)
PMUT(p_first_null, nth_stmt(b, 1)->dtsd_action = NULL)
PMUT(p_last_elsewhere, nth_stmt(b, 2)->dtsd_action_last =
    nth_stmt(b, 0)->dtsd_action)
PMUT(p_last_elsewhere_odd, nth_stmt(b, 1)->dtsd_action_last =
    nth_stmt(b, 0)->dtsd_action)
PMUT(p_fmt_base_none, nth_stmt(a, 0)->dtsd_fmtdata = NULL)
PMUT(p_fmt_alias, nth_stmt(b, 2)->dtsd_fmtdata = nth_stmt(b, 0)->dtsd_fmtdata)
PMUT(p_fmt_base_alias, nth_stmt(b, 0)->dtsd_fmtdata =
    nth_stmt(a, 0)->dtsd_fmtdata)
PMUT(p_fmt_none, nth_stmt(b, 0)->dtsd_fmtdata = NULL;
    nth_stmt(b, 2)->dtsd_fmtdata = NULL)

static dtrace_hdl_t *pv_dtp;

static void
case_verify_program(void)
{
	static const struct { const char *name; pmut_f fn; int accept; }
	    muts[] = {
		{ "dofversion", p_dofversion, 0 }, { "rflags", p_rflags, 0 },
		{ "exec", p_exec, 0 }, { "stmt-desc-null", p_desc_null, 0 },
		{ "stmt-desc-null-base", p_desc_null_base, 0 },
		{ "ecbdesc-null", p_ecb_null, 0 },
		{ "probe-unterminated", p_name_unterminated, 0 },
		{ "probe-unterminated-base", p_name_unterminated_base, 0 },
		{ "probe-name", p_name, 0 }, { "probe-id", p_probe_id, 0 },
		{ "descattr", p_descattr, 0 }, { "stmtattr", p_stmtattr, 0 },
		{ "aggdata-null", p_aggdata_null, 0 },
		{ "aggdata-unnamed", p_aggdata_name, 0 },
		{ "aggdata-id", p_aggdata_id, 0 },
		{ "ecb-uarg", p_uarg, 0 },
		{ "predicate-missing", p_pred_null, 0 },
		{ "predicate-difo", p_pred_difo, 0 },
		{ "action-loop", p_span_loop, 0 },
		{ "action-loop-base", p_span_base_loop, 0 },
		{ "actions-missing", p_no_actions, 0 },
		{ "actions-added", p_base_no_actions, 0 },
		{ "action-difo-missing", p_act_difo_null, 0 },
		{ "action-kind", p_act_kind, 0 },
		{ "action-ntuple", p_act_ntuple, 0 },
		{ "action-arg", p_act_arg, 0 },
		{ "action-return", p_act_return, 0 },
		{ "action-uarg", p_act_uarg, 0 },
		{ "action-uarg-base", p_act_uarg_base, 0 },
		{ "action-difo", p_act_difo, 0 },
		{ "action-span-shorter", p_span_shorter, 0 },
		{ "statement-added", p_extra_stmt, 0 },
		{ "statement-missing", p_extra_stmt_base, 0 },
		{ "eprobes-null-list", p_ep_count, 0 },
		{ "eprobes-list-without-count", p_ep_null, 0 },
		{ "eprobes-too-many", p_ep_huge, 0 },
		{ "eprobes-order", p_ep_order, 0 },
		{ "eprobes-id-limit", p_ep_limit, 0 },
		{ "eprobes-vmid", p_ep_vmid, 0 },
		{ "eprobes-unterminated", p_ep_unterminated, 0 },
		{ "eprobes-no-provider", p_ep_provider, 0 },
		{ "eprobes-provider-unterminated", p_ep_provider_unterminated, 0 },
		{ "eprobes-target-unterminated", p_ep_target_unterminated, 0 },
		{ "eprobes-mod-unterminated", p_ep_mod_unterminated, 0 },
		{ "eprobes-no-name", p_ep_name, 0 },
		{ "eprobes-uncovered-func", p_ep_uncovered, 0 },
		{ "eprobes-uncovered-mod", p_ep_uncovered_mod, 0 },
		{ "eprobes-uncovered-name", p_ep_uncovered_name, 0 },
		{ "eprobes-second-selector", p_ep_end, 1 },
		{ "eprobes-covered", p_ep_two, 1 },
		{ "ecbdesc-null-base", p_ecb_null_base, 0 },
		{ "aggdata-unnamed-base", p_aggdata_name_base, 0 },
		{ "aggdata-not-aggregation", p_aggdata_kind, 0 },
		{ "action-last-null", p_last_null, 0 },
		{ "action-first-null", p_first_null, 0 },
		{ "action-last-unreachable", p_last_elsewhere, 0 },
		{ "action-last-unreachable-2", p_last_elsewhere_odd, 0 },
		{ "formats-base-none", p_fmt_base_none, 1 },
		{ "formats-aliased", p_fmt_alias, 1 },
		{ "formats-alias-base", p_fmt_base_alias, 1 },
		{ "formats-absent", p_fmt_none, 1 },
	};
	int bad = 0;

	for (size_t i = 0; i < sizeof (muts) / sizeof (muts[0]); i++) {
		dtrace_prog_t *a, *b;
		uint8_t da[32], db[32];
		void *ctx;
		int v;

		pv_dtp = open_nodev();
		a = compile(pv_dtp, VSRC, 0);
		b = compile(pv_dtp, VSRC, 0);
		if (a == NULL || b == NULL ||
		    dtrace_program_compiled_digest(pv_dtp, a, da) != 0 ||
		    dtrace_program_compiled_digest(pv_dtp, b, db) != 0 ||
		    memcmp(da, db, 32) != 0) {
			bad++;
			continue;
		}
		/* Mutated programs are not handed back to dtrace_close(). */
		dt_list_delete(&pv_dtp->dt_programs, a);
		dt_list_delete(&pv_dtp->dt_programs, b);
		muts[i].fn(a, b);
		ctx = dt_verictx_init(pv_dtp);
		v = pv_quiet(ctx, a, b);
		/* A rejected program leaves the context as it was. */
		if ((v == 0) != muts[i].accept ||
		    (v != 0 && dt_verictx_mark(ctx) != 0)) {
			printf("verify-program %s: got %d mark %zu\n",
			    muts[i].name, v, dt_verictx_mark(ctx));
			bad++;
		}
		/* Accepted guests carry copies of the host's formats. */
		if (v == 0 && muts[i].fn != p_fmt_none &&
		    muts[i].fn != p_fmt_base_none &&
		    (nth_stmt(b, 0)->dtsd_fmtdata == NULL ||
		    nth_stmt(b, 0)->dtsd_fmtdata ==
		    nth_stmt(a, 0)->dtsd_fmtdata)) {
			printf("verify-program %s: formats not copied\n",
			    muts[i].name);
			bad++;
		}
		dt_verictx_teardown(ctx);
		dtrace_close(pv_dtp);
	}
	CHECK("verify-program-fields", bad == 0);

	/* A program verifies against itself; nothing is replaced. */
	{
		dtrace_prog_t *a;
		void *ctx;
		void *fmt;

		pv_dtp = open_nodev();
		a = compile(pv_dtp, VSRC, 0);
		fmt = nth_stmt(a, 0)->dtsd_fmtdata;
		ctx = dt_verictx_init(pv_dtp);
		CHECK("verify-program-self", dt_prog_verify(ctx, a, a) == 0 &&
		    nth_stmt(a, 0)->dtsd_fmtdata == fmt &&
		    dt_verictx_mark(ctx) > 0);
		CHECK("verify-program-null-args", pv_quiet(NULL, a, a) != 0 &&
		    pv_quiet(ctx, NULL, a) != 0 && pv_quiet(ctx, a, NULL) != 0);
		{
			dtrace_hdl_t *saved = *(dtrace_hdl_t **)ctx;

			*(dtrace_hdl_t **)ctx = NULL;
			CHECK("verify-program-null-handle",
			    pv_quiet(ctx, a, a) != 0);
			*(dtrace_hdl_t **)ctx = saved;
		}
		dt_verictx_teardown(ctx);
		dtrace_close(pv_dtp);
	}

	/* The accepted-DIFO vector grows past its initial 256 entries. */
	{
		dtrace_prog_t *a;
		void *ctx;
		char *src = calloc(1, 64 * 1024), *p = src;

		for (int i = 0; i < 300; i++)
			p += sprintf(p, "BEGIN /arg%d/ { trace(%d); } ", i % 10,
			    i);
		pv_dtp = open_nodev();
		a = compile(pv_dtp, src, 0);
		ctx = dt_verictx_init(pv_dtp);
		CHECK("verify-program-many-difos", a != NULL &&
		    dt_prog_verify(ctx, a, a) == 0 &&
		    dt_verictx_mark(ctx) == 600);
		dt_verictx_rewind(ctx, 10);
		CHECK("verictx-rewind", dt_verictx_mark(ctx) == 10);
		dt_verictx_teardown(ctx);
		dtrace_close(pv_dtp);
		free(src);
	}
}

static dtrace_prog_t *
vprog_src_simple(dtrace_hdl_t *dtp)
{
	dtrace_prog_t *pgp = dt_program_create(dtp);
	int kinds[] = { DTRACEACT_STACK };

	strlcpy(pgp->dp_vmname, "guest", VM_MAX_NAMELEN);
	add_stmt(dtp, pgp, "guest", "test", "a", 1, kinds, NULL, NULL);
	return (pgp);
}

static int
digest(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, uint8_t out[32])
{
	return (dtrace_program_compiled_digest(dtp, pgp, out));
}

/* ------------------------------------------------------------------ */
/* dtrace_vprog_from: guest forwarding programs.                       */

static void
case_vprog(void)
{
	dtrace_hdl_t *dtp = open_nodev();
	dtrace_prog_t *src, *dst;
	uint8_t before[32], after[32];
	int kinds[] = { DTRACEACT_DIFEXPR };
	dif_instr_t a6[] = { DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ARG6, 1),
	    DIF_INSTR_RET(1) };
	dif_instr_t a8[] = { DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ARG8, 1),
	    DIF_INSTR_RET(1) };
	static const char *names[] = { "a", "b", "a", "a" };
	dtrace_difo_t *dp;

	/* Only PGP_KIND_HYPERCALLS is defined. */
	src = vprog_src_simple(dtp);
	CHECK("vprog-unknown-kind", dtrace_vprog_from(dtp, src,
	    PGP_KIND_HYPERCALLS + 1) == NULL);

	/*
	 * An ERROR clause is retargeted to the program's VM; without a VM
	 * name, or with one longer than a probe target, the transform fails
	 * and leaves the source program unchanged.
	 */
	{
		int k[] = { DTRACEACT_STACK };

		add_stmt(dtp, src, "", "dtrace", "ERROR", 1, k, NULL, NULL);
	}
	digest(dtp, src, before);
	free(src->dp_vmname);
	src->dp_vmname = NULL;
	dst = dtrace_vprog_from(dtp, src, PGP_KIND_HYPERCALLS);
	CHECK("vprog-error-no-vm", dst == NULL && dtrace_errno(dtp) == EINVAL &&
	    digest(dtp, src, after) == 0 && memcmp(before, after, 32) == 0);
	src->dp_vmname = calloc(1, VM_MAX_NAMELEN);
	memset(src->dp_vmname, 'v', VM_MAX_NAMELEN - 1);
	dst = dtrace_vprog_from(dtp, src, PGP_KIND_HYPERCALLS);
	CHECK("vprog-error-long-vm", dst == NULL &&
	    dtrace_errno(dtp) == ENAMETOOLONG &&
	    digest(dtp, src, after) == 0 && memcmp(before, after, 32) == 0);
	strlcpy(src->dp_vmname, "guest", VM_MAX_NAMELEN);
	dst = dtrace_vprog_from(dtp, src, PGP_KIND_HYPERCALLS);
	CHECK("vprog-error-retargeted", dst != NULL &&
	    strcmp(nth_stmt(dst, 1)->dtsd_ecbdesc->dted_probe.dtpd_target,
	    "guest") == 0 && memcmp(dst->dp_srcident, src->dp_ident,
	    DT_PROG_IDENTLEN) == 0);
	if (dst != NULL)
		dt_program_destroy(dtp, dst);
	dt_program_destroy(dtp, src);

	/*
	 * Every clause for a guest probe is forwarded by one statement (one
	 * hypercall per firing: the hypercall names only the probe and the
	 * host runs each of its clauses once for it), in the order the
	 * probes first appear, and its DIFO loads the high arguments any of
	 * those clauses uses (arg8 of the second a clause included).
	 */
	src = dt_program_create(dtp);
	strlcpy(src->dp_vmname, "guest", VM_MAX_NAMELEN);
	for (int i = 0; i < 4; i++) {
		dp = make_difo(i == 2 ? a8 : a6, 2);
		add_stmt(dtp, src, "guest", "test", names[i], 1, kinds, &dp,
		    NULL);
	}
	dst = dtrace_vprog_from(dtp, src, PGP_KIND_HYPERCALLS);
	{
		const char *order[4];
		int n = 0, ok = dst != NULL;
		dtrace_difo_t *f;

		for (dt_stmt_t *stp = ok ? dt_list_next(&dst->dp_stmts) : NULL;
		    stp != NULL && n < 4; stp = dt_list_next(stp))
			order[n++] = stp->ds_desc->dtsd_ecbdesc->dted_probe.
			    dtpd_name;
		ok = ok && n == 2 && strcmp(order[0], "a") == 0 &&
		    strcmp(order[1], "b") == 0;
		/* a loads arg6 and arg8, then hypercalls and returns. */
		f = ok ? nth_stmt(dst, 0)->dtsd_action_last->dtad_difo : NULL;
		ok = ok && f->dtdo_len == 4 && f->dtdo_buf[0] ==
		    DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ARG6, 1) &&
		    f->dtdo_buf[1] == DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ARG8, 1);
		f = ok ? nth_stmt(dst, 1)->dtsd_action_last->dtad_difo : NULL;
		ok = ok && f->dtdo_len == 3 && f->dtdo_buf[0] ==
		    DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ARG6, 1);
		CHECK("vprog-grouping", ok);
	}
	if (dst != NULL)
		dt_program_destroy(dtp, dst);
	dt_program_destroy(dtp, src);

	/*
	 * stack() frame counts: the stackframes option supplies a default;
	 * zero or more than HYPERTRACE_STACK_MAX_FRAMES is refused.  The
	 * hypercall captures the largest request of the clause.
	 */
	{
		int k2[] = { DTRACEACT_STACK, DTRACEACT_STACK };
		uint64_t frames[] = { 9, 3 };
		dtrace_difo_t *f;

		src = dt_program_create(dtp);
		strlcpy(src->dp_vmname, "guest", VM_MAX_NAMELEN);
		add_stmt(dtp, src, "guest", "test", "s", 2, k2, NULL, frames);
		frames[0] = 0;
		add_stmt(dtp, src, "guest", "test", "t", 2, k2, NULL, frames);
		dtp->dt_options[DTRACEOPT_STACKFRAMES] = 5;
		dst = dtrace_vprog_from(dtp, src, PGP_KIND_HYPERCALLS);
		f = dst != NULL ? nth_stmt(dst, 0)->dtsd_action_last->
		    dtad_difo : NULL;
		CHECK("vprog-stack-frames", f != NULL &&
		    DIF_INSTR_R1(f->dtdo_buf[f->dtdo_len - 2]) == 9 &&
		    DIF_INSTR_R1(nth_stmt(dst, 1)->dtsd_action_last->dtad_difo->
		    dtdo_buf[0]) == 5 &&
		    nth_stmt(src, 1)->dtsd_action->dtad_arg == 5);
		if (dst != NULL)
			dt_program_destroy(dtp, dst);
		nth_stmt(src, 1)->dtsd_action->dtad_arg = 0;
		dtp->dt_options[DTRACEOPT_STACKFRAMES] = 0;
		CHECK("vprog-stack-zero", dtrace_vprog_from(dtp, src,
		    PGP_KIND_HYPERCALLS) == NULL && dtrace_errno(dtp) == EINVAL);
		dtp->dt_options[DTRACEOPT_STACKFRAMES] = DTRACEOPT_UNSET;
		dt_program_destroy(dtp, src);
	}

	/*
	 * DIFO shapes: a DIFO claiming instructions without a buffer is
	 * refused (EINVAL, source unchanged); an empty predicate, a vartab
	 * length without a table, non-ERROR dtrace probes and register-array
	 * loads are forwarded without extra argument loads.
	 */
	{
		dif_instr_t ldgaa[] = { DIF_INSTR_LDV(DIF_OP_LDGAA,
		    DIF_VAR_REGS, 1), DIF_INSTR_RET(1) };
		static const int want_ok[] = { 0, 1, 1, 1, 1, 0 };
		int ok = 1;

		for (int c = 0; c < 6; c++) {
			dtrace_difo_t *act, *pred = NULL;

			src = dt_program_create(dtp);
			strlcpy(src->dp_vmname, "guest", VM_MAX_NAMELEN);
			act = make_difo(c == 4 ? ldgaa : a6, 2);
			if (c == 0 || c == 1) {
				pred = make_difo(a8, 2);
				free(pred->dtdo_buf);
				pred->dtdo_buf = NULL;
				if (c == 1)
					pred->dtdo_len = 0;
			} else if (c == 2) {
				act->dtdo_varlen = 1;
			} else if (c == 5) {
				free(act->dtdo_buf);
				act->dtdo_buf = NULL;
			}
			add_stmt(dtp, src, "guest", c == 3 ? "dtrace" : "test",
			    c == 3 ? "BEGIN" : "m", 1, kinds, &act, NULL);
			nth_stmt(src, 0)->dtsd_ecbdesc->dted_pred.dtpdd_difo =
			    pred;
			digest(dtp, src, before);
			dst = dtrace_vprog_from(dtp, src, PGP_KIND_HYPERCALLS);
			if (want_ok[c]) {
				dtrace_difo_t *f = dst == NULL ? NULL :
				    nth_stmt(dst, 0)->dtsd_action_last->
				    dtad_difo;

				/* arg6 actions add one load; regs[] none. */
				ok &= f != NULL && f->dtdo_len ==
				    (c == 4 ? 2u : 3u);
				if (dst != NULL)
					dt_program_destroy(dtp, dst);
			} else {
				ok &= dst == NULL && dtrace_errno(dtp) == EINVAL;
			}
			if (c == 2)
				act->dtdo_varlen = 0;
			if (c == 0 || c == 5)
				(c == 0 ? pred : act)->dtdo_len = 0;
			dt_program_destroy(dtp, src);
			if (!ok) {
				printf("vprog-malformed case %d\n", c);
				ok = 0;
				break;
			}
		}
		CHECK("vprog-malformed-difo", ok);
	}

	/* An unterminated guest target name is refused. */
	src = vprog_src_simple(dtp);
	memset(nth_stmt(src, 0)->dtsd_ecbdesc->dted_probe.dtpd_target, 'g',
	    DTRACE_TARGETNAMELEN);
	CHECK("vprog-target-unterminated", dtrace_vprog_from(dtp, src,
	    PGP_KIND_HYPERCALLS) == NULL && dtrace_errno(dtp) == EINVAL);
	dt_program_destroy(dtp, src);

	/* dt_program_destroy() accepts NULL and a program without a VM name. */
	dt_program_destroy(dtp, NULL);
	src = dt_program_create(dtp);
	free(src->dp_vmname);
	src->dp_vmname = NULL;
	dt_program_destroy(dtp, src);
	dtrace_close(dtp);
}

#ifdef PP_FAULT
/* ------------------------------------------------------------------ */
/* Allocation-failure sweeps.  Each iteration runs in a child that     */
/* fails the Nth allocation inside the call under test; the call must  */
/* fail cleanly (documented error, inputs unchanged) or succeed.       */

typedef int (*scenario_f)(int n, char *why, size_t len);

static int
sc_program_create(int n, char *why, size_t len)
{
	dtrace_hdl_t *dtp = open_nodev();
	dtrace_prog_t *pgp;

	arm(n);
	pgp = dt_program_create(dtp);
	disarm();
	if (pgp == NULL && dtrace_errno(dtp) != EDT_NOMEM) {
		snprintf(why, len, "errno %d", dtrace_errno(dtp));
		return (-1);
	}
	if (pgp != NULL)
		dt_program_destroy(dtp, pgp);
	dtrace_close(dtp);
	return (0);
}

static int
sc_stmt_api(int n, char *why, size_t len)
{
	dtrace_hdl_t *dtp = open_nodev();
	dtrace_prog_t *pgp = dt_program_create(dtp);
	dtrace_probedesc_t pd = { 0 };
	dtrace_ecbdesc_t *edp;
	dtrace_stmtdesc_t *sdp = NULL;
	int rc = 0;

	strlcpy(pd.dtpd_name, "BEGIN", sizeof (pd.dtpd_name));
	arm(n);
	edp = dt_ecbdesc_create(dtp, &pd);
	if (edp != NULL) {
		sdp = dtrace_stmt_create(dtp, edp);
		if (sdp != NULL && (dtrace_stmt_action(dtp, sdp) == NULL ||
		    dtrace_stmt_add(dtp, pgp, sdp) != 0)) {
			disarm();
			dtrace_stmt_destroy(dtp, sdp);
			sdp = NULL;
		}
	}
	disarm();
	if (edp == NULL && dtrace_errno(dtp) != EDT_NOMEM) {
		snprintf(why, len, "ecbdesc errno %d", dtrace_errno(dtp));
		rc = -1;
	}
	if (edp != NULL)
		dt_ecbdesc_release(dtp, edp);
	dt_program_destroy(dtp, pgp);
	dtrace_close(dtp);
	return (rc);
}

static int
sc_exec(int n, char *why, size_t len)
{
	dtrace_hdl_t *dtp;
	dtrace_prog_t *pgp;
	int rc;

	memset(&V, 0, sizeof (V));
	V.n_desc = 2;
	dtp = open_vec();
	pgp = compile(dtp, "BEGIN /timestamp/ { x = 1; printf(\"%d\", x); }",
	    0);
	arm(n);
	rc = dtrace_program_exec(dtp, pgp, NULL);
	if (rc == 0)
		rc = dtrace_augment_tracing(dtp, pgp);
	disarm();
	if (rc != 0 && dtrace_errno(dtp) != EDT_NOMEM) {
		snprintf(why, len, "errno %d: %s", dtrace_errno(dtp),
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		return (-1);
	}
	dtrace_close(dtp);
	return (0);
}

static int
sc_dof(int n, char *why, size_t len)
{
	dtrace_hdl_t *dtp = open_nodev();
	dtrace_prog_t *pgp;
	dof_hdr_t *dof;
	int rc = 0;

	(void) dtrace_setopt(dtp, "late", "dynamic");
	pgp = compile(dtp, "struct xx { int a; int b; }; "
	    "translator struct xx < int x > { a = x + 1; b = x * 2; }; "
	    "provider my { probe ent__ry(int x) : (struct xx x); }; "
	    "BEGIN /timestamp/ { printf(\"%d %s\", 1, \"s\"); }", 0);
	{
		dt_provider_t *pvp = dt_provider_lookup(dtp, "my");

		(void) dt_probe_define(pvp, dt_probe_lookup(pvp, "ent-ry"),
		    "main", "main", 0x10, 0);
		(void) dt_probe_define(pvp, dt_probe_lookup(pvp, "ent-ry"),
		    "main", "main", 0x14, 1);
	}
	arm(n);
	dof = dtrace_dof_create(dtp, pgp, DTRACE_D_PROBES);
	disarm();
	if (dof == NULL && dtrace_errno(dtp) != EDT_NOMEM) {
		snprintf(why, len, "errno %d", dtrace_errno(dtp));
		rc = -1;
	}
	if (dof != NULL)
		dtrace_dof_destroy(dtp, dof);
	arm(n);
	dof = dtrace_getopt_dof(dtp);
	disarm();
	if (dof != NULL)
		dtrace_dof_destroy(dtp, dof);
	dtrace_close(dtp);
	return (rc);
}

static int
sc_hashmap(int n, char *why, size_t len)
{
	dt_hashmap_t *hm;
	static uint32_t k = 7;
	int rc = 0;

	(void) why;
	(void) len;
	arm(n);
	hm = dt_hashmap_create(8);
	if (hm != NULL) {
		rc = dt_hashmap_insert(hm, &k, 4, &k, DTH_MANAGED);
		disarm();
		if (rc == ENOMEM && hm->dthm_nitems == 0 &&
		    dt_hashmap_lookup(hm, &k, 4) == NULL)
			rc = 0;
		dt_hashmap_free(hm, 1);
	}
	disarm();
	return (rc);
}

/* A guest-forwarding source program with every transform feature. */
static dtrace_prog_t *
vprog_source(dtrace_hdl_t *dtp)
{
	dtrace_prog_t *pgp = dt_program_create(dtp);
	dif_instr_t args[] = { DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ARG6, 1),
	    DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_VTIMESTAMP, 2),
	    DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_WALLTIMESTAMP, 3),
	    DIF_INSTR_RET(1) };
	static const char *names[] = { "a", "b", "a", "ERROR", "a" };

	strlcpy(pgp->dp_vmname, "guest", VM_MAX_NAMELEN);
	for (int i = 0; i < 5; i++) {
		int kinds[] = { DTRACEACT_DIFEXPR, DTRACEACT_IMMSTACK,
		    DTRACEACT_STACK };
		dtrace_difo_t *difos[3];
		uint64_t a[] = { 0, 4, 0 };
		dtrace_difo_t *dp = make_difo(args, 4);

		dp->dtdo_vartab = calloc(2, sizeof (dtrace_difv_t));
		dp->dtdo_varlen = 2;
		dp->dtdo_vartab[0].dtdv_id = DIF_VAR_VTIMESTAMP;
		dp->dtdo_vartab[1].dtdv_id = DIF_VAR_WALLTIMESTAMP;
		difos[0] = dp;
		difos[1] = difos[2] = NULL;
		add_stmt(dtp, pgp, i == 3 ? "host" : "guest", i == 3 ?
		    "dtrace" : "test", names[i], 3, kinds, difos, a);
	}
	return (pgp);
}

static int
sc_vprog(int n, char *why, size_t len)
{
	dtrace_hdl_t *dtp = open_nodev();
	dtrace_prog_t *src = vprog_source(dtp), *dst;
	uint8_t before[32], after[32];

	if (digest(dtp, src, before) != 0) {
		snprintf(why, len, "digest");
		return (-1);
	}
	arm(n);
	dst = dtrace_vprog_from(dtp, src, PGP_KIND_HYPERCALLS);
	disarm();
	if (dst == NULL) {
		/* A failed transform leaves the source program unchanged. */
		if (digest(dtp, src, after) != 0 ||
		    memcmp(before, after, 32) != 0) {
			snprintf(why, len, "source changed by failed transform");
			return (-1);
		}
	} else {
		dt_program_destroy(dtp, dst);
	}
	dt_program_destroy(dtp, src);
	dtrace_close(dtp);
	return (0);
}

static int
sc_verify(int n, char *why, size_t len)
{
	dtrace_hdl_t *dtp = open_nodev();
	dtrace_prog_t *a, *b;
	void *ctx;
	int v;
	static const char *src = "BEGIN { printf(\"%d\\n\", 1); } "
	    "END { printf(\"%s %d\\n\", \"x\", 2); trace(3); }";

	a = compile(dtp, src, 0);
	b = compile(dtp, src, 0);
	b->dp_ident[0] ^= 1;
	arm(n);
	ctx = dt_verictx_init(dtp);
	v = ctx == NULL ? -1 : dt_prog_verify(ctx, a, b);
	disarm();
	if (ctx != NULL && v != 0 && !fault_hit) {
		snprintf(why, len, "identical programs rejected");
		return (-1);
	}
	dt_verictx_teardown(ctx);
	dtrace_close(dtp);
	return (0);
}

/* Growing the accepted-DIFO vector on a predicate or on an action. */
static int
sc_verify_growth(int n, char *why, size_t len, int action_first)
{
	dtrace_hdl_t *dtp = open_nodev();
	char *src = calloc(1, 64 * 1024), *p = src;
	dtrace_prog_t *a;
	void *ctx;
	int v;

	if (action_first)
		p += sprintf(p, "BEGIN { trace(0); } ");
	for (int i = 0; i < 130; i++)
		p += sprintf(p, "BEGIN /arg%d/ { trace(%d); } ", i % 10, i);
	a = compile(dtp, src, 0);
	ctx = dt_verictx_init(dtp);
	arm(n);
	v = dt_prog_verify(ctx, a, a);
	disarm();
	if (v != 0 && dt_verictx_mark(ctx) != 0) {
		snprintf(why, len, "context kept DIFOs of a rejected program");
		return (-1);
	}
	dt_verictx_teardown(ctx);
	dtrace_close(dtp);
	free(src);
	return (0);
}

static int
sc_verify_growth_pred(int n, char *why, size_t len)
{
	return (sc_verify_growth(n, why, len, 0));
}

static int
sc_verify_growth_action(int n, char *why, size_t len)
{
	return (sc_verify_growth(n, why, len, 1));
}

/* Format copies where an earlier statement has no format. */
static int
sc_verify_formats(int n, char *why, size_t len)
{
	dtrace_hdl_t *dtp = open_nodev();
	static const char *src = "BEGIN { trace(1); printf(\"%d\", 1); "
	    "printf(\"%s\", \"x\"); }";
	dtrace_prog_t *a = compile(dtp, src, 0), *b = compile(dtp, src, 0);
	void *fmt = nth_stmt(b, 1)->dtsd_fmtdata;
	void *ctx = dt_verictx_init(dtp);
	int v;

	arm(n);
	v = dt_prog_verify(ctx, a, b);
	disarm();
	/* A failed verification leaves the guest's formats in place. */
	if (v != 0 && nth_stmt(b, 1)->dtsd_fmtdata != fmt) {
		snprintf(why, len, "formats replaced by a failed verify");
		return (-1);
	}
	dt_verictx_teardown(ctx);
	dtrace_close(dtp);
	return (0);
}

/* Constant-table relocation bookkeeping (dt_prog_verify_inttab_...). */
static int
sc_verify_relocated(int n, char *why, size_t len)
{
	dtrace_hdl_t *dtp = open_nodev();
	void *ctx = dt_verictx_init(dtp);
	dtrace_difo_t *b = difo_base(), *g = difo_guest(b);
	char target[] = "test:::fault";
	int v;

	(void) why;
	(void) len;
	arm(n);
	v = vd_quiet(ctx, b, g, target);
	disarm();
	(void) v;
	difo_release(b);
	difo_release(g);
	dt_verictx_teardown(ctx);
	dtrace_close(dtp);
	return (0);
}

static void
sweep(const char *name, scenario_f fn, int max)
{
	int n, status, bad = 0, exits = 0, completed = 0;

	for (n = 0; n < max; n++) {
		int fds[2];
		pid_t pid;
		char buf[512] = "";
		ssize_t r;

		if (pipe(fds) != 0)
			abort();
		fflush(stdout);
		if ((pid = fork()) == 0) {
			char why[256] = "";
			int rc;

			close(fds[0]);
			fault_hit = 0;
			rc = fn(n, why, sizeof (why));
			dprintf(fds[1], "%d %d %s", rc, fault_hit, why);
			exit(0);	/* exit(), so profiles are written */
		}
		close(fds[1]);
		r = read(fds[0], buf, sizeof (buf) - 1);
		buf[r > 0 ? r : 0] = '\0';
		close(fds[0]);
		waitpid(pid, &status, 0);
		if (!WIFEXITED(status)) {
			printf("FAULT %s %d: signal %d\n", name, n,
			    WTERMSIG(status));
			bad++;
		} else if (WEXITSTATUS(status) != 0) {
			/*
			 * The library must not exit the consumer on ENOMEM
			 * (dof_construct_kvartab() used to call errx()).
			 */
			printf("EXIT %s %d: status %d\n", name, n,
			    WEXITSTATUS(status));
			exits++;
		} else if (atoi(buf) != 0) {
			printf("FAULT %s %d: %s\n", name, n, buf);
			bad++;
		} else if (strchr(buf, ' ') != NULL && atoi(strchr(buf, ' ') +
		    1) == 0) {
			completed = 1;	/* no allocation left to fail */
			break;
		}
	}
	result(name, bad == 0 && exits == 0 && completed,
	    "%d bad, %d exits, %d iterations",
	    bad, exits, n);
	printf("SWEEP %s iterations %d exits %d\n", name, n, exits);
}

static void
case_faults(void)
{
	if (getenv("PP_DEBUG")) {
		char why[256] = "";
		int rc = sc_verify_growth_pred(0, why, sizeof (why));

		printf("debug rc %d hit %d count %d why %s\n", rc, fault_hit,
		    alloc_count, why);
	}
	sweep("fault-program-create", sc_program_create, 50);
	sweep("fault-stmt-api", sc_stmt_api, 50);
	sweep("fault-hashmap", sc_hashmap, 50);
	sweep("fault-exec", sc_exec, 400);
	sweep("fault-dof", sc_dof, 400);
	sweep("fault-vprog", sc_vprog, 400);
	sweep("fault-verify", sc_verify, 400);
	sweep("fault-verify-growth-pred", sc_verify_growth_pred, 400);
	sweep("fault-verify-growth-action", sc_verify_growth_action, 400);
	sweep("fault-verify-formats", sc_verify_formats, 400);
	sweep("fault-verify-relocated", sc_verify_relocated, 400);
}
#endif

int
main(int argc, char **argv)
{
	(void) argc;
	(void) argv;
#ifndef PP_FAULT
	case_hashmap();
	case_analysis();
	case_modref_kinds();
	case_dof();
	case_exec();
	case_header();
	case_provider_dof();
	case_verify_difo();
	case_verify_program();
	case_vprog();
#endif
#ifdef PP_FAULT
	case_faults();
#endif
	printf("%d passed, %d failed\n", passes, failures);
	return (failures != 0);
}
