/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Allocation-failure injection for the printf/print paths of libdtrace.
 *
 * This program (built without ASan, which owns malloc) interposes malloc(),
 * calloc() and strdup().  A scenario is run in a forked child with the Nth
 * matching allocation failing, for N = 1, 2, ... until a run makes fewer
 * than N matching allocations.  An allocation matches either by its caller
 * (the exported function that called the allocator, from dladdr(3)) or by
 * falling inside the scenario's measured call.  The oracle for every
 * injected failure: the call returns its documented failure (NULL or -1
 * with EDT_NOMEM; dtrace_print() and dtrace_format_print() may instead
 * complete without the failed piece) and the child neither crashes nor
 * trips an assertion.  Each child exits with exit() so its coverage is kept.
 *
 * usage: printf-faults scenario   (prints one result line per N)
 */

#include <dt_impl.h>
#include <dt_printf.h>
#include <dt_module.h>

#include <sys/wait.h>

#include <dlfcn.h>
#include <libxo/xo.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void *__malloc(size_t);
void *__calloc(size_t, size_t);
void *__realloc(void *, size_t);

static const char *fi_caller;	/* match by exported caller name */
static int fi_window;		/* match everything while set */
static int fi_nth, fi_seen, fi_injected, fi_busy;

static int
fi_fail(void *ret)
{
	Dl_info info;
	int match;

	if (fi_nth == 0 || fi_busy)
		return (0);
	fi_busy = 1;
	match = fi_window || (fi_caller != NULL && dladdr(ret, &info) != 0 &&
	    info.dli_sname != NULL && strcmp(info.dli_sname, fi_caller) == 0);
	fi_busy = 0;
	if (!match || ++fi_seen != fi_nth)
		return (0);
	fi_injected = 1;
	errno = ENOMEM;
	return (1);
}

void *
malloc(size_t n)
{
	if (fi_fail(__builtin_return_address(0)))
		return (NULL);
	return (__malloc(n));
}

void *
calloc(size_t n, size_t m)
{
	if (fi_fail(__builtin_return_address(0)))
		return (NULL);
	return (__calloc(n, m));
}

void *
realloc(void *p, size_t n)
{
	if (fi_fail(__builtin_return_address(0)))
		return (NULL);
	return (__realloc(p, n));
}

char *
strdup(const char *s)
{
	size_t n = strlen(s) + 1;
	char *p;

	if (fi_fail(__builtin_return_address(0)))
		return (NULL);
	if ((p = __malloc(n)) != NULL)
		memcpy(p, s, n);
	return (p);
}

static dtrace_hdl_t *
open_nodev(void)
{
	int err;
	dtrace_hdl_t *h = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV |
	    DTRACE_O_NOSYS, &err);

	if (h == NULL) {
		fprintf(stderr, "open: %s\n", dtrace_errmsg(NULL, err));
		exit(3);
	}
	(void) dtrace_setopt(h, "strsize", "64");
	return (h);
}

/* Each returns 0 when the outcome is acceptable for fi_injected. */
static int
sc_pfdict(void)
{
	int err;
	dtrace_hdl_t *h;

	fi_caller = "dt_pfdict_create";
	h = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV | DTRACE_O_NOSYS, &err);
	fi_caller = NULL;
	if (fi_injected)
		return (h == NULL && err == EDT_NOMEM ? 0 : 1);
	if (h == NULL)
		return (1);
	dtrace_close(h);
	return (0);
}

static int
sc_printf_create(void)
{
	dtrace_hdl_t *h = open_nodev();
	void *pfv;

	fi_caller = "dt_printf_create";
	pfv = dtrace_printf_create(h, "a%db%5.2sc%%d");
	fi_caller = NULL;
	if (fi_injected)
		return (pfv == NULL && dtrace_errno(h) == EDT_NOMEM ? 0 : 1);
	if (pfv == NULL)
		return (1);
	dt_printf_destroy(pfv);
	dtrace_close(h);
	return (0);
}

static int
sc_printf_dup(void)
{
	dtrace_hdl_t *h = open_nodev();
	void *pfv = dtrace_printf_create(h, "a%db%sc"), *copy;

	fi_caller = "dt_printf_dup";
	copy = dt_printf_dup(pfv);
	fi_caller = NULL;
	if (fi_injected)
		return (copy == NULL && dtrace_errno(h) == EDT_NOMEM ? 0 : 1);
	if (copy == NULL)
		return (1);
	dt_printf_destroy(copy);
	dt_printf_destroy(pfv);
	dtrace_close(h);
	return (0);
}

static int
sc_record(const char *caller, const char *fmt, int sprintf_call)
{
	dtrace_hdl_t *h = open_nodev();
	void *pfv = dtrace_printf_create(h, fmt);
	dtrace_recdesc_t rec;
	char data[8] = "ab\tc";
	FILE *null = fopen("/dev/null", "w");
	int rc;

	memset(&rec, 0, sizeof (rec));
	rec.dtrd_action = DTRACEACT_DIFEXPR;
	rec.dtrd_size = 4;
	rec.dtrd_alignment = 1;
	fi_caller = caller;
	rc = sprintf_call ? dtrace_sprintf(h, NULL, pfv, &rec, 1, data, 8) :
	    dtrace_fprintf(h, null, pfv, NULL, &rec, 1, data, 8);
	fi_caller = NULL;
	fclose(null);
	if (fi_injected)
		return (rc == -1 && dtrace_errno(h) == EDT_NOMEM ? 0 : 1);
	if (rc != 1)
		return (1);
	dt_printf_destroy(pfv);
	dtrace_close(h);
	return (0);
}

static int
sc_sprintf(void)
{
	return (sc_record("dtrace_sprintf", "%s", 1));
}

static int
sc_escape(void)
{
	return (sc_record("strchr2esc", "%S", 0));
}

/* dtrace_print()/dtrace_format_print() of an int and a char[4] string. */
static int
sc_print(int structured)
{
	dtrace_hdl_t *h = open_nodev();
	ctf_file_t *fp = h->dt_cdefs->dm_ctfp;
	ctf_arinfo_t ar;
	ctf_id_t arr;
	char tn[64], data[8] = "abc";
	FILE *null = fopen("/dev/null", "w");
	int rc;

	ar.ctr_contents = ctf_lookup_by_name(fp, "char");
	ar.ctr_index = ctf_lookup_by_name(fp, "int");
	ar.ctr_nelems = 4;
	arr = ctf_add_array(fp, CTF_ADD_ROOT, &ar);
	if (arr == CTF_ERR || ctf_update(fp) == CTF_ERR)
		exit(3);
	snprintf(tn, sizeof (tn), "C`%ld", arr);
	if (structured) {
		xo_set_file(null);
		xo_set_style(NULL, XO_STYLE_JSON);
		(void) dtrace_oformat_configure(h);
	}
	fi_window = 1;
	rc = structured ? dtrace_format_print(h, null, tn, data, 4) :
	    dtrace_print(h, null, tn, data, 4);
	fi_window = 0;
	fclose(null);
	if (fi_injected)
		return (rc == 4 || rc == 0 ||
		    (rc == -1 && dtrace_errno(h) == EDT_NOMEM) ? 0 : 1);
	return (rc == 4 ? 0 : 1);
}

/*
 * printa() of one aggregation variable whose sorted walk cannot allocate:
 * the walk's own failure (no callback error) is returned.
 */
static int
sc_fprinta(void)
{
	dtrace_hdl_t *h = open_nodev();
	void *pfv = dtrace_printa_create(h, "%@d");
	dtrace_recdesc_t rec;
	uint32_t id = 1;
	FILE *null = fopen("/dev/null", "w");
	int rc;

	memset(&rec, 0, sizeof (rec));
	rec.dtrd_action = DTRACEACT_PRINTA;
	rec.dtrd_size = 4;
	rec.dtrd_alignment = 4;
	fi_caller = "dt_alloc";
	rc = dtrace_fprinta(h, null, pfv, NULL, &rec, 1, &id, 4);
	fi_caller = NULL;
	fclose(null);
	if (fi_injected)
		return (rc == -1 && dtrace_errno(h) == EDT_NOMEM ? 0 : 1);
	return (rc == 1 ? 0 : 1);
}

/*
 * Regression: structured print() of a char[4] string either fails with
 * EDT_NOMEM or emits the value; it used to drop the value when the string
 * copy could not be allocated and still report success.
 */
static int
sc_print_value(void)
{
	dtrace_hdl_t *h = open_nodev();
	ctf_file_t *fp = h->dt_cdefs->dm_ctfp;
	ctf_arinfo_t ar;
	ctf_id_t arr;
	char tn[64], data[8] = "abc", *text = NULL;
	size_t tlen = 0;
	FILE *out = open_memstream(&text, &tlen);
	int rc, ok;

	ar.ctr_contents = ctf_lookup_by_name(fp, "char");
	ar.ctr_index = ctf_lookup_by_name(fp, "int");
	ar.ctr_nelems = 4;
	arr = ctf_add_array(fp, CTF_ADD_ROOT, &ar);
	if (out == NULL || arr == CTF_ERR || ctf_update(fp) == CTF_ERR)
		exit(3);
	snprintf(tn, sizeof (tn), "C`%ld", arr);
	xo_set_file(out);
	xo_set_style(NULL, XO_STYLE_JSON);
	(void) dtrace_oformat_configure(h);
	xo_open_container("t");
	fi_window = 1;
	rc = dtrace_format_print(h, out, tn, data, 4);
	fi_window = 0;
	fi_caller = NULL;
	xo_close_container("t");
	xo_finish();
	fclose(out);
	ok = rc == 4 ? strstr(text, "\"abc\"") != NULL :
	    rc == -1 && dtrace_errno(h) == EDT_NOMEM;
	free(text);
	return (ok ? 0 : 1);
}

static int
sc_print_text(void)
{
	return (sc_print(0));
}

static int
sc_print_structured(void)
{
	return (sc_print(1));
}

static const struct {
	const char *name;
	int (*fn)(void);
} scenarios[] = {
	{ "pfdict", sc_pfdict },
	{ "printf-create", sc_printf_create },
	{ "printf-dup", sc_printf_dup },
	{ "sprintf", sc_sprintf },
	{ "escape", sc_escape },
	{ "print-text", sc_print_text },
	{ "print-structured", sc_print_structured },
	{ "fprinta", sc_fprinta },
	{ "print-value", sc_print_value },
};

int
main(int argc, char **argv)
{
	size_t i;
	int n;

	if (argc != 2)
		return (2);
	for (i = 0; i < sizeof (scenarios) / sizeof (scenarios[0]); i++)
		if (strcmp(scenarios[i].name, argv[1]) == 0)
			break;
	if (i == sizeof (scenarios) / sizeof (scenarios[0]))
		return (2);
	for (n = 1; n < 1000; n++) {
		pid_t pid;
		int status, fd[2];
		char r[2] = "?";

		if (pipe(fd) != 0)
			return (3);
		fflush(stdout);
		if ((pid = fork()) == 0) {
			int ok;

			close(fd[0]);
			fi_nth = n;
			ok = scenarios[i].fn();
			r[0] = fi_injected ? 'i' : 'n';
			(void) write(fd[1], r, 1);
			exit(ok);
		}
		close(fd[1]);
		(void) read(fd[0], r, 1);
		close(fd[0]);
		if (waitpid(pid, &status, 0) != pid)
			return (3);
		if (!WIFEXITED(status)) {
			printf("%s %d crash signal %d\n", argv[1], n,
			    WTERMSIG(status));
			return (1);
		}
		printf("%s %d %s %s\n", argv[1], n, r[0] == 'i' ? "injected" :
		    "complete", WEXITSTATUS(status) == 0 ? "ok" : "BAD");
		if (WEXITSTATUS(status) != 0)
			return (1);
		if (r[0] == 'n')
			return (n > 1 ? 0 : 1);	/* at least one injection */
	}
	return (1);
}
