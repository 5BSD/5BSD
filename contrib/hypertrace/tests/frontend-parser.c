/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Offline D compiler front-end driver for the frontend-parser-*.py suites.
 *
 * Reads a case file (see frontend_parser.py) describing D sources, compile
 * flags, options, macro arguments and the compile mode, compiles each case
 * through the public libdtrace API on a NODEV|NOSYS handle and writes one JSON
 * object per case: the diagnostic (if any), any text libdtrace wrote to
 * stdout/stderr during compilation (tree dumps, sugar output), and for each
 * compiled statement the probe description and the predicate/action DIFOs
 * (instructions, integer table, string table, variable table, return type).
 * For type compilation the CTF result is described (name, kind, size,
 * encoding, members, array info) so the Python side can compare it with the
 * system C compiler.  No oracle lives here: this program only reports.
 */
#include <sys/types.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dtrace.h>
#include <libctf.h>
#include <dt_impl.h>
#include <dt_module.h>
#include <libelf.h>

static FILE *out;

static void
jstr(const char *s, size_t n)
{
	size_t i;

	fputc('"', out);
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];
		if (c == '"' || c == '\\')
			fprintf(out, "\\%c", c);
		else if (c < 0x20 || c >= 0x7f)
			fprintf(out, "\\u%04x", c);
		else
			fputc(c, out);
	}
	fputc('"', out);
}

static void
jcstr(const char *s)
{
	if (s == NULL)
		fputs("null", out);
	else
		jstr(s, strlen(s));
}

static void
difo(const dtrace_difo_t *dp)
{
	uint_t i;

	if (dp == NULL) {
		fputs("null", out);
		return;
	}
	fputs("{\"insns\":[", out);
	for (i = 0; i < dp->dtdo_len; i++)
		fprintf(out, "%s%u", i ? "," : "", dp->dtdo_buf[i]);
	fputs("],\"ints\":[", out);
	for (i = 0; i < dp->dtdo_intlen; i++)
		fprintf(out, "%s\"%llu\"", i ? "," : "",
		    (unsigned long long)dp->dtdo_inttab[i]);
	fputs("],\"strtab\":", out);
	jstr(dp->dtdo_strtab ? dp->dtdo_strtab : "", dp->dtdo_strlen);
	fputs(",\"vars\":[", out);
	for (i = 0; i < dp->dtdo_varlen; i++) {
		const dtrace_difv_t *v = &dp->dtdo_vartab[i];
		fprintf(out, "%s{\"name\":", i ? "," : "");
		jcstr(v->dtdv_name < dp->dtdo_strlen ?
		    dp->dtdo_strtab + v->dtdv_name : NULL);
		fprintf(out, ",\"id\":%u,\"kind\":%u,\"scope\":%u,"
		    "\"flags\":%u,\"tkind\":%u,\"tckind\":%u,\"tflags\":%u,"
		    "\"tsize\":%u}", v->dtdv_id, v->dtdv_kind, v->dtdv_scope,
		    v->dtdv_flags, v->dtdv_type.dtdt_kind,
		    v->dtdv_type.dtdt_ckind, v->dtdv_type.dtdt_flags,
		    v->dtdv_type.dtdt_size);
	}
	fprintf(out, "],\"rkind\":%u,\"rckind\":%u,\"rflags\":%u,"
	    "\"rsize\":%u,\"krel\":%u,\"urel\":%u,\"xlm\":%u,\"symtab\":",
	    dp->dtdo_rtype.dtdt_kind, dp->dtdo_rtype.dtdt_ckind,
	    dp->dtdo_rtype.dtdt_flags, dp->dtdo_rtype.dtdt_size,
	    dp->dtdo_krelen, dp->dtdo_urelen, dp->dtdo_xlmlen);
	jstr(dp->dtdo_symtab ? dp->dtdo_symtab : "",
	    (size_t)dp->dtdo_symlen);
	fputc('}', out);
}

static int nstmt;

static int
stmt(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, dtrace_stmtdesc_t *sdp, void *arg)
{
	const dtrace_probedesc_t *pd = &sdp->dtsd_ecbdesc->dted_probe;
	const dtrace_actdesc_t *ap;
	int n = 0;

	(void)dtp; (void)pgp; (void)arg;
	fprintf(out, "%s{\"probe\":[", nstmt++ ? "," : "");
	jcstr(pd->dtpd_provider); fputc(',', out);
	jcstr(pd->dtpd_mod); fputc(',', out);
	jcstr(pd->dtpd_func); fputc(',', out);
	jcstr(pd->dtpd_name);
	fputs("],\"target\":", out);
	jcstr(pd->dtpd_target);
	fprintf(out, ",\"id\":%u,\"pred\":", pd->dtpd_id);
	difo(sdp->dtsd_ecbdesc->dted_pred.dtpdd_difo);
	fputs(",\"acts\":[", out);
	for (ap = sdp->dtsd_action; ap != NULL; ap = ap->dtad_next) {
		fprintf(out, "%s{\"kind\":%u,\"ntuple\":%u,\"arg\":\"%llu\","
		    "\"ret\":%d,\"difo\":", n++ ? "," : "", ap->dtad_kind,
		    ap->dtad_ntuple, (unsigned long long)ap->dtad_arg,
		    ap->dtad_return);
		difo(ap->dtad_difo);
		fputc('}', out);
		if (ap == sdp->dtsd_action_last)
			break;
	}
	fputs("]}", out);
	return (0);
}

static int
member(const char *name, ctf_id_t type, ulong_t off, void *arg)
{
	ctf_file_t *fp = arg;
	char buf[512];

	fputs(nstmt++ ? "," : "", out);
	fputs("{\"name\":", out);
	jcstr(name);
	fprintf(out, ",\"off\":%lu,\"size\":%zd,\"type\":", off,
	    ctf_type_size(fp, type));
	jcstr(ctf_type_name(fp, type, buf, sizeof (buf)));
	fputc('}', out);
	return (0);
}

static int
enumerator(const char *name, int value, void *arg)
{
	(void)arg;
	fputs(nstmt++ ? "," : "", out);
	fputs("[", out);
	jcstr(name);
	fprintf(out, ",%d]", value);
	return (0);
}

static void
typeinfo(dtrace_typeinfo_t *ti)
{
	char buf[512];
	ctf_file_t *fp = ti->dtt_ctfp;
	ctf_id_t base = ctf_type_resolve(fp, ti->dtt_type);
	int kind = ctf_type_kind(fp, base);
	ctf_encoding_t e;
	ctf_arinfo_t ar;

	fputs(",\"type\":{\"name\":", out);
	jcstr(ctf_type_name(fp, ti->dtt_type, buf, sizeof (buf)));
	fputs(",\"object\":", out);
	jcstr(ti->dtt_object);
	fprintf(out, ",\"kind\":%d,\"size\":%zd,\"flags\":%u", kind,
	    ctf_type_size(fp, ti->dtt_type), ti->dtt_flags);
	if ((kind == CTF_K_INTEGER || kind == CTF_K_FLOAT) &&
	    ctf_type_encoding(fp, base, &e) == 0)
		fprintf(out, ",\"enc\":[%u,%u,%u]", e.cte_format,
		    e.cte_offset, e.cte_bits);
	if (kind == CTF_K_ARRAY && ctf_array_info(fp, base, &ar) == 0) {
		fprintf(out, ",\"nelems\":%u,\"contents\":", ar.ctr_nelems);
		jcstr(ctf_type_name(fp, ar.ctr_contents, buf, sizeof (buf)));
	}
	if (kind == CTF_K_POINTER) {
		fputs(",\"ref\":", out);
		jcstr(ctf_type_name(fp, ctf_type_reference(fp, base), buf,
		    sizeof (buf)));
	}
	if (kind == CTF_K_STRUCT || kind == CTF_K_UNION) {
		fputs(",\"members\":[", out);
		nstmt = 0;
		(void) ctf_member_iter(fp, base, member, fp);
		fputc(']', out);
	}
	if (kind == CTF_K_ENUM) {
		fputs(",\"enums\":[", out);
		nstmt = 0;
		(void) ctf_enum_iter(fp, base, enumerator, NULL);
		fputc(']', out);
	}
	fputc('}', out);
}

/*
 * Model a loaded module whose name the kernel or a process could supply
 * (for example "sshd-session"): a dt_module_t with an in-memory CTF
 * container holding C base types.  This is what dt_module_getctf() returns
 * for a module once its CTF has been loaded, without any file or device.
 */
static int
synth_module(dtrace_hdl_t *h, const char *name)
{
	static const struct { const char *n; uint_t fmt, bits; } t[] = {
		{ "int", CTF_INT_SIGNED, 32 }, { "unsigned int", 0, 32 },
		{ "char", CTF_INT_SIGNED | CTF_INT_CHAR, 8 },
		{ "unsigned char", CTF_INT_CHAR, 8 },
		{ "signed char", CTF_INT_SIGNED | CTF_INT_CHAR, 8 },
		{ "short", CTF_INT_SIGNED, 16 }, { "unsigned short", 0, 16 },
		{ "long", CTF_INT_SIGNED, 64 }, { "unsigned long", 0, 64 },
		{ "long long", CTF_INT_SIGNED, 64 },
		{ "unsigned long long", 0, 64 },
	};
	dt_module_t *dmp = dt_module_create(h, name);
	ctf_file_t *fp;
	ctf_encoding_t e;
	size_t i;
	int err;

	if (dmp == NULL || (fp = ctf_create(&err)) == NULL)
		return (-1);
	for (i = 0; i < sizeof (t) / sizeof (t[0]); i++) {
		e.cte_format = t[i].fmt;
		e.cte_offset = 0;
		e.cte_bits = t[i].bits;
		if (ctf_add_integer(fp, CTF_ADD_ROOT, t[i].n, &e) == CTF_ERR)
			return (-1);
	}
	if (ctf_update(fp) == CTF_ERR)
		return (-1);
	dmp->dm_ctfp = fp;
	dmp->dm_flags |= DT_DM_LOADED;
	return (0);
}

/*
 * Model a module the kernel (or a process) has loaded from an ELF file with
 * CTF: libdtrace reads its symbol table and CTF lazily from dm_elf, as it
 * does for /boot modules.  flags: k = kernel, p = primary kernel module.
 */
static int
elf_module(dtrace_hdl_t *h, const char *spec)
{
	char name[128], flags[8], path[1024];
	dt_module_t *dmp;
	int fd;

	if (sscanf(spec, "%127s %7s %1023s", name, flags, path) != 3)
		return (-1);
	(void) elf_version(EV_CURRENT);
	if ((dmp = dt_module_create(h, name)) == NULL ||
	    (fd = open(path, O_RDONLY)) == -1 ||
	    (dmp->dm_elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
		return (-1);
	if (strchr(flags, 'k') != NULL)
		dmp->dm_flags |= DT_DM_KERNEL;
	if (strchr(flags, 'p') != NULL)
		dmp->dm_flags |= DT_DM_PRIMARY;
	/*
	 * '3': an ILP32 module, as dt_module_update() records for an
	 * ELFCLASS32 object.  The library's 32-bit module operations are the
	 * ones a module receives on an ILP32 handle.
	 */
	if (strchr(flags, '3') != NULL) {
		int e;
		dtrace_hdl_t *h32 = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV |
		    DTRACE_O_NOSYS | DTRACE_O_ILP32, &e);
		dt_module_t *m32;

		if (h32 == NULL || (m32 = dt_module_create(h32, "ilp32")) == NULL)
			return (-1);
		dmp->dm_ops = m32->dm_ops;
		dtrace_close(h32);
	}
	return (0);
}

struct kase {
	char id[256];
	char mode[32];
	unsigned flags;
	int oflags;
	int keep;
	int dof;
	int nargs, nopts, nmods;
	char *args[32];
	char *mods[8];
	char *elfmods[8];
	int nelfmods;
	char *opts[64];
	char *src;
	size_t srclen;
	int nosrc;
};

static char *
slurp(int fd, size_t *lenp)
{
	struct stat st;
	char *b;
	ssize_t n;

	if (fstat(fd, &st) != 0 || lseek(fd, 0, SEEK_SET) != 0)
		return (NULL);
	b = calloc(1, st.st_size + 1);
	n = read(fd, b, st.st_size);
	*lenp = n > 0 ? (size_t)n : 0;
	return (b);
}

static dtrace_hdl_t *dtp;

static void
run(struct kase *k)
{
	char tmpl[] = "frontend-capture.XXXXXX";
	int cap = mkstemp(tmpl), o1 = dup(1), o2 = dup(2), err = 0, i;
	dtrace_prog_t *pgp = NULL;
	dtrace_typeinfo_t ti;
	int rc = 0, compiled = 0, oerr = 0;
	char *capbuf;
	size_t caplen;

	unlink(tmpl);
	if (dtp == NULL || !k->keep) {
		if (dtp != NULL)
			dtrace_close(dtp);
		dtp = dtrace_open(DTRACE_VERSION, k->oflags, &err);
		if (dtp == NULL) {
			fprintf(out, "{\"id\":");
			jcstr(k->id);
			fprintf(out, ",\"open_error\":");
			jcstr(dtrace_errmsg(NULL, err));
			fputs("}\n", out);
			return;
		}
	}
	for (i = 0; i < k->nelfmods; i++) {
		if (elf_module(dtp, k->elfmods[i]) != 0) {
			fprintf(stderr, "elf_module %s failed\n", k->elfmods[i]);
			exit(4);
		}
	}
	for (i = 0; i < k->nmods; i++) {
		if (synth_module(dtp, k->mods[i]) != 0) {
			fprintf(stderr, "synth_module %s failed\n", k->mods[i]);
			exit(4);
		}
	}
	fprintf(out, "{\"id\":");
	jcstr(k->id);
	fputs(",\"setopt\":[", out);
	for (i = 0; i < k->nopts; i++) {
		char *eq = strchr(k->opts[i], '=');
		int r;
		if (eq != NULL)
			*eq = '\0';
		r = dtrace_setopt(dtp, k->opts[i], eq ? eq + 1 : NULL);
		if (eq != NULL)
			*eq = '=';
		fprintf(out, "%s", i ? "," : "");
		if (r != 0) {
			oerr = 1;
			jcstr(dtrace_errmsg(dtp, dtrace_errno(dtp)));
		} else
			fputs("0", out);
	}
	fputs("]", out);
	fflush(out);
	fflush(stdout);
	fflush(stderr);
	if (getenv("FRONTEND_NOCAPTURE") == NULL) {
		dup2(cap, 1);
		dup2(cap, 2);
	}
	if (strcmp(k->mode, "prog") == 0) {
		pgp = dtrace_program_strcompile(dtp, k->nosrc ? NULL : k->src,
		    DTRACE_PROBESPEC_NAME, k->flags, k->nargs, k->args);
		compiled = pgp != NULL;
	} else if (strncmp(k->mode, "prog-", 5) == 0) {
		/* prog-provider / prog-mod / prog-func / prog-name */
		dtrace_probespec_t sp = DTRACE_PROBESPEC_NAME;
		if (strcmp(k->mode, "prog-provider") == 0)
			sp = DTRACE_PROBESPEC_PROVIDER;
		else if (strcmp(k->mode, "prog-mod") == 0)
			sp = DTRACE_PROBESPEC_MOD;
		else if (strcmp(k->mode, "prog-func") == 0)
			sp = DTRACE_PROBESPEC_FUNC;
		pgp = dtrace_program_strcompile(dtp, k->src, sp, k->flags,
		    k->nargs, k->args);
		compiled = pgp != NULL;
	} else if (strcmp(k->mode, "file") == 0) {
		FILE *fp = fmemopen(k->src, k->srclen, "r");
		pgp = dtrace_program_fcompile(dtp, fp, k->flags, k->nargs,
		    k->args);
		compiled = pgp != NULL;
		fclose(fp);
	} else if (strcmp(k->mode, "type") == 0) {
		memset(&ti, 0, sizeof (ti));
		rc = dtrace_type_strcompile(dtp, k->src, &ti);
		compiled = rc == 0;
	} else if (strcmp(k->mode, "typefile") == 0) {
		FILE *fp = fmemopen(k->src, k->srclen, "r");
		memset(&ti, 0, sizeof (ti));
		rc = dtrace_type_fcompile(dtp, fp, &ti);
		compiled = rc == 0;
		fclose(fp);
	}
	fflush(stdout);
	fflush(stderr);
	dup2(o1, 1);
	dup2(o2, 2);
	close(o1);
	close(o2);
	capbuf = slurp(cap, &caplen);
	close(cap);
	fprintf(out, ",\"compiled\":%s,\"error\":", compiled ? "true" : "false");
	if (!compiled)
		jcstr(dtrace_errmsg(dtp, dtrace_errno(dtp)));
	else
		fputs("null", out);
	fputs(",\"output\":", out);
	jstr(capbuf ? capbuf : "", caplen);
	free(capbuf);
	if (pgp != NULL) {
		fputs(",\"stmts\":[", out);
		nstmt = 0;
		(void) dtrace_stmt_iter(dtp, pgp, stmt, NULL);
		fputc(']', out);
	}
	if (compiled && strncmp(k->mode, "type", 4) == 0)
		typeinfo(&ti);
	if (pgp != NULL && k->dof) {
		void *dof = dtrace_dof_create(dtp, pgp, DTRACE_D_PROBES);
		fprintf(out, ",\"dof\":%s", dof != NULL ? "true" : "false");
		if (dof == NULL) {
			fputs(",\"doferror\":", out);
			jcstr(dtrace_errmsg(dtp, dtrace_errno(dtp)));
		}
		if (dof != NULL)
			dtrace_dof_destroy(dtp, dof);
	}
	fprintf(out, ",\"opterr\":%d}\n", oerr);
	fflush(out);
}

/*
 * Case file: lines "@case ID", "@mode M", "@flags HEX", "@oflags HEX",
 * "@keep", "@arg TEXT", "@opt NAME[=VAL]", "@module NAME" (synthetic loaded
 * module with CTF base types), "@nosrc", "@src N" followed by
 * exactly N bytes of source and a newline, and "@end".
 */
int
main(int argc, char **argv)
{
	FILE *in;
	char line[8192];
	struct kase k;

	if (argc != 3 || (in = fopen(argv[1], "r")) == NULL ||
	    (out = fopen(argv[2], "w")) == NULL) {
		fprintf(stderr, "usage: frontend-parser cases.in results.jsonl\n");
		return (2);
	}
	memset(&k, 0, sizeof (k));
	while (fgets(line, sizeof (line), in) != NULL) {
		line[strcspn(line, "\n")] = '\0';
		if (strncmp(line, "@case ", 6) == 0) {
			memset(&k, 0, sizeof (k));
			strlcpy(k.id, line + 6, sizeof (k.id));
			strcpy(k.mode, "prog");
			k.oflags = DTRACE_O_NODEV | DTRACE_O_NOSYS;
		} else if (strncmp(line, "@mode ", 6) == 0)
			strlcpy(k.mode, line + 6, sizeof (k.mode));
		else if (strncmp(line, "@flags ", 7) == 0)
			k.flags = strtoul(line + 7, NULL, 16);
		else if (strncmp(line, "@oflags ", 8) == 0)
			k.oflags = strtoul(line + 8, NULL, 16);
		else if (strcmp(line, "@keep") == 0)
			k.keep = 1;
		else if (strcmp(line, "@nosrc") == 0)
			k.nosrc = 1;
		else if (strcmp(line, "@dof") == 0)
			k.dof = 1;
		else if (strncmp(line, "@arg ", 5) == 0)
			k.args[k.nargs++] = strdup(line + 5);
		else if (strncmp(line, "@opt ", 5) == 0)
			k.opts[k.nopts++] = strdup(line + 5);
		else if (strncmp(line, "@elfmod ", 8) == 0)
			k.elfmods[k.nelfmods++] = strdup(line + 8);
		else if (strncmp(line, "@module ", 8) == 0)
			k.mods[k.nmods++] = strdup(line + 8);
		else if (strncmp(line, "@src ", 5) == 0) {
			k.srclen = strtoul(line + 5, NULL, 10);
			k.src = calloc(1, k.srclen + 1);
			if (fread(k.src, 1, k.srclen, in) != k.srclen)
				return (3);
			(void) fgetc(in);
		} else if (strcmp(line, "@end") == 0) {
			int i;
			run(&k);
			for (i = 0; i < k.nargs; i++)
				free(k.args[i]);
			for (i = 0; i < k.nopts; i++)
				free(k.opts[i]);
			free(k.src);
		}
	}
	if (dtp != NULL)
		dtrace_close(dtp);
	fclose(out);
	/* exit() so instrumented library profiles are written. */
	exit(0);
}
