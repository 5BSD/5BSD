/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * A scripted stand-in for libdtrace, preloaded into bsdinstruments so
 * the watch and probes run loops can be tested without a DTrace
 * device or privileges.  The script named by $BI_MOCK has one
 * directive per line:
 *
 *	fail <what>	make one entry point fail: open, setopt:<name>,
 *			handle_drop, handle_buffered, compile:<n> (the
 *			n-th compile, 1-based), exec, go, work, snap,
 *			walk, aggprint, str2desc, grab, iter
 *	chunk <cpu> <hrtime> <epid> <text>
 *			one buffered-output chunk ("\n" and "\037"
 *			written as \n and \037); delivered to the
 *			buffered handler, or written to the work FILE
 *			in text mode.  cpu -1 means no probe data.
 *	work		end of one dtrace_work() pass
 *	drop <n> [kind]	report n drops (of dtrace_dropkind_t kind, default
 *			principal) from the next pass
 *	error <fault> <addr>
 *			a runtime error (DTRACEFLT_* number) for the
 *			error handler
 *	exit <status>	an exit() record for the record callback
 *	signal		raise SIGINT during the next pass
 *	done		the next pass reports DTRACE_WORKSTATUS_DONE
 *	sleep <ms>	pause inside the pass (lets time-based flushes,
 *			rotation and age limits come due)
 *	agg <name> <value>
 *			one count() aggregation with a single string
 *			key "k", walked by dtrace_aggregate_walk()
 *	probe <prov:mod:func:name>
 *			one probe listed by dtrace_probe_iter()
 *
 * $BI_MOCK_LOG, when set, receives every compiled program and the
 * options set, so tests can check what was asked of libdtrace.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dtrace.h>

struct mock_chunk {
	int		 cpu;
	uint64_t	 hrtime;
	dtrace_epid_t	 epid;
	char		*text;
	int		 endpass;	/* "work" marker */
	int		 drop;
	int		 dropkind;
	int		 fault;		/* error: DTRACEFLT_* + 1 */
	uint64_t	 addr;
	int		 exit;		/* exit: status + 1 */
	int		 sig;
	int		 done;
	int		 sleep_ms;
};

static struct {
	int		 loaded;
	char		 fail[64][32];
	int		 nfail;
	struct mock_chunk chunks[512];
	int		 nchunks, next;
	char		*aggname[16];
	int64_t		 aggval[16];
	int		 naggs;
	char		*probes[64];
	int		 nprobes;
	int		 ncompile;
	dtrace_handle_buffered_f *buffered;
	void		*bufarg;
	dtrace_handle_drop_f *drop;
	void		*droparg;
	dtrace_handle_err_f *err;
	void		*errarg;
	FILE		*log;
} m;

static int dummy_hdl;
static int dummy_prog;
static int dummy_proc;

static char *
unescape(const char *s)
{
	char *out, *o;

	out = o = malloc(strlen(s) + 1);
	for (; *s != '\0'; s++) {
		if (s[0] == '\\' && s[1] == 'n') {
			*o++ = '\n';
			s++;
		} else if (s[0] == '\\' && s[1] == '0' && s[2] == '3' &&
		    s[3] == '7') {
			*o++ = '\037';
			s += 3;
		} else
			*o++ = *s;
	}
	*o = '\0';
	return (out);
}

static void
load(void)
{
	FILE *fp;
	const char *path, *logpath;
	char line[4096], *p;
	struct mock_chunk *c;

	if (m.loaded)
		return;
	m.loaded = 1;
	logpath = getenv("BI_MOCK_LOG");
	if (logpath != NULL)
		m.log = fopen(logpath, "a");
	path = getenv("BI_MOCK");
	if (path == NULL || (fp = fopen(path, "r")) == NULL)
		return;
	while (fgets(line, sizeof(line), fp) != NULL) {
		line[strcspn(line, "\n")] = '\0';
		if (strncmp(line, "fail ", 5) == 0 && m.nfail < 64)
			strlcpy(m.fail[m.nfail++], line + 5,
			    sizeof(m.fail[0]));
		else if (strncmp(line, "chunk ", 6) == 0) {
			c = &m.chunks[m.nchunks++];
			c->cpu = (int)strtol(line + 6, &p, 10);
			c->hrtime = strtoull(p, &p, 10);
			c->epid = (dtrace_epid_t)strtoul(p, &p, 10);
			c->text = unescape(p + 1);
		} else if (strcmp(line, "work") == 0)
			m.chunks[m.nchunks++].endpass = 1;
		else if (strncmp(line, "drop ", 5) == 0) {
			c = &m.chunks[m.nchunks++];
			c->drop = (int)strtol(line + 5, &p, 10);
			c->dropkind = (int)strtol(p, NULL, 10);
		} else if (strncmp(line, "error ", 6) == 0) {
			c = &m.chunks[m.nchunks++];
			c->fault = (int)strtol(line + 6, &p, 10) + 1;
			c->addr = strtoull(p, NULL, 0);
		} else if (strncmp(line, "exit ", 5) == 0)
			m.chunks[m.nchunks++].exit = atoi(line + 5) + 1;
		else if (strcmp(line, "signal") == 0)
			m.chunks[m.nchunks++].sig = 1;
		else if (strcmp(line, "done") == 0)
			m.chunks[m.nchunks++].done = 1;
		else if (strncmp(line, "sleep ", 6) == 0)
			m.chunks[m.nchunks++].sleep_ms = atoi(line + 6);
		else if (strncmp(line, "agg ", 4) == 0) {
			p = strchr(line + 4, ' ');
			*p = '\0';
			m.aggname[m.naggs] = strdup(line + 4);
			m.aggval[m.naggs++] = strtoll(p + 1, NULL, 10);
		} else if (strncmp(line, "probe ", 6) == 0)
			m.probes[m.nprobes++] = strdup(line + 6);
	}
	fclose(fp);
}

static int
failing(const char *what)
{
	int i;

	load();
	for (i = 0; i < m.nfail; i++)
		if (strcmp(m.fail[i], what) == 0)
			return (1);
	return (0);
}

static void
logf_(const char *fmt, const char *a, const char *b)
{

	if (m.log != NULL) {
		fprintf(m.log, fmt, a, b);
		fflush(m.log);
	}
}

dtrace_hdl_t *
dtrace_open(int version, int flags, int *errp)
{

	(void)version;
	(void)flags;
	if (failing("open")) {
		*errp = EACCES;
		return (NULL);
	}
	return ((dtrace_hdl_t *)&dummy_hdl);
}

dtrace_hdl_t *
tracecmp_dtrace_open(int flags, int *errp)
{

	return (dtrace_open(0, flags, errp));
}

void
dtrace_close(dtrace_hdl_t *dtp)
{

	(void)dtp;
}

int
dtrace_errno(dtrace_hdl_t *dtp)
{

	(void)dtp;
	return (EINVAL);
}

const char *
dtrace_errmsg(dtrace_hdl_t *dtp, int error)
{

	(void)dtp;
	(void)error;
	return ("mock failure");
}

int
dtrace_setopt(dtrace_hdl_t *dtp, const char *opt, const char *val)
{
	char what[64];

	(void)dtp;
	snprintf(what, sizeof(what), "setopt:%s", opt);
	logf_("setopt %s=%s\n", opt, val != NULL ? val : "");
	return (failing(what) ? -1 : 0);
}

int
dtrace_handle_err(dtrace_hdl_t *dtp, dtrace_handle_err_f *hdlr, void *arg)
{

	(void)dtp;
	if (failing("handle_err"))
		return (-1);
	m.err = hdlr;
	m.errarg = arg;
	return (0);
}

int
dtrace_handle_drop(dtrace_hdl_t *dtp, dtrace_handle_drop_f *hdlr, void *arg)
{

	(void)dtp;
	if (failing("handle_drop"))
		return (-1);
	m.drop = hdlr;
	m.droparg = arg;
	return (0);
}

int
dtrace_handle_buffered(dtrace_hdl_t *dtp, dtrace_handle_buffered_f *hdlr,
    void *arg)
{

	(void)dtp;
	if (failing("handle_buffered"))
		return (-1);
	m.buffered = hdlr;
	m.bufarg = arg;
	return (0);
}

dtrace_prog_t *
dtrace_program_strcompile(dtrace_hdl_t *dtp, const char *s,
    dtrace_probespec_t spec, uint_t cflags, int argc, char *const argv[])
{
	char what[32];

	(void)dtp;
	(void)spec;
	(void)cflags;
	(void)argc;
	(void)argv;
	m.ncompile++;
	logf_("compile %s%s\n---\n", "", "");
	logf_("%s%s\n---\n", s, "");
	snprintf(what, sizeof(what), "compile:%d", m.ncompile);
	return (failing(what) ? NULL : (dtrace_prog_t *)&dummy_prog);
}

int
dtrace_program_exec(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_proginfo_t *pip)
{

	(void)dtp;
	(void)pgp;
	(void)pip;
	return (failing("exec") ? -1 : 0);
}

int
dtrace_go(dtrace_hdl_t *dtp)
{

	(void)dtp;
	return (failing("go") ? -1 : 0);
}

void
dtrace_sleep(dtrace_hdl_t *dtp)
{

	(void)dtp;
}

int
dtrace_stop(dtrace_hdl_t *dtp)
{

	(void)dtp;
	return (0);
}

static dtrace_probedesc_t mock_pdesc = {
	.dtpd_provider = "syscall",
	.dtpd_mod = "freebsd",
	.dtpd_func = "read",
	.dtpd_name = "entry",
};

dtrace_workstatus_t
dtrace_work(dtrace_hdl_t *dtp, FILE *fp, dtrace_consume_probe_f *pfunc,
    dtrace_consume_rec_f *rfunc, void *arg)
{
	dtrace_bufdata_t bd;
	dtrace_probedata_t pd;
	dtrace_eprobedesc_t ed;
	dtrace_recdesc_t rec;
	struct mock_chunk *c;
	dtrace_workstatus_t st = DTRACE_WORKSTATUS_OKAY;

	(void)dtp;
	load();
	/* Exercise the consumer callbacks the way libdtrace does. */
	memset(&pd, 0, sizeof(pd));
	memset(&rec, 0, sizeof(rec));
	(void)pfunc(&pd, arg);
	(void)rfunc(&pd, NULL, arg);
	rec.dtrd_action = DTRACEACT_PRINTF;
	(void)rfunc(&pd, &rec, arg);
	if (failing("work"))
		return (DTRACE_WORKSTATUS_ERROR);
	if (m.next >= m.nchunks)
		return (DTRACE_WORKSTATUS_DONE);
	for (; m.next < m.nchunks; m.next++) {
		c = &m.chunks[m.next];
		if (c->endpass) {
			m.next++;
			break;
		}
		if (c->done) {
			st = DTRACE_WORKSTATUS_DONE;
			continue;
		}
		if (c->sig) {
			raise(SIGINT);
			continue;
		}
		if (c->sleep_ms) {
			usleep((useconds_t)c->sleep_ms * 1000);
			continue;
		}
		if (c->drop) {
			dtrace_dropdata_t dd;

			memset(&dd, 0, sizeof(dd));
			dd.dtdda_drops = (uint64_t)c->drop;
			dd.dtdda_kind = (dtrace_dropkind_t)c->dropkind;
			dd.dtdda_msg = "mock drops";
			(void)m.drop(&dd, m.droparg);
			continue;
		}
		if (c->fault) {
			dtrace_errdata_t ed2;

			memset(&ed2, 0, sizeof(ed2));
			ed2.dteda_pdesc = &mock_pdesc;
			ed2.dteda_fault = c->fault - 1;
			ed2.dteda_addr = c->addr;
			ed2.dteda_action = 1;
			ed2.dteda_msg = "error on enabled probe ID 1 (ID 2: "
			    "syscall:freebsd:read:entry): mock fault\n";
			(void)m.err(&ed2, m.errarg);
			continue;
		}
		if (c->exit) {
			uint32_t status = (uint32_t)(c->exit - 1);

			memset(&rec, 0, sizeof(rec));
			rec.dtrd_action = DTRACEACT_EXIT;
			pd.dtpda_data = (caddr_t)&status;
			(void)rfunc(&pd, &rec, arg);
			continue;
		}
		if (fp != NULL) {
			fputs(c->text, fp);
			continue;
		}
		memset(&bd, 0, sizeof(bd));
		memset(&ed, 0, sizeof(ed));
		ed.dtepd_epid = c->epid;
		pd.dtpda_cpu = c->cpu;
		pd.dtpda_timestamp = c->hrtime;
		pd.dtpda_edesc = &ed;
		pd.dtpda_pdesc = &mock_pdesc;
		bd.dtbda_buffered = c->text;
		bd.dtbda_probe = c->cpu >= 0 ? &pd : NULL;
		if (m.buffered(&bd, m.bufarg) == DTRACE_HANDLE_ABORT)
			return (DTRACE_WORKSTATUS_ERROR);
	}
	return (st);
}

int
dtrace_aggregate_snap(dtrace_hdl_t *dtp)
{

	(void)dtp;
	return (failing("snap") ? -1 : 0);
}

int
dtrace_aggregate_print(dtrace_hdl_t *dtp, FILE *fp,
    dtrace_aggregate_walk_f *func)
{
	int i;

	(void)dtp;
	(void)func;
	if (failing("aggprint"))
		return (-1);
	for (i = 0; i < m.naggs; i++)
		fprintf(fp, "  %-20s %ju\n", m.aggname[i],
		    (uintmax_t)m.aggval[i]);
	return (0);
}

int
dtrace_aggregate_walk(dtrace_hdl_t *dtp, dtrace_aggregate_f *func, void *arg)
{
	dtrace_aggdesc_t *desc;
	dtrace_aggdata_t ad;
	char data[32];
	int i, ret;

	(void)dtp;
	if (failing("walk"))
		return (-1);
	/* Variable id, one 16-byte string key "k", the count. */
	desc = calloc(1, sizeof(*desc) + 2 * sizeof(dtrace_recdesc_t));
	for (i = 0, ret = DTRACE_AGGWALK_NEXT; i < m.naggs &&
	    ret == DTRACE_AGGWALK_NEXT; i++) {
		memset(&ad, 0, sizeof(ad));
		memset(data, 0, sizeof(data));
		desc->dtagd_name = m.aggname[i];
		desc->dtagd_nrecs = 3;
		desc->dtagd_rec[0].dtrd_size = 8;
		desc->dtagd_rec[1].dtrd_action = DTRACEACT_DIFEXPR;
		desc->dtagd_rec[1].dtrd_size = 16;
		desc->dtagd_rec[1].dtrd_offset = 8;
		desc->dtagd_rec[2].dtrd_action = DTRACEAGG_COUNT;
		desc->dtagd_rec[2].dtrd_size = 8;
		desc->dtagd_rec[2].dtrd_offset = 24;
		strlcpy(data + 8, "k", 16);
		memcpy(data + 24, &m.aggval[i], 8);
		ad.dtada_desc = desc;
		ad.dtada_data = data;
		ad.dtada_normal = 1;
		ret = func(&ad, arg);
	}
	free(desc);
	return (0);
}

int
dtrace_lookup_by_addr(dtrace_hdl_t *dtp, GElf_Addr addr, GElf_Sym *symp,
    dtrace_syminfo_t *sip)
{

	(void)dtp;
	(void)addr;
	(void)symp;
	(void)sip;
	return (-1);
}

int
dtrace_str2desc(dtrace_hdl_t *dtp, dtrace_probespec_t spec, const char *s,
    dtrace_probedesc_t *pdp)
{

	(void)dtp;
	(void)spec;
	memset(pdp, 0, sizeof(*pdp));
	strlcpy(pdp->dtpd_provider, s, sizeof(pdp->dtpd_provider));
	return (failing("str2desc") ? -1 : 0);
}

struct ps_prochandle *
dtrace_proc_grab(dtrace_hdl_t *dtp, pid_t pid, int flags)
{

	(void)dtp;
	(void)pid;
	(void)flags;
	return (failing("grab") ? NULL : (struct ps_prochandle *)&dummy_proc);
}

void
dtrace_proc_continue(dtrace_hdl_t *dtp, struct ps_prochandle *P)
{

	(void)dtp;
	(void)P;
}

void
dtrace_proc_release(dtrace_hdl_t *dtp, struct ps_prochandle *P)
{

	(void)dtp;
	(void)P;
}

int
dtrace_probe_iter(dtrace_hdl_t *dtp, const dtrace_probedesc_t *pdp,
    dtrace_probe_f *func, void *arg)
{
	dtrace_probedesc_t d;
	char buf[256], *f[4], *p;
	int i, j;

	if (failing("iter"))
		return (-1);
	for (i = 0; i < m.nprobes; i++) {
		strlcpy(buf, m.probes[i], sizeof(buf));
		for (j = 0, p = buf; j < 4; j++) {
			f[j] = p;
			p = strchr(p, ':');
			if (p != NULL)
				*p++ = '\0';
			else
				p = buf + strlen(buf);
		}
		if (pdp != NULL && pdp->dtpd_provider[0] != '\0' &&
		    strncmp(pdp->dtpd_provider, f[0], strlen(f[0])) != 0)
			continue;
		memset(&d, 0, sizeof(d));
		d.dtpd_id = (dtrace_id_t)(i + 1);
		strlcpy(d.dtpd_provider, f[0], sizeof(d.dtpd_provider));
		strlcpy(d.dtpd_mod, f[1], sizeof(d.dtpd_mod));
		strlcpy(d.dtpd_func, f[2], sizeof(d.dtpd_func));
		strlcpy(d.dtpd_name, f[3], sizeof(d.dtpd_name));
		if (func(dtp, &d, arg) != 0)
			break;
	}
	return (0);
}
