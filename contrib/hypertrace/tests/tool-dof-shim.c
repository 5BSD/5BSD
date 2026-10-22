/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Run a libdtrace consumer that does not link (lockstat, plockstat) offline
 * up to the DOF its dtrace_program_exec() hands the kernel, and report
 *
 * Linked into the tool's own objects with -Wl,--wrap: dtrace_open() opens a
 * handle whose ioctl vector receives DTRACEIOC_ENABLE (the exact DOF
 * dtrace_program_exec() built); dtrace_program_strcompile() adds
 * DTRACE_C_ZDEFS (the tool's providers are absent offline); plockstat's
 * process (dtrace_proc_create()) is stood in for by defining $target, and
 * lockstat's kernel symbol table (symtab_init(): /dev/ksyms, possibly a
 * kldload) is skipped -- it only names addresses in the tool's output.  The
 * program the tool compiled is also searched for TYPECAST annotations, so
 * a tool whose program has none is reported (the check would be vacuous).
 *
 * whether any DIF in it holds an instruction only the HyperTrace linker
 * resolves -- TYPECAST, USETX, ULOAD or UULOAD -- all of which the kernel's
 * DIF validator refuses.
 *
 * Output: "TOOLDOF difos=<n> instrs=<n> typecast=<n> usetx=<n> uload=<n>
 * uuload=<n> annotations=<n>" (annotations: link-time instructions in the
 * compiled program); the process exits 0 after reporting (the verdict is
 * the caller's).
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <dtrace.h>
#include <dt_impl.h>
#include <dt_program.h>
#include <errno.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int annotations;

static int
linktime(dif_instr_t i)
{
	uint_t op = DIF_INSTR_OP(i);
	return (op == DIF_OP_TYPECAST || op == DIF_OP_USETX ||
	    op == DIF_OP_ULOAD || op == DIF_OP_UULOAD);
}
/* The kernel's lockstat probes (sys/kern/kern_lockstat.c). */
static const char *const lockprobes[] = {
	"adaptive-acquire", "adaptive-release", "adaptive-spin",
	"adaptive-block", "spin-acquire", "spin-release", "spin-spin",
	"rw-acquire", "rw-release", "rw-block", "rw-spin", "rw-upgrade",
	"rw-downgrade", "sx-acquire", "sx-release", "sx-block", "sx-spin",
	"sx-upgrade", "sx-downgrade", "lockmgr-acquire", "lockmgr-release",
	"lockmgr-disown", "lockmgr-block", "lockmgr-upgrade",
	"lockmgr-downgrade", "thread-spin",
};
#define	NLOCKPROBES	(sizeof(lockprobes) / sizeof(lockprobes[0]))

static int
shim_ioctl(void *arg, u_long cmd, void *data)
{
	(void)arg;
	if ((cmd & 0xffffffff) == (DTRACEIOC_ENABLE & 0xffffffff)) {
		dtrace_enable_io_t *io = data;
		dof_hdr_t *dof = io->dof;
		int difos = 0, instrs = 0, tc = 0, usetx = 0, uload = 0,
		    uuload = 0;
		for (uint_t s = 0; s < dof->dofh_secnum; s++) {
			dof_sec_t *sec = (dof_sec_t *)((char *)dof +
			    dof->dofh_secoff + s * dof->dofh_secsize);
			if (sec->dofs_type != DOF_SECT_DIF)
				continue;
			difos++;
			dif_instr_t *ip = (dif_instr_t *)((char *)dof +
			    sec->dofs_offset);
			for (uint64_t i = 0; i < sec->dofs_size /
			    sizeof(dif_instr_t); i++, instrs++) {
				uint_t op = DIF_INSTR_OP(ip[i]);
				tc += op == DIF_OP_TYPECAST;
				usetx += op == DIF_OP_USETX;
				uload += op == DIF_OP_ULOAD;
				uuload += op == DIF_OP_UULOAD;
			}
		}
		printf("TOOLDOF difos=%d instrs=%d typecast=%d usetx=%d "
		    "uload=%d uuload=%d annotations=%d\n", difos, instrs, tc,
		    usetx, uload, uuload, annotations);
		fflush(stdout);
		exit(0);
	}
	if ((cmd & 0xffffffff) == (DTRACEIOC_CONF & 0xffffffff)) {
		dtrace_conf_t *c = data;
		memset(c, 0, sizeof(*c));
		c->dtc_difversion = DIF_VERSION;
		c->dtc_difintregs = DIF_DIR_NREGS;
		c->dtc_diftupregs = DIF_DTR_NREGS;
		c->dtc_ctfmodel = CTF_MODEL_NATIVE;
		return (0);
	}
	/*
	 * The lockstat provider, modelled after the kernel's: its probes'
	 * first argument is the lock (lockstat reads
	 * args[0]->lock_object.lo_name).  Other providers do not exist.
	 */
	if ((cmd & 0xffffffff) == (DTRACEIOC_PROVIDER & 0xffffffff)) {
		dtrace_providerdesc_t *pvd = data;
		dtrace_attribute_t at = { DTRACE_STABILITY_EVOLVING,
		    DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON };
		if (strcmp(pvd->dtvd_name, "lockstat") == 0) {
			memset(&pvd->dtvd_priv, 0, sizeof(pvd->dtvd_priv));
			pvd->dtvd_attr.dtpa_provider = at;
			pvd->dtvd_attr.dtpa_mod = at;
			pvd->dtvd_attr.dtpa_func = at;
			pvd->dtvd_attr.dtpa_name = at;
			pvd->dtvd_attr.dtpa_args = at;
			return (0);
		}
	} else if ((cmd & 0xffffffff) == (DTRACEIOC_PROBEMATCH & 0xffffffff) ||
	    (cmd & 0xffffffff) == (DTRACEIOC_PROBES & 0xffffffff)) {
		/* The first probe at or after dtpd_id matching the
		 * description (PROBES: any probe). */
		dtrace_probedesc_t *d = data;
		int match = (cmd & 0xffffffff) ==
		    (DTRACEIOC_PROBEMATCH & 0xffffffff);
		uint_t from = d->dtpd_id == DTRACE_IDNONE ? 1 : d->dtpd_id;
		for (uint_t i = from - 1; i < NLOCKPROBES; i++) {
			if (match && ((d->dtpd_provider[0] != '\0' &&
			    fnmatch(d->dtpd_provider, "lockstat", 0) != 0) ||
			    (d->dtpd_mod[0] != '\0' &&
			    fnmatch(d->dtpd_mod, "kernel", 0) != 0) ||
			    d->dtpd_func[0] != '\0' ||
			    (d->dtpd_name[0] != '\0' &&
			    fnmatch(d->dtpd_name, lockprobes[i], 0) != 0)))
				continue;
			d->dtpd_id = i + 1;
			strlcpy(d->dtpd_provider, "lockstat",
			    sizeof(d->dtpd_provider));
			strlcpy(d->dtpd_mod, "kernel", sizeof(d->dtpd_mod));
			d->dtpd_func[0] = '\0';
			strlcpy(d->dtpd_name, lockprobes[i],
			    sizeof(d->dtpd_name));
			return (0);
		}
	} else if ((cmd & 0xffffffff) == (DTRACEIOC_PROBEARG & 0xffffffff)) {
		dtrace_argdesc_t *a = data;
		const char *t = NULL;
		if (a->dtargd_id >= 1 && a->dtargd_id <= NLOCKPROBES) {
			const char *n = lockprobes[a->dtargd_id - 1];
			t = strncmp(n, "rw-", 3) == 0 ? "struct rwlock *" :
			    strncmp(n, "sx-", 3) == 0 ? "struct sx *" :
			    strncmp(n, "lockmgr-", 8) == 0 ? "struct lock *" :
			    "struct mtx *";
		}
		if (a->dtargd_ndx != 0 || t == NULL) {
			a->dtargd_ndx = DTRACE_ARGNONE;
			return (0);
		}
		strlcpy(a->dtargd_native, t, sizeof(a->dtargd_native));
		a->dtargd_mapping = 0;
		return (0);
	}
	errno = ESRCH; /* no such provider or probe */
	return (-1);
}

static int
shim_status(void *arg, processorid_t cpu)
{
	(void)arg;
	return (cpu == 0 ? 1 : -1);
}

static long
shim_sysconf(void *arg, int name)
{
	(void)arg;
	return (sysconf(name));
}

static const dtrace_vector_t shimvec = {
	.dtv_ioctl = shim_ioctl,
	.dtv_status = shim_status,
	.dtv_sysconf = shim_sysconf,
};

dtrace_hdl_t *
__wrap_dtrace_open(int version, int flags, int *errp)
{
	return (dtrace_vopen(version, flags | DTRACE_O_LP64, errp, &shimvec,
	    NULL));
}

dtrace_prog_t *__real_dtrace_program_strcompile(dtrace_hdl_t *, const char *,
    dtrace_probespec_t, uint_t, int, char *const []);

dtrace_prog_t *
__wrap_dtrace_program_strcompile(dtrace_hdl_t *dtp, const char *s,
    dtrace_probespec_t spec, uint_t cflags, int argc, char *const argv[])
{
	/*
	 * plockstat names its provider plockstat$target, a pid-style
	 * provider that needs a process and the fasttrap device: offline it
	 * becomes "plockstat" (same clauses, predicates and actions).
	 */
	char *text = strdup(s);
	if (text == NULL)
		return (NULL);
	for (char *m; (m = strstr(text, "plockstat$target")) != NULL;)
		memmove(m + 9, m + 16, strlen(m + 16) + 1);
	dtrace_prog_t *p = __real_dtrace_program_strcompile(dtp, text, spec,
	    cflags | DTRACE_C_ZDEFS, argc, argv);
	free(text);
	if (p == NULL) {
		fprintf(stderr, "TOOLDOF compile failed: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		return (NULL);
	}
	for (dt_stmt_t *st = dt_list_next(&p->dp_stmts); st != NULL;
	    st = dt_list_next(st)) {
		dtrace_stmtdesc_t *sd = st->ds_desc;
		dtrace_difo_t *pd = sd->dtsd_ecbdesc->dted_pred.dtpdd_difo;
		for (uint_t i = 0; pd != NULL && i < pd->dtdo_len; i++)
			annotations += linktime(pd->dtdo_buf[i]);
		for (dtrace_actdesc_t *a = sd->dtsd_action; a != NULL;
		    a = a->dtad_next) {
			dtrace_difo_t *d = a->dtad_difo;
			for (uint_t i = 0; d != NULL && i < d->dtdo_len; i++)
				annotations += linktime(d->dtdo_buf[i]);
			if (a == sd->dtsd_action_last)
				break;
		}
	}
	return (p);
}

/* plockstat: no process; $target names a pid no process has. */
struct ps_prochandle *
__wrap_dtrace_proc_create(dtrace_hdl_t *dtp, const char *file,
    char *const *argv, proc_child_func *pcf, void *child_arg)
{
	(void)file; (void)argv; (void)pcf; (void)child_arg;
	dt_ident_t *idp = dt_idhash_lookup(dtp->dt_macros, "target");
	if (idp != NULL)
		idp->di_id = 99999;
	static char dummy;
	return ((struct ps_prochandle *)&dummy);
}

/* lockstat: no kernel symbol table offline (and never a kldload). */
int
__wrap_symtab_init(void)
{
	return (0);
}
