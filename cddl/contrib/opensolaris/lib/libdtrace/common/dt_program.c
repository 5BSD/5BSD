/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011 by Delphix. All rights reserved.
 * Copyright (c) 2021, Domagoj Stolfa. All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from Arm Limited.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from the Kenneth Hayter Scholarship Fund.
 */

#include <assert.h>
#include <sys/param.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#ifdef illumos
#include <alloca.h>
#endif

#include <dt_hashmap.h>
#include <dt_impl.h>
//#include <dt_linker_subr.h>
#include <dt_printf.h>
#include <dt_program.h>
#include <dt_provider.h>

#include <dev/vmm/vmm_param.h>

#define VERICTX_DEFAULT_VECSIZE 256 /* We expect around 256 DIFOs by default. */

typedef struct dt_verictx {
	dtrace_hdl_t *dtp;

	/*
	 * Vector
	 */
	dtrace_difo_t **difovec;
	size_t num_difos;
	size_t difovec_size;
} dt_verictx_t;

void dt_prog_generate_ident(dtrace_prog_t *);

dtrace_prog_t *
dt_program_create(dtrace_hdl_t *dtp)
{
	char buf[DT_PROG_IDENTLEN] = { 0 };
	dtrace_prog_t *pgp = dt_zalloc(dtp, sizeof (dtrace_prog_t));

	if (pgp != NULL) {
		dt_list_append(&dtp->dt_programs, pgp);
	} else {
		(void) dt_set_errno(dtp, EDT_NOMEM);
		return (NULL);
	}

	/*
	 * Generate our random identifier
	 */
	dt_prog_generate_ident(pgp);


	/*
	 * By default, programs start with DOF version 1 so that output files
	 * containing DOF are backward compatible. If a program requires new
	 * DOF features, the version is increased as needed.
	 */
	pgp->dp_dofversion = DOF_VERSION_1;

	/*
	 * Default to host
	 */
	pgp->dp_vmid = 0;
	pgp->dp_vmname = dt_zalloc(dtp, VM_MAX_NAMELEN);
	if (pgp->dp_vmname == NULL) {
		dt_list_delete(&dtp->dt_programs, pgp);
		free(pgp);
		dt_set_errno(dtp, EDT_NOMEM);
		return (NULL);
	}

	/*
	 * We don't want to set this by default.
	 */
	pgp->dp_pid = 0;

	return (pgp);
}

void
dt_program_destroy(dtrace_hdl_t *dtp, dtrace_prog_t *pgp)
{
	dt_stmt_t *stp, *next;
	uint_t i;

	if (pgp == NULL)
		return;

	if (pgp->dp_eprobes)
		dt_free(dtp, pgp->dp_eprobes);

	for (stp = dt_list_next(&pgp->dp_stmts); stp != NULL; stp = next) {
		next = dt_list_next(stp);
		dtrace_stmt_destroy(dtp, stp->ds_desc);
		dt_free(dtp, stp);
	}

	for (dt_elf_ident_owner_t *owner = dt_list_next(&pgp->dp_elfidents), *next;
	    owner != NULL; owner = next) {
		next = dt_list_next(owner);
		dt_free(dtp, owner->deo_ident->di_name);
		dt_free(dtp, owner->deo_ident);
		dt_free(dtp, owner);
	}

	for (i = 0; i < pgp->dp_xrefslen; i++) {
		if (pgp->dp_xrefs && pgp->dp_xrefs[i])
			dt_free(dtp, pgp->dp_xrefs[i]);
	}

	if (pgp->dp_xrefs)
		dt_free(dtp, pgp->dp_xrefs);

	if (pgp->dp_vmname)
		dt_free(dtp, pgp->dp_vmname);

	dt_list_delete(&dtp->dt_programs, pgp);
	dt_free(dtp, pgp);
}

/*
 * Move every statement of the compiled program src to the end of dst, so a
 * consumer that delivers one program (a HyperTrace host, which forwards one
 * ELF and binds one compiled-program digest per consumer session) can send
 * every program of its command line.  The result is the program that
 * enabling dst and then src would have produced: statements keep their
 * order, the translator references are the union of both (the DOF imports
 * each referenced translator once), and the DOF version is the higher one.
 *
 * Only compiled programs qualify: not one received from a guest, parsed from
 * an ELF (which owns its identifiers) or with a recorded error.  The
 * translator table is the only allocation; when it fails, both programs are
 * unchanged.  On success src is left empty and still owned by the handle.
 */
int
dtrace_program_append(dtrace_hdl_t *dtp, dtrace_prog_t *dst,
    dtrace_prog_t *src)
{
	dt_stmt_t *stp;
	ulong_t **xrefs;
	dt_xlator_t *dxp;
	uint_t i, len;
	size_t w;

	if (dst == NULL || src == NULL || dst == src)
		return (dt_set_errno(dtp, EINVAL));
	if (dst->dp_vmid != 0 || src->dp_vmid != 0 ||
	    dst->dp_eprobes != NULL || src->dp_eprobes != NULL ||
	    dt_list_next(&dst->dp_elfidents) != NULL ||
	    dt_list_next(&src->dp_elfidents) != NULL ||
	    dst->dp_haserror || src->dp_haserror)
		return (dt_set_errno(dtp, EINVAL));

	len = MAX(dst->dp_xrefslen, src->dp_xrefslen);
	xrefs = dst->dp_xrefs;
	if (len > dst->dp_xrefslen) {
		xrefs = dt_zalloc(dtp, sizeof (ulong_t *) * len);
		if (xrefs == NULL)
			return (-1);
		if (dst->dp_xrefslen != 0)
			memcpy(xrefs, dst->dp_xrefs,
			    sizeof (ulong_t *) * dst->dp_xrefslen);
		dt_free(dtp, dst->dp_xrefs);
		dst->dp_xrefs = xrefs;
		dst->dp_xrefslen = len;
	}
	for (i = 0; i < src->dp_xrefslen; i++) {
		if (src->dp_xrefs[i] == NULL)
			continue;
		if (xrefs[i] == NULL) {
			xrefs[i] = src->dp_xrefs[i];
		} else {
			/*
			 * Translator ids are global to the handle: both bitmaps
			 * were sized for this translator (dt_as_xlate()).
			 */
			dxp = dt_xlator_lookup_id(dtp, i);
			for (w = 0; w < BT_BITOUL(dxp->dx_nmembers); w++)
				xrefs[i][w] |= src->dp_xrefs[i][w];
			dt_free(dtp, src->dp_xrefs[i]);
		}
		src->dp_xrefs[i] = NULL;
	}
	dt_free(dtp, src->dp_xrefs);
	src->dp_xrefs = NULL;
	src->dp_xrefslen = 0;

	while ((stp = dt_list_next(&src->dp_stmts)) != NULL) {
		dt_list_delete(&src->dp_stmts, stp);
		dt_list_append(&dst->dp_stmts, stp);
	}
	dst->dp_dofversion = MAX(dst->dp_dofversion, src->dp_dofversion);
	return (0);
}

/*ARGSUSED*/
void
dtrace_program_info(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_proginfo_t *pip)
{
	dt_stmt_t *stp;
	dtrace_actdesc_t *ap, *agg;
	uint_t index, agg_index;
	dtrace_ecbdesc_t *last = NULL;

	if (pip == NULL)
		return;

	bzero(pip, sizeof (dtrace_proginfo_t));

	if (dt_list_next(&pgp->dp_stmts) != NULL) {
		pip->dpi_descattr = _dtrace_maxattr;
		pip->dpi_stmtattr = _dtrace_maxattr;
	} else {
		pip->dpi_descattr = _dtrace_defattr;
		pip->dpi_stmtattr = _dtrace_defattr;
	}

	for (stp = dt_list_next(&pgp->dp_stmts); stp; stp = dt_list_next(stp)) {
		dtrace_ecbdesc_t *edp = stp->ds_desc->dtsd_ecbdesc;

		if (edp == last)
			continue;
		last = edp;

		pip->dpi_descattr =
		    dt_attr_min(stp->ds_desc->dtsd_descattr, pip->dpi_descattr);

		pip->dpi_stmtattr =
		    dt_attr_min(stp->ds_desc->dtsd_stmtattr, pip->dpi_stmtattr);

		/*
		 * If there aren't any actions, account for the fact that
		 * recording the epid will generate a record.
		 */
		if (edp->dted_action == NULL)
			pip->dpi_recgens++;

		agg = edp->dted_action;
		agg_index = 0;
		for (ap = edp->dted_action, index = 0; ap != NULL;
		    ap = ap->dtad_next, index++) {
			/*
			 * Locate the next aggregation with a monotonic lookahead.
			 * Its preceding ntuple actions belong to the aggregation,
			 * not the ordinary record stream.  Do not subtract arg:
			 * that field contains aggregation parameters, not a count.
			 * Skipping the tuple also handles void-valued increments.
			 */
			while (agg != NULL && (agg_index < index ||
			    !DTRACEACT_ISAGG(agg->dtad_kind))) {
				agg = agg->dtad_next;
				agg_index++;
			}
			if (agg != NULL && index < agg_index &&
			    agg_index - index <= agg->dtad_ntuple)
				continue;

			if (ap->dtad_kind == DTRACEACT_SPECULATE) {
				pip->dpi_speculations++;
				continue;
			}

			if (DTRACEACT_ISAGG(ap->dtad_kind)) {
				pip->dpi_aggregates++;
				continue;
			}

			if (DTRACEACT_ISDESTRUCTIVE(ap->dtad_kind))
				continue;

			if (ap->dtad_kind == DTRACEACT_DIFEXPR &&
			    ap->dtad_difo->dtdo_rtype.dtdt_kind ==
			    DIF_TYPE_CTF &&
			    ap->dtad_difo->dtdo_rtype.dtdt_size == 0)
				continue;

			pip->dpi_recgens++;
		}
	}
}

/*
 * The kernel copies out a description of every probe an enabling matched and
 * fails with E2BIG when they do not fit, so start small and grow the buffer:
 * pid$target:a.out:: alone matches every instruction of the program.
 */
#define	DT_ENABLE_NPROBES_MIN	4096
#define	DT_ENABLE_NPROBES_MAX	(1 << 22)
_Static_assert(DT_ENABLE_NPROBES_MAX <= INT_MAX / sizeof (dtrace_probedesc_t),
    "ps_bufsize is an int");

static int
dt_enable_ioctl(dtrace_hdl_t *dtp, int cmd, dtrace_enable_io_t *args,
    int *nprobesp)
{
	int nprobes, n;

	for (nprobes = DT_ENABLE_NPROBES_MIN;; nprobes *= 4) {
		args->n_matched = 0;
		args->n_desc = 0;
		args->ps = calloc(nprobes, sizeof (dtrace_probedesc_t));
		if (args->ps == NULL) {
			errno = ENOMEM;
			return (-1);
		}
		args->ps_bufsize = nprobes * sizeof (dtrace_probedesc_t);
		n = dt_ioctl(dtp, cmd, args);
		if (n != -1 || errno != E2BIG ||
		    nprobes >= DT_ENABLE_NPROBES_MAX)
			break;
		free(args->ps);
	}
	*nprobesp = nprobes;
	return (n);
}

int
dtrace_program_exec(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_proginfo_t *pip)
{
	dtrace_enable_io_t args;
	void *dof;
	int n, err;
	int i;
	int expected_nprobes = 0;

	dtrace_program_info(dtp, pgp, pip);

	if ((dof = dtrace_dof_create(dtp, pgp, DTRACE_D_STRIP)) == NULL)
		return (-1);

	args.dof = dof;
	args.vmid = pgp->dp_vmid;
	args.epoch = pgp->dp_vmepoch;
	n = dt_enable_ioctl(dtp, DTRACEIOC_ENABLE, &args, &expected_nprobes);
	err = errno;
	dtrace_dof_destroy(dtp, dof);

	if (n == -1) {
		if (args.ps == NULL)
			return (dt_set_errno(dtp, EDT_NOMEM));
		switch (err) {
		case EINVAL:
			err = EDT_DIFINVAL;
			break;
		case EFAULT:
			err = EDT_DIFFAULT;
			break;
		case E2BIG:
			err = EDT_DIFSIZE;
			break;
		case EBUSY:
			err = EDT_ENABLING_ERR;
			break;
		default:
			break;
		}

		free(args.ps);
		return (dt_set_errno(dtp, err));
	}

	/* An older or faulty driver may report more descriptions than it copied. */
	if (args.n_desc < 0 || args.n_desc > expected_nprobes) {
		free(args.ps);
		return (dt_set_errno(dtp, EDT_DIFSIZE));
	}

	if (args.n_desc > 0) {
		dtrace_probedesc_t *eprobes;

		eprobes = malloc((size_t)args.n_desc * sizeof(*eprobes));
		if (eprobes == NULL) {
			free(args.ps);
			return (dt_set_errno(dtp, EDT_NOMEM));
		}
		memcpy(eprobes, args.ps, (size_t)args.n_desc * sizeof(*eprobes));
		free(pgp->dp_eprobes);
		pgp->dp_eprobes = eprobes;
	} else {
		free(pgp->dp_eprobes);
		pgp->dp_eprobes = NULL;
	}
	pgp->dp_neprobes = args.n_desc;

	if (pip != NULL)
		pip->dpi_matches += args.n_matched;

	free(args.ps);
	return (0);
}

int
dtrace_vprobes_create(dtrace_hdl_t *dtp, dtrace_prog_t *pgp)
{
	int n;
	dtrace_vprobe_io_t args = { 0 };

	args.eprobes = pgp->dp_eprobes;
	args.neprobes = pgp->dp_neprobes;
	args.vmid = pgp->dp_vmid;
	args.epoch = pgp->dp_vmepoch;

	n = dt_ioctl(dtp, DTRACEIOC_VPROBE_CREATE, &args);
	if (n == -1) {
		fprintf(
		    stderr, "DTRACEIOC_VPROBE_CREATE: %s\n", strerror(errno));
		return (n);
	}

	return (0);
}

int
dtrace_augment_tracing(dtrace_hdl_t *dtp, dtrace_prog_t *pgp)
{
	dtrace_enable_io_t args = { 0 };
	void *dof;
	int n, err;
	int i;

	if ((dof = dtrace_dof_create(dtp, pgp, DTRACE_D_STRIP)) == NULL)
		return (-1);

	/* DTRACEIOC_AUGMENT does not describe the probes it matched. */
	args.dof = dof;
	args.n_matched = 0;
	args.n_desc = 0;
	args.vmid = pgp->dp_vmid;
	args.epoch = pgp->dp_vmepoch;
	args.ps = NULL;
	args.ps_bufsize = 0;
	n = dt_ioctl(dtp, DTRACEIOC_AUGMENT, &args);
	err = errno;
	dtrace_dof_destroy(dtp, dof);

	if (n == -1) {
		switch (err) {
		case EINVAL:
			err = EDT_DIFINVAL;
			break;
		case EFAULT:
			err = EDT_DIFFAULT;
			break;
		case E2BIG:
			err = EDT_DIFSIZE;
			break;
		case EBUSY:
			err = EDT_ENABLING_ERR;
			break;
		default:
			break;
		}

		return (dt_set_errno(dtp, err));
	}

	return (0);
}

void
dt_ecbdesc_hold(dtrace_ecbdesc_t *edp)
{
	edp->dted_refcnt++;
}

void
dt_ecbdesc_release(dtrace_hdl_t *dtp, dtrace_ecbdesc_t *edp)
{
	if (--edp->dted_refcnt > 0)
		return;

	dt_difo_free(dtp, edp->dted_pred.dtpdd_difo);
	assert(edp->dted_action == NULL);
	dt_free(dtp, edp);
}

dtrace_ecbdesc_t *
dt_ecbdesc_create(dtrace_hdl_t *dtp, const dtrace_probedesc_t *pdp)
{
	dtrace_ecbdesc_t *edp;

	if ((edp = dt_zalloc(dtp, sizeof (dtrace_ecbdesc_t))) == NULL) {
		(void) dt_set_errno(dtp, EDT_NOMEM);
		return (NULL);
	}

	edp->dted_probe = *pdp;
	dt_ecbdesc_hold(edp);
	return (edp);
}

dtrace_stmtdesc_t *
dtrace_stmt_create(dtrace_hdl_t *dtp, dtrace_ecbdesc_t *edp)
{
	dtrace_stmtdesc_t *sdp;

	if ((sdp = dt_zalloc(dtp, sizeof (dtrace_stmtdesc_t))) == NULL)
		return (NULL);

	dt_ecbdesc_hold(edp);
	sdp->dtsd_ecbdesc = edp;
	sdp->dtsd_descattr = _dtrace_defattr;
	sdp->dtsd_stmtattr = _dtrace_defattr;

	return (sdp);
}

dtrace_actdesc_t *
dtrace_stmt_action(dtrace_hdl_t *dtp, dtrace_stmtdesc_t *sdp)
{
	dtrace_actdesc_t *new;
	dtrace_ecbdesc_t *edp = sdp->dtsd_ecbdesc;

	if ((new = dt_zalloc(dtp, sizeof (dtrace_actdesc_t))) == NULL)
		return (NULL);

	if (sdp->dtsd_action_last != NULL) {
		assert(sdp->dtsd_action != NULL);
		assert(sdp->dtsd_action_last->dtad_next == NULL);
		sdp->dtsd_action_last->dtad_next = new;
	} else {
		dtrace_actdesc_t *ap = edp->dted_action;

		assert(sdp->dtsd_action == NULL);
		sdp->dtsd_action = new;

		while (ap != NULL && ap->dtad_next != NULL)
			ap = ap->dtad_next;

		if (ap == NULL)
			edp->dted_action = new;
		else
			ap->dtad_next = new;
	}

	sdp->dtsd_action_last = new;
	bzero(new, sizeof (dtrace_actdesc_t));
	new->dtad_uarg = (uintptr_t)sdp;

	return (new);
}

int
dtrace_stmt_add(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, dtrace_stmtdesc_t *sdp)
{
	dt_stmt_t *stp = dt_alloc(dtp, sizeof (dt_stmt_t));

	if (stp == NULL)
		return (-1); /* errno is set for us */

	dt_list_append(&pgp->dp_stmts, stp);
	stp->ds_desc = sdp;

	return (0);
}

int
dtrace_stmt_iter(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_stmt_f *func, void *data)
{
	dt_stmt_t *stp, *next;
	int status = 0;

	for (stp = dt_list_next(&pgp->dp_stmts); stp != NULL; stp = next) {
		next = dt_list_next(stp);
		if ((status = func(dtp, pgp, stp->ds_desc, data)) != 0)
			break;
	}

	return (status);
}

void
dtrace_stmt_destroy(dtrace_hdl_t *dtp, dtrace_stmtdesc_t *sdp)
{
	dtrace_ecbdesc_t *edp = sdp->dtsd_ecbdesc;

	/*
	 * We need to remove any actions that we have on this ECB, and
	 * remove our hold on the ECB itself.
	 */
	if (sdp->dtsd_action != NULL) {
		dtrace_actdesc_t *last = sdp->dtsd_action_last;
		dtrace_actdesc_t *ap, *next;

		assert(last != NULL);

		for (ap = edp->dted_action; ap != NULL; ap = ap->dtad_next) {
			if (ap == sdp->dtsd_action)
				break;

			if (ap->dtad_next == sdp->dtsd_action)
				break;
		}

		assert(ap != NULL);

		/* ap may be the head predecessor of the range being removed. */
		if (ap == sdp->dtsd_action)
			edp->dted_action = last->dtad_next;
		else
			ap->dtad_next = last->dtad_next;

		/*
		 * We have now removed our action list from its ECB; we can
		 * safely destroy the list.
		 */
		last->dtad_next = NULL;

		for (ap = sdp->dtsd_action; ap != NULL; ap = next) {
			assert(ap->dtad_uarg == (uintptr_t)sdp);
			dt_difo_free(dtp, ap->dtad_difo);
			next = ap->dtad_next;
			dt_free(dtp, ap);
		}
	}

	if (sdp->dtsd_fmtdata != NULL)
		dt_printf_destroy(sdp->dtsd_fmtdata);
	dt_free(dtp, sdp->dtsd_strdata);

	dt_ecbdesc_release(dtp, sdp->dtsd_ecbdesc);
	dt_free(dtp, sdp);
}

typedef struct dt_header_info {
	dtrace_hdl_t *dthi_dtp;	/* consumer handle */
	FILE *dthi_out;		/* output file */
	char *dthi_pmname;	/* provider macro name */
	char *dthi_pfname;	/* provider function name */
	int dthi_empty;		/* should we generate empty macros */
} dt_header_info_t;

static void
dt_header_fmt_macro(char *buf, const char *str)
{
	for (;;) {
		if (islower(*str)) {
			*buf++ = *str++ + 'A' - 'a';
		} else if (*str == '-') {
			*buf++ = '_';
			str++;
		} else if (*str == '.') {
			*buf++ = '_';
			str++;
		} else if ((*buf++ = *str++) == '\0') {
			break;
		}
	}
}

static void
dt_header_fmt_func(char *buf, const char *str)
{
	for (;;) {
		if (*str == '-') {
			*buf++ = '_';
			*buf++ = '_';
			str++;
		} else if ((*buf++ = *str++) == '\0') {
			break;
		}
	}
}

/*ARGSUSED*/
static int
dt_header_decl(dt_idhash_t *dhp, dt_ident_t *idp, void *data)
{
	dt_header_info_t *infop = data;
	dtrace_hdl_t *dtp = infop->dthi_dtp;
	dt_probe_t *prp = idp->di_data;
	dt_node_t *dnp;
	char buf[DT_TYPE_NAMELEN];
	char *fname;
	const char *p;
	int i;

	p = prp->pr_name;
	for (i = 0; (p = strchr(p, '-')) != NULL; i++)
		p++;

	fname = alloca(strlen(prp->pr_name) + 1 + i);
	dt_header_fmt_func(fname, prp->pr_name);

	if (fprintf(infop->dthi_out, "extern void __dtrace_%s___%s(",
	    infop->dthi_pfname, fname) < 0)
		return (dt_set_errno(dtp, errno));

	for (dnp = prp->pr_nargs, i = 0; dnp != NULL; dnp = dnp->dn_list, i++) {
		if (fprintf(infop->dthi_out, "%s",
		    ctf_type_name(dnp->dn_ctfp, dnp->dn_type,
		    buf, sizeof (buf))) < 0)
			return (dt_set_errno(dtp, errno));

		if (i + 1 != prp->pr_nargc &&
		    fprintf(infop->dthi_out, ", ") < 0)
			return (dt_set_errno(dtp, errno));
	}

	if (i == 0 && fprintf(infop->dthi_out, "void") < 0)
		return (dt_set_errno(dtp, errno));

	if (fprintf(infop->dthi_out, ");\n") < 0)
		return (dt_set_errno(dtp, errno));

	if (fprintf(infop->dthi_out,
	    "extern int __dtraceenabled_%s___%s(void);\n",
	    infop->dthi_pfname, fname) < 0)
		return (dt_set_errno(dtp, errno));

	return (0);
}

/*ARGSUSED*/
static int
dt_header_probe(dt_idhash_t *dhp, dt_ident_t *idp, void *data)
{
	dt_header_info_t *infop = data;
	dtrace_hdl_t *dtp = infop->dthi_dtp;
	dt_probe_t *prp = idp->di_data;
	char *mname, *fname;
	const char *p;
	int i;

	p = prp->pr_name;
	for (i = 0; (p = strchr(p, '-')) != NULL; i++)
		p++;

	mname = alloca(strlen(prp->pr_name) + 1);
	dt_header_fmt_macro(mname, prp->pr_name);

	fname = alloca(strlen(prp->pr_name) + 1 + i);
	dt_header_fmt_func(fname, prp->pr_name);

	if (fprintf(infop->dthi_out, "#define\t%s_%s(",
	    infop->dthi_pmname, mname) < 0)
		return (dt_set_errno(dtp, errno));

	for (i = 0; i < prp->pr_nargc; i++) {
		if (fprintf(infop->dthi_out, "arg%d", i) < 0)
			return (dt_set_errno(dtp, errno));

		if (i + 1 != prp->pr_nargc &&
		    fprintf(infop->dthi_out, ", ") < 0)
			return (dt_set_errno(dtp, errno));
	}

	if (!infop->dthi_empty) {
		if (fprintf(infop->dthi_out, ") \\\n\t") < 0)
			return (dt_set_errno(dtp, errno));

		if (fprintf(infop->dthi_out, "__dtrace_%s___%s(",
		    infop->dthi_pfname, fname) < 0)
			return (dt_set_errno(dtp, errno));

		for (i = 0; i < prp->pr_nargc; i++) {
			if (fprintf(infop->dthi_out, "arg%d", i) < 0)
				return (dt_set_errno(dtp, errno));

			if (i + 1 != prp->pr_nargc &&
			    fprintf(infop->dthi_out, ", ") < 0)
				return (dt_set_errno(dtp, errno));
		}
	}

	if (fprintf(infop->dthi_out, ")\n") < 0)
		return (dt_set_errno(dtp, errno));

	if (!infop->dthi_empty) {
		if (fprintf(infop->dthi_out,
		    "#define\t%s_%s_ENABLED() \\\n"
		    "\t__dtraceenabled_%s___%s()\n",
		    infop->dthi_pmname, mname,
		    infop->dthi_pfname, fname) < 0)
			return (dt_set_errno(dtp, errno));

	} else {
		if (fprintf(infop->dthi_out, "#define\t%s_%s_ENABLED() (0)\n",
		    infop->dthi_pmname, mname) < 0)
			return (dt_set_errno(dtp, errno));
	}

	return (0);
}

static int
dt_header_provider(dtrace_hdl_t *dtp, dt_provider_t *pvp, FILE *out)
{
	dt_header_info_t info;
	const char *p;
	int i;

	if (pvp->pv_flags & DT_PROVIDER_IMPL)
		return (0);

	/*
	 * Count the instances of the '-' character since we'll need to double
	 * those up.
	 */
	p = pvp->pv_desc.dtvd_name;
	for (i = 0; (p = strchr(p, '-')) != NULL; i++)
		p++;

	info.dthi_dtp = dtp;
	info.dthi_out = out;
	info.dthi_empty = 0;

	info.dthi_pmname = alloca(strlen(pvp->pv_desc.dtvd_name) + 1);
	dt_header_fmt_macro(info.dthi_pmname, pvp->pv_desc.dtvd_name);

	info.dthi_pfname = alloca(strlen(pvp->pv_desc.dtvd_name) + 1 + i);
	dt_header_fmt_func(info.dthi_pfname, pvp->pv_desc.dtvd_name);

#ifdef __FreeBSD__
	if (fprintf(out, "#include <sys/sdt.h>\n\n") < 0)
		return (dt_set_errno(dtp, errno));
#endif
	if (fprintf(out, "#if _DTRACE_VERSION\n\n") < 0)
		return (dt_set_errno(dtp, errno));

	if (dt_idhash_iter(pvp->pv_probes, dt_header_probe, &info) != 0)
		return (-1); /* dt_errno is set for us */
	if (fprintf(out, "\n\n") < 0)
		return (dt_set_errno(dtp, errno));
	if (dt_idhash_iter(pvp->pv_probes, dt_header_decl, &info) != 0)
		return (-1); /* dt_errno is set for us */

	if (fprintf(out, "\n#else\n\n") < 0)
		return (dt_set_errno(dtp, errno));

	info.dthi_empty = 1;

	if (dt_idhash_iter(pvp->pv_probes, dt_header_probe, &info) != 0)
		return (-1); /* dt_errno is set for us */

	if (fprintf(out, "\n#endif\n\n") < 0)
		return (dt_set_errno(dtp, errno));

	return (0);
}

int
dtrace_program_header(dtrace_hdl_t *dtp, FILE *out, const char *fname)
{
	dt_provider_t *pvp;
	char *mfname, *p;

	if (fname != NULL) {
		if ((p = strrchr(fname, '/')) != NULL)
			fname = p + 1;

		mfname = alloca(strlen(fname) + 1);
		dt_header_fmt_macro(mfname, fname);
		if (fprintf(out, "#ifndef\t_%s\n#define\t_%s\n\n",
		    mfname, mfname) < 0)
			return (dt_set_errno(dtp, errno));
	}

	if (fprintf(out, "#include <unistd.h>\n\n") < 0)
		return (-1);

	if (fprintf(out, "#ifdef\t__cplusplus\nextern \"C\" {\n#endif\n\n") < 0)
		return (-1);

	for (pvp = dt_list_next(&dtp->dt_provlist);
	    pvp != NULL; pvp = dt_list_next(pvp)) {
		if (dt_header_provider(dtp, pvp, out) != 0)
			return (-1); /* dt_errno is set for us */
	}

	if (fprintf(out, "\n#ifdef\t__cplusplus\n}\n#endif\n") < 0)
		return (dt_set_errno(dtp, errno));

	if (fname != NULL && fprintf(out, "\n#endif\t/* _%s */\n", mfname) < 0)
		return (dt_set_errno(dtp, errno));

	return (0);
}

static int
dt_prog_verify_inttab_relocations(const dtrace_difo_t *dbase,
    const dtrace_difo_t *dnew)
{
	size_t added = dnew->dtdo_intlen - dbase->dtdo_intlen;
	size_t usetx = 0;
	uint8_t *seen;

	if (added == 0)
		return (0);
	/* SETX has a 16-bit index. The linker adds a constant only while
	 * replacing an original USETX, and every added slot must be used. */
	if (dnew->dtdo_intlen > (size_t)UINT16_MAX + 1)
		return (1);
	for (size_t i = 0; i < dbase->dtdo_len; i++)
		usetx += DIF_INSTR_OP(dbase->dtdo_buf[i]) == DIF_OP_USETX;
	if (added > usetx)
		return (1);
	seen = calloc(added, sizeof(*seen));
	if (seen == NULL)
		return (1);
	for (size_t i = 0; i < dbase->dtdo_len; i++) {
		if (DIF_INSTR_OP(dbase->dtdo_buf[i]) != DIF_OP_USETX)
			continue;
		dif_instr_t relocated = dnew->dtdo_buf[i];
		if (DIF_INSTR_OP(relocated) != DIF_OP_SETX)
			continue; /* The full instruction check rejects it below. */
		size_t index = DIF_INSTR_INTEGER(relocated);
		if (index >= dbase->dtdo_intlen && index < dnew->dtdo_intlen)
			seen[index - dbase->dtdo_intlen] = 1;
	}
	int valid = 1;
	for (size_t i = 0; i < added; i++) {
		if (seen[i] == 0) {
			valid = 0;
			break;
		}
	}
	free(seen);
	return (valid ? 0 : 1);
}

/*
 * A host DIFO whose return type is DIF_TYPE_BOTTOM was compiled without the
 * type (it names guest data); the guest's HyperTrace linker resolves it
 * (HyperTraceLinker::relocateRet) from guest CTF that the host does not
 * have, so the host cannot recompute the guest's type and size.  What the
 * linker does deterministically, and what is checked here:
 *
 *  - the result is BOTTOM, CTF or STRING (never NONE or another kind);
 *  - still BOTTOM: nothing may change except that the linker marks the
 *    CTF kind CTF_BOTTOM_TYPE; flags and size stay as compiled;
 *  - STRING: the original flags plus DIF_TF_BYREF (strings are returned by
 *    reference); the size is replaced by the host's strsize afterwards
 *    (dt_prog_apply_difo_metadata), so the guest's value is not trusted;
 *  - CTF: the original flags, optionally plus DIF_TF_BYREF (arrays are
 *    returned by reference), or exactly dt_void_rtype / dt_int_rtype, which
 *    the linker substitutes for value-less and exit() returns; a by-value
 *    result fits a DIF register (1, 2, 4 or 8 bytes, or 0 where the linker
 *    leaves the compiled size, e.g. printa()/tracemem()/quantize() operands)
 *    and a by-reference one has a nonzero size.
 *
 * The CTF kind (dtdt_ckind is the kind of the resolved type, as
 * dt_node_diftype() gives it) must fit how the result is returned: a value
 * in a register is an integer, enum, float or pointer; a value returned by
 * reference is an array, struct or union.  Which of those remains a guest
 * assertion (it comes from guest types); the size of a by-reference result
 * is bounded by `refmax' (the "guestrefsize" option), so that a guest cannot
 * make the host record (and the consumer receive) more guest memory than
 * the host allows.
 */
static bool
dt_prog_bottom_rtype_ok(const dtrace_diftype_t *base,
    const dtrace_diftype_t *new, uint64_t refmax)
{
	const uint8_t refs = DIF_TF_BYREF | DIF_TF_BYUREF;

	switch (new->dtdt_kind) {
	case DIF_TYPE_BOTTOM:
		return ((new->dtdt_ckind == base->dtdt_ckind ||
		    new->dtdt_ckind == (uint8_t)CTF_BOTTOM_TYPE) &&
		    new->dtdt_flags == base->dtdt_flags &&
		    new->dtdt_size == base->dtdt_size);
	case DIF_TYPE_STRING:
		return (new->dtdt_flags == (base->dtdt_flags | DIF_TF_BYREF));
	case DIF_TYPE_CTF:
		if (memcmp(new, &dt_void_rtype, sizeof (*new)) == 0 ||
		    (memcmp(new, &dt_int_rtype, sizeof (*new) -
		    sizeof (new->dtdt_size)) == 0 &&
		    new->dtdt_size == sizeof (int)))
			return (true);
		if (new->dtdt_flags != base->dtdt_flags &&
		    new->dtdt_flags != (base->dtdt_flags | DIF_TF_BYREF))
			return (false);
		if (new->dtdt_flags & refs)
			return (new->dtdt_size != 0 && new->dtdt_size <= refmax &&
			    (new->dtdt_ckind == CTF_K_ARRAY ||
			    new->dtdt_ckind == CTF_K_STRUCT ||
			    new->dtdt_ckind == CTF_K_UNION));
		if (new->dtdt_ckind != CTF_K_INTEGER &&
		    new->dtdt_ckind != CTF_K_ENUM &&
		    new->dtdt_ckind != CTF_K_FLOAT &&
		    new->dtdt_ckind != CTF_K_POINTER)
			return (false);
		return (new->dtdt_size == base->dtdt_size ||
		    new->dtdt_size == 1 || new->dtdt_size == 2 ||
		    new->dtdt_size == 4 || new->dtdt_size == 8);
	default:
		return (false);
	}
}

static int
dt_prog_verify_difo_validate(void *_ctx, dtrace_difo_t *dbase,
    dtrace_difo_t *dnew,
    char *base_target, char *new_target)
{
	size_t i, j;
	dif_instr_t ibase, inew;
	uint8_t opbase, opnew, opnext;
	dt_verictx_t *ctx = _ctx;
	dtrace_difv_t *difv, *curdifo_var;
	dtrace_difo_t *difo = NULL;

	if (ctx == NULL || ctx->dtp == NULL || dbase == NULL || dnew == NULL ||
	    dbase->dtdo_len != dnew->dtdo_len ||
	    (dbase->dtdo_len != 0 &&
	    (dbase->dtdo_buf == NULL || dnew->dtdo_buf == NULL)) ||
	    dbase->dtdo_intlen > dnew->dtdo_intlen ||
	    dbase->dtdo_strlen != dnew->dtdo_strlen ||
	    dbase->dtdo_symlen != dnew->dtdo_symlen ||
	    dbase->dtdo_varlen != dnew->dtdo_varlen ||
	    dbase->dtdo_destructive != dnew->dtdo_destructive ||
	    (dnew->dtdo_rtype.dtdt_kind != DIF_TYPE_CTF &&
	    dnew->dtdo_rtype.dtdt_kind != DIF_TYPE_STRING &&
	    dnew->dtdo_rtype.dtdt_kind != DIF_TYPE_NONE &&
	    dnew->dtdo_rtype.dtdt_kind != DIF_TYPE_BOTTOM) ||
	    (dnew->dtdo_rtype.dtdt_flags & ~DIF_TF_BMASK) != 0 ||
	    dnew->dtdo_rtype.dtdt_pad != 0 ||
	    (dbase->dtdo_rtype.dtdt_kind != DIF_TYPE_BOTTOM &&
	    (dbase->dtdo_rtype.dtdt_kind != dnew->dtdo_rtype.dtdt_kind ||
	    (dbase->dtdo_rtype.dtdt_kind == DIF_TYPE_CTF &&
	    (dbase->dtdo_rtype.dtdt_ckind != dnew->dtdo_rtype.dtdt_ckind ||
	    dbase->dtdo_rtype.dtdt_size != dnew->dtdo_rtype.dtdt_size)) ||
	    dbase->dtdo_rtype.dtdt_flags !=
	    dnew->dtdo_rtype.dtdt_flags)) ||
	    (dbase->dtdo_rtype.dtdt_kind == DIF_TYPE_BOTTOM &&
	    !dt_prog_bottom_rtype_ok(&dbase->dtdo_rtype, &dnew->dtdo_rtype,
	    ctx->dtp->dt_guestrefsize != 0 ? ctx->dtp->dt_guestrefsize :
	    DT_GUESTREFSIZE_DEFAULT)) ||
	    (dbase->dtdo_intlen != 0 &&
	    (dbase->dtdo_inttab == NULL || dnew->dtdo_inttab == NULL)) ||
	    (dnew->dtdo_intlen != 0 && dnew->dtdo_inttab == NULL) ||
	    (dbase->dtdo_strlen != 0 &&
	    (dbase->dtdo_strtab == NULL || dnew->dtdo_strtab == NULL)) ||
	    (dbase->dtdo_symlen != 0 &&
	    (dbase->dtdo_symtab == NULL || dnew->dtdo_symtab == NULL)) ||
	    (dbase->dtdo_varlen != 0 &&
	    (dbase->dtdo_vartab == NULL || dnew->dtdo_vartab == NULL)))
		return (1);
	if ((dbase->dtdo_intlen != 0 && memcmp(dbase->dtdo_inttab,
	    dnew->dtdo_inttab, dbase->dtdo_intlen *
	    sizeof(*dbase->dtdo_inttab)) != 0) ||
	    (dbase->dtdo_strlen != 0 && memcmp(dbase->dtdo_strtab,
	    dnew->dtdo_strtab, dbase->dtdo_strlen) != 0) ||
	    (dbase->dtdo_symlen != 0 && memcmp(dbase->dtdo_symtab,
	    dnew->dtdo_symtab, dbase->dtdo_symlen) != 0))
		return (1);
	if (dt_prog_verify_inttab_relocations(dbase, dnew) != 0)
		return (1);
	for (i = 0; i < dbase->dtdo_varlen; i++) {
		const dtrace_difv_t *oldvar = &dbase->dtdo_vartab[i];
		const dtrace_difv_t *newvar = &dnew->dtdo_vartab[i];

		if ((newvar->dtdv_type.dtdt_kind != DIF_TYPE_CTF &&
		    newvar->dtdv_type.dtdt_kind != DIF_TYPE_STRING &&
		    newvar->dtdv_type.dtdt_kind != DIF_TYPE_NONE &&
		    newvar->dtdv_type.dtdt_kind != DIF_TYPE_BOTTOM) ||
		    (newvar->dtdv_type.dtdt_flags & ~DIF_TF_BMASK) != 0 ||
		    newvar->dtdv_type.dtdt_pad != 0 ||
		    oldvar->dtdv_name != newvar->dtdv_name ||
		    oldvar->dtdv_id != newvar->dtdv_id ||
		    oldvar->dtdv_kind != newvar->dtdv_kind ||
		    oldvar->dtdv_scope != newvar->dtdv_scope ||
		    oldvar->dtdv_flags != newvar->dtdv_flags ||
		    oldvar->dtdv_type.dtdt_kind !=
		    newvar->dtdv_type.dtdt_kind ||
		    oldvar->dtdv_type.dtdt_ckind !=
		    newvar->dtdv_type.dtdt_ckind ||
		    oldvar->dtdv_type.dtdt_flags !=
		    newvar->dtdv_type.dtdt_flags ||
		    memcmp(oldvar->dtdv_object, newvar->dtdv_object,
		    sizeof(oldvar->dtdv_object)) != 0)
			return (1);
	}

	i = 0;
	ibase = 0;
	inew = 0;
	opbase = 0;
	opnew = 0;
	for (i = 0; i < ctx->num_difos; i++) {
		difo = ctx->difovec[i];
		assert(difo != NULL);

		for (j = 0; j < dnew->dtdo_varlen; j++) {
			difv = &dnew->dtdo_vartab[j];

			curdifo_var = dt_get_variable(difo, difv->dtdv_id,
			    difv->dtdv_scope, difv->dtdv_kind);
			if (curdifo_var == NULL)
				continue;

			if (difv->dtdv_type.dtdt_kind !=
			    curdifo_var->dtdv_type.dtdt_kind ||
			    difv->dtdv_type.dtdt_ckind !=
			    curdifo_var->dtdv_type.dtdt_ckind ||
			    difv->dtdv_type.dtdt_flags !=
			    curdifo_var->dtdv_type.dtdt_flags ||
			    difv->dtdv_type.dtdt_pad !=
			    curdifo_var->dtdv_type.dtdt_pad)
				return (1);
		}
	}

	/*
	 * Go through all of the base instructions and compare it to the new
	 * instructions. If we encounter a relocation, we check that it has
	 * been applied correctly and adjust the counter accordingly.
	 */
	for (i = 0; i < dbase->dtdo_len; i++) {
		ibase = dbase->dtdo_buf[i];
		inew = dnew->dtdo_buf[i];

		opbase = DIF_INSTR_OP(ibase);
		switch (opbase) {
		case DIF_OP_USETX:
			opnew = DIF_INSTR_OP(inew);
			if (opnew != DIF_OP_SETX ||
			    DIF_INSTR_RD(ibase) != DIF_INSTR_RD(inew) ||
			    DIF_INSTR_INTEGER(inew) >= dnew->dtdo_intlen) {
				fprintf(stderr,
				    "usetx was not set to setx (!= %u)\n",
				    opnew);
				return (1);
			}

			break;

		case DIF_OP_ULOAD:
			opnew = DIF_INSTR_OP(inew);
			opnext = i + 1 < dbase->dtdo_len ?
			    DIF_INSTR_OP(dbase->dtdo_buf[i + 1]) : 0;
			if (opnew != DIF_OP_LDSB && opnew != DIF_OP_LDSH &&
			    opnew != DIF_OP_LDSW && opnew != DIF_OP_LDX  &&
			    opnew != DIF_OP_LDUB && opnew != DIF_OP_LDUH &&
			    opnew != DIF_OP_LDUW) {
				if (opnext == DIF_OP_RET &&
				    inew == DIF_INSTR_NOP &&
				    DIF_INSTR_RD(dbase->dtdo_buf[i + 1]) ==
				    DIF_INSTR_RD(ibase) &&
				    (dbase->dtdo_rtype.dtdt_flags &
				    (DIF_TF_BYREF | DIF_TF_BYUREF)) != 0 &&
				    (dbase->dtdo_rtype.dtdt_flags &
				    (DIF_TF_BYREF | DIF_TF_BYUREF)) ==
				    (dnew->dtdo_rtype.dtdt_flags &
				    (DIF_TF_BYREF | DIF_TF_BYUREF)))
					break;

				fprintf(stderr,
				    "uload was not set to a ld* "
				    "instruction (!= %u)\n",
				    opnew);
				return (1);
			}
			if (DIF_INSTR_R1(ibase) != DIF_INSTR_R1(inew) ||
			    DIF_INSTR_RD(ibase) != DIF_INSTR_RD(inew) ||
			    DIF_INSTR_R2(inew) != 0)
				return (1);

			break;

		case DIF_OP_UULOAD:
			opnew = DIF_INSTR_OP(inew);
			opnext = i + 1 < dbase->dtdo_len ?
			    DIF_INSTR_OP(dbase->dtdo_buf[i + 1]) : 0;
			if (opnew != DIF_OP_ULDSB && opnew != DIF_OP_ULDSH &&
			    opnew != DIF_OP_ULDSW && opnew != DIF_OP_ULDX  &&
			    opnew != DIF_OP_ULDUB && opnew != DIF_OP_ULDUH &&
			    opnew != DIF_OP_ULDUW) {
				if (opnext == DIF_OP_RET &&
				    inew == DIF_INSTR_NOP &&
				    DIF_INSTR_RD(dbase->dtdo_buf[i + 1]) ==
				    DIF_INSTR_RD(ibase) &&
				    (dbase->dtdo_rtype.dtdt_flags &
				    (DIF_TF_BYREF | DIF_TF_BYUREF)) != 0 &&
				    (dbase->dtdo_rtype.dtdt_flags &
				    (DIF_TF_BYREF | DIF_TF_BYUREF)) ==
				    (dnew->dtdo_rtype.dtdt_flags &
				    (DIF_TF_BYREF | DIF_TF_BYUREF)))
					break;

				fprintf(stderr,
				    "uuload was not set to a uld* "
				    "instruction (!= %u)\n",
				    opnew);
				return (1);
			}
			if (DIF_INSTR_R1(ibase) != DIF_INSTR_R1(inew) ||
			    DIF_INSTR_RD(ibase) != DIF_INSTR_RD(inew) ||
			    DIF_INSTR_R2(inew) != 0)
				return (1);

			break;

		case DIF_OP_TYPECAST:
			opnew = DIF_INSTR_OP(inew);
			if (inew != DIF_INSTR_NOP) {
				fprintf(stderr,
				    "typecast was not set to nop (!= %u)\n",
				    opnew);
				return (1);
			}

			break;

		case DIF_OP_PUSHTV: {
			uint8_t ors, orv, otype, nrs, nrv, ntype;

			opnew = DIF_INSTR_OP(inew);
			if (opnew != DIF_OP_PUSHTV) {
				fprintf(stderr, "pushtv was changed (!= %u)\n",
				    opnew);
				return (1);
			}

			ors = DIF_INSTR_RS(ibase);
			orv = DIF_INSTR_R2(ibase);
			otype = DIF_INSTR_TYPE(ibase);

			nrs = DIF_INSTR_RS(inew);
			nrv = DIF_INSTR_R2(inew);
			ntype = DIF_INSTR_TYPE(inew);

			if (ors != nrs || orv != nrv ||
			    !((otype == DIF_TYPE_CTF && ntype == DIF_TYPE_CTF) ||
			    (otype == DIF_TYPE_STRING && ntype == DIF_TYPE_STRING) ||
			    (otype == DIF_TYPE_BOTTOM && ntype == DIF_TYPE_CTF))) {
				fprintf(stderr,
				    "pushtv %u, %u, %u not allowed "
				    "from pushtv %u, %u, %u\n",
				    otype, orv, ors, ntype, nrv, nrs);
				return (1);
			}

			break;
		}

		default:
			/* A guest may not erase a shift or constant load without
			 * data-flow proof. Exact matching also covers those opcodes. */
			if (ibase != inew) {
				opnew = DIF_INSTR_OP(inew);
				fprintf(stderr, "Base program:\n");
				fprintf(stderr, "%s ==>\n", base_target);
				dt_dis(dbase, stderr);
				fprintf(stderr, "\nNew program:\n");
				fprintf(stderr, "%s ==>\n", new_target);
				dt_dis(dnew, stderr);
				fprintf(stderr, "\n");
				fprintf(stderr,
				    "ibase and inew aren't "
				    "the same at %zu (%x != %x)\n"
				    "  opbase = %u\n"
				    "  opnew = %u\n",
				    i, ibase, inew, opbase, opnew);
				return (1);
			}

			break;
		}
	}

	return (0);
}

static void
dt_prog_apply_difo_metadata(dt_verictx_t *ctx, dtrace_difo_t *dnew)
{
	dtrace_optval_t strsize = 0;
	size_t i, j;
	dtrace_difo_t *difo;
	dtrace_difv_t *difv, *curdifo_var;

	for (i = 0; i < ctx->num_difos; i++) {
		difo = ctx->difovec[i];
		for (j = 0; j < dnew->dtdo_varlen; j++) {
			difv = &dnew->dtdo_vartab[j];
			curdifo_var = dt_get_variable(difo, difv->dtdv_id,
			    difv->dtdv_scope, difv->dtdv_kind);
			if (curdifo_var == NULL)
				continue;
			if (difv->dtdv_type.dtdt_size >
			    curdifo_var->dtdv_type.dtdt_size)
				curdifo_var->dtdv_type.dtdt_size =
				    difv->dtdv_type.dtdt_size;
			else
				difv->dtdv_type.dtdt_size =
				    curdifo_var->dtdv_type.dtdt_size;
		}
	}
	if (dnew->dtdo_rtype.dtdt_kind == DIF_TYPE_STRING) {
		/* An unset option means the library's default string size. */
		if (dtrace_getopt(ctx->dtp, "strsize", &strsize) != 0 ||
		    strsize == DTRACEOPT_UNSET)
			strsize = _dtrace_strsize;
		dnew->dtdo_rtype.dtdt_size = strsize;
	}
}

int
dt_prog_verify_difo(void *_ctx, dtrace_difo_t *dbase, dtrace_difo_t *dnew,
    char *base_target, char *new_target)
{
	if (dt_prog_verify_difo_validate(_ctx, dbase, dnew,
	    base_target, new_target) != 0)
		return (1);
	dt_prog_apply_difo_metadata(_ctx, dnew);
	return (0);
}

static bool dt_vprog_fullname(char *, size_t, const dtrace_probedesc_t *);

static bool
dt_prog_attr_equal(dtrace_attribute_t old, dtrace_attribute_t new)
{
	return (old.dtat_name == new.dtat_name &&
	    old.dtat_data == new.dtat_data &&
	    old.dtat_class == new.dtat_class);
}

static bool
dt_prog_verify_aggdata(const dtrace_stmtdesc_t *base,
    const dtrace_stmtdesc_t *guest)
{
	const dt_ident_t *old = base->dtsd_aggdata;
	const dt_ident_t *new = guest->dtsd_aggdata;

	if (old == NULL || new == NULL)
		return (old == new);
	if (old->di_name == NULL || new->di_name == NULL)
		return (false);
	return (old->di_kind == DT_IDENT_AGG &&
	    new->di_kind == old->di_kind &&
	    new->di_id == old->di_id &&
	    new->di_flags == old->di_flags &&
	    new->di_vers == old->di_vers &&
	    dt_prog_attr_equal(old->di_attr, new->di_attr) &&
	    strcmp(new->di_name, old->di_name) == 0);
}

/* The guest reports the concrete probes it enabled, and the host creates
 * virtual probes from that list before enabling the verified host program.
 * Each report must be covered by one of the program's original selectors.
 * Target and VMID are not used by virtual-probe creation: the attested VM
 * identity supplies those, while the four probe components name the probe. */
static bool
dt_prog_verify_eprobes(const dtrace_prog_t *base, const dtrace_prog_t *guest)
{
	char fullname[DTRACE_FULLNAMELEN + 1];
	uint32_t previous_id = 0;

	if ((guest->dp_neprobes == 0) != (guest->dp_eprobes == NULL) ||
	    guest->dp_neprobes > 64 * 1024)
		return (false);
	for (uint32_t i = 0; i < guest->dp_neprobes; i++) {
		const dtrace_probedesc_t *actual = &guest->dp_eprobes[i];
		bool covered = false;

		/* Match the kernel's DTRACE_SENSIBLE_PROBELIMIT before ioctl. */
		if (actual->dtpd_id <= previous_id ||
		    actual->dtpd_id > (1U << 20) ||
		    actual->dtpd_vmid != 0 ||
		    !dt_vprog_fullname(fullname, sizeof(fullname), actual))
			return (false);
		if (actual->dtpd_provider[0] == '\0' ||
		    actual->dtpd_name[0] == '\0')
			return (false);
		for (dt_stmt_t *stmt = dt_list_next(&base->dp_stmts);
		    stmt != NULL; stmt = dt_list_next(stmt)) {
			const dtrace_probedesc_t *selector =
			    &stmt->ds_desc->dtsd_ecbdesc->dted_probe;

			if (dt_gmatch(actual->dtpd_provider,
			    selector->dtpd_provider) &&
			    dt_gmatch(actual->dtpd_mod, selector->dtpd_mod) &&
			    dt_gmatch(actual->dtpd_func, selector->dtpd_func) &&
			    dt_gmatch(actual->dtpd_name, selector->dtpd_name)) {
				covered = true;
				break;
			}
		}
		if (!covered)
			return (false);
		previous_id = actual->dtpd_id;
	}
	return (true);
}

/* Statements can share one ECB action chain, so last->next may name the
 * next statement's first action. It must never point back into this span:
 * the verifier compares through last->next and such a loop could make it
 * skip every action or accept a shorter guest span. */
static bool
dt_prog_action_span_valid(const dtrace_stmtdesc_t *stmt)
{
	dtrace_actdesc_t *first = stmt->dtsd_action;
	dtrace_actdesc_t *last = stmt->dtsd_action_last;
	dtrace_actdesc_t *slow, *fast, *action;

	if (first == NULL || last == NULL)
		return (first == NULL && last == NULL);
	slow = fast = first;
	while (slow != last) {
		slow = slow->dtad_next;
		if (slow == NULL)
			return (false);
		for (int i = 0; i < 2 && fast != last; i++) {
			fast = fast->dtad_next;
			if (fast == NULL)
				return (false);
		}
		if (slow == fast && slow != last)
			return (false);
	}
	for (action = first; ; action = action->dtad_next) {
		if (action == last->dtad_next)
			return (false);
		if (action == last)
			break;
	}
	return (true);
}

static dt_verictx_t *
dt_verictx_alloc(dtrace_hdl_t *dtp)
{
	dt_verictx_t *ctx;

	ctx = dt_alloc(dtp, sizeof(dt_verictx_t));
	if (ctx == NULL)
		return (NULL);

	/*
	 * Set the handle that we are working on.
	 */
	ctx->dtp = dtp;

	/*
	 * Allocate the vector of DIFOs we need to check.
	 */
	ctx->difovec = dt_alloc(dtp,
	    sizeof(dtrace_difo_t *) * VERICTX_DEFAULT_VECSIZE);
	if (ctx->difovec == NULL) {
		dt_free(dtp, ctx);
		return (NULL);
	}
	memset(
	    ctx->difovec, 0, sizeof(dtrace_difo_t *) * VERICTX_DEFAULT_VECSIZE);
	ctx->num_difos = 0;
	ctx->difovec_size = VERICTX_DEFAULT_VECSIZE;
	return (ctx);
}

void
dt_verictx_teardown(void *_ctx)
{
	dt_verictx_t *ctx = _ctx;

	if (ctx == NULL)
		return;
	dt_free(ctx->dtp, ctx->difovec);
	dt_free(ctx->dtp, ctx);
}

void *
dt_verictx_init(dtrace_hdl_t *dtp)
{

	return (dt_verictx_alloc(dtp));
}

size_t
dt_verictx_mark(void *_ctx)
{
	dt_verictx_t *ctx = _ctx;

	return (ctx == NULL ? 0 : ctx->num_difos);
}

void
dt_verictx_rewind(void *_ctx, size_t mark)
{
	dt_verictx_t *ctx = _ctx;

	if (ctx == NULL)
		return;
	assert(mark <= ctx->num_difos);
	for (size_t i = mark; i < ctx->num_difos; i++)
		ctx->difovec[i] = NULL;
	ctx->num_difos = mark;
}

static int
dt_verictx_add(dt_verictx_t *ctx, dtrace_difo_t *difo)
{

	assert(ctx->difovec != NULL);
	assert(ctx->num_difos <= ctx->difovec_size);
	if (ctx->num_difos == ctx->difovec_size) {
		size_t osize;
		dtrace_difo_t **new;

		osize = ctx->difovec_size;
		if (osize > SIZE_MAX / (2 * sizeof(*new)))
			return (dt_set_errno(ctx->dtp, EDT_NOMEM));
		new = dt_alloc(ctx->dtp,
		    osize * 2 * sizeof(*new));
		if (new == NULL)
			return (-1);

		memcpy(new, ctx->difovec, osize * sizeof(dtrace_difo_t *));
		dt_free(ctx->dtp, ctx->difovec);
		ctx->difovec = new;
		ctx->difovec_size = osize * 2;
	}

	ctx->difovec[ctx->num_difos++] = difo;
	return (0);
}

static int
dt_prog_verify_inner(void *_ctx, dtrace_prog_t *pbase,
    dtrace_prog_t *pnew)
{
	dt_stmt_t *sbase, *snew;
	dtrace_stmtdesc_t *sdbase, *sdnew;
	dtrace_actdesc_t *adbase, *adnew;
	dtrace_ecbdesc_t *enew, *edp_new, *edp_base;
	dtrace_probedesc_t *pdnew, *descp_new, *descp_base;
	char target_base[DTRACE_FULLNAMELEN + 1] = { 0 };
	char target_new[DTRACE_FULLNAMELEN + 1] = { 0 };
	dt_verictx_t *ctx = _ctx;
	dtrace_hdl_t *dtp;
	int self_ref;
	size_t nstmts = 0, fmtidx;
	dt_pfargv_t **format_copies = NULL;
	dt_pfargv_t **old_formats = NULL;
	int has_formats = 0;

	sbase = NULL;
	snew = NULL;
	sdbase = NULL;
	sdnew = NULL;
	adbase = NULL;
	adnew = NULL;
	enew = NULL;
	pdnew = NULL;

	if (ctx == NULL) {
		fprintf(stderr, "dt_prog_verify(%p): context is NULL\n", ctx);
		return (1);
	}

	dtp = ctx->dtp;
	if (dtp == NULL) {
		fprintf(stderr, "dt_prog_verify(): dtp == NULL\n");
		return (1);

	}

	if (pbase == NULL) {
		fprintf(stderr, "dt_prog_verify(): pbase == NULL\n");
		return (1);
	}

	if (pnew == NULL) {
		fprintf(stderr, "dt_prog_verify(): pnew == NULL\n");
		return (1);
	}
	if (pbase->dp_dofversion != pnew->dp_dofversion ||
	    pbase->dp_rflags != pnew->dp_rflags ||
	    pbase->dp_exec != pnew->dp_exec)
		return (1);

	self_ref = 0;
	if (pbase == pnew)
		self_ref = 1;

	/*
	 * Iterate through all the statements of both programs and verify

	 * that they match up, or if they are relocations that they are
	 * applied correctly.
	 */
	for (sbase = dt_list_next(&pbase->dp_stmts),
	    snew = dt_list_next(&pnew->dp_stmts);
	    sbase && snew; sbase = dt_list_next(sbase)) {
		sdbase = sbase->ds_desc;
		sdnew = snew->ds_desc;

		if (sdbase == NULL || sdnew == NULL) {
			fprintf(stderr, "sdbase = %p, sdnew = %p (NULL err)\n",
			    sdbase, sdnew);
			return (1);
		}

		edp_base = sdbase->dtsd_ecbdesc;
		edp_new = sdnew->dtsd_ecbdesc;
		if (edp_base == NULL || edp_new == NULL)
			return (1);
		descp_base = &edp_base->dted_probe;
		descp_new = &edp_new->dted_probe;

		if (!dt_vprog_fullname(target_base, sizeof(target_base),
		    descp_base) || !dt_vprog_fullname(target_new,
		    sizeof(target_new), descp_new))
			return (1);

		if (strcmp(target_base, target_new) != 0)
			return (1);
		/*
		 * A nonzero probe ID makes the kernel enable only that probe,
		 * so a returned program must keep the original's.
		 */
		if (descp_base->dtpd_id != descp_new->dtpd_id)
			return (1);
		if (!dt_prog_attr_equal(sdbase->dtsd_descattr,
		    sdnew->dtsd_descattr) ||
		    !dt_prog_attr_equal(sdbase->dtsd_stmtattr,
		    sdnew->dtsd_stmtattr))
			return (1);
		if (!dt_prog_verify_aggdata(sdbase, sdnew))
			return (1);
		/*
		 * print()'s type reference names the host's CTF type: the
		 * returned program must carry the host's (the consumer prints
		 * the value as that type).
		 */
		if ((sdbase->dtsd_strdata == NULL) !=
		    (sdnew->dtsd_strdata == NULL) ||
		    (sdbase->dtsd_strdata != NULL &&
		    strcmp(sdbase->dtsd_strdata, sdnew->dtsd_strdata) != 0))
			return (1);
		if (edp_base->dted_uarg != edp_new->dted_uarg ||
		    (edp_base->dted_pred.dtpdd_difo == NULL) !=
		    (edp_new->dted_pred.dtpdd_difo == NULL))
			return (1);
		if (edp_base->dted_pred.dtpdd_difo != NULL) {
			if (dt_prog_verify_difo_validate(ctx,
			    edp_base->dted_pred.dtpdd_difo,
			    edp_new->dted_pred.dtpdd_difo,
			    target_base, target_new) != 0 ||
			    dt_verictx_add(ctx,
			    edp_new->dted_pred.dtpdd_difo) != 0)
				return (1);
		}

		/* span_valid() already rejects a statement whose first and last
		 * action disagree about being NULL; only the cross-statement
		 * comparison remains. */
		if (!dt_prog_action_span_valid(sdbase) ||
		    !dt_prog_action_span_valid(sdnew))
			return (1);

		if ((sdbase->dtsd_action == NULL &&
		    sdnew->dtsd_action != NULL)           ||
		    (sdbase->dtsd_action_last == NULL &&
		    sdnew->dtsd_action_last != NULL)      ||
		    (sdbase->dtsd_action != NULL &&
		    sdnew->dtsd_action == NULL)           ||
		    (sdbase->dtsd_action_last != NULL &&
		    sdnew->dtsd_action_last == NULL)) {
			fprintf(stderr,
			    "statements inconsistent: "
			    "base = [%p, %p], new = [%p, %p]\n",
			    sdbase->dtsd_action, sdbase->dtsd_action_last,
			    sdnew->dtsd_action, sdnew->dtsd_action_last);
			return (1);
		}

		for (adbase = sdbase->dtsd_action, adnew = sdnew->dtsd_action;
		     sdbase->dtsd_action_last && sdnew->dtsd_action_last &&
		     adbase != sdbase->dtsd_action_last->dtad_next &&
		     adnew != sdnew->dtsd_action_last->dtad_next;
		     adbase = adbase->dtad_next, adnew = adnew->dtad_next) {
			if (adbase == NULL || adnew == NULL ||
			    (adbase->dtad_difo == NULL) !=
			    (adnew->dtad_difo == NULL))
				return (1);
			if (adbase->dtad_kind != adnew->dtad_kind ||
			    adbase->dtad_ntuple != adnew->dtad_ntuple ||
			    adbase->dtad_arg != adnew->dtad_arg ||
			    adbase->dtad_return != adnew->dtad_return ||
			    adbase->dtad_uarg != (uintptr_t)sdbase ||
			    adnew->dtad_uarg != (uintptr_t)sdnew)
				return (1);
			if (adbase->dtad_difo != NULL) {
				if (dt_prog_verify_difo_validate(ctx,
				    adbase->dtad_difo,
				    adnew->dtad_difo, target_base,
				    target_new))
					return (1);

				if (dt_verictx_add(ctx, adnew->dtad_difo) != 0)
					return (1);
			}
		}
		if (sdbase->dtsd_action_last != NULL &&
		    (adbase != sdbase->dtsd_action_last->dtad_next ||
		    adnew != sdnew->dtsd_action_last->dtad_next))
			return (1);

		if (sdbase->dtsd_fmtdata != NULL ||
		    sdnew->dtsd_fmtdata != NULL)
			has_formats = 1;
		nstmts++;
		snew = dt_list_next(snew);
	}
	if (sbase != NULL || snew != NULL)
		return (1);
	if (!dt_prog_verify_eprobes(pbase, pnew))
		return (1);

	/* A later invalid statement must not leave an earlier statement's
	 * probe identity or format data changed. Prepare every copy first. */
	if (!self_ref && has_formats) {
		format_copies = calloc(nstmts, sizeof(*format_copies));
		if (format_copies == NULL)
			return (1);
		old_formats = calloc(nstmts, sizeof(*old_formats));
		if (old_formats == NULL) {
			free(format_copies);
			return (1);
		}
		fmtidx = 0;
		for (sbase = dt_list_next(&pbase->dp_stmts),
		    snew = dt_list_next(&pnew->dp_stmts); sbase != NULL;
		    sbase = dt_list_next(sbase), snew = dt_list_next(snew),
		    fmtidx++) {
			old_formats[fmtidx] = snew->ds_desc->dtsd_fmtdata;
			if (sbase->ds_desc->dtsd_fmtdata == NULL)
				continue;
			format_copies[fmtidx] = dt_printf_dup(
			    sbase->ds_desc->dtsd_fmtdata);
			if (format_copies[fmtidx] == NULL) {
				for (size_t i = 0; i < fmtidx; i++)
					if (format_copies[i] != NULL)
						dt_printf_destroy(format_copies[i]);
				free(old_formats);
				free(format_copies);
				return (1);
			}
		}
	}

	/* No later step can fail. Apply DIFO size reconciliation only after
	 * all instructions, actions, and format allocations have passed. */
	for (snew = dt_list_next(&pnew->dp_stmts); snew != NULL;
	    snew = dt_list_next(snew)) {
		sdnew = snew->ds_desc;
		enew = sdnew->dtsd_ecbdesc;
		if (enew->dted_pred.dtpdd_difo != NULL)
			dt_prog_apply_difo_metadata(ctx,
			    enew->dted_pred.dtpdd_difo);
		if (sdnew->dtsd_action_last != NULL) {
			for (adnew = sdnew->dtsd_action; ;
			    adnew = adnew->dtad_next) {
				if (adnew->dtad_difo != NULL)
					dt_prog_apply_difo_metadata(ctx,
					    adnew->dtad_difo);
				if (adnew == sdnew->dtsd_action_last)
					break;
			}
		}
	}

	fmtidx = 0;
	for (sbase = dt_list_next(&pbase->dp_stmts),
	    snew = dt_list_next(&pnew->dp_stmts); snew != NULL;
	    sbase = dt_list_next(sbase), snew = dt_list_next(snew), fmtidx++) {
		sdnew = snew->ds_desc;
		enew = sdnew->dtsd_ecbdesc;
		pdnew = &enew->dted_probe;
		pdnew->dtpd_vmid = pnew->dp_vmid;
		/* The ELF identifier has no trusted compiler-private aux data.
		 * Use the verified host identifier for aggregation processing. */
		if (!self_ref)
			sdnew->dtsd_aggdata = sbase->ds_desc->dtsd_aggdata;
		/* Host format strings are needed only after full verification. */
		if (!self_ref)
			sdnew->dtsd_fmtdata = format_copies == NULL ? NULL :
			    format_copies[fmtidx];
	}
	/* Parsed format descriptors are owned by the new program. Replace each
	 * old descriptor once, preserving any unusual aliases into the base. */
	if (old_formats != NULL) {
		for (fmtidx = 0; fmtidx < nstmts; fmtidx++) {
			dt_pfargv_t *old = old_formats[fmtidx];
			int shared = 0;
			if (old == NULL)
				continue;
			for (size_t i = 0; i < fmtidx; i++)
				if (old_formats[i] == old)
					shared = 1;
			for (sbase = dt_list_next(&pbase->dp_stmts);
			    sbase != NULL && !shared;
			    sbase = dt_list_next(sbase))
				if (sbase->ds_desc->dtsd_fmtdata == old)
					shared = 1;
			if (!shared)
				dt_printf_destroy(old);
		}
	}
	free(old_formats);
	free(format_copies);
	return (0);
}

int
dt_prog_verify(void *_ctx, dtrace_prog_t *pbase, dtrace_prog_t *pnew)
{
	dt_verictx_t *ctx = _ctx;
	size_t accepted = ctx == NULL ? 0 : ctx->num_difos;
	int result = dt_prog_verify_inner(_ctx, pbase, pnew);

	if (result != 0 && ctx != NULL) {
		for (size_t i = accepted; i < ctx->num_difos; i++)
			ctx->difovec[i] = NULL;
		ctx->num_difos = accepted;
	}
	return (result);
}

void
dt_prog_generate_ident(dtrace_prog_t *pgp)
{

	arc4random_buf(pgp->dp_ident, DT_PROG_IDENTLEN);
}

static void
fill_instructions(dtrace_difo_t *difo, dif_instr_t *loads, size_t num_loads,
    bool vtime, bool walltime, uint_t stackframes)
{
	uint_t i;

	i = num_loads;

	memcpy(difo->dtdo_buf, loads, sizeof(dif_instr_t) * num_loads);
	if (vtime)
		difo->dtdo_buf[i++] = DIF_INSTR_LDV(DIF_OP_LDGS,
		    DIF_VAR_VTIMESTAMP, 1);
	if (walltime)
		difo->dtdo_buf[i++] = DIF_INSTR_LDV(DIF_OP_LDGS,
		    DIF_VAR_WALLTIMESTAMP, 1);
	difo->dtdo_buf[i++] = DIF_INSTR_FMT(DIF_OP_HYPERCALL, stackframes, 0, 0);
	difo->dtdo_buf[i++] = DIF_INSTR_RET(0);
}

static bool
dt_vprog_stack_frames(dtrace_hdl_t *dtp, const dtrace_actdesc_t *act,
    uint_t *frames)
{
	uint64_t count = act->dtad_arg;

	if (count == 0) {
		dtrace_optval_t option = dtp->dt_options[DTRACEOPT_STACKFRAMES];
		count = option == DTRACEOPT_UNSET ? 20 : (uint64_t)option;
	}
	if (count == 0 || count > HYPERTRACE_STACK_MAX_FRAMES)
		return (false);
	*frames = (uint_t)count;
	return (true);
}

static bool
dt_vprog_fullname(char *out, size_t length, const dtrace_probedesc_t *pdp)
{
	int written;

	if (memchr(pdp->dtpd_target, '\0', sizeof(pdp->dtpd_target)) == NULL ||
	    memchr(pdp->dtpd_provider, '\0', sizeof(pdp->dtpd_provider)) == NULL ||
	    memchr(pdp->dtpd_mod, '\0', sizeof(pdp->dtpd_mod)) == NULL ||
	    memchr(pdp->dtpd_func, '\0', sizeof(pdp->dtpd_func)) == NULL ||
	    memchr(pdp->dtpd_name, '\0', sizeof(pdp->dtpd_name)) == NULL)
		return (false);
	memset(out, 0, length);
	written = snprintf(out, length, "%s:%s:%s:%s:%s", pdp->dtpd_target,
	    pdp->dtpd_provider, pdp->dtpd_mod, pdp->dtpd_func, pdp->dtpd_name);
	return (written >= 0 && (size_t)written < length);
}

typedef struct dt_loads_entry {
	size_t *num_loads;
	dif_instr_t *loads;
} dt_loads_entry_t;

static dif_instr_t *
dt_loads_get(dtrace_hdl_t *dtp, dt_hashmap_t *load_hm, char *target,
    size_t **num_loads)
{
	int rval;
	dt_loads_entry_t *he;

	he = dt_hashmap_lookup(load_hm, target, DTRACE_FULLNAMELEN + 1);
	if (he != NULL) {
		*num_loads = he->num_loads;
		return (he->loads);
	}

	he = malloc(sizeof(*he));
	if (he == NULL) {
		(void)dt_set_errno(dtp, EDT_NOMEM);
		return (NULL);
	}

	he->loads = malloc(sizeof(dif_instr_t) * HYPERTRACE_ARGS_MAX);
	if (he->loads == NULL) {
		free(he);
		(void)dt_set_errno(dtp, EDT_NOMEM);
		return (NULL);
	}

	he->num_loads = malloc(sizeof(size_t));
	if (he->num_loads == NULL) {
		free(he->loads);
		free(he);
		(void)dt_set_errno(dtp, EDT_NOMEM);
		return (NULL);
	}

	*he->num_loads = 0;

	rval = dt_hashmap_insert(load_hm, target, DTRACE_FULLNAMELEN + 1, he,
	    DTH_MANAGED);
	if (rval != 0) {
		(void)dt_set_errno(dtp, rval == ENOMEM ? EDT_NOMEM : rval);
		free(he->num_loads);
		free(he->loads);
		free(he);
		return (NULL);
	}

	*num_loads = he->num_loads;
	return (he->loads);
}

/*
 * Callers pass only DIF_VAR_ARG5..DIF_VAR_ARG9 and duplicates are skipped, so
 * a target's list holds at most five loads (HYPERTRACE_ARGS_MAX is ten).
 */
static void
dtrace_vprog_addargload(dif_instr_t *loads, size_t *num_loads, uint16_t var)
{
	dif_instr_t load = DIF_INSTR_LDV(DIF_OP_LDGS, var, 1);

	_Static_assert(DIF_VAR_ARG9 - DIF_VAR_ARG5 + 1 <= HYPERTRACE_ARGS_MAX,
	    "argument loads must fit the per-target list");
	for (size_t i = 0; i < *num_loads; i++)
		if (loads[i] == load)
			return;
	loads[(*num_loads)++] = load;
}

static bool
dtrace_vprog_genargloads(const dtrace_difo_t *difo, dif_instr_t *loads,
    size_t *num_loads)
{
	if (difo == NULL || (difo->dtdo_len != 0 && difo->dtdo_buf == NULL))
		return (false);
	for (size_t i = 0; i < difo->dtdo_len; i++) {
		dif_instr_t instr = difo->dtdo_buf[i];
		uint8_t opcode = DIF_INSTR_OP(instr);
		uint16_t var = DIF_INSTR_VAR(instr);

		if (opcode == DIF_OP_LDGS) {
			if (var >= DIF_VAR_ARG5 && var <= DIF_VAR_ARG9)
				dtrace_vprog_addargload(loads, num_loads, var);
			continue;
		}
		/* LDGA uses the R1 byte for its variable; LDGAA uses the
		 * 16-bit LDV field. DIF_INSTR_VAR on LDGA also includes its index
		 * register and misses args[] whenever that register is nonzero. */
		if (!((opcode == DIF_OP_LDGA &&
		    DIF_INSTR_R1(instr) == DIF_VAR_ARGS) ||
		    (opcode == DIF_OP_LDGAA && var == DIF_VAR_ARGS) ||
		    opcode == DIF_OP_XLARG))
			continue;
		/* args[] and dynamic translators may use a computed index.
		 * Capturing all five stack arguments is bounded and cannot mistake
		 * a SETX constant-table slot for the argument's value. */
		for (uint16_t arg = DIF_VAR_ARG5; arg <= DIF_VAR_ARG9; arg++)
			dtrace_vprog_addargload(loads, num_loads, arg);
	}
	return (true);
}

static const dtrace_difv_t *
dt_vprog_builtin_var(const dtrace_difo_t *difo, uint32_t id)
{
	if (difo == NULL || (difo->dtdo_varlen != 0 &&
	    difo->dtdo_vartab == NULL))
		return (NULL);
	for (uint_t i = 0; i < difo->dtdo_varlen; i++)
		if (difo->dtdo_vartab[i].dtdv_id == id)
			return (&difo->dtdo_vartab[i]);
	return (NULL);
}

int
dt_free_loads(void *key __unused, size_t ks __unused, void *data,
    void *arg __unused)
{
	dt_loads_entry_t *entry = data;
	free(entry->num_loads);
	free(entry->loads);
	free(entry);
	return (0);
}

/*
 * The guest-side forwarding of one probe: every clause of the source
 * program on that probe is forwarded by a single statement, so that a
 * firing makes one hypercall.  A hypercall names only the probe, and the
 * host runs every clause enabled on its vprobe for each hypercall: one
 * forwarding statement per source statement (the compiler makes one per
 * action) ran every host action, and evaluated every host predicate, once
 * per statement of the probe for each guest firing.
 */
typedef struct dt_vprog_group {
	char target[DTRACE_FULLNAMELEN + 1];
	dtrace_probedesc_t pdesc;
	dif_instr_t *loads;		/* argument loads (dt_loads_get) */
	size_t *num_loads;
	uint_t stackframes;		/* most frames any stack() wants */
	const dtrace_difv_t *vtime_var, *walltime_var;
	bool immstack;			/* some clause uses immstack() */
	uint64_t immstackarg;		/* its largest frame count */
} dt_vprog_group_t;

static dt_vprog_group_t *
dt_vprog_group(dtrace_hdl_t *dtp, dt_vprog_group_t **groups, size_t *ngroups,
    const char *target, const dtrace_probedesc_t *pdesc)
{
	dt_vprog_group_t *g;

	for (size_t i = 0; i < *ngroups; i++)
		if (strcmp((*groups)[i].target, target) == 0)
			return (&(*groups)[i]);
	g = realloc(*groups, (*ngroups + 1) * sizeof (**groups));
	if (g == NULL) {
		(void)dt_set_errno(dtp, EDT_NOMEM);
		return (NULL);
	}
	*groups = g;
	g = &g[(*ngroups)++];
	memset(g, 0, sizeof (*g));
	(void)strlcpy(g->target, target, sizeof (g->target));
	g->pdesc = *pdesc;
	return (g);
}

static void
dt_vprog_groups_free(dt_vprog_group_t *groups, size_t ngroups __unused)
{
	free(groups);
}

/* Record one source statement in its probe's group. */
static int
dt_vprog_collect(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, dt_hashmap_t *load_hm,
    dtrace_stmtdesc_t *sdp, dt_vprog_group_t **groups, size_t *ngroups)
{
	dtrace_ecbdesc_t *ecb = sdp->dtsd_ecbdesc;
	dtrace_probedesc_t pdesc = ecb->dted_probe;
	char target[DTRACE_FULLNAMELEN + 1] = { 0 };
	dt_vprog_group_t *g;
	dtrace_actdesc_t *act;
	size_t *num_loads;
	dif_instr_t *loads;

	pdesc.dtpd_vmid = 0;
	/*
	 * This program goes to one guest only, and a guest matches a target
	 * against its hostname, not the name its host gave the VM: an ERROR
	 * clause aimed at that name would be dropped there.  Leave it
	 * untargeted.
	 */
	if (strcmp(pdesc.dtpd_provider, "dtrace") == 0 &&
	    strcmp(pdesc.dtpd_name, "ERROR") == 0)
		pdesc.dtpd_target[0] = '\0';
	if (!dt_vprog_fullname(target, sizeof (target), &pdesc))
		return (dt_set_errno(dtp, EINVAL));
	if ((loads = dt_loads_get(dtp, load_hm, target, &num_loads)) == NULL)
		return (-1);
	if ((g = dt_vprog_group(dtp, groups, ngroups, target, &pdesc)) == NULL)
		return (-1);
	g->loads = loads;
	g->num_loads = num_loads;

	if (g->vtime_var == NULL)
		g->vtime_var = dt_vprog_builtin_var(ecb->dted_pred.dtpdd_difo,
		    DIF_VAR_VTIMESTAMP);
	if (g->walltime_var == NULL)
		g->walltime_var = dt_vprog_builtin_var(
		    ecb->dted_pred.dtpdd_difo, DIF_VAR_WALLTIMESTAMP);
	if (ecb->dted_pred.dtpdd_difo != NULL &&
	    !dtrace_vprog_genargloads(ecb->dted_pred.dtpdd_difo, loads,
	    num_loads))
		return (dt_set_errno(dtp, EINVAL));

	for (act = sdp->dtsd_action; act != NULL &&
	     act != sdp->dtsd_action_last->dtad_next; act = act->dtad_next) {
		if (act->dtad_kind == DTRACEACT_STACK) {
			uint_t requested;
			if (!dt_vprog_stack_frames(dtp, act, &requested))
				return (dt_set_errno(dtp, EINVAL));
			if (g->stackframes < requested)
				g->stackframes = requested;
		}
		if (g->vtime_var == NULL)
			g->vtime_var = dt_vprog_builtin_var(act->dtad_difo,
			    DIF_VAR_VTIMESTAMP);
		if (g->walltime_var == NULL)
			g->walltime_var = dt_vprog_builtin_var(act->dtad_difo,
			    DIF_VAR_WALLTIMESTAMP);
		/*
		 * A guest's immstack() captures the firing's stack into the
		 * per-CPU buffer the hypercall sends (dtrace.c), and every
		 * host printimmstack() prints that buffer: one capture serves
		 * every clause of the probe.
		 */
		if (act->dtad_kind == DTRACEACT_IMMSTACK) {
			g->immstack = true;
			if (g->immstackarg < act->dtad_arg)
				g->immstackarg = act->dtad_arg;
		}
		if (act->dtad_difo != NULL &&
		    !dtrace_vprog_genargloads(act->dtad_difo, loads, num_loads))
			return (dt_set_errno(dtp, EINVAL));
	}
	return (0);
}

/* The forwarding statement of one probe. */
static int
dt_vprog_emit(dtrace_hdl_t *dtp, dtrace_prog_t *newpgp,
    const dt_vprog_group_t *g)
{
	dtrace_ecbdesc_t *newecb;
	dtrace_stmtdesc_t *newstmtdesc;
	dtrace_actdesc_t *newact;
	dtrace_difo_t *difo;
	bool vtime = g->vtime_var != NULL, walltime = g->walltime_var != NULL;
	dtrace_probedesc_t pdesc = g->pdesc;

	newecb = dt_ecbdesc_create(dtp, &pdesc);
	if (newecb == NULL)
		return (-1);
	newstmtdesc = dtrace_stmt_create(dtp, newecb);
	if (newstmtdesc == NULL) {
		dt_ecbdesc_release(dtp, newecb);
		return (dt_set_errno(dtp, EDT_NOMEM));
	}

	if (g->immstack) {
		newact = dtrace_stmt_action(dtp, newstmtdesc);
		if (newact == NULL)
			goto nomem;
		newact->dtad_kind = DTRACEACT_IMMSTACK;
		newact->dtad_arg = g->immstackarg; /* the number of frames */
		newact->dtad_return = 0;
	}

	newact = dtrace_stmt_action(dtp, newstmtdesc);
	if (newact == NULL)
		goto nomem;
	newact->dtad_difo = difo = dt_zalloc(dtp, sizeof (dtrace_difo_t));
	if (difo == NULL)
		goto nomem;

	/* Capture guest virtual and wall time only for probes whose clauses
	 * use them.  The virtual-time reference enables guest thread
	 * accounting. */
	difo->dtdo_buf = dt_alloc(dtp, sizeof (dif_instr_t) *
	    (2 + *g->num_loads + vtime + walltime));
	if (difo->dtdo_buf == NULL)
		goto nomem;
	fill_instructions(difo, g->loads, *g->num_loads, vtime, walltime,
	    g->stackframes);
	difo->dtdo_len = 2 + *g->num_loads + vtime + walltime;
	if (vtime || walltime) {
		static const char vname[] = "vtimestamp";
		static const char wname[] = "walltimestamp";
		size_t namesize = (vtime ? sizeof (vname) : 0) +
		    (walltime ? sizeof (wname) : 0);
		size_t offset = 0;
		uint_t index = 0;

		difo->dtdo_varlen = vtime + walltime;
		difo->dtdo_vartab = dt_zalloc(dtp,
		    difo->dtdo_varlen * sizeof (*difo->dtdo_vartab));
		difo->dtdo_strtab = dt_alloc(dtp, namesize);
		if (difo->dtdo_vartab == NULL || difo->dtdo_strtab == NULL)
			goto nomem;
		if (vtime) {
			difo->dtdo_vartab[index] = *g->vtime_var;
			difo->dtdo_vartab[index++].dtdv_name = offset;
			memcpy(difo->dtdo_strtab + offset, vname,
			    sizeof (vname));
			offset += sizeof (vname);
		}
		if (walltime) {
			difo->dtdo_vartab[index] = *g->walltime_var;
			difo->dtdo_vartab[index].dtdv_name = offset;
			memcpy(difo->dtdo_strtab + offset, wname,
			    sizeof (wname));
			offset += sizeof (wname);
		}
		difo->dtdo_strlen = offset;
	}
	newact->dtad_kind = DTRACEACT_DIFEXPR;

	if (dtrace_stmt_add(dtp, newpgp, newstmtdesc))
		goto nomem;
	dt_ecbdesc_release(dtp, newecb);
	return (0);

nomem:
	dtrace_stmt_destroy(dtp, newstmtdesc);
	dt_ecbdesc_release(dtp, newecb);
	return (dt_set_errno(dtp, EDT_NOMEM));
}

static dtrace_prog_t *
dt_vprog_hcalls(dtrace_hdl_t *dtp, dtrace_prog_t *pgp)
{
	dtrace_prog_t *newpgp;
	dt_hashmap_t *load_hm;
	dt_stmt_t *stmt;
	dtrace_stmtdesc_t *curstmtdesc;
	dtrace_actdesc_t *curact;
	dt_vprog_group_t *groups = NULL;
	size_t ngroups = 0;

	newpgp = dt_program_create(dtp);
	if (newpgp == NULL)
		return (NULL);

	load_hm = dt_hashmap_create(DT_HASHSIZE_DEFAULT);
	if (load_hm == NULL) {
		dt_program_destroy(dtp, newpgp);
		return (NULL);
	}

	/* Every statement of a probe first (its argument loads, stack frames
	 * and time references), then one forwarding statement per probe. */
	for (stmt = dt_list_next(&pgp->dp_stmts); stmt;
	     stmt = dt_list_next(stmt)) {
		assert(stmt->ds_desc != NULL);
		if (dt_vprog_collect(dtp, pgp, load_hm, stmt->ds_desc, &groups,
		    &ngroups) != 0)
			goto fail;
	}
	for (size_t i = 0; i < ngroups; i++)
		if (dt_vprog_emit(dtp, newpgp, &groups[i]) != 0)
			goto fail;

	newpgp->dp_rflags = pgp->dp_rflags;
	dt_vprog_groups_free(groups, ngroups);
	dt_hashmap_iter(load_hm, dt_free_loads, NULL);
	dt_hashmap_free(load_hm, 1);

	/* Commit source action changes only after the new program is complete. */
	for (stmt = dt_list_next(&pgp->dp_stmts); stmt;
	    stmt = dt_list_next(stmt)) {
		curstmtdesc = stmt->ds_desc;
		for (curact = curstmtdesc->dtsd_action; curact != NULL &&
		     curact != curstmtdesc->dtsd_action_last->dtad_next;
		     curact = curact->dtad_next) {
			if (curact->dtad_kind == DTRACEACT_STACK &&
			    curact->dtad_arg == 0) {
				uint_t frames;
				(void)dt_vprog_stack_frames(dtp, curact, &frames);
				curact->dtad_arg = frames;
			}
			if (curact->dtad_kind == DTRACEACT_IMMSTACK)
				curact->dtad_kind = DTRACEACT_PRINTIMMSTACK;
		}
	}

	return (newpgp);
fail:
	dt_vprog_groups_free(groups, ngroups);
	dt_hashmap_iter(load_hm, dt_free_loads, NULL);
	dt_hashmap_free(load_hm, 1);
	dt_program_destroy(dtp, newpgp);
	return (NULL);
}

dtrace_prog_t *
dtrace_vprog_from(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, int pgp_kind)
{
	dtrace_prog_t *newpgp;

	newpgp = NULL;

	switch (pgp_kind) {
	case PGP_KIND_HYPERCALLS:
		newpgp = dt_vprog_hcalls(dtp, pgp);
		break;

	default:
		return (NULL);
	}
	if (newpgp == NULL)
		return (NULL);


	/*
	 * Patch up the necessary information to identify which program this one
	 * comes from.
	 */
	memcpy(newpgp->dp_srcident, pgp->dp_ident, DT_PROG_IDENTLEN);
	newpgp->dp_dofversion = pgp->dp_dofversion;
	newpgp->dp_vmid = pgp->dp_vmid;
	newpgp->dp_vmepoch = pgp->dp_vmepoch;

	return (newpgp);
}
