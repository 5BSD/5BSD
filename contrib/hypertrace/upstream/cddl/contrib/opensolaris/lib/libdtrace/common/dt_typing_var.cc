/*-
 * Copyright (c) 2024 Domagoj Stolfa
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
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/dtrace.h>

#include <assert.h>
#include <dt_basic_block.hh>
#include <dt_dfg.hh>
#include <dt_hypertrace_linker.hh>
#include <dt_impl.h>
#include <dt_linker_subr.hh>
#include <dt_list.h>
#include <dt_program.h>
#include <dt_typefile.hh>
#include <dt_typing.hh>
#include <dt_typing_helpers.hh>
#include <dt_typing_var.hh>
#include <dtrace.h>
#include <err.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

namespace dtrace {

/*
 * setBuiltinType() takes a node and a builtin variable, returning
 * the expected type of said builtin variable.
 */
void
TypeInference::setBuiltinType(DFGNode *n, uint16_t var, uint8_t idx)
{
	dtrace_probedesc_t *pdesc;
	int check_types;

	switch (var) {
	/*
	 * struct thread *
	 */
	case DIF_VAR_CURTHREAD:
	case DIF_VAR_HCURTHREAD:
		n->tf = dt_typefile_kernel();
		assert(n->tf != nullptr);
		n->ctfid = n->tf->getCtfID(t_thread.c_str());
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp, "failed to get type %s: %s",
			    t_thread.c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	/*
	 * uint64_t
	 */
	case DIF_VAR_HUCALLER:
	case DIF_VAR_UCALLER:
	case DIF_VAR_TIMESTAMP:
	case DIF_VAR_VTIMESTAMP:
	case DIF_VAR_HTIMESTAMP:
	case DIF_VAR_HVTIMESTAMP:
		n->tf = dt_typefile_mod("D");
		assert(n->tf != nullptr);
		n->ctfid = n->tf->getCtfID("uint64_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "failed to get type uint64_t: %s",
			    n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	/*
	 * uint_t
	 */
	case DIF_VAR_IPL:
	case DIF_VAR_HIPL:
	case DIF_VAR_HEPID:
	case DIF_VAR_EPID:
	case DIF_VAR_ID:
	case DIF_VAR_HPRID:
		n->tf = dt_typefile_mod("D");
		assert(n->tf != nullptr);
		n->ctfid = n->tf->getCtfID("uint_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "failed to get type uint_t: %s (%s)",
			    n->tf->getErrMsg(), n->tf->name().c_str());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_VAR_ARGS:
		pdesc = &n->edp->dted_probe;
		if (strcmp(pdesc->dtpd_name, "ERROR") == 0) {
			/*
			 * arg0 -> nothing
			 * arg1 -> epid
			 * arg2 -> index of the action
			 * arg3 -> DIF offset into the action or -1
			 * arg4 -> fault type
			 * arg5 -> value dependent on the fault type
			 */
			Array<String, 6> arg_type = { "", "uint32_t",
				"uint32_t", "int", "uint32_t", "uintptr_t" };

			if (idx == 0 || idx > 5)
				dt_set_progerr(dtp, pgp,
				    "accessing arg%d in the ERROR probe is "
				    "not supported",
				    idx);

			n->tf = dt_typefile_kernel();
			assert(n->tf != nullptr);

			n->ctfid = n->tf->getCtfID(arg_type[idx].c_str());
			if (n->ctfid == CTF_ERR)
				dt_set_progerr(dtp, pgp,
				    "failed to get type %s: %s",
				    arg_type[idx].c_str(), n->tf->getErrMsg());

			n->dType = DIF_TYPE_CTF;
		} else if (strcmp(pdesc->dtpd_provider, "dtrace") == 0) {
			dt_set_progerr(dtp, pgp,
			    "accessing arg%d in %s probe is not supported", idx,
			    pdesc->dtpd_name);
		} else {
			uint8_t child_op;
			argcheck_cookie cookie(n, var, idx, this);
			check_types = 0;
			for (auto child : n->r1Children) {
				assert(child->difo == n->difo);

				child_op = DIF_INSTR_OP(
				    child->getInstruction());

				if (child_op != DIF_OP_RET &&
				    child_op != DIF_OP_TYPECAST)
					check_types = 1;
			}

			for (auto child : n->r2Children) {
				assert(child->difo == n->difo);

				child_op = DIF_INSTR_OP(
				    child->getInstruction());

				if (child_op != DIF_OP_RET &&
				    child_op != DIF_OP_TYPECAST)
					check_types = 1;
			}

			if (check_types == 1)
				dtrace_probe_iter(dtp, &n->edp->dted_probe,
				    dt_infer_type_arg, &cookie);
			else {
				n->dType = DIF_TYPE_CTF;
				n->tf = dt_typefile_kernel();
				n->ctfid = n->tf->getCtfID("uint64_t");
			}
		}
		break;

	case DIF_VAR_ARG0:
	case DIF_VAR_ARG1:
	case DIF_VAR_ARG2:
	case DIF_VAR_ARG3:
	case DIF_VAR_ARG4:
	case DIF_VAR_ARG5:
	case DIF_VAR_ARG6:
	case DIF_VAR_ARG7:
	case DIF_VAR_ARG8:
	case DIF_VAR_ARG9:
	case DIF_VAR_HARG0:
	case DIF_VAR_HARG1:
	case DIF_VAR_HARG2:
	case DIF_VAR_HARG3:
	case DIF_VAR_HARG4:
	case DIF_VAR_HARG5:
	case DIF_VAR_HARG6:
	case DIF_VAR_HARG7:
	case DIF_VAR_HARG8:
	case DIF_VAR_HARG9:
	case DIF_VAR_UREGS:
	case DIF_VAR_REGS:
		n->tf = dt_typefile_mod("D");
		assert(n->tf != nullptr);
		n->ctfid = n->tf->getCtfID("uintptr_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "failed to get type uintptr_t: %s",
			    n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_VAR_WALLTIMESTAMP:
	case DIF_VAR_HWALLTIMESTAMP:
		n->tf = dt_typefile_mod("D");
		assert(n->tf != nullptr);
		n->ctfid = n->tf->getCtfID("int64_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "failed to get type int64_t: %s",
			    n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	/*
	 * uint32_t
	 */
	case DIF_VAR_STACKDEPTH:
	case DIF_VAR_USTACKDEPTH:
	case DIF_VAR_HSTACKDEPTH:
	case DIF_VAR_HUSTACKDEPTH:
		n->tf = dt_typefile_mod("D");
		assert(n->tf != nullptr);
		n->ctfid = n->tf->getCtfID("uint32_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "failed to get type uint32_t: %s",
			    n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	/*
	 * uintptr_t
	 */
	case DIF_VAR_CALLER:
	case DIF_VAR_HCALLER:
		n->tf = dt_typefile_mod("D");
		assert(n->tf != nullptr);
		n->ctfid = n->tf->getCtfID("uintptr_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "failed to get type uintptr_t: %s",
			    n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	/*
	 * string
	 */
	case DIF_VAR_PROBEPROV:
	case DIF_VAR_PROBEMOD:
	case DIF_VAR_PROBEFUNC:
	case DIF_VAR_PROBENAME:
	case DIF_VAR_HPROBEPROV:
	case DIF_VAR_HPROBEMOD:
	case DIF_VAR_HPROBEFUNC:
	case DIF_VAR_HPROBENAME:
	case DIF_VAR_EXECNAME:
	case DIF_VAR_ZONENAME:
	case DIF_VAR_HEXECNAME:
	case DIF_VAR_HZONENAME:
	case DIF_VAR_JAILNAME:
	case DIF_VAR_HJAILNAME:
	case DIF_VAR_VMNAME:
	case DIF_VAR_HVMNAME:
	case DIF_VAR_EXECARGS:
	case DIF_VAR_HEXECARGS:
		n->dType = DIF_TYPE_STRING;
		break;

	/*
	 * pid_t
	 */
	case DIF_VAR_HPID:
	case DIF_VAR_PID:
	case DIF_VAR_PPID:
	case DIF_VAR_HPPID:
		n->tf = dt_typefile_kernel();
		assert(n->tf != nullptr);
		n->ctfid = n->tf->getCtfID("pid_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp, "failed to get type pid_t: %s",
			    n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	/*
	 * id_t
	 */
	case DIF_VAR_HTID:
	case DIF_VAR_TID:
		n->tf = dt_typefile_mod("D");
		assert(n->tf != nullptr);
		n->ctfid = n->tf->getCtfID("id_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp, "failed to get type id_t: %s",
			    n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	/*
	 * uid_t
	 */
	case DIF_VAR_UID:
	case DIF_VAR_HUID:
		n->tf = dt_typefile_kernel();
		assert(n->tf != nullptr);
		n->ctfid = n->tf->getCtfID("uid_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp, "failed to get type uid_t: %s",
			    n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	/*
	 * gid_t
	 */
	case DIF_VAR_GID:
	case DIF_VAR_HGID:
		n->tf = dt_typefile_kernel();
		assert(n->tf != nullptr);
		n->ctfid = n->tf->getCtfID("gid_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp, "failed to get type gid_t: %s",
			    n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	/*
	 * int
	 */
	case DIF_VAR_HCPU:
	case DIF_VAR_CPU:
	case DIF_VAR_HERRNO:
	case DIF_VAR_ERRNO:
	case DIF_VAR_HJID:
	case DIF_VAR_JID:
		n->tf = dt_typefile_mod("D");
		assert(n->tf != nullptr);
		n->ctfid = n->tf->getCtfID("int");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp, "failed to get type int: %s",
			    n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_VAR_HHOSTID:
	case DIF_VAR_HOSTID:
		n->tf = dt_typefile_kernel();
		assert(n->tf != nullptr);

		n->ctfid = n->tf->getCtfID("hostid_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "failed te got type hostid_t: %s",
			    n->tf->getErrMsg());
		n->dType = DIF_TYPE_CTF;
		break;

	default:
		dt_set_progerr(dtp, pgp, "variable %x does not exist", var);
	}
}

int
dt_infer_type_arg(dtrace_hdl_t *dtp, const dtrace_probedesc_t *pdp,
    void *_cookie)
{
	char resolved_type[DTRACE_ARGTYPELEN];
	Typefile *tf;
	int type, which;
	int is_profile_probe;

	assert(_cookie != nullptr);
	memset(resolved_type, 0, DTRACE_ARGTYPELEN);

	argcheck_cookie *cookie = (argcheck_cookie *)_cookie;
	DFGNode *n = cookie->node;
	uint16_t var = cookie->varcode;
	uint8_t idx = cookie->idx;
	TypeInference *ti = cookie->ti;

	if (__predict_false(var != DIF_VAR_ARGS))
		return (1);

	assert(n != nullptr);
	char *mod = (char *)pdp->dtpd_mod;

	dtrace_argdesc_t ad;
	memset(&ad, 0, sizeof(ad));
	ad.dtargd_ndx = idx;
	assert(ad.dtargd_ndx <= 9);

	ad.dtargd_id = pdp->dtpd_id;
	assert(ad.dtargd_id != DTRACE_IDNONE);

	is_profile_probe = 0;
	if (strstr(pdp->dtpd_name, "tick") != nullptr)
		is_profile_probe = 1;

	if (!is_profile_probe && dt_ioctl(dtp, DTRACEIOC_PROBEARG, &ad) != 0) {
		(void)dt_set_errno(dtp, errno);
		return (1);
	}

	if (is_profile_probe == 0)
		memcpy(resolved_type, ad.dtargd_native, DTRACE_ARGTYPELEN);
	else
		strcpy(resolved_type, "uint64_t");

	ctf_id_t ctfid = dt_autoresolve_ctfid(mod, resolved_type, &tf);
	if (ctfid == CTF_ERR) {
		fprintf(stderr, "could not find type %s in %s\n", resolved_type,
		    tf->name().c_str());
		return (1);
	}

	type = DIF_TYPE_CTF;

	/*
	 * This can't currently happen, but the assertion is here for
	 * completeness.
	 */
	assert(type != DIF_TYPE_NONE);

	if (n->dType == DIF_TYPE_BOTTOM || n->dType == DIF_TYPE_NONE ||
	    n->dType == -1) {
		n->dType = type;
		n->tf = tf;
		n->ctfid = ctfid;
		return (0);
	}

	/*
	 * This can't currently happen, but the rule is here for completness.
	 */
	if (type == DIF_TYPE_BOTTOM)
		return (0);

	if (n->dType == DIF_TYPE_STRING && type == DIF_TYPE_STRING)
		return (0);

	if (n->dType == DIF_TYPE_CTF) {
		if (type != DIF_TYPE_CTF) {
			fprintf(stderr,
			    "node currently has CTF type, but type is %d\n",
			    type);
			return (1);
		}

		assert(n->dType == type);

		if (n->tf == tf && ctfid == n->ctfid)
			return (0);

		if (ti->getSubtypeRelation(n->tf, n->ctfid, tf, ctfid, which) ==
		    0) {
			if (which == SUBTYPE_NONE)
				return (1);

			if (which & SUBTYPE_SND) {
				n->tf = tf;
				n->ctfid = ctfid;
				n->dType = type;
			} else if ((which & SUBTYPE_ANY) == SUBTYPE_ANY) {
				fprintf(stderr,
				    "dt_infer_type_arg(): impossible "
				    "subtyping relation\n");
				return (1);
			}

			return (0);
		}
	}

	fprintf(stderr, "failed to infer type for type = %s\n", resolved_type);
	/*
	 * If we don't have a matching case before this, we can't type-check it.
	 */
	return (1);
}

/*
 * inferVar() figures out the type of a variable in the varlist and
 * typechecks it against dr.
 */
int
TypeInference::inferVar(DFGNode *dr, dtrace_difv_t *dif_var)
{
	char buf[4096] = { 0 }, var_type[4096] = { 0 };
	int rv, which;

	if (dr == nullptr && dif_var == nullptr) {
		fprintf(stderr,
		    "inferVar(): both dr and dif_var are nullptr\n");
		return (-1);
	}

	if (dr == nullptr)
		return (dif_var->dtdv_type.dtdt_kind);

	if (dif_var == nullptr) {
		fprintf(stderr,
		    "inferVar(): dif_var is nullptr, this makes "
		    "no sense\n");
		return (-1);
	}

	if (dif_var->dtdv_type.dtdt_kind == DIF_TYPE_BOTTOM) {
		dif_var->dtdv_tf = dr->tf;
		dif_var->dtdv_ctfid = dr->ctfid;
		dif_var->dtdv_sym = dr->sym;
		dif_var->dtdv_type.dtdt_kind = dr->dType;
		if (dr->dType == DIF_TYPE_CTF)
			dif_var->dtdv_type.dtdt_size = dr->tf->getSize(
			    dr->ctfid);
		dif_var->dtdv_type.dtdt_ckind = dr->ctfid;

		return (dr->dType);
	}

	if (dr->dType == DIF_TYPE_BOTTOM)
		return (dif_var->dtdv_type.dtdt_kind);

	if (dif_var->dtdv_type.dtdt_kind == DIF_TYPE_STRING && dr->isNull)
		return (DIF_TYPE_STRING);

	if (dt_typecheck_stringiv(dtp, dr, dif_var)) {
		dif_var->dtdv_type.dtdt_kind = DIF_TYPE_STRING;
		return (DIF_TYPE_STRING);
	}

	if (dif_var->dtdv_type.dtdt_kind != DIF_TYPE_NONE &&
	    dif_var->dtdv_type.dtdt_kind != dr->dType) {
		char b1[32] = "", b2[32] = "";
		if (dr->dType == DIF_TYPE_CTF) {
			if (dr->tf->getTypename(dr->ctfid, buf, sizeof(buf)) !=
			    ((char *)buf))
				dt_set_progerr(dtp, pgp,
				    "inferVar(): failed at getting "
				    "type name %ld: %s\n",
				    dr->ctfid, dr->tf->getErrMsg());
			sprintf(b2, "@%ld", dr->ctfid);
		} else if (dr->dType == DIF_TYPE_STRING)
			strcpy(buf, "D string");
		else if (dr->dType == DIF_TYPE_NONE)
			strcpy(buf, "none");
		else if (dr->dType == DIF_TYPE_BOTTOM)
			strcpy(buf, "bottom");
		else
			strcpy(buf, "unknown");

		if (dif_var->dtdv_type.dtdt_kind == DIF_TYPE_CTF) {
			if (v2tf(dif_var->dtdv_tf)
				->getTypename(dif_var->dtdv_ctfid, var_type,
				    sizeof(var_type)) != ((char *)var_type))
				dt_set_progerr(dtp, pgp,
				    "inferVar(): failed at getting "
				    "type name %ld: %s\n",
				    dif_var->dtdv_ctfid,
				    v2tf(dif_var->dtdv_tf)->getErrMsg());
			sprintf(b1, "@%ld", dif_var->dtdv_ctfid);
		} else if (dif_var->dtdv_type.dtdt_kind == DIF_TYPE_STRING)
			strcpy(var_type, "D string");
		else if (dif_var->dtdv_type.dtdt_kind == DIF_TYPE_NONE)
			strcpy(var_type, "none");
		else if (dif_var->dtdv_type.dtdt_kind == DIF_TYPE_BOTTOM)
			strcpy(var_type, "bottom");
		else
			strcpy(var_type, "unknown");

		fprintf(stderr,
		    "inferVar(): dif_var and dr have different "
		    "types: %s (%d%s) != %s (%d%s)\n",
		    var_type, dif_var->dtdv_type.dtdt_kind, b1, buf, dr->dType,
		    b2);

		return (-1);
	}

	if (dr->dType == DIF_TYPE_NONE || dr->dType == DIF_TYPE_BOTTOM)
		dt_set_progerr(dtp, pgp, "inferVar(): unexpected type %d\n",
		    dr->dType);

	if (dif_var->dtdv_type.dtdt_kind == DIF_TYPE_STRING)
		return (DIF_TYPE_STRING);

	if (dif_var->dtdv_ctfid != CTF_ERR) {
		if (v2tf(dif_var->dtdv_tf)
			->getTypename(dif_var->dtdv_ctfid, var_type,
			    sizeof(var_type)) != ((char *)var_type))
			dt_set_progerr(dtp, pgp,
			    "inferVar(): failed at getting "
			    "type name %ld: %s\n",
			    dif_var->dtdv_ctfid,
			    v2tf(dif_var->dtdv_tf)->getErrMsg());

		if (dr->tf->getTypename(dr->ctfid, buf, sizeof(buf)) !=
		    ((char *)buf))
			dt_set_progerr(dtp, pgp,
			    "inferVar(): failed at getting "
			    "type name %ld: %s\n",
			    dr->ctfid, dr->tf->getErrMsg());

		rv = getSubtypeRelation(v2tf(dif_var->dtdv_tf),
		    dif_var->dtdv_ctfid, dr->tf, dr->ctfid, which);

		if (rv != 0) {
			fprintf(stderr,
			    "inferVar(): type mismatch "
			    "in variable store: %s != %s\n",
			    var_type, buf);

			return (-1);
		}

		if (which & SUBTYPE_FST) {
			dif_var->dtdv_tf = dr->tf;
			dif_var->dtdv_ctfid = dr->ctfid;
			dif_var->dtdv_sym = dr->sym;
			dif_var->dtdv_type.dtdt_kind = dr->dType;
			dif_var->dtdv_type.dtdt_size = dr->tf->getSize(
			    dr->ctfid);
			dif_var->dtdv_type.dtdt_ckind = dr->ctfid;
		}

		if (dif_var->dtdv_sym != nullptr) {
			if (dr->sym &&
			    strcmp(dif_var->dtdv_sym, dr->sym) != 0) {
				fprintf(stderr,
				    "inferVar(): symbol name "
				    "mismatch: %s != %s\n",
				    dif_var->dtdv_sym, dr->sym);

				return (-1);
			} else if (dr->sym == nullptr) {
				fprintf(stderr, "inferVar(): sym is nullptr\n");
				return (-1);
			}
		}
	} else {
		dif_var->dtdv_tf = dr->tf;
		dif_var->dtdv_ctfid = dr->ctfid;
		dif_var->dtdv_sym = dr->sym;
		dif_var->dtdv_type.dtdt_kind = dr->dType;
		dif_var->dtdv_type.dtdt_size = dr->tf->getSize(dr->ctfid);
		dif_var->dtdv_type.dtdt_ckind = dr->ctfid;
	}

	return (DIF_TYPE_CTF);
}

/*
 * dt_typecheck_vardefs() ensures that all existing variable definitions are
 * are consistent in their types inside the DIFO (defs list) and across DIFOs
 * which is done using the var_list.
 */
DFGNode *
TypeInference::checkVarDefs(DFGNode *n, dtrace_difo_t *difo, NodeSet &defs,
    bool &empty)
{
	DFGNode *node, *onode;
	char buf1[4096] = { 0 }, buf2[4096] = { 0 };
	int type, otype;
	dtrace_difv_t *var;
	uint16_t varid;
	int scope, kind;
	dif_instr_t instr;

	type = otype = DIF_TYPE_NONE;
	node = onode = nullptr;
	var = nullptr;
	varid = 0;
	scope = kind = 0;
	instr = 0;
	empty = defs.size() > 0;

	/*
	 * We iterate over all the variable definitions for a particular
	 * node that is created through a variable load instruction.
	 * We make sure that:
	 *  (1) All definitions agree on the type of the variable
	 *  (2) All definitions conform to the previously inferred variable
	 *      type from a different DIFO (if it exists).
	 */
	for (auto it = defs.begin(); it != defs.end(); ++it) {
		onode = node;
		node = *it;

		/*
		 * For r0node, we don't actually have check anything because
		 * by definition, the register r0 is always of type bottom,
		 * allowing us to construct any type we find convenient.
		 */
		otype = type;
		type = inferNode(node);

		/*
		 * We failed to infer the type to begin with, bail out.
		 */
		if (type == -1) {
			return (nullptr);
		}

		/*
		 * The type at the previous definition does not match the type
		 * inferred in the current one, which is nonsense.
		 */
		if (onode && otype != type) {
			fprintf(stderr,
			    "%s(%p[%zu]): otype and type mismatch (%d, %d)\n",
			    __func__, (void *)n->difo, n->uidx, otype, type);
			return (nullptr);
		}

		instr = node->getInstruction();
		getVariableInfo(instr, &varid, &scope, &kind);
		if (varid == 0 && scope == -1 && kind == -1)
			dt_set_progerr(dtp, pgp,
			    "%s(%p[%zu]): failed to get variable information",
			    __func__, (void *)n->difo, n->uidx);

		/*
		 * We get the variable from the variable list.
		 *
		 * N.B.: This is not the variable table that is in the DIFO,
		 *       it is rather a separate variable table that we use
		 *       to keep track of types for each variable _across_
		 *       DIFOs.
		 */
		var = linkerContext.getVarFromVarVec(varid, scope, kind);
		if (var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "%s(%p[%zu]): could not find variable "
			    "(%u, %d, %d) in varlist",
			    __func__, (void *)n->difo, n->uidx, varid, scope,
			    kind);

		/* If the type we are comparing to is bottom, skip. */
		if (type == DIF_TYPE_BOTTOM)
			continue;

		/*
		 * The previously inferred variable type must match the
		 * current type we inferred.
		 */
		if (var->dtdv_type.dtdt_kind != type) {
			char t1[DT_TYPE_NAMELEN] = { 0 };
			char t2[DT_TYPE_NAMELEN] = { 0 };

			if (type == DIF_TYPE_CTF) {
				if (node->tf->getTypename(node->ctfid, t1,
					sizeof(t1)) != ((char *)t1))
					dt_set_progerr(dtp, pgp,
					    "%s(%p[%zu]): failed at getting "
					    "type name %ld: %s\n",
					    __func__, (void *)n->difo, n->uidx,
					    node->ctfid, node->tf->getErrMsg());
				sprintf(t1, "@%ld", node->ctfid);
			} else if (type == DIF_TYPE_STRING)
				strcpy(t1, "D string");
			else if (type == DIF_TYPE_NONE)
				strcpy(t1, "none");
			else if (type == DIF_TYPE_BOTTOM)
				strcpy(t1, "bottom");
			else
				strcpy(t1, "unknown");

			if (var->dtdv_type.dtdt_kind == DIF_TYPE_CTF) {
				if (v2tf(var->dtdv_tf)
					->getTypename(var->dtdv_ctfid, t2,
					    sizeof(t2)) != ((char *)t2))
					dt_set_progerr(dtp, pgp,
					    "%s(%p[%zu]): failed at getting "
					    "type name %ld: %s\n",
					    __func__, (void *)n->difo, n->uidx,
					    var->dtdv_ctfid,
					    v2tf(var->dtdv_tf)->getErrMsg());
				sprintf(t2, "@%ld", var->dtdv_ctfid);
			} else if (var->dtdv_type.dtdt_kind == DIF_TYPE_STRING)
				strcpy(t2, "D string");
			else if (var->dtdv_type.dtdt_kind == DIF_TYPE_NONE)
				strcpy(t2, "none");
			else if (var->dtdv_type.dtdt_kind == DIF_TYPE_BOTTOM)
				strcpy(t2, "bottom");
			else
				strcpy(t2, "unknown");

			fprintf(stderr, "%s(%p[%zu]): %s != %s\n", __func__,
			    (void *)n->difo, n->uidx, t1, t2);
			return (nullptr);
		}

		if (type == DIF_TYPE_CTF) {
			/*
			 * We only allow for comparison within the typefile.
			 */
			if (node->tf != var->dtdv_tf) {
				fprintf(stderr,
				    "%s(%p[%zu]): comparing node with typefile "
				    "%s to variable with typefile %s",
				    __func__, (void *)n->difo, n->uidx,
				    node->tf->name().c_str(),
				    v2tf(var->dtdv_tf)->name().c_str());
				return (nullptr);
			}
			/*
			 * We get the type name for reporting purposes.
			 */
			if (node->tf->getTypename(node->ctfid, buf1,
				sizeof(buf1)) != ((char *)buf1))
				dt_set_progerr(dtp, pgp,
				    "%s(%p[%zu]): failed at getting "
				    "type name %ld: %s",
				    __func__, (void *)n->difo, n->uidx,
				    node->ctfid, node->tf->getErrMsg());

			/*
			 * If the variable already has a type assigned to it,
			 * but it is not the same type that we just inferred
			 * it to be, we get the type name of the variable and
			 * report an error.
			 */
			if (var->dtdv_ctfid != -1 &&
			    node->ctfid != var->dtdv_ctfid) {
				if (var->dtdv_name >= difo->dtdo_strlen)
					dt_set_progerr(dtp, pgp,
					    "%s(%p[%zu]): variable "
					    "name outside strtab (%zu, %zu)",
					    __func__, (void *)n->difo, n->uidx,
					    var->dtdv_name, difo->dtdo_strlen);

				if (v2tf(var->dtdv_tf)
					->getTypename(var->dtdv_ctfid, buf2,
					    sizeof(buf2)) != ((char *)buf2))
					dt_set_progerr(dtp, pgp,
					    "%s(%p[%zu]): failed at "
					    "getting type name %ld: %s",
					    __func__, (void *)n->difo, n->uidx,
					    var->dtdv_ctfid,
					    v2tf(var->dtdv_tf)->getErrMsg());

				fprintf(stderr,
				    "%s(%p[%zu]): variable (%s) type and "
				    "inferred type mismatch: %s, %s",
				    __func__, (void *)n->difo, n->uidx,
				    difo->dtdo_strtab + var->dtdv_name, buf1,
				    buf2);
				return (nullptr);
			}

			/*
			 * If we are at the first definition, or only have one
			 * definition, we don't need to check the types.
			 */
			if (onode == nullptr)
				continue;

			/*
			 * Get the previous' node's inferred type for
			 * error reporting.
			 */
			if (onode->tf->getTypename(onode->ctfid, buf2,
				sizeof(buf2)) != ((char *)buf2))
				dt_set_progerr(dtp, pgp,
				    "%s(%p[%zu]): failed at getting "
				    "type name %ld: %s",
				    onode->ctfid, onode->tf->getErrMsg());

			/*
			 * Only compare within the typefile
			 */
			if (node->tf != onode->tf) {
				fprintf(stderr,
				    "%s(%p[%zu]): node has typefile "
				    "%s but typefile %s is expected\n",
				    __func__, (void *)n->difo, n->uidx,
				    node->tf->name().c_str(),
				    onode->tf->name().c_str());
				return (nullptr);
			}

			/*
			 * Fail to typecheck if the types don't match 100%.
			 */
			if (node->ctfid != onode->ctfid) {
				fprintf(stderr,
				    "%s(%p[%zu]): types %s and "
				    "%s do not match\n",
				    __func__, (void *)n->difo, n->uidx, buf1,
				    buf2);
				return (nullptr);
			}

			if ((node->sym == nullptr && onode->sym != nullptr) ||
			    (node->sym != nullptr && onode->sym == nullptr)) {
				fprintf(stderr,
				    "%s(%p[%zu]): node or onode "
				    "is missing a symbol\n",
				    __func__, (void *)n->difo, n->uidx);
				return (nullptr);
			}

			if ((node->sym == nullptr &&
				var->dtdv_sym != nullptr) ||
			    (node->sym != nullptr &&
				var->dtdv_sym == nullptr)) {
				fprintf(stderr,
				    "%s(%p[%zu]): node or dif_var "
				    "is missing a symbol\n",
				    __func__, (void *)n->difo, n->uidx);
				return (nullptr);
			}

			/*
			 * We don't have to check anything except for
			 * node->sym being not nullptr
			 */
			if (node->sym && strcmp(node->sym, onode->sym) != 0) {
				fprintf(stderr,
				    "%s(%p[%zu]): nodes have "
				    "different symbols: %s != %s\n",
				    __func__, (void *)n->difo, n->uidx,
				    node->sym, onode->sym);
				return (nullptr);
			}

			if (node->sym &&
			    strcmp(node->sym, var->dtdv_sym) != 0) {
				fprintf(stderr,
				    "%s(%p[%zu]): node and var "
				    "have different symbols: %s != %s\n",
				    __func__, (void *)n->difo, n->uidx,
				    node->sym, onode->sym);
				return (nullptr);
			}
		}
	}

	return (node);
}

}
