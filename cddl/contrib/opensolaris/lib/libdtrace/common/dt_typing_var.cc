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
/*
 * Type `n' as `type' from the type file `tf'.
 */
int
TypeInference::setTypeFrom(DFGNode *n, Typefile *tf, const char *type)
{
	n->tf = tf;
	n->ctfid = tf->getCtfID(type);
	if (n->ctfid == CTF_ERR)
		return (progErr("failed to get type %s: %s", type,
		    tf->getErrMsg()));
	n->dType = DIF_TYPE_CTF;
	return (0);
}

/*
 * setBuiltinType() takes a node and a builtin variable, returning
 * the expected type of said builtin variable.
 */
int
TypeInference::setBuiltinType(DFGNode *n, uint16_t var, uint8_t idx)
{
	dtrace_probedesc_t *pdesc;
	int check_types;

	/*
	 * Where each builtin's type comes from: the D definitions, the kernel
	 * (nullptr: struct thread *, from thread_str), or a D string.
	 */
	enum Source { D, KERNEL, STRING };
	struct Builtin {
		Source src;
		const char *type;
	};
	static const UMap<uint16_t, Builtin> builtins = {
		{ DIF_VAR_CURTHREAD, { KERNEL, nullptr } },
		{ DIF_VAR_HCURTHREAD, { KERNEL, nullptr } },
		{ DIF_VAR_HUCALLER, { D, "uint64_t" } },
		{ DIF_VAR_UCALLER, { D, "uint64_t" } },
		{ DIF_VAR_TIMESTAMP, { D, "uint64_t" } },
		{ DIF_VAR_VTIMESTAMP, { D, "uint64_t" } },
		{ DIF_VAR_HTIMESTAMP, { D, "uint64_t" } },
		{ DIF_VAR_HVTIMESTAMP, { D, "uint64_t" } },
		{ DIF_VAR_IPL, { D, "uint_t" } },
		{ DIF_VAR_HIPL, { D, "uint_t" } },
		{ DIF_VAR_HEPID, { D, "uint_t" } },
		{ DIF_VAR_EPID, { D, "uint_t" } },
		{ DIF_VAR_ID, { D, "uint_t" } },
		{ DIF_VAR_HPRID, { D, "uint_t" } },
		{ DIF_VAR_ARG0, { D, "int64_t" } },
		{ DIF_VAR_ARG1, { D, "int64_t" } },
		{ DIF_VAR_ARG2, { D, "int64_t" } },
		{ DIF_VAR_ARG3, { D, "int64_t" } },
		{ DIF_VAR_ARG4, { D, "int64_t" } },
		{ DIF_VAR_ARG5, { D, "int64_t" } },
		{ DIF_VAR_ARG6, { D, "int64_t" } },
		{ DIF_VAR_ARG7, { D, "int64_t" } },
		{ DIF_VAR_ARG8, { D, "int64_t" } },
		{ DIF_VAR_ARG9, { D, "int64_t" } },
		{ DIF_VAR_HARG0, { D, "int64_t" } },
		{ DIF_VAR_HARG1, { D, "int64_t" } },
		{ DIF_VAR_HARG2, { D, "int64_t" } },
		{ DIF_VAR_HARG3, { D, "int64_t" } },
		{ DIF_VAR_HARG4, { D, "int64_t" } },
		{ DIF_VAR_HARG5, { D, "int64_t" } },
		{ DIF_VAR_HARG6, { D, "int64_t" } },
		{ DIF_VAR_HARG7, { D, "int64_t" } },
		{ DIF_VAR_HARG8, { D, "int64_t" } },
		{ DIF_VAR_HARG9, { D, "int64_t" } },
		{ DIF_VAR_UREGS, { D, "uintptr_t" } },
		{ DIF_VAR_REGS, { D, "uintptr_t" } },
		{ DIF_VAR_WALLTIMESTAMP, { D, "int64_t" } },
		{ DIF_VAR_HWALLTIMESTAMP, { D, "int64_t" } },
		{ DIF_VAR_STACKDEPTH, { D, "uint32_t" } },
		{ DIF_VAR_USTACKDEPTH, { D, "uint32_t" } },
		{ DIF_VAR_HSTACKDEPTH, { D, "uint32_t" } },
		{ DIF_VAR_HUSTACKDEPTH, { D, "uint32_t" } },
		{ DIF_VAR_CALLER, { D, "uintptr_t" } },
		{ DIF_VAR_HCALLER, { D, "uintptr_t" } },
		{ DIF_VAR_PROBEPROV, { STRING, nullptr } },
		{ DIF_VAR_PROBEMOD, { STRING, nullptr } },
		{ DIF_VAR_PROBEFUNC, { STRING, nullptr } },
		{ DIF_VAR_PROBENAME, { STRING, nullptr } },
		{ DIF_VAR_HPROBEPROV, { STRING, nullptr } },
		{ DIF_VAR_HPROBEMOD, { STRING, nullptr } },
		{ DIF_VAR_HPROBEFUNC, { STRING, nullptr } },
		{ DIF_VAR_HPROBENAME, { STRING, nullptr } },
		{ DIF_VAR_EXECNAME, { STRING, nullptr } },
		{ DIF_VAR_ZONENAME, { STRING, nullptr } },
		{ DIF_VAR_HEXECNAME, { STRING, nullptr } },
		{ DIF_VAR_HZONENAME, { STRING, nullptr } },
		{ DIF_VAR_JAILNAME, { STRING, nullptr } },
		{ DIF_VAR_HJAILNAME, { STRING, nullptr } },
		{ DIF_VAR_VMNAME, { STRING, nullptr } },
		{ DIF_VAR_HVMNAME, { STRING, nullptr } },
		{ DIF_VAR_EXECARGS, { STRING, nullptr } },
		{ DIF_VAR_HEXECARGS, { STRING, nullptr } },
		{ DIF_VAR_HPID, { KERNEL, "pid_t" } },
		{ DIF_VAR_PID, { KERNEL, "pid_t" } },
		{ DIF_VAR_PPID, { KERNEL, "pid_t" } },
		{ DIF_VAR_HPPID, { KERNEL, "pid_t" } },
		{ DIF_VAR_HTID, { D, "id_t" } },
		{ DIF_VAR_TID, { D, "id_t" } },
		{ DIF_VAR_UID, { KERNEL, "uid_t" } },
		{ DIF_VAR_HUID, { KERNEL, "uid_t" } },
		{ DIF_VAR_GID, { KERNEL, "gid_t" } },
		{ DIF_VAR_HGID, { KERNEL, "gid_t" } },
		{ DIF_VAR_HCPU, { D, "int" } },
		{ DIF_VAR_CPU, { D, "int" } },
		{ DIF_VAR_HERRNO, { D, "int" } },
		{ DIF_VAR_ERRNO, { D, "int" } },
		{ DIF_VAR_HJID, { D, "int" } },
		{ DIF_VAR_JID, { D, "int" } },
		{ DIF_VAR_HHOSTID, { KERNEL, "hostid_t" } },
		{ DIF_VAR_HOSTID, { KERNEL, "hostid_t" } },
	};

	/* Builtins with kernel types need the kernel's type information. */
	auto kernelTypes = [&](uint16_t v) -> Typefile * {
		Typefile *ktf = dt_typefile_kernel();
		if (ktf == nullptr)
			progErr("variable %x: kernel type "
			    "information is unavailable", v);
		return (ktf);
	};

	if (var != DIF_VAR_ARGS) {
		auto it = builtins.find(var);
		if (it == builtins.end()) {
			return (progErr("variable %x does not exist", var));
		}

		const Builtin &b = it->second;
		if (b.src == STRING) {
			n->dType = DIF_TYPE_STRING;
			return (0);
		}

		Typefile *tf = b.src == D ? dt_typefile_D() : kernelTypes(var);
		if (tf == nullptr)
			return (-1);
		return (setTypeFrom(n, tf, b.type != nullptr ? b.type :
		    t_thread.c_str()));
	}

	/*
	 * args[]: the ERROR probe's arguments are fixed (dtrace.c); the
	 * dtrace provider's other probes have none; any other probe's are
	 * looked up, unless the value is only returned or cast.
	 */
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
		static const char *arg_type[6] = { "", "uint32_t", "uint32_t",
			"int", "uint32_t", "uintptr_t" };

		if (idx == 0 || idx > 5)
			return (progErr(
			    "accessing arg%d in the ERROR probe is not supported",
			    idx));

		Typefile *tf = kernelTypes(var);
		return (tf == nullptr ? -1 : setTypeFrom(n, tf, arg_type[idx]));
	} else if (strcmp(pdesc->dtpd_provider, "dtrace") == 0) {
		return (progErr(
		    "accessing arg%d in %s probe is not supported", idx,
		    pdesc->dtpd_name));
	} else {
		argcheck_cookie cookie(n, var, idx, this);
		check_types = 0;
		for (auto children : { &n->r1Children, &n->r2Children }) {
			for (auto child : *children) {
				uint8_t child_op = DIF_INSTR_OP(
				    child->getInstruction());

				if (child_op != DIF_OP_RET &&
				    child_op != DIF_OP_TYPECAST)
					check_types = 1;
			}
		}

		/* A probe whose argument cannot be typed leaves the node
		 * untyped (-1), which inferNode() reports. */
		if (check_types == 1) {
			(void)dtrace_probe_iter(dtp, &n->edp->dted_probe,
			    dt_infer_type_arg, &cookie);
			return (0);
		}

		Typefile *tf = kernelTypes(var);
		return (tf == nullptr ? -1 : setTypeFrom(n, tf, "uint64_t"));
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
	ad.dtargd_ndx = idx; /* the kernel checks the index */

	ad.dtargd_id = pdp->dtpd_id;
	assert(ad.dtargd_id != DTRACE_IDNONE);

	/*
	 * Profile probes (profile-N, tick-N) describe no argument types; their
	 * arguments are 64-bit program counters.  Other providers' probes
	 * may well be named "tick" (e.g. sched:::tick) and are asked.
	 */
	is_profile_probe = strcmp(pdp->dtpd_provider, "profile") == 0;

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
		    tf ? tf->name().c_str() : mod);
		return (1);
	}

	/* A probe argument always has a CTF type. */
	type = DIF_TYPE_CTF;

	if (n->dType == DIF_TYPE_BOTTOM || n->dType == DIF_TYPE_NONE ||
	    n->dType == -1) {
		n->dType = type;
		n->tf = tf;
		n->ctfid = ctfid;
		return (0);
	}

	/*
	 * Probes matching the description may declare the argument with
	 * different types: keep the larger of two related ones (a successful
	 * getSubtypeRelation() names exactly one relation).
	 */
	if (n->dType == DIF_TYPE_CTF) {
		if (n->tf == tf && ctfid == n->ctfid)
			return (0);

		if (ti->getSubtypeRelation(n->tf, n->ctfid, tf, ctfid, which) ==
		    0) {
			if (which & SUBTYPE_SND) {
				n->tf = tf;
				n->ctfid = ctfid;
				n->dType = type;
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
 * The type a store of `dr' gives the variable.  A variable the compiler
 * keeps by reference (a struct or union value) is stored from the address
 * of the value the store copies (`this->s = *(struct s *)p' stores a
 * struct s *), so it takes the pointer's target; otherwise dr's type.
 */
ctf_id_t
TypeInference::byRefStoredType(DFGNode *dr, dtrace_difv_t *dif_var)
{
	if (dr->dType != DIF_TYPE_CTF || dr->tf == nullptr ||
	    (dif_var->dtdv_type.dtdt_flags & (DIF_TF_BYREF | DIF_TF_BYUREF)) ==
	    0)
		return (dr->ctfid);
	ctf_id_t ptr = dr->tf->resolve(dr->ctfid);
	if ((int)dr->tf->getKind(ptr) != CTF_K_POINTER)
		return (dr->ctfid);
	ctf_id_t target = dr->tf->getReference(ptr);
	int tkind = (int)dr->tf->getKind(dr->tf->resolve(target));
	return (tkind == CTF_K_STRUCT || tkind == CTF_K_UNION ? target :
	    dr->ctfid);
}

/*
 * The type a pointer value points at: for the address of a member
 * (`t | sym'), the member's type; for a pointer, its target.  False for
 * anything else.
 */
static bool
pointedType(Typefile *tf, ctf_id_t id, const char *sym, ctf_file_t **fp,
    ctf_id_t *target)
{
	if (tf == nullptr || id == CTF_ERR)
		return (false);
	ctf_id_t r = tf->resolve(id);
	bool ptr = (int)tf->getKind(r) == CTF_K_POINTER;
	if (sym == nullptr) {
		if (!ptr)
			return (false);
		*fp = tf->getCtfPointer();
		*target = tf->getReference(r);
		return (*target != CTF_ERR);
	}
	ctf_id_t s = ptr ? tf->resolve(tf->getReference(r)) : r;
	ctf_membinfo_t mi;
	/* The member may be found in the definition of a forward
	 * declaration, in another container. */
	if ((*fp = tf->getMembInfo(s, sym, &mi)) == nullptr)
		return (false);
	*target = mi.ctm_type;
	return (true);
}

/*
 * Whether two pointer values (each possibly a member address) point at
 * compatible types (libctf's compatibility of the resolved targets).
 */
bool
TypeInference::sameTarget(Typefile *tf1, ctf_id_t id1, const char *sym1,
    Typefile *tf2, ctf_id_t id2, const char *sym2)
{
	ctf_file_t *fp1, *fp2;
	ctf_id_t t1, t2;
	if (!pointedType(tf1, id1, sym1, &fp1, &t1) ||
	    !pointedType(tf2, id2, sym2, &fp2, &t2))
		return (false);
	return (ctf_type_compat(fp1, ctf_type_resolve(fp1, t1), fp2,
	    ctf_type_resolve(fp2, t2)) != 0);
}

/*
 * Whether two CTF values have the same type: the same type id of the same
 * type file, or -- when either is a member address (`t | sym') -- pointers
 * at compatible types (sameTarget()).
 */
bool
TypeInference::sameValueType(Typefile *tf1, ctf_id_t id1, const char *sym1,
    Typefile *tf2, ctf_id_t id2, const char *sym2)
{
	if (sym1 == nullptr && sym2 == nullptr)
		return (tf1 == tf2 && id1 == id2);
	if (sym1 != nullptr && sym2 != nullptr && tf1 == tf2 && id1 == id2 &&
	    strcmp(sym1, sym2) == 0)
		return (true);
	return (sameTarget(tf1, id1, sym1, tf2, id2, sym2));
}

/*
 * inferVar() figures out the type of a variable in the varlist and
 * typechecks it against dr.
 */
int
TypeInference::inferVar(DFGNode *dr, dtrace_difv_t *dif_var)
{
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

	/*
	 * A variable without a type yet (bottom, or none) takes the stored
	 * value's type.
	 */
	if (dif_var->dtdv_type.dtdt_kind == DIF_TYPE_BOTTOM ||
	    dif_var->dtdv_type.dtdt_kind == DIF_TYPE_NONE) {
		ctf_id_t stored = byRefStoredType(dr, dif_var);
		dif_var->dtdv_tf = dr->tf;
		dif_var->dtdv_ctfid = stored;
		dif_var->dtdv_sym = dr->sym;
		dif_var->dtdv_type.dtdt_kind = dr->dType;
		if (dr->dType == DIF_TYPE_CTF)
			dif_var->dtdv_type.dtdt_size = dr->tf->getSize(stored);
		dif_var->dtdv_type.dtdt_ckind = dt_diftype_ckind(
		    dr->dType, dr->tf, stored);

		return (dr->dType);
	}

	if (dr->dType == DIF_TYPE_BOTTOM)
		return (dif_var->dtdv_type.dtdt_kind);

	if (dif_var->dtdv_type.dtdt_kind == DIF_TYPE_STRING && dr->isNull)
		return (DIF_TYPE_STRING);

	if (dt_typecheck_stringiv(dtp, dr, dif_var)) {
		dif_var->dtdv_type.dtdt_kind = DIF_TYPE_STRING;
		dif_var->dtdv_type.dtdt_ckind = CTF_K_UNKNOWN;
		return (DIF_TYPE_STRING);
	}

	if (dif_var->dtdv_type.dtdt_kind != dr->dType) {
		fprintf(stderr,
		    "inferVar(): dif_var and dr have different "
		    "types: %s (%d) != %s (%d)\n",
		    dt_type_diagname(dif_var->dtdv_type.dtdt_kind,
			v2tf(dif_var->dtdv_tf), dif_var->dtdv_ctfid, true)
			.c_str(),
		    dif_var->dtdv_type.dtdt_kind,
		    dt_type_diagname(dr->dType, dr->tf, dr->ctfid, true).c_str(),
		    dr->dType);

		return (-1);
	}

	/*
	 * Both are CTF types now: two D strings were accepted by
	 * dt_typecheck_stringiv() above, and bottom values returned early.
	 */
	if (dif_var->dtdv_ctfid != CTF_ERR) {
		/*
		 * A struct or union variable is stored by reference: the
		 * register holds the address of the value the store copies
		 * (`this->s = *(struct s *)p' stores a struct s *), so the
		 * pointer's target is what must agree with the variable.
		 */
		ctf_id_t stored = byRefStoredType(dr, dif_var);
		Typefile *vtf = v2tf(dif_var->dtdv_tf);

		/*
		 * The address of a member is kept as the structure pointer
		 * and the member's name (`t | sym': &curthread->td_tid is
		 * struct thread * | td_tid).  Such a value and a plain
		 * pointer, or the address of another member, are the same
		 * kind of value when they point at the same type (C:
		 * `p = &curthread->td_tid; p = (lwpid_t *)arg0;').
		 */
		if ((dif_var->dtdv_sym != nullptr || dr->sym != nullptr) &&
		    sameTarget(vtf, dif_var->dtdv_ctfid, dif_var->dtdv_sym,
		    dr->tf, dr->ctfid, dr->sym))
			return (DIF_TYPE_CTF);

		rv = getSubtypeRelation(vtf, dif_var->dtdv_ctfid, dr->tf,
		    stored, which);

		if (rv != 0) {
			fprintf(stderr,
			    "inferVar(): type mismatch "
			    "in variable store: %s != %s\n",
			    dt_type_diagname(DIF_TYPE_CTF, v2tf(dif_var->dtdv_tf),
				dif_var->dtdv_ctfid, false).c_str(),
			    dt_type_diagname(DIF_TYPE_CTF, dr->tf, dr->ctfid, false)
				.c_str());

			return (-1);
		}

		/*
		 * A member address that does not point at the same type as
		 * the other value (same-target pairs returned above) is a
		 * different type, whatever its structure pointer: C rejects
		 * `p = curthread; p = &curthread->td_tid;'.
		 */
		if (dif_var->dtdv_sym != nullptr || dr->sym != nullptr) {
			fprintf(stderr, "inferVar(): %s%s%s and %s%s%s point at "
			    "different types\n",
			    dt_type_diagname(DIF_TYPE_CTF, vtf,
				dif_var->dtdv_ctfid, false).c_str(),
			    dif_var->dtdv_sym ? " | " : "",
			    dif_var->dtdv_sym ? dif_var->dtdv_sym : "",
			    dt_type_diagname(DIF_TYPE_CTF, dr->tf, dr->ctfid,
				false).c_str(),
			    dr->sym ? " | " : "", dr->sym ? dr->sym : "");
			return (-1);
		}

		if (which & SUBTYPE_FST) {
			dif_var->dtdv_tf = dr->tf;
			dif_var->dtdv_ctfid = stored;
			dif_var->dtdv_sym = dr->sym;
			dif_var->dtdv_type.dtdt_kind = dr->dType;
			dif_var->dtdv_type.dtdt_size = dr->tf->getSize(stored);
			dif_var->dtdv_type.dtdt_ckind = dt_diftype_ckind(
			    dr->dType, dr->tf, stored);
		}
	} else {
		dif_var->dtdv_tf = dr->tf;
		dif_var->dtdv_ctfid = dr->ctfid;
		dif_var->dtdv_sym = dr->sym;
		dif_var->dtdv_type.dtdt_kind = dr->dType;
		dif_var->dtdv_type.dtdt_size = dr->tf->getSize(dr->ctfid);
		dif_var->dtdv_type.dtdt_ckind = dt_diftype_ckind(
		    dr->dType, dr->tf, dr->ctfid);
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
		/* A variable's definition is a store to it. */
		if (getVariableInfo(instr, &varid, &scope, &kind) !=
		    DT_VARINFO_STORE)
			return (progErr(
			    "%s(%p[%zu]): failed to get variable information",
			    __func__, (void *)n->difo, n->uidx), nullptr);

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
			return (progErr(
			    "%s(%p[%zu]): could not find variable "
			    "(%u, %d, %d) in varlist",
			    __func__, (void *)n->difo, n->uidx, varid, scope,
			    kind), nullptr);

		/* If the type we are comparing to is bottom, skip. */
		if (type == DIF_TYPE_BOTTOM)
			continue;

		/*
		 * The previously inferred variable type must match the
		 * current type we inferred.
		 */
		if (var->dtdv_type.dtdt_kind != type) {
			fprintf(stderr, "%s(%p[%zu]): %s != %s\n", __func__,
			    (void *)n->difo, n->uidx,
			    dt_type_diagname(type, node->tf, node->ctfid, true)
				.c_str(),
			    dt_type_diagname(var->dtdv_type.dtdt_kind,
				v2tf(var->dtdv_tf), var->dtdv_ctfid, true)
				.c_str());
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
				return (progErr(
				    "%s(%p[%zu]): failed at getting "
				    "type name %ld: %s",
				    __func__, (void *)n->difo, n->uidx,
				    node->ctfid, node->tf->getErrMsg()), nullptr);

			/*
			 * If the variable already has a type assigned to it,
			 * but it is not the same type that we just inferred
			 * it to be, we get the type name of the variable and
			 * report an error.
			 */
			if (var->dtdv_ctfid != -1 &&
			    !sameValueType(node->tf, node->ctfid, node->sym,
			    v2tf(var->dtdv_tf), var->dtdv_ctfid,
			    var->dtdv_sym)) {
				if (var->dtdv_name >= difo->dtdo_strlen)
					return (progErr(
					    "%s(%p[%zu]): variable "
					    "name outside strtab (%u, %u)",
					    __func__, (void *)n->difo, n->uidx,
					    var->dtdv_name, difo->dtdo_strlen), nullptr);

				if (v2tf(var->dtdv_tf)
					->getTypename(var->dtdv_ctfid, buf2,
					    sizeof(buf2)) != ((char *)buf2))
					return (progErr(
					    "%s(%p[%zu]): failed at "
					    "getting type name %ld: %s",
					    __func__, (void *)n->difo, n->uidx,
					    var->dtdv_ctfid,
					    v2tf(var->dtdv_tf)->getErrMsg()), nullptr);

				fprintf(stderr,
				    "%s(%p[%zu]): variable (%s) type and "
				    "inferred type mismatch: %s%s%s, %s%s%s\n",
				    __func__, (void *)n->difo, n->uidx,
				    difo->dtdo_strtab + var->dtdv_name, buf1,
				    node->sym ? " | " : "",
				    node->sym ? node->sym : "", buf2,
				    var->dtdv_sym ? " | " : "",
				    var->dtdv_sym ? var->dtdv_sym : "");
				return (nullptr);
			}

			/*
			 * If we are at the first definition, or only have one
			 * definition, we don't need to check the types.
			 */
			if (onode == nullptr)
				continue;

			/*
			 * Both definitions have the variable's type file
			 * (checked above for each of them).
			 */
			/*
			 * Fail to typecheck if the types don't match 100%
			 * (member addresses: if they point at the same type).
			 */
			if (!sameValueType(node->tf, node->ctfid, node->sym,
			    onode->tf, onode->ctfid, onode->sym)) {
				/*
				 * The previous definition's type was named
				 * when it was checked in the previous
				 * iteration; name it again for the report.
				 */
				fprintf(stderr,
				    "%s(%p[%zu]): types %s%s%s and "
				    "%s%s%s do not match\n",
				    __func__, (void *)n->difo, n->uidx, buf1,
				    node->sym ? " | " : "",
				    node->sym ? node->sym : "",
				    onode->tf->getTypename(onode->ctfid)
					.value_or("?").c_str(),
				    onode->sym ? " | " : "",
				    onode->sym ? onode->sym : "");
				return (nullptr);
			}
		}
	}

	return (node);
}

}
