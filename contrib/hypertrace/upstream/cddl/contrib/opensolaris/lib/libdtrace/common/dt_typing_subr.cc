/*-
 * Copyright (c) 2021 Domagoj Stolfa
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
#include <dtrace.h>
#include <err.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

namespace dtrace {
void
TypeInference::argCmpWith(DFGNode *arg, Vec<Typefile *> &tfs,
    const String &type, const String &loc, int subtype_relation)
{
	char buf[1024] = { 0 };
	auto *cloc = loc.c_str();
	Typefile *tf = linkerContext.getTypenameChecked(arg, tfs, buf,
	    sizeof(buf), loc);
	ctf_id_t arg_ctfid = tf->getCtfID(type.c_str());
	if (arg_ctfid == CTF_ERR)
		dt_set_progerr(dtp, pgp, "%s: failed to get type %s: %s", cloc,
		    type.c_str(), tf->getErrMsg());

	ctf_id_t arg_kind = tf->stripTypedef(arg_ctfid);
	assert(arg_kind != CTF_K_TYPEDEF);
	ctf_id_t passed_arg_ctfid = arg->ctfid;
	ctf_id_t passed_arg_kind = arg->tf->stripTypedef(passed_arg_ctfid);
	assert(passed_arg_kind != CTF_K_TYPEDEF);
	String s = String(buf);

	if ((type == "void *" || type == "uintptr_t") &&
	    (s != "void *" && s != "uintptr_t")) {
		/*
		 * Since this is a void * / uintptr_t, any pointer will do, as D
		 * allows us to implicitly cast any pointer to void * /
		 * uintptr_t.
		 */
		if (passed_arg_kind != CTF_K_POINTER &&
		    passed_arg_kind != CTF_K_ARRAY)
			dt_set_progerr(dtp, pgp,
			    "%s: %s (%s) can't be cast to void *", cloc, buf,
			    tf->name().c_str());

		return;
	}

	if (arg_kind != passed_arg_kind)
		dt_set_progerr(dtp, pgp, "%s (argkind): %s (%s) != %s (%s)",
		    cloc, type.c_str(), tf->name().c_str(), buf,
		    arg->tf->name().c_str());

	if (arg_kind == CTF_K_INTEGER) {
		int which = 0;
		auto rv = getSubtypeRelation(arg->tf, arg->ctfid, tf, arg_ctfid,
		    which);
		if (rv != 0 || ((which & subtype_relation) == 0))
			dt_set_progerr(dtp, pgp, "%s: %s (%s) != %s (%s)", cloc,
			    type.c_str(), tf->name().c_str(), buf,
			    arg->tf->name().c_str());
	} else {
		/*
		 * If the argument type is wrong, fail to type check.
		 */
		if (arg->tf->typeIsCompatibleWith(arg->ctfid, tf, arg_ctfid) ==
		    0)
			dt_set_progerr(dtp, pgp, "%s: %s (%s) != %s (%s)", cloc,
			    type.c_str(), tf->name().c_str(), buf,
			    arg->tf->name().c_str());
	}
}

int
TypeInference::inferSubr(DFGNode *n, NodeVec *stack)
{
	DFGNode *arg0, *arg1, *arg2;
	size_t i = 0;

	UMap<uint32_t, String> subr_name = { { DIF_SUBR_RAND, "rand()" },
		{ DIF_SUBR_MUTEX_OWNED, "mutex_owned()" },
		{ DIF_SUBR_MUTEX_OWNER, "mutex_owner()" },
		{ DIF_SUBR_MUTEX_TYPE_ADAPTIVE, "mutex_type_adaptive()" },
		{ DIF_SUBR_MUTEX_TYPE_SPIN, "mutex_type_spin()" },
		{ DIF_SUBR_RW_READ_HELD, "rw_read_held()" },
		{ DIF_SUBR_RW_WRITE_HELD, "rw_write_held()" },
		{ DIF_SUBR_RW_ISWRITER, "rw_iswriter()" },
		{ DIF_SUBR_COPYIN, "copyin()" },
		{ DIF_SUBR_COPYINSTR, "copyinstr()" },
		{ DIF_SUBR_SPECULATION, "speculation()" },
		{ DIF_SUBR_PROGENYOF, "progenyof()" },
		{ DIF_SUBR_STRLEN, "strlen()" },
		{ DIF_SUBR_COPYOUT, "copyout()" },
		{ DIF_SUBR_COPYOUTSTR, "copyoutstr()" },
		{ DIF_SUBR_ALLOCA, "alloca()" }, { DIF_SUBR_BCOPY, "bcopy()" },
		{ DIF_SUBR_COPYINTO, "copyinto()" },
		{ DIF_SUBR_MSGDSIZE, "msgdsize()" },
		{ DIF_SUBR_MSGSIZE, "msgsize()" },
		{ DIF_SUBR_GETMAJOR, "getmajor()" },
		{ DIF_SUBR_GETMINOR, "getminor()" },
		{ DIF_SUBR_DDI_PATHNAME, "ddi_pathname()" },
		{ DIF_SUBR_STRJOIN, "strjoin()" },
		{ DIF_SUBR_LLTOSTR, "lltostr()" },
		{ DIF_SUBR_BASENAME, "basename()" },
		{ DIF_SUBR_DIRNAME, "dirname()" },
		{ DIF_SUBR_CLEANPATH, "cleanpath()" },
		{ DIF_SUBR_STRCHR, "strchr()" },
		{ DIF_SUBR_STRRCHR, "strrchr()" },
		{ DIF_SUBR_STRSTR, "strstr()" },
		{ DIF_SUBR_STRTOK, "strtok()" },
		{ DIF_SUBR_SUBSTR, "substr()" }, { DIF_SUBR_INDEX, "index()" },
		{ DIF_SUBR_RINDEX, "rindex()" }, { DIF_SUBR_HTONS, "htons()" },
		{ DIF_SUBR_HTONL, "htonl()" }, { DIF_SUBR_HTONLL, "htonll()" },
		{ DIF_SUBR_NTOHS, "ntohs()" }, { DIF_SUBR_NTOHL, "ntohl()" },
		{ DIF_SUBR_NTOHLL, "ntohll()" },
		{ DIF_SUBR_INET_NTOP, "inet_ntop()" },
		{ DIF_SUBR_INET_NTOA, "inet_ntoa()" },
		{ DIF_SUBR_INET_NTOA6, "inet_ntoa6()" },
		{ DIF_SUBR_TOUPPER, "toupper()" },
		{ DIF_SUBR_TOLOWER, "tolower()" },
		{ DIF_SUBR_MEMREF, "memref()" },
		{ DIF_SUBR_SX_SHARED_HELD, "sx_shared_held()" },
		{ DIF_SUBR_SX_EXCLUSIVE_HELD, "sx_exclusive_held()" },
		{ DIF_SUBR_SX_ISEXCLUSIVE, "sx_isexclusive()" },
		{ DIF_SUBR_MEMSTR, "memstr()" }, { DIF_SUBR_GETF, "getf()" },
		{ DIF_SUBR_JSON, "json()" }, { DIF_SUBR_STRTOLL, "strtoll()" },
		{ DIF_SUBR_RANDOM, "random()" },
		{ DIF_SUBR_PTINFO, "ptinfo()" } };

	dif_instr_t instr = n->getInstruction();
	uint16_t subr = DIF_INSTR_SUBR(instr);
	Vec<Typefile *> tfsToCheck = { dt_typefile_D(), dt_typefile_kernel() };

	/*
	 * The return typefile of a call instruction will always be the
	 * kernel itself, so we just do it ahead of time.
	 */
	n->tf = dt_typefile_kernel();
	assert(n->tf != nullptr);

	/*
	 * We don't care if there are more things on the stack than
	 * the arguments we need, because they will simply not be used.
	 *
	 * Therefore, the transformation where we have
	 *
	 *     foo(a, b);
	 *     bar(a, b, c);
	 *
	 * which results in
	 *
	 *     push a
	 *     push b
	 *     push c
	 *     call foo
	 *     call bar
	 *
	 * is perfectly valid, so we shouldn't fail to type check this.
	 */
	switch (subr) {
	case DIF_SUBR_RAND:
		n->ctfid = n->tf->getCtfID("uint64_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type uint64_t: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_MUTEX_OWNED:
	case DIF_SUBR_MUTEX_TYPE_ADAPTIVE:
	case DIF_SUBR_MUTEX_TYPE_SPIN:
		/*
		 * We expect a "struct mtx *" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, t_mtx, subr_name[subr],
		    SUBTYPE_EQUAL);

		n->ctfid = n->tf->getCtfID("int");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type int: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_MUTEX_OWNER:
		/*
		 * We expect a "struct mtx *" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, t_mtx, subr_name[subr],
		    SUBTYPE_EQUAL);

		n->ctfid = n->tf->getCtfID(t_thread.c_str());
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get thread type: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_RW_READ_HELD:
		/*
		 * We expect a "struct rwlock *" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, t_rw, subr_name[subr],
		    SUBTYPE_EQUAL);

		n->ctfid = n->tf->getCtfID("int");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type int: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_RW_WRITE_HELD:
		/*
		 * We expect a "struct rwlock *" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, t_rw, subr_name[subr],
		    SUBTYPE_EQUAL);

		n->ctfid = n->tf->getCtfID("int");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type int: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_RW_ISWRITER:
		/*
		 * We expect a "struct rwlock *" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, t_rw, subr_name[subr],
		    SUBTYPE_EQUAL);

		n->ctfid = n->tf->getCtfID("int");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type int: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_COPYIN:
		/*
		 * We expect a "uintptr_t" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "uintptr_t", subr_name[subr],
		    SUBTYPE_EQUAL);

		/*
		 * We expect a "size_t" as the second argument.
		 */
		arg1 = (*stack)[i++];
		assert(arg1->tf != nullptr);
		argCmpWith(arg1, tfsToCheck, "size_t", subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->ctfid = n->tf->getCtfID("void *");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type void *: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_COPYINSTR:
		/*
		 * We expect a "uintptr_t" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "uintptr_t", subr_name[subr],
		    SUBTYPE_EQUAL);

		/*
		 * Check if the second (optional) argument is present
		 */
		if (stack->size() > 1) {
			arg1 = (*stack)[i++];
			assert(arg1->tf != nullptr);
			argCmpWith(arg1, tfsToCheck, "size_t", subr_name[subr],
			    SUBTYPE_SND | SUBTYPE_EQUAL);
		}

		n->dType = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_SPECULATION:
		n->ctfid = n->tf->getCtfID("int");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type int: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_PROGENYOF:
		/*
		 * We expect a "pid_t" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "pid_t", subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->ctfid = n->tf->getCtfID("int");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type int: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_STRLEN:
		/*
		 * We expect a "const char *" as an argument.
		 */
		arg0 = (*stack)[i++];
		if (arg0->dType == DIF_TYPE_CTF)
			argCmpWith(arg0, tfsToCheck, "const char *",
			    subr_name[subr], SUBTYPE_EQUAL);
		else if (arg0->dType == DIF_TYPE_NONE)
			dt_set_progerr(dtp, pgp, "%s: arg0 type is NONE",
			    subr_name[subr].c_str());

		n->ctfid = n->tf->getCtfID("size_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type size_t: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_COPYOUT:
		/*
		 * We expect a "void *" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "void *", subr_name[subr],
		    SUBTYPE_NONE);

		/*
		 * We expect a "uintptr_t" as a second argument.
		 */
		arg1 = (*stack)[i++];
		assert(arg1->tf != nullptr);
		argCmpWith(arg1, tfsToCheck, "uintptr_t", subr_name[subr],
		    SUBTYPE_EQUAL);

		/*
		 * We expect a "size_t" as a third argument.
		 */
		arg2 = (*stack)[i++];
		assert(arg2->tf != nullptr);
		argCmpWith(arg2, tfsToCheck, "size_t", subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->dType = DIF_TYPE_NONE;
		break;

	case DIF_SUBR_COPYOUTSTR:
		/*
		 * We expect a "char *" as an argument.
		 */
		arg0 = (*stack)[i++];

		if (arg0->dType == DIF_TYPE_CTF)
			argCmpWith(arg0, tfsToCheck, "char *", subr_name[subr],
			    SUBTYPE_EQUAL);
		else if (arg0->dType == DIF_TYPE_NONE)
			dt_set_progerr(dtp, pgp, "%s: arg0 type is NONE",
			    subr_name[subr].c_str());

		/*
		 * We expect a "uintptr_t" as a second argument.
		 */
		arg1 = (*stack)[i++];
		assert(arg1->tf != nullptr);
		argCmpWith(arg1, tfsToCheck, "uintptr_t", subr_name[subr],
		    SUBTYPE_EQUAL);

		/*
		 * We expect a "size_t" as a third argument.
		 */
		arg2 = (*stack)[i++];
		assert(arg2->tf != nullptr);
		argCmpWith(arg2, tfsToCheck, "size_t", subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->dType = DIF_TYPE_NONE;
		break;

	case DIF_SUBR_ALLOCA:
		/*
		 * We expect a "size_t" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "size_t", subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->ctfid = n->tf->getCtfID("void *");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type void *: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_BCOPY:
		/*
		 * We expect a "void *" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "void *", subr_name[subr],
		    SUBTYPE_NONE);

		/*
		 * We expect a "void *" as a second argument.
		 */
		arg1 = (*stack)[i++];
		assert(arg1->tf != nullptr);
		argCmpWith(arg1, tfsToCheck, "void *", subr_name[subr],
		    SUBTYPE_NONE);

		/*
		 * We expect a "size_t" as a third argument.
		 */
		arg2 = (*stack)[i++];
		assert(arg2->tf != nullptr);
		argCmpWith(arg2, tfsToCheck, "size_t", subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->dType = DIF_TYPE_NONE;
		break;

	case DIF_SUBR_COPYINTO:
		/*
		 * We expect a "uintptr_t" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "uintptr_t", subr_name[subr],
		    SUBTYPE_EQUAL);

		/*
		 * We expect a "size_t" as a second argument.
		 */
		arg1 = (*stack)[i++];
		assert(arg1->tf != nullptr);
		argCmpWith(arg1, tfsToCheck, "size_t", subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		/*
		 * We expect a "void *" as a third argument.
		 */
		arg2 = (*stack)[i++];
		assert(arg2->tf != nullptr);
		argCmpWith(arg2, tfsToCheck, "void *", subr_name[subr],
		    SUBTYPE_NONE);

		n->dType = DIF_TYPE_NONE;
		break;

	case DIF_SUBR_MSGDSIZE:
	case DIF_SUBR_MSGSIZE:
		/*
		 * We expect a "mblk_t *" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "mblk_t *", subr_name[subr],
		    SUBTYPE_EQUAL);

		n->ctfid = n->tf->getCtfID("size_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type size_t: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_GETMAJOR:
		break;
	case DIF_SUBR_GETMINOR:
		break;

	case DIF_SUBR_DDI_PATHNAME:
		/*
		 * We expect a "void *" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "void *", subr_name[subr],
		    SUBTYPE_NONE);

		/*
		 * We expect a "int64_t" as a second argument.
		 */
		arg1 = (*stack)[i++];
		assert(arg1->tf != nullptr);
		argCmpWith(arg1, tfsToCheck, "int64_t", subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->dType = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_LLTOSTR:
		/*
		 * We expect a "int64_t" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "int64_t", subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		/*
		 * Check if the second (optional) argument is present
		 */
		if (stack->size() > 1) {
			arg1 = (*stack)[i++];
			assert(arg1->tf != nullptr);
			argCmpWith(arg1, tfsToCheck, "int", subr_name[subr],
			    SUBTYPE_ANY);
		}

		n->dType = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_CLEANPATH:
	case DIF_SUBR_DIRNAME:
	case DIF_SUBR_BASENAME:
		/*
		 * We expect a "const char *" as an argument.
		 */
		arg0 = (*stack)[i++];

		if (arg0->dType == DIF_TYPE_CTF)
			argCmpWith(arg0, tfsToCheck, "const char *",
			    subr_name[subr], SUBTYPE_EQUAL);
		else if (arg0->dType == DIF_TYPE_NONE)
			dt_set_progerr(dtp, pgp, "%s: arg0 type is NONE",
			    subr_name[subr].c_str());

		n->dType = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_STRRCHR:
	case DIF_SUBR_STRCHR:
		/*
		 * We expect a "const char *" as an argument.
		 */
		arg0 = (*stack)[i++];
		if (arg0->dType == DIF_TYPE_CTF)
			argCmpWith(arg0, tfsToCheck, "const char *",
			    subr_name[subr], SUBTYPE_EQUAL);
		else if (arg0->dType == DIF_TYPE_NONE)
			dt_set_progerr(dtp, pgp, "%s: arg0 type is NONE",
			    subr_name[subr].c_str());

		/*
		 * We expect a "char" as a second argument.
		 */
		arg1 = (*stack)[i++];
		assert(arg1->tf != nullptr);
		argCmpWith(arg1, tfsToCheck, "char", subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->dType = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_SUBSTR:
		/*
		 * We expect a "const char *" as an argument.
		 */
		arg0 = (*stack)[i++];
		if (arg0->dType == DIF_TYPE_CTF)
			argCmpWith(arg0, tfsToCheck, "const char *",
			    subr_name[subr], SUBTYPE_EQUAL);
		else if (arg0->dType == DIF_TYPE_NONE)
			dt_set_progerr(dtp, pgp, "%s: arg0 type is NONE",
			    subr_name[subr].c_str());

		/*
		 * We expect a "int" as a second argument.
		 */
		arg1 = (*stack)[i++];
		assert(arg1->tf != nullptr);
		argCmpWith(arg1, tfsToCheck, "int", subr_name[subr],
		    SUBTYPE_ANY);

		/*
		 * Check if the third (optional) argument is present
		 */
		if (stack->size() > 2) {
			arg2 = (*stack)[i++];
			assert(arg2->tf != nullptr);
			argCmpWith(arg2, tfsToCheck, "int", subr_name[subr],
			    SUBTYPE_ANY);
		}

		n->dType = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_RINDEX:
	case DIF_SUBR_INDEX:
		/*
		 * We expect a "const char *" as an argument.
		 */
		arg0 = (*stack)[i++];
		if (arg0->dType == DIF_TYPE_CTF)
			argCmpWith(arg0, tfsToCheck, "const char *",
			    subr_name[subr], SUBTYPE_EQUAL);
		else if (arg0->dType == DIF_TYPE_NONE)
			dt_set_progerr(dtp, pgp, "%s: arg0 type is NONE",
			    subr_name[subr].c_str());

		/*
		 * We expect a "const char *" as a second argument.
		 */
		arg1 = (*stack)[i++];

		if (arg0->dType == DIF_TYPE_CTF)
			argCmpWith(arg1, tfsToCheck, "const char *",
			    subr_name[subr], SUBTYPE_EQUAL);
		else if (arg0->dType == DIF_TYPE_NONE)
			dt_set_progerr(dtp, pgp, "%s: arg1 type is NONE",
			    subr_name[subr].c_str());

		/*
		 * Check if the third (optional) argument is present
		 */
		if (stack->size() > 2) {
			arg2 = (*stack)[i++];
			assert(arg2->tf != nullptr);
			argCmpWith(arg2, tfsToCheck, "int", subr_name[subr],
			    SUBTYPE_ANY);
		}

		n->ctfid = n->tf->getCtfID("int");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type int: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_NTOHS:
	case DIF_SUBR_HTONS:
		/*
		 * We expect a "uint16_t" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "uint16_t", subr_name[subr],
		    SUBTYPE_ANY);

		n->ctfid = n->tf->getCtfID("uint16_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type uint16_t: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_NTOHL:
	case DIF_SUBR_HTONL:
		/*
		 * We expect a "uint32_t" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "uint32_t", subr_name[subr],
		    SUBTYPE_ANY);

		n->ctfid = n->tf->getCtfID("uint32_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type uint32_t: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_NTOHLL:
	case DIF_SUBR_HTONLL:
		/*
		 * We expect a "uint64_t" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "uint64_t", subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->ctfid = n->tf->getCtfID("uint64_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type uint64_t: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_INET_NTOP:
		/*
		 * We expect a "int" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "int", subr_name[subr],
		    SUBTYPE_ANY);

		/*
		 * We expect a "void *" as a second argument.
		 */
		arg1 = (*stack)[i++];
		assert(arg1->tf != nullptr);
		argCmpWith(arg1, tfsToCheck, "void *", subr_name[subr],
		    SUBTYPE_NONE);

		n->dType = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_INET_NTOA:
		/*
		 * We expect a "in_addr_t *" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "in_addr_t *", subr_name[subr],
		    SUBTYPE_EQUAL);

		n->dType = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_INET_NTOA6:
		/*
		 * We expect a "struct in6_addr *" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "struct in6_addr *",
		    subr_name[subr], SUBTYPE_EQUAL);

		n->dType = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_TOLOWER:
	case DIF_SUBR_TOUPPER:
		/*
		 * We expect a "const char *" as an argument.
		 */
		arg0 = (*stack)[i++];

		if (arg0->dType == DIF_TYPE_CTF)
			argCmpWith(arg0, tfsToCheck, "const char *",
			    subr_name[subr], SUBTYPE_EQUAL);
		else if (arg0->dType == DIF_TYPE_NONE)
			dt_set_progerr(dtp, pgp, "%s: arg0 type is NONE",
			    subr_name[subr].c_str());

		n->dType = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_MEMREF:
		/*
		 * We expect a "void *" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "void *", subr_name[subr],
		    SUBTYPE_NONE);

		/*
		 * We expect a "size_t" as a second argument.
		 */
		arg1 = (*stack)[i++];
		assert(arg1->tf != nullptr);
		argCmpWith(arg1, tfsToCheck, "size_t", subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->ctfid = n->tf->getCtfID("uintptr_t *");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type uintptr_t *: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_SX_SHARED_HELD:
	case DIF_SUBR_SX_EXCLUSIVE_HELD:
	case DIF_SUBR_SX_ISEXCLUSIVE:
		/*
		 * We expect a sx_str as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, t_sx, subr_name[subr],
		    SUBTYPE_EQUAL);

		n->ctfid = n->tf->getCtfID("int");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type int: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_MEMSTR:
		/*
		 * We expect a "void *" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "void *", subr_name[subr],
		    SUBTYPE_NONE);

		/*
		 * We expect a "char" as a second argument.
		 */
		arg1 = (*stack)[i++];
		assert(arg1->tf != nullptr);
		argCmpWith(arg1, tfsToCheck, "char", subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		/*
		 * We expect a "size_t" as a third argument.
		 */
		arg2 = (*stack)[i++];
		assert(arg2->tf != nullptr);
		argCmpWith(arg2, tfsToCheck, "size_t", subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->dType = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_GETF:
		/*
		 * We expect a "int" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "int", subr_name[subr],
		    SUBTYPE_ANY);

		n->ctfid = n->tf->getCtfID("file_t *");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type file_t *: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_STRTOLL:
		/*
		 * We expect a "const char *" as an argument.
		 */
		arg0 = (*stack)[i++];
		if (arg0->dType == DIF_TYPE_CTF)
			argCmpWith(arg0, tfsToCheck, "const char *",
			    subr_name[subr], SUBTYPE_EQUAL);
		else if (arg0->dType == DIF_TYPE_NONE)
			dt_set_progerr(dtp, pgp, "%s: arg0 type is NONE",
			    subr_name[subr].c_str());

		/*
		 * Check if the second (optional) argument is present
		 */
		if (stack->size() > 1) {
			arg1 = (*stack)[i++];
			assert(arg1->tf != nullptr);
			argCmpWith(arg1, tfsToCheck, "int", subr_name[subr],
			    SUBTYPE_ANY);
		}

		n->ctfid = n->tf->getCtfID("int64_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type int64_t: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_RANDOM:
		n->ctfid = n->tf->getCtfID("uint64_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type uint64_t: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_PTINFO:
		/*
		 * We expect a "uintptr_t" as an argument.
		 */
		arg0 = (*stack)[i++];
		assert(arg0->tf != nullptr);
		argCmpWith(arg0, tfsToCheck, "uintptr_t", subr_name[subr],
		    SUBTYPE_EQUAL);

		n->ctfid = n->tf->getCtfID("void *");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "%s: failed to get type void *: %s",
			    subr_name[subr].c_str(), n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_STRTOK:
	case DIF_SUBR_STRSTR:
	case DIF_SUBR_STRJOIN:
	case DIF_SUBR_JSON:
		/*
		 * We expect a "const char *" as an argument.
		 */
		arg0 = (*stack)[i++];
		if (arg0->dType == DIF_TYPE_CTF)
			argCmpWith(arg0, tfsToCheck, "const char *",
			    subr_name[subr], SUBTYPE_EQUAL);
		else if (arg0->dType == DIF_TYPE_NONE)
			dt_set_progerr(dtp, pgp, "%s: arg0 type is NONE",
			    subr_name[subr].c_str());

		/*
		 * We expect a "const char *" as the second argument.
		 */
		arg1 = (*stack)[i++];
		if (arg1->dType == DIF_TYPE_CTF)
			argCmpWith(arg1, tfsToCheck, "const char *",
			    subr_name[subr], SUBTYPE_EQUAL);
		else if (arg1->dType == DIF_TYPE_NONE)
			dt_set_progerr(dtp, pgp, "%s: arg1 type is NONE",
			    subr_name[subr].c_str());

		n->dType = DIF_TYPE_STRING;
		break;
	default:
		return (-1);
	}

	return (n->dType);
}
}

