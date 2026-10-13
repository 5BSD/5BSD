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

#include <string>
#include <unordered_map>

namespace dtrace {
TypeInference::TypeInference(HyperTraceLinker &_linkerContext,
    dtrace_hdl_t *_dtp, dtrace_prog_t *_pgp)
    : dtp(_dtp)
    , pgp(_pgp)
    , linkerContext(_linkerContext)
{
	char __kernel[] = "kernel`";
	size_t __kernel_len = strlen(__kernel);

	if (strncmp(mtx_str, __kernel, __kernel_len) != 0)
		dt_set_progerr(dtp, pgp,
		    "mtx_str does not start with \"kernel`\" (%s)", mtx_str);

	if (strncmp(rw_str, __kernel, __kernel_len) != 0)
		dt_set_progerr(dtp, pgp,
		    "rw_str does not start with \"kernel`\" (%s)", rw_str);

	if (strncmp(sx_str, __kernel, __kernel_len) != 0)
		dt_set_progerr(dtp, pgp,
		    "sx_str does not start with \"kernel`\" (%s)", sx_str);

	t_mtx = String(mtx_str + __kernel_len);
	t_rw = String(rw_str + __kernel_len);
	t_sx = String(sx_str + __kernel_len);
	t_thread = String(thread_str);
}

void
TypeInference::setErrorMessage(const char *fmt, ...)
{
	va_list va, va_cp;
	va_start(va, fmt);
	va_copy(va_cp, va);
	auto len = vsnprintf(nullptr, 0, fmt, va);
	if (len < 0)
		abort();
	if (len > 0) {
		errorMessage.resize(len);
		vsnprintf(&errorMessage[0], len + 1, fmt, va_cp);
	}
	va_end(va_cp);
	va_end(va);
}

static int
isVoidPointer(String &t)
{

	return (t == "void *" || t == "const void *");
}

static int
dt_setx_value(dtrace_difo_t *difo, dif_instr_t instr)
{
	uint8_t opcode;
	uint16_t index;

	opcode = DIF_INSTR_OP(instr);
	assert(opcode == DIF_OP_SETX);
	assert(difo->dtdo_inttab != nullptr);

	index = DIF_INSTR_INTEGER(instr);
	assert(index < difo->dtdo_intlen);

	return (difo->dtdo_inttab[index]);
}

struct MemberInfoHelper {
	dtrace_hdl_t *dtp = nullptr;
	ctf_file_t *ctfp = nullptr;
	ctf_membinfo_t *mip = nullptr;
	uint64_t offs = 0;
	ctf_id_t ctfid = CTF_ERR;

	MemberInfoHelper(dtrace_hdl_t *_dtp, ctf_file_t *_ctfp, uint64_t _offs,
	    ctf_id_t _ctfid)
	    : dtp(_dtp)
	    , ctfp(_ctfp)
	    , offs(_offs)
	    , ctfid(_ctfid)
	{
	}
};

static int
findMemberOffset(const char *name, [[maybe_unused]] ctf_id_t ctfid, ulong_t off,
    void *arg)
{
	MemberInfoHelper *mh = (MemberInfoHelper *)arg;
	// Invalid argument, return an error
	if (arg == nullptr)
		return (-1);
	// We already found our member, simply return.
	if (mh->mip != nullptr)
		return (0);
	// If not matching, simply continue searching.
	if (off / NBBY != mh->offs)
		return (0);
	// We now know we have a matching offset. Get the mip and populate our
	// struct.
	mh->mip = (ctf_membinfo_t *)dt_zalloc(mh->dtp, sizeof(ctf_membinfo_t));
	if (mh->mip == nullptr)
		return (-1);
	if (ctf_member_info(mh->ctfp, mh->ctfid, name, mh->mip) == CTF_ERR)
		return (-1);
	// We now have the membinfo filled in, so we just return 0.
	return (0);
}

ctf_membinfo_t *
TypeInference::getMipByOffset(Typefile *tf, ctf_id_t ctfid, uint64_t offs)
{
	ctf_file_t *ctfp = tf->getCtfPointer();
	MemberInfoHelper mh(dtp, ctfp, offs, ctfid);
	if (ctf_member_iter(mh.ctfp, ctfid, &findMemberOffset, &mh) == -1)
		return (nullptr);
	return (mh.mip);
}


ctf_membinfo_t *
TypeInference::getMipFromSymbol(DFGNode *n)
{
	if (n == nullptr)
		return (nullptr);
	/*
	 * If there is no symbol here, we can't do anything.
	 */
	if (n->sym == nullptr)
		return (nullptr);
	if (n->difo == nullptr)
		return (nullptr);

	dtrace_difo_t *difo = n->difo;
	/*
	 * sym in range(symtab)
	 */
	if ((uintptr_t)n->sym >=
	    ((uintptr_t)difo->dtdo_symtab) + difo->dtdo_symlen)
		return (nullptr);
	int c = dt_get_class(n->tf, n->ctfid, 1);
	if (c != DTC_STRUCT && c != DTC_FORWARD) {
		return (nullptr);
	}
	/*
	 * Figure out t2 = type_at(t1, symname)
	 */
	auto *mip = (ctf_membinfo_t *)dt_zalloc(dtp, sizeof(ctf_membinfo_t));
	if (mip == nullptr)
		return (nullptr);
	ctf_id_t kind = n->tf->getKind(n->ctfid);
	ctf_id_t type;
	if (kind == CTF_K_POINTER || kind == CTF_K_VOLATILE ||
	    kind == CTF_K_TYPEDEF || kind == CTF_K_RESTRICT ||
	    kind == CTF_K_CONST)
		/*
		 * Get the non-pointer type. This should NEVER fail.
		 */
		type = n->tf->getReference(n->ctfid);
	else
		type = n->ctfid;
	assert(type != CTF_ERR);
	if (n->tf->getMembInfo(type, n->sym, mip) == 0) {
		free(mip);
		return (nullptr);
	}
	return (mip);
}

int
TypeInference::getSubtypeRelation(Typefile *tf1, ctf_id_t id1, Typefile *tf2,
    ctf_id_t id2, int &which)
{
	which = SUBTYPE_NONE;

	assert(tf1 != nullptr);
	assert(tf2 != nullptr);

	auto opt = tf1->getTypename(id1);
	if (!opt.has_value()) {
		return (-1);
	}

	String type1_name = std::move(opt.value());
	opt = tf2->getTypename(id2);
	if (!opt.has_value()) {
		return (-1);
	}

	String type2_name = std::move(opt.value());
	bool isvoid1 = isVoidPointer(type1_name);
	bool isvoid2 = isVoidPointer(type2_name);

	if (isvoid1 && isvoid2) {
		which = SUBTYPE_EQUAL;
		return (0);
	} else if (isvoid1) {
		which = SUBTYPE_FST;
		return (0);
	} else if (isvoid2) {
		which = SUBTYPE_SND;
		return (0);
	}

	size_t n_stars1, n_stars2;
	ctf_id_t kind1 = tf1->stripReference(id1, n_stars1);
	ctf_id_t kind2 = tf2->stripReference(id2, n_stars2);

	/*
	 * In case number of stars in a pointer didn't match.
	 */
	if (n_stars1 != n_stars2) {
		fprintf(stderr,
		    "mismatched pointer %s != %s "
		    "(%zu stars != %zu stars)\n",
		    type1_name.c_str(), type2_name.c_str(), n_stars1, n_stars2);
		return (-1);
	}

	/*
	 * We don't want bogus values, functions or floats here.
	 */
	assert(kind1 != CTF_K_UNKNOWN);
	assert(kind2 != CTF_K_UNKNOWN);

	assert(kind1 != CTF_K_FUNCTION);
	assert(kind2 != CTF_K_FUNCTION);

	assert(kind1 != CTF_K_FLOAT);
	assert(kind2 != CTF_K_FLOAT);

	assert(kind1 < CTF_K_MAX);
	assert(kind2 < CTF_K_MAX);

	/*
	 * For integers, we just want to check if they are compatible and then
	 * pick the one that is larger as the one to use for our storage.
	 */
	if (kind1 == CTF_K_INTEGER && kind2 == CTF_K_INTEGER) {
		ctf_encoding_t enc1, enc2;

		if (tf1->getEncoding(id1, &enc1) != 0) {
			fprintf(stderr,
			    "dt_type_subtype(): failed getting encoding "
			    "with %s: %s\n",
			    tf1->name().c_str(), tf1->getErrMsg());
			return (-1);
		}

		if (tf2->getEncoding(id2, &enc2) != 0) {
			fprintf(stderr,
			    "dt_type_subtype(): failed getting encoding "
			    "with %s: %s\n",
			    tf2->name().c_str(), tf2->getErrMsg());
			return (-1);
		}

		auto size1 = tf1->getSize(id1);
		auto size2 = tf2->getSize(id2);

#if 0
		if (enc1.cte_format != enc2.cte_format && size1 == size2) {
			fprintf(stderr,
			    "dt_type_subtype(): both arguments types "
			    "need to have same signedness\n");
			return (-1);
		}
#endif

		if (size1 == size2)
			which = SUBTYPE_EQUAL;
		else
			which = size1 > size2 ? SUBTYPE_FST : SUBTYPE_SND;

		return (0);
	}

	/*
	 * We require that arrays are fully compatible
	 */
	if (kind1 == CTF_K_ARRAY && kind2 == CTF_K_ARRAY) {
		if (ctfTypeCompare(tf1, id1, tf2, id2))
			return (-1);

		which = SUBTYPE_EQUAL;
		return (0);
	}

	opt = tf1->getTypename(id1);
	if (!opt.has_value()) {
		fprintf(stderr, "typefile::getTypename() failed: %s\n",
		    tf1->getErrMsg());
		return (-1);
	}

	String r1_type_name = std::move(opt.value());

	opt = tf2->getTypename(id2);
	if (!opt.has_value()) {
		fprintf(stderr, "typefile::getTypename() failed: %s\n",
		    tf2->getErrMsg());
		return (-1);
	}

	String r2_type_name = std::move(opt.value());

	/*
	 * Since this is C, we do a comparison by name first. If the names don't
	 * match identically, we aren't really interested.
	 *
	 * Note that this is not really a requirement and we could require a
	 * definition of equivalence defined by a bijection which is far more
	 * relaxed, but for now we require that the name matches. This is easily
	 * removed later.
	 */
	if (r1_type_name != r2_type_name) {
		fprintf(stderr, "%s(): subtyping not possible: %s != %s\n",
		    __func__, type1_name.c_str(), type2_name.c_str());
		return (-1);
	}

	if (kind1 == CTF_K_STRUCT) {
		/*
		 * We have a few conditions for subtyping of structs.
		 *
		 * s1 is a subtype of s2 iff:
		 *  (1) sizeof(s1) <= sizeof(s2)
		 *  (2) s1 is a slice of s2 (s1 = s2 up to a point, but s2 has
		 *                           more stuff afterwards)
		 *
		 * We could loosen this restriction quite a bit, but for now
		 * this is sufficient.
		 */

		auto *s1 = tf1->buildStruct(id1);
		if (s1 == nullptr) {
			fprintf(stderr,
			    "build up struct %s failed for %s: %s\n",
			    type1_name.c_str(), tf1->name().c_str(),
			    tf1->getErrMsg());
			return (-1);
		}

		auto *s2 = tf2->buildStruct(id2);
		if (s2 == nullptr) {
			fprintf(stderr,
			    "build up struct %s failed for %s: %s\n",
			    type2_name.c_str(), tf2->name().c_str(),
			    tf2->getErrMsg());
			return (-1);
		}

		Vec<ctf_id_t>::iterator it1, it2;
		/*
		 * Go over each member and ensure that if both exist, they are
		 * pointwise equal. We don't accept *any* variety between them.
		 */
		for (it1 = s1->begin(), it2 = s2->begin();
		     it1 != s1->end() && it2 != s2->end(); ++it1, ++it2) {
			ctf_id_t memb1 = *it1;
			ctf_id_t memb2 = *it2;

			auto opt = tf1->getTypename(memb1);
			if (!opt.has_value()) {
				return (-1);
			}

			String memb1_name = std::move(opt.value());
			opt = tf2->getTypename(memb2);
			if (!opt.has_value()) {
				return (-1);
			}

			String memb2_name = std::move(opt.value());
			if (ctfTypeCompare(tf1, memb1, tf2, memb2)) {
				fprintf(stderr,
				    "comparison between %s and %s failed\n",
				    memb1_name.c_str(), memb2_name.c_str());
				return (-1);
			}
		}

		assert(it1 == s1->end() || it2 == s2->end());
		if (it1 == s1->end() && it2 != s2->end())
			which = SUBTYPE_FST;
		else if (it1 != s1->end() && it2 == s2->end())
			which = SUBTYPE_SND;
		else
			which = SUBTYPE_EQUAL;

		return (0);
	} else if (kind1 == CTF_K_UNION || kind1 == CTF_K_ENUM ||
	    kind1 == CTF_K_FORWARD) {
		/*
		 * It doesn't really make sense to support different unions or
		 * enum types. We only check pointwise equality.
		 */
		if (ctfTypeCompare(tf1, id1, tf2, id2))
			return (-1);

		which = SUBTYPE_EQUAL;
		return (0);
	}

	fprintf(stderr, "unknown typing error (%s != %s)\n", type1_name.c_str(),
	    type2_name.c_str());
	return (-1);
}
static std::unordered_map<uint8_t, String> insname = {
	{ DIF_OP_OR, "or" },
	{ DIF_OP_XOR, "xor" },
	{ DIF_OP_AND, "and" },
	{ DIF_OP_SLL, "sll" },
	{ DIF_OP_SRL, "srl" },
	{ DIF_OP_SUB, "sub" },
	{ DIF_OP_ADD, "add" },
	{ DIF_OP_MUL, "mul" },
	{ DIF_OP_SDIV, "sdiv" },
	{ DIF_OP_UDIV, "udiv" },
	{ DIF_OP_SREM, "srem" },
	{ DIF_OP_UREM, "urem" },
	{ DIF_OP_NOT, "not" },
	{ DIF_OP_MOV, "mov" },
	{ DIF_OP_CMP, "cmp" },
	{ DIF_OP_TST, "tst" },
	{ DIF_OP_BA, "ba" },
	{ DIF_OP_BE, "be" },
	{ DIF_OP_BNE, "bne" },
	{ DIF_OP_BG, "bg" },
	{ DIF_OP_BGU, "bgu" },
	{ DIF_OP_BGE, "bge" },
	{ DIF_OP_BGEU, "bgeu" },
	{ DIF_OP_BL, "bl" },
	{ DIF_OP_BLU, "blu" },
	{ DIF_OP_BLE, "ble" },
	{ DIF_OP_BLEU, "bleu" },
	{ DIF_OP_LDSB, "ldsb" },
	{ DIF_OP_LDSH, "ldsh" },
	{ DIF_OP_LDSW, "ldsw" },
	{ DIF_OP_LDUB, "ldub" },
	{ DIF_OP_LDUH, "lduh" },
	{ DIF_OP_LDUW, "lduw" },
	{ DIF_OP_LDX, "ldx" },
	{ DIF_OP_RET, "ret" },
	{ DIF_OP_NOP, "nop" },
	{ DIF_OP_SETX, "setx" },
	{ DIF_OP_SETS, "sets" },
	{ DIF_OP_SCMP, "scmp" },
	{ DIF_OP_LDGA, "ldga" },
	{ DIF_OP_LDGS, "ldgs" },
	{ DIF_OP_STGS, "stgs" },
	{ DIF_OP_LDTA, "ldta" },
	{ DIF_OP_LDTS, "ldts" },
	{ DIF_OP_STTS, "stts" },
	{ DIF_OP_SRA, "sra" },
	{ DIF_OP_CALL, "call" },
	{ DIF_OP_PUSHTR, "pushtr" },
	{ DIF_OP_PUSHTV, "pushtv" },
	{ DIF_OP_POPTS, "popts" },
	{ DIF_OP_FLUSHTS, "flushts" },
	{ DIF_OP_LDGAA, "ldgaa" },
	{ DIF_OP_LDTAA, "ldtaa" },
	{ DIF_OP_STGAA, "stgaa" },
	{ DIF_OP_STTAA, "sttaa" },
	{ DIF_OP_LDLS, "ldls" },
	{ DIF_OP_STLS, "stls" },
	{ DIF_OP_ALLOCS, "allocs" },
	{ DIF_OP_COPYS, "copys" },
	{ DIF_OP_STB, "stb" },
	{ DIF_OP_STH, "sth" },
	{ DIF_OP_STW, "stw" },
	{ DIF_OP_STX, "stx" },
	{ DIF_OP_ULDSB, "uldsb" },
	{ DIF_OP_ULDSH, "uldsh" },
	{ DIF_OP_ULDSW, "uldsw" },
	{ DIF_OP_ULDUB, "uldub" },
	{ DIF_OP_ULDUH, "ulduh" },
	{ DIF_OP_ULDUW, "ulduw" },
	{ DIF_OP_ULDX, "uldx" },
	{ DIF_OP_RLDSB, "rldsb" },
	{ DIF_OP_RLDSH, "rldsh" },
	{ DIF_OP_RLDSW, "rldsw" },
	{ DIF_OP_RLDUB, "rldub" },
	{ DIF_OP_RLDUH, "rlduh" },
	{ DIF_OP_RLDUW, "rlduw" },
	{ DIF_OP_RLDX, "rldx" },
	{ DIF_OP_XLATE, "xlate" },
	{ DIF_OP_XLARG, "xlarg" },
	{ DIF_OP_HYPERCALL, "hypercall" },
	{ DIF_OP_USETX, "usetx" },
	{ DIF_OP_ULOAD, "uload" },
	{ DIF_OP_UULOAD, "uuload" },
	{ DIF_OP_TYPECAST, "typecast" },
};

#define TYPING_ERROR(fmt, op, n, ...)                                       \
	do {                                                                \
		setErrorMessage("%s (%zu @ %p): " fmt, insname[op].c_str(), \
		    n->uidx, (void *)n->difo, ##__VA_ARGS__);               \
	} while (0)

#define TYPING_LOG(fmt, op, n, ...)                                \
	do {                                                       \
		_HYPERTRACE_LOG_TYPING("%s (%zu @ %p): " fmt,      \
		    insname[op].c_str(), n->uidx, (void *)n->difo, \
		    ##__VA_ARGS__);                                \
	} while (0)

#define TYPING_LOG_DEFAULT(op, n)                                       \
	TYPING_LOG("inferred %s [%s] (sym=%s, mip=%p)\n", op, n,        \
	    n->tf->getTypename(n->ctfid).value_or("UNDEFINED").c_str(), \
	    n->tf->name().c_str(), n->sym ? n->sym : "none", (void *)n->mip)

dtrace_difv_t *
TypeInference::findVariableFromNodeDefs(NodeSet &defs)
{
	for (auto defn : defs) {
		uint8_t op = DIF_INSTR_OP(defn->Instruction());
		if (op == DIF_OP_ADD || op == DIF_OP_MUL) {
			// Check if either of the two registers lead to a DIF
			// variable.
			auto d1 = findVariableFromNodeDefs(defn->r1Defs);
			auto d2 = findVariableFromNodeDefs(defn->r2Defs);
			return (d1 ? d1 : d2);
		} else if (op == DIF_OP_LDGS || op == DIF_OP_LDTS ||
		    op == DIF_OP_LDLS) {
			// Find the actual variable.
			uint16_t id;
			int scope, kind;
			getVariableInfo(defn->Instruction(), &id, &scope,
			    &kind);
			return (linkerContext.getVarFromVarVec(id, scope, kind));
		} else {
			// If we encounter an unexpected instruction, it means
			// there can't possibly be a variable at the root of it.
			return (nullptr);
		}
	}
	return (nullptr);
}

/*
 * This is the main part of the type inference algorithm.
 */
int
TypeInference::inferNode(DFGNode *n)
{
	DFGNode *symnode, *other;
	int res;
	char buf[4096] = { 0 }, symname[4096] = { 0 }, var_type[4096] = { 0 };
	ctf_membinfo_t *mip;
	size_t l;
	uint16_t var;
	dtrace_difo_t *difo;
	uint16_t sym;
	ctf_id_t type = 0;
	dtrace_difv_t *dif_var;
	size_t userland_len = strlen("userland ");
	int c;

	if (n == linkerContext.getR0Node())
		return (n->dType);

	mip = nullptr;
	l = 0;
	difo = n->difo;
	sym = 0;
	res = 0;
	symnode = nullptr;
	other = nullptr;
	var = 0;
	dif_var = nullptr;

	/*
	 * If we already have the type, we just return it.
	 */
	if (n->dType != -1)
		return (n->dType);

	/*
	 * We do not tolerate nullptr ECBs.
	 */
	assert(n->edp != nullptr);
	dif_instr_t instr = n->getInstruction();
	uint8_t opcode = DIF_INSTR_OP(instr);
	bool empty;
	DFGNode *dn1 = checkRegDefs(n, n->r1Defs, empty);
	if (dn1 == nullptr && empty) {
		TYPING_ERROR("failed to r1defs stack\n", opcode, n);
		return (-1);
	}

	DFGNode *dn2 = checkRegDefs(n, n->r2Defs, empty);
	if (dn2 == nullptr && empty) {
		TYPING_ERROR("failed to r2defs stack\n", opcode, n);
		return (-1);
	}

	DFGNode *dnv = checkVarDefs(n, difo, n->varDefs, empty);
	if (dnv == nullptr && empty) {
		TYPING_ERROR("failed to vardefs stack\n", opcode, n);
		return (-1);
	}

	NodeVec *stack = checkStack(n->stacks, empty);
	if (stack == nullptr && empty) {
		TYPING_ERROR("failed to infer stack\n", opcode, n);
		return (-1);
	}

	switch (opcode) {
	case DIF_OP_ULOAD:
	case DIF_OP_UULOAD:
		/*
		 *  %r1 : t1 | sym    sym in range(symtab)
		 *        symtab(sym) = symname
		 *       t2 = type_at(t1, symname)
		 * ----------------------------------------
		 *      opcode [%r1], %r2 => %r2 : t2
		 */

		/*
		 * We only need one type here (the first one).
		 */
		if (dn1 == nullptr) {
			TYPING_ERROR("expected a non-null r1 definition for\n",
				     opcode, n);
			return (-1);
		}

		/*
		 * If there is no symbol here, we can't do anything.
		 */
		if (dn1->sym == nullptr) {
			TYPING_ERROR("expected a non-null r1 symbol\n", opcode,
			    n);
			return (-1);
		}

		mip = getMipFromSymbol(dn1);
		if (mip == nullptr) {
			TYPING_ERROR("failed to get mip [%s:%s]: %s\n", opcode,
			    n,
			    dn1->tf->getTypename(dn1->ctfid)
				.value_or("UNDEFINED")
				.c_str(),
			    dn1->sym, dn1->tf->getErrMsg());
			return (-1);
		}

		n->mip = mip;
		n->ctfid = mip->ctm_type;
		n->dType = DIF_TYPE_CTF;
		n->tf = dn1->tf;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_USETX:
		/*
		 *  symtab(idx) = sym    idx in range(symtab)
		 * ------------------------------------------
		 *   usetx idx, %r1 => %r1 : uint64_t | sym
		 */

		sym = DIF_INSTR_SYMBOL(instr);
		if (sym >= difo->dtdo_symlen) {
			TYPING_ERROR("sym >= symlen (%u >= %ju)\n", opcode, n,
			    sym, (uintmax_t)difo->dtdo_symlen);
			return (-1);
		}

		n->tf = dt_typefile_D();
		n->ctfid = n->tf->getCtfID("uint64_t");
		if (n->ctfid == CTF_ERR) {
			TYPING_ERROR("failed to get uint64_t: %s\n", opcode, n,
			    n->tf->getErrMsg());
			return (-1);
		}

		n->sym = difo->dtdo_symtab + sym;
		n->dType = DIF_TYPE_CTF;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_TYPECAST:
		/*  symtab(idx) = t   idx in range(symtab)    t in ctf_file
		 * ---------------------------------------------------------
		 *                typecast idx, %r1 => %r1 : t
		 */

		if (dn1 == nullptr) {
			TYPING_ERROR("r1 definition must not be NULL\n", opcode,
			    n);
			return (-1);
		}

		mip = getMipFromSymbol(dn1);
		sym = DIF_INSTR_SYMBOL(instr);
		if (sym >= difo->dtdo_symlen) {
			TYPING_ERROR("sym >= symlen (%u >= %ju)\n", opcode, n,
			    sym, difo->dtdo_symlen);
			return (-1);
		}

		l = strlcpy(symname, difo->dtdo_symtab + sym, sizeof(symname));
		if (l >= sizeof(symname)) {
			TYPING_ERROR("length %zu >= %zu when copying type name",
			    opcode, n, l, sizeof(symname));
			return (-1);
		}

		if (strncmp(symname, "userland ", userland_len) == 0) {
			char *tmpbuf = (char *)dt_alloc(dtp, sizeof(symname));
			if (tmpbuf == nullptr) {
				TYPING_ERROR("malloc() failed: %s", opcode, n,
				    strerror(errno));
				return (-1);
			}

			memcpy(tmpbuf, symname + userland_len,
			    sizeof(symname) - userland_len);
			memcpy(symname, tmpbuf, sizeof(symname));
		}

		/*
		 * We kind of have to guess here. We start by getting the
		 * 'module' field of the probe description and try to find that
		 * module. If we can't, this might be a SDT probe that is
		 * "poorly" defined. We then look for the type in the kernel
		 * itself. If we can't find it there, we just bail out for now
		 * rather than causing runtime failures.
		 *
		 * TODO: Maybe we can tolerate some failures by looking at
		 * symbols too?
		 */
		if (strcmp(symname, "D string") == 0) {
			n->dType = DIF_TYPE_STRING;
			n->mip = mip;
			TYPING_LOG_DEFAULT(opcode, n);
			return (n->dType);
		}

		if (strcmp(symname, "bottom") == 0) {
			n->dType = DIF_TYPE_BOTTOM;
			n->mip = mip;
			TYPING_LOG_DEFAULT(opcode, n);
			return (n->dType);
		}

		n->ctfid = dt_autoresolve_ctfid(n->edp->dted_probe.dtpd_mod,
		    symname, &n->tf);
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get "
			    "type %s: %s",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo, symname,
			    n->tf->getErrMsg());

		n->mip = mip;
		n->dType = DIF_TYPE_CTF;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);
	/*
	 * Potential information necessary to apply relocations
	 */
	case DIF_OP_OR:
	case DIF_OP_XOR:
	case DIF_OP_AND:
	case DIF_OP_SLL:
	case DIF_OP_SRL:
	case DIF_OP_SRA:
	case DIF_OP_ADD:
	case DIF_OP_SUB:
	case DIF_OP_MUL:
	case DIF_OP_SDIV:
	case DIF_OP_UDIV:
	case DIF_OP_SREM:
	case DIF_OP_UREM:
		/*
		 * In this rule, we allow %r1 and %r2 to be swapped.
		 * For the sake of conciseness, we just write out 1 rule.
		 *
		 *  %r1 : t1    %r2 : t2    t2 <: t1
		 * ----------------------------------
		 *  opcode %r1, %r2, %r3 => %r3 : t1
		 *
		 * The second rule has to do with symbol resolution and should
		 * only get applied when one of the two registers contains a
		 * type annotated with a symbol (indicating that the type)
		 * originates from symbol resolution, rather than a poset
		 * relation.
		 *
		 *  %r1 : t1    %r2 : uint64_t | sym    uint64_t <: t1
		 * ----------------------------------------------------
		 *        opcode %r1, %r2, %r3 => %r3 : t1 | sym
		 *
		 * N.B.: We allow this rule to work with a whole bunch of
		 *       arithmetic operations, not only add. This is simply
		 *       because we can't possibly infer all ways that one could
		 *       arrive at a given struct member, so we simply assume
		 *       that the calculation is correct. For example, we could
		 *       have something that looks like:
		 *
		 *  usetx %r1, sym
		 *  sll %r1, %r2, %r1
		 *  srl %r1, %r2, %r1
		 *
		 * where the first %r1 would be of type uint64_t | sym.
		 * Following that, sll %r1, %r2, %r1 => %r1 : uint64_t | sym
		 * and srl %r1, %r2, %r1 => %r1 : uint64_t | sym, still knowing
		 * that this type originates from a symbol.
		 */

		/*
		 * Nonsense. We need both types.
		 */
		if (dn1 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): dn1 is nullptr\n",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo);
			return (-1);
		}

		if (dn2 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): dn2 is nullptr\n",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo);
			return (-1);
		}

		/*
		 * If we have no type with a symbol associated with it,
		 * we apply the first typing rule.
		 */
		if (dn1->sym == nullptr && dn2->sym == nullptr) {
			DFGNode *tc_n = nullptr;

			/*
			 * Check which type is "bigger".
			 */
			res = typeCompare(dn1, dn2);
			assert(res == 1 || res == 2 || res == -1);

			if (res == 1) {
				tc_n = dn1;
				other = dn2;
			} else if (res == 2) {
				tc_n = dn2;
				other = dn1;
			} else {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p) nosym: types can "
				    "not be compared\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo);
				return (-1);
			}

			ctf_id_t k = tc_n->tf->getKind(tc_n->ctfid);
			if (opcode == DIF_OP_ADD &&
			    (k == CTF_K_STRUCT || k == CTF_K_UNION) &&
			    other->integer.has_value()) {
				mip = getMipByOffset(tc_n->tf, tc_n->ctfid,
				    other->integer.value());
				if (mip == nullptr) {
					n->dType = tc_n->dType;
					n->ctfid = tc_n->ctfid;
					n->tf = tc_n->tf;
					n->integer = other->integer;
					TYPING_LOG_DEFAULT(opcode, n);
					return (n->dType);
				}

				n->dType = DIF_TYPE_CTF;
				n->ctfid = mip->ctm_type;
				n->tf = tc_n->tf;
				n->mip = nullptr;
				n->sym = nullptr;
			} else {
				/*
				 * We don't have to sanity check these because
				 * we do it in every base case of the recursive
				 * call.
				 */
				n->dType = tc_n->dType;
				n->ctfid = tc_n->ctfid;
				n->tf = tc_n->tf;
				n->integer = other->integer;
			}
		} else {
			if (dn1->sym == nullptr) {
				assert(dn2->sym != nullptr);
				symnode = dn2;
				other = dn1;
			} else if (dn2->sym == nullptr) {
				assert(dn1->sym != nullptr);
				symnode = dn1;
				other = dn2;
			} else {
				uint8_t op1, op2;
				assert(
				    dn1->sym != nullptr && dn2->sym != nullptr);

				op1 = DIF_INSTR_OP(dn1->getInstruction());
				op2 = DIF_INSTR_OP(dn2->getInstruction());
				if (op1 == DIF_OP_USETX) {
					symnode = dn1;
					other = dn2;
				} else {
					assert(op2 == DIF_OP_USETX);
					symnode = dn2;
					other = dn1;
				}
			}

			if (other->dType == DIF_TYPE_BOTTOM ||
			    symnode->dType == DIF_TYPE_BOTTOM)
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): unexpected bottom "
				    "type (binary arithmetic operation)",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo);

			/*
			 * Check which type is "bigger".
			 */
			res = typeCompare(symnode, other);
			assert(res == 1 || res == 2 || res == -1);

			if (res == -1) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): types can not be "
				    "compared\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo);
				return (-1);
			}

			/*
			 * Get the type name of the other node
			 */
			if (other->tf->getTypename(other->ctfid, buf,
				sizeof(buf)) != ((char *)buf))
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): failed at getting "
				    "type name %ld for other: %s",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    other->ctfid, other->tf->getErrMsg());

			if (res == 1) {
				if (strcmp(buf, "uint64_t") != 0)
					dt_set_progerr(dtp, pgp,
					    "inferNode(%s, %zu@%p): the type "
					    "of the other node must be uint64_t"
					    " if symnode->ctfid (%zu@%p) <:"
					    " other->ctfid (%zu@%p), but it "
					    "is: %s",
					    insname[opcode].c_str(), n->uidx,
					    n->difo, symnode->uidx,
					    symnode->difo, other->uidx,
					    other->difo, buf);
			}

			/*
			 * At this point, we have ensured that the types are:
			 *  (1) Related (<: exists between t1 and t2)
			 *  (2) Well-ordered: if
			 *
			 *            symnode->ctfid <: other->ctfid,
			 *
			 *      then other->ctfid is also
			 *      uint64_t (reflexivity).
			 *  (3) One of the uint64_ts originates from a symbol.
			 */
			if (other->sym == nullptr) { // FIXME: suspect
				n->sym = symnode->sym;
				n->ctfid = other->ctfid;
				n->tf = other->tf;
				n->dType = DIF_TYPE_CTF;
				TYPING_LOG_DEFAULT(opcode, n);
				return (n->dType);
			}

			c = dt_get_class(other->tf, other->ctfid, 1);
			if (c != DTC_STRUCT && c != DTC_UNION)
				return (-1);

			/*
			 * Figure out t2 = type_at(t1, symname)
			 */
			mip = (ctf_membinfo_t *)malloc(sizeof(ctf_membinfo_t));
			if (mip == nullptr)
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): failed to "
				    "malloc mip",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo);

			memset(mip, 0, sizeof(ctf_membinfo_t));

			/*
			 * Get the non-pointer type. This should NEVER fail.
			 */
			type = other->tf->getReference(other->ctfid);
			if (other->tf->getMembInfo(type, other->sym, mip) == 0)
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): failed to get "
				    "member info for %s(%s): %s",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    buf, other->sym, other->tf->getErrMsg());

			n->mip = mip;
			n->sym = symnode->sym;
			n->ctfid = mip->ctm_type;
			n->tf = other->tf;
			n->dType = DIF_TYPE_CTF;
		}

		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_MOV:
	case DIF_OP_NOT:
		/*
		 *           %r1 : t
		 * ---------------------------
		 * opcode %r1, %r2 => %r2 : t
		 */

		/*
		 * Nonsense.
		 *
		 * N.B.: We don't need to check that type1 is sane, because
		 *       if dn1 is not nullptr, then we'll have checked it
		 * already.
		 */
		if (dn1 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): dn1 is nullptr\n",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo);
			return (-1);
		}

		/*
		 * We don't have to sanity check here because we do it in every
		 * base case of the recursive call.
		 */
		n->ctfid = dn1->ctfid;
		n->tf = dn1->tf;
		n->dType = dn1->dType;
		n->mip = dn1->mip;
		n->sym = dn1->sym;

		if (opcode == DIF_OP_MOV)
			n->isNull = dn1->isNull;

		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_LDSB:
	case DIF_OP_RLDSB:
	case DIF_OP_ULDSB:
		/*
		 *          %r1 :: Pointer
		 * -----------------------------------
		 *  opcode [%r1], %r2 => %r2 : int8_t
		 */
		n->tf = dt_typefile_D();
		n->ctfid = n->tf->getCtfID("int8_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get type "
			    "int8_t: %s",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo,
			    n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_LDSH:
	case DIF_OP_RLDSH:
	case DIF_OP_ULDSH:
		/*
		 *          %r1 :: Pointer
		 * ------------------------------------
		 *  opcode [%r1], %r2 => %r2 : int16_t
		 */
		n->tf = dt_typefile_D();
		n->ctfid = n->tf->getCtfID("int16_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get type "
			    "int16_t: %s",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo,
			    n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_LDSW:
	case DIF_OP_RLDSW:
	case DIF_OP_ULDSW:
		/*
		 *          %r1 :: Pointer
		 * ------------------------------------
		 *  opcode [%r1], %r2 => %r2 : int32_t
		 */
		n->tf = dt_typefile_D();
		n->ctfid = n->tf->getCtfID("int32_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get "
			    "type unsigned char: %s",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo,
			    n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_LDUB:
	case DIF_OP_RLDUB:
	case DIF_OP_ULDUB:
		/*
		 *          %r1 :: Pointer
		 * ------------------------------------
		 *  opcode [%r1], %r2 => %r2 : uint8_t
		 */
		n->tf = dt_typefile_D();
		n->ctfid = n->tf->getCtfID("uint8_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get type "
			    "uint8_t: %s",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo,
			    n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_LDUH:
	case DIF_OP_RLDUH:
	case DIF_OP_ULDUH:
		/*
		 *          %r1 :: Pointer
		 * -------------------------------------
		 *  opcode [%r1], %r2 => %r2 : uint16_t
		 */
		n->tf = dt_typefile_D();
		n->ctfid = n->tf->getCtfID("uint16_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get type "
			    "uint16_t: %s",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo,
			    n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_LDUW:
	case DIF_OP_RLDUW:
	case DIF_OP_ULDUW:
		/*
		 *          %r1 :: Pointer
		 * -------------------------------------
		 *  opcode [%r1], %r2 => %r2 : uint32_t
		 */
		n->tf = dt_typefile_D();
		n->ctfid = n->tf->getCtfID("uint32_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get type "
			    "uint32_t: %s",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo,
			    n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_ULDX:
	case DIF_OP_RLDX:
	case DIF_OP_LDX:
	case DIF_OP_SETX:
		/*
		 * ---------------------------------
		 *  setx idx, %r1 => %r1 : uint64_t
		 */

		n->tf = dt_typefile_D();
		n->ctfid = n->tf->getCtfID("uint64_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get type "
			    "uint64_t: %s",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo,
			    n->tf->getErrMsg());

		n->dType = DIF_TYPE_CTF;
		if (opcode == DIF_OP_SETX) {
			n->integer = std::make_optional<uint64_t>(
			    dt_setx_value(difo, instr));
			n->isNull = n->integer.value() == 0;
		}

		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_SETS:
		/*
		 * --------------------------------
		 *  sets idx, %r1 => %r1: D string
		 */

		n->dType = DIF_TYPE_STRING;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_LDGA:
		/*
		 *   var : t[]          %r2 : int
		 * --------------------------------
		 *  ldga var, %r2,  %r1 => %r1 : t
		 */

		var = DIF_INSTR_R1(instr);
		assert(dn2 != nullptr);

		if (!isBuiltinVariable(var)) {
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): %u "
			    "is not a built-in variable",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo, var);
		}

		if (DIF_INSTR_OP(dn2->getInstruction()) != DIF_OP_SETX) {
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): %%r%u "
			    "is not assigned by a SETX instruction @ %zu",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo,
			    DIF_INSTR_R2(instr), dn2->uidx);
		}

		setBuiltinType(n, var, dn2->integer.value());
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_LDLS:
		/*
		 *           var : t
		 * ----------------------------
		 *  ldls var, %r1 => %r1 : t
		 */

		var = DIF_INSTR_VAR(instr);

		dif_var = linkerContext.getVarFromVarVec(var, DIFV_SCOPE_LOCAL,
		    DIFV_KIND_SCALAR);
		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to find variable "
			    "(%u, %d, %d)",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo, var,
			    DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);

		if (dnv == nullptr) {
			if (dif_var == nullptr) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): variable and dnv "
				    "don't exist\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo);
				return (-1);
			} else {
				n->ctfid = dif_var->dtdv_ctfid;
				n->tf = v2tf(dif_var->dtdv_tf);
				n->dType = dif_var->dtdv_type.dtdt_kind;
				n->sym = dif_var->dtdv_sym;
				TYPING_LOG_DEFAULT(opcode, n);
				return (n->dType);
			}
		}

		if (dif_var != nullptr) {
			if (dif_var->dtdv_type.dtdt_kind != dnv->dType) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): type "
				    "mismatch %d != %d\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    dif_var->dtdv_type.dtdt_kind, dn1->dType);
				return (-1);
			}

			if (dif_var->dtdv_ctfid != dnv->ctfid) {
				if (dnv->tf->getTypename(dnv->ctfid, buf,
					sizeof(buf)) != ((char *)buf))
					dt_set_progerr(dtp, pgp,
					    "inferNode(%s, %zu@%p): failed at "
					    "getting type name %ld for dnv: %s",
					    insname[opcode].c_str(), n->uidx,
					    n->difo, dnv->ctfid,
					    dnv->tf->getErrMsg());

				if (v2tf(dif_var->dtdv_tf)
					->getTypename(dif_var->dtdv_ctfid,
					    var_type, sizeof(var_type)) !=
				    ((char *)var_type))
					dt_set_progerr(dtp, pgp,
					    "inferNode(%s, %zu@%p): failed at "
					    "getting type name %ld for dif_var: %s",
					    insname[opcode].c_str(), n->uidx,
					    n->difo, dif_var->dtdv_ctfid,
					    v2tf(dif_var->dtdv_tf)
						->getErrMsg());

				fprintf(stderr,
				    "inferNode(%s, %zu@%p): variable ctf type "
				    "mismatch %s != %s\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    buf, var_type);
				return (-1);
			}

			if (dnv->sym && dif_var->dtdv_sym == nullptr) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): symbol "
				    "mismatch %s != nullptr\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    dnv->sym);
				return (-1);
			}

			if (dnv->sym == nullptr && dif_var->dtdv_sym) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): symbol "
				    "mismatch nullptr != %s\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    dif_var->dtdv_sym);
				return (-1);
			}

			if (strcmp(dif_var->dtdv_sym, dnv->sym) != 0) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): symbol "
				    "mismatch %s != %s\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    dnv->sym, dif_var->dtdv_sym);
				return (-1);
			}
		}

		n->ctfid = dnv->ctfid;
		n->tf = dnv->tf;
		n->dType = dnv->dType;
		n->mip = dnv->mip;
		n->sym = dnv->sym;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_LDGS:
		/*
		 *           var : t
		 * ----------------------------
		 *  ldgs var, %r1 => %r1 : t
		 */

		var = DIF_INSTR_VAR(instr);

		dif_var = linkerContext.getVarFromVarVec(var, DIFV_SCOPE_GLOBAL,
		    DIFV_KIND_SCALAR);

		assert(dn1 == nullptr);
		if (isBuiltinVariable(var)) {
			setBuiltinType(n, var, 0);
			TYPING_LOG_DEFAULT(opcode, n);
			return (n->dType);
		} else if (dif_var == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): variable %d and "
			    "dn1 don't exist\n",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo,
			    var);
			return (-1);
		} else {
			n->ctfid = dif_var->dtdv_ctfid;
			n->tf = v2tf(dif_var->dtdv_tf);
			n->dType = dif_var->dtdv_type.dtdt_kind;
			n->sym = dif_var->dtdv_sym;
			TYPING_LOG_DEFAULT(opcode, n);
			return (n->dType);
		}

		if (dif_var != nullptr) {
			if (dif_var->dtdv_type.dtdt_kind != dn1->dType) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): type "
				    "mismatch %d != %d\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    dif_var->dtdv_type.dtdt_kind, dn1->dType);
				return (-1);
			}

			if (v2tf(dif_var->dtdv_tf) != dn1->tf) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): variable typefile "
				    "is %s, but dn1 typefile is %s\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    v2tf(dif_var->dtdv_tf)->name().c_str(),
				    dn1->tf->name().c_str());
				return (-1);
			}

			if (dif_var->dtdv_ctfid != dn1->ctfid) {
				if (dn1->tf->getTypename(dn1->ctfid, buf,
					sizeof(buf)) != ((char *)buf))
					dt_set_progerr(dtp, pgp,
					    "inferNode(%s, %zu@%p): failed at "
					    "getting type name %ld: %s\n",
					    insname[opcode].c_str(), n->uidx,
					    n->difo, dn1->ctfid,
					    dn1->tf->getErrMsg());

				if (v2tf(dif_var->dtdv_tf)
					->getTypename(dif_var->dtdv_ctfid,
					    var_type, sizeof(var_type)) !=
				    ((char *)var_type))
					dt_set_progerr(dtp, pgp,
					    "inferNode(%s, %zu@%p): failed at "
					    "getting type name %ld: %s\n",
					    insname[opcode].c_str(), n->uidx,
					    n->difo, dn1->ctfid,
					    v2tf(dif_var->dtdv_tf)
						->getErrMsg());

				fprintf(stderr,
				    "inferNode(%s, %zu@%p): variable ctf type "
				    "mismatch %s != %s\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    buf, var_type);
				return (-1);
			}

			if (dn1->sym && dif_var->dtdv_sym == nullptr) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): symbol "
				    "mismatch %s != nullptr\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    dn1->sym);
				return (-1);
			}

			if (dn1->sym == nullptr && dif_var->dtdv_sym) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): symbol "
				    "mismatch nullptr != %s\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    dif_var->dtdv_sym);
				return (-1);
			}

			if (strcmp(dif_var->dtdv_sym, dn1->sym) != 0) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): symbol "
				    "mismatch %s != %s\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    dn1->sym, dif_var->dtdv_sym);
				return (-1);
			}
		}

		n->ctfid = dn1->ctfid;
		n->tf = dn1->tf;
		n->dType = dn1->dType;
		n->mip = dn1->mip;
		n->sym = dn1->sym;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_LDTS:
		/*
		 *           var : t
		 * ----------------------------
		 *  ldts var, %r1 => %r1 : t
		 */

		var = DIF_INSTR_VAR(instr);

		dif_var = linkerContext.getVarFromVarVec(var, DIFV_SCOPE_THREAD,
		    DIFV_KIND_SCALAR);
		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to find variable "
			    "(%u, %d, %d)",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo, var,
			    DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR);

		if (dn1 == nullptr) {
			if (dif_var == nullptr) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): variable "
				    "and dn1 don't exist\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo);
				return (-1);
			} else {
				n->ctfid = dif_var->dtdv_ctfid;
				n->tf = v2tf(dif_var->dtdv_tf);
				n->dType = dif_var->dtdv_type.dtdt_kind;
				n->sym = dif_var->dtdv_sym;
				TYPING_LOG_DEFAULT(opcode, n);
				return (n->dType);
			}
		}

		if (dif_var != nullptr) {
			if (dif_var->dtdv_type.dtdt_kind != dn1->dType) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): type "
				    "mismatch %d != %d\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    dif_var->dtdv_type.dtdt_kind, dn1->dType);
				return (-1);
			}

			if (dif_var->dtdv_ctfid != dn1->ctfid) {
				if (dn1->tf->getTypename(dn1->ctfid, buf,
					sizeof(buf)) != ((char *)buf))
					dt_set_progerr(dtp, pgp,
					    "inferNode(%s, %zu@%p): failed at "
					    "getting type name %ld: %s\n",
					    insname[opcode].c_str(), n->uidx,
					    n->difo, dn1->ctfid,
					    dn1->tf->getErrMsg());

				if (v2tf(dif_var->dtdv_tf)
					->getTypename(dif_var->dtdv_ctfid,
					    var_type, sizeof(var_type)) !=
				    ((char *)var_type))
					dt_set_progerr(dtp, pgp,
					    "inferNode(%s, %zu@%p): failed at "
					    "getting type name %ld: %s\n",
					    insname[opcode].c_str(), n->uidx,
					    n->difo, dn1->ctfid,
					    v2tf(dif_var->dtdv_tf)
						->getErrMsg());

				fprintf(stderr,
				    "inferNode(%s, %zu@%p): variable ctf type "
				    "mismatch %s != %s\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    buf, var_type);
				return (-1);
			}

			if (dn1->sym && dif_var->dtdv_sym == nullptr) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): symbol "
				    "mismatch %s != nullptr\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    dn1->sym);
				return (-1);
			}

			if (dn1->sym == nullptr && dif_var->dtdv_sym) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): symbol "
				    "mismatch nullptr != %s\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    dif_var->dtdv_sym);
				return (-1);
			}

			if (strcmp(dif_var->dtdv_sym, dn1->sym) != 0) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): symbol "
				    "mismatch %s != %s\n",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    dn1->sym, dif_var->dtdv_sym);
				return (-1);
			}
		}

		n->ctfid = dn1->ctfid;
		n->tf = dn1->tf;
		n->dType = dn1->dType;
		n->mip = dn1->mip;
		n->sym = dn1->sym;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_STGS:
		/*
		 *  %r1 : t       var notin builtins
		 *         var in var_list
		 *         var_list @ var = t
		 * ----------------------------------
		 *     stgs %r1, var => var : t
		 *
		 *  %r1 : t       var notin builtins
		 *         var notin var_list
		 * ----------------------------------
		 *     stgs %r1, var => var : t /\
		 *        update var_list var t
		 */

		var = DIF_INSTR_VAR(instr);

		/*
		 * If we are doing a STGS, and the variable is a builtin
		 * variable, we fail to type-check the instruction.
		 */
		if (isBuiltinVariable(var)) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): trying to store to a "
			    "builtin variable\n",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo);
			return (-1);
		}

		if (dn2 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): dn2 is nullptr in stgs.\n",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo);
			return (-1);
		}

		dif_var = linkerContext.getVarFromVarVec(var, DIFV_SCOPE_GLOBAL,
		    DIFV_KIND_SCALAR);

		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to find "
			    "variable (%u, %d, %d)",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo, var,
			    DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR);

		if (inferVar(dn2, dif_var) == -1)
			return (-1);

		n->ctfid = dif_var->dtdv_ctfid;
		n->tf = v2tf(dif_var->dtdv_tf);
		n->dType = dif_var->dtdv_type.dtdt_kind;
		n->mip = dn2->mip;
		n->sym = dn2->sym;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_STTS:
		/*
		 *             %r1 : t
		 *         var in var_list
		 *         var_list @ var = t
		 * ----------------------------------
		 *     stts %r1, var => var : t
		 *
		 *              %r1 : t
		 *         var notin var_list
		 * ----------------------------------
		 *     stts %r1, var => var : t /\
		 *        update var_list var t
		 */

		var = DIF_INSTR_VAR(instr);

		if (dn2 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): dn2 is nullptr in stts.\n",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo);
			return (-1);
		}

		dif_var = linkerContext.getVarFromVarVec(var, DIFV_SCOPE_THREAD,
		    DIFV_KIND_SCALAR);
		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to find "
			    "variable (%u, %d, %d)",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo, var,
			    DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR);

		if (inferVar(dn2, dif_var) == -1)
			return (-1);

		n->ctfid = dif_var->dtdv_ctfid;
		n->tf = v2tf(dif_var->dtdv_tf);
		n->dType = dif_var->dtdv_type.dtdt_kind;
		n->mip = dn2->mip;
		n->sym = dn2->sym;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_STLS:
		/*
		 *             %r1 : t
		 *         var in var_list
		 *         var_list @ var = t
		 * ----------------------------------
		 *     stls %r1, var => var : t
		 *
		 *              %r1 : t
		 *         var notin var_list
		 * ----------------------------------
		 *     stls %r1, var => var : t /\
		 *        update var_list var t
		 */

		var = DIF_INSTR_VAR(instr);

		if (dn2 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): dn2 is nullptr in stls.\n",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo);
			return (-1);
		}

		dif_var = linkerContext.getVarFromVarVec(var, DIFV_SCOPE_LOCAL,
		    DIFV_KIND_SCALAR);
		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to find "
			    "variable (%u, %d, %d)",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo, var,
			    DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);

		if (inferVar(dn2, dif_var) == -1)
			return (-1);

		n->ctfid = dn2->ctfid;
		n->tf = dn2->tf;
		n->dType = dn2->dType;
		n->mip = dn2->mip;
		n->sym = dn2->sym;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_LDTA:
		break;
	case DIF_OP_CALL: {
		/*
		 *     subr : t1 -> t2 ... -> tn -> t
		 *  stack[0] : t1    stack[1] : t2     ...
		 *  stack[n-1] : tn        m = stacklen - 1
		 *                m >= n
		 * ----------------------------------------
		 *       call subr, %r1 => %r1 : t
		 */
		int type = inferSubr(n, stack);
		TYPING_LOG_DEFAULT(opcode, n);
		return (type);
	}

	case DIF_OP_LDGAA:
		var = DIF_INSTR_VAR(instr);

		dif_var = linkerContext.getVarFromVarVec(var, DIFV_SCOPE_GLOBAL,
		    DIFV_KIND_ARRAY);
		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to find "
			    "variable (%u, %d, %d)",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo, var,
			    DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY);

		/*
		 * If the stack is empty, this instruction makes no sense.
		 */
		if (n->stacks.empty()) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): stack list is "
			    "empty in ldgaa\n",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo);
			return (-1);
		}

		/*
		 * Make sure the stack contains what we expect
		 */
		if (checkVarStack(n, dnv, dif_var) == -1)
			return (-1);

		if (inferVar(dnv, dif_var) == -1)
			return (-1);

		if (dnv) {
			n->ctfid = dnv->ctfid;
			n->tf = dnv->tf;
			n->dType = dnv->dType;
			n->mip = dnv->mip;
			n->sym = dnv->sym;
		} else {
			n->ctfid = dif_var->dtdv_ctfid;
			n->tf = v2tf(dif_var->dtdv_tf);
			n->dType = dif_var->dtdv_type.dtdt_kind;
			n->sym = dif_var->dtdv_sym;
		}

		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_LDTAA:
		var = DIF_INSTR_VAR(instr);

		dif_var = linkerContext.getVarFromVarVec(var, DIFV_SCOPE_THREAD,
		    DIFV_KIND_ARRAY);
		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): "
			    "failed to find variable (%u, %d, %d)",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo, var,
			    DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY);

		/*
		 * If the stack is empty, this instruction makes no sense.
		 */
		if (n->stacks.empty()) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): stack list is "
			    "empty in ldgaa\n",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo);
			return (-1);
		}

		/*
		 * Make sure the stack contains what we expect
		 */
		if (checkVarStack(n, dnv, dif_var) == -1)
			return (-1);

		if (inferVar(dnv, dif_var) == -1)
			return (-1);

		if (dnv) {
			n->ctfid = dnv->ctfid;
			n->tf = dnv->tf;
			n->dType = dnv->dType;
			n->mip = dnv->mip;
			n->sym = dnv->sym;
		} else {
			n->ctfid = dif_var->dtdv_ctfid;
			n->tf = v2tf(dif_var->dtdv_tf);
			n->dType = dif_var->dtdv_type.dtdt_kind;
			n->sym = dif_var->dtdv_sym;
		}

		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	/*
	 * FIXME(dstolfa): Handle STGAAs to struct types.
	 */
	case DIF_OP_STGAA:
		if (dn2 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): dn2 is nullptr in "
			    "stgaa.\n",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo);
			return (-1);
		}

		var = DIF_INSTR_VAR(instr);

		dif_var = linkerContext.getVarFromVarVec(var, DIFV_SCOPE_GLOBAL,
		    DIFV_KIND_ARRAY);
		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): "
			    "failed to find variable (%u, %d, %d)",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo, var,
			    DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY);

		/*
		 * We compare the first seen stack and the current possible
		 * stacks in order to make sure that we aren't doing something
		 * like:
		 *
		 *  x[curthread] = 1;
		 *  x[tid] = 2;
		 */

		if (checkVarStack(n, dn2, dif_var) == -1)
			return (-1);

		if (inferVar(dn2, dif_var) == -1)
			return (-1);

		if (dn2->dType != DIF_TYPE_BOTTOM) {
			n->ctfid = dn2->ctfid;
			n->tf = dn2->tf;
			n->dType = dn2->dType;
			n->mip = dn2->mip;
			n->sym = dn2->sym;
		} else {
			n->ctfid = dif_var->dtdv_ctfid;
			n->tf = v2tf(dif_var->dtdv_tf);
			n->dType = dif_var->dtdv_type.dtdt_kind;
			n->mip = dn2->mip;
			n->sym = dn2->sym;
		}

		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_STTAA:
		if (dn2 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): dn2 is nullptr in sttaa.\n",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo);
			return (-1);
		}

		var = DIF_INSTR_VAR(instr);

		dif_var = linkerContext.getVarFromVarVec(var, DIFV_SCOPE_THREAD,
		    DIFV_KIND_ARRAY);
		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to find "
			    "variable (%u, %d, %d)",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo, var,
			    DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY);

		/*
		 * We compare the first seen stack and the current possible
		 * stacks in order to make sure that we aren't doing something
		 * like:
		 *
		 *  self->x[curthread] = 1;
		 *  self->x[tid] = 2;
		 */
		if (checkVarStack(n, dn2, dif_var) == -1)
			return (-1);

		if (inferVar(dn2, dif_var) == -1)
			return (-1);

		n->ctfid = dn2->ctfid;
		n->tf = dn2->tf;
		n->dType = dn2->dType;
		n->mip = dn2->mip;
		n->sym = dn2->sym;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_ALLOCS:
		n->ctfid = CTF_ERR;
		n->tf = nullptr;
		n->dType = DIF_TYPE_BOTTOM;
		n->mip = nullptr;
		n->sym = nullptr;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_COPYS:
		n->ctfid = dn1->ctfid;
		n->tf = dn1->tf;
		n->dType = dn1->dType;
		n->mip = dn1->mip;
		n->sym = dn1->sym;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_RET:
		/*
		 * Only do this if it's a CTF type. We might be coming from a
		 * typecast.
		 */
		if (dn1->sym != nullptr) {
			/*
			 * We only need one type here (the first one).
			 */
			mip = getMipFromSymbol(dn1);
			if (mip == nullptr) {
				dt_set_progerr(dtp, pgp,
				    "%s(%s, %zu@%p): failed to get mip from symbol (%s)",
				    __func__, insname[opcode].c_str(), n->uidx,
				    n->difo, dn1->sym);
				return (-1);
			}

			n->mip = mip;
			n->tf = dn1->tf;
			n->ctfid = mip->ctm_type;
			n->dType = DIF_TYPE_CTF;
		} else {
			n->ctfid = dn1->ctfid;
			n->tf = dn1->tf;
			n->dType = dn1->dType;
		}

		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);

	case DIF_OP_PUSHTR:
		if (dn1 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): pushtr dn1 is nullptr\n",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo);
			return (-1);
		}

		if (dn1->sym != nullptr) {
			/*
			 * We only need one type here (the first one).
			 */

			mip = getMipFromSymbol(dn1);
			if (mip == nullptr) {
				dt_set_progerr(dtp, pgp,
				    "%s(%s, %zu@%p): failed to get mip from symbol (%s)",
				    __func__, insname[opcode].c_str(), n->uidx,
				    n->difo, dn1->sym);
				return (-1);
			}

			n->mip = mip;
			n->ctfid = mip->ctm_type;
			n->tf = dn1->tf;
			n->dType = DIF_TYPE_CTF;
		} else if (dn1->dType == DIF_TYPE_CTF) {
			n->ctfid = dn1->ctfid;
			n->tf = dn1->tf;
			n->dType = dn1->dType;
		} else
			/*
			 * XXX: Do we need to store the typefile here?
			 */
			n->dType = dn1->dType;

		TYPING_LOG_DEFAULT(opcode, n);
		return (DIF_TYPE_NONE);

	case DIF_OP_PUSHTV:
		n->ctfid = dn1->ctfid;
		n->tf = dn1->tf;
		n->dType = dn1->dType;
		TYPING_LOG_DEFAULT(opcode, n);
		return (DIF_TYPE_NONE);

	case DIF_OP_FLUSHTS:
	case DIF_OP_POPTS:
	case DIF_OP_CMP:
	case DIF_OP_SCMP:
	case DIF_OP_HYPERCALL:
	case DIF_OP_TST:
	case DIF_OP_BA:
	case DIF_OP_BE:
	case DIF_OP_BNE:
	case DIF_OP_BG:
	case DIF_OP_BGU:
	case DIF_OP_BGE:
	case DIF_OP_BGEU:
	case DIF_OP_BL:
	case DIF_OP_BLU:
	case DIF_OP_BLE:
	case DIF_OP_BLEU:
	case DIF_OP_NOP:
		return (DIF_TYPE_NONE);

	case DIF_OP_STB:
	case DIF_OP_STH:
	case DIF_OP_STW:
	case DIF_OP_STX: {
		int insid;

		insid = opcode - DIF_OP_STB;
		assert(insid >= 0 && insid <= 3);

		assert(dn1 != nullptr);
		assert(dn2 != nullptr); /* the destination register source */

		/*
		 * If we reach a ST instruction, we need to make sure that we
		 * didn't do so by having a string or an uninitialized node.
		 */
		if (dn1->dType == DIF_TYPE_STRING)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): can't store from a "
			    "string type (loc %zu)",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo,
			    dn1->uidx);

		if (dn1->dType == DIF_TYPE_NONE)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): can't store "
			    "from type none (loc %zu)",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo,
			    dn1->uidx);

		/*
		 * If there is no symbol associated with our stx, this might
		 * have come from a translator which was resolved before this
		 * step. We just skip this instruction, as nothing will actually
		 * have this as a source.
		 */
		if (dn1->sym == nullptr) {
			n->dType = dn2->dType;
			n->ctfid = dn2->ctfid;
			n->tf = dn2->tf;
			TYPING_LOG_DEFAULT(opcode, n);
			return (n->dType);
		}

		// Find the variable and ensure that their types match up.
		// XXX(dstolfa): We don't actually check against all the
		// possible paths, and instead just work with varsources. This
		// is technically wrong, but it will do for the prototype.
		dif_var = TypeInference::findVariableFromNodeDefs(n->r1Defs);
		if (dif_var == nullptr) {
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): register [%%r%d] "
			    "is not within a variable",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo,
			    n->getRD());
		}
		if (dif_var->dtdv_type.dtdt_kind != DIF_TYPE_CTF) {
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): instruction only "
			    "makes sense on CTF variable types, got %d",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo,
			    dif_var->dtdv_type.dtdt_kind);
		}
		if (v2tf(dif_var->dtdv_tf)
		    ->getTypename(dif_var->dtdv_ctfid, buf,
		    sizeof(var_type)) != ((char *)var_type))
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed getting "
			    "type name %ld: %s",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo,
			    dif_var->dtdv_ctfid, v2tf(dif_var->dtdv_tf)->getErrMsg());
		for (auto var : n->varSources) {
			if (v2tf(var->dtdv_tf)
			    ->getTypename(var->dtdv_ctfid, buf,
			    sizeof(var_type)) != ((char *)buf))
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): failed getting "
				    "type name %ld: %s",
				    insname[opcode].c_str(), n->uidx,
				    (void *)n->difo, var->dtdv_ctfid,
				    v2tf(var->dtdv_tf)->getErrMsg());

			// We don't need to compare the variables against each
			// other because if they're equal fo dif_var, they will
			// be equal to each other.
			if (!TypeInference::varEqualCTF(dif_var, var)) {
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): node has a "
				    "mismatch in variable sources with "
				    "inferred variable: (%u, %u, %u) : %s@%s !="
				    " (%u, %u, %u) : %s@%s",
				    insname[opcode].c_str(), n->uidx,
				    (void *)n->difo, dif_var->dtdv_id,
				    dif_var->dtdv_scope, var_type,
				    n->tf->name().c_str(), dif_var->dtdv_kind,
				    var->dtdv_id, var->dtdv_scope,
				    var->dtdv_kind, buf,
				    v2tf(var->dtdv_tf)->name().c_str());
			}
		}

		ctf_id_t varkind =
		    v2tf(dif_var->dtdv_tf)->getKind(dif_var->dtdv_ctfid);

		/*
		 * Only accept structs for now -- but we might need to handle
		 * unions and arrays at some point too.
		 */
		if (varkind != CTF_K_STRUCT)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): expected a struct CTF "
			    "kind, got %d",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo, varkind);

		/*
		 * At this point, we should have a membinfo pointer to the field
		 * that we will be accessing.
		 */
		mip = (ctf_membinfo_t *)malloc(sizeof(ctf_membinfo_t));
		if (mip == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): malloc failed on "
			    "mip: %s",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo,
			    strerror(errno));

		memset(mip, 0, sizeof(ctf_membinfo_t));

		if (v2tf(dif_var->dtdv_tf)
		    ->getMembInfo(dif_var->dtdv_ctfid, dn1->sym, mip) == 0)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get "
			    "member info: %s",
			    insname[opcode].c_str(), n->uidx, (void *)n->difo,
			    v2tf(dif_var->dtdv_tf)->getErrMsg());

		/*
		 * If dn1 is a CTF type, we will actually type-check that
		 * we are storing a meaningful type to the destination. If
		 * instead it is a bottom type, we will simply accept whatever
		 * the type is and store it anyway.
		 */
		if (dn1->dType == DIF_TYPE_CTF) {
			/*
			 * We will be checking all of the compatible types too,
			 * but we start with these.
			 */
			Array<String, 4> dst_type = { "uint8_t", "uint16_t",
				"uint32_t", "uint64_t" };
			ctf_id_t dst_ctfid;

			if (dn1->tf->getTypename(dn1->ctfid, buf,
				sizeof(buf)) != (char *)buf)
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): failed getting "
				    "type_name of %d: %s",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    dn1->ctfid, dn1->tf->getErrMsg());

			if (v2tf(dif_var->dtdv_tf)
			    ->getTypename(dif_var->dtdv_ctfid, var_type,
			    sizeof(var_type)) != (char *)var_type)
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): failed getting "
				    "type_name of %d: %s",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    dif_var->dtdv_ctfid,
				    v2tf(dif_var->dtdv_tf)->getErrMsg());

			auto ktf = dt_typefile_kernel();
			dst_ctfid = ktf->getCtfID(dst_type[insid].c_str());
			if (dst_ctfid == CTF_ERR)
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): failed getting "
				    "ctfid from %s for %s: %s",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    ktf->name().c_str(),
				    dst_type[insid].c_str(), ktf->getErrMsg());

			if (v2tf(dif_var->dtdv_tf)
			    ->typeIsCompatibleWith(dst_ctfid, dn1->tf,
			    dn1->ctfid) == 0)
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): types %s "
				    "(variable field) and %s "
				    "(instruction %zu) are not compatible",
				    insname[opcode].c_str(), n->uidx, (void *)n->difo,
				    var_type, buf, dn1->uidx);
		}

		n->dType = dn2->dType;
		n->ctfid = dn2->ctfid;
		n->tf = dn2->tf;
		TYPING_LOG_DEFAULT(opcode, n);
		return (n->dType);
	} /* case DIF_OP_STX */
	default:
		dt_set_progerr(dtp, pgp, "unhandled instruction: %u", opcode);
	}

	return (-1);
}

int
TypeInference::inferDIFO(dtrace_difo_t *difo)
{
	/*
	 * A DIFO without instructions makes no sense.
	 */
	if (difo->dtdo_buf == nullptr) {
		setErrorMessage("DIFO has no instructions\n");
		return (E_HYPERTRACE_TYPING);
	}
	/*
	 * If we don't have a table, length MUST be 0.
	 */
	if (difo->dtdo_inttab == nullptr && difo->dtdo_intlen != 0) {
		setErrorMessage("inttab length is %zu but inttab is NULL\n",
		    difo->dtdo_intlen);
		return (E_HYPERTRACE_TYPING);
	}
	if (difo->dtdo_strtab == nullptr && difo->dtdo_strlen != 0) {
		setErrorMessage("strtab length is %zu but strtab is NULL\n",
		    difo->dtdo_strlen);
		return (E_HYPERTRACE_TYPING);
	}
	if (difo->dtdo_vartab == nullptr && difo->dtdo_varlen != 0) {
		setErrorMessage("vartab length is %zu but vartab is NULL\n",
		    difo->dtdo_varlen);
		return (E_HYPERTRACE_TYPING);
	}
	if (difo->dtdo_symtab == nullptr && difo->dtdo_symlen != 0) {
		setErrorMessage("symtab length is %zu but symtab is NULL\n",
		    difo->dtdo_symlen);
		return (E_HYPERTRACE_TYPING);
	}
	/*
	 * If the symbol length is 0 and the symbol table is 0, we don't
	 * have any relocations to apply. In this case, we just return that
	 * no error occurred and leave the DIFO as it is.
	 */
	if (difo->dtdo_symtab == nullptr)
		return (E_HYPERTRACE_NONE);
	if (pgp == nullptr) {
		setErrorMessage("program is NULL\n");
		return (E_HYPERTRACE_TYPING);
	}
	if (dtp == nullptr) {
		setErrorMessage("dtrace handle is NULL\n");
		return (E_HYPERTRACE_TYPING);
	}

	difo->dtdo_types = (char **)dt_zalloc(dtp,
	    sizeof(char *) * difo->dtdo_len);
	if (difo->dtdo_types == nullptr)
		dt_set_progerr(dtp, pgp, "failed to malloc dtdo_types");

	_HYPERTRACE_LOG_TYPING("walking over nodes to infer types\n");
	for (auto &node : linkerContext.dfgNodes) {
		if (node.get() == linkerContext.getR0Node())
			continue;
		if (node->DIFOBuf() == nullptr)
			continue;
		if (node->DIFOBuf() != difo->dtdo_buf)
			continue;
		int type = inferNode(node.get());
		assert(type == -1 || type == DIF_TYPE_CTF ||
		    type == DIF_TYPE_STRING || type == DIF_TYPE_NONE ||
		    type == DIF_TYPE_BOTTOM);

		if (type == -1) {
			return (E_HYPERTRACE_TYPING);
		}

		if (type == DIF_TYPE_CTF) {
			if (node->tf == nullptr)
				dt_set_progerr(dtp, pgp,
				    "%s(): typefile nullptr at %zu@%p\n",
				    __func__, node->uidx, node->difo);

			auto opt = node->tf->getTypename(node->ctfid);
			if (!opt.has_value())
				dt_set_progerr(dtp, pgp,
				    "inferDIFO(): failed at getting "
				    "type name %ld: %s (DIFO %p, node %zu)",
				    node->ctfid, node->tf->getErrMsg(),
				    node->difo, node->uidx);

			difo->dtdo_types[node->uidx] = strdup(
			    opt.value().c_str());
		} else if (type == DIF_TYPE_STRING)
			difo->dtdo_types[node->uidx] = strdup("string");
		else if (type == DIF_TYPE_NONE)
			difo->dtdo_types[node->uidx] = strdup("none");
		else if (type == DIF_TYPE_BOTTOM)
			difo->dtdo_types[node->uidx] = strdup("bottom");
		else
			difo->dtdo_types[node->uidx] = strdup("ERROR");
	}
	_HYPERTRACE_LOG_TYPING("successfully inferred all the types\n");
	return (0);
}

}
