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
#include <sys/param.h>
#include <sys/linker.h>

#include <sys/dtrace.h>

#include <dtrace.h>

#include <dt_impl.h>
#include <dt_program.h>

#include <dt_dfg.hh>
#include <dt_basic_block.hh>
#include <dt_dfg.hh>
#include <dt_linker_subr.hh>
#include <dt_typefile.hh>
#include <dt_typing.hh>
#include <dt_hypertrace_linker.hh>

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <err.h>
#include <errno.h>

#ifndef illumos
#include <sys/sysctl.h>
#endif

namespace dtrace {

HyperTraceLinker::HyperTraceLinker(dtrace_hdl_t *_dtp, dtrace_prog_t *_pgp)
    : dtp(_dtp)
    , pgp(_pgp)
{
}

void
HyperTraceLinker::setErrorMessage(const char *fmt, ...)
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

int
HyperTraceLinker::patchUsetxDefs(DFGNode *n)
{
	if (n == nullptr)
		return (E_HYPERTRACE_NONE);
	if (n->difo == nullptr)
		return (E_HYPERTRACE_NONE);
	if (n->mip == nullptr)
		return (E_HYPERTRACE_NONE);

	uint16_t offset = n->mip->ctm_offset / 8 /* bytes */;
	for (auto node : n->usetxDefs) {
		if (node->isRelocated)
			continue;

		dif_instr_t instr = node->getInstruction();
		uint8_t opcode = DIF_INSTR_OP(instr);
		if (opcode != DIF_OP_USETX) {
			setErrorMessage("opcode (%d @ %u) is not usetx", opcode,
			    node->uidx);
			return (E_HYPERTRACE_LINKING);
		}

		uint8_t rd = DIF_INSTR_RD(instr);
		if (n->difo->dtdo_inthash == nullptr) {
			n->difo->dtdo_inthash = dt_inttab_create(dtp);
			if (n->difo->dtdo_inthash == nullptr) {
				setErrorMessage("failed to allocate inttab");
				return (E_HYPERTRACE_LIBDTRACE);
			}
		}

		int index = dt_inttab_insert(n->difo->dtdo_inthash, offset, 0);
		if (index == -1) {
			setErrorMessage("failed to insert %" PRIu64
					" into inthash",
			    offset);
			return (E_HYPERTRACE_LIBDTRACE);
		}

		node->Instruction() = DIF_INSTR_SETX(index, rd);
		node->isRelocated = true;
	}
	return (E_HYPERTRACE_NONE);
}

int
HyperTraceLinker::relocateUloadOrAdd(DFGNode *node)
{
	dif_instr_t instr = node->getInstruction();
	uint8_t opcode = DIF_INSTR_OP(instr);
	ctf_id_t ctfid, kind;
	size_t size;
	if (opcode == DIF_OP_ADD)
		goto usetx_relo;

	ctfid = node->tf->resolve(node->mip->ctm_type);
	size = node->tf->getSize(ctfid);
	kind = node->tf->getKind(ctfid);
	/*
	 * NOTE: We support loading of CTF_K_ARRAY due to it
	 * just being a pointer, really.
	 */
	if (kind != CTF_K_INTEGER && kind != CTF_K_POINTER &&
	    kind != CTF_K_ARRAY) {
		setErrorMessage("a load of kind %zu is unsupported in DIF.",
		    kind);
		return (E_HYPERTRACE_LINKING);
	}

	dif_instr_t new_instr;
	uint8_t new_op, rd, r1;
	if (kind == CTF_K_POINTER || kind == CTF_K_ARRAY) {
		new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDX : DIF_OP_ULDX;
		rd = DIF_INSTR_RD(instr);
		r1 = DIF_INSTR_R1(instr);

		new_instr = DIF_INSTR_LOAD(new_op, r1, rd);
	} else {
		ctf_encoding_t encoding;
		if (node->tf->getEncoding(ctfid, &encoding) != 0) {
			setErrorMessage("failed to get encoding for %ld",
			    ctfid);
			return (E_HYPERTRACE_LINKING);
		}

		if (encoding.cte_format & CTF_INT_SIGNED) {
			if (size == 1)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDSB :
				    DIF_OP_ULDSB;
			else if (size == 2)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDSH :
				    DIF_OP_ULDSH;
			else if (size == 4)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDSW :
				    DIF_OP_ULDSW;
			else if (size == 8)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDX :
				    DIF_OP_ULDX;
			else {
				setErrorMessage("unsupported size %zu", size);
				return (E_HYPERTRACE_LINKING);
			}
		} else {
			if (size == 1)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDUB :
				    DIF_OP_ULDUB;
			else if (size == 2)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDUH :
				    DIF_OP_ULDUH;
			else if (size == 4)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDUW :
				    DIF_OP_ULDUW;
			else if (size == 8)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDX :
				    DIF_OP_ULDX;
			else {
				setErrorMessage("unsupported size %zu", size);
				return (E_HYPERTRACE_LINKING);
			}
		}

		rd = DIF_INSTR_RD(instr);
		r1 = DIF_INSTR_R1(instr);
		new_instr = DIF_INSTR_LOAD(new_op, r1, rd);
	}

usetx_relo:
	if (node->mip == nullptr) {
		if (node->sym == nullptr) {
			node->isRelocated = true;
			return (E_HYPERTRACE_NONE);
		}

		auto *mip = (ctf_membinfo_t *)dt_zalloc(dtp,
		    sizeof(ctf_membinfo_t));
		if (mip == nullptr) {
			setErrorMessage("malloc for mip failed: %s",
			    strerror(errno));
			return (E_HYPERTRACE_SYS);
		}
		auto type = node->tf->getReference(node->ctfid);
		if (node->tf->getMembInfo(type, node->sym, mip) == 0) {
			dt_set_progerr(dtp, pgp,
			    "%s(%p[%zu]): failed to get mip: %s.%s: %s\n",
			    __func__, node->difo, node->uidx,
			    node->tf->getTypename(node->ctfid)
				.value_or("UNKNOWN")
				.c_str(),
			    node->sym, node->tf->getErrMsg());
		}
		node->mip = mip;
	}

	int e = patchUsetxDefs(node);
	if (e)
		return (e);
	if (opcode != DIF_OP_ADD)
		node->Instruction() = new_instr;
	node->isRelocated = true;
	return (E_HYPERTRACE_NONE);
}

int
HyperTraceLinker::relocateRetOrPush(DFGNode *node)
{
	/*
	 * If this instruction does not come from a usetx,
	 * we don't really have to do anything with it.
	 */
	if (node->mip == nullptr)
		return (E_HYPERTRACE_NONE);
	return (patchUsetxDefs(node));
}

int
HyperTraceLinker::relocatePush(DFGNode *node)
{
	return (relocateRetOrPush(node));
}

static void
retCleanup(DFGNode *node, dtrace_diftype_t *rtype)
{
	/*
	 * We only need to clean up things if we return by reference
	 * currently.
	 */
	if ((rtype->dtdt_flags & DIF_TF_BYREF) == 0 &&
	    (rtype->dtdt_flags & DIF_TF_BYUREF) == 0)
		return;

	for (auto n : node->r1Defs) {
		dif_instr_t instr = n->getInstruction();
		uint8_t opcode = DIF_INSTR_OP(instr);

		switch (opcode) {
		case DIF_OP_ULOAD:
		case DIF_OP_UULOAD:
			break;

		case DIF_OP_LDUB:
		case DIF_OP_LDSB:
		case DIF_OP_LDUH:
		case DIF_OP_LDSH:
		case DIF_OP_LDUW:
		case DIF_OP_LDSW:
		case DIF_OP_LDX:
			n->Instruction() = DIF_INSTR_NOP;
			break;
		}
	}
}

int
HyperTraceLinker::relocateRet(DFGNode *node, dtrace_actkind_t actionKind,
    dtrace_actdesc_t *ad, dtrace_diftype_t *originalReturnType)
{
	/*
	 * In case of a RET, we first patch up the DIFO with the correct return
	 * type and size.
	 */
	dtrace_difo_t *difo = node->difo;
	dtrace_diftype_t *rtype = &difo->dtdo_rtype;

	rtype->dtdt_kind = node->dType;
	if (node->dType == DIF_TYPE_CTF)
		rtype->dtdt_ckind = node->ctfid;
	else if (node->dType == DIF_TYPE_STRING)
		rtype->dtdt_ckind = DT_STR_TYPE(dtp);
	else if (node->dType == DIF_TYPE_BOTTOM)
		/*
		 * If we have a bottom type, we really
		 * don't care which CTF type the host
		 * wants here. It can be patched in
		 * later on demand.
		 */
		rtype->dtdt_ckind = CTF_BOTTOM_TYPE;
	else {
		setErrorMessage(
		    "unexpected node->din_type (%x@%p) at location %zu",
		    node->dType, (void *)node->difo, node->uidx);
		return (E_HYPERTRACE_LINKING);
	}

	assert(actionKind != DTRACEACT_NONE);
	if (actionKind != DTRACEACT_DIFEXPR)
		assert(ad != nullptr);

	switch (actionKind) {
	case DTRACEACT_EXIT:
		*rtype = dt_int_rtype;
		rtype->dtdt_size = sizeof(int);
		break;

	case DTRACEACT_PRINTA:
	case DTRACEACT_PRINTM:
	case DTRACEACT_TRACEMEM:
	case DTRACEACT_TRACEMEM_DYNSIZE:
		break;

	case DTRACEAGG_QUANTIZE:
	case DTRACEAGG_LQUANTIZE:
	case DTRACEAGG_LLQUANTIZE:
		break;

	case DTRACEACT_PRINTF:
	case DTRACEACT_DIFEXPR:
		if (ad && ad->dtad_return == 0) {
			*rtype = dt_void_rtype;
			break;
		}

		/*
		 * Fall through to the default case.
		 */
	default:
		if (node->mip == nullptr && rtype->dtdt_kind == DIF_TYPE_CTF) {
			int ctf_kind = node->tf->getKind(node->ctfid);

			/*
			 * XXX(dstolfa, important): Is this a sensible thing to
			 * be doing for all guests? We claim to know on the host
			 * whether or not we need to dereference something --
			 * but is that actually true? Need to think about this a
			 * bit more. On the guest, we lack the information about
			 * what takes a dereferenced value in, but on the host
			 * we lack type information.
			 */
			rtype->dtdt_flags = originalReturnType->dtdt_flags;
			if (ctf_kind == CTF_K_ARRAY) {
				rtype->dtdt_flags |= DIF_TF_BYREF;
			}

			retCleanup(node, rtype);

			if (rtype->dtdt_flags & DIF_TF_BYREF) {
				ctf_id_t return_ctfid = node->tf->getReference(
				    node->ctfid);
				/*
				 * FIXME:. This is very much a heuristic. This
				 * can probably be done better.
				 */
				return_ctfid = return_ctfid == CTF_ERR ?
				    node->ctfid :
				    return_ctfid;
				rtype->dtdt_size = node->tf->getSize(
				    return_ctfid);
			} else {
				rtype->dtdt_size = node->tf->getSize(
				    node->ctfid);
			}
		} else if (rtype->dtdt_kind == DIF_TYPE_BOTTOM) {
			/*
			 * We don't care what the size is, we just need to set
			 * the correct flags.
			 */
			rtype->dtdt_flags = originalReturnType->dtdt_flags;
		} else {
			rtype->dtdt_flags |= DIF_TF_BYREF;
		}

		break;
	}
	/*
	 * Safety guard
	 */
	if (node->dType == DIF_TYPE_STRING) {
		rtype->dtdt_flags |= DIF_TF_BYREF;
		rtype->dtdt_ckind = CTF_ERR;
	}
	return (relocateRetOrPush(node));
}

static void
patchSETXInstructions(NodeSet *setx_defs1, NodeSet *setx_defs2)
{
	NodeSet::iterator it1, it2;
	for (it1 = setx_defs1->begin(), it2 = setx_defs2->begin();
	     it1 != setx_defs1->end() && it2 != setx_defs2->end();
	     ++it1, ++it2) {
		auto sd1 = *it1;
		auto sd2 = *it2;

		sd1->Instruction() = DIF_INSTR_NOP;
		sd2->Instruction() = DIF_INSTR_NOP;
	}
}

static bool
checkSETXDefs(NodeSet *setx_defs1, NodeSet *setx_defs2)
{
	NodeSet::iterator it1, it2;

	for (it1 = setx_defs1->begin(), it2 = setx_defs2->begin();
	     it1 != setx_defs1->end() && it2 != setx_defs2->end();
	     ++it1, ++it2) {
		DFGNode *sd1, *sd2;
		dif_instr_t instr1, instr2;
		uint8_t op1;
		sd1 = *it1;
		sd2 = *it2;
		instr1 = sd1->getInstruction();
		instr2 = sd2->getInstruction();
		op1 = DIF_INSTR_OP(instr1);
		/*
		 * This is really the only thing we need to check here.
		 */
		if (op1 != DIF_OP_SETX || instr1 != instr2)
			return (false);
	}

	return (true);
}

int
HyperTraceLinker::relocateDFGNode(DFGNode *node, dtrace_actkind_t actionKind,
    dtrace_actdesc_t *ad, dtrace_difo_t *difo,
    dtrace_diftype_t *originalReturnType)
{
	if (node->difo != difo)
		return (E_HYPERTRACE_NONE);

	dif_instr_t instr = node->getInstruction();
	uint8_t opcode = DIF_INSTR_OP(instr);
	switch (opcode) {
	case DIF_OP_RET: {
		int e = relocateRet(node, actionKind, ad, originalReturnType);
		if (e)
			return (e);
		break;
	}

	case DIF_OP_PUSHTR: {
		int e = relocatePush(node);
		if (e)
			return (e);
		break;
	}

	case DIF_OP_PUSHTV: {
		/*
		 * Patch up the type we're pushing on the stack.
		 */
		uint8_t rs = DIF_INSTR_RS(instr);
		uint8_t rv = DIF_INSTR_R2(instr);
		dif_instr_t newinstr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV,
		    node->dType, rv, rs);
		node->Instruction() = newinstr;
		break;
	}

	case DIF_OP_ADD:
	case DIF_OP_ULOAD:
	case DIF_OP_UULOAD: {
		int e = relocateUloadOrAdd(node);
		if (e)
			return (e);
		break;
	}

	case DIF_OP_TYPECAST: {
		/*
		 * For typecast, we simply turn it into a nop. We only
		 * ever use typecast for type inference and can't
		 * actually execute it as an instruction. We will
		 * collapse the nops later.
		 */
		node->Instruction() = DIF_INSTR_NOP;
		if (node->uidx < 2) {
			node->isRelocated = true;
			break;
		}

		int e = patchUsetxDefs(node);
		if (e)
			return (e);
		uint16_t sym = DIF_INSTR_SYMBOL(instr);
		uint8_t currd = DIF_INSTR_RD(instr);
		if (sym >= difo->dtdo_symlen)
			dt_set_progerr(dtp, pgp,
			    "%s(): sym (%u) >= symlen (%zu)\n", __func__, sym,
			    difo->dtdo_symlen);

		String symname = String(difo->dtdo_symtab + sym);
		if (symname == "uintptr_t") {
			node->isRelocated = true;
			break;
		}
		/*
		 * Now we need to check if we have an sll followed by an sra as
		 * the previous two instructions. This can happen in the case
		 * sign extension is needed -- however we don't actually want to
		 * do this for an uintptr_t.
		 */
		for (auto ndef1 : node->r1Defs) {
			dif_instr_t idef1 = ndef1->getInstruction();
			uint8_t opdef1 = DIF_INSTR_OP(idef1);
			if (opdef1 != DIF_OP_SRA)
				continue;

			uint8_t r11 = DIF_INSTR_R1(idef1);
			uint8_t r21 = DIF_INSTR_R2(idef1);
			/*
			 * Figure out which register we need to look up the
			 * definitions for.
			 */
			NodeSet *defs = nullptr;
			NodeSet *setx_defs1 = nullptr;
			if (r11 == currd) {
				defs = &ndef1->r1Defs;
				setx_defs1 = &ndef1->r2Defs;
			}

			if (r21 == currd) {
				/*
				 * Assert that we don't have a sra %r1, %r1, %r1
				 * as that would be extremely weird.
				 */
				assert(defs == nullptr);
				assert(setx_defs1 == nullptr);
				defs = &ndef1->r2Defs;
				setx_defs1 = &ndef1->r1Defs;
			}

			if (defs == nullptr)
				continue;

			for (auto ndef2 : *defs) {
				dif_instr_t idef2 = ndef2->getInstruction();
				uint8_t opdef2 = DIF_INSTR_OP(idef2);
				if (opdef2 != DIF_OP_SLL)
					continue;

				uint8_t r12 = DIF_INSTR_R1(idef2);
				uint8_t r22 = DIF_INSTR_R2(idef2);
				uint8_t rd = DIF_INSTR_RD(idef2);
				NodeSet *setx_defs2 = nullptr;
				if (r12 == rd)
					setx_defs2 = &ndef2->r2Defs;
				if (r22 == rd)
					setx_defs2 = &ndef2->r1Defs;
				if (setx_defs2 == nullptr)
					continue;
				if (!checkSETXDefs(setx_defs1, setx_defs2))
					continue;
				ndef2->Instruction() = DIF_INSTR_NOP;
				ndef1->Instruction() = DIF_INSTR_NOP;
				patchSETXInstructions(setx_defs1, setx_defs2);
			}
		}
		node->isRelocated = true;
		break;
	}

	default:
		break;
	}
	return (E_HYPERTRACE_NONE);
}

int
HyperTraceLinker::relocateProgram(dtrace_actkind_t actionKind,
    dtrace_actdesc_t *ad, dtrace_difo_t *difo,
    dtrace_diftype_t *originalReturnType)
{
	if (difo->dtdo_inttab != nullptr) {
		assert(difo->dtdo_intlen != 0);
		assert(difo->dtdo_inthash == nullptr);

		difo->dtdo_inthash = dt_inttab_create(dtp);
		if (difo->dtdo_inthash == nullptr) {
			setErrorMessage("failed to allocate inthash");
			return (E_HYPERTRACE_LIBDTRACE);
		}

		for (uint_t i = 0; i < difo->dtdo_intlen; i++) {
			auto index = (uint_t)dt_inttab_insert(
			    difo->dtdo_inthash, difo->dtdo_inttab[i], 0);
			if (index != i) {
				setErrorMessage("failed to insert %" PRIu64
						", index = %d, expected %d",
				    difo->dtdo_inttab[i], index, i);
				return (E_HYPERTRACE_LIBDTRACE);
			}
		}
	}

	for (auto &n : dfgNodes) {
		if (n.get() == r0node)
			continue;
		int e = relocateDFGNode(n.get(), actionKind, ad, difo,
		    originalReturnType);
		if (e)
			return (e);
	}

	return (E_HYPERTRACE_NONE);
}

int
HyperTraceLinker::updateUsetxDefsInBB(dtrace_difo_t *difo, BasicBlock *bb, DFGNode *n)
{
	if (n->sym == nullptr) {
		setErrorMessage("usetx din_sym should not be nullptr");
		return (E_HYPERTRACE_LINKING);
	}

	for (auto &node : dfgNodes) {
		if (node.get() == r0node)
			continue;

		dif_instr_t instr = node->getInstruction();
		uint8_t opcode = DIF_INSTR_OP(instr);
		if (node.get() == n)
			continue;
		if (node->difo != difo)
			continue;
		if (n->uidx >= node->uidx)
			continue;
		if (node->uidx < bb->start || node->uidx > bb->end)
			continue;
		if (opcode == DIF_OP_ULOAD    ||
		    opcode == DIF_OP_UULOAD   ||
		    opcode == DIF_OP_RET      ||
		    opcode == DIF_OP_PUSHTR   ||
		    opcode == DIF_OP_ADD      ||
		    opcode == DIF_OP_TYPECAST) {
			auto usetx_node = node->findChild(n);
			if (usetx_node != n)
				continue;
			node->usetxDefs.insert(n);
		}
	}
	return (E_HYPERTRACE_NONE);
}

int
HyperTraceLinker::updateUsetxDefs(dtrace_difo_t *difo, BasicBlock *bb, DFGNode *n)
{
	int e = updateUsetxDefsInBB(difo, bb, n);
	if (e) [[unlikely]]
		return (e);

	for (auto child : bb->children) {
		e = updateUsetxDefs(difo, child.first, n);
		if (e) [[unlikely]]
			return (e);
	}
	return (E_HYPERTRACE_NONE);
}

int
HyperTraceLinker::inferUsetxDefs(dtrace_difo_t *difo)
{
	BasicBlock *bb = static_cast<BasicBlock *>(difo->dtdo_bb);

	for (auto it = dfgNodes.rbegin(); it != dfgNodes.rend(); ++it) {
		auto n = it->get();
		assert(n != nullptr);
		if (n->sym == nullptr)
			continue;
		if (n->difo != difo)
			continue;

		dif_instr_t instr = n->getInstruction();
		uint8_t opcode = DIF_INSTR_OP(instr);
		if (opcode != DIF_OP_USETX)
			continue;
		int e = updateUsetxDefs(difo, bb, n);
		if (e) [[unlikely]]
			return (e);
	}
	return (E_HYPERTRACE_NONE);
}

int
HyperTraceLinker::assembleProgram(dtrace_difo_t *difo,
    Array<UMap<uint32_t, dtrace_diftype_t>, DIFV_NSCOPES> &biggestVarType)
{
	if (difo->dtdo_inthash != nullptr) {
		size_t inthash_size = dt_inttab_size(difo->dtdo_inthash);
		if (inthash_size == 0) {
			setErrorMessage(
			    "inthash_size is 0, but inthash is not NULL");
			return (E_HYPERTRACE_LINKING);
		}

		uint64_t *otab = difo->dtdo_inttab;
		difo->dtdo_inttab = (uint64_t *)dt_zalloc(dtp,
		    sizeof(uint64_t) * inthash_size);
		if (difo->dtdo_inttab == nullptr) {
			setErrorMessage("malloc of inttab failed: %s", strerror(errno));
			return (E_HYPERTRACE_SYS);
		}
		free(otab);
		dt_inttab_write(difo->dtdo_inthash, difo->dtdo_inttab);
		difo->dtdo_intlen = inthash_size;
	}

	/*
	 * By this time we should have any variable being used in this
	 * DIFO inside the varlist because the only _valid_ DIF currently
	 * is one where we store to a variable before loading it, so this
	 * information should already be available.
	 */
	for (uint_t i = 0; i < difo->dtdo_varlen; i++) {
		dtrace_difv_t *var = &difo->dtdo_vartab[i];
		if (isBuiltinVariable(var->dtdv_id))
			continue;

		dtrace_difv_t *vlvar = getVarFromVarVec(var->dtdv_id,
		    var->dtdv_scope, var->dtdv_kind);
		assert(vlvar != nullptr);
		var->dtdv_type = vlvar->dtdv_type;
		auto id = var->dtdv_id;
		auto scope = var->dtdv_scope;
		assert(scope < DIFV_NSCOPES);
		auto bt_size = biggestVarType[scope][id].dtdt_size;
		auto vt_size = var->dtdv_type.dtdt_size;
		if (bt_size < vt_size)
			biggestVarType[scope][id] = var->dtdv_type;
	}
	return (E_HYPERTRACE_NONE);
}

static void
finalizeVartab(dtrace_difo_t *difo,
    Array<UMap<uint32_t, dtrace_diftype_t>, DIFV_NSCOPES> &biggestVarType)
{
	/*
	 * Re-patch the variable table to ensure that we have uniform types
	 * across all of the references of the variable. Without this, the
	 * kernel verifier will fail.
	 */
	for (uint_t i = 0; i < difo->dtdo_varlen; i++) {
		dtrace_difv_t *var = &difo->dtdo_vartab[i];
		if (isBuiltinVariable(var->dtdv_id))
			continue;
		var->dtdv_type = biggestVarType[var->dtdv_scope][var->dtdv_id];
	}
}

int
HyperTraceLinker::processDIFO(dtrace_actdesc_t *ad, dtrace_difo_t *difo,
    dtrace_ecbdesc_t *ecbdesc,
    Array<UMap<uint32_t, dtrace_diftype_t>, DIFV_NSCOPES> &biggestVarType)
{
	TypeInference ti(*this, dtp, pgp);
	int rval = computeDFG(ecbdesc, difo);
	if (rval)
		return (rval);
	_HYPERTRACE_LOG_LINKER("computed DFG for %p\n", (void *)difo);
	dtrace_diftype_t savedRType = difo->dtdo_rtype;
	rval = ti.inferDIFO(difo);
	if (rval)
		return (rval);
	_HYPERTRACE_LOG_LINKER("inferred types for %p\n", (void *)difo);
	rval = inferUsetxDefs(difo);
	if (rval)
		return (rval);
	_HYPERTRACE_LOG_LINKER("inferred usetx definitions %p\n", (void *)difo);
	dtrace_actkind_t actionKind = ad == nullptr ?
	    DTRACEACT_DIFEXPR : ad->dtad_kind;
	rval = relocateProgram(actionKind, ad, difo, &savedRType);
	if (rval)
		return (rval);
	_HYPERTRACE_LOG_LINKER("relocated %p\n", (void *)difo);
	rval = assembleProgram(difo, biggestVarType);
	if (rval)
		return (rval);
	_HYPERTRACE_LOG_LINKER("assembled %p\n", (void *)difo);
	return (E_HYPERTRACE_NONE);
}

int
HyperTraceLinker::link(void)
{

	dt_stmt_t *stp;
	dtrace_stmtdesc_t *sdp;
	dtrace_actdesc_t *ad;
	dtrace_ecbdesc_t *ecbdesc;
	dtrace_preddesc_t *pred;
	std::unordered_set<dtrace_ecbdesc_t *> processed_ecbdescs;
	int rval, e;
	Array<UMap<uint32_t, dtrace_diftype_t>, DIFV_NSCOPES> biggestVarType;

	dt_typefile_openall(dtp);
	_HYPERTRACE_LOG_LINKER("finished opening typefiles\n");
	dfgNodes.push_front(std::make_unique<DFGNode>(dtp, pgp, nullptr,
	    nullptr, nullptr, UINT_MAX));
	r0node = dfgNodes.front().get();
	r0node->dType = DIF_TYPE_BOTTOM;

	/*
	 * Regenerate the identifier, since it's no longer the same program. Set
	 * the srcident to the original identifier.
	 */
	memcpy(pgp->dp_srcident, pgp->dp_ident, DT_PROG_IDENTLEN);
	dt_prog_generate_ident(pgp);
	for (stp = (dt_stmt_t *)dt_list_next(&pgp->dp_stmts); stp;
	     stp = (dt_stmt_t *)dt_list_next(stp)) {
		sdp = stp->ds_desc;
		if (sdp == nullptr) {
			setErrorMessage("statement (%p): description is NULL",
			    stp);
			return (E_HYPERTRACE_LINKING);
		}
		ecbdesc = sdp->dtsd_ecbdesc;
		if (ecbdesc == nullptr) {
			setErrorMessage("statement (%p): ecbdesc is NULL", sdp);
			return (E_HYPERTRACE_LINKING);
		}
		pred = &ecbdesc->dted_pred;
		if (pred == nullptr) {
			setErrorMessage("ecbdesc (%p): predicate is NULL",
			    ecbdesc);
			return (E_HYPERTRACE_LINKING);
		}
		_HYPERTRACE_LOG_LINKER(
		    "pre-processing {sdp=%p, ecbdesc=%p, pred=%p}\n",
		    (void *)sdp, (void *)ecbdesc, (void *)pred);
		if (pred->dtpdd_difo != nullptr) {
			_HYPERTRACE_LOG_LINKER("predicate detected at %p\n",
			    (void *)pred->dtpdd_difo);
			e = populateVariablesFromDIFO(pred->dtpdd_difo);
			if (e) [[unlikely]]
				return (e);
		}
		/*
		 * Nothing to do if the action is missing
		 */
		if (sdp->dtsd_action == nullptr)
			continue;
		/*
		 * If we are in a state where we have the first action, but not
		 * a last action we bail out. This should not happen.
		 */
		if (sdp->dtsd_action_last == nullptr) {
			setErrorMessage(
			    "first action = %p, but last action is NULL",
			    sdp->dtsd_action);
			return (E_HYPERTRACE_LINKING);
		}

		/*
		 * We populate the variable list before we actually do a pass
		 * to infer definitions or type-checking. The reason for this
		 * is to do with the semantics of probes being concurrent, in
		 * the sense that they are in fact in parallel composition with
		 * each other, rather than having some sort of ordering. Even
		 * though for now we simply adopt the D style of type checking
		 * for variables (store before a load), we would also like for
		 * this to type-check:
		 *
		 * foo { y = x; } bar { x = 1; }
		 */
		for (ad = sdp->dtsd_action;
		     ad != sdp->dtsd_action_last->dtad_next;
		     ad = ad->dtad_next) {
			if (ad->dtad_difo == nullptr)
				continue;

			_HYPERTRACE_LOG_LINKER("populate variables from %p\n",
			    (void *)ad->dtad_difo);
			populateVariablesFromDIFO(ad->dtad_difo);
		}
	}
	/*
	 * Go over all the statements in a D program
	 */
	for (stp = (dt_stmt_t *)dt_list_next(&pgp->dp_stmts); stp;
	     stp = (dt_stmt_t *)dt_list_next(stp)) {
		sdp = stp->ds_desc;
		if (sdp == nullptr) {
			setErrorMessage("statement (%p): description is NULL",
			    (void *)stp);
			return (E_HYPERTRACE_LINKING);
		}
		ecbdesc = sdp->dtsd_ecbdesc;
		if (ecbdesc == nullptr) {
			setErrorMessage("statement (%p): ecbdesc is NULL",
			    (void *)sdp);
			return (E_HYPERTRACE_LINKING);
		}
		pred = &ecbdesc->dted_pred;
		if (pred == nullptr) {
			setErrorMessage("ecbdesc (%p): predicate is NULL",
			    ecbdesc);
			return (E_HYPERTRACE_LINKING);
		}
		_HYPERTRACE_LOG_LINKER(
		    "processing {sdp=%p, ecbdesc=%p, pred=%p}\n", (void *)sdp,
		    (void *)ecbdesc, (void *)pred);
		if (pred->dtpdd_difo != nullptr) {
			if (!processed_ecbdescs.contains(ecbdesc)) {
				_HYPERTRACE_LOG_LINKER("process predicate %p\n",
				    (void *)pred->dtpdd_difo);
				rval = processDIFO(nullptr, pred->dtpdd_difo,
				    ecbdesc, biggestVarType);
				if (rval != 0)
					return (rval);
				processed_ecbdescs.insert(ecbdesc);
			}
		}
		/*
		 * Nothing to do if the action is missing
		 */
		if (sdp->dtsd_action == nullptr)
			continue;
		/*
		 * If we are in a state where we have the first action, but not
		 * a last action we bail out. This should not happen.
		 */
		if (sdp->dtsd_action_last == nullptr) {
			setErrorMessage(
			    "first action = %p, but last action is NULL",
			    (void *)sdp->dtsd_action);
			return (E_HYPERTRACE_LINKING);
		}

		/*
		 * We go over each action and apply the relocations in each
		 * DIFO (if it exists).
		 */
		for (ad = sdp->dtsd_action;
		     ad != sdp->dtsd_action_last->dtad_next;
		     ad = ad->dtad_next) {
			if (ad->dtad_difo == nullptr)
				continue;

			_HYPERTRACE_LOG_LINKER("process difo %p\n",
			    (void *)ad->dtad_difo);
			rval = processDIFO(ad, ad->dtad_difo, ecbdesc,
			    biggestVarType);
			if (rval != 0)
				return (rval);
		}
	}

	for (stp = (dt_stmt_t *)dt_list_next(&pgp->dp_stmts); stp;
	     stp = (dt_stmt_t *)dt_list_next(stp)) {
		/*
		 * We don't need any checks here, because we just passed them
		 * above.
		 */
		sdp = stp->ds_desc;
		ecbdesc = sdp->dtsd_ecbdesc;
		pred = &ecbdesc->dted_pred;
		_HYPERTRACE_LOG_LINKER(
		    "finalizing {sdp=%p, ecbdesc=%p, pred=%p}\n", (void *)sdp,
		    (void *)ecbdesc, (void *)pred);
		if (pred->dtpdd_difo != nullptr) {
			_HYPERTRACE_LOG_LINKER(
			    "finalize vartab for predicate %p\n",
			    (void *)pred->dtpdd_difo);
			finalizeVartab(pred->dtpdd_difo, biggestVarType);
		}

		/*
		 * Nothing to do if the action is missing
		 */
		if (sdp->dtsd_action == nullptr)
			continue;

		/*
		 * Finalize the variable table for each DIFO.
		 */
		for (ad = sdp->dtsd_action;
		     ad != sdp->dtsd_action_last->dtad_next;
		     ad = ad->dtad_next) {
			if (ad->dtad_difo == nullptr)
				continue;

			_HYPERTRACE_LOG_LINKER("finalize vartab for %p\n",
			    (void *)ad->dtad_difo);
			finalizeVartab(ad->dtad_difo, biggestVarType);
		}
	}
	return (E_HYPERTRACE_NONE);
}
} // namespace dtrace

int
hypertrace_link(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    hypertrace_errmsg_t errmsg)
{
	dtrace::HyperTraceLinker l(dtp, pgp);
	_HYPERTRACE_LOG_LINKER("beginning the linking stage\n");
	int rval = l.link();
	const dtrace::String &errorMessage = l.getErrorMessage();
	assert(errorMessage.size() < HYPERTRACE_ERRMSGLEN);
	strcpy(errmsg, errorMessage.c_str());
	return (rval);
}
