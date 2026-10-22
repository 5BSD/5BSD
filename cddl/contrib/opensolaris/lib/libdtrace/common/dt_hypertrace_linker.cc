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

#include <new>
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
#include <dt_typing_helpers.hh>
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
	if (len < 0) {
		/* E.g. EOVERFLOW: the message would exceed INT_MAX bytes. */
		errorMessage = "(the error message could not be formatted)";
	} else {
		errorMessage.assign((size_t)len, '\0');
		vsnprintf(errorMessage.data(), (size_t)len + 1, fmt, va_cp);
	}
	va_end(va_cp);
	va_end(va);
}

/*
 * Record a program error and return -1.  The first one is the program's
 * (dt_set_progerr(): the program is marked, the message kept, and a guest
 * forwards the program to dtraced once); later ones, from checks that do not
 * stop at the first (the TypeInference constructor), are only printed.
 */
int
HyperTraceLinker::progErr(const char *fmt, ...)
{
	char msg[DT_PROG_ERRLEN];
	va_list va;

	va_start(va, fmt);
	vsnprintf(msg, sizeof(msg), fmt, va);
	va_end(va);
	if (progErrors++ != 0) {
		fprintf(stderr, "%s\n", msg);
		return (-1);
	}
	errorMessage = msg;
	if (dt_set_progerr(dtp, pgp, "%s", msg) != 0) {
		/* dp_err now also says why the program was not forwarded. */
		progErrForwardFailed = true;
		errorMessage = pgp->dp_err;
	}
	return (-1);
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

	/* CTF member offsets are in bits. Preserve the full byte offset in
	 * the 64-bit DIF integer table; narrowing to uint16_t silently wrapped
	 * members beyond 64 KiB back into an earlier part of the structure. */
	if ((n->mip->ctm_offset & 7) != 0) {
		setErrorMessage("member offset %lu is not byte aligned",
		    n->mip->ctm_offset);
		return (E_HYPERTRACE_LINKING);
	}
	uint64_t offset = n->mip->ctm_offset / 8;
	for (auto node : n->usetxDefs) {
		if (node->isRelocated)
			continue;

		dif_instr_t instr = node->getInstruction();
		uint8_t opcode = DIF_INSTR_OP(instr);
		if (opcode != DIF_OP_USETX) {
			setErrorMessage("opcode (%d @ %zu) is not usetx", opcode,
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
		if (index < 0) {
			setErrorMessage("failed to insert %" PRIu64
					" into inthash",
			    offset);
			return (E_HYPERTRACE_LIBDTRACE);
		}
		if (index > UINT16_MAX) {
			setErrorMessage("DIF integer table index %d exceeds 16 bits",
			    index);
			return (E_HYPERTRACE_LINKING);
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
	if (node->mip == nullptr) {
		if (node->sym == nullptr) {
			if (opcode != DIF_OP_ADD) {
				setErrorMessage("missing CTF member for load");
				return (E_HYPERTRACE_LINKING);
			}
			node->isRelocated = true;
			return (E_HYPERTRACE_NONE);
		}
		if (node->tf == nullptr) {
			setErrorMessage("missing CTF typefile for member %s",
			    node->sym);
			return (E_HYPERTRACE_LINKING);
		}
		auto *mip = (ctf_membinfo_t *)dt_zalloc(dtp,
		    sizeof(ctf_membinfo_t));
		if (mip == nullptr) {
			setErrorMessage("malloc for mip failed: %s",
			    strerror(errno));
			return (E_HYPERTRACE_SYS);
		}
		/*
		 * The member is in the struct the register points to, or in
		 * the struct the register holds by reference (a by-reference
		 * variable such as `self->t = *curthread').
		 */
		ctf_id_t base = node->tf->resolve(node->ctfid);
		int bkind = (int)node->tf->getKind(base);
		auto type = bkind == CTF_K_STRUCT || bkind == CTF_K_UNION ?
		    base : node->tf->getReference(node->ctfid);
		if (node->tf->getMembInfo(type, node->sym, mip) == 0) {
			setErrorMessage("failed to resolve member %s at node %zu: %s",
			    node->sym, node->uidx, node->tf->getErrMsg());
			dt_free(dtp, mip);
			return (E_HYPERTRACE_LINKING);
		}
		node->mip = mip;
	}
	if (node->tf == nullptr && opcode != DIF_OP_ADD) {
		setErrorMessage("missing CTF typefile for member load");
		return (E_HYPERTRACE_LINKING);
	}
	ctf_id_t ctfid;
	int kind;
	ssize_t ctf_size;
	size_t size;
	if (opcode == DIF_OP_ADD)
		goto usetx_relo;

	ctfid = node->tf->resolve(node->mip->ctm_type);
	ctf_size = node->tf->getSize(ctfid);
	if (ctf_size < 0) {
		setErrorMessage("failed to resolve size for CTF type %ld",
		    ctfid);
		return (E_HYPERTRACE_LINKING);
	}
	size = (size_t)ctf_size;
	kind = node->tf->getKind(ctfid);
	/*
	 * NOTE: We support loading of CTF_K_ARRAY due to it
	 * just being a pointer, really.
	 */
	if (kind != CTF_K_INTEGER && kind != CTF_K_POINTER &&
	    kind != CTF_K_ARRAY) {
		setErrorMessage("a load of kind %d is unsupported in DIF.",
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
		/* An integer always has an encoding. */
		ctf_encoding_t encoding = {};
		(void)node->tf->getEncoding(ctfid, &encoding);
		/* A byte load cannot extract a CTF bitfield. Its neighboring bits
		 * would become part of the guest value even when the member begins
		 * on a byte boundary. */
		if (encoding.cte_offset != 0 ||
		    encoding.cte_bits != size * 8) {
			setErrorMessage("unsupported bitfield encoding for CTF type %ld",
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

	/*
	 * A type the compiler knew is the result's type: the compiler is D's
	 * source of truth (no integer promotions, its constant types), the
	 * consumer formats the record by it, and dt_prog_verify() requires a
	 * returned program to keep it.  Only a result the compiler could not
	 * type (BOTTOM: guest data) is typed by the linker.
	 */
	if (originalReturnType != nullptr &&
	    originalReturnType->dtdt_kind != DIF_TYPE_BOTTOM) {
		*rtype = *originalReturnType;
		if (rtype->dtdt_kind == DIF_TYPE_CTF && node->mip == nullptr)
			retCleanup(node, rtype);
		return (relocateRetOrPush(node));
	}

	rtype->dtdt_kind = node->dType;
	/* dtdt_ckind holds a CTF kind (dt_node_diftype()), not a type id. */
	if (node->dType == DIF_TYPE_CTF || node->dType == DIF_TYPE_STRING)
		rtype->dtdt_ckind = dt_diftype_ckind(node->dType, node->tf,
		    node->ctfid);
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
			if (node->tf == nullptr) {
				setErrorMessage("missing CTF typefile for return");
				return (E_HYPERTRACE_LINKING);
			}
			int ctf_kind = node->tf->getKind(node->ctfid);
			if (ctf_kind == CTF_ERR) {
				setErrorMessage("failed to resolve return CTF kind");
				return (E_HYPERTRACE_LINKING);
			}

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

			/*
			 * A value returned by reference (kernel or user
			 * memory) is described by the object the register
			 * points to: its kind and its size (a dereferenced
			 * userland struct is its full size, not a pointer's).
			 */
			ctf_id_t return_ctfid = node->ctfid;
			if (rtype->dtdt_flags & (DIF_TF_BYREF | DIF_TF_BYUREF)) {
				ctf_id_t reference = node->tf->getReference(
				    node->ctfid);
				/*
				 * FIXME:. This is very much a heuristic. This
				 * can probably be done better.
				 */
				if (reference != CTF_ERR)
					return_ctfid = reference;
			}
			ssize_t return_size = node->tf->getSize(return_ctfid);
			if (return_size <= 0 || (uintmax_t)return_size > UINT32_MAX) {
				setErrorMessage("invalid return CTF size %jd",
				    (intmax_t)return_size);
				return (E_HYPERTRACE_LINKING);
			}
			rtype->dtdt_size = (uint32_t)return_size;
			rtype->dtdt_ckind = dt_diftype_ckind(DIF_TYPE_CTF,
			    node->tf, return_ctfid);
			/* `*(userland string *)p': the object is a D string. */
			if (node->tf == dt_typefile_D() &&
			    return_ctfid == DT_STR_TYPE(dtp)) {
				rtype->dtdt_kind = DIF_TYPE_STRING;
				rtype->dtdt_ckind = CTF_K_UNKNOWN;
			}
			retCleanup(node, rtype);
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
	 * A D string is returned by reference.  Only a string return type is
	 * marked: an action that returns nothing (void) or exit()'s int keeps
	 * the type set above even when the returned register holds a string
	 * (e.g. the store `s = execname').
	 */
	if (rtype->dtdt_kind == DIF_TYPE_STRING) {
		/* A string in user memory stays by user reference. */
		if ((rtype->dtdt_flags & DIF_TF_BYUREF) == 0)
			rtype->dtdt_flags |= DIF_TF_BYREF;
		rtype->dtdt_ckind = CTF_K_UNKNOWN;
	}
	return (relocateRetOrPush(node));
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

		int e = patchUsetxDefs(node);
		if (e)
			return (e);
		/* Type inference has checked the symbol already; the linker
		 * does not rely on that when called on its own. */
		uint16_t sym = DIF_INSTR_SYMBOL(instr);
		if (difo->dtdo_symtab == nullptr ||
		    sym >= difo->dtdo_symlen ||
		    memchr(difo->dtdo_symtab + sym, '\0',
		    difo->dtdo_symlen - sym) == nullptr) {
			setErrorMessage("typecast symbol %u is invalid for a "
			    "%ju-byte symbol table", sym,
			    (uintmax_t)difo->dtdo_symlen);
			return (E_HYPERTRACE_LINKING);
		}

		/*
		 * The conversion code the compiler emitted before the typecast
		 * (sll/sra or sll/srl: sign extension or truncation, dt_cg)
		 * is the cast itself and stays: removing it made
		 * `(char)arg0 + 1' see all 64 bits of arg0.
		 */
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
	/*
	 * Rebuild the integer table as a hash that relocations can append to
	 * (a hash left by an earlier failed link is replaced).
	 */
	if (difo->dtdo_inttab != nullptr && difo->dtdo_intlen != 0) {
		if (difo->dtdo_inthash != nullptr)
			dt_inttab_destroy(difo->dtdo_inthash);

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

/*
 * Record the usetx `n' (which has a symbol) as a definition of the later
 * nodes of the basic block that consume its value.
 */
void
HyperTraceLinker::updateUsetxDefsInBB(dtrace_difo_t *difo, BasicBlock *bb,
    DFGNode *n)
{
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
}

void
HyperTraceLinker::updateUsetxDefs(dtrace_difo_t *difo, BasicBlock *bb, DFGNode *n)
{
	updateUsetxDefsInBB(difo, bb, n);
	for (auto child : bb->children)
		updateUsetxDefs(difo, child.first, n);
}

void
HyperTraceLinker::inferUsetxDefs(dtrace_difo_t *difo)
{
	BasicBlock *bb = static_cast<BasicBlock *>(difo->dtdo_bb);

	for (auto it = dfgNodes.rbegin(); it != dfgNodes.rend(); ++it) {
		auto n = it->get();
		if (n->sym == nullptr)
			continue;
		if (n->difo != difo)
			continue;

		dif_instr_t instr = n->getInstruction();
		uint8_t opcode = DIF_INSTR_OP(instr);
		if (opcode != DIF_OP_USETX)
			continue;
		updateUsetxDefs(difo, bb, n);
	}
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
		/* The table is final: the linker's hash is not kept (nothing
		 * else frees it). */
		dt_inttab_destroy(difo->dtdo_inthash);
		difo->dtdo_inthash = nullptr;
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

		auto id = var->dtdv_id;
		auto scope = var->dtdv_scope;
		if (scope >= DIFV_NSCOPES) {
			setErrorMessage("variable %u has an invalid scope %u", id,
			    scope);
			return (E_HYPERTRACE_LINKING);
		}

		/* Every variable of the DIFO was entered by link(). */
		dtrace_difv_t *vlvar = getVarFromVarVec(var->dtdv_id,
		    var->dtdv_scope, var->dtdv_kind);
		assert(vlvar != nullptr);
		var->dtdv_type = vlvar->dtdv_type;
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

/*
 * Reject malformed DIFOs before any pass reads them, with a HyperTrace
 * error code and a message (hypertrace_link() reports E_HYPERTRACE_* codes
 * only).
 */
int
HyperTraceLinker::checkDIFO(dtrace_difo_t *difo)
{
	if (difo->dtdo_buf == nullptr || difo->dtdo_len == 0) {
		setErrorMessage("DIFO %p has no instructions", (void *)difo);
		return (E_HYPERTRACE_LINKING);
	}

	/*
	 * If we don't have a table, length MUST be 0.
	 */
	if ((difo->dtdo_inttab == nullptr && difo->dtdo_intlen != 0) ||
	    (difo->dtdo_strtab == nullptr && difo->dtdo_strlen != 0) ||
	    (difo->dtdo_vartab == nullptr && difo->dtdo_varlen != 0) ||
	    (difo->dtdo_symtab == nullptr && difo->dtdo_symlen != 0)) {
		setErrorMessage("DIFO %p has a missing table with a non-zero "
		    "length (int %u, str %u, var %u, sym %ju)", (void *)difo,
		    difo->dtdo_intlen, difo->dtdo_strlen, difo->dtdo_varlen,
		    (uintmax_t)difo->dtdo_symlen);
		return (E_HYPERTRACE_LINKING);
	}

	/*
	 * Branches go forward to an instruction of the DIFO and are never its
	 * last instruction (computeBasicBlocks() relies on both).
	 */
	for (uint_t i = 0; i < difo->dtdo_len; i++) {
		uint8_t op = DIF_INSTR_OP(difo->dtdo_buf[i]);
		uint_t lbl = DIF_INSTR_LABEL(difo->dtdo_buf[i]);
		if (op < DIF_OP_BA || op > DIF_OP_BLEU)
			continue;
		if (lbl >= difo->dtdo_len || i + 1 >= difo->dtdo_len) {
			setErrorMessage("branch at %u to %u is outside of the "
			    "DIFO's %u instructions", i, lbl, difo->dtdo_len);
			return (E_HYPERTRACE_LINKING);
		}
	}
	return (E_HYPERTRACE_NONE);
}

int
HyperTraceLinker::processDIFO(dtrace_actdesc_t *ad, dtrace_difo_t *difo,
    dtrace_ecbdesc_t *ecbdesc,
    Array<UMap<uint32_t, dtrace_diftype_t>, DIFV_NSCOPES> &biggestVarType)
{
	TypeInference ti(*this, dtp, pgp);
	computeDFG(ecbdesc, difo);
	_HYPERTRACE_LOG_LINKER("computed DFG for %p\n", (void *)difo);
	dtrace_diftype_t savedRType = difo->dtdo_rtype;
	int rval = ti.inferDIFO(difo);
	if (rval) {
		/* Report the type checker's diagnostic to the caller. */
		errorMessage = ti.getErrorMessage();
		return (rval);
	}
	_HYPERTRACE_LOG_LINKER("inferred types for %p\n", (void *)difo);
	inferUsetxDefs(difo);
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

	if (dt_typefile_openall(dtp) != 0) {
		setErrorMessage("kldstat() failed with: %s", strerror(errno));
		return (E_HYPERTRACE_SYS);
	}
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
			    (void *)stp);
			return (E_HYPERTRACE_LINKING);
		}
		ecbdesc = sdp->dtsd_ecbdesc;
		if (ecbdesc == nullptr) {
			setErrorMessage("statement (%p): ecbdesc is NULL", (void *)sdp);
			return (E_HYPERTRACE_LINKING);
		}
		pred = &ecbdesc->dted_pred;
		_HYPERTRACE_LOG_LINKER(
		    "pre-processing {sdp=%p, ecbdesc=%p, pred=%p}\n",
		    (void *)sdp, (void *)ecbdesc, (void *)pred);
		if (pred->dtpdd_difo != nullptr) {
			_HYPERTRACE_LOG_LINKER("predicate detected at %p\n",
			    (void *)pred->dtpdd_difo);
			e = checkDIFO(pred->dtpdd_difo);
			if (e == 0)
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
			    (void *)sdp->dtsd_action);
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
			e = checkDIFO(ad->dtad_difo);
			if (e == 0)
				e = populateVariablesFromDIFO(ad->dtad_difo);
			if (e) [[unlikely]]
				return (e);
		}
	}
	/*
	 * Go over all the statements in a D program
	 */
	for (stp = (dt_stmt_t *)dt_list_next(&pgp->dp_stmts); stp;
	     stp = (dt_stmt_t *)dt_list_next(stp)) {
		/*
		 * The statements were validated by the pass above.
		 */
		sdp = stp->ds_desc;
		ecbdesc = sdp->dtsd_ecbdesc;
		pred = &ecbdesc->dted_pred;
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
try {
	dtrace::HyperTraceLinker l(dtp, pgp);
	_HYPERTRACE_LOG_LINKER("beginning the linking stage\n");
	int rval = l.link();
	/*
	 * No type file outlives the link that opened it: each refers to this
	 * handle's modules, and the next link may be on another handle.
	 */
	dtrace::dt_typefile_closeall();
	/*
	 * A program error ends the link with the program marked (dp_haserror,
	 * dp_err); a guest that could not forward it reports a system error.
	 */
	/* Every program error makes the link fail. */
	assert(!l.hadProgErr() || rval != E_HYPERTRACE_NONE);
	if (l.progErrForwardFailed)
		rval = E_HYPERTRACE_SYS;
	const dtrace::String &errorMessage = l.getErrorMessage();
	strlcpy(errmsg, errorMessage.c_str(), HYPERTRACE_ERRMSGLEN);
	return (rval);
} catch (const std::bad_alloc &) {
	/*
	 * An allocation failed (the linker's containers throw): the linker is
	 * unwound, its type files are released, and the failure is returned
	 * (a consumer is never terminated for it).  The program may be partly
	 * relocated and must not be executed.
	 */
	dtrace::dt_typefile_closeall();
	errno = ENOMEM;
	strlcpy(errmsg, "linker allocation failed", HYPERTRACE_ERRMSGLEN);
	return (E_HYPERTRACE_SYS);
}
