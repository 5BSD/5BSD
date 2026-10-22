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
#include <err.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>


#include <dt_basic_block.hh>
#include <dt_dfg.hh>
#include <dt_impl.h>
#include <dt_linker_subr.hh>
#include <dt_program.h>
#include <dtrace.h>
#include <dt_hypertrace_linker.hh>

#include <stack>
#include <unordered_map>
#include <iterator>
#include <unordered_set>

namespace dtrace {

template <typename K, typename T> using HashMap = std::unordered_map<K, T>;

StackData::StackData(Vec<BasicBlock *> &ident)
    : identifier(ident)
{
}

DFGNode::DFGNode(dtrace_hdl_t *_dtp, dtrace_prog_t *pgp,
    dtrace_ecbdesc_t *_edp, dtrace_difo_t *_difo, BasicBlock *_bb, uint_t idx)
    : uidx(idx)
    , dtp(_dtp)
    , edp(_edp)
    , program(pgp)
    , difo(_difo)
    , bb(_bb)
{
}

void
getNodeData(dif_instr_t instr, DFGNodeData &data)
{
	uint8_t opcode = DIF_INSTR_OP(instr);

	switch (opcode) {
	case DIF_OP_ULOAD:
	case DIF_OP_UULOAD:
	case DIF_OP_USETX:
	case DIF_OP_TYPECAST:
	case DIF_OP_XLATE:	/* xlate xlrindex, rd: rd's input translated */
	case DIF_OP_XLARG:	/* xlarg xlrindex, rd: an argument translated */
	case DIF_OP_OR:
	case DIF_OP_XOR:
	case DIF_OP_AND:
	case DIF_OP_SLL:
	case DIF_OP_SRL:
	case DIF_OP_ADD:
	case DIF_OP_SUB:
	case DIF_OP_MUL:
	case DIF_OP_SDIV:
	case DIF_OP_UDIV:
	case DIF_OP_SREM:
	case DIF_OP_UREM:
	case DIF_OP_NOT:
	case DIF_OP_MOV:
	case DIF_OP_LDSB:
	case DIF_OP_LDSH:
	case DIF_OP_LDSW:
	case DIF_OP_LDUB:
	case DIF_OP_LDUH:
	case DIF_OP_LDUW:
	case DIF_OP_LDX:
	case DIF_OP_SETX:
	case DIF_OP_SETS:
	case DIF_OP_LDGA:
	case DIF_OP_LDGS:
	case DIF_OP_LDTA:
	case DIF_OP_LDTS:
	case DIF_OP_SRA:
	case DIF_OP_CALL:
	case DIF_OP_LDGAA:
	case DIF_OP_LDTAA:
	case DIF_OP_LDLS:
	case DIF_OP_ALLOCS:
	case DIF_OP_COPYS:
	case DIF_OP_ULDSB:
	case DIF_OP_ULDSH:
	case DIF_OP_ULDSW:
	case DIF_OP_ULDUB:
	case DIF_OP_ULDUH:
	case DIF_OP_ULDUW:
	case DIF_OP_ULDX:
	case DIF_OP_RLDSB:
	case DIF_OP_RLDSH:
	case DIF_OP_RLDSW:
	case DIF_OP_RLDUB:
	case DIF_OP_RLDUH:
	case DIF_OP_RLDUW:
	case DIF_OP_RLDX:
		data.kind = DT_NKIND_REG;
		data.rd() = DIF_INSTR_RD(instr);
		break;

	case DIF_OP_STGS:
		data.kind = DT_NKIND_VAR;
		data.var() = DIF_INSTR_VAR(instr);
		data.scope() = DIFV_SCOPE_GLOBAL;
		data.varkind() = DIFV_KIND_SCALAR;
		break;

	case DIF_OP_STGAA:
		data.kind = DT_NKIND_VAR;
		data.var() = DIF_INSTR_VAR(instr);
		data.scope() = DIFV_SCOPE_GLOBAL;
		data.varkind() = DIFV_KIND_ARRAY;
		break;

	case DIF_OP_STTAA:
		data.kind = DT_NKIND_VAR;
		data.var() = DIF_INSTR_VAR(instr);
		data.scope() = DIFV_SCOPE_THREAD;
		data.varkind() = DIFV_KIND_ARRAY;
		break;

	case DIF_OP_STTS:
		data.kind = DT_NKIND_VAR;
		data.var() = DIF_INSTR_VAR(instr);
		data.scope() = DIFV_SCOPE_THREAD;
		data.varkind() = DIFV_KIND_SCALAR;
		break;

	case DIF_OP_STLS:
		data.kind = DT_NKIND_VAR;
		data.var() = DIF_INSTR_VAR(instr);
		data.scope() = DIFV_SCOPE_LOCAL;
		data.varkind() = DIFV_KIND_SCALAR;
		break;

	case DIF_OP_PUSHTR:
	case DIF_OP_PUSHTV:
		data.kind = DT_NKIND_STACK;

	default:
		break;
	}
}

/*
 * This method assumes it's being called with a node `n` that is an
 * instruction with a destination register.
 */
uint8_t
DFGNode::getRD(void)
{

	return (DIF_INSTR_RD(this->difo->dtdo_buf[this->uidx]));
}

dif_instr_t
DFGNode::getInstruction(void) const
{

	return (this->difo->dtdo_buf[this->uidx]);
}

static bool
usiteUsesStack(DFGNode *n)
{
	dif_instr_t instr;
	uint8_t op;

	instr = n->getInstruction();
	op = DIF_INSTR_OP(instr);

	switch (op) {
	case DIF_OP_CALL:
	case DIF_OP_LDGAA:
	case DIF_OP_LDTAA:
	case DIF_OP_STTS:
	case DIF_OP_LDTS:
	case DIF_OP_STGAA:
	case DIF_OP_STTAA:
		return (true);

	default:
		break;
	}

	return (false);
}

/*
 * Whether instruction n loads the variable `data' describes: a variable is
 * identified by its id, scope and kind (getVariableInfo()).
 */
static bool
usiteContainsVar(DFGNode *n, DFGNodeData &data)
{
	uint16_t v;
	int scope, kind;

	return (getVariableInfo(n->getInstruction(), &v, &scope, &kind) ==
	    DT_VARINFO_LOAD && v == data.var() && scope == data.scope() &&
	    kind == data.varkind());
}

static bool
usiteContainsReg(DFGNode *n, DFGNode *curnode, uint8_t rd,
    int *r1, int *r2)
{
	dif_instr_t instr = 0;
	uint8_t rs = 0, _rd = 0, _r1 = 0, _r2 = 0, opcode = 0;
	dif_instr_t curinstr;
	uint8_t curop;

	curinstr = curnode->getInstruction();
	instr = n->getInstruction();

	*r1 = 0;
	*r2 = 0;

	opcode = DIF_INSTR_OP(instr);
	curop = DIF_INSTR_OP(curinstr);

	/*
	 * A subroutine that does not write its result register (bcopy() and
	 * the copyout family, subrClobbers()) defines nothing a later
	 * instruction could use.
	 */
	if (curop == DIF_OP_CALL &&
	    !subrClobbers(DIF_INSTR_SUBR(curinstr)))
		return (false);

	switch (opcode) {
	case DIF_OP_ULOAD:
	case DIF_OP_UULOAD:
	case DIF_OP_LDSB:
	case DIF_OP_LDSH:
	case DIF_OP_LDSW:
	case DIF_OP_LDUB:
	case DIF_OP_LDUH:
	case DIF_OP_LDUW:
	case DIF_OP_LDX:
	case DIF_OP_ULDSB:
	case DIF_OP_ULDSH:
	case DIF_OP_ULDSW:
	case DIF_OP_ULDUB:
	case DIF_OP_ULDUH:
	case DIF_OP_ULDUW:
	case DIF_OP_ULDX:
	case DIF_OP_RLDSB:
	case DIF_OP_RLDSH:
	case DIF_OP_RLDSW:
	case DIF_OP_RLDUB:
	case DIF_OP_RLDUH:
	case DIF_OP_RLDUW:
	case DIF_OP_RLDX:
		/* ld* [r1], rd: the address is in r1 (sys/dtrace.h). */
		_r1 = DIF_INSTR_R1(instr);
		if (rd == _r1)
			*r1 = 1;
		break;

	case DIF_OP_PUSHTR:
	case DIF_OP_PUSHTV:
	case DIF_OP_TYPECAST:
	case DIF_OP_XLATE:	/* the translator's input is rd itself */
		rs = DIF_INSTR_RS(instr);
		if (rd == rs)
			*r1 = 1;
		break;

	case DIF_OP_OR:
	case DIF_OP_XOR:
	case DIF_OP_AND:
	case DIF_OP_SLL:
	case DIF_OP_SRL:
	case DIF_OP_ADD:
	case DIF_OP_SUB:
	case DIF_OP_MUL:
	case DIF_OP_SDIV:
	case DIF_OP_UDIV:
	case DIF_OP_SREM:
	case DIF_OP_UREM:
	case DIF_OP_SRA:
 	case DIF_OP_COPYS:
		_r1 = DIF_INSTR_R1(instr);
		_r2 = DIF_INSTR_R2(instr);

		if (_r1 == rd)
			*r1 = 1;
		if (_r2 == rd)
			*r2 = 1;
		break;

	case DIF_OP_NOT:
	case DIF_OP_MOV:
	case DIF_OP_STB:
	case DIF_OP_STH:
	case DIF_OP_STW:
	case DIF_OP_STX:
		_r1 = DIF_INSTR_R1(instr);
		_r2 = DIF_INSTR_RD(instr);

		if (_r1 == rd)
			*r1 = 1;
		if (_r2 == rd)
			*r2 = 1;
		break;

	case DIF_OP_LDGA:
	case DIF_OP_LDTA:
		/* ld{g,t}a var, r2, rd: the index is in r2. */
		_r2 = DIF_INSTR_R2(instr);

		if (_r2 == rd)
			*r2 = 1;
		break;

	case DIF_OP_ALLOCS:
		/* allocs r1, rd: the size is in r1 (sys/dtrace.h). */
		_r1 = DIF_INSTR_R1(instr);

		if (_r1 == rd)
			*r1 = 1;
		break;

	case DIF_OP_STGS:
	case DIF_OP_STGAA:
	case DIF_OP_STTAA:
	case DIF_OP_STTS:
	case DIF_OP_STLS:
		_r2 = DIF_INSTR_RS(instr);

		if (_r2 == rd)
			*r2 = 1;
		break;

	case DIF_OP_RET:
		_rd = DIF_INSTR_RD(instr);

		if (_rd == rd)
			*r1 = 1;
		break;

	default:
		break;
	}

	return (*r1 != 0 || *r2 != 0);
}

bool
HyperTraceLinker::updateNodesInBBForVar(BasicBlock *bb, DFGNodeData &data,
    DFGList::iterator pos)
{
	/*
	 * The nodes after pos are this DIFO's later instructions (computeDFG()
	 * appends a DIFO's nodes in order, and DIF has no backward branches).
	 */
	DFGNode *curnode = pos->get();
	for (++pos; pos != dfgNodes.end(); ++pos) {
		DFGNode *n = pos->get();
		dif_instr_t instr = n->getInstruction();

		if (n->uidx < bb->start || n->uidx > bb->end)
			continue;

		if (usiteContainsVar(n, data)) {
			n->varDefs.insert(curnode);
		}

		/*
		 * If we run into a redefinition of the current register,
		 * we simply break out of the loop, there is nothing left
		 * to fill in inside this basic block.
		 */
		if (clobbersVariable(instr, data))
			return (true);
	}

	return (false);
}

int
HyperTraceLinker::updateNodesInBBForStack(Vec<BasicBlock *> &bb_path,
    BasicBlock *bb, DFGList::iterator pos)
{
	/* n_pushes counts this push and the later ones still on the
	 * stack; it never drops below 1 (the pop of this push returns). */
	int n_pushes = 1;
	DFGNode *curnode = pos->get();
	for (++pos; pos != dfgNodes.end(); ++pos) {
		DFGNode *n = pos->get();
		dif_instr_t instr = n->getInstruction();
		uint8_t op = DIF_INSTR_OP(instr);

		if (n->uidx < bb->start || n->uidx > bb->end)
			continue;

		if (op == DIF_OP_FLUSHTS)
			return (1);

		if (n_pushes == 1 && op == DIF_OP_POPTS)
			return (1);

		if (n_pushes > 1 && op == DIF_OP_POPTS) {
			n_pushes--;
			continue;
		}

		if (op == DIF_OP_PUSHTV || op == DIF_OP_PUSHTR) {
			n_pushes++;
			continue;
		}

		if (usiteUsesStack(n)) {
			auto stackId = getStack(bb_path, n); /* found or added */
			n->stacks[stackId].nodesOnStack.push_back(curnode);
		}
	}

	return (0);
}

int
HyperTraceLinker::updateNodesInBBForReg([[maybe_unused]] dtrace_difo_t *difo,
    BasicBlock *bb,
    uint8_t rd, DFGList::iterator pos, int *seen_typecast)
{
	DFGNode *n, *curnode;
	int r1, r2;
	dif_instr_t instr, curinstr;
	uint8_t opcode, curop;
	int clobbers;

	r1 = 0;
	r2 = 0;
	curnode = pos->get();

	curinstr = curnode->getInstruction();
	curop = DIF_INSTR_OP(curinstr);

	/* usiteContainsReg() is true when it sets r1 or r2. */
	if (usiteContainsReg(curnode, curnode, 0, &r1, &r2)) {
		if (r1 == 1) {
			curnode->r1Defs.insert(r0node);
		}

		if (r2 == 1) {
			curnode->r2Defs.insert(r0node);
		}
	}

	r1 = r2 = 0;
	for (++pos; pos != dfgNodes.end(); ++pos) {
		n = pos->get();
		instr = n->getInstruction();
		opcode = DIF_INSTR_OP(instr);

		if (n->uidx < bb->start || n->uidx > bb->end)
			continue;

		if (usiteContainsReg(n, curnode, rd, &r1, &r2)) {
			if (r1 == 1 && *seen_typecast == 0) {
				n->r1Defs.insert(curnode);
				curnode->r1Children.insert(n);
			}

			if (r2 == 1 && *seen_typecast == 0) {
				n->r2Defs.insert(curnode);
				curnode->r2Children.insert(n);
			}

			if (r1 == 1 && curop != DIF_OP_TYPECAST) {
				n->r1DataDefs.insert(curnode);
			}

			if (r2 == 1 && curop != DIF_OP_TYPECAST) {
				n->r2DataDefs.insert(curnode);
			}
		}

		clobbers = clobbersRegister(instr, rd);

		/*
		 * If we run into a redefinition of the current register,
		 * we simply break out of the loop, there is nothing left
		 * to fill in inside this basic block.
		 */
		if (clobbers) {
			if (opcode != DIF_OP_TYPECAST)
				return (1);
			*seen_typecast = 1;
		}
	}

	return (0);
}

static void
computeActiveVarRegs(uint8_t *active_varregs, size_t n_varregs,
    DFGNode *n)
{
	uint8_t r1, r2, rd;

	/*
	 * Based on the opcode, we will now compute the new set of active
	 * registers in the current run of the inference for varsources.
	 */
	dif_instr_t instr = n->getInstruction();
	uint8_t opcode = DIF_INSTR_OP(instr);
	switch (opcode) {
	case DIF_OP_OR:
	case DIF_OP_XOR:
	case DIF_OP_AND:
	case DIF_OP_SLL:
	case DIF_OP_SRL:
	case DIF_OP_SUB:
	case DIF_OP_ADD:
	case DIF_OP_MUL:
	case DIF_OP_SRA:
		/*
		 * If either of r1 and r2 is active, we will activate rd too, as
		 * this is probably some computation of an offset within a
		 * variable. However, if both are inactive, then we deactivate
		 * rd as well.
		 */
		r1 = DIF_INSTR_R1(instr);
		r2 = DIF_INSTR_R2(instr);
		rd = DIF_INSTR_RD(instr);



		if (active_varregs[r1] == 0 && active_varregs[r2] == 0)
			active_varregs[rd] = 0;

		if (active_varregs[rd] == 0 && active_varregs[r1] == 1)
			active_varregs[rd] = 1;

		if (active_varregs[rd] == 0 && active_varregs[r2] == 1)
			active_varregs[rd] = 1;
		break;

	case DIF_OP_MOV:
		/*
		 * For any one of these instructions, we will compute if
		 * r1 is already an active register. If so, we simply activate
		 * rd as well.
		 */
		rd = DIF_INSTR_RD(instr);
		r1 = DIF_INSTR_R1(instr);

		active_varregs[rd] = active_varregs[r1];
		break;

	case DIF_OP_STB:
	case DIF_OP_STH:
	case DIF_OP_STW:
	case DIF_OP_STX:
	case DIF_OP_CMP:
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
	case DIF_OP_SCMP:
	case DIF_OP_PUSHTR:
	case DIF_OP_PUSHTV:
	case DIF_OP_POPTS:
		break;

	case DIF_OP_RET:
		/*
		 * On a ret instruction, all of the active registers are
		 * cleared. We are not longer actively looking to figure out
		 * which registers could be defining a variable, and therefore
		 * we don't want to keep track of them.
		 */
		for (size_t i = 0; i < n_varregs; i++)
			active_varregs[i] = 0;

	default:
		rd = DIF_INSTR_RD(instr);

		active_varregs[rd] = 0;
	}
}

void
HyperTraceLinker::updateActiveVarRegs(uint8_t active_varregs[DT_VARREGS],
    [[maybe_unused]] dtrace_difo_t *_difo, BasicBlock *bb,
    DFGList::iterator pos)
{
	/* updateDFG() has checked _difo and bb. */
	DFGNode *curnode = pos->get();
	dif_instr_t instr = curnode->getInstruction();
	uint8_t opcode = DIF_INSTR_OP(instr);

	/*
	 * This is only really relevant for load instructions -- nothing else
	 * in DIF can define a register as "containing a variable" that we can
	 * infer statically -- so we don't allow it.
	 */
	if (opcode != DIF_OP_LDGS && opcode != DIF_OP_LDGA &&
	    opcode != DIF_OP_LDTS && opcode != DIF_OP_LDTA &&
	    opcode != DIF_OP_LDLS)
		return;

	uint16_t varid = DIF_INSTR_VAR(instr);

	/*
	 * Annoying boilerplate to compute the kind and scope of the variable.
	 */
	int scope, kind;
	if (opcode == DIF_OP_LDGS || opcode == DIF_OP_LDTS ||
	    opcode == DIF_OP_LDLS)
		kind = DIFV_KIND_SCALAR;
	else
		kind = DIFV_KIND_ARRAY;

	if (opcode == DIF_OP_LDGS || opcode == DIF_OP_LDGA)
		scope = DIFV_SCOPE_GLOBAL;
	else if (opcode == DIF_OP_LDTS || opcode == DIF_OP_LDTA)
		scope = DIFV_SCOPE_THREAD;
	else
		scope = DIFV_SCOPE_LOCAL;

	uint8_t curnode_rd = DIF_INSTR_RD(instr);

	/*
	 * Activate the current node's destination register.
	 */
	active_varregs[curnode_rd] = 1;

	/*
	 * Go through all of the nodes in the current basic block
	 */
	for (++pos; pos != dfgNodes.end(); ++pos) {
		DFGNode *n = pos->get();
		instr = n->getInstruction();
		opcode = DIF_INSTR_OP(instr);

		if (n->uidx < bb->start || n->uidx > bb->end)
			continue;

		/*
		 * Compute which registers are being activated or deactivated
		 * with this node.
		 */
		computeActiveVarRegs(active_varregs, DT_VARREGS, n);

		bool keep_going = false;
		for (size_t i = 0; i < DT_VARREGS; i++)
			if (active_varregs[i] == 1)
				keep_going = true;

		/*
		 * If there's no reason to keep going, that is to say that all
		 * the active registers have been clobbered, we simply return
		 * from the subroutine.
		 */
		if (!keep_going)
			return;

		if (opcode != DIF_OP_STB && opcode != DIF_OP_STH &&
		    opcode != DIF_OP_STW && opcode != DIF_OP_STX)
			continue;

		/*
		 * If we have STB/STH/STW/STX, we will get its r1 register and
		 * check if it's active. If so, we will add our varsource to the
		 * list.
		 */
		uint8_t rd = DIF_INSTR_RD(instr);

		if (active_varregs[rd] == 0)
			continue;


		/* Builtin variables are not in the variable list: a store
		 * through their value has no variable source. */
		dtrace_difv_t *difv = getVarFromVarVec(varid, scope, kind);
		if (difv != nullptr)
			n->varSources.push_back(difv);
	}
}

static void
removeBasicBlocks(BasicBlock *bb,
    HashMap<size_t, BasicBlock *> &bb_map, Vec<BasicBlock *> &bb_path)
{
	BasicBlock *parent_BasicBlock;
	int remove;

	/*
	 * Start by removing the current basic block from the path. Since
	 * this will always be the last element in bb_path, we just need to
	 * decrement bb_last and we can consider it to be out of bb_path.
	 */
	bb_map.erase(bb->idx);
	bb_path.pop_back();

	/*
	 * Find the parent that's in the path.
	 */
	parent_BasicBlock = nullptr;
	for (auto p : bb->parents) {
		if (bb_map.contains(p.first->idx)) {
			parent_BasicBlock = p.first;
			break;
		}
	}

	/*
	 * There's only one case when we won't have a parent. That case is when
	 * we are in the root node. In that case, we will simply assert a few
	 * things and break out of the function.
	 */
	assert((bb->parents.empty() && parent_BasicBlock == nullptr) ||
	    (!bb->parents.empty() && parent_BasicBlock != nullptr));

	if (parent_BasicBlock == nullptr) {
		assert(bb->start == 0);
		return;
	}

	remove = 1;
	for (auto child : parent_BasicBlock->children) {
		if (child.second == true) {
			remove = 0;
			break;
		}
	}

	if (remove)
		removeBasicBlocks(parent_BasicBlock, bb_map, bb_path);
}

void
HyperTraceLinker::updateDFG(dtrace_difo_t *difo, DFGNode *n,
    DFGList::iterator pos)
{
	uint8_t active_varregs[DT_VARREGS];
	int seen_typecast = 0;

	/* computeDFG() gives every node its basic block. */

	std::stack<BasicBlock *> bb_stack;
	BasicBlock *bbp = n->bb;
	bb_stack.push(bbp);

	Vec<BasicBlock *> bb_path;
	HashMap<size_t, BasicBlock *> bb_map;
	DFGNodeData &data = n->nodeData;
	memset(active_varregs, 0, sizeof(active_varregs));

	while (!bb_stack.empty()) {
		auto bb = bb_stack.top();

		bb_stack.pop();

		bool redefined = false;
		bool var_redefined = false;

		bb_path.push_back(bb);
		bb_map[bb->idx] = bb;

		if (data.kind == DT_NKIND_REG) {
			redefined = updateNodesInBBForReg(difo, bb, data.rd(),
			    pos, &seen_typecast);
			updateActiveVarRegs(active_varregs, difo, bb, pos);
			var_redefined = true;
			for (size_t i = 0; i < DT_VARREGS; i++)
				if (active_varregs[i] == 1)
					var_redefined = false;
		} else if (data.kind == DT_NKIND_VAR)
			redefined = updateNodesInBBForVar(bb, data, pos);
		else if (data.kind == DT_NKIND_STACK)
			redefined = updateNodesInBBForStack(bb_path, bb, pos);
		else
			return;

		if (redefined || bb->children.empty())
			removeBasicBlocks(bb, bb_map, bb_path);

		if ((data.kind == DT_NKIND_REG && var_redefined == false) ||
		    !redefined) {
			for (auto child : bb->children) {
				bb_stack.push(child.first);
				/*
				 * This is a little more subtle than it looks.
				 * dtbe_tovisit here is not per basic-block.
				 * It is in fact per individual child of each
				 * basic block -- which differs for different
				 * basic blocks. This ensures that we have a
				 * way to say "have we visited the children
				 * of *this particular basic block*" rather than
				 * "have we visited this basic block".
				 */
				child.second = false;
			}
		}
	}
}

/*
 * The basic block of `difo' that holds instruction ins_idx (every
 * instruction is in one).  The newest blocks, those computeBasicBlocks()
 * has just made for this DIFO, are searched first.
 */
static BasicBlock *
nodeFindBasicBlock(Vec<UPtr<BasicBlock>> &blocks, dtrace_difo_t *difo,
    uint_t ins_idx)
{
	for (auto it = blocks.rbegin(); it != blocks.rend(); ++it)
		if ((*it)->difo == difo && (*it)->start <= ins_idx &&
		    (*it)->end >= ins_idx)
			return (it->get());
	return (nullptr);
}

/*
 * We assume that both dtp and difo are not nullptr.
 */
void
HyperTraceLinker::computeDFG(dtrace_ecbdesc_t *edp, dtrace_difo_t *difo)
{
	DFGList::iterator fst;
	dif_instr_t instr = 0;

	/*
	 * link() has validated the DIFO's shape (checkDIFO()).
	 */

	/*
	 * If the symbol length is 0 and the symbol table is 0, we don't
	 * have any relocations to apply. In this case, we just return that
	 * no error occurred and leave the DIFO as it is.
	 */
	if (difo->dtdo_symtab == nullptr)
		return;

	/*
	 * Compute the basic blocks, CFG and prepare the data flow node vector.
	 */
	computeBasicBlocks(difo);
	computeCFG(difo);
	fst = dfgNodes.end();

	/*
	 * First pass over the instructions. We build up all of the IFG nodes
	 * that we are going to need.
	 */
	for (uint_t i = 0; i < difo->dtdo_len; i++) {
		auto node_BasicBlock = nodeFindBasicBlock(basicBlocks, difo, i);
		assert(node_BasicBlock != nullptr);
		dfgNodes.push_back(std::make_unique<DFGNode>(dtp, pgp, edp,
		    difo, node_BasicBlock, i));
		if (i == 0) {
			fst = std::prev(dfgNodes.end());
		}
	}

	/*
	 * Second pass over all the instructions, but this time we actually
	 * compute the IFG.
	 */
	for (auto it = fst; it != dfgNodes.end(); ++it) {
		auto n = it->get();
		instr = n->getInstruction();

		getNodeData(instr, n->nodeData);
		updateDFG(difo, n, it);
	}
}

DFGNode *
DFGNode::findChild(DFGNode *find) {
	if (this == find)
		return (this);

	if (auto f = this->r1DataDefs.find(find);
	    f != this->r1DataDefs.end())
		return (*f);

	if (auto f = this->r2DataDefs.find(find);
	    f != this->r2DataDefs.end())
		return (*f);

	return (nullptr);
}

}
