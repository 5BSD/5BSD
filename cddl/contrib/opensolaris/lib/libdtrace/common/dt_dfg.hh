/*-
 * Copyright (c) 2020 Domagoj Stolfa
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

#ifndef _DT_IFG_H_
#define _DT_IFG_H_

#include <sys/types.h>
#include <sys/dtrace.h>

#include <dtrace.h>

#ifndef __cplusplus
#error "This file should only be included from C++"
#endif

#include <dt_cxxdefs.hh>

namespace dtrace {
enum DFGNodeKind {
	DT_NKIND_IGNORE = -1,
	DT_NKIND_REG = 1,
	DT_NKIND_VAR = 2,
	DT_NKIND_STACK = 3
};

class DFGNodeData {
    public:
	DFGNodeKind kind = DT_NKIND_IGNORE; /* kind (see below) */

    private:
	union {
		uint8_t rd; /* DT_RKIND_REG */
		struct {    /* DT_RKIND_VAR */
			uint16_t var;
			uint8_t scope;
			uint8_t varkind;
		} v;
	} u;

    public:
	uint8_t &rd() { return (this->u.rd); }
	uint16_t &var() { return (this->u.v.var); }
	uint8_t &scope() { return (this->u.v.scope); }
	uint8_t &varkind() { return (this->u.v.varkind); }
};

class StackData {
    public:
	Vec<BasicBlock *> identifier;
	NodeVec nodesOnStack;

    public:
	StackData(Vec<BasicBlock *> &);
	~StackData() = default;
};

/*
 * Data-flow graph node.
 */
class DFGNode {
    public:
	size_t uidx; /* index of the use site */

	/*
	 * Vectors of various IFG nodes. They contain backpointers to various
	 * kinds of definitions in the IFG.
	 */
	NodeSet r1Defs;	    /* type flow for r1 */
	NodeSet r2Defs;	    /* type flow for r2 */
	NodeSet r1DataDefs; /* data flow for r1 */
	NodeSet r2DataDefs; /* data flow for r2 */
	NodeSet varDefs;    /* vector of variable defns in DIFO */
	NodeSet r1Children; /* which r1s do we define */
	NodeSet r2Children; /* which r2s do we define */
	NodeSet usetxDefs;  /* usetx insn vector defining the node */

	Vec<dtrace_difv_t *> varSources; /* variable origin (if exists) */

	int dType = -1;		       /* D type */
	Typefile *tf = nullptr;	       /* reference to the type's type file */
	ctf_id_t ctfid = CTF_ERR;      /* CTF type */
	char *sym = nullptr;	       /* symbol (if applicable) */
	ctf_membinfo_t *mip = nullptr; /* CTF member info (type, offs) */

	dtrace_hdl_t *dtp = nullptr;
	dtrace_ecbdesc_t *edp = nullptr;  /* node's ecbdesc */
	dtrace_prog_t *program = nullptr; /* program this node belongs to */
	dtrace_difo_t *difo = nullptr;	  /* DIFO which this node belongs to */
	BasicBlock *bb = nullptr;	  /* basic block that the node is in */
	Vec<StackData> stacks;		  /* list of pushtr/pushtv nodes */
	DFGNodeData nodeData;		  /* node data (reg, var, stack) */
	bool isRelocated = false;	  /* relocated or not? */
	bool isNull = true;		  /* can this node contain NULL? */
	std::optional<uint64_t> integer;  /* integer value from setx */

    public:
	DFGNode(dtrace_hdl_t *, dtrace_prog_t *, dtrace_ecbdesc_t *,
	    dtrace_difo_t *, BasicBlock *, uint_t);
	~DFGNode() = default;

	dif_instr_t *DIFOBuf() { return (this->difo->dtdo_buf); }
	dif_instr_t &Instruction()
	{
		return (this->difo->dtdo_buf[this->uidx]);
	}
	uint8_t getRD(void);
	dif_instr_t getInstruction(void) const;
	DFGNode *findChild(DFGNode *);
};

extern void get_node_data(dif_instr_t, DFGNodeData &);
}

#endif /* _DT_IFG_H_ */
