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

#ifndef _HYPERTRACE_LINKER_HH_
#define _HYPERTRACE_LINKER_HH_

#include <sys/dtrace.h>

#ifndef __cplusplus
#error "File should only be included from C++"
#endif

#include <dt_cxxdefs.hh>
#include <dtrace.h>

namespace dtrace {
/*
 * Registers tracked by the variable-source analysis: every value of an
 * 8-bit register field, so that a malformed instruction cannot index
 * outside the table (DIF itself has DIF_DIR_NREGS registers).
 */
constexpr size_t DT_VARREGS = 256;

class HyperTraceLinker {
    private:
	dtrace_hdl_t *dtp;
	dtrace_prog_t *pgp;
	DFGNode *r0node = nullptr;
	String errorMessage = "";

    public:
	DFGList dfgNodes;
	Vec<UPtr<BasicBlock>> basicBlocks;
	Vec<UPtr<dtrace_difv_t>> varVector;

	const String &
	getErrorMessage()
	{
		return (errorMessage);
	}

	/*
	 * Program errors (dt_set_progerr()): the first one's message is kept;
	 * a guest's failure to forward the program to dtraced is noted.
	 */
	int progErr(const char *, ...)
	    __attribute__((__format__(__printf__, 2, 3)));
	bool hadProgErr() const { return (progErrors != 0); }
	unsigned progErrors = 0;
	bool progErrForwardFailed = false;

	/*
	 * The stacks recorded for variables (dtdv_stack) during this link;
	 * they hold this link's nodes, so they end with it.  (They were a
	 * process-global list that grew with every link and kept pointers to
	 * the nodes of finished links.)
	 */
	List<UPtr<NodeVec>> varNodeVecs;

    private:
	void setErrorMessage(const char *, ...)
	    __attribute__((__format__(__printf__, 2, 3)));

	int integerIndex(dtrace_difo_t *, uint64_t, uint16_t *);
	int patchUsetxDefs(DFGNode *);
	int patchUsetxDefs(DFGNode *, uint64_t);
	int relocateBitfieldLoad(DFGNode *, ctf_id_t, const ctf_encoding_t &);
	/* Additions of a bit-field member's offset that no load has resolved
	 * yet, and those that one has (relocateProgram()). */
	NodeSet bitfieldAdds;
	NodeSet bitfieldAddsDone;
	int processDIFO(dtrace_actdesc_t *, dtrace_difo_t *, dtrace_ecbdesc_t *,
	    Array<UMap<uint32_t, dtrace_diftype_t>, DIFV_NSCOPES> &);
	int relocateDFGNode(DFGNode *, dtrace_actkind_t, dtrace_actdesc_t *,
	    dtrace_difo_t *, dtrace_diftype_t *);
	int assembleProgram(dtrace_difo_t *,
	    Array<UMap<uint32_t, dtrace_diftype_t>, DIFV_NSCOPES> &);
	int relocateProgram(dtrace_actkind_t, dtrace_actdesc_t *,
	    dtrace_difo_t *, dtrace_diftype_t *);
	void inferUsetxDefs(dtrace_difo_t *);
	int relocateRetOrPush(DFGNode *);
	int relocatePush(DFGNode *);
	int relocateRet(DFGNode *, dtrace_actkind_t, dtrace_actdesc_t *,
	    dtrace_diftype_t *);
	int relocateUloadOrAdd(DFGNode *);
	void computeBasicBlocks(dtrace_difo_t *);
	void computeCFG(dtrace_difo_t *);
	int insertVar(dtrace_difo_t *, uint16_t, uint8_t, uint8_t);
	int insertVar(dtrace_difv_t *);
	int populateVariablesFromDIFO(dtrace_difo_t *);
	void updateActiveVarRegs(uint8_t[DT_VARREGS], dtrace_difo_t *,
	    BasicBlock *, DFGList::iterator);
	bool updateNodesInBBForVar(BasicBlock *, DFGNodeData &,
	    DFGList::iterator);
	int updateNodesInBBForStack(Vec<BasicBlock *> &, BasicBlock *,
	    DFGList::iterator);
	int updateNodesInBBForReg(dtrace_difo_t *, BasicBlock *, uint8_t,
	    DFGList::iterator, int *);
	void updateDFG(dtrace_difo_t *, DFGNode *, DFGList::iterator);
	void updateDFGReach(dtrace_difo_t *, DFGNode *, DFGList::iterator);
	void updateDFGStack(dtrace_difo_t *, DFGNode *, DFGList::iterator);
	void computeDFG(dtrace_ecbdesc_t *, dtrace_difo_t *);
	int checkDIFO(dtrace_difo_t *);

    public:
	HyperTraceLinker(dtrace_hdl_t *, dtrace_prog_t *);
	~HyperTraceLinker() = default;

	int link();
	const DFGNode *getR0Node() const { return (r0node); }
	Typefile *getTypenameChecked(DFGNode *, Vec<Typefile *> &, char *,
	    size_t, const String &);
	dtrace_difv_t *getVarFromVarVec(uint16_t, int, int);
};
}

#endif /* _HYPERTRACE_LINKER_HH_ */
