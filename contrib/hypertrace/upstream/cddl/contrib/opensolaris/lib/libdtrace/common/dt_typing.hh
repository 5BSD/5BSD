/*-
 * Copyright (c) 2020, 2021 Domagoj Stolfa
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

#ifndef _DT_TYPING_H_
#define _DT_TYPING_H_

#include <sys/dtrace.h>
#include <dtrace.h>

#define DTC_BOTTOM  -1
#define DTC_INT      0
#define DTC_STRUCT   1
#define DTC_STRING   2
#define DTC_FORWARD  3
#define DTC_UNION    4
#define DTC_ENUM     5

#define SUBTYPE_NONE  0
#define SUBTYPE_EQUAL (1 << 0)
#define SUBTYPE_FST   (1 << 1)
#define SUBTYPE_SND   (1 << 2)
#define SUBTYPE_ANY   (SUBTYPE_EQUAL | SUBTYPE_FST | SUBTYPE_SND)

#ifndef __cplusplus
#error "This file should only be included from C++"
#endif

#include <dt_cxxdefs.hh>
#include <dt_dfg.hh>

#include <string>

namespace dtrace {
class TypeInference {
    private:
	dtrace_hdl_t *dtp;
	dtrace_prog_t *pgp;
	String t_mtx = "";
	String t_rw = "";
	String t_sx = "";
	String t_thread = "";
	String errorMessage = "";
	HyperTraceLinker &linkerContext;

    private:
	void setErrorMessage(const char *, ...);
	dtrace_difv_t *findVariableFromNodeDefs(NodeSet &);
	int inferNode(DFGNode *);
	int inferSubr(DFGNode *, NodeVec *);
	int inferVar(DFGNode *, dtrace_difv_t *);
	int checkVarStack(DFGNode *, DFGNode *, dtrace_difv_t *);
	NodeVec *checkStack(Vec<StackData> &, bool &);
	DFGNode *checkRegDefs(DFGNode *, NodeSet &, bool &);
	DFGNode *checkVarDefs(DFGNode *, dtrace_difo_t *, NodeSet &, bool &);
	void argCmpWith(DFGNode *, Vec<Typefile *> &, const String &,
	    const String &, int);
	void setBuiltinType(DFGNode *, uint16_t, uint8_t);
	int ctfTypeCompare(Typefile *, ctf_id_t, Typefile *, ctf_id_t);
	ctf_membinfo_t *getMipFromSymbol(DFGNode *);
	ctf_membinfo_t *getMipByOffset(Typefile *, ctf_id_t, uint64_t);

	static bool varEqualCTF(dtrace_difv_t *v1, dtrace_difv_t *v2) {
		return (v1->dtdv_id == v2->dtdv_id &&
		    v1->dtdv_scope == v2->dtdv_scope &&
		    v1->dtdv_kind == v2->dtdv_kind &&
		    v1->dtdv_type.dtdt_kind == v2->dtdv_type.dtdt_kind &&
		    v1->dtdv_tf == v2->dtdv_tf &&
		    v1->dtdv_ctfid == v2->dtdv_ctfid);
	}

    public:
	TypeInference(HyperTraceLinker &, dtrace_hdl_t *, dtrace_prog_t *);
	int inferDIFO(dtrace_difo_t *);
	int getSubtypeRelation(Typefile *, ctf_id_t, Typefile *, ctf_id_t, int &);
	int typeCompare(DFGNode *, DFGNode *);
};

}

#endif /* _DT_TYPING_H_ */
