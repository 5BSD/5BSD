/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2024 Domagoj Stolfa.
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _DT_BASIC_BLOCK_H_
#define _DT_BASIC_BLOCK_H_

#include <sys/dtrace.h>

#ifndef __cplusplus
#error "This file should only be included from C++"
#endif

#include <dt_cxxdefs.hh>

namespace dtrace {
class BasicBlock {
    public:
	static size_t index;

	dtrace_difo_t *difo;
	size_t start;
	size_t end;
	size_t idx;
	/*
	 * Keep a vector of basic blocks as children and parents. We add a
	 * 'bool' flag to each of the entries because we want to keep track if
	 * that particular child in this particular vector was visited, rather
	 * than caring if the basic block itself was visited at some point.
	 */
	Vec<Pair<BasicBlock *, bool>> children;
	Vec<Pair<BasicBlock *, bool>> parents;

    public:
	BasicBlock(dtrace_difo_t *);
	dif_instr_t *DIFOBuf() { return (this->difo->dtdo_buf); }
};

extern void dt_compute_bb(dtrace_difo_t *);
extern void dt_compute_cfg(dtrace_difo_t *);
}

#endif /* _DT_BASIC_BLOCK_H_ */
