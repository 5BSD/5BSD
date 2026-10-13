/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020, 2024 Domagoj Stolfa.
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

#include <dt_basic_block.hh>

#include <sys/types.h>
#include <sys/dtrace.h>

#include <dtrace.h>
#include <dt_impl.h>
#include <dt_program.h>
#include <dt_list.h>
#include <dt_linker_subr.hh>
#include <dt_hypertrace_linker.hh>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <err.h>

namespace dtrace {
size_t BasicBlock::index = 0;

BasicBlock::BasicBlock(dtrace_difo_t *difo)
    : difo(difo)
    , start(0)
    , end(0)
    , idx(BasicBlock::index++)
{
}

void
HyperTraceLinker::computeBasicBlocks(dtrace_difo_t *difo)
{
	BasicBlock *bb;
	std::vector<bool> leaders(difo->dtdo_len);
	uint32_t lbl;
	dif_instr_t instr;
	uint8_t opcode;

	bb = nullptr;

	/*
	 * First instruction is a leader.
	 */
	leaders[0] = true;

	/*
	 * Compute the leaders.
	 */
	for (uint_t i = 0; i < difo->dtdo_len; i++) {
		instr = difo->dtdo_buf[i];
		opcode = DIF_INSTR_OP(instr);

		if (opcode >= DIF_OP_BA && opcode <= DIF_OP_BLEU) {
			lbl = DIF_INSTR_LABEL(instr);
			if (lbl >= difo->dtdo_len)
				errx(EXIT_FAILURE,
				    "lbl (%u) branching outside"
				    " of code length (%u)",
				    lbl, difo->dtdo_len);

			/*
			 * We have a valid label. Any DIFO which does not end
			 * with a ret instruction is not valid, so we check if
			 * position i + 1 is a valid instruction.
			 */
			if (i + 1 >= difo->dtdo_len)
				errx(EXIT_FAILURE, "malformed DIFO");

			/*
			 * For a direct branch, i + 1 is not a leader. We are
			 * skipping it all together.
			 */
			if (opcode != DIF_OP_BA)
				leaders[i + 1] = true;
			leaders[lbl] = true;
		}
	}

	/*
	 * For each leader we encounter, we compute the set of all instructions
	 * that fit into the current basic block.
	 */
	for (uint_t i = 0; i < difo->dtdo_len; i++) {
		if (leaders[i]) {
			/*
			 * We've encountered a leader, we don't actually need
			 * to copy any instructions over, as we already have
			 * them in a DIFO (and we will be changing said
			 * instructions in the DIFO itself). Instead, we just
			 * observe that we will always have had a basic block
			 * allocated in our bb pointer and simply save the end
			 * instruction as the instruction before the leader and
			 * allocate a new basic block with the leader as the
			 * starting instruction.
			 */
			if (bb != NULL) {
				bb->end = i - 1;
			}

			basicBlocks.push_back(
			    std::make_unique<BasicBlock>(difo));
			auto bbp = basicBlocks.back().get();
			if (bb == nullptr) [[unlikely]]
				difo->dtdo_bb = (void *)bbp;

			bb = bbp;
			if (bb == nullptr)
				errx(EXIT_FAILURE, "allocating new bb failed");
			bb->start = i;
		}
	}

	/*
	 * We will always have allocated a new basic block without the end
	 * instruction, because in the case of no branches we will simply have
	 * the first basic block, whereas with branches we will have the case
	 * of a target near the end, with no branches in between there and the
	 * ret instruction.
	 */
	bb->end = difo->dtdo_len - 1;
}

void
HyperTraceLinker::computeCFG(dtrace_difo_t *difo)
{
	uint32_t lbl;
	uint8_t opcode;
	dif_instr_t instr;

	for (auto &bb1 : basicBlocks) {
		assert(bb1 != NULL);
		if (bb1->difo != difo)
			continue;

		instr = bb1->DIFOBuf()[bb1->end];
		opcode = DIF_INSTR_OP(instr);

		if (opcode >= DIF_OP_BA && opcode <= DIF_OP_BLEU)
			lbl = DIF_INSTR_LABEL(instr);
		else
			continue;

		for (auto &bb2 : basicBlocks) {
			assert(bb2 != NULL);

			if (bb1 == bb2)
				continue;

			if (bb2->difo != difo)
				continue;

			if (bb2->start == lbl) {
				bb1->children.push_back(
				    std::make_pair(bb2.get(), true));
				bb2->parents.push_back(
				    std::make_pair(bb1.get(), true));
			}

			if (opcode != DIF_OP_BA &&
			    bb1->end + 1 == bb2->start) {
				bb1->children.push_back(
				    std::make_pair(bb2.get(), true));
				bb2->parents.push_back(
				    std::make_pair(bb1.get(), true));
			}
		}
	}
}

}
