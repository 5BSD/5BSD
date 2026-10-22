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

#include <sys/types.h>
#include <sys/dtrace.h>

#include <assert.h>
#include <dt_basic_block.hh>
#include <dt_dfg.hh>
#include <dt_impl.h>
#include <dt_linker_subr.hh>
#include <dt_list.h>
#include <dt_program.h>
#include <dt_typefile.hh>
#include <dt_typing.hh>
#include <dt_hypertrace_linker.hh>
#include <dt_typing_helpers.hh>
#include <dtrace.h>
#include <err.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

namespace dtrace {

/*
 * dt_var_stack_typecheck() ensures that all the stacks at variable use
 * and definition site across all branches are consistent in their types.
 * Moreover, ensure that if we already have a variable in our varlist that
 * corresponds to the variable we are currently inferring/checking the type
 * of, ensure that the types there are consistent as well.
 */
int
TypeInference::checkVarStack(DFGNode *n, DFGNode *dr1, dtrace_difv_t *dif_var)
{
	DFGNode *var_stacknode, *node;
	String var_type, type;
	if (dr1 == nullptr && dif_var == nullptr) {
		fprintf(stderr, "both dr1 and dif_var are nullptr");
		return (-1);
	}
	/*
	 * If there was nothing to typecheck above, then we simply create a new
	 * stack for the variable using the data from what we were comparing it
	 * to and move on.
	 */
	if (dif_var->dtdv_stack == nullptr) {
		/* The stack belongs to this link (it holds its nodes). */
		linkerContext.varNodeVecs.push_back(
		    std::make_unique<NodeVec>());
		auto var_nodeset = linkerContext.varNodeVecs.back().get();
		dif_var->dtdv_stack = (void *)var_nodeset;

		if (n->stacks.size() == 0)
			return (progErr("sl is nullptr, nonsense."));

		for (auto node : n->stacks[0].nodesOnStack) {
			var_nodeset->push_back(node);
		}

		return (0);
	} else if (dr1 == nullptr)
		return (0);

	/*
	 * In the case that we _do_ have a variable in our varlist, we
	 * check that the types of the inside DIFO definition and the varlist
	 * definition are consistent.
	 */
	for (auto &stack : n->stacks) {
		NodeVec::iterator ni;
		NodeVec::iterator vi;
		NodeVec *var_stack = (NodeVec *)dif_var->dtdv_stack;

		for (ni = stack.nodesOnStack.begin(), vi = var_stack->begin();
		    ni != stack.nodesOnStack.end() && vi != var_stack->end();
		    ++vi, ++ni) {
			node = *ni;
			var_stacknode = *vi;

			if (node->dType != var_stacknode->dType) {
				fprintf(stderr, "type mismatch in variable\n");
				return (-1);
			}

			if (node->tf != var_stacknode->tf) {
				fprintf(stderr, "typefile mismatch: %s != %s\n",
				    node->tf->name().c_str(),
				    var_stacknode->tf->name().c_str());
				return (-1);
			}

			if (node->dType == DIF_TYPE_CTF) {
				auto opt = node->tf->getTypename(node->ctfid);
				if (!opt.has_value())
					return (progErr(
					    "failed at getting type name %ld: %s",
					    dr1->ctfid, node->tf->getErrMsg()));

				type = std::move(opt.value());
				opt = var_stacknode->tf->getTypename(
				    var_stacknode->ctfid);
				if (!opt.has_value())
					return (progErr(
					    "failed at getting type name %ld: %s",
					    var_stacknode->ctfid,
					    var_stacknode->tf->getErrMsg()));

				var_type = std::move(opt.value());
				if (var_stacknode->ctfid != node->ctfid) {
					fprintf(stderr, "type mismatch "
					    "in stgaa: %s != %s\n",
					    type.c_str(), var_type.c_str());
					return (-1);
				}
			}
		}
	}

	return (0);
}

/*
 * dt_typecheck_stack() ensures that everything on the stack across all branches
 * is consistent with its types.
 */
/*
 * The tuple stacks reaching an instruction along different paths must
 * agree, entry by entry: same number of entries, same D type kinds, the
 * same CTF types (by name: each path may have resolved it in another type
 * file), no symbols.  Returns the first path's stack, or nullptr; with
 * `failed' set, the stacks disagree (or did not type-check), otherwise
 * there is no stack.
 */
NodeVec *
TypeInference::checkStack(Vec<StackData> &stacks, bool &failed)
{
	failed = !stacks.empty();
	if (stacks.empty())
		return (nullptr);

	NodeVec *first = &stacks.front().nodesOnStack;
	for (auto &sd : stacks) {
		NodeVec *stack = &sd.nodesOnStack;

		/*
		 * Infer types on the stack.
		 */
		for (auto n : *stack) {
			if (inferNode(n) == -1)
				return (progErr(
				    "%s(%p[%zu]): failed to infer "
				    "type for opcode %d at %zu\n",
				    __func__, (void *)n->difo, n->uidx,
				    n->getInstruction(), n->uidx), nullptr);
		}

		if (stack == first)
			continue;

		if (stack->size() != first->size()) {
			fprintf(stderr, "%s(): %zu stack entries on one path, "
			    "%zu on another\n", __func__, stack->size(),
			    first->size());
			return (nullptr);
		}

		for (size_t i = 0; i < stack->size(); i++) {
			DFGNode *n = (*stack)[i], *on = (*first)[i];

			if (n->dType != on->dType) {
				fprintf(stderr,
				    "%s(%p[%zu]): stack type "
				    "mismatch at %zu and %zu: %d != %d\n",
				    __func__, (void *)n->difo, n->uidx, n->uidx,
				    on->uidx, n->dType, on->dType);
				return (nullptr);
			}

			if (n->dType == DIF_TYPE_CTF &&
			    (n->tf != on->tf || n->ctfid != on->ctfid)) {
				String type1 = n->tf->getTypename(n->ctfid)
				    .value_or("?");
				String type2 = on->tf->getTypename(on->ctfid)
				    .value_or("?");
				if (type1 != type2 || type1 == "?") {
					fprintf(stderr,
					    "%s(%p[%zu]): stack ctf type "
					    "mismatch at %zu and %zu: %s != "
					    "%s\n", __func__, (void *)n->difo,
					    n->uidx, n->uidx, on->uidx,
					    type1.c_str(), type2.c_str());
					return (nullptr);
				}
			}

			if (n->sym || on->sym) {
				fprintf(stderr,
				    "%s(%p[%zu]): symbol found "
				    "on stack at %zu\n",
				    __func__, (void *)n->difo, n->uidx,
				    n->sym ? n->uidx : on->uidx);
				return (nullptr);
			}
		}
	}

	return (first);
}

}
