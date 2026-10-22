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
#include <dt_hypertrace_linker.hh>
#include <dt_impl.h>
#include <dt_linker_subr.hh>
#include <dt_list.h>
#include <dt_program.h>
#include <dt_typefile.hh>
#include <dt_typing.hh>
#include <dt_typing_helpers.hh>
#include <dtrace.h>
#include <err.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

namespace dtrace {
/*
 * dt_typecheck_regdefs() takes in a list of nodes that define
 * the current node we are looking at and ensures that their types
 * are consistent.
 *
 * Returns the definition whose type the register has, or nullptr.  A
 * nullptr result with `failed' set means that the definitions exist but do
 * not type-check; without it, the register has no definition.
 */
DFGNode *
TypeInference::checkRegDefs(DFGNode *n, NodeSet &defs, bool &failed)
{
	String s1, s2;
	int which;

	failed = false;

	/*
	 * If we only have a r0node in our list of definitions,
	 * we will return the r0node and have the type as BOTTOM.
	 */
	auto *r0node = linkerContext.getR0Node();
	if (defs.size() == 1 && *defs.begin() == r0node)
		return (const_cast<DFGNode *>(r0node));

	/* Every early return below reports a definition that does not
	 * type-check. */
	failed = true;

	DFGNode *node = nullptr;
	if (defs.size() > 0)
		node = *defs.begin(); // FIXME: Needed for onode to be set
				      // correctly.
	/*
	 * We iterate over all the register definitions for a particular
	 * node. We make sure that each of the definitions agrees
	 * on the type of the register.
	 *
	 * Moreover, at this point we will have eliminated the case where
	 * we only have 1 node (r0node) present in the list.
	 */
	bool first_iter = true;
	int type, otype;
	type = otype = DIF_TYPE_NONE;
	for (auto it = defs.begin(); it != defs.end(); ++it) {
		DFGNode *onode = node;
		node = *it;
		otype = type;

		if (node == r0node)
			continue;

		/*
		 * If we have bottom, we just take the old node's value.
		 * onode is _the first_ node in the list, and could be
		 * bottom as well. The only two states we will pass this check
		 * in are:
		 *  (i)  onode is also bottom and we move on until we find the
		 *       first node that is not bottom, which we then
		 *       infer the type of and bail out when we find onode to be
		 *       bottom;
		 *  (ii) onode is a node that is _not_ bottom, but the
		 *       current node is bottom. We decide that we'll just
		 *       set node's value to the last node we saw and
		 *       inferred the type of which is not bottom. Two things
		 *       can happen in the next run. We either realise that we
		 *       have reached the end of the loop and bail out with the
		 *       last node that was not bottom, or we reach the
		 *       case where this check will fail and we can continue on
		 *       typechecking our last seen node that was not
		 *       bottom and the current node which is not bottom,
		 *       giving us the desired type-checking behaviour, making
		 *       sure that all branches have consistent register defns.
		 */
		if (node->dType == DIF_TYPE_BOTTOM) {
			type = otype;
			node = onode;
			continue;
		}

		type = inferNode(node);

		/*
		 * We failed to infer the type to begin with, bail out.
		 */
		if (type == -1) {
			return (nullptr);
		}

		if (onode == r0node)
			continue;

		if (type == DIF_TYPE_STRING || otype == DIF_TYPE_STRING) {
			DFGNode *other_node = type == DIF_TYPE_STRING ?
			    onode : node;
			int other_type = other_node->dType;
			if (other_type == DIF_TYPE_BOTTOM)
				continue;
			if (other_type ==  DIF_TYPE_STRING) {
				first_iter = false;
				continue;
			}
			if (other_type == DIF_TYPE_CTF) {
				/*
				 * Get the CTF type name
				 */
				auto opt = other_node->tf->getTypename(
				    other_node->ctfid);
				if (!opt.has_value())
					return (progErr(
					    "dt_typecheck_regdefs(): failed at "
					    "getting type name node %ld: %s",
					    other_node->ctfid,
					    other_node->tf->getErrMsg()), nullptr);

				s1 = std::move(opt.value());

				if (s1 == "const char *" || s1 == "char *" ||
				    s1 == "string") {
					first_iter = false;
					continue;
				}
			}
		}

		/*
		 * The type at the previous definition does not match the type
		 * inferred in the current one, which is nonsense.
		 */
		if (!first_iter && otype != type) {
			String otype_str = dt_type_diagname(otype, onode->tf,
			    onode->ctfid, false);
			String ctype_str = dt_type_diagname(type, node->tf,
			    node->ctfid, false);

			return (progErr(
			    "%p[%zu]: failed to typecheck conditional: "
			    "(branch 1: %s (%zu) != branch 2: %s (%zu))\n",
			    (void *)n->difo, n->uidx, otype_str.c_str(), onode->uidx,
			    ctype_str.c_str(), node->uidx), nullptr);
		}

		if (type == DIF_TYPE_CTF) {
			assert(node->tf != nullptr);

			/*
			 * We get the type name for reporting purposes.
			 */
			auto opt = node->tf->getTypename(node->ctfid);
			if (!opt.has_value())
				return (progErr(
				    "dt_typecheck_regdefs(%p[%zu]): failed at "
				    "getting type name node %ld: %s",
				    (void *)n->difo, n->uidx, node->ctfid,
				    node->tf->getErrMsg()), nullptr);

			s1 = std::move(opt.value());

			/*
			 * If we are at the first definition, or only have one
			 * definition, we don't need to check the types.  (The
			 * first iteration sees the first definition as its own
			 * predecessor.)
			 */
			if (onode == node) {
				first_iter = false;
				continue;
			}

			if (onode->dType == DIF_TYPE_BOTTOM)
				continue;

			assert(onode->tf != nullptr);
 			/*
			 * The previous definition's type was named when it
			 * was checked; name it again for error reporting.
			 */
			s2 = onode->tf->getTypename(onode->ctfid).value_or("?");

			/*
			 * Fail to typecheck if the types don't match 100%.
			 * We only do this if both types are non-nullptr/0 as we
			 * might be doing some weird zeroing thing where we
			 * can't infer the correct type in either of the nodes.
			 * However, we know that any base CTF type can be
			 * reliably zeroed (non-struct, non-union).
			 */
			if ((!node->isNull && !onode->isNull) &&
			    getSubtypeRelation(node->tf, node->ctfid, onode->tf,
			    onode->ctfid, which)) {
				fprintf(stderr,
				    "dt_typecheck_regdefs(%p[%zu]): types %s (%zu) "
				    "and %s (%zu) do not match\n",
				    (void *)n->difo, n->uidx, s1.c_str(),
				    node->uidx, s2.c_str(), onode->uidx);
				return (nullptr);
			}

			if ((node->sym == nullptr && onode->sym != nullptr) ||
			    (node->sym != nullptr && onode->sym == nullptr)) {
				return (progErr(
				    "dt_typecheck_regdefs(%p[%zu]): symbol is "
				    "missing in a node\n",
				    (void *)n->difo, n->uidx), nullptr);
			}

			/*
			 * We don't need to check both
			 * because of the above check.
			 */
			if (node->sym && strcmp(node->sym, onode->sym) != 0) {
				return (progErr(
				    "dt_typecheck_regdefs(%p[%zu]): nodes have "
				    "different symbols: %s != %s\n",
				    (void *)n->difo, n->uidx, node->sym, onode->sym), nullptr);
			}
		}

		first_iter = false;
	}

	failed = false;
	return (node);
}

}
