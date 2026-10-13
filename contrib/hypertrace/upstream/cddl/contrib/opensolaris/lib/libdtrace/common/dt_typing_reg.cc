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
 */
DFGNode *
TypeInference::checkRegDefs(DFGNode *n, NodeSet &defs, bool &empty)
{
	String s1, s2;
	int which;

	empty = false;

	/*
	 * If we only have a r0node in our list of definitions,
	 * we will return the r0node and have the type as BOTTOM.
	 */
	auto *r0node = linkerContext.getR0Node();
	if (defs.size() == 1 && *defs.begin() == r0node) {
		empty = true;
		return (const_cast<DFGNode *>(r0node));
	}

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
					dt_set_progerr(dtp, pgp,
					    "dt_typecheck_regdefs(): failed at "
					    "getting type name node %ld: %s",
					    other_node->ctfid,
					    other_node->tf->getErrMsg());

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
			String otype_str, ctype_str;

			if (otype == DIF_TYPE_STRING) {
				otype_str = "D string";
			} else if (otype == DIF_TYPE_BOTTOM) {
				otype_str = "D bottom type";
			} else if (otype == DIF_TYPE_NONE) {
				otype_str = "none";
			} else if (otype == DIF_TYPE_CTF) {
				/*
				 * Get the CTF type name
				 */
				auto opt = onode->tf->getTypename(onode->ctfid);
				if (!opt.has_value())
					dt_set_progerr(dtp, pgp,
					    "dt_typecheck_regdefs(%p[%zu]): failed at "
					    "getting type name node %ld: %s",
					    (void *)n->difo, n->uidx,
					    onode->ctfid,
					    onode->tf->getErrMsg());
				otype_str = std::move(opt.value());
			} else {
				otype_str = "unknown (ERROR)";
			}

			if (type == DIF_TYPE_STRING) {
				ctype_str = "D string";
			} else if (type == DIF_TYPE_BOTTOM) {
				ctype_str = "D bottom type";
			} else if (type == DIF_TYPE_NONE) {
				ctype_str = "none";
			} else if (type == DIF_TYPE_CTF) {
				/*
				 * Get the CTF type name
				 */
				auto opt = node->tf->getTypename(node->ctfid);
				if (!opt.has_value())
					dt_set_progerr(dtp, pgp,
					    "dt_typecheck_regdefs(%p[%zu]): failed at "
					    "getting type name node %ld: %s",
					    (void *)n->difo, n->uidx,
					    node->ctfid, node->tf->getErrMsg());
				ctype_str = std::move(opt.value());
			} else {
				ctype_str = "unknown (ERROR)";
			}

			dt_set_progerr(dtp, pgp,
			    "%p[%zu]: failed to typecheck conditional: "
			    "(branch 1: %s (%zu) != branch 2: %s (%zu))\n",
			    n->difo, n->uidx, otype_str.c_str(), onode->uidx,
			    ctype_str.c_str(), node->uidx);
			return (nullptr);
		}

		if (type == DIF_TYPE_CTF) {
			assert(node->tf != nullptr);

			/*
			 * We get the type name for reporting purposes.
			 */
			auto opt = node->tf->getTypename(node->ctfid);
			if (!opt.has_value())
				dt_set_progerr(dtp, pgp,
				    "dt_typecheck_regdefs(%p[%zu]): failed at "
				    "getting type name node %ld: %s",
				    n->difo, n->uidx, node->ctfid,
				    node->tf->getErrMsg());

			s1 = std::move(opt.value());

			/*
			 * If we are at the first definition, or only have one
			 * definition, we don't need to check the types.
			 */
			if (onode == nullptr)
				continue;

			if (onode->dType == DIF_TYPE_BOTTOM)
				continue;

			assert(onode->tf != nullptr);
 			/*
			 * Get the previous' node's inferred type for
			 * error reporting.
			 */
			opt = onode->tf->getTypename(onode->ctfid);
			if (!opt.has_value())
				dt_set_progerr(dtp, pgp,
				    "dt_typecheck_regdefs(%p[%zu]): failed at "
				    "getting type onode name %ld: %s",
				    n->difo, n->uidx, onode->ctfid,
				    onode->tf->getErrMsg());

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
				dt_set_progerr(dtp, pgp,
				    "dt_typecheck_regdefs(%p[%zu]): symbol is "
				    "missing in a node\n",
				    n->difo, n->uidx);
				return (nullptr);
			}

			/*
			 * We don't need to check both
			 * because of the above check.
			 */
			if (node->sym && strcmp(node->sym, onode->sym) != 0) {
				dt_set_progerr(dtp, pgp,
				    "dt_typecheck_regdefs(%p[%zu]): nodes have "
				    "different symbols: %s != %s\n",
				    n->difo, n->uidx, node->sym, onode->sym);
				return (nullptr);
			}
		}

		first_iter = false;
	}

	return (node);
}

}
