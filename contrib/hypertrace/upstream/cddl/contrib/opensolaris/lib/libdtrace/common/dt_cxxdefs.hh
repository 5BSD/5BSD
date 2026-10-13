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

#ifndef _DT_CXXDEFS_HH_
#define _DT_CXXDEFS_HH_

#include <dt_elf.h>

#ifndef __cplusplus
#error "This file should only be included from C++"
#endif

#include <list>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace dtrace {
class DFGNode;
class BasicBlock;
class Typefile;
class TypeInference;
class HyperTraceLinker;

template <typename T> using USet = std::unordered_set<T>;
template <typename K, typename T> using UMap = std::unordered_map<K, T>;
template <typename T> using Vec = std::vector<T>;
template <typename T> using Opt = std::optional<T>;
template <typename T> using UPtr = std::unique_ptr<T>;
template <typename T1, typename T2> using Pair = std::pair<T1, T2>;
template <typename T> using List = std::list<T>;
template <typename T, std::size_t n> using Array = std::array<T, n>;
template <typename... Types> using Var = std::variant<Types...>;
template <typename T>
using ElfMap = UMap<Var<T *, dt_elf_ref_t>, Var<Elf_Scn *, T *>>;

using String = std::string;
using NodeSet = USet<DFGNode *>;
using NodeVec = Vec<DFGNode *>;
using DFGList = List<UPtr<DFGNode>>;

template <typename T1, typename T2> constexpr T1
Get(T2 v)
{
	return (std::get<T1>(v));
}
}

#endif /* _DT_CXXDEFS_HH_ */
