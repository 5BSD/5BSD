/*-
 * Copyright (c) 2024 Domagoj Stolfa
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
 *
 * $FreeBSD$
 */

#ifndef _DT_LINKER_SUBR_H_
#define _DT_LINKER_SUBR_H_

#include <sys/types.h>
#include <sys/dtrace.h>

#ifndef __cplusplus
#error "This file should only be included from C++"
#endif

#include <dt_dfg.hh>
#include <dt_basic_block.hh>

#include <dt_list.h>

namespace dtrace {
extern int subrClobbers(uint16_t);
extern int clobbersRegister(dif_instr_t, uint8_t);
extern int isBuiltinVariable(uint16_t);
extern int clobbersVariable(dif_instr_t, DFGNodeData &);
extern void getVariableInfo(dif_instr_t, uint16_t *, int *, int *);
extern int varIsUninitialized(dtrace_difv_t *);
extern ssize_t getStack(std::vector<BasicBlock *> &, DFGNode *);
}

#endif /* _DT_LINKER_SUBR_H_ */
