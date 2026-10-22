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

#ifndef _DT_TYPING_HELPERS_HH_
#define _DT_TYPING_HELPERS_HH_

#include <sys/types.h>
#include <sys/ctf.h>

#include <dtrace.h>
#include <dt_program.h>

#ifndef __cplusplus
#error "This file should only be included from C++"
#endif

#include <dt_typefile.hh>

namespace dtrace {
extern int dt_get_class(Typefile *, ctf_id_t, int);
extern int dt_typecheck_string(dtrace_hdl_t *, int, int, ctf_id_t, ctf_id_t,
    Typefile *, Typefile *);
extern int dt_typecheck_stringii(dtrace_hdl_t *, DFGNode *,
    DFGNode *);
extern int dt_typecheck_stringiv(dtrace_hdl_t *, DFGNode *,
    dtrace_difv_t *);
extern ctf_id_t dt_autoresolve_ctfid(const char *, const char *,
    Typefile **);
extern String dt_type_diagname(int, Typefile *, ctf_id_t, bool);
extern uint8_t dt_diftype_ckind(int, Typefile *, ctf_id_t);
}

#endif /* _DT_TYPING_HELPERS_HH_ */
