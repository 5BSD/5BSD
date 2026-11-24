/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
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

/*
 * Kernel options 5BSD requires (sys/conf/mandatory-options).  This file is
 * compiled into every kernel ("standard" in sys/conf/files); a
 * configuration that removes one of the options fails here.  opt_global.h
 * is included by the kernel build; the Capsicum options are in
 * opt_capsicum.h.
 */

#include "opt_capsicum.h"

#include <sys/param.h>

#ifndef AUDIT
#error "5BSD kernels require options AUDIT (sys/conf/mandatory-options)"
#endif
#ifndef CAPABILITY_MODE
#error "5BSD kernels require options CAPABILITY_MODE (sys/conf/mandatory-options)"
#endif
#ifndef CAPABILITIES
#error "5BSD kernels require options CAPABILITIES (sys/conf/mandatory-options)"
#endif
#ifndef RACCT
#error "5BSD kernels require options RACCT (sys/conf/mandatory-options)"
#endif
#ifndef RCTL
#error "5BSD kernels require options RCTL (sys/conf/mandatory-options)"
#endif
