/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dtrace_vm_subr.c is not a stand-alone translation unit: the amd64 dtrace
 * module compiles it through `#include "dtrace_vm_subr.c"' at the end of
 * amd64/dtrace_subr.c.  This forced prelude supplies the system headers that
 * dtrace_subr.c includes before that point (its DTrace-only headers are not
 * needed by the page walker).
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/smp.h>
#include <machine/cpufunc.h>
#include <machine/md_var.h>
#include <machine/vmm.h>
#include <vm/vm.h>
#include <vm/pmap.h>
