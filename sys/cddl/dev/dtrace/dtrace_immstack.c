/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 *
 * CDDL HEADER END
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/dtrace_impl.h>
#include <sys/pcpu.h>

#include <ddb/ddb.h>
#include <ddb/db_sym.h>

#include <cddl/dev/dtrace/dtrace_cddl.h>

/* The DTrace symbol lookup uses the loaded kernel and module ELF tables. */
#include <cddl/dev/dtrace/dtrace_db.c>

/* One slot contains a terminated symbol name and an aligned 64-bit offset. */
int
dtrace_immstack_format(char *slot, int size, pc_t pc)
{
	volatile uint16_t *flags;
	const char *name, *cache_name;
	c_db_sym_t sym;
	db_expr_t off;
	uint64_t cached_off;
	char *end, *p;
	uintptr_t offset_addr;
	bool cache;

	flags = (volatile uint16_t *)&cpu_core[curcpu].cpuc_dtrace_flags;
	if (slot == NULL || size < 16 ||
	    ((uintptr_t)slot & ALIGNBYTES) != 0 ||
	    (size & ALIGNBYTES) != 0) {
		*flags |= CPU_DTRACE_BADSTACK;
		return (-1);
	}
	bzero(slot, size);
	if (pc == 0)
		return (0);

	name = NULL;
	off = 0;
	cached_off = 0;
	cache = dtrace_immstack_caching_enabled != 0;
	if (cache)
		name = dtrace_immstack_get_cached(pc, &cached_off);
	if (name != NULL)
		off = (db_expr_t)cached_off;
	if (name == NULL) {
		*flags |= CPU_DTRACE_NOFAULT;
		sym = dtrace_search_symbol(pc, DB_STGY_PROC, &off);
		if ((*flags & CPU_DTRACE_FAULT) != 0) {
			*flags &= ~(CPU_DTRACE_FAULT | CPU_DTRACE_NOFAULT);
			*flags |= CPU_DTRACE_BADSTACK;
			return (-1);
		}
		if (sym != C_DB_SYM_NULL)
			dtrace_symbol_values(sym, &name, NULL);
		if ((*flags & CPU_DTRACE_FAULT) != 0) {
			*flags &= ~(CPU_DTRACE_FAULT | CPU_DTRACE_NOFAULT);
			*flags |= CPU_DTRACE_BADSTACK;
			return (-1);
		}
		*flags &= ~CPU_DTRACE_NOFAULT;
	}
	if (name == NULL || off >= 0x10000) {
		name = "??";
		off = 0;
		cache = false;
	}
	cache_name = name;
	end = slot + size - sizeof(uint64_t);
	*flags |= CPU_DTRACE_NOFAULT;
	for (p = slot; p < end - 1 && *name != '\0'; p++, name++) {
		*p = *name;
		if ((*flags & CPU_DTRACE_FAULT) != 0) {
			*flags &= ~(CPU_DTRACE_FAULT | CPU_DTRACE_NOFAULT);
			*flags |= CPU_DTRACE_BADSTACK;
			return (-1);
		}
	}
	*flags &= ~CPU_DTRACE_NOFAULT;
	*p = '\0';
	offset_addr = (uintptr_t)ALIGN(p + 1);
	/* slot and size are 8-byte aligned (checked on entry) and p < end - 1,
	 * so the aligned offset word ends at or before slot + size. */
	ASSERT(offset_addr + sizeof(uint64_t) <= (uintptr_t)slot + size);
	*(uint64_t *)offset_addr = (uint64_t)off;
	if (cache)
		dtrace_immstack_cache(pc, cache_name, off);
	return (0);
}
