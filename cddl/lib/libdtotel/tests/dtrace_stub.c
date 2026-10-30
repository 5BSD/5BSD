/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Scriptable stand-ins for the libdtrace entry points libdtotel uses.
 * Defined in the test program, they take precedence over libdtrace.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dtrace_stub.h"

struct stub_state stub;

int
dtrace_handle_buffered(dtrace_hdl_t *dtp, dtrace_handle_buffered_f *hdlr,
    void *arg)
{

	(void)dtp;
	if (stub.fail_handle_buffered)
		return (-1);
	stub.bufhandler = hdlr;
	stub.bufarg = arg;
	return (0);
}

int
dtrace_errno(dtrace_hdl_t *dtp)
{

	(void)dtp;
	return (1);
}

const char *
dtrace_errmsg(dtrace_hdl_t *dtp, int error)
{

	(void)dtp;
	(void)error;
	return ("stub error");
}

int
dtrace_lookup_by_addr(dtrace_hdl_t *dtp, GElf_Addr addr, GElf_Sym *symp,
    dtrace_syminfo_t *sip)
{
	static char names[16][16];
	int idx;

	(void)dtp;
	if (addr < STUB_SYM_LO || addr >= STUB_SYM_HI)
		return (-1);
	idx = (int)((addr >> 8) & 0xf);
	snprintf(names[idx], sizeof(names[idx]), "fn%d", idx);
	memset(symp, 0, sizeof(*symp));
	symp->st_value = addr & ~0xffULL;
	memset(sip, 0, sizeof(*sip));
	sip->dts_object = "kernel";
	sip->dts_name = names[idx];
	return (0);
}

/*
 * User addresses: STUB_USYM_LO..HI symbolize as a.out`ufnN+0xoff (N from
 * bits 8..11), STUB_UOBJ_LO..HI as an object without a symbol
 * (libc.so.7`0xaddr), anything else stays an address; pid 0 never
 * symbolizes, as for an exited process.
 */
int
dtrace_uaddr2str(dtrace_hdl_t *dtp, pid_t pid, uint64_t addr, char *buf,
    int len)
{

	(void)dtp;
	stub.uaddr_lookups++;
	if (pid != 0 && addr >= STUB_USYM_LO && addr < STUB_USYM_HI)
		return (snprintf(buf, (size_t)len, "a.out`ufn%d+0x%jx",
		    (int)((addr >> 8) & 0xf), (uintmax_t)(addr & 0xff)));
	if (pid != 0 && addr >= STUB_UOBJ_LO && addr < STUB_UOBJ_HI)
		return (snprintf(buf, (size_t)len, "libc.so.7`0x%jx",
		    (uintmax_t)addr));
	return (snprintf(buf, (size_t)len, "0x%jx", (uintmax_t)addr));
}

int
dtrace_aggregate_snap(dtrace_hdl_t *dtp)
{

	(void)dtp;
	return (stub.fail_snap ? -1 : 0);
}

int
dtrace_aggregate_walk(dtrace_hdl_t *dtp, dtrace_aggregate_f *func,
    void *arg)
{
	size_t i;

	(void)dtp;
	for (i = 0; i < stub.naggs; i++)
		if (func(stub.aggs[i], arg) != DTRACE_AGGWALK_NEXT)
			break;
	return (stub.fail_walk ? -1 : 0);
}

/* Jails 1..99 are named "jail<N>"; others are not visible. */
char *
jail_getname(int jid)
{
	char *name;

	stub.jail_lookups++;
	if (jid < 1 || jid > 99)
		return (NULL);
	asprintf(&name, "jail%d", jid);
	return (name);
}

static int stub_prog;

dtrace_prog_t *
dtrace_program_strcompile(dtrace_hdl_t *dtp, const char *s,
    dtrace_probespec_t spec, uint_t cflags, int argc, char *const argv[])
{

	(void)dtp;
	(void)s;
	(void)spec;
	(void)cflags;
	(void)argc;
	(void)argv;
	stub.compiled++;
	return (stub.fail_compile ? NULL : (dtrace_prog_t *)&stub_prog);
}

int
dtrace_program_exec(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_proginfo_t *pip)
{

	(void)dtp;
	(void)pgp;
	(void)pip;
	return (stub.fail_exec ? -1 : 0);
}
