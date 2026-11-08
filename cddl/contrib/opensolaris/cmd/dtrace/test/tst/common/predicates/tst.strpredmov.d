/*
 * SPDX-License-Identifier: CDDL-1.0
 * A predicate whose string comparison leaves its operand in the register
 * that the final "mov %r0, %rd" overwrites must enable: the HyperTrace
 * linker's data-flow graph treated that mov as a use of %rd and rejected
 * the string and integer definitions reaching it.
 */

#pragma D option quiet

proc:::exit
/curpsinfo->pr_ppid == 1 && curpsinfo->pr_psargs == "nosuchprocess" &&
    args[0] == CLD_KILLED/
{
	exit(1);
}

BEGIN
{
	exit(0);
}
