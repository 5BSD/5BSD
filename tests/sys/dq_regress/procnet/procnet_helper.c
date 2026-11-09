/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The image the procnet exec, core and syscall cases run.  The mode is
 * argv[1]; as a #! interpreter that is the script's option string, so
 * modes match by prefix.
 *
 *   ids        print "ruid euid suid rgid egid sgid"
 *   paths      print AT_EXECPATH ("-" if absent) and kern.proc.pathname
 *   args       print argc, then each argv element on its own line
 *   pdeathsig  print the PROC_PDEATHSIG_STATUS signal (0 if none)
 *   abort      abort(3)
 *   exit       exit 0
 */

#include <sys/types.h>
#include <sys/auxv.h>
#include <sys/procctl.h>
#include <sys/sysctl.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	char ep[PATH_MAX], pp[PATH_MAX];
	uid_t ru, eu, su;
	gid_t rg, eg, sg;
	size_t len;
	int i, mib[4], sig;
	const char *mode;

	if (argc < 2)
		return (64);
	mode = argv[1];
	if (strncmp(mode, "ids", 3) == 0) {
		if (getresuid(&ru, &eu, &su) != 0 ||
		    getresgid(&rg, &eg, &sg) != 0)
			return (65);
		printf("%u %u %u %u %u %u\n", ru, eu, su, rg, eg, sg);
	} else if (strncmp(mode, "paths", 5) == 0) {
		if (elf_aux_info(AT_EXECPATH, ep, sizeof(ep)) != 0)
			strlcpy(ep, "-", sizeof(ep));
		mib[0] = CTL_KERN;
		mib[1] = KERN_PROC;
		mib[2] = KERN_PROC_PATHNAME;
		mib[3] = -1;
		len = sizeof(pp);
		if (sysctl(mib, 4, pp, &len, NULL, 0) != 0)
			strlcpy(pp, "-", sizeof(pp));
		printf("%s\n%s\n", ep, pp);
	} else if (strncmp(mode, "args", 4) == 0) {
		printf("%d\n", argc);
		for (i = 0; i < argc; i++)
			printf("%s\n", argv[i]);
	} else if (strncmp(mode, "pdeathsig", 9) == 0) {
		sig = -1;
		if (procctl(P_PID, 0, PROC_PDEATHSIG_STATUS, &sig) != 0)
			return (66);
		printf("%d\n", sig);
	} else if (strncmp(mode, "abort", 5) == 0) {
		abort();
	} else if (strncmp(mode, "exit", 4) != 0) {
		return (67);
	}
	if (fflush(stdout) != 0)
		return (68);
	return (0);
}
