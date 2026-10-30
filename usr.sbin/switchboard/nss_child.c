/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/cap_authority.h>
#include <sys/cap_process.h>
#include <sys/procctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "nss_child.h"

/* No NSS, allocation, logging, atfork callbacks, or library cleanup here.
 * Closing libservice's inventory alone would leave other descriptor and
 * attached authority. Start a fresh image with only the selected stdio. */
void
sb_nss_child_exec(const char *helper, int input, int output, int diagnostic)
{
	/* execve reads argv strings; its historic interface lacks const. */
	char *const argv[] = { __DECONST(char *, helper), NULL };
	char *const env[] = { NULL };
	int state = PROC_NO_NEW_PRIVS_ENABLE;

	if (helper == NULL || helper[0] != '/' || input < 3 || output < 3 ||
	    diagnostic < 3 || input == output || input == diagnostic ||
	    output == diagnostic)
		_exit(126);
	if (syscall(SYS_cap_process, CAP_AUTH_CLEAR, -1, 0, NULL) == -1 ||
	    syscall(SYS_cap_process, MAC_CAP_PROCESS_CLEAR, -1, 0, NULL) == -1 ||
	    procctl(P_PID, getpid(), PROC_NO_NEW_PRIVS_CTL, &state) == -1)
		_exit(126);
	if (dup2(input, STDIN_FILENO) == -1 ||
	    dup2(output, STDOUT_FILENO) == -1 ||
	    dup2(diagnostic, STDERR_FILENO) == -1)
		_exit(126);
	closefrom(STDERR_FILENO + 1);
	execve(helper, argv, env);
	_exit(126);
}
