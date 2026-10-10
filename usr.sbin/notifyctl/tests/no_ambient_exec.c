/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Run a command without the process's ambient service lookup route.  Under a
 * live plane the route is a kernel per-process slot inherited across exec,
 * so removing SERVICE_LOOKUP_FD from the environment alone does not make a
 * broker unavailable.
 */
#include <err.h>
#include <errno.h>
#include <libservice_session.h>
#include <signal.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	if (argc < 2)
		errx(64, "usage: no_ambient_exec command [argument ...]");
	/* Kernels without the process-context call have no route to clear. */
	(void)signal(SIGSYS, SIG_IGN);
	if (service_clear_ambient_lookup() == -1 && errno != ENOSYS)
		err(70, "service_clear_ambient_lookup");
	(void)signal(SIGSYS, SIG_DFL);
	execvp(argv[1], argv + 1);
	err(126, "%s", argv[1]);
}
