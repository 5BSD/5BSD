#include <sys/types.h>
#include <sys/param.h>
#include <sys/dtrace.h>
#include <sys/sysctl.h>

#include <assert.h>
#include <dt_impl.h>
#include <dt_resolver.h>
#include <dtrace.h>
#include <errno.h>
#include <fnmatch.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define	DT_RESOLVER_HOSTNAME(f) ((f) & 1)
#define	DT_RESOLVER_VERSION(f)  (((f) >> 1) & 1)

static uint32_t resolve_flags;

/*
 * The current machine's identity could not be determined.  During a D
 * compilation this is a compile error; otherwise report DT_RESOLVE_ERROR
 * with errno set.  libdtrace never terminates the process here.
 */
static int
dt_resolve_fail(const char *what, int error)
{
	if (yypcb != NULL && yypcb->pcb_hdl != NULL) {
		xyerror(D_UNKNOWN, "cannot match target: failed to get %s: "
		    "%s\n", what, strerror(error));
	}

	errno = error;
	return (DT_RESOLVE_ERROR);
}

/*
 * This subroutine checks whether or not the current target machine matches
 * the "target" description, whatever it may be based on the flags passed in.
 * It returns 0 on a match, -1 if the target does not match, and
 * DT_RESOLVE_ERROR (errno set) if the local identity cannot be read outside
 * a compilation.
 */
int
dt_resolve(const char *target, uint32_t flags)
{
	char curtarget[
	    MAX(MAXHOSTNAMELEN, OSRELEASELEN) + sizeof("FreeBSD-")] = {0};
	size_t len = MAX(MAXHOSTNAMELEN, OSRELEASELEN) + sizeof("FreeBSD-");

	/*
	 * If there is no target, we just assume that it's for all targets.
	 */
	if (strlen(target) == 0)
		return (0);

	/*
	 * If flags are 0, we assume default configuration
	 */
	if (flags == 0)
		flags = resolve_flags;

	if (DT_RESOLVER_HOSTNAME(flags) != 0) {
		if (gethostname(curtarget, MAXHOSTNAMELEN) != 0)
			return (dt_resolve_fail("hostname", errno));

		if (fnmatch(target, curtarget, 0) == 0)
			return (0);
	}

	if (DT_RESOLVER_VERSION(flags) != 0) {
		strcpy(curtarget, "FreeBSD-");
		len -= strlen("FreeBSD-");
		if (sysctlbyname("kern.osrelease",
		    curtarget + strlen("FreeBSD-"), &len, NULL, 0) != 0)
			return (dt_resolve_fail("the OS release", errno));

		if (fnmatch(target, curtarget, 0) == 0)
			return (0);
	}

	return (-1);
}

void
dtrace_resolver_setflags(uint32_t flags)
{

	resolve_flags = flags;
}
