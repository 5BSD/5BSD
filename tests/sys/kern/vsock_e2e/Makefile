# vsock end-to-end (host <-> bhyve guest) test harness.
#
# Installed into the base "tests" package (pkgbase: FreeBSD-tests) under
# ${TESTSBASE}/sys/kern/vsock_e2e.  Unlike the ATF suites in the parent
# directory these are NOT run by kyua automatically: they require a bhyve
# host with a running guest and are driven by run.sh.  See the header of
# run.sh for the environment it expects.
#
# Host-side tools (built and installed here):
#   unix-pipe       AF_UNIX netcat (relay/echo/drain) for the device's
#                   path= directory -- the host end of the vsock device.
#   vsh-connect     capability-mode host->guest connector via the device
#                   control socket (SCM_RIGHTS fd relay).
#
# Guest-side tools (vsock-pipe, vsock-conntest) live here as sources too
# so a 5BSD guest image build can compile them; they use <sys/vsock.h>
# which only the guest kernel provides at runtime, so they are shipped as
# source, not built here.

PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/sys/kern/vsock_e2e
BINDIR=		${TESTSDIR}
SCRIPTSDIR=	${TESTSDIR}
FILESDIR=	${TESTSDIR}

WARNS?=		3
MAN=

# Host-side helper programs.
PROGS+=		unix-pipe
PROGS+=		vsh-connect

# Driver script (keep the .sh suffix; SCRIPTS strips it by default).
SCRIPTS+=	run.sh
SCRIPTSNAME_run.sh=	run.sh

# Guest-side tool sources (shipped for in-guest compilation).
FILES+=		vsock-pipe.c
FILES+=		vsock-conntest.c

.include <bsd.prog.mk>
