PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/netpfil/integration
BINDIR=		${TESTSDIR}

# 5BSD seam tests: OpenBSD PF on the FreeBSD network stack, with 5BSD's
# capability plane and jails.  See README.
ATF_TESTS_SH+=	vnet_dev \
		host_limits \
		modules \
		cloners \
		jail_rule \
		rdomain \
		sockets \
		securelevel \
		consumers \
		dtrace \
		bridge \
		containers

# The seam tests create their own VNET jails, read host-wide state (pool
# limits, loaded modules, DTrace providers) and mount devfs for jails with
# their own root, so they run in the host vnet, one program at a time.
.for t in ${ATF_TESTS_SH}
TEST_METADATA.${t}+=	execenv="" is_exclusive="true"
.endfor

${PACKAGE}FILES+=	integration.subr \
			pf_devhelper.py \
			README
${PACKAGE}FILESMODE_pf_devhelper.py=	0555

# Helpers: socket options (sockets, rdomain), raw pf ioctls (securelevel)
# and a capability-mode /dev/pf descriptor (consumers).
PROGS+=		sockhelper pfiochelper pf_capfd
MAN.sockhelper=
MAN.pfiochelper=
MAN.pf_capfd=
.for p in pfiochelper pf_capfd
CFLAGS.${p}+=	-I${SRCTOP}/sys/netpfil/openbsd-pf/user
CFLAGS.${p}+=	-I${SRCTOP}/contrib/openbsd-pf/sys
CFLAGS.${p}+=	-include ${SRCTOP}/sys/netpfil/openbsd-pf/user/openbsd_compat.h
.endfor

.include <bsd.test.mk>
