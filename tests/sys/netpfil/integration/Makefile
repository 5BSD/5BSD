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
		bridge

# The seam tests create their own VNET jails, read host-wide state (pool
# limits, loaded modules, DTrace providers) and mount devfs for jails with
# their own root, so they run in the host vnet, one program at a time.
.for t in ${ATF_TESTS_SH}
TEST_METADATA.${t}+=	execenv="" is_exclusive="true"
.endfor

${PACKAGE}FILES+=	integration.subr

.include <bsd.test.mk>
