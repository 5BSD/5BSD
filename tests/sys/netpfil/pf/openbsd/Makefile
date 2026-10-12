# 5BSD glue for the OpenBSD PF regress corpus in contrib/openbsd-pf.
# The corpus is installed beneath ${TESTSDIR}/srctree (tests/srctree.mk) so
# installed tests do not depend on the build machine's source tree.

PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/sys/netpfil/pf/openbsd

ATF_TESTS_SH+=	openbsd_regress
TEST_METADATA.openbsd_regress+=	execenv="jail" \
				required_user="root" \
				is_exclusive="true"

# Per-vnet OpenBSD PF instances (5BSD).
ATF_TESTS_SH+=	vnet_test
TEST_METADATA.vnet_test+=	required_user="root" \
				is_exclusive="true"

# Transparent proxying with divert-to (TCP and UDP, IPv4 and IPv6).
ATF_TESTS_SH+=	divert_test
TEST_METADATA.divert_test+=	required_user="root" \
				required_programs="python3" \
				is_exclusive="true"
${PACKAGE}FILES+=	tproxy.py

# authpf(8) sessions load and remove their rules.
ATF_TESTS_SH+=	authpf_test
TEST_METADATA.authpf_test+=	required_user="root" \
				is_exclusive="true"

# ftp-proxy(8) on a NAT router, passive and active (+ ftpd.py).
ATF_TESTS_SH+=	ftpproxy_test
TEST_METADATA.ftpproxy_test+=	required_user="root" \
				required_programs="python3" \
				is_exclusive="true"
${PACKAGE}FILES+=	ftpd.py
${PACKAGE}FILESMODE_ftpd.py=	0555

# pfsync(4) between two firewalls (vnet jails): sync and failover.
ATF_TESTS_SH+=	pfsync_test
TEST_METADATA.pfsync_test+=	required_user="root" \
				required_programs="python3" \
				is_exclusive="true"

# 5BSD extension: the "jail" rule option.
ATF_TESTS_SH+=	jail_test
TEST_METADATA.jail_test+=	required_user="root" \
				is_exclusive="true"
${PACKAGE}FILESMODE_tproxy.py=	0555

SRCTREE_FILES!=	cd ${SRCTOP} && find contrib/openbsd-pf -type f \
		    ! -name README.5BSD | sort

# bmake-adapted copy of OpenBSD's bsd.regress.mk (see bsd.regress.mk.sed).
FILESGROUPS+=	REGRESSMK
REGRESSMK=	bsd.regress.mk
REGRESSMKDIR=	${TESTSDIR}/mk
REGRESSMKPACKAGE=	${PACKAGE}
CLEANFILES+=	bsd.regress.mk
bsd.regress.mk: ${SRCTOP}/contrib/openbsd-pf/share/mk/bsd.regress.mk \
    ${.CURDIR}/bsd.regress.mk.sed
	sed -f ${.CURDIR}/bsd.regress.mk.sed \
	    ${SRCTOP}/contrib/openbsd-pf/share/mk/bsd.regress.mk > ${.TARGET}

.include "${SRCTOP}/tests/srctree.mk"
.include <bsd.test.mk>
