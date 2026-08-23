# Core AF_VSOCK and kernel-contract tests used by the WASPNest qualification
# suite.  The sources remain beside the other kernel tests; this separate
# Makefile gives them one package owner without moving unrelated sys/kern tests.

PACKAGE=	waspnest-tests
TESTSDIR=	${TESTSBASE}/sys/kern/waspnest_core

.PATH: ${.CURDIR}/..

ATF_TESTS_C+=	vsock_test
CFLAGS.vsock_test+=	-I${SRCTOP}/sys
LIBADD.vsock_test+=	pthread
CWARNFLAGS.vsock_test.c+=	-Wno-cast-align
TEST_METADATA.vsock_test+=	required_user="root"
TEST_METADATA.vsock_test+=	required_kmods="vsock"
TEST_METADATA.vsock_test+=	timeout="60"

ATF_TESTS_C+=	vsock_wire_test
CFLAGS.vsock_wire_test+=	-I${SRCTOP}/sys

ATF_TESTS_C+=	vsock_iov_test
CFLAGS.vsock_iov_test+=	-I${SRCTOP}/usr.sbin/bhyve

ATF_TESTS_PYTEST+=	sglist_boundary_test.py
ATF_TESTS_PYTEST_SRC_sglist_boundary_test.py.xtmp=	\
	${.CURDIR}/../sglist_boundary_test.py

ATF_TESTS_SH+=	run_vsock_tests_test
TEST_METADATA.run_vsock_tests_test+=	required_user="root"

${PACKAGE}FILES+=	run_vsock_tests.sh
${PACKAGE}FILESMODE_run_vsock_tests.sh=0555

.if ${.OBJDIR} != ${.CURDIR}
CLEANFILES+=	run_vsock_tests.sh
beforedepend:	run_vsock_tests.sh
run_vsock_tests.sh: ${.CURDIR}/../run_vsock_tests.sh
	cp ${.ALLSRC} ${.TARGET}.tmp.${.MAKE.PID}
	mv -f ${.TARGET}.tmp.${.MAKE.PID} ${.TARGET}
all: run_vsock_tests.sh
.endif

.include <bsd.test.mk>
