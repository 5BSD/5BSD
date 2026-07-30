.include <src.opts.mk>

PACKAGE=	servicectl-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/servicectl

.PATH: ${SRCTOP}/usr.sbin/oracled/tests
.PATH: ${SRCTOP}/usr.sbin/serviced/tests

ATF_TESTS_SH+=	servicectl_test

PROGS+=		capd_test_guardian
PROGS+=		capd_protocol_fixture
PROGS+=		deps_network_fixture
PROGS+=		deps_both_fixture
BINDIR=		${TESTSDIR}

SRCS.deps_network_fixture=	deps_network_fixture.c
SRCS.deps_both_fixture=	deps_both_fixture.c

LIBADD.capd_protocol_fixture+=	service
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/lib/libservice
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/usr.sbin/kldmgrd
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/usr.sbin/rebootd

${PACKAGE}FILES+=	capd_test_harness.sh
.include <bsd.test.mk>
