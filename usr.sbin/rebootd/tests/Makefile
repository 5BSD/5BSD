PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/usr.sbin/rebootd

.PATH: ${SRCTOP}/usr.sbin/oracled/tests
.PATH: ${SRCTOP}/usr.sbin/serviced/tests

ATF_TESTS_SH=	rebootd_test

PROGS+=		capd_test_guardian
PROGS+=		capd_protocol_fixture
BINDIR=		${TESTSDIR}

LIBADD.capd_protocol_fixture+=	service
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/lib/libservice
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/usr.sbin/kldmgrd
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/usr.sbin/rebootd

FILES+=		capd_test_harness.sh
FILESDIR=	${TESTSDIR}

.include <bsd.test.mk>
