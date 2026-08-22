PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/sys/tzfs

ATF_TESTS_C+=	tzfsd_test
ATF_TESTS_C+=	libtzfsd_protocol_test

CFLAGS.tzfsd_test.c+=	-I${SRCTOP}/lib/libtzfsd
CFLAGS.tzfsd_test.c+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.tzfsd_test.c+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS.tzfsd_test.c+=	-I${SRCTOP}/sys
LIBADD.tzfsd_test+=	tzfsd trustedzfs
CFLAGS.libtzfsd_protocol_test.c+=	-I${SRCTOP}/lib/libtzfsd
CFLAGS.libtzfsd_protocol_test.c+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.libtzfsd_protocol_test.c+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS.libtzfsd_protocol_test.c+=	-I${SRCTOP}/sys
LIBADD.libtzfsd_protocol_test+=	tzfsd trustedzfs

BINDIR=		${TESTSDIR}

.include <bsd.test.mk>
