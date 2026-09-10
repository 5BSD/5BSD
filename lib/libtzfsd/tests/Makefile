PACKAGE=	tzfs-tests
TESTSDIR=	${TESTSBASE}/lib/libtzfsd

ATF_TESTS_C=	tzfsd_test
SRCS.tzfsd_test=	tzfsd_test.c
CFLAGS.tzfsd_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.tzfsd_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.tzfsd_test+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS.tzfsd_test+=	-I${SRCTOP}/sys

.include <bsd.test.mk>
